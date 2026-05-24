//! PeerConnection — port of `rtc::PeerConnection` / `rtc::impl::PeerConnection`
//! from `native/libdatachannel/src/peerconnection.cpp` and
//! `native/libdatachannel/src/impl/peerconnection.cpp`.
//!
//! This is the facade that automates the manual transport orchestration the
//! lower-level loopback tests perform by hand
//! (`dtls_transport::tests::dtls_handshake_completes_over_ice_loopback`,
//! `sctp_transport::tests::sctp_association_completes_over_dtls_loopback`).
//! Instead of hard-coding ActPass/Active roles and cross-pinning
//! fingerprints, the PeerConnection drives both from the negotiated SDP:
//!
//! - **SDP-driven DTLS role:** the offerer emits `a=setup:actpass`; the
//!   answerer picks `active` (DTLS client). Each side's resolved DTLS role
//!   comes from [`IceTransport::set_remote_description`], which inspects the
//!   remote `a=setup:` attribute and flips an `ActPass` local role to the
//!   opposite of the remote (matching `icetransport.cpp:203`).
//! - **SDP-driven remote fingerprint:** [`PeerConnection::set_remote_description`]
//!   parses the remote `a=fingerprint:` line and pins it on the
//!   [`DtlsTransport`] before the handshake starts, so DTLS auth works off
//!   real negotiation rather than a manual cross-pin.
//! - **State aggregation:** [`PeerConnectionState`] is derived from the
//!   underlying ICE + DTLS (+ SCTP) states following the C++
//!   `initIceTransport` / `initDtlsTransport` / `initSctpTransport` state
//!   handlers; [`SignalingState`] and [`GatheringState`] track the
//!   offer/answer and gathering progress.
//!
//! ## Lazy transport creation (matches the C++ flow)
//!
//! - The **ICE** transport is created when a local description is generated
//!   (`create_offer` / `set_local_description`) so it can mint the local
//!   ice-ufrag/pwd and start gathering.
//! - The **DTLS** transport is created when ICE first reaches `Connected`
//!   (the C++ `initDtlsTransport()` call inside the ICE state handler) — at
//!   which point the DTLS role has already been resolved from the remote
//!   SDP, so the right side becomes the DTLS client.
//! - The **SCTP** transport is created when DTLS reaches `Connected` and the
//!   negotiated description has an application m-line (the C++
//!   `initSctpTransport()` call inside the DTLS state handler).
//!
//! Because the lower transports each capture role / readiness at
//! construction time and install their own auto-start hooks on the
//! transport beneath them, building them *lazily at the right moment* and
//! then explicitly calling `start()` / `connect()` reproduces the C++
//! semantics exactly: the DTLS transport reads the SDP-resolved ICE role,
//! and the SCTP transport only comes up once an application m-line was
//! negotiated.
//!
//! ## DataChannels + DCEP (#18)
//!
//! [`PeerConnection::create_data_channel`] returns a real [`DataChannel`]
//! handle. It records the channel (ensuring the application m-line is
//! advertised so SCTP comes up) and, once SCTP reaches `Connected`, drives
//! the DCEP `DATA_CHANNEL_OPEN`/`ACK` handshake (RFC 8832) over the SCTP
//! Control PPID. Stream ids follow RFC 8832 §6 — the DTLS client uses even
//! ids, the server odd. Inbound `OPEN`s allocate a channel, reply with an
//! `ACK`, and fire [`PeerConnectionCallbacks::on_data_channel`] with the new
//! handle; inbound user data (String/Binary PPIDs) routes to the channel
//! bound to its SCTP stream. See [`crate::data_channel`] for the protocol.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use thiserror::Error;
use tracing::warn;

use crate::certificate::{Certificate, CertificateError};
use crate::configuration::Configuration;
use crate::description::{
    Application, Description, DescriptionParseError, Fingerprint, FingerprintAlgorithm, Role,
    Type as DescriptionType,
};
use crate::dtls_transport::{
    DtlsState, DtlsTransport, DtlsTransportCallbacks, DtlsTransportError,
};
use crate::ice_transport::{
    GatheringState as IceGatheringState, IceTransport, IceTransportCallbacks, IceTransportError,
    State as IceState,
};
use crate::sctp_transport::{
    PayloadProtocolId, SctpMessage, SctpState, SctpTransport, SctpTransportCallbacks,
};
use crate::candidate::Candidate;
use crate::data_channel::{
    decode_control, DataChannel, DataChannelCallbacks, DataChannelInit, DcepMessage,
    StreamIdAllocator,
};

/// Aggregate connection state, mirroring W3C `RTCPeerConnectionState` and the
/// C++ `rtc::PeerConnection::State`.
///
/// Derived from the underlying ICE + DTLS (+ SCTP) transport states by
/// [`PeerConnection`], following the transitions in
/// `native/libdatachannel/src/impl/peerconnection.cpp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerConnectionState {
    /// No transport activity yet.
    New,
    /// ICE began connectivity checks (and/or DTLS/SCTP are coming up).
    Connecting,
    /// The full negotiated stack is up: DTLS connected (data-less) or SCTP
    /// connected (with an application m-line).
    Connected,
    /// A transport lost connectivity (consent freshness lapsed, etc.).
    Disconnected,
    /// A transport failed unrecoverably.
    Failed,
    /// [`PeerConnection::close`] ran or the peer closed the session.
    Closed,
}

/// Signaling state, mirroring W3C `RTCSignalingState` and the reference
/// crate's `SignalingState`. Tracks offer/answer progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalingState {
    /// No offer/answer exchange in progress.
    Stable,
    /// A local offer has been applied; awaiting the remote answer.
    HaveLocalOffer,
    /// A remote offer has been applied; awaiting the local answer.
    HaveRemoteOffer,
    /// A local provisional answer has been applied.
    HaveLocalPranswer,
    /// A remote provisional answer has been applied.
    HaveRemotePranswer,
}

/// Candidate gathering state. Re-exposed at the PeerConnection layer so
/// callers don't need to reach into the ICE transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatheringState {
    /// No gathering has been triggered yet.
    New,
    /// Gathering is underway; `on_local_candidate` fires for each candidate.
    InProgress,
    /// Gathering finished.
    Complete,
}

impl From<IceGatheringState> for GatheringState {
    fn from(g: IceGatheringState) -> Self {
        match g {
            IceGatheringState::New => GatheringState::New,
            IceGatheringState::InProgress => GatheringState::InProgress,
            IceGatheringState::Complete => GatheringState::Complete,
        }
    }
}

/// Errors returned by [`PeerConnection`] operations.
#[derive(Debug, Error)]
pub enum PeerConnectionError {
    /// Forwarded from the ICE transport.
    #[error("ice: {0}")]
    Ice(#[from] IceTransportError),

    /// Forwarded from the DTLS transport.
    #[error("dtls: {0}")]
    Dtls(#[from] DtlsTransportError),

    /// Forwarded from certificate generation.
    #[error("certificate: {0}")]
    Certificate(#[from] CertificateError),

    /// A remote SDP blob failed to parse.
    #[error("description parse: {0}")]
    Description(#[from] DescriptionParseError),

    /// An operation required a local description that hasn't been set yet.
    #[error("no local description set")]
    NoLocalDescription,

    /// The remote description carried no DTLS fingerprint, so the handshake
    /// could not be authenticated.
    #[error("remote description has no fingerprint")]
    MissingRemoteFingerprint,

    /// The operation was attempted on a closed PeerConnection.
    #[error("peer connection closed")]
    Closed,
}

/// Callbacks the [`PeerConnection`] fires from the transport driver
/// threads. All are `Arc<dyn Fn(..) + Send + Sync>` to match the existing
/// transport convention (rather than the reference crate's handler-generic
/// trait style). Use [`PeerConnectionCallbacks::default`] for all-no-ops.
#[derive(Clone)]
pub struct PeerConnectionCallbacks {
    /// Fires on every [`PeerConnectionState`] transition.
    pub on_state_change: Arc<dyn Fn(PeerConnectionState) + Send + Sync>,
    /// Fires on every [`GatheringState`] transition.
    pub on_gathering_state_change: Arc<dyn Fn(GatheringState) + Send + Sync>,
    /// Fires on every [`SignalingState`] transition.
    pub on_signaling_state_change: Arc<dyn Fn(SignalingState) + Send + Sync>,
    /// Fires exactly once per negotiation with the local [`Description`] once
    /// it carries ICE credentials (`a=ice-ufrag` / `a=ice-pwd`).
    ///
    /// Mirrors libdatachannel's `onLocalDescription`: a single, complete local
    /// description is surfaced for signaling, independently of (and typically
    /// before) the per-candidate trickle. In this port libjuice mints the
    /// ufrag/pwd asynchronously on its driver task, so this fires from the
    /// same path that folds the credentials into the stored description — at
    /// the first moment the description provably has them — rather than from
    /// `set_local_description` (where they may not be minted yet).
    pub on_local_description: Arc<dyn Fn(Description) + Send + Sync>,
    /// Fires for each local ICE candidate the agent surfaces (trickle).
    pub on_local_candidate: Arc<dyn Fn(Candidate) + Send + Sync>,
    /// Fires when the remote peer opens a data channel, delivering a real
    /// [`DataChannel`] handle. The handle arrives already bound to its
    /// inbound SCTP stream and ACK'd; install callbacks on it via
    /// [`DataChannel::set_callbacks`] to receive messages.
    pub on_data_channel: Arc<dyn Fn(DataChannel) + Send + Sync>,
}

impl Default for PeerConnectionCallbacks {
    fn default() -> Self {
        PeerConnectionCallbacks {
            on_state_change: Arc::new(|_| {}),
            on_gathering_state_change: Arc::new(|_| {}),
            on_signaling_state_change: Arc::new(|_| {}),
            on_local_description: Arc::new(|_| {}),
            on_local_candidate: Arc::new(|_| {}),
            on_data_channel: Arc::new(|_| {}),
        }
    }
}

// ---------------------------------------------------------------------------
// PeerConnection
// ---------------------------------------------------------------------------

/// The PeerConnection facade. Owns the transport stack and drives the
/// offer/answer + transport-layering dance.
///
/// Cheap to clone — it's an `Arc<Inner>` under the hood, matching the
/// existing transport pattern.
#[derive(Clone)]
pub struct PeerConnection {
    inner: Arc<Inner>,
}

struct Inner {
    config: Configuration,
    /// Local certificate; its fingerprint goes into every local SDP.
    certificate: Certificate,
    /// Cached local fingerprint (SHA-256) so we don't re-hash on every SDP.
    local_fingerprint: Fingerprint,

    callbacks: Mutex<PeerConnectionCallbacks>,

    // --- transport stack (lazily created, matching the C++ flow) ---
    ice: Mutex<Option<Arc<IceTransport>>>,
    dtls: Mutex<Option<DtlsTransport>>,
    sctp: Mutex<Option<Arc<SctpTransport>>>,

    // --- descriptions ---
    local_description: Mutex<Option<Description>>,
    remote_description: Mutex<Option<Description>>,
    /// The type (offer/answer) of the local description we're assembling, so
    /// the gathering callbacks know to refresh `local_description` with the
    /// ice-ufrag/pwd once libjuice mints them (they aren't available
    /// synchronously when `set_local_description` returns).
    pending_local_type: Mutex<Option<DescriptionType>>,

    /// Single-shot guard for [`PeerConnectionCallbacks::on_local_description`].
    /// Set once the credential-complete local description has been surfaced so
    /// the callback fires exactly once per negotiation, even though the
    /// refresh path runs from both the candidate and gathering-state handlers.
    /// Reset when a fresh local description is assembled
    /// (`set_local_description` / `create_offer`) so a re-negotiation fires
    /// again.
    local_description_signalled: AtomicBool,

    // --- state ---
    state: Mutex<PeerConnectionState>,
    gathering_state: Mutex<GatheringState>,
    signaling_state: Mutex<SignalingState>,

    /// Data channels keyed by their assigned SCTP stream id. Holds both
    /// locally-created channels (allocated a stream up front) and channels
    /// created from inbound DCEP OPENs. Channels created before SCTP is up
    /// have already been allocated a stream id, so the map is the single
    /// source of truth for stream→channel routing.
    data_channels: Mutex<std::collections::HashMap<u16, DataChannel>>,

    /// Allocates stream ids per RFC 8832 §6 once the DTLS role is known.
    /// `None` until SCTP comes up and the role is resolved (the allocator's
    /// parity depends on whether we are the DTLS client).
    stream_allocator: Mutex<Option<StreamIdAllocator>>,

    /// Locally-created channels still awaiting a stream id (created before
    /// the DTLS role was resolved). Flushed into `data_channels` with a real
    /// stream id once SCTP is up.
    pending_local_channels: Mutex<Vec<DataChannel>>,

    /// True once we are the offerer (so we know to advertise actpass and
    /// know whether the local m-line should exist for SCTP).
    closed: AtomicBool,
}

impl std::fmt::Debug for PeerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConnection")
            .field("state", &*self.inner.state.lock())
            .field("signaling_state", &*self.inner.signaling_state.lock())
            .field("gathering_state", &*self.inner.gathering_state.lock())
            .field("closed", &self.inner.closed.load(Ordering::SeqCst))
            .finish()
    }
}

impl PeerConnection {
    /// Construct a new PeerConnection with the given configuration and
    /// callbacks. A fresh local certificate is generated using the
    /// configuration's certificate type.
    pub fn new(
        config: Configuration,
        callbacks: PeerConnectionCallbacks,
    ) -> Result<Self, PeerConnectionError> {
        let certificate = Certificate::generate(config.certificate_type, "rtc")?;
        Self::with_certificate(config, certificate, callbacks)
    }

    /// Construct a new PeerConnection with an externally-supplied
    /// certificate (handy for tests that want a deterministic cert).
    pub fn with_certificate(
        config: Configuration,
        certificate: Certificate,
        callbacks: PeerConnectionCallbacks,
    ) -> Result<Self, PeerConnectionError> {
        let local_fingerprint = certificate.fingerprint(FingerprintAlgorithm::Sha256)?;
        let inner = Arc::new(Inner {
            config,
            certificate,
            local_fingerprint,
            callbacks: Mutex::new(callbacks),
            ice: Mutex::new(None),
            dtls: Mutex::new(None),
            sctp: Mutex::new(None),
            local_description: Mutex::new(None),
            remote_description: Mutex::new(None),
            pending_local_type: Mutex::new(None),
            local_description_signalled: AtomicBool::new(false),
            state: Mutex::new(PeerConnectionState::New),
            gathering_state: Mutex::new(GatheringState::New),
            signaling_state: Mutex::new(SignalingState::Stable),
            data_channels: Mutex::new(std::collections::HashMap::new()),
            stream_allocator: Mutex::new(None),
            pending_local_channels: Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
        });
        Ok(PeerConnection { inner })
    }

    // -- accessors ------------------------------------------------------------

    /// Current aggregate connection state.
    pub fn state(&self) -> PeerConnectionState {
        *self.inner.state.lock()
    }

    /// Current gathering state.
    pub fn gathering_state(&self) -> GatheringState {
        *self.inner.gathering_state.lock()
    }

    /// Current signaling state.
    pub fn signaling_state(&self) -> SignalingState {
        *self.inner.signaling_state.lock()
    }

    /// The local SDP, if a local description has been set.
    pub fn local_description(&self) -> Option<Description> {
        self.inner.local_description.lock().clone()
    }

    /// The remote SDP, if a remote description has been set.
    pub fn remote_description(&self) -> Option<Description> {
        self.inner.remote_description.lock().clone()
    }

    /// The local certificate fingerprint (SHA-256) advertised in the SDP.
    pub fn local_fingerprint(&self) -> Fingerprint {
        self.inner.local_fingerprint.clone()
    }

    // -- data channels (DCEP, task #18) ---------------------------------------

    /// Create a locally-initiated data channel with default settings.
    /// Equivalent to [`create_data_channel_ext`](Self::create_data_channel_ext)
    /// with a default [`DataChannelInit`] and no callbacks.
    pub fn create_data_channel(&self, label: impl Into<String>) -> DataChannel {
        self.create_data_channel_ext(label, DataChannelInit::default(), DataChannelCallbacks::default())
    }

    /// Create a locally-initiated data channel.
    ///
    /// Registers the channel so the application m-line is advertised
    /// (bringing up SCTP during negotiation) and returns a real
    /// [`DataChannel`] handle. The DCEP `DATA_CHANNEL_OPEN` is sent
    /// automatically once the SCTP association reaches `Connected`; the
    /// channel fires `on_open` when the peer's `ACK` arrives. User data sent
    /// before then is buffered (matching libdatachannel).
    ///
    /// The stream id follows RFC 8832 §6: if the DTLS role is already
    /// resolved we allocate one immediately (even for the DTLS client, odd
    /// for the server); otherwise the channel is parked until SCTP comes up
    /// and the role is known. An explicit `init.stream` is honoured verbatim.
    pub fn create_data_channel_ext(
        &self,
        label: impl Into<String>,
        init: DataChannelInit,
        callbacks: DataChannelCallbacks,
    ) -> DataChannel {
        let label = label.into();

        // Try to assign a stream id now. We can if the caller pinned one, or
        // if the DTLS role is already resolved (allocator present).
        let mut alloc_guard = self.inner.stream_allocator.lock();
        let assigned: Option<u16> = match init.stream {
            Some(s) => {
                if let Some(a) = alloc_guard.as_mut() {
                    a.reserve(s);
                }
                Some(s)
            }
            None => alloc_guard.as_mut().map(|a| a.allocate()),
        };
        drop(alloc_guard);

        match assigned {
            Some(stream) => {
                let dc = DataChannel::new_outgoing(label, stream, init, callbacks);
                if let Some(sctp) = self.inner.sctp.lock().as_ref().cloned() {
                    dc.attach_transport(sctp);
                    // SCTP already up: drive the OPEN immediately.
                    if matches!(self.sctp_state(), SctpState::Connected) {
                        let _ = dc.send_open();
                    }
                }
                self.inner.data_channels.lock().insert(stream, dc.clone());
                dc
            }
            None => {
                // No stream id yet — park it; the stream is assigned and the
                // OPEN is flushed when SCTP comes up (`flush_local_channels`).
                // Use a placeholder stream id of 0; it is replaced on flush.
                let dc = DataChannel::new_outgoing(label, 0, init, callbacks);
                self.inner.pending_local_channels.lock().push(dc.clone());
                dc
            }
        }
    }

    /// Snapshot of the currently-registered data channels (both
    /// locally-created and inbound), keyed by stream id is collapsed to a
    /// flat list.
    pub fn data_channels(&self) -> Vec<DataChannel> {
        self.inner.data_channels.lock().values().cloned().collect()
    }

    /// Current SCTP association state, or [`SctpState::New`] if SCTP hasn't
    /// been created yet.
    fn sctp_state(&self) -> SctpState {
        self.inner
            .sctp
            .lock()
            .as_ref()
            .map(|s| s.state())
            .unwrap_or(SctpState::New)
    }

    // -- offer / answer -------------------------------------------------------

    /// Create an SDP offer. Lazily creates the ICE transport (role
    /// `ActPass` — the offerer advertises `actpass`), starts gathering, and
    /// returns a [`Description`] carrying the local ice-ufrag/pwd, the
    /// local DTLS fingerprint, and an `application` m-line for the data
    /// path. This does **not** set the local description — call
    /// [`set_local_description`](Self::set_local_description) with the
    /// returned description (or a re-rendered one) to apply it.
    pub fn create_offer(&self) -> Result<Description, PeerConnectionError> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(PeerConnectionError::Closed);
        }
        // Offerer is ActPass.
        let ice = self.ensure_ice(Role::ActPass)?;
        // libjuice only mints the local ice-ufrag/pwd once gathering has
        // started, and `get_local_description` returns `NotAvailable`
        // before then. The credentials are available synchronously as soon
        // as gathering begins (well before it completes), so kick off
        // gathering here. `gather()` is idempotent.
        if !self.inner.config.disable_auto_gathering {
            ice.gather()?;
        }
        let desc = self.build_local_description(&ice, DescriptionType::Offer)?;
        Ok(desc)
    }

    /// Apply a local description, generating + starting the ICE transport if
    /// it doesn't exist yet and beginning candidate gathering.
    ///
    /// For an **offer** the role is `ActPass`. For an **answer** the role
    /// has already been resolved against the remote offer (in
    /// [`set_remote_description`](Self::set_remote_description)); we render
    /// the SDP using the ICE transport's resolved role.
    pub fn set_local_description(
        &self,
        typ: DescriptionType,
    ) -> Result<Description, PeerConnectionError> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(PeerConnectionError::Closed);
        }

        // Determine the role to construct ICE with: an offer is ActPass; an
        // answer reuses whatever the ICE transport already resolved (if ICE
        // exists) or ActPass otherwise.
        let initial_role = if matches!(typ, DescriptionType::Offer) {
            Role::ActPass
        } else {
            self.inner
                .ice
                .lock()
                .as_ref()
                .map(|i| i.role())
                .unwrap_or(Role::ActPass)
        };
        let ice = self.ensure_ice(initial_role)?;

        // Begin gathering BEFORE rendering the description: libjuice only
        // mints the local ice-ufrag/pwd once gathering has started, and
        // `get_local_description` returns `NotAvailable` until then. The
        // credentials are available synchronously as gathering begins (well
        // before completion). This matches the C++ which starts gathering
        // once the local description is set. `gather()` is idempotent.
        if !self.inner.config.disable_auto_gathering {
            ice.gather()?;
        }

        // Remember the type so the gathering callbacks can refresh the
        // stored description with ufrag/pwd once libjuice mints them.
        *self.inner.pending_local_type.lock() = Some(typ);

        // Arm the single-shot on_local_description signal for this
        // negotiation; it fires from `refresh_local_description` the moment the
        // credential-complete description is available.
        self.inner
            .local_description_signalled
            .store(false, Ordering::SeqCst);

        let desc = self.build_local_description(&ice, typ)?;

        *self.inner.local_description.lock() = Some(desc.clone());

        // If gathering already advanced far enough to mint credentials
        // (possible if ICE was created earlier), fold them in immediately.
        let desc = self.refresh_local_description().unwrap_or(desc);

        // Signaling-state transition.
        let next_sig = match typ {
            DescriptionType::Offer => SignalingState::HaveLocalOffer,
            DescriptionType::Answer | DescriptionType::Pranswer => SignalingState::Stable,
            _ => *self.inner.signaling_state.lock(),
        };
        self.set_signaling_state(next_sig);

        Ok(desc)
    }

    /// Apply a remote description.
    ///
    /// - Parses the SDP (if a string is provided via [`Description::parse`]
    ///   by the caller — here we accept an already-parsed [`Description`]).
    /// - Resolves our DTLS role against the remote `a=setup:` by handing the
    ///   description to [`IceTransport::set_remote_description`] (which flips
    ///   an `ActPass` local role to the opposite of the remote).
    /// - Records the remote description so SCTP knows whether an application
    ///   m-line was negotiated and which ports to use.
    /// - Trickles any candidates embedded in the description.
    ///
    /// If this PeerConnection has no local description yet (i.e. we're the
    /// answerer receiving an offer), the ICE transport is created here with
    /// role `ActPass` so the remote `setup:actpass` resolves us to `active`
    /// (the DTLS client) per RFC 8842.
    pub fn set_remote_description(
        &self,
        desc: Description,
    ) -> Result<(), PeerConnectionError> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(PeerConnectionError::Closed);
        }

        // The remote MUST carry a fingerprint for DTLS auth.
        if desc.fingerprint().is_none() {
            return Err(PeerConnectionError::MissingRemoteFingerprint);
        }

        // Ensure ICE exists. As the answerer we won't have created it yet;
        // build it ActPass so the remote setup attribute resolves our role.
        let ice = self.ensure_ice(Role::ActPass)?;

        // Hand the description to ICE: this resolves our DTLS role from the
        // remote setup attribute and records the bundle mid + ufrag/pwd.
        ice.set_remote_description(&desc)?;

        // Trickle any candidates embedded in the offer/answer.
        for cand in desc.candidates() {
            let _ = ice.add_remote_candidate(cand);
        }
        if desc.end_of_candidates() {
            let _ = ice.set_remote_end_of_candidates();
        }

        // Signaling-state transition.
        let next_sig = match desc.type_() {
            DescriptionType::Offer => SignalingState::HaveRemoteOffer,
            DescriptionType::Answer | DescriptionType::Pranswer => SignalingState::Stable,
            _ => *self.inner.signaling_state.lock(),
        };

        // Record the remote description (after pulling out what we need) so
        // the DTLS-Connected hook can read its fingerprint + application.
        *self.inner.remote_description.lock() = Some(desc);

        // If DTLS already exists (ICE connected before the remote
        // description arrived — unlikely on loopback but possible), pin the
        // fingerprint now.
        if let Some(dtls) = self.inner.dtls.lock().as_ref() {
            self.pin_remote_fingerprint(dtls);
        }

        self.set_signaling_state(next_sig);

        Ok(())
    }

    /// Trickle a remote ICE candidate received out of band.
    pub fn add_remote_candidate(
        &self,
        candidate: &Candidate,
    ) -> Result<(), PeerConnectionError> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(PeerConnectionError::Closed);
        }
        let ice = self
            .inner
            .ice
            .lock()
            .as_ref()
            .cloned()
            .ok_or(PeerConnectionError::NoLocalDescription)?;
        ice.add_remote_candidate(candidate)?;
        Ok(())
    }

    /// Signal that the remote peer has finished trickling candidates.
    pub fn set_remote_end_of_candidates(&self) -> Result<(), PeerConnectionError> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(PeerConnectionError::Closed);
        }
        if let Some(ice) = self.inner.ice.lock().as_ref() {
            ice.set_remote_end_of_candidates()?;
        }
        Ok(())
    }

    /// Swap the callback set at runtime.
    pub fn set_callbacks(&self, callbacks: PeerConnectionCallbacks) {
        *self.inner.callbacks.lock() = callbacks;
    }

    /// Close the PeerConnection and tear down the transport stack.
    /// Idempotent; fires `on_state_change(Closed)` exactly once.
    pub fn close(&self) -> Result<(), PeerConnectionError> {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // Tear down from the top down (SCTP → DTLS → ICE), mirroring the
        // C++ `PeerConnection::close()`.
        if let Some(sctp) = self.inner.sctp.lock().take() {
            let _ = sctp.close();
        }
        if let Some(dtls) = self.inner.dtls.lock().take() {
            let _ = dtls.close();
        }
        if let Some(ice) = self.inner.ice.lock().take() {
            let _ = ice.close();
        }
        self.force_state(PeerConnectionState::Closed);
        Ok(())
    }

    // -- internal: transport assembly -----------------------------------------

    /// Create the ICE transport if it doesn't exist yet, wiring its
    /// callbacks to the PeerConnection state machine. The `initial_role`
    /// is what the agent is built with; ICE resolves it further in
    /// `set_remote_description`.
    fn ensure_ice(&self, initial_role: Role) -> Result<Arc<IceTransport>, PeerConnectionError> {
        let mut guard = self.inner.ice.lock();
        if let Some(ice) = guard.as_ref() {
            return Ok(Arc::clone(ice));
        }

        let pc = self.clone();
        let pc_cand = self.clone();
        let pc_gather = self.clone();
        let callbacks = IceTransportCallbacks {
            on_state_change: Arc::new(move |s| pc.on_ice_state(s)),
            on_gathering_state_change: Arc::new(move |g| {
                pc_gather.on_ice_gathering_state(g)
            }),
            on_candidate: Arc::new(move |c| {
                // The driver populates the local credentials before firing
                // candidate callbacks, so this is the earliest reliable
                // point to fold ufrag/pwd into the stored local description.
                let _ = pc_cand.refresh_local_description();
                let cb = {
                    let g = pc_cand.inner.callbacks.lock();
                    Arc::clone(&g.on_local_candidate)
                };
                (cb)(c);
            }),
            on_data: Arc::new(|_| {}),
        };

        let ice = IceTransport::new(&self.inner.config, initial_role, callbacks)?;
        *guard = Some(Arc::clone(&ice));
        Ok(ice)
    }

    /// Render a local [`Description`] from the ICE transport's attributes,
    /// stamping the local DTLS fingerprint and an application m-line.
    ///
    /// libjuice mints the local ice-ufrag/pwd asynchronously (only once the
    /// driver task has processed the gather command), so right after
    /// `set_local_description`/`create_offer` kick off gathering the ICE
    /// transport may still report `NotAvailable`. In that case we render a
    /// credential-less skeleton (correct setup role + fingerprint +
    /// application m-line); the gathering callbacks then call
    /// [`Self::refresh_local_description`] to fold the ufrag/pwd in once
    /// they're available, and [`PeerConnection::local_description`] returns
    /// the complete SDP after gathering.
    fn build_local_description(
        &self,
        ice: &Arc<IceTransport>,
        typ: DescriptionType,
    ) -> Result<Description, PeerConnectionError> {
        // ICE gives us ufrag/pwd + the right setup role for the type. If the
        // credentials aren't minted yet, fall back to a role-correct
        // skeleton; the gathering callback will refresh it.
        let mut desc = match ice.get_local_description(typ) {
            Ok(d) => d,
            Err(IceTransportError::Juice(_)) => Description::new(typ, ice.role()),
            Err(e) => return Err(e.into()),
        };
        // Pin our certificate fingerprint.
        desc.set_fingerprint(self.inner.local_fingerprint.clone());
        // Ensure an application m-line so SCTP comes up. Reuse the mid ICE
        // already stamped (defaults to "0"); set the standard SCTP port.
        let mid = desc
            .application()
            .map(|a| a.mid().to_string())
            .unwrap_or_else(|| "0".to_string());
        let mut app = Application::new(mid);
        // Standard data-channel SCTP port (the SCTP transport's
        // DEFAULT_SCTP_PORT; kept private there, so spell it out here).
        app.set_sctp_port(5000);
        app.set_max_message_size(
            self.inner
                .config
                .max_message_size
                .unwrap_or(256 * 1024),
        );
        desc.set_application(app);
        desc.hint_type(typ);
        Ok(desc)
    }

    /// Re-render the stored local description from the current ICE
    /// attributes, folding in the ice-ufrag/pwd once libjuice has minted
    /// them. Called from the gathering / candidate callbacks (which fire
    /// after the driver has populated the local credentials) so that
    /// [`PeerConnection::local_description`] reflects the complete SDP. Also
    /// trickles the freshly-gathered local candidates into the stored
    /// description so a peer reading `local_description()` after gathering
    /// completes gets a self-contained offer/answer.
    ///
    /// Returns the refreshed description on success, or `None` if there's no
    /// pending local description or the credentials still aren't available.
    fn refresh_local_description(&self) -> Option<Description> {
        let typ = (*self.inner.pending_local_type.lock())?;
        let ice = self.inner.ice.lock().as_ref().cloned()?;
        // Only refresh once the credentials are actually mintable.
        let fresh = match ice.get_local_description(typ) {
            Ok(d) => d,
            Err(_) => return None,
        };
        let mut desc = fresh;
        desc.set_fingerprint(self.inner.local_fingerprint.clone());
        let mid = desc
            .application()
            .map(|a| a.mid().to_string())
            .unwrap_or_else(|| "0".to_string());
        let mut app = Application::new(mid);
        app.set_sctp_port(5000);
        app.set_max_message_size(self.inner.config.max_message_size.unwrap_or(256 * 1024));
        desc.set_application(app);
        desc.hint_type(typ);
        *self.inner.local_description.lock() = Some(desc.clone());

        // libdatachannel surfaces one complete local description for
        // signaling. `ice.get_local_description` only returns `Ok` once
        // libjuice has published the description with its minted ufrag/pwd, so
        // reaching here means the credentials are present. Fire
        // `on_local_description` exactly once per negotiation (the guard is
        // re-armed when a fresh local description is assembled).
        self.fire_local_description_once(&desc);

        Some(desc)
    }

    /// Surface a credential-complete local description via
    /// [`PeerConnectionCallbacks::on_local_description`], at most once per
    /// negotiation. The caller must have verified the description carries ICE
    /// credentials (every call site refreshes from libjuice's published
    /// description, which only exists once ufrag/pwd are minted). We
    /// nonetheless assert the credentials are present to keep the single-shot
    /// contract honest.
    fn fire_local_description_once(&self, desc: &Description) {
        debug_assert!(
            !desc.ice_ufrag().is_empty() && !desc.ice_pwd().is_empty(),
            "on_local_description must only fire with ICE credentials present"
        );
        if desc.ice_ufrag().is_empty() || desc.ice_pwd().is_empty() {
            return;
        }
        if self
            .inner
            .local_description_signalled
            .swap(true, Ordering::SeqCst)
        {
            return;
        }
        let cb = {
            let g = self.inner.callbacks.lock();
            Arc::clone(&g.on_local_description)
        };
        (cb)(desc.clone());
    }

    /// Pin the remote fingerprint (parsed from the stored remote
    /// description) onto the DTLS transport. No-op if we don't yet have a
    /// remote fingerprint.
    fn pin_remote_fingerprint(&self, dtls: &DtlsTransport) {
        let fp = self
            .inner
            .remote_description
            .lock()
            .as_ref()
            .and_then(|d| d.fingerprint().cloned());
        if let Some(fp) = fp {
            dtls.set_remote_fingerprint(fp);
        } else {
            warn!(
                "PeerConnection: DTLS coming up without a remote fingerprint; \
                 handshake will fail verification"
            );
        }
    }

    // -- internal: state handlers (mirror the C++ init*Transport closures) ----

    fn on_ice_state(&self, s: IceState) {
        if self.inner.closed.load(Ordering::SeqCst) {
            return;
        }
        match s {
            IceState::Checking => {
                self.change_state(PeerConnectionState::Connecting);
            }
            IceState::Connected | IceState::Completed => {
                // C++ initDtlsTransport() — create DTLS now that the role is
                // resolved, pin the remote fingerprint, and start it.
                self.init_dtls_transport();
            }
            IceState::Failed => {
                self.change_state(PeerConnectionState::Failed);
            }
            IceState::Disconnected => {
                self.change_state(PeerConnectionState::Disconnected);
            }
            IceState::New | IceState::Closed => {}
        }
    }

    fn on_ice_gathering_state(&self, g: IceGatheringState) {
        if self.inner.closed.load(Ordering::SeqCst) {
            return;
        }
        // Once gathering is underway the driver has minted ice-ufrag/pwd and
        // gathered candidates, so refresh the stored local description to
        // carry them (it was rendered credential-less if gathering hadn't
        // started yet when set_local_description ran).
        let _ = self.refresh_local_description();
        self.set_gathering_state(g.into());
    }

    /// Create + start the DTLS transport. Mirrors `initDtlsTransport()`:
    /// only runs once (guarded by the `dtls` slot), reads the SDP-resolved
    /// ICE role at construction time, pins the remote fingerprint, and
    /// drives the handshake.
    fn init_dtls_transport(&self) {
        let mut guard = self.inner.dtls.lock();
        if guard.is_some() {
            return;
        }

        let ice = match self.inner.ice.lock().as_ref().cloned() {
            Some(ice) => ice,
            None => {
                warn!("PeerConnection: ICE reached Connected but no ICE transport stored");
                return;
            }
        };

        let pc = self.clone();
        let dtls_cbs = DtlsTransportCallbacks {
            on_state_change: Arc::new(move |s| pc.on_dtls_state(s)),
            on_data: Arc::new(|_| {}),
        };

        // The certificate is cloned-by-reference into a fresh handle; the
        // DtlsTransport takes ownership of a Certificate, so generate the
        // SSL_CTX from our stored cert's X509 + pkey. We clone the
        // Certificate by re-wrapping its parts.
        let cert = match self.inner.certificate.try_clone() {
            Ok(c) => c,
            Err(e) => {
                warn!("PeerConnection: failed to clone local certificate: {e}");
                self.change_state(PeerConnectionState::Failed);
                return;
            }
        };

        let dtls = match DtlsTransport::new(Arc::clone(&ice), cert, dtls_cbs) {
            Ok(d) => d,
            Err(e) => {
                warn!("PeerConnection: DTLS transport init failed: {e}");
                self.change_state(PeerConnectionState::Failed);
                return;
            }
        };

        // Pin the remote fingerprint BEFORE starting the handshake.
        self.pin_remote_fingerprint(&dtls);

        *guard = Some(dtls.clone());
        drop(guard);

        // If the negotiated description carries an application m-line, bring
        // the SCTP transport up NOW — i.e. *before* DTLS reaches Connected —
        // so its auto-connect hook is installed on the (still-Connecting)
        // DTLS transport. When DTLS later reaches Connected, that hook
        // enqueues the `usrsctp_connect` onto the SCTP worker thread.
        //
        // This is the crucial ordering detail: SCTP's INIT chunk is emitted
        // synchronously from `usrsctp_connect` via `dtls.send()`, which
        // re-locks the DTLS inner mutex. DTLS fires its `on_state_change`
        // callback *while holding that mutex* (see
        // `dtls_transport::drive_handshake_locked`). If we created SCTP and
        // called `connect()` inline from our own `on_dtls_state(Connected)`
        // handler, that re-lock would deadlock. Deferring the connect to the
        // SCTP worker thread (via the auto-connect hook installed here)
        // sidesteps it — matching the design note in
        // `SctpTransport::new`.
        if self.negotiated_has_application() {
            self.init_sctp_transport();
        }

        // ICE is already Connected, so the DtlsTransport's own auto-start
        // hook (which fires on the ICE-Connected transition) has already
        // missed its window. Drive the handshake explicitly. start() is
        // idempotent, so a racing auto-start is harmless.
        if let Err(e) = dtls.start() {
            warn!("PeerConnection: DTLS start failed: {e}");
            self.change_state(PeerConnectionState::Failed);
        }
    }

    fn on_dtls_state(&self, s: DtlsState) {
        if self.inner.closed.load(Ordering::SeqCst) {
            return;
        }
        match s {
            DtlsState::Connecting => {
                self.change_state(PeerConnectionState::Connecting);
            }
            DtlsState::Connected => {
                // If the negotiated description carries an application
                // m-line, the SCTP transport was already created in
                // `init_dtls_transport` and its auto-connect hook (which
                // runs earlier in this same DTLS-Connected callback chain)
                // has enqueued the association open on the SCTP worker
                // thread; the aggregate state reaches Connected when SCTP
                // signals `SctpState::Connected`. With no application
                // m-line, the connection is Connected at the DTLS layer.
                //
                // NOTE: this handler runs while the DTLS inner mutex is held
                // (see `dtls_transport::drive_handshake_locked`), so it must
                // NOT call anything that re-enters DTLS (e.g. an inline SCTP
                // connect, which emits INIT via `dtls.send()`). It only
                // touches PeerConnection-local state here.
                if !self.negotiated_has_application() {
                    self.change_state(PeerConnectionState::Connected);
                }
            }
            DtlsState::Failed => {
                self.change_state(PeerConnectionState::Failed);
            }
            DtlsState::New | DtlsState::Closed => {}
        }
    }

    /// True if both local and remote descriptions advertise an application
    /// m-line (the data-channel path). Matches the C++ guard in
    /// `initSctpTransport()`.
    fn negotiated_has_application(&self) -> bool {
        let local_app = self
            .inner
            .local_description
            .lock()
            .as_ref()
            .map(|d| d.has_application())
            .unwrap_or(false);
        let remote_app = self
            .inner
            .remote_description
            .lock()
            .as_ref()
            .map(|d| d.has_application())
            .unwrap_or(false);
        local_app && remote_app
    }

    /// Create the SCTP transport. Mirrors `initSctpTransport()`, but is
    /// invoked from [`Self::init_dtls_transport`] *before* DTLS reaches
    /// Connected, so the [`SctpTransport`]'s auto-connect hook — installed on
    /// the lower DTLS transport by [`SctpTransport::new`] — is in place when
    /// DTLS connects. That hook enqueues the `usrsctp_connect` onto the SCTP
    /// worker thread, so the INIT chunk is *not* emitted inline from the
    /// DTLS-Connected callback (which holds the DTLS inner mutex). We
    /// therefore deliberately do NOT call `connect()` here.
    fn init_sctp_transport(&self) {
        let mut guard = self.inner.sctp.lock();
        if guard.is_some() {
            return;
        }

        let dtls = match self.inner.dtls.lock().as_ref().cloned() {
            Some(dtls) => dtls,
            None => {
                warn!("PeerConnection: cannot init SCTP — no DTLS transport stored");
                return;
            }
        };

        let pc = self.clone();
        let pc_msg = self.clone();
        let pc_low = self.clone();
        let sctp_cbs = SctpTransportCallbacks {
            on_state_change: Arc::new(move |s| pc.on_sctp_state(s)),
            on_message: Arc::new(move |m| pc_msg.on_sctp_message(m)),
            on_buffered_amount_low: Arc::new(move |stream| {
                if let Some(dc) = pc_low.inner.data_channels.lock().get(&stream) {
                    dc.fire_buffered_amount_low();
                }
            }),
        };

        // `SctpTransport::new` installs an auto-connect hook on `dtls` that
        // enqueues the association open onto the SCTP worker thread when DTLS
        // reaches Connected. Because we are called while DTLS is still
        // Connecting, that hook fires at the right moment — no inline
        // `connect()` (which would deadlock on the DTLS inner mutex).
        let sctp = SctpTransport::new(Arc::new(dtls), sctp_cbs);
        *guard = Some(sctp);
    }

    fn on_sctp_state(&self, s: SctpState) {
        if self.inner.closed.load(Ordering::SeqCst) {
            return;
        }
        match s {
            SctpState::Connecting => {
                self.change_state(PeerConnectionState::Connecting);
            }
            SctpState::Connected => {
                self.change_state(PeerConnectionState::Connected);
                // assignDataChannels() + openDataChannels(): now that the
                // DTLS role is resolved we can build the stream allocator,
                // assign stream ids to any channels created before SCTP came
                // up, attach the transport, and drive the DCEP OPEN for each.
                self.flush_local_channels();
            }
            SctpState::Failed => {
                self.change_state(PeerConnectionState::Failed);
            }
            SctpState::New | SctpState::Closed => {}
        }
    }

    // -- internal: DCEP / data-channel plumbing -------------------------------

    /// True if this peer is the DTLS **client** (resolved `a=setup:active`).
    /// Determines stream-id parity per RFC 8832 §6 (client = even).
    fn is_dtls_client(&self) -> bool {
        self.inner
            .ice
            .lock()
            .as_ref()
            .map(|i| matches!(i.role(), Role::Active))
            .unwrap_or(false)
    }

    /// Ensure the stream-id allocator exists, building it from the resolved
    /// DTLS role on first call. Returns a clone-free borrow via the closure
    /// is awkward; instead we just (idempotently) construct it.
    fn ensure_stream_allocator(&self) {
        let mut guard = self.inner.stream_allocator.lock();
        if guard.is_none() {
            *guard = Some(StreamIdAllocator::new(self.is_dtls_client()));
        }
    }

    /// Called once SCTP is `Connected`: build the allocator, assign stream
    /// ids to any channels parked before the role was known, attach the SCTP
    /// transport to every local channel, and drive the DCEP OPEN for each.
    fn flush_local_channels(&self) {
        self.ensure_stream_allocator();

        let sctp = match self.inner.sctp.lock().as_ref().cloned() {
            Some(s) => s,
            None => return,
        };

        // Assign stream ids to parked channels and move them into the map.
        let pending: Vec<DataChannel> =
            std::mem::take(&mut *self.inner.pending_local_channels.lock());
        for dc in pending {
            let stream = {
                let mut g = self.inner.stream_allocator.lock();
                g.as_mut().expect("allocator built above").allocate()
            };
            dc.assign_stream(stream);
            self.inner.data_channels.lock().insert(stream, dc);
        }

        // Attach the transport + drive OPEN for every local (non-incoming)
        // channel that isn't open yet.
        let channels: Vec<DataChannel> =
            self.inner.data_channels.lock().values().cloned().collect();
        for dc in channels {
            if dc.is_incoming() {
                continue;
            }
            dc.attach_transport(Arc::clone(&sctp));
            if let Err(e) = dc.send_open() {
                warn!("PeerConnection: failed to send DCEP OPEN: {e}");
            }
        }
    }

    /// Route an inbound SCTP message: Control(50)→DCEP handling; String/
    /// StringEmpty→text; Binary/BinaryEmpty→binary; everything else ignored
    /// (including the deprecated `*Partial` PPIDs, which never reach here as
    /// reassembled messages).
    fn on_sctp_message(&self, msg: SctpMessage) {
        if self.inner.closed.load(Ordering::SeqCst) {
            return;
        }
        match msg.ppid {
            PayloadProtocolId::Control => self.on_dcep_control(msg.stream, &msg.data),
            PayloadProtocolId::String => self.deliver_to_channel(msg.stream, &msg.data, false),
            PayloadProtocolId::StringEmpty => self.deliver_to_channel(msg.stream, &[], false),
            PayloadProtocolId::Binary => self.deliver_to_channel(msg.stream, &msg.data, true),
            PayloadProtocolId::BinaryEmpty => self.deliver_to_channel(msg.stream, &[], true),
            // Deprecated PPID-based fragments are reassembled below the SCTP
            // layer and never surface here; ignore defensively.
            PayloadProtocolId::StringPartial | PayloadProtocolId::BinaryPartial => {}
        }
    }

    /// Handle an inbound DCEP control message on `stream`.
    fn on_dcep_control(&self, stream: u16, data: &[u8]) {
        let parsed = match decode_control(data) {
            Ok(p) => p,
            Err(e) => {
                warn!("PeerConnection: bad DCEP control on stream {stream}: {e}");
                return;
            }
        };
        match parsed {
            DcepMessage::Open(open) => {
                // Inbound OPEN: a channel already on this stream (e.g. a
                // negotiated channel) just transitions open; otherwise build
                // an incoming channel, ACK it, and surface it.
                let existing = self.inner.data_channels.lock().get(&stream).cloned();
                let dc = match existing {
                    Some(dc) => dc,
                    None => {
                        let dc = DataChannel::new_incoming(stream, &open);
                        // Keep our allocator from re-handing-out this id.
                        self.ensure_stream_allocator();
                        if let Some(a) = self.inner.stream_allocator.lock().as_mut() {
                            a.reserve(stream);
                        }
                        self.inner.data_channels.lock().insert(stream, dc.clone());
                        dc
                    }
                };
                if let Some(sctp) = self.inner.sctp.lock().as_ref().cloned() {
                    dc.attach_transport(sctp);
                }
                // Reply with ACK and mark open, then surface to the app.
                if let Err(e) = dc.send_ack() {
                    warn!("PeerConnection: failed to send DCEP ACK: {e}");
                }
                dc.mark_open();
                let cb = {
                    let g = self.inner.callbacks.lock();
                    Arc::clone(&g.on_data_channel)
                };
                (cb)(dc);
            }
            DcepMessage::Ack => {
                // Inbound ACK: the locally-created channel on this stream is
                // now open.
                if let Some(dc) = self.inner.data_channels.lock().get(&stream).cloned() {
                    dc.mark_open();
                }
            }
        }
    }

    /// Deliver a user message to the channel bound to `stream`, if any.
    fn deliver_to_channel(&self, stream: u16, data: &[u8], binary: bool) {
        if let Some(dc) = self.inner.data_channels.lock().get(&stream).cloned() {
            dc.deliver_message(data, binary);
        }
    }

    // -- internal: state transition helpers -----------------------------------

    /// Apply a state transition with the C++ ordering guard: never move
    /// *out* of a terminal/forward state backwards. The C++ `changeState`
    /// simply compares-and-fires; we replicate the "don't regress past
    /// Connected to Connecting" behaviour loosely by only firing on an
    /// actual change, while still allowing Connected→Disconnected→Failed.
    fn change_state(&self, new_state: PeerConnectionState) {
        // Closed is terminal.
        let changed = {
            let mut g = self.inner.state.lock();
            if *g == PeerConnectionState::Closed {
                false
            } else if *g != new_state {
                // Don't regress Connected back to Connecting (a late ICE
                // Checking after SCTP is up). The C++ relies on the
                // transports firing in order; on loopback a stray
                // Connecting can arrive from a lower transport after a
                // higher one already reported Connected.
                if *g == PeerConnectionState::Connected
                    && new_state == PeerConnectionState::Connecting
                {
                    false
                } else {
                    *g = new_state;
                    true
                }
            } else {
                false
            }
        };
        if changed {
            let cb = {
                let g = self.inner.callbacks.lock();
                Arc::clone(&g.on_state_change)
            };
            (cb)(new_state);
        }
    }

    /// Force a state (used by `close()` to set Closed unconditionally).
    fn force_state(&self, new_state: PeerConnectionState) {
        let changed = {
            let mut g = self.inner.state.lock();
            if *g != new_state {
                *g = new_state;
                true
            } else {
                false
            }
        };
        if changed {
            let cb = {
                let g = self.inner.callbacks.lock();
                Arc::clone(&g.on_state_change)
            };
            (cb)(new_state);
        }
    }

    fn set_gathering_state(&self, new_state: GatheringState) {
        let changed = {
            let mut g = self.inner.gathering_state.lock();
            if *g != new_state {
                *g = new_state;
                true
            } else {
                false
            }
        };
        if changed {
            let cb = {
                let g = self.inner.callbacks.lock();
                Arc::clone(&g.on_gathering_state_change)
            };
            (cb)(new_state);
        }
    }

    fn set_signaling_state(&self, new_state: SignalingState) {
        let changed = {
            let mut g = self.inner.signaling_state.lock();
            if *g != new_state {
                *g = new_state;
                true
            } else {
                false
            }
        };
        if changed {
            let cb = {
                let g = self.inner.callbacks.lock();
                Arc::clone(&g.on_signaling_state_change)
            };
            (cb)(new_state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    async fn wait_for<F: FnMut() -> bool>(mut pred: F, timeout_ms: u64) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if pred() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    fn loopback_config() -> Configuration {
        let mut cfg = Configuration::new();
        cfg.bind_address = Some("127.0.0.1".to_string());
        cfg
    }

    #[test]
    fn construct_starts_in_new_stable() {
        let pc = PeerConnection::new(loopback_config(), PeerConnectionCallbacks::default())
            .expect("construct");
        assert_eq!(pc.state(), PeerConnectionState::New);
        assert_eq!(pc.signaling_state(), SignalingState::Stable);
        assert_eq!(pc.gathering_state(), GatheringState::New);
    }

    #[test]
    fn create_offer_emits_application_and_fingerprint() {
        rt().block_on(async {
            let pc = PeerConnection::new(loopback_config(), PeerConnectionCallbacks::default())
                .expect("construct");
            // The synchronously-returned offer carries the static bits
            // (application m-line, actpass setup, fingerprint, sctp-port).
            let offer = pc.create_offer().expect("offer");
            let sdp = offer.to_sdp();
            assert!(sdp.contains("m=application 9 UDP/DTLS/SCTP webrtc-datachannel"));
            assert!(sdp.contains("a=setup:actpass"), "offer must advertise actpass");
            assert!(sdp.contains("a=fingerprint:sha-256 "));
            assert!(sdp.contains("a=sctp-port:5000"));

            // The ice-ufrag/pwd are minted asynchronously by libjuice; apply
            // the offer (which starts gathering) and wait for the refreshed
            // local description to carry them.
            pc.set_local_description(DescriptionType::Offer)
                .expect("set local offer");
            assert!(
                wait_for(
                    || pc
                        .local_description()
                        .map(|d| {
                            let s = d.to_sdp();
                            s.contains("a=ice-ufrag:") && s.contains("a=ice-pwd:")
                        })
                        .unwrap_or(false),
                    3000,
                )
                .await,
                "local description never gained ice-ufrag/pwd"
            );
        });
    }

    #[test]
    fn set_local_offer_transitions_signaling() {
        rt().block_on(async {
            let pc = PeerConnection::new(loopback_config(), PeerConnectionCallbacks::default())
                .expect("construct");
            pc.set_local_description(DescriptionType::Offer).expect("set local");
            assert_eq!(pc.signaling_state(), SignalingState::HaveLocalOffer);
            assert!(pc.local_description().is_some());
        });
    }

    /// The real `on_local_description` callback (task #26) must fire exactly
    /// once per negotiation, and the SDP it delivers must already carry the
    /// ICE credentials (`a=ice-ufrag:` / `a=ice-pwd:`) that libjuice mints
    /// asynchronously — i.e. it never surfaces the credential-less skeleton.
    /// Mirrors the C-API contract that `rtcSetLocalDescriptionCallback` now
    /// backs.
    #[test]
    fn on_local_description_fires_once_with_ice_credentials() {
        rt().block_on(async {
            // Count fires and capture the SDP delivered to the callback.
            let count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
            let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

            let count_cb = count.clone();
            let captured_cb = captured.clone();
            let cbs = PeerConnectionCallbacks {
                on_local_description: Arc::new(move |d| {
                    *count_cb.lock() += 1;
                    *captured_cb.lock() = Some(d.to_sdp());
                }),
                ..PeerConnectionCallbacks::default()
            };

            let pc = PeerConnection::new(loopback_config(), cbs).expect("construct");
            // Registering a channel makes the offer carry the data path; not
            // strictly required for credentials but matches real usage.
            let _dc = pc.create_data_channel("chat");

            pc.set_local_description(DescriptionType::Offer)
                .expect("set local offer");

            // libjuice mints ufrag/pwd asynchronously; wait for the callback.
            assert!(
                wait_for(|| *count.lock() >= 1, 3000).await,
                "on_local_description never fired"
            );

            // The SDP delivered to the callback must already carry the ICE
            // credentials — never the credential-less skeleton.
            let sdp = captured.lock().clone().expect("captured sdp");
            assert!(
                sdp.contains("a=ice-ufrag:"),
                "local description callback fired without ice-ufrag; got:\n{sdp}"
            );
            assert!(
                sdp.contains("a=ice-pwd:"),
                "local description callback fired without ice-pwd; got:\n{sdp}"
            );

            // And `local_description()` read after the callback agrees.
            let read = pc.local_description().expect("local description").to_sdp();
            assert!(read.contains("a=ice-ufrag:") && read.contains("a=ice-pwd:"));

            // Give any in-flight gathering/candidate callbacks a moment to run
            // and confirm the callback stays single-shot for this negotiation.
            let _ = wait_for(|| pc.gathering_state() == GatheringState::Complete, 3000).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                *count.lock(),
                1,
                "on_local_description must fire exactly once per negotiation"
            );
        });
    }

    #[test]
    fn set_remote_without_fingerprint_errors() {
        rt().block_on(async {
            let pc = PeerConnection::new(loopback_config(), PeerConnectionCallbacks::default())
                .expect("construct");
            // A description with no fingerprint.
            let mut desc = Description::new(DescriptionType::Offer, Role::ActPass);
            desc.set_ice_ufrag("ufrag");
            desc.set_ice_pwd("password1234567890123456");
            desc.set_application(Application::new("0"));
            let err = pc.set_remote_description(desc).expect_err("must reject");
            assert!(matches!(err, PeerConnectionError::MissingRemoteFingerprint));
        });
    }

    #[test]
    fn close_is_idempotent_and_terminal() {
        rt().block_on(async {
            let pc = PeerConnection::new(loopback_config(), PeerConnectionCallbacks::default())
                .expect("construct");
            pc.close().expect("first close");
            pc.close().expect("second close");
            assert_eq!(pc.state(), PeerConnectionState::Closed);
            // Operations after close error out.
            assert!(matches!(
                pc.create_offer(),
                Err(PeerConnectionError::Closed)
            ));
        });
    }

    /// The gold-star integration test: two PeerConnections on loopback wire
    /// their `on_local_candidate` to each other, exchange offer/answer
    /// through the PUBLIC API, and both reach `Connected` — i.e. the
    /// ICE→DTLS→SCTP stack comes up through the facade, with role +
    /// fingerprint taken from the SDP (NOT manually pinned).
    #[test]
    fn two_peers_negotiate_to_connected_over_loopback() {
        rt().block_on(async {
            let t_start = std::time::Instant::now();

            let a_state: Arc<Mutex<PeerConnectionState>> =
                Arc::new(Mutex::new(PeerConnectionState::New));
            let b_state: Arc<Mutex<PeerConnectionState>> =
                Arc::new(Mutex::new(PeerConnectionState::New));

            // Candidate buffers — we forward each side's local candidates to
            // the other via add_remote_candidate.
            let a_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));
            let b_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));

            let a_state_cb = a_state.clone();
            let a_cands_cb = a_cands.clone();
            let a_cbs = PeerConnectionCallbacks {
                on_state_change: Arc::new(move |s| *a_state_cb.lock() = s),
                on_local_candidate: Arc::new(move |c| a_cands_cb.lock().push(c)),
                ..PeerConnectionCallbacks::default()
            };

            let b_state_cb = b_state.clone();
            let b_cands_cb = b_cands.clone();
            let b_cbs = PeerConnectionCallbacks {
                on_state_change: Arc::new(move |s| *b_state_cb.lock() = s),
                on_local_candidate: Arc::new(move |c| b_cands_cb.lock().push(c)),
                ..PeerConnectionCallbacks::default()
            };

            let pc_a = PeerConnection::new(loopback_config(), a_cbs).expect("pc a");
            let pc_b = PeerConnection::new(loopback_config(), b_cbs).expect("pc b");

            // A registers a data channel so the application m-line carries
            // the data path (and SCTP comes up).
            let _dc = pc_a.create_data_channel("chat");

            // --- A creates + sets the offer ---
            pc_a.set_local_description(DescriptionType::Offer)
                .expect("a set local offer");

            // Wait for A to finish gathering so the offer SDP we hand to B is
            // fully formed. libjuice mints ice-ufrag/pwd asynchronously, so
            // we read the *refreshed* local description (not the synchronous
            // return value) once gathering completes.
            assert!(
                wait_for(
                    || pc_a.gathering_state() == GatheringState::Complete,
                    3000
                )
                .await,
                "A never finished gathering"
            );
            let offer = pc_a.local_description().expect("a local description");
            assert!(
                offer.to_sdp().contains("a=ice-ufrag:"),
                "offer must carry ice-ufrag after gathering; got:\n{}",
                offer.to_sdp()
            );

            // --- B applies A's offer, then creates + sets its answer ---
            pc_b.set_remote_description(offer).expect("b set remote offer");
            pc_b.set_local_description(DescriptionType::Answer)
                .expect("b set local answer");
            assert!(
                wait_for(
                    || pc_b.gathering_state() == GatheringState::Complete,
                    3000
                )
                .await,
                "B never finished gathering"
            );
            let answer = pc_b.local_description().expect("b local description");
            assert!(
                answer.to_sdp().contains("a=setup:active"),
                "answerer must resolve to active (DTLS client); got:\n{}",
                answer.to_sdp()
            );

            // --- A applies B's answer ---
            pc_a.set_remote_description(answer).expect("a set remote answer");

            // --- Trickle candidates both ways via the public API ---
            for c in a_cands.lock().iter() {
                let _ = pc_b.add_remote_candidate(c);
            }
            for c in b_cands.lock().iter() {
                let _ = pc_a.add_remote_candidate(c);
            }
            pc_a.set_remote_end_of_candidates().expect("a eoc");
            pc_b.set_remote_end_of_candidates().expect("b eoc");

            // --- Wait for both to reach Connected ---
            let connected = wait_for(
                || {
                    *a_state.lock() == PeerConnectionState::Connected
                        && *b_state.lock() == PeerConnectionState::Connected
                },
                12000,
            )
            .await;
            let elapsed = t_start.elapsed();

            assert!(
                connected,
                "peers did not reach Connected in {:?}: a={:?}, b={:?}",
                elapsed,
                *a_state.lock(),
                *b_state.lock(),
            );
            eprintln!("PeerConnection loopback converged in {:?}", elapsed);

            assert_eq!(pc_a.state(), PeerConnectionState::Connected);
            assert_eq!(pc_b.state(), PeerConnectionState::Connected);
        });
    }

    /// End-to-end DataChannel test: two PeerConnections negotiate to
    /// Connected, A creates a data channel "chat", B receives it via
    /// `on_data_channel` (driven by an inbound DCEP OPEN), then a message
    /// round-trips A→B and B→A through the channel, asserted byte-equal.
    #[test]
    fn data_channel_message_round_trips_over_loopback() {
        rt().block_on(async {
            let a_state: Arc<Mutex<PeerConnectionState>> =
                Arc::new(Mutex::new(PeerConnectionState::New));
            let b_state: Arc<Mutex<PeerConnectionState>> =
                Arc::new(Mutex::new(PeerConnectionState::New));
            let a_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));
            let b_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));

            // B's inbound channel + the messages each side receives.
            let b_channel: Arc<Mutex<Option<DataChannel>>> = Arc::new(Mutex::new(None));
            let b_recv: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let a_recv: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));

            let a_state_cb = a_state.clone();
            let a_cands_cb = a_cands.clone();
            let a_cbs = PeerConnectionCallbacks {
                on_state_change: Arc::new(move |s| *a_state_cb.lock() = s),
                on_local_candidate: Arc::new(move |c| a_cands_cb.lock().push(c)),
                ..PeerConnectionCallbacks::default()
            };

            let b_state_cb = b_state.clone();
            let b_cands_cb = b_cands.clone();
            let b_channel_cb = b_channel.clone();
            let b_recv_cb = b_recv.clone();
            let b_cbs = PeerConnectionCallbacks {
                on_state_change: Arc::new(move |s| *b_state_cb.lock() = s),
                on_local_candidate: Arc::new(move |c| b_cands_cb.lock().push(c)),
                on_data_channel: Arc::new(move |dc| {
                    // Install message callbacks on the inbound channel and
                    // stash it so the test body can send back on it.
                    let recv = b_recv_cb.clone();
                    dc.set_callbacks(DataChannelCallbacks {
                        on_message: Arc::new(move |data, _binary| {
                            recv.lock().push(data.to_vec());
                        }),
                        ..DataChannelCallbacks::default()
                    });
                    *b_channel_cb.lock() = Some(dc);
                }),
                ..PeerConnectionCallbacks::default()
            };

            let pc_a = PeerConnection::new(loopback_config(), a_cbs).expect("pc a");
            let pc_b = PeerConnection::new(loopback_config(), b_cbs).expect("pc b");

            // A creates the channel and installs its own receive callback.
            let dc_a = pc_a.create_data_channel("chat");
            let a_recv_cb = a_recv.clone();
            dc_a.set_callbacks(DataChannelCallbacks {
                on_message: Arc::new(move |data, _binary| {
                    a_recv_cb.lock().push(data.to_vec());
                }),
                ..DataChannelCallbacks::default()
            });

            // --- Offer/answer + trickle (same dance as the connect test) ---
            pc_a.set_local_description(DescriptionType::Offer)
                .expect("a set local offer");
            assert!(
                wait_for(|| pc_a.gathering_state() == GatheringState::Complete, 3000).await,
                "A never finished gathering"
            );
            let offer = pc_a.local_description().expect("a local description");

            pc_b.set_remote_description(offer).expect("b set remote offer");
            pc_b.set_local_description(DescriptionType::Answer)
                .expect("b set local answer");
            assert!(
                wait_for(|| pc_b.gathering_state() == GatheringState::Complete, 3000).await,
                "B never finished gathering"
            );
            let answer = pc_b.local_description().expect("b local description");
            pc_a.set_remote_description(answer).expect("a set remote answer");

            for c in a_cands.lock().iter() {
                let _ = pc_b.add_remote_candidate(c);
            }
            for c in b_cands.lock().iter() {
                let _ = pc_a.add_remote_candidate(c);
            }
            pc_a.set_remote_end_of_candidates().expect("a eoc");
            pc_b.set_remote_end_of_candidates().expect("b eoc");

            // --- Wait for both peers to reach Connected ---
            assert!(
                wait_for(
                    || {
                        *a_state.lock() == PeerConnectionState::Connected
                            && *b_state.lock() == PeerConnectionState::Connected
                    },
                    12000,
                )
                .await,
                "peers did not reach Connected: a={:?}, b={:?}",
                *a_state.lock(),
                *b_state.lock(),
            );

            // --- B receives the channel via DCEP OPEN ---
            assert!(
                wait_for(|| b_channel.lock().is_some(), 5000).await,
                "B never received the data channel via on_data_channel"
            );
            let dc_b = b_channel.lock().clone().expect("b channel");
            assert_eq!(dc_b.label(), "chat", "inbound channel label must match");
            // RFC 8832 §6: A is the offerer → DTLS server (passive) → odd id;
            // B is the answerer → DTLS client (active) → even id. A created
            // the channel, so it carries A's (odd) parity on both ends.
            assert_eq!(dc_b.stream() % 2, 1, "A's channel id must be odd (A is DTLS server)");
            assert_eq!(dc_a.stream(), dc_b.stream(), "both ends share the stream id");

            // A's channel opens once the ACK arrives.
            assert!(
                wait_for(|| dc_a.is_open(), 5000).await,
                "A's channel never opened (no DCEP ACK?)"
            );

            // --- A → B ---
            dc_a.send_text("hello-from-a").expect("a send");
            assert!(
                wait_for(|| !b_recv.lock().is_empty(), 5000).await,
                "B never received A's message"
            );
            assert_eq!(b_recv.lock()[0], b"hello-from-a");

            // --- B → A ---
            dc_b.send_binary(b"hello-from-b").expect("b send");
            assert!(
                wait_for(|| !a_recv.lock().is_empty(), 5000).await,
                "A never received B's message"
            );
            assert_eq!(a_recv.lock()[0], b"hello-from-b");

            pc_a.close().expect("close a");
            pc_b.close().expect("close b");
        });
    }
}
