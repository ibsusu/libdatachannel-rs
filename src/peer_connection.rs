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
//! ## DataChannel scope (#17 vs #18)
//!
//! `create_data_channel` here is the **minimal** registration the task
//! calls for: it records the requested channel (label + optional id),
//! ensures the application m-line is advertised so SCTP comes up, and
//! exposes an `on_data_channel` hook. The full DCEP `OPEN`/`ACK` handshake
//! and the `DataChannel` object itself are **task #18** — see the `TODO`s on
//! [`PeerConnection::create_data_channel`].

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
    SctpState, SctpTransport, SctpTransportCallbacks,
};
use crate::candidate::Candidate;

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
    /// Fires for each local ICE candidate the agent surfaces (trickle).
    pub on_local_candidate: Arc<dyn Fn(Candidate) + Send + Sync>,
    /// Fires when the remote peer opens a data channel. Phase #17 only
    /// surfaces the channel **label**; the full `DataChannel` object lands
    /// in #18 with the DCEP protocol.
    pub on_data_channel: Arc<dyn Fn(String) + Send + Sync>,
}

impl Default for PeerConnectionCallbacks {
    fn default() -> Self {
        PeerConnectionCallbacks {
            on_state_change: Arc::new(|_| {}),
            on_gathering_state_change: Arc::new(|_| {}),
            on_signaling_state_change: Arc::new(|_| {}),
            on_local_candidate: Arc::new(|_| {}),
            on_data_channel: Arc::new(|_| {}),
        }
    }
}

/// A registered (but not yet DCEP-opened) data channel.
///
/// Phase #17 only tracks the label and the locally-assigned stream id; the
/// actual open handshake is task #18.
#[derive(Debug, Clone)]
pub struct DataChannelStub {
    /// Application-supplied label.
    pub label: String,
    /// Locally-assigned SCTP stream id (even for the DTLS client, odd for
    /// the server — RFC 8832 §6). Assigned lazily once SCTP is up in #18;
    /// `None` until then.
    pub stream: Option<u16>,
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

    // --- state ---
    state: Mutex<PeerConnectionState>,
    gathering_state: Mutex<GatheringState>,
    signaling_state: Mutex<SignalingState>,

    /// Data channels registered via [`PeerConnection::create_data_channel`].
    data_channels: Mutex<Vec<DataChannelStub>>,

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
            state: Mutex::new(PeerConnectionState::New),
            gathering_state: Mutex::new(GatheringState::New),
            signaling_state: Mutex::new(SignalingState::Stable),
            data_channels: Mutex::new(Vec::new()),
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

    // -- data channels (minimal — full DCEP is #18) ---------------------------

    /// Register a data channel by label.
    ///
    /// **Scope (task #17):** this is the minimal registration the task
    /// asks for. It records the channel so the application m-line is
    /// advertised (ensuring the SCTP transport is brought up during
    /// negotiation), and returns a [`DataChannelStub`].
    ///
    /// TODO(#18): drive the DCEP `DATA_CHANNEL_OPEN` / `ACK` protocol over
    /// SCTP, assign the stream id per RFC 8832 §6 (even for the DTLS
    /// client, odd for the server), expose a real `DataChannel` handle, and
    /// fire `on_data_channel` on the remote side from an inbound DCEP OPEN
    /// rather than from this stub.
    pub fn create_data_channel(&self, label: impl Into<String>) -> DataChannelStub {
        let stub = DataChannelStub {
            label: label.into(),
            stream: None,
        };
        self.inner.data_channels.lock().push(stub.clone());
        stub
    }

    /// Currently-registered data channel stubs.
    pub fn data_channels(&self) -> Vec<DataChannelStub> {
        self.inner.data_channels.lock().clone()
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
        Some(desc)
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
        let sctp_cbs = SctpTransportCallbacks {
            on_state_change: Arc::new(move |s| pc.on_sctp_state(s)),
            on_message: Arc::new(|_| {
                // TODO(#18): route inbound SCTP messages to DataChannels and
                // parse DCEP control messages here.
            }),
            on_buffered_amount_low: Arc::new(|_| {}),
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
                // TODO(#18): assignDataChannels() + openDataChannels() —
                // drive DCEP OPEN for every channel registered via
                // create_data_channel, and fire on_data_channel for inbound
                // OPENs.
            }
            SctpState::Failed => {
                self.change_state(PeerConnectionState::Failed);
            }
            SctpState::New | SctpState::Closed => {}
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
}
