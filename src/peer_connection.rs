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

use crate::candidate::Candidate;
use crate::certificate::{Certificate, CertificateError};
use crate::configuration::Configuration;
use crate::data_channel::{
    DataChannel, DataChannelCallbacks, DataChannelInit, DcepMessage, StreamIdAllocator,
    decode_control,
};
use crate::description::MediaSection;
use crate::description::{
    Application, Description, DescriptionParseError, Fingerprint, FingerprintAlgorithm, Role,
    Type as DescriptionType,
};
use crate::dtls_transport::{DtlsState, DtlsTransport, DtlsTransportCallbacks, DtlsTransportError};
use crate::ice_transport::{
    GatheringState as IceGatheringState, IceTransport, IceTransportCallbacks, IceTransportError,
    State as IceState,
};
use crate::media_handler::{MediaHandler, Message, Sender as MediaSender};
use crate::rtp::RtpHeader;
use crate::sctp_transport::{
    PayloadProtocolId, SctpMessage, SctpState, SctpTransport, SctpTransportCallbacks,
};
use crate::srtp_transport::{SrtpTransport, SrtpTransportCallbacks};
use crate::track::{Track, TrackCallbacks, TrackInit};

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
    /// Fires on every ICE transport state transition (the underlying
    /// [`IceState`], before it is folded into the aggregate
    /// [`PeerConnectionState`]). Mirrors libdatachannel's `onIceStateChange`.
    pub on_ice_state_change: Arc<dyn Fn(IceState) + Send + Sync>,
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
    /// Fires when a remote media track is negotiated (a remote `m=audio` /
    /// `m=video` section appears in an applied remote description that this
    /// peer didn't create locally). Delivers a real [`Track`] handle, already
    /// recorded so inbound RTP for its SSRC routes to it once the DTLS-SRTP
    /// transport is up; install callbacks via [`Track::set_callbacks`].
    pub on_track: Arc<dyn Fn(Arc<Track>) + Send + Sync>,
}

impl Default for PeerConnectionCallbacks {
    fn default() -> Self {
        PeerConnectionCallbacks {
            on_state_change: Arc::new(|_| {}),
            on_gathering_state_change: Arc::new(|_| {}),
            on_ice_state_change: Arc::new(|_| {}),
            on_signaling_state_change: Arc::new(|_| {}),
            on_local_description: Arc::new(|_| {}),
            on_local_candidate: Arc::new(|_| {}),
            on_data_channel: Arc::new(|_| {}),
            on_track: Arc::new(|_| {}),
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
    /// DTLS-SRTP media transport, created alongside SCTP in
    /// [`Self::init_dtls_transport`] when media has been negotiated. Inbound
    /// RTP/RTCP demuxes off this transport's `on_rtp`/`on_rtcp` hooks and
    /// routes to the track bound to the packet's SSRC.
    srtp: Mutex<Option<Arc<SrtpTransport>>>,

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

    /// Media tracks keyed by their `mid`. Holds both locally-added tracks
    /// (via [`PeerConnection::add_track`]) and remote tracks surfaced through
    /// `on_track`. Each entry records the track plus the SSRC it carries so
    /// inbound RTP can be routed to the right track.
    tracks: Mutex<std::collections::HashMap<String, TrackEntry>>,

    /// The PeerConnection-global media handler, set via
    /// [`PeerConnection::set_media_handler`]. Mirrors `mMediaHandler` in
    /// `impl::PeerConnection`: a single handler (which may itself be a chain
    /// head) applied to all inbound/outbound media, distinct from the
    /// per-[`Track`] chain. `None` until set; cleared on
    /// [`close`](PeerConnection::close).
    media_handler: Mutex<Option<Box<dyn MediaHandler>>>,

    /// True once we are the offerer (so we know to advertise actpass and
    /// know whether the local m-line should exist for SCTP).
    closed: AtomicBool,
}

/// A recorded track plus the metadata the PeerConnection needs to advertise
/// its media section and route inbound RTP.
struct TrackEntry {
    track: Arc<Track>,
    /// The modeled media section advertised for this track in the local SDP.
    media: MediaSection,
    /// The SSRC this track sends/receives on (for inbound RTP routing).
    ssrc: u32,
    /// True for a remote track (surfaced via `on_track`) — these are NOT
    /// advertised in our local description (the remote already did).
    remote: bool,
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
            srtp: Mutex::new(None),
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
            tracks: Mutex::new(std::collections::HashMap::new()),
            media_handler: Mutex::new(None),
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

    /// Whether automatic (re)negotiation is disabled for this connection.
    ///
    /// When `false` (the default), the C-API layer mirrors
    /// `rtc::PeerConnection` by generating an offer when the first data
    /// channel/track is added and an answer when a remote offer is applied.
    /// The Rust API itself always negotiates explicitly via
    /// [`set_local_description`](Self::set_local_description).
    pub fn disable_auto_negotiation(&self) -> bool {
        self.inner.config.disable_auto_negotiation
    }

    /// The local SDP, if a local description has been set.
    pub fn local_description(&self) -> Option<Description> {
        self.inner.local_description.lock().clone()
    }

    /// The remote SDP, if a remote description has been set.
    pub fn remote_description(&self) -> Option<Description> {
        self.inner.remote_description.lock().clone()
    }

    /// The negotiated maximum size for an outgoing message: the smaller of the
    /// remote peer's advertised `max-message-size` and our local maximum.
    /// Mirrors `PeerConnection::remoteMaxMessageSize()`. Per RFC 8841 a remote
    /// value of 0 means "no limit" (so the local max wins); when the remote SDP
    /// carries no application section or attribute, the 64 KiB remote default
    /// applies.
    pub fn remote_max_message_size(&self) -> usize {
        const DEFAULT_LOCAL_MAX_MESSAGE_SIZE: usize = 256 * 1024;
        const DEFAULT_REMOTE_MAX_MESSAGE_SIZE: usize = 65536;
        let local_max = self
            .inner
            .config
            .max_message_size
            .unwrap_or(DEFAULT_LOCAL_MAX_MESSAGE_SIZE);
        let mut remote_max = DEFAULT_REMOTE_MAX_MESSAGE_SIZE;
        if let Some(desc) = self.inner.remote_description.lock().as_ref() {
            if let Some(app) = desc.application() {
                if let Some(max) = app.max_message_size() {
                    remote_max = if max > 0 { max } else { usize::MAX };
                }
            }
        }
        remote_max.min(local_max)
    }

    /// The local certificate fingerprint (SHA-256) advertised in the SDP.
    pub fn local_fingerprint(&self) -> Fingerprint {
        self.inner.local_fingerprint.clone()
    }

    /// The selected local socket address (`"ip port"` form), or `None` if no
    /// candidate pair has been nominated. Mirrors `PeerConnection::localAddress()`.
    pub fn local_address(&self) -> Option<String> {
        let ice = self.inner.ice.lock().as_ref().cloned()?;
        ice.get_selected_addresses().ok().map(|(local, _)| local)
    }

    /// The selected remote socket address (`"ip port"` form), or `None` if no
    /// candidate pair has been nominated. Mirrors `PeerConnection::remoteAddress()`.
    pub fn remote_address(&self) -> Option<String> {
        let ice = self.inner.ice.lock().as_ref().cloned()?;
        ice.get_selected_addresses().ok().map(|(_, remote)| remote)
    }

    /// The selected `(local, remote)` candidate pair, or `None` if no pair has
    /// been nominated. Mirrors `PeerConnection::getSelectedCandidatePair()`.
    pub fn selected_candidate_pair(&self) -> Option<(Candidate, Candidate)> {
        let ice = self.inner.ice.lock().as_ref().cloned()?;
        ice.get_selected_pair().ok()
    }

    /// The highest usable SCTP stream id for data channels. Mirrors
    /// `PeerConnection::maxDataChannelStream()`: the negotiated stream count
    /// less one, defaulting to `MAX_SCTP_STREAMS_COUNT - 1` (1023) when the
    /// association has not negotiated a smaller count.
    pub fn max_data_channel_stream(&self) -> u16 {
        match self.inner.sctp.lock().as_ref() {
            Some(sctp) => sctp.max_stream(),
            None => crate::sctp_transport::MAX_SCTP_STREAMS_COUNT - 1,
        }
    }

    // -- data channels (DCEP, task #18) ---------------------------------------

    /// Create a locally-initiated data channel with default settings.
    /// Equivalent to [`create_data_channel_ext`](Self::create_data_channel_ext)
    /// with a default [`DataChannelInit`] and no callbacks.
    pub fn create_data_channel(&self, label: impl Into<String>) -> DataChannel {
        self.create_data_channel_ext(
            label,
            DataChannelInit::default(),
            DataChannelCallbacks::default(),
        )
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

    /// Whether the local description should carry an application (SCTP
    /// data-channel) m-line. Mirrors upstream `populateLocalDescription`,
    /// which adds it only when data channels exist (offer) or to reciprocate
    /// a remote application section (answer). A track-only peer with no data
    /// channels therefore produces a media-only SDP and never starts SCTP.
    fn wants_application(&self) -> bool {
        if !self.inner.data_channels.lock().is_empty()
            || !self.inner.pending_local_channels.lock().is_empty()
        {
            return true;
        }
        // Reciprocate / preserve a negotiated application section.
        self.inner
            .remote_description
            .lock()
            .as_ref()
            .map(|d| d.has_application())
            .unwrap_or(false)
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

    // -- media tracks (task #27) ----------------------------------------------

    /// Add a local media track. Records the track so its `m=audio`/`m=video`
    /// section is advertised in the next local description, and so inbound RTP
    /// for its SSRC routes to it once the DTLS-SRTP transport is up. Returns a
    /// real [`Track`] handle.
    ///
    /// Mirrors `rtc::PeerConnection::addTrack`. The track is **not** open until
    /// the media transport's keys are derived (after the DTLS handshake); it
    /// fires `on_open` then. Sending before that errors with
    /// [`crate::TrackError::NotOpen`].
    pub fn add_track(&self, init: TrackInit) -> Arc<Track> {
        self.add_track_with(init, TrackCallbacks::default())
    }

    /// Like [`add_track`](Self::add_track) but with callbacks installed up
    /// front (so they are present before the track opens).
    pub fn add_track_with(&self, init: TrackInit, callbacks: TrackCallbacks) -> Arc<Track> {
        let media = MediaSection::from_track_media(&crate::TrackMedia::from_init(&init));
        let ssrc = init.ssrc;
        let mid = init.mid.clone();
        let track = Track::new(init, callbacks);
        self.inner.tracks.lock().insert(
            mid,
            TrackEntry {
                track: Arc::clone(&track),
                media,
                ssrc,
                remote: false,
            },
        );
        // If the SRTP transport is already up (track added after connect),
        // open the track immediately.
        if let Some(srtp) = self.inner.srtp.lock().as_ref().cloned() {
            if srtp.is_ready() {
                track.open(srtp);
            }
        }
        track
    }

    /// Snapshot of all recorded tracks (local + remote) in arbitrary order.
    pub fn tracks(&self) -> Vec<Arc<Track>> {
        self.inner
            .tracks
            .lock()
            .values()
            .map(|e| Arc::clone(&e.track))
            .collect()
    }

    /// Install the PeerConnection-global media handler, mirroring
    /// `rtc::PeerConnection::setMediaHandler`. This handler runs over all
    /// inbound media (in [`route_inbound_media`](Self::route_inbound_media))
    /// before per-track routing, and is distinct from the per-[`Track`] chain
    /// installed with [`Track::chain_media_handler`]. Replaces any previously
    /// set handler. Pass a [`MediaHandlerChain`](crate::media_handler::MediaHandlerChain)
    /// (which itself implements [`MediaHandler`]) to install several at once.
    pub fn set_media_handler(&self, handler: Box<dyn MediaHandler>) {
        *self.inner.media_handler.lock() = Some(handler);
    }

    /// Whether a PeerConnection-global media handler is currently set. Mirrors
    /// `rtc::PeerConnection::getMediaHandler` (which returns the handler
    /// `shared_ptr`); since [`MediaHandler`] is not clonable we expose its
    /// presence rather than handing out the boxed trait object, matching how
    /// [`Track::media_handler_count`] surfaces its chain.
    #[must_use]
    pub fn has_media_handler(&self) -> bool {
        self.inner.media_handler.lock().is_some()
    }

    /// True if any media (audio/video) track has been added locally.
    fn has_local_media(&self) -> bool {
        self.inner.tracks.lock().values().any(|e| !e.remote)
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
    pub fn set_remote_description(&self, desc: Description) -> Result<(), PeerConnectionError> {
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

        // Surface any remote media tracks (m=audio/m=video sections we didn't
        // add locally) via `on_track`. Mirrors libdatachannel's incoming-track
        // negotiation: each remote section creates a Track recorded under its
        // mid + SSRC so inbound RTP routes to it; the app installs callbacks
        // and the track opens once SRTP keys are derived.
        self.surface_remote_tracks();

        self.set_signaling_state(next_sig);

        Ok(())
    }

    /// Create + surface a [`Track`] for each remote media section we don't
    /// already track locally. Called from [`Self::set_remote_description`].
    fn surface_remote_tracks(&self) {
        let remote = match self.inner.remote_description.lock().as_ref().cloned() {
            Some(d) => d,
            None => return,
        };
        let mut new_tracks: Vec<Arc<Track>> = Vec::new();
        {
            let mut tracks = self.inner.tracks.lock();
            for media in remote.media_sections() {
                let mid = media.mid().to_string();
                if tracks.contains_key(&mid) {
                    continue; // locally added or already surfaced
                }
                // Our local direction is the reciprocal of the remote's: if the
                // remote is sendonly we are recvonly, and vice-versa.
                let local_dir = match media.direction() {
                    crate::Direction::SendOnly => crate::Direction::RecvOnly,
                    crate::Direction::RecvOnly => crate::Direction::SendOnly,
                    other => other,
                };
                // Pick the first advertised payload type / codec.
                let (payload_type, ssrc) = (
                    media
                        .rtp_maps()
                        .first()
                        .map(|m| m.payload_type)
                        .unwrap_or(0),
                    media.ssrcs().first().map(|s| s.ssrc).unwrap_or(0),
                );
                let codec = media
                    .rtp_maps()
                    .first()
                    .and_then(|m| codec_from_rtpmap(&m.format))
                    .unwrap_or(crate::Codec::H264);
                let init = TrackInit::new(local_dir, codec, payload_type, ssrc, mid.clone());
                // The media section WE advertise in the answer mirrors the
                // offer's payload type / mid but carries OUR (reciprocal)
                // direction. Build it from the track's own media description.
                let local_media = MediaSection::from_track_media(
                    &Track::new(init.clone(), TrackCallbacks::default()).description(),
                );
                let track = Track::new(init, TrackCallbacks::default());
                tracks.insert(
                    mid,
                    TrackEntry {
                        track: Arc::clone(&track),
                        media: local_media,
                        ssrc,
                        remote: true,
                    },
                );
                new_tracks.push(track);
            }
        }
        // If SRTP is already up, open the freshly-surfaced tracks.
        if let Some(srtp) = self.inner.srtp.lock().as_ref().cloned() {
            if srtp.is_ready() {
                for t in &new_tracks {
                    t.open(Arc::clone(&srtp));
                }
            }
        }
        let cb = {
            let g = self.inner.callbacks.lock();
            Arc::clone(&g.on_track)
        };
        for t in new_tracks {
            (cb)(t);
        }
    }

    /// Trickle a remote ICE candidate received out of band.
    pub fn add_remote_candidate(&self, candidate: &Candidate) -> Result<(), PeerConnectionError> {
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
        // Close all media tracks first.
        for entry in self.inner.tracks.lock().values() {
            entry.track.close();
        }
        // Drop the PC-global media handler (mirrors `setMediaHandler(nullptr)`
        // in the C++ `close()`).
        *self.inner.media_handler.lock() = None;
        // Tear down from the top down (SCTP / SRTP → DTLS → ICE), mirroring
        // the C++ `PeerConnection::close()`.
        if let Some(sctp) = self.inner.sctp.lock().take() {
            sctp.set_callbacks(SctpTransportCallbacks::default());
            let _ = sctp.close();
        }
        if let Some(srtp) = self.inner.srtp.lock().take() {
            srtp.set_callbacks(SrtpTransportCallbacks::default());
            let _ = srtp.close();
        }
        if let Some(dtls) = self.inner.dtls.lock().take() {
            dtls.set_callbacks(DtlsTransportCallbacks::default());
            let _ = dtls.close();
        }
        if let Some(ice) = self.inner.ice.lock().take() {
            ice.set_callbacks(IceTransportCallbacks::default());
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
            on_gathering_state_change: Arc::new(move |g| pc_gather.on_ice_gathering_state(g)),
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
        // Add an application m-line so SCTP comes up — but only when data
        // channels exist / are negotiated. Reuse the mid ICE already stamped
        // (defaults to "0"); set the standard SCTP port.
        if self.wants_application() {
            let mid = desc
                .application()
                .map(|a| a.mid().to_string())
                .unwrap_or_else(|| "0".to_string());
            let mut app = Application::new(mid);
            // Standard data-channel SCTP port (the SCTP transport's
            // DEFAULT_SCTP_PORT; kept private there, so spell it out here).
            app.set_sctp_port(5000);
            app.set_max_message_size(self.inner.config.max_message_size.unwrap_or(256 * 1024));
            desc.set_application(app);
        }
        self.apply_local_media(&mut desc);
        desc.hint_type(typ);
        Ok(desc)
    }

    /// Fold every recorded track's media section into the description. Both
    /// locally-added tracks and remote tracks are advertised: the answerer
    /// must echo the offer's m-lines (with its own reciprocal direction), and
    /// `TrackEntry::media` already holds OUR side's section for remote tracks
    /// (see [`Self::surface_remote_tracks`]).
    fn apply_local_media(&self, desc: &mut Description) {
        let tracks = self.inner.tracks.lock();
        for entry in tracks.values() {
            desc.add_media(entry.media.clone());
        }
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
        if self.wants_application() {
            let mid = desc
                .application()
                .map(|a| a.mid().to_string())
                .unwrap_or_else(|| "0".to_string());
            let mut app = Application::new(mid);
            app.set_sctp_port(5000);
            app.set_max_message_size(self.inner.config.max_message_size.unwrap_or(256 * 1024));
            desc.set_application(app);
        }
        self.apply_local_media(&mut desc);
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
        // Surface the raw ICE state to observers before folding it into the
        // aggregate PeerConnectionState (mirrors libdatachannel's separate
        // onIceStateChange hook). Clone the callback out of the lock so we
        // don't hold the callbacks mutex across the user callback.
        let ice_cb = {
            let g = self.inner.callbacks.lock();
            Arc::clone(&g.on_ice_state_change)
        };
        (ice_cb)(s);
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

        // Likewise bring the DTLS-SRTP media transport up *before* the
        // handshake starts, so the `use_srtp` extension is present on the
        // ClientHello/ServerHello (SrtpTransport::new sets it via
        // SSL_set_tlsext_use_srtp). The transport derives its keys off the
        // DTLS-Connected callback (on its own worker thread) and demuxes
        // inbound media off the chained DTLS on_data hook.
        if self.negotiated_has_media() {
            self.init_srtp_transport();
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

    /// Create the DTLS-SRTP transport and route its inbound RTP/RTCP to the
    /// recorded tracks. Runs once (guarded by the `srtp` slot). Called from
    /// [`Self::init_dtls_transport`] *before* `dtls.start()` so the `use_srtp`
    /// extension is set on the handshake. When SRTP signals Connected (keys
    /// derived) every recorded track is opened so it can send/receive.
    fn init_srtp_transport(&self) {
        let mut guard = self.inner.srtp.lock();
        if guard.is_some() {
            return;
        }
        let dtls = match self.inner.dtls.lock().as_ref().cloned() {
            Some(dtls) => dtls,
            None => {
                warn!("PeerConnection: cannot init SRTP — no DTLS transport stored");
                return;
            }
        };

        let pc_rtp = self.clone();
        let pc_rtcp = self.clone();
        let pc_state = self.clone();
        let cbs = SrtpTransportCallbacks {
            on_rtp: Arc::new(move |pkt| pc_rtp.route_inbound_media(pkt)),
            on_rtcp: Arc::new(move |pkt| pc_rtcp.route_inbound_media(pkt)),
            on_state_change: Arc::new(move |s| {
                if matches!(s, DtlsState::Connected) {
                    pc_state.open_tracks();
                }
            }),
        };

        match SrtpTransport::new(Arc::new(dtls), cbs) {
            Ok(srtp) => {
                *guard = Some(srtp);
            }
            Err(e) => {
                warn!("PeerConnection: SRTP transport init failed: {e}");
            }
        }
    }

    /// Open every recorded track against the (now key-derived) SRTP transport.
    /// Idempotent — `Track::open` only fires `on_open` once. Called when SRTP
    /// reports keys derived, and also when a track is added after connect.
    fn open_tracks(&self) {
        let srtp = match self.inner.srtp.lock().as_ref().cloned() {
            Some(s) => s,
            None => return,
        };
        // The on_state_change(Connected) fires before keys are derived (it is
        // forwarded straight from the lower DTLS layer); the key derivation
        // happens on the srtp-derive worker thread. Poll briefly for readiness
        // on a detached thread so we don't block the DTLS callback.
        if srtp.is_ready() {
            let tracks = self.tracks();
            for t in tracks {
                t.open(Arc::clone(&srtp));
            }
            return;
        }
        let pc = self.clone();
        std::thread::Builder::new()
            .name("pc-open-tracks".into())
            .spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                loop {
                    let ready = pc
                        .inner
                        .srtp
                        .lock()
                        .as_ref()
                        .map(|s| s.is_ready())
                        .unwrap_or(false);
                    if ready {
                        if let Some(srtp) = pc.inner.srtp.lock().as_ref().cloned() {
                            for t in pc.tracks() {
                                t.open(Arc::clone(&srtp));
                            }
                        }
                        return;
                    }
                    if std::time::Instant::now() >= deadline
                        || pc.inner.closed.load(Ordering::SeqCst)
                    {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            })
            .expect("spawn pc-open-tracks thread");
    }

    /// Route an inbound (SRTP-unprotected) RTP/RTCP packet to the track bound
    /// to its SSRC. For RTP we read the SSRC from the header; for RTCP (and
    /// when the SSRC isn't recognised) we fall back to delivering to the sole
    /// recorded track if there is exactly one. Mirrors the BUNDLE'd demux: a
    /// single media transport feeds every m-line, keyed by SSRC.
    fn route_inbound_media(&self, pkt: &[u8]) {
        if self.inner.closed.load(Ordering::SeqCst) {
            return;
        }
        // PC-global media handler, mirroring `impl::PeerConnection::forwardMedia`:
        // run the handler's incoming transform over the packet, flush any
        // control replies it queues (RR/REMB/PLI/NACK) back through the SRTP
        // transport, then dispatch the (possibly rewritten) messages to the
        // per-track routing below. With no handler set, the raw packet is
        // dispatched unchanged — the prior behaviour.
        let transformed: Option<Vec<Message>> = {
            let mut guard = self.inner.media_handler.lock();
            guard.as_mut().map(|handler| {
                let mut messages = vec![Message::classify(pkt.to_vec())];
                let mut sender = MediaSender::new();
                handler.incoming(&mut messages, &mut sender);
                let replies = sender.take();
                if !replies.is_empty() {
                    if let Some(srtp) = self.inner.srtp.lock().as_ref() {
                        for reply in replies {
                            let _ = srtp.send_media(reply.data);
                        }
                    }
                }
                messages
            })
        };
        if let Some(messages) = transformed {
            for m in messages {
                self.dispatch_inbound_media(&m.data);
            }
        } else {
            self.dispatch_inbound_media(pkt);
        }
    }

    /// Route a single (SRTP-unprotected, PC-handler-transformed) RTP/RTCP
    /// packet to the track bound to its SSRC. Split out of
    /// [`route_inbound_media`](Self::route_inbound_media) so the PC-global
    /// media handler can rewrite/expand the inbound packet into zero or more
    /// messages before per-track dispatch.
    fn dispatch_inbound_media(&self, pkt: &[u8]) {
        // Try SSRC-based routing for RTP.
        if let Some((header, _)) = RtpHeader::parse(pkt) {
            let ssrc = header.ssrc;
            let target = self
                .inner
                .tracks
                .lock()
                .values()
                .find(|e| e.ssrc == ssrc)
                .map(|e| Arc::clone(&e.track));
            if let Some(track) = target {
                track.incoming(pkt);
                return;
            }
        }
        // Fallback: deliver to the single recorded track, if unambiguous.
        let tracks: Vec<Arc<Track>> = self
            .inner
            .tracks
            .lock()
            .values()
            .map(|e| Arc::clone(&e.track))
            .collect();
        if tracks.len() == 1 {
            tracks[0].incoming(pkt);
        } else {
            // Ambiguous SSRC with multiple tracks — deliver to all so an app
            // wiring on_message still sees it (matches a best-effort demux).
            for t in tracks {
                t.incoming(pkt);
            }
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

    /// True if either the negotiated descriptions or a locally-added track
    /// imply a media (SRTP) path. We bring SRTP up if *either* side advertises
    /// media, or we have a local track, so the `use_srtp` extension is on the
    /// DTLS handshake. Mirrors libdatachannel creating the DTLS-SRTP transport
    /// whenever any media m-line is present.
    fn negotiated_has_media(&self) -> bool {
        if self.has_local_media() {
            return true;
        }
        let local_media = self
            .inner
            .local_description
            .lock()
            .as_ref()
            .map(|d| d.has_media())
            .unwrap_or(false);
        let remote_media = self
            .inner
            .remote_description
            .lock()
            .as_ref()
            .map(|d| d.has_media())
            .unwrap_or(false);
        local_media || remote_media
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
            on_buffered_amount_low: Arc::new(move |stream, amount| {
                // Clone the channel Arc out and DROP the `data_channels` guard
                // before firing the user callback. `trigger_buffered_amount`
                // invokes the application `on_buffered_amount_low`, which may
                // call `send()` synchronously; the send path re-enters this
                // same closure via `update_buffered_amount`. Holding the lock
                // across the callback would self-deadlock (parking_lot mutex is
                // non-reentrant).
                let dc = pc_low.inner.data_channels.lock().get(&stream).cloned();
                if let Some(dc) = dc {
                    dc.trigger_buffered_amount(amount);
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
                // now open. Clone out + drop the guard before `mark_open`,
                // which fires the user `on_open` (may send re-entrantly).
                let dc = self.inner.data_channels.lock().get(&stream).cloned();
                if let Some(dc) = dc {
                    dc.mark_open();
                }
            }
        }
    }

    /// Deliver a user message to the channel bound to `stream`, if any.
    fn deliver_to_channel(&self, stream: u16, data: &[u8], binary: bool) {
        // Clone the channel Arc out and DROP the `data_channels` guard before
        // dispatching `deliver_message` → user `on_message`. A common, legal
        // pattern (and what the inline echo does) is to `send()` straight from
        // `on_message`; that send path can fire `on_buffered_amount_low`, which
        // re-locks `data_channels`. Holding the guard across the callback would
        // self-deadlock the SCTP worker. (Was the prod concurrent-load wedge.)
        let dc = self.inner.data_channels.lock().get(&stream).cloned();
        if let Some(dc) = dc {
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

/// Map an rtpmap encoding name (case-insensitive) to a [`crate::Codec`].
fn codec_from_rtpmap(format: &str) -> Option<crate::Codec> {
    match format.to_ascii_uppercase().as_str() {
        "H264" => Some(crate::Codec::H264),
        "H265" => Some(crate::Codec::H265),
        "VP8" => Some(crate::Codec::Vp8),
        "VP9" => Some(crate::Codec::Vp9),
        "AV1" | "AV1X" => Some(crate::Codec::Av1),
        "OPUS" => Some(crate::Codec::Opus),
        _ => None,
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
    fn remote_max_message_size_reflects_remote_sdp() {
        // A minimal remote offer carrying an application section. The
        // max-message-size attribute is what `remote_max_message_size` reads.
        const REMOTE_SDP: &str = "v=0\r\n\
o=rtc 3767197920 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
a=msid-semantic:WMS *\r\n\
a=ice-options:trickle\r\n\
a=fingerprint:sha-256 0F:74:31:25:CB:A2:13:EC:28:6F:6D:2C:61:FF:5D:C2:BC:B9:DB:3D:98:14:8D:1A:BB:EA:33:0C:A4:60:A8:8E\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
a=sendrecv\r\n\
a=setup:actpass\r\n\
a=ice-ufrag:ufrag\r\n\
a=ice-pwd:password1234567890123456\r\n\
a=fingerprint:sha-256 0F:74:31:25:CB:A2:13:EC:28:6F:6D:2C:61:FF:5D:C2:BC:B9:DB:3D:98:14:8D:1A:BB:EA:33:0C:A4:60:A8:8E\r\n\
a=sctp-port:5000\r\n\
a=max-message-size:262144\r\n";

        let pc = PeerConnection::new(loopback_config(), PeerConnectionCallbacks::default())
            .expect("construct");
        // No remote description: the 64 KiB remote default, min'd with the
        // 256 KiB local default → 64 KiB.
        assert_eq!(pc.remote_max_message_size(), 65536);

        // Remote advertises 256 KiB: min(262144, 262144) = 262144. Inject the
        // parsed description directly to avoid the full transport handshake.
        let desc = Description::parse(REMOTE_SDP).expect("parse remote");
        *pc.inner.remote_description.lock() = Some(desc);
        assert_eq!(pc.remote_max_message_size(), 262_144);

        // RFC 8841: a remote max-message-size of 0 means "no limit", so the
        // local maximum (256 KiB) wins.
        let sdp0 = REMOTE_SDP.replace("a=max-message-size:262144", "a=max-message-size:0");
        let desc0 = Description::parse(&sdp0).expect("parse remote 0");
        *pc.inner.remote_description.lock() = Some(desc0);
        assert_eq!(pc.remote_max_message_size(), 256 * 1024);
    }

    #[test]
    fn create_offer_emits_application_and_fingerprint() {
        rt().block_on(async {
            let pc = PeerConnection::new(loopback_config(), PeerConnectionCallbacks::default())
                .expect("construct");
            // The application m-line is gated on having a data channel (mirrors
            // upstream `populateLocalDescription`), so register one first; the
            // synchronously-returned offer then carries the static bits
            // (application m-line, actpass setup, fingerprint, sctp-port).
            let _dc = pc.create_data_channel("chat");
            let offer = pc.create_offer().expect("offer");
            let sdp = offer.to_sdp();
            assert!(sdp.contains("m=application 9 UDP/DTLS/SCTP webrtc-datachannel"));
            assert!(
                sdp.contains("a=setup:actpass"),
                "offer must advertise actpass"
            );
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
            pc.set_local_description(DescriptionType::Offer)
                .expect("set local");
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
    fn close_breaks_transport_callback_cycles() {
        rt().block_on(async {
            let pc = PeerConnection::new(loopback_config(), PeerConnectionCallbacks::default())
                .expect("construct");
            pc.set_local_description(DescriptionType::Offer)
                .expect("initialize transports");
            let weak = Arc::downgrade(&pc.inner);
            pc.close().expect("close");
            drop(pc);
            assert!(
                weak.upgrade().is_none(),
                "transport callbacks retained the PC"
            );
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

    #[test]
    fn pc_media_handler_set_runs_on_inbound_and_clears_on_close() {
        // A handler that records how many inbound messages it is handed.
        struct Counting(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl MediaHandler for Counting {
            fn incoming(&mut self, messages: &mut Vec<Message>, _sender: &mut MediaSender) {
                self.0
                    .fetch_add(messages.len(), std::sync::atomic::Ordering::SeqCst);
            }
        }

        rt().block_on(async {
            let pc = PeerConnection::new(loopback_config(), PeerConnectionCallbacks::default())
                .expect("construct");
            assert!(!pc.has_media_handler(), "no handler before set");

            let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            pc.set_media_handler(Box::new(Counting(seen.clone())));
            assert!(pc.has_media_handler(), "handler present after set");

            // Drive a packet through the inbound media path. The PC-global
            // handler must see it even with no tracks bound (per-track routing
            // is then a no-op). Bytes are a minimal RTP-shaped header.
            let pkt = [0x80u8, 0x60, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
            pc.route_inbound_media(&pkt);
            assert_eq!(
                seen.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "PC media handler saw the inbound packet"
            );

            // close() clears the handler (mirrors setMediaHandler(nullptr)).
            pc.close().expect("close");
            assert!(!pc.has_media_handler(), "handler cleared on close");
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
                wait_for(|| pc_a.gathering_state() == GatheringState::Complete, 3000).await,
                "A never finished gathering"
            );
            let offer = pc_a.local_description().expect("a local description");
            assert!(
                offer.to_sdp().contains("a=ice-ufrag:"),
                "offer must carry ice-ufrag after gathering; got:\n{}",
                offer.to_sdp()
            );

            // --- B applies A's offer, then creates + sets its answer ---
            pc_b.set_remote_description(offer)
                .expect("b set remote offer");
            pc_b.set_local_description(DescriptionType::Answer)
                .expect("b set local answer");
            assert!(
                wait_for(|| pc_b.gathering_state() == GatheringState::Complete, 3000).await,
                "B never finished gathering"
            );
            let answer = pc_b.local_description().expect("b local description");
            assert!(
                answer.to_sdp().contains("a=setup:active"),
                "answerer must resolve to active (DTLS client); got:\n{}",
                answer.to_sdp()
            );

            // --- A applies B's answer ---
            pc_a.set_remote_description(answer)
                .expect("a set remote answer");

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

            pc_b.set_remote_description(offer)
                .expect("b set remote offer");
            pc_b.set_local_description(DescriptionType::Answer)
                .expect("b set local answer");
            assert!(
                wait_for(|| pc_b.gathering_state() == GatheringState::Complete, 3000).await,
                "B never finished gathering"
            );
            let answer = pc_b.local_description().expect("b local description");
            pc_a.set_remote_description(answer)
                .expect("a set remote answer");

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
            assert_eq!(
                dc_b.stream() % 2,
                1,
                "A's channel id must be odd (A is DTLS server)"
            );
            assert_eq!(
                dc_a.stream(),
                dc_b.stream(),
                "both ends share the stream id"
            );

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

    /// Regression for the concurrent-load self-deadlock (issue #57): echoing
    /// straight from `on_message` must not wedge the SCTP worker. B installs an
    /// inline echo — it calls `send_binary` synchronously from inside its
    /// receive callback. The send path runs `update_buffered_amount`, which on
    /// the high→low transition fires `on_buffered_amount_low`; that closure
    /// re-locks the PeerConnection `data_channels` map. Before the fix,
    /// `deliver_to_channel` still held that (non-reentrant) lock across the
    /// callback, so the worker thread self-deadlocked on the first backpressure
    /// edge and no echo ever returned. With the lock dropped before dispatch,
    /// all echoes round-trip. If this regresses, the worker hangs and the
    /// receive assertion below times out (the test's own runtime thread is
    /// unaffected, so the suite fails cleanly rather than hanging forever).
    #[test]
    fn inline_echo_from_on_message_does_not_deadlock() {
        rt().block_on(async {
            let a_state: Arc<Mutex<PeerConnectionState>> =
                Arc::new(Mutex::new(PeerConnectionState::New));
            let b_state: Arc<Mutex<PeerConnectionState>> =
                Arc::new(Mutex::new(PeerConnectionState::New));
            let a_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));
            let b_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));

            // A counts the echoes it gets back; B holds its inbound channel.
            let a_echoes: Arc<std::sync::atomic::AtomicUsize> =
                Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let b_channel: Arc<Mutex<Option<DataChannel>>> = Arc::new(Mutex::new(None));

            let a_state_cb = a_state.clone();
            let a_cands_cb = a_cands.clone();
            let a_echoes_cb = a_echoes.clone();
            let a_cbs = PeerConnectionCallbacks {
                on_state_change: Arc::new(move |s| *a_state_cb.lock() = s),
                on_local_candidate: Arc::new(move |c| a_cands_cb.lock().push(c)),
                ..PeerConnectionCallbacks::default()
            };

            let b_state_cb = b_state.clone();
            let b_cands_cb = b_cands.clone();
            let b_channel_cb = b_channel.clone();
            let b_cbs = PeerConnectionCallbacks {
                on_state_change: Arc::new(move |s| *b_state_cb.lock() = s),
                on_local_candidate: Arc::new(move |c| b_cands_cb.lock().push(c)),
                on_data_channel: Arc::new(move |dc| {
                    // INLINE ECHO: send straight back from the receive
                    // callback — the pattern that triggered the deadlock.
                    let echo_dc = dc.clone();
                    dc.set_callbacks(DataChannelCallbacks {
                        on_message: Arc::new(move |data, _binary| {
                            let _ = echo_dc.send_binary(data);
                        }),
                        ..DataChannelCallbacks::default()
                    });
                    *b_channel_cb.lock() = Some(dc);
                }),
                ..PeerConnectionCallbacks::default()
            };

            let pc_a = PeerConnection::new(loopback_config(), a_cbs).expect("pc a");
            let pc_b = PeerConnection::new(loopback_config(), b_cbs).expect("pc b");

            let dc_a = pc_a.create_data_channel("echo");
            dc_a.set_callbacks(DataChannelCallbacks {
                on_message: Arc::new(move |_data, _binary| {
                    a_echoes_cb.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }),
                ..DataChannelCallbacks::default()
            });

            // Offer/answer + trickle.
            pc_a.set_local_description(DescriptionType::Offer)
                .expect("a set local offer");
            assert!(
                wait_for(|| pc_a.gathering_state() == GatheringState::Complete, 3000).await,
                "A never finished gathering"
            );
            let offer = pc_a.local_description().expect("a local description");
            pc_b.set_remote_description(offer)
                .expect("b set remote offer");
            pc_b.set_local_description(DescriptionType::Answer)
                .expect("b set local answer");
            assert!(
                wait_for(|| pc_b.gathering_state() == GatheringState::Complete, 3000).await,
                "B never finished gathering"
            );
            let answer = pc_b.local_description().expect("b local description");
            pc_a.set_remote_description(answer)
                .expect("a set remote answer");
            for c in a_cands.lock().iter() {
                let _ = pc_b.add_remote_candidate(c);
            }
            for c in b_cands.lock().iter() {
                let _ = pc_a.add_remote_candidate(c);
            }
            pc_a.set_remote_end_of_candidates().expect("a eoc");
            pc_b.set_remote_end_of_candidates().expect("b eoc");

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
            assert!(
                wait_for(|| b_channel.lock().is_some(), 5000).await,
                "B never received the data channel"
            );
            assert!(
                wait_for(|| dc_a.is_open(), 5000).await,
                "A's channel never opened"
            );

            // Fire a burst of sizeable messages so buffered-amount rises above
            // and falls back below the (default 0) low-water threshold, forcing
            // `on_buffered_amount_low` to fire from inside the echo's send —
            // the re-entrant path. Pre-fix, the first such edge wedges B's
            // worker and `n` echoes never come back.
            const N: usize = 200;
            let payload = vec![0xABu8; 16 * 1024];
            for _ in 0..N {
                dc_a.send_binary(&payload).expect("a send");
            }

            assert!(
                wait_for(
                    || a_echoes.load(std::sync::atomic::Ordering::SeqCst) >= N,
                    15000,
                )
                .await,
                "inline echo deadlocked: only {} of {N} echoes returned \
                 (B's SCTP worker wedged on a re-entrant data_channels lock)",
                a_echoes.load(std::sync::atomic::Ordering::SeqCst),
            );

            pc_a.close().expect("close a");
            pc_b.close().expect("close b");
        });
    }

    /// A locally-added video track must surface in the offer as a modeled
    /// `m=video` section carrying the codec, mid and (after gathering) the
    /// session ICE credentials.
    #[test]
    fn add_track_advertises_video_in_offer() {
        rt().block_on(async {
            let pc = PeerConnection::new(loopback_config(), PeerConnectionCallbacks::default())
                .expect("construct");
            let init = TrackInit::new(
                crate::Direction::SendRecv,
                crate::Codec::H264,
                96,
                0x1234_5678,
                "video0",
            );
            let track = pc.add_track(init);
            assert_eq!(track.mid(), "video0");

            pc.set_local_description(DescriptionType::Offer)
                .expect("set local offer");
            assert!(
                wait_for(|| pc.gathering_state() == GatheringState::Complete, 3000).await,
                "never finished gathering"
            );
            let offer = pc.local_description().expect("local description");
            let sdp = offer.to_sdp();
            assert!(
                sdp.contains("m=video 9 UDP/TLS/RTP/SAVPF 96"),
                "offer lacks m=video:\n{sdp}"
            );
            assert!(sdp.contains("a=mid:video0"));
            assert!(sdp.contains("a=rtpmap:96 H264/90000"));
            assert!(
                sdp.contains("a=ice-ufrag:"),
                "m-line offer lacks ICE creds:\n{sdp}"
            );
            assert!(sdp.contains("a=ice-pwd:"));
            assert!(offer.has_media());
            assert_eq!(
                offer.media_by_mid("video0").unwrap().rtp_maps()[0].payload_type,
                96
            );
        });
    }

    /// End-to-end media test: A adds a sendrecv video track and offers; B
    /// receives the remote track via `on_track`; both peers reach Connected;
    /// A sends a media payload that arrives at B's track `on_frame` after the
    /// full packetize → SRTP protect → DTLS/ICE → unprotect → depacketize path.
    #[test]
    fn media_track_round_trips_over_loopback() {
        rt().block_on(async {
            let a_state: Arc<Mutex<PeerConnectionState>> =
                Arc::new(Mutex::new(PeerConnectionState::New));
            let b_state: Arc<Mutex<PeerConnectionState>> =
                Arc::new(Mutex::new(PeerConnectionState::New));
            let a_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));
            let b_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));

            // B's remote track + frames it recovers.
            let b_track: Arc<Mutex<Option<Arc<Track>>>> = Arc::new(Mutex::new(None));
            let b_frames: Arc<Mutex<Vec<(Vec<u8>, u32, u8)>>> = Arc::new(Mutex::new(Vec::new()));

            let a_state_cb = a_state.clone();
            let a_cands_cb = a_cands.clone();
            let a_cbs = PeerConnectionCallbacks {
                on_state_change: Arc::new(move |s| *a_state_cb.lock() = s),
                on_local_candidate: Arc::new(move |c| a_cands_cb.lock().push(c)),
                ..PeerConnectionCallbacks::default()
            };

            let b_state_cb = b_state.clone();
            let b_cands_cb = b_cands.clone();
            let b_track_cb = b_track.clone();
            let b_frames_cb = b_frames.clone();
            let b_cbs = PeerConnectionCallbacks {
                on_state_change: Arc::new(move |s| *b_state_cb.lock() = s),
                on_local_candidate: Arc::new(move |c| b_cands_cb.lock().push(c)),
                on_track: Arc::new(move |t| {
                    let frames = b_frames_cb.clone();
                    t.set_callbacks(TrackCallbacks {
                        on_frame: Arc::new(move |p, ts, pt| {
                            frames.lock().push((p.to_vec(), ts, pt));
                        }),
                        ..TrackCallbacks::default()
                    });
                    *b_track_cb.lock() = Some(t);
                }),
                ..PeerConnectionCallbacks::default()
            };

            let pc_a = PeerConnection::new(loopback_config(), a_cbs).expect("pc a");
            let pc_b = PeerConnection::new(loopback_config(), b_cbs).expect("pc b");

            // A adds a sendrecv video track (SSRC pins inbound routing on B).
            let init = TrackInit::new(
                crate::Direction::SendRecv,
                crate::Codec::H264,
                96,
                0x0BAD_F00D,
                "video0",
            );
            let track_a = pc_a.add_track(init);

            // --- Offer/answer + trickle ---
            pc_a.set_local_description(DescriptionType::Offer)
                .expect("a set local offer");
            assert!(
                wait_for(|| pc_a.gathering_state() == GatheringState::Complete, 3000).await,
                "A never finished gathering"
            );
            let offer = pc_a.local_description().expect("a local description");
            assert!(
                offer.to_sdp().contains("m=video"),
                "offer must carry m=video"
            );

            pc_b.set_remote_description(offer)
                .expect("b set remote offer");
            pc_b.set_local_description(DescriptionType::Answer)
                .expect("b set local answer");
            assert!(
                wait_for(|| pc_b.gathering_state() == GatheringState::Complete, 3000).await,
                "B never finished gathering"
            );
            let answer = pc_b.local_description().expect("b local description");
            assert!(
                answer.to_sdp().contains("m=video"),
                "answer must echo m=video"
            );
            pc_a.set_remote_description(answer)
                .expect("a set remote answer");

            // B surfaces the remote track immediately on applying the offer.
            assert!(
                wait_for(|| b_track.lock().is_some(), 2000).await,
                "B never received the track via on_track"
            );
            let track_b = b_track.lock().clone().expect("b track");
            assert_eq!(track_b.mid(), "video0");

            for c in a_cands.lock().iter() {
                let _ = pc_b.add_remote_candidate(c);
            }
            for c in b_cands.lock().iter() {
                let _ = pc_a.add_remote_candidate(c);
            }
            pc_a.set_remote_end_of_candidates().expect("a eoc");
            pc_b.set_remote_end_of_candidates().expect("b eoc");

            // --- Wait for both to reach Connected ---
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

            // --- Both tracks open once SRTP keys are derived ---
            assert!(
                wait_for(|| track_a.is_open() && track_b.is_open(), 5000).await,
                "tracks never opened (SRTP keys not derived?)"
            );

            // --- A sends a media payload; B recovers it via on_frame ---
            let payload = b"hello-media-track".to_vec();
            let n = track_a.send(&payload).expect("a send media");
            assert_eq!(n, 1, "generic packetizer emits one RTP packet");

            assert!(
                wait_for(|| !b_frames.lock().is_empty(), 5000).await,
                "B never received the media frame"
            );
            let frames = b_frames.lock();
            assert_eq!(frames[0].0, payload, "payload round-trips through SRTP");
            assert_eq!(frames[0].2, 96, "payload type preserved");
            drop(frames);

            pc_a.close().expect("close a");
            pc_b.close().expect("close b");
        });
    }
}
