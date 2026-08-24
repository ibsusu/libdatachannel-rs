//! ICE transport — port of `rtc::impl::IceTransport` from
//! `native/libdatachannel/src/impl/icetransport.{cpp,hpp}`.
//!
//! This module is the seam between libdatachannel's `PeerConnection` layer
//! and the underlying ICE agent (libjuice). It wraps a [`libjuice::Agent`]
//! and exposes a callback-driven, Rust-idiomatic surface that mirrors the
//! C++ class: gather candidates, set the remote description, trickle in
//! remote candidates, watch state transitions, and tunnel raw bytes once
//! the pair is selected (the bytes are DTLS records once Task #14 lands).
//!
//! ## Concurrency model
//!
//! [`libjuice::Agent`] is `Clone + Send + Sync` and forwards commands to a
//! tokio task. We hand the application its callbacks via `Arc<dyn Fn(...) +
//! Send + Sync>` and install thin shims on the libjuice [`Handler`] that
//! call into them. The driver task delivers callbacks serially, so the
//! application doesn't need to add its own mutex around per-callback
//! state, but the application's callbacks MUST NOT block the driver
//! thread.
//!
//! ## Phase G-4a scope
//!
//! - Construct from a [`Configuration`]; map STUN/TURN, port range, bind
//!   address. Multiple STUN servers degrade to "first one wins" (libjuice
//!   only supports one in its `Config`); the rest are logged and dropped.
//! - Drive gather → checking → connected transitions, surfaced through
//!   the [`IceTransportCallbacks::on_state_change`] callback.
//! - Trickle candidates both directions through SDP strings — the dc
//!   Candidate's [`Candidate::to_sdp`] form is what libjuice's
//!   `add_remote_candidate` consumes, and the SDP string libjuice emits
//!   via its candidate handler is parsed back into a dc [`Candidate`].
//! - Expose [`IceTransport::send`] for the byte stream that DTLS will sit
//!   on top of in Task #14.
//!
//! Out of scope (deferred):
//! - ICE restart (C++ `restartIce()` at `icetransport.cpp:???` — n/a here
//!   since the C++ for `libjuice` backend doesn't yet implement it).
//! - Strict `TransportPolicy::Relay` filtering. Logged + TODO; libjuice
//!   doesn't filter candidate types itself.
//! - Proxy server support — libjuice doesn't honour proxies. Logged.
//! - DTLS handoff — the `on_data` callback is the seam for Task #14.

use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use thiserror::Error;
use tracing::warn;

// The libjuice crate's `[package]` name is `libjuice` (so we depend on it
// as `libjuice` in Cargo.toml) but its `[lib]` name is `juice` — the
// library output is `libjuice.dylib` / `libjuice.a`, matching upstream's
// `liblibjuice` convention. We alias here so the rest of this file can
// continue to read as `libjuice::*`, matching the C++ source it ports.
use juice as libjuice;

use crate::candidate::{Candidate, ParseError as CandidateParseError};
use crate::configuration::{Configuration, IceServerType, IceTransportPolicy};
use crate::description::{
    Application, Description, DescriptionParseError, Role, Type as DescriptionType,
};

/// libjuice caps additional TURN servers at 2 — match the C++ constant
/// `MAX_TURN_SERVERS_COUNT` in `icetransport.cpp:39`.
const MAX_TURN_SERVERS_COUNT: usize = 2;

/// W3C WebRTC ICE transport state.
///
/// Mirrors libdatachannel's `rtc::Transport::State` (the values
/// IceTransport switches through). See `transport.hpp` for the C++ enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// Construction succeeded; no gathering yet.
    New,
    /// Connectivity checks underway.
    Checking,
    /// A working candidate pair has been nominated.
    Connected,
    /// `Connected` + checks all confirmed via USE-CANDIDATE.
    Completed,
    /// All connectivity checks failed; an ICE restart is required.
    Failed,
    /// Transport was up but consent freshness lapsed.
    Disconnected,
    /// Transport has been closed and the agent torn down.
    Closed,
}

/// W3C WebRTC ICE gathering state.
///
/// Mirrors `IceTransport::GatheringState` in `icetransport.hpp:38`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatheringState {
    /// No gathering has been triggered yet.
    New,
    /// `gather()` has been called; candidates are being emitted.
    InProgress,
    /// Gathering finished; no more `on_candidate` callbacks expected.
    Complete,
}

/// Callbacks the transport invokes from the driver task.
///
/// All four callbacks are `Arc<dyn Fn(...) + Send + Sync>` so they can be
/// freely shared with the libjuice [`Handler`] without forcing every
/// closure to be `FnMut`. Use [`IceTransportCallbacks::default`] for an
/// all-no-ops set.
#[derive(Clone)]
pub struct IceTransportCallbacks {
    /// Fired when the ICE state transitions. See [`State`].
    pub on_state_change: Arc<dyn Fn(State) + Send + Sync>,
    /// Fired when the gathering state transitions. See [`GatheringState`].
    pub on_gathering_state_change: Arc<dyn Fn(GatheringState) + Send + Sync>,
    /// Fired for each new local candidate the agent surfaces. The
    /// candidate already has its `mid` populated from the local
    /// description we recorded at construction (or the last
    /// `set_local_description` call once that lands in Task #17).
    pub on_candidate: Arc<dyn Fn(Candidate) + Send + Sync>,
    /// Fired for each application datagram. Phase G-4a delivers raw bytes;
    /// Task #14 will sit DTLS on top of this seam.
    pub on_data: Arc<dyn Fn(&[u8]) + Send + Sync>,
}

impl Default for IceTransportCallbacks {
    fn default() -> Self {
        IceTransportCallbacks {
            on_state_change: Arc::new(|_| {}),
            on_gathering_state_change: Arc::new(|_| {}),
            on_candidate: Arc::new(|_| {}),
            on_data: Arc::new(|_| {}),
        }
    }
}

/// Errors returned by [`IceTransport`] operations.
#[derive(Debug, Error)]
pub enum IceTransportError {
    /// Forwarded from the libjuice agent.
    #[error("libjuice agent: {0}")]
    Juice(#[from] libjuice::Error),

    /// The supplied `bind_address` did not parse as a valid IP address.
    #[error("failed to parse bind address {addr:?}: {source}")]
    BadBindAddress {
        /// The offending string.
        addr: String,
        /// The underlying parser error.
        source: std::net::AddrParseError,
    },

    /// A candidate string (incoming SDP) did not parse.
    #[error("candidate parse error: {0}")]
    Candidate(#[from] CandidateParseError),

    /// A description blob (from libjuice's `get_local_description`) did
    /// not parse — should be unreachable in practice.
    #[error("description parse error: {0}")]
    Description(#[from] DescriptionParseError),

    /// `get_selected_pair` was called before a pair was nominated.
    #[error("no selected candidate pair yet")]
    NoSelectedPair,

    /// The transport has been closed (the agent's command channel is gone).
    #[error("transport closed")]
    Closed,
}

/// libjuice → dc state mapping. Matches `processStateChange` at
/// `icetransport.cpp:307`. Note that libjuice's `Gathering` (which is
/// purely candidate gathering) precedes `Connecting` (start of
/// connectivity checks), but the C++ never sees a `Gathering` state token
/// — it tracks gathering separately. We map `Gathering` to `Checking`
/// the same way the C++ would if libjuice surfaced it: the W3C
/// `IceTransport.state` doesn't have a "gathering" value.
fn map_state(s: libjuice::State) -> State {
    match s {
        libjuice::State::Disconnected => State::New,
        libjuice::State::Gathering => State::Checking,
        libjuice::State::Connecting => State::Checking,
        libjuice::State::Connected => State::Connected,
        libjuice::State::Completed => State::Completed,
        libjuice::State::Failed => State::Failed,
    }
}

/// How the underlying libjuice agent is owned. Most PeerConnections own a
/// standalone agent on its own UDP socket ([`AgentHandle::Plain`]). When
/// `enable_ice_udp_mux` is set, the agent instead joins a process-wide
/// `juice_mux_listen` socket ([`AgentHandle::Mux`]) — the same socket the C
/// `IceUdpMuxListener` adapter registers — so many PeerConnections share one
/// port. Both deref to the same [`libjuice::Agent`] surface; the [`Mux`]
/// variant additionally deregisters from the shared demux table on drop.
///
/// [`Mux`]: AgentHandle::Mux
enum AgentHandle {
    Plain(libjuice::Agent),
    Mux(libjuice::MuxAgent),
}

impl Deref for AgentHandle {
    type Target = libjuice::Agent;
    fn deref(&self) -> &libjuice::Agent {
        match self {
            AgentHandle::Plain(a) => a,
            AgentHandle::Mux(m) => &**m, // MuxAgent: Deref<Target = Agent>
        }
    }
}

/// The ICE transport. Wraps a [`libjuice::Agent`] and applies the
/// libdatachannel adapter layer on top.
///
/// Cheap to share: it sits behind an `Arc` so the libjuice handler
/// closures can hold a clone of the inner state without borrowing the
/// outer handle.
pub struct IceTransport {
    /// libjuice's agent handle (itself `Clone + Send + Sync`), either a
    /// standalone agent or one joined to a shared UDP-mux socket. Derefs to
    /// [`libjuice::Agent`] for all lifecycle calls.
    agent: AgentHandle,
    /// Current dc-side role. Starts at [`Role::ActPass`] and switches
    /// to either Active or Passive in `set_remote_description`, matching
    /// the C++ behaviour at `icetransport.cpp:215`.
    role: Mutex<Role>,
    /// Shared bridge holding the dc-side state machine + callback set.
    /// The libjuice handler closures hold their own clones of this Arc;
    /// `IceTransport` holds this clone so [`set_callbacks`] and
    /// [`close`] can mutate the shared state.
    bridge: Arc<Bridge>,
}

impl std::fmt::Debug for IceTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceTransport")
            .field("state", &*self.bridge.state.lock())
            .field("gathering_state", &*self.bridge.gathering_state.lock())
            .field("role", &*self.role.lock())
            .field("mid", &*self.bridge.mid.lock())
            .field("closed", &self.bridge.closed.load(Ordering::SeqCst))
            .finish()
    }
}

impl IceTransport {
    /// Build a new ICE transport with the given configuration, initial
    /// DTLS role and callback set.
    ///
    /// The libjuice agent is constructed inline and the four user
    /// callbacks are wired into its `Handler`. Returns the transport
    /// wrapped in an `Arc` so it can be shared with future
    /// `DtlsTransport` / `SctpTransport` layers without re-wrapping.
    ///
    /// Configuration mapping:
    /// - The **first** STUN entry in `config.ice_servers` is wired into
    ///   `Builder::with_stun`. Subsequent STUN entries trigger a
    ///   `tracing::warn` and are dropped (libjuice's [`Config`] only
    ///   holds one). Matches the C++ "first match wins" loop at
    ///   `icetransport.cpp:105`.
    /// - Up to [`MAX_TURN_SERVERS_COUNT`] TURN entries are forwarded
    ///   via `Builder::add_turn_server`, mirroring `addIceServer` at
    ///   `icetransport.cpp:149`.
    /// - `port_range_begin..=port_range_end` → `with_port_range`, but
    ///   only when narrower than the default `1024..=65535` (matches
    ///   `icetransport.cpp:122`).
    /// - `bind_address` is parsed to an [`IpAddr`]; an invalid string
    ///   yields [`IceTransportError::BadBindAddress`] before the agent
    ///   is created.
    /// - `ice_transport_policy = Relay` logs a warning and is otherwise
    ///   a no-op for now. TODO: filter non-Relayed candidates in the
    ///   `on_candidate` callback.
    /// - `proxy_server` logs a warning if set; libjuice's UDP transport
    ///   doesn't honour proxies.
    /// - All other knobs (DTLS cert type, congestion control, etc.) are
    ///   no-ops at this layer; later transports consume them.
    pub fn new(
        config: &Configuration,
        role: Role,
        callbacks: IceTransportCallbacks,
    ) -> Result<Arc<Self>, IceTransportError> {
        // --- pre-flight: parse bind_address before touching libjuice. ---
        let bind_addr: Option<IpAddr> = match &config.bind_address {
            Some(s) => Some(
                s.parse()
                    .map_err(|source| IceTransportError::BadBindAddress {
                        addr: s.clone(),
                        source,
                    })?,
            ),
            None => None,
        };

        // --- mid-flight: warn on knobs we don't (yet) honour. ---
        if matches!(config.ice_transport_policy, IceTransportPolicy::Relay) {
            // TODO: filter on_candidate to drop non-Relayed candidates,
            // matching the W3C contract for `iceTransportPolicy: "relay"`.
            warn!(
                "IceTransport: ice_transport_policy=Relay is recognised but \
                 libjuice does not filter candidate types itself; this \
                 phase does not yet enforce the relay-only constraint"
            );
        }
        if config.proxy_server.is_some() {
            warn!(
                "IceTransport: proxy_server is set but libjuice's UDP \
                 transport does not honour proxies; continuing without one"
            );
        }

        // --- build the shared bridge state. ---
        let bridge = Arc::new(Bridge {
            state: Mutex::new(State::New),
            gathering_state: Mutex::new(GatheringState::New),
            mid: Mutex::new("0".to_string()),
            callbacks: Mutex::new(callbacks),
            closed: AtomicBool::new(false),
        });

        // --- build the libjuice Handler with our shims. ---
        let handler = {
            let b_state = bridge.clone();
            let b_cand = bridge.clone();
            let b_done = bridge.clone();
            let b_recv = bridge.clone();
            libjuice::Handler::default()
                .state_handler(move |s| b_state.on_juice_state(s))
                .candidate_handler(move |sdp| b_cand.on_juice_candidate(sdp))
                .gathering_done_handler(move || b_done.on_juice_gathering_done())
                .recv_handler(move |data| b_recv.on_juice_recv(data))
        };

        // --- build the libjuice Agent from the dc Configuration. ---
        //
        // When ICE UDP mux is enabled, the agent must SHARE the process-wide
        // socket registered by `juice_mux_listen` (the C `IceUdpMuxListener`
        // adapter) rather than bind its own. We join that registry on
        // `(bind_address, port_range_begin)`, mirroring upstream
        // `icetransport.cpp`, which passes the same knobs to `juice_create`
        // with `JUICE_CONCURRENCY_MODE_MUX`. A shared-socket agent ignores the
        // per-agent bind/port-range/STUN/TURN builder knobs, so they're skipped
        // on this path; `join_udp_mux` mints a random ufrag/pwd and registers
        // the agent so a normally-exchanged offer/answer routes the offerer's
        // checks to it by USERNAME.
        let agent = if config.enable_ice_udp_mux {
            let mux = libjuice::join_udp_mux(bind_addr, config.port_range_begin, handler)
                .map_err(IceTransportError::Juice)?;
            AgentHandle::Mux(mux)
        } else {
            let mut builder = libjuice::Agent::builder(handler);

            // First STUN entry wins; rest are logged + dropped.
            let mut stun_taken = false;
            for srv in &config.ice_servers {
                if !matches!(srv.typ, IceServerType::Stun) {
                    continue;
                }
                if srv.hostname.is_empty() {
                    continue;
                }
                if !stun_taken {
                    let port = if srv.port == 0 { 3478 } else { srv.port };
                    builder = builder.with_stun(srv.hostname.clone(), port);
                    stun_taken = true;
                } else {
                    warn!(
                        "IceTransport: dropping extra STUN server {}:{} \
                     (libjuice only supports one STUN server in Config)",
                        srv.hostname, srv.port
                    );
                }
            }

            // Bind address.
            if let Some(ip) = bind_addr {
                builder = builder.with_bind_address(&ip);
            }

            // Port range — only override when narrower than the default
            // (matches the C++ guard at icetransport.cpp:122).
            let pr_begin = config.port_range_begin;
            let pr_end = config.port_range_end;
            if pr_begin > 1024 || (pr_end != 0 && pr_end != 65535) {
                builder = builder.with_port_range(pr_begin, pr_end);
            }

            // TURN servers (cap at MAX_TURN_SERVERS_COUNT, matching the C++
            // counter at icetransport.cpp:163).
            let mut turn_added = 0usize;
            for srv in &config.ice_servers {
                if !matches!(srv.typ, IceServerType::Turn) {
                    continue;
                }
                if srv.hostname.is_empty() {
                    continue;
                }
                if turn_added >= MAX_TURN_SERVERS_COUNT {
                    warn!(
                        "IceTransport: dropping additional TURN server {}:{} \
                     (libjuice cap is {})",
                        srv.hostname, srv.port, MAX_TURN_SERVERS_COUNT
                    );
                    continue;
                }
                // C++ icetransport.cpp:158 warns that only TurnUdp is
                // supported with libjuice; we mirror that — non-UDP entries
                // are dropped with a warning rather than silently passed.
                if !matches!(srv.relay_type, crate::configuration::RelayType::TurnUdp) {
                    warn!(
                        "IceTransport: skipping TURN server {}:{} — only \
                     TurnUdp is supported with libjuice (got {:?})",
                        srv.hostname, srv.port, srv.relay_type
                    );
                    continue;
                }
                let port = if srv.port == 0 { 3478 } else { srv.port };
                builder = builder
                    .add_turn_server(
                        srv.hostname.clone(),
                        port,
                        srv.username.clone(),
                        srv.password.clone(),
                    )
                    .map_err(IceTransportError::Juice)?;
                turn_added += 1;
            }

            // Finally, construct the agent (which spawns the driver task).
            AgentHandle::Plain(builder.build().map_err(IceTransportError::Juice)?)
        };

        Ok(Arc::new(IceTransport {
            agent,
            role: Mutex::new(role),
            bridge,
        }))
    }

    /// Current ICE state. Updated by the libjuice state callback.
    pub fn state(&self) -> State {
        *self.bridge.state.lock()
    }

    /// Current gathering state.
    pub fn gathering_state(&self) -> GatheringState {
        *self.bridge.gathering_state.lock()
    }

    /// Current DTLS role (`actpass` until [`set_remote_description`]
    /// resolves it, then either `active` or `passive`).
    pub fn role(&self) -> Role {
        *self.role.lock()
    }

    /// Start candidate gathering. Idempotent — calling twice is a no-op
    /// (libjuice's driver simply ignores the second command and we update
    /// the gathering state to `InProgress` once).
    pub fn gather(&self) -> Result<(), IceTransportError> {
        if self.bridge.closed.load(Ordering::SeqCst) {
            return Err(IceTransportError::Closed);
        }
        // Update our own gathering-state machine first so the first
        // `on_candidate` callback (which may fire synchronously on the
        // driver task) sees `InProgress`. Matches the C++ comment at
        // `icetransport.cpp:243` ("Change state now as candidates calls
        // can be synchronous").
        let prev = {
            let mut g = self.bridge.gathering_state.lock();
            let was = *g;
            if was == GatheringState::New {
                *g = GatheringState::InProgress;
            }
            was
        };
        if prev == GatheringState::New {
            let cb = {
                let guard = self.bridge.callbacks.lock();
                Arc::clone(&guard.on_gathering_state_change)
            };
            (cb)(GatheringState::InProgress);
            self.agent.gather_candidates()?;
        }
        Ok(())
    }

    /// Render a [`Description`] from the local ICE attributes libjuice
    /// has assembled. The returned description carries `ice-ufrag` +
    /// `ice-pwd` + a stub application m-section. Candidates are NOT
    /// folded in here — they arrive via the `on_candidate` callback and
    /// the caller is expected to attach them to whichever
    /// [`Description`] it's building.
    ///
    /// This mirrors `IceTransport::getLocalDescription` in
    /// `icetransport.cpp:189`, except we don't have a `Description`
    /// constructor that takes the libjuice SDP fragment directly — so we
    /// parse the fragment, lift `ice-ufrag` / `ice-pwd`, and construct
    /// a new `Description` of the requested [`Type`](DescriptionType).
    ///
    /// Returns the description with `setup:actpass` for an offer, or the
    /// transport's current resolved [`Role`] otherwise (matches C++).
    pub fn get_local_description(
        &self,
        typ: DescriptionType,
    ) -> Result<Description, IceTransportError> {
        let role_to_use = if matches!(typ, DescriptionType::Offer) {
            Role::ActPass
        } else {
            *self.role.lock()
        };

        let sdp_fragment = self.agent.get_local_description()?;

        // libjuice's fragment is a sequence of attribute lines:
        //   a=ice-ufrag:...\r\n
        //   a=ice-pwd:...\r\n
        //   a=candidate:...\r\n   (zero or more)
        //   [a=end-of-candidates\r\n]
        //   a=ice-options:...
        // We pluck ufrag / pwd directly; everything else is the
        // caller's problem (the C++ wraps the same fragment in a
        // Description ctor that does the same plucking).
        let (ufrag, pwd) = extract_ice_creds(&sdp_fragment);

        let mid = self.bridge.mid.lock().clone();
        let mut desc = Description::new(typ, role_to_use);
        if let Some(u) = ufrag {
            desc.set_ice_ufrag(u);
        }
        if let Some(p) = pwd {
            desc.set_ice_pwd(p);
        }
        desc.set_application(Application::new(mid));
        // RFC 8829 / libdatachannel always advertises `trickle` on
        // generated offers/answers. Matches the explicit
        // `desc.addIceOption("trickle")` at icetransport.cpp:199.
        desc.add_ice_option("trickle");

        Ok(desc)
    }

    /// Install the remote description. Records the bundle mid so future
    /// trickled candidates can be stamped, resolves the local DTLS role
    /// against the remote's `setup` attribute, and forwards the
    /// application-mid SDP to libjuice via `set_remote_description`.
    ///
    /// The role-switching logic mirrors `icetransport.cpp:203` exactly:
    /// if we were `ActPass` and the remote is also `ActPass`, the
    /// offerer answers with `Active`; otherwise we flip to the opposite
    /// of the remote. An `Answer` with `ActPass` is rejected by libjuice
    /// itself; here we accept the description and let libjuice surface
    /// any incompatibility.
    pub fn set_remote_description(&self, desc: &Description) -> Result<(), IceTransportError> {
        if self.bridge.closed.load(Ordering::SeqCst) {
            return Err(IceTransportError::Closed);
        }
        // Role resolution.
        {
            let mut role = self.role.lock();
            if *role == Role::ActPass {
                *role = if matches!(desc.role(), Role::Active) {
                    Role::Passive
                } else {
                    Role::Active
                };
            }
        }

        // Record the bundle mid so candidate-callback shims can stamp
        // trickled candidates.
        *self.bridge.mid.lock() = desc.bundle_mid();

        // libjuice's `set_remote_description` accepts an SDP fragment
        // (it only looks for ice-ufrag / ice-pwd / candidate lines), so
        // we can feed it the full description here — its parser ignores
        // the v=/o=/s=/t=/m= lines it doesn't recognise.
        self.agent
            .set_remote_description(desc.to_sdp())
            .map_err(IceTransportError::Juice)
    }

    /// Push a single trickled remote candidate into libjuice.
    ///
    /// Returns `Ok(true)` if libjuice accepted the candidate; `Ok(false)`
    /// if the candidate was unresolved (the C++ at
    /// `icetransport.cpp:229` short-circuits on
    /// `!candidate.isResolved()`). Returns an error if libjuice's
    /// command channel is gone.
    pub fn add_remote_candidate(&self, candidate: &Candidate) -> Result<bool, IceTransportError> {
        if self.bridge.closed.load(Ordering::SeqCst) {
            return Err(IceTransportError::Closed);
        }
        if !candidate.is_resolved() {
            return Ok(false);
        }
        self.agent
            .add_remote_candidate(candidate.to_sdp())
            .map(|_| true)
            .map_err(IceTransportError::Juice)
    }

    /// Signal that the remote peer has finished trickling candidates.
    pub fn set_remote_end_of_candidates(&self) -> Result<(), IceTransportError> {
        if self.bridge.closed.load(Ordering::SeqCst) {
            return Err(IceTransportError::Closed);
        }
        self.agent
            .set_remote_gathering_done()
            .map_err(IceTransportError::Juice)
    }

    /// Send raw application bytes over the selected pair. Errors out
    /// (via libjuice's [`Error::NotAvailable`](libjuice::Error)) if no
    /// pair has been nominated yet.
    pub fn send(&self, data: &[u8]) -> Result<(), IceTransportError> {
        if self.bridge.closed.load(Ordering::SeqCst) {
            return Err(IceTransportError::Closed);
        }
        self.agent.send(data).map_err(IceTransportError::Juice)
    }

    /// Returns the selected `(local, remote)` candidate pair, parsing
    /// libjuice's SDP back into dc [`Candidate`]s.
    pub fn get_selected_pair(&self) -> Result<(Candidate, Candidate), IceTransportError> {
        let (local_sdp, remote_sdp) = self
            .agent
            .get_selected_candidates()
            .map_err(|_| IceTransportError::NoSelectedPair)?;
        let mid = self.bridge.mid.lock().clone();
        let local = Candidate::parse(&local_sdp, &mid)?;
        let remote = Candidate::parse(&remote_sdp, &mid)?;
        Ok((local, remote))
    }

    /// Returns the selected `(local_addr, remote_addr)` socket addresses
    /// in libjuice's `"ip port"` form. Errors out if no pair has been
    /// nominated yet.
    pub fn get_selected_addresses(&self) -> Result<(String, String), IceTransportError> {
        self.agent
            .get_selected_addresses()
            .map_err(|_| IceTransportError::NoSelectedPair)
    }

    /// Request an ICE restart.
    ///
    /// In W3C terms an ICE restart resets the local gathering and
    /// connection state and produces a fresh ufrag/pwd pair so a new
    /// round of connectivity checks can be triggered.
    ///
    /// libjuice's [`Agent`] does not yet expose a restart API (see
    /// `native/rust/libjuice/src/agent/mod.rs` — there is no
    /// `restart`/`restart_gather` command). This implementation is a
    /// best-effort stub: it resets the dc-side `state` and
    /// `gathering_state` flags to [`State::New`] /
    /// [`GatheringState::New`] and fires the corresponding callbacks so
    /// upper layers can observe the transition, but it does NOT cycle
    /// libjuice's own state machine or generate a fresh ufrag/pwd.
    ///
    /// TODO: once `libjuice::Agent` grows a `restart_gather` (or
    /// similar) entry point, plumb it through here so the local
    /// ufrag/pwd actually rotates. The relevant file is
    /// `native/rust/libjuice/src/agent/mod.rs`.
    pub fn restart_ice(&self) -> Result<(), IceTransportError> {
        if self.bridge.closed.load(Ordering::SeqCst) {
            return Err(IceTransportError::Closed);
        }

        warn!(
            "IceTransport::restart_ice: best-effort stub — libjuice backend \
             does not yet expose a restart API; resetting dc-side state \
             flags only (no fresh ufrag/pwd)"
        );

        let gathering_changed = {
            let mut g = self.bridge.gathering_state.lock();
            if *g != GatheringState::New {
                *g = GatheringState::New;
                true
            } else {
                false
            }
        };
        let state_changed = {
            let mut s = self.bridge.state.lock();
            if *s != State::New {
                *s = State::New;
                true
            } else {
                false
            }
        };

        if gathering_changed {
            let cb = {
                let guard = self.bridge.callbacks.lock();
                Arc::clone(&guard.on_gathering_state_change)
            };
            (cb)(GatheringState::New);
        }
        if state_changed {
            let cb = {
                let guard = self.bridge.callbacks.lock();
                Arc::clone(&guard.on_state_change)
            };
            (cb)(State::New);
        }

        Ok(())
    }

    /// Eagerly close the transport.
    ///
    /// Transitions the dc-side state to [`State::Closed`] and fires
    /// `on_state_change(Closed)` exactly once. Subsequent calls are
    /// a no-op (idempotent).
    ///
    /// After `close()`:
    /// - [`send`](Self::send), [`gather`](Self::gather),
    ///   [`add_remote_candidate`](Self::add_remote_candidate),
    ///   [`set_remote_description`](Self::set_remote_description), and
    ///   [`set_remote_end_of_candidates`](Self::set_remote_end_of_candidates)
    ///   all return [`IceTransportError::Closed`].
    /// - The `on_data` callback will no longer be invoked even if more
    ///   bytes arrive on the libjuice driver task.
    ///
    /// Note: this does NOT tear down the libjuice [`Agent`] — libjuice's
    /// driver only exits when the last `Arc` reference to it drops.
    /// `IceTransport` keeps that `Arc` alive (for example so the
    /// closures above this layer can still inspect the selected pair
    /// for diagnostics). The driver is released on `Drop`.
    pub fn close(&self) -> Result<(), IceTransportError> {
        // Mark closed first. If we were already closed, bail out — this
        // makes the operation idempotent and ensures the callback fires
        // exactly once.
        let was_closed = self.bridge.closed.swap(true, Ordering::SeqCst);
        if was_closed {
            return Ok(());
        }

        let state_changed = {
            let mut s = self.bridge.state.lock();
            if *s != State::Closed {
                *s = State::Closed;
                true
            } else {
                false
            }
        };

        if state_changed {
            let cb = {
                let guard = self.bridge.callbacks.lock();
                Arc::clone(&guard.on_state_change)
            };
            (cb)(State::Closed);
        }
        self.agent.shutdown();

        Ok(())
    }

    /// Swap the callback set at runtime.
    ///
    /// Wired in for Task #14 (DTLS): the DTLS transport constructs the
    /// underlying `IceTransport` first (so it can use it to push
    /// handshake records into the agent), then installs its own
    /// `on_data` handler to receive raw bytes off the wire. The full
    /// `IceTransportCallbacks` set is replaced atomically — pass
    /// [`IceTransportCallbacks::default`] for an all-no-ops set.
    ///
    /// The dispatch path locks the callbacks mutex only long enough to
    /// clone the relevant `Arc<dyn Fn>` out, so callbacks are free to
    /// call back into `IceTransport` without deadlocking.
    pub fn set_callbacks(&self, callbacks: IceTransportCallbacks) {
        let mut guard = self.bridge.callbacks.lock();
        *guard = callbacks;
    }

    /// Snapshot of the currently-installed callback set.
    ///
    /// Layered transports (DTLS in Phase G-5a, SCTP in G-5c) use this
    /// to remember the upper-layer callbacks before they install their
    /// own shims with [`set_callbacks`](Self::set_callbacks) — for
    /// example, DTLS stashes the original `on_data` so it can chain
    /// application-record bytes back to the original recipient once
    /// the handshake is up.
    ///
    /// Each callback in the returned set is an `Arc::clone` of what's
    /// currently installed, so the snapshot keeps working even after
    /// a subsequent `set_callbacks` swap.
    pub fn callbacks(&self) -> IceTransportCallbacks {
        let guard = self.bridge.callbacks.lock();
        IceTransportCallbacks {
            on_state_change: Arc::clone(&guard.on_state_change),
            on_gathering_state_change: Arc::clone(&guard.on_gathering_state_change),
            on_candidate: Arc::clone(&guard.on_candidate),
            on_data: Arc::clone(&guard.on_data),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal bridge — wires libjuice's Handler closures to the dc-side
// state machine + user callbacks.
// ---------------------------------------------------------------------------

/// Inner state shared with the libjuice handler closures. We can't put
/// these mutexes on `IceTransport` itself because the closures need to
/// outlive any particular `Arc<IceTransport>` snapshot — they're owned
/// by the libjuice driver task.
struct Bridge {
    state: Mutex<State>,
    gathering_state: Mutex<GatheringState>,
    mid: Mutex<String>,
    /// Callback set, behind a Mutex so [`IceTransport::set_callbacks`]
    /// can swap it at runtime (used by DTLS in Task #14 to install its
    /// own `on_data` after construction).
    ///
    /// Each dispatch path locks the mutex only long enough to clone the
    /// relevant `Arc<dyn Fn>`, then releases the lock before invoking
    /// the callback. This keeps callbacks free to call back into
    /// `IceTransport` (which might in turn try to `set_callbacks`)
    /// without deadlocking.
    callbacks: Mutex<IceTransportCallbacks>,
    /// Set true by [`IceTransport::close`]. Gates the recv handler so
    /// `on_data` no longer fires once the transport is closed, even if
    /// the libjuice driver delivers more bytes before its socket is
    /// torn down on `Drop`.
    closed: AtomicBool,
}

impl Bridge {
    fn on_juice_state(&self, s: libjuice::State) {
        // Once we're closed, our `state` mutex is pinned at `Closed`
        // and the user has already been notified. Silently drop any
        // late libjuice state callbacks rather than risk re-firing.
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let new_state = map_state(s);
        let changed = {
            let mut g = self.state.lock();
            if *g != new_state {
                *g = new_state;
                true
            } else {
                false
            }
        };
        if changed {
            let cb = {
                let guard = self.callbacks.lock();
                Arc::clone(&guard.on_state_change)
            };
            (cb)(new_state);
        }
    }

    fn on_juice_candidate(&self, sdp: String) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let mid = self.mid.lock().clone();
        match Candidate::parse(&sdp, &mid) {
            Ok(c) => {
                let cb = {
                    let guard = self.callbacks.lock();
                    Arc::clone(&guard.on_candidate)
                };
                (cb)(c);
            }
            Err(e) => {
                // Match the C++ "ignore malformed candidates" stance at
                // `icetransport.cpp:344`.
                warn!("IceTransport: dropping malformed local candidate {sdp:?}: {e}");
            }
        }
    }

    fn on_juice_gathering_done(&self) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let changed = {
            let mut g = self.gathering_state.lock();
            if *g != GatheringState::Complete {
                *g = GatheringState::Complete;
                true
            } else {
                false
            }
        };
        if changed {
            let cb = {
                let guard = self.callbacks.lock();
                Arc::clone(&guard.on_gathering_state_change)
            };
            (cb)(GatheringState::Complete);
        }
    }

    fn on_juice_recv(&self, data: &[u8]) {
        // Drop any datagrams that race past close — DTLS in Task #14
        // relies on this gate to safely tear down its own state before
        // a final flurry of records lands.
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let cb = {
            let guard = self.callbacks.lock();
            Arc::clone(&guard.on_data)
        };
        (cb)(data);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pluck `a=ice-ufrag:` and `a=ice-pwd:` values out of a libjuice SDP
/// fragment. Returns `(ufrag, pwd)`; either may be `None` if the
/// fragment didn't carry that attribute (shouldn't happen for a real
/// libjuice fragment).
fn extract_ice_creds(fragment: &str) -> (Option<String>, Option<String>) {
    let mut ufrag = None;
    let mut pwd = None;
    for raw in fragment.lines() {
        let line = raw.trim_end_matches(['\r', '\n']);
        if let Some(v) = line.strip_prefix("a=ice-ufrag:") {
            ufrag = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("a=ice-pwd:") {
            pwd = Some(v.trim().to_string());
        }
    }
    (ufrag, pwd)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Spin until `pred` is true or `timeout_ms` elapses. Returns whether
    /// the predicate became true within the window.
    async fn wait_for<F: FnMut() -> bool>(mut pred: F, timeout_ms: u64) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if pred() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn construct_ok_with_minimal_config() {
        rt().block_on(async {
            let cfg = Configuration::new();
            let t = IceTransport::new(&cfg, Role::ActPass, IceTransportCallbacks::default())
                .expect("construct");
            assert_eq!(t.state(), State::New);
            assert_eq!(t.gathering_state(), GatheringState::New);
            assert_eq!(t.role(), Role::ActPass);
        });
    }

    #[test]
    fn construct_with_stun_server() {
        rt().block_on(async {
            let mut cfg = Configuration::new();
            cfg.add_ice_server("stun:stun.example.com:3478").unwrap();
            // Bind to loopback so the agent doesn't try to reach the
            // real (nonexistent) STUN server during the test.
            cfg.bind_address = Some("127.0.0.1".to_string());
            let t = IceTransport::new(&cfg, Role::ActPass, IceTransportCallbacks::default())
                .expect("construct with STUN");
            assert_eq!(t.state(), State::New);
        });
    }

    #[test]
    fn bind_address_bad_string_errors() {
        rt().block_on(async {
            let mut cfg = Configuration::new();
            cfg.bind_address = Some("not-an-ip".to_string());
            let err = IceTransport::new(&cfg, Role::ActPass, IceTransportCallbacks::default())
                .expect_err("bad bind address must error");
            assert!(matches!(
                err,
                IceTransportError::BadBindAddress { ref addr, .. } if addr == "not-an-ip"
            ));
        });
    }

    #[test]
    fn state_callback_fires_on_gather() {
        rt().block_on(async {
            let states: Arc<Mutex<Vec<State>>> = Arc::new(Mutex::new(Vec::new()));
            let states_cb = states.clone();
            let callbacks = IceTransportCallbacks {
                on_state_change: Arc::new(move |s| states_cb.lock().push(s)),
                ..IceTransportCallbacks::default()
            };

            let mut cfg = Configuration::new();
            cfg.bind_address = Some("127.0.0.1".to_string());
            let t = IceTransport::new(&cfg, Role::ActPass, callbacks).expect("construct");
            t.gather().expect("gather");

            // Wait up to a second for at least one state transition to
            // surface from the driver task.
            let got = wait_for(|| !states.lock().is_empty(), 1000).await;
            assert!(
                got,
                "no state transitions observed; states={:?}",
                states.lock().clone()
            );
        });
    }

    #[test]
    fn gather_emits_at_least_one_local_candidate() {
        rt().block_on(async {
            let count = Arc::new(AtomicUsize::new(0));
            let count_cb = count.clone();
            let callbacks = IceTransportCallbacks {
                on_candidate: Arc::new(move |_c| {
                    count_cb.fetch_add(1, Ordering::SeqCst);
                }),
                ..IceTransportCallbacks::default()
            };

            let mut cfg = Configuration::new();
            cfg.bind_address = Some("127.0.0.1".to_string());
            let t = IceTransport::new(&cfg, Role::ActPass, callbacks).expect("construct");
            t.gather().expect("gather");

            let got = wait_for(|| count.load(Ordering::SeqCst) > 0, 1500).await;
            assert!(
                got,
                "expected at least one local candidate; loopback host gathering should emit one"
            );
        });
    }

    #[test]
    fn gather_is_idempotent() {
        rt().block_on(async {
            let mut cfg = Configuration::new();
            cfg.bind_address = Some("127.0.0.1".to_string());
            let t = IceTransport::new(&cfg, Role::ActPass, IceTransportCallbacks::default())
                .expect("construct");
            assert_eq!(t.gathering_state(), GatheringState::New);
            t.gather().expect("first gather");
            assert_eq!(t.gathering_state(), GatheringState::InProgress);
            // Second call should not flip the state or error.
            t.gather().expect("second gather");
            assert_eq!(t.gathering_state(), GatheringState::InProgress);
        });
    }

    #[test]
    fn get_selected_pair_returns_err_before_connected() {
        rt().block_on(async {
            let cfg = Configuration::new();
            let t = IceTransport::new(&cfg, Role::ActPass, IceTransportCallbacks::default())
                .expect("construct");
            let err = t.get_selected_pair().expect_err("no pair yet");
            assert!(matches!(err, IceTransportError::NoSelectedPair));
        });
    }

    #[test]
    fn send_before_connected_errors() {
        rt().block_on(async {
            let cfg = Configuration::new();
            let t = IceTransport::new(&cfg, Role::ActPass, IceTransportCallbacks::default())
                .expect("construct");
            let err = t.send(b"hello").expect_err("send must fail pre-connect");
            // libjuice signals "no selected pair" via Error::NotAvailable.
            assert!(
                matches!(err, IceTransportError::Juice(libjuice::Error::NotAvailable)),
                "got {err:?}"
            );
        });
    }

    /// The gold-star loopback test: two IceTransports, one ActPass / one
    /// Active, signal their SDPs to each other and trickle candidates,
    /// converging on Connected within a few seconds on loopback.
    ///
    /// Sequence (mirrors the libjuice agent loopback test pattern):
    /// 1. Build both transports with a per-side `Vec<Candidate>` buffer
    ///    that `on_candidate` pushes into.
    /// 2. Drive `a.gather()`; wait for its `gathering_state == Complete`.
    /// 3. Take a's local Description (ufrag/pwd), give it to b as the
    ///    remote description.
    /// 4. Drive `b.gather()`; wait for completion; install on a.
    /// 5. Trickle each side's collected candidates into the OTHER side
    ///    via `add_remote_candidate`, then call
    ///    `set_remote_end_of_candidates`.
    /// 6. Wait up to 5s for both sides to fire
    ///    `on_state_change(Connected)`.
    #[test]
    fn two_transports_handshake_to_connected() {
        rt().block_on(async {
            // Per-side connected flag + candidate buffer.
            let a_connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let b_connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let a_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));
            let b_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));

            let ac = a_connected.clone();
            let bc = b_connected.clone();
            let a_cands_cb = a_cands.clone();
            let b_cands_cb = b_cands.clone();

            let a_callbacks = IceTransportCallbacks {
                on_state_change: Arc::new(move |s| {
                    if matches!(s, State::Connected | State::Completed) {
                        ac.store(true, Ordering::SeqCst);
                    }
                }),
                on_candidate: Arc::new(move |c| {
                    a_cands_cb.lock().push(c);
                }),
                ..IceTransportCallbacks::default()
            };

            let b_callbacks = IceTransportCallbacks {
                on_state_change: Arc::new(move |s| {
                    if matches!(s, State::Connected | State::Completed) {
                        bc.store(true, Ordering::SeqCst);
                    }
                }),
                on_candidate: Arc::new(move |c| {
                    b_cands_cb.lock().push(c);
                }),
                ..IceTransportCallbacks::default()
            };

            let mut cfg = Configuration::new();
            cfg.bind_address = Some("127.0.0.1".to_string());

            let a = IceTransport::new(&cfg, Role::ActPass, a_callbacks).expect("a");
            let b = IceTransport::new(&cfg, Role::Active, b_callbacks).expect("b");

            // --- 1. A gathers ---
            // We wait on the SDP carrying `end-of-candidates` rather than
            // on the `GatheringState::Complete` callback so this test
            // pins down behaviour even if a future libjuice change moves
            // the order of `gathering_done` vs. the final candidate.
            let t_start = std::time::Instant::now();
            a.gather().expect("a gather");
            assert!(
                wait_for(
                    || a.agent
                        .get_local_description()
                        .map(|s| s.contains("end-of-candidates"))
                        .unwrap_or(false),
                    3000
                )
                .await,
                "A never finished gathering (gathering_state={:?})",
                a.gathering_state()
            );

            // --- 2. Hand A's description to B ---
            let desc_a = a
                .get_local_description(DescriptionType::Offer)
                .expect("a sdp");
            b.set_remote_description(&desc_a).expect("b set remote");

            // --- 3. B gathers ---
            b.gather().expect("b gather");
            assert!(
                wait_for(
                    || b.agent
                        .get_local_description()
                        .map(|s| s.contains("end-of-candidates"))
                        .unwrap_or(false),
                    3000
                )
                .await,
                "B never finished gathering (gathering_state={:?})",
                b.gathering_state()
            );

            // --- 4. Hand B's description to A ---
            let desc_b = b
                .get_local_description(DescriptionType::Answer)
                .expect("b sdp");
            a.set_remote_description(&desc_b).expect("a set remote");

            // --- 5. Trickle collected candidates across (A → B, B → A) ---
            for c in a_cands.lock().iter() {
                b.add_remote_candidate(c).expect("trickle a→b");
            }
            for c in b_cands.lock().iter() {
                a.add_remote_candidate(c).expect("trickle b→a");
            }
            a.set_remote_end_of_candidates().expect("a eoc");
            b.set_remote_end_of_candidates().expect("b eoc");

            // --- 6. Wait for both sides to reach Connected ---
            let connected = wait_for(
                || a_connected.load(Ordering::SeqCst) && b_connected.load(Ordering::SeqCst),
                5000,
            )
            .await;
            let elapsed = t_start.elapsed();

            assert!(
                connected,
                "loopback handshake did not converge in {:?}: \
                 a_connected={}, b_connected={}, a_state={:?}, b_state={:?}, \
                 a_cands={}, b_cands={}",
                elapsed,
                a_connected.load(Ordering::SeqCst),
                b_connected.load(Ordering::SeqCst),
                a.state(),
                b.state(),
                a_cands.lock().len(),
                b_cands.lock().len(),
            );

            eprintln!(
                "loopback handshake converged in {:?} (a_cands={}, b_cands={})",
                elapsed,
                a_cands.lock().len(),
                b_cands.lock().len()
            );

            // Sanity: selected pair queryable on both sides now.
            assert!(a.get_selected_pair().is_ok());
            assert!(b.get_selected_pair().is_ok());
        });
    }

    // ---------------------------------------------------------------
    // Phase G-4b: ICE restart, eager close, runtime callback swap.
    // ---------------------------------------------------------------

    #[test]
    fn restart_ice_resets_state_flags() {
        rt().block_on(async {
            // Capture gathering-state transitions so we can assert the
            // restart fires `on_gathering_state_change(New)`.
            let gstates: Arc<Mutex<Vec<GatheringState>>> = Arc::new(Mutex::new(Vec::new()));
            let gstates_cb = gstates.clone();
            let callbacks = IceTransportCallbacks {
                on_gathering_state_change: Arc::new(move |g| {
                    gstates_cb.lock().push(g);
                }),
                ..IceTransportCallbacks::default()
            };

            let mut cfg = Configuration::new();
            cfg.bind_address = Some("127.0.0.1".to_string());
            let t = IceTransport::new(&cfg, Role::ActPass, callbacks).expect("construct");

            t.gather().expect("gather");
            assert_eq!(t.gathering_state(), GatheringState::InProgress);
            // The synchronous part of gather() must have pushed
            // InProgress already.
            assert!(
                gstates
                    .lock()
                    .iter()
                    .any(|g| *g == GatheringState::InProgress),
                "expected InProgress in {:?}",
                gstates.lock().clone()
            );

            t.restart_ice().expect("restart_ice");
            assert_eq!(t.gathering_state(), GatheringState::New);

            // The restart should have fired a New transition on the
            // gathering-state callback.
            assert!(
                gstates.lock().iter().any(|g| *g == GatheringState::New),
                "expected New after restart in {:?}",
                gstates.lock().clone()
            );
        });
    }

    #[test]
    fn close_transitions_to_closed_state() {
        rt().block_on(async {
            let states: Arc<Mutex<Vec<State>>> = Arc::new(Mutex::new(Vec::new()));
            let states_cb = states.clone();
            let callbacks = IceTransportCallbacks {
                on_state_change: Arc::new(move |s| states_cb.lock().push(s)),
                ..IceTransportCallbacks::default()
            };

            let cfg = Configuration::new();
            let t = IceTransport::new(&cfg, Role::ActPass, callbacks).expect("construct");

            t.close().expect("close");
            assert_eq!(t.state(), State::Closed);
            assert!(
                states.lock().iter().any(|s| *s == State::Closed),
                "expected Closed in {:?}",
                states.lock().clone()
            );
        });
    }

    #[test]
    fn close_is_idempotent() {
        rt().block_on(async {
            let closed_calls = Arc::new(AtomicUsize::new(0));
            let closed_calls_cb = closed_calls.clone();
            let callbacks = IceTransportCallbacks {
                on_state_change: Arc::new(move |s| {
                    if s == State::Closed {
                        closed_calls_cb.fetch_add(1, Ordering::SeqCst);
                    }
                }),
                ..IceTransportCallbacks::default()
            };

            let cfg = Configuration::new();
            let t = IceTransport::new(&cfg, Role::ActPass, callbacks).expect("construct");

            t.close().expect("first close");
            t.close().expect("second close");

            assert_eq!(
                closed_calls.load(Ordering::SeqCst),
                1,
                "close() must fire the Closed callback exactly once"
            );
            assert_eq!(t.state(), State::Closed);
        });
    }

    #[test]
    fn send_after_close_errors() {
        rt().block_on(async {
            let cfg = Configuration::new();
            let t = IceTransport::new(&cfg, Role::ActPass, IceTransportCallbacks::default())
                .expect("construct");
            t.close().expect("close");
            let err = t.send(b"hi").expect_err("send after close must fail");
            assert!(
                matches!(err, IceTransportError::Closed),
                "expected Closed, got {err:?}"
            );
        });
    }

    #[test]
    fn add_remote_candidate_after_close_errors() {
        rt().block_on(async {
            let cfg = Configuration::new();
            let t = IceTransport::new(&cfg, Role::ActPass, IceTransportCallbacks::default())
                .expect("construct");
            t.close().expect("close");
            // Construct a syntactically-valid host candidate so the
            // pre-flight `is_resolved` check doesn't short-circuit
            // before the closed check.
            let cand =
                Candidate::parse("candidate:1 1 UDP 2122252543 127.0.0.1 54321 typ host", "0")
                    .expect("parse cand");
            let err = t
                .add_remote_candidate(&cand)
                .expect_err("add_remote_candidate after close must fail");
            assert!(
                matches!(err, IceTransportError::Closed),
                "expected Closed, got {err:?}"
            );
        });
    }

    #[test]
    fn set_callbacks_replaces_existing() {
        rt().block_on(async {
            let a_calls = Arc::new(AtomicUsize::new(0));
            let b_calls = Arc::new(AtomicUsize::new(0));
            let a_calls_cb = a_calls.clone();

            // Initial callbacks: only A counts state transitions.
            let initial = IceTransportCallbacks {
                on_state_change: Arc::new(move |_s| {
                    a_calls_cb.fetch_add(1, Ordering::SeqCst);
                }),
                ..IceTransportCallbacks::default()
            };

            let cfg = Configuration::new();
            let t = IceTransport::new(&cfg, Role::ActPass, initial).expect("construct");

            // Swap in a new set: only B counts.
            let b_calls_cb = b_calls.clone();
            let replacement = IceTransportCallbacks {
                on_state_change: Arc::new(move |_s| {
                    b_calls_cb.fetch_add(1, Ordering::SeqCst);
                }),
                ..IceTransportCallbacks::default()
            };
            t.set_callbacks(replacement);

            // Trigger a state change via close().
            t.close().expect("close");

            assert_eq!(
                a_calls.load(Ordering::SeqCst),
                0,
                "old callback must not fire after set_callbacks"
            );
            assert_eq!(
                b_calls.load(Ordering::SeqCst),
                1,
                "new callback must fire on close()"
            );
        });
    }

    #[test]
    fn callbacks_getter_round_trips() {
        // The snapshot returned by `callbacks()` should be a live Arc
        // clone of the currently-installed set: invoking it dispatches
        // to the same closures, and a subsequent `set_callbacks` does
        // NOT mutate the snapshot we already took.
        rt().block_on(async {
            let original_calls = Arc::new(AtomicUsize::new(0));
            let original_calls_cb = original_calls.clone();
            let initial = IceTransportCallbacks {
                on_state_change: Arc::new(move |_s| {
                    original_calls_cb.fetch_add(1, Ordering::SeqCst);
                }),
                ..IceTransportCallbacks::default()
            };

            let cfg = Configuration::new();
            let t = IceTransport::new(&cfg, Role::ActPass, initial).expect("construct");

            // Snapshot the original on_state_change closure.
            let snapshot = t.callbacks();

            // Now install something else.
            let replacement_calls = Arc::new(AtomicUsize::new(0));
            let replacement_calls_cb = replacement_calls.clone();
            t.set_callbacks(IceTransportCallbacks {
                on_state_change: Arc::new(move |_s| {
                    replacement_calls_cb.fetch_add(1, Ordering::SeqCst);
                }),
                ..IceTransportCallbacks::default()
            });

            // Manually invoke the snapshot — it should still point at
            // the original closure (Arc keepalive).
            (snapshot.on_state_change)(State::Connected);
            assert_eq!(
                original_calls.load(Ordering::SeqCst),
                1,
                "snapshot must keep the original closure alive"
            );
            assert_eq!(
                replacement_calls.load(Ordering::SeqCst),
                0,
                "snapshot must not see the replacement"
            );

            // And the transport itself now dispatches to the replacement.
            t.close().expect("close");
            assert_eq!(
                replacement_calls.load(Ordering::SeqCst),
                1,
                "transport must dispatch to the replacement after set_callbacks"
            );
        });
    }

    #[test]
    fn callbacks_default_are_safe_noops() {
        rt().block_on(async {
            let cfg = Configuration::new();
            let t = IceTransport::new(&cfg, Role::ActPass, IceTransportCallbacks::default())
                .expect("construct");
            t.set_callbacks(IceTransportCallbacks::default());
            // Trigger close() — the default on_state_change must just
            // do nothing rather than panic.
            t.close().expect("close");
            assert_eq!(t.state(), State::Closed);
        });
    }
}
