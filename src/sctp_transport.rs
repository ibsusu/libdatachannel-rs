//! SCTP transport — scaffolding port of `rtc::impl::SctpTransport` from
//! `native/libdatachannel/src/impl/sctptransport.cpp`.
//!
//! ## Phase G-6a (this file): STUB only — no `usrsctp` linkage
//!
//! This iteration establishes the transport **layering** and **state
//! machine** so the DataChannel layer (Task #18) has a stable surface to
//! compile against, and so Phase G-6b becomes a mechanical "fill in the
//! FFI" job. It deliberately does NOT:
//!
//! - link or compile `usrsctp` (no `build.rs`, no `cc`, no `bindgen`),
//! - open a real SCTP association (state tops out at
//!   [`SctpState::Connecting`] — see below),
//! - parse DCEP (DataChannel Establishment Protocol) messages (Task #18),
//! - implement partial-reliability send (`usrsctp_sendv`) — [`send`] is a
//!   typed stub.
//!
//! The two seams that G-6b fills are [`SctpTransport::connect`] (which
//! today only flips New → Connecting; G-6b kicks `usrsctp_connect` and
//! lets the `SCTP_ASSOC_CHANGE`/`SCTP_COMM_UP` notification flip
//! Connecting → Connected) and [`SctpTransport::feed_inbound`] (which
//! today is a trace-level no-op; G-6b wires it to `usrsctp_conninput`).
//!
//! ## Architecture (mirrors [`crate::DtlsTransport`])
//!
//! The transport is an `Arc<Self>` holding the lower [`DtlsTransport`], a
//! [`parking_lot::Mutex<Inner>`] for the (future) socket state, an
//! [`AtomicU8`] state cell, `closed`/`started` [`AtomicBool`] guards, and
//! a `Mutex<SctpTransportCallbacks>`.
//!
//! On construction we install an `on_data` shim on the DTLS transport
//! that routes decrypted application records into [`feed_inbound`], while
//! preserving the upstream (PeerConnection-owned) `on_state_change`. We
//! also chain the DTLS `on_state_change` so that when DTLS reaches
//! [`crate::DtlsState::Connected`] we auto-call [`connect`]. This mirrors
//! the way [`DtlsTransport::new`] auto-starts off ICE-Connected.
//!
//! [`feed_inbound`]: SctpTransport::feed_inbound
//! [`connect`]: SctpTransport::connect
//! [`send`]: SctpTransport::send

use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc,
};

use parking_lot::Mutex;
use thiserror::Error;
use tracing::trace;

use crate::dtls_transport::{DtlsState, DtlsTransportCallbacks};
use crate::{DtlsTransport, Reliability};

/// SCTP port WebRTC always uses for the data-channel association
/// (RFC 8831 §6.2). Mirrors `DEFAULT_SCTP_PORT` in
/// `native/libdatachannel/src/impl/internals.hpp`.
const DEFAULT_SCTP_PORT: u16 = 5000;

/// WebRTC SCTP association state.
///
/// Mirrors the subset of `rtc::Transport::State` that
/// `rtc::impl::SctpTransport` actually transitions through. The C++ uses
/// a shared `Transport::State` enum that also has `Disconnected`; we fold
/// the disconnect path into [`SctpState::Closed`] for the data-channel
/// surface (G-6b revisits this if a distinct Disconnected proves useful).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpState {
    /// Constructed; [`SctpTransport::connect`] has not run yet.
    New,
    /// Association handshake in progress. In this stub phase this is the
    /// terminal "up" state — real Connected awaits the usrsctp
    /// `SCTP_COMM_UP` notification wired in G-6b.
    Connecting,
    /// Association established; messages can flow. **Unreachable in
    /// G-6a** — documented here so the DataChannel layer can match on it.
    Connected,
    /// The association attempt failed, or the lower DTLS transport went
    /// down.
    Failed,
    /// [`SctpTransport::close`] was called or the peer closed the
    /// association.
    Closed,
}

impl SctpState {
    fn from_u8(v: u8) -> SctpState {
        match v {
            0 => SctpState::New,
            1 => SctpState::Connecting,
            2 => SctpState::Connected,
            3 => SctpState::Failed,
            _ => SctpState::Closed,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            SctpState::New => 0,
            SctpState::Connecting => 1,
            SctpState::Connected => 2,
            SctpState::Failed => 3,
            SctpState::Closed => 4,
        }
    }
}

/// PPIDs for the WebRTC DataChannel protocol (RFC 8831 §8).
///
/// The numeric values look out of order because they are — they're the
/// actual IANA-assigned values, copied from the C++ `PayloadId` enum at
/// `sctptransport.hpp:66`. The `*Partial` variants are deprecated
/// (PPID-based fragmentation) and are kept for receive-side parity; we
/// must never *send* them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PayloadProtocolId {
    /// DCEP (DataChannel Establishment Protocol) control message.
    Control = 50,
    /// UTF-8 string payload.
    String = 51,
    /// Binary payload.
    Binary = 53,
    /// Empty string payload (SCTP requires at least one byte on the wire,
    /// so an empty string is signalled by this PPID).
    StringEmpty = 56,
    /// Empty binary payload.
    BinaryEmpty = 57,
    /// Deprecated PPID-based string fragment. Receive-only; never sent.
    StringPartial = 54,
    /// Deprecated PPID-based binary fragment. Receive-only; never sent.
    BinaryPartial = 52,
}

impl PayloadProtocolId {
    /// Map a raw on-the-wire PPID (host byte order) to the enum, if known.
    /// Unknown PPIDs are dropped by the C++ (`COUNTER_UNKNOWN_PPID`); the
    /// G-6b recv path will mirror that by treating `None` as "ignore".
    pub fn from_u32(v: u32) -> Option<PayloadProtocolId> {
        match v {
            50 => Some(PayloadProtocolId::Control),
            51 => Some(PayloadProtocolId::String),
            53 => Some(PayloadProtocolId::Binary),
            56 => Some(PayloadProtocolId::StringEmpty),
            57 => Some(PayloadProtocolId::BinaryEmpty),
            54 => Some(PayloadProtocolId::StringPartial),
            52 => Some(PayloadProtocolId::BinaryPartial),
            _ => None,
        }
    }
}

/// A message arriving from / destined for a single SCTP stream.
#[derive(Debug, Clone)]
pub struct SctpMessage {
    /// SCTP stream identifier (`snd_sid` / `rcv_sid`).
    pub stream: u16,
    /// Payload protocol identifier.
    pub ppid: PayloadProtocolId,
    /// Reassembled payload bytes (a complete message — the C++ reassembles
    /// partial deliveries on `MSG_EOR` before surfacing).
    pub data: Vec<u8>,
}

/// Callbacks the [`SctpTransport`] invokes.
#[derive(Clone)]
pub struct SctpTransportCallbacks {
    /// Fires on every association state transition.
    pub on_state_change: Arc<dyn Fn(SctpState) + Send + Sync>,
    /// Fires for each inbound reassembled message.
    pub on_message: Arc<dyn Fn(SctpMessage) + Send + Sync>,
    /// Fires when the buffered amount on a stream drops below the low
    /// threshold (used by DataChannel backpressure later). The argument is
    /// the stream id. Mirrors the C++ `amount_callback`.
    pub on_buffered_amount_low: Arc<dyn Fn(u16) + Send + Sync>,
}

impl Default for SctpTransportCallbacks {
    fn default() -> Self {
        SctpTransportCallbacks {
            on_state_change: Arc::new(|_| {}),
            on_message: Arc::new(|_| {}),
            on_buffered_amount_low: Arc::new(|_| {}),
        }
    }
}

/// Errors returned by [`SctpTransport`] operations.
#[derive(Debug, Error)]
pub enum SctpTransportError {
    /// [`SctpTransport::send`] was called before the association reached
    /// [`SctpState::Connected`].
    #[error("sctp transport not connected (state = {0:?})")]
    NotConnected(SctpState),

    /// Operation called on a closed transport.
    #[error("sctp transport closed")]
    Closed,

    /// The send path is not yet implemented — `usrsctp_sendv` lands in
    /// Phase G-6b. The signature is final; only the body is a stub.
    #[error("usrsctp not yet wired (Phase G-6b)")]
    NotImplemented,

    /// Forwarded from the lower [`DtlsTransport`].
    #[error("dtls transport: {0}")]
    Dtls(#[from] crate::DtlsTransportError),
}

/// Inner mutable state. In G-6a these fields are placeholders documenting
/// the seam the usrsctp socket plugs into; they are held behind the same
/// `Mutex` discipline `DtlsTransport::Inner` uses so G-6b can drop in the
/// raw `*mut socket` (with a hand-written `unsafe impl Send`) without
/// reshaping the type.
struct Inner {
    /// PLACEHOLDER for the usrsctp socket association.
    ///
    /// G-6b replaces this with the `*mut usrsctp::socket` returned by
    /// `usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, ...)` and flips
    /// it true on the `SCTP_COMM_UP` notification. For now it just records
    /// whether [`SctpTransport::connect`] has run.
    associated: bool,
    /// PLACEHOLDER for outbound SCTP packets produced by usrsctp's write
    /// callback (`SctpTransport::WriteCallback` in C++), which would be
    /// handed to `dtls.send()`. Unused in the stub.
    _pending_out: Vec<Vec<u8>>,
}

/// The SCTP transport. Cheap to clone via the surrounding `Arc<Self>`,
/// matching the [`DtlsTransport`] / [`crate::IceTransport`] pattern.
pub struct SctpTransport {
    /// Lower transport. We install our `on_data` shim on it and (in G-6b)
    /// push outbound SCTP packets through `dtls.send()`.
    dtls: Arc<DtlsTransport>,
    /// Future socket state (see [`Inner`]).
    inner: Mutex<Inner>,
    /// Current [`SctpState`], encoded as a `u8` for lock-free reads.
    state: AtomicU8,
    /// Set once [`close`](Self::close) runs so the DTLS recv shim and all
    /// mutators short-circuit.
    closed: AtomicBool,
    /// Guards [`connect`](Self::connect) against double-driving when the
    /// auto-connect (DTLS-Connected) hook and an explicit user call race.
    started: AtomicBool,
    /// Application-installed callbacks.
    callbacks: Mutex<SctpTransportCallbacks>,
    /// Local SCTP port (RFC 8831 §6.2: always 5000).
    local_port: u16,
    /// Remote SCTP port (always 5000).
    remote_port: u16,
}

impl std::fmt::Debug for SctpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SctpTransport")
            .field("state", &self.state())
            .field("local_port", &self.local_port)
            .field("remote_port", &self.remote_port)
            .finish()
    }
}

impl SctpTransport {
    /// Build the SCTP transport over a [`DtlsTransport`]. Local and remote
    /// SCTP ports default to 5000 (RFC 8831 §6.2).
    ///
    /// The constructor installs an `on_data` shim on the DTLS transport
    /// that routes decrypted records into [`feed_inbound`](Self::feed_inbound)
    /// (a no-op trace in this stub phase), while **preserving** the
    /// upstream `on_state_change` so the PeerConnection still sees DTLS
    /// state transitions. It additionally chains the DTLS `on_state_change`
    /// so that when DTLS reaches [`DtlsState::Connected`] the SCTP
    /// transport auto-calls [`connect`](Self::connect) — exactly how
    /// [`DtlsTransport::new`] auto-starts off ICE-Connected.
    ///
    /// Returns the handle in [`SctpState::New`]; call
    /// [`connect`](Self::connect) (or let the auto-connect hook fire) to
    /// begin the association.
    pub fn new(
        dtls: Arc<DtlsTransport>,
        callbacks: SctpTransportCallbacks,
    ) -> Arc<Self> {
        let transport = Arc::new(SctpTransport {
            dtls: Arc::clone(&dtls),
            inner: Mutex::new(Inner {
                associated: false,
                _pending_out: Vec::new(),
            }),
            state: AtomicU8::new(SctpState::New.as_u8()),
            closed: AtomicBool::new(false),
            started: AtomicBool::new(false),
            callbacks: Mutex::new(callbacks),
            local_port: DEFAULT_SCTP_PORT,
            remote_port: DEFAULT_SCTP_PORT,
        });

        // Install our recv shim + auto-connect hook on the DTLS transport.
        // We snapshot the existing DTLS callbacks and chain them so the
        // PeerConnection-owned on_state_change is preserved and any prior
        // on_data still fires (DTLS surfaces non-SCTP records there until
        // demux lands; for now we just also pump into feed_inbound).
        let prev = dtls.callbacks();
        let weak = Arc::downgrade(&transport);

        let new_on_state_change = {
            let prev_state = Arc::clone(&prev.on_state_change);
            let weak = weak.clone();
            Arc::new(move |s: DtlsState| {
                if matches!(s, DtlsState::Connected) {
                    if let Some(this) = weak.upgrade() {
                        // connect() is idempotent (started AtomicBool).
                        this.connect();
                    }
                }
                (prev_state)(s);
            })
        };

        let new_on_data = {
            let prev_data = Arc::clone(&prev.on_data);
            let weak = weak.clone();
            Arc::new(move |data: &[u8]| {
                if let Some(this) = weak.upgrade() {
                    this.feed_inbound(data);
                }
                // Preserve any upstream on_data the application installed
                // on DTLS directly. Once full SCTP demux lands this chain
                // can be dropped, but keeping it now is harmless.
                (prev_data)(data);
            })
        };

        dtls.set_callbacks(DtlsTransportCallbacks {
            on_state_change: new_on_state_change,
            on_data: new_on_data,
        });

        transport
    }

    /// Current SCTP association state.
    pub fn state(&self) -> SctpState {
        SctpState::from_u8(self.state.load(Ordering::SeqCst))
    }

    /// Local SCTP port (always 5000 in WebRTC).
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Remote SCTP port (always 5000 in WebRTC).
    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }

    /// Begin the SCTP association.
    ///
    /// Transitions New → Connecting and fires `on_state_change(Connecting)`.
    /// Idempotent via the `started` [`AtomicBool`] (so the auto-connect
    /// DTLS-Connected hook and an explicit user call can race safely).
    ///
    /// **G-6a stub:** this is the honest ceiling — the C++ here calls
    /// `usrsctp_bind` + `usrsctp_connect` and the association reaches
    /// `Connected` only once the `SCTP_ASSOC_CHANGE` / `SCTP_COMM_UP`
    /// notification arrives on the upcall thread. None of that is wired
    /// yet, so we stop at Connecting and do not fake Connected.
    pub fn connect(self: &Arc<Self>) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }

        // Idempotency guard: the second caller short-circuits.
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }

        // Only transition if we're still in New (covers close-during-connect).
        let changed = {
            // CAS New(0) → Connecting(1).
            self.state
                .compare_exchange(
                    SctpState::New.as_u8(),
                    SctpState::Connecting.as_u8(),
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
        };
        if !changed {
            return;
        }

        self.inner.lock().associated = true;

        trace!(
            local_port = self.local_port,
            remote_port = self.remote_port,
            "SctpTransport::connect: New -> Connecting (usrsctp_bind / \
             usrsctp_connect not yet wired — Phase G-6b)"
        );

        let cb = {
            let g = self.callbacks.lock();
            Arc::clone(&g.on_state_change)
        };
        (cb)(SctpState::Connecting);
    }

    /// Send a message on a stream with the given reliability parameters.
    ///
    /// The signature is final — the DataChannel layer (Task #18) calls
    /// exactly this. **G-6a stub:** returns
    /// [`SctpTransportError::Closed`] if closed,
    /// [`SctpTransportError::NotConnected`] unless state is
    /// [`SctpState::Connected`], and (since Connected is unreachable in
    /// this phase) [`SctpTransportError::NotImplemented`] otherwise.
    /// G-6b implements this via `usrsctp_sendv` with an `sctp_sendv_spa`
    /// built from `reliability` (PR-SCTP TTL / RTX policy).
    pub fn send(
        &self,
        msg: &SctpMessage,
        reliability: &Reliability,
    ) -> Result<(), SctpTransportError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SctpTransportError::Closed);
        }
        let state = self.state();
        if !matches!(state, SctpState::Connected) {
            return Err(SctpTransportError::NotConnected(state));
        }
        // Connected is unreachable in G-6a, but keep the typed stub so the
        // surface is final. usrsctp_sendv lands in G-6b.
        let _ = (msg, reliability);
        Err(SctpTransportError::NotImplemented)
    }

    /// Swap the callback set at runtime.
    pub fn set_callbacks(&self, callbacks: SctpTransportCallbacks) {
        *self.callbacks.lock() = callbacks;
    }

    /// Snapshot of the currently-installed callback set (symmetric with
    /// [`DtlsTransport::callbacks`]).
    pub fn callbacks(&self) -> SctpTransportCallbacks {
        let g = self.callbacks.lock();
        SctpTransportCallbacks {
            on_state_change: Arc::clone(&g.on_state_change),
            on_message: Arc::clone(&g.on_message),
            on_buffered_amount_low: Arc::clone(&g.on_buffered_amount_low),
        }
    }

    /// Close the transport. Idempotent; fires `on_state_change(Closed)`
    /// exactly once. Gates all mutators thereafter.
    ///
    /// **G-6b:** this is where `usrsctp_shutdown` / `usrsctp_close` /
    /// `usrsctp_deregister_address` get called.
    pub fn close(&self) -> Result<(), SctpTransportError> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // Transition to Closed unless already Closed.
        let prev = self
            .state
            .swap(SctpState::Closed.as_u8(), Ordering::SeqCst);
        if prev != SctpState::Closed.as_u8() {
            let cb = {
                let g = self.callbacks.lock();
                Arc::clone(&g.on_state_change)
            };
            (cb)(SctpState::Closed);
        }
        self.inner.lock().associated = false;
        Ok(())
    }

    /// Inbound DTLS record → SCTP. **G-6a stub:** logs at trace and does
    /// nothing. G-6b wires this to `usrsctp_conninput(this, data, len, 0)`,
    /// whose recv path reassembles messages and surfaces them via
    /// `on_message`.
    fn feed_inbound(&self, data: &[u8]) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        trace!(
            len = data.len(),
            "SctpTransport::feed_inbound: dropping {} byte(s) — \
             usrsctp_conninput not yet wired (Phase G-6b)",
            data.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicUsize;

    use crate::certificate::Certificate;
    use crate::configuration::Configuration;
    use crate::description::Role;
    use crate::ice_transport::{IceTransport, IceTransportCallbacks};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Construct a real DTLS-over-ICE transport without driving any
    /// handshake — enough to layer SCTP on top and exercise the stub
    /// state machine.
    fn make_dtls(role: Role) -> Arc<DtlsTransport> {
        let mut cfg = Configuration::new();
        cfg.bind_address = Some("127.0.0.1".to_string());
        let ice = IceTransport::new(&cfg, role, IceTransportCallbacks::default())
            .expect("ice");
        let cert = Certificate::generate_default().expect("cert");
        Arc::new(
            DtlsTransport::new(ice, cert, DtlsTransportCallbacks::default())
                .expect("dtls new"),
        )
    }

    fn sample_message() -> SctpMessage {
        SctpMessage {
            stream: 0,
            ppid: PayloadProtocolId::String,
            data: b"hello".to_vec(),
        }
    }

    #[test]
    fn new_starts_in_new_state() {
        rt().block_on(async {
            let dtls = make_dtls(Role::Active);
            let sctp = SctpTransport::new(dtls, SctpTransportCallbacks::default());
            assert_eq!(sctp.state(), SctpState::New);
            assert_eq!(sctp.local_port(), 5000);
            assert_eq!(sctp.remote_port(), 5000);
        });
    }

    #[test]
    fn connect_transitions_to_connecting() {
        rt().block_on(async {
            let states: Arc<Mutex<Vec<SctpState>>> = Arc::new(Mutex::new(Vec::new()));
            let states_cb = states.clone();
            let callbacks = SctpTransportCallbacks {
                on_state_change: Arc::new(move |s| states_cb.lock().push(s)),
                ..SctpTransportCallbacks::default()
            };
            let dtls = make_dtls(Role::Active);
            let sctp = SctpTransport::new(dtls, callbacks);

            assert_eq!(sctp.state(), SctpState::New);
            sctp.connect();
            assert_eq!(sctp.state(), SctpState::Connecting);
            assert!(
                states.lock().iter().any(|s| matches!(s, SctpState::Connecting)),
                "expected Connecting in {:?}",
                states.lock().clone()
            );
        });
    }

    #[test]
    fn connect_is_idempotent() {
        rt().block_on(async {
            let connecting_count = Arc::new(AtomicUsize::new(0));
            let cb = connecting_count.clone();
            let callbacks = SctpTransportCallbacks {
                on_state_change: Arc::new(move |s| {
                    if matches!(s, SctpState::Connecting) {
                        cb.fetch_add(1, Ordering::SeqCst);
                    }
                }),
                ..SctpTransportCallbacks::default()
            };
            let dtls = make_dtls(Role::Active);
            let sctp = SctpTransport::new(dtls, callbacks);

            sctp.connect();
            sctp.connect();
            assert_eq!(
                connecting_count.load(Ordering::SeqCst),
                1,
                "connect() must fire Connecting exactly once"
            );
            assert_eq!(sctp.state(), SctpState::Connecting);
        });
    }

    #[test]
    fn send_before_connected_errors_not_connected() {
        rt().block_on(async {
            let dtls = make_dtls(Role::Active);
            let sctp = SctpTransport::new(dtls, SctpTransportCallbacks::default());

            let err = sctp
                .send(&sample_message(), &Reliability::reliable())
                .expect_err("send before connect must fail");
            assert!(
                matches!(err, SctpTransportError::NotConnected(SctpState::New)),
                "got {err:?}"
            );

            // Same after connect() (still Connecting, not Connected).
            sctp.connect();
            let err = sctp
                .send(&sample_message(), &Reliability::reliable())
                .expect_err("send while connecting must fail");
            assert!(
                matches!(
                    err,
                    SctpTransportError::NotConnected(SctpState::Connecting)
                ),
                "got {err:?}"
            );
        });
    }

    #[test]
    fn close_transitions_to_closed_and_is_idempotent() {
        rt().block_on(async {
            let count = Arc::new(AtomicUsize::new(0));
            let cb = count.clone();
            let callbacks = SctpTransportCallbacks {
                on_state_change: Arc::new(move |s| {
                    if matches!(s, SctpState::Closed) {
                        cb.fetch_add(1, Ordering::SeqCst);
                    }
                }),
                ..SctpTransportCallbacks::default()
            };
            let dtls = make_dtls(Role::Active);
            let sctp = SctpTransport::new(dtls, callbacks);

            sctp.close().expect("first close");
            sctp.close().expect("second close");
            assert_eq!(sctp.state(), SctpState::Closed);
            assert_eq!(
                count.load(Ordering::SeqCst),
                1,
                "Closed callback must fire exactly once"
            );
        });
    }

    #[test]
    fn send_after_close_errors_closed() {
        rt().block_on(async {
            let dtls = make_dtls(Role::Active);
            let sctp = SctpTransport::new(dtls, SctpTransportCallbacks::default());

            sctp.close().expect("close");
            let err = sctp
                .send(&sample_message(), &Reliability::reliable())
                .expect_err("send after close must fail");
            assert!(matches!(err, SctpTransportError::Closed), "got {err:?}");
        });
    }

    #[test]
    fn connect_after_close_is_noop() {
        // Closing before any connect must keep us Closed; a subsequent
        // connect() must not resurrect the transport.
        rt().block_on(async {
            let dtls = make_dtls(Role::Active);
            let sctp = SctpTransport::new(dtls, SctpTransportCallbacks::default());

            sctp.close().expect("close");
            sctp.connect();
            assert_eq!(sctp.state(), SctpState::Closed);
        });
    }

    #[test]
    fn payload_protocol_id_round_trips() {
        // The wire values are the IANA-assigned PPIDs; round-trip a few
        // through from_u32 to lock in the (deliberately non-sequential)
        // mapping the DataChannel layer will rely on.
        for ppid in [
            PayloadProtocolId::Control,
            PayloadProtocolId::String,
            PayloadProtocolId::Binary,
            PayloadProtocolId::StringEmpty,
            PayloadProtocolId::BinaryEmpty,
            PayloadProtocolId::StringPartial,
            PayloadProtocolId::BinaryPartial,
        ] {
            let raw = ppid as u32;
            assert_eq!(PayloadProtocolId::from_u32(raw), Some(ppid));
        }
        assert_eq!(PayloadProtocolId::Control as u32, 50);
        assert_eq!(PayloadProtocolId::Binary as u32, 53);
        assert_eq!(PayloadProtocolId::from_u32(99), None);
    }
}
