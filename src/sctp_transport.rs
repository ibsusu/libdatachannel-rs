//! SCTP transport — port of `rtc::impl::SctpTransport` from
//! `native/libdatachannel/src/impl/sctptransport.cpp`, running SCTP over
//! DTLS via the vendored `usrsctp` C library through FFI
//! ([`crate::usrsctp_sys`]).
//!
//! ## Architecture (mirrors [`crate::DtlsTransport`])
//!
//! The transport is an `Arc<Self>` holding the lower [`DtlsTransport`], a
//! [`parking_lot::Mutex<Inner>`] owning the raw `*mut usrsctp::socket`
//! (with a hand-written `unsafe impl Send`), an [`AtomicU8`] state cell,
//! `closed`/`started` [`AtomicBool`] guards, and a
//! `Mutex<SctpTransportCallbacks>`.
//!
//! On construction we install an `on_data` shim on the DTLS transport that
//! routes decrypted records into [`feed_inbound`](SctpTransport::feed_inbound)
//! → `usrsctp_conninput`, while preserving the upstream
//! `on_state_change`. We also chain the DTLS `on_state_change` so that
//! when DTLS reaches [`crate::DtlsState::Connected`] we auto-call
//! [`connect`](SctpTransport::connect). usrsctp's write callback routes
//! outbound SCTP packets back through [`DtlsTransport::send`].
//!
//! ## usrsctp threading / instance safety
//!
//! usrsctp invokes the write callback and the socket upcall with a raw
//! `void*` we hand it at socket-creation / `usrsctp_register_address`
//! time. That pointer is this transport's `Arc<SctpTransport>` (as a raw
//! `*const`). Because usrsctp can fire those callbacks on its own thread
//! — including, per sctplab/usrsctp#405, briefly after `usrsctp_close` —
//! we guard every callback dispatch through a global instances set
//! (mirroring the C++ `InstancesSet`): a pointer that isn't currently
//! registered is treated as stale and ignored. The two loopback
//! transports register distinct pointers so `usrsctp_conninput` and the
//! write callback never cross-talk.
//!
//! Per RFC 8841 §9.3 both peers `usrsctp_bind` + `usrsctp_connect`
//! (simultaneous open) regardless of the DTLS client/server role, so
//! there is no listen/accept path.

use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    mpsc::{Receiver, Sender},
    Arc, Mutex as StdMutex, Once,
};
use std::thread::JoinHandle;

use parking_lot::Mutex;
use thiserror::Error;
use tracing::{trace, warn};

use crate::dtls_transport::{DtlsState, DtlsTransportCallbacks};
use crate::usrsctp_sys as sys;
use crate::{DtlsTransport, Reliability, ReliabilityType};

// ---------------------------------------------------------------------------
// usrsctp constants (not emitted by bindgen — they live in headers not
// transitively included by usrsctp.h, or are plain #defines). Values are
// the verified ABI constants. See sctptransport.cpp / RFC 8831/8841.
// ---------------------------------------------------------------------------

const AF_CONN: i32 = 123;
const IPPROTO_SCTP: i32 = 132;
const SOCK_STREAM: i32 = 1;

// Socket option levels.
const SOL_SOCKET: i32 = 0xffff; // macOS/BSD SOL_SOCKET
const SOL_SOCKET_LINUX: i32 = 1; // Linux SOL_SOCKET

// SOL_SOCKET option names (BSD/macOS values; usrsctp uses BSD numbering
// in userspace regardless of host OS).
const SO_LINGER: i32 = 0x0080;

// IPPROTO_SCTP socket options.
const SCTP_NODELAY: i32 = 0x04;
const SCTP_INITMSG: i32 = 0x03;
const SCTP_FRAGMENT_INTERLEAVE: i32 = 0x10;
const SCTP_PEER_ADDR_PARAMS: i32 = 0x0a;
const SCTP_EVENT: i32 = 0x1e;
const SCTP_RECVRCVINFO: i32 = 0x1f;
const SCTP_ENABLE_STREAM_RESET: i32 = 0x900;
const SCTP_RESET_STREAMS: i32 = 0x901;
const SCTP_STATUS: i32 = 0x100;

// Association id sentinel.
const SCTP_ALL_ASSOC: sys::sctp_assoc_t = 2;

// sctp_paddrparams flags.
const SPP_HB_ENABLE: u32 = 0x01;
const SPP_PMTUD_DISABLE: u32 = 0x10;

// recv/send info types and flags.
const SCTP_RECVV_RCVINFO: u32 = 1;
const SCTP_SENDV_SPA: u32 = 4;
const SCTP_SEND_SNDINFO_VALID: u32 = 0x1;
const SCTP_SEND_PRINFO_VALID: u32 = 0x2;

// msg flags.
const MSG_NOTIFICATION: i32 = 0x2000;
const MSG_EOR: i32 = 0x8;

// snd_flags.
const SCTP_UNORDERED: u16 = 0x0400;
const SCTP_EOR: u16 = 0x2000;

// PR-SCTP policies.
const SCTP_PR_SCTP_NONE: u16 = 0;
const SCTP_PR_SCTP_TTL: u16 = 1;
const SCTP_PR_SCTP_RTX: u16 = 3;

// Notification types.
const SCTP_ASSOC_CHANGE: u16 = 0x0001;
const SCTP_SENDER_DRY_EVENT: u16 = 0x000a;
const SCTP_STREAM_RESET_EVENT: u16 = 0x0009;

// sac_state values for SCTP_ASSOC_CHANGE.
const SCTP_COMM_UP: u16 = 0x0001;
const SCTP_COMM_LOST: u16 = 0x0002;
const SCTP_SHUTDOWN_COMP: u16 = 0x0004;

// stream-reset list bits.
const SCTP_STREAM_RESET_OUTGOING: u16 = 0x01;

// usrsctp tuning.
const MAX_SCTP_STREAMS_COUNT: u16 = 1024;
const DEFAULT_LOCAL_MAX_MESSAGE_SIZE: usize = 256 * 1024;

// shutdown how.
const SHUT_RDWR: i32 = 2;

/// SCTP port WebRTC always uses for the data-channel association
/// (RFC 8831 §6.2). Mirrors `DEFAULT_SCTP_PORT` in
/// `native/libdatachannel/src/impl/internals.hpp`.
const DEFAULT_SCTP_PORT: u16 = 5000;

/// Safe SCTP MTU when PMTU discovery is disabled. The C++ derives this as
/// `DEFAULT_MTU(1280) - 12(SCTP) - 48(DTLS) - 8(UDP) - 40(IPv6) = 1172`.
const SAFE_SCTP_MTU: u32 = 1280 - 12 - 48 - 8 - 40;

/// Resolve the platform SOL_SOCKET value. usrsctp's userspace socket layer
/// uses the host's `SO_*` numbering for `SOL_SOCKET`-level options.
#[inline]
fn sol_socket() -> i32 {
    if cfg!(target_os = "linux") || cfg!(target_os = "android") {
        SOL_SOCKET_LINUX
    } else {
        SOL_SOCKET
    }
}

// ---------------------------------------------------------------------------
// Global usrsctp init + instance registry (mirrors C++ Init / InstancesSet)
// ---------------------------------------------------------------------------

static USRSCTP_INIT: Once = Once::new();

/// Set of currently-live transport pointers (as `usize`). A usrsctp
/// callback whose `arg` pointer is not in this set is treated as stale and
/// dropped — this both prevents cross-talk between the two loopback
/// transports and guards against the use-after-close window described in
/// sctplab/usrsctp#405.
static INSTANCES: StdMutex<Option<HashSet<usize>>> = StdMutex::new(None);

fn instances_insert(ptr: usize) {
    let mut g = INSTANCES.lock().unwrap();
    g.get_or_insert_with(HashSet::new).insert(ptr);
}

fn instances_remove(ptr: usize) {
    if let Some(set) = INSTANCES.lock().unwrap().as_mut() {
        set.remove(&ptr);
    }
}

fn instance_is_live(ptr: usize) -> bool {
    INSTANCES
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| s.contains(&ptr))
        .unwrap_or(false)
}

/// Run the one-time global usrsctp initialization, matching the C++
/// `SctpTransport::Init`.
fn usrsctp_global_init() {
    USRSCTP_INIT.call_once(|| {
        unsafe {
            // port 0 (conn), our write callback, our debug callback.
            // Third arg is a printf-style C-variadic debug callback. Passing
            // `Some(fn(..., ...))` would require defining a C-variadic Rust fn,
            // which is unstable on stable Rust, so we disable debug output with
            // `None` — usrsctp guards every call with a null check.
            sys::usrsctp_init(0, Some(write_cb), None);
            sys::usrsctp_sysctl_set_sctp_pr_enable(1); // PR-SCTP (RFC 3758)
            sys::usrsctp_sysctl_set_sctp_ecn_enable(0); // no ECN
            sys::usrsctp_enable_crc32c_offload(); // we CRC outgoing ourselves
        }
        *INSTANCES.lock().unwrap() = Some(HashSet::new());
    });
}

// ---------------------------------------------------------------------------
// Public surface (preserved verbatim from the G-6a stub)
// ---------------------------------------------------------------------------

/// WebRTC SCTP association state.
///
/// Mirrors the subset of `rtc::Transport::State` that
/// `rtc::impl::SctpTransport` actually transitions through. The C++ uses a
/// shared `Transport::State` enum that also has `Disconnected`; we fold the
/// disconnect path into [`SctpState::Closed`] for the data-channel surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpState {
    /// Constructed; [`SctpTransport::connect`] has not run yet.
    New,
    /// Association handshake in progress (`usrsctp_connect` issued, INIT in
    /// flight). The `SCTP_COMM_UP` notification flips this to
    /// [`SctpState::Connected`].
    Connecting,
    /// Association established; messages can flow.
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
    /// recv path mirrors that by treating `None` as "ignore".
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
    /// Reassembled payload bytes (a complete message — partial deliveries
    /// are reassembled on `MSG_EOR` before surfacing).
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

    /// A usrsctp FFI call failed; carries the C `errno`.
    #[error("usrsctp error: {0} (errno {1})")]
    Usrsctp(&'static str, i32),

    /// The message exceeds the local maximum message size.
    #[error("sctp message too large ({0} bytes)")]
    MessageTooLarge(usize),

    /// Forwarded from the lower [`DtlsTransport`].
    #[error("dtls transport: {0}")]
    Dtls(#[from] crate::DtlsTransportError),
}

/// Inner mutable state guarded by the transport's `Mutex`. Holds the raw
/// usrsctp socket and the partial reassembly buffers.
struct Inner {
    /// The usrsctp association socket
    /// (`usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, ...)`).
    /// Null until [`SctpTransport::connect`] runs.
    sock: *mut sys::socket,
    /// Partial inbound message accumulator (data PPIDs), flushed on
    /// `MSG_EOR`.
    partial_message: Vec<u8>,
    /// Partial inbound notification accumulator, flushed on `MSG_EOR`.
    partial_notification: Vec<u8>,
}

// Safety: `Inner` is only ever touched while the surrounding Mutex is held.
// The raw socket pointer is owned by this transport and freed via
// `usrsctp_close` on `close()` / `Drop`. usrsctp callbacks reach the
// transport through the global instances set, not through this pointer.
unsafe impl Send for Inner {}

/// Work items handed to the per-transport worker thread.
///
/// Both `Connect` and `Inbound` ultimately call usrsctp functions that can
/// synchronously emit outbound SCTP packets through `write_cb` → `dtls.send()`.
/// `dtls.send()` takes the DTLS inner mutex, and the DTLS state-change /
/// on_data callbacks fire that very lock held. Running these on the DTLS
/// callback thread would therefore self-deadlock (parking_lot mutexes are not
/// reentrant). The worker thread breaks that reentrancy: the DTLS hooks only
/// enqueue, and the usrsctp work runs after the DTLS lock is released. This
/// mirrors libdatachannel doing its usrsctp work off its own processing thread.
enum SctpCommand {
    /// Open the socket and issue bind+connect (RFC 8841 simultaneous open).
    Connect,
    /// Decrypted DTLS record to feed into `usrsctp_conninput`.
    Inbound(Vec<u8>),
}

/// The SCTP transport. Cheap to clone via the surrounding `Arc<Self>`,
/// matching the [`DtlsTransport`] / [`crate::IceTransport`] pattern.
pub struct SctpTransport {
    /// Lower transport. We install our `on_data` shim on it and push
    /// outbound SCTP packets through `dtls.send()` in the write callback.
    dtls: Arc<DtlsTransport>,
    /// Socket + reassembly state.
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
    /// Maximum inbound/outbound message size.
    max_message_size: usize,
    /// Sender side of the worker command channel. `connect`/`feed_inbound`
    /// enqueue here; the worker thread executes the usrsctp calls. `None`
    /// only transiently during construction. Dropping the sender (in
    /// `close`/`Drop`) makes the worker's `recv` return `Err` and exit.
    tx: StdMutex<Option<Sender<SctpCommand>>>,
    /// Worker thread handle, joined on `close`/`Drop`.
    worker: StdMutex<Option<JoinHandle<()>>>,
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
    /// → `usrsctp_conninput`, while **preserving** the upstream
    /// `on_state_change`. It additionally chains the DTLS `on_state_change`
    /// so that when DTLS reaches [`DtlsState::Connected`] the SCTP transport
    /// auto-calls [`connect`](Self::connect).
    ///
    /// Returns the handle in [`SctpState::New`]; call
    /// [`connect`](Self::connect) (or let the auto-connect hook fire) to
    /// begin the association.
    pub fn new(
        dtls: Arc<DtlsTransport>,
        callbacks: SctpTransportCallbacks,
    ) -> Arc<Self> {
        usrsctp_global_init();

        let (tx, rx) = std::sync::mpsc::channel::<SctpCommand>();

        let transport = Arc::new(SctpTransport {
            dtls: Arc::clone(&dtls),
            inner: Mutex::new(Inner {
                sock: std::ptr::null_mut(),
                partial_message: Vec::new(),
                partial_notification: Vec::new(),
            }),
            state: AtomicU8::new(SctpState::New.as_u8()),
            closed: AtomicBool::new(false),
            started: AtomicBool::new(false),
            callbacks: Mutex::new(callbacks),
            local_port: DEFAULT_SCTP_PORT,
            remote_port: DEFAULT_SCTP_PORT,
            max_message_size: DEFAULT_LOCAL_MAX_MESSAGE_SIZE,
            tx: StdMutex::new(Some(tx)),
            worker: StdMutex::new(None),
        });

        // Spawn the worker thread. It holds a weak ref so it never keeps the
        // transport alive; it exits when the command channel's sender is
        // dropped (close/Drop) or the transport is gone.
        {
            let weak = Arc::downgrade(&transport);
            let handle = std::thread::Builder::new()
                .name("sctp-worker".into())
                .spawn(move || worker_loop(weak, rx))
                .expect("spawn sctp worker thread");
            *transport.worker.lock().unwrap() = Some(handle);
        }

        // Install our recv shim + auto-connect hook on the DTLS transport.
        // Snapshot the existing DTLS callbacks and chain them so the
        // PeerConnection-owned on_state_change is preserved and any prior
        // on_data still fires.
        let prev = dtls.callbacks();
        let weak = Arc::downgrade(&transport);

        let new_on_state_change = {
            let prev_state = Arc::clone(&prev.on_state_change);
            let weak = weak.clone();
            Arc::new(move |s: DtlsState| {
                if matches!(s, DtlsState::Connected) {
                    if let Some(this) = weak.upgrade() {
                        // Enqueue the connect for the worker thread. We must
                        // NOT call connect() inline: this callback runs with
                        // the DTLS inner mutex held, and usrsctp_connect emits
                        // the INIT chunk synchronously via write_cb →
                        // dtls.send(), which re-locks that same mutex.
                        this.enqueue(SctpCommand::Connect);
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
                    // Enqueue for the worker thread. As with Connect,
                    // usrsctp_conninput can synchronously emit SACKs etc. via
                    // write_cb → dtls.send(); this on_data callback runs with
                    // the DTLS inner mutex held, so feed it off-thread.
                    this.enqueue(SctpCommand::Inbound(data.to_vec()));
                }
                (prev_data)(data);
            })
        };

        dtls.set_callbacks(DtlsTransportCallbacks {
            on_state_change: new_on_state_change,
            on_data: new_on_data,
        });

        transport
    }

    /// Hand a command to the worker thread. Silently drops the command if the
    /// channel is gone (transport closing/closed), which is the desired
    /// teardown behavior.
    fn enqueue(&self, cmd: SctpCommand) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        if let Some(tx) = self.tx.lock().unwrap().as_ref() {
            let _ = tx.send(cmd);
        }
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

    /// Raw pointer identity used as the usrsctp `void* addr` / upcall arg
    /// and as the instances-set key. This is the `Arc`'s inner allocation
    /// address, stable for the transport's lifetime.
    fn self_ptr(self: &Arc<Self>) -> *mut c_void {
        Arc::as_ptr(self) as *mut c_void
    }

    /// Begin the SCTP association.
    ///
    /// Transitions New → Connecting, creates and configures the usrsctp
    /// socket, registers the connection address, and issues
    /// `usrsctp_bind` + `usrsctp_connect` (simultaneous open, RFC 8841).
    /// The association reaches [`SctpState::Connected`] later, when the
    /// `SCTP_ASSOC_CHANGE` / `SCTP_COMM_UP` notification arrives on the
    /// upcall. Idempotent via the `started` [`AtomicBool`].
    pub fn connect(self: &Arc<Self>) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }

        // Idempotency guard: the second caller short-circuits.
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }

        // Only transition if we're still in New (covers close-during-connect).
        let changed = self
            .state
            .compare_exchange(
                SctpState::New.as_u8(),
                SctpState::Connecting.as_u8(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok();
        if !changed {
            return;
        }

        trace!(
            local_port = self.local_port,
            remote_port = self.remote_port,
            "SctpTransport::connect: New -> Connecting"
        );

        // Fire Connecting before opening the socket so observers see the
        // transition even if setup fails.
        self.fire_state(SctpState::Connecting);

        if let Err(e) = self.open_and_connect() {
            warn!("SctpTransport::connect failed: {e}");
            self.fail();
        }
    }

    /// Socket creation + configuration + bind + connect. Mirrors the C++
    /// constructor body and `connect()`.
    fn open_and_connect(self: &Arc<Self>) -> Result<(), SctpTransportError> {
        let self_ptr = self.self_ptr();

        // Register the connection address and add to the instances set
        // BEFORE creating the socket so any early upcall finds us live.
        unsafe { sys::usrsctp_register_address(self_ptr) };
        instances_insert(self_ptr as usize);

        let sock = unsafe {
            sys::usrsctp_socket(
                AF_CONN,
                SOCK_STREAM,
                IPPROTO_SCTP,
                None, // recv cb: driven by upcall
                None, // send cb: driven by upcall
                0,
                // ulp_info MUST be NULL here: usrsctp rejects (EINVAL) a
                // socket with a NULL receive_cb but a non-NULL ulp_info. We
                // carry our identity via the upcall arg and sconn_addr, not
                // ulp_info.
                std::ptr::null_mut(),
            )
        };
        if sock.is_null() {
            return Err(SctpTransportError::Usrsctp("usrsctp_socket", errno()));
        }

        {
            let mut g = self.inner.lock();
            g.sock = sock;
        }

        unsafe {
            sys::usrsctp_set_upcall(sock, Some(upcall_cb), self_ptr);

            if sys::usrsctp_set_non_blocking(sock, 1) != 0 {
                return Err(SctpTransportError::Usrsctp(
                    "usrsctp_set_non_blocking",
                    errno(),
                ));
            }

            // SO_LINGER {1, 0}: stop sending once the lower layer is down.
            #[repr(C)]
            struct Linger {
                l_onoff: i32,
                l_linger: i32,
            }
            let sol = Linger {
                l_onoff: 1,
                l_linger: 0,
            };
            setsockopt(sock, sol_socket(), SO_LINGER, &sol)?;

            // SCTP_ENABLE_STREAM_RESET on all associations.
            let av = sys::sctp_assoc_value {
                assoc_id: SCTP_ALL_ASSOC,
                assoc_value: 1,
            };
            setsockopt(sock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av)?;

            // SCTP_RECVRCVINFO: surface rcvinfo on recvv.
            let on: i32 = 1;
            setsockopt(sock, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on)?;

            // Subscribe to the three events we act on.
            for ty in [
                SCTP_ASSOC_CHANGE,
                SCTP_SENDER_DRY_EVENT,
                SCTP_STREAM_RESET_EVENT,
            ] {
                let se = sys::sctp_event {
                    se_assoc_id: SCTP_ALL_ASSOC,
                    se_type: ty,
                    se_on: 1,
                };
                setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &se)?;
            }

            // SCTP_NODELAY (RFC 8831 §6.6: disable Nagle).
            let nodelay: i32 = 1;
            setsockopt(sock, IPPROTO_SCTP, SCTP_NODELAY, &nodelay)?;

            // SCTP_PEER_ADDR_PARAMS: heartbeats on, PMTUD off, safe MTU.
            let mut spp = sys::sctp_paddrparams::default();
            spp.spp_flags = SPP_HB_ENABLE | SPP_PMTUD_DISABLE;
            spp.spp_pathmtu = SAFE_SCTP_MTU;
            setsockopt(sock, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &spp)?;

            // SCTP_INITMSG: cap streams.
            let sinit = sys::sctp_initmsg {
                sinit_num_ostreams: MAX_SCTP_STREAMS_COUNT,
                sinit_max_instreams: MAX_SCTP_STREAMS_COUNT,
                sinit_max_attempts: 0,
                sinit_max_init_timeo: 0,
            };
            setsockopt(sock, IPPROTO_SCTP, SCTP_INITMSG, &sinit)?;

            // SCTP_FRAGMENT_INTERLEAVE = 0: no interleave of messages.
            let level: i32 = 0;
            setsockopt(sock, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE, &level)?;

            // bind + connect on the same conn address (simultaneous open).
            let mut local = self.sockaddr_conn(self.local_port);
            let ret = sys::usrsctp_bind(
                sock,
                &mut local as *mut sys::sockaddr_conn as *mut sys::sockaddr,
                std::mem::size_of::<sys::sockaddr_conn>() as sys::socklen_t,
            );
            if ret != 0 {
                return Err(SctpTransportError::Usrsctp("usrsctp_bind", errno()));
            }

            let mut remote = self.sockaddr_conn(self.remote_port);
            let ret = sys::usrsctp_connect(
                sock,
                &mut remote as *mut sys::sockaddr_conn as *mut sys::sockaddr,
                std::mem::size_of::<sys::sockaddr_conn>() as sys::socklen_t,
            );
            // EINPROGRESS (36 on macOS / 115 on Linux) is the expected
            // non-blocking result.
            if ret != 0 {
                let e = errno();
                if !is_einprogress(e) {
                    return Err(SctpTransportError::Usrsctp("usrsctp_connect", e));
                }
            }
        }

        Ok(())
    }

    /// Build a `sockaddr_conn` pointing at this transport's `self_ptr`.
    fn sockaddr_conn(self: &Arc<Self>, port: u16) -> sys::sockaddr_conn {
        let mut sconn = sys::sockaddr_conn::default();
        sconn.sconn_family = AF_CONN as u8;
        sconn.sconn_port = port.to_be(); // htons
        sconn.sconn_addr = self.self_ptr();
        // Apple's sockaddr_conn has a leading sconn_len byte.
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            sconn.sconn_len = std::mem::size_of::<sys::sockaddr_conn>() as u8;
        }
        sconn
    }

    /// Send a message on a stream with the given reliability parameters.
    ///
    /// Builds an `sctp_sendv_spa` from `reliability` (PR-SCTP TTL / RTX /
    /// NONE plus `SCTP_UNORDERED`) and calls `usrsctp_sendv`.
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
        if msg.data.len() > self.max_message_size {
            return Err(SctpTransportError::MessageTooLarge(msg.data.len()));
        }

        let mut spa: sys::sctp_sendv_spa = unsafe { std::mem::zeroed() };

        // sndinfo
        spa.sendv_flags |= SCTP_SEND_SNDINFO_VALID;
        spa.sendv_sndinfo.snd_sid = msg.stream;
        spa.sendv_sndinfo.snd_ppid = (msg.ppid as u32).to_be(); // htonl
        spa.sendv_sndinfo.snd_flags |= SCTP_EOR;
        if reliability.unordered {
            spa.sendv_sndinfo.snd_flags |= SCTP_UNORDERED;
        }

        // prinfo
        spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
        match reliability.typ {
            ReliabilityType::Rexmit => {
                spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
                spa.sendv_prinfo.pr_value = reliability.rexmit;
            }
            ReliabilityType::Timed => {
                spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_TTL;
                spa.sendv_prinfo.pr_value = reliability.rexmit;
            }
            ReliabilityType::Reliable => {
                spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_NONE;
            }
        }

        // SCTP requires at least one byte on the wire; the empty-string /
        // empty-binary PPIDs already signal emptiness, so send a single
        // zero byte for an empty payload.
        let (ptr, len): (*const c_void, usize) = if msg.data.is_empty() {
            (&0u8 as *const u8 as *const c_void, 1)
        } else {
            (msg.data.as_ptr() as *const c_void, msg.data.len())
        };

        let sock = {
            let g = self.inner.lock();
            g.sock
        };
        if sock.is_null() {
            return Err(SctpTransportError::NotConnected(self.state()));
        }

        let ret = unsafe {
            sys::usrsctp_sendv(
                sock,
                ptr,
                len,
                std::ptr::null_mut(),
                0,
                &mut spa as *mut sys::sctp_sendv_spa as *mut c_void,
                std::mem::size_of::<sys::sctp_sendv_spa>() as sys::socklen_t,
                SCTP_SENDV_SPA,
                0,
            )
        };
        if ret < 0 {
            return Err(SctpTransportError::Usrsctp("usrsctp_sendv", errno()));
        }
        Ok(())
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
    /// exactly once. Closes the usrsctp socket and deregisters the
    /// connection address.
    pub fn close(&self) -> Result<(), SctpTransportError> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        // Stop the worker: drop the sender so its `recv` returns Err and the
        // loop exits, then join it. Joining before we touch the socket ensures
        // no worker-driven usrsctp call races our close. The worker never calls
        // close(), so this can't deadlock. If close() is somehow invoked from
        // the worker thread itself we must not join ourselves.
        *self.tx.lock().unwrap() = None;
        let handle = self.worker.lock().unwrap().take();
        if let Some(h) = handle {
            if h.thread().id() != std::thread::current().id() {
                let _ = h.join();
            }
        }

        // Take the socket out under the lock; close it after releasing so
        // we don't hold the inner mutex across a usrsctp call that could
        // re-enter the write callback.
        let sock = {
            let mut g = self.inner.lock();
            std::mem::replace(&mut g.sock, std::ptr::null_mut())
        };

        // Remove from instances set first so any in-flight callback sees us
        // as stale, then close + deregister. The instances key is the
        // Arc allocation address; we recover it from a field-free pointer.
        let self_ptr = self as *const SctpTransport as usize;
        instances_remove(self_ptr);

        if !sock.is_null() {
            unsafe {
                sys::usrsctp_shutdown(sock, SHUT_RDWR);
                sys::usrsctp_close(sock);
                sys::usrsctp_deregister_address(
                    self as *const SctpTransport as *mut c_void,
                );
            }
        }

        let prev = self
            .state
            .swap(SctpState::Closed.as_u8(), Ordering::SeqCst);
        if prev != SctpState::Closed.as_u8() {
            self.fire_state(SctpState::Closed);
        }
        Ok(())
    }

    /// Inbound DTLS record → SCTP. Feeds the decrypted bytes into
    /// `usrsctp_conninput`, whose recv path reassembles messages and fires
    /// the upcall (handled by [`upcall_cb`]).
    fn feed_inbound(&self, data: &[u8]) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        if data.is_empty() {
            return;
        }
        let self_ptr = self as *const SctpTransport as *mut c_void;
        // Guard: only feed if we're a live registered instance.
        if !instance_is_live(self_ptr as usize) {
            return;
        }
        trace!(len = data.len(), "SctpTransport::feed_inbound → conninput");
        unsafe {
            sys::usrsctp_conninput(
                self_ptr,
                data.as_ptr() as *const c_void,
                data.len(),
                0,
            );
        }
    }

    // ---- upcall-side helpers --------------------------------------------

    /// usrsctp upcall: drain the socket via `usrsctp_recvv`, reassembling
    /// messages and notifications on `MSG_EOR`.
    fn handle_upcall(&self) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let sock = {
            let g = self.inner.lock();
            g.sock
        };
        if sock.is_null() {
            return;
        }
        self.drain_recv(sock);
    }

    fn drain_recv(&self, sock: *mut sys::socket) {
        const BUF: usize = 65536;
        let mut buffer = vec![0u8; BUF];
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            let mut info: sys::sctp_rcvinfo = unsafe { std::mem::zeroed() };
            let mut infolen =
                std::mem::size_of::<sys::sctp_rcvinfo>() as sys::socklen_t;
            let mut infotype: u32 = 0;
            let mut flags: i32 = 0;
            let mut fromlen: sys::socklen_t = 0;

            let len = unsafe {
                sys::usrsctp_recvv(
                    sock,
                    buffer.as_mut_ptr() as *mut c_void,
                    BUF,
                    std::ptr::null_mut(),
                    &mut fromlen,
                    &mut info as *mut sys::sctp_rcvinfo as *mut c_void,
                    &mut infolen,
                    &mut infotype,
                    &mut flags,
                )
            };

            if len < 0 {
                let e = errno();
                // EWOULDBLOCK/EAGAIN/ECONNRESET → done draining.
                if is_wouldblock(e) || is_econnreset(e) {
                    return;
                }
                warn!("SctpTransport: usrsctp_recvv failed, errno={e}");
                return;
            }
            if len == 0 {
                return;
            }
            let len = len as usize;
            let chunk = &buffer[..len];

            if flags & MSG_NOTIFICATION != 0 {
                let mut g = self.inner.lock();
                g.partial_notification.extend_from_slice(chunk);
                if flags & MSG_EOR != 0 {
                    let notif = std::mem::take(&mut g.partial_notification);
                    drop(g);
                    self.process_notification(&notif);
                }
            } else {
                let mut g = self.inner.lock();
                g.partial_message.extend_from_slice(chunk);
                if g.partial_message.len() > self.max_message_size {
                    g.partial_message.truncate(self.max_message_size);
                }
                if flags & MSG_EOR != 0 {
                    let data = std::mem::take(&mut g.partial_message);
                    drop(g);
                    if infotype == SCTP_RECVV_RCVINFO {
                        let sid = info.rcv_sid;
                        let ppid = u32::from_be(info.rcv_ppid); // ntohl
                        self.process_data(data, sid, ppid);
                    } else {
                        warn!("SctpTransport: recv missing rcvinfo, dropping");
                    }
                }
            }
        }
    }

    fn process_data(&self, data: Vec<u8>, sid: u16, ppid_raw: u32) {
        let ppid = match PayloadProtocolId::from_u32(ppid_raw) {
            Some(p) => p,
            None => {
                trace!(ppid = ppid_raw, "SctpTransport: unknown PPID, dropping");
                return;
            }
        };
        let msg = SctpMessage {
            stream: sid,
            ppid,
            data,
        };
        let cb = {
            let g = self.callbacks.lock();
            Arc::clone(&g.on_message)
        };
        (cb)(msg);
    }

    fn process_notification(&self, notif: &[u8]) {
        if notif.len() < std::mem::size_of::<sys::sctp_notification_sctp_tlv>() {
            return;
        }
        // The notification union begins with the sn_header TLV.
        let header = unsafe {
            &*(notif.as_ptr() as *const sys::sctp_notification_sctp_tlv)
        };
        let sn_type = header.sn_type;
        match sn_type {
            SCTP_ASSOC_CHANGE => {
                if notif.len() < std::mem::size_of::<sys::sctp_assoc_change>() {
                    return;
                }
                let sac = unsafe {
                    &*(notif.as_ptr() as *const sys::sctp_assoc_change)
                };
                match sac.sac_state {
                    SCTP_COMM_UP => {
                        // Connecting → Connected.
                        if self
                            .state
                            .compare_exchange(
                                SctpState::Connecting.as_u8(),
                                SctpState::Connected.as_u8(),
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            )
                            .is_ok()
                        {
                            trace!("SctpTransport: SCTP_COMM_UP → Connected");
                            self.fire_state(SctpState::Connected);
                        }
                    }
                    SCTP_COMM_LOST | SCTP_SHUTDOWN_COMP => {
                        if matches!(self.state(), SctpState::Connected) {
                            self.set_state_and_fire(SctpState::Closed);
                        } else {
                            self.fail();
                        }
                    }
                    _ => {}
                }
            }
            SCTP_SENDER_DRY_EVENT => {
                // Backpressure relief signal; the data-channel layer hooks
                // buffered-amount here later.
            }
            SCTP_STREAM_RESET_EVENT => {
                // Stream reset surfaces here; DataChannel close handling
                // (Task #18) consumes it. Nothing to do at the transport
                // level for the loopback round-trip.
            }
            _ => {}
        }
    }

    // ---- state helpers ---------------------------------------------------

    fn fire_state(&self, s: SctpState) {
        let cb = {
            let g = self.callbacks.lock();
            Arc::clone(&g.on_state_change)
        };
        (cb)(s);
    }

    fn set_state_and_fire(&self, s: SctpState) {
        let prev = self.state.swap(s.as_u8(), Ordering::SeqCst);
        if prev != s.as_u8() {
            self.fire_state(s);
        }
    }

    fn fail(&self) {
        let prev = self.state.swap(SctpState::Failed.as_u8(), Ordering::SeqCst);
        if prev != SctpState::Failed.as_u8() && prev != SctpState::Closed.as_u8()
        {
            self.fire_state(SctpState::Failed);
        }
    }
}

impl Drop for SctpTransport {
    fn drop(&mut self) {
        // Stop and join the worker first. Its `recv` returns Err once the
        // sender drops, so it won't block forever. The worker only holds a
        // Weak<Self>, so it can't keep us alive — but it could still be
        // mid-iteration, so we join to avoid a use-after-free on `self`.
        *self.tx.lock().unwrap() = None;
        if let Some(h) = self.worker.lock().unwrap().take() {
            if h.thread().id() != std::thread::current().id() {
                let _ = h.join();
            }
        }

        // Ensure the socket is closed and the instance deregistered even if
        // the caller never called close().
        if !self.closed.load(Ordering::SeqCst) {
            let sock =
                std::mem::replace(&mut self.inner.lock().sock, std::ptr::null_mut());
            let self_ptr = self as *const SctpTransport as usize;
            instances_remove(self_ptr);
            if !sock.is_null() {
                unsafe {
                    sys::usrsctp_close(sock);
                    sys::usrsctp_deregister_address(
                        self as *const SctpTransport as *mut c_void,
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// worker thread
// ---------------------------------------------------------------------------

/// Per-transport worker loop. Drains the command channel, executing the
/// usrsctp calls that may synchronously emit outbound packets (and thus call
/// back into `dtls.send()`), keeping them off the DTLS callback thread where
/// the DTLS inner mutex is held.
fn worker_loop(weak: std::sync::Weak<SctpTransport>, rx: Receiver<SctpCommand>) {
    while let Ok(cmd) = rx.recv() {
        let Some(this) = weak.upgrade() else {
            break;
        };
        if this.closed.load(Ordering::SeqCst) {
            // Keep draining so the channel doesn't back up, but do no work.
            continue;
        }
        match cmd {
            SctpCommand::Connect => this.connect(),
            SctpCommand::Inbound(data) => this.feed_inbound(&data),
        }
    }
}

// ---------------------------------------------------------------------------
// usrsctp C trampolines
// ---------------------------------------------------------------------------

/// usrsctp write callback: an outbound SCTP packet for the connection
/// `addr` (= a transport's `self_ptr`). We compute the CRC32c ourselves
/// (CRC offload is enabled), then forward the bytes to the lower DTLS
/// transport.
unsafe extern "C" fn write_cb(
    addr: *mut c_void,
    buffer: *mut c_void,
    length: usize,
    _tos: u8,
    _set_df: u8,
) -> i32 {
    if addr.is_null() || buffer.is_null() || length == 0 {
        return -1;
    }
    // Stale-pointer guard (sctplab/usrsctp#405).
    if !instance_is_live(addr as usize) {
        return -1;
    }

    // Compute the SCTP CRC32c into bytes [8..12) since offload is enabled.
    if length >= 12 {
        let csum_ptr = unsafe { (buffer as *mut u8).add(8) as *mut u32 };
        unsafe {
            csum_ptr.write_unaligned(0);
            let c = sys::usrsctp_crc32c(buffer, length);
            csum_ptr.write_unaligned(c);
        }
    }

    let data = unsafe { std::slice::from_raw_parts(buffer as *const u8, length) };

    // SAFETY: the pointer is live per the instances set; the transport
    // outlives the registration (close/Drop deregister before freeing).
    let transport = unsafe { &*(addr as *const SctpTransport) };
    match transport.dtls.send(data) {
        Ok(()) => 0,
        Err(e) => {
            // Closed/NotConnected during teardown is expected.
            trace!("SctpTransport write_cb: dtls.send failed: {e}");
            -1
        }
    }
}

/// usrsctp socket upcall: data/event readiness on the association socket.
unsafe extern "C" fn upcall_cb(_sock: *mut sys::socket, arg: *mut c_void, _flags: i32) {
    if arg.is_null() || !instance_is_live(arg as usize) {
        return;
    }
    let transport = unsafe { &*(arg as *const SctpTransport) };
    transport.handle_upcall();
}

// ---------------------------------------------------------------------------
// small FFI helpers
// ---------------------------------------------------------------------------

/// Thin wrapper over `usrsctp_setsockopt` for a `Sized` option value.
unsafe fn setsockopt<T>(
    sock: *mut sys::socket,
    level: i32,
    name: i32,
    value: &T,
) -> Result<(), SctpTransportError> {
    let ret = unsafe {
        sys::usrsctp_setsockopt(
            sock,
            level,
            name,
            value as *const T as *const c_void,
            std::mem::size_of::<T>() as sys::socklen_t,
        )
    };
    if ret != 0 {
        Err(SctpTransportError::Usrsctp("usrsctp_setsockopt", errno()))
    } else {
        Ok(())
    }
}

/// Read the current C `errno`.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn is_einprogress(e: i32) -> bool {
    // EINPROGRESS: 36 on macOS, 115 on Linux.
    e == 36 || e == 115
}

fn is_wouldblock(e: i32) -> bool {
    // EWOULDBLOCK/EAGAIN: 35 on macOS, 11 on Linux (and 35/140 variants).
    e == 35 || e == 11 || e == 0
}

fn is_econnreset(e: i32) -> bool {
    // ECONNRESET: 54 on macOS, 104 on Linux.
    e == 54 || e == 104
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
    use crate::description::{FingerprintAlgorithm, Role, Type as DescriptionType};
    use crate::ice_transport::{IceTransport, IceTransportCallbacks};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Construct a real DTLS-over-ICE transport without driving any
    /// handshake — enough to layer SCTP on top and exercise the state
    /// machine / socket setup.
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
        // connect() opens the usrsctp socket and issues bind/connect; the
        // association stays in Connecting until COMM_UP, which can't arrive
        // without a peer. We assert the synchronous transition to
        // Connecting (and that socket setup didn't error into Failed).
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
            sctp.close().expect("close");
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
            sctp.close().expect("close");
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
            sctp.close().expect("close");
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

    /// Spin until `pred` is true or `timeout_ms` elapses.
    async fn wait_for<F: FnMut() -> bool>(mut pred: F, timeout_ms: u64) -> bool {
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if pred() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        false
    }

    /// Full ICE→DTLS→SCTP loopback association on 127.0.0.1, mirroring the
    /// DTLS end-to-end test. Asserts both sides reach Connected and a
    /// message round-trips each direction.
    #[test]
    fn sctp_association_completes_over_dtls_loopback() {
        rt().block_on(async {
            use crate::candidate::Candidate;

            let a_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));
            let b_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));
            let a_cands_cb = a_cands.clone();
            let b_cands_cb = b_cands.clone();

            let a_callbacks = IceTransportCallbacks {
                on_candidate: Arc::new(move |c| a_cands_cb.lock().push(c)),
                ..IceTransportCallbacks::default()
            };
            let b_callbacks = IceTransportCallbacks {
                on_candidate: Arc::new(move |c| b_cands_cb.lock().push(c)),
                ..IceTransportCallbacks::default()
            };

            let mut cfg = Configuration::new();
            cfg.bind_address = Some("127.0.0.1".to_string());

            // A: offerer / ActPass → Passive (DTLS server). B: Active (client).
            let ice_a = IceTransport::new(&cfg, Role::ActPass, a_callbacks).expect("ice a");
            let ice_b = IceTransport::new(&cfg, Role::Active, b_callbacks).expect("ice b");

            let cert_a = Certificate::generate_default().expect("cert a");
            let cert_b = Certificate::generate_default().expect("cert b");
            let fp_a = cert_a.fingerprint(FingerprintAlgorithm::Sha256).expect("fp a");
            let fp_b = cert_b.fingerprint(FingerprintAlgorithm::Sha256).expect("fp b");

            let dtls_a = Arc::new(
                DtlsTransport::new(
                    Arc::clone(&ice_a),
                    cert_a,
                    DtlsTransportCallbacks::default(),
                )
                .expect("dtls a"),
            );
            let dtls_b = Arc::new(
                DtlsTransport::new(
                    Arc::clone(&ice_b),
                    cert_b,
                    DtlsTransportCallbacks::default(),
                )
                .expect("dtls b"),
            );
            dtls_a.set_remote_fingerprint(fp_b);
            dtls_b.set_remote_fingerprint(fp_a);

            // SCTP state + recv buffers per side.
            let a_connected = Arc::new(AtomicBool::new(false));
            let b_connected = Arc::new(AtomicBool::new(false));
            let a_recv: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let b_recv: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));

            let ac = a_connected.clone();
            let ar = a_recv.clone();
            let sctp_a = SctpTransport::new(
                Arc::clone(&dtls_a),
                SctpTransportCallbacks {
                    on_state_change: Arc::new(move |s| {
                        if matches!(s, SctpState::Connected) {
                            ac.store(true, Ordering::SeqCst);
                        }
                    }),
                    on_message: Arc::new(move |m| ar.lock().push(m.data)),
                    ..SctpTransportCallbacks::default()
                },
            );
            let bc = b_connected.clone();
            let br = b_recv.clone();
            let sctp_b = SctpTransport::new(
                Arc::clone(&dtls_b),
                SctpTransportCallbacks {
                    on_state_change: Arc::new(move |s| {
                        if matches!(s, SctpState::Connected) {
                            bc.store(true, Ordering::SeqCst);
                        }
                    }),
                    on_message: Arc::new(move |m| br.lock().push(m.data)),
                    ..SctpTransportCallbacks::default()
                },
            );

            // Drive ICE; DTLS auto-starts on ICE-Connected, SCTP
            // auto-connects on DTLS-Connected.
            ice_a.gather().expect("a gather");
            assert!(
                wait_for(
                    || ice_a.gathering_state()
                        == crate::ice_transport::GatheringState::Complete,
                    3000
                )
                .await
            );
            let desc_a = ice_a.get_local_description(DescriptionType::Offer).unwrap();
            ice_b.set_remote_description(&desc_a).unwrap();
            ice_b.gather().expect("b gather");
            assert!(
                wait_for(
                    || ice_b.gathering_state()
                        == crate::ice_transport::GatheringState::Complete,
                    3000
                )
                .await
            );
            let desc_b = ice_b.get_local_description(DescriptionType::Answer).unwrap();
            ice_a.set_remote_description(&desc_b).unwrap();
            for c in a_cands.lock().iter() {
                ice_b.add_remote_candidate(c).unwrap();
            }
            for c in b_cands.lock().iter() {
                ice_a.add_remote_candidate(c).unwrap();
            }
            ice_a.set_remote_end_of_candidates().unwrap();
            ice_b.set_remote_end_of_candidates().unwrap();

            // Wait for the SCTP association to come up on both sides.
            let up = wait_for(
                || {
                    a_connected.load(Ordering::SeqCst)
                        && b_connected.load(Ordering::SeqCst)
                },
                12000,
            )
            .await;
            assert!(
                up,
                "SCTP did not converge: a={:?}, b={:?}",
                sctp_a.state(),
                sctp_b.state()
            );

            // Round-trip a message each direction.
            sctp_b
                .send(
                    &SctpMessage {
                        stream: 1,
                        ppid: PayloadProtocolId::String,
                        data: b"ping".to_vec(),
                    },
                    &Reliability::reliable(),
                )
                .expect("b→a send");
            assert!(
                wait_for(|| !a_recv.lock().is_empty(), 4000).await,
                "a never received ping"
            );
            assert_eq!(a_recv.lock()[0], b"ping");

            sctp_a
                .send(
                    &SctpMessage {
                        stream: 1,
                        ppid: PayloadProtocolId::Binary,
                        data: b"pong".to_vec(),
                    },
                    &Reliability::reliable(),
                )
                .expect("a→b send");
            assert!(
                wait_for(|| !b_recv.lock().is_empty(), 4000).await,
                "b never received pong"
            );
            assert_eq!(b_recv.lock()[0], b"pong");

            sctp_a.close().expect("close a");
            sctp_b.close().expect("close b");
        });
    }
}
