//! C-ABI shim (`extern "C"`) replicating libdatachannel's `rtc.h` surface.
//!
//! This module lets the existing node-datachannel N-API C++ glue — which
//! `#include`s libdatachannel's `rtc.h` and calls the `rtc*` symbols — link
//! against this crate's `staticlib`/`cdylib` with no source changes. The
//! signatures, struct layouts (`#[repr(C)]`), enum discriminants
//! (`#[repr(i32)]`) and string-buffer conventions mirror
//! `native/libdatachannel/include/rtc/rtc.h` byte-for-byte, and the handle
//! model mirrors `native/libdatachannel/src/capi.cpp`.
//!
//! ## Handle registry
//!
//! `rtcCreate*` returns a positive `int` handle; negative returns are
//! `RTC_ERR_*` codes. A single global registry
//! ([`REGISTRY`]) maps `handle -> RtcObject` and a monotonic atomic counter
//! ([`LAST_ID`]) hands out ids starting at 1 — PeerConnection, DataChannel and
//! Track all share the same id space, exactly like the C++ generic `Channel`
//! base. A parallel [`USER_POINTERS`] map backs
//! `rtcSetUserPointer`/`rtcGetUserPointer`.
//!
//! ## Panic safety
//!
//! Every exported function body runs inside [`std::panic::catch_unwind`] (via
//! [`guard`]/[`guard_bool`]) so a Rust panic can never unwind across the FFI
//! boundary into C (which is UB). Callbacks invoked from runtime threads are
//! likewise wrapped in `catch_unwind` ([`dispatch`]).
//!
//! ## What is stubbed
//!
//! The runtime's [`Track`](crate::Track) is standalone — the
//! [`PeerConnection`](crate::PeerConnection) has no `addTrack`/`onTrack`
//! integration yet (that lands in a later task). Per task #22's scope, every
//! Track function and RTCP media-chain function therefore returns
//! `RTC_ERR_NOT_AVAIL` with a `// TODO(#22)` note rather than faking a result.
//! The WebSocket client and server C-ABI is fully wired (see the
//! `rtcCreateWebSocket*` / `rtcCreateWebSocketServer` section).

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// These `pub extern "C"` items are exported by the linker via `#[no_mangle]`,
// not through Rust's module tree, so the crate-wide `unreachable_pub` lint is a
// false positive for the whole shim.
#![allow(unreachable_pub)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{CStr, c_char, c_double, c_int, c_void};
use std::os::raw::c_uint;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use once_cell::sync::Lazy;
use parking_lot::Mutex;

use crate::{
    Av1Packetization, Av1RtpPacketizer, Certificate, CertificateType, CodecPacketizer,
    Configuration, DEFAULT_MAX_FRAGMENT_SIZE, DataChannel, DataChannelCallbacks, DataChannelInit,
    Description, H264RtpPacketizer, H265RtpPacketizer, IceServer, IceTransportPolicy, NalSeparator,
    PeerConnection, PeerConnectionCallbacks, PeerConnectionState, Reliability, ReliabilityType,
    RtpPacketizationConfig, SsrcEntry, Track, Type as DescriptionType, Vp8RtpPacketizer, WebSocket,
    WebSocketConfig, WebSocketServer, WebSocketServerConfig, WsMessage,
};

// ===========================================================================
// Error codes (mirror rtc.h #define RTC_ERR_*)
// ===========================================================================

/// `RTC_ERR_SUCCESS` — operation succeeded.
pub const RTC_ERR_SUCCESS: c_int = 0;
/// `RTC_ERR_INVALID` — invalid argument.
pub const RTC_ERR_INVALID: c_int = -1;
/// `RTC_ERR_FAILURE` — runtime error.
pub const RTC_ERR_FAILURE: c_int = -2;
/// `RTC_ERR_NOT_AVAIL` — element not available.
pub const RTC_ERR_NOT_AVAIL: c_int = -3;
/// `RTC_ERR_TOO_SMALL` — buffer too small.
pub const RTC_ERR_TOO_SMALL: c_int = -4;

// ===========================================================================
// Enums (mirror rtc.h; #[repr(i32)] so the C enum discriminants match)
// ===========================================================================

/// Mirrors `rtcState`.
#[repr(i32)]
#[derive(Clone, Copy)]
pub enum RtcState {
    /// `RTC_NEW`
    New = 0,
    /// `RTC_CONNECTING`
    Connecting = 1,
    /// `RTC_CONNECTED`
    Connected = 2,
    /// `RTC_DISCONNECTED`
    Disconnected = 3,
    /// `RTC_FAILED`
    Failed = 4,
    /// `RTC_CLOSED`
    Closed = 5,
}

/// Mirrors `rtcIceState`.
#[repr(i32)]
#[derive(Clone, Copy)]
pub enum RtcIceState {
    /// `RTC_ICE_NEW`
    New = 0,
    /// `RTC_ICE_CHECKING`
    Checking = 1,
    /// `RTC_ICE_CONNECTED`
    Connected = 2,
    /// `RTC_ICE_COMPLETED`
    Completed = 3,
    /// `RTC_ICE_FAILED`
    Failed = 4,
    /// `RTC_ICE_DISCONNECTED`
    Disconnected = 5,
    /// `RTC_ICE_CLOSED`
    Closed = 6,
}

/// Mirrors `rtcGatheringState`.
#[repr(i32)]
#[derive(Clone, Copy)]
pub enum RtcGatheringState {
    /// `RTC_GATHERING_NEW`
    New = 0,
    /// `RTC_GATHERING_INPROGRESS`
    InProgress = 1,
    /// `RTC_GATHERING_COMPLETE`
    Complete = 2,
}

/// Mirrors `rtcSignalingState`.
#[repr(i32)]
#[derive(Clone, Copy)]
pub enum RtcSignalingState {
    /// `RTC_SIGNALING_STABLE`
    Stable = 0,
    /// `RTC_SIGNALING_HAVE_LOCAL_OFFER`
    HaveLocalOffer = 1,
    /// `RTC_SIGNALING_HAVE_REMOTE_OFFER`
    HaveRemoteOffer = 2,
    /// `RTC_SIGNALING_HAVE_LOCAL_PRANSWER`
    HaveLocalPranswer = 3,
    /// `RTC_SIGNALING_HAVE_REMOTE_PRANSWER`
    HaveRemotePranswer = 4,
}

/// Mirrors `rtcLogLevel` (must match plog severity, do not reorder).
#[repr(i32)]
#[derive(Clone, Copy)]
pub enum RtcLogLevel {
    /// `RTC_LOG_NONE`
    None = 0,
    /// `RTC_LOG_FATAL`
    Fatal = 1,
    /// `RTC_LOG_ERROR`
    Error = 2,
    /// `RTC_LOG_WARNING`
    Warning = 3,
    /// `RTC_LOG_INFO`
    Info = 4,
    /// `RTC_LOG_DEBUG`
    Debug = 5,
    /// `RTC_LOG_VERBOSE`
    Verbose = 6,
}

// ===========================================================================
// Callback function-pointer typedefs (mirror rtc.h)
// ===========================================================================

/// `rtcLogCallbackFunc`
pub type RtcLogCallbackFunc = extern "C" fn(level: c_int, message: *const c_char);
/// `rtcDescriptionCallbackFunc`
pub type RtcDescriptionCallbackFunc =
    extern "C" fn(pc: c_int, sdp: *const c_char, typ: *const c_char, ptr: *mut c_void);
/// `rtcCandidateCallbackFunc`
pub type RtcCandidateCallbackFunc =
    extern "C" fn(pc: c_int, cand: *const c_char, mid: *const c_char, ptr: *mut c_void);
/// `rtcStateChangeCallbackFunc`
pub type RtcStateChangeCallbackFunc = extern "C" fn(pc: c_int, state: c_int, ptr: *mut c_void);
/// `rtcIceStateChangeCallbackFunc`
pub type RtcIceStateChangeCallbackFunc = extern "C" fn(pc: c_int, state: c_int, ptr: *mut c_void);
/// `rtcGatheringStateCallbackFunc`
pub type RtcGatheringStateCallbackFunc = extern "C" fn(pc: c_int, state: c_int, ptr: *mut c_void);
/// `rtcSignalingStateCallbackFunc`
pub type RtcSignalingStateCallbackFunc = extern "C" fn(pc: c_int, state: c_int, ptr: *mut c_void);
/// `rtcDataChannelCallbackFunc`
pub type RtcDataChannelCallbackFunc = extern "C" fn(pc: c_int, dc: c_int, ptr: *mut c_void);
/// `rtcTrackCallbackFunc`
pub type RtcTrackCallbackFunc = extern "C" fn(pc: c_int, tr: c_int, ptr: *mut c_void);
/// `rtcOpenCallbackFunc`
pub type RtcOpenCallbackFunc = extern "C" fn(id: c_int, ptr: *mut c_void);
/// `rtcClosedCallbackFunc`
pub type RtcClosedCallbackFunc = extern "C" fn(id: c_int, ptr: *mut c_void);
/// `rtcErrorCallbackFunc`
pub type RtcErrorCallbackFunc = extern "C" fn(id: c_int, error: *const c_char, ptr: *mut c_void);
/// `rtcMessageCallbackFunc`
pub type RtcMessageCallbackFunc =
    extern "C" fn(id: c_int, message: *const c_char, size: c_int, ptr: *mut c_void);
/// `rtcBufferedAmountLowCallbackFunc`
pub type RtcBufferedAmountLowCallbackFunc = extern "C" fn(id: c_int, ptr: *mut c_void);
/// `rtcAvailableCallbackFunc`
pub type RtcAvailableCallbackFunc = extern "C" fn(id: c_int, ptr: *mut c_void);
/// `rtcPliHandlerCallbackFunc`
pub type RtcPliHandlerCallbackFunc = extern "C" fn(tr: c_int, ptr: *mut c_void);
/// `rtcRembHandlerCallbackFunc`
pub type RtcRembHandlerCallbackFunc = extern "C" fn(tr: c_int, bitrate: c_uint, ptr: *mut c_void);
/// `rtcWebSocketClientCallbackFunc`
pub type RtcWebSocketClientCallbackFunc =
    extern "C" fn(wsserver: c_int, ws: c_int, ptr: *mut c_void);

// ===========================================================================
// #[repr(C)] structs (mirror rtc.h field order + types EXACTLY)
// ===========================================================================

/// Mirrors `rtcConfiguration`. Field order and types match `rtc.h` exactly.
#[repr(C)]
pub struct RtcConfiguration {
    /// `const char **iceServers`
    pub iceServers: *const *const c_char,
    /// `int iceServersCount`
    pub iceServersCount: c_int,
    /// `const char *proxyServer`
    pub proxyServer: *const c_char,
    /// `const char *bindAddress`
    pub bindAddress: *const c_char,
    /// `rtcCertificateType certificateType`
    pub certificateType: c_int,
    /// `rtcTransportPolicy iceTransportPolicy`
    pub iceTransportPolicy: c_int,
    /// `bool enableIceTcp`
    pub enableIceTcp: bool,
    /// `bool enableIceUdpMux`
    pub enableIceUdpMux: bool,
    /// `bool disableAutoNegotiation`
    pub disableAutoNegotiation: bool,
    /// `bool forceMediaTransport`
    pub forceMediaTransport: bool,
    /// `uint16_t portRangeBegin`
    pub portRangeBegin: u16,
    /// `uint16_t portRangeEnd`
    pub portRangeEnd: u16,
    /// `int mtu`
    pub mtu: c_int,
    /// `int maxMessageSize`
    pub maxMessageSize: c_int,
}

/// Mirrors `rtcReliability`.
#[repr(C)]
pub struct RtcReliability {
    /// `bool unordered`
    pub unordered: bool,
    /// `bool unreliable`
    pub unreliable: bool,
    /// `unsigned int maxPacketLifeTime`
    pub maxPacketLifeTime: c_uint,
    /// `unsigned int maxRetransmits`
    pub maxRetransmits: c_uint,
}

/// Mirrors `rtcDataChannelInit`.
#[repr(C)]
pub struct RtcDataChannelInit {
    /// `rtcReliability reliability`
    pub reliability: RtcReliability,
    /// `const char *protocol`
    pub protocol: *const c_char,
    /// `bool negotiated`
    pub negotiated: bool,
    /// `bool manualStream`
    pub manualStream: bool,
    /// `uint16_t stream`
    pub stream: u16,
}

/// Mirrors `rtcTrackInit`.
#[repr(C)]
pub struct RtcTrackInit {
    /// `rtcDirection direction`
    pub direction: c_int,
    /// `rtcCodec codec`
    pub codec: c_int,
    /// `int payloadType`
    pub payloadType: c_int,
    /// `uint32_t ssrc`
    pub ssrc: u32,
    /// `const char *mid`
    pub mid: *const c_char,
    /// `const char *name`
    pub name: *const c_char,
    /// `const char *msid`
    pub msid: *const c_char,
    /// `const char *trackId`
    pub trackId: *const c_char,
    /// `const char *profile`
    pub profile: *const c_char,
}

/// Mirrors `rtcPacketizerInit` (`rtc.h`). Field order/types match exactly so
/// the struct is byte-compatible with a C caller. The `nalSeparator` /
/// `obuPacketization` fields are `int`-sized C enums (see the `RTC_NAL_*` /
/// `RTC_OBU_*` constants). The trailing playout-delay and color-space fields are
/// accepted for ABI compatibility but have no backing in the Rust packetizers
/// (the upstream header-extension writers are unported), so they are ignored.
#[repr(C)]
pub struct RtcPacketizerInit {
    /// `uint32_t ssrc`
    pub ssrc: u32,
    /// `const char *cname`
    pub cname: *const c_char,
    /// `uint8_t payloadType`
    pub payloadType: u8,
    /// `uint32_t clockRate`
    pub clockRate: u32,
    /// `uint16_t sequenceNumber`
    pub sequenceNumber: u16,
    /// `uint32_t timestamp`
    pub timestamp: u32,
    /// `uint16_t maxFragmentSize` — 0 selects the default (H264/H265/AV1).
    pub maxFragmentSize: u16,
    /// `rtcNalUnitSeparator nalSeparator` (H264/H265 only).
    pub nalSeparator: c_int,
    /// `rtcObuPacketization obuPacketization` (AV1 only).
    pub obuPacketization: c_int,
    /// `uint8_t playoutDelayId` (unported — ignored).
    pub playoutDelayId: u8,
    /// `uint16_t playoutDelayMin` (unported — ignored).
    pub playoutDelayMin: u16,
    /// `uint16_t playoutDelayMax` (unported — ignored).
    pub playoutDelayMax: u16,
    /// `uint8_t colorSpaceId` (unported — ignored).
    pub colorSpaceId: u8,
    /// `uint8_t colorChromaSitingHorz` (unported — ignored).
    pub colorChromaSitingHorz: u8,
    /// `uint8_t colorChromaSitingVert` (unported — ignored).
    pub colorChromaSitingVert: u8,
    /// `uint8_t colorRange` (unported — ignored).
    pub colorRange: u8,
    /// `uint8_t colorPrimaries` (unported — ignored).
    pub colorPrimaries: u8,
    /// `uint8_t colorTransfer` (unported — ignored).
    pub colorTransfer: u8,
    /// `uint8_t colorMatrix` (unported — ignored).
    pub colorMatrix: u8,
}

/// `rtcNalUnitSeparator` values (`rtc.h`).
pub const RTC_NAL_SEPARATOR_LENGTH: c_int = 0;
/// `0x00 0x00 0x00 0x01`
pub const RTC_NAL_SEPARATOR_LONG_START_SEQUENCE: c_int = 1;
/// `0x00 0x00 0x01`
pub const RTC_NAL_SEPARATOR_SHORT_START_SEQUENCE: c_int = 2;
/// long or short start sequence
pub const RTC_NAL_SEPARATOR_START_SEQUENCE: c_int = 3;

/// `rtcObuPacketization` values (`rtc.h`).
pub const RTC_OBU_PACKETIZED_OBU: c_int = 0;
/// one temporal unit per packet
pub const RTC_OBU_PACKETIZED_TEMPORAL_UNIT: c_int = 1;

/// Mirrors `rtcWsConfiguration` (WebSocket client). Field order/types match
/// `rtc.h` exactly.
#[repr(C)]
pub struct RtcWsConfiguration {
    /// `bool disableTlsVerification`
    pub disableTlsVerification: bool,
    /// `const char *proxyServer`
    pub proxyServer: *const c_char,
    /// `const char **protocols`
    pub protocols: *const *const c_char,
    /// `int protocolsCount`
    pub protocolsCount: c_int,
    /// `int connectionTimeoutMs`
    pub connectionTimeoutMs: c_int,
    /// `int pingIntervalMs`
    pub pingIntervalMs: c_int,
    /// `int maxOutstandingPings`
    pub maxOutstandingPings: c_int,
    /// `int maxMessageSize`
    pub maxMessageSize: c_int,
}

/// Mirrors `rtcWsServerConfiguration`. Field order/types match `rtc.h` exactly.
#[repr(C)]
pub struct RtcWsServerConfiguration {
    /// `uint16_t port`
    pub port: u16,
    /// `bool enableTls`
    pub enableTls: bool,
    /// `const char *certificatePemFile`
    pub certificatePemFile: *const c_char,
    /// `const char *keyPemFile`
    pub keyPemFile: *const c_char,
    /// `const char *keyPemPass`
    pub keyPemPass: *const c_char,
    /// `const char *bindAddress`
    pub bindAddress: *const c_char,
    /// `int connectionTimeoutMs`
    pub connectionTimeoutMs: c_int,
    /// `int maxMessageSize`
    pub maxMessageSize: c_int,
}

// ===========================================================================
// Handle registry
// ===========================================================================

/// A registered object behind an integer handle. PeerConnection, DataChannel
/// and Track share the same handle space, matching the C++ generic-`Channel`
/// registry.
enum RtcObject {
    Pc(PeerConnection),
    Dc(DataChannel),
    #[allow(dead_code)]
    Tr(Arc<Track>),
    Ws(Arc<WebSocket>),
    WsServer(Arc<WebSocketServer>),
}

/// Monotonic handle counter (`lastId` in capi.cpp). First handle is 1.
static LAST_ID: AtomicI32 = AtomicI32::new(0);

/// `handle -> object` registry (`peerConnectionMap`/`dataChannelMap`/... fused
/// into one map keyed by the shared id space).
static REGISTRY: Lazy<Mutex<HashMap<c_int, RtcObject>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// `handle -> user pointer`. We store the pointer as `usize` (it is opaque to
/// us and only handed back to C verbatim) so the map stays `Send`/`Sync`.
static USER_POINTERS: Lazy<Mutex<HashMap<c_int, usize>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// Optional global log callback installed by `rtcInitLogger`.
static LOG_CALLBACK: Lazy<Mutex<Option<RtcLogCallbackFunc>>> = Lazy::new(|| Mutex::new(None));

/// Process-global Tokio runtime backing the C-ABI surface.
///
/// The high-level Rust API (`PeerConnection`, the libjuice agent's
/// `tokio::spawn` of its event-loop driver) requires an **entered** Tokio
/// runtime on the calling thread — Rust consumers get this from
/// `rt.block_on(...)`. A C/C++ consumer calling the `rtc*` symbols runs on a
/// plain OS thread with no runtime in context, so without this `tokio::spawn`
/// panics ("there is no reactor running"). We therefore stand up a single
/// multi-threaded runtime for the whole process and *enter* it for the body of
/// every exported call (see [`guard`]/[`guard_bool`]/[`dispatch`]); entering is
/// cheap (just sets a thread-local handle) and idempotent across nested calls.
/// The runtime lives for the program's lifetime — matching libdatachannel's own
/// global thread pool / poll service that `rtcCleanup` tears down.
static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("libdatachannel-rust: failed to build global Tokio runtime")
});

fn next_id() -> c_int {
    LAST_ID.fetch_add(1, Ordering::SeqCst) + 1
}

fn emplace(obj: RtcObject) -> c_int {
    let id = next_id();
    REGISTRY.lock().insert(id, obj);
    USER_POINTERS.lock().insert(id, 0);
    id
}

fn user_pointer(id: c_int) -> *mut c_void {
    USER_POINTERS
        .lock()
        .get(&id)
        .map(|p| *p as *mut c_void)
        .unwrap_or(std::ptr::null_mut())
}

fn get_pc(id: c_int) -> Option<PeerConnection> {
    match REGISTRY.lock().get(&id) {
        Some(RtcObject::Pc(pc)) => Some(pc.clone()),
        _ => None,
    }
}

fn get_dc(id: c_int) -> Option<DataChannel> {
    match REGISTRY.lock().get(&id) {
        Some(RtcObject::Dc(dc)) => Some(dc.clone()),
        _ => None,
    }
}

fn get_tr(id: c_int) -> Option<Arc<Track>> {
    match REGISTRY.lock().get(&id) {
        Some(RtcObject::Tr(tr)) => Some(Arc::clone(tr)),
        _ => None,
    }
}

fn get_ws(id: c_int) -> Option<Arc<WebSocket>> {
    match REGISTRY.lock().get(&id) {
        Some(RtcObject::Ws(ws)) => Some(Arc::clone(ws)),
        _ => None,
    }
}

fn get_ws_server(id: c_int) -> Option<Arc<WebSocketServer>> {
    match REGISTRY.lock().get(&id) {
        Some(RtcObject::WsServer(s)) => Some(Arc::clone(s)),
        _ => None,
    }
}

/// `track handle -> owning pc handle`. Populated when a track is added via
/// `rtcAddTrack`/`rtcAddTrackEx` or surfaced via the `on_track` callback, so
/// the media-handler chain / keyframe-request functions can resolve the
/// PeerConnection backing the track.
static TRACK_OWNERS: Lazy<Mutex<HashMap<c_int, c_int>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// `data-channel handle -> owning pc handle`. Populated when a channel is
/// created via `rtcCreateDataChannel*` or surfaced via `on_data_channel`, so
/// `rtcMaxMessageSize` can resolve the negotiated remote max message size from
/// the owning PeerConnection (mirroring `DataChannel::maxMessageSize()`).
static DC_OWNERS: Lazy<Mutex<HashMap<c_int, c_int>>> = Lazy::new(|| Mutex::new(HashMap::new()));

// ===========================================================================
// Panic-safe boundary guards + string-buffer convention
// ===========================================================================

/// Run an `int`-returning body, catching panics (they must not cross into C)
/// and mapping a panic to `RTC_ERR_FAILURE`, mirroring the C++ `wrap()` which
/// turns a `std::exception` into `RTC_ERR_FAILURE`.
fn guard<F: FnOnce() -> c_int + std::panic::UnwindSafe>(f: F) -> c_int {
    // Enter the global runtime so any `tokio::spawn` in the body has a reactor,
    // even when called from a non-Tokio C/C++ thread. `enter()` is unwind-safe
    // (it just installs/uninstalls a thread-local handle on drop).
    let _rt = RUNTIME.enter();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => RTC_ERR_FAILURE,
    }
}

/// Run a `bool`-returning body, mapping a panic to `false`.
fn guard_bool<F: FnOnce() -> bool + std::panic::UnwindSafe>(f: F) -> bool {
    let _rt = RUNTIME.enter();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(false)
}

/// Invoke a C callback inside `catch_unwind` so a panic in the (rare) event a
/// closure we pass to the runtime panics can't unwind across the runtime's
/// threads either. The C callback itself is `extern "C"`, so a panic *inside*
/// the C code is already its problem; this guards our marshalling.
fn dispatch<F: FnOnce() + std::panic::UnwindSafe>(f: F) {
    let _rt = RUNTIME.enter();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
}

/// libdatachannel's `copyAndReturn(string, buffer, size)`:
/// - `buffer == NULL` → return required size (`s.len() + 1`, including NUL).
/// - `size < required` → `RTC_ERR_TOO_SMALL`.
/// - otherwise copy `s` + trailing NUL and return the required size.
fn copy_string(s: &str, buffer: *mut c_char, size: c_int) -> c_int {
    let needed = s.len() + 1; // + NUL
    if buffer.is_null() {
        return needed as c_int;
    }
    if size < needed as c_int {
        return RTC_ERR_TOO_SMALL;
    }
    // SAFETY: caller guarantees `buffer` points to at least `size` bytes and
    // we've checked `size >= needed`.
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr() as *const c_char, buffer, s.len());
        *buffer.add(s.len()) = 0;
    }
    needed as c_int
}

/// libdatachannel's `copyAndReturn(vector<T>, T *buffer, int size)` for the
/// array-returning getters:
/// - `buffer == NULL` → return the element count (a sizing query).
/// - `size < count` → `RTC_ERR_TOO_SMALL`.
/// - otherwise copy `items` into `buffer` and return the count.
///
/// # Safety
/// `buffer`, if non-null, must point to at least `size` elements of `T`.
unsafe fn copy_and_return<T: Copy>(items: &[T], buffer: *mut T, size: c_int) -> c_int {
    let count = items.len() as c_int;
    if buffer.is_null() {
        return count;
    }
    if size < count {
        return RTC_ERR_TOO_SMALL;
    }
    // SAFETY: caller guarantees `buffer` holds at least `size >= count` elements.
    unsafe { std::ptr::copy_nonoverlapping(items.as_ptr(), buffer, items.len()) };
    count
}

/// Borrow a `*const c_char` as `&str`. Returns `None` for a null pointer or
/// non-UTF-8 content (caller maps that to `RTC_ERR_INVALID`).
///
/// # Safety
/// `ptr`, if non-null, must point to a valid NUL-terminated C string.
unsafe fn cstr_opt<'a>(ptr: *const c_char) -> Option<Option<&'a str>> {
    if ptr.is_null() {
        return Some(None);
    }
    // SAFETY: caller guarantees a non-null `ptr` is a valid NUL-terminated
    // C string.
    match unsafe { CStr::from_ptr(ptr) }.to_str() {
        Ok(s) => Some(Some(s)),
        Err(_) => None, // invalid UTF-8
    }
}

// ===========================================================================
// Logger + user pointer
// ===========================================================================

/// `rtcInitLogger`. We record the callback (if any). The runtime uses the
/// `log`/`tracing` facades; a full bridge into them is out of scope, but a
/// supplied callback is stored so the symbol behaves and future log wiring can
/// fan out to it. A NULL callback clears it.
///
/// # Safety
/// `cb`, if non-null, must be a valid function pointer for the program's
/// lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn rtcInitLogger(_level: c_int, cb: Option<RtcLogCallbackFunc>) {
    *LOG_CALLBACK.lock() = cb;
}

/// `rtcSetUserPointer`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetUserPointer(id: c_int, ptr: *mut c_void) {
    USER_POINTERS.lock().insert(id, ptr as usize);
}

/// `rtcGetUserPointer`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetUserPointer(id: c_int) -> *mut c_void {
    user_pointer(id)
}

// ===========================================================================
// PeerConnection lifecycle
// ===========================================================================

/// `rtcCreatePeerConnection`. Returns a positive pc handle, or a negative
/// `RTC_ERR_*` code.
///
/// # Safety
/// `config` must point to a valid `rtcConfiguration` whose `iceServers` array
/// holds `iceServersCount` valid C strings; `proxyServer`/`bindAddress` are
/// either NULL or valid C strings.
#[unsafe(no_mangle)]
pub extern "C" fn rtcCreatePeerConnection(config: *const RtcConfiguration) -> c_int {
    guard(|| {
        if config.is_null() {
            return RTC_ERR_INVALID;
        }
        // SAFETY: checked non-null; caller guarantees validity.
        let cfg = unsafe { &*config };

        let mut c = Configuration::new();

        // ICE servers.
        if !cfg.iceServers.is_null() && cfg.iceServersCount > 0 {
            for i in 0..cfg.iceServersCount as isize {
                // SAFETY: caller guarantees the array has iceServersCount entries.
                let entry = unsafe { *cfg.iceServers.offset(i) };
                let s = match unsafe { cstr_opt(entry) } {
                    Some(Some(s)) => s,
                    Some(None) => continue, // null entry: skip
                    None => return RTC_ERR_INVALID,
                };
                if let Ok(server) = IceServer::parse(s) {
                    c.add_ice_server_parsed(server);
                }
            }
        }

        // bindAddress (libjuice).
        match unsafe { cstr_opt(cfg.bindAddress) } {
            Some(Some(s)) => c.bind_address = Some(s.to_string()),
            Some(None) => {}
            None => return RTC_ERR_INVALID,
        }
        // proxyServer is parsed by the C++ but our Configuration takes a typed
        // ProxyServer; validate the string and ignore (libnice-only path).
        if unsafe { cstr_opt(cfg.proxyServer) }.is_none() {
            return RTC_ERR_INVALID;
        }

        if cfg.portRangeBegin > 0 || cfg.portRangeEnd > 0 {
            c.port_range_begin = cfg.portRangeBegin;
            c.port_range_end = cfg.portRangeEnd;
        }

        c.certificate_type = match cfg.certificateType {
            1 => CertificateType::EcDsa,
            2 => CertificateType::Rsa,
            _ => CertificateType::Default,
        };
        c.ice_transport_policy = match cfg.iceTransportPolicy {
            1 => IceTransportPolicy::Relay,
            _ => IceTransportPolicy::All,
        };
        c.enable_ice_tcp = cfg.enableIceTcp;
        c.enable_ice_udp_mux = cfg.enableIceUdpMux;
        c.disable_auto_negotiation = cfg.disableAutoNegotiation;
        c.force_media_transport = cfg.forceMediaTransport;
        if cfg.mtu > 0 {
            c.mtu = Some(cfg.mtu as usize);
        }
        if cfg.maxMessageSize != 0 {
            c.max_message_size = Some(cfg.maxMessageSize as usize);
        }

        match PeerConnection::new(c, PeerConnectionCallbacks::default()) {
            Ok(pc) => emplace(RtcObject::Pc(pc)),
            Err(_) => RTC_ERR_FAILURE,
        }
    })
}

/// `rtcClosePeerConnection`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcClosePeerConnection(pc: c_int) -> c_int {
    guard(|| match get_pc(pc) {
        Some(pc) => {
            let _ = pc.close();
            RTC_ERR_SUCCESS
        }
        None => RTC_ERR_INVALID,
    })
}

/// `rtcDeletePeerConnection`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcDeletePeerConnection(pc: c_int) -> c_int {
    guard(|| {
        let obj = REGISTRY.lock().remove(&pc);
        match obj {
            Some(RtcObject::Pc(p)) => {
                let _ = p.close();
                USER_POINTERS.lock().remove(&pc);
                RTC_ERR_SUCCESS
            }
            Some(other) => {
                // Not a PC: put it back, report invalid.
                REGISTRY.lock().insert(pc, other);
                RTC_ERR_INVALID
            }
            None => RTC_ERR_INVALID,
        }
    })
}

// ---------------------------------------------------------------------------
// PeerConnection callbacks
// ---------------------------------------------------------------------------

// The PeerConnection runtime exposes a single `set_callbacks` that replaces the
// whole set, and has no getter. To support rtc.h's six independent
// `rtcSet*Callback` setters we keep a per-handle snapshot of the installed C
// callbacks and rebuild the Rust closure set from it on every change.

#[derive(Default, Clone)]
struct PcCallbackSlots {
    local_description: Option<RtcDescriptionCallbackFunc>,
    local_candidate: Option<RtcCandidateCallbackFunc>,
    state_change: Option<RtcStateChangeCallbackFunc>,
    ice_state_change: Option<RtcIceStateChangeCallbackFunc>,
    gathering_state: Option<RtcGatheringStateCallbackFunc>,
    signaling_state: Option<RtcSignalingStateCallbackFunc>,
    data_channel: Option<RtcDataChannelCallbackFunc>,
    track: Option<RtcTrackCallbackFunc>,
}

// SAFETY: the slots hold bare `extern "C" fn` pointers, which are `Send`/`Sync`
// (they are plain code addresses). The user-pointer they're invoked with is
// fetched from USER_POINTERS at call time.
unsafe impl Send for PcCallbackSlots {}
unsafe impl Sync for PcCallbackSlots {}

static PC_SLOTS: Lazy<Mutex<HashMap<c_int, PcCallbackSlots>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// `rtcSetLocalDescriptionCallback`. Backed by the runtime's real
/// [`PeerConnectionCallbacks::on_local_description`], which fires once per
/// negotiation with a credential-complete local description (see
/// [`install_pc_callbacks`]).
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetLocalDescriptionCallback(
    pc: c_int,
    cb: Option<RtcDescriptionCallbackFunc>,
) -> c_int {
    if get_pc(pc).is_none() {
        return RTC_ERR_INVALID;
    }
    PC_SLOTS.lock().entry(pc).or_default().local_description = cb;
    install_pc_callbacks(pc)
}

/// Rebuild and install the full PeerConnectionCallbacks set from the per-handle
/// slot snapshot. Each closure looks up the live user pointer at fire time and
/// dispatches through `catch_unwind`.
fn install_pc_callbacks(pc: c_int) -> c_int {
    guard(|| {
        let pc_obj = match get_pc(pc) {
            Some(p) => p,
            None => return RTC_ERR_INVALID,
        };
        let slots = PC_SLOTS.lock().get(&pc).cloned().unwrap_or_default();
        let mut cbs = PeerConnectionCallbacks::default();

        let ld_cb = slots.local_description;
        let lc_cb = slots.local_candidate;
        let sc_cb = slots.state_change;
        let is_cb = slots.ice_state_change;
        let gs_cb = slots.gathering_state;
        let ss_cb = slots.signaling_state;
        let dc_cb = slots.data_channel;
        let tr_cb = slots.track;

        if let Some(cb) = sc_cb {
            cbs.on_state_change = Arc::new(move |s| {
                let ptr = user_pointer(pc);
                let st = map_pc_state(s) as c_int;
                dispatch(move || cb(pc, st, ptr));
            });
        }
        if let Some(cb) = is_cb {
            cbs.on_ice_state_change = Arc::new(move |s| {
                let ptr = user_pointer(pc);
                let st = map_ice_state(s) as c_int;
                dispatch(move || cb(pc, st, ptr));
            });
        }
        if let Some(cb) = gs_cb {
            cbs.on_gathering_state_change = Arc::new(move |g| {
                let ptr = user_pointer(pc);
                let gs = match g {
                    crate::PeerGatheringState::New => RtcGatheringState::New,
                    crate::PeerGatheringState::InProgress => RtcGatheringState::InProgress,
                    crate::PeerGatheringState::Complete => RtcGatheringState::Complete,
                } as c_int;
                dispatch(move || cb(pc, gs, ptr));
            });
        }
        if let Some(cb) = ss_cb {
            cbs.on_signaling_state_change = Arc::new(move |s| {
                let ptr = user_pointer(pc);
                let ss = map_signaling(s) as c_int;
                dispatch(move || cb(pc, ss, ptr));
            });
        }
        if let Some(cb) = lc_cb {
            cbs.on_local_candidate = Arc::new(move |c| {
                let ptr = user_pointer(pc);
                let cand = std::ffi::CString::new(c.to_sdp()).unwrap_or_default();
                let mid = std::ffi::CString::new(c.mid()).unwrap_or_default();
                dispatch(move || cb(pc, cand.as_ptr(), mid.as_ptr(), ptr));
            });
        }
        if let Some(cb) = dc_cb {
            cbs.on_data_channel = Arc::new(move |dc| {
                let id = emplace(RtcObject::Dc(dc));
                DC_OWNERS.lock().insert(id, pc);
                // Inherit the pc's user pointer (capi.cpp does this).
                let ptr = user_pointer(pc);
                rtcSetUserPointer(id, ptr);
                // Buffer inbound messages for the pull API until the app attaches
                // an onMessage handler (parity with upstream's receive queue).
                install_dc_callbacks(id);
                dispatch(move || cb(pc, id, ptr));
            });
        }
        if let Some(cb) = tr_cb {
            cbs.on_track = Arc::new(move |tr| {
                let id = emplace(RtcObject::Tr(tr));
                // Record which PeerConnection owns the track so the
                // Chain/Transform/Request functions can resolve it.
                TRACK_OWNERS.lock().insert(id, pc);
                // Inherit the pc's user pointer (capi.cpp does this).
                let ptr = user_pointer(pc);
                rtcSetUserPointer(id, ptr);
                dispatch(move || cb(pc, id, ptr));
            });
        }

        // Local description callback: backed by the runtime's real
        // `on_local_description`, which fires exactly once per negotiation with
        // a credential-complete SDP (ice-ufrag/ice-pwd folded in). Marshal the
        // SDP + type to the C callback through the usual dispatch/user-pointer
        // mechanism.
        if let Some(cb) = ld_cb {
            cbs.on_local_description = Arc::new(move |desc| {
                let ptr = user_pointer(pc);
                let sdp = std::ffi::CString::new(desc.to_sdp()).unwrap_or_default();
                let typ = std::ffi::CString::new(desc.type_string()).unwrap_or_default();
                dispatch(move || cb(pc, sdp.as_ptr(), typ.as_ptr(), ptr));
            });
        }

        pc_obj.set_callbacks(cbs);
        RTC_ERR_SUCCESS
    })
}

fn map_pc_state(s: PeerConnectionState) -> RtcState {
    match s {
        PeerConnectionState::New => RtcState::New,
        PeerConnectionState::Connecting => RtcState::Connecting,
        PeerConnectionState::Connected => RtcState::Connected,
        PeerConnectionState::Disconnected => RtcState::Disconnected,
        PeerConnectionState::Failed => RtcState::Failed,
        PeerConnectionState::Closed => RtcState::Closed,
    }
}

fn map_ice_state(s: crate::ice_transport::State) -> RtcIceState {
    use crate::ice_transport::State;
    match s {
        State::New => RtcIceState::New,
        State::Checking => RtcIceState::Checking,
        State::Connected => RtcIceState::Connected,
        State::Completed => RtcIceState::Completed,
        State::Failed => RtcIceState::Failed,
        State::Disconnected => RtcIceState::Disconnected,
        State::Closed => RtcIceState::Closed,
    }
}

fn map_signaling(s: crate::SignalingState) -> RtcSignalingState {
    match s {
        crate::SignalingState::Stable => RtcSignalingState::Stable,
        crate::SignalingState::HaveLocalOffer => RtcSignalingState::HaveLocalOffer,
        crate::SignalingState::HaveRemoteOffer => RtcSignalingState::HaveRemoteOffer,
        crate::SignalingState::HaveLocalPranswer => RtcSignalingState::HaveLocalPranswer,
        crate::SignalingState::HaveRemotePranswer => RtcSignalingState::HaveRemotePranswer,
    }
}

/// `rtcSetLocalCandidateCallback`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetLocalCandidateCallback(
    pc: c_int,
    cb: Option<RtcCandidateCallbackFunc>,
) -> c_int {
    if get_pc(pc).is_none() {
        return RTC_ERR_INVALID;
    }
    PC_SLOTS.lock().entry(pc).or_default().local_candidate = cb;
    install_pc_callbacks(pc)
}

/// `rtcSetStateChangeCallback`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetStateChangeCallback(
    pc: c_int,
    cb: Option<RtcStateChangeCallbackFunc>,
) -> c_int {
    if get_pc(pc).is_none() {
        return RTC_ERR_INVALID;
    }
    PC_SLOTS.lock().entry(pc).or_default().state_change = cb;
    install_pc_callbacks(pc)
}

/// `rtcSetIceStateChangeCallback`. Bound to the runtime's per-ICE-transition
/// hook (`on_ice_state_change`), which surfaces the raw [`crate::ice_transport::State`]
/// before it is folded into the aggregate PeerConnection state.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetIceStateChangeCallback(
    pc: c_int,
    cb: Option<RtcIceStateChangeCallbackFunc>,
) -> c_int {
    if get_pc(pc).is_none() {
        return RTC_ERR_INVALID;
    }
    PC_SLOTS.lock().entry(pc).or_default().ice_state_change = cb;
    install_pc_callbacks(pc)
}

/// `rtcSetGatheringStateChangeCallback`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetGatheringStateChangeCallback(
    pc: c_int,
    cb: Option<RtcGatheringStateCallbackFunc>,
) -> c_int {
    if get_pc(pc).is_none() {
        return RTC_ERR_INVALID;
    }
    PC_SLOTS.lock().entry(pc).or_default().gathering_state = cb;
    install_pc_callbacks(pc)
}

/// `rtcSetSignalingStateChangeCallback`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetSignalingStateChangeCallback(
    pc: c_int,
    cb: Option<RtcSignalingStateCallbackFunc>,
) -> c_int {
    if get_pc(pc).is_none() {
        return RTC_ERR_INVALID;
    }
    PC_SLOTS.lock().entry(pc).or_default().signaling_state = cb;
    install_pc_callbacks(pc)
}

// ---------------------------------------------------------------------------
// PeerConnection description / candidate plumbing
// ---------------------------------------------------------------------------

/// `rtcSetLocalDescription`. `type` may be NULL.
///
/// # Safety
/// `typ`, if non-null, must be a valid C string.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetLocalDescription(pc: c_int, typ: *const c_char) -> c_int {
    guard(|| {
        let pc = match get_pc(pc) {
            Some(p) => p,
            None => return RTC_ERR_INVALID,
        };
        let t = match unsafe { cstr_opt(typ) } {
            Some(Some(s)) => DescriptionType::from_string(s),
            Some(None) => DescriptionType::Unspec,
            None => return RTC_ERR_INVALID,
        };
        // The runtime requires a concrete Offer/Answer; map Unspec by inferring
        // from signaling state (Stable => Offer, HaveRemoteOffer => Answer),
        // matching the C++ default behaviour.
        let t = match t {
            DescriptionType::Unspec => {
                if matches!(pc.signaling_state(), crate::SignalingState::HaveRemoteOffer) {
                    DescriptionType::Answer
                } else {
                    DescriptionType::Offer
                }
            }
            other => other,
        };
        match pc.set_local_description(t) {
            Ok(_) => RTC_ERR_SUCCESS,
            Err(_) => RTC_ERR_FAILURE,
        }
    })
}

/// `rtcSetRemoteDescription`.
///
/// # Safety
/// `sdp` must be a valid C string; `typ`, if non-null, a valid C string.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetRemoteDescription(
    pc: c_int,
    sdp: *const c_char,
    typ: *const c_char,
) -> c_int {
    guard(|| {
        let pc = match get_pc(pc) {
            Some(p) => p,
            None => return RTC_ERR_INVALID,
        };
        let sdp = match unsafe { cstr_opt(sdp) } {
            Some(Some(s)) => s,
            _ => return RTC_ERR_INVALID, // null or invalid utf-8
        };
        let type_str = match unsafe { cstr_opt(typ) } {
            Some(opt) => opt,
            None => return RTC_ERR_INVALID,
        };
        let mut desc = match Description::parse(sdp) {
            Ok(d) => d,
            Err(_) => return RTC_ERR_INVALID,
        };
        if let Some(ts) = type_str {
            desc.hint_type(DescriptionType::from_string(ts));
        }
        match pc.set_remote_description(desc) {
            Ok(_) => {
                // Upstream auto-negotiation: applying a remote *offer* makes us
                // the answerer, so we generate the answer immediately (unless
                // the app opted out). `set_remote_description` leaves signaling
                // in `HaveRemoteOffer` exactly in that case, so we key off it
                // rather than re-inspecting the description type.
                if !pc.disable_auto_negotiation()
                    && matches!(pc.signaling_state(), crate::SignalingState::HaveRemoteOffer)
                {
                    let _ = pc.set_local_description(DescriptionType::Answer);
                }
                RTC_ERR_SUCCESS
            }
            Err(_) => RTC_ERR_FAILURE,
        }
    })
}

/// `rtcAddRemoteCandidate`.
///
/// # Safety
/// `cand` must be a valid C string; `mid`, if non-null, a valid C string.
#[unsafe(no_mangle)]
pub extern "C" fn rtcAddRemoteCandidate(
    pc: c_int,
    cand: *const c_char,
    mid: *const c_char,
) -> c_int {
    guard(|| {
        let pc = match get_pc(pc) {
            Some(p) => p,
            None => return RTC_ERR_INVALID,
        };
        let cand_s = match unsafe { cstr_opt(cand) } {
            Some(Some(s)) => s,
            _ => return RTC_ERR_INVALID,
        };
        let mid_s = match unsafe { cstr_opt(mid) } {
            Some(opt) => opt.unwrap_or(""),
            None => return RTC_ERR_INVALID,
        };
        let candidate = match crate::Candidate::parse(cand_s, mid_s) {
            Ok(c) => c,
            Err(_) => return RTC_ERR_INVALID,
        };
        match pc.add_remote_candidate(&candidate) {
            Ok(_) => RTC_ERR_SUCCESS,
            Err(_) => RTC_ERR_FAILURE,
        }
    })
}

fn pc_string_out(
    pc: c_int,
    buffer: *mut c_char,
    size: c_int,
    f: impl Fn(&PeerConnection) -> Option<String> + std::panic::RefUnwindSafe,
) -> c_int {
    guard(|| {
        let pc = match get_pc(pc) {
            Some(p) => p,
            None => return RTC_ERR_INVALID,
        };
        match f(&pc) {
            Some(s) => copy_string(&s, buffer, size),
            None => RTC_ERR_NOT_AVAIL,
        }
    })
}

/// `rtcGetLocalDescription`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetLocalDescription(pc: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    pc_string_out(pc, buffer, size, |pc| {
        pc.local_description().map(|d| d.to_sdp())
    })
}

/// `rtcGetRemoteDescription`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetRemoteDescription(pc: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    pc_string_out(pc, buffer, size, |pc| {
        pc.remote_description().map(|d| d.to_sdp())
    })
}

/// `rtcGetLocalDescriptionType`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetLocalDescriptionType(pc: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    pc_string_out(pc, buffer, size, |pc| {
        pc.local_description().map(|d| d.type_string().to_string())
    })
}

/// `rtcGetRemoteDescriptionType`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetRemoteDescriptionType(
    pc: c_int,
    buffer: *mut c_char,
    size: c_int,
) -> c_int {
    pc_string_out(pc, buffer, size, |pc| {
        pc.remote_description().map(|d| d.type_string().to_string())
    })
}

/// `rtcCreateOffer`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcCreateOffer(pc: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    guard(|| {
        let pc = match get_pc(pc) {
            Some(p) => p,
            None => return RTC_ERR_INVALID,
        };
        match pc.create_offer() {
            Ok(d) => copy_string(&d.to_sdp(), buffer, size),
            Err(_) => RTC_ERR_FAILURE,
        }
    })
}

/// `rtcCreateAnswer`. The runtime has no standalone `createAnswer`; an answer
/// is produced by `set_local_description(Answer)` after a remote offer. We
/// build it that way and render the resulting local description.
#[unsafe(no_mangle)]
pub extern "C" fn rtcCreateAnswer(pc: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    guard(|| {
        let pc = match get_pc(pc) {
            Some(p) => p,
            None => return RTC_ERR_INVALID,
        };
        match pc.set_local_description(DescriptionType::Answer) {
            Ok(d) => copy_string(&d.to_sdp(), buffer, size),
            Err(_) => RTC_ERR_FAILURE,
        }
    })
}

/// `rtcGetLocalAddress`. Selected local socket address, available once a
/// candidate pair is nominated. Mirrors `PeerConnection::localAddress()`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetLocalAddress(pc: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    pc_string_out(pc, buffer, size, |pc| pc.local_address())
}

/// `rtcGetRemoteAddress`. Selected remote socket address, available once a
/// candidate pair is nominated. Mirrors `PeerConnection::remoteAddress()`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetRemoteAddress(pc: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    pc_string_out(pc, buffer, size, |pc| pc.remote_address())
}

/// `rtcGetSelectedCandidatePair`. Writes the selected local/remote candidates
/// (SDP form) into the two buffers. Returns the larger of the two needed sizes,
/// or `RTC_ERR_NOT_AVAIL` if no pair has been nominated. Mirrors
/// `rtcGetSelectedCandidatePair` / `PeerConnection::getSelectedCandidatePair()`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetSelectedCandidatePair(
    pc: c_int,
    local: *mut c_char,
    local_size: c_int,
    remote: *mut c_char,
    remote_size: c_int,
) -> c_int {
    guard(|| {
        let pc = match get_pc(pc) {
            Some(p) => p,
            None => return RTC_ERR_INVALID,
        };
        match pc.selected_candidate_pair() {
            Some((local_cand, remote_cand)) => {
                let local_ret = copy_string(&local_cand.to_sdp(), local, local_size);
                if local_ret < 0 {
                    return local_ret;
                }
                let remote_ret = copy_string(&remote_cand.to_sdp(), remote, remote_size);
                if remote_ret < 0 {
                    return remote_ret;
                }
                local_ret.max(remote_ret)
            }
            None => RTC_ERR_NOT_AVAIL,
        }
    })
}

/// `rtcIsNegotiationNeeded`. The runtime has no negotiation-needed flag; we
/// report `false` (matching a freshly-negotiated connection).
//
// TODO(#22): expose PeerConnection::negotiation_needed() in the runtime.
#[unsafe(no_mangle)]
pub extern "C" fn rtcIsNegotiationNeeded(pc: c_int) -> bool {
    // Always false: a freshly-negotiated connection needs no renegotiation, and
    // the runtime has no renegotiation path yet. Validating the handle has no
    // observable effect on the bool result, so we simply report false.
    let _ = pc;
    false
}

/// `rtcGetMaxDataChannelStream`. Highest usable SCTP stream id for data
/// channels. Mirrors `PeerConnection::maxDataChannelId()`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetMaxDataChannelStream(pc: c_int) -> c_int {
    guard(|| match get_pc(pc) {
        Some(pc) => c_int::from(pc.max_data_channel_stream()),
        None => RTC_ERR_INVALID,
    })
}

/// `rtcGetRemoteMaxMessageSize`. The smaller of the remote peer's advertised
/// `max-message-size` and our local maximum (see
/// [`PeerConnection::remote_max_message_size`]). Saturates to `c_int::MAX` for
/// an unbounded (RFC 8841 zero) remote limit.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetRemoteMaxMessageSize(pc: c_int) -> c_int {
    guard(|| match get_pc(pc) {
        Some(pc) => pc.remote_max_message_size().min(c_int::MAX as usize) as c_int,
        None => RTC_ERR_INVALID,
    })
}

// ===========================================================================
// DataChannel
// ===========================================================================

/// Mirror `rtc::PeerConnection`'s automatic negotiation: when auto-negotiation
/// is enabled and signaling is `Stable`, adding the first data channel or track
/// generates a local offer (firing the local-description callback). Upstream
/// defers this to the event loop and coalesces multiple additions into one
/// offer; we fire synchronously, so the offer reflects whatever is registered
/// at the moment the first item is added (sufficient for the common single
/// pre-connection channel, and for tracks/channels added one before connecting).
/// A non-`Stable` state means an offer is already in flight, so we skip.
fn auto_negotiate_offer(pc: &PeerConnection) {
    if pc.disable_auto_negotiation() {
        return;
    }
    if matches!(pc.signaling_state(), crate::SignalingState::Stable) {
        let _ = pc.set_local_description(DescriptionType::Offer);
    }
}

/// `rtcSetDataChannelCallback`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetDataChannelCallback(
    pc: c_int,
    cb: Option<RtcDataChannelCallbackFunc>,
) -> c_int {
    if get_pc(pc).is_none() {
        return RTC_ERR_INVALID;
    }
    PC_SLOTS.lock().entry(pc).or_default().data_channel = cb;
    install_pc_callbacks(pc)
}

/// `rtcCreateDataChannel`.
///
/// # Safety
/// `label`, if non-null, must be a valid C string.
#[unsafe(no_mangle)]
pub extern "C" fn rtcCreateDataChannel(pc: c_int, label: *const c_char) -> c_int {
    rtcCreateDataChannelEx(pc, label, std::ptr::null())
}

/// `rtcCreateDataChannelEx`.
///
/// # Safety
/// `label`, if non-null, must be a valid C string; `init`, if non-null, a
/// valid `rtcDataChannelInit`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcCreateDataChannelEx(
    pc: c_int,
    label: *const c_char,
    init: *const RtcDataChannelInit,
) -> c_int {
    guard(|| {
        let pc_obj = match get_pc(pc) {
            Some(p) => p,
            None => return RTC_ERR_INVALID,
        };
        let label_s = match unsafe { cstr_opt(label) } {
            Some(opt) => opt.unwrap_or("").to_string(),
            None => return RTC_ERR_INVALID,
        };

        let mut dci = DataChannelInit::default();
        if !init.is_null() {
            // SAFETY: checked non-null; caller guarantees validity.
            let i = unsafe { &*init };
            let r = &i.reliability;
            dci.reliability.unordered = r.unordered;
            if r.unreliable {
                if r.maxPacketLifeTime > 0 {
                    dci.reliability.typ = ReliabilityType::Timed;
                    dci.reliability.rexmit = r.maxPacketLifeTime;
                } else {
                    dci.reliability.typ = ReliabilityType::Rexmit;
                    dci.reliability.rexmit = r.maxRetransmits;
                }
            }
            dci.negotiated = i.negotiated;
            dci.stream = if i.manualStream { Some(i.stream) } else { None };
            dci.protocol = match unsafe { cstr_opt(i.protocol) } {
                Some(opt) => opt.unwrap_or("").to_string(),
                None => return RTC_ERR_INVALID,
            };
        }

        let dc = pc_obj.create_data_channel_ext(label_s, dci, DataChannelCallbacks::default());
        let id = emplace(RtcObject::Dc(dc));
        DC_OWNERS.lock().insert(id, pc);
        // Inherit the pc's user pointer (capi.cpp does this).
        let ptr = user_pointer(pc);
        rtcSetUserPointer(id, ptr);
        // Install the default (no-callback) handler set so inbound messages are
        // buffered for the pull API from creation, exactly as upstream queues
        // before an onMessage handler is attached.
        install_dc_callbacks(id);
        // Upstream kicks negotiation once a channel is registered (unless the
        // app opted out). The channel is now in the description, so the offer
        // carries the application m-line.
        auto_negotiate_offer(&pc_obj);
        id
    })
}

/// `rtcDeleteDataChannel`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcDeleteDataChannel(dc: c_int) -> c_int {
    guard(|| {
        let obj = REGISTRY.lock().remove(&dc);
        match obj {
            Some(RtcObject::Dc(d)) => {
                d.close();
                USER_POINTERS.lock().remove(&dc);
                DC_SLOTS.lock().remove(&dc);
                DC_RECV.lock().remove(&dc);
                DC_OPEN_FIRED.lock().remove(&dc);
                DC_AVAIL_PENDING.lock().remove(&dc);
                DC_OWNERS.lock().remove(&dc);
                RTC_ERR_SUCCESS
            }
            Some(other) => {
                REGISTRY.lock().insert(dc, other);
                RTC_ERR_INVALID
            }
            None => RTC_ERR_INVALID,
        }
    })
}

/// `rtcGetDataChannelStream`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetDataChannelStream(dc: c_int) -> c_int {
    guard(|| match get_dc(dc) {
        Some(d) => d.stream() as c_int,
        None => RTC_ERR_INVALID,
    })
}

/// `rtcGetDataChannelLabel`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetDataChannelLabel(dc: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    guard(|| match get_dc(dc) {
        Some(d) => copy_string(d.label(), buffer, size),
        None => RTC_ERR_INVALID,
    })
}

/// `rtcGetDataChannelProtocol`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetDataChannelProtocol(dc: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    guard(|| match get_dc(dc) {
        Some(d) => copy_string(d.protocol(), buffer, size),
        None => RTC_ERR_INVALID,
    })
}

/// `rtcGetDataChannelReliability`.
///
/// # Safety
/// `reliability` must point to a valid `rtcReliability`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetDataChannelReliability(
    dc: c_int,
    reliability: *mut RtcReliability,
) -> c_int {
    guard(|| {
        let d = match get_dc(dc) {
            Some(d) => d,
            None => return RTC_ERR_INVALID,
        };
        if reliability.is_null() {
            return RTC_ERR_INVALID;
        }
        let r: Reliability = d.reliability();
        // SAFETY: checked non-null.
        let out = unsafe { &mut *reliability };
        out.unordered = r.unordered;
        out.maxPacketLifeTime = 0;
        out.maxRetransmits = 0;
        match r.typ {
            ReliabilityType::Reliable => out.unreliable = false,
            ReliabilityType::Timed => {
                out.unreliable = true;
                out.maxPacketLifeTime = r.rexmit;
            }
            ReliabilityType::Rexmit => {
                out.unreliable = true;
                out.maxRetransmits = r.rexmit;
            }
        }
        RTC_ERR_SUCCESS
    })
}

// ===========================================================================
// Generic Channel ops (DataChannel; Track/WebSocket share the API in rtc.h)
// ===========================================================================

/// Per-handle storage for the channel-level message callback (and the others)
/// so we can rebuild the DataChannelCallbacks set on every `rtcSet*Callback`.
#[derive(Default, Clone)]
struct DcCallbackSlots {
    open: Option<RtcOpenCallbackFunc>,
    closed: Option<RtcClosedCallbackFunc>,
    error: Option<RtcErrorCallbackFunc>,
    message: Option<RtcMessageCallbackFunc>,
    buffered_low: Option<RtcBufferedAmountLowCallbackFunc>,
    available: Option<RtcAvailableCallbackFunc>,
}

// SAFETY: bare `extern "C" fn` pointers are Send/Sync (code addresses).
unsafe impl Send for DcCallbackSlots {}
unsafe impl Sync for DcCallbackSlots {}

static DC_SLOTS: Lazy<Mutex<HashMap<c_int, DcCallbackSlots>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Per-DataChannel inbound message queue for the pull API
/// (`rtcReceiveMessage`). The runtime is push-based; when no `rtcMessageCallback`
/// is registered we install an enqueue closure that buffers inbound messages
/// here, mirroring libdatachannel where an unset `onMessage` leaves messages in
/// the channel's receive queue. Each entry is `(payload, is_binary)`; for text
/// the payload holds the UTF-8 bytes WITHOUT a trailing NUL.
static DC_RECV: Lazy<Mutex<HashMap<c_int, VecDeque<(Vec<u8>, bool)>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// DataChannel ids whose open callback has already been delivered to the
/// application. Ports the exactly-once half of upstream's
/// `synchronized_stored_callback`: the open event reaches the app a single
/// time regardless of how often the callback set is rebuilt (`rtcSet*Callback`
/// re-runs `install_dc_callbacks`) and regardless of whether it arrives via the
/// runtime's open transition (`mark_open`) or via a replay onto an
/// already-open channel. Membership is gated by `HashSet::insert` returning
/// `true` only on first insert.
static DC_OPEN_FIRED: Lazy<Mutex<HashSet<c_int>>> = Lazy::new(|| Mutex::new(HashSet::new()));

/// DataChannel ids whose pull-API receive queue transitioned empty→non-empty
/// while no `rtcAvailableCallback` was installed, so the "available" edge has
/// not yet reached the app. A subsequent `rtcSetAvailableCallback` replays it
/// once and clears the flag — porting the replay half of upstream's
/// `synchronized_stored_callback` for `availableCallback`. Unlike a level
/// signal, it is *not* re-set while the queue stays non-empty: only the next
/// empty→non-empty edge re-arms it (mirroring `triggerAvailable(count == 1)`).
static DC_AVAIL_PENDING: Lazy<Mutex<HashSet<c_int>>> = Lazy::new(|| Mutex::new(HashSet::new()));

/// Marshal one inbound DataChannel message to a C `rtcMessageCallback`, applying
/// rtc.h's size convention: binary → non-negative byte count; text → a
/// NUL-terminated string with NEGATIVE size `-(len + 1)`. `dispatch` runs the
/// call synchronously, so the raw pointers into `data`/the temporary `CString`
/// stay valid for the duration of the C call.
fn deliver_c_message(id: c_int, cb: RtcMessageCallbackFunc, data: &[u8], binary: bool) {
    let ptr = user_pointer(id);
    if binary {
        let len = data.len() as c_int;
        let p = data.as_ptr() as *const c_char;
        dispatch(move || cb(id, p, len, ptr));
    } else {
        let cstr = std::ffi::CString::new(data).unwrap_or_default();
        let neg = -((cstr.as_bytes().len() + 1) as c_int);
        let p = cstr.as_ptr();
        dispatch(move || cb(id, p, neg, ptr));
    }
}

/// Rebuild and install the DataChannelCallbacks set for `id` from its slots.
fn install_dc_callbacks(id: c_int) -> c_int {
    guard(|| {
        let dc = match get_dc(id) {
            Some(d) => d,
            None => return RTC_ERR_INVALID,
        };
        let slots = DC_SLOTS.lock().get(&id).cloned().unwrap_or_default();
        let mut cbs = DataChannelCallbacks::default();

        // Build the open dispatcher behind a per-id exactly-once guard so the
        // app's `openCallback` fires a single time however this is reached: the
        // runtime's open transition firing `cbs.on_open`, or the replay below
        // re-invoking it on an already-open channel. Mirrors upstream's
        // `synchronized_stored_callback`.
        let open_dispatcher: Option<Arc<dyn Fn() + Send + Sync>> = slots.open.map(|cb| {
            Arc::new(move || {
                if DC_OPEN_FIRED.lock().insert(id) {
                    let ptr = user_pointer(id);
                    dispatch(move || cb(id, ptr));
                }
            }) as Arc<dyn Fn() + Send + Sync>
        });
        if let Some(ref d) = open_dispatcher {
            cbs.on_open = Arc::clone(d);
        }
        if let Some(cb) = slots.closed {
            cbs.on_closed = Arc::new(move || {
                let ptr = user_pointer(id);
                dispatch(move || cb(id, ptr));
            });
        }
        if let Some(cb) = slots.message {
            // A handler is attached: forward any messages that queued while none
            // was set (parity with upstream, which flushes the receive backlog
            // when onMessage is assigned), then dispatch live.
            let backlog: Vec<(Vec<u8>, bool)> = DC_RECV
                .lock()
                .get_mut(&id)
                .map(|q| q.drain(..).collect())
                .unwrap_or_default();
            for (data, binary) in backlog {
                deliver_c_message(id, cb, &data, binary);
            }
            // The queue is now drained to the live handler, so any unmarked
            // "available" edge no longer applies.
            DC_AVAIL_PENDING.lock().remove(&id);
            cbs.on_message = Arc::new(move |data, binary| {
                deliver_c_message(id, cb, data, binary);
            });
        } else {
            // No handler: buffer inbound messages for the pull API
            // (`rtcReceiveMessage`), as upstream's unset onMessage does. On the
            // empty→non-empty transition fire the available callback once
            // (edge-triggered, mirroring upstream's `triggerAvailable(count ==
            // 1)`); if none is installed yet, mark the edge pending so a later
            // `rtcSetAvailableCallback` replays it.
            let avail = slots.available;
            cbs.on_message = Arc::new(move |data: &[u8], binary: bool| {
                let became_nonempty = {
                    let mut recv = DC_RECV.lock();
                    let queue = recv.entry(id).or_default();
                    let was_empty = queue.is_empty();
                    queue.push_back((data.to_vec(), binary));
                    was_empty
                };
                if became_nonempty {
                    match avail {
                        Some(cb) => {
                            let ptr = user_pointer(id);
                            dispatch(move || cb(id, ptr));
                        }
                        None => {
                            DC_AVAIL_PENDING.lock().insert(id);
                        }
                    }
                }
            });
        }
        if let Some(cb) = slots.buffered_low {
            cbs.on_buffered_amount_low = Arc::new(move || {
                let ptr = user_pointer(id);
                dispatch(move || cb(id, ptr));
            });
        }
        // `error` has no runtime backing on DataChannel; stored but never fired.

        dc.set_callbacks(cbs);

        // Replay a missed open: an incoming channel is marked open *before* it
        // is surfaced via `on_data_channel`, so the app's `rtcSetOpenCallback`
        // (registered inside its dataChannelCallback) arrives after the open
        // transition already fired the default no-op. Deliver the open now. The
        // dispatcher's `DC_OPEN_FIRED` guard keeps this idempotent with the
        // runtime's own firing.
        if dc.is_open() {
            if let Some(d) = open_dispatcher {
                d();
            }
        }

        // Replay a pending "available" edge: the receive queue went non-empty
        // before an available callback existed. Deliver it once now. Gated on
        // pull mode — when a message handler is set the backlog was just
        // flushed to it (and the pending flag cleared above), so there is
        // nothing to announce. Mirrors `synchronized_stored_callback`'s replay.
        if slots.message.is_none() {
            if let Some(cb) = slots.available {
                let pending = DC_AVAIL_PENDING.lock().remove(&id);
                if pending {
                    let ptr = user_pointer(id);
                    dispatch(move || cb(id, ptr));
                }
            }
        }
        RTC_ERR_SUCCESS
    })
}

// ---------------------------------------------------------------------------
// WebSocket callback plumbing (shares the generic-channel id space)
// ---------------------------------------------------------------------------

/// Per-WebSocket-handle storage for the channel-level callbacks, so the runtime
/// callback set can be rebuilt on every `rtcSet*Callback` (mirrors
/// [`DcCallbackSlots`]). Unlike DataChannel, the runtime WebSocket *does* have
/// an error hook, so `error` is live here.
#[derive(Default, Clone)]
struct WsCallbackSlots {
    open: Option<RtcOpenCallbackFunc>,
    closed: Option<RtcClosedCallbackFunc>,
    error: Option<RtcErrorCallbackFunc>,
    message: Option<RtcMessageCallbackFunc>,
}

// SAFETY: bare `extern "C" fn` pointers are Send/Sync (code addresses).
unsafe impl Send for WsCallbackSlots {}
unsafe impl Sync for WsCallbackSlots {}

static WS_SLOTS: Lazy<Mutex<HashMap<c_int, WsCallbackSlots>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Per-WebSocket inbound message backlog (and pull-API queue), matching
/// [`DC_RECV`]. Messages that arrive before a `rtcMessageCallback` is set are
/// buffered here and flushed by [`install_ws_callbacks`] when one attaches.
/// Each entry is `(payload, is_binary)`; text payloads hold UTF-8 bytes with no
/// trailing NUL.
static WS_RECV: Lazy<Mutex<HashMap<c_int, VecDeque<(Vec<u8>, bool)>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// WebSocket ids whose open callback has already been delivered, mirroring
/// [`DC_OPEN_FIRED`]: a server-accepted socket is already `Open` when surfaced
/// to the app, so `rtcSetOpenCallback` (registered inside the client callback)
/// arrives after the runtime's open transition already fired against no
/// callback. The replay in [`install_ws_callbacks`] delivers it once, gated by
/// this set.
static WS_OPEN_FIRED: Lazy<Mutex<HashSet<c_int>>> = Lazy::new(|| Mutex::new(HashSet::new()));

/// Convert a runtime [`WsMessage`] into the `(bytes, is_binary)` shape the
/// generic [`deliver_c_message`] marshaller expects.
fn ws_message_parts(msg: WsMessage) -> (Vec<u8>, bool) {
    match msg {
        WsMessage::Text(b) => (b, false),
        WsMessage::Binary(b) => (b, true),
    }
}

/// Rebuild and install the runtime callback set for WebSocket `id` from its
/// slots. Mirrors [`install_dc_callbacks`]: exactly-once open (with replay onto
/// an already-open socket), live-or-buffered message delivery, and panic-safe
/// dispatch of each C callback.
fn install_ws_callbacks(id: c_int) -> c_int {
    guard(|| {
        let ws = match get_ws(id) {
            Some(w) => w,
            None => return RTC_ERR_INVALID,
        };
        let slots = WS_SLOTS.lock().get(&id).cloned().unwrap_or_default();

        // Exactly-once open dispatcher (see DC_OPEN_FIRED / install_dc_callbacks).
        let open_dispatcher: Option<Arc<dyn Fn() + Send + Sync>> = slots.open.map(|cb| {
            Arc::new(move || {
                if WS_OPEN_FIRED.lock().insert(id) {
                    let ptr = user_pointer(id);
                    dispatch(move || cb(id, ptr));
                }
            }) as Arc<dyn Fn() + Send + Sync>
        });
        if let Some(ref d) = open_dispatcher {
            let d = Arc::clone(d);
            ws.set_on_open(move || d());
        }

        if let Some(cb) = slots.closed {
            ws.set_on_closed(move || {
                let ptr = user_pointer(id);
                dispatch(move || cb(id, ptr));
            });
        }

        if let Some(cb) = slots.error {
            ws.set_on_error(move |err: String| {
                let ptr = user_pointer(id);
                let cstr = std::ffi::CString::new(err).unwrap_or_default();
                let p = cstr.as_ptr();
                dispatch(move || cb(id, p, ptr));
            });
        }

        if let Some(cb) = slots.message {
            // Flush messages buffered before a handler attached, then go live
            // (parity with install_dc_callbacks).
            let backlog: Vec<(Vec<u8>, bool)> = WS_RECV
                .lock()
                .get_mut(&id)
                .map(|q| q.drain(..).collect())
                .unwrap_or_default();
            for (data, binary) in backlog {
                deliver_c_message(id, cb, &data, binary);
            }
            ws.set_on_message(move |msg: WsMessage| {
                let (data, binary) = ws_message_parts(msg);
                deliver_c_message(id, cb, &data, binary);
            });
        } else {
            // No handler yet: buffer inbound messages for the backlog / pull API.
            ws.set_on_message(move |msg: WsMessage| {
                let (data, binary) = ws_message_parts(msg);
                WS_RECV
                    .lock()
                    .entry(id)
                    .or_default()
                    .push_back((data, binary));
            });
        }

        // Replay a missed open onto an already-open socket (server-accepted, or
        // a client that connected before its callback was registered). The
        // WS_OPEN_FIRED guard keeps this idempotent with the runtime's firing.
        if ws.is_open() {
            if let Some(d) = open_dispatcher {
                d();
            }
        }
        RTC_ERR_SUCCESS
    })
}

/// `rtcSetOpenCallback`. Works on a DataChannel **or** a Track handle (rtc.h's
/// generic-channel API).
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetOpenCallback(id: c_int, cb: Option<RtcOpenCallbackFunc>) -> c_int {
    if get_tr(id).is_some() {
        TRACK_SLOTS.lock().entry(id).or_default().open = cb;
        return install_track_callbacks(id);
    }
    if get_ws(id).is_some() {
        WS_SLOTS.lock().entry(id).or_default().open = cb;
        return install_ws_callbacks(id);
    }
    if get_dc(id).is_none() {
        return RTC_ERR_INVALID;
    }
    DC_SLOTS.lock().entry(id).or_default().open = cb;
    install_dc_callbacks(id)
}

/// `rtcSetClosedCallback`. DataChannel or Track handle.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetClosedCallback(id: c_int, cb: Option<RtcClosedCallbackFunc>) -> c_int {
    if get_tr(id).is_some() {
        TRACK_SLOTS.lock().entry(id).or_default().closed = cb;
        return install_track_callbacks(id);
    }
    if get_ws(id).is_some() {
        WS_SLOTS.lock().entry(id).or_default().closed = cb;
        return install_ws_callbacks(id);
    }
    if get_dc(id).is_none() {
        return RTC_ERR_INVALID;
    }
    DC_SLOTS.lock().entry(id).or_default().closed = cb;
    install_dc_callbacks(id)
}

/// `rtcSetErrorCallback`. Stored for ABI completeness; neither the runtime
/// DataChannel nor Track has an error hook, so it will not fire. DataChannel or
/// Track handle.
//
// TODO(#22): wire to an error hook when the runtime grows one.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetErrorCallback(id: c_int, cb: Option<RtcErrorCallbackFunc>) -> c_int {
    if get_tr(id).is_some() {
        TRACK_SLOTS.lock().entry(id).or_default().error = cb;
        return RTC_ERR_SUCCESS;
    }
    if get_ws(id).is_some() {
        WS_SLOTS.lock().entry(id).or_default().error = cb;
        return install_ws_callbacks(id);
    }
    if get_dc(id).is_none() {
        return RTC_ERR_INVALID;
    }
    DC_SLOTS.lock().entry(id).or_default().error = cb;
    RTC_ERR_SUCCESS
}

/// `rtcSetMessageCallback`. DataChannel or Track handle.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetMessageCallback(id: c_int, cb: Option<RtcMessageCallbackFunc>) -> c_int {
    if get_tr(id).is_some() {
        TRACK_SLOTS.lock().entry(id).or_default().message = cb;
        return install_track_callbacks(id);
    }
    if get_ws(id).is_some() {
        WS_SLOTS.lock().entry(id).or_default().message = cb;
        return install_ws_callbacks(id);
    }
    if get_dc(id).is_none() {
        return RTC_ERR_INVALID;
    }
    DC_SLOTS.lock().entry(id).or_default().message = cb;
    install_dc_callbacks(id)
}

/// `rtcSendMessage`. `size >= 0` sends binary; `size < 0` sends the
/// NUL-terminated string at `data` (matching rtc.h).
///
/// # Safety
/// `data` must point to at least `size` bytes (binary) or a NUL-terminated
/// string (text), unless `size == 0`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSendMessage(id: c_int, data: *const c_char, size: c_int) -> c_int {
    guard(|| {
        // For a Track handle, `data` is a pre-formed RTP/RTCP packet (binary).
        if let Some(tr) = get_tr(id) {
            if data.is_null() && size != 0 {
                return RTC_ERR_INVALID;
            }
            let bytes: &[u8] = if size <= 0 || data.is_null() {
                &[]
            } else {
                // SAFETY: caller guarantees `data` has `size` bytes.
                unsafe { std::slice::from_raw_parts(data as *const u8, size as usize) }
            };
            return match tr.send_rtp(bytes) {
                Ok(_) => RTC_ERR_SUCCESS,
                Err(_) => RTC_ERR_FAILURE,
            };
        }
        // WebSocket: `size >= 0` is binary; `size < 0` is a NUL-terminated text
        // string (rtc.h's shared send convention).
        if let Some(ws) = get_ws(id) {
            if data.is_null() && size != 0 {
                return RTC_ERR_INVALID;
            }
            let res = if size >= 0 {
                let bytes: &[u8] = if size == 0 || data.is_null() {
                    &[]
                } else {
                    // SAFETY: caller guarantees `data` has `size` bytes.
                    unsafe { std::slice::from_raw_parts(data as *const u8, size as usize) }
                };
                ws.send_binary(bytes)
            } else {
                let s = match unsafe { cstr_opt(data) } {
                    Some(Some(s)) => s,
                    _ => return RTC_ERR_INVALID,
                };
                ws.send_text(s.as_bytes())
            };
            return match res {
                Ok(_) => RTC_ERR_SUCCESS,
                Err(_) => RTC_ERR_FAILURE,
            };
        }
        let dc = match get_dc(id) {
            Some(d) => d,
            None => return RTC_ERR_INVALID,
        };
        if data.is_null() && size != 0 {
            return RTC_ERR_INVALID;
        }
        let res = if size >= 0 {
            let bytes: &[u8] = if size == 0 || data.is_null() {
                &[]
            } else {
                // SAFETY: caller guarantees `data` has `size` bytes.
                unsafe { std::slice::from_raw_parts(data as *const u8, size as usize) }
            };
            dc.send_binary(bytes)
        } else {
            // Negative size => NUL-terminated text string.
            let s = match unsafe { cstr_opt(data) } {
                Some(Some(s)) => s,
                _ => return RTC_ERR_INVALID,
            };
            dc.send_text(s)
        };
        match res {
            Ok(_) => RTC_ERR_SUCCESS,
            Err(_) => RTC_ERR_FAILURE,
        }
    })
}

/// `rtcClose` (generic channel close — DataChannel or Track).
#[unsafe(no_mangle)]
pub extern "C" fn rtcClose(id: c_int) -> c_int {
    guard(|| {
        if let Some(tr) = get_tr(id) {
            tr.close();
            return RTC_ERR_SUCCESS;
        }
        if let Some(ws) = get_ws(id) {
            ws.close();
            return RTC_ERR_SUCCESS;
        }
        match get_dc(id) {
            Some(d) => {
                d.close();
                RTC_ERR_SUCCESS
            }
            None => RTC_ERR_INVALID,
        }
    })
}

/// `rtcDelete` (generic channel delete — DataChannel or Track).
#[unsafe(no_mangle)]
pub extern "C" fn rtcDelete(id: c_int) -> c_int {
    if get_tr(id).is_some() {
        return rtcDeleteTrack(id);
    }
    if get_ws(id).is_some() {
        return rtcDeleteWebSocket(id);
    }
    if get_ws_server(id).is_some() {
        return rtcDeleteWebSocketServer(id);
    }
    rtcDeleteDataChannel(id)
}

/// `rtcIsOpen`. DataChannel or Track handle.
#[unsafe(no_mangle)]
pub extern "C" fn rtcIsOpen(id: c_int) -> bool {
    guard_bool(|| {
        if let Some(tr) = get_tr(id) {
            return tr.is_open();
        }
        if let Some(ws) = get_ws(id) {
            return ws.is_open();
        }
        get_dc(id).map(|d| d.is_open()).unwrap_or(false)
    })
}

/// `rtcIsClosed`. Reports the channel's actual closed state — distinct from
/// "not open", since a still-connecting channel is neither. An unknown handle
/// reports `false`: upstream wraps `getChannel(id)->isClosed()` in `wrap(...)`,
/// which catches the not-found exception and yields a negative error, so
/// `rtcIsClosed` returns false for an unknown id (capi.cpp:820).
#[unsafe(no_mangle)]
pub extern "C" fn rtcIsClosed(id: c_int) -> bool {
    guard_bool(|| {
        if let Some(tr) = get_tr(id) {
            return tr.is_closed();
        }
        if let Some(ws) = get_ws(id) {
            return ws.is_closed();
        }
        match get_dc(id) {
            Some(d) => d.is_closed(),
            None => false,
        }
    })
}

/// `rtcMaxMessageSize`. The largest message that may be sent on this channel:
/// `DataChannel::maxMessageSize()` defers to the owning peer's
/// `remoteMaxMessageSize()` (min of the remote-advertised and local maxima),
/// falling back to the 64 KiB remote default when the channel has no resolvable
/// owner yet. Saturates to `c_int::MAX` for an unbounded remote limit.
#[unsafe(no_mangle)]
pub extern "C" fn rtcMaxMessageSize(id: c_int) -> c_int {
    guard(|| {
        if get_dc(id).is_none() {
            return RTC_ERR_INVALID;
        }
        let size = match DC_OWNERS.lock().get(&id).copied().and_then(get_pc) {
            Some(pc) => pc.remote_max_message_size(),
            None => 65536, // DEFAULT_REMOTE_MAX_MESSAGE_SIZE
        };
        size.min(c_int::MAX as usize) as c_int
    })
}

/// `rtcGetBufferedAmount`. Bytes queued for sending but not yet accepted by
/// the SCTP transport (waiting behind usrsctp backpressure).
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetBufferedAmount(id: c_int) -> c_int {
    guard(|| match get_dc(id) {
        Some(dc) => dc.buffered_amount().min(c_int::MAX as usize) as c_int,
        None => RTC_ERR_INVALID,
    })
}

/// `rtcSetBufferedAmountLowThreshold`. Sets the low-water threshold at which
/// the buffered-amount-low callback fires (default 0). A negative value is
/// clamped to 0.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetBufferedAmountLowThreshold(id: c_int, amount: c_int) -> c_int {
    match get_dc(id) {
        Some(dc) => {
            dc.set_buffered_amount_low_threshold(amount.max(0) as usize);
            RTC_ERR_SUCCESS
        }
        None => RTC_ERR_INVALID,
    }
}

/// `rtcSetBufferedAmountLowCallback`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetBufferedAmountLowCallback(
    id: c_int,
    cb: Option<RtcBufferedAmountLowCallbackFunc>,
) -> c_int {
    if get_dc(id).is_none() {
        return RTC_ERR_INVALID;
    }
    DC_SLOTS.lock().entry(id).or_default().buffered_low = cb;
    install_dc_callbacks(id)
}

/// `rtcGetAvailableAmount` — total bytes of inbound messages waiting in the
/// pull-API receive queue (i.e. messages that arrived while no `rtcMessageCallback`
/// was set). Zero when a handler is attached, since those are dispatched live.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetAvailableAmount(id: c_int) -> c_int {
    guard(|| {
        if get_dc(id).is_none() {
            return RTC_ERR_INVALID;
        }
        let total: usize = DC_RECV
            .lock()
            .get(&id)
            .map(|q| q.iter().map(|(d, _)| d.len()).sum())
            .unwrap_or(0);
        total as c_int
    })
}

/// `rtcSetAvailableCallback`. Fires when the pull-API receive queue (the buffer
/// used while no `rtcMessageCallback` is set) transitions empty→non-empty,
/// porting upstream's `triggerAvailable(count == 1)`. Edge-triggered: it
/// re-arms after the queue is drained via `rtcReceiveMessage` and the next
/// message arrives. If the edge already happened before this callback was
/// registered, it is replayed once on installation (the replay half of
/// upstream's `synchronized_stored_callback`). Pass `NULL` to clear. No-op for
/// channels with a live message handler, where inbound data is dispatched
/// immediately rather than queued.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetAvailableCallback(
    id: c_int,
    cb: Option<RtcAvailableCallbackFunc>,
) -> c_int {
    if get_dc(id).is_none() {
        return RTC_ERR_INVALID;
    }
    DC_SLOTS.lock().entry(id).or_default().available = cb;
    install_dc_callbacks(id)
}

/// `rtcReceiveMessage` — dequeue the next inbound message from the pull-API
/// receive queue. Faithful port of upstream's `rtcReceiveMessage` (capi.cpp):
///
/// * `*size` carries the buffer capacity on input (upstream takes its abs).
/// * With `buffer == NULL` the front message is *peeked*: `*size` is set to its
///   size (negative `-(len+1)` for text, positive `len` for binary) and the
///   message is left queued. Returns `RTC_ERR_SUCCESS`.
/// * With a real `buffer` too small to hold the message, `*size` is set to the
///   required size (same sign rule) and `RTC_ERR_TOO_SMALL` is returned without
///   dequeuing.
/// * Otherwise the message is copied out (text gets a trailing NUL), `*size` is
///   set as above, the message is dequeued, and `RTC_ERR_SUCCESS` is returned.
/// * An empty queue yields `RTC_ERR_NOT_AVAIL`.
///
/// # Safety
/// `size` must be non-null; `buffer`, if non-null, must point to at least
/// `abs(*size)` bytes.
#[unsafe(no_mangle)]
pub extern "C" fn rtcReceiveMessage(id: c_int, buffer: *mut c_char, size: *mut c_int) -> c_int {
    guard(|| {
        if get_dc(id).is_none() {
            return RTC_ERR_INVALID;
        }
        if size.is_null() {
            return RTC_ERR_INVALID;
        }
        // Input capacity (upstream: `*size = std::abs(*size)`).
        let cap = unsafe { (*size).unsigned_abs() } as usize;

        let mut guard_q = DC_RECV.lock();
        let queue = match guard_q.get_mut(&id) {
            Some(q) if !q.is_empty() => q,
            _ => return RTC_ERR_NOT_AVAIL,
        };

        // Inspect the front message without removing it yet.
        let front = queue.front().expect("queue non-empty checked above");
        let data = &front.0;
        let binary = front.1;
        let msg_len = data.len();

        // Required size and the value to report in `*size`, with rtc.h's sign
        // rule: binary is positive `len`; text is negative `-(len + 1)` (the
        // magnitude counts the NUL terminator).
        let (needed, report): (usize, c_int) = if binary {
            (msg_len, msg_len as c_int)
        } else {
            (msg_len + 1, -((msg_len + 1) as c_int))
        };

        if buffer.is_null() {
            // Peek: report size, leave the message queued.
            unsafe { *size = report };
            return RTC_ERR_SUCCESS;
        }
        if cap < needed {
            // Caller's buffer is too small: report the required size, keep it.
            unsafe { *size = report };
            return RTC_ERR_TOO_SMALL;
        }
        // Copy out, NUL-terminating text.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr() as *const c_char, buffer, msg_len);
            if !binary {
                *buffer.add(msg_len) = 0;
            }
            *size = report;
        }
        queue.pop_front();
        RTC_ERR_SUCCESS
    })
}

// ===========================================================================
// Track + media handlers
// ===========================================================================
//
// Tracks are now registry-backed (`RtcObject::Tr`) and wired to the runtime's
// `PeerConnection::add_track` / `on_track`. The media-handler *chain* functions
// (RTCP receiving session, SR reporter, NACK responder, PLI/REMB/pacing) are
// backed by the runtime `Track`'s `MediaHandlerChain` (#28): each appends the
// corresponding handler, after which inbound RTP routes through the chain's
// incoming path and outbound through its outgoing path. `rtcRequestBitrate`
// still reports `RTC_ERR_NOT_AVAIL` (no standalone REMB sender on the Track).
// The handle plumbing, callbacks, add/delete, accessors, keyframe and
// transform helpers are fully implemented.

/// Per-handle storage for the track-level callbacks so we can rebuild the
/// TrackCallbacks set on every setter call (mirrors [`DcCallbackSlots`]).
#[derive(Default, Clone)]
struct TrackCallbackSlots {
    open: Option<RtcOpenCallbackFunc>,
    closed: Option<RtcClosedCallbackFunc>,
    error: Option<RtcErrorCallbackFunc>,
    message: Option<RtcMessageCallbackFunc>,
}

// SAFETY: bare `extern "C" fn` pointers are Send/Sync (code addresses).
unsafe impl Send for TrackCallbackSlots {}
unsafe impl Sync for TrackCallbackSlots {}

static TRACK_SLOTS: Lazy<Mutex<HashMap<c_int, TrackCallbackSlots>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Map a runtime [`crate::Direction`] to the C `rtcDirection` enum value.
fn direction_to_c(d: crate::Direction) -> c_int {
    match d {
        crate::Direction::Unknown => 0,  // RTC_DIRECTION_UNKNOWN
        crate::Direction::SendOnly => 1, // RTC_DIRECTION_SENDONLY
        crate::Direction::RecvOnly => 2, // RTC_DIRECTION_RECVONLY
        crate::Direction::SendRecv => 3, // RTC_DIRECTION_SENDRECV
        crate::Direction::Inactive => 4, // RTC_DIRECTION_INACTIVE
    }
}

/// Map a C `rtcDirection` to the runtime [`crate::Direction`]. Unknown (0) and
/// any out-of-range value default to `SendRecv`.
fn direction_from_c(d: c_int) -> crate::Direction {
    match d {
        1 => crate::Direction::SendOnly,
        2 => crate::Direction::RecvOnly,
        4 => crate::Direction::Inactive,
        _ => crate::Direction::SendRecv,
    }
}

/// Map a C `rtcCodec` to the runtime [`crate::Codec`]. Returns `None` for codecs
/// the runtime does not model.
fn codec_from_c(c: c_int) -> Option<crate::Codec> {
    Some(match c {
        0 => crate::Codec::H264,   // RTC_CODEC_H264
        1 => crate::Codec::Vp8,    // RTC_CODEC_VP8
        2 => crate::Codec::Vp9,    // RTC_CODEC_VP9
        3 => crate::Codec::H265,   // RTC_CODEC_H265
        4 => crate::Codec::Av1,    // RTC_CODEC_AV1
        128 => crate::Codec::Opus, // RTC_CODEC_OPUS
        _ => return None,
    })
}

/// Map an SDP rtpmap encoding name (e.g. `"H264"`, `"opus"`) to a runtime codec.
fn codec_from_rtpmap_name(name: &str) -> Option<crate::Codec> {
    match name.to_ascii_uppercase().as_str() {
        "H264" => Some(crate::Codec::H264),
        "H265" => Some(crate::Codec::H265),
        "VP8" => Some(crate::Codec::Vp8),
        "VP9" => Some(crate::Codec::Vp9),
        "AV1" => Some(crate::Codec::Av1),
        "OPUS" => Some(crate::Codec::Opus),
        _ => None,
    }
}

/// Rebuild + install the TrackCallbacks set for a track handle from its slots.
fn install_track_callbacks(id: c_int) -> c_int {
    guard(|| {
        let tr = match get_tr(id) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        let slots = TRACK_SLOTS.lock().get(&id).cloned().unwrap_or_default();
        let mut cbs = crate::TrackCallbacks::default();

        if let Some(cb) = slots.open {
            cbs.on_open = Arc::new(move || {
                let ptr = user_pointer(id);
                dispatch(move || cb(id, ptr));
            });
        }
        if let Some(cb) = slots.closed {
            cbs.on_closed = Arc::new(move || {
                let ptr = user_pointer(id);
                dispatch(move || cb(id, ptr));
            });
        }
        if let Some(cb) = slots.message {
            // Track inbound bytes are an RTP/RTCP packet — always binary.
            cbs.on_message = Arc::new(move |data: &[u8]| {
                let ptr = user_pointer(id);
                let len = data.len() as c_int;
                let p = data.as_ptr() as *const c_char;
                dispatch(move || cb(id, p, len, ptr));
            });
        }
        // `error` is stored for ABI completeness; the runtime Track has no
        // error hook so it never fires.

        tr.set_callbacks(cbs);
        RTC_ERR_SUCCESS
    })
}

/// `rtcSetTrackCallback` — install the PeerConnection-level incoming-track
/// callback. Backed by the runtime's [`PeerConnectionCallbacks::on_track`].
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetTrackCallback(pc: c_int, cb: Option<RtcTrackCallbackFunc>) -> c_int {
    if get_pc(pc).is_none() {
        return RTC_ERR_INVALID;
    }
    PC_SLOTS.lock().entry(pc).or_default().track = cb;
    install_pc_callbacks(pc)
}

/// `rtcAddTrack` — add a local track described by an SDP media section. We parse
/// the media line (kind, mid, direction, first rtpmap → codec + payload type)
/// and build a runtime [`crate::TrackInit`]. Returns the new track handle.
///
/// # Safety
/// `media_description_sdp` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub extern "C" fn rtcAddTrack(pc: c_int, media_description_sdp: *const c_char) -> c_int {
    guard(|| {
        let pc_obj = match get_pc(pc) {
            Some(p) => p,
            None => return RTC_ERR_INVALID,
        };
        let sdp = match unsafe { cstr_opt(media_description_sdp) } {
            Some(Some(s)) => s,
            _ => return RTC_ERR_INVALID,
        };
        let init = match track_init_from_sdp(sdp) {
            Some(i) => i,
            None => return RTC_ERR_INVALID,
        };
        let track = pc_obj.add_track(init);
        let id = emplace(RtcObject::Tr(track));
        TRACK_OWNERS.lock().insert(id, pc);
        let ptr = user_pointer(pc);
        rtcSetUserPointer(id, ptr);
        // NB: unlike createDataChannel, upstream's addTrack does NOT trigger
        // auto-negotiation — it only creates the track object. The application
        // drives renegotiation explicitly via rtcSetLocalDescription. (Faithful
        // to peerconnection.cpp: addTrack omits the setLocalDescription path
        // that createDataChannel runs.)
        id
    })
}

/// Parse a single SDP media section into a [`crate::TrackInit`]. Extracts the
/// media kind/mid/direction and the first `a=rtpmap:` line for codec + payload
/// type; reads `a=ssrc:` if present (else 0).
fn track_init_from_sdp(sdp: &str) -> Option<crate::TrackInit> {
    let mut kind = "";
    let mut mid = String::new();
    let mut direction = crate::Direction::SendRecv;
    let mut payload_type: u8 = 0;
    let mut codec: Option<crate::Codec> = None;
    let mut ssrc: u32 = 0;

    for line in sdp.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("m=") {
            // m=<kind> <port> <proto> <fmt...>
            kind = rest.split_whitespace().next().unwrap_or("");
        } else if kind.is_empty() && !line.is_empty() && !line.starts_with("a=") {
            // Upstream `rtcAddTrack` passes the m-line content WITHOUT the "m="
            // prefix (e.g. "video 9 UDP/TLS/RTP/SAVPF"); treat the first such
            // line as the media line.
            let first = line.split_whitespace().next().unwrap_or("");
            if first == "audio" || first == "video" || first == "application" {
                kind = first;
            }
        } else if let Some(v) = line.strip_prefix("a=mid:") {
            mid = v.trim().to_string();
        } else if line == "a=sendonly" {
            direction = crate::Direction::SendOnly;
        } else if line == "a=recvonly" {
            direction = crate::Direction::RecvOnly;
        } else if line == "a=sendrecv" {
            direction = crate::Direction::SendRecv;
        } else if line == "a=inactive" {
            direction = crate::Direction::Inactive;
        } else if let Some(v) = line.strip_prefix("a=rtpmap:") {
            // <pt> <name>/<clock>[/<params>]
            if codec.is_none() {
                let mut parts = v.splitn(2, ' ');
                if let (Some(pt_s), Some(spec)) = (parts.next(), parts.next()) {
                    if let Ok(pt) = pt_s.trim().parse::<u8>() {
                        let name = spec.split('/').next().unwrap_or("");
                        if let Some(c) = codec_from_rtpmap_name(name) {
                            payload_type = pt;
                            codec = Some(c);
                        }
                    }
                }
            }
        } else if let Some(v) = line.strip_prefix("a=ssrc:") {
            if ssrc == 0 {
                if let Some(first) = v.split_whitespace().next() {
                    ssrc = first.parse::<u32>().unwrap_or(0);
                }
            }
        }
    }

    if kind != "audio" && kind != "video" {
        return None;
    }
    let codec = codec.unwrap_or(if kind == "audio" {
        crate::Codec::Opus
    } else {
        crate::Codec::H264
    });
    if mid.is_empty() {
        mid = kind.to_string();
    }
    Some(crate::TrackInit::new(
        direction,
        codec,
        payload_type,
        ssrc,
        mid,
    ))
}

/// `rtcAddTrackEx` — add a local track from a structured `rtcTrackInit`.
///
/// # Safety
/// `init`, if non-null, must point to a valid `rtcTrackInit` whose string
/// fields are NUL-terminated C strings or NULL.
#[unsafe(no_mangle)]
pub extern "C" fn rtcAddTrackEx(pc: c_int, init: *const RtcTrackInit) -> c_int {
    guard(|| {
        let pc_obj = match get_pc(pc) {
            Some(p) => p,
            None => return RTC_ERR_INVALID,
        };
        if init.is_null() {
            return RTC_ERR_INVALID;
        }
        // SAFETY: checked non-null; caller guarantees validity.
        let i = unsafe { &*init };
        let codec = match codec_from_c(i.codec) {
            Some(c) => c,
            None => return RTC_ERR_INVALID,
        };
        let mid = match unsafe { cstr_opt(i.mid) } {
            Some(Some(s)) => s.to_string(),
            Some(None) => codec.media_kind().to_string(),
            None => return RTC_ERR_INVALID,
        };
        let pt = if i.payloadType < 0 || i.payloadType > 127 {
            // Pick a sane default payload type per codec kind.
            if codec.is_video() { 96 } else { 111 }
        } else {
            i.payloadType as u8
        };

        let mut track_init =
            crate::TrackInit::new(direction_from_c(i.direction), codec, pt, i.ssrc, mid);
        // Optional CNAME / msid / track id.
        if let Some(Some(s)) = unsafe { cstr_opt(i.name) } {
            track_init.name = Some(s.to_string());
        }
        if let Some(Some(s)) = unsafe { cstr_opt(i.msid) } {
            track_init.msid = Some(s.to_string());
        }
        if let Some(Some(s)) = unsafe { cstr_opt(i.trackId) } {
            track_init.track_id = Some(s.to_string());
        }

        let track = pc_obj.add_track(track_init);
        let id = emplace(RtcObject::Tr(track));
        TRACK_OWNERS.lock().insert(id, pc);
        let ptr = user_pointer(pc);
        rtcSetUserPointer(id, ptr);
        // See rtcAddTrack: addTrack does not auto-negotiate upstream.
        id
    })
}

/// `rtcDeleteTrack` — close + remove a track from the registry.
#[unsafe(no_mangle)]
pub extern "C" fn rtcDeleteTrack(tr: c_int) -> c_int {
    guard(|| {
        let obj = REGISTRY.lock().remove(&tr);
        match obj {
            Some(RtcObject::Tr(t)) => {
                t.close();
                USER_POINTERS.lock().remove(&tr);
                TRACK_SLOTS.lock().remove(&tr);
                TRACK_OWNERS.lock().remove(&tr);
                RTC_ERR_SUCCESS
            }
            Some(other) => {
                REGISTRY.lock().insert(tr, other);
                RTC_ERR_INVALID
            }
            None => RTC_ERR_INVALID,
        }
    })
}

/// `rtcGetTrackDescription` — copy the track's SDP media section into `buffer`.
///
/// # Safety
/// `buffer`, if non-null, must point to at least `size` bytes.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetTrackDescription(tr: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    guard(|| match get_tr(tr) {
        Some(t) => copy_string(&t.description_sdp(), buffer, size),
        None => RTC_ERR_INVALID,
    })
}

/// `rtcGetTrackMid` — copy the track's `mid` into `buffer`.
///
/// # Safety
/// `buffer`, if non-null, must point to at least `size` bytes.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetTrackMid(tr: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    guard(|| match get_tr(tr) {
        Some(t) => copy_string(&t.mid(), buffer, size),
        None => RTC_ERR_INVALID,
    })
}

/// `rtcGetTrackDirection` — write the track's direction as a `rtcDirection`.
///
/// # Safety
/// `direction`, if non-null, must point to a valid `int`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetTrackDirection(tr: c_int, direction: *mut c_int) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        if direction.is_null() {
            return RTC_ERR_INVALID;
        }
        // SAFETY: checked non-null.
        unsafe { *direction = direction_to_c(t.direction()) };
        RTC_ERR_SUCCESS
    })
}

/// `rtcRequestKeyframe` — send an RTCP PLI for the track's media SSRC.
#[unsafe(no_mangle)]
pub extern "C" fn rtcRequestKeyframe(tr: c_int) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        match t.request_keyframe() {
            Ok(_) => RTC_ERR_SUCCESS,
            Err(_) => RTC_ERR_FAILURE,
        }
    })
}

/// `rtcRequestBitrate` — request a target bitrate from the remote by driving the
/// track's runtime media-handler chain (REMB). A chained
/// [`crate::RtcpReceivingSession`] queues a REMB packet that is flushed back to
/// the peer; with no such handler the request succeeds as a no-op (mirroring the
/// C++ default `requestBitrate`). Backed by the runtime `Track` chain.
#[unsafe(no_mangle)]
pub extern "C" fn rtcRequestBitrate(tr: c_int, bitrate: c_uint) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        match t.request_bitrate(bitrate) {
            Ok(_) => RTC_ERR_SUCCESS,
            Err(_) => RTC_ERR_FAILURE,
        }
    })
}

// ===========================================================================
// Codec RTP packetizers (rtcSet{H264,H265,AV1,VP8}Packetizer)
// ===========================================================================

/// Build an [`RtpPacketizationConfig`] from a borrowed [`RtcPacketizerInit`].
/// Mirrors upstream `createRtpPacketizationConfig`: a NULL or non-UTF-8 `cname`
/// is rejected (`None` → `RTC_ERR_INVALID`). A zero `clockRate` is also rejected
/// (the Rust config requires a positive clock rate; upstream would later divide
/// by it). The playout-delay/color fields are intentionally ignored — those
/// RTP header-extension writers are unported.
fn rtp_config_from_init(init: &RtcPacketizerInit) -> Option<RtpPacketizationConfig> {
    // SAFETY: per the C-API contract `cname`, if non-null, is a valid C string.
    let cname = match unsafe { cstr_opt(init.cname) } {
        Some(Some(s)) => s,
        _ => return None, // NULL or invalid-UTF-8 cname
    };
    if init.clockRate == 0 {
        return None;
    }
    Some(RtpPacketizationConfig::new(
        init.ssrc,
        cname,
        init.payloadType,
        init.clockRate,
        init.sequenceNumber,
        init.timestamp,
    ))
}

/// Map a C `rtcNalUnitSeparator` value to the Rust [`NalSeparator`]. Unknown
/// values fall back to `Length` (the `0`/default upstream separator).
fn nal_separator_from_c(v: c_int) -> NalSeparator {
    match v {
        RTC_NAL_SEPARATOR_LONG_START_SEQUENCE => NalSeparator::LongStartSequence,
        RTC_NAL_SEPARATOR_SHORT_START_SEQUENCE => NalSeparator::ShortStartSequence,
        RTC_NAL_SEPARATOR_START_SEQUENCE => NalSeparator::StartSequence,
        _ => NalSeparator::Length,
    }
}

/// A `maxFragmentSize` of `0` selects the libdatachannel default (1220).
fn max_fragment_size(v: u16) -> usize {
    if v == 0 {
        DEFAULT_MAX_FRAGMENT_SIZE
    } else {
        v as usize
    }
}

/// `rtcSetH264Packetizer` — install an H.264 (RFC 6184) RTP packetizer on the
/// track. Mirrors upstream: `createRtpPacketizationConfig(init)` →
/// `H264RtpPacketizer(nalSeparator, config, maxFragmentSize)` → installed as the
/// outbound packetizer (the upstream chain head). NULL `init`/`cname`, a zero
/// `clockRate`, or an unknown track is `RTC_ERR_INVALID`.
///
/// # Safety
/// `init`, if non-null, must point to a valid [`RtcPacketizerInit`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtcSetH264Packetizer(tr: c_int, init: *const RtcPacketizerInit) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        if init.is_null() {
            return RTC_ERR_INVALID;
        }
        // SAFETY: checked non-null; caller guarantees a valid RtcPacketizerInit.
        let init = unsafe { &*init };
        let config = match rtp_config_from_init(init) {
            Some(c) => c,
            None => return RTC_ERR_INVALID,
        };
        let packetizer = H264RtpPacketizer::new(
            nal_separator_from_c(init.nalSeparator),
            config,
            max_fragment_size(init.maxFragmentSize),
        );
        t.set_codec_packetizer(CodecPacketizer::H264(packetizer));
        RTC_ERR_SUCCESS
    })
}

/// `rtcSetH265Packetizer` — install an H.265 (RFC 7798) RTP packetizer. Same
/// shape as [`rtcSetH264Packetizer`].
///
/// # Safety
/// `init`, if non-null, must point to a valid [`RtcPacketizerInit`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtcSetH265Packetizer(tr: c_int, init: *const RtcPacketizerInit) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        if init.is_null() {
            return RTC_ERR_INVALID;
        }
        // SAFETY: checked non-null; caller guarantees a valid RtcPacketizerInit.
        let init = unsafe { &*init };
        let config = match rtp_config_from_init(init) {
            Some(c) => c,
            None => return RTC_ERR_INVALID,
        };
        let packetizer = H265RtpPacketizer::new(
            nal_separator_from_c(init.nalSeparator),
            config,
            max_fragment_size(init.maxFragmentSize),
        );
        t.set_codec_packetizer(CodecPacketizer::H265(packetizer));
        RTC_ERR_SUCCESS
    })
}

/// `rtcSetAV1Packetizer` — install an AV1 RTP packetizer. `obuPacketization`
/// selects OBU vs temporal-unit packetization (default OBU, mirroring upstream's
/// `== RTC_OBU_PACKETIZED_TEMPORAL_UNIT ? TemporalUnit : Obu`).
///
/// # Safety
/// `init`, if non-null, must point to a valid [`RtcPacketizerInit`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtcSetAV1Packetizer(tr: c_int, init: *const RtcPacketizerInit) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        if init.is_null() {
            return RTC_ERR_INVALID;
        }
        // SAFETY: checked non-null; caller guarantees a valid RtcPacketizerInit.
        let init = unsafe { &*init };
        let config = match rtp_config_from_init(init) {
            Some(c) => c,
            None => return RTC_ERR_INVALID,
        };
        let packetization = if init.obuPacketization == RTC_OBU_PACKETIZED_TEMPORAL_UNIT {
            Av1Packetization::TemporalUnit
        } else {
            Av1Packetization::Obu
        };
        let packetizer = Av1RtpPacketizer::new(
            packetization,
            config,
            max_fragment_size(init.maxFragmentSize),
        );
        t.set_codec_packetizer(CodecPacketizer::Av1(packetizer));
        RTC_ERR_SUCCESS
    })
}

/// `rtcSetVP8Packetizer` — install a VP8 (RFC 7741) RTP packetizer. VP8 takes
/// only the config and `maxFragmentSize`.
///
/// # Safety
/// `init`, if non-null, must point to a valid [`RtcPacketizerInit`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtcSetVP8Packetizer(tr: c_int, init: *const RtcPacketizerInit) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        if init.is_null() {
            return RTC_ERR_INVALID;
        }
        // SAFETY: checked non-null; caller guarantees a valid RtcPacketizerInit.
        let init = unsafe { &*init };
        let config = match rtp_config_from_init(init) {
            Some(c) => c,
            None => return RTC_ERR_INVALID,
        };
        let packetizer = Vp8RtpPacketizer::new(config, max_fragment_size(init.maxFragmentSize));
        t.set_codec_packetizer(CodecPacketizer::Vp8(packetizer));
        RTC_ERR_SUCCESS
    })
}

/// `rtcChainRtcpReceivingSession` — append an [`crate::RtcpReceivingSession`] to
/// the track's runtime media-handler chain. The session learns the inbound SSRC
/// and replies to SR with RR (and REMB once a bitrate is requested), and emits
/// PLI on keyframe requests. Backed by the runtime `Track` chain.
#[unsafe(no_mangle)]
pub extern "C" fn rtcChainRtcpReceivingSession(tr: c_int) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        t.chain_media_handler(Box::new(crate::RtcpReceivingSession::new()));
        RTC_ERR_SUCCESS
    })
}

/// `rtcChainRtcpSrReporter` — append an [`crate::RtcpSrReporter`] to the track's
/// chain, generating outgoing Sender Reports from the outbound RTP stream for
/// the track's media SSRC. Uses the C++ default 1 s report cadence.
#[unsafe(no_mangle)]
pub extern "C" fn rtcChainRtcpSrReporter(tr: c_int) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        let ssrc = t.media_ssrc();
        t.chain_media_handler(Box::new(crate::RtcpSrReporter::new(ssrc, 1000)));
        RTC_ERR_SUCCESS
    })
}

/// `rtcChainRtcpNackResponder` — append an [`crate::RtcpNackResponder`] buffering
/// up to `max_stored_packets` outbound RTP packets and retransmitting them on
/// incoming NACK. `0` selects the libdatachannel default (512).
#[unsafe(no_mangle)]
pub extern "C" fn rtcChainRtcpNackResponder(tr: c_int, max_stored_packets: c_uint) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        let max = if max_stored_packets == 0 {
            crate::RtcpNackResponder::DEFAULT_MAX_SIZE
        } else {
            max_stored_packets as usize
        };
        t.chain_media_handler(Box::new(crate::RtcpNackResponder::new(max)));
        RTC_ERR_SUCCESS
    })
}

/// `rtcChainPliHandler` — append a [`crate::PliHandler`] invoking the C callback
/// `cb(tr, ptr)` whenever an incoming PLI/FIR is observed.
#[unsafe(no_mangle)]
pub extern "C" fn rtcChainPliHandler(tr: c_int, cb: Option<RtcPliHandlerCallbackFunc>) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        let cb = match cb {
            Some(c) => c,
            None => return RTC_ERR_INVALID,
        };
        let handler = crate::PliHandler::new(move || {
            let ptr = user_pointer(tr);
            dispatch(move || cb(tr, ptr));
        });
        t.chain_media_handler(Box::new(handler));
        RTC_ERR_SUCCESS
    })
}

/// `rtcChainRembHandler` — append a [`crate::RembHandler`] invoking the C
/// callback `cb(tr, bitrate, ptr)` for each incoming REMB.
#[unsafe(no_mangle)]
pub extern "C" fn rtcChainRembHandler(tr: c_int, cb: Option<RtcRembHandlerCallbackFunc>) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        let cb = match cb {
            Some(c) => c,
            None => return RTC_ERR_INVALID,
        };
        let handler = crate::RembHandler::new(move |bitrate: u64| {
            let ptr = user_pointer(tr);
            let br = bitrate as c_uint;
            dispatch(move || cb(tr, br, ptr));
        });
        t.chain_media_handler(Box::new(handler));
        RTC_ERR_SUCCESS
    })
}

/// `rtcChainPacingHandler` — append a [`crate::PacingHandler`] pacing outbound
/// RTP to `bits_per_second` on a `send_interval_ms` cadence. The handler buffers
/// outbound packets; the Rust port releases them via its `tick` from the media
/// loop (see [`crate::PacingHandler`]).
#[unsafe(no_mangle)]
pub extern "C" fn rtcChainPacingHandler(
    tr: c_int,
    bits_per_second: c_double,
    send_interval_ms: c_int,
) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        let interval = if send_interval_ms <= 0 {
            1
        } else {
            send_interval_ms as u64
        };
        t.chain_media_handler(Box::new(crate::PacingHandler::new(
            bits_per_second,
            interval,
        )));
        RTC_ERR_SUCCESS
    })
}

/// `rtcTransformSecondsToTimestamp` — convert seconds to an RTP timestamp using
/// the track's clock rate.
///
/// # Safety
/// `timestamp`, if non-null, must point to a valid `uint32_t`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcTransformSecondsToTimestamp(
    id: c_int,
    seconds: c_double,
    timestamp: *mut u32,
) -> c_int {
    guard(|| {
        let t = match get_tr(id) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        if timestamp.is_null() {
            return RTC_ERR_INVALID;
        }
        let ts = (seconds * f64::from(t.clock_rate())).round() as i64 as u32;
        // SAFETY: checked non-null.
        unsafe { *timestamp = ts };
        RTC_ERR_SUCCESS
    })
}

/// `rtcTransformTimestampToSeconds` — convert an RTP timestamp to seconds using
/// the track's clock rate.
///
/// # Safety
/// `seconds`, if non-null, must point to a valid `double`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcTransformTimestampToSeconds(
    id: c_int,
    timestamp: u32,
    seconds: *mut c_double,
) -> c_int {
    guard(|| {
        let t = match get_tr(id) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        if seconds.is_null() {
            return RTC_ERR_INVALID;
        }
        let secs = f64::from(timestamp) / f64::from(t.clock_rate());
        // SAFETY: checked non-null.
        unsafe { *seconds = secs };
        RTC_ERR_SUCCESS
    })
}

/// `rtcGetCurrentTrackTimestamp` — read the active packetizer's current RTP
/// timestamp. Mirrors upstream `config->timestamp`; a null `timestamp` pointer
/// is tolerated (returns success without writing), matching the upstream guard.
///
/// # Safety
/// `timestamp`, if non-null, must point to a valid `uint32_t`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetCurrentTrackTimestamp(id: c_int, timestamp: *mut u32) -> c_int {
    guard(|| {
        let t = match get_tr(id) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        if !timestamp.is_null() {
            // SAFETY: checked non-null.
            unsafe { *timestamp = t.current_timestamp() };
        }
        RTC_ERR_SUCCESS
    })
}

/// `rtcSetTrackRtpTimestamp` — set the active packetizer's RTP timestamp used by
/// subsequent sends. Mirrors upstream `config->timestamp = timestamp`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetTrackRtpTimestamp(id: c_int, timestamp: u32) -> c_int {
    guard(|| {
        let t = match get_tr(id) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        t.set_rtp_timestamp(timestamp);
        RTC_ERR_SUCCESS
    })
}

/// `rtcGetLastTrackSenderReportTimestamp` — the RTP timestamp of the last RTCP
/// Sender Report emitted by a chained [`crate::RtcpSrReporter`]. Returns
/// `RTC_ERR_INVALID` when no SR reporter is in the track's media-handler chain
/// (upstream throws when the track has no registered reporter).
///
/// # Safety
/// `timestamp`, if non-null, must point to a valid `uint32_t`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetLastTrackSenderReportTimestamp(id: c_int, timestamp: *mut u32) -> c_int {
    guard(|| {
        let t = match get_tr(id) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        let ts = match t.last_sr_timestamp() {
            Some(ts) => ts,
            None => return RTC_ERR_INVALID,
        };
        if !timestamp.is_null() {
            // SAFETY: checked non-null.
            unsafe { *timestamp = ts };
        }
        RTC_ERR_SUCCESS
    })
}

/// `rtcGetTrackPayloadTypesForCodec` — fill `buffer` with the payload types in
/// the track's media description whose rtpmap encoding name matches `ccodec`
/// (case-insensitive). Follows the [`copy_and_return`] sizing convention: a null
/// `buffer` returns the count, a too-small `size` returns `RTC_ERR_TOO_SMALL`.
///
/// # Safety
/// `ccodec` must be a valid NUL-terminated C string; `buffer`, if non-null, must
/// point to at least `size` `int`s.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetTrackPayloadTypesForCodec(
    tr: c_int,
    ccodec: *const c_char,
    buffer: *mut c_int,
    size: c_int,
) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        let codec = match unsafe { cstr_opt(ccodec) } {
            Some(Some(s)) => s.to_ascii_lowercase(),
            _ => return RTC_ERR_INVALID,
        };
        let media = t.description();
        let pts: Vec<c_int> = media
            .rtp_maps()
            .iter()
            .filter(|m| m.format.eq_ignore_ascii_case(&codec))
            .map(|m| c_int::from(m.payload_type))
            .collect();
        // SAFETY: caller upholds the buffer/size contract.
        unsafe { copy_and_return(&pts, buffer, size) }
    })
}

/// `rtcGetSsrcsForTrack` — fill `buffer` with the SSRCs bound to the track's
/// media description, following the [`copy_and_return`] sizing convention.
///
/// # Safety
/// `buffer`, if non-null, must point to at least `count` `uint32_t`s.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetSsrcsForTrack(tr: c_int, buffer: *mut u32, count: c_int) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        let media = t.description();
        let ssrcs: Vec<u32> = media.ssrcs().iter().map(|s| s.ssrc).collect();
        // SAFETY: caller upholds the buffer/count contract.
        unsafe { copy_and_return(&ssrcs, buffer, count) }
    })
}

/// `rtcGetCNameForSsrc` — write the CNAME bound to `ssrc` in the track's media
/// description into `cname` (the [`copy_string`] convention). Returns `0` when
/// the SSRC has no CNAME, matching upstream.
///
/// # Safety
/// `cname`, if non-null, must point to at least `cname_size` bytes.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetCNameForSsrc(
    tr: c_int,
    ssrc: u32,
    cname: *mut c_char,
    cname_size: c_int,
) -> c_int {
    guard(|| {
        let t = match get_tr(tr) {
            Some(t) => t,
            None => return RTC_ERR_INVALID,
        };
        let media = t.description();
        match media
            .ssrcs()
            .iter()
            .find(|s| s.ssrc == ssrc)
            .and_then(|s| s.name.as_deref())
        {
            Some(name) => copy_string(name, cname, cname_size),
            None => 0,
        }
    })
}

/// `rtcSetNeedsToSendRtcpSr` — deprecated upstream no-op kept for ABI
/// compatibility; always returns success.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetNeedsToSendRtcpSr(_id: c_int) -> c_int {
    guard(|| RTC_ERR_SUCCESS)
}

// ===========================================================================
// SDP-string SSRC utilities (free functions — operate on an SDP string, not a
// live PeerConnection/Track handle). Mirror capi.cpp's rtcGetSsrcsForType /
// rtcSetSsrcForType, which build a throwaway `Description(sdp, "unspec")`,
// inspect/mutate the media section matching a media type, and (for the setter)
// re-serialize the SDP.
// ===========================================================================

/// Mirrors `rtcSsrcForTypeInit` (`rtc.h`): the SSRC plus optional cname / msid /
/// track-id to stamp onto a media section. Field order/types match exactly so a
/// C caller's struct is byte-compatible. The three string fields are optional
/// (`NULL` → unset).
#[repr(C)]
pub struct rtcSsrcForTypeInit {
    /// `uint32_t ssrc`
    pub ssrc: u32,
    /// `const char *name` — optional cname.
    pub name: *const c_char,
    /// `const char *msid` — optional.
    pub msid: *const c_char,
    /// `const char *trackId` — optional, track id used within the msid.
    pub trackId: *const c_char,
}

/// `rtcGetSsrcsForType` — parse `sdp`, find the first media section whose type
/// matches `mediaType` (case-insensitive), and write its SSRCs into `buffer`
/// following the [`copy_and_return`] sizing convention. Returns `0` when no
/// media of that type is present (matching upstream).
///
/// # Safety
/// `mediaType` / `sdp` must be valid NUL-terminated C strings; `buffer`, if
/// non-null, must point to at least `bufferSize` `uint32_t`s.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetSsrcsForType(
    mediaType: *const c_char,
    sdp: *const c_char,
    buffer: *mut u32,
    bufferSize: c_int,
) -> c_int {
    guard(|| {
        let mtype = match unsafe { cstr_opt(mediaType) } {
            Some(Some(s)) => s.to_ascii_lowercase(),
            _ => return RTC_ERR_INVALID,
        };
        let sdp = match unsafe { cstr_opt(sdp) } {
            Some(Some(s)) => s,
            _ => return RTC_ERR_INVALID,
        };
        let desc = match Description::parse(sdp) {
            Ok(d) => d,
            Err(_) => return RTC_ERR_FAILURE,
        };
        let ssrcs: Vec<u32> = match desc
            .media_sections()
            .iter()
            .find(|m| m.kind().eq_ignore_ascii_case(&mtype))
        {
            Some(m) => m.ssrcs().iter().map(|s| s.ssrc).collect(),
            None => return 0,
        };
        // SAFETY: caller upholds the buffer/size contract.
        unsafe { copy_and_return(&ssrcs, buffer, bufferSize) }
    })
}

/// `rtcSetSsrcForType` — parse `sdp`, append the SSRC binding described by
/// `init` to the first media section whose type matches `mediaType`
/// (case-insensitive, additive like `Description::Media::addSSRC`), re-serialize
/// the SDP, and write it into `buffer` (the [`copy_string`] convention). If no
/// media of that type is present the SDP is returned unchanged, matching
/// upstream.
///
/// # Safety
/// `mediaType` / `sdp` must be valid NUL-terminated C strings; `init` must be a
/// valid `rtcSsrcForTypeInit` (its string fields NUL-terminated or null);
/// `buffer`, if non-null, must point to at least `bufferSize` bytes.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetSsrcForType(
    mediaType: *const c_char,
    sdp: *const c_char,
    buffer: *mut c_char,
    bufferSize: c_int,
    init: *const rtcSsrcForTypeInit,
) -> c_int {
    guard(|| {
        let mtype = match unsafe { cstr_opt(mediaType) } {
            Some(Some(s)) => s.to_ascii_lowercase(),
            _ => return RTC_ERR_INVALID,
        };
        let sdp = match unsafe { cstr_opt(sdp) } {
            Some(Some(s)) => s,
            _ => return RTC_ERR_INVALID,
        };
        if init.is_null() {
            return RTC_ERR_INVALID;
        }
        // SAFETY: checked non-null; caller guarantees a valid struct.
        let init = unsafe { &*init };
        let name = match unsafe { cstr_opt(init.name) } {
            Some(v) => v.map(str::to_owned),
            None => return RTC_ERR_INVALID,
        };
        let msid = match unsafe { cstr_opt(init.msid) } {
            Some(v) => v.map(str::to_owned),
            None => return RTC_ERR_INVALID,
        };
        let track_id = match unsafe { cstr_opt(init.trackId) } {
            Some(v) => v.map(str::to_owned),
            None => return RTC_ERR_INVALID,
        };
        let mut desc = match Description::parse(sdp) {
            Ok(d) => d,
            Err(_) => return RTC_ERR_FAILURE,
        };
        if let Some(m) = desc
            .media_sections_mut()
            .iter_mut()
            .find(|m| m.kind().eq_ignore_ascii_case(&mtype))
        {
            m.add_ssrc(SsrcEntry {
                ssrc: init.ssrc,
                name,
                msid,
                track_id,
            });
        }
        copy_string(&desc.to_sdp(), buffer, bufferSize)
    })
}

// ===========================================================================
// Opaque message (rtcMessage* = void*). Mirrors capi.cpp's
// rtcCreateOpaqueMessage / rtcDeleteOpaqueMessage: a heap copy of caller bytes
// wrapped behind an opaque pointer. (The media-interceptor callback that would
// consume one is not wired in this port — see notes on rtcSetMediaInterceptor —
// so the only supported lifecycle is create → delete, which this pair owns
// leak-free.)
// ===========================================================================

/// `rtcCreateOpaqueMessage` — heap-copy `size` bytes from `data` and return an
/// opaque handle (`rtcMessage *`). Returns null on a null `data` or negative
/// `size`. Free it with [`rtcDeleteOpaqueMessage`].
///
/// # Safety
/// `data`, if non-null, must point to at least `size` readable bytes.
#[unsafe(no_mangle)]
pub extern "C" fn rtcCreateOpaqueMessage(data: *mut c_void, size: c_int) -> *mut c_void {
    if data.is_null() || size < 0 {
        return std::ptr::null_mut();
    }
    // SAFETY: caller guarantees `data` has at least `size` readable bytes.
    let bytes = unsafe { std::slice::from_raw_parts(data as *const u8, size as usize) }.to_vec();
    Box::into_raw(Box::new(bytes)) as *mut c_void
}

/// `rtcDeleteOpaqueMessage` — free a handle returned by
/// [`rtcCreateOpaqueMessage`]. A null pointer is a no-op.
///
/// # Safety
/// `msg` must be a pointer returned by [`rtcCreateOpaqueMessage`] and not freed
/// already.
#[unsafe(no_mangle)]
pub extern "C" fn rtcDeleteOpaqueMessage(msg: *mut c_void) {
    if msg.is_null() {
        return;
    }
    // SAFETY: `msg` was produced by rtcCreateOpaqueMessage as a Box<Vec<u8>>.
    drop(unsafe { Box::from_raw(msg as *mut Vec<u8>) });
}

// ===========================================================================
// WebSocket (client + server) — shares the generic-channel id space
// ===========================================================================

/// Open a WebSocket against `url` with `config`, register it in the handle
/// space, and install its callback plumbing. Returns the new handle, or a
/// negative error code. Shared by `rtcCreateWebSocket`/`rtcCreateWebSocketEx`.
fn open_and_register_ws(url: *const c_char, config: WebSocketConfig) -> c_int {
    let url = match unsafe { cstr_opt(url) } {
        Some(Some(s)) => s.to_owned(),
        _ => return RTC_ERR_INVALID,
    };
    let mut ws = WebSocket::new(config);
    if ws.open(&url).is_err() {
        return RTC_ERR_FAILURE;
    }
    let id = emplace(RtcObject::Ws(Arc::new(ws)));
    install_ws_callbacks(id);
    id
}

/// `rtcCreateWebSocket` — open a client WebSocket with default configuration.
#[unsafe(no_mangle)]
pub extern "C" fn rtcCreateWebSocket(url: *const c_char) -> c_int {
    guard(|| open_and_register_ws(url, WebSocketConfig::default()))
}

/// `rtcCreateWebSocketEx` — open a client WebSocket with explicit configuration.
///
/// # Safety
/// `config`, if non-null, must point to a valid `rtcWsConfiguration`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcCreateWebSocketEx(
    url: *const c_char,
    config: *const RtcWsConfiguration,
) -> c_int {
    guard(|| {
        let mut cfg = WebSocketConfig::default();
        if !config.is_null() {
            // SAFETY: caller guarantees a non-null `config` is valid.
            let c = unsafe { &*config };
            cfg.disable_tls_verification = c.disableTlsVerification;
            if c.maxMessageSize > 0 {
                cfg.max_message_size = Some(c.maxMessageSize as usize);
            }
            if c.maxOutstandingPings > 0 {
                cfg.max_outstanding_pings = Some(c.maxOutstandingPings as u32);
            }
            if !c.protocols.is_null() && c.protocolsCount > 0 {
                let mut protos = Vec::with_capacity(c.protocolsCount as usize);
                for i in 0..c.protocolsCount as isize {
                    // SAFETY: `protocols` points to `protocolsCount` C strings.
                    let p = unsafe { *c.protocols.offset(i) };
                    if let Some(Some(s)) = unsafe { cstr_opt(p) } {
                        protos.push(s.to_owned());
                    }
                }
                cfg.protocols = protos;
            }
        }
        open_and_register_ws(url, cfg)
    })
}

/// `rtcDeleteWebSocket` — close and unregister a client WebSocket handle.
#[unsafe(no_mangle)]
pub extern "C" fn rtcDeleteWebSocket(ws: c_int) -> c_int {
    guard(|| {
        let obj = REGISTRY.lock().remove(&ws);
        match obj {
            Some(RtcObject::Ws(w)) => {
                w.close();
                USER_POINTERS.lock().remove(&ws);
                WS_SLOTS.lock().remove(&ws);
                WS_RECV.lock().remove(&ws);
                WS_OPEN_FIRED.lock().remove(&ws);
                RTC_ERR_SUCCESS
            }
            Some(other) => {
                REGISTRY.lock().insert(ws, other);
                RTC_ERR_INVALID
            }
            None => RTC_ERR_INVALID,
        }
    })
}

/// `rtcGetWebSocketRemoteAddress` — peer address of an accepted socket.
/// `RTC_ERR_NOT_AVAIL` when no remote address is known (e.g. a client socket).
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetWebSocketRemoteAddress(
    ws: c_int,
    buffer: *mut c_char,
    size: c_int,
) -> c_int {
    guard(|| match get_ws(ws) {
        Some(w) => match w.remote_address() {
            Some(addr) => copy_string(addr, buffer, size),
            None => RTC_ERR_NOT_AVAIL,
        },
        None => RTC_ERR_INVALID,
    })
}

/// `rtcGetWebSocketPath` — request path of an accepted socket.
/// `RTC_ERR_NOT_AVAIL` when no path is known.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetWebSocketPath(ws: c_int, buffer: *mut c_char, size: c_int) -> c_int {
    guard(|| match get_ws(ws) {
        Some(w) => match w.path() {
            Some(path) => copy_string(path, buffer, size),
            None => RTC_ERR_NOT_AVAIL,
        },
        None => RTC_ERR_INVALID,
    })
}

/// `rtcCreateWebSocketServer` — start a listening WebSocket server. Each
/// accepted client is registered in the generic-channel id space and surfaced
/// to `cb`. When `enableTls` is set without cert/key files, a self-signed
/// certificate is generated, matching upstream.
///
/// # Safety
/// `config` must point to a valid `rtcWsServerConfiguration`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcCreateWebSocketServer(
    config: *const RtcWsServerConfiguration,
    cb: Option<RtcWebSocketClientCallbackFunc>,
) -> c_int {
    guard(|| {
        if config.is_null() {
            return RTC_ERR_INVALID;
        }
        let cb = match cb {
            Some(cb) => cb,
            None => return RTC_ERR_INVALID,
        };
        // SAFETY: caller guarantees `config` is valid.
        let c = unsafe { &*config };
        let mut scfg = WebSocketServerConfig {
            port: c.port,
            enable_tls: c.enableTls,
            ..Default::default()
        };
        if c.maxMessageSize > 0 {
            scfg.max_message_size = Some(c.maxMessageSize as usize);
        }
        if let Some(Some(s)) = unsafe { cstr_opt(c.bindAddress) } {
            scfg.bind_address = Some(s.to_owned());
        }
        if c.enableTls {
            let cert_file = unsafe { cstr_opt(c.certificatePemFile) };
            let key_file = unsafe { cstr_opt(c.keyPemFile) };
            match (cert_file, key_file) {
                // Both PEM file paths supplied: load them.
                (Some(Some(cf)), Some(Some(kf))) => {
                    let cert = match std::fs::read_to_string(cf) {
                        Ok(s) => s,
                        Err(_) => return RTC_ERR_INVALID,
                    };
                    let key = match std::fs::read_to_string(kf) {
                        Ok(s) => s,
                        Err(_) => return RTC_ERR_INVALID,
                    };
                    scfg.certificate_pem = Some(cert);
                    scfg.key_pem = Some(key);
                }
                // Otherwise autogenerate a self-signed certificate.
                _ => {
                    let cert = match Certificate::generate_default() {
                        Ok(c) => c,
                        Err(_) => return RTC_ERR_FAILURE,
                    };
                    let cert_pem = match cert
                        .x509()
                        .to_pem()
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                    {
                        Some(s) => s,
                        None => return RTC_ERR_FAILURE,
                    };
                    let key_pem = match cert
                        .pkey()
                        .private_key_to_pem_pkcs8()
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                    {
                        Some(s) => s,
                        None => return RTC_ERR_FAILURE,
                    };
                    scfg.certificate_pem = Some(cert_pem);
                    scfg.key_pem = Some(key_pem);
                }
            }
        }
        let server = match WebSocketServer::new(scfg) {
            Ok(s) => Arc::new(s),
            Err(_) => return RTC_ERR_FAILURE,
        };
        let server_id = emplace(RtcObject::WsServer(Arc::clone(&server)));
        server.set_on_client(move |ws| {
            let ws_id = emplace(RtcObject::Ws(Arc::new(ws)));
            install_ws_callbacks(ws_id);
            let ptr = user_pointer(server_id);
            dispatch(move || cb(server_id, ws_id, ptr));
        });
        server_id
    })
}

/// `rtcDeleteWebSocketServer` — stop and unregister a server handle.
#[unsafe(no_mangle)]
pub extern "C" fn rtcDeleteWebSocketServer(wsserver: c_int) -> c_int {
    guard(|| {
        let obj = REGISTRY.lock().remove(&wsserver);
        match obj {
            Some(RtcObject::WsServer(s)) => {
                s.stop();
                USER_POINTERS.lock().remove(&wsserver);
                RTC_ERR_SUCCESS
            }
            Some(other) => {
                REGISTRY.lock().insert(wsserver, other);
                RTC_ERR_INVALID
            }
            None => RTC_ERR_INVALID,
        }
    })
}

/// `rtcGetWebSocketServerPort` — the (possibly auto-selected) listening port.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetWebSocketServerPort(wsserver: c_int) -> c_int {
    guard(|| match get_ws_server(wsserver) {
        Some(s) => s.port() as c_int,
        None => RTC_ERR_INVALID,
    })
}

// ===========================================================================
// Global settings + lifecycle
// ===========================================================================

/// `rtcSetThreadPoolSize`. The runtime uses tokio's runtime, not a fixed pool;
/// accept and ignore.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetThreadPoolSize(_count: c_uint) -> c_int {
    RTC_ERR_SUCCESS
}

/// `rtcSetSctpSettings`. The runtime does not expose global SCTP tuning yet.
//
// TODO(#22): map onto SctpTransport settings when exposed.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetSctpSettings(_settings: *const c_void) -> c_int {
    RTC_ERR_SUCCESS
}

/// `rtcPreload`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcPreload() {
    crate::preload();
}

/// `rtcCleanup`. Closes and drops every registered object, mirroring the C++
/// `eraseAll()` + `rtc::Cleanup()`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcCleanup() {
    let drained: Vec<RtcObject> = {
        let mut reg = REGISTRY.lock();
        reg.drain().map(|(_, v)| v).collect()
    };
    for obj in drained {
        match obj {
            RtcObject::Pc(p) => {
                let _ = p.close();
            }
            RtcObject::Dc(d) => d.close(),
            RtcObject::Tr(t) => t.close(),
            RtcObject::Ws(w) => w.close(),
            RtcObject::WsServer(s) => s.stop(),
        }
    }
    USER_POINTERS.lock().clear();
    PC_SLOTS.lock().clear();
    DC_SLOTS.lock().clear();
    DC_RECV.lock().clear();
    DC_OPEN_FIRED.lock().clear();
    DC_AVAIL_PENDING.lock().clear();
    DC_OWNERS.lock().clear();
    TRACK_SLOTS.lock().clear();
    TRACK_OWNERS.lock().clear();
    WS_SLOTS.lock().clear();
    WS_RECV.lock().clear();
    WS_OPEN_FIRED.lock().clear();
    crate::cleanup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::sync::atomic::AtomicUsize;
    use std::time::{Duration, Instant};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    async fn wait_for<F: FnMut() -> bool>(mut pred: F, timeout_ms: u64) -> bool {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        while Instant::now() < deadline {
            if pred() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    /// A minimal loopback rtcConfiguration (bind to 127.0.0.1) built from
    /// owned C strings the caller must keep alive for the call.
    fn loopback_config(bind: &CString) -> RtcConfiguration {
        RtcConfiguration {
            iceServers: std::ptr::null(),
            iceServersCount: 0,
            proxyServer: std::ptr::null(),
            bindAddress: bind.as_ptr(),
            certificateType: 0,
            iceTransportPolicy: 0,
            enableIceTcp: false,
            enableIceUdpMux: false,
            disableAutoNegotiation: false,
            forceMediaTransport: false,
            portRangeBegin: 0,
            portRangeEnd: 0,
            mtu: 0,
            maxMessageSize: 0,
        }
    }

    #[test]
    fn create_and_delete_peer_connection() {
        let bind = CString::new("127.0.0.1").unwrap();
        let cfg = loopback_config(&bind);
        let pc = rtcCreatePeerConnection(&cfg);
        assert!(pc > 0, "handle must be positive, got {pc}");
        assert_eq!(rtcDeletePeerConnection(pc), RTC_ERR_SUCCESS);
        // Deleting again is an invalid handle.
        assert_eq!(rtcDeletePeerConnection(pc), RTC_ERR_INVALID);
    }

    #[test]
    fn invalid_handle_returns_invalid() {
        // A handle that was never issued.
        assert_eq!(rtcClosePeerConnection(999_999), RTC_ERR_INVALID);
        assert_eq!(rtcGetDataChannelStream(999_999), RTC_ERR_INVALID);
        assert!(!rtcIsOpen(999_999));
        // Upstream wraps getChannel(id)->isClosed(); an unknown id throws and
        // wrap() returns an error, so rtcIsClosed reports false (capi.cpp:820),
        // matching capi_connectivity.cpp's rtcIsClosed(666) == false assertion.
        assert!(!rtcIsClosed(999_999));
    }

    #[test]
    fn null_config_is_invalid() {
        assert_eq!(rtcCreatePeerConnection(std::ptr::null()), RTC_ERR_INVALID);
    }

    #[test]
    fn handles_are_distinct_and_share_space() {
        let bind = CString::new("127.0.0.1").unwrap();
        let cfg = loopback_config(&bind);
        let a = rtcCreatePeerConnection(&cfg);
        let cfg2 = loopback_config(&bind);
        let b = rtcCreatePeerConnection(&cfg2);
        assert!(
            a > 0 && b > 0 && a != b,
            "handles must be distinct: {a}, {b}"
        );
        let dc = rtcCreateDataChannel(a, CString::new("x").unwrap().as_ptr());
        assert!(dc > 0 && dc != a && dc != b, "dc shares the id space");
        // Targeted teardown only: `rtcCleanup()` would drain the process-global
        // registry that sibling tests (running in parallel) also use.
        rtcDeleteDataChannel(dc);
        rtcDeletePeerConnection(a);
        rtcDeletePeerConnection(b);
    }

    #[test]
    fn user_pointer_round_trips() {
        let bind = CString::new("127.0.0.1").unwrap();
        let cfg = loopback_config(&bind);
        let pc = rtcCreatePeerConnection(&cfg);
        assert!(rtcGetUserPointer(pc).is_null(), "default is null");
        let sentinel = 0xABCD_1234usize as *mut c_void;
        rtcSetUserPointer(pc, sentinel);
        assert_eq!(rtcGetUserPointer(pc), sentinel);
        rtcDeletePeerConnection(pc);
    }

    #[test]
    fn string_out_buffer_convention() {
        let bind = CString::new("127.0.0.1").unwrap();
        let cfg = loopback_config(&bind);
        let pc = rtcCreatePeerConnection(&cfg);

        // Create a data channel so the label getter has something to copy.
        let dc = rtcCreateDataChannel(pc, CString::new("chat-label").unwrap().as_ptr());
        assert!(dc > 0);

        // NULL buffer => required size (len + 1).
        let needed = rtcGetDataChannelLabel(dc, std::ptr::null_mut(), 0);
        assert_eq!(needed, "chat-label".len() as c_int + 1);

        // Too-small buffer => RTC_ERR_TOO_SMALL.
        let mut small = [0i8; 4];
        let r = rtcGetDataChannelLabel(dc, small.as_mut_ptr(), small.len() as c_int);
        assert_eq!(r, RTC_ERR_TOO_SMALL);

        // Exactly-right buffer => copies + NUL, returns needed size.
        let mut buf = vec![0i8; needed as usize];
        let r = rtcGetDataChannelLabel(dc, buf.as_mut_ptr(), needed);
        assert_eq!(r, needed);
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "chat-label");

        // Targeted teardown (see `handles_are_distinct_and_share_space`).
        rtcDeleteDataChannel(dc);
        rtcDeletePeerConnection(pc);
    }

    #[test]
    fn data_channel_label_protocol_reliability() {
        let bind = CString::new("127.0.0.1").unwrap();
        let cfg = loopback_config(&bind);
        let pc = rtcCreatePeerConnection(&cfg);

        let proto = CString::new("myproto").unwrap();
        let init = RtcDataChannelInit {
            reliability: RtcReliability {
                unordered: true,
                unreliable: true,
                maxPacketLifeTime: 0,
                maxRetransmits: 5,
            },
            protocol: proto.as_ptr(),
            negotiated: false,
            manualStream: true,
            stream: 42,
        };
        let dc = rtcCreateDataChannelEx(pc, CString::new("lbl").unwrap().as_ptr(), &init);
        assert!(dc > 0);
        assert_eq!(rtcGetDataChannelStream(dc), 42);

        // Protocol round-trips.
        let needed = rtcGetDataChannelProtocol(dc, std::ptr::null_mut(), 0);
        let mut buf = vec![0i8; needed as usize];
        rtcGetDataChannelProtocol(dc, buf.as_mut_ptr(), needed);
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "myproto");

        // Reliability reflects unordered + rexmit=5.
        let mut rel = RtcReliability {
            unordered: false,
            unreliable: false,
            maxPacketLifeTime: 0,
            maxRetransmits: 0,
        };
        assert_eq!(rtcGetDataChannelReliability(dc, &mut rel), RTC_ERR_SUCCESS);
        assert!(rel.unordered);
        assert!(rel.unreliable);
        assert_eq!(rel.maxRetransmits, 5);
        assert_eq!(rel.maxPacketLifeTime, 0);

        // Targeted teardown (see `handles_are_distinct_and_share_space`).
        rtcDeleteDataChannel(dc);
        rtcDeletePeerConnection(pc);
    }

    /// The Track C-API is now backed by the runtime: add/accessors/callbacks/
    /// keyframe/transform work; the media-handler *chain* functions remain
    /// honestly NOT_AVAIL (no runtime MediaHandlerChain on Track yet). WebSocket
    /// is not ported.
    #[test]
    fn track_capi_is_backed_and_chain_handlers_not_avail() {
        let bind = CString::new("127.0.0.1").unwrap();
        let cfg = loopback_config(&bind);
        let pc = rtcCreatePeerConnection(&cfg);

        // rtcSetTrackCallback now installs the on_track hook (success).
        assert_eq!(rtcSetTrackCallback(pc, None), RTC_ERR_SUCCESS);

        // rtcAddTrackEx returns a real track handle.
        let mid = CString::new("video0").unwrap();
        let init = RtcTrackInit {
            direction: 1, // RTC_DIRECTION_SENDONLY
            codec: 0,     // RTC_CODEC_H264
            payloadType: 96,
            ssrc: 0x1234_5678,
            mid: mid.as_ptr(),
            name: std::ptr::null(),
            msid: std::ptr::null(),
            trackId: std::ptr::null(),
            profile: std::ptr::null(),
        };
        let tr = rtcAddTrackEx(pc, &init);
        assert!(tr > 0, "rtcAddTrackEx should return a track handle");

        // mid round-trips.
        let needed = rtcGetTrackMid(tr, std::ptr::null_mut(), 0);
        let mut buf = vec![0i8; needed as usize];
        assert_eq!(rtcGetTrackMid(tr, buf.as_mut_ptr(), needed), needed);
        let got = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(got, "video0");

        // direction reads back as SENDONLY.
        let mut dir: c_int = -99;
        assert_eq!(rtcGetTrackDirection(tr, &mut dir), RTC_ERR_SUCCESS);
        assert_eq!(dir, 1);

        // description SDP is non-empty and carries the m=video line.
        let dn = rtcGetTrackDescription(tr, std::ptr::null_mut(), 0);
        let mut dbuf = vec![0i8; dn as usize];
        assert_eq!(rtcGetTrackDescription(tr, dbuf.as_mut_ptr(), dn), dn);
        let sdp = unsafe { CStr::from_ptr(dbuf.as_ptr()) }.to_str().unwrap();
        assert!(sdp.contains("m=video"), "got: {sdp}");

        // rtcAddTrack from raw SDP also returns a handle.
        let sdp2 = CString::new(
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:audio0\r\na=sendrecv\r\na=rtpmap:111 opus/48000/2\r\n",
        )
        .unwrap();
        let tr2 = rtcAddTrack(pc, sdp2.as_ptr());
        assert!(tr2 > 0, "rtcAddTrack should return a track handle");

        // Transform helpers use the track clock rate (video: 90 kHz).
        let mut ts: u32 = 0;
        assert_eq!(
            rtcTransformSecondsToTimestamp(tr, 1.0, &mut ts),
            RTC_ERR_SUCCESS
        );
        assert_eq!(ts, 90_000);
        let mut secs: c_double = 0.0;
        assert_eq!(
            rtcTransformTimestampToSeconds(tr, 90_000, &mut secs),
            RTC_ERR_SUCCESS
        );
        assert!((secs - 1.0).abs() < 1e-9);

        // Media-handler chain functions are now backed by the runtime Track
        // chain: appending handlers succeeds on a valid handle.
        assert_eq!(rtcChainRtcpReceivingSession(tr), RTC_ERR_SUCCESS);
        assert_eq!(rtcChainRtcpSrReporter(tr), RTC_ERR_SUCCESS);
        assert_eq!(rtcChainRtcpNackResponder(tr, 0), RTC_ERR_SUCCESS);
        assert_eq!(rtcChainPacingHandler(tr, 800_000.0, 5), RTC_ERR_SUCCESS);
        // rtcRequestBitrate now drives the runtime media-handler chain (the
        // RtcpReceivingSession chained above honours it via REMB): success on a
        // valid handle, INVALID on an unknown one.
        assert_eq!(rtcRequestBitrate(tr, 100_000), RTC_ERR_SUCCESS);
        assert_eq!(rtcRequestBitrate(999_999, 100_000), RTC_ERR_INVALID);
        // Invalid handle on a chain function reports INVALID.
        assert_eq!(rtcChainRtcpReceivingSession(999_999), RTC_ERR_INVALID);
        // Deleting an unknown track is INVALID.
        assert_eq!(rtcDeleteTrack(999_999), RTC_ERR_INVALID);

        // Real delete succeeds.
        assert_eq!(rtcDeleteTrack(tr), RTC_ERR_SUCCESS);
        assert_eq!(rtcDeleteTrack(tr2), RTC_ERR_SUCCESS);

        // WebSocket client/server are now wired (full loopback is exercised by
        // the capi_websocketserver conformance test). Here we just check the
        // handle-validation edges, which are deterministic without a network.
        assert_eq!(rtcCreateWebSocket(std::ptr::null()), RTC_ERR_INVALID);
        assert_eq!(rtcDeleteWebSocket(999_999), RTC_ERR_INVALID);
        assert_eq!(rtcDeleteWebSocketServer(999_999), RTC_ERR_INVALID);
        assert_eq!(rtcGetWebSocketServerPort(999_999), RTC_ERR_INVALID);

        rtcDeletePeerConnection(pc);
    }

    /// `rtcSet{H264,H265,AV1,VP8}Packetizer` install a codec packetizer on a real
    /// track handle and validate their argument edges (unknown track, NULL init,
    /// NULL cname, zero clockRate all report `RTC_ERR_INVALID`).
    #[test]
    fn set_codec_packetizers_install_and_validate() {
        let bind = CString::new("127.0.0.1").unwrap();
        let cfg = loopback_config(&bind);
        let pc = rtcCreatePeerConnection(&cfg);

        let mid = CString::new("video0").unwrap();
        let tinit = RtcTrackInit {
            direction: 1, // SENDONLY
            codec: 0,     // H264
            payloadType: 96,
            ssrc: 0x1234_5678,
            mid: mid.as_ptr(),
            name: std::ptr::null(),
            msid: std::ptr::null(),
            trackId: std::ptr::null(),
            profile: std::ptr::null(),
        };
        let tr = rtcAddTrackEx(pc, &tinit);
        assert!(tr > 0, "rtcAddTrackEx should return a track handle");

        let cname = CString::new("video-cname").unwrap();
        let mk = |nal: c_int, obu: c_int| RtcPacketizerInit {
            ssrc: 0x1234_5678,
            cname: cname.as_ptr(),
            payloadType: 96,
            clockRate: 90_000,
            sequenceNumber: 0,
            timestamp: 0,
            maxFragmentSize: 0, // default
            nalSeparator: nal,
            obuPacketization: obu,
            playoutDelayId: 0,
            playoutDelayMin: 0,
            playoutDelayMax: 0,
            colorSpaceId: 0,
            colorChromaSitingHorz: 0,
            colorChromaSitingVert: 0,
            colorRange: 0,
            colorPrimaries: 0,
            colorTransfer: 0,
            colorMatrix: 0,
        };

        // All four install on a valid track (each replaces the previous packetizer).
        let h264 = mk(RTC_NAL_SEPARATOR_START_SEQUENCE, 0);
        assert_eq!(unsafe { rtcSetH264Packetizer(tr, &h264) }, RTC_ERR_SUCCESS);
        let h265 = mk(RTC_NAL_SEPARATOR_LENGTH, 0);
        assert_eq!(unsafe { rtcSetH265Packetizer(tr, &h265) }, RTC_ERR_SUCCESS);
        let av1 = mk(0, RTC_OBU_PACKETIZED_TEMPORAL_UNIT);
        assert_eq!(unsafe { rtcSetAV1Packetizer(tr, &av1) }, RTC_ERR_SUCCESS);
        let vp8 = mk(0, 0);
        assert_eq!(unsafe { rtcSetVP8Packetizer(tr, &vp8) }, RTC_ERR_SUCCESS);

        // Unknown track -> INVALID.
        assert_eq!(
            unsafe { rtcSetH264Packetizer(999_999, &h264) },
            RTC_ERR_INVALID
        );
        // NULL init -> INVALID.
        assert_eq!(
            unsafe { rtcSetVP8Packetizer(tr, std::ptr::null()) },
            RTC_ERR_INVALID
        );
        // NULL cname -> INVALID.
        let mut bad_cname = mk(0, 0);
        bad_cname.cname = std::ptr::null();
        assert_eq!(
            unsafe { rtcSetH264Packetizer(tr, &bad_cname) },
            RTC_ERR_INVALID
        );
        // Zero clockRate -> INVALID.
        let mut zero_clock = mk(0, 0);
        zero_clock.clockRate = 0;
        assert_eq!(
            unsafe { rtcSetAV1Packetizer(tr, &zero_clock) },
            RTC_ERR_INVALID
        );

        assert_eq!(rtcDeleteTrack(tr), RTC_ERR_SUCCESS);
        rtcDeletePeerConnection(pc);
    }

    /// Exercises the Track timestamp / SSRC / CNAME C-ABI utilities against a
    /// real track: timestamp get/set (generic packetizer and, once installed,
    /// the codec packetizer's config), payload-types-for-codec filtering with
    /// the `copyAndReturn` sizing convention, SSRC enumeration, CNAME lookup,
    /// the last-SR-timestamp (INVALID until an SR reporter is chained), and the
    /// deprecated `rtcSetNeedsToSendRtcpSr` no-op.
    #[test]
    fn track_timestamp_ssrc_cname_c_api() {
        use std::os::raw::c_char;

        let bind = CString::new("127.0.0.1").unwrap();
        let cfg = loopback_config(&bind);
        let pc = rtcCreatePeerConnection(&cfg);

        let mid = CString::new("video0").unwrap();
        let name = CString::new("video-cname").unwrap();
        let tinit = RtcTrackInit {
            direction: 1, // SENDONLY
            codec: 0,     // H264
            payloadType: 96,
            ssrc: 0x1234_5678,
            mid: mid.as_ptr(),
            name: name.as_ptr(),
            msid: std::ptr::null(),
            trackId: std::ptr::null(),
            profile: std::ptr::null(),
        };
        let tr = rtcAddTrackEx(pc, &tinit);
        assert!(tr > 0, "rtcAddTrackEx should return a track handle");

        // --- timestamp get/set on the generic packetizer (round-trips) ---
        let mut ts: u32 = 0;
        assert_eq!(rtcGetCurrentTrackTimestamp(tr, &mut ts), RTC_ERR_SUCCESS);
        assert_eq!(rtcSetTrackRtpTimestamp(tr, 0xDEAD_BEEF), RTC_ERR_SUCCESS);
        let mut got: u32 = 0;
        assert_eq!(rtcGetCurrentTrackTimestamp(tr, &mut got), RTC_ERR_SUCCESS);
        assert_eq!(got, 0xDEAD_BEEF);
        // Null out-pointer is tolerated (matches upstream guard).
        assert_eq!(
            rtcGetCurrentTrackTimestamp(tr, std::ptr::null_mut()),
            RTC_ERR_SUCCESS
        );

        // Installing a codec packetizer redirects timestamp access to ITS config.
        let cname = CString::new("video-cname").unwrap();
        let pkt = RtcPacketizerInit {
            ssrc: 0x1234_5678,
            cname: cname.as_ptr(),
            payloadType: 96,
            clockRate: 90_000,
            sequenceNumber: 0,
            timestamp: 777,
            maxFragmentSize: 0,
            nalSeparator: RTC_NAL_SEPARATOR_LENGTH,
            obuPacketization: 0,
            playoutDelayId: 0,
            playoutDelayMin: 0,
            playoutDelayMax: 0,
            colorSpaceId: 0,
            colorChromaSitingHorz: 0,
            colorChromaSitingVert: 0,
            colorRange: 0,
            colorPrimaries: 0,
            colorTransfer: 0,
            colorMatrix: 0,
        };
        assert_eq!(unsafe { rtcSetH264Packetizer(tr, &pkt) }, RTC_ERR_SUCCESS);
        let mut got2: u32 = 0;
        assert_eq!(rtcGetCurrentTrackTimestamp(tr, &mut got2), RTC_ERR_SUCCESS);
        assert_eq!(got2, 777, "reads the installed codec packetizer's config");
        assert_eq!(rtcSetTrackRtpTimestamp(tr, 999), RTC_ERR_SUCCESS);
        let mut got3: u32 = 0;
        assert_eq!(rtcGetCurrentTrackTimestamp(tr, &mut got3), RTC_ERR_SUCCESS);
        assert_eq!(got3, 999);

        // --- payload types for codec (copyAndReturn semantics) ---
        let h264 = CString::new("H264").unwrap();
        // Sizing query: null buffer returns the count.
        assert_eq!(
            rtcGetTrackPayloadTypesForCodec(tr, h264.as_ptr(), std::ptr::null_mut(), 0),
            1
        );
        let mut buf = [0 as c_int; 4];
        let n = rtcGetTrackPayloadTypesForCodec(
            tr,
            h264.as_ptr(),
            buf.as_mut_ptr(),
            buf.len() as c_int,
        );
        assert_eq!(n, 1);
        assert_eq!(buf[0], 96);
        // Case-insensitive match.
        let lower = CString::new("h264").unwrap();
        assert_eq!(
            rtcGetTrackPayloadTypesForCodec(
                tr,
                lower.as_ptr(),
                buf.as_mut_ptr(),
                buf.len() as c_int
            ),
            1
        );
        // Unknown codec -> 0.
        let vp9 = CString::new("VP9").unwrap();
        assert_eq!(
            rtcGetTrackPayloadTypesForCodec(tr, vp9.as_ptr(), buf.as_mut_ptr(), buf.len() as c_int),
            0
        );
        // Too-small buffer -> RTC_ERR_TOO_SMALL.
        assert_eq!(
            rtcGetTrackPayloadTypesForCodec(tr, h264.as_ptr(), buf.as_mut_ptr(), 0),
            RTC_ERR_TOO_SMALL
        );
        // Null codec name -> INVALID.
        assert_eq!(
            rtcGetTrackPayloadTypesForCodec(tr, std::ptr::null(), buf.as_mut_ptr(), 4),
            RTC_ERR_INVALID
        );

        // --- SSRCs for track ---
        assert_eq!(rtcGetSsrcsForTrack(tr, std::ptr::null_mut(), 0), 1);
        let mut sbuf = [0u32; 4];
        assert_eq!(
            rtcGetSsrcsForTrack(tr, sbuf.as_mut_ptr(), sbuf.len() as c_int),
            1
        );
        assert_eq!(sbuf[0], 0x1234_5678);
        assert_eq!(
            rtcGetSsrcsForTrack(tr, sbuf.as_mut_ptr(), 0),
            RTC_ERR_TOO_SMALL
        );

        // --- CNAME for SSRC ---
        let mut cbuf = [0 as c_char; 32];
        assert_eq!(
            rtcGetCNameForSsrc(tr, 0x1234_5678, cbuf.as_mut_ptr(), cbuf.len() as c_int),
            "video-cname".len() as c_int + 1
        );
        // Unknown SSRC -> 0.
        assert_eq!(
            rtcGetCNameForSsrc(tr, 0xFFFF_FFFF, cbuf.as_mut_ptr(), cbuf.len() as c_int),
            0
        );

        // --- last SR timestamp: INVALID until a reporter is chained ---
        let mut srt: u32 = 123;
        assert_eq!(
            rtcGetLastTrackSenderReportTimestamp(tr, &mut srt),
            RTC_ERR_INVALID
        );
        assert_eq!(rtcChainRtcpSrReporter(tr), RTC_ERR_SUCCESS);
        let mut srt2: u32 = 123;
        assert_eq!(
            rtcGetLastTrackSenderReportTimestamp(tr, &mut srt2),
            RTC_ERR_SUCCESS
        );
        assert_eq!(srt2, 0, "no SR emitted yet -> last reported timestamp is 0");

        // --- deprecated no-op ---
        assert_eq!(rtcSetNeedsToSendRtcpSr(tr), RTC_ERR_SUCCESS);

        // --- invalid track handle on each getter/setter ---
        assert_eq!(
            rtcGetCurrentTrackTimestamp(999_999, &mut got),
            RTC_ERR_INVALID
        );
        assert_eq!(rtcSetTrackRtpTimestamp(999_999, 0), RTC_ERR_INVALID);
        assert_eq!(
            rtcGetSsrcsForTrack(999_999, sbuf.as_mut_ptr(), 4),
            RTC_ERR_INVALID
        );

        assert_eq!(rtcDeleteTrack(tr), RTC_ERR_SUCCESS);
        rtcDeletePeerConnection(pc);
    }

    /// Exercises the SDP-string SSRC utilities (`rtcGetSsrcsForType` /
    /// `rtcSetSsrcForType`) and the opaque-message create/delete pair. Mints a
    /// real offer SDP (one sendonly H264 video track carrying an SSRC) via the
    /// C API, then reads / mutates its SSRCs purely through the string-based
    /// functions (no live handle), mirroring how a caller post-processes SDP.
    #[test]
    fn ssrc_for_type_and_opaque_message_c_api() {
        use std::os::raw::c_char;

        let bind = CString::new("127.0.0.1").unwrap();
        let cfg = loopback_config(&bind);
        let pc = rtcCreatePeerConnection(&cfg);

        let mid = CString::new("video0").unwrap();
        let name = CString::new("vcname").unwrap();
        let tinit = RtcTrackInit {
            direction: 1, // SENDONLY
            codec: 0,     // H264
            payloadType: 96,
            ssrc: 0x1111_2222,
            mid: mid.as_ptr(),
            name: name.as_ptr(),
            msid: std::ptr::null(),
            trackId: std::ptr::null(),
            profile: std::ptr::null(),
        };
        assert!(rtcAddTrackEx(pc, &tinit) > 0);

        // Mint an offer SDP. ufrag/pwd + the video m-line with a=ssrc are present
        // immediately; gathered candidates aren't needed for SSRC inspection.
        assert_eq!(
            rtcSetLocalDescription(pc, std::ptr::null()),
            RTC_ERR_SUCCESS
        );
        let needed = rtcGetLocalDescription(pc, std::ptr::null_mut(), 0);
        assert!(needed > 0, "no local description: {needed}");
        let mut sdp_buf = vec![0 as c_char; needed as usize];
        assert_eq!(
            rtcGetLocalDescription(pc, sdp_buf.as_mut_ptr(), needed),
            needed
        );
        let sdp = unsafe { CStr::from_ptr(sdp_buf.as_ptr()) }.to_owned();

        let video = CString::new("video").unwrap();
        let audio = CString::new("audio").unwrap();

        // --- rtcGetSsrcsForType ---
        // Sizing query (null buffer) returns the count: 1 SSRC on the video m-line.
        assert_eq!(
            rtcGetSsrcsForType(video.as_ptr(), sdp.as_ptr(), std::ptr::null_mut(), 0),
            1
        );
        let mut ssrcs = [0u32; 4];
        assert_eq!(
            rtcGetSsrcsForType(video.as_ptr(), sdp.as_ptr(), ssrcs.as_mut_ptr(), 4),
            1
        );
        assert_eq!(ssrcs[0], 0x1111_2222);
        // Case-insensitive media type.
        let video_upper = CString::new("VIDEO").unwrap();
        assert_eq!(
            rtcGetSsrcsForType(video_upper.as_ptr(), sdp.as_ptr(), ssrcs.as_mut_ptr(), 4),
            1
        );
        // Too-small (non-null buffer, size < count) -> TOO_SMALL.
        assert_eq!(
            rtcGetSsrcsForType(video.as_ptr(), sdp.as_ptr(), ssrcs.as_mut_ptr(), 0),
            RTC_ERR_TOO_SMALL
        );
        // No audio media section -> 0 (matches upstream).
        assert_eq!(
            rtcGetSsrcsForType(audio.as_ptr(), sdp.as_ptr(), ssrcs.as_mut_ptr(), 4),
            0
        );
        // Invalid args.
        assert_eq!(
            rtcGetSsrcsForType(std::ptr::null(), sdp.as_ptr(), ssrcs.as_mut_ptr(), 4),
            RTC_ERR_INVALID
        );
        assert_eq!(
            rtcGetSsrcsForType(video.as_ptr(), std::ptr::null(), ssrcs.as_mut_ptr(), 4),
            RTC_ERR_INVALID
        );

        // --- rtcSetSsrcForType: append a second SSRC to the video section ---
        let extra_name = CString::new("extra-cname").unwrap();
        let init = rtcSsrcForTypeInit {
            ssrc: 0x9999_0000,
            name: extra_name.as_ptr(),
            msid: std::ptr::null(),
            trackId: std::ptr::null(),
        };
        // Sizing query.
        let needed2 =
            rtcSetSsrcForType(video.as_ptr(), sdp.as_ptr(), std::ptr::null_mut(), 0, &init);
        assert!(needed2 > 0, "set-ssrc sizing query: {needed2}");
        let mut out_buf = vec![0 as c_char; needed2 as usize];
        assert_eq!(
            rtcSetSsrcForType(
                video.as_ptr(),
                sdp.as_ptr(),
                out_buf.as_mut_ptr(),
                needed2,
                &init
            ),
            needed2
        );
        let new_sdp = unsafe { CStr::from_ptr(out_buf.as_ptr()) }.to_owned();

        // The mutated SDP advertises BOTH SSRCs on the video section.
        assert_eq!(
            rtcGetSsrcsForType(video.as_ptr(), new_sdp.as_ptr(), ssrcs.as_mut_ptr(), 4),
            2
        );
        assert!(ssrcs[..2].contains(&0x1111_2222));
        assert!(ssrcs[..2].contains(&0x9999_0000));
        // Null init -> INVALID.
        assert_eq!(
            rtcSetSsrcForType(
                video.as_ptr(),
                sdp.as_ptr(),
                out_buf.as_mut_ptr(),
                needed2,
                std::ptr::null()
            ),
            RTC_ERR_INVALID
        );

        // --- opaque message create/delete ---
        let mut payload = *b"opaque-bytes";
        let msg =
            rtcCreateOpaqueMessage(payload.as_mut_ptr() as *mut c_void, payload.len() as c_int);
        assert!(!msg.is_null());
        rtcDeleteOpaqueMessage(msg);
        // Null data / negative size -> null; deleting null is a no-op.
        assert!(rtcCreateOpaqueMessage(std::ptr::null_mut(), 4).is_null());
        assert!(rtcCreateOpaqueMessage(payload.as_mut_ptr() as *mut c_void, -1).is_null());
        rtcDeleteOpaqueMessage(std::ptr::null_mut());

        rtcDeletePeerConnection(pc);
    }

    /// End-to-end loopback through the C API: two PCs, a data channel, message
    /// round-trip — all driven via the `extern "C"` symbols. Proves the handle
    /// registry, the callback marshalling (state/candidate/data-channel/
    /// message), and the user-pointer plumbing all work across the boundary.
    #[test]
    fn loopback_data_channel_round_trip_via_c_api() {
        // Cross-thread collectors. The C callbacks below push into these via
        // the user pointer (set to the address of a context struct).
        struct Ctx {
            a_connected: AtomicUsize,
            b_connected: AtomicUsize,
            b_dc: AtomicI32,
            b_got_msg: AtomicUsize,
            a_cands: Mutex<Vec<(CString, CString)>>,
            b_cands: Mutex<Vec<(CString, CString)>>,
        }
        let ctx = Box::new(Ctx {
            a_connected: AtomicUsize::new(0),
            b_connected: AtomicUsize::new(0),
            b_dc: AtomicI32::new(0),
            b_got_msg: AtomicUsize::new(0),
            a_cands: Mutex::new(Vec::new()),
            b_cands: Mutex::new(Vec::new()),
        });
        let ctx_ptr: *mut Ctx = Box::into_raw(ctx);

        extern "C" fn on_state_a(_pc: c_int, state: c_int, ptr: *mut c_void) {
            if state == RtcState::Connected as c_int {
                let c = unsafe { &*(ptr as *const Ctx) };
                c.a_connected.fetch_add(1, Ordering::SeqCst);
            }
        }
        extern "C" fn on_state_b(_pc: c_int, state: c_int, ptr: *mut c_void) {
            if state == RtcState::Connected as c_int {
                let c = unsafe { &*(ptr as *const Ctx) };
                c.b_connected.fetch_add(1, Ordering::SeqCst);
            }
        }
        extern "C" fn on_cand_a(
            _pc: c_int,
            cand: *const c_char,
            mid: *const c_char,
            ptr: *mut c_void,
        ) {
            let c = unsafe { &*(ptr as *const Ctx) };
            let cand = unsafe { CStr::from_ptr(cand) }.to_owned();
            let mid = unsafe { CStr::from_ptr(mid) }.to_owned();
            c.a_cands.lock().push((cand, mid));
        }
        extern "C" fn on_cand_b(
            _pc: c_int,
            cand: *const c_char,
            mid: *const c_char,
            ptr: *mut c_void,
        ) {
            let c = unsafe { &*(ptr as *const Ctx) };
            let cand = unsafe { CStr::from_ptr(cand) }.to_owned();
            let mid = unsafe { CStr::from_ptr(mid) }.to_owned();
            c.b_cands.lock().push((cand, mid));
        }
        extern "C" fn on_dc_b(_pc: c_int, dc: c_int, ptr: *mut c_void) {
            let c = unsafe { &*(ptr as *const Ctx) };
            c.b_dc.store(dc, Ordering::SeqCst);
            // Install a message callback on the inbound channel.
            rtcSetMessageCallback(dc, Some(on_msg_b));
        }
        extern "C" fn on_msg_b(_id: c_int, _msg: *const c_char, _size: c_int, ptr: *mut c_void) {
            let c = unsafe { &*(ptr as *const Ctx) };
            c.b_got_msg.fetch_add(1, Ordering::SeqCst);
        }

        rt().block_on(async {
            let bind = CString::new("127.0.0.1").unwrap();
            let cfg_a = loopback_config(&bind);
            let cfg_b = loopback_config(&bind);
            let pc_a = rtcCreatePeerConnection(&cfg_a);
            let pc_b = rtcCreatePeerConnection(&cfg_b);
            assert!(pc_a > 0 && pc_b > 0);

            // Wire user pointers so callbacks can reach the context.
            rtcSetUserPointer(pc_a, ctx_ptr as *mut c_void);
            rtcSetUserPointer(pc_b, ctx_ptr as *mut c_void);

            assert_eq!(
                rtcSetStateChangeCallback(pc_a, Some(on_state_a)),
                RTC_ERR_SUCCESS
            );
            assert_eq!(
                rtcSetStateChangeCallback(pc_b, Some(on_state_b)),
                RTC_ERR_SUCCESS
            );
            assert_eq!(
                rtcSetLocalCandidateCallback(pc_a, Some(on_cand_a)),
                RTC_ERR_SUCCESS
            );
            assert_eq!(
                rtcSetLocalCandidateCallback(pc_b, Some(on_cand_b)),
                RTC_ERR_SUCCESS
            );
            assert_eq!(
                rtcSetDataChannelCallback(pc_b, Some(on_dc_b)),
                RTC_ERR_SUCCESS
            );

            // A creates the channel.
            let dc_a = rtcCreateDataChannel(pc_a, CString::new("chat").unwrap().as_ptr());
            assert!(dc_a > 0);

            // Offer/answer via the C API.
            assert_eq!(
                rtcSetLocalDescription(pc_a, std::ptr::null()),
                RTC_ERR_SUCCESS
            );

            // Wait for A's gathering to complete (candidates collected).
            assert!(
                wait_for(
                    || {
                        let c = unsafe { &*ctx_ptr };
                        !c.a_cands.lock().is_empty()
                    },
                    4000
                )
                .await,
                "A produced no candidates"
            );

            // Read A's local description and hand it to B.
            let needed = rtcGetLocalDescription(pc_a, std::ptr::null_mut(), 0);
            assert!(needed > 0, "A has no local description: {needed}");
            let mut buf = vec![0i8; needed as usize];
            assert_eq!(
                rtcGetLocalDescription(pc_a, buf.as_mut_ptr(), needed),
                needed
            );
            let offer = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_owned();

            let typ_offer = CString::new("offer").unwrap();
            assert_eq!(
                rtcSetRemoteDescription(pc_b, offer.as_ptr(), typ_offer.as_ptr()),
                RTC_ERR_SUCCESS
            );
            // B creates its answer.
            let needed = rtcCreateAnswer(pc_b, std::ptr::null_mut(), 0);
            assert!(needed > 0, "B produced no answer: {needed}");
            // Wait for B's candidates.
            assert!(
                wait_for(
                    || {
                        let c = unsafe { &*ctx_ptr };
                        !c.b_cands.lock().is_empty()
                    },
                    4000
                )
                .await,
                "B produced no candidates"
            );
            let needed = rtcGetLocalDescription(pc_b, std::ptr::null_mut(), 0);
            let mut buf = vec![0i8; needed as usize];
            assert_eq!(
                rtcGetLocalDescription(pc_b, buf.as_mut_ptr(), needed),
                needed
            );
            let answer = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_owned();
            let typ_answer = CString::new("answer").unwrap();
            assert_eq!(
                rtcSetRemoteDescription(pc_a, answer.as_ptr(), typ_answer.as_ptr()),
                RTC_ERR_SUCCESS
            );

            // Trickle candidates both ways.
            {
                let c = unsafe { &*ctx_ptr };
                for (cand, mid) in c.a_cands.lock().iter() {
                    rtcAddRemoteCandidate(pc_b, cand.as_ptr(), mid.as_ptr());
                }
                for (cand, mid) in c.b_cands.lock().iter() {
                    rtcAddRemoteCandidate(pc_a, cand.as_ptr(), mid.as_ptr());
                }
            }

            // Wait for both to connect.
            assert!(
                wait_for(
                    || {
                        let c = unsafe { &*ctx_ptr };
                        c.a_connected.load(Ordering::SeqCst) > 0
                            && c.b_connected.load(Ordering::SeqCst) > 0
                    },
                    15000
                )
                .await,
                "peers did not reach Connected via the C API"
            );

            // B should have received the channel via on_data_channel.
            assert!(
                wait_for(
                    || unsafe { &*ctx_ptr }.b_dc.load(Ordering::SeqCst) > 0,
                    5000
                )
                .await,
                "B never got the data channel"
            );

            // A's channel should open (ACK received).
            assert!(
                wait_for(|| rtcIsOpen(dc_a), 5000).await,
                "A's channel never opened"
            );

            // A → B message.
            let payload = b"hello-c-api";
            assert_eq!(
                rtcSendMessage(
                    dc_a,
                    payload.as_ptr() as *const c_char,
                    payload.len() as c_int
                ),
                RTC_ERR_SUCCESS
            );
            assert!(
                wait_for(
                    || unsafe { &*ctx_ptr }.b_got_msg.load(Ordering::SeqCst) > 0,
                    5000
                )
                .await,
                "B never received A's message through the C message callback"
            );

            rtcDeletePeerConnection(pc_a);
            rtcDeletePeerConnection(pc_b);
        });

        // Reclaim the context box.
        unsafe {
            drop(Box::from_raw(ctx_ptr));
        }
    }

    /// The available callback is edge-triggered on the pull-API receive queue:
    /// it fires when the queue goes empty→non-empty, stays silent while the
    /// queue remains non-empty, and re-arms once drained. Ports upstream's
    /// `triggerAvailable(count == 1)`. Drives `deliver_message` directly to
    /// simulate inbound data without a full handshake.
    #[test]
    fn available_callback_fires_on_empty_to_nonempty_edge() {
        static FIRES: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn on_avail(_id: c_int, _ptr: *mut c_void) {
            FIRES.fetch_add(1, Ordering::SeqCst);
        }
        FIRES.store(0, Ordering::SeqCst);

        let bind = CString::new("127.0.0.1").unwrap();
        let cfg = loopback_config(&bind);
        let pc = rtcCreatePeerConnection(&cfg);
        let dc = rtcCreateDataChannel(pc, CString::new("chat").unwrap().as_ptr());
        assert!(dc > 0);

        // No message handler → inbound data buffers in the pull queue.
        assert_eq!(rtcSetAvailableCallback(dc, Some(on_avail)), RTC_ERR_SUCCESS);
        let channel = get_dc(dc).expect("dc handle");

        // First message: empty→non-empty edge fires exactly once.
        channel.deliver_message(b"one", true);
        assert_eq!(FIRES.load(Ordering::SeqCst), 1);
        assert_eq!(rtcGetAvailableAmount(dc), 3);

        // Second message while still non-empty: no new edge, no fire.
        channel.deliver_message(b"two", true);
        assert_eq!(FIRES.load(Ordering::SeqCst), 1);
        assert_eq!(rtcGetAvailableAmount(dc), 6);

        // Drain the queue via the pull API.
        loop {
            let mut size = 256i32;
            let mut buf = vec![0i8; 256];
            let rc = rtcReceiveMessage(dc, buf.as_mut_ptr(), &mut size);
            if rc == RTC_ERR_NOT_AVAIL {
                break;
            }
            assert_eq!(rc, RTC_ERR_SUCCESS);
        }
        assert_eq!(rtcGetAvailableAmount(dc), 0);

        // After draining to empty, the next message re-arms the edge.
        channel.deliver_message(b"three", true);
        assert_eq!(FIRES.load(Ordering::SeqCst), 2);

        // Clearing the callback stops further fires.
        assert_eq!(rtcSetAvailableCallback(dc, None), RTC_ERR_SUCCESS);
        loop {
            let mut size = 256i32;
            let mut buf = vec![0i8; 256];
            if rtcReceiveMessage(dc, buf.as_mut_ptr(), &mut size) == RTC_ERR_NOT_AVAIL {
                break;
            }
        }
        channel.deliver_message(b"four", true);
        assert_eq!(FIRES.load(Ordering::SeqCst), 2);

        rtcDeleteDataChannel(dc);
        rtcDeletePeerConnection(pc);
    }

    /// An available edge that happened *before* the callback was registered is
    /// replayed once on registration — porting the replay half of upstream's
    /// `synchronized_stored_callback` for `availableCallback`, and mirroring how
    /// the open callback replays a missed transition.
    #[test]
    fn available_callback_replays_edge_registered_after_message() {
        static FIRES: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn on_avail(_id: c_int, _ptr: *mut c_void) {
            FIRES.fetch_add(1, Ordering::SeqCst);
        }
        FIRES.store(0, Ordering::SeqCst);

        let bind = CString::new("127.0.0.1").unwrap();
        let cfg = loopback_config(&bind);
        let pc = rtcCreatePeerConnection(&cfg);
        let dc = rtcCreateDataChannel(pc, CString::new("chat").unwrap().as_ptr());
        assert!(dc > 0);

        // Message arrives with no callback yet: queued, edge marked pending.
        let channel = get_dc(dc).expect("dc handle");
        channel.deliver_message(b"early", true);
        assert_eq!(FIRES.load(Ordering::SeqCst), 0);

        // Registering now replays the missed edge exactly once.
        assert_eq!(rtcSetAvailableCallback(dc, Some(on_avail)), RTC_ERR_SUCCESS);
        assert_eq!(FIRES.load(Ordering::SeqCst), 1);

        // Re-registering must not re-fire (the pending flag was consumed).
        assert_eq!(rtcSetAvailableCallback(dc, Some(on_avail)), RTC_ERR_SUCCESS);
        assert_eq!(FIRES.load(Ordering::SeqCst), 1);

        rtcDeleteDataChannel(dc);
        rtcDeletePeerConnection(pc);
    }
}
