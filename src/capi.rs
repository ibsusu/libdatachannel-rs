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
//! WebSocket is not ported and likewise returns `RTC_ERR_NOT_AVAIL`.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// These `pub extern "C"` items are exported by the linker via `#[no_mangle]`,
// not through Rust's module tree, so the crate-wide `unreachable_pub` lint is a
// false positive for the whole shim.
#![allow(unreachable_pub)]

use std::collections::HashMap;
use std::ffi::{c_char, c_double, c_int, c_void, CStr};
use std::os::raw::c_uint;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::Mutex;

use crate::{
    CertificateType, Configuration, DataChannel, DataChannelCallbacks, DataChannelInit,
    Description, IceServer, IceTransportPolicy, PeerConnection, PeerConnectionCallbacks,
    PeerConnectionState, Reliability, ReliabilityType, Track, Type as DescriptionType,
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
}

/// Monotonic handle counter (`lastId` in capi.cpp). First handle is 1.
static LAST_ID: AtomicI32 = AtomicI32::new(0);

/// `handle -> object` registry (`peerConnectionMap`/`dataChannelMap`/... fused
/// into one map keyed by the shared id space).
static REGISTRY: Lazy<Mutex<HashMap<c_int, RtcObject>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// `handle -> user pointer`. We store the pointer as `usize` (it is opaque to
/// us and only handed back to C verbatim) so the map stays `Send`/`Sync`.
static USER_POINTERS: Lazy<Mutex<HashMap<c_int, usize>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Optional global log callback installed by `rtcInitLogger`.
static LOG_CALLBACK: Lazy<Mutex<Option<RtcLogCallbackFunc>>> = Lazy::new(|| Mutex::new(None));

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

// ===========================================================================
// Panic-safe boundary guards + string-buffer convention
// ===========================================================================

/// Run an `int`-returning body, catching panics (they must not cross into C)
/// and mapping a panic to `RTC_ERR_FAILURE`, mirroring the C++ `wrap()` which
/// turns a `std::exception` into `RTC_ERR_FAILURE`.
fn guard<F: FnOnce() -> c_int + std::panic::UnwindSafe>(f: F) -> c_int {
    match std::panic::catch_unwind(f) {
        Ok(v) => v,
        Err(_) => RTC_ERR_FAILURE,
    }
}

/// Run a `bool`-returning body, mapping a panic to `false`.
fn guard_bool<F: FnOnce() -> bool + std::panic::UnwindSafe>(f: F) -> bool {
    std::panic::catch_unwind(f).unwrap_or(false)
}

/// Invoke a C callback inside `catch_unwind` so a panic in the (rare) event a
/// closure we pass to the runtime panics can't unwind across the runtime's
/// threads either. The C callback itself is `extern "C"`, so a panic *inside*
/// the C code is already its problem; this guards our marshalling.
fn dispatch<F: FnOnce() + std::panic::UnwindSafe>(f: F) {
    let _ = std::panic::catch_unwind(f);
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
    gathering_state: Option<RtcGatheringStateCallbackFunc>,
    signaling_state: Option<RtcSignalingStateCallbackFunc>,
    data_channel: Option<RtcDataChannelCallbackFunc>,
}

// SAFETY: the slots hold bare `extern "C" fn` pointers, which are `Send`/`Sync`
// (they are plain code addresses). The user-pointer they're invoked with is
// fetched from USER_POINTERS at call time.
unsafe impl Send for PcCallbackSlots {}
unsafe impl Sync for PcCallbackSlots {}

static PC_SLOTS: Lazy<Mutex<HashMap<c_int, PcCallbackSlots>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// `rtcSetLocalDescriptionCallback`. The runtime has no dedicated
/// local-description hook, so we emulate one: the closure installed for the
/// local-candidate path also fires this callback once a local description is
/// available (see [`install_pc_callbacks`]).
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

        // The runtime fires on_local_candidate for trickle but has no dedicated
        // local-description hook; we emulate the description callback below by
        // chaining it onto the local-candidate path (a candidate implies a
        // local description exists).
        let ld_cb = slots.local_description;
        let lc_cb = slots.local_candidate;
        let sc_cb = slots.state_change;
        let gs_cb = slots.gathering_state;
        let ss_cb = slots.signaling_state;
        let dc_cb = slots.data_channel;

        if let Some(cb) = sc_cb {
            cbs.on_state_change = Arc::new(move |s| {
                let ptr = user_pointer(pc);
                let st = map_pc_state(s) as c_int;
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
                // Inherit the pc's user pointer (capi.cpp does this).
                let ptr = user_pointer(pc);
                rtcSetUserPointer(id, ptr);
                dispatch(move || cb(pc, id, ptr));
            });
        }

        // Local description callback: the runtime has no dedicated hook, so we
        // chain it onto the local-candidate path. It fires once, the first time
        // a local description is available (a candidate implies one exists),
        // matching the single description event a caller expects.
        if let Some(cb) = ld_cb {
            // Wrap the (possibly already-set) local_candidate closure so the
            // description callback also fires when a candidate is produced.
            let prev = cbs.on_local_candidate.clone();
            let pc_ld = pc_obj.clone();
            let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
            cbs.on_local_candidate = Arc::new(move |c| {
                (prev)(c);
                if fired.swap(true, Ordering::SeqCst) {
                    return;
                }
                if let Some(desc) = pc_ld.local_description() {
                    let ptr = user_pointer(pc);
                    let sdp = std::ffi::CString::new(desc.to_sdp()).unwrap_or_default();
                    let typ = std::ffi::CString::new(desc.type_string()).unwrap_or_default();
                    dispatch(move || cb(pc, sdp.as_ptr(), typ.as_ptr(), ptr));
                } else {
                    // No description yet; allow a later candidate to fire it.
                    fired.store(false, Ordering::SeqCst);
                }
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

/// `rtcSetIceStateChangeCallback`. The runtime aggregates ICE state into the
/// PeerConnection state, so there is no separate ICE-state hook to bind. We
/// validate the handle and accept the callback, but it will not fire.
//
// TODO(#22): wire to a dedicated ICE-state callback once the PeerConnection
// exposes one (it currently folds ICE state into PeerConnectionState).
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetIceStateChangeCallback(
    pc: c_int,
    _cb: Option<RtcIceStateChangeCallbackFunc>,
) -> c_int {
    if get_pc(pc).is_none() {
        RTC_ERR_INVALID
    } else {
        RTC_ERR_SUCCESS
    }
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
            Ok(_) => RTC_ERR_SUCCESS,
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
    pc_string_out(pc, buffer, size, |pc| pc.local_description().map(|d| d.to_sdp()))
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

/// `rtcGetLocalAddress`. The runtime does not expose the selected local
/// socket address yet.
//
// TODO(#22): expose PeerConnection::local_address() in the runtime.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetLocalAddress(pc: c_int, _buffer: *mut c_char, _size: c_int) -> c_int {
    if get_pc(pc).is_none() {
        RTC_ERR_INVALID
    } else {
        RTC_ERR_NOT_AVAIL
    }
}

/// `rtcGetRemoteAddress`. Not exposed by the runtime yet.
//
// TODO(#22): expose PeerConnection::remote_address() in the runtime.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetRemoteAddress(pc: c_int, _buffer: *mut c_char, _size: c_int) -> c_int {
    if get_pc(pc).is_none() {
        RTC_ERR_INVALID
    } else {
        RTC_ERR_NOT_AVAIL
    }
}

/// `rtcGetSelectedCandidatePair`. Not exposed by the runtime yet.
//
// TODO(#22): expose PeerConnection::get_selected_candidate_pair() in the runtime.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetSelectedCandidatePair(
    pc: c_int,
    _local: *mut c_char,
    _local_size: c_int,
    _remote: *mut c_char,
    _remote_size: c_int,
) -> c_int {
    if get_pc(pc).is_none() {
        RTC_ERR_INVALID
    } else {
        RTC_ERR_NOT_AVAIL
    }
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

/// `rtcGetMaxDataChannelStream`. Not exposed by the runtime yet.
//
// TODO(#22): expose PeerConnection::max_data_channel_id() in the runtime.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetMaxDataChannelStream(pc: c_int) -> c_int {
    if get_pc(pc).is_none() {
        RTC_ERR_INVALID
    } else {
        RTC_ERR_NOT_AVAIL
    }
}

/// `rtcGetRemoteMaxMessageSize`. Not exposed by the runtime yet.
//
// TODO(#22): expose PeerConnection::remote_max_message_size() in the runtime.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetRemoteMaxMessageSize(pc: c_int) -> c_int {
    if get_pc(pc).is_none() {
        RTC_ERR_INVALID
    } else {
        RTC_ERR_NOT_AVAIL
    }
}

// ===========================================================================
// DataChannel
// ===========================================================================

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
        // Inherit the pc's user pointer (capi.cpp does this).
        let ptr = user_pointer(pc);
        rtcSetUserPointer(id, ptr);
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
}

// SAFETY: bare `extern "C" fn` pointers are Send/Sync (code addresses).
unsafe impl Send for DcCallbackSlots {}
unsafe impl Sync for DcCallbackSlots {}

static DC_SLOTS: Lazy<Mutex<HashMap<c_int, DcCallbackSlots>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Rebuild and install the DataChannelCallbacks set for `id` from its slots.
fn install_dc_callbacks(id: c_int) -> c_int {
    guard(|| {
        let dc = match get_dc(id) {
            Some(d) => d,
            None => return RTC_ERR_INVALID,
        };
        let slots = DC_SLOTS.lock().get(&id).cloned().unwrap_or_default();
        let mut cbs = DataChannelCallbacks::default();

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
            cbs.on_message = Arc::new(move |data, binary| {
                let ptr = user_pointer(id);
                if binary {
                    // Binary: size is the byte count (non-negative). Data is not
                    // NUL-terminated; pass the raw pointer + length.
                    let len = data.len() as c_int;
                    let p = data.as_ptr() as *const c_char;
                    // We must keep `data` alive across the call; it is borrowed
                    // for the duration of this closure body, so the pointer is
                    // valid here.
                    dispatch(move || cb(id, p, len, ptr));
                } else {
                    // Text: rtc.h convention is a NUL-terminated string with a
                    // NEGATIVE size of -(len+1). Build a CString to guarantee
                    // the terminator.
                    let cstr = std::ffi::CString::new(data).unwrap_or_default();
                    let neg = -((cstr.as_bytes().len() + 1) as c_int);
                    let p = cstr.as_ptr();
                    dispatch(move || cb(id, p, neg, ptr));
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
        RTC_ERR_SUCCESS
    })
}

/// `rtcSetOpenCallback`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetOpenCallback(id: c_int, cb: Option<RtcOpenCallbackFunc>) -> c_int {
    if get_dc(id).is_none() {
        return RTC_ERR_INVALID;
    }
    DC_SLOTS.lock().entry(id).or_default().open = cb;
    install_dc_callbacks(id)
}

/// `rtcSetClosedCallback`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetClosedCallback(id: c_int, cb: Option<RtcClosedCallbackFunc>) -> c_int {
    if get_dc(id).is_none() {
        return RTC_ERR_INVALID;
    }
    DC_SLOTS.lock().entry(id).or_default().closed = cb;
    install_dc_callbacks(id)
}

/// `rtcSetErrorCallback`. Stored for ABI completeness; the runtime
/// DataChannel has no error hook, so it will not fire.
//
// TODO(#22): wire to a DataChannel error hook when the runtime grows one.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetErrorCallback(id: c_int, cb: Option<RtcErrorCallbackFunc>) -> c_int {
    if get_dc(id).is_none() {
        return RTC_ERR_INVALID;
    }
    DC_SLOTS.lock().entry(id).or_default().error = cb;
    RTC_ERR_SUCCESS
}

/// `rtcSetMessageCallback`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetMessageCallback(id: c_int, cb: Option<RtcMessageCallbackFunc>) -> c_int {
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

/// `rtcClose` (generic channel close — DataChannel only in this port).
#[unsafe(no_mangle)]
pub extern "C" fn rtcClose(id: c_int) -> c_int {
    guard(|| match get_dc(id) {
        Some(d) => {
            d.close();
            RTC_ERR_SUCCESS
        }
        None => RTC_ERR_INVALID,
    })
}

/// `rtcDelete` (generic channel delete — DataChannel only in this port).
#[unsafe(no_mangle)]
pub extern "C" fn rtcDelete(id: c_int) -> c_int {
    rtcDeleteDataChannel(id)
}

/// `rtcIsOpen`.
#[unsafe(no_mangle)]
pub extern "C" fn rtcIsOpen(id: c_int) -> bool {
    guard_bool(|| get_dc(id).map(|d| d.is_open()).unwrap_or(false))
}

/// `rtcIsClosed`. The runtime DataChannel does not expose an `is_closed`
/// accessor; we derive "closed" as "registered but not open". A handle that is
/// open is definitely not closed; an unknown handle reports closed.
#[unsafe(no_mangle)]
pub extern "C" fn rtcIsClosed(id: c_int) -> bool {
    guard_bool(|| match get_dc(id) {
        Some(d) => !d.is_open(),
        None => true,
    })
}

/// `rtcMaxMessageSize`. The runtime does not expose a per-channel max message
/// size; report the WebRTC default (256 KiB) as the C++ would after
/// negotiation defaults.
//
// TODO(#22): expose DataChannel::max_message_size() in the runtime.
#[unsafe(no_mangle)]
pub extern "C" fn rtcMaxMessageSize(id: c_int) -> c_int {
    guard(|| {
        if get_dc(id).is_none() {
            RTC_ERR_INVALID
        } else {
            262_144 // 256 KiB, libdatachannel's LOCAL_MAX_MESSAGE_SIZE default
        }
    })
}

/// `rtcGetBufferedAmount`. The runtime does not track buffered amount yet.
//
// TODO(#22): expose DataChannel::buffered_amount() in the runtime.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetBufferedAmount(id: c_int) -> c_int {
    guard(|| if get_dc(id).is_none() { RTC_ERR_INVALID } else { 0 })
}

/// `rtcSetBufferedAmountLowThreshold`. The runtime does not expose a threshold
/// setter; accept and ignore for ABI completeness.
//
// TODO(#22): expose DataChannel::set_buffered_amount_low_threshold().
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetBufferedAmountLowThreshold(id: c_int, _amount: c_int) -> c_int {
    if get_dc(id).is_none() {
        RTC_ERR_INVALID
    } else {
        RTC_ERR_SUCCESS
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

/// `rtcGetAvailableAmount`. The runtime is push-based (`on_message`), so there
/// is no receive queue to report an available amount for.
//
// TODO(#22): expose a receive queue if a poll-based API is wanted.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetAvailableAmount(id: c_int) -> c_int {
    guard(|| if get_dc(id).is_none() { RTC_ERR_INVALID } else { 0 })
}

/// `rtcSetAvailableCallback`. No poll-based receive queue exists in the
/// runtime; accept and ignore.
//
// TODO(#22): wire when a poll-based receive queue lands.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetAvailableCallback(
    id: c_int,
    _cb: Option<RtcAvailableCallbackFunc>,
) -> c_int {
    if get_dc(id).is_none() {
        RTC_ERR_INVALID
    } else {
        RTC_ERR_SUCCESS
    }
}

/// `rtcReceiveMessage`. The runtime delivers messages via the push-based
/// `on_message` callback, not a poll-based queue, so there is nothing to
/// dequeue here.
//
// TODO(#22): expose DataChannel::peek()/receive() if a poll API is wanted.
#[unsafe(no_mangle)]
pub extern "C" fn rtcReceiveMessage(id: c_int, _buffer: *mut c_char, _size: *mut c_int) -> c_int {
    if get_dc(id).is_none() {
        RTC_ERR_INVALID
    } else {
        RTC_ERR_NOT_AVAIL
    }
}

// ===========================================================================
// Track + media handlers — NOT backed by the runtime yet
// ===========================================================================
//
// The runtime's `Track` is standalone: `PeerConnection` has no `addTrack` /
// `onTrack` integration (that lands in a later task). Per task #22's scope,
// every Track and RTCP-chain function therefore returns RTC_ERR_NOT_AVAIL with
// a TODO rather than fabricating a handle/result. They are still exported so
// node-datachannel links.

/// `rtcSetTrackCallback` — stub.
// TODO(#22): wire once PeerConnection::on_track lands.
#[unsafe(no_mangle)]
pub extern "C" fn rtcSetTrackCallback(pc: c_int, _cb: Option<RtcTrackCallbackFunc>) -> c_int {
    if get_pc(pc).is_none() {
        RTC_ERR_INVALID
    } else {
        RTC_ERR_NOT_AVAIL
    }
}

/// `rtcAddTrack` — stub.
// TODO(#22): wire once PeerConnection::add_track lands.
#[unsafe(no_mangle)]
pub extern "C" fn rtcAddTrack(pc: c_int, _media_description_sdp: *const c_char) -> c_int {
    if get_pc(pc).is_none() {
        RTC_ERR_INVALID
    } else {
        RTC_ERR_NOT_AVAIL
    }
}

/// `rtcAddTrackEx` — stub.
// TODO(#22): wire once PeerConnection::add_track lands.
#[unsafe(no_mangle)]
pub extern "C" fn rtcAddTrackEx(pc: c_int, _init: *const RtcTrackInit) -> c_int {
    if get_pc(pc).is_none() {
        RTC_ERR_INVALID
    } else {
        RTC_ERR_NOT_AVAIL
    }
}

/// `rtcDeleteTrack` — stub.
// TODO(#22): wire once tracks are registry-managed.
#[unsafe(no_mangle)]
pub extern "C" fn rtcDeleteTrack(_tr: c_int) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcGetTrackDescription` — stub.
// TODO(#22)
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetTrackDescription(_tr: c_int, _buffer: *mut c_char, _size: c_int) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcGetTrackMid` — stub.
// TODO(#22)
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetTrackMid(_tr: c_int, _buffer: *mut c_char, _size: c_int) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcGetTrackDirection` — stub.
// TODO(#22)
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetTrackDirection(_tr: c_int, _direction: *mut c_int) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcRequestKeyframe` — stub.
// TODO(#22)
#[unsafe(no_mangle)]
pub extern "C" fn rtcRequestKeyframe(_tr: c_int) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcRequestBitrate` — stub.
// TODO(#22)
#[unsafe(no_mangle)]
pub extern "C" fn rtcRequestBitrate(_tr: c_int, _bitrate: c_uint) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcChainRtcpReceivingSession` — stub.
// TODO(#22): requires Track registered on a PeerConnection.
#[unsafe(no_mangle)]
pub extern "C" fn rtcChainRtcpReceivingSession(_tr: c_int) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcChainRtcpSrReporter` — stub.
// TODO(#22)
#[unsafe(no_mangle)]
pub extern "C" fn rtcChainRtcpSrReporter(_tr: c_int) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcChainRtcpNackResponder` — stub.
// TODO(#22)
#[unsafe(no_mangle)]
pub extern "C" fn rtcChainRtcpNackResponder(_tr: c_int, _max_stored_packets: c_uint) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcChainPliHandler` — stub.
// TODO(#22)
#[unsafe(no_mangle)]
pub extern "C" fn rtcChainPliHandler(_tr: c_int, _cb: Option<RtcPliHandlerCallbackFunc>) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcChainRembHandler` — stub.
// TODO(#22)
#[unsafe(no_mangle)]
pub extern "C" fn rtcChainRembHandler(
    _tr: c_int,
    _cb: Option<RtcRembHandlerCallbackFunc>,
) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcChainPacingHandler` — stub.
// TODO(#22)
#[unsafe(no_mangle)]
pub extern "C" fn rtcChainPacingHandler(
    _tr: c_int,
    _bits_per_second: c_double,
    _send_interval_ms: c_int,
) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcTransformSecondsToTimestamp` — stub (needs a track's RTP config).
// TODO(#22)
#[unsafe(no_mangle)]
pub extern "C" fn rtcTransformSecondsToTimestamp(
    _id: c_int,
    _seconds: c_double,
    _timestamp: *mut u32,
) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcTransformTimestampToSeconds` — stub (needs a track's RTP config).
// TODO(#22)
#[unsafe(no_mangle)]
pub extern "C" fn rtcTransformTimestampToSeconds(
    _id: c_int,
    _timestamp: u32,
    _seconds: *mut c_double,
) -> c_int {
    RTC_ERR_NOT_AVAIL
}

// ===========================================================================
// WebSocket — NOT ported (return RTC_ERR_NOT_AVAIL)
// ===========================================================================

/// `rtcCreateWebSocket` — WebSocket is not ported.
#[unsafe(no_mangle)]
pub extern "C" fn rtcCreateWebSocket(_url: *const c_char) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcCreateWebSocketEx` — WebSocket is not ported.
#[unsafe(no_mangle)]
pub extern "C" fn rtcCreateWebSocketEx(_url: *const c_char, _config: *const c_void) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcDeleteWebSocket` — WebSocket is not ported.
#[unsafe(no_mangle)]
pub extern "C" fn rtcDeleteWebSocket(_ws: c_int) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcGetWebSocketRemoteAddress` — WebSocket is not ported.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetWebSocketRemoteAddress(
    _ws: c_int,
    _buffer: *mut c_char,
    _size: c_int,
) -> c_int {
    RTC_ERR_NOT_AVAIL
}

/// `rtcGetWebSocketPath` — WebSocket is not ported.
#[unsafe(no_mangle)]
pub extern "C" fn rtcGetWebSocketPath(_ws: c_int, _buffer: *mut c_char, _size: c_int) -> c_int {
    RTC_ERR_NOT_AVAIL
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
            RtcObject::Tr(_) => {}
        }
    }
    USER_POINTERS.lock().clear();
    PC_SLOTS.lock().clear();
    DC_SLOTS.lock().clear();
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
        assert!(rtcIsClosed(999_999)); // unknown => closed
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
        assert!(a > 0 && b > 0 && a != b, "handles must be distinct: {a}, {b}");
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

    #[test]
    fn track_and_websocket_stubs_report_not_avail() {
        let bind = CString::new("127.0.0.1").unwrap();
        let cfg = loopback_config(&bind);
        let pc = rtcCreatePeerConnection(&cfg);

        assert_eq!(
            rtcAddTrack(pc, CString::new("m=video 9 ...").unwrap().as_ptr()),
            RTC_ERR_NOT_AVAIL
        );
        assert_eq!(rtcSetTrackCallback(pc, None), RTC_ERR_NOT_AVAIL);
        assert_eq!(rtcDeleteTrack(123), RTC_ERR_NOT_AVAIL);
        assert_eq!(rtcChainRtcpReceivingSession(123), RTC_ERR_NOT_AVAIL);

        let url = CString::new("ws://localhost").unwrap();
        assert_eq!(rtcCreateWebSocket(url.as_ptr()), RTC_ERR_NOT_AVAIL);

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
        extern "C" fn on_cand_a(_pc: c_int, cand: *const c_char, mid: *const c_char, ptr: *mut c_void) {
            let c = unsafe { &*(ptr as *const Ctx) };
            let cand = unsafe { CStr::from_ptr(cand) }.to_owned();
            let mid = unsafe { CStr::from_ptr(mid) }.to_owned();
            c.a_cands.lock().push((cand, mid));
        }
        extern "C" fn on_cand_b(_pc: c_int, cand: *const c_char, mid: *const c_char, ptr: *mut c_void) {
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

            assert_eq!(rtcSetStateChangeCallback(pc_a, Some(on_state_a)), RTC_ERR_SUCCESS);
            assert_eq!(rtcSetStateChangeCallback(pc_b, Some(on_state_b)), RTC_ERR_SUCCESS);
            assert_eq!(rtcSetLocalCandidateCallback(pc_a, Some(on_cand_a)), RTC_ERR_SUCCESS);
            assert_eq!(rtcSetLocalCandidateCallback(pc_b, Some(on_cand_b)), RTC_ERR_SUCCESS);
            assert_eq!(rtcSetDataChannelCallback(pc_b, Some(on_dc_b)), RTC_ERR_SUCCESS);

            // A creates the channel.
            let dc_a = rtcCreateDataChannel(pc_a, CString::new("chat").unwrap().as_ptr());
            assert!(dc_a > 0);

            // Offer/answer via the C API.
            assert_eq!(rtcSetLocalDescription(pc_a, std::ptr::null()), RTC_ERR_SUCCESS);

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
            assert_eq!(rtcGetLocalDescription(pc_a, buf.as_mut_ptr(), needed), needed);
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
            assert_eq!(rtcGetLocalDescription(pc_b, buf.as_mut_ptr(), needed), needed);
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
                rtcSendMessage(dc_a, payload.as_ptr() as *const c_char, payload.len() as c_int),
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
}
