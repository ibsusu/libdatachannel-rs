//! DTLS-SRTP transport — port of `rtc::impl::DtlsSrtpTransport` from
//! `native/libdatachannel/src/impl/dtlssrtptransport.cpp`, layering SRTP
//! (RFC 3711) on top of [`crate::DtlsTransport`] via the vendored libsrtp2 C
//! library through FFI ([`crate::srtp_sys`]).
//!
//! ## What this is
//!
//! WebRTC media (audio/video) flows as SRTP/SRTCP multiplexed onto the **same**
//! transport as the DTLS handshake (RFC 5764). The DTLS handshake negotiates a
//! `use_srtp` extension; once it completes, both sides export keying material
//! via `SSL_export_keying_material` and feed it into libsrtp2 to protect /
//! unprotect the media stream. The DTLS records and the SRTP packets are
//! demultiplexed by inspecting the first byte (RFC 5764 §5.1.2).
//!
//! ## Architecture (mirrors [`crate::SctpTransport`])
//!
//! The transport is an `Arc<Self>` holding the lower [`DtlsTransport`], the two
//! libsrtp2 sessions (`*mut srtp_ctx_t` for inbound + outbound) behind a single
//! [`parking_lot::Mutex<Inner>`] with a hand-written `unsafe impl Send`, an
//! [`AtomicBool`] `init_done` guard, a `closed` guard, and a
//! `Mutex<SrtpTransportCallbacks>`.
//!
//! On construction we snapshot the DTLS callbacks and chain them: our
//! `on_state_change` derives the SRTP keys when DTLS reaches
//! [`DtlsState::Connected`] (the auto-derive hook, analogous to SCTP's
//! auto-connect); our `on_data` demuxes inbound records — DTLS records are
//! forwarded to the previous handler (so a layered DataChannel/SCTP path still
//! works), media packets are `srtp_unprotect`'d and surfaced via `on_rtp` /
//! `on_rtcp`. The `use_srtp` extension is set on the DTLS `SSL` **before** the
//! handshake via [`DtlsTransport::set_srtp_profiles`].
//!
//! ## libsrtp2 backend
//!
//! libsrtp2 is compiled with its OpenSSL crypto backend (see `build.rs`),
//! giving both `SRTP_AES128_CM_SHA1_80` and `SRTP_AEAD_AES_128_GCM` — the two
//! profiles this transport negotiates by default. `srtp_init()` runs once via a
//! global [`Once`], mirroring usrsctp's init in [`crate::SctpTransport`].

use std::ffi::{c_int, c_void, CStr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};

use parking_lot::Mutex;
use thiserror::Error;
use tracing::{trace, warn};

use crate::dtls_transport::{DtlsState, DtlsTransportCallbacks};
use crate::srtp_sys as sys;
use crate::DtlsTransport;

// ---------------------------------------------------------------------------
// Constants from libsrtp2 + RFC 5764 (most come straight from bindgen).
// ---------------------------------------------------------------------------

/// RFC 5764 §4.2 label fed to the DTLS keying-material exporter.
const SRTP_EXTRACTOR_LABEL: &str = "EXTRACTOR-dtls_srtp";

/// Default SRTP profile list offered on the DTLS `use_srtp` extension. Matches
/// the C++ `DtlsSrtpTransport`: prefer AES-GCM, fall back to AES-CM-SHA1-80.
pub const DEFAULT_SRTP_PROFILES: &str = "SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80";

/// `srtp_err_status_ok` (0), the libsrtp2 success code.
const SRTP_OK: sys::srtp_err_status_t = sys::srtp_err_status_t_srtp_err_status_ok;

// ---------------------------------------------------------------------------
// Global libsrtp2 init (mirrors usrsctp_global_init / C++ DtlsSrtpTransport::Init)
// ---------------------------------------------------------------------------

static SRTP_INIT: Once = Once::new();
static SRTP_INIT_OK: AtomicBool = AtomicBool::new(false);

/// Run the one-time global `srtp_init()`. Mirrors the C++
/// `DtlsSrtpTransport::Init`. Idempotent; safe to call from any number of
/// transports.
fn srtp_global_init() {
    SRTP_INIT.call_once(|| {
        let st = unsafe { sys::srtp_init() };
        SRTP_INIT_OK.store(st == SRTP_OK, Ordering::SeqCst);
        if st != SRTP_OK {
            warn!("srtp_init() failed, status={st}");
        }
    });
}

// ---------------------------------------------------------------------------
// Profile parameters (port of getProfileParamsFromName)
// ---------------------------------------------------------------------------

/// libsrtp2 profile + master-key/salt lengths derived from the OpenSSL profile
/// name negotiated on the wire. Mirrors
/// `DtlsSrtpTransport::getProfileParamsFromName`.
#[derive(Debug, Clone, Copy)]
struct ProfileParams {
    profile: sys::srtp_profile_t,
    key_len: usize,
    salt_len: usize,
}

fn profile_params_from_name(name: &str) -> Option<ProfileParams> {
    let key128 = sys::SRTP_AES_128_KEY_LEN as usize;
    let key256 = sys::SRTP_AES_256_KEY_LEN as usize;
    let salt = sys::SRTP_SALT_LEN as usize;
    let aead_salt = sys::SRTP_AEAD_SALT_LEN as usize;
    Some(match name {
        "SRTP_AES128_CM_SHA1_80" => ProfileParams {
            profile: sys::srtp_profile_t_srtp_profile_aes128_cm_sha1_80,
            key_len: key128,
            salt_len: salt,
        },
        "SRTP_AES128_CM_SHA1_32" => ProfileParams {
            profile: sys::srtp_profile_t_srtp_profile_aes128_cm_sha1_32,
            key_len: key128,
            salt_len: salt,
        },
        "SRTP_AEAD_AES_128_GCM" => ProfileParams {
            profile: sys::srtp_profile_t_srtp_profile_aead_aes_128_gcm,
            key_len: key128,
            salt_len: aead_salt,
        },
        "SRTP_AEAD_AES_256_GCM" => ProfileParams {
            profile: sys::srtp_profile_t_srtp_profile_aead_aes_256_gcm,
            key_len: key256,
            salt_len: aead_salt,
        },
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// Callbacks the [`SrtpTransport`] invokes.
#[derive(Clone)]
pub struct SrtpTransportCallbacks {
    /// Fires for each successfully-unprotected inbound RTP packet (cleartext
    /// RTP bytes).
    pub on_rtp: Arc<dyn Fn(&[u8]) + Send + Sync>,
    /// Fires for each successfully-unprotected inbound RTCP packet (cleartext
    /// RTCP bytes).
    pub on_rtcp: Arc<dyn Fn(&[u8]) + Send + Sync>,
    /// Fires on each lower DTLS state transition (forwarded). Lets the
    /// application observe Connected / Failed / Closed on the media transport.
    pub on_state_change: Arc<dyn Fn(DtlsState) + Send + Sync>,
}

impl Default for SrtpTransportCallbacks {
    fn default() -> Self {
        SrtpTransportCallbacks {
            on_rtp: Arc::new(|_| {}),
            on_rtcp: Arc::new(|_| {}),
            on_state_change: Arc::new(|_| {}),
        }
    }
}

/// Errors returned by [`SrtpTransport`] operations.
#[derive(Debug, Error)]
pub enum SrtpTransportError {
    /// `srtp_init()` failed at process start.
    #[error("srtp_init failed")]
    InitFailed,

    /// A libsrtp2 FFI call returned a non-ok status. Carries the operation
    /// name and the raw `srtp_err_status_t`.
    #[error("libsrtp2 error in {0}: status {1}")]
    Srtp(&'static str, u32),

    /// Keys have not been derived yet (the DTLS handshake has not completed,
    /// or no SRTP profile was negotiated).
    #[error("srtp keys not derived (DTLS not connected / no profile)")]
    NotReady,

    /// The negotiated SRTP profile name is not one we support.
    #[error("unsupported SRTP profile: {0}")]
    UnsupportedProfile(String),

    /// Operation called on a closed transport.
    #[error("srtp transport closed")]
    Closed,

    /// Forwarded from the lower [`DtlsTransport`].
    #[error("dtls transport: {0}")]
    Dtls(#[from] crate::DtlsTransportError),
}

/// Inner mutable state guarded by the transport's `Mutex`. Owns the two
/// libsrtp2 sessions and the derived master-key buffers (which libsrtp2 copies
/// at `srtp_add_stream` time, but we keep them alive for the duration of the
/// add to be safe).
struct Inner {
    /// Inbound (unprotect) session. Null until keys are derived.
    srtp_in: sys::srtp_t,
    /// Outbound (protect) session. Null until keys are derived.
    srtp_out: sys::srtp_t,
    /// Client write key||salt (kept alive across `srtp_add_stream`).
    client_key: Vec<u8>,
    /// Server write key||salt.
    server_key: Vec<u8>,
}

// Safety: `Inner` is only ever touched while the surrounding Mutex is held.
// The raw `srtp_t` pointers are owned by this transport and freed via
// `srtp_dealloc` on `close()` / `Drop`. libsrtp2 sessions are not shared
// across transports and have no callbacks reaching back into Rust.
unsafe impl Send for Inner {}

/// The DTLS-SRTP transport. Cheap to clone via the surrounding `Arc<Self>`,
/// matching the [`DtlsTransport`] / [`crate::SctpTransport`] pattern.
pub struct SrtpTransport {
    /// Lower transport. We install our `on_data` demux + `on_state_change`
    /// key-derivation hook on it, and push protected media through
    /// `dtls.send_media()` (see [`Self::send_rtp`]).
    dtls: Arc<DtlsTransport>,
    /// libsrtp2 sessions + key buffers.
    inner: Mutex<Inner>,
    /// Set once keys are derived (DTLS Connected → [`Self::derive_keys`]).
    init_done: AtomicBool,
    /// Set once [`close`](Self::close) runs.
    closed: AtomicBool,
    /// Guards [`derive_keys`](Self::derive_keys) against double-driving when
    /// the auto-derive hook and an explicit call race.
    derive_started: AtomicBool,
    /// Application-installed callbacks.
    callbacks: Mutex<SrtpTransportCallbacks>,
    /// True if this side is the DTLS client (Active role). Decides which half
    /// of the exported material is the local (outbound) key.
    is_client: bool,
}

impl std::fmt::Debug for SrtpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrtpTransport")
            .field("init_done", &self.init_done.load(Ordering::SeqCst))
            .field("is_client", &self.is_client)
            .finish()
    }
}

impl SrtpTransport {
    /// Build the DTLS-SRTP transport over a [`DtlsTransport`], offering
    /// [`DEFAULT_SRTP_PROFILES`].
    ///
    /// The constructor:
    /// 1. Runs the one-time global `srtp_init()`.
    /// 2. Creates the two empty libsrtp2 sessions (`srtp_create(.., NULL)`),
    ///    matching the C++ constructor.
    /// 3. Sets the `use_srtp` extension on the DTLS `SSL` via
    ///    [`DtlsTransport::set_srtp_profiles`] — this MUST happen before the
    ///    DTLS handshake starts.
    /// 4. Chains the DTLS callbacks: `on_state_change` auto-derives keys when
    ///    DTLS reaches [`DtlsState::Connected`]; `on_data` demuxes DTLS vs
    ///    media (RFC 5764 §5.1.2) and unprotects media into `on_rtp`/`on_rtcp`.
    ///
    /// You must call this **before** the DTLS handshake starts (i.e. before
    /// ICE reaches Connected, which auto-starts DTLS), so the `use_srtp`
    /// extension is present on the ClientHello/ServerHello. If the DTLS layer
    /// is already Connected, the keys are derived immediately.
    pub fn new(
        dtls: Arc<DtlsTransport>,
        callbacks: SrtpTransportCallbacks,
    ) -> Result<Arc<Self>, SrtpTransportError> {
        Self::with_profiles(dtls, callbacks, DEFAULT_SRTP_PROFILES)
    }

    /// Like [`new`](Self::new) but with a caller-chosen OpenSSL SRTP profile
    /// list (colon-separated, e.g. `"SRTP_AES128_CM_SHA1_80"`).
    pub fn with_profiles(
        dtls: Arc<DtlsTransport>,
        callbacks: SrtpTransportCallbacks,
        profiles: &str,
    ) -> Result<Arc<Self>, SrtpTransportError> {
        srtp_global_init();
        if !SRTP_INIT_OK.load(Ordering::SeqCst) {
            return Err(SrtpTransportError::InitFailed);
        }

        // Create the two empty sessions up front (C++ ctor does this).
        let (srtp_in, srtp_out) = unsafe {
            let mut srtp_in: sys::srtp_t = std::ptr::null_mut();
            let st = sys::srtp_create(&mut srtp_in, std::ptr::null());
            if st != SRTP_OK {
                return Err(SrtpTransportError::Srtp("srtp_create(in)", st));
            }
            let mut srtp_out: sys::srtp_t = std::ptr::null_mut();
            let st = sys::srtp_create(&mut srtp_out, std::ptr::null());
            if st != SRTP_OK {
                sys::srtp_dealloc(srtp_in);
                return Err(SrtpTransportError::Srtp("srtp_create(out)", st));
            }
            (srtp_in, srtp_out)
        };

        let is_client = dtls.is_client();

        // Set the use_srtp extension BEFORE the handshake.
        dtls.set_srtp_profiles(profiles)?;

        let transport = Arc::new(SrtpTransport {
            dtls: Arc::clone(&dtls),
            inner: Mutex::new(Inner {
                srtp_in,
                srtp_out,
                client_key: Vec::new(),
                server_key: Vec::new(),
            }),
            init_done: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            derive_started: AtomicBool::new(false),
            callbacks: Mutex::new(callbacks),
            is_client,
        });

        // Chain the DTLS callbacks: key-derivation hook + media demux.
        let prev = dtls.callbacks();
        let weak = Arc::downgrade(&transport);

        let new_on_state_change = {
            let prev_state = Arc::clone(&prev.on_state_change);
            let weak = weak.clone();
            Arc::new(move |s: DtlsState| {
                if matches!(s, DtlsState::Connected) {
                    if let Some(this) = weak.upgrade() {
                        // Derive OFF this thread. This callback fires from
                        // `drive_handshake_locked` with the DTLS inner mutex
                        // held, and `derive_keys` calls back into
                        // `selected_srtp_profile` / `export_keying_material`,
                        // which re-lock that same (non-reentrant) mutex —
                        // doing it inline deadlocks. Mirrors the SCTP
                        // auto-connect hook, which enqueues onto a worker
                        // thread for the same reason. `derive_keys` is
                        // idempotent (guarded by `derive_started`).
                        std::thread::Builder::new()
                            .name("srtp-derive".into())
                            .spawn(move || {
                                if let Err(e) = this.derive_keys() {
                                    warn!("SrtpTransport: key derivation failed: {e}");
                                }
                            })
                            .expect("spawn srtp-derive thread");
                    }
                }
                // Forward the lower state change to our own observers and to
                // the previously-installed handler.
                if let Some(this) = weak.upgrade() {
                    let cb = {
                        let g = this.callbacks.lock();
                        Arc::clone(&g.on_state_change)
                    };
                    (cb)(s);
                }
                (prev_state)(s);
            })
        };

        let new_on_data = {
            let prev_data = Arc::clone(&prev.on_data);
            let weak = weak.clone();
            Arc::new(move |data: &[u8]| {
                // Demux: media packets are consumed here; everything else
                // (DTLS records — though the DTLS layer already decrypted
                // these before calling on_data — and unknown) falls through
                // to the previously-installed handler so a layered SCTP /
                // DataChannel path keeps working.
                if let Some(this) = weak.upgrade() {
                    if this.demux_inbound(data) {
                        return;
                    }
                }
                (prev_data)(data);
            })
        };

        dtls.set_callbacks(DtlsTransportCallbacks {
            on_state_change: new_on_state_change,
            on_data: new_on_data,
        });

        // If DTLS is already Connected (rare: SRTP layered after handshake),
        // derive immediately.
        if matches!(dtls.state(), DtlsState::Connected) {
            if let Err(e) = transport.derive_keys() {
                warn!("SrtpTransport: immediate key derivation failed: {e}");
            }
        }

        Ok(transport)
    }

    /// True once the SRTP keys have been derived (after the DTLS handshake).
    pub fn is_ready(&self) -> bool {
        self.init_done.load(Ordering::SeqCst)
    }

    /// The negotiated SRTP profile name, if the handshake selected one.
    pub fn selected_profile(&self) -> Option<String> {
        self.dtls.selected_srtp_profile()
    }

    /// Derive the SRTP master keys from the completed DTLS handshake and add
    /// the inbound/outbound streams to the libsrtp2 sessions.
    ///
    /// Port of `DtlsSrtpTransport::postHandshake` (OpenSSL branch): get the
    /// selected profile, `SSL_export_keying_material` 2×(key+salt) bytes under
    /// the `"EXTRACTOR-dtls_srtp"` label, split into client/server (key, salt)
    /// per RFC 5764, then `srtp_add_stream` for inbound (remote key) and
    /// outbound (local key) using the role to pick which half is local.
    ///
    /// Idempotent via `derive_started`.
    pub fn derive_keys(&self) -> Result<(), SrtpTransportError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SrtpTransportError::Closed);
        }
        if self.derive_started.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let profile_name = self
            .dtls
            .selected_srtp_profile()
            .ok_or(SrtpTransportError::NotReady)?;
        let params = profile_params_from_name(&profile_name)
            .ok_or_else(|| SrtpTransportError::UnsupportedProfile(profile_name.clone()))?;

        let key_size = params.key_len;
        let salt_size = params.salt_len;
        let key_with_salt = key_size + salt_size;

        // Export client_key || server_key || client_salt || server_salt.
        let material_len = key_with_salt * 2;
        let mut material = vec![0u8; material_len];
        self.dtls
            .export_keying_material(&mut material, SRTP_EXTRACTOR_LABEL)?;

        // RFC 5764 layout: client write key, server write key, client salt,
        // server salt — in that order.
        let client_key = &material[0..key_size];
        let server_key = &material[key_size..2 * key_size];
        let client_salt = &material[2 * key_size..2 * key_size + salt_size];
        let server_salt = &material[2 * key_size + salt_size..2 * key_size + 2 * salt_size];

        // Pack key||salt the way libsrtp2 expects a master key buffer.
        let mut client_session_key = Vec::with_capacity(key_with_salt);
        client_session_key.extend_from_slice(client_key);
        client_session_key.extend_from_slice(client_salt);
        let mut server_session_key = Vec::with_capacity(key_with_salt);
        server_session_key.extend_from_slice(server_key);
        server_session_key.extend_from_slice(server_salt);

        trace!(
            profile = %profile_name,
            is_client = self.is_client,
            "SrtpTransport: deriving keys"
        );

        let mut g = self.inner.lock();
        g.client_key = client_session_key;
        g.server_key = server_session_key;

        // inbound = remote write key (client unprotects with server key, and
        // vice-versa); outbound = local write key.
        let inbound_key_ptr = if self.is_client {
            g.server_key.as_ptr()
        } else {
            g.client_key.as_ptr()
        } as *mut u8;
        let outbound_key_ptr = if self.is_client {
            g.client_key.as_ptr()
        } else {
            g.server_key.as_ptr()
        } as *mut u8;

        // Build + add inbound stream.
        let inbound = make_policy(
            params.profile,
            sys::srtp_ssrc_type_t_ssrc_any_inbound,
            inbound_key_ptr,
        )?;
        let st = unsafe { sys::srtp_add_stream(g.srtp_in, &inbound) };
        if st != SRTP_OK {
            return Err(SrtpTransportError::Srtp("srtp_add_stream(in)", st));
        }

        // Build + add outbound stream.
        let outbound = make_policy(
            params.profile,
            sys::srtp_ssrc_type_t_ssrc_any_outbound,
            outbound_key_ptr,
        )?;
        let st = unsafe { sys::srtp_add_stream(g.srtp_out, &outbound) };
        if st != SRTP_OK {
            return Err(SrtpTransportError::Srtp("srtp_add_stream(out)", st));
        }

        drop(g);
        self.init_done.store(true, Ordering::SeqCst);
        Ok(())
    }

    // ---- protect / unprotect --------------------------------------------

    /// Protect (encrypt + authenticate) an RTP packet in place, returning the
    /// SRTP packet. The output is longer than the input by up to the auth tag;
    /// callers pass an owned `Vec` we can grow. Mirrors the `srtp_protect`
    /// path of `DtlsSrtpTransport::sendMedia`.
    pub fn protect_rtp(&self, mut packet: Vec<u8>) -> Result<Vec<u8>, SrtpTransportError> {
        self.protect_inner(&mut packet, false)?;
        Ok(packet)
    }

    /// Protect an RTCP packet in place. See [`protect_rtp`](Self::protect_rtp).
    pub fn protect_rtcp(&self, mut packet: Vec<u8>) -> Result<Vec<u8>, SrtpTransportError> {
        self.protect_inner(&mut packet, true)?;
        Ok(packet)
    }

    fn protect_inner(&self, packet: &mut Vec<u8>, rtcp: bool) -> Result<(), SrtpTransportError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SrtpTransportError::Closed);
        }
        if !self.init_done.load(Ordering::SeqCst) {
            return Err(SrtpTransportError::NotReady);
        }
        let mut size = packet.len() as c_int;
        // srtp_protect{,_rtcp} writes up to SRTP_MAX_TRAILER_LEN extra bytes
        // (the auth tag) immediately after the packet — reserve that room.
        packet.resize(packet.len() + sys::SRTP_MAX_TRAILER_LEN as usize, 0);
        let g = self.inner.lock();
        let ctx = g.srtp_out;
        let st = unsafe {
            if rtcp {
                sys::srtp_protect_rtcp(ctx, packet.as_mut_ptr() as *mut c_void, &mut size)
            } else {
                sys::srtp_protect(ctx, packet.as_mut_ptr() as *mut c_void, &mut size)
            }
        };
        drop(g);
        if st != SRTP_OK {
            let op = if rtcp { "srtp_protect_rtcp" } else { "srtp_protect" };
            return Err(SrtpTransportError::Srtp(op, st));
        }
        packet.truncate(size as usize);
        Ok(())
    }

    /// Unprotect (verify + decrypt) an inbound SRTP packet in place, returning
    /// the cleartext RTP. Mirrors the `srtp_unprotect` path of
    /// `DtlsSrtpTransport::recvMedia`.
    pub fn unprotect_rtp(&self, mut packet: Vec<u8>) -> Result<Vec<u8>, SrtpTransportError> {
        self.unprotect_inner(&mut packet, false)?;
        Ok(packet)
    }

    /// Unprotect an inbound SRTCP packet in place. See
    /// [`unprotect_rtp`](Self::unprotect_rtp).
    pub fn unprotect_rtcp(&self, mut packet: Vec<u8>) -> Result<Vec<u8>, SrtpTransportError> {
        self.unprotect_inner(&mut packet, true)?;
        Ok(packet)
    }

    fn unprotect_inner(&self, packet: &mut Vec<u8>, rtcp: bool) -> Result<(), SrtpTransportError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SrtpTransportError::Closed);
        }
        if !self.init_done.load(Ordering::SeqCst) {
            return Err(SrtpTransportError::NotReady);
        }
        let mut size = packet.len() as c_int;
        let g = self.inner.lock();
        let ctx = g.srtp_in;
        let st = unsafe {
            if rtcp {
                sys::srtp_unprotect_rtcp(ctx, packet.as_mut_ptr() as *mut c_void, &mut size)
            } else {
                sys::srtp_unprotect(ctx, packet.as_mut_ptr() as *mut c_void, &mut size)
            }
        };
        drop(g);
        if st != SRTP_OK {
            let op = if rtcp { "srtp_unprotect_rtcp" } else { "srtp_unprotect" };
            return Err(SrtpTransportError::Srtp(op, st));
        }
        packet.truncate(size as usize);
        Ok(())
    }

    /// Protect an RTP/RTCP packet and push it down through the DTLS transport's
    /// raw send path. The packet is demuxed to RTP vs RTCP automatically (RFC
    /// 5761). Convenience wrapper combining `protect_*` with a transport send.
    ///
    /// NOTE: this routes the protected bytes through [`DtlsTransport::send`],
    /// which encrypts them as a DTLS application record. In a full WebRTC
    /// media stack the protected SRTP packet would instead go straight onto
    /// the ICE transport (multiplexed alongside DTLS); that lower-level
    /// `outgoing()` seam is a follow-up. For the loopback this exercises the
    /// protect path end-to-end.
    pub fn send_media(&self, packet: Vec<u8>) -> Result<(), SrtpTransportError> {
        let protected = if is_rtcp(&packet) {
            self.protect_rtcp(packet)?
        } else {
            self.protect_rtp(packet)?
        };
        self.dtls.send(&protected)?;
        Ok(())
    }

    /// Demux an inbound record per RFC 5764 §5.1.2 and, if it is media,
    /// unprotect it and surface it via `on_rtp` / `on_rtcp`. Returns `true` if
    /// the packet was consumed as media, `false` if it should fall through to
    /// the previously-installed `on_data` handler (DTLS / SCTP path).
    fn demux_inbound(&self, data: &[u8]) -> bool {
        if !self.init_done.load(Ordering::SeqCst) {
            return false;
        }
        if data.is_empty() {
            return false;
        }
        let first = data[0];
        // 20..=63 → DTLS, 128..=191 → RTP/RTCP (RFC 5764 §5.1.2).
        if (20..=63).contains(&first) {
            return false; // DTLS record — let the lower path handle it.
        }
        if !(128..=191).contains(&first) {
            trace!(value = first, "SrtpTransport: unknown packet type, dropping");
            return true; // consume (and drop) unknown media-range bytes
        }
        // Media. An RTCP packet is >= 8 bytes, RTP >= 12.
        if data.len() < 8 {
            trace!("SrtpTransport: media packet too short, dropping");
            return true;
        }
        let rtcp = is_rtcp(data);
        let res = if rtcp {
            self.unprotect_rtcp(data.to_vec())
        } else {
            self.unprotect_rtp(data.to_vec())
        };
        match res {
            Ok(plain) => {
                let cb = {
                    let g = self.callbacks.lock();
                    if rtcp {
                        Arc::clone(&g.on_rtcp)
                    } else {
                        Arc::clone(&g.on_rtp)
                    }
                };
                (cb)(&plain);
            }
            Err(e) => {
                trace!("SrtpTransport: unprotect failed: {e}");
            }
        }
        true
    }

    /// Swap the callback set at runtime.
    pub fn set_callbacks(&self, callbacks: SrtpTransportCallbacks) {
        *self.callbacks.lock() = callbacks;
    }

    /// Snapshot of the currently-installed callback set.
    pub fn callbacks(&self) -> SrtpTransportCallbacks {
        let g = self.callbacks.lock();
        SrtpTransportCallbacks {
            on_rtp: Arc::clone(&g.on_rtp),
            on_rtcp: Arc::clone(&g.on_rtcp),
            on_state_change: Arc::clone(&g.on_state_change),
        }
    }

    /// Close the transport: deallocate both libsrtp2 sessions. Idempotent.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut g = self.inner.lock();
        unsafe {
            if !g.srtp_in.is_null() {
                sys::srtp_dealloc(g.srtp_in);
                g.srtp_in = std::ptr::null_mut();
            }
            if !g.srtp_out.is_null() {
                sys::srtp_dealloc(g.srtp_out);
                g.srtp_out = std::ptr::null_mut();
            }
        }
    }
}

impl Drop for SrtpTransport {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::SeqCst) {
            let mut g = self.inner.lock();
            unsafe {
                if !g.srtp_in.is_null() {
                    sys::srtp_dealloc(g.srtp_in);
                    g.srtp_in = std::ptr::null_mut();
                }
                if !g.srtp_out.is_null() {
                    sys::srtp_dealloc(g.srtp_out);
                    g.srtp_out = std::ptr::null_mut();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Build an `srtp_policy_t` for one direction. Mirrors the C++ `postHandshake`
/// policy setup: profile-derived RTP+RTCP crypto policies, the given SSRC
/// wildcard type, window 1024, allow_repeat_tx, the master key, and a NULL
/// `next`.
fn make_policy(
    profile: sys::srtp_profile_t,
    ssrc_type: sys::srtp_ssrc_type_t,
    key: *mut u8,
) -> Result<sys::srtp_policy_t, SrtpTransportError> {
    let mut policy: sys::srtp_policy_t = unsafe { std::mem::zeroed() };
    unsafe {
        let st = sys::srtp_crypto_policy_set_from_profile_for_rtp(&mut policy.rtp, profile);
        if st != SRTP_OK {
            return Err(SrtpTransportError::Srtp("crypto_policy_set_rtp", st));
        }
        let st = sys::srtp_crypto_policy_set_from_profile_for_rtcp(&mut policy.rtcp, profile);
        if st != SRTP_OK {
            return Err(SrtpTransportError::Srtp("crypto_policy_set_rtcp", st));
        }
    }
    policy.ssrc.type_ = ssrc_type;
    policy.ssrc.value = 0;
    policy.key = key;
    policy.window_size = 1024;
    policy.allow_repeat_tx = 1;
    policy.next = std::ptr::null_mut();
    Ok(policy)
}

/// RFC 5761 RTP/RTCP demux: a packet whose payload-type byte (`data[1] &
/// 0x7F`) is in 64..=95 is RTCP. Port of `rtc::IsRtcp`.
fn is_rtcp(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    let payload_type = data[1] & 0x7F;
    (64..=95).contains(&payload_type)
}

/// The libsrtp2 version string, for diagnostics. (Touches the FFI so the
/// linker keeps a reference even if no transport is constructed in a build.)
pub fn srtp_version() -> String {
    // `srtp_get_version_string` returns a static C string.
    unsafe {
        let p = sys::srtp_get_version_string();
        if p.is_null() {
            return String::new();
        }
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::Ordering;

    use crate::certificate::Certificate;
    use crate::configuration::Configuration;
    use crate::description::{FingerprintAlgorithm, Role};
    use crate::dtls_transport::DtlsTransportCallbacks;
    use crate::ice_transport::{IceTransport, IceTransportCallbacks};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Build a minimal RTP packet: version 2, given payload type + ssrc.
    fn rtp_packet(payload_type: u8, seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(12 + payload.len());
        p.push(0x80); // V=2, P=0, X=0, CC=0
        p.push(payload_type & 0x7F); // M=0, PT
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    /// Known-key SRTP round-trip: prove the libsrtp2 FFI links and that a
    /// protect → unprotect round-trips an RTP packet under a fixed key, with
    /// NO DTLS involved. This is the minimal "the C library works" test.
    #[test]
    fn known_key_protect_unprotect_round_trips() {
        srtp_global_init();
        assert!(SRTP_INIT_OK.load(Ordering::SeqCst), "srtp_init failed");

        // 30-byte master key||salt for AES_CM_128_SHA1_80 (16 key + 14 salt).
        let master: [u8; 30] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e,
        ];

        let profile = sys::srtp_profile_t_srtp_profile_aes128_cm_sha1_80;

        // Sender session (outbound), receiver session (inbound) with the SAME
        // key — like a single SRTP context protecting then unprotecting.
        let mut send_key = master.to_vec();
        let mut recv_key = master.to_vec();

        let send = unsafe {
            let mut s: sys::srtp_t = std::ptr::null_mut();
            assert_eq!(sys::srtp_create(&mut s, std::ptr::null()), SRTP_OK);
            let pol = make_policy(
                profile,
                sys::srtp_ssrc_type_t_ssrc_any_outbound,
                send_key.as_mut_ptr(),
            )
            .unwrap();
            assert_eq!(sys::srtp_add_stream(s, &pol), SRTP_OK);
            s
        };
        let recv = unsafe {
            let mut s: sys::srtp_t = std::ptr::null_mut();
            assert_eq!(sys::srtp_create(&mut s, std::ptr::null()), SRTP_OK);
            let pol = make_policy(
                profile,
                sys::srtp_ssrc_type_t_ssrc_any_inbound,
                recv_key.as_mut_ptr(),
            )
            .unwrap();
            assert_eq!(sys::srtp_add_stream(s, &pol), SRTP_OK);
            s
        };

        let original = rtp_packet(96, 1000, 0xdead_beef, b"the quick brown fox");

        // Protect.
        let mut buf = original.clone();
        let plain_len = buf.len() as c_int;
        buf.resize(buf.len() + sys::SRTP_MAX_TRAILER_LEN as usize, 0);
        let mut size = plain_len;
        let st = unsafe {
            sys::srtp_protect(send, buf.as_mut_ptr() as *mut c_void, &mut size)
        };
        assert_eq!(st, SRTP_OK, "srtp_protect failed");
        buf.truncate(size as usize);
        assert!(
            buf.len() > original.len(),
            "protected packet should grow by the auth tag"
        );
        assert_ne!(&buf[12..], &original[12..], "payload must be encrypted");

        // Unprotect.
        let mut size2 = buf.len() as c_int;
        let st = unsafe {
            sys::srtp_unprotect(recv, buf.as_mut_ptr() as *mut c_void, &mut size2)
        };
        assert_eq!(st, SRTP_OK, "srtp_unprotect failed");
        buf.truncate(size2 as usize);
        assert_eq!(buf, original, "round-tripped packet must equal the original");

        unsafe {
            sys::srtp_dealloc(send);
            sys::srtp_dealloc(recv);
        }
    }

    /// AEAD GCM variant of the known-key round-trip — proves the OpenSSL GCM
    /// backend is compiled in and works (key||salt = 16 + 12).
    #[test]
    fn known_key_gcm_protect_unprotect_round_trips() {
        srtp_global_init();
        assert!(SRTP_INIT_OK.load(Ordering::SeqCst));

        let master: [u8; 28] = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        ];
        let profile = sys::srtp_profile_t_srtp_profile_aead_aes_128_gcm;

        let mut send_key = master.to_vec();
        let mut recv_key = master.to_vec();
        let send = unsafe {
            let mut s: sys::srtp_t = std::ptr::null_mut();
            assert_eq!(sys::srtp_create(&mut s, std::ptr::null()), SRTP_OK);
            let pol = make_policy(profile, sys::srtp_ssrc_type_t_ssrc_any_outbound, send_key.as_mut_ptr()).unwrap();
            assert_eq!(sys::srtp_add_stream(s, &pol), SRTP_OK);
            s
        };
        let recv = unsafe {
            let mut s: sys::srtp_t = std::ptr::null_mut();
            assert_eq!(sys::srtp_create(&mut s, std::ptr::null()), SRTP_OK);
            let pol = make_policy(profile, sys::srtp_ssrc_type_t_ssrc_any_inbound, recv_key.as_mut_ptr()).unwrap();
            assert_eq!(sys::srtp_add_stream(s, &pol), SRTP_OK);
            s
        };

        let original = rtp_packet(96, 42, 0x1234_5678, b"gcm payload bytes");
        let mut buf = original.clone();
        let mut size = buf.len() as c_int;
        buf.resize(buf.len() + sys::SRTP_MAX_TRAILER_LEN as usize, 0);
        assert_eq!(
            unsafe { sys::srtp_protect(send, buf.as_mut_ptr() as *mut c_void, &mut size) },
            SRTP_OK
        );
        buf.truncate(size as usize);
        let mut size2 = buf.len() as c_int;
        assert_eq!(
            unsafe { sys::srtp_unprotect(recv, buf.as_mut_ptr() as *mut c_void, &mut size2) },
            SRTP_OK
        );
        buf.truncate(size2 as usize);
        assert_eq!(buf, original);
        unsafe {
            sys::srtp_dealloc(send);
            sys::srtp_dealloc(recv);
        }
    }

    #[test]
    fn profile_params_known_names() {
        assert!(profile_params_from_name("SRTP_AES128_CM_SHA1_80").is_some());
        assert!(profile_params_from_name("SRTP_AEAD_AES_128_GCM").is_some());
        let gcm = profile_params_from_name("SRTP_AEAD_AES_128_GCM").unwrap();
        assert_eq!(gcm.key_len, 16);
        assert_eq!(gcm.salt_len, 12);
        let cm = profile_params_from_name("SRTP_AES128_CM_SHA1_80").unwrap();
        assert_eq!(cm.key_len, 16);
        assert_eq!(cm.salt_len, 14);
        assert!(profile_params_from_name("NONSENSE").is_none());
    }

    #[test]
    fn is_rtcp_demux() {
        // PT 200 (SR) → &0x7F = 72 → RTCP.
        let rtcp = rtp_packet(0, 0, 0, b"xxxxxxxx");
        let mut rtcp = rtcp;
        rtcp[1] = 200 & 0x7F; // 72, in 64..=95
        assert!(is_rtcp(&rtcp));
        // PT 96 (dynamic RTP) → not RTCP.
        let rtp = rtp_packet(96, 0, 0, b"xxxxxxxx");
        assert!(!is_rtcp(&rtp));
        // Too short → not RTCP.
        assert!(!is_rtcp(&[0x80, 0xc8]));
    }

    #[test]
    fn version_string_links() {
        // Touches the FFI; just proves the symbol resolves.
        let v = srtp_version();
        assert!(!v.is_empty(), "expected a libsrtp2 version string");
    }

    fn make_dtls(role: Role) -> Arc<DtlsTransport> {
        let mut cfg = Configuration::new();
        cfg.bind_address = Some("127.0.0.1".to_string());
        let ice = IceTransport::new(&cfg, role, IceTransportCallbacks::default()).expect("ice");
        let cert = Certificate::generate_default().expect("cert");
        Arc::new(
            DtlsTransport::new(ice, cert, DtlsTransportCallbacks::default()).expect("dtls new"),
        )
    }

    #[test]
    fn new_sets_profiles_and_is_not_ready() {
        rt().block_on(async {
            let dtls = make_dtls(Role::Active);
            let srtp = SrtpTransport::new(dtls, SrtpTransportCallbacks::default())
                .expect("srtp new");
            assert!(!srtp.is_ready(), "no keys before handshake");
            assert!(srtp.selected_profile().is_none(), "no profile before handshake");
            // protect before ready must error NotReady.
            let err = srtp
                .protect_rtp(rtp_packet(96, 1, 1, b"x"))
                .expect_err("protect before ready");
            assert!(matches!(err, SrtpTransportError::NotReady), "got {err:?}");
            srtp.close();
        });
    }

    /// Full DTLS-SRTP loopback: two transports do the DTLS handshake with
    /// `use_srtp` negotiated, both derive keys, and an RTP packet protected by
    /// one is unprotected by the other. Mirrors
    /// `dtls_transport::dtls_handshake_completes_over_ice_loopback`.
    #[test]
    fn dtls_srtp_loopback_protect_unprotect() {
        use crate::candidate::Candidate;
        use crate::description::Type as DescriptionType;
        use crate::ice_transport::State as IceState;

        rt().block_on(async {
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

            let dtls_a = DtlsTransport::new(
                Arc::clone(&ice_a),
                cert_a,
                DtlsTransportCallbacks::default(),
            )
            .expect("dtls a");
            let dtls_b = DtlsTransport::new(
                Arc::clone(&ice_b),
                cert_b,
                DtlsTransportCallbacks::default(),
            )
            .expect("dtls b");

            dtls_a.set_remote_fingerprint(fp_b);
            dtls_b.set_remote_fingerprint(fp_a);

            // Layer SRTP on each side BEFORE the handshake starts so use_srtp
            // is in the ClientHello/ServerHello and keys auto-derive on
            // Connected.
            let a_rtp: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
            let a_rtp_cb = a_rtp.clone();
            let srtp_a = SrtpTransport::new(
                Arc::new(dtls_a.clone()),
                SrtpTransportCallbacks {
                    on_rtp: Arc::new(move |d| a_rtp_cb.lock().extend_from_slice(d)),
                    ..SrtpTransportCallbacks::default()
                },
            )
            .expect("srtp a");
            let srtp_b = SrtpTransport::new(
                Arc::new(dtls_b.clone()),
                SrtpTransportCallbacks::default(),
            )
            .expect("srtp b");

            // Drive ICE.
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

            // Wait for both SRTP layers to derive keys (post DTLS handshake).
            let ready = wait_for(
                || srtp_a.is_ready() && srtp_b.is_ready(),
                10000,
            )
            .await;
            assert!(
                ready,
                "srtp keys not derived: a_ready={}, b_ready={}, dtls_a={:?}, dtls_b={:?}",
                srtp_a.is_ready(),
                srtp_b.is_ready(),
                dtls_a.state(),
                dtls_b.state()
            );

            // Both must have negotiated the same profile.
            let pa = srtp_a.selected_profile().expect("a profile");
            let pb = srtp_b.selected_profile().expect("b profile");
            assert_eq!(pa, pb, "both sides must agree on the SRTP profile");

            // B protects an RTP packet; A unprotects it (cross-key).
            let original = rtp_packet(96, 7, 0x0bad_f00d, b"hello srtp loopback");
            let protected = srtp_b.protect_rtp(original.clone()).expect("b protect");
            assert_ne!(protected, original, "must be encrypted");
            let recovered = srtp_a.unprotect_rtp(protected).expect("a unprotect");
            assert_eq!(recovered, original, "cross-derived keys must round-trip");

            // And the reverse direction.
            let original2 = rtp_packet(97, 8, 0x0bad_f00d, b"reverse direction");
            let protected2 = srtp_a.protect_rtp(original2.clone()).expect("a protect");
            let recovered2 = srtp_b.unprotect_rtp(protected2).expect("b unprotect");
            assert_eq!(recovered2, original2);

            let _ = IceState::New;
            srtp_a.close();
            srtp_b.close();
        });
    }
}
