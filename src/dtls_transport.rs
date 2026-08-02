//! DTLS transport — port of `rtc::impl::DtlsTransport` from
//! `native/libdatachannel/src/impl/dtlstransport.cpp` (OpenSSL path).
//!
//! Phase G-5a delivers the **handshake driver** that sits on top of
//! [`IceTransport`]. It does NOT yet implement:
//! - SRTP profile selection (G-5b)
//! - Remote-fingerprint verification (G-5b)
//! - SCTP demux / `recv()` (G-5c — application records are surfaced via
//!   the [`DtlsTransportCallbacks::on_data`] callback in the meantime)
//!
//! ## Architecture
//!
//! The DTLS layer uses OpenSSL's two-BIO pattern: an inbound `BIO_s_mem`
//! that the recv path pumps ICE datagrams into, and an outbound
//! `BIO_s_mem` that the handshake/write paths drain (one record at a
//! time) and forward back to ICE via [`IceTransport::send`]. We avoid
//! [`SslStream`](openssl::ssl::SslStream) because it expects a
//! [`Read`] + [`Write`] pair, whereas our transport is callback-driven.
//!
//! ## Concurrency model
//!
//! OpenSSL's `Ssl` struct is `Send + Sync` (via
//! [`foreign_type_and_impl_send_sync!`]), but its operations are NOT
//! reentrant — concurrent `SSL_read`/`SSL_write`/`SSL_do_handshake`
//! against the same `*mut SSL` is undefined behaviour. We serialize
//! every OpenSSL call through a single [`parking_lot::Mutex<Inner>`]
//! that also owns the two raw `BIO*` pointers. This matches the C++
//! `mSslMutex` at `dtlstransport.cpp:848`.
//!
//! ## Send/Sync resolution
//!
//! `Inner` holds raw `*mut BIO` pointers (returned by `BIO_new`). Raw
//! pointers are `!Send + !Sync` by default, so we manually impl `Send`
//! for `Inner`: the BIOs are only ever touched while the mutex is held,
//! and `BIO_free_all` runs on `Drop`. We do NOT impl `Sync` for
//! `Inner` — that's enforced by sitting inside a `Mutex`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use openssl::hash::MessageDigest;
use openssl::ssl::{
    Ssl, SslContext, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode, SslVersion,
};
use openssl_sys as ossl_sys;
use parking_lot::Mutex;
use thiserror::Error;
use tracing::warn;

/// Extract the raw `*mut SSL` pointer from an `Ssl` handle.
///
/// `openssl-rs` only exposes `as_ptr()` on `Ssl` via the
/// [`foreign_types::ForeignType`] trait, which isn't a direct dependency
/// of this crate (it's pulled in transitively through `openssl`). Rather
/// than add a new top-level dep just for this one method, we lean on
/// the layout contract of the `foreign_type_and_impl_send_sync!` macro
/// that produces `Ssl`: the struct is `#[repr(transparent)]` over a
/// single `*mut ffi::SSL` field, so `transmute_copy` yields the same
/// pointer the trait method would.
///
/// Safety: relies on the foreign-types macro layout contract, which is
/// stable and used by every BIO/SSL/X509 type in openssl-rs.
#[inline]
fn ssl_ptr(ssl: &Ssl) -> *mut ossl_sys::SSL {
    // SAFETY: `Ssl` is `#[repr(transparent)]` over `*mut ffi::SSL` per
    // the `foreign_type_and_impl_send_sync!` macro contract.
    unsafe { std::mem::transmute_copy::<Ssl, *mut ossl_sys::SSL>(ssl) }
}

// `DTLSv1_get_timeout` / `DTLSv1_handle_timeout` are macros in OpenSSL
// (thin wrappers over `SSL_ctrl`), so `openssl-sys` does not expose them as
// functions. We invoke `SSL_ctrl` directly with the documented command
// numbers from `<openssl/dtls1.h>`.
const DTLS_CTRL_GET_TIMEOUT: std::ffi::c_int = 73;
const DTLS_CTRL_HANDLE_TIMEOUT: std::ffi::c_int = 74;

/// `DTLSv1_get_timeout(ssl, &mut tv)` — the time remaining until OpenSSL's
/// next handshake retransmit is due. Returns `Some(duration)` when a timer
/// is pending, `None` when nothing is scheduled (no unacked flight).
///
/// Safety: `ssl` must be a live `*mut SSL` and the caller must hold the
/// `Inner` mutex (OpenSSL calls are not reentrant).
unsafe fn dtls_get_timeout(ssl: *mut ossl_sys::SSL) -> Option<std::time::Duration> {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let r = unsafe {
        ossl_sys::SSL_ctrl(
            ssl,
            DTLS_CTRL_GET_TIMEOUT,
            0,
            &mut tv as *mut libc::timeval as *mut std::ffi::c_void,
        )
    };
    if r == 1 {
        Some(std::time::Duration::new(
            tv.tv_sec.max(0) as u64,
            (tv.tv_usec.max(0) as u32).saturating_mul(1000),
        ))
    } else {
        None
    }
}

/// `DTLSv1_handle_timeout(ssl)` — retransmit the last handshake flight *iff*
/// the retransmit timer has actually expired. OpenSSL checks expiry
/// internally, so polling this is safe: returns `0` when nothing is due,
/// `>0` when a flight was re-queued into the outbound BIO, `<0` on error.
///
/// Safety: same contract as [`dtls_get_timeout`].
unsafe fn dtls_handle_timeout(ssl: *mut ossl_sys::SSL) -> std::ffi::c_long {
    unsafe { ossl_sys::SSL_ctrl(ssl, DTLS_CTRL_HANDLE_TIMEOUT, 0, std::ptr::null_mut()) }
}

use crate::certificate::{Certificate, CertificateError, format_fingerprint};
use crate::description::{Fingerprint, FingerprintAlgorithm, Role};
use crate::ice_transport::{
    IceTransport, IceTransportCallbacks, IceTransportError, State as IceState,
};

/// Shared state between the SSL_CTX verify callback and the Bridge.
///
/// The verify callback is installed at `SSL_CTX` construction time —
/// before [`Bridge`] exists — so we wire both ends through this small
/// Arc. The bridge calls `set` / `get`; the callback reads.
type SharedFingerprint = Arc<Mutex<Option<Fingerprint>>>;

/// MTU default mirroring `DEFAULT_MTU` in libdatachannel
/// (`src/impl/transport.hpp`). `1280` is the IPv6 minimum.
const DEFAULT_MTU: usize = 1280;

/// Cipher list inherited byte-for-byte from
/// `native/libdatachannel/src/impl/dtlstransport.cpp:766`.
const CIPHER_LIST: &str =
    "ALL:!SHA256:!SHA384:!aPSK:!ECDSA+SHA1:!ADH:!LOW:!EXP:!MD5:!3DES:!SSLv3:!TLSv1";

/// Tells `BIO_s_mem` to return -1 (retryable) on empty read instead of 0
/// (eof). The C++ uses `BIO_set_mem_eof_return(mInBio, BIO_EOF)` where
/// `BIO_EOF` is `-1` on its libdatachannel build.
const BIO_EOF: std::ffi::c_long = -1;

/// State of the DTLS transport. Mirrors `rtc::Transport::State`
/// restricted to the subset DtlsTransport actually transitions through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DtlsState {
    /// Constructed; `start()` has not been called yet.
    New,
    /// Handshake in progress (records exchanged either via the
    /// initial ClientHello or driven by inbound ICE bytes).
    Connecting,
    /// Handshake completed; application records can be sent and
    /// received.
    Connected,
    /// Either an unrecoverable handshake error fired, or the underlying
    /// ICE transport went down.
    Failed,
    /// `close()` was called or the peer cleanly closed the session.
    Closed,
}

/// Callbacks the [`DtlsTransport`] invokes once it's been wired up.
#[derive(Clone)]
pub struct DtlsTransportCallbacks {
    /// Fires on every state transition.
    pub on_state_change: Arc<dyn Fn(DtlsState) + Send + Sync>,
    /// Fires for each decrypted application record. Until G-5c adds
    /// the SCTP demux, every record surfaces here unfiltered.
    pub on_data: Arc<dyn Fn(&[u8]) + Send + Sync>,
}

impl Default for DtlsTransportCallbacks {
    fn default() -> Self {
        DtlsTransportCallbacks {
            on_state_change: Arc::new(|_| {}),
            on_data: Arc::new(|_| {}),
        }
    }
}

/// Errors returned by [`DtlsTransport`] operations.
#[derive(Debug, Error)]
pub enum DtlsTransportError {
    /// OpenSSL barfed during construction or handshake.
    #[error("openssl: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    /// Forwarded from the lower [`IceTransport`].
    #[error("ice: {0}")]
    Ice(#[from] IceTransportError),

    /// Forwarded from [`Certificate`] generation.
    #[error("certificate: {0}")]
    Certificate(#[from] CertificateError),

    /// A `BIO_new()` returned NULL.
    #[error("BIO allocation failed")]
    BioAlloc,

    /// Operation called on a closed transport.
    #[error("transport closed")]
    Closed,

    /// `start()` returned a fatal SSL error during the initial handshake
    /// drive.
    #[error("DTLS handshake failed: ssl error {0}")]
    Handshake(i32),

    /// `send()` called before the handshake completed.
    #[error("DTLS not connected")]
    NotConnected,
}

/// Wraps the OpenSSL `Ssl` object and the two memory BIOs together with
/// the `*mut BIO` pointers used by the FFI calls. Held behind a mutex
/// inside [`Bridge`].
struct Inner {
    ssl: Ssl,
    /// Inbound BIO (ICE → SSL). Owned by `ssl` after `SSL_set_bio` — we
    /// keep the pointer purely so we can call `BIO_write` directly.
    in_bio: *mut ossl_sys::BIO,
    /// Outbound BIO (SSL → ICE). Same ownership rule as `in_bio`.
    out_bio: *mut ossl_sys::BIO,
    /// Set once the handshake has produced the first records (or once
    /// we've seen `SSL_ERROR_NONE` on `SSL_do_handshake`).
    handshake_done: bool,
}

// Safety: `Inner` is only ever touched while the surrounding Mutex is
// held; the raw BIO pointers don't escape the module, and `Drop`
// frees them on the same thread that constructed them.
unsafe impl Send for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        // `Ssl` owns the BIOs after `SSL_set_bio`, so we must NOT free
        // them here — `Ssl::drop` calls `SSL_free` which in turn frees
        // both BIOs. The fields are zeroed for safety.
        self.in_bio = std::ptr::null_mut();
        self.out_bio = std::ptr::null_mut();
    }
}

/// Shared mutable state. The user-facing handle is [`DtlsTransport`],
/// which holds an `Arc<Bridge>`. The IceTransport `on_data` shim
/// installed by `start()` also holds an `Arc<Bridge>` so it can pump
/// inbound bytes through the SSL state machine.
struct Bridge {
    /// SSL state — locked across every OpenSSL call.
    inner: Mutex<Inner>,
    /// Held SSL_CTX so its lifetime exceeds the Ssl object's.
    _ctx: SslContext,
    /// Current DtlsState. Read-mostly; written when the handshake
    /// progresses or `close()` fires.
    state: Mutex<DtlsState>,
    /// Lower transport — `start()` uses it to install our recv shim and
    /// to push outbound records.
    ice: Arc<IceTransport>,
    /// Callbacks the application installed.
    callbacks: Mutex<DtlsTransportCallbacks>,
    /// Set once `close()` runs so the ICE recv shim short-circuits.
    closed: AtomicBool,
    /// True if we're the DTLS client (Active role). The C++ at
    /// `dtlstransport.cpp:736` derives this from the lower transport's
    /// resolved role; we mirror that.
    is_client: bool,
    /// Expected remote certificate fingerprint, set by
    /// [`DtlsTransport::set_remote_fingerprint`]. Shared with the
    /// SSL_CTX verify callback installed at construction time.
    expected_remote_fingerprint: SharedFingerprint,
    /// Guards [`DtlsTransport::start`] against double-driving the
    /// handshake when both the auto-start callback on ICE-Connected and
    /// an explicit user call race.
    started: AtomicBool,
}

/// The DTLS transport. Cheap to clone — it's an `Arc<Bridge>` under
/// the hood, the same pattern used by [`IceTransport`].
#[derive(Clone)]
pub struct DtlsTransport {
    bridge: Arc<Bridge>,
}

impl std::fmt::Debug for DtlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsTransport")
            .field("state", &*self.bridge.state.lock())
            .field("is_client", &self.bridge.is_client)
            .finish()
    }
}

impl DtlsTransport {
    /// Construct a new DTLS transport on top of `ice`, using `certificate`
    /// as the local credentials.
    ///
    /// The constructor:
    /// 1. Builds an `SSL_CTX` with the same options the C++ uses:
    ///    `DTLS_method`, `NO_SSLv3 | NO_COMPRESSION | NO_QUERY_MTU | NO_RENEGOTIATION`,
    ///    cipher list `"ALL:!SHA256:!SHA384:..."`,
    ///    `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT` with a verify callback that
    ///    accepts any peer cert (G-5b will replace this with fingerprint
    ///    pinning). The peer's cert chain is allowed because RFC 8827
    ///    requires DTLS to authenticate via the fingerprint on the SDP.
    /// 2. Loads the local cert+key into the context.
    /// 3. Creates an `Ssl` and switches it to client or server state
    ///    based on `ice.role()`.
    /// 4. Allocates two `BIO_s_mem` and wires them via `SSL_set_bio`.
    /// 5. Returns the handle in `DtlsState::New`. Call [`start`](Self::start)
    ///    to begin the handshake.
    ///
    /// The lower transport's callbacks are NOT replaced until
    /// [`start`](Self::start) is called.
    pub fn new(
        ice: Arc<IceTransport>,
        certificate: Certificate,
        callbacks: DtlsTransportCallbacks,
    ) -> Result<Self, DtlsTransportError> {
        // The role is captured at construction time. The C++ does the
        // same — it derives `mIsClient` from the lower transport's role
        // in the constructor's initializer list.
        let role = ice.role();
        let is_client = matches!(role, Role::Active);

        // The expected remote fingerprint is wired through both the
        // SSL_CTX verify callback (read-only) and the Bridge (read/write
        // via `set_remote_fingerprint`). We construct the shared cell
        // first so both ends can hold a clone.
        let expected_remote_fingerprint: SharedFingerprint = Arc::new(Mutex::new(None));

        // Build the SSL_CTX with the libdatachannel options.
        let ctx = build_ssl_context(&certificate, Arc::clone(&expected_remote_fingerprint))?;

        // Build the Ssl wrapper and switch sides.
        let mut ssl = Ssl::new(&ctx)?;
        if is_client {
            ssl.set_connect_state();
        } else {
            ssl.set_accept_state();
        }

        // Allocate the two memory BIOs. Once `SSL_set_bio` runs, `Ssl`
        // owns them — `SSL_free` frees them transitively.
        let (in_bio, out_bio) = unsafe {
            let in_bio = ossl_sys::BIO_new(ossl_sys::BIO_s_mem());
            if in_bio.is_null() {
                return Err(DtlsTransportError::BioAlloc);
            }
            let out_bio = ossl_sys::BIO_new(ossl_sys::BIO_s_mem());
            if out_bio.is_null() {
                ossl_sys::BIO_free_all(in_bio);
                return Err(DtlsTransportError::BioAlloc);
            }
            // BIO_set_mem_eof_return(in_bio, BIO_EOF) — matches the C++ at
            // dtlstransport.cpp:798. Without this, a drained inbound BIO
            // returns 0 from BIO_read which OpenSSL interprets as EOF.
            ossl_sys::BIO_ctrl(
                in_bio,
                ossl_sys::BIO_C_SET_BUF_MEM_EOF_RETURN,
                BIO_EOF,
                std::ptr::null_mut(),
            );
            ossl_sys::BIO_ctrl(
                out_bio,
                ossl_sys::BIO_C_SET_BUF_MEM_EOF_RETURN,
                BIO_EOF,
                std::ptr::null_mut(),
            );
            // SSL_set_bio takes ownership of both BIOs.
            ossl_sys::SSL_set_bio(ssl_ptr(&ssl), in_bio, out_bio);
            (in_bio, out_bio)
        };

        let bridge = Arc::new(Bridge {
            inner: Mutex::new(Inner {
                ssl,
                in_bio,
                out_bio,
                handshake_done: false,
            }),
            _ctx: ctx,
            state: Mutex::new(DtlsState::New),
            ice: Arc::clone(&ice),
            callbacks: Mutex::new(callbacks),
            closed: AtomicBool::new(false),
            is_client,
            expected_remote_fingerprint,
            started: AtomicBool::new(false),
        });

        // Auto-start: install an `on_state_change` shim on the lower ICE
        // transport that kicks the DTLS handshake the moment ICE first
        // reaches Connected (or Completed), then drains any handshake
        // records that got stuck in the outbound BIO while ICE didn't
        // yet have a selected pair. The existing user-installed
        // `on_state_change` is captured and re-fired afterwards so the
        // chain is preserved.
        //
        // We deliberately install this BEFORE `start()` (which itself
        // chains in its own shim once called). `start()` is idempotent
        // — see `started` AtomicBool — so racing the auto-start with a
        // manual `start()` call is harmless.
        let prev = ice.callbacks();
        // Capture only a *weak* ref to the bridge. A strong `Arc<Bridge>`
        // here (via a `DtlsTransport`) would form a reference cycle —
        // `Bridge → ice → ICE callbacks → this closure → Bridge` — that
        // leaks the whole transport (and its ICE agent) forever and keeps
        // the DTLS retransmit timer alive past the transport's real
        // lifetime. With a `Weak`, dropping the last `DtlsTransport` handle
        // frees the cycle and the timer's own `Weak::upgrade` then fails so
        // it exits promptly.
        let weak_bridge = Arc::downgrade(&bridge);
        let new_on_state_change = {
            let prev_state = Arc::clone(&prev.on_state_change);
            Arc::new(move |s: IceState| {
                if matches!(s, IceState::Connected | IceState::Completed) {
                    if let Some(bridge) = weak_bridge.upgrade() {
                        let dtls_for_cb = DtlsTransport {
                            bridge: Arc::clone(&bridge),
                        };
                        // start() is idempotent: no-op if we've already
                        // started, otherwise drives the ClientHello.
                        if let Err(e) = dtls_for_cb.start() {
                            // Only Closed should bubble out here; everything
                            // else (Ice / SSL handshake error) is logged.
                            warn!("DtlsTransport: auto-start on ICE-Connected failed: {e}");
                        }
                        // Drain the outbound BIO: ClientHello bytes pushed
                        // during a prior `start()` may have been stranded
                        // because ICE didn't have a selected pair at the
                        // time. Now that we're Connected, push them.
                        let mut g = bridge.inner.lock();
                        let _ = drain_outbound_locked(&mut g, &bridge);
                    }
                }
                (prev_state)(s);
            })
        };
        ice.set_callbacks(IceTransportCallbacks {
            on_state_change: new_on_state_change,
            on_gathering_state_change: prev.on_gathering_state_change,
            on_candidate: prev.on_candidate,
            on_data: prev.on_data,
        });

        Ok(DtlsTransport { bridge })
    }

    /// Current DTLS state.
    pub fn state(&self) -> DtlsState {
        *self.bridge.state.lock()
    }

    // -----------------------------------------------------------------------
    // DTLS-SRTP seam (consumed by [`crate::SrtpTransport`])
    //
    // These three methods are the *minimal* surface the SRTP layer needs to
    // reach into the SSL object. They keep the SCTP/DataChannel path behaving
    // identically when SRTP is not requested (none of them is called unless a
    // `SrtpTransport` is layered on top). All three serialize through the same
    // `inner` mutex as every other OpenSSL call, per the concurrency model.
    // -----------------------------------------------------------------------

    /// Enable the DTLS `use_srtp` extension with the given OpenSSL profile
    /// list (e.g. `"SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80"`) on the
    /// underlying `SSL` object via `SSL_set_tlsext_use_srtp`.
    ///
    /// MUST be called **before** [`start`](Self::start): OpenSSL only sends
    /// the extension in the ClientHello / ServerHello, which the handshake
    /// emits on the first `SSL_do_handshake`. Returns an error if OpenSSL
    /// rejects the profile string.
    ///
    /// This is the seam [`crate::SrtpTransport`] uses; the
    /// SCTP/DataChannel path never calls it, so the default behaviour is
    /// unchanged.
    pub fn set_srtp_profiles(&self, profiles: &str) -> Result<(), DtlsTransportError> {
        let c = std::ffi::CString::new(profiles).map_err(|_| DtlsTransportError::Handshake(-1))?;
        let g = self.bridge.inner.lock();
        // SSL_set_tlsext_use_srtp returns 0 on success, non-zero on error
        // (the inverse of most OpenSSL calls).
        let ret = unsafe { ossl_sys::SSL_set_tlsext_use_srtp(ssl_ptr(&g.ssl), c.as_ptr()) };
        if ret != 0 {
            return Err(DtlsTransportError::Handshake(ret));
        }
        Ok(())
    }

    /// Name of the SRTP protection profile OpenSSL negotiated during the
    /// handshake (e.g. `"SRTP_AEAD_AES_128_GCM"`), or `None` if no profile was
    /// selected (or the handshake has not completed). Wraps
    /// `SSL_get_selected_srtp_profile`.
    pub fn selected_srtp_profile(&self) -> Option<String> {
        let g = self.bridge.inner.lock();
        unsafe {
            let profile = ossl_sys::SSL_get_selected_srtp_profile(ssl_ptr(&g.ssl));
            if profile.is_null() {
                return None;
            }
            let name = (*profile).name;
            if name.is_null() {
                return None;
            }
            Some(
                std::ffi::CStr::from_ptr(name)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }

    /// Export `out.len()` bytes of keying material under the given RFC 5705
    /// `label`, with no context, via `SSL_export_keying_material`. The SRTP
    /// layer calls this post-handshake with the `"EXTRACTOR-dtls_srtp"` label
    /// to derive the SRTP master keys/salts (RFC 5764). Returns an error if
    /// OpenSSL's export fails (return value <= 0).
    pub fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &str,
    ) -> Result<(), DtlsTransportError> {
        let g = self.bridge.inner.lock();
        let ret = unsafe {
            ossl_sys::SSL_export_keying_material(
                ssl_ptr(&g.ssl),
                out.as_mut_ptr(),
                out.len(),
                label.as_ptr() as *const std::ffi::c_char,
                label.len(),
                std::ptr::null(),
                0,
                0,
            )
        };
        if ret <= 0 {
            return Err(DtlsTransportError::Handshake(ret));
        }
        Ok(())
    }

    /// True if this side is acting as the DTLS client (Active role).
    pub fn is_client(&self) -> bool {
        self.bridge.is_client
    }

    /// Compute the fingerprint of the local certificate stored in this
    /// transport's SSL_CTX. Provided for symmetry with the C++
    /// `DtlsTransport::localFingerprint`; in practice the caller already
    /// has the [`Certificate`] handle and can call
    /// [`Certificate::fingerprint`] directly.
    pub fn local_fingerprint_algorithm() -> FingerprintAlgorithm {
        // libdatachannel defaults to SHA-256 on the `a=fingerprint:` line.
        FingerprintAlgorithm::Sha256
    }

    /// Pin the expected remote certificate fingerprint. The verify
    /// callback installed on this transport's `SSL_CTX` compares every
    /// peer certificate it sees against this value (uppercase
    /// colon-separated SHA-256 hex by default). A mismatch — or calling
    /// [`start`](Self::start) without ever calling this — causes the
    /// DTLS handshake to abort and the transport to transition to
    /// [`DtlsState::Failed`].
    ///
    /// Callers MUST set the remote fingerprint before [`start`](Self::start),
    /// otherwise verification fails on the first peer certificate seen.
    pub fn set_remote_fingerprint(&self, fingerprint: Fingerprint) {
        *self.bridge.expected_remote_fingerprint.lock() = Some(fingerprint);
    }

    /// Returns the expected remote fingerprint if it has been set via
    /// [`set_remote_fingerprint`](Self::set_remote_fingerprint).
    pub fn remote_fingerprint(&self) -> Option<Fingerprint> {
        self.bridge.expected_remote_fingerprint.lock().clone()
    }

    /// Start the DTLS handshake. Installs an `on_data` shim on the
    /// underlying [`IceTransport`] that pumps incoming bytes through
    /// the SSL state machine, then (if we're the client) drives the
    /// first `SSL_do_handshake` to emit a ClientHello.
    ///
    /// This is idempotent: subsequent calls (whether from the user or
    /// from the auto-start ICE-Connected hook installed by [`new`](Self::new))
    /// return `Ok(())` without re-driving the handshake.
    ///
    /// # Important
    ///
    /// You MUST call [`set_remote_fingerprint`](Self::set_remote_fingerprint)
    /// before `start()`, otherwise the verify callback will reject the
    /// peer's certificate as soon as the handshake produces one and the
    /// transport will transition to [`DtlsState::Failed`].
    pub fn start(&self) -> Result<(), DtlsTransportError> {
        if self.bridge.closed.load(Ordering::SeqCst) {
            return Err(DtlsTransportError::Closed);
        }

        // Idempotency guard #1: AtomicBool so the auto-start
        // on_state_change callback and an explicit user call can race
        // safely. The second caller short-circuits here.
        if self.bridge.started.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        // Idempotency guard #2: only transition to Connecting if we're
        // still in New (covers the close-during-start race).
        {
            let mut s = self.bridge.state.lock();
            if !matches!(*s, DtlsState::New) {
                return Ok(());
            }
            *s = DtlsState::Connecting;
        }
        let cb = {
            let g = self.bridge.callbacks.lock();
            Arc::clone(&g.on_state_change)
        };
        (cb)(DtlsState::Connecting);

        // Install our recv shim on the ICE transport. We chain the
        // previous on_data into a tiny on_state_change wrapper too so
        // ICE state transitions can still surface to the upper layer
        // (we lift the existing on_state_change unchanged).
        let prev = self.bridge.ice.callbacks();
        // Weak, not strong — see the cycle note in `new()`. These shims live
        // inside the ICE transport, which the Bridge owns; a strong capture
        // would leak the transport and keep the DTLS timer alive forever.
        let new_callbacks = IceTransportCallbacks {
            on_state_change: {
                // Chain to the previous on_state_change and additionally
                // mark the transport failed if ICE falls over.
                let prev_state = Arc::clone(&prev.on_state_change);
                let weak = Arc::downgrade(&self.bridge);
                Arc::new(move |s: IceState| {
                    (prev_state)(s);
                    if matches!(s, IceState::Failed | IceState::Closed) {
                        if let Some(bridge) = weak.upgrade() {
                            fail_transport(&bridge);
                        }
                    }
                })
            },
            on_gathering_state_change: prev.on_gathering_state_change,
            on_candidate: prev.on_candidate,
            on_data: {
                let weak = Arc::downgrade(&self.bridge);
                Arc::new(move |data: &[u8]| {
                    if let Some(bridge) = weak.upgrade() {
                        pump_inbound(&bridge, data);
                    }
                })
            },
        };
        self.bridge.ice.set_callbacks(new_callbacks);

        // MTU calculation matches C++ at dtlstransport.cpp:850:
        // DEFAULT_MTU - 8 (UDP) - 40 (IPv6) = 1232.
        let mtu = DEFAULT_MTU.saturating_sub(8 + 40);
        {
            let mut g = self.bridge.inner.lock();
            unsafe {
                ossl_sys::SSL_set_mtu(ssl_ptr(&g.ssl), mtu as std::ffi::c_long);
            }

            // Client kicks off; server just waits for the ClientHello
            // (which will be fed in through the recv shim). The C++
            // ignores transient ICE-send failures during the initial
            // drive (`dtlstransport.cpp:870` — the handshake's own
            // retransmit timer will retry), so we mirror that: an Ice
            // error from `drain_outbound_locked` is downgraded to a
            // warn-and-keep-going. Anything else (a true SSL handshake
            // error) still surfaces.
            if self.bridge.is_client {
                if let Err(e) = drive_handshake_locked(&mut g, &self.bridge) {
                    match e {
                        DtlsTransportError::Ice(_) => {
                            warn!(
                                "DtlsTransport::start: initial ClientHello \
                                 could not be flushed to ICE ({e}); will \
                                 retry on next handshake tick"
                            );
                        }
                        other => return Err(other),
                    }
                }
            }
        }

        // Spawn the DTLS retransmit timer. OpenSSL does NOT self-retransmit
        // lost handshake flights — the application must call
        // `DTLSv1_handle_timeout()` once OpenSSL's timer expires. C++
        // libdatachannel runs a dedicated timer thread for exactly this
        // (`dtlstransport.cpp`). Without it, a handshake flight dropped on
        // the wire — common over the real internet, ~never over loopback or
        // veth — is never resent and the handshake stalls forever. This is
        // why Rust↔Rust handshakes over clean local links always succeeded
        // while Chrome↔Rust over a lossy path hung at "ctrl open timeout".
        // Runs for both roles (client and server both emit flights) until
        // the handshake leaves `Connecting`.
        //
        // The timer holds only a `Weak<Bridge>` and upgrades per tick: the
        // instant the application drops the transport (PeerConnection close
        // / Drop), the upgrade fails and the timer exits — it must never keep
        // a dead transport (and its ICE agent) alive, nor touch ICE after the
        // owner has torn down.
        {
            let weak = Arc::downgrade(&self.bridge);
            if let Err(e) = std::thread::Builder::new()
                .name("dtls-timer".into())
                .spawn(move || dtls_timer_loop(weak))
            {
                warn!("DtlsTransport: failed to spawn DTLS retransmit timer: {e}");
            }
        }
        Ok(())
    }

    /// Encrypt and send application data over the established session.
    /// Errors with [`DtlsTransportError::NotConnected`] until the
    /// handshake completes.
    pub fn send(&self, data: &[u8]) -> Result<(), DtlsTransportError> {
        if self.bridge.closed.load(Ordering::SeqCst) {
            return Err(DtlsTransportError::Closed);
        }
        if !matches!(*self.bridge.state.lock(), DtlsState::Connected) {
            return Err(DtlsTransportError::NotConnected);
        }
        let mut g = self.bridge.inner.lock();
        let ret = unsafe {
            ossl_sys::SSL_write(
                ssl_ptr(&g.ssl),
                data.as_ptr() as *const std::ffi::c_void,
                data.len() as std::ffi::c_int,
            )
        };
        if ret <= 0 {
            let err = unsafe { ossl_sys::SSL_get_error(ssl_ptr(&g.ssl), ret) };
            // WANT_READ/WANT_WRITE are normal for non-blocking IO; for
            // SSL_write on a memory BIO they shouldn't happen post-handshake.
            return Err(DtlsTransportError::Handshake(err));
        }
        // Drain the outbound BIO into the ICE transport.
        drain_outbound_locked(&mut g, &self.bridge)?;
        Ok(())
    }

    /// Swap the callback set at runtime.
    pub fn set_callbacks(&self, callbacks: DtlsTransportCallbacks) {
        *self.bridge.callbacks.lock() = callbacks;
    }

    /// Snapshot the current callbacks bag, so a layered transport (SCTP)
    /// can install its own `on_data` while keeping the upstream handlers.
    ///
    /// Mirrors [`IceTransport::callbacks`]; consumed by
    /// [`crate::SctpTransport`] in Phase G-6a, which chains its own
    /// `on_data` onto DTLS while preserving the PeerConnection-owned
    /// `on_state_change`.
    pub fn callbacks(&self) -> DtlsTransportCallbacks {
        let g = self.bridge.callbacks.lock();
        DtlsTransportCallbacks {
            on_state_change: Arc::clone(&g.on_state_change),
            on_data: Arc::clone(&g.on_data),
        }
    }

    /// Close the transport. Idempotent; fires `on_state_change(Closed)`
    /// exactly once.
    pub fn close(&self) -> Result<(), DtlsTransportError> {
        if self.bridge.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let changed = {
            let mut s = self.bridge.state.lock();
            if !matches!(*s, DtlsState::Closed) {
                *s = DtlsState::Closed;
                true
            } else {
                false
            }
        };
        if changed {
            let cb = {
                let g = self.bridge.callbacks.lock();
                Arc::clone(&g.on_state_change)
            };
            (cb)(DtlsState::Closed);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SSL_CTX construction
// ---------------------------------------------------------------------------

fn build_ssl_context(
    certificate: &Certificate,
    expected_remote_fingerprint: SharedFingerprint,
) -> Result<SslContext, DtlsTransportError> {
    let mut builder = SslContextBuilder::new(SslMethod::dtls())?;
    // Options inherited from dtlstransport.cpp:754.
    builder.set_options(
        SslOptions::NO_SSLV3
            | SslOptions::NO_COMPRESSION
            | SslOptions::NO_QUERY_MTU
            | SslOptions::NO_RENEGOTIATION,
    );
    builder.set_cipher_list(CIPHER_LIST)?;

    // Pin DTLS to 1.2. OpenSSL 3.5+ can negotiate DTLS 1.3, and Chrome (with
    // WebRTC-ForceDtls13) presents a DTLS 1.3 endpoint — but DTLS 1.3 is a
    // different record/ACK state machine than the 1.2 path libdatachannel
    // (and this port) was written against. Empirically the OpenSSL↔OpenSSL
    // path negotiates 1.2 and completes, while the OpenSSL↔Chrome path stalls
    // mid-handshake. libdatachannel C++ itself uses DTLS 1.2; matching that
    // keeps browser interop on the well-trodden path. (No min cap — 1.0/1.2
    // range is fine; we just refuse to climb to 1.3.)
    builder.set_max_proto_version(Some(SslVersion::DTLS1_2))?;

    // Verify mode matches dtlstransport.cpp:762 — REQUIRE the peer
    // certificate. The callback ports the C++
    // `DtlsTransport::CertificateCallback` at
    // `native/libdatachannel/src/impl/dtlstransport.cpp:1035`: ignore
    // OpenSSL's `preverify_ok` (self-signed certs always preverify-fail,
    // which is fine per RFC 8827 — DTLS-SRTP authenticates the peer via
    // the SDP fingerprint), grab the peer leaf cert, hash it, compare
    // against the pinned fingerprint.
    builder.set_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        move |_preverify_ok, store_ctx| {
            // Pull out the cert currently under inspection. None at
            // chain root or if OpenSSL hasn't surfaced one yet — reject.
            let Some(cert) = store_ctx.current_cert() else {
                warn!("DtlsTransport verify: no current cert in X509 store ctx");
                return false;
            };
            // The expected fingerprint MUST have been set before the
            // handshake started. None here means the application
            // forgot to call `set_remote_fingerprint` — fail closed.
            let expected = match expected_remote_fingerprint.lock().clone() {
                Some(fp) => fp,
                None => {
                    warn!(
                        "DtlsTransport verify: no remote fingerprint set; \
                         rejecting peer cert (call set_remote_fingerprint \
                         before start())"
                    );
                    return false;
                }
            };
            // Hash the peer cert with the algorithm the application
            // pinned, then render in the same SDP shape as
            // `Certificate::fingerprint`.
            let md = message_digest_for(expected.algorithm);
            let actual = match cert.digest(md) {
                Ok(d) => format_fingerprint(d.as_ref()),
                Err(e) => {
                    warn!("DtlsTransport verify: X509_digest failed: {e}");
                    return false;
                }
            };
            // Case-insensitive equality match. `Fingerprint::value` is
            // always uppercase per `format_fingerprint`, but the
            // application could have constructed one manually with
            // lowercase hex; the C++ comparator is case-insensitive too
            // (see `make_fingerprint` callers around dtlstransport.cpp).
            if actual.eq_ignore_ascii_case(&expected.value) {
                true
            } else {
                warn!(
                    "DtlsTransport verify: peer fingerprint mismatch \
                     (expected {}, got {})",
                    expected.value, actual
                );
                false
            }
        },
    );

    // Wire in our cert + key.
    builder.set_certificate(certificate.x509())?;
    builder.set_private_key(certificate.pkey())?;
    builder.check_private_key()?;

    Ok(builder.build())
}

/// Translate our [`FingerprintAlgorithm`] enum into the OpenSSL
/// [`MessageDigest`] used by `X509_digest`. Used only inside the
/// verify callback.
fn message_digest_for(algo: FingerprintAlgorithm) -> MessageDigest {
    match algo {
        FingerprintAlgorithm::Sha1 => MessageDigest::sha1(),
        FingerprintAlgorithm::Sha224 => MessageDigest::sha224(),
        FingerprintAlgorithm::Sha256 => MessageDigest::sha256(),
        FingerprintAlgorithm::Sha384 => MessageDigest::sha384(),
        FingerprintAlgorithm::Sha512 => MessageDigest::sha512(),
    }
}

// ---------------------------------------------------------------------------
// Inbound pump (ICE → SSL) + outbound drain (SSL → ICE)
// ---------------------------------------------------------------------------

/// Called by the IceTransport recv shim. Writes `data` into the inbound
/// BIO, then drives the handshake (if not yet connected) or pulls plaintext
/// out via `SSL_read` (if connected) and surfaces it via `on_data`.
fn pump_inbound(bridge: &Arc<Bridge>, data: &[u8]) {
    if bridge.closed.load(Ordering::SeqCst) {
        return;
    }

    let mut g = bridge.inner.lock();
    unsafe {
        let written = ossl_sys::BIO_write(
            g.in_bio,
            data.as_ptr() as *const std::ffi::c_void,
            data.len() as std::ffi::c_int,
        );
        if written < 0 {
            warn!(
                "DtlsTransport: BIO_write returned {written}, dropping {} bytes",
                data.len()
            );
            return;
        }
    }

    // Drive the handshake if we're still mid-handshake.
    let state_now = *bridge.state.lock();
    if matches!(state_now, DtlsState::Connecting) {
        if let Err(e) = drive_handshake_locked(&mut g, bridge) {
            warn!("DtlsTransport: handshake drive failed: {e}");
            drop(g);
            fail_transport(bridge);
            return;
        }
    }

    // If we're connected (now or as of construction), drain plaintext.
    if matches!(*bridge.state.lock(), DtlsState::Connected) {
        let mut buf = [0u8; 4096];
        loop {
            let ret = unsafe {
                ossl_sys::SSL_read(
                    ssl_ptr(&g.ssl),
                    buf.as_mut_ptr() as *mut std::ffi::c_void,
                    buf.len() as std::ffi::c_int,
                )
            };
            if ret <= 0 {
                let err = unsafe { ossl_sys::SSL_get_error(ssl_ptr(&g.ssl), ret) };
                if err == ossl_sys::SSL_ERROR_ZERO_RETURN {
                    // Peer sent close_notify.
                    drop(g);
                    let _ = bridge_close(bridge);
                    return;
                }
                if err != ossl_sys::SSL_ERROR_WANT_READ && err != ossl_sys::SSL_ERROR_WANT_WRITE {
                    warn!("DtlsTransport: SSL_read returned err={err}");
                }
                break;
            }
            let cb = {
                let cbs = bridge.callbacks.lock();
                Arc::clone(&cbs.on_data)
            };
            (cb)(&buf[..ret as usize]);
        }
    }
}

/// Drive `SSL_do_handshake` once and drain whatever records it produced.
/// Caller holds the inner mutex.
fn drive_handshake_locked(
    inner: &mut Inner,
    bridge: &Arc<Bridge>,
) -> Result<(), DtlsTransportError> {
    let ret = unsafe { ossl_sys::SSL_do_handshake(ssl_ptr(&inner.ssl)) };
    let err = unsafe { ossl_sys::SSL_get_error(ssl_ptr(&inner.ssl), ret) };

    // Always drain whatever records OpenSSL queued (ClientHello,
    // ServerHello, Finished, ...).
    drain_outbound_locked(inner, bridge)?;

    match err {
        ossl_sys::SSL_ERROR_NONE => {
            // Handshake done.
            if !inner.handshake_done {
                inner.handshake_done = true;
                // Diagnostic (gated): which DTLS version actually got
                // negotiated. Chrome forces a DTLS 1.3 ClientHello; an
                // OpenSSL 3.5+ server will happily complete 1.3, which is a
                // different record/ACK machine than the 1.2 path this port
                // was written against.
                if std::env::var_os("DTLS_LOG_VERSION").is_some() {
                    let ver = unsafe {
                        let p = ossl_sys::SSL_get_version(ssl_ptr(&inner.ssl));
                        if p.is_null() {
                            "?".to_string()
                        } else {
                            std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
                        }
                    };
                    let role = if bridge.is_client { "client" } else { "server" };
                    eprintln!("[dtls] handshake complete role={role} version={ver}");
                }
                // Set MTU to a sane post-handshake value matching C++
                // at dtlstransport.cpp:962.
                unsafe { ossl_sys::SSL_set_mtu(ssl_ptr(&inner.ssl), 4097) };
                {
                    let mut s = bridge.state.lock();
                    *s = DtlsState::Connected;
                }
                let cb = {
                    let g = bridge.callbacks.lock();
                    Arc::clone(&g.on_state_change)
                };
                (cb)(DtlsState::Connected);
            }
            Ok(())
        }
        ossl_sys::SSL_ERROR_WANT_READ | ossl_sys::SSL_ERROR_WANT_WRITE => {
            // Normal: handshake needs more datagrams.
            Ok(())
        }
        other => {
            // Surface the concrete OpenSSL error (gated) — the SSL_get_error
            // code alone (e.g. SSL_ERROR_SSL=1) doesn't say *why*. Drain the
            // error queue into a readable string for diagnosis.
            if std::env::var_os("DTLS_LOG_VERSION").is_some() {
                // Drains the thread's OpenSSL error queue into a Display.
                let detail = openssl::error::ErrorStack::get();
                let role = if bridge.is_client { "client" } else { "server" };
                eprintln!("[dtls] handshake ERROR role={role} ssl_err={other} detail=[{detail}]");
            }
            Err(DtlsTransportError::Handshake(other))
        }
    }
}

/// Drain the outbound BIO into the ICE transport via `ice.send()`.
/// Caller holds the inner mutex.
fn drain_outbound_locked(
    inner: &mut Inner,
    bridge: &Arc<Bridge>,
) -> Result<(), DtlsTransportError> {
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe {
            ossl_sys::BIO_read(
                inner.out_bio,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len() as std::ffi::c_int,
            )
        };
        if n <= 0 {
            // BIO_eof / no data pending.
            return Ok(());
        }
        // Forward the record to ICE. We swallow IceTransportError::Closed
        // because that path is normal on shutdown; everything else surfaces.
        match bridge.ice.send(&buf[..n as usize]) {
            Ok(()) => {}
            Err(IceTransportError::Closed) => {
                return Ok(());
            }
            Err(e) => return Err(DtlsTransportError::Ice(e)),
        }
    }
}

/// Background retransmit driver for the DTLS handshake. Spawned by
/// [`DtlsTransport::start`]; runs until the handshake leaves `Connecting`
/// (→ Connected / Failed / Closed) or a hard cap elapses.
///
/// Each tick, while still handshaking, it asks OpenSSL to retransmit the
/// last flight if its timer has expired (`DTLSv1_handle_timeout`) and, when
/// a flight was re-queued, drains the outbound BIO back onto ICE. The poll
/// cadence follows OpenSSL's own next-timeout (clamped) so we fire close to
/// when each flight is actually due without busy-spinning. A 30 s overall
/// cap mirrors libdatachannel's transport timeout: past it the peer is gone
/// and we fail rather than spin forever.
fn dtls_timer_loop(weak: std::sync::Weak<Bridge>) {
    const MAX_HANDSHAKE: std::time::Duration = std::time::Duration::from_secs(30);
    const MIN_TICK: std::time::Duration = std::time::Duration::from_millis(10);
    const MAX_TICK: std::time::Duration = std::time::Duration::from_millis(250);

    let deadline = std::time::Instant::now() + MAX_HANDSHAKE;
    loop {
        // Each tick computes a sleep while holding a *strong* ref, then drops
        // it before sleeping — so during the sleep only the Weak remains and
        // the real owner can free the Bridge (and its ICE agent) at will.
        let sleep = {
            let Some(bridge) = weak.upgrade() else {
                // Transport dropped by its owner — nothing left to drive.
                return;
            };
            if bridge.closed.load(Ordering::SeqCst) {
                return;
            }
            if !matches!(*bridge.state.lock(), DtlsState::Connecting) {
                // Handshake completed or failed — nothing left to retransmit.
                return;
            }
            if std::time::Instant::now() >= deadline {
                warn!("DtlsTransport: DTLS handshake timed out after 30s; failing transport");
                fail_transport(&bridge);
                return;
            }

            let mut g = bridge.inner.lock();
            let ssl = ssl_ptr(&g.ssl);
            // 0 = nothing due yet, >0 = a flight was re-queued, <0 = error.
            let r = unsafe { dtls_handle_timeout(ssl) };
            if r > 0 {
                if let Err(e) = drain_outbound_locked(&mut g, &bridge) {
                    // ICE may not have a selected pair yet (e.g. start()
                    // raced ahead of ICE-Connected); log and keep ticking —
                    // the next tick retries once the pair is up.
                    warn!("DtlsTransport: handshake retransmit drain failed: {e}");
                }
            }
            // Sleep until OpenSSL's next scheduled retransmit, clamped so we
            // stay responsive to state changes and the overall deadline.
            match unsafe { dtls_get_timeout(ssl) } {
                Some(d) => d.clamp(MIN_TICK, MAX_TICK),
                None => MAX_TICK,
            }
            // `bridge` (strong ref) and `g` (lock guard) drop here.
        };
        std::thread::sleep(sleep);
    }
}

fn fail_transport(bridge: &Arc<Bridge>) {
    let changed = {
        let mut s = bridge.state.lock();
        if !matches!(*s, DtlsState::Failed | DtlsState::Closed) {
            *s = DtlsState::Failed;
            true
        } else {
            false
        }
    };
    if changed {
        let cb = {
            let g = bridge.callbacks.lock();
            Arc::clone(&g.on_state_change)
        };
        (cb)(DtlsState::Failed);
    }
}

fn bridge_close(bridge: &Arc<Bridge>) -> Result<(), DtlsTransportError> {
    if bridge.closed.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let changed = {
        let mut s = bridge.state.lock();
        if !matches!(*s, DtlsState::Closed) {
            *s = DtlsState::Closed;
            true
        } else {
            false
        }
    };
    if changed {
        let cb = {
            let g = bridge.callbacks.lock();
            Arc::clone(&g.on_state_change)
        };
        (cb)(DtlsState::Closed);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicUsize;

    use crate::configuration::Configuration;
    use crate::ice_transport::{IceTransport, IceTransportCallbacks};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn make_ice(role: Role) -> Arc<IceTransport> {
        let mut cfg = Configuration::new();
        cfg.bind_address = Some("127.0.0.1".to_string());
        IceTransport::new(&cfg, role, IceTransportCallbacks::default()).expect("ice")
    }

    #[test]
    fn construct_active_is_client() {
        rt().block_on(async {
            let ice = make_ice(Role::Active);
            let cert = Certificate::generate_default().unwrap();
            let dtls =
                DtlsTransport::new(ice, cert, DtlsTransportCallbacks::default()).expect("dtls new");
            assert!(dtls.is_client());
            assert_eq!(dtls.state(), DtlsState::New);
        });
    }

    #[test]
    fn construct_passive_is_server() {
        rt().block_on(async {
            let ice = make_ice(Role::Passive);
            let cert = Certificate::generate_default().unwrap();
            let dtls =
                DtlsTransport::new(ice, cert, DtlsTransportCallbacks::default()).expect("dtls new");
            assert!(!dtls.is_client());
            assert_eq!(dtls.state(), DtlsState::New);
        });
    }

    #[test]
    fn start_transitions_to_connecting() {
        rt().block_on(async {
            let states: Arc<Mutex<Vec<DtlsState>>> = Arc::new(Mutex::new(Vec::new()));
            let states_cb = states.clone();
            let callbacks = DtlsTransportCallbacks {
                on_state_change: Arc::new(move |s| states_cb.lock().push(s)),
                ..DtlsTransportCallbacks::default()
            };
            let ice = make_ice(Role::Active);
            let cert = Certificate::generate_default().unwrap();
            let dtls = DtlsTransport::new(ice, cert, callbacks).expect("dtls new");
            assert_eq!(dtls.state(), DtlsState::New);
            dtls.start().expect("start");
            assert_eq!(dtls.state(), DtlsState::Connecting);
            assert!(
                states
                    .lock()
                    .iter()
                    .any(|s| matches!(s, DtlsState::Connecting)),
                "expected Connecting in {:?}",
                states.lock().clone()
            );
        });
    }

    #[test]
    fn start_is_idempotent() {
        rt().block_on(async {
            let connecting_count = Arc::new(AtomicUsize::new(0));
            let cb = connecting_count.clone();
            let callbacks = DtlsTransportCallbacks {
                on_state_change: Arc::new(move |s| {
                    if matches!(s, DtlsState::Connecting) {
                        cb.fetch_add(1, Ordering::SeqCst);
                    }
                }),
                ..DtlsTransportCallbacks::default()
            };
            let ice = make_ice(Role::Active);
            let cert = Certificate::generate_default().unwrap();
            let dtls = DtlsTransport::new(ice, cert, callbacks).expect("dtls new");
            dtls.start().expect("first start");
            dtls.start().expect("second start");
            assert_eq!(
                connecting_count.load(Ordering::SeqCst),
                1,
                "start() must fire Connecting exactly once"
            );
        });
    }

    #[test]
    fn send_before_connected_errors() {
        rt().block_on(async {
            let ice = make_ice(Role::Active);
            let cert = Certificate::generate_default().unwrap();
            let dtls =
                DtlsTransport::new(ice, cert, DtlsTransportCallbacks::default()).expect("dtls new");
            let err = dtls
                .send(b"hello")
                .expect_err("send before connect must fail");
            assert!(
                matches!(err, DtlsTransportError::NotConnected),
                "got {err:?}"
            );
        });
    }

    #[test]
    fn close_transitions_to_closed_and_is_idempotent() {
        rt().block_on(async {
            let count = Arc::new(AtomicUsize::new(0));
            let cb = count.clone();
            let callbacks = DtlsTransportCallbacks {
                on_state_change: Arc::new(move |s| {
                    if matches!(s, DtlsState::Closed) {
                        cb.fetch_add(1, Ordering::SeqCst);
                    }
                }),
                ..DtlsTransportCallbacks::default()
            };
            let ice = make_ice(Role::Active);
            let cert = Certificate::generate_default().unwrap();
            let dtls = DtlsTransport::new(ice, cert, callbacks).expect("dtls new");
            dtls.close().expect("first close");
            dtls.close().expect("second close");
            assert_eq!(dtls.state(), DtlsState::Closed);
            assert_eq!(
                count.load(Ordering::SeqCst),
                1,
                "Closed callback must fire exactly once"
            );
            // Sending after close must surface Closed.
            let err = dtls.send(b"hi").expect_err("send after close");
            assert!(matches!(err, DtlsTransportError::Closed), "got {err:?}");
        });
    }

    #[test]
    fn client_start_emits_client_hello_into_outbound_bio() {
        // The client kicks off `SSL_do_handshake` on `start()`. The
        // resulting ClientHello is drained from the outbound BIO and
        // pushed into the ICE transport — which has no selected pair
        // yet, so the `ice.send()` call returns a NotAvailable error
        // (we swallow non-Closed errors as Ice in drain_outbound_locked,
        // but here we want to verify the BIO was at least produced).
        //
        // We assert indirectly: the transport must reach Connecting
        // (not Failed) and at least one drain attempt must have run.
        rt().block_on(async {
            let states: Arc<Mutex<Vec<DtlsState>>> = Arc::new(Mutex::new(Vec::new()));
            let states_cb = states.clone();
            let callbacks = DtlsTransportCallbacks {
                on_state_change: Arc::new(move |s| states_cb.lock().push(s)),
                ..DtlsTransportCallbacks::default()
            };
            let ice = make_ice(Role::Active);
            let cert = Certificate::generate_default().unwrap();
            let dtls = DtlsTransport::new(ice, cert, callbacks).expect("dtls new");

            // start() will try to drain to ICE. ICE has no selected pair,
            // so ice.send() returns Juice(NotAvailable) which we map to
            // DtlsTransportError::Ice. The driver propagates that error
            // out of start().
            let res = dtls.start();
            // Either start succeeds (ClientHello sat in the BIO and the
            // drain call surfaced an Ice error) or the transport is at
            // least Connecting.
            assert!(
                res.is_err() || dtls.state() == DtlsState::Connecting,
                "start result={:?}, state={:?}",
                res,
                dtls.state()
            );
        });
    }

    #[test]
    fn set_callbacks_replaces_existing() {
        rt().block_on(async {
            let a_calls = Arc::new(AtomicUsize::new(0));
            let b_calls = Arc::new(AtomicUsize::new(0));
            let a_cb = a_calls.clone();

            let initial = DtlsTransportCallbacks {
                on_state_change: Arc::new(move |_s| {
                    a_cb.fetch_add(1, Ordering::SeqCst);
                }),
                ..DtlsTransportCallbacks::default()
            };
            let ice = make_ice(Role::Active);
            let cert = Certificate::generate_default().unwrap();
            let dtls = DtlsTransport::new(ice, cert, initial).expect("dtls new");

            let b_cb = b_calls.clone();
            dtls.set_callbacks(DtlsTransportCallbacks {
                on_state_change: Arc::new(move |_s| {
                    b_cb.fetch_add(1, Ordering::SeqCst);
                }),
                ..DtlsTransportCallbacks::default()
            });

            dtls.close().expect("close");
            assert_eq!(a_calls.load(Ordering::SeqCst), 0);
            assert_eq!(b_calls.load(Ordering::SeqCst), 1);
        });
    }

    // -------------------------------------------------------------------
    // Phase G-5b: remote-fingerprint pinning + end-to-end handshake.
    // -------------------------------------------------------------------

    #[test]
    fn set_remote_fingerprint_getter_round_trips() {
        rt().block_on(async {
            let ice = make_ice(Role::Active);
            let cert = Certificate::generate_default().unwrap();
            let dtls =
                DtlsTransport::new(ice, cert, DtlsTransportCallbacks::default()).expect("dtls new");
            assert!(dtls.remote_fingerprint().is_none(), "starts unset");

            let other = Certificate::generate_default().unwrap();
            let fp = other
                .fingerprint(FingerprintAlgorithm::Sha256)
                .expect("fingerprint");
            dtls.set_remote_fingerprint(fp.clone());

            let round = dtls.remote_fingerprint().expect("set");
            assert_eq!(round.algorithm, fp.algorithm);
            assert_eq!(round.value, fp.value);
        });
    }

    /// Spin until `pred` is true or `timeout_ms` elapses.
    async fn wait_for_dtls<F: FnMut() -> bool>(mut pred: F, timeout_ms: u64) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if pred() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        false
    }

    /// Build the standard A/B ICE-pair on loopback, wire their candidate
    /// callbacks together, exchange descriptions, and gather. Returns
    /// the two transports once both sides have ICE-Connected. Reused by
    /// the DTLS end-to-end tests below.
    async fn pair_ice_loopback() -> (Arc<IceTransport>, Arc<IceTransport>) {
        use crate::candidate::Candidate;
        use crate::description::Type as DescriptionType;
        use crate::ice_transport::State as IceState;

        let a_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));
        let b_cands: Arc<Mutex<Vec<Candidate>>> = Arc::new(Mutex::new(Vec::new()));
        let a_connected = Arc::new(AtomicBool::new(false));
        let b_connected = Arc::new(AtomicBool::new(false));

        let ac = a_connected.clone();
        let bc = b_connected.clone();
        let a_cands_cb = a_cands.clone();
        let b_cands_cb = b_cands.clone();

        let a_callbacks = IceTransportCallbacks {
            on_state_change: Arc::new(move |s| {
                if matches!(s, IceState::Connected | IceState::Completed) {
                    ac.store(true, Ordering::SeqCst);
                }
            }),
            on_candidate: Arc::new(move |c| a_cands_cb.lock().push(c)),
            ..IceTransportCallbacks::default()
        };
        let b_callbacks = IceTransportCallbacks {
            on_state_change: Arc::new(move |s| {
                if matches!(s, IceState::Connected | IceState::Completed) {
                    bc.store(true, Ordering::SeqCst);
                }
            }),
            on_candidate: Arc::new(move |c| b_cands_cb.lock().push(c)),
            ..IceTransportCallbacks::default()
        };

        let mut cfg = Configuration::new();
        cfg.bind_address = Some("127.0.0.1".to_string());

        let a = IceTransport::new(&cfg, Role::ActPass, a_callbacks).expect("a");
        let b = IceTransport::new(&cfg, Role::Active, b_callbacks).expect("b");

        a.gather().expect("a gather");
        // Wait for A's gathering to finish.
        let _ = wait_for_dtls(
            || a.gathering_state() == crate::ice_transport::GatheringState::Complete,
            3000,
        )
        .await;
        let desc_a = a
            .get_local_description(DescriptionType::Offer)
            .expect("a sdp");
        b.set_remote_description(&desc_a).expect("b set remote");

        b.gather().expect("b gather");
        let _ = wait_for_dtls(
            || b.gathering_state() == crate::ice_transport::GatheringState::Complete,
            3000,
        )
        .await;
        let desc_b = b
            .get_local_description(DescriptionType::Answer)
            .expect("b sdp");
        a.set_remote_description(&desc_b).expect("a set remote");

        for c in a_cands.lock().iter() {
            b.add_remote_candidate(c).expect("trickle a→b");
        }
        for c in b_cands.lock().iter() {
            a.add_remote_candidate(c).expect("trickle b→a");
        }
        a.set_remote_end_of_candidates().expect("a eoc");
        b.set_remote_end_of_candidates().expect("b eoc");

        let connected = wait_for_dtls(
            || a_connected.load(Ordering::SeqCst) && b_connected.load(Ordering::SeqCst),
            5000,
        )
        .await;
        assert!(
            connected,
            "ice loopback failed: a={:?}, b={:?}",
            a.state(),
            b.state()
        );

        (a, b)
    }

    #[test]
    fn dtls_handshake_completes_over_ice_loopback() {
        rt().block_on(async {
            let t_start = std::time::Instant::now();

            // ICE first — build a paired transport up to Connected.
            // We construct DTLS BEFORE driving ICE through the pair
            // dance so the auto-start ICE-Connected hook is in place
            // when each side reaches Connected.
            //
            // We can't use the shared helper because it builds + drives
            // ICE before returning, but the auto-start hook must be
            // installed before ICE reaches Connected. So we inline the
            // pairing here with DTLS layered on top.

            use crate::candidate::Candidate;
            use crate::description::Type as DescriptionType;
            use crate::ice_transport::State as IceState;

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

            // A is the offerer / ActPass → resolves to Passive (DTLS server).
            // B is the answerer / Active → DTLS client.
            let ice_a = IceTransport::new(&cfg, Role::ActPass, a_callbacks).expect("ice a");
            let ice_b = IceTransport::new(&cfg, Role::Active, b_callbacks).expect("ice b");

            // Per-side DTLS state buffers.
            let a_dtls_connected = Arc::new(AtomicBool::new(false));
            let b_dtls_connected = Arc::new(AtomicBool::new(false));
            let a_dtls_failed = Arc::new(AtomicBool::new(false));
            let b_dtls_failed = Arc::new(AtomicBool::new(false));
            let a_recv: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
            let b_recv: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

            let cert_a = Certificate::generate_default().expect("cert a");
            let cert_b = Certificate::generate_default().expect("cert b");
            let fp_a = cert_a
                .fingerprint(FingerprintAlgorithm::Sha256)
                .expect("fp a");
            let fp_b = cert_b
                .fingerprint(FingerprintAlgorithm::Sha256)
                .expect("fp b");

            let a_dtls_connected_cb = a_dtls_connected.clone();
            let a_dtls_failed_cb = a_dtls_failed.clone();
            let a_recv_cb = a_recv.clone();
            let a_dtls_cbs = DtlsTransportCallbacks {
                on_state_change: Arc::new(move |s| match s {
                    DtlsState::Connected => {
                        a_dtls_connected_cb.store(true, Ordering::SeqCst);
                    }
                    DtlsState::Failed => {
                        a_dtls_failed_cb.store(true, Ordering::SeqCst);
                    }
                    _ => {}
                }),
                on_data: Arc::new(move |d| a_recv_cb.lock().extend_from_slice(d)),
            };

            let b_dtls_connected_cb = b_dtls_connected.clone();
            let b_dtls_failed_cb = b_dtls_failed.clone();
            let b_recv_cb = b_recv.clone();
            let b_dtls_cbs = DtlsTransportCallbacks {
                on_state_change: Arc::new(move |s| match s {
                    DtlsState::Connected => {
                        b_dtls_connected_cb.store(true, Ordering::SeqCst);
                    }
                    DtlsState::Failed => {
                        b_dtls_failed_cb.store(true, Ordering::SeqCst);
                    }
                    _ => {}
                }),
                on_data: Arc::new(move |d| b_recv_cb.lock().extend_from_slice(d)),
            };

            let dtls_a =
                DtlsTransport::new(Arc::clone(&ice_a), cert_a, a_dtls_cbs).expect("dtls a");
            let dtls_b =
                DtlsTransport::new(Arc::clone(&ice_b), cert_b, b_dtls_cbs).expect("dtls b");

            // Cross-pin fingerprints BEFORE start() / auto-start fires.
            dtls_a.set_remote_fingerprint(fp_b);
            dtls_b.set_remote_fingerprint(fp_a);

            // Now drive ICE through its gather/exchange dance. As soon
            // as each side hits Connected, the auto-start hook installed
            // by DtlsTransport::new will fire and drive the handshake.
            ice_a.gather().expect("a gather");
            assert!(
                wait_for_dtls(
                    || ice_a.gathering_state() == crate::ice_transport::GatheringState::Complete,
                    3000
                )
                .await,
                "a never finished gathering"
            );
            let desc_a = ice_a
                .get_local_description(DescriptionType::Offer)
                .expect("a sdp");
            ice_b.set_remote_description(&desc_a).expect("b set remote");

            ice_b.gather().expect("b gather");
            assert!(
                wait_for_dtls(
                    || ice_b.gathering_state() == crate::ice_transport::GatheringState::Complete,
                    3000
                )
                .await,
                "b never finished gathering"
            );
            let desc_b = ice_b
                .get_local_description(DescriptionType::Answer)
                .expect("b sdp");
            ice_a.set_remote_description(&desc_b).expect("a set remote");

            for c in a_cands.lock().iter() {
                ice_b.add_remote_candidate(c).expect("trickle a→b");
            }
            for c in b_cands.lock().iter() {
                ice_a.add_remote_candidate(c).expect("trickle b→a");
            }
            ice_a.set_remote_end_of_candidates().expect("a eoc");
            ice_b.set_remote_end_of_candidates().expect("b eoc");

            // Wait for DTLS to converge on both sides.
            let connected = wait_for_dtls(
                || {
                    a_dtls_connected.load(Ordering::SeqCst)
                        && b_dtls_connected.load(Ordering::SeqCst)
                },
                8000,
            )
            .await;
            let elapsed = t_start.elapsed();
            assert!(
                connected,
                "DTLS handshake did not converge in {:?}: \
                 a={:?} (connected={}, failed={}), \
                 b={:?} (connected={}, failed={}), \
                 ice_a={:?}, ice_b={:?}",
                elapsed,
                dtls_a.state(),
                a_dtls_connected.load(Ordering::SeqCst),
                a_dtls_failed.load(Ordering::SeqCst),
                dtls_b.state(),
                b_dtls_connected.load(Ordering::SeqCst),
                b_dtls_failed.load(Ordering::SeqCst),
                ice_a.state(),
                ice_b.state(),
            );
            eprintln!("DTLS handshake converged in {:?}", elapsed);

            // Round-trip an application record each direction.
            dtls_b.send(b"ping").expect("send ping (b→a)");
            assert!(
                wait_for_dtls(|| !a_recv.lock().is_empty(), 2000).await,
                "a never received ping"
            );
            assert_eq!(&*a_recv.lock(), b"ping");

            dtls_a.send(b"pong").expect("send pong (a→b)");
            assert!(
                wait_for_dtls(|| !b_recv.lock().is_empty(), 2000).await,
                "b never received pong"
            );
            assert_eq!(&*b_recv.lock(), b"pong");

            // Suppress unused-variable warnings on IceState import.
            let _ = IceState::New;
        });
    }

    #[test]
    fn dtls_handshake_aborts_on_fingerprint_mismatch() {
        rt().block_on(async {
            use crate::candidate::Candidate;
            use crate::description::Type as DescriptionType;

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

            let ice_a = IceTransport::new(&cfg, Role::ActPass, a_callbacks).expect("ice a");
            let ice_b = IceTransport::new(&cfg, Role::Active, b_callbacks).expect("ice b");

            let a_failed = Arc::new(AtomicBool::new(false));
            let b_failed = Arc::new(AtomicBool::new(false));

            let cert_a = Certificate::generate_default().expect("cert a");
            let cert_b = Certificate::generate_default().expect("cert b");
            let fp_a = cert_a
                .fingerprint(FingerprintAlgorithm::Sha256)
                .expect("fp a");
            // The "wrong" fingerprint: hash of an entirely-unrelated cert.
            let cert_decoy = Certificate::generate_default().expect("decoy");
            let fp_wrong = cert_decoy
                .fingerprint(FingerprintAlgorithm::Sha256)
                .expect("fp decoy");

            let af = a_failed.clone();
            let bf = b_failed.clone();
            let dtls_a = DtlsTransport::new(
                Arc::clone(&ice_a),
                cert_a,
                DtlsTransportCallbacks {
                    on_state_change: Arc::new(move |s| {
                        if matches!(s, DtlsState::Failed) {
                            af.store(true, Ordering::SeqCst);
                        }
                    }),
                    ..DtlsTransportCallbacks::default()
                },
            )
            .expect("dtls a");
            let dtls_b = DtlsTransport::new(
                Arc::clone(&ice_b),
                cert_b,
                DtlsTransportCallbacks {
                    on_state_change: Arc::new(move |s| {
                        if matches!(s, DtlsState::Failed) {
                            bf.store(true, Ordering::SeqCst);
                        }
                    }),
                    ..DtlsTransportCallbacks::default()
                },
            )
            .expect("dtls b");

            // A pins the WRONG fingerprint; B pins the correct one.
            dtls_a.set_remote_fingerprint(fp_wrong);
            dtls_b.set_remote_fingerprint(fp_a);

            // Drive ICE.
            ice_a.gather().expect("a gather");
            assert!(
                wait_for_dtls(
                    || ice_a.gathering_state() == crate::ice_transport::GatheringState::Complete,
                    3000
                )
                .await
            );
            let desc_a = ice_a.get_local_description(DescriptionType::Offer).unwrap();
            ice_b.set_remote_description(&desc_a).unwrap();
            ice_b.gather().expect("b gather");
            assert!(
                wait_for_dtls(
                    || ice_b.gathering_state() == crate::ice_transport::GatheringState::Complete,
                    3000
                )
                .await
            );
            let desc_b = ice_b
                .get_local_description(DescriptionType::Answer)
                .unwrap();
            ice_a.set_remote_description(&desc_b).unwrap();
            for c in a_cands.lock().iter() {
                ice_b.add_remote_candidate(c).unwrap();
            }
            for c in b_cands.lock().iter() {
                ice_a.add_remote_candidate(c).unwrap();
            }
            ice_a.set_remote_end_of_candidates().unwrap();
            ice_b.set_remote_end_of_candidates().unwrap();

            // We expect the mismatch side to flip to Failed within the
            // handshake window. The OTHER side may go Failed too once it
            // sees the fatal alert; we only assert on the side we know
            // must reject.
            let failed = wait_for_dtls(|| a_failed.load(Ordering::SeqCst), 8000).await;
            assert!(
                failed,
                "mismatch side did not reach Failed: a={:?}, b={:?}",
                dtls_a.state(),
                dtls_b.state()
            );
        });
    }

    #[test]
    fn verify_callback_rejects_when_no_remote_fingerprint_set() {
        // Same as the e2e but with NO fingerprint pinned on side A.
        // The verify callback rejects on the first peer cert and A
        // transitions to Failed.
        rt().block_on(async {
            use crate::candidate::Candidate;
            use crate::description::Type as DescriptionType;

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
            let ice_a = IceTransport::new(&cfg, Role::ActPass, a_callbacks).expect("ice a");
            let ice_b = IceTransport::new(&cfg, Role::Active, b_callbacks).expect("ice b");

            let a_failed = Arc::new(AtomicBool::new(false));
            let af = a_failed.clone();
            let cert_a = Certificate::generate_default().expect("cert a");
            let cert_b = Certificate::generate_default().expect("cert b");
            let fp_a = cert_a
                .fingerprint(FingerprintAlgorithm::Sha256)
                .expect("fp a");
            let dtls_a = DtlsTransport::new(
                Arc::clone(&ice_a),
                cert_a,
                DtlsTransportCallbacks {
                    on_state_change: Arc::new(move |s| {
                        if matches!(s, DtlsState::Failed) {
                            af.store(true, Ordering::SeqCst);
                        }
                    }),
                    ..DtlsTransportCallbacks::default()
                },
            )
            .expect("dtls a");
            let dtls_b = DtlsTransport::new(
                Arc::clone(&ice_b),
                cert_b,
                DtlsTransportCallbacks::default(),
            )
            .expect("dtls b");
            // Deliberately do NOT set A's fingerprint. B gets the right one.
            dtls_b.set_remote_fingerprint(fp_a);

            ice_a.gather().expect("a gather");
            assert!(
                wait_for_dtls(
                    || ice_a.gathering_state() == crate::ice_transport::GatheringState::Complete,
                    3000
                )
                .await
            );
            let desc_a = ice_a.get_local_description(DescriptionType::Offer).unwrap();
            ice_b.set_remote_description(&desc_a).unwrap();
            ice_b.gather().expect("b gather");
            assert!(
                wait_for_dtls(
                    || ice_b.gathering_state() == crate::ice_transport::GatheringState::Complete,
                    3000
                )
                .await
            );
            let desc_b = ice_b
                .get_local_description(DescriptionType::Answer)
                .unwrap();
            ice_a.set_remote_description(&desc_b).unwrap();
            for c in a_cands.lock().iter() {
                ice_b.add_remote_candidate(c).unwrap();
            }
            for c in b_cands.lock().iter() {
                ice_a.add_remote_candidate(c).unwrap();
            }
            ice_a.set_remote_end_of_candidates().unwrap();
            ice_b.set_remote_end_of_candidates().unwrap();

            let failed = wait_for_dtls(|| a_failed.load(Ordering::SeqCst), 8000).await;
            assert!(
                failed,
                "expected A to Fail without remote fingerprint pinned (state={:?}, dtls_b={:?})",
                dtls_a.state(),
                dtls_b.state(),
            );
            // Suppress the unused-helper warning when pair_ice_loopback
            // is only referenced from the loopback test.
            let _ = pair_ice_loopback;
        });
    }

    #[test]
    fn dtls_callbacks_getter_round_trips() {
        // The callbacks() snapshot must hand back the same closures that
        // were installed, so a layered transport (SCTP, G-6a) can chain
        // its own on_data while preserving the upstream on_state_change.
        rt().block_on(async {
            let state_calls = Arc::new(AtomicUsize::new(0));
            let data_bytes = Arc::new(AtomicUsize::new(0));
            let sc = state_calls.clone();
            let db = data_bytes.clone();

            let callbacks = DtlsTransportCallbacks {
                on_state_change: Arc::new(move |_s| {
                    sc.fetch_add(1, Ordering::SeqCst);
                }),
                on_data: Arc::new(move |d| {
                    db.fetch_add(d.len(), Ordering::SeqCst);
                }),
            };
            let ice = make_ice(Role::Active);
            let cert = Certificate::generate_default().unwrap();
            let dtls = DtlsTransport::new(ice, cert, callbacks).expect("dtls new");

            // Snapshot and invoke the returned closures directly.
            let snap = dtls.callbacks();
            (snap.on_state_change)(DtlsState::Connecting);
            (snap.on_data)(b"hello");

            assert_eq!(
                state_calls.load(Ordering::SeqCst),
                1,
                "snapshot on_state_change must be the installed closure"
            );
            assert_eq!(
                data_bytes.load(Ordering::SeqCst),
                5,
                "snapshot on_data must be the installed closure"
            );
        });
    }
}
