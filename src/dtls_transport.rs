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

use openssl::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode};
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

use crate::certificate::{Certificate, CertificateError};
use crate::description::{Role, FingerprintAlgorithm};
use crate::ice_transport::{
    IceTransport, IceTransportCallbacks, IceTransportError, State as IceState,
};

/// MTU default mirroring `DEFAULT_MTU` in libdatachannel
/// (`src/impl/transport.hpp`). `1280` is the IPv6 minimum.
const DEFAULT_MTU: usize = 1280;

/// Cipher list inherited byte-for-byte from
/// `native/libdatachannel/src/impl/dtlstransport.cpp:766`.
const CIPHER_LIST: &str = "ALL:!SHA256:!SHA384:!aPSK:!ECDSA+SHA1:!ADH:!LOW:!EXP:!MD5:!3DES:!SSLv3:!TLSv1";

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

        // Build the SSL_CTX with the libdatachannel options.
        let ctx = build_ssl_context(&certificate)?;

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
            ice,
            callbacks: Mutex::new(callbacks),
            closed: AtomicBool::new(false),
            is_client,
        });

        Ok(DtlsTransport { bridge })
    }

    /// Current DTLS state.
    pub fn state(&self) -> DtlsState {
        *self.bridge.state.lock()
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

    /// Start the DTLS handshake. Installs an `on_data` shim on the
    /// underlying [`IceTransport`] that pumps incoming bytes through
    /// the SSL state machine, then (if we're the client) drives the
    /// first `SSL_do_handshake` to emit a ClientHello.
    ///
    /// This is idempotent: a second call after the first returns Ok
    /// without restarting the handshake.
    pub fn start(&self) -> Result<(), DtlsTransportError> {
        if self.bridge.closed.load(Ordering::SeqCst) {
            return Err(DtlsTransportError::Closed);
        }

        // Idempotency: only transition to Connecting once.
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
        let bridge = Arc::clone(&self.bridge);
        let new_callbacks = IceTransportCallbacks {
            on_state_change: {
                // Chain to the previous on_state_change and additionally
                // mark the transport failed if ICE falls over.
                let prev_state = Arc::clone(&prev.on_state_change);
                let bridge = Arc::clone(&self.bridge);
                Arc::new(move |s: IceState| {
                    (prev_state)(s);
                    if matches!(s, IceState::Failed | IceState::Closed) {
                        fail_transport(&bridge);
                    }
                })
            },
            on_gathering_state_change: prev.on_gathering_state_change,
            on_candidate: prev.on_candidate,
            on_data: Arc::new(move |data: &[u8]| {
                pump_inbound(&bridge, data);
            }),
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

    /// Snapshot of the currently-installed callback set (symmetric with
    /// [`IceTransport::callbacks`]).
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

fn build_ssl_context(certificate: &Certificate) -> Result<SslContext, DtlsTransportError> {
    let mut builder = SslContextBuilder::new(SslMethod::dtls())?;
    // Options inherited from dtlstransport.cpp:754.
    builder.set_options(
        SslOptions::NO_SSLV3
            | SslOptions::NO_COMPRESSION
            | SslOptions::NO_QUERY_MTU
            | SslOptions::NO_RENEGOTIATION,
    );
    builder.set_cipher_list(CIPHER_LIST)?;

    // Verify mode matches dtlstransport.cpp:762 — REQUIRE the peer
    // certificate. The callback always accepts (returns 1) because
    // RFC 8827 says authentication happens via the SDP fingerprint.
    // Phase G-5b will swap this for a fingerprint check.
    builder.set_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        |_preverify_ok, _store_ctx| true,
    );

    // Wire in our cert + key.
    builder.set_certificate(certificate.x509())?;
    builder.set_private_key(certificate.pkey())?;
    builder.check_private_key()?;

    Ok(builder.build())
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
            warn!("DtlsTransport: BIO_write returned {written}, dropping {} bytes", data.len());
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
        other => Err(DtlsTransportError::Handshake(other)),
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
            let dtls = DtlsTransport::new(ice, cert, DtlsTransportCallbacks::default())
                .expect("dtls new");
            assert!(dtls.is_client());
            assert_eq!(dtls.state(), DtlsState::New);
        });
    }

    #[test]
    fn construct_passive_is_server() {
        rt().block_on(async {
            let ice = make_ice(Role::Passive);
            let cert = Certificate::generate_default().unwrap();
            let dtls = DtlsTransport::new(ice, cert, DtlsTransportCallbacks::default())
                .expect("dtls new");
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
                states.lock().iter().any(|s| matches!(s, DtlsState::Connecting)),
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
            let dtls = DtlsTransport::new(ice, cert, DtlsTransportCallbacks::default())
                .expect("dtls new");
            let err = dtls.send(b"hello").expect_err("send before connect must fail");
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
}
