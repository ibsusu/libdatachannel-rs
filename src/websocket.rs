//! WebSocket client — a native Rust port of libdatachannel's
//! `rtc::WebSocket` / `rtc::impl::WebSocket` (`src/websocket.cpp`,
//! `src/impl/websocket.cpp`) plus the RFC6455 framing and HTTP Upgrade
//! handshake from `src/impl/wstransport.cpp` and `src/impl/wshandshake.cpp`.
//!
//! ## Scope of this slice (task #31, pass 1)
//!
//! This pass lands the **pure, fully-testable** parts:
//!
//! - The [RFC6455 frame codec](Frame): [`Frame::encode`] / [`Frame::decode`],
//!   covering FIN, RSV (parsed, not used), the six opcodes, the MASK bit + the
//!   4-byte masking key, the 7/16/64-bit payload-length forms, client→server
//!   masking, unmasking on decode, and partial-buffer handling.
//! - The [handshake](WsHandshake): the client `GET … Upgrade: websocket`
//!   request, the `Sec-WebSocket-Key` → `Sec-WebSocket-Accept` computation
//!   (`base64(sha1(key + GUID))`), and parsing/validating the `101` response.
//! - [`WsUrl`] parsing for `ws://` and `wss://`.
//! - The [`WebSocket`] state-machine skeleton ([`State`], config, message
//!   buffering helpers).
//!
//! The **live transport** (TCP connect for `ws://`, OpenSSL TLS for `wss://`,
//! the read loop, ping/pong, and the C-API/`rtc::` adapter backing) is left as
//! an explicit [`WebSocketError::NotWired`] TODO for the next iteration; see
//! [`WebSocket::open`]. Nothing here opens a socket, so every path is unit
//! testable without a live server.
//!
//! ## On-the-wire layout (RFC6455 §5.2)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-------+-+-------------+-------------------------------+
//! |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//! |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//! |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//! +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//! |    Extended payload length continued, if payload len == 127   |
//! + - - - - - - - - - - - - - - - +-------------------------------+
//! |                               | Masking-key, if MASK set to 1 |
//! +-------------------------------+-------------------------------+
//! |    Masking-key (continued)    |          Payload Data         |
//! +-------------------------------+ - - - - - - - - - - - - - - - +
//! :                     Payload Data continued ...                :
//! +---------------------------------------------------------------+
//! ```

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use crossbeam_channel::{Receiver, Sender, TryRecvError, unbounded};
use openssl::pkey::PKey;
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslStream, SslVerifyMode};
use openssl::x509::X509;
use parking_lot::Mutex;
use rand::RngCore;
use sha1::{Digest, Sha1};
use thiserror::Error;

/// Default WebSocket max message size, mirrors
/// `DEFAULT_WS_MAX_MESSAGE_SIZE` in `impl/internals.hpp` (256 KiB).
pub const DEFAULT_WS_MAX_MESSAGE_SIZE: usize = 256 * 1024;

/// The RFC6455 magic GUID concatenated with the client key before SHA-1.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by WebSocket framing, handshake, URL parsing, and the
/// (not-yet-wired) connect path.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WebSocketError {
    /// A frame opcode byte was not one of the six RFC6455 opcodes.
    #[error("invalid WebSocket opcode: {0}")]
    InvalidOpcode(u8),

    /// The handshake response was malformed or rejected the upgrade.
    #[error("WebSocket handshake error: {0}")]
    Handshake(&'static str),

    /// The `ws://` / `wss://` URL could not be parsed.
    #[error("invalid WebSocket URL: {0}")]
    InvalidUrl(&'static str),

    /// The live TCP/TLS connect path is not implemented yet (task #31, pass 2).
    ///
    /// Retained for compatibility; [`WebSocket::open`] now drives a real
    /// transport and no longer returns this.
    #[error("WebSocket transport not yet wired")]
    NotWired,

    /// An operation was attempted in a state that does not allow it.
    #[error("WebSocket is not open")]
    NotOpen,

    /// A TCP/TLS-level transport failure (connect, handshake I/O, or read/write).
    /// Held as a `String` so [`WebSocketError`] keeps its `PartialEq`/`Eq`
    /// derivation (an `io::Error` / OpenSSL error would not).
    #[error("WebSocket transport error: {0}")]
    Transport(String),
}

/// Convenience alias.
pub type WsResult<T> = std::result::Result<T, WebSocketError>;

// ---------------------------------------------------------------------------
// Opcodes
// ---------------------------------------------------------------------------

/// RFC6455 frame opcode. Mirrors the `Opcode` enum in `impl/wstransport.hpp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// Continuation of a fragmented message.
    Continuation = 0,
    /// A text (UTF-8) message frame.
    Text = 1,
    /// A binary message frame.
    Binary = 2,
    /// Connection-close control frame.
    Close = 8,
    /// Ping control frame.
    Ping = 9,
    /// Pong control frame.
    Pong = 10,
}

impl Opcode {
    /// Parse a 4-bit opcode value, rejecting reserved opcodes.
    pub fn from_u8(v: u8) -> WsResult<Self> {
        Ok(match v {
            0 => Opcode::Continuation,
            1 => Opcode::Text,
            2 => Opcode::Binary,
            8 => Opcode::Close,
            9 => Opcode::Ping,
            10 => Opcode::Pong,
            other => return Err(WebSocketError::InvalidOpcode(other)),
        })
    }

    /// `true` for control opcodes (Close/Ping/Pong), which per RFC6455 §5.5
    /// carry at most 125 bytes and must not be fragmented.
    pub fn is_control(self) -> bool {
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong)
    }
}

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

/// A decoded / to-be-encoded RFC6455 frame. Mirrors the `Frame` struct in
/// `impl/wstransport.hpp`, but owns its (already unmasked) payload rather than
/// pointing into a shared buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The opcode.
    pub opcode: Opcode,
    /// The FIN bit: this frame is the final fragment of a message.
    pub fin: bool,
    /// Whether the frame was/will be masked. Client→server frames MUST be
    /// masked (RFC6455 §5.3); server→client frames MUST NOT be.
    pub mask: bool,
    /// The payload, already unmasked on decode (host order, application bytes).
    pub payload: Vec<u8>,
}

/// Result of [`Frame::decode`]: either a frame plus the number of bytes
/// consumed, or a signal that more bytes are needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeOutcome {
    /// A full frame was decoded; `consumed` bytes should be removed from the
    /// front of the input buffer.
    Frame {
        /// The decoded frame.
        frame: Frame,
        /// Number of bytes consumed from the buffer.
        consumed: usize,
    },
    /// The buffer does not yet hold a complete frame; wait for more bytes.
    NeedMore,
}

impl Frame {
    /// Build a non-fragmented data/control frame.
    pub fn new(opcode: Opcode, payload: Vec<u8>, mask: bool) -> Self {
        Frame {
            opcode,
            fin: true,
            mask,
            payload,
        }
    }

    /// Encode this frame into bytes (ports `WsTransport::sendFrame`).
    ///
    /// When `self.mask` is set, a random 4-byte masking key is generated and
    /// the payload is XOR-masked in the output — the input `self.payload` is
    /// left untouched. Header length is 2/4/10 bytes depending on payload
    /// length, plus 4 more if masked.
    pub fn encode(&self) -> Vec<u8> {
        let mut key = [0u8; 4];
        if self.mask {
            rand::thread_rng().fill_bytes(&mut key);
        }
        self.encode_with_key(if self.mask { Some(key) } else { None })
    }

    /// Deterministic variant of [`encode`](Self::encode) for tests: encode with
    /// an explicit masking key (or `None` for an unmasked frame). Panics if a
    /// key is supplied for a frame whose `mask` flag is false, or vice-versa,
    /// is not enforced — the key presence drives masking here.
    pub fn encode_with_key(&self, key: Option<[u8; 4]>) -> Vec<u8> {
        let masked = key.is_some();
        let len = self.payload.len();
        let mut out = Vec::with_capacity(len + 14);

        // Byte 1: FIN + RSV(0) + opcode.
        out.push((self.opcode as u8 & 0x0F) | if self.fin { 0x80 } else { 0 });

        // Byte 2: MASK + payload-length form.
        let mask_bit = if masked { 0x80u8 } else { 0 };
        if len < 0x7E {
            out.push((len as u8 & 0x7F) | mask_bit);
        } else if len <= 0xFFFF {
            out.push(0x7E | mask_bit);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0x7F | mask_bit);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }

        if let Some(key) = key {
            out.extend_from_slice(&key);
            out.extend(self.payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        } else {
            out.extend_from_slice(&self.payload);
        }

        out
    }

    /// Decode a single frame from the front of `buffer` (ports
    /// `WsTransport::parseFrame`). Returns [`DecodeOutcome::NeedMore`] if the
    /// buffer is too short for the header or the full payload. Masked frames
    /// are unmasked into the returned [`Frame::payload`].
    pub fn decode(buffer: &[u8]) -> WsResult<DecodeOutcome> {
        if buffer.len() < 2 {
            return Ok(DecodeOutcome::NeedMore);
        }

        let b1 = buffer[0];
        let b2 = buffer[1];

        let fin = (b1 & 0x80) != 0;
        let opcode = Opcode::from_u8(b1 & 0x0F)?;
        let mask = (b2 & 0x80) != 0;

        let mut cur = 2usize;
        let len7 = (b2 & 0x7F) as u64;
        let length: u64 = if len7 == 0x7E {
            if buffer.len() < cur + 2 {
                return Ok(DecodeOutcome::NeedMore);
            }
            let v = u16::from_be_bytes([buffer[cur], buffer[cur + 1]]) as u64;
            cur += 2;
            v
        } else if len7 == 0x7F {
            if buffer.len() < cur + 8 {
                return Ok(DecodeOutcome::NeedMore);
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&buffer[cur..cur + 8]);
            let v = u64::from_be_bytes(b);
            cur += 8;
            v
        } else {
            len7
        };

        let masking_key: Option<[u8; 4]> = if mask {
            if buffer.len() < cur + 4 {
                return Ok(DecodeOutcome::NeedMore);
            }
            let k = [
                buffer[cur],
                buffer[cur + 1],
                buffer[cur + 2],
                buffer[cur + 3],
            ];
            cur += 4;
            Some(k)
        } else {
            None
        };

        let length = length as usize;
        if buffer.len() < cur + length {
            return Ok(DecodeOutcome::NeedMore);
        }

        let mut payload = buffer[cur..cur + length].to_vec();
        if let Some(key) = masking_key {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= key[i % 4];
            }
        }
        let consumed = cur + length;

        Ok(DecodeOutcome::Frame {
            frame: Frame {
                opcode,
                fin,
                mask,
                payload,
            },
            consumed,
        })
    }
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

/// A parsed `ws://` / `wss://` URL. Ports the URL handling in
/// `impl::WebSocket::open` (`src/impl/websocket.cpp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsUrl {
    /// `true` for `wss://` (TLS), `false` for `ws://`.
    pub secure: bool,
    /// The host **without** port — used for TCP connect and TLS SNI. IPv6
    /// literals have their surrounding `[ ]` stripped.
    pub hostname: String,
    /// The port (numeric service). Defaults to 443 for `wss`, 80 for `ws`.
    pub port: u16,
    /// `host:port` (or bare host if the default port was implied) — used for
    /// the HTTP `Host:` header. Mirrors libdatachannel's `host`.
    pub host_header: String,
    /// The request path, always starting with `/`, including any `?query`.
    pub path: String,
}

impl WsUrl {
    /// Parse a WebSocket URL. The scheme defaults to `ws` when absent, matching
    /// the upstream regex behaviour.
    pub fn parse(url: &str) -> WsResult<WsUrl> {
        // Split scheme.
        let (scheme, rest) = match url.split_once("://") {
            Some((s, r)) => (s.to_ascii_lowercase(), r),
            None => ("ws".to_string(), url),
        };
        let secure = match scheme.as_str() {
            "ws" => false,
            "wss" => true,
            _ => return Err(WebSocketError::InvalidUrl("scheme must be ws or wss")),
        };

        // Strip any userinfo ("user:pass@host..."): upstream warns and ignores.
        let rest = match rest.split_once('@') {
            Some((_userinfo, after)) => after,
            None => rest,
        };

        // Authority ends at the first '/', '?' or '#'.
        let authority_end = rest
            .find(|c| c == '/' || c == '?' || c == '#')
            .unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let mut path_and_query = &rest[authority_end..];

        if authority.is_empty() {
            return Err(WebSocketError::InvalidUrl("missing host"));
        }

        // Split host and optional port, honouring IPv6 literals "[::1]:443".
        let (hostname_raw, port_str): (&str, Option<&str>) = if authority.starts_with('[') {
            let close = authority
                .find(']')
                .ok_or(WebSocketError::InvalidUrl("unterminated IPv6 literal"))?;
            let host = &authority[..=close];
            let after = &authority[close + 1..];
            let port = after.strip_prefix(':');
            (host, port)
        } else {
            match authority.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };

        // Default-port handling + Host header (matches `impl::WebSocket::open`).
        let (port, host_header) = match port_str {
            None | Some("") => {
                let p = if secure { 443 } else { 80 };
                (p, hostname_raw.to_string())
            }
            Some(p) => {
                let parsed: u16 = p
                    .parse()
                    .map_err(|_| WebSocketError::InvalidUrl("invalid port"))?;
                (parsed, format!("{hostname_raw}:{p}"))
            }
        };

        // Strip IPv6 brackets for the connect/SNI hostname.
        let hostname = if hostname_raw.starts_with('[') && hostname_raw.ends_with(']') {
            hostname_raw[1..hostname_raw.len() - 1].to_string()
        } else {
            hostname_raw.to_string()
        };
        if hostname.is_empty() {
            return Err(WebSocketError::InvalidUrl("missing host"));
        }

        // Path defaults to "/"; query is preserved, fragment dropped.
        let path = {
            let no_fragment = match path_and_query.split_once('#') {
                Some((p, _frag)) => p,
                None => path_and_query,
            };
            path_and_query = no_fragment;
            if path_and_query.is_empty() {
                "/".to_string()
            } else if path_and_query.starts_with('/') {
                path_and_query.to_string()
            } else {
                format!("/{path_and_query}")
            }
        };

        Ok(WsUrl {
            secure,
            hostname,
            port,
            host_header,
            path,
        })
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// Compute the `Sec-WebSocket-Accept` value for a given client key
/// (`base64(sha1(key + GUID))`). Ports `WsHandshake::computeAcceptKey`.
pub fn compute_accept_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    let digest = hasher.finalize();
    BASE64.encode(digest)
}

/// Generate a fresh random 16-byte base64 `Sec-WebSocket-Key`
/// (ports `WsHandshake::generateKey`).
pub fn generate_key() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    BASE64.encode(bytes)
}

/// The client side of the WebSocket HTTP/1.1 Upgrade handshake. Ports the
/// client-relevant parts of `rtc::impl::WsHandshake`.
#[derive(Debug, Clone)]
pub struct WsHandshake {
    host: String,
    path: String,
    protocols: Vec<String>,
    key: String,
}

impl WsHandshake {
    /// Construct a handshake. `host` is the `Host:` header value, `path` the
    /// request target. Both must be non-empty (mirrors the C++ ctor).
    pub fn new(
        host: impl Into<String>,
        path: impl Into<String>,
        protocols: Vec<String>,
    ) -> WsResult<Self> {
        let host = host.into();
        let path = path.into();
        if host.is_empty() {
            return Err(WebSocketError::Handshake("host cannot be empty"));
        }
        if path.is_empty() {
            return Err(WebSocketError::Handshake("path cannot be empty"));
        }
        Ok(WsHandshake {
            host,
            path,
            protocols,
            key: String::new(),
        })
    }

    /// The request path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The `Host:` header value.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The `Sec-WebSocket-Key` chosen for the most recent
    /// [`generate_http_request`](Self::generate_http_request).
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Build the client HTTP/1.1 Upgrade request, generating a fresh random
    /// `Sec-WebSocket-Key` and storing it for later accept validation. Ports
    /// `WsHandshake::generateHttpRequest`.
    pub fn generate_http_request(&mut self) -> String {
        self.key = generate_key();
        self.generate_http_request_with_key(self.key.clone())
    }

    /// Deterministic variant for tests: build the request with an explicit key.
    pub fn generate_http_request_with_key(&mut self, key: String) -> String {
        self.key = key;
        let mut out = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: {}\r\n",
            self.path, self.host, self.key
        );
        if !self.protocols.is_empty() {
            out.push_str("Sec-WebSocket-Protocol: ");
            out.push_str(&self.protocols.join(","));
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out
    }

    /// Parse and validate the server's `101 Switching Protocols` response
    /// against the stored key. Ports `WsHandshake::parseHttpResponse`.
    ///
    /// Returns `Ok(Some(len))` with the number of bytes consumed (through the
    /// terminating blank line) on success, `Ok(None)` if the response is not
    /// yet complete (no blank-line terminator), or an [`WebSocketError`] if the
    /// status, upgrade header, or accept value is wrong.
    pub fn parse_http_response(&self, buffer: &[u8]) -> WsResult<Option<usize>> {
        let (lines, len) = match parse_http_lines(buffer) {
            Some(v) => v,
            None => return Ok(None),
        };
        if lines.is_empty() {
            return Err(WebSocketError::Handshake("empty HTTP response"));
        }

        // Status line: "HTTP/1.1 101 Switching Protocols".
        let status = &lines[0];
        let mut it = status.split_whitespace();
        let _protocol = it.next();
        let code: u32 = it
            .next()
            .and_then(|c| c.parse().ok())
            .ok_or(WebSocketError::Handshake("missing response code"))?;
        if code != 101 {
            return Err(WebSocketError::Handshake("unexpected response code"));
        }

        let headers = parse_http_headers(&lines[1..]);

        let upgrade = headers
            .iter()
            .find(|(k, _)| k == "upgrade")
            .map(|(_, v)| v.to_ascii_lowercase());
        match upgrade.as_deref() {
            Some("websocket") => {}
            Some(_) => return Err(WebSocketError::Handshake("upgrade header mismatching")),
            None => return Err(WebSocketError::Handshake("upgrade header missing")),
        }

        let accept = headers
            .iter()
            .find(|(k, _)| k == "sec-websocket-accept")
            .map(|(_, v)| v.clone())
            .ok_or(WebSocketError::Handshake("accept header missing"))?;

        if accept != compute_accept_key(&self.key) {
            return Err(WebSocketError::Handshake("accept header is invalid"));
        }

        Ok(Some(len))
    }

    /// Server side: an empty handshake to be populated by
    /// [`parse_http_request`](Self::parse_http_request). Unlike [`new`](Self::new),
    /// this does not require host/path up front — the server learns them from
    /// the client's request line/headers.
    pub fn new_server() -> Self {
        WsHandshake {
            host: String::new(),
            path: String::new(),
            protocols: Vec::new(),
            key: String::new(),
        }
    }

    /// Server side: parse the client's `GET … Upgrade: websocket` request,
    /// storing the host, path, offered protocols, and `Sec-WebSocket-Key` on
    /// `self` for a subsequent [`generate_http_response`](Self::generate_http_response).
    /// Ports `WsHandshake::parseHttpRequest`.
    ///
    /// Returns `Ok(Some(len))` with the bytes consumed through the terminating
    /// blank line on success, `Ok(None)` if the request is not yet complete, or
    /// an [`WebSocketError::Handshake`] if the method, upgrade header, or key is
    /// missing/invalid.
    pub fn parse_http_request(&mut self, buffer: &[u8]) -> WsResult<Option<usize>> {
        // Cheap early reject of obvious non-HTTP bytes (ports http.cpp isHttpRequest).
        if !buffer.is_empty() && !is_http_request(buffer) {
            return Err(WebSocketError::Handshake("not an HTTP request"));
        }
        let (lines, len) = match parse_http_lines(buffer) {
            Some(v) => v,
            None => return Ok(None),
        };
        if lines.is_empty() {
            return Err(WebSocketError::Handshake("empty HTTP request"));
        }

        // Request line: "GET /path HTTP/1.1".
        let mut it = lines[0].split_whitespace();
        let method = it.next().unwrap_or("");
        if method != "GET" {
            return Err(WebSocketError::Handshake("invalid request method"));
        }
        let path = it.next().unwrap_or("/");
        self.path = if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };

        let headers = parse_http_headers(&lines[1..]);

        self.host = headers
            .iter()
            .find(|(k, _)| k == "host")
            .map(|(_, v)| v.clone())
            .ok_or(WebSocketError::Handshake("host header missing"))?;

        let upgrade = headers
            .iter()
            .find(|(k, _)| k == "upgrade")
            .map(|(_, v)| v.to_ascii_lowercase());
        match upgrade.as_deref() {
            Some("websocket") => {}
            Some(_) => return Err(WebSocketError::Handshake("upgrade header mismatching")),
            None => return Err(WebSocketError::Handshake("upgrade header missing")),
        }

        self.key = headers
            .iter()
            .find(|(k, _)| k == "sec-websocket-key")
            .map(|(_, v)| v.clone())
            .ok_or(WebSocketError::Handshake("key header missing"))?;

        self.protocols = headers
            .iter()
            .find(|(k, _)| k == "sec-websocket-protocol")
            .map(|(_, v)| {
                v.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        Ok(Some(len))
    }

    /// Server side: build the `101 Switching Protocols` response echoing
    /// `Sec-WebSocket-Accept = base64(sha1(key + GUID))` (and any negotiated
    /// protocols). Ports `WsHandshake::generateHttpResponse`. Call only after a
    /// successful [`parse_http_request`](Self::parse_http_request).
    pub fn generate_http_response(&self) -> String {
        let mut out = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Server: libdatachannel-rust\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Accept: {}\r\n",
            compute_accept_key(&self.key)
        );
        if !self.protocols.is_empty() {
            out.push_str("Sec-WebSocket-Protocol: ");
            out.push_str(&self.protocols.join(","));
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out
    }
}

/// Cheap heuristic: does `buffer` look like the start of an HTTP request line?
/// The first token (up to the first space, capped at 8 bytes) must be all
/// uppercase ASCII letters (the method). Ports `http.cpp::isHttpRequest`.
fn is_http_request(buffer: &[u8]) -> bool {
    let probe = &buffer[..buffer.len().min(8)];
    let mut saw_letter = false;
    for &b in probe {
        if b == b' ' {
            return saw_letter;
        }
        if !b.is_ascii_uppercase() {
            return false;
        }
        saw_letter = true;
    }
    // No space yet within the probe window — still plausibly a method prefix.
    saw_letter
}

/// Parse an HTTP message into header lines, returning the lines plus the total
/// byte length consumed through the terminating blank line. Returns `None` when
/// the blank-line terminator has not arrived yet. Ports `parseHttpLines`.
fn parse_http_lines(buffer: &[u8]) -> Option<(Vec<String>, usize)> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < buffer.len() {
        if buffer[i] == b'\n' {
            // Drop a trailing '\r' if present.
            let mut line_end = i;
            if line_end > start && buffer[line_end - 1] == b'\r' {
                line_end -= 1;
            }
            let line = String::from_utf8_lossy(&buffer[start..line_end]).into_owned();
            let consumed = i + 1;
            if line.is_empty() {
                // Blank line terminates the header section.
                return Some((lines, consumed));
            }
            lines.push(line);
            start = consumed;
        }
        i += 1;
    }
    None
}

/// Parse `Key: Value` header lines into lowercased-key pairs. Ports
/// `parseHttpHeaders`.
fn parse_http_headers(lines: &[String]) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for line in lines {
        if let Some(pos) = line.find(':') {
            let key = line[..pos].trim().to_ascii_lowercase();
            let value = line[pos + 1..].trim_start().to_string();
            headers.push((key, value));
        } else {
            headers.push((line.to_ascii_lowercase(), String::new()));
        }
    }
    headers
}

// ---------------------------------------------------------------------------
// WebSocket state machine (skeleton)
// ---------------------------------------------------------------------------

/// WebSocket ready state. Mirrors `rtc::WebSocket::State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum State {
    /// The connection is being established (TCP/TLS/handshake in progress).
    Connecting = 0,
    /// The handshake completed and messages may flow.
    Open = 1,
    /// A close has been initiated.
    Closing = 2,
    /// The connection is fully closed.
    Closed = 3,
}

impl State {
    /// Reconstruct a state from its `#[repr(i32)]` value (used to read the
    /// lock-free [`AtomicI32`] the transport thread shares with the handle).
    /// Unknown values map to [`State::Closed`].
    fn from_i32(v: i32) -> State {
        match v {
            0 => State::Connecting,
            1 => State::Open,
            2 => State::Closing,
            _ => State::Closed,
        }
    }
}

/// Configuration for a [`WebSocket`]. Mirrors the client-relevant fields of
/// `rtc::WebSocketConfiguration`.
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Skip TLS certificate verification for `wss://` (dev only).
    pub disable_tls_verification: bool,
    /// Sub-protocols offered in `Sec-WebSocket-Protocol`.
    pub protocols: Vec<String>,
    /// Maximum inbound/outbound message size; defaults to
    /// [`DEFAULT_WS_MAX_MESSAGE_SIZE`] when `None`.
    pub max_message_size: Option<usize>,
    /// Max outstanding unanswered pings before the connection is failed
    /// (0 / `None` disables the check).
    pub max_outstanding_pings: Option<u32>,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        WebSocketConfig {
            disable_tls_verification: false,
            protocols: Vec::new(),
            max_message_size: None,
            max_outstanding_pings: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Live transport (task #31, pass 2)
// ---------------------------------------------------------------------------

/// Inbound-message callback: invoked from the transport thread for every
/// reassembled [`WsMessage`]. (Internal; callers pass an `impl Fn` to the
/// `set_on_*` setters and never name this type.)
pub(crate) type OnMessage = Arc<dyn Fn(WsMessage) + Send + Sync>;
/// Fired once the HTTP Upgrade handshake completes and the socket is open.
pub(crate) type OnOpen = Arc<dyn Fn() + Send + Sync>;
/// Fired once when the connection reaches [`State::Closed`].
pub(crate) type OnClosed = Arc<dyn Fn() + Send + Sync>;
/// Fired on a transport/handshake failure, with a human-readable reason.
pub(crate) type OnError = Arc<dyn Fn(String) + Send + Sync>;

/// State shared (via `Arc`) between the [`WebSocket`] handle and its transport
/// thread. The ready-state is a lock-free [`AtomicI32`] (mirrors the
/// `std::atomic<State>` in `rtc::impl::WebSocket`); callbacks sit behind small
/// mutexes and are cloned out before invocation so a callback never runs with a
/// lock held. Mirrors the shared-state + callback pattern in
/// `dtls_transport.rs` / `ice_transport.rs`.
struct WsShared {
    state: AtomicI32,
    on_message: Mutex<Option<OnMessage>>,
    on_open: Mutex<Option<OnOpen>>,
    on_closed: Mutex<Option<OnClosed>>,
    on_error: Mutex<Option<OnError>>,
}

impl WsShared {
    fn new() -> Self {
        WsShared {
            state: AtomicI32::new(State::Closed as i32),
            on_message: Mutex::new(None),
            on_open: Mutex::new(None),
            on_closed: Mutex::new(None),
            on_error: Mutex::new(None),
        }
    }

    fn state(&self) -> State {
        State::from_i32(self.state.load(Ordering::SeqCst))
    }

    fn set_state(&self, s: State) {
        self.state.store(s as i32, Ordering::SeqCst);
    }

    fn fire_open(&self) {
        let cb = self.on_open.lock().clone();
        if let Some(cb) = cb {
            cb();
        }
    }

    fn fire_message(&self, msg: WsMessage) {
        let cb = self.on_message.lock().clone();
        if let Some(cb) = cb {
            cb(msg);
        }
    }

    fn fire_closed(&self) {
        let cb = self.on_closed.lock().clone();
        if let Some(cb) = cb {
            cb();
        }
    }

    fn fire_error(&self, reason: String) {
        let cb = self.on_error.lock().clone();
        if let Some(cb) = cb {
            cb(reason);
        }
    }
}

/// An outbound command pushed from the handle to the transport thread.
enum OutMsg {
    /// A pre-encoded (masked) frame to write to the socket.
    Frame(Vec<u8>),
    /// Initiate a clean close: send a Close frame, then tear down.
    Close,
}

/// The live byte stream: plain TCP for `ws://`, OpenSSL TLS for `wss://`.
/// `SslStream` is boxed to keep the enum small and avoid moving a large value.
enum WsStream {
    Plain(TcpStream),
    Tls(Box<SslStream<TcpStream>>),
}

impl WsStream {
    /// Set the read timeout on the underlying socket (drives the poll cadence of
    /// the frame read loop). For TLS this reaches through to the wrapped socket.
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        match self {
            WsStream::Plain(s) => s.set_read_timeout(d),
            WsStream::Tls(s) => s.get_ref().set_read_timeout(d),
        }
    }
}

impl Read for WsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            WsStream::Plain(s) => s.read(buf),
            WsStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for WsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            WsStream::Plain(s) => s.write(buf),
            WsStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            WsStream::Plain(s) => s.flush(),
            WsStream::Tls(s) => s.flush(),
        }
    }
}

/// `true` for a benign socket-timeout error (the read-timeout poll fired with no
/// data) — the loop should simply retry, not treat it as a fatal error.
fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Read-loop poll cadence: bounds how long an outbound send waits before the
/// thread notices it. Small enough to feel synchronous on a signaling channel.
const READ_POLL: Duration = Duration::from_millis(20);
/// Upper bound on the blocking connect + HTTP-Upgrade handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Reassembles inbound data/continuation frames into whole [`WsMessage`]s,
/// applying the `max` size cap (truncating, as upstream does). Used by the
/// transport thread; the synchronous [`WebSocket::ingest_frame`] keeps its own
/// inline copy for the unit-test surface.
#[derive(Default)]
struct Reassembler {
    partial: Vec<u8>,
    partial_is_text: bool,
    have_partial: bool,
}

impl Reassembler {
    fn push(&mut self, frame: &Frame, max: usize) -> Option<WsMessage> {
        match frame.opcode {
            Opcode::Text | Opcode::Binary => {
                let is_text = frame.opcode == Opcode::Text;
                if frame.fin {
                    let mut data = frame.payload.clone();
                    data.truncate(max);
                    Some(if is_text {
                        WsMessage::Text(data)
                    } else {
                        WsMessage::Binary(data)
                    })
                } else {
                    self.partial_is_text = is_text;
                    self.have_partial = true;
                    self.partial.clear();
                    self.partial.extend_from_slice(&frame.payload);
                    self.partial.truncate(max);
                    None
                }
            }
            Opcode::Continuation => {
                self.partial.extend_from_slice(&frame.payload);
                if self.partial.len() > max {
                    self.partial.truncate(max);
                }
                if frame.fin && self.have_partial {
                    self.have_partial = false;
                    let data = std::mem::take(&mut self.partial);
                    Some(if self.partial_is_text {
                        WsMessage::Text(data)
                    } else {
                        WsMessage::Binary(data)
                    })
                } else {
                    None
                }
            }
            Opcode::Ping | Opcode::Pong | Opcode::Close => None,
        }
    }
}

/// Transport-thread entry point: connect + handshake, then run the read loop.
/// Mirrors the lifecycle of `rtc::impl::WsTransport` (connect → open → recv loop
/// → closed). On any failure it fires `on_error` and transitions to `Closed`.
fn run_ws_client(
    url: WsUrl,
    handshake: WsHandshake,
    config: WebSocketConfig,
    shared: Arc<WsShared>,
    outbound: Receiver<OutMsg>,
) {
    match connect_and_handshake(&url, handshake, &config) {
        Ok((stream, leftover)) => {
            shared.set_state(State::Open);
            shared.fire_open();
            read_loop(stream, leftover, &config, &shared, &outbound, true);
            shared.set_state(State::Closed);
            shared.fire_closed();
        }
        Err(e) => {
            shared.fire_error(e.to_string());
            shared.set_state(State::Closed);
            shared.fire_closed();
        }
    }
}

/// TCP connect (+ optional TLS), then drive the client HTTP Upgrade handshake.
/// Returns the live stream plus any bytes already read past the response
/// headers (the leading bytes of the first frame, which arrived in the same
/// segment as the `101` response).
fn connect_and_handshake(
    url: &WsUrl,
    mut handshake: WsHandshake,
    config: &WebSocketConfig,
) -> WsResult<(WsStream, Vec<u8>)> {
    let tcp = TcpStream::connect((url.hostname.as_str(), url.port)).map_err(|e| {
        WebSocketError::Transport(format!("connect {}:{}: {e}", url.hostname, url.port))
    })?;
    tcp.set_nodelay(true).ok();
    // Bound the blocking handshake so a silent peer can't wedge the thread.
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| WebSocketError::Transport(format!("set_read_timeout: {e}")))?;

    let mut stream = if url.secure {
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| WebSocketError::Transport(format!("TLS init: {e}")))?;
        if config.disable_tls_verification {
            builder.set_verify(SslVerifyMode::NONE);
        }
        let connector = builder.build();
        let mut cfg = connector
            .configure()
            .map_err(|e| WebSocketError::Transport(format!("TLS configure: {e}")))?;
        if config.disable_tls_verification {
            cfg.set_verify_hostname(false);
        }
        let ssl = cfg
            .connect(&url.hostname, tcp)
            .map_err(|e| WebSocketError::Transport(format!("TLS handshake: {e}")))?;
        WsStream::Tls(Box::new(ssl))
    } else {
        WsStream::Plain(tcp)
    };

    // Send the GET ... Upgrade request.
    let request = handshake.generate_http_request();
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|e| WebSocketError::Transport(format!("write handshake: {e}")))?;

    // Read until the response headers are complete; keep any trailing bytes.
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(consumed) = handshake.parse_http_response(&buf)? {
            let leftover = buf[consumed..].to_vec();
            return Ok((stream, leftover));
        }
        let n = stream
            .read(&mut tmp)
            .map_err(|e| WebSocketError::Transport(format!("read handshake: {e}")))?;
        if n == 0 {
            return Err(WebSocketError::Transport(
                "connection closed during handshake".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// The frame read/write loop: drains outbound commands, decodes inbound frames,
/// answers pings, honours close, and delivers data messages via `on_message`.
/// Returns when the peer closes, a local close completes, the handle is dropped
/// (outbound channel disconnected), or a fatal I/O error occurs.
fn read_loop(
    mut stream: WsStream,
    leftover: Vec<u8>,
    config: &WebSocketConfig,
    shared: &Arc<WsShared>,
    outbound: &Receiver<OutMsg>,
    is_client: bool,
) {
    // Switch from the blocking handshake timeout to the short poll cadence.
    let _ = stream.set_read_timeout(Some(READ_POLL));
    let max = config
        .max_message_size
        .unwrap_or(DEFAULT_WS_MAX_MESSAGE_SIZE);
    let mut reasm = Reassembler::default();
    let mut inbuf = leftover;
    let mut tmp = [0u8; 8192];

    'outer: loop {
        // 1. Drain outbound commands.
        loop {
            match outbound.try_recv() {
                Ok(OutMsg::Frame(bytes)) => {
                    if stream
                        .write_all(&bytes)
                        .and_then(|()| stream.flush())
                        .is_err()
                    {
                        break 'outer;
                    }
                }
                Ok(OutMsg::Close) => {
                    shared.set_state(State::Closing);
                    let close = Frame::new(Opcode::Close, Vec::new(), is_client).encode();
                    let _ = stream.write_all(&close).and_then(|()| stream.flush());
                    break 'outer;
                }
                Err(TryRecvError::Empty) => break,
                // Handle dropped: shut down cleanly.
                Err(TryRecvError::Disconnected) => break 'outer,
            }
        }

        // 2. Decode and dispatch any frames already buffered.
        loop {
            match Frame::decode(&inbuf) {
                Ok(DecodeOutcome::Frame { frame, consumed }) => {
                    inbuf.drain(..consumed);
                    match frame.opcode {
                        Opcode::Ping => {
                            let pong =
                                Frame::new(Opcode::Pong, frame.payload.clone(), is_client).encode();
                            if stream
                                .write_all(&pong)
                                .and_then(|()| stream.flush())
                                .is_err()
                            {
                                break 'outer;
                            }
                        }
                        Opcode::Close => {
                            shared.set_state(State::Closing);
                            let close = Frame::new(Opcode::Close, Vec::new(), is_client).encode();
                            let _ = stream.write_all(&close).and_then(|()| stream.flush());
                            break 'outer;
                        }
                        Opcode::Pong => {}
                        _ => {
                            if let Some(msg) = reasm.push(&frame, max) {
                                shared.fire_message(msg);
                            }
                        }
                    }
                }
                Ok(DecodeOutcome::NeedMore) => break,
                Err(_) => {
                    shared.fire_error("malformed inbound frame".into());
                    break 'outer;
                }
            }
        }

        // 3. Read more bytes (blocks up to READ_POLL).
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => inbuf.extend_from_slice(&tmp[..n]),
            Err(ref e) if is_timeout(e) => {}
            Err(_) => break,
        }
    }
}

/// A WebSocket client — a native Rust port of `rtc::WebSocket`. The handle owns
/// the configuration and the synchronous frame-reassembly helpers; once
/// [`open`](Self::open) is called it spawns a transport thread that owns the
/// live socket and shares ready-state + callbacks via [`WsShared`].
pub struct WebSocket {
    config: WebSocketConfig,
    url: Option<WsUrl>,
    handshake: Option<WsHandshake>,
    /// Inbound message queue for the synchronous [`Self::ingest_frame`] surface.
    recv_queue: VecDeque<WsMessage>,
    /// Partial (fragmented) message accumulator (synchronous surface).
    partial: Vec<u8>,
    partial_is_text: bool,
    have_partial: bool,
    /// Shared state + callbacks; the atomic ready-state lives here.
    shared: Arc<WsShared>,
    /// Outbound command channel to the transport thread (set once open).
    outbound_tx: Option<Sender<OutMsg>>,
    /// The transport thread handle (detached on drop).
    thread: Option<JoinHandle<()>>,
    /// `true` for a client socket (sends masked frames), `false` for a
    /// server-side accepted socket (sends unmasked frames) — RFC6455 §5.1.
    is_client: bool,
    /// Peer address (`ip:port`) of an accepted server-side connection, captured
    /// from the TCP socket before any TLS wrap. `None` for client sockets.
    remote_address: Option<String>,
}

impl std::fmt::Debug for WebSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocket")
            .field("state", &self.shared.state())
            .field("url", &self.url)
            .field("running", &self.thread.is_some())
            .finish()
    }
}

/// A reassembled inbound WebSocket message handed to the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsMessage {
    /// A UTF-8 text message (raw bytes; not validated as UTF-8 here).
    Text(Vec<u8>),
    /// A binary message.
    Binary(Vec<u8>),
}

impl WebSocket {
    /// Create a closed WebSocket with the given configuration.
    pub fn new(config: WebSocketConfig) -> Self {
        WebSocket {
            config,
            url: None,
            handshake: None,
            recv_queue: VecDeque::new(),
            partial: Vec::new(),
            partial_is_text: false,
            have_partial: false,
            shared: Arc::new(WsShared::new()),
            outbound_tx: None,
            thread: None,
            is_client: true,
            remote_address: None,
        }
    }

    /// Build a server-side WebSocket around an already-accepted, already-
    /// handshaken stream and spawn its read loop. The socket starts [`State::Open`]
    /// and sends **unmasked** frames (`is_client = false`). Used by
    /// [`WebSocketServer`] after [`server_handshake`] completes.
    fn from_accepted(
        stream: WsStream,
        leftover: Vec<u8>,
        handshake: WsHandshake,
        config: WebSocketConfig,
        remote_address: Option<String>,
    ) -> Self {
        let shared = Arc::new(WsShared::new());
        shared.set_state(State::Open);
        let (tx, rx) = unbounded::<OutMsg>();
        let shared_t = shared.clone();
        let config_t = config.clone();
        let handle = thread::Builder::new()
            .name("ws-server-conn".into())
            .spawn(move || {
                shared_t.fire_open();
                read_loop(stream, leftover, &config_t, &shared_t, &rx, false);
                shared_t.set_state(State::Closed);
                shared_t.fire_closed();
            })
            .expect("spawn ws-server-conn thread");
        WebSocket {
            config,
            url: None,
            handshake: Some(handshake),
            recv_queue: VecDeque::new(),
            partial: Vec::new(),
            partial_is_text: false,
            have_partial: false,
            shared,
            outbound_tx: Some(tx),
            thread: Some(handle),
            is_client: false,
            remote_address,
        }
    }

    /// The current ready state (read from the atomic the transport thread shares).
    pub fn ready_state(&self) -> State {
        self.shared.state()
    }

    /// `true` iff [`State::Open`].
    pub fn is_open(&self) -> bool {
        self.ready_state() == State::Open
    }

    /// `true` iff [`State::Closed`].
    pub fn is_closed(&self) -> bool {
        self.ready_state() == State::Closed
    }

    /// Register the inbound-message callback (invoked from the transport thread).
    pub fn set_on_message(&self, f: impl Fn(WsMessage) + Send + Sync + 'static) {
        *self.shared.on_message.lock() = Some(Arc::new(f));
    }

    /// Register the open callback (fires once the handshake completes).
    pub fn set_on_open(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.shared.on_open.lock() = Some(Arc::new(f));
    }

    /// Register the closed callback (fires once when fully closed).
    pub fn set_on_closed(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.shared.on_closed.lock() = Some(Arc::new(f));
    }

    /// Register the error callback (fires on a transport/handshake failure).
    pub fn set_on_error(&self, f: impl Fn(String) + Send + Sync + 'static) {
        *self.shared.on_error.lock() = Some(Arc::new(f));
    }

    /// The effective max message size.
    pub fn max_message_size(&self) -> usize {
        self.config
            .max_message_size
            .unwrap_or(DEFAULT_WS_MAX_MESSAGE_SIZE)
    }

    /// The negotiated request path, available once [`open`](Self::open) has
    /// parsed a URL (i.e. not while `Closed`).
    pub fn path(&self) -> Option<&str> {
        if self.ready_state() == State::Connecting {
            return None;
        }
        self.handshake.as_ref().map(|h| h.path())
    }

    /// The peer address (`ip:port`) of an accepted server-side connection.
    /// `None` for client sockets (which know only the URL they dialed).
    pub fn remote_address(&self) -> Option<&str> {
        self.remote_address.as_deref()
    }

    /// Begin opening the WebSocket to `url`.
    ///
    /// **Non-blocking.** It parses/validates the URL, transitions to
    /// [`State::Connecting`], and spawns a transport thread that performs the
    /// TCP connect (TLS for `wss://`), drives the HTTP Upgrade handshake, and
    /// then runs the frame read/write loop. Connection progress is observed via
    /// [`Self::ready_state`] and the registered callbacks
    /// ([`Self::set_on_open`] / [`Self::set_on_message`] / [`Self::set_on_closed`]
    /// / [`Self::set_on_error`]). Returns immediately with `Ok(())` once the
    /// thread is spawned; transport failures surface on the error callback and
    /// drive the state to [`State::Closed`].
    pub fn open(&mut self, url: &str) -> WsResult<()> {
        if self.ready_state() != State::Closed {
            return Err(WebSocketError::NotOpen);
        }
        let parsed = WsUrl::parse(url)?;
        let handshake = WsHandshake::new(
            parsed.host_header.clone(),
            parsed.path.clone(),
            self.config.protocols.clone(),
        )?;

        // Connecting is set synchronously, before the thread runs, so callers
        // observe the transition the moment `open` returns.
        self.shared.set_state(State::Connecting);

        let (tx, rx) = unbounded::<OutMsg>();
        let shared = self.shared.clone();
        let config = self.config.clone();
        let url_for_thread = parsed.clone();
        let handshake_for_thread = handshake.clone();
        let handle = thread::Builder::new()
            .name("ws-client".into())
            .spawn(move || run_ws_client(url_for_thread, handshake_for_thread, config, shared, rx))
            .map_err(|e| WebSocketError::Transport(format!("spawn transport thread: {e}")))?;

        self.url = Some(parsed);
        self.handshake = Some(handshake);
        self.outbound_tx = Some(tx);
        self.thread = Some(handle);
        Ok(())
    }

    /// Send a text message over the live transport. Returns
    /// [`WebSocketError::NotOpen`] unless the socket is open.
    pub fn send_text(&self, data: &[u8]) -> WsResult<()> {
        self.send_frame(Opcode::Text, data)
    }

    /// Send a binary message over the live transport.
    pub fn send_binary(&self, data: &[u8]) -> WsResult<()> {
        self.send_frame(Opcode::Binary, data)
    }

    fn send_frame(&self, opcode: Opcode, data: &[u8]) -> WsResult<()> {
        if self.ready_state() != State::Open {
            return Err(WebSocketError::NotOpen);
        }
        let tx = self.outbound_tx.as_ref().ok_or(WebSocketError::NotOpen)?;
        // Client frames MUST be masked, server frames MUST NOT (RFC6455 §5.1/§5.3).
        let bytes = Frame::new(opcode, data.to_vec(), self.is_client).encode();
        tx.send(OutMsg::Frame(bytes))
            .map_err(|_| WebSocketError::Transport("transport thread gone".into()))
    }

    /// Initiate a clean close. Idempotent; safe to call when not open.
    pub fn close(&self) {
        if let Some(tx) = self.outbound_tx.as_ref() {
            let _ = tx.send(OutMsg::Close);
        }
    }

    /// Encode an outbound text message as one (masked, client-side) frame.
    /// Returns [`WebSocketError::NotOpen`] unless the socket is open.
    pub fn encode_send_text(&self, data: &[u8]) -> WsResult<Vec<u8>> {
        self.encode_send(Opcode::Text, data)
    }

    /// Encode an outbound binary message as one (masked, client-side) frame.
    pub fn encode_send_binary(&self, data: &[u8]) -> WsResult<Vec<u8>> {
        self.encode_send(Opcode::Binary, data)
    }

    fn encode_send(&self, opcode: Opcode, data: &[u8]) -> WsResult<Vec<u8>> {
        if self.ready_state() != State::Open {
            return Err(WebSocketError::NotOpen);
        }
        // Client frames MUST be masked, server frames MUST NOT (RFC6455 §5.1/§5.3).
        Ok(Frame::new(opcode, data.to_vec(), self.is_client).encode())
    }

    /// Feed a decoded inbound frame into the reassembly state machine, queuing
    /// any completed [`WsMessage`]. Ports the data-frame handling of
    /// `WsTransport::recvFrame` (control-frame side effects — pong replies,
    /// close — are handled by the transport in pass 2). Frames whose data
    /// would exceed [`Self::max_message_size`] are truncated, as upstream does.
    pub fn ingest_frame(&mut self, frame: &Frame) {
        let max = self.max_message_size();
        match frame.opcode {
            Opcode::Text | Opcode::Binary => {
                // A new data frame implicitly finishes any dangling partial.
                if self.have_partial {
                    let kind = if self.partial_is_text {
                        WsMessage::Text(std::mem::take(&mut self.partial))
                    } else {
                        WsMessage::Binary(std::mem::take(&mut self.partial))
                    };
                    self.recv_queue.push_back(kind);
                    self.partial.clear();
                    self.have_partial = false;
                }
                let is_text = frame.opcode == Opcode::Text;
                if frame.fin {
                    let mut data = frame.payload.clone();
                    data.truncate(max);
                    self.recv_queue.push_back(if is_text {
                        WsMessage::Text(data)
                    } else {
                        WsMessage::Binary(data)
                    });
                } else {
                    self.partial_is_text = is_text;
                    self.have_partial = true;
                    self.partial.extend_from_slice(&frame.payload);
                    if self.partial.len() > max {
                        self.partial.truncate(max);
                    }
                }
            }
            Opcode::Continuation => {
                self.partial.extend_from_slice(&frame.payload);
                if self.partial.len() > max {
                    self.partial.truncate(max);
                }
                if frame.fin {
                    let kind = if self.partial_is_text {
                        WsMessage::Text(std::mem::take(&mut self.partial))
                    } else {
                        WsMessage::Binary(std::mem::take(&mut self.partial))
                    };
                    self.recv_queue.push_back(kind);
                    self.partial.clear();
                    self.have_partial = false;
                }
            }
            // Control frames carry no application message; transport handles them.
            Opcode::Ping | Opcode::Pong | Opcode::Close => {}
        }
    }

    /// Pop the next reassembled inbound message, if any.
    pub fn receive(&mut self) -> Option<WsMessage> {
        self.recv_queue.pop_front()
    }

    /// Force the state to [`State::Open`] — test hook for exercising the
    /// synchronous frame/encode helpers without a live socket.
    #[doc(hidden)]
    pub fn force_open_for_test(&mut self) {
        self.shared.set_state(State::Open);
    }
}

// ---------------------------------------------------------------------------
// WebSocketServer (task #32)
// ---------------------------------------------------------------------------

/// Configuration for a [`WebSocketServer`] — ports the client-relevant fields
/// of `rtc::WebSocketServerConfiguration`. TLS material is supplied as PEM
/// strings (load from file at the call site) to avoid filesystem coupling.
#[derive(Debug, Clone)]
pub struct WebSocketServerConfig {
    /// Listen port; `0` binds an ephemeral port (read back via [`WebSocketServer::port`]).
    pub port: u16,
    /// Bind address; `None` binds all interfaces (`0.0.0.0`).
    pub bind_address: Option<String>,
    /// Serve `wss://` (TLS). Requires `certificate_pem` + `key_pem`.
    pub enable_tls: bool,
    /// PEM-encoded server certificate (required iff `enable_tls`).
    pub certificate_pem: Option<String>,
    /// PEM-encoded server private key (required iff `enable_tls`).
    pub key_pem: Option<String>,
    /// Max inbound/outbound message size for accepted connections.
    pub max_message_size: Option<usize>,
}

impl Default for WebSocketServerConfig {
    fn default() -> Self {
        WebSocketServerConfig {
            port: 8080,
            bind_address: None,
            enable_tls: false,
            certificate_pem: None,
            key_pem: None,
            max_message_size: None,
        }
    }
}

/// Callback invoked with each accepted (already-open) client connection.
pub(crate) type OnClient = Arc<dyn Fn(WebSocket) + Send + Sync>;

/// State shared between the [`WebSocketServer`] handle and its accept thread.
struct WsServerShared {
    stopped: AtomicBool,
    on_client: Mutex<Option<OnClient>>,
    tls: Option<Arc<SslAcceptor>>,
    config: WebSocketServerConfig,
}

/// Accept-loop poll cadence (so `stop()` can interrupt a non-blocking listener).
const ACCEPT_POLL: Duration = Duration::from_millis(20);

/// Build a server `SslAcceptor` from PEM cert + key (mirrors the OpenSSL server
/// context wiring in `dtls_transport.rs`). WS clients never present a cert, so
/// no peer-verification is configured.
fn build_tls_acceptor(cert_pem: &str, key_pem: &str) -> WsResult<SslAcceptor> {
    let cert = X509::from_pem(cert_pem.as_bytes())
        .map_err(|e| WebSocketError::Transport(format!("certificate parse: {e}")))?;
    let key = PKey::private_key_from_pem(key_pem.as_bytes())
        .map_err(|e| WebSocketError::Transport(format!("private key parse: {e}")))?;
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
        .map_err(|e| WebSocketError::Transport(format!("TLS acceptor init: {e}")))?;
    builder
        .set_private_key(&key)
        .map_err(|e| WebSocketError::Transport(format!("set private key: {e}")))?;
    builder
        .set_certificate(&cert)
        .map_err(|e| WebSocketError::Transport(format!("set certificate: {e}")))?;
    builder
        .check_private_key()
        .map_err(|e| WebSocketError::Transport(format!("key/cert mismatch: {e}")))?;
    Ok(builder.build())
}

/// Server side of the HTTP Upgrade: read the client's `GET` request, validate
/// it, reply `101`, and return the live stream plus any frame bytes that
/// trailed the request in the same segment. The inverse of
/// [`connect_and_handshake`]; the socket is already accepted (no TCP connect).
fn server_handshake(mut stream: WsStream) -> WsResult<(WsStream, Vec<u8>, WsHandshake)> {
    // Bound a silent client so a half-open connection can't wedge the thread.
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| WebSocketError::Transport(format!("set_read_timeout: {e}")))?;
    let mut hs = WsHandshake::new_server();
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(consumed) = hs.parse_http_request(&buf)? {
            let response = hs.generate_http_response();
            stream
                .write_all(response.as_bytes())
                .and_then(|()| stream.flush())
                .map_err(|e| WebSocketError::Transport(format!("write 101: {e}")))?;
            let leftover = buf[consumed..].to_vec();
            return Ok((stream, leftover, hs));
        }
        let n = stream
            .read(&mut tmp)
            .map_err(|e| WebSocketError::Transport(format!("read request: {e}")))?;
        if n == 0 {
            return Err(WebSocketError::Transport(
                "connection closed during handshake".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Per-connection handler (one detached thread per accepted socket, so a slow
/// client never blocks the accept loop). Wraps TLS if configured, drives the
/// server handshake, and delivers the resulting open [`WebSocket`] via the
/// `on_client` callback (if set) or the accept channel.
fn handle_accepted(tcp: TcpStream, shared: Arc<WsServerShared>, accept_tx: Sender<WebSocket>) {
    tcp.set_nodelay(true).ok();
    // Capture the peer address before any TLS wrap moves the TcpStream.
    let remote_address = tcp.peer_addr().ok().map(|a| a.to_string());
    // The listener is non-blocking; make accepted sockets blocking (with the
    // read timeouts the handshake/read loop set explicitly).
    if tcp.set_nonblocking(false).is_err() {
        return;
    }
    let stream = match &shared.tls {
        Some(acceptor) => match acceptor.accept(tcp) {
            Ok(s) => WsStream::Tls(Box::new(s)),
            Err(_) => return, // bad TLS handshake — drop the connection
        },
        None => WsStream::Plain(tcp),
    };
    let (stream, leftover, hs) = match server_handshake(stream) {
        Ok(v) => v,
        Err(_) => return, // malformed request — drop
    };
    let config = WebSocketConfig {
        max_message_size: shared.config.max_message_size,
        ..WebSocketConfig::default()
    };
    let ws = WebSocket::from_accepted(stream, leftover, hs, config, remote_address);

    let cb = shared.on_client.lock().clone();
    if let Some(cb) = cb {
        cb(ws);
    } else {
        let _ = accept_tx.send(ws);
    }
}

/// The accept loop: non-blocking `accept` + poll so [`WebSocketServer::stop`]
/// can interrupt it via the `stopped` flag (std has no `PollInterrupter`).
fn run_accept_loop(
    listener: TcpListener,
    shared: Arc<WsServerShared>,
    accept_tx: Sender<WebSocket>,
) {
    listener.set_nonblocking(true).ok();
    loop {
        if shared.stopped.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((tcp, _addr)) => {
                let shared2 = shared.clone();
                let tx2 = accept_tx.clone();
                let _ = thread::Builder::new()
                    .name("ws-accept-conn".into())
                    .spawn(move || handle_accepted(tcp, shared2, tx2));
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(_) => break,
        }
    }
}

/// A WebSocket server — a native Rust port of `rtc::WebSocketServer`. Binds a
/// TCP listener, accepts connections on a background thread, completes the
/// server-side HTTP Upgrade per connection, and surfaces each accepted client
/// as an open [`WebSocket`] — via [`accept`](Self::accept) (idiomatic) or the
/// [`set_on_client`](Self::set_on_client) callback (upstream-faithful).
pub struct WebSocketServer {
    port: u16,
    shared: Arc<WsServerShared>,
    accept_rx: Receiver<WebSocket>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for WebSocketServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketServer")
            .field("port", &self.port)
            .field("stopped", &self.shared.stopped.load(Ordering::SeqCst))
            .finish()
    }
}

impl WebSocketServer {
    /// Bind the listener and start accepting. With `config.port == 0` an
    /// ephemeral port is chosen; read it back with [`Self::port`].
    pub fn new(config: WebSocketServerConfig) -> WsResult<Self> {
        let tls = if config.enable_tls {
            let cert = config
                .certificate_pem
                .as_deref()
                .ok_or(WebSocketError::Transport(
                    "enable_tls set but certificate_pem missing".into(),
                ))?;
            let key = config.key_pem.as_deref().ok_or(WebSocketError::Transport(
                "enable_tls set but key_pem missing".into(),
            ))?;
            Some(Arc::new(build_tls_acceptor(cert, key)?))
        } else {
            None
        };

        let bind_host = config
            .bind_address
            .clone()
            .unwrap_or_else(|| "0.0.0.0".to_string());
        let listener = TcpListener::bind((bind_host.as_str(), config.port)).map_err(|e| {
            WebSocketError::Transport(format!("bind {bind_host}:{}: {e}", config.port))
        })?;
        let port = listener
            .local_addr()
            .map_err(|e| WebSocketError::Transport(format!("local_addr: {e}")))?
            .port();

        let shared = Arc::new(WsServerShared {
            stopped: AtomicBool::new(false),
            on_client: Mutex::new(None),
            tls,
            config,
        });
        let (accept_tx, accept_rx) = unbounded::<WebSocket>();
        let shared_t = shared.clone();
        let thread = thread::Builder::new()
            .name("ws-server-accept".into())
            .spawn(move || run_accept_loop(listener, shared_t, accept_tx))
            .map_err(|e| WebSocketError::Transport(format!("spawn accept thread: {e}")))?;

        Ok(WebSocketServer {
            port,
            shared,
            accept_rx,
            thread: Some(thread),
        })
    }

    /// The resolved listen port (useful when `config.port` was `0`).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Register a callback invoked with each accepted client (upstream
    /// `onClient`). When set, accepted connections go to the callback instead of
    /// the [`accept`](Self::accept) channel. Set before connections arrive.
    pub fn set_on_client(&self, f: impl Fn(WebSocket) + Send + Sync + 'static) {
        *self.shared.on_client.lock() = Some(Arc::new(f));
    }

    /// Block until the next client connects (or the server stops), returning the
    /// accepted, already-open [`WebSocket`]. Returns `None` once the server is
    /// stopped and no more connections are queued.
    pub fn accept(&self) -> Option<WebSocket> {
        self.accept_rx.recv().ok()
    }

    /// Non-blocking variant of [`accept`](Self::accept).
    pub fn try_accept(&self) -> Option<WebSocket> {
        self.accept_rx.try_recv().ok()
    }

    /// Stop accepting and tear down the accept thread. Idempotent. In-flight
    /// connections already handed to the user are left running (matches C++).
    pub fn stop(&self) {
        self.shared.stopped.store(true, Ordering::SeqCst);
    }
}

impl Drop for WebSocketServer {
    fn drop(&mut self) {
        self.stop();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Frame codec -----------------------------------------------------

    fn roundtrip(opcode: Opcode, payload: Vec<u8>, mask: bool, key: Option<[u8; 4]>) {
        let frame = Frame {
            opcode,
            fin: true,
            mask,
            payload: payload.clone(),
        };
        let bytes = frame.encode_with_key(key);
        match Frame::decode(&bytes).unwrap() {
            DecodeOutcome::Frame {
                frame: decoded,
                consumed,
            } => {
                assert_eq!(consumed, bytes.len());
                assert_eq!(decoded.opcode, opcode);
                assert!(decoded.fin);
                assert_eq!(decoded.mask, mask);
                assert_eq!(decoded.payload, payload);
            }
            DecodeOutcome::NeedMore => panic!("expected full frame"),
        }
    }

    #[test]
    fn roundtrip_each_opcode_unmasked() {
        for op in [
            Opcode::Continuation,
            Opcode::Text,
            Opcode::Binary,
            Opcode::Close,
            Opcode::Ping,
            Opcode::Pong,
        ] {
            roundtrip(op, b"hello".to_vec(), false, None);
        }
    }

    #[test]
    fn roundtrip_each_opcode_masked() {
        let key = [0x12, 0x34, 0x56, 0x78];
        for op in [
            Opcode::Continuation,
            Opcode::Text,
            Opcode::Binary,
            Opcode::Close,
            Opcode::Ping,
            Opcode::Pong,
        ] {
            roundtrip(op, b"hello world".to_vec(), true, Some(key));
        }
    }

    #[test]
    fn roundtrip_empty_payload() {
        roundtrip(Opcode::Text, Vec::new(), false, None);
        roundtrip(Opcode::Binary, Vec::new(), true, Some([1, 2, 3, 4]));
    }

    #[test]
    fn length_form_7bit() {
        // len < 126 uses a 2-byte header (unmasked).
        let frame = Frame {
            opcode: Opcode::Binary,
            fin: true,
            mask: false,
            payload: vec![0xAB; 100],
        };
        let bytes = frame.encode_with_key(None);
        assert_eq!(bytes.len(), 2 + 100);
        assert_eq!(bytes[1] & 0x7F, 100);
        roundtrip(Opcode::Binary, vec![0xAB; 100], false, None);
    }

    #[test]
    fn length_form_16bit() {
        // 126..=65535 uses the 0x7E + u16 form.
        let payload = vec![0xCD; 200];
        let frame = Frame {
            opcode: Opcode::Binary,
            fin: true,
            mask: false,
            payload: payload.clone(),
        };
        let bytes = frame.encode_with_key(None);
        assert_eq!(bytes[1] & 0x7F, 0x7E);
        assert_eq!(bytes.len(), 2 + 2 + 200);
        roundtrip(Opcode::Binary, payload, false, None);
    }

    #[test]
    fn length_form_64bit() {
        // > 65535 uses the 0x7F + u64 form.
        let payload = vec![0xEF; 70_000];
        let frame = Frame {
            opcode: Opcode::Binary,
            fin: true,
            mask: false,
            payload: payload.clone(),
        };
        let bytes = frame.encode_with_key(None);
        assert_eq!(bytes[1] & 0x7F, 0x7F);
        assert_eq!(bytes.len(), 2 + 8 + 70_000);
        roundtrip(Opcode::Binary, payload, false, None);
    }

    #[test]
    fn masking_actually_obscures_payload() {
        let key = [0xAA, 0xBB, 0xCC, 0xDD];
        let payload = b"secret".to_vec();
        let frame = Frame {
            opcode: Opcode::Binary,
            fin: true,
            mask: true,
            payload: payload.clone(),
        };
        let bytes = frame.encode_with_key(Some(key));
        // Header(2) + key(4) + payload(6).
        let on_wire = &bytes[6..];
        assert_ne!(
            on_wire,
            &payload[..],
            "masked payload must differ from plaintext"
        );
        // XOR back to verify masking math.
        let unmasked: Vec<u8> = on_wire
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 4])
            .collect();
        assert_eq!(unmasked, payload);
    }

    #[test]
    fn fragmented_continuation_reassembles() {
        let mut ws = WebSocket::new(WebSocketConfig::default());
        ws.force_open_for_test();
        // First fragment: text, not final.
        ws.ingest_frame(&Frame {
            opcode: Opcode::Text,
            fin: false,
            mask: false,
            payload: b"Hel".to_vec(),
        });
        assert!(ws.receive().is_none());
        // Continuation, not final.
        ws.ingest_frame(&Frame {
            opcode: Opcode::Continuation,
            fin: false,
            mask: false,
            payload: b"lo ".to_vec(),
        });
        assert!(ws.receive().is_none());
        // Final continuation.
        ws.ingest_frame(&Frame {
            opcode: Opcode::Continuation,
            fin: true,
            mask: false,
            payload: b"world".to_vec(),
        });
        assert_eq!(ws.receive(), Some(WsMessage::Text(b"Hello world".to_vec())));
        assert!(ws.receive().is_none());
    }

    #[test]
    fn decode_too_short_buffers() {
        // Empty / one byte → NeedMore.
        assert_eq!(Frame::decode(&[]).unwrap(), DecodeOutcome::NeedMore);
        assert_eq!(Frame::decode(&[0x82]).unwrap(), DecodeOutcome::NeedMore);
        // Header announces 5 bytes (0x05) but only 3 present.
        assert_eq!(
            Frame::decode(&[0x82, 0x05, 1, 2, 3]).unwrap(),
            DecodeOutcome::NeedMore
        );
        // 16-bit length form announced but extended length truncated.
        assert_eq!(
            Frame::decode(&[0x82, 0x7E, 0x00]).unwrap(),
            DecodeOutcome::NeedMore
        );
        // 64-bit length form truncated.
        assert_eq!(
            Frame::decode(&[0x82, 0x7F, 0, 0, 0, 0]).unwrap(),
            DecodeOutcome::NeedMore
        );
        // Masked frame missing its 4-byte key.
        assert_eq!(
            Frame::decode(&[0x82, 0x83, 0x00]).unwrap(),
            DecodeOutcome::NeedMore
        );
    }

    #[test]
    fn decode_consumes_only_one_frame() {
        let f1 = Frame {
            opcode: Opcode::Text,
            fin: true,
            mask: false,
            payload: b"ab".to_vec(),
        }
        .encode_with_key(None);
        let f2 = Frame {
            opcode: Opcode::Binary,
            fin: true,
            mask: false,
            payload: b"cd".to_vec(),
        }
        .encode_with_key(None);
        let mut buf = f1.clone();
        buf.extend_from_slice(&f2);
        match Frame::decode(&buf).unwrap() {
            DecodeOutcome::Frame { frame, consumed } => {
                assert_eq!(frame.payload, b"ab");
                assert_eq!(consumed, f1.len());
            }
            DecodeOutcome::NeedMore => panic!(),
        }
    }

    #[test]
    fn decode_rejects_reserved_opcode() {
        // Opcode 3 is reserved for non-control data frames.
        let err = Frame::decode(&[0x83, 0x00]).unwrap_err();
        assert_eq!(err, WebSocketError::InvalidOpcode(3));
    }

    // ---- Handshake key / accept ------------------------------------------

    #[test]
    fn accept_key_matches_rfc6455_vector() {
        // RFC6455 §1.3 worked example.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        assert_eq!(compute_accept_key(key), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn generated_key_is_16_bytes_base64() {
        let k = generate_key();
        let decoded = BASE64.decode(&k).unwrap();
        assert_eq!(decoded.len(), 16);
    }

    #[test]
    fn request_generation_contains_required_headers() {
        let mut hs = WsHandshake::new(
            "example.com:8080",
            "/chat",
            vec!["proto1".into(), "proto2".into()],
        )
        .unwrap();
        let req = hs.generate_http_request_with_key("dGhlIHNhbXBsZSBub25jZQ==".into());
        assert!(req.starts_with("GET /chat HTTP/1.1\r\n"));
        assert!(req.contains("Host: example.com:8080\r\n"));
        assert!(req.contains("Connection: Upgrade\r\n"));
        assert!(req.contains("Upgrade: websocket\r\n"));
        assert!(req.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(req.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        assert!(req.contains("Sec-WebSocket-Protocol: proto1,proto2\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn request_without_protocols_omits_protocol_header() {
        let mut hs = WsHandshake::new("h", "/", vec![]).unwrap();
        let req = hs.generate_http_request_with_key("k".into());
        assert!(!req.contains("Sec-WebSocket-Protocol"));
    }

    #[test]
    fn handshake_rejects_empty_host_or_path() {
        assert!(WsHandshake::new("", "/", vec![]).is_err());
        assert!(WsHandshake::new("h", "", vec![]).is_err());
    }

    #[test]
    fn parse_response_accepts_valid_101() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = compute_accept_key(key);
        let mut hs = WsHandshake::new("h", "/", vec![]).unwrap();
        hs.key = key.to_string();
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Server: test\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        let consumed = hs.parse_http_response(resp.as_bytes()).unwrap();
        assert_eq!(consumed, Some(resp.len()));
    }

    #[test]
    fn parse_response_rejects_bad_accept() {
        let mut hs = WsHandshake::new("h", "/", vec![]).unwrap();
        hs.key = "dGhlIHNhbXBsZSBub25jZQ==".to_string();
        let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                    Upgrade: websocket\r\n\
                    Sec-WebSocket-Accept: WRONGWRONGWRONG=\r\n\r\n";
        assert_eq!(
            hs.parse_http_response(resp.as_bytes()).unwrap_err(),
            WebSocketError::Handshake("accept header is invalid")
        );
    }

    #[test]
    fn parse_response_rejects_non_101_status() {
        let hs = WsHandshake::new("h", "/", vec![]).unwrap();
        let resp = "HTTP/1.1 404 Not Found\r\n\r\n";
        assert_eq!(
            hs.parse_http_response(resp.as_bytes()).unwrap_err(),
            WebSocketError::Handshake("unexpected response code")
        );
    }

    #[test]
    fn parse_response_rejects_missing_upgrade() {
        let mut hs = WsHandshake::new("h", "/", vec![]).unwrap();
        hs.key = "k".to_string();
        let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                    Sec-WebSocket-Accept: x\r\n\r\n";
        assert_eq!(
            hs.parse_http_response(resp.as_bytes()).unwrap_err(),
            WebSocketError::Handshake("upgrade header missing")
        );
    }

    #[test]
    fn parse_response_needs_more_without_terminator() {
        let hs = WsHandshake::new("h", "/", vec![]).unwrap();
        let partial = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n";
        assert_eq!(hs.parse_http_response(partial.as_bytes()).unwrap(), None);
    }

    // ---- URL parsing -----------------------------------------------------

    #[test]
    fn parse_ws_url_defaults() {
        let u = WsUrl::parse("ws://example.com/chat").unwrap();
        assert!(!u.secure);
        assert_eq!(u.hostname, "example.com");
        assert_eq!(u.port, 80);
        assert_eq!(u.host_header, "example.com");
        assert_eq!(u.path, "/chat");
    }

    #[test]
    fn parse_wss_url_defaults() {
        let u = WsUrl::parse("wss://example.com").unwrap();
        assert!(u.secure);
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/");
        assert_eq!(u.host_header, "example.com");
    }

    #[test]
    fn parse_url_with_explicit_port_and_query() {
        let u = WsUrl::parse("ws://h.test:9001/path?token=abc").unwrap();
        assert_eq!(u.port, 9001);
        assert_eq!(u.host_header, "h.test:9001");
        assert_eq!(u.path, "/path?token=abc");
    }

    #[test]
    fn parse_url_default_scheme_is_ws() {
        let u = WsUrl::parse("host:1234/x").unwrap();
        assert!(!u.secure);
        assert_eq!(u.port, 1234);
        assert_eq!(u.path, "/x");
    }

    #[test]
    fn parse_url_ipv6_literal() {
        let u = WsUrl::parse("wss://[2001:db8::1]:8443/p").unwrap();
        assert_eq!(u.hostname, "2001:db8::1");
        assert_eq!(u.port, 8443);
        assert_eq!(u.host_header, "[2001:db8::1]:8443");
    }

    #[test]
    fn parse_url_strips_userinfo_and_fragment() {
        let u = WsUrl::parse("ws://user:pass@h.test/p#frag").unwrap();
        assert_eq!(u.hostname, "h.test");
        assert_eq!(u.path, "/p");
    }

    #[test]
    fn parse_url_rejects_bad_scheme() {
        assert!(WsUrl::parse("http://h/").is_err());
    }

    #[test]
    fn parse_url_rejects_missing_host() {
        assert!(WsUrl::parse("ws:///path").is_err());
    }

    // ---- State machine skeleton ------------------------------------------

    #[test]
    fn new_socket_is_closed() {
        let ws = WebSocket::new(WebSocketConfig::default());
        assert_eq!(ws.ready_state(), State::Closed);
        assert!(ws.is_closed());
        assert!(!ws.is_open());
        assert_eq!(ws.max_message_size(), DEFAULT_WS_MAX_MESSAGE_SIZE);
    }

    // A loopback TCP listener that accepts the connection but never replies,
    // so the client wedges in the blocking handshake → state stays Connecting
    // for the life of the test (deterministic, no connect-refused race).
    fn dangling_listener() -> (std::net::TcpListener, u16) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        (l, port)
    }

    #[test]
    fn open_transitions_to_connecting() {
        let (_listener, port) = dangling_listener();
        let mut ws = WebSocket::new(WebSocketConfig::default());
        // open() is non-blocking and returns Ok once the thread is spawned.
        ws.open(&format!("ws://127.0.0.1:{port}/chat")).unwrap();
        // Connecting is set synchronously before the thread runs.
        assert_eq!(ws.ready_state(), State::Connecting);
        // While Connecting, path() is hidden (matches upstream).
        assert_eq!(ws.path(), None);
    }

    #[test]
    fn open_rejects_when_not_closed() {
        let (_listener, port) = dangling_listener();
        let mut ws = WebSocket::new(WebSocketConfig::default());
        ws.open(&format!("ws://127.0.0.1:{port}/")).unwrap(); // -> Connecting
        assert_eq!(
            ws.open(&format!("ws://127.0.0.1:{port}/")).unwrap_err(),
            WebSocketError::NotOpen
        );
    }

    #[test]
    fn open_rejects_bad_url() {
        let mut ws = WebSocket::new(WebSocketConfig::default());
        assert!(matches!(
            ws.open("http://h/"),
            Err(WebSocketError::InvalidUrl(_))
        ));
        // Failed URL parse leaves it Closed.
        assert_eq!(ws.ready_state(), State::Closed);
    }

    #[test]
    fn encode_send_requires_open() {
        let ws = WebSocket::new(WebSocketConfig::default());
        assert_eq!(
            ws.encode_send_text(b"hi").unwrap_err(),
            WebSocketError::NotOpen
        );
    }

    #[test]
    fn encode_send_masks_client_frame() {
        let mut ws = WebSocket::new(WebSocketConfig::default());
        ws.force_open_for_test();
        let bytes = ws.encode_send_text(b"hi").unwrap();
        // MASK bit set in byte 2.
        assert_ne!(bytes[1] & 0x80, 0, "client frames must be masked");
        // Round-trips through the decoder.
        match Frame::decode(&bytes).unwrap() {
            DecodeOutcome::Frame { frame, .. } => {
                assert_eq!(frame.opcode, Opcode::Text);
                assert!(frame.mask);
                assert_eq!(frame.payload, b"hi");
            }
            DecodeOutcome::NeedMore => panic!(),
        }
    }

    #[test]
    fn single_final_frame_yields_message() {
        let mut ws = WebSocket::new(WebSocketConfig::default());
        ws.force_open_for_test();
        ws.ingest_frame(&Frame {
            opcode: Opcode::Binary,
            fin: true,
            mask: false,
            payload: vec![1, 2, 3],
        });
        assert_eq!(ws.receive(), Some(WsMessage::Binary(vec![1, 2, 3])));
    }

    // ---- Live transport (pass 2) -----------------------------------------

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    /// Minimal RFC6455 echo server on 127.0.0.1, built from this module's own
    /// [`Frame`] codec + [`compute_accept_key`]. Accepts one connection,
    /// completes the Upgrade handshake, then echoes each data frame back
    /// (server→client frames are unmasked, per RFC6455 §5.1), and replies to a
    /// Close with a Close. Returns the bound port.
    fn spawn_echo_server() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            // 1. Read request headers, extract Sec-WebSocket-Key.
            let header_end = loop {
                if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
                    break pos + 4;
                }
                let n = sock.read(&mut tmp).unwrap();
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&tmp[..n]);
            };
            let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
            let key = head
                .lines()
                .find_map(|l| l.strip_prefix("Sec-WebSocket-Key:"))
                .map(|v| v.trim().to_string())
                .unwrap();
            // 2. Send the 101 response.
            let accept = compute_accept_key(&key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            sock.write_all(resp.as_bytes()).unwrap();
            // 3. Echo frames (any bytes past the headers begin the first frame).
            let mut inbuf: Vec<u8> = buf[header_end..].to_vec();
            loop {
                match Frame::decode(&inbuf) {
                    Ok(DecodeOutcome::Frame { frame, consumed }) => {
                        inbuf.drain(..consumed);
                        match frame.opcode {
                            Opcode::Text | Opcode::Binary => {
                                let reply =
                                    Frame::new(frame.opcode, frame.payload.clone(), false).encode();
                                if sock.write_all(&reply).is_err() {
                                    return;
                                }
                            }
                            Opcode::Close => {
                                let _ = sock.write_all(
                                    &Frame::new(Opcode::Close, Vec::new(), false).encode(),
                                );
                                return;
                            }
                            _ => {}
                        }
                    }
                    Ok(DecodeOutcome::NeedMore) => {
                        let n = sock.read(&mut tmp).unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        inbuf.extend_from_slice(&tmp[..n]);
                    }
                    Err(_) => return,
                }
            }
        });
        port
    }

    fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if cond() {
                return true;
            }
            thread::sleep(Duration::from_millis(5));
        }
        cond()
    }

    #[test]
    fn loopback_ws_text_and_binary_roundtrip() {
        let port = spawn_echo_server();

        let received: Arc<Mutex<Vec<WsMessage>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();

        let mut ws = WebSocket::new(WebSocketConfig::default());
        ws.set_on_message(move |msg| sink.lock().push(msg));
        ws.open(&format!("ws://127.0.0.1:{port}/chat")).unwrap();

        assert!(
            wait_until(|| ws.ready_state() == State::Open),
            "never reached Open"
        );

        ws.send_text(b"hello").unwrap();
        ws.send_binary(&[1, 2, 3, 4]).unwrap();

        assert!(
            wait_until(|| received.lock().len() >= 2),
            "did not receive both echoes"
        );

        let got = received.lock().clone();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], WsMessage::Text(b"hello".to_vec()));
        assert_eq!(got[1], WsMessage::Binary(vec![1, 2, 3, 4]));

        ws.close();
        assert!(
            wait_until(|| ws.ready_state() == State::Closed),
            "never reached Closed"
        );
    }

    #[test]
    fn send_before_open_is_rejected() {
        let ws = WebSocket::new(WebSocketConfig::default());
        assert_eq!(ws.send_text(b"x").unwrap_err(), WebSocketError::NotOpen);
        assert_eq!(ws.send_binary(b"x").unwrap_err(), WebSocketError::NotOpen);
        // close() on a never-opened socket is a no-op (no panic).
        ws.close();
    }

    // ---- Server-side handshake (pass 2) ----------------------------------

    #[test]
    fn server_handshake_parses_request_and_builds_101() {
        let mut hs = WsHandshake::new_server();
        let req = "GET /chat HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Upgrade: websocket\r\n\
                   Connection: Upgrade\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                   Sec-WebSocket-Version: 13\r\n\r\n";
        let consumed = hs.parse_http_request(req.as_bytes()).unwrap().unwrap();
        assert_eq!(consumed, req.len());
        assert_eq!(hs.path(), "/chat");
        assert_eq!(hs.host(), "example.com");
        // RFC6455 §1.3 worked example: this key → this accept value.
        let resp = hs.generate_http_response();
        assert!(resp.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(resp.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        assert!(resp.ends_with("\r\n\r\n"));
    }

    #[test]
    fn server_handshake_rejects_non_get() {
        let mut hs = WsHandshake::new_server();
        let req =
            "POST / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\n\r\n";
        assert_eq!(
            hs.parse_http_request(req.as_bytes()).unwrap_err(),
            WebSocketError::Handshake("invalid request method")
        );
    }

    #[test]
    fn server_handshake_needs_more_without_terminator() {
        let mut hs = WsHandshake::new_server();
        let partial = "GET / HTTP/1.1\r\nHost: h\r\n";
        assert_eq!(hs.parse_http_request(partial.as_bytes()).unwrap(), None);
    }

    // ---- Live server <-> client loopback ---------------------------------

    #[test]
    fn loopback_server_accepts_client_and_text_roundtrips() {
        let server = WebSocketServer::new(WebSocketServerConfig {
            port: 0,
            ..WebSocketServerConfig::default()
        })
        .unwrap();
        let port = server.port();
        assert_ne!(port, 0, "ephemeral port should be resolved after bind");

        // Accept thread: echo every text message back to the client.
        let server = Arc::new(server);
        let server_for_accept = server.clone();
        let accept_handle = thread::spawn(move || {
            let conn = Arc::new(
                server_for_accept
                    .accept()
                    .expect("server accepted a client"),
            );
            let echo = conn.clone();
            conn.set_on_message(move |m| {
                if let WsMessage::Text(d) = m {
                    let _ = echo.send_text(&d);
                }
            });
            // Confirm the server parsed the request path.
            assert_eq!(conn.path(), Some("/chat"));
            // Keep `conn` (and its read loop) alive until the client is done.
            thread::sleep(Duration::from_secs(2));
        });

        let got: Arc<Mutex<Vec<WsMessage>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = got.clone();
        let mut client = WebSocket::new(WebSocketConfig::default());
        client.set_on_message(move |m| sink.lock().push(m));
        client.open(&format!("ws://127.0.0.1:{port}/chat")).unwrap();

        assert!(
            wait_until(|| client.ready_state() == State::Open),
            "client never opened"
        );

        client.send_text(b"ping").unwrap();
        assert!(wait_until(|| got.lock().len() >= 1), "no echo received");

        let messages = got.lock().clone();
        assert_eq!(messages[0], WsMessage::Text(b"ping".to_vec()));

        client.close();
        accept_handle.join().unwrap();
        server.stop();
    }
}
