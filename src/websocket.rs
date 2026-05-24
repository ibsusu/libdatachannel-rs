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

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
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
    #[error("WebSocket transport not yet wired")]
    NotWired,

    /// An operation was attempted in a state that does not allow it.
    #[error("WebSocket is not open")]
    NotOpen,
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
        Frame { opcode, fin: true, mask, payload }
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
            let k = [buffer[cur], buffer[cur + 1], buffer[cur + 2], buffer[cur + 3]];
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
            frame: Frame { opcode, fin, mask, payload },
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

        Ok(WsUrl { secure, hostname, port, host_header, path })
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
    pub fn new(host: impl Into<String>, path: impl Into<String>, protocols: Vec<String>) -> WsResult<Self> {
        let host = host.into();
        let path = path.into();
        if host.is_empty() {
            return Err(WebSocketError::Handshake("host cannot be empty"));
        }
        if path.is_empty() {
            return Err(WebSocketError::Handshake("path cannot be empty"));
        }
        Ok(WsHandshake { host, path, protocols, key: String::new() })
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

/// A WebSocket client. **Skeleton only in this slice** — holds the config and
/// state, exposes the public surface, and reassembles inbound frames into
/// messages, but does not yet open a live socket (see [`WebSocket::open`]).
#[derive(Debug)]
pub struct WebSocket {
    config: WebSocketConfig,
    state: State,
    url: Option<WsUrl>,
    handshake: Option<WsHandshake>,
    /// Inbound message queue (already reassembled from frames).
    recv_queue: VecDeque<WsMessage>,
    /// Partial (fragmented) message accumulator.
    partial: Vec<u8>,
    partial_is_text: bool,
    have_partial: bool,
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
            state: State::Closed,
            url: None,
            handshake: None,
            recv_queue: VecDeque::new(),
            partial: Vec::new(),
            partial_is_text: false,
            have_partial: false,
        }
    }

    /// The current ready state.
    pub fn ready_state(&self) -> State {
        self.state
    }

    /// `true` iff [`State::Open`].
    pub fn is_open(&self) -> bool {
        self.state == State::Open
    }

    /// `true` iff [`State::Closed`].
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// The effective max message size.
    pub fn max_message_size(&self) -> usize {
        self.config.max_message_size.unwrap_or(DEFAULT_WS_MAX_MESSAGE_SIZE)
    }

    /// The negotiated request path, available once [`open`](Self::open) has
    /// parsed a URL (i.e. not while `Closed`).
    pub fn path(&self) -> Option<&str> {
        if self.state == State::Connecting {
            return None;
        }
        self.handshake.as_ref().map(|h| h.path())
    }

    /// Begin opening the WebSocket to `url`.
    ///
    /// This parses and validates the URL and prepares the handshake, then
    /// transitions to [`State::Connecting`]. **The live transport is not wired
    /// yet** (task #31 pass 2: TCP connect for `ws://`, OpenSSL TLS for
    /// `wss://`, the read loop, ping/pong), so this returns
    /// [`WebSocketError::NotWired`] after recording the parsed state. Callers
    /// can still inspect [`Self::path`] / the prepared [`WsHandshake`].
    pub fn open(&mut self, url: &str) -> WsResult<()> {
        if self.state != State::Closed {
            return Err(WebSocketError::NotOpen);
        }
        let parsed = WsUrl::parse(url)?;
        let handshake =
            WsHandshake::new(parsed.host_header.clone(), parsed.path.clone(), self.config.protocols.clone())?;
        self.url = Some(parsed);
        self.handshake = Some(handshake);
        self.state = State::Connecting;

        // TODO(task #31, pass 2): open the TCP transport (std::net) for ws://,
        // wrap it in OpenSSL TLS for wss://, drive `WsHandshake` over it, then
        // run the frame read loop feeding `ingest_frame` and answering pings.
        Err(WebSocketError::NotWired)
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
        if self.state != State::Open {
            return Err(WebSocketError::NotOpen);
        }
        // Client frames MUST be masked (RFC6455 §5.3).
        Ok(Frame::new(opcode, data.to_vec(), true).encode())
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

    /// Force the state to [`State::Open`] — test/transport hook for the
    /// not-yet-wired connect path.
    #[doc(hidden)]
    pub fn force_open_for_test(&mut self) {
        self.state = State::Open;
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
        let frame = Frame { opcode, fin: true, mask, payload: payload.clone() };
        let bytes = frame.encode_with_key(key);
        match Frame::decode(&bytes).unwrap() {
            DecodeOutcome::Frame { frame: decoded, consumed } => {
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
        for op in [Opcode::Continuation, Opcode::Text, Opcode::Binary, Opcode::Close, Opcode::Ping, Opcode::Pong] {
            roundtrip(op, b"hello".to_vec(), false, None);
        }
    }

    #[test]
    fn roundtrip_each_opcode_masked() {
        let key = [0x12, 0x34, 0x56, 0x78];
        for op in [Opcode::Continuation, Opcode::Text, Opcode::Binary, Opcode::Close, Opcode::Ping, Opcode::Pong] {
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
        let frame = Frame { opcode: Opcode::Binary, fin: true, mask: false, payload: vec![0xAB; 100] };
        let bytes = frame.encode_with_key(None);
        assert_eq!(bytes.len(), 2 + 100);
        assert_eq!(bytes[1] & 0x7F, 100);
        roundtrip(Opcode::Binary, vec![0xAB; 100], false, None);
    }

    #[test]
    fn length_form_16bit() {
        // 126..=65535 uses the 0x7E + u16 form.
        let payload = vec![0xCD; 200];
        let frame = Frame { opcode: Opcode::Binary, fin: true, mask: false, payload: payload.clone() };
        let bytes = frame.encode_with_key(None);
        assert_eq!(bytes[1] & 0x7F, 0x7E);
        assert_eq!(bytes.len(), 2 + 2 + 200);
        roundtrip(Opcode::Binary, payload, false, None);
    }

    #[test]
    fn length_form_64bit() {
        // > 65535 uses the 0x7F + u64 form.
        let payload = vec![0xEF; 70_000];
        let frame = Frame { opcode: Opcode::Binary, fin: true, mask: false, payload: payload.clone() };
        let bytes = frame.encode_with_key(None);
        assert_eq!(bytes[1] & 0x7F, 0x7F);
        assert_eq!(bytes.len(), 2 + 8 + 70_000);
        roundtrip(Opcode::Binary, payload, false, None);
    }

    #[test]
    fn masking_actually_obscures_payload() {
        let key = [0xAA, 0xBB, 0xCC, 0xDD];
        let payload = b"secret".to_vec();
        let frame = Frame { opcode: Opcode::Binary, fin: true, mask: true, payload: payload.clone() };
        let bytes = frame.encode_with_key(Some(key));
        // Header(2) + key(4) + payload(6).
        let on_wire = &bytes[6..];
        assert_ne!(on_wire, &payload[..], "masked payload must differ from plaintext");
        // XOR back to verify masking math.
        let unmasked: Vec<u8> = on_wire.iter().enumerate().map(|(i, b)| b ^ key[i % 4]).collect();
        assert_eq!(unmasked, payload);
    }

    #[test]
    fn fragmented_continuation_reassembles() {
        let mut ws = WebSocket::new(WebSocketConfig::default());
        ws.force_open_for_test();
        // First fragment: text, not final.
        ws.ingest_frame(&Frame { opcode: Opcode::Text, fin: false, mask: false, payload: b"Hel".to_vec() });
        assert!(ws.receive().is_none());
        // Continuation, not final.
        ws.ingest_frame(&Frame { opcode: Opcode::Continuation, fin: false, mask: false, payload: b"lo ".to_vec() });
        assert!(ws.receive().is_none());
        // Final continuation.
        ws.ingest_frame(&Frame { opcode: Opcode::Continuation, fin: true, mask: false, payload: b"world".to_vec() });
        assert_eq!(ws.receive(), Some(WsMessage::Text(b"Hello world".to_vec())));
        assert!(ws.receive().is_none());
    }

    #[test]
    fn decode_too_short_buffers() {
        // Empty / one byte → NeedMore.
        assert_eq!(Frame::decode(&[]).unwrap(), DecodeOutcome::NeedMore);
        assert_eq!(Frame::decode(&[0x82]).unwrap(), DecodeOutcome::NeedMore);
        // Header announces 5 bytes (0x05) but only 3 present.
        assert_eq!(Frame::decode(&[0x82, 0x05, 1, 2, 3]).unwrap(), DecodeOutcome::NeedMore);
        // 16-bit length form announced but extended length truncated.
        assert_eq!(Frame::decode(&[0x82, 0x7E, 0x00]).unwrap(), DecodeOutcome::NeedMore);
        // 64-bit length form truncated.
        assert_eq!(Frame::decode(&[0x82, 0x7F, 0, 0, 0, 0]).unwrap(), DecodeOutcome::NeedMore);
        // Masked frame missing its 4-byte key.
        assert_eq!(Frame::decode(&[0x82, 0x83, 0x00]).unwrap(), DecodeOutcome::NeedMore);
    }

    #[test]
    fn decode_consumes_only_one_frame() {
        let f1 = Frame { opcode: Opcode::Text, fin: true, mask: false, payload: b"ab".to_vec() }.encode_with_key(None);
        let f2 = Frame { opcode: Opcode::Binary, fin: true, mask: false, payload: b"cd".to_vec() }.encode_with_key(None);
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
        let mut hs = WsHandshake::new("example.com:8080", "/chat", vec!["proto1".into(), "proto2".into()]).unwrap();
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

    #[test]
    fn open_parses_url_then_reports_not_wired() {
        let mut ws = WebSocket::new(WebSocketConfig::default());
        let err = ws.open("ws://example.com/chat").unwrap_err();
        assert_eq!(err, WebSocketError::NotWired);
        // State advanced to Connecting and handshake/path are prepared.
        assert_eq!(ws.ready_state(), State::Connecting);
        // While Connecting, path() is hidden (matches upstream).
        assert_eq!(ws.path(), None);
    }

    #[test]
    fn open_rejects_when_not_closed() {
        let mut ws = WebSocket::new(WebSocketConfig::default());
        let _ = ws.open("ws://h/"); // -> Connecting
        assert_eq!(ws.open("ws://h/").unwrap_err(), WebSocketError::NotOpen);
    }

    #[test]
    fn open_rejects_bad_url() {
        let mut ws = WebSocket::new(WebSocketConfig::default());
        assert!(matches!(ws.open("http://h/"), Err(WebSocketError::InvalidUrl(_))));
        // Failed URL parse leaves it Closed.
        assert_eq!(ws.ready_state(), State::Closed);
    }

    #[test]
    fn encode_send_requires_open() {
        let ws = WebSocket::new(WebSocketConfig::default());
        assert_eq!(ws.encode_send_text(b"hi").unwrap_err(), WebSocketError::NotOpen);
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
        ws.ingest_frame(&Frame { opcode: Opcode::Binary, fin: true, mask: false, payload: vec![1, 2, 3] });
        assert_eq!(ws.receive(), Some(WsMessage::Binary(vec![1, 2, 3])));
    }
}
