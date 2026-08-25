//! Peer-connection configuration types, mirroring `rtc::Configuration`,
//! `rtc::IceServer`, and `rtc::ProxyServer` from libdatachannel C++.
//!
//! These are passive parameter bags consumed by the ICE/transport layer
//! (Task #13). The interesting bit here is the [`IceServer::parse`] URL
//! parser — it accepts the same shapes as the C++ `parse_url` regex but
//! is hand-rolled with stdlib (no `regex`, no `url` crate) and is stricter
//! about IPv6 literals than the C++ original.
//!
//! Hostnames and IP literals are **not** validated at parse time; the
//! caller resolves them at connect time. This matches the C++ behaviour.

use std::str::FromStr;

use thiserror::Error;

// ---------------------------------------------------------------------------
// Enums (match the C++ rtc::CertificateType / rtc::TransportPolicy etc.)
// ---------------------------------------------------------------------------

/// DTLS certificate type. Mirrors `rtc::CertificateType`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CertificateType {
    /// Library default (currently ECDSA upstream).
    Default,
    /// ECDSA (`RTC_CERTIFICATE_ECDSA`).
    EcDsa,
    /// RSA (`RTC_CERTIFICATE_RSA`).
    Rsa,
}

/// ICE transport policy. Mirrors `rtc::TransportPolicy` and the upstream
/// W3C `RTCIceTransportPolicy`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum IceTransportPolicy {
    /// Gather all candidate types.
    All,
    /// Only gather relay candidates (TURN). All host/srflx candidates are
    /// filtered out.
    Relay,
}

/// Alias for [`IceTransportPolicy`] — kept to match the C++ field name
/// (`Configuration::iceTransportPolicy` is typed `TransportPolicy`).
pub type TransportPolicy = IceTransportPolicy;

/// Explicit RFC 6544 role. `None` in [`Configuration`] preserves the legacy
/// `enable_ice_tcp` boolean (`true` means active/client mode).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum IceTcpMode {
    /// Initiate a framed TCP connection to a remote passive candidate.
    Active,
    /// Listen for a framed TCP connection from a remote active candidate.
    Passive,
}

/// Relay flavour for a TURN server. Mirrors `rtc::IceServer::RelayType`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum RelayType {
    /// TURN over UDP (`turn:`, default).
    TurnUdp,
    /// TURN over TCP (`turn:?transport=tcp`).
    TurnTcp,
    /// TURN over TLS (`turns:`).
    TurnTls,
}

/// Outgoing proxy protocol. Mirrors `rtc::ProxyServer::Type`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ProxyType {
    /// HTTP `CONNECT` tunnel.
    Http,
    /// SOCKS5 (RFC 1928).
    Socks5,
}

/// ICE server flavour. Mirrors `rtc::IceServer::Type`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum IceServerType {
    /// STUN server (`stun:` URI).
    Stun,
    /// TURN server (`turn:` or `turns:` URI).
    Turn,
}

/// Congestion-control algorithm hint. The C++ `Configuration` does not yet
/// expose this knob, but the SCTP transport accepts it and the upstream
/// `libdatachannel` runtime forwards it; we model it here so the Task #20
/// SCTP wiring has a place to read it from.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CongestionControl {
    /// Library default (currently NewReno upstream).
    Default,
    /// Google Congestion Control (BBR-style).
    GoogCc,
    /// Classic TCP New Reno.
    NewReno,
    /// CUBIC (Linux default).
    Cubic,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned when parsing an ICE or proxy server URL.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IceServerParseError {
    /// The URL was empty.
    #[error("empty URL")]
    Empty,
    /// The URL scheme was not one of the expected values for this URL kind.
    #[error("unknown scheme: {0}")]
    UnknownScheme(String),
    /// The URL did not contain a host portion.
    #[error("missing host")]
    MissingHost,
    /// The port could not be parsed as a `u16`.
    #[error("invalid port: {0}")]
    InvalidPort(String),
    /// An IPv6 literal was opened with `[` but never closed with `]`.
    #[error("unterminated IPv6 literal")]
    UnterminatedIpv6,
    /// A TURN URL was supplied without `user:password@` credentials.
    #[error("TURN URL requires credentials")]
    TurnMissingCredentials,
    /// A STUN URL was supplied with `user:password@` credentials (RFC 7064
    /// disallows userinfo on `stun:`).
    #[error("STUN URL must not carry credentials")]
    StunWithCredentials,
    /// A percent-encoded escape was malformed.
    #[error("invalid percent-encoding")]
    BadPercentEncoding,
}

// ---------------------------------------------------------------------------
// IceServer
// ---------------------------------------------------------------------------

/// An ICE server (STUN or TURN) used during candidate gathering.
///
/// Construct via the typed constructors ([`IceServer::stun`], [`IceServer::turn`]),
/// or parse a URL with [`IceServer::parse`] / `FromStr`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IceServer {
    /// Bare hostname or IP literal (no scheme, no brackets for IPv6).
    pub hostname: String,
    /// Server port.
    pub port: u16,
    /// STUN or TURN.
    pub typ: IceServerType,
    /// TURN username; empty when [`IceServer::typ`] is [`IceServerType::Stun`].
    pub username: String,
    /// TURN password; empty when [`IceServer::typ`] is [`IceServerType::Stun`].
    pub password: String,
    /// Relay transport for TURN; defaults to [`RelayType::TurnUdp`] for
    /// `stun:` (where it's meaningless).
    pub relay_type: RelayType,
}

impl IceServer {
    /// Construct a STUN server. Equivalent to [`IceServer::stun`].
    pub fn new(hostname: impl Into<String>, port: u16) -> Self {
        Self::stun(hostname, port)
    }

    /// Construct a STUN server.
    pub fn stun(hostname: impl Into<String>, port: u16) -> Self {
        IceServer {
            hostname: hostname.into(),
            port,
            typ: IceServerType::Stun,
            username: String::new(),
            password: String::new(),
            relay_type: RelayType::TurnUdp,
        }
    }

    /// Construct a TURN server.
    pub fn turn(
        hostname: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
        relay_type: RelayType,
    ) -> Self {
        IceServer {
            hostname: hostname.into(),
            port,
            typ: IceServerType::Turn,
            username: username.into(),
            password: password.into(),
            relay_type,
        }
    }

    /// Parse a `stun:`, `stuns:`, `turn:`, or `turns:` URL.
    ///
    /// Grammar (all parts optional except `<host>`):
    ///
    /// ```text
    /// <scheme>:[//]?[<user>[:<password>]@]<host>[:<port>][?transport=udp|tcp|tls]
    /// ```
    ///
    /// Default ports: `3478` for STUN and TURN/UDP/TCP, `5349` for TURN/TLS
    /// (`turns:`). The `transport` query parameter is honored for `turn:`
    /// only; `turns:` is always TLS. STUN URLs must not carry userinfo;
    /// TURN URLs must carry it.
    pub fn parse(url: &str) -> Result<Self, IceServerParseError> {
        let parsed = ParsedUrl::parse(url)?;
        let scheme = parsed.scheme.to_ascii_lowercase();

        let (typ, mut relay_type, default_port) = match scheme.as_str() {
            "stun" => (IceServerType::Stun, RelayType::TurnUdp, 3478),
            "turn" => (IceServerType::Turn, RelayType::TurnUdp, 3478),
            "turns" => (IceServerType::Turn, RelayType::TurnTls, 5349),
            // `stuns:` is intentionally rejected — matches C++ behaviour
            // (the C++ regex matches it but the scheme switch throws).
            other => return Err(IceServerParseError::UnknownScheme(other.to_string())),
        };

        // Honor ?transport=... for turn: only. Match C++: turns: keeps TLS.
        if typ == IceServerType::Turn && relay_type != RelayType::TurnTls {
            if let Some(query) = parsed.query.as_deref() {
                if query.contains("transport=udp") {
                    relay_type = RelayType::TurnUdp;
                } else if query.contains("transport=tcp") {
                    relay_type = RelayType::TurnTcp;
                } else if query.contains("transport=tls") {
                    relay_type = RelayType::TurnTls;
                }
            }
        }

        let has_userinfo = parsed.user.is_some() || parsed.password.is_some();
        match typ {
            IceServerType::Stun if has_userinfo => {
                return Err(IceServerParseError::StunWithCredentials);
            }
            IceServerType::Turn if !has_userinfo => {
                return Err(IceServerParseError::TurnMissingCredentials);
            }
            _ => {}
        }

        let port = match parsed.port.as_deref() {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| IceServerParseError::InvalidPort(p.to_string()))?,
            None => default_port,
        };

        Ok(IceServer {
            hostname: parsed.host,
            port,
            typ,
            username: parsed.user.unwrap_or_default(),
            password: parsed.password.unwrap_or_default(),
            relay_type,
        })
    }

    /// True if this is a STUN server.
    pub fn is_stun(&self) -> bool {
        matches!(self.typ, IceServerType::Stun)
    }

    /// True if this is a TURN server.
    pub fn is_turn(&self) -> bool {
        matches!(self.typ, IceServerType::Turn)
    }
}

impl FromStr for IceServer {
    type Err = IceServerParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IceServer::parse(s)
    }
}

// ---------------------------------------------------------------------------
// ProxyServer
// ---------------------------------------------------------------------------

/// Outgoing proxy used for TURN/TCP and signalling traffic.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProxyServer {
    /// Proxy protocol.
    pub typ: ProxyType,
    /// Proxy hostname or IP literal (no brackets for IPv6).
    pub hostname: String,
    /// Proxy port.
    pub port: u16,
    /// Optional username for proxy authentication.
    pub username: Option<String>,
    /// Optional password for proxy authentication.
    pub password: Option<String>,
}

impl ProxyServer {
    /// Construct a proxy server without authentication credentials.
    pub fn new(typ: ProxyType, hostname: impl Into<String>, port: u16) -> Self {
        ProxyServer {
            typ,
            hostname: hostname.into(),
            port,
            username: None,
            password: None,
        }
    }

    /// Construct a proxy server with `Basic` username/password credentials.
    pub fn with_credentials(
        typ: ProxyType,
        hostname: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        ProxyServer {
            typ,
            hostname: hostname.into(),
            port,
            username: Some(username.into()),
            password: Some(password.into()),
        }
    }

    /// Parse an `http://`, `https://`, or `socks5://` proxy URL.
    ///
    /// Default ports: `3128` for `http`/`https`, `1080` for `socks5`.
    pub fn parse(url: &str) -> Result<Self, IceServerParseError> {
        let parsed = ParsedUrl::parse(url)?;
        let scheme = parsed.scheme.to_ascii_lowercase();

        let (typ, default_port) = match scheme.as_str() {
            // C++ accepts http/HTTP only; we add https for symmetry — it's
            // the same protocol semantically as far as ProxyServer is concerned.
            "http" | "https" => (ProxyType::Http, 3128),
            "socks5" => (ProxyType::Socks5, 1080),
            other => return Err(IceServerParseError::UnknownScheme(other.to_string())),
        };

        let port = match parsed.port.as_deref() {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| IceServerParseError::InvalidPort(p.to_string()))?,
            None => default_port,
        };

        Ok(ProxyServer {
            typ,
            hostname: parsed.host,
            port,
            username: parsed.user,
            password: parsed.password,
        })
    }
}

impl FromStr for ProxyServer {
    type Err = IceServerParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ProxyServer::parse(s)
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Peer-connection configuration. Mirrors `rtc::Configuration`.
///
/// All fields are public so callers can construct the struct with the
/// struct-literal `Configuration { ice_servers: vec![..], ..Default::default() }`
/// pattern. For the common "add by URL" path use
/// [`Configuration::add_ice_server`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    /// ICE servers used for candidate gathering, in priority order.
    pub ice_servers: Vec<IceServer>,
    /// Optional outgoing proxy (libnice backend only upstream).
    pub proxy_server: Option<ProxyServer>,
    /// Local bind address for the ICE socket (libjuice backend only).
    pub bind_address: Option<String>,
    /// DTLS certificate type.
    pub certificate_type: CertificateType,
    /// ICE transport policy.
    pub ice_transport_policy: TransportPolicy,
    /// Legacy ICE-TCP switch. `true` means active mode unless
    /// [`Configuration::ice_tcp_mode`] overrides it.
    pub enable_ice_tcp: bool,
    /// Explicit active/passive role for native peer-to-peer fallback.
    pub ice_tcp_mode: Option<IceTcpMode>,
    /// Enable ICE UDP multiplexing (libjuice backend only).
    pub enable_ice_udp_mux: bool,
    /// If true, the runtime does not auto-create offers / process renegotiation.
    pub disable_auto_negotiation: bool,
    /// If true, the runtime does not begin candidate gathering automatically.
    pub disable_auto_gathering: bool,
    /// If true, ICE will be configured for media (RTP/RTCP) only.
    pub force_media_transport: bool,
    /// If true, DTLS fingerprint verification is skipped (debug only).
    pub disable_fingerprint_verification: bool,
    /// Lower bound (inclusive) of the ephemeral port range. Default `1024`.
    pub port_range_begin: u16,
    /// Upper bound (inclusive) of the ephemeral port range. Default `65535`.
    pub port_range_end: u16,
    /// Network MTU override; `None` falls back to the library default.
    pub mtu: Option<usize>,
    /// Local maximum message size for data channels; `None` falls back to
    /// the library default.
    pub max_message_size: Option<usize>,
    /// Congestion-control algorithm hint for SCTP.
    pub congestion_control_algorithm: CongestionControl,
}

impl Configuration {
    /// New configuration with the same defaults as the C++ `Configuration{}`
    /// brace-init: no ICE servers, port range `1024..=65535`, default DTLS
    /// cert type, `All` ICE transport policy, all toggles `false`, no MTU /
    /// message-size override.
    pub fn new() -> Self {
        Configuration {
            ice_servers: Vec::new(),
            proxy_server: None,
            bind_address: None,
            certificate_type: CertificateType::Default,
            ice_transport_policy: IceTransportPolicy::All,
            enable_ice_tcp: false,
            ice_tcp_mode: None,
            enable_ice_udp_mux: false,
            disable_auto_negotiation: false,
            disable_auto_gathering: false,
            force_media_transport: false,
            disable_fingerprint_verification: false,
            port_range_begin: 1024,
            port_range_end: 65535,
            mtu: None,
            max_message_size: None,
            congestion_control_algorithm: CongestionControl::Default,
        }
    }

    /// Append an ICE server by URL. The configuration is **not** mutated
    /// on parse failure.
    pub fn add_ice_server(&mut self, url: impl Into<String>) -> Result<(), IceServerParseError> {
        let url = url.into();
        let parsed = IceServer::parse(&url)?;
        self.ice_servers.push(parsed);
        Ok(())
    }

    /// Append an already-parsed ICE server. Infallible counterpart to
    /// [`Configuration::add_ice_server`].
    pub fn add_ice_server_parsed(&mut self, server: IceServer) {
        self.ice_servers.push(server);
    }
}

impl Default for Configuration {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// URL parser — hand-rolled, stdlib only.
// ---------------------------------------------------------------------------

/// Generic URL split shared by ICE and proxy URLs.
///
/// Recognises the grammar:
///
/// ```text
/// <scheme>:[//]?[<user>[:<password>]@]<host>[:<port>][?<query>][#<fragment>]
/// ```
///
/// The host may be an IPv6 literal in `[...]` brackets, in which case the
/// brackets are stripped from the returned `host`. User and password are
/// percent-decoded.
struct ParsedUrl {
    scheme: String,
    user: Option<String>,
    password: Option<String>,
    host: String,
    /// Port string (not yet validated as a `u16`).
    port: Option<String>,
    query: Option<String>,
}

impl ParsedUrl {
    fn parse(url: &str) -> Result<Self, IceServerParseError> {
        let url = url.trim();
        if url.is_empty() {
            return Err(IceServerParseError::Empty);
        }

        // 1. Extract scheme (everything before the first `:`). The scheme
        //    may not contain `/`, `?`, `#`, `@` — bail if any precede `:`.
        let colon = url
            .find(|c: char| c == ':' || c == '/' || c == '?' || c == '#' || c == '@')
            .ok_or_else(|| IceServerParseError::UnknownScheme(url.to_string()))?;
        if url.as_bytes()[colon] != b':' {
            return Err(IceServerParseError::UnknownScheme(url.to_string()));
        }
        let scheme = url[..colon].to_string();
        if scheme.is_empty() {
            return Err(IceServerParseError::UnknownScheme(String::new()));
        }
        let mut rest = &url[colon + 1..];

        // 2. Skip optional `//` (0, 1, or 2 leading slashes; mirrors the
        //    C++ regex `/{0,2}`).
        let mut slashes = 0;
        while slashes < 2 && rest.starts_with('/') {
            rest = &rest[1..];
            slashes += 1;
        }

        // 3. Split off fragment (`#...`) — discarded, but must not poison
        //    the host split.
        if let Some(hash) = rest.find('#') {
            rest = &rest[..hash];
        }

        // 4. Split off query string (`?...`).
        let (authority, query) = match rest.find('?') {
            Some(q) => (&rest[..q], Some(rest[q + 1..].to_string())),
            None => (rest, None),
        };

        // 5. Split userinfo from host on the LAST `@` (RFC 3986).
        let (userinfo, hostport) = match authority.rfind('@') {
            Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
            None => (None, authority),
        };

        let (user, password) = match userinfo {
            Some(ui) => {
                // First `:` splits user from password — matches the C++
                // userinfo regex `([^:@]*)(:([^@]*))?`.
                let (u, p) = match ui.find(':') {
                    Some(c) => (&ui[..c], Some(&ui[c + 1..])),
                    None => (ui, None),
                };
                let user = if u.is_empty() {
                    None
                } else {
                    Some(percent_decode(u)?)
                };
                let password = match p {
                    Some(pw) => Some(percent_decode(pw)?),
                    None => None,
                };
                (user, password)
            }
            None => (None, None),
        };

        // 6. Pull host[:port], honouring IPv6 brackets.
        let (host, port) = split_host_port(hostport)?;
        if host.is_empty() {
            return Err(IceServerParseError::MissingHost);
        }

        Ok(ParsedUrl {
            scheme,
            user,
            password,
            host,
            port,
            query,
        })
    }
}

/// Split a `host:port` (or `[ipv6]:port`) string. Returns the host with any
/// IPv6 brackets stripped and the port portion as an unparsed string.
fn split_host_port(s: &str) -> Result<(String, Option<String>), IceServerParseError> {
    if let Some(rest) = s.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or(IceServerParseError::UnterminatedIpv6)?;
        let host = rest[..close].to_string();
        let after = &rest[close + 1..];
        if after.is_empty() {
            return Ok((host, None));
        }
        let after = after
            .strip_prefix(':')
            .ok_or_else(|| IceServerParseError::InvalidPort(after.to_string()))?;
        if after.is_empty() {
            Ok((host, None))
        } else {
            Ok((host, Some(after.to_string())))
        }
    } else {
        match s.rfind(':') {
            Some(c) => {
                let host = percent_decode(&s[..c])?;
                let port = &s[c + 1..];
                if port.is_empty() {
                    Ok((host, None))
                } else {
                    Ok((host, Some(port.to_string())))
                }
            }
            None => Ok((percent_decode(s)?, None)),
        }
    }
}

/// Decode `%xx` escapes per RFC 3986. Mirrors `impl::utils::url_decode` but
/// returns an error for malformed input instead of warning-and-skipping.
fn percent_decode(s: &str) -> Result<String, IceServerParseError> {
    if !s.contains('%') {
        return Ok(s.to_string());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return Err(IceServerParseError::BadPercentEncoding);
            }
            let hi = hex_value(bytes[i + 1]).ok_or(IceServerParseError::BadPercentEncoding)?;
            let lo = hex_value(bytes[i + 2]).ok_or(IceServerParseError::BadPercentEncoding)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| IceServerParseError::BadPercentEncoding)
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- IceServer URL parsing ---

    #[test]
    fn parse_stun_default_port() {
        let s = IceServer::parse("stun:stun.example.com").unwrap();
        assert_eq!(s.hostname, "stun.example.com");
        assert_eq!(s.port, 3478);
        assert_eq!(s.typ, IceServerType::Stun);
        assert!(s.username.is_empty());
        assert!(s.password.is_empty());
    }

    #[test]
    fn parse_stun_with_port() {
        let s = IceServer::parse("stun:stun.example.com:19302").unwrap();
        assert_eq!(s.hostname, "stun.example.com");
        assert_eq!(s.port, 19302);
        assert!(s.is_stun());
    }

    #[test]
    fn parse_turn_udp_default() {
        let s = IceServer::parse("turn:user:pass@turn.example.com").unwrap();
        assert_eq!(s.hostname, "turn.example.com");
        assert_eq!(s.port, 3478);
        assert_eq!(s.typ, IceServerType::Turn);
        assert_eq!(s.username, "user");
        assert_eq!(s.password, "pass");
        assert_eq!(s.relay_type, RelayType::TurnUdp);
    }

    #[test]
    fn parse_turn_tcp_via_query() {
        let s = IceServer::parse("turn:user:pass@turn.example.com?transport=tcp").unwrap();
        assert_eq!(s.relay_type, RelayType::TurnTcp);
        assert_eq!(s.port, 3478);
    }

    #[test]
    fn parse_turns_default_port_5349() {
        let s = IceServer::parse("turns:user:pass@turn.example.com").unwrap();
        assert_eq!(s.port, 5349);
        assert_eq!(s.relay_type, RelayType::TurnTls);
        assert_eq!(s.typ, IceServerType::Turn);
    }

    #[test]
    fn parse_turns_transport_query_is_ignored() {
        // turns: is always TLS; ?transport=udp doesn't downgrade it.
        let s = IceServer::parse("turns:user:pass@turn.example.com?transport=udp").unwrap();
        assert_eq!(s.relay_type, RelayType::TurnTls);
    }

    #[test]
    fn parse_turn_ipv6_literal() {
        let s = IceServer::parse("turn:user:pass@[2001:db8::1]:3478").unwrap();
        assert_eq!(s.hostname, "2001:db8::1");
        assert_eq!(s.port, 3478);
        assert_eq!(s.username, "user");
        assert_eq!(s.password, "pass");
    }

    #[test]
    fn parse_turn_ipv6_literal_default_port() {
        let s = IceServer::parse("turn:user:pass@[2001:db8::1]").unwrap();
        assert_eq!(s.hostname, "2001:db8::1");
        assert_eq!(s.port, 3478);
    }

    #[test]
    fn parse_turn_percent_encoded_user_pass() {
        let s = IceServer::parse("turn:us%40er:p%3Ass@turn.example.com").unwrap();
        assert_eq!(s.username, "us@er");
        assert_eq!(s.password, "p:ss");
    }

    #[test]
    fn parse_uppercase_scheme_accepted() {
        let s = IceServer::parse("STUN:stun.example.com").unwrap();
        assert_eq!(s.typ, IceServerType::Stun);
        assert_eq!(s.port, 3478);
    }

    #[test]
    fn parse_with_double_slash_accepted() {
        // The C++ regex tolerates `//` after the scheme.
        let s = IceServer::parse("stun://stun.example.com:19302").unwrap();
        assert_eq!(s.hostname, "stun.example.com");
        assert_eq!(s.port, 19302);
    }

    #[test]
    fn parse_stun_with_userinfo_rejects() {
        let err = IceServer::parse("stun:user:pass@stun.example.com").unwrap_err();
        assert_eq!(err, IceServerParseError::StunWithCredentials);
    }

    #[test]
    fn parse_turn_without_userinfo_rejects() {
        let err = IceServer::parse("turn:turn.example.com").unwrap_err();
        assert_eq!(err, IceServerParseError::TurnMissingCredentials);
    }

    #[test]
    fn parse_invalid_scheme_rejects() {
        let err = IceServer::parse("http://stun.example.com").unwrap_err();
        assert_eq!(err, IceServerParseError::UnknownScheme("http".into()));
    }

    #[test]
    fn parse_stuns_rejected() {
        // Matches C++: the regex matches but the scheme switch throws.
        let err = IceServer::parse("stuns:stun.example.com").unwrap_err();
        assert_eq!(err, IceServerParseError::UnknownScheme("stuns".into()));
    }

    #[test]
    fn parse_empty_returns_error() {
        assert_eq!(
            IceServer::parse("").unwrap_err(),
            IceServerParseError::Empty
        );
        assert_eq!(
            IceServer::parse("   ").unwrap_err(),
            IceServerParseError::Empty
        );
    }

    #[test]
    fn parse_no_host_returns_error() {
        // `turn:user:pass@` has empty host after the `@`.
        let err = IceServer::parse("turn:user:pass@").unwrap_err();
        assert_eq!(err, IceServerParseError::MissingHost);
    }

    #[test]
    fn parse_bad_port_returns_error() {
        let err = IceServer::parse("stun:stun.example.com:notaport").unwrap_err();
        assert_eq!(err, IceServerParseError::InvalidPort("notaport".into()));
    }

    #[test]
    fn parse_unterminated_ipv6_rejects() {
        let err = IceServer::parse("turn:user:pass@[2001:db8::1").unwrap_err();
        assert_eq!(err, IceServerParseError::UnterminatedIpv6);
    }

    #[test]
    fn parse_bad_percent_encoding_rejects() {
        // %ZZ is not valid hex.
        let err = IceServer::parse("turn:bad%ZZ:pass@turn.example.com").unwrap_err();
        assert_eq!(err, IceServerParseError::BadPercentEncoding);
    }

    #[test]
    fn parse_password_with_at_uses_last_at_split() {
        // Per RFC 3986, the LAST `@` separates userinfo from host so a `@`
        // can appear inside a percent-encoded password without breaking the
        // parse. Use a literal `@` in the password — only the trailing `@`
        // before the host should split.
        let s = IceServer::parse("turn:user:p@ss@turn.example.com").unwrap();
        assert_eq!(s.hostname, "turn.example.com");
        assert_eq!(s.username, "user");
        assert_eq!(s.password, "p@ss");
    }

    #[test]
    fn roundtrip_via_fromstr_trait() {
        let s: IceServer = "turn:user:pass@turn.example.com:3478?transport=tcp"
            .parse()
            .unwrap();
        assert_eq!(s.hostname, "turn.example.com");
        assert_eq!(s.port, 3478);
        assert_eq!(s.relay_type, RelayType::TurnTcp);
        assert_eq!(s.username, "user");
        assert_eq!(s.password, "pass");
    }

    #[test]
    fn is_stun_is_turn_helpers() {
        let a = IceServer::stun("stun.example.com", 3478);
        let b = IceServer::turn("turn.example.com", 3478, "u", "p", RelayType::TurnUdp);
        assert!(a.is_stun() && !a.is_turn());
        assert!(b.is_turn() && !b.is_stun());
    }

    // --- Configuration helpers ---

    #[test]
    fn add_ice_server_appends_to_vec() {
        let mut c = Configuration::new();
        c.add_ice_server("stun:stun.example.com").unwrap();
        c.add_ice_server("turn:u:p@turn.example.com").unwrap();
        assert_eq!(c.ice_servers.len(), 2);
        assert!(c.ice_servers[0].is_stun());
        assert!(c.ice_servers[1].is_turn());
    }

    #[test]
    fn add_ice_server_bad_url_returns_error_no_mutation() {
        let mut c = Configuration::new();
        c.add_ice_server("stun:stun.example.com").unwrap();
        let before = c.ice_servers.clone();
        let err = c.add_ice_server("http://nope").unwrap_err();
        assert_eq!(err, IceServerParseError::UnknownScheme("http".into()));
        assert_eq!(c.ice_servers, before, "vec must not have grown on error");
    }

    #[test]
    fn add_ice_server_parsed_appends() {
        let mut c = Configuration::new();
        c.add_ice_server_parsed(IceServer::stun("stun.example.com", 19302));
        assert_eq!(c.ice_servers.len(), 1);
        assert_eq!(c.ice_servers[0].port, 19302);
    }

    #[test]
    fn default_certificate_type_is_default() {
        let c = Configuration::default();
        assert_eq!(c.certificate_type, CertificateType::Default);
        assert_eq!(c.ice_transport_policy, IceTransportPolicy::All);
        assert_eq!(c.port_range_begin, 1024);
        assert_eq!(c.port_range_end, 65535);
        assert!(c.mtu.is_none());
        assert!(c.max_message_size.is_none());
        assert!(c.ice_servers.is_empty());
        assert!(!c.enable_ice_tcp);
        assert!(c.ice_tcp_mode.is_none());
        assert!(!c.enable_ice_udp_mux);
        assert!(!c.disable_auto_negotiation);
        assert!(!c.disable_auto_gathering);
        assert!(!c.force_media_transport);
        assert!(!c.disable_fingerprint_verification);
        assert_eq!(c.congestion_control_algorithm, CongestionControl::Default);
    }

    // --- ProxyServer URL parsing ---

    #[test]
    fn parse_http_proxy() {
        let p = ProxyServer::parse("http://proxy.example.com").unwrap();
        assert_eq!(p.typ, ProxyType::Http);
        assert_eq!(p.hostname, "proxy.example.com");
        assert_eq!(p.port, 3128);
        assert!(p.username.is_none());
        assert!(p.password.is_none());
    }

    #[test]
    fn parse_socks5_with_credentials() {
        let p = ProxyServer::parse("socks5://user:pass@proxy.example.com:1080").unwrap();
        assert_eq!(p.typ, ProxyType::Socks5);
        assert_eq!(p.hostname, "proxy.example.com");
        assert_eq!(p.port, 1080);
        assert_eq!(p.username.as_deref(), Some("user"));
        assert_eq!(p.password.as_deref(), Some("pass"));
    }

    #[test]
    fn parse_bad_scheme_rejects() {
        let err = ProxyServer::parse("ftp://proxy.example.com").unwrap_err();
        assert_eq!(err, IceServerParseError::UnknownScheme("ftp".into()));
    }

    #[test]
    fn parse_with_port() {
        let p = ProxyServer::parse("http://proxy.example.com:8080").unwrap();
        assert_eq!(p.port, 8080);
    }

    #[test]
    fn parse_socks5_default_port_1080() {
        let p = ProxyServer::parse("socks5://proxy.example.com").unwrap();
        assert_eq!(p.port, 1080);
    }
}
