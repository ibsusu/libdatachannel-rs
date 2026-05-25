//! ICE candidate type, mirroring `rtc::Candidate` from libdatachannel C++.
//!
//! Format reference: RFC 8839 §5.1 (formerly RFC 5245 §15.1):
//!
//! ```text
//!   candidate:<foundation> <component> <transport> <priority>
//!             <connection-address> <port> typ <cand-type>
//!             [raddr <ip> rport <port>] [tcptype <type>]
//!             [<other-extensions>]
//! ```
//!
//! This is the SDP-bearing public-facing candidate. It is independent of
//! libjuice's internal `Candidate` (which is `pub(crate)`); the runtime
//! that drives ICE will translate between the two when the wiring lands
//! in a later phase.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use thiserror::Error;

/// Candidate type. RFC 8445 §5.1.1.1; mirrors `rtc::Candidate::Type`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// Unknown / unparseable type.
    Unknown,
    /// `host` — a directly attached interface address.
    Host,
    /// `srflx` — server-reflexive (learned via STUN).
    ServerReflexive,
    /// `prflx` — peer-reflexive (learned during connectivity checks).
    PeerReflexive,
    /// `relay` — relayed via TURN.
    Relayed,
}

impl CandidateType {
    /// SDP `typ` token; matches the C++ `operator<<` for `Type`.
    pub fn as_sdp(self) -> &'static str {
        match self {
            CandidateType::Host => "host",
            CandidateType::PeerReflexive => "prflx",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::Relayed => "relay",
            CandidateType::Unknown => "unknown",
        }
    }

    fn from_sdp(s: &str) -> Self {
        match s {
            "host" => CandidateType::Host,
            "prflx" => CandidateType::PeerReflexive,
            "srflx" => CandidateType::ServerReflexive,
            "relay" => CandidateType::Relayed,
            _ => CandidateType::Unknown,
        }
    }
}

impl fmt::Display for CandidateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sdp())
    }
}

/// Transport. Mirrors `rtc::Candidate::TransportType`.
///
/// `TcpUnknown` is set when a TCP candidate is parsed without a recognised
/// `tcptype` token (matches the C++ behaviour exactly).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TransportType {
    /// Unknown transport (e.g. neither UDP nor TCP).
    Unknown,
    /// UDP.
    Udp,
    /// TCP, `a=...tcptype active`.
    TcpActive,
    /// TCP, `a=...tcptype passive`.
    TcpPassive,
    /// TCP, `a=...tcptype so` (simultaneous open).
    TcpSo,
    /// TCP, `tcptype` missing or unrecognised.
    TcpUnknown,
}

impl TransportType {
    /// Debug-friendly token; matches the C++ `operator<<` for `TransportType`.
    pub fn as_sdp(self) -> &'static str {
        match self {
            TransportType::Udp => "UDP",
            TransportType::TcpActive => "TCP_active",
            TransportType::TcpPassive => "TCP_passive",
            TransportType::TcpSo => "TCP_so",
            TransportType::TcpUnknown => "TCP_unknown",
            TransportType::Unknown => "unknown",
        }
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sdp())
    }
}

/// Address family of a (possibly resolved) candidate. Mirrors
/// `rtc::Candidate::Family`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Family {
    /// The candidate carries a hostname that has not been resolved.
    Unresolved,
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
}

/// Errors returned when parsing a `candidate:` line.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// Required token missing.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// Integer parsing failed for one of the numeric fields.
    #[error("bad integer in field: {0}")]
    BadInteger(&'static str),
    /// The `typ` marker was missing or misspelled.
    #[error("expected `typ` marker")]
    MissingTypMarker,
}

/// An SDP-bearing ICE candidate.
///
/// This is libdatachannel's public-facing candidate type. It owns the parsed
/// fields plus the verbatim tail of any extension attributes so that
/// `to_sdp()` round-trips cleanly. Compare with [`libjuice`'s internal
/// `Candidate`](../../libjuice/src/ice/candidate.rs) which is a runtime
/// type for the ICE state machine.
#[derive(Debug, Clone)]
pub struct Candidate {
    foundation: String,
    component: u32,
    priority: u32,
    /// Verbatim transport token (`"UDP"`, `"udp"`, `"TCP"`, ...). Preserved
    /// so `to_sdp()` round-trips byte-for-byte for well-formed inputs.
    transport_string: String,
    transport_type: TransportType,
    /// As-on-the-wire `node` (numeric address or hostname).
    node: String,
    /// As-on-the-wire `service` (port string).
    service: String,
    /// Verbatim type token (`"host"`, `"srflx"`, ...).
    type_string: String,
    candidate_type: CandidateType,
    /// Everything after `typ <typeString>`, with leading/trailing whitespace
    /// trimmed. Preserved verbatim so unknown extensions survive a round trip.
    tail: String,

    mid: Option<String>,

    // Populated by `resolve()` when the node is a numeric address or DNS
    // lookup completes. Default is `Family::Unresolved` + `address` empty.
    family: Family,
    address: String,
    port: u16,
}

impl Default for Candidate {
    fn default() -> Self {
        // Matches the C++ default constructor.
        Candidate {
            foundation: "none".to_string(),
            component: 0,
            priority: 0,
            transport_string: "unknown".to_string(),
            transport_type: TransportType::Unknown,
            node: "0.0.0.0".to_string(),
            service: "9".to_string(),
            type_string: "unknown".to_string(),
            candidate_type: CandidateType::Unknown,
            tail: String::new(),
            mid: None,
            family: Family::Unresolved,
            address: String::new(),
            port: 0,
        }
    }
}

impl Candidate {
    /// Empty candidate, matching the C++ default constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a candidate line. `candidate` may be the raw SDP value (with or
    /// without a leading `candidate:` or `a=` prefix). `mid` is metadata that
    /// is attached to the candidate but does not appear in the `candidate:`
    /// line itself.
    pub fn parse(candidate: &str, mid: &str) -> Result<Self, ParseError> {
        let mut c = Self::new();
        if !candidate.is_empty() {
            c.parse_in_place(candidate)?;
        }
        if !mid.is_empty() {
            c.mid = Some(mid.to_string());
        }
        // Best-effort numeric resolution — matches the C++ default which
        // tries `getaddrinfo(AI_NUMERICHOST)` on the address tokens via
        // `resolve(Simple)` once the wiring lands. We do the IP-literal
        // short-circuit so `is_resolved()` is meaningful immediately.
        c.try_resolve_numeric();
        Ok(c)
    }

    fn parse_in_place(&mut self, candidate: &str) -> Result<(), ParseError> {
        // Strip optional leading "a=" then optional "candidate:" — matches
        // the C++ `prefixes` loop.
        let mut s = candidate;
        if let Some(rest) = s.strip_prefix("a=") {
            s = rest;
        }
        if let Some(rest) = s.strip_prefix("candidate:") {
            s = rest;
        }

        let mut it = s.split_ascii_whitespace();
        let foundation = it.next().ok_or(ParseError::MissingField("foundation"))?;
        let component = it
            .next()
            .ok_or(ParseError::MissingField("component"))?
            .parse::<u32>()
            .map_err(|_| ParseError::BadInteger("component"))?;
        let transport_string = it.next().ok_or(ParseError::MissingField("transport"))?;
        let priority = it
            .next()
            .ok_or(ParseError::MissingField("priority"))?
            .parse::<u32>()
            .map_err(|_| ParseError::BadInteger("priority"))?;
        let node = it.next().ok_or(ParseError::MissingField("address"))?;
        let service = it.next().ok_or(ParseError::MissingField("port"))?;
        let typ_marker = it.next().ok_or(ParseError::MissingTypMarker)?;
        if typ_marker != "typ" {
            return Err(ParseError::MissingTypMarker);
        }
        let type_string = it
            .next()
            .ok_or(ParseError::MissingField("candidate type"))?;

        // Everything remaining is `tail`, joined with single spaces and
        // trimmed — matches the C++ getline + trim. We rebuild it from the
        // already-split tokens (whitespace is normalised, which is fine for
        // SDP values).
        let tail_tokens: Vec<&str> = it.collect();
        let tail = tail_tokens.join(" ");

        self.foundation = foundation.to_string();
        self.component = component;
        self.priority = priority;
        self.node = node.to_string();
        self.service = service.to_string();
        self.type_string = type_string.to_string();
        self.candidate_type = CandidateType::from_sdp(type_string);
        self.transport_string = transport_string.to_string();
        self.transport_type = classify_transport(transport_string, &tail);
        self.tail = tail;
        Ok(())
    }

    /// IP-literal short-circuit. Mirrors the `AI_NUMERICHOST` path of the
    /// C++ `resolve(Simple)` — if `node` already parses as an IP, set the
    /// resolved fields without touching DNS.
    fn try_resolve_numeric(&mut self) {
        if let Ok(ip) = self.node.parse::<IpAddr>() {
            if let Ok(port) = self.service.parse::<u16>() {
                self.address = ip.to_string();
                self.port = port;
                self.family = match ip {
                    IpAddr::V4(_) => Family::Ipv4,
                    IpAddr::V6(_) => Family::Ipv6,
                };
            }
        }
    }

    /// Attach a `mid` if none was set. Matches `Candidate::hintMid`.
    pub fn hint_mid(&mut self, mid: impl Into<String>) {
        if self.mid.is_none() {
            self.mid = Some(mid.into());
        }
    }

    /// Serialize to the canonical `candidate:...` SDP value. Mirrors
    /// `rtc::Candidate::candidate()` byte-for-byte for well-formed inputs.
    pub fn to_sdp(&self) -> String {
        let mut out = String::with_capacity(96 + self.tail.len());
        out.push_str("candidate:");
        out.push_str(&self.foundation);
        out.push(' ');
        out.push_str(&self.component.to_string());
        out.push(' ');
        out.push_str(&self.transport_string);
        out.push(' ');
        out.push_str(&self.priority.to_string());
        out.push(' ');
        if self.is_resolved() {
            out.push_str(&self.address);
            out.push(' ');
            out.push_str(&self.port.to_string());
        } else {
            out.push_str(&self.node);
            out.push(' ');
            out.push_str(&self.service);
        }
        out.push(' ');
        out.push_str("typ");
        out.push(' ');
        out.push_str(&self.type_string);
        if !self.tail.is_empty() {
            out.push(' ');
            out.push_str(&self.tail);
        }
        out
    }

    /// `mid` for the m-line this candidate belongs to, defaulting to `"0"`
    /// when unset. Matches `rtc::Candidate::mid()`.
    pub fn mid(&self) -> &str {
        self.mid.as_deref().unwrap_or("0")
    }

    /// Returns true if a `mid` was explicitly set (as opposed to the `"0"`
    /// default returned by [`Candidate::mid`]).
    pub fn has_mid(&self) -> bool {
        self.mid.is_some()
    }

    /// Candidate type.
    pub fn candidate_type(&self) -> CandidateType {
        self.candidate_type
    }

    /// Transport type.
    pub fn transport_type(&self) -> TransportType {
        self.transport_type
    }

    /// Resolved address (numeric form), or `None` if the address is still
    /// an unresolved hostname.
    pub fn address(&self) -> Option<&str> {
        if self.is_resolved() {
            Some(&self.address)
        } else {
            None
        }
    }

    /// Resolved port, or `None` if the address is still an unresolved
    /// hostname.
    pub fn port(&self) -> Option<u16> {
        if self.is_resolved() {
            Some(self.port)
        } else {
            None
        }
    }

    /// Priority (the second-to-last token before the address; see RFC 8445
    /// §5.1.2.1).
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Foundation token; opaque grouping id (RFC 8839 §5.1).
    pub fn foundation(&self) -> &str {
        &self.foundation
    }

    /// Component id; `1` is RTP, `2` is RTCP under RFC 5245 (we no longer
    /// split RTCP for DataChannel use, so this is almost always `1`).
    pub fn component(&self) -> u32 {
        self.component
    }

    /// True once `address`/`port` have been populated either by
    /// IP-literal short-circuit or by DNS resolution.
    pub fn is_resolved(&self) -> bool {
        self.family != Family::Unresolved
    }

    /// Address family. `Unresolved` until the address has been resolved.
    pub fn family(&self) -> Family {
        self.family
    }

    /// `raddr` (related address) if it was present in the extension tail.
    pub fn related_address(&self) -> Option<&str> {
        find_kv(&self.tail, "raddr")
    }

    /// `rport` (related port) if it was present in the extension tail.
    pub fn related_port(&self) -> Option<u16> {
        find_kv(&self.tail, "rport").and_then(|s| s.parse().ok())
    }

    /// `tcptype` extension token if present.
    pub fn tcp_type(&self) -> Option<&str> {
        find_kv(&self.tail, "tcptype")
    }

    /// Resolved socket address pair, if available.
    pub fn resolved(&self) -> Option<SocketAddr> {
        if !self.is_resolved() {
            return None;
        }
        let ip: IpAddr = self.address.parse().ok()?;
        Some(SocketAddr::new(ip, self.port))
    }
}

impl fmt::Display for Candidate {
    /// Matches the C++ `operator string()`: prepends `a=` to the SDP value
    /// so the result is a complete attribute line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a={}", self.to_sdp())
    }
}

impl FromStr for Candidate {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Candidate::parse(s, "")
    }
}

impl PartialEq for Candidate {
    /// Equality matches the C++ definition: same foundation, node, service.
    fn eq(&self, other: &Self) -> bool {
        self.foundation == other.foundation
            && self.node == other.node
            && self.service == other.service
    }
}

impl Eq for Candidate {}

/// Classify the parsed transport string + tail tokens into a `TransportType`.
/// Mirrors the C++ block that peeks `mTail` for a `tcptype` token.
fn classify_transport(transport_string: &str, tail: &str) -> TransportType {
    if transport_string.eq_ignore_ascii_case("udp") {
        return TransportType::Udp;
    }
    if !transport_string.eq_ignore_ascii_case("tcp") {
        return TransportType::Unknown;
    }
    match find_kv(tail, "tcptype") {
        Some("active") => TransportType::TcpActive,
        Some("passive") => TransportType::TcpPassive,
        Some("so") => TransportType::TcpSo,
        _ => TransportType::TcpUnknown,
    }
}

/// Look up `key` in the tail extension list (whitespace-separated key/value
/// pairs). Returns the value token, or `None` if not present.
fn find_kv<'a>(tail: &'a str, key: &str) -> Option<&'a str> {
    let mut it = tail.split_ascii_whitespace();
    while let Some(k) = it.next() {
        let v = it.next();
        if k.eq_ignore_ascii_case(key) {
            return v;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_udp_ipv4_roundtrip() {
        let raw = "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host";
        let c: Candidate = raw.parse().unwrap();
        assert_eq!(c.candidate_type(), CandidateType::Host);
        assert_eq!(c.transport_type(), TransportType::Udp);
        assert_eq!(c.foundation(), "1");
        assert_eq!(c.component(), 1);
        assert_eq!(c.priority(), 2113937151);
        assert_eq!(c.address(), Some("192.168.1.10"));
        assert_eq!(c.port(), Some(56789));
        assert_eq!(c.family(), Family::Ipv4);
        assert!(c.is_resolved());
        assert_eq!(c.to_sdp(), raw);
    }

    #[test]
    fn parse_host_udp_ipv6_roundtrip() {
        let raw = "candidate:1 1 udp 2122252543 2001:db8::1 50001 typ host";
        let c: Candidate = raw.parse().unwrap();
        assert_eq!(c.candidate_type(), CandidateType::Host);
        assert_eq!(c.transport_type(), TransportType::Udp);
        assert_eq!(c.family(), Family::Ipv6);
        // Address is the canonical IpAddr::to_string form.
        assert_eq!(c.address(), Some("2001:db8::1"));
        assert_eq!(c.port(), Some(50001));
        assert_eq!(c.to_sdp(), raw);
    }

    #[test]
    fn parse_srflx_with_raddr_rport() {
        let raw = "candidate:842163049 1 udp 1677729535 192.0.2.1 50000 typ srflx raddr 198.51.100.1 rport 5000";
        let c: Candidate = raw.parse().unwrap();
        assert_eq!(c.candidate_type(), CandidateType::ServerReflexive);
        assert_eq!(c.transport_type(), TransportType::Udp);
        assert_eq!(c.related_address(), Some("198.51.100.1"));
        assert_eq!(c.related_port(), Some(5000));
        assert_eq!(c.to_sdp(), raw);
    }

    #[test]
    fn parse_prflx_ipv4_roundtrip() {
        let raw = "candidate:7 1 UDP 1845501695 203.0.113.7 50500 typ prflx";
        let c: Candidate = raw.parse().unwrap();
        assert_eq!(c.candidate_type(), CandidateType::PeerReflexive);
        assert_eq!(c.to_sdp(), raw);
    }

    #[test]
    fn parse_relay_ipv6_roundtrip() {
        let raw = "candidate:9 1 UDP 16777215 2001:db8::abcd 33445 typ relay raddr 2001:db8::1 rport 60000";
        let c: Candidate = raw.parse().unwrap();
        assert_eq!(c.candidate_type(), CandidateType::Relayed);
        assert_eq!(c.family(), Family::Ipv6);
        assert_eq!(c.related_address(), Some("2001:db8::1"));
        assert_eq!(c.to_sdp(), raw);
    }

    #[test]
    fn parse_tcp_active_with_tcptype() {
        let raw = "candidate:3 1 tcp 1518280447 192.0.2.1 9 typ host tcptype active";
        let c: Candidate = raw.parse().unwrap();
        assert_eq!(c.transport_type(), TransportType::TcpActive);
        assert_eq!(c.tcp_type(), Some("active"));
        assert_eq!(c.to_sdp(), raw);
    }

    #[test]
    fn parse_tcp_passive_with_tcptype() {
        let raw = "candidate:4 1 TCP 2128609279 10.0.0.1 8888 typ host tcptype passive";
        let c: Candidate = raw.parse().unwrap();
        assert_eq!(c.transport_type(), TransportType::TcpPassive);
        assert_eq!(c.to_sdp(), raw);
    }

    #[test]
    fn parse_tcp_so_with_tcptype() {
        let raw = "candidate:5 1 TCP 2128609279 10.0.0.1 9000 typ host tcptype so";
        let c: Candidate = raw.parse().unwrap();
        assert_eq!(c.transport_type(), TransportType::TcpSo);
        assert_eq!(c.to_sdp(), raw);
    }

    #[test]
    fn parse_tcp_without_tcptype_falls_back_to_unknown() {
        // C++ behaviour: TCP transport with no `tcptype` is still parsed but
        // typed as TcpUnknown.
        let raw = "candidate:6 1 TCP 2128609279 10.0.0.1 8888 typ host";
        let c: Candidate = raw.parse().unwrap();
        assert_eq!(c.transport_type(), TransportType::TcpUnknown);
        assert_eq!(c.to_sdp(), raw);
    }

    #[test]
    fn parse_accepts_candidate_prefix() {
        let raw = "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host";
        // Both with and without are accepted; SDP value re-emits with the prefix.
        let with: Candidate = raw.parse().unwrap();
        let without: Candidate = "1 1 UDP 2113937151 192.168.1.10 56789 typ host"
            .parse()
            .unwrap();
        assert_eq!(with.to_sdp(), raw);
        assert_eq!(without.to_sdp(), raw);
    }

    #[test]
    fn parse_accepts_a_equals_prefix() {
        let raw = "a=candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host";
        let c: Candidate = raw.parse().unwrap();
        // SDP value (without the `a=`) round-trips.
        assert_eq!(c.to_sdp(), &raw[2..]);
        // Display adds the `a=` back.
        assert_eq!(c.to_string(), raw);
    }

    #[test]
    fn parse_double_roundtrip_is_identity() {
        let raw = "candidate:842163049 1 udp 1677729535 192.0.2.1 50000 typ srflx raddr 198.51.100.1 rport 5000 generation 0 ufrag foo network-id 1";
        let c1: Candidate = raw.parse().unwrap();
        let s1 = c1.to_sdp();
        let c2: Candidate = s1.parse().unwrap();
        assert_eq!(c2.to_sdp(), s1);
        assert_eq!(s1, raw);
    }

    #[test]
    fn parse_rejects_too_few_fields() {
        let raw = "candidate:1 1 UDP 2113937151 192.168.1.10";
        let err = raw.parse::<Candidate>().unwrap_err();
        assert_eq!(err, ParseError::MissingField("port"));
    }

    #[test]
    fn parse_rejects_bad_integer() {
        let raw = "candidate:1 abc UDP 2113937151 192.168.1.10 56789 typ host";
        assert_eq!(
            raw.parse::<Candidate>().unwrap_err(),
            ParseError::BadInteger("component")
        );
    }

    #[test]
    fn parse_rejects_missing_typ_marker() {
        let raw = "candidate:1 1 UDP 2113937151 192.168.1.10 56789 host foo";
        assert_eq!(
            raw.parse::<Candidate>().unwrap_err(),
            ParseError::MissingTypMarker
        );
    }

    #[test]
    fn parse_unknown_type_keeps_token_but_classifies_unknown() {
        // The C++ parser doesn't reject unknown type tokens; it stores them
        // verbatim in mTypeString with mType=Unknown so they round-trip.
        let raw = "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ bogus";
        let c: Candidate = raw.parse().unwrap();
        assert_eq!(c.candidate_type(), CandidateType::Unknown);
        assert_eq!(c.to_sdp(), raw);
    }

    #[test]
    fn mid_default_is_zero_string() {
        let c: Candidate = "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host"
            .parse()
            .unwrap();
        assert_eq!(c.mid(), "0");
        assert!(!c.has_mid());
    }

    #[test]
    fn mid_preserved_and_not_in_sdp() {
        let raw = "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host";
        let c = Candidate::parse(raw, "audio").unwrap();
        assert_eq!(c.mid(), "audio");
        assert!(c.has_mid());
        // mid is metadata; the SDP value doesn't contain it.
        let sdp = c.to_sdp();
        assert_eq!(sdp, raw);
        assert!(!sdp.contains("audio"));
    }

    #[test]
    fn hint_mid_only_sets_when_empty() {
        let mut c = Candidate::parse(
            "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host",
            "video",
        )
        .unwrap();
        c.hint_mid("audio");
        assert_eq!(
            c.mid(),
            "video",
            "hint_mid must not overwrite an existing mid"
        );

        let mut d: Candidate = "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host"
            .parse()
            .unwrap();
        d.hint_mid("audio");
        assert_eq!(d.mid(), "audio");
    }

    #[test]
    fn ip_literal_short_circuits_resolution() {
        let c: Candidate = "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host"
            .parse()
            .unwrap();
        assert!(c.is_resolved());
        assert_eq!(c.family(), Family::Ipv4);
        assert_eq!(c.resolved(), Some("192.168.1.10:56789".parse().unwrap()));
    }

    #[test]
    fn hostname_candidate_stays_unresolved() {
        let raw = "candidate:1 1 UDP 2113937151 stun.example.com 56789 typ host";
        let c: Candidate = raw.parse().unwrap();
        assert!(!c.is_resolved());
        assert_eq!(c.family(), Family::Unresolved);
        assert_eq!(c.address(), None);
        assert_eq!(c.port(), None);
        // SDP round-trips with the hostname form (no resolved address).
        assert_eq!(c.to_sdp(), raw);
    }

    #[test]
    fn equality_matches_cpp_semantics() {
        // C++ Candidate::operator== compares (foundation, node, service).
        let a: Candidate = "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host"
            .parse()
            .unwrap();
        let b: Candidate = "candidate:1 1 UDP 9999 192.168.1.10 56789 typ host"
            .parse()
            .unwrap();
        let c: Candidate = "candidate:2 1 UDP 2113937151 192.168.1.10 56789 typ host"
            .parse()
            .unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn display_prefixes_a_equals() {
        let c: Candidate = "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host"
            .parse()
            .unwrap();
        assert_eq!(
            c.to_string(),
            "a=candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host"
        );
    }

    #[test]
    fn default_candidate_matches_cpp_defaults() {
        let c = Candidate::new();
        assert_eq!(c.foundation(), "none");
        assert_eq!(c.component(), 0);
        assert_eq!(c.priority(), 0);
        assert_eq!(c.candidate_type(), CandidateType::Unknown);
        assert_eq!(c.transport_type(), TransportType::Unknown);
        assert!(!c.is_resolved());
        assert_eq!(c.family(), Family::Unresolved);
        assert_eq!(c.mid(), "0");
    }
}
