//! SDP `Description`, mirroring `rtc::Description` from libdatachannel C++.
//!
//! This is a **partial** port for Phase G-2. We model session-level fields
//! and the `Application` (data-channel) media section in full. Media sections
//! with other types (`audio`, `video`, ...) are accepted by the parser but
//! preserved verbatim — their lines are stashed in [`Description::other_sections`]
//! so that parse → serialize round-trips cleanly. Full Audio/Video/Media
//! modelling lands with Task #19.
//!
//! The offer/answer state machine itself lives in `PeerConnection` (Task #17);
//! `Description` is a passive data type.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::candidate::{Candidate, ParseError as CandidateParseError};
use crate::track::{RtpMap, SsrcEntry};

// --- session-level enums -----------------------------------------------------

/// SDP session type. Mirrors `rtc::Description::Type`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    /// Unspecified / not yet set.
    Unspec,
    /// `offer`.
    Offer,
    /// `answer`.
    Answer,
    /// `pranswer` (provisional answer).
    Pranswer,
    /// `rollback`.
    Rollback,
}

impl Type {
    /// Lower-case token used by the WebRTC API and by libdatachannel's
    /// `typeToString`.
    pub fn as_str(self) -> &'static str {
        match self {
            Type::Unspec => "unspec",
            Type::Offer => "offer",
            Type::Answer => "answer",
            Type::Pranswer => "pranswer",
            Type::Rollback => "rollback",
        }
    }

    /// Parse a type string. Matches `Description::stringToType`. Unknown
    /// strings (including the empty string) fall back to `Unspec`.
    pub fn from_string(s: &str) -> Self {
        match s {
            "offer" => Type::Offer,
            "answer" => Type::Answer,
            "pranswer" => Type::Pranswer,
            "rollback" => Type::Rollback,
            _ => Type::Unspec,
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// DTLS role for `a=setup`. Mirrors `rtc::Description::Role`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Role {
    /// `actpass` — default; either side may take the active role.
    ActPass,
    /// `passive`.
    Passive,
    /// `active`.
    Active,
}

impl Role {
    /// SDP token for `a=setup:`. Matches the C++ `operator<<` for `Role`
    /// (used directly for SDP generation, do not change).
    pub fn as_sdp(self) -> &'static str {
        match self {
            Role::Active => "active",
            Role::Passive => "passive",
            Role::ActPass => "actpass",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sdp())
    }
}

/// Media direction (`a=sendrecv`, etc.). Mirrors `rtc::Description::Direction`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Direction {
    /// `unknown` / not set.
    Unknown,
    /// `sendonly`.
    SendOnly,
    /// `recvonly`.
    RecvOnly,
    /// `sendrecv`.
    SendRecv,
    /// `inactive`.
    Inactive,
}

impl Direction {
    /// SDP attribute name. Matches the C++ `operator<<` for `Direction`.
    pub fn as_sdp(self) -> &'static str {
        match self {
            Direction::RecvOnly => "recvonly",
            Direction::SendOnly => "sendonly",
            Direction::SendRecv => "sendrecv",
            Direction::Inactive => "inactive",
            Direction::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sdp())
    }
}

// --- fingerprint -------------------------------------------------------------

/// Hash algorithm for a DTLS certificate fingerprint. Mirrors
/// `rtc::CertificateFingerprint::Algorithm`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum FingerprintAlgorithm {
    /// SHA-1 (20 bytes).
    Sha1,
    /// SHA-224 (28 bytes).
    Sha224,
    /// SHA-256 (32 bytes).
    Sha256,
    /// SHA-384 (48 bytes).
    Sha384,
    /// SHA-512 (64 bytes).
    Sha512,
}

impl FingerprintAlgorithm {
    /// SDP identifier (`sha-256`, etc.). Matches `AlgorithmIdentifier`.
    pub fn as_sdp(self) -> &'static str {
        match self {
            FingerprintAlgorithm::Sha1 => "sha-1",
            FingerprintAlgorithm::Sha224 => "sha-224",
            FingerprintAlgorithm::Sha256 => "sha-256",
            FingerprintAlgorithm::Sha384 => "sha-384",
            FingerprintAlgorithm::Sha512 => "sha-512",
        }
    }

    /// Byte length of the raw hash. Matches `AlgorithmSize`.
    pub fn size(self) -> usize {
        match self {
            FingerprintAlgorithm::Sha1 => 20,
            FingerprintAlgorithm::Sha224 => 28,
            FingerprintAlgorithm::Sha256 => 32,
            FingerprintAlgorithm::Sha384 => 48,
            FingerprintAlgorithm::Sha512 => 64,
        }
    }

    fn from_sdp(s: &str) -> Option<Self> {
        match s {
            "sha-1" => Some(FingerprintAlgorithm::Sha1),
            "sha-224" => Some(FingerprintAlgorithm::Sha224),
            "sha-256" => Some(FingerprintAlgorithm::Sha256),
            "sha-384" => Some(FingerprintAlgorithm::Sha384),
            "sha-512" => Some(FingerprintAlgorithm::Sha512),
            _ => None,
        }
    }
}

impl fmt::Display for FingerprintAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sdp())
    }
}

/// Certificate fingerprint as it appears on `a=fingerprint:` lines. Mirrors
/// `rtc::CertificateFingerprint`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    /// Hash algorithm.
    pub algorithm: FingerprintAlgorithm,
    /// Colon-separated upper-case hex, e.g. `"AB:CD:EF:..."`. The C++ setter
    /// upper-cases the value; we do the same in [`Description::set_fingerprint`].
    pub value: String,
}

impl Fingerprint {
    /// Validate format: hex bytes separated by `:`, length matches algorithm.
    /// Matches `CertificateFingerprint::isValid`.
    pub fn is_valid(&self) -> bool {
        let expected = self.algorithm.size();
        if expected == 0 || self.value.len() != expected * 3 - 1 {
            return false;
        }
        for (i, ch) in self.value.bytes().enumerate() {
            if i % 3 == 2 {
                if ch != b':' {
                    return false;
                }
            } else if !ch.is_ascii_hexdigit() {
                return false;
            }
        }
        true
    }
}

// --- Application media section ----------------------------------------------

/// One `m=application ...` media section (the data-channel m-line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Application {
    mid: String,
    sctp_port: Option<u16>,
    max_message_size: Option<usize>,
    // Other per-media attributes we don't model individually. Preserved
    // verbatim (without the leading `a=`) so round-tripping doesn't lose data.
    extra_attrs: Vec<String>,
    direction: Direction,
}

impl Application {
    /// New Application with the given `mid`. Defaults match C++:
    /// `Direction::SendRecv`, no `sctp-port`, no `max-message-size`.
    pub fn new(mid: impl Into<String>) -> Self {
        Application {
            mid: mid.into(),
            sctp_port: None,
            max_message_size: None,
            extra_attrs: Vec::new(),
            direction: Direction::SendRecv,
        }
    }

    /// `a=mid:` value.
    pub fn mid(&self) -> &str {
        &self.mid
    }

    /// Override the `mid`.
    pub fn set_mid(&mut self, mid: impl Into<String>) {
        self.mid = mid.into();
    }

    /// `a=sctp-port:` value.
    pub fn sctp_port(&self) -> Option<u16> {
        self.sctp_port
    }

    /// Set `a=sctp-port:`.
    pub fn set_sctp_port(&mut self, port: u16) {
        self.sctp_port = Some(port);
    }

    /// `a=max-message-size:` value.
    pub fn max_message_size(&self) -> Option<usize> {
        self.max_message_size
    }

    /// Set `a=max-message-size:`.
    pub fn set_max_message_size(&mut self, size: usize) {
        self.max_message_size = Some(size);
    }

    /// Direction (`a=sendrecv` etc.). Defaults to [`Direction::SendRecv`].
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Set the direction.
    pub fn set_direction(&mut self, dir: Direction) {
        self.direction = dir;
    }

    /// Preserved attributes that the parser didn't recognise as a known
    /// Application key. Each entry is the attribute body (without `a=`).
    pub fn extra_attrs(&self) -> &[String] {
        &self.extra_attrs
    }
}

// --- audio / video media section --------------------------------------------

/// A modeled `m=audio` / `m=video` media section. Mirrors the subset of
/// `rtc::Description::Media` that the offer/answer + Track integration needs:
/// the media kind, mid, direction, the advertised payload types / rtpmaps
/// (reusing track.rs's [`RtpMap`]) and SSRC bindings ([`SsrcEntry`]).
///
/// Promoting these from raw-line passthrough means the [`Description`] now
/// understands media m-lines: it can be queried by [`PeerConnection::add_track`]
/// (to advertise a local track) and inspected when a remote offer/answer
/// arrives (to fire `on_track`). Per-media ICE credentials and the DTLS
/// fingerprint come from the session-level fields, matching the BUNDLE'd SDP
/// libdatachannel emits (a single ICE transport for all m-lines).
///
/// [`PeerConnection::add_track`]: crate::PeerConnection::add_track
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaSection {
    kind: String,
    mid: String,
    direction: Direction,
    rtp_maps: Vec<RtpMap>,
    ssrcs: Vec<SsrcEntry>,
    /// Per-media attributes we don't model individually (without the leading
    /// `a=`). Round-tripped verbatim so we don't lose attributes such as
    /// `extmap`, `rtcp-fb`, `ssrc-group`, etc.
    extra_attrs: Vec<String>,
}

impl MediaSection {
    /// Build a media section from its components.
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        mid: impl Into<String>,
        direction: Direction,
        rtp_maps: Vec<RtpMap>,
        ssrcs: Vec<SsrcEntry>,
    ) -> Self {
        MediaSection {
            kind: kind.into(),
            mid: mid.into(),
            direction,
            rtp_maps,
            ssrcs,
            extra_attrs: Vec::new(),
        }
    }

    /// Build a media section from a track's [`crate::TrackMedia`] description.
    #[must_use]
    pub fn from_track_media(media: &crate::TrackMedia) -> Self {
        MediaSection {
            kind: media.kind().to_string(),
            mid: media.mid().to_string(),
            direction: media.direction(),
            rtp_maps: media.rtp_maps().to_vec(),
            ssrcs: media.ssrcs().to_vec(),
            extra_attrs: Vec::new(),
        }
    }

    /// Media kind (`"audio"` / `"video"`).
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// `a=mid:` value.
    #[must_use]
    pub fn mid(&self) -> &str {
        &self.mid
    }

    /// Override the mid.
    pub fn set_mid(&mut self, mid: impl Into<String>) {
        self.mid = mid.into();
    }

    /// Media direction.
    #[must_use]
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Set the direction.
    pub fn set_direction(&mut self, dir: Direction) {
        self.direction = dir;
    }

    /// Advertised rtpmaps.
    #[must_use]
    pub fn rtp_maps(&self) -> &[RtpMap] {
        &self.rtp_maps
    }

    /// SSRC bindings.
    #[must_use]
    pub fn ssrcs(&self) -> &[SsrcEntry] {
        &self.ssrcs
    }

    /// Whether this media section advertises the given payload type.
    #[must_use]
    pub fn has_payload_type(&self, pt: u8) -> bool {
        self.rtp_maps.iter().any(|m| m.payload_type == pt)
    }

    /// True for `m=video`.
    #[must_use]
    pub fn is_video(&self) -> bool {
        self.kind == "video"
    }
}

// --- description -------------------------------------------------------------

/// Errors returned when parsing an SDP blob.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DescriptionParseError {
    /// The SDP didn't have a `v=` version line where one is expected.
    #[error("missing or malformed v= line")]
    MissingVersion,
    /// A media line (`m=`) was malformed.
    #[error("invalid m= line: {0}")]
    InvalidMedia(String),
    /// An attribute that needed an integer value couldn't be parsed.
    #[error("bad integer in attribute `{0}`")]
    BadInteger(&'static str),
    /// A `candidate:` attribute didn't parse.
    #[error("bad candidate: {0}")]
    BadCandidate(#[from] CandidateParseError),
}

/// A parsed (or freshly built) SDP description.
///
/// For Phase G-2 we expose session-level fields and a single optional
/// `Application` media section. Other media sections (`m=audio`, `m=video`)
/// are accepted and preserved verbatim so SDPs round-trip without loss.
#[derive(Debug, Clone)]
pub struct Description {
    typ: Type,
    role: Role,
    username: String,
    session_id: String,
    session_version: String,
    bundle_mids: Vec<String>,
    ice_ufrag: Option<String>,
    ice_pwd: Option<String>,
    ice_options: Vec<String>,
    fingerprint: Option<Fingerprint>,
    extmap_allow_mixed: bool,
    /// Session-level `a=` lines we don't model individually (without `a=`).
    extra_attrs: Vec<String>,

    application: Option<Application>,

    /// Modeled `m=audio` / `m=video` sections in declaration order.
    media_sections: Vec<MediaSection>,

    /// Verbatim text of media sections whose type we don't model
    /// (anything other than `application`, `audio`, `video`). Each entry begins
    /// with the `m=` line and contains every subsequent line up to (not
    /// including) the next `m=` line, terminated by `\r\n`. Round-tripped to
    /// `to_sdp`.
    other_sections: Vec<String>,

    candidates: Vec<Candidate>,
    ended: bool,
}

impl Description {
    /// Empty description. Defaults to:
    /// - `username = "rtc"`
    /// - random `session_id`
    /// - `session_version = "0"`
    /// - the supplied `typ` and `role`
    pub fn new(typ: Type, role: Role) -> Self {
        Description {
            typ,
            role,
            username: "rtc".to_string(),
            session_id: random_session_id(),
            session_version: "0".to_string(),
            bundle_mids: Vec::new(),
            ice_ufrag: None,
            ice_pwd: None,
            ice_options: Vec::new(),
            fingerprint: None,
            extmap_allow_mixed: false,
            extra_attrs: Vec::new(),
            application: None,
            media_sections: Vec::new(),
            other_sections: Vec::new(),
            candidates: Vec::new(),
            ended: false,
        }
    }

    /// Parse an SDP blob. The parser mirrors `Description::Description(const
    /// string &sdp, ...)`.
    pub fn parse(sdp: &str) -> Result<Self, DescriptionParseError> {
        let mut d = Description::new(Type::Unspec, Role::ActPass);
        parse_into(&mut d, sdp)?;
        Ok(d)
    }

    // -- session-level getters ------------------------------------------------

    /// Session type (`offer`, `answer`, ...).
    pub fn type_(&self) -> Type {
        self.typ
    }

    /// Lower-case type string (`"offer"`, etc.). Matches `typeString()`.
    pub fn type_string(&self) -> &'static str {
        self.typ.as_str()
    }

    /// Promote `Unspec` to the given type, matching `hintType`.
    pub fn hint_type(&mut self, typ: Type) {
        if self.typ == Type::Unspec {
            self.typ = typ;
        }
    }

    /// DTLS role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Override the DTLS role.
    pub fn set_role(&mut self, role: Role) {
        self.role = role;
    }

    /// ICE ufrag (session-level, falling back to media-level when only the
    /// media-level was supplied — same as the C++ store).
    pub fn ice_ufrag(&self) -> &str {
        self.ice_ufrag.as_deref().unwrap_or("")
    }

    /// ICE pwd.
    pub fn ice_pwd(&self) -> &str {
        self.ice_pwd.as_deref().unwrap_or("")
    }

    /// Set the ICE ufrag.
    pub fn set_ice_ufrag(&mut self, ufrag: impl Into<String>) {
        self.ice_ufrag = Some(ufrag.into());
    }

    /// Set the ICE pwd.
    pub fn set_ice_pwd(&mut self, pwd: impl Into<String>) {
        self.ice_pwd = Some(pwd.into());
    }

    /// Set both ICE attributes at once. Matches `setIceAttribute`.
    pub fn set_ice_attribute(&mut self, ufrag: impl Into<String>, pwd: impl Into<String>) {
        self.ice_ufrag = Some(ufrag.into());
        self.ice_pwd = Some(pwd.into());
    }

    /// `a=ice-options:` tokens.
    pub fn ice_options(&self) -> &[String] {
        &self.ice_options
    }

    /// Add an ICE option if not already present.
    pub fn add_ice_option(&mut self, option: impl Into<String>) {
        let o = option.into();
        if !self.ice_options.iter().any(|x| x == &o) {
            self.ice_options.push(o);
        }
    }

    /// Certificate fingerprint.
    pub fn fingerprint(&self) -> Option<&Fingerprint> {
        self.fingerprint.as_ref()
    }

    /// Set the fingerprint. Upper-cases the hex value to match the C++ setter.
    pub fn set_fingerprint(&mut self, mut fp: Fingerprint) {
        fp.value = fp.value.to_ascii_uppercase();
        self.fingerprint = Some(fp);
    }

    /// `a=extmap-allow-mixed` session-level flag.
    pub fn extmap_allow_mixed(&self) -> bool {
        self.extmap_allow_mixed
    }

    /// Set the `a=extmap-allow-mixed` flag.
    pub fn set_extmap_allow_mixed(&mut self, on: bool) {
        self.extmap_allow_mixed = on;
    }

    /// BUNDLE mids in declaration order. Empty when no `a=group:BUNDLE` was
    /// emitted (and no media sections are present).
    pub fn bundle_mids(&self) -> &[String] {
        &self.bundle_mids
    }

    /// First non-removed media's mid, or `"0"` if no media is present.
    /// Matches `bundleMid()`.
    pub fn bundle_mid(&self) -> String {
        if let Some(app) = &self.application {
            return app.mid().to_string();
        }
        if let Some(first) = self.bundle_mids.first() {
            return first.clone();
        }
        "0".to_string()
    }

    /// Origin username (the first token on `o=`). Defaults to `"rtc"`.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Session-id, the second token on `o=`. Random by default.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Session-version, the third token on `o=`. Defaults to `"0"`.
    pub fn session_version(&self) -> &str {
        &self.session_version
    }

    // -- application ----------------------------------------------------------

    /// Borrow the application m-section if present.
    pub fn application(&self) -> Option<&Application> {
        self.application.as_ref()
    }

    /// Mutably borrow the application m-section.
    pub fn application_mut(&mut self) -> Option<&mut Application> {
        self.application.as_mut()
    }

    /// Replace the application m-section, updating `bundle_mids` so the new
    /// mid is included.
    pub fn set_application(&mut self, app: Application) {
        // Remove the old application's mid from bundle_mids if present.
        if let Some(old) = &self.application {
            self.bundle_mids.retain(|m| m != old.mid());
        }
        let mid = app.mid().to_string();
        if !self.bundle_mids.iter().any(|m| m == &mid) {
            self.bundle_mids.insert(0, mid);
        }
        self.application = Some(app);
    }

    /// Get the application by mid, creating it if missing. Mirrors the C++
    /// pattern of `if (!app) addApplication(mid)` ​then `application()`.
    pub fn application_or_create(&mut self, mid: &str) -> &mut Application {
        if self.application.is_none() {
            self.set_application(Application::new(mid));
        }
        self.application.as_mut().unwrap()
    }

    /// True if an application m-section exists.
    pub fn has_application(&self) -> bool {
        self.application.is_some()
    }

    // -- media sections (audio / video) ---------------------------------------

    /// All modeled `m=audio` / `m=video` sections in declaration order.
    pub fn media_sections(&self) -> &[MediaSection] {
        &self.media_sections
    }

    /// True if at least one modeled media (audio/video) section exists.
    pub fn has_media(&self) -> bool {
        !self.media_sections.is_empty()
    }

    /// Borrow the media section with the given mid, if present.
    pub fn media_by_mid(&self, mid: &str) -> Option<&MediaSection> {
        self.media_sections.iter().find(|m| m.mid() == mid)
    }

    /// Add a media (audio/video) section, recording its mid in `bundle_mids`
    /// so it joins the BUNDLE group. If a section with the same mid already
    /// exists it is replaced.
    pub fn add_media(&mut self, media: MediaSection) {
        let mid = media.mid().to_string();
        if let Some(existing) = self.media_sections.iter_mut().find(|m| m.mid() == mid) {
            *existing = media;
            return;
        }
        if !self.bundle_mids.iter().any(|m| m == &mid) {
            self.bundle_mids.push(mid);
        }
        self.media_sections.push(media);
    }

    // -- candidates -----------------------------------------------------------

    /// All trickled candidates.
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// Add a candidate, hinting its mid to `bundle_mid()` if it doesn't have
    /// one. Mirrors `Description::addCandidate` byte-for-byte: hint always
    /// runs but the underlying `Candidate::hint_mid` is a no-op when mid is
    /// already set.
    pub fn add_candidate(&mut self, mut c: Candidate) {
        let default_mid = self.bundle_mid();
        c.hint_mid(default_mid);
        if !self.candidates.iter().any(|existing| existing == &c) {
            self.candidates.push(c);
        }
    }

    /// Mark `a=end-of-candidates`. Mirrors `endCandidates`.
    pub fn end_candidates(&mut self) {
        self.ended = true;
    }

    /// True if `a=end-of-candidates` has been signalled (set by either
    /// [`Description::end_candidates`] or by the parser).
    pub fn end_of_candidates(&self) -> bool {
        self.ended
    }

    // -- serialization --------------------------------------------------------

    /// Serialize to canonical SDP with CRLF line endings.
    pub fn to_sdp(&self) -> String {
        self.generate_sdp("\r\n")
    }

    /// Serialize with a configurable end-of-line.
    pub fn generate_sdp(&self, eol: &str) -> String {
        let mut out = String::with_capacity(512);

        // Header
        out.push_str("v=0");
        out.push_str(eol);
        out.push_str("o=");
        out.push_str(&self.username);
        out.push(' ');
        out.push_str(&self.session_id);
        out.push(' ');
        out.push_str(&self.session_version);
        out.push_str(" IN IP4 127.0.0.1");
        out.push_str(eol);
        out.push_str("s=-");
        out.push_str(eol);
        out.push_str("t=0 0");
        out.push_str(eol);

        // BUNDLE group
        if !self.bundle_mids.is_empty() {
            out.push_str("a=group:BUNDLE");
            for mid in &self.bundle_mids {
                out.push(' ');
                out.push_str(mid);
            }
            out.push_str(eol);
        }

        // Session-level attrs (libdatachannel always emits msid-semantic)
        out.push_str("a=msid-semantic:WMS *");
        out.push_str(eol);

        if !self.ice_options.is_empty() {
            out.push_str("a=ice-options:");
            for (i, opt) in self.ice_options.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(opt);
            }
            out.push_str(eol);
        }

        if self.extmap_allow_mixed {
            out.push_str("a=extmap-allow-mixed");
            out.push_str(eol);
        }

        // Session-level fingerprint (libdatachannel emits it at session level
        // when it's set; media-level fingerprint is also emitted further down
        // for compatibility with the C++ generator.)
        if let Some(fp) = &self.fingerprint {
            out.push_str("a=fingerprint:");
            out.push_str(fp.algorithm.as_sdp());
            out.push(' ');
            out.push_str(&fp.value);
            out.push_str(eol);
        }

        for attr in &self.extra_attrs {
            out.push_str("a=");
            out.push_str(attr);
            out.push_str(eol);
        }

        // Application m-section (data channel).
        if let Some(app) = &self.application {
            self.write_application(&mut out, app, eol);
        }

        // Modeled audio / video media sections.
        for media in &self.media_sections {
            self.write_media(&mut out, media, eol);
        }

        // Verbatim media sections we don't model (unknown m-line types).
        for section in &self.other_sections {
            out.push_str(section);
        }

        out
    }

    /// Serialize a modeled `m=audio`/`m=video` section. The per-media ICE
    /// credentials, setup role and DTLS fingerprint mirror the BUNDLE'd SDP
    /// libdatachannel emits — they come from the session-level fields (a single
    /// ICE/DTLS transport backs every BUNDLE'd m-line).
    fn write_media(&self, out: &mut String, media: &MediaSection, eol: &str) {
        let pts: Vec<String> = media
            .rtp_maps
            .iter()
            .map(|m| m.payload_type.to_string())
            .collect();
        out.push_str(&format!(
            "m={} 9 UDP/TLS/RTP/SAVPF {}",
            media.kind,
            pts.join(" ")
        ));
        out.push_str(eol);
        out.push_str("c=IN IP4 0.0.0.0");
        out.push_str(eol);
        out.push_str("a=mid:");
        out.push_str(&media.mid);
        out.push_str(eol);
        if media.direction != Direction::Unknown {
            out.push_str("a=");
            out.push_str(media.direction.as_sdp());
            out.push_str(eol);
        }
        out.push_str("a=rtcp-mux");
        out.push_str(eol);
        out.push_str("a=setup:");
        out.push_str(self.role.as_sdp());
        out.push_str(eol);
        if let Some(u) = &self.ice_ufrag {
            out.push_str("a=ice-ufrag:");
            out.push_str(u);
            out.push_str(eol);
        }
        if let Some(p) = &self.ice_pwd {
            out.push_str("a=ice-pwd:");
            out.push_str(p);
            out.push_str(eol);
        }
        if let Some(fp) = &self.fingerprint {
            out.push_str("a=fingerprint:");
            out.push_str(fp.algorithm.as_sdp());
            out.push(' ');
            out.push_str(&fp.value);
            out.push_str(eol);
        }
        for m in &media.rtp_maps {
            match &m.enc_params {
                Some(params) => out.push_str(&format!(
                    "a=rtpmap:{} {}/{}/{}",
                    m.payload_type, m.format, m.clock_rate, params
                )),
                None => out.push_str(&format!(
                    "a=rtpmap:{} {}/{}",
                    m.payload_type, m.format, m.clock_rate
                )),
            }
            out.push_str(eol);
            for fmtp in &m.fmtps {
                out.push_str(&format!("a=fmtp:{} {}", m.payload_type, fmtp));
                out.push_str(eol);
            }
        }
        for s in &media.ssrcs {
            if let Some(name) = &s.name {
                out.push_str(&format!("a=ssrc:{} cname:{}", s.ssrc, name));
                out.push_str(eol);
            }
            if let (Some(msid), Some(track_id)) = (&s.msid, &s.track_id) {
                out.push_str(&format!("a=ssrc:{} msid:{} {}", s.ssrc, msid, track_id));
                out.push_str(eol);
            }
        }
        for attr in &media.extra_attrs {
            out.push_str("a=");
            out.push_str(attr);
            out.push_str(eol);
        }
        // Candidates attached to this section's mid.
        for c in &self.candidates {
            if c.mid() == media.mid {
                out.push_str("a=");
                out.push_str(&c.to_sdp());
                out.push_str(eol);
            }
        }
    }

    fn write_application(&self, out: &mut String, app: &Application, eol: &str) {
        out.push_str("m=application 9 UDP/DTLS/SCTP webrtc-datachannel");
        out.push_str(eol);
        out.push_str("c=IN IP4 0.0.0.0");
        out.push_str(eol);
        out.push_str("a=mid:");
        out.push_str(app.mid());
        out.push_str(eol);
        if app.direction != Direction::Unknown {
            out.push_str("a=");
            out.push_str(app.direction.as_sdp());
            out.push_str(eol);
        }
        // Media-level setup/ice (RFC 8829: prefer media-level even when
        // identical to session-level).
        out.push_str("a=setup:");
        out.push_str(self.role.as_sdp());
        out.push_str(eol);
        if let Some(u) = &self.ice_ufrag {
            out.push_str("a=ice-ufrag:");
            out.push_str(u);
            out.push_str(eol);
        }
        if let Some(p) = &self.ice_pwd {
            out.push_str("a=ice-pwd:");
            out.push_str(p);
            out.push_str(eol);
        }
        if let Some(fp) = &self.fingerprint {
            out.push_str("a=fingerprint:");
            out.push_str(fp.algorithm.as_sdp());
            out.push(' ');
            out.push_str(&fp.value);
            out.push_str(eol);
        }
        if let Some(port) = app.sctp_port {
            out.push_str("a=sctp-port:");
            out.push_str(&port.to_string());
            out.push_str(eol);
        }
        if let Some(size) = app.max_message_size {
            out.push_str("a=max-message-size:");
            out.push_str(&size.to_string());
            out.push_str(eol);
        }
        for attr in &app.extra_attrs {
            out.push_str("a=");
            out.push_str(attr);
            out.push_str(eol);
        }
        // Candidates matching this section.
        for c in &self.candidates {
            if c.mid() == app.mid() {
                out.push_str("a=");
                out.push_str(&c.to_sdp());
                out.push_str(eol);
            }
        }
        if self.ended {
            out.push_str("a=end-of-candidates");
            out.push_str(eol);
        }
    }
}

impl FromStr for Description {
    type Err = DescriptionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Description::parse(s)
    }
}

impl fmt::Display for Description {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_sdp())
    }
}

// --- parser ------------------------------------------------------------------

/// What kind of media section the parser is currently accumulating.
enum SectionKind {
    Application,
    /// Modeled audio/video section.
    Media,
    /// Verbatim section for unmodeled m-line types.
    Other,
}

fn parse_into(d: &mut Description, sdp: &str) -> Result<(), DescriptionParseError> {
    // Section state. `current_kind` tracks what we're appending to.
    let mut current_kind: Option<SectionKind> = None;
    let mut current_app: Option<Application> = None;
    let mut current_media: Option<MediaSection> = None;
    let mut current_other = String::new();
    let mut other_mid: Option<String> = None;
    let mut section_index: i32 = -1;

    for raw in sdp.lines() {
        // Strip trailing CR (we already split on \n; lines() does that for us).
        let line = raw.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("m=") {
            // Flush whatever we were accumulating.
            flush_section(
                d,
                &mut current_kind,
                &mut current_app,
                &mut current_media,
                &mut current_other,
                &mut other_mid,
            );
            section_index += 1;
            // Parse the media type (first token).
            let mtype = rest.split_ascii_whitespace().next().unwrap_or("");
            if mtype == "application" {
                current_kind = Some(SectionKind::Application);
                // Default mid is the section index (overridden by a=mid:).
                current_app = Some(Application::new(section_index.to_string()));
            } else if mtype == "audio" || mtype == "video" {
                current_kind = Some(SectionKind::Media);
                // Default mid is the section index (overridden by a=mid:); the
                // rtpmap/ssrc lines populate the rest. Default direction is
                // SendRecv until an explicit a=<dir> line says otherwise.
                current_media = Some(MediaSection::new(
                    mtype,
                    section_index.to_string(),
                    Direction::SendRecv,
                    Vec::new(),
                    Vec::new(),
                ));
            } else {
                current_kind = Some(SectionKind::Other);
                current_other.clear();
                current_other.push_str(line);
                current_other.push_str("\r\n");
                other_mid = None;
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("o=") {
            let mut it = rest.split_ascii_whitespace();
            if let Some(u) = it.next() {
                d.username = u.to_string();
            }
            if let Some(sid) = it.next() {
                d.session_id = sid.to_string();
            }
            if let Some(sver) = it.next() {
                d.session_version = sver.to_string();
            }
            continue;
        }

        if let Some(attr) = line.strip_prefix("a=") {
            // If we're inside an "other" section, copy verbatim and also
            // capture mid so candidates can match.
            if matches!(current_kind, Some(SectionKind::Other)) {
                if let Some(val) = attr.strip_prefix("mid:") {
                    other_mid = Some(val.trim().to_string());
                }
                current_other.push_str(line);
                current_other.push_str("\r\n");
                continue;
            }

            let (key, value) = parse_pair(attr);

            // Session-level keys we recognise regardless of position.
            match key {
                "group" => {
                    // a=group:BUNDLE 0 1 2
                    if let Some(rest) = value.strip_prefix("BUNDLE") {
                        d.bundle_mids = rest
                            .split_ascii_whitespace()
                            .map(|s| s.to_string())
                            .collect();
                    }
                    continue;
                }
                "extmap-allow-mixed" => {
                    d.extmap_allow_mixed = true;
                    continue;
                }
                "ice-options" => {
                    // Session-level only stored if we don't have one yet
                    // (matches the C++ parser).
                    if d.ice_options.is_empty() {
                        d.ice_options = value.split(',').map(|s| s.trim().to_string()).collect();
                    }
                    continue;
                }
                "fingerprint" => {
                    if d.fingerprint.is_none() || section_index == 0 {
                        let mut parts = value.split_ascii_whitespace();
                        if let (Some(algo), Some(val)) = (parts.next(), parts.next()) {
                            let lower = algo.to_ascii_lowercase();
                            if let Some(a) = FingerprintAlgorithm::from_sdp(&lower) {
                                d.fingerprint = Some(Fingerprint {
                                    algorithm: a,
                                    value: val.to_ascii_uppercase(),
                                });
                            }
                        }
                    }
                    continue;
                }
                "ice-ufrag" => {
                    if d.ice_ufrag.is_none() || section_index == 0 {
                        d.ice_ufrag = Some(value.to_string());
                    }
                    continue;
                }
                "ice-pwd" => {
                    if d.ice_pwd.is_none() || section_index == 0 {
                        d.ice_pwd = Some(value.to_string());
                    }
                    continue;
                }
                "setup" => {
                    d.role = match value {
                        "active" => Role::Active,
                        "passive" => Role::Passive,
                        _ => Role::ActPass,
                    };
                    continue;
                }
                "candidate" => {
                    let default_mid = if let Some(app) = &current_app {
                        app.mid().to_string()
                    } else if let Some(m) = &current_media {
                        m.mid().to_string()
                    } else if let Some(m) = &other_mid {
                        m.clone()
                    } else if let Some(first) = d.bundle_mids.first() {
                        first.clone()
                    } else {
                        section_index.max(0).to_string()
                    };
                    let cand = Candidate::parse(attr, &default_mid)?;
                    if !d.candidates.iter().any(|existing| existing == &cand) {
                        d.candidates.push(cand);
                    }
                    continue;
                }
                "end-of-candidates" => {
                    d.ended = true;
                    continue;
                }
                // Always regenerated by the serializer — drop here so a
                // parse → emit → parse → emit cycle doesn't duplicate it.
                "msid-semantic" => continue,
                _ => {}
            }

            // Per-media application attributes.
            if let Some(app) = current_app.as_mut() {
                match key {
                    "mid" => {
                        app.set_mid(value);
                        continue;
                    }
                    "sctp-port" => {
                        let v: u16 = value
                            .parse()
                            .map_err(|_| DescriptionParseError::BadInteger("sctp-port"))?;
                        app.set_sctp_port(v);
                        continue;
                    }
                    "max-message-size" => {
                        let v: usize = value
                            .parse()
                            .map_err(|_| DescriptionParseError::BadInteger("max-message-size"))?;
                        app.set_max_message_size(v);
                        continue;
                    }
                    "sendonly" => {
                        app.set_direction(Direction::SendOnly);
                        continue;
                    }
                    "recvonly" => {
                        app.set_direction(Direction::RecvOnly);
                        continue;
                    }
                    "sendrecv" => {
                        app.set_direction(Direction::SendRecv);
                        continue;
                    }
                    "inactive" => {
                        app.set_direction(Direction::Inactive);
                        continue;
                    }
                    _ => {
                        // Preserve unknown attributes verbatim.
                        app.extra_attrs.push(attr.to_string());
                        continue;
                    }
                }
            }

            // Per-media (audio/video) attributes.
            if let Some(media) = current_media.as_mut() {
                match key {
                    "mid" => {
                        media.set_mid(value.trim());
                        continue;
                    }
                    "sendonly" => {
                        media.set_direction(Direction::SendOnly);
                        continue;
                    }
                    "recvonly" => {
                        media.set_direction(Direction::RecvOnly);
                        continue;
                    }
                    "sendrecv" => {
                        media.set_direction(Direction::SendRecv);
                        continue;
                    }
                    "inactive" => {
                        media.set_direction(Direction::Inactive);
                        continue;
                    }
                    "rtcp-mux" => continue, // implied; regenerated by serializer
                    "rtpmap" => {
                        if let Some(rm) = parse_rtpmap(value) {
                            media.rtp_maps.push(rm);
                        }
                        continue;
                    }
                    "fmtp" => {
                        // a=fmtp:<pt> <params>
                        let mut it = value.splitn(2, ' ');
                        if let (Some(pt_str), Some(params)) = (it.next(), it.next()) {
                            if let Ok(pt) = pt_str.parse::<u8>() {
                                if let Some(rm) =
                                    media.rtp_maps.iter_mut().find(|m| m.payload_type == pt)
                                {
                                    rm.fmtps.push(params.to_string());
                                    continue;
                                }
                            }
                        }
                        media.extra_attrs.push(attr.to_string());
                        continue;
                    }
                    "ssrc" => {
                        parse_ssrc_into(&mut media.ssrcs, value);
                        continue;
                    }
                    _ => {
                        // Preserve unknown per-media attributes verbatim.
                        media.extra_attrs.push(attr.to_string());
                        continue;
                    }
                }
            }

            // Session-level fallback for unknown attributes.
            d.extra_attrs.push(attr.to_string());
            continue;
        }

        // Inside "other" section, capture every other line type too (c=, b=, ...).
        if matches!(current_kind, Some(SectionKind::Other)) {
            current_other.push_str(line);
            current_other.push_str("\r\n");
        }
        // Otherwise: silently drop unrecognised top-level lines (v=, s=, t=,
        // c= at session level). We regenerate these in `to_sdp`.
    }

    flush_section(
        d,
        &mut current_kind,
        &mut current_app,
        &mut current_media,
        &mut current_other,
        &mut other_mid,
    );

    Ok(())
}

fn flush_section(
    d: &mut Description,
    kind: &mut Option<SectionKind>,
    app: &mut Option<Application>,
    media: &mut Option<MediaSection>,
    other: &mut String,
    other_mid: &mut Option<String>,
) {
    match kind.take() {
        Some(SectionKind::Application) => {
            if let Some(a) = app.take() {
                let mid = a.mid().to_string();
                d.application = Some(a);
                if !d.bundle_mids.iter().any(|m| m == &mid) {
                    d.bundle_mids.push(mid);
                }
            }
        }
        Some(SectionKind::Media) => {
            if let Some(m) = media.take() {
                let mid = m.mid().to_string();
                d.media_sections.push(m);
                if !d.bundle_mids.iter().any(|x| x == &mid) {
                    d.bundle_mids.push(mid);
                }
            }
        }
        Some(SectionKind::Other) => {
            if !other.is_empty() {
                d.other_sections.push(std::mem::take(other));
            }
            if let Some(mid) = other_mid.take() {
                if !d.bundle_mids.iter().any(|m| m == &mid) {
                    d.bundle_mids.push(mid);
                }
            }
        }
        None => {}
    }
}

/// Split `key:value` (matches the C++ `parse_pair`). Returns `(key, "")` if
/// no `:` is present.
fn parse_pair(attr: &str) -> (&str, &str) {
    match attr.find(':') {
        Some(i) => (&attr[..i], &attr[i + 1..]),
        None => (attr, ""),
    }
}

/// Parse an `a=rtpmap:` value `<pt> <name>/<rate>[/<params>]` into an
/// [`RtpMap`]. Returns `None` if the payload type doesn't parse.
fn parse_rtpmap(value: &str) -> Option<RtpMap> {
    let mut it = value.splitn(2, ' ');
    let pt: u8 = it.next()?.trim().parse().ok()?;
    let codec = it.next()?.trim();
    let mut parts = codec.split('/');
    let format = parts.next()?.to_string();
    let clock_rate: u32 = parts.next()?.trim().parse().ok()?;
    let enc_params = parts.next().map(|s| s.trim().to_string());
    Some(RtpMap {
        payload_type: pt,
        format,
        clock_rate,
        enc_params,
        fmtps: Vec::new(),
    })
}

/// Parse an `a=ssrc:` value into / merging onto the section's SSRC list.
/// Handles `<ssrc> cname:<name>` and `<ssrc> msid:<msid> <trackId>`, folding
/// multiple lines for the same SSRC into one [`SsrcEntry`].
fn parse_ssrc_into(ssrcs: &mut Vec<SsrcEntry>, value: &str) {
    let mut it = value.splitn(2, ' ');
    let ssrc: u32 = match it.next().and_then(|s| s.trim().parse().ok()) {
        Some(v) => v,
        None => return,
    };
    let rest = it.next().unwrap_or("").trim();
    let entry = match ssrcs.iter_mut().find(|e| e.ssrc == ssrc) {
        Some(e) => e,
        None => {
            ssrcs.push(SsrcEntry {
                ssrc,
                name: None,
                msid: None,
                track_id: None,
            });
            ssrcs.last_mut().unwrap()
        }
    };
    if let Some(cname) = rest.strip_prefix("cname:") {
        entry.name = Some(cname.trim().to_string());
    } else if let Some(msid) = rest.strip_prefix("msid:") {
        let mut m = msid.split_ascii_whitespace();
        entry.msid = m.next().map(|s| s.to_string());
        entry.track_id = m.next().map(|s| s.to_string());
    }
}

/// Random session-id matching the C++ fallback (a 32-bit unsigned value).
fn random_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // We don't need cryptographic randomness here — the C++ code uses
    // `uniform_int_distribution<uint32_t>` seeded by `random_engine()`.
    // A nanosecond timestamp gives us a perfectly fine session-id without
    // pulling in a new dep.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
        .unwrap_or(0);
    let v = (nanos as u32) ^ 0x9E37_79B1;
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A canonical libdatachannel-style data-channel offer.
    const OFFER_SDP: &str = "v=0\r\n\
o=rtc 3767197920 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
a=msid-semantic:WMS *\r\n\
a=ice-options:trickle\r\n\
a=fingerprint:sha-256 0F:74:31:25:CB:A2:13:EC:28:6F:6D:2C:61:FF:5D:C2:BC:B9:DB:3D:98:14:8D:1A:BB:EA:33:0C:A4:60:A8:8E\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
a=sendrecv\r\n\
a=setup:actpass\r\n\
a=ice-ufrag:ufrag\r\n\
a=ice-pwd:password1234567890123456\r\n\
a=fingerprint:sha-256 0F:74:31:25:CB:A2:13:EC:28:6F:6D:2C:61:FF:5D:C2:BC:B9:DB:3D:98:14:8D:1A:BB:EA:33:0C:A4:60:A8:8E\r\n\
a=sctp-port:5000\r\n\
a=max-message-size:262144\r\n";

    #[test]
    fn parse_offer_basic_fields() {
        let d = Description::parse(OFFER_SDP).unwrap();
        assert_eq!(d.role(), Role::ActPass);
        assert_eq!(d.ice_ufrag(), "ufrag");
        assert_eq!(d.ice_pwd(), "password1234567890123456");
        assert_eq!(d.bundle_mids(), &["0".to_string()]);
        assert_eq!(d.username(), "rtc");
        assert_eq!(d.session_id(), "3767197920");
        let app = d.application().expect("application present");
        assert_eq!(app.mid(), "0");
        assert_eq!(app.sctp_port(), Some(5000));
        assert_eq!(app.max_message_size(), Some(262144));
        let fp = d.fingerprint().expect("fingerprint present");
        assert_eq!(fp.algorithm, FingerprintAlgorithm::Sha256);
        // Value is upper-cased on store.
        assert!(fp.value.starts_with("0F:74:31"));
    }

    #[test]
    fn parse_offer_roundtrip_idempotent() {
        // Parse → serialize → parse → serialize, the second pass should equal
        // the first pass (canonical form).
        let d1 = Description::parse(OFFER_SDP).unwrap();
        let sdp1 = d1.to_sdp();
        let d2 = Description::parse(&sdp1).unwrap();
        let sdp2 = d2.to_sdp();
        assert_eq!(sdp1, sdp2, "second roundtrip differs from first");
        // Key tokens survived.
        assert!(sdp1.contains("m=application 9 UDP/DTLS/SCTP webrtc-datachannel"));
        assert!(sdp1.contains("a=mid:0"));
        assert!(sdp1.contains("a=sctp-port:5000"));
        assert!(sdp1.contains("a=max-message-size:262144"));
        assert!(sdp1.contains("a=setup:actpass"));
    }

    #[test]
    fn parse_answer_role_active() {
        let sdp = OFFER_SDP.replace("a=setup:actpass", "a=setup:active");
        let d = Description::parse(&sdp).unwrap();
        assert_eq!(d.role(), Role::Active);
    }

    #[test]
    fn builder_offer_emits_expected_attrs() {
        let mut d = Description::new(Type::Offer, Role::ActPass);
        d.set_ice_ufrag("abcd");
        d.set_ice_pwd("0123456789ABCDEF0123");
        d.set_fingerprint(Fingerprint {
            algorithm: FingerprintAlgorithm::Sha256,
            // dummy hex; the upper-caser doesn't validate.
            value: "ab:cd:ef:01".to_string(),
        });
        let mut app = Application::new("0");
        app.set_sctp_port(5000);
        app.set_max_message_size(262144);
        d.set_application(app);

        let sdp = d.to_sdp();
        assert!(sdp.starts_with("v=0\r\n"));
        assert!(sdp.contains("a=group:BUNDLE 0\r\n"));
        assert!(sdp.contains("a=msid-semantic:WMS *\r\n"));
        assert!(sdp.contains("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"));
        assert!(sdp.contains("a=mid:0\r\n"));
        assert!(sdp.contains("a=setup:actpass\r\n"));
        assert!(sdp.contains("a=ice-ufrag:abcd\r\n"));
        assert!(sdp.contains("a=ice-pwd:0123456789ABCDEF0123\r\n"));
        // Fingerprint value upper-cased on set.
        assert!(sdp.contains("a=fingerprint:sha-256 AB:CD:EF:01\r\n"));
        assert!(sdp.contains("a=sctp-port:5000\r\n"));
        assert!(sdp.contains("a=max-message-size:262144\r\n"));
        assert_eq!(d.type_(), Type::Offer);
    }

    #[test]
    fn add_candidate_hints_mid_when_missing() {
        let mut d = Description::new(Type::Offer, Role::ActPass);
        d.set_application(Application::new("0"));
        let c: Candidate = "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host"
            .parse()
            .unwrap();
        assert!(!c.has_mid());
        d.add_candidate(c);
        assert_eq!(d.candidates().len(), 1);
        assert_eq!(d.candidates()[0].mid(), "0");
        assert!(d.candidates()[0].has_mid());
    }

    #[test]
    fn add_candidate_preserves_explicit_mid() {
        let mut d = Description::new(Type::Offer, Role::ActPass);
        d.set_application(Application::new("0"));
        let c = Candidate::parse(
            "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host",
            "2",
        )
        .unwrap();
        d.add_candidate(c);
        assert_eq!(d.candidates()[0].mid(), "2");
    }

    #[test]
    fn bundle_mids_parsed() {
        let sdp = "v=0\r\n\
o=rtc 1 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0 1 2\r\n\
a=msid-semantic:WMS *\r\n";
        let d = Description::parse(sdp).unwrap();
        assert_eq!(
            d.bundle_mids(),
            &["0".to_string(), "1".to_string(), "2".to_string()]
        );
    }

    #[test]
    fn fingerprint_parsed() {
        let d = Description::parse(OFFER_SDP).unwrap();
        let fp = d.fingerprint().expect("present");
        assert_eq!(fp.algorithm, FingerprintAlgorithm::Sha256);
        assert_eq!(
            fp.value,
            "0F:74:31:25:CB:A2:13:EC:28:6F:6D:2C:61:FF:5D:C2:BC:B9:DB:3D:98:14:8D:1A:BB:EA:33:0C:A4:60:A8:8E"
        );
    }

    #[test]
    fn fingerprint_validates_sha256() {
        // 32 bytes -> 32*3 - 1 = 95 chars
        let fp = Fingerprint {
            algorithm: FingerprintAlgorithm::Sha256,
            value: "0F:74:31:25:CB:A2:13:EC:28:6F:6D:2C:61:FF:5D:C2:BC:B9:DB:3D:98:14:8D:1A:BB:EA:33:0C:A4:60:A8:8E".to_string(),
        };
        assert!(fp.is_valid());

        let bad = Fingerprint {
            algorithm: FingerprintAlgorithm::Sha256,
            value: "DEADBEEF".to_string(),
        };
        assert!(!bad.is_valid());
    }

    #[test]
    fn ice_options_trickle_parsed() {
        let d = Description::parse(OFFER_SDP).unwrap();
        assert_eq!(d.ice_options(), &["trickle".to_string()]);
    }

    #[test]
    fn role_actpass_default_on_new() {
        let d = Description::new(Type::Offer, Role::ActPass);
        assert_eq!(d.role(), Role::ActPass);
    }

    #[test]
    fn audio_media_section_modeled_and_round_trips() {
        // libwebrtc-style fragment that includes audio. Audio/video m-lines are
        // now MODELED (not raw passthrough): the parser produces a
        // `MediaSection` and the serializer regenerates a canonical form that
        // preserves the codec, mid, direction, rtpmap and fmtp.
        let sdp = "v=0\r\n\
o=rtc 42 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0 audio\r\n\
a=msid-semantic:WMS *\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
a=setup:actpass\r\n\
a=ice-ufrag:abcd\r\n\
a=ice-pwd:passphraselongenoughforice\r\n\
a=sctp-port:5000\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:audio\r\n\
a=sendrecv\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=fmtp:111 minptime=10;useinbandfec=1\r\n";
        let d = Description::parse(sdp).unwrap();
        assert!(d.application().is_some());
        // bundle mids should pick up both the application and the audio section.
        assert!(d.bundle_mids().contains(&"audio".to_string()));

        // The audio section is modeled.
        assert!(d.has_media());
        let m = d.media_by_mid("audio").expect("audio section modeled");
        assert_eq!(m.kind(), "audio");
        assert_eq!(m.direction(), Direction::SendRecv);
        assert_eq!(m.rtp_maps().len(), 1);
        assert_eq!(m.rtp_maps()[0].payload_type, 111);
        assert_eq!(m.rtp_maps()[0].format, "opus");
        assert_eq!(m.rtp_maps()[0].clock_rate, 48000);
        assert_eq!(m.rtp_maps()[0].enc_params.as_deref(), Some("2"));
        assert_eq!(
            m.rtp_maps()[0].fmtps,
            vec!["minptime=10;useinbandfec=1".to_string()]
        );

        let out = d.to_sdp();
        // The audio block regenerates canonically.
        assert!(
            out.contains("m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"),
            "audio m= missing in output"
        );
        assert!(out.contains("a=mid:audio\r\n"));
        assert!(out.contains("a=rtpmap:111 opus/48000/2\r\n"));
        assert!(out.contains("a=fmtp:111 minptime=10;useinbandfec=1\r\n"));

        // And it survives a second parse→serialize (idempotent canonical form).
        let d2 = Description::parse(&out).unwrap();
        assert_eq!(d2.to_sdp(), out);
    }

    #[test]
    fn add_video_media_section_emits_modeled_sdp() {
        use crate::track::{Codec, RtpMap, SsrcEntry};
        let mut d = Description::new(Type::Offer, Role::ActPass);
        d.set_ice_ufrag("u");
        d.set_ice_pwd("ppppppppppppppppppppppp");
        d.set_fingerprint(Fingerprint {
            algorithm: FingerprintAlgorithm::Sha256,
            value: "ab:cd".to_string(),
        });
        let rtp = RtpMap {
            payload_type: 96,
            format: Codec::H264.rtpmap_name().to_string(),
            clock_rate: 90000,
            enc_params: None,
            fmtps: vec!["profile-level-id=42e01f".to_string()],
        };
        let ssrc = SsrcEntry {
            ssrc: 0x1234,
            name: Some("cam".to_string()),
            msid: None,
            track_id: None,
        };
        d.add_media(MediaSection::new(
            "video",
            "video0",
            Direction::SendRecv,
            vec![rtp],
            vec![ssrc],
        ));
        let out = d.to_sdp();
        assert!(out.contains("a=group:BUNDLE video0\r\n") || out.contains(" video0"));
        assert!(out.contains("m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"));
        assert!(out.contains("a=mid:video0\r\n"));
        assert!(out.contains("a=sendrecv\r\n"));
        assert!(out.contains("a=rtcp-mux\r\n"));
        assert!(out.contains("a=setup:actpass\r\n"));
        assert!(out.contains("a=ice-ufrag:u\r\n"));
        assert!(out.contains("a=rtpmap:96 H264/90000\r\n"));
        assert!(out.contains("a=fmtp:96 profile-level-id=42e01f\r\n"));
        assert!(out.contains("a=ssrc:4660 cname:cam\r\n"));
    }

    #[test]
    fn end_of_candidates_roundtrip() {
        let sdp = "v=0\r\n\
o=rtc 1 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
a=msid-semantic:WMS *\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
a=setup:actpass\r\n\
a=sctp-port:5000\r\n\
a=candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host\r\n\
a=end-of-candidates\r\n";
        let d = Description::parse(sdp).unwrap();
        assert_eq!(d.candidates().len(), 1);
        assert!(d.end_of_candidates());
        let out = d.to_sdp();
        assert!(out.contains("a=candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host\r\n"));
        assert!(out.contains("a=end-of-candidates\r\n"));
    }

    #[test]
    fn application_or_create_inserts_default() {
        let mut d = Description::new(Type::Offer, Role::ActPass);
        assert!(d.application().is_none());
        let app = d.application_or_create("data");
        assert_eq!(app.mid(), "data");
        // Subsequent calls don't replace it.
        let again = d.application_or_create("other");
        assert_eq!(again.mid(), "data");
    }

    #[test]
    fn bad_sdp_does_not_panic() {
        // Random gibberish. We currently accept any input as best-effort
        // (matching the C++ parser, which silently drops malformed lines).
        let res = Description::parse("not an sdp\nnothing here\n");
        // It returns Ok with mostly-default fields.
        assert!(res.is_ok());
        let d = res.unwrap();
        assert!(d.application().is_none());
    }

    #[test]
    fn bad_sctp_port_returns_error() {
        let sdp = "v=0\r\n\
o=rtc 1 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
a=mid:0\r\n\
a=sctp-port:not-a-port\r\n";
        let err = Description::parse(sdp).unwrap_err();
        assert_eq!(err, DescriptionParseError::BadInteger("sctp-port"));
    }

    #[test]
    fn fromstr_trait_works() {
        let d: Description = OFFER_SDP.parse().unwrap();
        assert_eq!(d.application().unwrap().mid(), "0");
    }

    #[test]
    fn display_equals_to_sdp() {
        let d = Description::parse(OFFER_SDP).unwrap();
        assert_eq!(d.to_string(), d.to_sdp());
    }

    #[test]
    fn type_round_trip_string() {
        assert_eq!(Type::Offer.as_str(), "offer");
        assert_eq!(Type::from_string("offer"), Type::Offer);
        assert_eq!(Type::from_string("garbage"), Type::Unspec);
        assert_eq!(Type::from_string(""), Type::Unspec);
    }

    #[test]
    fn hint_type_only_promotes_unspec() {
        let mut d = Description::new(Type::Unspec, Role::ActPass);
        d.hint_type(Type::Offer);
        assert_eq!(d.type_(), Type::Offer);
        d.hint_type(Type::Answer);
        assert_eq!(
            d.type_(),
            Type::Offer,
            "hint_type must not overwrite a set type"
        );
    }

    #[test]
    fn extmap_allow_mixed_parsed_and_emitted() {
        let sdp = "v=0\r\n\
o=rtc 1 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=extmap-allow-mixed\r\n\
a=msid-semantic:WMS *\r\n";
        let d = Description::parse(sdp).unwrap();
        assert!(d.extmap_allow_mixed());
        let out = d.to_sdp();
        assert!(out.contains("a=extmap-allow-mixed\r\n"));
    }

    #[test]
    fn candidate_attached_to_application_mid_in_output() {
        // Candidate added without mid → should serialize under the application
        // mid in the output.
        let mut d = Description::new(Type::Offer, Role::ActPass);
        d.set_ice_ufrag("u");
        d.set_ice_pwd("ppppppppppppppppppppppp");
        d.set_application(Application::new("data"));
        let c: Candidate = "candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host"
            .parse()
            .unwrap();
        d.add_candidate(c);
        let out = d.to_sdp();
        // Candidate appears within the application section.
        assert!(out.contains("a=mid:data\r\n"));
        assert!(out.contains("a=candidate:1 1 UDP 2113937151 192.168.1.10 56789 typ host\r\n"));
    }
}
