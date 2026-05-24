//! Media [`Track`] — a native Rust port of `src/track.cpp` + `src/impl/track.cpp`.
//!
//! A `Track` is bound to an SDP media section (`m=audio`/`m=video`). It carries
//! a [`Direction`], a `mid`, codec/payload info, an [`RtpPacketizer`] for the
//! outbound path, and an optional [`SrtpTransport`] it sends protected media
//! through. Inbound SRTP-unprotected RTP is surfaced via [`TrackCallbacks`].
//!
//! This matches the established transport modules' architecture: an `Arc<Self>`
//! with a `parking_lot::Mutex<Inner>` for mutable state, closure-style callbacks
//! (`TrackCallbacks { on_open, on_message, on_closed, on_frame }`) snapshotted
//! under the lock before firing, and a public surface modelled on the reference
//! `datachannel-rs` `track.rs` (a [`Codec`] enum, [`TrackInit`], [`Direction`]
//! reused from `description.rs`, and `send`/`mid`/`direction`/`description`).
//!
//! Reconciliation with `description.rs`: this module **reuses** the existing
//! [`crate::Direction`] (re-exported from `description.rs`) rather than defining
//! a second one, and builds its SDP via a focused [`Media`] type here. Full
//! Audio/Video media modelling inside `description.rs`'s parser is a separate
//! follow-up; the `Media` here is sufficient for a Track's `description()`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use thiserror::Error;

use crate::description::Direction;
use crate::rtp::is_rtcp;
use crate::rtp_packetizer::{RtpPacketizationConfig, RtpPacketizer, VIDEO_CLOCK_RATE};
use crate::srtp_transport::SrtpTransport;

/// Media codec for a track. Mirrors the reference `Codec` enum, extended with
/// H265 and AV1 (which libdatachannel supports natively).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Codec {
    /// H.264 video.
    H264,
    /// H.265 / HEVC video.
    H265,
    /// VP8 video.
    Vp8,
    /// VP9 video.
    Vp9,
    /// AV1 video.
    Av1,
    /// Opus audio.
    Opus,
}

impl Codec {
    /// SDP rtpmap format token (the `<encoding name>`), e.g. `"H264"`.
    #[must_use]
    pub fn rtpmap_name(self) -> &'static str {
        match self {
            Codec::H264 => "H264",
            Codec::H265 => "H265",
            Codec::Vp8 => "VP8",
            Codec::Vp9 => "VP9",
            Codec::Av1 => "AV1",
            Codec::Opus => "opus",
        }
    }

    /// Whether this codec rides on an `m=video` (vs `m=audio`) media line.
    #[must_use]
    pub fn is_video(self) -> bool {
        !matches!(self, Codec::Opus)
    }

    /// The SDP media kind string (`"video"` or `"audio"`).
    #[must_use]
    pub fn media_kind(self) -> &'static str {
        if self.is_video() {
            "video"
        } else {
            "audio"
        }
    }

    /// Default RTP clock rate for this codec (Hz). Video is 90 kHz; Opus 48 kHz.
    #[must_use]
    pub fn default_clock_rate(self) -> u32 {
        match self {
            Codec::Opus => 48_000,
            _ => VIDEO_CLOCK_RATE,
        }
    }

    /// rtpmap encoding parameters (the trailing `/<channels>` for audio), if any.
    #[must_use]
    pub fn enc_params(self) -> Option<&'static str> {
        match self {
            Codec::Opus => Some("2"), // opus/48000/2
            _ => None,
        }
    }
}

/// Track initialization parameters. Modelled on the reference `TrackInit`, but
/// using owned `String`s and this crate's [`Direction`]/[`Codec`] types.
#[derive(Debug, Clone)]
pub struct TrackInit {
    /// Media direction.
    pub direction: Direction,
    /// Codec.
    pub codec: Codec,
    /// RTP payload type.
    pub payload_type: u8,
    /// Synchronization source.
    pub ssrc: u32,
    /// Media identification (`a=mid:`).
    pub mid: String,
    /// Track name (used as the SSRC `cname`/label), if any.
    pub name: Option<String>,
    /// Media stream id (`a=msid:`), if any.
    pub msid: Option<String>,
    /// Track id within the msid, if any.
    pub track_id: Option<String>,
    /// Codec profile (e.g. H.264 `profile-level-id=...`), if any.
    pub profile: Option<String>,
}

impl TrackInit {
    /// Convenience constructor with the required fields; optional fields `None`.
    #[must_use]
    pub fn new(
        direction: Direction,
        codec: Codec,
        payload_type: u8,
        ssrc: u32,
        mid: impl Into<String>,
    ) -> Self {
        TrackInit {
            direction,
            codec,
            payload_type,
            ssrc,
            mid: mid.into(),
            name: None,
            msid: None,
            track_id: None,
            profile: None,
        }
    }
}

/// One rtpmap entry on a media section (a `a=rtpmap:<pt> <name>/<rate>[/<params>]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpMap {
    /// Payload type.
    pub payload_type: u8,
    /// Encoding name (e.g. `"H264"`, `"opus"`).
    pub format: String,
    /// Clock rate (Hz).
    pub clock_rate: u32,
    /// Encoding parameters (e.g. channel count), if any.
    pub enc_params: Option<String>,
    /// `a=fmtp:` parameters for this PT (e.g. profile), each without the leading
    /// `fmtp:<pt> `.
    pub fmtps: Vec<String>,
}

/// One SSRC binding on a media section (`a=ssrc:<ssrc> cname:<name>`, optionally
/// with msid). Mirrors what `Description::Media::addSSRC` records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrcEntry {
    /// The SSRC value.
    pub ssrc: u32,
    /// Optional cname / label.
    pub name: Option<String>,
    /// Optional `a=msid:<msid> <trackId>` pair.
    pub msid: Option<String>,
    /// Track id within the msid.
    pub track_id: Option<String>,
}

/// A focused SDP media section for a Track (`m=audio`/`m=video`). This reuses
/// the crate's [`Direction`] and models exactly what a Track needs:
/// direction, mid, payload types / rtpmaps, and SSRC bindings. It is the seam
/// the future PeerConnection `add_track` integration emits into the full SDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Media {
    kind: String,
    mid: String,
    direction: Direction,
    rtp_maps: Vec<RtpMap>,
    ssrcs: Vec<SsrcEntry>,
}

impl Media {
    /// Build the media section described by a [`TrackInit`].
    #[must_use]
    pub fn from_init(init: &TrackInit) -> Self {
        let mut fmtps = Vec::new();
        if let Some(profile) = &init.profile {
            fmtps.push(profile.clone());
        }
        let rtp_map = RtpMap {
            payload_type: init.payload_type,
            format: init.codec.rtpmap_name().to_string(),
            clock_rate: init.codec.default_clock_rate(),
            enc_params: init.codec.enc_params().map(str::to_string),
            fmtps,
        };
        let ssrc = SsrcEntry {
            ssrc: init.ssrc,
            name: init.name.clone(),
            msid: init.msid.clone(),
            track_id: init.track_id.clone(),
        };
        Media {
            kind: init.codec.media_kind().to_string(),
            mid: init.mid.clone(),
            direction: init.direction,
            rtp_maps: vec![rtp_map],
            ssrcs: vec![ssrc],
        }
    }

    /// `a=mid:` value.
    #[must_use]
    pub fn mid(&self) -> &str {
        &self.mid
    }

    /// Media kind (`"audio"` / `"video"`).
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Media direction.
    #[must_use]
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// rtpmap entries.
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

    /// Render the media section as SDP lines (used by `Track::description`).
    /// Mirrors the relevant `Description::Media::generateSdpLines` output for
    /// the subset a Track needs.
    #[must_use]
    pub fn to_sdp(&self) -> String {
        let mut out = String::new();
        let pts: Vec<String> = self
            .rtp_maps
            .iter()
            .map(|m| m.payload_type.to_string())
            .collect();
        out.push_str(&format!(
            "m={} 9 UDP/TLS/RTP/SAVPF {}\r\n",
            self.kind,
            pts.join(" ")
        ));
        out.push_str("c=IN IP4 0.0.0.0\r\n");
        out.push_str(&format!("a=mid:{}\r\n", self.mid));
        out.push_str(&format!("a={}\r\n", self.direction.as_sdp()));
        out.push_str("a=rtcp-mux\r\n");
        for m in &self.rtp_maps {
            match &m.enc_params {
                Some(p) => out.push_str(&format!(
                    "a=rtpmap:{} {}/{}/{}\r\n",
                    m.payload_type, m.format, m.clock_rate, p
                )),
                None => out.push_str(&format!(
                    "a=rtpmap:{} {}/{}\r\n",
                    m.payload_type, m.format, m.clock_rate
                )),
            }
            for fmtp in &m.fmtps {
                out.push_str(&format!("a=fmtp:{} {}\r\n", m.payload_type, fmtp));
            }
        }
        for s in &self.ssrcs {
            if let Some(name) = &s.name {
                out.push_str(&format!("a=ssrc:{} cname:{}\r\n", s.ssrc, name));
            }
            if let (Some(msid), Some(track_id)) = (&s.msid, &s.track_id) {
                out.push_str(&format!("a=ssrc:{} msid:{} {}\r\n", s.ssrc, msid, track_id));
            }
        }
        out
    }
}

/// Errors returned by [`Track`] operations.
#[derive(Debug, Error)]
pub enum TrackError {
    /// The track is closed.
    #[error("track is closed")]
    Closed,
    /// A send was attempted in a direction the track doesn't permit
    /// (e.g. media on a `recvonly` track).
    #[error("media sent in invalid direction")]
    BadDirection,
    /// No SRTP transport has been bound (the track is not open yet).
    #[error("track is not open (no SRTP transport)")]
    NotOpen,
    /// The SRTP transport rejected the packet.
    #[error("srtp transport: {0}")]
    Srtp(#[from] crate::SrtpTransportError),
}

/// Callbacks the [`Track`] invokes. Closure-style, matching the transport
/// modules (NOT the reference's `TrackHandler` trait).
#[derive(Clone)]
pub struct TrackCallbacks {
    /// Fires once the track is opened (an SRTP transport was bound).
    pub on_open: Arc<dyn Fn() + Send + Sync>,
    /// Fires for each inbound RTP/RTCP message after SRTP unprotection. The
    /// bytes are the cleartext RTP (or RTCP) packet.
    pub on_message: Arc<dyn Fn(&[u8]) + Send + Sync>,
    /// Fires for each inbound media frame's RTP payload (header stripped),
    /// alongside its RTP timestamp and payload type. This is the depacketized
    /// view; the codec-specific reassembly is task #20.
    pub on_frame: Arc<dyn Fn(&[u8], u32, u8) + Send + Sync>,
    /// Fires when the track is closed.
    pub on_closed: Arc<dyn Fn() + Send + Sync>,
}

impl Default for TrackCallbacks {
    fn default() -> Self {
        TrackCallbacks {
            on_open: Arc::new(|| {}),
            on_message: Arc::new(|_| {}),
            on_frame: Arc::new(|_, _, _| {}),
            on_closed: Arc::new(|| {}),
        }
    }
}

struct Inner {
    media: Media,
    srtp: Option<Arc<SrtpTransport>>,
}

/// A media track bound to an SDP media section. Cheap to share via `Arc<Self>`.
pub struct Track {
    inner: Mutex<Inner>,
    callbacks: Mutex<TrackCallbacks>,
    packetizer: RtpPacketizer,
    direction: Direction,
    open: AtomicBool,
    closed: AtomicBool,
}

impl std::fmt::Debug for Track {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Track")
            .field("mid", &self.mid())
            .field("direction", &self.direction)
            .field("open", &self.open.load(Ordering::SeqCst))
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .finish()
    }
}

impl Track {
    /// Create a standalone track from a [`TrackInit`] and callbacks. The track
    /// starts **not open**; bind an [`SrtpTransport`] with
    /// [`open`](Self::open) (the PeerConnection does this once DTLS-SRTP is
    /// connected). The packetizer is seeded with a random sequence number /
    /// timestamp per RFC 3550.
    #[must_use]
    pub fn new(init: TrackInit, callbacks: TrackCallbacks) -> Arc<Self> {
        let media = Media::from_init(&init);
        let cname = init.name.clone().unwrap_or_else(|| init.mid.clone());
        let config = RtpPacketizationConfig::new_random(
            init.ssrc,
            cname,
            init.payload_type,
            init.codec.default_clock_rate(),
        );
        Arc::new(Track {
            inner: Mutex::new(Inner { media, srtp: None }),
            callbacks: Mutex::new(callbacks),
            packetizer: RtpPacketizer::new(config),
            direction: init.direction,
            open: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        })
    }

    /// Bind an SRTP transport, opening the track. Mirrors `impl::Track::open`.
    /// Fires `on_open`. Idempotent for an already-open track (re-binds the
    /// transport but only fires `on_open` once).
    pub fn open(&self, srtp: Arc<SrtpTransport>) {
        {
            let mut g = self.inner.lock();
            g.srtp = Some(srtp);
        }
        if !self.closed.load(Ordering::SeqCst) && !self.open.swap(true, Ordering::SeqCst) {
            let cb = self.callbacks.lock().on_open.clone();
            (cb)();
        }
    }

    /// True if the track is open (an SRTP transport is bound and it is not closed).
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::SeqCst) && !self.closed.load(Ordering::SeqCst)
    }

    /// True if the track has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// The track's `mid`.
    #[must_use]
    pub fn mid(&self) -> String {
        self.inner.lock().media.mid().to_string()
    }

    /// The track's direction.
    #[must_use]
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// A clone of the track's media [`Media`] description.
    #[must_use]
    pub fn description(&self) -> Media {
        self.inner.lock().media.clone()
    }

    /// The SDP text of the track's media section.
    #[must_use]
    pub fn description_sdp(&self) -> String {
        self.inner.lock().media.to_sdp()
    }

    /// Replace the media description. The `mid` must match, mirroring
    /// `impl::Track::setDescription`.
    pub fn set_description(&self, media: Media) -> Result<(), TrackError> {
        let mut g = self.inner.lock();
        if media.mid() != g.media.mid() {
            return Err(TrackError::BadDirection); // mid mismatch — reuse closest error
        }
        g.media = media;
        Ok(())
    }

    /// Send a **media payload** by packetizing it into RTP and protecting it
    /// through the bound SRTP transport. Returns the number of RTP packets sent.
    ///
    /// This is the outbound path: payload → [`RtpPacketizer::outgoing`] →
    /// `protect_rtp` → the transport. The generic packetizer emits a single
    /// packet (marker set); codec packetizers (#20) fragment first.
    pub fn send(&self, payload: &[u8]) -> Result<usize, TrackError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(TrackError::Closed);
        }
        if matches!(self.direction, Direction::RecvOnly | Direction::Inactive) {
            return Err(TrackError::BadDirection);
        }
        let srtp = self
            .inner
            .lock()
            .srtp
            .clone()
            .ok_or(TrackError::NotOpen)?;

        let packets = self.packetizer.outgoing(payload.to_vec());
        let n = packets.len();
        for pkt in packets {
            srtp.send_media(pkt)?;
        }
        Ok(n)
    }

    /// Send a pre-formed RTP **or RTCP** packet as-is (no packetization),
    /// protecting it through the bound SRTP transport. RTCP is permitted in any
    /// direction (it is control), mirroring `impl::Track::outgoing`'s handling
    /// of `IsRtcp`.
    pub fn send_rtp(&self, packet: &[u8]) -> Result<(), TrackError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(TrackError::Closed);
        }
        let is_control = is_rtcp(packet);
        if !is_control && matches!(self.direction, Direction::RecvOnly | Direction::Inactive) {
            return Err(TrackError::BadDirection);
        }
        let srtp = self
            .inner
            .lock()
            .srtp
            .clone()
            .ok_or(TrackError::NotOpen)?;
        srtp.send_media(packet.to_vec())?;
        Ok(())
    }

    /// Deliver an inbound (already SRTP-unprotected) RTP/RTCP packet to this
    /// track. Fires `on_message` with the raw packet and, for media RTP,
    /// `on_frame` with the depacketized payload. Mirrors `impl::Track::incoming`
    /// (minus the media-handler chain, which is #20/#21). Drops media on a
    /// send-only / inactive track.
    pub fn incoming(&self, packet: &[u8]) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let control = is_rtcp(packet);
        if !control
            && matches!(self.direction, Direction::SendOnly | Direction::Inactive)
        {
            return; // bad direction for media
        }

        let (on_message, on_frame) = {
            let g = self.callbacks.lock();
            (g.on_message.clone(), g.on_frame.clone())
        };
        (on_message)(packet);

        if !control {
            let depacketizer =
                crate::rtp_packetizer::RtpDepacketizer::new(self.packetizer.config().clock_rate);
            if let Some(frame) = depacketizer.depacketize(packet) {
                (on_frame)(&frame.payload, frame.timestamp, frame.payload_type);
            }
        }
    }

    /// Swap the callback set at runtime.
    pub fn set_callbacks(&self, callbacks: TrackCallbacks) {
        *self.callbacks.lock() = callbacks;
    }

    /// Close the track. Idempotent. Fires `on_closed` once.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.open.store(false, Ordering::SeqCst);
        {
            let mut g = self.inner.lock();
            g.srtp = None;
        }
        let cb = self.callbacks.lock().on_closed.clone();
        (cb)();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::RtpHeader;

    fn video_init() -> TrackInit {
        let mut init = TrackInit::new(Direction::SendRecv, Codec::H264, 96, 0x0BAD_F00D, "video0");
        init.name = Some("camera".into());
        init.profile = Some("profile-level-id=42e01f;packetization-mode=1".into());
        init
    }

    #[test]
    fn media_from_init_describes_video() {
        let media = Media::from_init(&video_init());
        assert_eq!(media.kind(), "video");
        assert_eq!(media.mid(), "video0");
        assert_eq!(media.direction(), Direction::SendRecv);
        assert!(media.has_payload_type(96));
        let sdp = media.to_sdp();
        assert!(sdp.contains("m=video 9 UDP/TLS/RTP/SAVPF 96"));
        assert!(sdp.contains("a=mid:video0"));
        assert!(sdp.contains("a=sendrecv"));
        assert!(sdp.contains("a=rtpmap:96 H264/90000"));
        assert!(sdp.contains("a=fmtp:96 profile-level-id=42e01f"));
        assert!(sdp.contains("a=ssrc:195948557 cname:camera"));
    }

    #[test]
    fn opus_audio_media_has_channels() {
        let init = TrackInit::new(Direction::SendOnly, Codec::Opus, 111, 42, "audio0");
        let media = Media::from_init(&init);
        assert_eq!(media.kind(), "audio");
        let sdp = media.to_sdp();
        assert!(sdp.contains("m=audio 9 UDP/TLS/RTP/SAVPF 111"));
        assert!(sdp.contains("a=rtpmap:111 opus/48000/2"));
        assert!(sdp.contains("a=sendonly"));
    }

    #[test]
    fn track_accessors_and_lifecycle() {
        let track = Track::new(video_init(), TrackCallbacks::default());
        assert_eq!(track.mid(), "video0");
        assert_eq!(track.direction(), Direction::SendRecv);
        assert!(!track.is_open());
        assert!(!track.is_closed());
        assert_eq!(track.description().mid(), "video0");

        track.close();
        assert!(track.is_closed());
        assert!(!track.is_open());
        // Idempotent.
        track.close();
    }

    #[test]
    fn send_before_open_fails_not_open() {
        let track = Track::new(video_init(), TrackCallbacks::default());
        let err = track.send(b"payload").unwrap_err();
        assert!(matches!(err, TrackError::NotOpen));
    }

    #[test]
    fn send_on_recvonly_is_bad_direction() {
        let init = TrackInit::new(Direction::RecvOnly, Codec::H264, 96, 1, "v");
        let track = Track::new(init, TrackCallbacks::default());
        let err = track.send(b"x").unwrap_err();
        assert!(matches!(err, TrackError::BadDirection));
    }

    #[test]
    fn incoming_fires_message_and_frame_callbacks() {
        use std::sync::atomic::AtomicUsize;

        let msgs = Arc::new(AtomicUsize::new(0));
        let frames = Arc::new(Mutex::new(Vec::<(Vec<u8>, u32, u8)>::new()));
        let msgs_cb = msgs.clone();
        let frames_cb = frames.clone();
        let cbs = TrackCallbacks {
            on_message: Arc::new(move |_| {
                msgs_cb.fetch_add(1, Ordering::SeqCst);
            }),
            on_frame: Arc::new(move |p, ts, pt| {
                frames_cb.lock().push((p.to_vec(), ts, pt));
            }),
            ..TrackCallbacks::default()
        };
        let track = Track::new(video_init(), cbs);

        // Build a known RTP packet (PT 96) with a payload.
        let header = RtpHeader {
            version: 2,
            marker: true,
            payload_type: 96,
            sequence_number: 7,
            timestamp: 12345,
            ssrc: 0x0BAD_F00D,
            ..RtpHeader::default()
        };
        let mut pkt = header.serialize();
        pkt.extend_from_slice(b"inbound-frame");

        track.incoming(&pkt);
        assert_eq!(msgs.load(Ordering::SeqCst), 1);
        let f = frames.lock();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, b"inbound-frame");
        assert_eq!(f[0].1, 12345);
        assert_eq!(f[0].2, 96);
    }

    #[test]
    fn incoming_drops_media_on_sendonly() {
        use std::sync::atomic::AtomicUsize;
        let count = Arc::new(AtomicUsize::new(0));
        let count_cb = count.clone();
        let init = TrackInit::new(Direction::SendOnly, Codec::H264, 96, 1, "v");
        let track = Track::new(
            init,
            TrackCallbacks {
                on_message: Arc::new(move |_| {
                    count_cb.fetch_add(1, Ordering::SeqCst);
                }),
                ..TrackCallbacks::default()
            },
        );
        let header = RtpHeader {
            payload_type: 96,
            ssrc: 1,
            ..RtpHeader::default()
        };
        let mut pkt = header.serialize();
        pkt.extend_from_slice(b"x");
        track.incoming(&pkt);
        assert_eq!(count.load(Ordering::SeqCst), 0, "media dropped on sendonly");
    }

    /// Full Track → packetize → SRTP protect → DTLS/ICE → SRTP unprotect →
    /// Track::incoming → on_frame loopback. Models the SRTP loopback test:
    /// two DTLS-SRTP transports handshake over ICE; a sendonly Track on side A
    /// sends a payload, and a recvonly Track on side B surfaces the recovered
    /// payload via its `on_frame` callback. Exercises the whole send path the
    /// PeerConnection will wire in #20+.
    #[test]
    fn track_send_srtp_loopback_to_peer_on_frame() {
        use crate::candidate::Candidate;
        use crate::certificate::Certificate;
        use crate::configuration::Configuration;
        use crate::description::{FingerprintAlgorithm, Role, Type as DescriptionType};
        use crate::dtls_transport::{DtlsTransport, DtlsTransportCallbacks};
        use crate::ice_transport::{
            GatheringState, IceTransport, IceTransportCallbacks,
        };
        use crate::srtp_transport::{SrtpTransportCallbacks};

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
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

            let mut cfg = Configuration::new();
            cfg.bind_address = Some("127.0.0.1".to_string());

            let ice_a = IceTransport::new(
                &cfg,
                Role::ActPass,
                IceTransportCallbacks {
                    on_candidate: Arc::new(move |c| a_cands_cb.lock().push(c)),
                    ..IceTransportCallbacks::default()
                },
            )
            .expect("ice a");
            let ice_b = IceTransport::new(
                &cfg,
                Role::Active,
                IceTransportCallbacks {
                    on_candidate: Arc::new(move |c| b_cands_cb.lock().push(c)),
                    ..IceTransportCallbacks::default()
                },
            )
            .expect("ice b");

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

            // Recv-side Track B: recvonly. We wire srtp_b's on_rtp straight into
            // track_b.incoming() — exactly what the PeerConnection demux will do.
            let track_b = Track::new(
                TrackInit::new(Direction::RecvOnly, Codec::H264, 96, 0x0BAD_F00D, "video0"),
                TrackCallbacks::default(),
            );
            let recovered: Arc<Mutex<Vec<(Vec<u8>, u32, u8)>>> =
                Arc::new(Mutex::new(Vec::new()));
            let recovered_cb = recovered.clone();
            track_b.set_callbacks(TrackCallbacks {
                on_frame: Arc::new(move |p, ts, pt| {
                    recovered_cb.lock().push((p.to_vec(), ts, pt));
                }),
                ..TrackCallbacks::default()
            });

            let track_b_for_srtp = track_b.clone();
            let srtp_a = SrtpTransport::new(
                Arc::new(dtls_a.clone()),
                SrtpTransportCallbacks::default(),
            )
            .expect("srtp a");
            let srtp_b = SrtpTransport::new(
                Arc::new(dtls_b.clone()),
                SrtpTransportCallbacks {
                    on_rtp: Arc::new(move |d| track_b_for_srtp.incoming(d)),
                    ..SrtpTransportCallbacks::default()
                },
            )
            .expect("srtp b");

            // Send-side Track A: sendonly, bound to srtp_a.
            let track_a = Track::new(
                TrackInit::new(Direction::SendOnly, Codec::H264, 96, 0x0BAD_F00D, "video0"),
                TrackCallbacks::default(),
            );

            // Drive ICE.
            ice_a.gather().expect("a gather");
            assert!(
                wait_for(
                    || ice_a.gathering_state() == GatheringState::Complete,
                    3000
                )
                .await
            );
            let desc_a = ice_a.get_local_description(DescriptionType::Offer).unwrap();
            ice_b.set_remote_description(&desc_a).unwrap();
            ice_b.gather().expect("b gather");
            assert!(
                wait_for(
                    || ice_b.gathering_state() == GatheringState::Complete,
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

            let ready = wait_for(|| srtp_a.is_ready() && srtp_b.is_ready(), 10000).await;
            assert!(ready, "srtp keys not derived");

            // Open both tracks now that the media transport is up.
            track_a.open(srtp_a);
            track_b.open(srtp_b);
            assert!(track_a.is_open());

            // Track A sends a media payload; it should arrive at Track B's
            // on_frame after packetize → protect → transport → unprotect →
            // incoming → depacketize.
            let payload = b"hello track loopback".to_vec();
            let n = track_a.send(&payload).expect("track a send");
            assert_eq!(n, 1, "generic packetizer emits one RTP packet");

            let arrived =
                wait_for(|| !recovered.lock().is_empty(), 5000).await;
            assert!(arrived, "frame did not arrive at peer track");
            let got = recovered.lock();
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].0, payload, "payload round-trips through SRTP");
            assert_eq!(got[0].2, 96, "payload type preserved");

            track_a.close();
            track_b.close();
        });
    }
}
