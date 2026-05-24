//! RTP packetization config + the generic base packetizer / depacketizer.
//!
//! Ports `src/rtppacketizationconfig.cpp`, `src/rtppacketizer.cpp`, and
//! `src/rtpdepacketizer.cpp` — the **generic** base only. The codec-specific
//! subclasses (H.264 / H.265 / VP8 / VP9 / AV1) and the RTP header-extension
//! writers (MID/RID/dependency-descriptor/CVO) are **task #20**; this file
//! leaves a clean seam for them:
//!
//! - [`RtpPacketizer`] is a concrete struct that owns an [`RtpPacketizationConfig`]
//!   and implements the generic `fragment` (identity) + `packetize` (one RTP
//!   packet per payload) flow. The codec packetizers in #20 reuse
//!   [`RtpPacketizer::packetize`] after running their own `fragment`.
//! - The MID/RID/extension fields live on [`RtpPacketizationConfig`] already so
//!   #20 can wire extension writing without changing the public surface.

use parking_lot::Mutex;

use crate::rtp::{RtpHeader, Ssrc};

/// Default clock rate for video RTP (90 kHz), as in
/// `RtpPacketizer::VideoClockRate`.
pub const VIDEO_CLOCK_RATE: u32 = 90_000;

/// Mutable per-stream packetization state. Ports `rtc::RtpPacketizationConfig`.
///
/// The fields a generic packetizer advances are `sequence_number` and
/// `timestamp`; `ssrc`, `payload_type`, `clock_rate` and `cname` are fixed for
/// the stream. The MID/RID extension-id fields are carried so the codec
/// packetizers in #20 can emit header extensions without a config change.
#[derive(Debug, Clone)]
pub struct RtpPacketizationConfig {
    /// Synchronization source.
    pub ssrc: Ssrc,
    /// Canonical name (CNAME) for SDES/RTCP.
    pub cname: String,
    /// RTP payload type.
    pub payload_type: u8,
    /// Clock rate (Hz) used for timestamp <-> seconds conversions.
    pub clock_rate: u32,

    /// Current sequence number (advanced by [`RtpPacketizer::packetize`]).
    pub sequence_number: u16,
    /// Current RTP timestamp.
    pub timestamp: u32,
    /// Start timestamp (the random base; `timestamp` is offset from this).
    pub start_timestamp: u32,

    /// CVO (video orientation) extension id, 0 = disabled. (#20 writes it.)
    pub video_orientation_id: u8,
    /// Current video orientation byte (see C++ docs).
    pub video_orientation: u8,

    /// MID header-extension id, 0 = disabled.
    pub mid_id: u8,
    /// MID value, if a MID extension is to be written.
    pub mid: Option<String>,

    /// RID header-extension id, 0 = disabled.
    pub rid_id: u8,
    /// RID value, if a RID extension is to be written.
    pub rid: Option<String>,
}

impl RtpPacketizationConfig {
    /// Construct a config the way the C++ ctor does, but with **deterministic**
    /// (caller-supplied) initial sequence number and timestamp. The C++ ctor
    /// randomizes these per RFC 3550; callers that want randomness pass random
    /// values (see [`new_random`](Self::new_random)). `clock_rate` must be > 0.
    #[must_use]
    pub fn new(
        ssrc: Ssrc,
        cname: impl Into<String>,
        payload_type: u8,
        clock_rate: u32,
        sequence_number: u16,
        timestamp: u32,
    ) -> Self {
        assert!(clock_rate > 0, "clock rate must be > 0");
        RtpPacketizationConfig {
            ssrc,
            cname: cname.into(),
            payload_type,
            clock_rate,
            sequence_number,
            timestamp,
            start_timestamp: timestamp,
            video_orientation_id: 0,
            video_orientation: 0,
            mid_id: 0,
            mid: None,
            rid_id: 0,
            rid: None,
        }
    }

    /// Construct with a random initial sequence number and timestamp, matching
    /// the RFC 3550 recommendation followed by the C++ ctor.
    #[must_use]
    pub fn new_random(
        ssrc: Ssrc,
        cname: impl Into<String>,
        payload_type: u8,
        clock_rate: u32,
    ) -> Self {
        let seq: u16 = rand::random();
        let ts: u32 = rand::random();
        Self::new(ssrc, cname, payload_type, clock_rate, seq, ts)
    }

    /// Convert a timestamp to seconds. Mirrors `getSecondsFromTimestamp`.
    #[must_use]
    pub fn timestamp_to_seconds(&self, timestamp: u32) -> f64 {
        f64::from(timestamp) / f64::from(self.clock_rate)
    }

    /// Convert seconds to a timestamp (rounded). Mirrors `getTimestampFromSeconds`.
    #[must_use]
    pub fn seconds_to_timestamp(&self, seconds: f64) -> u32 {
        (seconds * f64::from(self.clock_rate)).round() as i64 as u32
    }
}

/// The generic RTP packetizer. Ports the non-codec parts of
/// `rtc::RtpPacketizer`.
///
/// `fragment` returns the payload unchanged (one packet per call); the
/// codec-specific subclasses in #20 override fragmentation. `packetize` builds
/// one RTP packet for a payload, advancing the config's sequence number — the
/// behaviour shared by every codec packetizer.
///
/// The config is held behind a `Mutex` so a packetizer shared across a Track's
/// send path advances sequence numbers atomically, matching the transport
/// modules' `Arc<…>` + `parking_lot::Mutex<Inner>` style.
#[derive(Debug)]
pub struct RtpPacketizer {
    config: Mutex<RtpPacketizationConfig>,
}

impl RtpPacketizer {
    /// Construct a packetizer over the given config.
    #[must_use]
    pub fn new(config: RtpPacketizationConfig) -> Self {
        RtpPacketizer {
            config: Mutex::new(config),
        }
    }

    /// Snapshot of the current config (sequence number / timestamp included).
    #[must_use]
    pub fn config(&self) -> RtpPacketizationConfig {
        self.config.lock().clone()
    }

    /// The current sequence number that the **next** `packetize` will use.
    #[must_use]
    pub fn next_sequence_number(&self) -> u16 {
        self.config.lock().sequence_number
    }

    /// Set the RTP timestamp used by subsequent `packetize` calls. The C++
    /// `outgoing()` sets this from the frame's `FrameInfo`; here it is explicit
    /// so the Track / a future media pipeline drives it.
    pub fn set_timestamp(&self, timestamp: u32) {
        self.config.lock().timestamp = timestamp;
    }

    /// Generic fragmentation: a single payload, returned unchanged. Mirrors the
    /// base `RtpPacketizer::fragment`. Codec packetizers (#20) split here.
    #[must_use]
    pub fn fragment(&self, data: Vec<u8>) -> Vec<Vec<u8>> {
        vec![data]
    }

    /// Build one RTP packet for `payload`, setting marker per `mark` and using
    /// the config's payload type / SSRC / timestamp. Advances (increments) the
    /// sequence number, matching `RtpPacketizer::packetize` (`sequenceNumber++`).
    ///
    /// Header extensions (MID/RID/CVO/dependency-descriptor) are **not** written
    /// here — that is task #20. The seam is the config's `mid`/`rid`/`*_id`
    /// fields plus the `extension` flag on the header.
    #[must_use]
    pub fn packetize(&self, payload: &[u8], mark: bool) -> Vec<u8> {
        let (pt, seq, ts, ssrc) = {
            let mut c = self.config.lock();
            let seq = c.sequence_number;
            c.sequence_number = c.sequence_number.wrapping_add(1);
            (c.payload_type, seq, c.timestamp, c.ssrc)
        };
        let header = RtpHeader {
            version: 2,
            marker: mark,
            payload_type: pt,
            sequence_number: seq,
            timestamp: ts,
            ssrc,
            ..RtpHeader::default()
        };
        let mut out = header.serialize();
        out.extend_from_slice(payload);
        out
    }

    /// Run a whole frame through the generic flow: fragment, then packetize each
    /// fragment with the marker set on the **last** one. Mirrors the per-frame
    /// loop in `RtpPacketizer::outgoing`. Returns the RTP packets in order.
    #[must_use]
    pub fn outgoing(&self, frame: Vec<u8>) -> Vec<Vec<u8>> {
        let fragments = self.fragment(frame);
        let n = fragments.len();
        fragments
            .into_iter()
            .enumerate()
            .map(|(i, frag)| {
                let mark = i + 1 == n;
                self.packetize(&frag, mark)
            })
            .collect()
    }
}

/// Recovered RTP payload plus the header fields a downstream needs. The C++
/// `RtpDepacketizer` surfaces frame info (timestamp, payload type); we return
/// it inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepacketizedFrame {
    /// RTP timestamp from the header.
    pub timestamp: u32,
    /// Payload type from the header.
    pub payload_type: u8,
    /// The payload bytes (header + extension header stripped).
    pub payload: Vec<u8>,
}

/// The generic RTP depacketizer. Ports the base `rtc::RtpDepacketizer::incoming`
/// (one packet → one payload, header + extension stripped). The video
/// reassembly buffer (`VideoRtpDepacketizer`) and codec reassembly are #20.
#[derive(Debug, Default)]
pub struct RtpDepacketizer {
    clock_rate: u32,
}

impl RtpDepacketizer {
    /// New depacketizer. `clock_rate` of 0 means "unknown" (no seconds mapping),
    /// matching the C++ default ctor.
    #[must_use]
    pub fn new(clock_rate: u32) -> Self {
        RtpDepacketizer { clock_rate }
    }

    /// The configured clock rate (0 = unknown).
    #[must_use]
    pub fn clock_rate(&self) -> u32 {
        self.clock_rate
    }

    /// Strip the RTP (and extension) header from a single packet and return the
    /// payload + frame info. `None` if the packet is too small / truncated,
    /// mirroring the size checks in `RtpDepacketizer::incoming`.
    #[must_use]
    pub fn depacketize(&self, packet: &[u8]) -> Option<DepacketizedFrame> {
        let (header, header_size) = RtpHeader::parse(packet)?;
        // Account for an RTP header extension if present.
        let total_header = if header.extension {
            let ext = crate::rtp::RtpExtensionHeader::parse(packet.get(header_size..)?)?;
            header_size + ext.total_size()
        } else {
            header_size
        };
        if packet.len() < total_header {
            return None; // truncated header / extension
        }
        Some(DepacketizedFrame {
            timestamp: header.timestamp,
            payload_type: header.payload_type,
            payload: packet[total_header..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RtpPacketizationConfig {
        // ssrc, cname, pt=96, clock=90000, seq=1000, ts=5000
        RtpPacketizationConfig::new(0x0BAD_F00D, "cname", 96, VIDEO_CLOCK_RATE, 1000, 5000)
    }

    #[test]
    fn config_timestamp_seconds_round_trip() {
        let c = cfg();
        // 90000 clock => 1 second is 90000 ticks.
        assert_eq!(c.seconds_to_timestamp(1.0), 90_000);
        assert!((c.timestamp_to_seconds(90_000) - 1.0).abs() < 1e-9);
        assert_eq!(c.start_timestamp, 5000);
    }

    #[test]
    fn packetize_sets_fields_and_increments_seq() {
        let p = RtpPacketizer::new(cfg());

        let pkt0 = p.packetize(b"frame-zero", false);
        let (h0, off0) = RtpHeader::parse(&pkt0).unwrap();
        assert_eq!(h0.version, 2);
        assert_eq!(h0.payload_type, 96);
        assert_eq!(h0.ssrc, 0x0BAD_F00D);
        assert_eq!(h0.timestamp, 5000);
        assert_eq!(h0.sequence_number, 1000);
        assert!(!h0.marker);
        assert_eq!(&pkt0[off0..], b"frame-zero");

        let pkt1 = p.packetize(b"frame-one", true);
        let (h1, off1) = RtpHeader::parse(&pkt1).unwrap();
        assert_eq!(h1.sequence_number, 1001, "sequence number increments");
        assert!(h1.marker);
        assert_eq!(h1.ssrc, 0x0BAD_F00D);
        assert_eq!(h1.payload_type, 96);
        assert_eq!(&pkt1[off1..], b"frame-one");

        assert_eq!(p.next_sequence_number(), 1002);
    }

    #[test]
    fn packetize_sequence_number_wraps() {
        let mut c = cfg();
        c.sequence_number = 0xFFFF;
        let p = RtpPacketizer::new(c);
        let pkt = p.packetize(b"x", false);
        assert_eq!(RtpHeader::parse(&pkt).unwrap().0.sequence_number, 0xFFFF);
        assert_eq!(p.next_sequence_number(), 0, "wraps to 0");
    }

    #[test]
    fn outgoing_marks_only_last_fragment() {
        let p = RtpPacketizer::new(cfg());
        // Generic fragment() is identity, so a frame -> exactly one packet with
        // the marker set (it is the last fragment).
        let pkts = p.outgoing(b"single fragment frame".to_vec());
        assert_eq!(pkts.len(), 1);
        assert!(RtpHeader::parse(&pkts[0]).unwrap().0.marker);
    }

    #[test]
    fn depacketize_recovers_payload() {
        let p = RtpPacketizer::new(cfg());
        let payload = b"the quick brown fox";
        let pkt = p.packetize(payload, true);

        let d = RtpDepacketizer::new(VIDEO_CLOCK_RATE);
        let frame = d.depacketize(&pkt).expect("depacketize");
        assert_eq!(frame.payload, payload);
        assert_eq!(frame.payload_type, 96);
        assert_eq!(frame.timestamp, 5000);
    }

    #[test]
    fn packetize_then_depacketize_round_trip_multiple() {
        let p = RtpPacketizer::new(cfg());
        let d = RtpDepacketizer::new(VIDEO_CLOCK_RATE);
        for i in 0..5u8 {
            let payload = vec![i; (i as usize + 1) * 3];
            let pkt = p.packetize(&payload, i == 4);
            let frame = d.depacketize(&pkt).unwrap();
            assert_eq!(frame.payload, payload);
            assert_eq!(frame.timestamp, 5000);
        }
        assert_eq!(p.next_sequence_number(), 1005);
    }

    #[test]
    fn depacketize_rejects_truncated() {
        let d = RtpDepacketizer::new(0);
        assert!(d.depacketize(&[0x80, 0x60, 0x00]).is_none());
    }
}
