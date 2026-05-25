//! VP8 RTP packetizer + depacketizer.
//!
//! Ports `src/vp8rtppacketizer.cpp`/`.hpp` and `src/vp8rtpdepacketizer.cpp`.
//!
//! The packetizer uses the minimal 1-byte VP8 payload descriptor (RFC 7741
//! §4.2): only the `S` (start of partition) and `N` (non-reference) bits, no
//! extended control bits. The depacketizer implements the recommended partition
//! reconstruction (RFC 7741 §4.5.2), parsing the full optional descriptor
//! (X/I/L/T/K and the 15-bit PictureID `M` extension) to skip it.

use crate::codec::{DEFAULT_MAX_FRAGMENT_SIZE, Fragmenter};
use crate::rtp::RtpHeader;
use crate::rtp_packetizer::{RtpPacketizationConfig, RtpPacketizer};

// First descriptor byte bits.
const N_BIT: u8 = 0b0010_0000;
const S_BIT: u8 = 0b0001_0000;
const X_BIT: u8 = 0b1000_0000;
// Extension byte bits.
const I_BIT: u8 = 0b1000_0000;
const L_BIT: u8 = 0b0100_0000;
const T_BIT: u8 = 0b0010_0000;
const K_BIT: u8 = 0b0001_0000;
// PictureID byte: 15-bit extension flag.
const M_BIT: u8 = 0b1000_0000;
// First VP8 frame byte: inverse key-frame flag (P=0 => key frame).
const P_BIT: u8 = 0b0000_0001;

/// VP8 RTP packetizer. Ports `VP8RtpPacketizer`.
#[derive(Debug)]
pub struct Vp8RtpPacketizer {
    inner: RtpPacketizer,
    max_fragment_size: usize,
}

impl Vp8RtpPacketizer {
    /// Construct with the given max fragment size. Ports the `VP8RtpPacketizer`
    /// constructor.
    #[must_use]
    pub fn new(config: RtpPacketizationConfig, max_fragment_size: usize) -> Self {
        Vp8RtpPacketizer {
            inner: RtpPacketizer::new(config),
            max_fragment_size,
        }
    }

    /// Construct with the default max fragment size.
    #[must_use]
    pub fn with_defaults(config: RtpPacketizationConfig) -> Self {
        Self::new(config, DEFAULT_MAX_FRAGMENT_SIZE)
    }

    /// Borrow the underlying generic packetizer.
    #[must_use]
    pub fn inner(&self) -> &RtpPacketizer {
        &self.inner
    }

    /// Split a VP8 frame into RTP payloads, each prefixed with the 1-byte
    /// payload descriptor. Ports `VP8RtpPacketizer::fragment`. Returns empty for
    /// a frame shorter than the 3-byte uncompressed data chunk, or if the max
    /// fragment size cannot fit the descriptor + at least one payload byte.
    #[must_use]
    pub fn fragment(&self, frame: Vec<u8>) -> Vec<Vec<u8>> {
        if frame.len() < 3 {
            return vec![];
        }
        let is_keyframe = (frame[0] & P_BIT) == 0;
        const DESCRIPTOR_SIZE: usize = 1;
        if self.max_fragment_size <= DESCRIPTOR_SIZE {
            return vec![];
        }

        let mut payloads = Vec::new();
        let mut index = 0usize;
        while index < frame.len() {
            let remaining = frame.len() - index;
            let payload_size = (self.max_fragment_size - DESCRIPTOR_SIZE).min(remaining);

            let mut descriptor = 0u8;
            if !is_keyframe {
                descriptor |= N_BIT;
            }
            if index == 0 {
                descriptor |= S_BIT;
            }
            let mut payload = Vec::with_capacity(DESCRIPTOR_SIZE + payload_size);
            payload.push(descriptor);
            payload.extend_from_slice(&frame[index..index + payload_size]);
            payloads.push(payload);
            index += payload_size;
        }
        payloads
    }

    /// Fragment then packetize each fragment, marking the last.
    #[must_use]
    pub fn outgoing(&self, frame: Vec<u8>) -> Vec<Vec<u8>> {
        let frags = self.fragment(frame);
        let n = frags.len();
        frags
            .into_iter()
            .enumerate()
            .map(|(i, f)| self.inner.packetize(&f, i + 1 == n))
            .collect()
    }
}

impl Fragmenter for Vp8RtpPacketizer {
    fn fragment(&mut self, frame: Vec<u8>) -> Vec<Vec<u8>> {
        Vp8RtpPacketizer::fragment(self, frame)
    }
}

/// Parse the VP8 payload descriptor at the front of `payload` and return its
/// size in bytes, or `None` if the descriptor is truncated. Ports the
/// descriptor-skipping logic in `VP8RtpDepacketizer::reassemble`.
fn descriptor_size(payload: &[u8]) -> Option<usize> {
    if payload.is_empty() {
        return None;
    }
    let mut size = 1usize;
    let first = payload[0];
    if first & X_BIT != 0 {
        if payload.len() < size + 1 {
            return None;
        }
        let ext = payload[size];
        size += 1;
        if ext & I_BIT != 0 {
            if payload.len() < size + 1 {
                return None;
            }
            let pic_id = payload[size];
            size += 1;
            if pic_id & M_BIT != 0 {
                // 15-bit PictureID: one more byte.
                if payload.len() < size + 1 {
                    return None;
                }
                size += 1;
            }
        }
        if ext & L_BIT != 0 {
            if payload.len() < size + 1 {
                return None;
            }
            size += 1;
        }
        if ext & T_BIT != 0 || ext & K_BIT != 0 {
            if payload.len() < size + 1 {
                return None;
            }
            size += 1;
        }
    }
    Some(size)
}

/// VP8 RTP depacketizer. Ports `VP8RtpDepacketizer`. Reassembles a buffer of
/// RTP packets into a VP8 frame using RFC 7741's recommended partition
/// reconstruction.
#[derive(Debug, Default)]
pub struct Vp8RtpDepacketizer;

impl Vp8RtpDepacketizer {
    /// New depacketizer.
    #[must_use]
    pub fn new() -> Self {
        Vp8RtpDepacketizer
    }

    /// Reassemble RTP packets into a VP8 frame. Ports
    /// `VP8RtpDepacketizer::reassemble`. Returns `(frame, timestamp,
    /// payload_type)`, or `None` if no partition could be recovered.
    #[must_use]
    pub fn reassemble(&self, packets: &[Vec<u8>]) -> Option<(Vec<u8>, u32, u8)> {
        if packets.is_empty() {
            return None;
        }
        let (first_hdr, _) = RtpHeader::parse(&packets[0])?;
        let payload_type = first_hdr.payload_type;
        let timestamp = first_hdr.timestamp;
        let mut next_seq = first_hdr.sequence_number;

        let mut frame: Vec<u8> = Vec::new();
        // Pending payload slices (offset, len) into their packets, kept until a
        // start/marker confirms a continuous sequence.
        let mut payloads: Vec<(usize, usize, usize)> = Vec::new(); // (packet_index, offset, len)
        let mut continuous = false;

        for (pkt_index, packet) in packets.iter().enumerate() {
            let (hdr, hdr_size) = match RtpHeader::parse(packet) {
                Some(v) => v,
                None => continue,
            };
            if hdr.sequence_number < next_seq {
                continue;
            }
            if hdr.sequence_number > next_seq {
                continuous = false;
            }
            next_seq = hdr.sequence_number.wrapping_add(1);

            let ext_size = crate::codec::nal::extension_header_size(&hdr, packet, hdr_size);
            let rtp_header_size = hdr_size + ext_size;
            let padding_size = crate::codec::nal::padding_size(&hdr, packet);

            if packet.len() <= rtp_header_size + padding_size {
                continue; // empty payload
            }
            let payload = &packet[rtp_header_size..packet.len() - padding_size];
            if payload.is_empty() {
                continue;
            }
            let first_byte = payload[0];
            let desc = match descriptor_size(payload) {
                Some(d) => d,
                None => continue,
            };
            if payload.len() < desc {
                continue;
            }
            let data_offset = rtp_header_size + desc;
            let data_len = packet.len() - padding_size - data_offset;

            if first_byte & S_BIT != 0 || hdr.marker {
                if continuous {
                    // Sequence is continuous: append buffered payloads.
                    for &(pi, off, len) in &payloads {
                        frame.extend_from_slice(&packets[pi][off..off + len]);
                    }
                    if hdr.marker {
                        // Append the current payload too.
                        frame.extend_from_slice(&packet[data_offset..data_offset + data_len]);
                    }
                }
                payloads.clear();
                continuous = true;
            }

            if !hdr.marker {
                payloads.push((pkt_index, data_offset, data_len));
            }
        }

        if frame.is_empty() {
            return None;
        }
        Some((frame, timestamp, payload_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp_packetizer::VIDEO_CLOCK_RATE;

    fn cfg() -> RtpPacketizationConfig {
        RtpPacketizationConfig::new(0x1234_5678, "cname", 100, VIDEO_CLOCK_RATE, 500, 7000)
    }

    #[test]
    fn key_frame_descriptor_bits_first_and_continuation() {
        // Key frame: first byte's P bit is 0.
        let mut frame = vec![0x00u8, 0x00, 0x00]; // P=0 => key frame
        frame.extend((0..50u8).collect::<Vec<_>>());
        let p = Vp8RtpPacketizer::new(cfg(), 20); // small => multiple fragments
        let frags = p.fragment(frame);
        assert!(frags.len() >= 2);
        // First fragment: S bit set, N bit clear (key frame).
        assert_eq!(frags[0][0] & S_BIT, S_BIT, "first has S bit");
        assert_eq!(frags[0][0] & N_BIT, 0, "key frame: N bit clear");
        // Continuation fragments: S bit clear.
        for f in &frags[1..] {
            assert_eq!(f[0] & S_BIT, 0, "continuation: S bit clear");
        }
    }

    #[test]
    fn interframe_sets_non_reference_bit() {
        // Interframe: first byte's P bit is 1.
        let mut frame = vec![0x01u8, 0x00, 0x00]; // P=1 => interframe
        frame.extend((0..30u8).collect::<Vec<_>>());
        let p = Vp8RtpPacketizer::new(cfg(), 15);
        let frags = p.fragment(frame);
        for f in &frags {
            assert_eq!(f[0] & N_BIT, N_BIT, "interframe: N bit set");
        }
        // Only the first has S.
        assert_eq!(frags[0][0] & S_BIT, S_BIT);
    }

    #[test]
    fn too_short_frame_returns_empty() {
        let p = Vp8RtpPacketizer::with_defaults(cfg());
        assert!(p.fragment(vec![0x00, 0x01]).is_empty());
    }

    #[test]
    fn single_packet_frame_matches_libdatachannel_quirk() {
        // A whole frame fits in one packet (S + marker both set). libdatachannel's
        // VP8 depacketizer only emits buffered payloads once a *prior* start
        // primed `continuousSequence`; a lone S+marker packet therefore recovers
        // nothing (returns None). We port that behavior faithfully.
        let mut frame = vec![0x00u8, 0x12, 0x34]; // key frame
        frame.extend(b"vp8-frame-data-here");
        let p = Vp8RtpPacketizer::new(cfg(), 1000);
        let packets = p.outgoing(frame.clone());
        assert_eq!(packets.len(), 1);
        let (h, _) = RtpHeader::parse(&packets[0]).unwrap();
        assert!(h.marker);

        let d = Vp8RtpDepacketizer::new();
        assert!(
            d.reassemble(&packets).is_none(),
            "lone S+marker packet recovers nothing (libdatachannel quirk)"
        );
    }

    #[test]
    fn multi_packet_frame_then_following_start_round_trips() {
        // The realistic path: a frame fragmented across packets (S on the first,
        // no marker until the last). All buffered non-marker payloads plus the
        // marker payload reassemble to the original frame.
        let mut frame = vec![0x00u8, 0x9A, 0xBC];
        frame.extend((0..150u16).map(|i| (i & 0xFF) as u8));
        let p = Vp8RtpPacketizer::new(cfg(), 40);
        let packets = p.outgoing(frame.clone());
        assert!(packets.len() >= 3);
        // First packet has S, only the last has the marker.
        assert!(!RtpHeader::parse(&packets[0]).unwrap().0.marker);
        assert!(RtpHeader::parse(packets.last().unwrap()).unwrap().0.marker);

        let d = Vp8RtpDepacketizer::new();
        let (out, ts, pt) = d.reassemble(&packets).unwrap();
        assert_eq!(out, frame);
        assert_eq!(ts, 7000);
        assert_eq!(pt, 100);
    }

    #[test]
    fn round_trip_fragmented_frame() {
        // A frame split across several packets; last carries the marker.
        let mut frame = vec![0x00u8, 0xAB, 0xCD]; // key frame
        frame.extend((0..200u16).map(|i| (i & 0xFF) as u8));
        let p = Vp8RtpPacketizer::new(cfg(), 40);
        let packets = p.outgoing(frame.clone());
        assert!(packets.len() >= 4);

        let d = Vp8RtpDepacketizer::new();
        let (out, _, _) = d.reassemble(&packets).unwrap();
        assert_eq!(out, frame, "fragmented frame reassembles to original");
    }

    #[test]
    fn descriptor_size_parses_extended_fields() {
        // X=1, with I (and M extension), L, and T set.
        // byte0: X
        // byte1 (ext): I|L|T
        // byte2 (picid): M set => 15-bit (one more byte)
        // byte3: picid low
        // byte4: tl0picidx (L)
        // byte5: tid/y/keyidx (T)
        let payload = vec![
            X_BIT,
            I_BIT | L_BIT | T_BIT,
            M_BIT, // picid hi with M
            0x01,  // picid lo
            0x02,  // tl0picidx
            0x03,  // tid byte
            0xFF,  // actual data
        ];
        assert_eq!(descriptor_size(&payload), Some(6));
    }
}
