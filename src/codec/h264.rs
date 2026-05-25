//! H.264 RTP packetizer + depacketizer.
//!
//! Ports `src/h264rtppacketizer.cpp`/`.hpp` and
//! `src/h264rtpdepacketizer.cpp`/`.hpp`.
//!
//! Packetization: split the frame into NAL units ([`nal::split_frame`]); each
//! unit at or below `max_fragment_size` is emitted as a single-NAL payload
//! unchanged, and each larger unit is split into FU-A fragments. (Like
//! libdatachannel's H.264 packetizer, we do **not** aggregate small NALs into
//! STAP-A on the send side — but the depacketizer below splits incoming
//! STAP-A, since other senders use it.)
//!
//! Depacketization: reassemble a sequence of RTP packets into a coded frame,
//! inserting the configured Annex-B separator before each NAL unit, recovering
//! FU-A fragments and splitting STAP-A aggregation packets.

use crate::codec::nal::{
    self, H264_NAL_HEADER_SIZE, H264_NAL_TYPE_FU_A, H264_NAL_TYPE_STAP_A, NALU_LONG_START_CODE,
    NALU_SHORT_START_CODE, Separator,
};
use crate::codec::{DEFAULT_MAX_FRAGMENT_SIZE, Fragmenter, ReassembledFrame};
use crate::rtp::RtpHeader;
use crate::rtp_packetizer::{RtpPacketizationConfig, RtpPacketizer};

/// H.264 RTP packetizer. Ports `H264RtpPacketizer`. Owns an [`RtpPacketizer`]
/// (the generic header-writing/marking base) and overrides fragmentation.
#[derive(Debug)]
pub struct H264RtpPacketizer {
    inner: RtpPacketizer,
    separator: Separator,
    max_fragment_size: usize,
}

impl H264RtpPacketizer {
    /// Construct with an explicit separator (the convention of the input
    /// frames) and max fragment size. Ports the primary `H264RtpPacketizer`
    /// constructor.
    #[must_use]
    pub fn new(
        separator: Separator,
        config: RtpPacketizationConfig,
        max_fragment_size: usize,
    ) -> Self {
        H264RtpPacketizer {
            inner: RtpPacketizer::new(config),
            separator,
            max_fragment_size,
        }
    }

    /// Construct with the default max fragment size. The deprecated C++ ctor
    /// defaults the separator to `Length`.
    #[must_use]
    pub fn with_defaults(config: RtpPacketizationConfig) -> Self {
        Self::new(Separator::Length, config, DEFAULT_MAX_FRAGMENT_SIZE)
    }

    /// Borrow the underlying generic packetizer (for sequence-number / config
    /// inspection and timestamp control).
    #[must_use]
    pub fn inner(&self) -> &RtpPacketizer {
        &self.inner
    }

    /// Codec-specific fragmentation: split into NALs, FU-A-fragment the large
    /// ones, pass small ones through. Ports `H264RtpPacketizer::fragment` +
    /// `NalUnit::GenerateFragments`.
    #[must_use]
    pub fn fragment(&self, frame: Vec<u8>) -> Vec<Vec<u8>> {
        let nalus = nal::split_frame(&frame, self.separator);
        let mut result = Vec::new();
        for nalu in nalus {
            if nalu.len() > self.max_fragment_size {
                result.extend(nal::h264_generate_fragments(&nalu, self.max_fragment_size));
            } else {
                result.push(nalu);
            }
        }
        result
    }

    /// Fragment then packetize each fragment, marking the last. Ports the
    /// per-frame loop in `RtpPacketizer::outgoing`.
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

impl Fragmenter for H264RtpPacketizer {
    fn fragment(&mut self, frame: Vec<u8>) -> Vec<Vec<u8>> {
        H264RtpPacketizer::fragment(self, frame)
    }
}

/// H.264 RTP depacketizer. Ports `H264RtpDepacketizer`. Reassembles a buffer of
/// RTP packets (in sequence-number order) into a coded frame.
#[derive(Debug)]
pub struct H264RtpDepacketizer {
    separator: Separator,
}

impl H264RtpDepacketizer {
    /// Construct with the separator to insert between NAL units in the output
    /// frame. Ports the `H264RtpDepacketizer` ctor (rejects `Length`).
    ///
    /// # Errors
    /// Returns `Err` if `separator` is `Length` (only the start-sequence
    /// variants are valid output separators).
    pub fn new(separator: Separator) -> Result<Self, &'static str> {
        match separator {
            Separator::StartSequence
            | Separator::LongStartSequence
            | Separator::ShortStartSequence => Ok(H264RtpDepacketizer { separator }),
            Separator::Length => Err("Unimplemented H264 separator"),
        }
    }

    fn add_separator(&self, frame: &mut Vec<u8>) {
        match self.separator {
            Separator::StartSequence | Separator::LongStartSequence => {
                frame.extend_from_slice(&NALU_LONG_START_CODE);
            }
            Separator::ShortStartSequence => {
                frame.extend_from_slice(&NALU_SHORT_START_CODE);
            }
            Separator::Length => {}
        }
    }

    /// Reassemble RTP packets into a coded frame. Ports
    /// `H264RtpDepacketizer::reassemble`. `packets` should be in sequence-number
    /// order; out-of-order / missing packets break FU-A continuity exactly as
    /// the C++ does. Returns `(frame, timestamp, payload_type)`, or `None` if
    /// the buffer is empty.
    ///
    /// # Errors
    /// Returns `Err` for a malformed STAP-A (declared size exceeds payload) or
    /// an unknown NAL type, matching the C++ `throw std::runtime_error`.
    pub fn reassemble(
        &self,
        packets: &[Vec<u8>],
    ) -> Result<Option<ReassembledFrame>, &'static str> {
        if packets.is_empty() {
            return Ok(None);
        }
        let (first_hdr, _) = match RtpHeader::parse(&packets[0]) {
            Some(v) => v,
            None => return Ok(None),
        };
        let payload_type = first_hdr.payload_type;
        let timestamp = first_hdr.timestamp;
        let mut next_seq = first_hdr.sequence_number;

        let mut frame: Vec<u8> = Vec::new();
        let mut continuous = false;

        for packet in packets {
            let (hdr, hdr_size) = match RtpHeader::parse(packet) {
                Some(v) => v,
                None => continue,
            };
            if seq_lt(hdr.sequence_number, next_seq) {
                continue; // skip
            }
            if seq_gt(hdr.sequence_number, next_seq) {
                continuous = false; // missing packet(s)
            }
            next_seq = hdr.sequence_number.wrapping_add(1);

            let ext_size = nal::extension_header_size(&hdr, packet, hdr_size);
            let rtp_header_size = hdr_size + ext_size;
            let padding_size = nal::padding_size(&hdr, packet);

            if packet.len() <= rtp_header_size + padding_size {
                continue; // empty payload
            }

            let nal_byte = packet[rtp_header_size];
            let nal = nal::H264NalHeaderBits::parse(nal_byte);

            if nal.unit_type == H264_NAL_TYPE_FU_A {
                if packet.len() <= rtp_header_size + padding_size + 1 {
                    continue; // empty FU-A
                }
                let fu = nal::H264FuHeaderBits::parse(packet[rtp_header_size + 1]);

                if fu.start {
                    self.add_separator(&mut frame);
                    // Reconstruct the original NAL header: idc | fragment type.
                    frame.push(nal::H264NalHeaderBits::idc(nal_byte) | fu.unit_type);
                    continuous = true;
                }
                if continuous {
                    let end = packet.len() - padding_size;
                    frame.extend_from_slice(&packet[rtp_header_size + 2..end]);
                }
                if fu.end {
                    continuous = false;
                }
            } else {
                continuous = false;
                if nal.unit_type == H264_NAL_TYPE_STAP_A {
                    let mut offset = rtp_header_size + 1;
                    let limit = packet.len() - padding_size;
                    while offset + 2 < limit {
                        let nalu_size = (u16::from(packet[offset]) << 8
                            | u16::from(packet[offset + 1]))
                            as usize;
                        offset += 2;
                        if offset + nalu_size > limit {
                            return Err("H264 STAP-A size is larger than payload");
                        }
                        self.add_separator(&mut frame);
                        frame.extend_from_slice(&packet[offset..offset + nalu_size]);
                        offset += nalu_size;
                    }
                } else if nal.unit_type > 0 && nal.unit_type < 24 {
                    self.add_separator(&mut frame);
                    let end = packet.len() - padding_size;
                    frame.extend_from_slice(&packet[rtp_header_size..end]);
                } else {
                    return Err("Unknown H264 RTP Packetization");
                }
            }
        }

        Ok(Some((frame, timestamp, payload_type)))
    }
}

/// `a < b` in RTP sequence-number space, but the C++ does a plain `<` on the
/// 16-bit values (no wraparound serial arithmetic), so we match that.
fn seq_lt(a: u16, b: u16) -> bool {
    a < b
}
fn seq_gt(a: u16, b: u16) -> bool {
    a > b
}

/// Build a STAP-A aggregation packet payload from a list of NAL units (each
/// including its header), for depacketizer tests / interop. Layout:
/// `[STAP-A NAL header][len(2)][NAL]...`. The STAP-A header's F/NRI is the
/// maximum NRI across the aggregated units (a common convention); type = 24.
#[must_use]
pub fn build_stap_a(nalus: &[Vec<u8>]) -> Vec<u8> {
    let mut nri_max = 0u8;
    let mut forbidden = false;
    for n in nalus {
        if let Some(&b) = n.first() {
            let h = nal::H264NalHeaderBits::parse(b);
            nri_max = nri_max.max(h.nri);
            forbidden |= h.forbidden;
        }
    }
    let mut out = Vec::new();
    let mut hdr = 0u8;
    hdr = (hdr & 0x7F) | (u8::from(forbidden) << 7);
    hdr = (hdr & 0x9F) | ((nri_max & 0x03) << 5);
    hdr = (hdr & 0xE0) | (H264_NAL_TYPE_STAP_A & 0x1F);
    out.push(hdr);
    for n in nalus {
        out.extend_from_slice(&(n.len() as u16).to_be_bytes());
        out.extend_from_slice(n);
    }
    out
}

const _: () = assert!(H264_NAL_HEADER_SIZE == 1);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp_packetizer::VIDEO_CLOCK_RATE;

    fn cfg() -> RtpPacketizationConfig {
        RtpPacketizationConfig::new(0x0BAD_F00D, "cname", 96, VIDEO_CLOCK_RATE, 1000, 5000)
    }

    /// Build a length-prefixed frame from a set of NAL units.
    fn length_prefixed(nalus: &[Vec<u8>]) -> Vec<u8> {
        let mut f = Vec::new();
        for n in nalus {
            f.extend_from_slice(&(n.len() as u32).to_be_bytes());
            f.extend_from_slice(n);
        }
        f
    }

    #[test]
    fn single_small_nal_is_one_packet_no_fragmentation() {
        let nalu = {
            let mut v = vec![0x65u8]; // IDR
            v.extend(b"small payload");
            v
        };
        let frame = length_prefixed(&[nalu.clone()]);
        let p = H264RtpPacketizer::new(Separator::Length, cfg(), 1000);
        let frags = p.fragment(frame);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], nalu, "small NAL passed through unchanged");
    }

    #[test]
    fn large_nal_fragments_to_fu_a_and_reassembles() {
        // One big NAL (IDR, type 5, NRI 3 => 0x65) of 300 bytes payload.
        let mut nalu = vec![0x65u8];
        nalu.extend((0..300u16).map(|i| (i & 0xFF) as u8));
        let frame = length_prefixed(&[nalu.clone()]);

        let p = H264RtpPacketizer::new(Separator::Length, cfg(), 100);
        let packets = p.outgoing(frame);
        assert!(packets.len() >= 3, "fragmented into multiple FU-A packets");
        // Only the last RTP packet is marked.
        for (i, pkt) in packets.iter().enumerate() {
            let (h, _) = RtpHeader::parse(pkt).unwrap();
            assert_eq!(h.marker, i + 1 == packets.len());
        }

        let d = H264RtpDepacketizer::new(Separator::LongStartSequence).unwrap();
        let (frame_out, ts, pt) = d.reassemble(&packets).unwrap().unwrap();
        assert_eq!(ts, 5000);
        assert_eq!(pt, 96);
        // Output is start-code + original NAL (header + payload).
        let mut expected = NALU_LONG_START_CODE.to_vec();
        expected.extend_from_slice(&nalu);
        assert_eq!(frame_out, expected);
    }

    #[test]
    fn multiple_small_nals_depacketize_from_stap_a() {
        // Three small NALs aggregated into one STAP-A packet.
        let n1 = {
            let mut v = vec![0x67u8]; // SPS (type 7)
            v.extend(b"sps");
            v
        };
        let n2 = {
            let mut v = vec![0x68u8]; // PPS (type 8)
            v.extend(b"pps");
            v
        };
        let n3 = {
            let mut v = vec![0x65u8]; // IDR
            v.extend(b"idr-slice");
            v
        };
        let stap = build_stap_a(&[n1.clone(), n2.clone(), n3.clone()]);

        // Wrap STAP-A in a single RTP packet.
        let p = RtpPacketizer::new(cfg());
        let pkt = p.packetize(&stap, true);

        let d = H264RtpDepacketizer::new(Separator::ShortStartSequence).unwrap();
        let (frame_out, _, _) = d.reassemble(&[pkt]).unwrap().unwrap();
        // Each NAL is separated by a short start code.
        let mut expected = Vec::new();
        for n in [&n1, &n2, &n3] {
            expected.extend_from_slice(&NALU_SHORT_START_CODE);
            expected.extend_from_slice(n);
        }
        assert_eq!(frame_out, expected);
    }

    #[test]
    fn annexb_input_separator_round_trips() {
        // Two NALs in Annex-B (short start codes), each small (single-NAL pkts).
        let n1 = {
            let mut v = vec![0x41u8];
            v.extend(b"slice-one");
            v
        };
        let n2 = {
            let mut v = vec![0x41u8];
            v.extend(b"slice-two");
            v
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&NALU_SHORT_START_CODE);
        frame.extend_from_slice(&n1);
        frame.extend_from_slice(&NALU_SHORT_START_CODE);
        frame.extend_from_slice(&n2);

        let p = H264RtpPacketizer::new(Separator::ShortStartSequence, cfg(), 1000);
        let packets = p.outgoing(frame);
        assert_eq!(packets.len(), 2, "two single-NAL packets");

        let d = H264RtpDepacketizer::new(Separator::ShortStartSequence).unwrap();
        let (out, _, _) = d.reassemble(&packets).unwrap().unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&NALU_SHORT_START_CODE);
        expected.extend_from_slice(&n1);
        expected.extend_from_slice(&NALU_SHORT_START_CODE);
        expected.extend_from_slice(&n2);
        assert_eq!(out, expected);
    }

    #[test]
    fn end_to_end_mixed_frame_round_trip() {
        // A frame with a small NAL and a large NAL, length-prefixed.
        let small = {
            let mut v = vec![0x67u8];
            v.extend(b"sps-data");
            v
        };
        let mut large = vec![0x65u8];
        large.extend((0..500u16).map(|i| (i & 0xFF) as u8));
        let frame = length_prefixed(&[small.clone(), large.clone()]);

        let p = H264RtpPacketizer::new(Separator::Length, cfg(), 120);
        let packets = p.outgoing(frame);

        let d = H264RtpDepacketizer::new(Separator::LongStartSequence).unwrap();
        let (out, _, _) = d.reassemble(&packets).unwrap().unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&NALU_LONG_START_CODE);
        expected.extend_from_slice(&small);
        expected.extend_from_slice(&NALU_LONG_START_CODE);
        expected.extend_from_slice(&large);
        assert_eq!(out, expected);
    }

    #[test]
    fn depacketizer_rejects_length_separator() {
        assert!(H264RtpDepacketizer::new(Separator::Length).is_err());
    }
}
