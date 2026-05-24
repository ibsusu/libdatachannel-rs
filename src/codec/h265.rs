//! H.265 / HEVC RTP packetizer + depacketizer.
//!
//! Ports `src/h265rtppacketizer.cpp`/`.hpp` and
//! `src/h265rtpdepacketizer.cpp`/`.hpp`. Same shape as H.264 but with the
//! 2-byte NAL header, the FU type 49, the AP (aggregation packet) type 48, and
//! a 3-byte FU prefix (2-byte NAL header + 1-byte FU header).

use crate::codec::nal::{
    self, Separator, H265_NAL_TYPE_AP, H265_NAL_TYPE_FU, NALU_LONG_START_CODE,
    NALU_SHORT_START_CODE,
};
use crate::codec::{Fragmenter, ReassembledFrame, DEFAULT_MAX_FRAGMENT_SIZE};
use crate::rtp::RtpHeader;
use crate::rtp_packetizer::{RtpPacketizationConfig, RtpPacketizer};

/// H.265 RTP packetizer. Ports `H265RtpPacketizer`.
#[derive(Debug)]
pub struct H265RtpPacketizer {
    inner: RtpPacketizer,
    separator: Separator,
    max_fragment_size: usize,
}

impl H265RtpPacketizer {
    /// Construct with an explicit separator and max fragment size. Ports the
    /// primary `H265RtpPacketizer` constructor.
    #[must_use]
    pub fn new(separator: Separator, config: RtpPacketizationConfig, max_fragment_size: usize) -> Self {
        H265RtpPacketizer {
            inner: RtpPacketizer::new(config),
            separator,
            max_fragment_size,
        }
    }

    /// Construct with the default max fragment size and `Length` separator.
    #[must_use]
    pub fn with_defaults(config: RtpPacketizationConfig) -> Self {
        Self::new(Separator::Length, config, DEFAULT_MAX_FRAGMENT_SIZE)
    }

    /// Borrow the underlying generic packetizer.
    #[must_use]
    pub fn inner(&self) -> &RtpPacketizer {
        &self.inner
    }

    /// Split into NALs, FU-fragment the large ones, pass small ones through.
    /// Ports `H265RtpPacketizer::fragment` + `H265NalUnit::GenerateFragments`.
    #[must_use]
    pub fn fragment(&self, frame: Vec<u8>) -> Vec<Vec<u8>> {
        let nalus = nal::split_frame(&frame, self.separator);
        let mut result = Vec::new();
        for nalu in nalus {
            if nalu.len() > self.max_fragment_size {
                result.extend(nal::h265_generate_fragments(&nalu, self.max_fragment_size));
            } else {
                result.push(nalu);
            }
        }
        result
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

impl Fragmenter for H265RtpPacketizer {
    fn fragment(&mut self, frame: Vec<u8>) -> Vec<Vec<u8>> {
        H265RtpPacketizer::fragment(self, frame)
    }
}

/// H.265 RTP depacketizer. Ports `H265RtpDepacketizer`.
#[derive(Debug)]
pub struct H265RtpDepacketizer {
    separator: Separator,
}

impl H265RtpDepacketizer {
    /// Construct with the output separator. Ports the `H265RtpDepacketizer`
    /// ctor (rejects `Length`).
    ///
    /// # Errors
    /// Returns `Err` for `Length`.
    pub fn new(separator: Separator) -> Result<Self, &'static str> {
        match separator {
            Separator::StartSequence
            | Separator::LongStartSequence
            | Separator::ShortStartSequence => Ok(H265RtpDepacketizer { separator }),
            Separator::Length => Err("Unimplemented H265 separator"),
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
    /// `H265RtpDepacketizer::reassemble`.
    ///
    /// # Errors
    /// Returns `Err` for a truncated NAL unit (< 2 byte payload) or a malformed
    /// AP, matching the C++ `throw std::runtime_error`.
    pub fn reassemble(&self, packets: &[Vec<u8>]) -> Result<Option<ReassembledFrame>, &'static str> {
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
            if hdr.sequence_number < next_seq {
                continue;
            }
            if hdr.sequence_number > next_seq {
                continuous = false;
            }
            next_seq = hdr.sequence_number.wrapping_add(1);

            let ext_size = nal::extension_header_size(&hdr, packet, hdr_size);
            let rtp_header_size = hdr_size + ext_size;
            let padding_size = nal::padding_size(&hdr, packet);

            if packet.len() <= rtp_header_size + padding_size {
                continue; // empty payload
            }
            let payload_size = packet.len() - (rtp_header_size + padding_size);
            if payload_size < 2 {
                return Err("Truncated H265 NAL unit");
            }

            let nal = nal::H265NalHeaderBits::parse(
                packet[rtp_header_size],
                packet[rtp_header_size + 1],
            );

            if nal.unit_type == H265_NAL_TYPE_FU {
                if payload_size <= 2 {
                    continue; // empty FU
                }
                let fu = nal::H265FuHeaderBits::parse(packet[rtp_header_size + 2]);

                if fu.start {
                    self.add_separator(&mut frame);
                    // Reconstruct the original 2-byte NAL header with the fragment's unit type.
                    let recon = nal::H265NalHeaderBits {
                        forbidden: nal.forbidden,
                        unit_type: fu.unit_type,
                        nuh_layer_id: nal.nuh_layer_id,
                        nuh_temp_id_plus1: nal.nuh_temp_id_plus1,
                    }
                    .serialize();
                    frame.push(recon[0]);
                    frame.push(recon[1]);
                    continuous = true;
                }
                if continuous {
                    let end = packet.len() - padding_size;
                    frame.extend_from_slice(&packet[rtp_header_size + 3..end]);
                }
                if fu.end {
                    continuous = false;
                }
            } else {
                continuous = false;
                if nal.unit_type == H265_NAL_TYPE_AP {
                    let mut offset = rtp_header_size + 2;
                    let limit = packet.len() - padding_size;
                    while offset + 2 < limit {
                        let nalu_size = (u16::from(packet[offset]) << 8
                            | u16::from(packet[offset + 1]))
                            as usize;
                        offset += 2;
                        if offset + nalu_size > limit {
                            return Err("H265 AP size is larger than payload");
                        }
                        self.add_separator(&mut frame);
                        frame.extend_from_slice(&packet[offset..offset + nalu_size]);
                        offset += nalu_size;
                    }
                } else if nal.unit_type < 47 {
                    self.add_separator(&mut frame);
                    let end = packet.len() - padding_size;
                    frame.extend_from_slice(&packet[rtp_header_size..end]);
                } else {
                    // RFC 7798: types 48..=63 MUST NOT be passed to the decoder; drop.
                }
            }
        }

        Ok(Some((frame, timestamp, payload_type)))
    }
}

/// Build an H.265 AP (aggregation packet) payload from a list of NAL units
/// (each including its 2-byte header), for depacketizer tests / interop.
/// Layout: `[2-byte AP NAL header][len(2)][NAL]...`, AP type = 48.
#[must_use]
pub fn build_ap(nalus: &[Vec<u8>]) -> Vec<u8> {
    // Use a header with type=48 (AP); layer/temporal taken from the first NAL.
    let (forbidden, layer, tid) = nalus
        .first()
        .filter(|n| n.len() >= 2)
        .map(|n| {
            let h = nal::H265NalHeaderBits::parse(n[0], n[1]);
            (h.forbidden, h.nuh_layer_id, h.nuh_temp_id_plus1)
        })
        .unwrap_or((false, 0, 1));
    let hdr = nal::H265NalHeaderBits {
        forbidden,
        unit_type: H265_NAL_TYPE_AP,
        nuh_layer_id: layer,
        nuh_temp_id_plus1: tid,
    }
    .serialize();
    let mut out = vec![hdr[0], hdr[1]];
    for n in nalus {
        out.extend_from_slice(&(n.len() as u16).to_be_bytes());
        out.extend_from_slice(n);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp_packetizer::VIDEO_CLOCK_RATE;

    fn cfg() -> RtpPacketizationConfig {
        RtpPacketizationConfig::new(0xCAFE_BABE, "cname", 98, VIDEO_CLOCK_RATE, 2000, 9000)
    }

    fn idr_header() -> [u8; 2] {
        // type=19 (IDR_W_RADL), layer=0, tid+1=1.
        nal::H265NalHeaderBits {
            forbidden: false,
            unit_type: 19,
            nuh_layer_id: 0,
            nuh_temp_id_plus1: 1,
        }
        .serialize()
    }

    fn length_prefixed(nalus: &[Vec<u8>]) -> Vec<u8> {
        let mut f = Vec::new();
        for n in nalus {
            f.extend_from_slice(&(n.len() as u32).to_be_bytes());
            f.extend_from_slice(n);
        }
        f
    }

    #[test]
    fn fu_fragmentation_and_reassembly_with_2byte_header() {
        let hdr = idr_header();
        let mut nalu = vec![hdr[0], hdr[1]];
        nalu.extend((0..400u16).map(|i| (i & 0xFF) as u8));
        let frame = length_prefixed(&[nalu.clone()]);

        let p = H265RtpPacketizer::new(Separator::Length, cfg(), 100);
        let packets = p.outgoing(frame);
        assert!(packets.len() >= 4, "fragmented into multiple FU packets");
        for (i, pkt) in packets.iter().enumerate() {
            let (h, _) = RtpHeader::parse(pkt).unwrap();
            assert_eq!(h.marker, i + 1 == packets.len());
        }

        let d = H265RtpDepacketizer::new(Separator::LongStartSequence).unwrap();
        let (out, ts, pt) = d.reassemble(&packets).unwrap().unwrap();
        assert_eq!(ts, 9000);
        assert_eq!(pt, 98);
        let mut expected = NALU_LONG_START_CODE.to_vec();
        expected.extend_from_slice(&nalu);
        assert_eq!(out, expected, "FU reassembly recovers original NAL");
    }

    #[test]
    fn small_nal_single_packet_round_trip() {
        let hdr = idr_header();
        let mut nalu = vec![hdr[0], hdr[1]];
        nalu.extend(b"small-hevc-slice");
        let frame = length_prefixed(&[nalu.clone()]);

        let p = H265RtpPacketizer::new(Separator::Length, cfg(), 1000);
        let packets = p.outgoing(frame);
        assert_eq!(packets.len(), 1);

        let d = H265RtpDepacketizer::new(Separator::ShortStartSequence).unwrap();
        let (out, _, _) = d.reassemble(&packets).unwrap().unwrap();
        let mut expected = NALU_SHORT_START_CODE.to_vec();
        expected.extend_from_slice(&nalu);
        assert_eq!(out, expected);
    }

    #[test]
    fn aggregation_packet_splits_on_depacketize() {
        let hdr = idr_header();
        let n1 = {
            let mut v = vec![hdr[0], hdr[1]];
            v.extend(b"nal-a");
            v
        };
        let n2 = {
            let mut v = vec![hdr[0], hdr[1]];
            v.extend(b"nal-bb");
            v
        };
        let ap = build_ap(&[n1.clone(), n2.clone()]);
        let p = RtpPacketizer::new(cfg());
        let pkt = p.packetize(&ap, true);

        let d = H265RtpDepacketizer::new(Separator::LongStartSequence).unwrap();
        let (out, _, _) = d.reassemble(&[pkt]).unwrap().unwrap();
        let mut expected = Vec::new();
        for n in [&n1, &n2] {
            expected.extend_from_slice(&NALU_LONG_START_CODE);
            expected.extend_from_slice(n);
        }
        assert_eq!(out, expected);
    }
}
