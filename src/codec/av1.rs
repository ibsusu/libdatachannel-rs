//! AV1 RTP packetizer.
//!
//! Ports `src/av1rtppacketizer.cpp`/`.hpp`. libdatachannel ships **no** AV1
//! depacketizer, so none is ported here (faithful to upstream).
//!
//! Two packetization modes (`Packetization`):
//! - `TemporalUnit`: the input is a temporal unit; split it into OBUs (parsing
//!   the optional temporal-unit delimiter, OBU extension byte, and LEB128
//!   length) and packetize each.
//! - `Obu`: the input is already a single OBU; packetize it directly.
//!
//! Each RTP payload starts with the 1-byte AV1 aggregation header
//! (`Z|Y|W|N|----`), then the OBU element(s). A cached sequence-header OBU is
//! prepended (with its LEB128 length) to the next packetized OBU and the `N`
//! bit is set, mirroring `mSequenceHeader`.

use crate::codec::{DEFAULT_MAX_FRAGMENT_SIZE, Fragmenter};
use crate::rtp_packetizer::{RtpPacketizationConfig, RtpPacketizer};

// Aggregation header masks. (https://aomediacodec.github.io/av1-rtp-spec/#44)
const Z_MASK: u8 = 0b1000_0000;
const Y_MASK: u8 = 0b0100_0000;
const N_MASK: u8 = 0b0000_1000;
const W_BITSHIFT: u8 = 4;

const PAYLOAD_HEADER_SIZE: usize = 1;
const ONE_BYTE_LEB128_SIZE: usize = 1;

// OBU header bits.
const OBU_FRAME_TYPE_MASK: u8 = 0b0111_1000;
const OBU_FRAME_TYPE_BITSHIFT: u8 = 3;
const OBU_HEADER_SIZE: usize = 1;
const OBU_HAS_EXTENSION_MASK: u8 = 0b0000_0100;
const OBU_HAS_SIZE_MASK: u8 = 0b0000_0010;
const OBU_FRAME_TYPE_SEQUENCE_HEADER: u8 = 1;

const SEVEN_LSB_BITMASK: u8 = 0b0111_1111;
const MSB_BITMASK: u8 = 0b1000_0000;

/// Temporal-unit delimiter OBU bytes: `0x12 0x00`. `obuTemporalUnitDelimiter`.
const OBU_TEMPORAL_UNIT_DELIMITER: [u8; 2] = [0x12, 0x00];

/// AV1 OBU packetization mode. Ports `AV1RtpPacketizer::Packetization`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Packetization {
    /// The input frame is a single OBU. `RTC_OBU_PACKETIZED_OBU`.
    Obu,
    /// The input frame is a temporal unit (split into OBUs first).
    /// `RTC_OBU_PACKETIZED_TEMPORAL_UNIT`.
    TemporalUnit,
}

/// AV1 RTP packetizer. Ports `AV1RtpPacketizer`. Caches a sequence-header OBU
/// across frames (`mSequenceHeader`), so its fragmentation takes `&mut self`.
#[derive(Debug)]
pub struct Av1RtpPacketizer {
    inner: RtpPacketizer,
    packetization: Packetization,
    max_fragment_size: usize,
    sequence_header: Option<Vec<u8>>,
}

impl Av1RtpPacketizer {
    /// Construct with the packetization mode and max fragment size. Ports the
    /// `AV1RtpPacketizer` constructor.
    #[must_use]
    pub fn new(
        packetization: Packetization,
        config: RtpPacketizationConfig,
        max_fragment_size: usize,
    ) -> Self {
        Av1RtpPacketizer {
            inner: RtpPacketizer::new(config),
            packetization,
            max_fragment_size,
            sequence_header: None,
        }
    }

    /// Construct with the default max fragment size.
    #[must_use]
    pub fn with_defaults(packetization: Packetization, config: RtpPacketizationConfig) -> Self {
        Self::new(packetization, config, DEFAULT_MAX_FRAGMENT_SIZE)
    }

    /// Borrow the underlying generic packetizer.
    #[must_use]
    pub fn inner(&self) -> &RtpPacketizer {
        &self.inner
    }

    /// Split a temporal unit into its OBUs. Ports
    /// `AV1RtpPacketizer::extractTemporalUnitObus`. Each returned OBU includes
    /// its header, the (optional) extension byte, the LEB128 size field, and the
    /// payload. Stops if an OBU lacks the `has_size` bit (as the C++ does).
    #[must_use]
    pub fn extract_temporal_unit_obus(data: &[u8]) -> Vec<Vec<u8>> {
        let mut obus = Vec::new();
        if data.is_empty() {
            return obus;
        }
        // VAAPI sometimes omits the delimiter.
        let mut index = 0usize;
        if data.len() > 2
            && data[0] == OBU_TEMPORAL_UNIT_DELIMITER[0]
            && data[1] == OBU_TEMPORAL_UNIT_DELIMITER[1]
        {
            index = 2;
        }
        while index < data.len() {
            if data[index] & OBU_HAS_SIZE_MASK == 0 {
                return obus;
            }
            let mut idx = index;
            if data[idx] & OBU_HAS_EXTENSION_MASK != 0 {
                idx += 1;
            }

            // LEB128 OBU length.
            let mut obu_length: u32 = 0;
            let mut leb128_size: usize = 0;
            while leb128_size < 8 {
                let leb128_index = idx + leb128_size + OBU_HEADER_SIZE;
                if data.len() < leb128_index {
                    break;
                }
                // C++ uses `data.size() < leb128Index` then reads at leb128Index;
                // guard the actual read to avoid OOB on a truncated trailer.
                if leb128_index >= data.len() {
                    break;
                }
                let leb128_byte = data[leb128_index];
                obu_length |= u32::from(leb128_byte & SEVEN_LSB_BITMASK) << (leb128_size * 7);
                leb128_size += 1;
                if leb128_byte & MSB_BITMASK == 0 {
                    break;
                }
            }

            let end = index + OBU_HEADER_SIZE + leb128_size + obu_length as usize;
            let end = end.min(data.len());
            obus.push(data[index..end].to_vec());
            index += OBU_HEADER_SIZE + leb128_size + obu_length as usize;
        }
        obus
    }

    /// Fragment a frame into AV1 RTP payloads. Ports `AV1RtpPacketizer::fragment`.
    #[must_use]
    pub fn fragment(&mut self, data: Vec<u8>) -> Vec<Vec<u8>> {
        match self.packetization {
            Packetization::TemporalUnit => {
                let mut result = Vec::new();
                for obu in Self::extract_temporal_unit_obus(&data) {
                    result.extend(self.fragment_obu(&obu));
                }
                result
            }
            Packetization::Obu => self.fragment_obu(&data),
        }
    }

    /// Fragment a single OBU into RTP payloads with the aggregation header.
    /// Ports `AV1RtpPacketizer::fragmentObu`. A sequence-header OBU is cached
    /// and emitted nothing now; it is prepended to the next OBU.
    #[must_use]
    pub fn fragment_obu(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        if data.is_empty() {
            return vec![];
        }

        // Cache a sequence header and packetize with the next OBU.
        let frame_type = (data[0] & OBU_FRAME_TYPE_MASK) >> OBU_FRAME_TYPE_BITSHIFT;
        if frame_type == OBU_FRAME_TYPE_SEQUENCE_HEADER {
            self.sequence_header = Some(data.to_vec());
            return vec![];
        }

        let mut payloads: Vec<Vec<u8>> = Vec::new();
        let mut index = 0usize;
        let mut remaining = data.len();
        while remaining > 0 {
            let mut obu_count = 1usize;
            let mut metadata_size = PAYLOAD_HEADER_SIZE;
            if let Some(sh) = &self.sequence_header {
                obu_count += 1;
                metadata_size += 1 + sh.len(); // 1-byte LEB128 length + header
            }

            let payload_len = self.max_fragment_size.min(remaining + metadata_size);
            let mut payload = vec![0u8; payload_len];
            let mut payload_offset = PAYLOAD_HEADER_SIZE;

            // Aggregation header: W = obu_count.
            payload[0] = (obu_count as u8) << W_BITSHIFT;

            // Packetize cached sequence header (W = 2).
            if obu_count == 2 {
                let sh = self.sequence_header.take().expect("checked above");
                payload[0] ^= N_MASK; // first packet of coded video sequence
                payload[1] = (sh.len() as u8) & SEVEN_LSB_BITMASK;
                payload_offset += ONE_BYTE_LEB128_SIZE;
                payload[payload_offset..payload_offset + sh.len()].copy_from_slice(&sh);
                payload_offset += sh.len();
            }

            // Copy as much of the OBU as fits.
            let payload_remaining = payload.len() - payload_offset;
            payload[payload_offset..payload_offset + payload_remaining]
                .copy_from_slice(&data[index..index + payload_remaining]);
            remaining -= payload_remaining;
            index += payload_remaining;

            // Z: this fragment continues an OBU from a previous payload.
            if !payloads.is_empty() {
                payload[0] ^= Z_MASK;
            }
            // Y: this OBU continues in the next payload.
            if index < data.len() {
                payload[0] ^= Y_MASK;
            }

            payloads.push(payload);
        }
        payloads
    }

    /// Fragment then packetize each fragment, marking the last. With AV1, a
    /// frame consisting solely of a cached sequence header yields no packets.
    #[must_use]
    pub fn outgoing(&mut self, frame: Vec<u8>) -> Vec<Vec<u8>> {
        let frags = self.fragment(frame);
        let n = frags.len();
        frags
            .into_iter()
            .enumerate()
            .map(|(i, f)| self.inner.packetize(&f, i + 1 == n))
            .collect()
    }
}

impl Fragmenter for Av1RtpPacketizer {
    fn fragment(&mut self, frame: Vec<u8>) -> Vec<Vec<u8>> {
        Av1RtpPacketizer::fragment(self, frame)
    }
}

/// Read a LEB128 value at the front of `data`; returns `(value, bytes_read)`.
/// Test helper mirroring the AV1 LEB128 read.
#[cfg(test)]
fn read_leb128(data: &[u8]) -> (u32, usize) {
    let mut value = 0u32;
    let mut i = 0usize;
    while i < 8 && i < data.len() {
        let b = data[i];
        value |= u32::from(b & SEVEN_LSB_BITMASK) << (i * 7);
        i += 1;
        if b & MSB_BITMASK == 0 {
            break;
        }
    }
    (value, i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::RtpHeader;
    use crate::rtp_packetizer::VIDEO_CLOCK_RATE;

    fn cfg() -> RtpPacketizationConfig {
        RtpPacketizationConfig::new(0xAA_BB_CC_DD, "cname", 45, VIDEO_CLOCK_RATE, 10, 3000)
    }

    /// Build an OBU with the given frame_type (3..6 bit field), has_size set,
    /// no extension, a LEB128 size, and `payload`.
    fn make_obu(frame_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut header = 0u8;
        header |= (frame_type << OBU_FRAME_TYPE_BITSHIFT) & OBU_FRAME_TYPE_MASK;
        header |= OBU_HAS_SIZE_MASK;
        let mut obu = vec![header];
        // LEB128 of payload length (assume < 128 for tests).
        assert!(payload.len() < 128);
        obu.push(payload.len() as u8);
        obu.extend_from_slice(payload);
        obu
    }

    #[test]
    fn single_obu_one_packet_aggregation_header() {
        // frame_type 6 (OBU_FRAME) — not a sequence header.
        let obu = make_obu(6, b"the-obu-payload");
        let mut p = Av1RtpPacketizer::new(Packetization::Obu, cfg(), 1000);
        let frags = p.fragment(obu.clone());
        assert_eq!(frags.len(), 1);
        // Aggregation header: W=1, Z=0, Y=0, N=0.
        let agg = frags[0][0];
        assert_eq!(agg >> W_BITSHIFT, 1, "W = 1 OBU element");
        assert_eq!(agg & Z_MASK, 0, "Z clear (no continuation)");
        assert_eq!(agg & Y_MASK, 0, "Y clear (not continued)");
        assert_eq!(agg & N_MASK, 0, "N clear (no seq header)");
        // The rest is the OBU.
        assert_eq!(&frags[0][1..], &obu[..]);
    }

    #[test]
    fn large_obu_fragments_with_z_y_bits() {
        let obu = make_obu(6, &(0..100u8).collect::<Vec<_>>());
        let mut p = Av1RtpPacketizer::new(Packetization::Obu, cfg(), 30);
        let frags = p.fragment(obu.clone());
        assert!(frags.len() >= 4, "fragmented");

        // First: Z=0, Y=1. Middle: Z=1, Y=1. Last: Z=1, Y=0.
        assert_eq!(frags[0][0] & Z_MASK, 0);
        assert_eq!(frags[0][0] & Y_MASK, Y_MASK);
        let last = frags.last().unwrap();
        assert_eq!(last[0] & Z_MASK, Z_MASK);
        assert_eq!(last[0] & Y_MASK, 0);
        for f in &frags[1..frags.len() - 1] {
            assert_eq!(f[0] & Z_MASK, Z_MASK);
            assert_eq!(f[0] & Y_MASK, Y_MASK);
        }

        // Reassemble OBU bytes from fragments (strip 1-byte aggregation header).
        let mut recovered = Vec::new();
        for f in &frags {
            recovered.extend_from_slice(&f[1..]);
        }
        assert_eq!(recovered, obu);
    }

    #[test]
    fn sequence_header_cached_and_prepended_to_next_obu() {
        // A sequence header OBU (frame_type 1) is cached, produces no packets.
        let seq = make_obu(OBU_FRAME_TYPE_SEQUENCE_HEADER, b"seqhdr");
        let mut p = Av1RtpPacketizer::new(Packetization::Obu, cfg(), 1000);
        let frags = p.fragment(seq.clone());
        assert!(frags.is_empty(), "sequence header is cached, no packets");

        // The next (non-seq) OBU should carry W=2, N set, and the seq header.
        let frame = make_obu(6, b"frame-obu");
        let frags = p.fragment(frame.clone());
        assert_eq!(frags.len(), 1);
        let agg = frags[0][0];
        assert_eq!(agg >> W_BITSHIFT, 2, "W = 2 OBU elements");
        assert_eq!(
            agg & N_MASK,
            N_MASK,
            "N set (first of coded video sequence)"
        );
        // After the aggregation header: LEB128 size of seq header, then seq, then frame.
        let (sh_len, n) = read_leb128(&frags[0][1..]);
        assert_eq!(sh_len as usize, seq.len());
        let off = 1 + n;
        assert_eq!(&frags[0][off..off + seq.len()], &seq[..]);
        assert_eq!(&frags[0][off + seq.len()..], &frame[..]);
    }

    #[test]
    fn temporal_unit_split_into_obus() {
        // Two OBUs preceded by a temporal-unit delimiter.
        let obu1 = make_obu(6, b"first");
        let obu2 = make_obu(6, b"second-obu");
        let mut tu = OBU_TEMPORAL_UNIT_DELIMITER.to_vec();
        tu.extend_from_slice(&obu1);
        tu.extend_from_slice(&obu2);

        let obus = Av1RtpPacketizer::extract_temporal_unit_obus(&tu);
        assert_eq!(obus.len(), 2);
        assert_eq!(obus[0], obu1);
        assert_eq!(obus[1], obu2);

        // End to end: each small OBU becomes one packet.
        let mut p = Av1RtpPacketizer::new(Packetization::TemporalUnit, cfg(), 1000);
        let packets = p.outgoing(tu);
        assert_eq!(packets.len(), 2);
        // Last marked.
        assert!(RtpHeader::parse(&packets[1]).unwrap().0.marker);
        assert!(!RtpHeader::parse(&packets[0]).unwrap().0.marker);
    }

    #[test]
    fn leb128_multibyte_size_parsed() {
        // OBU with a 2-byte LEB128 length (value 200 = 0xC8 -> 0xC8,0x01).
        let payload: Vec<u8> = (0..200u16).map(|i| (i & 0xFF) as u8).collect();
        let mut header = 0u8;
        header |= (6 << OBU_FRAME_TYPE_BITSHIFT) & OBU_FRAME_TYPE_MASK;
        header |= OBU_HAS_SIZE_MASK;
        let mut obu = vec![header, 0xC8, 0x01];
        obu.extend_from_slice(&payload);

        let obus = Av1RtpPacketizer::extract_temporal_unit_obus(&obu);
        assert_eq!(obus.len(), 1);
        assert_eq!(obus[0], obu, "2-byte LEB128 OBU extracted whole");
    }
}
