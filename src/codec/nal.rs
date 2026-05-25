//! Shared NAL-unit foundation for H.264 and H.265 RTP packetization.
//!
//! Ports `src/nalunit.cpp`/`include/rtc/nalunit.hpp` (H.264) and
//! `src/h265nalunit.cpp`/`include/rtc/h265nalunit.hpp` (H.265):
//!
//! - Parsing a coded frame into NAL units under **both** separator conventions
//!   libdatachannel supports: length-prefixed (4-byte big-endian length) and
//!   Annex-B start codes (`00 00 01` short / `00 00 00 01` long).
//! - The fragmentation-unit construction: H.264 FU-A (1-byte NAL header,
//!   type 28) and H.265 FU (2-byte NAL header, type 49), with the
//!   start/end/reserved bits laid out exactly as the C++ headers.
//!
//! This module is byte-for-byte faithful to the C++ bit layouts; the per-codec
//! packetizers ([`crate::codec::h264`], [`crate::codec::h265`]) build on it.

use crate::rtp::RtpHeader;

/// H.264 NAL header size (1 byte). `H264_NAL_HEADER_SIZE`.
pub const H264_NAL_HEADER_SIZE: usize = 1;
/// H.265 NAL header size (2 bytes). `H265_NAL_HEADER_SIZE`.
pub const H265_NAL_HEADER_SIZE: usize = 2;
/// H.265 FU header size (1 byte). `H265_FU_HEADER_SIZE`.
pub const H265_FU_HEADER_SIZE: usize = 1;

/// H.264 FU-A NAL unit type. `NalUnitFragmentA::nal_type_fu_A`.
pub const H264_NAL_TYPE_FU_A: u8 = 28;
/// H.264 STAP-A NAL unit type. `naluTypeSTAPA`.
pub const H264_NAL_TYPE_STAP_A: u8 = 24;
/// H.265 FU NAL unit type. `H265NalUnitFragment::nal_type_fu`.
pub const H265_NAL_TYPE_FU: u8 = 49;
/// H.265 AP (aggregation packet) NAL unit type. `naluTypeAP`.
pub const H265_NAL_TYPE_AP: u8 = 48;

/// NAL unit separator convention. Ports `NalUnit::Separator`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Separator {
    /// First 4 bytes are the NAL unit length (big-endian). `RTC_NAL_SEPARATOR_LENGTH`.
    Length,
    /// Long start sequence `00 00 00 01`. `LongStartSequence`.
    LongStartSequence,
    /// Short start sequence `00 00 01`. `ShortStartSequence`.
    ShortStartSequence,
    /// Either long or short start sequence. `StartSequence`.
    StartSequence,
}

/// The Annex-B long start code `00 00 00 01`.
pub const NALU_LONG_START_CODE: [u8; 4] = [0, 0, 0, 1];
/// The Annex-B short start code `00 00 01`.
pub const NALU_SHORT_START_CODE: [u8; 3] = [0, 0, 1];

/// Start-sequence match state machine states. Ports `NalUnitStartSequenceMatch`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum StartSeqMatch {
    NoMatch,
    FirstZero,
    SecondZero,
    ThirdZero,
    ShortMatch,
    LongMatch,
}

/// Advance the start-sequence match state machine by one byte. Ports
/// `NalUnit::StartSequenceMatchSucc`. Panics if `separator` is `Length`
/// (matching the C++ `assert(separator != Separator::Length)`).
fn start_sequence_match_succ(
    state: StartSeqMatch,
    byte: u8,
    separator: Separator,
) -> StartSeqMatch {
    assert!(separator != Separator::Length);
    use StartSeqMatch::*;
    let detect_short =
        separator == Separator::ShortStartSequence || separator == Separator::StartSequence;
    let detect_long =
        separator == Separator::LongStartSequence || separator == Separator::StartSequence;
    match state {
        NoMatch => {
            if byte == 0x00 {
                return FirstZero;
            }
        }
        FirstZero => {
            if byte == 0x00 {
                return SecondZero;
            }
        }
        SecondZero => {
            if byte == 0x00 && detect_long {
                return ThirdZero;
            } else if byte == 0x00 && detect_short {
                return SecondZero;
            } else if byte == 0x01 && detect_short {
                return ShortMatch;
            }
        }
        ThirdZero => {
            if byte == 0x00 && detect_long {
                return ThirdZero;
            } else if byte == 0x01 && detect_long {
                return LongMatch;
            }
        }
        ShortMatch => return ShortMatch,
        LongMatch => return LongMatch,
    }
    NoMatch
}

/// Split a coded frame into NAL units (each *including* its NAL header) using
/// the given separator. Ports the `splitFrame` shared by the H.264 and H.265
/// packetizers (the byte logic is identical between them).
///
/// For `Length`, each unit is preceded by a 4-byte big-endian length; malformed
/// trailers are dropped (matching the C++ `LOG_WARNING ... break`). For the
/// start-sequence variants, the leading start code is skipped and units are
/// split at each subsequent start code.
#[must_use]
pub fn split_frame(frame: &[u8], separator: Separator) -> Vec<Vec<u8>> {
    let mut nalus = Vec::new();
    if separator == Separator::Length {
        let mut index = 0usize;
        while index < frame.len() {
            if index + 4 > frame.len() {
                // Invalid NAL Unit data (incomplete length), ignore.
                break;
            }
            let length = u32::from_be_bytes([
                frame[index],
                frame[index + 1],
                frame[index + 2],
                frame[index + 3],
            ]) as usize;
            let nalu_start = index + 4;
            let nalu_end = nalu_start + length;
            if nalu_end > frame.len() {
                // Invalid NAL Unit data (incomplete unit), ignore.
                break;
            }
            nalus.push(frame[nalu_start..nalu_end].to_vec());
            index = nalu_end;
        }
    } else {
        let mut state = StartSeqMatch::NoMatch;
        let mut index = 0usize;
        // Skip the leading start code.
        while index < frame.len() {
            state = start_sequence_match_succ(state, frame[index], separator);
            index += 1;
            if state == StartSeqMatch::LongMatch || state == StartSeqMatch::ShortMatch {
                state = StartSeqMatch::NoMatch;
                break;
            }
        }

        let mut nalu_start = index;
        while index < frame.len() {
            state = start_sequence_match_succ(state, frame[index], separator);
            if state == StartSeqMatch::LongMatch || state == StartSeqMatch::ShortMatch {
                let seq_len = if state == StartSeqMatch::LongMatch {
                    4
                } else {
                    3
                };
                let nalu_end = index - seq_len;
                state = StartSeqMatch::NoMatch;
                // end index inclusive in C++: begin..(naluEndIndex + 1)
                nalus.push(frame[nalu_start..=nalu_end].to_vec());
                nalu_start = index + 1;
            }
            index += 1;
        }
        nalus.push(frame[nalu_start..].to_vec());
    }
    nalus
}

/// One fragment of a NAL split: which part of the original unit it is. Ports
/// `NalUnitFragmentA::FragmentType` / `H265NalUnitFragment::FragmentType`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FragmentType {
    /// First fragment of the unit (start bit set).
    Start,
    /// A middle fragment (neither start nor end bit set).
    Middle,
    /// Last fragment of the unit (end bit set).
    End,
}

/// Number of fragments and per-fragment payload size for a unit larger than
/// `max_fragment_size`. Ports the `generateFragments` size arithmetic shared by
/// H.264 and H.265: `ceil(size / max)` fragments, then the effective fragment
/// size is `ceil(size / count)` minus the per-fragment header overhead.
///
/// `header_overhead` is 2 for H.264 (FU indicator + FU header) and 3 for H.265
/// (2-byte NAL header + 1-byte FU header). Returns the adjusted payload chunk
/// size (header excluded). The `size` argument is the **whole NAL unit size**
/// (header included), matching the C++ which divides `size()`.
#[must_use]
fn fragment_chunk_size(size: usize, max_fragment_size: usize, header_overhead: usize) -> usize {
    debug_assert!(size > max_fragment_size);
    let fragments_count = (size as f64 / max_fragment_size as f64).ceil();
    let adjusted = (size as f64 / fragments_count).ceil() as usize;
    adjusted - header_overhead
}

/// Build the H.264 FU-A fragments for one NAL unit (header + payload). Ports
/// `NalUnit::generateFragments` + the `NalUnitFragmentA` ctor.
///
/// Each fragment is `[FU indicator][FU header][payload chunk]`:
/// - FU indicator: F + NRI from the original header, type = 28 (FU-A).
/// - FU header: S/E bits per fragment position, type = original NAL type.
#[must_use]
pub fn h264_generate_fragments(nalu: &[u8], max_fragment_size: usize) -> Vec<Vec<u8>> {
    debug_assert!(nalu.len() > max_fragment_size);
    debug_assert!(!nalu.is_empty());
    let mut chunk = fragment_chunk_size(nalu.len(), max_fragment_size, 2);

    let first = nalu[0];
    let forbidden = (first >> 7) != 0;
    let nri = (first >> 5) & 0x03;
    let unit_type = first & 0x1F;
    let payload = &nalu[H264_NAL_HEADER_SIZE..];

    let mut result = Vec::new();
    let mut offset = 0usize;
    while offset < payload.len() {
        let frag_type = if offset == 0 {
            FragmentType::Start
        } else if offset + chunk < payload.len() {
            FragmentType::Middle
        } else {
            if offset + chunk > payload.len() {
                chunk = payload.len() - offset;
            }
            FragmentType::End
        };
        let data = &payload[offset..offset + chunk];
        result.push(h264_build_fu_a(frag_type, forbidden, nri, unit_type, data));
        offset += chunk;
    }
    result
}

/// Build a single H.264 FU-A fragment packet. Ports the `NalUnitFragmentA`
/// constructor + `setFragmentType`.
#[must_use]
fn h264_build_fu_a(
    frag_type: FragmentType,
    forbidden: bool,
    nri: u8,
    unit_type: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut out = vec![0u8; data.len() + 2];
    // FU indicator (byte 0): F | NRI | type=28
    let mut indicator = 0u8;
    indicator = (indicator & 0x7F) | (u8::from(forbidden) << 7);
    indicator = (indicator & 0x9F) | ((nri & 0x03) << 5);
    indicator = (indicator & 0xE0) | (H264_NAL_TYPE_FU_A & 0x1F);
    out[0] = indicator;
    // FU header (byte 1): S | E | R | type. The byte starts zeroed, so the
    // start/end/reserved bits only need to be set when they are 1.
    let mut fu = 0u8;
    match frag_type {
        FragmentType::Start => fu |= 1 << 7, // start = 1, end = 0
        FragmentType::End => fu |= 1 << 6,   // start = 0, end = 1
        FragmentType::Middle => {}           // start = 0, end = 0
    }
    fu = (fu & 0xE0) | (unit_type & 0x1F);
    out[1] = fu;
    out[2..].copy_from_slice(data);
    out
}

/// Build the H.265 FU fragments for one NAL unit (2-byte header + payload).
/// Ports `H265NalUnit::generateFragments` + the `H265NalUnitFragment` ctor.
///
/// Each fragment is `[2-byte FU NAL header][1-byte FU header][payload chunk]`.
#[must_use]
pub fn h265_generate_fragments(nalu: &[u8], max_fragment_size: usize) -> Vec<Vec<u8>> {
    debug_assert!(nalu.len() > max_fragment_size);
    debug_assert!(nalu.len() >= H265_NAL_HEADER_SIZE);
    let mut chunk = fragment_chunk_size(
        nalu.len(),
        max_fragment_size,
        H265_NAL_HEADER_SIZE + H265_FU_HEADER_SIZE,
    );

    let h = H265NalHeaderBits::parse(nalu[0], nalu[1]);
    let forbidden = h.forbidden;
    let nuh_layer_id = h.nuh_layer_id & 0x3F;
    let nuh_temp_id_plus1 = h.nuh_temp_id_plus1 & 0x07;
    let nalu_type = h.unit_type & 0x3F;
    let payload = &nalu[H265_NAL_HEADER_SIZE..];

    let mut result = Vec::new();
    let mut offset = 0usize;
    while offset < payload.len() {
        let frag_type = if offset == 0 {
            FragmentType::Start
        } else if offset + chunk < payload.len() {
            FragmentType::Middle
        } else {
            if offset + chunk > payload.len() {
                chunk = payload.len() - offset;
            }
            FragmentType::End
        };
        let data = &payload[offset..offset + chunk];
        result.push(h265_build_fu(
            frag_type,
            forbidden,
            nuh_layer_id,
            nuh_temp_id_plus1,
            nalu_type,
            data,
        ));
        offset += chunk;
    }
    result
}

/// Decoded H.265 2-byte NAL header bits. Ports `H265NalUnitHeader` getters.
#[derive(Debug, Copy, Clone)]
pub struct H265NalHeaderBits {
    /// forbidden_zero_bit.
    pub forbidden: bool,
    /// nal_unit_type (6 bits).
    pub unit_type: u8,
    /// nuh_layer_id (6 bits).
    pub nuh_layer_id: u8,
    /// nuh_temporal_id_plus1 (3 bits).
    pub nuh_temp_id_plus1: u8,
}

impl H265NalHeaderBits {
    /// Parse the two header bytes. Ports the `H265NalUnitHeader` accessors.
    #[must_use]
    pub fn parse(first: u8, second: u8) -> Self {
        H265NalHeaderBits {
            forbidden: (first >> 7) != 0,
            unit_type: (first & 0b0111_1110) >> 1,
            nuh_layer_id: ((first & 0x1) << 5) | ((second & 0b1111_1000) >> 3),
            nuh_temp_id_plus1: second & 0b111,
        }
    }

    /// Serialize back to two header bytes. Ports the `H265NalUnitHeader` setters
    /// applied to a zeroed header.
    #[must_use]
    pub fn serialize(&self) -> [u8; 2] {
        let mut first = 0u8;
        let mut second = 0u8;
        // setForbiddenBit
        first = (first & 0x7F) | (u8::from(self.forbidden) << 7);
        // setUnitType
        first = (first & 0b1000_0001) | ((self.unit_type & 0b11_1111) << 1);
        // setNuhLayerId
        first = (first & 0b1111_1110) | ((self.nuh_layer_id & 0b10_0000) >> 5);
        second = (second & 0b0000_0111) | ((self.nuh_layer_id & 0b01_1111) << 3);
        // setNuhTempIdPlus1
        second = (second & 0b1111_1000) | (self.nuh_temp_id_plus1 & 0b111);
        [first, second]
    }
}

/// Build a single H.265 FU fragment packet. Ports the `H265NalUnitFragment`
/// constructor + `setFragmentType`.
#[must_use]
fn h265_build_fu(
    frag_type: FragmentType,
    forbidden: bool,
    nuh_layer_id: u8,
    nuh_temp_id_plus1: u8,
    unit_type: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut out = vec![0u8; data.len() + H265_NAL_HEADER_SIZE + H265_FU_HEADER_SIZE];
    // FU NAL header (bytes 0..2): forbidden, layer/temporal preserved, type = 49.
    let indicator = H265NalHeaderBits {
        forbidden,
        unit_type: H265_NAL_TYPE_FU,
        nuh_layer_id,
        nuh_temp_id_plus1,
    }
    .serialize();
    out[0] = indicator[0];
    out[1] = indicator[1];
    // FU header (byte 2): S | E | FuType(6). The byte starts zeroed, so the
    // start/end bits only need to be set when they are 1.
    let mut fu = 0u8;
    match frag_type {
        FragmentType::Start => fu |= 1 << 7, // start = 1, end = 0
        FragmentType::End => fu |= 1 << 6,   // start = 0, end = 1
        FragmentType::Middle => {}           // start = 0, end = 0
    }
    fu = (fu & 0b1100_0000) | (unit_type & 0b11_1111);
    out[2] = fu;
    out[3..].copy_from_slice(data);
    out
}

/// Size of the RTP header extension (if the X bit is set), else 0. Mirrors
/// `RtpHeader::getExtensionHeaderSize`. Used by the depacketizers to skip the
/// extension before the payload.
#[must_use]
pub fn extension_header_size(hdr: &RtpHeader, packet: &[u8], hdr_size: usize) -> usize {
    if !hdr.extension {
        return 0;
    }
    match packet
        .get(hdr_size..)
        .and_then(crate::rtp::RtpExtensionHeader::parse)
    {
        Some(ext) => ext.total_size(),
        None => 0,
    }
}

/// Padding size = the last byte's value if the P bit is set, else 0. Mirrors
/// `std::to_integer<uint8_t>(packet->back())`.
#[must_use]
pub fn padding_size(hdr: &RtpHeader, packet: &[u8]) -> usize {
    if hdr.padding {
        packet.last().copied().unwrap_or(0) as usize
    } else {
        0
    }
}

/// Decoded H.264 1-byte NAL header bits. Ports `NalUnitHeader` getters.
#[derive(Debug, Copy, Clone)]
pub struct H264NalHeaderBits {
    /// forbidden_zero_bit.
    pub forbidden: bool,
    /// nal_ref_idc (2 bits).
    pub nri: u8,
    /// nal_unit_type (5 bits).
    pub unit_type: u8,
}

impl H264NalHeaderBits {
    /// Parse the header byte. Ports the `NalUnitHeader` accessors.
    #[must_use]
    pub fn parse(byte: u8) -> Self {
        H264NalHeaderBits {
            forbidden: (byte >> 7) != 0,
            nri: (byte >> 5) & 0x03,
            unit_type: byte & 0x1F,
        }
    }

    /// `idc()` = `_first & 0x60` — the NRI bits kept in place (not shifted).
    #[must_use]
    pub fn idc(byte: u8) -> u8 {
        byte & 0x60
    }
}

/// Decoded H.264 FU header bits. Ports `NalUnitFragmentHeader` getters.
#[derive(Debug, Copy, Clone)]
pub struct H264FuHeaderBits {
    /// Start bit.
    pub start: bool,
    /// End bit.
    pub end: bool,
    /// nal_unit_type (5 bits).
    pub unit_type: u8,
}

impl H264FuHeaderBits {
    /// Parse the FU header byte. Ports `NalUnitFragmentHeader` accessors.
    #[must_use]
    pub fn parse(byte: u8) -> Self {
        H264FuHeaderBits {
            start: (byte >> 7) != 0,
            end: ((byte >> 6) & 0x01) != 0,
            unit_type: byte & 0x1F,
        }
    }
}

/// Decoded H.265 FU header bits. Ports `H265NalUnitFragmentHeader` getters.
#[derive(Debug, Copy, Clone)]
pub struct H265FuHeaderBits {
    /// Start bit.
    pub start: bool,
    /// End bit.
    pub end: bool,
    /// FuType (6 bits).
    pub unit_type: u8,
}

impl H265FuHeaderBits {
    /// Parse the FU header byte. Ports `H265NalUnitFragmentHeader` accessors.
    #[must_use]
    pub fn parse(byte: u8) -> Self {
        H265FuHeaderBits {
            start: (byte >> 7) != 0,
            end: ((byte >> 6) & 0x01) != 0,
            unit_type: byte & 0b11_1111,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_length_prefixed_two_units() {
        // [len=3][A B C][len=2][D E]
        let frame = vec![0, 0, 0, 3, b'A', b'B', b'C', 0, 0, 0, 2, b'D', b'E'];
        let nalus = split_frame(&frame, Separator::Length);
        assert_eq!(nalus, vec![vec![b'A', b'B', b'C'], vec![b'D', b'E']]);
    }

    #[test]
    fn split_length_prefixed_truncated_trailer_ignored() {
        // valid unit then a dangling 2-byte length trailer.
        let frame = vec![0, 0, 0, 1, b'X', 0, 0];
        let nalus = split_frame(&frame, Separator::Length);
        assert_eq!(nalus, vec![vec![b'X']]);
    }

    #[test]
    fn split_annexb_short_start_code() {
        // 00 00 01 [A B] 00 00 01 [C]
        let frame = vec![0, 0, 1, b'A', b'B', 0, 0, 1, b'C'];
        let nalus = split_frame(&frame, Separator::ShortStartSequence);
        assert_eq!(nalus, vec![vec![b'A', b'B'], vec![b'C']]);
    }

    #[test]
    fn split_annexb_long_start_code() {
        // 00 00 00 01 [A] 00 00 00 01 [B C]
        let frame = vec![0, 0, 0, 1, b'A', 0, 0, 0, 1, b'B', b'C'];
        let nalus = split_frame(&frame, Separator::LongStartSequence);
        assert_eq!(nalus, vec![vec![b'A'], vec![b'B', b'C']]);
    }

    #[test]
    fn split_annexb_mixed_start_code() {
        // long then short, with StartSequence (detect both).
        let frame = vec![0, 0, 0, 1, b'A', 0, 0, 1, b'B'];
        let nalus = split_frame(&frame, Separator::StartSequence);
        assert_eq!(nalus, vec![vec![b'A'], vec![b'B']]);
    }

    #[test]
    fn h264_fu_a_round_trip_bits() {
        // NAL header: F=0, NRI=3 (0b11), type=5 (IDR) => 0x65.
        let mut nalu = vec![0x65u8];
        nalu.extend((0..100u8).collect::<Vec<_>>());
        // Force fragmentation with a small max.
        let frags = h264_generate_fragments(&nalu, 40);
        assert!(frags.len() >= 2);
        // First fragment: FU indicator type 28, FU header start bit set.
        let ind0 = H264NalHeaderBits::parse(frags[0][0]);
        assert_eq!(ind0.unit_type, H264_NAL_TYPE_FU_A);
        assert_eq!(ind0.nri, 3);
        let fu0 = H264FuHeaderBits::parse(frags[0][1]);
        assert!(fu0.start);
        assert!(!fu0.end);
        assert_eq!(fu0.unit_type, 5);
        // Last fragment: end bit set.
        let last = frags.last().unwrap();
        let fu_last = H264FuHeaderBits::parse(last[1]);
        assert!(fu_last.end);
        assert!(!fu_last.start);
        // Middle fragments: neither.
        for f in &frags[1..frags.len() - 1] {
            let fu = H264FuHeaderBits::parse(f[1]);
            assert!(!fu.start && !fu.end);
        }
        // Reassemble payload from fragments (drop 2-byte FU headers).
        let mut payload = Vec::new();
        for f in &frags {
            payload.extend_from_slice(&f[2..]);
        }
        assert_eq!(payload, &nalu[1..]);
    }

    #[test]
    fn h265_header_bits_round_trip() {
        // type=19 (IDR_W_RADL), layerId=0, tid+1=1.
        let bits = H265NalHeaderBits {
            forbidden: false,
            unit_type: 19,
            nuh_layer_id: 0,
            nuh_temp_id_plus1: 1,
        };
        let bytes = bits.serialize();
        let parsed = H265NalHeaderBits::parse(bytes[0], bytes[1]);
        assert_eq!(parsed.unit_type, 19);
        assert_eq!(parsed.nuh_layer_id, 0);
        assert_eq!(parsed.nuh_temp_id_plus1, 1);
        assert!(!parsed.forbidden);
    }

    #[test]
    fn h265_fu_round_trip_bits() {
        // 2-byte header: type=19, layer=0, tid+1=1.
        let hdr = H265NalHeaderBits {
            forbidden: false,
            unit_type: 19,
            nuh_layer_id: 0,
            nuh_temp_id_plus1: 1,
        }
        .serialize();
        let mut nalu = vec![hdr[0], hdr[1]];
        nalu.extend((0..120u8).collect::<Vec<_>>());
        let frags = h265_generate_fragments(&nalu, 40);
        assert!(frags.len() >= 2);
        // First fragment: 2-byte NAL header type=49(FU), FU header start set, FuType=19.
        let ind = H265NalHeaderBits::parse(frags[0][0], frags[0][1]);
        assert_eq!(ind.unit_type, H265_NAL_TYPE_FU);
        let fu0 = H265FuHeaderBits::parse(frags[0][2]);
        assert!(fu0.start && !fu0.end);
        assert_eq!(fu0.unit_type, 19);
        let last = frags.last().unwrap();
        let fu_last = H265FuHeaderBits::parse(last[2]);
        assert!(fu_last.end && !fu_last.start);
        // Reassemble payload (drop 3-byte FU prefix).
        let mut payload = Vec::new();
        for f in &frags {
            payload.extend_from_slice(&f[3..]);
        }
        assert_eq!(payload, &nalu[2..]);
    }
}
