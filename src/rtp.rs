//! RTP / RTCP header codec — a native Rust port of libdatachannel's
//! `src/rtp.cpp` (and `include/rtc/rtp.hpp`).
//!
//! libdatachannel keeps these structures in **network byte order** (big-endian)
//! in a packed C struct, and exposes accessors that byte-swap. Here we instead
//! parse/serialize explicitly from byte slices using `u16::from_be_bytes` /
//! `to_be_bytes`, which is the safe-Rust equivalent and avoids unaligned
//! `reinterpret_cast` over packed structs. The on-the-wire layout is identical.
//!
//! Scope (task #19): the RTP fixed header, the RTP extension header preamble,
//! the RTCP common header, the RTCP report block, and the SR / RR structures
//! (plus SDES/BYE/FB headers as needed). Codec-specific (de)packetizers are
//! task #20; PLI/REMB/NACK media handlers are task #21 — only the byte-layout
//! primitives they need live here.

/// SSRC (synchronization source identifier), as in `rtc::SSRC`.
pub type Ssrc = u32;

/// Size of the RTP fixed header, in bytes (no CSRCs, no extension).
pub const RTP_HEADER_SIZE: usize = 12;

/// Size of the RTCP common header, in bytes.
pub const RTCP_HEADER_SIZE: usize = 4;

/// Size of one RTCP report block, in bytes.
pub const RTCP_REPORT_BLOCK_SIZE: usize = 24;

/// RTCP payload type for a Sender Report (SR).
pub const RTCP_PT_SR: u8 = 200;
/// RTCP payload type for a Receiver Report (RR).
pub const RTCP_PT_RR: u8 = 201;
/// RTCP payload type for a Source Description (SDES).
pub const RTCP_PT_SDES: u8 = 202;
/// RTCP payload type for Goodbye (BYE).
pub const RTCP_PT_BYE: u8 = 203;

/// Demultiplex RTP vs RTCP by payload type (RFC 5761 §4).
///
/// Ports `rtc::IsRtcp`. A packet is treated as RTCP when its 7-bit payload-type
/// field is in the reserved range 64..=95. Packets shorter than 8 bytes are not
/// RTCP.
#[must_use]
pub fn is_rtcp(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    let payload_type = data[1] & 0x7F;
    (64..=95).contains(&payload_type)
}

// ---------------------------------------------------------------------------
// RTP fixed header
// ---------------------------------------------------------------------------

/// The RTP fixed header (RFC 3550 §5.1). Mirrors `rtc::RtpHeader`.
///
/// On the wire (big-endian):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|X|  CC   |M|     PT      |       sequence number         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           synchronization source (SSRC) identifier            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            contributing source (CSRC) identifiers             |
/// |                             ....                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpHeader {
    /// Protocol version (always 2 for RFC 3550 RTP).
    pub version: u8,
    /// Padding flag.
    pub padding: bool,
    /// Extension flag (an RTP header extension follows the CSRC list).
    pub extension: bool,
    /// Marker bit.
    pub marker: bool,
    /// 7-bit payload type.
    pub payload_type: u8,
    /// Sequence number.
    pub sequence_number: u16,
    /// Timestamp.
    pub timestamp: u32,
    /// Synchronization source.
    pub ssrc: Ssrc,
    /// Contributing sources (0..=15 entries).
    pub csrc: Vec<Ssrc>,
}

impl Default for RtpHeader {
    fn default() -> Self {
        RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            marker: false,
            payload_type: 0,
            sequence_number: 0,
            timestamp: 0,
            ssrc: 0,
            csrc: Vec::new(),
        }
    }
}

impl RtpHeader {
    /// On-the-wire size of the fixed header plus the CSRC list (excludes any
    /// extension header). Mirrors `RtpHeader::getSize`.
    #[must_use]
    pub fn size(&self) -> usize {
        RTP_HEADER_SIZE + self.csrc.len() * 4
    }

    /// CSRC count (the `CC` field).
    #[must_use]
    pub fn csrc_count(&self) -> u8 {
        self.csrc.len() as u8
    }

    /// Serialize the fixed header (and CSRC list) into a freshly-allocated
    /// buffer of length [`size`](Self::size). The extension-header bytes (if
    /// any) are written separately by the packetizer.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.size()];
        self.write_to(&mut out);
        out
    }

    /// Serialize into the front of `out`, which must be at least
    /// [`size`](Self::size) bytes. Returns the number of bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> usize {
        let n = self.size();
        assert!(out.len() >= n, "RtpHeader::write_to buffer too small");
        // Byte 0: V(2) P(1) X(1) CC(4)
        let cc = self.csrc.len() as u8 & 0x0F;
        out[0] = ((self.version & 0x03) << 6)
            | ((self.padding as u8) << 5)
            | ((self.extension as u8) << 4)
            | cc;
        // Byte 1: M(1) PT(7)
        out[1] = ((self.marker as u8) << 7) | (self.payload_type & 0x7F);
        out[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        out[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        out[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        let mut off = 12;
        for c in &self.csrc {
            out[off..off + 4].copy_from_slice(&c.to_be_bytes());
            off += 4;
        }
        n
    }

    /// Parse a fixed header (plus CSRC list) from the front of `data`. Returns
    /// the header and the number of bytes consumed (the offset to the body or
    /// extension header). `None` if the buffer is too short for the declared
    /// CSRC count.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<(RtpHeader, usize)> {
        if data.len() < RTP_HEADER_SIZE {
            return None;
        }
        let first = data[0];
        let version = first >> 6;
        let padding = (first >> 5) & 0x01 != 0;
        let extension = (first >> 4) & 0x01 != 0;
        let cc = (first & 0x0F) as usize;
        let second = data[1];
        let marker = (second & 0x80) != 0;
        let payload_type = second & 0x7F;
        let sequence_number = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let total = RTP_HEADER_SIZE + cc * 4;
        if data.len() < total {
            return None;
        }
        let mut csrc = Vec::with_capacity(cc);
        for i in 0..cc {
            let o = RTP_HEADER_SIZE + i * 4;
            csrc.push(u32::from_be_bytes([
                data[o],
                data[o + 1],
                data[o + 2],
                data[o + 3],
            ]));
        }

        Some((
            RtpHeader {
                version,
                padding,
                extension,
                marker,
                payload_type,
                sequence_number,
                timestamp,
                ssrc,
                csrc,
            },
            total,
        ))
    }
}

/// The RTP header extension preamble (RFC 3550 §5.3.1 / RFC 8285). Mirrors
/// `rtc::RtpExtensionHeader`. The body that follows is `header_length * 4`
/// bytes. Only the preamble is modelled here; per-element one/two-byte writers
/// are needed by the packetizer once header extensions are wired (#20+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpExtensionHeader {
    /// `profileSpecificId`: `0xbede` (one-byte) or `0x1000` (two-byte).
    pub profile_specific_id: u16,
    /// Number of 32-bit words of extension body that follow.
    pub header_length: u16,
}

impl RtpExtensionHeader {
    /// Size of the extension body in bytes (`headerLength * 4`).
    #[must_use]
    pub fn body_size(&self) -> usize {
        self.header_length as usize * 4
    }

    /// Total size of the extension (4-byte preamble + body).
    #[must_use]
    pub fn total_size(&self) -> usize {
        4 + self.body_size()
    }

    /// Serialize just the 4-byte preamble.
    #[must_use]
    pub fn serialize_preamble(&self) -> [u8; 4] {
        let mut out = [0u8; 4];
        out[0..2].copy_from_slice(&self.profile_specific_id.to_be_bytes());
        out[2..4].copy_from_slice(&self.header_length.to_be_bytes());
        out
    }

    /// Parse the 4-byte preamble from the front of `data`.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<RtpExtensionHeader> {
        if data.len() < 4 {
            return None;
        }
        Some(RtpExtensionHeader {
            profile_specific_id: u16::from_be_bytes([data[0], data[1]]),
            header_length: u16::from_be_bytes([data[2], data[3]]),
        })
    }
}

// ---------------------------------------------------------------------------
// RTCP common header
// ---------------------------------------------------------------------------

/// The RTCP common header (RFC 3550 §6.4.1). Mirrors `rtc::RtcpHeader`.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|   RC    |       PT      |             length            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// `length` is in 32-bit words minus one (i.e. the packet is `(length+1)*4`
/// bytes), matching the C++ `length()` / `lengthInBytes()` accessors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcpHeader {
    /// Protocol version (2).
    pub version: u8,
    /// Padding flag.
    pub padding: bool,
    /// Reception report count / format (the 5-bit `RC`/`FMT` field).
    pub report_count: u8,
    /// Packet type (200=SR, 201=RR, ...).
    pub payload_type: u8,
    /// Length in 32-bit words minus one.
    pub length: u16,
}

impl Default for RtcpHeader {
    fn default() -> Self {
        RtcpHeader {
            version: 2,
            padding: false,
            report_count: 0,
            payload_type: 0,
            length: 0,
        }
    }
}

impl RtcpHeader {
    /// Build a header the way `RtcpHeader::prepareHeader` does: version 2, no
    /// padding, with the given report count / payload type / length.
    #[must_use]
    pub fn prepare(payload_type: u8, report_count: u8, length: u16) -> Self {
        RtcpHeader {
            version: 2,
            padding: false,
            report_count: report_count & 0x1F,
            payload_type,
            length,
        }
    }

    /// Length of the whole RTCP packet in bytes (`(length + 1) * 4`). Mirrors
    /// `RtcpHeader::lengthInBytes`.
    #[must_use]
    pub fn length_in_bytes(&self) -> usize {
        (1 + self.length as usize) * 4
    }

    /// Serialize the 4-byte common header.
    #[must_use]
    pub fn serialize(&self) -> [u8; 4] {
        let mut out = [0u8; 4];
        out[0] = ((self.version & 0x03) << 6)
            | ((self.padding as u8) << 5)
            | (self.report_count & 0x1F);
        out[1] = self.payload_type;
        out[2..4].copy_from_slice(&self.length.to_be_bytes());
        out
    }

    /// Parse the 4-byte common header from the front of `data`.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<RtcpHeader> {
        if data.len() < RTCP_HEADER_SIZE {
            return None;
        }
        let first = data[0];
        Some(RtcpHeader {
            version: first >> 6,
            padding: (first >> 5) & 0x01 != 0,
            report_count: first & 0x1F,
            payload_type: data[1],
            length: u16::from_be_bytes([data[2], data[3]]),
        })
    }
}

/// One RTCP reception report block (RFC 3550 §6.4.1). Mirrors
/// `rtc::RtcpReportBlock`. The fraction-lost (8-bit) and cumulative-packets-lost
/// (24-bit) fields share one 32-bit word, exactly as in the C++ struct.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RtcpReportBlock {
    /// SSRC of the source this report is about.
    pub ssrc: Ssrc,
    /// Fraction of packets lost since the last report (8-bit fixed point).
    pub fraction_lost: u8,
    /// Cumulative number of packets lost (24-bit, stored in the low 3 bytes).
    pub packets_lost: u32,
    /// High 16 bits of the extended highest sequence number (the cycle count).
    pub seq_no_cycles: u16,
    /// Low 16 bits of the extended highest sequence number.
    pub highest_seq_no: u16,
    /// Interarrival jitter.
    pub jitter: u32,
    /// Middle 32 bits of the NTP timestamp of the last SR received.
    pub last_sr: u32,
    /// Delay since last SR, in units of 1/65536 s.
    pub delay_since_last_sr: u32,
}

impl RtcpReportBlock {
    /// Extended highest sequence number (`seqNoCycles << 16 | highestSeqNo`).
    #[must_use]
    pub fn extended_highest_seq_no(&self) -> u32 {
        ((self.seq_no_cycles as u32) << 16) | self.highest_seq_no as u32
    }

    /// Serialize the 24-byte report block.
    #[must_use]
    pub fn serialize(&self) -> [u8; RTCP_REPORT_BLOCK_SIZE] {
        let mut out = [0u8; RTCP_REPORT_BLOCK_SIZE];
        out[0..4].copy_from_slice(&self.ssrc.to_be_bytes());
        // fractionLost (8) | packetsLost (24)
        let word = ((self.fraction_lost as u32) << 24) | (self.packets_lost & 0x00FF_FFFF);
        out[4..8].copy_from_slice(&word.to_be_bytes());
        out[8..10].copy_from_slice(&self.seq_no_cycles.to_be_bytes());
        out[10..12].copy_from_slice(&self.highest_seq_no.to_be_bytes());
        out[12..16].copy_from_slice(&self.jitter.to_be_bytes());
        out[16..20].copy_from_slice(&self.last_sr.to_be_bytes());
        out[20..24].copy_from_slice(&self.delay_since_last_sr.to_be_bytes());
        out
    }

    /// Parse a 24-byte report block from the front of `data`.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<RtcpReportBlock> {
        if data.len() < RTCP_REPORT_BLOCK_SIZE {
            return None;
        }
        let ssrc = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let word = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        Some(RtcpReportBlock {
            ssrc,
            fraction_lost: (word >> 24) as u8,
            packets_lost: word & 0x00FF_FFFF,
            seq_no_cycles: u16::from_be_bytes([data[8], data[9]]),
            highest_seq_no: u16::from_be_bytes([data[10], data[11]]),
            jitter: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            last_sr: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
            delay_since_last_sr: u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        })
    }
}

/// An RTCP Sender Report (RFC 3550 §6.4.1). Mirrors `rtc::RtcpSr`. The sender
/// info block is 20 bytes (SSRC + NTP(8) + RTP TS + packet count + octet count),
/// followed by `report_count` report blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpSr {
    /// SSRC of the sender.
    pub sender_ssrc: Ssrc,
    /// 64-bit NTP timestamp.
    pub ntp_timestamp: u64,
    /// RTP timestamp corresponding to `ntp_timestamp`.
    pub rtp_timestamp: u32,
    /// Sender's packet count.
    pub packet_count: u32,
    /// Sender's octet count.
    pub octet_count: u32,
    /// Reception report blocks.
    pub report_blocks: Vec<RtcpReportBlock>,
}

impl RtcpSr {
    /// Byte size of an SR with `report_count` report blocks. Mirrors
    /// `RtcpSr::Size`: common header (4) + sender info (20) + blocks.
    #[must_use]
    pub fn size_with_blocks(report_count: usize) -> usize {
        // C++ uses sizeof(RtcpHeader)=4 + 24 (senderSSRC 4 + ntp 8 + rtpTs 4 +
        // packetCount 4 + octetCount 4) + reportCount * 24.
        RTCP_HEADER_SIZE + 24 + report_count * RTCP_REPORT_BLOCK_SIZE
    }

    /// Serialize the full SR packet (header + sender info + report blocks).
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let rc = self.report_blocks.len();
        let total = Self::size_with_blocks(rc);
        let length_words = (total / 4) as u16 - 1;
        let header = RtcpHeader::prepare(RTCP_PT_SR, rc as u8, length_words);
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&header.serialize());
        out.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        out.extend_from_slice(&self.ntp_timestamp.to_be_bytes());
        out.extend_from_slice(&self.rtp_timestamp.to_be_bytes());
        out.extend_from_slice(&self.packet_count.to_be_bytes());
        out.extend_from_slice(&self.octet_count.to_be_bytes());
        for b in &self.report_blocks {
            out.extend_from_slice(&b.serialize());
        }
        out
    }

    /// Parse a full SR packet from `data`.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<RtcpSr> {
        let header = RtcpHeader::parse(data)?;
        if header.payload_type != RTCP_PT_SR {
            return None;
        }
        // header(4) + senderSSRC(4) + ntp(8) + rtpTs(4) + packetCount(4) + octetCount(4) = 24
        if data.len() < 24 {
            return None;
        }
        let sender_ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ntp_timestamp = u64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let rtp_timestamp = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let packet_count = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let octet_count = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

        let mut report_blocks = Vec::with_capacity(header.report_count as usize);
        let mut off = 28;
        for _ in 0..header.report_count {
            let block = RtcpReportBlock::parse(data.get(off..)?)?;
            report_blocks.push(block);
            off += RTCP_REPORT_BLOCK_SIZE;
        }
        Some(RtcpSr {
            sender_ssrc,
            ntp_timestamp,
            rtp_timestamp,
            packet_count,
            octet_count,
            report_blocks,
        })
    }
}

/// An RTCP Receiver Report (RFC 3550 §6.4.2). Mirrors `rtc::RtcpRr`: common
/// header + reporter SSRC + report blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpRr {
    /// SSRC of the reporter (the packet sender).
    pub sender_ssrc: Ssrc,
    /// Reception report blocks.
    pub report_blocks: Vec<RtcpReportBlock>,
}

impl RtcpRr {
    /// Byte size of an RR with `report_count` blocks. Mirrors
    /// `RtcpRr::SizeWithReportBlocks`: header(4) + senderSSRC(4) + blocks.
    #[must_use]
    pub fn size_with_blocks(report_count: usize) -> usize {
        RTCP_HEADER_SIZE + 4 + report_count * RTCP_REPORT_BLOCK_SIZE
    }

    /// Serialize the full RR packet.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let rc = self.report_blocks.len();
        let total = Self::size_with_blocks(rc);
        let length_words = (total / 4) as u16 - 1;
        let header = RtcpHeader::prepare(RTCP_PT_RR, rc as u8, length_words);
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&header.serialize());
        out.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        for b in &self.report_blocks {
            out.extend_from_slice(&b.serialize());
        }
        out
    }

    /// Parse a full RR packet from `data`.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<RtcpRr> {
        let header = RtcpHeader::parse(data)?;
        if header.payload_type != RTCP_PT_RR {
            return None;
        }
        if data.len() < RTCP_HEADER_SIZE + 4 {
            return None;
        }
        let sender_ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let mut report_blocks = Vec::with_capacity(header.report_count as usize);
        let mut off = 8;
        for _ in 0..header.report_count {
            let block = RtcpReportBlock::parse(data.get(off..)?)?;
            report_blocks.push(block);
            off += RTCP_REPORT_BLOCK_SIZE;
        }
        Some(RtcpRr {
            sender_ssrc,
            report_blocks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtp_header_round_trip_all_fields() {
        let h = RtpHeader {
            version: 2,
            padding: true,
            extension: true,
            marker: true,
            payload_type: 96,
            sequence_number: 0x1234,
            timestamp: 0xDEAD_BEEF,
            ssrc: 0x0BAD_F00D,
            csrc: vec![0x1111_2222, 0x3333_4444],
        };
        let bytes = h.serialize();
        let (parsed, consumed) = RtpHeader::parse(&bytes).expect("parse");
        assert_eq!(consumed, h.size());
        assert_eq!(consumed, 12 + 2 * 4);
        assert_eq!(parsed, h);
        // Every field individually for clarity.
        assert_eq!(parsed.version, 2);
        assert!(parsed.padding);
        assert!(parsed.extension);
        assert!(parsed.marker);
        assert_eq!(parsed.payload_type, 96);
        assert_eq!(parsed.sequence_number, 0x1234);
        assert_eq!(parsed.timestamp, 0xDEAD_BEEF);
        assert_eq!(parsed.ssrc, 0x0BAD_F00D);
        assert_eq!(parsed.csrc, vec![0x1111_2222, 0x3333_4444]);
    }

    #[test]
    fn rtp_header_known_good_byte_layout() {
        // Hand-construct a known-good RTP header:
        //   version=2, padding=0, extension=0, CC=0  -> first byte 0x80
        //   marker=1, PT=96 (0x60)                    -> second byte 0xE0
        //   seq = 0x0102, ts = 0x03040506, ssrc = 0x0708090A
        let h = RtpHeader {
            version: 2,
            marker: true,
            payload_type: 96,
            sequence_number: 0x0102,
            timestamp: 0x0304_0506,
            ssrc: 0x0708_090A,
            ..RtpHeader::default()
        };
        let bytes = h.serialize();
        let expected: [u8; 12] = [
            0x80, // V=2, P=0, X=0, CC=0
            0xE0, // M=1, PT=96 (0x60)  => 0x80 | 0x60 = 0xE0
            0x01, 0x02, // sequence number (big-endian)
            0x03, 0x04, 0x05, 0x06, // timestamp (big-endian)
            0x07, 0x08, 0x09, 0x0A, // ssrc (big-endian)
        ];
        assert_eq!(bytes, expected, "RTP header byte layout must match");

        // The marker/PT shared byte: clearing the marker drops the top bit.
        let no_mark = RtpHeader {
            marker: false,
            ..h.clone()
        };
        assert_eq!(no_mark.serialize()[1], 0x60, "PT only, no marker");

        // CSRC count lives in the low nibble of byte 0.
        let with_csrc = RtpHeader {
            csrc: vec![0xAABB_CCDD, 0x1122_3344, 0x5566_7788],
            ..h.clone()
        };
        let cb = with_csrc.serialize();
        assert_eq!(cb[0] & 0x0F, 3, "CC nibble = number of CSRCs");
        assert_eq!(cb[0], 0x83, "V=2 + CC=3");
        assert_eq!(cb.len(), 12 + 3 * 4); // 24 bytes total
        assert_eq!(&cb[12..16], &[0xAA, 0xBB, 0xCC, 0xDD]); // 1st CSRC
        assert_eq!(&cb[16..20], &[0x11, 0x22, 0x33, 0x44]); // 2nd CSRC
        assert_eq!(&cb[20..24], &[0x55, 0x66, 0x77, 0x88]); // 3rd CSRC
    }

    #[test]
    fn rtp_header_version_and_flag_isolation() {
        // Verify each flag bit lands in the right position of byte 0.
        let base = RtpHeader::default();
        assert_eq!(base.serialize()[0], 0x80); // just V=2

        let p = RtpHeader { padding: true, ..RtpHeader::default() };
        assert_eq!(p.serialize()[0], 0xA0); // V=2 | P

        let x = RtpHeader { extension: true, ..RtpHeader::default() };
        assert_eq!(x.serialize()[0], 0x90); // V=2 | X
    }

    #[test]
    fn rtp_header_parse_too_short() {
        assert!(RtpHeader::parse(&[0x80, 0x60, 0x00]).is_none());
        // Declares CC=1 but no room for the CSRC.
        let mut buf = [0u8; 12];
        buf[0] = 0x81; // V=2, CC=1
        assert!(RtpHeader::parse(&buf).is_none());
    }

    #[test]
    fn is_rtcp_demux_ranges() {
        // PT 200 (SR) is in 64..=95? No — 200 & 0x7F = 72 -> in range. SR is RTCP.
        let mut sr = vec![0x80u8, 200, 0, 0, 0, 0, 0, 0];
        assert!(is_rtcp(&sr));
        sr[1] = 201; // RR, 201 & 0x7F = 73
        assert!(is_rtcp(&sr));
        // Dynamic RTP PT 96 -> not RTCP.
        let rtp = vec![0x80u8, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(!is_rtcp(&rtp));
        // Too short.
        assert!(!is_rtcp(&[0x80, 200, 0]));
    }

    #[test]
    fn rtcp_header_round_trip_and_length() {
        let h = RtcpHeader::prepare(RTCP_PT_SR, 2, 17);
        let bytes = h.serialize();
        let parsed = RtcpHeader::parse(&bytes).expect("parse");
        assert_eq!(parsed, h);
        assert_eq!(parsed.version, 2);
        assert!(!parsed.padding);
        assert_eq!(parsed.report_count, 2);
        assert_eq!(parsed.payload_type, RTCP_PT_SR);
        assert_eq!(parsed.length, 17);
        assert_eq!(parsed.length_in_bytes(), (17 + 1) * 4);
        // Byte layout: first = 0x80 | RC=2 = 0x82.
        assert_eq!(bytes[0], 0x82);
        assert_eq!(bytes[1], 200);
        assert_eq!(&bytes[2..4], &[0x00, 0x11]); // 17
    }

    #[test]
    fn rtcp_sr_round_trip() {
        let sr = RtcpSr {
            sender_ssrc: 0x1234_5678,
            ntp_timestamp: 0x1122_3344_5566_7788,
            rtp_timestamp: 0x9ABC_DEF0,
            packet_count: 42,
            octet_count: 99999,
            report_blocks: vec![RtcpReportBlock {
                ssrc: 0xAABB_CCDD,
                fraction_lost: 5,
                packets_lost: 0x00AB_CDEF & 0x00FF_FFFF,
                seq_no_cycles: 1,
                highest_seq_no: 0x4242,
                jitter: 777,
                last_sr: 0x1357_9BDF,
                delay_since_last_sr: 0x0002_0000,
            }],
        };
        let bytes = sr.serialize();
        assert_eq!(bytes.len(), RtcpSr::size_with_blocks(1));
        let parsed = RtcpSr::parse(&bytes).expect("parse sr");
        assert_eq!(parsed, sr);
        // Report block extended seq no helper.
        assert_eq!(
            parsed.report_blocks[0].extended_highest_seq_no(),
            (1u32 << 16) | 0x4242
        );
    }

    #[test]
    fn rtcp_sr_no_report_blocks() {
        let sr = RtcpSr {
            sender_ssrc: 1,
            ntp_timestamp: 2,
            rtp_timestamp: 3,
            packet_count: 4,
            octet_count: 5,
            report_blocks: vec![],
        };
        let bytes = sr.serialize();
        assert_eq!(bytes.len(), RtcpSr::size_with_blocks(0));
        // length field = total/4 - 1 = 28/4 - 1 = 6.
        let h = RtcpHeader::parse(&bytes).unwrap();
        assert_eq!(h.length, 6);
        assert_eq!(RtcpSr::parse(&bytes).unwrap(), sr);
    }

    #[test]
    fn rtcp_rr_round_trip() {
        let rr = RtcpRr {
            sender_ssrc: 0xCAFE_BABE,
            report_blocks: vec![
                RtcpReportBlock {
                    ssrc: 0x1111_1111,
                    fraction_lost: 0,
                    packets_lost: 0,
                    seq_no_cycles: 0,
                    highest_seq_no: 100,
                    jitter: 0,
                    last_sr: 0,
                    delay_since_last_sr: 0,
                },
                RtcpReportBlock {
                    ssrc: 0x2222_2222,
                    fraction_lost: 128,
                    packets_lost: 0xFFFFFF,
                    seq_no_cycles: 7,
                    highest_seq_no: 0xFFFF,
                    jitter: 0xDEAD_BEEF,
                    last_sr: 0x1234_5678,
                    delay_since_last_sr: 0x90AB_CDEF,
                },
            ],
        };
        let bytes = rr.serialize();
        assert_eq!(bytes.len(), RtcpRr::size_with_blocks(2));
        let parsed = RtcpRr::parse(&bytes).expect("parse rr");
        assert_eq!(parsed, rr);
        // 24-bit packets_lost must not bleed into fraction_lost.
        assert_eq!(parsed.report_blocks[1].fraction_lost, 128);
        assert_eq!(parsed.report_blocks[1].packets_lost, 0xFFFFFF);
    }

    #[test]
    fn rtp_extension_header_preamble() {
        let ext = RtpExtensionHeader {
            profile_specific_id: 0xBEDE,
            header_length: 3,
        };
        let bytes = ext.serialize_preamble();
        assert_eq!(bytes, [0xBE, 0xDE, 0x00, 0x03]);
        assert_eq!(ext.body_size(), 12);
        assert_eq!(ext.total_size(), 16);
        let parsed = RtpExtensionHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, ext);
    }
}
