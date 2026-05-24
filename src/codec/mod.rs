//! Codec-specific RTP packetizers (H.264, H.265, VP8, AV1) — task #20.
//!
//! These plug into the generic [`RtpPacketizer`](crate::rtp_packetizer::RtpPacketizer)
//! from task #19. The C++ `RtpPacketizer` is a base class whose subclasses
//! override one virtual method, `fragment(binary) -> vector<binary>`: the codec
//! turns a coded frame into a list of RTP *payloads*, and the base class wraps
//! each payload in an RTP header (`packetize`), marking the last one.
//!
//! # The seam
//!
//! We mirror that exactly with a [`Fragmenter`] trait — the single override
//! point — plus per-codec packetizer structs that **own** an `RtpPacketizer`
//! (composition, since Rust has no inheritance). Each struct exposes:
//!
//! - `fragment(&self, frame) -> Vec<Vec<u8>>` — the codec's payload split, and
//! - `outgoing(&self, frame) -> Vec<Vec<u8>>` — fragment, then
//!   [`RtpPacketizer::packetize`](crate::rtp_packetizer::RtpPacketizer::packetize)
//!   each fragment with the marker bit on the last (the per-frame loop from the
//!   C++ `RtpPacketizer::outgoing`).
//!
//! The generic identity `fragment` already on `RtpPacketizer` is the default
//! impl; these modules provide the codec overrides.
//!
//! # What is implemented
//!
//! - **NAL foundation** ([`nal`]): frame → NAL units (length-prefixed and
//!   Annex-B), H.264 FU-A and H.265 FU fragment construction.
//! - **H.264** ([`h264`]): packetizer (single NAL / FU-A) + depacketizer
//!   (FU-A reassembly, STAP-A split).
//! - **H.265** ([`h265`]): packetizer (single NAL / FU) + depacketizer
//!   (FU reassembly, AP split).
//! - **VP8** ([`vp8`]): packetizer (1-byte payload descriptor) + depacketizer
//!   (RFC 7741 partition reconstruction).
//! - **AV1** ([`av1`]): packetizer (OBU / temporal-unit, aggregation header,
//!   LEB128). libdatachannel ships **no** AV1 depacketizer, so none is ported.

pub mod av1;
pub mod h264;
pub mod h265;
pub mod nal;
pub mod vp8;

pub use nal::Separator;

/// The codec-specific fragmentation override point. Ports the single virtual
/// `RtpPacketizer::fragment(binary) -> std::vector<binary>` that each codec
/// subclass overrides: split a coded frame into the list of RTP payloads.
///
/// The generic base ([`RtpPacketizer`](crate::rtp_packetizer::RtpPacketizer))
/// returns the frame unchanged (identity); the implementors here split per
/// codec. `&mut self` because some packetizers carry state across frames (AV1
/// caches a sequence-header OBU, mirroring `mSequenceHeader`).
pub trait Fragmenter {
    /// Split a coded `frame` into RTP payloads (each later wrapped in an RTP
    /// header by `packetize`). May return empty (e.g. an AV1 sequence header
    /// that is cached for the next OBU).
    fn fragment(&mut self, frame: Vec<u8>) -> Vec<Vec<u8>>;
}

/// Default max fragment size: `RTC_DEFAULT_MAX_FRAGMENT_SIZE = MTU(1280) - 12 -
/// 8 - 40` (RTP/UDP/IPv6), i.e. 1220. `DefaultMaxFragmentSize`.
pub const DEFAULT_MAX_FRAGMENT_SIZE: usize = 1280 - 12 - 8 - 40;

/// A reassembled coded frame: `(frame bytes, RTP timestamp, payload type)`.
/// Returned by the codec depacketizers' `reassemble`.
pub type ReassembledFrame = (Vec<u8>, u32, u8);
