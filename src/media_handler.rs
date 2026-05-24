//! Media handler chain — a native Rust port of libdatachannel's
//! `MediaHandler` family (`src/mediahandler.cpp`, `src/rtcpreceivingsession.cpp`,
//! `src/rtcpsrreporter.cpp`, `src/plihandler.cpp`, `src/rembhandler.cpp`,
//! `src/rtcpnackresponder.cpp`, `src/pacinghandler.cpp`).
//!
//! A [`MediaHandler`] transforms the stream of [`Message`]s flowing through a
//! [`Track`](crate::Track): the **incoming** path (peer → application) and the
//! **outgoing** path (application → peer). Handlers are linked into a
//! [`MediaHandlerChain`].
//!
//! ## Chain ordering (mirrors the C++ `incomingChain` / `outgoingChain`)
//!
//! In libdatachannel `incomingChain` recurses to the *end* of the chain and runs
//! each handler's `incoming` on the way back, so **incoming runs in reverse
//! order** (tail first, head last). `outgoingChain` runs each handler's
//! `outgoing` *before* recursing, so **outgoing runs in forward order** (head
//! first, tail last). [`MediaHandlerChain`] reproduces this exactly.
//!
//! ## `Message` representation
//!
//! Rather than carry raw `Vec<u8>` and re-run [`is_rtcp`](crate::is_rtcp) at
//! every handler, this module introduces a minimal [`Message`] mirroring the
//! C++ `Message` `Binary`/`Control` distinction that the handlers branch on
//! (RTP media vs RTCP control). The byte layout is unchanged; codecs continue to
//! use the [`rtp`](crate::rtp) primitives.
//!
//! ## Threading
//!
//! These handlers sit on the synchronous media path and take `&mut self`,
//! matching the design guidance — no `Arc<Mutex>` is used. The C++
//! `PacingHandler` offloads to a thread pool timer; the Rust port keeps the
//! pacing *budget arithmetic* deterministic and testable by draining the buffer
//! against an explicit elapsed-time input (see [`PacingHandler`]), leaving the
//! actual timer scheduling to the caller's media loop.

use std::collections::HashMap;
use std::collections::VecDeque;

use crate::rtp::{
    is_rtcp, RtcpNack, RtcpPli, RtcpRemb, RtcpRr, RtcpSr, RtpHeader, Ssrc, RTCP_PT_RR, RTCP_PT_SR,
};

/// Whether a [`Message`] carries RTP media or RTCP control. Mirrors the
/// `Message::Binary` vs `Message::Control` distinction the C++ handlers branch
/// on. (`String`/`Reset` do not appear on the media path.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// RTP media (`Message::Binary`).
    Binary,
    /// RTCP control (`Message::Control`).
    Control,
}

/// A message flowing through the media handler chain. The raw bytes plus a
/// [`MessageType`] tag, mirroring the relevant fields of the C++ `Message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The packet bytes (RTP or RTCP).
    pub data: Vec<u8>,
    /// Whether this is media or control.
    pub kind: MessageType,
}

impl Message {
    /// A media (`Binary`) message.
    #[must_use]
    pub fn binary(data: Vec<u8>) -> Self {
        Message {
            data,
            kind: MessageType::Binary,
        }
    }

    /// A control (`Control`) message.
    #[must_use]
    pub fn control(data: Vec<u8>) -> Self {
        Message {
            data,
            kind: MessageType::Control,
        }
    }

    /// Classify raw bytes as media or control via [`is_rtcp`], as the transport
    /// does before handing a packet to the chain.
    #[must_use]
    pub fn classify(data: Vec<u8>) -> Self {
        let kind = if is_rtcp(&data) {
            MessageType::Control
        } else {
            MessageType::Binary
        };
        Message { data, kind }
    }

    /// Size of the message in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the message is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Outbound sink for messages a handler generates out-of-band (e.g. an RR/REMB
/// emitted in response to a received SR, or a retransmitted packet for a NACK).
/// Mirrors the C++ `message_callback &send`. The chain collects everything sent
/// here so the caller can flush it to the transport.
#[derive(Debug, Default)]
pub struct Sender {
    queued: Vec<Message>,
}

impl Sender {
    /// Create an empty sender.
    #[must_use]
    pub fn new() -> Self {
        Sender { queued: Vec::new() }
    }

    /// Queue a message to be sent to the peer. Mirrors invoking `send(message)`.
    pub fn send(&mut self, message: Message) {
        self.queued.push(message);
    }

    /// Take everything queued so far, leaving the sender empty.
    #[must_use]
    pub fn take(&mut self) -> Vec<Message> {
        std::mem::take(&mut self.queued)
    }

    /// Borrow the queued messages.
    #[must_use]
    pub fn queued(&self) -> &[Message] {
        &self.queued
    }
}

/// A media handler — a node in the [`MediaHandlerChain`]. Ports `rtc::MediaHandler`.
///
/// Each method has a default no-op so a handler implements only the direction it
/// cares about (matching the C++ virtuals).
///
/// Handlers are stored behind a [`Track`](crate::Track)'s `Arc<Self>` +
/// `Mutex<Inner>`, which the SRTP receive callback drives from a Tokio runtime
/// thread, so the trait requires [`Send`].
pub trait MediaHandler: Send {
    /// Transform messages coming **from** the peer. May filter/rewrite the
    /// vector in place and may queue control replies via `sender`.
    fn incoming(&mut self, _messages: &mut Vec<Message>, _sender: &mut Sender) {}

    /// Transform messages going **to** the peer. May filter/rewrite the vector
    /// in place and may queue extra messages via `sender`.
    fn outgoing(&mut self, _messages: &mut Vec<Message>, _sender: &mut Sender) {}

    /// Request a keyframe from the peer (PLI/FIR). Returns `true` if handled.
    /// Mirrors `MediaHandler::requestKeyframe`'s default of delegating.
    fn request_keyframe(&mut self, _sender: &mut Sender) -> bool {
        false
    }

    /// Request a target bitrate from the peer (REMB). Returns `true` if handled.
    fn request_bitrate(&mut self, _bitrate: u64, _sender: &mut Sender) -> bool {
        false
    }
}

/// An ordered chain of [`MediaHandler`]s. Ports the `addToChain` / `incomingChain`
/// / `outgoingChain` behaviour of `rtc::MediaHandler` without the `shared_ptr`
/// linked list: the handlers are simply owned in a `Vec`, and the directional
/// traversal order is applied here.
#[derive(Default)]
pub struct MediaHandlerChain {
    handlers: Vec<Box<dyn MediaHandler>>,
}

impl MediaHandlerChain {
    /// An empty chain.
    #[must_use]
    pub fn new() -> Self {
        MediaHandlerChain {
            handlers: Vec::new(),
        }
    }

    /// Append a handler to the end of the chain. Mirrors `addToChain`.
    pub fn add(&mut self, handler: Box<dyn MediaHandler>) {
        self.handlers.push(handler);
    }

    /// Number of handlers in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Run the incoming chain. Per the C++ `incomingChain`, handlers run in
    /// **reverse** order (the tail handler sees the messages first). Returns any
    /// messages handlers queued to send back to the peer.
    #[must_use]
    pub fn incoming(&mut self, messages: &mut Vec<Message>) -> Vec<Message> {
        let mut sender = Sender::new();
        for handler in self.handlers.iter_mut().rev() {
            handler.incoming(messages, &mut sender);
        }
        sender.take()
    }

    /// Run the outgoing chain. Per the C++ `outgoingChain`, handlers run in
    /// **forward** order (the head handler sees the messages first). Returns any
    /// extra messages handlers queued to send.
    #[must_use]
    pub fn outgoing(&mut self, messages: &mut Vec<Message>) -> Vec<Message> {
        let mut sender = Sender::new();
        for handler in self.handlers.iter_mut() {
            handler.outgoing(messages, &mut sender);
        }
        sender.take()
    }

    /// Request a keyframe, delegating down the chain until a handler handles it.
    /// Returns the messages queued and whether any handler handled the request.
    #[must_use]
    pub fn request_keyframe(&mut self) -> (Vec<Message>, bool) {
        let mut sender = Sender::new();
        let mut handled = false;
        for handler in self.handlers.iter_mut() {
            if handler.request_keyframe(&mut sender) {
                handled = true;
                break;
            }
        }
        (sender.take(), handled)
    }

    /// Request a bitrate, delegating down the chain until handled.
    #[must_use]
    pub fn request_bitrate(&mut self, bitrate: u64) -> (Vec<Message>, bool) {
        let mut sender = Sender::new();
        let mut handled = false;
        for handler in self.handlers.iter_mut() {
            if handler.request_bitrate(bitrate, &mut sender) {
                handled = true;
                break;
            }
        }
        (sender.take(), handled)
    }
}

// ---------------------------------------------------------------------------
// RtcpReceivingSession
// ---------------------------------------------------------------------------

/// RTP sequence-number modulus (`RTP_SEQ_MOD`, 2^16).
const RTP_SEQ_MOD: u32 = 1 << 16;
const MAX_DROPOUT: u32 = 3000;
const MAX_MISORDER: u32 = 100;
const MIN_SEQUENTIAL: u32 = 2;

/// Acts as an RTP receiver: tracks inbound sequence numbers (RFC 3550 Appendix
/// A.1 algorithm) and, on receiving a Sender Report, emits a Receiver Report
/// (and optionally a REMB if a bitrate has been requested). Also generates PLI
/// on [`request_keyframe`](MediaHandler::request_keyframe). Ports
/// `rtc::RtcpReceivingSession`.
#[derive(Debug)]
pub struct RtcpReceivingSession {
    ssrc: Ssrc,
    requested_bitrate: u64,
    // Synced from the last received SR.
    sync_rtp_timestamp: u32,
    sync_ntp_timestamp: u64,
    // RFC 3550 A.1 sequence tracking.
    base_seq: u32,
    max_seq: u16,
    bad_seq: u32,
    cycles: u32,
    received: u32,
    received_prior: u32,
    expected_prior: u32,
    probation: u32,
    greatest_seq_no: u32,
}

impl Default for RtcpReceivingSession {
    fn default() -> Self {
        RtcpReceivingSession {
            ssrc: 0,
            requested_bitrate: 0,
            sync_rtp_timestamp: 0,
            sync_ntp_timestamp: 0,
            base_seq: 0,
            max_seq: 0,
            bad_seq: RTP_SEQ_MOD + 1,
            cycles: 0,
            received: 0,
            received_prior: 0,
            expected_prior: 0,
            probation: MIN_SEQUENTIAL,
            greatest_seq_no: 0,
        }
    }
}

impl RtcpReceivingSession {
    /// Create a receiving session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The media SSRC last observed on the incoming path.
    #[must_use]
    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    /// RTP/NTP timestamps from the last received Sender Report (for A/V sync).
    #[must_use]
    pub fn sync_timestamps(&self) -> (u32, u64) {
        (self.sync_rtp_timestamp, self.sync_ntp_timestamp)
    }

    /// Build and queue a Receiver Report for the tracked source. Mirrors
    /// `pushRR`: computes fraction-lost / cumulative-lost from the A.1 counters.
    fn push_rr(&mut self, sender: &mut Sender, last_sr_delay: u32) {
        let extended_max = self.cycles + self.max_seq as u32;
        let expected = extended_max.wrapping_sub(self.base_seq).wrapping_add(1);
        let lost = if self.received > 0 {
            expected.wrapping_sub(self.received)
        } else {
            0
        };

        let expected_interval = expected.wrapping_sub(self.expected_prior);
        self.expected_prior = expected;
        let received_interval = self.received.wrapping_sub(self.received_prior);
        self.received_prior = self.received;
        let lost_interval = expected_interval as i64 - received_interval as i64;

        let fraction = if expected_interval == 0 || lost_interval <= 0 {
            0u8
        } else {
            ((lost_interval << 8) / expected_interval as i64) as u8
        };

        let block = crate::rtp::RtcpReportBlock {
            ssrc: self.ssrc,
            fraction_lost: fraction,
            packets_lost: lost & 0x00FF_FFFF,
            seq_no_cycles: (self.greatest_seq_no >> 16) as u16,
            highest_seq_no: self.max_seq,
            jitter: 0,
            last_sr: (self.sync_ntp_timestamp >> 16) as u32,
            delay_since_last_sr: last_sr_delay,
        };
        let rr = RtcpRr {
            sender_ssrc: self.ssrc,
            report_blocks: vec![block],
        };
        sender.send(Message::control(rr.serialize()));
    }

    /// Build and queue a REMB requesting `bitrate`. Mirrors `pushREMB`.
    fn push_remb(&self, sender: &mut Sender, bitrate: u64) {
        let remb = RtcpRemb {
            sender_ssrc: self.ssrc,
            bitrate,
            ssrcs: vec![self.ssrc],
        };
        sender.send(Message::control(remb.serialize()));
    }

    /// Build and queue a PLI for the tracked source. Mirrors `pushPLI`.
    fn push_pli(&self, sender: &mut Sender) {
        let pli = RtcpPli {
            media_ssrc: self.ssrc,
        };
        sender.send(Message::control(pli.serialize().to_vec()));
    }

    fn init_seq(&mut self, seq: u16) {
        self.base_seq = seq as u32;
        self.max_seq = seq;
        self.bad_seq = RTP_SEQ_MOD + 1;
        self.cycles = 0;
        self.received = 0;
        self.received_prior = 0;
        self.expected_prior = 0;
    }

    /// Update sequence tracking with a freshly-received sequence number. Returns
    /// `true` if the packet is considered valid. Ports `updateSeq` (RFC 3550 A.1).
    fn update_seq(&mut self, seq: u16) -> bool {
        let udelta = seq.wrapping_sub(self.max_seq) as u32;

        if self.probation > 0 {
            if seq == self.max_seq.wrapping_add(1) {
                self.probation -= 1;
                self.max_seq = seq;
                if self.probation == 0 {
                    self.init_seq(seq);
                    self.received += 1;
                    return true;
                }
            } else {
                self.probation = MIN_SEQUENTIAL - 1;
                self.max_seq = seq;
            }
            return false;
        } else if udelta < MAX_DROPOUT {
            if seq < self.max_seq {
                self.cycles += RTP_SEQ_MOD;
            }
            self.max_seq = seq;
        } else if udelta <= RTP_SEQ_MOD - MAX_MISORDER {
            if seq as u32 == self.bad_seq {
                self.init_seq(seq);
            } else {
                self.bad_seq = (seq as u32 + 1) & (RTP_SEQ_MOD - 1);
                return false;
            }
        }
        self.received += 1;
        self.greatest_seq_no = self.cycles + self.max_seq as u32;
        true
    }
}

impl MediaHandler for RtcpReceivingSession {
    fn incoming(&mut self, messages: &mut Vec<Message>, sender: &mut Sender) {
        let mut result = Vec::with_capacity(messages.len());
        for message in messages.drain(..) {
            match message.kind {
                MessageType::Binary => {
                    let Some((header, _)) = RtpHeader::parse(&message.data) else {
                        continue; // malformed RTP
                    };
                    if header.version != 2 {
                        continue;
                    }
                    if header.payload_type == RTCP_PT_RR || header.payload_type == RTCP_PT_SR {
                        continue; // PT indicating RR/SR on the media path
                    }
                    self.ssrc = header.ssrc;
                    self.update_seq(header.sequence_number);
                    result.push(message);
                }
                MessageType::Control => {
                    if let Some(rr) = RtcpRr::parse(&message.data) {
                        self.ssrc = rr.sender_ssrc;
                    } else if let Some(sr) = RtcpSr::parse(&message.data) {
                        self.ssrc = sr.sender_ssrc;
                        self.sync_rtp_timestamp = sr.rtp_timestamp;
                        self.sync_ntp_timestamp = sr.ntp_timestamp;
                        // On receiving an SR, reply with an RR (and REMB if set).
                        self.push_rr(sender, 0);
                        if self.requested_bitrate > 0 {
                            self.push_remb(sender, self.requested_bitrate);
                        }
                    }
                    // Control messages are not forwarded further by this session
                    // (the C++ drops them from the result vector too).
                }
            }
        }
        *messages = result;
    }

    fn request_keyframe(&mut self, sender: &mut Sender) -> bool {
        self.push_pli(sender);
        true
    }

    fn request_bitrate(&mut self, bitrate: u64, sender: &mut Sender) -> bool {
        self.requested_bitrate = bitrate;
        self.push_remb(sender, bitrate);
        true
    }
}

// ---------------------------------------------------------------------------
// RtcpSrReporter
// ---------------------------------------------------------------------------

/// Generates outgoing Sender Reports from the outgoing RTP stream, tracking the
/// cumulative packet and payload-octet counts and the latest RTP timestamp.
/// Ports `rtc::RtcpSrReporter`.
///
/// The C++ reporter emits at most one SR per second using a steady clock; the
/// Rust port keeps that policy but takes the "now" instant from the caller so
/// the cadence is testable. Pass the same `now` monotonically.
#[derive(Debug)]
pub struct RtcpSrReporter {
    ssrc: Ssrc,
    packet_count: u32,
    payload_octets: u32,
    last_reported_timestamp: u32,
    // Number of `outgoing` ticks since the last report was emitted. The C++ uses
    // wall-clock >= 1s; we expose an explicit interval so the cadence is testable.
    report_interval_ms: u64,
    elapsed_since_report_ms: u64,
}

impl RtcpSrReporter {
    /// Create a reporter for the given outgoing SSRC, emitting an SR at most once
    /// per `report_interval_ms` (the C++ default is 1000 ms).
    #[must_use]
    pub fn new(ssrc: Ssrc, report_interval_ms: u64) -> Self {
        RtcpSrReporter {
            ssrc,
            packet_count: 0,
            payload_octets: 0,
            last_reported_timestamp: 0,
            report_interval_ms,
            // Force the first SR to be emitted on the first qualifying packet.
            elapsed_since_report_ms: report_interval_ms,
        }
    }

    /// The RTP timestamp carried by the last emitted SR. Mirrors
    /// `lastReportedTimestamp`.
    #[must_use]
    pub fn last_reported_timestamp(&self) -> u32 {
        self.last_reported_timestamp
    }

    /// Cumulative count of RTP packets seen.
    #[must_use]
    pub fn packet_count(&self) -> u32 {
        self.packet_count
    }

    /// Cumulative count of RTP payload octets seen (excludes headers).
    #[must_use]
    pub fn payload_octets(&self) -> u32 {
        self.payload_octets
    }

    /// Accumulate one outgoing RTP packet into the report. Mirrors `addToReport`:
    /// bumps the packet count and adds the payload size (total minus header).
    fn add_to_report(&mut self, header: &RtpHeader, size: usize) {
        self.packet_count += 1;
        self.payload_octets += (size - header.size()) as u32;
    }

    /// Build a Sender Report at the given RTP timestamp. `ntp_timestamp` is the
    /// 64-bit NTP time of "now". Mirrors `getSenderReport` (minus the trailing
    /// SDES chunk, which is not modelled in this crate's `rtp.rs`).
    #[must_use]
    pub fn sender_report(&self, rtp_timestamp: u32, ntp_timestamp: u64) -> RtcpSr {
        RtcpSr {
            sender_ssrc: self.ssrc,
            ntp_timestamp,
            rtp_timestamp,
            packet_count: self.packet_count,
            octet_count: self.payload_octets,
            report_blocks: Vec::new(),
        }
    }

    /// Run the outgoing path with the elapsed time since the previous call and
    /// the NTP timestamp for "now". Accumulates packet/octet counts and, once at
    /// least `report_interval_ms` has elapsed, queues an SR. Returns whether an
    /// SR was emitted. This is the explicit-clock variant the chain calls via
    /// [`MediaHandler::outgoing`] (which uses a zero elapsed/NTP and never emits;
    /// drive reports through this method from the media loop instead).
    pub fn outgoing_at(
        &mut self,
        messages: &mut [Message],
        sender: &mut Sender,
        elapsed_ms: u64,
        ntp_timestamp: u64,
    ) -> bool {
        if messages.is_empty() {
            return false;
        }
        let mut timestamp = 0u32;
        for message in messages.iter() {
            if message.kind == MessageType::Control {
                continue;
            }
            let Some((header, _)) = RtpHeader::parse(&message.data) else {
                continue;
            };
            if header.ssrc != self.ssrc {
                continue;
            }
            timestamp = header.timestamp;
            self.add_to_report(&header, message.data.len());
        }

        self.elapsed_since_report_ms = self.elapsed_since_report_ms.saturating_add(elapsed_ms);
        if self.elapsed_since_report_ms >= self.report_interval_ms {
            let sr = self.sender_report(timestamp, ntp_timestamp);
            sender.send(Message::control(sr.serialize()));
            self.last_reported_timestamp = timestamp;
            self.elapsed_since_report_ms = 0;
            return true;
        }
        false
    }
}

impl MediaHandler for RtcpSrReporter {
    fn outgoing(&mut self, messages: &mut Vec<Message>, sender: &mut Sender) {
        // Accumulate counters every tick; the SR cadence is driven by the
        // elapsed time, defaulting to the configured interval so chaining alone
        // still produces a report once per qualifying batch.
        self.outgoing_at(messages, sender, self.report_interval_ms, 0);
    }
}

// ---------------------------------------------------------------------------
// PliHandler
// ---------------------------------------------------------------------------

/// Detects incoming PLI (and FIR) feedback and invokes a callback so the
/// application can produce a keyframe. Ports `rtc::PliHandler`.
pub struct PliHandler {
    on_pli: Box<dyn FnMut() + Send>,
}

impl PliHandler {
    /// Create a handler invoking `on_pli` whenever a PLI/FIR is received.
    pub fn new(on_pli: impl FnMut() + Send + 'static) -> Self {
        PliHandler {
            on_pli: Box::new(on_pli),
        }
    }
}

impl MediaHandler for PliHandler {
    fn incoming(&mut self, messages: &mut Vec<Message>, _sender: &mut Sender) {
        for message in messages.iter() {
            // Walk the compound RTCP packet looking for FIR (PT=196) or
            // PSFB/PLI (PT=206, FMT=1).
            if scan_compound_rtcp(&message.data, |header| {
                let pt = header.payload_type;
                (pt == 196) || (pt == crate::rtp::RTCP_PT_PSFB && header.report_count == crate::rtp::RTCP_FMT_PLI)
            }) {
                (self.on_pli)();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RembHandler
// ---------------------------------------------------------------------------

/// Detects incoming REMB feedback and invokes a callback with the estimated
/// bitrate. Ports `rtc::RembHandler`.
pub struct RembHandler {
    on_remb: Box<dyn FnMut(u64) + Send>,
}

impl RembHandler {
    /// Create a handler invoking `on_remb` with the bitrate of each REMB received.
    pub fn new(on_remb: impl FnMut(u64) + Send + 'static) -> Self {
        RembHandler {
            on_remb: Box::new(on_remb),
        }
    }
}

impl MediaHandler for RembHandler {
    fn incoming(&mut self, messages: &mut Vec<Message>, _sender: &mut Sender) {
        for message in messages.iter() {
            let mut offset = 0usize;
            while offset + crate::rtp::RTCP_HEADER_SIZE <= message.data.len() {
                let Some(header) = crate::rtp::RtcpHeader::parse(&message.data[offset..]) else {
                    break;
                };
                let len = header.length_in_bytes();
                if header.payload_type == crate::rtp::RTCP_PT_PSFB
                    && header.report_count == crate::rtp::RTCP_FMT_AFB
                {
                    if let Some(remb) = RtcpRemb::parse(&message.data[offset..]) {
                        (self.on_remb)(remb.bitrate);
                        break;
                    }
                }
                if len == 0 {
                    break;
                }
                offset += len;
            }
        }
    }
}

/// Walk a compound RTCP packet, invoking `predicate` on each sub-packet header.
/// Returns `true` as soon as the predicate matches. Mirrors the
/// `offset += lengthInBytes()` loop the C++ PLI/REMB handlers use.
fn scan_compound_rtcp(data: &[u8], mut predicate: impl FnMut(&crate::rtp::RtcpHeader) -> bool) -> bool {
    let mut offset = 0usize;
    while offset + crate::rtp::RTCP_HEADER_SIZE <= data.len() {
        let Some(header) = crate::rtp::RtcpHeader::parse(&data[offset..]) else {
            break;
        };
        if predicate(&header) {
            return true;
        }
        let len = header.length_in_bytes();
        if len == 0 {
            break;
        }
        offset += len;
    }
    false
}

// ---------------------------------------------------------------------------
// RtcpNackResponder
// ---------------------------------------------------------------------------

/// Buffers recently-sent RTP packets and retransmits them in response to
/// incoming NACKs. Ports `rtc::RtcpNackResponder` (and its `Storage`): an
/// insertion-ordered ring keyed by RTP sequence number, capped at `max_size`.
pub struct RtcpNackResponder {
    max_size: usize,
    // Insertion order (oldest at front) for eviction.
    order: VecDeque<u16>,
    by_seq: HashMap<u16, Vec<u8>>,
}

impl RtcpNackResponder {
    /// libdatachannel's default send-buffer size (`RTC_DEFAULT_MAX_NACK_SIZE`).
    pub const DEFAULT_MAX_SIZE: usize = 512;

    /// Create a responder buffering up to `max_size` packets. `max_size` must be
    /// greater than zero (mirrors the C++ `assert(maxSize > 0)`).
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        assert!(max_size > 0, "RtcpNackResponder max_size must be > 0");
        RtcpNackResponder {
            max_size,
            order: VecDeque::with_capacity(max_size),
            by_seq: HashMap::with_capacity(max_size),
        }
    }

    /// Number of packets currently buffered.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.order.len()
    }

    /// Retrieve a buffered packet by sequence number, if still present.
    #[must_use]
    pub fn get(&self, seq: u16) -> Option<&[u8]> {
        self.by_seq.get(&seq).map(Vec::as_slice)
    }

    /// Buffer an outgoing RTP packet, evicting the oldest if over capacity.
    /// Mirrors `Storage::store`.
    fn store(&mut self, packet: &[u8]) {
        let Some((header, _)) = RtpHeader::parse(packet) else {
            return; // too small for an RTP header
        };
        let seq = header.sequence_number;
        if self.by_seq.insert(seq, packet.to_vec()).is_none() {
            self.order.push_back(seq);
        }
        if self.order.len() > self.max_size {
            if let Some(old) = self.order.pop_front() {
                self.by_seq.remove(&old);
            }
        }
    }
}

impl MediaHandler for RtcpNackResponder {
    fn incoming(&mut self, messages: &mut Vec<Message>, sender: &mut Sender) {
        for message in messages.iter() {
            if message.kind != MessageType::Control {
                continue;
            }
            let mut p = 0usize;
            // Mirrors the C++ `p + sizeof(RtcpNack) <= size` walk over a
            // compound RTCP packet (sizeof(RtcpNack) == size_with_parts(1)).
            while p + RtcpNack::size_with_parts(1) <= message.data.len() {
                let Some(header) = crate::rtp::RtcpHeader::parse(&message.data[p..]) else {
                    break;
                };
                let advance = header.length_in_bytes(); // (length+1)*4 bytes
                if let Some(nack) = RtcpNack::parse(&message.data[p..]) {
                    for seq in nack.missing_sequence_numbers() {
                        if let Some(pkt) = self.get(seq) {
                            sender.send(Message::binary(pkt.to_vec()));
                        }
                    }
                }
                if advance == 0 {
                    break;
                }
                p += advance;
            }
        }
    }

    fn outgoing(&mut self, messages: &mut Vec<Message>, _sender: &mut Sender) {
        for message in messages.iter() {
            if message.kind != MessageType::Control {
                self.store(&message.data);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PacingHandler
// ---------------------------------------------------------------------------

/// Paces outgoing RTP to a target bitrate. Ports `rtc::PacingHandler`.
///
/// On each [`outgoing`](MediaHandler::outgoing) call the messages are queued
/// rather than passed through; [`tick`](PacingHandler::tick) then releases as
/// many as the accumulated byte budget allows (with one partial overshoot, as
/// in the C++). The budget grows by `bytes_per_second * elapsed` and is capped
/// at one `send_interval`'s worth, matching `PacingHandler::run`.
pub struct PacingHandler {
    bytes_per_second: f64,
    send_interval_ms: u64,
    budget: f64,
    buffer: VecDeque<Message>,
}

impl PacingHandler {
    /// Create a pacer for `bits_per_second` releasing on a `send_interval_ms`
    /// cadence. Mirrors `PacingHandler(double bitsPerSecond, milliseconds)`.
    #[must_use]
    pub fn new(bits_per_second: f64, send_interval_ms: u64) -> Self {
        PacingHandler {
            bytes_per_second: bits_per_second / 8.0,
            send_interval_ms,
            budget: 0.0,
            buffer: VecDeque::new(),
        }
    }

    /// Number of packets currently buffered awaiting release.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Release buffered packets given `elapsed_ms` since the previous tick.
    /// Updates and caps the budget, then drains while budget remains (allowing a
    /// single packet to push the budget negative). Returns the released packets,
    /// in order. Ports the body of `PacingHandler::run`.
    #[must_use]
    pub fn tick(&mut self, elapsed_ms: u64) -> Vec<Message> {
        let elapsed_s = elapsed_ms as f64 / 1000.0;
        let new_budget = elapsed_s * self.bytes_per_second;
        let max_budget = (self.send_interval_ms as f64 / 1000.0) * self.bytes_per_second;
        self.budget = (self.budget + new_budget).min(max_budget);

        let mut released = Vec::new();
        while let Some(front) = self.buffer.front() {
            if self.budget <= 0.0 {
                break;
            }
            let size = front.len() as f64;
            let message = self.buffer.pop_front().expect("front exists");
            released.push(message);
            self.budget -= size;
        }
        released
    }
}

impl MediaHandler for PacingHandler {
    fn outgoing(&mut self, messages: &mut Vec<Message>, _sender: &mut Sender) {
        for message in messages.drain(..) {
            self.buffer.push_back(message);
        }
        // Cleared: paced packets are released via `tick` from the media loop.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rtp_packet(ssrc: Ssrc, seq: u16, ts: u32, payload: &[u8]) -> Message {
        let header = RtpHeader {
            payload_type: 96,
            sequence_number: seq,
            timestamp: ts,
            ssrc,
            ..RtpHeader::default()
        };
        let mut data = header.serialize();
        data.extend_from_slice(payload);
        Message::binary(data)
    }

    // ---- chain ordering ---------------------------------------------------

    /// A handler that appends its label to a shared trace in both directions.
    /// Handlers must be `Send`, so the trace is an `Arc<Mutex<_>>`.
    struct Tracer {
        label: char,
        trace: std::sync::Arc<std::sync::Mutex<String>>,
    }

    impl MediaHandler for Tracer {
        fn incoming(&mut self, _m: &mut Vec<Message>, _s: &mut Sender) {
            self.trace.lock().unwrap().push(self.label);
        }
        fn outgoing(&mut self, _m: &mut Vec<Message>, _s: &mut Sender) {
            self.trace.lock().unwrap().push(self.label);
        }
    }

    #[test]
    fn chain_incoming_reverses_outgoing_forward() {
        let trace = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let mut chain = MediaHandlerChain::new();
        for label in ['A', 'B', 'C'] {
            chain.add(Box::new(Tracer {
                label,
                trace: trace.clone(),
            }));
        }

        let mut msgs = Vec::new();
        let _ = chain.outgoing(&mut msgs);
        assert_eq!(*trace.lock().unwrap(), "ABC", "outgoing runs head -> tail");

        trace.lock().unwrap().clear();
        let _ = chain.incoming(&mut msgs);
        assert_eq!(*trace.lock().unwrap(), "CBA", "incoming runs tail -> head");
    }

    // ---- RtcpSrReporter ---------------------------------------------------

    #[test]
    fn sr_reporter_counts_packets_and_octets() {
        let ssrc = 0x1234_5678;
        let mut reporter = RtcpSrReporter::new(ssrc, 1000);
        let mut sender = Sender::new();

        // Two 10-byte-payload packets for our SSRC, one for another SSRC.
        let mut msgs = vec![
            rtp_packet(ssrc, 1, 9000, &[0u8; 10]),
            rtp_packet(ssrc, 2, 9900, &[0u8; 10]),
            rtp_packet(0x9999_9999, 3, 100, &[0u8; 10]),
        ];

        // First call: 1000 ms elapsed -> emits an SR.
        let emitted = reporter.outgoing_at(&mut msgs, &mut sender, 1000, 0xABCD);
        assert!(emitted);
        assert_eq!(reporter.packet_count(), 2, "only our SSRC counts");
        assert_eq!(reporter.payload_octets(), 20, "2 x 10-byte payloads");
        assert_eq!(reporter.last_reported_timestamp(), 9900, "latest TS for our SSRC");

        let sent = sender.take();
        assert_eq!(sent.len(), 1);
        let sr = RtcpSr::parse(&sent[0].data).expect("parse sr");
        assert_eq!(sr.sender_ssrc, ssrc);
        assert_eq!(sr.packet_count, 2);
        assert_eq!(sr.octet_count, 20);
        assert_eq!(sr.rtp_timestamp, 9900);
        assert_eq!(sr.ntp_timestamp, 0xABCD);
    }

    #[test]
    fn sr_reporter_respects_interval() {
        let ssrc = 7;
        let mut reporter = RtcpSrReporter::new(ssrc, 1000);
        let mut sender = Sender::new();
        let mut msgs = vec![rtp_packet(ssrc, 1, 100, &[0u8; 4])];

        // Only 400 ms elapsed since construction's primed interval was reset on
        // the first emit; emit once, then a sub-interval call must not emit.
        assert!(reporter.outgoing_at(&mut msgs, &mut sender, 1000, 1)); // primes & emits
        let mut msgs2 = vec![rtp_packet(ssrc, 2, 200, &[0u8; 4])];
        assert!(!reporter.outgoing_at(&mut msgs2, &mut sender, 400, 2));
        // Crossing the interval emits again.
        let mut msgs3 = vec![rtp_packet(ssrc, 3, 300, &[0u8; 4])];
        assert!(reporter.outgoing_at(&mut msgs3, &mut sender, 600, 3));
        assert_eq!(reporter.packet_count(), 3);
    }

    // ---- RtcpReceivingSession --------------------------------------------

    #[test]
    fn receiving_session_emits_rr_on_sr() {
        let mut session = RtcpReceivingSession::new();
        let mut sender = Sender::new();

        // Feed a couple of media packets so the SSRC is learned.
        let mut media = vec![
            rtp_packet(0x55, 1000, 90_000, &[0u8; 8]),
            rtp_packet(0x55, 1001, 90_900, &[0u8; 8]),
        ];
        session.incoming(&mut media, &mut sender);
        assert_eq!(session.ssrc(), 0x55);
        // Media passes through.
        assert_eq!(media.len(), 2);

        // Now feed an SR; expect an RR queued and the SR consumed.
        let sr = RtcpSr {
            sender_ssrc: 0x55,
            ntp_timestamp: 0x1122_3344_5566_7788,
            rtp_timestamp: 91_800,
            packet_count: 100,
            octet_count: 5000,
            report_blocks: vec![],
        };
        let mut ctrl = vec![Message::control(sr.serialize())];
        session.incoming(&mut ctrl, &mut sender);
        assert!(ctrl.is_empty(), "SR is consumed, not forwarded");
        assert_eq!(session.sync_timestamps(), (91_800, 0x1122_3344_5566_7788));

        let sent = sender.take();
        assert_eq!(sent.len(), 1, "one RR emitted");
        let rr = RtcpRr::parse(&sent[0].data).expect("parse rr");
        assert_eq!(rr.sender_ssrc, 0x55);
        assert_eq!(rr.report_blocks.len(), 1);
    }

    #[test]
    fn receiving_session_keyframe_and_bitrate_requests() {
        let mut session = RtcpReceivingSession::new();
        let mut sender = Sender::new();
        let mut media = vec![rtp_packet(0xABCD, 1, 0, &[0u8; 4])];
        session.incoming(&mut media, &mut sender);
        let _ = sender.take();

        assert!(session.request_keyframe(&mut sender));
        let pli = sender.take();
        assert_eq!(pli.len(), 1);
        assert_eq!(RtcpPli::parse(&pli[0].data).unwrap().media_ssrc, 0xABCD);

        assert!(session.request_bitrate(1_000_000, &mut sender));
        let remb = sender.take();
        assert_eq!(remb.len(), 1);
        let parsed = RtcpRemb::parse(&remb[0].data).unwrap();
        assert_eq!(parsed.ssrcs, vec![0xABCD]);
    }

    // ---- PliHandler / RembHandler ----------------------------------------

    #[test]
    fn pli_handler_fires_on_pli() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;
        // Handlers must be `Send` (they live behind a Track's `Arc<Mutex<_>>`),
        // so the test callback uses an `Arc<Atomic*>` rather than `Rc<Cell<_>>`.
        let count = Arc::new(AtomicU32::new(0));
        let c = count.clone();
        let mut handler = PliHandler::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });

        let pli = RtcpPli { media_ssrc: 42 };
        let mut msgs = vec![Message::control(pli.serialize().to_vec())];
        handler.incoming(&mut msgs, &mut Sender::new());
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // A REMB must NOT trigger the PLI callback.
        let remb = RtcpRemb { sender_ssrc: 1, bitrate: 1000, ssrcs: vec![1] };
        let mut msgs2 = vec![Message::control(remb.serialize())];
        handler.incoming(&mut msgs2, &mut Sender::new());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn remb_handler_reports_bitrate() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
        let got = Arc::new(AtomicU64::new(0));
        let g = got.clone();
        let mut handler = RembHandler::new(move |br| {
            g.store(br, Ordering::SeqCst);
        });

        let remb = RtcpRemb { sender_ssrc: 9, bitrate: 1_200_000, ssrcs: vec![9] };
        let expected = RtcpRemb::decode_bitrate(RtcpRemb::encode_bitrate(1, 1_200_000));
        let mut msgs = vec![Message::control(remb.serialize())];
        handler.incoming(&mut msgs, &mut Sender::new());
        assert_eq!(got.load(Ordering::SeqCst), expected);
    }

    // ---- RtcpNackResponder ------------------------------------------------

    #[test]
    fn nack_responder_retransmits_buffered_packets() {
        let mut responder = RtcpNackResponder::new(64);
        let mut sender = Sender::new();

        // Buffer outgoing media seq 100..=104.
        let mut out: Vec<Message> = (100..=104)
            .map(|seq| rtp_packet(0x11, seq, seq as u32 * 90, &[seq as u8; 16]))
            .collect();
        responder.outgoing(&mut out, &mut sender);
        assert_eq!(responder.buffered(), 5);

        // NACK requesting 101 and 103.
        let nack = RtcpNack::from_missing(0x22, 0x11, &[101, 103]);
        let mut ctrl = vec![Message::control(nack.serialize())];
        responder.incoming(&mut ctrl, &mut sender);

        let resent = sender.take();
        assert_eq!(resent.len(), 2, "two packets retransmitted");
        // They must be the buffered media (Binary) packets, in request order.
        let seqs: Vec<u16> = resent
            .iter()
            .map(|m| RtpHeader::parse(&m.data).unwrap().0.sequence_number)
            .collect();
        assert_eq!(seqs, vec![101, 103]);
        assert!(resent.iter().all(|m| m.kind == MessageType::Binary));
    }

    #[test]
    fn nack_responder_evicts_oldest_over_capacity() {
        let mut responder = RtcpNackResponder::new(3);
        let mut sender = Sender::new();
        let mut out: Vec<Message> = (1..=5)
            .map(|seq| rtp_packet(0x11, seq, 0, &[0u8; 16]))
            .collect();
        responder.outgoing(&mut out, &mut sender);
        assert_eq!(responder.buffered(), 3);
        // Oldest (1, 2) evicted; 3, 4, 5 retained.
        assert!(responder.get(1).is_none());
        assert!(responder.get(2).is_none());
        assert!(responder.get(3).is_some());
        assert!(responder.get(5).is_some());
    }

    // ---- PacingHandler ----------------------------------------------------

    #[test]
    fn pacing_releases_within_budget() {
        // 8000 bits/s = 1000 bytes/s. Interval 100 ms => max budget 100 bytes.
        let mut pacer = PacingHandler::new(8000.0, 100);
        // Queue five 50-byte packets (header 12 + 38 payload = 50).
        let mut msgs: Vec<Message> = (0..5)
            .map(|i| rtp_packet(1, i, 0, &[0u8; 38]))
            .collect();
        assert_eq!(msgs[0].len(), 50);
        pacer.outgoing(&mut msgs, &mut Sender::new());
        assert!(msgs.is_empty(), "outgoing clears the vector (buffered)");
        assert_eq!(pacer.buffered(), 5);

        // 100 ms => budget 100 bytes => releases 2 packets (the second pushes
        // budget to 0; allow one overshoot is only when budget>0 before send).
        let released = pacer.tick(100);
        assert_eq!(released.len(), 2);
        assert_eq!(pacer.buffered(), 3);

        // Another 50 ms => 50 bytes budget => 1 more packet.
        let released = pacer.tick(50);
        assert_eq!(released.len(), 1);
        assert_eq!(pacer.buffered(), 2);
    }

    #[test]
    fn pacing_budget_is_capped_at_one_interval() {
        let mut pacer = PacingHandler::new(8000.0, 100); // 1000 B/s, cap 100 B
        let mut msgs: Vec<Message> = (0..10)
            .map(|i| rtp_packet(1, i, 0, &[0u8; 38]))
            .collect();
        pacer.outgoing(&mut msgs, &mut Sender::new());
        // A huge elapsed time must NOT release everything: budget caps at 100 B.
        let released = pacer.tick(100_000);
        assert_eq!(released.len(), 2, "budget capped at one interval (100 B)");
    }
}
