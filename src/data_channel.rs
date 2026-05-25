//! DataChannel + the DCEP establishment protocol — port of
//! `rtc::DataChannel` / `rtc::impl::DataChannel` from
//! `native/libdatachannel/src/datachannel.cpp` and
//! `native/libdatachannel/src/impl/datachannel.cpp`.
//!
//! This module implements the **DataChannel Establishment Protocol**
//! (RFC 8832, "DCEP") on top of the existing [`SctpTransport`]. It is the
//! task-#18 layer that turns a raw SCTP association into labelled,
//! reliability-tagged message channels.
//!
//! ## What DCEP does
//!
//! SCTP gives us ordered/unordered streams identified by a `u16` stream id,
//! but it knows nothing about *labels*, *sub-protocols*, or per-channel
//! reliability. DCEP is a tiny in-band handshake carried on the SCTP
//! **Control** PPID (50) that establishes that metadata:
//!
//! - The **creating** side allocates a stream id (see the stream-id rule
//!   below), then once the SCTP association is `Connected` it sends a
//!   [`DATA_CHANNEL_OPEN`](encode_open) control message carrying the label,
//!   protocol, and reliability parameters.
//! - The **receiving** side, on an inbound `OPEN`, allocates a channel bound
//!   to that incoming stream id, replies with a single-byte
//!   [`DATA_CHANNEL_ACK`](encode_ack), and surfaces the channel to the
//!   application (via `PeerConnection`'s `on_data_channel`).
//! - The creating side marks the channel **open** when it sees the `ACK`
//!   (and, per spec, also treats the first inbound user data as an implicit
//!   open). libdatachannel *buffers* outbound user data until open; we do
//!   the same.
//!
//! ## Stream-id rule (RFC 8832 §6)
//!
//! The peer acting as **DTLS client** uses **even** stream ids
//! (0, 2, 4, …); the peer acting as **DTLS server** uses **odd** ids
//! (1, 3, 5, …). The [`PeerConnection`](crate::PeerConnection) already knows
//! its DTLS role (derived from the SDP `a=setup:` attribute) and hands the
//! parity into [`StreamIdAllocator`].
//!
//! ## PPID mapping (RFC 8831 §6)
//!
//! User payloads are mapped onto SCTP PPIDs on the way out and back on the
//! way in:
//!
//! | direction | text | empty text | binary | empty binary |
//! |-----------|------|------------|--------|--------------|
//! | send      | String(51) | StringEmpty(56) + `0x00` | Binary(53) | BinaryEmpty(57) + `0x00` |
//! | recv      | text | text (strip pad) | binary | binary (strip pad) |
//!
//! Control(50) routes to DCEP handling instead of the application.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};

use parking_lot::Mutex;
use thiserror::Error;

use crate::reliability::{Reliability, ReliabilityType};
use crate::sctp_transport::{PayloadProtocolId, SctpMessage, SctpTransport, SctpTransportError};

// ---------------------------------------------------------------------------
// DCEP wire constants (mirror the C++ `MessageType` / `ChannelType` enums in
// `impl/datachannel.cpp:38`).
// ---------------------------------------------------------------------------

/// `DATA_CHANNEL_ACK` message type byte.
const MESSAGE_ACK: u8 = 0x02;
/// `DATA_CHANNEL_OPEN` message type byte.
const MESSAGE_OPEN: u8 = 0x03;

/// Reliable, ordered channel.
const CHANNEL_RELIABLE: u8 = 0x00;
/// Partial reliable channel capped by retransmit count.
const CHANNEL_PARTIAL_RELIABLE_REXMIT: u8 = 0x01;
/// Partial reliable channel capped by packet lifetime.
const CHANNEL_PARTIAL_RELIABLE_TIMED: u8 = 0x02;
/// OR'd into `channel_type` to request unordered delivery.
const CHANNEL_UNORDERED: u8 = 0x80;

/// Fixed-size prefix of a `DATA_CHANNEL_OPEN` message, before the
/// variable-length label and protocol bytes:
/// `type(1) + channel_type(1) + priority(2) + reliability_param(4) +
///  label_length(2) + protocol_length(2)` = 12 bytes.
const OPEN_HEADER_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by [`DataChannel`] operations and DCEP parsing.
#[derive(Debug, Error)]
pub enum DataChannelError {
    /// A `send` was attempted on a channel that is not open (and the
    /// payload could not be buffered — currently only on a closed channel).
    #[error("data channel not open")]
    NotOpen,

    /// The channel has been closed.
    #[error("data channel closed")]
    Closed,

    /// A DCEP control message was malformed or truncated.
    #[error("malformed DCEP message: {0}")]
    Malformed(&'static str),

    /// Forwarded from the SCTP transport.
    #[error("sctp: {0}")]
    Sctp(#[from] SctpTransportError),
}

// ---------------------------------------------------------------------------
// DCEP encode / decode
// ---------------------------------------------------------------------------

/// A decoded `DATA_CHANNEL_OPEN` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpenMessage {
    /// Channel label (UTF-8).
    pub label: String,
    /// Sub-protocol (UTF-8, may be empty).
    pub protocol: String,
    /// Reliability parameters reconstructed from `channel_type` +
    /// `reliability_parameter`.
    pub reliability: Reliability,
    /// Raw priority field (preserved for fidelity; libdatachannel sends 0).
    pub priority: u16,
}

/// Encode a `DATA_CHANNEL_OPEN` control message (RFC 8832 §5.1), big-endian.
///
/// Layout: `type=0x03, channel_type, priority(u16), reliability_param(u32),
/// label_length(u16), protocol_length(u16), label, protocol`.
pub(crate) fn encode_open(label: &str, protocol: &str, reliability: &Reliability) -> Vec<u8> {
    let (mut channel_type, reliability_parameter) = match reliability.typ {
        ReliabilityType::Rexmit => (CHANNEL_PARTIAL_RELIABLE_REXMIT, reliability.rexmit),
        ReliabilityType::Timed => (CHANNEL_PARTIAL_RELIABLE_TIMED, reliability.rexmit),
        ReliabilityType::Reliable => (CHANNEL_RELIABLE, 0u32),
    };
    if reliability.unordered {
        channel_type |= CHANNEL_UNORDERED;
    }

    let label_bytes = label.as_bytes();
    let protocol_bytes = protocol.as_bytes();
    let mut buf = Vec::with_capacity(OPEN_HEADER_LEN + label_bytes.len() + protocol_bytes.len());
    buf.push(MESSAGE_OPEN);
    buf.push(channel_type);
    buf.extend_from_slice(&0u16.to_be_bytes()); // priority
    buf.extend_from_slice(&reliability_parameter.to_be_bytes());
    buf.extend_from_slice(&(label_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(&(protocol_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(label_bytes);
    buf.extend_from_slice(protocol_bytes);
    buf
}

/// Encode a `DATA_CHANNEL_ACK` control message — a single `type` byte.
pub(crate) fn encode_ack() -> Vec<u8> {
    vec![MESSAGE_ACK]
}

/// The kind of a decoded DCEP control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DcepMessage {
    /// A `DATA_CHANNEL_OPEN`.
    Open(OpenMessage),
    /// A `DATA_CHANNEL_ACK`.
    Ack,
}

/// Decode a DCEP control message (the payload of a Control-PPID SCTP
/// message). Returns [`DataChannelError::Malformed`] on truncated or
/// unrecognised input.
pub(crate) fn decode_control(data: &[u8]) -> Result<DcepMessage, DataChannelError> {
    let first = *data
        .first()
        .ok_or(DataChannelError::Malformed("empty control message"))?;
    match first {
        MESSAGE_ACK => Ok(DcepMessage::Ack),
        MESSAGE_OPEN => Ok(DcepMessage::Open(decode_open(data)?)),
        _ => Err(DataChannelError::Malformed("unknown DCEP message type")),
    }
}

/// Decode a `DATA_CHANNEL_OPEN` message body (RFC 8832 §5.1).
pub(crate) fn decode_open(data: &[u8]) -> Result<OpenMessage, DataChannelError> {
    if data.len() < OPEN_HEADER_LEN {
        return Err(DataChannelError::Malformed("open message too small"));
    }
    debug_assert_eq!(data[0], MESSAGE_OPEN);
    let channel_type = data[1];
    let priority = u16::from_be_bytes([data[2], data[3]]);
    let reliability_parameter = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let label_length = u16::from_be_bytes([data[8], data[9]]) as usize;
    let protocol_length = u16::from_be_bytes([data[10], data[11]]) as usize;

    let body = &data[OPEN_HEADER_LEN..];
    if body.len() < label_length + protocol_length {
        return Err(DataChannelError::Malformed("open message truncated"));
    }
    let label = String::from_utf8(body[..label_length].to_vec())
        .map_err(|_| DataChannelError::Malformed("label is not valid UTF-8"))?;
    let protocol = String::from_utf8(body[label_length..label_length + protocol_length].to_vec())
        .map_err(|_| DataChannelError::Malformed("protocol is not valid UTF-8"))?;

    let unordered = (channel_type & CHANNEL_UNORDERED) != 0;
    let typ = match channel_type & 0x7F {
        CHANNEL_PARTIAL_RELIABLE_REXMIT => ReliabilityType::Rexmit,
        CHANNEL_PARTIAL_RELIABLE_TIMED => ReliabilityType::Timed,
        _ => ReliabilityType::Reliable,
    };
    let rexmit = if matches!(typ, ReliabilityType::Reliable) {
        0
    } else {
        reliability_parameter
    };
    let reliability = Reliability {
        unordered,
        typ,
        rexmit,
    };

    Ok(OpenMessage {
        label,
        protocol,
        reliability,
        priority,
    })
}

// ---------------------------------------------------------------------------
// Stream-id allocation (RFC 8832 §6)
// ---------------------------------------------------------------------------

/// Allocates SCTP stream ids for locally-created data channels following
/// RFC 8832 §6: the DTLS **client** uses even ids, the DTLS **server** uses
/// odd ids. Construct with the parity that matches the resolved DTLS role.
#[derive(Debug)]
pub(crate) struct StreamIdAllocator {
    /// Next id to hand out; advances by 2 to preserve parity.
    next: u16,
}

impl StreamIdAllocator {
    /// Build an allocator for the given DTLS-client-ness. `dtls_client`
    /// true → even ids starting at 0; false → odd ids starting at 1.
    pub(crate) fn new(dtls_client: bool) -> Self {
        StreamIdAllocator {
            next: if dtls_client { 0 } else { 1 },
        }
    }

    /// Hand out the next free stream id for this side, advancing by 2.
    pub(crate) fn allocate(&mut self) -> u16 {
        let id = self.next;
        self.next = self.next.saturating_add(2);
        id
    }

    /// Reserve `id` so the allocator will not hand it out again. Used when a
    /// channel was created with an explicit stream id, or (defensively) when
    /// an inbound channel claims an id on our parity.
    pub(crate) fn reserve(&mut self, id: u16) {
        if id >= self.next {
            self.next = id.saturating_add(2);
        }
    }
}

// ---------------------------------------------------------------------------
// DataChannel callbacks
// ---------------------------------------------------------------------------

/// Callbacks fired by a [`DataChannel`]. All are
/// `Arc<dyn Fn(..) + Send + Sync>` to match this crate's transport callback
/// convention (rather than the reference crate's `DataChannelHandler` trait).
/// Use [`DataChannelCallbacks::default`] for all-no-ops.
#[derive(Clone)]
// `on_message` is a two-argument boxed closure; clippy's type-complexity lint
// trips on it, but the boxed-closure callback shape is this crate's
// established convention (see `*Callbacks` in the transport modules).
#[allow(clippy::type_complexity)]
pub struct DataChannelCallbacks {
    /// Fires once the channel is open (ACK received for a locally-created
    /// channel, or immediately after an inbound OPEN is accepted).
    pub on_open: Arc<dyn Fn() + Send + Sync>,
    /// Fires for each inbound user message. The bool is `true` for a binary
    /// message (PPID Binary/BinaryEmpty) and `false` for a text message
    /// (PPID String/StringEmpty). The empty-payload PPIDs deliver an empty
    /// slice (the 1-byte SCTP padding is stripped).
    pub on_message: Arc<dyn Fn(&[u8], bool) + Send + Sync>,
    /// Fires when the channel is closed (locally or by the peer).
    pub on_closed: Arc<dyn Fn() + Send + Sync>,
    /// Fires when the buffered amount on the channel's stream drops below
    /// the low threshold (backpressure hook).
    pub on_buffered_amount_low: Arc<dyn Fn() + Send + Sync>,
}

impl Default for DataChannelCallbacks {
    fn default() -> Self {
        DataChannelCallbacks {
            on_open: Arc::new(|| {}),
            on_message: Arc::new(|_, _| {}),
            on_closed: Arc::new(|| {}),
            on_buffered_amount_low: Arc::new(|| {}),
        }
    }
}

/// Construction parameters for a locally-created data channel. Mirrors the
/// reference crate's `DataChannelInit` (label is passed separately to
/// `create_data_channel`).
#[derive(Debug, Clone, Default)]
pub struct DataChannelInit {
    /// Per-channel reliability (defaults to fully reliable/ordered).
    pub reliability: Reliability,
    /// Optional sub-protocol string (defaults to empty).
    pub protocol: String,
    /// If set, use this exact stream id instead of allocating one
    /// (the reference crate's `manual_stream` + `stream`).
    pub stream: Option<u16>,
    /// If true, the channel is *negotiated out of band* — no DCEP OPEN/ACK
    /// is exchanged; both sides create it with the same stream id. (The
    /// handshake-driving paths skip OPEN when this is set.)
    pub negotiated: bool,
}

// ---------------------------------------------------------------------------
// DataChannel
// ---------------------------------------------------------------------------

/// A WebRTC data channel: a labelled, reliability-tagged message stream over
/// the shared SCTP association. Port of `rtc::DataChannel`.
///
/// Cheap to clone — it's an `Arc<DataChannelInner>` under the hood, matching
/// the transport pattern. The [`PeerConnection`](crate::PeerConnection) holds
/// one clone and hands another to the application.
#[derive(Clone)]
pub struct DataChannel {
    inner: Arc<DataChannelInner>,
}

pub(crate) struct DataChannelInner {
    label: String,
    protocol: String,
    reliability: Reliability,
    /// Assigned SCTP stream id. Always finalised by the time the channel is
    /// surfaced to the application; for locally-created channels parked
    /// before the DTLS role is known it starts as a placeholder and is set
    /// by [`DataChannel::assign_stream`] when SCTP comes up.
    stream: AtomicU16,
    /// True for a channel created from an inbound DCEP OPEN (so it must not
    /// itself send OPEN); false for a locally-created channel.
    incoming: bool,
    /// True once the DCEP handshake has completed (ACK received, or inbound
    /// OPEN accepted).
    open: AtomicBool,
    /// True once the channel has been closed.
    closed: AtomicBool,
    /// The SCTP transport to send on. Populated once SCTP is up.
    sctp: Mutex<Option<Arc<SctpTransport>>>,
    /// User data queued before the channel opened (libdatachannel buffers).
    /// Each entry is `(data, is_binary)`.
    send_queue: Mutex<Vec<(Vec<u8>, bool)>>,
    /// Mirror of the SCTP transport's per-stream buffered byte count for this
    /// channel's stream (bytes accepted by `send` but not yet handed to
    /// usrsctp). Updated by [`trigger_buffered_amount`](Self::trigger_buffered_amount)
    /// whenever the transport reports a change. Mirrors `Channel::bufferedAmount`.
    buffered_amount: AtomicUsize,
    /// Low-water threshold (default 0): `on_buffered_amount_low` fires when the
    /// buffered amount transitions from above this value to at-or-below it.
    /// Mirrors `Channel::bufferedAmountLowThreshold`.
    buffered_amount_low_threshold: AtomicUsize,
    callbacks: Mutex<DataChannelCallbacks>,
}

impl DataChannel {
    /// Build a locally-created (outgoing) data channel. The stream id has
    /// already been allocated by the caller per RFC 8832 §6.
    pub(crate) fn new_outgoing(
        label: String,
        stream: u16,
        init: DataChannelInit,
        callbacks: DataChannelCallbacks,
    ) -> Self {
        DataChannel {
            inner: Arc::new(DataChannelInner {
                label,
                protocol: init.protocol,
                reliability: init.reliability,
                stream: AtomicU16::new(stream),
                incoming: false,
                open: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                sctp: Mutex::new(None),
                send_queue: Mutex::new(Vec::new()),
                buffered_amount: AtomicUsize::new(0),
                buffered_amount_low_threshold: AtomicUsize::new(0),
                callbacks: Mutex::new(callbacks),
            }),
        }
    }

    /// Build a data channel from an inbound DCEP OPEN. The label, protocol
    /// and reliability come off the wire; the stream id is the inbound
    /// stream the OPEN arrived on.
    pub(crate) fn new_incoming(stream: u16, open: &OpenMessage) -> Self {
        DataChannel {
            inner: Arc::new(DataChannelInner {
                label: open.label.clone(),
                protocol: open.protocol.clone(),
                reliability: open.reliability,
                stream: AtomicU16::new(stream),
                incoming: true,
                open: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                sctp: Mutex::new(None),
                send_queue: Mutex::new(Vec::new()),
                buffered_amount: AtomicUsize::new(0),
                buffered_amount_low_threshold: AtomicUsize::new(0),
                callbacks: Mutex::new(DataChannelCallbacks::default()),
            }),
        }
    }

    /// The application-supplied (or wire-supplied) channel label.
    pub fn label(&self) -> &str {
        &self.inner.label
    }

    /// The negotiated sub-protocol (empty string if none).
    pub fn protocol(&self) -> &str {
        &self.inner.protocol
    }

    /// The channel's assigned SCTP stream id (RFC 8832 §6 parity).
    pub fn stream(&self) -> u16 {
        self.inner.stream.load(Ordering::SeqCst)
    }

    /// Alias for [`stream`](Self::stream) matching the reference crate's
    /// `id()` naming.
    pub fn id(&self) -> u16 {
        self.inner.stream.load(Ordering::SeqCst)
    }

    /// Finalise the stream id of a locally-created channel that was parked
    /// before the DTLS role was resolved. Called by `PeerConnection` once
    /// SCTP is up and the allocator has handed out a real id.
    pub(crate) fn assign_stream(&self, stream: u16) {
        self.inner.stream.store(stream, Ordering::SeqCst);
    }

    /// This channel's reliability parameters.
    pub fn reliability(&self) -> Reliability {
        self.inner.reliability
    }

    /// True once the DCEP handshake completed and user data can flow.
    pub fn is_open(&self) -> bool {
        self.inner.open.load(Ordering::SeqCst) && !self.inner.closed.load(Ordering::SeqCst)
    }

    /// True once the channel has entered the closed state. Distinct from
    /// "not open": a still-connecting channel is neither open nor closed,
    /// matching upstream `Channel::isClosed()`.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// True for a channel created from an inbound OPEN.
    pub(crate) fn is_incoming(&self) -> bool {
        self.inner.incoming
    }

    /// Swap the callback set at runtime (used by `PeerConnection` to install
    /// application callbacks on an inbound channel after construction).
    pub fn set_callbacks(&self, callbacks: DataChannelCallbacks) {
        *self.inner.callbacks.lock() = callbacks;
    }

    /// Send a UTF-8 text message on the channel.
    pub fn send_text(&self, text: &str) -> Result<(), DataChannelError> {
        self.send_inner(text.as_bytes(), false)
    }

    /// Send a binary message on the channel.
    pub fn send_binary(&self, data: &[u8]) -> Result<(), DataChannelError> {
        self.send_inner(data, true)
    }

    /// Send raw bytes as a binary message (the reference crate's
    /// `send(&[u8])`). Equivalent to [`send_binary`](Self::send_binary).
    pub fn send(&self, data: &[u8]) -> Result<(), DataChannelError> {
        self.send_inner(data, true)
    }

    /// Common send path: maps the payload to the right PPID and either sends
    /// it (if open) or buffers it (if not yet open) — matching
    /// libdatachannel's buffer-until-open behaviour.
    fn send_inner(&self, data: &[u8], binary: bool) -> Result<(), DataChannelError> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(DataChannelError::Closed);
        }
        if !self.inner.open.load(Ordering::SeqCst) {
            // Buffer until the handshake completes; flushed by mark_open().
            self.inner.send_queue.lock().push((data.to_vec(), binary));
            return Ok(());
        }
        self.send_user_now(data, binary)
    }

    /// Map a user payload to the right PPID and send it immediately over
    /// SCTP. Empty payloads use the `*Empty` PPID; the transport's `send`
    /// already pads a single zero byte for empty `data`.
    fn send_user_now(&self, data: &[u8], binary: bool) -> Result<(), DataChannelError> {
        let sctp = self
            .inner
            .sctp
            .lock()
            .clone()
            .ok_or(DataChannelError::NotOpen)?;
        let ppid = match (binary, data.is_empty()) {
            (false, false) => PayloadProtocolId::String,
            (false, true) => PayloadProtocolId::StringEmpty,
            (true, false) => PayloadProtocolId::Binary,
            (true, true) => PayloadProtocolId::BinaryEmpty,
        };
        let msg = SctpMessage {
            stream: self.inner.stream.load(Ordering::SeqCst),
            ppid,
            data: data.to_vec(),
        };
        sctp.send(&msg, &self.inner.reliability)?;
        Ok(())
    }

    /// Attach the SCTP transport to this channel (called once SCTP is up).
    pub(crate) fn attach_transport(&self, sctp: Arc<SctpTransport>) {
        *self.inner.sctp.lock() = Some(sctp);
    }

    /// Drive the outbound DCEP OPEN for a locally-created channel. No-op for
    /// incoming channels (they never send OPEN) and for already-open ones.
    /// Sends the `DATA_CHANNEL_OPEN` control message on this channel's
    /// stream.
    pub(crate) fn send_open(&self) -> Result<(), DataChannelError> {
        if self.inner.incoming || self.inner.open.load(Ordering::SeqCst) {
            return Ok(());
        }
        let sctp = self
            .inner
            .sctp
            .lock()
            .clone()
            .ok_or(DataChannelError::NotOpen)?;
        let body = encode_open(
            &self.inner.label,
            &self.inner.protocol,
            &self.inner.reliability,
        );
        let msg = SctpMessage {
            stream: self.inner.stream.load(Ordering::SeqCst),
            ppid: PayloadProtocolId::Control,
            data: body,
        };
        // DCEP control is always sent reliably/ordered, regardless of the
        // channel's user-data reliability (RFC 8832 §5).
        sctp.send(&msg, &Reliability::reliable())?;
        Ok(())
    }

    /// Send a DCEP `DATA_CHANNEL_ACK` on this channel's stream (the
    /// receiving side's reply to an inbound OPEN).
    pub(crate) fn send_ack(&self) -> Result<(), DataChannelError> {
        let sctp = self
            .inner
            .sctp
            .lock()
            .clone()
            .ok_or(DataChannelError::NotOpen)?;
        let msg = SctpMessage {
            stream: self.inner.stream.load(Ordering::SeqCst),
            ppid: PayloadProtocolId::Control,
            data: encode_ack(),
        };
        sctp.send(&msg, &Reliability::reliable())?;
        Ok(())
    }

    /// Transition the channel to open (idempotent), flush any queued user
    /// data, and fire `on_open` on the first transition.
    pub(crate) fn mark_open(&self) {
        if self.inner.open.swap(true, Ordering::SeqCst) {
            return;
        }
        // Flush buffered user data now that the handshake is complete.
        let queued: Vec<(Vec<u8>, bool)> = std::mem::take(&mut *self.inner.send_queue.lock());
        for (data, binary) in queued {
            // Best-effort: if the transport went away the send simply fails.
            let _ = self.send_user_now(&data, binary);
        }
        let cb = Arc::clone(&self.inner.callbacks.lock().on_open);
        (cb)();
    }

    /// Route an inbound user message (already PPID-decoded) to the
    /// application callback. `binary` distinguishes text vs binary; `data`
    /// has had any `*Empty` padding stripped by the caller.
    pub(crate) fn deliver_message(&self, data: &[u8], binary: bool) {
        if self.inner.closed.load(Ordering::SeqCst) {
            return;
        }
        // Per RFC 8832, the creating side MAY treat the first inbound data as
        // an implicit open if the ACK was lost. Honour that here.
        if !self.inner.open.load(Ordering::SeqCst) {
            self.mark_open();
        }
        let cb = Arc::clone(&self.inner.callbacks.lock().on_message);
        (cb)(data, binary);
    }

    /// Bytes queued for sending but not yet accepted by the SCTP transport
    /// (i.e. waiting behind usrsctp backpressure). Mirrors
    /// `rtc::DataChannel::bufferedAmount`.
    pub fn buffered_amount(&self) -> usize {
        self.inner.buffered_amount.load(Ordering::SeqCst)
    }

    /// Set the low-water threshold for [`on_buffered_amount_low`]. When the
    /// buffered amount drops from above this value to at-or-below it, the
    /// callback fires. Defaults to 0. Mirrors
    /// `rtc::DataChannel::setBufferedAmountLowThreshold`.
    pub fn set_buffered_amount_low_threshold(&self, amount: usize) {
        self.inner
            .buffered_amount_low_threshold
            .store(amount, Ordering::SeqCst);
    }

    /// Record a new buffered-amount value reported by the SCTP transport for
    /// this channel's stream, and fire `on_buffered_amount_low` on the
    /// high→low transition. Port of `Channel::triggerBufferedAmount`: the
    /// callback fires only when the previous amount was *above* the threshold
    /// and the new amount is *at or below* it (edge-triggered, not level).
    pub(crate) fn trigger_buffered_amount(&self, amount: usize) {
        let previous = self.inner.buffered_amount.swap(amount, Ordering::SeqCst);
        let threshold = self.inner.buffered_amount_low_threshold.load(Ordering::SeqCst);
        if previous > threshold && amount <= threshold {
            let cb = Arc::clone(&self.inner.callbacks.lock().on_buffered_amount_low);
            (cb)();
        }
    }

    /// Close the channel (idempotent), firing `on_closed` on the first
    /// transition. Does not tear down the SCTP association (other channels
    /// may share it).
    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let cb = Arc::clone(&self.inner.callbacks.lock().on_closed);
        (cb)();
    }
}

impl std::fmt::Debug for DataChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataChannel")
            .field("label", &self.inner.label)
            .field("stream", &self.inner.stream.load(Ordering::SeqCst))
            .field("incoming", &self.inner.incoming)
            .field("open", &self.inner.open.load(Ordering::SeqCst))
            .field("closed", &self.inner.closed.load(Ordering::SeqCst))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_round_trips_reliable() {
        let rel = Reliability::reliable();
        let encoded = encode_open("chat", "proto", &rel);
        // Header (12) + label (4) + protocol (5).
        assert_eq!(encoded.len(), OPEN_HEADER_LEN + 4 + 5);
        assert_eq!(encoded[0], MESSAGE_OPEN);
        assert_eq!(encoded[1], CHANNEL_RELIABLE);

        let decoded = decode_open(&encoded).expect("decode");
        assert_eq!(decoded.label, "chat");
        assert_eq!(decoded.protocol, "proto");
        assert_eq!(decoded.reliability.typ, ReliabilityType::Reliable);
        assert!(!decoded.reliability.unordered);
        assert_eq!(decoded.priority, 0);
    }

    #[test]
    fn open_round_trips_unordered_rexmit() {
        let mut rel = Reliability::unreliable_retransmits(7);
        rel.unordered = true;
        let encoded = encode_open("v", "", &rel);
        assert_eq!(
            encoded[1],
            CHANNEL_PARTIAL_RELIABLE_REXMIT | CHANNEL_UNORDERED
        );

        let decoded = decode_open(&encoded).expect("decode");
        assert_eq!(decoded.label, "v");
        assert_eq!(decoded.protocol, "");
        assert_eq!(decoded.reliability.typ, ReliabilityType::Rexmit);
        assert_eq!(decoded.reliability.rexmit, 7);
        assert!(decoded.reliability.unordered);
    }

    #[test]
    fn open_round_trips_timed() {
        let rel = Reliability::unreliable_timed(2500);
        let encoded = encode_open("timed", "p", &rel);
        assert_eq!(encoded[1], CHANNEL_PARTIAL_RELIABLE_TIMED);
        let decoded = decode_open(&encoded).expect("decode");
        assert_eq!(decoded.reliability.typ, ReliabilityType::Timed);
        assert_eq!(decoded.reliability.rexmit, 2500);
        assert!(!decoded.reliability.unordered);
    }

    #[test]
    fn open_handles_utf8_label() {
        let rel = Reliability::reliable();
        let encoded = encode_open("café→chat", "x-proto", &rel);
        let decoded = decode_open(&encoded).expect("decode");
        assert_eq!(decoded.label, "café→chat");
        assert_eq!(decoded.protocol, "x-proto");
    }

    #[test]
    fn ack_encodes_single_byte() {
        let ack = encode_ack();
        assert_eq!(ack, vec![MESSAGE_ACK]);
        assert_eq!(decode_control(&ack).unwrap(), DcepMessage::Ack);
    }

    #[test]
    fn decode_control_routes_open_and_ack() {
        let open = encode_open("l", "", &Reliability::reliable());
        match decode_control(&open).unwrap() {
            DcepMessage::Open(m) => assert_eq!(m.label, "l"),
            _ => panic!("expected open"),
        }
        assert_eq!(decode_control(&encode_ack()).unwrap(), DcepMessage::Ack);
    }

    #[test]
    fn decode_control_rejects_empty() {
        let err = decode_control(&[]).unwrap_err();
        assert!(matches!(err, DataChannelError::Malformed(_)));
    }

    #[test]
    fn decode_control_rejects_unknown_type() {
        let err = decode_control(&[0x7F]).unwrap_err();
        assert!(matches!(err, DataChannelError::Malformed(_)));
    }

    #[test]
    fn decode_open_rejects_short_header() {
        // 11 bytes < 12-byte header.
        let err = decode_open(&[MESSAGE_OPEN; 11]).unwrap_err();
        assert!(matches!(err, DataChannelError::Malformed(_)));
    }

    #[test]
    fn decode_open_rejects_truncated_body() {
        // Header claims a 10-byte label but the body is empty.
        let mut buf = vec![MESSAGE_OPEN, CHANNEL_RELIABLE, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&10u16.to_be_bytes()); // label_length = 10
        buf.extend_from_slice(&0u16.to_be_bytes()); // protocol_length = 0
        // no body bytes
        let err = decode_open(&buf).unwrap_err();
        assert!(matches!(err, DataChannelError::Malformed(_)));
    }

    #[test]
    fn decode_open_rejects_invalid_utf8_label() {
        let mut buf = vec![MESSAGE_OPEN, CHANNEL_RELIABLE, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&2u16.to_be_bytes()); // label_length = 2
        buf.extend_from_slice(&0u16.to_be_bytes()); // protocol_length = 0
        buf.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        let err = decode_open(&buf).unwrap_err();
        assert!(matches!(err, DataChannelError::Malformed(_)));
    }

    #[test]
    fn stream_allocator_client_is_even() {
        let mut a = StreamIdAllocator::new(true);
        assert_eq!(a.allocate(), 0);
        assert_eq!(a.allocate(), 2);
        assert_eq!(a.allocate(), 4);
    }

    #[test]
    fn stream_allocator_server_is_odd() {
        let mut a = StreamIdAllocator::new(false);
        assert_eq!(a.allocate(), 1);
        assert_eq!(a.allocate(), 3);
        assert_eq!(a.allocate(), 5);
    }

    #[test]
    fn stream_allocator_reserve_skips_past() {
        let mut a = StreamIdAllocator::new(true);
        a.reserve(4);
        assert_eq!(a.allocate(), 6);
    }

    #[test]
    fn outgoing_channel_buffers_until_open() {
        let dc = DataChannel::new_outgoing(
            "chat".into(),
            0,
            DataChannelInit::default(),
            DataChannelCallbacks::default(),
        );
        assert!(!dc.is_open());
        // Send before open: buffered, returns Ok, not an error.
        dc.send_text("queued").expect("buffered send ok");
        // No transport attached, but mark_open's flush is best-effort so it
        // won't panic.
        dc.mark_open();
        assert!(dc.is_open());
    }

    #[test]
    fn closed_channel_rejects_send() {
        let dc = DataChannel::new_outgoing(
            "chat".into(),
            0,
            DataChannelInit::default(),
            DataChannelCallbacks::default(),
        );
        dc.close();
        assert!(matches!(dc.send_text("x"), Err(DataChannelError::Closed)));
    }

    #[test]
    fn incoming_channel_carries_wire_metadata() {
        let open = OpenMessage {
            label: "chat".into(),
            protocol: "p".into(),
            reliability: Reliability::reliable(),
            priority: 0,
        };
        let dc = DataChannel::new_incoming(3, &open);
        assert_eq!(dc.label(), "chat");
        assert_eq!(dc.protocol(), "p");
        assert_eq!(dc.stream(), 3);
        assert!(dc.is_incoming());
    }

    /// Build an outgoing channel whose `on_buffered_amount_low` bumps a shared
    /// counter, returning both so tests can drive `trigger_buffered_amount`
    /// and observe firings.
    fn dc_with_low_counter() -> (DataChannel, Arc<AtomicUsize>) {
        let fired = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fired);
        let callbacks = DataChannelCallbacks {
            on_buffered_amount_low: Arc::new(move || {
                f.fetch_add(1, Ordering::SeqCst);
            }),
            ..DataChannelCallbacks::default()
        };
        let dc = DataChannel::new_outgoing("chat".into(), 0, DataChannelInit::default(), callbacks);
        (dc, fired)
    }

    #[test]
    fn buffered_amount_mirrors_last_reported_value() {
        let (dc, _) = dc_with_low_counter();
        assert_eq!(dc.buffered_amount(), 0);
        dc.trigger_buffered_amount(4096);
        assert_eq!(dc.buffered_amount(), 4096);
        dc.trigger_buffered_amount(100);
        assert_eq!(dc.buffered_amount(), 100);
    }

    #[test]
    fn buffered_amount_low_fires_only_on_high_to_low_transition() {
        let (dc, fired) = dc_with_low_counter();
        // Default threshold is 0; the callback fires when crossing from
        // above 0 down to 0 (edge-triggered).
        dc.trigger_buffered_amount(8192); // 0 -> 8192: rising, no fire
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        dc.trigger_buffered_amount(4096); // 8192 -> 4096: still above, no fire
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        dc.trigger_buffered_amount(0); // 4096 -> 0: crosses threshold, fires
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        // Already at/below threshold: a repeat 0 must not re-fire.
        dc.trigger_buffered_amount(0);
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn buffered_amount_low_respects_custom_threshold() {
        let (dc, fired) = dc_with_low_counter();
        dc.set_buffered_amount_low_threshold(1024);
        dc.trigger_buffered_amount(4096); // above threshold
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        dc.trigger_buffered_amount(1024); // 4096 -> 1024 (== threshold): fires
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        // Rise back above, then drop to just at/below to fire again.
        dc.trigger_buffered_amount(2048); // rising past threshold
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        dc.trigger_buffered_amount(512); // 2048 -> 512 (< threshold): fires
        assert_eq!(fired.load(Ordering::SeqCst), 2);
    }
}
