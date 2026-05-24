//! Native Rust port of [libdatachannel](https://github.com/paullouisageneau/libdatachannel).
//!
//! This crate is the runtime; it is **not** an FFI wrapper. It exposes the same
//! public Rust surface as the `datachannel` reference crate so downstream code
//! can swap implementations transparently.
//!
//! See `rust/API_SURFACE.md` at the repo root for the target surface.

#![warn(missing_docs)]
#![warn(unreachable_pub)]
// During the in-progress port we accept dead code — modules land in pieces.
#![allow(dead_code)]

mod candidate;
mod capi;
mod certificate;
pub mod codec;
mod configuration;
mod data_channel;
mod description;
mod dtls_transport;
mod error;
mod ice_transport;
mod media_handler;
mod peer_connection;
mod reliability;
mod rtp;
mod rtp_packetizer;
mod sctp_transport;
mod srtp_sys;
mod srtp_transport;
mod track;
mod usrsctp_sys;

pub use candidate::{Candidate, CandidateType, Family, ParseError as CandidateParseError, TransportType};
pub use certificate::{Certificate, CertificateError};
pub use configuration::{
    CertificateType, Configuration, CongestionControl, IceServer, IceServerParseError,
    IceServerType, IceTransportPolicy, ProxyServer, ProxyType, RelayType, TransportPolicy,
};
pub use description::{
    Application, Description, DescriptionParseError, Direction, Fingerprint,
    FingerprintAlgorithm, Role, Type,
};
pub use dtls_transport::{
    DtlsState, DtlsTransport, DtlsTransportCallbacks, DtlsTransportError,
};
pub use error::{Error, Result};
pub use ice_transport::{
    GatheringState, IceTransport, IceTransportCallbacks, IceTransportError, State as IceState,
};
pub use data_channel::{
    DataChannel, DataChannelCallbacks, DataChannelError, DataChannelInit,
};
pub use peer_connection::{
    GatheringState as PeerGatheringState, PeerConnection, PeerConnectionCallbacks,
    PeerConnectionError, PeerConnectionState, SignalingState,
};
pub use reliability::{Reliability, ReliabilityType};
pub use rtp::{
    is_rtcp, RtcpFbHeader, RtcpHeader, RtcpNack, RtcpNackPart, RtcpPli, RtcpRemb, RtcpReportBlock,
    RtcpRr, RtcpSr, RtpExtensionHeader, RtpHeader, Ssrc, RTCP_FB_HEADER_SIZE, RTCP_FMT_AFB,
    RTCP_FMT_FIR, RTCP_FMT_NACK, RTCP_FMT_PLI, RTCP_HEADER_SIZE, RTCP_PT_BYE, RTCP_PT_PSFB,
    RTCP_PT_RR, RTCP_PT_RTPFB, RTCP_PT_SDES, RTCP_PT_SR, RTCP_REPORT_BLOCK_SIZE, RTP_HEADER_SIZE,
};
pub use media_handler::{
    MediaHandler, MediaHandlerChain, Message, MessageType, PacingHandler, PliHandler,
    RembHandler, RtcpNackResponder, RtcpReceivingSession, RtcpSrReporter, Sender,
};
pub use rtp_packetizer::{
    DepacketizedFrame, RtpDepacketizer, RtpPacketizationConfig, RtpPacketizer, VIDEO_CLOCK_RATE,
};
pub use codec::{
    av1::{Av1RtpPacketizer, Packetization as Av1Packetization},
    h264::{H264RtpDepacketizer, H264RtpPacketizer},
    h265::{H265RtpDepacketizer, H265RtpPacketizer},
    nal::Separator as NalSeparator,
    vp8::{Vp8RtpDepacketizer, Vp8RtpPacketizer},
    Fragmenter, DEFAULT_MAX_FRAGMENT_SIZE,
};
pub use track::{
    Codec, Media as TrackMedia, RtpMap, SsrcEntry, Track, TrackCallbacks, TrackError, TrackInit,
};
pub use sctp_transport::{
    PayloadProtocolId, SctpMessage, SctpState, SctpTransport, SctpTransportCallbacks,
    SctpTransportError,
};
pub use srtp_transport::{
    srtp_version, SrtpTransport, SrtpTransportCallbacks, SrtpTransportError,
    DEFAULT_SRTP_PROFILES,
};

/// Optional resource preload (no-op until task #17 lands the runtime).
pub fn preload() {}

/// Optional resource cleanup (no-op until task #17 lands the runtime).
pub fn cleanup() {}
