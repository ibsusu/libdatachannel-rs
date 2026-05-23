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
mod description;
mod error;

pub use candidate::{Candidate, CandidateType, Family, ParseError as CandidateParseError, TransportType};
pub use description::{
    Application, Description, DescriptionParseError, Direction, Fingerprint,
    FingerprintAlgorithm, Role, Type,
};
pub use error::{Error, Result};

/// Optional resource preload (no-op until task #17 lands the runtime).
pub fn preload() {}

/// Optional resource cleanup (no-op until task #17 lands the runtime).
pub fn cleanup() {}
