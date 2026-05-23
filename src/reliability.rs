//! Data-channel reliability parameters, mirroring `rtc::Reliability` from
//! libdatachannel C++.
//!
//! The C++ struct exposes both a deprecated `Type`/`rexmit` pair and the
//! newer `maxPacketLifeTime` / `maxRetransmits` optionals. The two paths
//! are equivalent — we model the deprecated tagged form here because it
//! matches what the data-channel init negotiation actually consumes inside
//! the runtime (Task #20 will wire it into the SCTP layer).

/// Reliability mode for a data channel. Mirrors `rtc::Reliability::Type`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ReliabilityType {
    /// Fully reliable, in-order delivery (default). The `rexmit` field is
    /// ignored.
    Reliable,
    /// Partially reliable with a maximum number of retransmissions. The
    /// `rexmit` field is the retransmit count.
    Rexmit,
    /// Partially reliable with a maximum packet lifetime. The `rexmit`
    /// field is the lifetime in milliseconds.
    Timed,
}

impl ReliabilityType {
    /// Token used in the deprecated C++ enum.
    pub fn as_str(self) -> &'static str {
        match self {
            ReliabilityType::Reliable => "reliable",
            ReliabilityType::Rexmit => "rexmit",
            ReliabilityType::Timed => "timed",
        }
    }
}

/// Reliability parameters for a data channel.
///
/// Mirrors `rtc::Reliability`. The C++ struct uses a `variant<int, milliseconds>`
/// for `rexmit`; we collapse that to a single `u32` because both arms have
/// the same wire representation — the interpretation depends on
/// [`ReliabilityType`]:
///
/// - [`ReliabilityType::Reliable`]: `rexmit` is ignored.
/// - [`ReliabilityType::Rexmit`]: `rexmit` is the maximum number of
///   retransmissions.
/// - [`ReliabilityType::Timed`]: `rexmit` is the maximum packet lifetime
///   in milliseconds.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Reliability {
    /// If true, the channel does not enforce message ordering and out-of-order
    /// delivery is allowed.
    pub unordered: bool,
    /// Reliability mode.
    pub typ: ReliabilityType,
    /// Retransmit count (for [`ReliabilityType::Rexmit`]) or packet lifetime
    /// in milliseconds (for [`ReliabilityType::Timed`]). Ignored for
    /// [`ReliabilityType::Reliable`]. Matches the C++ `rtc::Reliability::rexmit`
    /// variant.
    pub rexmit: u32,
}

impl Reliability {
    /// Default reliability: fully reliable, in-order delivery.
    pub fn new() -> Self {
        Reliability {
            unordered: false,
            typ: ReliabilityType::Reliable,
            rexmit: 0,
        }
    }

    /// Fully reliable, in-order delivery. Equivalent to [`Reliability::new`].
    pub fn reliable() -> Self {
        Self::new()
    }

    /// Partially reliable, capped at `max_retransmits` retries per message.
    pub fn unreliable_retransmits(max_retransmits: u32) -> Self {
        Reliability {
            unordered: false,
            typ: ReliabilityType::Rexmit,
            rexmit: max_retransmits,
        }
    }

    /// Partially reliable, capped at `max_lifetime_ms` milliseconds per
    /// message.
    pub fn unreliable_timed(max_lifetime_ms: u32) -> Self {
        Reliability {
            unordered: false,
            typ: ReliabilityType::Timed,
            rexmit: max_lifetime_ms,
        }
    }
}

impl Default for Reliability {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_fully_reliable() {
        let r = Reliability::default();
        assert_eq!(r.typ, ReliabilityType::Reliable);
        assert_eq!(r.rexmit, 0);
        assert!(!r.unordered);
        assert_eq!(r, Reliability::new());
        assert_eq!(r, Reliability::reliable());
    }

    #[test]
    fn unreliable_retransmits_sets_rexmit_type_and_value() {
        let r = Reliability::unreliable_retransmits(5);
        assert_eq!(r.typ, ReliabilityType::Rexmit);
        assert_eq!(r.rexmit, 5);
        assert!(!r.unordered);
    }

    #[test]
    fn unreliable_timed_sets_timed_type_and_lifetime() {
        let r = Reliability::unreliable_timed(2500);
        assert_eq!(r.typ, ReliabilityType::Timed);
        assert_eq!(r.rexmit, 2500);
        assert!(!r.unordered);
    }

    #[test]
    fn unordered_flag_is_independent_of_type() {
        // The unordered flag is set by the caller after construction; it
        // doesn't depend on the reliability type.
        let mut r = Reliability::unreliable_retransmits(3);
        r.unordered = true;
        assert!(r.unordered);
        assert_eq!(r.typ, ReliabilityType::Rexmit);

        let mut r = Reliability::reliable();
        r.unordered = true;
        assert!(r.unordered);
        assert_eq!(r.typ, ReliabilityType::Reliable);
    }

    #[test]
    fn clone_eq() {
        let r = Reliability::unreliable_timed(1000);
        let copy = r;
        assert_eq!(r, copy);
        assert_eq!(r.clone(), r);
    }

    #[test]
    fn reliable_resets_to_defaults() {
        // Helpers can be chained: start unreliable, then switch back.
        let mut r = Reliability::unreliable_retransmits(10);
        r.unordered = true;
        // Replacing with `reliable()` should drop the rexmit/timed bits.
        r = Reliability::reliable();
        assert_eq!(r.typ, ReliabilityType::Reliable);
        assert_eq!(r.rexmit, 0);
        assert!(!r.unordered);
    }

    #[test]
    fn type_as_str_tokens() {
        assert_eq!(ReliabilityType::Reliable.as_str(), "reliable");
        assert_eq!(ReliabilityType::Rexmit.as_str(), "rexmit");
        assert_eq!(ReliabilityType::Timed.as_str(), "timed");
    }
}
