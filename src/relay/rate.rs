// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The rate a relay received media at on one socket, between two answers.
//!
//! Vendor-neutral by construction: the inputs are the counters and identity a
//! relay implementation already decoded into [`super::types`], and the clock
//! is an argument. Nothing here asks a relay anything or reads a clock, so
//! every outcome can be driven from a test.
//!
//! # Why the identity is compared, not only the deltas
//!
//! A counter that goes backwards is a reset, but that rule alone misses a new
//! call with the same Call-ID whose counters already exceed the old ones by
//! the time the second answer arrives. Every delta is positive and the rate is
//! still wrong. So a change of the call's [`Incarnation`] or of the socket is a
//! reset too, whatever the deltas say.

use std::time::Duration;

use super::types::Counters;
use super::types::Incarnation;

/// Which relay socket a sample describes: the relay's own address and port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    /// The relay's own address for the stream.
    pub address: String,
    /// The relay's own port for the stream.
    pub port: u16,
}

/// One answer's view of one stream, stamped with when it arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateSample {
    /// When the answer arrived, on the caller's monotonic clock. Only the
    /// difference between two samples is used.
    pub at: Duration,
    /// The call's identity at the relay, when the relay reported one.
    pub incarnation: Option<Incarnation>,
    /// The relay socket the counters belong to.
    pub socket: Socket,
    /// Whether the stream carries RTCP rather than RTP.
    pub is_rtcp: bool,
    /// What the relay received on the socket, when it reported it.
    pub ingress: Option<Counters>,
}

/// Why two samples cannot be compared as one continuous count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetReason {
    /// The call's creation time changed: a different call with the same
    /// Call-ID, or the same call after a relay restart.
    IncarnationChanged,
    /// The sample describes a different relay socket or stream kind.
    SocketChanged,
    /// A counter is lower than in the previous sample.
    CounterWentBackwards,
    /// The rate does not fit the result type: a delta this large over this
    /// interval is not a count of one stream's media.
    RateOutOfRange,
}

/// The result of comparing two samples of one stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateOutcome {
    /// Bytes and packets per second received, rounded down, over `over`.
    Rate {
        /// Bytes per second.
        bytes_per_s: u64,
        /// Packets per second.
        packets_per_s: u64,
        /// The measured gap between the two answers that the rate covers.
        over: Duration,
    },
    /// There is no previous answer to compare with.
    NoRateYet,
    /// The two samples are not one continuous count.
    Reset {
        /// What made them incomparable.
        reason: ResetReason,
    },
    /// A counter is missing from one of the samples: the relay version did
    /// not report it. Never shown as zero.
    NotReported,
    /// The clock did not advance between the two samples.
    NoInterval,
    /// An RTCP stream: its rate is not computed and not part of any total.
    RtcpNotCounted,
}

/// The rate `current` shows against `previous`.
///
/// The divisor is the measured gap `current.at - previous.at`, never a
/// configured interval: a poll that slipped covers a longer gap.
#[must_use]
pub fn relay_rate(previous: Option<&RateSample>, current: &RateSample) -> RateOutcome {
    if current.is_rtcp {
        return RateOutcome::RtcpNotCounted;
    }
    let Some(previous) = previous else {
        return RateOutcome::NoRateYet;
    };
    if previous.socket != current.socket || previous.is_rtcp != current.is_rtcp {
        return RateOutcome::Reset {
            reason: ResetReason::SocketChanged,
        };
    }
    if previous.incarnation != current.incarnation {
        return RateOutcome::Reset {
            reason: ResetReason::IncarnationChanged,
        };
    }
    let (Some(before), Some(now)) = (previous.ingress, current.ingress) else {
        return RateOutcome::NotReported;
    };
    let (Some(bytes), Some(packets)) = (
        now.bytes.checked_sub(before.bytes),
        now.packets.checked_sub(before.packets),
    ) else {
        return RateOutcome::Reset {
            reason: ResetReason::CounterWentBackwards,
        };
    };
    let over = match current.at.checked_sub(previous.at) {
        Some(gap) if !gap.is_zero() => gap,
        _ => return RateOutcome::NoInterval,
    };
    match (per_second(bytes, over), per_second(packets, over)) {
        (Some(bytes_per_s), Some(packets_per_s)) => RateOutcome::Rate {
            bytes_per_s,
            packets_per_s,
            over,
        },
        _ => RateOutcome::Reset {
            reason: ResetReason::RateOutOfRange,
        },
    }
}

/// `delta` per second over `over`, rounded down, in integer arithmetic so the
/// result is the same on every platform. `None` when it does not fit a `u64`.
fn per_second(delta: u64, over: Duration) -> Option<u64> {
    let scaled = u128::from(delta).checked_mul(1_000_000_000)?;
    u64::try_from(scaled / over.as_nanos()).ok()
}

/// The total ingress rate of a call: the sum of every [`RateOutcome::Rate`].
///
/// `None` when no stream has a rate, so a call with nothing to sum is not
/// reported as receiving nothing.
#[must_use]
pub fn call_total(outcomes: &[RateOutcome]) -> Option<(u64, u64)> {
    let mut total: Option<(u64, u64)> = None;
    for outcome in outcomes {
        if let RateOutcome::Rate {
            bytes_per_s,
            packets_per_s,
            ..
        } = outcome
        {
            // Saturating, not checked: each addend is already a rate that fit
            // a u64, and a sum past u64::MAX bytes per second is not a call.
            let (bytes, packets) = total.unwrap_or((0, 0));
            total = Some((
                bytes.saturating_add(*bytes_per_s),
                packets.saturating_add(*packets_per_s),
            ));
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sample of an RTP stream on a documentation address.
    fn sample(at_ms: u64, bytes: u64, packets: u64) -> RateSample {
        RateSample {
            at: Duration::from_millis(at_ms),
            incarnation: Some(Incarnation {
                created_s: 1_789_316_560,
                created_us: Some(132_898),
            }),
            socket: Socket {
                address: "192.0.2.10".to_owned(),
                port: 30024,
            },
            is_rtcp: false,
            ingress: Some(Counters {
                packets,
                bytes,
                errors: 0,
            }),
        }
    }

    // 1.1
    #[test]
    fn one_second_apart_gives_the_delta_per_second() {
        let outcome = relay_rate(
            Some(&sample(10_000, 160_000, 931)),
            &sample(11_000, 176_000, 1031),
        );
        assert_eq!(
            outcome,
            RateOutcome::Rate {
                bytes_per_s: 16_000,
                packets_per_s: 100,
                over: Duration::from_secs(1),
            }
        );
    }

    // 1.2
    #[test]
    fn the_divisor_is_the_measured_gap_not_a_nominal_interval() {
        let outcome = relay_rate(
            Some(&sample(10_000, 160_000, 931)),
            &sample(11_500, 176_000, 1031),
        );
        assert_eq!(
            outcome,
            RateOutcome::Rate {
                bytes_per_s: 10_666,
                packets_per_s: 66,
                over: Duration::from_millis(1500),
            }
        );
    }

    // 1.3
    #[test]
    fn the_first_answer_has_no_rate_yet() {
        assert_eq!(
            relay_rate(None, &sample(10_000, 160_000, 931)),
            RateOutcome::NoRateYet
        );
    }

    // 1.4
    #[test]
    fn a_counter_going_backwards_is_a_reset_not_a_negative_rate() {
        let outcome = relay_rate(
            Some(&sample(10_000, 176_000, 1031)),
            &sample(11_000, 160_000, 1100),
        );
        assert_eq!(
            outcome,
            RateOutcome::Reset {
                reason: ResetReason::CounterWentBackwards
            }
        );
        let packets_back = relay_rate(
            Some(&sample(10_000, 160_000, 1031)),
            &sample(11_000, 176_000, 931),
        );
        assert_eq!(
            packets_back,
            RateOutcome::Reset {
                reason: ResetReason::CounterWentBackwards
            }
        );
    }

    // 1.5: the incarnations of the two committed 12.5.1 replies.
    #[test]
    fn a_new_incarnation_is_a_reset_even_when_every_delta_is_positive() {
        let mut earlier = sample(10_000, 160_000, 931);
        earlier.incarnation = Some(Incarnation {
            created_s: 1_787_517_788,
            created_us: Some(160_191),
        });
        let outcome = relay_rate(Some(&earlier), &sample(11_000, 176_000, 1031));
        assert_eq!(
            outcome,
            RateOutcome::Reset {
                reason: ResetReason::IncarnationChanged
            }
        );
    }

    /// The same creation second with a different microsecond part is a
    /// different call.
    #[test]
    fn a_change_in_the_microsecond_part_alone_is_a_reset() {
        let mut earlier = sample(10_000, 160_000, 931);
        earlier.incarnation = Some(Incarnation {
            created_s: 1_789_316_560,
            created_us: Some(132_899),
        });
        assert_eq!(
            relay_rate(Some(&earlier), &sample(11_000, 176_000, 1031)),
            RateOutcome::Reset {
                reason: ResetReason::IncarnationChanged
            }
        );
    }

    #[test]
    fn a_different_socket_is_a_reset() {
        let mut earlier = sample(10_000, 160_000, 931);
        earlier.socket.port = 30018;
        assert_eq!(
            relay_rate(Some(&earlier), &sample(11_000, 176_000, 1031)),
            RateOutcome::Reset {
                reason: ResetReason::SocketChanged
            }
        );
    }

    // 1.6
    #[test]
    fn an_rtcp_stream_has_no_rate_and_is_left_out_of_the_call_total() {
        let mut rtcp_before = sample(10_000, 4_000, 20);
        rtcp_before.is_rtcp = true;
        rtcp_before.socket.port = 30025;
        let mut rtcp_now = sample(11_000, 9_000, 45);
        rtcp_now.is_rtcp = true;
        rtcp_now.socket.port = 30025;
        let rtcp = relay_rate(Some(&rtcp_before), &rtcp_now);
        assert_eq!(rtcp, RateOutcome::RtcpNotCounted);

        let rtp = relay_rate(
            Some(&sample(10_000, 160_000, 931)),
            &sample(11_000, 176_000, 1031),
        );
        assert_eq!(call_total(&[rtp, rtcp]), Some((16_000, 100)));
    }

    #[test]
    fn a_call_with_no_rate_has_no_total_rather_than_zero() {
        assert_eq!(
            call_total(&[RateOutcome::NoRateYet, RateOutcome::RtcpNotCounted]),
            None
        );
    }

    // 1.7
    #[test]
    fn a_missing_counter_is_not_reported_never_zero() {
        let mut no_stats = sample(11_000, 176_000, 1031);
        no_stats.ingress = None;
        assert_eq!(
            relay_rate(Some(&sample(10_000, 160_000, 931)), &no_stats),
            RateOutcome::NotReported
        );
        let mut earlier_no_stats = sample(10_000, 160_000, 931);
        earlier_no_stats.ingress = None;
        assert_eq!(
            relay_rate(Some(&earlier_no_stats), &sample(11_000, 176_000, 1031)),
            RateOutcome::NotReported
        );
    }

    // 1.8
    #[test]
    fn a_clock_that_did_not_advance_gives_no_interval() {
        assert_eq!(
            relay_rate(
                Some(&sample(10_000, 160_000, 931)),
                &sample(10_000, 176_000, 1031)
            ),
            RateOutcome::NoInterval
        );
        assert_eq!(
            relay_rate(
                Some(&sample(11_000, 160_000, 931)),
                &sample(10_000, 176_000, 1031)
            ),
            RateOutcome::NoInterval
        );
    }

    /// A delta that cannot be one stream's media over the gap is refused,
    /// not wrapped or saturated into a plausible-looking number.
    #[test]
    fn a_rate_beyond_the_result_type_is_refused() {
        assert_eq!(
            relay_rate(Some(&sample(10_000, 0, 0)), &sample(10_001, u64::MAX, 1)),
            RateOutcome::Reset {
                reason: ResetReason::RateOutOfRange
            }
        );
    }
}
