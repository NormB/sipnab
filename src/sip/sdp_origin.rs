// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! When a shared SDP origin is evidence that two dialogs carry one media
//! session, and when it is not.
//!
//! [RFC 8866 section 5.2](https://www.rfc-editor.org/rfc/rfc8866.html#section-5.2)
//! says the tuple of `<username>`, `<sess-id>`, `<nettype>`, `<addrtype>` and
//! `<unicast-address>` *"forms a globally unique identifier for the session"*.
//! Endpoints do not all honor that. SIPp's built-in `uac` scenario writes
//! `o=user1 53655765 2353687637 IN IP4 <ip>` into every call it places, and
//! phones and gateways that write a constant `sess-id` exist. Matching the
//! tuple alone therefore joined unrelated calls and reported the join as an
//! identifier match at score 90.
//!
//! # The rule
//!
//! Two dialogs that carry the same origin tuple are one media session only
//! when both of these hold:
//!
//! 1. **Their lifetimes overlap.** A B2BUA that passes SDP through forwards the
//!    offer on the outgoing leg while the incoming leg's INVITE is still
//!    pending, and both legs stay up for the call. Two calls that a phone or
//!    SIPp placed one after the other do not overlap. A lifetime runs from the
//!    dialog's first message to its last, inclusive at both ends, so two legs
//!    a capture stamped with one instant overlap.
//! 2. **The origin is not shown to be reused in the capture.** Two dialogs
//!    that carry the origin, overlap in time and were sent on the same hop are
//!    two sessions with one origin: the source of an offer forwarded through
//!    a B2BUA changes from hop to hop, while a load test sends every call
//!    on the same hop. When that is seen anywhere in the store, no dialog
//!    joins any other by that origin.
//!
//! A hop is the sending address, the receiving address and the receiving port
//! of the dialog's first message. The sending port is left out because SIPp
//! with `-t un` sends each call from its own port.
//!
//! # What is not used, and why
//!
//! - **`sess-version`.** A B2BUA copies it with the rest of the line, and SIPp
//!   and many phones send a constant one, so it is equal in both cases.
//! - **The media address and port (`c=` and `m=`).** A pass-through copies
//!   them, and SIPp sends one `[media_port]` for every call, so they are equal
//!   in both cases too.
//! - **A count of the dialogs that carry the origin.** A chain of two B2BUAs is
//!   three legs and a forking B2BUA is more, all one session, so a count
//!   does not separate the cases.
//!
//! # Limits, in the direction of saying less
//!
//! The rule withholds a true join in three cases: a parallel fork sent to two
//! contacts through one next hop, a spiral that sends the same offer over the
//! same hop twice, and two capture points whose clocks disagree by more than
//! the call lasted. In each, the legs are still reported by any other strategy
//! that matches them, at that strategy's strength.

use std::net::IpAddr;

use chrono::{DateTime, Utc};

use super::dialog::SipDialog;

/// The facts the rule reads from one dialog that carries an origin tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginCarrier {
    /// Sending address of the dialog's first message.
    pub src: IpAddr,
    /// Receiving address of the dialog's first message.
    pub dst: IpAddr,
    /// Receiving port of the dialog's first message.
    pub dst_port: u16,
    /// Time of the dialog's first message.
    pub start: DateTime<Utc>,
    /// Time of the dialog's last message; never earlier than `start`.
    pub end: DateTime<Utc>,
}

impl OriginCarrier {
    /// The carrier facts of `dialog`, from the fields that idle compaction
    /// does not change.
    #[must_use]
    pub fn of(dialog: &SipDialog) -> Self {
        Self {
            src: dialog.src_addr,
            dst: dialog.dst_addr,
            dst_port: dialog.dst_port,
            start: dialog.created_at,
            // The newest message, which is never before the first.
            end: dialog.latest_message_at.max(dialog.created_at),
        }
    }

    /// The hop this dialog's first message was sent on: sending address,
    /// receiving address and receiving port.
    #[must_use]
    pub fn hop(&self) -> (IpAddr, IpAddr, u16) {
        (self.src, self.dst, self.dst_port)
    }
}

/// Whether `a` and `b` were open at one instant, inclusive at both ends.
#[must_use]
pub fn lifetimes_overlap(a: &OriginCarrier, b: &OriginCarrier) -> bool {
    a.start <= b.end && b.start <= a.end
}

/// Whether `carriers`, every dialog in the store that carries one origin
/// tuple, show that tuple reused: two of them sent on the same hop with
/// overlapping lifetimes.
#[must_use]
pub fn origin_reused(carriers: &[OriginCarrier]) -> bool {
    // Sorted by hop, then by start: within one hop, an overlap exists exactly
    // when some carrier starts no later than the end of the one before it.
    // Up to the first overlap, the carriers of a hop are disjoint and in
    // order, so the one before is the one that ends last.
    let mut sorted: Vec<&OriginCarrier> = carriers.iter().collect();
    sorted.sort_by_key(|c| (c.hop(), c.start));
    sorted
        .windows(2)
        .any(|w| w[0].hop() == w[1].hop() && w[1].start <= w[0].end)
}

/// Whether `source` and `candidate`, which carry the same origin tuple, are
/// one media session, given whether that tuple is reused in the store.
#[must_use]
pub fn joins(source: &OriginCarrier, candidate: &OriginCarrier, reused: bool) -> bool {
    !reused && lifetimes_overlap(source, candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;
    use std::net::Ipv4Addr;

    type TestError = Box<dyn std::error::Error>;

    /// An RFC 5737 TEST-NET-1 address.
    fn net1(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    /// A fixed instant plus `us` microseconds.
    fn at(us: i64) -> Result<DateTime<Utc>, TestError> {
        let base = DateTime::from_timestamp(1_700_000_000, 0).ok_or("a fixed instant")?;
        Ok(base + TimeDelta::microseconds(us))
    }

    /// A carrier sent from `src` to `dst`:`dst_port`, open from `start` to
    /// `end` microseconds.
    fn carrier(
        src: u8,
        dst: u8,
        dst_port: u16,
        start: i64,
        end: i64,
    ) -> Result<OriginCarrier, TestError> {
        Ok(OriginCarrier {
            src: net1(src),
            dst: net1(dst),
            dst_port,
            start: at(start)?,
            end: at(end)?,
        })
    }

    #[test]
    fn a_leg_contained_in_another_overlaps() -> Result<(), TestError> {
        let a = carrier(1, 10, 5060, 0, 10_000_000)?;
        let b = carrier(10, 20, 5060, 5_000, 9_000_000)?;
        assert!(
            lifetimes_overlap(&a, &b),
            "a leg contained in another overlaps: {a:?} {b:?}"
        );
        Ok(())
    }

    #[test]
    fn calls_placed_one_after_the_other_do_not_overlap() -> Result<(), TestError> {
        let first = carrier(1, 10, 5060, 0, 500_000)?;
        let second = carrier(10, 20, 5060, 1_000_000, 1_500_000)?;
        assert!(
            !lifetimes_overlap(&first, &second),
            "calls placed one after the other do not overlap: {first:?} {second:?}"
        );
        Ok(())
    }

    #[test]
    fn overlap_is_inclusive_at_the_shared_instant() -> Result<(), TestError> {
        let first = carrier(1, 10, 5060, 0, 500_000)?;
        let second = carrier(10, 20, 5060, 500_000, 900_000)?;
        assert!(
            lifetimes_overlap(&first, &second),
            "overlap is inclusive at the shared instant: {first:?} {second:?}"
        );
        Ok(())
    }

    #[test]
    fn one_microsecond_past_the_end_is_not_an_overlap() -> Result<(), TestError> {
        let first = carrier(1, 10, 5060, 0, 500_000)?;
        let second = carrier(10, 20, 5060, 500_001, 900_000)?;
        assert!(
            !lifetimes_overlap(&first, &second),
            "one microsecond past the end is not an overlap: {first:?} {second:?}"
        );
        Ok(())
    }

    #[test]
    fn two_zero_length_lifetimes_at_one_instant_overlap() -> Result<(), TestError> {
        let a = carrier(1, 10, 5060, 7, 7)?;
        let b = carrier(10, 20, 5060, 7, 7)?;
        assert!(
            lifetimes_overlap(&a, &b),
            "two zero length lifetimes at one instant overlap: {a:?} {b:?}"
        );
        Ok(())
    }

    #[test]
    fn overlap_does_not_depend_on_argument_order() -> Result<(), TestError> {
        let early = carrier(1, 10, 5060, 0, 100)?;
        let late = carrier(10, 20, 5060, 200, 300)?;
        let touching = carrier(10, 20, 5060, 100, 300)?;
        assert_eq!(
            lifetimes_overlap(&early, &late),
            lifetimes_overlap(&late, &early),
            "overlap does not depend on argument order"
        );
        assert_eq!(
            lifetimes_overlap(&early, &touching),
            lifetimes_overlap(&touching, &early),
            "overlap does not depend on argument order"
        );
        assert!(
            lifetimes_overlap(&touching, &early),
            "overlap does not depend on argument order: {touching:?} {early:?}"
        );
        Ok(())
    }

    #[test]
    fn two_concurrent_carriers_on_one_hop_show_reuse() -> Result<(), TestError> {
        let carriers = [
            carrier(1, 10, 5060, 0, 2_000_000)?,
            carrier(1, 10, 5060, 1_000_000, 3_000_000)?,
        ];
        assert!(
            origin_reused(&carriers),
            "two concurrent carriers on one hop show reuse: {carriers:?}"
        );
        Ok(())
    }

    #[test]
    fn two_carriers_on_one_hop_touching_at_one_instant_show_reuse() -> Result<(), TestError> {
        // The same inclusive rule as `lifetimes_overlap`: one ends at the
        // instant the other starts.
        let carriers = [
            carrier(1, 10, 5060, 0, 1_000_000)?,
            carrier(1, 10, 5060, 1_000_000, 2_000_000)?,
        ];
        assert!(
            origin_reused(&carriers),
            "two carriers on one hop touching at one instant show reuse: {carriers:?}"
        );
        Ok(())
    }

    #[test]
    fn concurrent_carriers_on_distinct_hops_do_not_show_reuse() -> Result<(), TestError> {
        // A chain of two B2BUAs: access, core, far leg, all open together.
        let carriers = [
            carrier(1, 10, 5060, 0, 9_000_000)?,
            carrier(10, 20, 5060, 2_000, 9_000_000)?,
            carrier(20, 30, 5060, 4_000, 9_000_000)?,
        ];
        assert!(
            !origin_reused(&carriers),
            "concurrent carriers on distinct hops do not show reuse: {carriers:?}"
        );
        Ok(())
    }

    #[test]
    fn sequential_carriers_on_one_hop_do_not_show_reuse() -> Result<(), TestError> {
        // A B2BUA that retries the same next hop after a 503 on the first try.
        let carriers = [
            carrier(1, 10, 5060, 0, 9_000_000)?,
            carrier(10, 20, 5060, 1_000, 40_000)?,
            carrier(10, 20, 5060, 50_000, 9_000_000)?,
        ];
        assert!(
            !origin_reused(&carriers),
            "sequential carriers on one hop do not show reuse: {carriers:?}"
        );
        Ok(())
    }

    #[test]
    fn reuse_is_found_whatever_order_the_carriers_arrive_in() -> Result<(), TestError> {
        // The overlapping pair is the first and the last. Between them are a
        // disjoint call on the same hop and calls on other hops, one of which
        // starts between the two, so only a comparison within the hop finds
        // the pair.
        let carriers = [
            carrier(1, 10, 5060, 5_000_000, 6_000_000)?,
            carrier(10, 20, 5060, 0, 100)?,
            carrier(1, 10, 5060, 0, 1_000)?,
            carrier(30, 40, 5060, 5_200_000, 9_000_000)?,
            carrier(1, 10, 5060, 5_500_000, 7_000_000)?,
        ];
        assert!(
            origin_reused(&carriers),
            "reuse is found whatever order the carriers arrive in: {carriers:?}"
        );
        Ok(())
    }

    #[test]
    fn the_receiving_port_is_part_of_the_hop() -> Result<(), TestError> {
        // A proxy and a B2BUA on one host: both legs are 192.0.2.10 to
        // 192.0.2.10, to port 5080 and then to port 5090.
        let carriers = [
            carrier(10, 10, 5080, 0, 2_000_000)?,
            carrier(10, 10, 5090, 1_000, 2_000_000)?,
        ];
        assert!(
            !origin_reused(&carriers),
            "the receiving port is part of the hop: {carriers:?}"
        );
        Ok(())
    }

    #[test]
    fn the_reverse_direction_on_one_host_pair_is_another_hop() -> Result<(), TestError> {
        // A hairpin: proxy to SBC, then SBC back to the proxy.
        let carriers = [
            carrier(10, 20, 5060, 0, 2_000_000)?,
            carrier(20, 10, 5060, 1_000, 2_000_000)?,
        ];
        assert!(
            !origin_reused(&carriers),
            "the reverse direction on one host pair is another hop: {carriers:?}"
        );
        Ok(())
    }

    #[test]
    fn a_reused_origin_joins_nothing_even_when_the_legs_overlap() -> Result<(), TestError> {
        let a = carrier(1, 10, 5060, 0, 2_000_000)?;
        let b = carrier(10, 20, 5060, 1_000, 2_000_000)?;
        assert!(
            !joins(&a, &b, true),
            "a reused origin joins nothing even when the legs overlap: {a:?} {b:?}"
        );
        Ok(())
    }

    #[test]
    fn an_unreused_origin_joins_overlapping_legs() -> Result<(), TestError> {
        let a = carrier(1, 10, 5060, 0, 2_000_000)?;
        let b = carrier(10, 20, 5060, 1_000, 2_000_000)?;
        assert!(
            joins(&a, &b, false),
            "an unreused origin joins overlapping legs: {a:?} {b:?}"
        );
        Ok(())
    }

    #[test]
    fn a_last_message_stamped_before_the_first_does_not_end_the_dialog_early()
    -> Result<(), TestError> {
        // A capture merged from two clocks can stamp the last message earlier
        // than the first. The lifetime is then the first instant alone.
        let invite = crate::test_utils::sdp_offer_and_answer("clamp@example.com")?.0;
        let mut dialog = SipDialog::new(&invite).ok_or("a dialog")?;
        dialog.updated_at = dialog.created_at - TimeDelta::seconds(5);
        let c = OriginCarrier::of(&dialog);
        assert_eq!(
            c.start, dialog.created_at,
            "a last message stamped before the first does not end the dialog early"
        );
        assert_eq!(
            c.end, dialog.created_at,
            "a last message stamped before the first does not end the dialog early"
        );
        Ok(())
    }
}

/// A carrier's lifetime on a call read out of timestamp order: see
/// [`crate::test_utils::call_read_out_of_order`].
#[cfg(test)]
mod latest_message_tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// The carrier's lifetime ends at the newest message, not at the last
    /// message read, so a leg that overlaps the call's end is seen to.
    #[test]
    fn a_carriers_lifetime_ends_at_the_newest_message() -> Result<(), TestError> {
        let (store, _) = crate::test_utils::call_read_out_of_order(
            "carrier@example.com",
            [192, 0, 2, 1].into(),
        )?;
        let d = store.get("carrier@example.com").ok_or("the call")?;
        assert_eq!(
            OriginCarrier::of(d).end,
            d.latest_message_at,
            "the lifetime ends at the newest message"
        );
        assert!(d.latest_message_at > d.updated_at, "the fixture");
        Ok(())
    }
}
