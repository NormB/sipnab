// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transaction timing measurement for SIP dialogs.
//!
//! Tracks timestamps at each signaling milestone (INVITE sent, 100 Trying,
//! 180 Ringing, 200 OK, BYE, etc.) and computes derived metrics such as
//! Post-Dial Delay (PDD), setup time, ring duration, and teardown time.
//! Also counts retransmissions per CSeq transaction.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use super::SipMessage;
use super::method::SipMethod;

/// Timing measurements collected across a dialog's lifetime.
///
/// All timestamps are captured from the `SipMessage::timestamp` field as
/// each message is processed by the dialog store. Derived metrics are
/// computed on demand from the stored timestamps.
#[derive(Debug, Clone, Default)]
pub struct DialogTiming {
    /// Timestamp of the initial INVITE request.
    pub invite_sent: Option<DateTime<Utc>>,
    /// CSeq number of the initial INVITE. Responses (100/180/200) are pinned
    /// to this number so a re-INVITE's responses are not mistaken for the
    /// initial transaction's milestones. `None` when the INVITE request was
    /// not captured (then responses fall back to first-match).
    pub invite_cseq: Option<u32>,
    /// Timestamp of the first 100 Trying response.
    pub trying_at: Option<DateTime<Utc>>,
    /// Timestamp of the first 180 Ringing or 183 Session Progress response.
    pub ringing_at: Option<DateTime<Utc>>,
    /// Timestamp of the 200 OK response to the initial INVITE.
    pub answered_at: Option<DateTime<Utc>>,
    /// Timestamp of the BYE request.
    pub bye_sent: Option<DateTime<Utc>>,
    /// Timestamp of the 200 OK response to BYE.
    pub bye_answered: Option<DateTime<Utc>>,
    /// Retransmission counts keyed by `"CSeq METHOD"` (e.g., `"1 INVITE"`).
    pub retransmit_counts: HashMap<String, u32>,
    /// Timestamp of the REFER request initiating a transfer.
    pub refer_sent_at: Option<DateTime<Utc>>,
    /// Timestamp of the NOTIFY with `Subscription-State: terminated` completing a transfer.
    pub transfer_completed_at: Option<DateTime<Utc>>,
}

/// Milliseconds from `from` to `to`, or `None` when the pair cannot be a
/// measurement.
///
/// A milestone pair that runs backwards is not a slow call. It means the two
/// timestamps came from different transactions — a capture that opened
/// mid-dialog, a merge of files whose clocks disagree, or a pairing rule with
/// a hole in it. Publishing the difference anyway turns that into a duration
/// an operator reads as measured, which is how a call report came to show
/// `Setup: -27.98s`. Unknown is reported as unknown.
fn elapsed_ms(from: DateTime<Utc>, to: DateTime<Utc>) -> Option<i64> {
    let ms = (to - from).num_milliseconds();
    (ms >= 0).then_some(ms)
}

impl DialogTiming {
    /// Post-Dial Delay: INVITE sent to first 180 Ringing, in milliseconds.
    ///
    /// Returns `None` if either timestamp is missing, and also when the two
    /// cannot belong to one transaction — an interval that runs backwards is
    /// not a measurement, so it is reported as unknown rather than published
    /// as a duration.
    pub fn pdd_ms(&self) -> Option<i64> {
        elapsed_ms(self.invite_sent?, self.ringing_at?)
    }

    /// Setup time: INVITE sent to 200 OK, in milliseconds.
    ///
    /// Returns `None` if either timestamp is missing, and also when the two
    /// cannot belong to one transaction — an interval that runs backwards is
    /// not a measurement, so it is reported as unknown rather than published
    /// as a duration.
    pub fn setup_ms(&self) -> Option<i64> {
        elapsed_ms(self.invite_sent?, self.answered_at?)
    }

    /// Ring duration: first 180 Ringing to 200 OK, in milliseconds.
    ///
    /// Returns `None` if either timestamp is missing, and also when the two
    /// cannot belong to one transaction — an interval that runs backwards is
    /// not a measurement, so it is reported as unknown rather than published
    /// as a duration.
    pub fn ring_ms(&self) -> Option<i64> {
        elapsed_ms(self.ringing_at?, self.answered_at?)
    }

    /// Trying delay: INVITE sent to 100 Trying, in milliseconds.
    ///
    /// Returns `None` if either timestamp is missing, and also when the two
    /// cannot belong to one transaction — an interval that runs backwards is
    /// not a measurement, so it is reported as unknown rather than published
    /// as a duration.
    pub fn trying_delay_ms(&self) -> Option<i64> {
        elapsed_ms(self.invite_sent?, self.trying_at?)
    }

    /// Teardown time: BYE sent to 200 OK for BYE, in milliseconds.
    ///
    /// Returns `None` if either timestamp is missing, and also when the two
    /// cannot belong to one transaction — an interval that runs backwards is
    /// not a measurement, so it is reported as unknown rather than published
    /// as a duration.
    pub fn teardown_ms(&self) -> Option<i64> {
        elapsed_ms(self.bye_sent?, self.bye_answered?)
    }

    /// Conversation time: 200 OK to INVITE through to the BYE, in milliseconds.
    ///
    /// The interval a carrier bills and the one Average Call Duration averages
    /// — not the dialog's wall-clock span, which starts at the INVITE and so
    /// charges the caller for the ringing. A call that was never answered has
    /// no conversation and reports `None` rather than zero, because zero here
    /// would drag an average down as if the call had connected and said
    /// nothing.
    ///
    /// `None` also while a call is still up: the BYE has not arrived, so the
    /// duration is not short, it is unfinished. Same rule for a pair that runs
    /// backwards, for the reason `elapsed_ms` gives.
    pub fn conversation_ms(&self) -> Option<i64> {
        elapsed_ms(self.answered_at?, self.bye_sent?)
    }

    /// Total retransmission count across all transactions in this dialog.
    pub fn total_retransmits(&self) -> u32 {
        self.retransmit_counts.values().sum()
    }
}

/// Update timing fields from a newly received SIP message.
///
/// Uses the message's method/status code and the dialog's initial method
/// to determine which timing field to populate. Only the first occurrence
/// of each milestone is recorded (subsequent duplicates are ignored to
/// avoid overwriting with retransmissions).
///
/// # Arguments
///
/// * `timing` — the dialog's timing record to update.
/// * `msg` — the newly observed SIP message.
/// * `dialog_method` — the method that created the dialog; INVITE
///   timestamps are only recorded for INVITE-initiated dialogs.
///
/// # Side effects
///
/// Sets at most one milestone timestamp on `timing`: requests populate
/// `invite_sent`, `bye_sent`, `refer_sent_at`, or `transfer_completed_at`
/// (NOTIFY with `Subscription-State: terminated`); responses are matched to
/// their transaction via the CSeq method and populate `trying_at` (100),
/// `ringing_at` (180/183), `answered_at` (200 to INVITE), or `bye_answered`
/// (200 to BYE). Messages matching no milestone leave `timing` unchanged.
pub fn update_timing(timing: &mut DialogTiming, msg: &SipMessage, dialog_method: &SipMethod) {
    if msg.is_request {
        match msg.method.as_ref() {
            // A request outside a dialog MUST NOT carry a To-tag (RFC 3261
            // §8.1.1.2); an in-dialog request carries the peer's (§12.2.1.1).
            // So a tagged INVITE is a re-INVITE, whatever the capture happens
            // to have seen before it. Without this, a capture that opened
            // mid-call took its `invite_sent` from a re-INVITE that arrived
            // long after the call was already up.
            Some(SipMethod::Invite)
                if *dialog_method == SipMethod::Invite
                    && timing.invite_sent.is_none()
                    && msg.to_tag().is_none() =>
            {
                timing.invite_sent = Some(msg.timestamp);
                // Remember which INVITE transaction this dialog began with so
                // its responses can be told apart from later re-INVITEs.
                timing.invite_cseq = msg.cseq().map(|(n, _)| n);
            }
            Some(SipMethod::Bye) if timing.bye_sent.is_none() => {
                timing.bye_sent = Some(msg.timestamp);
            }
            Some(SipMethod::Refer) if timing.refer_sent_at.is_none() => {
                timing.refer_sent_at = Some(msg.timestamp);
            }
            Some(SipMethod::Notify) => {
                // Subscription-State = substate-value *(";" subexp-params)
                // (RFC 6665 §8.4). Match the leading token exactly so a value
                // like "terminatedfoo" is not mistaken for "terminated";
                // "terminated;reason=noresource" still matches on its token.
                if let Some(sub_state) = msg.header("Subscription-State")
                    && sub_state.split(';').next().unwrap_or("").trim() == "terminated"
                    && timing.transfer_completed_at.is_none()
                {
                    timing.transfer_completed_at = Some(msg.timestamp);
                }
            }
            _ => {}
        }
    } else if let Some(code) = msg.status_code {
        // Determine which transaction this response belongs to via CSeq.
        let (cseq_num, cseq_method) = match msg.cseq() {
            Some((n, m)) => (Some(n), m),
            None => (None, ""),
        };
        // A response belongs to the dialog's initial INVITE when its CSeq
        // number matches the recorded one; if the INVITE was never captured
        // (invite_cseq is None) we cannot tell, so fall back to first-match.
        let is_initial_invite = timing.invite_cseq.is_none() || cseq_num == timing.invite_cseq;

        match code {
            100 if cseq_method == "INVITE" && is_initial_invite && timing.trying_at.is_none() => {
                timing.trying_at = Some(msg.timestamp);
            }
            180 | 183
                if cseq_method == "INVITE" && is_initial_invite && timing.ringing_at.is_none() =>
            {
                timing.ringing_at = Some(msg.timestamp);
            }
            200 if cseq_method == "INVITE" && is_initial_invite && timing.answered_at.is_none() => {
                timing.answered_at = Some(msg.timestamp);
            }
            200 if cseq_method == "BYE" && timing.bye_answered.is_none() => {
                timing.bye_answered = Some(msg.timestamp);
            }
            _ => {}
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for milestone recording and the derived timing metrics (PDD,
/// setup, ring, trying delay, teardown, transfer, retransmit totals).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::TimeDelta;
    use std::net::{IpAddr, Ipv4Addr};

    /// Fixed 127.0.0.1 address used for all test messages.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed base timestamp (2024-06-15 12:00:00 UTC) tests offset from.
    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build an INVITE request captured at `ts`.
    fn make_invite(ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: timing-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse INVITE")
    }

    /// Build a response with the given status, reason, and CSeq method,
    /// captured at `ts`.
    fn make_response(
        status: u16,
        reason: &str,
        cseq_method: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            &format!("SIP/2.0 {status} {reason}"),
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: timing-test@example.com",
                &format!("CSeq: 1 {cseq_method}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse response")
    }

    /// Build a BYE request captured at `ts`.
    fn make_bye(ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "BYE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: timing-test@example.com",
                "CSeq: 2 BYE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse BYE")
    }

    /// PDD equals the INVITE→180 interval.
    #[test]
    fn pdd_calculation() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(1500);

        let invite = make_invite(t0);
        let ringing = make_response(180, "Ringing", "INVITE", t1);

        update_timing(&mut timing, &invite, &SipMethod::Invite);
        update_timing(&mut timing, &ringing, &SipMethod::Invite);

        assert_eq!(timing.pdd_ms(), Some(1500));
    }

    /// A 200 whose CSeq does not belong to the initial INVITE (e.g. a
    /// re-INVITE's 200, when the original 200 was not captured) must not be
    /// recorded as the call's answer time.
    #[test]
    fn reinvite_200_is_not_recorded_as_answer() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        // Initial INVITE (CSeq 1); its 200 is never captured.
        update_timing(&mut timing, &make_invite(t0), &SipMethod::Invite);

        // A 200 belonging to a later re-INVITE (CSeq 2).
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: timing-test@example.com",
                "CSeq: 2 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let reinvite_200 = parse_sip(
            &raw,
            t0 + TimeDelta::milliseconds(9000),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse re-INVITE 200");
        update_timing(&mut timing, &reinvite_200, &SipMethod::Invite);

        assert_eq!(
            timing.answered_at, None,
            "a re-INVITE's 200 must not be recorded as the answer time"
        );
    }

    /// Build an in-dialog re-INVITE: an INVITE that carries a To-tag.
    ///
    /// RFC 3261 §8.1.1.2 — a request outside a dialog MUST NOT contain a To
    /// tag; §12.2.1.1 — an in-dialog request carries the peer's tag. The tag
    /// is what separates a call's one initial INVITE from every later
    /// re-INVITE, and it is stated on the message itself, so it holds however
    /// late the capture started.
    fn make_reinvite(ts: DateTime<Utc>, cseq: u32) -> SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: timing-test@example.com",
                &format!("CSeq: {cseq} INVITE"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse re-INVITE")
    }

    /// A capture that opens mid-call must report no setup time, not a negative
    /// one.
    ///
    /// Reproduces a real capture. Recording started after the call was up, so
    /// the dialog's first message was the 200 OK of an INVITE transaction that
    /// had already completed, and 28 s later the *callee* sent a re-INVITE.
    /// Each side numbers its own CSeq space (RFC 3261 §12.2.1.1), so the
    /// callee's re-INVITE was also CSeq 102 and matched by number.
    /// `invite_sent` was then taken from that re-INVITE while `answered_at`
    /// came from the earlier transaction, and the call report read
    /// `Setup: -27.98s`.
    #[test]
    fn a_capture_opening_mid_call_reports_no_setup_time() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();

        // The tail of a transaction whose INVITE preceded the capture.
        update_timing(
            &mut timing,
            &make_response(200, "OK", "INVITE", t0),
            &SipMethod::Invite,
        );
        // 28 s on, the far end re-INVITEs, reusing 102 from its own CSeq space.
        update_timing(
            &mut timing,
            &make_reinvite(t0 + TimeDelta::seconds(28), 102),
            &SipMethod::Invite,
        );

        assert_eq!(
            timing.invite_sent, None,
            "a re-INVITE 28 s into an established call is not the call's first INVITE"
        );
        assert_eq!(
            timing.setup_ms(),
            None,
            "the initial INVITE was never captured, so setup time is unknown — not negative"
        );
    }

    /// An in-dialog INVITE is not the initial INVITE even when it is the very
    /// first message the capture holds for the dialog.
    ///
    /// The To-tag settles this without reference to what was seen earlier,
    /// which is why the tag is the test rather than the arrival order.
    #[test]
    fn an_in_dialog_invite_is_never_the_initial_invite() {
        let mut timing = DialogTiming::default();
        update_timing(
            &mut timing,
            &make_reinvite(base_ts(), 7),
            &SipMethod::Invite,
        );

        assert_eq!(
            timing.invite_sent, None,
            "an INVITE bearing a To-tag is in-dialog (RFC 3261 §8.1.1.2)"
        );
    }

    /// An initial INVITE — no To-tag — still opens the dialog.
    ///
    /// The anti-vacuity half of the test above: a guard that rejected every
    /// INVITE would also pass it.
    #[test]
    fn an_initial_invite_still_starts_the_clock() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        update_timing(&mut timing, &make_invite(t0), &SipMethod::Invite);

        assert_eq!(
            timing.invite_sent,
            Some(t0),
            "an INVITE with no To-tag is the dialog's initial INVITE"
        );
    }

    /// No derived interval is ever negative.
    ///
    /// Backstop for the pairing rules above: a negative duration is not a slow
    /// call, it is two milestones that do not belong to one transaction, and
    /// publishing it as a measurement is worse than publishing nothing. Every
    /// surface reads these accessors — report, JSON, REST, MCP, DSL, TUI and
    /// WASM — so the rule belongs here rather than in any one renderer.
    #[test]
    fn derived_intervals_are_never_negative() {
        let late = base_ts();
        let early = late - TimeDelta::seconds(28);

        let setup = DialogTiming {
            invite_sent: Some(late),
            answered_at: Some(early),
            ..Default::default()
        };
        assert_eq!(
            setup.setup_ms(),
            None,
            "answered before INVITE is not a setup time"
        );

        let pdd = DialogTiming {
            invite_sent: Some(late),
            ringing_at: Some(early),
            ..Default::default()
        };
        assert_eq!(
            pdd.pdd_ms(),
            None,
            "ringing before INVITE is not a post-dial delay"
        );

        let trying = DialogTiming {
            invite_sent: Some(late),
            trying_at: Some(early),
            ..Default::default()
        };
        assert_eq!(
            trying.trying_delay_ms(),
            None,
            "100 Trying before INVITE is not a trying delay"
        );

        let ring = DialogTiming {
            ringing_at: Some(late),
            answered_at: Some(early),
            ..Default::default()
        };
        assert_eq!(
            ring.ring_ms(),
            None,
            "answered before ringing is not a ring duration"
        );

        let teardown = DialogTiming {
            bye_sent: Some(late),
            bye_answered: Some(early),
            ..Default::default()
        };
        assert_eq!(
            teardown.teardown_ms(),
            None,
            "BYE answered before it was sent is not a teardown time"
        );
    }

    /// Setup time equals the INVITE→200 interval.
    #[test]
    fn setup_time_calculation() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let t3 = t0 + TimeDelta::milliseconds(3000);

        let invite = make_invite(t0);
        let ok = make_response(200, "OK", "INVITE", t3);

        update_timing(&mut timing, &invite, &SipMethod::Invite);
        update_timing(&mut timing, &ok, &SipMethod::Invite);

        assert_eq!(timing.setup_ms(), Some(3000));
    }

    /// Ring duration equals the 180→200 interval.
    #[test]
    fn ring_duration_calculation() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(1000);
        let t2 = t0 + TimeDelta::milliseconds(4000);

        let invite = make_invite(t0);
        let ringing = make_response(180, "Ringing", "INVITE", t1);
        let ok = make_response(200, "OK", "INVITE", t2);

        update_timing(&mut timing, &invite, &SipMethod::Invite);
        update_timing(&mut timing, &ringing, &SipMethod::Invite);
        update_timing(&mut timing, &ok, &SipMethod::Invite);

        assert_eq!(timing.ring_ms(), Some(3000));
    }

    /// Trying delay equals the INVITE→100 interval.
    #[test]
    fn trying_delay_calculation() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(50);

        let invite = make_invite(t0);
        let trying = make_response(100, "Trying", "INVITE", t1);

        update_timing(&mut timing, &invite, &SipMethod::Invite);
        update_timing(&mut timing, &trying, &SipMethod::Invite);

        assert_eq!(timing.trying_delay_ms(), Some(50));
    }

    /// Teardown time equals the BYE→200 interval.
    #[test]
    fn teardown_time_calculation() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(200);

        let bye = make_bye(t0);
        let ok = make_response(200, "OK", "BYE", t1);

        update_timing(&mut timing, &bye, &SipMethod::Invite);
        update_timing(&mut timing, &ok, &SipMethod::Invite);

        assert_eq!(timing.teardown_ms(), Some(200));
    }

    /// `total_retransmits` sums counts across all transactions.
    #[test]
    fn retransmit_counting() {
        let mut timing = DialogTiming::default();
        timing.retransmit_counts.insert("1 INVITE".to_string(), 2);
        timing.retransmit_counts.insert("2 BYE".to_string(), 1);

        assert_eq!(timing.total_retransmits(), 3);
    }

    /// Every derived metric is `None` on a default (empty) timing record.
    #[test]
    fn missing_timestamps_return_none() {
        let timing = DialogTiming::default();
        assert_eq!(timing.pdd_ms(), None);
        assert_eq!(timing.setup_ms(), None);
        assert_eq!(timing.ring_ms(), None);
        assert_eq!(timing.trying_delay_ms(), None);
        assert_eq!(timing.teardown_ms(), None);
    }

    /// A duplicate 180 does not overwrite the first ringing timestamp.
    #[test]
    fn first_milestone_wins() {
        // Sending a second 180 Ringing should not overwrite the first one
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(1000);
        let t2 = t0 + TimeDelta::milliseconds(2000);

        let invite = make_invite(t0);
        let ringing1 = make_response(180, "Ringing", "INVITE", t1);
        let ringing2 = make_response(180, "Ringing", "INVITE", t2);

        update_timing(&mut timing, &invite, &SipMethod::Invite);
        update_timing(&mut timing, &ringing1, &SipMethod::Invite);
        update_timing(&mut timing, &ringing2, &SipMethod::Invite);

        assert_eq!(timing.pdd_ms(), Some(1000)); // First ringing, not second
    }

    /// REFER sets refer_sent_at; a terminated-NOTIFY sets transfer_completed_at.
    #[test]
    fn transfer_timing_fields_set() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(5);

        // REFER sets refer_sent_at
        let refer = {
            let raw = build_sip(
                "REFER sip:bob@example.com SIP/2.0",
                &[
                    "From: <sip:alice@example.com>;tag=t1",
                    "To: <sip:bob@example.com>;tag=t2",
                    "Call-ID: timing-test@example.com",
                    "CSeq: 3 REFER",
                    "Refer-To: <sip:carol@example.com>",
                    "Content-Length: 0",
                ],
                b"",
            );
            parse_sip(
                &raw,
                t0,
                localhost(),
                localhost(),
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("should parse REFER")
        };
        update_timing(&mut timing, &refer, &SipMethod::Invite);
        assert_eq!(timing.refer_sent_at, Some(t0));
        assert!(timing.transfer_completed_at.is_none());

        // NOTIFY with terminated sets transfer_completed_at
        let notify = {
            let raw = build_sip(
                "NOTIFY sip:alice@example.com SIP/2.0",
                &[
                    "From: <sip:bob@example.com>;tag=t2",
                    "To: <sip:alice@example.com>;tag=t1",
                    "Call-ID: timing-test@example.com",
                    "CSeq: 4 NOTIFY",
                    "Subscription-State: terminated;reason=noresource",
                    "Content-Length: 0",
                ],
                b"",
            );
            parse_sip(
                &raw,
                t1,
                localhost(),
                localhost(),
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("should parse NOTIFY")
        };
        update_timing(&mut timing, &notify, &SipMethod::Invite);
        assert_eq!(timing.transfer_completed_at, Some(t1));
    }

    /// Build a NOTIFY carrying the given `Subscription-State` value, captured
    /// at `ts`.
    fn make_notify_substate(sub_state: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "NOTIFY sip:alice@example.com SIP/2.0",
            &[
                "From: <sip:bob@example.com>;tag=t2",
                "To: <sip:alice@example.com>;tag=t1",
                "Call-ID: timing-test@example.com",
                "CSeq: 4 NOTIFY",
                &format!("Subscription-State: {sub_state}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse NOTIFY")
    }

    /// A `Subscription-State` value that merely *starts with* "terminated"
    /// (e.g. "terminatedfoo") is a different token and must NOT complete the
    /// transfer — the old `starts_with("terminated")` check false-matched it.
    #[test]
    fn notify_terminatedfoo_does_not_complete_transfer() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let notify = make_notify_substate("terminatedfoo", t0);
        update_timing(&mut timing, &notify, &SipMethod::Invite);
        assert_eq!(
            timing.transfer_completed_at, None,
            "'terminatedfoo' is not the 'terminated' token and must not complete a transfer"
        );
    }

    /// A bare `Subscription-State: terminated` token (no parameters)
    /// completes the transfer — the token match must not require a `;`.
    #[test]
    fn notify_bare_terminated_completes_transfer() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let notify = make_notify_substate("terminated", t0);
        update_timing(&mut timing, &notify, &SipMethod::Invite);
        assert_eq!(timing.transfer_completed_at, Some(t0));
    }

    /// `terminated;reason=noresource` (token plus parameters) still completes
    /// the transfer — anchoring on the token must tolerate trailing params.
    #[test]
    fn notify_terminated_with_params_completes_transfer() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let notify = make_notify_substate("terminated;reason=noresource", t0);
        update_timing(&mut timing, &notify, &SipMethod::Invite);
        assert_eq!(timing.transfer_completed_at, Some(t0));
    }
}
