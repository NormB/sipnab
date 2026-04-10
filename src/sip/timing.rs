//! Transaction timing measurement for SIP dialogs.
//!
//! Tracks timestamps at each signaling milestone (INVITE sent, 100 Trying,
//! 180 Ringing, 200 OK, BYE, etc.) and computes derived metrics such as
//! Post-Dial Delay (PDD), setup time, ring duration, and teardown time.
//! Also counts retransmissions per CSeq transaction.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use super::SipMessage;

/// Timing measurements collected across a dialog's lifetime.
///
/// All timestamps are captured from the `SipMessage::timestamp` field as
/// each message is processed by the dialog store. Derived metrics are
/// computed on demand from the stored timestamps.
#[derive(Debug, Clone, Default)]
pub struct DialogTiming {
    /// Timestamp of the initial INVITE request.
    pub invite_sent: Option<DateTime<Utc>>,
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
}

impl DialogTiming {
    /// Post-Dial Delay: INVITE sent to first 180 Ringing, in milliseconds.
    ///
    /// Returns `None` if either timestamp is missing.
    pub fn pdd_ms(&self) -> Option<i64> {
        let invite = self.invite_sent?;
        let ringing = self.ringing_at?;
        Some((ringing - invite).num_milliseconds())
    }

    /// Setup time: INVITE sent to 200 OK, in milliseconds.
    ///
    /// Returns `None` if either timestamp is missing.
    pub fn setup_ms(&self) -> Option<i64> {
        let invite = self.invite_sent?;
        let answered = self.answered_at?;
        Some((answered - invite).num_milliseconds())
    }

    /// Ring duration: first 180 Ringing to 200 OK, in milliseconds.
    ///
    /// Returns `None` if either timestamp is missing.
    pub fn ring_ms(&self) -> Option<i64> {
        let ringing = self.ringing_at?;
        let answered = self.answered_at?;
        Some((answered - ringing).num_milliseconds())
    }

    /// Trying delay: INVITE sent to 100 Trying, in milliseconds.
    ///
    /// Returns `None` if either timestamp is missing.
    pub fn trying_delay_ms(&self) -> Option<i64> {
        let invite = self.invite_sent?;
        let trying = self.trying_at?;
        Some((trying - invite).num_milliseconds())
    }

    /// Teardown time: BYE sent to 200 OK for BYE, in milliseconds.
    ///
    /// Returns `None` if either timestamp is missing.
    pub fn teardown_ms(&self) -> Option<i64> {
        let bye = self.bye_sent?;
        let answered = self.bye_answered?;
        Some((answered - bye).num_milliseconds())
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
pub fn update_timing(timing: &mut DialogTiming, msg: &SipMessage, dialog_method: &str) {
    if msg.is_request {
        let method = msg.method.as_deref().unwrap_or("");
        match method {
            "INVITE" if dialog_method == "INVITE" && timing.invite_sent.is_none() => {
                timing.invite_sent = Some(msg.timestamp);
            }
            "BYE" if timing.bye_sent.is_none() => {
                timing.bye_sent = Some(msg.timestamp);
            }
            _ => {}
        }
    } else if let Some(code) = msg.status_code {
        // Determine which method this response belongs to via CSeq
        let cseq_method = msg.cseq().map(|(_, m)| m).unwrap_or_default();

        match code {
            100 if cseq_method == "INVITE" && timing.trying_at.is_none() => {
                timing.trying_at = Some(msg.timestamp);
            }
            180 | 183 if cseq_method == "INVITE" && timing.ringing_at.is_none() => {
                timing.ringing_at = Some(msg.timestamp);
            }
            200 if cseq_method == "INVITE" && timing.answered_at.is_none() => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip;
    use chrono::TimeDelta;
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn build_sip(first_line: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(first_line.as_bytes());
        msg.extend_from_slice(b"\r\n");
        for h in headers {
            msg.extend_from_slice(h.as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        msg.extend_from_slice(body);
        msg
    }

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
        parse_sip(&raw, ts, localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse INVITE")
    }

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
        parse_sip(&raw, ts, localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse response")
    }

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
        parse_sip(&raw, ts, localhost(), localhost(), 5060, 5060, "UDP").expect("should parse BYE")
    }

    #[test]
    fn pdd_calculation() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(1500);

        let invite = make_invite(t0);
        let ringing = make_response(180, "Ringing", "INVITE", t1);

        update_timing(&mut timing, &invite, "INVITE");
        update_timing(&mut timing, &ringing, "INVITE");

        assert_eq!(timing.pdd_ms(), Some(1500));
    }

    #[test]
    fn setup_time_calculation() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let t3 = t0 + TimeDelta::milliseconds(3000);

        let invite = make_invite(t0);
        let ok = make_response(200, "OK", "INVITE", t3);

        update_timing(&mut timing, &invite, "INVITE");
        update_timing(&mut timing, &ok, "INVITE");

        assert_eq!(timing.setup_ms(), Some(3000));
    }

    #[test]
    fn ring_duration_calculation() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(1000);
        let t2 = t0 + TimeDelta::milliseconds(4000);

        let invite = make_invite(t0);
        let ringing = make_response(180, "Ringing", "INVITE", t1);
        let ok = make_response(200, "OK", "INVITE", t2);

        update_timing(&mut timing, &invite, "INVITE");
        update_timing(&mut timing, &ringing, "INVITE");
        update_timing(&mut timing, &ok, "INVITE");

        assert_eq!(timing.ring_ms(), Some(3000));
    }

    #[test]
    fn trying_delay_calculation() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(50);

        let invite = make_invite(t0);
        let trying = make_response(100, "Trying", "INVITE", t1);

        update_timing(&mut timing, &invite, "INVITE");
        update_timing(&mut timing, &trying, "INVITE");

        assert_eq!(timing.trying_delay_ms(), Some(50));
    }

    #[test]
    fn teardown_time_calculation() {
        let mut timing = DialogTiming::default();
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(200);

        let bye = make_bye(t0);
        let ok = make_response(200, "OK", "BYE", t1);

        update_timing(&mut timing, &bye, "INVITE");
        update_timing(&mut timing, &ok, "INVITE");

        assert_eq!(timing.teardown_ms(), Some(200));
    }

    #[test]
    fn retransmit_counting() {
        let mut timing = DialogTiming::default();
        timing.retransmit_counts.insert("1 INVITE".to_string(), 2);
        timing.retransmit_counts.insert("2 BYE".to_string(), 1);

        assert_eq!(timing.total_retransmits(), 3);
    }

    #[test]
    fn missing_timestamps_return_none() {
        let timing = DialogTiming::default();
        assert_eq!(timing.pdd_ms(), None);
        assert_eq!(timing.setup_ms(), None);
        assert_eq!(timing.ring_ms(), None);
        assert_eq!(timing.trying_delay_ms(), None);
        assert_eq!(timing.teardown_ms(), None);
    }

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

        update_timing(&mut timing, &invite, "INVITE");
        update_timing(&mut timing, &ringing1, "INVITE");
        update_timing(&mut timing, &ringing2, "INVITE");

        assert_eq!(timing.pdd_ms(), Some(1000)); // First ringing, not second
    }
}
