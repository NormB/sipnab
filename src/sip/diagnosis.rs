//! Signalling-side problem diagnosis.
//!
//! The complement to [`crate::rtp::diagnosis`], which does this job for media.
//! That module can already say a call had one-way audio or a NAT mismatch; this
//! one says the call failed on a `503` after three retransmitted INVITEs, or
//! that a phone has been looping on `401` without ever authenticating. The
//! evidence was always captured — it was simply never read as a diagnosis.
//!
//! Spec: `docs/design/sip-problem-diagnosis.md`. Detections 1–3 are implemented
//! here; 4–7 are specified and deliberately not built, because the spec's build
//! order puts the value in these three and they need no new plumbing.
//!
//! # Evidence, not verdicts
//!
//! Every detection carries the indices of the messages it was drawn from, into
//! the dialog's own `messages` list. A diagnosis that says "auth loop" but not
//! *which* challenges is a guess the reader has to re-derive by hand, which is
//! the work a capture tool exists to remove. The indices keep the payload small,
//! survive serialization, and let any surface render "because of these four
//! messages" without a second lookup.
//!
//! # Absence means checked-and-absent
//!
//! Every field is `Option`, unlike `MediaDiagnosis`, whose first three signals
//! are `bool` and so cannot distinguish "checked, not present" from "never
//! checked". That distinction starts to matter the moment a detection can be
//! skipped for want of data, which is why the spec calls for it explicitly.

use serde::{Deserialize, Serialize};

use crate::sip::message::SipMessage;
use crate::sip::method::SipMethod;

/// A dialog that ended on a `4xx`/`5xx`/`6xx` final response.
///
/// `reason` and `warning` are carried because a generic status code frequently
/// says nothing useful on its own: a bare `503 Service Unavailable` with
/// `Reason: Q.850;cause=34;text="no circuit available"` is a trunk capacity
/// problem, and the reader should not have to open the packet to learn that.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FinalFailure {
    /// The final response status code.
    pub code: u16,
    /// The reason phrase from the status line.
    pub reason_phrase: String,
    /// `Reason:` header (RFC 3326), verbatim, when present.
    pub reason_header: Option<String>,
    /// `Warning:` header, verbatim, when present.
    pub warning: Option<String>,
    /// Index of the final response in the dialog's message list.
    pub evidence: Vec<usize>,
}

/// Which way an authentication loop is failing.
///
/// The two shapes need different fixes, so collapsing them into "auth problem"
/// would throw away the answer: wrong credentials is a provisioning error, a
/// missing `Authorization` header is a client or proxy that never attempts the
/// challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthLoopKind {
    /// The UAC answers each challenge with `Authorization` and is challenged
    /// again — the credentials are wrong.
    CredentialFailure,
    /// The UAC never sends `Authorization` at all — a client that does not know
    /// the realm, or a proxy stripping the header.
    SilentDrop,
}

/// Repeated `401`/`407` challenges on one dialog with no `2xx` reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthLoop {
    /// Whether the UAC is answering the challenges or ignoring them.
    pub kind: AuthLoopKind,
    /// How many `401`/`407` responses were seen.
    pub challenges: usize,
    /// Indices of the challenge responses.
    pub evidence: Vec<usize>,
}

/// A request retransmitted with no response — the signature of a one-way
/// network path or a dead peer.
///
/// The count and span are both reported because "7 INVITEs over 32 seconds" is
/// diagnostic and "retransmissions detected" is not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Retransmissions {
    /// The method being retransmitted.
    pub method: String,
    /// Total transmissions of that request, original included.
    pub count: usize,
    /// Elapsed seconds from the first transmission to the last.
    pub span_sec: f64,
    /// Indices of every transmission, in order.
    pub evidence: Vec<usize>,
}

/// One dialog's signalling diagnosis.
///
/// Fields for detections 4–7 are deliberately absent rather than present-and-
/// always-`None`: a field that is never populated reads to every surface as
/// "checked, not detected", which is exactly the lie the `Option` choice above
/// exists to prevent. They are added when they are implemented.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SignalingDiagnosis {
    /// Detection 1 — the dialog ended on a `4xx`/`5xx`/`6xx`.
    pub final_failure: Option<FinalFailure>,
    /// Detection 2 — repeated challenges with no `2xx`.
    pub auth_loop: Option<AuthLoop>,
    /// Detection 3 — a request retransmitted with no response.
    pub retransmissions: Option<Retransmissions>,
    /// Plain-language lines, one per detection, so that surfaces rendering one
    /// line per problem do not each re-invent the phrasing.
    pub hints: Vec<String>,
}

impl SignalingDiagnosis {
    /// True when nothing was detected. Surfaces omit the object entirely in that
    /// case, matching how the media diagnosis is rendered.
    pub fn is_empty(&self) -> bool {
        self.final_failure.is_none() && self.auth_loop.is_none() && self.retransmissions.is_none()
    }
}

/// 3 challenges without a `2xx` is the signal. Two is normal: the first request
/// is unauthenticated by design, so a challenge-response-challenge sequence is
/// what a correct registration looks like.
const AUTH_LOOP_MIN_CHALLENGES: usize = 3;

/// Two transmissions of a request can be a genuine retransmission after a lost
/// response. Three with nothing coming back is a path that is not working.
const RETRANSMIT_MIN_COUNT: usize = 3;

/// What makes two requests the same transaction: CSeq number, CSeq method, and
/// top-`Via` branch (RFC 3261 §17). Named because the tuple appears in both the
/// grouping map and the search over it, and clippy is right that the bare form is
/// unreadable in a signature.
type TransactionKey = (u32, String, String);

/// Diagnose the signalling side of one dialog.
///
/// Takes the dialog's messages in capture order; every evidence index returned
/// points into that slice. Pure, like `diagnose_media`, so it can be called from
/// any surface and tested without a capture.
pub fn diagnose_signaling(messages: &[SipMessage]) -> SignalingDiagnosis {
    let mut diag = SignalingDiagnosis::default();

    detect_final_failure(messages, &mut diag);
    detect_auth_loop(messages, &mut diag);
    detect_retransmissions(messages, &mut diag);

    diag
}

/// Detection 1 — final failure with cause.
///
/// The *last* failure response wins, not the first: a dialog that is challenged
/// `401` and then fails `503` failed on the `503`, and reporting the `401` as the
/// cause would point the reader at authentication when the trunk was down. A
/// failure appearing after a `2xx` is not a dialog outcome either — a mid-dialog
/// re-INVITE can be rejected while the call continues — so anything at or after
/// the first `2xx` is ignored.
fn detect_final_failure(messages: &[SipMessage], diag: &mut SignalingDiagnosis) {
    let first_success = messages
        .iter()
        .position(|m| matches!(m.status_code, Some(c) if (200..300).contains(&c)));

    let limit = first_success.unwrap_or(messages.len());

    let failure = messages[..limit].iter().enumerate().rfind(|(_, m)| {
        // 401/407 are challenges, not outcomes: they are the auth loop's
        // business. A dialog whose only "failure" is a challenge has not
        // failed, it is mid-handshake.
        matches!(m.status_code, Some(c) if (400..700).contains(&c) && c != 401 && c != 407)
    });

    let Some((idx, msg)) = failure else { return };
    let code = msg.status_code.unwrap_or_default();
    let reason_phrase = msg.reason.clone().unwrap_or_default();

    diag.hints.push(match msg.header("Reason") {
        Some(r) => format!("Call failed: {code} {reason_phrase} ({r})."),
        None => format!("Call failed: {code} {reason_phrase}."),
    });

    diag.final_failure = Some(FinalFailure {
        code,
        reason_phrase,
        reason_header: msg.header("Reason").map(str::to_string),
        warning: msg.header("Warning").map(str::to_string),
        evidence: vec![idx],
    });
}

/// Detection 2 — authentication loop.
///
/// Only fires when no `2xx` was ever reached: a dialog that was challenged three
/// times and then succeeded is a slow registration, not a fault.
fn detect_auth_loop(messages: &[SipMessage], diag: &mut SignalingDiagnosis) {
    if messages
        .iter()
        .any(|m| matches!(m.status_code, Some(c) if (200..300).contains(&c)))
    {
        return;
    }

    let evidence: Vec<usize> = messages
        .iter()
        .enumerate()
        .filter(|(_, m)| matches!(m.status_code, Some(401) | Some(407)))
        .map(|(i, _)| i)
        .collect();

    if evidence.len() < AUTH_LOOP_MIN_CHALLENGES {
        return;
    }

    // Does the UAC ever actually attempt the challenge? One `Authorization` (or
    // `Proxy-Authorization`) anywhere in the dialog is enough to distinguish a
    // client that is trying and failing from one that never responds.
    let attempts = messages.iter().any(|m| {
        m.is_request
            && (m.header("Authorization").is_some() || m.header("Proxy-Authorization").is_some())
    });

    let challenges = evidence.len();
    let kind = if attempts {
        diag.hints.push(format!(
            "Authentication loop: {challenges} challenges answered with credentials and \
             re-challenged — the credentials are being rejected."
        ));
        AuthLoopKind::CredentialFailure
    } else {
        diag.hints.push(format!(
            "Authentication loop: {challenges} challenges and no Authorization header ever \
             sent — the client is not attempting the challenge, or a proxy is stripping it."
        ));
        AuthLoopKind::SilentDrop
    };

    diag.auth_loop = Some(AuthLoop {
        kind,
        challenges,
        evidence,
    });
}

/// Detection 3 — retransmission storm / no-response transaction.
///
/// A retransmission is the same request sent again: identical CSeq *and*
/// identical top-`Via` branch, per RFC 3261 §17. CSeq alone is not enough —
/// an INVITE and its ACK share a CSeq number, and a re-challenged request
/// reuses the branch only when it is genuinely the same transaction.
///
/// "No response" is scoped to the transaction, not the dialog: the point is a
/// request that got nothing back, which is what distinguishes a broken path from
/// a client that retransmitted once because a response was slow.
fn detect_retransmissions(messages: &[SipMessage], diag: &mut SignalingDiagnosis) {
    // Group requests by (CSeq number, CSeq method, branch).
    let mut groups: Vec<(TransactionKey, Vec<usize>)> = Vec::new();

    for (idx, msg) in messages.iter().enumerate() {
        if !msg.is_request {
            continue;
        }
        // ACK is fire-and-forget: it is never answered, so counting repeats of it
        // as "no response" would report every retransmitted ACK as a fault.
        if msg.method == Some(SipMethod::Ack) {
            continue;
        }
        let Some((num, method)) = msg.cseq() else {
            continue;
        };
        // No top-Via branch means no way to prove two requests are the same
        // transaction, so the message is skipped rather than grouped on CSeq
        // alone. Via is mandatory in SIP, so this only happens on a malformed or
        // truncated capture — and in that case reporting "no response" on a guess
        // would be worse than reporting nothing. The consequence is that this
        // detection is quietly unavailable for such captures, which is the right
        // trade but worth knowing when a storm you can see by eye is not flagged.
        let Some(branch) = msg.top_via_branch() else {
            continue;
        };
        let key = (num, method.to_string(), branch.to_string());
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(idx),
            None => groups.push((key, vec![idx])),
        }
    }

    // The worst offender is the one worth reporting: the transaction with the
    // most unanswered transmissions.
    //
    // `first`/`last` are destructured out of the group here rather than indexed
    // later, so the bounds come from the iterator that proved the group non-empty
    // instead of an `expect` asserting it after the fact.
    let mut worst: Option<(&TransactionKey, &Vec<usize>, usize, usize)> = None;

    for (key, idxs) in &groups {
        if idxs.len() < RETRANSMIT_MIN_COUNT {
            continue;
        }
        // Any response sharing this CSeq number and method answered it.
        let answered = messages.iter().any(|m| {
            !m.is_request
                && m.cseq()
                    .is_some_and(|(n, meth)| n == key.0 && meth == key.1)
        });
        if answered {
            continue;
        }
        // Indices came from an ascending enumerate, so the ends bound the span.
        let (Some(&first), Some(&last)) = (idxs.first(), idxs.last()) else {
            continue;
        };
        if worst.is_none_or(|(_, best, _, _)| idxs.len() > best.len()) {
            worst = Some((key, idxs, first, last));
        }
    }

    let Some((key, idxs, first_idx, last_idx)) = worst else {
        return;
    };

    let count = idxs.len();
    let span_sec = (messages[last_idx].timestamp - messages[first_idx].timestamp).num_milliseconds()
        as f64
        / 1000.0;

    let method = key.1.clone();
    diag.hints.push(format!(
        "No response to {method}: {count} transmissions over {span_sec:.1}s with nothing \
         received — a one-way path or an unreachable peer."
    ));

    diag.retransmissions = Some(Retransmissions {
        method,
        count,
        span_sec,
        evidence: idxs.clone(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use std::net::{IpAddr, Ipv4Addr};

    const SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const DST: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    /// Build a message from raw SIP text at a given offset in seconds, so the
    /// retransmission span is a real measurement rather than a fixture constant.
    ///
    /// Fixtures are written with bare `\n` for readability and converted here:
    /// the parser requires CRLF, so writing them out literally would make every
    /// fixture unreadable to catch a mistake the parser already catches.
    fn msg_at(raw: &str, secs: i64) -> SipMessage {
        let ts = chrono::DateTime::from_timestamp(1_700_000_000 + secs, 0)
            .expect("valid fixture timestamp");
        parse_sip(
            raw.replace('\n', "\r\n").as_bytes(),
            ts,
            SRC,
            DST,
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("fixture parses")
    }

    fn msg(raw: &str) -> SipMessage {
        msg_at(raw, 0)
    }

    fn invite(branch: &str, cseq: u32) -> String {
        format!(
            "INVITE sip:b@example.com SIP/2.0\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch={branch}\n\
             From: <sip:a@example.com>;tag=1\n\
             To: <sip:b@example.com>\n\
             Call-ID: c1@example.com\n\
             CSeq: {cseq} INVITE\n\
             Content-Length: 0\n\n"
        )
    }

    fn response(code: u16, phrase: &str, extra: &str) -> String {
        format!(
            "SIP/2.0 {code} {phrase}\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\n\
             From: <sip:a@example.com>;tag=1\n\
             To: <sip:b@example.com>;tag=2\n\
             Call-ID: c1@example.com\n\
             CSeq: 1 INVITE\n\
             {extra}Content-Length: 0\n\n"
        )
    }

    // -- detection 1 ------------------------------------------------------

    #[test]
    fn final_failure_records_code_and_phrase() {
        let d = diagnose_signaling(&[
            msg(&invite("z9hG4bK1", 1)),
            msg(&response(503, "Service Unavailable", "")),
        ]);
        let f = d.final_failure.expect("503 is a final failure");
        assert_eq!(f.code, 503);
        assert_eq!(f.reason_phrase, "Service Unavailable");
        assert_eq!(f.evidence, vec![1]);
        assert!(d.hints[0].contains("503"));
    }

    #[test]
    fn final_failure_carries_reason_and_warning_headers() {
        let d = diagnose_signaling(&[
            msg(&invite("z9hG4bK1", 1)),
            msg(&response(
                503,
                "Service Unavailable",
                "Reason: Q.850;cause=34;text=\"no circuit available\"\n\
                 Warning: 399 proxy \"trunk group exhausted\"\n",
            )),
        ]);
        let f = d.final_failure.expect("detected");
        assert_eq!(
            f.reason_header.as_deref(),
            Some("Q.850;cause=34;text=\"no circuit available\"")
        );
        assert_eq!(
            f.warning.as_deref(),
            Some("399 proxy \"trunk group exhausted\"")
        );
        // The hint surfaces the Reason, because 503 alone does not say why.
        assert!(d.hints[0].contains("no circuit available"));
    }

    #[test]
    fn a_successful_call_has_no_final_failure() {
        let d = diagnose_signaling(&[msg(&invite("z9hG4bK1", 1)), msg(&response(200, "OK", ""))]);
        assert!(d.final_failure.is_none());
        assert!(d.is_empty());
    }

    #[test]
    fn failure_after_a_2xx_is_not_the_dialog_outcome() {
        // A rejected re-INVITE mid-call must not be reported as the call failing.
        let d = diagnose_signaling(&[
            msg(&invite("z9hG4bK1", 1)),
            msg(&response(200, "OK", "")),
            msg(&invite("z9hG4bK9", 2)),
            msg(&response(488, "Not Acceptable Here", "")),
        ]);
        assert!(d.final_failure.is_none());
    }

    #[test]
    fn last_failure_wins_over_an_earlier_one() {
        // Challenged, then the trunk fails. The 503 is the answer, not the 404.
        let d = diagnose_signaling(&[
            msg(&invite("z9hG4bK1", 1)),
            msg(&response(404, "Not Found", "")),
            msg(&invite("z9hG4bK2", 2)),
            msg(&response(503, "Service Unavailable", "")),
        ]);
        assert_eq!(d.final_failure.expect("detected").code, 503);
    }

    #[test]
    fn a_challenge_alone_is_not_a_failure() {
        // 401 is a handshake step. Reporting it as the cause would send the
        // reader after credentials when nothing has failed yet.
        let d = diagnose_signaling(&[
            msg(&invite("z9hG4bK1", 1)),
            msg(&response(401, "Unauthorized", "")),
        ]);
        assert!(d.final_failure.is_none());
    }

    // -- detection 2 ------------------------------------------------------

    #[test]
    fn three_challenges_without_authorization_is_a_silent_drop() {
        let msgs: Vec<SipMessage> = (0..3)
            .flat_map(|i| {
                [
                    msg(&invite(&format!("z9hG4bK{i}"), i + 1)),
                    msg(&response(401, "Unauthorized", "")),
                ]
            })
            .collect();
        let a = diagnose_signaling(&msgs).auth_loop.expect("loop detected");
        assert_eq!(a.kind, AuthLoopKind::SilentDrop);
        assert_eq!(a.challenges, 3);
        assert_eq!(a.evidence, vec![1, 3, 5]);
    }

    #[test]
    fn three_challenges_with_authorization_is_a_credential_failure() {
        let with_auth = |i: u32| {
            invite(&format!("z9hG4bK{i}"), i).replace(
                "Content-Length: 0",
                "Authorization: Digest username=\"a\", response=\"deadbeef\"\nContent-Length: 0",
            )
        };
        let msgs = vec![
            msg(&with_auth(1)),
            msg(&response(407, "Proxy Authentication Required", "")),
            msg(&with_auth(2)),
            msg(&response(407, "Proxy Authentication Required", "")),
            msg(&with_auth(3)),
            msg(&response(407, "Proxy Authentication Required", "")),
        ];
        let a = diagnose_signaling(&msgs).auth_loop.expect("loop detected");
        assert_eq!(a.kind, AuthLoopKind::CredentialFailure);
        assert_eq!(a.challenges, 3);
    }

    #[test]
    fn two_challenges_is_normal_and_not_a_loop() {
        // The first request is unauthenticated by design.
        let msgs = vec![
            msg(&invite("z9hG4bK1", 1)),
            msg(&response(401, "Unauthorized", "")),
            msg(&invite("z9hG4bK2", 2)),
            msg(&response(401, "Unauthorized", "")),
        ];
        assert!(diagnose_signaling(&msgs).auth_loop.is_none());
    }

    #[test]
    fn challenges_followed_by_success_are_not_a_loop() {
        let mut msgs: Vec<SipMessage> = (0..3)
            .flat_map(|i| {
                [
                    msg(&invite(&format!("z9hG4bK{i}"), i + 1)),
                    msg(&response(401, "Unauthorized", "")),
                ]
            })
            .collect();
        msgs.push(msg(&response(200, "OK", "")));
        assert!(diagnose_signaling(&msgs).auth_loop.is_none());
    }

    // -- detection 3 ------------------------------------------------------

    #[test]
    fn retransmitted_invite_with_no_response_reports_count_and_span() {
        // Same branch and CSeq three times, nothing back.
        let msgs: Vec<SipMessage> = [0i64, 1, 3]
            .iter()
            .map(|s| msg_at(&invite("z9hG4bK1", 1), *s))
            .collect();
        let r = diagnose_signaling(&msgs)
            .retransmissions
            .expect("storm detected");
        assert_eq!(r.method, "INVITE");
        assert_eq!(r.count, 3);
        assert!((r.span_sec - 3.0).abs() < 0.001, "span was {}", r.span_sec);
        assert_eq!(r.evidence, vec![0, 1, 2]);
    }

    #[test]
    fn retransmissions_that_got_a_response_are_not_reported() {
        let mut msgs: Vec<SipMessage> = [0i64, 1, 3]
            .iter()
            .map(|s| msg_at(&invite("z9hG4bK1", 1), *s))
            .collect();
        msgs.push(msg_at(&response(503, "Service Unavailable", ""), 4));
        assert!(diagnose_signaling(&msgs).retransmissions.is_none());
    }

    #[test]
    fn two_transmissions_is_below_the_threshold() {
        let msgs: Vec<SipMessage> = [0i64, 1]
            .iter()
            .map(|s| msg_at(&invite("z9hG4bK1", 1), *s))
            .collect();
        assert!(diagnose_signaling(&msgs).retransmissions.is_none());
    }

    #[test]
    fn different_branches_are_different_transactions_not_retransmissions() {
        // Three separate INVITEs, each its own transaction. Grouping on CSeq
        // alone would call this a storm.
        let msgs: Vec<SipMessage> = (0..3)
            .map(|i| msg_at(&invite(&format!("z9hG4bK{i}"), 1), i))
            .collect();
        assert!(diagnose_signaling(&msgs).retransmissions.is_none());
    }

    #[test]
    fn retransmitted_ack_is_not_a_no_response_fault() {
        // ACK is never answered; counting its repeats would flag every dialog.
        let ack = |branch: &str| {
            format!(
                "ACK sip:b@example.com SIP/2.0\n\
                 Via: SIP/2.0/UDP 10.0.0.1:5060;branch={branch}\n\
                 From: <sip:a@example.com>;tag=1\n\
                 To: <sip:b@example.com>;tag=2\n\
                 Call-ID: c1@example.com\n\
                 CSeq: 1 ACK\n\
                 Content-Length: 0\n\n"
            )
        };
        let msgs: Vec<SipMessage> = [0i64, 1, 2]
            .iter()
            .map(|s| msg_at(&ack("z9hG4bK1"), *s))
            .collect();
        assert!(diagnose_signaling(&msgs).retransmissions.is_none());
    }

    // -- shape ------------------------------------------------------------

    #[test]
    fn an_empty_dialog_detects_nothing() {
        let d = diagnose_signaling(&[]);
        assert!(d.is_empty());
        assert!(d.hints.is_empty());
    }

    #[test]
    fn detections_compose_on_one_dialog() {
        // A storm and then a failure: both are true, and both are reported.
        let mut msgs: Vec<SipMessage> = [0i64, 1, 3]
            .iter()
            .map(|s| msg_at(&invite("z9hG4bK1", 1), *s))
            .collect();
        // A failure on a different transaction, so the storm stays unanswered.
        msgs.push(msg_at(&invite("z9hG4bK9", 2), 4));
        let mut fail = msg_at(&response(503, "Service Unavailable", ""), 5);
        fail.headers
            .retain(|h| !h.name.eq_ignore_ascii_case("CSeq"));
        msgs.push(fail);
        let d = diagnose_signaling(&msgs);
        assert!(d.retransmissions.is_some(), "storm should survive");
        assert!(d.final_failure.is_some(), "failure should be reported");
        assert_eq!(d.hints.len(), 2, "one hint per detection: {:?}", d.hints);
    }

    #[test]
    fn is_empty_tracks_the_detection_fields() {
        let mut d = SignalingDiagnosis::default();
        assert!(d.is_empty());
        d.hints.push("a hint alone does not count".to_string());
        assert!(
            d.is_empty(),
            "hints without a detection are not a diagnosis"
        );
        d.final_failure = Some(FinalFailure::default());
        assert!(!d.is_empty());
    }
}
