//! Signalling-side problem diagnosis.
//!
//! The complement to [`crate::rtp::diagnosis`], which does this job for media.
//! That module can already say a call had one-way audio or a NAT mismatch; this
//! one says the call failed on a `503` after three retransmitted INVITEs, or
//! that a phone has been looping on `401` without ever authenticating. The
//! evidence was always captured — it was simply never read as a diagnosis.
//!
//! Spec: `docs/design/sip-problem-diagnosis.md`. All seven detections are
//! implemented here.
//!
//! # Thresholds are protocol timers, not preferences
//!
//! Three detections need a number, and each takes it from a document rather
//! than from taste: post-dial delay from Table 2/E.721, the `ACK` window from
//! Timer H, and the no-final-response window from Timer C. Every one is
//! justified at [`SignalingThresholds::default`] with the clause it came from,
//! because a threshold whose origin nobody recorded is a threshold nobody can
//! argue with later.
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

/// A `2xx` answer to an `INVITE` that was never acknowledged.
///
/// `waited_sec` is carried because the claim depends on it entirely: this is a
/// fault only once the observation window exceeds Timer H, and a reader who
/// cannot see how long was waited cannot tell a definite fault from an
/// impatient one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AckMissing {
    /// Seconds from the `2xx` to the last message observed on the dialog.
    pub waited_sec: f64,
    /// How many times the answer was retransmitted, the `2xx` itself included.
    /// A UAS that never gets its `ACK` retransmits until Timer H (RFC 3261
    /// §17.2.1), so a count above one is the peer agreeing that it never
    /// arrived.
    pub answer_transmissions: usize,
    /// Indices of the `2xx` and any retransmissions of it.
    pub evidence: Vec<usize>,
}

/// Why a dialog never reached a final response.
///
/// The two cases are reported separately because only one of them is a
/// statement about the call. `Cancelled` is a fact — someone sent a `CANCEL`.
/// `NoFinalResponse` is a statement about the *capture*, and conflating them
/// would turn "the recording stopped" into "the call failed", which is the
/// specific lie this detection exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbandonedKind {
    /// A `CANCEL` was sent before any final response — the caller hung up.
    Cancelled,
    /// No final response was observed. **Not a failure.** The capture may have
    /// ended mid-call, or the call may still be ringing.
    NoFinalResponse,
}

/// A dialog that never reached a final response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Abandoned {
    /// Which of the two shapes this is.
    pub kind: AbandonedKind,
    /// Seconds from the initial request to the last message observed.
    pub elapsed_sec: f64,
    /// Indices of the `CANCEL` when there was one, otherwise of the initial
    /// request the dialog never got an answer to.
    pub evidence: Vec<usize>,
}

/// Time from `INVITE` to the first provisional ring-back, over threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostDialDelay {
    /// Measured delay in seconds.
    pub delay_sec: f64,
    /// The threshold it exceeded, echoed so a report is readable without also
    /// knowing how the tool was configured.
    pub threshold_sec: f64,
    /// The provisional status code that ended the wait (`180`, `183`, …).
    pub responded_with: u16,
    /// Indices of the `INVITE` and the provisional response.
    pub evidence: Vec<usize>,
}

/// How a `REGISTER` dialog disappointed the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationFailureKind {
    /// The registration was rejected outright.
    Rejected,
    /// The registration succeeded, but for less time than the endpoint asked
    /// for, so it will re-register sooner than it planned.
    ShortenedExpiry,
}

/// A `REGISTER` that failed, or succeeded for less time than it asked for.
///
/// Kept separate from [`FinalFailure`] because the operator question is a
/// different one — "is this phone online?" rather than "why did this call
/// fail?" — and the two get read by different people at different times.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistrationFailure {
    /// Rejected outright, or granted less time than requested.
    pub kind: RegistrationFailureKind,
    /// The final status code. `200` for a shortened expiry.
    pub code: u16,
    /// Seconds the endpoint asked for, when it said.
    pub requested_expiry_sec: Option<u32>,
    /// Seconds the registrar granted, when it said.
    pub granted_expiry_sec: Option<u32>,
    /// Indices of the `REGISTER` and its final response.
    pub evidence: Vec<usize>,
}

/// Tunable limits for the two detections that need one.
///
/// Separate from the detections themselves for the same reason
/// [`crate::rtp::diagnosis::AsymmetryThresholds`] is: a threshold buried in a
/// function body cannot be adjusted by a reader who knows their own network
/// better than the default does.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SignalingThresholds {
    /// Post-dial delay over which a call is flagged, in seconds.
    pub post_dial_delay_sec: f64,
    /// How long a `2xx` must go unacknowledged before the missing `ACK` counts
    /// as a fault rather than as a capture that stopped early, in seconds.
    pub ack_timeout_sec: f64,
    /// How long an `INVITE` must sit without a final response before the
    /// absence is worth reporting at all, in seconds.
    pub no_final_response_sec: f64,
}

impl Default for SignalingThresholds {
    /// # Post-dial delay: 11.0 s
    ///
    /// From Table 2/E.721, the 95th-percentile post-selection delay target for
    /// an **international** connection at normal load. E.721 §2.2(b) defines
    /// post-selection delay as the interval from the initial `SETUP` carrying
    /// all selection digits to the first message indicating call disposition —
    /// `ALERTING` for a successful call — which is `INVITE` to first `18x` with
    /// the protocol names changed.
    ///
    /// International, rather than the tighter local (6.0 s) or toll (8.0 s)
    /// figures, because a capture does not say which kind of call it is
    /// holding. Flagging at the most permissive target means the finding holds
    /// whatever the call turns out to be: it missed the target even if it were
    /// the longest connection type the recommendation contemplates. A local
    /// threshold applied to an international call would report a network
    /// meeting its target as broken.
    ///
    /// The full normal-load table, for anyone who does know their traffic and
    /// wants to tighten this — local 3.0 s mean / 6.0 s 95%, toll 5.0 / 8.0,
    /// international 8.0 / 11.0. The percentile figures are the right statistic
    /// for judging one call; the means are distribution targets and a single
    /// call exceeding one is not a fault.
    ///
    /// Caveat worth stating because the recommendation states it: NOTE 1 to
    /// Table 2 marks every value except the normal-load means as provisional.
    /// 11.0 s is therefore the best-grounded figure available, not a settled
    /// one.
    ///
    /// # ACK timeout: 32.0 s
    ///
    /// Timer H, RFC 3261 §17.2.1 — 64×T1 with the default T1 of 500 ms
    /// (Appendix A). Timer H is exactly "wait time for `ACK` receipt": the
    /// point at which the specification itself stops expecting one.
    ///
    /// # No final response: 180.0 s
    ///
    /// Timer C, RFC 3261 §16.6 bullet 11, which opens by naming this exact
    /// situation: "In order to handle the case where an INVITE request never
    /// generates a final response, the TU uses a timer which is called timer
    /// C… The timer MUST be larger than 3 minutes." Appendix A lists it as
    /// `> 3min`.
    ///
    /// Without this bound the detection reports every call that happens to be
    /// ringing when the capture stops, which is most captures — a warning on
    /// healthy in-progress traffic teaches the reader to ignore warnings. Past
    /// Timer C a proxy in the path would itself have given up, so the silence
    /// has outlived what the protocol tolerates and is worth a line.
    fn default() -> Self {
        Self {
            post_dial_delay_sec: 11.0,
            ack_timeout_sec: 32.0,
            no_final_response_sec: 180.0,
        }
    }
}

/// One dialog's signalling diagnosis.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SignalingDiagnosis {
    /// Detection 1 — the dialog ended on a `4xx`/`5xx`/`6xx`.
    pub final_failure: Option<FinalFailure>,
    /// Detection 2 — repeated challenges with no `2xx`.
    pub auth_loop: Option<AuthLoop>,
    /// Detection 3 — a request retransmitted with no response.
    pub retransmissions: Option<Retransmissions>,
    /// Detection 4 — an answered `INVITE` that was never acknowledged.
    pub ack_missing: Option<AckMissing>,
    /// Detection 5 — cancelled, or never answered at all.
    pub abandoned: Option<Abandoned>,
    /// Detection 6 — slow ring-back.
    pub post_dial_delay: Option<PostDialDelay>,
    /// Detection 7 — a `REGISTER` that failed or was cut short.
    pub registration_failure: Option<RegistrationFailure>,
    /// Plain-language lines, one per detection, so that surfaces rendering one
    /// line per problem do not each re-invent the phrasing.
    pub hints: Vec<String>,
}

impl SignalingDiagnosis {
    /// True when nothing was detected. Surfaces omit the object entirely in that
    /// case, matching how the media diagnosis is rendered.
    ///
    /// Restated as an exhaustive destructure rather than a chain of
    /// `is_none()` calls: adding a detection to the struct without adding it
    /// here would make every dialog carrying only that detection render as
    /// clean, and a prose list cannot fail to compile when someone forgets.
    pub fn is_empty(&self) -> bool {
        let Self {
            final_failure,
            auth_loop,
            retransmissions,
            ack_missing,
            abandoned,
            post_dial_delay,
            registration_failure,
            hints: _,
        } = self;
        final_failure.is_none()
            && auth_loop.is_none()
            && retransmissions.is_none()
            && ack_missing.is_none()
            && abandoned.is_none()
            && post_dial_delay.is_none()
            && registration_failure.is_none()
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
    diagnose_signaling_with(messages, &SignalingThresholds::default())
}

/// Diagnose the signalling side of one dialog against explicit thresholds.
///
/// [`diagnose_signaling`] is this with [`SignalingThresholds::default`], which
/// is what every surface calls; this exists for a caller who knows their own
/// network's post-dial delay budget better than E.721's international figure
/// does.
pub fn diagnose_signaling_with(
    messages: &[SipMessage],
    thresholds: &SignalingThresholds,
) -> SignalingDiagnosis {
    let mut diag = SignalingDiagnosis::default();

    detect_final_failure(messages, &mut diag);
    detect_auth_loop(messages, &mut diag);
    detect_retransmissions(messages, &mut diag);
    detect_ack_missing(messages, &mut diag, thresholds);
    detect_abandoned(messages, &mut diag, thresholds);
    detect_post_dial_delay(messages, &mut diag, thresholds);
    detect_registration_failure(messages, &mut diag);

    diag
}

/// Elapsed seconds between two messages, by index.
fn elapsed_sec(messages: &[SipMessage], from: usize, to: usize) -> f64 {
    (messages[to].timestamp - messages[from].timestamp).num_milliseconds() as f64 / 1000.0
}

/// The `Expires` value a REGISTER or its response is asking for or granting.
///
/// RFC 3261 §10.2.1.1 allows the interval to arrive two ways: an `Expires`
/// header, or an `expires` parameter on the `Contact`. The parameter wins where
/// both appear, because it is the per-binding value and the header is only the
/// default for bindings that do not carry one.
fn expiry_of(msg: &SipMessage) -> Option<u32> {
    if let Some(contact) = msg.contact() {
        for param in contact.split(';').skip(1) {
            let (name, value) = param.split_once('=')?;
            if name.trim().eq_ignore_ascii_case("expires") {
                return value.trim().trim_matches('"').parse().ok();
            }
        }
    }
    msg.header("Expires")?.trim().parse().ok()
}

/// Detection 4 — a `2xx` to an `INVITE` that was never acknowledged.
///
/// RFC 3261 §17.1.1.3 makes the `ACK` to a `2xx` the UAC's responsibility, and
/// §17.2.1 gives the UAS Timer H to wait for it. A missing `ACK` is invisible
/// from either end alone — the caller believes it answered, the callee believes
/// it never connected — which is exactly the class of fault a correlating
/// capture exists to find.
///
/// **The observation window is the whole claim.** A `2xx` at the very end of a
/// capture has no missing `ACK`; it has an `ACK` nobody recorded. So this only
/// fires once the dialog was watched for longer than Timer H past the answer.
/// The window is measured to the dialog's own last message, which is the only
/// bound available here — a dialog whose capture stopped at the `2xx` is
/// reported as nothing at all rather than as a fault.
fn detect_ack_missing(
    messages: &[SipMessage],
    diag: &mut SignalingDiagnosis,
    thresholds: &SignalingThresholds,
) {
    // Every 2xx answering an INVITE. Retransmissions of the answer are the
    // UAS's own evidence that it never saw an ACK, so they are collected too.
    let answers: Vec<usize> = messages
        .iter()
        .enumerate()
        .filter(|(_, m)| {
            !m.is_request
                && matches!(m.status_code, Some(c) if (200..300).contains(&c))
                && m.cseq().is_some_and(|(_, meth)| meth == "INVITE")
        })
        .map(|(i, _)| i)
        .collect();

    let (Some(&first), Some(&last_msg)) = (answers.first(), messages.len().checked_sub(1).as_ref())
    else {
        return;
    };

    // An ACK for the same CSeq number closes it out. The method of an ACK's own
    // CSeq is ACK, so the number is what ties it to the INVITE it acknowledges.
    let answered_cseq = messages[first].cseq().map(|(n, _)| n);
    let acked = messages.iter().any(|m| {
        m.is_request
            && m.method == Some(SipMethod::Ack)
            && m.cseq().map(|(n, _)| n) == answered_cseq
    });
    if acked {
        return;
    }

    // A `BYE` is proof the dialog was established, and therefore proof the
    // `ACK` arrived — RFC 3261 §15 has a UA not sending `BYE` on a confirmed
    // dialog until it has received the `ACK` for its `2xx`. A capture that
    // holds the answer and the hangup but not the `ACK` dropped one packet;
    // reporting that as "the caller believes the call is up and the callee does
    // not" about a call that then hung up cleanly is a false positive, and the
    // loudest possible one, since it fires on ordinary completed calls.
    let byed = messages
        .iter()
        .skip(first)
        .any(|m| m.is_request && m.method == Some(SipMethod::Bye));
    if byed {
        return;
    }

    let waited_sec = elapsed_sec(messages, first, last_msg);
    if waited_sec < thresholds.ack_timeout_sec {
        return;
    }

    let answer_transmissions = answers.len();
    diag.hints.push(format!(
        "INVITE answered but never acknowledged: no ACK in {waited_sec:.1}s \
         (Timer H is {:.0}s), answer sent {answer_transmissions} time(s). The caller \
         believes the call is up and the callee does not.",
        thresholds.ack_timeout_sec
    ));
    diag.ack_missing = Some(AckMissing {
        waited_sec,
        answer_transmissions,
        evidence: answers,
    });
}

/// Detection 5 — cancelled, or never answered at all.
///
/// The two cases are one detection because they are one question — "why is
/// there no outcome?" — and two variants because only one of them is an answer.
///
/// `NoFinalResponse` is deliberately **not** a failure. A capture that stopped
/// while the phone was still ringing looks identical to a call nobody ever
/// answered, and the tool cannot tell them apart. Reporting the state and
/// letting the reader decide is the honest move; the alternative silently
/// converts every truncated capture into a fault.
///
/// It is also bounded by Timer C, which the spec did not ask for. Reporting
/// every unanswered `INVITE` means reporting every call in flight when the
/// capture stopped — on a busy capture that is a warning against healthy
/// traffic, and a warning that fires on healthy traffic trains the reader to
/// stop reading warnings. Past Timer C the silence has outlived what a proxy
/// in the path would tolerate, so it is worth a line; before it, the call is
/// simply still happening.
fn detect_abandoned(
    messages: &[SipMessage],
    diag: &mut SignalingDiagnosis,
    thresholds: &SignalingThresholds,
) {
    // Only INVITE dialogs. A REGISTER or OPTIONS with no answer is detection
    // 3's business (a request that got nothing back), and detection 7's.
    let Some(invite) = messages
        .iter()
        .position(|m| m.is_request && m.method == Some(SipMethod::Invite))
    else {
        return;
    };

    let has_final = messages
        .iter()
        .any(|m| matches!(m.status_code, Some(c) if (200..700).contains(&c)));
    if has_final {
        return;
    }

    let Some(last) = messages.len().checked_sub(1) else {
        return;
    };

    let cancel = messages
        .iter()
        .position(|m| m.is_request && m.method == Some(SipMethod::Cancel));

    let (kind, evidence) = match cancel {
        Some(idx) => {
            diag.hints.push(format!(
                "Call cancelled by the caller after {:.1}s, before any final response.",
                elapsed_sec(messages, invite, idx)
            ));
            (AbandonedKind::Cancelled, vec![idx])
        }
        None => {
            let silent_for = elapsed_sec(messages, invite, last);
            // Still inside Timer C: the call is in progress, not abandoned.
            if silent_for < thresholds.no_final_response_sec {
                return;
            }
            diag.hints.push(format!(
                "No final response after {silent_for:.1}s — UNKNOWN, not a failure. Past \
                 Timer C ({:.0}s), but the capture may simply have ended while the call \
                 was still ringing.",
                thresholds.no_final_response_sec
            ));
            (AbandonedKind::NoFinalResponse, vec![invite])
        }
    };

    diag.abandoned = Some(Abandoned {
        kind,
        elapsed_sec: elapsed_sec(messages, invite, last),
        evidence,
    });
}

/// Detection 6 — slow ring-back.
///
/// Measured `INVITE` to first `18x`, which is E.721's post-selection delay
/// under different names. The caller experiences this as dead air, hears
/// nothing to suggest the call is progressing, and hangs up — so a network can
/// score well on answer-seizure ratio while its users believe it is broken.
///
/// `100 Trying` is excluded. It is hop-by-hop acknowledgement that a proxy took
/// the request (RFC 3261 §8.2.6), inaudible to the caller, and counting it
/// would measure the first proxy's responsiveness rather than the call's.
fn detect_post_dial_delay(
    messages: &[SipMessage],
    diag: &mut SignalingDiagnosis,
    thresholds: &SignalingThresholds,
) {
    let Some(invite) = messages
        .iter()
        .position(|m| m.is_request && m.method == Some(SipMethod::Invite))
    else {
        return;
    };

    let ringback = messages
        .iter()
        .enumerate()
        .skip(invite)
        .find(|(_, m)| matches!(m.status_code, Some(c) if (101..200).contains(&c)));

    let Some((idx, msg)) = ringback else { return };

    let delay_sec = elapsed_sec(messages, invite, idx);
    if delay_sec <= thresholds.post_dial_delay_sec {
        return;
    }

    let responded_with = msg.status_code.unwrap_or_default();
    diag.hints.push(format!(
        "Post-dial delay {delay_sec:.1}s to the first {responded_with} — over the \
         {:.1}s threshold. The caller hears silence for that whole interval.",
        thresholds.post_dial_delay_sec
    ));
    diag.post_dial_delay = Some(PostDialDelay {
        delay_sec,
        threshold_sec: thresholds.post_dial_delay_sec,
        responded_with,
        evidence: vec![invite, idx],
    });
}

/// Detection 7 — a `REGISTER` that failed, or was granted less time than it
/// asked for.
///
/// **There is no "suspiciously short" constant here, deliberately.** The spec
/// asked for an expiry "so short the endpoint will re-register immediately",
/// and any threshold answering that literally would be a number chosen for
/// looking reasonable — the thing the post-dial-delay grounding above exists to
/// avoid. The protocol already supplies a non-arbitrary comparison: the
/// endpoint states the interval it wants and the registrar states what it
/// granted (RFC 3261 §10.2.1.1), so "shorter than requested" is a fact about
/// the exchange rather than a judgement imposed on it. The two numbers are
/// reported and the reader decides whether 60 s against a requested 3600 s
/// matters on their network.
///
/// `Expires: 0` is excluded throughout. That is a de-registration — a phone
/// deliberately going offline (RFC 3261 §10.2.2) — and flagging it would report
/// every clean shutdown as a fault.
fn detect_registration_failure(messages: &[SipMessage], diag: &mut SignalingDiagnosis) {
    let Some(register) = messages
        .iter()
        .position(|m| m.is_request && m.method == Some(SipMethod::Register))
    else {
        return;
    };

    let requested_expiry_sec = expiry_of(&messages[register]);
    // A de-registration is not a failure, and neither is a rejected one worth
    // reporting under this detection: the phone is going away on purpose.
    if requested_expiry_sec == Some(0) {
        return;
    }

    let final_response = messages.iter().enumerate().rfind(|(_, m)| {
        matches!(m.status_code, Some(c) if (200..700).contains(&c) && c != 401 && c != 407)
            && m.cseq().is_some_and(|(_, meth)| meth == "REGISTER")
    });

    let Some((idx, msg)) = final_response else {
        return;
    };
    let code = msg.status_code.unwrap_or_default();
    let evidence = vec![register, idx];

    if !(200..300).contains(&code) {
        let reason = msg.reason.clone().unwrap_or_default();
        diag.hints.push(format!(
            "Registration rejected: {code} {reason}. The endpoint is offline."
        ));
        diag.registration_failure = Some(RegistrationFailure {
            kind: RegistrationFailureKind::Rejected,
            code,
            requested_expiry_sec,
            granted_expiry_sec: None,
            evidence,
        });
        return;
    }

    let granted_expiry_sec = expiry_of(msg);
    let (Some(requested), Some(granted)) = (requested_expiry_sec, granted_expiry_sec) else {
        return;
    };
    if granted == 0 || granted >= requested {
        return;
    }

    diag.hints.push(format!(
        "Registration granted {granted}s against {requested}s requested — the endpoint \
         will re-register {}× more often than it intends.",
        requested / granted.max(1)
    ));
    diag.registration_failure = Some(RegistrationFailure {
        kind: RegistrationFailureKind::ShortenedExpiry,
        code,
        requested_expiry_sec,
        granted_expiry_sec,
        evidence,
    });
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

    // -- detection 4: ACK never received ----------------------------------

    fn ack(cseq: u32) -> String {
        format!(
            "ACK sip:b@example.com SIP/2.0\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK9\n\
             From: <sip:a@example.com>;tag=1\n\
             To: <sip:b@example.com>;tag=2\n\
             Call-ID: c1@example.com\n\
             CSeq: {cseq} ACK\n\
             Content-Length: 0\n\n"
        )
    }

    #[test]
    fn answered_invite_with_no_ack_past_timer_h_is_flagged() {
        // 200 retransmitted for 40s — past Timer H — and never acknowledged.
        let d = diagnose_signaling(&[
            msg_at(&invite("z9hG4bK1", 1), 0),
            msg_at(&response(200, "OK", ""), 1),
            msg_at(&response(200, "OK", ""), 20),
            msg_at(&response(200, "OK", ""), 41),
        ]);
        let a = d.ack_missing.expect("no ACK in 40s is a fault");
        assert_eq!(a.answer_transmissions, 3);
        assert_eq!(a.evidence, vec![1, 2, 3]);
        assert!((a.waited_sec - 40.0).abs() < 0.001, "{}", a.waited_sec);
    }

    #[test]
    fn answered_invite_with_an_ack_is_not_flagged() {
        let d = diagnose_signaling(&[
            msg_at(&invite("z9hG4bK1", 1), 0),
            msg_at(&response(200, "OK", ""), 1),
            msg_at(&ack(1), 2),
            msg_at(&response(200, "OK", ""), 60),
        ]);
        assert!(d.ack_missing.is_none(), "the ACK is right there");
    }

    /// The capture-truncation guard. Without it, every capture that stops just
    /// after the answer reports a fault that did not happen.
    #[test]
    fn answered_invite_at_the_end_of_a_short_capture_is_not_flagged() {
        let d = diagnose_signaling(&[
            msg_at(&invite("z9hG4bK1", 1), 0),
            msg_at(&response(200, "OK", ""), 1),
            msg_at(&response(200, "OK", ""), 5),
        ]);
        assert!(
            d.ack_missing.is_none(),
            "5s is inside Timer H — the ACK may simply not have been captured yet"
        );
    }

    /// Caught by a TUI snapshot rather than by a unit test: the fixture call
    /// was `INVITE`/`180`/`200`/`BYE` with no `ACK` recorded, and the first
    /// version of this detection flagged an ordinary completed call. A
    /// diagnosis that fires on healthy traffic is worse than no diagnosis.
    #[test]
    fn a_call_that_hung_up_normally_has_no_missing_ack() {
        let bye = "BYE sip:b@example.com SIP/2.0\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK7\n\
             From: <sip:a@example.com>;tag=1\n\
             To: <sip:b@example.com>;tag=2\n\
             Call-ID: c1@example.com\n\
             CSeq: 2 BYE\n\
             Content-Length: 0\n\n";
        let d = diagnose_signaling(&[
            msg_at(&invite("z9hG4bK1", 1), 0),
            msg_at(&response(200, "OK", ""), 1),
            msg_at(bye, 62),
        ]);
        assert!(
            d.ack_missing.is_none(),
            "a BYE proves the dialog was established, so the ACK was captured-missing, not missing"
        );
    }

    #[test]
    fn ack_timeout_threshold_is_configurable() {
        let msgs = [
            msg_at(&invite("z9hG4bK1", 1), 0),
            msg_at(&response(200, "OK", ""), 1),
            msg_at(&response(200, "OK", ""), 5),
        ];
        let tight = SignalingThresholds {
            ack_timeout_sec: 4.0,
            ..Default::default()
        };
        assert!(
            diagnose_signaling_with(&msgs, &tight).ack_missing.is_some(),
            "5s exceeds a 4s window"
        );
    }

    // -- detection 5: abandoned / cancelled -------------------------------

    fn cancel(cseq: u32) -> String {
        format!(
            "CANCEL sip:b@example.com SIP/2.0\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\n\
             From: <sip:a@example.com>;tag=1\n\
             To: <sip:b@example.com>\n\
             Call-ID: c1@example.com\n\
             CSeq: {cseq} CANCEL\n\
             Content-Length: 0\n\n"
        )
    }

    #[test]
    fn cancel_before_a_final_response_is_cancelled() {
        let d = diagnose_signaling(&[
            msg_at(&invite("z9hG4bK1", 1), 0),
            msg_at(&response(180, "Ringing", ""), 1),
            msg_at(&cancel(1), 9),
        ]);
        let a = d.abandoned.expect("cancelled before any final response");
        assert_eq!(a.kind, AbandonedKind::Cancelled);
        assert_eq!(a.evidence, vec![2]);
        assert!(d.hints.iter().any(|h| h.contains("cancelled")));
    }

    /// The detection the spec calls "most likely to lie if written carelessly".
    /// A capture that stopped while ringing must report *unknown*, and must say
    /// so in the words a reader will see.
    #[test]
    fn no_final_response_is_unknown_not_a_failure() {
        let d = diagnose_signaling(&[
            msg_at(&invite("z9hG4bK1", 1), 0),
            msg_at(&response(180, "Ringing", ""), 1),
            msg_at(&response(180, "Ringing", ""), 200),
        ]);
        let a = d.abandoned.expect("no final response");
        assert_eq!(a.kind, AbandonedKind::NoFinalResponse);
        assert!(
            d.hints.iter().any(|h| h.contains("UNKNOWN")),
            "the hint must not read as a failure: {:?}",
            d.hints
        );
        assert!(
            d.final_failure.is_none(),
            "a truncated capture is not a call failure"
        );
    }

    #[test]
    fn a_call_that_reached_a_final_response_is_not_abandoned() {
        let d = diagnose_signaling(&[
            msg_at(&invite("z9hG4bK1", 1), 0),
            msg_at(&response(200, "OK", ""), 1),
            msg_at(&ack(1), 1),
        ]);
        assert!(d.abandoned.is_none());
    }

    // -- detection 6: post-dial delay -------------------------------------

    #[test]
    fn slow_ringback_exceeds_the_e721_threshold() {
        let d = diagnose_signaling(&[
            msg_at(&invite("z9hG4bK1", 1), 0),
            msg_at(&response(180, "Ringing", ""), 14),
        ]);
        let p = d.post_dial_delay.expect("14s is over the 11s target");
        assert_eq!(p.responded_with, 180);
        assert_eq!(p.threshold_sec, 11.0);
        assert!((p.delay_sec - 14.0).abs() < 0.001);
        assert_eq!(p.evidence, vec![0, 1]);
    }

    #[test]
    fn prompt_ringback_is_not_flagged() {
        let d = diagnose_signaling(&[
            msg_at(&invite("z9hG4bK1", 1), 0),
            msg_at(&response(180, "Ringing", ""), 2),
        ]);
        assert!(d.post_dial_delay.is_none());
    }

    /// `100 Trying` is hop-by-hop and inaudible. Counting it would measure the
    /// nearest proxy's reflexes and report a silent caller as a healthy one.
    #[test]
    fn trying_does_not_stop_the_post_dial_clock() {
        let d = diagnose_signaling(&[
            msg_at(&invite("z9hG4bK1", 1), 0),
            msg_at(&response(100, "Trying", ""), 0),
            msg_at(&response(180, "Ringing", ""), 15),
        ]);
        let p = d
            .post_dial_delay
            .expect("the caller waited 15s for ring-back, whatever the proxy said");
        assert!((p.delay_sec - 15.0).abs() < 0.001, "{}", p.delay_sec);
    }

    #[test]
    fn post_dial_threshold_is_configurable() {
        let msgs = [
            msg_at(&invite("z9hG4bK1", 1), 0),
            msg_at(&response(180, "Ringing", ""), 4),
        ];
        let strict = SignalingThresholds {
            post_dial_delay_sec: 3.0,
            ..Default::default()
        };
        assert!(
            diagnose_signaling_with(&msgs, &strict)
                .post_dial_delay
                .is_some()
        );
    }

    // -- detection 7: registration failure --------------------------------

    fn register(expires: &str) -> String {
        format!(
            "REGISTER sip:example.com SIP/2.0\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\n\
             From: <sip:a@example.com>;tag=1\n\
             To: <sip:a@example.com>\n\
             Call-ID: r1@example.com\n\
             CSeq: 1 REGISTER\n\
             Contact: <sip:a@10.0.0.1>\n\
             {expires}Content-Length: 0\n\n"
        )
    }

    fn register_response(code: u16, phrase: &str, contact: &str) -> String {
        format!(
            "SIP/2.0 {code} {phrase}\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\n\
             From: <sip:a@example.com>;tag=1\n\
             To: <sip:a@example.com>;tag=2\n\
             Call-ID: r1@example.com\n\
             CSeq: 1 REGISTER\n\
             {contact}Content-Length: 0\n\n"
        )
    }

    #[test]
    fn rejected_registration_is_flagged() {
        let d = diagnose_signaling(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(403, "Forbidden", "")),
        ]);
        let r = d.registration_failure.expect("403 rejects the binding");
        assert_eq!(r.kind, RegistrationFailureKind::Rejected);
        assert_eq!(r.code, 403);
        assert_eq!(r.requested_expiry_sec, Some(3600));
        assert!(d.hints.iter().any(|h| h.contains("offline")));
    }

    #[test]
    fn shortened_expiry_reports_both_numbers() {
        let d = diagnose_signaling(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(
                200,
                "OK",
                "Contact: <sip:a@10.0.0.1>;expires=60\n",
            )),
        ]);
        let r = d.registration_failure.expect("granted far less than asked");
        assert_eq!(r.kind, RegistrationFailureKind::ShortenedExpiry);
        assert_eq!(r.requested_expiry_sec, Some(3600));
        assert_eq!(r.granted_expiry_sec, Some(60));
        assert_eq!(r.code, 200);
    }

    #[test]
    fn a_registration_granted_what_it_asked_for_is_not_flagged() {
        let d = diagnose_signaling(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(
                200,
                "OK",
                "Contact: <sip:a@10.0.0.1>;expires=3600\n",
            )),
        ]);
        assert!(d.registration_failure.is_none());
    }

    /// `Expires: 0` is a phone deliberately going offline. Flagging it would
    /// report every clean shutdown on the network as a fault.
    #[test]
    fn deregistration_is_not_a_failure() {
        let d = diagnose_signaling(&[
            msg(&register("Expires: 0\n")),
            msg(&register_response(200, "OK", "")),
        ]);
        assert!(d.registration_failure.is_none());
    }

    #[test]
    fn a_challenged_registration_is_not_a_rejection() {
        let d = diagnose_signaling(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(401, "Unauthorized", "")),
            msg(&register("Expires: 3600\n")),
            msg(&register_response(
                200,
                "OK",
                "Contact: <sip:a@10.0.0.1>;expires=3600\n",
            )),
        ]);
        assert!(
            d.registration_failure.is_none(),
            "401 then 200 is a normal registration"
        );
    }

    /// The `Contact` parameter is the per-binding value and wins over the
    /// header, per RFC 3261 §10.2.1.1. Getting this backwards would compare a
    /// requested 3600 against a granted 3600 and miss the shortening.
    #[test]
    fn contact_expires_parameter_beats_the_expires_header() {
        let d = diagnose_signaling(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(
                200,
                "OK",
                "Contact: <sip:a@10.0.0.1>;expires=120\nExpires: 3600\n",
            )),
        ]);
        let r = d
            .registration_failure
            .expect("the binding got 120s whatever the header says");
        assert_eq!(r.granted_expiry_sec, Some(120));
    }

    // -- cross-detection --------------------------------------------------

    /// Every detection must be represented in `is_empty`, which the exhaustive
    /// destructure enforces at compile time. This checks the runtime half: each
    /// field alone is enough to make a diagnosis non-empty.
    #[test]
    fn every_detection_alone_makes_the_diagnosis_non_empty() {
        let base = SignalingDiagnosis::default();
        assert!(base.is_empty());

        let mut d = base.clone();
        d.ack_missing = Some(AckMissing {
            waited_sec: 40.0,
            answer_transmissions: 3,
            evidence: vec![1],
        });
        assert!(!d.is_empty(), "ack_missing");

        let mut d = base.clone();
        d.abandoned = Some(Abandoned {
            kind: AbandonedKind::Cancelled,
            elapsed_sec: 9.0,
            evidence: vec![2],
        });
        assert!(!d.is_empty(), "abandoned");

        let mut d = base.clone();
        d.post_dial_delay = Some(PostDialDelay {
            delay_sec: 14.0,
            threshold_sec: 11.0,
            responded_with: 180,
            evidence: vec![0, 1],
        });
        assert!(!d.is_empty(), "post_dial_delay");

        let mut d = base;
        d.registration_failure = Some(RegistrationFailure {
            kind: RegistrationFailureKind::Rejected,
            code: 403,
            requested_expiry_sec: Some(3600),
            granted_expiry_sec: None,
            evidence: vec![0, 1],
        });
        assert!(!d.is_empty(), "registration_failure");
    }
}
