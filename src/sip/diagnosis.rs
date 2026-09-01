//! Signaling-side problem diagnosis.
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
    /// The network's own words for why nothing came back, when an ICMP error
    /// against this dialog said so — `port unreachable`, `host unreachable`.
    /// `None` means no ICMP error was recorded for the dialog, which is the
    /// ordinary case and leaves the finding an inference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icmp_cause: Option<String>,
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
/// statement about the call. `Canceled` is a fact — someone sent a `CANCEL`.
/// `NoFinalResponse` is a statement about the *capture*, and conflating them
/// would turn "the recording stopped" into "the call failed", which is the
/// specific lie this detection exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbandonedKind {
    /// A `CANCEL` was sent before any final response — the caller hung up.
    Canceled,
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
        Self::BUILT_IN
    }
}

impl SignalingThresholds {
    /// The standards figures documented on [`Default::default`].
    ///
    /// Named so a caller can still reach the shipped numbers after the run has
    /// declared its own — [`configured`] answers with the declaration.
    pub const BUILT_IN: Self = Self {
        post_dial_delay_sec: 11.0,
        ack_timeout_sec: 32.0,
        no_final_response_sec: 180.0,
    };
}

/// The thresholds `[diagnosis]` declared, once the run has read its config.
///
/// Process-global and written once at startup, the same shape as
/// [`crate::provenance::set_node_name`]: the value is a property of the run.
static CONFIGURED: std::sync::OnceLock<SignalingThresholds> = std::sync::OnceLock::new();

/// Declare the signaling thresholds for this process. Call once, at startup.
///
/// # Side effects
///
/// Writes a process-global `OnceLock`; the first writer wins, so a later call
/// is ignored rather than moving the thresholds mid-run.
pub fn set_signaling_thresholds(thresholds: SignalingThresholds) {
    let _ = CONFIGURED.set(thresholds);
}

/// The thresholds this run diagnoses against: what `[diagnosis]` declared,
/// else [`SignalingThresholds::BUILT_IN`].
#[must_use]
pub fn configured() -> SignalingThresholds {
    CONFIGURED
        .get()
        .copied()
        .unwrap_or(SignalingThresholds::BUILT_IN)
}

/// The network said, in so many words, that the far end was not there.
///
/// Every other detection in this module reads intent out of what the endpoints
/// did or did not send. This one reads a statement: an ICMP error quoting one
/// of this dialog's own requests is the network reporting that the datagram
/// could not be delivered. It is the only evidence here that licenses a claim
/// about reachability, which is why `registration_failure` and `abandoned` are
/// careful never to make one on their own.
///
/// The two addresses are separate fields on purpose. `unreachable_endpoint` is
/// the socket that did not answer — the thing to go and look at.
/// `reported_by` is the router or host that noticed and said so, which is
/// usually a working device on the path and must never be reported as the
/// fault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcmpUnreachable {
    /// The network's own words, e.g. `port unreachable`.
    pub description: String,
    /// Raw ICMP type byte, so an unusual code is still traceable.
    pub icmp_type: u8,
    /// Raw ICMP code byte.
    pub icmp_code: u8,
    /// `address:port` of the endpoint that did not answer, or the bare address
    /// when the quote stopped before the transport header.
    pub unreachable_endpoint: String,
    /// Address of the device that reported the failure. Not the fault.
    pub reported_by: String,
    /// Method of the quoted request, when its start line was quoted.
    pub method: Option<String>,
    /// How many such errors were seen for this dialog. Exact — not the number
    /// of quotes retained, which is capped.
    pub errors: usize,
    /// Whether the quote sipnab read was shorter than the datagram it quoted.
    /// True is the ordinary case — RFC 792 guarantees only 8 bytes past the IP
    /// header — and is carried so a reader knows the quote is a prefix.
    pub truncated: bool,
    /// Indices of the dialog messages the quotes refer to, matched by `CSeq`
    /// and destination. Empty when the quote carried too little to identify
    /// one, which is a statement about the quote, not about the dialog.
    ///
    /// Drawn from the retained quotes only, so on a dialog hit more times than
    /// the retention cap this names fewer messages than `errors` counts. That
    /// under-states the evidence, which is the safe direction.
    pub evidence: Vec<usize>,
}

/// One message that only one of the two witnesses carried.
///
/// Which witness is said by the field this sits in —
/// [`SourceDisagreement::mirror_only`] or [`SourceDisagreement::wire_only`] —
/// never by a flag inside the entry, so a surface cannot render a gap without
/// naming the source that has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnwitnessedMessage {
    /// What the message is — `INVITE`, `200 OK`. A report pasted into a ticket
    /// has no message list to join `index` against, which is the same reason
    /// `evidence_label` exists on the report surfaces.
    pub summary: String,
    /// Index into the dialog's own message list, the coordinate every other
    /// detection's `evidence` uses.
    pub index: usize,
}

/// One message BOTH witnesses carried, whose SDP named different media
/// endpoints on each.
///
/// Both accounts travel, neither is the reference, and there is deliberately
/// no `expected`/`actual` pair here: an SDP rewritten between the proxy's own
/// account and the wire is sometimes the SBC doing its job and sometimes the
/// bug, and nothing at this layer can tell those apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdpDivergence {
    /// What the message is, as [`UnwitnessedMessage::summary`].
    pub summary: String,
    /// Media endpoints the MIRROR's copy advertised, `<media> <addr>:<port>`
    /// in `m=` order. Empty when that copy carried no SDP at all, which is
    /// itself a disagreement worth seeing.
    pub mirror: Vec<String>,
    /// Media endpoints the copy captured on the WIRE advertised.
    pub wire: Vec<String>,
    /// Index of the mirrored copy in the dialog's message list.
    pub mirror_index: usize,
    /// Index of the copy captured on the wire.
    pub wire_index: usize,
}

/// Detection 9 — the run's two witnesses do not tell the same story about
/// this call.
///
/// # Why two witnesses are not one witness twice
///
/// A HEP mirror is produced by the proxy under investigation: it reports what
/// that proxy BELIEVES it did. A local capture reports what actually left the
/// box. When the question is "is OpenSIPS misbehaving, or did I configure it
/// to", a mirror produced by the suspect cannot answer it. That makes the two
/// sources complementary rather than redundant, and it makes their
/// DISAGREEMENT the finding rather than an inconvenience to reconcile. Raised
/// by Dan Jenkins ([@danjenkins](https://github.com/danjenkins)) after using
/// the composite source SRC1 shipped.
///
/// Each state the entry names has a different reading:
///
/// * **Mirror-only** — the proxy believes it sent something this capture never
///   saw leave the box.
/// * **Wire-only** — the box did something its own trace does not admit to.
/// * **Differing** — an SDP rewrite between the two accounts.
/// * **Agreed** — [`agreed`](Self::agreed), the denominator. Two witnesses
///   that match are the healthy case, so a call with no gap and no divergence
///   produces no finding at all rather than a clean object on every call.
///
/// # What this cannot say
///
/// A call ONE witness never saw at all produces nothing here, deliberately.
/// From inside such a call there is no way to tell a proxy that mirrored a
/// phantom from a witness that was not watching that call's signaling — TLS it
/// cannot decrypt, a BPF filter that excludes the port, a mirror not
/// configured for that traffic. Separating those needs capture-wide evidence
/// this detection is not given, and guessing would put a finding on every call
/// of a run whose wire filter is media-only, which is the filter a composite
/// run wants.
///
/// A message either capture dropped also looks exactly like one a source never
/// carried. That is the nature of the comparison and the reason this is a
/// finding to investigate rather than a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDisagreement {
    /// How many messages both witnesses carried — the denominator that makes
    /// the gap counts mean something. "2 of 14 messages" is diagnostic; "2
    /// messages" is not.
    pub agreed: usize,
    /// Messages the HEP mirror reported that the wire never carried.
    pub mirror_only: Vec<UnwitnessedMessage>,
    /// Messages the wire carried that the mirror never reported.
    pub wire_only: Vec<UnwitnessedMessage>,
    /// Messages both witnesses carried whose SDP named different endpoints.
    pub sdp_differs: Vec<SdpDivergence>,
    /// Every message index this finding drew on, sorted and deduplicated —
    /// the same `evidence` shape the other eight detections carry, so the
    /// report surfaces render it with the machinery they already have.
    pub evidence: Vec<usize>,
}

/// One dialog's signaling diagnosis.
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
    /// Detection 5 — canceled, or never answered at all.
    pub abandoned: Option<Abandoned>,
    /// Detection 6 — slow ring-back.
    pub post_dial_delay: Option<PostDialDelay>,
    /// Detection 7 — a `REGISTER` that failed or was cut short.
    pub registration_failure: Option<RegistrationFailure>,
    /// Detection 8 — an ICMP error quoting one of this dialog's requests.
    ///
    /// Omitted from serialized output when absent, unlike the seven above:
    /// those are always checked, so `null` means "checked, not found". This
    /// one can only be checked when the capture holds ICMP at all, and a
    /// `null` on a capture that had none would read as "checked" when nothing
    /// was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icmp_unreachable: Option<IcmpUnreachable>,
    /// Detection 9 — the run's two capture sources disagree about this call.
    ///
    /// Omitted from serialized output when absent, for the reason
    /// [`Self::icmp_unreachable`] is: it can only be checked when TWO
    /// witnesses carried this call, and a `null` on a single-source capture
    /// would read as "checked, they agreed" when nothing was compared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_disagreement: Option<SourceDisagreement>,
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
            icmp_unreachable,
            source_disagreement,
            hints: _,
        } = self;
        final_failure.is_none()
            && auth_loop.is_none()
            && retransmissions.is_none()
            && ack_missing.is_none()
            && abandoned.is_none()
            && post_dial_delay.is_none()
            && registration_failure.is_none()
            && icmp_unreachable.is_none()
            && source_disagreement.is_none()
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

/// Diagnose the signaling side of one dialog.
///
/// Takes the dialog's messages in capture order; every evidence index returned
/// points into that slice. Detections 1-7 are pure functions of `messages`,
/// like `diagnose_media`, so they can be called from any surface and tested
/// without a capture.
///
/// Detection 8 additionally reads any ICMP error the capture held against this
/// dialog's `Call-ID` (see [`crate::pipeline::icmp_evidence_for`]). That
/// evidence is part of the same capture as the messages — an ICMP error is not
/// a `ParsedPacket`, so it cannot arrive through the `messages` slice, and
/// threading it through every caller would leave the most diagnostic packet in
/// a capture unread by every existing surface. A run that recorded no ICMP —
/// every unit test here, and any capture without ICMP — behaves exactly as it
/// did before detection 8 existed. Use [`diagnose_signaling_with_evidence`]
/// when the evidence should be supplied explicitly.
/// Reads the run's declared thresholds via [`configured`], so
/// `[diagnosis] post_dial_delay_secs` reaches every surface — the TUI, the
/// reports, `--json-dialogs` and the MCP tools — without any of them having to
/// remember to ask. This entry point is the ONLY place that resolution
/// happens, which is why the seven callers of it need no change and cannot
/// disagree about the answer.
pub fn diagnose_signaling(messages: &[SipMessage]) -> SignalingDiagnosis {
    diagnose_signaling_with(messages, &configured())
}

/// Diagnose the signaling side of one dialog against explicit thresholds.
///
/// [`diagnose_signaling`] is this with [`configured`], which is what every
/// surface calls; this exists for a caller who knows their own network's
/// post-dial delay budget better than E.721's international figure does, and
/// for the tests that have to pin a threshold rather than inherit the run's.
pub fn diagnose_signaling_with(
    messages: &[SipMessage],
    thresholds: &SignalingThresholds,
) -> SignalingDiagnosis {
    // One relaxed atomic load when the capture held no ICMP, which is the
    // common case: no allocation and no lock. The store is not built for wasm,
    // where a build diagnoses everything else exactly as before and simply has
    // no ICMP evidence to draw on.
    #[cfg(not(target_arch = "wasm32"))]
    let icmp = messages
        .iter()
        .find_map(|m| m.call_id())
        .map(crate::pipeline::icmp_evidence_for)
        .unwrap_or_default();
    #[cfg(target_arch = "wasm32")]
    let icmp = Default::default();
    diagnose_signaling_with_evidence(messages, thresholds, &icmp)
}

/// Diagnose one dialog against explicit thresholds and explicit ICMP evidence.
///
/// The pure form: given the same `messages` and `icmp`, the result is the
/// same. `diagnose_signaling_with` is this with the evidence looked up from
/// the capture-wide store.
///
/// # Arguments
///
/// * `messages` — the dialog's messages in capture order.
/// * `thresholds` — protocol timers governing detections 4-6.
/// * `icmp` — ICMP errors quoting this dialog's requests. Empty is normal.
pub fn diagnose_signaling_with_evidence(
    messages: &[SipMessage],
    thresholds: &SignalingThresholds,
    icmp: &crate::capture::parse::DialogIcmpEvidence,
) -> SignalingDiagnosis {
    let mut diag = SignalingDiagnosis::default();

    detect_final_failure(messages, &mut diag);
    detect_auth_loop(messages, &mut diag);
    detect_retransmissions(messages, &mut diag, icmp);
    detect_ack_missing(messages, &mut diag, thresholds);
    detect_abandoned(messages, &mut diag, thresholds);
    detect_post_dial_delay(messages, &mut diag, thresholds);
    detect_registration_failure(messages, &mut diag);
    detect_icmp_unreachable(messages, &mut diag, icmp);
    detect_source_disagreement(messages, &mut diag);

    diag
}

/// What one ICMP type/code actually asks the reader to go and fix.
///
/// The description alone (`host unreachable`, `communication administratively
/// prohibited`) is the network's wording, not an instruction, and the three
/// commonest codes in real captures send an operator to three different
/// devices:
///
/// * **port unreachable** — the host answered. It is up, and nothing was bound
///   to that port. The fault is the service.
/// * **administratively prohibited** — a firewall or router ACL rejected the
///   packet. The peer may be entirely healthy and reporting it as unreachable
///   sends someone to debug a working device. The fault is the filter.
/// * **host unreachable** — nothing reached the host at all, so nothing is
///   known about its ports. The fault is routing, addressing, or power.
///
/// Measured on one real corpus, a single file held 433 host-unreachable, 262
/// administratively-prohibited and 63 port-unreachable errors. One sentence
/// for all three would have been wrong for at least 695 of them.
///
/// # Arguments
///
/// * `icmp_type` / `icmp_code` — the raw bytes, so an unrecognized pair still
///   renders something rather than a claim.
/// * `v6` — the numbering is different between RFC 792 and RFC 4443: v4 type 3
///   code 1 is "host unreachable", v6 type 3 code 1 is a reassembly timeout.
pub fn icmp_remedy(icmp_type: u8, icmp_code: u8, v6: bool) -> &'static str {
    const PORT: &str = "The host answered, so it is reachable — nothing was listening on that \
                        port. Check the service and the address it binds, not the network.";
    const FILTER: &str = "A filtering device — a firewall or a router ACL — refused the packet. \
                          The peer itself may be perfectly healthy, so the fix is on whatever is \
                          filtering rather than on the endpoint.";
    const NO_ROUTE: &str = "Nothing reached the host, so nothing is known about its ports: it is \
                            powered off, at a different address, or the route to it is gone.";
    const PMTU: &str = "A link on the path has a smaller MTU and the datagram could not be \
                        fragmented — the black hole behind \"large INVITEs vanish, small \
                        requests work\". Lower the path MTU or fragment at the sender.";
    const LOOP_: &str = "The datagram ran out of hops before arriving — a routing loop, or a TTL \
                         set too low for the path.";
    const REASSEMBLY: &str = "The host received some fragments of the datagram and never the \
                              rest, so it gave up reassembling. Fragments are being lost or \
                              filtered on the path.";
    const MALFORMED: &str = "The receiver rejected a header field as malformed, so the datagram \
                             never reached the application.";
    const CONGESTION: &str = "A device on the path reported congestion (deprecated by RFC 6633, \
                              still emitted by some stacks).";
    const GENERIC: &str = "The network could not deliver the datagram; this is a stated failure, \
                           not a timeout.";

    if v6 {
        return match (icmp_type, icmp_code) {
            (1, 4) => PORT,
            (1, 1 | 5 | 6) => FILTER,
            (1, 0 | 2 | 3) => NO_ROUTE,
            (2, _) => PMTU,
            (3, 0) => LOOP_,
            (3, 1) => REASSEMBLY,
            (4, _) => MALFORMED,
            _ => GENERIC,
        };
    }
    match (icmp_type, icmp_code) {
        (3, 3) => PORT,
        (3, 9 | 10 | 13) => FILTER,
        (3, 0 | 1) => NO_ROUTE,
        (3, 4) => PMTU,
        (4, _) => CONGESTION,
        (11, 0) => LOOP_,
        (11, 1) => REASSEMBLY,
        (12, _) => MALFORMED,
        _ => GENERIC,
    }
}

/// Detection 8 — the network reported that a request could not be delivered.
///
/// Unlike every detection above it, this one does not infer: an ICMP error is
/// the network stating a cause. The finding therefore names the endpoint the
/// quoted datagram was addressed to, and names the reporter separately — the
/// two are frequently different hosts, and blaming the reporter would point an
/// operator at a device that is working correctly.
///
/// All the evidence is about one dialog, so it collapses to one finding: the
/// most recent error, with the total count. Message indices are matched by
/// `CSeq` and destination address; a quote too short to carry a `CSeq` yields
/// a finding with no indices rather than a guessed one.
fn detect_icmp_unreachable(
    messages: &[SipMessage],
    diag: &mut SignalingDiagnosis,
    icmp: &crate::capture::parse::DialogIcmpEvidence,
) {
    let Some(last) = icmp.samples.last() else {
        return;
    };

    // Which of this dialog's messages the quotes were about. A quote carries
    // the CSeq of the request that failed; the destination address rules out a
    // same-CSeq message sent the other way.
    let mut evidence: Vec<usize> = Vec::new();
    for e in &icmp.samples {
        let Some(cseq) = e.cseq.as_deref() else {
            continue;
        };
        for (i, m) in messages.iter().enumerate() {
            if m.is_request
                && m.dst_addr == e.unreachable_addr
                && m.header("CSeq").is_some_and(|v| v.trim() == cseq.trim())
                && !evidence.contains(&i)
            {
                evidence.push(i);
            }
        }
    }
    evidence.sort_unstable();

    let endpoint = match last.unreachable_port {
        Some(port) => format!("{}:{}", last.unreachable_addr, port),
        None => last.unreachable_addr.to_string(),
    };
    let truncated = icmp.samples.iter().any(|e| e.truncated);

    // The exact count, not the number of retained samples: a peer that failed
    // thirty times must not be reported as failing eight.
    let errors = usize::try_from(icmp.errors).unwrap_or(usize::MAX);
    let occurrences = if errors == 1 {
        String::new()
    } else {
        format!(" ({errors} times)")
    };
    let what = match &last.method {
        Some(m) => format!("the {m} sent to {endpoint}"),
        None => format!("a request sent to {endpoint}"),
    };
    diag.hints.push(format!(
        "ICMP {}: the network could not deliver {what}{occurrences}, reported by {}. {}",
        last.description,
        last.reported_by,
        icmp_remedy(last.icmp_type, last.icmp_code, last.reported_by.is_ipv6()),
    ));

    diag.icmp_unreachable = Some(IcmpUnreachable {
        description: last.description.to_string(),
        icmp_type: last.icmp_type,
        icmp_code: last.icmp_code,
        unreachable_endpoint: endpoint,
        reported_by: last.reported_by.to_string(),
        method: last.method.clone(),
        errors,
        truncated,
        evidence,
    });
}

/// What makes two captured copies the same message.
///
/// `(request?, status, request method, CSeq, top-`Via` branch)` — RFC 3261
/// §17.1.3 and §17.2.3 match a response to a transaction on the branch and the
/// CSeq method, and this adds only what tells one message of a transaction from
/// another. Borrowed from the messages, so building the whole index allocates
/// nothing but the map.
type MessageIdentity<'a> = (
    bool,
    Option<u16>,
    Option<&'a str>,
    Option<(u32, &'a str)>,
    Option<&'a str>,
);

/// The identity above, read off one message.
fn message_identity(m: &SipMessage) -> MessageIdentity<'_> {
    (
        m.is_request,
        m.status_code,
        m.method.as_ref().map(SipMethod::as_str),
        m.cseq(),
        m.top_via_branch(),
    )
}

/// What a message is, in the words the report surfaces already use.
fn message_summary(m: &SipMessage) -> String {
    if m.is_request {
        match &m.method {
            Some(method) => method.to_string(),
            None => "request".to_string(),
        }
    } else {
        match (m.status_code, &m.reason) {
            (Some(code), Some(reason)) => format!("{code} {reason}"),
            (Some(code), None) => code.to_string(),
            _ => "response".to_string(),
        }
    }
}

/// The media endpoints one copy of a message advertises, in `m=` order.
///
/// Resolved through [`crate::sip::sdp::effective_address`] — media-level `c=`
/// when present, session-level otherwise — because that is the address the
/// rest of sipnab binds RTP on, and comparing the raw lines instead would
/// report a session-level `c=` moved to media level as a rewrite when the
/// resulting socket is identical.
fn sdp_media_endpoints(m: &SipMessage) -> Vec<String> {
    let Some(sdp) = m.sdp() else {
        return Vec::new();
    };
    sdp.media
        .iter()
        .map(
            |media| match crate::sip::sdp::effective_address(media, &sdp) {
                Some(addr) => format!("{} {addr}:{}", media.media_type, media.port),
                // No `c=` at either level. Said, rather than dropped: a media
                // section with no address is not the same as no media section.
                None => format!("{} (no address):{}", media.media_type, media.port),
            },
        )
        .collect()
}

/// Render a per-source endpoint list for a human line.
fn endpoints_or_none(endpoints: &[String]) -> String {
    if endpoints.is_empty() {
        "no SDP".to_string()
    } else {
        endpoints.join(", ")
    }
}

/// How many entries of a gap list a hint names before it stops.
///
/// A hint is one line in a ticket, a TUI row and an MCP payload. A call whose
/// mirror is fifty messages ahead of its wire would otherwise render fifty
/// summaries into all three. The full list is in the structured finding, which
/// is where a reader who wants every one goes.
const HINT_ITEM_CAP: usize = 3;

/// Name the first few messages of a gap list, with a count of what was cut.
fn name_a_few(items: &[UnwitnessedMessage]) -> String {
    let mut named: Vec<String> = items
        .iter()
        .take(HINT_ITEM_CAP)
        .map(|item| format!("{} #{}", item.summary, item.index))
        .collect();
    if items.len() > HINT_ITEM_CAP {
        named.push(format!("and {} more", items.len() - HINT_ITEM_CAP));
    }
    named.join(", ")
}

/// Detection 9 — compare what the HEP mirror reported against what the wire
/// carried, for one call.
///
/// # Why the mirror cannot become the reference by arriving first
///
/// This is the trap the feature exists inside. The HEP mirror is usually
/// FIRST: the proxy mirrors as it processes, while the copy on the wire takes
/// a network hop and a kernel queue on the way to the same process. Any rule
/// shaped "first one wins" therefore makes the proxy's account authoritative —
/// and checking that account is the entire reason the wire capture is there.
/// Three properties keep that from happening, and none of them is a convention
/// a later edit can quietly drop:
///
/// 1. **The pairing key is content, never position.** Two copies pair on
///    [`message_identity`], which reads the start line, the `CSeq` and the top
///    `Via` branch. Which copy the pipeline saw first cannot change which
///    copies pair, or whether they pair at all.
/// 2. **Both accounts are reported by name.** [`SdpDivergence`] carries
///    `mirror` AND `wire`; there is no `expected` field for a surface to render
///    as the truth and no `actual` field to render as the deviation.
/// 3. **The two gap lists are produced by ONE expression applied twice with
///    the arguments swapped**, below. A rule that favoured either witness would
///    have to be written into that single closure, where it would be visible,
///    rather than emerging from two similar-looking blocks that drifted.
///
/// `the_mirror_arriving_first_does_not_make_it_the_reference` pins all three
/// by running the same ladder in both arrival orders and demanding the same
/// per-source answer.
///
/// # Cost on a single-source run
///
/// The gate below is one pass of `Copy`-byte comparisons that stops as soon as
/// both witnesses are known to have spoken, and it allocates nothing. A run
/// with one source walks the ladder once and returns; the index, the pairing
/// and every `String` here are past that return.
fn detect_source_disagreement(messages: &[SipMessage], diag: &mut SignalingDiagnosis) {
    use crate::capture::parse::InputOrigin;

    // Both witnesses must have carried at least one message of THIS call.
    //
    // Gating on the run instead ("the process was started with -d and -L")
    // was rejected: the BPF filter a composite run wants is media-only —
    // `composite_filter_warning` pushes the operator there — so the wire
    // carries no signaling at all and EVERY call would come out mirror-only.
    // A finding on every call is a finding on none. The cost of the weaker
    // gate is stated on `SourceDisagreement`: a call one witness never saw at
    // all says nothing here.
    let mut saw_mirror = false;
    let mut saw_wire = false;
    for m in messages {
        match m.input_origin {
            Some(InputOrigin::Hep) => saw_mirror = true,
            Some(InputOrigin::Wire) => saw_wire = true,
            // Uprobe has no counterpart to be compared against — `-d` beats
            // `--uprobe-tls` and `--uprobe-tls` beats `-L`, so it never
            // composes with another source — and an absent origin is "nobody
            // said" rather than "the same source as the last one".
            _ => {}
        }
        if saw_mirror && saw_wire {
            break;
        }
    }
    if !(saw_mirror && saw_wire) {
        return;
    }

    // Both witnesses' copies under one content-derived key. The two vectors
    // hold message indices in capture order within each source, which is the
    // only thing arrival order decides here: WHICH of N identical
    // retransmissions is called the counterpart of which. It cannot make
    // either source authoritative.
    let mut paired: std::collections::HashMap<MessageIdentity<'_>, (Vec<usize>, Vec<usize>)> =
        std::collections::HashMap::new();
    for (i, m) in messages.iter().enumerate() {
        let entry = match m.input_origin {
            Some(InputOrigin::Hep) => &mut paired.entry(message_identity(m)).or_default().0,
            Some(InputOrigin::Wire) => &mut paired.entry(message_identity(m)).or_default().1,
            _ => continue,
        };
        entry.push(i);
    }

    let mut agreed = 0usize;
    let mut mirror_only: Vec<UnwitnessedMessage> = Vec::new();
    let mut wire_only: Vec<UnwitnessedMessage> = Vec::new();
    let mut sdp_differs: Vec<SdpDivergence> = Vec::new();

    for (mirror_copies, wire_copies) in paired.into_values() {
        // Pair by count. Three mirrored transmissions against two on the wire
        // is ONE message the wire never carried, not three — reporting the two
        // that did arrive as gaps would turn every retransmitting call into a
        // disagreement.
        let matched = mirror_copies.len().min(wire_copies.len());
        agreed += matched;

        // Property 3 from the doc above: one expression, both witnesses.
        let surplus = |copies: &[usize]| -> Vec<UnwitnessedMessage> {
            copies[matched..]
                .iter()
                .map(|&i| UnwitnessedMessage {
                    summary: message_summary(&messages[i]),
                    index: i,
                })
                .collect()
        };
        mirror_only.extend(surplus(&mirror_copies));
        wire_only.extend(surplus(&wire_copies));

        for k in 0..matched {
            let (mirror_index, wire_index) = (mirror_copies[k], wire_copies[k]);
            let mirror = sdp_media_endpoints(&messages[mirror_index]);
            let wire = sdp_media_endpoints(&messages[wire_index]);
            if mirror != wire {
                sdp_differs.push(SdpDivergence {
                    summary: message_summary(&messages[mirror_index]),
                    mirror,
                    wire,
                    mirror_index,
                    wire_index,
                });
            }
        }
    }

    // Agreement is not a finding. Emitting an object for every matching call
    // would put a `signaling_diagnosis` on every clean dialog of a composite
    // run, which is the shape the module's own omission rule exists to avoid.
    if mirror_only.is_empty() && wire_only.is_empty() && sdp_differs.is_empty() {
        return;
    }

    // A `HashMap` iterates in an order the allocator picks, so without this
    // two runs over the same capture would render the same finding in
    // different orders and a golden test would flap.
    mirror_only.sort_unstable_by_key(|item| item.index);
    wire_only.sort_unstable_by_key(|item| item.index);
    sdp_differs.sort_unstable_by_key(|d| d.mirror_index.min(d.wire_index));

    let mut evidence: Vec<usize> = mirror_only
        .iter()
        .chain(wire_only.iter())
        .map(|item| item.index)
        .chain(
            sdp_differs
                .iter()
                .flat_map(|d| [d.mirror_index, d.wire_index]),
        )
        .collect();
    evidence.sort_unstable();
    evidence.dedup();

    let mut said: Vec<String> = Vec::new();
    if !mirror_only.is_empty() {
        said.push(format!(
            "the HEP mirror reported {} the wire never carried ({})",
            plural_messages(mirror_only.len()),
            name_a_few(&mirror_only)
        ));
    }
    if !wire_only.is_empty() {
        said.push(format!(
            "the wire carried {} the mirror never reported ({})",
            plural_messages(wire_only.len()),
            name_a_few(&wire_only)
        ));
    }
    for d in sdp_differs.iter().take(HINT_ITEM_CAP) {
        said.push(format!(
            "{} #{} advertises {} on the mirror and {} on the wire",
            d.summary,
            d.mirror_index,
            endpoints_or_none(&d.mirror),
            endpoints_or_none(&d.wire)
        ));
    }
    diag.hints.push(format!(
        "Capture sources disagree about this call: {}. {} matched on both. HEP is \
         the proxy's account of what it did and the wire is what left the box, so \
         neither is the reference — read them against each other. A message either \
         capture dropped looks the same as one a source never carried.",
        said.join("; "),
        plural_messages(agreed)
    ));

    diag.source_disagreement = Some(SourceDisagreement {
        agreed,
        mirror_only,
        wire_only,
        sdp_differs,
        evidence,
    });
}

/// `1 message` / `4 messages`, so a hint never reads "1 messages".
fn plural_messages(n: usize) -> String {
    if n == 1 {
        "1 message".to_string()
    } else {
        format!("{n} messages")
    }
}

/// Elapsed seconds between two messages, by index.
fn elapsed_sec(messages: &[SipMessage], from: usize, to: usize) -> f64 {
    (messages[to].timestamp - messages[from].timestamp).num_milliseconds() as f64 / 1000.0
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

/// Detection 5 — canceled, or never answered at all.
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
                "Call canceled by the caller after {:.1}s, before any final response.",
                elapsed_sec(messages, invite, idx)
            ));
            (AbandonedKind::Canceled, vec![idx])
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
/// `100 Trying` is excluded. It is hop-by-hop acknowledgment that a proxy took
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

    let requested_expiry_sec = crate::sip::registration_expiry(&messages[register]);
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
        let failure = RegistrationFailure {
            kind: RegistrationFailureKind::Rejected,
            code,
            requested_expiry_sec,
            granted_expiry_sec: None,
            evidence,
        };
        diag.hints
            .push(registration_rejection_headline(&failure, messages));
        diag.registration_failure = Some(failure);
        return;
    }

    let granted_expiry_sec = crate::sip::registration_expiry(msg);
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

/// The one-line statement of a rejected `REGISTER`, rendered from the status
/// code's meaning in RFC 3261 and from what the dialog actually shows.
///
/// # Why this is a function and not two format strings
///
/// It used to be two: the diagnosis hint and the call report each carried
/// their own copy of the sentence, and both copies said the same wrong thing —
/// *"the endpoint is offline"* — for every non-`2xx` code there is. That claim
/// is contradicted by the capture it is drawn from in nearly every case: a
/// rejection is a response, so something answered, and where the endpoint
/// replied to a challenge first it demonstrably transmitted twice. During a
/// registration outage the sentence sent an operator to check firewalls when
/// the fault was a password or a provisioning entry.
///
/// Rendering both surfaces from one function makes the two unable to disagree
/// again, which was the deeper defect.
///
/// # What it will and will not say
///
/// Where the code determines a cause, it is named with the clause it comes
/// from. Where it does not, the reason phrase is read back and nothing is
/// inferred — `480 No DNS results` in the corpus is a proxy that could not
/// resolve a hop, and any cause invented for the bare code would have been as
/// wrong as the one this replaces.
///
/// `408` is the single code where a reachability problem is a live
/// possibility, and it is phrased as one.
///
/// # Arguments
///
/// * `failure` — the detected rejection; `evidence` is `[request, response]`.
/// * `messages` — the dialog's messages, which `failure.evidence` indexes.
///   Out-of-range indices (a compacted dialog) degrade to the code alone
///   rather than panicking.
///
/// # Returns
///
/// Complete, punctuated prose, e.g. `"Registration rejected: 403 Forbidden.
/// The endpoint answered an authentication challenge and the registrar refused
/// the credentials it offered …"` — rendered verbatim by both callers so
/// neither can add a shade of meaning the other lacks.
pub fn registration_rejection_headline(
    failure: &RegistrationFailure,
    messages: &[SipMessage],
) -> String {
    let code = failure.code;
    // The response this was drawn from, when the message list still holds it.
    let response = failure.evidence.get(1).and_then(|&i| messages.get(i));
    let upto = failure.evidence.get(1).copied().unwrap_or(messages.len());

    let reason = response
        .and_then(|m| m.reason.as_deref())
        .map(str::trim)
        .filter(|r| !r.is_empty());

    // Two facts about the exchange, not guesses about it: was a challenge
    // issued, and did the endpoint answer one with credentials?
    let challenged = messages[..upto.min(messages.len())]
        .iter()
        .any(|m| matches!(m.status_code, Some(401 | 407)));
    let credentials_offered = messages[..upto.min(messages.len())].iter().any(|m| {
        m.is_request
            && (m.header("Authorization").is_some() || m.header("Proxy-Authorization").is_some())
    });

    let min_expires = response
        .and_then(|m| m.header("Min-Expires"))
        .map(str::trim);
    let retry_after = response
        .and_then(|m| m.header("Retry-After"))
        .map(str::trim);

    let meaning: String = match code {
        // RFC 3261 §21.4.1. A REGISTER the registrar could not read.
        400 => "The registrar could not parse the request (RFC 3261 §21.4.1) — a malformed \
                REGISTER, not an absent endpoint."
            .to_string(),

        // RFC 3261 §21.4.4: "Authorization will not help". The two shapes are
        // genuinely different findings and must not share a sentence — the
        // challenged one is the commonest registration fault there is, and
        // the unchallenged one supports no statement of cause at all.
        403 if challenged && credentials_offered => {
            "The endpoint answered an authentication challenge and the registrar refused the \
             credentials it offered, so the fault is in the account, its password or its \
             permission to register — none of which is a reachability problem."
                .to_string()
        }
        403 => "The registrar understood the request and refused it outright (RFC 3261 §21.4.4). \
                No challenge was answered in this dialog, so nothing here says why."
            .to_string(),

        // RFC 3261 §21.4.5: definitive information that the user does not exist.
        404 => "No such address-of-record at that domain (RFC 3261 §21.4.5). The endpoint \
                reached the registrar, which has no binding to make for that user."
            .to_string(),

        // RFC 3261 §21.4.6 / §21.5.2: this server does not do registration here.
        405 => "The registrar does not allow REGISTER on that Request-URI (RFC 3261 §21.4.6)."
            .to_string(),
        501 => "The server has not implemented REGISTER (RFC 3261 §21.5.2).".to_string(),

        // RFC 3261 §21.4.9. The one code consistent with a path problem — and
        // still only consistent with one, since the rejection itself arrived.
        408 => "The transaction timed out (RFC 3261 §21.4.9). This is the one rejection \
                consistent with a path or reachability problem rather than a provisioning one."
            .to_string(),

        // RFC 3261 §10.3 step 7 / §21.4.17. An interval negotiation. The
        // registrar MUST state its minimum, so its absence is worth saying.
        423 => match (failure.requested_expiry_sec, min_expires) {
            (Some(req), Some(min)) => format!(
                "An expiry negotiation, not a failure: the endpoint asked for {req}s and the \
                 registrar's minimum is {min}s (RFC 3261 §10.3 step 7)."
            ),
            (None, Some(min)) => format!(
                "An expiry negotiation, not a failure: the registrar's minimum is {min}s \
                 (RFC 3261 §10.3 step 7)."
            ),
            (Some(req), None) => format!(
                "An expiry negotiation, not a failure: the {req}s interval was rejected, but no \
                 Min-Expires was sent to negotiate against, which RFC 3261 §10.3 step 7 requires."
            ),
            (None, None) => "An expiry negotiation, not a failure: the interval was rejected \
                             with no Min-Expires to negotiate against, which RFC 3261 §10.3 \
                             step 7 requires."
                .to_string(),
        },

        // RFC 3261 §21.4.16. Max-Forwards reached zero, which is a routing
        // fault between the two ends and not a property of either.
        483 => "The request ran out of Max-Forwards before reaching a registrar that would \
                answer it (RFC 3261 §21.4.16) — a routing loop or too long a proxy chain."
            .to_string(),

        // RFC 3261 §21.5.4. The server said it was unavailable; reading that
        // as the endpoint being unavailable is the wrong end of the call.
        503 => "The registrar is temporarily unable to handle the request (RFC 3261 §21.5.4) — \
                the server side is unavailable, not the endpoint."
            .to_string(),

        500..=599 => "A server-side fault at the registrar (5xx): the request arrived and was \
                      not processed."
            .to_string(),

        // RFC 3261 §21.6: a 6xx speaks for every location of the user.
        600..=699 => "Refused for the user globally (6xx, RFC 3261 §21.6), not merely by this \
                      registrar."
            .to_string(),

        // Everything else: state the observation and stop. This is the branch
        // the old wording should have had, and its absence is why the corpus's
        // `480 No DNS results` — a proxy that could not resolve a hop — was
        // reported as an offline phone.
        _ if reason.is_some() => "The registrar answered, but this code carries no \
                                  registration-specific meaning in RFC 3261 — the reason phrase \
                                  above is the only statement of cause the capture holds."
            .to_string(),
        _ => "The registrar answered, but this code carries no registration-specific meaning in \
              RFC 3261 and the response carried no reason phrase, so the capture says nothing \
              about the cause."
            .to_string(),
    };

    let mut out = match reason {
        Some(r) => format!("Registration rejected: {code} {r}. {meaning}"),
        None => format!("Registration rejected: {code}. {meaning}"),
    };
    // Retry-After is the one number the server volunteered about when to come
    // back; dropping it leaves the reader to reopen the packet for it.
    if let Some(retry) = retry_after.filter(|r| !r.is_empty()) {
        out.push_str(&format!(" Retry-After: {retry}."));
    }
    // The caller decides the terminal punctuation; every branch above already
    // ends its own sentences, so nothing is appended here.
    out
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
///
/// # Annotated, not suppressed, when ICMP proves the cause
///
/// This detection used to close with "a one-way path or an unreachable peer" —
/// an inference drawn from silence. Detection 8 replaces that silence with a
/// router's own statement, and both used to fire on the same dialog, so a
/// reader saw a guess and a fact side by side with equal weight.
///
/// The fix is to annotate rather than to suppress, and the reason is that the
/// two findings measure different things. The ICMP error says *why* nothing
/// came back. The transmission count and span say *how hard the sender tried*
/// before giving up — 3 INVITEs over 3 s and 11 OPTIONS over 300 s are the
/// same cause and a very different operational picture, and neither is
/// recoverable from the ICMP finding. Suppressing detection 3 would delete a
/// measurement to remove a sentence; keeping it and deleting the sentence
/// costs nothing. So the finding survives with `icmp_cause` set, and only the
/// guess at the end of the hint gives way.
fn detect_retransmissions(
    messages: &[SipMessage],
    diag: &mut SignalingDiagnosis,
    icmp: &crate::capture::parse::DialogIcmpEvidence,
) {
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

    // Prefer a quote of this very method: it is then the same request, not
    // merely the same dialog. Otherwise the most recent quote still applies —
    // the evidence is filed per `Call-ID`, so it is about this dialog either
    // way — and saying so is better than withholding a stated cause because
    // the router happened to quote a different request on the same call.
    let cause = icmp
        .samples
        .iter()
        .rev()
        .find(|e| e.method.as_deref() == Some(method.as_str()))
        .or_else(|| icmp.samples.last());

    match cause {
        Some(e) => diag.hints.push(format!(
            "No response to {method}: {count} transmissions over {span_sec:.1}s with nothing \
             received — and ICMP says why: {}. The count is how hard the sender tried; the \
             ICMP finding is the cause.",
            e.description
        )),
        // Nothing better is available, so the inference is the honest answer.
        None => diag.hints.push(format!(
            "No response to {method}: {count} transmissions over {span_sec:.1}s with nothing \
             received — a one-way path or an unreachable peer."
        )),
    }

    diag.retransmissions = Some(Retransmissions {
        method,
        count,
        span_sec,
        evidence: idxs.clone(),
        icmp_cause: cause.map(|e| e.description.to_string()),
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

    // -- detection 5: abandoned / canceled -------------------------------

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
        let a = d.abandoned.expect("canceled before any final response");
        assert_eq!(a.kind, AbandonedKind::Canceled);
        assert_eq!(a.evidence, vec![2]);
        assert!(d.hints.iter().any(|h| h.contains("canceled")));
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
    }

    /// A second `REGISTER` answering a challenge: same transaction shape as
    /// [`register`] but carrying the `Authorization` header the registrar
    /// asked for.
    fn register_with_credentials() -> String {
        "REGISTER sip:example.com SIP/2.0\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK2\n\
         From: <sip:a@example.com>;tag=1\n\
         To: <sip:a@example.com>\n\
         Call-ID: r1@example.com\n\
         CSeq: 2 REGISTER\n\
         Contact: <sip:a@10.0.0.1>\n\
         Authorization: Digest username=\"a\", realm=\"example.com\", \
         nonce=\"abc\", uri=\"sip:example.com\", response=\"deadbeef\"\n\
         Expires: 3600\n\
         Content-Length: 0\n\n"
            .to_string()
    }

    /// The hint for a rejected `REGISTER`, or a panic naming what was found
    /// instead — a test that silently passed on an absent hint would prove
    /// nothing about its wording.
    fn rejection_hint(messages: &[SipMessage]) -> String {
        let d = diagnose_signaling(messages);
        d.hints
            .iter()
            .find(|h| h.starts_with("Registration"))
            .unwrap_or_else(|| panic!("no registration hint among {:?}", d.hints))
            .clone()
    }

    /// The defect this group exists for. Every non-`2xx` final response to a
    /// `REGISTER` used to be reported as "the endpoint is offline", which is
    /// false for all of these: each is answered BY a registrar the endpoint
    /// reached, and several are answered after the endpoint proved it was
    /// there by replying to a challenge.
    ///
    /// `408` is excluded because it is the one code where a reachability
    /// problem is a live possibility — see
    /// [`request_timeout_is_the_only_code_that_may_mention_reachability`].
    #[test]
    fn no_rejection_code_claims_the_endpoint_is_offline() {
        for (code, phrase) in [
            (400, "Bad Request"),
            (403, "Forbidden"),
            (404, "Not Found"),
            (423, "Interval Too Brief"),
            (480, "No DNS results"),
            (500, "Server Internal Error"),
            (503, "Service Unavailable"),
            (603, "Decline"),
        ] {
            let hint = rejection_hint(&[
                msg(&register("Expires: 3600\n")),
                msg(&register_response(code, phrase, "")),
            ]);
            let lower = hint.to_lowercase();
            for claim in ["offline", "unreachable", "not reachable"] {
                assert!(
                    !lower.contains(claim),
                    "{code} {phrase} must not claim the endpoint is {claim}: {hint}"
                );
            }
            assert!(
                hint.contains(&code.to_string()),
                "{code} hint must name the code it read: {hint}"
            );
        }
    }

    /// `401` challenge, credentials offered, `403` back. The endpoint is
    /// demonstrably online — it answered the challenge — and the fault is in
    /// the credentials or the account, not in the network.
    #[test]
    fn forbidden_after_a_challenge_points_at_the_credentials() {
        let hint = rejection_hint(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(401, "Unauthorized", "")),
            msg(&register_with_credentials()),
            msg(&register_response(403, "Forbidden", "")),
        ]);
        let lower = hint.to_lowercase();
        assert!(
            lower.contains("credential"),
            "403 after a challenge is a credential rejection: {hint}"
        );
        assert!(
            lower.contains("challenge"),
            "the challenge is the evidence that the endpoint is reachable: {hint}"
        );
        assert!(!lower.contains("offline"), "{hint}");
    }

    /// The same `403` with no challenge in front of it is a different fact.
    /// Nothing was offered and nothing was rejected, so naming credentials
    /// would be inventing a cause exactly as the old wording did.
    #[test]
    fn forbidden_without_a_challenge_does_not_invent_credentials() {
        let hint = rejection_hint(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(403, "Forbidden", "")),
        ]);
        assert!(
            !hint.to_lowercase().contains("credential"),
            "no credentials were offered, so none were rejected: {hint}"
        );
        assert!(hint.contains("403"), "{hint}");
    }

    /// RFC 3261 §21.4.5: the server has definitive information that the user
    /// does not exist. The endpoint is online; the address-of-record is not
    /// provisioned.
    #[test]
    fn not_found_names_the_address_of_record() {
        let hint = rejection_hint(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(404, "Not Found", "")),
        ]);
        let lower = hint.to_lowercase();
        assert!(
            lower.contains("address-of-record") || lower.contains("aor"),
            "404 is an unknown AOR: {hint}"
        );
    }

    /// RFC 3261 §21.5.4: the SERVER is unable to process the request. Sending
    /// an operator to check the phone points them at the wrong end of the
    /// call.
    #[test]
    fn service_unavailable_points_at_the_registrar() {
        let hint = rejection_hint(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(503, "Service Unavailable", "")),
        ]);
        let lower = hint.to_lowercase();
        assert!(
            lower.contains("registrar") || lower.contains("server"),
            "503 is the server's problem, not the endpoint's: {hint}"
        );
    }

    /// RFC 3261 §10.3 step 7 / §21.4.17: the registrar rejects an expiry
    /// shorter than its minimum and MUST say what that minimum is. Nothing is
    /// offline; the two numbers are the whole diagnosis.
    #[test]
    fn interval_too_brief_reports_both_intervals() {
        let hint = rejection_hint(&[
            msg(&register("Expires: 60\n")),
            msg(&register_response(
                423,
                "Interval Too Brief",
                "Min-Expires: 3600\n",
            )),
        ]);
        assert!(hint.contains("60"), "the requested interval: {hint}");
        assert!(hint.contains("3600"), "the registrar's minimum: {hint}");
        assert!(!hint.to_lowercase().contains("offline"), "{hint}");
    }

    /// A `423` whose `Min-Expires` is missing is a registrar breaking RFC 3261
    /// §10.3 step 7. Saying so beats inventing the minimum it did not send.
    #[test]
    fn interval_too_brief_without_min_expires_says_so() {
        let hint = rejection_hint(&[
            msg(&register("Expires: 60\n")),
            msg(&register_response(423, "Interval Too Brief", "")),
        ]);
        assert!(
            hint.contains("Min-Expires"),
            "the absent header is the finding: {hint}"
        );
    }

    /// The one code where a reachability problem is a live possibility. It is
    /// still phrased as a possibility, because the `408` reaching the endpoint
    /// proves something answered it.
    #[test]
    fn request_timeout_is_the_only_code_that_may_mention_reachability() {
        let hint = rejection_hint(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(408, "Request Timeout", "")),
        ]);
        let lower = hint.to_lowercase();
        assert!(hint.contains("408"), "{hint}");
        assert!(
            lower.contains("timed out") || lower.contains("timeout"),
            "408 is a timeout: {hint}"
        );
    }

    /// `483` turned up in the corpus and is a routing fault between the two
    /// ends (RFC 3261 §21.4.16) — the request never reached a registrar that
    /// would answer it. Neither end is offline.
    #[test]
    fn too_many_hops_is_a_routing_fault() {
        let hint = rejection_hint(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(483, "Too Many Hops", "")),
        ]);
        let lower = hint.to_lowercase();
        assert!(hint.contains("Max-Forwards"), "{hint}");
        assert!(!lower.contains("offline"), "{hint}");
    }

    /// A code with no registration-specific meaning gets the reason phrase
    /// read back and nothing else. This is the "say what happened, not why"
    /// case: `480 No DNS results` in the corpus is a proxy that could not
    /// resolve, and any invented cause would have been wrong.
    #[test]
    fn an_unmapped_code_reports_the_observation_and_stops() {
        let hint = rejection_hint(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(480, "No DNS results", "")),
        ]);
        assert!(hint.contains("480"), "{hint}");
        assert!(
            hint.contains("No DNS results"),
            "the reason phrase is the only cause evidence there is: {hint}"
        );
    }

    /// `Retry-After` is the registrar saying when to come back; dropping it
    /// leaves the reader guessing at the one number the server supplied.
    #[test]
    fn retry_after_is_carried_into_the_hint() {
        let hint = rejection_hint(&[
            msg(&register("Expires: 3600\n")),
            msg(&register_response(
                503,
                "Service Unavailable",
                "Retry-After: 120\n",
            )),
        ]);
        assert!(hint.contains("120"), "Retry-After must survive: {hint}");
    }

    /// The diagnosis hint and the call report are rendered by ONE function,
    /// so the two surfaces cannot drift back into disagreeing about what a
    /// rejection meant — which is how both came to say "the endpoint is
    /// offline" for every code.
    #[test]
    fn both_surfaces_render_the_same_headline() {
        let messages = [
            msg(&register("Expires: 3600\n")),
            msg(&register_response(401, "Unauthorized", "")),
            msg(&register_with_credentials()),
            msg(&register_response(403, "Forbidden", "")),
        ];
        let d = diagnose_signaling(&messages);
        let failure = d.registration_failure.expect("403 rejects the binding");
        let shared = registration_rejection_headline(&failure, &messages);
        assert!(
            d.hints.iter().any(|h| h.starts_with(&shared)),
            "the hint must be the shared headline: {:?} vs {shared}",
            d.hints
        );
    }

    /// A compacted dialog can no longer supply the response the headline was
    /// drawn from. It must degrade to the code rather than panic on an
    /// out-of-range evidence index.
    #[test]
    fn headline_survives_evidence_pointing_past_the_message_list() {
        let failure = RegistrationFailure {
            kind: RegistrationFailureKind::Rejected,
            code: 404,
            requested_expiry_sec: Some(3600),
            granted_expiry_sec: None,
            evidence: vec![0, 99],
        };
        let head = registration_rejection_headline(&failure, &[]);
        assert!(head.contains("404"), "{head}");
    }

    /// A valueless Contact parameter must not hide the expiry.
    ///
    /// RFC 3261 §10.2.1.1 puts the interval in either an `Expires` header or an
    /// `expires` Contact parameter, and both have to work. A Contact may also
    /// carry parameters with no value at all — `;ob` from an outbound
    /// registration, `;lr`, `;isfocus` — and `;ob` in particular is what pjsip
    /// and Asterisk send by default.
    ///
    /// The scan used `?` on `split_once('=')`, so the FIRST valueless parameter
    /// returned `None` from the whole function and the `Expires` header fallback
    /// never ran. An unregister from such a phone read as no expiry at all.
    #[test]
    fn a_valueless_contact_parameter_does_not_hide_the_expiry() {
        // `;ob` before the value-bearing parameter: the parameter form.
        let m = msg(&register("Expires: 3600\n").replace(
            "Contact: <sip:a@10.0.0.1>",
            "Contact: <sip:a@10.0.0.1>;ob;expires=0",
        ));
        assert_eq!(
            crate::sip::registration_expiry(&m),
            Some(0),
            "`;ob` before `expires=0` hid the parameter"
        );

        // `;ob` with no expires parameter at all: the header must still be read.
        let m = msg(&register("Expires: 0\n")
            .replace("Contact: <sip:a@10.0.0.1>", "Contact: <sip:a@10.0.0.1>;ob"));
        assert_eq!(
            crate::sip::registration_expiry(&m),
            Some(0),
            "`;ob` on the Contact stopped the `Expires` header from being read, \
             so an unregister from a pjsip phone looks like no expiry at all"
        );
    }

    /// Both spellings of the interval work, and the parameter wins.
    ///
    /// RFC 3261 §10.2.1.1 allows either, and the per-binding parameter takes
    /// precedence over the header default. Written out because "both must be
    /// supported" is the requirement, and one of the two was unreachable behind
    /// any valueless parameter.
    #[test]
    fn both_spellings_of_the_registration_interval_are_read() {
        // Header only.
        let m = msg(&register("Expires: 600\n"));
        assert_eq!(
            crate::sip::registration_expiry(&m),
            Some(600),
            "the Expires header"
        );

        // Parameter only.
        let m = msg(&register("").replace(
            "Contact: <sip:a@10.0.0.1>",
            "Contact: <sip:a@10.0.0.1>;expires=600",
        ));
        assert_eq!(
            crate::sip::registration_expiry(&m),
            Some(600),
            "the Contact parameter"
        );

        // Both, disagreeing: the parameter is the per-binding value and wins.
        let m = msg(&register("Expires: 3600\n").replace(
            "Contact: <sip:a@10.0.0.1>",
            "Contact: <sip:a@10.0.0.1>;expires=0",
        ));
        assert_eq!(
            crate::sip::registration_expiry(&m),
            Some(0),
            "the Contact parameter must win over the header, or an unregister \
             that carries a stale refresh interval in the header reads as a \
             refresh"
        );

        // Neither: nothing to report, rather than a default invented here.
        let m = msg(&register(""));
        assert_eq!(
            crate::sip::registration_expiry(&m),
            None,
            "no interval stated anywhere"
        );
    }

    /// The parameter scan tolerates the shapes real Contacts carry.
    ///
    /// Case, surrounding whitespace, quoting, and a valueless parameter AFTER
    /// the one that matters. Each is a way the scan could stop early and fall
    /// back to a header that may not be there.
    #[test]
    fn the_expiry_parameter_scan_tolerates_real_contact_shapes() {
        for (contact, want, why) in [
            (
                "<sip:a@10.0.0.1>;EXPIRES=0",
                Some(0),
                "parameter names are case-insensitive",
            ),
            (
                "<sip:a@10.0.0.1>; expires=0",
                Some(0),
                "space after the semicolon",
            ),
            ("<sip:a@10.0.0.1>;expires=\"0\"", Some(0), "a quoted value"),
            (
                "<sip:a@10.0.0.1>;expires=0;ob",
                Some(0),
                "a valueless parameter after it",
            ),
            (
                "<sip:a@10.0.0.1>;ob;lr;expires=0",
                Some(0),
                "two valueless parameters before it",
            ),
            (
                "<sip:a@10.0.0.1>;ob",
                None,
                "no interval at all once the header is absent",
            ),
        ] {
            let m =
                msg(&register("")
                    .replace("Contact: <sip:a@10.0.0.1>", &format!("Contact: {contact}")));
            assert_eq!(
                crate::sip::registration_expiry(&m),
                want,
                "{why}: {contact}"
            );
        }
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
            kind: AbandonedKind::Canceled,
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

    // -- detection 8, and what it does to detection 3 ---------------------

    /// One ICMP error against this dialog, with the given type/code.
    fn icmp_evidence(
        icmp_type: u8,
        icmp_code: u8,
        description: &'static str,
        errors: u64,
    ) -> crate::capture::parse::DialogIcmpEvidence {
        crate::capture::parse::DialogIcmpEvidence {
            errors,
            samples: vec![crate::capture::parse::IcmpEvidence {
                timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0)
                    .expect("valid fixture timestamp"),
                unreachable_addr: DST,
                unreachable_port: Some(5060),
                reported_by: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
                icmp_type,
                icmp_code,
                description,
                call_id: Some("c1@example.com".to_string()),
                method: Some("INVITE".to_string()),
                cseq: Some("1 INVITE".to_string()),
                truncated: true,
                quoted_bytes: 60,
            }],
        }
    }

    /// Three INVITEs into silence, and a router that said why.
    fn storm_with(icmp: &crate::capture::parse::DialogIcmpEvidence) -> SignalingDiagnosis {
        let msgs: Vec<SipMessage> = [0i64, 1, 3]
            .iter()
            .map(|s| msg_at(&invite("z9hG4bK1", 1), *s))
            .collect();
        diagnose_signaling_with_evidence(&msgs, &SignalingThresholds::default(), icmp)
    }

    /// The ICMP fact annotates the retransmission finding; it does not delete
    /// it. The count and span are the measurement of how hard the sender tried
    /// and are lost by suppression, so both findings survive — but the
    /// retransmission hint stops offering an inference the ICMP error has
    /// already settled.
    #[test]
    fn icmp_annotates_the_retransmission_finding_rather_than_replacing_it() {
        let d = storm_with(&icmp_evidence(3, 1, "host unreachable", 4));

        let r = d
            .retransmissions
            .as_ref()
            .expect("the storm is still reported: the count is the measurement");
        assert_eq!(r.count, 3, "suppression would have lost this");
        assert_eq!(
            r.icmp_cause.as_deref(),
            Some("host unreachable"),
            "the finding must carry the network's own words, not only the prose hint"
        );

        let hint = d
            .hints
            .iter()
            .find(|h| h.starts_with("No response to "))
            .expect("the retransmission hint is still rendered");
        assert!(
            !hint.contains("a one-way path or an unreachable peer"),
            "the guess must not stand beside the fact that replaced it: {hint}"
        );
        assert!(
            hint.contains("host unreachable"),
            "the annotation must name what ICMP said: {hint}"
        );
        assert!(
            hint.contains("3 transmissions"),
            "annotating must not cost the count: {hint}"
        );
    }

    /// With no ICMP evidence the retransmission hint is exactly what it always
    /// was — the inference is honest when nothing better is available.
    #[test]
    fn without_icmp_the_retransmission_hint_still_infers() {
        let d = storm_with(&Default::default());
        let r = d.retransmissions.as_ref().expect("storm detected");
        assert_eq!(r.icmp_cause, None);
        let hint = d
            .hints
            .iter()
            .find(|h| h.starts_with("No response to "))
            .expect("hint rendered");
        assert!(
            hint.contains("a one-way path or an unreachable peer"),
            "with nothing better, the inference is the honest answer: {hint}"
        );
    }

    /// "Administratively prohibited" is a filter, not a dead host, and the two
    /// send an operator to different devices. The finding must not tell them
    /// the peer is down when a firewall rejected the packet.
    #[test]
    fn administratively_prohibited_names_a_filter_not_a_dead_peer() {
        let d = storm_with(&icmp_evidence(
            3,
            13,
            "communication administratively prohibited",
            2,
        ));
        let hint = d
            .hints
            .iter()
            .find(|h| h.starts_with("ICMP "))
            .expect("the ICMP hint is rendered");
        assert!(
            hint.contains("filtering") || hint.contains("firewall"),
            "a prohibition is a policy device's decision, and that is the fix: {hint}"
        );
        assert!(
            !hint.contains("not reachable on that port"),
            "a filter says nothing about whether the port is open: {hint}"
        );
    }

    /// A port-unreachable is the opposite case: the host answered, so the
    /// service is the fault and the network is not.
    #[test]
    fn port_unreachable_names_the_service_not_the_network() {
        let d = storm_with(&icmp_evidence(3, 3, "port unreachable", 1));
        let hint = d
            .hints
            .iter()
            .find(|h| h.starts_with("ICMP "))
            .expect("the ICMP hint is rendered");
        assert!(
            hint.contains("nothing was listening"),
            "port-unreachable means the host is up and the port is not: {hint}"
        );
    }

    /// A host-unreachable is a routing or power question, not a port one.
    #[test]
    fn host_unreachable_does_not_claim_anything_about_a_port() {
        let d = storm_with(&icmp_evidence(3, 1, "host unreachable", 1));
        let hint = d
            .hints
            .iter()
            .find(|h| h.starts_with("ICMP "))
            .expect("the ICMP hint is rendered");
        assert!(
            !hint.contains("nothing was listening"),
            "nothing reached the host, so nothing is known about its ports: {hint}"
        );
        assert!(
            hint.contains("route") && hint.contains("powered off"),
            "the fix is routing, addressing or the host itself: {hint}"
        );
    }

    // -- detection 9: the two witnesses disagree --------------------------
    //
    // SRC2. HEP reports what the proxy BELIEVES it did; the wire reports what
    // actually left the box. SRC1 put both sources in one process and stage 2
    // tagged every fact with the source that produced it — and then nothing
    // compared them, so the disagreement that makes two witnesses worth
    // having was the one thing sipnab could not say.

    /// A message stamped with the capture source that delivered it, which is
    /// the only input detection 9 has that the other eight do not.
    fn from_source(raw: &str, origin: crate::capture::parse::InputOrigin) -> SipMessage {
        let mut m = msg(raw);
        m.input_origin = Some(origin);
        m
    }

    /// Parse CRLF-exact fixture text and stamp its source.
    ///
    /// [`msg`] rewrites every `\n` to `\r\n`, which is what makes the
    /// header-only fixtures readable — but an SDP body has to be written with
    /// real line endings for `Content-Length` to be the length the parser
    /// measures, and rewriting those would double every CR.
    fn msg_crlf(raw: &str, origin: crate::capture::parse::InputOrigin) -> SipMessage {
        let ts =
            chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid fixture timestamp");
        let mut m = parse_sip(
            raw.as_bytes(),
            ts,
            SRC,
            DST,
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("fixture parses");
        m.input_origin = Some(origin);
        m
    }

    /// An INVITE whose SDP advertises `ip:port` — the fact the two witnesses
    /// are made to disagree about, because a rewritten media address is the
    /// disagreement an operator can act on.
    fn invite_offering(branch: &str, cseq: u32, ip: &str, port: u16) -> String {
        let sdp = format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 {ip}\r\n\
             s=-\r\n\
             c=IN IP4 {ip}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n"
        );
        format!(
            "INVITE sip:b@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch={branch}\r\n\
             From: <sip:a@example.com>;tag=1\r\n\
             To: <sip:b@example.com>\r\n\
             Call-ID: c1@example.com\r\n\
             CSeq: {cseq} INVITE\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {len}\r\n\
             \r\n\
             {sdp}",
            len = sdp.len()
        )
    }

    /// **Mirror-only.** A message the proxy mirrored and the wire never
    /// carried is a proxy that believes it sent something it did not.
    #[test]
    fn a_message_only_the_mirror_reported_is_named_as_mirror_only() {
        use crate::capture::parse::InputOrigin;
        let d = diagnose_signaling(&[
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Hep),
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Wire),
            // The proxy says it answered. Nothing left the box.
            from_source(&response(200, "OK", ""), InputOrigin::Hep),
        ]);
        let s = d
            .source_disagreement
            .expect("a mirrored 200 the wire never carried is the finding");
        assert_eq!(
            s.agreed, 1,
            "the INVITE arrived on both witnesses and must pair"
        );
        assert_eq!(s.mirror_only.len(), 1, "one message, not the whole call");
        assert_eq!(s.mirror_only[0].index, 2, "the mirrored 200 OK");
        assert!(
            s.mirror_only[0].summary.contains("200"),
            "a report pasted into a ticket has no message list to join against: {:?}",
            s.mirror_only[0].summary
        );
        assert!(
            s.wire_only.is_empty(),
            "the wire carried nothing the mirror missed"
        );
        assert_eq!(
            s.evidence,
            vec![2],
            "the report surfaces render evidence with the machinery the other \
             eight detections use; an empty one renders nothing"
        );
    }

    /// **Wire-only.** A message on the wire the mirror never reported is
    /// tracing that is lying to its operator: the box did something its own
    /// trace does not admit to.
    #[test]
    fn a_message_only_the_wire_carried_is_named_as_wire_only() {
        use crate::capture::parse::InputOrigin;
        let d = diagnose_signaling(&[
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Hep),
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Wire),
            from_source(&response(486, "Busy Here", ""), InputOrigin::Wire),
        ]);
        let s = d
            .source_disagreement
            .expect("a 486 on the wire the mirror never reported is the finding");
        assert_eq!(s.wire_only.len(), 1);
        assert_eq!(s.wire_only[0].index, 2);
        assert!(
            s.wire_only[0].summary.contains("486"),
            "got {:?}",
            s.wire_only[0].summary
        );
        assert!(s.mirror_only.is_empty());
    }

    /// **Differing in SDP.** The same message on both witnesses advertising
    /// different media endpoints is a rewrite — sometimes the SBC doing its
    /// job, sometimes the bug. Both addresses are reported, because which of
    /// those it is cannot be decided here.
    #[test]
    fn matched_messages_whose_sdp_differs_report_both_addresses() {
        use crate::capture::parse::InputOrigin;
        let d = diagnose_signaling(&[
            msg_crlf(
                &invite_offering("z9hG4bK1", 1, "198.51.100.7", 20000),
                InputOrigin::Hep,
            ),
            msg_crlf(
                &invite_offering("z9hG4bK1", 1, "203.0.113.9", 30000),
                InputOrigin::Wire,
            ),
        ]);
        let s = d
            .source_disagreement
            .expect("two accounts of one message naming two media sockets");
        assert_eq!(
            s.agreed, 1,
            "they are the same message and must pair — a rewrite is not a gap"
        );
        assert_eq!(s.sdp_differs.len(), 1);
        assert_eq!(s.sdp_differs[0].mirror, vec!["audio 198.51.100.7:20000"]);
        assert_eq!(s.sdp_differs[0].wire, vec!["audio 203.0.113.9:30000"]);
        assert!(
            s.mirror_only.is_empty() && s.wire_only.is_empty(),
            "neither copy is missing; they disagree about content"
        );
    }

    /// **Agreement is not a finding.** Two witnesses that say the same thing
    /// are the healthy case, and a diagnosis object on every clean call in a
    /// composite run is how a finding becomes noise.
    #[test]
    fn two_witnesses_that_agree_on_every_message_report_nothing() {
        use crate::capture::parse::InputOrigin;
        let d = diagnose_signaling(&[
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Hep),
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Wire),
            from_source(&response(200, "OK", ""), InputOrigin::Hep),
            from_source(&response(200, "OK", ""), InputOrigin::Wire),
        ]);
        assert!(
            d.source_disagreement.is_none(),
            "the two accounts match; there is nothing to report"
        );
        assert!(d.is_empty(), "and the whole diagnosis stays clean");
    }

    /// **A single-source run reports nothing new.** One witness has no second
    /// account to be checked against, so every message would be "only this
    /// source" — the whole call, reported as a finding, for every call.
    #[test]
    fn a_single_source_run_reports_no_source_disagreement() {
        use crate::capture::parse::InputOrigin;
        for origin in [InputOrigin::Wire, InputOrigin::Hep, InputOrigin::Uprobe] {
            let d = diagnose_signaling(&[
                from_source(&invite("z9hG4bK1", 1), origin),
                from_source(&response(486, "Busy Here", ""), origin),
            ]);
            assert!(
                d.source_disagreement.is_none(),
                "{origin}: one witness cannot disagree with itself"
            );
        }
    }

    /// **An absent origin is "nobody said", never "the same source".**
    ///
    /// The half that can rot is the mixed one. A dialog with no origins at all
    /// stays silent under any defaulting rule, because every message would
    /// default to the SAME witness; it is a message with no origin standing
    /// beside one that has that catches `unwrap_or_default()`, which would
    /// read a hand-built message as something seen on a wire.
    #[test]
    fn messages_with_no_recorded_origin_report_nothing() {
        let d = diagnose_signaling(&[msg(&invite("z9hG4bK1", 1)), msg(&response(200, "OK", ""))]);
        assert!(
            d.source_disagreement.is_none(),
            "no origins, nothing to compare"
        );
        assert!(d.is_empty());

        let mixed = diagnose_signaling(&[
            from_source(
                &invite("z9hG4bK1", 1),
                crate::capture::parse::InputOrigin::Hep,
            ),
            msg(&response(486, "Busy Here", "")),
        ]);
        assert!(
            mixed.source_disagreement.is_none(),
            "a message no source claimed is not evidence that the OTHER source \
             carried it"
        );
    }

    /// **The trap SRC2 names.** The HEP mirror is usually FIRST — the proxy
    /// mirrors as it processes, while the wire copy takes a network hop — so
    /// any rule shaped "first one wins" would quietly make the proxy's account
    /// the truth that the wire capture exists to check.
    ///
    /// Both halves asserted, because a comparison can go wrong in two
    /// directions: the paired copies must report the same per-source values
    /// whichever arrived first, and a gap must stay on the side it belongs to.
    #[test]
    fn the_mirror_arriving_first_does_not_make_it_the_reference() {
        use crate::capture::parse::InputOrigin;
        let mirror = msg_crlf(
            &invite_offering("z9hG4bK1", 1, "198.51.100.7", 20000),
            InputOrigin::Hep,
        );
        let wire = msg_crlf(
            &invite_offering("z9hG4bK1", 1, "203.0.113.9", 30000),
            InputOrigin::Wire,
        );

        let first = diagnose_signaling(&[mirror.clone(), wire.clone()])
            .source_disagreement
            .expect("mirror first");
        let second = diagnose_signaling(&[wire, mirror])
            .source_disagreement
            .expect("wire first");

        assert_eq!(
            first.sdp_differs[0].mirror, second.sdp_differs[0].mirror,
            "the mirror's endpoints are the mirror's whichever copy arrived first"
        );
        assert_eq!(
            first.sdp_differs[0].wire, second.sdp_differs[0].wire,
            "and the wire's are the wire's"
        );
        assert_eq!(
            first.sdp_differs[0].mirror,
            vec!["audio 198.51.100.7:20000"]
        );
        assert_eq!(first.sdp_differs[0].wire, vec!["audio 203.0.113.9:30000"]);

        // The second direction: a message only the wire carried, with the
        // mirror's copies placed before it and after it. An early mirror must
        // not absorb it into a match, and a late mirror must not turn it into
        // a mirror-only gap.
        let inv_h = from_source(&invite("z9hG4bK1", 1), InputOrigin::Hep);
        let inv_w = from_source(&invite("z9hG4bK1", 1), InputOrigin::Wire);
        let busy_w = from_source(&response(486, "Busy Here", ""), InputOrigin::Wire);
        for (label, ladder) in [
            (
                "mirror first",
                vec![inv_h.clone(), inv_w.clone(), busy_w.clone()],
            ),
            ("mirror last", vec![busy_w, inv_w, inv_h]),
        ] {
            let s = diagnose_signaling(&ladder)
                .source_disagreement
                .unwrap_or_else(|| panic!("{label}: the 486 is on one witness only"));
            assert_eq!(s.wire_only.len(), 1, "{label}: the wire carried it");
            assert!(
                s.mirror_only.is_empty(),
                "{label}: the mirror is silent, not surplus"
            );
        }
    }

    /// **Only the pair sipnab can actually produce is compared.** A uprobe
    /// source never composes with another today — `-d` beats `--uprobe-tls`
    /// and `--uprobe-tls` beats `-L`, both with a warning — so pairing it
    /// against the wire would be untested code answering a question no run
    /// can ask.
    #[test]
    fn a_uprobe_source_is_not_compared_against_the_wire() {
        use crate::capture::parse::InputOrigin;
        let d = diagnose_signaling(&[
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Uprobe),
            from_source(&response(486, "Busy Here", ""), InputOrigin::Wire),
        ]);
        assert!(d.source_disagreement.is_none());
    }

    /// **Copies pair by count.** Three mirrored transmissions against two on
    /// the wire is ONE message the wire never carried, not three: the two that
    /// did arrive are matches, and reporting them as gaps would inflate every
    /// retransmitting call into a disagreement.
    #[test]
    fn a_retransmission_the_wire_missed_is_one_gap_not_three() {
        use crate::capture::parse::InputOrigin;
        let d = diagnose_signaling(&[
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Hep),
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Hep),
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Hep),
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Wire),
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Wire),
        ]);
        let s = d
            .source_disagreement
            .expect("three mirrored copies against two on the wire");
        assert_eq!(s.agreed, 2, "two transmissions reached both witnesses");
        assert_eq!(s.mirror_only.len(), 1, "one surplus copy, not three");
    }

    /// **A body one witness dropped is a disagreement, not a blank.** The two
    /// copies are the same message, so they pair; one carried SDP and the
    /// other did not, which is exactly the case a comparison written as "diff
    /// the endpoints when both have them" would render as agreement.
    #[test]
    fn an_sdp_only_one_witness_carried_is_reported_as_a_difference() {
        use crate::capture::parse::InputOrigin;
        let d = diagnose_signaling(&[
            msg_crlf(
                &invite_offering("z9hG4bK1", 1, "198.51.100.7", 20000),
                InputOrigin::Hep,
            ),
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Wire),
        ]);
        let s = d
            .source_disagreement
            .expect("one copy offered media and the other offered none");
        assert_eq!(s.agreed, 1, "same message, so it pairs");
        assert_eq!(s.sdp_differs[0].mirror, vec!["audio 198.51.100.7:20000"]);
        assert!(
            s.sdp_differs[0].wire.is_empty(),
            "the wire's copy carried no SDP at all: {:?}",
            s.sdp_differs[0].wire
        );
        let hint = d
            .hints
            .iter()
            .find(|h| h.starts_with("Capture sources disagree"))
            .expect("rendered");
        assert!(
            hint.contains("no SDP on the wire"),
            "an empty list must render as a statement, not as a blank: {hint}"
        );
    }

    /// **The hint stops naming messages; the finding does not.** A hint is one
    /// line in a TUI row, a ticket and an MCP payload. A call whose mirror ran
    /// fifty messages ahead of its wire would otherwise render fifty summaries
    /// into all three, and the reader who wants every one has the structured
    /// finding.
    #[test]
    fn the_hint_caps_the_messages_it_names_and_says_how_many_it_cut() {
        use crate::capture::parse::InputOrigin;
        let mut ladder = vec![
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Hep),
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Wire),
        ];
        for code in [180u16, 181, 182, 183, 199] {
            ladder.push(from_source(
                &response(code, "Ringing", ""),
                InputOrigin::Hep,
            ));
        }
        let d = diagnose_signaling(&ladder);
        let s = d.source_disagreement.expect("five mirrored-only responses");
        assert_eq!(s.mirror_only.len(), 5, "the finding carries all of them");
        let hint = d
            .hints
            .iter()
            .find(|h| h.starts_with("Capture sources disagree"))
            .expect("rendered");
        assert!(
            hint.contains("and 2 more"),
            "the hint names three and counts the rest: {hint}"
        );
        assert!(
            !hint.contains("199"),
            "the fifth is past the cap and must not be named: {hint}"
        );
    }

    /// **`is_empty` counts it.** A dialog whose only finding is that its two
    /// witnesses disagree must not render as clean — every surface omits the
    /// whole object on `is_empty`, so forgetting this one line would make the
    /// finding invisible on every door at once.
    #[test]
    fn a_source_disagreement_alone_makes_the_diagnosis_non_empty() {
        use crate::capture::parse::InputOrigin;
        let d = diagnose_signaling(&[
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Hep),
            from_source(&invite("z9hG4bK1", 1), InputOrigin::Wire),
            from_source(&response(200, "OK", ""), InputOrigin::Hep),
        ]);
        assert!(
            d.final_failure.is_none()
                && d.abandoned.is_none()
                && d.retransmissions.is_none()
                && d.ack_missing.is_none(),
            "nothing else fired, so is_empty can only be reading detection 9"
        );
        assert!(!d.is_empty(), "the disagreement is a finding");
    }

    /// **The hint names both witnesses and neither as the truth.** The plain
    /// line is what MCP's `diagnose_call` and the TUI render, and a sentence
    /// shaped "the wire is missing X" would hand the proxy's account the
    /// authority this whole detection exists to withhold.
    #[test]
    fn the_disagreement_hint_names_both_witnesses() {
        use crate::capture::parse::InputOrigin;
        let d = diagnose_signaling(&[
            msg_crlf(
                &invite_offering("z9hG4bK1", 1, "198.51.100.7", 20000),
                InputOrigin::Hep,
            ),
            msg_crlf(
                &invite_offering("z9hG4bK1", 1, "203.0.113.9", 30000),
                InputOrigin::Wire,
            ),
        ]);
        let hint = d
            .hints
            .iter()
            .find(|h| h.starts_with("Capture sources disagree"))
            .expect("one plain-language line per detection");
        assert!(
            hint.contains("198.51.100.7:20000") && hint.contains("203.0.113.9:30000"),
            "both accounts, side by side: {hint}"
        );
        assert!(
            hint.contains("mirror") && hint.contains("wire"),
            "each address attributed to the witness that gave it: {hint}"
        );
    }
}
