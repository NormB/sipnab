// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structured findings: the rule catalogue, and the citation carried with
//! every result.
//!
//! # Why the citation is a field and not a sentence
//!
//! Before this module the tree held 447 RFC references and every one of them
//! sat inside a prose string — `"(RFC 3261 §21.4.16)"` spliced into an
//! explanation. Nothing could read them, so nothing could check them, and a
//! wrong section number reads exactly like a right one at review time. Writing
//! this module found one: the angle-bracket rule for a `Contact` URI carrying
//! parameters lives in the **preamble of Section 20**, not in §20.10, which is
//! where three separate sources place it.
//!
//! [`RuleMeta`] therefore carries `rfc: u32` and `section: &'static str` as
//! data. A rule cites its RFC once, in one place, and `rule_ids_are_wellformed`
//! holds the identifier to the citation.

use serde::{Deserialize, Serialize};

/// How much attention a finding deserves.
///
/// Orthogonal to [`Basis`], which says *why the finding is a finding*. The two
/// axes stay separate on purpose: an operator who cannot tell a broken MUST
/// from a vendor-compatibility hint stops believing both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Cosmetic or contextual. Never a reason to fail a build.
    Info,
    /// Worth reading before the next change to this leg.
    Notice,
    /// Degrades interoperability or observability, and will bite eventually.
    Warning,
    /// Breaks the call, the routing, or the specification outright.
    Error,
}

impl Severity {
    /// Lowercase name, for configuration files and CLI flags.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Parse a severity name, case-insensitively.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "notice" => Some(Self::Notice),
            "warning" | "warn" => Some(Self::Warning),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// What kind of claim a rule makes.
///
/// The whole point of the enum is the first variant standing alone. A tool that
/// reports "your Contact header breaks Cisco" beside "your ACK violates RFC 3261
/// §17.1.1.3" under one word teaches the reader to discount the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    /// The cited section says MUST or MUST NOT, and the message disobeys it.
    /// No judgement, no heuristic, no threshold.
    Must,
    /// The cited section says SHOULD or RECOMMENDED. Deviating stays legal.
    Should,
    /// No specification forbids this. Deployed equipment mishandles it anyway,
    /// and the citation names the text the vendors read differently.
    Interop,
    /// The declaration and the observed media disagree. The specification is
    /// cited for what was promised; the finding comes from the wire, and only a
    /// tool holding signalling and media together can raise it.
    Observation,
}

impl Basis {
    /// Lowercase name, for configuration files and CLI flags.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Must => "must",
            Self::Should => "should",
            Self::Interop => "interop",
            Self::Observation => "observation",
        }
    }
}

/// What a rule needs in order to run.
///
/// Drives ruleset selection, and stops a caller from believing a media rule ran
/// when no media was supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// One SIP message, read alone.
    Message,
    /// A dialog's messages read against each other.
    Dialog,
    /// A dialog read against the RTP and RTCP observed for it.
    Media,
}

impl Scope {
    /// Lowercase name, for configuration files and CLI flags.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Dialog => "dialog",
            Self::Media => "media",
        }
    }
}

/// Everything static about a rule: identifier, citation, severity, basis.
///
/// One value per rule, all of them in [`RULES`]. A rule that is not in that
/// table cannot fire, because the engine looks its metadata up there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleMeta {
    /// Stable identifier, e.g. `SIP-3261-20-URI-BRACKETS`. Suppressible in CI,
    /// quotable in a carrier ticket, and never reused for a different check.
    pub id: &'static str,
    /// One line naming the defect, for a table of contents or a summary line.
    pub title: &'static str,
    /// How loudly to report it.
    pub severity: Severity,
    /// Why it is a finding at all.
    pub basis: Basis,
    /// RFC number the rule reads from.
    pub rfc: u32,
    /// Section within that RFC, as printed in the document — `"20"`,
    /// `"8.1.1.7"`, `"6.1"`.
    pub section: &'static str,
}

impl RuleMeta {
    /// The citation as an operator writes it: `RFC 3261 §8.1.1.7`.
    #[must_use]
    pub fn citation(&self) -> String {
        format!("RFC {} §{}", self.rfc, self.section)
    }

    /// A link straight to the cited section on rfc-editor.org.
    #[must_use]
    pub fn url(&self) -> String {
        format!(
            "https://www.rfc-editor.org/rfc/rfc{}#section-{}",
            self.rfc, self.section
        )
    }

    /// The scope this rule needs, derived from its identifier prefix.
    ///
    /// `OBS-` rules read the wire, `SDP-` rules read an offer against an answer,
    /// and everything else reads one message.
    #[must_use]
    pub fn scope(&self) -> Scope {
        if self.id.starts_with("OBS-") {
            Scope::Media
        } else if self.id.starts_with("SDP-") || DIALOG_SCOPED.contains(&self.id) {
            Scope::Dialog
        } else {
            Scope::Message
        }
    }
}

/// `SIP-`-prefixed rules that still need the whole dialog rather than one
/// message. Kept as an explicit list because the prefix cannot express it and a
/// silent misclassification would run a rule with too little context.
const DIALOG_SCOPED: &[&str] = &[
    ACK_CSEQ_MISMATCH.id,
    TO_TAG_IN_INITIAL_REQUEST.id,
    PRACK_MISSING.id,
];

/// A single conformance defect, with the evidence and the citation attached.
///
/// `observed` and `expected` are separate fields rather than one sentence so a
/// reader — or a diff, or a ticket template — can put them side by side without
/// parsing prose back apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Which rule fired.
    pub rule_id: &'static str,
    /// How loudly to report it.
    pub severity: Severity,
    /// Why it is a finding.
    pub basis: Basis,
    /// RFC number the rule reads from.
    pub rfc: u32,
    /// Section within that RFC.
    pub section: &'static str,
    /// Index into the dialog's `messages` of the message the finding was drawn
    /// from. For a message linted alone, whatever index the caller supplied.
    pub message_index: usize,
    /// What the capture actually holds.
    pub observed: String,
    /// What the cited section calls for.
    pub expected: String,
    /// Why the difference matters, in the terms an operator acts on.
    pub explanation: String,
}

impl Finding {
    /// Build a finding from its rule's metadata and the evidence.
    pub(crate) fn new(
        meta: &RuleMeta,
        message_index: usize,
        observed: impl Into<String>,
        expected: impl Into<String>,
        explanation: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: meta.id,
            severity: meta.severity,
            basis: meta.basis,
            rfc: meta.rfc,
            section: meta.section,
            message_index,
            observed: observed.into(),
            expected: expected.into(),
            explanation: explanation.into(),
        }
    }

    /// The citation as an operator writes it: `RFC 3261 §8.1.1.7`.
    #[must_use]
    pub fn citation(&self) -> String {
        format!("RFC {} §{}", self.rfc, self.section)
    }
}

// ── The rule catalogue ──────────────────────────────────────────────────
//
// Every citation below was read out of the RFC text, not recalled. Where the
// section a rule is usually attributed to turned out to be the wrong one, the
// comment says so.

/// One of `Call-ID`, `CSeq`, `From`, `To` or `Via` absent.
pub const MANDATORY_HEADER_MISSING: RuleMeta = RuleMeta {
    id: "SIP-3261-8.1.1-MANDATORY-HEADER-MISSING",
    title: "mandatory header field absent",
    severity: Severity::Error,
    basis: Basis::Must,
    rfc: 3261,
    // "A valid SIP request formulated by a UAC MUST, at a minimum, contain the
    // following header fields: To, From, CSeq, Call-ID, Max-Forwards, and Via".
    // Max-Forwards has its own rule below because it is request-only, while the
    // other five are equally mandatory in a response (§8.2.6.2).
    section: "8.1.1",
};

/// `CSeq` present but not `<number> <method>`.
pub const CSEQ_MALFORMED: RuleMeta = RuleMeta {
    id: "SIP-3261-20.16-CSEQ-MALFORMED",
    title: "CSeq header field unparseable",
    severity: Severity::Error,
    basis: Basis::Must,
    rfc: 3261,
    // §20.16: "A CSeq header field in a request contains a single decimal
    // sequence number and the request method."
    section: "20.16",
};

/// `Content-Length` larger than the body that arrived.
pub const CONTENT_LENGTH_MISMATCH: RuleMeta = RuleMeta {
    id: "SIP-3261-20.14-CONTENT-LENGTH-MISMATCH",
    title: "Content-Length exceeds the body present",
    severity: Severity::Error,
    basis: Basis::Must,
    rfc: 3261,
    // §20.14: "The Content-Length header field indicates the size of the
    // message-body, in decimal number of octets".
    section: "20.14",
};

/// A control byte inside a header name or value.
pub const HEADER_CONTROL_BYTE: RuleMeta = RuleMeta {
    id: "SIP-3261-25.1-HEADER-CONTROL-BYTE",
    title: "control byte inside a header field",
    severity: Severity::Error,
    basis: Basis::Must,
    rfc: 3261,
    // §25.1 Basic Rules: a header value is TEXT-UTF8char / UTF8-CONT / LWS.
    // No C0 control byte other than the tab of LWS can appear.
    section: "25.1",
};

/// A `Contact`, `From` or `To` URI holding a comma or question mark outside
/// angle brackets.
pub const URI_BRACKETS: RuleMeta = RuleMeta {
    id: "SIP-3261-20-URI-BRACKETS",
    title: "URI with a comma or question mark not enclosed in angle brackets",
    severity: Severity::Error,
    basis: Basis::Must,
    rfc: 3261,
    // NOT §20.10. The sentence lives in the preamble of Section 20, above
    // §20.1: "The Contact, From, and To header fields contain a URI. If the URI
    // contains a comma, question mark or semicolon, the URI MUST be enclosed in
    // angle brackets (< and >)."
    section: "20",
};

/// A URI parameter demoted to a header parameter for want of angle brackets.
///
/// The semicolon half of the Section 20 sentence, split off because it is a
/// different kind of claim. `Contact: sip:a@b;transport=tcp` parses as perfectly
/// legal SIP — it simply means something the sender did not intend, since
/// `transport` is a URI parameter (§19.1.1) and outside the brackets it lands on
/// the header instead. Nothing on the wire breaks a MUST, so this rule stays out
/// of the `must` ruleset. What it breaks is routing, which is why it is the
/// defect most often found at the bottom of a "calls go to the wrong trunk"
/// ticket.
pub const URI_PARAM_DEMOTED: RuleMeta = RuleMeta {
    id: "SIP-3261-19.1.1-URI-PARAM-DEMOTED",
    title: "URI parameter outside the angle brackets becomes a header parameter",
    severity: Severity::Warning,
    basis: Basis::Interop,
    rfc: 3261,
    // §19.1.1 and the §25.1 ABNF name the six: transport, user, method, ttl,
    // maddr and lr. "If the URI is not enclosed in angle brackets, any
    // semicolon-delimited parameters are header-parameters, not URI
    // parameters." (§20 preamble)
    section: "19.1.1",
};

/// No `Max-Forwards` in a request.
pub const MAX_FORWARDS_MISSING: RuleMeta = RuleMeta {
    id: "SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING",
    title: "Max-Forwards absent from a request",
    severity: Severity::Warning,
    basis: Basis::Must,
    rfc: 3261,
    // §8.1.1.6: "A UAC MUST insert a Max-Forwards header field into each
    // request it originates with a value that SHOULD be 70."
    section: "8.1.1.6",
};

/// `Max-Forwards` at zero, or above the recommended 70.
pub const MAX_FORWARDS_RANGE: RuleMeta = RuleMeta {
    id: "SIP-3261-20.22-MAX-FORWARDS-RANGE",
    title: "Max-Forwards outside the recommended range",
    severity: Severity::Notice,
    basis: Basis::Should,
    rfc: 3261,
    // §20.22: "The Max-Forwards value is an integer in the range 0-255 ... The
    // recommended initial value is 70."
    section: "20.22",
};

/// A top `Via` branch that does not start with the RFC 3261 magic cookie.
pub const BRANCH_COOKIE: RuleMeta = RuleMeta {
    id: "SIP-3261-8.1.1.7-BRANCH-COOKIE",
    title: "Via branch without the z9hG4bK magic cookie",
    severity: Severity::Warning,
    basis: Basis::Must,
    rfc: 3261,
    // §8.1.1.7: "The branch ID inserted by an element compliant with this
    // specification MUST always begin with the characters 'z9hG4bK'."
    section: "8.1.1.7",
};

/// A `To` tag on a request that starts a dialog.
///
/// Dialog-scoped, and deliberately hard to trigger. One message cannot say
/// whether a request sits inside a dialog, so a message-scoped version of this
/// rule fires on every re-`INVITE` in every capture that starts mid-call. See
/// [`crate::sip::lint::dialog`] for the two shapes that do settle it.
pub const TO_TAG_IN_INITIAL_REQUEST: RuleMeta = RuleMeta {
    id: "SIP-3261-8.1.1.2-TO-TAG-IN-INITIAL-REQUEST",
    title: "To tag present on a dialog-forming request",
    severity: Severity::Warning,
    basis: Basis::Must,
    rfc: 3261,
    // §8.1.1.2: "A request outside of a dialog MUST NOT contain a To tag".
    section: "8.1.1.2",
};

/// A `CSeq` method that disagrees with the request line.
pub const CSEQ_METHOD_MISMATCH: RuleMeta = RuleMeta {
    id: "SIP-3261-8.1.1.5-CSEQ-METHOD-MISMATCH",
    title: "CSeq method disagrees with the request method",
    severity: Severity::Error,
    basis: Basis::Must,
    rfc: 3261,
    // §8.1.1.5: "It consists of a sequence number and a method. The method MUST
    // match that of the request."
    section: "8.1.1.5",
};

/// An `ACK` whose CSeq number does not match the `INVITE` it acknowledges.
pub const ACK_CSEQ_MISMATCH: RuleMeta = RuleMeta {
    id: "SIP-3261-17.1.1.3-ACK-CSEQ-MISMATCH",
    title: "ACK CSeq number does not match its INVITE",
    severity: Severity::Error,
    basis: Basis::Must,
    rfc: 3261,
    // §17.1.1.3: "The CSeq header field in the ACK MUST contain the same value
    // for the sequence number as was present in the original request, but the
    // method parameter MUST be equal to 'ACK'."
    section: "17.1.1.3",
};

/// A 2xx answer to `INVITE` carrying no `Contact`.
pub const CONTACT_MISSING_IN_2XX: RuleMeta = RuleMeta {
    id: "SIP-3261-12.1.1-CONTACT-MISSING-IN-2XX",
    title: "2xx to INVITE carries no Contact header field",
    severity: Severity::Error,
    basis: Basis::Must,
    rfc: 3261,
    // §12.1.1: "The UAS MUST add a Contact header field to the response."
    // Without it the caller has no remote target for the dialog, so the ACK
    // and every in-dialog request afterwards have nowhere to go.
    section: "12.1.1",
};

/// A reliable provisional response with no `RSeq`.
pub const RELIABLE_PROVISIONAL_WITHOUT_RSEQ: RuleMeta = RuleMeta {
    id: "SIP-3262-3-RELIABLE-PROVISIONAL-WITHOUT-RSEQ",
    title: "provisional requires 100rel and carries no RSeq",
    severity: Severity::Error,
    basis: Basis::Must,
    rfc: 3262,
    // §3: "In addition, it MUST contain a Require header field containing the
    // option tag 100rel, and MUST include an RSeq header field." A receiver
    // cannot acknowledge what it cannot number, so the PRACK never comes.
    section: "3",
};

/// A reliable provisional the dialog never acknowledged with `PRACK`.
pub const PRACK_MISSING: RuleMeta = RuleMeta {
    id: "SIP-3262-4-PRACK-MISSING",
    title: "reliable provisional never acknowledged by a PRACK",
    severity: Severity::Warning,
    basis: Basis::Must,
    rfc: 3262,
    // §4: "Assuming the response is to be transmitted reliably, the UAC MUST
    // create a new request with method PRACK." Dialog-scoped, and guarded: one
    // message cannot say whether a PRACK followed, and a capture that ends
    // mid-transaction has not shown that it did not.
    section: "4",
};

/// `Session-Expires` smaller than the `Min-SE` in the same request.
pub const SESSION_EXPIRES_BELOW_MIN_SE: RuleMeta = RuleMeta {
    id: "SIP-4028-7.1-SESSION-EXPIRES-BELOW-MIN-SE",
    title: "Session-Expires below the Min-SE carried beside it",
    severity: Severity::Error,
    basis: Basis::Must,
    rfc: 4028,
    // §7.1: "If a Min-SE header is included in the initial session refresh
    // request, the value of the Session-Expires MUST be greater than or equal
    // to the value in Min-SE." The two headers contradict each other inside one
    // message, so this needs no dialog context to settle.
    section: "7.1",
};

/// `Session-Expires` below the 90-second floor.
pub const SESSION_EXPIRES_TOO_SMALL: RuleMeta = RuleMeta {
    id: "SIP-4028-4-SESSION-EXPIRES-TOO-SMALL",
    title: "Session-Expires below the 90-second minimum",
    severity: Severity::Warning,
    basis: Basis::Must,
    rfc: 4028,
    // §4: "The absolute minimum for the Session-Expires header field is 90
    // seconds."
    section: "4",
};

/// `Min-SE` below the 90-second floor.
pub const MIN_SE_TOO_SMALL: RuleMeta = RuleMeta {
    id: "SIP-4028-5-MIN-SE-TOO-SMALL",
    title: "Min-SE below the 90-second minimum",
    severity: Severity::Warning,
    basis: Basis::Must,
    rfc: 4028,
    // §5: "When present in a request or response, its value MUST NOT be less
    // than 90 seconds."
    section: "5",
};

/// A 2xx answer to `INVITE` carrying `Session-Expires` with no `refresher`.
pub const REFRESHER_MISSING: RuleMeta = RuleMeta {
    id: "SIP-4028-9-REFRESHER-MISSING",
    title: "2xx to INVITE negotiates a session timer without naming the refresher",
    severity: Severity::Warning,
    basis: Basis::Must,
    rfc: 4028,
    // §9, UAS Behavior — NOT §8, which is Proxy Behavior. "The UAS MUST set the
    // value of the refresher parameter in the Session-Expires header field in
    // the 2xx response." Checked against the RFC's table of contents rather
    // than recalled: the numbering runs 7 UAC, 8 Proxy, 9 UAS, and getting it
    // one out would send a reader to the wrong party's rules.
    section: "9",
};

/// An answer sharing no media format with the offer it answers.
pub const ANSWER_NO_COMMON_FORMAT: RuleMeta = RuleMeta {
    id: "SDP-3264-6.1-ANSWER-NO-COMMON-FORMAT",
    title: "answer shares no media format with the offer",
    severity: Severity::Error,
    basis: Basis::Must,
    rfc: 3264,
    // §6.1: "For streams marked as sendrecv in the answer, the 'm=' line MUST
    // contain at least one codec the answerer is willing to both send and
    // receive, from amongst those listed in the offer."
    section: "6.1",
};

/// An answer listing a format the offer never carried.
///
/// Widely reported as illegal. It is not: §6.1 permits it in as many words. The
/// answerer simply cannot send with that format, so the listing misleads every
/// reader who takes it for a negotiated codec.
pub const ANSWER_EXTRA_FORMAT: RuleMeta = RuleMeta {
    id: "SDP-3264-6.1-ANSWER-EXTRA-FORMAT",
    title: "answer lists a format absent from the offer",
    severity: Severity::Info,
    basis: Basis::Interop,
    rfc: 3264,
    // §6.1: "The stream MAY indicate additional media formats, not listed in
    // the corresponding stream in the offer, that the answerer is willing to
    // send or receive (of course, it will not be able to send them at this
    // time, since it was not listed in the offer)."
    section: "6.1",
};

/// A direction attribute in an answer that the offer forbids.
pub const ANSWER_DIRECTION_ILLEGAL: RuleMeta = RuleMeta {
    id: "SDP-3264-6.1-ANSWER-DIRECTION-ILLEGAL",
    title: "answer direction contradicts the offer",
    severity: Severity::Error,
    basis: Basis::Must,
    rfc: 3264,
    // §6.1: "If a stream is offered as sendonly, the corresponding stream MUST
    // be marked as recvonly or inactive in the answer. If a media stream is
    // listed as recvonly in the offer, the answer MUST be marked as sendonly or
    // inactive in the answer. ... If an offered media stream is listed as
    // inactive, it MUST be marked as inactive in the answer."
    section: "6.1",
};

/// A hold signalled by setting the connection address to `0.0.0.0`.
pub const HOLD_CONNECTION_ZERO: RuleMeta = RuleMeta {
    id: "SDP-3264-8.4-HOLD-CONNECTION-ZERO",
    title: "hold signalled with c=0.0.0.0",
    severity: Severity::Warning,
    basis: Basis::Should,
    rfc: 3264,
    // §8.4: "RFC 2543 specified that placing a user on hold was accomplished by
    // setting the connection address to 0.0.0.0. Its usage for putting a call
    // on hold is no longer recommended, since it doesn't allow for RTCP to be
    // used with held streams, doesn't work with IPv6, and breaks with
    // connection oriented media."
    section: "8.4",
};

/// The wire carried a payload type that no offer or answer declared.
pub const PT_UNDECLARED: RuleMeta = RuleMeta {
    id: "OBS-3264-6.1-PT-UNDECLARED",
    title: "RTP payload type never declared in SDP",
    severity: Severity::Error,
    basis: Basis::Observation,
    rfc: 3264,
    // §6.1 binds what may be sent to what the offer listed: the answerer's
    // formats come "from amongst those listed in the offer", and "if a
    // particular codec was referenced with a specific payload type number in
    // the offer, that same payload type number SHOULD be used for that codec in
    // the answer".
    section: "6.1",
};

/// RTP arrived somewhere other than the port the `m=` line advertised.
pub const MEDIA_PORT_MISMATCH: RuleMeta = RuleMeta {
    id: "OBS-4566-5.14-MEDIA-PORT-MISMATCH",
    title: "RTP observed on a port the SDP never advertised",
    severity: Severity::Warning,
    basis: Basis::Observation,
    rfc: 4566,
    // §5.14: "<port> is the transport port to which the media stream is sent."
    section: "5.14",
};

/// A stream negotiated in both directions that only ever flowed in one.
pub const DIRECTION_UNMET: RuleMeta = RuleMeta {
    id: "OBS-3264-6.1-DIRECTION-UNMET",
    title: "sendrecv negotiated, media observed one way",
    severity: Severity::Warning,
    basis: Basis::Observation,
    rfc: 3264,
    // §6.1 fixes what each direction attribute promises; sendrecv promises
    // media in both directions between the two negotiated addresses.
    section: "6.1",
};

/// Packet spacing that contradicts the declared `a=ptime`.
pub const PTIME_MISMATCH: RuleMeta = RuleMeta {
    id: "OBS-4566-6-PTIME-MISMATCH",
    title: "observed packet spacing contradicts a=ptime",
    severity: Severity::Notice,
    basis: Basis::Observation,
    rfc: 4566,
    // §6, a=ptime: "This gives the length of time in milliseconds represented
    // by the media in a packet."
    section: "6",
};

/// RTCP multiplexing offered, never answered, and used anyway.
pub const RTCP_MUX_UNANSWERED: RuleMeta = RuleMeta {
    id: "OBS-5761-5.1.1-RTCP-MUX-UNANSWERED",
    title: "rtcp-mux offered, unanswered, and used regardless",
    severity: Severity::Error,
    basis: Basis::Observation,
    rfc: 5761,
    // §5.1.1: "If the answer does not contain an 'a=rtcp-mux' attribute, the
    // offerer MUST NOT multiplex RTP and RTCP packets on a single port."
    section: "5.1.1",
};

/// A payload whose size the negotiated codec cannot produce.
pub const FRAME_SIZE_IMPOSSIBLE: RuleMeta = RuleMeta {
    id: "OBS-3551-4.2-FRAME-SIZE-IMPOSSIBLE",
    title: "payload size impossible for the negotiated codec",
    severity: Severity::Warning,
    basis: Basis::Observation,
    rfc: 3551,
    // §4.2: "For packetized audio, the default packetization interval SHOULD
    // have a duration of 20 ms or one frame, whichever is longer". Together
    // with the codec's fixed octet rate that fixes the payload size, so a
    // payload the codec cannot produce at the observed rate contradicts the
    // negotiation rather than merely deviating from it.
    section: "4.2",
};

/// Every rule the engine knows about.
///
/// The engine iterates this table, so a rule missing from it is a rule that
/// does not exist. `rule_ids_are_wellformed` holds each entry to its citation.
pub const RULES: &[RuleMeta] = &[
    MANDATORY_HEADER_MISSING,
    CSEQ_MALFORMED,
    CONTENT_LENGTH_MISMATCH,
    HEADER_CONTROL_BYTE,
    URI_BRACKETS,
    URI_PARAM_DEMOTED,
    MAX_FORWARDS_MISSING,
    MAX_FORWARDS_RANGE,
    BRANCH_COOKIE,
    TO_TAG_IN_INITIAL_REQUEST,
    CSEQ_METHOD_MISMATCH,
    ACK_CSEQ_MISMATCH,
    CONTACT_MISSING_IN_2XX,
    RELIABLE_PROVISIONAL_WITHOUT_RSEQ,
    PRACK_MISSING,
    SESSION_EXPIRES_BELOW_MIN_SE,
    SESSION_EXPIRES_TOO_SMALL,
    MIN_SE_TOO_SMALL,
    REFRESHER_MISSING,
    ANSWER_NO_COMMON_FORMAT,
    ANSWER_EXTRA_FORMAT,
    ANSWER_DIRECTION_ILLEGAL,
    HOLD_CONNECTION_ZERO,
    PT_UNDECLARED,
    MEDIA_PORT_MISMATCH,
    DIRECTION_UNMET,
    PTIME_MISMATCH,
    RTCP_MUX_UNANSWERED,
    FRAME_SIZE_IMPOSSIBLE,
];

/// Look a rule up by identifier.
#[must_use]
pub fn rule_by_id(id: &str) -> Option<&'static RuleMeta> {
    RULES.iter().find(|r| r.id == id)
}

/// Tests for the rule catalogue and the finding type.
#[cfg(test)]
mod tests {
    use super::*;

    /// Every identifier follows `<FAMILY>-<RFC>-<SECTION>-<SLUG>`, and the RFC
    /// and section spliced into it are the same ones the metadata carries.
    ///
    /// The identifier is what a CI suppression file and a carrier ticket both
    /// quote, so an identifier that disagrees with its own citation sends the
    /// reader to the wrong paragraph. Deriving nothing and checking everything
    /// keeps both halves honest.
    #[test]
    fn rule_ids_are_wellformed() {
        for rule in RULES {
            let mut parts = rule.id.splitn(4, '-');
            let family = parts.next().unwrap_or_default();
            let rfc = parts.next().unwrap_or_default();
            let section = parts.next().unwrap_or_default();
            let slug = parts.next().unwrap_or_default();

            assert!(
                matches!(family, "SIP" | "SDP" | "OBS"),
                "{}: family must be SIP, SDP or OBS, got {family:?}",
                rule.id
            );
            assert_eq!(
                rfc,
                rule.rfc.to_string(),
                "{}: identifier names RFC {rfc}, metadata says {}",
                rule.id,
                rule.rfc
            );
            assert_eq!(
                section, rule.section,
                "{}: identifier names §{section}, metadata says §{}",
                rule.id, rule.section
            );
            assert!(!slug.is_empty(), "{}: identifier has no slug", rule.id);
            assert!(
                slug.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'),
                "{}: slug must be upper-case ASCII, got {slug:?}",
                rule.id
            );
        }
    }

    /// No two rules share an identifier.
    ///
    /// Two rules under one identifier make a suppression silently disable a
    /// check nobody meant to turn off.
    #[test]
    fn rule_ids_are_unique() {
        let mut seen: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), before, "duplicate rule identifier in RULES");
    }

    /// Every section number cited is a plausible RFC section: digits separated
    /// by dots, nothing else.
    ///
    /// Catches the `§20.10.` and `§ 20.10` shapes that break the generated URL
    /// without breaking anything a human notices.
    #[test]
    fn cited_sections_are_section_numbers() {
        for rule in RULES {
            assert!(
                !rule.section.is_empty()
                    && rule.section.chars().all(|c| c.is_ascii_digit() || c == '.')
                    && !rule.section.starts_with('.')
                    && !rule.section.ends_with('.'),
                "{}: §{:?} is not a section number",
                rule.id,
                rule.section
            );
        }
    }

    /// Observation rules are the ones that read the wire, and nothing else is.
    ///
    /// A media rule silently classified as message-scoped would run with no
    /// media and report nothing, which looks exactly like a clean capture.
    #[test]
    fn observation_rules_are_media_scoped() {
        for rule in RULES {
            let expected = if rule.id.starts_with("OBS-") {
                Scope::Media
            } else if rule.id.starts_with("SDP-") || DIALOG_SCOPED.contains(&rule.id) {
                Scope::Dialog
            } else {
                Scope::Message
            };
            assert_eq!(rule.scope(), expected, "{}", rule.id);
            if rule.basis == Basis::Observation {
                assert_eq!(
                    rule.scope(),
                    Scope::Media,
                    "{}: observation basis needs media scope",
                    rule.id
                );
            }
        }
    }

    /// The citation renders the way an operator writes it, and the URL points
    /// at the section rather than the document.
    #[test]
    fn citation_and_url_render() {
        assert_eq!(BRANCH_COOKIE.citation(), "RFC 3261 §8.1.1.7");
        assert_eq!(
            BRANCH_COOKIE.url(),
            "https://www.rfc-editor.org/rfc/rfc3261#section-8.1.1.7"
        );
    }

    /// The angle-bracket rule cites Section 20, not §20.10.
    ///
    /// Pinned deliberately. The sentence sits in the preamble of Section 20,
    /// above §20.1, and three separate sources place it in §20.10 — which is
    /// the Contact header field's own subsection and says nothing about
    /// brackets. Stringly-typed citations are how that survives review.
    #[test]
    fn bracket_rule_cites_the_section_20_preamble() {
        assert_eq!(URI_BRACKETS.rfc, 3261);
        assert_eq!(URI_BRACKETS.section, "20");
    }

    /// Severity names round-trip through their parser.
    #[test]
    fn severity_names_round_trip() {
        for s in [
            Severity::Info,
            Severity::Notice,
            Severity::Warning,
            Severity::Error,
        ] {
            assert_eq!(Severity::from_name(s.as_str()), Some(s));
        }
        assert_eq!(Severity::from_name("WARN"), Some(Severity::Warning));
        assert_eq!(Severity::from_name("catastrophe"), None);
    }

    /// Severity orders from quietest to loudest, which is what a
    /// minimum-severity filter compares against.
    #[test]
    fn severity_orders_upward() {
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Notice);
        assert!(Severity::Notice > Severity::Info);
    }

    /// Looking a rule up by identifier finds it, and an unknown one finds
    /// nothing.
    #[test]
    fn rules_are_findable_by_id() {
        assert_eq!(rule_by_id(BRANCH_COOKIE.id), Some(&BRANCH_COOKIE));
        assert_eq!(rule_by_id("SIP-9999-1-NOPE"), None);
    }

    /// A finding carries its rule's citation without the caller restating it.
    #[test]
    fn finding_inherits_the_citation() {
        let f = Finding::new(&BRANCH_COOKIE, 3, "branch=abc", "branch=z9hG4bK...", "why");
        assert_eq!(f.rule_id, BRANCH_COOKIE.id);
        assert_eq!(f.rfc, 3261);
        assert_eq!(f.section, "8.1.1.7");
        assert_eq!(f.citation(), "RFC 3261 §8.1.1.7");
        assert_eq!(f.message_index, 3);
    }
}
