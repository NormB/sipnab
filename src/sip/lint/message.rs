// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rules that read one SIP message on its own.
//!
//! # The fold
//!
//! [`crate::sip::message::SipMessage::malformations`] already answered four of
//! these questions, in prose, for one consumer (`--json`). Reimplementing the
//! checks here would have left two detectors to keep in step. Instead the
//! predicates live here once — `missing_mandatory_headers`,
//! `cseq_unparseable`, `content_length_overrun`, `control_byte_headers` — and
//! both the rules and [`malformation_reasons`] read them. `--json` keeps its
//! exact wording, and `linter_and_malformations_agree` holds the two together.

use crate::sip::message::SipMessage;

use super::FindingSink;
use super::finding::{
    BRANCH_COOKIE, CONTENT_LENGTH_MISMATCH, CSEQ_MALFORMED, CSEQ_METHOD_MISMATCH,
    HEADER_CONTROL_BYTE, MANDATORY_HEADER_MISSING, MAX_FORWARDS_MISSING, MAX_FORWARDS_RANGE,
    URI_BRACKETS, URI_PARAM_DEMOTED,
};

/// The five header fields RFC 3261 §8.1.1 makes mandatory in every request and
/// §8.2.6.2 makes mandatory in every response.
///
/// `Max-Forwards` is the sixth in §8.1.1 and is absent from this list on
/// purpose: it applies to requests only, so it carries its own rule and its own
/// identifier, and an operator can suppress one without losing the other.
const MANDATORY_HEADERS: [&str; 5] = ["Call-ID", "CSeq", "From", "To", "Via"];

/// The header fields whose value RFC 3261 §20 says carries a URI.
const URI_HEADERS: [&str; 3] = ["Contact", "From", "To"];

/// The six parameter names RFC 3261 §19.1.1 defines as URI parameters.
///
/// Outside angle brackets each one silently becomes a header parameter, which
/// is a different message with the same bytes.
const URI_PARAMETERS: [&str; 6] = ["transport", "user", "method", "ttl", "maddr", "lr"];

/// The RFC 3261 §8.1.1.7 magic cookie every compliant branch begins with.
const BRANCH_MAGIC_COOKIE: &str = "z9hG4bK";

/// The `Max-Forwards` value RFC 3261 §20.22 recommends as the initial one.
const RECOMMENDED_MAX_FORWARDS: u32 = 70;

// ── Shared predicates ───────────────────────────────────────────────────
//
// Read by the rules below AND by `malformation_reasons`, so the two can never
// disagree about what a defect is.

/// The mandatory header fields this message does not carry, in the order of
/// [`MANDATORY_HEADERS`].
pub(crate) fn missing_mandatory_headers(msg: &SipMessage) -> Vec<&'static str> {
    MANDATORY_HEADERS
        .into_iter()
        .filter(|name| {
            if *name == "Via" {
                msg.via_headers().is_empty()
            } else {
                msg.header(name).is_none()
            }
        })
        .collect()
}

/// Whether a `CSeq` is present but cannot be read as `<number> <method>`.
pub(crate) fn cseq_unparseable(msg: &SipMessage) -> bool {
    msg.header("CSeq").is_some() && msg.cseq().is_none()
}

/// The declared `Content-Length` when it exceeds the body that arrived.
pub(crate) fn content_length_overrun(msg: &SipMessage) -> Option<usize> {
    let declared = msg
        .header("Content-Length")
        .and_then(|v| v.trim().parse::<usize>().ok())?;
    (declared > msg.body.len()).then_some(declared)
}

/// True when `s` holds a C0 control byte or DEL.
///
/// Tab is legal linear whitespace in a header value, so it is excluded. CR and
/// LF cannot survive line parsing, so finding one here is itself anomalous.
fn has_control_bytes(s: &str) -> bool {
    s.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

/// The names of every header whose name or value carries a control byte.
pub(crate) fn control_byte_headers(msg: &SipMessage) -> Vec<&str> {
    msg.headers
        .iter()
        .filter(|h| has_control_bytes(&h.name) || has_control_bytes(&h.value))
        .map(|h| h.name.as_ref())
        .collect()
}

/// The prose reasons `--json` has always reported under `malformed`.
///
/// Byte-for-byte what [`crate::sip::message::SipMessage::malformations`]
/// produced before the linter existed, now derived from the same predicates the
/// rules use. Structured callers want [`super::Linter::lint_message`]; this
/// exists so one long-standing output format does not change under its readers.
#[must_use]
pub fn malformation_reasons(msg: &SipMessage) -> Vec<String> {
    let mut reasons = Vec::new();

    for name in missing_mandatory_headers(msg) {
        reasons.push(format!("missing mandatory header: {name}"));
    }

    if cseq_unparseable(msg) {
        reasons.push("malformed CSeq header (not '<number> <method>')".to_string());
    }

    if let Some(declared) = content_length_overrun(msg) {
        reasons.push(format!(
            "content-length mismatch: declared {declared}, body {} bytes present",
            msg.body.len()
        ));
    }

    for name in control_byte_headers(msg) {
        reasons.push(format!("control character in header: {name}"));
    }

    reasons
}

// ── URI bracket analysis ────────────────────────────────────────────────

/// What a `Contact`, `From` or `To` value looks like once the brackets question
/// is settled.
#[derive(Debug, PartialEq, Eq)]
enum UriBrackets<'a> {
    /// The value carries a `<...>` name-addr. Nothing to report.
    Bracketed,
    /// The value carries a bare addr-spec, and this is the tail after it.
    Bare {
        /// The URI itself, up to the first semicolon.
        uri: &'a str,
        /// Semicolon-delimited parameters that landed on the header.
        params: Vec<&'a str>,
    },
}

/// Split a URI-bearing header value into its URI and its trailing parameters.
///
/// A value carrying `<` anywhere is a name-addr, and RFC 3261 puts every URI
/// parameter inside the brackets, so the question does not arise. Anything else
/// is an addr-spec whose semicolon-delimited tail the receiver reads as header
/// parameters.
fn split_uri_value(value: &str) -> UriBrackets<'_> {
    if value.contains('<') {
        return UriBrackets::Bracketed;
    }
    let mut parts = value.split(';');
    let uri = parts.next().unwrap_or("").trim();
    let params = parts.map(str::trim).filter(|p| !p.is_empty()).collect();
    UriBrackets::Bare { uri, params }
}

/// The parameter name from `name=value` or a bare flag such as `lr`.
fn param_name(param: &str) -> &str {
    param.split('=').next().unwrap_or(param).trim()
}

// ── The rules ───────────────────────────────────────────────────────────

/// Run every message-scoped rule against `msg`.
pub(crate) fn lint(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    mandatory_headers(msg, index, sink);
    cseq_shape(msg, index, sink);
    content_length(msg, index, sink);
    control_bytes(msg, index, sink);
    uri_brackets(msg, index, sink);
    max_forwards(msg, index, sink);
    branch_cookie(msg, index, sink);
    cseq_method(msg, index, sink);
}

/// RFC 3261 §8.1.1 — the five header fields no SIP message may omit.
fn mandatory_headers(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    if !sink.wants(&MANDATORY_HEADER_MISSING) {
        return;
    }
    for name in missing_mandatory_headers(msg) {
        let side = if msg.is_request {
            "A request without it cannot be routed, answered or matched to a transaction."
        } else {
            "RFC 3261 §8.2.6.2 makes the response copy it from the request, so its absence \
             means the responder built the message rather than answering one."
        };
        sink.push(
            &MANDATORY_HEADER_MISSING,
            index,
            format!("no {name} header field"),
            format!("{name} present"),
            format!(
                "{name} is one of the six fields §8.1.1 calls mandatory in all SIP \
                     requests. {side}"
            ),
        );
    }
}

/// RFC 3261 §20.16 — `CSeq` is a decimal number and a method.
fn cseq_shape(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    if !cseq_unparseable(msg) {
        return;
    }
    sink.push(
        &CSEQ_MALFORMED,
        index,
        "CSeq present but not readable as '<number> <method>'",
        "CSeq: <decimal sequence number> <method>",
        "Transaction matching keys on the CSeq number and method. A CSeq neither side can \
         parse leaves every retransmission looking like a new request.",
    );
}

/// RFC 3261 §20.14 — `Content-Length` counts the octets actually sent.
fn content_length(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    let Some(declared) = content_length_overrun(msg) else {
        return;
    };
    sink.push(
        &CONTENT_LENGTH_MISMATCH,
        index,
        format!("Content-Length {declared}, body {} octets", msg.body.len()),
        format!("Content-Length {}", msg.body.len()),
        "Over a stream transport the receiver frames the next message at the declared \
         offset, so an overstated length consumes the message that follows it. Over a \
         datagram transport the body is simply truncated.",
    );
}

/// RFC 3261 §25.1 — a header value holds text, not control bytes.
fn control_bytes(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    if !sink.wants(&HEADER_CONTROL_BYTE) {
        return;
    }
    for name in control_byte_headers(msg) {
        sink.push(
            &HEADER_CONTROL_BYTE,
            index,
            format!("control byte inside the {name} header field"),
            "printable text and linear whitespace only",
            "The §25.1 grammar admits no C0 control byte other than the tab of LWS. A \
             control byte here is a crafted message or a parser under test, not a phone.",
        );
    }
}

/// RFC 3261 §20 and §19.1.1 — angle brackets, and what happens without them.
fn uri_brackets(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    for name in URI_HEADERS {
        for value in msg.headers_by_name(name) {
            let UriBrackets::Bare { uri, params } = split_uri_value(value) else {
                continue;
            };

            // The decidable half: a comma or question mark in a bare URI breaks
            // the §20 MUST outright, with no appeal to intent.
            if let Some(ch) = uri.chars().find(|c| *c == ',' || *c == '?') {
                sink.push(
                    &URI_BRACKETS,
                    index,
                    format!("{name} carries a bare URI containing '{ch}'"),
                    format!("{name}: <uri>"),
                    "§20 requires angle brackets around a URI holding a comma, question \
                     mark or semicolon. Without them the receiver splits the value at that \
                     character and reads a different URI than the one sent.",
                );
            }

            // The intent half: a URI parameter that landed on the header.
            let demoted: Vec<&str> = params
                .iter()
                .map(|p| param_name(p))
                .filter(|n| URI_PARAMETERS.iter().any(|u| n.eq_ignore_ascii_case(u)))
                .collect();
            if !demoted.is_empty() {
                sink.push(
                    &URI_PARAM_DEMOTED,
                    index,
                    format!(
                        "{name} carries {} outside angle brackets",
                        demoted.join(", ")
                    ),
                    format!("{name}: <uri;{}>", demoted.join(";")),
                    format!(
                        "§19.1.1 defines {} as a URI parameter. Outside the brackets the \
                         receiver reads it as a header parameter and routes to the bare URI \
                         instead, which is how a call reaches the right host over the wrong \
                         transport or leaves the proxy loose-routing.",
                        demoted.join(", ")
                    ),
                );
            }
        }
    }
}

/// RFC 3261 §8.1.1.6 and §20.22 — `Max-Forwards` presence and range.
fn max_forwards(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    if !msg.is_request {
        return;
    }
    let Some(raw) = msg.header("Max-Forwards") else {
        sink.push(
            &MAX_FORWARDS_MISSING,
            index,
            "no Max-Forwards header field",
            "Max-Forwards: 70",
            "§8.1.1.6 makes a UAC insert one into every request it originates. Without it a \
             routing loop has nothing to stop it, and RFC 3261 §16.6 leaves each proxy to \
             invent its own starting value.",
        );
        return;
    };

    let Ok(value) = raw.trim().parse::<u32>() else {
        sink.push(
            &MAX_FORWARDS_RANGE,
            index,
            "Max-Forwards is not a decimal integer",
            "Max-Forwards: 0-255, recommended 70",
            "§20.22 makes the value an integer in the range 0-255. A value no proxy can \
             parse is a value no proxy can decrement.",
        );
        return;
    };

    if value == 0 {
        sink.push(
            &MAX_FORWARDS_RANGE,
            index,
            "Max-Forwards: 0",
            "Max-Forwards: 70",
            "A request arriving at zero is rejected 483 by the next proxy, so this one \
             reaches nothing beyond its first hop. From a UAC it is almost always a \
             counter decremented into the ground by a loop upstream.",
        );
    } else if value > RECOMMENDED_MAX_FORWARDS {
        sink.push(
            &MAX_FORWARDS_RANGE,
            index,
            format!("Max-Forwards: {value}"),
            format!("Max-Forwards: {RECOMMENDED_MAX_FORWARDS}"),
            "§20.22 recommends 70, chosen to cross any loop-free SIP network while \
             bounding the damage a loop can do. A higher value buys no reachability and \
             lets a loop consume proxy resources for longer.",
        );
    }
}

/// RFC 3261 §8.1.1.7 — the branch parameter's magic cookie.
///
/// Requests only. A response copies the request's `Via` verbatim (§8.2.6.2), so
/// reporting both would count one endpoint's defect once per message it
/// provoked.
fn branch_cookie(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    if !msg.is_request || msg.via_headers().is_empty() {
        return;
    }
    let branch = msg.top_via_branch();
    if branch.is_some_and(|b| b.starts_with(BRANCH_MAGIC_COOKIE)) {
        return;
    }
    let observed = match branch {
        Some(_) => "top Via branch without the z9hG4bK prefix".to_string(),
        None => "top Via carries no branch parameter".to_string(),
    };
    sink.push(
        &BRANCH_COOKIE,
        index,
        observed,
        "branch=z9hG4bK...",
        "§8.1.1.7 makes every compliant branch begin with z9hG4bK, so its absence \
         identifies a stack predating RFC 3261 in one field. Transaction matching then \
         falls back to the RFC 2543 rules, and CANCEL and ACK correlation stop being \
         reliable.",
    );
}

/// RFC 3261 §8.1.1.5 — the CSeq method matches the request method.
fn cseq_method(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    if !msg.is_request {
        return;
    }
    let (Some(method), Some((_, cseq_method))) = (msg.method.as_ref(), msg.cseq()) else {
        return;
    };
    // §20.16: "The method part of CSeq is case-sensitive." An extension method
    // parses as `SipMethod::Custom`, whose `as_str` returns the token from the
    // wire, so the comparison stays exact for methods the parser does not know.
    if cseq_method == method.as_str() {
        return;
    }
    sink.push(
        &CSEQ_METHOD_MISMATCH,
        index,
        format!(
            "request line says {}, CSeq says {cseq_method}",
            method.as_str()
        ),
        format!("CSeq: <number> {}", method.as_str()),
        "§8.1.1.5 makes the CSeq method match the request. A server matching on CSeq \
         files this request under the wrong transaction, so its response reaches the \
         wrong one and the real transaction times out.",
    );
}

/// Tests for the message-scoped rules.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::lint::{LintConfig, Linter};
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// Fixed capture timestamp for every test message.
    fn ts() -> DateTime<Utc> {
        DateTime::from_timestamp(1_718_452_800, 0).unwrap_or_default()
    }

    /// Parse `raw` into a message, from and to fixed RFC 5737 test addresses.
    fn msg(raw: &str) -> SipMessage {
        parse_sip(
            raw.as_bytes(),
            ts(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("test fixture must parse")
    }

    /// A well-formed INVITE with every header the rules look for.
    fn clean_invite() -> String {
        "INVITE sip:bob@example.net SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n\
         Max-Forwards: 70\r\n\
         To: <sip:bob@example.net>\r\n\
         From: <sip:alice@example.com>;tag=1928301774\r\n\
         Call-ID: a84b4c76e66710\r\n\
         CSeq: 314159 INVITE\r\n\
         Contact: <sip:alice@192.0.2.1>\r\n\
         Content-Length: 0\r\n\
         \r\n"
            .to_string()
    }

    /// Rule identifiers raised for `raw` by a default linter.
    fn ids(raw: &str) -> Vec<&'static str> {
        Linter::new(LintConfig::new())
            .lint_message(&msg(raw), 0)
            .into_iter()
            .map(|f| f.rule_id)
            .collect()
    }

    /// The clean fixture trips nothing.
    ///
    /// Without this, every rule below could be passing for the wrong reason.
    #[test]
    fn a_conformant_invite_raises_nothing() {
        assert_eq!(ids(&clean_invite()), Vec::<&str>::new());
    }

    /// A message with no `Call-ID` names the field that is missing.
    #[test]
    fn missing_mandatory_header_names_the_field() {
        let raw = clean_invite().replace("Call-ID: a84b4c76e66710\r\n", "");
        let findings = Linter::new(LintConfig::new()).lint_message(&msg(&raw), 0);
        let f = findings
            .iter()
            .find(|f| f.rule_id == MANDATORY_HEADER_MISSING.id)
            .expect("missing Call-ID must be reported");
        assert!(f.observed.contains("Call-ID"), "{}", f.observed);
        assert_eq!(f.citation(), "RFC 3261 §8.1.1");
    }

    /// An unparseable `CSeq` is a different finding from a missing one.
    #[test]
    fn unparseable_cseq_is_reported() {
        let raw = clean_invite().replace("CSeq: 314159 INVITE", "CSeq: nonsense");
        assert!(ids(&raw).contains(&CSEQ_MALFORMED.id));
    }

    /// A `Content-Length` larger than the body is reported with both numbers.
    #[test]
    fn content_length_overrun_reports_both_numbers() {
        let raw = clean_invite().replace("Content-Length: 0", "Content-Length: 400");
        let findings = Linter::new(LintConfig::new()).lint_message(&msg(&raw), 0);
        let f = findings
            .iter()
            .find(|f| f.rule_id == CONTENT_LENGTH_MISMATCH.id)
            .expect("overrun must be reported");
        assert!(f.observed.contains("400"), "{}", f.observed);
        assert!(f.observed.contains('0'), "{}", f.observed);
    }

    /// A control byte inside a header value is reported.
    ///
    /// The §25.1 grammar admits no C0 byte other than the tab of LWS, so this
    /// is a crafted message rather than a phone that got something wrong.
    #[test]
    fn control_byte_in_a_header_is_reported() {
        let raw = clean_invite().replace("Call-ID: a84b4c76e66710", "Call-ID: a84b\u{1}c76e66710");
        assert!(ids(&raw).contains(&HEADER_CONTROL_BYTE.id));
    }

    /// A `Contact` URI holding a question mark outside brackets breaks the
    /// §20 MUST and reports as one.
    #[test]
    fn bare_uri_with_question_mark_is_a_must_violation() {
        let raw = clean_invite().replace(
            "Contact: <sip:alice@192.0.2.1>",
            "Contact: sip:alice@192.0.2.1?Route=%3Csip:proxy%3E",
        );
        let findings = Linter::new(LintConfig::new()).lint_message(&msg(&raw), 0);
        let f = findings
            .iter()
            .find(|f| f.rule_id == URI_BRACKETS.id)
            .expect("bare URI with '?' must be reported");
        assert_eq!(f.basis, crate::sip::lint::Basis::Must);
        assert_eq!(f.citation(), "RFC 3261 §20");
    }

    /// A `transport` parameter outside the brackets reports as interop, not as
    /// a broken MUST — the bytes are legal SIP that means the wrong thing.
    #[test]
    fn demoted_uri_parameter_reports_as_interop() {
        let raw = clean_invite().replace(
            "Contact: <sip:alice@192.0.2.1>",
            "Contact: sip:alice@192.0.2.1;transport=tcp",
        );
        let findings = Linter::new(LintConfig::new()).lint_message(&msg(&raw), 0);
        let f = findings
            .iter()
            .find(|f| f.rule_id == URI_PARAM_DEMOTED.id)
            .expect("demoted transport parameter must be reported");
        assert_eq!(f.basis, crate::sip::lint::Basis::Interop);
        assert!(f.observed.contains("transport"), "{}", f.observed);
        assert!(!findings.iter().any(|f| f.rule_id == URI_BRACKETS.id));
    }

    /// A bare `From` with only a `tag` is legal and silent.
    ///
    /// `tag` is a header parameter, so `From: sip:a@b;tag=x` is correct SIP and
    /// appears in RFC 3261's own examples. A rule that fired here would fire on
    /// most of the traffic in existence.
    #[test]
    fn bare_from_with_only_a_tag_is_silent() {
        let raw = clean_invite().replace(
            "From: <sip:alice@example.com>;tag=1928301774",
            "From: sip:alice@example.com;tag=1928301774",
        );
        let raised = ids(&raw);
        assert!(!raised.contains(&URI_BRACKETS.id), "{raised:?}");
        assert!(!raised.contains(&URI_PARAM_DEMOTED.id), "{raised:?}");
    }

    /// A bracketed URI carrying every parameter inside is silent.
    #[test]
    fn bracketed_uri_parameters_are_silent() {
        let raw = clean_invite().replace(
            "Contact: <sip:alice@192.0.2.1>",
            "Contact: <sip:alice@192.0.2.1;transport=tcp;lr>",
        );
        assert!(!ids(&raw).contains(&URI_PARAM_DEMOTED.id));
    }

    /// A request with no `Max-Forwards` is reported.
    #[test]
    fn absent_max_forwards_is_reported() {
        let raw = clean_invite().replace("Max-Forwards: 70\r\n", "");
        assert!(ids(&raw).contains(&MAX_FORWARDS_MISSING.id));
    }

    /// A response with no `Max-Forwards` is not — the field is request-only.
    #[test]
    fn responses_are_exempt_from_max_forwards() {
        let raw = "SIP/2.0 200 OK\r\n\
                   Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n\
                   To: <sip:bob@example.net>;tag=a6c85cf\r\n\
                   From: <sip:alice@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710\r\n\
                   CSeq: 314159 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";
        assert!(!ids(raw).contains(&MAX_FORWARDS_MISSING.id));
    }

    /// Zero and anything above 70 both trip the range rule; 70 and 20 do not.
    #[test]
    fn max_forwards_range_fires_at_zero_and_above_seventy() {
        for (value, expected) in [("0", true), ("20", false), ("70", false), ("255", true)] {
            let raw = clean_invite().replace("Max-Forwards: 70", &format!("Max-Forwards: {value}"));
            assert_eq!(
                ids(&raw).contains(&MAX_FORWARDS_RANGE.id),
                expected,
                "Max-Forwards: {value}"
            );
        }
    }

    /// A branch without the magic cookie is reported, and a compliant one is
    /// not.
    #[test]
    fn branch_without_the_magic_cookie_is_reported() {
        let raw = clean_invite().replace("branch=z9hG4bK776asdhds", "branch=776asdhds");
        assert!(ids(&raw).contains(&BRANCH_COOKIE.id));
        assert!(!ids(&clean_invite()).contains(&BRANCH_COOKIE.id));
    }

    /// A `Via` with no branch at all is reported by the same rule, and says so.
    #[test]
    fn branch_absent_entirely_is_reported() {
        let raw = clean_invite().replace(";branch=z9hG4bK776asdhds", "");
        let findings = Linter::new(LintConfig::new()).lint_message(&msg(&raw), 0);
        let f = findings
            .iter()
            .find(|f| f.rule_id == BRANCH_COOKIE.id)
            .expect("absent branch must be reported");
        assert!(f.observed.contains("no branch"), "{}", f.observed);
    }

    /// A response carrying a pre-RFC3261 branch is silent — the originating
    /// request already carries the finding.
    #[test]
    fn responses_do_not_repeat_the_branch_finding() {
        let raw = "SIP/2.0 200 OK\r\n\
                   Via: SIP/2.0/UDP 192.0.2.1:5060;branch=776asdhds\r\n\
                   To: <sip:bob@example.net>;tag=a6c85cf\r\n\
                   From: <sip:alice@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710\r\n\
                   CSeq: 314159 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";
        assert!(!ids(raw).contains(&BRANCH_COOKIE.id));
    }

    /// A CSeq method disagreeing with the request line is reported, with both
    /// methods in the observation.
    #[test]
    fn cseq_method_mismatch_is_reported() {
        let raw = clean_invite().replace("CSeq: 314159 INVITE", "CSeq: 314159 OPTIONS");
        let findings = Linter::new(LintConfig::new()).lint_message(&msg(&raw), 0);
        let f = findings
            .iter()
            .find(|f| f.rule_id == CSEQ_METHOD_MISMATCH.id)
            .expect("mismatch must be reported");
        assert!(f.observed.contains("INVITE"), "{}", f.observed);
        assert!(f.observed.contains("OPTIONS"), "{}", f.observed);
    }

    /// An extension method the parser does not know is not a CSeq mismatch.
    ///
    /// `SipMethod::Other` renders as a placeholder rather than the token from
    /// the wire, so comparing against it would report every extension method
    /// in the capture.
    #[test]
    fn extension_methods_are_not_cseq_mismatches() {
        let raw = "SERVICE sip:bob@example.net SIP/2.0\r\n\
                   Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n\
                   Max-Forwards: 70\r\n\
                   To: <sip:bob@example.net>\r\n\
                   From: <sip:alice@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710\r\n\
                   CSeq: 1 SERVICE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";
        assert!(!ids(raw).contains(&CSEQ_METHOD_MISMATCH.id));
    }

    /// The linter and the long-standing `malformations` list agree on every
    /// defect, in both directions.
    ///
    /// This is the fold's guard rail: `--json` still reads
    /// `SipMessage::malformations`, and the day the two detectors disagree is
    /// the day one of them is wrong without anyone noticing.
    #[test]
    fn linter_and_malformations_agree() {
        let cases = [
            clean_invite(),
            clean_invite().replace("Call-ID: a84b4c76e66710\r\n", ""),
            clean_invite().replace("CSeq: 314159 INVITE", "CSeq: nonsense"),
            clean_invite().replace("Content-Length: 0", "Content-Length: 999"),
            clean_invite().replace("Via: SIP/2.0/UDP 192.0.2.1:5060", "Via: "),
        ];
        for raw in cases {
            let parsed = msg(&raw);
            let legacy = parsed.malformations();
            let linted: Vec<&str> = Linter::new(LintConfig::new())
                .lint_message(&parsed, 0)
                .into_iter()
                .map(|f| f.rule_id)
                .filter(|id| {
                    [
                        MANDATORY_HEADER_MISSING.id,
                        CSEQ_MALFORMED.id,
                        CONTENT_LENGTH_MISMATCH.id,
                        HEADER_CONTROL_BYTE.id,
                    ]
                    .contains(id)
                })
                .collect();
            assert_eq!(
                legacy.len(),
                linted.len(),
                "malformations {legacy:?} disagrees with linter {linted:?}"
            );
        }
    }

    /// `malformation_reasons` reproduces the exact strings `--json` publishes.
    ///
    /// The wording is a documented output format. Pinned here so a later
    /// rewording of a rule's explanation cannot silently change it.
    #[test]
    fn malformation_wording_is_unchanged() {
        let raw = clean_invite()
            .replace("Call-ID: a84b4c76e66710\r\n", "")
            .replace("Content-Length: 0", "Content-Length: 12");
        let reasons = malformation_reasons(&msg(&raw));
        assert!(
            reasons.contains(&"missing mandatory header: Call-ID".to_string()),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(
                &"content-length mismatch: declared 12, body 0 bytes present".to_string()
            ),
            "{reasons:?}"
        );
    }

    /// The bracket splitter recognises a name-addr wherever the brackets sit.
    #[test]
    fn bracket_split_recognises_name_addr() {
        assert_eq!(
            split_uri_value("\"Alice\" <sip:a@b>;tag=1"),
            UriBrackets::Bracketed
        );
        assert_eq!(split_uri_value("<sip:a@b>"), UriBrackets::Bracketed);
        assert_eq!(
            split_uri_value("sip:a@b;transport=tcp"),
            UriBrackets::Bare {
                uri: "sip:a@b",
                params: vec!["transport=tcp"],
            }
        );
    }

    /// A bare flag parameter yields its own name.
    #[test]
    fn param_name_handles_valueless_flags() {
        assert_eq!(param_name("lr"), "lr");
        assert_eq!(param_name("transport=tcp"), "transport");
    }
}
