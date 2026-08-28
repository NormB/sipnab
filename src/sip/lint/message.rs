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
use crate::sip::session_id::{SessionId, SessionIdDeviation, SessionIdHalf};

use super::FindingSink;
use super::finding::{
    BRANCH_COOKIE, CONTACT_MISSING_IN_2XX, CONTENT_LENGTH_MISMATCH, CSEQ_MALFORMED,
    CSEQ_METHOD_MISMATCH, HEADER_CONTROL_BYTE, MANDATORY_HEADER_MISSING, MAX_FORWARDS_MISSING,
    MAX_FORWARDS_RANGE, MIN_SE_TOO_SMALL, RECORD_ROUTE_NOT_LOOSE, REFRESHER_MISSING,
    RELIABLE_PROVISIONAL_WITHOUT_RSEQ, SESSION_EXPIRES_BELOW_MIN_SE, SESSION_EXPIRES_TOO_SMALL,
    SESSION_ID_LEGACY_FORM, SESSION_ID_MALFORMED, SESSION_ID_UPPERCASE, SINGULAR_HEADER_REPEATED,
    URI_BRACKETS, URI_PARAM_DEMOTED, VIA_BRANCH_DUPLICATE,
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

/// The header fields RFC 3261 defines with a single value, so a second row of
/// the same name breaks §7.3.1.
///
/// Every entry's ABNF in §25.1 is `header HCOLON <one value>` with no
/// `*(COMMA ...)` tail, which is the exact test §7.3.1 states. The list is
/// deliberately short of the full registry: a name whose grammar this comment
/// cannot vouch for is left out, because a false positive on a header an
/// operator has never thought about is how a linter loses its reader.
///
/// **The four authentication header fields are absent on purpose.** §7.3.1
/// names `WWW-Authenticate`, `Authorization`, `Proxy-Authenticate` and
/// `Proxy-Authorization` as its own exception: multiple rows "MAY be present in
/// a message", they simply may not be joined with commas. Listing them here
/// would report the RFC's own permitted form as a violation, and a `407` with
/// two challenges is ordinary traffic.
const SINGULAR_HEADERS: [&str; 17] = [
    "Call-ID",
    "Content-Disposition",
    "Content-Length",
    "Content-Type",
    "CSeq",
    "Date",
    "Expires",
    "From",
    "Max-Forwards",
    "MIME-Version",
    "Min-Expires",
    "Organization",
    "Priority",
    "Reply-To",
    "Server",
    "Subject",
    "To",
];

/// The loose-routing parameter RFC 3261 §19.1.1 defines and §16.6 item 4
/// requires in a `Record-Route` URI.
const LOOSE_ROUTE_PARAM: &str = "lr";

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
    session_timers(msg, index, sink);
    dialog_target(msg, index, sink);
    reliable_provisional(msg, index, sink);
    session_identifier(msg, index, sink);
    singular_headers(msg, index, sink);
    record_route_loose(msg, index, sink);
    via_branch_duplicates(msg, index, sink);
}

/// RFC 3261 §7.3.1 — a single-valued header field gets one row.
fn singular_headers(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    if !sink.wants(&SINGULAR_HEADER_REPEATED) {
        return;
    }
    for name in SINGULAR_HEADERS {
        let rows = msg.headers_by_name(name).len();
        if rows < 2 {
            continue;
        }
        sink.push(
            &SINGULAR_HEADER_REPEATED,
            index,
            format!("{rows} {name} header field rows"),
            format!("one {name} row"),
            format!(
                "§7.3.1 permits repeated rows only where the field-value is defined as a \
                 comma-separated list, and {name} is not. Which row a receiver honors is \
                 then an implementation choice: parsers that keep the first and parsers \
                 that keep the last both exist, so two elements reading these same bytes \
                 disagree about the message — which is the shape every header-smuggling \
                 attack on a SIP border takes."
            ),
        );
    }
}

/// The URIs inside one `Record-Route` or `Route` header field row.
///
/// A row is a comma-separated list, and each entry is a `name-addr` whose URI
/// sits inside angle brackets. Extracting the bracketed spans rather than
/// splitting on commas is what keeps a display name holding a comma from
/// splitting one route into two: `"Smith, John" <sip:p1.example.com;lr>` is one
/// entry, and a comma split reads it as two of which neither parses.
///
/// A row with no angle brackets at all yields nothing. RFC 3261 §20 requires
/// the brackets around any URI carrying a semicolon, and every route URI worth
/// checking carries `lr` — so a bracketless row is a different defect, already
/// reported by [`URI_BRACKETS`] and not restated here.
pub(crate) fn bracketed_uris(row: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = row.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let start = i + 1;
            match row[start..].find('>') {
                Some(offset) => {
                    out.push(&row[start..start + offset]);
                    i = start + offset + 1;
                }
                // An unterminated `<` cannot be read as a URI at all.
                None => break,
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Whether a URI's parameter list carries a bare or valued `lr`.
fn has_loose_route_param(uri: &str) -> bool {
    uri.split(';')
        .skip(1)
        .any(|p| param_name(p).eq_ignore_ascii_case(LOOSE_ROUTE_PARAM))
}

/// RFC 3261 §16.6 item 4 — a recorded route URI is a loose route.
fn record_route_loose(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    if !sink.wants(&RECORD_ROUTE_NOT_LOOSE) {
        return;
    }
    for row in msg.headers_by_name("Record-Route") {
        for uri in bracketed_uris(row) {
            if has_loose_route_param(uri) {
                continue;
            }
            sink.push(
                &RECORD_ROUTE_NOT_LOOSE,
                index,
                format!("Record-Route: <{uri}> carries no lr parameter"),
                format!("Record-Route: <{uri};{LOOSE_ROUTE_PARAM}>"),
                "§16.6 item 4 makes the URI a proxy places in Record-Route contain an lr \
                 parameter. Without it the recorded hop is a STRICT route, and a UA \
                 building its route set from this response rewrites the Request-URI on \
                 every in-dialog request to reach it. A route set that mixes the two \
                 conventions loses the original target at the first strict hop, which is \
                 why a BYE reaches the proxy and never reaches the phone.",
            );
        }
    }
}

/// Every `branch` in the message's `Via` stack, in stack order.
///
/// One `Via` row may carry several values (§7.3.1 makes `Via` a
/// comma-separated list), so the rows are split before the branches are read.
fn via_branches(msg: &SipMessage) -> Vec<&str> {
    let mut out = Vec::new();
    for row in msg.via_headers() {
        for value in row.split(',') {
            for param in value.split(';').skip(1) {
                let Some((name, branch)) = param.split_once('=') else {
                    continue;
                };
                if name.trim().eq_ignore_ascii_case("branch") {
                    let branch = branch.trim();
                    if !branch.is_empty() {
                        out.push(branch);
                    }
                }
            }
        }
    }
    out
}

/// RFC 3261 §8.1.1.7 — one branch identifies one transaction, once.
///
/// Requests only, and for the same reason [`branch_cookie`] is: a response
/// copies the request's whole `Via` stack (§8.2.6.2), so reporting both would
/// count one element's defect twice for every message it provoked.
fn via_branch_duplicates(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    if !msg.is_request || !sink.wants(&VIA_BRANCH_DUPLICATE) {
        return;
    }
    let branches = via_branches(msg);
    let mut reported: Vec<&str> = Vec::new();
    for (position, branch) in branches.iter().enumerate() {
        // Only the SECOND appearance is the finding, and each value is
        // reported once however many times it repeats: a request that looped
        // five times through one proxy is one loop, not four findings.
        if !branches[..position].contains(branch) || reported.contains(branch) {
            continue;
        }
        reported.push(branch);
        sink.push(
            &VIA_BRANCH_DUPLICATE,
            index,
            format!("branch={branch} appears at Via positions with an earlier copy above it"),
            "one branch value per Via header field value",
            "§8.1.1.7 makes a branch unique across space and time, and §16.6 item 8 spells \
             out the consequence: a spiraled or looped request gets a DIFFERENT branch each \
             time it passes an element. Two identical values in one stack therefore say the \
             request came back to an element that failed to re-derive it. Loop detection \
             keys on exactly this comparison, so the loop is running unbounded until \
             Max-Forwards stops it.",
        );
    }
}

/// Whether this response answers an `INVITE`, by its own `CSeq`.
fn answers_invite(msg: &SipMessage) -> bool {
    !msg.is_request
        && msg
            .cseq()
            .is_some_and(|(_, m)| m.eq_ignore_ascii_case("INVITE"))
}

/// RFC 3261 §12.1.1 — a 2xx to `INVITE` has to name where the dialog lives.
fn dialog_target(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    if !answers_invite(msg)
        || !msg.status_code.is_some_and(|c| (200..300).contains(&c))
        || msg.header("Contact").is_some()
    {
        return;
    }
    sink.push(
        &CONTACT_MISSING_IN_2XX,
        index,
        "2xx to INVITE with no Contact header field",
        "Contact: <sip:user@host>",
        "§12.1.1 makes the UAS add a Contact to the response. It is the remote target for \
         the dialog the 2xx creates, so without it the caller has nowhere to send the ACK \
         and nowhere to send the BYE. The call answers and then cannot be hung up cleanly.",
    );
}

/// RFC 3262 §3 — a provisional that demands 100rel has to carry an `RSeq`.
fn reliable_provisional(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    if !requires_100rel(msg) || msg.header("RSeq").is_some() {
        return;
    }
    sink.push(
        &RELIABLE_PROVISIONAL_WITHOUT_RSEQ,
        index,
        "provisional carries Require: 100rel with no RSeq header field",
        "RSeq: <sequence number>",
        "§3 makes a reliable provisional carry both the 100rel option tag and an RSeq. The \
         RSeq is the number the PRACK acknowledges, so without it the receiver has to \
         acknowledge a response it cannot name, and the retransmissions run until the \
         transaction gives up.",
    );
}

/// Whether `msg` is a provisional response demanding reliable delivery.
///
/// 100 Trying is excluded on purpose: it is the one provisional never sent
/// reliably, so a `Require` on it is a different defect from this one and
/// reporting it here would be wrong twice over.
pub(crate) fn requires_100rel(msg: &SipMessage) -> bool {
    msg.status_code.is_some_and(|c| (101..200).contains(&c))
        && msg.headers_by_name("Require").iter().any(|v| {
            v.split(',')
                .any(|tag| tag.trim().eq_ignore_ascii_case("100rel"))
        })
}

/// The RFC 4028 floor, in seconds, for both `Session-Expires` and `Min-SE`.
const SESSION_TIMER_FLOOR: u32 = 90;

/// The delta-seconds at the head of a `Session-Expires` or `Min-SE` value.
///
/// Both header fields carry `delta-seconds` followed by optional
/// semicolon-separated parameters, so the number stops at the first `;`.
fn timer_seconds(raw: &str) -> Option<u32> {
    raw.split(';').next()?.trim().parse().ok()
}

/// Whether a `Session-Expires` value names a refresher.
fn has_refresher(raw: &str) -> bool {
    raw.split(';').skip(1).any(|p| {
        p.split('=')
            .next()
            .is_some_and(|n| n.trim().eq_ignore_ascii_case("refresher"))
    })
}

/// RFC 4028 session timers: the floors, the ordering, and the refresher.
///
/// Message-scoped on purpose. Every check here reads one message against
/// itself — two header fields that contradict each other, a value below a
/// fixed floor, or a 2xx that negotiates a timer without saying who refreshes
/// it — so none of them needs the dialog, and a message linted alone still
/// settles them.
fn session_timers(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    let session_expires = msg.header("Session-Expires");
    let min_se = msg.header("Min-SE");

    if let Some(raw) = session_expires
        && let Some(secs) = timer_seconds(raw)
        && secs < SESSION_TIMER_FLOOR
    {
        sink.push(
            &SESSION_EXPIRES_TOO_SMALL,
            index,
            format!("Session-Expires: {secs}"),
            format!("Session-Expires at least {SESSION_TIMER_FLOOR}"),
            "§4 puts the absolute minimum for Session-Expires at 90 seconds. Below it the \
             refresh traffic costs more than the state it keeps alive, and equipment that \
             enforces the floor answers 422 rather than accepting the session.",
        );
    }

    if let Some(raw) = min_se
        && let Some(secs) = timer_seconds(raw)
        && secs < SESSION_TIMER_FLOOR
    {
        sink.push(
            &MIN_SE_TOO_SMALL,
            index,
            format!("Min-SE: {secs}"),
            format!("Min-SE at least {SESSION_TIMER_FLOOR}"),
            "§5 makes the value MUST NOT be less than 90 seconds wherever it appears. A \
             lower floor advertises a willingness the specification does not permit, and \
             the far end may hold you to it.",
        );
    }

    // The two header fields contradicting each other in one message. Checked
    // after the floors so a message breaking both reports both, which is the
    // honest answer: raising the Session-Expires above 90 would still leave it
    // below a Min-SE of 1800.
    if let (Some(se_raw), Some(min_raw)) = (session_expires, min_se)
        && let (Some(se), Some(min)) = (timer_seconds(se_raw), timer_seconds(min_raw))
        && se < min
    {
        sink.push(
            &SESSION_EXPIRES_BELOW_MIN_SE,
            index,
            format!("Session-Expires: {se} beside Min-SE: {min}"),
            "Session-Expires greater than or equal to Min-SE",
            "§7.1 makes Session-Expires greater than or equal to any Min-SE carried with \
             it. The message asks for a refresh interval it has already declared too \
             short, so a UAS honoring the floor rejects it with 422 Session Interval Too \
             Small and the call never starts.",
        );
    }

    // A 2xx to INVITE that negotiates a timer has to say who refreshes it.
    let answers_invite = !msg.is_request
        && msg.status_code.is_some_and(|c| (200..300).contains(&c))
        && msg
            .cseq()
            .is_some_and(|(_, m)| m.eq_ignore_ascii_case("INVITE"));
    if answers_invite
        && let Some(raw) = session_expires
        && !has_refresher(raw)
    {
        sink.push(
            &REFRESHER_MISSING,
            index,
            format!(
                "Session-Expires: {} with no refresher parameter",
                raw.trim()
            ),
            "Session-Expires: <delta-seconds>;refresher=uac|uas",
            "§9 makes the UAS set the refresher parameter in the 2xx response. Without it \
             both ends may believe the other refreshes, and the session ends at the timer \
             on a call neither side wanted to drop.",
        );
    }
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

// ── RFC 7989 Session-ID ─────────────────────────────────────────────────

/// The production both `Session-ID` rules hold a half to, quoted from the
/// RFC 7989 §5 ABNF so the `expected` field is the grammar itself rather than a
/// paraphrase of it.
const SESS_UUID_ABNF: &str = "sess-uuid = 32(DIGIT / %x61-66) — 32 lowercase hex characters";

/// Why an unusable half costs more here than a malformed header usually does.
///
/// One string, shared by the two shapes of malformation, because the
/// consequence is identical and an operator reading both should not have to
/// work out whether the difference in wording meant a difference in effect.
const MALFORMED_CONSEQUENCE: &str = "§5's ABNF admits exactly 32 characters of [0-9a-f], so this half is not a sess-uuid and \
     nothing downstream may treat it as one. sipnab drops an unreadable half from correlation \
     rather than guess at it, and RFC 7989 is the one identifier built to survive a B2BUA: an \
     SBC rewrites the Call-ID and issues a fresh Via branch, so once this half is gone there is \
     nothing left tying the two legs together. A call that did cross the border is then reported \
     as two unrelated calls.";

/// RFC 7989 §5 — each `Session-ID` half is 32 lowercase hexadecimal characters.
///
/// The classification comes from [`SessionId::deviations`], which is what makes
/// this a wiring of that detector rather than a second opinion about the same
/// bytes: the rule raises exactly what the parser reported and nothing else, so
/// a header the parser accepts as conforming can never produce a finding here.
///
/// §5 calls `Session-ID` a single-instance header field, so only the first one
/// is read. A message carrying two is a different defect, and claiming it under
/// this identifier would make the finding unsuppressible without also losing
/// the ABNF check.
fn session_identifier(msg: &SipMessage, index: usize, sink: &mut FindingSink<'_>) {
    let Some(value) = msg.header("Session-ID") else {
        return;
    };
    let Some(parsed) = SessionId::parse(value) else {
        return;
    };
    // `deviations` walks local then remote and yields one entry per half that
    // departed from the ABNF; `deviating_halves` walks the same two halves in
    // the same order. Zipping therefore pairs each classification with the half
    // that provoked it, and a conforming header empties both sides at once —
    // which is what makes `deviations` the gate rather than a decoration.
    // RFC 7989 §5 makes `remote` a MUST with a §11 exception for RFC 7329
    // interworking. Reported before the ABNF deviations because it is a fact
    // about the header's SHAPE rather than about a half's contents: a
    // legacy-form header can still carry a perfectly conforming local half.
    if parsed.legacy_rfc7329_form {
        sink.push(
            &SESSION_ID_LEGACY_FORM,
            index,
            "Session-ID carries no `remote` parameter".to_string(),
            "RFC 7989 §5: except for backwards compatibility with RFC 7329, the \
             `remote` parameter MUST be present",
            "The header identifies one side only, so correlation works in one \
             direction and a call crossing a B2BUA can be reported as two \
             unrelated calls. §11 permits this when the peer really is an RFC \
             7329 stack, which one message cannot establish — so this names the \
             peer as an interop observation rather than asserting a violation. \
             If the peer is modern, the defect is on its side.",
        );
    }

    let deviations = parsed.deviations();
    let halves = deviating_halves(&parsed);
    // `zip` stops at the shorter side, so a divergence between these two walks
    // would drop findings — or worse, pair a deviation with the wrong half and
    // name the innocent one — and do it without a word. The two live in
    // different files, so nothing but this line couples them: `deviations`
    // is `SessionId`'s, `deviating_halves` is here.
    debug_assert_eq!(
        deviations.len(),
        halves.len(),
        "SessionId::deviations and deviating_halves disagree about how many \
         halves deviated; zip would silently drop or mispair findings"
    );
    for (deviation, (half, length)) in deviations.into_iter().zip(halves) {
        match deviation {
            SessionIdDeviation::UppercaseHex => sink.push(
                &SESSION_ID_UPPERCASE,
                index,
                format!("Session-ID {half} carries uppercase hex digits"),
                SESS_UUID_ABNF,
                "§5 says it twice: the ABNF admits %x61-66 with no uppercase alternative, and \
                 the section closes by saying the values are presented as strings of lowercase \
                 hexadecimal characters. sipnab compares the halves case-insensitively, so \
                 correlation still works here — but a peer, an SBC or a log pipeline comparing \
                 the header byte for byte sees two identifiers for one session, which is the \
                 split RFC 7989 exists to prevent. The case also names the stack that emitted \
                 it, which is where the fix goes.",
            ),
            SessionIdDeviation::WrongLength => sink.push(
                &SESSION_ID_MALFORMED,
                index,
                format!("Session-ID {half} is {length} characters, not 32"),
                SESS_UUID_ABNF,
                MALFORMED_CONSEQUENCE,
            ),
            SessionIdDeviation::NonHex => sink.push(
                &SESSION_ID_MALFORMED,
                index,
                format!("Session-ID {half} carries a character outside 0-9 and a-f"),
                SESS_UUID_ABNF,
                MALFORMED_CONSEQUENCE,
            ),
        }
    }
}

/// The halves that departed from the ABNF: the name RFC 7989 §5 gives each, and
/// how many characters it carried, in the order [`SessionId::deviations`]
/// reports them.
///
/// The wire value is deliberately not carried out of here. A `Session-ID` is
/// attacker-controlled text that ends up in a carrier ticket and in an agent's
/// context, the length is what settles a wrong-length half, and "a character
/// outside the set" settles the other — so quoting the bytes would add risk
/// and no evidence. `nil` halves are absent by construction: the parser
/// classifies 32 zeros before it tests case, so they carry no deviation.
fn deviating_halves(parsed: &SessionId) -> Vec<(&'static str, usize)> {
    [
        ("local-uuid", Some(&parsed.local)),
        ("remote-uuid", parsed.remote.as_ref()),
    ]
    .into_iter()
    .filter_map(|(name, half)| Some((name, half?)))
    .filter_map(|(name, half)| match half {
        SessionIdHalf::Uuid {
            value,
            deviation: Some(_),
        } => Some((name, value.chars().count())),
        SessionIdHalf::Malformed { raw, .. } => Some((name, raw.chars().count())),
        _ => None,
    })
    .collect()
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

    /// A 2xx to INVITE, with whatever extra header lines the test needs.
    fn ok_to_invite(extra: &[&str]) -> String {
        let mut out = String::from(
            "SIP/2.0 200 OK\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n\
             To: <sip:bob@example.net>;tag=a6c85cf\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: a84b4c76e66710\r\n\
             CSeq: 314159 INVITE\r\n\
             Content-Length: 0\r\n",
        );
        for line in extra {
            out.push_str(line);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out
    }

    /// An INVITE asking for a refresh interval it has already called too short.
    ///
    /// The two header fields contradict each other inside one message, which is
    /// why this needs no dialog: a UAS honoring the floor answers 422 and the
    /// call never starts.
    #[test]
    fn session_expires_below_min_se_is_reported() {
        let raw = clean_invite().replace(
            "Content-Length: 0\r\n",
            "Session-Expires: 120\r\nMin-SE: 1800\r\nContent-Length: 0\r\n",
        );
        assert!(
            ids(&raw).contains(&SESSION_EXPIRES_BELOW_MIN_SE.id),
            "{:?}",
            ids(&raw)
        );
    }

    /// Session-Expires at or above Min-SE is silent.
    #[test]
    fn session_expires_at_or_above_min_se_is_silent() {
        for (se, min) in [(1800, 1800), (3600, 90)] {
            let raw = clean_invite().replace(
                "Content-Length: 0\r\n",
                &format!("Session-Expires: {se}\r\nMin-SE: {min}\r\nContent-Length: 0\r\n"),
            );
            assert!(
                !ids(&raw).contains(&SESSION_EXPIRES_BELOW_MIN_SE.id),
                "Session-Expires {se} against Min-SE {min} is legal: {:?}",
                ids(&raw)
            );
        }
    }

    /// Both floors fire below 90, and stay quiet at exactly 90.
    #[test]
    fn the_ninety_second_floors_are_inclusive() {
        let below = clean_invite().replace(
            "Content-Length: 0\r\n",
            "Session-Expires: 60\r\nMin-SE: 45\r\nContent-Length: 0\r\n",
        );
        let got = ids(&below);
        assert!(got.contains(&SESSION_EXPIRES_TOO_SMALL.id), "{got:?}");
        assert!(got.contains(&MIN_SE_TOO_SMALL.id), "{got:?}");

        // 90 is the minimum, not the first illegal value.
        let at = clean_invite().replace(
            "Content-Length: 0\r\n",
            "Session-Expires: 90\r\nMin-SE: 90\r\nContent-Length: 0\r\n",
        );
        let got = ids(&at);
        assert!(!got.contains(&SESSION_EXPIRES_TOO_SMALL.id), "{got:?}");
        assert!(!got.contains(&MIN_SE_TOO_SMALL.id), "{got:?}");
    }

    /// A message breaking the floor and the ordering reports both.
    ///
    /// Raising Session-Expires to 90 would still leave it under a Min-SE of
    /// 1800, so reporting only one would send the operator round twice.
    #[test]
    fn a_message_breaking_the_floor_and_the_ordering_reports_both() {
        let raw = clean_invite().replace(
            "Content-Length: 0\r\n",
            "Session-Expires: 60\r\nMin-SE: 1800\r\nContent-Length: 0\r\n",
        );
        let got = ids(&raw);
        assert!(got.contains(&SESSION_EXPIRES_TOO_SMALL.id), "{got:?}");
        assert!(got.contains(&SESSION_EXPIRES_BELOW_MIN_SE.id), "{got:?}");
    }

    /// The delta-seconds stops at the first parameter.
    ///
    /// `Session-Expires: 1800;refresher=uas` is 1800 seconds, not a parse
    /// failure and not 1800-with-junk. Reading the whole value as a number
    /// would silence every conformant timer in existence.
    #[test]
    fn parameters_do_not_confuse_the_delta_seconds() {
        assert_eq!(timer_seconds("1800;refresher=uas"), Some(1800));
        assert_eq!(timer_seconds("  90  "), Some(90));
        assert_eq!(timer_seconds("not-a-number"), None);
    }

    /// A 2xx to INVITE negotiating a timer must name the refresher.
    #[test]
    fn a_2xx_without_a_refresher_is_reported() {
        let raw = ok_to_invite(&["Session-Expires: 1800"]);
        assert!(ids(&raw).contains(&REFRESHER_MISSING.id), "{:?}", ids(&raw));
    }

    /// Either refresher value satisfies the rule, in any case.
    #[test]
    fn a_2xx_naming_a_refresher_is_silent() {
        for value in [
            "Session-Expires: 1800;refresher=uas",
            "Session-Expires: 1800;refresher=uac",
            "Session-Expires: 1800 ;REFRESHER=UAS",
        ] {
            let raw = ok_to_invite(&[value]);
            assert!(
                !ids(&raw).contains(&REFRESHER_MISSING.id),
                "{value} names a refresher: {:?}",
                ids(&raw)
            );
        }
    }

    /// The refresher rule is confined to 2xx answers to INVITE.
    ///
    /// The guard that keeps this rule off most of a capture. A request carries
    /// no refresher by rule -- §9 puts the obligation on the UAS response --
    /// and a 200 to REGISTER or a 180 Ringing is not the message §9 governs.
    /// Without these three checks the rule fires on ordinary conformant
    /// traffic, which is how a linter gets switched off in week one.
    #[test]
    fn the_refresher_rule_ignores_requests_and_non_invite_answers() {
        // A request carrying Session-Expires: the UAC offers, it does not answer.
        let request = clean_invite().replace(
            "Content-Length: 0\r\n",
            "Session-Expires: 1800\r\nContent-Length: 0\r\n",
        );
        assert!(
            !ids(&request).contains(&REFRESHER_MISSING.id),
            "{:?}",
            ids(&request)
        );

        // A 200 to REGISTER.
        let register = ok_to_invite(&["Session-Expires: 1800"])
            .replace("CSeq: 314159 INVITE", "CSeq: 314159 REGISTER");
        assert!(
            !ids(&register).contains(&REFRESHER_MISSING.id),
            "{:?}",
            ids(&register)
        );

        // A provisional answer to INVITE.
        let ringing = ok_to_invite(&["Session-Expires: 1800"]).replace("200 OK", "180 Ringing");
        assert!(
            !ids(&ringing).contains(&REFRESHER_MISSING.id),
            "{:?}",
            ids(&ringing)
        );

        // And a 2xx that negotiates no timer at all.
        let no_timer = ok_to_invite(&[]);
        assert!(
            !ids(&no_timer).contains(&REFRESHER_MISSING.id),
            "{:?}",
            ids(&no_timer)
        );
    }

    /// A 2xx to INVITE with no Contact leaves the dialog unroutable.
    #[test]
    fn a_2xx_to_invite_without_contact_is_reported() {
        let raw = ok_to_invite(&[]);
        assert!(
            ids(&raw).contains(&CONTACT_MISSING_IN_2XX.id),
            "{:?}",
            ids(&raw)
        );
    }

    /// The Contact rule is confined to 2xx answers to INVITE.
    ///
    /// A 2xx to REGISTER or BYE creates no dialog, and a provisional is not
    /// the response §12.1.1 governs. Without these guards the rule fires on
    /// ordinary conformant traffic.
    #[test]
    fn the_contact_rule_ignores_other_responses() {
        let with_contact = ok_to_invite(&["Contact: <sip:bob@192.0.2.2>"]);
        assert!(!ids(&with_contact).contains(&CONTACT_MISSING_IN_2XX.id));

        let bye = ok_to_invite(&[]).replace("CSeq: 314159 INVITE", "CSeq: 314159 BYE");
        assert!(
            !ids(&bye).contains(&CONTACT_MISSING_IN_2XX.id),
            "{:?}",
            ids(&bye)
        );

        let ringing = ok_to_invite(&[]).replace("200 OK", "180 Ringing");
        assert!(
            !ids(&ringing).contains(&CONTACT_MISSING_IN_2XX.id),
            "{:?}",
            ids(&ringing)
        );

        let busy = ok_to_invite(&[]).replace("200 OK", "486 Busy Here");
        assert!(
            !ids(&busy).contains(&CONTACT_MISSING_IN_2XX.id),
            "{:?}",
            ids(&busy)
        );
    }

    /// A provisional demanding 100rel must carry the number the PRACK cites.
    #[test]
    fn a_reliable_provisional_without_rseq_is_reported() {
        let raw = ok_to_invite(&["Require: 100rel", "Contact: <sip:bob@192.0.2.2>"])
            .replace("200 OK", "183 Session Progress");
        assert!(
            ids(&raw).contains(&RELIABLE_PROVISIONAL_WITHOUT_RSEQ.id),
            "{:?}",
            ids(&raw)
        );
    }

    /// The RSeq rule stays off everything it does not govern.
    ///
    /// 100 Trying is never sent reliably, a provisional with an RSeq is
    /// correct, and 100rel in a Require on a final response is a different
    /// question entirely.
    #[test]
    fn the_rseq_rule_is_confined_to_reliable_provisionals() {
        let with_rseq =
            ok_to_invite(&["Require: 100rel", "RSeq: 1"]).replace("200 OK", "183 Session Progress");
        assert!(!ids(&with_rseq).contains(&RELIABLE_PROVISIONAL_WITHOUT_RSEQ.id));

        // 100 Trying is the one provisional that is never reliable.
        let trying = ok_to_invite(&["Require: 100rel"]).replace("200 OK", "100 Trying");
        assert!(
            !ids(&trying).contains(&RELIABLE_PROVISIONAL_WITHOUT_RSEQ.id),
            "{:?}",
            ids(&trying)
        );

        // A provisional that never asked for reliability.
        let plain = ok_to_invite(&[]).replace("200 OK", "180 Ringing");
        assert!(!ids(&plain).contains(&RELIABLE_PROVISIONAL_WITHOUT_RSEQ.id));

        // A final response is out of scope even carrying the tag.
        let final_resp = ok_to_invite(&["Require: 100rel", "Contact: <sip:b@192.0.2.2>"]);
        assert!(!ids(&final_resp).contains(&RELIABLE_PROVISIONAL_WITHOUT_RSEQ.id));
    }

    /// The option tag is matched per comma-separated entry, case-insensitively.
    #[test]
    fn the_100rel_tag_is_matched_as_a_whole_entry() {
        let multi =
            ok_to_invite(&["Require: timer, 100REL"]).replace("200 OK", "183 Session Progress");
        assert!(
            ids(&multi).contains(&RELIABLE_PROVISIONAL_WITHOUT_RSEQ.id),
            "{:?}",
            ids(&multi)
        );

        // A tag that merely contains the text is not the tag.
        let lookalike =
            ok_to_invite(&["Require: no100relhere"]).replace("200 OK", "183 Session Progress");
        assert!(
            !ids(&lookalike).contains(&RELIABLE_PROVISIONAL_WITHOUT_RSEQ.id),
            "{:?}",
            ids(&lookalike)
        );
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

    /// The bracket splitter recognizes a name-addr wherever the brackets sit.
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

    /// A conforming RFC 7989 `Session-ID`, used as the base for the tests below.
    const SESSION_A: &str = "ab30317f1a784dc48ff824d0d3715d86";

    /// The far endpoint's half of [`SESSION_A`]'s session.
    const SESSION_B: &str = "47755a9de7794ba387653f2099600ef2";

    /// An INVITE carrying `value` as its `Session-ID`.
    fn invite_with_session_id(value: &str) -> String {
        clean_invite().replace(
            "Content-Length: 0\r\n",
            &format!("Session-ID: {value}\r\nContent-Length: 0\r\n"),
        )
    }

    /// Findings for `raw`, as `(rule_id, observed)` pairs.
    fn findings_of(raw: &str) -> Vec<(&'static str, String)> {
        Linter::new(LintConfig::new())
            .lint_message(&msg(raw), 0)
            .into_iter()
            .map(|f| (f.rule_id, f.observed))
            .collect()
    }

    /// A half that is not 32 characters cannot be a `sess-uuid`, and the
    /// finding says how long it actually was.
    #[test]
    fn a_short_session_id_half_is_reported_as_malformed() {
        let got = findings_of(&invite_with_session_id("deadbeef"));
        let observed = got
            .iter()
            .find(|(id, _)| *id == SESSION_ID_MALFORMED.id)
            .map(|(_, observed)| observed.as_str())
            .unwrap_or_else(|| panic!("no malformed finding: {got:?}"));
        assert_eq!(observed, "Session-ID local-uuid is 8 characters, not 32");
    }

    /// A half of the right length holding something outside `[0-9a-f]` is
    /// reported for the character set rather than for the length.
    #[test]
    fn a_non_hex_session_id_half_is_reported_for_its_character_set() {
        let got = findings_of(&invite_with_session_id(&"z".repeat(32)));
        assert!(
            got.contains(&(
                SESSION_ID_MALFORMED.id,
                "Session-ID local-uuid carries a character outside 0-9 and a-f".to_string(),
            )),
            "{} must report a non-hex half: {got:?}",
            SESSION_ID_MALFORMED.id
        );
    }

    /// Uppercase hex is its own finding, and is NOT reported as malformed.
    ///
    /// The distinction is the point of splitting the two rules: this value is
    /// unambiguous and sipnab still correlates on it, so calling it malformed
    /// would tell an operator to go and fix a leg that is in fact matching.
    /// The RFC 7329 legacy form is reported, and reported as INTEROP.
    ///
    /// Severity and basis are asserted, not merely presence. A `must` here
    /// would claim sipnab can tell genuine RFC 7329 interworking from a modern
    /// peer that simply omits the parameter — a distinction one message cannot
    /// support, and the reason this rule exists at notice rather than error.
    #[test]
    fn a_session_id_without_remote_is_an_interop_notice_not_a_violation() {
        let got = findings_of(&invite_with_session_id(SESSION_A));
        assert!(
            got.iter().any(|(id, _)| *id == SESSION_ID_LEGACY_FORM.id),
            "a Session-ID with no `remote` must be reported: {got:?}"
        );
        assert_eq!(
            SESSION_ID_LEGACY_FORM.severity,
            crate::sip::lint::Severity::Notice,
            "a form RFC 7989 §11 explicitly permits must not shout"
        );
        assert_eq!(
            SESSION_ID_LEGACY_FORM.basis,
            crate::sip::lint::Basis::Interop,
            "basis must be interop: §5's MUST carries a §11 exception this rule \
             cannot rule out from a single message"
        );
        assert_eq!(SESSION_ID_LEGACY_FORM.section, "11", "cite the exception");

        // A conforming two-half header must NOT trip it, or the rule fires on
        // every well-formed Session-ID and says nothing.
        let both = invite_with_session_id(&format!("{SESSION_A};remote={SESSION_B}"));
        assert!(
            !findings_of(&both)
                .iter()
                .any(|(id, _)| *id == SESSION_ID_LEGACY_FORM.id),
            "a conforming Session-ID with both halves must not be reported"
        );
    }

    #[test]
    fn uppercase_hex_is_reported_separately_from_a_malformed_half() {
        let got = findings_of(&invite_with_session_id(&SESSION_A.to_ascii_uppercase()));
        assert!(
            got.contains(&(
                SESSION_ID_UPPERCASE.id,
                "Session-ID local-uuid carries uppercase hex digits".to_string(),
            )),
            "{} must report an uppercase UUID: {got:?}",
            SESSION_ID_UPPERCASE.id
        );
        assert!(
            !got.iter().any(|(id, _)| *id == SESSION_ID_MALFORMED.id),
            "uppercase is still a usable UUID: {got:?}"
        );
    }

    /// A conforming header, and a `nil` remote, raise nothing.
    ///
    /// The mutation guard for every test above: a rule that fired on the mere
    /// presence of the header would pass all of them and fail this one. `nil`
    /// is in here because it is what every initial INVITE carries — RFC 7989
    /// §5 expects it before the far end has contributed a UUID — so reporting
    /// it would fire on the first message of practically every conformant call.
    #[test]
    fn a_conforming_session_id_raises_no_finding() {
        for value in [
            SESSION_A.to_string(),
            format!("{SESSION_A};remote={SESSION_B}"),
            format!("{SESSION_A};remote={}", "0".repeat(32)),
            format!("{};remote={SESSION_B}", "0".repeat(32)),
        ] {
            let got = findings_of(&invite_with_session_id(&value));
            assert!(
                !got.iter().any(|(id, _)| *id == SESSION_ID_MALFORMED.id
                    || *id == SESSION_ID_UPPERCASE.id),
                "{value} is conformant: {got:?}"
            );
        }
    }

    /// Each finding names the half it came from, and the two do not swap.
    ///
    /// The rule pairs what `SessionId::deviations` classified with the half
    /// that provoked it by walking both in the same order. A message whose two
    /// halves deviate in DIFFERENT ways is the only input that can catch that
    /// pairing coming apart: with one deviation, or with two of the same kind,
    /// a swap is invisible.
    #[test]
    fn each_session_id_finding_names_the_half_it_came_from() {
        let raw = invite_with_session_id(&format!(
            "{};remote=nonsense",
            SESSION_A.to_ascii_uppercase()
        ));
        let got = findings_of(&raw);
        assert!(
            got.contains(&(
                SESSION_ID_UPPERCASE.id,
                "Session-ID local-uuid carries uppercase hex digits".to_string(),
            )),
            "the uppercase finding must name the LOCAL half: {got:?}"
        );
        assert!(
            got.contains(&(
                SESSION_ID_MALFORMED.id,
                "Session-ID remote-uuid is 8 characters, not 32".to_string(),
            )),
            "the malformed finding must name the REMOTE half: {got:?}"
        );
    }

    /// The finding carries RFC 7989 §5 as data, and quotes the ABNF it holds
    /// the value to.
    ///
    /// A lint rule that cannot name the clause it enforces is an opinion, and
    /// the citation is only checkable because it is a field rather than prose.
    #[test]
    fn a_session_id_finding_cites_the_abnf_it_enforces() {
        let finding = Linter::new(LintConfig::new())
            .lint_message(&msg(&invite_with_session_id("deadbeef")), 0)
            .into_iter()
            .find(|f| f.rule_id == SESSION_ID_MALFORMED.id)
            .expect("the malformed rule must fire");
        assert_eq!(finding.rfc, 7989);
        assert_eq!(finding.section, "5");
        assert_eq!(finding.citation(), "RFC 7989 §5");
        assert_eq!(finding.expected, SESS_UUID_ABNF);
        assert!(
            finding.expected.contains("32(DIGIT / %x61-66)"),
            "the expectation must quote the production: {}",
            finding.expected
        );
    }

    /// A message with no `Session-ID` at all is silent.
    ///
    /// Most SIP carries no Session-ID whatsoever. A rule that reported its
    /// absence would fire on nearly every dialog in every capture, which is how
    /// a linter gets switched off in week one.
    #[test]
    fn a_message_without_a_session_id_is_silent() {
        let got = findings_of(&clean_invite());
        assert!(
            !got.iter()
                .any(|(id, _)| *id == SESSION_ID_MALFORMED.id || *id == SESSION_ID_UPPERCASE.id),
            "{got:?}"
        );
    }

    // ── RFC 3261 §7.3.1 — single-valued header fields ───────────────────

    /// A second `To` row is reported, and the count is named.
    ///
    /// The count matters because §7.3.1's whole objection is that a receiver
    /// has to pick, and "2 To header field rows" tells the operator how many
    /// candidates two elements could disagree about.
    #[test]
    fn a_repeated_singular_header_is_reported() {
        let raw = clean_invite().replace(
            "CSeq: 314159 INVITE\r\n",
            "CSeq: 314159 INVITE\r\nTo: <sip:mallory@example.net>\r\n",
        );
        let findings = Linter::new(LintConfig::new()).lint_message(&msg(&raw), 0);
        let found = findings
            .iter()
            .find(|f| f.rule_id == SINGULAR_HEADER_REPEATED.id)
            .unwrap_or_else(|| panic!("{:?}", ids(&raw)));
        assert!(found.observed.contains("2 To"), "{}", found.observed);
    }

    /// A compact row and its long form are two rows of one header field.
    ///
    /// The parser expands compact names at parse (RFC 3261 §7.3.3), so `i:`
    /// beside `Call-ID:` is the same field name twice — and it is the shape a
    /// header-smuggling attempt takes, because a parser that reads only one
    /// spelling sees a message with one `Call-ID`.
    #[test]
    fn a_compact_row_beside_its_long_form_is_a_repeat() {
        let raw = clean_invite().replace(
            "Call-ID: a84b4c76e66710\r\n",
            "Call-ID: a84b4c76e66710\r\ni: smuggled-call-id\r\n",
        );
        assert!(
            ids(&raw).contains(&SINGULAR_HEADER_REPEATED.id),
            "{:?}",
            ids(&raw)
        );
    }

    /// Two `Authorization` rows are the exception §7.3.1 writes down, not a
    /// finding.
    ///
    /// This is the mutation that matters for this rule: adding the four
    /// authentication header fields to `SINGULAR_HEADERS` would report the
    /// RFC's own permitted form as a violation, and a `407` carrying two
    /// challenges is ordinary traffic.
    #[test]
    fn repeated_authorization_rows_are_the_documented_exception() {
        let raw = clean_invite().replace(
            "CSeq: 314159 INVITE\r\n",
            "CSeq: 314159 INVITE\r\n\
             Authorization: Digest username=\"alice\", realm=\"a\"\r\n\
             Authorization: Digest username=\"alice\", realm=\"b\"\r\n",
        );
        assert!(
            !ids(&raw).contains(&SINGULAR_HEADER_REPEATED.id),
            "{:?}",
            ids(&raw)
        );
    }

    /// Two `Via` rows are the ordinary shape of a forwarded request.
    #[test]
    fn repeated_via_rows_are_not_a_singular_header_finding() {
        let raw = clean_invite().replace(
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n",
            "Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKproxy\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n",
        );
        assert!(
            !ids(&raw).contains(&SINGULAR_HEADER_REPEATED.id),
            "{:?}",
            ids(&raw)
        );
    }

    // ── RFC 3261 §16.6 item 4 — Record-Route is a loose route ───────────

    /// A recorded route with no `lr` is reported.
    #[test]
    fn a_strict_record_route_is_reported() {
        let raw = clean_invite().replace(
            "Content-Length: 0\r\n",
            "Record-Route: <sip:p1.example.net>\r\nContent-Length: 0\r\n",
        );
        let findings = Linter::new(LintConfig::new()).lint_message(&msg(&raw), 0);
        let found = findings
            .iter()
            .find(|f| f.rule_id == RECORD_ROUTE_NOT_LOOSE.id)
            .unwrap_or_else(|| panic!("{:?}", ids(&raw)));
        assert!(found.expected.contains(";lr>"), "{}", found.expected);
    }

    /// A loose route is silent, and so is the `lr=on` spelling some stacks
    /// emit.
    ///
    /// §19.1.1 defines `lr` as a flag parameter, and equipment that writes it
    /// with a value is still loose-routing. Reporting that spelling would send
    /// an operator to change a proxy that is behaving correctly.
    #[test]
    fn a_loose_record_route_is_silent() {
        for uri in ["sip:p1.example.net;lr", "sip:p1.example.net;lr=on"] {
            let raw = clean_invite().replace(
                "Content-Length: 0\r\n",
                &format!("Record-Route: <{uri}>\r\nContent-Length: 0\r\n"),
            );
            assert!(
                !ids(&raw).contains(&RECORD_ROUTE_NOT_LOOSE.id),
                "{uri}: {:?}",
                ids(&raw)
            );
        }
    }

    /// A comma inside a display name does not split one route into two.
    ///
    /// Splitting the row on commas — the obvious implementation — reads
    /// `"Smith, John" <sip:p1.example.net;lr>` as two entries of which neither
    /// carries `lr`, and reports a conformant proxy twice.
    #[test]
    fn a_display_name_comma_does_not_split_a_route() {
        let raw = clean_invite().replace(
            "Content-Length: 0\r\n",
            "Record-Route: \"Smith, John\" <sip:p1.example.net;lr>\r\nContent-Length: 0\r\n",
        );
        assert!(
            !ids(&raw).contains(&RECORD_ROUTE_NOT_LOOSE.id),
            "{:?}",
            ids(&raw)
        );
    }

    /// Two routes on one row are both read, and only the strict one reports.
    #[test]
    fn a_multi_value_record_route_row_reports_only_the_strict_hop() {
        let raw = clean_invite().replace(
            "Content-Length: 0\r\n",
            "Record-Route: <sip:p1.example.net;lr>, <sip:p2.example.net>\r\nContent-Length: 0\r\n",
        );
        let strict: Vec<String> = Linter::new(LintConfig::new())
            .lint_message(&msg(&raw), 0)
            .into_iter()
            .filter(|f| f.rule_id == RECORD_ROUTE_NOT_LOOSE.id)
            .map(|f| f.observed)
            .collect();
        assert_eq!(strict.len(), 1, "{strict:?}");
        assert!(strict[0].contains("p2.example.net"), "{strict:?}");
    }

    // ── RFC 3261 §8.1.1.7 — one branch, once ────────────────────────────

    /// The same branch twice in one Via stack is reported once.
    ///
    /// Once, not twice: a request that came round the loop repeatedly is one
    /// loop, and a finding per repetition would bury every other rule under a
    /// single defect.
    #[test]
    fn a_duplicated_via_branch_is_reported_once() {
        let raw = clean_invite().replace(
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n",
            "Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKloop\r\n\
             Via: SIP/2.0/UDP 192.0.2.8:5060;branch=z9hG4bKloop\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKloop\r\n",
        );
        let hits = ids(&raw)
            .iter()
            .filter(|id| **id == VIA_BRANCH_DUPLICATE.id)
            .count();
        assert_eq!(hits, 1, "{:?}", ids(&raw));
    }

    /// Distinct branches in a deep Via stack are silent.
    #[test]
    fn distinct_via_branches_are_silent() {
        let raw = clean_invite().replace(
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n",
            "Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKtwo\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKone\r\n",
        );
        assert!(
            !ids(&raw).contains(&VIA_BRANCH_DUPLICATE.id),
            "{:?}",
            ids(&raw)
        );
    }

    /// A response carrying the same duplicated stack is not reported.
    ///
    /// §8.2.6.2 makes the response copy the request's Via values verbatim, so
    /// reporting the response would count one element's defect once more for
    /// every message the loop provoked.
    #[test]
    fn a_response_echoing_a_duplicated_stack_is_silent() {
        let raw = ok_to_invite(&[]).replace(
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n",
            "Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKloop\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKloop\r\n",
        );
        assert!(
            !ids(&raw).contains(&VIA_BRANCH_DUPLICATE.id),
            "{:?}",
            ids(&raw)
        );
    }

    /// One row carrying two comma-separated Via values with one branch is
    /// still a duplicate.
    ///
    /// §7.3.1 makes `Via` a comma-separated list, so a stack written on one row
    /// is the same stack. Reading rows without splitting them is the shape that
    /// lets a loop hide from this rule.
    #[test]
    fn a_comma_separated_via_row_is_read_as_a_stack() {
        let raw = clean_invite().replace(
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n",
            "Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKloop, \
             SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKloop\r\n",
        );
        assert!(
            ids(&raw).contains(&VIA_BRANCH_DUPLICATE.id),
            "{:?}",
            ids(&raw)
        );
    }
}
