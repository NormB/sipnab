// SPDX-License-Identifier: MIT OR Apache-2.0

//! Why a call ended, as a field rather than as prose.
//!
//! "The call ended" and "the call ended because the far end was out of order"
//! are different answers, and only the second closes a ticket. The cause is on
//! the wire in two forms and sipnab read neither outside one narrow case:
//!
//! * **[RFC 3326](https://www.rfc-editor.org/rfc/rfc3326) `Reason`** — read in exactly one place before this module,
//!   and only on a final FAILURE response. A `Reason:` on a `BYE` or a `CANCEL`
//!   — where a normally-cleared call carries its cause — was never reached.
//! * **`X-Asterisk-HangupCause` / `X-Asterisk-HangupCauseCode`** — the text and
//!   the Q.850 number, as two separate headers.
//!
//! **The generic half is the feature and the vendor half is one extra header
//! name.** That is how to be Asterisk-aware without becoming Asterisk-specific.

use serde::{Deserialize, Serialize};

use crate::sip::message::SipMessage;

/// Longest `cause_text` reported, in characters.
///
/// The text is written by whoever sent the message and reaches an agent's
/// context through `triage_call`, so it is bounded where it is read rather
/// than at each surface. 200 characters is far past every value a gateway
/// produces — the longest `X-Asterisk-HangupCause` in the private corpus is
/// `"Network out of order"`, at 20 — and short enough that a crafted header
/// cannot spend a context window.
pub const MAX_CAUSE_TEXT_CHARS: usize = 200;

/// The header name Asterisk puts the numeric Q.850 cause in.
const ASTERISK_CODE_HEADER: &str = "X-Asterisk-HangupCauseCode";

/// The header name Asterisk puts the human-readable cause in.
const ASTERISK_TEXT_HEADER: &str = "X-Asterisk-HangupCause";

/// One [RFC 3326](https://www.rfc-editor.org/rfc/rfc3326) `reason-value`: a protocol, and what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonCause {
    /// RFC 3326 `protocol` — `"SIP"`, `"Q.850"` or a token nobody has
    /// registered. Kept as the sender spelled it.
    pub protocol: String,
    /// The `cause` parameter, when present and a number.
    pub cause: Option<u16>,
    /// The `text` parameter, unquoted, when present.
    pub text: Option<String>,
}

/// Why a dialog ended, and where that was said.
///
/// Every field except [`Self::frame_ref`] is optional because the wire is:
/// a `Reason` may name a protocol and no cause, and a vendor header may carry
/// a number and no text. The absent ones say "the message did not carry it",
/// never "zero".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Termination {
    /// The cause number, on the scale [`Self::protocol`] names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause_code: Option<u16>,
    /// The human-readable cause, bounded to [`MAX_CAUSE_TEXT_CHARS`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause_text: Option<String>,
    /// Which scale [`Self::cause_code`] is on. A `16` means normal clearing
    /// in Q.850 and is not a SIP status code at all, so a code without this
    /// is not interpretable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// The header the cause was read from, verbatim. What a vendor header
    /// asserts and what RFC 3326 asserts are not the same claim, and a reader
    /// deciding how much to trust the number needs to know which one this is.
    pub source_header: String,
    /// Index into the dialog's message list of the message that carried it.
    pub frame_ref: usize,
}

/// Parse one `Reason` header value into its `reason-value` list.
///
/// [RFC 3326](https://www.rfc-editor.org/rfc/rfc3326) §2:
///
/// ```text
/// Reason        = "Reason" HCOLON reason-value *(COMMA reason-value)
/// reason-value  = protocol *(SEMI reason-params)
/// reason-params = protocol-cause / reason-text / reason-extension
/// protocol-cause = "cause" EQUAL cause
/// reason-text   = "text" EQUAL quoted-string
/// ```
///
/// A comma inside the quoted `text` is text: splitting on every comma would
/// cut one value in half and invent a second protocol named after the rest of
/// the sentence. Parameter names are matched case-insensitively and linear
/// whitespace is allowed around `;` and `=`, both per RFC 3261 §7.3.1.
///
/// An unparsable `cause` is reported ABSENT rather than as zero. Zero is a
/// real Q.850 cause and appears in the private corpus, so coercing a parse
/// failure into it would put a value a reader cannot distinguish from a
/// measured one on an operator-facing field.
#[must_use]
pub fn parse_reason_value(value: &str) -> Vec<ReasonCause> {
    split_outside_quotes(value, ',')
        .into_iter()
        .filter_map(|v| {
            let mut parts = split_outside_quotes(v, ';').into_iter();
            let protocol = parts.next()?.trim().to_string();
            if protocol.is_empty() {
                return None;
            }
            let mut cause = None;
            let mut text = None;
            for param in parts {
                let Some((name, raw)) = param.split_once('=') else {
                    continue;
                };
                let name = name.trim();
                let raw = raw.trim();
                if name.eq_ignore_ascii_case("cause") {
                    cause = raw.parse::<u16>().ok();
                } else if name.eq_ignore_ascii_case("text") {
                    text = Some(bound_text(unquote(raw)));
                }
            }
            Some(ReasonCause {
                protocol,
                cause,
                text,
            })
        })
        .collect()
}

/// Split on `sep`, ignoring separators inside a `quoted-string`.
fn split_outside_quotes(input: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            c if c == sep && !quoted => {
                out.push(&input[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&input[start..]);
    out
}

/// Strip one layer of `quoted-string` quoting, and its `\` escapes.
fn unquote(raw: &str) -> String {
    // One call, not a prefix strip fed into a suffix strip: `strip_circumfix`
    // (Rust 1.98) fails when EITHER end is missing, which is the rule this
    // wanted, and it cannot succeed on a lone `"` the way a naive chain of two
    // strips on a one-character string can.
    let Some(inner) = raw.strip_circumfix('"', '"') else {
        return raw.to_string();
    };
    let mut out = String::with_capacity(inner.len());
    let mut escaped = false;
    for c in inner.chars() {
        match c {
            '\\' if !escaped => escaped = true,
            _ => {
                escaped = false;
                out.push(c);
            }
        }
    }
    out
}

/// Bound a remote-written string to [`MAX_CAUSE_TEXT_CHARS`].
///
/// Truncated on a CHARACTER boundary, not a byte one: a cause text can be
/// UTF-8 and cutting mid-sequence would put a replacement character on an
/// operator's screen and, worse, a different string on two surfaces that
/// truncate at different widths.
fn bound_text(text: String) -> String {
    text.chars()
        // Control characters are stripped here rather than at each renderer.
        // A folded header unfolds to a space, but nothing stops a sender
        // putting a `\r` or an escape sequence inside a quoted-string, and
        // this value is written to a terminal, a Markdown table and an
        // agent's context.
        .filter(|c| !c.is_control())
        .take(MAX_CAUSE_TEXT_CHARS)
        .collect()
}

/// What one message says about why the call ended, before it is placed.
///
/// [`Termination`] minus `frame_ref`, which only the scan over the dialog can
/// supply. A named type rather than a tuple, because four `Option`s in a row
/// have no reading order a caller can recover: `(None, None, Some(..), "..")`
/// says nothing about which `None` was the code.
struct MessageCause {
    /// The cause number, on the scale [`Self::protocol`] names.
    cause_code: Option<u16>,
    /// The human-readable cause, already bounded and stripped.
    cause_text: Option<String>,
    /// Which scale [`Self::cause_code`] is on.
    protocol: Option<String>,
    /// The header this came out of, verbatim.
    source_header: &'static str,
}

/// The cause a single message carries, if it carries one.
///
/// `Reason` outranks the vendor pair: RFC 3326 is what every other
/// implementation writes and reads. Measured against the private corpus on
/// 2026-09-08 the two never appear together — every `BYE` carrying
/// `X-Asterisk-HangupCauseCode` carries no `Reason` at all — so the ordering
/// is a rule for messages nobody has sent yet rather than a choice between
/// two observed values.
fn cause_in_message(msg: &SipMessage) -> Option<MessageCause> {
    let reasons: Vec<ReasonCause> = msg
        .headers_by_name("Reason")
        .into_iter()
        .flat_map(parse_reason_value)
        .collect();
    if let Some(chosen) = choose_reason(&reasons) {
        return Some(MessageCause {
            cause_code: chosen.cause,
            cause_text: chosen.text.clone(),
            protocol: Some(chosen.protocol.clone()),
            source_header: "Reason",
        });
    }

    let cause_code = msg
        .header(ASTERISK_CODE_HEADER)
        .and_then(|v| v.trim().parse::<u16>().ok());
    let cause_text = msg
        .header(ASTERISK_TEXT_HEADER)
        .map(|v| bound_text(v.trim().to_string()))
        .filter(|s| !s.is_empty());
    if cause_code.is_none() && cause_text.is_none() {
        return None;
    }
    Some(MessageCause {
        cause_code,
        cause_text,
        // Asterisk's codes ARE Q.850 causes, and saying so is what lets a
        // reader compare them against the standard ones. `source_header`
        // reports where the value actually came from, so naming the scale
        // launders nothing.
        protocol: Some("Q.850".to_string()),
        source_header: ASTERISK_CODE_HEADER,
    })
}

/// Pick one `reason-value` out of the several a message may carry.
///
/// A non-`SIP` protocol wins. `SIP;cause=` restates the status code, which is
/// already its own field on every surface that reports this; `Q.850;cause=`
/// is the gateway's cause and is the fact not otherwise recoverable. Spending
/// the one `termination` block on the duplicate would report the half a
/// reader already has.
fn choose_reason(reasons: &[ReasonCause]) -> Option<&ReasonCause> {
    reasons
        .iter()
        .find(|r| !r.protocol.eq_ignore_ascii_case("SIP"))
        .or_else(|| reasons.first())
}

impl Termination {
    /// One line a human reads, shared by every rendering.
    ///
    /// Written once so the text report, the Markdown report and anything
    /// added later cannot disagree about whether a call named a cause or
    /// about how the scale is spelled. The header name is part of the line
    /// because what a vendor header asserts and what RFC 3326 asserts are
    /// not the same claim, and a reader deciding how far to trust the number
    /// needs to know which one this is.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut out = String::new();
        if let Some(p) = &self.protocol {
            out.push_str(p);
        }
        if let Some(c) = self.cause_code {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&format!("cause {c}"));
        }
        if let Some(t) = &self.cause_text {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&format!("\"{t}\""));
        }
        format!("{out} [{}]", self.source_header)
    }
}

/// Why this dialog ended, read from the last message that says so.
///
/// The LAST one: a call that was challenged, retried and finally cleared
/// carries more than one cause, and the one that says why it ended is the
/// last thing said about it.
///
/// Returns `None` when nothing on the wire named a cause. That is different
/// from a cause of zero — which is a real Q.850 value — and the surfaces
/// omit the block entirely rather than reporting a default.
#[must_use]
pub fn detect_termination(messages: &[SipMessage]) -> Option<Termination> {
    messages.iter().enumerate().rev().find_map(|(idx, msg)| {
        cause_in_message(msg).map(|c| Termination {
            cause_code: c.cause_code,
            cause_text: c.cause_text,
            protocol: c.protocol,
            source_header: c.source_header.to_string(),
            frame_ref: idx,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(raw: &str) -> crate::sip::message::SipMessage {
        let ts =
            chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid fixture timestamp");
        let addr: std::net::IpAddr = "198.51.100.1".parse().expect("fixture address");
        crate::sip::parser::parse_sip(
            raw.replace('\n', "\r\n").as_bytes(),
            ts,
            addr,
            addr,
            5060,
            5060,
            crate::net::TransportProto::Udp,
        )
        .expect("fixture parses")
    }

    /// The two protocols RFC 3326 §2 names are not interchangeable, and a
    /// `cause_code` without one is ambiguous: `16` is normal clearing in
    /// Q.850 and is not a SIP status code at all.
    #[test]
    fn a_reason_value_carries_its_protocol() {
        let got = parse_reason_value(r#"Q.850;cause=16;text="Normal Clearing""#);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].protocol, "Q.850");
        assert_eq!(got[0].cause, Some(16));
        assert_eq!(got[0].text.as_deref(), Some("Normal Clearing"));
    }

    /// RFC 3326 §2 permits several reason-values in one header field,
    /// comma-separated, and a message MAY carry more than one `Reason` header.
    #[test]
    fn several_reason_values_in_one_field_are_all_read() {
        let got =
            parse_reason_value(r#"SIP;cause=200;text="Call completed elsewhere", Q.850;cause=16"#);
        assert_eq!(got.len(), 2, "got {got:?}");
        assert_eq!(got[0].protocol, "SIP");
        assert_eq!(got[0].cause, Some(200));
        assert_eq!(got[1].protocol, "Q.850");
        assert_eq!(got[1].cause, Some(16));
        assert_eq!(got[1].text, None);
    }

    /// A comma inside the quoted `text` is text, not a value separator.
    /// Splitting on every comma would cut one reason-value in half and invent
    /// a second protocol named after the rest of the sentence.
    #[test]
    fn a_comma_inside_quoted_text_does_not_split_the_value() {
        let got = parse_reason_value(r#"Q.850;cause=31;text="normal, unspecified""#);
        assert_eq!(got.len(), 1, "got {got:?}");
        assert_eq!(got[0].text.as_deref(), Some("normal, unspecified"));
    }

    /// `protocol` alone is a legal reason-value: RFC 3326's `reason-params`
    /// are optional. It says which side spoke without saying what it said,
    /// and reporting it as a missing cause is more honest than dropping it.
    #[test]
    fn a_protocol_with_no_parameters_is_still_a_reason() {
        let got = parse_reason_value("Q.850");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].cause, None);
        assert_eq!(got[0].text, None);
    }

    /// RFC 3261 §7.3.1 allows linear whitespace around `;` and `=`, and
    /// §7.3.1 makes parameter names case-insensitive. A parser that demands
    /// one spelling reports "no cause" on a message that carries one.
    #[test]
    fn whitespace_and_parameter_case_do_not_hide_a_cause() {
        for raw in [
            "Q.850 ; cause = 34",
            "Q.850;CAUSE=34",
            "Q.850;Cause=34",
            "  Q.850;cause=34  ",
        ] {
            let got = parse_reason_value(raw);
            assert_eq!(got.len(), 1, "{raw:?} -> {got:?}");
            assert_eq!(got[0].cause, Some(34), "{raw:?}");
        }
    }

    /// A cause that is not a number is reported as absent rather than as
    /// zero. Zero is a real Q.850 cause — the corpus carries `cause=0` — so
    /// coercing a parse failure into it would invent a value that a reader
    /// cannot tell from a measured one.
    #[test]
    fn an_unparsable_cause_is_absent_not_zero() {
        for raw in ["Q.850;cause=abc", "Q.850;cause=", "Q.850;cause=999999999"] {
            let got = parse_reason_value(raw);
            assert_eq!(got.len(), 1, "{raw:?}");
            assert_eq!(got[0].cause, None, "{raw:?} -> {got:?}");
        }
        // ...while a real zero survives.
        assert_eq!(parse_reason_value("Q.850;cause=0")[0].cause, Some(0));
    }

    /// A `Reason` on a `BYE` is the case this module exists for: the call
    /// connected, ran and ended, so there is no failure response to hang the
    /// cause on and the old reader found nothing.
    #[test]
    fn a_reason_on_a_bye_is_found() {
        let messages = vec![
            msg("INVITE sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 1 INVITE\n\n"),
            msg("SIP/2.0 200 OK\nCall-ID: c1\nCSeq: 1 INVITE\n\n"),
            msg("BYE sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 2 BYE\n\
                 Reason: Q.850;cause=38;text=\"Network out of order\"\n\n"),
        ];
        let t = detect_termination(&messages).expect("the BYE carries a cause");
        assert_eq!(t.cause_code, Some(38));
        assert_eq!(t.cause_text.as_deref(), Some("Network out of order"));
        assert_eq!(t.protocol.as_deref(), Some("Q.850"));
        assert_eq!(t.source_header, "Reason");
        assert_eq!(t.frame_ref, 2);
    }

    /// A `Reason` on a `CANCEL` is the other half of RFC 3326's own motivating
    /// case: `SIP;cause=200;text="Call completed elsewhere"` distinguishes a
    /// fork that lost from a caller who gave up, and both look like `487`.
    #[test]
    fn a_reason_on_a_cancel_is_found() {
        let messages = vec![
            msg("INVITE sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 1 INVITE\n\n"),
            msg(
                "CANCEL sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 1 CANCEL\n\
                 Reason: SIP;cause=200;text=\"Call completed elsewhere\"\n\n",
            ),
        ];
        let t = detect_termination(&messages).expect("the CANCEL carries a cause");
        assert_eq!(t.protocol.as_deref(), Some("SIP"));
        assert_eq!(t.cause_code, Some(200));
        assert_eq!(t.frame_ref, 1);
    }

    /// A `Reason` on a failure response still works — that path predates this
    /// module and must not regress.
    #[test]
    fn a_reason_on_a_failure_response_is_found() {
        let messages = vec![
            msg("INVITE sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 1 INVITE\n\n"),
            msg(
                "SIP/2.0 503 Service Unavailable\nCall-ID: c1\nCSeq: 1 INVITE\n\
                 Reason: Q.850;cause=34;text=\"no circuit available\"\n\n",
            ),
        ];
        let t = detect_termination(&messages).expect("the response carries a cause");
        assert_eq!(t.cause_code, Some(34));
    }

    /// The LAST cause in the dialog wins. A call that was challenged, retried
    /// and finally cleared has more than one, and the one that says why it
    /// ended is the last thing said.
    #[test]
    fn the_last_cause_in_the_dialog_is_the_termination() {
        let messages = vec![
            msg(
                "SIP/2.0 503 Service Unavailable\nCall-ID: c1\nCSeq: 1 INVITE\n\
                 Reason: Q.850;cause=34\n\n",
            ),
            msg("BYE sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 2 BYE\n\
                 Reason: Q.850;cause=16\n\n"),
        ];
        let t = detect_termination(&messages).expect("two causes, one termination");
        assert_eq!(t.cause_code, Some(16));
        assert_eq!(t.frame_ref, 1);
    }

    /// Where one message carries both protocols, the non-SIP one is reported.
    ///
    /// `SIP;cause=` restates the status code, which is already its own field
    /// on every surface; `Q.850;cause=` is the PSTN cause and is the fact that
    /// is not otherwise recoverable. Reporting the duplicate would spend the
    /// one `termination` block on the half a reader already has.
    #[test]
    fn a_gateway_cause_outranks_a_restatement_of_the_status_code() {
        let messages = vec![msg(
            "BYE sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 2 BYE\n\
             Reason: SIP;cause=200;text=\"Call completed elsewhere\"\n\
             Reason: Q.850;cause=16;text=\"Normal Clearing\"\n\n",
        )];
        let t = detect_termination(&messages).expect("both protocols present");
        assert_eq!(t.protocol.as_deref(), Some("Q.850"));
        assert_eq!(t.cause_code, Some(16));
    }

    /// Asterisk's pair is read as one cause: the code from
    /// `X-Asterisk-HangupCauseCode` and the text from `X-Asterisk-HangupCause`.
    ///
    /// Measured against the private corpus on 2026-09-08: BYEs carrying these
    /// headers carry NO `Reason` header, so this is the only cause available
    /// on those calls, and `triage_call` reported nothing for all of them.
    #[test]
    fn the_asterisk_pair_is_read_as_one_cause() {
        let messages = vec![msg(
            "BYE sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 2 BYE\n\
             X-Asterisk-HangupCauseCode: 38\n\
             X-Asterisk-HangupCause: Network out of order\n\n",
        )];
        let t = detect_termination(&messages).expect("the vendor pair is a cause");
        assert_eq!(t.cause_code, Some(38));
        assert_eq!(t.cause_text.as_deref(), Some("Network out of order"));
        // Asterisk's codes ARE Q.850 causes, and saying so is what lets a
        // reader compare them against the standard ones. The header the value
        // came from is reported separately, so nothing is laundered.
        assert_eq!(t.protocol.as_deref(), Some("Q.850"));
        assert_eq!(t.source_header, "X-Asterisk-HangupCauseCode");
    }

    /// The standard header outranks the vendor one where both appear. RFC
    /// 3326 is what every other implementation writes and reads.
    #[test]
    fn the_standard_header_outranks_the_vendor_one() {
        let messages = vec![msg(
            "BYE sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 2 BYE\n\
             Reason: Q.850;cause=16;text=\"Normal Clearing\"\n\
             X-Asterisk-HangupCauseCode: 38\n\
             X-Asterisk-HangupCause: Network out of order\n\n",
        )];
        let t = detect_termination(&messages).expect("both present");
        assert_eq!(t.source_header, "Reason");
        assert_eq!(t.cause_code, Some(16));
    }

    /// A dialog that says nothing about why it ended reports nothing, rather
    /// than a default that a reader cannot tell from a measured cause.
    #[test]
    fn a_dialog_with_no_cause_reports_none() {
        let messages = vec![
            msg("INVITE sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 1 INVITE\n\n"),
            msg("SIP/2.0 200 OK\nCall-ID: c1\nCSeq: 1 INVITE\n\n"),
            msg("BYE sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 2 BYE\n\n"),
        ];
        assert!(detect_termination(&messages).is_none());
        assert!(detect_termination(&[]).is_none());
    }

    /// A `Reason` naming a protocol and nothing else still identifies the
    /// message that ended the call, which is more than the old reader gave.
    #[test]
    fn a_cause_less_reason_still_locates_the_termination() {
        let messages = vec![msg(
            "BYE sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 2 BYE\nReason: Q.850\n\n",
        )];
        let t = detect_termination(&messages).expect("a protocol was named");
        assert_eq!(t.cause_code, None);
        assert_eq!(t.protocol.as_deref(), Some("Q.850"));
    }

    /// A control character in the cause text never reaches a renderer.
    ///
    /// The value is written to a terminal, into a Markdown table and into an
    /// agent's context. Stripping at the point the value is read is one rule;
    /// stripping at each renderer is three, and the third one is the one
    /// somebody forgets.
    #[test]
    fn control_characters_are_stripped_from_the_cause_text() {
        let got = parse_reason_value("Q.850;cause=16;text=\"a\u{1b}[31mb\u{7}c\"");
        assert_eq!(got[0].text.as_deref(), Some("a[31mbc"));
    }

    /// The one-line rendering says everything it has and nothing it does not.
    ///
    /// **First of two tests owed** for a gate run in 0.5.159. `summary()` is
    /// the shared formatter behind the text and Markdown reports, and it was
    /// pinned only through those — so its behavior on the sparse shapes the
    /// wire really produces (a protocol and no cause, a vendor code and no
    /// text) was covered by nothing.
    #[test]
    fn the_summary_renders_each_shape_the_wire_produces() {
        let base = Termination {
            cause_code: None,
            cause_text: None,
            protocol: None,
            source_header: "Reason".to_string(),
            frame_ref: 0,
        };

        // Everything present: scale, number, text, and where it came from.
        let full = Termination {
            cause_code: Some(38),
            cause_text: Some("Network out of order".to_string()),
            protocol: Some("Q.850".to_string()),
            ..base.clone()
        };
        assert_eq!(
            full.summary(),
            "Q.850 cause 38 \"Network out of order\" [Reason]"
        );

        // A `Reason` naming only a protocol: no cause to render, and nothing
        // invented in its place.
        let protocol_only = Termination {
            protocol: Some("Q.850".to_string()),
            ..base.clone()
        };
        assert_eq!(protocol_only.summary(), "Q.850 [Reason]");

        // The vendor pair with a code and no text.
        let code_only = Termination {
            cause_code: Some(17),
            protocol: Some("Q.850".to_string()),
            source_header: "X-Asterisk-HangupCauseCode".to_string(),
            ..base.clone()
        };
        assert_eq!(
            code_only.summary(),
            "Q.850 cause 17 [X-Asterisk-HangupCauseCode]"
        );

        // The vendor pair with text and no code, which happens when the
        // numeric header is absent or unparsable.
        let text_only = Termination {
            cause_text: Some("User busy".to_string()),
            protocol: Some("Q.850".to_string()),
            source_header: "X-Asterisk-HangupCauseCode".to_string(),
            ..base
        };
        assert_eq!(
            text_only.summary(),
            "Q.850 \"User busy\" [X-Asterisk-HangupCauseCode]"
        );
    }

    /// **Second of two.** The source header is in every rendering, always.
    ///
    /// What a vendor header asserts and what RFC 3326 asserts are not the same
    /// claim, and the whole reason `source_header` is a field is that a reader
    /// deciding how far to trust the number needs to know which one this is. A
    /// rendering that dropped it on some shape would take that away exactly
    /// where the answer is thinnest.
    #[test]
    fn every_summary_names_the_header_the_cause_came_from() {
        for (code, text, protocol) in [
            (Some(16u16), Some("Normal Clearing"), Some("Q.850")),
            (Some(200), None, Some("SIP")),
            (None, Some("User busy"), None),
            (None, None, Some("Q.850")),
            (None, None, None),
        ] {
            for header in ["Reason", "X-Asterisk-HangupCauseCode"] {
                let t = Termination {
                    cause_code: code,
                    cause_text: text.map(str::to_string),
                    protocol: protocol.map(str::to_string),
                    source_header: header.to_string(),
                    frame_ref: 0,
                };
                let rendered = t.summary();
                assert!(
                    rendered.ends_with(&format!("[{header}]")),
                    "{rendered:?} does not attribute the cause to {header}"
                );
            }
        }
    }

    /// The header value is data a remote wrote. It reaches an agent's context
    /// through `triage_call`, so it is bounded here rather than at each
    /// surface — one rule, applied where the value is read.
    #[test]
    fn an_enormous_cause_text_is_bounded() {
        let long = "A".repeat(4096);
        let messages = vec![msg(&format!(
            "BYE sip:b@example.net SIP/2.0\nCall-ID: c1\nCSeq: 2 BYE\n\
             Reason: Q.850;cause=16;text=\"{long}\"\n\n",
        ))];
        let t = detect_termination(&messages).expect("a cause is present");
        let text = t.cause_text.expect("text is present");
        assert!(
            text.chars().count() <= MAX_CAUSE_TEXT_CHARS,
            "cause_text is {} chars, over the {MAX_CAUSE_TEXT_CHARS} bound",
            text.chars().count()
        );
    }
}
