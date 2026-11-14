// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The matcher behind the `search_messages` tool, and its limits.
//!
//! # Two ways to match
//!
//! Without `regex`, or with `regex: false`, a query is a substring and the
//! match ignores ASCII case. With `regex: true` the query is a regular
//! expression, compiled by [`crate::sip::dsl::compile_payload_regex`], the
//! function the filter DSL's `payload =~` uses, and matched against the raw
//! bytes of each message. The two surfaces share the engine, the bytes and
//! the compile size limit, so they cannot disagree about a capture.
//!
//! # What bounds a hostile pattern
//!
//! - [`MAX_REGEX_QUERY_BYTES`]: a longer pattern is refused before it is
//!   compiled.
//! - [`crate::sip::dsl::REGEX_SIZE_LIMIT`]: a pattern whose compiled program
//!   is larger is refused by the regex crate.
//! - The regex crate has no look-around and no backreferences, and its match
//!   time is linear in the size of the message for a compiled program of a
//!   bounded size.
//! - [`REGEX_SCAN_BUDGET`]: the scan of the whole store reads the clock before
//!   each message and stops with a refusal once the budget has passed. The
//!   scan holds the store's read lock, so this is also the longest time a
//!   regex search can hold it, plus the time of one message.
//!
//! The clock is an argument of [`scan`], so a test drives both sides of the
//! time limit without waiting.

use std::time::Duration;

use super::errors::{self, Reason};
use crate::sip::SipMessage;
use crate::sip::dialog::SipDialog;
use crate::sip::dsl::{REGEX_SIZE_LIMIT, compile_payload_regex};

/// The longest `query`, in bytes, that `regex: true` accepts.
pub(crate) const MAX_REGEX_QUERY_BYTES: usize = 1024;

/// The longest time one regex search may spend scanning the store.
pub(crate) const REGEX_SCAN_BUDGET: Duration = Duration::from_secs(5);

/// Why a search was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The query is the empty string.
    EmptyQuery,
    /// A regex query longer than [`MAX_REGEX_QUERY_BYTES`].
    PatternTooLong {
        /// The query's length in bytes.
        bytes: usize,
    },
    /// A regex query whose compiled program passes [`REGEX_SIZE_LIMIT`].
    PatternTooBig,
    /// A regex query the regex crate does not accept.
    PatternInvalid {
        /// The regex crate's one-line reason.
        detail: String,
    },
    /// The scan passed [`REGEX_SCAN_BUDGET`].
    ScanTimeLimit {
        /// Messages scanned before the scan stopped.
        scanned: usize,
    },
}

impl Refusal {
    /// The reason code a client reads in `data.reason`.
    pub(crate) fn reason(&self) -> Reason {
        match self {
            Refusal::EmptyQuery | Refusal::PatternInvalid { .. } => Reason::InvalidValue,
            Refusal::PatternTooLong { .. }
            | Refusal::PatternTooBig
            | Refusal::ScanTimeLimit { .. } => Reason::LimitExceeded,
        }
    }

    /// The one-line message of the refusal.
    pub(crate) fn message(&self) -> String {
        match self {
            Refusal::EmptyQuery => "query must be non-empty".to_string(),
            Refusal::PatternTooLong { bytes } => format!(
                "query is {bytes} bytes; with regex true a query is at most \
                 {MAX_REGEX_QUERY_BYTES} bytes"
            ),
            Refusal::PatternTooBig => format!(
                "query compiles to more than {REGEX_SIZE_LIMIT} bytes; use fewer or smaller \
                 repetitions"
            ),
            Refusal::PatternInvalid { detail } => {
                format!("query is not a valid regular expression: {detail}")
            }
            Refusal::ScanTimeLimit { scanned } => format!(
                "the regex search passed its {} s limit after {scanned} messages; use a simpler \
                 pattern",
                REGEX_SCAN_BUDGET.as_secs()
            ),
        }
    }

    /// The `invalid_params` error for this refusal, naming `query`.
    pub(crate) fn into_error(self) -> rmcp::ErrorData {
        errors::refuse_param(self.reason(), "query", self.message())
    }
}

/// How one search decides whether a message is a hit.
#[derive(Debug)]
pub(crate) enum Matcher {
    /// The query, ASCII-lowercased, as a substring that ignores ASCII case.
    Substring(Vec<u8>),
    /// The query as a regular expression over the raw message bytes.
    Regex(regex::bytes::Regex),
}

/// Builds the matcher for `query`.
///
/// # Errors
///
/// [`Refusal::EmptyQuery`] for an empty query. With `regex` true also
/// [`Refusal::PatternTooLong`], [`Refusal::PatternTooBig`] and
/// [`Refusal::PatternInvalid`].
pub(crate) fn search_matcher(query: &str, regex: bool) -> Result<Matcher, Refusal> {
    if query.is_empty() {
        return Err(Refusal::EmptyQuery);
    }
    if !regex {
        return Ok(Matcher::Substring(query.to_ascii_lowercase().into_bytes()));
    }
    // Length first: a pattern over the limit is never handed to the parser.
    if query.len() > MAX_REGEX_QUERY_BYTES {
        return Err(Refusal::PatternTooLong { bytes: query.len() });
    }
    match compile_payload_regex(query) {
        Ok(re) => Ok(Matcher::Regex(re)),
        Err(regex::Error::CompiledTooBig(_)) => Err(Refusal::PatternTooBig),
        Err(e) => Err(Refusal::PatternInvalid {
            detail: one_line_reason(&e.to_string()),
        }),
    }
}

/// The regex crate's reason as one line.
///
/// A syntax error is printed over several lines: the pattern, a marker under
/// the fault, and a last line `error: <reason>`. The reason alone is kept. A
/// message of another shape is kept whole, with its line ends as spaces.
fn one_line_reason(text: &str) -> String {
    let reason = text
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix("error: "));
    match reason {
        Some(reason) => reason.to_string(),
        None => text.split_whitespace().collect::<Vec<_>>().join(" "),
    }
}

impl Matcher {
    /// True when `msg` is a hit.
    pub(crate) fn matches(&self, msg: &SipMessage) -> bool {
        match self {
            Matcher::Substring(needle) => substring_hit(msg, needle),
            Matcher::Regex(re) => re.is_match(&msg.raw),
        }
    }

    /// True for a matcher whose scan the time limit bounds.
    fn is_timed(&self) -> bool {
        matches!(self, Matcher::Regex(_))
    }
}

/// The substring match: cheap borrowed fields first, the whole message last.
///
/// The fields hit most queries without a scan of the whole message. The raw
/// bytes come last and make the answer agree with the filter DSL's `payload`.
fn substring_hit(msg: &SipMessage, needle: &[u8]) -> bool {
    let status = msg.status_code.map(|s| s.to_string());
    let body = String::from_utf8_lossy(&msg.body);
    let field = |text: Option<&str>| contains_ci(text.unwrap_or("").as_bytes(), needle);
    field(msg.method.as_ref().map(|m| m.as_str()))
        || field(status.as_deref())
        || field(msg.from_header())
        || field(msg.to_header())
        || field(msg.user_agent())
        || contains_ci(body.as_bytes(), needle)
        || contains_ci(&msg.raw, needle)
}

/// Is `needle` (already ASCII-lowercased) in `haystack`, ignoring ASCII case?
///
/// No allocation: each window is compared in place.
pub(crate) fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.iter().zip(needle).all(|(a, b)| a.eq_ignore_ascii_case(b)))
}

/// Every message of `dialogs` that `matcher` hits, as (dialog, message index),
/// in the order the dialogs and their messages are given.
///
/// `expired` is the clock: it answers true once the scan's time is used up.
/// A regex scan asks it before each message. A substring scan never asks.
///
/// # Errors
///
/// [`Refusal::ScanTimeLimit`] when `expired` answers true before a message of
/// a regex scan.
pub(crate) fn scan<'a>(
    dialogs: impl Iterator<Item = &'a SipDialog>,
    matcher: &Matcher,
    expired: &mut dyn FnMut() -> bool,
) -> Result<Vec<(&'a SipDialog, usize)>, Refusal> {
    let timed = matcher.is_timed();
    let mut scanned = 0usize;
    let mut hits = Vec::new();
    for dialog in dialogs {
        for (index, msg) in dialog.messages.iter().enumerate() {
            if timed && expired() {
                return Err(Refusal::ScanTimeLimit { scanned });
            }
            scanned += 1;
            if matcher.matches(msg) {
                hits.push((dialog, index));
            }
        }
    }
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::rtp::diagnosis::CaptureMedia;
    use crate::rtp::quality::MosDelay;
    use crate::sip::dialog_store::DialogStore;
    use crate::sip::dsl::FilterExpr;
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;
    use std::net::{IpAddr, Ipv4Addr};

    type TestError = Box<dyn std::error::Error>;

    /// An SDP body; the bytes after `s=` are not valid UTF-8.
    const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=\xff\xfe tail-token\r\n\
                         c=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 49170 RTP/AVP 0 8\r\n";

    fn parse(raw: &[u8]) -> Result<SipMessage, TestError> {
        let host = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let at = chrono::DateTime::UNIX_EPOCH + chrono::TimeDelta::seconds(1_718_452_800);
        Ok(
            parse_sip(raw, at, host, host, 5060, 5060, TransportProto::Udp)
                .map_err(|e| format!("the fixture should parse as SIP: {e:?}"))?,
        )
    }

    /// An INVITE with an SDP body.
    fn invite(call_id: &str) -> Result<SipMessage, TestError> {
        let length = format!("Content-Length: {}", SDP.len());
        parse(&build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK0a1b2c",
                "From: Alice <sip:+12025550100@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Max-Forwards: 70",
                "User-Agent: TestUA/1.0",
                "Content-Type: application/sdp",
                &length,
            ],
            SDP,
        ))
    }

    /// The 200 OK that answers [`invite`], without a body.
    fn ok200(call_id: &str) -> Result<SipMessage, TestError> {
        parse(&build_sip(
            "SIP/2.0 200 OK",
            &[
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK0a1b2c",
                "From: Alice <sip:+12025550100@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Contact: <sip:bob@192.0.2.20>",
                "Content-Length: 0",
            ],
            b"",
        ))
    }

    /// A store of `n` dialogs, an INVITE and its 200 OK in each.
    fn store(n: usize) -> Result<DialogStore, TestError> {
        let mut ds = DialogStore::new(100, false);
        for i in 0..n {
            let call_id = format!("call-{i}@example.com");
            ds.process_message(invite(&call_id)?);
            ds.process_message(ok200(&call_id)?);
        }
        Ok(ds)
    }

    fn regex(pattern: &str) -> Result<Matcher, TestError> {
        Ok(search_matcher(pattern, true).map_err(|r| format!("{pattern:?} refused: {r:?}"))?)
    }

    /// Does the regex `pattern` hit the INVITE, and does it hit the 200 OK?
    fn regex_hits(pattern: &str) -> Result<(bool, bool), TestError> {
        let m = regex(pattern)?;
        Ok((
            m.matches(&invite("a@example.com")?),
            m.matches(&ok200("a@example.com")?),
        ))
    }

    fn refusal(pattern: &str) -> Result<Refusal, TestError> {
        match search_matcher(pattern, true) {
            Ok(m) => Err(format!("{pattern:?} was accepted as {m:?}").into()),
            Err(r) => Ok(r),
        }
    }

    fn never() -> impl FnMut() -> bool {
        || false
    }

    // ── success ──────────────────────────────────────────────────────

    #[test]
    fn regex_alternation_hits_either_branch() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("REGISTER sip:|INVITE sip:")?,
            (true, false),
            "only the INVITE's request line holds a branch of the alternation"
        );
        Ok(())
    }

    #[test]
    fn regex_line_anchors_work_in_multi_line_mode() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("(?m)^Max-Forwards: 70\r$")?,
            (true, false),
            "(?m) anchors at each line of the message"
        );
        Ok(())
    }

    #[test]
    fn regex_class_and_counted_repetition_hit() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("branch=z9hG4bK[0-9a-f]{6};?")?,
            (true, true),
            "both messages carry the six-digit hex branch"
        );
        Ok(())
    }

    #[test]
    fn regex_inline_flag_ignores_case() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("(?i)testua/1\\.0")?,
            (true, false),
            "(?i) matches TestUA/1.0 in the INVITE"
        );
        Ok(())
    }

    #[test]
    fn regex_hits_text_that_is_only_in_the_body() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("m=audio \\d+ RTP/AVP")?,
            (true, false),
            "the media line is in the INVITE's SDP body only"
        );
        Ok(())
    }

    #[test]
    fn regex_hits_a_header_outside_the_named_fields() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("Contact: <sip:[a-z]+@192\\.0\\.2\\.\\d+>")?,
            (false, true),
            "Contact is in the 200 OK only"
        );
        Ok(())
    }

    #[test]
    fn regex_start_anchor_selects_responses_by_class() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("^SIP/2\\.0 2\\d\\d ")?,
            (false, true),
            "^ is the start of the message, where only the response has a status line"
        );
        Ok(())
    }

    #[test]
    fn regex_word_boundary_hits() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("\\bbob\\b")?,
            (true, true),
            "bob is a whole word in both"
        );
        assert_eq!(
            regex_hits("\\bbo\\b")?,
            (false, false),
            "bo is not a whole word"
        );
        Ok(())
    }

    #[test]
    fn regex_hits_a_phone_number_by_shape() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("\\+1202555\\d{4}@")?,
            (true, true),
            "From carries +12025550100 in both messages"
        );
        Ok(())
    }

    #[test]
    fn regex_hits_across_a_line_end() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("CSeq: 1 INVITE\r\nMax-Forwards")?,
            (true, false),
            "the raw bytes hold the CRLF between two headers"
        );
        Ok(())
    }

    #[test]
    fn scan_returns_every_regex_hit_in_store_order() -> Result<(), TestError> {
        let ds = store(3)?;
        let hits = scan(ds.iter(), &regex("^INVITE ")?, &mut never())
            .map_err(|r| format!("scan refused: {r:?}"))?;
        let got: Vec<(String, usize)> = hits.iter().map(|(d, i)| (d.call_id.clone(), *i)).collect();
        let want: Vec<(String, usize)> = ds.iter().map(|d| (d.call_id.clone(), 0)).collect();
        assert_eq!(
            got, want,
            "one hit per dialog, at message 0, in store order"
        );
        Ok(())
    }

    #[test]
    fn scan_asks_the_clock_once_before_each_message() -> Result<(), TestError> {
        let ds = store(4)?;
        let mut asked = 0usize;
        let hits = scan(ds.iter(), &regex("OK")?, &mut || {
            asked += 1;
            false
        })
        .map_err(|r| format!("scan refused: {r:?}"))?;
        assert_eq!(hits.len(), 4, "each 200 OK is a hit");
        assert_eq!(
            asked, 8,
            "the clock is read once for each of the 8 messages"
        );
        Ok(())
    }

    #[test]
    fn regex_and_the_payload_filter_agree_on_every_dialog() -> Result<(), TestError> {
        let mut ds = store(2)?;
        ds.process_message(ok200("lonely@example.com")?);
        for pattern in [
            "^INVITE ",
            "RTP/AVP 0 8",
            "(?i)CONTACT:",
            "tag=t2$",
            "no-such-token",
        ] {
            let filter = FilterExpr::parse(&format!("payload =~ '{pattern}'"))?;
            let by_filter: Vec<&str> = ds
                .iter()
                .filter(|d| {
                    filter.matches_dialog(d, &[], CaptureMedia::Absent, MosDelay::unknown())
                })
                .map(|d| d.call_id.as_str())
                .collect();
            let mut by_search: Vec<&str> = scan(ds.iter(), &regex(pattern)?, &mut never())
                .map_err(|r| format!("scan refused: {r:?}"))?
                .iter()
                .map(|(d, _)| d.call_id.as_str())
                .collect();
            by_search.dedup();
            assert_eq!(by_search, by_filter, "pattern {pattern:?}");
        }
        Ok(())
    }

    // ── failure ──────────────────────────────────────────────────────

    #[test]
    fn regex_with_an_unclosed_group_is_refused() -> Result<(), TestError> {
        let r = refusal("(INVITE")?;
        assert!(
            matches!(&r, Refusal::PatternInvalid { detail } if detail.contains("unclosed group")),
            "got {r:?}"
        );
        assert_eq!(r.reason(), Reason::InvalidValue, "a malformed value");
        Ok(())
    }

    #[test]
    fn regex_with_an_unclosed_class_is_refused() -> Result<(), TestError> {
        let r = refusal("[a-z")?;
        assert!(
            matches!(&r, Refusal::PatternInvalid { detail } if detail.contains("unclosed character class")),
            "got {r:?}"
        );
        Ok(())
    }

    #[test]
    fn regex_with_a_dangling_repetition_is_refused() -> Result<(), TestError> {
        let r = refusal("*INVITE")?;
        assert!(matches!(r, Refusal::PatternInvalid { .. }), "got {r:?}");
        Ok(())
    }

    #[test]
    fn regex_look_ahead_is_refused() -> Result<(), TestError> {
        let r = refusal("INVITE(?=.*bob)")?;
        assert!(
            matches!(&r, Refusal::PatternInvalid { detail } if detail.contains("look-around")),
            "got {r:?}"
        );
        Ok(())
    }

    #[test]
    fn regex_backreference_is_refused() -> Result<(), TestError> {
        let r = refusal("(tag)=\\1")?;
        assert!(
            matches!(&r, Refusal::PatternInvalid { detail } if detail.contains("backreference")),
            "got {r:?}"
        );
        Ok(())
    }

    #[test]
    fn regex_with_a_bad_hex_escape_is_refused() -> Result<(), TestError> {
        let r = refusal("\\xZZ")?;
        assert!(matches!(r, Refusal::PatternInvalid { .. }), "got {r:?}");
        Ok(())
    }

    #[test]
    fn regex_nested_past_the_parser_limit_is_refused() -> Result<(), TestError> {
        let pattern = format!("{}a{}", "(".repeat(300), ")".repeat(300));
        assert!(
            pattern.len() <= MAX_REGEX_QUERY_BYTES,
            "the length limit is not what refuses"
        );
        let r = refusal(&pattern)?;
        assert!(
            matches!(&r, Refusal::PatternInvalid { detail } if detail.contains("nested parentheses")),
            "got {r:?}"
        );
        Ok(())
    }

    #[test]
    fn regex_longer_than_the_length_limit_is_refused() -> Result<(), TestError> {
        let r = refusal(&"a".repeat(MAX_REGEX_QUERY_BYTES + 1))?;
        assert_eq!(
            r,
            Refusal::PatternTooLong { bytes: 1025 },
            "one byte past the limit"
        );
        assert_eq!(r.reason(), Reason::LimitExceeded, "a ceiling of the server");
        Ok(())
    }

    #[test]
    fn regex_that_compiles_past_the_size_limit_is_refused() -> Result<(), TestError> {
        let r = refusal("(?:[a-z]{1000}){1000}")?;
        assert_eq!(
            r,
            Refusal::PatternTooBig,
            "a 21-byte pattern with a million states"
        );
        assert_eq!(r.reason(), Reason::LimitExceeded, "a ceiling of the server");
        Ok(())
    }

    /// The limit that refuses is sipnab's 1000000 bytes, not the regex
    /// crate's own larger default: this pattern compiles under the default.
    #[test]
    fn the_size_limit_is_the_shared_one_not_the_crates_default() -> Result<(), TestError> {
        let pattern = "(?:[a-z]{200}){200}";
        assert!(
            regex::bytes::Regex::new(pattern).is_ok(),
            "the fixture must compile under the crate's default limit, or it proves nothing"
        );
        assert_eq!(
            refusal(pattern)?,
            Refusal::PatternTooBig,
            "40000 states pass the shared limit of {REGEX_SIZE_LIMIT} bytes"
        );
        let filter = FilterExpr::parse(&format!("payload =~ '{pattern}'"));
        assert!(
            filter.is_err(),
            "`payload =~` compiles through the same function and refuses it too"
        );
        Ok(())
    }

    #[test]
    fn a_long_hostile_pattern_is_refused_for_length_before_it_is_compiled() -> Result<(), TestError>
    {
        // 2000 bytes that would also fail to parse: the length is what the
        // refusal names, so the parser never saw it.
        let r = refusal(&"(".repeat(2000))?;
        assert_eq!(
            r,
            Refusal::PatternTooLong { bytes: 2000 },
            "length is checked first"
        );
        Ok(())
    }

    #[test]
    fn regex_with_an_empty_query_is_refused() -> Result<(), TestError> {
        assert_eq!(
            refusal("")?,
            Refusal::EmptyQuery,
            "an empty pattern would hit everything"
        );
        Ok(())
    }

    #[test]
    fn scan_stops_at_once_when_the_time_is_already_used_up() -> Result<(), TestError> {
        let ds = store(2)?;
        let r = scan(ds.iter(), &regex("INVITE")?, &mut || true);
        assert_eq!(
            r.err(),
            Some(Refusal::ScanTimeLimit { scanned: 0 }),
            "no message is scanned after the limit"
        );
        Ok(())
    }

    #[test]
    fn scan_stops_part_way_and_says_how_far_it_got() -> Result<(), TestError> {
        let ds = store(5)?;
        let mut asked = 0usize;
        let r = scan(ds.iter(), &regex("INVITE")?, &mut || {
            asked += 1;
            asked > 3
        });
        assert_eq!(
            r.err(),
            Some(Refusal::ScanTimeLimit { scanned: 3 }),
            "three messages were scanned before the fourth reading of the clock"
        );
        Ok(())
    }

    #[test]
    fn a_stopped_scan_returns_no_partial_hits() -> Result<(), TestError> {
        // A partial list would carry a total_matched that reads as the whole
        // store's.
        let ds = store(3)?;
        let mut asked = 0usize;
        let r = scan(ds.iter(), &regex("INVITE")?, &mut || {
            asked += 1;
            asked > 5
        });
        assert!(
            r.is_err(),
            "the five scanned messages held hits, and none is returned: {r:?}"
        );
        Ok(())
    }

    #[test]
    fn every_refusal_message_is_one_line_and_names_its_limit() -> Result<(), TestError> {
        let cases = [
            (Refusal::EmptyQuery, "non-empty".to_string()),
            (
                Refusal::PatternTooLong { bytes: 2000 },
                format!("at most {MAX_REGEX_QUERY_BYTES} bytes"),
            ),
            (
                Refusal::PatternTooBig,
                format!("more than {REGEX_SIZE_LIMIT} bytes"),
            ),
            (
                Refusal::PatternInvalid {
                    detail: "unclosed group".into(),
                },
                "unclosed group".to_string(),
            ),
            (
                Refusal::ScanTimeLimit { scanned: 7 },
                format!("{} s limit after 7 messages", REGEX_SCAN_BUDGET.as_secs()),
            ),
        ];
        for (refusal, part) in cases {
            let text = refusal.message();
            assert!(text.contains(&part), "{text:?} lacks {part:?}");
            assert!(!text.contains('\n'), "{text:?} is more than one line");
        }
        Ok(())
    }

    #[test]
    fn a_refusal_becomes_invalid_params_naming_query() -> Result<(), TestError> {
        for (refusal, reason) in [
            (refusal("(a")?, "invalid_value"),
            (refusal(&"a".repeat(1025))?, "limit_exceeded"),
            (Refusal::ScanTimeLimit { scanned: 1 }, "limit_exceeded"),
        ] {
            let text = refusal.message();
            let json = serde_json::to_value(refusal.into_error())?;
            assert_eq!(json["code"], -32602, "{text}");
            assert_eq!(json["data"]["param"], "query", "{text}");
            assert_eq!(json["data"]["reason"], reason, "{text}");
            assert_eq!(
                json["message"],
                text.as_str(),
                "the message is passed whole"
            );
        }
        Ok(())
    }

    // ── edge ─────────────────────────────────────────────────────────

    #[test]
    fn regex_that_matches_the_empty_string_hits_every_message() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("x*")?,
            (true, true),
            "x* matches at offset 0 of any message"
        );
        Ok(())
    }

    #[test]
    fn regex_of_a_flag_group_alone_hits_every_message() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("(?i)")?,
            (true, true),
            "an empty pattern after the flag"
        );
        Ok(())
    }

    #[test]
    fn regex_is_case_sensitive_unless_the_pattern_says_otherwise() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("invite sip:")?,
            (false, false),
            "no lower-case request line"
        );
        let substring = search_matcher("invite sip:", false).map_err(|r| format!("{r:?}"))?;
        assert!(
            substring.matches(&invite("a@example.com")?),
            "the same text as a substring ignores case"
        );
        Ok(())
    }

    #[test]
    fn regex_dot_stops_at_a_line_end_unless_s_is_set() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("INVITE sip:.*Max-Forwards")?,
            (false, false),
            ". is not \\n"
        );
        assert_eq!(
            regex_hits("(?s)INVITE sip:.*Max-Forwards")?,
            (true, false),
            "(?s) lets . be \\n"
        );
        Ok(())
    }

    #[test]
    fn regex_end_anchor_needs_crlf_mode_on_a_sip_line() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("(?m)^Max-Forwards: 70$")?,
            (false, false),
            "(?m)$ is before \\n, and a SIP line ends \\r\\n"
        );
        assert_eq!(
            regex_hits("(?mR)^Max-Forwards: 70$")?,
            (true, false),
            "(?R) is CRLF mode"
        );
        Ok(())
    }

    #[test]
    fn regex_scans_a_body_that_is_not_utf8() -> Result<(), TestError> {
        assert_eq!(
            regex_hits("tail-token")?,
            (true, false),
            "text after the bad bytes is found"
        );
        assert_eq!(
            regex_hits("(?-u)s=\\xff\\xfe ")?,
            (true, false),
            "the bytes themselves match"
        );
        assert_eq!(
            regex_hits("s=.. tail")?,
            (false, false),
            "a Unicode . matches no byte that is not UTF-8"
        );
        assert_eq!(
            regex_hits("(?-u)s=.. tail")?,
            (true, false),
            "a byte . matches any byte"
        );
        Ok(())
    }

    #[test]
    fn a_metacharacter_is_literal_unless_regex_is_true() -> Result<(), TestError> {
        let msg = invite("a@example.com")?;
        let literal = search_matcher("Test.A/1", false).map_err(|r| format!("{r:?}"))?;
        assert!(
            !literal.matches(&msg),
            "no literal `Test.A/1` in the message"
        );
        assert!(
            regex("Test.A/1")?.matches(&msg),
            "as a regex, . is the U of TestUA"
        );
        let dotted = search_matcher("TestUA/1.0", false).map_err(|r| format!("{r:?}"))?;
        assert!(dotted.matches(&msg), "a literal dot matches a dot");
        Ok(())
    }

    #[test]
    fn regex_false_builds_the_substring_matcher() -> Result<(), TestError> {
        let m = search_matcher("(INVITE", false).map_err(|r| format!("{r:?}"))?;
        assert!(
            matches!(&m, Matcher::Substring(n) if n == b"(invite"),
            "an unbalanced pattern is a legal substring, lower-cased: {m:?}"
        );
        Ok(())
    }

    #[test]
    fn the_length_limit_is_inclusive() -> Result<(), TestError> {
        let at_limit = format!("INVITE|{}", "a".repeat(MAX_REGEX_QUERY_BYTES - 7));
        assert_eq!(at_limit.len(), 1024, "the fixture is exactly at the limit");
        assert!(
            regex(&at_limit)?.matches(&invite("a@example.com")?),
            "1024 bytes compile and match"
        );
        Ok(())
    }

    #[test]
    fn the_length_limit_counts_bytes_not_characters() -> Result<(), TestError> {
        let fits = "é".repeat(512);
        assert!(
            search_matcher(&fits, true).is_ok(),
            "512 two-byte characters are 1024 bytes"
        );
        let over = "é".repeat(513);
        assert_eq!(
            refusal(&over)?,
            Refusal::PatternTooLong { bytes: 1026 },
            "513 characters, 1026 bytes"
        );
        Ok(())
    }

    #[test]
    fn the_length_limit_does_not_apply_to_a_substring() -> Result<(), TestError> {
        let m = search_matcher(&"a".repeat(5000), false);
        assert!(
            m.is_ok(),
            "a substring query had no length limit before this option: {m:?}"
        );
        Ok(())
    }

    #[test]
    fn scan_of_an_empty_store_never_reads_the_clock() -> Result<(), TestError> {
        let ds = store(0)?;
        let hits = scan(ds.iter(), &regex("INVITE")?, &mut || true);
        assert_eq!(
            hits.map(|h| h.len()),
            Ok(0),
            "nothing to scan, so nothing to refuse"
        );
        Ok(())
    }

    #[test]
    fn a_substring_scan_has_no_time_limit() -> Result<(), TestError> {
        let ds = store(2)?;
        let m = search_matcher("invite", false).map_err(|r| format!("{r:?}"))?;
        let hits = scan(ds.iter(), &m, &mut || true);
        assert_eq!(
            hits.map(|h| h.len()),
            Ok(4),
            "all four messages name INVITE, and the clock is not asked"
        );
        Ok(())
    }

    #[test]
    fn a_scan_that_ends_as_the_time_runs_out_is_whole() -> Result<(), TestError> {
        let ds = store(2)?;
        let mut asked = 0usize;
        let hits = scan(ds.iter(), &regex("^INVITE ")?, &mut || {
            asked += 1;
            asked > 4
        });
        assert_eq!(
            hits.map(|h| h.len()),
            Ok(2),
            "the clock is not read after the last message, so a finished scan stands"
        );
        Ok(())
    }

    #[test]
    fn contains_ci_folds_case_and_bounds() -> Result<(), TestError> {
        assert!(contains_ci(b"Hello WORLD", b"world"), "case is folded");
        assert!(contains_ci(b"INVITE", b"invite"), "the whole haystack");
        assert!(
            contains_ci(b"User-Agent: TestUA/1.0", b"testua"),
            "inside a header"
        );
        assert!(!contains_ci(b"hello", b"xyz"), "no byte in common");
        assert!(
            contains_ci(b"abc", b""),
            "the empty needle is in everything"
        );
        assert!(
            !contains_ci(b"ab", b"abc"),
            "a needle longer than the haystack"
        );
        assert!(!contains_ci(b"abc", b"abx"), "a near miss");
        Ok(())
    }

    // ── the docs say what the code does ──────────────────────────────

    /// The text of `docs/<page>` from the heading line `heading` to the next
    /// heading of the same or a higher level.
    fn doc_section(page: &str, heading: &str) -> Result<String, TestError> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs")
            .join(page);
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let level = heading.chars().take_while(|c| *c == '#').count();
        let mut section = String::new();
        let mut inside = false;
        for line in text.lines() {
            if line == heading {
                inside = true;
            } else if inside {
                let hashes = line.chars().take_while(|c| *c == '#').count();
                if hashes > 0 && hashes <= level && line[hashes..].starts_with(' ') {
                    break;
                }
            }
            if inside {
                section.push_str(line);
                section.push('\n');
            }
        }
        if section.is_empty() {
            return Err(format!("docs/{page} has no heading line {heading:?}").into());
        }
        Ok(section)
    }

    /// The fixed text of each regex refusal, and the three limits as written.
    fn documented_facts() -> Vec<String> {
        let fixed = |r: Refusal, cut: &str| -> String {
            let text = r.message();
            text.split(cut).last().unwrap_or(&text).trim().to_string()
        };
        vec![
            fixed(Refusal::PatternTooLong { bytes: 7 }, "7 bytes;"),
            fixed(Refusal::PatternTooBig, "query "),
            fixed(Refusal::PatternInvalid { detail: "X".into() }, "query ").replace(": X", ""),
            fixed(Refusal::ScanTimeLimit { scanned: 7 }, "the regex search ")
                .replace(" after 7 messages; use a simpler pattern", ""),
            format!("{MAX_REGEX_QUERY_BYTES} bytes"),
            format!("{REGEX_SIZE_LIMIT} bytes"),
            format!("{} s", REGEX_SCAN_BUDGET.as_secs()),
        ]
    }

    #[test]
    fn the_documented_facts_are_the_fragments_the_pages_must_hold() -> Result<(), TestError> {
        assert_eq!(
            documented_facts(),
            [
                "with regex true a query is at most 1024 bytes",
                "compiles to more than 1000000 bytes; use fewer or smaller repetitions",
                "is not a valid regular expression",
                "passed its 5 s limit",
                "1024 bytes",
                "1000000 bytes",
                "5 s",
            ],
            "the fragments are cut from the refusal messages and the constants"
        );
        Ok(())
    }

    #[test]
    fn the_tool_reference_states_the_regex_option_its_limits_and_refusals() -> Result<(), TestError>
    {
        let section = doc_section("mcp-tools-core.md", "### `search_messages`")?;
        for fact in documented_facts().iter().map(String::as_str).chain([
            "| `regex?` | bool? |",
            "limit_exceeded",
            "invalid_value",
            "payload =~",
            "(mcp.md#search-messages-with-a-regular-expression)",
        ]) {
            assert!(
                section.contains(fact),
                "the search_messages reference lacks {fact:?}"
            );
        }
        assert!(
            !section.contains("method, status, From"),
            "the reference still lists a closed set of fields; the search reads the whole message"
        );
        Ok(())
    }

    #[test]
    fn the_how_to_has_every_part_and_the_limits() -> Result<(), TestError> {
        let section = doc_section("mcp.md", "## Search messages with a regular expression")?;
        for part in [
            "### Before you start a regex search",
            "**No change on any other system",
            "### Run a regex search",
            "### Check that the regex search worked",
            "### When a regex search does not work",
            "\"regex\":true",
        ] {
            assert!(section.contains(part), "the how-to lacks {part:?}");
        }
        for fact in documented_facts() {
            assert!(section.contains(&fact), "the how-to lacks {fact:?}");
        }
        Ok(())
    }

    #[test]
    fn the_tool_tables_name_the_regex_option() -> Result<(), TestError> {
        for page in ["mcp-tools-core.md", "mcp-tools.md"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("docs")
                .join(page);
            let text = std::fs::read_to_string(&path)?;
            let row = text
                .lines()
                .find(|l| l.starts_with("| [`search_messages`]("))
                .ok_or_else(|| format!("docs/{page} has no search_messages row"))?;
            assert!(row.contains("regular expression"), "docs/{page}: {row}");
            assert!(
                !row.contains("method/From/To/UA/body"),
                "docs/{page} lists fields: {row}"
            );
        }
        Ok(())
    }

    #[test]
    fn the_changelog_entry_links_the_how_to() -> Result<(), TestError> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("CHANGELOG.md");
        let text = std::fs::read_to_string(&path)?;
        let entry = text
            .lines()
            .find(|l| l.contains("`search_messages`") && l.contains("`regex: true`"))
            .ok_or("CHANGELOG.md has no entry for the regex option of search_messages")?;
        assert!(
            entry.contains("(docs/mcp.md#search-messages-with-a-regular-expression)"),
            "the entry links no how-to: {entry}"
        );
        Ok(())
    }

    #[test]
    fn the_limits_are_the_documented_values() -> Result<(), TestError> {
        assert_eq!(
            MAX_REGEX_QUERY_BYTES, 1024,
            "docs/mcp-tools-core.md states 1024 bytes"
        );
        assert_eq!(
            REGEX_SIZE_LIMIT, 1_000_000,
            "docs/mcp-tools-core.md states 1000000 bytes"
        );
        assert_eq!(
            REGEX_SCAN_BUDGET,
            Duration::from_secs(5),
            "docs/mcp-tools-core.md states 5 s"
        );
        Ok(())
    }
}
