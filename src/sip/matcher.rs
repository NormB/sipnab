// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIP message matching and filtering engine.
//!
//! Evaluates [`SipMessage`]s against user-specified patterns compiled from CLI
//! flags. All specified criteria use AND logic — a message must satisfy every
//! active filter to match. The `invert` flag negates the final result.

use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};

use super::SipMessage;
use super::method::SipMethod;
use crate::cli::Cli;

/// Maximum size (in bytes) of a compiled regex program (D17).
///
/// The `regex` crate guarantees linear-time matching, so this is **not** a
/// ReDoS guard — it caps the memory and compile-time cost of a pathological
/// pattern (e.g. large bounded repetitions like `a{1000}{1000}`) so an
/// untrusted CLI pattern cannot blow up compilation.
const REGEX_SIZE_LIMIT: usize = 1_000_000;

/// Compiled set of match criteria. All specified criteria must match (AND logic).
///
/// Constructed from CLI flags via [`SipMatcher::new`]. Use [`SipMatcher::matches`]
/// to evaluate a [`SipMessage`] against the compiled criteria.
///
/// # Examples
///
/// ```no_run
/// # use sipnab::cli::Cli;
/// # use sipnab::sip::matcher::SipMatcher;
/// let cli = Cli::parse_from_args(["sipnab", "--from", "alice", "--to", "bob"]);
/// let matcher = SipMatcher::new(&cli, None).unwrap();
/// assert!(matcher.is_active());
/// ```
pub struct SipMatcher {
    /// Regex applied to the full raw message bytes copy-free (`regex::bytes`).
    payload_regex: Option<regex::bytes::Regex>,
    /// Regex applied to the From header value.
    from_regex: Option<Regex>,
    /// Regex applied to the To header value.
    to_regex: Option<Regex>,
    /// Regex applied to the Contact header value.
    contact_regex: Option<Regex>,
    /// Regex applied to the User-Agent (or Server) header value.
    ua_regex: Option<Regex>,
    /// Negate the final match result (`-v` / `--invert`).
    invert: bool,
}

impl SipMatcher {
    /// Build a matcher from CLI flags and an optional positional payload pattern.
    ///
    /// Each pattern is compiled with case-insensitive mode if `cli.matching_args.ignore_case`
    /// is set. If `cli.matching_args.word` is set, patterns are wrapped in `\b...\b` for
    /// whole-word matching. If `cli.matching_args.single_line` is false (the default), the
    /// payload regex is compiled with `dot_matches_new_line(true)` so `.`
    /// matches across header lines; when true, `.` only matches within a
    /// single line.
    ///
    /// The `payload_pattern` argument is intended for the
    /// positional match expression that tests against the full raw message.
    ///
    /// # Errors
    ///
    /// Returns an error if any user-provided pattern fails to compile or
    /// exceeds the regex size limit (1 MB).
    pub fn new(cli: &Cli, payload_pattern: Option<&str>) -> Result<Self> {
        Self::new_with_overrides(
            cli,
            payload_pattern,
            cli.matching_args.from.as_deref(),
            cli.matching_args.to.as_deref(),
        )
    }

    /// Build a matcher with explicit from/to overrides (for config fallback).
    ///
    /// `effective_from` and `effective_to` should already reflect the
    /// CLI-over-config priority (i.e., `cli.matching_args.from.or(config.filter.from)`).
    pub fn new_with_overrides(
        cli: &Cli,
        payload_pattern: Option<&str>,
        effective_from: Option<&str>,
        effective_to: Option<&str>,
    ) -> Result<Self> {
        let case_insensitive = cli.matching_args.ignore_case;
        let word = cli.matching_args.word;
        // When single_line is false (default), `.` matches newlines so
        // patterns can span across SIP header lines. When true, `.` does
        // NOT match `\n` (standard regex default).
        let dot_matches_new_line = !cli.matching_args.single_line;

        let payload_regex = payload_pattern
            .map(|p| compile_pattern_bytes(p, case_insensitive, word, dot_matches_new_line))
            .transpose()
            .context("invalid payload match expression")?;

        let from_regex = effective_from
            .map(|p| compile_pattern(p, case_insensitive, word, dot_matches_new_line))
            .transpose()
            .context("invalid --from pattern")?;

        let to_regex = effective_to
            .map(|p| compile_pattern(p, case_insensitive, word, dot_matches_new_line))
            .transpose()
            .context("invalid --to pattern")?;

        let contact_regex = cli
            .matching_args
            .contact
            .as_deref()
            .map(|p| compile_pattern(p, case_insensitive, word, dot_matches_new_line))
            .transpose()
            .context("invalid --contact pattern")?;

        let ua_regex = cli
            .matching_args
            .ua
            .as_deref()
            .map(|p| compile_pattern(p, case_insensitive, word, dot_matches_new_line))
            .transpose()
            .context("invalid --ua pattern")?;

        Ok(Self {
            payload_regex,
            from_regex,
            to_regex,
            contact_regex,
            ua_regex,
            invert: cli.matching_args.invert,
        })
    }

    /// Evaluate whether a SIP message matches all active criteria.
    ///
    /// The evaluation order is:
    /// 1. `payload_regex` — test against full raw message bytes (copy-free)
    /// 2. `from_regex` — test against the From header (full value, then user part)
    /// 3. `to_regex` — test against the To header (full value, then user part)
    /// 4. `contact_regex` — test against the Contact header
    /// 5. `ua_regex` — test against the User-Agent (or Server) header
    ///
    /// `-c` / `--calls-only` is not here: it is a property of the DIALOG a
    /// message belongs to, so it is [`calls_only_admits`], applied where the
    /// dialog is known.
    ///
    /// All active criteria must match (AND logic). If `invert` is set, the
    /// final boolean is negated.
    pub fn matches(&self, msg: &SipMessage) -> bool {
        let positive = self.matches_positive(msg);
        if self.invert { !positive } else { positive }
    }

    /// Returns `true` if any filter criterion is configured.
    ///
    /// When no filters are active, every message matches (subject to invert).
    pub fn is_active(&self) -> bool {
        self.payload_regex.is_some()
            || self.from_regex.is_some()
            || self.to_regex.is_some()
            || self.contact_regex.is_some()
            || self.ua_regex.is_some()
            || self.invert
    }

    /// Positive (non-inverted) match evaluation.
    ///
    /// Tests `msg` against each configured criterion in order (payload,
    /// From, To, Contact, User-Agent) and returns `false` at the
    /// first failure; missing headers are treated as empty strings. Returns
    /// `true` when every active criterion matches (vacuously true with no
    /// filters). Pure — `invert` is applied by the caller.
    fn matches_positive(&self, msg: &SipMessage) -> bool {
        // payload_regex: test against full raw message bytes (copy-free — no
        // lossy UTF-8 allocation, and non-UTF-8 payloads match faithfully)
        if let Some(ref re) = self.payload_regex
            && !re.is_match(&msg.raw)
        {
            return false;
        }

        // from_regex: test against full From header, falling back to
        // from_user() only when the header did not match (from_user()
        // allocates, so it is computed lazily).
        if let Some(ref re) = self.from_regex {
            let from_hdr = msg.from_header().unwrap_or("");
            if !re.is_match(from_hdr) {
                let from_user = msg.from_user();
                let from_user_ref = from_user.as_deref().unwrap_or("");
                if !re.is_match(from_user_ref) {
                    return false;
                }
            }
        }

        // to_regex: test against full To header, falling back to to_user()
        // only when the header did not match (to_user() allocates, so it is
        // computed lazily).
        if let Some(ref re) = self.to_regex {
            let to_hdr = msg.to_header().unwrap_or("");
            if !re.is_match(to_hdr) {
                let to_user = msg.to_user();
                let to_user_ref = to_user.as_deref().unwrap_or("");
                if !re.is_match(to_user_ref) {
                    return false;
                }
            }
        }

        // contact_regex: test against Contact header
        if let Some(ref re) = self.contact_regex {
            let contact = msg.contact().unwrap_or("");
            if !re.is_match(contact) {
                return false;
            }
        }

        // ua_regex: test against User-Agent (falls back to Server internally)
        if let Some(ref re) = self.ua_regex {
            let ua = msg.user_agent().unwrap_or("");
            if !re.is_match(ua) {
                return false;
            }
        }

        true
    }
}

/// Compile a user-provided pattern into a [`Regex`] with safety limits.
///
/// Applies case-insensitive mode, word-boundary wrapping, and
/// dot-matches-newline as requested. The compiled regex is limited to
/// [`REGEX_SIZE_LIMIT`] bytes, capping the memory and compile-time cost of a
/// pathological pattern (D17).
///
/// # Errors
///
/// Returns an error if the pattern is invalid regex syntax or exceeds the
/// size limit.
///
/// # Arguments
///
/// * `pattern` — user-supplied regex source text.
/// * `case_insensitive` — compile with case-insensitive matching.
/// * `word` — wrap the pattern in `\b...\b` for whole-word matching.
/// * `dot_matches_new_line` — let `.` match `\n` so patterns can span
///   header lines.
fn compile_pattern(
    pattern: &str,
    case_insensitive: bool,
    word: bool,
    dot_matches_new_line: bool,
) -> Result<Regex> {
    let effective = if word {
        format!(r"\b{pattern}\b")
    } else {
        pattern.to_string()
    };

    RegexBuilder::new(&effective)
        .case_insensitive(case_insensitive)
        .dot_matches_new_line(dot_matches_new_line)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .with_context(|| format!("failed to compile pattern '{pattern}'"))
}

/// Compile a user-provided pattern into a [`regex::bytes::Regex`] for
/// copy-free matching against raw message bytes.
///
/// Identical in options to [`compile_pattern`] (case-insensitivity,
/// word-boundary wrapping, dot-matches-newline, and the [`REGEX_SIZE_LIMIT`]
/// compile-cost cap) but targets `&[u8]` haystacks. The payload filter therefore
/// matches the captured bytes directly instead of a lossy UTF-8 copy: it
/// allocates nothing per message, and non-UTF-8 payloads (binary bodies)
/// that lossy conversion would have mangled into U+FFFD replacement
/// characters now match faithfully.
///
/// # Errors
///
/// Returns an error if the pattern is invalid regex syntax or exceeds the
/// size limit.
///
/// # Arguments
///
/// * `pattern` — user-supplied regex source text.
/// * `case_insensitive` — compile with case-insensitive matching.
/// * `word` — wrap the pattern in `\b...\b` for whole-word matching.
/// * `dot_matches_new_line` — let `.` match `\n` so patterns can span
///   header lines.
fn compile_pattern_bytes(
    pattern: &str,
    case_insensitive: bool,
    word: bool,
    dot_matches_new_line: bool,
) -> Result<regex::bytes::Regex> {
    let effective = if word {
        format!(r"\b{pattern}\b")
    } else {
        pattern.to_string()
    };

    regex::bytes::RegexBuilder::new(&effective)
        .case_insensitive(case_insensitive)
        .dot_matches_new_line(dot_matches_new_line)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .with_context(|| format!("failed to compile pattern '{pattern}'"))
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for filter compilation and matching: per-header filters, AND
/// combination, invert, calls-only, case/word modes, payload regexes, and
/// the regex safety limits.
/// Whether `-c` / `--calls-only` admits a message.
///
/// A call is a dialog that an INVITE started, and every message in it belongs
/// to the call: the responses, the ACK, the BYE, a re-INVITE. So the question
/// is asked of the DIALOG (`dialog_method`, the method that created it), not
/// of the message. It used to be asked of the message, inside the matcher,
/// which dropped everything but the INVITE request and made `-c` print a lone
/// INVITE for a complete call -- while the help and the CLI reference promise
/// "SIP dialogs (calls), not standalone messages".
///
/// With no dialog tracked (`--no-dialog`, or a Call-ID nothing recorded) the
/// only message recognizable as a call on its own is an INVITE request; a
/// response cannot say what it answers. Method tokens compare exactly, so a
/// lowercase `invite` is not one ([RFC 3261 section 7.1](https://www.rfc-editor.org/rfc/rfc3261#section-7.1)).
pub fn calls_only_admits(
    dialog_method: Option<&SipMethod>,
    message_method: Option<&SipMethod>,
) -> bool {
    match dialog_method {
        Some(method) => method == &SipMethod::Invite,
        None => message_method == Some(&SipMethod::Invite),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// Fixed 127.0.0.1 address used for all test messages.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed capture timestamp (2024-06-15 12:00:00 UTC) used in tests.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Construct a test INVITE SipMessage with configurable From user, To user,
    /// User-Agent, and Contact.
    fn make_test_invite(
        from_user: &str,
        to_user: &str,
        ua: &str,
        contact_addr: &str,
    ) -> SipMessage {
        let raw = build_sip(
            &format!("INVITE sip:{to_user}@example.com SIP/2.0"),
            &[
                &format!("From: <sip:{from_user}@example.com>;tag=test1"),
                &format!("To: <sip:{to_user}@example.com>"),
                &format!("Contact: <sip:{from_user}@{contact_addr}>"),
                &format!("User-Agent: {ua}"),
                "Call-ID: test-call-id@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("test INVITE should parse")
    }

    /// Construct a test REGISTER SipMessage.
    fn make_test_register(from_user: &str) -> SipMessage {
        let raw = build_sip(
            "REGISTER sip:registrar.example.com SIP/2.0",
            &[
                &format!("From: <sip:{from_user}@example.com>;tag=reg1"),
                &format!("To: <sip:{from_user}@example.com>"),
                "Call-ID: register-call-id@example.com",
                "CSeq: 1 REGISTER",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("test REGISTER should parse")
    }

    /// Helper: build a default CLI with no filters.
    fn default_cli() -> Cli {
        Cli::parse_from_args(["sipnab"])
    }

    // ── No filters → matches everything ──────────────────────────────

    /// With no filters configured, every message matches and is_active is false.
    #[test]
    fn no_filters_matches_everything() {
        let cli = default_cli();
        let matcher = SipMatcher::new(&cli, None).expect("should build");
        assert!(!matcher.is_active());

        let invite = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&invite));

        let register = make_test_register("1001");
        assert!(matcher.matches(&register));
    }

    // ── --from filter ────────────────────────────────────────────────

    /// `--from` matches a message whose From user matches the pattern.
    #[test]
    fn from_filter_matches() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "1001"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");
        assert!(matcher.is_active());

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    /// `--from` rejects a message with a non-matching From user.
    #[test]
    fn from_filter_rejects() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "1001"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("2002", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── --to filter ──────────────────────────────────────────────────

    /// `--to` matches a message whose To user matches the pattern.
    #[test]
    fn to_filter_matches() {
        let cli = Cli::parse_from_args(["sipnab", "--to", "1002"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    /// `--to` rejects a message with a non-matching To user.
    #[test]
    fn to_filter_rejects() {
        let cli = Cli::parse_from_args(["sipnab", "--to", "9999"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── --ua filter ──────────────────────────────────────────────────

    /// `--ua` matches on a User-Agent substring.
    #[test]
    fn ua_filter_matches() {
        let cli = Cli::parse_from_args(["sipnab", "--ua", "Oasis"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "Oasis/4.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    /// `--ua` rejects a non-matching User-Agent.
    #[test]
    fn ua_filter_rejects() {
        let cli = Cli::parse_from_args(["sipnab", "--ua", "Oasis"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "Ocelot/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── --contact filter ─────────────────────────────────────────────

    /// `--contact` matches on the Contact header value.
    #[test]
    fn contact_filter_matches() {
        let cli = Cli::parse_from_args(["sipnab", "--contact", "10\\.0\\.0"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    /// `--contact` rejects a non-matching Contact header.
    #[test]
    fn contact_filter_rejects() {
        let cli = Cli::parse_from_args(["sipnab", "--contact", "192\\.168"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── Combined AND logic ───────────────────────────────────────────

    /// `--from` and `--to` together match when both criteria hold.
    #[test]
    fn combined_from_and_to_both_match() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "1001", "--to", "1002"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    /// AND logic fails when only one of two criteria matches.
    #[test]
    fn combined_from_and_to_partial_mismatch() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "1001", "--to", "9999"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        // From matches but To doesn't → AND fails
        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── -v invert ────────────────────────────────────────────────────

    /// `-v` turns a would-be match into a non-match.
    #[test]
    fn invert_flips_match() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "1001", "-v"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        // Without invert this would match; with invert it should not
        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    /// `-v` turns a would-be non-match into a match.
    #[test]
    fn invert_flips_nonmatch() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "1001", "-v"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        // Without invert this would NOT match; with invert it should
        let msg = make_test_invite("2002", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    // ── -c is not a per-message filter ───────────────────────────────

    /// `-c` leaves the matcher alone: a REGISTER and a response both pass it,
    /// because whether a message is part of a call is decided by its dialog
    /// ([`calls_only_admits`]). Rejecting them here dropped every response,
    /// ACK and BYE of every call.
    #[test]
    fn calls_only_is_not_a_per_message_filter() {
        let cli = Cli::parse_from_args(["sipnab", "-c"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        assert!(matcher.matches(&make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5")));
        assert!(matcher.matches(&make_test_register("1001")));
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:1001@example.com>;tag=r1",
                "To: <sip:1002@example.com>;tag=r2",
                "Call-ID: resp-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let response = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        assert!(matcher.matches(&response));
    }

    // ── -i case insensitive ──────────────────────────────────────────

    /// `-i` makes `--from` match regardless of case.
    #[test]
    fn case_insensitive_from() {
        let cli = Cli::parse_from_args(["sipnab", "-i", "--from", "ALICE"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        // From header contains "alice" in lowercase
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        assert!(matcher.matches(&msg));
    }

    /// Without `-i`, matching is case-sensitive.
    #[test]
    fn case_sensitive_from_by_default() {
        // Without -i, "ALICE" should not match "alice"
        let cli = Cli::parse_from_args(["sipnab", "--from", "ALICE"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        assert!(!matcher.matches(&msg));
    }

    // ── --word whole-word matching ───────────────────────────────────

    /// `-w` matches when the pattern is bounded by word boundaries.
    #[test]
    fn word_boundary_matches_exact() {
        let cli = Cli::parse_from_args(["sipnab", "-w", "--from", "100"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        // "sip:100@" has word boundary after "100" at the "@"
        let raw = build_sip(
            "INVITE sip:100@example.com SIP/2.0",
            &[
                "From: <sip:100@example.com>;tag=w1",
                "To: <sip:100@example.com>",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        assert!(matcher.matches(&msg));
    }

    /// `-w` rejects a substring occurrence without word boundaries.
    #[test]
    fn word_boundary_rejects_partial() {
        let cli = Cli::parse_from_args(["sipnab", "-w", "--from", "100"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        // "1001" contains "100" but no word boundary before the "1"
        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── Payload regex ────────────────────────────────────────────────

    /// A positional payload pattern matches against the full raw message.
    #[test]
    fn payload_regex_matches_raw() {
        let cli = default_cli();
        let matcher = SipMatcher::new(&cli, Some("INVITE sip:")).expect("should build");
        assert!(matcher.is_active());

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    /// A payload pattern absent from the raw message rejects it.
    #[test]
    fn payload_regex_rejects_nonmatch() {
        let cli = default_cli();
        let matcher = SipMatcher::new(&cli, Some("BYE sip:")).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    /// A payload pattern targeting a raw non-UTF-8 byte matches the captured
    /// bytes directly. The old `String::from_utf8_lossy` path replaced the
    /// stray `0xFF` with U+FFFD, so a byte-literal pattern could never match
    /// (and `regex::Regex` cannot even compile `(?-u:\xff)` — it may match
    /// invalid UTF-8). The `regex::bytes` engine both compiles and matches it.
    #[test]
    fn payload_regex_matches_non_utf8_byte() {
        let cli = default_cli();
        // `(?-u:\xff)` matches the literal byte 0xFF; unavailable on the
        // Unicode-only str engine the old lossy path used.
        let matcher = SipMatcher::new(&cli, Some(r"(?-u:\xff)")).expect("should build");

        let raw = build_sip(
            "INVITE sip:1002@example.com SIP/2.0",
            &[
                "From: <sip:1001@example.com>;tag=bin1",
                "To: <sip:1002@example.com>",
                "Call-ID: nonutf8-payload@example.com",
                "CSeq: 1 INVITE",
                "Content-Type: application/octet-stream",
                "Content-Length: 1",
            ],
            b"\xff",
        );
        let msg = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");
        // Confirm the fixture really carries the non-UTF-8 byte.
        assert!(msg.raw.contains(&0xffu8));
        assert!(
            matcher.matches(&msg),
            "bytes regex must match a raw 0xFF byte that lossy UTF-8 would mangle"
        );
    }

    // ── -e / --match wiring (positional match-expression) ──

    /// `-e PATTERN` behaves exactly like a positional payload pattern.
    #[test]
    fn match_expr_flag_feeds_payload_regex() {
        // `-e REGISTER` should match REGISTER but not INVITE, exactly like a
        // positional payload pattern.
        let cli = Cli::parse_from_args(["sipnab", "-e", "REGISTER"]);
        let matcher =
            SipMatcher::new(&cli, cli.matching_args.match_expr.as_deref()).expect("should build");
        assert!(matcher.is_active());

        let register = make_test_register("1001");
        assert!(matcher.matches(&register));

        let invite = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&invite));
    }

    /// A malformed `-e` pattern fails matcher construction with an error.
    #[test]
    fn match_expr_invalid_regex_via_flag_errors() {
        // A malformed `-e` pattern must fail to build the matcher (not panic or
        // silently match nothing).
        let cli = Cli::parse_from_args(["sipnab", "-e", "[unterminated"]);
        let result = SipMatcher::new(&cli, cli.matching_args.match_expr.as_deref());
        assert!(
            result.is_err(),
            "-e with invalid regex must return an error"
        );
    }

    /// An `-e` pattern over the 1 MB size limit is rejected.
    #[test]
    fn match_expr_oversized_via_flag_errors() {
        // A >1 MB `-e` pattern trips the compiled-program size limit.
        let huge = "a".repeat(2_000_000);
        let cli = Cli::parse_from_args(["sipnab", "-e", &huge]);
        assert!(SipMatcher::new(&cli, cli.matching_args.match_expr.as_deref()).is_err());
    }

    /// `-e` composes with `-i` (case-insensitive) and `-v` (invert).
    #[test]
    fn match_expr_honors_ignore_case_and_invert() {
        // -i makes the expression case-insensitive; -v inverts the result.
        let cli = Cli::parse_from_args(["sipnab", "-i", "-v", "-e", "register"]);
        let matcher =
            SipMatcher::new(&cli, cli.matching_args.match_expr.as_deref()).expect("should build");

        // REGISTER matches case-insensitively, then invert flips it out.
        let register = make_test_register("1001");
        assert!(!matcher.matches(&register));

        // INVITE never matches "register", invert flips it in.
        let invite = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&invite));
    }

    // ── Regex size limit ─────────────────────────────────────────────

    /// A positional pattern over the 1 MB size limit is rejected.
    #[test]
    fn oversized_pattern_returns_error() {
        let cli = default_cli();
        // A 2 MB pattern of "a" characters — should exceed the 1 MB limit
        let huge_pattern = "a".repeat(2_000_000);
        let result = SipMatcher::new(&cli, Some(&huge_pattern));
        assert!(result.is_err(), "oversized pattern should return an error");
    }

    // ── Invalid regex returns error ──────────────────────────────────

    /// An invalid `--from` regex fails matcher construction.
    #[test]
    fn invalid_regex_returns_error() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "[invalid"]);
        let result = SipMatcher::new(&cli, None);
        assert!(result.is_err(), "invalid regex should return an error");
    }

    // ── is_active correctness ────────────────────────────────────────

    /// `-v` alone counts as an active filter.
    #[test]
    fn is_active_with_invert_only() {
        let cli = Cli::parse_from_args(["sipnab", "-v"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");
        assert!(matcher.is_active());
    }

    /// `-c` alone configures no matcher criterion; it is applied per dialog.
    #[test]
    fn calls_only_alone_leaves_the_matcher_inactive() {
        let cli = Cli::parse_from_args(["sipnab", "-c"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");
        assert!(!matcher.is_active());
    }
}

#[cfg(test)]
mod calls_only_admits_tests {
    use super::calls_only_admits;
    use crate::sip::SipMethod;

    const INVITE: Option<&SipMethod> = Some(&SipMethod::Invite);

    /// The INVITE that starts a call is a call.
    #[test]
    fn the_invite_that_starts_a_call_is_admitted() {
        assert!(calls_only_admits(INVITE, INVITE));
    }

    /// `--calls-only` shows the CALL, and a call is more than its INVITE: the
    /// provisional and final responses, the ACK and the BYE belong to it. The
    /// flag used to be applied per message, so every one of them was dropped
    /// and `-c` printed a lone INVITE for a complete call.
    #[test]
    fn every_message_of_an_invite_dialog_is_admitted() {
        assert!(calls_only_admits(INVITE, None), "a response has no method");
        for m in [
            SipMethod::Ack,
            SipMethod::Bye,
            SipMethod::Cancel,
            SipMethod::Invite,
        ] {
            assert!(calls_only_admits(INVITE, Some(&m)), "{m:?} inside a call");
        }
    }

    /// A dialog that did not start with INVITE is not a call, whatever passes
    /// through it: the REGISTER, its 200, a SUBSCRIBE and its NOTIFY.
    #[test]
    fn a_dialog_that_did_not_start_with_invite_is_refused() {
        let register = Some(&SipMethod::Register);
        assert!(!calls_only_admits(register, register));
        assert!(!calls_only_admits(register, None));
        let subscribe = Some(&SipMethod::Subscribe);
        assert!(!calls_only_admits(subscribe, Some(&SipMethod::Notify)));
        let options = Some(&SipMethod::Options);
        assert!(!calls_only_admits(options, None));
    }

    /// With no dialog tracked (`--no-dialog`, or a Call-ID nothing recorded),
    /// only an INVITE request can be recognized as a call on its own; a lone
    /// response cannot say what it answers.
    #[test]
    fn without_a_dialog_only_an_invite_request_is_admitted() {
        assert!(calls_only_admits(None, INVITE));
        assert!(!calls_only_admits(None, None));
        assert!(!calls_only_admits(None, Some(&SipMethod::Register)));
        // Method tokens are case-sensitive (RFC 3261 section 7.1): `invite`
        // parses to a custom method and is not a call.
        let lowercase = SipMethod::Custom("invite".into());
        assert!(!calls_only_admits(None, Some(&lowercase)));
    }
}
