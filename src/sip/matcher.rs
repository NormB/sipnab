//! SIP message matching and filtering engine.
//!
//! Evaluates [`SipMessage`]s against user-specified patterns compiled from CLI
//! flags. All specified criteria use AND logic — a message must satisfy every
//! active filter to match. The `invert` flag negates the final result.

use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};

use super::SipMessage;
use crate::cli::Cli;

/// Maximum compiled regex size in bytes, preventing ReDoS (D17).
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
    /// Regex applied to the full raw message bytes (lossy UTF-8).
    payload_regex: Option<Regex>,
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
    /// Only match INVITE requests (`-c` / `--calls-only`).
    calls_only: bool,
}

impl SipMatcher {
    /// Build a matcher from CLI flags and an optional positional payload pattern.
    ///
    /// Each pattern is compiled with case-insensitive mode if `cli.ignore_case`
    /// is set. If `cli.word` is set, patterns are wrapped in `\b...\b` for
    /// whole-word matching. If `cli.single_line` is false (the default), the
    /// payload regex is compiled with `dot_matches_new_line(true)` so `.`
    /// matches across header lines; when true, `.` only matches within a
    /// single line.
    ///
    /// The `payload_pattern` argument is intended for the sipgrep-style
    /// positional match expression that tests against the full raw message.
    ///
    /// # Errors
    ///
    /// Returns an error if any user-provided pattern fails to compile or
    /// exceeds the regex size limit (1 MB).
    pub fn new(cli: &Cli, payload_pattern: Option<&str>) -> Result<Self> {
        let case_insensitive = cli.ignore_case;
        let word = cli.word;
        // When single_line is false (default), `.` matches newlines so
        // patterns can span across SIP header lines. When true, `.` does
        // NOT match `\n` (standard regex default).
        let dot_matches_new_line = !cli.single_line;

        let payload_regex = payload_pattern
            .map(|p| compile_pattern(p, case_insensitive, word, dot_matches_new_line))
            .transpose()
            .context("invalid payload match expression")?;

        let from_regex = cli
            .from
            .as_deref()
            .map(|p| compile_pattern(p, case_insensitive, word, dot_matches_new_line))
            .transpose()
            .context("invalid --from pattern")?;

        let to_regex = cli
            .to
            .as_deref()
            .map(|p| compile_pattern(p, case_insensitive, word, dot_matches_new_line))
            .transpose()
            .context("invalid --to pattern")?;

        let contact_regex = cli
            .contact
            .as_deref()
            .map(|p| compile_pattern(p, case_insensitive, word, dot_matches_new_line))
            .transpose()
            .context("invalid --contact pattern")?;

        let ua_regex = cli
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
            invert: cli.invert,
            calls_only: cli.calls_only,
        })
    }

    /// Evaluate whether a SIP message matches all active criteria.
    ///
    /// The evaluation order is:
    /// 1. `calls_only` — reject non-INVITE messages
    /// 2. `payload_regex` — test against full raw message (lossy UTF-8)
    /// 3. `from_regex` — test against the From header (full value, then user part)
    /// 4. `to_regex` — test against the To header (full value, then user part)
    /// 5. `contact_regex` — test against the Contact header
    /// 6. `ua_regex` — test against the User-Agent (or Server) header
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
            || self.calls_only
    }

    /// Positive (non-inverted) match evaluation.
    fn matches_positive(&self, msg: &SipMessage) -> bool {
        // calls_only: reject anything that isn't an INVITE request
        if self.calls_only {
            let is_invite = msg
                .method
                .as_deref()
                .is_some_and(|m| m.eq_ignore_ascii_case("INVITE"));
            if !is_invite {
                return false;
            }
        }

        // payload_regex: test against full raw message as lossy UTF-8
        if let Some(ref re) = self.payload_regex {
            let text = String::from_utf8_lossy(&msg.raw);
            if !re.is_match(&text) {
                return false;
            }
        }

        // from_regex: test against full From header, fallback to from_user()
        if let Some(ref re) = self.from_regex {
            let from_hdr = msg.from_header().unwrap_or("");
            let from_user = msg.from_user();
            let from_user_ref = from_user.as_deref().unwrap_or("");
            if !re.is_match(from_hdr) && !re.is_match(from_user_ref) {
                return false;
            }
        }

        // to_regex: test against full To header, fallback to to_user()
        if let Some(ref re) = self.to_regex {
            let to_hdr = msg.to_header().unwrap_or("");
            let to_user = msg.to_user();
            let to_user_ref = to_user.as_deref().unwrap_or("");
            if !re.is_match(to_hdr) && !re.is_match(to_user_ref) {
                return false;
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
/// [`REGEX_SIZE_LIMIT`] bytes to prevent ReDoS attacks (D17).
///
/// # Errors
///
/// Returns an error if the pattern is invalid regex syntax or exceeds the
/// size limit.
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

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

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
        parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
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
        parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("test REGISTER should parse")
    }

    /// Helper: build a default CLI with no filters.
    fn default_cli() -> Cli {
        Cli::parse_from_args(["sipnab"])
    }

    // ── No filters → matches everything ──────────────────────────────

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

    #[test]
    fn from_filter_matches() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "1001"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");
        assert!(matcher.is_active());

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    #[test]
    fn from_filter_rejects() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "1001"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("2002", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── --to filter ──────────────────────────────────────────────────

    #[test]
    fn to_filter_matches() {
        let cli = Cli::parse_from_args(["sipnab", "--to", "1002"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    #[test]
    fn to_filter_rejects() {
        let cli = Cli::parse_from_args(["sipnab", "--to", "9999"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── --ua filter ──────────────────────────────────────────────────

    #[test]
    fn ua_filter_matches() {
        let cli = Cli::parse_from_args(["sipnab", "--ua", "Oasis"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "Oasis/4.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    #[test]
    fn ua_filter_rejects() {
        let cli = Cli::parse_from_args(["sipnab", "--ua", "Oasis"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "Ocelot/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── --contact filter ─────────────────────────────────────────────

    #[test]
    fn contact_filter_matches() {
        let cli = Cli::parse_from_args(["sipnab", "--contact", "10\\.0\\.0"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    #[test]
    fn contact_filter_rejects() {
        let cli = Cli::parse_from_args(["sipnab", "--contact", "192\\.168"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── Combined AND logic ───────────────────────────────────────────

    #[test]
    fn combined_from_and_to_both_match() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "1001", "--to", "1002"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    #[test]
    fn combined_from_and_to_partial_mismatch() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "1001", "--to", "9999"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        // From matches but To doesn't → AND fails
        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── -v invert ────────────────────────────────────────────────────

    #[test]
    fn invert_flips_match() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "1001", "-v"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        // Without invert this would match; with invert it should not
        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    #[test]
    fn invert_flips_nonmatch() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "1001", "-v"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        // Without invert this would NOT match; with invert it should
        let msg = make_test_invite("2002", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    // ── -c calls_only ────────────────────────────────────────────────

    #[test]
    fn calls_only_accepts_invite() {
        let cli = Cli::parse_from_args(["sipnab", "-c"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    #[test]
    fn calls_only_rejects_register() {
        let cli = Cli::parse_from_args(["sipnab", "-c"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        let msg = make_test_register("1001");
        assert!(!matcher.matches(&msg));
    }

    // ── -i case insensitive ──────────────────────────────────────────

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
        let msg = parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse");

        assert!(matcher.matches(&msg));
    }

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
        let msg = parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse");

        assert!(!matcher.matches(&msg));
    }

    // ── --word whole-word matching ───────────────────────────────────

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
        let msg = parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse");

        assert!(matcher.matches(&msg));
    }

    #[test]
    fn word_boundary_rejects_partial() {
        let cli = Cli::parse_from_args(["sipnab", "-w", "--from", "100"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

        // "1001" contains "100" but no word boundary before the "1"
        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── Payload regex ────────────────────────────────────────────────

    #[test]
    fn payload_regex_matches_raw() {
        let cli = default_cli();
        let matcher = SipMatcher::new(&cli, Some("INVITE sip:")).expect("should build");
        assert!(matcher.is_active());

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(matcher.matches(&msg));
    }

    #[test]
    fn payload_regex_rejects_nonmatch() {
        let cli = default_cli();
        let matcher = SipMatcher::new(&cli, Some("BYE sip:")).expect("should build");

        let msg = make_test_invite("1001", "1002", "TestUA/1.0", "10.0.0.5");
        assert!(!matcher.matches(&msg));
    }

    // ── Regex size limit ─────────────────────────────────────────────

    #[test]
    fn oversized_pattern_returns_error() {
        let cli = default_cli();
        // A 2 MB pattern of "a" characters — should exceed the 1 MB limit
        let huge_pattern = "a".repeat(2_000_000);
        let result = SipMatcher::new(&cli, Some(&huge_pattern));
        assert!(result.is_err(), "oversized pattern should return an error");
    }

    // ── Invalid regex returns error ──────────────────────────────────

    #[test]
    fn invalid_regex_returns_error() {
        let cli = Cli::parse_from_args(["sipnab", "--from", "[invalid"]);
        let result = SipMatcher::new(&cli, None);
        assert!(result.is_err(), "invalid regex should return an error");
    }

    // ── is_active correctness ────────────────────────────────────────

    #[test]
    fn is_active_with_invert_only() {
        let cli = Cli::parse_from_args(["sipnab", "-v"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");
        assert!(matcher.is_active());
    }

    #[test]
    fn is_active_with_calls_only() {
        let cli = Cli::parse_from_args(["sipnab", "-c"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");
        assert!(matcher.is_active());
    }

    // ── Response message with calls_only ─────────────────────────────

    #[test]
    fn calls_only_rejects_response() {
        let cli = Cli::parse_from_args(["sipnab", "-c"]);
        let matcher = SipMatcher::new(&cli, None).expect("should build");

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
        let msg = parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse");

        assert!(!matcher.matches(&msg));
    }
}
