// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fail2ban-compatible log output for security events.
//!
//! Generates log lines that can be parsed by fail2ban filter rules to
//! automatically block SIP scanners and registration flood sources.

use chrono::Local;

/// Sanitize a value for safe inclusion in log lines.
///
/// Replaces `\r` and `\n` with spaces to prevent CRLF log injection attacks
/// where attacker-controlled SIP header values could forge log entries.
fn sanitize_log_value(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

/// Render an optional, attacker-controlled header value as one log field.
///
/// # Arguments
///
/// * `v` — the header value, or `None` when the message carried no such header.
///
/// # Returns
///
/// A quoted, escaped value, or the bare absent marker `-`.
///
/// This is the ONE place the absent marker is decided. Before it, three
/// spellings of the same condition were in the tree at once — `"unknown"` in
/// the fail2ban path, `""` in `ScannerAlert`, and `"-"` in the kill-target
/// alert — so the same missing header read differently depending on which line
/// printed it, and no filter could match all three.
///
/// Present values are QUOTED, which is what makes the absent case
/// unambiguous: a `User-Agent` whose value is literally `-` renders as `"-"`
/// and cannot be confused with a message that carried no header at all.
///
/// Quoting also closes a field-injection hole. `sanitize_log_value` strips CR
/// and LF, so a crafted header could not forge a whole log *line* — but the
/// fields are space-separated, so it could forge a field *within* one:
/// `User-Agent: evil method=REGISTER src=1.2.3.4` produced
/// `… src=<real> ua=evil method=REGISTER src=1.2.3.4 method=OPTIONS`, giving a
/// parser two `src=` values, one of them attacker-chosen, in the output that
/// feeds a ban decision. Escaping `\` and `"` inside the quotes closes the
/// quoted form against the same trick.
///
/// This follows the Apache combined-log convention — quoted User-Agent, bare
/// `-` for absent — so the shape is already familiar to anyone writing filters.
pub fn render_absent(v: Option<&str>) -> String {
    match v {
        Some(s) => {
            let escaped = sanitize_log_value(s)
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            format!("\"{escaped}\"")
        }
        None => ABSENT.to_string(),
    }
}

/// What an absent header renders as in a log field.
///
/// Bare, and the only unquoted value the field can take — that is precisely
/// what distinguishes it from a header whose value is the same characters.
const ABSENT: &str = "-";

/// Format a SIP scanner detection event for fail2ban log parsing.
///
/// Output format:
/// ```text
/// YYYY-MM-DD HH:MM:SS sipnab[PID]: scanner_detected src=<IP> ua=<UA> method=<METHOD>
/// ```
///
/// The PID is obtained from the current process for log correlation.
/// Attacker-controlled values (UA, method) are sanitized to prevent CRLF injection.
///
/// # Arguments
///
/// * `src_ip` — Source IP of the suspected scanner.
/// * `ua` — Offending `User-Agent`, or `None` when the request carried no such
///   header.
/// * `method` — SIP method the scanner used.
///
/// `ua` is an `Option` rather than a pre-substituted string because the two
/// cases are different evidence. A request with **no** `User-Agent` is itself a
/// scanner signal — plenty of scanners omit it — and the callers used to
/// collapse that into the literal `"unknown"`, which a benign client can also
/// send. The output that feeds a ban decision should not merge the more
/// suspicious case into the less.
///
/// # Returns
///
/// The formatted log line (local-time timestamp); the caller is
/// responsible for emitting it — nothing is written here.
pub fn format_scanner_event(src_ip: &str, ua: Option<&str>, method: &str) -> String {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    let pid = std::process::id();
    let safe_src = sanitize_log_value(src_ip);
    let safe_ua = render_absent(ua);
    let safe_method = sanitize_log_value(method);
    format!(
        "{now} sipnab[{pid}]: scanner_detected src={safe_src} ua={safe_ua} method={safe_method}"
    )
}

/// Format a registration flood detection event for fail2ban log parsing.
///
/// Output format:
/// ```text
/// YYYY-MM-DD HH:MM:SS sipnab[PID]: reg_flood src=<IP> count=<COUNT>
/// ```
///
/// The source IP is sanitized (CR/LF stripped) to prevent CRLF log
/// injection, matching `format_scanner_event`.
///
/// # Arguments
///
/// * `src_ip` — Source IP of the flood; sanitized before formatting.
/// * `count` — Number of REGISTERs observed in the detection window.
///
/// # Returns
///
/// The formatted log line (local-time timestamp); nothing is written here.
pub fn format_reg_flood_event(src_ip: &str, count: u32) -> String {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    let pid = std::process::id();
    let safe_src = sanitize_log_value(src_ip);
    format!("{now} sipnab[{pid}]: reg_flood src={safe_src} count={count}")
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for the fail2ban log-line formats and CRLF-injection sanitizing.
#[cfg(test)]
mod tests {
    use super::*;

    /// Scanner lines carry prefix, event type, src/ua/method fields, and a
    /// `YYYY-MM-DD HH:MM:SS` timestamp.
    #[test]
    fn scanner_event_format() {
        let event = format_scanner_event("10.0.0.5", Some("friendly-scanner"), "OPTIONS");

        assert!(event.contains("sipnab["), "should contain 'sipnab[' prefix");
        assert!(
            event.contains("scanner_detected"),
            "should contain event type"
        );
        assert!(event.contains("src=10.0.0.5"), "should contain source IP");
        assert!(
            event.contains(r#"ua="friendly-scanner""#),
            "should contain user agent"
        );
        assert!(event.contains("method=OPTIONS"), "should contain method");
        // Verify timestamp format (YYYY-MM-DD HH:MM:SS)
        let parts: Vec<&str> = event.splitn(3, ' ').collect();
        assert!(parts.len() >= 2, "should have date and time parts");
        assert_eq!(parts[0].len(), 10, "date should be YYYY-MM-DD");
        assert_eq!(parts[1].len(), 8, "time should be HH:MM:SS");
    }

    /// An ABSENT User-Agent is distinguishable from one whose value is the
    /// literal absent marker.
    ///
    /// This is the whole reason `ua` is an `Option`. A request with no
    /// `User-Agent` is itself a scanner signal — many scanners omit it — and
    /// the callers used to substitute the string `"unknown"` for it, which any
    /// client can send. The two collapsed into one log line, so a fail2ban
    /// filter could not tell "no UA header" from "UA: unknown", and the more
    /// suspicious case was the one that disappeared.
    ///
    /// The assertion is deliberately about the two being DIFFERENT rather than
    /// about either exact spelling: it must keep holding when the absent marker
    /// changes.
    #[test]
    fn an_absent_user_agent_is_not_the_same_line_as_a_literal_one() {
        let absent = format_scanner_event("10.0.0.5", None, "OPTIONS");
        let literal = format_scanner_event("10.0.0.5", Some(ABSENT), "OPTIONS");

        let field = |line: &str| {
            line.split(" ua=")
                .nth(1)
                .and_then(|r| r.split(' ').next())
                .expect("every scanner line carries a ua= field")
                .to_string()
        };

        assert_ne!(
            field(&absent),
            field(&literal),
            "a message with no User-Agent and one sending the marker verbatim \
             produce the same ua= field — the absent case is unrecoverable from \
             the log, which is exactly what feeds the ban decision"
        );
    }

    /// A crafted User-Agent cannot forge another field in the same line.
    ///
    /// `sanitize_log_value` strips CR/LF, so a whole forged LINE was already
    /// impossible — but the fields are space-separated, and before quoting a
    /// `User-Agent` of `evil method=REGISTER src=1.2.3.4` produced a line
    /// carrying two `src=` values, the second attacker-chosen. In a fail2ban
    /// pipeline that is an attacker-chosen ban target.
    /// Split a log line into `key=value` fields the way a correct reader must:
    /// honouring the quotes, so text inside a quoted value is one token and not
    /// a field of its own.
    ///
    /// Counting substrings would NOT do here — quoting delimits the injected
    /// text, it does not delete it, so `event.matches("src=")` still sees the
    /// crafted copy and a test built on that fails against a correct
    /// implementation. The claim being made is about parsing, so the test has to
    /// parse.
    fn fields(line: &str) -> Vec<(String, String)> {
        let body = line.split(": ").nth(1).unwrap_or(line);
        let mut out = Vec::new();
        let mut chars = body.chars().peekable();
        let mut token = String::new();
        let mut in_quotes = false;
        let mut escaped = false;
        loop {
            let c = chars.next();
            match c {
                Some('\\') if in_quotes && !escaped => escaped = true,
                Some('"') if !escaped => {
                    in_quotes = !in_quotes;
                    token.push('"');
                }
                Some(' ') | None if !in_quotes => {
                    if let Some((k, v)) = token.split_once('=') {
                        out.push((k.to_string(), v.to_string()));
                    }
                    token.clear();
                    if c.is_none() {
                        break;
                    }
                }
                Some(ch) => {
                    escaped = false;
                    token.push(ch);
                }
                None => break,
            }
        }
        out
    }

    #[test]
    fn a_crafted_user_agent_cannot_forge_a_field() {
        let craft = "evil method=REGISTER src=1.2.3.4";
        let event = format_scanner_event("10.0.0.5", Some(craft), "OPTIONS");
        let f = fields(&event);

        let srcs: Vec<_> = f.iter().filter(|(k, _)| k == "src").collect();
        let methods: Vec<_> = f.iter().filter(|(k, _)| k == "method").collect();

        assert_eq!(
            srcs.len(),
            1,
            "a User-Agent forged a second src= in {event}"
        );
        assert_eq!(srcs[0].1, "10.0.0.5", "the src= is not the real source");
        assert_eq!(
            methods.len(),
            1,
            "a User-Agent forged a second method= in {event}"
        );
        assert_eq!(methods[0].1, "OPTIONS", "the method= was overwritten");
    }

    /// A quote in the User-Agent cannot close the quoting early and escape.
    #[test]
    fn a_quote_in_the_user_agent_cannot_break_out() {
        let event = format_scanner_event("10.0.0.5", Some(r#"a" src=9.9.9.9 x=""#), "OPTIONS");
        let f = fields(&event);

        let srcs: Vec<_> = f.iter().filter(|(k, _)| k == "src").collect();
        assert_eq!(srcs.len(), 1, "an embedded quote escaped ua= in {event}");
        assert_eq!(srcs[0].1, "10.0.0.5", "the forged src= won");
    }

    /// Reg-flood lines carry prefix, event type, source IP, and count.
    #[test]
    fn reg_flood_event_format() {
        let event = format_reg_flood_event("192.168.1.100", 42);

        assert!(event.contains("sipnab["), "should contain process prefix");
        assert!(event.contains("reg_flood"), "should contain event type");
        assert!(
            event.contains("src=192.168.1.100"),
            "should contain source IP"
        );
        assert!(event.contains("count=42"), "should contain count");
    }

    // ── Security regression tests ────────────────────────────────────

    /// CR/LF embedded in every field is stripped — no forged log entries.
    #[test]
    fn scanner_event_sanitizes_all_fields() {
        let event = format_scanner_event("10.0.0.1\r\nfake", Some("evil\nua"), "INVITE\rmethod");

        assert!(
            !event.contains('\r') && !event.contains('\n'),
            "output must not contain any CR or LF characters, got: {event:?}"
        );
        // The sanitized values should still be present (with newlines replaced)
        assert!(
            event.contains("src=10.0.0.1"),
            "sanitized IP should be present"
        );
        assert!(
            event.contains(r#"ua="evil"#),
            "sanitized UA should be present"
        );
        assert!(
            event.contains("method=INVITE"),
            "sanitized method should be present"
        );
    }

    /// CR/LF embedded in the reg-flood source IP is stripped — a crafted
    /// `src_ip` cannot forge additional log entries (mirrors the scanner
    /// path's sanitization).
    #[test]
    fn reg_flood_event_sanitizes_src_ip() {
        let event = format_reg_flood_event("10.0.0.1\r\nsipnab[1]: reg_flood src=fake", 7);

        assert!(
            !event.contains('\r') && !event.contains('\n'),
            "output must not contain any CR or LF characters, got: {event:?}"
        );
        assert!(
            event.contains("src=10.0.0.1"),
            "sanitized IP should be present"
        );
        assert!(event.contains("count=7"), "count should be present");
    }

    /// Benign values pass through unmodified and newline-free.
    #[test]
    fn scanner_event_normal_values() {
        let event = format_scanner_event("192.168.1.50", Some("Ooma/3.0"), "OPTIONS");

        assert!(
            event.contains("scanner_detected"),
            "should contain event type"
        );
        assert!(
            event.contains("src=192.168.1.50"),
            "should contain source IP"
        );
        assert!(
            event.contains(r#"ua="Ooma/3.0""#),
            "should contain user agent"
        );
        assert!(event.contains("method=OPTIONS"), "should contain method");
        // Should not have any stray newlines
        assert!(
            !event.contains('\r') && !event.contains('\n'),
            "normal output should not contain newlines"
        );
    }
}
