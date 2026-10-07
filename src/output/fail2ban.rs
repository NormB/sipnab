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
/// This is the ONE place the absent marker is decided, and every field of a
/// scanner line now goes through it. Before, FIVE spellings of the same
/// condition were in the tree at once — `"unknown"` and `""` and `"-"` for a
/// missing `User-Agent`, `"UNKNOWN"` and `"-"` for a missing method — so two
/// lines describing identical input could disagree, and no filter could match
/// them all. The first pass through this fixed only `ua`, which left the claim
/// on this very comment untrue for `method` for one release.
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
/// * `method` — SIP method the scanner used, or `None` when the request line
///   carried none.
///
/// Both are `Option` rather than pre-substituted strings because absence and a
/// value that happens to look like a placeholder are different evidence. A
/// request with **no** `User-Agent` is itself a scanner signal — plenty of
/// scanners omit it — and the callers used to collapse that into the literal
/// `"unknown"`, which a benign client can also send. `method` had the same
/// problem twice over: `"UNKNOWN"` on one detection path and `"-"` on another
/// for the same condition, so two lines describing identical input disagreed
/// about what absence looks like. The output that feeds a ban decision should
/// not merge the more suspicious case into the less, nor spell it two ways.
///
/// # Returns
///
/// The formatted log line (local-time timestamp); the caller is
/// responsible for emitting it — nothing is written here.
pub fn format_scanner_event(src_ip: &str, ua: Option<&str>, method: Option<&str>) -> String {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    let pid = std::process::id();
    let safe_src = sanitize_log_value(src_ip);
    let safe_ua = render_absent(ua);
    // Quoted like `ua`, and for the same reason: `SipMethod::Custom` carries
    // whatever token preceded the first space on the request line, so `method`
    // is attacker-influenced text too. It cannot contain a space, so it cannot
    // forge a whole field — but it can contain `=` or `"`, which is ambiguous
    // unquoted and would break a consumer's own quoting.
    let safe_method = render_absent(method);
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
/// * `count` — Challenged failures in the detection window: credentialed
///   REGISTERs the registrar refused. This is the figure that crossed the
///   threshold, not the REGISTER count.
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

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// Scanner lines carry prefix, event type, src/ua/method fields, and a
    /// `YYYY-MM-DD HH:MM:SS` timestamp.
    #[test]
    fn scanner_event_format() {
        let event = format_scanner_event("10.0.0.5", Some("friendly-scanner"), Some("OPTIONS"));

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
        assert!(
            event.contains(r#"method="OPTIONS""#),
            "should contain method"
        );
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
    fn an_absent_user_agent_is_not_the_same_line_as_a_literal_one() -> Result<(), TestError> {
        let absent = format_scanner_event("10.0.0.5", None, Some("OPTIONS"));
        let literal = format_scanner_event("10.0.0.5", Some(ABSENT), Some("OPTIONS"));

        let field = |line: &str| -> Result<String, TestError> {
            Ok(line
                .split(" ua=")
                .nth(1)
                .and_then(|r| r.split(' ').next())
                .ok_or("every scanner line carries a ua= field")?
                .to_string())
        };

        assert_ne!(
            field(&absent)?,
            field(&literal)?,
            "a message with no User-Agent and one sending the marker verbatim \
             produce the same ua= field — the absent case is unrecoverable from \
             the log, which is exactly what feeds the ban decision"
        );
        Ok(())
    }

    /// A crafted User-Agent cannot forge another field in the same line.
    ///
    /// `sanitize_log_value` strips CR/LF, so a whole forged LINE was already
    /// impossible — but the fields are space-separated, and before quoting a
    /// `User-Agent` of `evil method=REGISTER src=1.2.3.4` produced a line
    /// carrying two `src=` values, the second attacker-chosen. In a fail2ban
    /// pipeline that is an attacker-chosen ban target.
    /// Split a log line into `key=value` fields the way a correct reader must:
    /// honoring the quotes, so text inside a quoted value is one token and not
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
        let event = format_scanner_event("10.0.0.5", Some(craft), Some("OPTIONS"));
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
        assert_eq!(methods[0].1, r#""OPTIONS""#, "the method= was overwritten");
    }

    /// A quote in the User-Agent cannot close the quoting early and escape.
    #[test]
    fn a_quote_in_the_user_agent_cannot_break_out() {
        let event =
            format_scanner_event("10.0.0.5", Some(r#"a" src=9.9.9.9 x=""#), Some("OPTIONS"));
        let f = fields(&event);

        let srcs: Vec<_> = f.iter().filter(|(k, _)| k == "src").collect();
        assert_eq!(srcs.len(), 1, "an embedded quote escaped ua= in {event}");
        assert_eq!(srcs[0].1, "10.0.0.5", "the forged src= won");
    }

    /// The same guard for `method`, which had the defect twice over.
    ///
    /// An absent method rendered as `"UNKNOWN"` on the scanner path and `"-"`
    /// on the kill-target path, so two lines describing identical input
    /// disagreed — and `SipMethod::Custom` can hold either spelling, since it
    /// keeps whatever token preceded the first space on the request line. The
    /// first pass of this work fixed `ua` and left `method` behind, which made
    /// the "ONE place" claim on `render_absent` untrue for a release.
    #[test]
    fn an_absent_method_is_not_the_same_line_as_a_literal_one() -> Result<(), TestError> {
        let absent = format_scanner_event("10.0.0.5", Some("ua"), None);
        let literal = format_scanner_event("10.0.0.5", Some("ua"), Some(ABSENT));
        let legacy = format_scanner_event("10.0.0.5", Some("ua"), Some("UNKNOWN"));

        let field = |line: &str| -> Result<String, TestError> {
            Ok(line
                .split(" method=")
                .nth(1)
                .ok_or("every scanner line carries a method= field")?
                .to_string())
        };

        assert_ne!(
            field(&absent)?,
            field(&literal)?,
            "no method and a method of `-` produce the same field"
        );
        assert_ne!(
            field(&absent)?,
            field(&legacy)?,
            "no method and a Custom method of `UNKNOWN` produce the same field"
        );
        Ok(())
    }

    /// A `Custom` method cannot break out of its quoting.
    ///
    /// It cannot contain a space — the parser takes everything before the first
    /// one — so it cannot forge a whole field. It CAN contain `=` and `"`.
    #[test]
    fn a_custom_method_cannot_break_out_of_its_field() {
        let event = format_scanner_event("10.0.0.5", Some("ua"), Some(r#"X" src=9.9.9.9"#));
        let f = fields(&event);

        let srcs: Vec<_> = f.iter().filter(|(k, _)| k == "src").collect();
        assert_eq!(srcs.len(), 1, "a Custom method forged a src= in {event}");
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
        let event =
            format_scanner_event("10.0.0.1\r\nfake", Some("evil\nua"), Some("INVITE\rmethod"));

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
            event.contains(r#"method="INVITE"#),
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
        let event = format_scanner_event("192.168.1.50", Some("Ooma/3.0"), Some("OPTIONS"));

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
        assert!(
            event.contains(r#"method="OPTIONS""#),
            "should contain method"
        );
        // Should not have any stray newlines
        assert!(
            !event.contains('\r') && !event.contains('\n'),
            "normal output should not contain newlines"
        );
    }
    /// The SHIPPED fail2ban filter matches the lines this module writes.
    ///
    /// `contrib/fail2ban/sipnab-scanner.conf` pins the field order of both
    /// format strings above, and nothing checked it. Rename `scanner_detected`,
    /// swap `ua=` and `method=`, or insert a field, and the jail keeps running
    /// and bans nothing — which looks exactly like a quiet network. A filter
    /// that silently stops matching is worse than one that fails to load.
    ///
    /// `src/security/recommend.rs` already proves this property for the
    /// GENERATED failregex. The shipped file is the copy an operator actually
    /// installs, and it had no such test.
    ///
    /// `<HOST>` is fail2ban's own template; substituting a permissive address
    /// pattern tests the LITERAL structure around it, which is the half that
    /// drifts when a log line changes.
    #[test]
    fn the_shipped_filter_matches_the_lines_this_module_writes() -> Result<(), TestError> {
        let conf = include_str!("../../contrib/fail2ban/sipnab-scanner.conf");
        let patterns: Vec<String> = conf
            .lines()
            .skip_while(|l| !l.starts_with("failregex ="))
            .take_while(|l| !l.starts_with("ignoreregex"))
            .map(|l| l.trim_start_matches("failregex =").trim())
            .filter(|l| !l.is_empty())
            .map(|l| l.replace("<HOST>", "(?:[0-9a-fA-F:.]+)"))
            .collect();
        assert_eq!(
            patterns.len(),
            2,
            "the shipped filter should carry one pattern per event this \
             module emits; found {patterns:?}"
        );

        let scanner =
            format_scanner_event("198.51.100.7", Some("friendly-scanner"), Some("OPTIONS"));
        let flood = format_reg_flood_event("198.51.100.9", 42);

        let compiled = patterns
            .iter()
            .map(|p| {
                regex::Regex::new(p)
                    .map_err(|e| format!("shipped failregex does not compile: {p}: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (label, line) in [("scanner", &scanner), ("reg_flood", &flood)] {
            let matched = compiled.iter().any(|r| r.is_match(line));
            assert!(
                matched,
                "no pattern in the shipped filter matches the {label} line \
                 sipnab writes.\npatterns: {patterns:#?}\nline: {line}"
            );
        }
        Ok(())
    }

    /// The shipped patterns are not catch-alls wearing a rule name.
    ///
    /// The half the match test cannot see: `^.*$` would match both lines above
    /// and every other line in the log, so a jail built on it would ban on any
    /// syslog traffic at all.
    #[test]
    fn the_shipped_filter_does_not_match_an_unrelated_line() -> Result<(), TestError> {
        let conf = include_str!("../../contrib/fail2ban/sipnab-scanner.conf");
        let patterns: Vec<String> = conf
            .lines()
            .skip_while(|l| !l.starts_with("failregex ="))
            .take_while(|l| !l.starts_with("ignoreregex"))
            .map(|l| l.trim_start_matches("failregex =").trim())
            .filter(|l| !l.is_empty())
            .map(|l| l.replace("<HOST>", "(?:[0-9a-fA-F:.]+)"))
            .collect();

        for decoy in [
            "2026-09-07 12:00:00 sipnab[1]: capture started on eth0",
            "2026-09-07 12:00:00 sshd[1]: Accepted password for root from 198.51.100.7",
            "2026-09-07 12:00:00 sipnab[1]: scanner_detected src=198.51.100.7",
        ] {
            for p in &patterns {
                assert!(
                    !regex::Regex::new(p)
                        .map_err(|e| format!("compiles: {e:?}"))?
                        .is_match(decoy),
                    "the shipped filter matches a line it must not, so a jail \
                     on it bans the wrong host.\npattern: {p}\nline: {decoy}"
                );
            }
        }
        Ok(())
    }

    /// The value of `key` among the shipped jail's ACTIVE settings: comment
    /// lines are skipped, so a setting shown only as a commented alternative
    /// is not one.
    fn shipped_jail_setting(key: &str) -> Option<String> {
        include_str!("../../contrib/fail2ban/sipnab-jail.conf")
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
            .filter_map(|l| l.split_once('='))
            .find(|(k, _)| k.trim() == key)
            .map(|(_, v)| v.trim().to_string())
    }

    /// The SHIPPED jail bans with nftables and reads the file it names.
    ///
    /// Measured on clean Debian 13 and Ubuntu 24.04 (GUIDE-F2B, 2026-10-01),
    /// the jail as shipped banned nobody on either. Its `iptables-allports`
    /// action needs the `iptables` command, which installing fail2ban on
    /// Debian 13 leaves out: fail2ban listed the address as banned while the
    /// ban action failed with `returned 127`, and the scanner's traffic still
    /// got through. And with no `backend`, Ubuntu's packaged default
    /// (`backend = systemd`) made the jail read the journal and ignore
    /// `logpath`, so it never saw a line sipnab wrote.
    #[test]
    fn the_shipped_jail_bans_with_nftables_and_reads_its_log_file() {
        assert_eq!(
            shipped_jail_setting("action").as_deref(),
            Some(r#"nftables[type=allports, name=sipnab, protocol="udp,tcp"]"#),
            "the shipped jail must ban with nftables on every port, UDP and TCP"
        );
        assert_eq!(
            shipped_jail_setting("backend").as_deref(),
            Some("auto"),
            "without backend = auto, a distribution default of systemd makes \
             the jail read the journal and never the log sipnab writes"
        );
    }

    /// The shipped jail waits for five detections before it bans.
    ///
    /// One was the old setting. A single scanner_detected line is how a busy
    /// trunk can look, and `maxretry = 1` turned any one of them into an
    /// hour's ban of every port (Norm, 2026-10-01: 5).
    #[test]
    fn the_shipped_jail_bans_after_five_detections() {
        assert_eq!(
            shipped_jail_setting("maxretry").as_deref(),
            Some("5"),
            "the shipped jail should ban after five detections inside findtime"
        );
    }

    /// The legacy-iptables action is offered, and only as a comment.
    #[test]
    fn the_shipped_jail_offers_iptables_only_as_a_comment() {
        let conf = include_str!("../../contrib/fail2ban/sipnab-jail.conf");
        let mentions: Vec<&str> = conf
            .lines()
            .filter(|l| l.contains("iptables-allports"))
            .collect();
        assert!(
            !mentions.is_empty(),
            "the shipped jail should show the iptables-allports alternative \
             for hosts without nftables"
        );
        for l in mentions {
            assert!(
                l.trim_start().starts_with('#'),
                "iptables-allports must appear only in a comment, found: {l}"
            );
        }
    }
}
