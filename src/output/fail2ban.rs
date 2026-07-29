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

/// Render an optional header value for a log field.
///
/// # Arguments
///
/// * `v` — the header value, or `None` when the message carried no such header.
///
/// # Returns
///
/// The sanitized value, or the absent marker.
///
/// This is the ONE place the absent marker is decided. Before it, three
/// spellings of the same condition were in the tree at once -- `"unknown"` in
/// the fail2ban path, `""` in `ScannerAlert`, and `"-"` in the kill-target
/// alert -- so the same missing header read differently depending on which line
/// printed it, and no filter could match all three.
pub fn render_absent(v: Option<&str>) -> String {
    match v {
        Some(s) => sanitize_log_value(s),
        None => ABSENT.to_string(),
    }
}

/// What an absent header renders as in a log field.
const ABSENT: &str = "unknown";

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
            event.contains("ua=friendly-scanner"),
            "should contain user agent"
        );
        assert!(event.contains("method=OPTIONS"), "should contain method");
        // Verify timestamp format (YYYY-MM-DD HH:MM:SS)
        let parts: Vec<&str> = event.splitn(3, ' ').collect();
        assert!(parts.len() >= 2, "should have date and time parts");
        assert_eq!(parts[0].len(), 10, "date should be YYYY-MM-DD");
        assert_eq!(parts[1].len(), 8, "time should be HH:MM:SS");
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
        assert!(event.contains("ua=evil"), "sanitized UA should be present");
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
        assert!(event.contains("ua=Ooma/3.0"), "should contain user agent");
        assert!(event.contains("method=OPTIONS"), "should contain method");
        // Should not have any stray newlines
        assert!(
            !event.contains('\r') && !event.contains('\n'),
            "normal output should not contain newlines"
        );
    }
}
