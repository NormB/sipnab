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

/// Format a SIP scanner detection event for fail2ban log parsing.
///
/// Output format:
/// ```text
/// YYYY-MM-DD HH:MM:SS sipnab[PID]: scanner_detected src=<IP> ua=<UA> method=<METHOD>
/// ```
///
/// The PID is obtained from the current process for log correlation.
/// Attacker-controlled values (UA, method) are sanitized to prevent CRLF injection.
pub fn format_scanner_event(src_ip: &str, ua: &str, method: &str) -> String {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    let pid = std::process::id();
    let safe_ua = sanitize_log_value(ua);
    let safe_method = sanitize_log_value(method);
    format!("{now} sipnab[{pid}]: scanner_detected src={src_ip} ua={safe_ua} method={safe_method}")
}

/// Format a registration flood detection event for fail2ban log parsing.
///
/// Output format:
/// ```text
/// YYYY-MM-DD HH:MM:SS sipnab[PID]: reg_flood src=<IP> count=<COUNT>
/// ```
pub fn format_reg_flood_event(src_ip: &str, count: u32) -> String {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    let pid = std::process::id();
    format!("{now} sipnab[{pid}]: reg_flood src={src_ip} count={count}")
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_event_format() {
        let event = format_scanner_event("10.0.0.5", "friendly-scanner", "OPTIONS");

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
}
