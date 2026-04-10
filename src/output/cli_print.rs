//! sipgrep-style colored terminal output for SIP messages.
//!
//! Formats SIP messages with ANSI color codes for method-based highlighting,
//! timestamp display, and optional payload truncation. Designed for live
//! capture output similar to `sipgrep` and `sngrep`.

use std::fmt::Write as _;
use std::io::{self, Write};

use chrono::{DateTime, Utc};

use crate::sip::SipMessage;

// ── ANSI escape codes ───────────────────────────────────────────────

const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const BOLD_RED: &str = "\x1b[1;31m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";

/// Controls whether ANSI color codes are emitted in output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    /// Emit colors only when stdout is a TTY.
    Auto,
    /// Always emit ANSI color codes.
    Always,
    /// Never emit ANSI color codes.
    Never,
}

/// Options controlling SIP message display formatting.
#[derive(Debug, Clone)]
pub struct OutputOptions {
    /// When to emit ANSI color codes.
    pub color: ColorMode,
    /// If `true`, show time since previous message instead of absolute timestamp.
    pub delta_time: bool,
    /// If `Some(n)`, truncate the displayed payload at `n` bytes.
    pub payload_limit: Option<usize>,
    /// If `true`, show messages even when the body is empty.
    pub show_empty: bool,
}

impl Default for OutputOptions {
    fn default() -> Self {
        Self {
            color: ColorMode::Auto,
            delta_time: false,
            payload_limit: None,
            show_empty: true,
        }
    }
}

/// Print a SIP message in sipgrep-style colored format to stdout.
///
/// Format: `timestamp src:port -> dst:port method/status_code`
///
/// Color scheme:
/// - INVITE = green
/// - BYE = red
/// - Error responses (4xx-6xx) = bold red
/// - Provisional responses (1xx) = cyan
/// - Other responses = yellow
///
/// The `prev_timestamp` is used when `opts.delta_time` is `true` to compute
/// the time delta from the previous message.
pub fn print_sip_message(
    msg: &SipMessage,
    opts: &OutputOptions,
    prev_timestamp: Option<DateTime<Utc>>,
) {
    let output = format_sip_message(msg, opts, prev_timestamp);
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    // Best-effort write; don't panic on broken pipe
    let _ = handle.write_all(output.as_bytes());
    let _ = handle.flush();
}

/// Format a SIP message into a display string (testable without stdout).
pub fn format_sip_message(
    msg: &SipMessage,
    opts: &OutputOptions,
    prev_timestamp: Option<DateTime<Utc>>,
) -> String {
    let use_color = should_use_color(opts.color);
    let mut out = String::with_capacity(256);

    // Timestamp
    let time_str = if opts.delta_time {
        if let Some(prev) = prev_timestamp {
            let delta = msg.timestamp.signed_duration_since(prev);
            let ms = delta.num_milliseconds();
            format!("+{}.{:03}s", ms / 1000, ms.abs() % 1000)
        } else {
            "+0.000s".to_string()
        }
    } else {
        msg.timestamp.format("%H:%M:%S%.3f").to_string()
    };

    // Method or status descriptor
    let (descriptor, color_code) = if msg.is_request {
        let method = msg.method.as_deref().unwrap_or("???");
        let color = match method {
            "INVITE" => GREEN,
            "BYE" => RED,
            "CANCEL" => RED,
            _ => YELLOW,
        };
        (method.to_string(), color)
    } else {
        let code = msg.status_code.unwrap_or(0);
        let reason = msg.reason.as_deref().unwrap_or("");
        let color = match code {
            100..=199 => CYAN,
            200..=299 => GREEN,
            300..=399 => YELLOW,
            400..=699 => BOLD_RED,
            _ => RESET,
        };
        (format!("{code} {reason}"), color)
    };

    // Build the header line
    if use_color {
        let _ = write!(
            out,
            "{time_str} {src}:{sp} -> {dst}:{dp} {color}{desc}{reset}",
            src = msg.src_addr,
            sp = msg.src_port,
            dst = msg.dst_addr,
            dp = msg.dst_port,
            color = color_code,
            desc = descriptor,
            reset = RESET,
        );
    } else {
        let _ = write!(
            out,
            "{time_str} {src}:{sp} -> {dst}:{dp} {desc}",
            src = msg.src_addr,
            sp = msg.src_port,
            dst = msg.dst_addr,
            dp = msg.dst_port,
            desc = descriptor,
        );
    }

    // Transport tag
    out.push(' ');
    out.push_str(&msg.transport);
    out.push('\n');

    // Payload (optional, with truncation)
    if !msg.body.is_empty() || opts.show_empty {
        let raw_str = String::from_utf8_lossy(&msg.raw);
        match opts.payload_limit {
            Some(limit) if raw_str.len() > limit => {
                out.push_str(&raw_str[..limit]);
                out.push_str("\n[truncated]\n");
            }
            _ => {
                // Don't dump full raw for show_empty with no body
                if !msg.body.is_empty() {
                    out.push_str(&raw_str);
                    if !raw_str.ends_with('\n') {
                        out.push('\n');
                    }
                }
            }
        }
    }

    out
}

/// Determine whether to use color based on the mode and TTY detection.
fn should_use_color(mode: ColorMode) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            // Check if stdout is a TTY
            unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip;
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    fn make_invite() -> SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: cli-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse INVITE")
    }

    fn make_error_response() -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 503 Service Unavailable",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: cli-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse response")
    }

    #[test]
    fn format_invite_with_color() {
        let msg = make_invite();
        let opts = OutputOptions {
            color: ColorMode::Always,
            ..Default::default()
        };
        let output = format_sip_message(&msg, &opts, None);

        assert!(output.contains("INVITE"), "should contain INVITE");
        assert!(output.contains(GREEN), "should contain green ANSI code");
        assert!(output.contains(RESET), "should contain reset code");
        assert!(
            output.contains("127.0.0.1:5060"),
            "should contain source address"
        );
        assert!(output.contains("->"), "should contain arrow");
    }

    #[test]
    fn format_no_color() {
        let msg = make_invite();
        let opts = OutputOptions {
            color: ColorMode::Never,
            ..Default::default()
        };
        let output = format_sip_message(&msg, &opts, None);

        assert!(output.contains("INVITE"), "should contain INVITE");
        assert!(
            !output.contains('\x1b'),
            "should not contain ANSI escape codes"
        );
    }

    #[test]
    fn format_error_response_bold_red() {
        let msg = make_error_response();
        let opts = OutputOptions {
            color: ColorMode::Always,
            ..Default::default()
        };
        let output = format_sip_message(&msg, &opts, None);

        assert!(output.contains("503"), "should contain status code");
        assert!(
            output.contains(BOLD_RED),
            "should contain bold red for error response"
        );
    }

    #[test]
    fn payload_limit_truncates() {
        let body = b"v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\n";
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: truncate-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Type: application/sdp",
                &format!("Content-Length: {}", body.len()),
            ],
            body,
        );
        let msg = parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP")
            .expect("should parse");

        let opts = OutputOptions {
            color: ColorMode::Never,
            payload_limit: Some(20),
            ..Default::default()
        };
        let output = format_sip_message(&msg, &opts, None);

        assert!(
            output.contains("[truncated]"),
            "should contain truncation marker"
        );
    }

    #[test]
    fn delta_time_format() {
        let msg = make_invite();
        let prev = ts() - chrono::TimeDelta::milliseconds(1500);
        let opts = OutputOptions {
            color: ColorMode::Never,
            delta_time: true,
            ..Default::default()
        };
        let output = format_sip_message(&msg, &opts, Some(prev));

        assert!(
            output.contains("+1.500s"),
            "should show delta time: got {output}"
        );
    }

    #[test]
    fn delta_time_no_previous() {
        let msg = make_invite();
        let opts = OutputOptions {
            color: ColorMode::Never,
            delta_time: true,
            ..Default::default()
        };
        let output = format_sip_message(&msg, &opts, None);

        assert!(
            output.contains("+0.000s"),
            "should show zero delta when no previous"
        );
    }
}
