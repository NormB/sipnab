// SPDX-License-Identifier: MIT OR Apache-2.0

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

/// ANSI reset — ends any active color span.
const RESET: &str = "\x1b[0m";
/// ANSI green — INVITE requests and 2xx responses.
const GREEN: &str = "\x1b[32m";
/// ANSI red — BYE and CANCEL requests.
const RED: &str = "\x1b[31m";
/// ANSI bold red — error responses (4xx-6xx).
const BOLD_RED: &str = "\x1b[1;31m";
/// ANSI cyan — provisional responses (1xx).
const CYAN: &str = "\x1b[36m";
/// ANSI yellow — other methods and 3xx responses.
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
    /// If `true`, annotate the transport tag with the IANA IP protocol number
    /// (`sipgrep -N`), e.g. `UDP(17)`.
    pub show_proto_number: bool,
}

impl Default for OutputOptions {
    /// Defaults: auto color, absolute timestamps, no payload limit, show
    /// empty-bodied messages, no proto-number annotation.
    fn default() -> Self {
        Self {
            color: ColorMode::Auto,
            delta_time: false,
            payload_limit: None,
            show_empty: true,
            show_proto_number: false,
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
///
/// # Side effects
///
/// Locks stdout, writes the formatted message, and flushes. Writes are
/// best-effort: errors (e.g. broken pipe from `| head`) are swallowed
/// rather than panicking the capture process.
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
///
/// # Arguments
///
/// * `msg` — The parsed SIP message to render.
/// * `opts` — Color mode, delta-time, payload truncation, empty-body, and
///   proto-number options.
/// * `prev_timestamp` — Previous message's timestamp for delta-time mode
///   (`None` renders `+0.000s`).
///
/// # Returns
///
/// The newline-terminated header line, followed by the raw message text
/// when the body is non-empty or `show_empty` is set (truncated with a
/// `[truncated]` marker under `payload_limit`). Pure — nothing printed.
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
            // Derive the sign from the whole delta so sub-second negatives
            // (where `ms / 1000` truncates to 0 and loses the sign) still
            // render as e.g. `-0.500s`.
            let sign = if ms < 0 { "-" } else { "+" };
            let abs_ms = ms.unsigned_abs();
            format!("{sign}{}.{:03}s", abs_ms / 1000, abs_ms % 1000)
        } else {
            "+0.000s".to_string()
        }
    } else {
        msg.timestamp.format("%H:%M:%S%.3f").to_string()
    };

    // Method or status descriptor
    let (descriptor, color_code) = if msg.is_request {
        let method = msg.method.as_ref().map(|m| m.as_str()).unwrap_or("???");
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

    // Transport tag (optionally annotated with the IP proto number, sipgrep -N)
    out.push(' ');
    out.push_str(msg.transport.as_str());
    if opts.show_proto_number {
        let _ = write!(out, "({})", msg.transport.ip_proto_number());
    }
    out.push('\n');

    // Payload (optional, with truncation)
    if !msg.body.is_empty() || opts.show_empty {
        let raw_str = String::from_utf8_lossy(&msg.raw);
        match opts.payload_limit {
            Some(limit) if raw_str.len() > limit => {
                // Back the cut up to a char boundary — the limit is a byte
                // count and may land inside a multibyte UTF-8 sequence.
                let cut = crate::text::floor_char_boundary(&raw_str, limit);
                out.push_str(&raw_str[..cut]);
                out.push_str("\n[truncated]\n");
            }
            _ => {
                // We only reach here when the message has a body OR show_empty
                // is set (the outer guard). Either way, print the full raw so
                // bodyless messages reveal their header block instead of being
                // stuck at the one-line summary.
                out.push_str(&raw_str);
                if !raw_str.ends_with('\n') {
                    out.push('\n');
                }
            }
        }
    }

    out
}

/// Determine whether to use color based on the mode and TTY detection.
/// `Auto` queries `isatty(STDOUT_FILENO)`; `Always`/`Never` are fixed.
fn should_use_color(mode: ColorMode) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            // SAFETY: isatty() with STDOUT_FILENO only reads kernel fd state; cannot cause UB.
            unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for the sipgrep-style formatter: color selection, delta-time,
/// truncation, proto-number annotation, and show-empty semantics.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::parser::parse_sip;
    use std::net::{IpAddr, Ipv4Addr};

    /// The loopback IPv4 address used for all synthetic messages.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed timestamp (2024-06-15 12:00:00 UTC) for determinism.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Parse a minimal bodyless INVITE request.
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
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse INVITE")
    }

    /// Parse a 503 Service Unavailable response (error-color path).
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
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse response")
    }

    /// Parse a bodyless OPTIONS keepalive request.
    fn make_options() -> SipMessage {
        // A bodyless request, like the OPTIONS keepalives in a real trace.
        let raw = build_sip(
            "OPTIONS sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKopt",
                "From: <sip:alice@example.com>;tag=opt1",
                "To: <sip:bob@example.com>",
                "Call-ID: options-keepalive@example.com",
                "CSeq: 42 OPTIONS",
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
        .expect("should parse OPTIONS")
    }

    // Regression: `--show-empty` was a dead flag. Bodyless messages (every
    // response, OPTIONS, REGISTER, ACK, BYE, in-dialog SUBSCRIBE) could only
    // ever show their one-line summary — the raw header block was hard-blocked
    // regardless of the flag, so From/To/Call-ID/CSeq/Via were unreachable in
    // `-N` output. show_empty must actually reveal those headers.
    /// With `show_empty`, bodyless messages print their full header block.
    #[test]
    fn show_empty_reveals_headers_of_bodyless_messages() {
        for msg in [make_options(), make_error_response()] {
            let opts = OutputOptions {
                color: ColorMode::Never,
                show_empty: true,
                ..Default::default()
            };
            let out = format_sip_message(&msg, &opts, None);
            assert!(
                out.contains("Call-ID:") && out.contains("CSeq:"),
                "show_empty must print the full header block of a bodyless \
                 message, but got only:\n{out}"
            );
        }
    }

    // The terse default (no --show-empty) still shows only the summary line for
    // bodyless messages — no wall of headers for every OPTIONS keepalive.
    /// Without `show_empty`, bodyless messages stay a one-line summary.
    #[test]
    fn bodyless_messages_stay_terse_without_show_empty() {
        let opts = OutputOptions {
            color: ColorMode::Never,
            show_empty: false,
            ..Default::default()
        };
        let out = format_sip_message(&make_options(), &opts, None);
        assert!(
            out.contains("OPTIONS") && !out.contains("Call-ID:"),
            "without show_empty a bodyless message must be one line only, \
             got:\n{out}"
        );
    }

    /// An INVITE with `Always` color carries green + reset ANSI codes and
    /// the src -> dst line.
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

    /// `Never` color mode emits no ANSI escapes at all.
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

    /// A 503 response is rendered bold red.
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

    /// A `payload_limit` that lands mid-way through a multibyte UTF-8
    /// character truncates at the previous character boundary instead of
    /// panicking on a byte slice.
    #[test]
    fn payload_limit_mid_utf8_truncates_at_boundary() {
        let body = "média=é".repeat(8);
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: utf8-truncate-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Type: application/sdp",
                &format!("Content-Length: {}", body.len()),
            ],
            body.as_bytes(),
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

        // Aim the limit one byte into the first 'é' of the body so the cut
        // point is guaranteed to be inside a multibyte character.
        let raw_str = String::from_utf8_lossy(&msg.raw).into_owned();
        let limit = raw_str.find('é').expect("body contains é") + 1;
        let opts = OutputOptions {
            color: ColorMode::Never,
            payload_limit: Some(limit),
            ..Default::default()
        };
        let output = format_sip_message(&msg, &opts, None);

        assert!(
            output.contains("[truncated]"),
            "expected [truncated] marker, got: {output}"
        );
        assert!(
            !output.contains('\u{FFFD}'),
            "truncation must not split a UTF-8 sequence"
        );
    }

    /// `payload_limit` truncates the raw dump and appends `[truncated]`.
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

    /// Delta-time mode renders `+1.500s` for a 1500 ms gap.
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

    /// `show_proto_number` renders `UDP(17)` after the transport tag.
    #[test]
    fn proto_number_appended_to_transport_tag() {
        let msg = make_invite();
        let opts = OutputOptions {
            color: ColorMode::Never,
            show_proto_number: true,
            ..Default::default()
        };
        let output = format_sip_message(&msg, &opts, None);
        // UDP transport → IANA number 17, rendered adjacent to the tag.
        assert!(
            output.contains("UDP(17)"),
            "should annotate transport with proto number: got {output}"
        );
    }

    /// The default renders a bare `UDP` tag with no proto number.
    #[test]
    fn proto_number_off_by_default() {
        let msg = make_invite();
        let opts = OutputOptions {
            color: ColorMode::Never,
            ..Default::default()
        };
        let output = format_sip_message(&msg, &opts, None);
        assert!(
            output.contains("UDP") && !output.contains("UDP("),
            "default must show bare transport tag: got {output}"
        );
    }

    /// The proto-number annotation lands after the method's ANSI reset,
    /// never inside the color span.
    #[test]
    fn proto_number_with_color_stays_outside_reset() {
        // Adversarial: the number must not land inside the ANSI color span
        // for the method, which would corrupt the escape sequence.
        let msg = make_invite();
        let opts = OutputOptions {
            color: ColorMode::Always,
            show_proto_number: true,
            ..Default::default()
        };
        let output = format_sip_message(&msg, &opts, None);
        assert!(output.contains("UDP(17)"), "got {output}");
        // The transport annotation sits after the method's RESET.
        let reset_pos = output.find(RESET).expect("reset present");
        let tag_pos = output.find("UDP(17)").expect("tag present");
        assert!(tag_pos > reset_pos, "transport tag must follow reset");
    }

    /// A negative sub-second delta (previous message is newer than the
    /// current one, e.g. out-of-order capture) keeps its negative sign.
    #[test]
    fn delta_time_negative_sub_second_keeps_sign() {
        let msg = make_invite();
        // prev is 500 ms *after* msg.timestamp → delta is -500 ms.
        let prev = ts() + chrono::TimeDelta::milliseconds(500);
        let opts = OutputOptions {
            color: ColorMode::Never,
            delta_time: true,
            ..Default::default()
        };
        let output = format_sip_message(&msg, &opts, Some(prev));

        assert!(
            output.contains("-0.500s"),
            "negative sub-second delta must keep its sign: got {output}"
        );
    }

    /// Delta-time with no previous message renders `+0.000s`.
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
