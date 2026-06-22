//! Tabular dialog summary report.
//!
//! Generates a text-based summary table of SIP dialogs and associated
//! RTP streams, suitable for terminal display with `--report`.

use std::fmt::Write;

use crate::rtp::stream::RtpStream;
use crate::sip::dialog::{DialogState, SipDialog};

/// Print a dialog summary report to a string.
///
/// Generates a tabular overview of all dialogs with their timing metrics,
/// followed by associated RTP streams and any orphaned streams.
///
/// # Arguments
///
/// * `dialogs` — Dialogs to include in the report.
/// * `streams` — All RTP streams (both associated and orphaned).
pub fn print_dialog_report(dialogs: &[&SipDialog], streams: &[&RtpStream]) -> String {
    let mut out = String::with_capacity(4096);

    // ── Dialog summary table ────────────────────────────────────────
    let _ = writeln!(
        out,
        "{:<32} {:<14} {:<14} {:<12} {:<6} {:<10} {:<6} {:<8} {:<16}",
        "Call-ID", "From", "To", "State", "Code", "Duration", "Msgs", "PDD", "Tags"
    );
    let _ = writeln!(out, "{}", "-".repeat(121));

    for dialog in dialogs {
        let call_id = truncate_str(&dialog.call_id, 30);
        let from = dialog.from_user.as_deref().unwrap_or("-");
        let to = dialog.to_user.as_deref().unwrap_or("-");
        let state = state_str(dialog.state());
        // The precise SIP response behind the State word (486/503/487/200);
        // "-" while the call is still in progress (no final response yet).
        let code = dialog
            .final_status_code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".to_string());
        let duration = format_duration(dialog);
        let msg_count = dialog.messages.len();
        let pdd = dialog
            .timing
            .pdd_ms()
            .map(|ms| format!("{:.1}s", ms as f64 / 1000.0))
            .unwrap_or_else(|| "-".to_string());
        let tags = if dialog.tags.is_empty() {
            "-".to_string()
        } else {
            dialog.tags.join(", ")
        };

        let _ = writeln!(
            out,
            "{:<32} {:<14} {:<14} {:<12} {:<6} {:<10} {:<6} {:<8} {:<16}",
            call_id, from, to, state, code, duration, msg_count, pdd, tags
        );
    }

    // ── Associated RTP streams ──────────────────────────────────────
    let associated: Vec<&&RtpStream> = streams.iter().filter(|s| !s.orphaned).collect();
    if !associated.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "RTP Streams:");
        let _ = writeln!(
            out,
            "{:<12} {:<8} {:<24} {:<24} {:<8} {:<10} {:<8}",
            "SSRC", "Codec", "Source", "Destination", "Pkts", "Jitter", "Loss"
        );
        let _ = writeln!(out, "{}", "-".repeat(96));

        for stream in &associated {
            let ssrc = format!("0x{:08x}", stream.key.ssrc);
            let codec = stream.codec.as_deref().unwrap_or("?");
            let src = stream.key.src.to_string();
            let dst = stream.key.dst.to_string();
            let total = stream.packet_count + stream.lost_packets;
            let loss_pct = if total > 0 {
                (stream.lost_packets as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            let _ = writeln!(
                out,
                "{:<12} {:<8} {:<24} {:<24} {:<8} {:<10} {:<8}",
                ssrc,
                codec,
                src,
                dst,
                stream.packet_count,
                format!("{:.0}ms", stream.jitter),
                format!("{loss_pct:.1}%"),
            );
        }
    }

    // ── Orphaned RTP streams ────────────────────────────────────────
    let orphaned: Vec<&&RtpStream> = streams.iter().filter(|s| s.orphaned).collect();
    if !orphaned.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Orphaned Streams:");
        let _ = writeln!(
            out,
            "{:<12} {:<24} {:<24} {:<8} {:<10}",
            "SSRC", "Source", "Destination", "Pkts", "Duration"
        );
        let _ = writeln!(out, "{}", "-".repeat(80));

        for stream in &orphaned {
            let ssrc = format!("0x{:08x}", stream.key.ssrc);
            let src = stream.key.src.to_string();
            let dst = stream.key.dst.to_string();
            let dur = stream
                .last_seen
                .signed_duration_since(stream.first_seen)
                .num_seconds();
            let dur_str = format_seconds(dur);

            let _ = writeln!(
                out,
                "{:<12} {:<24} {:<24} {:<8} {:<10}",
                ssrc, src, dst, stream.packet_count, dur_str,
            );
        }
    }

    out
}

/// Convert a `DialogState` to a short display string.
fn state_str(state: &DialogState) -> &'static str {
    match state {
        DialogState::Trying => "Trying",
        DialogState::Ringing => "Ringing",
        DialogState::InCall => "InCall",
        DialogState::Completed => "Completed",
        DialogState::Cancelled => "Cancelled",
        DialogState::Failed => "Failed",
        DialogState::Registered => "Registered",
        DialogState::Expired => "Expired",
        DialogState::Pending => "Pending",
        DialogState::Active => "Active",
        DialogState::Terminated => "Terminated",
        DialogState::Transferring => "Transferring",
    }
}

/// Format the dialog duration as a human-readable string.
fn format_duration(dialog: &SipDialog) -> String {
    if dialog.messages.len() < 2 {
        return "0s".to_string();
    }
    let secs = dialog
        .updated_at
        .signed_duration_since(dialog.created_at)
        .num_seconds();
    format_seconds(secs)
}

/// Format seconds into a compact human-readable string.
fn format_seconds(secs: i64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m {}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

/// Truncate a string to a maximum length, appending "..." if needed.
/// Uses char boundaries to avoid panics on multi-byte UTF-8 input.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    if max_len <= 3 {
        return s.chars().take(max_len).collect();
    }
    let mut end = max_len - 3;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    fn make_completed_dialog() -> SipDialog {
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::seconds(153);

        let raw_invite = build_sip(
            "INVITE sip:1002@example.com SIP/2.0",
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@example.com>",
                "Call-ID: report-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let invite = parse_sip(
            &raw_invite,
            t0,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        let raw_bye = build_sip(
            "BYE sip:1002@example.com SIP/2.0",
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@example.com>;tag=t2",
                "Call-ID: report-test@example.com",
                "CSeq: 2 BYE",
                "Content-Length: 0",
            ],
            b"",
        );
        let bye = parse_sip(
            &raw_bye,
            t1,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        let mut dialog = SipDialog::new(&invite).expect("should create dialog");
        crate::sip::dialog::update_state(&mut dialog, &bye);
        dialog.messages.push(bye.clone());
        dialog.updated_at = bye.timestamp;
        dialog
    }

    #[test]
    fn single_completed_dialog_report() {
        let dialog = make_completed_dialog();
        let dialogs: Vec<&SipDialog> = vec![&dialog];
        let streams: Vec<&crate::rtp::stream::RtpStream> = vec![];

        let report = print_dialog_report(&dialogs, &streams);

        assert!(
            report.contains("report-test@example.com"),
            "should contain Call-ID"
        );
        assert!(report.contains("1001"), "should contain From user");
        assert!(report.contains("1002"), "should contain To user");
        assert!(report.contains("Completed"), "should contain state");
        assert!(
            report.contains("2m 33s"),
            "should contain duration: got {report}"
        );
        assert!(
            report.contains("Msgs"),
            "should contain message count header"
        );
    }

    /// Build an INVITE dialog and drive it with the given follow-up messages
    /// (each: start-line + CSeq), so we can craft Failed/Cancelled outcomes.
    fn make_dialog(call_id: &str, followups: &[(&str, &str, bool)]) -> SipDialog {
        let t0 = base_ts();
        let raw_invite = build_sip(
            "INVITE sip:1002@example.com SIP/2.0",
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let invite = parse_sip(
            &raw_invite,
            t0,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse invite");
        let mut dialog = SipDialog::new(&invite).expect("create dialog");

        for (i, (start, cseq, with_tag)) in followups.iter().enumerate() {
            let to = if *with_tag {
                "To: <sip:1002@example.com>;tag=t2"
            } else {
                "To: <sip:1002@example.com>"
            };
            let raw = build_sip(
                start,
                &[
                    "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                    to,
                    &format!("Call-ID: {call_id}"),
                    cseq,
                    "Content-Length: 0",
                ],
                b"",
            );
            let msg = parse_sip(
                &raw,
                t0 + TimeDelta::seconds(1 + i as i64),
                localhost(),
                localhost(),
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("parse followup");
            crate::sip::dialog::update_state(&mut dialog, &msg);
            dialog.messages.push(msg);
        }
        dialog
    }

    #[test]
    fn report_has_code_column_header() {
        let dialog = make_completed_dialog();
        let report = print_dialog_report(&[&dialog], &[]);
        assert!(
            report.contains("Code"),
            "report should have a Code column header: {report}"
        );
    }

    #[test]
    fn completed_dialog_shows_final_code_200() {
        // A real answered+ended call: INVITE -> 200 (INVITE) -> BYE.
        let dialog = make_dialog(
            "done@example.com",
            &[
                ("SIP/2.0 200 OK", "CSeq: 1 INVITE", true),
                ("BYE sip:1002@example.com SIP/2.0", "CSeq: 2 BYE", true),
            ],
        );
        assert_eq!(dialog.state(), &DialogState::Completed);
        let report = print_dialog_report(&[&dialog], &[]);
        assert!(
            report.contains("200"),
            "completed dialog should show final code 200: {report}"
        );
    }

    #[test]
    fn failed_dialog_shows_response_code() {
        // INVITE rejected with 486 Busy Here -> State Failed, Code 486.
        let dialog = make_dialog(
            "busy@example.com",
            &[("SIP/2.0 486 Busy Here", "CSeq: 1 INVITE", true)],
        );
        let report = print_dialog_report(&[&dialog], &[]);
        assert!(report.contains("Failed"), "should be Failed: {report}");
        assert!(
            report.contains("486"),
            "failed dialog should show its 486 code, not just 'Failed': {report}"
        );
    }

    #[test]
    fn cancelled_dialog_shows_487() {
        // INVITE cancelled before answer -> State Cancelled, Code 487.
        let dialog = make_dialog(
            "cxl@example.com",
            &[
                (
                    "CANCEL sip:1002@example.com SIP/2.0",
                    "CSeq: 1 CANCEL",
                    false,
                ),
                ("SIP/2.0 487 Request Terminated", "CSeq: 1 INVITE", true),
            ],
        );
        let report = print_dialog_report(&[&dialog], &[]);
        assert!(
            report.contains("Cancelled"),
            "should be Cancelled: {report}"
        );
        assert!(
            report.contains("487"),
            "cancelled dialog should show its 487 code: {report}"
        );
    }

    #[test]
    fn auth_challenged_call_reports_final_200_not_407() {
        // INVITE -> 407 (challenge) -> authed INVITE -> 200 -> BYE. The 407 is an
        // intermediate auth step; the call's outcome is 200, not 407.
        let dialog = make_dialog(
            "auth@example.com",
            &[
                (
                    "SIP/2.0 407 Proxy Authentication Required",
                    "CSeq: 1 INVITE",
                    true,
                ),
                ("SIP/2.0 200 OK", "CSeq: 2 INVITE", true),
                ("BYE sip:1002@example.com SIP/2.0", "CSeq: 3 BYE", true),
            ],
        );
        assert_eq!(
            dialog.final_status_code(),
            Some(200),
            "an auth-challenged call that then succeeds reports 200, not the 407 challenge"
        );
        let report = print_dialog_report(&[&dialog], &[]);
        assert!(
            !report.contains("407"),
            "report must not surface the intermediate 407 as the outcome: {report}"
        );
    }

    #[test]
    fn unauthenticated_call_still_reports_the_challenge() {
        // 407 with no authenticated retry: the challenge IS the outcome.
        let dialog = make_dialog(
            "noauth@example.com",
            &[(
                "SIP/2.0 407 Proxy Authentication Required",
                "CSeq: 1 INVITE",
                true,
            )],
        );
        assert_eq!(dialog.final_status_code(), Some(407));
    }

    #[test]
    fn in_progress_dialog_has_no_final_code() {
        // INVITE + 180 Ringing only — no final response yet -> Code "-".
        let dialog = make_dialog(
            "ring@example.com",
            &[("SIP/2.0 180 Ringing", "CSeq: 1 INVITE", true)],
        );
        assert_eq!(
            dialog.final_status_code(),
            None,
            "a ringing dialog has no final status code yet"
        );
    }

    #[test]
    fn truncate_long_call_id() {
        let result = truncate_str(
            "this-is-a-very-long-call-id-string-that-needs-truncation",
            22,
        );
        assert!(result.len() <= 22);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn format_seconds_variants() {
        assert_eq!(format_seconds(0), "0s");
        assert_eq!(format_seconds(45), "45s");
        assert_eq!(format_seconds(153), "2m 33s");
        assert_eq!(format_seconds(3661), "1h 1m 1s");
    }

    // ── UTF-8 safe truncate_str ────────────────────────────────────────

    #[test]
    fn truncate_str_short_string_unchanged() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_exact_ellipsis() {
        assert_eq!(truncate_str("hello world", 8), "hello...");
    }

    #[test]
    fn truncate_str_multibyte_latin_no_panic() {
        // "héllo wörld" contains 2-byte UTF-8 chars
        let result = truncate_str("héllo wörld", 8);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn truncate_str_cjk_no_panic() {
        // "日本語テスト" — each char is 3 bytes in UTF-8
        let result = truncate_str("日本語テスト", 6);
        assert!(!result.is_empty());
    }
}
