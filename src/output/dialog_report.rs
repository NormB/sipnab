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
        "{:<32} {:<14} {:<14} {:<12} {:<10} {:<6} {:<8}",
        "Call-ID", "From", "To", "State", "Duration", "Msgs", "PDD"
    );
    let _ = writeln!(out, "{}", "-".repeat(98));

    for dialog in dialogs {
        let call_id = truncate_str(&dialog.call_id, 30);
        let from = dialog.from_user.as_deref().unwrap_or("-");
        let to = dialog.to_user.as_deref().unwrap_or("-");
        let state = state_str(&dialog.state);
        let duration = format_duration(dialog);
        let msg_count = dialog.messages.len();
        let pdd = dialog
            .timing
            .pdd_ms()
            .map(|ms| format!("{:.1}s", ms as f64 / 1000.0))
            .unwrap_or_else(|| "-".to_string());

        let _ = writeln!(
            out,
            "{:<32} {:<14} {:<14} {:<12} {:<10} {:<6} {:<8}",
            call_id, from, to, state, duration, msg_count, pdd
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
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn build_sip(first_line: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(first_line.as_bytes());
        msg.extend_from_slice(b"\r\n");
        for h in headers {
            msg.extend_from_slice(h.as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        msg.extend_from_slice(body);
        msg
    }

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
        let invite = parse_sip(&raw_invite, t0, localhost(), localhost(), 5060, 5060, "UDP")
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
        let bye = parse_sip(&raw_bye, t1, localhost(), localhost(), 5060, 5060, "UDP")
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
}
