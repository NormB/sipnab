// SPDX-License-Identifier: MIT OR Apache-2.0

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
///
/// # Returns
///
/// The formatted report as a `String` (despite the name, nothing is
/// printed): a fixed-width dialog table, then an "RTP Streams:" table for
/// associated streams and an "Orphaned Streams:" table, each section
/// omitted when empty.
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
        // PT (payload type) and Clock disambiguate the codec (e.g. dynamic PTs,
        // a clock-rate mismatch); Lost/Loss%/Jitter are the quality signals;
        // Dur + Kbps catch one-way/short streams and bitrate anomalies.
        let _ = writeln!(
            out,
            "{:<12} {:<4} {:<8} {:<6} {:<21} {:<21} {:<7} {:<6} {:<7} {:<8} {:<6} {:<7}",
            "SSRC",
            "PT",
            "Codec",
            "Clock",
            "Source",
            "Destination",
            "Pkts",
            "Lost",
            "Loss%",
            "Jitter",
            "Dur",
            "Kbps"
        );
        let _ = writeln!(out, "{}", "-".repeat(122));

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
            let dur_s = stream
                .last_seen
                .signed_duration_since(stream.first_seen)
                .num_milliseconds() as f64
                / 1000.0;
            // mean bitrate over the stream's lifetime (payload octets only).
            let kbps = if dur_s > 0.0 {
                (stream.octet_count as f64 * 8.0) / dur_s / 1000.0
            } else {
                0.0
            };

            let _ = writeln!(
                out,
                "{:<12} {:<4} {:<8} {:<6} {:<21} {:<21} {:<7} {:<6} {:<7} {:<8} {:<6} {:<7}",
                ssrc,
                stream.payload_type,
                codec,
                stream.clock_rate,
                src,
                dst,
                stream.packet_count,
                stream.lost_packets,
                format!("{loss_pct:.1}%"),
                format!("{:.0}ms", stream.jitter),
                format!("{dur_s:.0}s"),
                format!("{kbps:.0}"),
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
        DialogState::Redirected => "Redirected",
        DialogState::Registered => "Registered",
        DialogState::Expired => "Expired",
        DialogState::Pending => "Pending",
        DialogState::Active => "Active",
        DialogState::Terminated => "Terminated",
        DialogState::Transferring => "Transferring",
    }
}

/// Format the dialog duration (`created_at` to `updated_at`) as a
/// human-readable string; `"0s"` for dialogs with fewer than 2 messages.
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

/// Format seconds into a compact human-readable string
/// (`45s` / `2m 33s` / `1h 1m 1s`).
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
    // Too small to fit the 3-byte "..." ellipsis plus any content: drop the
    // ellipsis and keep as many whole chars as fit within `max_len` *bytes*,
    // so the result never exceeds the byte budget (a single multi-byte char
    // may be wider than `max_len`, in which case nothing is kept).
    if max_len < 4 {
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        return s[..end].to_string();
    }
    let mut end = max_len - 3;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for the tabular report: dialog rows (state, code, duration),
/// RTP-stream columns, and UTF-8-safe truncation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// The loopback IPv4 address used for all synthetic messages.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed base timestamp (2024-06-15 12:00:00 UTC) for determinism.
    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build a Completed dialog: INVITE followed 153 s later by BYE.
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

    /// A single completed dialog renders Call-ID, users, state, duration,
    /// and the Msgs header.
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

    /// The dialog table header includes the Code column.
    #[test]
    fn report_has_code_column_header() {
        let dialog = make_completed_dialog();
        let report = print_dialog_report(&[&dialog], &[]);
        assert!(
            report.contains("Code"),
            "report should have a Code column header: {report}"
        );
    }

    /// An answered+ended call (200 then BYE) shows final code 200.
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

    /// A 486-rejected INVITE shows state Failed with code 486.
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

    /// A cancelled INVITE shows state Cancelled with code 487.
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

    /// An auth-challenged call that then succeeds reports 200, never the
    /// intermediate 407.
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

    /// A 407 with no authenticated retry reports the 407 as the outcome.
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

    /// A ringing dialog with no final response has no final status code.
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

    /// Build a PCMA stream with 250 pkts / 5 lost / 12 ms jitter over 5 s
    /// (64 kbps) for exercising the RTP table columns.
    fn make_rtp_stream() -> crate::rtp::stream::RtpStream {
        use crate::rtp::parser::RtpHeader;
        use crate::rtp::stream::{RtpStream, StreamKey};
        use std::net::SocketAddr;
        let key = StreamKey {
            ssrc: 0x0a0b0c0d,
            src: "10.0.0.1:20000".parse::<SocketAddr>().unwrap(),
            dst: "10.0.0.2:30000".parse::<SocketAddr>().unwrap(),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 8, // PCMA
            sequence: 100,
            timestamp: 0,
            ssrc: 0x0a0b0c0d,
            payload_offset: 12,
        };
        let mut s = RtpStream::new(key, &hdr, base_ts());
        s.packet_count = 250;
        s.octet_count = 40_000; // 40000 B * 8 / 5 s / 1000 = 64 kbps (G.711)
        s.lost_packets = 5; // 5 / (250+5) = 2.0%
        s.jitter = 12.0;
        s.last_seen = base_ts() + TimeDelta::seconds(5);
        s
    }

    /// The RTP table carries PT/Clock/Lost/Loss%/Jitter/Dur/Kbps columns
    /// with correctly derived values.
    #[test]
    fn rtp_report_includes_pt_and_critical_fields() {
        let s = make_rtp_stream();
        let report = print_dialog_report(&[], &[&s]);
        for col in ["PT", "Clock", "Lost", "Loss%", "Jitter", "Dur", "Kbps"] {
            assert!(
                report.contains(col),
                "RTP header missing column {col}: {report}"
            );
        }
        assert!(
            report.contains("PCMA"),
            "PT 8 should resolve to codec PCMA: {report}"
        );
        assert!(report.contains("8000"), "clock rate 8000 Hz: {report}");
        assert!(
            report.contains("64"),
            "bitrate 64 kbps (40000 B over 5 s): {report}"
        );
        assert!(report.contains("5s"), "duration 5s: {report}");
        assert!(report.contains("2.0%"), "loss 5/(250+5)=2.0%: {report}");
    }

    // ── Orphaned-stream section ────────────────────────────────────────

    /// Build the stream of [`make_rtp_stream`] as an orphan: no dialog, and
    /// flagged by the sweep. A distinct SSRC so a mixed report can name which
    /// row landed in which table.
    fn make_orphaned_stream() -> crate::rtp::stream::RtpStream {
        let mut s = make_rtp_stream();
        s.key.ssrc = 0x0bad0bad;
        s.associated_dialog = None;
        s.orphaned = true;
        s
    }

    /// An orphaned stream renders a row under the orphan heading.
    ///
    /// Filed as "the Orphaned Streams section can never render a row", on the
    /// premise that this renderer is handed one dialog's linked streams and a
    /// linked stream is never flagged orphaned. It is handed the store, not a
    /// dialog: the only production caller is `--report`, which passes every
    /// stream the capture holds whenever no `--filter` narrows it. Under a
    /// filter the section is absent by design — a filter selects dialogs, and
    /// an orphan belongs to none — which `docs/filter-dsl.md` states. The
    /// per-call `--call-report` is a different renderer
    /// (`crate::output::call_report`) with no orphan section at all, so
    /// nothing there can go empty either.
    #[test]
    fn orphaned_stream_renders_under_the_orphan_heading() {
        let s = make_orphaned_stream();

        let report = print_dialog_report(&[], &[&s]);

        let (before, orphans) = report.split_once("Orphaned Streams:").unwrap_or_else(|| {
            panic!("an orphaned stream produced no Orphaned Streams section:\n{report}")
        });
        assert!(
            orphans.contains("0x0bad0bad"),
            "the orphaned stream's SSRC must appear under the heading:\n{report}"
        );
        assert!(
            !before.contains("RTP Streams:"),
            "an orphan has no dialog, so it must not open the associated table:\n{report}"
        );
    }

    /// A stream linked to a dialog raises no orphan heading.
    ///
    /// The section is absent rather than empty, so "no Orphaned Streams" in a
    /// report reads as "this capture had no orphans" and must stay true.
    #[test]
    fn linked_stream_raises_no_orphan_heading() {
        let mut s = make_rtp_stream();
        s.associated_dialog = Some("report-test@example.com".to_string());

        let report = print_dialog_report(&[], &[&s]);

        assert!(
            report.contains("RTP Streams:"),
            "a linked stream belongs in the associated table:\n{report}"
        );
        assert!(
            !report.contains("Orphaned Streams:"),
            "a linked stream is not orphaned and must not raise the heading:\n{report}"
        );
    }

    /// The shape every real capture produces: the two tables partition the
    /// streams, each SSRC under exactly one heading.
    #[test]
    fn mixed_report_partitions_streams_between_the_two_tables() {
        let mut linked = make_rtp_stream();
        linked.associated_dialog = Some("report-test@example.com".to_string());
        let orphan = make_orphaned_stream();

        let report = print_dialog_report(&[], &[&linked, &orphan]);

        let (associated, orphans) = report
            .split_once("Orphaned Streams:")
            .unwrap_or_else(|| panic!("a report holding one orphan needs both tables:\n{report}"));
        assert!(
            associated.contains("0x0a0b0c0d") && !associated.contains("0x0bad0bad"),
            "the associated table must hold the linked stream and only it:\n{report}"
        );
        assert!(
            orphans.contains("0x0bad0bad") && !orphans.contains("0x0a0b0c0d"),
            "the orphan table must hold the orphan and only it:\n{report}"
        );
    }

    /// A long Call-ID is truncated within the limit and ends with "...".
    #[test]
    fn truncate_long_call_id() {
        let result = truncate_str(
            "this-is-a-very-long-call-id-string-that-needs-truncation",
            22,
        );
        assert!(result.len() <= 22);
        assert!(result.ends_with("..."));
    }

    /// `format_seconds` renders seconds, minutes, and hours variants.
    #[test]
    fn format_seconds_variants() {
        assert_eq!(format_seconds(0), "0s");
        assert_eq!(format_seconds(45), "45s");
        assert_eq!(format_seconds(153), "2m 33s");
        assert_eq!(format_seconds(3661), "1h 1m 1s");
    }

    // ── UTF-8 safe truncate_str ────────────────────────────────────────

    /// A string within the limit is returned unchanged.
    #[test]
    fn truncate_str_short_string_unchanged() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    /// Truncation to 8 keeps 5 chars plus the "..." suffix.
    #[test]
    fn truncate_str_exact_ellipsis() {
        assert_eq!(truncate_str("hello world", 8), "hello...");
    }

    /// 2-byte UTF-8 input truncates on a char boundary without panicking.
    #[test]
    fn truncate_str_multibyte_latin_no_panic() {
        // "héllo wörld" contains 2-byte UTF-8 chars
        let result = truncate_str("héllo wörld", 8);
        assert!(result.ends_with("..."));
    }

    /// 3-byte CJK input truncates without panicking or emptying the result.
    #[test]
    fn truncate_str_cjk_no_panic() {
        // "日本語テスト" — each char is 3 bytes in UTF-8
        let result = truncate_str("日本語テスト", 6);
        assert!(!result.is_empty());
    }

    /// Tiny `max_len` values (0..=3, too small for the 3-byte "..." ellipsis)
    /// must never produce a result exceeding `max_len` bytes, even for
    /// multi-byte input where a single char is wider than the budget.
    #[test]
    fn truncate_str_tiny_max_len_respects_byte_contract() {
        // Each CJK char is 3 bytes; 3 chars = 9 bytes total.
        let s = "日本語";
        for max_len in 0..=3 {
            let out = truncate_str(s, max_len);
            assert!(
                out.len() <= max_len,
                "max_len={max_len} produced {} bytes ({out:?})",
                out.len()
            );
        }
        // ASCII sanity: whole chars that fit, no ellipsis when there is no room.
        assert_eq!(truncate_str("hello", 0), "");
        assert_eq!(truncate_str("hello", 3), "hel");
    }
}
