//! Comprehensive single-call diagnosis report.
//!
//! Generates a detailed report for a single SIP dialog including timing,
//! SIP transactions, media streams, and diagnosed issues. Available in
//! text, JSON, and Markdown formats.

use std::fmt::Write;

use crate::rtp::diagnosis::MediaDiagnosis;
use crate::rtp::stream::RtpStream;
use crate::sip::dialog::{DialogState, SipDialog};

/// Output format for the call report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// Plain text format, suitable for pasting into tickets.
    Text,
    /// Structured JSON with all fields.
    Json,
    /// Markdown with headers and tables.
    Markdown,
}

/// Generate a comprehensive single-call report.
///
/// Produces a detailed analysis of one SIP dialog including:
/// - Call identification and result
/// - Transaction timing (PDD, setup, ring, teardown)
/// - SIP transaction flow
/// - Media stream quality metrics
/// - Diagnosed issues
///
/// The output format is selected by `format`.
pub fn generate_call_report(
    dialog: &SipDialog,
    streams: &[&RtpStream],
    diagnosis: &MediaDiagnosis,
    format: ReportFormat,
) -> String {
    match format {
        ReportFormat::Text => generate_text_report(dialog, streams, diagnosis),
        ReportFormat::Json => super::json::dialog_to_json(dialog, streams, diagnosis),
        ReportFormat::Markdown => generate_markdown_report(dialog, streams, diagnosis),
    }
}

// ── Text format ─────────────────────────────────────────────────────

/// Generate the plain-text call report.
fn generate_text_report(
    dialog: &SipDialog,
    streams: &[&RtpStream],
    diagnosis: &MediaDiagnosis,
) -> String {
    let mut out = String::with_capacity(2048);

    // Header
    let _ = writeln!(out, "Call Report: {}", dialog.call_id);
    let _ = writeln!(out, "{}", "\u{2550}".repeat(40));

    // Identification
    let duration_sec = dialog
        .updated_at
        .signed_duration_since(dialog.created_at)
        .num_seconds();
    let _ = writeln!(
        out,
        "Time:       {} -> {} ({}s)",
        dialog.created_at.format("%Y-%m-%d %H:%M:%S"),
        dialog.updated_at.format("%H:%M:%S"),
        duration_sec,
    );

    let from_str = match (&dialog.from_display, &dialog.from_user) {
        (Some(display), Some(user)) => format!("\"{display}\" <sip:{user}@...>"),
        (None, Some(user)) => format!("<sip:{user}@...>"),
        _ => "-".to_string(),
    };
    let _ = writeln!(out, "From:       {from_str}");

    let to_str = match (&dialog.to_display, &dialog.to_user) {
        (Some(display), Some(user)) => format!("\"{display}\" <sip:{user}@...>"),
        (None, Some(user)) => format!("<sip:{user}@...>"),
        _ => "-".to_string(),
    };
    let _ = writeln!(out, "To:         {to_str}");

    let result_str = match dialog.state() {
        DialogState::Completed => "Completed (BYE)".to_string(),
        DialogState::Cancelled => "Cancelled".to_string(),
        DialogState::Failed => "Failed".to_string(),
        DialogState::InCall => "In Progress".to_string(),
        other => format!("{other:?}"),
    };
    let _ = writeln!(out, "Result:     {result_str}");
    if !dialog.tags.is_empty() {
        let _ = writeln!(out, "Tags:       {}", dialog.tags.join(", "));
    }

    // Timing section
    let _ = writeln!(out);
    let _ = writeln!(out, "Timing:");
    let _ = writeln!(
        out,
        "  PDD:        {}",
        format_timing_ms(dialog.timing.pdd_ms())
    );
    let _ = writeln!(
        out,
        "  Setup:      {}",
        format_timing_ms(dialog.timing.setup_ms())
    );
    let _ = writeln!(
        out,
        "  Ring:       {}",
        format_timing_ms(dialog.timing.ring_ms())
    );
    let _ = writeln!(
        out,
        "  Teardown:   {}",
        format_timing_ms(dialog.timing.teardown_ms())
    );
    let _ = writeln!(out, "  Retransmits: {}", dialog.timing.total_retransmits());

    // SIP transactions section
    let _ = writeln!(out);
    let _ = writeln!(out, "SIP Transactions:");
    write_transaction_flow(&mut out, dialog);

    // Media streams section
    let _ = writeln!(out);
    let _ = writeln!(out, "Media Streams:");
    if streams.is_empty() {
        let _ = writeln!(out, "  None");
    } else {
        for stream in streams {
            let total = stream.packet_count + stream.lost_packets;
            let loss_pct = if total > 0 {
                (stream.lost_packets as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let codec = stream.codec.as_deref().unwrap_or("?");
            let from_to = format!("{}->{}", stream.key.src.ip(), stream.key.dst.ip());
            let _ = writeln!(
                out,
                "  RTP {from_to} {codec} SSRC=0x{:08x} pkts={} jitter={:.0}ms loss={loss_pct:.1}%",
                stream.key.ssrc, stream.packet_count, stream.jitter,
            );
            // Burst/gap analysis for loss pattern characterization
            if let Some(bg) = stream.burst_gap_analysis() {
                if bg.is_bursty {
                    let _ = writeln!(
                        out,
                        "    Loss pattern: BURSTY ({} bursts, avg duration {:.0}ms) \
                         — perceptually worse than random loss",
                        bg.burst_count, bg.burst_duration_ms,
                    );
                } else {
                    let _ = writeln!(out, "    Loss pattern: random (not bursty)");
                }
            }
        }
    }

    // Issues section
    let _ = writeln!(out);
    if diagnosis.hints.is_empty() {
        let _ = writeln!(out, "Issues Detected: None");
    } else {
        let _ = writeln!(out, "Issues Detected:");
        for hint in &diagnosis.hints {
            let _ = writeln!(out, "  - {hint}");
        }
    }

    out
}

// ── Markdown format ─────────────────────────────────────────────────

/// Generate the Markdown call report.
fn generate_markdown_report(
    dialog: &SipDialog,
    streams: &[&RtpStream],
    diagnosis: &MediaDiagnosis,
) -> String {
    let mut out = String::with_capacity(2048);

    let _ = writeln!(out, "# Call Report: {}", dialog.call_id);
    let _ = writeln!(out);

    // Identification
    let duration_sec = dialog
        .updated_at
        .signed_duration_since(dialog.created_at)
        .num_seconds();
    let _ = writeln!(out, "## Summary");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Field | Value |");
    let _ = writeln!(out, "|-------|-------|");
    let _ = writeln!(
        out,
        "| Time | {} -> {} ({}s) |",
        dialog.created_at.format("%Y-%m-%d %H:%M:%S"),
        dialog.updated_at.format("%H:%M:%S"),
        duration_sec,
    );
    let _ = writeln!(
        out,
        "| From | {} |",
        dialog.from_user.as_deref().unwrap_or("-")
    );
    let _ = writeln!(out, "| To | {} |", dialog.to_user.as_deref().unwrap_or("-"));
    let _ = writeln!(out, "| State | {:?} |", dialog.state());
    if !dialog.tags.is_empty() {
        let _ = writeln!(out, "| Tags | {} |", dialog.tags.join(", "));
    }
    let _ = writeln!(out);

    // Timing
    let _ = writeln!(out, "## Timing");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Metric | Value |");
    let _ = writeln!(out, "|--------|-------|");
    let _ = writeln!(
        out,
        "| PDD | {} |",
        format_timing_ms(dialog.timing.pdd_ms())
    );
    let _ = writeln!(
        out,
        "| Setup | {} |",
        format_timing_ms(dialog.timing.setup_ms())
    );
    let _ = writeln!(
        out,
        "| Ring | {} |",
        format_timing_ms(dialog.timing.ring_ms())
    );
    let _ = writeln!(
        out,
        "| Teardown | {} |",
        format_timing_ms(dialog.timing.teardown_ms())
    );
    let _ = writeln!(
        out,
        "| Retransmits | {} |",
        dialog.timing.total_retransmits()
    );
    let _ = writeln!(out);

    // Media streams
    let _ = writeln!(out, "## Media Streams");
    let _ = writeln!(out);
    if streams.is_empty() {
        let _ = writeln!(out, "No media streams detected.");
    } else {
        let _ = writeln!(
            out,
            "| SSRC | Codec | Source | Destination | Packets | Jitter | Loss |"
        );
        let _ = writeln!(
            out,
            "|------|-------|--------|-------------|---------|--------|------|"
        );
        for stream in streams {
            let total = stream.packet_count + stream.lost_packets;
            let loss_pct = if total > 0 {
                (stream.lost_packets as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let _ = writeln!(
                out,
                "| 0x{:08x} | {} | {} | {} | {} | {:.0}ms | {loss_pct:.1}% |",
                stream.key.ssrc,
                stream.codec.as_deref().unwrap_or("?"),
                stream.key.src,
                stream.key.dst,
                stream.packet_count,
                stream.jitter,
            );
        }
    }
    let _ = writeln!(out);

    // Issues
    let _ = writeln!(out, "## Issues");
    let _ = writeln!(out);
    if diagnosis.hints.is_empty() {
        let _ = writeln!(out, "No issues detected.");
    } else {
        for hint in &diagnosis.hints {
            let _ = writeln!(out, "- {hint}");
        }
    }

    out
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Format an optional millisecond timing value as a string.
fn format_timing_ms(ms: Option<i64>) -> String {
    match ms {
        Some(ms) => format!("{:.2}s", ms as f64 / 1000.0),
        None => "-".to_string(),
    }
}

/// Write a simplified SIP transaction flow from dialog messages.
fn write_transaction_flow(out: &mut String, dialog: &SipDialog) {
    // Group messages by CSeq to show transaction flows
    let mut current_cseq: Option<String> = None;
    let mut line = String::new();

    for msg in &dialog.messages {
        let cseq_key = msg.cseq().map(|(n, m)| format!("{n} {m}"));

        if msg.is_request {
            // Flush previous line if we're starting a new transaction
            if !line.is_empty() {
                let _ = writeln!(out, "  {line}");
                line.clear();
            }
            let method = msg.method.as_ref().map(|m| m.as_str()).unwrap_or("???");
            line = method.to_string();
            current_cseq = cseq_key;
        } else if cseq_key == current_cseq {
            // Response to the current transaction
            if let Some(code) = msg.status_code {
                let delay = if let Some(first_msg) = dialog.messages.first() {
                    let delta = msg
                        .timestamp
                        .signed_duration_since(first_msg.timestamp)
                        .num_milliseconds();
                    if delta > 0 {
                        format!(" ({delta}ms)")
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                let _ = write!(line, " -> {code}{delay}");
            }
        }
    }

    // Flush last line
    if !line.is_empty() {
        let _ = writeln!(out, "  {line}");
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::rtp::diagnosis::MediaDiagnosis;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use crate::sip::dialog;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, Utc};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    fn make_dialog_with_messages() -> SipDialog {
        let t0 = base_ts();
        let t1 = t0 + TimeDelta::milliseconds(1230);
        let t2 = t0 + TimeDelta::milliseconds(5790);

        let raw_invite = build_sip(
            "INVITE sip:1002@carrier.net SIP/2.0",
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@carrier.net>",
                "Call-ID: call-report-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let invite = parse_sip(&raw_invite, t0, localhost(), localhost(), 5060, 5060, TransportProto::Udp)
            .expect("should parse");

        let raw_ringing = build_sip(
            "SIP/2.0 180 Ringing",
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@carrier.net>;tag=t2",
                "Call-ID: call-report-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let ringing = parse_sip(
            &raw_ringing,
            t1,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        let raw_ok = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@carrier.net>;tag=t2",
                "Call-ID: call-report-test@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let ok = parse_sip(&raw_ok, t2, localhost(), localhost(), 5060, 5060, TransportProto::Udp)
            .expect("should parse");

        let mut d = SipDialog::new(&invite).expect("should create");
        crate::sip::timing::update_timing(&mut d.timing, &invite, &crate::sip::SipMethod::Invite);

        dialog::update_state(&mut d, &ringing);
        crate::sip::timing::update_timing(&mut d.timing, &ringing, &crate::sip::SipMethod::Invite);
        d.messages.push(ringing.clone());
        d.updated_at = ringing.timestamp;

        dialog::update_state(&mut d, &ok);
        crate::sip::timing::update_timing(&mut d.timing, &ok, &crate::sip::SipMethod::Invite);
        d.messages.push(ok.clone());
        d.updated_at = ok.timestamp;

        d
    }

    fn make_stream() -> RtpStream {
        let key = StreamKey {
            ssrc: 0x12345678,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 100,
            timestamp: 0,
            ssrc: 0x12345678,
            payload_offset: 12,
        };
        RtpStream::new(key, &hdr, base_ts())
    }

    #[test]
    fn text_report_contains_all_sections() {
        let dialog = make_dialog_with_messages();
        let stream = make_stream();
        let streams: Vec<&RtpStream> = vec![&stream];
        let diagnosis = MediaDiagnosis::default();

        let report = generate_call_report(&dialog, &streams, &diagnosis, ReportFormat::Text);

        assert!(report.contains("Call Report:"), "should have title");
        assert!(report.contains("Timing:"), "should have timing section");
        assert!(
            report.contains("SIP Transactions:"),
            "should have transactions section"
        );
        assert!(
            report.contains("Media Streams:"),
            "should have media section"
        );
        assert!(
            report.contains("Issues Detected:"),
            "should have issues section"
        );
        assert!(report.contains("PDD:"), "should have PDD");
        assert!(report.contains("Setup:"), "should have setup time");
    }

    #[test]
    fn json_report_valid() {
        let dialog = make_dialog_with_messages();
        let streams: Vec<&RtpStream> = vec![];
        let diagnosis = MediaDiagnosis::default();

        let report = generate_call_report(&dialog, &streams, &diagnosis, ReportFormat::Json);

        let parsed: serde_json::Value =
            serde_json::from_str(&report).expect("should be valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert!(parsed["timing"].is_object());
    }

    #[test]
    fn markdown_report_contains_headers() {
        let dialog = make_dialog_with_messages();
        let streams: Vec<&RtpStream> = vec![];
        let diagnosis = MediaDiagnosis::default();

        let report = generate_call_report(&dialog, &streams, &diagnosis, ReportFormat::Markdown);

        assert!(report.contains("# Call Report:"), "should have h1");
        assert!(report.contains("## Summary"), "should have summary section");
        assert!(report.contains("## Timing"), "should have timing section");
        assert!(
            report.contains("## Media Streams"),
            "should have media section"
        );
        assert!(report.contains("## Issues"), "should have issues section");
        // Markdown tables
        assert!(report.contains("|"), "should have table pipes");
        assert!(report.contains("---"), "should have table separators");
    }

    #[test]
    fn text_report_with_issues() {
        let dialog = make_dialog_with_messages();
        let streams: Vec<&RtpStream> = vec![];
        let diagnosis = MediaDiagnosis {
            one_way_audio: true,
            hints: vec!["One-way audio detected".to_string()],
            ..Default::default()
        };

        let report = generate_call_report(&dialog, &streams, &diagnosis, ReportFormat::Text);

        assert!(
            report.contains("One-way audio detected"),
            "should contain the hint"
        );
        assert!(
            !report.contains("Issues Detected: None"),
            "should not say None when there are issues"
        );
    }
}
