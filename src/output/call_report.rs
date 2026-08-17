// SPDX-License-Identifier: MIT OR Apache-2.0

//! Comprehensive single-call diagnosis report.
//!
//! Generates a detailed report for a single SIP dialog including timing,
//! SIP transactions, media streams, and diagnosed issues. Available in
//! text, JSON, and Markdown formats.

use std::fmt::Write;

use crate::rtp::diagnosis::MediaDiagnosis;
use crate::rtp::stream::RtpStream;
use crate::sip::diagnosis::{
    AbandonedKind, AuthLoopKind, RegistrationFailureKind, diagnose_signaling,
    registration_rejection_headline,
};
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
///
/// # Arguments
///
/// * `dialog` — The dialog to report on.
/// * `streams` — RTP streams associated with the dialog.
/// * `diagnosis` — Pre-computed media diagnosis whose hints populate the
///   issues section.
/// * `format` — Text, JSON (delegates to `super::json::dialog_to_json`),
///   or Markdown.
///
/// # Returns
///
/// The complete report as a `String`; pure — nothing is printed.
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

// ── Signaling diagnosis rendering ──────────────────────────────────

/// One `(headline, evidence)` pair per signaling detection, ready for either
/// output format.
///
/// Shared rather than written twice: the text and Markdown reports differ only in
/// their bullet syntax, and two copies of the evidence formatting would be two
/// places for "which messages" to drift out of agreement — which is exactly the
/// class of defect the rest of this release was spent removing.
fn signaling_findings(dialog: &SipDialog) -> Vec<(String, String)> {
    let diag = diagnose_signaling(&dialog.messages);
    let mut out = Vec::new();

    if let Some(f) = &diag.final_failure {
        let mut head = format!("Final failure: {} {}", f.code, f.reason_phrase);
        // The Reason header is why this detection carries it at all: a bare 503
        // says nothing, `Q.850;cause=34` says the trunk is full.
        if let Some(r) = &f.reason_header {
            head.push_str(&format!(" [Reason: {r}]"));
        }
        if let Some(w) = &f.warning {
            head.push_str(&format!(" [Warning: {w}]"));
        }
        out.push((head, evidence_label(dialog, &f.evidence)));
    }

    if let Some(a) = &diag.auth_loop {
        let shape = match a.kind {
            AuthLoopKind::CredentialFailure => {
                "credentials sent and rejected each time — wrong password"
            }
            AuthLoopKind::SilentDrop => {
                "no Authorization header ever sent — client not attempting the \
                 challenge, or a proxy stripping it"
            }
        };
        out.push((
            format!("Authentication loop: {} challenges, {shape}", a.challenges),
            evidence_label(dialog, &a.evidence),
        ));
    }

    if let Some(r) = &diag.retransmissions {
        out.push((
            format!(
                "No response to {}: {} transmissions over {:.1}s",
                r.method, r.count, r.span_sec
            ),
            evidence_label(dialog, &r.evidence),
        ));
    }

    if let Some(a) = &diag.ack_missing {
        out.push((
            format!(
                "INVITE answered but never acknowledged: no ACK in {:.1}s, answer sent \
                 {} time(s)",
                a.waited_sec, a.answer_transmissions
            ),
            evidence_label(dialog, &a.evidence),
        ));
    }

    if let Some(a) = &diag.abandoned {
        // The wording carries the whole distinction. "Canceled" is something
        // that happened; "no final response" is something that did not get
        // recorded, and a report that renders them alike hands the reader a
        // conclusion the capture does not support.
        let head = match a.kind {
            AbandonedKind::Canceled => {
                format!(
                    "Canceled by caller after {:.1}s, before any final response",
                    a.elapsed_sec
                )
            }
            AbandonedKind::NoFinalResponse => format!(
                "No final response after {:.1}s — OUTCOME UNKNOWN, not a failure: the \
                 capture may have ended while the call was still up",
                a.elapsed_sec
            ),
        };
        out.push((head, evidence_label(dialog, &a.evidence)));
    }

    if let Some(p) = &diag.post_dial_delay {
        out.push((
            format!(
                "Post-dial delay {:.1}s to the first {} (threshold {:.1}s) — the caller \
                 hears silence for that interval",
                p.delay_sec, p.responded_with, p.threshold_sec
            ),
            evidence_label(dialog, &p.evidence),
        ));
    }

    if let Some(r) = &diag.registration_failure {
        let head = match r.kind {
            // Rendered by the diagnosis module, not restated here. This report
            // used to carry its own copy of the sentence, and the copy said
            // "the endpoint is offline" for every status code — as did the
            // hint it was duplicating. One renderer means the two cannot
            // disagree about what a rejection meant.
            RegistrationFailureKind::Rejected => {
                registration_rejection_headline(r, &dialog.messages)
            }
            RegistrationFailureKind::ShortenedExpiry => format!(
                "Registration granted {}s against {}s requested — re-registers sooner \
                 than intended",
                r.granted_expiry_sec.unwrap_or_default(),
                r.requested_expiry_sec.unwrap_or_default()
            ),
        };
        out.push((head, evidence_label(dialog, &r.evidence)));
    }

    // An ICMP error quoting one of this dialog's requests is the strongest
    // statement a capture can make about reachability: not "nothing came back"
    // but "a router said this host is not there". Name the reporter separately
    // from the unreachable endpoint — they are different machines, and blaming
    // the router would send someone to the wrong device.
    if let Some(i) = &diag.icmp_unreachable {
        out.push((
            format!(
                "ICMP {}: {} unreachable{}, reported by {}",
                i.description,
                i.unreachable_endpoint,
                if i.errors > 1 {
                    format!(" ({} times)", i.errors)
                } else {
                    String::new()
                },
                i.reported_by
            ),
            evidence_label(dialog, &i.evidence),
        ));
    }

    out
}

/// Render evidence indices as something a reader can act on.
///
/// The JSON surface emits bare indices because a machine will join them against
/// the message list. A report pasted into a ticket has no such list to hand, so
/// "messages 1, 3, 5" would send the reader back to the capture to find out what
/// those were. Each index is labeled with what the message actually is.
fn evidence_label(dialog: &SipDialog, indices: &[usize]) -> String {
    let parts: Vec<String> = indices
        .iter()
        .map(|&i| match dialog.messages.get(i) {
            Some(m) if m.is_request => match &m.method {
                Some(meth) => format!("#{i} {meth}"),
                None => format!("#{i} request"),
            },
            Some(m) => match (m.status_code, &m.reason) {
                (Some(c), Some(r)) => format!("#{i} {c} {r}"),
                (Some(c), None) => format!("#{i} {c}"),
                _ => format!("#{i} response"),
            },
            // An index outside the list would mean the diagnosis and the dialog
            // disagree about the message set. Say so rather than dropping it.
            None => format!("#{i} (out of range)"),
        })
        .collect();
    parts.join(", ")
}

// ── Text format ─────────────────────────────────────────────────────

/// Generate the plain-text call report: identification header, timing,
/// transaction flow, media streams (with burst/gap loss analysis), and
/// diagnosed issues.
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
        DialogState::Canceled => "Canceled".to_string(),
        DialogState::Failed => "Failed".to_string(),
        DialogState::InCall => "In Progress".to_string(),
        other => format!("{other:?}"),
    };
    let _ = writeln!(out, "Result:     {result_str}");
    if !dialog.tags.is_empty() {
        let _ = writeln!(out, "Tags:       {}", dialog.tags.join(", "));
    }
    if let Some(frame) = dialog.first_frame.as_ref() {
        // Where this call opened in the capture, as `<source>#<ordinal>@<digest>`.
        // The same pointer the JSON, REST and MCP surfaces carry: copy it to
        // `sipnab --show-frame` to pull the exact bytes, so the human report
        // can be traced to the wire like every machine-read answer. Omitted,
        // not blank, when the dialog has no frame (a live capture stamps none).
        let _ = writeln!(out, "Frame:      {frame}");
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

    // Signaling section, separate from the media issues above because the
    // operator question differs: "was the audio bad" and "why did the call fail"
    // send you to different teams. Omitted when nothing was detected rather than
    // printing a reassuring "None" — the media section above already answers
    // whether anything was checked.
    let signaling = signaling_findings(dialog);
    if !signaling.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Signaling Issues:");
        for (head, evidence) in &signaling {
            let _ = writeln!(out, "  - {head}");
            let _ = writeln!(out, "    evidence: {evidence}");
        }
    }

    out
}

// ── Markdown format ─────────────────────────────────────────────────

/// Generate the Markdown call report: the same sections as the text report
/// rendered as `#`/`##` headers and pipe tables.
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

    // Signaling, as its own section for the same reason as the text report.
    let signaling = signaling_findings(dialog);
    if !signaling.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Signaling");
        let _ = writeln!(out);
        for (head, evidence) in &signaling {
            let _ = writeln!(out, "- **{head}**");
            let _ = writeln!(out, "  - evidence: {evidence}");
        }
    }

    out
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Format an optional millisecond timing value as seconds (`"1.23s"`), or
/// `"-"` for `None`.
fn format_timing_ms(ms: Option<i64>) -> String {
    match ms {
        Some(ms) => format!("{:.2}s", ms as f64 / 1000.0),
        None => "-".to_string(),
    }
}

/// Write a simplified SIP transaction flow from dialog messages.
///
/// Groups messages by CSeq: each request starts a line
/// (`INVITE -> 180 (1230ms) -> 200 (5790ms)`) and responses matching the
/// current transaction are appended with the delay since the dialog's
/// first message. Appends lines to `out`.
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

/// Tests covering all three report formats against a synthetic
/// INVITE/180/200 dialog.
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

    /// The loopback IPv4 address used for all synthetic messages.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed base timestamp (2024-06-15 12:00:00 UTC) for determinism.
    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build a dialog holding INVITE -> 180 (+1.23 s) -> 200 (+5.79 s) with
    /// timing updated at each step.
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
        let ok = parse_sip(
            &raw_ok,
            t2,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
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

    /// Build a fresh single-packet PCMU RTP stream with SSRC 0x12345678.
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

    /// The text report renders every section header plus PDD/setup lines.
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

    /// The text report carries the dialog's opening frame pointer, so a human
    /// reading it can jump to the bytes with `--show-frame` — the same pointer
    /// the JSON, REST and MCP surfaces already provide. Absent (no line, not a
    /// blank one) when the dialog has no frame, the last surface where packet
    /// provenance was missing.
    #[test]
    fn the_text_report_carries_the_frame_pointer_only_when_present() {
        use crate::capture::packet::{FrameOrigin, FrameRef};
        let streams: Vec<&RtpStream> = vec![];
        let diagnosis = MediaDiagnosis::default();

        let mut dialog = make_dialog_with_messages();
        dialog.first_frame = None;
        let without = generate_call_report(&dialog, &streams, &diagnosis, ReportFormat::Text);
        assert!(
            !without.contains("Frame:"),
            "a dialog with no frame must emit no Frame line:\n{without}"
        );

        dialog.first_frame = Some(FrameRef {
            source: std::sync::Arc::from("capture.pcap"),
            origin: FrameOrigin {
                ordinal: 4212,
                digest: Some(0x0123_4567_89ab_cdef),
            },
            kind: crate::capture::packet::FrameSource::Wire,
        });
        let with = generate_call_report(&dialog, &streams, &diagnosis, ReportFormat::Text);
        assert!(
            with.contains("Frame:      capture.pcap#4212@0123456789abcdef"),
            "the report must carry the resolvable <source>#<ordinal>@<digest> \
             pointer that --show-frame accepts:\n{with}"
        );
    }

    /// The JSON report parses as JSON with `schema_version` 1 and a
    /// `timing` object.
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

    /// The Markdown report renders h1/h2 headers and pipe tables.
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

    /// Diagnosis hints appear in the issues section, replacing "None".
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

    // ── Signaling diagnosis rendering ───────────────────────────────

    /// A dialog that failed on a 503 carrying a `Reason:` header.
    fn make_failed_dialog() -> SipDialog {
        let t0 = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let raw_invite = build_sip(
            "INVITE sip:1002@carrier.net SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKfail",
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@carrier.net>",
                "Call-ID: failed-call@example.com",
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

        let raw_fail = build_sip(
            "SIP/2.0 503 Service Unavailable",
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKfail",
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@carrier.net>;tag=t2",
                "Call-ID: failed-call@example.com",
                "CSeq: 1 INVITE",
                "Reason: Q.850;cause=34;text=\"no circuit available\"",
                "Content-Length: 0",
            ],
            b"",
        );
        let fail = parse_sip(
            &raw_fail,
            t0,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        let mut d = SipDialog::new(&invite).expect("should create");
        d.messages.push(fail);
        d
    }

    #[test]
    fn text_report_carries_the_signalling_section_with_evidence() {
        let dialog = make_failed_dialog();
        let stream = make_stream();
        let streams: Vec<&RtpStream> = vec![&stream];
        let report = generate_call_report(
            &dialog,
            &streams,
            &MediaDiagnosis::default(),
            ReportFormat::Text,
        );

        assert!(
            report.contains("Signaling Issues:"),
            "expected a signaling section:\n{report}"
        );
        assert!(report.contains("Final failure: 503 Service Unavailable"));
        // The Reason header is the whole reason the detection carries it.
        assert!(
            report.contains("no circuit available"),
            "Reason header should reach the report:\n{report}"
        );
        // Evidence names the message, not a bare index.
        assert!(
            report.contains("evidence: #1 503 Service Unavailable"),
            "evidence should label the message:\n{report}"
        );
    }

    #[test]
    fn markdown_report_carries_the_signalling_section() {
        let dialog = make_failed_dialog();
        let stream = make_stream();
        let streams: Vec<&RtpStream> = vec![&stream];
        let report = generate_call_report(
            &dialog,
            &streams,
            &MediaDiagnosis::default(),
            ReportFormat::Markdown,
        );

        assert!(
            report.contains("## Signaling"),
            "expected a Signaling header:\n{report}"
        );
        assert!(report.contains("**Final failure: 503 Service Unavailable"));
        assert!(report.contains("- evidence: #1 503 Service Unavailable"));
    }

    #[test]
    fn a_healthy_dialog_gets_no_signalling_section() {
        // make_dialog_with_messages ends on a 200 OK.
        let dialog = make_dialog_with_messages();
        let stream = make_stream();
        let streams: Vec<&RtpStream> = vec![&stream];

        for format in [ReportFormat::Text, ReportFormat::Markdown] {
            let report =
                generate_call_report(&dialog, &streams, &MediaDiagnosis::default(), format);
            assert!(
                !report.contains("Signaling Issues:") && !report.contains("## Signaling"),
                "a successful call must not get a signaling section ({format:?}):\n{report}"
            );
        }
    }

    #[test]
    fn evidence_label_reports_an_out_of_range_index_rather_than_dropping_it() {
        // A silent drop here would mean the report claims fewer messages of
        // evidence than the diagnosis found, which is the failure mode the
        // evidence principle exists to prevent.
        let dialog = make_failed_dialog();
        let label = evidence_label(&dialog, &[0, 99]);
        assert!(label.contains("#0 INVITE"), "got {label}");
        assert!(label.contains("#99 (out of range)"), "got {label}");
    }

    /// A ringing call the capture watched for five minutes without an answer.
    /// Past Timer C, so detection 5 reports it — as *unknown*.
    fn make_unanswered_dialog() -> SipDialog {
        let t0 = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let raw_invite = build_sip(
            "INVITE sip:1002@carrier.net SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKring",
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@carrier.net>",
                "Call-ID: ringing-call@example.com",
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

        let raw_ring = build_sip(
            "SIP/2.0 180 Ringing",
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKring",
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@carrier.net>;tag=t2",
                "Call-ID: ringing-call@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let ring = parse_sip(
            &raw_ring,
            t0 + chrono::TimeDelta::seconds(300),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse");

        let mut d = SipDialog::new(&invite).expect("should create");
        d.messages.push(ring);
        d
    }

    /// The report must not turn a capture that stopped early into a failure.
    /// This is the one detection the spec singles out as most likely to lie,
    /// and the lie would live in the wording rather than in the data.
    #[test]
    fn an_unanswered_call_is_reported_as_unknown_not_failed() {
        let dialog = make_unanswered_dialog();
        let stream = make_stream();
        let streams: Vec<&RtpStream> = vec![&stream];
        let report = generate_call_report(
            &dialog,
            &streams,
            &MediaDiagnosis::default(),
            ReportFormat::Text,
        );
        assert!(
            report.contains("OUTCOME UNKNOWN"),
            "expected an explicit unknown, got:\n{report}"
        );
        assert!(
            !report.contains("Final failure"),
            "a call with no final response has not failed:\n{report}"
        );
    }

    #[test]
    fn markdown_report_renders_the_same_unknown_finding() {
        let dialog = make_unanswered_dialog();
        let stream = make_stream();
        let streams: Vec<&RtpStream> = vec![&stream];
        let report = generate_call_report(
            &dialog,
            &streams,
            &MediaDiagnosis::default(),
            ReportFormat::Markdown,
        );
        assert!(report.contains("## Signaling"), "got:\n{report}");
        assert!(report.contains("OUTCOME UNKNOWN"), "got:\n{report}");
    }

    /// A `REGISTER` challenged `401`, answered with credentials, and refused
    /// `403` — the shape the corpus keeps, and the one this report used to
    /// summarize as an offline endpoint.
    fn make_rejected_registration_dialog() -> SipDialog {
        let t0 = base_ts();
        let build = |first_line: &str, extra: &[&str], offset: i64| {
            let mut headers = vec![
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKreg",
                "From: <sip:1001@example.com>;tag=t1",
                "To: <sip:1001@example.com>",
                "Call-ID: rejected-registration@example.com",
                "CSeq: 1 REGISTER",
            ];
            headers.extend_from_slice(extra);
            headers.push("Content-Length: 0");
            let raw = build_sip(first_line, &headers, b"");
            parse_sip(
                &raw,
                t0 + TimeDelta::milliseconds(offset),
                localhost(),
                localhost(),
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("should parse")
        };

        let register = build(
            "REGISTER sip:example.com SIP/2.0",
            &["Contact: <sip:1001@127.0.0.1>", "Expires: 3600"],
            0,
        );
        let challenge = build("SIP/2.0 401 Unauthorized", &[], 10);
        let authed = build(
            "REGISTER sip:example.com SIP/2.0",
            &[
                "Contact: <sip:1001@127.0.0.1>",
                "Expires: 3600",
                "Authorization: Digest username=\"1001\", realm=\"example.com\", \
                 nonce=\"abc\", uri=\"sip:example.com\", response=\"deadbeef\"",
            ],
            20,
        );
        let refused = build("SIP/2.0 403 Forbidden", &[], 30);

        let mut d = SipDialog::new(&register).expect("should create");
        d.messages.push(challenge);
        d.messages.push(authed);
        d.messages.push(refused);
        d
    }

    /// The report renders exactly what the diagnosis says, character for
    /// character.
    ///
    /// It used to render its OWN sentence, and both copies claimed the
    /// endpoint was offline for every status code there is. An assertion on
    /// the wording alone would let the two drift apart again as long as each
    /// stayed individually plausible, so this pins them to one string.
    #[test]
    fn the_report_renders_the_shared_registration_headline() {
        let dialog = make_rejected_registration_dialog();
        let diag = crate::sip::diagnosis::diagnose_signaling(&dialog.messages);
        let failure = diag
            .registration_failure
            .expect("403 rejects the registration");
        let expected =
            crate::sip::diagnosis::registration_rejection_headline(&failure, &dialog.messages);

        for format in [ReportFormat::Text, ReportFormat::Markdown] {
            let report = generate_call_report(&dialog, &[], &MediaDiagnosis::default(), format);
            assert!(
                report.contains(&expected),
                "{format:?} report must carry the diagnosis headline verbatim.\n\
                 expected: {expected}\ngot:\n{report}"
            );
        }
    }

    /// The claim itself, asserted on the rendered report rather than on the
    /// function that builds it: an operator reading this page must not be
    /// sent to check connectivity for a phone that answered a challenge in
    /// the same four messages.
    #[test]
    fn the_report_never_calls_a_rejected_registration_offline() {
        let dialog = make_rejected_registration_dialog();
        let report =
            generate_call_report(&dialog, &[], &MediaDiagnosis::default(), ReportFormat::Text);
        assert!(
            !report.to_lowercase().contains("offline"),
            "the endpoint answered the 401 in this capture:\n{report}"
        );
        assert!(
            report.contains("credentials"),
            "403 after an answered challenge is a credential rejection:\n{report}"
        );
    }
}
