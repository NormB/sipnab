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
/// associated streams, an "Orphaned Streams:" table, and an ICMP media
/// section, each omitted when empty.
///
/// The ICMP section is read from the run's resolved evidence
/// ([`crate::pipeline::icmp_media_findings`]) rather than taken as an
/// argument, for the reason `diagnose_signaling` reads its own: an ICMP error
/// is not a `SipDialog` and not an `RtpStream`, so it cannot arrive through
/// either slice, and a capture that recorded none behaves exactly as it did
/// before the section existed.
pub fn print_dialog_report(dialogs: &[&SipDialog], streams: &[&RtpStream]) -> String {
    print_dialog_report_as(dialogs, streams, crate::output::ReportFormat::Text)
}

/// One row of a table, rendered for the requested format.
///
/// Markdown tables do not depend on column width, which is why `--markdown`
/// also answers the OTHER half of #89: long From/To values overflowed the
/// fixed-width columns and corrupted the alignment, breaking anything parsing
/// the table. A pipe-delimited row cannot be corrupted that way, so the
/// markdown form carries values in FULL where the text form truncates.
fn row(md: bool, widths: &[usize], cells: &[String]) -> String {
    if md {
        format!("| {} |\n", cells.join(" | "))
    } else {
        // Space BETWEEN cells, never after the last: the original format
        // string was "{:<32} {:<14} ... {:<16}", and a trailing space is a
        // real diff to anything comparing this output byte for byte.
        let mut s = String::new();
        for (i, (c, w)) in cells.iter().zip(widths).enumerate() {
            if i > 0 {
                s.push(' ');
            }
            let _ = write!(s, "{c:<w$}");
        }
        s.push('\n');
        s
    }
}

/// The `---|---` separator markdown needs under a header row.
fn md_rule(n: usize) -> String {
    format!("|{}\n", "---|".repeat(n))
}

/// As [`print_dialog_report`], in the requested format.
///
/// `--markdown` was accepted alongside `--report` and did NOTHING: the output
/// was byte-identical with and without it, contradicting help text that says
/// "Format report output as Markdown". A flag that is read, documented and
/// ignored is the same defect class as a config key that parses and never
/// applies (#89).
#[must_use]
pub fn print_dialog_report_as(
    dialogs: &[&SipDialog],
    streams: &[&RtpStream],
    format: crate::output::ReportFormat,
) -> String {
    let md = matches!(format, crate::output::ReportFormat::Markdown);
    let mut out = String::with_capacity(4096);

    // ── Dialog summary table ────────────────────────────────────────
    const SUMMARY_W: [usize; 9] = [32, 14, 14, 12, 6, 10, 6, 8, 16];
    let headers = [
        "Call-ID", "From", "To", "State", "Code", "Duration", "Msgs", "PDD", "Tags",
    ];
    out.push_str(&row(
        md,
        &SUMMARY_W,
        &headers.iter().map(|h| (*h).to_string()).collect::<Vec<_>>(),
    ));
    if md {
        out.push_str(&md_rule(headers.len()));
    } else {
        let _ = writeln!(out, "{}", "-".repeat(121));
    }

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

        // Markdown carries the value in full: there is no column to overflow,
        // and truncating would discard data the format can hold.
        let call_id_cell = if md { dialog.call_id.clone() } else { call_id };
        out.push_str(&row(
            md,
            &SUMMARY_W,
            &[
                call_id_cell,
                from.to_string(),
                to.to_string(),
                state.to_string(),
                code,
                duration,
                msg_count.to_string(),
                pdd,
                tags,
            ],
        ));
    }

    // ── Associated RTP streams ──────────────────────────────────────
    let associated: Vec<&&RtpStream> = streams.iter().filter(|s| !s.orphaned()).collect();
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

    // ── Calls named by a relay, whose signaling is not in this capture ──
    //
    // A stream can be attributed to a Call-ID that has no dialog HERE. That is
    // not a defect, it is the deployment: on a standalone media relay the SIP
    // is on another host entirely, and the only thing naming the call is
    // rtpengine's own control plane. Such a stream is no longer orphaned, so
    // it correctly leaves the orphan table — and without this section its
    // Call-ID would then appear nowhere at all, which would be a worse answer
    // than the orphan row it replaced. The whole point of the attribution is
    // to be able to say WHICH call, so the report has to say it.
    // Keyed on the stream's own recorded provenance, NOT on "has a Call-ID
    // that no dialog here matches". That second test is also true of a dialog
    // the run simply dropped -- `--limit 1` keeps one dialog while its streams
    // keep pointing at the calls that were evicted -- and reporting those as
    // relay-named would be a confident wrong answer about where the name came
    // from. This exact mistake shipped for one gate run and was caught by
    // `limit_caps_tracked_dialogs`.
    let mut relay_named: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();
    for stream in streams {
        if stream.dialog_bound_from_relay()
            && let Some(id) = stream.associated_dialog.as_deref()
        {
            *relay_named.entry(id).or_default() += 1;
        }
    }
    if !relay_named.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Calls named by a media relay (no SIP for them in this capture):"
        );
        let headers = ["Call-ID", "Streams"];
        let widths = [60usize, 8];
        out.push_str(&row(
            md,
            &widths,
            &headers.iter().map(|h| (*h).to_string()).collect::<Vec<_>>(),
        ));
        if md {
            out.push_str(&md_rule(headers.len()));
        } else {
            let _ = writeln!(out, "{}", "-".repeat(69));
        }
        for (call_id, count) in &relay_named {
            // Markdown carries the Call-ID in full; the text form truncates to
            // the column, exactly as the dialog table above does.
            let shown = if md {
                (*call_id).to_string()
            } else {
                truncate_str(call_id, 60)
            };
            out.push_str(&row(md, &widths, &[shown, count.to_string()]));
        }
    }

    // ── Orphaned RTP streams ────────────────────────────────────────
    let orphaned: Vec<&&RtpStream> = streams.iter().filter(|s| s.orphaned()).collect();
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

    // ── What ICMP said about media ──────────────────────────────────
    write_icmp_media_section(&mut out, &crate::pipeline::icmp_media_findings());

    // ── What never decoded ──────────────────────────────────────────
    write_undecodable_section(&mut out, &crate::capture::undecodable_report());

    out
}

/// Append the capture-wide undecodable-frame section, or nothing.
///
/// Read from the run's tally rather than taken as an argument, for the reason
/// the ICMP section reads its own: a frame that never decoded is not a
/// `SipDialog` and not an `RtpStream`, so it can arrive through neither slice,
/// and a report built only from those two can never mention it.
///
/// It belongs in `--report` specifically because that is the surface an
/// operator reads to answer "what is in this capture". An empty dialog table
/// is the answer to that question when the capture was read; when it was not,
/// the empty table is not an answer at all — and the two used to render as
/// the same blank report.
///
/// Not narrowed by `--filter`: a filter selects dialogs, and these frames
/// reached none. Omitted entirely when everything decoded, so a clean report
/// is unchanged.
fn write_undecodable_section(out: &mut String, report: &crate::capture::UndecodableReport) {
    if report.frames == 0 {
        return;
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "NOT DECODED (capture-wide):");
    let _ = writeln!(
        out,
        "{} frame(s) produced no packet at all and are in none of the tables above.",
        report.frames
    );
    let _ = writeln!(out, "{:<48} {:>10}", "Reason", "Frames");
    let _ = writeln!(out, "{}", "-".repeat(59));
    for tally in &report.reasons {
        let _ = writeln!(out, "{:<48} {:>10}", tally.reason.to_string(), tally.frames);
    }
    if report.reasons_dropped > 0 {
        // Never silently absent: a breakdown that does not add up to the
        // total is the same defect as the total not existing.
        let _ = writeln!(
            out,
            "{:<48} {:>10}",
            "(reason not retained — more distinct than the tally holds)", report.reasons_dropped
        );
    }
}

/// Append the capture-wide ICMP media section, or nothing.
///
/// # This section is the LEDGER, and it is capture-wide on purpose
///
/// A media flow is not a dialog. On one real corpus, 205 of 514 ICMP errors
/// quoting non-SIP traffic matched nothing the capture held and one more quoted
/// too little even to be keyed on a flow — so a per-dialog rendering could show
/// at most the 308 that reached a stream or an SDP endpoint, and would drop the
/// rest without saying so. This section therefore reports every retained flow
/// and every outcome counter, and the per-dialog JSON carries only the findings
/// whose attribution named a call. Two views, one set of objects.
///
/// It is not narrowed by `--filter` for the same reason: a filter selects
/// dialogs, and most of these findings belong to none. The heading says
/// "capture-wide" so nobody reads it as filtered.
///
/// # Every row names its tier
///
/// `Tier` is the first column, before the addresses, because it is what decides
/// whether the row is a measurement or a lead: `flow` is an exact directed
/// 5-tuple match against a stream sipnab watched, `none` is no match at all.
/// A table that showed the endpoint without the tier would invite a reader to
/// act on all five as though they were the first.
///
/// # Three outcomes, never two
///
/// `unkeyed` counts errors whose quote stopped before the transport header, so
/// they have no flow to match. That is a different state from "matched
/// nothing", and the summary keeps them apart — the invariants
/// `attributed + unattributed == errors` and
/// `sum(row errors) + unkeyed + untracked == errors` are only checkable while
/// they stay apart.
fn write_icmp_media_section(out: &mut String, resolved: &crate::pipeline::ResolvedIcmpMedia) {
    let report = resolved.report();
    if report.errors == 0 {
        return;
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "ICMP (media, capture-wide):");
    let _ = writeln!(
        out,
        "{} error(s) quoting non-SIP traffic, {} of them media, across {} flow(s) and {} \
         endpoint(s).",
        report.errors,
        report.media,
        report.flows.len(),
        report.endpoints.len(),
    );
    let _ = writeln!(
        out,
        "Attributed to a stream or SDP endpoint: {}; matched nothing this capture holds: {}. \
         Of those, {} quoted too little to name a flow and {} reached no flow because the \
         tracking cap was full; {} endpoint(s) went untallied.",
        report.attributed,
        report.unattributed,
        report.unkeyed,
        report.untracked_flows,
        report.untallied_endpoints,
    );

    if report.flows.is_empty() {
        return;
    }

    let _ = writeln!(
        out,
        "{:<13} {:<9} {:<7} {:<8} {:<6} {:<22} {:<22} {:<16} Description",
        "Tier", "Payload", "Errors", "Streams", "Calls", "Source", "Unreachable", "Reported by",
    );
    let _ = writeln!(out, "{}", "-".repeat(122));
    for f in &report.flows {
        let _ = writeln!(
            out,
            "{:<13} {:<9} {:<7} {:<8} {:<6} {:<22} {:<22} {:<16} {}",
            f.attribution_tier(),
            f.payload_kind(),
            f.errors,
            f.streams,
            f.call_ids.len(),
            f.source,
            f.unreachable_endpoint,
            f.reported_by,
            f.description,
        );
    }
}

/// Convert a `DialogState` to a short display string.
fn state_str(state: &DialogState) -> &'static str {
    match state {
        DialogState::Trying => "Trying",
        DialogState::Ringing => "Ringing",
        DialogState::InCall => "InCall",
        DialogState::Completed => "Completed",
        DialogState::Canceled => "Canceled",
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
    /// (each: start-line + CSeq), so we can craft Failed/Canceled outcomes.
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

    /// A canceled INVITE shows state Canceled with code 487.
    #[test]
    fn cancelled_dialog_shows_487() {
        // INVITE canceled before answer -> State Canceled, Code 487.
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
        assert!(report.contains("Canceled"), "should be Canceled: {report}");
        assert!(
            report.contains("487"),
            "canceled dialog should show its 487 code: {report}"
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
        let mut s = make_rtp_stream();
        // The columns under test belong to the ASSOCIATED table, so the
        // fixture has to be a claimed stream. It used to reach that table by
        // default, back when an unclaimed stream counted as an orphan only
        // after 30 seconds.
        s.associated_dialog = Some("report-test@example.com".to_string());
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

    /// Build the stream of [`make_rtp_stream`] as an orphan: no dialog claims
    /// it, which is the whole of what an orphan is. A distinct SSRC so a mixed
    /// report can name which row landed in which table.
    fn make_orphaned_stream() -> crate::rtp::stream::RtpStream {
        let mut s = make_rtp_stream();
        s.key.ssrc = 0x0bad0bad;
        s.associated_dialog = None;
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

    // ── ICMP media section ─────────────────────────────────────────────

    /// One finding at `matched`, naming `call_ids`.
    fn media_finding(
        matched: crate::pipeline::MediaMatch,
        call_ids: &[&str],
    ) -> crate::pipeline::MediaIcmpFinding {
        crate::pipeline::MediaIcmpFinding {
            source: "192.0.2.1:40000".to_string(),
            unreachable_endpoint: "192.0.2.2:20000".to_string(),
            reported_by: "192.0.2.9".to_string(),
            transport: "UDP",
            description: "port unreachable".to_string(),
            icmp_type: 3,
            icmp_code: 3,
            errors: 4,
            payload: crate::pipeline::QuotedMediaKind::Rtp {
                ssrc: 0x0BAD_F00D,
                payload_type: 0,
            },
            matched,
            streams: 1,
            call_ids: call_ids.iter().map(|s| (*s).to_string()).collect(),
            hint: "audio sent that way is discarded".to_string(),
        }
    }

    /// A resolved set with one finding per tier and all three outcomes used.
    fn resolved_one_per_tier() -> crate::pipeline::ResolvedIcmpMedia {
        use crate::pipeline::MediaMatch;
        let flows: Vec<_> = [
            MediaMatch::Flow,
            MediaMatch::Ssrc,
            MediaMatch::Endpoint,
            MediaMatch::SdpEndpoint,
            MediaMatch::None,
        ]
        .into_iter()
        .map(|m| media_finding(m, &["call-1@example.com"]))
        .collect();
        crate::pipeline::ResolvedIcmpMedia::new(crate::pipeline::IcmpMediaReport {
            errors: 23,
            media: 20,
            attributed: 16,
            unattributed: 7,
            unkeyed: 3,
            untracked_flows: 0,
            untallied_endpoints: 0,
            flows,
            endpoints: Vec::new(),
        })
    }

    /// Every row names its tier, and all five tiers can be told apart.
    ///
    /// The tier is what decides whether a row is a measurement or a lead. A
    /// table that showed the endpoint without it would invite a reader to act
    /// on a `none`-tier guess as though it were an exact 5-tuple match.
    #[test]
    fn every_media_row_names_its_attribution_tier() {
        let mut out = String::new();
        write_icmp_media_section(&mut out, &resolved_one_per_tier());

        let (_, table) = out
            .split_once("Description")
            .unwrap_or_else(|| panic!("the section rendered no table:\n{out}"));
        let rows: Vec<&str> = table
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('-'))
            .collect();
        assert_eq!(rows.len(), 5, "one row per finding:\n{out}");
        for (i, row) in rows.iter().enumerate() {
            let tier = row.split_whitespace().next().unwrap_or("");
            assert!(
                ["flow", "ssrc", "endpoint", "sdp_endpoint", "none"].contains(&tier),
                "row {i} opens with {tier:?}, which is not an attribution tier:\n{out}"
            );
        }
        for tier in ["flow", "ssrc", "endpoint", "sdp_endpoint", "none"] {
            assert_eq!(
                rows.iter()
                    .filter(|r| r.split_whitespace().next() == Some(tier))
                    .count(),
                1,
                "tier {tier} must appear exactly once:\n{out}"
            );
        }
    }

    /// The summary keeps `unkeyed` as its own outcome.
    ///
    /// A quote that stopped before the ports has no flow to match — a third
    /// state, not "matched nothing". Folding it away would make the two
    /// invariants #98 asserts uncheckable from the report.
    #[test]
    fn the_media_summary_reports_unkeyed_separately() {
        let resolved = resolved_one_per_tier();
        let mut out = String::new();
        write_icmp_media_section(&mut out, &resolved);

        assert!(
            out.contains("3 quoted too little to name a flow"),
            "the unkeyed count must be stated, not folded into unattributed:\n{out}"
        );
        assert!(
            out.contains("matched nothing this capture holds: 7"),
            "the unattributed count must be stated:\n{out}"
        );
        // The report is the surface an invariant is checked FROM, so the
        // numbers it prints must still add up.
        let r = resolved.report();
        assert_eq!(r.attributed + r.unattributed, r.errors);
        assert_eq!(
            r.flows.iter().map(|f| f.errors).sum::<u64>() + r.unkeyed + r.untracked_flows,
            r.errors
        );
    }

    /// A finding no dialog can claim is still printed.
    ///
    /// On one real corpus 205 of 514 errors matched nothing the capture held.
    /// A section assembled from dialogs would show none of them, which is the
    /// invisibility this section exists to end.
    #[test]
    fn a_finding_that_named_no_call_is_still_printed() {
        use crate::pipeline::{IcmpMediaReport, MediaMatch, ResolvedIcmpMedia};
        let resolved = ResolvedIcmpMedia::new(IcmpMediaReport {
            errors: 4,
            unattributed: 4,
            flows: vec![media_finding(MediaMatch::None, &[])],
            ..IcmpMediaReport::default()
        });
        let mut out = String::new();
        write_icmp_media_section(&mut out, &resolved);

        let (_, table) = out
            .split_once("Description")
            .unwrap_or_else(|| panic!("a finding with no call produced no table:\n{out}"));
        assert!(
            table.lines().any(|l| l.starts_with("none ")),
            "the unattributed finding must be printed:\n{out}"
        );
    }

    /// A capture with no media ICMP raises no section.
    ///
    /// Absent rather than empty, so "no ICMP section" reads as "this capture
    /// had none" and stays true.
    #[test]
    fn a_capture_with_no_media_icmp_raises_no_section() {
        let mut out = String::new();
        write_icmp_media_section(&mut out, &crate::pipeline::ResolvedIcmpMedia::default());
        assert!(
            out.is_empty(),
            "silence when there is nothing to say: {out}"
        );
    }

    /// The whole report carries the section, not just the writer.
    ///
    /// The writer can be right while nothing calls it, which was the state
    /// this task started from.
    #[test]
    #[serial_test::serial(icmp_evidence)]
    fn the_report_carries_the_media_section() {
        let dialog = make_completed_dialog();

        crate::pipeline::reset_icmp_evidence();
        let clean = print_dialog_report(&[&dialog], &[]);
        assert!(
            !clean.contains("ICMP (media"),
            "a capture with no media ICMP must not grow a section:\n{clean}"
        );

        crate::pipeline::publish_icmp_media_for_test(resolved_one_per_tier());
        let report = print_dialog_report(&[&dialog], &[]);
        crate::pipeline::reset_icmp_evidence();

        assert!(
            report.contains("ICMP (media, capture-wide):"),
            "the report dropped the media section:\n{report}"
        );
        assert!(
            report.contains("sdp_endpoint"),
            "the weakest attributed tier must still reach the report:\n{report}"
        );
    }
}
