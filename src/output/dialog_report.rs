// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Tabular dialog summary report.
//!
//! Generates a text-based summary table of SIP dialogs and associated
//! RTP streams, suitable for terminal display with `--report`.

use std::fmt::Write;

use crate::rtp::stream::RtpStream;
use crate::sip::dialog::{DialogState, SipDialog};

/// The SIPREC block for one recorded dialog, or `None` for a dialog no
/// recorder described.
///
/// One renderer for `--report` and `--call-report`. The CLI reports are the
/// surface an operator reads without an agent or an HTTP client; both print the
/// recording session and mode, the participants, and each stream's label
/// resolved to the AOR of the party that sends it, since a participant id is a
/// UUID nobody reads off a screen.
#[must_use]
pub(crate) fn siprec_block(d: &SipDialog) -> Option<String> {
    let md = d.siprec_metadata.as_ref()?;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "SIPREC recording ({}): session {}, {}",
        d.call_id,
        md.session_id.as_deref().unwrap_or("id not stated"),
        md.mode.as_deref().unwrap_or("mode not stated")
    );
    for p in &md.participants {
        let aor = p.aor.as_deref().unwrap_or("aor not stated");
        match p.name.as_deref() {
            Some(n) => {
                let _ = writeln!(out, "  participant {aor} ({n})");
            }
            None => {
                let _ = writeln!(out, "  participant {aor}");
            }
        }
    }
    for st in &md.streams {
        let owner = st.participant_id.as_deref().map_or_else(
            || "no participant claims it".to_string(),
            |o| {
                md.participants
                    .iter()
                    .find(|p| p.participant_id.as_deref() == Some(o))
                    .and_then(|p| p.aor.clone())
                    .unwrap_or_else(|| o.to_string())
            },
        );
        let _ = writeln!(
            out,
            "  stream label {} -> {owner}",
            st.label.as_deref().unwrap_or("?")
        );
    }
    Some(out)
}

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

/// What to say about media-creating relay commands, or nothing.
///
/// `subscribe`, `publish` and `start recording` create media that belongs to a
/// call without being one of its two legs. sipnab counts them rather than
/// attributing them: counted as an ordinary leg, a two-party call reports
/// three streams, and the media analysis that judges one-way audio and
/// asymmetry then answers a question nobody asked.
///
/// Takes the count rather than reading the process-global tally, so a test can
/// state what it is testing. The tally is shared by every test in the binary
/// and an exact assertion against it is only true until the next test runs.
///
/// `None` at zero: a run with nothing to report says nothing, rather than
/// printing a line whose only content is a zero.
fn media_creating_note(count: u64) -> Option<String> {
    (count > 0).then(|| {
        format!(
            "Media-creating relay commands seen: {count}. These create media \
             that belongs to a call without being one of its two legs \
             (recording or forking). Decoding them is what sipnab declines: \
             counted as an ordinary leg, a two-party call reports three \
             streams. This is a count of what went past, not a claim about \
             where the media for it ended up."
        )
    })
}

/// Column widths for a fixed-width table: each column as wide as its
/// widest cell, header included, and never narrower than its `minimums`
/// entry.
///
/// A fixed width is a guess about the longest value, and a value longer than
/// the guess does not truncate: `{:<8}` prints all fifteen characters of
/// `telephone-event` and shifts every later column of that row to the right,
/// so the row no longer lines up with its header or its neighbors. An IPv6
/// socket overflows a column sized for IPv4 the same way. Sizing from the
/// cells keeps every value whole and every column straight; the minimums keep
/// a table of short values exactly as it printed before.
fn fitted_widths(minimums: &[usize], header: &[&str], rows: &[Vec<String>]) -> Vec<usize> {
    minimums
        .iter()
        .enumerate()
        .map(|(i, &min)| {
            let header_w = header.get(i).map_or(0, |h| h.chars().count());
            rows.iter()
                .filter_map(|r| r.get(i))
                .map(|c| c.chars().count())
                .fold(min.max(header_w), usize::max)
        })
        .collect()
}

/// The dashed rule under a fixed-width table: `base` long, plus however many
/// characters [`fitted_widths`] added to the columns.
fn rule_for(base: usize, minimums: &[usize], widths: &[usize]) -> String {
    let grown: usize = widths
        .iter()
        .zip(minimums)
        .map(|(w, m)| w.saturating_sub(*m))
        .sum();
    "-".repeat(base + grown)
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

    // ── SIPREC recording metadata ───────────────────────────────────
    //
    // Printed before the stream tables because it says what the streams below
    // are: on a recorded call, which of them a recorder was told about and
    // whose they are.
    for d in dialogs {
        if let Some(block) = siprec_block(d) {
            let _ = writeln!(out);
            out.push_str(&block);
        }
    }

    // ── Associated RTP streams ──────────────────────────────────────
    let associated: Vec<&&RtpStream> = streams.iter().filter(|s| !s.orphaned()).collect();
    if !associated.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "RTP Streams:");
        // PT (payload type) and Clock disambiguate the codec (e.g. dynamic PTs,
        // a clock-rate mismatch); Lost/Loss%/Jitter are the quality signals;
        // Dur + Kbps catch one-way/short streams and bitrate anomalies.
        const RTP_MIN_W: [usize; 12] = [12, 4, 8, 6, 21, 21, 7, 6, 7, 8, 6, 7];
        let header = [
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
            "Kbps",
        ];
        let mut rows: Vec<Vec<String>> = Vec::with_capacity(associated.len());
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

            rows.push(vec![
                ssrc,
                stream.payload_type.to_string(),
                codec.to_string(),
                stream.clock_rate.to_string(),
                src,
                dst,
                stream.packet_count.to_string(),
                stream.lost_packets.to_string(),
                format!("{loss_pct:.1}%"),
                format!("{:.0}ms", stream.jitter),
                format!("{dur_s:.0}s"),
                format!("{kbps:.0}"),
            ]);
        }
        let widths = fitted_widths(&RTP_MIN_W, &header, &rows);
        out.push_str(&row(
            false,
            &widths,
            &header.iter().map(|h| (*h).to_string()).collect::<Vec<_>>(),
        ));
        let _ = writeln!(out, "{}", rule_for(122, &RTP_MIN_W, &widths));
        for cells in &rows {
            out.push_str(&row(false, &widths, cells));
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
    // BOTH conditions, and the heading is why. Provenance alone says a relay
    // named the stream, which is true and useful but is ALSO true when the
    // call's signaling is right here in the same capture -- a proxy anchoring
    // media through a co-resident relay produces exactly that. Listing those
    // under a heading that says "no SIP for them in this capture" states
    // something false about a call whose SIP is three lines further up.
    //
    // Absence of a dialog alone is the other half, and is what the first
    // version used on its own. That is wrong the other way: it is also true of
    // a dialog `--limit` evicted, whose streams were named by ordinary
    // signaling. Neither test is sufficient; the section is about calls that
    // are BOTH relay-named AND unrepresented here.
    let signaled: std::collections::HashSet<&str> =
        dialogs.iter().map(|d| d.call_id.as_str()).collect();
    let mut relay_named: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();
    for stream in streams {
        if stream.dialog_bound_from_relay()
            && let Some(id) = stream.associated_dialog.as_deref()
            && !signaled.contains(id)
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

    // A run that saw a recording or forking command and says nothing is the
    // failure `note_media_creating_command` was added to prevent, and for a
    // while it was the failure anyway: the count existed and no surface read
    // it. Reported HERE, beside the relay-named calls, because both answer the
    // same question -- what did the relay do that this report does not show as
    // an ordinary call leg.
    if let Some(note) = media_creating_note(crate::relay::media_creating_commands_seen()) {
        let _ = writeln!(out);
        let _ = writeln!(out, "{note}");
    }

    // ── Orphaned RTP streams ────────────────────────────────────────
    let orphaned: Vec<&&RtpStream> = streams.iter().filter(|s| s.orphaned()).collect();
    if !orphaned.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Orphaned Streams:");
        const ORPHAN_MIN_W: [usize; 5] = [12, 24, 24, 8, 10];
        let header = ["SSRC", "Source", "Destination", "Pkts", "Duration"];
        let mut rows: Vec<Vec<String>> = Vec::with_capacity(orphaned.len());
        for stream in &orphaned {
            let ssrc = format!("0x{:08x}", stream.key.ssrc);
            let src = stream.key.src.to_string();
            let dst = stream.key.dst.to_string();
            let dur = stream
                .last_seen
                .signed_duration_since(stream.first_seen)
                .num_seconds();
            let dur_str = format_seconds(dur);

            rows.push(vec![
                ssrc,
                src,
                dst,
                stream.packet_count.to_string(),
                dur_str,
            ]);
        }
        let widths = fitted_widths(&ORPHAN_MIN_W, &header, &rows);
        out.push_str(&row(
            false,
            &widths,
            &header.iter().map(|h| (*h).to_string()).collect::<Vec<_>>(),
        ));
        let _ = writeln!(out, "{}", rule_for(80, &ORPHAN_MIN_W, &widths));
        for cells in &rows {
            out.push_str(&row(false, &widths, cells));
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
    state.as_str()
}

/// Format the dialog duration (`created_at` to `updated_at`) as a
/// human-readable string; `"0s"` for dialogs with fewer than 2 messages.
fn format_duration(dialog: &SipDialog) -> String {
    format_seconds(dialog_duration_secs(dialog))
}

/// A dialog's duration in whole seconds, `created_at` to `updated_at`; `0`
/// for a dialog with fewer than 2 messages. The one rule the dialog table's
/// Duration column and the vCon container report's durations both read.
#[must_use]
pub fn dialog_duration_secs(dialog: &SipDialog) -> i64 {
    if dialog.messages.len() < 2 {
        return 0;
    }
    dialog
        .updated_at
        .signed_duration_since(dialog.created_at)
        .num_seconds()
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

// ── vCon containers ──────────────────────────────────────────────────

/// Version of [`VconContainersReport`]'s shape.
pub const VCON_CONTAINERS_SCHEMA_VERSION: u32 = 1;

/// The top-level key of the JSON line `--report --json` writes the vCon
/// container report under. No dialog or message object has it, so a reader
/// of the line stream tells the report from the rest by looking at the line.
pub const VCON_CONTAINERS_JSON_KEY: &str = "sipnab_vcon_containers";

/// `status` of a container the run read.
pub const VCON_READ: &str = "read";

/// `status` of a container the run skipped.
pub const VCON_SKIPPED: &str = "skipped";

/// One stored vCon container a run met: read, with what it contributed, or
/// skipped, with why.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Default)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct VconContainerRow {
    /// `read` or `skipped`.
    pub status: String,
    /// The file. `-I` names it as it named the input; the MCP tool names it
    /// relative to the directory it was asked for.
    pub file: String,
    /// The container's `uuid`; null when it has none, or did not open far
    /// enough to show one.
    pub uuid: Option<String>,
    /// The form the file arrived in, by its outermost layer: `unsigned`,
    /// `signed`, `encrypted`, `gzip`, or `unknown` for bytes that are not a
    /// JSON object.
    pub form: String,
    /// Places the unsigned vCon disagrees with the vendored
    /// draft-ietf-vcon-vcon-core-04 schema. Null when the schema check did
    /// not run: the file did not open, or is not JSON.
    pub validation_findings: Option<usize>,
    /// Calls (dialogs, by Call-ID) rebuilt from the container.
    pub calls_rebuilt: usize,
    /// Their Call-IDs, sorted.
    pub call_ids: Vec<String>,
    /// Those calls counted by state, the word the dialog table's State
    /// column prints.
    pub dispositions: std::collections::BTreeMap<String, u64>,
    /// Those calls' durations added up, in whole seconds, each as the dialog
    /// table's Duration column computes it.
    pub duration_secs: i64,
    /// Why a skipped container was not read, as one word: `no_key`,
    /// `no_sip_signaling`, `not_json`, `not_a_vcon`, `not_opened`,
    /// `unsupported_critical` or `unreadable`. Absent on a read row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// The same reason in full, as the `Skipping` warning prints it. Absent
    /// on a read row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_detail: Option<String>,
}

/// What the rows add up to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Default)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct VconContainerTotals {
    /// Container files met: `read` plus `skipped`.
    pub containers: usize,
    /// Containers read.
    pub read: usize,
    /// Containers skipped.
    pub skipped: usize,
    /// Skipped containers counted by `skip_reason`.
    pub skipped_by_reason: std::collections::BTreeMap<String, u64>,
    /// Containers, read or skipped, with at least one schema finding.
    pub failed_validation: usize,
    /// Distinct calls rebuilt across the read containers. A call two
    /// containers both hold counts once here, and in each of their rows.
    pub calls: usize,
    /// Those distinct calls counted by state.
    pub dispositions: std::collections::BTreeMap<String, u64>,
    /// Those distinct calls' durations added up, in whole seconds.
    pub duration_secs: i64,
}

/// One report over every stored vCon container a run met: `--report`'s vCon
/// section, the `sipnab_vcon_containers` line of `--report --json`, and the
/// MCP `vcon_directory_report` answer. One builder,
/// [`vcon_containers_report`], feeds all three.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Default)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct VconContainersReport {
    /// [`VCON_CONTAINERS_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// One row per container file, in file-name order.
    pub containers: Vec<VconContainerRow>,
    /// The rows added up.
    pub totals: VconContainerTotals,
}

impl VconContainersReport {
    /// Whether the run met no container at all, so there is nothing to print.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.containers.is_empty()
    }
}

/// Build the vCon container report.
///
/// # Arguments
///
/// * `read` — the containers read, as [`crate::capture::vcon_input::read_report`]
///   holds them.
/// * `skipped` — the containers skipped, as
///   [`crate::capture::vcon_input::skipped_report`] holds them.
/// * `dialogs` — the store the read containers were rebuilt into: each row's
///   states and durations are read from the dialogs its Call-IDs name.
#[must_use]
pub fn vcon_containers_report(
    read: &[crate::capture::vcon_input::VconProvenance],
    skipped: &[crate::capture::vcon_input::VconSkip],
    dialogs: &crate::sip::dialog_store::DialogStore,
) -> VconContainersReport {
    use std::collections::BTreeMap;
    // The state word and duration of one call; a call the store no longer
    // holds (a cap evicted it) is counted under its own word, not dropped.
    let call = |id: &str| -> (String, i64) {
        dialogs.get(id).map_or_else(
            || ("NotRetained".to_string(), 0),
            |d| (state_str(d.state()).to_string(), dialog_duration_secs(d)),
        )
    };
    let mut rows: Vec<VconContainerRow> = Vec::with_capacity(read.len() + skipped.len());
    let mut distinct: BTreeMap<&str, (String, i64)> = BTreeMap::new();
    for p in read {
        let mut dispositions: BTreeMap<String, u64> = BTreeMap::new();
        let mut duration_secs = 0i64;
        for id in &p.call_ids {
            let (state, secs) = call(id);
            *dispositions.entry(state.clone()).or_insert(0) += 1;
            duration_secs = duration_secs.saturating_add(secs);
            distinct.insert(id.as_str(), (state, secs));
        }
        rows.push(VconContainerRow {
            status: VCON_READ.to_string(),
            file: p.source.clone(),
            uuid: p.uuid.clone(),
            form: p.form.as_str().to_string(),
            validation_findings: Some(p.schema_findings.len()),
            calls_rebuilt: p.call_ids.len(),
            call_ids: p.call_ids.clone(),
            dispositions,
            duration_secs,
            skip_reason: None,
            skip_detail: None,
        });
    }
    let mut skipped_by_reason: BTreeMap<String, u64> = BTreeMap::new();
    for s in skipped {
        *skipped_by_reason.entry(s.reason.clone()).or_insert(0) += 1;
        rows.push(VconContainerRow {
            status: VCON_SKIPPED.to_string(),
            file: s.source.clone(),
            uuid: s.uuid.clone(),
            form: s.form.as_str().to_string(),
            validation_findings: s.validation_findings,
            skip_reason: Some(s.reason.clone()),
            skip_detail: Some(s.detail.clone()),
            ..VconContainerRow::default()
        });
    }
    rows.sort_by(|a, b| a.file.cmp(&b.file));
    let mut dispositions: BTreeMap<String, u64> = BTreeMap::new();
    let mut duration_secs = 0i64;
    for (state, secs) in distinct.values() {
        *dispositions.entry(state.clone()).or_insert(0) += 1;
        duration_secs = duration_secs.saturating_add(*secs);
    }
    let totals = VconContainerTotals {
        containers: rows.len(),
        read: read.len(),
        skipped: skipped.len(),
        skipped_by_reason,
        failed_validation: rows
            .iter()
            .filter(|r| r.validation_findings.is_some_and(|n| n > 0))
            .count(),
        calls: distinct.len(),
        dispositions,
        duration_secs,
    };
    VconContainersReport {
        schema_version: VCON_CONTAINERS_SCHEMA_VERSION,
        containers: rows,
        totals,
    }
}

/// `word count, word count` for a histogram, or `none` for an empty one.
fn histogram(counts: &std::collections::BTreeMap<String, u64>) -> String {
    if counts.is_empty() {
        return "none".to_string();
    }
    counts
        .iter()
        .map(|(k, v)| format!("{k} {v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The vCon container section of `--report`, in text or Markdown: one row
/// per container, the totals, and each skipped container's reason in full.
/// Empty when the run met no container, so a capture's report is unchanged.
#[must_use]
pub fn render_vcon_containers(
    report: &VconContainersReport,
    format: crate::output::ReportFormat,
) -> String {
    if report.is_empty() {
        return String::new();
    }
    let md = matches!(format, crate::output::ReportFormat::Markdown);
    // The file last: a long path then runs past the table's right edge
    // instead of pushing every column after it out of line.
    const W: [usize; 8] = [26, 10, 9, 6, 9, 24, 37, 0];
    let headers = [
        "Status",
        "Form",
        "Findings",
        "Calls",
        "Duration",
        "Disposition",
        "UUID",
        "File",
    ];
    let mut out = String::from("\nvCon containers:\n");
    out.push_str(&row(
        md,
        &W,
        &headers.iter().map(|h| (*h).to_string()).collect::<Vec<_>>(),
    ));
    if md {
        out.push_str(&md_rule(headers.len()));
    } else {
        let _ = writeln!(out, "{}", "-".repeat(130));
    }
    for r in &report.containers {
        let status = r
            .skip_reason
            .as_deref()
            .map_or_else(|| r.status.clone(), |why| format!("{}: {why}", r.status));
        let disposition = if r.dispositions.is_empty() {
            "-".to_string()
        } else {
            histogram(&r.dispositions)
        };
        let line = row(
            md,
            &W,
            &[
                status,
                r.form.clone(),
                r.validation_findings
                    .map_or_else(|| "-".to_string(), |n| n.to_string()),
                r.calls_rebuilt.to_string(),
                format_seconds(r.duration_secs),
                disposition,
                r.uuid.clone().unwrap_or_else(|| "-".to_string()),
                r.file.clone(),
            ],
        );
        // `row` pads the last cell too; the file ends the line.
        let _ = writeln!(out, "{}", line.trim_end());
    }
    let t = &report.totals;
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Totals: {} container(s): {} read, {} skipped",
        t.containers, t.read, t.skipped
    );
    let _ = writeln!(
        out,
        "Skipped by reason: {}",
        histogram(&t.skipped_by_reason)
    );
    let _ = writeln!(
        out,
        "Failed validation: {} container(s)",
        t.failed_validation
    );
    let _ = writeln!(out, "Calls: {} ({})", t.calls, histogram(&t.dispositions));
    let _ = writeln!(out, "Total duration: {}", format_seconds(t.duration_secs));
    let skips: Vec<&VconContainerRow> = report
        .containers
        .iter()
        .filter(|r| r.skip_detail.is_some())
        .collect();
    if !skips.is_empty() {
        let _ = writeln!(out, "\nSkipped:");
        for r in skips {
            let _ = writeln!(
                out,
                "  {}: {}",
                r.file,
                r.skip_detail.as_deref().unwrap_or_default()
            );
        }
    }
    out
}

/// The vCon container report as the line `--report --json` writes:
/// `{"sipnab_vcon_containers": {...}}`, compact and newline-terminated, or
/// pretty-printed for `--json-pretty`. Empty when the run met no container.
#[must_use]
pub fn vcon_containers_json_line(report: &VconContainersReport, pretty: bool) -> String {
    if report.is_empty() {
        return String::new();
    }
    let value = serde_json::json!({ VCON_CONTAINERS_JSON_KEY: report });
    let text = if pretty {
        serde_json::to_string_pretty(&value)
    } else {
        serde_json::to_string(&value)
    };
    text.map(|t| t + "\n").unwrap_or_default()
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

    type TestError = Box<dyn std::error::Error>;

    /// The loopback IPv4 address used for all synthetic messages.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Fixed base timestamp (2024-06-15 12:00:00 UTC) for determinism.
    fn base_ts() -> Result<DateTime<Utc>, TestError> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0)
            .single()
            .ok_or_else(|| "2024-06-15T12:00:00Z is a valid timestamp".into())
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build a Completed dialog: INVITE followed 153 s later by BYE.
    fn make_completed_dialog() -> Result<SipDialog, TestError> {
        let t0 = base_ts()?;
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
        .map_err(|e| format!("should parse: {e:?}"))?;

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
        .map_err(|e| format!("should parse: {e:?}"))?;

        let mut dialog = SipDialog::new(&invite).ok_or("should create dialog")?;
        crate::sip::dialog::update_state(&mut dialog, &bye);
        dialog.messages.push(bye.clone());
        dialog.updated_at = bye.timestamp;
        Ok(dialog)
    }

    /// The vCon container report counts a call two containers both hold once
    /// in the totals and in each row, counts a call the store no longer holds
    /// under its own word, and totals skips by reason and schema failures
    /// across read and skipped rows alike.
    #[test]
    fn the_vcon_container_totals_count_each_call_once() -> Result<(), TestError> {
        use crate::capture::vcon_input::{ContainerForm, VconProvenance, VconSkip};
        let dialog = make_completed_dialog()?;
        let mut store = crate::sip::dialog_store::DialogStore::new(16, false);
        for m in &dialog.messages {
            store.process_message(m.clone());
        }
        let held = store.get("report-test@example.com").ok_or("dialog held")?;
        let state = held.state().as_str().to_string();
        let secs = dialog_duration_secs(held);
        assert_eq!(secs, 153);
        let both = vec!["report-test@example.com".to_string()];
        let read = [
            VconProvenance {
                source: "b.vcon.json".into(),
                call_ids: both.clone(),
                schema_findings: vec!["/x (type): y".into()],
                ..VconProvenance::default()
            },
            VconProvenance {
                source: "a.vcon.json".into(),
                call_ids: vec![both[0].clone(), "gone@example.com".into()],
                form: ContainerForm::Gzip,
                ..VconProvenance::default()
            },
        ];
        let skipped = [VconSkip {
            source: "c.vcon.json".into(),
            reason: "no_sip_signaling".into(),
            detail: "a vCon container with no SIP signaling".into(),
            validation_findings: Some(2),
            ..VconSkip::default()
        }];
        let r = vcon_containers_report(&read, &skipped, &store);
        let files: Vec<&str> = r.containers.iter().map(|c| c.file.as_str()).collect();
        assert_eq!(files, ["a.vcon.json", "b.vcon.json", "c.vcon.json"]);
        let a = &r.containers[0];
        assert_eq!(a.form, "gzip");
        assert_eq!(a.calls_rebuilt, 2);
        assert_eq!(a.duration_secs, secs);
        assert_eq!(a.dispositions.get("NotRetained"), Some(&1));
        assert_eq!(r.containers[1].dispositions.get(&state), Some(&1));
        assert_eq!(r.containers[1].duration_secs, secs);
        let t = &r.totals;
        assert_eq!((t.containers, t.read, t.skipped), (3, 2, 1));
        assert_eq!(t.calls, 2, "one call held by two containers counts once");
        assert_eq!(t.duration_secs, secs, "and its duration once");
        assert_eq!(t.dispositions.get(&state), Some(&1));
        assert_eq!(t.skipped_by_reason.get("no_sip_signaling"), Some(&1));
        assert_eq!(t.failed_validation, 2);

        let text = render_vcon_containers(&r, crate::output::ReportFormat::Text);
        assert!(
            text.contains("Totals: 3 container(s): 2 read, 1 skipped"),
            "{text}"
        );
        assert!(text.contains("Total duration: 2m 33s"), "{text}");
        let line = vcon_containers_json_line(&r, false);
        let v: serde_json::Value = serde_json::from_str(&line)?;
        assert_eq!(v[VCON_CONTAINERS_JSON_KEY]["totals"]["calls"], 2);
        Ok(())
    }

    /// A run that met no container prints nothing, in either form.
    #[test]
    fn no_container_no_vcon_section() {
        let store = crate::sip::dialog_store::DialogStore::new(1, false);
        let r = vcon_containers_report(&[], &[], &store);
        assert!(render_vcon_containers(&r, crate::output::ReportFormat::Text).is_empty());
        assert!(vcon_containers_json_line(&r, false).is_empty());
    }

    /// A single completed dialog renders Call-ID, users, state, duration,
    /// and the Msgs header.
    #[test]
    fn single_completed_dialog_report() -> Result<(), TestError> {
        let dialog = make_completed_dialog()?;
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
        Ok(())
    }

    /// Build an INVITE dialog and drive it with the given follow-up messages
    /// (each: start-line + CSeq), so we can craft Failed/Canceled outcomes.
    /// A recorded call names its recording in the text report.
    ///
    /// The CLI report is what an operator reads with no agent and no HTTP
    /// client, and it was the one surface the metadata did not reach after
    /// MCP, REST and the ladder had it. Surface parity is a rule here, and a
    /// report that omits the recording is the reader who most needs it going
    /// without.
    #[test]
    fn a_recorded_call_names_its_recording_in_the_report() -> Result<(), TestError> {
        let mut d = make_dialog("rec@test", &[])?;
        d.siprec_metadata = Some(crate::sip::siprec::SirecMetadata {
            session_id: Some("sess-9".to_string()),
            mode: Some("complete".to_string()),
            participants: vec![crate::sip::siprec::SirecParticipant {
                participant_id: Some("p1".to_string()),
                aor: Some("sip:alice@example.invalid".to_string()),
                name: Some("Alice".to_string()),
            }],
            streams: vec![crate::sip::siprec::SirecStream {
                stream_id: Some("s1".to_string()),
                label: Some("0".to_string()),
                participant_id: Some("p1".to_string()),
            }],
        });
        let report = print_dialog_report(&[&d], &[]);
        assert!(
            report.contains("SIPREC recording"),
            "the report must say the call is recorded:\n{report}"
        );
        assert!(
            report.contains("sess-9") && report.contains("complete"),
            "with the session and the mode:\n{report}"
        );
        assert!(
            report.contains("sip:alice@example.invalid"),
            "and who is on it:\n{report}"
        );
        assert!(
            report.contains("stream label 0 -> sip:alice@example.invalid"),
            "and each stream resolved to the party that sends it, by AOR rather \
             than by the UUID an operator cannot read:\n{report}"
        );
        Ok(())
    }

    /// An ordinary call raises no recording heading.
    #[test]
    fn an_unrecorded_call_raises_no_siprec_heading() -> Result<(), TestError> {
        let d = make_dialog("plain@test", &[])?;
        let report = print_dialog_report(&[&d], &[]);
        assert!(
            !report.contains("SIPREC"),
            "a call nobody recorded must not be labeled as recorded:\n{report}"
        );
        Ok(())
    }

    fn make_dialog(
        call_id: &str,
        followups: &[(&str, &str, bool)],
    ) -> Result<SipDialog, TestError> {
        let t0 = base_ts()?;
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
        .map_err(|e| format!("parse invite: {e:?}"))?;
        let mut dialog = SipDialog::new(&invite).ok_or("create dialog")?;

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
            .map_err(|e| format!("parse followup: {e:?}"))?;
            crate::sip::dialog::update_state(&mut dialog, &msg);
            dialog.messages.push(msg);
        }
        Ok(dialog)
    }

    /// The dialog table header includes the Code column.
    #[test]
    fn report_has_code_column_header() -> Result<(), TestError> {
        let dialog = make_completed_dialog()?;
        let report = print_dialog_report(&[&dialog], &[]);
        assert!(
            report.contains("Code"),
            "report should have a Code column header: {report}"
        );
        Ok(())
    }

    /// An answered+ended call (200 then BYE) shows final code 200.
    #[test]
    fn completed_dialog_shows_final_code_200() -> Result<(), TestError> {
        // A real answered+ended call: INVITE -> 200 (INVITE) -> BYE.
        let dialog = make_dialog(
            "done@example.com",
            &[
                ("SIP/2.0 200 OK", "CSeq: 1 INVITE", true),
                ("BYE sip:1002@example.com SIP/2.0", "CSeq: 2 BYE", true),
            ],
        )?;
        assert_eq!(dialog.state(), &DialogState::Completed);
        let report = print_dialog_report(&[&dialog], &[]);
        assert!(
            report.contains("200"),
            "completed dialog should show final code 200: {report}"
        );
        Ok(())
    }

    /// A 486-rejected INVITE shows state Failed with code 486.
    #[test]
    fn failed_dialog_shows_response_code() -> Result<(), TestError> {
        // INVITE rejected with 486 Busy Here -> State Failed, Code 486.
        let dialog = make_dialog(
            "busy@example.com",
            &[("SIP/2.0 486 Busy Here", "CSeq: 1 INVITE", true)],
        )?;
        let report = print_dialog_report(&[&dialog], &[]);
        assert!(report.contains("Failed"), "should be Failed: {report}");
        assert!(
            report.contains("486"),
            "failed dialog should show its 486 code, not just 'Failed': {report}"
        );
        Ok(())
    }

    /// A canceled INVITE shows state Canceled with code 487.
    #[test]
    fn canceled_dialog_shows_487() -> Result<(), TestError> {
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
        )?;
        let report = print_dialog_report(&[&dialog], &[]);
        assert!(report.contains("Canceled"), "should be Canceled: {report}");
        assert!(
            report.contains("487"),
            "canceled dialog should show its 487 code: {report}"
        );
        Ok(())
    }

    /// An auth-challenged call that then succeeds reports 200, never the
    /// intermediate 407.
    #[test]
    fn auth_challenged_call_reports_final_200_not_407() -> Result<(), TestError> {
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
        )?;
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
        Ok(())
    }

    /// A 407 with no authenticated retry reports the 407 as the outcome.
    #[test]
    fn unauthenticated_call_still_reports_the_challenge() -> Result<(), TestError> {
        // 407 with no authenticated retry: the challenge IS the outcome.
        let dialog = make_dialog(
            "noauth@example.com",
            &[(
                "SIP/2.0 407 Proxy Authentication Required",
                "CSeq: 1 INVITE",
                true,
            )],
        )?;
        assert_eq!(dialog.final_status_code(), Some(407));
        Ok(())
    }

    /// A ringing dialog with no final response has no final status code.
    #[test]
    fn in_progress_dialog_has_no_final_code() -> Result<(), TestError> {
        // INVITE + 180 Ringing only — no final response yet -> Code "-".
        let dialog = make_dialog(
            "ring@example.com",
            &[("SIP/2.0 180 Ringing", "CSeq: 1 INVITE", true)],
        )?;
        assert_eq!(
            dialog.final_status_code(),
            None,
            "a ringing dialog has no final status code yet"
        );
        Ok(())
    }

    /// Build a PCMA stream with 250 pkts / 5 lost / 12 ms jitter over 5 s
    /// (64 kbps) for exercising the RTP table columns.
    fn make_rtp_stream() -> Result<crate::rtp::stream::RtpStream, TestError> {
        use crate::rtp::parser::RtpHeader;
        use crate::rtp::stream::{RtpStream, StreamKey};
        use std::net::SocketAddr;
        let key = StreamKey {
            ssrc: 0x0a0b0c0d,
            src: "10.0.0.1:20000".parse::<SocketAddr>()?,
            dst: "10.0.0.2:30000".parse::<SocketAddr>()?,
            session: 0,
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
        let mut s = RtpStream::new(key, &hdr, base_ts()?);
        s.packet_count = 250;
        s.octet_count = 40_000; // 40000 B * 8 / 5 s / 1000 = 64 kbps (G.711)
        s.lost_packets = 5; // 5 / (250+5) = 2.0%
        s.jitter = 12.0;
        s.last_seen = base_ts()? + TimeDelta::seconds(5);
        Ok(s)
    }

    /// The RTP table carries PT/Clock/Lost/Loss%/Jitter/Dur/Kbps columns
    /// with correctly derived values.
    #[test]
    fn rtp_report_includes_pt_and_critical_fields() -> Result<(), TestError> {
        let mut s = make_rtp_stream()?;
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
        Ok(())
    }

    /// The lines of the table under `heading`, header first, dashed rule
    /// dropped, up to the first blank line.
    fn table_under<'a>(report: &'a str, heading: &str) -> Vec<&'a str> {
        let mut lines = report.lines().skip_while(|l| *l != heading).skip(1);
        let mut out: Vec<&str> = lines.next().into_iter().collect();
        out.extend(lines.skip(1).take_while(|l| !l.trim().is_empty()));
        out
    }

    /// Every named column of `table` starts at the same byte in each data
    /// row as in the header, and is preceded by a space.
    fn assert_columns_aligned(table: &[&str], columns: &[&str]) -> Result<(), TestError> {
        let header = table.first().ok_or("the table has no header")?;
        assert!(table.len() > 1, "the table has no rows: {table:?}");
        for column in columns {
            let at = header
                .find(column)
                .ok_or_else(|| format!("no {column} column in {header:?}"))?;
            for row in &table[1..] {
                let before = row.get(..at).ok_or("a row shorter than the header")?;
                assert!(
                    before.ends_with(' ') && !row[at..].starts_with(' '),
                    "{column} starts at byte {at} in the header and elsewhere \
                     in this row:\n{header}\n{row}"
                );
            }
        }
        Ok(())
    }

    /// A codec name longer than the Codec column's eight characters widens
    /// the column for every row instead of pushing its own row out of line.
    #[test]
    fn a_telephone_event_row_keeps_the_rtp_table_aligned() -> Result<(), TestError> {
        let mut audio = make_rtp_stream()?;
        audio.associated_dialog = Some("report-test@example.com".to_string());
        let mut dtmf = make_rtp_stream()?;
        dtmf.key.ssrc = 0x0d7f0d7f;
        dtmf.payload_type = 101;
        dtmf.codec = Some("telephone-event".to_string());
        dtmf.associated_dialog = audio.associated_dialog.clone();
        let report = print_dialog_report(&[], &[&audio, &dtmf]);
        let table = table_under(&report, "RTP Streams:");
        assert!(
            table.iter().any(|r| r.contains("telephone-event")),
            "the long name is printed whole: {report}"
        );
        assert_columns_aligned(
            &table,
            &[
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
                "Kbps",
            ],
        )
    }

    /// The same holds for an IPv6 socket, which overflows a column sized for
    /// IPv4, in both stream tables.
    #[test]
    fn an_ipv6_socket_keeps_both_stream_tables_aligned() -> Result<(), TestError> {
        let mut linked = make_rtp_stream()?;
        linked.key.src = "[2001:db8:1234:5678::100]:20000".parse()?;
        linked.associated_dialog = Some("report-test@example.com".to_string());
        let short = {
            let mut s = make_rtp_stream()?;
            s.key.ssrc = 0x00000001;
            s.associated_dialog = linked.associated_dialog.clone();
            s
        };
        let mut orphan = make_orphaned_stream()?;
        orphan.key.dst = "[2001:db8:1234:5678::200]:30000".parse()?;
        let other_orphan = {
            let mut s = make_orphaned_stream()?;
            s.key.ssrc = 0x00000002;
            s
        };
        let report = print_dialog_report(&[], &[&linked, &short, &orphan, &other_orphan]);
        assert_columns_aligned(
            &table_under(&report, "RTP Streams:"),
            &["Source", "Destination", "Pkts", "Kbps"],
        )?;
        assert_columns_aligned(
            &table_under(&report, "Orphaned Streams:"),
            &["Source", "Destination", "Pkts", "Duration"],
        )
    }

    /// Columns grow to their widest cell and never shrink below the minimum,
    /// and the rule grows by what the columns grew.
    #[test]
    fn fitted_widths_grow_to_the_widest_cell_only() {
        let rows = vec![
            vec!["a".to_string(), "telephone-event".to_string()],
            vec!["b".to_string(), "PCMU".to_string()],
        ];
        let widths = fitted_widths(&[4, 8], &["SSRC", "Codec"], &rows);
        assert_eq!(widths, [4, 15]);
        assert_eq!(rule_for(10, &[4, 8], &widths).len(), 17);
        let short = vec![vec!["a".to_string(), "PCMU".to_string()]];
        let widths = fitted_widths(&[4, 8], &["SSRC", "Codec"], &short);
        assert_eq!(widths, [4, 8], "short values keep the old widths");
        assert_eq!(rule_for(10, &[4, 8], &widths).len(), 10);
    }

    // ── Orphaned-stream section ────────────────────────────────────────

    /// Build the stream of [`make_rtp_stream`] as an orphan: no dialog claims
    /// it, which is the whole of what an orphan is. A distinct SSRC so a mixed
    /// report can name which row landed in which table.
    fn make_orphaned_stream() -> Result<crate::rtp::stream::RtpStream, TestError> {
        let mut s = make_rtp_stream()?;
        s.key.ssrc = 0x0bad0bad;
        s.associated_dialog = None;
        Ok(s)
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
    fn orphaned_stream_renders_under_the_orphan_heading() -> Result<(), TestError> {
        let s = make_orphaned_stream()?;

        let report = print_dialog_report(&[], &[&s]);

        let (before, orphans) = report.split_once("Orphaned Streams:").ok_or_else(|| {
            format!("an orphaned stream produced no Orphaned Streams section:\n{report}")
        })?;
        assert!(
            orphans.contains("0x0bad0bad"),
            "the orphaned stream's SSRC must appear under the heading:\n{report}"
        );
        assert!(
            !before.contains("RTP Streams:"),
            "an orphan has no dialog, so it must not open the associated table:\n{report}"
        );
        Ok(())
    }

    /// A stream linked to a dialog raises no orphan heading.
    ///
    /// The section is absent rather than empty, so "no Orphaned Streams" in a
    /// report reads as "this capture had no orphans" and must stay true.
    #[test]
    fn linked_stream_raises_no_orphan_heading() -> Result<(), TestError> {
        let mut s = make_rtp_stream()?;
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
        Ok(())
    }

    /// The shape every real capture produces: the two tables partition the
    /// streams, each SSRC under exactly one heading.
    #[test]
    fn mixed_report_partitions_streams_between_the_two_tables() -> Result<(), TestError> {
        let mut linked = make_rtp_stream()?;
        linked.associated_dialog = Some("report-test@example.com".to_string());
        let orphan = make_orphaned_stream()?;

        let report = print_dialog_report(&[], &[&linked, &orphan]);

        let (associated, orphans) = report
            .split_once("Orphaned Streams:")
            .ok_or_else(|| format!("a report holding one orphan needs both tables:\n{report}"))?;
        assert!(
            associated.contains("0x0a0b0c0d") && !associated.contains("0x0bad0bad"),
            "the associated table must hold the linked stream and only it:\n{report}"
        );
        assert!(
            orphans.contains("0x0bad0bad") && !orphans.contains("0x0a0b0c0d"),
            "the orphan table must hold the orphan and only it:\n{report}"
        );
        Ok(())
    }

    /// A long Call-ID is truncated within the limit and ends with "...".
    #[test]
    fn truncate_long_call_id() -> Result<(), TestError> {
        let result = truncate_str(
            "this-is-a-very-long-call-id-string-that-needs-truncation",
            22,
        );
        assert!(result.len() <= 22);
        assert!(result.ends_with("..."));
        Ok(())
    }

    /// `format_seconds` renders seconds, minutes, and hours variants.
    #[test]
    fn format_seconds_variants() -> Result<(), TestError> {
        assert_eq!(format_seconds(0), "0s");
        assert_eq!(format_seconds(45), "45s");
        assert_eq!(format_seconds(153), "2m 33s");
        assert_eq!(format_seconds(3661), "1h 1m 1s");
        Ok(())
    }

    // ── UTF-8 safe truncate_str ────────────────────────────────────────

    /// A string within the limit is returned unchanged.
    #[test]
    fn truncate_str_short_string_unchanged() -> Result<(), TestError> {
        assert_eq!(truncate_str("hello", 10), "hello");
        Ok(())
    }

    /// Truncation to 8 keeps 5 chars plus the "..." suffix.
    #[test]
    fn truncate_str_exact_ellipsis() -> Result<(), TestError> {
        assert_eq!(truncate_str("hello world", 8), "hello...");
        Ok(())
    }

    /// 2-byte UTF-8 input truncates on a char boundary without panicking.
    #[test]
    fn truncate_str_multibyte_latin_no_panic() -> Result<(), TestError> {
        // "héllo wörld" contains 2-byte UTF-8 chars
        let result = truncate_str("héllo wörld", 8);
        assert!(result.ends_with("..."));
        Ok(())
    }

    /// 3-byte CJK input truncates without panicking or emptying the result.
    #[test]
    fn truncate_str_cjk_no_panic() -> Result<(), TestError> {
        // "日本語テスト" — each char is 3 bytes in UTF-8
        let result = truncate_str("日本語テスト", 6);
        assert!(!result.is_empty());
        Ok(())
    }

    /// Tiny `max_len` values (0..=3, too small for the 3-byte "..." ellipsis)
    /// must never produce a result exceeding `max_len` bytes, even for
    /// multi-byte input where a single char is wider than the budget.
    #[test]
    fn truncate_str_tiny_max_len_respects_byte_contract() -> Result<(), TestError> {
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
        Ok(())
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
    fn every_media_row_names_its_attribution_tier() -> Result<(), TestError> {
        let mut out = String::new();
        write_icmp_media_section(&mut out, &resolved_one_per_tier());

        let (_, table) = out
            .split_once("Description")
            .ok_or_else(|| format!("the section rendered no table:\n{out}"))?;
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
        Ok(())
    }

    /// The summary keeps `unkeyed` as its own outcome.
    ///
    /// A quote that stopped before the ports has no flow to match — a third
    /// state, not "matched nothing". Folding it away would make the two
    /// invariants #98 asserts uncheckable from the report.
    #[test]
    fn the_media_summary_reports_unkeyed_separately() -> Result<(), TestError> {
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
        Ok(())
    }

    /// A finding no dialog can claim is still printed.
    ///
    /// On one real corpus 205 of 514 errors matched nothing the capture held.
    /// A section assembled from dialogs would show none of them, which is the
    /// invisibility this section exists to end.
    #[test]
    fn a_finding_that_named_no_call_is_still_printed() -> Result<(), TestError> {
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
            .ok_or_else(|| format!("a finding with no call produced no table:\n{out}"))?;
        assert!(
            table.lines().any(|l| l.starts_with("none ")),
            "the unattributed finding must be printed:\n{out}"
        );
        Ok(())
    }

    /// A capture with no media ICMP raises no section.
    ///
    /// Absent rather than empty, so "no ICMP section" reads as "this capture
    /// had none" and stays true.
    #[test]
    fn a_capture_with_no_media_icmp_raises_no_section() -> Result<(), TestError> {
        let mut out = String::new();
        write_icmp_media_section(&mut out, &crate::pipeline::ResolvedIcmpMedia::default());
        assert!(
            out.is_empty(),
            "silence when there is nothing to say: {out}"
        );
        Ok(())
    }

    /// The whole report carries the section, not just the writer.
    ///
    /// The writer can be right while nothing calls it, which was the state
    /// this task started from.
    #[test]
    #[serial_test::serial(icmp_evidence)]
    fn the_report_carries_the_media_section() -> Result<(), TestError> {
        let dialog = make_completed_dialog()?;

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
        Ok(())
    }

    /// Evidence the PARSER filed reaches the report, not just a published set.
    ///
    /// Every other test of this section hands the surface a set built by
    /// `publish_icmp_media_for_test`, which proves the renderer and nothing
    /// about the path a real capture takes: an ICMP error is filed by
    /// `record_icmp_error` while the parser walks the packet, resolved against
    /// the stream store by `select_dialogs`, and only then read here. Nothing
    /// joined those three, so an evidence store that stopped being written --
    /// or a resolve that stopped publishing -- would have left every test in
    /// this file green.
    ///
    /// It is also the mechanism behind a flake: one filed quote is enough to
    /// raise the section, so any test that files one poisons any concurrent
    /// test asserting the section is absent. That is why the parser-side
    /// writer is serialized on `icmp_evidence` with the tests that read it.
    #[test]
    #[serial_test::serial(icmp_evidence)]
    fn media_icmp_the_parser_filed_reaches_the_whole_report() -> Result<(), TestError> {
        let dialog = make_completed_dialog()?;
        crate::pipeline::reset_icmp_evidence();

        crate::pipeline::test_support::file_one_media_icmp_error()?;
        crate::pipeline::resolve_icmp_media(&crate::rtp::stream_store::StreamStore::new(4));

        let report = print_dialog_report(&[&dialog], &[]);
        crate::pipeline::reset_icmp_evidence();

        assert!(
            report.contains("ICMP (media, capture-wide):"),
            "a quote the parser filed never reached the report:\n{report}"
        );
        assert!(
            report.contains("1 error(s) quoting non-SIP traffic, 1 of them media"),
            "the report must count the filed quote as media, not merely as \
             an error:\n{report}"
        );
        assert!(
            report.contains("198.51.100.20:20000"),
            "the report must name the endpoint that did not answer:\n{report}"
        );
        Ok(())
    }

    /// A run that saw a recording or forking command has to SAY so. The
    /// counter existed for exactly this and no surface read it, which made
    /// the promise in its own doc comment -- "a run can say what it did not
    /// attribute" -- false for as long as it went unrendered.
    #[test]
    fn a_media_creating_command_reaches_the_report() -> Result<(), TestError> {
        let note = super::media_creating_note(3).ok_or("three commands is something to say")?;

        assert!(
            note.contains('3'),
            "the operator needs the COUNT, not just that it happened:\n{note}"
        );
        assert!(
            note.contains("not being one of its two legs") || note.contains("two legs"),
            "and why it is not attributed, or the line reads as a defect:\n{note}"
        );
        Ok(())
    }

    /// The note must actually REACH the report. The two tests around this one
    /// exercise the formatting helper, and would both stay green if the call
    /// site rendering it were deleted -- which is precisely the state this
    /// whole change fixed: a counter that existed and no surface read.
    ///
    /// Asserts presence rather than a count. The tally is process-global and
    /// every test in this binary shares it, so an exact number is true only
    /// until the next test runs. Presence after an increment is stable either
    /// way, and it is what fails if the render site goes away.
    #[test]
    fn the_note_reaches_the_rendered_report() -> Result<(), TestError> {
        crate::relay::note_media_creating_command();

        let report = print_dialog_report(&[], &[]);

        assert!(
            report.contains("Media-creating relay commands seen:"),
            "a command sipnab saw and did not attribute must appear in the \
             report an operator actually reads:\n{report}"
        );
        Ok(())
    }

    /// Nothing seen, nothing said. A line whose only content is a zero is
    /// noise in a report an operator reads under time pressure.
    #[test]
    fn a_run_that_saw_none_says_nothing_about_them() -> Result<(), TestError> {
        assert_eq!(super::media_creating_note(0), None, "zero is not a finding");
        Ok(())
    }
}
