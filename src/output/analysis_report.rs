// SPDX-License-Identifier: MIT OR Apache-2.0

//! Renders a [`CaptureAnalysis`] as the `--analyze` report.
//!
//! The model, the ranking and the severity ladder live in
//! [`crate::analysis`]; this file only decides what an operator reads. The
//! split is the one [`crate::stun`] and [`crate::output::stun_report`] already
//! use, and it exists so that "which problem is worse" is answered in one
//! place and never inside a formatter.
//!
//! Two rules the layout is built around:
//!
//! * **Worst first, and say why.** Every finding leads with its severity and
//!   its count, then one sentence of what it means, then the evidence rows
//!   that let a reader go back to the capture and check it.
//! * **A clean run is one line.** Not an empty table with headings — those
//!   read as "the tool ran and found a place to put results", which is exactly
//!   the impression a capture sipnab could not read must never give.

use std::fmt::Write;

use crate::analysis::{CaptureAnalysis, Evidence, Finding, Severity};

/// Render an analysis in the requested format.
///
/// # Returns
///
/// The formatted report. Never empty: a capture with no findings still gets
/// the clean line, because silence would be indistinguishable from the flag
/// not having run.
#[must_use]
pub fn print_analysis_report_as(
    analysis: &CaptureAnalysis,
    format: crate::output::ReportFormat,
) -> String {
    let md = matches!(format, crate::output::ReportFormat::Markdown);
    let mut out = String::with_capacity(2048);

    if analysis.is_clean() {
        out.push_str(&clean_line(analysis));
        out.push('\n');
        return out;
    }

    let _ = writeln!(
        out,
        "{}Capture analysis: {} finding(s) across {} dialog(s), {} stream(s), {} frame(s) read.",
        if md { "## " } else { "" },
        analysis.findings.len(),
        analysis.dialogs_examined,
        analysis.streams_examined,
        analysis.frames_read
    );

    // The incompleteness banner goes ABOVE the findings, not below them. A
    // reader who stops after the first screen must still have been told that
    // the list is a floor: putting the qualification at the bottom is the same
    // defect as not printing it, for everyone who scrolls no further than the
    // worst finding.
    if !analysis.complete {
        let _ = writeln!(
            out,
            "\n{}THIS ANALYSIS IS INCOMPLETE — sipnab did not read all of this capture. The \
             findings below describe what it UNDERSTOOD, so their counts are floors and the \
             ABSENCE of a finding is not evidence that the problem is absent. The {} finding(s) \
             are listed first.",
            if md { "> " } else { "" },
            Severity::Blind.as_str()
        );
    }

    for (i, finding) in analysis.findings.iter().enumerate() {
        out.push('\n');
        out.push_str(&render_finding(i + 1, finding, md));
    }

    out
}

/// As [`print_analysis_report_as`], in plain text.
#[must_use]
pub fn print_analysis_report(analysis: &CaptureAnalysis) -> String {
    print_analysis_report_as(analysis, crate::output::ReportFormat::Text)
}

/// The one line a clean capture gets.
///
/// It names its own denominators on purpose. "No problems found." is a claim
/// about the traffic; "No problems found in 214 dialog(s) ... across 41,203
/// frame(s), all of which decoded" is a claim about the traffic AND about how
/// much of it was looked at, and only the second is a sentence sipnab is
/// entitled to print. This is the same rule `no_sip_guidance` enforces for
/// "No SIP traffic found."
fn clean_line(analysis: &CaptureAnalysis) -> String {
    format!(
        "No problems found in {} dialog(s) and {} stream(s) across {} frame(s). Every frame \
         decoded, no port gate discarded SIP, and no retention cap was reached — so this is a \
         statement about the capture, not only about what sipnab could read of it.",
        analysis.dialogs_examined, analysis.streams_examined, analysis.frames_read
    )
}

/// One finding: heading, meaning, evidence.
fn render_finding(rank: usize, finding: &Finding, md: bool) -> String {
    let meta = finding.kind.meta();
    let mut out = String::with_capacity(512);
    let _ = writeln!(
        out,
        "{}{rank}. [{}] {} — {} {}(s)",
        if md { "### " } else { "" },
        meta.severity.as_str().to_uppercase(),
        meta.title,
        finding.occurrences,
        meta.unit
    );
    let _ = writeln!(out, "{}{}", if md { "" } else { "   " }, meta.detail);

    if finding.evidence.is_empty() {
        return out;
    }
    let _ = writeln!(out, "{}Evidence:", if md { "\n" } else { "   " });
    for ev in &finding.evidence {
        let _ = writeln!(
            out,
            "{}{}",
            if md { "- " } else { "     - " },
            evidence_line(ev)
        );
    }
    // A capped list that looks complete understates the problem — the rule
    // `--stun` and the ICMP summaries follow, restated here because this is
    // the surface an operator will read first. Reads the counted omission
    // rather than `occurrences - evidence.len()`: one row often stands for
    // many occurrences, and the subtraction invents an omission that did not
    // happen.
    if finding.evidence_omitted > 0 {
        let _ = writeln!(
            out,
            "{}... and {} further evidence row(s) not listed ({} shown).",
            if md { "- " } else { "     " },
            finding.evidence_omitted,
            finding.evidence.len()
        );
    }
    out
}

/// One evidence row, as a single line an operator can grep the pcap with.
fn evidence_line(ev: &Evidence) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(ref call_id) = ev.call_id {
        parts.push(format!("Call-ID {call_id}"));
    }
    if !ev.endpoints.is_empty() {
        parts.push(ev.endpoints.join(", "));
    }
    if let Some(at) = ev.at {
        parts.push(at.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string());
    }
    if !ev.counts.is_empty() {
        parts.push(
            ev.counts
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    if let Some(ref note) = ev.note {
        parts.push(note.clone());
    }
    // An evidence row with nothing in it would be a blank bullet, which reads
    // as a rendering bug rather than as the absence it is.
    if parts.is_empty() {
        return "(no detail retained)".to_string();
    }
    parts.join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::FindingKind;
    use std::collections::BTreeMap;

    /// A finding whose evidence list is complete.
    fn finding(kind: FindingKind, occurrences: u64, evidence: Vec<Evidence>) -> Finding {
        Finding {
            kind,
            severity: kind.meta().severity,
            occurrences,
            unit: kind.meta().unit,
            evidence,
            evidence_omitted: 0,
        }
    }

    /// A clean capture must produce exactly one line, and that line must carry
    /// the denominators. An empty scaffold — headings with nothing under them
    /// — reads as "analyzed and fine" for a capture that was never read.
    #[test]
    fn a_clean_capture_gets_one_honest_line() {
        let analysis = CaptureAnalysis {
            frames_read: 41_203,
            dialogs_examined: 214,
            streams_examined: 402,
            complete: true,
            findings: Vec::new(),
        };
        let out = print_analysis_report(&analysis);
        assert_eq!(out.lines().count(), 1, "one line, not a scaffold: {out}");
        assert!(out.contains("41203 frame(s)"), "{out}");
        assert!(out.contains("214 dialog(s)"), "{out}");
        assert!(out.contains("No problems found"), "{out}");
    }

    /// The clean line must never be printed for an incomplete read. This is
    /// structural — an incomplete read always carries a Blind finding, so the
    /// list is never empty — and the test states it so the structure cannot be
    /// quietly removed.
    #[test]
    fn an_incomplete_read_never_prints_the_clean_line() {
        let analysis = CaptureAnalysis {
            frames_read: 49,
            dialogs_examined: 0,
            streams_examined: 0,
            complete: false,
            findings: vec![finding(
                FindingKind::UndecodableFrames,
                49,
                vec![Evidence {
                    counts: BTreeMap::from([("frames", 49), ("frames_read", 49)]),
                    note: Some("unsupported link type 0 (49)".to_string()),
                    ..Evidence::default()
                }],
            )],
        };
        let out = print_analysis_report(&analysis);
        assert!(!out.contains("No problems found"), "{out}");
        assert!(out.contains("THIS ANALYSIS IS INCOMPLETE"), "{out}");
        assert!(out.contains("unsupported link type 0 (49)"), "{out}");
        assert!(
            out.contains("[BLIND]"),
            "the severity must be on the heading: {out}"
        );
    }

    /// Every finding must carry evidence a reader can take back to the pcap.
    #[test]
    fn a_finding_renders_its_call_id_addresses_and_counts() {
        let at =
            chrono::DateTime::from_timestamp_millis(1_700_000_000_000).expect("valid timestamp");
        let analysis = CaptureAnalysis {
            frames_read: 900,
            dialogs_examined: 1,
            streams_examined: 1,
            complete: true,
            findings: vec![finding(
                FindingKind::OneWayAudio,
                1,
                vec![Evidence {
                    call_id: Some("abc123@192.0.2.1".to_string()),
                    endpoints: vec!["SDP 192.168.10.50:16400".to_string()],
                    at: Some(at),
                    counts: BTreeMap::from([("rtp_packets", 412), ("streams", 1)]),
                    note: Some("nothing came back the other way".to_string()),
                }],
            )],
        };
        let out = print_analysis_report(&analysis);
        assert!(out.contains("Call-ID abc123@192.0.2.1"), "{out}");
        assert!(out.contains("SDP 192.168.10.50:16400"), "{out}");
        assert!(out.contains("rtp_packets=412"), "{out}");
        assert!(out.contains("2023-11-14"), "{out}");
        assert!(out.contains("[CRITICAL]"), "{out}");
    }

    /// A capped evidence list must say it was capped — and a COMPLETE list
    /// must not. The second half is the defect this pairs against: deriving
    /// the omission as `occurrences - evidence.len()` printed "22 more not
    /// listed" for a one-row list that stood for 23 discarded messages, which
    /// is a fabricated omission dressed as evidence of one.
    #[test]
    fn a_capped_evidence_list_states_what_it_left_out() {
        let one_row = vec![Evidence {
            call_id: Some("one@192.0.2.1".to_string()),
            ..Evidence::default()
        }];
        let complete = CaptureAnalysis {
            frames_read: 9_000,
            dialogs_examined: 40,
            streams_examined: 80,
            complete: true,
            findings: vec![finding(FindingKind::NoMedia, 40, one_row.clone())],
        };
        let out = print_analysis_report(&complete);
        assert!(
            !out.contains("not listed"),
            "one row standing for 40 occurrences omitted nothing: {out}"
        );

        let mut capped = complete;
        capped.findings[0].evidence_omitted = 39;
        let out = print_analysis_report(&capped);
        assert!(
            out.contains("39 further evidence row(s) not listed"),
            "{out}"
        );
    }

    /// Markdown carries headings and bullets; text carries neither.
    #[test]
    fn markdown_format_uses_headings() {
        let analysis = CaptureAnalysis {
            frames_read: 10,
            dialogs_examined: 1,
            streams_examined: 0,
            complete: true,
            findings: vec![finding(FindingKind::Abandoned, 1, Vec::new())],
        };
        let md = print_analysis_report_as(&analysis, crate::output::ReportFormat::Markdown);
        assert!(md.contains("## Capture analysis"), "{md}");
        assert!(md.contains("### 1. [MINOR]"), "{md}");
        let text = print_analysis_report(&analysis);
        assert!(!text.contains("##"), "{text}");
    }

    /// The operator-facing prose must not carry the runs of spaces a broken
    /// `\` line-continuation leaves behind.
    #[test]
    fn rendered_prose_has_no_doubled_spaces() {
        let analysis = CaptureAnalysis {
            frames_read: 10,
            dialogs_examined: 0,
            streams_examined: 0,
            complete: false,
            findings: vec![
                finding(FindingKind::UndecodableFrames, 10, Vec::new()),
                finding(FindingKind::OneWayAudio, 1, Vec::new()),
            ],
        };
        for out in [
            print_analysis_report(&analysis),
            print_analysis_report_as(&analysis, crate::output::ReportFormat::Markdown),
            print_analysis_report(&CaptureAnalysis::default()),
        ] {
            for line in out.lines() {
                assert!(
                    !line.trim_start().contains("  "),
                    "doubled space in operator-facing output: {line:?}"
                );
            }
        }
    }
}
