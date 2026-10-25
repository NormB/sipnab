// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A capture judged against a suite of expectations.
//!
//! The judgement is [`crate::expect::evaluate`], which the MCP
//! `evaluate_expectations` tool also runs; its [`Report`] is the answer, and
//! [`Report::exit_code`] the exit status `--expect` carries. This module
//! reads a suite file the way the command line names it, and renders the
//! report as text.

use std::path::{Path, PathBuf};

use crate::expect::{Inputs, Report, Suite, SuiteVerdict, Verdict, evaluate};
use crate::output::ReportFormat;

/// A suite file and the rules it holds, read and checked when the command
/// line is parsed.
#[derive(Debug, Clone)]
pub struct SuiteFile {
    /// The file, as named.
    pub path: PathBuf,
    /// Its rules.
    pub suite: Suite,
}

/// Read the suite `path` names and check every rule compiles, by evaluating
/// it against an empty capture: the one check [`evaluate`] makes before it
/// measures anything, so a suite that passes here is never refused later
/// for a defect in its own rules.
///
/// # Errors
///
/// A message naming the file when it cannot be read, does not parse as a
/// suite, or holds a rule the evaluator refuses.
pub fn read_suite(path: &Path) -> Result<SuiteFile, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let suite = Suite::from_toml_str(&text).map_err(|e| {
        format!(
            "{} does not parse as an expectation suite: {e}",
            path.display()
        )
    })?;
    let dialogs = crate::sip::dialog_store::DialogStore::new(1, false);
    let streams = crate::rtp::stream_store::StreamStore::new(1);
    evaluate(
        &suite.rules,
        &Inputs {
            dialogs: &dialogs,
            streams: &streams,
            thresholds: &crate::sip::dsl::AliasThresholds::default(),
            suppressions: None,
        },
    )
    .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(SuiteFile {
        path: path.to_path_buf(),
        suite,
    })
}

/// The answer `--expect` prints: the report and the identity of the capture
/// it judged, the shape the MCP tool answers with.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExpectAnswer {
    /// The evaluator's report.
    #[serde(flatten)]
    pub report: Report,
    /// Which capture and store revision the suite judged.
    pub capture_identity: Option<crate::provenance::CaptureEtag>,
}

/// The verdict word the text uses.
fn verdict(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "pass",
        Verdict::Fail => "fail",
        Verdict::Skipped => "skipped",
    }
}

/// A number as the text prints it: whole when it is whole, otherwise to
/// two decimals.
fn number(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{n:.0}")
    } else {
        format!("{n:.2}")
    }
}

/// The report as text: a line with the suite's verdict and counts, one row
/// per rule, then the reason for every rule that failed or skipped.
#[must_use]
pub fn render(report: &Report, format: ReportFormat) -> String {
    use std::fmt::Write as _;

    let head = match report.verdict {
        SuiteVerdict::Pass => "pass",
        SuiteVerdict::Fail => "fail",
        SuiteVerdict::NotEvaluated => "not evaluated",
    };
    let mut out = format!(
        "Expectations: {head}, {} of {} passed",
        report.passed,
        super::plural(report.evaluated as u64, "rule"),
    );
    if report.failed > 0 {
        let _ = write!(out, ", {} failed", report.failed);
    }
    if report.skipped > 0 {
        let _ = write!(out, ", {} skipped", report.skipped);
    }
    out.push('\n');
    let label = |r: &crate::expect::RuleOutcome| {
        r.name
            .clone()
            .unwrap_or_else(|| format!("#{}", r.index + 1))
    };
    let rows: Vec<Vec<String>> = report
        .results
        .iter()
        .map(|r| {
            vec![
                label(r),
                r.metric.clone(),
                r.op.to_string(),
                number(r.threshold),
                r.observed.map_or_else(|| "-".to_string(), number),
                r.sample.to_string(),
                verdict(r.verdict).to_string(),
            ]
        })
        .collect();
    out.push_str(&super::table(
        format,
        &[
            "Rule",
            "Metric",
            "Op",
            "Threshold",
            "Observed",
            "Sample",
            "Verdict",
        ],
        &rows,
    ));
    for r in report.results.iter().filter(|r| r.verdict != Verdict::Pass) {
        let _ = writeln!(
            out,
            "{}: {}",
            super::clean(&label(r)),
            super::clean(&r.reason)
        );
    }
    out
}
