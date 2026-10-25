// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Two capture files diffed by dimension: for each, the values ranked by how
//! far they moved from the baseline to the other file.
//!
//! One answer, [`CaptureComparisonView`], built by [`compare_files`] and
//! [`view`]: `GET /v1/captures/compare` serializes it and
//! `--compare-captures` prints it. The comparison is
//! [`crate::capture::compare::compare`], which the MCP `compare_captures`
//! tool also runs, reading each file into scratch stores bounded the same
//! way on every surface.

use crate::capture::compare::{CaptureComparison, CaptureRef, CompareError};
use crate::output::ReportFormat;

/// What reading one capture produced, for `GET /v1/captures/compare`.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct CaptureSideView {
    /// The name the caller gave.
    pub filename: String,
    /// Packets read from the file.
    pub packets: u64,
    /// Dialogs the read produced.
    pub dialogs: usize,
    /// RTP streams the read produced.
    pub streams: usize,
    /// Dialogs the scratch store's capacity refused; non-zero means this
    /// side is truncated and every count is a floor.
    pub dialogs_dropped: u64,
    /// Why the read stopped early, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_error: Option<String>,
}

/// One value's movement between the two captures. `value` is raw.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct BucketDeltaView {
    /// The grouped value, raw. Absent from a side means zero there.
    pub value: String,
    /// Dialogs in this bucket in capture `a`.
    pub a: usize,
    /// Dialogs in this bucket in capture `b`.
    pub b: usize,
    /// `b - a`. Negative means the value became rarer.
    pub delta: i64,
}

/// One dimension's diff.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct DimensionDiffView {
    /// The field grouped on.
    pub dimension: String,
    /// Buckets, largest absolute movement first.
    pub buckets: Vec<BucketDeltaView>,
    /// Everything past `top_n`, summed.
    pub other: BucketDeltaView,
    /// Distinct values seen across both captures.
    pub distinct_values: usize,
}

/// Two capture files diffed by aggregate. Bucket values are raw.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct CaptureComparisonView {
    /// Version of this response's shape.
    #[cfg_attr(feature = "api", schema(example = 1))]
    pub schema_version: u32,
    /// The baseline.
    pub a: CaptureSideView,
    /// The capture held against it.
    pub b: CaptureSideView,
    /// One entry per requested dimension, in the order requested.
    pub dimensions: Vec<DimensionDiffView>,
    /// What the two sides are and what the numbers do not cover.
    pub summary: String,
}

/// Who reports a comparison, which decides its summary: a server says the
/// two files are not the capture it holds; the command line holds none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reporter {
    /// `GET /v1/captures/compare`.
    Server,
    /// `--compare-captures`.
    CommandLine,
}

/// Compare `a` (the baseline) with `b`, reading each into scratch stores
/// bounded by the default dialog and stream caps, the bounds every surface
/// reads them with.
///
/// # Errors
///
/// As [`crate::capture::compare::compare`]: the same file twice, a
/// dimension outside the vocabulary, or a file that yields nothing.
pub fn compare_files(
    a: CaptureRef<'_>,
    b: CaptureRef<'_>,
    dimensions: &[String],
    options: &crate::pipeline::PipelineOptions,
    top_n: usize,
) -> Result<CaptureComparison, CompareError> {
    crate::capture::compare::compare(
        a,
        b,
        dimensions,
        options,
        crate::cli::Cli::DEFAULT_DIALOG_LIMIT as usize,
        crate::cli::Cli::DEFAULT_MAX_STREAMS as usize,
        top_n,
    )
}

/// `comparison` as the answer `reporter` gives.
#[must_use]
pub fn view(comparison: CaptureComparison, reporter: Reporter) -> CaptureComparisonView {
    let side = |s: crate::capture::compare::CaptureSide| CaptureSideView {
        filename: s.filename,
        packets: s.packets,
        dialogs: s.dialogs,
        streams: s.streams,
        dialogs_dropped: s.dialogs_dropped,
        read_error: s.read_error,
    };
    let bucket = |bd: crate::capture::compare::BucketDelta| BucketDeltaView {
        value: bd.value,
        a: bd.a,
        b: bd.b,
        delta: bd.delta,
    };
    let dimensions = comparison
        .dimensions
        .into_iter()
        .map(|dd| DimensionDiffView {
            dimension: dd.dimension,
            buckets: dd.buckets.into_iter().map(&bucket).collect(),
            other: bucket(dd.other),
            distinct_values: dd.distinct_values,
        })
        .collect();
    CaptureComparisonView {
        schema_version: 1,
        a: side(comparison.a),
        b: side(comparison.b),
        dimensions,
        summary: match reporter {
            Reporter::Server => comparison.summary,
            Reporter::CommandLine => comparison.summary_off_server,
        },
    }
}

/// A change in a count: signed, and `0` without a sign.
fn change(delta: i64) -> String {
    if delta == 0 {
        "0".to_string()
    } else {
        format!("{delta:+}")
    }
}

/// The comparison as text: a line per side, then a table per dimension with
/// each value's count in A and B and the change, largest movement first, the
/// values past the cut summed in an `(other)` row when there are any, and the
/// summary last.
#[must_use]
pub fn render(answer: &CaptureComparisonView, format: ReportFormat) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    for (label, side) in [("A", &answer.a), ("B", &answer.b)] {
        let _ = write!(
            out,
            "{label}: {}, {}, {}, {}",
            super::clean(&side.filename),
            super::plural(side.packets, "packet"),
            super::plural(side.dialogs as u64, "dialog"),
            super::plural(side.streams as u64, "stream"),
        );
        if side.dialogs_dropped > 0 {
            let _ = write!(out, ", {} not counted", side.dialogs_dropped);
        }
        out.push('\n');
    }
    for dim in &answer.dimensions {
        let _ = writeln!(out, "\nBy {}:", dim.dimension);
        let mut rows: Vec<Vec<String>> = dim
            .buckets
            .iter()
            .map(|b| {
                vec![
                    b.value.clone(),
                    b.a.to_string(),
                    b.b.to_string(),
                    change(b.delta),
                ]
            })
            .collect();
        if dim.other.a > 0 || dim.other.b > 0 {
            rows.push(vec![
                dim.other.value.clone(),
                dim.other.a.to_string(),
                dim.other.b.to_string(),
                change(dim.other.delta),
            ]);
        }
        out.push_str(&super::table(format, &["Value", "A", "B", "Change"], &rows));
    }
    let _ = writeln!(out, "\n{}", super::clean(&answer.summary));
    out
}
