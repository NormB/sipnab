// SPDX-License-Identifier: MIT OR Apache-2.0

//! Diff two capture FILES by aggregate — the shared core of the MCP
//! `compare_captures` tool and the REST `GET /v1/captures/compare` route.
//!
//! Each file is read into private stores through [`crate::capture::replay`] —
//! the same applier the live path uses — reduced to per-dimension tallies with
//! [`crate::sip::dialog::dialog_group_value_raw`], and joined into deltas ranked
//! by how far each bucket MOVED, so "today is worse than yesterday, and here is
//! where" is the first row.
//!
//! It returns RAW bucket values: a `ua` or `from.user` bucket is a banner a
//! stranger typed. A surface renders them — MCP fences those dimensions before
//! they reach a model, REST hands a monitoring system the value it keys on.
//! Neither read touches the caller's loaded capture; the private stores never
//! leave this module.

use crate::sip::dialog::dialog_group_value_raw;
use std::collections::BTreeMap;

/// Dimensions diffed when the caller names none: how many calls reached each
/// state, and which final response codes they ended on.
pub const DEFAULT_DIMENSIONS: &[&str] = &["state", "response_code"];

/// What reading one capture produced. Counts only; RAW.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CaptureSide {
    /// The name the caller gave.
    pub filename: String,
    /// Packets read from the file.
    pub packets: u64,
    /// Dialogs the read produced.
    pub dialogs: usize,
    /// RTP streams the read produced.
    pub streams: usize,
    /// Dialogs the scratch store's capacity refused. Non-zero means this side is
    /// TRUNCATED and every count below it is a floor.
    pub dialogs_dropped: u64,
    /// Why the read stopped early, when it did. A truncated pcap is the normal
    /// state of a rotating capture's newest member, so a partial read is
    /// reported rather than refused.
    pub read_error: Option<String>,
}

/// One value's movement between the two captures. `value` is RAW.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BucketDelta {
    /// The grouped value, rendered as a string, raw. Absent from a side means
    /// zero there, not missing.
    pub value: String,
    /// Dialogs in this bucket in capture `a`.
    pub a: usize,
    /// Dialogs in this bucket in capture `b`.
    pub b: usize,
    /// `b - a`. Negative means the value became rarer.
    pub delta: i64,
}

/// One dimension's diff.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DimensionDiff {
    /// The field grouped on.
    pub dimension: String,
    /// Buckets, largest absolute movement first.
    pub buckets: Vec<BucketDelta>,
    /// Everything past `top_n`, summed, so the rows and the remainder account
    /// for the whole population on both sides.
    pub other: BucketDelta,
    /// Distinct values seen across both captures.
    pub distinct_values: usize,
}

/// The whole comparison, raw.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CaptureComparison {
    /// The baseline.
    pub a: CaptureSide,
    /// The capture held against it.
    pub b: CaptureSide,
    /// One entry per requested dimension, in the order requested.
    pub dimensions: Vec<DimensionDiff>,
    /// What the two sides are and what the numbers do not cover.
    pub summary: String,
}

/// Why a comparison could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareError {
    /// A requested dimension is not in the grouping vocabulary.
    UnknownDimension {
        /// The offending key.
        key: String,
        /// The whole vocabulary, comma-joined.
        expected: String,
    },
    /// The two paths resolve to the same file — a capture differs from itself
    /// nowhere, and reading it twice learns nothing.
    SameFile {
        /// The name given for the baseline.
        a: String,
        /// The name given for the comparison.
        b: String,
    },
    /// A side yielded no dialogs and reported a read error, so every bucket
    /// would appear to have collapsed to zero — a finding that is not there.
    Unreadable {
        /// The file that produced nothing.
        filename: String,
        /// What the read reported.
        error: String,
    },
}

impl std::fmt::Display for CompareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownDimension { key, expected } => {
                write!(f, "cannot compare on '{key}'; one of: {expected}")
            }
            Self::SameFile { a, b } => write!(
                f,
                "'{a}' and '{b}' are the same file; a capture compared with \
                 itself differs from itself nowhere"
            ),
            Self::Unreadable { filename, error } => write!(
                f,
                "'{filename}' yielded no dialogs and reported: {error}. Refusing \
                 to diff against it — every bucket would appear to have collapsed \
                 to zero, which is a finding that is not there."
            ),
        }
    }
}

/// Validate and dedup the requested dimensions against the grouping vocabulary.
///
/// Vocabulary first, files second: reading two captures is the most expensive
/// thing this does, and a mistyped dimension must not cost it. Empty or `None`
/// takes [`DEFAULT_DIMENSIONS`].
///
/// # Errors
///
/// [`CompareError::UnknownDimension`] naming the vocabulary, when a key is
/// outside [`crate::sip::dialog::GROUPABLE`].
pub fn resolve_dimensions(requested: Option<&[String]>) -> Result<Vec<String>, CompareError> {
    match requested {
        None | Some([]) => Ok(DEFAULT_DIMENSIONS
            .iter()
            .map(|d| (*d).to_string())
            .collect()),
        Some(list) => {
            let mut seen: Vec<String> = Vec::new();
            for raw in list {
                let key = raw.trim();
                if !crate::sip::dialog::GROUPABLE.contains(&key) {
                    return Err(CompareError::UnknownDimension {
                        key: key.to_string(),
                        expected: crate::sip::dialog::GROUPABLE.join(", "),
                    });
                }
                // Deduped rather than refused: a repeated dimension is a caller
                // assembling a list, and diffing it twice would double the read.
                if !seen.iter().any(|s| s == key) {
                    seen.push(key.to_string());
                }
            }
            Ok(seen)
        }
    }
}

/// One capture read into private stores and reduced to counts.
struct Snapshot {
    /// The counts this side reports.
    side: CaptureSide,
    /// `dimension -> value -> dialogs`, values RAW.
    tallies: BTreeMap<String, BTreeMap<String, usize>>,
}

/// One side of a comparison: a resolved path and the name the caller gave it.
///
/// A pair rather than four loose arguments, so [`compare`] stays under the
/// argument ceiling and a call site cannot cross a path with the other side's
/// name.
pub struct CaptureRef<'a> {
    /// The resolved path to read.
    pub path: &'a std::path::Path,
    /// The name the caller gave, echoed in the result.
    pub name: &'a str,
}

/// Read `path` and reduce it to per-dimension tallies.
///
/// `max_dialogs`/`max_streams` are the caller's: the ceilings are policy, and a
/// helper that chose its own would be a second place to change them. Whatever a
/// cap refuses is counted through [`CaptureSide::dialogs_dropped`].
fn snapshot(
    path: &std::path::Path,
    filename: &str,
    dimensions: &[String],
    max_dialogs: usize,
    max_streams: usize,
) -> Snapshot {
    use crate::rtp::stream_store::StreamStore;
    use crate::sip::dialog_store::DialogStore;
    use std::sync::Arc;

    let ds = Arc::new(parking_lot::RwLock::new(DialogStore::new(
        max_dialogs,
        false,
    )));
    let ss = Arc::new(parking_lot::RwLock::new(StreamStore::new(max_streams)));
    let progress = std::sync::atomic::AtomicU64::new(0);
    let outcome = crate::capture::replay::read_into_stores(path, &ds, &ss, &progress);

    let dialogs_read = ds.read();
    let streams_read = ss.read();
    let mut tallies: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for dimension in dimensions {
        let bucket = tallies.entry(dimension.clone()).or_default();
        for d in dialogs_read.iter() {
            let streams: Vec<&crate::rtp::stream::RtpStream> =
                streams_read.streams_for(&d.call_id).collect();
            // `None` cannot happen: the caller validated every dimension against
            // GROUPABLE before the file was opened. Skipping rather than
            // panicking keeps a future key added to one list and not the other
            // from taking the process down. RAW value; the surface fences it.
            if let Some(value) = dialog_group_value_raw(dimension, d, &streams) {
                *bucket.entry(value).or_insert(0) += 1;
            }
        }
    }

    Snapshot {
        side: CaptureSide {
            filename: filename.to_string(),
            packets: outcome.packets,
            dialogs: dialogs_read.len(),
            streams: streams_read.len(),
            dialogs_dropped: dialogs_read.total_capacity_dialogs_dropped(),
            read_error: outcome.error,
        },
        tallies,
    }
}

/// Join one dimension's two tallies into ranked deltas.
///
/// Ranked by ABSOLUTE movement rather than by count, because the question is
/// "what changed", and the largest bucket is usually the one that changed
/// least. Ties break on the value so the same pair of files always produces the
/// same order.
fn diff_dimension(
    dimension: &str,
    a: &BTreeMap<String, usize>,
    b: &BTreeMap<String, usize>,
    top_n: usize,
) -> DimensionDiff {
    let mut values: Vec<&String> = a.keys().chain(b.keys()).collect();
    values.sort_unstable();
    values.dedup();
    let distinct_values = values.len();

    let mut rows: Vec<BucketDelta> = values
        .into_iter()
        .map(|value| {
            let (ca, cb) = (
                a.get(value).copied().unwrap_or(0),
                b.get(value).copied().unwrap_or(0),
            );
            BucketDelta {
                value: value.clone(),
                a: ca,
                b: cb,
                delta: cb as i64 - ca as i64,
            }
        })
        .collect();
    crate::sort::sort_by_dyn(&mut rows, &mut |x, y| {
        y.delta.abs().cmp(&x.delta.abs()).then_with(|| {
            y.a.saturating_add(y.b)
                .cmp(&x.a.saturating_add(x.b))
                .then_with(|| x.value.cmp(&y.value))
        })
    });

    let other = rows.iter().skip(top_n).fold(
        BucketDelta {
            value: "(other)".to_string(),
            a: 0,
            b: 0,
            delta: 0,
        },
        |mut acc, r| {
            acc.a += r.a;
            acc.b += r.b;
            acc.delta += r.delta;
            acc
        },
    );
    rows.truncate(top_n);

    DimensionDiff {
        dimension: dimension.to_string(),
        buckets: rows,
        other,
        distinct_values,
    }
}

/// Diff two already-resolved capture files. BLOCKING — reads both in sequence,
/// so a caller on an async runtime hands it to a blocking task.
///
/// `dimensions` must already have passed [`resolve_dimensions`]. One capture at
/// a time, not two in parallel: the tallies are small and the stores are not.
///
/// # Errors
///
/// [`CompareError::SameFile`] when the two paths are equal (a caller
/// canonicalizes first), and [`CompareError::Unreadable`] when a side produced
/// no dialogs and reported why.
pub fn compare(
    a: CaptureRef,
    b: CaptureRef,
    dimensions: &[String],
    max_dialogs: usize,
    max_streams: usize,
    top_n: usize,
) -> Result<CaptureComparison, CompareError> {
    if a.path == b.path {
        return Err(CompareError::SameFile {
            a: a.name.to_string(),
            b: b.name.to_string(),
        });
    }

    let snap_a = snapshot(a.path, a.name, dimensions, max_dialogs, max_streams);
    let snap_b = snapshot(b.path, b.name, dimensions, max_dialogs, max_streams);

    for snap in [&snap_a, &snap_b] {
        if snap.side.dialogs == 0
            && let Some(err) = &snap.side.read_error
        {
            return Err(CompareError::Unreadable {
                filename: snap.side.filename.clone(),
                error: err.clone(),
            });
        }
    }

    let empty = BTreeMap::new();
    let dimensions_out: Vec<DimensionDiff> = dimensions
        .iter()
        .map(|d| {
            diff_dimension(
                d,
                snap_a.tallies.get(d).unwrap_or(&empty),
                snap_b.tallies.get(d).unwrap_or(&empty),
                top_n,
            )
        })
        .collect();

    let mut summary = format!(
        "'{}' ({} dialogs) is the baseline; '{}' ({} dialogs) is held against \
         it, so delta is b minus a. Neither is the capture this server holds.",
        snap_a.side.filename, snap_a.side.dialogs, snap_b.side.filename, snap_b.side.dialogs,
    );
    for side in [&snap_a.side, &snap_b.side] {
        if let Some(err) = &side.read_error {
            summary.push_str(&format!(
                " '{}' was read only in part ({err}), so its counts are a floor.",
                side.filename
            ));
        }
        if side.dialogs_dropped > 0 {
            summary.push_str(&format!(
                " '{}' exceeded the dialog ceiling and {} dialog(s) were not \
                 counted.",
                side.filename, side.dialogs_dropped
            ));
        }
    }

    Ok(CaptureComparison {
        a: snap_a.side,
        b: snap_b.side,
        dimensions: dimensions_out,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples")
            .join(name)
    }

    /// An unknown dimension is refused before any file is read, naming the
    /// vocabulary. Valid ones dedup and default when empty.
    #[test]
    fn resolve_dimensions_guards_the_vocabulary() {
        let err = resolve_dimensions(Some(&["bogus".to_string()])).expect_err("unknown");
        assert!(
            matches!(err, CompareError::UnknownDimension { .. }),
            "an unknown dimension is refused: {err}"
        );
        assert!(err.to_string().contains("state"), "names the vocabulary");

        assert_eq!(
            resolve_dimensions(None).expect("defaults"),
            vec!["state".to_string(), "response_code".to_string()]
        );
        // A repeated dimension is deduped, not doubled.
        assert_eq!(
            resolve_dimensions(Some(&["state".to_string(), "state".to_string()])).expect("dedup"),
            vec!["state".to_string()]
        );
    }

    /// Two real captures diff by state: each bucket carries both sides and their
    /// signed delta, and the same file against itself is refused.
    #[test]
    fn compare_two_captures_by_state() {
        let a = fixture("b2bua-asterisk.pcapng");
        let b = fixture("sip-rtp-g711.pcap");
        let dims = vec!["state".to_string()];
        let cmp = compare(
            CaptureRef {
                path: &a,
                name: "a.pcap",
            },
            CaptureRef {
                path: &b,
                name: "b.pcap",
            },
            &dims,
            1000,
            1000,
            50,
        )
        .expect("two readable captures diff");

        assert_eq!(cmp.dimensions.len(), 1);
        assert_eq!(cmp.dimensions[0].dimension, "state");
        assert!(cmp.a.dialogs > 0 && cmp.b.dialogs > 0, "both sides read");
        for bucket in &cmp.dimensions[0].buckets {
            assert_eq!(
                bucket.delta,
                bucket.b as i64 - bucket.a as i64,
                "delta is b minus a"
            );
        }

        // A capture against itself is refused before it wastes two reads.
        let same = compare(
            CaptureRef {
                path: &a,
                name: "a.pcap",
            },
            CaptureRef {
                path: &a,
                name: "a.pcap",
            },
            &dims,
            1000,
            1000,
            50,
        );
        assert!(matches!(same, Err(CompareError::SameFile { .. })));
    }

    /// A side that yields nothing and reports why is refused, not diffed against
    /// — every bucket would look like it collapsed to zero.
    #[test]
    fn an_unreadable_side_is_refused() {
        let good = fixture("sip-rtp-g711.pcap");
        let missing = std::path::Path::new("/nonexistent/nope.pcap");
        let dims = vec!["state".to_string()];
        let err = compare(
            CaptureRef {
                path: &good,
                name: "good.pcap",
            },
            CaptureRef {
                path: missing,
                name: "missing.pcap",
            },
            &dims,
            1000,
            1000,
            50,
        )
        .expect_err("a side that read nothing is refused");
        assert!(
            matches!(err, CompareError::Unreadable { .. }),
            "an unreadable side is refused: {err}"
        );
    }

    /// Buckets are ranked by how far they MOVED, not by how big they are. The
    /// largest bucket is usually the one that changed least, and putting it
    /// first buries the answer.
    #[test]
    fn buckets_rank_by_movement_not_by_size() {
        let a: BTreeMap<String, usize> = [("200".to_string(), 900), ("503".to_string(), 1)].into();
        let b: BTreeMap<String, usize> = [("200".to_string(), 899), ("503".to_string(), 60)].into();
        let diff = diff_dimension("response_code", &a, &b, 10);
        assert_eq!(
            diff.buckets[0].value, "503",
            "the bucket that moved 59 must outrank the one that moved 1"
        );
        assert_eq!(diff.buckets[0].delta, 59);
        assert_eq!(diff.buckets[1].delta, -1);
        assert_eq!(diff.distinct_values, 2);
    }

    /// A value present in one capture only is reported as zero on the other
    /// side, because "this appeared today" is the finding, not a missing row.
    #[test]
    fn a_value_seen_in_one_capture_only_reads_as_zero_on_the_other() {
        let a: BTreeMap<String, usize> = [("200".to_string(), 5)].into();
        let b: BTreeMap<String, usize> = [("200".to_string(), 5), ("603".to_string(), 4)].into();
        let diff = diff_dimension("response_code", &a, &b, 10);
        let new = diff
            .buckets
            .iter()
            .find(|r| r.value == "603")
            .expect("the new value must be a bucket, not an omission");
        assert_eq!((new.a, new.b, new.delta), (0, 4, 4));
    }

    /// Everything past `top_n` is summed rather than dropped, so the rows and
    /// the remainder still account for both populations.
    #[test]
    fn buckets_past_top_n_are_summed_into_other() {
        let a: BTreeMap<String, usize> = [
            ("200".to_string(), 10),
            ("404".to_string(), 3),
            ("486".to_string(), 2),
        ]
        .into();
        let b: BTreeMap<String, usize> = [
            ("200".to_string(), 1),
            ("404".to_string(), 3),
            ("486".to_string(), 2),
        ]
        .into();
        let diff = diff_dimension("response_code", &a, &b, 1);
        assert_eq!(diff.buckets.len(), 1, "top_n must bound the rows");
        assert_eq!(
            diff.buckets[0].a + diff.other.a,
            15,
            "rows plus other must account for a"
        );
        assert_eq!(
            diff.buckets[0].b + diff.other.b,
            6,
            "rows plus other must account for b"
        );
    }

    /// A cap the capture exceeds is reported, not hidden: a diff over a
    /// truncated population is a wrong answer that looks like a right one.
    #[test]
    fn a_capture_over_the_dialog_ceiling_says_so() {
        let snap = snapshot(
            &fixture("sip-problem-call.pcap"),
            "sip-problem-call.pcap",
            &["state".to_string()],
            1,
            1000,
        );
        assert!(
            snap.side.dialogs_dropped > 0,
            "a one-dialog ceiling over a multi-dialog capture must report the loss"
        );
    }
}
