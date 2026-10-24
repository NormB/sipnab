// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Dialogs counted by one dimension: how many fall in each value of state,
//! response code, method, a user part, the User-Agent, an address or the
//! codec.
//!
//! One answer, [`Aggregate`], built by [`aggregate`]: `GET /v1/aggregate`
//! serializes it and `--count-by` prints it. The bucket a dialog falls in is
//! [`crate::sip::dialog::dialog_group_value_raw`], and the order and the cut
//! are [`rank_by_count`], which the MCP `aggregate_dialogs` and
//! `group_dialogs` tools and `GET /v1/dialogs/rates` also apply: largest
//! first, ties broken by value so the same capture always answers in the same
//! order, and everything past the cut summed rather than dropped, so the
//! answer still adds up to every dialog counted.

use crate::output::ReportFormat;
use crate::sip::dialog::GROUPABLE;
use crate::sip::dsl::DialogSelection;

/// One bucket of an aggregate: a grouped value and how many dialogs fell in
/// it. A null in the data becomes the literal `(none)` rather than being
/// dropped, so the buckets sum to the total.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct AggregateBucket {
    /// The grouped value, rendered as a string.
    pub value: String,
    /// How many dialogs fell in this bucket.
    pub count: usize,
}

/// A "how many, by what" count over the dialog store, one dimension.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct Aggregate {
    /// Version of this response's shape.
    #[cfg_attr(feature = "api", schema(example = 1))]
    pub schema_version: u32,
    /// The dimension the count grouped by, echoed verbatim.
    pub group_by: String,
    /// The buckets, largest first, ties broken by value for a stable answer.
    pub buckets: Vec<AggregateBucket>,
    /// Total count in every bucket past the `top_n` cut, so the answer still
    /// sums to `total_matched`.
    pub other_count: usize,
    /// How many distinct values the dimension took, before the cut.
    pub distinct_values: usize,
    /// How many dialogs the filter admitted, across all buckets.
    pub total_matched: usize,
    /// WHICH capture this answer came from, and which revision of its
    /// stores, stamped under the locks the answer was built with. A
    /// different `instance` from an earlier answer means a different
    /// capture. The same identity the MCP tool answering this question
    /// carries. `null` when nobody told this server what it is attached to.
    #[cfg_attr(
        feature = "api",
        schema(value_type = Option<crate::output::api::schema::CaptureIdentity>)
    )]
    pub capture_identity: Option<crate::provenance::CaptureEtag>,
}

/// Whether `key` is a dimension a count may group by.
///
/// # Errors
///
/// The refusal REST and `--count-by` give for any other key, listing the
/// real ones. `narrow_with` names how this surface narrows a count instead
/// of adding a second dimension: `` `filter` `` on REST, `--filter` on the
/// CLI.
pub fn check_dimension(key: &str, narrow_with: &str) -> Result<(), String> {
    if GROUPABLE.contains(&key) {
        Ok(())
    } else {
        Err(format!(
            "cannot group by '{key}'; one of: {}. One dimension only — narrow \
             with {narrow_with} rather than adding a second.",
            GROUPABLE.join(", ")
        ))
    }
}

/// Values ranked by a count, cut after the first `top`.
#[derive(Debug, Clone, PartialEq)]
pub struct Ranked<T> {
    /// The first `top` values with what was tallied for each, largest first.
    pub kept: Vec<(String, T)>,
    /// The counts of every value past the cut, summed.
    pub other_count: usize,
    /// How many values there were before the cut.
    pub distinct: usize,
}

/// Rank `tally` largest count first, ties broken by value, keep the first
/// `top` and sum the counts of the rest.
///
/// The one ordering every group-by answer uses, on every surface, so a
/// cursor-free answer never reorders between two calls and looks like the
/// capture changed.
///
/// # Arguments
///
/// * `tally` — each value with what was tallied for it.
/// * `count` — how many dialogs a tally entry counts.
/// * `top` — how many values to keep.
pub fn rank_by_count<T>(
    tally: impl IntoIterator<Item = (String, T)>,
    count: &dyn Fn(&T) -> usize,
    top: usize,
) -> Ranked<T> {
    let mut ordered: Vec<(String, T)> = tally.into_iter().collect();
    let distinct = ordered.len();
    crate::sort::sort_by_dyn(&mut ordered, &mut |a, b| {
        count(&b.1).cmp(&count(&a.1)).then_with(|| a.0.cmp(&b.0))
    });
    let rest = ordered.split_off(top.min(ordered.len()));
    Ranked {
        other_count: rest.iter().map(|(_, t)| count(t)).sum(),
        kept: ordered,
        distinct,
    }
}

/// Count `selection`'s dialogs by `key`.
///
/// # Arguments
///
/// * `selection` — the dialogs to count, each with its streams: the whole
///   store, or the dialogs a filter admitted.
/// * `key` — a dimension [`check_dimension`] accepts. A dialog with no value
///   for it counts under `(none)`.
/// * `top` — how many values to keep; the rest are summed in `other_count`.
/// * `capture_identity` — which capture and store revision the dialogs came
///   from, stamped on the answer.
#[must_use]
pub fn aggregate(
    selection: &DialogSelection<'_>,
    key: &str,
    top: usize,
    capture_identity: Option<crate::provenance::CaptureEtag>,
) -> Aggregate {
    let mut tally: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (dialog, streams) in &selection.dialogs {
        if let Some(value) = crate::sip::dialog::dialog_group_value_raw(key, dialog, streams) {
            *tally.entry(value).or_insert(0) += 1;
        }
    }
    let ranked = rank_by_count(tally, &|n| *n, top);
    Aggregate {
        schema_version: 1,
        group_by: key.to_string(),
        buckets: ranked
            .kept
            .into_iter()
            .map(|(value, count)| AggregateBucket { value, count })
            .collect(),
        other_count: ranked.other_count,
        distinct_values: ranked.distinct,
        total_matched: selection.dialogs.len(),
        capture_identity,
    }
}

/// The count as a table: a line naming the dimension, the values and the
/// dialogs, one row per value kept, and a line summing the cut when there
/// is one.
#[must_use]
pub fn render(answer: &Aggregate, format: ReportFormat) -> String {
    let mut out = format!(
        "Dialogs by {}: {}, {}\n",
        answer.group_by,
        super::plural(answer.distinct_values as u64, "value"),
        super::plural(answer.total_matched as u64, "dialog"),
    );
    let rows: Vec<Vec<String>> = answer
        .buckets
        .iter()
        .map(|b| vec![b.value.clone(), b.count.to_string()])
        .collect();
    out.push_str(&super::table(format, &["Value", "Dialogs"], &rows));
    if answer.other_count > 0 {
        out.push_str(&format!(
            "Other: {} in {} past --top {}\n",
            super::plural(answer.other_count as u64, "dialog"),
            super::plural(
                answer.distinct_values.saturating_sub(answer.buckets.len()) as u64,
                "value"
            ),
            answer.buckets.len(),
        ));
    }
    out
}

/// The dimension check, the ranking and the table, driven directly.
#[cfg(test)]
mod tests {
    use super::*;

    /// A groupable key passes; any other is refused with the real list and
    /// the surface's own way to narrow.
    #[test]
    fn only_a_groupable_dimension_passes() {
        assert_eq!(check_dimension("state", "--filter"), Ok(()));
        let why = check_dimension("bogus", "--filter")
            .err()
            .unwrap_or_default();
        assert!(
            why.starts_with("cannot group by 'bogus'; one of: state, "),
            "{why}"
        );
        assert!(why.contains("narrow with --filter"), "{why}");
    }

    /// Largest first, ties by value, the cut summed, the distinct count
    /// taken before the cut.
    #[test]
    fn ranking_orders_by_count_then_value_and_sums_the_cut() {
        let tally = vec![
            ("b".to_string(), 1usize),
            ("c".to_string(), 5),
            ("a".to_string(), 1),
            ("d".to_string(), 2),
        ];
        let ranked = rank_by_count(tally, &|n| *n, 2);
        assert_eq!(
            ranked.kept,
            vec![("c".to_string(), 5), ("d".to_string(), 2)]
        );
        assert_eq!(ranked.other_count, 2);
        assert_eq!(ranked.distinct, 4);
        let all = rank_by_count(
            vec![("b".to_string(), 1usize), ("a".to_string(), 1)],
            &|n| *n,
            9,
        );
        assert_eq!(all.kept, vec![("a".to_string(), 1), ("b".to_string(), 1)]);
        assert_eq!(all.other_count, 0);
    }

    /// The table counts in the singular for one, and sums a cut on its own
    /// line.
    #[test]
    fn the_table_names_its_counts_and_sums_the_cut() {
        let answer = Aggregate {
            schema_version: 1,
            group_by: "method".into(),
            buckets: vec![AggregateBucket {
                value: "INVITE".into(),
                count: 3,
            }],
            other_count: 1,
            distinct_values: 2,
            total_matched: 4,
            capture_identity: None,
        };
        let out = render(&answer, ReportFormat::Text);
        assert!(
            out.starts_with("Dialogs by method: 2 values, 4 dialogs\n"),
            "{out}"
        );
        assert!(out.contains("INVITE  3"), "{out}");
        assert!(
            out.ends_with("Other: 1 dialog in 1 value past --top 1\n"),
            "{out}"
        );
    }
}
