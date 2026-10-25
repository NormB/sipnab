// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Carrier metrics per group: for each value of one dimension, ASR, NER,
//! ACD, post-dial delay percentiles, the 10th-percentile MOS and the
//! retransmit rate, each with the population it was computed over.
//!
//! One answer, [`Rates`], built by [`rates`]: `GET /v1/dialogs/rates`
//! serializes it and `--rates-by` prints it. The group a dialog falls in and
//! every metric are [`crate::sip::group_metrics`]'s, which the MCP
//! `group_dialogs` tool also reads, and the order and the cut are
//! [`super::aggregate::rank_by_count`].

use crate::output::ReportFormat;
use crate::sip::dsl::DialogSelection;
use crate::sip::group_metrics::{EXTRA_DIMENSIONS, GroupAccumulator, METRICS};

/// The populations one rate group's figures were computed over, published so
/// a reader checks every ratio against its denominator.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct RatePopulation {
    /// Every dialog in the group.
    pub dialogs: usize,
    /// INVITE dialogs that reached a final response.
    pub seizures: usize,
    /// Seizures answered with a 2xx.
    pub answered: usize,
    /// Seizures the far end decided (answered or an E.411 destination code).
    pub delivered: usize,
    /// Calls both answered and torn down inside the capture (the ACD base).
    pub completed_calls: usize,
    /// Dialogs a post-dial delay was measured for.
    pub pdd_measured: usize,
    /// Dialogs a grounded MOS was scored for.
    pub mos_grounded_dialogs: usize,
    /// Retransmitted messages summed across the group.
    pub retransmits: u64,
}

/// One group's carrier metrics, with the population behind them and the
/// reason for any metric its population could not support.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct RateGroup {
    /// The dimension value this group is keyed on.
    pub value: String,
    /// Dialogs in the group (the same as `population.dialogs`, surfaced for
    /// a reader who reads only the top line).
    pub count: usize,
    /// Each requested metric to its value, or null when the population could
    /// not support it — the reason is then in `not_grounded`.
    pub metrics: std::collections::BTreeMap<String, Option<f64>>,
    /// For each null metric, the population that was missing. A null with no
    /// entry here would be a silent gap.
    pub not_grounded: std::collections::BTreeMap<String, String>,
    /// The populations every figure was computed over.
    pub population: RatePopulation,
}

/// Carrier metrics per group over the dialog store, one dimension.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct Rates {
    /// Version of this response's shape.
    #[cfg_attr(feature = "api", schema(example = 1))]
    pub schema_version: u32,
    /// The dimension the metrics were grouped by, echoed verbatim.
    pub group_by: String,
    /// The metric names computed: every metric, in the order of the metric
    /// table, when none were named; otherwise the named ones, sorted and
    /// de-duplicated.
    pub metrics: Vec<String>,
    /// Each metric name to the unit it is expressed in.
    pub units: std::collections::BTreeMap<String, String>,
    /// The groups, largest first, ties broken by value for a stable answer.
    pub groups: Vec<RateGroup>,
    /// Dialogs in every group past the `top_n` cut, so the groups plus this
    /// account for `total_matched`.
    pub other_count: usize,
    /// How many distinct values the dimension took, before the cut.
    pub distinct_values: usize,
    /// How many dialogs the filter admitted, across all groups.
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

/// Every dimension carrier metrics may group by: the groupable fields plus
/// [`EXTRA_DIMENSIONS`].
#[must_use]
pub fn dimensions() -> Vec<&'static str> {
    crate::sip::dialog::GROUPABLE
        .iter()
        .chain(EXTRA_DIMENSIONS)
        .copied()
        .collect()
}

/// Whether `key` is a dimension carrier metrics may group by.
///
/// # Errors
///
/// The refusal REST, MCP and `--rates-by` give for any other key, listing
/// the real ones; `narrow_with` names how the surface narrows instead.
pub fn check_dimension(key: &str, narrow_with: &str) -> Result<(), String> {
    super::check_dimension_in(key, &dimensions(), narrow_with)
}

/// Every metric, in the order of the metric table: what an answer computes
/// when the caller names none.
#[must_use]
pub fn all_metrics() -> Vec<String> {
    METRICS
        .iter()
        .map(|(name, _)| (*name).to_string())
        .collect()
}

/// The metrics to compute: every metric in the table's order when `asked`
/// is `None` or names none, otherwise the named ones, sorted and
/// de-duplicated, so the answer's key order does not depend on the order
/// the caller listed them in.
///
/// # Errors
///
/// The refusal for a name outside the metric table, listing the real ones.
pub fn wanted_metrics<'a>(
    asked: Option<impl IntoIterator<Item = &'a str>>,
) -> Result<Vec<String>, String> {
    let Some(asked) = asked else {
        return Ok(all_metrics());
    };
    let mut set = std::collections::BTreeSet::new();
    for m in asked.into_iter().map(str::trim).filter(|m| !m.is_empty()) {
        if !METRICS.iter().any(|(name, _)| *name == m) {
            return Err(format!(
                "unknown metric '{m}'; one of: {}",
                METRICS
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        set.insert(m.to_string());
    }
    Ok(if set.is_empty() {
        all_metrics()
    } else {
        set.into_iter().collect()
    })
}

/// Carrier metrics for `selection`'s dialogs, grouped by `key`.
///
/// # Arguments
///
/// * `selection` — the dialogs to group, each with its streams.
/// * `delay` — the capture's one-way delay, for the MOS.
/// * `key` — a dimension [`check_dimension`] accepts.
/// * `wanted` — the metrics, from [`wanted_metrics`].
/// * `top` — how many groups to keep; the rest are summed in `other_count`.
/// * `capture_identity` — stamped on the answer.
///
/// # Errors
///
/// A metric in `wanted` that the metric table has no extractor for, which
/// [`wanted_metrics`] never yields.
pub fn rates(
    selection: &DialogSelection<'_>,
    delay: crate::rtp::quality::MosDelay<'_>,
    key: &str,
    wanted: &[String],
    top: usize,
    capture_identity: Option<crate::provenance::CaptureEtag>,
) -> Result<Rates, String> {
    let mut tally: std::collections::HashMap<String, GroupAccumulator> =
        std::collections::HashMap::new();
    for (dialog, streams) in &selection.dialogs {
        if let Some(value) = crate::sip::group_metrics::group_value_raw(key, dialog, streams) {
            tally.entry(value).or_default().add(dialog, streams, delay);
        }
    }
    let ranked = super::aggregate::rank_by_count(tally, &|a| a.dialogs(), top);

    let mut groups = Vec::new();
    for (value, acc) in ranked.kept {
        let mut metrics = std::collections::BTreeMap::new();
        let mut not_grounded = std::collections::BTreeMap::new();
        for m in wanted {
            match acc.value_of(m) {
                Some(Ok(v)) => match crate::sip::group_metrics::rounded(v) {
                    Some(v) => {
                        metrics.insert(m.clone(), Some(v));
                    }
                    None => {
                        metrics.insert(m.clone(), None);
                        not_grounded.insert(
                            m.clone(),
                            "the computed value is not a finite number".to_string(),
                        );
                    }
                },
                Some(Err(why)) => {
                    metrics.insert(m.clone(), None);
                    not_grounded.insert(m.clone(), why);
                }
                None => return Err(format!("metric '{m}' has no extractor")),
            }
        }
        let pop = acc.population();
        groups.push(RateGroup {
            value,
            count: pop.dialogs,
            metrics,
            not_grounded,
            population: RatePopulation {
                dialogs: pop.dialogs,
                seizures: pop.seizures,
                answered: pop.answered,
                delivered: pop.delivered,
                completed_calls: pop.completed_calls,
                pdd_measured: pop.pdd_measured,
                mos_grounded_dialogs: pop.mos_grounded_dialogs,
                retransmits: pop.retransmits,
            },
        });
    }

    let units = wanted
        .iter()
        .filter_map(|m| {
            METRICS
                .iter()
                .find(|(name, _)| name == m)
                .map(|(_, unit)| (m.clone(), (*unit).to_string()))
        })
        .collect();

    Ok(Rates {
        schema_version: 1,
        group_by: key.to_string(),
        metrics: wanted.to_vec(),
        units,
        groups,
        other_count: ranked.other_count,
        distinct_values: ranked.distinct,
        total_matched: selection.dialogs.len(),
        capture_identity,
    })
}

/// The metrics as a table: a line naming the dimension, the values and the
/// dialogs; one row per group with a column per metric (`count` is the
/// Dialogs column), `-` for a figure the group's population could not
/// support; the units; and a line summing the cut when there is one.
#[must_use]
pub fn render(answer: &Rates, format: ReportFormat) -> String {
    use std::fmt::Write as _;

    let mut out = format!(
        "Carrier metrics by {}: {}, {}\n",
        answer.group_by,
        super::plural(answer.distinct_values as u64, "value"),
        super::plural(answer.total_matched as u64, "dialog"),
    );
    let columns: Vec<&str> = answer
        .metrics
        .iter()
        .map(String::as_str)
        .filter(|m| *m != "count")
        .collect();
    let mut headers = vec!["Value", "Dialogs"];
    headers.extend(&columns);
    let rows: Vec<Vec<String>> = answer
        .groups
        .iter()
        .map(|g| {
            let mut row = vec![g.value.clone(), g.count.to_string()];
            row.extend(columns.iter().map(|m| match g.metrics.get(*m) {
                Some(Some(v)) => v.to_string(),
                _ => "-".to_string(),
            }));
            row
        })
        .collect();
    out.push_str(&super::table(format, &headers, &rows));
    if answer.other_count > 0 {
        let _ = writeln!(
            out,
            "Other: {} in {} past --top {}",
            super::plural(answer.other_count as u64, "dialog"),
            super::plural(
                answer.distinct_values.saturating_sub(answer.groups.len()) as u64,
                "value"
            ),
            answer.groups.len(),
        );
    }
    let units: Vec<String> = columns
        .iter()
        .filter_map(|m| answer.units.get(*m).map(|u| format!("{m} {u}")))
        .collect();
    if !units.is_empty() {
        let _ = writeln!(out, "Units: {}", units.join(", "));
    }
    if answer.groups.iter().any(|g| !g.not_grounded.is_empty()) {
        let _ = writeln!(
            out,
            "-: the group's population could not support the figure; --json names \
             why in not_grounded"
        );
    }
    out
}

/// The metric list, the dimension rule and the table, driven directly.
#[cfg(test)]
mod tests {
    use super::*;

    /// No list is every metric in the table's order; a list is sorted and
    /// de-duplicated; an unknown name is refused with the real ones.
    #[test]
    fn the_metric_list_defaults_sorts_and_refuses() {
        let none: Option<Vec<&str>> = None;
        assert_eq!(
            wanted_metrics(none),
            Ok(METRICS.iter().map(|(n, _)| (*n).to_string()).collect())
        );
        assert_eq!(
            wanted_metrics(Some(vec!["ner", " asr", "ner"])),
            Ok(vec!["asr".to_string(), "ner".to_string()])
        );
        assert_eq!(
            wanted_metrics(Some(vec!["", " "])),
            Ok(METRICS.iter().map(|(n, _)| (*n).to_string()).collect())
        );
        let why = wanted_metrics(Some(vec!["asr", "bogus"]))
            .err()
            .unwrap_or_default();
        assert!(
            why.starts_with("unknown metric 'bogus'; one of: count, asr"),
            "{why}"
        );
    }

    /// The extra dimensions are accepted beside the groupable ones.
    #[test]
    fn the_extra_dimensions_are_accepted() {
        for key in ["state", "to_domain", "hour", "next_hop"] {
            assert_eq!(check_dimension(key, "--filter"), Ok(()), "{key}");
        }
        let why = check_dimension("bogus", "--filter")
            .err()
            .unwrap_or_default();
        assert!(
            why.contains("rtp.codec, to_domain, hour, next_hop"),
            "{why}"
        );
    }

    /// A null figure is `-`, `count` is the Dialogs column, and the units
    /// and the dash are explained below the table.
    #[test]
    fn the_table_dashes_a_null_and_names_the_units() {
        let group = RateGroup {
            value: "Failed".into(),
            count: 4,
            metrics: [("count".to_string(), Some(4.0)), ("acd".to_string(), None)]
                .into_iter()
                .collect(),
            not_grounded: [("acd".to_string(), "no call was timed".to_string())]
                .into_iter()
                .collect(),
            population: RatePopulation {
                dialogs: 4,
                seizures: 4,
                answered: 0,
                delivered: 2,
                completed_calls: 0,
                pdd_measured: 0,
                mos_grounded_dialogs: 0,
                retransmits: 0,
            },
        };
        let answer = Rates {
            schema_version: 1,
            group_by: "state".into(),
            metrics: vec!["count".into(), "acd".into()],
            units: [
                ("count".to_string(), "dialogs".to_string()),
                ("acd".to_string(), "seconds".to_string()),
            ]
            .into_iter()
            .collect(),
            groups: vec![group],
            other_count: 0,
            distinct_values: 1,
            total_matched: 4,
            capture_identity: None,
        };
        let out = render(&answer, ReportFormat::Text);
        assert!(out.contains("Value   Dialogs  acd"), "{out}");
        assert!(out.contains("Failed  4        -"), "{out}");
        assert!(out.contains("Units: acd seconds\n"), "{out}");
        assert!(out.contains("not_grounded"), "{out}");
    }
}
