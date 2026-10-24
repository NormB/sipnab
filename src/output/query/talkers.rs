// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The busiest participants: who took part in the most dialogs, by sending
//! address, banner or the dialed number's leading digits.
//!
//! One answer, [`Talkers`], built by [`talkers`]: `GET /v1/talkers`
//! serializes it and `--talkers` prints it. Who a dialog credits is
//! [`TalkerDimension::credit`], and the order is [`rank`], which the MCP
//! `top_talkers` tool also applies (it fences `ua` keys before a model reads
//! them, a step only that surface takes).

use std::collections::BTreeMap;

use crate::output::ReportFormat;
use crate::sip::dsl::DialogSelection;
use crate::sip::talkers::{TalkerAccumulator, TalkerDimension};

/// One ranked talker: a participant and what it did across the dialogs it
/// took part in. The same fields the MCP `top_talkers` tool reports.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct Talker {
    /// The talker's key — an address (`ip`), a banner (`ua`), or the dialed
    /// number's leading digits (`prefix`).
    pub key: String,
    /// Dialogs the talker appeared in.
    pub dialogs: usize,
    /// Messages attributed to the talker.
    pub messages: usize,
    /// Of `dialogs`, the INVITE ones.
    pub invites: usize,
    /// Of `invites`, the ones that reached a 2xx.
    pub answered: usize,
    /// Of `invites`, the ones that ended 4xx, 5xx or 6xx.
    pub failed: usize,
    /// The share of matched dialogs this talker appeared in, as a percent.
    /// Null on an empty capture, where a zero would read as a talker
    /// measured to be idle. Shares sum above 100% because a dialog counts
    /// for every participant.
    pub share_pct: Option<f64>,
}

/// The busiest participants, ranked largest first.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct Talkers {
    /// Version of this response's shape.
    #[cfg_attr(feature = "api", schema(example = 1))]
    pub schema_version: u32,
    /// The dimension ranked by (`ip`, `ua` or `prefix`), echoed verbatim.
    pub by: String,
    /// The ranked talkers, busiest first, ties broken by messages then key.
    pub talkers: Vec<Talker>,
    /// True when there are more distinct talkers than the page returned.
    pub truncated: bool,
    /// How many distinct talkers the filter admitted, before the page cut.
    pub distinct_talkers: usize,
    /// How many dialogs the filter admitted, the share denominator.
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

/// `tally` ranked: most dialogs first, then most messages, then the key, so
/// the same capture always answers in the same order. The one ordering
/// every talker ranking uses.
#[must_use]
pub fn rank(tally: BTreeMap<String, TalkerAccumulator>) -> Vec<(String, TalkerAccumulator)> {
    let mut ordered: Vec<(String, TalkerAccumulator)> = tally.into_iter().collect();
    crate::sort::sort_by_dyn(&mut ordered, &mut |(ka, a), (kb, b)| {
        b.dialogs
            .cmp(&a.dialogs)
            .then_with(|| b.messages.cmp(&a.messages))
            .then_with(|| ka.cmp(kb))
    });
    ordered
}

/// The share of `total` dialogs a talker in `dialogs` of them appeared in,
/// as a percent; `None` when there are no dialogs, where a zero would read
/// as a talker measured to be idle.
#[must_use]
pub fn share_pct(dialogs: usize, total: usize) -> Option<f64> {
    (total > 0).then(|| (dialogs as f64 / total as f64) * 100.0)
}

/// `selection`'s dialogs ranked by `dimension`, the first `limit` kept.
///
/// # Arguments
///
/// * `selection` — the dialogs to rank: the whole store, or the dialogs a
///   filter admitted.
/// * `dimension` — what to rank by, from [`TalkerDimension::parse`].
/// * `limit` — how many talkers to keep; `truncated` says whether any were
///   left out.
/// * `capture_identity` — stamped on the answer.
#[must_use]
pub fn talkers(
    selection: &DialogSelection<'_>,
    dimension: TalkerDimension,
    limit: usize,
    capture_identity: Option<crate::provenance::CaptureEtag>,
) -> Talkers {
    let total_matched = selection.dialogs.len();
    let mut tally: BTreeMap<String, TalkerAccumulator> = BTreeMap::new();
    for (dialog, _) in &selection.dialogs {
        dimension.credit(dialog, &mut tally);
    }
    let distinct_talkers = tally.len();
    // RAW keys: a program wants the value it can key on, so a `ua` banner is
    // returned verbatim (the MCP surface fences it).
    let talkers: Vec<Talker> = rank(tally)
        .into_iter()
        .take(limit)
        .map(|(key, acc)| Talker {
            key,
            dialogs: acc.dialogs,
            messages: acc.messages,
            invites: acc.invites,
            answered: acc.answered,
            failed: acc.failed,
            share_pct: share_pct(acc.dialogs, total_matched),
        })
        .collect();
    Talkers {
        schema_version: 1,
        by: dimension.name().to_string(),
        truncated: distinct_talkers > talkers.len(),
        talkers,
        distinct_talkers,
        total_matched,
        capture_identity,
    }
}

/// The ranking as a table: a line naming the dimension, the talkers and the
/// dialogs, one row per talker kept, and a line counting the talkers left
/// out when there are any.
#[must_use]
pub fn render(answer: &Talkers, format: ReportFormat) -> String {
    let mut out = format!(
        "Talkers by {}: {}, {}\n",
        answer.by,
        super::plural(answer.distinct_talkers as u64, "talker"),
        super::plural(answer.total_matched as u64, "dialog"),
    );
    let rows: Vec<Vec<String>> = answer
        .talkers
        .iter()
        .map(|t| {
            vec![
                t.key.clone(),
                t.dialogs.to_string(),
                t.messages.to_string(),
                t.invites.to_string(),
                t.answered.to_string(),
                t.failed.to_string(),
                t.share_pct.map_or_else(
                    || "-".to_string(),
                    |p| format!("{}", (p * 10.0).round() / 10.0),
                ),
            ]
        })
        .collect();
    out.push_str(&super::table(
        format,
        &[
            "Talker", "Dialogs", "Messages", "INVITEs", "Answered", "Failed", "Share%",
        ],
        &rows,
    ));
    if answer.truncated {
        out.push_str(&format!(
            "Other: {} past --top {}\n",
            super::plural(
                answer.distinct_talkers.saturating_sub(answer.talkers.len()) as u64,
                "talker"
            ),
            answer.talkers.len(),
        ));
    }
    out
}

/// The ordering, the share and the table, driven directly.
#[cfg(test)]
mod tests {
    use super::*;

    fn acc(dialogs: usize, messages: usize) -> TalkerAccumulator {
        TalkerAccumulator {
            dialogs,
            messages,
            ..TalkerAccumulator::default()
        }
    }

    /// Dialogs first, messages next, the key last.
    #[test]
    fn rank_orders_by_dialogs_then_messages_then_key() {
        let tally: BTreeMap<String, TalkerAccumulator> = [
            ("b".to_string(), acc(1, 2)),
            ("a".to_string(), acc(1, 2)),
            ("c".to_string(), acc(1, 9)),
            ("d".to_string(), acc(3, 1)),
        ]
        .into_iter()
        .collect();
        let keys: Vec<String> = rank(tally).into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["d", "c", "a", "b"]);
    }

    /// No dialogs is no share, never a zero.
    #[test]
    fn share_is_none_without_dialogs() {
        assert_eq!(share_pct(1, 0), None);
        assert_eq!(share_pct(1, 4), Some(25.0));
    }

    /// A share prints to one decimal, a missing one as `-`, and a cut is
    /// counted on its own line.
    #[test]
    fn the_table_rounds_the_share_and_counts_the_cut() {
        let answer = Talkers {
            schema_version: 1,
            by: "ip".into(),
            talkers: vec![Talker {
                key: "192.0.2.1".into(),
                dialogs: 1,
                messages: 2,
                invites: 1,
                answered: 0,
                failed: 1,
                share_pct: Some(100.0 / 3.0),
            }],
            truncated: true,
            distinct_talkers: 3,
            total_matched: 3,
            capture_identity: None,
        };
        let out = render(&answer, ReportFormat::Text);
        assert!(
            out.starts_with("Talkers by ip: 3 talkers, 3 dialogs\n"),
            "{out}"
        );
        assert!(
            out.contains("192.0.2.1  1        2         1        0         1       33.3"),
            "{out}"
        );
        assert!(out.ends_with("Other: 2 talkers past --top 1\n"), "{out}");
    }
}
