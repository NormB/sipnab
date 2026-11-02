// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The other legs of one call, and the strategy that matched each.
//!
//! One answer, [`Correlated`], built by [`correlated`]:
//! `GET /v1/dialogs/{call_id}/correlated` serializes it, `--correlate`
//! prints it, and the MCP `find_correlated` tool returns its legs in its own
//! response, so all three decide "unknown Call-ID" in one place and describe
//! each leg with one type, [`CorrelatedLeg`]. The matching
//! is [`DialogStore::find_correlated_scored`] and the vocabulary
//! [`crate::sip::dialog_store::CorrelationResult::strategy_and_gap`].

use crate::output::ReportFormat;
use crate::sip::dialog_store::DialogStore;

/// One other leg of a call, and the strategy that matched it.
///
/// One type for every surface: `GET /v1/dialogs/{call_id}/correlated`,
/// `--correlate --json` and the MCP `find_correlated` tool all return it, so
/// an agent and a REST client read the same description of each field. The
/// strategy vocabulary comes from the one
/// `CorrelationResult::strategy_and_gap` rule.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct CorrelatedLeg {
    /// Call-ID of the correlated dialog. Pass it to `/v1/dialogs/{call_id}`
    /// on REST, or to the `get_dialog` tool on MCP, for its detail.
    pub call_id: String,
    /// Confidence, 0-100.
    #[cfg_attr(feature = "api", schema(minimum = 0, maximum = 100))]
    pub score: u8,
    /// Which strategy matched, by name: `session_id`, `x_call_id`,
    /// `sdp_origin`, `charging_vector_related_icid`, `charging_vector_icid`,
    /// `via_branch` or `timing_heuristic`. The decisive field.
    ///
    /// `session_id` and `x_call_id` both score 100 and are not the same claim:
    /// one is an RFC 7989 identifier designed to cross a B2BUA, the other a
    /// vendor header someone configured. `charging_vector_related_icid` and
    /// `charging_vector_icid` come out of ONE header and are likewise not the
    /// same claim: RFC 7315's `related-icid` is an intermediary declaring the
    /// link across a B2BUA, while plain `icid-value` equality is silent across
    /// a conformant one, because an ICID identifies a dialog and a B2BUA is
    /// two. `timing_heuristic` is not an identifier at all.
    pub strategy: String,
    /// True when the strategy compared identifiers, false for a guess.
    ///
    /// Present so a caller can filter on the distinction without having to
    /// know which strategy names mean what.
    pub identifier_match: bool,
    /// For `timing_heuristic` only: the observed gap between the two
    /// dialogs' creation, in milliseconds. Null for an identifier match,
    /// where it would be a number with no bearing on why they matched.
    ///
    /// The evidence behind the guess, so a reader can judge it. A 15 ms gap on
    /// a quiet box and a 1,900 ms gap on a busy SBC score identically and mean
    /// very different things.
    pub observed_gap_ms: Option<i64>,
}

/// The other legs of one call, with the source it was asked about.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct Correlated {
    /// Version of this response's shape.
    #[cfg_attr(feature = "api", schema(example = 1))]
    pub schema_version: u32,
    /// The Call-ID the legs were correlated against.
    pub source_call_id: String,
    /// The correlated legs, highest score first.
    pub legs: Vec<CorrelatedLeg>,
    /// How many legs matched before the row cap.
    pub total_matched: usize,
    /// True when every matched leg is a timing guess rather than an
    /// identifier match, so a reader weighs the whole answer accordingly.
    pub heuristic_only: bool,
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

/// Whether every leg in `identifier_matches` is a timing guess: true only
/// when there is at least one leg and none compared identifiers.
#[must_use]
pub fn heuristic_only(identifier_matches: impl IntoIterator<Item = bool>) -> bool {
    let mut any = false;
    for matched in identifier_matches {
        if matched {
            return false;
        }
        any = true;
    }
    any
}

/// The legs correlated with `call_id`, at most `limit` of them.
///
/// `None` when the store holds no dialog with that Call-ID, so an empty
/// `legs` always means "this call stands alone" and never "this call is not
/// here": REST answers 404, the MCP tool refuses, and `--correlate` exits 1.
#[must_use]
pub fn correlated(
    ds: &DialogStore,
    call_id: &str,
    limit: usize,
    capture_identity: Option<crate::provenance::CaptureEtag>,
) -> Option<Correlated> {
    let source_created = ds.get(call_id)?.created_at;
    let results = ds.find_correlated_scored(call_id);
    let legs: Vec<CorrelatedLeg> = results
        .iter()
        .take(limit)
        .map(|r| {
            let (strategy, identifier_match, observed_gap_ms) =
                r.strategy_and_gap(Some(source_created));
            CorrelatedLeg {
                call_id: r.dialog.call_id.clone(),
                score: r.score,
                strategy: strategy.to_string(),
                identifier_match,
                observed_gap_ms,
            }
        })
        .collect();
    Some(Correlated {
        schema_version: 1,
        source_call_id: call_id.to_string(),
        heuristic_only: heuristic_only(legs.iter().map(|l| l.identifier_match)),
        legs,
        total_matched: results.len(),
        capture_identity,
    })
}

/// The legs as a table: a line naming the source and the legs matched, one
/// row per leg with its strategy, score, whether it was an identifier match
/// or a guess, and the observed gap for a guess; a line when the row cap cut
/// the list; and a warning when every leg is a guess.
#[must_use]
pub fn render(answer: &Correlated, format: ReportFormat) -> String {
    let mut out = format!(
        "Legs correlated with {}: {}\n",
        answer.source_call_id,
        super::plural(answer.total_matched as u64, "leg"),
    );
    let rows: Vec<Vec<String>> = answer
        .legs
        .iter()
        .map(|leg| {
            vec![
                leg.call_id.clone(),
                leg.strategy.clone(),
                leg.score.to_string(),
                if leg.identifier_match {
                    "identifier"
                } else {
                    "guess"
                }
                .to_string(),
                leg.observed_gap_ms
                    .map_or_else(|| "-".to_string(), |ms| ms.to_string()),
            ]
        })
        .collect();
    out.push_str(&super::table(
        format,
        &["Leg", "Strategy", "Score", "Match", "Gap ms"],
        &rows,
    ));
    if answer.total_matched > answer.legs.len() {
        out.push_str(&format!(
            "Showing {} of {}.\n",
            answer.legs.len(),
            super::plural(answer.total_matched as u64, "leg"),
        ));
    }
    if answer.heuristic_only {
        out.push_str("Every leg here is a timing guess: no identifier ties it to this call.\n");
    }
    out
}

/// The guess rule, driven directly.
#[cfg(test)]
mod tests {
    use super::*;

    /// No legs is not "only guesses"; any identifier match makes it false.
    #[test]
    fn heuristic_only_needs_a_leg_and_no_identifier() {
        assert!(!heuristic_only([]));
        assert!(heuristic_only([false, false]));
        assert!(!heuristic_only([false, true]));
    }
}
