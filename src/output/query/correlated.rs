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
    /// Which strategy matched, by name: `session_id`, `th_callid_decoded`,
    /// `th_callid_mapping`, `x_call_id`, `sdp_origin`, `charging_vector_related_icid`,
    /// `charging_vector_icid`, `via_branch` or `timing_heuristic`. The
    /// decisive field.
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
    /// How the link was made: `decoded` (an OpenSIPS topology-hiding Call-ID
    /// decoded with the configured secret), `mapping` (an OpenSIPS
    /// `E_SIPNAB_TH_MAP` event named both legs), `header` (a SIP header both legs
    /// carry: a header named in `[sip] xcid_headers`, `Session-ID`,
    /// `P-Charging-Vector` or a Via branch), `sdp` (the SDP origin) or
    /// `timing` (the guess).
    pub method: String,
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
    /// This leg's own OpenSIPS topology-hiding status: `decoded`,
    /// `no_secret`, `undecodable`, `unmatched`, `mapped` or `conflict`, as
    /// the answer's top-level `th_callid` reports for the source. Null when
    /// the leg is not a hidden leg.
    pub th_callid: Option<crate::sip::dialog_store::ThCallidStatus>,
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
    /// When the source is the callee-side leg of an OpenSIPS
    /// `topology_hiding("C")` call: `decoded`, `no_secret` (no secret
    /// configured), `undecodable` (the secret or prefix does not decode it),
    /// `unmatched` (decoded, but no observed leg has that Call-ID and From
    /// tag), `mapped` (an `E_SIPNAB_TH_MAP` event joined it) or `conflict`
    /// (two events disagree about it). Null when the source is not a hidden
    /// leg.
    pub th_callid: Option<crate::sip::dialog_store::ThCallidStatus>,
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
                method: r.reason.method().to_string(),
                identifier_match,
                observed_gap_ms,
                th_callid: ds.th_callid_status(&r.dialog.call_id),
            }
        })
        .collect();
    Some(Correlated {
        schema_version: 1,
        source_call_id: call_id.to_string(),
        heuristic_only: heuristic_only(legs.iter().map(|l| l.identifier_match)),
        legs,
        total_matched: results.len(),
        th_callid: ds.th_callid_status(call_id),
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
                leg.method.clone(),
                leg.score.to_string(),
                if leg.identifier_match {
                    "identifier"
                } else {
                    "guess"
                }
                .to_string(),
                leg.observed_gap_ms
                    .map_or_else(|| "-".to_string(), |ms| ms.to_string()),
                leg.th_callid
                    .map_or_else(|| "-".to_string(), |s| s.as_str().to_string()),
            ]
        })
        .collect();
    out.push_str(&super::table(
        format,
        &[
            "Leg", "Strategy", "Method", "Score", "Match", "Gap ms", "TH",
        ],
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
    if let Some(status) = answer.th_callid {
        out.push_str(&format!(
            "Topology hiding: {status} ({})\n",
            status.explanation()
        ));
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

    /// T13 (REST and --correlate answer): a hidden call is one correlated
    /// call, its leg says `decoded`, and the source's topology-hiding status
    /// is reported.
    #[cfg(feature = "tls")]
    #[test]
    fn t13_decoded_leg_names_its_method_and_status() -> Result<(), Box<dyn std::error::Error>> {
        let (ds, caller, hidden) = crate::test_utils::th_hidden_call_store("right", Some("right"))?;
        let a = correlated(&ds, &hidden, 10, None).ok_or("hidden leg known")?;
        let leg = a
            .legs
            .iter()
            .find(|l| l.call_id == caller)
            .ok_or("caller leg")?;
        assert_eq!(
            leg.strategy, "th_callid_decoded",
            "the caller leg is joined by the decode strategy"
        );
        assert_eq!(
            leg.method, "decoded",
            "the caller leg is joined by the decoded method"
        );
        assert!(
            leg.identifier_match,
            "a decoded join compares identifiers, not timing"
        );
        assert_eq!(
            a.th_callid.map(|s| s.as_str()),
            Some("decoded"),
            "the hidden source reports that it decoded"
        );
        let v = serde_json::to_value(&a)?;
        assert_eq!(
            v["th_callid"], "decoded",
            "the JSON answer carries th_callid by its wire name: {v}"
        );
        let b = correlated(&ds, &caller, 10, None).ok_or("caller leg known")?;
        assert!(
            b.legs
                .iter()
                .any(|l| l.call_id == hidden && l.method == "decoded"),
            "from the caller side, the hidden leg is listed as decoded"
        );
        assert!(b.th_callid.is_none(), "the caller leg is not hidden");
        Ok(())
    }

    /// T13 / T8 (text report): the method column, and a line for a hidden
    /// source that says what went wrong without naming any secret.
    #[cfg(feature = "tls")]
    #[test]
    fn render_shows_method_and_th_status() -> Result<(), Box<dyn std::error::Error>> {
        let (ds, _, hidden) = crate::test_utils::th_hidden_call_store("right", Some("right"))?;
        let a = correlated(&ds, &hidden, 10, None).ok_or("known")?;
        let text = render(&a, ReportFormat::Text);
        assert!(text.contains("Method"), "{text}");
        assert!(text.contains("decoded"), "{text}");
        assert!(text.contains("Topology hiding: decoded"), "{text}");
        let (ds, _, hidden) = crate::test_utils::th_hidden_call_store("right", Some("wrong"))?;
        let a = correlated(&ds, &hidden, 10, None).ok_or("known")?;
        let text = render(&a, ReportFormat::Text);
        assert!(text.contains("Topology hiding: undecodable"), "{text}");
        assert!(text.contains("th_callid_secret_file"), "{text}");
        let wrong = String::from_utf8(crate::test_utils::th_test_secret("wrong"))?;
        assert!(
            !text.contains(&wrong),
            "the report shows the secret: {text}"
        );
        let (ds, _, hidden) = crate::test_utils::th_hidden_call_store("right", None)?;
        let a = correlated(&ds, &hidden, 10, None).ok_or("known")?;
        assert!(
            render(&a, ReportFormat::Text).contains("Topology hiding: no_secret"),
            "the text report names a hidden leg with no secret configured"
        );
        Ok(())
    }

    /// Each correlated leg carries its OWN topology-hiding status, so an answer
    /// asked from the caller side says which listed leg is the hidden one and
    /// whether it decoded, on REST, `--correlate` and MCP alike.
    #[cfg(feature = "tls")]
    #[test]
    fn each_leg_names_its_own_th_status() -> Result<(), Box<dyn std::error::Error>> {
        let (ds, caller, hidden) = crate::test_utils::th_hidden_call_store("right", Some("right"))?;
        let b = correlated(&ds, &caller, 10, None).ok_or("caller leg known")?;
        let leg = b
            .legs
            .iter()
            .find(|l| l.call_id == hidden)
            .ok_or("hidden leg listed")?;
        assert_eq!(
            leg.th_callid.map(|s| s.as_str()),
            Some("decoded"),
            "the hidden leg reports its own status"
        );
        let v = serde_json::to_value(&b)?;
        let row = v["legs"]
            .as_array()
            .and_then(|a| a.iter().find(|l| l["call_id"] == hidden.as_str()))
            .ok_or("hidden leg in JSON")?;
        assert_eq!(row["th_callid"], "decoded", "{v}");
        let text = render(&b, ReportFormat::Text);
        assert!(
            text.lines()
                .any(|l| l.split_whitespace().any(|w| w == "TH")),
            "the table has a TH column: {text}"
        );
        let row = text
            .lines()
            .find(|l| l.contains(hidden.as_str()))
            .ok_or("the hidden leg has a row")?;
        assert_eq!(
            row.split_whitespace().last(),
            Some("decoded"),
            "the hidden leg's row ends with its own status, the TH column: {row}"
        );
        let a = correlated(&ds, &hidden, 10, None).ok_or("hidden leg known")?;
        let caller_leg = a
            .legs
            .iter()
            .find(|l| l.call_id == caller)
            .ok_or("caller leg")?;
        assert!(
            caller_leg.th_callid.is_none(),
            "the caller leg is not hidden, so it has no status"
        );
        Ok(())
    }

    /// T6 / T8 (REST): a wrong or missing secret yields no decoded leg, and
    /// the status says which. The timing guess may still appear, labeled
    /// `timing`.
    #[cfg(feature = "tls")]
    #[test]
    fn t6_wrong_or_missing_secret_is_reported_not_joined() -> Result<(), Box<dyn std::error::Error>>
    {
        for (key, status) in [(Some("wrong"), "undecodable"), (None, "no_secret")] {
            let (ds, _, hidden) = crate::test_utils::th_hidden_call_store("right", key)?;
            let a = correlated(&ds, &hidden, 10, None).ok_or("hidden leg known")?;
            assert!(a.legs.iter().all(|l| l.method != "decoded"), "{status}");
            assert!(
                a.legs
                    .iter()
                    .all(|l| l.method == "timing" && !l.identifier_match),
                "with a {status} secret, only timing may tie the legs, and as a guess"
            );
            assert_eq!(
                a.th_callid.map(|s| s.as_str()),
                Some(status),
                "the hidden source reports {status}"
            );
        }
        Ok(())
    }
}
