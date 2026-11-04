// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The OpenSIPS topology-hiding mappings sipnab holds, one row each.
//!
//! One answer, [`ThMappings`], built by [`th_mappings`]:
//! `GET /v1/th-mappings` serializes it, `--th-mappings` prints it at the end
//! of a run, and the MCP `th_mappings` tool returns it, so all three list the
//! same rows in the same order with the same state. The counts beside the rows
//! are the `th_mappings` and `th_callid` objects `/v1/stats` and
//! `capture_status` already return, read from the same store under the same
//! lock.
//!
//! The rows answer the question the counts cannot: WHICH mapping is waiting,
//! and for which leg. A call that did not join is either not named by any
//! mapping (no row for its Call-ID), named by one whose other leg was never
//! captured (`pending`, with `caller_captured` or `callee_captured` false), or
//! named by two events that disagree (`conflict`).

use crate::output::ReportFormat;
use crate::sip::dialog_store::{DialogStore, ThCallidSummary};
use crate::sip::th_mapping::{ThMappingCounts, ThMappingState};

/// One mapping the table holds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct ThMappingRow {
    /// The caller-side Call-ID OpenSIPS named (`$ci`).
    pub caller_call_id: String,
    /// The callee-side Call-ID OpenSIPS named (`$TH_callee_callid`).
    pub callee_call_id: String,
    /// `joined` (both legs are captured and the mapping joins them),
    /// `pending` (a leg is not captured yet) or `conflict` (another event
    /// named one of these Call-IDs with a different partner, so this mapping
    /// joins nothing).
    pub state: ThMappingState,
    /// Whether the store holds a dialog with `caller_call_id`.
    pub caller_captured: bool,
    /// Whether the store holds a dialog with `callee_call_id`.
    pub callee_captured: bool,
}

/// The mappings held, with the counts they belong to.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct ThMappings {
    /// Version of this response's shape.
    #[cfg_attr(feature = "api", schema(example = 1))]
    pub schema_version: u32,
    /// The Call-ID the rows were narrowed to, either side of a mapping. Null
    /// when none was asked for.
    pub call_id: Option<String>,
    /// The state the rows were narrowed to. Null when none was asked for.
    pub state: Option<ThMappingState>,
    /// The rows, ordered by state (`conflict`, `pending`, `joined`) and then
    /// by caller-side Call-ID, so the ones worth looking at come first and two
    /// answers about the same table list them in the same order.
    pub mappings: Vec<ThMappingRow>,
    /// How many rows matched before the row cap.
    pub total_matched: usize,
    /// The `E_SIPNAB_TH_MAP` counts, the object `/v1/stats` returns as
    /// `th_mappings`.
    pub counts: ThMappingCounts,
    /// The hidden legs held now by status, the object `/v1/stats` returns as
    /// `th_callid`.
    pub th_callid: ThCallidSummary,
    /// WHICH capture this answer came from, and which revision of its
    /// stores, stamped under the locks the answer was built with: whether a
    /// leg is captured depends on the dialog store. The same identity the MCP
    /// tool answering this question carries. `null` when nobody told this
    /// server what it is attached to.
    #[cfg_attr(
        feature = "api",
        schema(value_type = Option<crate::output::api::schema::CaptureIdentity>)
    )]
    pub capture_identity: Option<crate::provenance::CaptureEtag>,
}

/// The mappings `ds` holds, narrowed to those naming `call_id` (either side)
/// and to `state`, at most `limit` of them.
#[must_use]
pub fn th_mappings(
    ds: &DialogStore,
    call_id: Option<&str>,
    state: Option<ThMappingState>,
    limit: usize,
    capture_identity: Option<crate::provenance::CaptureEtag>,
) -> ThMappings {
    let present = |id: &str| ds.get(id).is_some();
    let mut rows: Vec<ThMappingRow> = ds
        .th_mapping_entries()
        .filter(|m| call_id.is_none_or(|id| m.caller_call_id == id || m.callee_call_id == id))
        .map(|m| {
            let caller_captured = present(m.caller_call_id);
            let callee_captured = present(m.callee_call_id);
            ThMappingRow {
                caller_call_id: m.caller_call_id.to_string(),
                callee_call_id: m.callee_call_id.to_string(),
                state: ThMappingState::of(m.conflicted, caller_captured, callee_captured),
                caller_captured,
                callee_captured,
            }
        })
        .filter(|r| state.is_none_or(|s| r.state == s))
        .collect();
    rows.sort_by(|a, b| {
        a.state
            .cmp(&b.state)
            .then_with(|| a.caller_call_id.cmp(&b.caller_call_id))
    });
    let total_matched = rows.len();
    rows.truncate(limit);
    ThMappings {
        schema_version: 1,
        call_id: call_id.map(str::to_string),
        state,
        mappings: rows,
        total_matched,
        counts: ds.th_mapping_counts(),
        th_callid: ds.th_callid_summary(),
        capture_identity,
    }
}

/// The answer as text: the counts line, one row per mapping, and a line when
/// the row cap cut the list.
#[must_use]
pub fn render(answer: &ThMappings, format: ReportFormat) -> String {
    let c = &answer.counts;
    let mut out = format!(
        "Topology-hiding mappings: {} held, {} pending; events: {} accepted, {} \
         duplicate, {} conflicting, {} malformed, {} refused (table full); {} expired\n",
        super::plural(c.held, "mapping"),
        c.pending,
        c.accepted,
        c.duplicate,
        c.conflict,
        c.malformed,
        c.refused_full,
        c.expired,
    );
    let legs: Vec<String> = answer
        .th_callid
        .by_status()
        .iter()
        .map(|(status, n)| format!("{n} {status}"))
        .collect();
    out.push_str(&format!("Hidden legs held: {}\n", legs.join(", ")));
    if answer.mappings.is_empty() {
        out.push_str("No E_SIPNAB_TH_MAP mapping is held");
        out.push_str(if answer.call_id.is_some() || answer.state.is_some() {
            " that matches.\n"
        } else {
            ".\n"
        });
        return out;
    }
    let yes_no = |b: bool| if b { "yes" } else { "no" }.to_string();
    let rows: Vec<Vec<String>> = answer
        .mappings
        .iter()
        .map(|r| {
            vec![
                r.caller_call_id.clone(),
                r.callee_call_id.clone(),
                r.state.as_str().to_string(),
                yes_no(r.caller_captured),
                yes_no(r.callee_captured),
            ]
        })
        .collect();
    out.push_str(&super::table(
        format,
        &[
            "Caller Call-ID",
            "Callee Call-ID",
            "State",
            "Caller captured",
            "Callee captured",
        ],
        &rows,
    ));
    if answer.total_matched > answer.mappings.len() {
        out.push_str(&format!(
            "Showing {} of {}.\n",
            answer.mappings.len(),
            super::plural(answer.total_matched as u64, "mapping"),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the tests that build a store need these, and that store needs
    // `tls`; ungated, a build without `tls` fails -Dwarnings on them.
    #[cfg(feature = "tls")]
    use crate::sip::th_mapping::ThMapping;

    #[cfg(feature = "tls")]
    type TestError = Box<dyn std::error::Error>;

    /// A store holding the hidden call's two legs with a mapping that joins
    /// them, a mapping neither of whose legs is captured, and a conflict.
    #[cfg(feature = "tls")]
    fn store() -> Result<(DialogStore, String, String), TestError> {
        let (mut ds, caller, hidden) = crate::test_utils::th_hidden_call_store("right", None)?;
        let now = chrono::Utc::now();
        let mut map = |a: &str, b: &str| {
            ds.apply_th_mapping(
                Ok(ThMapping {
                    caller_call_id: a.into(),
                    callee_call_id: b.into(),
                }),
                now,
            );
        };
        map(&caller, &hidden);
        map("waiting@example.com", "DLGCH_waiting");
        map("x@example.com", "DLGCH_x1");
        map("x@example.com", "DLGCH_x2");
        Ok((ds, caller, hidden))
    }

    /// Every held mapping is a row with its state and which legs are
    /// captured, conflicts first, and the counts are the store's.
    #[cfg(feature = "tls")]
    #[test]
    fn lists_every_mapping_with_its_state() -> Result<(), TestError> {
        let (ds, caller, hidden) = store()?;
        let a = th_mappings(&ds, None, None, 100, None);
        assert_eq!(a.total_matched, 3, "three mappings held: {a:?}");
        assert_eq!(a.mappings.len(), 3, "every mapping is a row: {a:?}");
        let states: Vec<_> = a.mappings.iter().map(|r| r.state.as_str()).collect();
        assert_eq!(states, ["conflict", "pending", "joined"], "{a:?}");
        let joined = &a.mappings[2];
        assert_eq!(
            joined.caller_call_id, caller,
            "the joined row names the caller leg"
        );
        assert_eq!(
            joined.callee_call_id, hidden,
            "the joined row names the hidden leg"
        );
        assert!(
            joined.caller_captured && joined.callee_captured,
            "a joined mapping has both legs captured: {joined:?}"
        );
        let pending = &a.mappings[1];
        assert_eq!(
            pending.caller_call_id, "waiting@example.com",
            "the pending row is the mapping with no captured leg"
        );
        assert!(
            !pending.caller_captured && !pending.callee_captured,
            "neither leg of the pending mapping is captured: {pending:?}"
        );
        assert_eq!(a.counts, ds.th_mapping_counts(), "the store's counts");
        assert_eq!(a.th_callid, ds.th_callid_summary(), "the store's summary");
        assert_eq!(a.th_callid.mapped, 1, "the hidden leg joined by mapping");
        Ok(())
    }

    /// A Call-ID narrows to the mapping naming it on either side; a state
    /// narrows to that state; the cap keeps the count of what matched.
    #[cfg(feature = "tls")]
    #[test]
    fn narrows_by_call_id_state_and_cap() -> Result<(), TestError> {
        let (ds, caller, hidden) = store()?;
        for id in [caller.as_str(), hidden.as_str()] {
            let a = th_mappings(&ds, Some(id), None, 100, None);
            assert_eq!(a.total_matched, 1, "{id}: {a:?}");
            assert_eq!(
                a.mappings[0].caller_call_id, caller,
                "{id} narrows to its own mapping"
            );
            assert_eq!(
                a.call_id.as_deref(),
                Some(id),
                "the answer echoes the Call-ID"
            );
        }
        let a = th_mappings(&ds, Some("nobody@example.com"), None, 100, None);
        assert_eq!(a.total_matched, 0, "no event named this Call-ID: {a:?}");
        let a = th_mappings(&ds, None, Some(ThMappingState::Pending), 100, None);
        assert_eq!(a.total_matched, 1, "{a:?}");
        assert_eq!(
            a.mappings[0].caller_call_id, "waiting@example.com",
            "the one pending mapping"
        );
        let a = th_mappings(&ds, None, None, 1, None);
        assert_eq!(a.mappings.len(), 1, "capped");
        assert_eq!(a.total_matched, 3, "the count is before the cap");
        Ok(())
    }

    /// The text names the counts, each row with its state and captured legs,
    /// and the cap.
    #[cfg(feature = "tls")]
    #[test]
    fn render_names_rows_states_and_cap() -> Result<(), TestError> {
        let (ds, _, hidden) = store()?;
        let text = render(&th_mappings(&ds, None, None, 100, None), ReportFormat::Text);
        assert!(text.contains("3 mappings held"), "{text}");
        let row = text
            .lines()
            .find(|l| l.contains(hidden.as_str()))
            .ok_or("the joined mapping has a row")?;
        assert!(row.contains("joined"), "{row}");
        let row = text
            .lines()
            .find(|l| l.contains("DLGCH_waiting"))
            .ok_or("the pending mapping has a row")?;
        assert!(row.contains("pending"), "{row}");
        assert!(
            row.split_whitespace().filter(|w| *w == "no").count() == 2,
            "{row}"
        );
        let capped = render(&th_mappings(&ds, None, None, 1, None), ReportFormat::Text);
        assert!(capped.contains("Showing 1 of 3 mappings"), "{capped}");
        Ok(())
    }

    /// An empty table says so rather than printing an empty table.
    #[test]
    fn render_says_when_nothing_is_held() {
        let ds = DialogStore::new(10, false);
        let text = render(&th_mappings(&ds, None, None, 100, None), ReportFormat::Text);
        assert!(text.contains("0 mappings held"), "{text}");
        assert!(
            text.contains("No E_SIPNAB_TH_MAP mapping is held"),
            "{text}"
        );
    }
}
