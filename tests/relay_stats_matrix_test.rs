// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST-S3 acceptance: the relay-statistics capability matrix.
//!
//! One test asserting all five capabilities (C1–C5) exist on all four surfaces
//! (CLI, REST, MCP, TUI), with C5's two omissions -- REST and MCP -- named as
//! expected AND carrying their reason, so removing the reason fails the test
//! rather than the omission passing silently (the spec's own acceptance wording,
//! `docs/design/relay-statistics-surfaces.md`).
//!
//! The contract lives in that doc, so the matrix is read FROM it: a surface that
//! silently drops a capability, or an omission that loses its reason, breaks
//! here. The newest surface, the TUI, is additionally GROUNDED by driving it --
//! a doc row is a claim, a key press that changes the view is proof.

#![cfg(feature = "tui")]

use crossterm::event::KeyCode;
use sipnab::tui::{App, RelayStatsMode, View};

const SPEC: &str = include_str!("../docs/design/relay-statistics-surfaces.md");
const SURFACES: [&str; 4] = ["CLI", "REST", "MCP", "TUI"];
const CAPABILITIES: [&str; 5] = ["C1", "C2", "C3", "C4", "C5"];

/// The spelling the spec gives `surface` under capability section `cap` (e.g.
/// `C5`), read from the `| Surface | Spelling |` table that follows the
/// `### C5 …` heading. `None` if the row is missing entirely.
fn spelling(cap: &str, surface: &str) -> Option<String> {
    let heading = format!("### {cap} ");
    let start = SPEC
        .find(&heading)
        .unwrap_or_else(|| panic!("no `{heading}` section in the spec"));
    // The section runs to the next `### ` capability heading (or a `## ` one).
    let rest = &SPEC[start + heading.len()..];
    let end = rest
        .find("\n### ")
        .or_else(|| rest.find("\n## "))
        .unwrap_or(rest.len());
    let section = &rest[..end];
    let prefix = format!("| {surface} | ");
    section.lines().find(|l| l.starts_with(&prefix)).map(|l| {
        l.trim_start_matches(&prefix)
            .trim_end_matches(" |")
            .trim()
            .to_string()
    })
}

/// Every capability names every surface, and only C5/REST and C5/MCP are the
/// deliberate omissions ("not offered"), each with its reason still in the doc.
#[test]
fn the_capability_matrix_is_complete_and_c5_omissions_are_reasoned() {
    for cap in CAPABILITIES {
        for surface in SURFACES {
            let cell = spelling(cap, surface)
                .unwrap_or_else(|| panic!("{cap} has no {surface} row in the surfaces spec"));
            assert!(!cell.is_empty(), "{cap}/{surface} row is empty");

            let omitted = cell.eq_ignore_ascii_case("not offered");
            let is_c5_rest_or_mcp = cap == "C5" && (surface == "REST" || surface == "MCP");
            assert_eq!(
                omitted, is_c5_rest_or_mcp,
                "the ONLY omissions are C5 on REST and MCP; {cap}/{surface} = {cell:?}"
            );
        }
    }

    // The omission is a decision, not an accident: its reason must stay in the
    // doc. Remove this sentence and the test fails, which is the point.
    assert!(
        SPEC.contains("REST and MCP deliberately omit it, and here is why."),
        "C5's omission lost its reason; an omission with no reason is indistinguishable \
         from a capability someone forgot"
    );
    assert!(
        SPEC.contains("A poll is a standing\ninstruction to transmit")
            || SPEC.contains("A poll is a standing instruction to transmit"),
        "the reason must actually explain the omission, not merely assert one"
    );
}

/// No surface introduces a BARE `stats` spelling for the relay capability: the
/// command, path or tool a caller reaches for carries the word `relay`, so it
/// never collides with the four things already called "statistics" that are
/// about sipnab (ST-S3's naming decision). Checked on CLI/REST/MCP, whose cells
/// are the literal spellings; the TUI cell is prose describing keys.
#[test]
fn no_surface_introduces_a_bare_stats_spelling() {
    for cap in CAPABILITIES {
        for surface in ["CLI", "REST", "MCP"] {
            let cell = spelling(cap, surface).unwrap();
            if cell.eq_ignore_ascii_case("not offered") {
                continue;
            }
            assert!(
                cell.to_ascii_lowercase().contains("relay"),
                "{cap}/{surface} spelling {cell:?} must carry `relay`, never a bare `stats`"
            );
        }
    }
}

/// The TUI surface is real, not just a row in the doc: `S` from the call list
/// opens the relay-stats view (C1), and `?` within it shows the names the relay
/// knows (C3) -- the two capabilities reachable without a loaded call. C2, C4
/// and C5 are grounded in `tui_state_test` and `tui_relay_stats_test`.
#[test]
fn the_tui_cells_are_backed_by_a_real_view() {
    let mut app = App::new_test();
    app.handle_key(KeyCode::Char('S'));
    assert_eq!(
        *app.current_view(),
        View::RelayStats {
            call_id: None,
            mode: RelayStatsMode::Counters,
        },
        "C1: S opens the relay-stats view"
    );
    app.handle_key(KeyCode::Char('?'));
    assert_eq!(
        *app.current_view(),
        View::RelayStats {
            call_id: None,
            mode: RelayStatsMode::Names,
        },
        "C3: ? shows the names the relay knows"
    );
}
