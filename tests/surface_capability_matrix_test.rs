// SPDX-License-Identifier: MIT OR Apache-2.0

//! Surface-capability JOIN (PAR2): the parity gate over the authored matrix.
//!
//! PAR1 lists what exists on each surface separately
//! (`docs/design/surface-capability-inventory.md`, kept current by
//! `capability_matrix_test.rs`). PAR2's matrix
//! (`docs/design/surface-capability-matrix.md`) is the JOIN: one capability per
//! row, and for each of CLI/TUI/REST/MCP either the spelling that reaches it or
//! a recorded reason it is absent, per `docs/design/surface-parity-definition.md`.
//!
//! This gate holds that matrix honest against the inventory:
//!   - every `present` spelling is a real inventory item (no invented JOIN),
//!   - every MCP tool is claimed by exactly one capability (the anchor is
//!     complete -- a tool with no row is a capability nobody joined),
//!   - every REST route and TUI view is claimed or declared operational,
//!   - every absence carries a reason (a gap or a decision, never a blank), and
//!     MCP -- the anchor -- is never itself a gap,
//!   - the gap count matches a ledger, so closing one is a deliberate edit and
//!     opening one is visible.
//!
//! The inventory sets are read from the generated inventory doc rather than
//! re-derived from source, because `capability_matrix_test.rs` already holds
//! that doc to the program; this gate builds on that guarantee instead of
//! duplicating the four scans.

#![cfg(feature = "full")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const INVENTORY: &str = "docs/design/surface-capability-inventory.md";
const MATRIX: &str = "docs/design/surface-capability-matrix.md";

/// The number of `gap:` cells the matrix names. A gap is a capability that
/// passes a surface's question but is not built there yet. Closing one means
/// flipping its cell to a present spelling and decrementing this; opening one
/// (PAR2 naming a new hole) means raising it and adding the hole to PAR3/4/5.
const EXPECTED_GAPS: usize = 19;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read(rel: &str) -> String {
    let p = root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Bullets `- `item`` under the inventory doc's `## <title> (...)` heading.
fn inventory(title_prefix: &str) -> BTreeSet<String> {
    let doc = read(INVENTORY);
    let mut out = BTreeSet::new();
    let mut inside = false;
    for line in doc.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            inside = h.starts_with(title_prefix);
            continue;
        }
        if inside
            && let Some(rest) = line.strip_prefix("- `")
            && let Some(end) = rest.find('`')
        {
            out.insert(rest[..end].to_string());
        }
    }
    out
}

/// Every backtick-quoted token in a string.
fn backticks(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(a) = rest.find('`') {
        rest = &rest[a + 1..];
        if let Some(b) = rest.find('`') {
            out.push(rest[..b].to_string());
            rest = &rest[b + 1..];
        } else {
            break;
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Present,
    Gap,
    Decision,
}

struct Cell {
    detail: String,
}

impl Cell {
    fn status(&self) -> Status {
        let low = self.detail.trim().to_lowercase();
        if low.starts_with("gap:") {
            Status::Gap
        } else if low.starts_with("decision:") {
            Status::Decision
        } else {
            Status::Present
        }
    }

    /// The reason after a `gap:` / `decision:` marker, empty when present.
    fn reason(&self) -> &str {
        let d = self.detail.trim();
        match self.status() {
            Status::Gap => d[4..].trim(),
            Status::Decision => d[9..].trim(),
            Status::Present => "",
        }
    }
}

struct Capability {
    name: String,
    cli: Cell,
    tui: Cell,
    rest: Cell,
    mcp: Cell,
}

impl Capability {
    fn cells(&self) -> [(&'static str, &Cell); 4] {
        [
            ("CLI", &self.cli),
            ("TUI", &self.tui),
            ("REST", &self.rest),
            ("MCP", &self.mcp),
        ]
    }
}

/// The `## Capabilities` block, one Capability per `### ` section.
fn capabilities() -> Vec<Capability> {
    let doc = read(MATRIX);
    let start = doc
        .find("\n## Capabilities")
        .expect("matrix has no `## Capabilities` heading");
    let block = &doc[start..];
    let mut caps = Vec::new();
    for section in block.split("\n### ").skip(1) {
        let name = section
            .lines()
            .next()
            .expect("capability section has no heading")
            .trim()
            .to_string();
        let mut cli = None;
        let mut tui = None;
        let mut rest = None;
        let mut mcp = None;
        for line in section.lines() {
            let l = line.trim();
            if !l.starts_with('|') {
                continue;
            }
            let cols: Vec<&str> = l.trim_matches('|').split('|').map(str::trim).collect();
            if cols.len() != 2 {
                continue;
            }
            let cell = Cell {
                detail: cols[1].to_string(),
            };
            match cols[0] {
                "CLI" => cli = Some(cell),
                "TUI" => tui = Some(cell),
                "REST" => rest = Some(cell),
                "MCP" => mcp = Some(cell),
                _ => {}
            }
        }
        caps.push(Capability {
            cli: cli.unwrap_or_else(|| panic!("capability `{name}` has no CLI row")),
            tui: tui.unwrap_or_else(|| panic!("capability `{name}` has no TUI row")),
            rest: rest.unwrap_or_else(|| panic!("capability `{name}` has no REST row")),
            mcp: mcp.unwrap_or_else(|| panic!("capability `{name}` has no MCP row")),
            name,
        });
    }
    caps
}

/// Backticked tokens under an `### <subheading>` inside the operational block
/// (before `## Capabilities`), for the routes and views that carry no
/// capability but must still be accounted for.
fn operational_bullets(subheading: &str) -> BTreeSet<String> {
    let doc = read(MATRIX);
    let s = doc
        .find("## Operational routes and views")
        .expect("matrix has no operational section");
    let e = doc[s..]
        .find("\n## Capabilities")
        .map(|i| s + i)
        .unwrap_or(doc.len());
    let block = &doc[s..e];
    let mut out = BTreeSet::new();
    let mut inside = false;
    for line in block.lines() {
        if let Some(h) = line.strip_prefix("### ") {
            inside = h.starts_with(subheading);
            continue;
        }
        if inside {
            out.extend(backticks(line));
        }
    }
    out
}

#[test]
fn every_present_spelling_is_a_real_inventory_item() {
    let cli = inventory("CLI flags");
    let tui = inventory("TUI views");
    let rest = inventory("REST routes");
    let mcp = inventory("MCP tools");

    let mut bad = Vec::new();
    for c in capabilities() {
        if c.cli.status() == Status::Present {
            let flags: Vec<_> = backticks(&c.cli.detail)
                .into_iter()
                .filter(|t| t.starts_with("--"))
                .collect();
            if flags.is_empty() {
                bad.push(format!("{}: CLI present but names no `--flag`", c.name));
            }
            for f in flags {
                if !cli.contains(&f) {
                    bad.push(format!("{}: CLI `{f}` is not a real flag", c.name));
                }
            }
        }
        if c.rest.status() == Status::Present {
            let routes: Vec<_> = backticks(&c.rest.detail)
                .into_iter()
                .filter(|t| t.starts_with('/'))
                .collect();
            if routes.is_empty() {
                bad.push(format!("{}: REST present but names no `/route`", c.name));
            }
            for r in routes {
                if !rest.contains(&r) {
                    bad.push(format!("{}: REST `{r}` is not a real route", c.name));
                }
            }
        }
        if c.tui.status() == Status::Present
            && !backticks(&c.tui.detail).iter().any(|t| tui.contains(t))
        {
            bad.push(format!("{}: TUI present but names no real `View`", c.name));
        }
        if c.mcp.status() == Status::Present
            && !backticks(&c.mcp.detail).iter().any(|t| mcp.contains(t))
        {
            bad.push(format!("{}: MCP present but names no real tool", c.name));
        }
    }
    assert!(
        bad.is_empty(),
        "matrix spellings that are not real PAR1 inventory items:\n  {}",
        bad.join("\n  ")
    );
}

#[test]
fn every_mcp_tool_is_claimed_by_exactly_one_capability() {
    let mcp = inventory("MCP tools");
    let mut claimed: Vec<String> = Vec::new();
    for c in capabilities() {
        if c.mcp.status() == Status::Present {
            for t in backticks(&c.mcp.detail) {
                if mcp.contains(&t) {
                    claimed.push(t);
                }
            }
        }
    }

    let mut seen = BTreeSet::new();
    let mut dups = BTreeSet::new();
    for t in &claimed {
        if !seen.insert(t.clone()) {
            dups.insert(t.clone());
        }
    }
    let missing: Vec<_> = mcp.difference(&seen).cloned().collect();

    assert!(
        dups.is_empty(),
        "MCP tools claimed by more than one capability: {}",
        dups.into_iter().collect::<Vec<_>>().join(", ")
    );
    assert!(
        missing.is_empty(),
        "MCP tools no capability claims ({}): {}\nEvery agent tool is a capability; give it a row or fold it into one.",
        missing.len(),
        missing.join(", ")
    );
    assert!(
        seen.len() >= 60,
        "only {} MCP tools claimed; the anchor scan has stopped working",
        seen.len()
    );
}

#[test]
fn every_rest_route_and_tui_view_is_claimed_or_operational() {
    let rest = inventory("REST routes");
    let tui = inventory("TUI views");

    let mut claimed_rest: BTreeSet<String> = operational_bullets("Operational REST routes")
        .into_iter()
        .filter(|t| t.starts_with('/'))
        .collect();
    let mut claimed_tui: BTreeSet<String> = operational_bullets("Operational TUI views")
        .into_iter()
        .filter(|t| tui.contains(t))
        .collect();

    for c in capabilities() {
        if c.rest.status() == Status::Present {
            for t in backticks(&c.rest.detail) {
                if t.starts_with('/') {
                    claimed_rest.insert(t);
                }
            }
        }
        if c.tui.status() == Status::Present {
            for t in backticks(&c.tui.detail) {
                if tui.contains(&t) {
                    claimed_tui.insert(t);
                }
            }
        }
    }

    let rest_missing: Vec<_> = rest.difference(&claimed_rest).cloned().collect();
    let tui_missing: Vec<_> = tui.difference(&claimed_tui).cloned().collect();
    assert!(
        rest_missing.is_empty(),
        "REST routes no capability claims and not declared operational ({}): {}",
        rest_missing.len(),
        rest_missing.join(", ")
    );
    assert!(
        tui_missing.is_empty(),
        "TUI views no capability claims and not declared operational ({}): {}",
        tui_missing.len(),
        tui_missing.join(", ")
    );
}

#[test]
fn every_absence_carries_a_reason() {
    let mut bad = Vec::new();
    for c in capabilities() {
        for (surface, cell) in c.cells() {
            match cell.status() {
                Status::Gap => {
                    if surface == "MCP" {
                        bad.push(format!(
                            "{}: MCP is the anchor and can never be a gap",
                            c.name
                        ));
                    }
                    if cell.reason().len() < 12 {
                        bad.push(format!("{}: {surface} gap has no real reason", c.name));
                    }
                }
                Status::Decision => {
                    if cell.reason().len() < 12 {
                        bad.push(format!("{}: {surface} decision has no real reason", c.name));
                    }
                }
                Status::Present => {}
            }
        }
    }
    assert!(
        bad.is_empty(),
        "absences without a recorded reason (a gap or decision must say why):\n  {}",
        bad.join("\n  ")
    );
}

#[test]
fn the_gap_count_matches_the_ledger() {
    let gaps = capabilities()
        .iter()
        .flat_map(|c| c.cells())
        .filter(|(_, cell)| cell.status() == Status::Gap)
        .count();
    assert_eq!(
        gaps, EXPECTED_GAPS,
        "the matrix names {gaps} gaps but the ledger (EXPECTED_GAPS) expects \
         {EXPECTED_GAPS}. Closing a gap means flipping its cell to a present \
         spelling and decrementing this. A NEW gap means PAR2 named a hole \
         PAR3/PAR4/PAR5 must close -- raise this and add it to the plan."
    );
}

#[test]
fn the_matrix_is_not_vacuous() {
    let caps = capabilities();
    assert!(
        caps.len() >= 45,
        "only {} capabilities parsed; the matrix reader has stopped working",
        caps.len()
    );

    let mut present = [0usize; 4];
    for c in &caps {
        for (i, (_, cell)) in c.cells().into_iter().enumerate() {
            if cell.status() == Status::Present {
                present[i] += 1;
            }
        }
    }
    assert!(
        present[0] >= 10,
        "CLI present on only {} capabilities",
        present[0]
    );
    assert!(
        present[1] >= 10,
        "TUI present on only {} capabilities",
        present[1]
    );
    assert!(
        present[2] >= 10,
        "REST present on only {} capabilities",
        present[2]
    );
    assert!(
        present[3] >= 40,
        "MCP present on only {} capabilities",
        present[3]
    );
}
