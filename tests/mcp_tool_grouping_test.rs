// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every MCP tool sits under exactly one group in the reference.
//!
//! # Why this file exists
//!
//! `docs/mcp-tools.md` was a flat run of 51 `###` tool sections under no
//! organizing heading at all, ordered by the accident of when each tool was
//! added. The tools were individually well documented; nothing told a reader
//! which one to reach for. Someone arriving with a task -- "which tool tells me
//! why this call failed", "how do I get the bytes back" -- had to read all of
//! them to find out.
//!
//! The page is now grouped by the reader's question rather than by subsystem.
//! "HEP tools", "RTP tools", "vCon tools" would have described sipnab's
//! internals instead, which is how a reference becomes a table of contents for
//! the code.
//!
//! # What this gate is for
//!
//! A grouping is only useful while it is complete, and the failure mode is
//! silent: a tool lands in `src/mcp/`, gets its own `###` section appended
//! wherever the diff was easiest, and belongs to whatever group happens to
//! precede it. Nothing looks wrong. The reference simply stops being a map.
//!
//! `docs_drift_test` already pins the page against the registered tool set, so
//! a tool with no section at all is caught. This adds the half that was
//! missing: a tool with a section but no group, and a tool that has somehow
//! landed in two.
//!
//! The grouping also has a second job, which is why it is worth gating rather
//! than just writing. Read the groups and the gaps are legible: *Export and
//! handoff* carries exactly one vCon tool against six vCon flags on the CLI,
//! and no group contains a media-relay tool at all while `src/rtpengine/`
//! carries `Reconciler`, `Attribution`, `RelayLink` and `OrphanSink`. Flat,
//! a missing tool looks like every other tool that is not there. Grouped, it
//! is an empty shelf.

#![cfg(feature = "full")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every tool name registered under `src/mcp/`.
///
/// Derived from the source, never hand-listed, for the reason the walk in
/// `site_journey_test` exists: a fixed list cannot notice a new member, which
/// is the one thing this gate is for.
fn registered_tools() -> BTreeSet<String> {
    let re = regex::Regex::new(r#"(?m)^\s+name = "([a-z0-9_]+)","#).expect("pattern compiles");
    let mut out = BTreeSet::new();
    let mut stack = vec![repo().join("src/mcp")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let src = std::fs::read_to_string(&p).unwrap_or_default();
                for c in re.captures_iter(&src) {
                    out.insert(c[1].to_string());
                }
            }
        }
    }
    out
}

/// `tool name -> the `##` groups it appears under` in the reference.
///
/// Headings inside fenced code blocks are skipped. The page renders a sample
/// call report that contains `## Summary`, `## Timing`, `## Media Streams` and
/// `## Issues`; counting those as groups would put ten tools in a section
/// called "Timing".
fn tool_groups() -> BTreeMap<String, Vec<String>> {
    let src = std::fs::read_to_string(repo().join("docs/mcp-tools.md"))
        .expect("docs/mcp-tools.md is readable");
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut group: Option<String> = None;
    let mut in_fence = false;
    for line in src.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if let Some(rest) = line.strip_prefix("## ") {
            group = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("### ") {
            let t = rest.trim();
            if let Some(name) = t.strip_prefix('`').and_then(|s| s.strip_suffix('`'))
                && let Some(g) = &group
            {
                out.entry(name.to_string()).or_default().push(g.clone());
            }
        }
    }
    out
}

/// The scanners see a real page and a real tool set.
///
/// Both rules below are `is_empty()` assertions over derived collections, and
/// both are vacuously true if either derivation returns nothing.
#[test]
fn the_grouping_scanners_read_a_real_page_and_a_real_tool_set() {
    let tools = registered_tools();
    assert!(
        tools.len() >= 40,
        "found only {} registered MCP tool(s); the registration pattern has \
         stopped matching and every rule below proves nothing",
        tools.len()
    );
    let grouped = tool_groups();
    assert!(
        grouped.len() >= 40,
        "found only {} tool section(s) under a group heading in \
         docs/mcp-tools.md; the heading scan is not matching the page",
        grouped.len()
    );
}

/// Every registered tool appears under exactly one group.
///
/// The gate proper. A tool documented outside any `##` group is invisible to a
/// reader navigating by question, and a tool under two is a reference
/// disagreeing with itself about what the tool is for.
#[test]
fn every_registered_tool_is_in_exactly_one_group() {
    let tools = registered_tools();
    let grouped = tool_groups();

    let ungrouped: Vec<&String> = tools.iter().filter(|t| !grouped.contains_key(*t)).collect();
    assert!(
        ungrouped.is_empty(),
        "these registered tools have no section under any group heading in \
         docs/mcp-tools.md: {ungrouped:?}\n\nA tool outside every group cannot \
         be found by a reader navigating by question, and the page reverts to \
         the flat list this grouping replaced."
    );

    let doubled: Vec<String> = grouped
        .iter()
        .filter(|(_, gs)| gs.len() > 1)
        .map(|(t, gs)| format!("{t} in {gs:?}"))
        .collect();
    assert!(
        doubled.is_empty(),
        "these tools appear under more than one group: {doubled:?}\n\nThe \
         groups answer \"which tool do I reach for\", and a tool in two places \
         means the page has two answers."
    );
}

/// Every documented tool is a tool that exists.
///
/// The other direction. A `###` section under a group naming something no
/// longer registered is a reader following a map to a tool the server will
/// refuse.
#[test]
fn every_grouped_tool_is_actually_registered() {
    let tools = registered_tools();
    let grouped = tool_groups();
    let stale: Vec<&String> = grouped.keys().filter(|t| !tools.contains(*t)).collect();
    assert!(
        stale.is_empty(),
        "docs/mcp-tools.md groups these tools, and `src/mcp/` registers none \
         of them: {stale:?}"
    );
}

/// The groups are phrased as questions, not as subsystems.
///
/// The rule that keeps the grouping useful as tools are added. The tempting
/// move when a relay tool lands is a "Relay tools" heading beside it, and that
/// is how a task-oriented reference turns back into a table of contents for
/// the code. Named subsystems are refused explicitly rather than left to
/// judgement.
#[test]
fn no_group_is_named_after_a_subsystem() {
    let groups: BTreeSet<String> = tool_groups().values().flatten().cloned().collect();
    assert!(!groups.is_empty(), "no groups found at all");
    for g in &groups {
        let lower = g.to_ascii_lowercase();
        for subsystem in ["hep", "rtpengine", "rtpproxy", "vcon", "tui", "wasm", "bpf"] {
            assert!(
                !lower.contains(subsystem),
                "the group {g:?} is named after a subsystem. Groups answer the \
                 reader's question -- what they are trying to find out -- not \
                 which part of sipnab implements the answer."
            );
        }
    }
}

/// Every group holds at least one tool.
///
/// An empty group is a heading a reader scans past and a promise the page does
/// not keep. It is also what a careless removal leaves behind.
#[test]
fn no_group_is_empty() {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for gs in tool_groups().values() {
        for g in gs {
            *counts.entry(g.clone()).or_default() += 1;
        }
    }
    assert!(
        counts.len() >= 5,
        "only {} group(s) carry any tool; the page has lost its structure",
        counts.len()
    );
    let empty: Vec<&String> = counts
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(g, _)| g)
        .collect();
    assert!(empty.is_empty(), "these groups hold no tools: {empty:?}");
}

/// The reference carries exactly the groups it is supposed to.
///
/// The rule above cannot see a deleted heading: removing `## Security` merges
/// its two tools into whatever group precedes them, and every tool is still in
/// exactly one group. A mutation survived on precisely that.
///
/// So the group NAMES are pinned, and they are the one thing here that is
/// hand-listed. That is deliberate and it is the opposite of the tool list: the
/// tools are derived because a new one must be noticed automatically, while the
/// groups are editorial and a change to them should be a decision someone
/// makes and records, not a diff that slips through. Adding a ninth group is
/// fine; adding it here at the same time is the cost.
#[test]
fn the_reference_carries_exactly_the_expected_groups() {
    const EXPECTED_GROUPS: &[&str] = &[
        "Survey — what is in this capture",
        "Find — narrow to the calls that matter",
        "Diagnose one call",
        "Conformance and rules",
        "Security",
        "Evidence and provenance",
        "Export and handoff",
        "Capture control (opt-in, off by default)",
    ];
    let found: BTreeSet<String> = tool_groups().values().flatten().cloned().collect();
    let expected: BTreeSet<String> = EXPECTED_GROUPS.iter().map(|s| (*s).to_string()).collect();

    let missing: Vec<&String> = expected.difference(&found).collect();
    assert!(
        missing.is_empty(),
        "these groups are gone from docs/mcp-tools.md: {missing:?}\n\nDeleting \
         a heading does not orphan its tools -- it silently moves them into the \
         group above, where a reader looking for them will not think to look."
    );
    let extra: Vec<&String> = found.difference(&expected).collect();
    assert!(
        extra.is_empty(),
        "these groups are new: {extra:?}\n\nIf the surface really needs another \
         group, add it to EXPECTED_GROUPS in the same change. Groups answer the \
         reader's question, so a new one is an editorial decision worth making \
         on purpose."
    );
}
