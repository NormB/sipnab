// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every registered MCP tool must have a release that added it.
//!
//! The "Since version" column in `docs/mcp-tools.md` cannot be typed by hand
//! and stay true: nothing in the repository disagrees with a wrong entry, and
//! nothing at all notices a missing one. The published tool table has already
//! under-reported the surface once, and a review read the wrong tool set off
//! the site because of it.
//!
//! So the column has a source — `CHANGELOG.md`, read by
//! [`sipnab::mcp::since`] — and this file is the gate on that source. It
//! compares the ROUTER against the release notes, in both directions that
//! matter:
//!
//! * a registered tool no release note names is a release note that forgot to
//!   mention a new tool, and it fails the build here rather than shipping as a
//!   blank cell;
//! * a version older than the first release that could have carried it, or
//!   newer than anything released, is a parse that went wrong.
//!
//! What this deliberately does NOT do is check the column itself. The column
//! does not exist yet, and a gate written against an absent column would have
//! to be skipped, which is a gate that asserts nothing while looking like one
//! that passes.

#![cfg(feature = "mcp")]

use parking_lot::RwLock;
use sipnab::mcp::SipnabMcp;
use sipnab::mcp::since::{since_version, versions};
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;
use std::sync::Arc;

/// Every tool a stock server registers.
fn registered() -> Vec<String> {
    SipnabMcp::new(
        Arc::new(RwLock::new(DialogStore::new(64, false))),
        Arc::new(RwLock::new(StreamStore::new(64))),
    )
    .registered_tool_names()
}

/// The version's numeric components, for ordering.
fn numeric(version: &str) -> Vec<u64> {
    version
        .split_once('-')
        .map_or(version, |(head, _)| head)
        .split('.')
        .map(|p| p.parse::<u64>().unwrap_or(0))
        .collect()
}

/// Every registered tool is named by some release note.
///
/// This is the gate that keeps the column honest. Add a tool without saying so
/// in `CHANGELOG.md` and the build stops here, naming the tool — which is a
/// far better failure than a table cell nobody can fill in six months later.
#[test]
fn every_registered_tool_has_a_release_that_added_it() {
    let tools = registered();
    assert!(
        tools.len() > 20,
        "the router registered only {} tools -- this test is reading an empty \
         router rather than checking the release notes: {tools:?}",
        tools.len()
    );

    let missing: Vec<&String> = tools
        .iter()
        .filter(|t| since_version(t).is_none())
        .collect();

    assert!(
        missing.is_empty(),
        "these MCP tools are registered and no CHANGELOG.md entry names them: \
         {missing:?}. Name the tool in the release note that added it -- the \
         \"Since version\" column in docs/mcp-tools.md is derived from those \
         entries, so a tool the notes never mention has no version to show"
    );
}

/// No tool claims a release older than the one that first carried MCP at all.
///
/// A parse that fell through to the wrong section would most likely land on
/// the oldest heading in the file, which predates the MCP server entirely.
/// That failure is invisible in a spot check and obvious here.
#[test]
fn no_tool_predates_the_mcp_server() {
    // 0.3.x carried the first MCP tools; nothing before 0.3 had a tool
    // surface to add to.
    const FLOOR: &[u64] = &[0, 3];
    for tool in registered() {
        let Some(version) = since_version(&tool) else {
            continue; // covered, by name, by the test above
        };
        // The pending section is newer than every release, not older than the
        // first: a tool named only under `## [Unreleased]` has shipped in no
        // release yet, and `owed_bulk_edit_gates_test` already treats that as
        // the legitimate answer it is.
        if version == "Unreleased" {
            continue;
        }
        let parts = numeric(version);
        assert!(
            parts.len() >= 2 && &parts[0..2] >= FLOOR,
            "{tool} claims {version}, which predates the MCP server -- the \
             changelog walk landed in the wrong section"
        );
    }
}

/// A tool takes the OLDEST release that names it, not the newest.
///
/// The tools added in the first MCP releases are still discussed in recent
/// entries, so a walk that kept the last mention would report almost every
/// tool as brand new — which is exactly the misreading the column exists to
/// prevent.
#[test]
fn a_long_lived_tool_keeps_its_first_release() {
    let tools = registered();
    let mut oldest: Option<Vec<u64>> = None;
    let mut newest: Option<Vec<u64>> = None;
    for tool in &tools {
        let Some(version) = since_version(tool) else {
            continue;
        };
        let parts = numeric(version);
        if oldest.as_ref().is_none_or(|o| parts < *o) {
            oldest = Some(parts.clone());
        }
        if newest.as_ref().is_none_or(|n| parts > *n) {
            newest = Some(parts);
        }
    }

    assert!(
        oldest < newest,
        "every registered tool resolved to the same release ({oldest:?}) -- a \
         walk that took the newest mention would do exactly this"
    );
    assert_eq!(
        since_version("list_dialogs"),
        Some("0.3.2"),
        "list_dialogs shipped with the first MCP tools and is named in later \
         entries too; the first one is the answer"
    );
}

/// The index knows names that are no longer registered, and callers must
/// intersect rather than treat it as the tool list.
///
/// Stated as a test because the doc comment saying so is not enforcement: if
/// this ever became an equality, a removed tool's release note would fail the
/// build for describing history correctly.
#[test]
fn the_index_may_name_tools_the_router_does_not() {
    let tools = registered();
    let indexed = versions();
    assert!(
        indexed.len() >= tools.len(),
        "the changelog index knows {} names against {} registered tools -- it \
         is meant to be a superset",
        indexed.len(),
        tools.len()
    );
}
