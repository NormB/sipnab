// SPDX-License-Identifier: MIT OR Apache-2.0

//! A claim that something is not checked must itself be checked.
//!
//! # The defect this file exists for
//!
//! Asked to close the window between "a release is tagged with assets" and
//! "the site advertises it", I said nothing caught that state and started
//! building a gate for it. Nothing was missing.
//! `release_completeness_test::the_site_advertises_the_newest_release_whose_assets_exist`
//! does exactly that job, refuses to skip silently, and had already failed on
//! me earlier the same day at the 0.5.130 tag commit.
//!
//! One `grep` would have shown that. What I nearly shipped was a second gate
//! asserting the same property — and a duplicate gate is worse than no gate:
//! it doubles the maintenance, and when the two drift apart the tree gets an
//! argument with itself that neither side can win.
//!
//! The class is broader than one mistake. **An assertion of absence is the
//! easiest kind of claim to make and the easiest to get wrong**, because
//! nothing pushes back — a gate you did not find looks identical to a gate
//! that is not there. This repository is full of such claims, in test doc
//! comments and backlog entries, and every one is load-bearing: they justify
//! building things.
//!
//! So the rules here are:
//!
//! - a cross-reference to another test must resolve to a test that exists;
//! - no two tests may share a name, which is what a duplicated gate looks
//!   like from the outside;
//! - a written claim that something is ungated must name what was searched,
//!   so a reader can repeat the search rather than trust the claim.

#![cfg(feature = "full")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[path = "support/absence_scan.rs"]
mod absence_scan;

use absence_scan::{
    ABSENCE_PHRASES, cross_reference, defines, implausible_coincidence, ratchet_pins, test_bodies,
    test_fns,
};

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file directly under `tests/`, excluding shared support modules.
///
/// Support modules are compiled into several binaries, so a function defined
/// once there legitimately appears in many — counting them would report every
/// helper as a duplicate.
fn test_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dir = repo().join("tests");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// Read a file, or the empty string.
fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Every `some_test::some_fn` cross-reference appearing in prose or code.
///
/// These are the claims most likely to rot: a test gets renamed and the
/// sentence pointing at it keeps its old name, which reads as authoritative
/// and sends the next reader looking for something that is not there.
///
/// The decision about any one token lives in [`cross_reference`], driven from
/// both sides by `scanner_calibration_test`. This function only supplies it
/// with the real tree.
fn cross_references() -> Vec<(String, String, String)> {
    let exists = |left: &str| repo().join("tests").join(format!("{left}.rs")).exists();
    let mut out = Vec::new();
    for path in test_files() {
        let src = read(&path);
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        for token in src.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':')) {
            if let Some((left, right)) = cross_reference(token, &exists) {
                out.push((file.clone(), left, right));
            }
        }
    }
    out
}

// ── A. cross-references must resolve ────────────────────────────────

/// The cross-reference scanner found real references.
///
/// Every rule below reads what this returns. A scanner that matched nothing
/// would report a perfectly consistent tree.
#[test]
fn the_cross_reference_scanner_reads_real_references() {
    let refs = cross_references();
    assert!(
        refs.len() >= 3,
        "found only {} `some_test::some_fn` reference(s) across {} test \
         file(s); the scanner has stopped matching and the rule below proves \
         nothing",
        refs.len(),
        test_files().len()
    );
}

/// Every test named in a cross-reference exists.
///
/// The mechanical half of the defect: a sentence that names a gate is a claim
/// about the tree, and a renamed test turns it into a confident wrong answer.
#[test]
fn every_test_named_in_a_cross_reference_exists() {
    // Build the name index once, across every test binary.
    let mut known: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in test_files() {
        let file = path.file_stem().unwrap().to_string_lossy().to_string();
        for f in test_fns(&read(&path)) {
            known.entry(f).or_default().push(file.clone());
        }
    }
    let mut broken = Vec::new();
    for (from, target_file, target_fn) in cross_references() {
        let Some(files) = known.get(&target_fn) else {
            broken.push(format!(
                "  {from} names {target_file}::{target_fn}, which is not a \
                 test anywhere in tests/"
            ));
            continue;
        };
        if !files.iter().any(|f| f == &target_file) {
            broken.push(format!(
                "  {from} names {target_file}::{target_fn}, but that test \
                 lives in {files:?}"
            ));
        }
    }
    assert!(
        broken.is_empty(),
        "cross-references that do not resolve:\n{}\n\nA sentence naming a gate \
         is a claim about the tree. When it is wrong it reads as authoritative \
         and sends the next reader looking for something that moved.",
        broken.join("\n")
    );
}

/// The gate the pre-push hook points at exists and can fire.
///
/// The hook now prints a phase-two reminder naming
/// `the_site_advertises_the_newest_release_whose_assets_exist`. If that test
/// were renamed the reminder would send an operator to a gate that is not
/// there, at exactly the moment they are trying to finish a release.
#[test]
fn the_gate_the_pre_push_prompt_names_exists() {
    let hook = read(&repo().join(".githooks/pre-push"));
    assert!(
        !hook.is_empty(),
        ".githooks/pre-push is missing or unreadable"
    );
    let named = "the_site_advertises_the_newest_release_whose_assets_exist";
    if !hook.contains(named) {
        // The prompt may legitimately be reworded; what must not happen is it
        // naming something that does not exist. Nothing to check here.
        return;
    }
    let completeness = read(&repo().join("tests/release_completeness_test.rs"));
    assert!(
        completeness.contains(&format!("fn {named}")),
        "the pre-push prompt names {named}, which release_completeness_test no \
         longer defines"
    );
}

// ── B. a duplicated gate is what a missed grep produces ─────────────

/// The test-name index reads the whole tree.
#[test]
fn the_test_name_scanner_reads_the_whole_tree() {
    let files = test_files();
    assert!(
        files.len() >= 40,
        "found only {} file(s) under tests/; the walk is not reaching them",
        files.len()
    );
    let total: usize = files.iter().map(|p| test_fns(&read(p)).len()).sum();
    assert!(
        total >= 500,
        "extracted only {total} `#[test]` function(s); the extractor has \
         stopped matching and the duplicate rule below would pass by \
         examining nothing"
    );
}

/// No two tests share a name AND a body.
///
/// A shared name alone is not a defect and demanding otherwise would make the
/// tree worse: `expired_signed_token_is_rejected` exists in both
/// `api_token_test` and `mcp_token_test` because the REST and MCP surfaces
/// each have to refuse an expired token, and renaming either would lose that
/// symmetry. This doc comment first said there were five such pairs; nothing
/// had counted them, and there are eight. That the count is not pinned here is
/// deliberate — `scanner_calibration_test` asserts the property instead, that
/// every name shared across files carries a DIFFERENT body.
///
/// A shared name AND a matching body is the real thing: one property asserted
/// twice, which is what a gate built without grepping produces. It doubles the
/// maintenance and, when the copies drift, gives the tree an argument with
/// itself that neither side can win.
#[test]
fn no_two_tests_share_a_name_and_a_body() {
    let mut seen: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for path in test_files() {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let src = read(&path);
        for (name, body) in test_bodies(&src) {
            seen.entry((name, body)).or_default().push(file.clone());
        }
    }
    let dupes: Vec<String> = seen
        .iter()
        .filter(|(_, files)| files.len() > 1)
        .map(|((name, _), files)| format!("  {name} in {files:?}"))
        .collect();
    assert!(
        dupes.is_empty(),
        "these tests are defined identically in more than one file:\n{}\n\nOne \
         property asserted twice is what a gate built without grepping looks \
         like from the outside.",
        dupes.join("\n")
    );
}

/// A ratchet constant is pinned in exactly one place.
///
/// The same failure in a different costume. Two files pinning
/// `EXPECTED_TABLES` would both have to be moved together, and whichever is
/// forgotten becomes a gate asserting a number nobody maintains.
#[test]
fn no_ratchet_constant_is_pinned_in_two_files() {
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in test_files() {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        for (name, value) in ratchet_pins(&read(&path)) {
            seen.entry(format!("{name} = {value}"))
                .or_default()
                .push(file.clone());
        }
    }
    assert!(
        !seen.is_empty(),
        "no EXPECTED_* ratchet constants found at all; the scanner is not \
         matching the form this repository uses"
    );
    let dupes: Vec<String> = seen
        .iter()
        .filter(|(_, files)| files.len() > 1)
        .filter(|(key, _)| key.rsplit("= ").next().is_some_and(implausible_coincidence))
        .map(|(name, files)| format!("  {name} in {files:?}"))
        .collect();
    assert!(
        dupes.is_empty(),
        "these ratchet constants are pinned at the same large value in more \
         than one file:\n{}\n\nA number this size arrived at twice \
         independently is a copy, and whichever copy is forgotten becomes a \
         gate asserting a figure nobody maintains.",
        dupes.join("\n")
    );
}

// ── C. claims of absence must name what was searched ────────────────

/// The absence-claim scanner finds real claims.
#[test]
fn the_absence_claim_scanner_finds_real_claims() {
    let mut count = 0usize;
    for path in test_files() {
        let src = read(&path).to_ascii_lowercase();
        for phrase in ABSENCE_PHRASES {
            count += src.matches(phrase).count();
        }
    }
    assert!(
        count >= 3,
        "found only {count} claim(s) of absence across the test tree; either \
         the phrase list has stopped matching how this repository writes them, \
         or the rule below is checking nothing"
    );
}

/// No claim of absence names a gate that exists.
///
/// The direct guard for the defect. If a comment says "nothing gates the
/// site advertising a release" while a test named for that property exists,
/// the comment is wrong and someone is about to build a duplicate.
///
/// Matched conservatively: the claim must name a specific test that exists.
/// A prose claim with no name is caught by the rule below instead.
#[test]
fn no_claim_of_absence_names_a_test_that_exists() {
    let mut known: Vec<String> = Vec::new();
    for path in test_files() {
        known.extend(test_fns(&read(&path)));
    }
    let mut wrong = Vec::new();
    for path in test_files() {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        for line in read(&path).lines() {
            let lower = line.to_ascii_lowercase();
            if !ABSENCE_PHRASES.iter().any(|p| lower.contains(p)) {
                continue;
            }
            for name in &known {
                if name.len() > 20 && line.contains(name.as_str()) {
                    wrong.push(format!(
                        "  {file}: claims absence while naming {name}, which \
                         exists"
                    ));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "claims of absence that name something present:\n{}",
        wrong.join("\n")
    );
}

/// The delivery gates still cover the tagged-but-unadvertised state.
///
/// Named explicitly so that deleting the real gate is a visible act rather
/// than a quiet narrowing — and so a future reader tempted to build a second
/// one finds this pointing at the first.
#[test]
fn the_tagged_but_unadvertised_state_is_covered_exactly_once() {
    let completeness = read(&repo().join("tests/release_completeness_test.rs"));
    let named = "fn the_site_advertises_the_newest_release_whose_assets_exist";
    assert!(
        completeness.contains(named),
        "release_completeness_test no longer covers the state where a tag has \
         published assets and the site still advertises the previous release. \
         That window is where 0.5.128 shipped to nobody."
    );
    // And exactly once, across the whole tree.
    // Definitions, not mentions: this very file names the gate several times
    // in prose, and counting occurrences reported it as defined four times.
    let defs: usize = test_files()
        .iter()
        .map(|p| {
            defines(
                &read(p),
                "the_site_advertises_the_newest_release_whose_assets_exist",
            )
        })
        .sum();
    assert_eq!(
        defs, 1,
        "that gate is defined {defs} times; a second copy is the duplicate \
         this file exists to prevent"
    );
}

/// The gate that covers it actually asserts the site version.
///
/// Naming a gate is not the same as the gate doing the job. This reads the
/// body and requires it to compare `published_version` against the tag,
/// because a test could keep its name while its assertion was hollowed out.
#[test]
fn the_advertisement_gate_still_compares_the_site_to_the_tag() {
    let src = read(&repo().join("tests/release_completeness_test.rs"));
    let start = src
        .find("fn the_site_advertises_the_newest_release_whose_assets_exist")
        .expect("the gate exists");
    let body = &src[start..];
    let end = body.find("\n}\n").map_or(body.len(), |i| i + 3);
    let body = &body[..end];
    // Operand position, not mere presence. Checking `contains` was too weak:
    // replacing the compared value with `String::new()` left the call in the
    // failure message, so the string was still there and this passed. A
    // mutation survived on exactly that, which is why the check now looks at
    // where the call sits rather than whether it occurs.
    let cmp = body
        .find("assert_eq!")
        .map(|i| &body[i..])
        .expect("the gate compares something");
    let first_literal = cmp.find('"').unwrap_or(cmp.len());
    let operands = &cmp[..first_literal];
    assert!(
        operands.contains("published_version()"),
        "the gate no longer COMPARES published_version -- it appears only in \
         the message, if at all. It can no longer tell whether the site moved:\n\
         {operands}"
    );
    assert!(
        body.contains("assert_eq!"),
        "the gate no longer compares anything; it would pass whatever the site \
         advertises"
    );
    assert!(
        body.contains("assets"),
        "the gate no longer considers whether assets exist, so it would demand \
         the site advertise a release nobody can download"
    );
}
