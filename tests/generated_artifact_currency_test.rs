// SPDX-License-Identifier: MIT OR Apache-2.0

//! An artifact generated from the dependency graph goes stale when the graph
//! moves, and a batch of individually-green pull requests can still land red.
//!
//! # The defect this file exists for
//!
//! Five Dependabot pull requests merged in sequence. Every one was green.
//! `main` went red immediately on `third_party_notices_are_current`, in both
//! `CI` and `Quality`.
//!
//! Nothing was wrong with any single pull request. Each one's CI ran against a
//! dependency graph that did not yet contain the other four, so each was
//! honestly green about a combination that never existed. `THIRD-PARTY-NOTICES.md`
//! is generated from the graph, and the graph they produced together was one
//! no pull request had ever built.
//!
//! I then announced the release complete -- "0.5.137 live, `main` is the only
//! branch" -- without re-checking CI after the merges. The claim was true of
//! the tree I had tested and false of the tree that existed.
//!
//! # What is actually gated here
//!
//! `third_party_notices_are_current` already regenerates the file and compares
//! it, and it is what caught this. What it does not do is describe the CLASS,
//! so this file pins the surrounding facts a reader needs in order to trust it:
//!
//! - every artifact generated from the dependency graph is named, and its
//!   generator exists;
//! - the notices cover the crates the lockfile actually names, so a generator
//!   that silently produced a short file would not read as current;
//! - the dependency-bump exemption in the delivery gate does NOT cover those
//!   artifacts, so a bump that forgets the regeneration still has to declare
//!   itself;
//! - the file says how to regenerate it, in the file, where someone hitting the
//!   red gate will look.

#![cfg(feature = "full")]

use std::collections::BTreeSet;
use std::path::PathBuf;

#[path = "support/release_logic.rs"]
mod release_logic;

use release_logic::{DEPENDENCY_PATHS, dependency_path, is_dependency_bump};

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repository file, or the empty string.
fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_default()
}

/// Artifacts generated FROM the dependency graph, and what regenerates each.
///
/// A table rather than a walk: the property is not "this file is generated" —
/// plenty are — but "this file's content is a function of the dependency graph,
/// so bumping a dependency invalidates it". That is a judgement about the
/// generator's inputs, and it belongs in writing next to the consequence.
const GRAPH_DERIVED: &[(&str, &str)] = &[(
    "THIRD-PARTY-NOTICES.md",
    "scripts/build-third-party-notices.py",
)];

/// Every graph-derived artifact exists and its generator does too.
///
/// The floor. A table naming a file that is gone, or a generator that is gone,
/// reads as coverage and is a dangling promise: the gate that regenerates and
/// compares cannot run at all.
#[test]
fn every_graph_derived_artifact_has_a_generator_that_exists() {
    assert!(
        !GRAPH_DERIVED.is_empty(),
        "no graph-derived artifacts are named, so every rule below examines \
         nothing"
    );
    for (artifact, generator) in GRAPH_DERIVED {
        assert!(
            repo().join(artifact).is_file(),
            "{artifact} is named as generated from the dependency graph and is \
             not there"
        );
        assert!(
            repo().join(generator).is_file(),
            "{generator} regenerates {artifact} and is missing; the gate that \
             compares them cannot run, and a stale file would look current"
        );
    }
}

/// The artifact says how to regenerate it, in the artifact.
///
/// Whoever meets the red gate is looking at a diff of this file, not at the
/// test that failed. The instruction has to be where they are.
#[test]
fn the_artifact_names_its_own_generator() {
    for (artifact, generator) in GRAPH_DERIVED {
        let body = read(artifact);
        assert!(
            !body.is_empty(),
            "{artifact} is empty; nothing below is measuring anything"
        );
        assert!(
            body.contains(generator),
            "{artifact} does not name {generator} anywhere in it. A reader who \
             hits the staleness gate is looking at this file, and the fix is a \
             command they have to be told."
        );
    }
}

/// The notices cover the crates the lockfile names.
///
/// The half a regenerate-and-compare cannot give: comparing the file to a fresh
/// run proves they AGREE, not that either is complete. A generator that started
/// emitting half the graph would produce a file that matches itself perfectly.
///
/// Sampled rather than exhaustive, and the sample is the crates most likely to
/// be dropped by a scoping mistake: the direct dependencies this project names
/// in its own manifest.
#[test]
fn the_notices_cover_the_crates_the_lockfile_names() {
    let notices = read("THIRD-PARTY-NOTICES.md");
    let lock = read("Cargo.lock");
    assert!(
        notices.len() > 10_000 && lock.len() > 10_000,
        "notices ({}) or lockfile ({}) is too small to be the real thing",
        notices.len(),
        lock.len()
    );

    let names: BTreeSet<String> = lock
        .lines()
        .filter_map(|l| l.strip_prefix("name = \""))
        .filter_map(|l| l.split('"').next())
        .map(str::to_string)
        .collect();
    assert!(
        names.len() >= 100,
        "parsed only {} crate name(s) from Cargo.lock; the parser has stopped \
         matching and the check below would pass over nothing",
        names.len()
    );

    // A floor on coverage rather than an exact count: the notices list the
    // crates reachable with `--features full,bpf`, which is a subset of the
    // lockfile, and pinning the difference would be a ratchet nobody maintains.
    let covered = names.iter().filter(|n| notices.contains(*n)).count();
    let pct = covered * 100 / names.len();
    assert!(
        pct >= 70,
        "the notices mention only {covered} of {} lockfile crates ({pct}%). A \
         regenerate-and-compare cannot catch this: a generator emitting half \
         the graph produces a file that agrees with itself.",
        names.len()
    );
}

/// A dependency bump does not exempt the artifacts it invalidates.
///
/// The delivery gate skips a commit that only bumps dependencies, because such
/// a commit ships nothing a reader needs told about. That exemption must NOT
/// reach `THIRD-PARTY-NOTICES.md`: the regeneration is the part a bump can
/// forget, and exempting it would let the forgetting through the one gate
/// positioned to notice.
#[test]
fn the_dependency_exemption_does_not_cover_a_graph_derived_artifact() {
    for (artifact, _) in GRAPH_DERIVED {
        assert!(
            !dependency_path(artifact),
            "{artifact} is treated as a dependency-manifest path. It is a \
             CONSEQUENCE of the graph, not an input to it, and exempting it \
             lets a bump that forgot to regenerate skip the delivery gate."
        );
        assert!(
            !DEPENDENCY_PATHS.contains(artifact),
            "{artifact} is listed in DEPENDENCY_PATHS"
        );
    }
    // And a changeset carrying the artifact is therefore not a bare bump.
    let with_artifact: Vec<String> = vec![
        "Cargo.lock".to_string(),
        "THIRD-PARTY-NOTICES.md".to_string(),
    ];
    assert!(
        !is_dependency_bump(&with_artifact),
        "a commit regenerating the notices beside a lockfile is not exempt -- \
         it changes a published attribution list, which is exactly the kind of \
         thing the changelog is for"
    );
}

/// The staleness gate still exists and still regenerates rather than guessing.
///
/// This file describes a class; `third_party_notices_are_current` is what
/// actually catches it. If that test is deleted or narrowed to a heuristic --
/// a byte count, a date stamp -- everything here keeps passing while nothing
/// compares the file to the graph.
#[test]
fn the_staleness_gate_regenerates_and_compares() {
    let src = read("tests/docs_drift_test.rs");
    assert!(!src.is_empty(), "docs_drift_test.rs must be readable");
    let start = src
        .find("fn third_party_notices_are_current")
        .expect("the staleness gate still exists by name");
    let body = &src[start..];
    let end = body.find("\n}\n").map_or(body.len(), |i| i + 3);
    let body = &body[..end];
    assert!(
        body.contains("build-third-party-notices.py"),
        "the staleness gate no longer runs the generator, so it is comparing \
         the file to something other than the dependency graph:\n{body}"
    );
    assert!(
        body.contains("assert_eq!") || body.contains("assert!"),
        "the staleness gate compares nothing"
    );
}

/// The inputs every rule above reads are real.
///
/// Each rule is an assertion over a file read by path. A missing file reads as
/// the empty string here, and every `contains` over it is false -- which is the
/// shape of a suite that passes because it looked at nothing.
#[test]
fn the_inputs_these_rules_read_are_real() {
    for f in [
        "THIRD-PARTY-NOTICES.md",
        "Cargo.lock",
        "tests/docs_drift_test.rs",
        "scripts/build-third-party-notices.py",
    ] {
        let body = read(f);
        assert!(
            body.len() > 1_000,
            "{f} read as {} bytes; every rule reading it would pass by \
             examining nothing",
            body.len()
        );
    }
    assert!(
        !DEPENDENCY_PATHS.is_empty(),
        "DEPENDENCY_PATHS is empty, so the exemption rule above proves nothing"
    );
}
