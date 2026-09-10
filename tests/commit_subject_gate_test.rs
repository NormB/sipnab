// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gates whose subject is THE COMMIT cannot be asked before the commit exists.
//!
//! # The blindness this closes
//!
//! `release_delivery_test` compares the tree against the newest tag: has code
//! changed since it, does the changelog say so, did a security-relevant file
//! move in silence. At pre-commit time the commit being judged does not exist
//! yet. HEAD is still the tag, nothing sits past it, and all three questions
//! answer "nothing to report" — correctly, and uselessly.
//!
//! Minutes after 0.5.161 published, a commit landed with `src/` changes and no
//! `[Unreleased]` section. Its pre-commit run was green. CI was the first thing
//! that could see the problem, and `main` went red on both runners.
//!
//! The fix was to run that one file from `pre-push`, which is the first moment
//! the question is answerable. What was left open is that nobody enumerated the
//! rest: any other test asking about HEAD relative to a tag or an upstream has
//! the same shape, and a gate that passes vacuously at the moment it is asked
//! is indistinguishable from one that passed.
//!
//! So this enumerates them by SIGNAL rather than by name. A test that runs
//! `git rev-list <tag>..HEAD`, `git describe --tags` or anything else measuring
//! HEAD against history is asking about the commit, and must be run where the
//! commit exists.

use std::collections::BTreeMap;
use std::path::Path;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Git invocations that measure HEAD against history rather than reading the
/// tree or the index.
///
/// `git ls-files`, `git status` and `git diff --cached` all describe what is
/// on disk or staged, which is exactly what pre-commit is for. These do not:
/// each needs a commit to exist before it can answer.
const HISTORY_SIGNALS: [&str; 5] = [
    "rev-list",
    "describe\", \"--tags",
    "..HEAD",
    "@{upstream}",
    "merge-base",
];

/// Files that query history but are NOT asking about the commit under
/// judgement, each with the reason.
const NOT_ABOUT_THIS_COMMIT: [(&str, &str); 1] = [(
    "repo_hygiene_test.rs",
    "counts commits in OTHER worktrees to decide whether one is abandoned. \
     The subject is a different checkout, so the answer does not change when \
     this commit comes into being.",
)];

/// Every test file asking about HEAD-versus-history must run at push time.
#[test]
fn every_history_relative_test_runs_where_the_commit_exists() {
    let pre_push = read(".githooks/pre-push");
    let dir = repo().join("tests");
    let mut history_relative: BTreeMap<String, Vec<&str>> = BTreeMap::new();

    for entry in std::fs::read_dir(&dir).expect("read tests/") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|x| x != "rs") || path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        // This file names every signal in a constant, so it matches all of
        // them without running any. Derived from the crate name rather than
        // written down, so renaming the file cannot resurrect the false
        // positive.
        if name == format!("{}.rs", module_path!()) {
            continue;
        }
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        let hits: Vec<&str> = HISTORY_SIGNALS
            .iter()
            .copied()
            .filter(|s| body.contains(s))
            .collect();
        if !hits.is_empty() {
            history_relative.insert(name, hits);
        }
    }

    assert!(
        !history_relative.is_empty(),
        "no test asks about HEAD versus history, which cannot be true while \
         release_delivery_test exists. The signal list has stopped matching \
         and this gate is checking nothing."
    );

    let mut unrun = Vec::new();
    for (name, hits) in &history_relative {
        if NOT_ABOUT_THIS_COMMIT.iter().any(|(f, _)| f == name) {
            continue;
        }
        let stem = name.trim_end_matches(".rs");
        if !pre_push.contains(stem) {
            unrun.push(format!("{name} (matched {hits:?})"));
        }
    }
    assert!(
        unrun.is_empty(),
        "these tests measure HEAD against history and nothing runs them at \
         push time, so pre-commit answers them before the commit exists and \
         they pass vacuously:\n  {}\n\
         Either add the file to .githooks/pre-push, or add it to \
         NOT_ABOUT_THIS_COMMIT with the reason its subject is something else.",
        unrun.join("\n  ")
    );
}

/// An exemption must carry a reason, and must name a file that exists.
///
/// An exemption list that outlives its files is how a gate quietly stops
/// covering anything: the name no longer matches, so nothing is exempted and
/// nothing is checked either — but the entry reads as though a decision was
/// made.
#[test]
fn every_exemption_names_a_real_file_and_says_why() {
    for (file, reason) in NOT_ABOUT_THIS_COMMIT {
        assert!(
            repo().join("tests").join(file).is_file(),
            "NOT_ABOUT_THIS_COMMIT names {file}, which does not exist"
        );
        assert!(
            reason.len() > 40,
            "the exemption for {file} does not explain itself: {reason:?}"
        );
    }
}

/// Push-time strictness is armed by the hook, not by hope.
///
/// The release gates answer "cannot tell" when git cannot report — a shallow
/// clone, a checkout with no tags — and skipping is right there. At push time
/// none of those hold: git is present, the tags are fetched, and "cannot tell"
/// means the gate is broken rather than the environment being limited. The
/// hook says so by setting the variable; without that line the strict path
/// exists and nothing ever takes it.
#[test]
fn the_push_hook_arms_strict_release_gates() {
    let pre_push = read(".githooks/pre-push");
    assert!(
        pre_push.contains("SIPNAB_RELEASE_GATES_STRICT=1"),
        ".githooks/pre-push does not set SIPNAB_RELEASE_GATES_STRICT=1, so a \
         release gate that cannot answer skips silently at the one moment it \
         has everything it needs to answer"
    );
}
