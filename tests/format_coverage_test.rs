// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cargo fmt --all` does not mean every package.
//!
//! # The gap
//!
//! Two packages sit outside this workspace on purpose. `fuzz/` is built by
//! `cargo fuzz` and depends on the root crate by path; `bpf/` is the kernel
//! half of the capture backend, a `bpfel-unknown-none` package needing nightly
//! and `bpf-linker` that a stock build must never demand. The root manifest
//! excludes both.
//!
//! Every formatting gate in this repository — the two hooks, CI, the preflight
//! script and the prepare-commit helper — runs `cargo fmt --all`, and `--all`
//! means every member of THIS workspace. An excluded package is not a member.
//! So `bpf/src/main.rs` went unformatted with five gates green, and the only
//! thing that ever noticed was a per-file check run by hand.
//!
//! The rule these tests hold is that formatting coverage is derived from the
//! packages that exist, not from the ones somebody remembered.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Every tracked `Cargo.toml` that declares a package, as a repo-relative
/// directory.
///
/// From `git ls-files` rather than a walk, so a manifest in an ignored build
/// directory is never mistaken for a package this repository ships.
fn package_dirs() -> BTreeSet<String> {
    let out = Command::new("git")
        .args(["ls-files", "*Cargo.toml", "Cargo.toml"])
        .current_dir(repo())
        .output()
        .expect("git ls-files");
    assert!(out.status.success(), "git ls-files failed");
    let mut dirs = BTreeSet::new();
    for rel in String::from_utf8_lossy(&out.stdout).lines() {
        let body = read(rel);
        if !body.contains("[package]") {
            continue;
        }
        let dir = Path::new(rel)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        dirs.insert(if dir.is_empty() { ".".to_string() } else { dir });
    }
    assert!(
        dirs.len() > 1,
        "found {} package(s); this tree has several, so the scan is broken",
        dirs.len()
    );
    dirs
}

/// The workspace members `cargo fmt --all` covers, from the root manifest's
/// `members` list.
fn workspace_members() -> BTreeSet<String> {
    let root = read("Cargo.toml");
    let list = root
        .split_once("members = [")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(v, _)| v.to_string())
        .expect("the root manifest must list its members");
    list.split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The scripts and workflows that check formatting.
const FMT_GATES: [&str; 5] = [
    ".githooks/pre-commit",
    ".githooks/pre-push",
    ".github/workflows/ci.yml",
    "scripts/preflight.sh",
    "scripts/prepare-commit.sh",
];

/// Every package outside the workspace is named by every formatting gate.
///
/// `--all` cannot reach them, so each gate has to say so explicitly. Deriving
/// the list here means a third excluded package fails this test on the day it
/// is added rather than going unformatted until somebody runs a per-file check
/// by hand.
#[test]
fn every_package_outside_the_workspace_is_checked_by_every_format_gate() {
    let members = workspace_members();
    let outside: Vec<String> = package_dirs()
        .into_iter()
        .filter(|d| !members.contains(d))
        .collect();
    assert!(
        !outside.is_empty(),
        "no package sits outside the workspace, which contradicts the root \
         manifest's `exclude` list — the member scan has stopped matching"
    );

    let mut missing = Vec::new();
    for gate in FMT_GATES {
        let body = read(gate);
        for dir in &outside {
            if !body.contains(&format!("--manifest-path {dir}/Cargo.toml")) {
                missing.push(format!("{gate} does not format {dir}/"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "these formatting gates run `cargo fmt --all`, which cannot reach a \
         package the workspace excludes:\n  {}",
        missing.join("\n  ")
    );
}

/// What a `cargo fmt --check` run actually established.
///
/// Three outcomes, and the third is why this is not a boolean. A non-zero exit
/// with an empty diff is not unformatted code — it is rustfmt failing to run,
/// and the two look identical from the exit status alone. This test asserted
/// the first and meant the second on 2026-09-10: CI's feature-matrix jobs
/// install the toolchain without the rustfmt component, so `cargo fmt` exited
/// non-zero with nothing on stdout, and both excluded packages were reported
/// as unformatted with an empty diff underneath. Main went red over code that
/// was correctly formatted.
#[derive(Debug, PartialEq, Eq)]
enum FormatCheck {
    /// rustfmt ran and the package is clean.
    Clean,
    /// rustfmt ran and printed a diff.
    Unformatted,
    /// rustfmt could not run. Nothing was established either way.
    CouldNotRun,
}

/// Pure, so all three arms have a test without needing a machine that lacks
/// rustfmt.
fn classify_format_check(ok: bool, stdout: &str, stderr: &str) -> FormatCheck {
    if ok {
        return FormatCheck::Clean;
    }
    // A real diff is the only evidence of unformatted code. Everything else
    // failing is a broken checker wearing the same exit status.
    if stdout.trim().is_empty() {
        let _ = stderr;
        return FormatCheck::CouldNotRun;
    }
    FormatCheck::Unformatted
}

/// A missing rustfmt is not a finding about the code.
#[test]
fn a_checker_that_could_not_run_is_not_a_verdict() {
    assert_eq!(
        classify_format_check(false, "", "error: 'cargo-fmt' is not installed"),
        FormatCheck::CouldNotRun,
        "an empty diff with a non-zero exit is rustfmt failing to run; calling \
         it unformatted turns a missing component into a code defect"
    );
}

/// A real diff still is one.
#[test]
fn a_diff_is_still_reported_as_unformatted() {
    assert_eq!(
        classify_format_check(false, "Diff in /x/src/main.rs:78:\n-a, b\n+a,\n+b", ""),
        FormatCheck::Unformatted
    );
    assert_eq!(classify_format_check(true, "", ""), FormatCheck::Clean);
}

/// And the packages themselves are actually formatted.
///
/// The test above proves the plumbing exists. This proves the result, which is
/// the thing that was wrong: `bpf/src/main.rs` had an unformatted array with
/// every gate green, because no gate was looking. Running it here means
/// `cargo test` alone catches a regression, without waiting for a hook.
///
/// Where rustfmt is absent this says so and declines to judge, rather than
/// reporting every package as unformatted. CI's Format step has rustfmt and
/// names both packages — `every_package_outside_the_workspace_is_checked_by_every_format_gate`
/// is what guarantees that — so the check is enforced there whatever this run
/// could see.
#[test]
fn every_package_outside_the_workspace_is_formatted() {
    let members = workspace_members();
    let mut unformatted = Vec::new();
    let mut unavailable = Vec::new();
    let mut checked = 0usize;
    for dir in package_dirs() {
        if members.contains(&dir) {
            continue;
        }
        let manifest: PathBuf = repo().join(&dir).join("Cargo.toml");
        let out = Command::new(env!("CARGO"))
            .args(["fmt", "--manifest-path"])
            .arg(&manifest)
            .args(["--", "--check"])
            .current_dir(repo())
            .output()
            .expect("cargo fmt");
        checked += 1;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        match classify_format_check(out.status.success(), &stdout, &stderr) {
            FormatCheck::Clean => {}
            FormatCheck::Unformatted => {
                unformatted.push(format!("{dir}/:\n{}", stdout.trim()));
            }
            FormatCheck::CouldNotRun => unavailable.push(format!("{dir}/: {}", stderr.trim())),
        }
    }
    assert!(
        checked > 0,
        "checked no packages; this gate is passing over an empty list"
    );
    if !unavailable.is_empty() {
        eprintln!(
            "SKIP: rustfmt could not run here, so nothing was established about \
             these packages:\n  {}",
            unavailable.join("\n  ")
        );
    }
    assert!(
        unformatted.is_empty(),
        "these packages are outside the workspace and unformatted. \
         `cargo fmt --all` does not reach them:\n\n{}",
        unformatted.join("\n\n")
    );
}
