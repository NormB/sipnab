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

/// And the packages themselves are actually formatted.
///
/// The test above proves the plumbing exists. This proves the result, which is
/// the thing that was wrong: `bpf/src/main.rs` had an unformatted array with
/// every gate green, because no gate was looking. Running it here means
/// `cargo test` alone catches a regression, without waiting for a hook.
#[test]
fn every_package_outside_the_workspace_is_formatted() {
    let members = workspace_members();
    let mut unformatted = Vec::new();
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
        if !out.status.success() {
            unformatted.push(format!(
                "{dir}/:\n{}",
                String::from_utf8_lossy(&out.stdout).trim()
            ));
        }
    }
    assert!(
        checked > 0,
        "checked no packages; this gate is passing over an empty list"
    );
    assert!(
        unformatted.is_empty(),
        "these packages are outside the workspace and unformatted. \
         `cargo fmt --all` does not reach them:\n\n{}",
        unformatted.join("\n\n")
    );
}
