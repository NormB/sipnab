// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
//! script and the prepare-commit helper — used to run `cargo fmt --all`, and
//! `--all` means every member of THIS workspace. An excluded package is not a
//! member. So `bpf/src/main.rs` went unformatted with five gates green, and the
//! only thing that ever noticed was a per-file check run by hand.
//!
//! Now every gate runs scripts/check-rustfmt.sh, which formats every `.rs`
//! file git knows of with the pinned nightly rustfmt (the Google Rust Style
//! Guide's rustfmt options are unstable, and a stable rustfmt ignores them).
//! The rule these tests hold is that formatting coverage is derived from the
//! files that exist, not from the packages somebody remembered.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// The error a test returns: any error, boxed, so `?` works on I/O,
/// parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> Result<String, TestError> {
    Ok(std::fs::read_to_string(repo().join(rel)).map_err(|e| format!("read {rel}: {e}"))?)
}

/// Every tracked `Cargo.toml` that declares a package, as a repo-relative
/// directory.
///
/// From `git ls-files` rather than a walk, so a manifest in an ignored build
/// directory is never mistaken for a package this repository ships.
fn package_dirs() -> Result<BTreeSet<String>, TestError> {
    let out = Command::new("git")
        .args(["ls-files", "*Cargo.toml", "Cargo.toml"])
        .current_dir(repo())
        .output()?;
    assert!(out.status.success(), "git ls-files failed");
    let mut dirs = BTreeSet::new();
    for rel in String::from_utf8_lossy(&out.stdout).lines() {
        let body = read(rel)?;
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
    Ok(dirs)
}

/// The scripts and workflows that check or apply formatting.
const FMT_GATES: [&str; 5] = [
    ".githooks/pre-commit",
    ".githooks/pre-push",
    ".github/workflows/ci.yml",
    "scripts/preflight.sh",
    "scripts/prepare-commit.sh",
];

/// The one formatting command every gate runs.
const FMT_SCRIPT: &str = "scripts/check-rustfmt.sh";

/// Every formatting gate runs scripts/check-rustfmt.sh, and none runs
/// `cargo fmt` itself.
///
/// The script lists the files from git, so it reaches the packages the
/// workspace excludes without naming them, and it runs the pinned nightly
/// rustfmt, the only one that applies every option in rustfmt.toml. A gate
/// that ran `cargo fmt` instead would check fewer files with a rustfmt that
/// ignores the Google style options, and pass what the others refuse.
#[test]
fn every_format_gate_runs_the_one_script() -> Result<(), TestError> {
    let mut wrong = Vec::new();
    for gate in FMT_GATES {
        let body = read(gate)?;
        if !body.contains(FMT_SCRIPT) {
            wrong.push(format!("{gate} does not run {FMT_SCRIPT}"));
        }
        for (n, line) in body.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with('#') {
                continue;
            }
            if code.contains("cargo fmt") || code.contains("cargo +nightly fmt") {
                wrong.push(format!("{gate}:{}: runs cargo fmt: {}", n + 1, code));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "every formatting gate must run {FMT_SCRIPT}, and only it:\n  {}",
        wrong.join("\n  ")
    );
    Ok(())
}

/// The script's file list reaches every package, including the ones outside
/// the workspace.
///
/// Derived from the packages that exist, so a third excluded package is
/// covered, or fails here, on the day it is added.
#[test]
fn the_format_file_list_reaches_every_package() -> Result<(), TestError> {
    let script = read(FMT_SCRIPT)?;
    assert!(
        script.contains("git ls-files -z --cached --others --exclude-standard -- '*.rs'"),
        "{FMT_SCRIPT} must take its file list from git, tracked and new files alike"
    );
    let out = Command::new("git")
        .args(["ls-files", "--", "*.rs"])
        .current_dir(repo())
        .output()?;
    assert!(out.status.success(), "git ls-files failed: {out:?}");
    let files = String::from_utf8(out.stdout)?;
    let mut unreached = Vec::new();
    for dir in package_dirs()? {
        let prefix = if dir == "." {
            String::new()
        } else {
            format!("{dir}/")
        };
        if !files.lines().any(|f| f.starts_with(&prefix)) {
            unreached.push(dir);
        }
    }
    assert!(
        unreached.is_empty(),
        "no tracked .rs file under these packages, so the format list cannot \
         reach them: {unreached:?}"
    );
    Ok(())
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
fn a_checker_that_could_not_run_is_not_a_verdict() -> Result<(), TestError> {
    assert_eq!(
        classify_format_check(false, "", "error: 'cargo-fmt' is not installed"),
        FormatCheck::CouldNotRun,
        "an empty diff with a non-zero exit is rustfmt failing to run; calling \
         it unformatted turns a missing component into a code defect"
    );
    Ok(())
}

/// A real diff still is one.
#[test]
fn a_diff_is_still_reported_as_unformatted() -> Result<(), TestError> {
    assert_eq!(
        classify_format_check(false, "Diff in /x/src/main.rs:78:\n-a, b\n+a,\n+b", ""),
        FormatCheck::Unformatted
    );
    assert_eq!(classify_format_check(true, "", ""), FormatCheck::Clean);
    Ok(())
}

/// And the tree itself is formatted.
///
/// The tests above prove the plumbing. This proves the result, so `cargo test`
/// alone catches a regression without waiting for a hook: `bpf/src/main.rs`
/// once had an unformatted array with every gate green, because no gate was
/// looking.
///
/// The script exits 2 when the pinned rustfmt is not installed. That says so
/// and declines to judge, rather than reporting the tree as unformatted. CI's
/// Format step installs the pinned rustfmt and runs the script, and
/// `every_format_gate_runs_the_one_script` guarantees that, so the check is
/// enforced there whatever this run could see.
#[test]
fn the_tree_is_formatted() -> Result<(), TestError> {
    let out = Command::new("bash")
        .arg(repo().join(FMT_SCRIPT))
        .current_dir(repo())
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let verdict = if out.status.code() == Some(2) {
        FormatCheck::CouldNotRun
    } else {
        classify_format_check(out.status.success(), &stdout, &stderr)
    };
    match verdict {
        FormatCheck::Clean => {}
        FormatCheck::CouldNotRun => {
            eprintln!(
                "SKIP: {FMT_SCRIPT} could not run here, so nothing was established: {}",
                stderr.trim()
            );
        }
        FormatCheck::Unformatted => {
            return Err(format!(
                "the tree is not formatted; run `{FMT_SCRIPT} --fix`:\n\n{}",
                stdout.trim()
            )
            .into());
        }
    }
    Ok(())
}
