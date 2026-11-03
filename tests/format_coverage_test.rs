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

use std::collections::{BTreeMap, BTreeSet};
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

/// The command that installs the rustfmt named in .rustfmt-toolchain, as CI's
/// Format step runs it.
const PIN_INSTALL: &str =
    r#"rustup toolchain install "$(cat .rustfmt-toolchain)" --profile minimal --component rustfmt"#;

/// The lines of a shell script or workflow that are not comments.
fn code_lines(body: &str) -> impl Iterator<Item = &str> {
    body.lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with('#'))
}

/// The lines that can run a command: code lines, less the ones that only
/// print text (`echo`, `printf`), which name a script without running it.
fn call_lines(body: &str) -> impl Iterator<Item = &str> {
    code_lines(body).filter(|l| !l.starts_with("echo ") && !l.starts_with("printf "))
}

/// A shell script or a git hook, the only files that run the hooks and the
/// format script. A Python script that names one does so in prose.
fn is_shell(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    path.ends_with(".sh") || (path.starts_with(".githooks/") && !name.contains('.'))
}

/// Whether a Python line names `runner` as a whole string literal, the way a
/// test that runs it does (`REPO / "scripts/prepare-commit.sh"`). Prose in a
/// docstring that mentions a script is not a literal of exactly its path.
fn names_as_literal(line: &str, runner: &str) -> bool {
    line.contains(&format!("\"{runner}\"")) || line.contains(&format!("'{runner}'"))
}

/// The files that run the format gate: the script itself, every shell script
/// or hook whose call lines run one that does, and every Python file that names
/// one as a string literal (scripts/tests/test_prepare_commit.py runs
/// prepare-commit.sh), to a fixed point.
///
/// Pure, over `(path, body)` pairs, so both sides have a test.
fn format_gate_runners(files: &BTreeMap<String, String>) -> BTreeSet<String> {
    let mut runners = BTreeSet::from([FMT_SCRIPT.to_string()]);
    loop {
        let before = runners.len();
        for (path, body) in files {
            let runs_one = if is_shell(path) {
                call_lines(body).any(|l| runners.iter().any(|r| l.contains(r.as_str())))
            } else if path.ends_with(".py") {
                code_lines(body).any(|l| runners.iter().any(|r| names_as_literal(l, r)))
            } else {
                false
            };
            if !runners.contains(path) && runs_one {
                runners.insert(path.clone());
            }
        }
        if runners.len() == before {
            return runners;
        }
    }
}

/// Whether a workflow line runs the directory that holds `runner`, as
/// `python3 -m pytest scripts/tests -q` runs every test in scripts/tests: one
/// of its words is exactly that directory. Only a path with a `/` counts, so
/// the bare word `scripts` in a job name ("Ops scripts") is not a run.
fn runs_dir_of(line: &str, runner: &str) -> bool {
    runner.rsplit_once('/').is_some_and(|(dir, _)| {
        dir.contains('/')
            && line
                .split_whitespace()
                .any(|w| w.trim_end_matches('/') == dir)
    })
}

/// The jobs of a workflow that run the format gate, directly or through a
/// runner, without installing the pinned rustfmt it needs.
///
/// A job is a line indented two spaces under `jobs:` that ends in `:`, up to
/// the next one. Pure, so both sides have a test.
fn jobs_missing_the_pin(workflow: &str, runners: &BTreeSet<String>) -> Vec<String> {
    let mut jobs: Vec<(String, Vec<&str>)> = Vec::new();
    let mut in_jobs = false;
    for line in workflow.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_jobs = line.trim_end() == "jobs:";
            continue;
        }
        if !in_jobs {
            continue;
        }
        let is_job = line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim_end().ends_with(':')
            && !line.trim_start().starts_with('#');
        if is_job {
            jobs.push((line.trim().trim_end_matches(':').to_string(), Vec::new()));
        } else if let Some((_, body)) = jobs.last_mut() {
            body.push(line);
        }
    }
    jobs.into_iter()
        .filter(|(_, body)| {
            // The pin must be installed BEFORE the first line that runs the
            // gate: on #603 the Check job installed it in its Format step,
            // after the Python tests that run prepare-commit.sh.
            let text = body.join("\n");
            let first_run = call_lines(&text).position(|l| {
                runners
                    .iter()
                    .any(|r| l.contains(r.as_str()) || runs_dir_of(l, r))
            });
            let first_pin = code_lines(&text)
                .filter(|l| !l.starts_with("echo ") && !l.starts_with("printf "))
                .position(|l| l.contains(PIN_INSTALL));
            match (first_run, first_pin) {
                (None, _) => false,
                (Some(_), None) => true,
                (Some(run), Some(pin)) => pin > run,
            }
        })
        .map(|(name, _)| name)
        .collect()
}

/// Every tracked script and hook, by repo-relative path.
fn scripts_and_hooks() -> Result<BTreeMap<String, String>, TestError> {
    let out = Command::new("git")
        .args(["ls-files", "scripts", ".githooks"])
        .current_dir(repo())
        .output()?;
    assert!(
        out.status.success(),
        "git ls-files scripts .githooks failed"
    );
    let mut files = BTreeMap::new();
    for rel in String::from_utf8_lossy(&out.stdout).lines() {
        if let Ok(body) = std::fs::read_to_string(repo().join(rel)) {
            files.insert(rel.to_string(), body);
        }
    }
    Ok(files)
}

/// A CI job that runs the format gate installs the rustfmt it needs.
///
/// scripts/check-rustfmt.sh exits 2 without the pinned nightly rustfmt, and a
/// harness that drives the hooks then sees every gate blocked by the format
/// step. On PR #603 the Git hook scenarios job installed only the stable
/// rustfmt, and twelve scenarios failed as "blocked, but not by that gate".
/// The runners are derived from the scripts that exist, so a new harness that
/// reaches the gate is covered the day it is added.
#[test]
fn every_job_that_runs_the_format_gate_installs_the_pinned_rustfmt() -> Result<(), TestError> {
    let runners = format_gate_runners(&scripts_and_hooks()?);
    assert!(
        runners.contains(".githooks/pre-push") && runners.contains("scripts/test-pre-push.sh"),
        "the runner scan missed the pre-push hook or its harness, so it is broken: {runners:?}"
    );
    let out = Command::new("git")
        .args(["ls-files", ".github/workflows/*.yml"])
        .current_dir(repo())
        .output()?;
    assert!(
        out.status.success(),
        "git ls-files .github/workflows failed"
    );
    let mut missing = Vec::new();
    for rel in String::from_utf8_lossy(&out.stdout).lines() {
        for job in jobs_missing_the_pin(&read(rel)?, &runners) {
            missing.push(format!("{rel}: job `{job}`"));
        }
    }
    assert!(
        missing.is_empty(),
        "these jobs run the format gate without installing the pinned rustfmt; add a step \
         that runs `{PIN_INSTALL}`:\n  {}",
        missing.join("\n  ")
    );
    Ok(())
}

/// The runner scan follows calls through scripts and ignores comments.
#[test]
fn the_runner_scan_follows_calls_and_skips_comments() {
    let files = BTreeMap::from([
        (
            "fixture/a.sh".to_string(),
            "x=1\nscripts/check-rustfmt.sh --fix\n".to_string(),
        ),
        ("fixture/b.sh".to_string(), "sh fixture/a.sh\n".to_string()),
        (
            "fixture/c.sh".to_string(),
            "  # scripts/check-rustfmt.sh\necho\n".to_string(),
        ),
        (
            "fixture/d.py".to_string(),
            "\"\"\"Runs after fixture/a.sh.\"\"\"\n".to_string(),
        ),
        (
            "fixture/e.sh".to_string(),
            "echo \"then run fixture/a.sh\"\n".to_string(),
        ),
        (
            "fixture/t/test_x.py".to_string(),
            "SWEEP = REPO / \"fixture/a.sh\"\n".to_string(),
        ),
        (".githooks/pre-x".to_string(), "fixture/b.sh\n".to_string()),
        (
            ".githooks/pre-x.sample".to_string(),
            "fixture/b.sh\n".to_string(),
        ),
    ]);
    let runners = format_gate_runners(&files);
    let want: BTreeSet<String> = [
        FMT_SCRIPT,
        "fixture/a.sh",
        "fixture/b.sh",
        ".githooks/pre-x",
        "fixture/t/test_x.py",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(
        runners, want,
        "a direct call, a call through a script, a hook and a Python test that names a \
         runner as a whole string literal count; a comment, a Python docstring, an echo \
         and a hook sample do not"
    );
}

/// The job scan names a job that runs a runner without the pin, and only it.
#[test]
fn the_job_scan_names_only_jobs_without_the_pin() {
    let runners: BTreeSet<String> = [FMT_SCRIPT, "fixture/a.sh", "fixture/t/test_x.py"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let workflow = format!(
        "name: x\non: push\njobs:\n  bare:\n    steps:\n      - run: sh fixture/a.sh\n  \
         pinned:\n    steps:\n      - run: |\n          {PIN_INSTALL}\n          \
         scripts/check-rustfmt.sh\n  commented:\n    steps:\n      # fixture/a.sh\n      \
         - run: echo\n  unrelated:\n    steps:\n      - run: cargo test\n  \
         pytests:\n    steps:\n      - run: python3 -m pytest fixture/t -q\n  \
         prefix:\n    steps:\n      - run: python3 -m pytest fixture/tt -q\n  \
         named:\n    name: Ops scripts (verdict.sh)\n    steps:\n      - run: bash ops/x.sh\n  \
         late:\n    steps:\n      - run: python3 -m pytest fixture/t -q\n      - run: {PIN_INSTALL}\n"
    );
    assert_eq!(
        jobs_missing_the_pin(&workflow, &runners),
        vec![
            "bare".to_string(),
            "pytests".to_string(),
            "late".to_string()
        ],
        "a job that runs the gate, directly or by running the directory that holds a \
         runner, without installing the pin is named; a directory that only shares a \
         prefix is not, and neither is a bare word such as `scripts` in a job's name; \
         installing the pin only after the gate ran (the Check job on #603) still counts as \
         missing"
    );
}

/// The lines of a script that run the format script and discard its exit
/// status with `|| true`.
///
/// Pure, so both sides have a test.
fn swallowed_format_runs(body: &str) -> Vec<String> {
    code_lines(body)
        .filter(|l| l.contains(FMT_SCRIPT) && l.trim_end().ends_with("|| true"))
        .map(ToString::to_string)
        .collect()
}

/// No script runs the format script and throws its exit status away.
///
/// The script exits 2 when the pinned rustfmt is missing. scripts/test-pre-push.sh
/// ran `--fix` with `>/dev/null 2>&1 || true` before each scenario, so on a
/// runner without the pin the fixer did nothing, said nothing, and each
/// scenario failed later as "blocked, but not by that gate". A harness must
/// stop on a fixer that could not run.
#[test]
fn no_script_discards_the_format_scripts_exit_status() -> Result<(), TestError> {
    let mut wrong = Vec::new();
    for (path, body) in scripts_and_hooks()? {
        for line in swallowed_format_runs(&body) {
            wrong.push(format!("{path}: {line}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "these lines discard {FMT_SCRIPT}'s exit status, so a missing rustfmt reads as \
         a later gate's failure:\n  {}",
        wrong.join("\n  ")
    );
    Ok(())
}

/// The swallow scan finds `|| true` after the format script, and nothing else.
#[test]
fn the_swallow_scan_finds_only_a_discarded_format_run() {
    let body = "( cd x && scripts/check-rustfmt.sh --fix ) >/dev/null 2>&1 || true\n\
                # scripts/check-rustfmt.sh --fix || true\n\
                fmt_fixture\n\
                cargo build || true\n";
    assert_eq!(
        swallowed_format_runs(body),
        vec!["( cd x && scripts/check-rustfmt.sh --fix ) >/dev/null 2>&1 || true".to_string()],
        "only the code line that runs the format script and discards its status is named"
    );
}
