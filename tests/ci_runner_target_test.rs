// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A self-hosted runner keeps its build between jobs, and keeps it bounded.
//!
//! The self-hosted runners are persistent: the same four runner processes
//! take job after job on one machine. Their `target` directories did not
//! persist. `actions/checkout` defaults to `clean: true`, which runs
//! `git clean -ffdx`, and `target/` is untracked, so every job's log began
//! with `Removing target/`. Measured on 2026-10-08 over one push's feature
//! matrix: each leg recompiled 279 to 701 crates from nothing, one to three
//! minutes of cargo per leg, eighteen legs per push.
//!
//! The clean stays. A job must not read untracked leftovers from another
//! branch, because several gates read the disk rather than git. The build
//! directory moves instead: the shared action
//! `.github/actions/runner-target` points `CARGO_TARGET_DIR` at a directory
//! outside the workspace, one per runner, and bounds its size with
//! `scripts/ci-target-cap.sh` before the build.
//!
//! One directory per runner, not one shared by all four: cargo takes a lock
//! on its build directory, so four concurrent jobs on one directory would
//! run one at a time.
//!
//! These tests hold the workflow shape and drive the cap script itself.

use std::path::{Path, PathBuf};
use std::process::Command;

type TestError = Box<dyn std::error::Error>;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> Result<String, TestError> {
    Ok(std::fs::read_to_string(repo().join(rel)).map_err(|e| format!("read {rel}: {e}"))?)
}

const ACTION: &str = ".github/actions/runner-target/action.yml";
const ACTION_USE: &str = "uses: ./.github/actions/runner-target";
const CAP_SCRIPT: &str = "scripts/ci-target-cap.sh";

/// The one self-hosted cargo job that must build from nothing.
///
/// `reproducible.yml` proves that two builds of one commit, in two fresh
/// trees, produce the same bytes. A warm target directory would make the
/// second build reuse the first one's artifacts, and the comparison would
/// prove nothing about a clean build.
const FRESH_BUILD_EXEMPT: &[(&str, &str)] = &[("reproducible.yml", "reproducible")];

/// One job: its workflow file, its id, and its body text.
struct Job {
    workflow: String,
    id: String,
    body: String,
}

/// Split a workflow into its jobs by indentation.
///
/// A job is a two-space-indented key under the top-level `jobs:`; its body
/// runs to the next such key. Workflows in this repository are written in
/// that shape, and `every_self_hosted_cargo_job_builds_outside_the_workspace`
/// asserts it found jobs, so a change of shape fails loudly instead of
/// scanning nothing.
fn jobs_of(workflow: &str, text: &str) -> Vec<Job> {
    let mut jobs = Vec::new();
    let mut in_jobs = false;
    let mut current: Option<Job> = None;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() && !line.starts_with('#') {
            in_jobs = line.trim_end() == "jobs:";
            if let Some(j) = current.take() {
                jobs.push(j);
            }
            continue;
        }
        if !in_jobs {
            continue;
        }
        let is_job_key = line.starts_with("  ")
            && !line.starts_with("   ")
            && !line.trim_start().starts_with('#')
            && line.trim_end().ends_with(':');
        if is_job_key {
            if let Some(j) = current.take() {
                jobs.push(j);
            }
            current = Some(Job {
                workflow: workflow.to_string(),
                id: line.trim().trim_end_matches(':').to_string(),
                body: String::new(),
            });
        } else if let Some(j) = current.as_mut() {
            j.body.push_str(line);
            j.body.push('\n');
        }
    }
    if let Some(j) = current.take() {
        jobs.push(j);
    }
    jobs
}

/// Every job in every workflow under `.github/workflows`.
fn all_jobs() -> Result<Vec<Job>, TestError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(repo().join(".github/workflows"))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("workflow file name")?
            .to_string();
        let text = std::fs::read_to_string(&path)?;
        out.extend(jobs_of(&name, &text));
    }
    out.sort_by(|a, b| (&a.workflow, &a.id).cmp(&(&b.workflow, &b.id)));
    Ok(out)
}

/// The job selects a self-hosted runner.
fn runs_self_hosted(body: &str) -> bool {
    body.lines()
        .any(|l| l.trim_start().starts_with("runs-on:") && l.contains("self-hosted"))
}

/// Lines that run cargo: a `run:` value or a line of a `run: |` block that
/// invokes `cargo`, or one of the repository's `scripts/*-build.sh` wrappers
/// that invoke it, comments excluded.
fn cargo_lines(body: &str) -> Vec<usize> {
    body.lines()
        .enumerate()
        .filter(|(_, l)| {
            let t = l.trim_start();
            !t.starts_with('#')
                && (t.starts_with("cargo ")
                    || t.starts_with("run: cargo ")
                    || t.contains("&& cargo ")
                    || (t.contains("scripts/") && t.contains("-build.sh")))
        })
        .map(|(i, _)| i)
        .collect()
}

/// The value assigned to `CARGO_TARGET_DIR` in `text`, in either the
/// `env:` form (`CARGO_TARGET_DIR: v`) or the `$GITHUB_ENV` form
/// (`CARGO_TARGET_DIR=v`).
fn target_dir_value(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let t = l.trim_start();
        if t.starts_with('#') {
            return None;
        }
        let at = t.find("CARGO_TARGET_DIR")?;
        let rest = &t[at + "CARGO_TARGET_DIR".len()..];
        let rest = rest.strip_prefix(':').or_else(|| rest.strip_prefix('='))?;
        Some(rest.trim().trim_matches('"').to_string())
    })
}

/// Why `value` is not a per-runner directory outside the workspace, if it
/// is not one.
fn target_dir_defect(value: &str) -> Option<String> {
    if !(value.contains("RUNNER_NAME") || value.contains("runner.name")) {
        return Some(format!(
            "`{value}` does not include the runner name, so the four runners \
             would share one directory and serialize on cargo's build lock"
        ));
    }
    if value.contains("GITHUB_WORKSPACE") || value.contains("github.workspace") {
        return Some(format!(
            "`{value}` is inside the workspace, which checkout's clean removes"
        ));
    }
    if !(value.starts_with('/') || value.starts_with("$HOME") || value.starts_with("${HOME}")) {
        return Some(format!(
            "`{value}` is relative, so it resolves inside the workspace"
        ));
    }
    None
}

/// Every self-hosted job that runs cargo keeps its target directory outside
/// the workspace, per runner, set before the first cargo command.
#[test]
fn every_self_hosted_cargo_job_builds_outside_the_workspace() -> Result<(), TestError> {
    let action = std::fs::read_to_string(repo().join(ACTION)).unwrap_or_default();
    let mut scanned = Vec::new();
    let mut defects = Vec::new();
    for job in all_jobs()? {
        if !runs_self_hosted(&job.body) {
            continue;
        }
        let cargo = cargo_lines(&job.body);
        let Some(&first_cargo) = cargo.first() else {
            continue;
        };
        let label = format!("{}:{}", job.workflow, job.id);
        scanned.push(label.clone());
        if FRESH_BUILD_EXEMPT
            .iter()
            .any(|(w, j)| *w == job.workflow && *j == job.id)
        {
            continue;
        }
        let lines: Vec<&str> = job.body.lines().collect();
        let set_at = lines
            .iter()
            .position(|l| l.contains(ACTION_USE))
            .map(|i| (i, action.as_str()))
            .or_else(|| {
                lines
                    .iter()
                    .position(|l| l.contains("CARGO_TARGET_DIR"))
                    .map(|i| (i, job.body.as_str()))
            });
        let Some((at, source)) = set_at else {
            defects.push(format!(
                "{label}: runs cargo on a self-hosted runner and never sets \
                 CARGO_TARGET_DIR (no `{ACTION_USE}` step), so checkout's \
                 clean deletes target/ and every run rebuilds from nothing"
            ));
            continue;
        };
        if at > first_cargo {
            defects.push(format!(
                "{label}: CARGO_TARGET_DIR is set after the first cargo command"
            ));
        }
        match target_dir_value(source) {
            None => defects.push(format!(
                "{label}: the step it uses assigns no CARGO_TARGET_DIR value"
            )),
            Some(v) => {
                if let Some(why) = target_dir_defect(&v) {
                    defects.push(format!("{label}: {why}"));
                }
            }
        }
    }
    assert!(
        scanned.len() >= 4,
        "only {} self-hosted cargo job(s) found ({}); the job scan is wrong \
         and this gate proves nothing",
        scanned.len(),
        scanned.join(", ")
    );
    assert!(defects.is_empty(), "{}", defects.join("\n"));
    Ok(())
}

/// The exempt job really does build fresh: no shared action, no
/// `CARGO_TARGET_DIR`. An exemption that silently picked up a warm
/// directory would turn the reproducibility check into a cache comparison.
#[test]
fn the_reproducible_build_stays_fresh() -> Result<(), TestError> {
    let mut seen = 0;
    for job in all_jobs()? {
        if !FRESH_BUILD_EXEMPT
            .iter()
            .any(|(w, j)| *w == job.workflow && *j == job.id)
        {
            continue;
        }
        seen += 1;
        assert!(
            !job.body.contains(ACTION_USE) && !job.body.contains("CARGO_TARGET_DIR"),
            "{}:{} must build in fresh trees; it now sets a target directory",
            job.workflow,
            job.id
        );
    }
    assert_eq!(
        seen,
        FRESH_BUILD_EXEMPT.len(),
        "an exempt job no longer exists; remove it from FRESH_BUILD_EXEMPT"
    );
    Ok(())
}

/// The shared action applies only on a self-hosted runner and caps the
/// directory before handing it to cargo.
#[test]
fn the_shared_action_is_self_hosted_only_and_caps_first() -> Result<(), TestError> {
    let action = read(ACTION)?;
    assert!(
        action.contains("runner.environment == 'self-hosted'"),
        "the action must do nothing on a GitHub-hosted runner, whose target \
         directory is restored by actions/cache inside the workspace"
    );
    let cap = action
        .find(CAP_SCRIPT)
        .ok_or("the action must bound the directory with scripts/ci-target-cap.sh")?;
    let set = action
        .find(">> \"$GITHUB_ENV\"")
        .ok_or("the action must export CARGO_TARGET_DIR through $GITHUB_ENV")?;
    assert!(
        cap < set,
        "the cap must run before the directory is handed to cargo"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Which runner each job takes, and what a self-hosted job must not do.
// ---------------------------------------------------------------------------

/// The labels a `runs-on:` value selects for a job whose matrix `os` is `os`.
///
/// Understands the three shapes the workflows use: a literal label
/// (`ubuntu-latest`), a literal list (`[self-hosted, jetson]`), and the
/// one-condition expression `${{ matrix.os == 'X' && A || B }}`, where `A`
/// and `B` are a quoted label or `fromJSON('[...]')`. Anything else is an
/// error, so a new shape fails here instead of being read as no labels.
fn runner_labels(runs_on: &str, os: &str) -> Result<Vec<String>, TestError> {
    fn list(text: &str) -> Vec<String> {
        text.trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(|l| l.trim().trim_matches('"').trim_matches('\'').to_string())
            .filter(|l| !l.is_empty())
            .collect()
    }
    fn operand(text: &str) -> Result<Vec<String>, TestError> {
        let t = text.trim();
        if let Some(inner) = t
            .strip_prefix("fromJSON('")
            .and_then(|r| r.strip_suffix("')"))
        {
            return Ok(list(inner));
        }
        if t.len() >= 2 && t.starts_with('\'') && t.ends_with('\'') {
            return Ok(vec![t.trim_matches('\'').to_string()]);
        }
        Err(format!("unrecognized runs-on operand `{t}`").into())
    }
    let value = runs_on.trim();
    let Some(expr) = value.strip_prefix("${{").and_then(|r| r.strip_suffix("}}")) else {
        return Ok(if value.starts_with('[') {
            list(value)
        } else {
            vec![value.to_string()]
        });
    };
    let (lhs, otherwise) = expr
        .split_once(" || ")
        .ok_or_else(|| format!("runs-on `{value}` has no `||` branch"))?;
    let (cond, then) = lhs
        .split_once(" && ")
        .ok_or_else(|| format!("runs-on `{value}` has no `&&` branch"))?;
    let wanted = cond
        .trim()
        .strip_prefix("matrix.os == '")
        .and_then(|r| r.strip_suffix('\''))
        .ok_or_else(|| format!("runs-on `{value}` does not test matrix.os"))?;
    if wanted == os {
        operand(then)
    } else {
        operand(otherwise)
    }
}

/// The `runs-on:` value of a job body.
fn runs_on(job: &Job) -> Result<&str, TestError> {
    job.body
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("runs-on:"))
        .map(str::trim)
        .ok_or_else(|| format!("{}:{} has no runs-on", job.workflow, job.id).into())
}

fn job<'a>(jobs: &'a [Job], workflow: &str, id: &str) -> Result<&'a Job, TestError> {
    jobs.iter()
        .find(|j| j.workflow == workflow && j.id == id)
        .ok_or_else(|| format!("{workflow} has no job `{id}`").into())
}

/// The two slowest Linux jobs of a pull request run on the self-hosted
/// runners, with their builds kept between runs; macOS stays on GitHub.
///
/// Measured on two pull requests on 2026-10-09 (#410, #411): the Linux leg
/// of Check took 22.1 and 20.2 minutes on GitHub's `ubuntu-24.04-arm`, of
/// which the Test step alone was 10.9, and Coverage took 21.2 and 15.3, each
/// rebuilding from a restored cache on a four-core runner. Both were among
/// the three jobs that set the length of the run.
#[test]
fn the_linux_check_leg_and_coverage_run_on_the_self_hosted_runners() -> Result<(), TestError> {
    let jobs = all_jobs()?;
    let self_hosted = vec!["self-hosted".to_string(), "jetson".to_string()];

    let check = runs_on(job(&jobs, "ci.yml", "check")?)?;
    assert_eq!(
        runner_labels(check, "ubuntu-latest")?,
        self_hosted,
        "ci.yml check: the Linux leg must run on [self-hosted, jetson] (runs-on: {check})"
    );
    assert_eq!(
        runner_labels(check, "macos-latest")?,
        vec!["macos-latest".to_string()],
        "ci.yml check: the macOS leg must stay on macos-latest; no self-hosted \
         runner is a Mac (runs-on: {check})"
    );

    let coverage = runs_on(job(&jobs, "quality.yml", "coverage")?)?;
    assert_eq!(
        runner_labels(coverage, "")?,
        self_hosted,
        "quality.yml coverage must run on [self-hosted, jetson] (runs-on: {coverage})"
    );
    Ok(())
}

/// The steps of a job body: each starts at a `- ` six spaces in.
fn steps_of(body: &str) -> Vec<String> {
    let mut steps: Vec<String> = Vec::new();
    for line in body.lines() {
        if line.starts_with("      - ") {
            steps.push(String::new());
        }
        if let Some(s) = steps.last_mut() {
            s.push_str(line);
            s.push('\n');
        }
    }
    steps
}

/// The step's `if:` condition, written on the dash line or its own line.
fn step_if(step: &str) -> Option<&str> {
    step.lines().find_map(|l| {
        let t = l.trim_start();
        let t = t.strip_prefix("- ").unwrap_or(t);
        t.strip_prefix("if:").map(str::trim)
    })
}

const HOSTED_ONLY: &str = "runner.environment == 'github-hosted'";

fn hosted_only(step: &str) -> bool {
    step_if(step).is_some_and(|c| c.contains(HOSTED_ONLY))
}

/// Steps written for a disposable GitHub VM are skipped on a self-hosted
/// runner.
///
/// `free-disk` runs `sudo rm -rf` over SDK directories and prunes every
/// docker image: on a hosted VM that is reclaimed space, on the self-hosted
/// machine it deletes software other work depends on. `actions/cache` of
/// `target` (its `restore` and `save` halves too) restores and uploads a
/// build directory the self-hosted job does not use (its own is outside the
/// workspace) and would upload the machine's cargo registry. The prune step
/// that precedes the save edits that workspace `target` for the upload.
#[test]
fn hosted_only_steps_are_skipped_on_self_hosted_runners() -> Result<(), TestError> {
    let mut seen = 0;
    let mut defects = Vec::new();
    for job in all_jobs()? {
        if !runs_self_hosted(&job.body) {
            continue;
        }
        for step in steps_of(&job.body) {
            let hosted_kind = step.contains("uses: ./.github/actions/free-disk")
                || step.contains("uses: actions/cache@")
                || step.contains("uses: actions/cache/restore@")
                || step.contains("uses: actions/cache/save@")
                || step.contains("scripts/ci-cache-prune.sh");
            if !hosted_kind {
                continue;
            }
            seen += 1;
            if !hosted_only(&step) {
                defects.push(format!(
                    "{}:{}: this step must carry `if: {HOSTED_ONLY}`:\n{step}",
                    job.workflow, job.id
                ));
            }
        }
    }
    assert!(
        seen >= 8,
        "found {seen} hosted-only step(s) in self-hosted jobs; the step scan is wrong"
    );
    assert!(defects.is_empty(), "{}", defects.join("\n"));
    Ok(())
}

/// A self-hosted job changes the machine's packages only through the shared
/// `system-deps` action.
///
/// Four runner instances share one machine, and dpkg and debconf each hold
/// one machine-wide lock. The action installs only what `dpkg -s` reports
/// missing and serializes the install, so a job that needs nothing does
/// nothing. A bare `apt-get`, `dpkg -i` or `debconf-set-selections` in a job
/// does neither, and two concurrent jobs fail on the lock.
#[test]
fn self_hosted_jobs_change_packages_only_through_system_deps() -> Result<(), TestError> {
    let mut scanned = 0;
    let mut defects = Vec::new();
    for job in all_jobs()? {
        if !runs_self_hosted(&job.body) {
            continue;
        }
        scanned += 1;
        for step in steps_of(&job.body) {
            if hosted_only(&step) {
                continue;
            }
            for line in step.lines() {
                let t = line.trim_start();
                if t.starts_with('#') {
                    continue;
                }
                if ["apt-get", "dpkg -i", "debconf-set-selections"]
                    .iter()
                    .any(|c| t.contains(c))
                {
                    defects.push(format!("{}:{}: {}", job.workflow, job.id, t));
                }
            }
        }
    }
    assert!(
        scanned >= 4,
        "only {scanned} self-hosted job(s) found; the job scan is wrong"
    );
    assert!(defects.is_empty(), "{}", defects.join("\n"));
    Ok(())
}

/// Whether `line` names the in-workspace `target/` directory as a path.
fn names_workspace_target(line: &str) -> bool {
    line.match_indices("target/").any(|(at, _)| {
        line[..at]
            .chars()
            .last()
            .is_none_or(|c| c.is_whitespace() || "\"'=(:".contains(c))
    })
}

/// A self-hosted job that moved its build out of the workspace reads the
/// build from `CARGO_TARGET_DIR`, not from `target/`.
///
/// After the runner-target step, `target/debug/sipnab` does not exist in the
/// workspace: a step that names it runs nothing, or uploads nothing.
#[test]
fn self_hosted_jobs_read_their_build_from_cargo_target_dir() -> Result<(), TestError> {
    let mut defects = Vec::new();
    for job in all_jobs()? {
        if !runs_self_hosted(&job.body) || !job.body.contains(ACTION_USE) {
            continue;
        }
        for step in steps_of(&job.body) {
            if hosted_only(&step) {
                continue;
            }
            for line in step.lines() {
                let t = line.trim_start();
                if !t.starts_with('#') && names_workspace_target(t) {
                    defects.push(format!("{}:{}: {}", job.workflow, job.id, t));
                }
            }
        }
    }
    assert!(
        defects.is_empty(),
        "these lines name the workspace's target/ in a job whose build is in \
         CARGO_TARGET_DIR:\n{}",
        defects.join("\n")
    );
    Ok(())
}

#[test]
fn the_workspace_target_scan_tells_a_path_from_a_flag() {
    assert!(names_workspace_target("path: target/llvm-cov/html"));
    assert!(names_workspace_target(
        "scripts/smoke-clients.sh target/debug/sipnab"
    ));
    assert!(names_workspace_target("bin=\"target/release/sipnab\""));
    assert!(!names_workspace_target(
        "scripts/smoke-clients.sh \"${CARGO_TARGET_DIR:-target}/debug/sipnab\""
    ));
    assert!(!names_workspace_target(
        "cargo check --target wasm32-unknown-unknown"
    ));
    assert!(!names_workspace_target(
        "path: ${{ env.CARGO_TARGET_DIR }}/llvm-cov/html"
    ));
}

/// The `dir:` input a job passes to the runner-target action, if any.
fn runner_target_dir_input(body: &str) -> Option<String> {
    let step = steps_of(body)
        .into_iter()
        .find(|s| s.contains(ACTION_USE))?;
    step.lines()
        .find_map(|l| l.trim_start().strip_prefix("dir:"))
        .map(|v| v.trim().trim_matches('\'').trim_matches('"').to_string())
}

/// An instrumented build keeps its own directory.
///
/// `cargo llvm-cov` compiles every crate with `-C instrument-coverage`. In
/// the directory the plain builds use, each Coverage job and each plain job
/// on the same runner would invalidate the other's artifacts, and the two
/// together would reach the 64 GiB cap sooner and lose both.
#[test]
fn an_instrumented_build_has_its_own_target_directory() -> Result<(), TestError> {
    let action = read(ACTION)?;
    assert!(
        action.contains("inputs.dir"),
        "the runner-target action takes no `dir` input, so every job on a \
         runner shares one directory"
    );
    let mut instrumented = 0;
    let mut defects = Vec::new();
    for job in all_jobs()? {
        if !runs_self_hosted(&job.body) || !job.body.contains(ACTION_USE) {
            continue;
        }
        let covers = cargo_lines(&job.body).iter().any(|&i| {
            job.body
                .lines()
                .nth(i)
                .is_some_and(|l| l.contains("llvm-cov"))
        });
        let dir = runner_target_dir_input(&job.body);
        if covers {
            instrumented += 1;
            match dir.as_deref() {
                None | Some("target") => defects.push(format!(
                    "{}:{}: runs cargo llvm-cov in the plain build's directory; \
                     pass the runner-target action a `dir:` of its own",
                    job.workflow, job.id
                )),
                Some(_) => {}
            }
        } else if let Some(d) = dir.as_deref().filter(|d| *d != "target") {
            defects.push(format!(
                "{}:{}: a plain build in directory `{d}`, apart from every other \
                 plain build on the runner",
                job.workflow, job.id
            ));
        }
    }
    assert!(
        instrumented >= 1,
        "no self-hosted job runs cargo llvm-cov; this gate is reading the wrong jobs"
    );
    assert!(defects.is_empty(), "{}", defects.join("\n"));
    Ok(())
}

/// Run the action's own selection script with `dir` as its input, in a
/// temporary home. Returns the exit code and what it wrote to `$GITHUB_ENV`.
fn select_target_dir(home: &Path, dir: &str) -> Result<(i32, String), TestError> {
    let action = read(ACTION)?;
    let start = action
        .find("run: |\n")
        .ok_or("the action has no run block")?
        + "run: |\n".len();
    let script: String = action[start..]
        .lines()
        .take_while(|l| l.starts_with("        ") || l.trim().is_empty())
        .map(|l| l.strip_prefix("        ").unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n");
    let env_file = home.join("github-env");
    std::fs::write(&env_file, "")?;
    let out = Command::new("bash")
        .arg("-c")
        .arg(&script)
        .env("HOME", home)
        .env("RUNNER_NAME", "runner-7")
        .env("GITHUB_WORKSPACE", repo())
        .env("GITHUB_ENV", &env_file)
        .env("TARGET_DIR_NAME", dir)
        .output()?;
    let code = out.status.code().ok_or("killed by a signal")?;
    Ok((code, std::fs::read_to_string(&env_file)?))
}

#[test]
fn the_action_selects_the_named_directory_under_the_runner() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    for dir in ["target", "coverage-target"] {
        let (code, env) = select_target_dir(home.path(), dir)?;
        assert_eq!(code, 0, "dir `{dir}` was refused");
        let want = format!(
            "CARGO_TARGET_DIR={}/.cache/sipnab-ci/runner-7/{dir}\n",
            home.path().display()
        );
        assert_eq!(env, want, "dir `{dir}`");
    }
    Ok(())
}

#[test]
fn the_action_refuses_a_dir_that_leaves_the_runner_directory() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    for dir in [
        "",
        "..",
        "../runner-8/target",
        "a/b",
        "/tmp",
        "Target",
        "x y",
    ] {
        let (code, env) = select_target_dir(home.path(), dir)?;
        assert_ne!(code, 0, "dir `{dir}` was accepted");
        assert!(
            env.is_empty(),
            "dir `{dir}` was refused but still exported: {env}"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// scripts/ci-target-cap.sh, driven for real on temporary directories.
// ---------------------------------------------------------------------------

/// Run the cap script with `args`, returning its exit code.
fn cap(args: &[&str]) -> Result<i32, TestError> {
    let out = Command::new("bash")
        .arg(repo().join(CAP_SCRIPT))
        .args(args)
        .output()?;
    out.status
        .code()
        .ok_or_else(|| "the cap script was killed by a signal".into())
}

/// A directory holding `mib` MiB of real (non-sparse) data.
fn filled(root: &Path, mib: usize) -> Result<PathBuf, TestError> {
    let dir = root.join("target");
    std::fs::create_dir_all(dir.join("debug"))?;
    std::fs::write(dir.join("debug/blob"), vec![0x5au8; mib * 1024 * 1024])?;
    Ok(dir)
}

fn arg(p: &Path) -> Result<&str, TestError> {
    p.to_str().ok_or_else(|| "non-UTF-8 temp path".into())
}

#[test]
fn a_directory_under_the_cap_is_kept() -> Result<(), TestError> {
    let tmp = tempfile::tempdir()?;
    let dir = filled(tmp.path(), 1)?;
    let rc = cap(&[arg(&dir)?, "4M"])?;
    assert_eq!(rc, 0, "under the cap must exit 0");
    assert!(
        dir.join("debug/blob").exists(),
        "a 1 MiB directory under a 4 MiB cap was removed"
    );
    Ok(())
}

#[test]
fn a_directory_over_the_cap_is_removed() -> Result<(), TestError> {
    let tmp = tempfile::tempdir()?;
    let dir = filled(tmp.path(), 3)?;
    let rc = cap(&[arg(&dir)?, "2M"])?;
    assert_eq!(rc, 0, "over the cap must exit 0 after removing it");
    assert!(!dir.exists(), "a 3 MiB directory over a 2 MiB cap was kept");
    assert!(
        tmp.path().exists(),
        "the cap removed the directory's parent"
    );
    Ok(())
}

#[test]
fn a_missing_directory_is_not_an_error() -> Result<(), TestError> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("never-built");
    let rc = cap(&[arg(&dir)?, "64G"])?;
    assert_eq!(
        rc, 0,
        "a runner's first job has no directory yet; that is fine"
    );
    Ok(())
}

#[test]
fn bad_arguments_exit_2() -> Result<(), TestError> {
    let tmp = tempfile::tempdir()?;
    let dir = filled(tmp.path(), 1)?;
    let d = arg(&dir)?;
    for args in [
        vec![],
        vec![d],
        vec![d, "64G", "extra"],
        vec![d, "64"],
        vec![d, "0G"],
        vec![d, "-1G"],
        vec![d, "64T"],
        vec!["relative/target", "64G"],
        vec!["", "64G"],
        vec!["/", "1M"],
    ] {
        let rc = cap(&args)?;
        assert_eq!(rc, 2, "arguments {args:?} must be refused with exit 2");
    }
    assert!(
        dir.join("debug/blob").exists(),
        "a refused invocation removed something"
    );
    Ok(())
}

/// The minutes a job's `Slowest run measured on the self-hosted runners: N
/// min` comment records, if it has one.
fn measured_minutes(body: &str) -> Option<f64> {
    body.lines().find_map(|l| {
        let rest = l
            .trim()
            .strip_prefix("# Slowest run measured on the self-hosted runners:")?;
        rest.trim().strip_suffix("min")?.trim().parse().ok()
    })
}

/// The job's own `timeout-minutes`, at job level (four spaces in).
fn timeout_minutes(body: &str) -> Option<f64> {
    body.lines()
        .find_map(|l| l.strip_prefix("    timeout-minutes:"))
        .and_then(|v| v.trim().parse().ok())
}

/// A self-hosted job's timeout bounds a WEDGED job, not a slow one: it must
/// clear the slowest successful run measured on those runners by half again.
///
/// Coverage moved to the self-hosted runners with the 40-minute timeout it had
/// on GitHub's, where it took 15 to 21 minutes. On the self-hosted runners it
/// took 27 to 35, and a cold build or a host carrying other builds ran it past
/// 40: the timeout canceled healthy runs, and a canceled run on a tagged
/// commit holds the release (2026-10-18 and 19).
#[test]
fn a_self_hosted_timeout_clears_its_slowest_measured_run() -> Result<(), TestError> {
    let mut checked = 0;
    for job in all_jobs()?.iter().filter(|j| runs_self_hosted(&j.body)) {
        let Some(measured) = measured_minutes(&job.body) else {
            continue;
        };
        let timeout = timeout_minutes(&job.body)
            .ok_or_else(|| format!("{}/{} has no timeout-minutes", job.workflow, job.id))?;
        assert!(
            timeout >= 1.5 * measured,
            "{}/{}: timeout-minutes {timeout} does not clear the slowest measured run \
             ({measured} min) by half again ({} min), so a slow healthy run is canceled",
            job.workflow,
            job.id,
            1.5 * measured
        );
        checked += 1;
    }
    assert!(
        checked >= 1,
        "no self-hosted job records its slowest measured run, so this gate checks nothing"
    );
    Ok(())
}
