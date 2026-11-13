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

/// The job runs on a self-hosted runner, or is written to: it carries the
/// runner-target step, which applies on a self-hosted runner only. Check's
/// Linux leg, the feature matrix and Coverage ran on the self-hosted runners
/// from 2026-10-09 to 2026-10-27 and keep that shape, so routing one back is
/// a change to its `runs-on:` alone, and the rules below hold it either way.
fn can_run_self_hosted(body: &str) -> bool {
    runs_self_hosted(body) || body.contains(ACTION_USE)
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
    // The runner's per-job temporary directory: its own runner's, outside
    // the workspace, and a pooled job removes it at the end
    // (a_pooled_job_builds_in_its_own_directory_and_removes_it).
    if value.starts_with("${{ runner.temp }}/") {
        return None;
    }
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
/// (`ubuntu-24.04`), a literal list (`[self-hosted, jetson]`), and the
/// one-condition expression `${{ matrix.os == 'X' && A || B }}`, where `A`
/// and `B` are a quoted label or `fromJSON('[...]')`. Anything else is an
/// error, so a new shape fails here instead of being read as no labels.
/// A literal label list, `[a, b]` or `["a","b"]`.
fn list(text: &str) -> Vec<String> {
    text.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|l| l.trim().trim_matches('"').trim_matches('\'').to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// One value of a `runs-on:` expression: a quoted label or `fromJSON('[...]')`.
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

fn runner_labels(runs_on: &str, os: &str) -> Result<Vec<String>, TestError> {
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

/// The jobs every push runs take GitHub's runners, not the self-hosted ones.
///
/// Until 2026-10-27 the Linux leg of Check, the feature matrix and Coverage ran
/// on the four aarch64 self-hosted runners. Those share one machine's 14
/// cores with the local gates' build queue, and on 2026-10-27 that queue held
/// about 20 entries with a wait of about two hours while the runners' test
/// jobs were among the busiest processes on the machine. The repository is
/// public, so GitHub's runners cost nothing, and the three moved back on
/// 2026-10-27. `ubuntu-24.04-arm` keeps the aarch64 builds these jobs had.
#[test]
fn the_per_push_jobs_run_on_github_hosted_runners() -> Result<(), TestError> {
    let jobs = all_jobs()?;
    let arm = vec!["ubuntu-24.04-arm".to_string()];

    for id in ["check", "test"] {
        let value = runs_on(job(&jobs, "ci.yml", id)?)?;
        assert_eq!(
            runner_labels(value, "ubuntu-24.04")?,
            arm,
            "ci.yml {id}: the Linux leg must run on ubuntu-24.04-arm (runs-on: {value})"
        );
    }
    let mac = runs_on(job(&jobs, "ci.yml", "check-macos")?)?;
    assert_eq!(
        runner_labels(mac, "macos-26")?,
        vec!["macos-26".to_string()],
        "ci.yml check-macos: the macOS leg must run on macos-26 (runs-on: {mac})"
    );
    // The feature combinations left GitHub's runners on 2026-11-03 for the
    // pooled self-hosted runners;
    // a_self_hosted_job_takes_overflow_or_x64_unless_it_needs_the_aarch64_host
    // holds them there.
    let coverage = runs_on(job(&jobs, "quality.yml", "coverage")?)?;
    assert_eq!(
        runner_labels(coverage, "")?,
        arm,
        "quality.yml coverage must run on ubuntu-24.04-arm (runs-on: {coverage})"
    );
    Ok(())
}

/// One light x86_64 job runs on the x86_64 self-hosted runner.
///
/// That runner is a four-core VM with 6 GB of memory, registered for this
/// repository only, and one Rust build at a time is all it holds. The RPM
/// packaging job builds no Rust: it runs `rpmbuild` over stub ELFs, and the
/// runner already has every package it names, so it installs nothing there.
#[test]
fn the_rpm_packaging_job_runs_on_the_x86_64_self_hosted_runner() -> Result<(), TestError> {
    let jobs = all_jobs()?;
    let value = runs_on(job(&jobs, "ci.yml", "rpm-packaging")?)?;
    assert_eq!(
        runner_labels(value, "")?,
        vec!["self-hosted".to_string(), "X64".to_string()],
        "ci.yml rpm-packaging must run on [self-hosted, X64] (runs-on: {value})"
    );
    Ok(())
}

/// GitHub-hosted images a job may name.
const HOSTED_IMAGES: &[&str] = &["ubuntu-24.04", "ubuntu-24.04-arm", "macos-26"];

/// The self-hosted pools, each by a label that names no machine:
/// `jetson` is the four aarch64 runners, `overflow` the two of them whose
/// services run at the lowest CPU and I/O priority, and `X64` the one x86_64
/// runner. Never a machine's name: tests/private_identity_test.rs B6 says why.
const SELF_HOSTED_POOLS: &[&str] = &["jetson", "overflow", "X64"];

/// The jobs that may take any `jetson` runner, and why each needs the
/// aarch64 host itself rather than spare capacity on it. Every other
/// self-hosted job takes the `overflow` runners, which use only the CPU and
/// I/O the host's local gates leave idle, or the `X64` runner.
const AARCH64_HOST_ONLY: &[(&str, &str, &str)] = &[
    (
        "ci.yml",
        "features",
        "only on a push to main, whose run waited 34 and 68 minutes for the \
         two overflow runners behind pull request runs on 2026-11-11 (run \
         42977445618); every other event keeps the overflow pair, and \
         scripts/tests/test_feature_matrix_runner.py holds that split",
    ),
    (
        "bench.yml",
        "throughput",
        "the throughput baseline was measured on this hardware",
    ),
    (
        "memcheck.yml",
        "memcheck",
        "valgrind is installed on the aarch64 runners",
    ),
    (
        "reproducible.yml",
        "reproducible",
        "the eBPF toolchain's bpf-linker is installed there",
    ),
    (
        "self-hosted-smoke.yml",
        "smoke",
        "it exists to prove an aarch64 runner can build",
    ),
];

/// The pooled self-hosted jobs: those on `overflow` or `X64`.
fn pooled_jobs() -> Result<Vec<Job>, TestError> {
    let mut out = Vec::new();
    for job in all_jobs()? {
        let Some(sels) = selections(&job)? else {
            continue;
        };
        if sels
            .iter()
            .any(|s| s.iter().any(|l| l == "overflow" || l == "X64"))
        {
            out.push(job);
        }
    }
    Ok(out)
}

/// A self-hosted job takes the shared capacity, not the aarch64 host's own
/// runners, unless it needs that host.
///
/// Runners 1 and 2 of the aarch64 host serve the jobs that need it; runners 3
/// and 4 carry `overflow` and run at CPUWeight=1, IOWeight=1, Nice=19, so a
/// job there uses only what the host's local gates leave idle. A job that
/// named `jetson` for capacity would take a full-priority runner beside the
/// local gates.
#[test]
fn a_self_hosted_job_takes_overflow_or_x64_unless_it_needs_the_aarch64_host()
-> Result<(), TestError> {
    let mut defects = Vec::new();
    let mut jetson = Vec::new();
    for job in all_jobs()? {
        let Some(sels) = selections(&job)? else {
            continue;
        };
        if !sels.iter().any(|s| s.iter().any(|l| l == "jetson")) {
            continue;
        }
        jetson.push(format!("{}:{}", job.workflow, job.id));
        if !AARCH64_HOST_ONLY
            .iter()
            .any(|(w, j, _)| *w == job.workflow && *j == job.id)
        {
            defects.push(format!(
                "{}:{} takes a `jetson` runner; take `[self-hosted, overflow]` or \
                 `[self-hosted, X64]`, or add it to AARCH64_HOST_ONLY with the reason",
                job.workflow, job.id
            ));
        }
    }
    for (w, j, _) in AARCH64_HOST_ONLY {
        assert!(
            jetson.iter().any(|x| *x == format!("{w}:{j}")),
            "{w}:{j} is listed in AARCH64_HOST_ONLY but no longer takes a `jetson` runner"
        );
    }
    assert!(defects.is_empty(), "{}", defects.join("\n"));
    let pooled = pooled_jobs()?;
    assert!(
        pooled
            .iter()
            .any(|j| j.workflow == "ci.yml" && j.id == "features"),
        "the feature combinations must run on the pooled runners"
    );
    Ok(())
}

/// A job-level `env:` names no `runner` context.
///
/// GitHub evaluates a job's `env:` before it assigns a runner, so the
/// `runner` context does not exist there, and a workflow that uses it is
/// invalid as a whole: every job of the run is refused, the required check
/// with them. The first push of the pooled feature jobs set
/// `CARGO_TARGET_DIR: ${{ runner.temp }}/...` at job level and CI refused
/// the file (run 41763896012, "Unrecognized named-value: 'runner'"). A
/// step's `env:` may use it.
#[test]
fn no_job_level_env_reads_the_runner_context() -> Result<(), TestError> {
    let mut defects = Vec::new();
    let mut envs = 0;
    for job in all_jobs()? {
        let mut in_env = false;
        for line in job.body.lines() {
            if line == "    env:" {
                in_env = true;
                envs += 1;
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if in_env && !line.trim().is_empty() && indent <= 4 {
                in_env = false;
            }
            if in_env && line.contains("runner.") && line.contains("${{") {
                defects.push(format!("{}:{}: {}", job.workflow, job.id, line.trim()));
            }
        }
    }
    assert!(
        envs >= 1,
        "no job-level env: block found; the scan is wrong"
    );
    assert!(
        defects.is_empty(),
        "a job-level env: uses the runner context, which does not exist there, \
         so GitHub refuses the whole workflow; set it on the steps instead:\n{}",
        defects.join("\n")
    );
    Ok(())
}

const DISK_FLOOR_SCRIPT: &str = "scripts/ci-disk-floor.sh";

/// A job on the x86_64 runner refuses to start short of disk.
///
/// That runner is a virtual machine on a host that also runs other virtual
/// machines; a build that filled its disk would stop them as well. So the
/// step right after checkout, which brings the script, is the floor, before
/// any other step.
#[test]
fn an_x64_job_refuses_to_start_with_less_than_25_gb_free() -> Result<(), TestError> {
    let mut checked = 0;
    for job in pooled_jobs()? {
        let Some(sels) = selections(&job)? else {
            continue;
        };
        if !sels.iter().any(|s| s.iter().any(|l| l == "X64")) {
            continue;
        }
        checked += 1;
        let steps = steps_of(&job.body);
        assert!(
            steps
                .first()
                .is_some_and(|s| s.contains("uses: actions/checkout@")),
            "{}:{}: the first step must be the checkout",
            job.workflow,
            job.id
        );
        let floor = steps.get(1).map(String::as_str).unwrap_or_default();
        assert!(
            floor.contains(&format!("run: bash {DISK_FLOOR_SCRIPT} 25"))
                && step_if(floor).is_none(),
            "{}:{}: the step after checkout must be `bash {DISK_FLOOR_SCRIPT} 25`, \
             unconditional, before any build:\n{floor}",
            job.workflow,
            job.id
        );
    }
    assert!(
        checked >= 1,
        "no job on the x86_64 runner found; the scan is wrong"
    );
    // The floor itself, driven: a floor no disk meets refuses, zero admits.
    let run = |gb: &str| -> Result<std::process::Output, TestError> {
        Ok(Command::new("bash")
            .arg(repo().join(DISK_FLOOR_SCRIPT))
            .arg(gb)
            .arg(std::env::temp_dir())
            .output()?)
    };
    let refused = run("999999999")?;
    assert!(
        !refused.status.success(),
        "a floor above the free space must fail"
    );
    let text = String::from_utf8_lossy(&refused.stdout).into_owned()
        + &String::from_utf8_lossy(&refused.stderr);
    assert!(
        text.contains("::error::") && text.contains("999999999"),
        "the refusal must say why, as a workflow error: {text}"
    );
    assert!(run("0")?.status.success(), "a floor of 0 GB must pass");
    assert!(
        !run("lots")?.status.success(),
        "a non-number floor must be refused"
    );
    Ok(())
}

/// A pooled job builds in a directory of its own, and removes it however the
/// job ends.
///
/// The pooled runners are persistent and shared with other work, and a
/// build directory is tens of gigabytes. So the job points CARGO_TARGET_DIR
/// under the runner's per-job temporary directory and a final step, `if:
/// always()`, removes it.
#[test]
fn a_pooled_job_builds_in_its_own_directory_and_removes_it() -> Result<(), TestError> {
    let pooled = pooled_jobs()?;
    let mut checked = 0;
    for job in &pooled {
        if cargo_lines(&job.body).is_empty() && !job.body.contains("check-feature-matrix.py") {
            continue;
        }
        checked += 1;
        let label = format!("{}:{}", job.workflow, job.id);
        let value = target_dir_value(&job.body)
            .ok_or_else(|| format!("{label}: sets no CARGO_TARGET_DIR"))?;
        assert!(
            value.starts_with("${{ runner.temp }}/"),
            "{label}: CARGO_TARGET_DIR `{value}` is not under the runner's per-job \
             temporary directory"
        );
        let steps = steps_of(&job.body);
        let last = steps.last().ok_or("no steps")?;
        assert!(
            step_if(last) == Some("always()") && last.contains("rm -rf \"$CARGO_TARGET_DIR\""),
            "{label}: the last step must remove $CARGO_TARGET_DIR `if: always()`:\n{last}"
        );
    }
    assert!(checked >= 1, "no pooled cargo job found; the scan is wrong");
    Ok(())
}

/// The comment a self-hosted job carries to say why it is not on GitHub's
/// runners.
const SELF_HOSTED_REASON: &str = "# Self-hosted because:";

/// Why the labels `labels` are not an allowed runner selection, if they are
/// not one.
///
/// A selection is one GitHub-hosted image, or `self-hosted` with exactly one
/// pool label. `self-hosted` alone takes any self-hosted runner the
/// repository has, an aarch64 one or the x86_64 one, so the job's
/// architecture would depend on which was idle.
fn runner_defect(labels: &[String]) -> Option<String> {
    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    match refs.as_slice() {
        [image] if HOSTED_IMAGES.contains(image) => None,
        ["self-hosted"] => Some(
            "the bare `self-hosted` label takes any self-hosted runner; name its pool \
             (one of jetson, X64)"
                .to_string(),
        ),
        ["self-hosted", pool] if SELF_HOSTED_POOLS.contains(pool) => None,
        ["self-hosted", other] => Some(format!(
            "`{other}` is not a self-hosted pool label (one of jetson, X64)"
        )),
        _ => Some(format!(
            "{labels:?} is neither one GitHub-hosted image ({HOSTED_IMAGES:?}) nor \
             [self-hosted, <pool>]"
        )),
    }
}

/// The values a job's matrix gives `os`.
fn matrix_os_values(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let t = line.trim_start();
        let t = t.strip_prefix("- ").unwrap_or(t);
        let Some(v) = t.strip_prefix("os:") else {
            continue;
        };
        let v = v.trim();
        if v.starts_with('[') {
            out.extend(
                v.trim_matches(|c| c == '[' || c == ']')
                    .split(',')
                    .map(|s| s.trim().to_string()),
            );
        } else {
            out.push(v.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Every label set a job's `runs-on:` can select. `None` for a job that calls
/// a reusable workflow, which chooses its own runner.
fn selections(job: &Job) -> Result<Option<Vec<Vec<String>>>, TestError> {
    let Ok(value) = runs_on(job) else {
        let calls = job.body.lines().any(|l| l.starts_with("    uses:"));
        return if calls {
            Ok(None)
        } else {
            Err(format!("{}:{} has no runs-on", job.workflow, job.id).into())
        };
    };
    let Some(expr) = value.strip_prefix("${{").and_then(|r| r.strip_suffix("}}")) else {
        return Ok(Some(vec![runner_labels(value, "")?]));
    };
    if expr.trim() == "matrix.os" {
        let values = matrix_os_values(&job.body);
        if values.is_empty() {
            return Err(format!(
                "{}:{}: runs-on is matrix.os with no os values",
                job.workflow, job.id
            )
            .into());
        }
        return Ok(Some(values.into_iter().map(|v| vec![v]).collect()));
    }
    // A conditional: every operand that is not a comparison is a value.
    let mut out = Vec::new();
    for part in expr.split("||").flat_map(|p| p.split("&&")) {
        let t = strip_grouping(part);
        if t.contains("==") || t.contains("!=") {
            continue;
        }
        out.push(operand(t)?);
    }
    if out.is_empty() {
        return Err(format!("{}:{}: no runner in `{value}`", job.workflow, job.id).into());
    }
    Ok(Some(out))
}

/// One operand of `a && b || c` without the grouping parentheses around
/// it. A `)` is removed only while the operand has more `)` than `(`, so
/// `fromJSON('[...]')` keeps its own.
fn strip_grouping(part: &str) -> &str {
    let mut t = part.trim().trim_start_matches('(').trim();
    while t.ends_with(')') && t.matches(')').count() > t.matches('(').count() {
        t = t[..t.len() - 1].trim_end();
    }
    t
}

/// The reason a self-hosted job gives, if it gives one.
fn self_hosted_reason(body: &str) -> Option<&str> {
    body.lines()
        .find_map(|l| l.trim_start().strip_prefix(SELF_HOSTED_REASON))
        .map(str::trim)
        .filter(|r| r.split_whitespace().count() >= 4)
}

/// Every job runs on a GitHub-hosted image, or on a named self-hosted pool
/// with a written reason.
///
/// The self-hosted runners share their machines with other work, so a job
/// goes there only for something those machines have: hardware a measurement
/// depends on, a tool installed there, or relief for the hosted queue. The
/// reason is written on the job, beside its `runs-on:`, where whoever moves
/// it next reads it.
#[test]
fn every_job_runs_on_a_hosted_image_or_a_self_hosted_pool_with_a_reason() -> Result<(), TestError> {
    let mut defects = Vec::new();
    let mut self_hosted = 0;
    let mut hosted = 0;
    for job in all_jobs()? {
        let label = format!("{}:{}", job.workflow, job.id);
        let Some(sels) = selections(&job)? else {
            continue;
        };
        for sel in &sels {
            if let Some(why) = runner_defect(sel) {
                defects.push(format!("{label}: {why}"));
            }
        }
        if sels.iter().any(|s| s.iter().any(|l| l == "self-hosted")) {
            self_hosted += 1;
            if self_hosted_reason(&job.body).is_none() {
                defects.push(format!(
                    "{label}: runs on a self-hosted runner and gives no reason; add a \
                     `{SELF_HOSTED_REASON} ...` comment to the job"
                ));
            }
        } else {
            hosted += 1;
        }
    }
    assert!(
        self_hosted >= 5 && hosted >= 30,
        "found {self_hosted} self-hosted and {hosted} hosted job(s); the job scan is wrong"
    );
    assert!(defects.is_empty(), "{}", defects.join("\n"));
    Ok(())
}

/// The floating labels GitHub moves to a newer image on its own schedule.
const FLOATING_LABELS: &[&str] = &["ubuntu-latest", "macos-latest", "windows-latest"];

/// Lines of a workflow or composite action that name a floating runner
/// label outside a comment, as `LINE: text`.
///
/// The scan is of the text, not of `runs-on:` alone: a matrix value
/// (`os: [ubuntu-latest]`), an `include` entry, an expression
/// (`matrix.os == 'ubuntu-latest' && ...`), a job name and an artifact
/// pattern all carry the label into a check's name or a runner selection.
fn floating_label_lines(text: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let code = match line.find(" #") {
                _ if line.trim_start().starts_with('#') => "",
                Some(at) => &line[..at],
                None => line,
            };
            FLOATING_LABELS
                .iter()
                .any(|label| code.contains(label))
                .then(|| format!("{}: {}", i + 1, line.trim()))
        })
        .collect()
}

/// Every workflow and every composite action, as `(path, text)`.
fn workflow_and_action_files() -> Result<Vec<(String, String)>, TestError> {
    let mut out = Vec::new();
    let mut dirs = vec![
        repo().join(".github/workflows"),
        repo().join(".github/actions"),
    ];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
                let rel = path.strip_prefix(repo())?.to_string_lossy().into_owned();
                out.push((rel, std::fs::read_to_string(&path)?));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// No workflow and no composite action names a floating runner label.
///
/// On 2026-11-13 `ubuntu-latest` resolved to Ubuntu 26.04 for some runs and
/// to 24.04 for others, minutes apart (vcon-server run 43499382207: "Image:
/// ubuntu-26.04", where `playwright install --with-deps` then failed on
/// missing packages). `macos-latest` had already moved: main's CI run
/// 43490217694 ran `Check (macos-latest)` on "Image: macos-26-arm64". A job
/// that names a floating label changes its image without a commit, so a
/// failure it brings cannot be tied to a change. Each job names a fixed
/// image, and moving to a newer one is a commit that this gate and CI see.
#[test]
fn no_workflow_or_action_names_a_floating_runner_label() -> Result<(), TestError> {
    let files = workflow_and_action_files()?;
    assert!(
        files.len() >= 25,
        "found {} workflow and action file(s); the scan is wrong",
        files.len()
    );
    let mut defects = Vec::new();
    for (path, text) in &files {
        for line in floating_label_lines(text) {
            defects.push(format!("{path}:{line}"));
        }
    }
    assert!(
        defects.is_empty(),
        "{} line(s) name a floating runner label; name a fixed image (one of \
         {HOSTED_IMAGES:?}):\n{}",
        defects.len(),
        defects.join("\n")
    );
    Ok(())
}

/// The runner rule refuses each floating label by itself.
#[test]
fn the_runner_rule_refuses_a_floating_label() {
    for label in FLOATING_LABELS {
        assert!(
            runner_defect(&[(*label).to_string()]).is_some(),
            "`{label}` moves to a newer image without a commit and must be refused"
        );
        assert!(
            !HOSTED_IMAGES.contains(label),
            "`{label}` must not be in HOSTED_IMAGES"
        );
    }
    for image in HOSTED_IMAGES {
        assert!(
            !image.ends_with("-latest"),
            "`{image}` in HOSTED_IMAGES is a floating label"
        );
        assert!(
            runner_defect(&[(*image).to_string()]).is_none(),
            "the fixed image `{image}` must be admitted"
        );
    }
}

/// The text scan finds the label wherever a workflow can carry it, and
/// leaves a comment alone.
#[test]
fn the_floating_label_scan_reads_code_and_not_comments() {
    let found = |text: &str| floating_label_lines(text).len();
    assert_eq!(
        found("    runs-on: ubuntu-latest\n"),
        1,
        "a literal runs-on"
    );
    assert_eq!(found("        os: [macos-latest]\n"), 1, "a matrix list");
    assert_eq!(
        found("          - os: windows-latest\n"),
        1,
        "an include entry"
    );
    assert_eq!(
        found(
            "    runs-on: ${{ matrix.os == 'ubuntu-latest' && 'ubuntu-24.04-arm' || 'macos-26' }}\n"
        ),
        1,
        "an expression"
    );
    assert_eq!(
        found("    name: Test results (ubuntu-latest)\n"),
        1,
        "a job name"
    );
    assert_eq!(
        found("          pattern: test-shard-ubuntu-latest-*\n"),
        1,
        "an artifact pattern"
    );
    assert_eq!(
        found("    runs-on: ubuntu-24.04 # was ubuntu-latest until 2026-11-13\n"),
        0,
        "a trailing comment is history, not a selection"
    );
    assert_eq!(
        found("# ubuntu-latest moved on 2026-11-13\n"),
        0,
        "a comment at the first column"
    );
    assert_eq!(
        found("    # Check (macos-latest) failed on #601\n"),
        0,
        "a comment line"
    );
    assert_eq!(
        found("    runs-on: ubuntu-24.04\n    runs-on: macos-26\n"),
        0,
        "fixed images"
    );
    assert_eq!(
        found("        image: ghcr.io/example/tool:latest\n"),
        0,
        "another tool's `latest` tag is not a runner label"
    );
    assert_eq!(
        floating_label_lines("a: 1\n    runs-on: ubuntu-latest\n"),
        vec!["2: runs-on: ubuntu-latest".to_string()],
        "the line number is 1-based"
    );
}

/// The runner rule refuses what it exists to refuse, and admits the
/// selections the workflows use.
#[test]
fn the_runner_rule_refuses_a_bare_or_unknown_self_hosted_label() {
    let v = |s: &[&str]| s.iter().map(|l| (*l).to_string()).collect::<Vec<_>>();
    assert_eq!(
        strip_grouping(" (matrix.language == 'swift'"),
        "matrix.language == 'swift'",
        "a leading grouping parenthesis must be removed"
    );
    assert_eq!(
        strip_grouping(" 'macos-26') "),
        "'macos-26'",
        "a trailing grouping parenthesis must be removed"
    );
    assert_eq!(
        strip_grouping(r#" fromJSON('["self-hosted","jetson"]') "#),
        r#"fromJSON('["self-hosted","jetson"]')"#,
        "fromJSON must keep its own closing parenthesis"
    );
    assert!(
        runner_defect(&v(&["self-hosted"])).is_some(),
        "`self-hosted` must be refused"
    );
    assert!(
        runner_defect(&v(&["self-hosted", "build-host"])).is_some(),
        "`self-hosted, build-host` must be refused"
    );
    assert!(
        runner_defect(&v(&["self-hosted", "jetson", "X64"])).is_some(),
        "`self-hosted, jetson, X64` must be refused"
    );
    assert!(
        runner_defect(&v(&["jetson"])).is_some(),
        "`jetson` must be refused"
    );
    assert!(
        runner_defect(&v(&["ubuntu-24.04-arm", "self-hosted"])).is_some(),
        "`ubuntu-24.04-arm, self-hosted` must be refused"
    );
    assert!(
        runner_defect(&v(&["self-hosted", "jetson"])).is_none(),
        "`self-hosted, jetson` must be admitted"
    );
    assert!(
        runner_defect(&v(&["self-hosted", "X64"])).is_none(),
        "`self-hosted, X64` must be admitted"
    );
    assert!(
        runner_defect(&v(&["ubuntu-24.04-arm"])).is_none(),
        "`ubuntu-24.04-arm` must be admitted"
    );
    assert!(
        runner_defect(&v(&["macos-26"])).is_none(),
        "`macos-26` must be admitted"
    );
    assert!(
        self_hosted_reason("    # Self-hosted because: valgrind is installed there\n").is_some(),
        "`# Self-hosted because: valgrind is installed theren` must be accepted as a reason"
    );
    assert!(
        self_hosted_reason("    # Self-hosted because: yes\n").is_none(),
        "`# Self-hosted because: yesn` must be refused as a reason"
    );
    assert!(
        self_hosted_reason("    # self-hosted on purpose\n").is_none(),
        "`# self-hosted on purposen` must be refused as a reason"
    );
}

/// Whether some selection of the job is a GitHub-hosted Linux image.
fn has_hosted_linux_leg(job: &Job) -> Result<bool, TestError> {
    Ok(selections(job)?.is_some_and(|sels| {
        sels.iter()
            .any(|s| s.len() == 1 && s[0].starts_with("ubuntu-"))
    }))
}

/// A job written to run on either kind of runner: it carries the
/// runner-target step, which applies on a self-hosted runner only.
fn written_for_both(job: &Job) -> bool {
    job.body.contains(ACTION_USE)
}

/// Jobs that run on GitHub's runners with no cargo cache, and why.
const UNCACHED: &[(&str, &str, &str)] = &[(
    "quality.yml",
    "coverage",
    "its 5.0 GB instrumented entry cost what its hit saved (tests/ci_cache_policy_test.rs)",
)];

/// A job written for both kinds of runner, on a hosted Linux leg, gets back
/// what a disposable VM needs: disk freed before the build, and its cargo
/// build restored from the cache.
///
/// On the self-hosted runners these steps are skipped, so a job that ran
/// there for a while can lose them without any run noticing. Then a hosted
/// build of `--all-features --all-targets` runs out of disk, or rebuilds
/// every crate on every run.
#[test]
fn a_hosted_leg_frees_disk_and_restores_its_cargo_cache() -> Result<(), TestError> {
    let mut checked = 0;
    let mut defects = Vec::new();
    for job in all_jobs()? {
        if !written_for_both(&job) || !has_hosted_linux_leg(&job)? {
            continue;
        }
        checked += 1;
        let label = format!("{}:{}", job.workflow, job.id);
        let steps = steps_of(&job.body);
        let first_cargo = steps.iter().position(|s| !cargo_lines(s).is_empty());
        let free_disk = steps
            .iter()
            .position(|s| s.contains("uses: ./.github/actions/free-disk") && hosted_only(s));
        match (free_disk, first_cargo) {
            (None, _) => defects.push(format!(
                "{label}: no `free-disk` step guarded by `if: {HOSTED_ONLY}`"
            )),
            (Some(f), Some(c)) if f > c => {
                defects.push(format!("{label}: frees disk after the first cargo command"))
            }
            _ => {}
        }
        let uncached = UNCACHED
            .iter()
            .any(|(w, j, _)| *w == job.workflow && *j == job.id);
        let restores = steps
            .iter()
            .any(|s| s.contains("uses: actions/cache/restore@") && hosted_only(s));
        if !uncached && !restores {
            defects.push(format!(
                "{label}: no cargo cache restore guarded by `if: {HOSTED_ONLY}`"
            ));
        }
        if uncached && restores {
            defects.push(format!(
                "{label}: restores a cargo cache it is listed without"
            ));
        }
    }
    assert!(
        checked >= 3,
        "only {checked} job(s) written for both kinds of runner have a hosted Linux leg; \
         the job scan is wrong"
    );
    assert!(defects.is_empty(), "{}", defects.join("\n"));
    Ok(())
}

/// What a job's steps run that a hosted image need not have, and the Ubuntu
/// package that provides it.
///
/// The self-hosted machine has all of these installed, so a job that ran
/// there could drop its install and stay green until it ran on a fresh VM.
/// `ubuntu-24.04` packages yanglint as `libyang2-tools`; there is no
/// `libyang3-tools` in that release.
const NEEDS: &[(&str, &str)] = &[
    ("check-yang.py", "libyang2-tools"),
    ("tui_e2e_test", "tmux"),
    ("smoke-clients.sh", "tshark"),
    // libopus, which the `opus` feature builds with cmake (opusic-sys).
    ("--all-features", "cmake"),
    // The feature combinations, among them `opus`, from
    // .github/feature-combos.txt.
    ("check-feature-matrix.py", "cmake"),
    ("--all-features", "libpcap-dev"),
    ("--all-features", "libasound2-dev"),
];

/// Whether a trimmed line of a job runs `trigger`. A trigger written as a
/// list item (`- opus`) is a matrix entry and matches the whole line.
fn runs(line: &str, trigger: &str) -> bool {
    if trigger.starts_with("- ") {
        line == trigger
    } else {
        line.contains(trigger)
    }
}

/// The packages a job's Linux `system-deps` steps install.
fn linux_packages(job: &Job) -> Vec<String> {
    steps_of(&job.body)
        .iter()
        .filter(|s| s.contains("uses: ./.github/actions/system-deps"))
        .filter(|s| step_if(s).is_none_or(|c| !c.contains("macOS")))
        .flat_map(|s| {
            s.lines()
                .filter_map(|l| l.trim_start().strip_prefix("packages:"))
                .flat_map(|v| v.split_whitespace().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// What a job's steps run that the pinned toolchain installs only when asked,
/// and the rustup component that provides it.
///
/// `dtolnay/rust-toolchain` installs the minimal profile, which has neither
/// clippy nor rustfmt. The self-hosted machine has both installed for its
/// own use, so the feature matrix ran `cargo clippy` there for a month
/// without asking for the component, and every leg but wasm failed on its
/// first hosted run (2026-10-28, "'cargo-clippy' is not installed for the
/// toolchain").
const COMPONENT_NEEDS: &[(&str, &str)] = &[
    ("cargo clippy", "clippy"),
    ("cargo fmt", "rustfmt"),
    ("cargo llvm-cov", "llvm-tools-preview"),
];

/// The rustup components a job's toolchain steps ask for.
fn toolchain_components(job: &Job) -> Vec<String> {
    steps_of(&job.body)
        .iter()
        .filter(|s| s.contains("uses: dtolnay/rust-toolchain@"))
        .flat_map(|s| {
            s.lines()
                .filter_map(|l| l.trim_start().strip_prefix("components:"))
                .flat_map(|v| v.split(',').map(|c| c.trim().to_string()))
                .collect::<Vec<_>>()
        })
        .filter(|c| !c.is_empty())
        .collect()
}

/// A job written for both kinds of runner asks its toolchain step for every
/// component its steps run.
#[test]
fn a_hosted_leg_installs_the_toolchain_components_its_steps_run() -> Result<(), TestError> {
    let mut checked = 0;
    let mut defects = Vec::new();
    for job in all_jobs()? {
        if !written_for_both(&job) || !has_hosted_linux_leg(&job)? {
            continue;
        }
        checked += 1;
        let components = toolchain_components(&job);
        let runs_line = |trigger: &str| {
            job.body
                .lines()
                .map(str::trim)
                .any(|l| !l.starts_with('#') && l.contains(trigger))
        };
        for (trigger, component) in COMPONENT_NEEDS {
            if runs_line(trigger) && !components.iter().any(|c| c == component) {
                defects.push(format!(
                    "{}:{}: runs `{trigger}` and its toolchain step asks for no `{component}`",
                    job.workflow, job.id
                ));
            }
        }
    }
    assert!(
        checked >= 3,
        "only {checked} job(s) checked; the job scan is wrong"
    );
    assert!(defects.is_empty(), "{}", defects.join("\n"));
    Ok(())
}

/// A job written for both kinds of runner installs, on its hosted Linux leg,
/// every package its steps need.
#[test]
fn a_hosted_leg_installs_what_its_steps_need() -> Result<(), TestError> {
    let mut checked = 0;
    let mut defects = Vec::new();
    for job in all_jobs()? {
        if !written_for_both(&job) || !has_hosted_linux_leg(&job)? {
            continue;
        }
        checked += 1;
        let installed = linux_packages(&job);
        let text: String = job
            .body
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .map(|l| format!("{}\n", l.trim()))
            .collect();
        for (trigger, package) in NEEDS {
            let needed = text.lines().any(|l| runs(l, trigger));
            if needed && !installed.iter().any(|p| p == package) {
                defects.push(format!(
                    "{}:{}: runs `{trigger}` and installs no `{package}`",
                    job.workflow, job.id
                ));
            }
        }
    }
    assert!(
        checked >= 3,
        "only {checked} job(s) checked; the job scan is wrong"
    );
    assert!(defects.is_empty(), "{}", defects.join("\n"));
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
        if !can_run_self_hosted(&job.body) {
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
        if !can_run_self_hosted(&job.body) {
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
        if !job.body.contains(ACTION_USE) {
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
        if !job.body.contains(ACTION_USE) {
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
        "no job carrying the runner-target step runs cargo llvm-cov; this gate is reading the wrong jobs"
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

/// The comments that record a job's slowest measured run, one per kind of
/// runner, each followed by `N min`.
const MEASURED: &[&str] = &[
    "# Slowest run measured on the self-hosted runners:",
    "# Slowest run measured on GitHub's runners:",
];

/// The minutes a job's slowest-measured-run comment records, if it has one.
fn measured_minutes(body: &str) -> Option<f64> {
    body.lines().find_map(|l| {
        let t = l.trim();
        let rest = MEASURED.iter().find_map(|m| t.strip_prefix(m))?;
        rest.trim().strip_suffix("min")?.trim().parse().ok()
    })
}

/// The job's own `timeout-minutes`, at job level (four spaces in).
fn timeout_minutes(body: &str) -> Option<f64> {
    body.lines()
        .find_map(|l| l.strip_prefix("    timeout-minutes:"))
        .and_then(|v| v.trim().parse().ok())
}

/// A job's timeout bounds a WEDGED job, not a slow one: it must clear the
/// slowest successful run measured on its runners by half again.
///
/// Coverage moved to the self-hosted runners with the 40-minute timeout it had
/// on GitHub's, where it took 15 to 21 minutes. On the self-hosted runners it
/// took 27 to 35, and a cold build or a host carrying other builds ran it past
/// 40: the timeout canceled healthy runs, and a canceled run on a tagged
/// commit holds the release (2026-10-18 and 19).
#[test]
fn a_timeout_clears_its_slowest_measured_run() -> Result<(), TestError> {
    let mut checked = 0;
    for job in &all_jobs()? {
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
    // Check, the feature matrix, Coverage and the RPM packaging job.
    assert!(
        checked >= 4,
        "only {checked} job(s) record their slowest measured run; the jobs \
         moved on 2026-10-27 must each record theirs"
    );
    Ok(())
}
