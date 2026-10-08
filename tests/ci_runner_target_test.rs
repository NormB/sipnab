// SPDX-License-Identifier: MIT OR Apache-2.0

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
