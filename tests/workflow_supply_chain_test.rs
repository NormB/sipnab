// SPDX-License-Identifier: MIT OR Apache-2.0

//! CI must not install a binary it has not checked the bytes of.
//!
//! Every `uses:` in this repo is pinned to a commit SHA rather than a tag,
//! because a tag is a movable label and a supply-chain review that stops at the
//! version number stops one step short. Two tools -- Zola and Vale -- arrive by
//! `curl` instead, and for a while they were pinned only by version: the URL
//! named `v0.19.2`, and whatever bytes GitHub served for that name got installed
//! into `/usr/local/bin` and run. A release asset can be replaced after
//! publication, so that is the same movable-label problem wearing a different
//! hat.
//!
//! The consequence is not theoretical for Zola specifically. It builds the site
//! that `pages.yml` publishes, in a job holding `pages: write` -- including the
//! download page telling users which sipnab binary to fetch. A swapped Zola is
//! therefore a path to rewriting sipnab's own install instructions.
//!
//! These tests exist because the fix is one line that a future edit can drop
//! without anything noticing. A new tool added the obvious way -- copy the
//! nearest install step, change the URL -- inherits a checksum line only if
//! something insists.
//!
//! Scope: this proves the *shape* holds, not that any hash is the right one. No
//! test can establish that from inside the repo; a hash is only ever as good as
//! the fetch that recorded it. What it does guarantee is that the bytes reaching
//! `install` are the bytes someone committed to, and that a silent substitution
//! fails the job instead of running.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn workflows() -> Vec<(String, String)> {
    let dir = repo().join(".github/workflows");
    let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .map(|p: PathBuf| {
            let name = p
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned();
            let body =
                std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
            (name, body)
        })
        .collect();
    out.sort();
    assert!(
        !out.is_empty(),
        "no workflow files found -- this suite would pass vacuously"
    );
    out
}

/// Split a workflow into YAML list items. A step's `env:` block and its `run:`
/// block live in the same item, which is the granularity the checks need: a
/// checksum is only meaningful if it guards the download sitting beside it.
fn steps(body: &str) -> Vec<String> {
    let mut chunks: Vec<String> = Vec::new();
    let mut cur = String::new();
    for line in body.lines() {
        if line.trim_start().starts_with("- ") && !cur.is_empty() {
            chunks.push(std::mem::take(&mut cur));
        }
        cur.push_str(line);
        cur.push('\n');
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }
    chunks
}

/// Every step that downloads a release artifact must verify it before use.
#[test]
fn no_workflow_installs_a_release_artifact_without_checking_its_bytes() {
    let mut checked = 0usize;
    let mut unchecked: Vec<String> = Vec::new();

    for (name, body) in workflows() {
        for step in steps(&body) {
            if !step.contains("releases/download/") {
                continue;
            }
            if step.contains("sha256sum -c") {
                checked += 1;
            } else {
                let label = step
                    .lines()
                    .find(|l| l.contains("name:"))
                    .map_or("<unnamed step>", str::trim)
                    .to_string();
                unchecked.push(format!("{name}: {label}"));
            }
        }
    }

    assert!(
        unchecked.is_empty(),
        "these steps download a release artifact and install it without verifying the bytes.\n\
         Pin the artifact by SHA-256 and check it before `install`:\n  {}",
        unchecked.join("\n  ")
    );

    // Without this the suite would pass by finding nothing to check -- exactly
    // what would happen if the URL shape changed or the splitter stopped working.
    assert!(
        checked >= 4,
        "expected at least the 4 known artifact downloads (2x Zola, Vale, Vale's Google \
         style package), found {checked}. Fewer means the scan stopped seeing them, not \
         that the risk went away"
    );
}

/// The Google style package is named in two places: `Packages =` in `.vale.ini`,
/// which is what a local `vale sync` follows, and `VALE_GOOGLE_URL` in the
/// workflow, which is the copy that gets checksummed. If those drift, CI lints
/// against a different rule set than a contributor's machine does, and the
/// checksum guards a package nobody else is using.
#[test]
fn the_vale_package_url_is_the_same_in_the_config_and_the_workflow() {
    let ini = std::fs::read_to_string(repo().join(".vale.ini")).expect("read .vale.ini");
    let from_ini = ini
        .lines()
        .find_map(|l| l.strip_prefix("Packages ="))
        .map(str::trim)
        .expect("`Packages =` not found in .vale.ini");

    let quality = std::fs::read_to_string(repo().join(".github/workflows/quality.yml"))
        .expect("read quality.yml");
    let from_workflow = quality
        .lines()
        .find_map(|l| l.trim().strip_prefix("VALE_GOOGLE_URL:"))
        .map(|v| v.trim().trim_matches(['\'', '"']).to_string())
        .expect("VALE_GOOGLE_URL not found in quality.yml");

    assert_eq!(
        from_ini, from_workflow,
        "the Vale package URL in .vale.ini and quality.yml disagree; the checksummed \
         download and the one `vale sync` performs are not the same package"
    );
}

/// A pinned hash has to be a whole SHA-256, not a prefix or a placeholder.
#[test]
fn every_pinned_checksum_is_a_full_sha256() {
    for (name, body) in workflows() {
        for line in body.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if !key.trim().ends_with("_SHA256") {
                continue;
            }
            let hash = value.trim().trim_matches(['\'', '"']);
            assert_eq!(
                hash.len(),
                64,
                "{name}: {} is {} chars; a SHA-256 is 64",
                key.trim(),
                hash.len()
            );
            assert!(
                hash.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "{name}: {} is not lowercase hex -- `sha256sum -c` compares textually",
                key.trim()
            );
        }
    }
}

/// Zola is installed by two different workflows. Both must agree on version and
/// hash, or one of them is quietly building the site with a different binary.
#[test]
fn a_tool_installed_by_more_than_one_workflow_is_pinned_identically() {
    let mut seen: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();

    for (name, body) in workflows() {
        for line in body.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim();
            if !(key.ends_with("_SHA256") || key.ends_with("_VERSION") || key.ends_with("_URL")) {
                continue;
            }
            let value = value.trim().trim_matches(['\'', '"']).to_string();
            if value.is_empty() || value.contains("${{") {
                continue;
            }
            seen.entry(key.to_string())
                .or_default()
                .entry(value)
                .or_default()
                .push(name.clone());
        }
    }

    for (key, values) in &seen {
        assert!(
            values.len() <= 1,
            "{key} is pinned to {} different values across workflows: {:?}. \
             One workflow is installing a different build than the other",
            values.len(),
            values
        );
    }

    // A bare hash is unmaintainable: the next person cannot tell what it is
    // supposed to be the hash OF, so they cannot re-derive it to check an
    // upgrade. Something adjacent has to identify the artifact -- either the
    // version that composes the URL, or the URL itself.
    for key in seen.keys().filter(|k| k.ends_with("_SHA256")) {
        let stem = key.trim_end_matches("_SHA256");
        let version = format!("{stem}_VERSION");
        let url = format!("{stem}_URL");
        assert!(
            seen.contains_key(&version) || seen.contains_key(&url),
            "{key} has neither {version} nor {url} beside it -- a hash that names no \
             artifact cannot be re-derived when the pin needs bumping"
        );
    }
    assert!(
        seen.keys().any(|k| k.ends_with("_SHA256")),
        "no *_SHA256 pins found at all -- the checks above would hold vacuously"
    );
}

/// Every job in every workflow bounds how long it may run.
///
/// # Why this is a supply-chain concern and not housekeeping
///
/// `ci.yml` deliberately does NOT supersede on `main`:
///
/// ```yaml
/// concurrency:
///   group: ci-${{ github.workflow }}-${{ github.ref }}
///   cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
/// ```
///
/// That is correct — every commit on main deserves a real verdict rather than
/// being cancelled by the next push, and it should stay. But it means a run
/// holds its concurrency group until it ENDS, and with no `timeout-minutes`
/// nothing bounds that.
///
/// On 2026-08-05 the two combined: run 31024491079 reached 20 completed jobs and
/// then its `CI success` aggregation job — the only check branch protection
/// requires — sat in `queued` with its dependencies already cancelled. It could
/// never finish. It held `ci-CI-refs/heads/main`, and the 0.5.83 release commit's
/// CI stayed `pending` with ZERO jobs created for 80 minutes. `gh run cancel`
/// stalled; only the force-cancel API cleared it.
///
/// The reason it went unnoticed that long is the reason it needs a gate rather
/// than a habit: a `pending` run with no jobs is indistinguishable from ordinary
/// runner contention. Blocked-forever and busy-be-patient render identically.
///
/// `pages.yml` shares the shape with `group: pages, cancel-in-progress: false`,
/// so it is covered here too rather than only `ci.yml`.
///
/// The values are not policed — only their presence. Sizing is a judgement call
/// against observed durations; having no bound at all is not.
#[test]
fn every_workflow_job_bounds_its_runtime() {
    let mut missing: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (name, body) in workflows() {
        // Only the `jobs:` mapping. `on:`, `env:`, `permissions:` and
        // `concurrency:` also carry two-space keys, and none of them is a job.
        let mut in_jobs = false;
        let mut current: Option<String> = None;
        let mut has_timeout = false;

        let close = |job: &Option<String>, found: bool, out: &mut Vec<String>| {
            if let Some(j) = job
                && !found
            {
                out.push(format!("{name}: job `{j}`"));
            }
        };

        for line in body.lines() {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();

            if indent == 0 && !trimmed.is_empty() && !trimmed.starts_with('#') {
                close(&current, has_timeout, &mut missing);
                current = None;
                in_jobs = trimmed.starts_with("jobs:");
                continue;
            }
            if !in_jobs {
                continue;
            }
            if indent == 2 && trimmed.ends_with(':') && !trimmed.starts_with('#') {
                close(&current, has_timeout, &mut missing);
                current = Some(trimmed.trim_end_matches(':').to_string());
                has_timeout = false;
                checked += 1;
            } else if current.is_some() && trimmed.starts_with("timeout-minutes:") && indent == 4 {
                has_timeout = true;
            }
        }
        close(&current, has_timeout, &mut missing);
    }

    // A parser that finds nothing reports a clean bill of health, which is
    // indistinguishable from a safe one.
    assert!(
        checked >= 20,
        "only {checked} workflow jobs parsed -- the scan is broken and a pass \
         here means nothing"
    );

    assert!(
        missing.is_empty(),
        "these workflow jobs set no `timeout-minutes`, so nothing bounds how \
         long they may hold their concurrency group:\n  {}\n\n\
         On main, ci.yml and pages.yml never supersede, so one job that wedges \
         blocks every later commit indefinitely -- and a `pending` run with no \
         jobs looks exactly like ordinary queueing. Size the value against the \
         job's observed duration with headroom; the number is a judgement call, \
         having one is not.",
        missing.join("\n  ")
    );
}
