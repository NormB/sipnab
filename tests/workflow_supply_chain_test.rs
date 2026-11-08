// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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

type TestError = Box<dyn std::error::Error>;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn workflows() -> Result<Vec<(String, String)>, TestError> {
    let dir = repo().join(".github/workflows");
    let mut out: Vec<(String, String)> = Vec::new();
    for e in std::fs::read_dir(&dir).map_err(|e| format!("read {}: {e}", dir.display()))? {
        let p: PathBuf = e.map_err(|e| format!("dir entry: {e}"))?.path();
        if !p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            continue;
        }
        let name = p
            .file_name()
            .ok_or("file name")?
            .to_string_lossy()
            .into_owned();
        let body = std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
        out.push((name, body));
    }
    out.sort();
    assert!(
        !out.is_empty(),
        "no workflow files found -- this suite would pass vacuously"
    );
    Ok(out)
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

/// Every composite action under `.github/actions/`, as (path, text).
fn composite_actions() -> Result<Vec<(String, String)>, TestError> {
    let dir = repo().join(".github/actions");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&dir).map_err(|e| format!("read {}: {e}", dir.display()))? {
        let p = e
            .map_err(|e| format!("dir entry: {e}"))?
            .path()
            .join("action.yml");
        if !p.is_file() {
            continue;
        }
        let rel = p.strip_prefix(repo()).unwrap_or(&p).display().to_string();
        let body = std::fs::read_to_string(&p).map_err(|e| format!("read {rel}: {e}"))?;
        out.push((rel, body));
    }
    out.sort();
    Ok(out)
}

/// The composite action every pinned release download goes through.
const PINNED_DOWNLOAD: &str = "uses: ./.github/actions/pinned-download";

/// The script that composite action runs, and release.yml runs directly.
const FETCH_PINNED: &str = "scripts/fetch-pinned.sh";

/// Why one step's release download breaks the one rule, or `None` when the
/// step does not download a release asset or does it through the rule.
///
/// The rule (CI-TOOL-DOWNLOAD-RESILIENCE): a step that names a
/// `releases/download/` URL either is a `pinned-download` step passing a
/// `sha256:` input, or runs `scripts/fetch-pinned.sh` with `--sha256`. It
/// never fetches with `curl` or `wget` itself: those were one live download
/// with about 25 s of retries, and github.com answered 504 for most of an
/// hour on 2026-11-08.
fn release_download_violation(step: &str) -> Option<&'static str> {
    if !step.contains("releases/download/") {
        return None;
    }
    let code: String = step
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let fetches_itself = code
        .split(|c: char| c.is_whitespace() || c == '(' || c == ';' || c == '|' || c == '&')
        .any(|w| w == "curl" || w == "wget" || w.ends_with("/curl") || w.ends_with("/wget"));
    if fetches_itself {
        return Some("fetches the release asset with curl or wget itself");
    }
    let through_action = code.contains(PINNED_DOWNLOAD)
        && code.lines().any(|l| l.trim_start().starts_with("sha256:"));
    let through_script = code.contains(FETCH_PINNED) && code.contains("--sha256");
    if through_action || through_script {
        None
    } else {
        Some("names a release asset without going through pinned-download or fetch-pinned.sh")
    }
}

/// The classifier accepts the two forms of the rule and rejects the rest.
#[test]
fn the_release_download_classifier_accepts_only_the_one_rule() {
    let url = "https://github.com/o/r/releases/download/v1/t.tgz";
    let action =
        format!("- name: Fetch\n  {PINNED_DOWNLOAD}\n  with:\n    sha256: abc\n    url: {url}\n");
    let script = format!(
        "- name: Fetch\n  run: |\n    bash {FETCH_PINNED} --url \"{url}\" --sha256 \"$S\" --dest t.tgz\n"
    );
    let bare_curl = format!("- name: Fetch\n  run: |\n    curl -fsSL -o t.tgz \"{url}\"\n");
    let checked_curl = format!(
        "- name: Fetch\n  run: |\n    curl --retry 5 -o t.tgz \"{url}\"\n    echo \"$S  t.tgz\" | sha256sum -c -\n"
    );
    let wget = format!("- name: Fetch\n  run: wget -q \"{url}\"\n");
    let unchecked_action = format!("- name: Fetch\n  {PINNED_DOWNLOAD}\n  with:\n    url: {url}\n");
    let script_and_curl = format!(
        "- name: Fetch\n  run: |\n    bash {FETCH_PINNED} --url u --sha256 s --dest d\n    (curl -o x \"{url}\")\n"
    );
    let commented = format!(
        "- name: Fetch\n  # once was: curl -o t.tgz {url}\n  {PINNED_DOWNLOAD}\n  with:\n    sha256: abc\n"
    );
    assert_eq!(release_download_violation(&action), None, "{action}");
    assert_eq!(release_download_violation(&script), None, "{script}");
    assert_eq!(
        release_download_violation(&commented),
        None,
        "a comment naming curl is not a fetch: {commented}"
    );
    assert_eq!(
        release_download_violation("- name: Build\n  run: cargo build\n"),
        None,
        "a step with no release URL is out of scope"
    );
    for bad in [
        &bare_curl,
        &checked_curl,
        &wget,
        &unchecked_action,
        &script_and_curl,
    ] {
        assert!(
            release_download_violation(bad).is_some(),
            "a download outside the one rule was accepted:\n{bad}"
        );
    }
}

/// Every step that downloads a release artifact goes through the one rule:
/// `.github/actions/pinned-download` (cache, then `scripts/fetch-pinned.sh`)
/// or, where no cache can help, `scripts/fetch-pinned.sh` itself. Both verify
/// the sha256 on every run, so this also proves no release asset is
/// installed unchecked.
#[test]
fn no_workflow_installs_a_release_artifact_without_checking_its_bytes() -> Result<(), TestError> {
    let mut checked = 0usize;
    let mut bad: Vec<String> = Vec::new();

    let mut files = workflows()?;
    files.extend(composite_actions()?);
    for (name, body) in files {
        for step in steps(&body) {
            if !step.contains("releases/download/") {
                continue;
            }
            checked += 1;
            if let Some(why) = release_download_violation(&step) {
                let label = step
                    .lines()
                    .find(|l| l.contains("name:"))
                    .map_or("<unnamed step>", str::trim)
                    .to_string();
                bad.push(format!("{name}: {label}: {why}"));
            }
        }
    }

    assert!(
        bad.is_empty(),
        "these steps download a release artifact outside the one rule. Use \
         {PINNED_DOWNLOAD} (or {FETCH_PINNED} where no cache can help), which \
         verifies the pinned sha256 on every run and retries an outage for up \
         to five minutes:\n  {}",
        bad.join("\n  ")
    );

    // Without this the suite would pass by finding nothing to check -- exactly
    // what would happen if the URL shape changed or the splitter stopped working.
    // The nine: Zola in pages.yml and three quality.yml jobs, Vale and its
    // Google style, bpf-linker in release.yml, and the pagefind and nextest
    // actions.
    assert!(
        checked >= 9,
        "expected at least the 9 known release downloads, found {checked}. Fewer \
         means the scan stopped seeing them, not that the risk went away"
    );
    Ok(())
}

/// `.github/actions/pinned-download` is one cached, verified rule.
///
/// It restores the archive from the actions cache under a key made of the
/// tool's name, version and sha256, runs `scripts/fetch-pinned.sh` on every
/// run (so a restored file is hashed before it is used, and fetched on a
/// miss), and saves only after a miss and only from `main`, as
/// tests/ci_cache_policy_test.rs requires of the cargo caches. The directory
/// is the job's own `runner.temp`: the self-hosted runners share one home
/// directory, and on run 42267347105 two jobs writing one file under it
/// corrupted each other's check.
#[test]
fn pinned_download_is_one_cached_and_verified_rule() -> Result<(), TestError> {
    const ACTION: &str = ".github/actions/pinned-download/action.yml";
    const KEY: &str = "key: pinned-${{ inputs.name }}-${{ inputs.version }}-${{ inputs.sha256 }}";
    const PATH: &str = "path: ${{ runner.temp }}/sipnab-pinned/${{ inputs.name }}";
    let action =
        std::fs::read_to_string(repo().join(ACTION)).map_err(|e| format!("read {ACTION}: {e}"))?;
    let parts: Vec<&str> = action.split("\n    - name: ").skip(1).collect();
    let find = |name: &str| -> Result<(usize, &str), TestError> {
        Ok(parts
            .iter()
            .enumerate()
            .find(|(_, s)| s.starts_with(name))
            .map(|(i, s)| (i, *s))
            .ok_or_else(|| format!("{ACTION} has no step named {name:?}"))?)
    };
    let (restore_at, restore) = find("Restore the pinned archive")?;
    let (fetch_at, fetch) = find("Verify the restored archive, or fetch it")?;
    let (save_at, save) = find("Save the pinned archive")?;
    assert!(
        restore.contains("uses: actions/cache/restore@")
            && restore.contains(KEY)
            && restore.contains(PATH),
        "the restore does not read the job's own directory under the pin key:\n{restore}"
    );
    assert!(
        save.contains("uses: actions/cache/save@") && save.contains(KEY) && save.contains(PATH),
        "the save does not write the key and directory the restore reads:\n{save}"
    );
    assert_eq!(
        action.matches("key: ").count(),
        2,
        "{ACTION} names a cache key other than the restore's and the save's"
    );
    assert!(
        !action.contains("~/.cache") && !action.contains("$HOME/.cache"),
        "{ACTION} keeps the archive under the shared home directory"
    );
    assert!(
        fetch.contains(FETCH_PINNED)
            && fetch.contains("--sha256 \"$SHA256\"")
            && fetch.contains("SHA256: ${{ inputs.sha256 }}"),
        "the fetch step does not run {FETCH_PINNED} against the pinned sha256:\n{fetch}"
    );
    assert!(
        !fetch.lines().any(|l| l.trim_start().starts_with("if:")),
        "the verify-or-fetch step is conditional, so a restored archive could \
         be used without its sha256 being checked:\n{fetch}"
    );
    assert!(
        save.contains(
            "if: steps.cache.outputs.cache-hit != 'true' && github.ref == 'refs/heads/main'"
        ),
        "the save runs on a hit or off main:\n{save}"
    );
    assert!(
        restore_at < fetch_at && fetch_at < save_at,
        "{ACTION} runs restore, verify-or-fetch and save out of order; a save \
         before the check stores bytes nobody checked"
    );
    Ok(())
}

/// The Google style package is named in two places: `Packages =` in `.vale.ini`,
/// which is what a local `vale sync` follows, and the URL quality.yml's fetch
/// step builds from `VALE_GOOGLE_VERSION`, which is the copy that gets
/// checksummed. If those drift, CI lints against a different rule set than a
/// contributor's machine does, and the checksum guards a package nobody else
/// is using.
#[test]
fn the_vale_package_url_is_the_same_in_the_config_and_the_workflow() -> Result<(), TestError> {
    let ini = std::fs::read_to_string(repo().join(".vale.ini"))
        .map_err(|e| format!("read .vale.ini: {e}"))?;
    let from_ini = ini
        .lines()
        .find_map(|l| l.strip_prefix("Packages ="))
        .map(str::trim)
        .ok_or("`Packages =` not found in .vale.ini")?;

    let quality = std::fs::read_to_string(repo().join(".github/workflows/quality.yml"))
        .map_err(|e| format!("read quality.yml: {e}"))?;
    let version = quality
        .lines()
        .find_map(|l| l.trim().strip_prefix("VALE_GOOGLE_VERSION:"))
        .map(|v| v.trim().trim_matches(['\'', '"']).to_string())
        .ok_or("VALE_GOOGLE_VERSION not found in quality.yml")?;
    let step = steps(&quality)
        .into_iter()
        .find(|s| s.contains("- name: Fetch the Vale Google style (pinned, cached)"))
        .ok_or("quality.yml has no step `Fetch the Vale Google style (pinned, cached)`")?;
    let url = step
        .lines()
        .find_map(|l| l.trim().strip_prefix("url:"))
        .map(str::trim)
        .ok_or("the Vale Google style fetch passes no url")?;
    let from_workflow = url.replace("${{ env.VALE_GOOGLE_VERSION }}", &version);

    assert_eq!(
        from_ini, from_workflow,
        "the Vale package URL in .vale.ini and quality.yml disagree; the checksummed \
         download and the one `vale sync` performs are not the same package"
    );
    Ok(())
}

/// A pinned hash has to be a whole SHA-256, not a prefix or a placeholder.
#[test]
fn every_pinned_checksum_is_a_full_sha256() -> Result<(), TestError> {
    for (name, body) in workflows()? {
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
    Ok(())
}

/// `pip install pytest==8.4.2` is the movable-label problem again: PyPI serves
/// whatever file sits under that version, and pip resolves the dependencies
/// unpinned. OpenSSF Scorecard's Pinned-Dependencies check reports it, and
/// ci.yml's `code-scanning-clean` job turns that open alert into a red main,
/// which is how 3ada003c found out. `--require-hashes` makes pip refuse any
/// file, dependency included, whose SHA-256 the requirements file does not
/// list. Scorecard runs only in CI; this is the local copy of its rule.
#[test]
fn every_pip_install_requires_hashes() -> Result<(), TestError> {
    let mut installs = 0;
    for (name, body) in workflows()? {
        for (i, line) in body.lines().enumerate() {
            let cmd = line.trim();
            if cmd.starts_with('#') || !cmd.contains("pip install") && !cmd.contains("pip3 install")
            {
                continue;
            }
            installs += 1;
            let at = format!("{name}:{}", i + 1);
            assert!(
                cmd.contains("--require-hashes"),
                "{at}: `{cmd}` installs without --require-hashes"
            );
            let words: Vec<&str> = cmd.split_whitespace().collect();
            let req = words
                .iter()
                .position(|w| *w == "-r")
                .and_then(|p| words.get(p + 1))
                .ok_or_else(|| format!("{at}: `{cmd}` names no -r requirements file"))?;
            let text = std::fs::read_to_string(repo().join(req))
                .map_err(|e| format!("{at}: read {req}: {e}"))?;
            // pip's own format: `name==version \` then `--hash=sha256:...` lines.
            let mut packages = 0;
            for entry in text.split('\n').filter(|l| {
                let l = l.trim_start();
                !l.is_empty() && !l.starts_with('#') && !l.starts_with("--hash")
            }) {
                packages += 1;
                assert!(
                    entry.contains("=="),
                    "{req}: `{entry}` is not pinned to a version"
                );
            }
            let hashes: Vec<&str> = text
                .split_whitespace()
                .filter_map(|w| w.strip_prefix("--hash=sha256:"))
                .collect();
            assert!(packages > 0, "{req}: lists no packages");
            assert!(
                hashes.len() >= packages,
                "{req}: fewer hashes than packages"
            );
            for h in hashes {
                assert!(
                    h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()),
                    "{req}: `{h}` is not a full SHA-256"
                );
            }
        }
    }
    assert!(
        installs > 0,
        "no pip install found in any workflow: either the matcher broke, or the \
         last one was removed and this test should go with it"
    );
    Ok(())
}

/// Zola is installed by two different workflows. Both must agree on version and
/// hash, or one of them is quietly building the site with a different binary.
#[test]
fn a_tool_installed_by_more_than_one_workflow_is_pinned_identically() -> Result<(), TestError> {
    let mut seen: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();

    for (name, body) in workflows()? {
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
    Ok(())
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
/// being canceled by the next push, and it should stay. But it means a run
/// holds its concurrency group until it ENDS, and with no `timeout-minutes`
/// nothing bounds that.
///
/// On 2026-08-05 the two combined: run 31024491079 reached 20 completed jobs and
/// then its `CI success` aggregation job — the only check branch protection
/// requires — sat in `queued` with its dependencies already canceled. It could
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
fn every_workflow_job_bounds_its_runtime() -> Result<(), TestError> {
    let mut missing: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (name, body) in workflows()? {
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
    Ok(())
}

/// A job that declares its own `permissions:` must grant everything its steps
/// need, because a job-level block REPLACES the workflow-level one rather than
/// extending it.
///
/// This is the failure mode that gate exists for. `docker.yml` declared
/// `security-events: write` at workflow level for Trivy, then the publishing job
/// restated `contents/packages/id-token/attestations` and omitted it. The
/// workflow read as if the grant were present -- it was there, eight lines up --
/// and the job that needed it silently had none.
///
/// What made it expensive is where it surfaced. The image built, Trivy ran, the
/// scan found nothing, and only the final `upload-sarif` step failed, with
/// `Resource not accessible by integration`. That message names neither the
/// missing permission nor the override that dropped it, and it is the same
/// message a fork PR produces for entirely legitimate reasons -- so the obvious
/// reading is "expected on forks", which is exactly wrong on a push to main.
///
/// The file already carried a comment explaining that a job block replaces the
/// workflow block, written when `contents: read` had to be restated for the same
/// reason. The comment did not prevent the next omission. A comment states the
/// rule once, where a reader has to remember to apply it; this applies it.
///
/// Only permissions inferable from a step are checked, and the level is part of
/// the inference: `write` satisfies a `read` requirement and `read` does not
/// satisfy `write`. Ignoring the level would make two of these checks vacuous,
/// because every job in this repository grants `contents: read` -- so a check
/// that asked only "is `contents` present?" would clear the release job whether
/// or not it could actually create a release.
///
/// `packages: write` is inferred only for the `build-push-action` invocation
/// that sets `push: true`. The same job also builds a local image for Trivy to
/// scan, and requiring push rights for a build that never pushes would fail a
/// job that is correct as written.
///
/// Two things stay out of the table deliberately. `codecov-action` needs
/// `id-token: write` only under `use_oidc`, which is not how it is called here.
/// A `permissions:` block written as `write-all` has no child keys and so reads
/// here as granting nothing, failing loudly; that is the wanted outcome, since
/// the blanket form is what Scorecard marks down.
#[test]
fn a_job_permissions_block_grants_what_its_steps_need() -> Result<(), TestError> {
    // (marker in a `uses:` line, permission that marker requires, level)
    const NEEDS: &[(&str, &str, &str)] = &[
        ("upload-sarif", "security-events", "write"),
        ("codeql-action/analyze", "security-events", "write"),
        ("attest-build-provenance", "attestations", "write"),
        ("attest-build-provenance", "id-token", "write"),
        ("deploy-pages", "pages", "write"),
        ("deploy-pages", "id-token", "write"),
        ("action-gh-release", "contents", "write"),
        // Exchanges the job's OIDC token for a crates.io one.
        ("crates-io-auth-action", "id-token", "write"),
    ];
    // Conditional on `push: true`, so it is resolved per job rather than here.
    const PUSH_MARKER: &str = "build-push-action";

    fn grants(perms: &[(String, String)], need: &str, level: &str) -> bool {
        perms
            .iter()
            .any(|(k, v)| k == need && (v == "write" || v == level))
    }

    /// What the scan has found across every workflow.
    #[derive(Default)]
    struct Tally {
        /// Jobs seen to need an inferable permission.
        jobs_needing: usize,
        /// Jobs whose permissions block omits one they need.
        gaps: Vec<String>,
    }

    /// The job the scan is inside, and what it has seen of it.
    #[derive(Default)]
    struct JobScan {
        /// The job's name, once its header is read.
        name: Option<String>,
        /// Its own `permissions:` block, when it has one.
        perms: Option<Vec<(String, String)>>,
        /// Whether the scan is inside that block.
        in_perms: bool,
        /// Markers of steps that need a permission.
        markers: Vec<&'static str>,
        /// Whether a step sets `push: true`.
        pushes: bool,
    }

    let mut tally = Tally::default();

    for (name, body) in workflows()? {
        let mut wf_perms: Vec<(String, String)> = Vec::new();
        let mut in_wf_perms = false;
        let mut in_jobs = false;

        let mut scan = JobScan::default();

        // Borrowed by the loop and again after it, so it takes its state as
        // arguments rather than capturing.
        fn close(file: &str, wf: &[(String, String)], scan: &JobScan, tally: &mut Tally) {
            let Some(j) = &scan.name else { return };
            let (perms, markers, pushes) = (&scan.perms, &scan.markers, scan.pushes);

            let mut needs: Vec<(&str, &str)> = Vec::new();
            for m in markers {
                for (marker, perm, level) in NEEDS {
                    if m == marker && !needs.iter().any(|(p, _)| p == perm) {
                        needs.push((perm, level));
                    }
                }
            }
            // `push: true` is an input written below the `uses:` line, so this
            // cannot be decided where the marker is seen.
            if pushes
                && markers.contains(&PUSH_MARKER)
                && !needs.iter().any(|(p, _)| *p == "packages")
            {
                needs.push(("packages", "write"));
            }
            if needs.is_empty() {
                return;
            }
            tally.jobs_needing += 1;

            // No job block means the workflow block applies unmodified.
            let effective = perms.as_deref().unwrap_or(wf);
            for (need, level) in needs {
                if !grants(effective, need, level) {
                    let via = if perms.is_some() {
                        "its own permissions block"
                    } else {
                        "the workflow-level block"
                    };
                    tally.gaps.push(format!(
                        "{file}: job `{j}` needs `{need}: {level}` -- {via} omits it"
                    ));
                }
            }
        }

        for line in body.lines() {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if indent == 0 {
                close(&name, &wf_perms, &scan, &mut tally);
                scan = JobScan::default();
                in_wf_perms = trimmed.starts_with("permissions:");
                in_jobs = trimmed.starts_with("jobs:");
                continue;
            }

            // Workflow-level `permissions:` keys sit at indent 2, before `jobs:`.
            if in_wf_perms && !in_jobs && indent == 2 {
                if let Some((k, v)) = trimmed.split_once(':') {
                    wf_perms.push((k.to_string(), v.trim().to_string()));
                }
                continue;
            }
            if !in_jobs {
                continue;
            }

            if indent == 2 && trimmed.ends_with(':') {
                close(&name, &wf_perms, &scan, &mut tally);
                scan = JobScan {
                    name: Some(trimmed.trim_end_matches(':').to_string()),
                    ..JobScan::default()
                };
                continue;
            }
            if scan.name.is_none() {
                continue;
            }

            if indent == 4 {
                scan.in_perms = trimmed.starts_with("permissions:");
                if scan.in_perms {
                    scan.perms = Some(Vec::new());
                }
            } else if scan.in_perms
                && indent == 6
                && let Some((k, v)) = trimmed.split_once(':')
                && let Some(p) = scan.perms.as_mut()
            {
                p.push((k.to_string(), v.trim().to_string()));
            }

            // Steps live deeper than the job's own keys; a `uses:` anywhere
            // inside the job is this job's step.
            if trimmed.contains("uses:") {
                for (marker, _, _) in NEEDS {
                    if trimmed.contains(marker) && !scan.markers.contains(marker) {
                        scan.markers.push(marker);
                    }
                }
                if trimmed.contains(PUSH_MARKER) && !scan.markers.contains(&PUSH_MARKER) {
                    scan.markers.push(PUSH_MARKER);
                }
            }
            if trimmed == "push: true" {
                scan.pushes = true;
            }
        }
        close(&name, &wf_perms, &scan, &mut tally);
    }

    // A detector that recognizes nothing reports every workflow as correct.
    assert!(
        tally.jobs_needing >= 6,
        "only {} jobs were seen to need an inferable permission -- \
         SARIF upload, CodeQL analysis, attestation, Pages deployment, release \
         creation and the GHCR push are spread across more jobs than that, so \
         the parser is broken and a pass here means nothing",
        tally.jobs_needing
    );

    assert!(
        tally.gaps.is_empty(),
        "these jobs run a step whose permission their own block does not \
         grant:\n  {}\n\n\
         A job-level `permissions:` block REPLACES the workflow-level one, so a \
         grant declared at the top of the file does not reach a job that \
         restates permissions. The step fails with `Resource not accessible by \
         integration`, which names neither the permission nor the override, and \
         which fork PRs produce for unrelated reasons.",
        tally.gaps.join("\n  ")
    );
    Ok(())
}

/// The `path:` entries of one `actions/upload-artifact` step: the inline value,
/// or every line of a `path: |` block.
fn upload_paths(step: &str) -> Vec<String> {
    let lines: Vec<&str> = step.lines().collect();
    let Some(at) = lines
        .iter()
        .position(|l| l.trim_start().starts_with("path:"))
    else {
        return Vec::new();
    };
    let head = lines[at].trim_start().trim_start_matches("path:").trim();
    if head != "|" && head != ">" {
        return vec![head.to_string()];
    }
    let indent = lines[at].len() - lines[at].trim_start().len();
    lines[at + 1..]
        .iter()
        .take_while(|l| l.trim().is_empty() || l.len() - l.trim_start().len() > indent)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// An artifact upload of a hidden path must say `include-hidden-files: true`.
///
/// `actions/upload-artifact` v4.4 and later skip every file under a
/// dot-prefixed path component unless that input is set, and a skipped file is
/// not an error: with `if-no-files-found: ignore` or `warn` the step is green.
/// The Lighthouse job uploaded `e2e/.lighthouseci` that way from the day it was
/// added. Its log said "No files were found with the provided path", and the
/// reports were never kept -- so when `/download/` finally went over its layout
/// shift budget on 2026-09-17, the per-run evidence that would have named the
/// shifting element did not exist, and the defect had to be re-measured from
/// scratch.
#[test]
fn an_artifact_upload_of_a_hidden_path_opts_into_hidden_files() -> Result<(), TestError> {
    let mut uploads = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    for (name, body) in workflows()? {
        for step in steps(&body) {
            if !step.contains("uses: actions/upload-artifact@") {
                continue;
            }
            uploads += 1;
            let paths = upload_paths(&step);
            assert!(
                !paths.is_empty(),
                "{name}: an upload-artifact step has no `path:` this test can \
                 read, so the rule below cannot be checked for it:\n{step}"
            );
            let hidden: Vec<&String> = paths
                .iter()
                .filter(|p| {
                    p.split('/')
                        .any(|c| c.starts_with('.') && c != "." && c != "..")
                })
                .collect();
            let opted_in = step
                .lines()
                .any(|l| l.trim() == "include-hidden-files: true");
            if !hidden.is_empty() && !opted_in {
                offenders.push(format!("{name}: {hidden:?}"));
            }
        }
    }
    assert!(
        uploads >= 5,
        "only {uploads} upload-artifact steps were found across the workflows; \
         coverage, fuzz, scorecard, sanitizer, release and Lighthouse uploads \
         exist, so the step parser is broken and a pass here means nothing"
    );
    assert!(
        offenders.is_empty(),
        "these artifact uploads name a hidden path without \
         `include-hidden-files: true`, so upload-artifact silently skips \
         everything under it:\n  {}",
        offenders.join("\n  ")
    );
    Ok(())
}

/// CodeQL's analyze step uploads the database it built by default, and to
/// upload it first zips it with `codeql database bundle`. Nothing here reads
/// that upload: the findings travel as SARIF, which the step sends either way.
/// The zip took 25-35 s on five runs, then 18+ minutes (killed by the job's
/// 30-minute bound) and 11m45s on 2026-09-17, so it is the one step that can
/// fail a clean analysis on time alone. Raising the bound would hide the growth;
/// turning the upload off removes the step. In the pinned action, the
/// `upload-database` check returns before either `bundleDb` call in
/// `src/database-upload.ts`.
#[test]
fn codeql_analyze_does_not_bundle_a_database_nobody_reads() -> Result<(), TestError> {
    let mut checked = 0usize;
    let mut uploading: Vec<String> = Vec::new();
    for (name, body) in workflows()? {
        for step in steps(&body) {
            if !step.contains("github/codeql-action/analyze@") {
                continue;
            }
            checked += 1;
            let off = step.lines().any(|l| l.trim() == "upload-database: false");
            if !off {
                uploading.push(format!("{name}:\n{step}"));
            }
        }
    }
    assert!(
        checked > 0,
        "no codeql-action/analyze step found -- this test would pass vacuously"
    );
    assert!(
        uploading.is_empty(),
        "these CodeQL analyze steps still upload (and so bundle) the database; \
         set `upload-database: false`:\n{}",
        uploading.join("\n")
    );
    Ok(())
}

/// OpenSSF Baseline AC-04.02: a job gets only the permissions it needs.
///
/// A workflow-level `permissions:` block applies to EVERY job in the file, so
/// a write scope there reaches jobs that never use it: `pages.yml` granted
/// `pages: write` and `id-token: write` to its build and csp jobs as well as
/// to deploy, and `cert-expiry.yml` granted `issues: write` the same way.
/// Write scopes belong on the job that needs them; the workflow level may
/// only read.
#[test]
fn no_workflow_level_permissions_block_grants_a_write_scope() -> Result<(), TestError> {
    let mut offenders = Vec::new();
    for (name, body) in workflows()? {
        let mut inside = false;
        for line in body.lines() {
            if line.starts_with("permissions:") {
                inside = true;
                if line.contains("write") {
                    offenders.push(format!("{name}: {line}"));
                }
                continue;
            }
            if inside {
                if !line.starts_with(' ') && !line.trim().is_empty() {
                    inside = false;
                } else if !line.trim_start().starts_with('#') && line.contains("write") {
                    offenders.push(format!("{name}: {}", line.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "workflow-level permissions grant write to every job in the file; move \
         each write scope into the job that uses it:\n  {}",
        offenders.join("\n  ")
    );
    Ok(())
}

/// cargo-nextest, which runs the suite, is installed through one pinned rule
/// (TEST-DEADLINE-NEXTEST-SIPNAB).
///
/// `scripts/parallel-tests.py` runs the suite under the nextest version
/// `.config/nextest.toml` pins and refuses any other, so every job that runs
/// it must install that version first, and nothing else may install nextest.
/// `.github/actions/nextest` is the one install: it names the same version as
/// the config, a full SHA-256 for each runner it serves, a cache key made of
/// the version, the target and the hash, a fetch only on a miss, a check on
/// every run, and a save only from `main`.
#[test]
fn nextest_is_installed_through_one_pinned_rule() -> Result<(), TestError> {
    const ACTION: &str = ".github/actions/nextest/action.yml";
    const USES: &str = "uses: ./.github/actions/nextest";
    let read = |rel: &str| -> Result<String, TestError> {
        Ok(std::fs::read_to_string(repo().join(rel)).map_err(|e| format!("read {rel}: {e}"))?)
    };
    let pin = |text: &str, re: &str| -> Result<Vec<String>, TestError> {
        let re = regex::Regex::new(re).map_err(|e| format!("regex: {e}"))?;
        Ok(re.captures_iter(text).map(|c| c[1].to_string()).collect())
    };

    let config = read(".config/nextest.toml")?;
    let action = read(ACTION)?;
    let pinned = pin(
        &config,
        r#"(?m)^nextest-version = \{ required = "([0-9.]+)" \}$"#,
    )?;
    let installs = pin(&action, r"(?m)^\s+NEXTEST_VERSION: '([^']+)'$")?;
    assert_eq!(
        pinned.len(),
        1,
        ".config/nextest.toml pins no single nextest-version: {pinned:?}"
    );
    assert_eq!(
        installs, pinned,
        "{ACTION} installs cargo-nextest {installs:?} while .config/nextest.toml \
         pins {pinned:?}: scripts/parallel-tests.py would refuse every CI run"
    );
    let hashes = pin(&action, r"(?m)^\s+NEXTEST_SHA256_[A-Z0-9_]+: '([^']*)'$")?;
    assert!(
        hashes.len() >= 3,
        "{ACTION} pins {} tarball hash(es); the suite runs on aarch64 Linux, \
         x86_64 Linux and macOS",
        hashes.len()
    );
    for h in &hashes {
        assert!(
            h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()),
            "{ACTION}: `{h}` is not a full SHA-256"
        );
    }
    // The tarball comes through the one cached, verified rule, which
    // `pinned_download_is_one_cached_and_verified_rule` holds; this action
    // only chooses the pin for the runner and installs the result.
    assert!(
        !action.contains("actions/cache"),
        "{ACTION} uses actions/cache itself, beside {PINNED_DOWNLOAD}: a second \
         cache rule to drift from the first"
    );
    let parts: Vec<&str> = action.split("\n    - name: ").skip(1).collect();
    let find = |name: &str| -> Result<(usize, &str), TestError> {
        Ok(parts
            .iter()
            .enumerate()
            .find(|(_, s)| s.starts_with(name))
            .map(|(i, s)| (i, *s))
            .ok_or_else(|| format!("{ACTION} has no step named {name:?}"))?)
    };
    let (pick_at, _) = find("Choose the cargo-nextest tarball")?;
    let (fetch_at, fetch) = find("Fetch the cargo-nextest tarball (pinned, cached)")?;
    let (install_at, install) = find("Install cargo-nextest")?;
    for want in [
        PINNED_DOWNLOAD,
        "id: archive",
        // The target is in the name, so it is in the cache key: an aarch64
        // tarball is never restored for an x86_64 runner.
        "name: cargo-nextest-${{ steps.pick.outputs.target }}",
        "version: ${{ steps.pick.outputs.version }}",
        "sha256: ${{ steps.pick.outputs.sha256 }}",
        "url: https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-${{ steps.pick.outputs.version }}/${{ steps.pick.outputs.tarball }}",
        "file: ${{ steps.pick.outputs.tarball }}",
    ] {
        assert!(
            fetch.contains(want),
            "{ACTION}'s fetch step lacks `{want}`:\n{fetch}"
        );
    }
    assert!(
        install.contains("${{ steps.archive.outputs.path }}"),
        "{ACTION} installs something other than the verified archive:\n{install}"
    );
    assert!(
        pick_at < fetch_at && fetch_at < install_at,
        "{ACTION} runs choose, fetch and install out of order"
    );

    // Every job that runs the suite installs nextest first; nothing else
    // installs it.
    let job_re =
        regex::Regex::new(r"(?m)^  [A-Za-z0-9_-]+:\s*$").map_err(|e| format!("regex: {e}"))?;
    let mut suite_jobs = 0usize;
    for (name, body) in workflows()? {
        for st in steps(&body) {
            let another = st.contains("cargo install cargo-nextest")
                || st.contains("get.nexte.st")
                || (st.contains("install-action") && st.contains("nextest"));
            assert!(
                !another,
                "{name} installs nextest another way; {ACTION} is the one install:\n{st}"
            );
        }
        let starts: Vec<usize> = job_re.find_iter(&body).map(|m| m.start()).collect();
        for (i, &start) in starts.iter().enumerate() {
            let job = &body[start..starts.get(i + 1).copied().unwrap_or(body.len())];
            let first_run = job
                .match_indices("scripts/parallel-tests.py")
                .filter(|(at, _)| !job[*at..].starts_with("scripts/parallel-tests.py merge"))
                .map(|(at, _)| at)
                .chain(
                    job.match_indices("scripts/check-feature-matrix.py --group")
                        .map(|(at, _)| at),
                )
                .filter(|&at| {
                    // A mention in a comment is not a run.
                    let line_start = job[..at].rfind('\n').map_or(0, |n| n + 1);
                    !job[line_start..at].trim_start().starts_with('#')
                })
                .min();
            let Some(run_at) = first_run else { continue };
            suite_jobs += 1;
            let label = job.lines().next().unwrap_or("?").trim();
            let installed = job.find(USES);
            assert!(
                installed.is_some_and(|at| at < run_at),
                "{name}: job `{label}` runs the suite without installing the pinned \
                 cargo-nextest first ({USES})"
            );
        }
    }
    assert!(
        suite_jobs >= 3,
        "only {suite_jobs} job(s) found running the suite; ci.yml's check (macOS), \
         test and features jobs all do, so the scan stopped matching"
    );
    Ok(())
}
