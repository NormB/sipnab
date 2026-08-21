// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every system package a hosted CI job needs must come from a local cache
//! first, not from the Ubuntu archives on every run.
//!
//! Measured, not theorised. On 2026-08-20 the `Security audit` job of the
//! 0.5.118 CI run sat in `apt-get install -y libpcap-dev` for **15 minutes**
//! (`23:44:35Z` to `23:59:51Z`) and was cancelled, which failed the aggregate
//! `CI success` job and blocked the release tag. Nothing was wrong with the
//! code: `azure.archive.ubuntu.com` simply did not answer. The same run lost
//! `Docker` to a second external fetch — Trivy's vulnerability DB download
//! from `mirror.gcr.io` — for a combined cost of two full re-run cycles.
//!
//! The guard that was supposed to prevent this exists and cannot fire. Every
//! apt step is written `dpkg -s <pkg> || need="$need <pkg>"`, which skips the
//! install when the package is already present. That was written when these
//! jobs ran on the self-hosted box, where `libpcap-dev` is installed once and
//! stays. On a GitHub-hosted runner the package is never present, so the guard
//! evaluates to "install everything" on every job of every run — seventeen
//! sites across five workflows, each one an unbounded network fetch.
//!
//! So the rule is not "guard the install". It is: **a hosted job must not
//! reach the archives on the common path at all.** The shared composite action
//! restores the `.deb` files from `actions/cache` and installs them with
//! `dpkg -i`, which touches no network; the archives are consulted only to
//! populate a cold cache, and even then under a bounded timeout so a stall
//! costs minutes rather than a cancelled run.
//!
//! `release.yml` is deliberately NOT in scope here and is not an oversight.
//! Its builds run inside pinned `bookworm` and `cross` containers as root,
//! where the package set is multiarch and `actions/cache` has no meaning; that
//! conversion is tracked separately rather than rushed alongside this one.

use std::path::Path;

/// Repository root, taken from `CARGO_MANIFEST_DIR`.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repo-relative file, panicking with the path on failure.
fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The workflows whose jobs run on GitHub-hosted runners without a container.
///
/// Derived rather than listed: any workflow that installs system packages and
/// never declares a `container:` is one of these by construction, so a new
/// workflow is covered the day it lands instead of the day someone remembers
/// to add it here. A gate that hardcodes its subjects cannot see a new one.
fn hosted_workflows_installing_packages() -> Vec<String> {
    let dir = repo().join(".github/workflows");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read .github/workflows") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("workflow file name")
            .to_string();
        let text = std::fs::read_to_string(&path).expect("read workflow");
        // A workflow that never installs anything has nothing to convert.
        if !text.contains("apt-get install") && !text.contains("system-deps") {
            continue;
        }
        // Container jobs install as root against a pinned image; `actions/cache`
        // does not apply to them. See the module note on `release.yml`.
        if text.contains("container:") {
            continue;
        }
        out.push(name);
    }
    out.sort();
    out
}

/// A hosted job must not shell out to `apt-get install` on the common path.
///
/// This is the failure that cost the 0.5.118 tag two re-run cycles. The
/// assertion is on the *absence of the fetch*, not on the presence of a
/// guard: the guard was already there and was structurally unable to fire.
#[test]
fn no_hosted_workflow_installs_system_packages_from_the_archives() {
    let mut offenders: Vec<String> = Vec::new();
    for wf in hosted_workflows_installing_packages() {
        let text = read(&format!(".github/workflows/{wf}"));
        for (i, line) in text.lines().enumerate() {
            // A comment that mentions the command is prose, not a fetch. Left
            // scanned-but-skipped rather than stripped, because the history of
            // WHY these steps look the way they do lives in those comments.
            if line.trim_start().starts_with('#') {
                continue;
            }
            if line.contains("apt-get install") {
                offenders.push(format!("{wf}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these hosted CI steps fetch system packages from the Ubuntu archives \
         on every run, which is what hung for 15 minutes and cancelled the \
         0.5.118 CI run.\nUse the shared local-first action instead:\n  \
         - uses: ./.github/actions/system-deps\n    with:\n      packages: \
         libpcap-dev libasound2-dev\n\n{}",
        offenders.join("\n")
    );
}

/// The shared action must install from the cache without touching the network.
///
/// The negative control for the rule above. An action that merely wraps the
/// same `apt-get install` would satisfy the first test while changing nothing
/// about the failure it exists to prevent, so the cache-hit path is asserted
/// to use `dpkg -i` — which cannot reach a network — and the cold path is
/// asserted to be bounded by a timeout.
#[test]
fn the_shared_action_installs_from_cache_and_bounds_the_cold_path() {
    let action = read(".github/actions/system-deps/action.yml");

    assert!(
        action.contains("dpkg -i"),
        "the cache-hit path must install the .deb files directly, which \
         performs no network access; without it the action is just apt-get \
         with extra steps:\n{action}"
    );
    assert!(
        action.contains("actions/cache"),
        "the .deb files must be restored from actions/cache, or every run \
         repopulates them from the archives:\n{action}"
    );
    assert!(
        action.contains("timeout "),
        "the cold-cache path still reaches the archives, so it must be bounded \
         by a timeout -- an unbounded apt-get is exactly what consumed 15 \
         minutes before being cancelled:\n{action}"
    );
}

/// The image scanner's vulnerability DB must be cached, and must be able to
/// fall back when the download fails.
///
/// The second external fetch that failed on 2026-08-20. Trivy pulls a ~60 MB
/// DB from `mirror.gcr.io`; the download stalled, and the Docker job died with
/// the image already built and smoke-tested. A cache alone is not enough --
/// without `restore-keys` a cold key on a day the mirror is down leaves the
/// job in exactly the same position.
#[test]
fn the_image_scanner_caches_its_vulnerability_db_with_a_fallback() {
    let docker = read(".github/workflows/docker.yml");

    assert!(
        docker.contains("TRIVY_CACHE_DIR"),
        "the scanner must be pointed at a cached DB directory, or it \
         re-downloads ~60 MB on every run:\n{docker}"
    );
    assert!(
        docker.contains("key: trivy-db-"),
        "the DB cache needs a key that changes over time; a fixed key is a \
         vulnerability DB that never refreshes, which is a scan that quietly \
         stops finding things"
    );
    assert!(
        docker.contains("restore-keys: trivy-db-"),
        "without restore-keys, the first run of a day on which the mirror is \
         down has no DB to fall back to and the job dies -- which is the exact \
         failure this cache exists to prevent"
    );
}

/// A scan that never ran must not be reported as a scan that failed.
///
/// `if: always()` on the SARIF upload turned one infrastructure failure into
/// two: the DB download stalled, no report was written, and the upload failed
/// with `Path does not exist: trivy.sarif`. Uploading findings when the scan
/// FINDS something is the intent; uploading a file that was never created is
/// not.
#[test]
fn the_sarif_upload_does_not_fail_when_the_scan_wrote_nothing() {
    let docker = read(".github/workflows/docker.yml");
    assert!(
        docker.contains("always() && hashFiles('trivy.sarif') != ''"),
        "the SARIF upload must be guarded on the report existing, or a scan \
         that died before writing one produces a second, misleading failure \
         that points at the upload rather than the download:\n{docker}"
    );
}

/// Every converted workflow must actually reference the shared action.
///
/// Deleting an apt step passes the first test as surely as converting it does.
/// This asserts the dependency is still installed, by the intended route.
#[test]
fn converted_workflows_reference_the_shared_action() {
    for wf in hosted_workflows_installing_packages() {
        let text = read(&format!(".github/workflows/{wf}"));
        assert!(
            text.contains("./.github/actions/system-deps"),
            "{wf} needs system packages but does not use \
             ./.github/actions/system-deps -- if its dependency was simply \
             deleted, the job builds against whatever the runner happens to \
             carry"
        );
    }
}
