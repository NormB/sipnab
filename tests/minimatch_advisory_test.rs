// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! No tracked npm lockfile resolves a `minimatch` that GHSA-g3hv-75wg-m249
//! (CVE-2026-118764) covers, and nothing excepts the advisory.
//!
//! osv.dev gives the affected range as introduced 0, fixed 11.0.1. Until
//! 2026-11-03, `e2e/package-lock.json` resolved minimatch 3.1.5 through the
//! Lighthouse CI tooling (`@lhci/cli` -> `chrome-launcher` 0.13 -> `rimraf` 3 ->
//! `glob` 7 -> `minimatch` 3), and `osv-scanner.toml` excepted the advisory.
//! `e2e/package.json` now overrides `chrome-launcher` to 1.x under `@lhci/cli`,
//! which has no `rimraf`, so that chain is gone. These tests keep it gone:
//!
//! - every `minimatch` any tracked npm lockfile resolves is 11.0.1 or later;
//! - `osv-scanner.toml` carries no exception for the advisory.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The advisory.
const ADVISORY: &str = "GHSA-g3hv-75wg-m249";

/// The first minimatch release osv.dev lists as fixed.
const FIXED: (u64, u64, u64) = (11, 0, 1);

/// `major.minor.patch` of a version string; a pre-release suffix is ignored.
fn semver(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.split(['-', '+']).next()?;
    let mut it = core.split('.').map(str::parse::<u64>);
    Some((it.next()?.ok()?, it.next()?.ok()?, it.next()?.ok()?))
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every tracked `package-lock.json`.
fn tracked_npm_lockfiles() -> Result<Vec<String>, TestError> {
    let out = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--",
            "package-lock.json",
            "**/package-lock.json",
        ])
        .current_dir(repo())
        .output()?;
    if !out.status.success() {
        return Err(format!("git ls-files: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

/// Every `(lockfile, version)` for a `minimatch` package in `lock`.
///
/// npm's lockfile v3 keys each installed package by its `node_modules` path, so
/// a nested copy is `.../node_modules/minimatch` too.
fn minimatch_in(lockfile: &str, lock: &serde_json::Value) -> Vec<(String, String)> {
    lock["packages"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(path, _)| {
            path.as_str() == "node_modules/minimatch" || path.ends_with("/node_modules/minimatch")
        })
        .map(|(_, entry)| {
            (
                lockfile.to_string(),
                entry["version"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// Every `minimatch` every tracked npm lockfile resolves.
fn locked_minimatch() -> Result<Vec<(String, String)>, TestError> {
    let lockfiles = tracked_npm_lockfiles()?;
    assert!(
        lockfiles.iter().any(|f| f == "e2e/package-lock.json"),
        "found no e2e/package-lock.json among {lockfiles:?}; the reader broke"
    );
    let mut found = Vec::new();
    for f in lockfiles {
        let lock: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(repo().join(&f))?)?;
        found.extend(minimatch_in(&f, &lock));
    }
    Ok(found)
}

/// The reader finds a nested copy as well as a top-level one.
#[test]
fn the_reader_finds_every_copy() {
    let lock = serde_json::json!({"packages": {
        "": {},
        "node_modules/minimatch": {"version": "3.1.5"},
        "node_modules/a/node_modules/minimatch": {"version": "9.0.5"},
        "node_modules/minimatch-extra": {"version": "1.0.0"},
    }});
    let found: BTreeSet<_> = minimatch_in("x/package-lock.json", &lock)
        .into_iter()
        .map(|(_, v)| v)
        .collect();
    assert_eq!(
        found,
        BTreeSet::from(["3.1.5".to_string(), "9.0.5".to_string()]),
        "both the top-level and the nested minimatch are found, and minimatch-extra is not"
    );
}

/// The version comparison orders by number, not by text.
#[test]
fn versions_compare_by_number() {
    assert_eq!(semver("3.1.5"), Some((3, 1, 5)), "a plain version parses");
    assert_eq!(
        semver("11.0.1-rc.1"),
        Some((11, 0, 1)),
        "a pre-release suffix is ignored"
    );
    assert_eq!(semver("x"), None, "a non-version is refused");
    assert!(
        semver("9.0.10") < Some(FIXED)
            && semver("11.0.1") >= Some(FIXED)
            && semver("11.10.0") > Some(FIXED),
        "9.0.10 is below the fix and 11.0.1 and 11.10.0 are at or above it"
    );
}

/// Every locked `minimatch` is at or past the fixed release.
#[test]
fn no_lockfile_resolves_a_minimatch_the_advisory_covers() -> Result<(), TestError> {
    for (lockfile, version) in locked_minimatch()? {
        let parsed = semver(&version).ok_or(format!(
            "{lockfile}: minimatch version {version:?} does not parse"
        ))?;
        assert!(
            parsed >= FIXED,
            "{lockfile} resolves minimatch {version}, which {ADVISORY} covers (fixed in 11.0.1)"
        );
    }
    Ok(())
}

/// The advisory is fixed, so `osv-scanner.toml` must not except it.
#[test]
fn no_exception_hides_the_advisory() -> Result<(), TestError> {
    let config: toml::Table = std::fs::read_to_string(repo().join("osv-scanner.toml"))?.parse()?;
    let excepted = config
        .get("IgnoredVulns")
        .and_then(toml::Value::as_array)
        .is_some_and(|a| {
            a.iter()
                .any(|v| v.get("id").and_then(toml::Value::as_str) == Some(ADVISORY))
        });
    assert!(
        !excepted,
        "osv-scanner.toml still excepts {ADVISORY}; it is fixed, so the exception would hide a regression"
    );
    Ok(())
}
