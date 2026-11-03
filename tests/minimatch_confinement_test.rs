// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `minimatch` stays at the 3.x release that GHSA-g3hv-75wg-m249 cannot reach,
//! and only in the site's test tooling.
//!
//! The advisory (CVE-2026-118764) is a pattern amplification in
//! `firstPhasePreProcess()`, which runs when `optimizationLevel` is 2 or more.
//! osv.dev lists every release before 11.0.1 as affected, but minimatch 3.1.5
//! has neither `firstPhasePreProcess` nor `optimizationLevel`: they arrived in a
//! later major line. 3.1.5 reaches the repository only through
//! `e2e/package-lock.json`, the Lighthouse CI tooling (`@lhci/cli` ->
//! `chrome-launcher` 0.13 -> `rimraf` 3 -> `glob` 7 -> `minimatch` 3), and no
//! minimatch 3 release carries a fix, because none is needed. `osv-scanner.toml`
//! records that; these tests hold the facts the record rests on:
//!
//! - every `minimatch` any tracked npm lockfile resolves is a version whose
//!   source was read and found without the mechanism;
//! - it is resolved in `e2e/` and nowhere else;
//! - the exception exists exactly while such a `minimatch` is locked, and
//!   expires.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The advisory the `osv-scanner.toml` exception names.
const ADVISORY: &str = "GHSA-g3hv-75wg-m249";

/// minimatch releases whose published package was read and found to contain
/// neither `firstPhasePreProcess` nor `optimizationLevel`. Add a version only
/// after reading its package the same way.
const READ_WITHOUT_THE_MECHANISM: &[&str] = &["3.1.5"];

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

/// Every locked `minimatch` is one read and found without the mechanism, and
/// it is in the site's test tooling only.
///
/// A new version, even a 3.x patch, fails here until its package has been read:
/// the exception says the mechanism is absent, and that was checked for the
/// versions listed, not for a range.
#[test]
fn every_locked_minimatch_was_read_and_is_e2e_tooling_only() -> Result<(), TestError> {
    for (lockfile, version) in locked_minimatch()? {
        assert!(
            READ_WITHOUT_THE_MECHANISM.contains(&version.as_str()),
            "{lockfile} resolves minimatch {version}, whose source has not been read for \
             {ADVISORY}'s firstPhasePreProcess/optimizationLevel; read it, or move past the \
             advisory (11.0.1 is fixed)"
        );
        assert_eq!(
            lockfile, "e2e/package-lock.json",
            "minimatch {version} is now resolved outside the site's test tooling"
        );
    }
    Ok(())
}

/// The exception stands exactly while such a `minimatch` is locked, and it
/// expires.
///
/// When `e2e/` stops resolving minimatch 3 (an `@lhci/cli` release without
/// `chrome-launcher` 0.13, for one), this fails: remove the exception, its VEX
/// statement and this file.
#[test]
fn the_advisory_exception_lasts_only_while_minimatch_3_is_locked() -> Result<(), TestError> {
    let locked = locked_minimatch()?;
    let config: toml::Table = std::fs::read_to_string(repo().join("osv-scanner.toml"))?.parse()?;
    let entry = config
        .get("IgnoredVulns")
        .and_then(toml::Value::as_array)
        .and_then(|a| {
            a.iter()
                .find(|v| v.get("id").and_then(toml::Value::as_str) == Some(ADVISORY))
        });
    assert_eq!(
        entry.is_some(),
        !locked.is_empty(),
        "minimatch {locked:?}: the {ADVISORY} exception must exist exactly while e2e/ locks a minimatch 3"
    );
    if let Some(e) = entry {
        let until = e
            .get("ignoreUntil")
            .ok_or("the exception has no ignoreUntil: it must expire")?
            .to_string();
        assert!(
            until.starts_with("2027-01-") || until.starts_with("2027-02-"),
            "ignoreUntil {until} is not within about 90 days of 2026-11-02"
        );
        let reason = e.get("reason").and_then(toml::Value::as_str).unwrap_or("");
        for fact in [
            "firstPhasePreProcess",
            "optimizationLevel",
            "3.1.5",
            "e2e/package-lock.json",
            "chrome-launcher",
        ] {
            assert!(reason.contains(fact), "the reason does not cite {fact}");
        }
    }
    Ok(())
}
