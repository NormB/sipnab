// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! sipnab builds nothing from the `digest` 0.10 line, and accepts no advisory
//! for `rsa` or `block-buffer`.
//!
//! Until `rsa` 0.10.0, sipnab's RSA came from `rsa` 0.9, which is built on
//! `digest` 0.10 and has RUSTSEC-2023-0071 (the "Marvin" timing side channel).
//! Its OAEP took a `digest` 0.10 hash, so sipnab also depended on `sha1` 0.10
//! (as `sha1_oaep`), and three scanner configurations carried exceptions:
//! RUSTSEC-2023-0071 for `rsa`, and GHSA-qwgh-2vcv-g2f7 for the `block-buffer`
//! under `digest` 0.10. `rsa` 0.10.0 fixes the first and is built on `digest`
//! 0.11. These tests hold what the move left:
//!
//! - `rsa` is locked at 0.10 or later and `sha1` 0.10 is in no lock file,
//!   manifest or source file;
//! - `digest` 0.10 stays in `Cargo.lock` only under ratatui's termwiz backend,
//!   which `Cargo.lock` lists because it records every optional dependency,
//!   and which sipnab never enables;
//! - no scanner is told to accept either advisory.
#![cfg(feature = "native")]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The advisories sipnab accepted while it used `rsa` 0.9, with their aliases.
const FORMER_EXCEPTIONS: [&str; 4] = [
    "RUSTSEC-2023-0071",
    "CVE-2023-49092",
    "GHSA-c827-hfw6-qwvm",
    "GHSA-qwgh-2vcv-g2f7",
];

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Tracked Rust sources under `src/` and `crates/`.
fn tracked_rust_sources() -> Result<Vec<String>, TestError> {
    let out = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--",
            "src/*.rs",
            "src/**/*.rs",
            "crates/**/*.rs",
        ])
        .current_dir(repo())
        .output()?;
    assert!(out.status.success(), "git ls-files failed");
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

/// Every line naming `sha1_oaep`, as `file:line: text`.
fn lines_naming_sha1_oaep(file: &str, text: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| l.contains("sha1_oaep"))
        .map(|(n, l)| format!("{file}:{}: {}", n + 1, l.trim()))
        .collect()
}

/// The packages in the lock file at `path`, relative to the repository root,
/// as (name, version, dependencies).
fn locked_in(path: &str) -> Result<Vec<(String, String, Vec<String>)>, TestError> {
    let lock: toml::Table = std::fs::read_to_string(repo().join(path))?.parse()?;
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or("the lock file has no [[package]]")?;
    let mut out = Vec::new();
    for p in packages {
        let field = |k: &str| {
            p.get(k)
                .and_then(toml::Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let deps = p
            .get("dependencies")
            .and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|d| d.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        out.push((field("name"), field("version"), deps));
    }
    Ok(out)
}

/// Whether a `Cargo.lock` dependency entry names `name` at a version starting
/// `prefix`, given the versions of `name` the lock holds. An entry carries a
/// version only when the lock holds more than one.
fn names(entry: &str, name: &str, prefix: &str, versions: &[String]) -> bool {
    let mut parts = entry.split(' ');
    if parts.next() != Some(name) {
        return false;
    }
    match parts.next() {
        Some(v) => v.starts_with(prefix),
        None => versions.iter().all(|v| v.starts_with(prefix)),
    }
}

/// The rule that reads a lock entry, on both of its forms.
#[test]
fn a_lock_entry_names_a_version_only_when_the_lock_holds_several() {
    let two = ["0.10.7".to_string(), "0.11.3".to_string()];
    let one = ["0.11.3".to_string()];
    assert!(
        names("digest 0.10.7", "digest", "0.10.", &two),
        "an entry with a version is read by that version"
    );
    assert!(
        !names("digest 0.11.3", "digest", "0.10.", &two),
        "another version of the same crate is not a match"
    );
    assert!(
        !names("digest", "digest", "0.10.", &one),
        "an entry without a version means the one locked version"
    );
    assert!(
        names("digest", "digest", "0.11.", &one),
        "an entry without a version matches the one locked version"
    );
    assert!(
        !names("digest-extra 0.10.7", "digest", "0.10.", &two),
        "a crate whose name only starts the same is not a match"
    );
}

/// `rsa` is locked at 0.10 or later, which is built on `digest` 0.11, so the
/// `sha1` 0.10 that only `rsa` 0.9's OAEP needed is in no lock file and no
/// manifest.
#[test]
fn rsa_is_past_0_9_and_sha1_0_10_is_gone() -> Result<(), TestError> {
    for lock_file in ["Cargo.lock", "fuzz/Cargo.lock"] {
        let lock = locked_in(lock_file)?;
        let rsa: Vec<&str> = lock
            .iter()
            .filter(|p| p.0 == "rsa")
            .map(|p| p.1.as_str())
            .collect();
        assert!(
            rsa.len() == 1 && !rsa.iter().any(|v| v.starts_with("0.9.")),
            "{lock_file} locks rsa at {rsa:?}: it must be one version, 0.10 or later"
        );
        let old_sha1: Vec<&str> = lock
            .iter()
            .filter(|p| p.0 == "sha1" && p.1.starts_with("0.10."))
            .map(|p| p.1.as_str())
            .collect();
        assert!(
            old_sha1.is_empty(),
            "{lock_file} still locks sha1 {old_sha1:?}: nothing needs it once rsa is 0.10"
        );
    }
    let manifest = std::fs::read_to_string(repo().join("Cargo.toml"))?;
    assert!(
        !manifest.contains("sha1_oaep"),
        "Cargo.toml still names the sha1 0.10 dependency `sha1_oaep`"
    );
    Ok(())
}

/// No source file names `sha1_oaep`: every SHA-1 is `sha1` 0.11.
#[test]
fn no_source_names_the_removed_sha1_0_10_dependency() -> Result<(), TestError> {
    let sources = tracked_rust_sources()?;
    assert!(
        sources.len() > 100,
        "the walk found only {} source files",
        sources.len()
    );
    let mut found = Vec::new();
    for file in sources {
        let text = std::fs::read_to_string(repo().join(&file))?;
        found.extend(lines_naming_sha1_oaep(&file, &text));
    }
    assert!(
        found.is_empty(),
        "`sha1_oaep` (sha1 0.10) is removed; hash with `sha1` (0.11):\n{}",
        found.join("\n")
    );
    Ok(())
}

/// The scan above reports a line that names the removed dependency, with its
/// place, and no other line.
#[test]
fn the_scan_reports_each_line_naming_sha1_oaep() {
    let text = "use sha1::Digest;\nlet h = sha1_oaep::Sha1::new();\n// done\n";
    assert_eq!(
        lines_naming_sha1_oaep("a.rs", text),
        vec!["a.rs:2: let h = sha1_oaep::Sha1::new();".to_string()],
        "one line names it, the second"
    );
    assert!(
        lines_naming_sha1_oaep("a.rs", "let h = sha1::Sha1::new();\n").is_empty(),
        "sha1 0.11 is not reported"
    );
}

/// `digest` 0.10, and with it `block-buffer` 0.10, is in `Cargo.lock` only
/// under `sha2` 0.10, which only ratatui's termwiz backend pulls in; the fuzz
/// lock file has none of it.
#[test]
fn digest_0_10_is_locked_only_under_the_termwiz_backend() -> Result<(), TestError> {
    let lock = locked_in("Cargo.lock")?;
    let versions = |n: &str| -> Vec<String> {
        lock.iter()
            .filter(|p| p.0 == n)
            .map(|p| p.1.clone())
            .collect()
    };
    let parents = |name: &str, prefix: &str| -> BTreeSet<String> {
        let held = versions(name);
        lock.iter()
            .filter(|p| p.2.iter().any(|d| names(d, name, prefix, &held)))
            .map(|p| format!("{} {}", p.0, p.1))
            .collect()
    };
    let of_block_buffer = parents("block-buffer", "0.10.");
    assert!(
        of_block_buffer
            .iter()
            .all(|p| p.starts_with("digest 0.10.")),
        "block-buffer 0.10 is reached other than through digest 0.10: {of_block_buffer:?}"
    );
    let of_digest = parents("digest", "0.10.");
    assert!(
        of_digest.iter().all(|p| p.starts_with("sha2 0.10.")),
        "something other than sha2 0.10 brings in digest 0.10: {of_digest:?}"
    );
    let name_of = |p: String| p.split(' ').next().unwrap_or("").to_string();
    let termwiz_chain: BTreeSet<&str> = ["pest_meta", "termwiz", "wezterm-blob-leases"].into();
    let of_sha2_0_10: BTreeSet<String> =
        parents("sha2", "0.10.").into_iter().map(name_of).collect();
    assert!(
        of_sha2_0_10
            .iter()
            .all(|p| termwiz_chain.contains(p.as_str())),
        "sha2 0.10 is pulled in outside ratatui's termwiz backend: {of_sha2_0_10:?}"
    );
    let of_termwiz: BTreeSet<String> = parents("termwiz", "").into_iter().map(name_of).collect();
    assert!(
        of_termwiz.iter().all(|p| p == "ratatui-termwiz"),
        "termwiz is reached other than as ratatui's backend: {of_termwiz:?}"
    );
    let fuzz_old: Vec<String> = locked_in("fuzz/Cargo.lock")?
        .into_iter()
        .filter(|p| (p.0 == "digest" || p.0 == "block-buffer") && p.1.starts_with("0.10."))
        .map(|p| format!("{} {}", p.0, p.1))
        .collect();
    assert!(
        fuzz_old.is_empty(),
        "fuzz/Cargo.lock locks {fuzz_old:?}: the fuzz targets build no digest 0.10"
    );
    Ok(())
}

/// sipnab never turns on ratatui's termwiz backend, the one place `sha2` 0.10
/// (and through it `digest` 0.10) sits in `Cargo.lock`: so that copy is never
/// compiled.
#[test]
fn ratatui_termwiz_backend_stays_off() -> Result<(), TestError> {
    let manifest: toml::Table = std::fs::read_to_string(repo().join("Cargo.toml"))?.parse()?;
    let ratatui = manifest
        .get("dependencies")
        .and_then(|d| d.get("ratatui"))
        .ok_or("Cargo.toml has no ratatui dependency")?;
    let features: Vec<&str> = ratatui
        .get("features")
        .and_then(toml::Value::as_array)
        .map(|a| a.iter().filter_map(toml::Value::as_str).collect())
        .unwrap_or_default();
    assert!(
        !features.contains(&"termwiz"),
        "ratatui's termwiz feature is on"
    );
    let manifest_text = std::fs::read_to_string(repo().join("Cargo.toml"))?;
    assert!(
        !manifest_text.contains("ratatui/termwiz") && !manifest_text.contains("ratatui-termwiz"),
        "a sipnab feature turns on ratatui's termwiz backend"
    );
    Ok(())
}

/// The scanner configurations and the VEX document accept none of the
/// advisories `rsa` 0.9 needed an exception for, and CI's `cargo audit` runs
/// with no `--ignore`.
#[test]
fn no_scanner_is_told_to_accept_an_rsa_or_block_buffer_advisory() -> Result<(), TestError> {
    for file in ["deny.toml", "osv-scanner.toml", "vex/sipnab.openvex.json"] {
        let text = std::fs::read_to_string(repo().join(file))?;
        for id in FORMER_EXCEPTIONS {
            assert!(
                !text.contains(id),
                "{file} still names {id}: rsa 0.10.0 fixes it or does not bring it in"
            );
        }
    }
    let ci = std::fs::read_to_string(repo().join(".github/workflows/ci.yml"))?;
    let audits: Vec<&str> = ci
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("run: cargo audit"))
        .collect();
    assert_eq!(
        audits,
        [
            "run: cargo audit",
            "run: cargo audit --file fuzz/Cargo.lock"
        ],
        "CI audits both lock files, with no advisory ignored"
    );
    Ok(())
}
