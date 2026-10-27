// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The `digest` 0.10 line, and with it `block-buffer` 0.10.4
//! (GHSA-qwgh-2vcv-g2f7), stays confined to `rsa` 0.9's OAEP.
//!
//! `rsa` 0.9, the newest stable `rsa`, is built on `digest` 0.10, and its
//! `Oaep::new::<D>()` takes a `digest` 0.10 hash, which is the only reason
//! sipnab still depends on `sha1` 0.10 (as `sha1_oaep`). Every other SHA-1 in
//! sipnab is `sha1` 0.11. `osv-scanner.toml` records why the advisory does not
//! apply to that one use; these tests hold the facts the record rests on:
//!
//! - sipnab's code names `sha1` 0.10 only as the type argument of an OAEP
//!   padding built inside the `encrypt`/`decrypt` call that consumes it, so no
//!   `digest` 0.10 hasher of sipnab's outlives one call or crosses a
//!   `catch_unwind` boundary;
//! - in `Cargo.lock`, only `rsa`, the `signature` crate under it and `sha1`
//!   0.10 depend on `digest` 0.10, apart from `sha2` 0.10 under ratatui's
//!   termwiz backend, which `Cargo.lock` lists because it records every
//!   optional dependency, and which sipnab never enables;
//! - the exception exists exactly while `rsa` 0.9 is locked, and expires.
#![cfg(feature = "native")]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The advisory the `osv-scanner.toml` exception names.
const ADVISORY: &str = "GHSA-qwgh-2vcv-g2f7";

/// The one form in which sipnab's code may name `sha1` 0.10: the OAEP padding,
/// a temporary moved into the call that uses it.
const OAEP_PADDING: &str = "rsa::Oaep::new::<sha1_oaep::Sha1>()";

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

/// Every line naming `sha1_oaep` that is not the OAEP padding, as `file:line: text`.
fn sha1_0_10_uses_outside_oaep(file: &str, text: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| l.contains("sha1_oaep") && !l.contains(OAEP_PADDING))
        .map(|(n, l)| format!("{file}:{}: {}", n + 1, l.trim()))
        .collect()
}

#[test]
fn sha1_0_10_is_named_only_as_the_rsa_oaep_padding() -> Result<(), TestError> {
    let mut found = Vec::new();
    let mut paddings = 0;
    for file in tracked_rust_sources()? {
        let text = std::fs::read_to_string(repo().join(&file))?;
        paddings += text.matches(OAEP_PADDING).count();
        found.extend(sha1_0_10_uses_outside_oaep(&file, &text));
    }
    assert!(
        found.is_empty(),
        "sha1 0.10 (`sha1_oaep`) is for rsa 0.9's OAEP only; hash with sha1 0.11 \
         (`sha1`) instead:\n{}",
        found.join("\n")
    );
    assert_eq!(
        paddings, 2,
        "the JWE encrypt and decrypt paths each build one"
    );
    Ok(())
}

/// The scan above tells a stored or reused hasher from the padding.
#[test]
fn the_scan_refuses_a_sha1_0_10_hasher() {
    let ok = "    .decrypt(rsa::Oaep::new::<sha1_oaep::Sha1>(), &encrypted_key)";
    assert!(sha1_0_10_uses_outside_oaep("a.rs", ok).is_empty());
    for bad in [
        "let digest = <sha1_oaep::Sha1 as sha1_oaep::Digest>::digest(name);",
        "let mut h = sha1_oaep::Sha1::new();",
        "    hasher: sha1_oaep::Sha1,",
        "use sha1_oaep::Digest;",
    ] {
        assert_eq!(sha1_0_10_uses_outside_oaep("a.rs", bad).len(), 1, "{bad}");
    }
}

/// The packages in `Cargo.lock`, as (name, version, dependencies).
fn locked() -> Result<Vec<(String, String, Vec<String>)>, TestError> {
    let lock: toml::Table = std::fs::read_to_string(repo().join("Cargo.lock"))?.parse()?;
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or("Cargo.lock has no [[package]]")?;
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

#[test]
fn only_rsa_0_9_pulls_in_the_digest_0_10_line() -> Result<(), TestError> {
    let lock = locked()?;
    let versions = |n: &str| -> Vec<String> {
        lock.iter()
            .filter(|p| p.0 == n)
            .map(|p| p.1.clone())
            .collect()
    };
    let (digest, block_buffer, sha1) = (
        versions("digest"),
        versions("block-buffer"),
        versions("sha1"),
    );
    assert!(
        digest.iter().any(|v| v.starts_with("0.10.")),
        "digest 0.10 is gone from Cargo.lock: remove the {ADVISORY} exception and this test"
    );
    let parents = |name: &str, prefix: &str, versions: &[String]| -> BTreeSet<String> {
        lock.iter()
            .filter(|p| p.2.iter().any(|d| names(d, name, prefix, versions)))
            .map(|p| format!("{} {}", p.0, p.1))
            .collect()
    };
    let of_block_buffer = parents("block-buffer", "0.10.", &block_buffer);
    assert!(
        of_block_buffer
            .iter()
            .all(|p| p.starts_with("digest 0.10.")),
        "block-buffer 0.10 is reached other than through digest 0.10: {of_block_buffer:?}"
    );
    // A parent by name; `sha1` with its version, since sha1 0.11 must not appear.
    let of_digest: BTreeSet<String> = lock
        .iter()
        .filter(|p| p.2.iter().any(|d| names(d, "digest", "0.10.", &digest)))
        .map(|p| {
            if p.0 == "sha1" {
                format!("sha1@{}", p.1)
            } else {
                p.0.clone()
            }
        })
        .collect();
    let allowed: BTreeSet<String> = ["rsa", "signature", "sha2"]
        .into_iter()
        .map(String::from)
        .chain(
            sha1.iter()
                .filter(|v| v.starts_with("0.10."))
                .map(|v| format!("sha1@{v}")),
        )
        .collect();
    assert!(
        of_digest.is_subset(&allowed),
        "something other than rsa 0.9 brings in digest 0.10: {of_digest:?}, allowed {allowed:?}"
    );
    // sha2 0.10 is in the lock only under ratatui's optional termwiz backend.
    let termwiz_chain: BTreeSet<&str> = ["pest_meta", "termwiz", "wezterm-blob-leases"].into();
    let of_sha2_0_10: BTreeSet<String> = parents("sha2", "0.10.", &versions("sha2"))
        .into_iter()
        .map(|p| p.split(' ').next().unwrap_or("").to_string())
        .collect();
    assert!(
        of_sha2_0_10
            .iter()
            .all(|p| termwiz_chain.contains(p.as_str())),
        "sha2 0.10 is pulled in outside ratatui's termwiz backend: {of_sha2_0_10:?}"
    );
    let of_termwiz: BTreeSet<String> = parents("termwiz", "", &versions("termwiz"))
        .into_iter()
        .map(|p| p.split(' ').next().unwrap_or("").to_string())
        .collect();
    assert!(
        of_termwiz.iter().all(|p| p == "ratatui-termwiz"),
        "termwiz is reached other than as ratatui's backend: {of_termwiz:?}"
    );
    let of_sha1_0_10: BTreeSet<String> = parents("sha1", "0.10.", &sha1)
        .into_iter()
        .map(|p| p.split(' ').next().unwrap_or("").to_string())
        .collect();
    assert!(
        of_sha1_0_10.iter().all(|p| p == "sipnab" || p == "rsa"),
        "sha1 0.10 is pulled in by {of_sha1_0_10:?}"
    );
    Ok(())
}

/// sipnab never turns on ratatui's termwiz backend, the one place `sha2` 0.10
/// (and through it `digest` 0.10) sits in `Cargo.lock` outside `rsa`: so that
/// copy is never compiled.
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

/// The exception stands exactly while `rsa` 0.9 is locked, and it expires.
///
/// When `rsa` moves to a stable 0.10 (built on `digest` 0.11 and `block-buffer`
/// 0.12), this fails: remove the exception, the `sha1_oaep` dependency and this
/// file. `scripts/check-dependency-canaries.py` is the check that notices the
/// release; it runs in `.github/workflows/osv-scanner.yml`.
#[test]
fn the_advisory_exception_lasts_only_while_rsa_0_9_is_locked() -> Result<(), TestError> {
    let rsa = locked()?
        .into_iter()
        .filter(|p| p.0 == "rsa")
        .map(|p| p.1)
        .collect::<Vec<_>>();
    let config: toml::Table = std::fs::read_to_string(repo().join("osv-scanner.toml"))?.parse()?;
    let entry = config
        .get("IgnoredVulns")
        .and_then(toml::Value::as_array)
        .and_then(|a| {
            a.iter()
                .find(|v| v.get("id").and_then(toml::Value::as_str) == Some(ADVISORY))
        });
    let on_0_9 = rsa.iter().all(|v| v.starts_with("0.9."));
    assert!(
        !rsa.is_empty(),
        "rsa is no longer locked: remove the {ADVISORY} exception"
    );
    assert_eq!(
        entry.is_some(),
        on_0_9,
        "rsa {rsa:?}: the {ADVISORY} exception must exist exactly while rsa 0.9 is locked"
    );
    if let Some(e) = entry {
        let until = e
            .get("ignoreUntil")
            .ok_or("the exception has no ignoreUntil: it must expire")?;
        let until = until.to_string();
        assert!(
            until.starts_with("2026-12-") || until.starts_with("2027-01-"),
            "ignoreUntil {until} is not within about 60 days of 2026-10-27"
        );
        let reason = e.get("reason").and_then(toml::Value::as_str).unwrap_or("");
        for fact in ["vcon_jose.rs", "oaep.rs", "block-buffer", "catch_unwind"] {
            assert!(reason.contains(fact), "the reason does not cite {fact}");
        }
    }
    Ok(())
}
