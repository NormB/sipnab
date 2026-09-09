// SPDX-License-Identifier: MIT OR Apache-2.0

//! Known-vulnerable dependency versions must not reach the lockfile, and an
//! acceptance must not outlive the problem it accepts.
//!
//! Adding `@lhci/cli` for the Lighthouse gate pulled three vulnerable packages
//! into `e2e/`: `tmp`, `uuid` and `extract-zip`. All three are now pinned out
//! through npm `overrides`, and the lockfile is where that is checked.
//!
//! `extract-zip` was the hard one, and it is why this file used to carry an
//! ACCEPTANCE table. Its newest published release IS the vulnerable one — no
//! upgrade closes it — so the first CVE was accepted in writing. A second
//! advisory then landed on the same version, code scanning opened an alert,
//! and CI went red on main: an acceptance is written against the problem
//! known on the day, and the next one arrives without asking.
//!
//! The package is gone instead. It reached the tree through
//! `@lhci/cli -> lighthouse -> puppeteer-core -> @puppeteer/browsers`, and
//! `@puppeteer/browsers` 3.0.2 replaced it with `tar-fs`. An override to that
//! major removes `extract-zip` from the lockfile entirely, and Lighthouse
//! still collects: every symbol `puppeteer-core` imports from that package is
//! present in 3.x, and a real collection run was made against the override
//! before it was committed.
//!
//! The acceptance mechanism went with it, on the instruction its own test
//! carried: an acceptance table with nothing in it is an untested mechanism,
//! and this file would rather have none than one nothing drives. If an
//! unfixable advisory lands again, it comes back with its tests.
//!
//! The failure this file guards against is not the vulnerability. It is the
//! way a dependency fix quietly stops working: **an override that did not
//! take.** `overrides` is advisory until npm resolves it; an entry naming a
//! package the tree does not have, or one npm declined, leaves the vulnerable
//! version installed while `package.json` says otherwise. Nothing fails, and
//! the lockfile is the only place the truth exists.

#![cfg(feature = "full")]

use std::path::PathBuf;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repository file, panicking with the path on failure.
fn read(rel: &str) -> String {
    let p = repo().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Every `(path, version)` pair in the e2e lockfile, as raw text pairs.
///
/// Parsed by hand rather than with a JSON crate the test tree does not
/// otherwise need. The lockfile is machine-generated, so its shape is stable.
fn lockfile_packages() -> Vec<(String, String)> {
    let text = read("e2e/package-lock.json");
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("\"node_modules/") && t.ends_with("{") {
            let name = t.trim_start_matches('"');
            if let Some(end) = name.find("\":") {
                current = Some(name[..end].to_string());
            }
        } else if t.starts_with("\"version\":")
            && let Some(pkg) = current.take()
            && let Some(v) = t.split('"').nth(3)
        {
            out.push((pkg, v.to_string()));
        }
    }
    out
}

/// Installed versions of one package name, across every path it appears at.
fn versions_of(pkg: &str) -> Vec<String> {
    lockfile_packages()
        .into_iter()
        .filter(|(path, _)| path.rsplit("node_modules/").next() == Some(pkg))
        .map(|(_, v)| v)
        .collect()
}

/// The `overrides` block of `e2e/package.json`, as `(package, requirement)`.
fn overrides() -> Vec<(String, String)> {
    let text = read("e2e/package.json");
    let Some(start) = text.find("\"overrides\"") else {
        return Vec::new();
    };
    let Some(open) = text[start..].find('{') else {
        return Vec::new();
    };
    let Some(close) = text[start + open..].find('}') else {
        return Vec::new();
    };
    let block = &text[start + open + 1..start + open + close];
    block
        .split(',')
        .filter_map(|line| {
            let mut it = line
                .split('"')
                .filter(|s| !s.trim().is_empty() && *s != ":");
            let k = it.next()?.to_string();
            let v = it.find(|s| {
                s.starts_with('^')
                    || s.starts_with('~')
                    || s.starts_with(|c: char| c.is_ascii_digit())
            })?;
            Some((k, v.to_string()))
        })
        .collect()
}

/// Versions a published advisory says are fixed, and the version the tree must
/// therefore be at or past.
///
/// `(package, first_patched)`. Written down rather than fetched: a test that
/// asks npm at run time fails offline and passes when the registry is having a
/// bad day, which is the opposite of a gate.
const MUST_BE_PATCHED: &[(&str, &str)] = &[
    // GHSA on `tmp`: arbitrary file write via symlink. Dependabot could not
    // resolve it and errored, which turned its workflow red on the release
    // commit and blocked the tag.
    ("tmp", "0.2.7"),
    // CVE-2026-41907: missing buffer bounds check in v3/v5/v6 when `buf` is
    // provided. First patched in 11.1.1.
    ("uuid", "11.1.1"),
    // Not a flaw in this package: it is the last hop that could choose. Every
    // release at or below 2.13.2 unpacks a browser download with
    // `extract-zip`, which has two symlink advisories and no fixed version at
    // all. 3.0.2 replaced it with `tar-fs`, so the floor is a floor on the
    // dependency it drags in rather than on a defect of its own — which is why
    // `the_lockfile_no_longer_contains_extract_zip` below states the real
    // property instead of trusting this number to imply it.
    ("@puppeteer/browsers", "3.0.2"),
];

/// Compare two dotted versions numerically.
fn at_least(have: &str, want: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split(['.', '-'])
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (h, w) = (parse(have), parse(want));
    for i in 0..h.len().max(w.len()) {
        let (a, b) = (
            h.get(i).copied().unwrap_or(0),
            w.get(i).copied().unwrap_or(0),
        );
        if a != b {
            return a > b;
        }
    }
    true
}

// ── the lockfile is the only place the truth lives ──────────────────

/// The lockfile parser reads a real lockfile.
///
/// Every rule below compares against what this returns, so a parser that found
/// nothing would report a perfectly patched tree.
#[test]
fn the_lockfile_parser_reads_a_real_lockfile() {
    let pkgs = lockfile_packages();
    assert!(
        pkgs.len() >= 100,
        "parsed only {} package(s) from e2e/package-lock.json; the parser has \
         stopped matching and every check here would pass by examining nothing",
        pkgs.len()
    );
    assert!(
        pkgs.iter().any(|(p, _)| p.ends_with("@lhci/cli")),
        "the lockfile does not contain @lhci/cli, which every entry in this \
         file is about"
    );
}

/// Every package with a published fix is at or past it.
#[test]
fn every_package_with_a_published_fix_is_patched() {
    for (pkg, patched) in MUST_BE_PATCHED {
        let found = versions_of(pkg);
        assert!(
            !found.is_empty(),
            "{pkg} is not in the lockfile at all; either the dependency was \
             dropped — in which case delete this entry — or the parser missed it"
        );
        for v in &found {
            assert!(
                at_least(v, patched),
                "{pkg} {v} is in the lockfile and the advisory is fixed in \
                 {patched}. An `overrides` entry is advisory until npm \
                 resolves it, so package.json saying otherwise proves nothing."
            );
        }
    }
}

/// `tmp` specifically, because its failure blocked a release.
#[test]
fn the_lockfile_pins_tmp_past_the_advisory() {
    let found = versions_of("tmp");
    assert!(!found.is_empty(), "tmp is absent from the lockfile");
    for v in &found {
        assert!(
            at_least(v, "0.2.7"),
            "tmp {v} is still installed. Dependabot could not resolve this and \
             errored, which turned its workflow red on the 0.5.131 release \
             commit and blocked the tag — the pre-push tag gate counts every \
             completed non-success run."
        );
    }
}

/// `uuid` specifically, and at every path it appears.
///
/// Checked per path rather than once: npm can install a second copy nested
/// under a dependency that pinned an older range, and a check that looked at
/// only the top-level copy would call that patched.
#[test]
fn the_lockfile_pins_uuid_past_the_advisory_everywhere_it_appears() {
    let paths: Vec<(String, String)> = lockfile_packages()
        .into_iter()
        .filter(|(p, _)| p.rsplit("node_modules/").next() == Some("uuid"))
        .collect();
    assert!(!paths.is_empty(), "uuid is absent from the lockfile");
    for (path, v) in &paths {
        assert!(
            at_least(v, "11.1.1"),
            "uuid {v} at {path} is below the patched 11.1.1; a nested copy is \
             as exploitable as the top-level one"
        );
    }
}

// ── overrides must actually take ────────────────────────────────────

/// Every override resolved to something the lockfile agrees with.
///
/// The silent failure this catches: `overrides` is a request. If npm declines
/// it, or the entry names a package the tree does not have, the vulnerable
/// version stays installed while `package.json` reads as though it were fixed.
#[test]
fn every_override_took_effect_in_the_lockfile() {
    let ov = overrides();
    assert!(
        !ov.is_empty(),
        "no overrides parsed from e2e/package.json; if they were removed, the \
         packages they pinned must be checked another way"
    );
    for (pkg, req) in &ov {
        let want = req.trim_start_matches(['^', '~']);
        let found = versions_of(pkg);
        assert!(
            !found.is_empty(),
            "override pins {pkg} to {req}, but {pkg} is not in the lockfile — \
             the entry pins nothing"
        );
        for v in &found {
            assert!(
                at_least(v, want),
                "override asks for {pkg} {req} and the lockfile has {v}; npm \
                 did not apply it and nothing else would have said so"
            );
        }
    }
}

/// No override is stale.
///
/// An override for a package the tree no longer pulls is a standing
/// instruction about nothing, and it outlives the reason nobody wrote down.
#[test]
fn no_override_names_a_package_the_tree_no_longer_has() {
    for (pkg, _) in overrides() {
        assert!(
            !versions_of(&pkg).is_empty(),
            "override names {pkg}, which the lockfile does not contain; delete \
             the entry rather than leaving it to be read as protection"
        );
    }
}

// ── the package that had no fix is simply gone ──────────────────────

/// `extract-zip` is not in the lockfile.
///
/// The property, stated directly. The `@puppeteer/browsers` floor above is the
/// MECHANISM that keeps it true, and a floor is exactly the kind of thing that
/// keeps passing while the property it was chosen for stops holding — another
/// dependency could pull `extract-zip` in tomorrow through a path that has
/// nothing to do with Puppeteer, and every version check here would still be
/// green.
#[test]
fn the_lockfile_no_longer_contains_extract_zip() {
    let found = versions_of("extract-zip");
    assert!(
        found.is_empty(),
        "extract-zip {found:?} is back in e2e/package-lock.json. It has TWO \
         symlink advisories and no fixed version — 2.0.1 is the newest release \
         published — so an upgrade is not available and code scanning opens an \
         alert on it, which turns main red. Find what pulled it in and pin that \
         package past the release that dropped it."
    );
}

/// Nothing in the tree still ASKS for `extract-zip`.
///
/// The paired half of the test above, and the one that fails first. A package
/// can declare a dependency that npm has not installed yet — a fresh
/// `npm install` on a runner would resolve it and put the vulnerable version
/// back, while the lockfile this repository committed still looks clean.
#[test]
fn no_package_in_the_lockfile_still_depends_on_extract_zip() {
    let lock = read("e2e/package-lock.json");
    assert!(
        !lock.contains("\"extract-zip\""),
        "e2e/package-lock.json still names extract-zip, so some package \
         declares it even if none resolved to it. The next install would \
         bring it back."
    );
}

/// The version comparator orders releases numerically, not as text.
///
/// `"0.2.7"` vs `"0.10.0"` is the case a string comparison gets backwards, and
/// every rule above rests on this being right.
#[test]
fn the_version_comparison_is_numeric_not_lexical() {
    assert!(at_least("0.2.7", "0.2.7"), "equal must satisfy at-least");
    assert!(at_least("0.2.8", "0.2.7"));
    assert!(
        at_least("0.10.0", "0.2.7"),
        "10 is above 2, textually it is not"
    );
    assert!(!at_least("0.2.6", "0.2.7"));
    assert!(!at_least("0.1.99", "0.2.0"));
    assert!(at_least("11.1.1", "11.1.1"));
    assert!(!at_least("8.3.2", "11.1.1"), "8 is below 11");
    assert!(at_least("2.0.1", "2.0.1"));
}
