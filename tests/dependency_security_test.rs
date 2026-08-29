// SPDX-License-Identifier: MIT OR Apache-2.0

//! Known-vulnerable dependency versions must not reach the lockfile, and an
//! acceptance must not outlive the problem it accepts.
//!
//! Adding `@lhci/cli` for the Lighthouse gate pulled three vulnerable packages
//! into `e2e/`: `tmp`, `uuid` and `extract-zip`. Two had published fixes and
//! are pinned through npm `overrides`. The third has none — `extract-zip`'s
//! newest published version IS the vulnerable one — so it is accepted, in
//! writing, with the reasoning and an expiry condition.
//!
//! The failure this file guards against is not the vulnerability. It is the
//! two ways a dependency fix quietly stops working:
//!
//! - **An override that did not take.** `overrides` is advisory until npm
//!   resolves it; an entry naming a package the tree does not have, or one npm
//!   declined, leaves the vulnerable version installed while `package.json`
//!   says otherwise. Nothing fails, and the lockfile is the only place the
//!   truth exists.
//! - **An acceptance nobody revisits.** "No fix available" is true on the day
//!   it is written. `ACCEPTED_WITHOUT_FIX` therefore records the exact version
//!   checked, and this file fails the moment the tree moves off it — so a
//!   bump forces the question to be asked again rather than inheriting a
//!   verdict from a version that no longer ships.

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

/// A vulnerability accepted because no fixed version exists, with the reason
/// and the exact version that was checked.
///
/// `(package, version_checked, reason)`. Both other rules below read this: an
/// entry must name a package the lockfile actually has, and the lockfile must
/// still be on the version the reason was written against.
const ACCEPTED_WITHOUT_FIX: &[(&str, &str, &str)] = &[(
    "extract-zip",
    "2.0.1",
    "CVE-2026-56876, unvalidated symlink path traversal. There is no fixed \
     version: 2.0.1 is the NEWEST published release, so no upgrade closes it. \
     It arrives dev-only, through @lhci/cli -> lighthouse -> puppeteer-core \
     -> @puppeteer/browsers, whose sole use is extracting a Chrome download \
     fetched over HTTPS from Google's CDN onto an ephemeral CI runner. \
     Exploiting it requires controlling that archive. Accepted rather than \
     dropping the Lighthouse gate; revisit if a fix publishes or if the \
     dependency is ever reached with an attacker-supplied zip.",
)];

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

// ── acceptances must expire ─────────────────────────────────────────

/// Every acceptance states a real reason.
#[test]
fn every_accepted_vulnerability_states_why() {
    assert!(
        !ACCEPTED_WITHOUT_FIX.is_empty(),
        "the acceptance table is empty; delete the mechanism rather than \
         leaving an untested one in place"
    );
    for (pkg, version, reason) in ACCEPTED_WITHOUT_FIX {
        assert!(
            reason.trim().len() >= 60,
            "{pkg} {version} is accepted with no real reason. An acceptance \
             without one is a silenced alert."
        );
        assert!(
            reason.contains("no fixed version") || reason.contains("no fix"),
            "{pkg}'s reason must say why an upgrade is not the answer, since \
             upgrading is the first thing a reader will try"
        );
    }
}

/// An acceptance is bound to the exact version it was written against.
///
/// The expiry condition. "No fix available" was true on the day it was
/// checked; if the tree moves to a different version, the reasoning was
/// written about something that no longer ships and has to be redone.
#[test]
fn an_acceptance_expires_when_the_tree_moves_off_the_version_it_names() {
    for (pkg, version, _) in ACCEPTED_WITHOUT_FIX {
        let found = versions_of(pkg);
        assert!(
            !found.is_empty(),
            "{pkg} is accepted but absent from the lockfile; the dependency \
             was dropped and the acceptance should go with it"
        );
        for v in &found {
            assert_eq!(
                v, version,
                "{pkg} is now {v} and the acceptance was written against \
                 {version}. Re-check whether a fix has published — the \
                 reasoning does not carry over to a version it never saw."
            );
        }
    }
}

/// An accepted package must not also claim to be patched.
///
/// The two tables answer the same question and must not disagree; an entry in
/// both would let whichever ran first decide.
#[test]
fn no_package_is_both_accepted_and_claimed_patched() {
    for (pkg, _, _) in ACCEPTED_WITHOUT_FIX {
        assert!(
            !MUST_BE_PATCHED.iter().any(|(p, _)| p == pkg),
            "{pkg} appears in both ACCEPTED_WITHOUT_FIX and MUST_BE_PATCHED; \
             it is either fixed or it is not"
        );
    }
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
