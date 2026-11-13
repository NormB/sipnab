// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Known-vulnerable dependency versions must not reach the lockfile, and an
//! acceptance must not outlive the problem it accepts.
//!
//! Adding `@lhci/cli` for the Lighthouse gate pulled three vulnerable packages
//! into `e2e/`: `tmp`, `uuid` and `extract-zip`. `uuid` is pinned out through
//! npm `overrides`, and the lockfile is where that is checked. `@lhci/cli`
//! 0.16 no longer depends on `tmp`, so its override went with it; a test below
//! still refuses a vulnerable `tmp` at any path.
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

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repository file, panicking with the path on failure.
fn read(rel: &str) -> Result<String, TestError> {
    let p = repo().join(rel);
    Ok(std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?)
}

/// Every `(path, version)` pair in the e2e lockfile, as raw text pairs.
///
/// Parsed by hand rather than with a JSON crate the test tree does not
/// otherwise need. The lockfile is machine-generated, so its shape is stable.
fn lockfile_packages() -> Result<Vec<(String, String)>, TestError> {
    lockfile_packages_in(E2E_LOCK)
}

/// The site-test tooling's lockfile. Nothing in it ships to a user.
const E2E_LOCK: &str = "e2e/package-lock.json";

/// The lockfile of the TypeScript MCP client `docs/mcp-deploy.md` shows.
const TS_LOCK: &str = "clients/typescript/package-lock.json";

/// Every `(path, version)` pair in the lockfile at `rel`.
fn lockfile_packages_in(rel: &str) -> Result<Vec<(String, String)>, TestError> {
    let text = read(rel)?;
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
    Ok(out)
}

/// Installed versions of one package name, across every path it appears at.
fn versions_of(pkg: &str) -> Result<Vec<String>, TestError> {
    Ok(lockfile_packages()?
        .into_iter()
        .filter(|(path, _)| path.rsplit("node_modules/").next() == Some(pkg))
        .map(|(_, v)| v)
        .collect())
}

/// The `overrides` block of `e2e/package.json`, as `(package, requirement)`.
fn overrides() -> Result<Vec<(String, String)>, TestError> {
    overrides_in("e2e/package.json")
}

/// The `overrides` block of the `package.json` at `rel`.
fn overrides_in(rel: &str) -> Result<Vec<(String, String)>, TestError> {
    let text = read(rel)?;
    let Some(start) = text.find("\"overrides\"") else {
        return Ok(Vec::new());
    };
    let Some(open) = text[start..].find('{') else {
        return Ok(Vec::new());
    };
    let Some(close) = text[start + open..].find('}') else {
        return Ok(Vec::new());
    };
    let block = &text[start + open + 1..start + open + close];
    Ok(block
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
        .collect())
}

/// Versions a published advisory says are fixed, and the version the tree must
/// therefore be at or past.
///
/// `(package, first_patched)`. Written down rather than fetched: a test that
/// asks npm at run time fails offline and passes when the registry is having a
/// bad day, which is the opposite of a gate.
const MUST_BE_PATCHED: &[(&str, &str)] = &[
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
    // GHSA-3g3m-2fjr-6pw4 (CVE-2026-118773): an aborted `glob` walk keeps
    // reading the filesystem after its AbortSignal fires. Affects 9.0.0 up to
    // 14.0.2. `@lhci/cli` 0.16 brought `glob` in through
    // `lighthouse -> @sentry/node -> @sentry/bundler-plugins`; 11.10.0 asks
    // for `glob` 13, and 11.11.0 for `glob` 14 (which also takes `minimatch`
    // 11, past GHSA-g3hv-75wg-m249; tests/minimatch_advisory_test.rs).
    ("glob", "14.0.2"),
    // GHSA-5pm8-86m8-9m6r (CVE-2026-126345): a `__proto__` fact name in an
    // MLSD directory listing makes `Client.list()` throw. Every release
    // before 6.2.4 is affected.
    ("basic-ftp", BASIC_FTP_FIXED),
];

/// The first `basic-ftp` release past GHSA-5pm8-86m8-9m6r.
const BASIC_FTP_FIXED: &str = "6.2.4";

/// The first `@hono/node-server` 2.x release past GHSA-jpvv-r467-5p4w
/// (CVE-2026-126210: a backslash in the request path is read as a path
/// separator) and GHSA-qv5m-9pm6-hqp3 (CVE-2026-126343: a connection reset
/// during a WebSocket upgrade ends the process).
const NODE_SERVER_FIXED_2: &str = "2.1.6";

/// The first `@hono/node-server` 1.x release past GHSA-jpvv-r467-5p4w.
const NODE_SERVER_FIXED_1: &str = "1.19.18";

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
fn the_lockfile_parser_reads_a_real_lockfile() -> Result<(), TestError> {
    let pkgs = lockfile_packages()?;
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
    Ok(())
}

/// Every package with a published fix is at or past it.
#[test]
fn every_package_with_a_published_fix_is_patched() -> Result<(), TestError> {
    for (pkg, patched) in MUST_BE_PATCHED {
        let found = versions_of(pkg)?;
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
    Ok(())
}

/// `tmp` specifically, because its failure blocked a release.
///
/// GHSA on `tmp`: arbitrary file write via symlink, fixed in 0.2.7.
/// `@lhci/cli` 0.16 dropped the dependency, so the lockfile has no `tmp` and
/// `MUST_BE_PATCHED` and the override no longer name it. A `tmp` that comes
/// back at any path must still be 0.2.7 or later.
#[test]
fn no_tmp_below_the_advisory_fix_is_in_the_lockfile() -> Result<(), TestError> {
    let found = versions_of("tmp")?;
    for v in &found {
        assert!(
            at_least(v, "0.2.7"),
            "tmp {v} is still installed. Dependabot could not resolve this and \
             errored, which turned its workflow red on the 0.5.131 release \
             commit and blocked the tag — the pre-push tag gate counts every \
             completed non-success run."
        );
    }
    Ok(())
}

/// `uuid` specifically, and at every path it appears.
///
/// Checked per path rather than once: npm can install a second copy nested
/// under a dependency that pinned an older range, and a check that looked at
/// only the top-level copy would call that patched.
#[test]
fn the_lockfile_pins_uuid_past_the_advisory_everywhere_it_appears() -> Result<(), TestError> {
    let paths: Vec<(String, String)> = lockfile_packages()?
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
    Ok(())
}

// ── overrides must actually take ────────────────────────────────────

/// Every override resolved to something the lockfile agrees with.
///
/// The silent failure this catches: `overrides` is a request. If npm declines
/// it, or the entry names a package the tree does not have, the vulnerable
/// version stays installed while `package.json` reads as though it were fixed.
#[test]
fn every_override_took_effect_in_the_lockfile() -> Result<(), TestError> {
    let ov = overrides()?;
    assert!(
        !ov.is_empty(),
        "no overrides parsed from e2e/package.json; if they were removed, the \
         packages they pinned must be checked another way"
    );
    for (pkg, req) in &ov {
        let want = req.trim_start_matches(['^', '~']);
        let found = versions_of(pkg)?;
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
    Ok(())
}

/// No override is stale.
///
/// An override for a package the tree no longer pulls is a standing
/// instruction about nothing, and it outlives the reason nobody wrote down.
#[test]
fn no_override_names_a_package_the_tree_no_longer_has() -> Result<(), TestError> {
    for (pkg, _) in overrides()? {
        assert!(
            !versions_of(&pkg)?.is_empty(),
            "override names {pkg}, which the lockfile does not contain; delete \
             the entry rather than leaving it to be read as protection"
        );
    }
    Ok(())
}

// ── an override stays only while a parent still asks for less ───────

/// Whether the npm requirement `req` admits a release an advisory covers.
///
/// `fixed` lists the first fixed release for each major line as
/// `(Some(major), version)`, and `(None, version)` for every line without an
/// entry of its own. A line with no entry at all is not affected. `req` is
/// read as its alternatives (`||`), each by the lowest release it admits:
/// the version after `^`, `~`, `>=` or `=`. An alternative that is not
/// written that way counts as admitting one, so that an override stays.
fn admits_affected(req: &str, fixed: &[(Option<u64>, &str)]) -> bool {
    req.split("||").any(|alternative| {
        let floor = alternative
            .trim()
            .trim_start_matches(['^', '~', '>', '=', 'v', ' ']);
        let numbers: Vec<&str> = floor.split('.').collect();
        let well_formed = numbers
            .iter()
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if !well_formed {
            return true;
        }
        // Digits only, so the one failure left is a number past `u64`.
        let Some(major) = numbers.first().and_then(|n| n.parse::<u64>().ok()) else {
            return true;
        };
        let own = fixed.iter().find(|(line, _)| *line == Some(major));
        let any = fixed.iter().find(|(line, _)| line.is_none());
        match own.or(any) {
            Some((_, first_fixed)) => !at_least(floor, first_fixed),
            None => false,
        }
    })
}

/// The requirements for `pkg` that other packages in the lockfile at `rel`
/// declare: every `"pkg": "requirement"` line.
fn requirements_for(rel: &str, pkg: &str) -> Result<Vec<String>, TestError> {
    let key = format!("\"{pkg}\": \"");
    Ok(read(rel)?
        .lines()
        .filter_map(|line| line.trim().strip_prefix(key.as_str()))
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_string)
        .collect())
}

/// Which releases of each package the advisories of 2026-11-12 cover.
const BASIC_FTP_LINES: &[(Option<u64>, &str)] = &[(None, BASIC_FTP_FIXED)];
const NODE_SERVER_LINES: &[(Option<u64>, &str)] = &[
    (Some(1), NODE_SERVER_FIXED_1),
    (Some(2), NODE_SERVER_FIXED_2),
];

/// Requirements that still admit an affected release.
#[test]
fn a_requirement_below_the_fix_admits_an_affected_release() {
    for (req, lines) in [
        ("^5.0.2", BASIC_FTP_LINES),
        ("^5.3.1", BASIC_FTP_LINES),
        ("^6.2.1", BASIC_FTP_LINES),
        ("^6.2.3", BASIC_FTP_LINES),
        ("~6.2.0", BASIC_FTP_LINES),
        ("6.2.1", BASIC_FTP_LINES),
        (">=4.0.0", BASIC_FTP_LINES),
        ("^1.19.9 || ^2.0.5", NODE_SERVER_LINES),
        ("^2.1.3", NODE_SERVER_LINES),
        ("^2.1.5", NODE_SERVER_LINES),
        ("^1.19.17", NODE_SERVER_LINES),
        ("^1.19.18 || ^2.1.5", NODE_SERVER_LINES),
        ("^1.19.17 || ^2.1.6", NODE_SERVER_LINES),
        ("~2.0.0", NODE_SERVER_LINES),
    ] {
        assert!(
            admits_affected(req, lines),
            "{req:?} admits a release before the fix in {lines:?}"
        );
    }
}

/// Requirements whose every alternative starts at or past the fix.
#[test]
fn a_requirement_at_or_past_the_fix_admits_no_affected_release() {
    for (req, lines) in [
        ("^6.2.4", BASIC_FTP_LINES),
        ("^6.2.6", BASIC_FTP_LINES),
        ("^6.3.0", BASIC_FTP_LINES),
        ("^7.0.0", BASIC_FTP_LINES),
        ("~6.2.4", BASIC_FTP_LINES),
        ("6.2.4", BASIC_FTP_LINES),
        (">=6.2.4", BASIC_FTP_LINES),
        ("^10.0.0", BASIC_FTP_LINES),
        ("^2.1.6", NODE_SERVER_LINES),
        ("^2.1.8", NODE_SERVER_LINES),
        ("^1.19.18", NODE_SERVER_LINES),
        ("^1.19.18 || ^2.1.6", NODE_SERVER_LINES),
        ("^1.20.0 || ^2.2.0", NODE_SERVER_LINES),
        ("~2.1.6", NODE_SERVER_LINES),
    ] {
        assert!(
            !admits_affected(req, lines),
            "{req:?} admits no release before the fix in {lines:?}"
        );
    }
}

/// Requirements at the edges of what the reader takes.
#[test]
fn a_requirement_the_reader_cannot_place_keeps_the_override() {
    // Not written as a lowest release: counted as admitting an affected one.
    for req in [
        "*",
        "",
        "latest",
        "x",
        "6.x",
        "^6",
        "^6.2",
        "<7.0.0",
        "6.2.4 - 7.0.0",
        "^6.2.4-beta.1",
        "^6.2.4 || *",
        "^6.2.4 ||",
        "^six.2.4",
        "^99999999999999999999999.0.0",
        "^7.",
        "^7..0",
    ] {
        assert!(
            admits_affected(req, BASIC_FTP_LINES),
            "{req:?} is not a lowest release, so it counts as affected"
        );
    }
    // A major line no advisory entry covers is not affected.
    assert!(
        !admits_affected("^3.0.0", NODE_SERVER_LINES),
        "a 3.x line has no entry"
    );
    assert!(
        !admits_affected("^0.9.0", NODE_SERVER_LINES),
        "a 0.x line has no entry"
    );
    // The number comparison is by number: 6.10.0 is past 6.2.4.
    assert!(
        !admits_affected("^6.10.0", BASIC_FTP_LINES),
        "6.10.0 is past 6.2.4"
    );
    assert!(
        admits_affected("^6.2.04", BASIC_FTP_LINES) == admits_affected("^6.2.4", BASIC_FTP_LINES),
        "a leading zero does not change the number"
    );
    // Spaces around the alternatives do not matter.
    assert!(
        !admits_affected("  ^1.19.18  ||  ^2.1.6  ", NODE_SERVER_LINES),
        "spaces around the alternatives"
    );
    assert!(
        admits_affected("^1.19.18||^2.1.5", NODE_SERVER_LINES),
        "no spaces around the alternatives"
    );
    // With no advisory entry at all nothing is affected.
    assert!(
        !admits_affected("^1.0.0", &[]),
        "no advisory, no affected release"
    );
}

/// The `basic-ftp` override in `e2e/package.json` is still needed: the
/// package that asks for `basic-ftp` (`get-uri`, under `@lhci/cli`) admits
/// releases before the fix. When this fails, the parent has caught up:
/// remove the override and this test's reason for it.
#[test]
fn the_basic_ftp_override_is_removed_when_its_parent_asks_for_the_fix() -> Result<(), TestError> {
    let asked = requirements_for(E2E_LOCK, "basic-ftp")?;
    assert!(
        !asked.is_empty(),
        "no package in {E2E_LOCK} asks for basic-ftp; delete its override"
    );
    assert!(
        asked
            .iter()
            .any(|req| admits_affected(req, BASIC_FTP_LINES)),
        "every package that asks for basic-ftp now asks for {BASIC_FTP_FIXED} or later \
         ({asked:?}); remove the basic-ftp override from e2e/package.json"
    );
    let floor = overrides()?
        .into_iter()
        .find(|(pkg, _)| pkg == "basic-ftp")
        .map(|(_, req)| req);
    assert_eq!(
        floor
            .as_deref()
            .map(|req| admits_affected(req, BASIC_FTP_LINES)),
        Some(false),
        "the basic-ftp override in e2e/package.json must start at {BASIC_FTP_FIXED} or later, \
         found {floor:?}"
    );
    Ok(())
}

/// The TypeScript client's lockfile resolves `@hono/node-server` at or past
/// the fixed release, wherever it appears.
#[test]
fn the_typescript_client_locks_a_fixed_node_server() -> Result<(), TestError> {
    let found: Vec<String> = lockfile_packages_in(TS_LOCK)?
        .into_iter()
        .filter(|(path, _)| path.rsplit("node_modules/").next() == Some("@hono/node-server"))
        .map(|(_, version)| version)
        .collect();
    assert!(
        !found.is_empty(),
        "@hono/node-server is not in {TS_LOCK}; delete this test and its override, or the \
         parser missed it"
    );
    for version in &found {
        let fixed = if version.starts_with("1.") {
            NODE_SERVER_FIXED_1
        } else {
            NODE_SERVER_FIXED_2
        };
        assert!(
            at_least(version, fixed),
            "{TS_LOCK} resolves @hono/node-server {version}; the advisories are fixed in {fixed}"
        );
    }
    Ok(())
}

/// The `@hono/node-server` override in `clients/typescript/package.json`
/// starts at the fixed release, and is still needed: the MCP SDK admits
/// releases before the fix. When the second assertion fails, the SDK has
/// caught up: remove the override.
#[test]
fn the_node_server_override_is_removed_when_the_sdk_asks_for_the_fix() -> Result<(), TestError> {
    let floor = overrides_in("clients/typescript/package.json")?
        .into_iter()
        .find(|(pkg, _)| pkg == "@hono/node-server")
        .map(|(_, req)| req);
    assert_eq!(
        floor
            .as_deref()
            .map(|req| admits_affected(req, NODE_SERVER_LINES)),
        Some(false),
        "the @hono/node-server override in clients/typescript/package.json must start at \
         {NODE_SERVER_FIXED_2} or later, found {floor:?}"
    );
    let asked = requirements_for(TS_LOCK, "@hono/node-server")?;
    assert!(
        !asked.is_empty(),
        "no package in {TS_LOCK} asks for @hono/node-server; delete its override"
    );
    assert!(
        asked
            .iter()
            .any(|req| admits_affected(req, NODE_SERVER_LINES)),
        "every package that asks for @hono/node-server now asks for a fixed release \
         ({asked:?}); remove the override from clients/typescript/package.json"
    );
    Ok(())
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
fn the_lockfile_no_longer_contains_extract_zip() -> Result<(), TestError> {
    let found = versions_of("extract-zip")?;
    assert!(
        found.is_empty(),
        "extract-zip {found:?} is back in e2e/package-lock.json. It has TWO \
         symlink advisories and no fixed version — 2.0.1 is the newest release \
         published — so an upgrade is not available and code scanning opens an \
         alert on it, which turns main red. Find what pulled it in and pin that \
         package past the release that dropped it."
    );
    Ok(())
}

/// Nothing in the tree still ASKS for `extract-zip`.
///
/// The paired half of the test above, and the one that fails first. A package
/// can declare a dependency that npm has not installed yet — a fresh
/// `npm install` on a runner would resolve it and put the vulnerable version
/// back, while the lockfile this repository committed still looks clean.
#[test]
fn no_package_in_the_lockfile_still_depends_on_extract_zip() -> Result<(), TestError> {
    let lock = read("e2e/package-lock.json")?;
    assert!(
        !lock.contains("\"extract-zip\""),
        "e2e/package-lock.json still names extract-zip, so some package \
         declares it even if none resolved to it. The next install would \
         bring it back."
    );
    Ok(())
}

/// The version comparator orders releases numerically, not as text.
///
/// `"0.2.7"` vs `"0.10.0"` is the case a string comparison gets backwards, and
/// every rule above rests on this being right.
#[test]
fn the_version_comparison_is_numeric_not_lexical() -> Result<(), TestError> {
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
    Ok(())
}
