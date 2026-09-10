// SPDX-License-Identifier: MIT OR Apache-2.0

//! A test file that imports a feature-gated module must carry that feature's
//! gate.
//!
//! # The defect
//!
//! `tests/corpus_rtcp_chain_test.rs` gained a DTLS measurement and imported
//! `sipnab::capture::dtls`. That module is declared `#[cfg(feature = "tls")]`;
//! the test file gated itself on `native`, which does not imply it. The build
//! `--no-default-features --features api --tests` stopped compiling, and the
//! pre-push feature matrix refused the push.
//!
//! That is the gate working — one cycle before CI would have said the same
//! thing at ten times the cost. What was missing is anything cheaper than a
//! full matrix build, which takes minutes and only runs at push time. This
//! file is that cheaper thing: it reads the module gates out of `src/` and the
//! imports out of `tests/`, and compares them.
//!
//! # It reads the implication graph rather than restating it
//!
//! A file gated on `api` legitimately imports a `native` module, because `api`
//! pulls `native` in. The first version of this gate ignored that and reported
//! eleven correct files — a new scanner's first red is almost always its
//! author's bug, and it was. The fix is not to loosen the rule but to read
//! `Cargo.toml`'s `[features]` table, which is the authority on implication
//! rather than a copy of it, and take the transitive closure of whatever the
//! file's own `cfg` attributes name.
//!
//! What it still does not do is decide whether the resulting build is one CI
//! actually runs. That is the feature matrix's job and it costs minutes; this
//! costs milliseconds and catches the case the matrix only reports at push
//! time.
#![cfg(feature = "full")]

use std::collections::BTreeMap;
use std::path::PathBuf;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `dir`, sorted.
fn rs_files(dir: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![repo().join(dir)];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Map a module path such as `capture::dtls` to the feature gating it.
///
/// Read from `src/`, never restated: the pair `#[cfg(feature = "x")]` followed
/// by `pub mod y;` is the declaration itself, so a module that stops being
/// gated stops appearing here rather than disagreeing with a list.
fn gated_modules() -> BTreeMap<String, String> {
    let re =
        regex::Regex::new(r#"#\[cfg\(feature = "([a-z0-9_-]+)"\)\]\s*\n\s*pub mod ([a-z0-9_]+);"#)
            .expect("pattern");
    let mut out = BTreeMap::new();
    for path in rs_files("src") {
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        // `src/capture/mod.rs` declares `capture::*`; `src/lib.rs` declares the
        // crate root's modules.
        let prefix = path
            .strip_prefix(repo().join("src"))
            .ok()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
            .map(|p| p.to_string_lossy().replace('/', "::"))
            .unwrap_or_default();
        for c in re.captures_iter(&src) {
            let module = if prefix.is_empty() {
                c[2].to_string()
            } else {
                format!("{prefix}::{}", &c[2])
            };
            out.insert(module, c[1].to_string());
        }
    }
    out
}

/// `[features]` from `Cargo.toml`, as `feature -> the features it enables`.
///
/// The manifest is the authority, so this reads it rather than describing it.
/// `dep:` entries and `package/feature` entries name crates rather than this
/// crate's features and are skipped.
fn feature_graph() -> BTreeMap<String, Vec<String>> {
    let manifest =
        std::fs::read_to_string(repo().join("Cargo.toml")).expect("Cargo.toml is in the tree");
    let mut out = BTreeMap::new();
    let mut in_features = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_features = t == "[features]";
            continue;
        }
        if !in_features || t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((name, rest)) = t.split_once('=') else {
            continue;
        };
        let deps: Vec<String> = rest
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(|d| d.trim().trim_matches('"').to_string())
            .filter(|d| !d.is_empty() && !d.contains(':') && !d.contains('/'))
            .collect();
        out.insert(name.trim().to_string(), deps);
    }
    out
}

/// Every feature `seeds` enables, transitively, including the seeds.
fn closure(
    seeds: &[String],
    graph: &BTreeMap<String, Vec<String>>,
) -> std::collections::BTreeSet<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut stack: Vec<String> = seeds.to_vec();
    while let Some(f) = stack.pop() {
        if !seen.insert(f.clone()) {
            continue;
        }
        for d in graph.get(&f).into_iter().flatten() {
            stack.push(d.clone());
        }
    }
    seen
}

/// The feature graph reaches the implication that made the first version wrong.
///
/// A fixture guard on the manifest parse: if `[features]` stops being read,
/// every closure collapses to its seeds and this gate reports correct files as
/// broken again — loudly the first time, and then by being deleted.
#[test]
fn the_feature_graph_knows_that_api_implies_native() {
    let graph = feature_graph();
    assert!(
        graph.len() >= 5,
        "only {} feature(s) parsed out of Cargo.toml; the [features] table is \
         no longer being read: {graph:?}",
        graph.len()
    );
    let from_api = closure(&["api".to_string()], &graph);
    assert!(
        from_api.contains("native"),
        "`api` no longer reaches `native` in the parsed graph, so files gated \
         on `api` will be reported for importing a native module: {from_api:?}"
    );
    let from_native = closure(&["native".to_string()], &graph);
    assert!(
        !from_native.contains("tls"),
        "`native` now reaches `tls`, which is the implication whose ABSENCE \
         caused the break this file is about: {from_native:?}"
    );
}

/// The scan finds the module the defect was about.
///
/// The fixture guard, and it names a specific pair rather than a count: this is
/// a regex over source, and a reformat that put the attribute and the `pub mod`
/// on one line would reduce it to finding nothing. A scan that matches nothing
/// agrees with every tree.
#[test]
fn the_module_scan_finds_the_gate_that_caused_this() {
    let modules = gated_modules();
    assert_eq!(
        modules.get("capture::dtls").map(String::as_str),
        Some("tls"),
        "the scan no longer sees that `capture::dtls` is behind `tls`, so it \
         proves nothing about any other module either. Found: {modules:?}"
    );
    assert!(
        modules.len() >= 5,
        "only {} feature-gated module(s) found; the pattern has stopped \
         matching: {modules:?}",
        modules.len()
    );
}

/// Every test file importing a gated module names that feature in a `cfg`.
#[test]
fn a_test_importing_a_gated_module_names_that_feature() {
    let modules = gated_modules();
    let graph = feature_graph();
    let feat = regex::Regex::new(r#"feature = "([a-z0-9_-]+)""#).expect("pattern");
    let mut problems = Vec::new();
    for path in rs_files("tests") {
        // `tests/support/` holds modules pulled in with `#[path = ...] mod`,
        // not test targets. They carry no `cfg` of their own on purpose: the
        // file that includes them does, and cargo never compiles them alone.
        // Paired with its reason rather than left as a bare skip, because an
        // exclusion nobody can audit is how a scanner quietly stops scanning.
        if path.components().any(|c| c.as_os_str() == "support") {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        let named: Vec<String> = src
            .lines()
            .filter(|l| l.contains("cfg(") || l.contains("cfg_attr("))
            .flat_map(|l| {
                feat.captures_iter(l)
                    .map(|c| c[1].to_string())
                    .collect::<Vec<_>>()
            })
            .collect();
        let enabled = closure(&named, &graph);
        for (module, feature) in &modules {
            let import = format!("sipnab::{module}");
            if !src.contains(&import) {
                continue;
            }
            if !enabled.contains(feature) {
                problems.push(format!(
                    "{}: imports `{import}`, which is behind `{feature}`, and \
                     nothing this file's cfgs enable reaches it",
                    path.strip_prefix(repo()).unwrap_or(&path).display()
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "these test files import a feature-gated module without naming the \
         feature, so a build without it fails to compile and nothing says so \
         until the push:\n  {}",
        problems.join("\n  ")
    );

    // The exclusion above is only safe while every support module has an
    // includer that carries the gate. Checked rather than assumed: a support
    // file nobody includes would be skipped here and compiled nowhere, which
    // is a scanner agreeing with a tree it never read.
    let mut orphans = Vec::new();
    for path in rs_files("tests") {
        if !path.components().any(|c| c.as_os_str() == "support") {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let included = rs_files("tests")
            .iter()
            .filter(|p| !p.components().any(|c| c.as_os_str() == "support"))
            .any(|p| {
                std::fs::read_to_string(p)
                    .unwrap_or_default()
                    .contains(&format!("support/{name}"))
            });
        if !included {
            orphans.push(name);
        }
    }
    assert!(
        orphans.is_empty(),
        "these support modules are excluded from the scan above and included by \
         no test target, so nothing checks their imports at all: {orphans:?}"
    );
}

/// The RTCP half of the corpus measurement still runs without `tls`.
///
/// The other half of the fix, and the one a blunt repair would have lost. The
/// obvious way out of the break was to gate the whole file on `tls`; that
/// compiles, and it silently stops measuring RFC 3550's condition in every
/// build that does not carry DTLS. The items are gated instead, and this pins
/// the distinction so a later tidy-up cannot collapse it.
#[test]
fn gating_the_dtls_half_did_not_gate_the_rtcp_half() {
    let path = repo().join("tests/corpus_rtcp_chain_test.rs");
    let src = std::fs::read_to_string(&path).expect("the corpus measurement is in the tree");
    let file_gate = src
        .lines()
        .find(|l| l.trim_start().starts_with("#![cfg("))
        .unwrap_or_default();
    assert!(
        !file_gate.contains("tls"),
        "the whole corpus measurement is gated on `tls`, so a build without \
         DTLS stops measuring RFC 3550 A.2's condition as well: {file_gate}"
    );
    assert!(
        src.contains("fn the_corpus_holds_rtcp_whose_lengths_cannot_chain"),
        "the RTCP measurement is gone from the file this gate is about"
    );
    let rtcp = src
        .find("fn the_corpus_holds_rtcp_whose_lengths_cannot_chain")
        .expect("the RTCP test is present");
    let head = &src[rtcp.saturating_sub(400)..rtcp];
    assert!(
        !head.contains("feature = \"tls\""),
        "the RTCP measurement itself is now gated on `tls`: {head}"
    );
}
