// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gates owed for a bulk text edit that damaged what it was not aiming at.
//!
//! # The failures these exist for
//!
//! A repository-wide rename was applied with regular expressions, three times,
//! and each attempt broke something outside its intent:
//!
//! 1. `\(\)` — meant to tidy the empty parentheses left behind by deleting a
//!    parenthetical — stripped the call parens off **every function-call form in
//!    the changelog**. `explain_response_code()` became `explain_response_code`,
//!    which is exactly the distinction [`mcp::since`] exists to preserve: the
//!    former is a fix to the function, the latter is the release that shipped
//!    the tool. One unit test caught one instance of it.
//!
//! 2. ` +\)` — meant to close up the space before a closing paren — dedented
//!    closing parens in unrelated JavaScript and SCSS.
//!
//! 3. The rename itself rewrote the names **inside URLs**, producing nine
//!    404s. Covered in `doc_link_hygiene_test`.
//!
//! The common shape is a substitution with no idea what it is inside. None of
//! it was caught by review; two of three were caught by machines, and the third
//! by an audit of my own diff. These gates make the invariants explicit so the
//! next bulk edit is checked rather than trusted.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

// ── 1. The changelog's function-call forms ──────────────────────────────────

/// Every tool must still resolve to the release that added it.
///
/// `mcp::since` pins ONE pair by name. That is the pair that happened to be
/// known when the rule was written, and a bulk edit does not damage one entry —
/// it damages all of them. This asks the same question of the whole surface.
///
/// Gated on the item rather than the file: the other gates here read the
/// changelog, the workflows and the site's JavaScript, none of which need a
/// feature, and they must keep running in every combination the matrix builds.
#[cfg(feature = "mcp")]
#[test]
fn every_registered_tool_resolves_a_since_version() {
    let versions = sipnab::mcp::since::versions();
    assert!(
        versions.len() > 20,
        "only {} tools resolved a since-version; the changelog index is not \
         reading what it thinks it is",
        versions.len()
    );
    for (tool, ver) in versions {
        // "Unreleased" is a legitimate answer: a tool named in the pending
        // section has shipped in no release yet, and saying so is the point.
        let released =
            ver.split('.').count() == 3 && ver.split('.').all(|p| p.parse::<u32>().is_ok());
        assert!(
            released || ver == "Unreleased",
            "{tool} resolved to {ver:?}, which is neither a version nor Unreleased"
        );
    }
}

/// The changelog must still contain function-call forms at all.
///
/// This is the invariant `\(\)` destroyed, stated directly. If a future edit
/// strips `()` from every code span again, the distinction between "a fix to
/// the function" and "the release that added the tool" silently collapses, and
/// `since_version` starts answering with releases that predate the tool.
#[test]
fn the_changelog_still_distinguishes_a_function_from_a_tool() {
    let text = std::fs::read_to_string(repo().join("CHANGELOG.md")).expect("CHANGELOG.md");
    let call_forms = text.matches("()`").count();
    assert!(
        call_forms > 50,
        "only {call_forms} function-call code spans left in the changelog. An edit \
         has stripped the parentheses that separate `name()` (the function) from \
         `name` (the tool), which is the pair mcp::since reads"
    );
}

// ── 2. Web assets a text pass has no business reformatting ──────────────────

fn site_js() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dir = repo().join("website/static/js");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("js") {
                out.push(p);
            }
        }
    }
    out
}

/// The site's JavaScript must still parse.
///
/// A prose pass that reaches into `website/static/js` is a prose pass that has
/// gone wrong, and the damage is invisible to every other gate here: Rust
/// formatting does not see it, Vale does not read it, and the site build will
/// happily copy a broken file to `public/`.
#[test]
fn the_sites_javascript_parses() {
    let files = site_js();
    if Command::new("node").arg("--version").output().is_err() {
        eprintln!("node not available — skipping the JavaScript parse check");
        return;
    }
    let mut broken = Vec::new();
    for f in &files {
        let out = Command::new("node")
            .arg("--check")
            .arg(f)
            .output()
            .expect("node --check");
        if !out.status.success() {
            broken.push(format!(
                "{}: {}",
                f.file_name().unwrap_or_default().to_string_lossy(),
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .next()
                    .unwrap_or("")
            ));
        }
    }
    assert!(
        broken.is_empty(),
        "site JavaScript does not parse:\n  {}",
        broken.join("\n  ")
    );
}

/// POSITIVE CONTROL for the check above: it must be looking at real files.
#[test]
fn the_javascript_checker_has_files_to_check() {
    let files = site_js();
    assert!(
        files.len() >= 3,
        "only {} JavaScript file(s) found under website/static/js; the parse \
         check above is passing over nothing",
        files.len()
    );
}

// ── 3. Reporting a subset as the whole ──────────────────────────────────────

/// Every workflow in `.github/workflows` must be known to this test.
///
/// Owed for a different failure in the same session: after a push I read ONE
/// workflow's result and reported the repository green. Eight run here, and two
/// of them were failing at that moment. Reading `--limit 1` and calling it the
/// state is the same error as sampling one file and calling it the tree.
///
/// A list that must be updated when a workflow is added is the cheapest
/// possible reminder that the set is bigger than one.
#[test]
fn the_full_workflow_set_is_accounted_for() {
    // Read from the directory, not from memory. Guessing this list is how the
    // original mistake was made in the first place.
    const KNOWN: &[&str] = &[
        "bench.yml",
        "ci.yml",
        "codeql.yml",
        "docker.yml",
        "fuzz.yml",
        "osv-scanner.yml",
        "pages.yml",
        "quality.yml",
        "release.yml",
        "sanitizers.yml",
        "scorecard.yml",
        "self-hosted-smoke.yml",
        "wiki-sync.yml",
    ];
    let dir = repo().join(".github/workflows");
    let mut found: Vec<String> = std::fs::read_dir(&dir)
        .expect("workflows directory")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
        .collect();
    found.sort();
    assert!(
        found.len() >= 5,
        "only {} workflow(s) found; this gate is reading the wrong directory",
        found.len()
    );
    let unknown: Vec<&String> = found
        .iter()
        .filter(|n| !KNOWN.contains(&n.as_str()))
        .collect();
    assert!(
        unknown.is_empty(),
        "workflow(s) not in this list: {unknown:?}. Add them here, and remember \
         that checking one workflow's result is not checking the repository's"
    );
}

/// The count is the thing that gets forgotten, so it is asserted separately.
#[test]
fn more_than_one_workflow_gates_this_repository() {
    let dir = repo().join(".github/workflows");
    let n = std::fs::read_dir(&dir)
        .expect("workflows directory")
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.ends_with(".yml") || n.ends_with(".yaml")
        })
        .count();
    assert!(
        n > 1,
        "expected several workflows; found {n}. If this ever becomes 1, the \
         habit of reading a single result stops being wrong -- until it is again"
    );
}
