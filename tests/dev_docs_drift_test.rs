// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drift guards for the developer documentation under `docs/internals/`.
//!
//! These pages cite code by path and symbol. Unguarded, they rot silently
//! into the next refactor: a moved file or a renamed function leaves prose
//! that reads authoritatively and is wrong. The project already gates the
//! user-facing docs this way (`docs_drift_test`, `link_integrity_test`);
//! this is the same contract for the developer tree.
//!
//! Conventions enforced here (see
//! `docs/superpowers/specs/2026-07-25-developer-documentation-design.md`):
//!
//! 1. cited repo paths exist,
//! 2. symbols named in link text — `()`-suffixed — resolve to a definition,
//! 3. every page is registered for wiki publication,
//! 4. every mermaid fence is a `sequenceDiagram`,
//! 5. no markdown-link syntax inside a mermaid fence (`build-wiki.py`
//!    rewrites links with no fence awareness),
//! 6. every mermaid fence is preceded by prose, so the page reads where
//!    mermaid does not render.

use std::path::{Path, PathBuf};

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: impl AsRef<Path>) -> String {
    let p = repo().join(rel.as_ref());
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Every `.md` directly under `docs/internals/`, as repo-relative paths.
fn internals_pages() -> Vec<PathBuf> {
    let dir = repo().join("docs/internals");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("md"))
        .map(|p| p.strip_prefix(repo()).expect("under repo").to_path_buf())
        .collect();
    out.sort();
    out
}

/// Every markdown link on a page as `(link_text, target)`.
fn links(text: &str) -> Vec<(String, String)> {
    let re = regex::Regex::new(r"\[([^\]]*)\]\(([^)\s]+)\)").expect("link regex");
    re.captures_iter(text)
        .map(|c| (c[1].to_string(), c[2].to_string()))
        .collect()
}

/// Links that point into the code rather than at another document. Anchored
/// on a known top-level tree so an ordinary `../fault-model.md` doc link and
/// an external URL are both excluded.
fn code_links(text: &str) -> Vec<(String, String)> {
    const TREES: &[&str] = &[
        "src",
        "tests",
        "crates",
        "benches",
        "fuzz",
        "scripts",
        "contrib",
        "harness",
        "ops",
        "man",
        "demos",
        ".github",
        ".githooks",
    ];
    links(text)
        .into_iter()
        .filter(|(_, target)| {
            if target.ends_with(".md") || target.starts_with('#') {
                return false;
            }
            // An absolute link into THIS repo is a code link written the wrong
            // way, and must be reported. An absolute link anywhere else (an
            // RFC, a crate doc) is an ordinary external reference — not ours.
            if target.starts_with("http") {
                return target.contains("github.com/NormB/sipnab");
            }
            // trim_start_matches strips repeatedly, so this handles ../../.
            let stripped = target.trim_start_matches("./").trim_start_matches("../");
            TREES
                .iter()
                .any(|t| stripped == *t || stripped.starts_with(&format!("{t}/")))
        })
        .collect()
}

/// The `()`-suffixed symbol inside a link's text, if any: `` `foo()` ``,
/// `` `Type::method()` ``. The final identifier is what must resolve.
fn symbol_in(link_text: &str) -> Option<String> {
    let re = regex::Regex::new(r"(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Za-z_][A-Za-z0-9_]*)\(\)")
        .expect("symbol regex");
    re.captures(link_text).map(|c| c[1].to_string())
}

/// Resolve a page-relative link target to a repo-relative path.
fn resolve(page: &Path, target: &str) -> PathBuf {
    let dir = page.parent().expect("page has a parent");
    let mut out = dir.to_path_buf();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            p => out.push(p),
        }
    }
    out
}

/// Concatenated Rust source across the workspace, for symbol resolution.
fn all_rust_source() -> String {
    let mut out = String::new();
    let mut stack = vec![repo().join("src"), repo().join("crates")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}")) {
            let p = entry.expect("dir entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push_str(&std::fs::read_to_string(&p).unwrap_or_default());
                out.push('\n');
            }
        }
    }
    out
}

#[test]
fn linked_code_targets_exist() {
    let mut missing = Vec::new();
    let mut seen = 0;
    for page in internals_pages() {
        for (text, target) in code_links(&read(&page)) {
            if target.starts_with("http") {
                continue; // reported by linked_code_uses_relative_paths
            }
            seen += 1;
            if !repo().join(resolve(&page, &target)).exists() {
                missing.push(format!(
                    "{}: [{text}]({target}) points at nothing",
                    page.display()
                ));
            }
        }
    }
    assert!(seen >= 40, "code-link extraction found only {seen} links");
    assert!(
        missing.is_empty(),
        "developer docs link to code that has moved or been deleted:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn linked_symbols_resolve_to_a_definition() {
    let source = all_rust_source();
    let mut missing = Vec::new();
    let mut seen = 0;
    for page in internals_pages() {
        for (text, target) in code_links(&read(&page)) {
            let Some(sym) = symbol_in(&text) else {
                continue; // a plain file/subsystem link carries no symbol claim
            };
            seen += 1;
            if !source.contains(&format!("fn {sym}")) {
                missing.push(format!(
                    "{}: [{text}]({target}) — no `fn {sym}` in the workspace",
                    page.display()
                ));
            }
        }
    }
    assert!(seen >= 30, "symbol extraction found only {seen} claims");
    assert!(
        missing.is_empty(),
        "developer docs name functions that no longer exist:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn linked_code_uses_relative_paths() {
    // An absolute blob URL pins a branch and goes stale silently; the relative
    // form is what build-wiki.py rewrites into a blob URL for the wiki.
    let mut offenders = Vec::new();
    for page in internals_pages() {
        for (text, target) in code_links(&read(&page)) {
            if target.starts_with("http") {
                offenders.push(format!(
                    "{}: [{text}]({target}) — use a relative path",
                    page.display()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "code links must be repo-relative:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn every_internals_page_is_registered_for_the_wiki() {
    let wiki = read("scripts/build-wiki.py");
    let mut unregistered = Vec::new();
    for page in internals_pages() {
        let key = format!(
            "internals/{}",
            page.file_name().expect("file name").to_string_lossy()
        );
        let quoted = format!("\"{key}\"");
        // PAGES maps the key to a title; GROUPS places it in the sidebar.
        // build-wiki.py errors on a PAGES entry with no file, but silently
        // declines to publish a file with no PAGES entry — this closes that.
        if wiki.matches(&quoted).count() < 2 {
            unregistered.push(key);
        }
    }
    assert!(
        unregistered.is_empty(),
        "docs/internals pages missing from build-wiki.py PAGES and/or GROUPS \
         (they would never publish to the wiki):\n  {}",
        unregistered.join("\n  ")
    );
}

/// Fenced mermaid blocks as `(line_index_of_opening_fence, body)`.
fn mermaid_fences(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("```mermaid") {
            let start = i;
            let mut body = String::new();
            i += 1;
            while i < lines.len() && !lines[i].trim_start().starts_with("```") {
                body.push_str(lines[i]);
                body.push('\n');
                i += 1;
            }
            out.push((start, body));
        }
        i += 1;
    }
    out
}

#[test]
fn every_mermaid_block_is_a_sequence_diagram() {
    let mut offenders = Vec::new();
    for page in internals_pages() {
        for (line, body) in mermaid_fences(&read(&page)) {
            let first = body.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
            if first.trim() != "sequenceDiagram" && !first.trim().starts_with("sequenceDiagram") {
                offenders.push(format!(
                    "{}:{}: mermaid block opens with {first:?}, not sequenceDiagram",
                    page.display(),
                    line + 1
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "developer docs use sequenceDiagram only:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn no_markdown_links_inside_mermaid_blocks() {
    // scripts/build-wiki.py applies LINK_RE.sub() to the whole page body with
    // no fence awareness, so a link inside a diagram label gets rewritten into
    // a wiki link and corrupts the diagram source.
    let link = regex::Regex::new(r"\]\([^)\s]+\.md").expect("link regex");
    let mut offenders = Vec::new();
    for page in internals_pages() {
        for (line, body) in mermaid_fences(&read(&page)) {
            if link.is_match(&body) {
                offenders.push(format!(
                    "{}:{}: markdown link inside a mermaid block",
                    page.display(),
                    line + 1
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "build-wiki.py rewrites links without fence awareness:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn every_mermaid_block_is_introduced_by_prose() {
    // A diagram must never carry meaning the prose does not, so the page still
    // reads in a plain-text viewer, a diff, or a renderer without mermaid.
    let mut offenders = Vec::new();
    for page in internals_pages() {
        let text = read(&page);
        let lines: Vec<&str> = text.lines().collect();
        for (line, _) in mermaid_fences(&text) {
            let prev = lines[..line]
                .iter()
                .rev()
                .find(|l| !l.trim().is_empty())
                .copied()
                .unwrap_or("");
            let t = prev.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with("```") || t.starts_with('|') {
                offenders.push(format!(
                    "{}:{}: mermaid block is preceded by {t:?}, not a prose sentence",
                    page.display(),
                    line + 1
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "every diagram needs a one-sentence prose summary above it:\n  {}",
        offenders.join("\n  ")
    );
}

/// build-wiki.py must rewrite code links to blob URLs. A relative code link
/// that reaches the flat wiki resolves to nothing — the wiki has no repo tree.
#[test]
fn build_wiki_rewrites_code_links() {
    let script = read("scripts/build-wiki.py");
    assert!(
        script.contains("CODE_LINK_RE"),
        "build-wiki.py must rewrite relative code links to {{BLOB}} URLs; \
         LINK_RE only matches .md, so code links would reach the wiki dead"
    );
    assert!(
        script.contains("CODE_LINK_RE.sub"),
        "CODE_LINK_RE is defined but never applied in transform()"
    );
}

/// The developer docs carry a designed diagram set; losing them silently
/// would strip the pages of half their meaning.
#[test]
fn developer_docs_carry_their_diagram_set() {
    let total: usize = internals_pages()
        .iter()
        .map(|p| mermaid_fences(&read(p)).len())
        .sum();
    assert!(
        total >= 17,
        "expected at least 17 sequence diagrams across docs/internals, found {total}"
    );
}
