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
//!    mermaid does not render,
//! 7. every page is published to the website, and the committed site mirror
//!    under `website/content/docs/internals/` is byte-identical to what
//!    `scripts/build-site-internals.py` produces today,
//! 8. every mirrored page carrying a diagram declares `has_diagrams`, and the
//!    page template loads the mermaid bundle on exactly that flag.

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
///
/// This used to assert only that the string `CODE_LINK_RE` appeared in the
/// script, which is true whether or not the rewriting works — and it did pass
/// while `](../bench/)` published to the wiki dead, because `bench` was not in
/// the regex's list of top-level trees. Inspecting a generator's source is not
/// a test of its output.
#[test]
fn build_wiki_leaves_no_relative_links_in_the_output() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::env::temp_dir().join(format!("sipnab-wiki-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);

    let run = std::process::Command::new("python3")
        .arg(repo.join("scripts/build-wiki.py"))
        .arg(&out)
        .current_dir(repo)
        .output()
        .expect("run scripts/build-wiki.py — python3 must be on PATH");
    assert!(
        run.status.success(),
        "build-wiki.py failed:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );

    let link = regex::Regex::new(r"\]\(([^)]+)\)").unwrap();
    let mut leaked: Vec<String> = Vec::new();

    for entry in std::fs::read_dir(&out).expect("wiki output dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let page = path.file_name().unwrap().to_string_lossy().to_string();
        let body = std::fs::read_to_string(&path).expect("wiki page");
        for cap in link.captures_iter(&body) {
            let target = cap[1].trim();
            // Valid on a flat wiki: an absolute URL, a pure anchor, or a wiki
            // page name. Anything else carrying a path separator is a repo-
            // relative link that resolves to nothing once published.
            let ok = target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
                || target.starts_with('#')
                || !target.contains('/');
            if !ok {
                leaked.push(format!("{page}: ]({target})"));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&out);

    assert!(
        leaked.is_empty(),
        "relative links reached the generated wiki, where they resolve to \
         nothing — add the tree to CODE_LINK_RE in build-wiki.py, or write the \
         link as an absolute URL:\n  {}",
        leaked.join("\n  ")
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

/// Mermaid syntax hazards that render as a *silently broken* diagram.
///
/// Both of these shipped, and both survived every existing gate: the fences
/// were well-formed markdown, started with `sequenceDiagram`, and carried no
/// markdown links, so nothing here looked wrong until the diagrams were put
/// in front of a real mermaid parser.
///
/// 1. `;` is a statement separator in mermaid. A semicolon in note or message
///    text ends the statement there, and the remainder is parsed as a new
///    statement — which fails, taking the whole diagram with it.
/// 2. An actor id that spells a mermaid keyword (`Loop`, `End`, `Alt`, …)
///    tokenizes as that keyword when it appears as a message target, so
///    `Term-->>Loop: ...` is a parse error even though `Loop->>Term: ...`
///    parses.
#[test]
fn mermaid_fences_avoid_syntax_hazards() {
    // Keywords the sequence-diagram lexer claims, lowercased.
    const KEYWORDS: &[&str] = &[
        "loop",
        "alt",
        "else",
        "opt",
        "par",
        "and",
        "end",
        "rect",
        "note",
        "over",
        "activate",
        "deactivate",
        "critical",
        "option",
        "break",
        "box",
        "autonumber",
        "participant",
        "actor",
        "create",
        "destroy",
        "link",
        "links",
        "title",
    ];

    let mut problems = Vec::new();
    for page in internals_pages() {
        let text = read(&page);
        for (line_idx, body) in mermaid_fences(&text) {
            let at = format!("{}:{}", page.display(), line_idx + 1);
            for (n, line) in body.lines().enumerate() {
                if line.contains(';') {
                    problems.push(format!(
                        "{at} (+{n}): `;` is a mermaid statement separator and \
                         truncates the text — use an em dash:\n      {}",
                        line.trim()
                    ));
                }
            }
            for line in body.lines() {
                let t = line.trim();
                let Some(rest) = t
                    .strip_prefix("participant ")
                    .or_else(|| t.strip_prefix("actor "))
                else {
                    continue;
                };
                // `participant Loop as TUI event loop` — the id is the first
                // word; everything after `as` is the display label and may
                // say anything.
                let id = rest.split_whitespace().next().unwrap_or("");
                if KEYWORDS.contains(&id.to_ascii_lowercase().as_str()) {
                    problems.push(format!(
                        "{at}: actor id `{id}` collides with the mermaid \
                         keyword `{}` — it parses as that keyword when used \
                         as a message target",
                        id.to_ascii_lowercase()
                    ));
                }
            }
        }
    }
    assert!(
        problems.is_empty(),
        "mermaid fences with syntax hazards (these render as a broken diagram, \
         on the site and on the wiki):\n  {}",
        problems.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Site mirror: website/content/docs/internals/ is generated, not written
// ---------------------------------------------------------------------------

/// `docs/internals/<name>.md` -> the site file it generates.
fn site_mirror_name(page: &Path) -> String {
    let name = page.file_name().expect("file name").to_string_lossy();
    if name == "README.md" {
        "_index.md".to_string()
    } else {
        name.into_owned()
    }
}

/// Every developer page reaches the website, and no orphan mirror survives a
/// renamed source. The wiki gate above is the same contract for the wiki;
/// without this one a new page publishes to the wiki and silently never
/// appears on sipnab.com.
#[test]
fn every_internals_page_is_published_to_the_site() {
    let dir = repo().join("website/content/docs/internals");
    let expected: Vec<String> = internals_pages()
        .iter()
        .map(|p| site_mirror_name(p))
        .collect();

    let mut missing = Vec::new();
    for name in &expected {
        if !dir.join(name).is_file() {
            missing.push(name.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "docs/internals pages with no site mirror (run \
         `python3 scripts/build-site-internals.py`):\n  {}",
        missing.join("\n  ")
    );

    let mut orphans: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| n.ends_with(".md") && !expected.contains(n))
        .collect();
    orphans.sort();
    assert!(
        orphans.is_empty(),
        "site pages under website/content/docs/internals with no source in \
         docs/internals (a renamed source left these behind):\n  {}",
        orphans.join("\n  ")
    );
}

/// The committed mirror equals what the generator produces today.
///
/// The mirror is committed so the Zola build needs nothing but Zola, which
/// means it is exactly the kind of generated-but-checked-in artifact that
/// goes stale the first time someone edits the source and forgets the
/// script. Regenerate into a temp dir and compare byte-for-byte.
#[test]
fn site_internals_mirror_is_current() {
    let tmp = std::env::temp_dir().join(format!(
        "sipnab-site-internals-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&tmp);

    let out = std::process::Command::new("python3")
        .arg(repo().join("scripts/build-site-internals.py"))
        .arg(&tmp)
        .current_dir(repo())
        .output()
        .expect(
            "run scripts/build-site-internals.py — python3 must be on PATH \
             (CI installs it; wiki-sync.yml already depends on it)",
        );
    assert!(
        out.status.success(),
        "build-site-internals.py failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let committed = repo().join("website/content/docs/internals");
    let mut stale = Vec::new();
    for page in internals_pages() {
        let name = site_mirror_name(&page);
        let fresh = std::fs::read_to_string(tmp.join(&name)).expect("generated page");
        let have = std::fs::read_to_string(committed.join(&name)).unwrap_or_default();
        if fresh != have {
            stale.push(name);
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        stale.is_empty(),
        "website/content/docs/internals is stale — regenerate with \
         `python3 scripts/build-site-internals.py` and commit:\n  {}",
        stale.join("\n  ")
    );
}

/// A mirrored page with a diagram declares `has_diagrams`, and `page.html`
/// loads the mermaid bundle on exactly that flag.
///
/// Two ways this breaks silently: a page gains a diagram and never loads
/// mermaid (the reader sees raw `sequenceDiagram` source), or the template
/// stops gating on the flag and every doc page pays 3.4 MB.
#[test]
fn pages_with_diagrams_load_the_mermaid_bundle() {
    let committed = repo().join("website/content/docs/internals");
    let mut wrong = Vec::new();
    let mut with_diagrams = 0;
    for page in internals_pages() {
        let name = site_mirror_name(&page);
        let mirrored = std::fs::read_to_string(committed.join(&name)).unwrap_or_default();
        let source_has = !mermaid_fences(&read(&page)).is_empty();
        let declares = mirrored.contains("has_diagrams = true");
        let rendered = mirrored.contains("<pre class=\"mermaid\">");
        if source_has {
            with_diagrams += 1;
        }
        if source_has != declares || source_has != rendered {
            wrong.push(format!(
                "{name}: source diagrams={source_has}, has_diagrams={declares}, \
                 rendered <pre class=\"mermaid\">={rendered}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "site mirror diagram flags disagree with the source pages:\n  {}",
        wrong.join("\n  ")
    );
    assert!(
        with_diagrams >= 6,
        "expected at least 6 developer pages to carry diagrams, found {with_diagrams}"
    );

    let tpl = read("website/templates/page.html");
    assert!(
        tpl.contains("page.extra.has_diagrams"),
        "page.html must gate the mermaid bundle on page.extra.has_diagrams"
    );
    for asset in ["js/mermaid.min.js", "js/diagram-viewer.js"] {
        assert!(
            tpl.contains(asset),
            "page.html does not load {asset} — the diagrams would render as \
             raw mermaid source"
        );
        assert!(
            repo().join("website/static").join(asset).is_file(),
            "website/static/{asset} is missing but page.html references it"
        );
    }
}

/// Every mirrored page is reachable from the Docs dropdown.
///
/// The gap that started this: the developer docs shipped and the dropdown
/// never learned about them, so the only way to the pages was a direct URL.
#[test]
fn every_site_internals_page_is_in_the_docs_dropdown() {
    let base = read("website/templates/base.html");
    let mut missing = Vec::new();
    for page in internals_pages() {
        let link = format!("@/docs/internals/{}", site_mirror_name(&page));
        if !base.contains(&link) {
            missing.push(link);
        }
    }
    assert!(
        missing.is_empty(),
        "developer pages absent from the Docs dropdown in base.html:\n  {}",
        missing.join("\n  ")
    );
}

/// The workflow-inventory heading counts the workflows. Keep it honest.
///
/// `build-ci-release.md` opens its inventory with "The N workflows" and then
/// tables them. The count is spelled out in the heading, so adding a workflow
/// silently makes the heading wrong — and a table missing a row reads as
/// "these are all of them" rather than as an omission. Nothing checked either
/// half until `scorecard.yml` became the ninth.
#[test]
fn workflow_inventory_heading_counts_the_workflows() {
    const WORDS: [&str; 16] = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
        "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    ];
    let dir = repo().join(".github/workflows");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("workflows dir")
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x == "yml" || x == "yaml")
        })
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    let n = names.len();
    let word = WORDS
        .get(n)
        .unwrap_or_else(|| panic!("{n} workflows — extend WORDS"));

    let doc = read("docs/internals/build-ci-release.md");
    let heading = format!("## The {word} workflows");
    assert!(
        doc.contains(&heading),
        "docs/internals/build-ci-release.md should say \"{heading}\" — \
         there are {n} workflow files: {names:?}"
    );
    // Every workflow must appear in the table under that heading, not just be
    // counted by it.
    let missing: Vec<&String> = names.iter().filter(|f| !doc.contains(f.as_str())).collect();
    assert!(
        missing.is_empty(),
        "workflows counted but never described in build-ci-release.md: {missing:?}"
    );
}

/// Site pages generated from `docs/` must match what the generator produces.
///
/// Every page under `scripts/build-site-pages.py` was maintained by hand on
/// both sides and drifted badly. The cookbook: 740 lines on the site against
/// 122 in `docs/`, sharing 2 of their 36 commands. The REST API page: 893
/// against 430, each side holding sections the other did not have. The wiki
/// renders from `docs/`, so wiki readers got whichever copy was thinner, shown
/// as though it were the whole page. Nothing was broken, nothing was stale,
/// and nothing could have noticed.
///
/// Regenerate into a temp dir and compare byte-for-byte, then check that no
/// page has fallen out of the registry — see the comment on `orphaned` for
/// why the count of generated pages cannot answer that question.
#[test]
fn site_pages_mirror_is_current() {
    let tmp = std::env::temp_dir().join(format!(
        "sipnab-site-pages-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("temp dir");

    let out = std::process::Command::new("python3")
        .arg(repo().join("scripts/build-site-pages.py"))
        .arg(&tmp)
        .current_dir(repo())
        .output()
        .expect("run scripts/build-site-pages.py — python3 must be on PATH");
    assert!(
        out.status.success(),
        "build-site-pages.py failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut produced = Vec::new();
    let mut stale = Vec::new();
    for entry in std::fs::read_dir(&tmp).expect("generated pages").flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        produced.push(name.clone());
        let fresh = std::fs::read_to_string(entry.path()).expect("generated page");
        let have = read(format!("website/content/docs/{name}"));
        if fresh != have {
            stale.push(name);
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);

    // A count of the pages produced cannot see the registry shrink: drop a page
    // from PAGES and the generator simply stops writing it, so the count drops
    // with it and any floor below the real number still passes. The mirror,
    // meanwhile, stays on disk — still stamped "do not edit", no longer
    // regenerated, quietly back to being the hand-maintained copy this merge
    // existed to end. The banner the generator stamped is the witness that does
    // not move, and needs no number kept in sync with PAGES.
    const BANNER_MARK: &str = "Generated by scripts/build-site-pages.py";
    let mut orphaned = Vec::new();
    for entry in std::fs::read_dir(repo().join("website/content/docs"))
        .expect("read website/content/docs")
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".md") || produced.contains(&name) {
            continue;
        }
        if read(format!("website/content/docs/{name}")).contains(BANNER_MARK) {
            orphaned.push(name);
        }
    }

    assert!(
        !produced.is_empty(),
        "build-site-pages.py generated no pages at all — PAGES is empty, or the \
         script stopped writing to the output directory it was given"
    );
    assert!(
        orphaned.is_empty(),
        "these site pages carry the build-site-pages.py banner but the generator no \
         longer writes them — they were dropped from PAGES in \
         scripts/build-site-pages.py and are hand-maintained copies again. \
         Re-register the page in PAGES, or delete the file if the page is gone:\n  {}",
        orphaned.join("\n  ")
    );
    assert!(
        stale.is_empty(),
        "these site pages are stale — regenerate with \
         `python3 scripts/build-site-pages.py` and commit:\n  {}",
        stale.join("\n  ")
    );
}
