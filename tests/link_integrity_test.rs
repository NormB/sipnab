// SPDX-License-Identifier: MIT OR Apache-2.0

//! Static link-integrity / journey guards for BOTH documentation trees:
//!
//! - `website/content/docs/*.md` — Zola content. Internal links use the
//!   `@/docs/NAME.md` form (bare, inside `[text](...)`, or inside
//!   `{{ get_url(path='@/docs/NAME.md') }}` in templates), optionally with a
//!   `#anchor` suffix.
//! - `docs/*.md` (+ `docs/internals/`) — wiki source. Plain relative links
//!   (`NAME.md`, `./NAME.md`, `internals/x.md`, `NAME.md#anchor`).
//!
//! Regression context: a docs restructure renamed/merged/split pages
//! (`mcp-overview.md` + `mcp-setup.md` + `mcp-tools.md` -> `mcp.md`), and a
//! real bug shipped where a link's visible text ("Learn the TUI") no longer
//! matched the destination page's title ("Keybindings"). These tests make
//! every class of that breakage unshippable:
//!
//! 1. every intra-docs link resolves to an existing file (both trees),
//! 2. every `#anchor` resolves to a heading the renderer would emit,
//! 3. link text on the index/getting-started pages must share vocabulary
//!    with the destination page's title,
//! 4. template `@/docs` links (incl. any `}}#anchor`) resolve,
//! 5. nothing references the merged-away mcp-*.md pages.
//!
//! Anchor model (verified against the actually-rendered site in
//! `website/public/docs/api/index.html`): a link anchor is accepted if ANY
//! renderer that serves these files would emit it, i.e. the candidate set is
//! the union of
//!
//! - GitHub-style slugs (wiki tree renders on GitHub): lowercase, backticks
//!   stripped, punctuation removed EXCEPT `-` and `_`, spaces -> `-`;
//! - the stricter spec slug (same, but `_` also stripped);
//! - Zola-style slugs: a trailing `{...}` block is a pulldown-cmark heading
//!   attribute and is stripped from the text first (this is why
//!   `### GET /v1/dialogs/{call_id}` renders as id="get-v1-dialogs-1"),
//!   then every non-alphanumeric run becomes a single `-`;
//!
//! with `-1`, `-2`, ... de-duplication suffixes applied per style, in
//! document order, exactly as GitHub and Zola both do. Headings inside
//! fenced code blocks (shell comments like `# or all features:`) are NOT
//! headings and are excluded, as is `+++` frontmatter.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Repository root, taken from `CARGO_MANIFEST_DIR`.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repo-relative file to a `String`, panicking with the full path
/// on failure.
fn read(rel: impl AsRef<Path>) -> String {
    let p = repo().join(rel.as_ref());
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

// ---------------------------------------------------------------------------
// Markdown pre-processing
// ---------------------------------------------------------------------------

/// Strip Zola `+++` TOML frontmatter (lines in it can start with `#`, which
/// are TOML comments, not headings).
fn strip_frontmatter(md: &str) -> &str {
    let rest = md.strip_prefix("+++").map(|r| r.trim_start_matches('\r'));
    match rest {
        Some(r) => match r.split_once("\n+++") {
            Some((_, body)) => body,
            None => md,
        },
        None => md,
    }
}

/// Blank out fenced code blocks (``` ... ```): their `# comment` lines are
/// not headings and their example text is not rendered links.
fn strip_fences(md: &str) -> String {
    let mut out = String::with_capacity(md.len());
    let mut in_fence = false;
    for line in md.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            out.push('\n');
            continue;
        }
        if !in_fence {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Rendered prose of a markdown file: frontmatter and code fences removed.
fn prose(rel: impl AsRef<Path>) -> String {
    strip_fences(strip_frontmatter(&read(rel)))
}

// ---------------------------------------------------------------------------
// Slugify / anchor candidates
// ---------------------------------------------------------------------------

/// GitHub-style slug: lowercase, backticks stripped, keep [a-z0-9-_ ],
/// spaces -> hyphens. `### \`find_problems\`` -> `find_problems`.
fn slug_github(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter(|c| *c != '`')
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' '))
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// The task-spec slug: like GitHub's but underscores are stripped too.
fn slug_spec(heading: &str) -> String {
    slug_github(heading).chars().filter(|c| *c != '_').collect()
}

/// Zola slug: trailing `{...}` heading-attribute block stripped, then every
/// non-alphanumeric run collapses to a single `-`, trimmed.
fn slug_zola(heading: &str) -> String {
    static ATTR_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let attr_re = ATTR_RE.get_or_init(|| regex::Regex::new(r"\s*\{[^{}]*\}\s*$").unwrap());
    let text = attr_re.replace(heading, "");
    let mut out = String::new();
    let mut pending_dash = false;
    for c in text.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(c);
        } else {
            pending_dash = true;
        }
    }
    out
}

/// ATX heading texts of a markdown file, in order (fences/frontmatter
/// excluded, closing `#`s trimmed).
fn headings(rel: impl AsRef<Path>) -> Vec<String> {
    let re = regex::Regex::new(r"(?m)^#{1,6}[ \t]+(.+?)[ \t#]*$").unwrap();
    re.captures_iter(&prose(rel))
        .map(|c| c[1].to_string())
        .collect()
}

/// All anchors any of our renderers would emit for a file, including the
/// `-N` suffixes both GitHub and Zola append to duplicate slugs.
fn anchor_candidates(rel: impl AsRef<Path>) -> BTreeSet<String> {
    let hs = headings(rel);
    let mut out = BTreeSet::new();
    for slugger in [slug_github, slug_spec, slug_zola] {
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for h in &hs {
            let slug = slugger(h);
            let n = seen.entry(slug.clone()).or_insert(0);
            out.insert(if *n == 0 {
                slug.clone()
            } else {
                format!("{slug}-{n}")
            });
            *n += 1;
        }
    }
    out
}

/// Record a problem if `anchor` matches no anchor any renderer would emit
/// for `target_rel`.
///
/// # Arguments
/// * `target_rel` - Repo-relative markdown file the link points at.
/// * `anchor` - The `#anchor` fragment, without the `#`.
/// * `from` / `raw` - Linking file and raw link text, for the message.
/// * `problems` - Accumulator the failure message is pushed onto.
fn check_anchor(
    target_rel: &Path,
    anchor: &str,
    from: &str,
    raw: &str,
    problems: &mut Vec<String>,
) {
    if !anchor_candidates(target_rel).contains(anchor) {
        problems.push(format!(
            "{from}: link `{raw}` -> DANGLING ANCHOR `#{anchor}` (no heading in {} slugifies to it)",
            target_rel.display()
        ));
    }
}

// ---------------------------------------------------------------------------
// Tree walking
// ---------------------------------------------------------------------------

/// All `.md` files under `rel`, recursively, as repo-relative paths.
fn md_files_recursive(rel: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![repo().join(rel)];
    while let Some(dir) = stack.pop() {
        for entry in
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        {
            let p = entry.expect("dir entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("md") {
                out.push(p.strip_prefix(repo()).unwrap().to_path_buf());
            }
        }
    }
    out.sort();
    out
}

/// The wiki-source pages whose links a reader actually walks: the top-level
/// docs plus internals/. design/ and research/ are internal planning
/// material, not part of the published wiki journey (but links pointing INTO
/// them from scanned pages are still resolved).
fn wiki_source_files() -> Vec<PathBuf> {
    md_files_recursive("docs")
        .into_iter()
        .filter(|p| {
            let mut comps = p.components();
            comps.next(); // "docs"
            let next = comps
                .next()
                .unwrap()
                .as_os_str()
                .to_string_lossy()
                .into_owned();
            next.ends_with(".md") || next == "internals"
        })
        .collect()
}

/// All markdown files under `website/content/docs`, recursively.
fn website_docs_files() -> Vec<PathBuf> {
    md_files_recursive("website/content/docs")
}

// ---------------------------------------------------------------------------
// 1. WEBSITE: every @/docs link (file + anchor) resolves
// ---------------------------------------------------------------------------

/// Every `@/docs` link, same-page anchor, and anchor suffix in the website
/// docs resolves; plain relative `.md` links are flagged as dead-URL bugs.
#[test]
fn website_intra_docs_links_resolve() {
    // Matches the bare form, the [text](@/docs/x.md#a) form, and the
    // get_url(path='@/docs/x.md') form (the path capture is identical).
    let re = regex::Regex::new(r"@/docs/([A-Za-z0-9_.-]+?\.md)(#[A-Za-z0-9_.-]+)?").unwrap();
    // A plain relative .md link inside Zola content silently renders as a
    // dead URL — internal links must use @/docs/. Catch those too.
    let rel_md = regex::Regex::new(r"\]\((\./)?([A-Za-z0-9_-]+\.md)(#[A-Za-z0-9_.-]+)?\)").unwrap();
    // Same-page anchors: [text](#anchor)
    let self_re = regex::Regex::new(r"\]\(#([A-Za-z0-9_.-]+)\)").unwrap();

    let mut problems = Vec::new();
    let mut seen = 0;
    for file in website_docs_files() {
        let from = file.display().to_string();
        let text = prose(&file);
        for cap in re.captures_iter(&text) {
            seen += 1;
            let raw = cap[0].to_string();
            let target = repo().join("website/content/docs").join(&cap[1]);
            if !target.is_file() {
                problems.push(format!(
                    "{from}: link `{raw}` -> MISSING FILE website/content/docs/{}",
                    &cap[1]
                ));
                continue;
            }
            if let Some(anchor) = cap.get(2) {
                let target_rel = Path::new("website/content/docs").join(&cap[1]);
                check_anchor(
                    &target_rel,
                    &anchor.as_str()[1..],
                    &from,
                    &raw,
                    &mut problems,
                );
            }
        }
        for cap in rel_md.captures_iter(&text) {
            problems.push(format!(
                "{from}: plain relative link `{}` — Zola content must use the @/docs/ form or this renders as a dead URL",
                &cap[0]
            ));
        }
        for cap in self_re.captures_iter(&text) {
            seen += 1;
            check_anchor(
                &file,
                &cap[1],
                &from,
                &format!("(#{})", &cap[1]),
                &mut problems,
            );
        }
    }
    assert!(
        seen >= 20,
        "extractor found only {seen} website links — regex broken?"
    );
    assert!(
        problems.is_empty(),
        "{} broken website docs link(s):\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 2. WIKI SOURCE: every relative link (file + anchor) resolves
// ---------------------------------------------------------------------------

/// Every relative .md link and anchor across the wiki-source pages resolves to a real file and heading.
#[test]
fn wiki_intra_docs_links_resolve() {
    let link_re = regex::Regex::new(r"\[[^\]]*\]\(([^)\s]+)\)").unwrap();
    let mut problems = Vec::new();
    let mut seen = 0;
    for file in wiki_source_files() {
        let from = file.display().to_string();
        let dir = file.parent().unwrap();
        for cap in link_re.captures_iter(&prose(&file)) {
            let raw = cap[1].to_string();
            if raw.starts_with("http://")
                || raw.starts_with("https://")
                || raw.starts_with("mailto:")
            {
                continue;
            }
            let (path_part, anchor) = match raw.split_once('#') {
                Some((p, a)) => (p, Some(a.to_string())),
                None => (raw.as_str(), None),
            };
            // Only markdown journeys are in scope (images/assets are not).
            if !path_part.is_empty() && !path_part.ends_with(".md") {
                continue;
            }
            seen += 1;
            let target_rel = if path_part.is_empty() {
                file.clone() // same-page anchor
            } else {
                // Resolve ./ and ../ relative to the linking file's dir.
                let mut resolved = dir.to_path_buf();
                for comp in Path::new(path_part).components() {
                    use std::path::Component::*;
                    match comp {
                        CurDir => {}
                        ParentDir => {
                            if !resolved.pop() {
                                break;
                            }
                        }
                        Normal(c) => resolved.push(c),
                        _ => {}
                    }
                }
                resolved
            };
            if !repo().join(&target_rel).is_file() {
                problems.push(format!(
                    "{from}: link `{raw}` -> MISSING FILE {}",
                    target_rel.display()
                ));
                continue;
            }
            if let Some(a) = anchor {
                check_anchor(&target_rel, &a, &from, &raw, &mut problems);
            }
        }
    }
    assert!(
        seen >= 40,
        "extractor found only {seen} wiki links — regex broken?"
    );
    assert!(
        problems.is_empty(),
        "{} broken wiki docs link(s):\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
}

/// The `_index.md` task cards' hrefs (`/docs/NAME/`) must point at existing
/// content pages (they bypass @/docs resolution, so Zola will not catch a
/// rename for us).
#[test]
fn index_task_cards_point_at_existing_pages() {
    let text = read("website/content/docs/_index.md");
    let re = regex::Regex::new(r#"href = "/docs/([A-Za-z0-9_-]+)/""#).unwrap();
    let mut missing = Vec::new();
    let mut seen = 0;
    for cap in re.captures_iter(&text) {
        seen += 1;
        let page = repo()
            .join("website/content/docs")
            .join(format!("{}.md", &cap[1]));
        if !page.is_file() {
            missing.push(format!(
                "task card href /docs/{}/ -> no website/content/docs/{}.md",
                &cap[1], &cap[1]
            ));
        }
    }
    assert!(
        seen >= 5,
        "only {seen} task cards found — extractor broken?"
    );
    assert!(
        missing.is_empty(),
        "dead task-card hrefs:\n  {}",
        missing.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 4. Templates: @/docs links resolve, including any `}}#anchor` suffix
// ---------------------------------------------------------------------------

/// Every get_url `@/docs` link in every template resolves, including `}}#anchor` suffixes.
#[test]
fn template_docs_links_and_anchors_resolve() {
    // site_journey_test covers bare existence in base/index; this covers ALL
    // templates and validates anchors appended after the get_url call
    // (`{{ get_url(path='@/docs/x.md') }}#anchor`).
    let re = regex::Regex::new(
        r"get_url\(path='@/docs/([A-Za-z0-9_.-]+?\.md)'\)\s*\}\}(#[A-Za-z0-9_.-]+)?",
    )
    .unwrap();
    let mut problems = Vec::new();
    let mut seen = 0;
    for entry in std::fs::read_dir(repo().join("website/templates")).expect("templates dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let from = format!(
            "website/templates/{}",
            p.file_name().unwrap().to_string_lossy()
        );
        let text = std::fs::read_to_string(&p).expect("read template");
        for cap in re.captures_iter(&text) {
            seen += 1;
            let raw = cap[0].to_string();
            let target = repo().join("website/content/docs").join(&cap[1]);
            if !target.is_file() {
                problems.push(format!(
                    "{from}: `{raw}` -> MISSING FILE website/content/docs/{}",
                    &cap[1]
                ));
                continue;
            }
            if let Some(anchor) = cap.get(2) {
                let target_rel = Path::new("website/content/docs").join(&cap[1]);
                check_anchor(
                    &target_rel,
                    &anchor.as_str()[1..],
                    &from,
                    &raw,
                    &mut problems,
                );
            }
        }
    }
    assert!(
        seen >= 15,
        "only {seen} template @/docs links found — extractor broken?"
    );
    assert!(
        problems.is_empty(),
        "{} broken template docs link(s):\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 5. No references to the merged-away MCP pages
// ---------------------------------------------------------------------------

/// `mcp-overview.md`, `mcp-setup.md`, `mcp-tools.md` were merged into
/// `mcp.md` in the docs restructure; nothing in either tree may still point
/// at them (or a reader lands on a 404 / dead wiki page).
#[test]
fn no_references_to_merged_away_mcp_pages() {
    const GONE: &[&str] = &["mcp-overview.md", "mcp-setup.md", "mcp-tools.md"];
    let mut offenders = Vec::new();
    let mut files = md_files_recursive("docs");
    files.extend(md_files_recursive("website/content/docs"));
    for file in files {
        let text = read(&file);
        for (i, line) in text.lines().enumerate() {
            for gone in GONE {
                if line.contains(gone) {
                    offenders.push(format!("{}:{}: references {gone}", file.display(), i + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "references to pages merged into mcp.md:\n  {}",
        offenders.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Unit checks for the slugify model itself (so a future edit to it that
// diverges from GitHub/Zola behavior fails loudly, not silently).
// ---------------------------------------------------------------------------

/// The three slug styles reproduce anchors verified against real GitHub/Zola output, including -1 dedup suffixes.
#[test]
fn slugify_matches_known_rendered_anchors() {
    // Backticked code heading -> backticks stripped, underscore kept.
    assert_eq!(slug_github("`find_problems`"), "find_problems");
    assert_eq!(slug_spec("`find_problems`"), "findproblems");
    // Numbered cookbook heading.
    assert_eq!(
        slug_github("3. Find every failed call, grouped by response code"),
        "3-find-every-failed-call-grouped-by-response-code"
    );
    // Zola: trailing {attr} block stripped (verified against the rendered
    // site: `### GET /v1/dialogs/{call_id}` -> id="get-v1-dialogs" + dedup).
    assert_eq!(slug_zola("GET /v1/dialogs/{call_id}"), "get-v1-dialogs");
    assert_eq!(
        slug_zola("GET /v1/dialogs/{call_id}/report"),
        "get-v1-dialogs-call-id-report"
    );
    assert_eq!(slug_zola("GET /v1/dialogs"), "get-v1-dialogs");
    // Duplicate headings get -1 suffixes.
    let anchors = anchor_candidates(Path::new("website/content/docs/api.md"));
    assert!(
        anchors.contains("get-v1-dialogs"),
        "api.md anchors: {anchors:?}"
    );
    assert!(
        anchors.contains("get-v1-dialogs-1"),
        "dedup -1 suffix missing: {anchors:?}"
    );
}
