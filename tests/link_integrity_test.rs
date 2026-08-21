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

#[path = "support/markdown.rs"]
mod markdown;

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

/// Rendered prose of a markdown file: frontmatter, code fences, inline code
/// spans and HTML comments removed.
///
/// Delegates to the shared CommonMark lexer. The scanner this replaces toggled
/// one `bool` on any line starting with ` ``` `, which is wrong in a way that
/// silently disarms every check built on it: a `~~~` block *containing* a
/// ` ``` ` line switched fence mode ON with nothing to switch it back, so the
/// entire remainder of the file was blanked. Both link tests then examined zero
/// links while still counting the file as scanned — a whole page of links going
/// dark with the suite greener than before.
fn prose(rel: impl AsRef<Path>) -> String {
    markdown::prose(&read(rel))
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

/// No page may contain two headings that slugify to the same anchor.
///
/// A duplicate does not fail to render — both GitHub and Zola quietly append
/// `-1`, `-2` in DOCUMENT ORDER — which is worse than a dangling link. The
/// anchor resolves, so nothing complains, and it points at whichever heading
/// happens to be second today. Insert a heading above and every saved bookmark
/// silently lands somewhere else.
///
/// Found on the REST API page: `### GET /v1/dialogs/{call_id}` collided with
/// `### GET /v1/dialogs`, because Zola treats a TRAILING `{...}` as a
/// heading-attribute block and strips it before slugifying. Two unrelated
/// endpoints shared `get-v1-dialogs`, the second became `get-v1-dialogs-1`,
/// and docs/output-formats.md linked straight at it.
///
/// Checked under every slug rule this file models, because a collision under
/// ANY renderer is a broken bookmark for the readers using it.
#[test]
fn no_page_mints_a_positional_anchor() {
    let mut clashes = Vec::new();
    let mut pages = 0usize;

    for rel in md_files_recursive("docs")
        .into_iter()
        .chain(md_files_recursive("website/content/docs"))
    {
        let hs = headings(&rel);
        if hs.is_empty() {
            continue;
        }
        pages += 1;
        for (name, slugger) in [
            ("github", slug_github as fn(&str) -> String),
            ("spec", slug_spec),
            ("zola", slug_zola),
        ] {
            let mut seen: BTreeMap<String, String> = BTreeMap::new();
            for h in &hs {
                let slug = slugger(h);
                if slug.is_empty() {
                    continue;
                }
                if let Some(first) = seen.get(&slug) {
                    clashes.push(format!(
                        "{}: under {name} slugs, \"{h}\" collides with \"{first}\" \
                         (both -> #{slug}), so the second gets a document-order \
                         -N suffix",
                        rel.display()
                    ));
                } else {
                    seen.insert(slug, h.clone());
                }
            }
        }
    }

    // A walk that found no headings would report perfect uniqueness.
    assert!(
        pages >= 10,
        "only {pages} pages had headings — the walk or the heading regex broke, \
         so this gate checked almost nothing"
    );

    assert!(
        clashes.is_empty(),
        "headings that slugify to the same anchor:\n  {}\n\n\
         Rename one so each is unique. Avoid ending a heading with `{{param}}`: \
         Zola strips a trailing brace block as a heading attribute, which is how \
         two endpoints came to share one anchor. `:param` slugifies normally on \
         every renderer.",
        clashes.join("\n  ")
    );
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
    // `/` is in the class so subsection links (`@/docs/internals/x.md`) are
    // resolved too; the pattern previously skipped them entirely.
    let re = regex::Regex::new(r"@/docs/([A-Za-z0-9_./-]+?\.md)(#[A-Za-z0-9_.-]+)?").unwrap();
    // A plain relative .md link inside Zola content silently renders as a
    // dead URL — internal links must use @/docs/. Catch those too.
    // `/` and `.` belong in the class. Without them `[Threading](internals/threading.md)`
    // and `[Up](../install.md)` matched nothing at all — so a plain relative
    // link into a subdirectory, which Zola renders as a literal dead URL, was
    // invisible to the check whose docstring says it flags exactly those.
    let rel_md =
        regex::Regex::new(r"\]\((\./)?([A-Za-z0-9_./-]+\.md)(#[A-Za-z0-9_.-]+)?\)").unwrap();
    // Same-page anchors: [text](#anchor)
    let self_re = regex::Regex::new(r"\]\(#([A-Za-z0-9_.-]+)\)").unwrap();

    let mut problems = Vec::new();
    let mut seen_docs = 0;
    let mut seen_anchors = 0;
    for file in website_docs_files() {
        let from = file.display().to_string();
        let text = prose(&file);
        for cap in re.captures_iter(&text) {
            seen_docs += 1;
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
            seen_anchors += 1;
            check_anchor(
                &file,
                &cap[1],
                &from,
                &format!("(#{})", &cap[1]),
                &mut problems,
            );
        }
    }
    // Two counters, because two independent extractors ran into one. The
    // combined floor of 20 was cleared by the 22 self-anchors alone, so
    // breaking the @/docs regex entirely — 107 links down to zero — left the
    // gate green with a link to a nonexistent page in the tree.
    assert!(
        seen_docs >= 90,
        "@/docs extractor found only {seen_docs} links (107 at the time of \
         writing) — the regex stopped matching and broken links pass unseen"
    );
    assert!(
        seen_anchors >= 15,
        "self-anchor extractor found only {seen_anchors} links (22 at the time \
         of writing) — the regex stopped matching"
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
    // Pinned, not floored. This read `>= 40` while the extractor found 179, so
    // the regex could have stopped matching three quarters of the wiki links and
    // still reported itself healthy. A DROP is the only failure that matters
    // here; growth costs one deliberate bump, the same contract
    // `linked_code_targets_exist` uses.
    //
    // Lowered 180 -> 179 when the duplicated intro in `docs/rest-api.md` came
    // out. A merge of two REST API pages had left both intros in place, so the
    // page pointed at `mcp.md` twice in eight lines; deleting the second copy
    // deleted a real link. Before changing this number, diff the link TARGETS
    // against the previous revision and confirm which one disappeared — a drop
    // that nobody can name is the regex breaking, which is exactly what this
    // pin is here to catch, and editing the number is how it gets missed.
    // Raised 246 -> 248 when `docs/cli-reference.md` gained two links into its
    // new "What `--hep-send` sends" section: one from the `--hep-send` table
    // row, one from that section back to `#security`. Both are same-page
    // anchors and both resolve.
    // Raised 248 -> 249 when the RTCP XR section of `docs/filter-dsl.md`
    // gained a cross-link to `mos-and-codecs.md`, where the rule it depends on
    // — a far end's reported figures never move sipnab's own — is written out.
    // Raised 251 -> 252 when the `lint_dialog` section of `docs/mcp.md` gained
    // a link to `sip-lint-rules.md`: the tool reference names the rule
    // catalog rather than restating the rules beside it.
    // Raised 252 -> 254 when `.sipnablint` was documented on both sides of that
    // pair — the MCP page's suppression section links to the rule catalog for
    // the pattern syntax, and the catalog links back to the MCP page for the
    // response fields that report what a suppression silenced.
    // Raised 254 -> 261 by `tuning-capture.md`, which cross-links the CLI and
    // config references, benchmarks and troubleshooting, and is linked from the
    // docs index in turn.
    // Raised 261 -> 268 by concurrent capture-docs work, diffed per file rather
    // than assumed: `troubleshooting.md` +4, `internals/invariants.md` +2,
    // `benchmarks.md` +1. The `any`-versus-named section added to
    // `tuning-capture.md` contributed none — it cites source paths inline
    // rather than linking out.
    // Raised 268 -> 271 by the encapsulation-aware auto-BPF work: the new
    // "A live capture that sees nothing" section in `troubleshooting.md` links
    // to `tuning-capture.md` (buffer sizing before --capture-tunnels) and back
    // into its own symptom index twice.
    // Raised 271 -> 274 by `encapsulations.md`, diffed per file rather than
    // assumed: the new page links out twice (`troubleshooting.md` for what each
    // undecodable reason means, `cli-reference.md` for `--capture-tunnels`), and
    // the docs index gains one entry pointing at it.
    //
    // NB the expected count appears TWICE below — in the assertion and in the
    // message. They had already drifted apart once (message said 271 while the
    // assertion compared 273), which makes the failure text lie about what it
    // wants. Change both or neither.
    // Raised 274 -> 279 by the MCP walkthrough's "three shapes" rework, counted
    // rather than assumed: the at-a-glance bullet list became a table so each
    // shape links to the section documenting it (+3), and the "always on"
    // section's stale prose pointer ("use 2C or 4", naming headings that had
    // been renamed away) became two real links to the SSH-tunnel and
    // outside-your-network sections (+2). The wiki mirror is ONE copy, not two,
    // so unlike the docs_drift table gate this is +5 and not +10.
    // Raised 279 -> 280 by the federated-tracing section's link back to
    // "Collect captures from several SIP servers in one place", the
    // centralised alternative it compares against. One link, one page.
    // Raised 280 -> 281 by the security model's pointer to the new
    // "Untrusted capture text" section in docs/mcp.md (#139).
    // Raised 281 -> 282 by the security model's pointer to the new
    // "What the write verbs do" section in docs/mcp.md (#146).
    // Raised 282 -> 284 by the stale-documentation sweep: docs/examples.md's
    // MCP tool list now points at docs/mcp.md as the authoritative table
    // instead of restating a count that had drifted from 25 to 31, and
    // internals/build-ci-release.md's new `plugins` row links the design note
    // that priced the feature. One link each, two pages.
    //
    // Taken from a clean run after merging two branches that each bumped this
    // independently — neither side's total described the merged tree.
    // Raised 284 -> 297 by the Installation-page UX rewrite: docs/install.md
    // gained a ten-row "I want to" goal index, which the project's own
    // task-first rule requires of every how-to page, plus an Uninstall section
    // and two pointers from the installer straight to "Check it worked". Every
    // one of those is an intra-page link the extractor counts.
    // Raised 297 -> 310 by the MCP walkthrough's B2BUA-correlation and
    // scripted-client work, taken from this gate's own count: four new rows in
    // the page's "I want to" index, cross-links between the new
    // read-what-matched, correlation-identifier and drive-it-from-a-script
    // sections, and pointers from those back to the HEP, tunnel and
    // client-cookbook sections they compare against. The wiki mirror is ONE
    // copy, so this counts each authored link once.
    // Raised 310 -> 312 by the RFC 7315 charging-vector strategies, taken from
    // this gate's own failing count rather than added up: the walkthrough's
    // correlation-identifier note and mcp.md's strategy table each gained a
    // pointer to docs/design/icid-correlation.md, which is where the argument
    // and its open questions live instead of being restated on either page.
    // Lowered 314 -> 313 on 2026-08-10 by removing the tool-comparison section
    // from the benchmarks pages, which carried one authored link.
    //
    // The expectation is interpolated rather than typed twice: this assertion
    // read `seen, 314` under a message that said "expected 312", because a
    // previous bump moved the number and not the sentence describing it. A
    // gate whose failure message contradicts its own condition sends the next
    // reader looking for a discrepancy that is not there.
    // Raised 313 -> 345 by linking all 32 rows of the MCP tool reference to
    // their own sections: the sections existed and the index did not point at
    // them, so no tool was addressable from the table a reader starts at.
    // Lowered 345 -> 344 by folding `stats` into `capture_status`: its row in
    // the tool reference was one of the 32 links added above, and the section
    // it pointed at is gone with the tool.
    // Raised 344 -> 345 by the doc-link pass: one more tracked repo path in a
    // wiki-published page became a link instead of text a reader must retype.
    // Raised 345 -> 347 by the scoped-token rewrite in docs/auth.md: the
    // scrape-job recipe now points at the MCP page's tool table and at the
    // REST reference, because the credential it hands out is only safe if the
    // reader can see what that scope actually reaches. Attributed with this
    // gate's OWN rule — relative targets that are same-page anchors or end in
    // `.md` — after a first pass counted every relative link and reported a
    // net zero, which would have sent me looking for a regression that did not
    // exist. auth.md is the only changed file, +2, nothing lost elsewhere.
    // Raised 347 -> 383 by the MCP tool-reference rewrite. Attributed with this
    // gate's OWN rule — relative targets that are same-page anchors or end in
    // `.md` — against HEAD before the number moved: docs/mcp.md is the only
    // changed wiki source and carries all 36, and the site mirror under
    // website/content/ is not a wiki source, so this counts each authored link
    // once rather than twice.
    //
    // All 36 are same-page anchors, and they exist because the rewrite answers
    // each parameter where a reader meets it instead of restating the
    // vocabulary on every tool that shares it.
    // `#list_dialogs` takes 9 of them: it owns the diagnostic-alias list, the
    // `DialogSummary` shape and the page-object contract, so find_problems,
    // tail_dialogs, get_dialog, search_by_time and rtp_stats point at it rather
    // than repeating any of the three. `#get_message` takes 4 as the fenced
    // counterpart to get_dialog's unfenced `messages[]`, and `#list_captures`
    // 3 because export_capture, export_audio and open_capture all write names
    // into a directory it is the only tool that reads back.
    // 384: `docs/benchmarks.md` +1. The reach argument added there points at
    // `--hep-rate-limit` in `cli-reference.md#network-listeners` rather than
    // restating the default packets-per-second ceiling a third time.
    // 385: `docs/cli-reference.md` +1. The `--split-keep` table row points at
    // the deletion warning in the same page's capture section rather than
    // restating in a table cell which files the flag will and will not remove.
    // 385: `docs/mcp.md` +1. The tool table's new `media_diagnostics` row
    // links into the section documenting it, exactly as every other row does.
    // 406 -> 412: the plugins and authentication pages 0.5.107 published.
    // 412 -> 426: the TLS capture chooser, which links every method it lists.
    // 426 -> 431: prometheus-metrics.md, split out of rest-api.md, plus the
    // cross-links the two pages now need to point at each other.
    // 431 -> 433: the STUN/TURN sections in troubleshooting.md and
    // encapsulations.md, each linking on to the metrics page.
    // Raised 433 -> 441 by the MCP split: mcp.md shed its tool reference and
    // protocol contract into two new pages, and the four-page set cross-links
    // where one page used to link internally.
    const EXPECTED_WIKI_LINKS: usize = 459;
    // Raised 441 -> 459 by doubling the cookbook from fourteen recipes to
    // twenty-eight. Attributed per file, measured rather than assumed:
    // docs/examples.md +17 and docs/tuning-capture.md +1. The site mirrors
    // gained the same links again (+17 and +1) and are deliberately NOT in
    // this figure -- the extractor walks docs/ only, which is why the delta is
    // 18 and not 36.
    //
    // Of the 17: fourteen are rows in the page's own "What do you want to do?"
    // table, one per new recipe, which is what makes a recipe reachable rather
    // than merely present. The other three are cross-references the new
    // recipes make instead of restating -- two to the capture-tuning page (the
    // drop-counter recipe, and `--cores` meaning something different on a live
    // device) and one to the plugins page. tuning-capture.md's single link
    // points at output-formats.md, where the same counters appear again on the
    // API's capture-quality object.
    // 385: `docs/mos-and-codecs.md` +1. The new "Declaring an impairment factor
    // sipnab does not have" section points at "AMR-WB — published, and
    // mode-dependent" further down the same page rather than restating why a
    // wideband `Ie` cannot go in `[media.codec_ie]`. Attributed per file against
    // HEAD before this number moved: it is the only counted link any staged .md
    // gained, and every other page held its count exactly.

    assert_eq!(
        seen, EXPECTED_WIKI_LINKS,
        "extractor found {seen} wiki links, expected {EXPECTED_WIKI_LINKS}. \
         More is fine — bump this. FEWER means the regex stopped matching and \
         the anchor checks above it silently narrowed."
    );
    assert!(
        problems.is_empty(),
        "{} broken wiki docs link(s):\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
}

/// The root community-health files cross-reference each other by relative
/// path, and nothing above covers them: `wiki_source_files()` walks `docs/`
/// and `website_docs_files()` walks the Zola content, so a rename of
/// `SECURITY.md` would break `SUPPORT.md` and `MAINTAINERS.md` in silence.
///
/// These are the files a first-time reader lands on from the GitHub sidebar,
/// which makes a dead link here more expensive than one buried in the
/// reference, not less.
#[test]
fn root_community_file_links_resolve() {
    const ROOT_FILES: &[&str] = &[
        "README.md",
        "SUPPORT.md",
        "MAINTAINERS.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CODE_OF_CONDUCT.md",
    ];
    let link_re = regex::Regex::new(r"\[[^\]]*\]\(([^)\s]+)\)").unwrap();
    let mut problems = Vec::new();
    let mut seen = 0;
    for name in ROOT_FILES {
        assert!(
            repo().join(name).is_file(),
            "{name} is listed here but missing from the repo root — GitHub \
             renders these in the sidebar, so losing one is user-visible."
        );
        for cap in link_re.captures_iter(&prose(name)) {
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
            if !path_part.is_empty() && !path_part.ends_with(".md") {
                continue;
            }
            seen += 1;
            let target = if path_part.is_empty() {
                PathBuf::from(name)
            } else {
                PathBuf::from(path_part)
            };
            if !repo().join(&target).is_file() {
                problems.push(format!(
                    "{name}: link `{raw}` -> MISSING FILE {}",
                    target.display()
                ));
                continue;
            }
            if let Some(a) = anchor {
                check_anchor(&target, &a, name, &raw, &mut problems);
            }
        }
    }
    // Pinned for the same reason as the wiki pin above: a floor cannot tell a
    // healthy repo from an extractor that stopped matching.
    assert_eq!(
        seen, 46,
        "extractor found {seen} root community links, expected 46. More is \
         fine — bump this. FEWER means the regex stopped matching and this \
         gate narrowed silently."
    );
    assert!(
        problems.is_empty(),
        "{} broken root community link(s):\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
}

/// The `_index.md` task cards' hrefs (`/docs/NAME/`, optionally with an
/// `#anchor`) must point at existing content pages, and the anchor must
/// resolve (the cards bypass @/docs resolution, so Zola will not catch a
/// rename for us).
///
/// The extractor used to require a closing quote immediately after the
/// trailing slash, so the one card carrying an anchor never matched, and the
/// coverage floor of `seen >= 5` sat below the eight cards — a card pointing
/// at `/docs/this-page-does-not-exist/#anchor` matched nothing, was counted
/// as nothing, and shipped green. So the expected count is no longer a
/// number to keep in sync: every entry in the `tasks = [...]` array must
/// yield exactly one parsed href, and an href shape this gate cannot read
/// fails here instead of disappearing. The anchors need checking for the
/// same reason the pages do — `/docs/cookbook/` is generated from
/// `docs/examples.md`, whose headings the docs pipeline is free to retitle.
#[test]
fn index_task_cards_point_at_existing_pages() {
    let text = read("website/content/docs/_index.md");
    // The frontmatter's `tasks = [...]` array: one inline table per line.
    let tasks = {
        let start = text.find("tasks = [").expect(
            "website/content/docs/_index.md has no `tasks = [` array — the task cards \
             moved or were renamed, and this gate is reading nothing",
        );
        let rest = &text[start..];
        let end = rest
            .find("\n]")
            .expect("unterminated `tasks = [` array in website/content/docs/_index.md");
        &rest[..end]
    };
    let cards = tasks
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .count();
    let re = regex::Regex::new(r#"href = "/docs/([A-Za-z0-9_-]+)/(#[A-Za-z0-9_.-]+)?""#).unwrap();
    let mut problems = Vec::new();
    let mut seen = 0;
    for cap in re.captures_iter(tasks) {
        seen += 1;
        let page_rel = PathBuf::from("website/content/docs").join(format!("{}.md", &cap[1]));
        if !repo().join(&page_rel).is_file() {
            problems.push(format!(
                "task card href /docs/{}/ -> no website/content/docs/{}.md",
                &cap[1], &cap[1]
            ));
            continue;
        }
        if let Some(a) = cap.get(2) {
            check_anchor(
                &page_rel,
                a.as_str().trim_start_matches('#'),
                "_index.md task card",
                &cap[0],
                &mut problems,
            );
        }
    }
    assert!(
        cards > 0,
        "no task cards parsed out of the `tasks = [...]` array in \
         website/content/docs/_index.md — the card format changed, so this gate is \
         checking nothing; teach it the new shape"
    );
    assert_eq!(
        seen, cards,
        "{cards} task card(s) in website/content/docs/_index.md but {seen} href(s) \
         parsed — a card's href is not in the `/docs/NAME/` or `/docs/NAME/#anchor` \
         form this gate reads, so it would ship unchecked. Fix the href, or widen the \
         regex here to cover the new form"
    );
    assert!(
        problems.is_empty(),
        "{} broken task-card link(s):\n  {}",
        problems.len(),
        problems.join("\n  ")
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
    // `/` belongs in the class. Without it the ten `@/docs/internals/…` calls —
    // the entire internals nav block in base.html — matched nothing, a 28%
    // blind spot in a test whose comment says it covers ALL templates. A
    // get_url to a nonexistent page there would have shipped a broken nav link.
    let re = regex::Regex::new(
        r"get_url\(path='@/docs/([A-Za-z0-9_./-]+?\.md)'\)\s*\}\}(#[A-Za-z0-9_.-]+)?",
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
                // Zola's rule alone. check_anchor unions the GitHub, task-spec
                // and Zola slugs, which is right for docs/ — read on GitHub,
                // published to the wiki AND generated onto the site — but these
                // targets live under website/content/docs and are rendered by
                // Zola and nothing else. The union accepted GitHub spellings
                // Zola never emits: `#step-0--install-…` (two hyphens) passed
                // here while the identical anchor in a content file failed
                // generated_site_anchors_resolve_under_zola.
                let target_rel = Path::new("website/content/docs").join(&cap[1]);
                let zola_ok = {
                    let mut seen_slugs: BTreeMap<String, usize> = BTreeMap::new();
                    let mut ok = false;
                    for h in headings(&target_rel) {
                        let slug = slug_zola(&h);
                        let n = seen_slugs.entry(slug.clone()).or_insert(0);
                        let candidate = if *n == 0 {
                            slug.clone()
                        } else {
                            format!("{slug}-{n}")
                        };
                        *n += 1;
                        if candidate == anchor.as_str()[1..] {
                            ok = true;
                        }
                    }
                    ok
                };
                if !zola_ok {
                    problems.push(format!(
                        "{from}: `{raw}` -> #{} does not exist in {} under Zola's slug \
                         rule — the site is the only thing that renders it",
                        &anchor.as_str()[1..],
                        target_rel.display()
                    ));
                    continue;
                }
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
        seen >= 32,
        "only {seen} template @/docs links found (36 at the time of writing) — \
         the extractor stopped matching. A floor of 15 against a true 26 could \
         not see that ten subdirectory links matched nothing at all."
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

/// `mcp-overview.md` and `mcp-setup.md` were merged into `mcp.md` in the docs
/// restructure; nothing in either tree may still point at them (or a reader
/// lands on a 404 / dead wiki page).
///
/// # Why `mcp-tools.md` is no longer on this list
///
/// It was, and it has been deliberately taken off. The merge (#145) removed
/// three pages for ONE stated reason: each restated the `--mcp` requires `-N`
/// / stdout-is-the-wire boilerplate, and consolidating gave that invariant a
/// single owner. That was about duplication, not about page count.
///
/// By 0.5.111 `mcp.md` had reached 3435 lines, 2639 of them tool reference,
/// and the boilerplate had already partly returned: `mcp.md` stated the
/// invariant twice and `mcp-walkthrough.md` a third time — two pages, three
/// mentions, before anything was split. Splitting the reference back out to
/// `mcp-tools.md` left the total at three and reduced the introduction to one,
/// with `mcp-protocol.md` owning the normative statement. The measurement is
/// in the commit that made the change.
///
/// So the condition #145 protected is not violated by a page of that name
/// existing, and the guard would now block the fix rather than the defect.
/// `mcp-overview.md` and `mcp-setup.md` stay listed: nothing brought them
/// back, and a stale link to either is still a 404.
#[test]
fn no_references_to_merged_away_mcp_pages() {
    const GONE: &[&str] = &["mcp-overview.md", "mcp-setup.md"];
    let mut offenders = Vec::new();
    // The published surface, not every markdown file on disk. Two changes
    // from the old `md_files_recursive("docs")`:
    //   - gains root markdown: README.md links into docs/ and shipped two
    //     dead mcp-*.md links precisely because the scan stopped at docs/;
    //   - drops docs/superpowers/ and docs/design/: planning material that
    //     is never published, and that must be free to name a merged-away
    //     page while describing the merge.
    let mut files = wiki_source_files();
    files.extend(md_files_recursive("website/content/docs"));
    for name in [
        "README.md",
        "CONTRIBUTING.md",
        "docs/architecture.md",
        "SECURITY.md",
    ] {
        files.push(PathBuf::from(name));
    }
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

/// The three slug styles reproduce anchors verified against real GitHub/Zola output.
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
    // The rule above is why brace params used to collide: under Zola,
    // `GET /v1/dialogs/{call_id}` rendered as #get-v1-dialogs -- the same
    // anchor as plain `GET /v1/dialogs` -- so the second got a document-order
    // -1 suffix that moved whenever an endpoint was inserted above it.
    //
    // api.md now writes path params as `:call_id`, so each endpoint owns a
    // distinct anchor that survives reordering. Collisions are caught
    // repo-wide by no_page_mints_a_positional_anchor; this pins the three
    // endpoints an operator is most likely to bookmark, and the absence of
    // the specific suffix that used to appear.
    let anchors = anchor_candidates(Path::new("website/content/docs/api.md"));
    for expected in [
        "get-v1-dialogs",
        "get-v1-dialogs-call-id",
        "get-v1-dialogs-call-id-report",
    ] {
        assert!(
            anchors.contains(expected),
            "api.md no longer anchors {expected}: {anchors:?}"
        );
    }
    assert!(
        !anchors.contains("get-v1-dialogs-1"),
        "api.md is minting a positional dedup anchor again: {anchors:?}"
    );
}

/// Every operator doc must be reachable from the docs index.
///
/// `architecture.md` (169 lines) and `backers.md` were both in `docs/` and
/// linked from nowhere in `docs/README.md`. Neither was broken and neither was
/// stale — a reader starting at the index simply had no path to them. Nothing
/// in the repo could notice, because an unreferenced file is indistinguishable
/// from a file nobody needs.
///
/// The index is the only entry point the wiki and a GitHub browse share, so
/// "reachable from somewhere in the repo" is not the bar; reachable from here
/// is.
#[test]
fn every_docs_page_is_linked_from_the_index() {
    // Links are extracted from PROSE, not from the file's bytes. A raw
    // `contains("](backers.md")` counted a link that had been wrapped in an
    // HTML comment: the substring was still there, the page was reachable from
    // nowhere on GitHub or the wiki, and this test said it was linked.
    let index = markdown::linkable_prose(&read("docs/README.md"));
    let link_re = regex::Regex::new(r"\]\(\s*\.?/?([^)#\s]+\.md)").expect("link regex");
    let linked: BTreeSet<String> = link_re
        .captures_iter(&index)
        .map(|c| c[1].trim_start_matches("./").to_string())
        .collect();
    assert!(
        linked.len() >= 10,
        "extracted only {} links from docs/README.md — the extraction stopped \
         matching and every page below would report as unlinked",
        linked.len()
    );

    // Recursive: `read_dir` stopped at the top level, so nothing checked
    // whether a page under docs/internals/ was reachable at all.
    let mut unlinked = Vec::new();
    let mut checked = 0usize;
    let mut stack = vec![PathBuf::from("docs")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("docs/").flatten() {
            let p = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if p.is_dir() {
                // Planning material outside the published journey, matching the
                // scope `scanned_markdown` already documents.
                if !matches!(name.as_str(), "design" | "research" | "superpowers") {
                    stack.push(p);
                }
                continue;
            }
            if !name.ends_with(".md") || name == "README.md" {
                continue;
            }
            checked += 1;
            let rel = p
                .strip_prefix("docs")
                .expect("under docs/")
                .to_string_lossy()
                .into_owned();
            // A page is reachable if the index links it directly, or if it
            // sits under a subdirectory whose own index the index links —
            // docs/internals/ is reached through docs/internals/README.md.
            let via_section = rel.contains('/')
                && linked.iter().any(|l| {
                    l.starts_with(&format!("{}/", rel.split('/').next().unwrap_or_default()))
                });
            if !linked.contains(&rel) && !linked.contains(&name) && !via_section {
                unlinked.push(rel);
            }
        }
    }
    // Pinned, not floored. This read `>= 10` while the walk saw 19, which the
    // gate audit reported; the fix widened the walk to recurse into
    // subdirectories, taking the true count to 28 — and left the floor at 10,
    // so the guard ended up nearly three times looser than when it was flagged.
    // The walk could have dropped from 31 pages to 11 and still reported the
    // docs tree as fully checked.
    //
    // An exact pin makes a DROP the failure, which is the only direction that
    // matters here, and matches how `linked_code_targets_exist` pins its link
    // count. Adding a docs page fails this once, deliberately: bump the number.
    // Raised 34 -> 35 by `tuning-capture.md`, 37 -> 38 by
    // `internals/uprobe-capture.md`, 39 -> 40 by `plugins.md` — the published
    // WASM plugins page 0.5.107 added, and 41 -> 42 by
    // `prometheus-metrics.md`, split out of the REST API page. Raised 42 -> 44
    // by the MCP split: `mcp-walkthrough.md` became `mcp-deploy.md` (no
    // change), and `mcp.md` shed its tool reference and protocol contract into
    // `mcp-tools.md` and `mcp-protocol.md`.
    assert_eq!(
        checked, 44,
        "docs-page walk saw {checked} pages, expected 44. More is fine — bump \
         this. FEWER means the walk stopped reading part of docs/ and every \
         reachability assertion above it silently narrowed."
    );
    unlinked.sort();
    assert!(
        unlinked.is_empty(),
        "these docs/ pages are not linked from docs/README.md, so a reader \
         starting at the index cannot reach them: {unlinked:?}"
    );
}

/// Anchors on the generated site pages must resolve under **Zola's** slug
/// rule alone — not under the union of every renderer we support.
///
/// `anchor_candidates` deliberately unions `slug_github`, `slug_spec` and
/// `slug_zola`, because a page in `docs/` is read on GitHub, published to the
/// wiki, and generated onto the site, and an anchor valid for any of those is
/// a real anchor somewhere. For `website/content/docs/**` that union is too
/// generous: Zola is the only thing that will ever render those files, so an
/// anchor that is merely valid on GitHub is a dead link on the site.
///
/// That gap shipped a broken deploy. `docs/mcp-deploy.md` writes its
/// same-page anchors in GitHub's spelling (`#step-0--install-...`, two hyphens
/// because GitHub drops the em dash and keeps its spaces); Zola collapses the
/// run to one hyphen. When the page joined the generated set, the whole test
/// suite stayed green and `zola build` failed with 14 broken internal anchor
/// links — the site's own check catching what ours had excused.
/// `scripts/build-site-pages.py` now translates anchors on the way out; this
/// asserts the translation actually happened.
#[test]
fn generated_site_anchors_resolve_under_zola() {
    let re = regex::Regex::new(r"\]\(\s*(?:@/docs/([^)#\s]+\.md))?(#[^)\s]+)\s*\)").unwrap();
    let dir = repo().join("website/content/docs");

    /// Every anchor Zola emits for a file, including the `-N` it appends to a
    /// duplicate slug.
    fn zola_anchors(rel: &Path) -> BTreeSet<String> {
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        let mut out = BTreeSet::new();
        for h in headings(rel) {
            let slug = slug_zola(&h);
            let n = seen.entry(slug.clone()).or_insert(0);
            out.insert(if *n == 0 {
                slug.clone()
            } else {
                format!("{slug}-{n}")
            });
            *n += 1;
        }
        out
    }

    let mut problems = Vec::new();
    let mut seen = 0;
    let mut files = Vec::new();
    for entry in walk_md(&dir) {
        files.push(entry);
    }
    assert!(
        !files.is_empty(),
        "no markdown found under website/content/docs — this gate is reading nothing"
    );

    for path in &files {
        let rel = path.strip_prefix(repo()).expect("under repo").to_path_buf();
        let text = read(&rel);
        for cap in re.captures_iter(&text) {
            let anchor = cap[2].trim_start_matches('#');
            // Zola resolves a bare `#a` against the page it appears on.
            let target = match cap.get(1) {
                Some(m) => dir.join(m.as_str()),
                None => path.clone(),
            };
            let target_rel = match target.strip_prefix(repo()) {
                Ok(r) => r.to_path_buf(),
                Err(_) => continue,
            };
            if !target.exists() {
                continue; // page existence is covered by its own gate
            }
            seen += 1;
            if !zola_anchors(&target_rel).contains(anchor) {
                problems.push(format!(
                    "{}: #{anchor} does not exist in {} under Zola's slug rule \
                     (it may be the GitHub spelling — regenerate with \
                     scripts/build-site-pages.py)",
                    rel.display(),
                    target_rel.display()
                ));
            }
        }
    }

    assert!(
        seen >= 40,
        "only {seen} anchored links examined on the generated site — the \
         extractor stopped matching and this gate is reporting a safety it is \
         not providing"
    );
    assert!(
        problems.is_empty(),
        "site anchors that Zola will not resolve ({} of {seen}):\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
}

/// Every `.md` under `dir`, recursively.
fn walk_md(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("read dir").flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("md") {
                out.push(p);
            }
        }
    }
    out
}
