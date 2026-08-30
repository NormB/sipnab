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
    // 473 -> 479 by the two rtpengine pages: docs/rtpengine.md links three
    // sibling docs from its "See also" and two from the body, and
    // docs/internals/rtpengine-control-plane.md links the operator page.
    // Attributed per file before the number moved.
    // 479 -> 478, DOWN by one, which this gate treats as suspicious and is
    // right to. Attributed by measurement before the number moved: exactly one
    // file lost a link, `docs/mcp-tools.md` at 120 -> 119, and it is the
    // same-page anchor `[what changed in 0.5.98](#what-changed-in-0-5-98)`
    // that pointed into a release-history section removed from that reference.
    // The changelog lives in CHANGELOG.md; a tool reference describes what the
    // tools do now. No other page moved, and the extractor still matches --
    // the drop is a deletion, not a narrowing.
    // 478 -> 480: two links to rtpengine.md, one from docs/rest-api.md and one
    // from docs/mcp-tools.md, where each `dialog_assertion` section says what a
    // `media-relay` assertion IS rather than re-explaining relay attribution
    // twice. Two pages, one link each; the site mirrors are generated and this
    // gate reads docs/.
    // 480 -> 482: two links in `docs/mcp-tools.md` for the `export_vcon`
    // section -- its row in the tool index, so the tool is addressable from
    // the table a reader starts at, and a pointer from the feature-gate note
    // to `server_capabilities`, which is what answers "does this binary carry
    // the exporter". Attributed by measurement before the number moved with
    // this gate's OWN rule (relative targets that are same-page anchors or end
    // in `.md`): that page went 93 -> 95 and no other page under docs/ moved.
    // The site mirrors are generated and this extractor reads docs/.
    // 482 -> 498 by the vCon pages. Attributed per file against `main` with
    // this gate's own rules -- `docs/*.md` and `docs/internals/` only, code
    // blocks stripped, same-page anchors counted: `docs/vcon.md` +7 (the new
    // operator page), `docs/internals/vcon.md` +6 (the maintainer page),
    // `docs/mcp-tools.md` +2 for the `export_vcon` section, and +1 each to
    // `docs/README.md` and `docs/internals/README.md` registering the two new
    // pages. `docs/design/vcon.md` contributes nothing: it is outside this
    // walk. A standalone reproduction of the count lands one above the gate's,
    // because `prose()` strips more than fenced blocks; the gate's own number
    // is the one pinned here.
    // 498 -> 501 by three links, all pointing a reader at something runnable
    // rather than restating it: `docs/output-formats.md` +1 to the vCon page
    // from its new `--export-vcon` section, `docs/examples.md` +1 to the same
    // page from recipe 13b, and `docs/examples.md` +1 to `rtpengine.md` from
    // the §6b relay config, which previously told a reader to set up a mirror
    // and never said what reads it. Attributed per file; every other page in
    // this walk held its count.
    // 503 -> 552 by the PA batch. Twelve tools documented in
    // docs/mcp-tools.md, each contributing an index-table row that links to its
    // own section plus the cross-references inside it (the metric tables point
    // at the DSL and MOS pages, the evidence tools at show_evidence). The rest
    // are the RFC section citations scripts/rfc-links.py linked in
    // docs/sip-lint-rules.md for the nine new lint rules.
    // 502 -> 503 by the `timeline` row in the docs/mcp-tools.md index table.
    // One tool, one link: the index entry points at that tool's own section,
    // which is what makes the table an index rather than a list of names.
    // 501 -> 502 by the docs index entry for `vcon-harness.md`. One link, and
    // one is the whole delta: the page's own body links only pages already
    // counted here, so it adds a link TO itself and none that were missing.
    // 552 -> 593: attributed by differential measurement. Removing
    // docs/real-world-captures.md drops the count to 556, so the new page of
    // worked examples contributes 37 of the 41; the other 4 come from links
    // added across the batch's doc edits, including the ones
    // `scripts/link-repo-paths.py --apply` created when it made bare repo
    // paths clickable.
    //
    // 593 -> 595: attributed per file against HEAD before the number moved.
    // Exactly two links, both from the DOC batch. docs/rest-api.md gained
    // `[vCon](vcon.md)` where DOC1 corrected the claim that a vCon carries no
    // media -- the two pages had contradicted each other and the API page held
    // the unsafe version, so it now points at the one that was right.
    // docs/cli-reference.md gained `[Authentication](auth.md)` where DOC8
    // recorded that an exec hook inherits sipnab's whole environment,
    // credentials included, and auth.md is the page that recommends putting
    // them there.
    const EXPECTED_WIKI_LINKS: usize = 595;
    // Raised 459 -> 460 when SRC1 stage 1 shipped: docs/cli-reference.md's
    // `--hep-listen` row now points at cookbook recipe 6d in docs/examples.md
    // rather than restating how to pair `-L` with `-d`. Attributed per file
    // against HEAD before the number moved — docs/examples.md gained recipe 6d
    // itself, whose links are all external (GitHub handles and a repo path),
    // so it held its count, and the site mirrors are not walked by this
    // extractor at all.
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
    // 460 -> 464: the documentation sweep after the 0.5.118 throughput
    // regression, attributed per file against HEAD. docs/README.md +3 -- MCP
    // had no entry in the How-to list at all, so the new one links the guide,
    // the deployment tutorial and the tool reference rather than restating
    // any of them. docs/architecture.md +1, pointing at design/mcp-write-back
    // .md from the sentence that says no MCP tool mutates the analysis, so the
    // reason lives in one place. Every other changed page held its count.
    // 464 -> 467: splitting docs/mcp-deploy.md into docs/mcp-estate.md.
    // Attributed per file against HEAD. docs/README.md +1 for the new How-to
    // entry. docs/mcp-deploy.md's six same-page anchors into the moved
    // sections became cross-page links to mcp-estate.md, and the extracted
    // text's own links back into what stayed behind became cross-page links
    // the other way -- those are counted links where a same-page `#anchor` is
    // not, which is where the remaining +2 comes from.
    // 467 -> 471 by MCPX5's `get_capture_report` section in docs/mcp-tools.md:
    // it links analysis.rs, get_dialog_report, render_ladder and
    // capture_status rather than restating what each already says. Four links,
    // one page -- the site mirror is generated and this gate reads docs/.
    // 471 -> 472 by MCPX2's `aggregate_dialogs` section, which links
    // positioning.md for the one-dimension cap rather than re-arguing it.
    // 472 -> 473 by the response-class section in docs/filter-dsl.md, which
    // links sip-response-codes.md to say what response_class is NOT: that page
    // classifies by what a code means for a CALL, and this field is the
    // numeric IANA registry. Naming the difference beats re-arguing it.

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
    /// Root community links the extractor is expected to find.
    ///
    /// 46 across the root community files listed below. Raise it only after
    /// attributing the delta per file: the count exists so a link that stops
    /// being extracted -- a heading renamed, a list reformatted -- shows up as
    /// a shortfall rather than as fewer links quietly going unchecked.
    const EXPECTED_COMMUNITY_LINKS: usize = 46;
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
        seen, EXPECTED_COMMUNITY_LINKS,
        "extractor found {seen} root community links, expected \
         {EXPECTED_COMMUNITY_LINKS}. More is \
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

/// The `_index.md` audience paths resolve, and name the audiences the page
/// itself claims to serve.
///
/// The task cards above are one axis over the docs ("what do I need to do");
/// `[[extra.audiences]]` is the other ("who am I"). Both are literal
/// `/docs/NAME/` strings in TOML frontmatter, so both bypass Zola's `@/docs`
/// resolution and neither can be caught by the site build — a renamed page
/// leaves the route pointing at a 404 that renders perfectly.
///
/// Three things are checked, and the middle one is the reason this is a test
/// rather than a glance:
///
///   1. every `href` resolves to a `website/content/docs/NAME.md`, and an
///      `#anchor` on it slugifies from a real heading in that page;
///   2. the number of hrefs this gate PARSED equals the number of step
///      entries written, asserted as an equality rather than a floor. A floor
///      passes when the href shape changes and the regex quietly matches
///      nothing, which is exactly how the task-card gate above shipped a card
///      pointing at a page that did not exist;
///   3. the roles equal the ones the "Who it is for" section of the same file
///      names. Two places describe the audience, prose is the one people edit,
///      and a route block addressing a reader the page no longer claims is
///      worse than no route block — it is confidently wrong.
#[test]
fn index_audience_paths_point_at_existing_pages() {
    let text = read("website/content/docs/_index.md");
    let mut parts = text.split("+++");
    parts.next();
    let front = parts
        .next()
        .expect("website/content/docs/_index.md has no `+++` frontmatter");
    let body = parts
        .next()
        .expect("website/content/docs/_index.md has no body after the frontmatter");

    // One chunk per `[[extra.audiences]]` array-of-tables entry.
    let chunks: Vec<&str> = front.split("[[extra.audiences]]").skip(1).collect();
    assert!(
        !chunks.is_empty(),
        "website/content/docs/_index.md has no `[[extra.audiences]]` entries — the \
         audience block moved or was renamed, and this gate is reading nothing. \
         section.html still renders `section.extra.audiences`, so the page would \
         simply lose the block with no other complaint"
    );

    let field = regex::Regex::new(r#"(?m)^(role|goal) = "([^"]+)""#).unwrap();
    let href = regex::Regex::new(r#"href = "/docs/([A-Za-z0-9_-]+)/(#[A-Za-z0-9_.-]+)?""#).unwrap();

    let mut problems = Vec::new();
    let mut roles: Vec<String> = Vec::new();
    let mut entries = 0usize;
    let mut seen = 0usize;

    for chunk in &chunks {
        let mut role = None;
        let mut goal = None;
        for cap in field.captures_iter(chunk) {
            match &cap[1] {
                "role" => role = Some(cap[2].to_string()),
                _ => goal = Some(cap[2].to_string()),
            }
        }
        let role = role
            .unwrap_or_else(|| panic!("an `[[extra.audiences]]` entry has no `role = \"…\"` line"));
        assert!(
            goal.is_some_and(|g| !g.trim().is_empty()),
            "audience `{role}` has no `goal` — the role alone does not tell a \
             reader whether this route is theirs"
        );

        let start = chunk
            .find("steps = [")
            .unwrap_or_else(|| panic!("audience `{role}` has no `steps = [` array"));
        let rest = &chunk[start..];
        let end = rest
            .find("\n]")
            .unwrap_or_else(|| panic!("audience `{role}` has an unterminated `steps = [` array"));
        let steps = &rest[..end];

        let here = steps
            .lines()
            .filter(|l| l.trim_start().starts_with('{'))
            .count();
        assert!(
            here >= 2,
            "audience `{role}` lists {here} step(s). A one-stop route is a link, \
             not a path — either give it the pages that come next, or fold it \
             into the task cards above"
        );
        entries += here;

        for cap in href.captures_iter(steps) {
            seen += 1;
            let page_rel = PathBuf::from("website/content/docs").join(format!("{}.md", &cap[1]));
            if !repo().join(&page_rel).is_file() {
                problems.push(format!(
                    "audience `{role}`: href /docs/{}/ -> no website/content/docs/{}.md",
                    &cap[1], &cap[1]
                ));
                continue;
            }
            if let Some(a) = cap.get(2) {
                check_anchor(
                    &page_rel,
                    a.as_str().trim_start_matches('#'),
                    &format!("_index.md audience `{role}`"),
                    &cap[0],
                    &mut problems,
                );
            }
        }
        roles.push(role);
    }

    assert_eq!(
        seen, entries,
        "{entries} audience step(s) in website/content/docs/_index.md but {seen} \
         href(s) parsed — a step's href is not in the `/docs/NAME/` or \
         `/docs/NAME/#anchor` form this gate reads, so it would ship unchecked. \
         Fix the href, or widen the regex here to cover the new form"
    );

    // The prose the block has to agree with: the bolded lead-in of each bullet
    // under "Who it is for".
    let section = body
        .split("## Who it is for")
        .nth(1)
        .expect("website/content/docs/_index.md has no `## Who it is for` section")
        .split("\n## ")
        .next()
        .expect("the `Who it is for` section terminates");
    let bold = regex::Regex::new(r"(?m)^- \*\*([^*]+)\*\*").unwrap();
    let prose: BTreeSet<String> = bold
        .captures_iter(section)
        .map(|c| c[1].trim().to_string())
        .collect();
    assert!(
        !prose.is_empty(),
        "no bolded audience found under `## Who it is for` — the bullet shape \
         changed and this half of the gate is comparing against an empty set"
    );
    let declared: BTreeSet<String> = roles.iter().cloned().collect();
    assert_eq!(
        declared, prose,
        "the `[[extra.audiences]]` roles and the `Who it is for` bullets name \
         different audiences. Both are read by someone deciding whether this \
         page is for them, so they have to be the same list"
    );

    assert!(
        problems.is_empty(),
        "{} broken audience-path link(s):\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 3b. Index links must land where the task they promise is answered
// ---------------------------------------------------------------------------

/// Words that never decide where a link belongs: articles, prepositions and
/// pronouns.
const LINK_STOPWORDS: &[&str] = &[
    "a", "an", "the", "and", "or", "of", "to", "in", "into", "for", "with", "from", "on", "off",
    "at", "by", "your", "you", "own", "it", "its", "is", "are", "that", "this", "what", "why",
    "how", "when", "where", "as", "all", "my", "me", "be", "do", "does", "not", "no", "non",
    "over", "under", "out", "up",
];

/// Adverbs, which sharpen a promise without naming it. Nobody routes by
/// "actually", so it must not decide whether a landing page is the right one.
const LINK_ADVERBS: &[&str] = &[
    "actually", "really", "just", "still", "also", "exactly", "simply", "properly", "quickly",
    "easily", "even", "only",
];

/// Imperative verbs a task card or an audience step may open with.
///
/// Widen this list when a card opens with a verb it does not yet hold. The
/// list exists so a title cannot dodge the landing rules by turning into a
/// noun phrase: a noun phrase names a topic, and a topic belongs in the
/// reference index further down this page, not in an intent-titled card.
const TASK_VERBS: &[&str] = &[
    "add", "analyze", "ban", "build", "capture", "chase", "check", "collect", "compare", "decode",
    "decrypt", "detect", "diagnose", "drive", "emit", "export", "find", "follow", "forward", "get",
    "graph", "inspect", "install", "let", "lint", "make", "measure", "narrow", "open", "pick",
    "pipe", "read", "run", "scrape", "set", "size", "stop", "turn", "use", "verify", "watch",
    "wire", "write",
];

/// Particles belonging to the leading verb rather than to the subject:
/// "Turn ON the detectors", "Set UP a HEP capture server".
const VERB_PARTICLES: &[&str] = &["up", "on", "off", "out", "in", "it"];

/// The lowercased alphanumeric runs of `s`.
fn link_words(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

/// A crude suffix stemmer, applied to both sides of every comparison so the
/// two always agree: `packets`/`packet`, `dropping`/`drops`,
/// `headlessly`/`headless`.
fn link_stem(w: &str) -> String {
    let mut s = w.to_string();
    for suf in ["ies", "es", "s", "ing", "ed", "ly"] {
        if s.ends_with(suf) && s.len() - suf.len() >= 4 {
            s.truncate(s.len() - suf.len());
            break;
        }
    }
    let b = s.as_bytes();
    if b.len() >= 4 && b[b.len() - 1] == b[b.len() - 2] && !b"aeiou".contains(&b[b.len() - 1]) {
        s.truncate(s.len() - 1);
    }
    s
}

/// Whether `text` talks about `term`.
///
/// A short term (`sip`, `hep`, `mos`) has to match a whole stemmed word,
/// because a substring rule makes `ban` match `banner`. A longer one matches
/// on a five-character prefix, which is what lets `detectors` find
/// `detection` and `dropping` find `drops` with no synonym table to curate.
fn text_covers(text: &str, term: &str) -> bool {
    let k = link_stem(term);
    let stems: BTreeSet<String> = link_words(text).iter().map(|w| link_stem(w)).collect();
    if k.len() < 5 {
        return stems.contains(&k);
    }
    stems
        .iter()
        .any(|t| t.len() >= 5 && (t.starts_with(&k[..5]) || k.starts_with(&t[..5])))
}

/// The leading imperative verb of a link title, when it opens with one.
fn leading_task_verb(title: &str) -> Option<String> {
    let words = link_words(title);
    let first = words.first()?;
    TASK_VERBS.contains(&first.as_str()).then(|| first.clone())
}

/// What a link title promises, with the leading verb, that verb's particle,
/// stopwords and adverbs removed.
///
/// "Set up a HEP capture server" -> `hep`, `capture`, `server`. The verb says
/// the link is a task; the rest says which task, and the rest is what has to
/// be findable where the link lands.
fn subject_terms(title: &str) -> Vec<String> {
    let mut words = link_words(title);
    if leading_task_verb(title).is_some() {
        words.remove(0);
        while words.first().is_some_and(|w| {
            VERB_PARTICLES.contains(&w.as_str()) || LINK_STOPWORDS.contains(&w.as_str())
        }) {
            words.remove(0);
        }
    }
    words
        .into_iter()
        .filter(|w| !LINK_STOPWORDS.contains(&w.as_str()) && !LINK_ADVERBS.contains(&w.as_str()))
        .collect()
}

/// One heading of a content page, with the body underneath it.
struct DocSection {
    /// How many `#` the heading carries.
    level: usize,
    /// The heading text, as written.
    heading: String,
    /// The heading and everything under it, down to the next heading of the
    /// same or a higher level.
    body: String,
}

/// The lead paragraph and the sections of a `website/content/docs` page.
///
/// HTML comments go first. Several of these pages carry a generated-file
/// banner naming the source path, and counting its words as page content let
/// a page "mention" `file` and `source` while saying nothing a reader sees.
/// Headings inside fenced blocks are shell comments rather than headings, so
/// the walk tracks fences the same way `prose` does.
///
/// # Arguments
/// * `rel` - Repo-relative path of the page.
///
/// # Returns
/// The text before the first heading, and every section in document order.
fn page_lead_and_sections(rel: &Path) -> (String, Vec<DocSection>) {
    let raw = read(rel);
    let comment = regex::Regex::new(r"(?s)<!--.*?-->").unwrap();
    let stripped = comment.replace_all(&raw, "").into_owned();
    let body = stripped
        .splitn(3, "+++")
        .nth(2)
        .unwrap_or(&stripped)
        .to_string();

    let head_re = regex::Regex::new(r"^(#{1,6})[ \t]+(.+?)[ \t#]*$").unwrap();
    let lines: Vec<&str> = body.lines().collect();
    let mut fenced = false;
    let mut heads: Vec<(usize, usize, String)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        if let Some(c) = head_re.captures(line) {
            heads.push((i, c[1].len(), c[2].to_string()));
        }
    }

    let lead_end = heads.first().map_or(lines.len(), |h| h.0);
    let lead = lines[..lead_end].join("\n");
    let sections = heads
        .iter()
        .enumerate()
        .map(|(n, (i, level, heading))| {
            let end = heads[n + 1..]
                .iter()
                .find(|(_, other, _)| other <= level)
                .map_or(lines.len(), |(j, _, _)| *j);
            DocSection {
                level: *level,
                heading: heading.clone(),
                body: lines[*i..end].join("\n"),
            }
        })
        .collect();
    (lead, sections)
}

/// A `key = "value"` line from a page's TOML front matter, or an empty string.
fn front_matter_field(rel: &Path, key: &str) -> String {
    let text = read(rel);
    let front = text.split("+++").nth(1).unwrap_or_default().to_string();
    regex::Regex::new(&format!(r#"(?m)^{key} = "(.*)""#))
        .unwrap()
        .captures(&front)
        .map_or_else(String::new, |c| c[1].to_string())
}

/// One `{ title = …, href = "/docs/NAME/" }` entry of the docs index.
struct IndexLink {
    /// Where the entry is written, for the failure message.
    origin: String,
    /// The text a reader clicks.
    title: String,
    /// The `NAME` of `/docs/NAME/`.
    page: String,
    /// The `#anchor` the href carries, without the `#`.
    anchor: Option<String>,
}

/// The body of the TOML array opening at `opener`.
fn array_body<'a>(haystack: &'a str, opener: &str) -> Option<&'a str> {
    let start = haystack.find(opener)?;
    let rest = &haystack[start..];
    let end = rest.find("\n]")?;
    Some(&rest[..end])
}

/// Every task card and audience step of the docs index.
///
/// Parsed one entry line at a time, and every line starting with `{` has to
/// yield both a title and an href. An entry this gate cannot read panics here
/// rather than silently dropping out of the count, which is how the task-card
/// gate above once shipped a card pointing at a page that did not exist.
fn index_links() -> Vec<IndexLink> {
    let text = read("website/content/docs/_index.md");
    let front = text
        .split("+++")
        .nth(1)
        .expect("website/content/docs/_index.md has no `+++` front matter")
        .to_string();

    let mut blocks: Vec<(String, String)> = vec![(
        "task card".to_string(),
        array_body(&front, "tasks = [")
            .expect(
                "website/content/docs/_index.md has no `tasks = [` array — the task cards \
                 moved or were renamed, and this gate is reading nothing",
            )
            .to_string(),
    )];
    let role_re = regex::Regex::new(r#"(?m)^role = "([^"]+)""#).unwrap();
    for chunk in front.split("[[extra.audiences]]").skip(1) {
        let role = role_re
            .captures(chunk)
            .map_or_else(|| "unnamed".to_string(), |c| c[1].to_string());
        let steps = array_body(chunk, "steps = [")
            .unwrap_or_else(|| panic!("audience `{role}` has no `steps = [` array"));
        blocks.push((format!("audience `{role}` step"), steps.to_string()));
    }

    let title_re = regex::Regex::new(r#"title = "([^"]+)""#).unwrap();
    let href_re =
        regex::Regex::new(r#"href = "/docs/([A-Za-z0-9_-]+)/(#[A-Za-z0-9_.-]+)?""#).unwrap();
    let mut out = Vec::new();
    for (origin, array) in &blocks {
        for line in array.lines().filter(|l| l.trim_start().starts_with('{')) {
            let title = title_re
                .captures(line)
                .unwrap_or_else(|| panic!("{origin} has no `title = \"…\"`: {line}"))[1]
                .to_string();
            let href = href_re.captures(line).unwrap_or_else(|| {
                panic!(
                    "{origin} `{title}` has no href in the `/docs/NAME/` or \
                     `/docs/NAME/#anchor` form this gate reads, so it would ship \
                     unchecked. Fix the href, or widen the regex here: {line}"
                )
            });
            out.push(IndexLink {
                origin: origin.clone(),
                title,
                page: href[1].to_string(),
                anchor: href.get(2).map(|m| m.as_str()[1..].to_string()),
            });
        }
    }
    out
}

/// Every index link has to land where the task it names is answered.
///
/// The gates above resolve these links: the page exists, the anchor exists.
/// Both stay green for a link whose TEXT promises one thing and whose target
/// delivers another, and that is the defect this catches. "Run it headless"
/// pointed at `/docs/cli/`, which is titled "CLI Reference" and described as
/// "Complete flag reference for sipnab, organized by functional group" — the
/// page's own lead sends a task-shaped reader to the cookbook instead. "Ban a
/// source with fail2ban" pointed at `/docs/integrations/`, whose first half is
/// HEP: the fail2ban section is the fourth of eight, so the reader arrives and
/// scrolls. Neither link was broken. Both were wrong.
///
/// Three rules, and the middle one is the load-bearing one:
///
///   1. **Intent-titled.** Every card and step opens with an imperative verb
///      from `TASK_VERBS` and leaves at least one subject word behind. These
///      two blocks are entry points for a reader who arrives with a problem,
///      and a title made of stopwords cannot be checked by rule 2 at all.
///   2. **The landing names the task.** At least one subject word of the title
///      appears where the link lands — the target section for an anchored
///      link, and the page's title, description, lead and first section
///      heading for a bare one. That is everything a reader sees on arrival
///      without scrolling. "Headless" appears nowhere in any of them on the
///      CLI page.
///   3. **Not buried.** A bare link fails when some `##` section OTHER than
///      the first names the subject at least as well as the page's own
///      whole-page promise does. That is what "the promise lives in one
///      section" looks like from outside, and the fix is to anchor at it. A
///      subject word already in the page TITLE is dropped from this
///      comparison: it is the page's theme rather than any one section's, and
///      counting it made every "Output" heading on the output-formats page
///      look like a better landing than the page itself.
///
/// The rules do not compose into a demand for an anchor everywhere.
/// `/docs/install/`, `/docs/tui/`, `/docs/filter-dsl/`, `/docs/tuning-capture/`
/// and `/docs/tls-capture/` all pass bare, because on each the whole page is
/// the answer. Nor is an anchor a way out: rule 2 reads the section the anchor
/// selects, so anchoring at a section that never mentions the promise fails
/// exactly as the bare link did.
///
/// The matcher is deliberately crude — stem-prefix word overlap, no synonyms.
/// It cannot see that "Read signaling that is encrypted" and "Capture SIP over
/// TLS" are the same subject, so it can only ever judge the words an author
/// actually chose. That is the blind spot: a link retitled into a page's
/// vocabulary while still promising the wrong thing passes. Rule 1 keeps the
/// cheapest version of that dodge (dropping the verb) out.
#[test]
fn index_links_land_where_the_task_they_promise_is_answered() {
    let links = index_links();
    assert!(
        links.len() >= 10,
        "only {} index link(s) parsed out of website/content/docs/_index.md — the card \
         or step format changed and this gate is checking almost nothing",
        links.len()
    );

    let mut problems = Vec::new();
    for link in &links {
        let rel = PathBuf::from("website/content/docs").join(format!("{}.md", link.page));
        if !repo().join(&rel).is_file() {
            // A missing page is the resolution gates' finding, not this one's.
            continue;
        }
        let at = format!("{} \"{}\"", link.origin, link.title);

        if leading_task_verb(&link.title).is_none() {
            problems.push(format!(
                "{at}: does not open with an imperative verb. These blocks are \
                 intent-titled entry points — a noun phrase names a topic, and topics \
                 belong in the reference index below. Retitle it, or add the verb to \
                 TASK_VERBS in this test if it is genuinely one"
            ));
        }
        let terms = subject_terms(&link.title);
        if terms.is_empty() {
            problems.push(format!(
                "{at}: nothing but stopwords after the verb, so there is no promise to \
                 check. Say what the reader gets"
            ));
            continue;
        }
        let listed = terms.join(", ");

        let (lead, sections) = page_lead_and_sections(&rel);
        let page_title = front_matter_field(&rel, "title");
        let page_desc = front_matter_field(&rel, "description");

        let Some(anchor) = link.anchor.as_deref() else {
            let first_h2 = sections.iter().find(|s| s.level == 2);
            let top = format!(
                "{page_title}\n{page_desc}\n{lead}\n{}",
                first_h2.map_or("", |s| s.heading.as_str())
            );

            if !terms.iter().any(|t| text_covers(&top, t)) {
                problems.push(format!(
                    "{at} -> /docs/{}/ : the title, description, lead and first section \
                     heading of that page mention none of [{listed}]. A reader who \
                     clicked that text arrives at a page that never claims to answer \
                     it. Point the link somewhere that does, or say what this page \
                     actually gives them",
                    link.page
                ));
            }

            // Rule 3. A word already in the page title is the page's theme, not
            // any one section's, so it cannot show that the subject is buried.
            let owned: Vec<String> = terms
                .iter()
                .filter(|t| !text_covers(&page_title, t))
                .cloned()
                .collect();
            if owned.is_empty() {
                continue;
            }
            let top_score = owned.iter().filter(|t| text_covers(&top, t)).count();
            let mut best = 0usize;
            let mut named: Vec<String> = Vec::new();
            for section in sections.iter().filter(|s| s.level == 2).skip(1) {
                let score = owned
                    .iter()
                    .filter(|t| text_covers(&section.heading, t))
                    .count();
                if score > best {
                    best = score;
                    named.clear();
                }
                if score == best && score >= 1 {
                    named.push(format!("#{}", slug_zola(&section.heading)));
                }
            }
            if best >= 1 && best >= top_score {
                named.truncate(4);
                problems.push(format!(
                    "{at} -> /docs/{}/ : that page answers [{listed}] in a section rather \
                     than as a whole — {} names it at least as well as the page's own \
                     title and description do, and it is not the first section, so the \
                     reader lands above it and has to hunt. Anchor the link at the right \
                     one: {}",
                    link.page,
                    if named.len() == 1 {
                        "one of its sections"
                    } else {
                        "sections of it"
                    },
                    named.join(" or ")
                ));
            }
            continue;
        };

        let Some(section) = sections.iter().find(|s| slug_zola(&s.heading) == anchor) else {
            problems.push(format!(
                "{at} -> /docs/{}/#{anchor} : no heading in {} slugifies to that anchor \
                 under Zola's rule, so the link lands at the top of the page and this \
                 gate cannot read what it promised to show",
                link.page,
                rel.display()
            ));
            continue;
        };
        if !terms.iter().any(|t| text_covers(&section.body, t)) {
            problems.push(format!(
                "{at} -> /docs/{}/#{anchor} : lands on \"{}\", which says nothing about \
                 [{listed}]. An anchor is a promise about where the answer is, so it has \
                 to point at the section that holds it",
                link.page, section.heading
            ));
            continue;
        }
        // ... and it has to point at the BEST one. Reaching a section that
        // merely mentions a subject word somewhere in its body is a low bar:
        // `#hep-protocol` on the integrations page clears it for "Ban a source
        // with fail2ban", because a sentence about a HEP source allowlist
        // contains "source". No heading may name the task better than the
        // heading the anchor selects.
        let landed = terms
            .iter()
            .filter(|t| text_covers(&section.heading, t))
            .count();
        let better: Vec<String> = sections
            .iter()
            .filter(|s| slug_zola(&s.heading) != anchor)
            .filter(|s| terms.iter().filter(|t| text_covers(&s.heading, t)).count() > landed)
            .map(|s| format!("#{}", slug_zola(&s.heading)))
            .collect();
        if !better.is_empty() {
            problems.push(format!(
                "{at} -> /docs/{}/#{anchor} : \"{}\" is not the section that answers \
                 [{listed}] — {} name(s) it better. An anchor is a claim about where the \
                 answer is, so it has to be the right section, not merely one that \
                 mentions a word from the title",
                link.page,
                section.heading,
                better
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" or ")
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "{} index link(s) do not deliver what their text promises:\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
}

/// The subject extractor and the word matcher behave as the gate above assumes.
///
/// Both fail open. A stopword list that swallows the subject leaves every link
/// with nothing to check, and a matcher that says yes to everything passes
/// every link — neither shows up anywhere as a failure, so the suite would get
/// greener as the gate stopped working. These cases pin the behavior the
/// rules are written against, including the two the design turns on: a
/// three-letter term must match a word rather than a substring, and a longer
/// one must survive an English suffix on either side.
#[test]
fn link_subject_and_word_matching_behave() {
    assert_eq!(subject_terms("Run it headless"), ["headless"]);
    assert_eq!(
        subject_terms("Set up a HEP capture server"),
        ["hep", "capture", "server"]
    );
    assert_eq!(subject_terms("Turn on the detectors"), ["detectors"]);
    assert_eq!(
        subject_terms("Read what a MOS score is worth"),
        ["mos", "score", "worth"]
    );
    assert!(leading_task_verb("Ban a source with fail2ban").is_some());
    assert!(
        leading_task_verb("CLI reference").is_none(),
        "a noun phrase is not an intent title"
    );

    assert!(text_covers("1. Are you dropping packets?", "packets"));
    assert!(text_covers("analyze a pcap headlessly", "headless"));
    assert!(text_covers("scanner detection heuristics", "detectors"));
    assert!(
        !text_covers("a banner across the top", "ban"),
        "a short term matches a word, never a substring"
    );
    assert!(!text_covers(
        "Complete flag reference for sipnab",
        "headless"
    ));
    assert!(!text_covers("Output Formats", "tooling"));
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
    /// Pages the docs walk is expected to reach.
    // Raised 47 -> 49 by the vCon pair, the same shape as the rtpengine pair
    // above: `vcon.md` for the operator and `internals/vcon.md` for the
    // maintainer, both registered in their indexes. `docs/design/vcon.md` is
    // the third page this branch adds and does NOT move this number --
    // `wiki_source_files()` walks `docs/*.md` and `docs/internals/` only, so a
    // design note has never been in this walk. Attributed per file before the
    // number moved.
    // Raised 49 -> 50 by `docs/vcon-harness.md`, the capture-stack page. ONE
    // and not two: this walk covers `docs/*.md` and `docs/internals/` only, so
    // the generated `website/content/docs/vcon-harness.md` is outside it --
    // the inverse of the markdown-file counter, which sees both. Attributed
    // with `git diff --diff-filter=A HEAD -- 'docs/*.md'` before the number
    // moved.
    // 50 -> 51: docs/real-world-captures.md, one new page.
    const EXPECTED_DOCS_PAGES: usize = 51;
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
    // `mcp-tools.md` and `mcp-protocol.md`. Raised 44 -> 45 by the second MCP
    // split: `mcp-deploy.md` shed its four estate scenarios into
    // `mcp-estate.md`, taking the page from 2386 lines to 1840. Raised 45 -> 47
    // by the rtpengine pair: `rtpengine.md` for the operator and
    // `internals/rtpengine-control-plane.md` for the maintainer, both
    // registered in their indexes. Attributed per file before the number moved.
    assert_eq!(
        checked, EXPECTED_DOCS_PAGES,
        "docs-page walk saw {checked} pages, expected {EXPECTED_DOCS_PAGES}. \
         More is fine — bump \
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
