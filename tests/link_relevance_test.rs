// SPDX-License-Identifier: MIT OR Apache-2.0

//! Does the destination answer what the link text promised?
//!
//! Link correctness has two halves and this repository only enforced one.
//!
//! **Resolution** — the target file exists, the `#anchor` slugifies from a real
//! heading — is enforced hard, four times over: `tests/link_integrity_test.rs`,
//! `tests/doc_link_hygiene_test.rs`, and two lychee passes in
//! `.github/workflows/quality.yml`.
//!
//! **Relevance** — the reader lands where the link text said they would — was
//! enforced by nothing. Most cross-page links in the published documentation
//! carry no anchor and land at the top of a page with many sections (151 of 503
//! were anchored when this was written). Most of those are right. The wrong
//! ones are indistinguishable from the right ones to every gate above:
//!
//! ```text
//! [Install sipnab]           -> install.md        (31 headings)   correct
//! [Ban a source with fail2ban] -> integrations.md (8 headings)    wrong
//! ```
//!
//! Both resolve. Both are green. In the first the whole page is the answer; in
//! the second the answer is the fourth of eight sections and the reader has to
//! find it. A green `link_integrity_test` therefore reads as "the links are
//! correct" when it only means "the links resolve".
//!
//! # The rule
//!
//! > A no-anchor cross-page link is wrong when **one section of the target
//! > answers the link text and the target as a whole does not**.
//!
//! That is the whole judgment, and it is deliberately narrower than "the link
//! text names a task". Two independent tests implement it, and a link is
//! flagged if either fires. Both refuse to speak unless they can name the
//! anchor they think the link wants — a finding that cannot be acted on is a
//! finding that gets bypassed.
//!
//! **A. Heading echo.** The link text and one heading of the target reduce to
//! the same content words (either as a subset of the other), that heading is
//! not the page title, and the link carries no anchor. The author already wrote
//! the destination into the link text; the anchor is simply missing.
//!
//! **B. Topic localization.** Take the link text's content words. Discard the
//! ones the target's *title* already names — those describe the page, not a
//! place in it. Discard the ones that appear in a third or more of the page's
//! sections — those are the page's own vocabulary, and a word that is
//! everywhere points nowhere. What is left is the link's distinctive
//! vocabulary. If two or more of those words live in one section, that section
//! holds strictly more of them than any other, and it holds at least half of
//! them, the answer is buried in that section and the link should say so.
//!
//! Worked through the four cases:
//!
//! | link | why |
//! |---|---|
//! | `[Install sipnab]` -> `install.md` | "install" is in the title and in 12 of 17 sections. Nothing distinctive is left. Silent. |
//! | `[Cookbook]` -> `examples.md` | one content word, and it is the page's own title. Silent. |
//! | `[Reading SIP over TLS without keys]` -> `uprobe-walkthrough.md` | every word is in the title and spread across the page. Silent, despite 20 headings. |
//! | `[Ban a source with fail2ban]` -> `integrations.md` | "ban", "source" and "fail2ban" are in no title and each in one section; two of the three are in `## Fail2ban Integration`. **Fires**, naming `#fail2ban-integration`. |
//!
//! # Why not the simpler rules
//!
//! *"Link text has no word in common with the target's title or description,
//! and no anchor."* Rejected after measuring it: the description is written to
//! summarize everything the page covers, so it names the buried topic too.
//! `integrations.md`'s own description ends "...and emit fail2ban and syslog
//! alerts", which gives `[Ban a source with fail2ban]` the same title-and-
//! description coverage as `## Fail2ban Integration` gives it. The known-bad
//! case scores exactly like the known-good ones. A summary cannot discriminate
//! between "the page is about this" and "the page mentions this", because a
//! good summary mentions everything.
//!
//! *"A heading matches the link text better than the title does."* Too eager on
//! its own: it fired on `[response-code reference] -> sip-response-codes.md`
//! and proposed `#failure`, on the strength of the single word "reference"
//! appearing in one section. Requiring **two** distinctive words in the winning
//! section is what separates a section that is about the link text from a
//! section that happens to contain one of its words.
//!
//! *"Link text names a specific task."* No robust test for it exists that is
//! not really a test for something else. "Ban a source with fail2ban" and
//! "Install sipnab" are both imperative verb phrases naming a specific task;
//! the difference between them has nothing to do with their grammar and
//! everything to do with what fraction of the target page answers them.
//!
//! # Why this gate cannot be tuned into uselessness
//!
//! The obvious failure mode of a judgment gate is that the next person to hit
//! it loosens a threshold until their link passes. That is blocked by
//! [`the_rule_reproduces_the_anchors_authors_already_chose`], which is a
//! mutation test run against human ground truth: the repository contains 151
//! cross-page links whose authors *did* choose an anchor. Strip those anchors
//! in memory and the rule must demand them back — for at least 25 of them, and
//! when it does it must name the author's own anchor at least 85% of the time.
//! Loosening the rule to silence a finding drives the agreement rate down;
//! tightening it drives the demand count down. Both are asserted.
//!
//! The corresponding vacuity trap — a walk that quietly finds nothing and
//! reports itself healthy, which is how the fence-lexing bug disarmed both
//! existing link gates — is closed by floors on pages scanned, links found and
//! links actually judged, and by
//! [`a_walk_that_finds_nothing_refuses_rather_than_passing`], which proves
//! those floors fire.
//!
//! # Scope, and a narrower sibling
//!
//! This gate reads every cross-page link in both published trees — `docs/` plus
//! `docs/internals/`, and everything under `website/content/docs/`. A separate
//! gate in `tests/link_integrity_test.rs` judges the docs index's task cards and
//! audience steps against a stricter standard: those are intent-titled entry
//! points, so it also demands an imperative verb and reads the anchored
//! section's body. The two overlap on the index and disagree nowhere; this one
//! is the corpus-wide floor.
//!
//! # ACCEPTED
//!
//! [`ACCEPTED`] records findings judged and not yet fixed. It is empty today —
//! the two links this gate reported when it was written were fixed while it was
//! being written, with the anchors it proposed. Every entry carries a reason;
//! an entry that names no link in the tree fails as stale, and an entry whose
//! link is no longer flagged fails asking to be deleted, so the list cannot rot
//! into a permanent silence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[path = "support/markdown.rs"]
mod markdown;

// ---------------------------------------------------------------------------
// The accepted list
// ---------------------------------------------------------------------------

/// One finding judged by a human and left in place, with the reason.
struct Accepted {
    /// Repo-relative path of the page holding the link.
    src: &'static str,
    /// The link's visible text, verbatim.
    text: &'static str,
    /// Repo-relative path of the page it resolves to.
    target: &'static str,
    /// Why this one is not being fixed right now.
    reason: &'static str,
}

/// Findings that exist today and are not yet fixed.
///
/// The list is a snapshot of judgment, not a permission slip. Two rules keep
/// it from rotting into one: an entry naming no link in the tree fails as
/// stale, and an entry whose link is no longer flagged fails asking to be
/// deleted. Both failures name the entry and the single line to remove.
const ACCEPTED: &[Accepted] = &[
    // Empty, and it should stay that way. The two findings this gate reported
    // when it was written -- `[cookbook recipe 6d]` -> the 32-section cookbook
    // and `[the security implications]` -> the 20-heading uprobe walkthrough,
    // each in both documentation trees -- were fixed while it was being
    // written, with the anchors this gate proposed.
    //
    // An entry looks like:
    //
    //     Accepted {
    //         src: "docs/foo.md",
    //         text: "the link text, verbatim",
    //         target: "docs/bar.md",
    //         reason: "why the whole page really is the answer here",
    //     },
];

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// Words that carry no topic.
///
/// English function words, plus the handful of documentation words that appear
/// in so many link texts and headings that matching on them is noise ("page",
/// "docs", "see", "guide"). Deliberately does NOT contain "reference",
/// "walkthrough" or "rules": those are page subjects here, and dropping them
/// would blind the title check on `cli-reference.md` and `sip-lint-rules.md`.
fn stopwords() -> &'static BTreeSet<&'static str> {
    static S: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    S.get_or_init(|| {
        "a an the and or but of to in on at for with without from by as is are was were be been \
         being this that these those it its not no nor so than then there here your you yours we \
         our us i me my how what when where which who whom why do does did doing done can could \
         should would will shall may might must into onto over under up down out off about across \
         after before between through during again more most other some any each every all both \
         few many much such only own same too very just also via using use used uses one two \
         three four five six seven eight nine ten first second third next previous page pages doc \
         docs documentation see read learn guide guides"
            .split_whitespace()
            .collect()
    })
}

/// Content words of a phrase: lowercased, split on anything that is not
/// `[a-z0-9]`, stopwords and single characters dropped.
///
/// Splitting on non-alphanumerics keeps `fail2ban` whole while breaking
/// `find_problems` into two words and `§7a–7f` into `7a` and `7f`.
fn content_words(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() > 1 && !stopwords().contains(w))
        .map(str::to_string)
        .collect()
}

/// Crude suffix stripping, enough to make "install"/"installing" and
/// "capture"/"captures" the same token.
fn stem(w: &str) -> String {
    for (suffix, replacement) in [("ies", "y"), ("ing", ""), ("ed", ""), ("es", ""), ("s", "")] {
        if let Some(base) = w.strip_suffix(suffix)
            && base.len() + replacement.len() >= 3
        {
            return format!("{base}{replacement}");
        }
    }
    w.to_string()
}

/// Do two already-stemmed words denote the same thing?
///
/// Equality, or a shared prefix when both are at least five characters:
/// stemming leaves "capturing" as "captur" and "capture" as "capture", and the
/// prefix rule is what reunites them. Five is the floor because shorter
/// prefixes start joining unrelated words ("port"/"portable").
fn same_word(a: &str, b: &str) -> bool {
    a == b || (a.len() >= 5 && b.len() >= 5 && (a.starts_with(b) || b.starts_with(a)))
}

/// A stemmed vocabulary that can be asked whether it contains a word.
#[derive(Default, Debug)]
struct Vocab(BTreeSet<String>);

impl Vocab {
    fn extend(&mut self, text: &str) {
        self.0.extend(content_words(text).iter().map(|w| stem(w)));
    }

    fn from(text: &str) -> Self {
        let mut v = Self::default();
        v.extend(text);
        v
    }

    /// `word` must already be stemmed.
    fn has(&self, word: &str) -> bool {
        self.0.contains(word) || (word.len() >= 5 && self.0.iter().any(|w| same_word(w, word)))
    }

    /// Fraction of `words` (stemmed) this vocabulary contains.
    fn coverage(&self, words: &[String]) -> f64 {
        if words.is_empty() {
            return 0.0;
        }
        let hits = words.iter().filter(|w| self.has(w)).count();
        hits as f64 / words.len() as f64
    }
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

/// One `##` section of a page, with everything under it.
#[derive(Debug)]
struct Section {
    /// The `##` heading text, verbatim.
    heading: String,
    /// Level 3+ headings inside it, in order — candidate anchors too.
    subheadings: Vec<String>,
    /// Heading, sub-headings and body prose, stemmed.
    vocab: Vocab,
}

/// A page of the published documentation.
#[derive(Debug)]
struct Page {
    /// Repo-relative path.
    rel: String,
    /// Frontmatter `title` where there is one, else the `#` heading.
    title: String,
    /// Level-2 sections in document order.
    sections: Vec<Section>,
    /// Every heading at level 2 or deeper, in document order.
    headings: Vec<String>,
}

impl Page {
    /// Parse a page out of its raw markdown.
    ///
    /// Reads [`markdown::prose`], so fenced blocks are gone: `# not a heading`
    /// inside a shell example is a comment, and counting it would put a
    /// section boundary in the middle of a section.
    fn parse(rel: &str, raw: &str) -> Self {
        let front_title = frontmatter_field(raw, "title");
        let body = markdown::prose(raw);
        let heading_re = heading_re();

        let mut title = front_title.unwrap_or_default();
        let mut sections: Vec<Section> = Vec::new();
        let mut headings = Vec::new();
        let mut preamble = String::new();

        for line in body.lines() {
            let Some(caps) = heading_re.captures(line) else {
                match sections.last_mut() {
                    Some(s) => s.vocab.extend(line),
                    None => preamble.push_str(line),
                }
                continue;
            };
            let level = caps[1].len();
            let text = caps[2].trim().to_string();
            if level == 1 {
                if title.is_empty() {
                    title = text;
                }
                continue;
            }
            headings.push(text.clone());
            if level == 2 {
                let mut vocab = Vocab::default();
                vocab.extend(&text);
                sections.push(Section {
                    heading: text,
                    subheadings: Vec::new(),
                    vocab,
                });
            } else if let Some(s) = sections.last_mut() {
                s.vocab.extend(&text);
                s.subheadings.push(text);
            }
        }
        let _ = preamble;
        if title.is_empty() {
            title = rel.to_string();
        }
        Page {
            rel: rel.to_string(),
            title,
            sections,
            headings,
        }
    }

    /// GitHub- and Zola-style slugs for a heading.
    ///
    /// Both are emitted because the same page is served by both renderers: the
    /// wiki tree renders on GitHub (which keeps `_`) and the website tree
    /// renders under Zola (which does not).
    fn anchor_for(&self, heading: &str) -> String {
        if self.rel.starts_with("website/") {
            slug_zola(heading)
        } else {
            slug_github(heading)
        }
    }
}

/// `title = "..."` out of `+++` frontmatter, if the file has any.
fn frontmatter_field(raw: &str, key: &str) -> Option<String> {
    let rest = raw.strip_prefix("+++")?;
    let end = rest.find("\n+++")?;
    let re = regex::Regex::new(&format!(r#"(?m)^{key}\s*=\s*"([^"]*)""#)).ok()?;
    re.captures(&rest[..end]).map(|c| c[1].to_string())
}

fn heading_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^(#{1,6})[ \t]+(.+?)[ \t#]*$").unwrap())
}

/// GitHub's slug: lowercase, backticks dropped, keep `[a-z0-9-_]`, spaces to
/// hyphens.
fn slug_github(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter(|c| *c != '`')
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' '))
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// Zola's slug: every run of non-alphanumerics collapses to one hyphen.
fn slug_zola(heading: &str) -> String {
    let mut out = String::new();
    let mut pending = false;
    for c in heading.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            if pending && !out.is_empty() {
                out.push('-');
            }
            pending = false;
            out.push(c);
        } else {
            pending = true;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------

/// A cross-page link: text, where it lands, and whether it names a section.
#[derive(Clone, Debug)]
struct Link {
    src: String,
    text: String,
    target: String,
    anchor: Option<String>,
}

fn link_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\[((?:[^\[\]]|\[[^\[\]]*\])*)\]\(([^)\s]+)\)").unwrap())
}

/// Resolve a link destination to a repo-relative page path, or `None` if it is
/// not an intra-documentation page link.
///
/// Four spellings reach the same pages and all four are in scope, because a
/// reader cannot tell them apart: relative (`examples.md`, `../foo.md`) in the
/// wiki tree, Zola's `@/docs/cookbook.md`, the site-absolute `/docs/cookbook/`
/// used inside website prose, and the fully qualified
/// `https://sipnab.com/docs/integrations/` the wiki tree uses to reach
/// website-only pages.
fn resolve(src: &str, dest: &str, pages: &BTreeMap<String, Page>) -> Option<String> {
    let path_part = dest.split('#').next().unwrap_or("");
    if path_part.is_empty() {
        return None; // same-page anchor
    }
    let site_page = |name: &str| -> Option<String> {
        let name = name.trim_matches('/');
        if name.is_empty() || name.contains('/') {
            return None;
        }
        Some(format!("website/content/docs/{name}.md"))
    };
    let rel = if let Some(rest) = path_part.strip_prefix("@/") {
        format!("website/content/{rest}")
    } else if let Some(rest) = path_part
        .strip_prefix("https://sipnab.com/docs/")
        .or_else(|| path_part.strip_prefix("http://sipnab.com/docs/"))
    {
        site_page(rest)?
    } else if let Some(rest) = path_part.strip_prefix("/docs/") {
        site_page(rest)?
    } else if path_part.contains("://") || path_part.starts_with("mailto:") {
        return None;
    } else if path_part.ends_with(".md") {
        let mut acc = PathBuf::from(src);
        acc.pop();
        for comp in Path::new(path_part).components() {
            use std::path::Component::{CurDir, Normal, ParentDir};
            match comp {
                CurDir => {}
                ParentDir => {
                    acc.pop();
                }
                Normal(c) => acc.push(c),
                _ => return None,
            }
        }
        acc.to_string_lossy().into_owned()
    } else {
        return None;
    };
    if rel == src || !pages.contains_key(&rel) {
        return None;
    }
    Some(rel)
}

// ---------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------

/// Why a link was flagged, and what it should point at.
#[derive(Debug)]
struct Finding {
    rule: &'static str,
    heading: String,
    anchor: String,
    detail: String,
}

/// A target with fewer headings than this is a short scroll, not a search.
const MIN_HEADINGS: usize = 4;

/// Vacuity floors. Each is named once and interpolated into its own failure
/// message: a ratchet that spells its expected value twice drifts from itself
/// (`scripts/check-ratchet-messages.py`).
const MIN_PAGES: usize = 60;
/// Cross-page links the walk must find.
const MIN_LINKS: usize = 400;
/// No-anchor links that must survive the skip filters and be judged.
const MIN_JUDGED: usize = 150;
/// Already-anchored links needed for the ground-truth comparison.
const MIN_ANCHORED: usize = 60;
/// Of those, how many the rule must independently demand an anchor for.
const MIN_DEMANDED: usize = 25;
/// And how often it must then name the author's own anchor.
const MIN_AGREEMENT_PERCENT: usize = 85;

/// Rule A — the link text and one heading of the target say the same thing.
fn heading_echo(link: &Link, page: &Page) -> Option<Finding> {
    if page.headings.len() < MIN_HEADINGS {
        return None;
    }
    let words: Vec<String> = content_words(&link.text).iter().map(|w| stem(w)).collect();
    if words.len() < 2 {
        return None;
    }
    let text_set: BTreeSet<&String> = words.iter().collect();
    let title_set: BTreeSet<String> = content_words(&page.title).iter().map(|w| stem(w)).collect();
    if text_set
        .iter()
        .map(|s| (*s).clone())
        .collect::<BTreeSet<_>>()
        == title_set
    {
        return None; // the link text IS the page's subject
    }
    let mut hits: Vec<&String> = Vec::new();
    for heading in &page.headings {
        let h: BTreeSet<String> = content_words(heading).iter().map(|w| stem(w)).collect();
        if h.len() < 2 {
            continue;
        }
        let t: BTreeSet<String> = words.iter().cloned().collect();
        if h.is_subset(&t) || t.is_subset(&h) {
            hits.push(heading);
        }
    }
    // Two headings matching means two candidate destinations and no advice
    // worth giving.
    let [heading] = hits[..] else { return None };
    Some(Finding {
        rule: "A (heading echo)",
        heading: heading.clone(),
        anchor: page.anchor_for(heading),
        detail: format!("the link text and `{heading}` name the same thing"),
    })
}

/// Rule B — the link's distinctive vocabulary lives in one section.
fn topic_localization(link: &Link, page: &Page) -> Option<Finding> {
    let n = page.sections.len();
    if n < MIN_HEADINGS || page.headings.len() < MIN_HEADINGS {
        return None;
    }
    let words: Vec<String> = content_words(&link.text).iter().map(|w| stem(w)).collect();
    if words.len() < 2 {
        return None;
    }
    let title = Vocab::from(&page.title);
    // The page's own subject already explains the link text.
    if title.coverage(&words) >= 0.5 {
        return None;
    }
    // A word in a third or more of the sections is the page's vocabulary, not a
    // signpost to one of them.
    let pervasive = std::cmp::max(2, n.div_ceil(3));
    let mut distinctive: Vec<&String> = Vec::new();
    for w in &words {
        if title.has(w) {
            continue;
        }
        let df = page.sections.iter().filter(|s| s.vocab.has(w)).count();
        if df >= 1 && df < pervasive {
            distinctive.push(w);
        }
    }
    if distinctive.len() < 2 {
        return None;
    }
    let hits: Vec<usize> = page
        .sections
        .iter()
        .map(|s| distinctive.iter().filter(|w| s.vocab.has(w)).count())
        .collect();
    let best = *hits.iter().max()?;
    if best < 2 || best < distinctive.len().div_ceil(2) {
        return None;
    }
    if hits.iter().filter(|h| **h == best).count() != 1 {
        return None; // two sections tie: no single destination to name
    }
    let idx = hits.iter().position(|h| *h == best)?;
    let section = &page.sections[idx];
    // Within the winning section, the most specific heading wins.
    let mut heading = &section.heading;
    let mut score = Vocab::from(&section.heading).coverage(&words);
    for sub in &section.subheadings {
        let s = Vocab::from(sub).coverage(&words);
        if s > score {
            score = s;
            heading = sub;
        }
    }
    Some(Finding {
        rule: "B (topic localization)",
        heading: heading.clone(),
        anchor: page.anchor_for(heading),
        detail: format!(
            "{:?} are distinctive to this link, and {best} of them are in `{}` \
             (no other section holds more than {})",
            distinctive,
            section.heading,
            hits.iter()
                .filter(|h| **h != best)
                .max()
                .copied()
                .unwrap_or(0)
        ),
    })
}

/// The gate: judge one no-anchor link against its target.
fn judge(link: &Link, page: &Page) -> Option<Finding> {
    if link.anchor.is_some() {
        return None;
    }
    if is_filename(&link.text) {
        // `[install.md](install.md)` promises the page, not a place in it.
        return None;
    }
    heading_echo(link, page).or_else(|| topic_localization(link, page))
}

/// Is this link text just a path, spelled out?
fn is_filename(text: &str) -> bool {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^\s*`?\s*\.{0,2}/?[\w./-]+\.md\s*`?\s*$").unwrap())
        .is_match(text)
}

// ---------------------------------------------------------------------------
// Walking the trees
// ---------------------------------------------------------------------------

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The published documentation: the wiki tree's top-level pages plus
/// `internals/`, and everything under the website's `docs/`.
///
/// `docs/design/` and `docs/research/` are excluded for the same reason
/// `link_integrity_test` excludes them — planning material, not a reader's
/// journey.
fn doc_pages() -> BTreeMap<String, Page> {
    let mut out = BTreeMap::new();
    for root in ["docs", "website/content/docs"] {
        let mut stack = vec![repo().join(root)];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().and_then(|e| e.to_str()) != Some("md") {
                    continue;
                }
                let Ok(rel) = p.strip_prefix(repo()) else {
                    continue;
                };
                let rel = rel.to_string_lossy().into_owned();
                let parts: Vec<&str> = rel.split('/').collect();
                if parts[0] == "docs" && parts.len() > 2 && parts[1] != "internals" {
                    continue;
                }
                let Ok(raw) = std::fs::read_to_string(&p) else {
                    continue;
                };
                out.insert(rel.clone(), Page::parse(&rel, &raw));
            }
        }
    }
    out
}

/// Every cross-page link in those pages.
///
/// Read from [`markdown::prose`], which keeps inline code spans: a span's
/// content is rendered *text*, and `` [`--hep-listen`](cli-reference.md) `` is
/// precisely the shape this gate exists to judge. Blanking spans first — what
/// `linkable_prose` does, correctly, for deciding whether a `](…)` is live —
/// would erase the link text and hide the case.
fn doc_links(pages: &BTreeMap<String, Page>) -> Vec<Link> {
    let mut out = Vec::new();
    for rel in pages.keys() {
        let Ok(raw) = std::fs::read_to_string(repo().join(rel)) else {
            continue;
        };
        for caps in link_re().captures_iter(&markdown::prose(&raw)) {
            let dest = &caps[2];
            let Some(target) = resolve(rel, dest, pages) else {
                continue;
            };
            let anchor = dest.split_once('#').map(|(_, a)| a.to_string());
            out.push(Link {
                src: rel.clone(),
                text: caps[1].trim().to_string(),
                target,
                anchor,
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 1. The gate
// ---------------------------------------------------------------------------

/// Every no-anchor cross-page link either lands on a page that is the answer,
/// or is on the [`ACCEPTED`] list with a reason.
#[test]
fn link_text_promises_a_section_the_target_buries_it_in() {
    let pages = doc_pages();
    let links = doc_links(&pages);

    // A walk that finds nothing must refuse, not pass. Floors rather than
    // pinned equalities: every documentation edit moves these, and a gate that
    // demands a bump per edit is a gate people learn to edit rather than read.
    // The margins are wide enough that a broken walk cannot squeak past —
    // measured at 103 pages and 540 links when this was written.
    assert!(
        pages.len() >= MIN_PAGES,
        "walked {} documentation pages; expected at least {MIN_PAGES}. Either the trees \
         moved or the walk is broken — a gate reading nothing reports itself healthy",
        pages.len()
    );
    assert!(
        links.len() >= MIN_LINKS,
        "found {} cross-page links; expected at least {MIN_LINKS}. The link regex or the \
         target resolver stopped matching, and this gate is judging almost nothing",
        links.len()
    );

    let judged = links
        .iter()
        .filter(|l| {
            l.anchor.is_none() && !is_filename(&l.text) && content_words(&l.text).len() >= 2
        })
        .count();
    assert!(
        judged >= MIN_JUDGED,
        "only {judged} no-anchor links survived the skip filters (filename-only text, \
         fewer than two content words); expected at least {MIN_JUDGED}. The filters are \
         eating the corpus"
    );

    let mut findings = Vec::new();
    for link in &links {
        let Some(page) = pages.get(&link.target) else {
            continue;
        };
        if let Some(f) = judge(link, page) {
            findings.push((link.clone(), f));
        }
    }

    // ACCEPTED entries must still describe a real, still-flagged link.
    let mut stale = Vec::new();
    for a in ACCEPTED {
        let named_link = links
            .iter()
            .any(|l| l.src == a.src && l.text == a.text && l.target == a.target);
        if !named_link {
            stale.push(format!(
                "{}: ACCEPTED entry [{}] -> {} names no link in the tree. The link was \
                 deleted or retargeted; delete this entry.",
                a.src, a.text, a.target
            ));
            continue;
        }
        let still = findings
            .iter()
            .any(|(l, _)| l.src == a.src && l.text == a.text && l.target == a.target);
        if !still {
            stale.push(format!(
                "{}: ACCEPTED entry [{}] -> {} is FIXED — the link is no longer flagged. \
                 Delete its entry from ACCEPTED so the list cannot rot into a permanent \
                 silence.",
                a.src, a.text, a.target
            ));
        }
    }

    let unaccepted: Vec<String> = findings
        .iter()
        .filter(|(l, _)| {
            !ACCEPTED
                .iter()
                .any(|a| a.src == l.src && a.text == l.text && a.target == l.target)
        })
        .map(|(l, f)| {
            format!(
                "{}: [{}]({}) has no anchor, but {} -> add `#{}`\n      rule {}: {}",
                l.src, l.text, l.target, f.detail, f.anchor, f.rule, f.heading
            )
        })
        .collect();

    assert!(
        stale.is_empty(),
        "{} stale ACCEPTED entr(ies):\n  {}",
        stale.len(),
        stale.join("\n  ")
    );
    assert!(
        unaccepted.is_empty(),
        "{} link(s) whose text promises a section the target buries \
         ({} pages, {} cross-page links, {judged} judged):\n  {}\n\n\
         Fix by adding the suggested anchor, or — if the whole page really is the answer \
         — add an ACCEPTED entry with the reason.",
        unaccepted.len(),
        pages.len(),
        links.len(),
        unaccepted.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 2. Ground truth: the rule agrees with the authors
// ---------------------------------------------------------------------------

/// Strip the anchor off every link that has one, and the rule must ask for it
/// back — by name.
///
/// This is the mutation test for the gate above, run against ~99 decisions real
/// authors already made. It is also what stops the rule being tuned into
/// uselessness: loosening a threshold to silence a finding drives the agreement
/// rate down, tightening one drives the demand count down, and both are
/// asserted here.
///
/// Perfect recall is not the goal and is not achievable — an anchor whose link
/// text is "below", "2C" or "Step 0" carries no vocabulary to match on. What is
/// asserted is that when the rule *does* speak, it says what the author said.
#[test]
fn the_rule_reproduces_the_anchors_authors_already_chose() {
    let pages = doc_pages();
    let links = doc_links(&pages);
    let anchored: Vec<&Link> = links.iter().filter(|l| l.anchor.is_some()).collect();
    assert!(
        anchored.len() >= MIN_ANCHORED,
        "only {} anchored cross-page links found; expected at least {MIN_ANCHORED}. \
         Without ground truth this test proves nothing",
        anchored.len()
    );

    let mut demanded = 0usize;
    let mut agreed = 0usize;
    let mut disagreements = Vec::new();
    for link in anchored {
        let Some(page) = pages.get(&link.target) else {
            continue;
        };
        let Some(author) = link.anchor.clone() else {
            continue;
        };
        // The mutation: the same link with its anchor removed.
        let stripped = Link {
            anchor: None,
            ..link.clone()
        };
        let Some(f) = judge(&stripped, page) else {
            continue;
        };
        demanded += 1;
        let both = [slug_github(&f.heading), slug_zola(&f.heading)];
        if both.contains(&author) {
            agreed += 1;
        } else {
            disagreements.push(format!(
                "{}: [{}] -> {} — author chose #{author}, rule proposes #{}",
                link.src, link.text, link.target, f.anchor
            ));
        }
    }

    assert!(
        demanded >= MIN_DEMANDED,
        "the rule demanded an anchor for only {demanded} of the links whose authors \
         already chose one; expected at least {MIN_DEMANDED}. It has been tightened past \
         the point of usefulness: it can no longer reproduce judgments humans made in \
         this very repository.\nDisagreements seen:\n  {}",
        disagreements.join("\n  ")
    );
    assert!(
        agreed * 100 >= demanded * MIN_AGREEMENT_PERCENT,
        "the rule demanded an anchor for {demanded} already-anchored links but named the \
         author's own anchor for only {agreed} ({}%). Below {MIN_AGREEMENT_PERCENT}% it \
         is guessing, and a guess dressed as a gate is worse than no gate.\n  {}",
        agreed * 100 / demanded.max(1),
        disagreements.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 3. The known-bad and known-good cases
// ---------------------------------------------------------------------------

/// Build a page from literal markdown, as if it were at `rel`.
fn page_from(rel: &str, raw: &str) -> Page {
    Page::parse(rel, raw)
}

fn link(src: &str, text: &str, target: &str) -> Link {
    Link {
        src: src.to_string(),
        text: text.to_string(),
        target: target.to_string(),
        anchor: None,
    }
}

/// The defect this gate exists for fires; the shapes that look identical to
/// every other gate in the repo do not.
///
/// The fixtures are literal because the real pages are being edited by other
/// work: a gate whose known-bad case is a link in the tree stops testing
/// anything the moment somebody fixes that link.
#[test]
fn the_rule_fires_on_the_known_bad_case_and_spares_the_known_good() {
    // Known bad: the shape of website/content/docs/integrations.md — title
    // "Integrations", a description that names every topic including this one,
    // and `## Fail2ban Integration` as the fourth of eight headings.
    let integrations = page_from(
        "docs/integrations.md",
        "+++\ntitle = \"Integrations\"\n\
         description = \"Forward to HEP/Homer, run event-exec hooks, and emit fail2ban and \
         syslog alerts.\"\n+++\n\n\
         Wire sipnab into your wider stack: forward captured traffic to HEP/Homer, run \
         external commands on dialog and quality events, and emit fail2ban and syslog \
         security alerts.\n\n\
         ## HEP Protocol\n\nsipnab speaks HEP v2/v3 for Homer. A routable bind needs a \
         source allowlist or a shared secret.\n\n\
         ### Receiving HEP\n\nBind a listener and constrain it.\n\n\
         ### Sending HEP\n\nForward to a collector.\n\n\
         ## Event execution\n\nRun a command when a dialog or quality event fires.\n\n\
         ## Fail2ban Integration\n\nsipnab writes a log line the fail2ban filter matches, \
         so a repeat offender is banned at the firewall.\n\n\
         ### Measure it against your own traffic first\n\nA busy trunk looks like a scan.\n\n\
         ### Filter and jail\n\nNever ban the boxes the phone system needs.\n\n\
         ## Syslog alerts\n\nEmit findings to syslog.\n",
    );
    assert_eq!(integrations.headings.len(), 8, "fixture drifted");
    assert_eq!(integrations.sections.len(), 4, "fixture drifted");
    let bad = judge(
        &link(
            "docs/troubleshooting.md",
            "Ban a source with fail2ban",
            "docs/integrations.md",
        ),
        &integrations,
    )
    .expect(
        "the known-bad case did not fire: [Ban a source with fail2ban] -> integrations.md \
         with no anchor is the defect this gate exists for",
    );
    assert_eq!(bad.anchor, "fail2ban-integration", "{}", bad.detail);

    // Known good, from the real tree: the whole page is the answer.
    let pages = doc_pages();
    let install = pages
        .get("docs/install.md")
        .expect("docs/install.md must exist for this test to mean anything");
    assert!(
        install.headings.len() > 20,
        "docs/install.md has {} headings; the known-good case is only interesting \
         because the page is long",
        install.headings.len()
    );
    for (text, target) in [
        ("Install sipnab", "docs/install.md"),
        ("Installing sipnab", "docs/install.md"),
        ("Cookbook", "docs/examples.md"),
        (
            "Reading SIP over TLS without keys",
            "docs/uprobe-walkthrough.md",
        ),
    ] {
        let page = pages
            .get(target)
            .unwrap_or_else(|| panic!("{target} must exist"));
        if let Some(f) = judge(&link("docs/README.md", text, target), page) {
            panic!(
                "false positive: [{text}] -> {target} was flagged and told to point at \
                 #{} ({}). The whole page is the answer here — {} headings do not make it \
                 otherwise.",
                f.anchor,
                f.detail,
                page.headings.len()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. The mechanisms themselves fire
// ---------------------------------------------------------------------------

/// The ACCEPTED list cannot rot, and the vacuity floors are not decorative.
///
/// Both properties are asserted by construction rather than by reading the
/// code: an instrument that cannot be shown to fire is indistinguishable from
/// one that passed.
#[test]
fn a_walk_that_finds_nothing_refuses_rather_than_passing() {
    // The floors in the gate above compare against a corpus. Prove the corpus
    // is what makes them pass, by evaluating the same conditions on nothing.
    let empty: BTreeMap<String, Page> = BTreeMap::new();
    let no_links = doc_links(&empty);
    assert!(
        no_links.is_empty(),
        "resolving links against an empty page set produced {} link(s) — the resolver is \
         inventing targets, and every floor built on it is meaningless",
        no_links.len()
    );
    assert!(
        empty.len() < MIN_PAGES,
        "the page floor accepts an empty walk"
    );
    assert!(
        no_links.len() < MIN_LINKS,
        "the link floor accepts an empty walk"
    );

    // And the real walk clears them, so the floors are measuring the corpus and
    // not a constant.
    let pages = doc_pages();
    let links = doc_links(&pages);
    assert!(pages.len() >= MIN_PAGES && links.len() >= MIN_LINKS);
}

/// A stale ACCEPTED entry is rejected, and a live one is not.
///
/// Runs the same predicate the gate runs, against a fabricated entry that names
/// a link nobody wrote. Without this the rot check is a branch nobody has ever
/// taken.
#[test]
fn an_accepted_entry_that_names_no_link_is_rejected() {
    let pages = doc_pages();
    let links = doc_links(&pages);
    let names_a_link = |src: &str, text: &str, target: &str| {
        links
            .iter()
            .any(|l| l.src == src && l.text == text && l.target == target)
    };

    assert!(
        !names_a_link(
            "docs/install.md",
            "a link text nobody has ever written",
            "docs/examples.md"
        ),
        "the staleness predicate matched a fabricated entry; it cannot detect rot"
    );

    // Every shipped entry passes the same predicate — otherwise the gate's own
    // failure message would be the first place anyone learns the list is stale.
    for a in ACCEPTED {
        assert!(
            names_a_link(a.src, a.text, a.target),
            "ACCEPTED entry [{}] in {} -> {} names no link in the tree",
            a.text,
            a.src,
            a.target
        );
        assert!(
            !a.reason.trim().is_empty(),
            "ACCEPTED entry [{}] in {} carries no reason",
            a.text,
            a.src
        );
    }
}
