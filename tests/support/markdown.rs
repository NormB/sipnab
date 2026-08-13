// SPDX-License-Identifier: MIT OR Apache-2.0

//! CommonMark fence lexing, comment stripping, and the repository's own tree
//! layout — shared by every documentation gate.
//!
//! Each of those gates used to carry its own copy of this logic, and each copy
//! was wrong in a different way. The copies are what this module exists to
//! delete, because the bugs were not independent:
//!
//! - `mermaid_fences` matched ` ```mermaid ` only, so a `~~~mermaid` fence —
//!   valid CommonMark — was invisible to all five mermaid conventions at once.
//! - `strip_fences` toggled one `bool` on any line starting with ` ``` `, so a
//!   `~~~` block *containing* a ` ``` ` line switched fence mode on with
//!   nothing to switch it back: the rest of the file vanished from prose while
//!   still counting as scanned.
//! - `config_examples_test` compared the fence line for equality with
//!   `"```toml"`, so one trailing space, or an info string like
//!   `` ```toml,ignore ``, skipped the sample entirely.
//!
//! Three spellings of "a fenced block", three different sets of documents
//! silently exempted. [`fences`] is the one implementation, and it follows the
//! CommonMark rules the generators and GitHub actually apply: a fence is three
//! or more backticks *or* tildes, it closes only on a run of the **same**
//! character at least as long as the opener, and an unclosed fence runs to the
//! end of the document.
//!
//! Consumers include it with `#[path = "support/markdown.rs"] mod markdown;`,
//! the same way `support/mod.rs` is included — it lives under `tests/` so cargo
//! does not build it as its own test binary.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// One fenced code block.
#[derive(Debug, Clone)]
pub struct Fence {
    /// 1-based line number of the opening fence marker.
    pub line: usize,
    /// 1-based line number of the first body line.
    pub body_line: usize,
    /// The info string's first whitespace-separated word, lowercased.
    /// `` ```Bash,ignore `` and `` ```bash `` both yield `"bash"`; an unlabeled
    /// fence yields `""`.
    pub lang: String,
    /// The whole info string, trimmed, case preserved.
    pub info: String,
    /// The fence character, `` ` `` or `~`. Kept because a gate that rewrites
    /// or re-emits a fence has to reproduce the marker it found.
    pub ch: char,
    /// The opening marker's run length. A closer must be at least this long.
    pub run: usize,
    /// Body lines, each with a trailing newline. Markers excluded.
    pub body: String,
    /// Whether a closing marker was found. An unclosed fence is legal
    /// CommonMark but is nearly always a typo in a document, so gates that
    /// care can say so.
    pub closed: bool,
}

/// Every fenced code block in `text`, in document order.
///
/// Nested fences are not a thing in CommonMark: inside a ` ``` ` block a `~~~`
/// line is body text, and vice versa. That asymmetry is exactly what the
/// single-`bool` scanners got wrong, so it is the property this function is
/// built around.
pub fn fences(text: &str) -> Vec<Fence> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some((ch, run, info)) = opening_marker(lines[i]) else {
            i += 1;
            continue;
        };
        let start = i;
        let mut body = String::new();
        let mut closed = false;
        i += 1;
        while i < lines.len() {
            if is_closing_marker(lines[i], ch, run) {
                closed = true;
                break;
            }
            body.push_str(lines[i]);
            body.push('\n');
            i += 1;
        }
        // Past the closer, or past the end for an unclosed fence.
        i += 1;
        out.push(Fence {
            line: start + 1,
            body_line: start + 2,
            lang: info
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches(',')
                .to_lowercase(),
            info: info.clone(),
            ch,
            run,
            body,
            closed,
        });
    }
    out
}

/// An opening fence marker: `(fence char, run length, info string)`.
///
/// CommonMark allows up to three leading spaces; a fourth makes it an indented
/// code block, which is not a fence. A backtick fence's info string may not
/// contain a backtick — that rule is what keeps a line of inline code from
/// being read as a fence.
fn opening_marker(line: &str) -> Option<(char, usize, String)> {
    let indent = line.len() - line.trim_start().len();
    if indent > 3 {
        return None;
    }
    let t = line.trim_start();
    let ch = match t.chars().next()? {
        '`' => '`',
        '~' => '~',
        _ => return None,
    };
    let run = t.chars().take_while(|c| *c == ch).count();
    if run < 3 {
        return None;
    }
    let info = t.chars().skip(run).collect::<String>().trim().to_string();
    if ch == '`' && info.contains('`') {
        return None;
    }
    Some((ch, run, info))
}

/// A closing marker for a fence opened with `ch` repeated `run` times: the
/// same character, at least as long, and nothing else on the line.
fn is_closing_marker(line: &str, ch: char, run: usize) -> bool {
    let indent = line.len() - line.trim_start().len();
    if indent > 3 {
        return false;
    }
    let t = line.trim_start();
    let n = t.chars().take_while(|c| *c == ch).count();
    n >= run && t.chars().skip(n).all(char::is_whitespace)
}

/// Blank out every fenced code block, preserving line numbering.
///
/// Callers report `file:line`, so a stripper that removed lines would shift
/// every number it reports. Each suppressed line becomes empty rather than
/// disappearing.
pub fn blank_fences(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut keep = vec![true; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        let Some((ch, run, _)) = opening_marker(lines[i]) else {
            i += 1;
            continue;
        };
        keep[i] = false;
        i += 1;
        while i < lines.len() {
            keep[i] = false;
            if is_closing_marker(lines[i], ch, run) {
                i += 1;
                break;
            }
            i += 1;
        }
    }
    let mut out = String::with_capacity(text.len());
    for (n, line) in lines.iter().enumerate() {
        if keep[n] {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Blank out inline code spans, preserving line numbering.
///
/// A link inside backticks is a link being *quoted*, not a link being made.
/// `docs/internals/testing.md` documents a past bug as `` `](../bench/)` ``;
/// a gate reading raw bytes calls that a relative link that escaped rewriting,
/// and a generator reading raw bytes rewrites it.
///
/// CommonMark: a run of N backticks opens a span that closes on the next run of
/// exactly N. A run with no matching closer is literal text, not an opener.
///
/// Run this after [`blank_fences`] — backticks inside a fenced block are body
/// text, and blanking the block first removes them from consideration.
pub fn blank_inline_code(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'`' {
            let ch_len = text[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&text[i..i + ch_len]);
            i += ch_len;
            continue;
        }
        let open = i;
        let run = b[i..].iter().take_while(|c| **c == b'`').count();
        // Find the next run of exactly `run` backticks.
        let mut j = open + run;
        let close = loop {
            if j >= b.len() {
                break None;
            }
            if b[j] != b'`' {
                j += 1;
                continue;
            }
            let n = b[j..].iter().take_while(|c| **c == b'`').count();
            if n == run {
                break Some(j);
            }
            j += n;
        };
        match close {
            Some(end) => {
                for _ in text[open..end + run].matches('\n') {
                    out.push('\n');
                }
                i = end + run;
            }
            None => {
                // Literal backticks; emit them and move on.
                out.push_str(&text[open..open + run]);
                i = open + run;
            }
        }
    }
    out
}

/// Blank out HTML comments, preserving line numbering.
///
/// A commented-out sentence is not rendered prose, on GitHub or in Zola. A gate
/// that reads raw bytes counts it anyway: wrapping the only link to
/// `docs/backers.md` in `<!-- … -->` left the page reachable from nowhere and
/// the reachability gate green.
pub fn blank_html_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("<!--") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 4..];
        match after.find("-->") {
            Some(close) => {
                // Keep the newlines so line numbers survive.
                for _ in after[..close + 3].matches('\n') {
                    out.push('\n');
                }
                rest = &after[close + 3..];
            }
            None => {
                // Unterminated: everything after it is commented out.
                for _ in after.matches('\n') {
                    out.push('\n');
                }
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Blank out Tera comments `{# … #}`, preserving line numbering.
///
/// Tera never renders these. A template gate that greps raw bytes cannot tell
/// a live `{% if %}` guard from the same words parked in a comment — which is
/// how "this page loads the mermaid bundle" and "this page is in the docs
/// dropdown" both stayed green with the markup deleted.
pub fn blank_tera_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("{#") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        match after.find("#}") {
            Some(close) => {
                for _ in after[..close + 2].matches('\n') {
                    out.push('\n');
                }
                rest = &after[close + 2..];
            }
            None => {
                for _ in after.matches('\n') {
                    out.push('\n');
                }
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Strip Zola `+++` TOML frontmatter.
///
/// Lines inside it can start with `#`, which is a TOML comment and not a
/// heading.
pub fn strip_frontmatter(md: &str) -> &str {
    match md.strip_prefix("+++").map(|r| r.trim_start_matches('\r')) {
        Some(r) => match r.split_once("\n+++") {
            Some((_, body)) => body,
            None => md,
        },
        None => md,
    }
}

/// What a reader actually sees: frontmatter, code fences and HTML comments
/// removed, line numbering intact.
///
/// Inline code spans are **kept**, because their content renders. A heading
/// written `` ### `find_problems` `` displays as `find_problems` and both
/// GitHub and Zola slugify it that way — blanking the span here erased the
/// heading text and turned every anchor pointing at it into a dangling link.
/// Only the backticks are markup; what is between them is prose.
pub fn prose(md: &str) -> String {
    blank_html_comments(&blank_fences(strip_frontmatter(md)))
}

/// [`prose`], plus inline code spans blanked: for deciding whether a `](…)` is
/// a link a reader can follow.
///
/// The distinction is not pedantry. A span's content is rendered *text*, so it
/// belongs in a heading; it is not rendered *markup*, so a link inside one is
/// being quoted rather than made. `docs/internals/testing.md` documents a past
/// bug as `` `](../bench/)` ``, and reading that as a live relative link is
/// what made a generator rewrite the example and a gate report the example as
/// an escaped link.
///
/// Order matters: fences first, so backticks inside a fenced block are gone
/// before span detection runs.
pub fn linkable_prose(md: &str) -> String {
    blank_html_comments(&blank_inline_code(&blank_fences(strip_frontmatter(md))))
}

/// The repository root.
pub fn repo_root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

/// The shared code-tree list, verbatim.
///
/// `include_str!` rather than a runtime read, so every gate built on it is
/// recompiled when the list changes and none of them can be looking at a stale
/// copy.
pub const CODE_TREES_FILE: &str = ".config/code-trees.txt";
const CODE_TREES_TEXT: &str = include_str!("../../.config/code-trees.txt");

/// Parse the shared list: one tree per line, `#` comments and blanks ignored.
///
/// Shared with `scripts/lib_markdown.py`, which parses the same file the same
/// way. Two parsers, one grammar — deliberately the simplest grammar that can
/// carry the comments explaining why the list exists.
pub fn parse_code_trees(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Every top-level repository directory a link may point into, except `docs/`.
///
/// This is the set a link target can start with and still be a link into the
/// code rather than into the documentation. It lives in
/// [`CODE_TREES_FILE`] because it had been typed out five times and the copies
/// diverged: this helper derived it from `git ls-files`, `build-wiki.py` listed
/// `bench`, `build-site-pages.py` listed `packaging`,
/// `build-site-internals.py` listed neither, and `scripts/link-repo-paths.py`
/// — the fixer a failing gate tells you to run — knew none of it and rewrote 33
/// paths the gates never asked for. A link into an unlisted tree is not
/// classified as a code link at all, so a citation to a file that does not
/// exist passes every gate and ships.
///
/// The file is no longer derived from `git ls-files` at read time;
/// `code_tree_list_matches_the_repository` holds the two equal instead, so
/// adding a top-level directory fails loudly rather than silently changing
/// what every documentation gate believes.
///
/// `docs/` is excluded deliberately: a link into it is a document link, and the
/// generators must not rewrite it into a blob URL.
pub fn code_trees() -> &'static BTreeSet<String> {
    static TREES: OnceLock<BTreeSet<String>> = OnceLock::new();
    TREES.get_or_init(|| {
        let set = parse_code_trees(CODE_TREES_TEXT);
        assert!(
            set.len() >= 10,
            "read only {} top-level code trees from {CODE_TREES_FILE} ({set:?}) — \
             the list or its parser is broken and every code-link gate built on \
             it just went blind",
            set.len()
        );
        set
    })
}

/// The top-level directories git actually tracks, `docs/` excluded.
///
/// The truth [`code_trees`] is checked against, not a second source of it.
pub fn tracked_top_level_dirs() -> BTreeSet<String> {
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repo_root())
        .output()
        .expect("git ls-files — the code-tree list is checked against it");
    assert!(
        out.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter_map(|p| p.split_once('/'))
        .map(|(top, _)| top.to_string())
        .filter(|top| top != "docs")
        .collect()
}

/// Whether a link target points into the code tree.
///
/// `trim_start_matches` strips repeatedly, so `../../src/foo.rs` resolves the
/// same as `src/foo.rs`.
pub fn is_code_tree_path(target: &str) -> bool {
    let stripped = target.trim_start_matches("./").trim_start_matches("../");
    code_trees()
        .iter()
        .any(|t| stripped == *t || stripped.starts_with(&format!("{t}/")))
}
