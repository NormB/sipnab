// SPDX-License-Identifier: MIT OR Apache-2.0
//! Documentation never cites a section as a bare "§".
//!
//! "§7" tells a reader that something exists and nothing about where. The
//! reader goes looking for a section 7 on the page in front of them, in the
//! RFC mentioned three paragraphs earlier, or in a design document the
//! sentence never named -- and that search is worse than no reference at all,
//! because it ends in a wrong answer as often as in none. Norm, 2026-09-18:
//! *"references like this §7 in the documentation are worse than confusing
//! because the user will attempt to locate what §7 means."*
//!
//! So a reference names what it points at and links there: "[RFC 3261 section
//! 17.1.3](https://www.rfc-editor.org/rfc/rfc3261#section-17.1.3)", or a
//! document's section by its title with a link to the heading.
//! `scripts/rfc-links.py` writes the RFC form.
//!
//! Prose only. A fenced block or an inline code span quotes something -- a
//! command, a program's output -- and changing the quote without changing what
//! it quotes would make the documentation lie in a different way.

use std::path::Path;
use std::process::Command;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn tracked(pattern: &str) -> Vec<String> {
    let out = Command::new("git")
        .args(["ls-files", "-z", "--", pattern])
        .current_dir(repo())
        .output()
        .expect("git ls-files");
    assert!(out.status.success(), "git ls-files {pattern}");
    String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// `line` with its inline code spans removed.
fn without_code_spans(line: &str) -> String {
    let mut out = String::new();
    let mut in_code = false;
    for (i, part) in line.split('`').enumerate() {
        if i > 0 {
            in_code = !in_code;
        }
        if !in_code {
            out.push_str(part);
        }
    }
    out
}

/// The prose lines of a markdown text: fenced blocks skipped, inline code
/// removed, numbered from 1.
fn prose(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut fence: Option<String> = None;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        let marker: String = t.chars().take_while(|c| *c == '`' || *c == '~').collect();
        if marker.len() >= 3
            && marker
                .chars()
                .all(|c| c == marker.chars().next().unwrap_or('`'))
        {
            match &fence {
                None => {
                    fence = Some(marker);
                    continue;
                }
                Some(open) if marker.starts_with(open.as_str()) && t.trim() == marker => {
                    fence = None;
                    continue;
                }
                _ => {}
            }
        }
        if fence.is_none() {
            out.push((i + 1, without_code_spans(line)));
        }
    }
    out
}

/// Where a bare "§" sits in the documentation, as `path:line: text`.
fn offenders() -> Vec<String> {
    let mut found = Vec::new();
    for path in tracked("*.md") {
        let text = std::fs::read_to_string(repo().join(&path)).unwrap_or_default();
        for (n, line) in prose(&text) {
            if line.contains('§') {
                found.push(format!("{path}:{n}: {}", line.trim()));
            }
        }
    }
    // rustdoc is published on docs.rs: the `///` and `//!` lines of src/ are
    // documentation by the same standard.
    for path in tracked(":(glob)src/**/*.rs") {
        let text = std::fs::read_to_string(repo().join(&path)).unwrap_or_default();
        let doc: String = text
            .lines()
            .map(|l| {
                let t = l.trim_start();
                t.strip_prefix("//!")
                    .or_else(|| t.strip_prefix("///"))
                    .map_or(String::new(), str::to_string)
            })
            .collect::<Vec<_>>()
            .join("\n");
        for (n, line) in prose(&doc) {
            if line.contains('§') {
                found.push(format!("{path}:{n}: {}", line.trim()));
            }
        }
    }
    found
}

#[test]
fn no_documentation_cites_a_section_as_a_bare_section_sign() {
    let found = offenders();
    assert!(
        found.is_empty(),
        "{} documentation lines cite a section with a bare \"§\". Name what the \
         reference points at and link it: `[RFC 3261 section 17.1.3](https://www.\
         rfc-editor.org/rfc/rfc3261#section-17.1.3)` (scripts/rfc-links.py \
         --apply writes that form), or a document's section by its title with a \
         link to the heading. First ones:\n  {}",
        found.len(),
        found
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

/// POSITIVE CONTROL: the reader sees a bare sign in prose, and not in a code
/// span or a fenced block, where it is part of a quote.
#[test]
fn the_reader_finds_a_section_sign_in_prose_and_only_there() {
    let text = "see §7 above\n`(RFC 3261 §8.1.1)` is output\n```\nRFC 3261 §21.5\n```\nplain\n";
    let hits: Vec<(usize, String)> = prose(text)
        .into_iter()
        .filter(|(_, l)| l.contains('§'))
        .collect();
    assert_eq!(hits, [(1, "see §7 above".to_string())]);
}
