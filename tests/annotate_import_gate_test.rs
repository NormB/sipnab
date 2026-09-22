// SPDX-License-Identifier: MIT OR Apache-2.0

//! Operator notes are output, never input: the import allow-list (L3).
//!
//! `crate::annotate` holds text a person typed. It may reach a pcapng packet
//! comment, the TUI's note pane and the operator's notes file, and nothing
//! else. The sealed `NoteText` keeps the text from leaking out of a value;
//! this keeps the MODULE from being reachable where it must not be.
//!
//! The two things this scan looks for:
//!
//! - the `annotate` module, by any path (`crate::annotate`, a grouped
//!   `use crate::{annotate, ..}`, `sipnab::annotate`): permitted only in
//!   `src/annotate/`, `src/tui/`, `src/app/` and `src/capture/writer.rs`;
//! - `EnhancedPacketOption`, the pcapng type a packet comment is written
//!   through: permitted in the same places, so no other exporter can write a
//!   comment of its own.
//!
//! The forbidden list is named explicitly as well, because those are the
//! modules the rule exists for: `src/mcp/` (an agent may neither read an
//! operator's note nor write text into a file that leaves the box),
//! `src/output/` (every wire shape: REST, JSON, reports, vCon), and the
//! analysis itself in `src/sip/`, `src/rtp/`, `src/security/` and
//! `src/analysis.rs`.
//!
//! Comments and string literals are stripped before the scan, so prose about
//! annotation is not a violation and an import hidden behind a comment-shaped
//! string is not a pass. The scanner is tested on its own below, because a
//! stripper that ate everything would make this gate pass while checking
//! nothing.

use std::path::{Path, PathBuf};

/// Where the annotate module and the packet-comment type may be named.
const PERMITTED: &[&str] = &[
    "src/annotate/",
    "src/tui/",
    "src/app/",
    "src/capture/writer.rs",
];

/// Where they must never be named, whatever the permitted list later says.
const FORBIDDEN: &[&str] = &[
    "src/mcp/",
    "src/output/",
    "src/sip/",
    "src/rtp/",
    "src/security/",
    "src/analysis.rs",
    "src/analysis/",
];

/// The one line outside the permitted set that may name the module: its
/// declaration.
const DECLARATION: (&str, &str) = ("src/lib.rs", "pub mod annotate;");

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `src/`, as a repo-relative `/`-separated path.
fn sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(&repo().join("src"), &mut files);
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(repo())
                .expect("under the repo")
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {rel}: {e}"));
            (rel, text)
        })
        .collect()
}

/// `src` with every comment and every string and character literal replaced
/// by spaces, newlines kept so line numbers still line up.
///
/// Handles nested block comments, escapes, raw strings with any number of
/// hashes, and the difference between a character literal and a lifetime.
fn strip(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let blank = |ch: char| if ch == '\n' { '\n' } else { ' ' };
    let ident = |ch: char| ch.is_alphanumeric() || ch == '_';
    let mut i = 0;
    while i < c.len() {
        // Line comment.
        if c[i] == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        // Block comment, nested.
        if c[i] == '/' && c.get(i + 1) == Some(&'*') {
            let mut depth = 0usize;
            while i < c.len() {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(c[i]));
                    i += 1;
                }
            }
            continue;
        }
        // Raw string: r"..", r#".."#, br#".."#.
        if c[i] == 'r'
            && (i == 0 || !ident(c[i - 1]) || (c[i - 1] == 'b' && (i < 2 || !ident(c[i - 2]))))
        {
            let mut j = i + 1;
            while j < c.len() && c[j] == '#' {
                j += 1;
            }
            if c.get(j) == Some(&'"') {
                let hashes = j - i - 1;
                for _ in i..=j {
                    out.push(' ');
                }
                i = j + 1;
                while i < c.len() {
                    if c[i] == '"' && (1..=hashes).all(|k| c.get(i + k) == Some(&'#')) {
                        for _ in 0..=hashes {
                            out.push(' ');
                        }
                        i += hashes + 1;
                        break;
                    }
                    out.push(blank(c[i]));
                    i += 1;
                }
                continue;
            }
        }
        // String.
        if c[i] == '"' {
            out.push(' ');
            i += 1;
            while i < c.len() {
                if c[i] == '\\' {
                    out.push(' ');
                    if let Some(&n) = c.get(i + 1) {
                        out.push(blank(n));
                    }
                    i += 2;
                    continue;
                }
                if c[i] == '"' {
                    out.push(' ');
                    i += 1;
                    break;
                }
                out.push(blank(c[i]));
                i += 1;
            }
            continue;
        }
        // Character literal, not a lifetime: '\x', or 'x' closed at i+2.
        if c[i] == '\'' {
            if c.get(i + 1) == Some(&'\\') {
                // The opening quote, the backslash and the escaped character,
                // which may itself be a quote; then up to the closing quote
                // (`'\u{1F600}'` runs longer than three).
                out.push_str("   ");
                i += 3;
                while i < c.len() && c[i] != '\'' {
                    out.push(' ');
                    i += 1;
                }
                out.push(' ');
                i += 1;
                continue;
            }
            if c.get(i + 2) == Some(&'\'') {
                out.push_str("   ");
                i += 3;
                continue;
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

/// 1-based line numbers where `word` appears as a whole identifier in the
/// already-stripped `code`.
fn identifier_lines(code: &str, word: &str) -> Vec<usize> {
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut hits = Vec::new();
    for (n, line) in code.lines().enumerate() {
        let bytes = line.as_bytes();
        let found = line.match_indices(word).any(|(at, _)| {
            let before = at.checked_sub(1).map(|b| bytes[b]);
            let after = bytes.get(at + word.len()).copied();
            !before.is_some_and(ident) && !after.is_some_and(ident)
        });
        if found {
            hits.push(n + 1);
        }
    }
    hits
}

/// Every `(file, line, what)` naming the module or the comment type where
/// the allow-list does not permit it, plus how many permitted references
/// exist OUTSIDE `src/annotate/` itself.
fn violations_in(files: &[(String, String)]) -> (Vec<String>, usize) {
    let mut bad = Vec::new();
    let mut permitted_uses = 0usize;
    for (rel, text) in files {
        let code = strip(text);
        let permitted = PERMITTED.iter().any(|p| rel.starts_with(p));
        let forbidden = FORBIDDEN.iter().any(|p| rel.starts_with(p));
        for word in ["annotate", "EnhancedPacketOption"] {
            for line in identifier_lines(&code, word) {
                let source_line = text.lines().nth(line - 1).unwrap_or("").trim();
                if (rel.as_str(), source_line) == DECLARATION {
                    continue;
                }
                if permitted && !forbidden {
                    if !rel.starts_with("src/annotate/") {
                        permitted_uses += 1;
                    }
                    continue;
                }
                let why = if forbidden {
                    "FORBIDDEN here"
                } else {
                    "not on the allow-list"
                };
                bad.push(format!("{rel}:{line}: `{word}` ({why}): {source_line}"));
            }
        }
    }
    (bad, permitted_uses)
}

/// The rule, over the real tree.
#[test]
fn only_the_permitted_modules_name_the_notes_module_or_the_comment_type() {
    let files = sources();
    // 266 files when this gate was written.
    assert!(
        files.len() >= 250,
        "only {} source files found under src/; the walk has stopped working",
        files.len()
    );
    let (bad, permitted_uses) = violations_in(&files);
    assert!(
        bad.is_empty(),
        "operator notes reached a module that must never see them. A note is \
         output, never input (Invariant 13, docs/internals/invariants.md), and \
         an agent must not be able to read one or write text into a file that \
         leaves the box:\n  {}",
        bad.join("\n  ")
    );
    // Anti-vacuity: the scan must see at least one real, permitted use, or a
    // stripper that ate every line would pass the assertion above.
    assert!(
        permitted_uses >= 1,
        "no permitted use of the notes module was found outside src/annotate/; \
         either nothing uses it (then this gate guards nothing) or the scan \
         cannot see code"
    );
}

/// The scanner flags an import in a forbidden module, by every spelling.
#[test]
fn the_scanner_flags_every_spelling_of_the_import() {
    for source in [
        "use crate::annotate::Notes;\n",
        "use crate::{capture, annotate};\n",
        "fn f() { let _ = sipnab::annotate::MAX_NOTES; }\n",
        "use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketOption;\n",
    ] {
        let files = vec![("src/mcp/server.rs".to_string(), source.to_string())];
        let (bad, _) = violations_in(&files);
        assert_eq!(bad.len(), 1, "must flag {source:?}: {bad:?}");
        assert!(bad[0].contains("FORBIDDEN"), "{bad:?}");
    }
}

/// And it does not flag prose, strings or a longer identifier.
#[test]
fn the_scanner_ignores_comments_strings_and_longer_identifiers() {
    let source = "// use crate::annotate::Notes;\n\
                  /* nested /* crate::annotate */ still a comment */\n\
                  /// annotate the transport tag\n\
                  let s = \"crate::annotate\";\n\
                  let r = r#\"use crate::annotate;\"#;\n\
                  let c = '\\'';\n\
                  fn f<'a>(x: &'a str) -> &'a str { x }\n\
                  let write_annotated = 1;\n\
                  fn annotate_transport() {}\n";
    let files = vec![("src/output/cli_print.rs".to_string(), source.to_string())];
    let (bad, _) = violations_in(&files);
    assert!(
        bad.is_empty(),
        "prose and longer names are not imports: {bad:?}"
    );
}

/// A permitted module is permitted, and its use counts toward the floor.
#[test]
fn a_permitted_use_is_counted_and_not_flagged() {
    let files = vec![
        (
            "src/capture/writer.rs".to_string(),
            "use crate::annotate::pcapng::EpbComment;\n".to_string(),
        ),
        (
            "src/annotate/copy.rs".to_string(),
            "use super::annotate;\n".to_string(),
        ),
    ];
    let (bad, permitted_uses) = violations_in(&files);
    assert!(bad.is_empty(), "{bad:?}");
    assert_eq!(
        permitted_uses, 1,
        "the writer's use counts; the module's own does not"
    );
}
