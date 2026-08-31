// SPDX-License-Identifier: MIT OR Apache-2.0

//! What breaks when a vendor-neutral abstraction moves out from under a
//! vendor-named module.
//!
//! `src/rtpengine/reconcile.rs` became `src/relay/reconcile.rs`, six neutral
//! types moved from `src/rtpengine/control.rs` into a new `src/relay/types.rs`,
//! and the neutral counters moved from `src/rtpengine/mod.rs` to
//! `src/relay/mod.rs`. `relay_seam_test` gates the SEAM that move created --
//! which way the dependency runs, that no consuming layer names a vendor in
//! code, that no MCP tool is named after one. This file gates the MOVE itself:
//! six defects, every one of them produced by doing it, and not one of them
//! visible to a passing `cargo build`.
//!
//! 1. **The implementation stayed in the seam.** `impl ReadOnlyRelay for
//!    ControlClient` was left behind in `reconcile.rs`, under a comment still
//!    arguing that it belonged there. The argument was true while `reconcile`
//!    lived UNDER `src/rtpengine/`; the move inverted it, and the comment did
//!    not notice.
//! 2. **Operator messages kept a vendor name.** The seam's own strings said
//!    "rtpengine at {}" in five places. With a second relay those sentences are
//!    not merely coupled, they are false -- the operator is told which daemon
//!    answered, and told wrong. The trait already carried `describe()` for
//!    exactly this, so the fix was for the implementation to name itself.
//! 3. **A blanket `sed` rewrote an import backwards.** A global
//!    `super::control::` -> `crate::rtpengine::control::` substitution also
//!    rewrote the one line importing the types that had just moved OUT of that
//!    module, aiming the seam back at the vendor it had been extracted from.
//! 4. **An insert detached a doc comment.** Splitting `rtpengine/mod.rs`
//!    carried the doc block for `is_ng_over_hep` away with the moved code and
//!    left `///` above nothing. The same trap had fired hours earlier,
//!    inserting a type alias above a struct: an insert lands BETWEEN a doc
//!    block and the item it documents, and both halves still compile.
//! 5. **Test-only imports broke while the library built clean.**
//!    `src/relay/reconcile.rs`'s `mod tests` and `src/app/relay_reconciler.rs`
//!    still named the old paths. `cargo build` said nothing at all; only
//!    `cargo test --no-run` reported it.
//! 6. **Documentation links pointed at the moved file.** Pages under
//!    `docs/internals/` still cited `src/rtpengine/reconcile.rs`.
//!
//! # The class
//!
//! A move renames a PATH, and a path is written down in more places than the
//! compiler reads. Every one of the six is a reference the move invalidated in
//! a position the build does not type-check: a comment, a string, a doc
//! block's attachment to its item, an import behind `#[cfg(test)]`, a markdown
//! link. The compiler proves the production import graph and nothing else, so
//! "it builds" is evidence about one of the six and silence about the rest.

#![cfg(feature = "full")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The two directories the move split apart, repo-relative.
///
/// `src/relay/` is where the neutral half landed and `src/rtpengine/` is what
/// it was carved out of. Both halves are scanned: a detached doc block or a
/// dead import is as damaging on the side that stayed as on the side that
/// moved, and defect 4 landed on the side that stayed.
const MOVED_DIRS: &[&str] = &["src/relay", "src/rtpengine"];

/// Relay implementations sipnab knows or plans to know, lowercase.
///
/// Deliberately shorter than `relay_seam_test::VENDOR_TOKENS`: this file reads
/// operator-facing TEXT, and `bencode` or `NgCommand` inside a string is a
/// wire-format name, not a claim to an operator about which daemon answered.
const VENDOR_NAMES: &[&str] = &["rtpengine", "rtpproxy"];

/// Every `.rs` file under one repo-relative directory, recursively, sorted.
fn rust_files(rel: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![repo().join(rel)];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Every `.rs` file in both moved directories, as `(repo-relative dir, path)`.
fn moved_files() -> Vec<(&'static str, PathBuf)> {
    let mut out = Vec::new();
    for dir in MOVED_DIRS {
        for p in rust_files(dir) {
            out.push((*dir, p));
        }
    }
    out
}

/// A path shown to a reader: repo-relative, with the repo root trimmed off.
fn show(p: &Path) -> String {
    p.strip_prefix(repo()).unwrap_or(p).display().to_string()
}

/// Is this an outer doc-comment line?
///
/// `////` is a plain comment and `//!` documents the enclosing module, not the
/// next item; neither can be detached from anything.
fn is_doc_line(trimmed: &str) -> bool {
    trimmed.starts_with("///") && !trimmed.starts_with("////")
}

/// Maximal runs of consecutive outer doc lines, as `[start, end)` indices.
fn doc_blocks(lines: &[&str]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if is_doc_line(lines[i].trim()) {
            let start = i;
            while i < lines.len() && is_doc_line(lines[i].trim()) {
                i += 1;
            }
            out.push((start, i));
        } else {
            i += 1;
        }
    }
    out
}

/// Skip forward over attribute lines and plain `//` comments, returning the
/// index of the first line that is neither.
///
/// A multi-line attribute is consumed as one unit by bracket balance, so a
/// `#[cfg(all(\n ... \n))]` between a doc block and its item does not read as
/// a gap.
fn skip_attributes(lines: &[&str], mut i: usize) -> usize {
    while i < lines.len() {
        let t = lines[i].trim();
        if t.starts_with("#[") || t.starts_with("#![") {
            let mut balance = t.matches('[').count() as isize - t.matches(']').count() as isize;
            while balance > 0 && i + 1 < lines.len() {
                i += 1;
                let n = lines[i];
                balance += n.matches('[').count() as isize - n.matches(']').count() as isize;
            }
            i += 1;
            continue;
        }
        if t.starts_with("//") && !is_doc_line(t) {
            i += 1;
            continue;
        }
        break;
    }
    i
}

/// Every double-quoted string literal in a Rust file, with the 1-based line it
/// opens on.
///
/// Comments are skipped by the scanner rather than by a line filter, so a
/// vendor name inside `//` prose is not mistaken for operator-facing text and
/// a `//` inside a URL literal does not truncate the scan.
fn string_literals(src: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut line = 1usize;
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                if chars[i] == '\n' {
                    line += 1;
                }
                i += 1;
            }
            i += 2;
        } else if c == '\'' {
            i += 1;
        } else if c == '"' {
            let start = line;
            let mut buf = String::new();
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    i += 1;
                    if chars.get(i) == Some(&'\n') {
                        line += 1;
                    }
                    i += 1;
                    continue;
                }
                if chars[i] == '\n' {
                    line += 1;
                }
                buf.push(chars[i]);
                i += 1;
            }
            i += 1;
            out.push((start, buf));
        } else {
            i += 1;
        }
    }
    out
}

/// The child modules of one moved directory: `.rs` stems and subdirectories,
/// with `mod` itself excluded because it is the directory.
fn child_modules(dir: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(repo().join(dir))
        .into_iter()
        .flatten()
        .flatten()
    {
        let p = entry.path();
        if p.is_dir() {
            if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                out.insert(n.to_string());
            }
        } else if p.extension().is_some_and(|x| x == "rs")
            && let Some(stem) = p.file_stem().and_then(|n| n.to_str())
            && stem != "mod"
        {
            out.insert(stem.to_string());
        }
    }
    out
}

/// Items declared directly in a moved directory's `mod.rs`.
///
/// `crate::relay::note_media_creating_command` is a path into `src/relay/`
/// that resolves to a function rather than a file, so the name set has to hold
/// both or the resolver would report a live import as dead.
fn root_items(dir: &str) -> BTreeSet<String> {
    let src = std::fs::read_to_string(repo().join(dir).join("mod.rs")).unwrap_or_default();
    let re = regex::Regex::new(
        r"(?m)^pub (?:fn|const|static|struct|enum|trait|type|mod|use) ([A-Za-z_][A-Za-z0-9_]*)",
    )
    .expect("item pattern");
    re.captures_iter(&src).map(|c| c[1].to_string()).collect()
}

/// One `use` statement naming a module of `src/relay/` or `src/rtpengine/`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ModuleRef {
    /// The file holding the `use`, repo-relative.
    file: String,
    /// 1-based line of the `use`.
    line: usize,
    /// Which moved directory the path names.
    dir: String,
    /// The first path segment after that directory.
    segment: String,
    /// The `use` line itself, for the failure message.
    text: String,
}

/// Every `use` in `src/` and `tests/` that names a module of a moved
/// directory.
///
/// Two forms are read. `use crate::relay::X` / `use crate::rtpengine::X` is
/// read at any indentation, so an import inside `#[cfg(test)] mod tests` is
/// collected exactly like a production one. A bare `use super::X` is read ONLY
/// at column zero and only inside the moved directories, where `super`
/// unambiguously means the directory module; indented `super` inside a nested
/// module means that module's parent instead, and guessing would be worse than
/// declining.
fn module_refs() -> (Vec<ModuleRef>, Vec<String>) {
    let crate_re =
        regex::Regex::new(r"^\s*use\s+crate::(relay|rtpengine)::([A-Za-z_][A-Za-z0-9_]*)")
            .expect("crate use pattern");
    let crate_any =
        regex::Regex::new(r"^\s*use\s+crate::(relay|rtpengine)::").expect("crate use prefix");
    let super_re =
        regex::Regex::new(r"^use\s+super::([A-Za-z_][A-Za-z0-9_]*)").expect("super use pattern");

    let mut refs = Vec::new();
    let mut unparsed = Vec::new();
    let mut files: Vec<(Option<&str>, PathBuf)> = Vec::new();
    for p in rust_files("src") {
        let dir = MOVED_DIRS
            .iter()
            .find(|d| p.starts_with(repo().join(d)))
            .copied();
        files.push((dir, p));
    }
    for p in rust_files("tests") {
        files.push((None, p));
    }

    for (moved_dir, path) in files {
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        for (idx, line) in src.lines().enumerate() {
            if let Some(c) = crate_re.captures(line) {
                refs.push(ModuleRef {
                    file: show(&path),
                    line: idx + 1,
                    dir: format!("src/{}", &c[1]),
                    segment: c[2].to_string(),
                    text: line.trim().to_string(),
                });
            } else if crate_any.is_match(line) {
                unparsed.push(format!("  {}:{}: {}", show(&path), idx + 1, line.trim()));
            }
            if let Some(dir) = moved_dir
                && let Some(c) = super_re.captures(line)
            {
                refs.push(ModuleRef {
                    file: show(&path),
                    line: idx + 1,
                    dir: dir.to_string(),
                    segment: c[1].to_string(),
                    text: line.trim().to_string(),
                });
            }
        }
    }
    (refs, unparsed)
}

/// The module refs a moved directory's own `#[cfg(test)] mod` blocks make,
/// plus how many `use` lines and modules were seen.
///
/// A test module runs from `mod NAME {` to the next unindented `}`, which is
/// where a rustfmt-formatted top-level module ends. Brace counting is not used
/// on purpose: these files carry format strings full of `{` and `}`, and a
/// miscount would silently move the end of the block.
fn test_module_refs() -> (Vec<ModuleRef>, usize, usize) {
    let head = regex::Regex::new(r"^mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{").expect("mod pattern");
    let crate_re =
        regex::Regex::new(r"^\s*use\s+crate::(relay|rtpengine)::([A-Za-z_][A-Za-z0-9_]*)")
            .expect("crate use pattern");
    let mut refs = Vec::new();
    let mut modules = 0usize;
    let mut use_lines = 0usize;
    for (_, path) in moved_files() {
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = src.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            if lines[i].trim() == "#[cfg(test)]" {
                let mut k = i + 1;
                while k < lines.len() && lines[k].trim().starts_with("#[") {
                    k += 1;
                }
                if k < lines.len() && head.is_match(lines[k]) {
                    modules += 1;
                    let mut j = k + 1;
                    while j < lines.len() && lines[j] != "}" {
                        if lines[j].trim().starts_with("use ") {
                            use_lines += 1;
                        }
                        if let Some(c) = crate_re.captures(lines[j]) {
                            refs.push(ModuleRef {
                                file: show(&path),
                                line: j + 1,
                                dir: format!("src/{}", &c[1]),
                                segment: c[2].to_string(),
                                text: lines[j].trim().to_string(),
                            });
                        }
                        j += 1;
                    }
                    i = j;
                }
            }
            i += 1;
        }
    }
    (refs, modules, use_lines)
}

/// Does a first path segment under a moved directory name something real?
fn segment_resolves(dir: &str, segment: &str) -> bool {
    child_modules(dir).contains(segment) || root_items(dir).contains(segment)
}

/// Every `.md` under `docs/`, recursively, sorted.
fn docs_pages() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![repo().join("docs")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "md") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Resolve a page-relative link target against the page's directory.
fn resolve_link(page: &Path, target: &str) -> PathBuf {
    let mut out = page
        .parent()
        .unwrap_or(Path::new(""))
        .strip_prefix(repo())
        .unwrap_or(Path::new(""))
        .to_path_buf();
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

/// Relative markdown links on one page that point into `src/`, as
/// `(raw link, repo-relative target)`.
fn src_links(page: &Path, text: &str) -> Vec<(String, PathBuf)> {
    let re = regex::Regex::new(r"\[([^\]]*)\]\(([^)\s]+)\)").expect("link pattern");
    let mut out = Vec::new();
    for c in re.captures_iter(text) {
        let target = &c[2];
        if target.starts_with("http") || target.starts_with('#') {
            continue;
        }
        let bare = target.split('#').next().unwrap_or(target);
        let resolved = resolve_link(page, bare);
        if resolved.starts_with("src") {
            out.push((c[0].to_string(), resolved));
        }
    }
    out
}

/// A doc comment still sits on the item it documents.
///
/// Defect 4, and the reason it is structural rather than cosmetic: an insert
/// that lands between a `///` block and its item leaves BOTH halves compiling.
/// The block above documents whatever now follows it -- or nothing at all --
/// and the item below is silently undocumented, while `missing_docs` stays
/// quiet because some other block drifted into place above it. `is_ng_over_hep`
/// is the live instance: its summary line ended up below `#[must_use]` and
/// below the paragraph that used to follow it, so rustdoc renders a body
/// paragraph as the function's one-line summary.
///
/// A block is detached when the line after it is blank, when the file ends
/// there, or when the attribute run between it and its item is broken by a
/// blank line.
#[test]
fn every_doc_block_is_attached_to_the_item_it_documents() {
    let mut detached = Vec::new();
    let mut blocks = 0usize;
    for (_, path) in moved_files() {
        let src = std::fs::read_to_string(&path).expect("read moved file");
        let lines: Vec<&str> = src.lines().collect();
        for (start, end) in doc_blocks(&lines) {
            blocks += 1;
            let why = if end >= lines.len() {
                Some("the file ends here")
            } else if lines[end].trim().is_empty() {
                Some("a blank line follows it")
            } else {
                let after = skip_attributes(&lines, end);
                if after >= lines.len() {
                    Some("the file ends after its attributes")
                } else if lines[after].trim().is_empty() {
                    Some("a blank line splits it from its item")
                } else {
                    None
                }
            };
            if let Some(why) = why {
                detached.push(format!(
                    "  {}:{}: {why}\n      {}",
                    show(&path),
                    start + 1,
                    lines[start].trim()
                ));
            }
        }
    }
    assert!(
        blocks >= 150,
        "only {blocks} doc blocks found across {MOVED_DIRS:?}; the block scanner has stopped matching and this rule is reading an empty tree"
    );
    assert!(
        detached.is_empty(),
        "these doc blocks document nothing:\n{}\n\nAn insert landed between a \
         `///` block and its item. Both halves still compile, so nothing else \
         reports it: the block now describes whatever follows it, and the item \
         below carries whichever block drifted into place -- which is how a \
         function keeps a body paragraph as its rendered summary line. Move \
         the block back onto its item, attributes included.",
        detached.join("\n")
    );
}

/// Every public item in the moved modules carries a doc comment.
///
/// # Why this duplicates `missing_docs`
///
/// `src/lib.rs` sets `#![warn(missing_docs)]` and CI compiles with
/// `-D warnings`, so rustc already refuses an undocumented public item. The
/// duplication is deliberate and specific: rustc reports the ABSENCE of a doc,
/// and a move that shuffles doc blocks between neighbors produces a tree where
/// every item has SOME doc and rustc is therefore silent. This gate fires
/// under the name of the move that caused it, in the same file as the
/// attachment rule above, so the two failures are read together rather than as
/// an unrelated lint and an unrelated test. It also runs when nobody has
/// enabled `-D warnings` locally, which is the state the pre-commit hook found
/// this repository in.
///
/// `pub mod NAME;` is exempt exactly when `NAME`'s own file opens with a `//!`
/// header -- the repository convention `module_doc_form_test` enforces -- and
/// the exemption is checked rather than assumed.
#[test]
fn every_public_item_in_the_moved_modules_is_documented() {
    let mut undocumented = Vec::new();
    let mut public_items = 0usize;
    let mod_decl = regex::Regex::new(r"^pub mod ([A-Za-z_][A-Za-z0-9_]*);").expect("mod pattern");
    for (dir, path) in moved_files() {
        let src = std::fs::read_to_string(&path).expect("read moved file");
        let lines: Vec<&str> = src.lines().collect();
        let mut documented = false;
        let mut i = 0;
        while i < lines.len() {
            let t = lines[i].trim();
            if t.is_empty() {
                documented = false;
                i += 1;
                continue;
            }
            if is_doc_line(t) {
                documented = true;
                i += 1;
                continue;
            }
            if t.starts_with("//") {
                i += 1;
                continue;
            }
            if t.starts_with("#[") || t.starts_with("#![") {
                i = skip_attributes(&lines, i);
                continue;
            }
            if t.starts_with("pub ") {
                public_items += 1;
                if !documented {
                    let exempt = mod_decl.captures(t).is_some_and(|c| {
                        let child = repo().join(dir).join(format!("{}.rs", &c[1]));
                        let nested = repo().join(dir).join(&c[1]).join("mod.rs");
                        let target = if child.is_file() { child } else { nested };
                        std::fs::read_to_string(&target)
                            .unwrap_or_default()
                            .lines()
                            .any(|l| l.trim_start().starts_with("//!"))
                    });
                    if !exempt {
                        undocumented.push(format!("  {}:{}: {t}", show(&path), i + 1));
                    }
                }
            }
            documented = false;
            i += 1;
        }
    }
    assert!(
        public_items >= 80,
        "only {public_items} public items found across {MOVED_DIRS:?}; the item scanner has stopped matching, so this rule would pass on a tree with no docs at all"
    );
    assert!(
        undocumented.is_empty(),
        "these public items carry no doc comment:\n{}\n\nThe first reader of a \
         moved module is somebody deciding which side of the seam a thing \
         belongs on, and an undocumented item gives them the signature and \
         nothing else. `missing_docs` says the same thing at build time; this \
         says it under the name of the move, next to the rule about doc blocks \
         drifting off their items, because those two failures have one cause.",
        undocumented.join("\n")
    );
}

/// No string the seam can show an operator names a relay vendor.
///
/// Defect 2, and it is a different rule from
/// `relay_seam_test::no_consuming_layer_names_a_relay_vendor`. That one scans
/// code lines in the layers ABOVE the seam and is about coupling: a module
/// reaching a vendor name has taken a dependency it should not have. This one
/// scans string LITERALS inside the seam and is about truth: "rtpengine at
/// 10.0.0.4" printed while rtpproxy answered is not a coupling smell, it is a
/// false sentence in an operator's log. `ReadOnlyRelay::describe()` exists so
/// the implementation names itself.
#[test]
fn no_operator_string_in_the_seam_names_a_relay_vendor() {
    let mut offenders = Vec::new();
    let mut literals = 0usize;
    for path in rust_files("src/relay") {
        let src = std::fs::read_to_string(&path).expect("read seam file");
        for (line, text) in string_literals(&src) {
            literals += 1;
            let lower = text.to_ascii_lowercase();
            if let Some(name) = VENDOR_NAMES.iter().find(|v| lower.contains(**v)) {
                offenders.push(format!(
                    "  {}:{line}: names {name:?} in \"{}\"",
                    show(&path),
                    &text[..text.len().min(70)]
                ));
            }
        }
    }
    assert!(
        literals >= 80,
        "only {literals} string literals found under src/relay/; the literal scanner has stopped matching and this rule cannot see an operator message at all"
    );
    assert!(
        offenders.is_empty(),
        "the seam hardcodes a relay vendor in text it shows an operator:\n{}\n\n\
         The seam does not know which relay answered, so a sentence naming one \
         is false as soon as a second exists -- and it is false in a log line, \
         where somebody will act on it. Ask the implementation what it is: \
         `ReadOnlyRelay::describe()` is there for this.",
        offenders.join("\n")
    );
}

/// Every import naming a moved module names one that exists.
///
/// Defects 3 and 5 together. Defect 3 was a blanket `sed` that rewrote
/// `super::control::` to `crate::rtpengine::control::` everywhere, including
/// on the one line importing types that had just left that module. Defect 5
/// was two files still importing the old paths, which the compiler never saw
/// because both imports sit behind `#[cfg(test)]`.
///
/// The check is structural rather than a build: it holds for imports the
/// current feature set does not compile at all, which is where a stale path
/// survives longest. `use crate::relay::X` is read at any indentation and
/// `use super::X` only at column zero inside the moved directories, where
/// `super` can only mean the directory module.
#[test]
fn every_import_of_a_moved_module_resolves() {
    let (refs, unparsed) = module_refs();
    assert!(
        unparsed.is_empty(),
        "these lines import from a moved directory in a form this scanner \
         cannot read, so they are checked by nothing:\n{}\n\nTeach the parser \
         the form or rewrite the import; a silently skipped line is the state \
         this gate exists to make impossible.",
        unparsed.join("\n")
    );
    assert!(
        refs.len() >= 12,
        "only {} import(s) of a moved module found across src/ and tests/; the `use` scanner has stopped matching and every path below is unchecked",
        refs.len()
    );

    let mut dead = Vec::new();
    for r in &refs {
        if !segment_resolves(&r.dir, &r.segment) {
            dead.push(format!(
                "  {}:{}: {} -- {}/{}.rs does not exist",
                r.file, r.line, r.text, r.dir, r.segment
            ));
        }
    }
    assert!(
        dead.is_empty(),
        "these imports name a module the move deleted:\n{}\n\nA path is a \
         reference the compiler only checks where it compiles the code holding \
         it. Behind `#[cfg(test)]` or a feature this build does not enable, a \
         stale path is invisible -- `cargo build` was silent about both files \
         that carried one after the reconciler moved.",
        dead.join("\n")
    );
}

/// Every relative documentation link into `src/` resolves.
///
/// Defect 6. `dev_docs_drift_test::linked_code_targets_exist` already does
/// this, and does it more broadly -- every code tree, not just `src/` -- but
/// only for pages under `docs/internals/`. Measured on 2026-08-31: the `docs/`
/// tree holds 294 relative links into `src/`, 208 of them on internals pages
/// that gate reads and 86 on pages it never opens (`docs/*.md`,
/// `docs/design/`, `docs/research/`, `docs/superpowers/`). The sibling gates
/// do not close that gap either: `link_integrity_test` and
/// `doc_link_hygiene_test` both `continue` on any target not ending in `.md`.
///
/// So this is the half that was missing, not agreement with an existing gate,
/// and it is written to overlap on purpose: running the same rule over the
/// whole tree means a page moving between `docs/` and `docs/internals/` cannot
/// move out from under the check.
#[test]
fn every_documentation_link_into_src_resolves() {
    let mut missing = Vec::new();
    let mut links = 0usize;
    let mut outside_internals = 0usize;
    let pages = docs_pages();
    for page in &pages {
        let text = std::fs::read_to_string(page).expect("read documentation page");
        let internals = show(page).starts_with("docs/internals/");
        for (raw, target) in src_links(page, &text) {
            links += 1;
            if !internals {
                outside_internals += 1;
            }
            if !repo().join(&target).exists() {
                missing.push(format!(
                    "  {}: {raw} -> {} does not exist",
                    show(page),
                    target.display()
                ));
            }
        }
    }
    assert!(
        pages.len() >= 60,
        "only {} markdown page(s) found under docs/; the walk is reading \
         almost nothing and this rule would report a clean tree",
        pages.len()
    );
    assert!(
        links >= 200,
        "only {links} link(s) into src/ found across docs/; the link extractor has stopped matching, which is exactly how a documentation gate goes quiet without failing"
    );
    assert!(
        outside_internals >= 40,
        "only {outside_internals} of those links sit outside docs/internals/; those are the ones no other gate reads, and finding none means this test has become a duplicate of `linked_code_targets_exist`"
    );
    assert!(
        missing.is_empty(),
        "these documentation links point at code that has moved:\n{}\n\nA \
         citation that looks precise and lands nowhere is worse than no \
         citation: the reader has no reason to doubt it. Repoint them at the \
         path the file has now.",
        missing.join("\n")
    );
}

/// Test-only imports are held to the same rule as production ones.
///
/// # Why a green build says nothing here
///
/// `cargo build` compiles the library. It does not compile anything behind
/// `#[cfg(test)]`, so an import inside `mod tests` can name a module that was
/// deleted an hour ago and the build stays green -- which is exactly what
/// happened: `src/relay/reconcile.rs`'s own test module and
/// `src/app/relay_reconciler.rs` both still pointed at
/// `crate::rtpengine::reconcile`, and the first thing that said so was
/// `cargo test --no-run`.
///
/// This asserts the coverage structurally instead of re-deriving it: every
/// moved-module import inside a `#[cfg(test)] mod` block must appear, by file
/// and line, in the repo-wide set that `every_import_of_a_moved_module_resolves`
/// checks. One scan covers both kinds of code, so a future narrowing that
/// excluded test modules fails here rather than quietly halving what is
/// checked.
#[test]
fn test_only_imports_are_covered_by_the_same_import_scan() {
    let (test_refs, modules, use_lines) = test_module_refs();
    assert!(
        modules >= 4,
        "only {modules} `#[cfg(test)] mod` block(s) found across {MOVED_DIRS:?}; \
         the block finder has stopped matching and no test-only import is \
         being examined"
    );
    assert!(
        use_lines >= 8,
        "only {use_lines} `use` line(s) inside those test modules; the block boundary has collapsed, so this rule is reading a fragment of the test code"
    );
    assert!(
        !test_refs.is_empty(),
        "no test-only import names a moved module (measured: 2 on 2026-08-31), so this rule proves nothing about the code `cargo build` never compiles"
    );

    let (all_refs, _) = module_refs();
    let indexed: BTreeMap<(String, usize), &ModuleRef> = all_refs
        .iter()
        .map(|r| ((r.file.clone(), r.line), r))
        .collect();
    let mut uncovered = Vec::new();
    for r in &test_refs {
        match indexed.get(&(r.file.clone(), r.line)) {
            Some(found) if found.segment == r.segment => {}
            _ => uncovered.push(format!("  {}:{}: {}", r.file, r.line, r.text)),
        }
    }
    assert!(
        uncovered.is_empty(),
        "these test-only imports are outside the scan that checks production \
         imports:\n{}\n\nThe library building clean is not evidence about test \
         code -- `#[cfg(test)]` is not compiled by `cargo build` at all. If the \
         import scan stops reading indented `use` lines, every one of these \
         goes unchecked and the only thing left that would notice is a full \
         `cargo test --no-run`.",
        uncovered.join("\n")
    );
    for r in &test_refs {
        assert!(
            segment_resolves(&r.dir, &r.segment),
            "test-only import {}:{} names `{}`, which does not exist under {}",
            r.file,
            r.line,
            r.segment,
            r.dir
        );
    }
}

/// Every walk in this file found a tree, not an empty directory.
///
/// Six of the seven rules here are scans, and a scan that matches nothing
/// agrees with any repository. Each floor below is well under what was
/// measured on 2026-08-31 -- the measured value is in the message -- so
/// ordinary growth does not move it, while an extractor that has stopped
/// matching fails here instead of reporting a clean tree.
#[test]
fn every_walk_in_this_file_found_a_plausible_tree() {
    let files = moved_files();
    let mut blocks = 0usize;
    let mut public_items = 0usize;
    for (_, path) in &files {
        let src = std::fs::read_to_string(path).expect("read moved file");
        let lines: Vec<&str> = src.lines().collect();
        blocks += doc_blocks(&lines).len();
        public_items += lines
            .iter()
            .filter(|l| l.trim().starts_with("pub "))
            .count();
    }
    let literals: usize = rust_files("src/relay")
        .iter()
        .map(|p| string_literals(&std::fs::read_to_string(p).unwrap_or_default()).len())
        .sum();
    let (refs, _) = module_refs();
    let (test_refs, test_modules, test_uses) = test_module_refs();
    let pages = docs_pages();
    let doc_links: usize = pages
        .iter()
        .map(|p| src_links(p, &std::fs::read_to_string(p).unwrap_or_default()).len())
        .sum();

    let measured = [
        ("rust files in the moved directories", files.len(), 6, 7),
        ("doc-comment blocks", blocks, 150, 264),
        ("public item lines", public_items, 80, 114),
        ("string literals under src/relay", literals, 80, 149),
        ("imports of a moved module", refs.len(), 12, 17),
        ("test-only imports of a moved module", test_refs.len(), 1, 2),
        ("cfg(test) modules in the moved dirs", test_modules, 4, 5),
        ("use lines inside those modules", test_uses, 8, 13),
        ("markdown pages under docs/", pages.len(), 60, 96),
        ("documentation links into src/", doc_links, 200, 294),
    ];
    let mut thin = Vec::new();
    for (what, got, floor, baseline) in measured {
        if got < floor {
            thin.push(format!(
                "  {what}: found {got}, floor {floor}, measured {baseline} on 2026-08-31"
            ));
        }
    }
    assert!(
        thin.is_empty(),
        "these walks found less than the tree holds:\n{}\n\nEvery rule in this \
         file is a scan, and a scan matching nothing passes on any repository. \
         A number below its floor means the extractor stopped matching, not \
         that the code shrank -- attribute the drop per file before touching a \
         floor.",
        thin.join("\n")
    );
}
