// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Public documentation must not link to items rustdoc cannot reach.
//!
//! `cargo doc` with `RUSTDOCFLAGS="-D warnings"` refuses a `pub` item whose
//! docs carry an intra-doc link to a private or `pub(crate)` item, because the
//! rendered page would show a link the reader cannot follow. That check lives
//! in the pre-push hook and in CI's Docs step -- not in pre-commit, which is
//! the gap these tests close. Two doc links added to `capture_hep` sailed
//! through a full green pre-commit run, including its own 15-minute suite, and
//! were caught only when `git push` ran the hook ten minutes later.
//!
//! The cost is not the ten minutes. It is that the commit was already made, so
//! the fix arrives as a second commit against work that was reported finished.
//!
//! Names are resolved by module scope. A private test helper `fn sorted` in a
//! `#[cfg(test)] mod` once made this gate refuse a correct link to the
//! file's `pub fn sorted`, because every declaration of the file shared one
//! table. The scopes are read from indentation, so the gate assumes a
//! rustfmt-formatted tree, as `scripts/check-rustfmt.sh` enforces: each inline
//! `mod NAME {` closes with a `}` alone on a line at the `mod` line's
//! indentation. A module laid out any other way is refused by file and line
//! rather than read wrongly.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The error a test returns: any error, boxed, so `?` works on I/O,
/// parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `src/`.
fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo().join("src"), &mut out);
    out.sort();
    out
}

/// Whether an item declaration line makes the item public *outside the crate*.
///
/// `pub(crate)` and `pub(super)` are deliberately NOT public here. That is the
/// whole point: rustdoc treats them exactly as it treats a bare private item
/// when a `pub` item's documentation links to one, and `hep_stream_frame` --
/// one of the two links that blocked the push -- was `pub(crate)`. A checker
/// that accepted any leading `pub` would have called that link fine.
fn is_public(decl: &str) -> bool {
    let t = decl.trim_start();
    t.starts_with("pub ") || t.starts_with("pub\t")
}

/// Item name and whether it is publicly visible, for every item declared in
/// one file.
///
/// Keyed by name, so a file declaring two items with one name (an inherent
/// method and a free function, say) keeps the last -- acceptable because the
/// question asked of this map is only ever "is there a NON-public item by this
/// name here", and a collision that hides a private one would make the gate
/// quieter, never louder.
fn declarations(text: &str) -> BTreeMap<String, bool> {
    text.lines().filter_map(declared).collect()
}

/// The item one line declares, if it declares one: its name and whether it
/// is public.
///
/// `const` is both a kind (`const LIMIT: u8`) and a qualifier (`const fn`),
/// so it is stepped over only when a function follows it. Stepping over it
/// always made every `const` item invisible to this gate.
fn declared(line: &str) -> Option<(String, bool)> {
    let kinds = [
        "fn",
        "struct",
        "enum",
        "trait",
        "const",
        "static",
        "type",
        "union",
        "macro_rules!",
        // A module is an item a link can name: on #888 a public fn linked the
        // private file module `sngrep_mode`, and only `cargo doc` refused it.
        "mod",
    ];
    let t = line.trim_start();
    // Skip the visibility prefix to find the kind keyword, remembering
    // whether that prefix made it public. Every restricted form,
    // `pub(in path)` included, is one `pub(...)`.
    let public = is_public(t);
    let rest = t
        .strip_prefix("pub(")
        .and_then(|r| r.split_once(") "))
        .map(|(_, after)| after)
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    // `async`, `unsafe`, `extern "C"` and a function's `const` may sit
    // between the visibility and the kind.
    let mut rest = rest.trim_start_matches("default ");
    if let Some(after) = rest.strip_prefix("const ") {
        let qualified = after
            .trim_start_matches("async ")
            .trim_start_matches("unsafe ")
            .trim_start_matches("extern \"C\" ")
            .trim_start_matches("extern \"Rust\" ");
        if qualified.starts_with("fn ") {
            rest = after;
        }
    }
    let rest = rest
        .trim_start_matches("async ")
        .trim_start_matches("unsafe ")
        .trim_start_matches("extern \"C\" ")
        .trim_start_matches("extern \"Rust\" ");
    for kind in kinds {
        let Some(after) = rest.strip_prefix(kind) else {
            continue;
        };
        let Some(after) = after.strip_prefix([' ', '\t']) else {
            continue;
        };
        let name: String = after
            .trim_start()
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        return (!name.is_empty()).then_some((name, public));
    }
    None
}

/// Leading spaces of a line.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// An inline module's opening line, `mod NAME {` with any visibility: its
/// indentation, its name, and the text after its `{`, trimmed.
///
/// `mod NAME;` opens nothing: its body is another file, which this gate
/// scans on its own.
fn mod_opener(line: &str) -> Option<(usize, &str, &str)> {
    let mut rest = line.trim_start_matches(' ');
    if let Some(r) = rest.strip_prefix("pub(") {
        let close = r.find(')')?;
        rest = r[close + 1..].strip_prefix(' ')?;
    } else if let Some(r) = rest.strip_prefix("pub ") {
        rest = r;
    }
    let rest = rest.strip_prefix("mod ")?;
    let end = rest.find([' ', '{', ';'])?;
    let (name, after) = rest.split_at(end);
    let after = after.trim_start().strip_prefix('{')?;
    Some((indent_of(line), name, after.trim()))
}

/// The terms of a `cfg` list at its top level: `unix, not(test)` gives
/// `unix` and `not(test)`.
fn top_level_terms(list: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, c) in list.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(list[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(list[start..].trim());
    out
}

/// Whether an attribute line limits its item to test builds: `#[cfg(test)]`,
/// or `#[cfg(all(...))]` with `test` as one of its top-level terms.
///
/// `any(test, ...)` and `not(test)` are not test-only, and rustdoc builds
/// what they guard.
fn is_test_only_cfg(attr: &str) -> bool {
    let a: String = attr.chars().filter(|c| !c.is_whitespace()).collect();
    if a == "#[cfg(test)]" {
        return true;
    }
    a.strip_prefix("#[cfg(all(")
        .and_then(|r| r.strip_suffix("))]"))
        .is_some_and(|list| top_level_terms(list).contains(&"test"))
}

/// Whether the attributes above line `at` make it test-only. Attribute and
/// comment lines are read upward until the first line that is neither.
fn under_test_cfg(lines: &[&str], at: usize) -> bool {
    lines[..at]
        .iter()
        .rev()
        .map(|l| l.trim_start())
        .take_while(|t| t.starts_with("#[") || t.starts_with("//"))
        .any(is_test_only_cfg)
}

/// For each line, whether it begins inside a string literal, a raw string or
/// a block comment.
///
/// Such a line is text, not code: a sample in a test that holds `}` or
/// `mod x {` at column 0 must neither close nor open a scope. Escapes in a
/// string, the `#` count of a raw string, nested block comments, line
/// comments, and a `'"'` char literal (as distinct from a lifetime) are read
/// as the compiler reads them.
fn starts_in_literal(lines: &[&str]) -> Vec<bool> {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Code,
        Str,
        Raw(usize),
        Block(usize),
    }
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut state = State::Code;
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        out.push(state != State::Code);
        let c: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < c.len() {
            match state {
                State::Code => {
                    let prev = i.checked_sub(1).map(|p| c[p]);
                    if c[i] == '/' && c.get(i + 1) == Some(&'/') {
                        break;
                    } else if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                        state = State::Block(1);
                        i += 1;
                    } else if c[i] == '"' {
                        state = State::Str;
                    } else if c[i] == '\'' {
                        // A char literal is `'x'` or an escape such as
                        // `'\n'`; anything else is a lifetime or a label.
                        if c.get(i + 1) == Some(&'\\') {
                            i += 2;
                            while i < c.len() && c[i] != '\'' {
                                i += 1;
                            }
                        } else if c.get(i + 2) == Some(&'\'') {
                            i += 2;
                        }
                    } else if c[i] == 'r'
                        && match prev {
                            // `r"`, `r#"`, and the byte form `br"`.
                            None => true,
                            Some('b') => i < 2 || !ident(c[i - 2]),
                            Some(p) => !ident(p),
                        }
                    {
                        let hashes = c[i + 1..].iter().take_while(|&&h| h == '#').count();
                        if c.get(i + 1 + hashes) == Some(&'"') {
                            state = State::Raw(hashes);
                            i += 1 + hashes;
                        }
                    }
                }
                State::Str => {
                    if c[i] == '\\' {
                        i += 1;
                    } else if c[i] == '"' {
                        state = State::Code;
                    }
                }
                State::Raw(n) => {
                    if c[i] == '"' && c[i + 1..].iter().take(n).filter(|&&h| h == '#').count() == n
                    {
                        state = State::Code;
                        i += n;
                    }
                }
                State::Block(d) => {
                    if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                        state = State::Block(d + 1);
                        i += 1;
                    } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                        state = if d == 1 {
                            State::Code
                        } else {
                            State::Block(d - 1)
                        };
                        i += 1;
                    }
                }
            }
            i += 1;
        }
    }
    out
}

/// The line that closes the inline module opened at line `open` with
/// indentation `indent`: the first later non-blank line indented no deeper
/// than the `mod` line. It must be exactly that indentation and a `}`
/// (a trailing `//` comment is allowed), or the module is not laid out as
/// rustfmt lays it out and there is no line to return.
/// Lines that begin inside a literal or a block comment (`literal`) are
/// skipped.
fn closing_line(lines: &[&str], literal: &[bool], open: usize, indent: usize) -> Option<usize> {
    for (j, line) in lines.iter().enumerate().skip(open + 1) {
        if literal[j] || line.trim().is_empty() || indent_of(line) > indent {
            continue;
        }
        let rest = line[indent_of(line)..].strip_prefix('}')?;
        let rest = rest.trim_start();
        return (indent_of(line) == indent && (rest.is_empty() || rest.starts_with("//")))
            .then_some(j);
    }
    None
}

/// One module scope of a file: the file itself, or an inline `mod` block.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Scope {
    /// 0-based index of the scope's first line.
    first: usize,
    /// 0-based index one past its last line: the closing `}` line of a
    /// module, the line count for the file.
    end: usize,
    /// Indentation of the scope's own items. Deeper lines (methods in an
    /// `impl`, items inside a function) are not names of the scope.
    body_indent: usize,
    /// The scope is under a test-only `cfg`, so rustdoc never builds it.
    test_only: bool,
}

/// A file split into its module scopes, the file first.
///
/// This assumes a rustfmt-formatted file, which `scripts/check-rustfmt.sh`
/// holds the tree to: an inline module opens on a line `mod NAME {`, its
/// items sit four spaces deeper, and its closing `}` is on a line of its own
/// at the `mod` line's indentation. A module that does not fit (its body on
/// the `mod` line, a `}` at another indentation, no `}` at all, or a name a
/// macro supplies) is refused with its line, because reading it by
/// indentation would put items in the wrong scope. Only `mod NAME {}`, which
/// has no body to misplace, is accepted on one line.
///
/// A line that begins inside a string literal or a block comment neither
/// opens nor closes a module. The inside of a test-only module is not split
/// further: nothing in it is judged.
fn scopes(lines: &[&str]) -> Result<Vec<Scope>, ScopeError> {
    let literal = starts_in_literal(lines);
    let mut out = vec![Scope {
        first: 0,
        end: lines.len(),
        body_indent: 0,
        test_only: false,
    }];
    let mut i = 0;
    while i < lines.len() {
        let opener = if literal[i] {
            None
        } else {
            mod_opener(lines[i])
        };
        let Some((indent, name, after)) = opener else {
            i += 1;
            continue;
        };
        let refuse = |message: String| ScopeError {
            line_no: i + 1,
            message,
        };
        if name.starts_with('$') {
            return Err(refuse(format!(
                "`mod {name}` is generated by a macro: its layout is the macro's, not \
                 rustfmt's, so its scope cannot be read by indentation"
            )));
        }
        if after == "}" {
            i += 1;
            continue;
        }
        if !after.is_empty() {
            return Err(refuse(format!(
                "`mod {name}` has its body on the same line; the scope split needs the \
                 closing `}}` on a line of its own at the `mod` line's indentation"
            )));
        }
        let close = closing_line(lines, &literal, i, indent).ok_or_else(|| {
            refuse(format!(
                "`mod {name}` has no closing `}}` at its own indentation ({indent} spaces) \
                 before the next line at that indentation or the end of the file"
            ))
        })?;
        let test_only = under_test_cfg(lines, i);
        out.push(Scope {
            first: i + 1,
            end: close,
            body_indent: indent + 4,
            test_only,
        });
        i = if test_only { close + 1 } else { i + 1 };
    }
    Ok(out)
}

/// Index of the innermost scope holding line `at`. Scopes are listed in the
/// order they open, so the last one that holds the line is the innermost.
fn scope_of(scopes: &[Scope], at: usize) -> usize {
    scopes
        .iter()
        .rposition(|s| s.first <= at && at < s.end)
        .unwrap_or(0)
}

/// One documented item: the doc lines above it and the line declaring it.
struct Documented {
    line_no: usize,
    /// 0-based index of the declaration line.
    decl_line: usize,
    doc: String,
    decl: String,
    /// `#[doc(hidden)]` sat between the docs and the declaration.
    ///
    /// Such an item is not rendered, so rustdoc never resolves its links and
    /// this gate must not either -- rustdoc is the authority, and a gate that
    /// demanded more than the authority would be unfixable except by weakening
    /// documentation nobody reads. `rtp::rtcp::compact_ntp_for_test` is the
    /// real instance: `pub` inside a `pub mod`, hidden, and its docs open by
    /// naming the private `compact_ntp` it wraps.
    hidden: bool,
}

/// Every item in a file that carries `///` documentation.
///
/// Attributes between the docs and the declaration are stepped over -- a
/// `#[derive]` or `#[allow]` does not end a doc block -- but a blank line
/// does, because a `///` block separated from its item by a blank line is not
/// attached to it at all. That is the same attachment rule
/// `attribute_attachment_test` exists to police, and reading it differently
/// here would make the two gates disagree about what a doc comment belongs to.
fn documented_items(text: &str) -> Vec<Documented> {
    let mut out = Vec::new();
    let mut doc: Vec<&str> = Vec::new();
    let mut doc_start = 0usize;
    let mut hidden = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("///") {
            if doc.is_empty() {
                doc_start = i + 1;
                hidden = false;
            }
            doc.push(rest);
        } else if doc.is_empty() {
            continue;
        } else if t.starts_with("#[") || t.starts_with("#![") {
            // An attribute keeps the block open, but `#[doc(hidden)]` decides
            // whether rustdoc will ever look at what follows.
            if t.replace(' ', "").starts_with("#[doc(hidden)") {
                hidden = true;
            }
        } else if t.is_empty() {
            // A blank line detaches the block from whatever comes next.
            doc.clear();
        } else {
            out.push(Documented {
                line_no: doc_start,
                decl_line: i,
                doc: doc.join("\n"),
                decl: line.to_string(),
                hidden,
            });
            doc.clear();
        }
    }
    out
}

/// The unqualified intra-doc link targets in one doc block.
///
/// Only the ``[`Name`]`` form, and only when no `(target)` follows it: a
/// ``[`x`](https://…)`` is an ordinary markdown link whose destination rustdoc
/// never resolves, and flagging those would make this gate fire on every
/// citation in the tree. Qualified paths (`signals::shutdown_requested`,
/// `Self::send`) are skipped because they resolve somewhere other than this
/// file, and this gate only claims to know what this file declares.
///
/// Fenced blocks inside the doc comment are skipped, so a `[`x`]` shown as
/// example prose in a doctest is not read as a link.
fn intra_doc_links(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut fenced = false;
    for line in doc.lines() {
        // Tolerate a leading `///`: `documented_items` hands over stripped
        // content, but a caller reading raw source lines must see the same
        // fences, or an example block would be scanned as prose.
        let t = line.trim_start().trim_start_matches("///").trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let bytes: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i + 2 < bytes.len() {
            if bytes[i] == '[' && bytes[i + 1] == '`' {
                let mut j = i + 2;
                let mut name = String::new();
                while j < bytes.len() && bytes[j] != '`' {
                    name.push(bytes[j]);
                    j += 1;
                }
                // Require the closing "`]" and no "(" immediately after.
                let closed = j + 1 < bytes.len() && bytes[j] == '`' && bytes[j + 1] == ']';
                let linked = closed && bytes.get(j + 2) != Some(&'(');
                if linked
                    && !name.contains("::")
                    && !name.contains(' ')
                    && !name.is_empty()
                    && name.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    out.push(name);
                }
                i = j + 1;
            } else {
                i += 1;
            }
        }
    }
    out
}

/// One documented public item whose link names an item rustdoc cannot reach.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Offense {
    /// 1-based line of the first `///` line of the item's documentation.
    line_no: usize,
    /// The item's declaration line, trimmed.
    decl: String,
    /// The linked name.
    name: String,
}

/// What one file's scan found.
#[derive(Debug, Default)]
struct Scan {
    /// Documented public items whose links were judged.
    scanned: usize,
    /// Intra-doc links read from those items.
    links: usize,
    offenses: Vec<Offense>,
}

/// A file this gate cannot split into module scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopeError {
    /// 1-based line of the `mod` line that could not be read.
    line_no: usize,
    message: String,
}

/// The offenses in one file's text.
///
/// A link resolves only against the names of the scope that holds the
/// documented item, as rustdoc resolves it: a method in an `impl` against
/// its module, an item of an inline module against that module. A name is
/// an offense when that scope declares it and no declaration of it there is
/// `pub`. Items in a test-only module are neither names nor judged, because
/// rustdoc never builds them.
fn offenses_in(text: &str) -> Result<Scan, ScopeError> {
    let lines: Vec<&str> = text.lines().collect();
    let scopes = scopes(&lines)?;
    let mut names: Vec<BTreeMap<String, bool>> = vec![BTreeMap::new(); scopes.len()];
    for (at, line) in lines.iter().enumerate() {
        let s = scope_of(&scopes, at);
        if scopes[s].test_only || line.trim().is_empty() || indent_of(line) != scopes[s].body_indent
        {
            continue;
        }
        if let Some((name, public)) = declared(line) {
            *names[s].entry(name).or_insert(false) |= public;
        }
    }
    let mut scan = Scan::default();
    for item in documented_items(text) {
        let s = scope_of(&scopes, item.decl_line);
        if !is_public(&item.decl) || item.hidden || scopes[s].test_only {
            continue;
        }
        scan.scanned += 1;
        for name in intra_doc_links(&item.doc) {
            scan.links += 1;
            if let Some(false) = names[s].get(&name) {
                scan.offenses.push(Offense {
                    line_no: item.line_no,
                    decl: item.decl.trim().to_string(),
                    name,
                });
            }
        }
    }
    Ok(scan)
}

/// A `pub` item's documentation never links to a private or `pub(crate)` item
/// declared beside it.
///
/// This is the defect rustdoc rejected on `capture_hep`: it is `pub`, and its
/// docs linked ``[`HepIngest`]`` (a private struct) and ``[`hep_stream_frame`]``
/// (`pub(crate)`). Both are the right things to NAME in that prose -- they are
/// what the function's behavior is made of -- so the fix is to name them in a
/// code span rather than a link, not to make them public to satisfy a linker.
///
/// Scoped to names declared in the SAME module scope of the same file (see
/// `offenses_in`), which is what makes it cheap and
/// keeps it honest: it never guesses at cross-module resolution, so a link it
/// passes may still be wrong and rustdoc remains the authority. What it buys
/// is the common case, in the seconds before a commit rather than the minutes
/// after one.
#[test]
fn public_docs_do_not_link_to_items_rustdoc_cannot_reach() -> Result<(), TestError> {
    let mut offenses: Vec<String> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let mut links_seen = 0usize;

    for path in source_files() {
        let text = std::fs::read_to_string(&path)?;
        let shown = path.strip_prefix(repo()).unwrap_or(&path).display();
        match offenses_in(&text) {
            Ok(scan) => {
                scanned += scan.scanned;
                links_seen += scan.links;
                for o in scan.offenses {
                    offenses.push(format!(
                        "{shown}:{} — public `{}` links to `{}`, which is not public here",
                        o.line_no, o.decl, o.name
                    ));
                }
            }
            Err(e) => unreadable.push(format!("{shown}:{} — {}", e.line_no, e.message)),
        }
    }

    // A file the scope split cannot read is a refusal, not a pass: judging it
    // with the scopes misread would be wrong in either direction.
    assert!(
        unreadable.is_empty(),
        "files this gate cannot split into module scopes:\n  {}",
        unreadable.join("\n  ")
    );

    // An extractor that stopped matching would report zero offenses and look
    // exactly like a clean tree. Prove it still sees the shapes it reads.
    assert!(
        scanned > 500,
        "only {scanned} documented public items found — the item scanner stopped matching"
    );
    assert!(
        links_seen > 100,
        "only {links_seen} intra-doc links found — the link extractor stopped matching"
    );

    assert!(
        offenses.is_empty(),
        "public documentation links to items rustdoc cannot reach:\n  {}\n\
         Name them in a code span (`Foo`) instead of a link ([`Foo`]), or make \
         the target public if it genuinely belongs to the public API.",
        offenses.join("\n  ")
    );
    Ok(())
}

/// The scanner reads a real tree, and can tell a public link from a private
/// one.
///
/// Without this the gate above could pass because every helper returned
/// nothing. Each half is driven with material shaped like the defect.
#[test]
fn the_visibility_scanner_distinguishes_what_rustdoc_distinguishes() -> Result<(), TestError> {
    let sample = "\
/// Doc for a private struct.
struct HepIngest;

/// Doc for a crate-visible fn.
pub(crate) fn hep_stream_frame() {}

/// Doc for a public fn.
pub fn capture_hep() {}
";
    let decls = declarations(sample);
    assert_eq!(
        decls.get("HepIngest"),
        Some(&false),
        "a bare `struct` is not public"
    );
    assert_eq!(
        decls.get("hep_stream_frame"),
        Some(&false),
        "`pub(crate)` is not public to rustdoc's eye, which is the case that \
         caught us"
    );
    assert_eq!(decls.get("capture_hep"), Some(&true), "`pub fn` is public");

    assert_eq!(
        intra_doc_links("/// see [`HepIngest`] and [`hep_stream_frame`]")
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["HepIngest", "hep_stream_frame"],
        "both intra-doc links are read"
    );
    assert!(
        intra_doc_links("/// see [`x`](https://example.invalid/)").is_empty(),
        "a markdown link with a target is not an intra-doc link"
    );
    assert!(
        intra_doc_links("/// see [`signals::shutdown_requested`]").is_empty(),
        "a qualified path resolves outside this file, so it is not judged here"
    );
    assert!(
        intra_doc_links("/// ```\n/// [`NotALink`]\n/// ```").is_empty(),
        "a fenced example is content, not a link"
    );

    assert_eq!(
        documented_items(sample).len(),
        3,
        "all three documented items are found"
    );
    assert!(
        documented_items(sample).iter().all(|d| !d.hidden),
        "nothing in the sample is hidden"
    );

    // The one exclusion this gate makes, driven rather than asserted in prose.
    // Without it the gate is stricter than rustdoc, and a gate stricter than
    // its own authority is unfixable except by damaging documentation.
    let hidden_sample = "\
/// Wraps the private one for tests in sibling modules.
#[doc(hidden)]
#[must_use]
pub fn compact_ntp_for_test() {}
";
    let found = documented_items(hidden_sample);
    assert_eq!(found.len(), 1, "the hidden item is still parsed");
    assert!(
        found[0].hidden,
        "`#[doc(hidden)]` between the docs and the declaration must be seen, \
         even with another attribute after it -- rustdoc renders no page for \
         this item and so resolves none of its links"
    );
    Ok(())
}

/// The pre-push hook still runs rustdoc with warnings denied.
///
/// This gate is only as good as the authority behind it: the scanner above
/// judges one file at a time and says so, and rustdoc is what actually decides.
/// If the hook's Docs step were dropped or softened to a warning, nothing else
/// in the repo would notice -- pre-commit does not run `cargo doc` at all.
#[test]
fn the_pre_push_hook_still_denies_rustdoc_warnings() -> Result<(), TestError> {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-push"))?;

    let invocation = hook
        .lines()
        .find(|l| {
            l.contains("cargo doc") && l.contains("RUSTDOCFLAGS") && l.trim().starts_with("if")
        })
        .ok_or(
            "the pre-push hook no longer runs `cargo doc` under RUSTDOCFLAGS as a \
                 condition — without it, a private intra-doc link reaches CI",
        )?;

    assert!(
        invocation.contains("-D warnings"),
        "the hook runs cargo doc but no longer denies warnings, so a broken \
         intra-doc link would merely print: {invocation}"
    );
    assert!(
        invocation.contains("--all-features"),
        "the hook must document all features, or a link inside a feature-gated \
         item is never resolved: {invocation}"
    );
    Ok(())
}

/// What one sample must produce.
enum Want {
    /// The file splits, and the scan finds exactly this.
    Scan {
        scanned: usize,
        links: usize,
        /// `(line_no, linked name)` of each offense, in file order.
        offenses: &'static [(usize, &'static str)],
    },
    /// The file does not split: the error names this `mod` line and says
    /// this.
    Refused { line_no: usize, says: &'static str },
}

/// A scan with no offense.
const fn clean(scanned: usize, links: usize) -> Want {
    Want::Scan {
        scanned,
        links,
        offenses: &[],
    }
}

/// A scan with these offenses.
const fn offends(scanned: usize, links: usize, offenses: &'static [(usize, &'static str)]) -> Want {
    Want::Scan {
        scanned,
        links,
        offenses,
    }
}

/// A file the scope split refuses.
const fn refused(line_no: usize, says: &'static str) -> Want {
    Want::Refused { line_no, says }
}

/// Runs one sample through `offenses_in` and compares the result with `want`.
///
/// A sample is written as a raw string that opens with a newline, so its
/// first line can start at column 0 in the source; that newline is dropped
/// here, and line 1 is the sample's first line.
fn check(case: &str, text: &str, want: Want) -> Result<(), TestError> {
    let text = text.strip_prefix('\n').unwrap_or(text);
    let got = offenses_in(text);
    match want {
        Want::Scan {
            scanned,
            links,
            offenses,
        } => {
            let scan =
                got.map_err(|e| format!("{case}: expected a scan, got the refusal {e:?}"))?;
            let found: Vec<(usize, &str)> = scan
                .offenses
                .iter()
                .map(|o| (o.line_no, o.name.as_str()))
                .collect();
            assert_eq!(found, offenses, "{case}: offenses (line, name)");
            assert_eq!(
                scan.scanned, scanned,
                "{case}: documented public items judged"
            );
            assert_eq!(scan.links, links, "{case}: intra-doc links read");
        }
        Want::Refused { line_no, says } => {
            let e = match got {
                Ok(scan) => {
                    return Err(format!(
                        "{case}: expected a refusal at line {line_no}, got {scan:?}"
                    )
                    .into());
                }
                Err(e) => e,
            };
            assert_eq!(e.line_no, line_no, "{case}: refused line ({})", e.message);
            assert!(
                e.message.contains(says),
                "{case}: the refusal must say {says:?}, it says {:?}",
                e.message
            );
        }
    }
    Ok(())
}

/// One `#[test]` per sample, so each case passes or fails by its own name.
macro_rules! cases {
    ($($name:ident: $text:expr => $want:expr;)+) => {
        $(
            #[test]
            fn $name() -> Result<(), TestError> {
                check(stringify!($name), $text, $want)
            }
        )+
    };
}

cases! {
    // Success: a correct link passes, and an item rustdoc never builds or
    // never renders is not judged.
    success_the_real_sorted_shape_passes: r#"
/// Files the records; [`sorted`] orders them.
pub fn file() {}

/// Orders the members.
pub fn sorted() {}

#[cfg(test)]
mod rebuild_tests {
    fn sorted() {}
}
"# => clean(2, 1);
    success_a_link_to_a_public_fn_passes: r#"
/// Calls [`helper`].
pub fn run() {}

pub fn helper() {}
"# => clean(1, 1);
    success_a_link_to_a_public_struct_passes: r#"
/// Returns a [`Report`].
pub fn report() {}

/// The report.
pub struct Report;
"# => clean(2, 1);
    success_a_nested_pub_mod_links_its_own_public_item: r#"
pub mod inner {
    /// Uses [`Thing`].
    pub fn make() {}

    pub struct Thing;
}
"# => clean(1, 1);
    success_a_private_method_named_like_a_public_root_fn_passes: r#"
/// See [`sorted`].
pub fn file() {}

pub fn sorted() {}

struct Holder;

impl Holder {
    fn sorted(&self) {}
}
"# => clean(1, 1);
    success_a_method_name_is_not_a_name_of_its_module: r#"
/// See [`step`].
pub fn run() {}

struct Engine;

impl Engine {
    fn step(&self) {}
}
"# => clean(1, 1);
    success_attributes_between_cfg_test_and_mod_keep_it_test_only: r#"
/// Calls [`helper`].
pub fn run() {}

pub fn helper() {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    fn helper() {}
}
"# => clean(1, 1);
    success_cfg_all_test_and_a_feature_is_test_only: r#"
/// Calls [`helper`].
pub fn run() {}

pub fn helper() {}

#[cfg(all(test, feature = "native"))]
mod tests {
    /// Uses [`helper`].
    pub fn exercised() {}

    fn helper() {}
}
"# => clean(1, 1);
    success_documented_items_in_a_test_mod_are_not_judged: r#"
#[cfg(test)]
mod tests {
    /// Uses [`fixture`].
    pub fn case() {}

    fn fixture() {}
}
"# => clean(0, 0);
    success_a_private_name_of_a_nested_mod_is_not_a_root_name: r#"
/// See [`detail`].
pub fn run() {}

mod inner {
    fn detail() {}
}
"# => clean(1, 1);
    success_a_qualified_link_is_not_judged: r#"
/// See [`inner::detail`].
pub fn run() {}

fn detail() {}
"# => clean(1, 0);
    success_a_hidden_public_item_is_not_judged: r#"
/// Wraps [`compact`].
#[doc(hidden)]
pub fn compact_for_test() {}

fn compact() {}
"# => clean(0, 0);
    success_a_crate_visible_item_may_link_a_private_one: r#"
/// Uses [`helper`].
pub(crate) fn run() {}

fn helper() {}
"# => clean(0, 0);
    success_a_private_item_may_link_a_private_one: r#"
/// Uses [`helper`].
fn run() {}

fn helper() {}
"# => clean(0, 0);
    success_a_public_name_of_the_items_own_scope_shadows_a_private_root_name: r#"
fn build() {}

pub mod inner {
    /// Calls [`build`].
    pub fn run() {}

    pub fn build() {}
}
"# => clean(1, 1);
    success_an_empty_inline_mod_is_accepted: r#"
#[cfg(doctest)]
#[doc = include_str!("../docs/library.md")]
mod library_md_is_compiled {}

/// Calls [`helper`].
pub fn run() {}

pub fn helper() {}
"# => clean(1, 1);
    success_a_public_enum_const_type_and_trait_resolve: r#"
/// Takes a [`Mode`], a [`LIMIT`], an [`Alias`] and a [`Codec`].
pub fn run() {}

pub enum Mode {}

pub const LIMIT: u8 = 1;

pub type Alias = u8;

pub trait Codec {}
"# => clean(1, 4);
    success_an_out_of_line_mod_opens_no_scope: r#"
mod wire;

/// Calls [`helper`].
pub fn run() {}

pub fn helper() {}
"# => clean(1, 1);
    success_root_names_after_a_closed_mod_are_root_names: r#"
mod inner {
    fn helper() {}
}

/// Calls [`helper`].
pub fn run() {}

pub fn helper() {}
"# => clean(1, 1);
    success_one_public_declaration_of_a_name_is_enough: r#"
/// Calls [`open`].
pub fn run() {}

#[cfg(unix)]
pub fn open() {}

#[cfg(not(unix))]
fn open() {}
"# => clean(1, 1);

    // Failure: a public item that links an item rustdoc cannot reach from it
    // is still refused.
    failure_a_private_root_helper_is_refused: r#"
/// Calls [`helper`].
pub fn run() {}

fn helper() {}
"# => offends(1, 1, &[(1, "helper")]);
    failure_a_crate_visible_target_is_refused: r#"
/// Calls [`helper`].
pub fn run() {}

pub(crate) fn helper() {}
"# => offends(1, 1, &[(1, "helper")]);
    failure_a_super_visible_target_is_refused: r#"
/// Calls [`helper`].
pub fn run() {}

pub(super) fn helper() {}
"# => offends(1, 1, &[(1, "helper")]);
    failure_a_nested_pub_mods_private_item_linked_from_its_own_pub_item: r#"
pub mod inner {
    /// Uses [`secret`].
    pub fn run() {}

    fn secret() {}
}
"# => offends(1, 1, &[(2, "secret")]);
    failure_a_public_method_linking_a_private_root_fn_is_refused: r#"
pub struct Engine;

impl Engine {
    /// Calls [`step`].
    pub fn run(&self) {}
}

fn step() {}
"# => offends(1, 1, &[(4, "step")]);
    failure_a_private_struct_is_refused: r#"
/// Returns a [`Report`].
pub fn report() {}

struct Report;
"# => offends(1, 1, &[(1, "Report")]);
    failure_a_private_const_is_refused: r#"
/// Stops at [`LIMIT`].
pub fn run() {}

const LIMIT: u8 = 1;
"# => offends(1, 1, &[(1, "LIMIT")]);
    failure_only_the_private_one_of_two_links_is_refused: r#"
/// Calls [`open`] and [`close`].
pub fn run() {}

pub fn open() {}

fn close() {}
"# => offends(1, 2, &[(1, "close")]);
    failure_two_private_declarations_of_a_name_are_refused_once: r#"
/// Calls [`open`].
pub fn run() {}

#[cfg(unix)]
fn open() {}

#[cfg(not(unix))]
fn open() {}
"# => offends(1, 1, &[(1, "open")]);
    failure_a_root_item_after_a_test_mod_is_judged_again: r#"
#[cfg(test)]
mod tests {
    fn fixture() {}
}

/// Calls [`helper`].
pub fn run() {}

fn helper() {}
"# => offends(1, 1, &[(6, "helper")]);
    failure_a_feature_gated_mod_is_still_judged: r#"
#[cfg(feature = "hep")]
pub mod hep {
    /// Uses [`frame`].
    pub fn ingest() {}

    fn frame() {}
}
"# => offends(1, 1, &[(3, "frame")]);
    failure_private_async_and_unsafe_fns_are_refused: r#"
/// Calls [`fetch`] and [`poke`].
pub fn run() {}

async fn fetch() {}

unsafe fn poke() {}
"# => offends(1, 2, &[(1, "fetch"), (1, "poke")]);
    failure_a_public_item_of_a_private_mod_is_still_judged: r#"
mod inner {
    /// Uses [`secret`].
    pub fn run() {}

    fn secret() {}
}
"# => offends(1, 1, &[(2, "secret")]);
    failure_a_private_item_two_mods_deep_is_refused: r#"
pub mod outer {
    pub mod inner {
        /// Uses [`deep`].
        pub fn run() {}

        fn deep() {}
    }
}
"# => offends(1, 1, &[(3, "deep")]);
    failure_a_private_const_fn_is_refused: r#"
/// Sized by [`width`].
pub fn run() {}

const fn width() -> u8 {
    8
}
"# => offends(1, 1, &[(1, "width")]);
    failure_a_private_static_is_refused: r#"
/// Counts into [`COUNT`].
pub fn run() {}

static COUNT: u8 = 0;
"# => offends(1, 1, &[(1, "COUNT")]);
    failure_a_public_field_linking_a_private_root_fn_is_refused: r#"
pub struct Config {
    /// Set by [`load`].
    pub path: String,
}

fn load() {}
"# => offends(1, 1, &[(2, "load")]);
    failure_cfg_any_test_is_not_test_only: r#"
#[cfg(any(test, feature = "x"))]
mod support {
    /// Uses [`helper`].
    pub fn run() {}

    fn helper() {}
}
"# => offends(1, 1, &[(3, "helper")]);
    failure_cfg_not_test_is_judged: r#"
#[cfg(not(test))]
mod live {
    /// Uses [`helper`].
    pub fn run() {}

    fn helper() {}
}
"# => offends(1, 1, &[(3, "helper")]);
    failure_a_private_name_of_the_items_own_scope_beats_a_public_root_name: r#"
pub fn secret() {}

pub mod inner {
    /// Uses [`secret`].
    pub fn run() {}

    fn secret() {}
}
"# => offends(1, 1, &[(4, "secret")]);

    // Edge: the scope split refuses what it cannot read, names the `mod` line,
    // and reads the shapes rustfmt leaves around a module correctly.
    edge_a_one_line_mod_body_is_refused: r#"
/// Calls [`helper`].
pub fn run() {}

mod inner { fn helper() {} }
"# => refused(4, "same line");
    edge_a_macro_generated_mod_is_refused: r#"
macro_rules! make {
    ($name:ident) => {
        mod $name {
            fn helper() {}
        }
    };
}
"# => refused(3, "macro");
    edge_a_mod_that_never_closes_is_refused: r#"
mod inner {
    fn helper() {}
"# => refused(1, "closing");
    edge_a_closing_brace_at_another_indentation_is_refused: r#"
mod inner {
    fn helper() {}
  }

/// Calls [`helper`].
pub fn run() {}
"# => refused(1, "closing");
    edge_a_nested_mod_closing_at_another_indentation_is_refused: r#"
pub mod outer {
    mod inner {
        fn helper() {}
      }
}
"# => refused(2, "closing");
    edge_a_mod_without_a_space_before_its_brace_opens_a_scope: r#"
mod inner{
    fn helper() {}
}

/// Calls [`helper`].
pub fn run() {}

pub fn helper() {}
"# => clean(1, 1);
    edge_a_restricted_path_visibility_opens_a_scope: r#"
pub fn helper() {}

pub(in crate::app) mod inner {
    /// Uses [`helper`].
    pub fn run() {}

    fn helper() {}
}
"# => offends(1, 1, &[(4, "helper")]);
    edge_the_inside_of_a_test_mod_is_not_split: r#"
#[cfg(test)]
mod tests {
    mod one_line { fn x() {} }
}
"# => clean(0, 0);
    edge_a_blank_line_inside_a_mod_does_not_end_it: r#"
pub mod inner {
    /// Uses [`secret`].
    pub fn run() {}

    fn secret() {}

}
"# => offends(1, 1, &[(2, "secret")]);
    edge_empty_text_scans_nothing: "" => clean(0, 0);
    edge_a_commented_out_mod_is_not_an_opener: r#"
// mod inner {
/// Calls [`helper`].
pub fn run() {}

fn helper() {}
"# => offends(1, 1, &[(2, "helper")]);
    edge_a_doc_comment_between_cfg_test_and_mod_keeps_it_test_only: r#"
/// Calls [`helper`].
pub fn run() {}

pub fn helper() {}

#[cfg(test)]
/// Tests.
mod tests {
    fn helper() {}
}
"# => clean(1, 1);
    edge_an_identifier_starting_with_mod_is_not_an_opener: r#"
/// Calls [`helper`].
pub fn run() {
    let module = {
        1
    };
}

fn helper() {}
"# => offends(1, 1, &[(1, "helper")]);
    edge_a_closing_brace_followed_by_a_comment_closes_the_mod: r#"
mod inner {
    fn helper() {}
} // mod inner

/// Calls [`helper`].
pub fn run() {}

pub fn helper() {}
"# => clean(1, 1);
    edge_test_as_a_later_conjunct_of_all_is_test_only: r#"
#[cfg(all(unix, test))]
mod tests {
    /// Uses [`fixture`].
    pub fn case() {}

    fn fixture() {}
}
"# => clean(0, 0);
    edge_not_test_inside_all_is_not_test_only: r#"
#[cfg(all(unix, not(test)))]
mod live {
    /// Uses [`fixture`].
    pub fn case() {}

    fn fixture() {}
}
"# => offends(1, 1, &[(3, "fixture")]);
    edge_a_refusal_names_the_mod_line_not_the_file_start: r#"
/// Calls [`helper`].
pub fn run() {}

pub fn helper() {}

mod inner {
    fn helper() {}
"# => refused(6, "closing");
    edge_string_lines_at_column_0_inside_a_mod_do_not_close_it: r#"
#[cfg(test)]
mod tests {
    const SAMPLE: &str = "\
first line
}
last line";
    fn helper() {}
}

/// Calls [`helper`].
pub fn run() {}

fn helper() {}
"# => offends(1, 1, &[(10, "helper")]);
    edge_a_mod_line_inside_a_raw_string_is_not_an_opener: r##"
/// Calls [`helper`].
pub fn run() {}

pub fn helper() {}

const TEXT: &str = r#"
mod inner {
"#;
"## => clean(1, 1);
    edge_a_quote_inside_a_raw_string_does_not_end_it: r##"
pub fn helper() {}

mod inner {
    const S: &str = r#"a"
}
"#;
    /// Uses [`helper`].
    pub fn run() {}

    fn helper() {}
}
"## => offends(1, 1, &[(7, "helper")]);
    edge_a_block_comment_inside_a_mod_is_not_read: r#"
pub fn helper() {}

mod inner {
    /*
}
*/
    /// Uses [`helper`].
    pub fn run() {}

    fn helper() {}
}
"# => offends(1, 1, &[(7, "helper")]);
    edge_a_quote_in_a_char_literal_opens_no_string: r#"
mod inner {
    const Q: char = '"';
    fn f<'a>(x: &'a str) -> &'a str {
        x
    }
}

/// Calls [`helper`].
pub fn run() {}

fn helper() {}
"# => offends(1, 1, &[(8, "helper")]);
    edge_an_escaped_quote_does_not_end_a_string: r#"
mod inner {
    const S: &str = "a \" b
text at column 0";
}
"# => clean(0, 0);
    edge_a_test_mod_that_never_closes_is_refused: r#"
#[cfg(test)]
mod tests {
    fn helper() {}
"# => refused(2, "closing");
    // A module is an item a link can name. On #888 the public
    // `enable_sngrep_mode` linked the private file module `sngrep_mode`; this
    // gate passed it, and only `cargo doc` in the pre-push hook refused it.
    failure_a_link_to_a_private_file_module_offends: r#"
mod sngrep_mode;

/// See [`sngrep_mode`].
pub fn enable() {}
"# => offends(1, 1, &[(3, "sngrep_mode")]);
    failure_a_link_to_a_crate_visible_file_module_offends: r#"
pub(crate) mod sngrep_mode;

/// See [`sngrep_mode`].
pub fn enable() {}
"# => offends(1, 1, &[(3, "sngrep_mode")]);
    failure_a_link_to_a_private_inline_module_offends: r#"
/// See [`inner`].
pub fn run() {}

mod inner {
    pub fn f() {}
}
"# => offends(1, 1, &[(1, "inner")]);
    failure_a_link_to_a_pub_in_path_item_offends: r#"
/// See [`helper`].
pub fn run() {}

pub(in crate::tui) fn helper() {}
"# => offends(1, 1, &[(1, "helper")]);
    success_a_link_to_a_public_file_module_passes: r#"
pub mod sngrep_mode;

/// See [`sngrep_mode`].
pub fn enable() {}
"# => clean(1, 1);
    success_a_link_to_a_public_inline_module_passes: r#"
/// See [`inner`].
pub fn run() {}

pub mod inner {
    pub fn f() {}
}
"# => clean(1, 1);
    edge_a_module_of_a_nested_scope_is_not_a_root_name: r#"
/// See [`deep`].
pub fn run() {}

pub mod inner {
    mod deep;
}
"# => clean(1, 1);
    edge_a_pub_self_module_offends: r#"
pub(self) mod hidden;

/// See [`hidden`].
pub fn run() {}
"# => offends(1, 1, &[(3, "hidden")]);
}
