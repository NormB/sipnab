// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The Rust style mandate's rules that no lint enforces.
//!
//! sipnab's Rust follows the Google Rust Style Guide, the Rust Style Guide and
//! the Rust API Guidelines (Norm, 2026-10-27). rustfmt and clippy enforce most
//! of them. This gate reads every tracked `.rs` file, `fuzz/` and `bpf/`
//! included because no clippy run builds those two, and refuses what neither
//! tool sees:
//!
//! * A glob import, except `use super::*` in an inline module, `use Enum::*`
//!   inside a body, and `pub use module::*` in a non-leaf module. Clippy's
//!   `wildcard_imports` exempts every glob in a test module and every
//!   `prelude::*`, and the guide allows neither.
//! * An `unsafe` block, `unsafe impl` or `unsafe extern` block without a
//!   `SAFETY:` comment directly above it or on its line.
//! * An `unsafe fn` or `unsafe trait` without a `# Safety` doc section.
//! * `#[rustfmt::skip]` without a `// rustfmt::skip: <reason>` comment. The
//!   guide allows it only for deliberate alignment and generated code.
//! * `catch_unwind` without a `// catch_unwind: <reason>` comment. The guide
//!   allows it only as defense in depth, never as the thing relied on.
//! * Reaching into a poisoned lock (`PoisonError::into_inner`).
//! * Code that runs before `main` (`#[ctor]`, `.init_array`), and unstable
//!   `#![feature]`s.
//!
//! A reason must be at least three words, so a marker cannot be a bare waiver.
//! Sites that predate the gate are listed in [`KNOWN`] by file and count, and
//! the list may only shrink: a file with more sites than listed fails, and one
//! with fewer fails until its entry is lowered, so a fixed site cannot be
//! silently re-spent.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

type TestError = Box<dyn std::error::Error>;

/// A rule this gate enforces, with the fix it asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Rule {
    GlobImport,
    UnsafeWithoutSafety,
    UnsafeFnWithoutSafetyDoc,
    RustfmtSkipWithoutReason,
    CatchUnwindWithoutReason,
    PoisonedLock,
    CodeBeforeMain,
    UnstableFeature,
    AssertWithoutMessage,
}

impl Rule {
    fn fix(self) -> &'static str {
        match self {
            Rule::GlobImport => {
                "name each import; only `use super::*` in an inline module, `use Enum::*` in a \
                 body and `pub use module::*` in a non-leaf module may glob"
            }
            Rule::UnsafeWithoutSafety => {
                "add a `// SAFETY:` comment directly above that says why the code is sound"
            }
            Rule::UnsafeFnWithoutSafetyDoc => {
                "add a `# Safety` doc section that states the caller's obligations"
            }
            Rule::RustfmtSkipWithoutReason => {
                "format the item, or say why above it: `// rustfmt::skip: <reason>` (alignment or \
                 generated code only)"
            }
            Rule::CatchUnwindWithoutReason => {
                "remove it, or say above it why it is defense in depth: `// catch_unwind: <reason>`"
            }
            Rule::PoisonedLock => {
                "do not reach into a poisoned lock; use a lock that does not poison \
                 (parking_lot) or let the panic propagate"
            }
            Rule::CodeBeforeMain => "do not run code before main; call it from main",
            Rule::UnstableFeature => "use stable Rust only",
            Rule::AssertWithoutMessage => {
                "add a message that says why the assertion holds or what failing it means, \
                 with the values that matter"
            }
        }
    }
}

/// Sites that predate the gate, one `rule<TAB>file<TAB>count` per line, read
/// from tests/rust_style_known.tsv. The list only shrinks.
const KNOWN_FILE: &str = "tests/rust_style_known.tsv";

impl Rule {
    const ALL: [Rule; 9] = [
        Rule::GlobImport,
        Rule::UnsafeWithoutSafety,
        Rule::UnsafeFnWithoutSafetyDoc,
        Rule::RustfmtSkipWithoutReason,
        Rule::CatchUnwindWithoutReason,
        Rule::PoisonedLock,
        Rule::CodeBeforeMain,
        Rule::UnstableFeature,
        Rule::AssertWithoutMessage,
    ];

    fn parse(name: &str) -> Option<Rule> {
        Rule::ALL.into_iter().find(|r| format!("{r:?}") == name)
    }
}

/// The known sites, from [`KNOWN_FILE`]'s text.
fn known(text: &str) -> Result<BTreeMap<(Rule, String), usize>, TestError> {
    let mut out = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        let (Some(rule), Some(file), Some(count), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(format!(
                "{KNOWN_FILE}:{}: want rule<TAB>file<TAB>count: {line:?}",
                n + 1
            )
            .into());
        };
        let rule = Rule::parse(rule).ok_or(format!("{KNOWN_FILE}:{}: no rule {rule:?}", n + 1))?;
        out.insert((rule, file.to_string()), count.parse()?);
    }
    Ok(out)
}

/// [`KNOWN_FILE`]'s text for the sites found now, for the failure message.
fn known_text(found: &BTreeMap<(Rule, String), Vec<usize>>) -> String {
    let mut text = String::from(
        "# Sites that predate tests/rust_style_test.rs. rule<TAB>file<TAB>count.\n\
         # Counts may only fall; the test prints this file's new text when one does.\n",
    );
    for ((rule, file), lines) in found {
        text.push_str(&format!("{rule:?}\t{file}\t{}\n", lines.len()));
    }
    text
}

/// One source file split into code and comments, line by line.
///
/// `code[i]` is line `i + 1` with every comment removed and the contents of
/// every string and character literal blanked to spaces (the quotes stay), so
/// a rule cannot match text that is only quoted or only mentioned in prose.
/// `comment[i]` is the comment text on that line, doc comments included.
struct Lexed {
    code: Vec<String>,
    comment: Vec<String>,
}

fn lex(src: &str) -> Lexed {
    let mut lexer = Lexer {
        chars: src.chars().collect(),
        at: 0,
        out: Lexed {
            code: vec![String::new()],
            comment: vec![String::new()],
        },
    };
    while lexer.at < lexer.chars.len() {
        let _ = lexer.line_comment()
            || lexer.block_comment()
            || lexer.raw_string()
            || lexer.string()
            || lexer.char_literal()
            || lexer.other();
    }
    lexer.out
}

/// The state of [`lex`]: the source, the read position and the output. Each
/// method consumes one token kind and says whether it found one there.
struct Lexer {
    chars: Vec<char>,
    at: usize,
    out: Lexed,
}

impl Lexer {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    /// Writes `c` to the current line of the code or the comment output,
    /// starting a new line of both at '\n'.
    fn put(&mut self, c: char, to_comment: bool) {
        if c == '\n' {
            self.out.code.push(String::new());
            self.out.comment.push(String::new());
            return;
        }
        let side = if to_comment {
            &mut self.out.comment
        } else {
            &mut self.out.code
        };
        if let Some(line) = side.last_mut() {
            line.push(c);
        }
    }

    /// Writes the literal character at the read position as a space, or as
    /// a newline when it is one, and advances.
    fn blank(&mut self) {
        let c = if self.peek(0) == Some('\n') {
            '\n'
        } else {
            ' '
        };
        self.put(c, false);
        self.at += 1;
    }

    fn after_ident(&self) -> bool {
        self.at > 0 && {
            let c = self.chars[self.at - 1];
            c.is_alphanumeric() || c == '_'
        }
    }

    fn line_comment(&mut self) -> bool {
        if !(self.peek(0) == Some('/') && self.peek(1) == Some('/')) {
            return false;
        }
        while let Some(c) = self.peek(0).filter(|&c| c != '\n') {
            self.put(c, true);
            self.at += 1;
        }
        true
    }

    fn block_comment(&mut self) -> bool {
        if !(self.peek(0) == Some('/') && self.peek(1) == Some('*')) {
            return false;
        }
        let mut depth = 0;
        while let Some(c) = self.peek(0) {
            let pair = (c, self.peek(1));
            let step = match pair {
                ('/', Some('*')) => {
                    depth += 1;
                    2
                }
                ('*', Some('/')) => {
                    depth -= 1;
                    2
                }
                _ => 1,
            };
            for k in 0..step {
                self.put(self.chars[self.at + k], true);
            }
            self.at += step;
            if depth == 0 {
                break;
            }
        }
        true
    }

    /// r"..", r#".."#, br"..", cr#".."#.
    fn raw_string(&mut self) -> bool {
        let c = self.peek(0);
        let prefix = match (c, self.peek(1)) {
            (Some('r'), _) => 1,
            (Some('b' | 'c'), Some('r')) => 2,
            _ => return false,
        };
        if self.after_ident() {
            return false;
        }
        let mut hashes = 0;
        while self.peek(prefix + hashes) == Some('#') {
            hashes += 1;
        }
        if self.peek(prefix + hashes) != Some('"') {
            return false;
        }
        for _ in 0..=prefix + hashes {
            self.put(self.chars[self.at], false);
            self.at += 1;
        }
        while self.peek(0).is_some() {
            let closes =
                self.peek(0) == Some('"') && (1..=hashes).all(|h| self.peek(h) == Some('#'));
            if closes {
                for _ in 0..=hashes {
                    self.put(self.chars[self.at], false);
                    self.at += 1;
                }
                break;
            }
            self.blank();
        }
        true
    }

    /// "..", b"..", c"..".
    fn string(&mut self) -> bool {
        let prefixed = matches!(self.peek(0), Some('b' | 'c'))
            && self.peek(1) == Some('"')
            && !self.after_ident();
        if !(self.peek(0) == Some('"') || prefixed) {
            return false;
        }
        if prefixed {
            self.put(self.chars[self.at], false);
            self.at += 1;
        }
        self.put('"', false);
        self.at += 1;
        while let Some(c) = self.peek(0).filter(|&c| c != '"') {
            if c == '\\' && self.peek(1).is_some() {
                self.blank();
            }
            self.blank();
        }
        if self.peek(0).is_some() {
            self.put('"', false);
            self.at += 1;
        }
        true
    }

    /// A character literal; a lifetime (`'a`) has no closing quote.
    fn char_literal(&mut self) -> bool {
        if self.peek(0) != Some('\'') {
            return false;
        }
        let close = if self.peek(1) == Some('\\') {
            (2..12).find(|&k| self.peek(k) == Some('\''))
        } else if self.peek(2) == Some('\'') {
            Some(2)
        } else {
            None
        };
        let Some(end) = close else {
            return false;
        };
        self.put('\'', false);
        for _ in 1..end {
            self.put(' ', false);
        }
        self.put('\'', false);
        self.at += end + 1;
        true
    }

    fn other(&mut self) -> bool {
        self.put(self.chars[self.at], false);
        self.at += 1;
        true
    }
}

/// Whether line `i` (0-based) holds only a comment, only an attribute, or
/// both: the lines that may sit between a justification and its code.
fn comment_or_attribute(lexed: &Lexed, i: usize) -> bool {
    let code = lexed.code[i].trim();
    (code.is_empty() && !lexed.comment[i].trim().is_empty())
        || code.starts_with("#[")
        || code.starts_with("#![")
}

/// The comment text that justifies the code on line `i` (0-based): the
/// comment on that line, and the run of comment and attribute lines directly
/// above it. When line `i` continues a statement begun on an earlier line,
/// the comments above that statement count too, as clippy reads them.
fn justification(lexed: &Lexed, i: usize) -> String {
    let mut text = lexed.comment[i].clone();
    let mut line = i;
    for _ in 0..12 {
        let mut k = line;
        while k > 0 && comment_or_attribute(lexed, k - 1) {
            k -= 1;
            text.push('\n');
            text.push_str(&lexed.comment[k]);
        }
        // Step to the previous code line when this one continues it.
        if k == 0 {
            break;
        }
        let above = lexed.code[k - 1].trim_end();
        let ends = above.is_empty()
            || above.ends_with(';')
            || above.ends_with('{')
            || above.ends_with('}')
            || above.ends_with(']');
        if ends || k != line {
            break;
        }
        line = k - 1;
        text.push('\n');
        text.push_str(&lexed.comment[line]);
    }
    text
}

/// Whether `text` holds `marker` followed by a reason of at least three words.
fn reasoned(text: &str, marker: &str) -> bool {
    text.match_indices(marker).any(|(at, _)| {
        let rest = &text[at + marker.len()..];
        let reason = rest.lines().next().unwrap_or_default();
        reason.split_whitespace().count() >= 3
    })
}

/// The doc comment directly above line `i` (0-based), attributes stepped over.
fn doc_above(lexed: &Lexed, i: usize) -> String {
    let mut text = String::new();
    let mut k = i;
    while k > 0 && comment_or_attribute(lexed, k - 1) {
        k -= 1;
        text.push_str(&lexed.comment[k]);
        text.push('\n');
    }
    text
}

/// Every position in `code` where the whole word `word` starts.
fn word_at(code: &str, word: &str) -> Vec<usize> {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices(word)
        .filter(|(at, _)| {
            !code[..*at].chars().next_back().is_some_and(ident)
                && !code[at + word.len()..].chars().next().is_some_and(ident)
        })
        .map(|(at, _)| at)
        .collect()
}

/// What follows an `unsafe` keyword.
#[derive(Debug, PartialEq)]
enum UnsafeKind {
    /// A block, an impl or an extern block: needs a `SAFETY:` comment.
    Code,
    /// A function or trait: needs a `# Safety` doc section.
    Contract,
    /// A type (`unsafe fn(..)`), an attribute (`unsafe(no_mangle)`) or a bound.
    Other,
}

/// Classifies the `unsafe` at byte `at` of `code`, reading on into the next
/// lines when the item continues there.
fn unsafe_kind(code: &[String], line: usize, at: usize) -> UnsafeKind {
    let mut rest = code[line][at + "unsafe".len()..].to_string();
    for more in code.iter().skip(line + 1).take(3) {
        rest.push(' ');
        rest.push_str(more);
    }
    let mut words = rest.trim_start();
    if words.starts_with('{') {
        return UnsafeKind::Code;
    }
    if words.starts_with("impl") {
        return UnsafeKind::Code;
    }
    if words.starts_with("trait") {
        return UnsafeKind::Contract;
    }
    if let Some(tail) = words.strip_prefix("extern") {
        let tail = tail.trim_start();
        // Skip the ABI string, already blanked to `"   "`.
        let tail = match tail.strip_prefix('"') {
            Some(abi) => abi.split_once('"').map_or("", |(_, t)| t).trim_start(),
            None => tail,
        };
        if tail.starts_with('{') {
            return UnsafeKind::Code;
        }
        words = tail;
    }
    if let Some(tail) = words.strip_prefix("fn") {
        // `unsafe fn(u8)` is a pointer type; `unsafe fn name(` is an item.
        return if tail.trim_start().starts_with('(') {
            UnsafeKind::Other
        } else {
            UnsafeKind::Contract
        };
    }
    UnsafeKind::Other
}

/// Whether a file is a non-leaf module: one that declares submodules in a
/// directory of its own (`mod.rs`, a crate root, or `foo.rs` beside `foo/`).
fn non_leaf(rel: &str, has_sibling_dir: bool) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    matches!(name, "mod.rs" | "lib.rs" | "main.rs") || has_sibling_dir
}

/// The glob imports on one line of code that the guide refuses.
fn refused_globs(code: &str, non_leaf: bool) -> usize {
    let trimmed = code.trim_start();
    let indented = trimmed.len() != code.len();
    let (public, rest) = match trimmed.strip_prefix("pub") {
        Some(after) => {
            let after = after.trim_start();
            let after = match after.strip_prefix('(') {
                Some(inner) => inner.split_once(')').map_or("", |(_, t)| t),
                None => after,
            };
            (true, after.trim_start())
        }
        None => (false, trimmed),
    };
    let Some(path) = rest.strip_prefix("use ") else {
        return 0;
    };
    // Each glob's path is the text before `::*` back to `use`, `{` or `,`.
    let mut refused = 0;
    for (at, _) in path.match_indices("::*") {
        let start = path[..at].rfind(['{', ',', ' ']).map_or(0, |p| p + 1);
        let prefix = path[..at].split_once('{').map_or("", |(p, _)| p);
        let full = format!("{prefix}{}", &path[start..at]);
        let last = full.rsplit("::").next().unwrap_or_default();
        let allowed = if public {
            non_leaf
        } else if full == "super" {
            indented
        } else {
            // `use Enum::*` inside a body: the last segment names a type.
            indented && last.chars().next().is_some_and(char::is_uppercase)
        };
        if !allowed {
            refused += 1;
        }
    }
    refused
}

/// Every violation in one file, as (rule, 1-based line).
fn scan(src: &str, non_leaf: bool) -> Vec<(Rule, usize)> {
    let lexed = lex(src);
    let mut found = Vec::new();
    for (i, code) in lexed.code.iter().enumerate() {
        for _ in 0..refused_globs(code, non_leaf) {
            found.push((Rule::GlobImport, i + 1));
        }
        for at in word_at(code, "unsafe") {
            match unsafe_kind(&lexed.code, i, at) {
                UnsafeKind::Code if !justification(&lexed, i).contains("SAFETY:") => {
                    found.push((Rule::UnsafeWithoutSafety, i + 1));
                }
                UnsafeKind::Contract if !doc_above(&lexed, i).contains("# Safety") => {
                    found.push((Rule::UnsafeFnWithoutSafetyDoc, i + 1));
                }
                _ => {}
            }
        }
        if code.contains("rustfmt::skip") && !reasoned(&justification(&lexed, i), "rustfmt::skip:")
        {
            found.push((Rule::RustfmtSkipWithoutReason, i + 1));
        }
        if !word_at(code, "catch_unwind").is_empty()
            && !code.trim_start().starts_with("use ")
            && !reasoned(&justification(&lexed, i), "catch_unwind:")
        {
            found.push((Rule::CatchUnwindWithoutReason, i + 1));
        }
        let poison = code.contains("PoisonError::into_inner")
            || (code.contains("unwrap_or_else(|") && code.contains(".into_inner())"));
        if poison {
            found.push((Rule::PoisonedLock, i + 1));
        }
        let before_main = code.contains("#[ctor")
            || code.contains("#[dtor")
            || (code.contains("link_section")
                && src
                    .lines()
                    .nth(i)
                    .is_some_and(|l| l.contains(".init_array")));
        if before_main {
            found.push((Rule::CodeBeforeMain, i + 1));
        }
        if code.trim_start().starts_with("#![feature(") {
            found.push((Rule::UnstableFeature, i + 1));
        }
    }
    for line in asserts_without_message(&lexed.code) {
        found.push((Rule::AssertWithoutMessage, line));
    }
    found.sort();
    found
}

/// The 1-based line of every `assert!`, `assert_eq!`, `assert_ne!` and
/// `debug_` form among them that carries no message argument.
///
/// Reads the code with strings blanked, so a comma inside a string is not an
/// argument. Arguments are split at the commas outside every bracket pair; a
/// turbofish with two type arguments at the top level of an assertion would
/// read as one argument too many, which errs toward passing.
fn asserts_without_message(code: &[String]) -> Vec<usize> {
    let text = code.join("\n");
    // Byte offset of each line's start, to turn a match into its line number.
    let starts: Vec<usize> = std::iter::once(0)
        .chain(text.match_indices('\n').map(|(at, _)| at + 1))
        .collect();
    let mut found = Vec::new();
    for name in [
        "assert",
        "assert_eq",
        "assert_ne",
        "debug_assert",
        "debug_assert_eq",
        "debug_assert_ne",
    ] {
        let needed = if name.ends_with("_eq") || name.ends_with("_ne") {
            2
        } else {
            1
        };
        for at in word_at(&text, name) {
            let rest = &text[at + name.len()..];
            let Some(args) = rest.strip_prefix('!').map(str::trim_start) else {
                continue;
            };
            if !args.starts_with(['(', '[', '{']) {
                continue;
            }
            if top_level_arguments(args) <= needed {
                found.push(starts.partition_point(|&start| start <= at));
            }
        }
    }
    found
}

/// How many non-empty comma-separated arguments the bracketed group at the
/// start of `args` holds.
fn top_level_arguments(args: &str) -> usize {
    let mut depth = 0usize;
    let mut count = 0;
    let mut current = false;
    for c in args.chars() {
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                if depth == 1 {
                    continue;
                }
            }
            ')' | ']' | '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            ',' if depth == 1 => {
                count += usize::from(current);
                current = false;
                continue;
            }
            _ => {}
        }
        if depth >= 1 && !c.is_whitespace() {
            current = true;
        }
    }
    count + usize::from(current)
}

/// Every violation in the tree, grouped by (rule, file).
fn tree() -> Result<BTreeMap<(Rule, String), Vec<usize>>, TestError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("git")
        .args(["ls-files", "-z", "--", "*.rs"])
        .current_dir(root)
        .output()?;
    assert!(out.status.success(), "git ls-files failed: {out:?}");
    let mut found: BTreeMap<(Rule, String), Vec<usize>> = BTreeMap::new();
    let mut files = 0;
    for rel in String::from_utf8(out.stdout)?.split('\0') {
        let path = root.join(rel);
        // A symlink (bpf/sipnab-bpf-types) is read through its target's name.
        if rel.is_empty() || path.is_symlink() || !path.is_file() {
            continue;
        }
        files += 1;
        let src = std::fs::read_to_string(&path)?;
        let sibling = path.with_extension("");
        for (rule, line) in scan(&src, non_leaf(rel, sibling.is_dir())) {
            found.entry((rule, rel.to_string())).or_default().push(line);
        }
    }
    assert!(
        files >= 900,
        "read only {files} source files; the scan lost its input"
    );
    Ok(found)
}

#[test]
fn the_tree_follows_the_rules_no_lint_sees() -> Result<(), TestError> {
    let found = tree()?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let known = known(&std::fs::read_to_string(root.join(KNOWN_FILE))?)?;
    let mut problems = Vec::new();
    for ((rule, file), lines) in &found {
        let allowed = known.get(&(*rule, file.clone())).copied().unwrap_or(0);
        if lines.len() > allowed {
            let at: Vec<String> = lines.iter().map(|l| format!("{file}:{l}")).collect();
            problems.push(format!(
                "{rule:?}: {} site(s), {allowed} known: {}\n    fix: {}",
                lines.len(),
                at.join(" "),
                rule.fix()
            ));
        }
    }
    let mut fell = false;
    for ((rule, file), &n) in &known {
        let now = found.get(&(*rule, file.clone())).map_or(0, Vec::len);
        if now < n {
            fell = true;
            problems.push(format!(
                "{rule:?} in {file}: {now} site(s) now, {n} known; lower its entry in {KNOWN_FILE}"
            ));
        }
    }
    let rewrite = if fell && problems.iter().all(|p| p.contains(KNOWN_FILE)) {
        format!("\n\nNew text for {KNOWN_FILE}:\n{}", known_text(&found))
    } else {
        String::new()
    };
    assert!(
        problems.is_empty(),
        "{} problem(s):\n  {}{rewrite}",
        problems.len(),
        problems.join("\n  ")
    );
    Ok(())
}

// ---- The scanner's own rules, each driven both ways. ----

#[test]
fn glob_rules() {
    let refused = |src: &str, nl: bool| -> usize {
        scan(src, nl)
            .iter()
            .filter(|(r, _)| *r == Rule::GlobImport)
            .count()
    };
    assert_eq!(
        refused("mod t {\n    use super::*;\n}\n", false),
        0,
        "use super::* inline"
    );
    assert_eq!(
        refused("use super::*;\n", false),
        1,
        "use super::* at file scope"
    );
    assert_eq!(
        refused("mod t {\n    use super::super::*;\n}\n", false),
        1,
        "super::super"
    );
    assert_eq!(
        refused("fn f() {\n    use Kind::*;\n}\n", false),
        0,
        "enum glob in a body"
    );
    assert_eq!(
        refused("use Kind::*;\n", false),
        1,
        "enum glob at file scope"
    );
    assert_eq!(
        refused("pub use state::*;\n", true),
        0,
        "pub use in a non-leaf module"
    );
    assert_eq!(
        refused("pub(crate) use state::*;\n", false),
        1,
        "pub use in a leaf module"
    );
    assert_eq!(refused("use proptest::prelude::*;\n", false), 1, "prelude");
    assert_eq!(
        refused("    use crate::a::helpers::*;\n", false),
        1,
        "module glob in a test"
    );
    assert_eq!(
        refused("use std::{fs, io::*};\n", false),
        1,
        "glob inside braces"
    );
    assert_eq!(
        refused("let s = \"use x::*;\";\n// use y::*;\n", false),
        0,
        "quoted, commented"
    );
}

#[test]
fn unsafe_rules() {
    let rules = |src: &str| -> Vec<Rule> { scan(src, false).into_iter().map(|(r, _)| r).collect() };
    let block = "fn f() {\n    // SAFETY: the pointer is valid here.\n    unsafe { g() }\n}\n";
    assert!(
        rules(block).is_empty(),
        "a justified block: {:?}",
        rules(block)
    );
    let bare = "fn f() {\n    unsafe { g() }\n}\n";
    assert_eq!(
        rules(bare),
        [Rule::UnsafeWithoutSafety],
        "an unjustified block"
    );
    let let_block =
        "fn f() {\n    // SAFETY: sound.\n    let x = unsafe {\n        g()\n    };\n}\n";
    assert!(
        rules(let_block).is_empty(),
        "a let-bound block: {:?}",
        rules(let_block)
    );
    let cont =
        "fn f() {\n    // SAFETY: sound.\n    if let Some(x) =\n        unsafe { g() } {}\n}\n";
    assert!(
        rules(cont).is_empty(),
        "a continued statement: {:?}",
        rules(cont)
    );
    let attr = "// SAFETY: plain old data.\n#[cfg(x)]\nunsafe impl Pod for T {}\n";
    assert!(
        rules(attr).is_empty(),
        "attribute between: {:?}",
        rules(attr)
    );
    assert_eq!(
        rules("unsafe impl Pod for T {}\n"),
        [Rule::UnsafeWithoutSafety],
        "bare impl"
    );
    assert_eq!(
        rules("unsafe extern \"C\" {\n    fn f();\n}\n"),
        [Rule::UnsafeWithoutSafety],
        "a bare extern block"
    );
    let doc = concat!(
        "/// Does it.\n///\n/// # Safety\n///\n/// `p` is valid.\n",
        "pub unsafe fn f(p: *const u8) {}\n",
    );
    assert!(
        rules(doc).is_empty(),
        "a documented unsafe fn: {:?}",
        rules(doc)
    );
    assert_eq!(
        rules("pub unsafe extern \"C\" fn f() {}\n"),
        [Rule::UnsafeFnWithoutSafetyDoc],
        "an undocumented unsafe extern fn"
    );
    assert_eq!(
        rules("unsafe trait T {}\n"),
        [Rule::UnsafeFnWithoutSafetyDoc],
        "unsafe trait"
    );
    let types = "type F = unsafe extern \"C\" fn(u8);\n#[unsafe(no_mangle)]\nfn g() {}\n";
    assert!(
        rules(types).is_empty(),
        "a pointer type and an attribute: {:?}",
        rules(types)
    );
    let quoted = "let s = \"unsafe { x }\";\n// unsafe { y }\n";
    assert!(
        rules(quoted).is_empty(),
        "quoted and commented: {:?}",
        rules(quoted)
    );
}

#[test]
fn marker_rules() {
    let rules = |src: &str| -> Vec<Rule> { scan(src, false).into_iter().map(|(r, _)| r).collect() };
    let skip = concat!(
        "// rustfmt::skip: a matrix aligned by column.\n",
        "#[rustfmt::skip]\nconst M: [u8; 2] = [1, 2];\n",
    );
    assert!(rules(skip).is_empty(), "a reasoned skip: {:?}", rules(skip));
    let terse = "// rustfmt::skip: aligned\n#[rustfmt::skip]\nconst M: u8 = 1;\n";
    assert_eq!(
        rules(terse),
        [Rule::RustfmtSkipWithoutReason],
        "a one-word reason"
    );
    assert_eq!(
        rules("#[rustfmt::skip]\nconst M: u8 = 1;\n"),
        [Rule::RustfmtSkipWithoutReason],
        "no reason"
    );
    let caught = concat!(
        "fn f() {\n    // catch_unwind: defense in depth for one input.\n",
        "    let r = std::panic::catch_unwind(g);\n}\n",
    );
    assert!(
        rules(caught).is_empty(),
        "a reasoned catch_unwind: {:?}",
        rules(caught)
    );
    assert_eq!(
        rules("fn f() {\n    let r = catch_unwind(g);\n}\n"),
        [Rule::CatchUnwindWithoutReason],
        "a bare catch_unwind"
    );
    assert!(
        rules("use std::panic::catch_unwind;\n").is_empty(),
        "importing it is not using it"
    );
}

#[test]
fn lock_and_startup_rules() {
    let rules = |src: &str| -> Vec<Rule> { scan(src, false).into_iter().map(|(r, _)| r).collect() };
    assert_eq!(
        rules("let g = m.lock().unwrap_or_else(|e| e.into_inner());\n"),
        [Rule::PoisonedLock],
        "a closure into a poisoned guard"
    );
    assert_eq!(
        rules("let g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);\n"),
        [Rule::PoisonedLock],
        "a path into a poisoned guard"
    );
    assert!(
        rules("let v = cursor.into_inner();\n").is_empty(),
        "other into_inner calls"
    );
    assert_eq!(
        rules("#[ctor::ctor]\nfn init() {}\n"),
        [Rule::CodeBeforeMain],
        "#[ctor::ctor]"
    );
    assert_eq!(
        rules("#[ctor]\nfn init() {}\n"),
        [Rule::CodeBeforeMain],
        "#[ctor]"
    );
    let section = "#[unsafe(link_section = \".init_array\")]\nstatic F: fn() = init;\n";
    assert_eq!(rules(section), [Rule::CodeBeforeMain], ".init_array");
    assert_eq!(
        rules("#![feature(never_type)]\n"),
        [Rule::UnstableFeature],
        "a feature gate"
    );
}

#[test]
fn assert_rules() {
    let lines = |src: &str| -> Vec<usize> {
        scan(src, false)
            .into_iter()
            .filter(|(r, _)| *r == Rule::AssertWithoutMessage)
            .map(|(_, l)| l)
            .collect()
    };
    assert_eq!(lines("assert!(a);\n"), [1], "a bare assert!");
    assert!(
        lines("assert!(a, \"why it holds\");\n").is_empty(),
        "assert! with a message"
    );
    assert_eq!(lines("assert_eq!(a, b);\n"), [1], "a bare assert_eq!");
    assert!(
        lines("assert_eq!(a, b, \"why\");\n").is_empty(),
        "assert_eq! with a message"
    );
    assert_eq!(
        lines("debug_assert_ne!(f(x, y), b,);\n"),
        [1],
        "a trailing comma is no message"
    );
    assert_eq!(
        lines("x();\nassert!(\n    v.iter().all(|(a, b)| a < b)\n);\n"),
        [2],
        "commas inside brackets are not arguments; the line is where the macro starts"
    );
    assert!(
        lines("assert!(a, \"{}\", b);\n").is_empty(),
        "a formatted message"
    );
    assert!(
        lines("let s = \"assert!(a)\";\n// assert!(b)\n").is_empty(),
        "quoted, commented"
    );
    assert!(
        lines("my_assert!(a);\nassert_matches(a);\n").is_empty(),
        "other names"
    );
}

#[test]
fn the_known_list_parses_and_prints_its_own_format() -> Result<(), TestError> {
    let text = "# comment\nGlobImport\tsrc/a.rs\t2\n\nPoisonedLock\tsrc/b.rs\t1\n";
    let parsed = known(text)?;
    assert_eq!(parsed.len(), 2, "two entries in {text:?}");
    assert_eq!(
        parsed.get(&(Rule::GlobImport, "src/a.rs".to_string())),
        Some(&2),
        "{parsed:?}"
    );
    assert!(
        known("NoSuchRule\tsrc/a.rs\t1\n").is_err(),
        "an unknown rule is refused"
    );
    assert!(
        known("GlobImport\tsrc/a.rs\n").is_err(),
        "a short line is refused"
    );
    let found: BTreeMap<(Rule, String), Vec<usize>> =
        [((Rule::GlobImport, "src/a.rs".to_string()), vec![3, 9])]
            .into_iter()
            .collect();
    let round = known(&known_text(&found))?;
    assert_eq!(
        round.get(&(Rule::GlobImport, "src/a.rs".to_string())),
        Some(&2),
        "{round:?}"
    );
    Ok(())
}
