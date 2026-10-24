// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `docs/errors.md` holds one entry per message sipnab prints when a run is
//! refused or fails at startup, and the message literals in `src/` are the
//! single source of truth for that list.
//!
//! The scope is the fatal path a command-line user meets: `src/main.rs`,
//! `src/app/**`, `src/error.rs`, `src/cli.rs`, `src/config.rs` and
//! `src/settings.rs`. In those files every place that raises or prints a
//! message is a SITE:
//!
//! * `bail!`, `anyhow!`, `.context(…)`, `.with_context(|| …)` and
//!   `#[error(…)]`, which build an error value;
//! * `error!` and `warn!` (tracing) and `stderr_line!`, which print one;
//! * `PlanError::arg/new/refused(…)` and `PlanError { message: … }`, the
//!   startup planner's refusals, which `PlanError::exit` prints through
//!   `error!("{}", self.message)`;
//! * `Error::CliValidation(…)` and `Error::ConfigInvalid(…)`, the flag and
//!   configuration refusals of `Cli::validate` and the config validators;
//! * `Err(format!(…))`, the helpers that build a message as a `String` for a
//!   caller to print.
//!
//! A site whose message is a string literal (directly or as the first
//! argument of `format!`) contributes that literal, placeholders as written,
//! as a TEMPLATE. Every template must have an entry on the page, and every
//! entry must name a template, so a new message, a reworded one and a removed
//! one each turn this file red.
//!
//! A site whose message is not a literal (`error!("{e}")`, `PlanError::arg(msg)`)
//! cannot be read off the call. Each one is accounted for by hand in one of
//! two lists in [`LISTS`]: `resolved` when the text it prints is built by
//! sites this file already reads, and `unresolved` when it is not. Both lists
//! are checked in
//! both directions (no site missing, no entry stale), and the length of
//! `unresolved` is pinned exactly, so it can only shrink on purpose.

#[path = "support/source_scan.rs"]
mod source_scan;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The page this file holds to the source.
const PAGE: &str = "docs/errors.md";

/// The files whose messages the page lists, relative to the crate root.
const SCOPE_FILES: &[&str] = &[
    "src/main.rs",
    "src/error.rs",
    "src/cli.rs",
    "src/config.rs",
    "src/settings.rs",
];

/// Directories whose `.rs` files (recursively) are in scope.
const SCOPE_DIRS: &[&str] = &["src/app"];

// ---------------------------------------------------------------------------
// The extractor
// ---------------------------------------------------------------------------

/// What one byte of a source file is, for the purpose of finding calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Ordinary code.
    Code,
    /// Inside a `//` or `/* */` comment.
    Comment,
    /// Inside a string or character literal, delimiters included.
    Literal,
}

/// The kinds of site, each with the text that introduces it and which
/// argument (0-based) carries the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Bail,
    Anyhow,
    Context,
    WithContext,
    ErrorAttr,
    ErrorLog,
    WarnLog,
    StderrLine,
    PlanArg,
    PlanNew,
    PlanRefused,
    ErrFormat,
    CliValidation,
    ConfigInvalid,
    PlanStruct,
}

/// Every site kind and the text that opens it, up to and including the `(`
/// (or the `{` of a struct literal). An opening text that starts with a
/// letter must also start at an identifier boundary.
const KINDS: &[(Kind, &str)] = &[
    (Kind::Bail, "bail!("),
    (Kind::Anyhow, "anyhow!("),
    (Kind::Context, ".context("),
    (Kind::WithContext, ".with_context("),
    (Kind::ErrorAttr, "#[error("),
    (Kind::ErrorLog, "error!("),
    (Kind::WarnLog, "warn!("),
    (Kind::StderrLine, "stderr_line!("),
    (Kind::PlanArg, "PlanError::arg("),
    (Kind::PlanNew, "PlanError::new("),
    (Kind::PlanRefused, "PlanError::refused("),
    (Kind::ErrFormat, "Err(format!("),
    // The path is part of the opening text: a bare `CliValidation(String)`
    // or `ConfigInvalid(String)` is the variant declaration in src/error.rs.
    (Kind::CliValidation, "Error::CliValidation("),
    (Kind::ConfigInvalid, "Error::ConfigInvalid("),
    (Kind::PlanStruct, "PlanError {"),
];

/// One place in a source file that raises or prints a message.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    /// 1-based line of the opening text.
    line: usize,
    /// Which kind of site this is.
    kind: Kind,
    /// The whole call, whitespace collapsed: the key the hand-kept lists use.
    call: String,
    /// The message literal, placeholders as written, or `None` when the
    /// message is not a literal.
    template: Option<String>,
}

/// Classify every byte of `src` as code, comment or literal.
///
/// # Arguments
/// * `src` — Rust source text.
///
/// # Returns
/// One [`Class`] per byte of `src`.
fn classify(src: &str) -> Vec<Class> {
    let b = src.as_bytes();
    let mut out = vec![Class::Code; b.len()];
    let mut i = 0;
    let mark = |out: &mut Vec<Class>, from: usize, to: usize, c: Class| {
        for slot in &mut out[from..to.min(b.len())] {
            *slot = c;
        }
    };
    while i < b.len() {
        let rest = &b[i..];
        let prev_ident = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        if rest.starts_with(b"//") {
            let end = rest
                .iter()
                .position(|c| *c == b'\n')
                .map_or(b.len(), |n| i + n);
            mark(&mut out, i, end, Class::Comment);
            i = end;
        } else if rest.starts_with(b"/*") {
            // Block comments nest in Rust.
            let (mut depth, mut j) = (0usize, i);
            while j < b.len() {
                if b[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if b[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            mark(&mut out, i, j, Class::Comment);
            i = j;
        } else if let Some((open, hashes)) = raw_string_open(rest).filter(|_| !prev_ident) {
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            let body = i + open;
            let end = b[body..]
                .windows(close.len())
                .position(|w| w == close.as_slice())
                .map_or(b.len(), |n| body + n + close.len());
            mark(&mut out, i, end, Class::Literal);
            i = end;
        } else if b[i] == b'"' || (rest.starts_with(b"b\"") && !prev_ident) {
            let mut j = if b[i] == b'"' { i + 1 } else { i + 2 };
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(b.len());
            mark(&mut out, i, end, Class::Literal);
            i = end;
        } else if b[i] == b'\'' {
            // A character literal ('x', '\n', '\u{1F600}', 'é') or a
            // lifetime ('a, 'static), which is code.
            let len = if rest.get(1) == Some(&b'\\') {
                rest.iter().skip(2).position(|c| *c == b'\'').map(|n| n + 3)
            } else {
                src[i + 1..]
                    .chars()
                    .next()
                    .map(char::len_utf8)
                    .filter(|w| rest.get(1 + w) == Some(&b'\''))
                    .map(|w| w + 2)
            };
            match len {
                Some(n) => {
                    mark(&mut out, i, i + n, Class::Literal);
                    i += n;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    out
}

/// When `rest` opens a raw string (`r"`, `r#"`, `br##"` …), the length of the
/// opening and its number of `#`.
fn raw_string_open(rest: &[u8]) -> Option<(usize, usize)> {
    let after_b = rest.strip_prefix(b"b").unwrap_or(rest);
    let after_r = after_b.strip_prefix(b"r")?;
    let hashes = after_r.iter().take_while(|c| **c == b'#').count();
    (after_r.get(hashes) == Some(&b'"'))
        .then_some((rest.len() - after_r.len() + hashes + 1, hashes))
}

/// Every site in `src`, in source order.
///
/// Only the production part of the file is read (the test module is cut off
/// by [`source_scan::production_source`]), and an opening text inside a
/// comment or a literal is not a site.
///
/// # Arguments
/// * `src` — the whole text of one Rust source file.
///
/// # Returns
/// The sites, with their templates where the message is a literal.
fn extract_sites(src: &str) -> Vec<Site> {
    let src = source_scan::production_source(src);
    let class = classify(src);
    let b = src.as_bytes();
    let mut sites = Vec::new();
    for i in 0..b.len() {
        if class[i] != Class::Code {
            continue;
        }
        for (kind, open) in KINDS {
            let open = open.as_bytes();
            if !b[i..].starts_with(open)
                || class[i..i + open.len()].iter().any(|c| *c != Class::Code)
            {
                continue;
            }
            // `my_bail!(` and `log_error!(` are other macros.
            if open[0].is_ascii_alphabetic()
                && i > 0
                && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')
            {
                continue;
            }
            let paren = i + open.len() - 1;
            let Some(close) = matching_paren(b, &class, paren) else {
                continue;
            };
            // `Err(format!(` closes the `format!` call at `close`; the site's
            // message is that call's first argument either way.
            let args = top_level_args(src, &class, paren + 1, close);
            let field;
            let message = match kind {
                Kind::PlanStruct => {
                    // `PlanError { exit_code, message: … }`. A `PlanError {`
                    // with no `message` field is the type's declaration, an
                    // `impl` block or a return type, not a value.
                    let Some(value) = args.iter().find_map(|a| message_field(a)) else {
                        continue;
                    };
                    field = value;
                    field.as_deref()
                }
                Kind::PlanNew | Kind::PlanRefused => args.get(1).copied(),
                Kind::ErrorLog | Kind::WarnLog => args
                    .iter()
                    .copied()
                    .find(|a| literal_value(a.trim()).is_some()),
                Kind::WithContext => args
                    .first()
                    .map(|a| a.trim().strip_prefix("||").unwrap_or(a).trim_start()),
                _ => args.first().copied(),
            };
            let template = message
                .and_then(message_literal)
                .filter(|t| !placeholder_only(t));
            // The key starts at the macro or call name, without the `.`, `#[`
            // or `Err(` that introduced it.
            let name_at = match kind {
                Kind::Context | Kind::WithContext => i + 1,
                Kind::ErrorAttr => i + 2,
                _ => i,
            };
            let mut call = collapse(&src[name_at..=close]);
            if *kind == Kind::ErrFormat {
                // The opening text holds two `(`; `close` ends the inner one.
                call.push(')');
            }
            let line = src[..i].matches('\n').count() + 1;
            sites.push(Site {
                line,
                kind: *kind,
                call,
                template,
            });
        }
    }
    sites
}

/// When a struct-literal field is `message: <value>` or the shorthand
/// `message`, its value: `Some(Some(value))` and `Some(None)` respectively.
/// Comments inside the field are ignored.
fn message_field(field: &str) -> Option<Option<String>> {
    let class = classify(field);
    let code: String = field
        .char_indices()
        .filter(|(i, _)| class[*i] != Class::Comment)
        .map(|(_, c)| c)
        .collect();
    let code = code.trim();
    if code == "message" {
        return Some(None);
    }
    code.strip_prefix("message")
        .and_then(|rest| rest.trim_start().strip_prefix(':'))
        .map(|value| Some(value.trim().to_string()))
}

/// The index of the `)` that closes the `(` at `open`, skipping comments and
/// literals.
fn matching_paren(b: &[u8], class: &[Class], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for j in open..b.len() {
        if class[j] != Class::Code {
            continue;
        }
        match b[j] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => {}
        }
    }
    None
}

/// The top-level comma-separated arguments between `from` and `to`.
fn top_level_args<'a>(src: &'a str, class: &[Class], from: usize, to: usize) -> Vec<&'a str> {
    let b = src.as_bytes();
    let (mut depth, mut start, mut out) = (0usize, from, Vec::new());
    for j in from..to {
        if class[j] != Class::Code {
            continue;
        }
        match b[j] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            // A comma between `|a, b|` closure parameters splits an argument
            // here too. That can only move arguments AFTER the closure, and
            // the message argument comes before any closure in every kind.
            b',' if depth == 0 => {
                out.push(&src[start..j]);
                start = j + 1;
            }
            _ => {}
        }
    }
    if !src[start..to].trim().is_empty() {
        out.push(&src[start..to]);
    }
    out
}

/// The message literal an argument carries: a string literal, or the format
/// string of `format!(…)`, optionally followed by `.to_string()`, `.into()`
/// or `.to_owned()`.
fn message_literal(arg: &str) -> Option<String> {
    let arg = arg.trim();
    let arg = [".to_string()", ".into()", ".to_owned()"]
        .iter()
        .find_map(|s| arg.strip_suffix(s))
        .unwrap_or(arg)
        .trim();
    if let Some(v) = literal_value(arg) {
        return Some(v);
    }
    let inner = arg.strip_prefix("format!(")?.strip_suffix(')')?;
    let class = classify(inner);
    let first = top_level_args(inner, &class, 0, inner.len());
    literal_value(first.first()?.trim())
}

/// The value of `text` when it is exactly one string literal, escapes kept as
/// written except a line continuation, `\"` and `\\`.
fn literal_value(text: &str) -> Option<String> {
    if let Some((open, hashes)) = raw_string_open(text.as_bytes()) {
        let close = format!("\"{}", "#".repeat(hashes));
        return text
            .get(open..)?
            .strip_suffix(close.as_str())
            .map(str::to_string);
    }
    let body = text.strip_prefix('"')?.strip_suffix('"')?;
    let class = classify(text);
    if class.iter().any(|c| *c != Class::Literal) {
        // Two literals side by side, or a literal followed by code.
        return None;
    }
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\n') => {
                while chars.peek().is_some_and(|c| c.is_whitespace()) {
                    chars.next();
                }
            }
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('\'') => out.push('\''),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    Some(out)
}

/// Whether a template says nothing outside its placeholders: no letter
/// appears outside `{…}` (`{}`, `{e:#}`, `  {}`, `{refusal}.`), so it passes
/// text through rather than saying anything itself.
fn placeholder_only(template: &str) -> bool {
    let mut depth = 0;
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if depth == 0 && chars.peek() == Some(&'{') => {
                chars.next();
            }
            '{' => depth += 1,
            '}' if depth > 0 => depth -= 1,
            c if depth == 0 && c.is_alphabetic() => return false,
            _ => {}
        }
    }
    true
}

/// Every string literal in the production part of `src`, decoded as
/// [`literal_value`] decodes a message.
fn file_literals(src: &str) -> BTreeSet<String> {
    let src = source_scan::production_source(src);
    let class = classify(src);
    let mut out = BTreeSet::new();
    let mut i = 0;
    while i < class.len() {
        if class[i] != Class::Literal {
            i += 1;
            continue;
        }
        let end = class[i..]
            .iter()
            .position(|c| *c != Class::Literal)
            .map_or(class.len(), |n| i + n);
        if let Some(v) = literal_value(&src[i..end]) {
            out.insert(v);
        }
        i = end;
    }
    out
}

/// `text` with every run of whitespace replaced by one space.
fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------
// Reading the source tree and the page
// ---------------------------------------------------------------------------

/// The crate root.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every in-scope file, as a crate-relative path, sorted.
fn scope_files() -> Result<Vec<String>, TestError> {
    fn walk(dir: &Path, out: &mut Vec<String>) -> Result<(), TestError> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, out)?;
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path.strip_prefix(repo())?;
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
        Ok(())
    }
    let mut files: Vec<String> = SCOPE_FILES.iter().map(|f| (*f).to_string()).collect();
    for dir in SCOPE_DIRS {
        walk(&repo().join(dir), &mut files)?;
    }
    files.sort();
    Ok(files)
}

/// Every site in scope, keyed by file.
fn scope_sites() -> Result<BTreeMap<String, Vec<Site>>, TestError> {
    let mut out = BTreeMap::new();
    for file in scope_files()? {
        let text = std::fs::read_to_string(repo().join(&file))?;
        out.insert(file, extract_sites(&text));
    }
    Ok(out)
}

/// Every distinct template the scope prints, minus the informational lines,
/// with where each is raised: the literal sites, and the literals that
/// `resolved` entries carry.
fn required_templates(
    sites: &BTreeMap<String, Vec<Site>>,
    lists: &Lists,
) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for a in &lists.resolved {
        for t in &a.carries {
            out.entry(t.clone())
                .or_default()
                .push(format!("{} via `{}`", a.file, a.call));
        }
    }
    for (file, list) in sites {
        for site in list {
            if let Some(t) = &site.template
                && !lists.informational.contains(t)
            {
                out.entry(t.clone())
                    .or_default()
                    .push(format!("{file}:{}", site.line));
            }
        }
    }
    out
}

/// The templates the page has an entry for: every `### ` heading that is
/// exactly one code span.
///
/// # Arguments
/// * `page` — the markdown text of the page.
///
/// # Returns
/// The code span contents, in page order (duplicates kept so a test can
/// report them).
fn page_entries(page: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_fence = false;
    for line in page.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let Some(head) = line.strip_prefix("### ") else {
            continue;
        };
        if let Some(span) = single_code_span(head.trim_end()) {
            out.push(span);
        }
    }
    out
}

/// The content of `text` when it is exactly one markdown code span.
///
/// A span opened by N backticks closes at the next run of exactly N, and one
/// space is stripped from each end when both are present, which is how a
/// message containing a backtick is written (`` `` a `b` c `` ``).
fn single_code_span(text: &str) -> Option<String> {
    let ticks = text.bytes().take_while(|b| *b == b'`').count();
    if ticks == 0 {
        return None;
    }
    let fence = "`".repeat(ticks);
    let inner = text.get(ticks..)?.strip_suffix(fence.as_str())?;
    if inner.is_empty() || inner.ends_with('`') {
        return None;
    }
    // A run of exactly `ticks` backticks inside would have closed the span.
    let mut run = 0;
    for b in inner.bytes().chain(std::iter::once(b' ')) {
        if b == b'`' {
            run += 1;
        } else {
            if run == ticks {
                return None;
            }
            run = 0;
        }
    }
    let inner = match inner.strip_prefix(' ').and_then(|i| i.strip_suffix(' ')) {
        Some(stripped) if !stripped.trim().is_empty() => stripped,
        _ => inner,
    };
    Some(inner.to_string())
}

// ---------------------------------------------------------------------------
// The hand-kept lists
// ---------------------------------------------------------------------------

/// Where the hand-kept lists live.
///
/// A JSON file rather than constants here, because the lists quote message
/// text, and message text names flags (`--alert-exec`). `flag_coverage_test`
/// counts a flag named anywhere in a `tests/*.rs` file as tested, so the same
/// text in this file would mark flags as tested that no test runs.
const LISTS: &str = "tests/fixtures/error_reference_sites.json";

/// The hand-kept lists, as [`LISTS`] holds them.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Lists {
    /// Literal `stderr_line!` lines in scope that report a result rather
    /// than a failure (a summary, a count, a file written). They print to
    /// stderr so a pipe on stdout stays clean, not because anything went
    /// wrong, so the page does not list them.
    informational: Vec<String>,
    /// Non-literal sites whose text is built by sites this file already
    /// reads, or nearby from the literals they carry, so their messages are on
    /// the page.
    resolved: Vec<Accounted>,
    /// Non-literal sites whose text is not built by any site in scope.
    unresolved: Vec<Accounted>,
}

/// A non-literal site, keyed by its file and its whitespace-collapsed call.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Accounted {
    /// Crate-relative file.
    file: String,
    /// The call, whitespace collapsed, exactly as [`Site::call`] has it.
    call: String,
    /// How many sites in `file` have this exact call.
    count: usize,
    /// The message literals in `file` that this site prints, when its text is
    /// built nearby (`let msg = format!("…")` a few lines up) rather than at
    /// another site. Each must be a string literal in `file`'s production
    /// source, and each becomes a template the page must list.
    carries: Vec<String>,
    /// Where the text comes from, or why it cannot be listed.
    why: String,
}

/// Read [`LISTS`].
fn lists() -> Result<Lists, TestError> {
    let text = std::fs::read_to_string(repo().join(LISTS))?;
    Ok(serde_json::from_str(&text)?)
}

/// How many sites the `unresolved` list holds. Pinned with `==` so the list can only
/// change on purpose.
///
/// 74, measured when the page was written: 38 distinct calls, most of them
/// passing on the text of an error raised outside the scope (the capture,
/// security and TLS code, the operating system).
// 74 -> 76: merging the 0.5.213 batch. Added 4: src/app/bootstrap.rs 3
// (apply_read_config's copied config refusal, and unwritable_output_refusal's
// describe_output_error call and its context) and src/app/batch.rs 1 (the
// end-of-run vCon count, built by end_of_run_vcon_summary). Removed 2:
// src/app/bootstrap.rs's ws_portrange PlanError literal, now
// `PlanError::refused` in the resolved list, and one of the three
// `error!("{}", e.message)` sites.
// 76 -> 78: src/app/bootstrap.rs `PlanError::arg(e.to_string())` gained the
// inert --redact refusal (an `Error::CliValidation` literal in src/cli.rs),
// and `PlanError::arg(unknown_reference_message(...))`, whose text is built
// in src/sip/named_filters.rs, out of scope.
// 78 -> 79: src/app/bootstrap.rs `warn!("{msg}")` 8 -> 9, the call in
// warn_vcon_rules that prints VconRule::sealed_updates_warning.
// 79 -> 80: src/config.rs parse_sha256_fingerprint's
// `Err(format!("{text:?}: {WANT}"))`, whose text joins a const, for
// [vcon_fetch] signer_sha256.
// 80 -> 82: src/app/bootstrap.rs `PlanError { exit_code: 1, message:
// e.to_string(), }` 11 -> 12, the `[vcon_input]` validate() call in
// load_config, and `PlanError::refused(origin, problem)` 3 -> 4, the
// bootstrap::reader_keys refusal.
// 82 -> 83: src/app/bootstrap.rs `warn!("{notice}")` 1 -> 2, the
// live_rtp file notice in warn_live_rtp.
// 83 -> 84: src/app/bootstrap.rs `PlanError { exit_code: 1, message:
// e.to_string(), }` 12 -> 13, the `[hep]` validate() call in apply_config.
const EXPECTED_UNRESOLVED: usize = 84;

/// How many distinct templates the scope prints (informational lines
/// excluded). Pinned with `==` so a new or removed message is a decision.
///
/// 414, measured when the page was written, counting the literals that
/// `resolved` entries carry.
// 414 -> 419: merging the 0.5.213 batch. Added 8: src/app/vcon_spool.rs 4
// (`cannot read '{path}': {e}` and the three failure-record problems),
// src/app/bootstrap.rs 2 (`--vcon-spool-status: {e}` and its missing-feature
// refusal), src/cli.rs 2 (`Invalid --ws-portrange: {e}` and
// `[capture] ws_ports: {e}`, which replace the carried `{source}: {e}`).
// Removed 3: src/cli.rs `--mcp-transport must be 'stdio' or 'http', got '{}'`
// and src/app/servers.rs `unknown --mcp-transport '{other}', expected stdio
// or http` (the transport is an enum now), and the carried `{source}: {e}`.
// Reworded in place, no count change: the three `Failed to load` key-file
// messages (`{e}` -> `{e:#}`) and `Processing thread panicked: {}`.
// 419 -> 427: merging docs/doc-improvements into land/2026-10-12c, which
// carries feat/vcon-input, feat/whole-call-audio and the --since/--until
// window. src/app/bootstrap.rs 2 (`--cores` refusing a stored vCon, and the
// `--calls-only` internal error), src/config.rs 1 (`[limits]
// max_audio_bytes` below its minimum), src/app/queries/mod.rs 1 (a query
// answer that did not serialize), src/cli.rs 2 (the two `--since`/`--until`
// refusals, carried by `Error::CliValidation(refusal)`), src/app/batch.rs 2
// (the two empty-window notices, carried by `stderr_line!("{notice}")`).
// Nothing removed.
// 427 -> 450 (+23), the PBX vCon work: src/app/bootstrap.rs 12 (nine
// `[[vcon.rule]]` refusals carried by vcon_rules' refuse closure, the
// live-audio listener refusal, `[[vcon.enrich]]` with --redact, and `[pbx]
// addresses`), src/app/batch.rs 6 (the live compaction warning, the
// enrichment queue's drain warning, the per-service enrichment line, the
// write-after-enrichment failure, and the `audio` and `grouping` reasons),
// src/app/vcon_enrich.rs 5 (two name refusals and three outcome details).
// Nothing removed.
// 450 -> 451: src/app/batch.rs 1, the `sealed_updates` reason carried by
// vcon_rules' refuse closure. Nothing removed.
// 451 -> 452: src/config.rs `[display] view_filter_detail must be one of
// summary, full, got {m:?}`, the F7 filter summary's mode key.
// 466 -> 467: src/config.rs `[vcon_input] signer_sha256: {e}`, the vCon
// readers' signer fingerprint key. Nothing removed.
// 467 -> 469: src/config.rs `[vcon_forward] content_type: {e}` and
// `{value:?} is not one of {}` (forward_content_type, the rule
// --vcon-forward-content-type and the key share). Nothing removed.
// 469 -> 470: src/config.rs `[vcon] encrypt_to is an empty list: ...`,
// the refusal of an empty recipient list. Nothing removed.
// 470 -> 473: src/app/bootstrap.rs `--vcon-resign: {message}` and
// `--vcon-resign requires the 'vcon' feature (not compiled in)`, and
// src/app/vcon_resign.rs `'{}' is {len} bytes, over the {cap}-byte limit
// for one container`. Nothing removed.
// 473 -> 484: --vcon-audio-fetch. src/app/bootstrap.rs `--vcon-audio-fetch:
// {reason}` and `--vcon-audio-fetch requires the 'vcon' feature (not
// compiled in)`; src/app/vcon_audio_fetch.rs 6 (an output that exists, a
// non-sha512 content_hash, audio that is not WAV or Ogg, a JWE cty that is
// not the mediatype, a url with no local file name, a url that is not
// https); src/app/vcon_fetch.rs get_body 3 (`{url} answered {}`, the size
// limit, the short body). `--vcon-fetch-out '{}': not a directory` became
// `{flag} '{}': not a directory`, shared with --vcon-audio-fetch-out.
// 484 -> 486: src/app/bootstrap.rs `[[vcon.rule]] '{}' live_rtp = '{}' sends
// nothing in this run: ...` and src/app/batch.rs `live_rtp: {} datagram(s)
// could not be sent to their target`. Nothing removed.
// 486 -> 487: src/config.rs `[vcon] uuid_domain: {value:?} {why}`, the
// refusal of a value that is not a fully qualified host name. Nothing
// removed.
// 487 -> 501: src/app/g729_install.rs, the fourteen refusals of
// `sipnab g729 install`: no place to install, the package and table-file
// hash refusals, the importer's refusal, the four file errors, the download
// failure and its two answers, and the build without an HTTPS client.
// Nothing removed.
// 501 -> 500: the build without an HTTPS client is gone: every build with
// `g729` downloads with the shared client in src/app/https_client.rs.
// 500 -> 501: src/cli.rs, `--lint-fail-on` refuses a severity it does not
// know instead of reading it as no threshold. Nothing removed.
// 501 -> 502: src/app/bootstrap.rs, an offline --cores run started as root
// opens its whole set before dropping privileges and refuses a set that would
// not fit under the open-file limit (cores_fd_budget_refusal).
// 502 -> 504: src/app/https_client.rs, the URL refusals name the part of
// sipnab that reads the URL: the scheme and credential refusals became
// `{client} speaks ...` and `put credentials in {setting} ...`, and a URL read
// without credentials has its own refusal (+1). src/app/bootstrap.rs,
// `--uprobe-list --uprobe-library` names each path that is not a file (+1).
// 504 -> 505: src/app/bootstrap.rs, an offline --cores run that asks for no
// whole-capture view is refused (refuse_cores_without_a_view). Nothing removed.
// 505 -> 506: src/config.rs, `[hep] send_queue_mib` and `send_timeout_secs`
// are held to the ranges of `--hep-send-queue` and `--hep-send-timeout`
// (`[hep] {key} must be 1-{max}, got {v}`).
// 506 -> 507: src/app/bootstrap.rs, `-K/--kill-target` together with
// `--kill-scanner-detect-only` (or `[security] kill_scanner_detect_only`) is
// refused (kill_target_detect_only_refusal). The `--kill-ua` refusal was
// reworded to name detect-only; still one template. Nothing removed.
// 507 -> 508: src/app/bootstrap.rs refuses --multi-device with -I/--input when
// the run is planned, instead of the capture thread refusing it later.
// 508 -> 509: src/app/queries/b1.rs, `--timeline: {e}`, the store refusing a
// span of more than MAX_TIMELINE_BUCKETS intervals. Nothing removed.
const EXPECTED_TEMPLATES: usize = 509;

// ---------------------------------------------------------------------------
// The page gates
// ---------------------------------------------------------------------------

#[test]
fn every_fatal_error_message_has_an_entry() -> Result<(), TestError> {
    let sites = scope_sites()?;
    // A page that does not exist yet lists nothing, so every message is
    // reported missing rather than one "file not found".
    let page = std::fs::read_to_string(repo().join(PAGE)).unwrap_or_default();
    let entries: BTreeSet<String> = page_entries(&page).into_iter().collect();
    let missing: Vec<String> = required_templates(&sites, &lists()?)
        .into_iter()
        .filter(|(t, _)| !entries.contains(t))
        .map(|(t, at)| format!("`{t}`  (raised at {})", at.join(", ")))
        .collect();
    assert!(
        missing.is_empty(),
        "{} message(s) sipnab prints have no `### ` entry on {PAGE}. Add an \
         entry headed by the exact template in backticks, with what it means \
         and what to do:\n  {}",
        missing.len(),
        missing.join("\n  ")
    );
    Ok(())
}

#[test]
fn every_entry_names_a_message_the_source_still_prints() -> Result<(), TestError> {
    let sites = scope_sites()?;
    let page = std::fs::read_to_string(repo().join(PAGE))?;
    let required = required_templates(&sites, &lists()?);
    let entries = page_entries(&page);
    let mut seen = BTreeSet::new();
    let duplicated: Vec<&String> = entries.iter().filter(|e| !seen.insert(*e)).collect();
    assert!(
        duplicated.is_empty(),
        "{PAGE} has more than one entry for: {duplicated:?}"
    );
    let stale: Vec<&String> = entries
        .iter()
        .filter(|e| !required.contains_key(e.as_str()))
        .collect();
    assert!(
        stale.is_empty(),
        "{} entr(y/ies) on {PAGE} name a message no in-scope site prints. \
         The message was reworded or removed; update or delete the entry:\n  {}",
        stale.len(),
        stale
            .iter()
            .map(|s| format!("`{s}`"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
    Ok(())
}

#[test]
fn every_non_literal_site_is_accounted_for_exactly_once() -> Result<(), TestError> {
    let sites = scope_sites()?;
    // (file, call) -> how many non-literal sites have it.
    let mut found: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (file, list) in &sites {
        for site in list.iter().filter(|s| s.template.is_none()) {
            *found.entry((file.clone(), site.call.clone())).or_default() += 1;
        }
    }
    let mut listed: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut twice = Vec::new();
    let lists = lists()?;
    for a in lists.resolved.iter().chain(&lists.unresolved) {
        assert!(
            !a.why.trim().is_empty(),
            "{}: `{}` has no reason",
            a.file,
            a.call
        );
        let key = (a.file.clone(), a.call.clone());
        if listed.insert(key, a.count).is_some() {
            twice.push(format!("{}: `{}`", a.file, a.call));
        }
    }
    assert!(twice.is_empty(), "listed more than once: {twice:?}");
    let unlisted: Vec<String> = found
        .iter()
        .filter(|(k, n)| listed.get(*k) != Some(*n))
        .map(|((f, c), n)| {
            format!(
                "{f}: `{c}` x{n} (listed: {:?})",
                listed.get(&(f.clone(), c.clone()))
            )
        })
        .collect();
    assert!(
        unlisted.is_empty(),
        "{} non-literal site(s) are not in the resolved or unresolved list of \
         {LISTS} with their exact count. Say where each one's text comes from:\n  {}",
        unlisted.len(),
        unlisted.join("\n  ")
    );
    let stale: Vec<String> = listed
        .keys()
        .filter(|k| !found.contains_key(*k))
        .map(|(f, c)| format!("{f}: `{c}`"))
        .collect();
    assert!(
        stale.is_empty(),
        "{LISTS} names site(s) the source no longer has:\n  {}",
        stale.join("\n  ")
    );
    Ok(())
}

#[test]
fn every_carried_message_is_a_literal_in_its_file() -> Result<(), TestError> {
    let lists = lists()?;
    let mut wrong = Vec::new();
    for a in &lists.unresolved {
        assert!(
            a.carries.is_empty(),
            "unresolved {}: `{}` carries messages; a site whose text is known is resolved",
            a.file,
            a.call
        );
    }
    for a in &lists.resolved {
        let text = std::fs::read_to_string(repo().join(&a.file))?;
        let literals = file_literals(&text);
        for t in &a.carries {
            if !literals.contains(t) {
                wrong.push(format!("{}: `{t}`", a.file));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{LISTS} carries message(s) that are not a string literal in the file's \
         production source (reworded or removed?):\n  {}",
        wrong.join("\n  ")
    );
    Ok(())
}

#[test]
fn extractor_counts_are_pinned() -> Result<(), TestError> {
    let sites = scope_sites()?;
    let total: usize = sites.values().map(Vec::len).sum();
    assert!(
        total > 0,
        "the extractor read no sites in scope; every other test here would pass on nothing"
    );
    let templates = required_templates(&sites, &lists()?).len();
    assert!(
        templates == EXPECTED_TEMPLATES,
        "the scope prints {templates} distinct message template(s); \
         EXPECTED_TEMPLATES is {EXPECTED_TEMPLATES}. Re-measure and attribute the change"
    );
    let lists = lists()?;
    let unresolved: usize = lists.unresolved.iter().map(|a| a.count).sum();
    assert!(
        unresolved == EXPECTED_UNRESOLVED,
        "the unresolved list holds {unresolved} site(s); EXPECTED_UNRESOLVED is \
         {EXPECTED_UNRESOLVED}"
    );
    for t in &lists.informational {
        assert!(
            sites
                .values()
                .flatten()
                .any(|s| s.template.as_ref() == Some(t)),
            "the informational list names `{t}`, which no in-scope site prints"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The extractor on fixed inputs
// ---------------------------------------------------------------------------

/// The templates of `src`'s sites, `None` for a non-literal one.
fn templates_of(src: &str) -> Vec<Option<String>> {
    extract_sites(src).into_iter().map(|s| s.template).collect()
}

#[test]
fn extractor_reads_a_plain_literal_of_each_kind() {
    let src = r##"
fn f() -> anyhow::Result<()> {
    bail!("one {x}");
    let e = anyhow::anyhow!("two");
    x.context("three")?;
    x.with_context(|| format!("four {}", y))?;
    tracing::error!("five {path}");
    warn!(%e, "six");
    stderr_line!("seven");
    PlanError::arg(format!("eight {a}"));
    PlanError::new(1, "nine".to_string());
    PlanError::refused(origin, format!("ten"));
    return Err(format!("eleven {b}"));
    return Err(crate::Error::CliValidation(format!("thirteen {c}")));
    return Err(Error::ConfigInvalid("fifteen".into()));
    return Err(PlanError {
        exit_code: 1,
        message: format!("fourteen {d}"),
    });
}
pub struct PlanError {
    pub exit_code: i32,
    pub message: String,
}
fn g() -> PlanError {
    PlanError { exit_code: 2, message }
}
#[derive(thiserror::Error)]
enum E { #[error("twelve: {0}")] A(String), CliValidation(String), ConfigInvalid(String) }
"##;
    let got = templates_of(src);
    let want: Vec<Option<String>> = [
        "one {x}",
        "two",
        "three",
        "four {}",
        "five {path}",
        "six",
        "seven",
        "eight {a}",
        "nine",
        "ten",
        "eleven {b}",
        "thirteen {c}",
        "fifteen",
        "fourteen {d}",
    ]
    .iter()
    .map(|s| Some((*s).to_string()))
    .chain([None, Some("twelve: {0}".to_string())])
    .collect();
    assert_eq!(got, want);
    let kinds: Vec<Kind> = extract_sites(src).into_iter().map(|s| s.kind).collect();
    assert_eq!(
        kinds,
        vec![
            Kind::Bail,
            Kind::Anyhow,
            Kind::Context,
            Kind::WithContext,
            Kind::ErrorLog,
            Kind::WarnLog,
            Kind::StderrLine,
            Kind::PlanArg,
            Kind::PlanNew,
            Kind::PlanRefused,
            Kind::ErrFormat,
            Kind::CliValidation,
            Kind::ConfigInvalid,
            Kind::PlanStruct,
            Kind::PlanStruct,
            Kind::ErrorAttr,
        ]
    );
}

#[test]
fn extractor_joins_a_line_continuation() {
    let src = "fn f() {\n    bail!(\"first part \\\n           second part {x}\");\n}\n";
    assert_eq!(
        templates_of(src),
        vec![Some("first part second part {x}".to_string())]
    );
}

#[test]
fn extractor_reads_a_message_split_across_lines_with_named_args() {
    let src = r#"
fn f() {
    tracing::error!(
        "cannot open {path}: {err}",
        path = p.display(),
        err = e,
    );
    let _ = PlanError::arg(
        format!(
            "--flag {value} is out of range",
            value = v
        ),
    );
}
"#;
    assert_eq!(
        templates_of(src),
        vec![
            Some("cannot open {path}: {err}".to_string()),
            Some("--flag {value} is out of range".to_string()),
        ]
    );
    let sites = extract_sites(src);
    assert_eq!(
        sites[0].line, 3,
        "a site's line is where its opening text is"
    );
    assert_eq!(
        sites[0].call,
        r#"error!( "cannot open {path}: {err}", path = p.display(), err = e, )"#
    );
}

#[test]
fn extractor_reads_raw_strings_and_keeps_escapes_as_written() {
    let src = r####"
fn f() {
    bail!(r#"a "quoted" {name}"#);
    bail!("tab\tthen \"quote\" and {{braces}}\n");
}
"####;
    assert_eq!(
        templates_of(src),
        vec![
            Some(r#"a "quoted" {name}"#.to_string()),
            Some(r#"tab\tthen "quote" and {{braces}}\n"#.to_string()),
        ]
    );
}

#[test]
fn extractor_marks_a_non_literal_or_placeholder_only_message() {
    let src = r#"
fn f() {
    tracing::error!("{e}");
    tracing::error!("{}", self.message);
    stderr_line!("{e:#}");
    let _ = PlanError::arg(msg);
    bail!(reason);
    x.context(msg.clone())?;
    stderr_line!("{refusal}.");
    stderr_line!("  {}", f.hint);
}
"#;
    assert_eq!(
        templates_of(src),
        vec![None, None, None, None, None, None, None, None]
    );
    let calls: Vec<String> = extract_sites(src).into_iter().map(|s| s.call).collect();
    assert_eq!(calls[1], r#"error!("{}", self.message)"#);
    assert_eq!(calls[3], "PlanError::arg(msg)");
}

#[test]
fn extractor_ignores_comments_literals_and_the_test_module() {
    let src = r##"
// bail!("in a line comment");
/* error!("in a block comment /* nested */ still"); */
/// Doc: `bail!("in a doc comment")`.
fn f() {
    let s = "bail!(\"inside a string\")";
    let r = r#"warn!("inside a raw string")"#;
    let c = '(';
    let lt: &'static str = "x";
    my_bail!("not a site: identifier prefix");
    bail!("real");
}
#[cfg(test)]
mod tests {
    fn t() { bail!("in the test module"); }
}
"##;
    assert_eq!(templates_of(src), vec![Some("real".to_string())]);
}

#[test]
fn page_entries_read_only_headings_that_are_one_code_span() {
    let page = "\
# Error messages
### `config file not found: {path}`
### Not an entry
### `a` and `b`
```text
### `inside a fence`
```
### `` uses `ticks` here ``
";
    assert_eq!(
        page_entries(page),
        vec![
            "config file not found: {path}".to_string(),
            "uses `ticks` here".to_string(),
        ]
    );
}

#[test]
fn file_literals_reads_every_string_literal_of_the_production_source() {
    let src = r##"
// "in a comment"
fn f() {
    let msg = format!("built {here}");
    let other = r#"raw "one""#;
    let joined = "a \
                  b";
}
#[cfg(test)]
mod tests { const T: &str = "in the test module"; }
"##;
    let got = file_literals(src);
    let want: BTreeSet<String> = ["built {here}", r#"raw "one""#, "a b"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(got, want);
}
