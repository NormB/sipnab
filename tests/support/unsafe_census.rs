// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The one `unsafe` census over `src/`: which blocks ship and which are test
//! code.
//!
//! Two gates publish this number: `tests/unsafe_census_test.rs` (the fault
//! model and the build page) and `tests/homepage_claim_truth_test.rs` (the
//! homepage, and through `readme_homepage_parity_test` the README). Each used
//! to carry its own walk, and the two walks disagreed about what a
//! `#[cfg(test)]` line means (one matched the whole trimmed line, the other a
//! prefix). Both shared two defects, found 2026-11-06:
//!
//! * A test-only module kept in its OWN file (`#[cfg(test)] pub mod x;` in
//!   `src/lib.rs`, with `src/x.rs`) was counted as shipped code, because the
//!   walk only knew how to skip a module written in place. That is why
//!   `src/lib.rs` carried `test_alloc` inline.
//! * After a `#[cfg(test)]` on an item with no braces (a `mod x;`, a `use`, a
//!   struct field, one statement), the walk stayed "in test" until some LATER
//!   brace group closed, so the shipped code after it vanished from the count.
//!
//! # The rule
//!
//! Code is test code when the compiler builds it only under `cfg(test)`:
//!
//! 1. an item whose attributes include `#[cfg(test)]` or
//!    `#[cfg(all(test, ...))]` (not `cfg(any(test, ...))`, whose other arm
//!    ships it). The item ends at its own end: the brace group it opens, or a
//!    `;` (or for a field, statement or arm, a `,`) outside any bracket;
//! 2. every line of a file whose module declaration is such an item, or that
//!    opens with `#![cfg(test)]`;
//! 3. every line of a file declared by a test-only file, transitively.
//!
//! A module file is found the way rustc finds it: `#[path = "..."]` relative
//! to the declaring file's directory, else `name.rs` or `name/mod.rs` beside
//! the declaring file when that file is `lib.rs`, `main.rs`, `mod.rs` or a
//! `src/bin/` root, and under a directory named for its stem otherwise.
//! Declarations inside an inline `mod a { mod b; }` are not resolved, and
//! one inside an inline test module is not marked; `src/` has neither.
//!
//! The walk is lexical, not a parse. A bracket inside a string literal or a
//! trailing comment in a skipped region unbalances it; that boundary is pinned
//! by `the_census_brace_walk_is_lexical_and_this_is_its_boundary`. Whole-line
//! `//` comments are not counted. Marking is per line: a line that holds both
//! the end of a test-only item and shipped code counts as test code.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

type TestError = Box<dyn std::error::Error>;

/// One `unsafe` census over `src/`.
///
/// # Arguments
/// * `root` — the `src/` directory to walk.
///
/// # Returns
/// `(raw_total, non_test_total, per_file_non_test)`. The raw total counts
/// every `unsafe {` in every `.rs` file, which is what
/// `grep -rc 'unsafe {' src/` gives a reader who checks by hand. The per-file
/// map is keyed by the path relative to `root`'s parent and lists only files
/// that hold a shipped block.
///
/// # Errors
/// A directory or `.rs` file under `root` that cannot be read, or a `root`
/// with no parent.
pub fn census(root: &Path) -> Result<(usize, usize, BTreeMap<String, usize>), TestError> {
    let base = root.parent().ok_or("src has a parent")?;
    let mut texts: BTreeMap<PathBuf, String> = BTreeMap::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(|e| format!("src/ is readable: {e}"))? {
            let path = entry.map_err(|e| format!("a readable entry: {e}"))?.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("a readable .rs file: {e}"))?;
            texts.insert(path, text);
        }
    }

    let scans: BTreeMap<&PathBuf, FileScan> = texts
        .iter()
        .map(|(path, text)| (path, scan(text)))
        .collect();
    let test_files = test_only_files(root, &scans);

    let mut raw = 0;
    let mut non_test = 0;
    let mut per_file: BTreeMap<String, usize> = BTreeMap::new();
    for (path, text) in &texts {
        let whole_file_is_test = test_files.contains(path);
        let mask = &scans[path].test_lines;
        let mut here = 0;
        for (i, line) in text.lines().enumerate() {
            let n = line.matches("unsafe {").count();
            raw += n;
            if !whole_file_is_test && !mask[i] && !line.trim_start().starts_with("//") {
                here += n;
            }
        }
        if here > 0 {
            non_test += here;
            per_file.insert(
                path.strip_prefix(base)
                    .map_err(|e| format!("under the repo root: {e}"))?
                    .display()
                    .to_string(),
                here,
            );
        }
    }
    Ok((raw, non_test, per_file))
}

/// An out-of-line module declaration (`mod name;`) found in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModDecl {
    /// The module's name.
    pub name: String,
    /// The `#[path = "..."]` value, when the declaration carries one.
    pub path: Option<String>,
    /// Whether the declaration itself is test-only.
    pub test_only: bool,
}

/// What one file's text says about its test-only parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileScan {
    /// One entry per line of the file: true where the line is test code.
    pub test_lines: Vec<bool>,
    /// Whether the file opens with `#![cfg(test)]`.
    pub inner_cfg_test: bool,
    /// Every out-of-line module the file declares.
    pub mods: Vec<ModDecl>,
}

/// Whether an attribute (the full `#[...]` text) compiles its item only
/// under `cfg(test)`.
///
/// # Arguments
/// * `attr` — one attribute, `#[` to `]`, over one line or several.
pub fn is_test_cfg(attr: &str) -> bool {
    let compact: String = attr.chars().filter(|c| !c.is_whitespace()).collect();
    compact == "#[cfg(test)]" || compact.starts_with("#[cfg(all(test,")
}

/// The `#[path = "..."]` value of an attribute, when it is one.
fn path_attr(attr: &str) -> Option<String> {
    let rest = attr
        .strip_prefix("#[path")?
        .trim_start()
        .strip_prefix('=')?;
    let rest = rest.trim_start().strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

/// How a guarded item ends, chosen from its first word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemShape {
    /// `fn`, `impl`, `mod`, `struct`...: ends where its first brace group
    /// closes, or at a `;` outside any bracket. A `,` does not end it, so the
    /// one in `impl<A, B>` or a `where` clause is stepped over.
    Braced,
    /// `let`, `const`, `static`, `use`, `type`: ends at a `;` outside any
    /// bracket.
    Statement,
    /// A field, struct-literal field, enum variant, match arm, macro call or
    /// expression: ends where its first brace group closes, or at a `;` or `,`
    /// outside any bracket.
    Listed,
}

/// The item's shape from its first word, after any `pub` or `pub(...)`.
///
/// # Arguments
/// * `item` — the item's text from its first character.
pub fn item_shape(item: &str) -> ItemShape {
    let mut words = item.trim_start();
    if let Some(rest) = words.strip_prefix("pub")
        && (rest.starts_with(' ') || rest.starts_with('('))
    {
        words = rest.trim_start();
        if words.starts_with('(') {
            words = words.find(')').map_or("", |i| &words[i + 1..]).trim_start();
        }
    }
    let first: String = words
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    match first.as_str() {
        "let" | "const" | "static" | "use" | "type" => ItemShape::Statement,
        "fn" | "impl" | "mod" | "struct" | "enum" | "trait" | "union" | "extern" | "unsafe"
        | "async" => ItemShape::Braced,
        _ => ItemShape::Listed,
    }
}

/// The module a `mod name;` item declares, when the item is one.
fn mod_decl_name(item: &str) -> Option<String> {
    let mut rest = item.trim();
    if let Some(r) = rest.strip_prefix("pub") {
        rest = r.trim_start();
        if rest.starts_with('(') {
            rest = rest[rest.find(')')? + 1..].trim_start();
        }
    }
    let name = rest.strip_prefix("mod ")?.trim().strip_suffix(';')?.trim();
    (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .then(|| name.to_string())
}

/// Where a guarded item ends, scanning from `(line, col)` across `lines`.
///
/// Returns the index of the item's last line.
fn item_end(lines: &[&str], start_line: usize, start_col: usize, shape: ItemShape) -> usize {
    // Brackets of all three kinds, so a `;` or `,` inside `[u8; 4]` or `f(a, b)`
    // is not taken for the item's end. Angle brackets are not tracked: `<` is
    // also a comparison. A `,` in a field's `HashMap<K, V>` ends the item on
    // that same line, which marks the same line.
    let mut depth: i64 = 0;
    for (i, line) in lines.iter().enumerate().skip(start_line) {
        let text = if i == start_line {
            &line[start_col..]
        } else {
            line
        };
        if text.trim_start().starts_with("//") {
            continue;
        }
        for c in text.chars() {
            match c {
                '{' | '(' | '[' => depth += 1,
                '}' | ')' | ']' => {
                    depth -= 1;
                    if depth < 0 || (c == '}' && depth == 0 && shape != ItemShape::Statement) {
                        return i;
                    }
                }
                ';' if depth == 0 => return i,
                ',' if depth == 0 && shape == ItemShape::Listed => return i,
                _ => {}
            }
        }
    }
    lines.len().saturating_sub(1)
}

/// Splits a line's leading attributes from the text after them.
///
/// Returns each complete `#[...]` on the line and the rest of the line, or
/// `None` for the rest when an attribute is still open at the line's end.
fn leading_attrs(line: &str) -> (Vec<String>, Option<&str>) {
    let mut attrs = Vec::new();
    let mut rest = line.trim_start();
    while rest.starts_with("#[") {
        let mut depth = 0i64;
        let mut end = None;
        for (i, c) in rest.char_indices() {
            match c {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else {
            attrs.push(rest.to_string());
            return (attrs, None);
        };
        attrs.push(rest[..=end].to_string());
        rest = rest[end + 1..].trim_start();
    }
    (attrs, Some(rest))
}

/// Scans one file: which lines are test code and which modules it declares.
///
/// # Arguments
/// * `text` — the whole contents of a Rust source file.
pub fn scan(text: &str) -> FileScan {
    let lines: Vec<&str> = text.lines().collect();
    let mut test_lines = vec![false; lines.len()];
    let mut mods = Vec::new();
    let inner_cfg_test = lines.iter().any(|l| {
        let t = l.trim_start();
        t.starts_with("#![") && is_test_cfg(&t.replacen("#![", "#[", 1))
    });

    // The attribute run being gathered for the next item.
    let mut run_test = false;
    let mut run_path: Option<String> = None;
    // An attribute that spans lines, gathered until its brackets close.
    let mut open_attr: Option<String> = None;

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();

        if let Some(mut acc) = open_attr.take() {
            acc.push(' ');
            acc.push_str(trimmed);
            let (attrs, rest) = leading_attrs(&acc);
            if rest.is_none() {
                open_attr = Some(acc);
                i += 1;
                continue;
            }
            for a in &attrs {
                run_test |= is_test_cfg(a);
                run_path = run_path.or_else(|| path_attr(a));
            }
            i += 1;
            continue;
        }

        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#![") {
            i += 1;
            continue;
        }

        let (attrs, rest) = if trimmed.starts_with("#[") {
            leading_attrs(trimmed)
        } else {
            (Vec::new(), Some(trimmed))
        };
        let Some(rest) = rest else {
            // An attribute continues on the next line.
            open_attr = attrs.last().cloned();
            for a in &attrs[..attrs.len() - 1] {
                run_test |= is_test_cfg(a);
                run_path = run_path.or_else(|| path_attr(a));
            }
            i += 1;
            continue;
        };
        for a in &attrs {
            run_test |= is_test_cfg(a);
            run_path = run_path.or_else(|| path_attr(a));
        }
        if rest.is_empty() || rest.starts_with("//") {
            i += 1;
            continue;
        }

        // `rest` starts an item on line `i`.
        let col = line.len() - rest.len();
        if let Some(name) = mod_decl_name(rest) {
            mods.push(ModDecl {
                name,
                path: run_path.clone(),
                test_only: run_test,
            });
        }
        if run_test {
            let end = item_end(&lines, i, col, item_shape(rest));
            for mark in &mut test_lines[i..=end] {
                *mark = true;
            }
            i = end + 1;
        } else {
            i += 1;
        }
        run_test = false;
        run_path = None;
    }
    FileScan {
        test_lines,
        inner_cfg_test,
        mods,
    }
}

/// The directory a file's `mod name;` declarations resolve under.
fn module_dir(root: &Path, file: &Path) -> PathBuf {
    let parent = file.parent().unwrap_or(root);
    let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let is_root = matches!(name, "lib.rs" | "main.rs" | "mod.rs") || parent == root.join("bin");
    if is_root {
        parent.to_path_buf()
    } else {
        let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        parent.join(stem)
    }
}

/// The file a declaration names, when that file exists in the census.
fn resolve(
    root: &Path,
    file: &Path,
    decl: &ModDecl,
    known: &BTreeMap<&PathBuf, FileScan>,
) -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = match &decl.path {
        Some(p) => vec![file.parent().unwrap_or(root).join(p)],
        None => {
            let dir = module_dir(root, file);
            vec![
                dir.join(format!("{}.rs", decl.name)),
                dir.join(&decl.name).join("mod.rs"),
            ]
        }
    };
    candidates.into_iter().find_map(|c| {
        let normal = normalize(&c);
        known
            .keys()
            .find(|k| normalize(k) == normal)
            .map(|k| (*k).clone())
    })
}

/// A path with `.` and `..` components folded, without touching the disk.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Every file compiled only under `cfg(test)`: rule 2 and rule 3 of the
/// module documentation, iterated until nothing more is added.
fn test_only_files(root: &Path, scans: &BTreeMap<&PathBuf, FileScan>) -> BTreeSet<PathBuf> {
    let mut test: BTreeSet<PathBuf> = scans
        .iter()
        .filter(|(_, s)| s.inner_cfg_test)
        .map(|(p, _)| (*p).clone())
        .collect();
    loop {
        let before = test.len();
        for (file, s) in scans {
            let file_is_test = test.contains(*file);
            for decl in &s.mods {
                if (decl.test_only || file_is_test)
                    && let Some(target) = resolve(root, file, decl, scans)
                {
                    test.insert(target);
                }
            }
        }
        if test.len() == before {
            return test;
        }
    }
}
