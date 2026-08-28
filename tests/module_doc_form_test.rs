// SPDX-License-Identifier: MIT OR Apache-2.0

//! A module documents itself in its own file, and nowhere else.
//!
//! Rust lets a file-backed module be documented twice: an inner `//!` header
//! inside the module's file, and an outer `///` comment on the `mod` line that
//! declares it. Both are accepted, and neither is reported.
//!
//! What actually happens was measured on a two-file crate rather than assumed.
//! rustdoc does not pick one and drop the other -- it CONCATENATES them, outer
//! first, and then resolves intra-doc links in the whole concatenated block
//! against the scope of the DECLARATION rather than the module. A link the
//! module's own header writes about the module's own items then resolves one
//! level up:
//!
//! ```text
//! warning: unresolved link to `THING`
//!   = note: no item named `THING` in scope
//! ```
//!
//! That is the loud half. The quiet half is worse: `[`super`]` written in a
//! submodule's header still resolves under the parent's scope, so it points at
//! the grandparent, produces no warning, and ships a link to the wrong page.
//! `src/capture/uprobe/bpf.rs` carried exactly that.
//!
//! The two halves also collide typographically. The inner summary line is glued
//! onto the outer block's last paragraph, so the module's own one-line summary
//! stops being a summary and the parent's index shows the outer's first line
//! instead.
//!
//! # The convention this pins
//!
//! Measured across `src/` when this gate was written: 213 file-backed module
//! declarations, 213 documented by an inner `//!` header, 0 documented only by
//! an outer `///`. The convention is not close, and `src/mcp/mod.rs` already
//! states it in a comment above `pub mod metrics;` -- written after that
//! module's own `[`MAX_TOOLS`]` stopped resolving.
//!
//! So the rule is one rule, and the fix it implies is one fix: move the prose
//! into the module file's `//!` header and delete the `///`.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The trees rustdoc renders, or would render. `tests/` is deliberately out:
/// integration tests are never documented, so a doc form there cannot produce
/// the defect this gate exists for.
const TREES: &[&str] = &["src", "crates", "harness", "benches", "fuzz", "examples"];

/// One `mod NAME;` declaration whose module file was found on disk.
#[derive(Debug)]
struct Decl {
    /// File holding the declaration, relative to the repo root.
    parent: String,
    /// 1-based line of the declaration.
    line: usize,
    /// Module file the declaration resolves to, relative to the repo root.
    module: String,
    /// The declaration carries an outer `///` doc comment.
    outer: bool,
    /// The module's own file opens with an inner `//!` header.
    inner: bool,
}

fn rs_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    for t in TREES {
        let dir = repo().join(t);
        if dir.is_dir() {
            walk(&dir, &mut out);
        }
    }
    out.sort();
    out
}

/// The module name in `mod NAME;`, or `None` for anything else.
///
/// Only the file-backed form matters. `mod NAME { .. }` writes its body inline,
/// has no second file to hold a `//!` header, and documenting it with `///` is
/// the only option there is.
fn declared_module(line: &str) -> Option<&str> {
    let mut t = line.trim();
    if let Some(after_pub) = t.strip_prefix("pub") {
        // `pub`, and the restricted forms `pub(crate)` / `pub(super)` /
        // `pub(in crate::path)`.
        let after_vis = match after_pub.strip_prefix('(') {
            Some(restriction) => restriction.split_once(')')?.1,
            None => after_pub,
        };
        if !after_vis.starts_with(char::is_whitespace) {
            return None;
        }
        t = after_vis.trim_start();
    }
    let name = t.strip_prefix("mod ")?.trim().strip_suffix(';')?.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    Some(name)
}

/// Where `mod NAME;` inside `parent` puts the module's file.
fn module_file(parent: &Path, name: &str) -> Option<PathBuf> {
    let dir = parent.parent()?;
    let stem = parent.file_stem()?.to_str()?;
    let bases = if matches!(stem, "mod" | "lib" | "main") {
        vec![dir.to_path_buf()]
    } else {
        vec![dir.join(stem)]
    };
    for base in bases {
        for cand in [
            base.join(format!("{name}.rs")),
            base.join(name).join("mod.rs"),
        ] {
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

/// Every file-backed `mod` declaration in [`TREES`], with both doc forms read.
///
/// The backward walk past attributes tracks bracket depth rather than assuming
/// one attribute per line: `#[cfg(all(\n    feature = "a",\n))]` would
/// otherwise stop the walk on its closing line and report "no outer doc" for a
/// declaration that has one -- a scanner that reads less than it claims, which
/// is the failure mode this whole gate is about.
fn declarations() -> Vec<Decl> {
    let root = repo();
    let mut out = Vec::new();

    for path in rs_files() {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();

        for (n, line) in lines.iter().enumerate() {
            let Some(name) = declared_module(line) else {
                continue;
            };
            let Some(mf) = module_file(&path, name) else {
                continue;
            };

            let mut outer = false;
            let mut depth: i32 = 0;
            let mut i = n;
            while i > 0 {
                i -= 1;
                let above = lines[i].trim();
                let open = above.matches('[').count() as i32;
                let close = above.matches(']').count() as i32;
                if depth > 0 {
                    depth -= close - open;
                    continue;
                }
                if above.starts_with("///") || above.starts_with("/**") {
                    outer = true;
                    break;
                }
                if above.starts_with("#[") || above.starts_with("#![") {
                    depth += close - open;
                    continue;
                }
                break;
            }

            // The header, not "anywhere in the file": a `//!` inside a nested
            // inline `mod tests { //! .. }` documents that module, not this one.
            let inner = std::fs::read_to_string(&mf)
                .unwrap_or_default()
                .lines()
                .take_while(|l| {
                    let t = l.trim();
                    t.is_empty() || t.starts_with("//") || t.starts_with("#![")
                })
                .any(|l| l.trim().starts_with("//!"));

            let rel = |p: &Path| {
                p.strip_prefix(&root)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .into_owned()
            };
            out.push(Decl {
                parent: rel(&path),
                line: n + 1,
                module: rel(&mf),
                outer,
                inner,
            });
        }
    }
    out
}

/// The scanner read a real tree.
///
/// A scanner that matches nothing agrees with every possible repository, so it
/// is asserted FIRST and on its own: without this, breaking [`declared_module`]
/// or [`module_file`] would turn the two gates below green rather than red.
/// 213 declarations resolved when this was written; the floor leaves room to
/// delete modules without inventing a reason to lower a gate.
#[test]
fn the_module_scanner_reads_a_real_tree() {
    let decls = declarations();
    assert!(
        decls.len() >= 150,
        "the module scanner resolved only {} file-backed `mod` declarations in \
         {TREES:?}. 213 resolved when this gate was written, so the extractor \
         has stopped matching declarations or stopped finding module files -- \
         either way the assertions below would now pass by examining nothing.",
        decls.len()
    );
    assert!(
        decls.iter().any(|d| d.parent == "src/lib.rs"),
        "the scanner resolved {} declarations but none from src/lib.rs, which \
         declares the crate's top-level modules. It is reading the wrong tree.",
        decls.len()
    );
}

/// No module is documented twice.
///
/// The effect, not the predicate: this reads what is on disk rather than
/// asserting that some list of known offenders is still the list.
#[test]
fn no_module_carries_both_an_inner_and_an_outer_doc() {
    let doubled: Vec<String> = declarations()
        .iter()
        .filter(|d| d.inner && d.outer)
        .map(|d| format!("{}:{} -> {}", d.parent, d.line, d.module))
        .collect();

    assert!(
        doubled.is_empty(),
        "{} module(s) carry BOTH an inner `//!` header in their own file and \
         an outer `///` comment on the `mod` line that declares them. rustdoc \
         concatenates the two and then resolves the module's own intra-doc \
         links in the PARENT scope, which breaks them loudly or -- for \
         `[`super`]` and friends -- silently retargets them one level up.\n\n\
         Fix: merge the outer prose into the module file's `//!` header and \
         delete the `///`.\n  {}",
        doubled.len(),
        doubled.join("\n  ")
    );
}

/// The convention is inner-only, so an outer doc on a `mod` line is the defect
/// whether or not the module file happens to have a header today.
///
/// Without this, deleting a module's `//!` header would "fix" the gate above
/// while leaving the documentation on the declaration -- the same split, one
/// half missing, and the next author to add a header re-creates the trap.
#[test]
fn a_mod_declaration_carries_no_outer_doc_comment() {
    let decls = declarations();
    let annotated: Vec<String> = decls
        .iter()
        .filter(|d| d.outer)
        .map(|d| {
            format!(
                "{}:{} -> {} ({})",
                d.parent,
                d.line,
                d.module,
                if d.inner {
                    "module file also has a `//!` header"
                } else {
                    "module file has no `//!` header of its own"
                }
            )
        })
        .collect();

    assert!(
        annotated.is_empty(),
        "{} `mod` declaration(s) carry an outer `///` doc comment. This crate \
         documents a file-backed module in that module's own file: {} of {} \
         declarations use the inner `//!` header and none used `///` alone \
         when this gate was written.\n\n\
         Fix: move the prose into the module file's `//!` header.\n  {}",
        annotated.len(),
        decls.iter().filter(|d| d.inner).count(),
        decls.len(),
        annotated.join("\n  ")
    );
}

/// Every file-backed module says what it is, in its own file.
///
/// The other side of the same rule. A module with neither form is undocumented
/// in rustdoc's index, and "it had a `///` that someone moved" is exactly how
/// that happens.
#[test]
fn every_file_backed_module_has_an_inner_header() {
    let decls = declarations();
    let bare: Vec<String> = decls
        .iter()
        .filter(|d| !d.inner)
        .map(|d| format!("{} (declared at {}:{})", d.module, d.parent, d.line))
        .collect();

    assert!(
        bare.is_empty(),
        "{} module file(s) open with no `//!` header, so rustdoc has nothing \
         to show for them in the parent's module index:\n  {}",
        bare.len(),
        bare.join("\n  ")
    );
}
