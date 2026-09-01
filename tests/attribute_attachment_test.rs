// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an insert steals from the item it lands above.
//!
//! In Rust, an outer attribute and a `///` block bind FORWARD, to whatever item
//! comes next. Nothing binds them to the item they were written for. So an
//! insert placed immediately before an existing item does not sit beside that
//! item's attributes and docs -- it takes them, and both halves still compile.
//! Four instances, all in this repository, all mine:
//!
//! 1. **A type alias above `AlertEngine`** took its doc comment. The alias was
//!    documented by prose about an engine; the engine was documented by
//!    whatever drifted up behind it.
//! 2. **`is_ng_over_hep` in `src/rtpengine/mod.rs`.** A `#[must_use]` ended up
//!    BETWEEN the summary line and the body of its own doc comment. rustdoc
//!    then rendered a body paragraph as the function's one-line summary, and
//!    clippy failed on the blank line the split left behind.
//! 3. **The same function again**, while repairing instance 2.
//! 4. **`src/lib.rs`.** `pub mod relay;` was inserted between
//!    `#[cfg(not(target_arch = "wasm32"))]` and `pub mod rtpengine;`. The
//!    `#[cfg]` moved to `relay`, and so did the five-line comment above it --
//!    a comment whose subject is `rtpengine`'s dependency on `pipeline`.
//!    `rtpengine` was left ungated and compiled for wasm32 for the first time,
//!    where `crate::pipeline` does not exist. Reintroducing the insert on
//!    2026-08-31 and running the gate's own command produced five errors --
//!    three E0433 for `crate::relay` and `crate::pipeline`, and two E0220 that
//!    follow from the import those took down -- none of them visible to
//!    `cargo test`, `cargo clippy`, or any host-target build. The pre-push
//!    wasm gate found it, minutes before a push.
//!
//! # The class
//!
//! **An edit that changes no line can change what every line above it means.**
//! Instances 1-3 move a description onto the wrong item, which is a
//! documentation defect and a rustdoc rendering defect. Instance 4 moves a
//! COMPILATION CONDITION onto the wrong item, which is a build defect on a
//! target this machine never builds. All four survive the compiler because
//! nothing they produce is ill-formed: the attributes are valid, the doc blocks
//! are valid, and the items they now belong to accept them.
//!
//! # What each rule here does, and what already overlapped
//!
//! * `no_outer_attribute_is_separated_from_its_item_by_a_blank_line` overlaps
//!   `clippy::empty_line_after_outer_attr` on purpose -- see that test's own
//!   doc comment for the measurement of where the two differ.
//! * `no_doc_comment_block_is_split_by_an_intervening_attribute` is the shape
//!   instance 2 took when no blank line was left behind.
//! * `every_comment_gating_a_module_names_a_path_that_module_reaches` reads
//!   instance 4's comment as a CLAIM and checks it against the module the
//!   `#[cfg]` now gates.
//! * `no_module_the_wasm_build_compiles_reaches_a_module_it_excludes` is
//!   instance 4's compile error itself, derived statically from the same cfg
//!   environment the pre-push gate builds under.
//!
//! `module_move_test::every_doc_block_is_attached_to_the_item_it_documents`
//! already gates the "block, then a gap, then the item" shape. It reads
//! `src/relay` and `src/rtpengine` only, and it treats an attribute run as
//! something to step OVER on the way to the item -- so it can see neither the
//! attribute that lost its item nor the attribute that gained the wrong one.
//! This file reads all of `src/` and reads the attributes themselves.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A path shown to a reader: repo-relative, with the repo root trimmed off.
fn show(p: &Path) -> String {
    p.strip_prefix(repo()).unwrap_or(p).display().to_string()
}

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

/// Is this an outer doc-comment line?
///
/// `////` is a plain comment and `//!` documents the enclosing module, not the
/// next item; neither binds forward, so neither can be split off an item.
fn is_doc_line(trimmed: &str) -> bool {
    trimmed.starts_with("///") && !trimmed.starts_with("////")
}

/// Is this the first line of an OUTER attribute?
///
/// `#![...]` is an inner attribute: it applies to the enclosing module and
/// binds backward, so a blank line beneath one separates it from nothing.
fn is_outer_attr(trimmed: &str) -> bool {
    trimmed.starts_with("#[")
}

/// Unbalanced square brackets contributed by one line.
fn bracket_delta(line: &str) -> isize {
    line.matches('[').count() as isize - line.matches(']').count() as isize
}

/// Index one past the last line of the attribute starting at `i`.
///
/// A multi-line `#[cfg(all(\n ... \n))]` is consumed as one unit by bracket
/// balance, so its inner lines are never mistaken for a second attribute and
/// the blank-line rule below measures from the attribute's real end.
fn attribute_end(lines: &[&str], i: usize) -> usize {
    let mut j = i;
    let mut balance = bracket_delta(lines[i]);
    while balance > 0 && j + 1 < lines.len() {
        j += 1;
        balance += bracket_delta(lines[j]);
    }
    j + 1
}

/// No outer attribute is separated from its item by a blank line.
///
/// Instance 2's visible symptom. `#[must_use]` was moved into the middle of
/// `is_ng_over_hep`'s doc comment, and what remained under it was a blank line
/// and then the rest of the block.
///
/// # This is not the only guard, and saying otherwise would be false
///
/// `clippy::empty_line_after_outer_attr` is warn-by-default and sits in
/// `clippy::suspicious`, hence in `clippy::all`; this repository's CI runs
/// clippy with `-D warnings`, so it is a hard gate there. Verified against the
/// pinned toolchain rather than assumed: `clippy-driver -Whelp` on rustc
/// 1.97.1 lists `clippy::empty-line-after-outer-attr  warn` and shows it under
/// `clippy::suspicious`. It is what failed the build on instance 2.
///
/// What this adds is COVERAGE, not novelty. Clippy lints the code the current
/// feature set and target actually compile; `src/` holds 1008 `#[cfg(...)]`
/// attributes, and no single invocation compiles all of what they gate. This
/// walk reads the text, so an attribute inside `#[cfg(feature = "bpf")]` -- a
/// feature deliberately outside `full`, which the pre-commit hook's
/// `cargo test --features full` therefore never builds -- is read exactly like
/// one on a line that compiles everywhere.
///
/// Its limit runs the other way: it reads lines, so an attribute written
/// inside a string literal or a `/* */` block would be counted. Measured on
/// 2026-08-31 there is no such line in `src/`, and the count in
/// `every_walk_in_this_file_found_a_plausible_tree` is what would notice the
/// scan drifting.
#[test]
fn no_outer_attribute_is_separated_from_its_item_by_a_blank_line() {
    let mut orphaned = Vec::new();
    let mut attributes = 0usize;
    for path in rust_files("src") {
        let src = std::fs::read_to_string(&path).expect("read source file");
        let lines: Vec<&str> = src.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            if !is_outer_attr(lines[i].trim()) {
                i += 1;
                continue;
            }
            attributes += 1;
            let end = attribute_end(&lines, i);
            if end < lines.len() && lines[end].trim().is_empty() {
                orphaned.push(format!("  {}:{}: {}", show(&path), i + 1, lines[i].trim()));
            }
            i = end;
        }
    }
    assert!(
        attributes >= 5000,
        "only {attributes} outer attribute(s) found across src/ (measured 7560 on 2026-08-31); the attribute scanner has stopped matching and this rule is reading an empty tree"
    );
    assert!(
        orphaned.is_empty(),
        "these outer attributes are separated from their item by a blank \
         line:\n{}\n\nAn outer attribute binds FORWARD. A blank line beneath \
         one is the residue of an insert that landed between the attribute and \
         what it was written for -- which is how `#[must_use]` ended up inside \
         `is_ng_over_hep`'s doc comment. Move the attribute back onto its item.",
        orphaned.join("\n")
    );
}

/// No doc comment is split in two by an attribute wedged into the middle.
///
/// Instance 2 and instance 3, in the form that leaves no blank line behind and
/// so trips neither `clippy::empty_line_after_outer_attr` nor
/// `clippy::empty_line_after_doc_comments`:
///
/// ```text
/// /// Does this HEP packet carry an rtpengine `ng` message?
/// #[must_use]
/// ///
/// /// Accepts either the documented capture protocol or ...
/// pub fn is_ng_over_hep(...)
/// ```
///
/// That compiles, and it renders. What rustdoc does with it was measured on
/// the pinned toolchain rather than recalled: it CONCATENATES the halves in
/// source order and takes the lead paragraph as the item's summary, so a split
/// alone changes nothing a reader would see.
///
/// The damage is that a split block can be REORDERED by a later edit, and
/// instance 2 is what that looks like. Splitting `src/rtpengine/mod.rs` left
/// `is_ng_over_hep`'s summary line below both the `#[must_use]` and the
/// paragraph that used to follow it. Fed that arrangement, rustdoc 1.97.1
/// leads the rendered page with "Accepts either the documented capture
/// protocol ..." and buries "Does this HEP packet carry an rtpengine `ng`
/// message?" underneath it -- a body paragraph serving as the function's
/// one-line summary. Nothing in the output says an edit went wrong; it simply
/// documents the function badly, in a way that reads as a writing choice.
///
/// Both halves of that are checked here rather than trusted, because a rule
/// whose stated reason is wrong is a rule nobody can maintain. Measured
/// 2026-08-31 against this tree: `cargo clippy --features full --lib` reports
/// NOTHING on the split shape -- not `empty_line_after_outer_attr`, which
/// needs the blank line the previous rule covers, and not
/// `empty_line_after_doc_comments` -- and `cargo fmt --check` does not touch
/// it either. For this shape, and unlike the rule above it, this test is the
/// only thing in the repository that reports it.
///
/// Interleaving attributes with doc comments is legal Rust and occasionally
/// deliberate elsewhere in the ecosystem. It is not done anywhere in this
/// tree: measured 2026-08-31, zero of 14396 doc blocks in `src/` are followed
/// by an attribute and then more doc lines. The rule is therefore a real
/// invariant of this repository rather than a style preference imposed on it.
#[test]
fn no_doc_comment_block_is_split_by_an_intervening_attribute() {
    let mut split = Vec::new();
    let mut blocks = 0usize;
    for path in rust_files("src") {
        let src = std::fs::read_to_string(&path).expect("read source file");
        let lines: Vec<&str> = src.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            if !is_doc_line(lines[i].trim()) {
                i += 1;
                continue;
            }
            blocks += 1;
            let start = i;
            while i < lines.len() && is_doc_line(lines[i].trim()) {
                i += 1;
            }
            let mut j = i;
            let mut wedge: Option<String> = None;
            while j < lines.len() && is_outer_attr(lines[j].trim()) {
                if wedge.is_none() {
                    wedge = Some(lines[j].trim().to_string());
                }
                j = attribute_end(&lines, j);
            }
            if let Some(attr) = wedge
                && j < lines.len()
                && is_doc_line(lines[j].trim())
            {
                split.push(format!(
                    "  {}:{}: block interrupted at line {} by {attr}\n      {}",
                    show(&path),
                    start + 1,
                    i + 1,
                    lines[start].trim()
                ));
            }
        }
    }
    assert!(
        blocks >= 10_000,
        "only {blocks} doc block(s) found across src/ (measured 14396 on 2026-08-31); the doc scanner has stopped matching and this rule would pass on a tree with no docs at all"
    );
    assert!(
        split.is_empty(),
        "these doc comments are cut in half by an attribute:\n{}\n\nrustdoc \
         concatenates the halves in source order, so the rendered summary line \
         is whatever leads the second half and the sentence written as the \
         summary is buried in the body. Both halves compile and both halves \
         render, which is why nothing else reports it. Put the whole block \
         above the attribute run.",
        split.join("\n")
    );
}

/// One `mod NAME;` declaration, with everything the scanner needs about it.
#[derive(Debug, Clone)]
struct ModDecl {
    /// The declaring file, repo-relative.
    file: String,
    /// 1-based line of the `mod` declaration.
    line: usize,
    /// The declared module's name.
    name: String,
    /// `cfg` predicates carried by the declaration's own attribute run.
    cfgs: Vec<String>,
    /// The `//` or `///` comment block directly above that attribute run, with
    /// the comment markers stripped, joined into one string.
    comment: String,
    /// The file backing the module, if one can be found on disk.
    target: Option<PathBuf>,
}

/// Where a `mod NAME;` in `file` looks for `NAME`'s source.
///
/// `mod.rs`, `lib.rs` and `main.rs` declare children beside themselves; any
/// other file declares them in a directory named after itself. An explicit
/// `#[path = "..."]` overrides both and is resolved against the declaring
/// file's directory -- `src/app/mod.rs` uses one to compile `src/mcp/audit.rs`
/// under a second name.
fn module_target(file: &Path, name: &str, cfgs_and_attrs: &[String]) -> Option<PathBuf> {
    let dir = file.parent()?;
    for attr in cfgs_and_attrs {
        if let Some(rest) = attr.strip_prefix("#[path = \"")
            && let Some(p) = rest.strip_suffix("\"]")
        {
            let joined = dir.join(p);
            return std::fs::canonicalize(&joined).ok().or(Some(joined));
        }
    }
    let stem = file.file_stem()?.to_str()?;
    let base = if matches!(stem, "mod" | "lib" | "main") {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    let flat = base.join(format!("{name}.rs"));
    if flat.is_file() {
        return Some(flat);
    }
    let nested = base.join(name).join("mod.rs");
    if nested.is_file() {
        return Some(nested);
    }
    None
}

/// Every `mod NAME;` declared in one file, with its attributes and the comment
/// block above them.
fn mod_decls(path: &Path) -> Vec<ModDecl> {
    let decl =
        regex::Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
            .expect("mod declaration pattern");
    let cfg_re = regex::Regex::new(r"^#\[cfg\((.*)\)\]$").expect("cfg pattern");
    let src = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(c) = decl.captures(line) else {
            continue;
        };
        let mut attrs: Vec<String> = Vec::new();
        let mut j = i;
        while j > 0 && is_outer_attr(lines[j - 1].trim()) {
            attrs.push(lines[j - 1].trim().to_string());
            j -= 1;
        }
        let mut comment: Vec<String> = Vec::new();
        while j > 0 {
            let t = lines[j - 1].trim();
            if t.starts_with("//!") {
                break;
            }
            if is_doc_line(t) {
                comment.push(t.trim_start_matches('/').trim().to_string());
                j -= 1;
                continue;
            }
            if let Some(rest) = t.strip_prefix("//") {
                comment.push(rest.trim().to_string());
                j -= 1;
                continue;
            }
            break;
        }
        comment.reverse();
        let cfgs = attrs
            .iter()
            .filter_map(|a| cfg_re.captures(a).map(|c| c[1].to_string()))
            .collect();
        out.push(ModDecl {
            file: show(path),
            line: i + 1,
            name: c[1].to_string(),
            cfgs,
            comment: comment.join(" "),
            target: module_target(path, &c[1], &attrs),
        });
    }
    out
}

/// Every `.rs` byte of a module: the file itself, plus the directory beside it
/// when the module has one.
fn module_body(target: &Path) -> String {
    let mut body = std::fs::read_to_string(target).unwrap_or_default();
    let dir = if target.file_stem().is_some_and(|s| s == "mod") {
        target.parent().map(Path::to_path_buf)
    } else {
        target
            .parent()
            .map(|d| d.join(target.file_stem().unwrap_or_default()))
    };
    if let Some(dir) = dir
        && dir.is_dir()
    {
        let mut stack = vec![dir];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") && p != target {
                    body.push_str(&std::fs::read_to_string(&p).unwrap_or_default());
                }
            }
        }
    }
    body
}

/// Paths a comment claims the module it gates reaches, as `(claim, needle)`.
///
/// A claim is a backticked `SIBLING::item` where `SIBLING` is another module
/// declared in the same file and is not the gated module itself. Only the
/// PATH form counts, and the reason is measured rather than assumed. Two
/// weaker extractions were tried against the tree first:
///
/// * **Bare backticked sibling names.** `src/capture/mod.rs` gates
///   `pub mod resolve;` under a comment saying it "shares `file`'s gate rather
///   than inventing its own". That names a sibling in order to talk about the
///   GATE, and asserts nothing about `resolve` calling into `file`. Demanding
///   a reference would report a comment that is entirely correct.
/// * **Substring matching on the bare name.** Searching `resolve`'s source for
///   `file` matches `std::fs::File`, `profile`, and the word itself in prose.
///   It cannot fail, which is worse than a false positive.
///
/// `SIBLING::item` has neither problem: writing it is a statement that this
/// module names that path. Its own limit is that it is rare -- one such claim
/// exists in the tree, `src/lib.rs`'s comment on `rtpengine`, which is the
/// comment instance 4 stole. `every_walk_in_this_file_found_a_plausible_tree`
/// pins that count, and the paired fixtures below exercise the rule in both
/// directions so it is not resting on a single live case.
fn comment_claims(decl: &ModDecl, siblings: &BTreeSet<String>) -> Vec<(String, String)> {
    let backticked = regex::Regex::new(r"`([^`]+)`").expect("backtick pattern");
    let mut out = Vec::new();
    for c in backticked.captures_iter(&decl.comment) {
        let quoted = c[1].trim();
        let Some((head, _)) = quoted.split_once("::") else {
            continue;
        };
        if head == decl.name || !siblings.contains(head) {
            continue;
        }
        let needle = quoted
            .split('(')
            .next()
            .unwrap_or(quoted)
            .trim()
            .to_string();
        out.push((quoted.to_string(), needle));
    }
    out
}

/// A comment gating a module describes THAT module.
///
/// Instance 4, read as a claim rather than as prose. `src/lib.rs` carried
///
/// ```text
/// // Native only, exactly as `pipeline` is: this module hands `ng`-derived
/// // SDP to `pipeline::extract_sdp_links`, so it cannot compile where that
/// // does not. ...
/// #[cfg(not(target_arch = "wasm32"))]
/// pub mod rtpengine;
/// ```
///
/// and `pub mod relay;` was inserted directly under the `#[cfg]`. The comment
/// and the gate both moved to `relay`, which hands nothing to
/// `pipeline::extract_sdp_links` and does not name it anywhere. The sentence
/// stayed true about `rtpengine` and became false about the module it now sat
/// on, and no build reads a comment.
///
/// The check is the one thing in that sentence a machine can settle: the
/// module the comment now gates must actually contain the path the comment
/// says it uses. `comment_claims` documents which forms count and which two
/// weaker extractions were rejected against this tree and why.
#[test]
fn every_comment_gating_a_module_names_a_path_that_module_reaches() {
    let mut unmet = Vec::new();
    let mut claims = 0usize;
    for path in rust_files("src") {
        let decls = mod_decls(&path);
        let siblings: BTreeSet<String> = decls.iter().map(|d| d.name.clone()).collect();
        for decl in &decls {
            if decl.comment.is_empty() {
                continue;
            }
            let Some(target) = decl.target.as_ref() else {
                continue;
            };
            let found = comment_claims(decl, &siblings);
            if found.is_empty() {
                continue;
            }
            let body = module_body(target);
            for (quoted, needle) in found {
                claims += 1;
                if !body.contains(&needle) {
                    unmet.push(format!(
                        "  {}:{}: `mod {}` is gated under a comment naming `{quoted}`, \
                         but nothing under {} names `{needle}`",
                        decl.file,
                        decl.line,
                        decl.name,
                        show(target)
                    ));
                }
            }
        }
    }
    assert!(
        claims >= 1,
        "only {claims} comment(s) above a `mod` declaration name a sibling path (measured 1 on 2026-08-31, `src/lib.rs`'s comment on `rtpengine`); the claim extractor has stopped matching, so this rule is asserting nothing about anything"
    );
    assert!(
        unmet.is_empty(),
        "these comments describe a module other than the one they gate:\n{}\n\n\
         A `//` block above a `#[cfg]` above a `mod` is three separate things \
         to the compiler and one paragraph to a reader. An insert between the \
         attribute and the declaration moves all three onto the new module at \
         once, and the sentence goes on reading as though it had not: that is \
         how `src/lib.rs` came to tell a reader that `relay` hands SDP to \
         `pipeline::extract_sdp_links`. Put the comment back on the module it \
         is about.",
        unmet.join("\n")
    );

    // The rule reads exactly one live comment, so its two directions are
    // exercised here as well. Both fixtures are instance 4: the same comment,
    // above the module it belongs to and above the module the insert gave it
    // to. A narrowing that silenced the defect would also flatten these.
    let claim = "this module hands `ng`-derived SDP to `pipeline::extract_sdp_links`";
    let siblings: BTreeSet<String> = ["pipeline", "relay", "rtpengine"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let on_relay = ModDecl {
        file: "src/lib.rs".to_string(),
        line: 0,
        name: "relay".to_string(),
        cfgs: vec!["not(target_arch = \"wasm32\")".to_string()],
        comment: claim.to_string(),
        target: None,
    };
    let extracted = comment_claims(&on_relay, &siblings);
    assert_eq!(
        extracted,
        vec![(
            "pipeline::extract_sdp_links".to_string(),
            "pipeline::extract_sdp_links".to_string()
        )],
        "the claim extractor no longer reads instance 4's own comment"
    );
    let relay_body = std::fs::read_to_string(repo().join("src/relay/mod.rs"))
        .map(|_| module_body(&repo().join("src/relay/mod.rs")))
        .expect("read src/relay/mod.rs");
    assert!(
        !relay_body.contains(&extracted[0].1),
        "src/relay no longer reaches `pipeline::extract_sdp_links`, so the \
         fixture proving this rule can FAIL has stopped proving it"
    );
    let rtpengine_body = module_body(&repo().join("src/rtpengine/mod.rs"));
    assert!(
        rtpengine_body.contains(&extracted[0].1),
        "src/rtpengine no longer reaches `pipeline::extract_sdp_links`, so the \
         fixture proving this rule can PASS has stopped proving it"
    );
}

/// One `cfg` predicate, evaluated in the environment the wasm gate builds in.
///
/// `.githooks/pre-push` and `ci.yml` both run
/// `cargo check --target wasm32-unknown-unknown --no-default-features
/// --features wasm --lib`, and `Cargo.toml`'s `wasm` feature enables only
/// `dep:` entries, so the named feature set is exactly `{"wasm"}` and every
/// other feature is off.
///
/// `None` is "this scanner cannot decide" and every caller reads it as "assume
/// the code is not compiled". That is the direction that cannot invent a
/// finding: an undecidable gate makes the rule blind to what is inside it,
/// never wrong about it. `unknown_cfg_predicates` counts them so the blindness
/// is a number rather than a silence.
fn eval_wasm_cfg(pred: &str) -> Option<bool> {
    let pred = pred.trim();
    for (head, combine) in [("all(", true), ("any(", false)] {
        if let Some(rest) = pred.strip_prefix(head)
            && let Some(inner) = rest.strip_suffix(')')
        {
            let mut acc = combine;
            let mut unknown = false;
            for part in split_top_level(inner) {
                match eval_wasm_cfg(&part) {
                    Some(v) if combine => acc &= v,
                    Some(v) => acc |= v,
                    None => unknown = true,
                }
            }
            // `all` with a false conjunct is false whatever the unknowns are,
            // and `any` with a true disjunct is true; only an undecided
            // remainder that could still swing the answer is undecidable.
            if acc != combine {
                return Some(acc);
            }
            return if unknown { None } else { Some(acc) };
        }
    }
    if let Some(rest) = pred.strip_prefix("not(")
        && let Some(inner) = rest.strip_suffix(')')
    {
        return eval_wasm_cfg(inner).map(|v| !v);
    }
    if let Some((key, value)) = pred.split_once('=') {
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        return match key {
            "feature" => Some(value == "wasm"),
            "target_arch" => Some(value == "wasm32"),
            "target_os" => Some(value == "unknown"),
            "target_family" => Some(value == "wasm"),
            "target_pointer_width" => Some(value == "32"),
            "target_env" => Some(value.is_empty()),
            _ => None,
        };
    }
    match pred {
        "test" | "doctest" | "unix" | "windows" => Some(false),
        _ => None,
    }
}

/// Split a `cfg` argument list on top-level commas.
fn split_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        cur.push(ch);
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// The crate's module tree, keyed by `::`-joined path, with the file backing
/// each module and whether the wasm build compiles it.
///
/// The verdict is inherited: a module the wasm build does not compile cannot
/// have children it compiles, so the walk does not descend past one. That is
/// what keeps `capture::fanout` -- `#[cfg(feature = "native")]`, and full of
/// `crate::parallel` -- out of the scan below without an exclusion list.
fn wasm_module_tree() -> (BTreeMap<String, (PathBuf, Option<bool>)>, usize) {
    let mut out: BTreeMap<String, (PathBuf, Option<bool>)> = BTreeMap::new();
    let mut unknown = 0usize;
    let root = repo().join("src/lib.rs");
    let mut stack = vec![(String::new(), root, Some(true))];
    while let Some((path, file, compiled)) = stack.pop() {
        if out.contains_key(&path) {
            continue;
        }
        out.insert(path.clone(), (file.clone(), compiled));
        for decl in mod_decls(&file) {
            let Some(target) = decl.target else {
                continue;
            };
            let mut child = compiled;
            for cfg in &decl.cfgs {
                match eval_wasm_cfg(cfg) {
                    Some(false) => child = Some(false),
                    Some(true) => {}
                    None => {
                        unknown += 1;
                        if child == Some(true) {
                            child = None;
                        }
                    }
                }
            }
            let key = if path.is_empty() {
                decl.name.clone()
            } else {
                format!("{path}::{}", decl.name)
            };
            stack.push((key, target, child));
        }
    }
    (out, unknown)
}

/// For each line of `lines`, whether the wasm build compiles it.
///
/// An outer `#[cfg(P)]` whose `P` is not decidably true guards the item that
/// follows it, and the item runs to the first later line indented no further
/// than the attribute. That is a rule about rustfmt's output, not about Rust,
/// and it holds here because `cargo fmt --check` is a push gate: an attribute,
/// its item, and the item's closing brace all sit at one indentation, and
/// everything belonging to the item sits deeper.
///
/// It suppresses 21 references in this tree, and the four that reach
/// `crate::pipeline` were opened by hand before this was written, because they
/// are the four shapes the rule has to get right: a bare guarded statement
/// (`src/sip/dsl.rs`), a `let` whose initializer spans five lines
/// (`src/sip/diagnosis.rs`), an `if let` block (`src/capture/parse.rs`), and a
/// whole `#[cfg(test)] mod` (`src/capture/mod.rs`). Inverting this function's
/// own condition reports all 21, which is what says it is doing the work
/// rather than returning a convenient constant.
fn wasm_dead_lines(lines: &[&str]) -> Vec<bool> {
    let cfg_re = regex::Regex::new(r"^#\[cfg\((.*)\)\]$").expect("cfg pattern");
    let indent = |l: &str| l.len() - l.trim_start().len();
    let mut dead = vec![false; lines.len()];
    for i in 0..lines.len() {
        let t = lines[i].trim();
        let Some(c) = cfg_re.captures(t) else {
            continue;
        };
        if eval_wasm_cfg(&c[1]) == Some(true) {
            continue;
        }
        let depth = indent(lines[i]);
        let mut start = i + 1;
        while start < lines.len() {
            let s = lines[start].trim();
            if s.is_empty() || s.starts_with("#[") || s.starts_with("//") {
                start += 1;
                continue;
            }
            break;
        }
        if start >= lines.len() {
            continue;
        }
        let mut end = lines.len() - 1;
        for (k, line) in lines.iter().enumerate().skip(start + 1) {
            if line.trim().is_empty() {
                continue;
            }
            if indent(line) <= depth {
                end = k;
                break;
            }
        }
        for slot in dead.iter_mut().take(end + 1).skip(start) {
            *slot = true;
        }
    }
    dead
}

/// No module the wasm build compiles reaches a module the wasm build excludes.
///
/// Instance 4's compile error, derived from the text instead of from a
/// cross-compile. When `pub mod relay;` took `rtpengine`'s `#[cfg]`,
/// `rtpengine` became unconditional, and `src/rtpengine/mod.rs` calls
/// `crate::pipeline::extract_sdp_links` and `crate::relay::note_media_creating_command`
/// while `src/rtpengine/control.rs` imports `crate::relay::types` -- three
/// references into modules that do not exist on wasm32. Reintroducing the
/// insert makes this rule report exactly those three lines.
///
/// # Why this is a static claim and not a guess
///
/// Nothing here approximates the compiler's cfg evaluation; it performs it,
/// under the one environment the release gates build in, and refuses to guess
/// where it cannot. Three things bound what it can see, and all three fail
/// toward silence rather than toward a false finding:
///
/// 1. A module whose gate is undecidable is not scanned (`eval_wasm_cfg`).
/// 2. A reference under an undecidable inner `#[cfg]` is treated as guarded.
/// 3. A reference reached through a `use` alias, a macro, or a re-export,
///    rather than written as `crate::NAME::`, is not seen at all.
///
/// So a green result is not proof the wasm build compiles --
/// `cargo check --target wasm32-unknown-unknown` is, and it stays the gate in
/// `.githooks/pre-push`. What this buys is that the failure arrives in
/// `cargo test` seconds after the edit, on a machine with no wasm32 toolchain,
/// instead of at the last gate before a push.
#[test]
fn no_module_the_wasm_build_compiles_reaches_a_module_it_excludes() {
    let (tree, _) = wasm_module_tree();
    let excluded: BTreeSet<String> = tree
        .iter()
        .filter(|(k, (_, c))| !k.is_empty() && !k.contains("::") && *c == Some(false))
        .map(|(k, _)| k.clone())
        .collect();
    let compiled: Vec<(&String, &PathBuf)> = tree
        .iter()
        .filter(|(_, (_, c))| *c == Some(true))
        .map(|(k, (f, _))| (k, f))
        .collect();
    assert!(
        excluded.len() >= 10,
        "only {} root module(s) are excluded from the wasm build (measured 18 on 2026-08-31); the cfg evaluator has stopped deciding and every reference below is unchecked",
        excluded.len()
    );
    assert!(
        compiled.len() >= 40,
        "only {} module(s) are compiled by the wasm build (measured 74 on 2026-08-31); the module-tree walk has stopped descending",
        compiled.len()
    );

    let ref_re = regex::Regex::new(r"\bcrate::([a-z_][a-z0-9_]*)\b").expect("crate path pattern");
    let mut candidates = 0usize;
    let mut unreachable_on_wasm = Vec::new();
    for (_, file) in &compiled {
        let src = std::fs::read_to_string(file).unwrap_or_default();
        let lines: Vec<&str> = src.lines().collect();
        let dead = wasm_dead_lines(&lines);
        for (idx, line) in lines.iter().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with('*') {
                continue;
            }
            for c in ref_re.captures_iter(line) {
                if !excluded.contains(&c[1]) {
                    continue;
                }
                candidates += 1;
                if !dead[idx] {
                    unreachable_on_wasm.push(format!(
                        "  {}:{}: names `crate::{}`, which the wasm build does not compile\n      {t}",
                        show(file),
                        idx + 1,
                        &c[1]
                    ));
                }
            }
        }
    }
    assert!(
        candidates >= 10,
        "only {candidates} reference(s) from wasm-compiled code into wasm-excluded modules were even considered (measured 21 on 2026-08-31); the reference scanner has stopped matching, so a module that lost its gate would look clean"
    );
    assert!(
        unreachable_on_wasm.is_empty(),
        "these lines are compiled for wasm32 and name a module wasm32 does not \
         build:\n{}\n\nEither the module holding them lost its own \
         `#[cfg(not(target_arch = \"wasm32\"))]` -- which is what an insert \
         directly beneath that attribute in `src/lib.rs` does, silently -- or \
         the reference needs a gate of its own. The host build cannot see this \
         and neither can clippy; the only other thing that reports it is \
         `cargo check --target wasm32-unknown-unknown`, at the end of \
         `.githooks/pre-push`.",
        unreachable_on_wasm.join("\n")
    );
}

/// One paragraph of a doc comment, after markdown block structure is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Para {
    /// A `#`-prefixed section heading.
    Heading(String),
    /// Everything else -- prose, a list, a table, a fenced block -- joined into
    /// one line.
    Prose(String),
}

/// One doc line with its `///` marker and the single following space removed.
fn strip_doc_marker(trimmed: &str) -> String {
    let rest = trimmed.strip_prefix("///").unwrap_or_default();
    rest.strip_prefix(' ').unwrap_or(rest).to_string()
}

/// Every maximal run of `///` lines in a file, as `(1-based start line, text)`.
fn doc_blocks_of(path: &Path) -> Vec<(usize, Vec<String>)> {
    let src = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !is_doc_line(lines[i].trim()) {
            i += 1;
            continue;
        }
        let start = i;
        let mut body = Vec::new();
        while i < lines.len() && is_doc_line(lines[i].trim()) {
            body.push(strip_doc_marker(lines[i].trim()));
            i += 1;
        }
        out.push((start + 1, body));
    }
    out
}

/// Split a doc block into headings and paragraphs.
///
/// Blank lines separate paragraphs, a line opening with `#` is a heading, and a
/// fenced block is carried whole so a blank line inside a `” ```text ”` table
/// does not split it into two paragraphs.
fn paragraphs(body: &[String]) -> Vec<Para> {
    let mut groups: Vec<Vec<String>> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    let mut fence = false;
    for line in body {
        let st = line.trim();
        if st.starts_with("```") {
            fence = !fence;
            cur.push(line.clone());
            continue;
        }
        if fence {
            cur.push(line.clone());
            continue;
        }
        if st.is_empty() {
            if !cur.is_empty() {
                groups.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if st.starts_with('#') {
            if !cur.is_empty() {
                groups.push(std::mem::take(&mut cur));
            }
            groups.push(vec![line.clone()]);
            continue;
        }
        cur.push(line.clone());
    }
    if !cur.is_empty() {
        groups.push(cur);
    }
    groups
        .into_iter()
        .map(|g| {
            let text = g
                .iter()
                .map(|l| l.trim())
                .collect::<Vec<_>>()
                .join(" ")
                .trim()
                .to_string();
            if text.starts_with('#') {
                Para::Heading(text)
            } else {
                Para::Prose(text)
            }
        })
        .collect()
}

/// How many sentences a paragraph holds.
///
/// Code spans and markdown links are blanked first, because a `[`Foo`](bar)`
/// and a version number both carry full stops that end no sentence, and the
/// three abbreviations this tree actually uses are folded away.
fn sentence_count(text: &str) -> usize {
    static CODE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static LINK: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static END: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let code = CODE.get_or_init(|| regex::Regex::new(r"`[^`]*`").expect("code span pattern"));
    let link =
        LINK.get_or_init(|| regex::Regex::new(r"\[[^\]]*\]\([^)]*\)").expect("link pattern"));
    let end = END.get_or_init(|| regex::Regex::new(r"[.!?](\s|$)").expect("sentence end pattern"));
    let blanked = code.replace_all(text, "X");
    let blanked = link.replace_all(&blanked, "X");
    let folded = blanked
        .replace("e.g.", "eg")
        .replace("i.e.", "ie")
        .replace("etc.", "etc");
    end.find_iter(&folded).count()
}

/// Does this paragraph read as an item's opening summary line?
///
/// One sentence, short, and not a list, table, quote or fenced block.
fn reads_as_a_summary(text: &str) -> bool {
    const NOT_PROSE: &[&str] = &["- ", "* ", "1. ", "|", "```", ">"];
    if NOT_PROSE.iter().any(|o| text.starts_with(o)) {
        return false;
    }
    sentence_count(text) <= 1 && text.chars().count() <= 120
}

/// The paragraph that opens a SECOND summary inside one doc block, if any.
///
/// Five conditions, and every one of them was forced by measuring the tree
/// rather than chosen up front -- see
/// `no_doc_block_opens_a_second_summary_after_a_section_heading` for the counts
/// each one removed. The paragraph must sit after the block's first `#`
/// heading; must not be the first paragraph of its section, which is where a
/// section's own opening sentence legitimately lives; must read as a summary;
/// must not be a lead-in ending in `:`, which points forward at a list instead
/// of summarizing; and must itself be followed by more prose, because a summary
/// is a thing that has a body under it.
///
/// `skip_lead_ins` exists so the paired discriminator test can ask for the
/// same rule with the `:` condition switched off, and check that every
/// paragraph the condition removes really is a lead-in.
fn second_summary(paras: &[Para], skip_lead_ins: bool) -> Option<String> {
    let first_heading = paras.iter().position(|p| matches!(p, Para::Heading(_)))?;
    if first_heading == 0 {
        return None;
    }
    for i in (first_heading + 1)..paras.len() {
        let Para::Prose(text) = &paras[i] else {
            continue;
        };
        if matches!(paras[i - 1], Para::Heading(_)) {
            continue;
        }
        if !reads_as_a_summary(text) {
            continue;
        }
        if skip_lead_ins && text.trim_end().ends_with(':') {
            continue;
        }
        if !matches!(paras.get(i + 1), Some(Para::Prose(_))) {
            continue;
        }
        return Some(text.clone());
    }
    None
}

/// The doc block sitting above one item declaration, read from the tree.
fn doc_block_above(path: &Path, item: &str) -> Vec<String> {
    let src = std::fs::read_to_string(path).expect("read source file");
    let lines: Vec<&str> = src.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.starts_with(item))
        .unwrap_or_else(|| panic!("{} no longer declares `{item}`", show(path)));
    let mut j = at;
    while j > 0 && is_outer_attr(lines[j - 1].trim()) {
        j -= 1;
    }
    let mut s = j;
    while s > 0 && is_doc_line(lines[s - 1].trim()) {
        s -= 1;
    }
    lines[s..j]
        .iter()
        .map(|l| strip_doc_marker(l.trim()))
        .collect()
}

/// No doc block opens a second summary after a section heading.
///
/// Instance 5, and the one shape the four rules above cannot see. RP2 moved
/// `ControlClient` from `src/relay/types.rs` to `src/rtpengine/control.rs` and
/// left its doc block behind. The orphan came to rest directly on top of
/// `RelayStream`'s own doc block with no item and no blank line between them,
/// so the two `///` runs are ONE run to the compiler and one doc block to
/// rustdoc. `RelayStream` rendered with a summary about a control client and
/// two `# Why ...` sections about a type it is not.
///
/// Nothing else reports it. Rule 1 needs a blank line and there is none; rule 2
/// needs an intervening attribute and there is none; rules 3 and 4 are about
/// module gating. The block IS attached to an item, so
/// `module_move_test::every_doc_block_is_attached_to_the_item_it_documents` is
/// green on it too -- it is attached, to the wrong number of items.
///
/// # What the rule had to become, measured at each step
///
/// The obvious fingerprint is "a summary-shaped paragraph turns up after a
/// `#` heading". Run against `src/` on 2026-08-31 that reports **268 of 14396
/// blocks**, because a legitimate `# Errors`, `# Panics` or `# Why ...` section
/// very often ends in one short sentence. Three further conditions bring it to
/// zero, and each is a claim about what a well-formed block looks like rather
/// than a patch to silence a file:
///
/// | condition added | blocks still reported |
/// |---|---|
/// | summary-shaped paragraph after a heading | 268 |
/// | ...and not the first paragraph of its section | 12 |
/// | ...and followed by more prose, as a summary's body | 6 |
/// | ...and not a lead-in ending in `:` | 0 |
///
/// (`12` and `6` are the same scan with one condition switched off at a time;
/// `268` is the rule as first proposed.)
///
/// The last two are the load-bearing pair. A summary has a body under it, so a
/// lone trailing sentence is a section ending, not an opening. And all six
/// survivors of the third condition end in `:` -- every one introduces a bullet
/// list or a code block, which is a sentence pointing FORWARD rather than
/// summarizing. That exclusion is not taken on faith:
/// `the_second_summary_rule_separates_a_stranded_block_from_a_list_lead_in`
/// re-derives the six and asserts each one really is a lead-in, so the day one
/// of them stops being a lead-in this rule stops being silent about it.
///
/// # What this does NOT catch, including instance 5 itself
///
/// This fires only when a blank `///` line separates the two runs. Instance 5
/// had none: read out of the commit that still carries it, the stranded block
/// ends `... is something an operator opts into.` and `RelayStream`'s summary
/// begins on the very next source line, so markdown joins the two into ONE
/// paragraph and no summary-shaped paragraph survives anywhere after a
/// heading. **This rule returns nothing on the defect it is named for**, and
/// `the_second_summary_rule_separates_a_stranded_block_from_a_list_lead_in`
/// pins that as an assertion so it stays a measured fact.
///
/// What it does gate is the same concatenation one blank line apart, which is
/// the more common way a moved item strands its doc, and it gates it with no
/// false positives at all.
///
/// Three wider rules were built and measured against `src/` before this one
/// was settled on, and every one of them is unusable here. Recorded so nobody
/// spends the afternoon again:
///
/// | rule | reports on a clean `src/` |
/// |---|---|
/// | summary-shaped paragraph after a heading | 268 |
/// | greedy-wrap violation inside a paragraph | 1533 |
/// | sentence-end line join, narrowed four ways | 5, of which 2 are correct prose |
///
/// The last of those is the one that DOES see instance 5, and it is the
/// painful one: it separates a concatenation seam from an author's deliberate
/// sentence-per-line break only by arithmetic on the wrap width, and the two
/// populations overlap -- 3 columns of slack on a correct paragraph in
/// `src/app/bootstrap.rs` against 9 on the real defect. A threshold there is a
/// number picked to make the tree green, which is the one thing a gate may
/// never be. It is not offered as a rule; it was run once as an audit, and
/// what it found is in the report rather than in a test.
#[test]
fn no_doc_block_opens_a_second_summary_after_a_section_heading() {
    let mut offenders = Vec::new();
    let mut blocks = 0usize;
    let mut with_heading = 0usize;
    let mut paragraphs_seen = 0usize;
    let mut before_the_lead_in_filter = 0usize;
    for path in rust_files("src") {
        for (line, body) in doc_blocks_of(&path) {
            blocks += 1;
            let paras = paragraphs(&body);
            paragraphs_seen += paras.len();
            if paras.iter().any(|p| matches!(p, Para::Heading(_))) {
                with_heading += 1;
            }
            if second_summary(&paras, false).is_some() {
                before_the_lead_in_filter += 1;
            }
            if let Some(text) = second_summary(&paras, true) {
                offenders.push(format!("  {}:{line}: {text}", show(&path)));
            }
        }
    }
    assert!(
        blocks >= 10_000,
        "only {blocks} doc block(s) found across src/ (measured 14396 on 2026-08-31); the block scanner has stopped matching and this rule is reading an empty tree"
    );
    assert!(
        with_heading >= 500,
        "only {with_heading} doc block(s) carry a `#` heading (measured 824 on 2026-08-31); this rule only ever looks at those, so below this it is examining almost nothing"
    );
    assert!(
        paragraphs_seen >= 15_000,
        "only {paragraphs_seen} paragraph(s) parsed out of those blocks (measured 22103 on 2026-08-31); the markdown splitter has collapsed and every block now looks like one paragraph, which no rule below can fire on"
    );
    assert!(
        before_the_lead_in_filter >= 4,
        "only {before_the_lead_in_filter} block(s) reach the lead-in filter (measured 6 on 2026-08-31). Below this the `:` exclusion is not removing false positives, it IS the rule -- everything is being rejected earlier, and a stranded block would be rejected with it."
    );
    assert!(
        offenders.is_empty(),
        "these doc blocks open a second summary partway through:\n{}\n\nA \
         well-formed block is one summary, then prose, then `#` sections. A \
         summary appearing again after a heading is the seam where two blocks \
         were concatenated -- which happens when an item is moved out from \
         under its doc and the orphan comes to rest on the next item's doc \
         with no blank line between them. Both halves compile and both halves \
         render; what the reader gets is one item documented as two.",
        offenders.join("\n")
    );
}

/// The second-summary rule tells a stranded block from a list lead-in.
///
/// The paired discriminator. A rule with one live instance and an exclusion
/// bolted on is indistinguishable from a rule narrowed until it went green, so
/// both sides are asserted here against text read from the tree rather than
/// copied into a fixture -- if either doc is rewritten, this fails instead of
/// quietly testing nothing.
///
/// * **It must fire on the real thing.** `ControlClient`'s doc block is read
///   from `src/rtpengine/control.rs`, where the stranded prose was merged back,
///   and `RelayStream`'s from `src/relay/types.rs`. Concatenated the way the
///   defect had them, the rule must report `RelayStream`'s summary.
/// * **It must not fire on the lead-ins.** Every paragraph the `:` condition
///   removes is re-derived from the tree and each one must really end in `:`.
///   This is what the exclusion owes: it is allowed to spare a sentence that
///   points at a list, and nothing else.
/// * **The blind spot is pinned as a negative.** Without a blank `///` between
///   the two runs the shape is invisible to this rule. That is not a
///   hypothetical: it is the arrangement instance 5 actually had. Asserting it
///   keeps a measured limit from decaying into an assumed capability.
#[test]
fn the_second_summary_rule_separates_a_stranded_block_from_a_list_lead_in() {
    let orphan = doc_block_above(
        &repo().join("src/rtpengine/control.rs"),
        "pub struct ControlClient {",
    );
    let victim = doc_block_above(
        &repo().join("src/relay/types.rs"),
        "pub struct RelayStream {",
    );
    let orphan_paras = paragraphs(&orphan);
    let headings = orphan_paras
        .iter()
        .filter(|p| matches!(p, Para::Heading(_)))
        .count();
    assert!(
        headings >= 2 && matches!(orphan_paras.first(), Some(Para::Prose(_))),
        "`ControlClient`'s doc block no longer has the shape this fixture is \
         built from ({headings} heading(s), first paragraph {:?}). It is the \
         stranded prose itself, so a rewrite means this test is now proving \
         something about a block that never went missing.",
        orphan_paras.first()
    );
    assert!(
        !victim.iter().any(|l| l.trim_start().starts_with('#')),
        "`RelayStream`'s own doc block now carries a `#` heading. It is a plain \
         data struct documented in two paragraphs, so either the stranded \
         block is back -- which is instance 5 itself, at the site it happened \
         -- or the doc was rewritten. Either way the clean half this fixture \
         is built from is no longer clean. This assertion is a tripwire on one \
         known site, not a general rule; the general rules are the two tests \
         above, and neither of them sees this arrangement."
    );
    let victim_summary = match victim.first() {
        Some(s) => s.clone(),
        None => panic!("`RelayStream` has no doc comment to strand a block above"),
    };
    assert!(
        !victim_summary.trim_end().ends_with(':'),
        "`RelayStream`'s summary now ends in `:`, so the lead-in exclusion \
         would spare it and this fixture proves nothing"
    );

    // The defect as it stood: the orphan, a blank doc line, then the victim's
    // own block, with no item between them.
    let mut stranded = orphan.clone();
    stranded.push(String::new());
    stranded.extend(victim.iter().cloned());
    assert_eq!(
        second_summary(&paragraphs(&stranded), true).as_deref(),
        Some(victim_summary.trim()),
        "the rule no longer reports the stranded block that instance 5 was"
    );

    // The same two blocks with no blank line between them: markdown joins the
    // victim's summary onto the tail of the orphan's last paragraph, and no
    // summary-shaped paragraph survives anywhere after a heading. Pinned so
    // the limit is a recorded fact.
    let mut joined = orphan.clone();
    joined.extend(victim.iter().cloned());
    assert_eq!(
        second_summary(&paragraphs(&joined), true),
        None,
        "the no-blank-line concatenation is now visible to this rule. That is \
         the arrangement instance 5 had, so this is an improvement rather than \
         a failure -- widen the doc comment's stated blind spot, re-measure \
         the whole of src/ for the false positives the widening brings, and \
         move this assertion."
    );

    // Every paragraph the `:` condition removes, re-derived from the tree.
    let mut spared = Vec::new();
    for path in rust_files("src") {
        for (line, body) in doc_blocks_of(&path) {
            let paras = paragraphs(&body);
            if second_summary(&paras, true).is_none()
                && let Some(text) = second_summary(&paras, false)
            {
                spared.push((show(&path), line, text));
            }
        }
    }
    assert!(
        spared.len() >= 4,
        "the lead-in exclusion now spares only {} paragraph(s) (measured 6 on 2026-08-31). It is meant to remove a known, checkable class; sparing nothing means the rule is rejecting them earlier and this discriminator has stopped discriminating.",
        spared.len()
    );
    let not_lead_ins: Vec<String> = spared
        .iter()
        .filter(|(_, _, t)| !t.trim_end().ends_with(':'))
        .map(|(f, l, t)| format!("  {f}:{l}: {t}"))
        .collect();
    assert!(
        not_lead_ins.is_empty(),
        "the lead-in exclusion is sparing paragraphs that are not \
         lead-ins:\n{}\n\nIt is allowed to spare exactly one thing: a sentence \
         ending in `:` that introduces a list or a code block. Anything else \
         it hides is a second summary this rule was built to report, and the \
         exclusion has become the narrowing it was written to avoid.",
        not_lead_ins.join("\n")
    );
}

/// The declaration a doc block sits on, flattened to one line.
///
/// Attributes are stepped over by bracket balance rather than by "the line
/// starts with `#[`". Written the naive way this reported 43 violations, 42 of
/// them inside a multi-line `#[tool(name = "...", description = "...")]` whose
/// continuation lines do not start with `#[` -- the scanner had walked into the
/// middle of an attribute and read its arguments as an item.
fn item_below(lines: &[&str], after: usize) -> String {
    let mut j = after;
    while j < lines.len() {
        let t = lines[j].trim();
        if t.is_empty() {
            j += 1;
            continue;
        }
        if is_outer_attr(t) {
            j = attribute_end(lines, j);
            continue;
        }
        break;
    }
    let mut sig: Vec<&str> = Vec::new();
    while j < lines.len() && sig.len() < 12 {
        let t = lines[j].trim();
        sig.push(t);
        if t.ends_with('{') || t.ends_with(';') {
            break;
        }
        j += 1;
    }
    sig.join(" ")
}

/// Rustdoc section headings that only a function can honor.
///
/// `# Safety` is deliberately absent. It is legitimate on a SAFE function that
/// wraps an `unsafe` block -- `src/signals.rs`'s `install_handlers` is one, and
/// the exclusion is checked rather than asserted in the test below.
/// `# Side effects` joined this list on 2026-08-31, and the reason is a near
/// miss rather than tidiness. An insertion split `set_parser_limits`'s doc
/// block, and the orphaned half landed on a `static`. This rule caught it --
/// but only because that half happened to carry `# Arguments` too. Had the cut
/// fallen one section later the orphan would have carried `# Side effects`
/// alone and nothing here would have fired, because a side effect is just as
/// much a claim about a CALL and was not on the list.
///
/// Measured before widening: adding it reports zero blocks on `src/`, so this
/// buys coverage without an exclusion.
const FUNCTION_ONLY_SECTIONS: &[&str] =
    &["errors", "panics", "returns", "arguments", "side effects"];

/// Does this declaration declare a function?
fn declares_a_function(sig: &str) -> bool {
    static FN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    FN.get_or_init(|| regex::Regex::new(r"\bfn\s+[A-Za-z_]").expect("fn pattern"))
        .is_match(sig)
}

/// The `#` heading text of a doc line, lowercased, if it is one.
fn heading_name(text: &str) -> Option<String> {
    let t = text.trim();
    if !t.starts_with('#') {
        return None;
    }
    Some(t.trim_start_matches('#').trim().to_lowercase())
}

/// No doc block carries a contract section its item cannot have.
///
/// The narrow, certain half of instance 5. Where the second-summary rule reads
/// prose shape and can be argued with, this reads a contract: `# Errors`
/// describes what a call returns `Err` for, `# Panics` what it panics on,
/// `# Returns` and `# Arguments` what it takes and gives back. An `enum` does
/// none of those things. A block carrying one of those headings on a
/// non-function is not badly written, it is **evidence that the block was
/// assembled out of two items** -- and unlike a wrap width or a sentence count,
/// there is nothing to tune.
///
/// It is narrower than instance 5: the block stranded on `RelayStream` carried
/// only `# Why ...` sections, so this would not have caught that one. It is
/// also the only rule in this file that found a defect nobody had reported --
/// see the failure message it produces on `src/privilege.rs`, where the entire
/// doc for `disable_core_dumps`, `# Errors` section included, is sitting on
/// `pub enum MemoryLock`, whose own summary is glued to the tail of that
/// section's last paragraph. That is instance 5's shape exactly, in a second
/// file, found by a rule with no threshold in it.
///
/// # Why `# Safety` is not in the list
///
/// A safe function that wraps an `unsafe` block documents the reasoning under
/// `# Safety` legitimately, and this tree does it once. The exclusion is not
/// taken on trust: the test asserts that site still exists and still has that
/// shape, so if it ever stops being the reason, the exclusion stops being
/// justified and this fails.
#[test]
fn no_doc_block_carries_a_contract_section_its_item_cannot_have() {
    let mut misplaced = Vec::new();
    let mut sections = 0usize;
    let mut blocks = 0usize;
    let mut safety_on_a_safe_fn = 0usize;
    for path in rust_files("src") {
        let src = std::fs::read_to_string(&path).expect("read source file");
        let lines: Vec<&str> = src.lines().collect();
        for (start, body) in doc_blocks_of(&path) {
            blocks += 1;
            let sig = item_below(&lines, start - 1 + body.len());
            let is_fn = declares_a_function(&sig);
            for text in &body {
                let Some(name) = heading_name(text) else {
                    continue;
                };
                if name == "safety" && is_fn && !sig.contains("unsafe") {
                    safety_on_a_safe_fn += 1;
                }
                if !FUNCTION_ONLY_SECTIONS.contains(&name.as_str()) {
                    continue;
                }
                sections += 1;
                if !is_fn {
                    misplaced.push(format!(
                        "  {}:{start}: `# {}` sits on `{}`, which is not a function",
                        show(&path),
                        text.trim().trim_start_matches('#').trim(),
                        sig.chars().take(60).collect::<String>()
                    ));
                }
            }
        }
    }
    assert!(
        blocks >= 10_000,
        "only {blocks} doc block(s) walked (measured 14458 on 2026-08-31); the block scanner has stopped matching"
    );
    assert!(
        sections >= 400,
        "only {sections} function-only section heading(s) found (measured 919 on 2026-08-31); the heading extractor has stopped matching, so this rule is examining nothing"
    );
    assert!(
        safety_on_a_safe_fn >= 1,
        "no `# Safety` section on a safe function remains in src/ (measured 1 on 2026-08-31, `signals::install_handlers`). That site is the entire reason `# Safety` is left out of FUNCTION_ONLY_SECTIONS; with it gone the exclusion is unjustified and should be removed rather than left standing."
    );
    assert!(
        misplaced.is_empty(),
        "these doc blocks carry a section their item cannot have:\n{}\n\n\
         `# Errors`, `# Panics`, `# Returns` and `# Arguments` are claims about \
         a CALL. On a struct or an enum they cannot be about the item they sit \
         on, which means the block was assembled from two items -- an item \
         moved out from under its doc, and the orphan came to rest on the next \
         item's block. Split the block and put each half on what it describes.",
        misplaced.join("\n")
    );
}

/// Every walk in this file found a tree, not an empty directory.
///
/// All four rules above are scans, and a scan that matches nothing agrees with
/// any repository. Each floor is well under the value measured on 2026-08-31 --
/// the measured value is in the message -- so ordinary growth does not move it,
/// while an extractor that has stopped matching fails here rather than
/// reporting a clean tree.
///
/// The undecidable-`cfg` count is pinned from the other side: it is a CEILING,
/// because every `None` is a region this file declines to look inside. It sits
/// at zero today, and a predicate spelling the evaluator does not know would
/// raise it silently -- turning a rule that reads the tree into one that reads
/// part of it.
#[test]
fn every_walk_in_this_file_found_a_plausible_tree() {
    let files = rust_files("src");
    let mut attributes = 0usize;
    let mut blocks = 0usize;
    let mut declarations = 0usize;
    let mut commented = 0usize;
    for path in &files {
        let src = std::fs::read_to_string(path).expect("read source file");
        let lines: Vec<&str> = src.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let t = lines[i].trim();
            if is_outer_attr(t) {
                attributes += 1;
                i = attribute_end(&lines, i);
                continue;
            }
            if is_doc_line(t) {
                blocks += 1;
                while i < lines.len() && is_doc_line(lines[i].trim()) {
                    i += 1;
                }
                continue;
            }
            i += 1;
        }
        for decl in mod_decls(path) {
            declarations += 1;
            if !decl.comment.is_empty() {
                commented += 1;
            }
        }
    }
    let (tree, unknown_cfgs) = wasm_module_tree();
    let compiled = tree.values().filter(|(_, c)| *c == Some(true)).count();
    let excluded = tree.values().filter(|(_, c)| *c == Some(false)).count();

    let measured = [
        ("rust files under src/", files.len(), 150, 221),
        ("outer attributes", attributes, 5_000, 7_560),
        ("doc-comment blocks", blocks, 10_000, 14_396),
        ("`mod NAME;` declarations", declarations, 150, 219),
        ("declarations carrying a comment", commented, 5, 10),
        ("modules the wasm build compiles", compiled, 40, 74),
        ("modules the wasm build excludes", excluded, 60, 146),
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
    assert_eq!(
        unknown_cfgs, 0,
        "{unknown_cfgs} `cfg` predicate(s) on `mod` declarations are ones \
         `eval_wasm_cfg` cannot decide (measured 0 on 2026-08-31). Every one \
         is a subtree `no_module_the_wasm_build_compiles_reaches_a_module_it_excludes` \
         stops reading, and it stops reading it quietly. Teach the evaluator \
         the spelling rather than letting the number drift."
    );
}

/// The last line of a doc block that says anything, ignoring trailing blanks.
fn last_speaking_line(body: &[String]) -> Option<&String> {
    body.iter().rev().find(|l| !l.trim().is_empty())
}

/// Whether a doc block ends on a section heading with no prose under it.
///
/// A pure function of the block's own lines so both the tree scan and the
/// discriminator below drive ONE rule. Two copies of this test would be two
/// chances to disagree about the same shape, and the disagreement would be
/// silent -- the scan would go green while the discriminator proved a rule
/// nothing was actually using.
fn block_ends_on_a_heading(body: &[String]) -> bool {
    last_speaking_line(body).is_some_and(|l| l.trim_start().starts_with("# "))
}

/// No doc block ends on a section heading with nothing under it.
///
/// The failure this gates, from 2026-08-31: a scripted insertion anchored on a
/// CONTINUATION line of `set_parser_limits`'s doc block rather than on the
/// block's first line, so a static and three functions landed in the middle of
/// it. The half left above ended `/// # Side effects` with no prose, and the
/// prose resumed as a separate block further down, above the function it had
/// always described.
///
/// **This rule does NOT catch the instance it was written for, and saying so is
/// the point.** Mutation showed why: the inserted items came WITH their own doc
/// comment, so the two `///` runs were contiguous and merged into one block.
/// That block does not END on a heading, it continues into the newcomer's
/// prose. What fires on that shape is
/// `no_doc_block_carries_a_contract_section_its_item_cannot_have`, whose
/// section list was widened to `# Side effects` for exactly this reason.
///
/// What this rule DOES catch is the sibling variant, which nothing else does:
/// the same insertion made with an item carrying NO doc comment. Then the block
/// really is cut, and its surviving half ends on a heading promising prose that
/// was carried away. A section heading is a promise, so a block ending on one
/// was cut.
///
/// Blocks that legitimately end in a heading do not exist: rustdoc renders an
/// empty section as a bare bold line, which no author writes on purpose. The
/// measured count on a clean tree is zero, which is why this is an equality
/// rather than a ratchet.
#[test]
fn no_doc_block_ends_on_a_section_heading() {
    let mut cut = Vec::new();
    let mut blocks = 0usize;
    let mut with_headings = 0usize;

    for path in rust_files("src") {
        for (line, body) in doc_blocks_of(&path) {
            blocks += 1;
            if body.iter().any(|l| l.trim_start().starts_with("# ")) {
                with_headings += 1;
            }
            let last = last_speaking_line(&body);
            if block_ends_on_a_heading(&body) {
                cut.push(format!(
                    "  {}:{line}: block ends on {:?} with nothing under it",
                    path.display(),
                    last.unwrap_or(&String::new()).trim()
                ));
            }
        }
    }

    // Anti-vacuity: the walk found a real tree and headings really occur, so a
    // zero result means "nothing is cut", not "nothing was read".
    assert!(
        blocks >= 1000,
        "only {blocks} doc block(s) parsed from src/; the walk is wrong"
    );
    assert!(
        with_headings >= 100,
        "only {with_headings} block(s) carry a section heading; the heading \
         predicate has stopped matching and this gate proves nothing"
    );
    assert!(
        cut.is_empty(),
        "these doc blocks end on a section heading, which promises prose that \
         is not there. The usual cause is an insertion anchored on a \
         continuation line of the block rather than on its first line, which \
         cuts the block in half and leaves the rest of it attached to whatever \
         was inserted:\n{}",
        cut.join("\n")
    );
}

/// The heading rule fires on the split that caused it, and spares intact blocks.
///
/// The paired half of `no_doc_block_ends_on_a_section_heading`. That test is an
/// equality against zero, so on a clean tree it passes whether the rule works
/// or matches nothing at all -- and a rule that matches nothing is exactly what
/// a careless narrowing produces. This drives the same predicate over the shape
/// the real failure had.
///
/// The fixture is the real one, reduced: `set_parser_limits` documents
/// `# Arguments` and `# Side effects`, and an insertion anchored on a
/// continuation line landed between the heading and its prose. The half left
/// behind ended on `# Side effects` with nothing under it.
#[test]
fn the_heading_rule_fires_on_a_cut_block_and_spares_an_intact_one() {
    let doc = |lines: &[&str]| -> Vec<String> { lines.iter().map(|l| (*l).to_string()).collect() };

    // The wound: a block cut immediately after a section heading.
    let cut = doc(&[
        "Set parser limits from configuration. Call once at startup.",
        "",
        "# Arguments",
        "",
        "* `max_header_line` — maximum bytes allowed in one unfolded header line.",
        "",
        "# Side effects",
        "",
    ]);
    assert!(
        block_ends_on_a_heading(&cut),
        "the rule must fire on the shape that caused it: a heading promising          prose that an insertion carried away"
    );

    // Same block, whole. The heading is present and so is what it promised.
    let intact = doc(&[
        "Set parser limits from configuration. Call once at startup.",
        "",
        "# Side effects",
        "",
        "Stores both values into the process-global atomics, affecting every",
        "subsequent parse on any thread.",
    ]);
    assert!(
        !block_ends_on_a_heading(&intact),
        "a block whose heading is followed by its prose is not cut"
    );

    // Trailing blank doc lines are ordinary and must not read as a cut.
    let trailing_blanks = doc(&["A summary.", "", "Some prose.", "", ""]);
    assert!(
        !block_ends_on_a_heading(&trailing_blanks),
        "a block ending in blank `///` lines is not cut; only a HEADING with          nothing under it is"
    );

    // A block that is only a summary has no heading to be cut after.
    assert!(
        !block_ends_on_a_heading(&doc(&["Just a summary."])),
        "a block with no heading cannot end on one"
    );

    // The widened contract list is the half that catches the MERGED variant --
    // the one this file's heading rule cannot see. `# Side effects` is on the
    // list because the real cut fell one section short of landing there alone,
    // and had it not, nothing would have fired.
    assert!(
        FUNCTION_ONLY_SECTIONS.contains(&"side effects"),
        "a side effect is a claim about a CALL. Dropping it from the list \
         reopens the exact near miss that put it there: an orphan carrying \
         `# Side effects` and no other contract section, sitting on a static."
    );
}
