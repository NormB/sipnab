// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `unsafe` counts the documentation quotes are the counts the tree holds.
//!
//! Two published pages state how much `unsafe` this crate carries, and on
//! 2026-09-06 they disagreed with the tree and with each other:
//! `docs/internals/build-ci-release.md` said 49 (the tree held 92) and
//! `docs/fault-model.md` said 16 in five files (the tree held 77 across 20).
//! Both were written from a measurement that was true once, and neither had
//! anything watching it — which is how a number that looks measured survives
//! long after it stopped being true.
//!
//! # One census, two consumers
//!
//! The walk below is the only implementation. Both pages are checked against
//! it, so they cannot drift apart from each other either: the failure that
//! made this test necessary was two pages quoting two different counts of the
//! same thing, each internally consistent.
//!
//! # Two numbers, because they answer different questions
//!
//! The RAW total counts every `unsafe {` in `src/`, which is what
//! `grep -rc 'unsafe {' src/` gives anyone who checks by hand — so the page
//! that tells a reader to recount that way must quote what that command
//! prints. The NON-TEST total excludes `#[cfg(test)]` modules, which is the
//! attack surface a fault model is about: `unsafe` inside a test is not
//! reachable by a packet.
#![cfg(feature = "native")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One `unsafe` census over `src/`.
///
/// Returns `(raw_total, non_test_total, per_file_non_test)`.
///
/// `#[cfg(test)]` modules are skipped by brace depth from the attribute's
/// opening brace. That is a lexical walk rather than a parse, so it would
/// mis-handle a `{` inside a string literal in the skipped region — no such
/// case exists in this tree, and a parser dependency to count braces is a
/// worse trade than this comment.
fn census(root: &Path) -> (usize, usize, BTreeMap<String, usize>) {
    let mut raw = 0;
    let mut non_test = 0;
    let mut per_file: BTreeMap<String, usize> = BTreeMap::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src/ is readable") {
            let path = entry.expect("a readable entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("a readable .rs file");
            let mut in_test = false;
            let mut depth: i64 = 0;
            let mut opened = false;
            let mut here = 0;
            for line in text.lines() {
                raw += line.matches("unsafe {").count();
                if !in_test && line.trim() == "#[cfg(test)]" {
                    in_test = true;
                    depth = 0;
                    opened = false;
                    continue;
                }
                if in_test {
                    depth += line.matches('{').count() as i64;
                    depth -= line.matches('}').count() as i64;
                    if line.contains('{') {
                        opened = true;
                    }
                    if opened && depth <= 0 {
                        in_test = false;
                    }
                    continue;
                }
                here += line.matches("unsafe {").count();
            }
            if here > 0 {
                non_test += here;
                per_file.insert(
                    path.strip_prefix(root.parent().expect("src has a parent"))
                        .expect("under the repo root")
                        .display()
                        .to_string(),
                    here,
                );
            }
        }
    }
    (raw, non_test, per_file)
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The census counts a block outside a test module.
///
/// The positive half. Without it a walk that skipped everything would report
/// zero, both pages would need to say zero, and the gate would pass while
/// describing a tree with no `unsafe` in it at all.
#[test]
fn the_census_counts_a_block_outside_a_test_module() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir(&src).expect("src/");
    std::fs::write(
        src.join("a.rs"),
        "fn f() {\n    // SAFETY: fixture.\n    let _ = unsafe { 1 };\n}\n",
    )
    .expect("write");

    let (raw, non_test, per_file) = census(&src);
    assert_eq!((raw, non_test), (1, 1));
    assert_eq!(per_file.len(), 1, "one file holds it: {per_file:?}");
}

/// A block inside a `#[cfg(test)]` module counts toward the raw total and NOT
/// toward the non-test total.
///
/// The negative half, and the one that matters: `unsafe` inside a test is not
/// reachable by a packet, so a fault model that counted it would overstate the
/// attack surface. A walk whose skip silently stopped working would raise the
/// non-test number, both pages would be "corrected" to the larger figure, and
/// the published claim about this crate's attack surface would quietly become
/// wrong — which is exactly the drift this file exists to stop.
#[test]
fn the_census_excludes_a_block_inside_a_cfg_test_module() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir(&src).expect("src/");
    std::fs::write(
        src.join("b.rs"),
        "fn f() {\n    // SAFETY: fixture.\n    let _ = unsafe { 1 };\n}\n\
         \n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        \
         // SAFETY: fixture.\n        let _ = unsafe { 2 };\n    }\n}\n",
    )
    .expect("write");

    let (raw, non_test, per_file) = census(&src);
    assert_eq!(raw, 2, "the raw total counts both");
    assert_eq!(
        non_test, 1,
        "the non-test total counts only the reachable one"
    );
    assert_eq!(
        per_file.values().copied().collect::<Vec<usize>>(),
        vec![1],
        "and the per-file breakdown agrees: {per_file:?}"
    );
}

/// The walk descends into subdirectories.
///
/// `src/` is nested four deep in places, and a walk that read only the top
/// level would report a small number that looks like a real measurement.
#[test]
fn the_census_descends_into_subdirectories() {
    let dir = tempfile::tempdir().expect("temp dir");
    let deep = dir.path().join("src/capture/uprobe");
    std::fs::create_dir_all(&deep).expect("nested dirs");
    std::fs::write(
        deep.join("c.rs"),
        "fn f() {\n    // SAFETY: fixture.\n    let _ = unsafe { 3 };\n}\n",
    )
    .expect("write");

    let (raw, non_test, _) = census(&dir.path().join("src"));
    assert_eq!((raw, non_test), (1, 1), "a nested file must be reached");
}

/// A tree with no `unsafe` at all censuses to zero, and the gate refuses it.
///
/// Not a hypothetical: the assertion guarding this is the reason a broken walk
/// cannot pass by finding nothing. This proves the census reports the zero
/// honestly, and `the_documented_unsafe_counts_match_the_tree` proves the gate
/// treats that zero as a failure rather than a pass.
#[test]
fn a_tree_with_no_unsafe_censuses_to_zero() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir(&src).expect("src/");
    std::fs::write(src.join("d.rs"), "fn f() -> u8 {\n    1\n}\n").expect("write");

    let (raw, non_test, per_file) = census(&src);
    assert_eq!((raw, non_test), (0, 0));
    assert!(per_file.is_empty(), "no file is listed: {per_file:?}");
}

/// Only `.rs` files are read.
///
/// `src/` carries more than Rust — a `.md`, a build fixture, a `.toml`. A walk
/// that read everything would count the word in a comment or a doc example and
/// report a number no source file backs.
#[test]
fn the_census_reads_only_rust_files() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir(&src).expect("src/");
    std::fs::write(src.join("notes.md"), "here is `unsafe {` in prose\n").expect("write");
    std::fs::write(src.join("data.toml"), "text = \"unsafe {\"\n").expect("write");

    let (raw, non_test, per_file) = census(&src);
    assert_eq!(
        (raw, non_test),
        (0, 0),
        "a non-Rust file contributes nothing"
    );
    assert!(per_file.is_empty(), "{per_file:?}");
}

/// `unsafe fn` is not an `unsafe` block.
///
/// The census counts blocks, and `unsafe fn f()` declares a function whose
/// CALLERS need a block — the block is at the call site and gets counted there.
/// Counting the declaration too would double-count every such function, which
/// is the kind of error that inflates a published attack-surface figure while
/// looking like diligence.
#[test]
fn the_census_does_not_count_an_unsafe_fn_declaration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir(&src).expect("src/");
    std::fs::write(
        src.join("e.rs"),
        "/// # Safety\n/// Fixture.\npub unsafe fn f() -> u8 {\n    1\n}\n",
    )
    .expect("write");

    let (raw, non_test, _) = census(&src);
    assert_eq!((raw, non_test), (0, 0), "a declaration is not a block");
}

/// A `#[cfg(test)]` module nested inside another module is still skipped.
///
/// The brace walk starts counting at the attribute, so a test module that is
/// not at file scope has to unwind the right number of braces. Getting that
/// wrong leaves the walk inside the skipped region for the rest of the file and
/// silently drops every later block — which reads as a smaller attack surface,
/// the direction nobody questions.
#[test]
fn the_census_skips_a_nested_test_module_and_resumes_after_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir(&src).expect("src/");
    std::fs::write(
        src.join("f.rs"),
        "pub mod inner {\n    #[cfg(test)]\n    mod tests {\n        #[test]\n        \
         fn t() {\n            // SAFETY: fixture.\n            let _ = unsafe { 1 };\n        \
         }\n    }\n}\n\nfn after() {\n    // SAFETY: fixture.\n    let _ = unsafe { 2 };\n}\n",
    )
    .expect("write");

    let (raw, non_test, _) = census(&src);
    assert_eq!(raw, 2, "both blocks are in the file");
    assert_eq!(
        non_test, 1,
        "the nested test module is skipped and the walk resumes after it"
    );
}

/// The documented limitation, pinned rather than assumed away.
///
/// `census` walks braces lexically, so a `{` inside a string literal in a
/// skipped region would unbalance it. No such case exists in this tree, which
/// is why the walk is acceptable — but "no such case exists" is a claim that
/// decays, and a reader who finds this test knows the shape to look for. If
/// this ever starts failing, the walk needs a real parser rather than a wider
/// regex.
#[test]
fn the_census_brace_walk_is_lexical_and_this_is_its_boundary() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir(&src).expect("src/");
    std::fs::write(
        src.join("g.rs"),
        "#[cfg(test)]\nmod tests {\n    const S: &str = \"{\";\n}\n\nfn after() {\n    \
         // SAFETY: fixture.\n    let _ = unsafe { 1 };\n}\n",
    )
    .expect("write");

    let (raw, non_test, _) = census(&src);
    assert_eq!(raw, 1, "the file holds one block");
    assert_eq!(
        non_test, 0,
        "an unbalanced brace in a skipped region swallows what follows -- the \
         known limitation. sipnab's own src/ has no such literal, which is what \
         makes the walk sound there; if this assertion flips to 1 the walk was \
         made smarter and this test should be updated to say so"
    );
}

/// Both pages quote the census, and the census is what the tree holds.
#[test]
fn the_documented_unsafe_counts_match_the_tree() {
    let (raw, non_test, per_file) = census(&repo().join("src"));
    assert!(
        raw > 0 && non_test > 0,
        "the census found nothing, so this test is validating nothing"
    );

    let fault = std::fs::read_to_string(repo().join("docs/fault-model.md"))
        .expect("docs/fault-model.md is readable");
    let expected = format!(
        "{non_test} blocks outside `#[cfg(test)]`, across {} files",
        per_file.len()
    );
    assert!(
        fault.contains(&expected),
        "docs/fault-model.md must say \"{expected}\" — the tree holds \
         {non_test} across {} files",
        per_file.len()
    );

    let ci = std::fs::read_to_string(repo().join("docs/internals/build-ci-release.md"))
        .expect("docs/internals/build-ci-release.md is readable");
    let raw_claim = format!("{raw} `unsafe` blocks");
    assert!(
        ci.contains(&raw_claim),
        "docs/internals/build-ci-release.md tells the reader to recount with \
         `grep -rc 'unsafe {{' src/`, so it must quote what that prints: \
         \"{raw_claim}\""
    );

    // The three largest groups are named on the fault model, and a rename or a
    // migration moves them without moving the total.
    let mut ranked: Vec<(&String, &usize)> = per_file.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    for (path, count) in ranked.iter().take(3) {
        let claim = format!("({count})");
        assert!(
            fault.contains(path.as_str()) && fault.contains(&claim),
            "docs/fault-model.md names the three largest `unsafe` groups; \
             {path} holds {count} and the page does not say so"
        );
    }
}
