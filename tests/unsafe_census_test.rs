// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
//! The walk in `tests/support/unsafe_census.rs` is the only implementation.
//! Both pages are checked against it here, and the homepage against it in
//! `tests/homepage_claim_truth_test.rs`, so they cannot drift apart from each
//! other either: the failure that made this test necessary was two pages
//! quoting two different counts of the same thing, each internally
//! consistent. The tests below are that walk's self-tests.
//!
//! # Two numbers, because they answer different questions
//!
//! The RAW total counts every `unsafe {` in `src/`, which is what
//! `grep -rc 'unsafe {' src/` gives anyone who checks by hand — so the page
//! that tells a reader to recount that way must quote what that command
//! prints. The NON-TEST total excludes code compiled only under `cfg(test)`
//! (the rule is in the support module's documentation), which is the
//! attack surface a fault model is about: `unsafe` inside a test is not
//! reachable by a packet.
#![cfg(feature = "native")]

#[path = "support/unsafe_census.rs"]
mod unsafe_census;

use std::collections::BTreeMap;
use std::path::PathBuf;

use unsafe_census::census;

type TestError = Box<dyn std::error::Error>;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The census counts a block outside a test module.
///
/// The positive half. Without it a walk that skipped everything would report
/// zero, both pages would need to say zero, and the gate would pass while
/// describing a tree with no `unsafe` in it at all.
#[test]
fn the_census_counts_a_block_outside_a_test_module() -> Result<(), TestError> {
    let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    let src = dir.path().join("src");
    std::fs::create_dir(&src).map_err(|e| format!("src/: {e}"))?;
    std::fs::write(
        src.join("a.rs"),
        "fn f() {\n    // SAFETY: fixture.\n    let _ = unsafe { 1 };\n}\n",
    )
    .map_err(|e| format!("write: {e}"))?;

    let (raw, non_test, per_file) = census(&src)?;
    assert_eq!((raw, non_test), (1, 1));
    assert_eq!(per_file.len(), 1, "one file holds it: {per_file:?}");
    Ok(())
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
fn the_census_excludes_a_block_inside_a_cfg_test_module() -> Result<(), TestError> {
    let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    let src = dir.path().join("src");
    std::fs::create_dir(&src).map_err(|e| format!("src/: {e}"))?;
    std::fs::write(
        src.join("b.rs"),
        "fn f() {\n    // SAFETY: fixture.\n    let _ = unsafe { 1 };\n}\n\
         \n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        \
         // SAFETY: fixture.\n        let _ = unsafe { 2 };\n    }\n}\n",
    )
    .map_err(|e| format!("write: {e}"))?;

    let (raw, non_test, per_file) = census(&src)?;
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
    Ok(())
}

/// The walk descends into subdirectories.
///
/// `src/` is nested four deep in places, and a walk that read only the top
/// level would report a small number that looks like a real measurement.
#[test]
fn the_census_descends_into_subdirectories() -> Result<(), TestError> {
    let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    let deep = dir.path().join("src/capture/uprobe");
    std::fs::create_dir_all(&deep).map_err(|e| format!("nested dirs: {e}"))?;
    std::fs::write(
        deep.join("c.rs"),
        "fn f() {\n    // SAFETY: fixture.\n    let _ = unsafe { 3 };\n}\n",
    )
    .map_err(|e| format!("write: {e}"))?;

    let (raw, non_test, _) = census(&dir.path().join("src"))?;
    assert_eq!((raw, non_test), (1, 1), "a nested file must be reached");
    Ok(())
}

/// A tree with no `unsafe` at all censuses to zero, and the gate refuses it.
///
/// Not a hypothetical: the assertion guarding this is the reason a broken walk
/// cannot pass by finding nothing. This proves the census reports the zero
/// honestly, and `the_documented_unsafe_counts_match_the_tree` proves the gate
/// treats that zero as a failure rather than a pass.
#[test]
fn a_tree_with_no_unsafe_censuses_to_zero() -> Result<(), TestError> {
    let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    let src = dir.path().join("src");
    std::fs::create_dir(&src).map_err(|e| format!("src/: {e}"))?;
    std::fs::write(src.join("d.rs"), "fn f() -> u8 {\n    1\n}\n")
        .map_err(|e| format!("write: {e}"))?;

    let (raw, non_test, per_file) = census(&src)?;
    assert_eq!((raw, non_test), (0, 0));
    assert!(per_file.is_empty(), "no file is listed: {per_file:?}");
    Ok(())
}

/// Only `.rs` files are read.
///
/// `src/` carries more than Rust — a `.md`, a build fixture, a `.toml`. A walk
/// that read everything would count the word in a comment or a doc example and
/// report a number no source file backs.
#[test]
fn the_census_reads_only_rust_files() -> Result<(), TestError> {
    let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    let src = dir.path().join("src");
    std::fs::create_dir(&src).map_err(|e| format!("src/: {e}"))?;
    std::fs::write(src.join("notes.md"), "here is `unsafe {` in prose\n")
        .map_err(|e| format!("write: {e}"))?;
    std::fs::write(src.join("data.toml"), "text = \"unsafe {\"\n")
        .map_err(|e| format!("write: {e}"))?;

    let (raw, non_test, per_file) = census(&src)?;
    assert_eq!(
        (raw, non_test),
        (0, 0),
        "a non-Rust file contributes nothing"
    );
    assert!(per_file.is_empty(), "{per_file:?}");
    Ok(())
}

/// `unsafe fn` is not an `unsafe` block.
///
/// The census counts blocks, and `unsafe fn f()` declares a function whose
/// CALLERS need a block — the block is at the call site and gets counted there.
/// Counting the declaration too would double-count every such function, which
/// is the kind of error that inflates a published attack-surface figure while
/// looking like diligence.
#[test]
fn the_census_does_not_count_an_unsafe_fn_declaration() -> Result<(), TestError> {
    let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    let src = dir.path().join("src");
    std::fs::create_dir(&src).map_err(|e| format!("src/: {e}"))?;
    std::fs::write(
        src.join("e.rs"),
        "/// # Safety\n/// Fixture.\npub unsafe fn f() -> u8 {\n    1\n}\n",
    )
    .map_err(|e| format!("write: {e}"))?;

    let (raw, non_test, _) = census(&src)?;
    assert_eq!((raw, non_test), (0, 0), "a declaration is not a block");
    Ok(())
}

/// A `#[cfg(test)]` module nested inside another module is still skipped.
///
/// The brace walk starts counting at the attribute, so a test module that is
/// not at file scope has to unwind the right number of braces. Getting that
/// wrong leaves the walk inside the skipped region for the rest of the file and
/// silently drops every later block — which reads as a smaller attack surface,
/// the direction nobody questions.
#[test]
fn the_census_skips_a_nested_test_module_and_resumes_after_it() -> Result<(), TestError> {
    let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    let src = dir.path().join("src");
    std::fs::create_dir(&src).map_err(|e| format!("src/: {e}"))?;
    std::fs::write(
        src.join("f.rs"),
        "pub mod inner {\n    #[cfg(test)]\n    mod tests {\n        #[test]\n        \
         fn t() {\n            // SAFETY: fixture.\n            let _ = unsafe { 1 };\n        \
         }\n    }\n}\n\nfn after() {\n    // SAFETY: fixture.\n    let _ = unsafe { 2 };\n}\n",
    )
    .map_err(|e| format!("write: {e}"))?;

    let (raw, non_test, _) = census(&src)?;
    assert_eq!(raw, 2, "both blocks are in the file");
    assert_eq!(
        non_test, 1,
        "the nested test module is skipped and the walk resumes after it"
    );
    Ok(())
}

/// Writes each `(path, text)` under a fresh temp dir and censuses its `src/`.
///
/// Returns the temp dir too, so it outlives the census.
fn census_tree(files: &[(&str, &str)]) -> Result<(tempfile::TempDir, CensusResult), TestError> {
    let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    for (rel, text) in files {
        let path = dir.path().join(rel);
        let parent = path.parent().ok_or("a fixture path has a parent")?;
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {rel}: {e}"))?;
        std::fs::write(&path, text).map_err(|e| format!("write {rel}: {e}"))?;
    }
    let result = census(&dir.path().join("src"))?;
    Ok((dir, result))
}

/// The census's result: raw total, non-test total, and per-file non-test.
type CensusResult = (usize, usize, BTreeMap<String, usize>);

/// One shipped block, used as the "after" marker in the fixtures below.
const SHIPPED: &str = "fn shipped() {\n    // SAFETY: fixture.\n    let _ = unsafe { 1 };\n}\n";

/// One block in a file whose only role is to be a test-only module.
const IN_TEST_FILE: &str = "pub fn f() {\n    // SAFETY: fixture.\n    let _ = unsafe { 2 };\n}\n";

/// The per-file map as `(path, count)` pairs, for one-line assertions.
fn files(per_file: &BTreeMap<String, usize>) -> Vec<(&str, usize)> {
    per_file.iter().map(|(k, v)| (k.as_str(), *v)).collect()
}

/// A test-only module kept in its own file is test code, and the attribute
/// that declares it does not swallow the lines after it.
///
/// The defect this file was missing a test for: `#[cfg(test)] pub mod x;` in
/// `src/lib.rs` made the walk count `src/x.rs` as shipped, and because the
/// declaration has no brace the walk stayed "in test" through the next item
/// that did, so the shipped block after it disappeared from the count. Both
/// errors at once can even cancel in the total, which is why the per-file map
/// is asserted too.
#[test]
fn an_out_of_line_test_module_is_test_code() -> Result<(), TestError> {
    let lib = format!("#[cfg(test)] // the tests' helpers\npub mod helper;\n\n{SHIPPED}");
    let (_dir, (raw, non_test, per_file)) =
        census_tree(&[("src/lib.rs", &lib), ("src/helper.rs", IN_TEST_FILE)])?;
    assert_eq!(raw, 2, "the raw total counts both files");
    assert_eq!(non_test, 1, "only the block in lib.rs ships");
    assert_eq!(
        files(&per_file),
        vec![("src/lib.rs", 1)],
        "only lib.rs ships a block; the test-only helper.rs is not listed"
    );
    Ok(())
}

/// The attribute and the declaration on one line, resolved to `x/mod.rs`
/// under a `mod.rs` parent.
#[test]
fn a_one_line_declaration_resolves_to_a_mod_rs_file() -> Result<(), TestError> {
    let parent = format!("#[cfg(test)] pub(crate) mod helper;\n\n{SHIPPED}");
    let (_dir, (raw, non_test, per_file)) = census_tree(&[
        ("src/lib.rs", "pub mod net;\n"),
        ("src/net/mod.rs", &parent),
        ("src/net/helper/mod.rs", IN_TEST_FILE),
    ])?;
    assert_eq!(
        (raw, non_test),
        (2, 1),
        "the raw total counts both files; only net/mod.rs ships"
    );
    assert_eq!(
        files(&per_file),
        vec![("src/net/mod.rs", 1)],
        "helper/mod.rs is the test-only module, so only net/mod.rs is listed"
    );
    Ok(())
}

/// Under a non-`mod.rs` parent `a.rs`, `mod tests;` is `a/tests.rs`, and
/// a doc comment and another attribute between the two do not hide it.
#[test]
fn a_declaration_in_a_non_mod_rs_file_resolves_beside_its_stem() -> Result<(), TestError> {
    let parent = format!("{SHIPPED}\n#[cfg(test)]\n/// Tests.\n#[allow(dead_code)]\nmod tests;\n");
    let (_dir, (raw, non_test, per_file)) = census_tree(&[
        ("src/lib.rs", "pub mod a;\n"),
        ("src/a.rs", &parent),
        ("src/a/tests.rs", IN_TEST_FILE),
    ])?;
    assert_eq!(
        (raw, non_test),
        (2, 1),
        "the raw total counts both files; only a.rs ships"
    );
    assert_eq!(
        files(&per_file),
        vec![("src/a.rs", 1)],
        "a/tests.rs is the test-only module, so only a.rs is listed"
    );
    Ok(())
}

/// A file in `src/bin/` is a crate root, so its `mod x;` is `src/bin/x.rs`,
/// not a directory named for the file.
#[test]
fn a_declaration_in_a_bin_root_resolves_beside_it() -> Result<(), TestError> {
    let (_dir, (raw, non_test, per_file)) = census_tree(&[
        (
            "src/bin/tool.rs",
            &format!("#[cfg(test)]\nmod helper;\n{SHIPPED}"),
        ),
        ("src/bin/helper.rs", IN_TEST_FILE),
    ])?;
    assert_eq!(
        (raw, non_test),
        (2, 1),
        "the raw total counts both files; only tool.rs ships"
    );
    assert_eq!(
        files(&per_file),
        vec![("src/bin/tool.rs", 1)],
        "bin/helper.rs is the test-only module, so only tool.rs is listed"
    );
    Ok(())
}

/// A module declared inside a test-only file is test code too, whatever its
/// own declaration says.
#[test]
fn a_module_declared_by_a_test_only_file_is_test_code() -> Result<(), TestError> {
    let (_dir, (raw, non_test, per_file)) = census_tree(&[
        (
            "src/lib.rs",
            &format!("#[cfg(test)]\nmod helper;\n{SHIPPED}"),
        ),
        ("src/helper.rs", "pub mod deeper;\n"),
        ("src/helper/deeper.rs", IN_TEST_FILE),
    ])?;
    assert_eq!(
        (raw, non_test),
        (2, 1),
        "deeper.rs is declared by a test-only file, so only lib.rs ships"
    );
    assert_eq!(
        files(&per_file),
        vec![("src/lib.rs", 1)],
        "neither helper.rs nor helper/deeper.rs is listed"
    );
    Ok(())
}

/// A module declared without `#[cfg(test)]` is shipped code.
///
/// The positive half: a resolver that marked every out-of-line module as test
/// code would pass every test above and report a tiny attack surface.
#[test]
fn an_ordinary_out_of_line_module_is_shipped_code() -> Result<(), TestError> {
    let (_dir, (raw, non_test, per_file)) = census_tree(&[
        (
            "src/lib.rs",
            "pub mod shipped;\n#[cfg(test)]\nmod helper;\n",
        ),
        ("src/shipped.rs", SHIPPED),
        ("src/helper.rs", IN_TEST_FILE),
    ])?;
    assert_eq!(
        (raw, non_test),
        (2, 1),
        "shipped.rs ships; the test-only helper.rs does not"
    );
    assert_eq!(
        files(&per_file),
        vec![("src/shipped.rs", 1)],
        "only the ordinary module is listed"
    );
    Ok(())
}

/// `#[path = "..."]` names the file, relative to the declaring file's
/// directory, in either attribute order and through `..`.
#[test]
fn a_path_attribute_names_the_test_only_file() -> Result<(), TestError> {
    let lib = "#[cfg(test)]\n#[path = \"fixtures/one.rs\"]\nmod one;\n\
               #[path = \"fixtures/two.rs\"]\n#[cfg(test)]\nmod two;\npub mod net;\n";
    let net = "#[cfg(test)]\n#[path = \"../shared/three.rs\"]\nmod three;\n";
    let (_dir, (raw, non_test, per_file)) = census_tree(&[
        ("src/lib.rs", lib),
        ("src/fixtures/one.rs", IN_TEST_FILE),
        ("src/fixtures/two.rs", IN_TEST_FILE),
        ("src/net/mod.rs", net),
        ("src/shared/three.rs", IN_TEST_FILE),
        ("src/shipped.rs", SHIPPED),
    ])?;
    assert_eq!(
        (raw, non_test),
        (4, 1),
        "three test-only files named by #[path], one shipped file"
    );
    assert_eq!(
        files(&per_file),
        vec![("src/shipped.rs", 1)],
        "no file a #[path] attribute named is listed"
    );
    Ok(())
}

/// A file whose first item is `#![cfg(test)]` is test code.
#[test]
fn an_inner_cfg_test_attribute_makes_the_file_test_code() -> Result<(), TestError> {
    let helper = format!("//! Helpers.\n#![cfg(test)]\n\n{IN_TEST_FILE}");
    let (_dir, (raw, non_test, per_file)) = census_tree(&[
        ("src/lib.rs", &format!("mod helper;\n{SHIPPED}")),
        ("src/helper.rs", &helper),
    ])?;
    assert_eq!(
        (raw, non_test),
        (2, 1),
        "helper.rs opens with #![cfg(test)], so only lib.rs ships"
    );
    assert_eq!(
        files(&per_file),
        vec![("src/lib.rs", 1)],
        "the #![cfg(test)] file is not listed"
    );
    Ok(())
}

/// `#[cfg(test)]` on an item with no braces covers that item only.
///
/// `src/lru.rs` guards a struct FIELD, a struct-literal field and single
/// statements this way, and `src/capture/compare.rs` a `static`. The walk
/// used to stay "in test" from each of those until some later brace group
/// closed, so whatever shipped code followed was dropped from the count.
/// Blocks numbered 1-7 ship; 10-13 sit inside test-only items.
#[test]
fn a_cfg_test_on_a_braceless_item_covers_only_that_item() -> Result<(), TestError> {
    let src = "use std::sync::atomic::{AtomicUsize, Ordering};\n\
               #[cfg(test)]\nuse std::collections::HashMap;\n\
               fn a() {\n    // SAFETY: fixture.\n    let _ = unsafe { 1 };\n}\n\
               pub struct S {\n    #[cfg(test)]\n    walked: AtomicUsize,\n}\n\
               pub struct T {\n    keep: u8,\n    #[cfg(test)]\n    last: AtomicUsize\n}\n\
               fn b() {\n    // SAFETY: fixture.\n    let _ = unsafe { 2 };\n}\n\
               fn c(s: &S) {\n    #[cfg(test)]\n    s.walked.fetch_add(1, Ordering::Relaxed);\n    \
               // SAFETY: fixture.\n    let _ = unsafe { 3 };\n}\n\
               fn d() -> S {\n    S {\n        #[cfg(test)]\n        walked: AtomicUsize::new(0),\n        \
               // SAFETY: fixture.\n        other: unsafe { 4 },\n    }\n}\n\
               #[cfg(test)]\nstatic HOLDS: std::sync::Mutex<Vec<(u8, u8)>> =\n    std::sync::Mutex::new(Vec::new());\n\
               fn e() {\n    // SAFETY: fixture.\n    let _ = unsafe { 5 };\n}\n\
               #[cfg(test)]\nimpl<A, B> Drop for Pair<A, B>\nwhere\n    A: Clone,\n    B: Clone,\n{\n    \
               fn drop(&mut self) {\n        // SAFETY: fixture.\n        let _ = unsafe { 10 };\n    }\n}\n\
               fn f(c: bool) {\n    #[cfg(test)]\n    let x = if c {\n        0\n    } else {\n        \
               // SAFETY: fixture.\n        unsafe { 11 }\n    };\n    \
               // SAFETY: fixture.\n    let _ = unsafe { 6 };\n}\n\
               #[cfg(test)]\nstatic ONE: u8 =\n    // Two parts; the comment is not the end.\n    \
               // SAFETY: fixture.\n    unsafe { 12 };\n\
               #[cfg(test)]\npub(crate) fn g<A, B>(a: A, b: B) {\n    \
               // SAFETY: fixture.\n    let _ = unsafe { 13 };\n}\n\
               fn h() {\n    // SAFETY: fixture.\n    let _ = unsafe { 7 };\n}\n";
    let (_dir, (raw, non_test, per_file)) = census_tree(&[("src/lib.rs", src)])?;
    assert_eq!(
        raw, 11,
        "the raw total counts all eleven blocks, as grep does"
    );
    assert_eq!(
        non_test, 7,
        "blocks 1 to 7 ship; 10 to 13 are in test-only items"
    );
    assert_eq!(
        files(&per_file),
        vec![("src/lib.rs", 7)],
        "every shipped block is in lib.rs"
    );
    Ok(())
}

/// A comment is not a block: `unsafe {` in a `//` or `///` line counts toward
/// the raw total, which is what `grep` prints, and not toward what ships.
#[test]
fn an_unsafe_block_in_a_comment_does_not_ship() -> Result<(), TestError> {
    let src = format!("/// Call it as `unsafe {{ f() }}`.\n// unsafe {{ g() }}\n{SHIPPED}");
    let (_dir, (raw, non_test, _)) = census_tree(&[("src/lib.rs", &src)])?;
    assert_eq!(
        (raw, non_test),
        (3, 1),
        "the raw total counts the two comments, as grep does; only the block ships"
    );
    Ok(())
}

/// Every first word the item shapes name, and what an unnamed one gets.
///
/// The shape decides whether a `,` ends a test-only item. A `Braced` item read
/// as `Listed` would end at the `,` in `impl<A, B>` and count its body as
/// shipped; a field read as `Braced` would run past its own `,`.
#[test]
fn each_first_word_has_its_item_shape() {
    use unsafe_census::{ItemShape, item_shape};
    for word in ["let", "const", "static", "use", "type"] {
        assert_eq!(
            item_shape(&format!("{word} x")),
            ItemShape::Statement,
            "{word}"
        );
    }
    for word in [
        "fn", "impl", "mod", "struct", "enum", "trait", "union", "extern", "unsafe", "async",
    ] {
        assert_eq!(
            item_shape(&format!("{word} x")),
            ItemShape::Braced,
            "{word}"
        );
        assert_eq!(
            item_shape(&format!("pub {word} x")),
            ItemShape::Braced,
            "pub {word}"
        );
        assert_eq!(
            item_shape(&format!("pub(crate) {word} x")),
            ItemShape::Braced,
            "pub(crate) {word}"
        );
    }
    for item in [
        "walked: AtomicUsize,",
        "pub walked: u8,",
        "Udp(UdpSocket),",
        "x.f();",
        "thread_local! {",
    ] {
        assert_eq!(item_shape(item), ItemShape::Listed, "{item}");
    }
    assert_eq!(
        item_shape("function()"),
        ItemShape::Listed,
        "a word that starts with fn"
    );
    assert_eq!(
        item_shape("public: u8,"),
        ItemShape::Listed,
        "a word that starts with pub"
    );
}

/// `#[cfg(all(test, ...))]` is test-only as well, also written over several
/// lines; `#[cfg(any(test, ...))]` is not, because the other arm ships it.
#[test]
fn a_cfg_all_test_module_is_test_code_and_cfg_any_is_not() -> Result<(), TestError> {
    let src = "#[cfg(all(test, target_os = \"linux\"))]\nmod linux_tests {\n    \
               fn t() {\n        // SAFETY: fixture.\n        let _ = unsafe { 1 };\n    }\n}\n\
               #[cfg(any(test, feature = \"x\"))]\nmod either {\n    \
               fn t() {\n        // SAFETY: fixture.\n        let _ = unsafe { 2 };\n    }\n}\n\
               #[cfg(all(\n    test,\n    feature = \"y\"\n))]\n#[allow(\n    dead_code\n)]\nmod spread {\n    \
               fn t() {\n        // SAFETY: fixture.\n        let _ = unsafe { 3 };\n    }\n}\n";
    let (_dir, (raw, non_test, _)) = census_tree(&[("src/lib.rs", src)])?;
    assert_eq!(
        (raw, non_test),
        (3, 1),
        "only the cfg(any) module ships; an attribute spread over lines still counts"
    );
    Ok(())
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
fn the_census_brace_walk_is_lexical_and_this_is_its_boundary() -> Result<(), TestError> {
    let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    let src = dir.path().join("src");
    std::fs::create_dir(&src).map_err(|e| format!("src/: {e}"))?;
    std::fs::write(
        src.join("g.rs"),
        "#[cfg(test)]\nmod tests {\n    const S: &str = \"{\";\n}\n\nfn after() {\n    \
         // SAFETY: fixture.\n    let _ = unsafe { 1 };\n}\n",
    )
    .map_err(|e| format!("write: {e}"))?;

    let (raw, non_test, _) = census(&src)?;
    assert_eq!(raw, 1, "the file holds one block");
    assert_eq!(
        non_test, 0,
        "an unbalanced brace in a skipped region swallows what follows -- the \
         known limitation. sipnab's own src/ has no such literal, which is what \
         makes the walk sound there; if this assertion flips to 1 the walk was \
         made smarter and this test should be updated to say so"
    );
    Ok(())
}

/// Both pages quote the census, and the census is what the tree holds.
#[test]
fn the_documented_unsafe_counts_match_the_tree() -> Result<(), TestError> {
    let (raw, non_test, per_file) = census(&repo().join("src"))?;
    assert!(
        raw > 0 && non_test > 0,
        "the census found nothing, so this test is validating nothing"
    );

    let fault = std::fs::read_to_string(repo().join("docs/fault-model.md"))
        .map_err(|e| format!("docs/fault-model.md is readable: {e}"))?;
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
        .map_err(|e| format!("docs/internals/build-ci-release.md is readable: {e}"))?;
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
    Ok(())
}
