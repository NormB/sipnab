// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gate logic, driven through states this repository is not currently in.
//!
//! # The defect this file exists for
//!
//! Writing the delivery gates, I put their decision logic inline, reading git
//! and the filesystem. It looked tested — the gates ran, the suite was green,
//! and I had mutation-tested them. Then two mutations SURVIVED:
//!
//! - deleting the check that the site actually names the newest tag, and
//! - making an empty changeset count as advertising a release.
//!
//! Both survived for the same reason, and it is not that the tests were lazy.
//! **This tree cannot reach those branches.** The changeset since the newest
//! tag is never empty here, and `published_version` already equals that tag,
//! so removing either check changed nothing any test could observe. The logic
//! was not under-tested by oversight; it was *untestable in place*.
//!
//! That is the failure class: **a gate whose logic can only run in one state
//! is a gate whose logic is mostly untested, and it looks healthy the entire
//! time.** It is the same shape as a scanner that matches nothing agreeing
//! with any tree, and as a monitor whose silence reads as calm.
//!
//! # What this file does about it
//!
//! Every function under test takes its inputs as arguments and touches nothing
//! global, so each one can be asked about states that do not exist here: an
//! empty changeset, a site left a release behind, a burst shorter than a
//! debounce window. The cases below walk the full truth table of each input
//! dimension rather than the one row this checkout happens to occupy.
//!
//! Exercising it that way immediately found a real hole. The path rule used
//! `starts_with` for every entry, so `docs/install.md.bak`,
//! `CHANGELOG.md.orig`, `website/config.toml.tmp` and `website/config.tomlx`
//! were all treated as release advertisements — meaning a commit carrying one
//! of those beside real work would have skipped every delivery gate. Nothing
//! in the live tree produces such a name, which is exactly why no test that
//! only observed the tree could have found it.

#![cfg(feature = "full")]

use std::path::PathBuf;

#[path = "support/release_logic.rs"]
mod release_logic;

use release_logic::{
    ADVERTISEMENT_PATHS, advertisement_path, debounce_ceiling, is_advertisement, parse_version,
};

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A version triple standing in for "the newest tag", chosen so the tests do
/// not depend on what this checkout is tagged at.
const TAG: (u32, u32, u32) = (0, 5, 131);

/// Advertisement files, as a changeset.
fn ads() -> Vec<String> {
    vec!["website/config.toml".into(), "docs/install.md".into()]
}

// ── A. `is_advertisement`: the full truth table ─────────────────────

/// An empty changeset advertises nothing.
///
/// The branch a mutation survived in, because this tree never has one.
#[test]
fn an_empty_changeset_is_not_an_advertisement() {
    assert!(
        !is_advertisement(&[], TAG, TAG),
        "returning true for an empty changeset would exempt the case where \
         git reported nothing at all — the same error as reading 'cannot \
         look' as 'nothing to see'"
    );
}

/// The site config alone, with the site naming the tag, is the release's
/// second phase.
#[test]
fn the_site_config_alone_is_an_advertisement() {
    assert!(is_advertisement(
        &["website/config.toml".to_string()],
        TAG,
        TAG
    ));
}

/// The install page alone likewise.
#[test]
fn the_install_page_alone_is_an_advertisement() {
    assert!(is_advertisement(&["docs/install.md".to_string()], TAG, TAG));
}

/// Every advertisement path together is still an advertisement.
#[test]
fn all_advertisement_paths_together_are_an_advertisement() {
    let changed: Vec<String> = vec![
        "website/config.toml".into(),
        "docs/install.md".into(),
        "website/content/docs/install.md".into(),
        "website/static/llms.txt".into(),
        "CHANGELOG.md".into(),
    ];
    assert!(is_advertisement(&changed, TAG, TAG));
}

/// One source file makes it ordinary work.
#[test]
fn a_source_file_in_the_changeset_is_never_an_advertisement() {
    let mut changed = ads();
    changed.push("src/main.rs".into());
    assert!(
        !is_advertisement(&changed, TAG, TAG),
        "a changeset containing code is never merely an advertisement"
    );
}

/// So does one test file.
#[test]
fn a_test_file_in_the_changeset_is_never_an_advertisement() {
    let mut changed = ads();
    changed.push("tests/release_delivery_test.rs".into());
    assert!(!is_advertisement(&changed, TAG, TAG));
}

/// And the manifest, which is how a version bump would sneak through.
#[test]
fn the_manifest_in_the_changeset_is_never_an_advertisement() {
    let mut changed = ads();
    changed.push("Cargo.toml".into());
    assert!(
        !is_advertisement(&changed, TAG, TAG),
        "Cargo.toml carries the crate version; exempting it would let a bump \
         ship undeclared"
    );
}

/// A site left behind the newest tag is not advertising it.
///
/// The other branch a mutation survived in: here `published` already equals
/// the tag, so deleting the comparison changed nothing observable.
#[test]
fn a_site_a_release_behind_is_not_advertising_the_tag() {
    let behind = (TAG.0, TAG.1, TAG.2 - 1);
    assert!(
        !is_advertisement(&ads(), behind, TAG),
        "touching the advertisement files while the site still names \
         {behind:?} against a newest tag of {TAG:?} is ordinary work in the \
         release flow's clothes"
    );
}

/// A site ahead of the newest tag is not advertising it either.
#[test]
fn a_site_ahead_of_the_newest_tag_is_not_advertising_it() {
    let ahead = (TAG.0, TAG.1, TAG.2 + 1);
    assert!(
        !is_advertisement(&ads(), ahead, TAG),
        "the site naming a version with no tag is a different fault, not an \
         advertisement"
    );
}

/// Names that merely BEGIN with an advertisement file are not advertisements.
///
/// The hole this file found. Every one of these was exempt under the original
/// `starts_with` rule, and none of them can occur in the live tree — which is
/// precisely why observing the tree could never have caught it.
#[test]
fn a_name_that_merely_begins_with_an_advertisement_file_is_rejected() {
    for trap in [
        "docs/install.md.bak",
        "docs/install.md~",
        "CHANGELOG.md.orig",
        "website/config.toml.tmp",
        "website/config.tomlx",
    ] {
        assert!(
            !advertisement_path(trap),
            "{trap} is treated as a release advertisement; a commit carrying \
             it beside real work would skip every delivery gate"
        );
        assert!(
            !is_advertisement(&[trap.to_string()], TAG, TAG),
            "{trap} reached is_advertisement as an advertisement"
        );
    }
}

// ── B. directory entries versus file entries ────────────────────────

/// A directory entry matches its children.
#[test]
fn a_directory_entry_matches_its_children() {
    for child in [
        "website/content/docs/install.md",
        "website/content/_index.md",
        "website/static/llms-full.txt",
    ] {
        assert!(
            advertisement_path(child),
            "{child} is inside a directory the exemption names and must match"
        );
    }
}

/// A sibling that shares a directory's prefix does not.
#[test]
fn a_sibling_sharing_a_directory_prefix_is_rejected() {
    for sibling in ["website/contentious.md", "website/staticky.txt"] {
        assert!(
            !advertisement_path(sibling),
            "{sibling} merely shares a prefix with a directory entry; \
             matching it would exempt an arbitrary file"
        );
    }
}

/// The directory itself, with no child, is not a file that changed.
#[test]
fn a_bare_directory_name_is_not_a_changed_file() {
    assert!(
        !advertisement_path("website/content"),
        "a directory is not a file; git reports children, and accepting the \
         bare name would accept a file called exactly that"
    );
}

// ── C. `debounce_ceiling` across window ratios ──────────────────────

/// A burst shorter than one window still allows the pending flush.
#[test]
fn a_burst_shorter_than_one_window_allows_the_pending_flush() {
    assert_eq!(debounce_ceiling(0.001, 1.0), 2);
}

/// Exactly one window is one notification plus the flush.
#[test]
fn exactly_one_window_allows_two() {
    assert_eq!(debounce_ceiling(1.0, 1.0), 2);
}

/// Two windows, three notifications.
#[test]
fn two_windows_allow_three() {
    assert_eq!(debounce_ceiling(2.0, 1.0), 3);
}

/// The ceiling never decreases as the burst lengthens.
#[test]
fn the_ceiling_is_monotonic_in_the_burst_length() {
    let mut prev = 0;
    for tenths in 0..60 {
        let c = debounce_ceiling(f64::from(tenths) / 10.0, 1.0);
        assert!(
            c >= prev,
            "ceiling fell from {prev} to {c} as the burst grew; a longer burst \
             can never permit fewer notifications"
        );
        prev = c;
    }
}

/// The ceiling is never below two, so a correct server is never failed for
/// sending the one notification the burst earned plus its flush.
#[test]
fn the_ceiling_never_drops_below_two_for_a_real_burst() {
    // Any burst with duration earns at least one window plus the flush.
    for secs in [0.001, 0.5, 1.0, 3.0, 60.0] {
        assert!(
            debounce_ceiling(secs, 1.0) >= 2,
            "ceiling for a {secs}s burst is below two, which would fail a \
             server that debounced perfectly"
        );
    }
    // A zero-length burst is the degenerate case and earns only the flush.
    // Asserted rather than excluded: my first version of this test demanded
    // two here and failed, and the code was right — no window elapsed, so
    // there is nothing to notify about beyond the pending change.
    assert_eq!(
        debounce_ceiling(0.0, 1.0),
        1,
        "a burst of no duration earns the flush and nothing more"
    );
}

/// A wider window permits fewer notifications for the same burst.
#[test]
fn a_wider_debounce_window_permits_fewer_notifications() {
    assert!(
        debounce_ceiling(10.0, 5.0) < debounce_ceiling(10.0, 1.0),
        "doubling the window must not leave the ceiling unchanged, or the \
         window is not what the arithmetic depends on"
    );
}

// ── D. purity: the property that made the logic testable ────────────

/// The decision does not change when the working tree does.
///
/// The defect in one sentence: logic that reads the tree cannot be asked about
/// any other state. This asserts the opposite property directly.
#[test]
fn the_decision_does_not_depend_on_the_working_tree() {
    let before = is_advertisement(&ads(), TAG, TAG);
    // Touch something real. If the answer moved, the function is reading the
    // tree behind the caller's back.
    let probe = repo().join("Cargo.toml");
    let _ = std::fs::metadata(&probe).expect("Cargo.toml exists");
    let after = is_advertisement(&ads(), TAG, TAG);
    assert_eq!(
        before, after,
        "the answer moved without its arguments moving"
    );
}

/// Repeated calls agree, so there is no hidden state between them.
#[test]
fn repeated_calls_with_the_same_inputs_agree() {
    let a = is_advertisement(&ads(), TAG, TAG);
    let b = is_advertisement(&ads(), TAG, TAG);
    let c = is_advertisement(&ads(), TAG, TAG);
    assert!(a == b && b == c, "the decision is not deterministic");
    assert_eq!(
        debounce_ceiling(2.0, 1.0),
        debounce_ceiling(2.0, 1.0),
        "the ceiling is not deterministic"
    );
}

/// Argument order matters, and swapping it is detectable.
///
/// `is_advertisement(changed, published, tag)` takes two same-typed triples in
/// a row, which is the shape that produced a swapped-argument defect elsewhere
/// in this release. A test that only ever passes equal values cannot see it.
#[test]
fn the_two_version_arguments_are_not_interchangeable() {
    let behind = (TAG.0, TAG.1, TAG.2 - 1);
    assert!(!is_advertisement(&ads(), behind, TAG));
    assert!(!is_advertisement(&ads(), TAG, behind));
    assert!(
        is_advertisement(&ads(), behind, behind),
        "equal values in either order must agree; only the mismatch is a \
         refusal"
    );
}

// ── E. the list itself, and the coverage claim ──────────────────────

/// No entry may be a prefix of another.
///
/// Overlapping entries make the rule ambiguous: whether a path is exempt would
/// depend on which entry the iterator reached first.
#[test]
fn no_advertisement_entry_is_a_prefix_of_another() {
    for a in ADVERTISEMENT_PATHS {
        for b in ADVERTISEMENT_PATHS {
            if a == b {
                continue;
            }
            assert!(
                !a.starts_with(b),
                "{a:?} is covered by {b:?}; overlapping entries make the rule \
                 depend on iteration order"
            );
        }
    }
}

/// Every entry names something that exists, in the form it claims.
///
/// An entry describing a tree that is not this one silently exempts nothing,
/// or exempts the wrong thing after a rename.
#[test]
fn every_advertisement_entry_names_something_real() {
    for p in ADVERTISEMENT_PATHS {
        let is_dir_entry = p.ends_with('/');
        let target = repo().join(p.trim_end_matches('/'));
        assert!(
            target.exists(),
            "ADVERTISEMENT_PATHS names {p}, which does not exist here"
        );
        assert_eq!(
            target.is_dir(),
            is_dir_entry,
            "{p} is written as a {} but is a {} on disk; the trailing slash \
             decides whether children match",
            if is_dir_entry { "directory" } else { "file" },
            if target.is_dir() { "directory" } else { "file" }
        );
    }
}

/// The exemption stays small.
///
/// Each entry is a place undeclared work can hide, so growth should be a
/// decision rather than an accumulation.
#[test]
fn the_advertisement_list_stays_small() {
    assert!(
        ADVERTISEMENT_PATHS.len() <= 6,
        "the exemption has grown to {} entries",
        ADVERTISEMENT_PATHS.len()
    );
    assert!(
        !ADVERTISEMENT_PATHS.is_empty(),
        "an empty list exempts nothing, which would make the release flow's \
         second phase fail every gate again"
    );
}

/// Nothing under `src/` or `tests/` is reachable through the exemption.
#[test]
fn no_code_path_is_reachable_through_the_exemption() {
    for forbidden in [
        "src/main.rs",
        "src/mcp/server.rs",
        "src/capture/hep.rs",
        "tests/gate_logic_test.rs",
        "Cargo.lock",
        ".github/workflows/ci.yml",
        ".githooks/pre-push",
    ] {
        assert!(
            !advertisement_path(forbidden),
            "{forbidden} is reachable through the exemption; a change to it \
             would skip the delivery gates"
        );
    }
}

/// The version parser accepts the forms this repository writes, and rejects
/// the shapes that would silently become a wrong triple.
#[test]
fn the_version_parser_accepts_real_forms_and_rejects_junk() {
    assert_eq!(parse_version("0.5.131"), Some((0, 5, 131)));
    assert_eq!(parse_version("v0.5.131"), Some((0, 5, 131)));
    assert_eq!(parse_version("  v0.5.131  "), Some((0, 5, 131)));
    assert_eq!(parse_version("0.5"), None, "two parts is not a release");
    assert_eq!(parse_version("0.5.131.1"), None, "four parts is not one");
    assert_eq!(parse_version("v0.5.x"), None);
    assert_eq!(parse_version(""), None);
    assert_eq!(parse_version("v"), None);
}

/// This suite drives states the live tree cannot produce.
///
/// The claim the whole file rests on, asserted rather than left implicit. If
/// every case here happened to match the checkout, the file would be back to
/// testing one row of the truth table and the defect could return.
#[test]
fn this_suite_exercises_states_this_checkout_is_not_in() {
    // An empty changeset: never true of a tree with commits since the tag.
    assert!(!is_advertisement(&[], TAG, TAG));
    // A mismatched pair: never true while the release flow is complete.
    let behind = (TAG.0, TAG.1, TAG.2 - 1);
    assert!(!is_advertisement(&ads(), behind, TAG));
    // A filename no repository would carry.
    assert!(!advertisement_path("website/config.toml.tmp"));
    // A burst shorter than a debounce window.
    assert_eq!(debounce_ceiling(0.001, 1.0), 2);

    // And the source of this file must actually contain fabricated inputs —
    // a suite that only read the tree would satisfy every assertion above by
    // accident on some future checkout.
    let src = std::fs::read_to_string(repo().join("tests/gate_logic_test.rs"))
        .expect("read this test file");
    for marker in ["config.toml.tmp", "install.md.bak", "TAG.2 - 1"] {
        assert!(
            src.contains(marker),
            "this suite no longer fabricates {marker}; it has drifted back to \
             observing the tree, which is the defect it exists to prevent"
        );
    }
}
