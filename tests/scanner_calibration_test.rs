// SPDX-License-Identifier: MIT OR Apache-2.0

//! A new scanner's first red is a claim about the scanner, not about the tree.
//!
//! # The defect this file exists for
//!
//! `claims_of_absence_test` went red four times on its first run. I read all
//! four as findings. All four were bugs in the scanner:
//!
//! 1. `serial_test::serial` — a crate import — was reported as a reference to
//!    a test that had been renamed away. It names nothing in this repository.
//! 2. `some_test::some_fn` was reported the same way. It was placeholder prose
//!    in the scanner's own doc comment. The scanner had found itself.
//! 3. The advertisement gate was reported as defined four times. Those were
//!    four MENTIONS of its name in prose — prose that exists precisely because
//!    the gate does.
//! 4. Five — actually eight — cross-surface test pairs were reported as
//!    duplicates. Every one is legitimate: the REST and MCP surfaces both have
//!    to refuse an expired token, and the shared name is what makes the pair
//!    readable.
//!
//! Four for four. The base rate for "my brand-new scanner found four real
//! problems in a tree that has been green all week" was never plausible, and I
//! did not stop to ask.
//!
//! # Why the fix was itself a hazard
//!
//! I fixed each one by NARROWING the scanner until it went green. That is the
//! move worth guarding. **Narrowing until green is indistinguishable from
//! narrowing until blind** — the run prints the same thing either way. Every
//! exclusion that silences a false positive has exactly the shape of an
//! exclusion that swallows a true one, and once the suite is green nothing
//! will ever ask again.
//!
//! Four narrowings went in and not one of them was shown to still catch
//! anything. So each is driven here from both sides:
//!
//! | narrowing | must exclude | must still catch |
//! |---|---|---|
//! | the referenced file must exist | a crate import | a name that moved |
//! | duplicates key on name AND body | two surfaces, one property | a real copy |
//! | ratchets need an implausible value | two fixtures both holding one | a shared 756 |
//! | count definitions, not mentions | a name in a sentence | a second definition |
//!
//! The left column is what I observed. The right column is what nobody
//! checked, and is the only thing standing between a narrowed scanner and a
//! decorative one.
//!
//! # One more, from writing this
//!
//! Mutating all four predicates, seven of these went red and the `#[cfg]` one
//! did not. The obvious reading was that the test was weak. It was not: the
//! `#[cfg(...)]` line is guarded out by `!t.starts_with('#')` before it ever
//! reaches the statement I had mutated, so the mutation never ran on the path
//! it was named for. A mutation that does not reach the code proves as little
//! as one that does not compile, and it fails in the reassuring direction.

#![cfg(feature = "full")]

use std::collections::BTreeMap;
use std::path::PathBuf;

#[path = "support/absence_scan.rs"]
mod absence_scan;

use absence_scan::{
    COINCIDENCE_CEILING, candidate_tokens, cross_reference, defines, implausible_coincidence,
    ratchet_pins, test_bodies,
};

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file directly under `tests/`.
fn test_files() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(repo().join("tests"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    out.sort();
    out
}

/// Read a file, or the empty string.
fn read(p: &std::path::Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// The real tree's answer to "is there a `tests/<name>.rs`".
fn real_tree(name: &str) -> bool {
    repo().join("tests").join(format!("{name}.rs")).exists()
}

// ── 1. the referenced file must exist ───────────────────────────────

/// A crate import is not a cross-reference, and the exclusion does real work.
///
/// The first half of narrowing one. `serial_test::serial` satisfies every
/// syntactic test a reference does — it ends in `_test`, it has a `::`, the
/// right side is snake_case — and means something entirely different.
///
/// The count matters as much as the verdict. An exclusion that never fires is
/// not protecting the scanner from anything; it is a line someone added to
/// make a red go away, still sitting there after the red became impossible.
#[test]
fn a_crate_import_is_not_a_cross_reference() {
    assert_eq!(
        cross_reference("serial_test::serial", &real_tree),
        None,
        "`serial_test::serial` is a crate import. Reading it as a reference to \
         a test in this repository is how this scanner produced its first \
         false finding."
    );

    // And the exclusion is exercised: the raw scan really does surface it.
    let mut excluded = 0usize;
    for path in test_files() {
        for token in candidate_tokens(&read(&path)) {
            if token
                .split_once("::")
                .is_some_and(|(l, _)| l.ends_with("_test"))
                && cross_reference(&token, &real_tree).is_none()
            {
                excluded += 1;
            }
        }
    }
    assert!(
        excluded > 0,
        "the existence check excluded nothing across the whole tree, so it is \
         not what keeps the scanner quiet and something else is. An exclusion \
         nothing reaches cannot be the reason a suite is green."
    );
}

/// The exclusion turns only on the file it names — not on the token's spelling.
///
/// The second half, and the one that was never checked. If `serial_test::serial`
/// is refused for a reason that would also refuse a real reference, the scanner
/// is blind rather than calibrated.
///
/// So the same token is asked twice under different trees. Under a tree where
/// `tests/serial_test.rs` exists it IS a reference, which pins the exclusion to
/// the stated reason. And a reference into a file that exists, naming a
/// function that does not, still comes back — that is the dangling reference
/// the whole rule is for.
#[test]
fn the_existence_check_still_catches_a_name_that_moved() {
    let everything_exists = |_: &str| true;
    assert_eq!(
        cross_reference("serial_test::serial", &everything_exists),
        Some(("serial_test".into(), "serial".into())),
        "the crate import is excluded by something other than the missing \
         file. Whatever that is would also exclude a genuine reference, and \
         the scanner would be quiet for the wrong reason."
    );

    // The placeholder in the scanner's own prose, same story: excluded because
    // no such file exists, not because it looks like a placeholder.
    assert_eq!(
        cross_reference("some_test::some_fn", &real_tree),
        None,
        "`some_test::some_fn` is documentation, and tests/some_test.rs does \
         not exist"
    );
    assert!(
        cross_reference("some_test::some_fn", &everything_exists).is_some(),
        "the placeholder is being excluded by its spelling. A rule that reads \
         intent from a name will let a real dangling reference through as soon \
         as it happens to be worded like an example."
    );

    // A real file, a function that is not in it: still a finding.
    //
    // Assembled at runtime rather than written out. Spelled as one literal it
    // is a token in this file's source, and the real scan reads this file like
    // any other -- which it did, and reported the fixture as a dangling
    // reference. That was the scanner working correctly on a claim I had
    // fabricated. The fix is to stop fabricating it, NOT to teach the scanner
    // to skip this file: an exclusion carved out for the test that checks the
    // exclusions is how a scanner ends up unable to see its own blind spot.
    let moved = format!("release_completeness_test{}a_gate_that_was_renamed", "::");
    let real = cross_reference(&moved, &real_tree);
    assert_eq!(
        real,
        Some((
            "release_completeness_test".into(),
            "a_gate_that_was_renamed".into()
        )),
        "a reference into a file that exists no longer survives the narrowing, \
         so the dangling-reference rule can never fire again"
    );
}

// ── 2. duplicates key on name AND body ──────────────────────────────

/// Two surfaces may assert the same property under one name.
///
/// The first half of narrowing two, driven by the real tree rather than by a
/// fixture, because the claim being defended is about this repository: every
/// name shared across files carries a different body.
///
/// This replaces a number. The doc comment on the rule said there were five
/// such pairs; nothing had counted them and there are eight. Asserting the
/// property instead of the count means the next pair added does not have to
/// remember to come back here.
#[test]
fn two_surfaces_may_assert_the_same_property_under_one_name() {
    let mut by_name: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for path in test_files() {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        for (name, body) in test_bodies(&read(&path)) {
            by_name.entry(name).or_default().push((file.clone(), body));
        }
    }
    let shared: Vec<_> = by_name.iter().filter(|(_, v)| v.len() > 1).collect();
    assert!(
        !shared.is_empty(),
        "no test name is shared across files, so the name-and-body narrowing \
         is excluding nothing and this repository would be just as green with \
         the stricter rule that was wrong"
    );
    for (name, uses) in shared {
        let bodies: Vec<&String> = uses.iter().map(|(_, b)| b).collect();
        let first = bodies[0];
        assert!(
            bodies.iter().any(|b| *b != first),
            "{name} is defined identically in {:?}. The name-only rule was \
             relaxed because every shared name in this tree named a genuinely \
             different assertion; that is no longer true, and the relaxation \
             is now hiding a real copy.",
            uses.iter().map(|(f, _)| f).collect::<Vec<_>>()
        );
    }
}

/// A genuine copy is still caught after the relaxation.
///
/// The second half. Keying on name AND body is a strictly weaker rule than
/// keying on the name, and the whole question is whether it is still strong
/// enough to catch what it was written for: one property asserted twice,
/// reformatted.
#[test]
fn the_name_and_body_rule_still_fires_on_a_genuine_copy() {
    let original = "#[test]\nfn the_gate_holds() {\n    let v = published_version();\n    assert_eq!(v, newest_tag());\n}\n";
    // Same assertion, reformatted and re-indented: what a copied gate looks
    // like after someone runs a formatter over it.
    let copy = "#[test]\nfn the_gate_holds() {\n        let v = published_version();\n\n        assert_eq!(v, newest_tag());\n}\n";
    let a = test_bodies(original);
    let b = test_bodies(copy);
    assert_eq!(a.len(), 1, "the extractor lost the original");
    assert_eq!(b.len(), 1, "the extractor lost the copy");
    assert_eq!(
        a[0], b[0],
        "two copies of one gate differing only in whitespace no longer key \
         alike, so the duplicate rule would miss exactly the case it exists \
         for -- a gate built without grepping, then formatted"
    );

    // And a real difference must still separate them, or the rule collapses
    // into the name-only rule it replaced.
    let different = "#[test]\nfn the_gate_holds() {\n    assert!(assets_exist());\n}\n";
    assert_ne!(
        test_bodies(original)[0].1,
        test_bodies(different)[0].1,
        "two different assertions share a body key; the narrowing has gone \
         past 'ignore formatting' into 'ignore the test'"
    );
}

// ── 3. ratchets need an implausible value ───────────────────────────

/// Two fixtures may pin a small ratchet at the same value.
///
/// The first half of narrowing three. Two suites that each hold one dialog
/// both pin `= 1`, and that is two ratchets sharing a word rather than one
/// written twice.
#[test]
fn two_fixtures_may_pin_a_small_ratchet_at_one_value() {
    for coincidence in ["0", "1", "2", "20"] {
        assert!(
            !implausible_coincidence(coincidence),
            "a shared ratchet value of {coincidence} is reported as a copy. \
             Small counts collide honestly, and a rule that says otherwise \
             gets deleted by whoever hits it."
        );
    }
    // Exercised by the real tree, or the ceiling is protecting nothing.
    let mut pins: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in test_files() {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        for (name, value) in ratchet_pins(&read(&path)) {
            pins.entry(format!("{name} = {value}"))
                .or_default()
                .push(file.clone());
        }
    }
    assert!(
        !pins.is_empty(),
        "no EXPECTED_* pins found; the parser has stopped matching the form \
         this repository uses and both halves of this narrowing are moot"
    );
}

/// A shared large value is still caught.
///
/// The second half, and the reason the ceiling is a number rather than a
/// blanket exemption. Two files independently arriving at `756` is a copy.
#[test]
fn the_coincidence_ceiling_still_catches_a_shared_large_value() {
    assert!(
        implausible_coincidence("756"),
        "a value of 756 pinned in two files is not coincidence, and the \
         ceiling has been raised until nothing trips it"
    );
    // The boundary, both sides, so the constant cannot drift without this
    // failing.
    let ceiling = COINCIDENCE_CEILING.to_string();
    let above = (COINCIDENCE_CEILING + 1).to_string();
    assert!(
        !implausible_coincidence(&ceiling),
        "the ceiling itself is reported as implausible; the comparison is off \
         by one from what the constant documents"
    );
    assert!(
        implausible_coincidence(&above),
        "one past the ceiling is not reported; the rule is dead above the \
         threshold as well as below it"
    );
    // A non-numeric pin is never coincidence -- nothing arrives at the same
    // expression twice by accident.
    assert!(
        implausible_coincidence("&[\"a\", \"b\"]"),
        "a shared non-numeric ratchet is treated as coincidence. The parse \
         failure is being read as 'small', which exempts every pin the parser \
         does not understand -- silence from a scanner that could not look."
    );
}

// ── 4. count definitions, not mentions ──────────────────────────────

/// A name in prose is not a definition.
///
/// The first half of narrowing four, and the one that produced the strangest
/// failure: the scanner reported the advertisement gate as defined four times
/// because the file explaining why there is exactly one gate named it four
/// times. Documentation about a gate is evidence that it exists, not evidence
/// of a second one.
#[test]
fn a_name_in_prose_is_not_a_definition() {
    let prose = r#"
/// See `the_gate_holds` for the real check.
///
/// A second `the_gate_holds` would be a duplicate.
fn helper() {
    let msg = "the_gate_holds must stay";
    let _ = msg;
}
"#;
    assert_eq!(
        defines(prose, "the_gate_holds"),
        0,
        "three mentions of a name -- two in a doc comment, one in a string \
         literal -- were counted as definitions. That is what made the \
         'exactly once' rule fail on a tree containing exactly one."
    );
    // The real file that triggered it still mentions the gate more than once,
    // so this narrowing is exercised rather than historical.
    let src = read(&repo().join("tests/claims_of_absence_test.rs"));
    let mentions = src
        .matches("the_site_advertises_the_newest_release_whose_assets_exist")
        .count();
    assert!(
        mentions > 1,
        "the file that provoked this now mentions the gate {mentions} time(s); \
         with fewer than two mentions the mention-versus-definition \
         distinction is untested by the real tree"
    );
    assert_eq!(
        defines(
            &src,
            "the_site_advertises_the_newest_release_whose_assets_exist"
        ),
        0,
        "the scanner's own file is being counted as defining the gate it only \
         writes about"
    );
}

/// A second definition is still found.
///
/// The second half. Counting definitions rather than mentions is what makes
/// the "exactly once" rule survivable; it must not have made it unfailable.
/// A duplicated gate is the entire thing `claims_of_absence_test` was written
/// to prevent, so a rule that can no longer see one is worse than none.
#[test]
fn the_definition_counter_still_finds_a_second_definition() {
    let one = "#[test]\nfn the_gate_holds() {\n    assert!(true);\n}\n";
    assert_eq!(defines(one, "the_gate_holds"), 1, "a single definition");

    // Concatenated rather than written as a string continuation. Spelled out,
    // the second physical line of that literal BEGINS with `#[test]`, which
    // arms the very extractor under test -- fixture text a line-oriented
    // scanner cannot tell from a real definition. It was in this file, the one
    // written to guard against exactly that. `fixture_isolation_test` now gates
    // it across the tree.
    let two = format!("{one}\n{}", one.replace("true", "false"));
    let two = two.as_str();
    assert_eq!(
        defines(two, "the_gate_holds"),
        2,
        "two definitions of one gate counted as {} -- the narrowing from \
         mentions to definitions went past 'ignore prose' and now cannot see a \
         real duplicate either",
        defines(two, "the_gate_holds")
    );

    // An attribute between the marker and the fn is still a definition; that
    // is how most gated tests in this tree are written, and losing them would
    // silently shrink every rule that reads definitions.
    let gated =
        "#[test]\n#[cfg(feature = \"full\")]\nfn the_gate_holds() {\n    assert!(true);\n}\n";
    assert_eq!(
        defines(gated, "the_gate_holds"),
        1,
        "a `#[cfg]`-gated test is not seen as a definition, so every rule \
         built on this counter is blind to the feature-gated half of the tree"
    );
}
