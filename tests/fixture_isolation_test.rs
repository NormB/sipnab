// SPDX-License-Identifier: MIT OR Apache-2.0

//! A repo-scanning gate cannot tell my test fixture from the real thing.
//!
//! # The defect this file exists for
//!
//! `scanner_calibration_test` needed a cross-reference naming a test that does
//! not exist, so I wrote one out as a literal. The real scan walks every file
//! under `tests/`, read mine like any other, and reported a dangling
//! reference. The scanner was right; the claim was mine, invented as test data.
//!
//! That is the fifth time in one day that a gate caught something I had
//! written rather than something the code did, and the first four were the
//! subject of `claims_of_absence_test` and `scanner_calibration_test`. The
//! thing all of them share is not carelessness. It is that **a gate which
//! reads the repository has no way to distinguish an example from an
//! assertion.** Both are text in a file it walks.
//!
//! # The direction nobody had looked at
//!
//! Instance five was loud: the fixture looked like a violation, so a gate
//! failed and I went and looked. The dangerous direction is the other one — a
//! fixture that looks like a gate being SATISFIED. Nothing fails, nobody
//! looks, and a counting gate quietly reports a number that includes something
//! I made up.
//!
//! That direction is reachable. A `#[test] fn phantom()` inside a raw string
//! is counted as a definition by the extractor every duplicate and
//! exactly-once rule is built on, and a `const EXPECTED_X: usize = 756;` inside
//! one is counted as a ratchet pin. Both are demonstrated below rather than
//! asserted.
//!
//! # Instance six, found writing this
//!
//! Measuring the tree for the silent direction turned up exactly one offender,
//! in `scanner_calibration_test` — the file written to guard instance five. A
//! string continuation put `#[test]` at the start of a physical line, which
//! arms the extractor; it produced no phantom only because the next line
//! happened to begin with `assert_eq!` and the recovery path disarmed. One
//! different word and it would have manufactured a test that does not exist,
//! silently, in the file whose subject is scanners being wrong.
//!
//! So the invariant here is structural rather than a matter of care: a line
//! whose text begins with `#[test]` must be nothing but `#[test]`, and the
//! count of those lines must equal the count of definitions the extractor
//! finds. Fixture text then cannot reach a counter without breaking an
//! equality that is checked.

#![cfg(feature = "full")]

use std::path::{Path, PathBuf};

#[path = "support/absence_scan.rs"]
mod absence_scan;

use absence_scan::{cross_reference, defines, ratchet_pins, split_raw_strings, test_fns};

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
fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Lines whose trimmed text starts with the test marker.
///
/// Both a real marker and a fixture that merely begins a line with one.
fn marker_lines(src: &str) -> Vec<String> {
    src.lines()
        .map(str::trim)
        .filter(|t| t.starts_with("#[test]"))
        .map(str::to_string)
        .collect()
}

// ── A. fixture text must not arm the extractor ──────────────────────

/// A marker at the start of a string continuation arms the extractor.
///
/// Instance six, pinned as a demonstration rather than a warning. This is not
/// a claim that the extractor is broken — it is line-oriented on purpose, and
/// a line-oriented reader cannot see quoting. It is a claim that fixture text
/// laid out this way REACHES it, which is what makes the bare-marker rule
/// below structural instead of stylistic.
#[test]
fn a_marker_beginning_a_string_continuation_reaches_the_extractor() {
    // The shape that was in scanner_calibration_test: a Rust string
    // continuation whose second physical line begins with the marker.
    let fixture = "let s = \"...\\n\\\n               #[test]\nfn phantom_gate() {}\n";
    assert_eq!(
        defines(fixture, "phantom_gate"),
        1,
        "the extractor no longer reads a marker at the start of a continuation \
         line. If that is now true the bare-marker rule below has lost its \
         subject, and the demonstration this file rests on is stale."
    );
}

/// A whole test definition inside a raw string is counted as real.
///
/// The silent direction, demonstrated. Nothing about this fixture is
/// syntactically a test — it is a string — and the extractor counts it,
/// because a line-oriented scanner has no notion of quoting.
#[test]
fn a_definition_inside_a_raw_string_is_counted_as_real() {
    let fixture = "fn helper() {\n    let f = r#\"\n#[test]\nfn phantom_gate() {\n    assert!(true);\n}\n\"#;\n}\n";
    assert_eq!(
        defines(fixture, "phantom_gate"),
        1,
        "a definition inside a raw string is no longer counted. That would be \
         a better extractor, and it would also mean the tree-wide equality \
         below is guarding a hole that has closed -- check before deleting it."
    );
}

/// Real definitions beside a fixture are still found.
///
/// The control. A rule that made the extractor ignore fixture text by ignoring
/// more text generally would satisfy the two tests above and break everything
/// built on it.
#[test]
fn real_definitions_beside_a_fixture_are_still_found() {
    let src = "#[test]\nfn real_one() {\n    let f = \"#[test]\";\n    let _ = f;\n}\n\n#[test]\nfn real_two() {\n    assert!(true);\n}\n";
    let found = test_fns(src);
    assert!(
        found.contains(&"real_one".to_string()) && found.contains(&"real_two".to_string()),
        "the extractor lost a real definition sitting next to fixture text: \
         found {found:?}"
    );
}

/// A `#[cfg]` between marker and function is still a definition.
///
/// Most gated tests in this tree are written that way, and an extractor that
/// dropped them would shrink every count built on it without failing anything.
#[test]
fn a_gated_definition_survives_the_attribute_run() {
    let src =
        "#[test]\n#[cfg(feature = \"full\")]\n#[ignore]\nfn gated_one() {\n    assert!(true);\n}\n";
    assert_eq!(
        test_fns(src),
        vec!["gated_one".to_string()],
        "an attribute run between the marker and the function breaks the \
         extractor, so every rule reading definitions is blind to the gated \
         half of the tree"
    );
}

// ── B. the structural invariants that keep fixtures out ─────────────

/// Every marker line in the tree is bare.
///
/// The rule that makes instance six impossible rather than unlikely. A line
/// whose text begins with `#[test]` and continues into something else is
/// fixture text wearing a marker's clothes, and the extractor cannot tell.
///
/// The fix when this fires is in the FIXTURE — build the string by
/// concatenation so no physical line starts with the marker — never in the
/// extractor. Teaching a line-oriented scanner about quoting to accommodate
/// test data is how it stops being able to read the tree.
#[test]
fn every_marker_line_in_the_tree_is_bare() {
    let mut bad = Vec::new();
    for path in test_files() {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        for (i, line) in read(&path).lines().enumerate() {
            let t = line.trim();
            if t.starts_with("#[test]") && t != "#[test]" {
                bad.push(format!("  {file}:{}  {}", i + 1, &t[..t.len().min(72)]));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "these lines begin with the test marker but are not a marker:\n{}\n\n\
         A line-oriented extractor arms on them. Rebuild the fixture so no \
         physical line starts with `#[test]`.",
        bad.join("\n")
    );
}

/// Marker count and definition count agree, file by file.
///
/// I first wrote that this makes the silent direction loud. It does not, and
/// the test asserting so failed: a phantom inside a raw string sits on its own
/// physical line, so it contributes a marker AND a definition and the two
/// counts move together. Raw-string poisoning is caught by
/// `no_raw_string_in_the_tree_declares_a_test` instead.
///
/// What this equality does catch is the pair either side of that: a definition
/// with no bare marker — fixture text arming the extractor from a continuation
/// line, which is instance six — and a marker with no definition, meaning the
/// extractor has stopped reading.
#[test]
fn the_marker_count_and_the_definition_count_agree_in_every_file() {
    let mut off = Vec::new();
    for path in test_files() {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let src = read(&path);
        let markers = marker_lines(&src).len();
        let defs = test_fns(&src).len();
        if markers != defs {
            off.push(format!(
                "  {file}: {markers} marker(s), {defs} definition(s)"
            ));
        }
    }
    assert!(
        off.is_empty(),
        "marker and definition counts disagree:\n{}\n\nA definition without a \
         bare marker is fixture text being counted as a test; a marker without \
         a definition is an extractor that has stopped reading.",
        off.join("\n")
    );
}

/// Stripping raw strings is what separates a phantom from a real definition.
///
/// The correction, kept as a test rather than a note. The marker/definition
/// equality is shown here NOT separating them — both counts are 2 — and the
/// raw-string split is shown doing it. Writing the failed claim down beside
/// the working one is the only way the next reader learns which rule covers
/// which direction.
#[test]
fn stripping_raw_strings_separates_a_phantom_from_a_real_definition() {
    let clean = "#[test]\nfn real_one() {\n    assert!(true);\n}\n";
    let phantom = "#[test]\nfn phantom_gate() {\n    assert!(true);\n}";
    let poisoned =
        format!("{clean}\nfn helper() {{\n    let f = r#\"\n{phantom}\n\"#;\n    let _ = f;\n}}\n");

    assert_eq!(
        marker_lines(&poisoned).len(),
        test_fns(&poisoned).len(),
        "the marker/definition equality was supposed to separate here and does \
         not -- if it now does, this file's account of which rule covers which \
         direction is wrong and should be corrected rather than deleted"
    );
    assert_eq!(
        defines(&poisoned, "phantom_gate"),
        1,
        "the phantom must be visible in the raw source, or there is nothing to \
         separate"
    );

    let (stripped, inner) = split_raw_strings(&poisoned);
    assert_eq!(
        test_fns(&stripped),
        vec!["real_one".to_string()],
        "stripping raw strings did not remove the phantom, so the tree-wide \
         rule built on it is examining poisoned text"
    );
    assert_eq!(
        defines(&stripped, "phantom_gate"),
        0,
        "the phantom survived the strip"
    );
    assert!(
        inner.iter().any(|c| c.contains("phantom_gate")),
        "the stripped content was discarded rather than returned; the rules \
         below need to look INSIDE the strings, not just remove them"
    );
}

/// No raw string in the test tree declares a test.
///
/// The rule the corrected reasoning produces. A definition written inside a
/// string is invisible to the compiler and counted by every line-oriented
/// scanner in this tree, which is the silent direction in its purest form:
/// nothing fails, and a count quietly includes something I made up.
#[test]
fn no_raw_string_in_the_tree_declares_a_test() {
    let mut bad = Vec::new();
    for path in test_files() {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let (_, inner) = split_raw_strings(&read(&path));
        for chunk in inner {
            for line in chunk.lines() {
                if line.trim() == "#[test]" {
                    bad.push(format!(
                        "  {file}: a raw string contains a bare test marker"
                    ));
                }
            }
        }
    }
    bad.dedup();
    assert!(
        bad.is_empty(),
        "these files hide a test definition inside a string:\n{}\n\nThe \
         compiler never sees it and every scanner counts it.",
        bad.join("\n")
    );
}

/// No raw string in the test tree declares a ratchet.
///
/// Same rule, other scanner. This replaces a first attempt that treated
/// INDENTATION as the marker of a fixture; it reported eight pins and all
/// eight were genuine ratchets declared `const` inside their own test
/// function, which is ordinary Rust. Indentation never distinguished fixture
/// from real — being inside a string is what does.
#[test]
fn no_raw_string_in_the_tree_declares_a_ratchet() {
    let mut bad = Vec::new();
    for path in test_files() {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let (_, inner) = split_raw_strings(&read(&path));
        for chunk in inner {
            for line in chunk.lines() {
                if line.trim_start().starts_with("const EXPECTED_") {
                    bad.push(format!("  {file}:  {}", line.trim()));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "these ratchet pins live inside a string:\n{}\n\nThe duplicate-ratchet \
         rule cannot tell them from a real pin.",
        bad.join("\n")
    );
}

/// The raw-string split leaves ordinary code alone.
///
/// The control, and the one that matters most: `"a\r"` ends in the two
/// characters that open a raw string, and an over-eager split would swallow
/// the rest of the file from there — blanking real definitions and turning
/// every rule above into a scan of nothing.
#[test]
fn the_raw_string_split_leaves_ordinary_code_alone() {
    // Two string literals, deliberately. With only one there is no second
    // quote for a bogus raw string to close on, so disabling the boundary rule
    // changes nothing and this control passes while testing nothing -- which
    // is what it did when first written.
    let ordinary = "#[test]\nfn real_one() {\n    let s = \"a\\r\";\n    let t = \"second\";\n    assert!(true);\n}\n";
    let (stripped, inner) = split_raw_strings(ordinary);
    assert!(
        inner.is_empty(),
        "ordinary code was read as containing raw strings: {inner:?}"
    );
    assert_eq!(
        test_fns(&stripped),
        vec!["real_one".to_string()],
        "the split removed part of ordinary code, so every rule reading the \
         stripped text is scanning less than the file"
    );
}

/// The invariants hold for the file that defines them.
///
/// This file is full of fixture text shaped like markers and definitions; it
/// is the most likely place for the next instance. Self-application is not
/// decoration — instance six was in the file written to guard instance five.
#[test]
fn the_invariants_hold_for_the_file_that_defines_them() {
    let src = read(&repo().join("tests/fixture_isolation_test.rs"));
    assert!(!src.is_empty(), "this file must be readable by name");
    for t in src.lines().map(str::trim) {
        assert!(
            !t.starts_with("#[test]") || t == "#[test]",
            "this file breaks its own bare-marker rule at: {t}"
        );
    }
    assert_eq!(
        marker_lines(&src).len(),
        test_fns(&src).len(),
        "this file breaks its own marker/definition equality"
    );
}

// ── C. the other scanners' inputs, same treatment ───────────────────

/// A ratchet pin inside a raw string is read as a pin.
///
/// The same silent direction, in the scanner that decides whether two files
/// have copied a ratchet. Demonstrated, not assumed.
#[test]
fn a_ratchet_pin_inside_a_raw_string_is_read_as_a_pin() {
    let fixture = "fn helper() {\n    let f = r#\"\nconst EXPECTED_TABLES: usize = 756;\n\"#;\n}\n";
    let pins = ratchet_pins(fixture);
    assert_eq!(
        pins.len(),
        1,
        "a pin inside a raw string is no longer parsed. If the parser learned \
         about quoting, the tree-wide rule below is guarding a closed hole."
    );
    assert_eq!(pins[0].0, "EXPECTED_TABLES");
    assert_eq!(pins[0].1, "756");
}

/// The ratchet parser still finds a real pin.
///
/// The control for the rule above.
#[test]
fn the_ratchet_parser_still_finds_a_real_pin() {
    let real = "const EXPECTED_TABLES: usize = 756;\n";
    assert_eq!(
        ratchet_pins(real),
        vec![("EXPECTED_TABLES".to_string(), "756".to_string())],
        "the ratchet parser no longer reads an ordinary pin, so the duplicate \
         rule built on it is examining nothing"
    );
}

// ── D. the loud direction stays loud ────────────────────────────────

/// A cross-reference written into a fixture is still read as a claim.
///
/// Instance five, pinned from the other side. It is tempting to read that
/// failure as "the scanner should skip test data" — it should not. A name
/// written into a file under `tests/` IS text in this repository, and the next
/// reader greps, they do not parse. The scanner was right and the fixture was
/// wrong.
///
/// This test exists so that nobody closes that failure by narrowing the
/// scanner, which is the move `scanner_calibration_test` was written about.
#[test]
fn a_cross_reference_written_into_a_fixture_is_still_a_claim() {
    let exists = |name: &str| repo().join("tests").join(format!("{name}.rs")).exists();
    let token = format!("release_completeness_test{}a_gate_that_was_renamed", "::");
    assert!(
        cross_reference(&token, &exists).is_some(),
        "a reference naming a real test file is no longer read as a claim. \
         Instance five was closed by fixing the fixture; closing it by \
         narrowing the scanner instead would make every genuine dangling \
         reference invisible too."
    );
}

/// The calibration fixture builds its dangling token at runtime.
///
/// The actual fix for instance five, pinned so a later edit that spells the
/// token out fails here — next to the explanation — rather than in a scanner
/// three files away whose message is about renamed gates.
#[test]
fn the_calibration_fixture_builds_its_dangling_token_at_runtime() {
    let src = read(&repo().join("tests/scanner_calibration_test.rs"));
    assert!(
        !src.is_empty(),
        "scanner_calibration_test.rs is missing; the fix this pins is gone \
         along with the file"
    );
    let spelled = format!("release_completeness_test{}a_gate_that_was_renamed", "::");
    assert!(
        !src.contains(&spelled),
        "the calibration fixture spells its dangling reference out as a \
         literal again. That is a claim about this repository naming a test \
         that does not exist, and the real scan reads that file like any other."
    );
}

/// No scanner predicate exempts a file by name.
///
/// The narrowing that would have made instance five "go away" is a filename
/// skip, and it is the one narrowing that can never be justified: a scanner
/// blind to the file that tests it cannot report its own blind spot.
#[test]
fn no_scanner_predicate_exempts_a_file_by_name() {
    let src = read(&repo().join("tests/support/absence_scan.rs"));
    assert!(!src.is_empty(), "the shared predicates must be readable");
    for banned in [
        "scanner_calibration_test",
        "claims_of_absence_test",
        "fixture_isolation_test",
    ] {
        let hits: Vec<&str> = src
            .lines()
            .filter(|l| l.contains(banned) && !l.trim_start().starts_with("//"))
            .collect();
        assert!(
            hits.is_empty(),
            "absence_scan.rs names {banned} outside a comment: {hits:?}. A \
             predicate that knows which file is asking cannot be trusted by \
             any of them."
        );
    }
}

/// The scanners really do read the files that test them.
///
/// The claim above is only worth something if these files are in scope. An
/// exclusion is one way to be blind; simply never walking the file is another,
/// and it leaves no line of code to grep for.
#[test]
fn the_scanners_read_the_files_that_test_them() {
    let files = test_files();
    assert!(
        files.len() >= 40,
        "the walk reached only {} file(s) under tests/; every tree-wide rule \
         in this file is vacuous on a corpus that size",
        files.len()
    );
    for required in [
        "scanner_calibration_test.rs",
        "claims_of_absence_test.rs",
        "fixture_isolation_test.rs",
    ] {
        assert!(
            files.iter().any(|p| p.file_name().unwrap() == required),
            "{required} is not in the walked set, so every rule that claims to \
             cover it covers nothing"
        );
    }
}

/// A self-exemption states its reason.
///
/// One file in this tree legitimately excludes itself: `corpus_skip_notice_test`
/// contains the notice text it searches for, so scanning itself would always
/// match. That is a real exemption with a real reason, and the rule is not
/// that exemptions are forbidden — it is that an unexplained one is
/// indistinguishable from a red someone silenced.
#[test]
fn a_self_exemption_states_its_reason() {
    for path in test_files() {
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let src = read(&path);
        // Does the file name itself in code (not prose)?
        let self_named = src
            .lines()
            .any(|l| l.contains(&format!("\"{file}\"")) && !l.trim_start().starts_with("//"));
        if !self_named {
            continue;
        }
        let explained =
            src.contains("//!") || src.lines().any(|l| l.trim_start().starts_with("//"));
        assert!(
            explained,
            "{file} excludes itself from a scan with no comment saying why. An \
             unexplained self-exemption reads the same as a silenced failure."
        );
    }
}

/// A name in a doc comment is not a definition.
///
/// The mention-versus-definition distinction, applied to the form this
/// repository actually writes: `///` and `//!` blocks that name gates. Those
/// exist because the gate does, and counting them was what made the
/// exactly-once rule fail on a tree containing exactly one.
#[test]
fn a_name_in_a_doc_comment_is_not_a_definition() {
    let src = "//! See `phantom_gate` for the real check.\n\n/// Unlike `phantom_gate`, this one runs.\n#[test]\nfn real_one() {\n    assert!(true);\n}\n";
    assert_eq!(
        defines(src, "phantom_gate"),
        0,
        "a name mentioned twice in doc comments is being counted as a \
         definition"
    );
    assert_eq!(
        defines(src, "real_one"),
        1,
        "the real definition beside those mentions was lost"
    );
}
