// SPDX-License-Identifier: MIT OR Apache-2.0

//! A suite that never compiled and a suite that passed must not sum to the
//! same number.
//!
//! # The defect this file exists for
//!
//! I ran the full suite and piped it through a small parser that summed the
//! `test result:` lines. The parser printed one line:
//!
//! ```text
//! suite: 0 passed, 0 failed
//! ```
//!
//! I very nearly reported that as a clean run. It was not a run at all. A
//! module move had left an import pointing at a name that is no longer public,
//! so the test targets failed to COMPILE:
//!
//! ```text
//! error[E0603]: struct import `RelayTag` is private
//! error: could not compile `sipnab` (test "relay_seam_test") due to 1 previous error
//! ```
//!
//! cargo prints no `test result:` line for a target it could not build, so the
//! parser summed an empty list. Zero is what a sum over nothing returns, and
//! zero is also what a suite that ran and passed nothing returns. Through that
//! parser those two inputs are one output — and the compile failure is the one
//! that reads like success.
//!
//! # The three siblings
//!
//! This is the fourth instance of one shape in this repository, which is why
//! it is written as a gate and not as a resolution to be more careful.
//!
//! 1. `cargo test --features full corpus` filtered by test NAME while the gate
//!    it was standing in for derives test BINARIES from the tree. It ran 0
//!    tests across 5 binaries and printed `ok` five times.
//! 2. A `cargo test` filter written with regex alternation, `a\|b`, matched
//!    nothing — cargo takes a plain SUBSTRING — and printed `ok` beside
//!    `4448 filtered out`.
//! 3. A shell loop over an empty URL list set no failure flag, exited 0, and
//!    reported that every download link answered 200.
//!
//! # What the siblings own, and what is added here
//!
//! `vacuous_success_test` owns the walk: an empty collection and a clean one
//! must not share a verdict, a name filter selects a different set than a
//! binary derivation, and one `test result:` line reading `0 passed` is not a
//! pass. `verification_hygiene_test` owns the filter ARGUMENT — substring
//! versus regex — and splits the two zero-passed shapes apart, because "the
//! filter selected nothing" and "this binary held nothing" call for different
//! fixes.
//!
//! Both classify ONE LINE, and both begin from output that HAS one. Neither
//! has a verdict for output with no result line in it at all, neither reads a
//! compiler diagnostic, and neither adds two result lines together. That is
//! this file's subject, in three parts:
//!
//! * the absence of every result line is its own verdict, never a zero;
//! * a compile failure is recognizable from the diagnostics cargo prints, and
//!   is distinct from both a clean run and a run with failing tests;
//! * a sum over many result lines means nothing without the COUNT of lines it
//!   summed, because that count is the only part of the answer separating "47
//!   binaries reported" from "no binary reported".

#![cfg(feature = "full")]

use std::path::{Path, PathBuf};

use regex::Regex;

// ── the model: what a whole invocation proved ───────────────────────

/// What a WHOLE cargo invocation proved, as opposed to what one line said.
///
/// Four values, not three, and the fourth is the one the incident needed:
/// `NotVerified` is returned for output that contains no result line and no
/// diagnostic either, so it can never be confused with a `Clean` carrying
/// zeroes.
#[derive(Debug, PartialEq, Eq)]
enum SuiteVerdict {
    /// Every reporting target reported and none failed.
    Clean {
        /// Result lines summed to reach this verdict.
        lines: usize,
        /// Tests that passed across those lines.
        passed: usize,
    },
    /// Tests ran and at least one failed.
    TestsFailed {
        /// Result lines summed to reach this verdict.
        lines: usize,
        /// Tests that passed across those lines.
        passed: usize,
        /// Tests that failed across those lines.
        failed: usize,
    },
    /// The compiler refused at least one target.
    CompileFailed {
        /// Result lines present anyway. Non-zero for a PARTIAL compile, where
        /// some targets built and ran while another never got that far.
        lines: usize,
        /// Refusal diagnostics counted.
        errors: usize,
    },
    /// No result line, and no diagnostic explaining why. Nothing is known.
    NotVerified,
}

impl SuiteVerdict {
    /// Whether this verdict is evidence that the suite ran and passed.
    ///
    /// The `passed > 0` half is `vacuous_success_test`'s subject and is
    /// restated here rather than assumed, so a classifier that grew a whole-run
    /// verdict cannot regress the single-line rule underneath it.
    fn is_evidence(&self) -> bool {
        matches!(self, SuiteVerdict::Clean { lines, passed } if *lines > 0 && *passed > 0)
    }
}

/// A `test result:` line, with its verdict word and its two counts.
fn result_line_pattern() -> Regex {
    Regex::new(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed")
        .expect("the cargo summary pattern must compile")
}

/// A line on which the compiler refused to produce a target.
///
/// Two spellings, both of which cargo prints for the incident's failure: the
/// coded diagnostic itself, and the per-target refusal that names which test
/// binary was lost. `error: aborting due to N previous errors` is deliberately
/// NOT matched — it restates a count already carried by the lines above it, and
/// counting it would inflate `errors` without naming anything new.
fn compile_refusal_pattern() -> Regex {
    Regex::new(r"^(error\[E\d{4}\]|error: could not compile)")
        .expect("the compile-refusal pattern must compile")
}

/// Classify a whole cargo invocation.
///
/// Order matters and is the whole design. A refusal outranks any number of
/// result lines, because a target that did not build reported nothing and its
/// silence is invisible in the sum. Only then does the absence of result lines
/// become `NotVerified`, and only then does the sum get read.
fn classify_run(output: &str) -> SuiteVerdict {
    let result = result_line_pattern();
    let refusal = compile_refusal_pattern();

    let mut lines = 0usize;
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut errors = 0usize;
    let mut failed_word = false;

    for raw in output.lines() {
        let line = raw.trim_start();
        if refusal.is_match(line) {
            errors += 1;
            continue;
        }
        if let Some(caps) = result.captures(line) {
            lines += 1;
            passed += caps[2].parse::<usize>().unwrap_or(0);
            failed += caps[3].parse::<usize>().unwrap_or(0);
            if &caps[1] == "FAILED" {
                failed_word = true;
            }
        }
    }

    if errors > 0 {
        return SuiteVerdict::CompileFailed { lines, errors };
    }
    if lines == 0 {
        return SuiteVerdict::NotVerified;
    }
    if failed > 0 || failed_word {
        return SuiteVerdict::TestsFailed {
            lines,
            passed,
            failed,
        };
    }
    SuiteVerdict::Clean { lines, passed }
}

/// The sum, carrying how many result lines produced it: `(passed, failed, lines)`.
fn sum_with_count(output: &str) -> (usize, usize, usize) {
    let result = result_line_pattern();
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut lines = 0usize;
    for raw in output.lines() {
        if let Some(caps) = result.captures(raw.trim_start()) {
            lines += 1;
            passed += caps[2].parse::<usize>().unwrap_or(0);
            failed += caps[3].parse::<usize>().unwrap_or(0);
        }
    }
    (passed, failed, lines)
}

/// The parser from the incident: the same sum with the count thrown away.
///
/// Written as a projection of `sum_with_count` on purpose. The defect is not a
/// different arithmetic, it is the same arithmetic with one field dropped, and
/// building it this way means the tests below compare a value against itself
/// minus the field rather than against a second implementation that might
/// differ for some other reason.
fn sum_without_count(output: &str) -> (usize, usize) {
    let (passed, failed, _lines) = sum_with_count(output);
    (passed, failed)
}

// ── the fixtures ────────────────────────────────────────────────────

/// A run in which three targets built, ran, and passed.
fn clean_run_output() -> String {
    [
        "   Compiling sipnab v0.5.138 ($HOME/src/sipnab)",
        "    Finished `test` profile [unoptimized + debuginfo] target(s) in 41.02s",
        "     Running unittests src/lib.rs (target/debug/deps/sipnab-1a2b3c4d5e6f7081)",
        "test result: ok. 40 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; \
         finished in 1.21s",
        "     Running tests/relay_seam_test.rs (target/debug/deps/relay_seam_test-90ab)",
        "test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; \
         finished in 0.08s",
        "     Running tests/hep_test.rs (target/debug/deps/hep_test-cdef)",
        "test result: ok. 5 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; \
         finished in 0.03s",
    ]
    .join("\n")
}

/// A run in which everything built and one test failed.
fn failing_run_output() -> String {
    [
        "     Running unittests src/lib.rs (target/debug/deps/sipnab-1a2b3c4d5e6f7081)",
        "test result: ok. 40 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; \
         finished in 1.19s",
        "     Running tests/relay_seam_test.rs (target/debug/deps/relay_seam_test-90ab)",
        "failures:",
        "    the_relay_seam_carries_its_tag",
        "test result: FAILED. 11 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; \
         finished in 0.09s",
    ]
    .join("\n")
}

/// The incident's own output: nothing built, so nothing reported.
///
/// The shape that matters is the ABSENCE — there is not one `test result:`
/// line anywhere in it — and the tests below assert that absence rather than
/// trusting the fixture to have it.
fn compile_failure_output() -> String {
    [
        "   Compiling sipnab v0.5.138 ($HOME/src/sipnab)",
        "error[E0603]: struct import `RelayTag` is private",
        "   --> tests/relay_seam_test.rs:31:26",
        "    |",
        "31 | use sipnab::relay::RelayTag;",
        "   |                    ^^^^^^^^ private struct import",
        "   |",
        "note: the struct import `RelayTag` is defined here",
        "error: could not compile `sipnab` (test \"relay_seam_test\") due to 1 previous error",
        "warning: build failed, waiting for other jobs to finish...",
    ]
    .join("\n")
}

/// Output that reports nothing and explains nothing.
///
/// An invocation killed before it printed, a capture that lost its pipe, a
/// wrapper that swallowed stderr. There is no diagnostic to read and no result
/// to sum, which is exactly the state the incident's parser called zero.
fn silent_output() -> String {
    [
        "   Compiling sipnab v0.5.138 ($HOME/src/sipnab)",
        "    Finished `test` profile [unoptimized + debuginfo] target(s) in 39.44s",
    ]
    .join("\n")
}

/// The dangerous middle: some targets built and passed, one did not build.
fn partial_compile_output() -> String {
    [
        "     Running unittests src/lib.rs (target/debug/deps/sipnab-1a2b3c4d5e6f7081)",
        "test result: ok. 40 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; \
         finished in 1.20s",
        "     Running tests/hep_test.rs (target/debug/deps/hep_test-cdef)",
        "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; \
         finished in 0.03s",
        "     Running tests/api_test.rs (target/debug/deps/api_test-2244)",
        "test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; \
         finished in 0.11s",
        "error[E0603]: struct import `RelayTag` is private",
        "   --> tests/relay_seam_test.rs:31:26",
        "error: could not compile `sipnab` (test \"relay_seam_test\") due to 1 previous error",
    ]
    .join("\n")
}

/// `count` reporting targets, each passing `passed_each` tests.
///
/// Built by concatenation so the size of the fixture is a parameter rather than
/// a wall of literal text: the arithmetic under test is about how MANY lines
/// were summed, and a fixture whose size cannot be varied cannot show that.
fn many_reporting_targets(count: usize, passed_each: usize) -> String {
    let mut out = String::new();
    for i in 0..count {
        out.push_str(&format!(
            "     Running tests/target_{i}_test.rs (target/debug/deps/target_{i}_test-{i:04x})\n"
        ));
        out.push_str(&format!(
            "test result: ok. {passed_each} passed; 0 failed; 0 ignored; 0 measured; \
             0 filtered out; finished in 0.0{}s\n",
            i % 10
        ));
    }
    out
}

/// Result lines recorded from the run behind this incident: 47.
///
/// Reported by the run, not measured here; the arithmetic below does not
/// depend on the exact value, only on it being far from zero. A real figure is
/// used anyway so the fixture is the size of a real suite rather than a
/// three-line toy. The floor this tree can actually be held to is measured
/// separately, by the two scans at the end of this file.
const INCIDENT_RUN_RESULT_LINES: usize = 47;

// ── the corpus this file is anchored to ─────────────────────────────

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file directly under `tests/` — one integration target each.
///
/// `cargo build` compiles none of these.
fn integration_targets() -> Vec<PathBuf> {
    let dir = repo().join("tests");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("tests/ must be readable: {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    out.sort();
    out
}

/// Every `.rs` file under `src/`, recursively.
fn src_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo().join("src"), &mut out);
    out.sort();
    out
}

/// Read a file, or the empty string.
fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Lines that are exactly the bare test marker.
///
/// Bare because `fixture_isolation_test::every_marker_line_in_the_tree_is_bare`
/// makes every marker in this tree bare, so an equality is a complete count
/// here and a prefix test would additionally sweep up fixture text.
fn bare_marker_count(src: &str) -> usize {
    src.lines().filter(|l| l.trim() == "#[test]").count()
}

/// `#[cfg(test)]` attributes whose next non-blank line declares a module.
///
/// The module form specifically, not every `#[cfg(test)]` item: a module is a
/// whole tree of code that only ever exists in a test build, which is the
/// property this file needs.
fn cfg_test_modules(src: &str) -> usize {
    let mut count = 0usize;
    let mut armed = false;
    for line in src.lines() {
        let t = line.trim();
        if t == "#[cfg(test)]" {
            armed = true;
            continue;
        }
        if armed && t.is_empty() {
            continue;
        }
        if armed {
            if t.starts_with("mod ") || t.starts_with("pub mod ") {
                count += 1;
            }
            armed = false;
        }
    }
    count
}

/// Floor under the tree-wide `#[test]` marker count. Measured: 6547 on
/// 2026-08-31 (2380 under `tests/`, 4167 under `src/`). Set well below so
/// ordinary churn never moves it, while a scan that has stopped matching the
/// tree falls through it loudly.
const MIN_TEST_MARKERS: usize = 3000;

/// Floor under the `#[cfg(test)]` module count under `src/`. Measured: 239.
const MIN_CFG_TEST_MODULES: usize = 100;

/// Floor under the integration target count. Measured: 207.
const MIN_INTEGRATION_TARGETS: usize = 100;

// ── the gates ───────────────────────────────────────────────────────

/// Output with no result line is NOT-VERIFIED, never zero-passing-zero-failing.
///
/// The incident in its smallest form. A classifier that answers `Clean` with
/// zeroes for output it found nothing in has spent the reader's only chance to
/// notice: the number it prints is indistinguishable from a real suite that
/// happens to pass nothing. Pinning that the empty case is a DIFFERENT value
/// from a genuine all-pass is what makes "0 passed" impossible to file as a
/// clean run. Consequence if this regresses: a run that never happened is
/// reported as a run that succeeded.
#[test]
fn output_with_no_result_line_is_not_verified_rather_than_zero_passing() {
    let clean = clean_run_output();
    let silent = silent_output();
    let cases: Vec<(&str, &str, SuiteVerdict)> = vec![
        (
            "three targets reported and passed",
            clean.as_str(),
            SuiteVerdict::Clean {
                lines: 3,
                passed: 57,
            },
        ),
        (
            "a build that printed no result line and no diagnostic",
            silent.as_str(),
            SuiteVerdict::NotVerified,
        ),
        ("no output whatsoever", "", SuiteVerdict::NotVerified),
        (
            "one target reported and passed",
            "test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; \
             finished in 0.05s",
            SuiteVerdict::Clean {
                lines: 1,
                passed: 7,
            },
        ),
    ];
    assert!(
        cases.len() >= 4,
        "the case table holds {} row(s); a verdict proven over fewer inputs \
         than it has variants says nothing about which input maps to which",
        cases.len()
    );

    for (what, output, expected) in &cases {
        assert_eq!(
            &classify_run(output),
            expected,
            "misclassified {what}; a verdict this classifier gets wrong is a \
             verdict the caller reports as fact"
        );
    }

    assert_ne!(
        classify_run(&clean),
        classify_run(&silent),
        "a run that passed 57 tests and a run that reported nothing reached \
         the same verdict. That collapse is the incident: the parser summed an \
         empty list, printed the same zeroes a real empty suite prints, and I \
         nearly reported a compile failure as a clean suite."
    );
    assert!(
        !classify_run(&silent).is_evidence(),
        "output containing no result line was accepted as evidence of a pass, \
         so a suite that never ran can be cited as a suite that succeeded"
    );
    assert!(
        classify_run(&clean).is_evidence(),
        "a genuine three-target pass was not accepted as evidence; a \
         classifier that refuses real runs gets switched off, and then nothing \
         is checked at all"
    );
}

/// A compile failure is its own verdict, distinct from clean and from failing.
///
/// Cargo says two things about a target it could not build, `error[E...]` and
/// `error: could not compile`, and it says nothing at all in the one place the
/// parser was reading. So the diagnostics are the evidence, and this pins that
/// reading them yields a third verdict rather than folding into either of the
/// two a result line can produce. Consequence if this regresses: the reader
/// cannot tell "the code is broken" from "the tests are broken" from "the
/// tests are fine", which are three different next actions.
#[test]
fn a_compile_failure_is_a_distinct_verdict_from_clean_and_from_failing_tests() {
    let broken = compile_failure_output();
    let clean = clean_run_output();
    let failing = failing_run_output();

    // The premise first: the fixture must genuinely lack result lines, or this
    // test is about a fixture I mistyped rather than about compile output.
    let (_, _, result_lines) = sum_with_count(&broken);
    assert_eq!(
        result_lines, 0,
        "the compile-failure fixture contains {result_lines} result line(s); \
         cargo prints none for a target it never built, so a fixture with any \
         is not the input this rule is about"
    );
    assert!(
        broken.contains("error[E0603]") && broken.contains("error: could not compile"),
        "the compile-failure fixture lost the diagnostics that identify it; \
         without them this test proves only that empty-ish output is not clean"
    );

    assert_eq!(
        classify_run(&broken),
        SuiteVerdict::CompileFailed {
            lines: 0,
            errors: 2
        },
        "compile-failure output was not recognized as a compile failure. That \
         is the incident exactly: the targets never built, and the verdict \
         reported was arithmetic over nothing."
    );
    assert_ne!(
        classify_run(&broken),
        classify_run(&clean),
        "a compile failure and a clean run share a verdict, so `it built and \
         passed` and `it never built` are the same sentence to the caller"
    );
    assert_ne!(
        classify_run(&broken),
        classify_run(&failing),
        "a compile failure and a failing test share a verdict. They need \
         different next actions -- fix the build, or read the failure -- and a \
         single verdict sends the reader to the wrong one."
    );
    assert_eq!(
        classify_run(&failing),
        SuiteVerdict::TestsFailed {
            lines: 2,
            passed: 51,
            failed: 1
        },
        "a run with one failing test was misread; a classifier that cannot \
         count a failure will not report one"
    );
    assert!(
        !classify_run(&broken).is_evidence(),
        "compile-failure output was accepted as evidence of a pass, which is \
         the exact claim I nearly made"
    );
}

/// A sum over result lines carries how many lines it summed.
///
/// The arithmetic half. Summing is fine; summing without saying how many
/// addends there were is not, because the total alone cannot distinguish a
/// suite where every one of 47 binaries reported zero passes from a suite where
/// no binary reported at all. Both are `0 passed, 0 failed`. This asserts the
/// counted sum tells them apart and that dropping the count -- the single
/// difference between the two functions here -- makes them identical.
/// Consequence if this regresses: the printed total is once again a number
/// whose denominator nobody knows.
#[test]
fn a_summed_result_carries_how_many_result_lines_it_summed() {
    let busy = many_reporting_targets(INCIDENT_RUN_RESULT_LINES, 3);
    let all_zero = many_reporting_targets(INCIDENT_RUN_RESULT_LINES, 0);
    let none = compile_failure_output();

    // The builder is asked what it actually produced rather than the constant
    // it was handed: a generator that silently emitted nothing would leave
    // every comparison below comparing zero against zero.
    let generated = busy.lines().filter(|l| l.contains("test result:")).count();
    assert!(
        generated > 0,
        "the many-target fixture generated {generated} result line(s) for a \
         requested {INCIDENT_RUN_RESULT_LINES}; a rule about summing many \
         lines cannot be shown on none of them"
    );
    assert_eq!(
        sum_with_count(&busy),
        (INCIDENT_RUN_RESULT_LINES * 3, 0, INCIDENT_RUN_RESULT_LINES),
        "the counted sum lost either its total or its line count over a \
         {INCIDENT_RUN_RESULT_LINES}-target run"
    );
    assert_eq!(
        sum_with_count(&all_zero),
        (0, 0, INCIDENT_RUN_RESULT_LINES),
        "a run in which {INCIDENT_RUN_RESULT_LINES} targets each reported zero \
         passes must still report {INCIDENT_RUN_RESULT_LINES} lines summed; \
         without that the reader cannot see that the binaries did report"
    );
    assert_eq!(
        sum_with_count(&none),
        (0, 0, 0),
        "output with no result line reported a non-zero line count, so the \
         count itself is no longer evidence of anything"
    );

    // The distinction, and then its loss.
    assert_ne!(
        sum_with_count(&all_zero),
        sum_with_count(&none),
        "47 binaries reporting nothing and no binary reporting at all reached \
         the same counted answer, so the count is not doing the work it is \
         here to do"
    );
    assert_eq!(
        sum_without_count(&all_zero),
        sum_without_count(&none),
        "dropping the line count no longer collapses the two inputs. If that \
         is now true the incident's parser was not the defect described here \
         -- re-derive this file before deleting it."
    );
    assert_eq!(
        sum_without_count(&none),
        (0, 0),
        "the incident's parser printed something other than `0 passed, 0 \
         failed` for a compile failure; the sentence this whole file exists \
         for is that one"
    );
}

/// A partial compile is not a successful run, however green the total.
///
/// The dangerous middle, and the reason the refusal check outranks the sum.
/// When most targets build and one does not, the output carries real result
/// lines with real passing counts, so every number on the screen goes UP while
/// the coverage goes down. A regression hides there better than anywhere else:
/// the target that would have caught it is the one that never ran, and its
/// silence looks exactly like a target with no failures. Consequence if this
/// regresses: a big green number is reported for a suite that skipped whichever
/// binary the broken import belonged to.
#[test]
fn a_partial_compile_beside_passing_binaries_is_not_a_successful_run() {
    let partial = partial_compile_output();

    let (passed, failed, lines) = sum_with_count(&partial);
    assert_eq!(
        (passed, failed, lines),
        (57, 0, 3),
        "the partial-compile fixture no longer carries passing result lines \
         beside its refusal; without them it is just a compile failure and the \
         middle case is untested"
    );

    assert_eq!(
        classify_run(&partial),
        SuiteVerdict::CompileFailed {
            lines: 3,
            errors: 2
        },
        "a run in which three targets passed and one never built was not \
         reported as a compile failure. The three passing lines are true and \
         they are not the question; the question is the target that is missing \
         from the sum entirely."
    );
    assert_ne!(
        classify_run(&partial),
        SuiteVerdict::Clean {
            lines: 3,
            passed: 57
        },
        "a partial compile reached the same verdict as a clean three-target \
         run, so a suite missing a whole binary reports as a suite that passed"
    );
    assert!(
        !classify_run(&partial).is_evidence(),
        "a partial compile was accepted as evidence of a pass; 57 real passes \
         beside a target that never built is precisely how a regression ships \
         behind a green number"
    );
    assert_eq!(
        sum_without_count(&partial),
        (57, 0),
        "the uncounted parser no longer prints a green total for a partial \
         compile. That would be an improvement, and it would also mean this \
         demonstration has lost its subject -- check before deleting it."
    );
}

/// This tree really does emit many result lines, so a zero is never ordinary.
///
/// The anti-vacuity anchor. Every rule above is proven against fixtures I
/// wrote, and a fixture cannot testify about the repository it sits in: a
/// classifier could be perfect on invented output while the real suite had
/// quietly shrunk to nothing. So the marker count is measured off the tree
/// itself. Consequence if this regresses: `0 passed` becomes a plausible
/// reading of a healthy run, and the whole distinction above stops mattering.
#[test]
fn the_test_marker_count_in_this_tree_is_far_above_zero() {
    let targets = integration_targets();
    assert!(
        !targets.is_empty(),
        "the walk over tests/ found no integration target at all; every count \
         derived from it below would be a floor over an empty tree"
    );
    let sources = src_files();
    assert!(
        !sources.is_empty(),
        "the walk over src/ found no source file at all, so the marker census \
         is being taken over nothing"
    );

    let in_tests: usize = targets.iter().map(|p| bare_marker_count(&read(p))).sum();
    let in_src: usize = sources.iter().map(|p| bare_marker_count(&read(p))).sum();
    let total = in_tests + in_src;

    assert!(
        in_tests > 0 && in_src > 0,
        "the marker scan found {in_tests} marker(s) across {} integration \
         target(s) and {in_src} across {} source file(s). A zero on either \
         side means the scan stopped matching how a test is written, not that \
         the tests are gone.",
        targets.len(),
        sources.len()
    );
    assert!(
        total >= MIN_TEST_MARKERS,
        "the tree holds {total} test marker(s) ({in_tests} under tests/, \
         {in_src} under src/), below the floor of {MIN_TEST_MARKERS}. Either \
         the suite lost most of itself, or this scan no longer reads the tree \
         -- and in the second case every parser tested only against fixtures \
         is unanchored."
    );
}

/// `cargo build` succeeding says nothing about whether the tests compile.
///
/// The other half of the incident, and the reason "it builds" was never
/// evidence. The import that broke was in a test target, so `cargo build` was
/// green throughout: the code it compiles and the code the test targets compile
/// are different sets, and the second one is enormous here. This measures both
/// bodies of test-only code that a plain build never touches. Consequence if
/// this regresses: a green build gets cited as a green suite, which is the
/// state the compile failure went unnoticed in.
#[test]
fn the_tree_holds_test_only_code_that_cargo_build_never_compiles() {
    let sources = src_files();
    assert!(
        !sources.is_empty(),
        "the walk over src/ found no source file, so the count of test-only \
         modules below is a claim about an empty tree"
    );
    let modules: usize = sources.iter().map(|p| cfg_test_modules(&read(p))).sum();
    assert!(
        modules >= MIN_CFG_TEST_MODULES,
        "found {modules} `#[cfg(test)]` module(s) across {} source file(s), \
         below the floor of {MIN_CFG_TEST_MODULES}. `cargo build` compiles \
         none of them, so if this number is really that low then a green build \
         covers almost everything and the distinction this test draws has \
         gone.",
        sources.len()
    );

    let targets = integration_targets();
    assert!(
        targets.len() >= MIN_INTEGRATION_TARGETS,
        "found {} integration target(s) under tests/, below the floor of \
         {MIN_INTEGRATION_TARGETS}. Each is a separate crate that `cargo \
         build` never compiles and that can fail to build on its own, which is \
         how one broken import silenced a whole suite while the build stayed \
         green.",
        targets.len()
    );

    // The two bodies are disjoint and both large: a build being green says
    // nothing about either.
    assert!(
        modules > 0 && !targets.is_empty(),
        "one of the two test-only bodies measured empty ({modules} module(s), \
         {} target(s)); the argument that a build proves nothing rests on both \
         being real",
        targets.len()
    );
}

/// Every fixture and every scan behind these rules examined something.
///
/// This file turned on itself. A gate against reading zero as success that is
/// itself checking nothing would be the purest form of the bug it is named for
/// -- and it is reachable here in two ways at once: a fixture builder that
/// returned an empty string would make every classifier assertion above trivial
/// in the same direction the incident failed, and a tree walk that reached
/// nothing would make both floors vacuous. Every number is put in its own
/// assertion message so a future failure reports what was actually found
/// instead of only that something was wrong.
#[test]
fn every_fixture_and_every_scan_behind_these_rules_is_non_empty() {
    let generated = many_reporting_targets(INCIDENT_RUN_RESULT_LINES, 3);
    let fixtures: Vec<(&str, String)> = vec![
        ("clean_run_output", clean_run_output()),
        ("failing_run_output", failing_run_output()),
        ("compile_failure_output", compile_failure_output()),
        ("silent_output", silent_output()),
        ("partial_compile_output", partial_compile_output()),
        ("many_reporting_targets", generated),
    ];
    assert!(
        fixtures.len() >= 6,
        "the fixture list holds {} entry(ies); a self-check that walks fewer \
         fixtures than this file defines is not checking this file",
        fixtures.len()
    );
    for (name, text) in &fixtures {
        assert!(
            !text.is_empty(),
            "fixture `{name}` is empty, so every assertion built on it passes \
             for the reason this whole file exists to reject"
        );
        let line_count = text.lines().count();
        assert!(
            line_count >= 2,
            "fixture `{name}` holds {line_count} line(s); cargo output shorter \
             than that cannot exercise a multi-line classifier"
        );
    }

    // The fixtures that must contain result lines, and the one that must not.
    let with_results = [
        "clean_run_output",
        "failing_run_output",
        "partial_compile_output",
        "many_reporting_targets",
    ];
    assert!(
        !with_results.is_empty(),
        "the list of result-bearing fixtures is empty, so the loop below \
         checks nothing"
    );
    for name in with_results {
        let (_, _, lines) = sum_with_count(
            &fixtures
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("fixture `{name}` is not in the fixture list"))
                .1,
        );
        assert!(
            lines > 0,
            "fixture `{name}` carries {lines} result line(s); a fixture meant \
             to exercise the sum contributes nothing to it"
        );
    }

    // The tree scans, each reporting what it found.
    let targets = integration_targets();
    let sources = src_files();
    assert!(
        !targets.is_empty() && !sources.is_empty(),
        "the tree walks reached {} integration target(s) and {} source \
         file(s); a floor asserted over an empty walk is satisfied by an empty \
         repository",
        targets.len(),
        sources.len()
    );
    let markers: usize = targets
        .iter()
        .chain(sources.iter())
        .map(|p| bare_marker_count(&read(p)))
        .sum();
    let modules: usize = sources.iter().map(|p| cfg_test_modules(&read(p))).sum();
    assert!(
        markers > 0 && modules > 0,
        "the scans found {markers} test marker(s) and {modules} \
         `#[cfg(test)]` module(s) across {} file(s). A zero here means the \
         extractor stopped matching the tree, and a floor over a zero passes \
         only because nothing was examined.",
        targets.len() + sources.len()
    );
}
