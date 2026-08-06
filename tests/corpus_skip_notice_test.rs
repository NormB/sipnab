// SPDX-License-Identifier: MIT OR Apache-2.0

//! The corpus skip must be audible.
//!
//! `tests/support/corpus.rs` explains the defect: the corpus-backed suites
//! printed "SIPNAB_CORPUS not set — skipping" from inside a test body, libtest
//! captured that per test and discarded it on success, and nine binaries
//! reported `ok` while proving nothing about real traffic. One of them had
//! been failing on every real capture the whole time.
//!
//! Three properties are gated here:
//!
//! 1. The notice reaches a stderr that libtest's capture would have swallowed
//!    — proved by running a probe in a child process *without* `--nocapture`,
//!    which is the exact condition the old `eprintln!` died under.
//! 2. It is emitted once per binary, not once per test.
//! 3. No test source rolls its own silent corpus gate.
//!
//! An absent corpus stays a *skip*, never a failure: a contributor who does
//! not have the captures must still get a green suite, and a red one would
//! only teach the next person to delete the gate.
#![cfg(feature = "native")]

use std::process::Command;

#[path = "support/corpus.rs"]
mod corpus_support;

/// Test sources exempt from the "wires the shared corpus gate" rule below,
/// each for a stated reason. An exemption is a decision someone has to read,
/// which is the point of listing them here rather than loosening the scan.
const EXEMPT: &[(&str, &str)] = &[
    (
        "corpus_skip_notice_test.rs",
        "this file — it gates the notice rather than consuming it",
    ),
    (
        "fuzz_corpus_replay.rs",
        "a cargo-fuzz corpus, unrelated to the capture corpus; never reads SIPNAB_CORPUS",
    ),
    (
        "synthetic_corpus_test.rs",
        "builds the committed synthetic captures; runs unconditionally, gated on nothing",
    ),
    (
        "corpus_push_gate_test.rs",
        "gates the pre-push corpus block by extracting and running it with a stub cargo; \
         it never reads a corpus itself, so it has nothing to skip",
    ),
];

/// Read a file under `tests/`.
fn read(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Every `tests/*.rs` filename, sorted.
fn test_sources() -> Vec<String> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut out: Vec<String> = std::fs::read_dir(&dir)
        .expect("read tests/")
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".rs"))
        .collect();
    out.sort();
    out
}

/// The probe the child-process tests run. Ignored, so it never fires in a
/// normal pass of this binary — its whole job is to be spawned.
///
/// It calls the gate twice on purpose: the notice must collapse to one line
/// however many corpus tests a binary holds.
#[test]
#[ignore = "spawned as a child by the notice tests in this file"]
fn corpus_skip_notice_probe() {
    assert!(
        corpus_support::root().is_none(),
        "the probe must run with {} unset",
        corpus_support::ENV_VAR
    );
    assert!(corpus_support::root().is_none());
}

/// Run the probe in a child process with the corpus unset and no
/// `--nocapture`, and return its `(stderr, exit code)`.
fn run_probe() -> (String, Option<i32>) {
    let exe = std::env::current_exe().expect("current_exe");
    let out = Command::new(exe)
        .args(["corpus_skip_notice_probe", "--exact", "--ignored"])
        .env_remove(corpus_support::ENV_VAR)
        .output()
        .expect("spawn self");
    (
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

/// The notice survives libtest's output capture.
///
/// This is the regression gate for the original defect. `eprintln!` goes
/// through the print machinery libtest redirects per test and drops on
/// success, so an implementation that used it would leave this child's stderr
/// empty even though the code "printed" a warning.
#[test]
fn the_skip_notice_survives_libtests_output_capture() {
    let (stderr, code) = run_probe();
    assert!(
        stderr.contains(corpus_support::NOTICE_MARKER),
        "a corpus skip left no trace on stderr under libtest capture — the notice is \
         back to being invisible. Child stderr was: {stderr:?}"
    );
    assert!(
        stderr.contains(corpus_support::ENV_VAR),
        "the notice must name the variable that would turn the gates on: {stderr:?}"
    );
    assert_eq!(
        code,
        Some(0),
        "a missing corpus must remain a skip, not a failure"
    );
}

/// One line per binary, not one per test — the probe gates twice.
#[test]
fn the_skip_notice_is_printed_once_per_binary() {
    let (stderr, _) = run_probe();
    assert_eq!(
        stderr.matches(corpus_support::NOTICE_MARKER).count(),
        1,
        "the notice must be emitted exactly once per test binary however many \
         corpus tests it holds; stderr was: {stderr:?}"
    );
}

/// The wording carries the three things a reader needs: which variable, which
/// suite, and that green here does not mean validated.
#[test]
fn the_notice_names_the_binary_and_denies_full_validation() {
    let line = corpus_support::notice_line("example_corpus_test");
    assert_eq!(
        line.lines().count(),
        1,
        "the notice must be one line: {line}"
    );
    for needle in [
        corpus_support::ENV_VAR,
        "example_corpus_test",
        corpus_support::NOTICE_MARKER,
        "not full validation",
    ] {
        assert!(line.contains(needle), "notice omits {needle:?}: {line}");
    }
}

/// No test source rolls its own corpus gate.
///
/// Reading `SIPNAB_CORPUS` directly is how a *new* corpus suite would go
/// silent again without touching anything this file watches, so the read is
/// centralised and the bypass is a build-time-visible failure.
#[test]
fn no_test_source_reads_the_corpus_variable_directly() {
    let mut offenders = Vec::new();
    for name in test_sources() {
        let src = read(&name);
        if src.contains(&format!("var(\"{}\")", corpus_support::ENV_VAR))
            || src.contains(&format!("var_os(\"{}\")", corpus_support::ENV_VAR))
        {
            offenders.push(name);
        }
    }
    assert!(
        offenders.is_empty(),
        "these read {} directly instead of going through tests/support/corpus.rs, so \
         their skip is not announced: {offenders:?}",
        corpus_support::ENV_VAR
    );
}

/// The old silent form is gone and stays gone.
#[test]
fn no_test_source_prints_the_skip_through_libtests_capture() {
    let mut offenders = Vec::new();
    for name in test_sources() {
        if name == "corpus_skip_notice_test.rs" {
            continue;
        }
        let src = read(&name);
        for line in src.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("eprintln!") && trimmed.contains(corpus_support::ENV_VAR) {
                offenders.push(format!("{name}: {trimmed}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "eprintln! is captured per test and discarded when the test passes, which is \
         how the corpus skip stayed invisible: {offenders:?}"
    );
}

/// Every corpus-gated suite wires the shared gate.
///
/// Scans by *filename* rather than by content: a suite that mentions the
/// corpus nowhere but is named for it is exactly the file most likely to have
/// grown a private gate.
#[test]
fn every_corpus_suite_wires_the_shared_gate() {
    let mut missing = Vec::new();
    let mut wired = 0usize;
    for name in test_sources() {
        if !name.contains("corpus") {
            continue;
        }
        if EXEMPT.iter().any(|(f, _)| *f == name) {
            continue;
        }
        if read(&name).contains("support/corpus.rs") {
            wired += 1;
        } else {
            missing.push(name);
        }
    }
    assert!(
        missing.is_empty(),
        "these corpus suites do not include tests/support/corpus.rs, so an absent \
         corpus is silent in them: {missing:?}"
    );
    // A ratchet: without it, deleting the include from every file would leave
    // an empty `missing` and a passing test.
    assert!(
        wired >= 9,
        "only {wired} corpus suites wire the shared gate; the wiring is being removed"
    );
}
