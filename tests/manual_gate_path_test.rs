// SPDX-License-Identifier: MIT OR Apache-2.0

//! The manual pre-push path must never block on stdin.
//!
//! # The failure these exist for
//!
//! `.githooks/pre-push` ends with the git pre-push protocol's refspec loop —
//! `while read -r _local_ref local_sha remote_ref _remote_sha`. git feeds that
//! loop the refspec being pushed and then closes stdin; the loop reads what it
//! is given and stops at EOF. Run BY HAND through a harness that leaves stdin
//! open, the same `read` blocks forever, and the hook appears to freeze right
//! after the last gate before the loop, never reaching the ones after it.
//!
//! On 2026-09-03 that cost three misdiagnoses — the stall was blamed on the
//! prose gate, then on machine load — before the cause was found: an open
//! stdin, not a flaky gate. The safe manual path is `scripts/preflight.sh`,
//! which runs the same class of checks and reads no refspec, or
//! `git push` itself, which drives the hook with the stdin it expects.
//!
//! These tests pin the two properties that keep that true: the predictor stays
//! stdin-free, and the hook's only stdin read is the one refspec loop, so a
//! future edit cannot add a second, earlier `read` that blocks a manual run
//! before any gate has even printed.

use std::path::{Path, PathBuf};

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p: PathBuf = repo().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Lines that open a `while read` loop, trimmed of leading whitespace.
fn while_read_lines(body: &str) -> Vec<&str> {
    body.lines()
        .map(str::trim_start)
        .filter(|l| l.starts_with("while read ") || l.starts_with("while read\t"))
        .collect()
}

/// The documented manual path must not consume a refspec from stdin.
///
/// `scripts/preflight.sh` is what a person runs to learn whether the push will
/// pass. If it grew a `while read` refspec loop it would block on an open
/// stdin exactly as the hook did, and the one safe manual path would be gone.
#[test]
fn the_manual_predictor_never_blocks_on_a_refspec_read() {
    let body = read("scripts/preflight.sh");
    let loops = while_read_lines(&body);
    assert!(
        loops.is_empty(),
        "scripts/preflight.sh has a `while read` loop ({loops:?}). The manual \
         predictor must read no refspec, or it blocks on an open stdin the way \
         `.githooks/pre-push` does when run by hand."
    );
}

/// The predictor has to actually exist to be the safe path.
#[test]
fn the_manual_predictor_exists() {
    let p = repo().join("scripts/preflight.sh");
    assert!(
        p.is_file(),
        "scripts/preflight.sh is missing: there is no stdin-free manual path"
    );
}

/// The hook's ONLY stdin read is the refspec loop.
///
/// Every gate — fmt, clippy, the feature matrix, vale — runs before that loop
/// and prints as it goes. A second `while read` added earlier would block a
/// manual run before a single gate printed, which is precisely the shape that
/// was misread as a frozen gate. One loop, and it binds the ref variables git
/// supplies, so the block (when it happens) is always the last thing, never the
/// first.
#[test]
fn the_hook_reads_stdin_only_in_the_refspec_loop() {
    let body = read(".githooks/pre-push");
    let loops = while_read_lines(&body);
    assert_eq!(
        loops.len(),
        1,
        "expected exactly one `while read` in the pre-push hook, found {}: {loops:?}. \
         A second stdin read blocks a manual run before any gate prints.",
        loops.len()
    );
    let refspec = loops[0];
    assert!(
        refspec.contains("_ref") || refspec.contains("local_sha"),
        "the one `while read` must be the refspec loop (binding the push refs git \
         supplies); found {refspec:?}"
    );
}

/// POSITIVE CONTROL: the detector must see the loop it is meant to judge.
///
/// Without this, a `while_read_lines` that silently matched nothing — a broken
/// pattern, a moved file — would make every test above pass over an empty list,
/// which is the vacuous-green failure this project keeps finding.
#[test]
fn the_read_loop_detector_finds_the_known_loop() {
    let hook = read(".githooks/pre-push");
    assert_eq!(
        while_read_lines(&hook).len(),
        1,
        "the detector found no `while read` in a hook that has one; the pattern \
         or the path is wrong and every assertion here is vacuous"
    );
    let sample = "  x=1\n  while read -r a b c d; do\n    :\n  done\n";
    assert_eq!(
        while_read_lines(sample).len(),
        1,
        "detector misses a known loop"
    );
    assert!(
        while_read_lines("no loops here\n").is_empty(),
        "detector invents a loop"
    );
}
