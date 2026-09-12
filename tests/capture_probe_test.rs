// SPDX-License-Identifier: MIT OR Apache-2.0

//! The live-capture probe measures the binary, not the process asking.
//!
//! # The defect
//!
//! `hep_test.rs` and `integration_test.rs` each carried a copy of
//! `can_live_capture()` that read `/proc/self/status` and tested the TEST
//! RUNNER for `CAP_NET_RAW`. A sipnab carrying file capabilities --
//! `setcap cap_net_raw+ep`, which this project applies to exercise live
//! capture and uprobes -- gains the capability at `exec` whatever the runner
//! holds.
//!
//! On 2026-09-12 the runner's `CapEff` was zero and `target/debug/sipnab`
//! carried `cap_net_admin,cap_net_raw=ep`. Both copies answered
//! "unprivileged", `a_live_device_and_a_hep_listener_run_in_one_process` took
//! its unprivileged branch, and the child opened `lo` and captured. The
//! assertion was right about the branch it was in. The branch was chosen by a
//! measurement of the wrong process.
//!
//! Two copies of one rule agreed with each other, which is exactly why neither
//! was suspected.

#![cfg(feature = "full")]

use std::path::Path;
use std::process::Command;

#[path = "support/mod.rs"]
mod support;

use support::capture_probe::{can_live_capture, probe, probe_device};

const BIN: &str = env!("CARGO_BIN_EXE_sipnab");

/// The probe's answer is what a real capture attempt does.
///
/// Both directions. A probe that always said `false` would satisfy a one-sided
/// test on an unprivileged runner and be exactly the original bug.
#[test]
fn the_probe_agrees_with_what_the_binary_actually_does() {
    // The REAL attempt first, so the probe is judged against an observation
    // this test made itself rather than against its own opinion.
    let out = Command::new(BIN)
        .args([
            "-N",
            "-q",
            "-d",
            probe_device(),
            "--duration",
            "1s",
            "--no-cli-print",
        ])
        .env("SIPNAB_LOG", "info")
        .output()
        .expect("the binary under test is runnable");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let opened = stderr.contains(&format!("Capturing on '{}'", probe_device()));
    let refused = stderr.contains("Operation not permitted")
        || stderr.contains("permission denied")
        || stderr.contains("Permission denied")
        || stderr.contains("You don't have permission");

    let answer = can_live_capture(BIN);

    if !opened && !refused {
        // Genuinely ambiguous, and the probe is allowed to say so. Anything
        // else here would be this test inventing a verdict.
        assert_eq!(
            answer, None,
            "a real attempt neither opened nor was refused, so the probe must \
             say it cannot tell, not {answer:?}.\nstderr:\n{stderr}"
        );
        return;
    }

    // An attempt with a clear outcome makes `None` a WRONG answer, not an
    // excusable one. An earlier version of this test returned early on `None`
    // and a probe hard-wired never to report success stayed green: `None` is
    // precisely what a broken probe produces, so skipping on it skipped the
    // defect.
    assert_eq!(
        answer,
        Some(opened),
        "a real attempt on {} {}, and the probe said {answer:?}. Every test \
         that branches on this probe asserts the opposite half when the two \
         disagree.\nstderr:\n{stderr}",
        probe_device(),
        if opened { "OPENED" } else { "was REFUSED" }
    );
}

/// One implementation, not one per test file.
///
/// The bug shipped in two places and the copies agreed, so a reader comparing
/// them found nothing. Any new local copy fails this.
#[test]
fn only_one_live_capture_probe_exists_in_the_suite() {
    let mut definitions = Vec::new();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().is_none_or(|x| x != "rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue;
            };
            for (n, line) in text.lines().enumerate() {
                // A DEFINITION, not a call and not this file's prose about one.
                if line.trim_start().starts_with("pub fn can_live_capture")
                    || line.trim_start().starts_with("fn can_live_capture")
                {
                    // A one-line delegation to the shared module is not a copy.
                    let body = text.lines().nth(n + 1).unwrap_or("");
                    if body.contains("capture_probe::can_live_capture") {
                        continue;
                    }
                    definitions.push(format!(
                        "{}:{}",
                        p.strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
                            .unwrap_or(&p)
                            .display(),
                        n + 1
                    ));
                }
            }
        }
    }
    assert_eq!(
        definitions.len(),
        1,
        "expected exactly one real `can_live_capture` implementation and found \
         {}: {definitions:?}. Two copies of this rule agreed with each other \
         and both read the wrong process.",
        definitions.len()
    );
}

/// Probing twice returns the same answer.
///
/// A probe that consumed what it measured -- bound the socket, held the handle,
/// exhausted a one-shot permission -- would answer differently the second time,
/// and every caller after the first would branch on a fiction.
#[test]
fn the_memo_returns_what_a_fresh_probe_returns() {
    let memoized = can_live_capture(BIN);
    let fresh = probe(BIN);
    assert_eq!(
        memoized, fresh,
        "the memoized answer ({memoized:?}) differs from a fresh probe \
         ({fresh:?}); either the memo is stale or the probe consumes what it \
         measures"
    );
    assert_eq!(
        can_live_capture(BIN),
        memoized,
        "the memo is not stable across calls"
    );
}

/// The probe must not answer from the asking process's own capabilities.
///
/// A source scan, deliberately, and the one place in this file where that is
/// the right tool: the defect is not a wrong output, it is a right-looking
/// output derived from the wrong subject. `/proc/self` is the test runner by
/// definition, so reading it to decide what the CHILD can do is the mistake
/// itself rather than an implementation of it.
#[test]
fn the_probe_does_not_decide_from_the_asking_process() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/capture_probe.rs"),
    )
    .expect("the probe module is readable");
    let code: String = src
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with("///") && !t.starts_with("//!")
        })
        .collect::<Vec<_>>()
        .join("\n");
    for wrong_subject in ["/proc/self/status", "CapEff", "geteuid"] {
        assert!(
            !code.contains(wrong_subject),
            "the probe consults {wrong_subject:?}, which describes the process \
             ASKING rather than the binary that will capture. That is the \
             defect this module was written to remove."
        );
    }
    assert!(
        code.contains("Command::new(binary)"),
        "the probe no longer runs the binary, so it is answering from \
         something other than an observation"
    );
}
