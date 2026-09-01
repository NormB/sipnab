// SPDX-License-Identifier: MIT OR Apache-2.0

//! The runners must have room, and the rule that makes room lives in ONE place.
//!
//! On 2026-09-01 a CI job died like this:
//!
//! ```text
//! System.IO.IOException: No space left on device :
//!   '/home/runner/actions-runner/cached/2.337.0/_diag/Worker_....log'
//! ```
//!
//! The runner process itself could not write its own diagnostic log. That
//! failure produces no readable job log — the thing that failed was the logger
//! — so it had to be diagnosed from a check annotation after the log blob had
//! already expired. It cost a release cycle.
//!
//! The cause was drift between four copies of one rule. Two "Free disk space"
//! steps in `ci.yml` removed dotnet, android, ghc, CodeQL and boost. Two in
//! `quality.yml` removed those PLUS swift, the hosted tool cache and every
//! docker image. The stronger pair was written when the Coverage job ran out
//! of space; CI's copy never got the update, and CI is what ran out.
//!
//! Two copies of a rule agree until one is updated. These tests hold the
//! single definition in place.

use std::path::PathBuf;

fn repo(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

const WORKFLOWS: &[&str] = &[".github/workflows/ci.yml", ".github/workflows/quality.yml"];

const ACTION: &str = ".github/actions/free-disk/action.yml";

/// Every disk-reclaiming step uses the shared action.
///
/// An inline `run:` block beside the action is a second copy, and the second
/// copy is the one that goes stale.
#[test]
fn every_free_disk_step_uses_the_shared_action() {
    let mut steps = 0;
    for wf in WORKFLOWS {
        let src = repo(wf);
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("- name: Free disk space") {
                continue;
            }
            steps += 1;
            // The step body, up to the next step at the same indent.
            let body: String = lines[i + 1..]
                .iter()
                .take_while(|l| !l.trim_start().starts_with("- name:"))
                .copied()
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                body.contains("uses: ./.github/actions/free-disk"),
                "{wf}: a 'Free disk space' step does not use the shared \
                 action. Four copies of this rule drifted apart once and the \
                 weakest one killed a runner:\n{body}"
            );
            assert!(
                !body.contains("run: |"),
                "{wf}: a 'Free disk space' step still carries an inline \
                 script beside the action, which is the second copy again"
            );
        }
    }
    assert!(
        steps >= 4,
        "only {steps} disk-reclaiming step(s) found; the scan is wrong and \
         this gate proves nothing"
    );
}

/// The shared action reclaims everything the four copies between them did.
///
/// The union, not the weaker of the two. Losing an entry here is silent: the
/// job still runs, just with less room, until one day it does not.
#[test]
fn the_shared_action_reclaims_every_path_the_copies_did() {
    let action = repo(ACTION);
    for path in [
        "/usr/share/dotnet",
        "/usr/local/lib/android",
        "/opt/ghc",
        "/usr/local/share/boost",
        "/usr/share/swift",
        "/opt/hostedtoolcache/CodeQL",
        "AGENT_TOOLSDIRECTORY",
    ] {
        assert!(
            action.contains(path),
            "the shared action no longer reclaims {path}, which one of the \
             copies it replaced did reclaim"
        );
    }
    assert!(
        action.contains("docker image prune"),
        "the shared action no longer prunes docker images; the quality.yml \
         copies did, and that is several GB on a hosted runner"
    );
}

/// The action reports the margin it leaves.
///
/// `df -h` printed after the fact does not say how close the job came. The
/// failure this file is about happened with 62 MB left, and nothing in any log
/// said the margin had been shrinking. A number that is reported can be read
/// later; one that is not is a surprise waiting.
#[test]
fn the_shared_action_reports_the_margin_it_leaves() {
    let action = repo(ACTION);
    assert!(
        action.contains("reclaimed") && action.contains("free after"),
        "the action must report how much it freed AND how much is left; the \
         second number is the one that predicts the next failure"
    );
    assert!(
        action.contains("df --output=avail"),
        "the action must measure free space before and after, not merely \
         print df at the end"
    );
}

/// Every job that builds the whole matrix reclaims space first.
///
/// The job that died was a `--all-features --all-targets` check. A heavy job
/// without a reclaim step is the next one to run out, and it will fail the
/// same unreadable way.
#[test]
fn every_heavy_linux_job_reclaims_space_first() {
    for wf in WORKFLOWS {
        let src = repo(wf);
        let heavy = src.matches("--all-features").count() + src.matches("llvm-cov").count();
        let reclaims = src.matches("./.github/actions/free-disk").count();
        assert!(
            heavy > 0,
            "{wf} no longer builds anything heavy; this gate is reading the \
             wrong file"
        );
        assert!(
            reclaims > 0,
            "{wf} builds the whole matrix and no job reclaims disk first. The \
             runner dies writing its own log, which produces no readable \
             failure at all."
        );
    }
}
