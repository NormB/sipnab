// SPDX-License-Identifier: MIT OR Apache-2.0

//! The local coverage rehearsal and the CI gate describe one run.
//!
//! `scripts/coverage.sh` exists so the coverage floor can be checked before a
//! push rather than discovered by CI afterwards. That is only worth having if
//! the rehearsal and the gate agree: a script that skipped a different set of
//! tests, or enforced a floor of its own, would report green on a tree CI then
//! refuses — and the rehearsal is the one a developer trusts, because it is
//! the one that answered first.
//!
//! So the script reads the floor out of the workflow instead of repeating it.
//! These tests hold that arrangement in place.

/// Read a repo-relative file.
///
/// Runtime reads rather than `include_str!`, so the paths in this file are
/// repo-relative and a reader — or `every_cited_script_exists` — can follow
/// them. `include_str!` resolves relative to this source file, which would put
/// a parent-directory hop in front of every path and leave each one pointing
/// at nothing the repo root recognizes.
fn read(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The workflow that owns the coverage job.
fn workflow() -> String {
    read(".github/workflows/quality.yml")
}

/// The local rehearsal.
fn script() -> String {
    read("scripts/coverage.sh")
}

/// The script takes the floor from the workflow rather than carrying its own.
///
/// Mutation-checked by inlining a number: a script with `--fail-under-lines 93`
/// written out would pass a naive "both say 93" test and drift the moment CI's
/// floor moved. What must be true is that the script contains no literal floor
/// at all.
#[test]
fn the_local_rehearsal_reads_the_floor_rather_than_repeating_it() {
    assert!(
        script().contains("--fail-under-lines [0-9]+"),
        "scripts/coverage.sh must extract the floor from the workflow; \
         without that the two can disagree and the local one wins the \
         developer's trust"
    );
    assert!(
        script().contains("$FLOOR"),
        "and must enforce the value it extracted"
    );

    // No inlined floor. `--fail-under-lines` followed by a literal digit is
    // exactly the drift this arrangement exists to prevent.
    let script = script();
    let inlined = script
        .split("--fail-under-lines ")
        .skip(1)
        .any(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
    assert!(
        !inlined,
        "scripts/coverage.sh hard-codes a coverage floor. It must read the \
         workflow's, or the rehearsal and the gate will diverge silently"
    );
}

/// The workflow still declares a floor for the script to find.
///
/// If the gate stopped enforcing one, the script would exit rather than
/// invent a number — but nothing would say the gate had gone. This is what
/// says it.
#[test]
fn the_workflow_still_enforces_a_coverage_floor() {
    let floor = workflow()
        .split("--fail-under-lines ")
        .nth(1)
        .and_then(|rest| {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<u32>().ok()
        })
        .expect("quality.yml declares a --fail-under-lines floor");

    assert!(
        (50..=100).contains(&floor),
        "a floor of {floor} is not a percentage; the extraction is reading \
         the wrong thing"
    );
    assert!(
        floor >= 93,
        "the floor was measured at 93.64% and set to 93. A lower value has \
         been walked backwards, which the workflow's own comment forbids: \
         raise it when the real number rises, never lower it to make a build \
         pass. Found {floor}"
    );
}

/// The script skips exactly the tests the coverage job skips.
///
/// Both skips are technical, not preferences: `cli_goldens` spawns the
/// instrumented binary as 13 parallel subprocesses that collide on the
/// llvm-cov merge-pool `.profraw`, and `wasm_plugin_` shells out to a wasm32
/// build that ships no `profiler_builtins`. A rehearsal that skipped a
/// different set would measure a different population and compare it to CI's
/// floor as though they were the same number.
#[test]
fn the_rehearsal_skips_what_the_coverage_job_skips() {
    for skip in ["cli_goldens", "wasm_plugin_"] {
        assert!(
            workflow().contains(&format!("--skip {skip}")),
            "the coverage job no longer skips {skip}; the script still does, \
             so the two now measure different populations"
        );
        assert!(
            script().contains(skip),
            "scripts/coverage.sh does not skip {skip}, which the coverage job \
             skips for a reason that applies equally here"
        );
    }
}

/// The rehearsal is not wired into the pre-push hook.
///
/// A 30-to-60-minute instrumented run in front of every push is a gate people
/// route around, and a gate routed around is worse than one that was never
/// claimed: the claim is what stops someone adding a real check later. The
/// script says so in its own header, and this holds it to that.
#[test]
fn the_rehearsal_is_not_bolted_onto_the_pre_push_hook() {
    let hook = read(".githooks/pre-push");
    assert!(
        !hook.contains("coverage.sh") && !hook.contains("llvm-cov"),
        "scripts/coverage.sh has been added to the pre-push hook. An \
         instrumented build plus the full suite is 30-60 minutes; the hook is \
         already ~15. If this is deliberate, delete this test and say why in \
         the same commit"
    );
}
