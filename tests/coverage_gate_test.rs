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

type TestError = Box<dyn std::error::Error>;

/// Read a repo-relative file.
///
/// Runtime reads rather than `include_str!`, so the paths in this file are
/// repo-relative and a reader — or `every_cited_script_exists` — can follow
/// them. `include_str!` resolves relative to this source file, which would put
/// a parent-directory hop in front of every path and leave each one pointing
/// at nothing the repo root recognizes.
fn read(rel: &str) -> Result<String, TestError> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    Ok(std::fs::read_to_string(&path).map_err(|e| format!("read {rel}: {e}"))?)
}

/// The workflow that owns the coverage job.
fn workflow() -> Result<String, TestError> {
    read(".github/workflows/quality.yml")
}

/// The local rehearsal.
fn script() -> Result<String, TestError> {
    read("scripts/coverage.sh")
}

/// The script takes the floor from the workflow rather than carrying its own.
///
/// Mutation-checked by inlining a number: a script with `--fail-under-lines 93`
/// written out would pass a naive "both say 93" test and drift the moment CI's
/// floor moved. What must be true is that the script contains no literal floor
/// at all.
#[test]
fn the_local_rehearsal_reads_the_floor_rather_than_repeating_it() -> Result<(), TestError> {
    assert!(
        script()?.contains("--fail-under-lines [0-9]+"),
        "scripts/coverage.sh must extract the floor from the workflow; \
         without that the two can disagree and the local one wins the \
         developer's trust"
    );
    assert!(
        script()?.contains("$FLOOR"),
        "and must enforce the value it extracted"
    );

    // No inlined floor. `--fail-under-lines` followed by a literal digit is
    // exactly the drift this arrangement exists to prevent.
    let script = script()?;
    let inlined = script
        .split("--fail-under-lines ")
        .skip(1)
        .any(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
    assert!(
        !inlined,
        "scripts/coverage.sh hard-codes a coverage floor. It must read the \
         workflow's, or the rehearsal and the gate will diverge silently"
    );
    Ok(())
}

/// The workflow still declares a floor for the script to find.
///
/// If the gate stopped enforcing one, the script would exit rather than
/// invent a number — but nothing would say the gate had gone. This is what
/// says it.
#[test]
fn the_workflow_still_enforces_a_coverage_floor() -> Result<(), TestError> {
    let floor = workflow()?
        .split("--fail-under-lines ")
        .nth(1)
        .and_then(|rest| {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<u32>().ok()
        })
        .ok_or("quality.yml declares a --fail-under-lines floor")?;

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
    Ok(())
}

/// The script skips exactly the tests the coverage job skips.
///
/// Both skips are technical, not preferences: `cli_goldens` spawns the
/// instrumented binary as 13 parallel subprocesses that collide on the
/// llvm-cov merge-pool `.profraw`, and `wasm_plugin_` shells out to a wasm32
/// build that ships no `profiler_builtins`. A rehearsal that skipped a
/// different set would measure a different population and compare it to CI's
/// floor as though they were the same number. So the script READS the scope
/// the workflow states rather than keeping a copy that agrees today.
#[test]
fn the_rehearsal_skips_what_the_coverage_job_skips() -> Result<(), TestError> {
    for skip in ["cli_goldens", "wasm_plugin_"] {
        assert!(
            workflow()?.contains(&format!("--skip {skip}")),
            "the coverage scope no longer skips {skip}; if that is deliberate, \
             the reason it was skipped has to have gone too"
        );
    }
    let script = script()?;
    for var in ["COVERAGE_TEST_SKIPS", "COVERAGE_IGNORE_REGEX"] {
        assert!(
            script.contains(var),
            "scripts/coverage.sh does not read {var} from the workflow, so it \
             measures a scope of its own"
        );
    }
    for literal in ["--skip cli_goldens", "--skip wasm_plugin_", "gen_fixture"] {
        assert!(
            !script.contains(literal),
            "scripts/coverage.sh carries its own copy of `{literal}`; it must \
             read the scope from quality.yml, or the two drift apart"
        );
    }
    Ok(())
}

/// The body of one top-level job in quality.yml, up to the next job.
fn job(name: &str) -> Result<String, TestError> {
    let wf = workflow()?;
    let header = format!("\n  {name}:\n");
    let start = wf
        .find(&header)
        .ok_or_else(|| format!("quality.yml has no `{name}` job"))?;
    let body = &wf[start + header.len()..];
    // The next line at exactly two spaces of indent that is not a comment
    // opens the next job.
    let end = body
        .match_indices('\n')
        .map(|(i, _)| i + 1)
        .find(|&i| {
            let rest = &body[i..];
            rest.starts_with("  ")
                && !rest.starts_with("   ")
                && !rest[2..].starts_with('#')
                && !rest[2..].starts_with('\n')
        })
        .unwrap_or(body.len());
    Ok(body[..end].to_string())
}

/// The coverage scope is stated once, and every llvm-cov call uses it.
///
/// The line job and the weekly branch job are two measurements of one suite.
/// Before this, the ignore regex was written out on four separate lines of the
/// line job and again in the script: five copies agreeing by coincidence. A
/// branch job that grew a sixth copy would be one edit away from describing a
/// different population from the line number it sits beside.
///
/// Mutation-checked by writing the regex back inline on one report line: the
/// count of the literal goes to two and this fails.
#[test]
fn the_coverage_scope_is_stated_once_and_every_llvm_cov_call_uses_it() -> Result<(), TestError> {
    let wf = workflow()?;
    for literal in [
        "--skip cli_goldens",
        "--skip wasm_plugin_",
        "gen_fixture\\.rs",
    ] {
        assert_eq!(
            wf.matches(literal).count(),
            1,
            "`{literal}` must appear exactly once in quality.yml -- in the \
             workflow-level env that states the coverage scope"
        );
    }
    let mut collections = 0;
    let mut reports = 0;
    for line in wf.lines().map(str::trim) {
        if line.starts_with('#') || !line.contains("cargo") || !line.contains("llvm-cov") {
            continue;
        }
        if line.contains("llvm-cov report") {
            reports += 1;
            assert!(
                line.contains("--ignore-filename-regex \"$COVERAGE_IGNORE_REGEX\""),
                "an llvm-cov report ignores something other than the stated \
                 scope:\n  {line}"
            );
        } else if line.contains("--no-report") {
            collections += 1;
            assert!(
                line.contains("-- $COVERAGE_TEST_SKIPS"),
                "an llvm-cov collection skips something other than the stated \
                 scope:\n  {line}"
            );
        }
    }
    assert!(
        collections >= 2 && reports >= 4,
        "found {collections} collections and {reports} reports; the line and \
         branch jobs between them make at least 2 and 4, so this scan is \
         reading the wrong thing"
    );
    Ok(())
}

/// Branch coverage is measured, on a schedule, and reported under its own flag.
///
/// OpenSSF Gold `test_branch_coverage80` asks for branch coverage. The line
/// job cannot give it: `--branch` needs `-Z coverage-options=branch`, which is
/// nightly-only, and the line gate must stay on the pinned stable toolchain
/// the release builds with. So the branch job is weekly and on demand, on the
/// same nightly pin fuzz.yml and sanitizers.yml use as a TOOL, and it uploads
/// under a Codecov flag of its own so it does not overwrite the line report.
#[test]
fn branch_coverage_runs_weekly_on_the_shared_nightly_pin() -> Result<(), TestError> {
    let wf = workflow()?;
    let on = wf
        .split("\non:\n")
        .nth(1)
        .and_then(|rest| rest.split("\n\n").next())
        .ok_or("quality.yml has an `on:` block")?;
    assert!(
        on.contains("schedule:") && on.contains("workflow_dispatch:"),
        "quality.yml must trigger on a schedule and by hand for the branch job:\n{on}"
    );

    let branch = job("coverage-branch")?;
    assert!(
        branch.contains("github.event_name == 'schedule'")
            && branch.contains("github.event_name == 'workflow_dispatch'"),
        "the branch job must run only on the schedule or by hand; a nightly \
         instrumented run on every push is not what this job is for"
    );
    assert!(
        branch.contains("--branch"),
        "the branch job collects without --branch, so it measures no branches"
    );
    assert!(
        branch.contains("scripts/branch-coverage.py"),
        "the branch job must hand its summary to scripts/branch-coverage.py, \
         which refuses a report holding no branches"
    );
    assert!(
        branch.contains("flags: branch"),
        "the branch upload needs its own Codecov flag, or it overwrites the \
         line report"
    );

    let fuzz = read(".github/workflows/fuzz.yml")?;
    let pin = fuzz
        .lines()
        .map(str::trim)
        .find(|l| l.contains("dtolnay/rust-toolchain@") && l.ends_with("# nightly"))
        .ok_or("fuzz.yml pins a nightly toolchain")?;
    assert!(
        branch.contains(pin),
        "the branch job must use the nightly pin fuzz.yml uses (`{pin}`), \
         not a second nightly of its own"
    );

    // Every OTHER job skips the weekly schedule: it exists for the branch job,
    // and a scheduled rerun of the docs, bench and line jobs buys nothing.
    let others = ["bench", "coverage", "clippy-sarif", "docs", "accessibility"];
    for name in others {
        assert!(
            job(name)?.contains("if: github.event_name != 'schedule'"),
            "the `{name}` job runs on the weekly schedule too; it should not"
        );
    }
    Ok(())
}

/// The rehearsal is not wired into the pre-push hook.
///
/// A 30-to-60-minute instrumented run in front of every push is a gate people
/// route around, and a gate routed around is worse than one that was never
/// claimed: the claim is what stops someone adding a real check later. The
/// script says so in its own header, and this holds it to that.
#[test]
fn the_rehearsal_is_not_bolted_onto_the_pre_push_hook() -> Result<(), TestError> {
    let hook = read(".githooks/pre-push")?;
    assert!(
        !hook.contains("coverage.sh") && !hook.contains("llvm-cov"),
        "scripts/coverage.sh has been added to the pre-push hook. An \
         instrumented build plus the full suite is 30-60 minutes; the hook is \
         already ~15. If this is deliberate, delete this test and say why in \
         the same commit"
    );
    Ok(())
}
