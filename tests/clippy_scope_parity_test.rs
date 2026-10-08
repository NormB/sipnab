// SPDX-License-Identifier: MIT OR Apache-2.0

//! The commit gate lints what CI lints, or it is not a gate.
//!
//! `pre-commit` ran `cargo clippy --features full`, while CI and `pre-push`
//! run `--workspace --all-features --all-targets`. Test binaries are not a
//! default target, so every test file in this repository was UNLINTED at
//! commit time. Measured 2026-08-30: a `needless_splitn` in a test and an
//! `items_after_test_module` in `src/sip/mod.rs` both passed the commit gate
//! and failed CI's exact command. It happened twice more on 2026-09-01, in
//! test files added that day.
//!
//! The item that tracked this (GATE1) left the fix as an open question,
//! because widening the hook was assumed to "roughly double its wall clock".
//! Measured 2026-09-01, warm, on the machine that runs it:
//!
//! | command                                       | steady state |
//! |-----------------------------------------------|--------------|
//! | `--features full` (the old hook)              |    245 ms    |
//! | `--workspace --all-features --all-targets`    |    517 ms    |
//! | `--features full --all-targets`               | 40,110 ms    |
//!
//! The assumption was wrong, and the reason is worth keeping: CI's exact
//! command is cheap here BECAUSE pre-push and CI already use it, so it hits a
//! warm build cache. The bespoke middle option is 78x slower than the strict
//! one — a feature combination nothing else builds has a cache nothing else
//! warms.
//!
//! Which is the general lesson this repository keeps relearning: run the gate,
//! do not approximate it. An approximation is not merely weaker, it is
//! usually slower too.

use std::path::PathBuf;

type TestError = Box<dyn std::error::Error>;

fn read(rel: &str) -> Result<String, TestError> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    Ok(std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?)
}

/// Is this line a clippy the gate RUNS, rather than one it prints?
///
/// A hook tells the user how to fix what it found -- `printf '  cargo clippy
/// ... --fix'` -- and those lines are help text, not gates. Counting them
/// reports a `--fix` suggestion as an invocation that forgot `-D warnings`,
/// which is a false alarm, and a gate that cries wolf gets switched off.
fn is_invocation(line: &str) -> bool {
    let l = line.trim();
    l.contains("cargo clippy")
        && !l.starts_with('#')
        && !l.starts_with("//")
        && !l.starts_with("printf")
        && !l.starts_with("echo")
        && !l.contains("--fix")
        && !l.contains("Reproduce:")
        // Another architecture's lint is its own rule; see
        // `a_cross_architecture_clippy_is_not_the_host_scope`.
        && !l.contains("--target")
}

/// The clippy invocation a file makes, as the flags between `clippy` and `--`.
fn clippy_scopes(src: &str) -> Vec<String> {
    src.lines()
        .filter(|l| is_invocation(l))
        .map(|l| {
            let after = l.split("cargo clippy").nth(1).unwrap_or_default();
            after
                .split("--")
                .filter(|f| {
                    let f = f.trim();
                    f.starts_with("workspace")
                        || f.starts_with("all-features")
                        || f.starts_with("all-targets")
                        || f.starts_with("features")
                        || f.starts_with("no-default-features")
                })
                .map(|f| format!("--{}", f.trim()))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// A clippy run for another architecture (`--target`) is not the host gate.
///
/// `.githooks/pre-push` lints the other Linux architecture too, so code under
/// `#[cfg(target_arch = ...)]` is read before CI. That run cannot use CI's
/// scope: `--workspace --all-targets` reaches a crate whose build script
/// (`alsa-sys`) needs a sysroot for the other target, which a development host
/// does not have. It is a separate rule with its own test,
/// `tests/pre_push_cross_arch_test.rs`, and the host scope stays CI's.
#[test]
fn a_cross_architecture_clippy_is_not_the_host_scope() -> Result<(), TestError> {
    let hook = "cargo clippy --workspace --all-features --all-targets -- -D warnings\n\
                CARGO_TARGET_DIR=x cargo clippy --target \"$CROSS_TARGET\" --features full --tests -- -D warnings\n";
    assert_eq!(
        clippy_scopes(hook),
        ["--workspace --all-features --all-targets"],
        "only the host invocation is the host scope"
    );
    Ok(())
}

/// The commit gate lints test binaries.
///
/// The defect, stated directly. Without `--all-targets`, `cargo clippy` builds
/// only the default targets: the lib and the binaries. Every `tests/*.rs` and
/// every `#[cfg(test)]` block behind an integration target goes unread, which
/// is most of what this repository is.
#[test]
fn the_commit_gate_lints_test_targets() -> Result<(), TestError> {
    let hook = read(".githooks/pre-commit")?;
    let scopes = clippy_scopes(&hook);
    assert!(
        !scopes.is_empty(),
        ".githooks/pre-commit runs no clippy at all, or this scan can no \
         longer find it"
    );
    for scope in &scopes {
        assert!(
            scope.contains("--all-targets"),
            "the commit gate runs `cargo clippy {scope}`, which does not \
             include test targets. Every test file is then unlinted until \
             pre-push, and the lints that reach CI are exactly the ones \
             written in the files this project spends most of its lines on."
        );
    }
    Ok(())
}

/// The commit gate and CI run the SAME clippy scope.
///
/// Not "a wide enough one" — the same one. A hook that approximates the gate
/// is a hook that disagrees with it eventually, and the disagreement always
/// surfaces as a red CI on work that passed locally.
#[test]
fn the_commit_gate_and_ci_run_the_same_clippy_scope() -> Result<(), TestError> {
    let hook = clippy_scopes(&read(".githooks/pre-commit")?);
    let push = clippy_scopes(&read(".githooks/pre-push")?);
    let ci = clippy_scopes(&read(".github/workflows/ci.yml")?);

    assert!(
        !ci.is_empty(),
        "no clippy invocation found in ci.yml; this gate is reading the wrong \
         file and proves nothing"
    );
    let want = &ci[0];
    for (name, found) in [("pre-commit", &hook), ("pre-push", &push)] {
        assert!(
            !found.is_empty(),
            "{name} runs no clippy, so nothing checks lints before {}",
            if name == "pre-commit" {
                "a commit"
            } else {
                "a push"
            }
        );
        for scope in found.iter() {
            assert_eq!(
                scope, want,
                "{name} runs `cargo clippy {scope}` and CI runs `cargo clippy \
                 {want}`. Two spellings of one rule drift, and the cheaper \
                 one is the one that stops catching things.\n\nMeasured \
                 2026-09-01: CI's exact command costs 517 ms warm against the \
                 245 ms the narrow one cost, because pre-push and CI already \
                 warm that cache. Matching it is cheaper than inventing a \
                 third scope, which measured 40,110 ms."
            );
        }
    }
    Ok(())
}

/// Every clippy invocation denies warnings.
///
/// Scope is half of it. A gate with the right targets and no `-D warnings`
/// prints its findings and exits 0, which is the failure mode that looks most
/// like success.
#[test]
fn every_clippy_invocation_denies_warnings() -> Result<(), TestError> {
    for rel in [
        ".githooks/pre-commit",
        ".githooks/pre-push",
        ".github/workflows/ci.yml",
    ] {
        let src = read(rel)?;
        let mut checked = 0;
        for line in src.lines() {
            let l = line.trim();
            if !is_invocation(l) {
                continue;
            }
            checked += 1;
            assert!(
                l.contains("-D warnings") || l.contains("-Dwarnings"),
                "{rel} runs clippy without denying warnings:\n  {l}\nIt would \
                 print every finding and exit 0."
            );
        }
        assert!(checked >= 1, "{rel} has no clippy invocation to check");
    }
    Ok(())
}

/// The scan reads real files.
///
/// Anti-vacuity: every assertion above iterates a list that a broken parser
/// would return empty, and an empty list passes a `for` loop in silence.
#[test]
fn the_clippy_scan_found_real_invocations() -> Result<(), TestError> {
    let hook = clippy_scopes(&read(".githooks/pre-commit")?);
    let push = clippy_scopes(&read(".githooks/pre-push")?);
    let ci = clippy_scopes(&read(".github/workflows/ci.yml")?);
    for (name, found) in [("pre-commit", &hook), ("pre-push", &push), ("ci.yml", &ci)] {
        assert!(
            !found.is_empty(),
            "no clippy invocation parsed from {name}; the scan is wrong"
        );
        assert!(
            found.iter().all(|s| s.starts_with("--")),
            "{name} parsed a scope that is not a flag list: {found:?}"
        );
    }
    Ok(())
}
