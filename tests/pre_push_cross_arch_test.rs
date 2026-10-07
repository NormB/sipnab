// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pre-push hook compiles the code for the OTHER Linux architecture too.
//!
//! Code under `#[cfg(target_arch = "x86_64")]` is never compiled on an aarch64
//! host, so every local gate passes over it. On 2026-10-07 nine `.ok_or(..)?`
//! calls on `Result` values in x86_64-only tests in
//! `tests/seccomp_child_test.rs` passed `.githooks/pre-commit` and
//! `.githooks/pre-push` on the aarch64 development host and failed CI's x86_64 Coverage
//! and clippy jobs on PR #386. `scripts/cross-arch-target.sh` names the other
//! architecture's target for the host, and the hook runs clippy for it.

use std::path::Path;
use std::process::Command;

type TestError = Box<dyn std::error::Error>;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The target `scripts/cross-arch-target.sh` names for a host machine name.
fn other_target(machine: &str) -> Result<(bool, String), TestError> {
    let out = Command::new("sh")
        .arg(repo().join("scripts/cross-arch-target.sh"))
        .arg(machine)
        .output()?;
    Ok((
        out.status.success(),
        String::from_utf8(out.stdout)?.trim().to_string(),
    ))
}

#[test]
fn each_linux_host_is_checked_for_the_other_architecture() -> Result<(), TestError> {
    assert_eq!(
        other_target("aarch64")?,
        (true, "x86_64-unknown-linux-gnu".to_string())
    );
    assert_eq!(
        other_target("arm64")?,
        (true, "x86_64-unknown-linux-gnu".to_string())
    );
    assert_eq!(
        other_target("x86_64")?,
        (true, "aarch64-unknown-linux-gnu".to_string())
    );
    Ok(())
}

#[test]
fn an_unknown_host_names_no_target() -> Result<(), TestError> {
    let (ok, target) = other_target("riscv64")?;
    assert!(!ok && target.is_empty(), "riscv64 -> {ok} {target:?}");
    Ok(())
}

/// The hook runs clippy with the target the script names, over the same scope
/// as the host clippy gate, and says NOT CHECKED rather than passing when the
/// target is not installed.
#[test]
fn the_pre_push_hook_runs_clippy_for_the_other_architecture() -> Result<(), TestError> {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-push"))?;
    assert!(
        hook.contains("scripts/cross-arch-target.sh"),
        "the hook does not ask which architecture to cross-check"
    );
    let line = hook
        .lines()
        .find(|l| l.contains("cargo clippy") && l.contains("--target \"$CROSS_TARGET\""))
        .ok_or("no clippy run with --target \"$CROSS_TARGET\" in the hook")?;
    for part in ["--features full", "--tests", "-D warnings"] {
        assert!(
            line.contains(part),
            "the cross-arch clippy lacks {part}: {line}"
        );
    }
    assert!(
        hook.contains("NOT CHECKED") && hook.contains("rustup target add %s\\n' \"$CROSS_TARGET\""),
        "a missing target must be reported, with how to install it"
    );
    Ok(())
}
