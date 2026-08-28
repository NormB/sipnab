//! The feature-dependency check exists, runs clean, and the hook invokes it.
//!
//! `--features vcon` did not build at 0.5.130. `src/output/redact.rs` is gated
//! by `any(api, mcp, vcon)` and imports `hmac`, and only two of those three
//! features declared `dep:hmac`. `--features full` hid it, because `mcp`
//! supplies `hmac` anyway — so every ordinary build passed while one matrix
//! combination failed, and CI's `Features (vcon)` job is what found it.
//!
//! The pre-push feature matrix is supposed to catch exactly this, and did not.
//! It builds the WORKING TREE, and the working tree held the fix while the
//! commit lacked it. That is the defect worth gating: not a missing `hmac`,
//! but a check whose input is not the thing being shipped.
//!
//! These tests hold the replacement in place. A script nothing runs is a script
//! that rots, and the failure mode is silent — the hook keeps printing OK for
//! the gates it does run.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// 1. The tree currently satisfies the check.
///
/// Runs the real script rather than reimplementing its rule here. Two
/// implementations of one rule is two things to keep true, and the one that
/// drifts is whichever nobody reads.
#[test]
fn every_feature_declares_what_its_modules_import() {
    let out = Command::new("python3")
        .arg("scripts/check-feature-deps.py")
        .current_dir(repo())
        .output()
        .expect("run scripts/check-feature-deps.py");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "a feature-gated module imports a crate its feature does not declare. \
         A build enabling only that feature fails on the import, while \
         --features full passes because a sibling feature supplies the \
         crate:\n{stderr}{stdout}"
    );
    // Exit status alone cannot tell "nothing wrong" from "nothing examined".
    // The script refuses with status 2 when its walk goes blind, and this
    // pins the reported subject count so a silent narrowing shows up here.
    let scanned: usize = stdout
        .split_whitespace()
        .nth(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert!(
        scanned >= 20,
        "the check reported only {scanned} feature-gated modules; it is not \
         reaching src/ and a pass would mean nothing.\n{stdout}{stderr}"
    );
}

/// 2. `pre-commit` actually invokes it.
///
/// Without this the script can stay green in isolation forever while no gate
/// runs it, which is indistinguishable from a repository where the rule holds.
#[test]
fn the_pre_commit_hook_runs_the_feature_dependency_check() {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-commit"))
        .expect("read .githooks/pre-commit");
    assert!(
        hook.contains("scripts/check-feature-deps.py"),
        ".githooks/pre-commit does not run scripts/check-feature-deps.py, so \
         the check that replaced a gate reading the wrong input is itself \
         never read"
    );
    assert!(
        hook.contains("exit 1"),
        "the hook must FAIL on the check rather than print and continue"
    );
}

/// 3. The script refuses rather than passes when it cannot see its subject.
///
/// This is the property that separates it from the gate it replaces. Status 2
/// means "cannot answer" and must not be confused with 0, "nothing wrong".
#[test]
fn the_check_refuses_when_it_can_see_nothing() {
    let script = std::fs::read_to_string(repo().join("scripts/check-feature-deps.py"))
        .expect("read scripts/check-feature-deps.py");
    assert!(
        script.contains("return 2"),
        "the script has no distinct 'cannot answer' status. Without one, a walk \
         that finds nothing exits 0 and reads as a clean tree — the exact shape \
         this repository keeps rediscovering"
    );
    assert!(
        script.contains("len(modules) < 10") && script.contains("len(optional) < 5"),
        "both floors must be present: one for the module walk and one for the \
         Cargo.toml dependency parse. Either going blind alone makes every \
         later comparison vacuous"
    );
}

/// 4. The script is executable and lives where the hook expects it.
#[test]
fn the_check_script_is_present_and_executable() {
    let path = repo().join("scripts/check-feature-deps.py");
    assert!(path.is_file(), "scripts/check-feature-deps.py is missing");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("stat the script")
            .permissions()
            .mode();
        assert!(
            mode & 0o111 != 0,
            "scripts/check-feature-deps.py is not executable (mode {mode:o})"
        );
    }
    let _ = Path::new("");
}
