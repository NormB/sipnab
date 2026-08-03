// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "native")]

//! `demos/keycast.py --self-test` has to run somewhere, and has to mean something.
//!
//! Two separate defects (#227), and fixing only one leaves the other:
//!
//! 1. The checks were bare `assert` statements. `python -O` strips those, so the
//!    body vanished, `_self_test` fell through, and it printed `self-test OK`
//!    having verified nothing. Same shape as the corpus skip that reached nobody
//!    (`abebdc0`): a green signal that is not evidence.
//! 2. Nothing ever ran it. There is no Python test runner wired into CI --
//!    `scripts/test_repair_pcapng_tsresol.py` is not executed either -- so the
//!    self-test only ran when a human remembered to type it, which is its own
//!    version of the same problem.
//!
//! This file fixes (2) by running it from the Rust suite, which CI does execute,
//! and guards (1) by running it under `-O` as well and proving that a broken
//! expectation still fails there.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn keycast() -> PathBuf {
    repo().join("demos/keycast.py")
}

fn run_self_test(script: &Path, optimised: bool) -> std::process::Output {
    let mut cmd = Command::new("python3");
    if optimised {
        cmd.arg("-O");
    }
    cmd.arg(script).arg("--self-test");
    cmd.output()
        .unwrap_or_else(|e| panic!("run python3 on {}: {e}", script.display()))
}

/// It passes, and CI is the thing running it.
#[test]
fn the_keycast_self_test_passes() {
    let out = run_self_test(&keycast(), false);
    assert!(
        out.status.success(),
        "keycast --self-test failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("self-test OK"),
        "self-test did not report success; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// The `-O` case, which is the defect #227 is actually about.
///
/// Passing under `-O` proves nothing on its own -- the old code "passed" under
/// `-O` precisely by checking nothing. So this also breaks an expectation and
/// requires the broken copy to fail *under `-O`*. If the checks were ever
/// converted back to bare `assert`, the mutated copy would pass and this test
/// would fail, which is the point.
#[test]
fn the_checks_survive_python_dash_o() {
    let out = run_self_test(&keycast(), true);
    assert!(
        out.status.success(),
        "keycast --self-test failed under -O:\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Break one expectation, then require -O to catch it.
    let src = std::fs::read_to_string(keycast()).expect("read keycast.py");
    let broken_src = src.replace(
        r#"_check(labels == ["↓", "↓", "Enter"], "unexpected badge labels", labels)"#,
        r#"_check(labels == ["NOPE"], "unexpected badge labels", labels)"#,
    );
    assert_ne!(
        broken_src, src,
        "the mutation did not apply -- the check was reworded, so this test is \
         no longer proving anything; update the pattern"
    );

    let dir = std::env::temp_dir().join(format!("sipnab-keycast-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let broken = dir.join("keycast_broken.py");
    std::fs::write(&broken, &broken_src).expect("write broken copy");

    let out = run_self_test(&broken, true);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !out.status.success(),
        "a deliberately broken expectation passed under `python3 -O`, which \
         means the checks are being stripped and the self-test proves nothing"
    );
}
