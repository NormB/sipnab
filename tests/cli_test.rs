// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for CLI argument parsing.
//!
//! Smoke-level checks that spawn the real `sipnab` binary: `--version` works,
//! `--help` lists key flags, and unknown flags are rejected with an error.

use std::process::Command;

/// Builds a `Command` targeting the compiled `sipnab` test binary.
///
/// # Returns
/// An unconfigured `Command`; callers add args and spawn it.
fn sipnab_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sipnab"))
}

/// `--version` exits 0 and its output contains the binary name `sipnab`.
#[test]
fn version_flag_works() {
    let output = sipnab_cmd().arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("sipnab"),
        "Expected version output to contain 'sipnab', got:\n{}",
        stdout
    );
}

/// `--help` exits 0 and mentions each of a representative set of key flags.
#[test]
fn help_shows_key_flags() {
    let output = sipnab_cmd().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let expected_flags = [
        "--from",
        "--to",
        "--json",
        "--filter",
        "--report",
        "--call-report",
        "--problems",
        "--kill-scanner",
        "--no-rtp",
    ];

    for flag in &expected_flags {
        assert!(
            stdout.contains(flag),
            "Expected --help to contain '{}', got:\n{}",
            flag,
            stdout
        );
    }
}

/// An unknown flag makes the process exit non-zero with an error on stderr.
#[test]
fn invalid_flag_rejected() {
    let output = sipnab_cmd().arg("--nonexistent-flag").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("error"),
        "Expected error message about unknown flag, got: {}",
        stderr
    );
}
