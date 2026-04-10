//! Integration tests for CLI argument parsing.

use std::process::Command;

fn sipnab_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sipnab"))
}

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
