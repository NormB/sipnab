// SPDX-License-Identifier: MIT OR Apache-2.0

//! UX contracts of the top-level CLI surface: --help must group its ~140
//! flags under section headings (one flat Options: list is unscannable),
//! and --completions must emit a usable shell completion script.
#![cfg(feature = "native")]

#[path = "support/run.rs"]
mod run_support;

/// Runs the `sipnab` binary from the crate root under the shared test baseline
/// (see [`run_support::run`]); this surface asserts only on stdout and exit
/// codes, so it leaves `SIPNAB_LOG` unset (`None`).
///
/// # Arguments
/// * `args` — CLI arguments to pass.
///
/// # Returns
/// `(stdout, stderr, exit_code)` of the finished process.
fn run(args: &[&str]) -> (String, String, Option<i32>) {
    run_support::run(args, None)
}

/// --help must render section headings, not one flat Options: wall.
#[test]
fn help_groups_flags_under_headings() {
    let (stdout, _, code) = run(&["--help"]);
    assert_eq!(code, Some(0));
    for heading in [
        "Capture:",
        "Mode:",
        "Matching:",
        "Output:",
        "Security:",
        "TLS / Decryption:",
        "Config:",
    ] {
        assert!(
            stdout.contains(heading),
            "--help must contain the '{heading}' section heading:\n{stdout}"
        );
    }
}

/// --completions <shell> prints a completion script to stdout and exits 0.
#[test]
fn completions_emit_scripts_for_each_shell() {
    for shell in ["bash", "zsh", "fish"] {
        let (stdout, stderr, code) = run(&["--completions", shell]);
        assert_eq!(code, Some(0), "--completions {shell} failed:\n{stderr}");
        assert!(
            stdout.contains("sipnab"),
            "{shell} completion script must reference the binary:\n{stdout}"
        );
        assert!(
            stdout.len() > 200,
            "{shell} completion script suspiciously short ({} bytes)",
            stdout.len()
        );
    }
}

/// An unknown shell name is a usage error (exit 2), not a silent success.
#[test]
fn completions_reject_unknown_shell() {
    let (_, stderr, code) = run(&["--completions", "tcsh"]);
    assert_eq!(code, Some(2), "unknown shell must be a usage error");
    assert!(
        stderr.contains("tcsh"),
        "error should echo the bad value:\n{stderr}"
    );
}
