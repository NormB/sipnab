// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `sipnab g729 status -f FILE` reports on the file a run with the same
//! options reads, so it reads that file the way a run does: a value a run
//! refuses is refused, and a key sipnab does not know is warned about.
//!
//! Measured on 0.5.224: `[g729] tables = ""` printed `Table file: ` with an
//! empty path and `not installed`, exit 1, with no refusal; `[capture]
//! portrange = "9-1"` (a run exits 1) was reported on as if accepted; and
//! `[g729] tablez = "x"` printed no warning.

#![cfg(feature = "g729")]

use std::process::{Command, Output};

/// The error a test returns.
type TestError = Box<dyn std::error::Error>;

/// `sipnab g729 status -f <file holding toml>`, with HOME and the XDG
/// directories in a fresh temporary directory.
fn status_with(toml: &str) -> Result<(Output, String, String), TestError> {
    let dir = tempfile::tempdir()?;
    let config = dir.path().join("sipnab.toml");
    std::fs::write(&config, toml)?;
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["g729", "status", "-f"])
        .arg(&config)
        .current_dir(dir.path())
        .env_remove("SIPNAB_LOG")
        .env("NO_COLOR", "1")
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Ok((out, stdout, stderr))
}

/// An empty `[g729] tables` is refused by name, exit 1, as a run refuses it,
/// and no table file is reported.
#[test]
fn an_empty_tables_path_is_refused_by_name() -> Result<(), TestError> {
    let (out, stdout, stderr) = status_with("[g729]\ntables = \"\"\n")?;
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(
        stderr.contains("[g729] tables is empty"),
        "the refusal names the key: {stderr}"
    );
    assert!(
        !stdout.contains("Table file:"),
        "nothing is reported on a refused file: {stdout}"
    );
    Ok(())
}

/// A value a run refuses in another section is refused here too, with the
/// run's message: the command reports on the file a run reads, and a run
/// reads none of this one.
#[test]
fn a_file_a_run_refuses_is_refused() -> Result<(), TestError> {
    let (out, stdout, stderr) = status_with("[capture]\nportrange = \"9-1\"\n")?;
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(stderr.contains("[capture] portrange"), "{stderr}");
    assert!(!stdout.contains("Table file:"), "{stdout}");
    Ok(())
}

/// A key sipnab does not know is named on stderr, as a run names it, and the
/// command still answers.
#[test]
fn an_unknown_key_is_warned_about() -> Result<(), TestError> {
    let (out, stdout, stderr) = status_with("[g729]\ntablez = \"x\"\n")?;
    assert!(
        stderr.contains("Unknown config key: g729.tablez"),
        "{stdout}\n{stderr}"
    );
    assert!(stdout.contains("Table file:"), "{stdout}");
    // Not installed in a fresh HOME, which is exit 1 and not a refusal.
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{stderr}");
    Ok(())
}
