// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for configuration file loading.
//!
//! Spawns the real binary with `--dump-config` to verify config discovery:
//! explicit `-f` paths, the `SIPNAB_CONFIG` env var, unknown-key warnings,
//! `--no-config`, and the missing-file error path.

use std::io::Write;
use std::process::Command;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// Builds a `Command` targeting the compiled `sipnab` test binary.
///
/// # Returns
/// An unconfigured `Command`; callers add args/env and spawn it.
fn sipnab_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sipnab"))
}

/// `-f <path> --dump-config` loads the file: the dumped config shows the
/// file's `device = "eth42"` value.
#[test]
fn explicit_path_loads() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("test.toml");
    let mut f = std::fs::File::create(&config_path)?;
    writeln!(f, "[capture]\ndevice = \"eth42\"")?;

    let output = sipnab_cmd()
        .args([
            "-f",
            config_path.to_str().ok_or("config_path.to_str() is None")?,
            "--dump-config",
        ])
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("eth42"),
        "Expected config dump to show device, got:\n{}",
        stdout
    );
    Ok(())
}

/// The `SIPNAB_CONFIG` env var selects the config file: the dump reflects the
/// file's `color = "never"` setting.
#[test]
fn env_var_loads() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("env.toml");
    let mut f = std::fs::File::create(&config_path)?;
    writeln!(f, "[display]\ncolor = \"never\"")?;

    let output = sipnab_cmd()
        .env(
            "SIPNAB_CONFIG",
            config_path.to_str().ok_or("config_path.to_str() is None")?,
        )
        .arg("--dump-config")
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("never"),
        "Expected config dump to show color=never, got:\n{}",
        stdout
    );
    Ok(())
}

/// An unknown config key does not fail startup: the known keys load and stderr
/// carries the `Unknown config key: capture.bogus` warning.
#[test]
fn unknown_key_warns_but_loads() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("unknown.toml");
    let mut f = std::fs::File::create(&config_path)?;
    writeln!(f, "[capture]\ndevice = \"eth0\"\nbogus = true")?;

    let output = sipnab_cmd()
        .env("SIPNAB_LOG", "warn")
        .args([
            "-f",
            config_path.to_str().ok_or("config_path.to_str() is None")?,
            "--dump-config",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "Unknown key should not cause failure. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("eth0"));

    // Verify the warning was emitted
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unknown config key: capture.bogus"),
        "Expected warning about unknown key, got stderr:\n{}",
        stderr
    );
    Ok(())
}

/// `--no-config` skips discovery: the dump reports no config file loaded.
#[test]
fn no_config_skips_loading() -> Result<(), TestError> {
    let output = sipnab_cmd()
        .args(["--no-config", "--dump-config"])
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No config file loaded") || stdout.contains("defaults only"),
        "Expected 'no config' message, got:\n{}",
        stdout
    );
    Ok(())
}

/// An explicit `-f` path that does not exist is a startup failure with a
/// not-found error on stderr.
#[test]
fn missing_explicit_file_errors() -> Result<(), TestError> {
    let output = sipnab_cmd()
        .args(["-f", "/nonexistent/path/sipnab.toml", "--dump-config"])
        .output()?;

    assert!(
        !output.status.success(),
        "Should fail when explicit config file is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Config file"),
        "Expected 'not found' error, got: {}",
        stderr
    );
    Ok(())
}
