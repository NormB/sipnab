//! Integration tests for configuration file loading.

use std::io::Write;
use std::process::Command;

fn sipnab_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sipnab"))
}

#[test]
fn explicit_path_loads() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("test.toml");
    let mut f = std::fs::File::create(&config_path).unwrap();
    writeln!(f, "[capture]\ndevice = \"eth42\"").unwrap();

    let output = sipnab_cmd()
        .args(["-f", config_path.to_str().unwrap(), "--dump-config"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("eth42"),
        "Expected config dump to show device, got:\n{}",
        stdout
    );
}

#[test]
fn env_var_loads() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("env.toml");
    let mut f = std::fs::File::create(&config_path).unwrap();
    writeln!(f, "[display]\ncolor = \"never\"").unwrap();

    let output = sipnab_cmd()
        .env("SIPNAB_CONFIG", config_path.to_str().unwrap())
        .arg("--dump-config")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("never"),
        "Expected config dump to show color=never, got:\n{}",
        stdout
    );
}

#[test]
fn unknown_key_warns_but_loads() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("unknown.toml");
    let mut f = std::fs::File::create(&config_path).unwrap();
    writeln!(f, "[capture]\ndevice = \"eth0\"\nbogus = true").unwrap();

    let output = sipnab_cmd()
        .env("SIPNAB_LOG", "warn")
        .args(["-f", config_path.to_str().unwrap(), "--dump-config"])
        .output()
        .unwrap();

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
}

#[test]
fn no_config_skips_loading() {
    let output = sipnab_cmd()
        .args(["--no-config", "--dump-config"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No config file loaded") || stdout.contains("defaults only"),
        "Expected 'no config' message, got:\n{}",
        stdout
    );
}

#[test]
fn missing_explicit_file_errors() {
    let output = sipnab_cmd()
        .args(["-f", "/nonexistent/path/sipnab.toml", "--dump-config"])
        .output()
        .unwrap();

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
}
