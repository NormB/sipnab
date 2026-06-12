//! Privilege-drop regression guard: capture must NEVER continue as root
//! after a failed drop. main.rs treats a drop_privileges() error as
//! fatal (exit 1) — these tests pin that wiring end-to-end so a future
//! refactor cannot soften it into a logged warning.
//!
//! Runs only where passwordless sudo is available (GitHub runners, dev
//! hosts with NOPASSWD); skips with a note otherwise.
#![cfg(all(unix, feature = "native"))]

use std::process::Command;

fn sudo_available() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Copy the fixture somewhere a dropped-privilege process can read it
/// (the repo may live under a 0700 home directory).
fn world_readable_fixture() -> std::path::PathBuf {
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sip_call.pcap");
    let dst = std::env::temp_dir().join("sipnab-priv-guard.pcap");
    std::fs::copy(src, &dst).expect("copy fixture to temp");
    dst
}

#[test]
fn failed_privilege_drop_aborts_instead_of_running_as_root() {
    if !sudo_available() {
        eprintln!("skipping: passwordless sudo not available");
        return;
    }
    let fixture = world_readable_fixture();
    let out = Command::new("sudo")
        .args([
            "-n",
            env!("CARGO_BIN_EXE_sipnab"),
            "-N",
            "-I",
            fixture.to_str().unwrap(),
            "--user",
            "no-such-user-sipnab-guard",
        ])
        .output()
        .expect("spawn sipnab under sudo");
    assert!(
        !out.status.success(),
        "a failed privilege drop must abort the process, not continue as root"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Failed to drop privileges"),
        "abort must say why, got:\n{stderr}"
    );
}

#[test]
fn successful_privilege_drop_still_processes_capture() {
    if !sudo_available() {
        eprintln!("skipping: passwordless sudo not available");
        return;
    }
    let fixture = world_readable_fixture();
    let out = Command::new("sudo")
        .args([
            "-n",
            env!("CARGO_BIN_EXE_sipnab"),
            "-N",
            "-I",
            fixture.to_str().unwrap(),
            "--user",
            "nobody",
        ])
        .output()
        .expect("spawn sipnab under sudo");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "root -> drop to nobody -> read fixture must succeed, got:\n{stderr}"
    );
}
