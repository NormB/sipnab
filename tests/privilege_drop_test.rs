// SPDX-License-Identifier: MIT OR Apache-2.0

//! Privilege-drop regression guard: capture must NEVER continue as root
//! after a failed drop. main.rs treats a drop_privileges() error as
//! fatal (exit 1) — these tests pin that wiring end-to-end so a future
//! refactor cannot soften it into a logged warning.
//!
//! Runs only where passwordless sudo is available (GitHub runners, dev
//! hosts with NOPASSWD); skips with a note otherwise.
#![cfg(all(unix, feature = "native"))]

use std::process::Command;

/// True when passwordless sudo (`sudo -n true`) works in this environment.
///
/// # Side effects
/// Spawns `sudo -n true` as a probe.
fn sudo_available() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Copy the fixture somewhere a dropped-privilege process can read it
/// (the repo may live under a 0700 home directory).
///
/// `tag` makes the destination unique per test: the two tests here run
/// in parallel (cargo's default), so a shared fixed path would let one
/// test's `fs::copy` truncate the file mid-read of the other, surfacing
/// as a spurious "truncated dump file" abort.
///
/// # Returns
/// Path to the copied fixture in the system temp directory.
///
/// # Side effects
/// Writes `sipnab-priv-guard-<tag>.pcap` into the system temp directory.
fn world_readable_fixture(tag: &str) -> std::path::PathBuf {
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sip_call.pcap");
    let dst = std::env::temp_dir().join(format!("sipnab-priv-guard-{tag}.pcap"));
    std::fs::copy(src, &dst).expect("copy fixture to temp");
    dst
}

/// Running as root with `--user` naming a nonexistent account exits non-zero
/// with "Failed to drop privileges" — never continues capturing as root.
#[test]
fn failed_privilege_drop_aborts_instead_of_running_as_root() {
    if !sudo_available() {
        eprintln!("skipping: passwordless sudo not available");
        return;
    }
    let fixture = world_readable_fixture("drop-fail");
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

/// Root dropping to `nobody` still reads and processes the fixture, exiting 0.
#[test]
fn successful_privilege_drop_still_processes_capture() {
    if !sudo_available() {
        eprintln!("skipping: passwordless sudo not available");
        return;
    }
    let fixture = world_readable_fixture("drop-success");
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
