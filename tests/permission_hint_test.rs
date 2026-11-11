// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The permission hint of a refused live capture names the cause the
//! process STARTED with, not one sipnab gave itself.
//!
//! sipnab sets `PR_SET_NO_NEW_PRIVS` on itself at startup
//! (`privilege::block_privilege_escalation`), before the capture opens. A hint
//! that read `/proc/self/status` when the capture failed therefore always saw
//! `NoNewPrivs: 1` and told every operator that systemd's
//! `NoNewPrivileges=yes` was the cause, including one running from a shell
//! where `sipnab --setup-caps` is the fix.
//!
//! Both tests drive the binary as the test's own user on `lo`. A host where
//! that capture opens (root, or a binary with file capabilities) has no
//! refusal to read, and the test says so on stderr rather than asserting on
//! nothing; the unit tests of `bootstrap::capture_open_failure_in` and
//! `privilege::status_for_hint` hold the rule there.

#![cfg(all(target_os = "linux", feature = "native"))]

use std::process::{Command, Stdio};

/// The error a test returns.
type TestError = Box<dyn std::error::Error>;

/// The first line of every permission refusal.
const REFUSED: &str = "Permission denied on 'lo'.";

/// The paragraph the hint adds for a process started under NoNewPrivs.
const NNP: &str = "This process runs with NoNewPrivs set";

/// The `NoNewPrivs` value of this test process, from `/proc/self/status`.
fn own_no_new_privs() -> Result<String, TestError> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    Ok(status
        .lines()
        .find_map(|l| l.strip_prefix("NoNewPrivs:"))
        .map(str::trim)
        .unwrap_or_default()
        .to_string())
}

/// Run `prefix` followed by sipnab on `lo` for at most a second, and return
/// its stderr.
fn capture_lo(prefix: &[&str]) -> Result<String, TestError> {
    let binary = env!("CARGO_BIN_EXE_sipnab");
    let (program, args): (&str, Vec<&str>) = match prefix.split_first() {
        Some((first, rest)) => {
            let mut args = rest.to_vec();
            args.push(binary);
            (first, args)
        }
        None => (binary, Vec::new()),
    };
    let out = Command::new(program)
        .args(args)
        .args(["-N", "-d", "lo", "--no-cli-print", "--duration", "1"])
        .env("NO_COLOR", "1")
        .env("SIPNAB_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()?;
    Ok(String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The reported regression: started without NoNewPrivs, a refused capture
/// must not blame NoNewPrivs.
#[test]
fn a_refusal_started_without_no_new_privs_does_not_blame_it() -> Result<(), TestError> {
    if own_no_new_privs()? != "0" {
        eprintln!("this test process already runs under NoNewPrivs; nothing to drive");
        return Ok(());
    }
    let stderr = capture_lo(&[])?;
    if !stderr.contains(REFUSED) {
        eprintln!("the capture on lo was not refused here; nothing to read:\n{stderr}");
        return Ok(());
    }
    assert!(
        !stderr.contains(NNP),
        "sipnab's own PR_SET_NO_NEW_PRIVS was reported as the cause:\n{stderr}"
    );
    Ok(())
}

/// Started under NoNewPrivs (`setpriv --no-new-privs`, what systemd's
/// `NoNewPrivileges=yes` does), a refused capture names it.
#[test]
fn a_refusal_started_under_no_new_privs_names_it() -> Result<(), TestError> {
    if !std::path::Path::new("/usr/bin/setpriv").exists() {
        eprintln!("no /usr/bin/setpriv on this host; nothing to drive");
        return Ok(());
    }
    let stderr = capture_lo(&["/usr/bin/setpriv", "--no-new-privs"])?;
    if !stderr.contains(REFUSED) {
        eprintln!("the capture on lo was not refused here; nothing to read:\n{stderr}");
        return Ok(());
    }
    assert!(stderr.contains(NNP), "{stderr}");
    Ok(())
}
