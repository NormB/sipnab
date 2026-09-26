// SPDX-License-Identifier: MIT OR Apache-2.0

//! A TUI that cannot start must not report success.
//!
//! With no terminal, `sipnab -I <file>` logged `TUI error: No such device or
//! address` and exited 0. A script, a service manager or a CI step reading
//! the exit status saw a run that worked; `scripts/check-cookbook.py` counted
//! five TUI commands as passing that had done nothing. Found by EX8 on
//! 2026-09-25 (backlog TTY-EXIT-1).
//!
//! The run happens under `setsid --wait`, which starts it in a new session
//! with no controlling terminal and returns its exit status, so the test
//! behaves the same from a developer's terminal as it does in CI.
//!
//! Linux only: `setsid` is util-linux's, and macOS does not ship it. What is
//! tested does not differ by platform (how sipnab treats the TUI's error), so
//! running it on Linux alone loses nothing.
#![cfg(all(feature = "tui", target_os = "linux"))]

use std::process::{Command, Stdio};

#[test]
fn a_tui_that_cannot_start_exits_non_zero_and_says_why() {
    let out = Command::new("setsid")
        .arg("--wait")
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-I", "tests/fixtures/sip_call.pcap"])
        .env("SIPNAB_LOG", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run sipnab under setsid");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(
        out.status.code(),
        Some(0),
        "the TUI could not start and sipnab still exited 0; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("terminal"),
        "the refusal must say a terminal is missing, even with logging off; stderr:\n{stderr}"
    );
}
