// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The log on stderr carries ANSI color codes only when stderr is a terminal.
//!
//! journald, `docker logs` and a pipe are not terminals. Before this rule the
//! log subscriber colored every line unless `NO_COLOR` was set, so
//! `sipnab -N -I x.pcap 2>&1 | cat` printed `\x1b[2m...\x1b[0m` around each
//! timestamp and level. A test cannot hand the child a terminal without a
//! pty, so the terminal half of the rule is held by the unit tests of
//! `sipnab::output::cli_print::log_color_enabled`; these drive the binary with
//! stderr on a pipe, which is the case operators hit.

#![cfg(all(unix, feature = "native"))]

use std::process::{Command, Output, Stdio};

/// The error a test returns.
type TestError = Box<dyn std::error::Error>;

/// A capture with SIP messages, so both the log and the message lines print.
fn fixture() -> String {
    format!(
        "{}/tests/fixtures/sip_call.pcap",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// Run sipnab headless over the fixture with stdout and stderr on pipes,
/// `NO_COLOR` set to `no_color` (removed when `None`) and `SIPNAB_LOG=info`.
fn run(extra: &[&str], no_color: Option<&str>) -> Result<Output, TestError> {
    let fixture = fixture();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.args(["-N", "-I", &fixture])
        .args(extra)
        .env("SIPNAB_LOG", "info")
        .env_remove("NO_COLOR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(value) = no_color {
        cmd.env("NO_COLOR", value);
    }
    Ok(cmd.output()?)
}

/// The stderr of `out`, asserting the run succeeded and logged at least one
/// `INFO` line, so an empty stderr cannot pass as "no color".
fn logged(out: &Output) -> Result<String, TestError> {
    let stderr = String::from_utf8(out.stderr.clone())?;
    assert!(out.status.success(), "the run must succeed:\n{stderr}");
    assert!(stderr.contains("INFO"), "the run must log:\n{stderr}");
    Ok(stderr)
}

/// The reported case: `NO_COLOR` unset, stderr a pipe. No escape sequence.
#[test]
fn log_lines_on_a_pipe_carry_no_color_without_no_color() -> Result<(), TestError> {
    let stderr = logged(&run(&["--no-cli-print"], None)?)?;
    assert!(
        !stderr.contains('\x1b'),
        "a log on a pipe must carry no ANSI codes:\n{stderr:?}"
    );
    Ok(())
}

/// An empty `NO_COLOR` is the same as unset, and the pipe still decides.
#[test]
fn log_lines_on_a_pipe_carry_no_color_with_an_empty_no_color() -> Result<(), TestError> {
    let stderr = logged(&run(&["--no-cli-print"], Some(""))?)?;
    assert!(!stderr.contains('\x1b'), "{stderr:?}");
    Ok(())
}

/// `--color always` is the message-line option and keeps working: the
/// SIP lines on stdout are colored, the log on stderr follows its own stream.
#[test]
fn color_always_colors_the_message_lines_and_not_a_piped_log() -> Result<(), TestError> {
    let out = run(&["--color", "always"], Some("1"))?;
    let stderr = logged(&out)?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(
        stdout.contains("\x1b["),
        "--color always must color the message lines:\n{stdout:?}"
    );
    assert!(!stderr.contains('\x1b'), "{stderr:?}");
    Ok(())
}

/// `--color auto` writes no color to a piped stdout.
#[test]
fn color_auto_writes_no_color_to_a_piped_stdout() -> Result<(), TestError> {
    let out = run(&["--color", "auto"], None)?;
    logged(&out)?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(
        stdout.contains("INVITE"),
        "the messages must print:\n{stdout}"
    );
    assert!(!stdout.contains('\x1b'), "{stdout:?}");
    Ok(())
}
