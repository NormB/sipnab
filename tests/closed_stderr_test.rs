// SPDX-License-Identifier: MIT OR Apache-2.0

//! A reader that goes away must not turn a finished run into a crash.
//!
//! `sipnab ... 2>&1 | head -1` closes the pipe that carries both stdout and
//! stderr after one line. Every later write fails with `EPIPE`. stdout already
//! treats that as the reader's choice; stderr did not: `eprintln!` panics when
//! its write fails, and so does the `eprintln!` tracing-subscriber uses to
//! report a log line it could not write. The panic hook then exited 101 and
//! wrote a crash report for a run that had done everything it was asked.
//!
//! Each test hands the child a pipe whose read end is already closed, so every
//! write to it fails from the first byte. Racing a real `head` would make the
//! failure depend on timing; this makes it depend only on sipnab.

use std::process::{Command, Stdio};

/// The error a test returns: any error, boxed, so `?` works on I/O,
/// parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// A pipe nobody will ever read: the read end is dropped before the child
/// starts, so the child's writes to it fail with `EPIPE`.
fn reader_gone() -> Result<Stdio, TestError> {
    let (reader, writer) = std::io::pipe()?;
    drop(reader);
    Ok(Stdio::from(writer))
}

/// Run sipnab with `args`, stderr into a pipe with no reader, and return the
/// exit code. Crash reports go to a private directory, so a panic is visible
/// to the test as a file and never lands in the developer's own state
/// directory.
fn exit_code_with_stderr_gone(
    args: &[&str],
    log: &str,
    stdout: Stdio,
) -> Result<(i32, usize), TestError> {
    let state = tempfile::tempdir()?;
    let status = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("SIPNAB_LOG", log)
        .env("XDG_STATE_HOME", state.path())
        .env("HOME", state.path())
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(reader_gone()?)
        .status()?;
    let reports = walk_count(state.path());
    Ok((status.code().unwrap_or(-1), reports))
}

/// Number of files under `dir`, recursively.
fn walk_count(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .map(|it| {
            it.flatten()
                .map(|e| {
                    let p = e.path();
                    if p.is_dir() { walk_count(&p) } else { 1 }
                })
                .sum()
        })
        .unwrap_or(0)
}

/// The log lines a batch run writes to stderr must not crash it when nobody
/// reads stderr. This is the `tracing` path: the subscriber's own report of
/// the failed write was itself an `eprintln!`.
#[test]
fn log_lines_to_a_closed_stderr_do_not_crash_a_batch_run() -> Result<(), TestError> {
    let pcap = fixture("sip_call.pcap");
    let (code, reports) = exit_code_with_stderr_gone(&["-N", "-I", &pcap], "info", Stdio::null())?;
    assert_eq!(code, 0, "exit {code}; 101 is the panic hook");
    assert_eq!(reports, 0, "a crash report was written");
    Ok(())
}

/// sipnab's own `eprintln!` lines, with logging off so only they write to
/// stderr: a capture with RTP and no SIP prints its guidance that way.
#[test]
fn guidance_lines_to_a_closed_stderr_do_not_crash_a_batch_run() -> Result<(), TestError> {
    let pcap = fixture("turn_relay.pcap");
    let (code, reports) = exit_code_with_stderr_gone(&["-N", "-I", &pcap], "off", Stdio::null())?;
    assert_eq!(code, 0, "exit {code}; 101 is the panic hook");
    assert_eq!(reports, 0, "a crash report was written");
    Ok(())
}

/// `2>&1 | head`: stdout and stderr both lose their reader. stdout's
/// `BrokenPipe` already counted as success; stderr's must not undo that.
#[test]
fn both_streams_closed_is_a_clean_exit() -> Result<(), TestError> {
    let pcap = fixture("sip_call.pcap");
    let (code, reports) = exit_code_with_stderr_gone(&["-N", "-I", &pcap], "info", reader_gone()?)?;
    assert_eq!(code, 0, "exit {code}; 101 is the panic hook");
    assert_eq!(reports, 0, "a crash report was written");
    Ok(())
}

/// No source file writes to stderr with `eprintln!` or `eprint!`, which panic
/// when the write fails. `stderr_line!` (defined in `src/lib.rs`) writes the
/// same line and drops the error. One rule in one place: a new `eprintln!`
/// anywhere in `src/` would bring the crash back on its own path.
#[test]
fn no_source_file_uses_a_panicking_stderr_macro() -> Result<(), TestError> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("git")
        .args(["ls-files", "-z", "--", "src/*.rs", "src/**/*.rs"])
        .current_dir(root)
        .output()?;
    assert!(out.status.success(), "git ls-files failed");
    let mut files = 0;
    let mut offenders = Vec::new();
    for rel in String::from_utf8_lossy(&out.stdout).split('\0') {
        if rel.is_empty() {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(root.join(rel))?;
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("eprintln!") || code.contains("eprint!") {
                offenders.push(format!("{rel}:{}", n + 1));
            }
        }
    }
    assert!(files >= 290, "read only {files} source files");
    assert!(
        offenders.is_empty(),
        "{} stderr write(s) that panic when stderr is a closed pipe; use \
         stderr_line!: {offenders:?}",
        offenders.len()
    );
    Ok(())
}
