// SPDX-License-Identifier: MIT OR Apache-2.0

//! A reader that closes stdout must not turn a finished run into a crash.
//!
//! `sipnab ... | head -1` closes stdout after one line, and every later write
//! fails with `EPIPE`. The per-message output already treats that as the
//! reader's choice; the end-of-run prints (`--wireshark`, `--tshark-filter`,
//! `--recommend-block`, `-D` and the other one-shot answers) used `println!`,
//! which panics when its write fails. The panic hook then exited 101 and wrote
//! a crash report for a run that had done everything it was asked.
//!
//! Each case hands the child a stdout pipe whose read end is already closed,
//! so every write fails from the first byte. Racing a real `head` would make
//! the result depend on timing; this makes it depend only on sipnab.

use std::process::{Command, Stdio};

/// The error a test returns: any error, boxed, so `?` works on every error.
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

/// Run sipnab with `args` and stdout into a pipe with no reader. Returns the
/// exit code and the number of crash reports written. Crash reports go to a
/// private directory, so a panic is visible to the test as a file and never
/// lands in the developer's own state directory.
fn run_with_stdout_gone(args: &[&str]) -> Result<(i32, usize), TestError> {
    let state = tempfile::tempdir()?;
    let status = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("XDG_STATE_HOME", state.path())
        .env("HOME", state.path())
        .env("XDG_CONFIG_HOME", state.path())
        .stdin(Stdio::null())
        .stdout(reader_gone()?)
        .stderr(Stdio::null())
        .status()?;
    Ok((status.code().unwrap_or(-1), walk_count(state.path())))
}

/// Every one-shot answer printed after a batch run, and the config dump,
/// exits as it would with a reader: the reader leaving is not a failure of
/// the run.
#[test]
fn end_of_run_prints_to_a_closed_stdout_do_not_crash() -> Result<(), TestError> {
    let call = fixture("sip_call.pcap");
    let flood = fixture("sip-scanner-and-register-flood.pcap");
    let cases: [(&str, Vec<&str>); 4] = [
        ("--wireshark", vec!["-N", "-q", "-I", &call, "--wireshark"]),
        (
            "--tshark-filter",
            vec!["-N", "-q", "-I", &call, "--tshark-filter", "sip"],
        ),
        (
            "--recommend-block",
            vec![
                "-N",
                "-q",
                "-I",
                &flood,
                "--kill-scanner",
                "--recommend-block",
                "all",
            ],
        ),
        ("-D", vec!["--no-config", "-D"]),
    ];
    let mut failures = Vec::new();
    for (name, args) in &cases {
        let (code, reports) = run_with_stdout_gone(args)?;
        if code != 0 || reports != 0 {
            failures.push(format!("{name}: exit {code}, {reports} crash report(s)"));
        }
    }
    assert!(
        failures.is_empty(),
        "a closed stdout crashed these runs (101 is the panic hook):\n{}",
        failures.join("\n")
    );
    Ok(())
}
