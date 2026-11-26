// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! FILE-2 (d): the first failed write to standard output is said at once.
//!
//! The per-message output (printed messages, `--json` lines) goes to
//! standard output through one buffered sink. Before this rule a write that
//! failed for a reason other than a closed pipe, such as a full disk under
//! `sipnab --json > out.ndjson`, was said only at the end of the run, which
//! for a live capture can be days later. Now the first such failure prints
//! one line on standard error when it happens, and the end-of-run line and
//! exit code 1 stay as they were.
//!
//! `/dev/full` fails every write with `ENOSPC`, so it stands in for a full
//! disk; it is a Linux device, so the file is Linux-only. The line is tested
//! here through the real binary; the rule that only the first hard failure
//! calls it is tested in src/output/sink.rs. Names prefixed `s_` are
//! success cases, `f_` cases where no line may appear, `e_` edge cases.
#![cfg(all(target_os = "linux", feature = "native"))]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

type TestError = Box<dyn std::error::Error>;

#[path = "support/run.rs"]
mod run_support;

#[path = "support/pcap_build.rs"]
mod pcap_build;

include!("support/timeout.rs");
include!("support/child_lifetime.rs");

/// The capture most runs read.
const FIXTURE: &str = "tests/fixtures/sip_call.pcap";

/// The start of the line the first failure prints.
const FIRST: &str = "Writing standard output failed: ";

/// The start of the end-of-run line.
const END: &str = "Failed to write output: ";

/// One finished run.
struct Run {
    /// Standard error.
    stderr: String,
    /// The exit code; `None` when a signal ended it or the deadline passed.
    code: Option<i32>,
}

impl Run {
    /// How many stderr lines start with `prefix`.
    fn lines_starting(&self, prefix: &str) -> usize {
        self.stderr
            .lines()
            .filter(|l| l.starts_with(prefix))
            .count()
    }

    /// The run, for an assertion message.
    fn dump(&self) -> String {
        format!("code {:?}\n--- stderr ---\n{}", self.code, self.stderr)
    }
}

/// Where a run's standard output goes.
enum Out<'a> {
    /// `/dev/full`: every write fails with `ENOSPC`.
    Full,
    /// `/dev/null`: every write succeeds.
    Null,
    /// A new file at this path.
    File(&'a Path),
    /// A pipe whose read end is closed at once: writes fail with `EPIPE`.
    ClosedPipe,
}

/// Run `sipnab -N args` with standard output at `out` and `SIPNAB_LOG=log`,
/// ended at a deadline.
fn sipnab(args: &[&str], out: &Out<'_>, log: &str) -> Result<Run, TestError> {
    let home = tempfile::tempdir()?;
    let stdout = match out {
        Out::Full => Stdio::from(std::fs::OpenOptions::new().write(true).open("/dev/full")?),
        Out::Null => Stdio::null(),
        Out::File(p) => Stdio::from(std::fs::File::create(p)?),
        Out::ClosedPipe => Stdio::piped(),
    };
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("-N")
        .args(args)
        .envs(run_support::config_isolation(home.path()))
        .env("SIPNAB_LOG", log)
        .env("NO_COLOR", "1")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .tied_to_test()
        .spawn()?;
    drop(child.stdout.take());
    let mut pipe = child.stderr.take().ok_or("stderr is piped")?;
    let reader = std::thread::spawn(move || {
        use std::io::Read as _;
        let mut s = String::new();
        let _ = pipe.read_to_string(&mut s);
        s
    });
    let deadline = Instant::now() + test_timeout(60);
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait()?;
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let stderr = reader.join().map_err(|_| "the stderr reader failed")?;
    Ok(Run {
        stderr,
        code: status.and_then(|st| st.code()),
    })
}

/// A capture of `calls` SIP calls in `dir`; its per-message output is far
/// past the sink's 64 KiB buffer, so writes fail many times in one run.
fn long_capture(dir: &Path, calls: usize) -> Result<String, TestError> {
    let cap = dir.join("long.pcap");
    let frames: Vec<Vec<u8>> = (0..calls)
        .flat_map(|i| {
            pcap_build::sip_call_frames(&format!("ff-{i}@t"), &format!("{i:06x}"), "a", "b")
        })
        .collect();
    pcap_build::write_pcap(&cap, &frames)?;
    Ok(cap.to_str().ok_or("not UTF-8")?.to_owned())
}

/// Assert that `run` printed the first-failure line exactly once and
/// exited 1.
fn assert_said_once(run: &Run, what: &str) {
    assert_eq!(
        run.lines_starting(FIRST),
        1,
        "{what}: the first failure is said once\n{}",
        run.dump()
    );
    assert_eq!(run.code, Some(1), "{what}: the run exits 1\n{}", run.dump());
}

/// Assert that `run` printed no first-failure line.
fn assert_no_line(run: &Run, what: &str) {
    assert_eq!(
        run.lines_starting(FIRST),
        0,
        "{what}: no first-failure line\n{}",
        run.dump()
    );
}

// ── Success ─────────────────────────────────────────────────────────

/// `--json` into a full disk says so once.
#[test]
fn s_json_to_a_full_disk_says_so_once() -> Result<(), TestError> {
    let run = sipnab(&["--json", "-I", FIXTURE], &Out::Full, "off")?;
    assert_said_once(&run, "--json > /dev/full");
    Ok(())
}

/// The first-failure line comes before the end-of-run line, which stays.
#[test]
fn s_the_first_line_comes_before_the_end_of_run_line() -> Result<(), TestError> {
    let run = sipnab(&["--json", "-I", FIXTURE], &Out::Full, "off")?;
    let first = run.stderr.find(FIRST).ok_or_else(|| run.dump())?;
    let end = run.stderr.find(END).ok_or_else(|| run.dump())?;
    assert!(
        first < end,
        "first line before the end line\n{}",
        run.dump()
    );
    assert_eq!(run.lines_starting(END), 1, "one end line\n{}", run.dump());
    Ok(())
}

/// `--json-pretty` into a full disk says so once.
#[test]
fn s_json_pretty_to_a_full_disk_says_so_once() -> Result<(), TestError> {
    let run = sipnab(&["--json-pretty", "-I", FIXTURE], &Out::Full, "off")?;
    assert_said_once(&run, "--json-pretty > /dev/full");
    Ok(())
}

/// The printed messages (no `--json`) into a full disk say so once.
#[test]
fn s_text_output_to_a_full_disk_says_so_once() -> Result<(), TestError> {
    let run = sipnab(&["-I", FIXTURE], &Out::Full, "off")?;
    assert_said_once(&run, "text > /dev/full");
    Ok(())
}

/// `--line-buffer` (a flush per message) into a full disk says so once.
#[test]
fn s_line_buffered_json_to_a_full_disk_says_so_once() -> Result<(), TestError> {
    let run = sipnab(
        &["--json", "--line-buffer", "-I", FIXTURE],
        &Out::Full,
        "off",
    )?;
    assert_said_once(&run, "--json --line-buffer > /dev/full");
    Ok(())
}

/// The line carries the system's error text.
#[test]
fn s_the_line_names_the_system_error() -> Result<(), TestError> {
    let run = sipnab(&["--json", "-I", FIXTURE], &Out::Full, "off")?;
    let line = run
        .stderr
        .lines()
        .find(|l| l.starts_with(FIRST))
        .ok_or_else(|| run.dump())?;
    assert!(
        line.contains("No space left on device"),
        "the ENOSPC text is in the line: {line}"
    );
    Ok(())
}

/// The line is printed with logging at its default level too.
#[test]
fn s_the_line_is_printed_with_logging_on() -> Result<(), TestError> {
    let run = sipnab(&["--json", "-I", FIXTURE], &Out::Full, "info")?;
    assert_said_once(&run, "SIPNAB_LOG=info");
    Ok(())
}

/// A run whose output fails many times says so once.
#[test]
fn s_a_long_run_to_a_full_disk_says_so_once() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let cap = long_capture(dir.path(), 400)?;
    let run = sipnab(&["--json", "-I", &cap], &Out::Full, "off")?;
    assert_said_once(&run, "400 calls > /dev/full");
    Ok(())
}

/// The line says that the run goes on and exits 1.
#[test]
fn s_the_line_says_what_happens_next() -> Result<(), TestError> {
    let run = sipnab(&["--json", "-I", FIXTURE], &Out::Full, "off")?;
    let line = run
        .stderr
        .lines()
        .find(|l| l.starts_with(FIRST))
        .ok_or_else(|| run.dump())?;
    assert!(
        line.contains("The run continues") && line.contains("exits 1"),
        "the line says what happens next: {line}"
    );
    Ok(())
}

// ── Failure: no line ────────────────────────────────────────────────

/// A closed pipe (`| head`) is the reader's choice: no line, and the run
/// does not fail.
#[test]
fn f_a_closed_pipe_prints_no_line() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let cap = long_capture(dir.path(), 400)?;
    let run = sipnab(&["--json", "-I", &cap], &Out::ClosedPipe, "off")?;
    assert_no_line(&run, "closed pipe");
    assert_eq!(run.lines_starting(END), 0, "no end line\n{}", run.dump());
    Ok(())
}

/// A writable file gets the output and no line.
#[test]
fn f_a_writable_file_prints_no_line() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("out.ndjson");
    let run = sipnab(&["--json", "-I", FIXTURE], &Out::File(&out), "off")?;
    assert_no_line(&run, "writable file");
    assert_eq!(run.code, Some(0), "the run succeeds\n{}", run.dump());
    assert!(
        std::fs::metadata(&out)?.len() > 0,
        "the NDJSON reached the file"
    );
    Ok(())
}

/// `/dev/null` takes every write: no line.
#[test]
fn f_dev_null_prints_no_line() -> Result<(), TestError> {
    let run = sipnab(&["--json", "-I", FIXTURE], &Out::Null, "off")?;
    assert_no_line(&run, "/dev/null");
    assert_eq!(run.code, Some(0), "the run succeeds\n{}", run.dump());
    Ok(())
}

/// With the per-message output turned off, nothing is written to the full
/// disk and no line is printed.
#[test]
fn f_no_cli_print_to_a_full_disk_prints_no_line() -> Result<(), TestError> {
    let run = sipnab(
        &["--quiet", "--no-cli-print", "-I", FIXTURE],
        &Out::Full,
        "off",
    )?;
    assert_no_line(&run, "--no-cli-print");
    Ok(())
}

/// A long run into a closed pipe with `--line-buffer` prints no line.
#[test]
fn f_a_closed_pipe_with_line_buffer_prints_no_line() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let cap = long_capture(dir.path(), 400)?;
    let run = sipnab(
        &["--json", "--line-buffer", "-I", &cap],
        &Out::ClosedPipe,
        "off",
    )?;
    assert_no_line(&run, "closed pipe, --line-buffer");
    Ok(())
}

// ── Edge ────────────────────────────────────────────────────────────

/// The run goes on after the failure: the `-O` capture file is written as
/// it is when standard output works.
#[test]
fn e_the_capture_file_is_still_written_whole() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let good = dir.path().join("good.pcap");
    let full = dir.path().join("full.pcap");
    let g = good.to_str().ok_or("not UTF-8")?;
    let f = full.to_str().ok_or("not UTF-8")?;
    let control = sipnab(&["--json", "-I", FIXTURE, "-O", g], &Out::Null, "off")?;
    assert_eq!(control.code, Some(0), "the control run\n{}", control.dump());
    let run = sipnab(&["--json", "-I", FIXTURE, "-O", f], &Out::Full, "off")?;
    assert_said_once(&run, "-O beside /dev/full");
    assert_eq!(
        std::fs::read(&full)?,
        std::fs::read(&good)?,
        "the capture file matches the control"
    );
    Ok(())
}

/// A capture with no packets writes nothing to the full disk: no line, and
/// the run succeeds.
///
/// A standard output opened read-only is not tested here: Rust's standard
/// library reports a write that fails with `EBADF` on standard output as
/// written, so no error reaches sipnab (reported to the coordinator as its
/// own item, 2026-11-25).
#[test]
fn e_an_empty_capture_to_a_full_disk_prints_no_line() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let cap = dir.path().join("empty.pcap");
    pcap_build::write_pcap(&cap, &[])?;
    let run = sipnab(
        &["--json", "-I", cap.to_str().ok_or("not UTF-8")?],
        &Out::Full,
        "off",
    )?;
    assert_no_line(&run, "empty capture");
    assert_eq!(
        run.code,
        Some(0),
        "nothing to write, no failure\n{}",
        run.dump()
    );
    Ok(())
}

/// A long run with `--line-buffer`, which fails at every message, says so
/// once.
#[test]
fn e_a_long_line_buffered_run_says_so_once() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let cap = long_capture(dir.path(), 400)?;
    let run = sipnab(&["--json", "--line-buffer", "-I", &cap], &Out::Full, "off")?;
    assert_said_once(&run, "400 calls, --line-buffer > /dev/full");
    Ok(())
}

/// The line is one line: no newline inside it splits it.
#[test]
fn e_the_line_is_one_line() -> Result<(), TestError> {
    let run = sipnab(&["--json", "-I", FIXTURE], &Out::Full, "off")?;
    let line = run
        .stderr
        .lines()
        .find(|l| l.starts_with(FIRST))
        .ok_or_else(|| run.dump())?;
    assert!(
        line.ends_with("exits 1."),
        "the whole message is on its line: {line}"
    );
    Ok(())
}
