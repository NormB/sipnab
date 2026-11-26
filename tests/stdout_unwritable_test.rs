// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A run whose standard output cannot be written says so and exits 6.
//!
//! Rust's standard library hides two cases from a program. A write to a
//! standard output opened read-only fails with `EBADF`, and `std::io::Stdout`
//! reports that failure as a successful write (`handle_ebadf` in
//! `library/std/src/io/stdio.rs`). A standard output that was closed when the
//! process started is opened on `/dev/null` by the runtime before `main`
//! (`sanitize_standard_fds` in `library/std/src/sys/pal/unix/mod.rs`), so
//! every write succeeds. Both runs used to exit 0 with no output and no word.
//!
//! Each case runs the real binary with standard output set up by the test.
//! Names prefixed `s_` are success cases (the output arrives, the run exits
//! 0), `f_` failure cases (the run refuses, names the reason on stderr and
//! exits 6), `e_` edge cases. The rule that decides is tested in
//! src/output/stdout.rs.
#![cfg(all(target_os = "linux", feature = "native"))]

use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

type TestError = Box<dyn std::error::Error>;

#[path = "support/run.rs"]
mod run_support;

#[path = "support/pcap_build.rs"]
mod pcap_build;

#[path = "support/source_scan.rs"]
mod source_scan;

include!("support/timeout.rs");
include!("support/child_lifetime.rs");

/// The capture most runs read.
const FIXTURE: &str = "tests/fixtures/sip_call.pcap";

/// The exit code of a run whose standard output could not be written.
const UNWRITABLE: i32 = 6;

/// The reason named for a standard output closed at start.
const CLOSED: &str = "standard output is closed";

/// The reason named for a standard output not open for writing.
const NOT_FOR_WRITING: &str = "standard output is not open for writing";

/// The start of the line the per-message output's first failure prints.
const FIRST: &str = "Writing standard output failed: ";

/// One finished run.
struct Run {
    /// Standard error; empty when the test closed it.
    stderr: String,
    /// The exit code; `None` when a signal ended it or the deadline passed.
    code: Option<i32>,
}

impl Run {
    /// How many stderr lines contain `text`.
    fn lines_with(&self, text: &str) -> usize {
        self.stderr.lines().filter(|l| l.contains(text)).count()
    }

    /// The run, for an assertion message.
    fn dump(&self) -> String {
        format!("code {:?}\n--- stderr ---\n{}", self.code, self.stderr)
    }
}

/// Where a run's standard output goes.
enum Out<'a> {
    /// A file opened read-only: every write fails with `EBADF`.
    ReadOnly,
    /// No descriptor 1 at all when the process starts.
    Closed,
    /// An `O_PATH` descriptor: it names a file and cannot be written.
    PathOnly,
    /// A new file at this path.
    File(&'a Path),
    /// `/dev/null` opened write-only, as `> /dev/null` does.
    NullWriteOnly,
    /// `/dev/null` opened for reading and writing, as `1<> /dev/null` does.
    NullReadWrite,
    /// `/dev/full`: every write fails with `ENOSPC`.
    Full,
    /// A pipe whose read end is closed at once: writes fail with `EPIPE`.
    ClosedPipe,
}

/// What else the test changes about the child.
#[derive(Clone, Copy, Default)]
struct Also {
    /// Close standard input before the program starts.
    close_stdin: bool,
    /// Close standard error before the program starts.
    close_stderr: bool,
}

/// Run `sipnab args` with standard output at `out`, ended at a deadline.
fn sipnab(args: &[&str], out: &Out<'_>) -> Result<Run, TestError> {
    sipnab_with(args, out, Also::default())
}

/// [`sipnab`], with the changes in `also`.
fn sipnab_with(args: &[&str], out: &Out<'_>, also: Also) -> Result<Run, TestError> {
    let home = tempfile::tempdir()?;
    let target = home.path().join("stdout-target");
    std::fs::write(&target, b"")?;
    let close_stdout = matches!(out, Out::Closed);
    let stdout = match out {
        Out::ReadOnly => Stdio::from(std::fs::File::open(&target)?),
        Out::Closed => Stdio::null(),
        Out::PathOnly => Stdio::from(
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH)
                .open(&target)?,
        ),
        Out::File(p) => Stdio::from(std::fs::File::create(p)?),
        Out::NullWriteOnly => {
            Stdio::from(std::fs::OpenOptions::new().write(true).open("/dev/null")?)
        }
        Out::NullReadWrite => Stdio::from(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")?,
        ),
        Out::Full => Stdio::from(std::fs::OpenOptions::new().write(true).open("/dev/full")?),
        Out::ClosedPipe => Stdio::piped(),
    };
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.args(args)
        .envs(run_support::config_isolation(home.path()))
        .env("SIPNAB_LOG", "off")
        .env("NO_COLOR", "1")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped());
    let (close_stdin, close_stderr) = (also.close_stdin, also.close_stderr);
    // SAFETY: the closure runs in the forked child before exec and calls
    // only close(2), which is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            if close_stdout {
                libc::close(1);
            }
            if close_stdin {
                libc::close(0);
            }
            if close_stderr {
                libc::close(2);
            }
            Ok(())
        });
    }
    let mut child = cmd.tied_to_test().spawn()?;
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

/// Assert that `run` exited 6 and named `reason` on stderr.
fn assert_refused(run: &Run, reason: &str, what: &str) {
    assert_eq!(
        run.code,
        Some(UNWRITABLE),
        "{what}: the run exits {UNWRITABLE}\n{}",
        run.dump()
    );
    assert!(
        run.lines_with(reason) >= 1,
        "{what}: stderr names `{reason}`\n{}",
        run.dump()
    );
}

/// Run `args` with its output in a file; return the run and the file's text.
fn to_file(args: &[&str]) -> Result<(Run, String), TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("out");
    let run = sipnab(args, &Out::File(&path))?;
    let text = std::fs::read_to_string(&path)?;
    Ok((run, text))
}

/// Assert that `run` exited 0 with `text` holding its output.
fn assert_delivered(run: &Run, text: &str, what: &str) {
    assert_eq!(run.code, Some(0), "{what}: the run exits 0\n{}", run.dump());
    assert!(
        !text.is_empty(),
        "{what}: the output arrived\n{}",
        run.dump()
    );
    assert_eq!(
        run.lines_with(CLOSED) + run.lines_with(NOT_FOR_WRITING),
        0,
        "{what}: no refusal is named\n{}",
        run.dump()
    );
}

/// A capture of `calls` SIP calls in `dir`, far past the sink's buffer.
fn long_capture(dir: &Path, calls: usize) -> Result<String, TestError> {
    let cap = dir.join("long.pcap");
    let frames: Vec<Vec<u8>> = (0..calls)
        .flat_map(|i| {
            pcap_build::sip_call_frames(&format!("uw-{i}@t"), &format!("{i:06x}"), "a", "b")
        })
        .collect();
    pcap_build::write_pcap(&cap, &frames)?;
    Ok(cap.to_str().ok_or("not UTF-8")?.to_owned())
}

// ── Failure: the run refuses ─────────────────────────────────────────

/// The printed messages into a read-only standard output.
#[test]
fn f_text_read_only() -> Result<(), TestError> {
    let run = sipnab(&["-N", "-I", FIXTURE], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "text, read-only");
    Ok(())
}

/// The printed messages into a closed standard output.
#[test]
fn f_text_closed() -> Result<(), TestError> {
    let run = sipnab(&["-N", "-I", FIXTURE], &Out::Closed)?;
    assert_refused(&run, CLOSED, "text, closed");
    Ok(())
}

/// `--json` into a read-only standard output (the backlog's case).
#[test]
fn f_json_read_only() -> Result<(), TestError> {
    let run = sipnab(&["-N", "--json", "-I", FIXTURE], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "--json, read-only");
    Ok(())
}

/// `--json` into a closed standard output.
#[test]
fn f_json_closed() -> Result<(), TestError> {
    let run = sipnab(&["-N", "--json", "-I", FIXTURE], &Out::Closed)?;
    assert_refused(&run, CLOSED, "--json, closed");
    Ok(())
}

/// `--json-pretty` into a read-only standard output.
#[test]
fn f_json_pretty_read_only() -> Result<(), TestError> {
    let run = sipnab(&["-N", "--json-pretty", "-I", FIXTURE], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "--json-pretty, read-only");
    Ok(())
}

/// `--json-pretty` into a closed standard output.
#[test]
fn f_json_pretty_closed() -> Result<(), TestError> {
    let run = sipnab(&["-N", "--json-pretty", "-I", FIXTURE], &Out::Closed)?;
    assert_refused(&run, CLOSED, "--json-pretty, closed");
    Ok(())
}

/// `--json --line-buffer` (a flush per message) into a read-only output.
#[test]
fn f_line_buffered_json_read_only() -> Result<(), TestError> {
    let run = sipnab(
        &["-N", "--json", "--line-buffer", "-I", FIXTURE],
        &Out::ReadOnly,
    )?;
    assert_refused(&run, NOT_FOR_WRITING, "--json --line-buffer, read-only");
    Ok(())
}

/// The `--report` table into a read-only standard output.
#[test]
fn f_report_read_only() -> Result<(), TestError> {
    let run = sipnab(&["-N", "-q", "--report", "-I", FIXTURE], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "--report, read-only");
    Ok(())
}

/// The `--report` table into a closed standard output.
#[test]
fn f_report_closed() -> Result<(), TestError> {
    let run = sipnab(&["-N", "-q", "--report", "-I", FIXTURE], &Out::Closed)?;
    assert_refused(&run, CLOSED, "--report, closed");
    Ok(())
}

/// `--dump-config` into a read-only standard output.
#[test]
fn f_dump_config_read_only() -> Result<(), TestError> {
    let run = sipnab(&["-D"], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "-D, read-only");
    Ok(())
}

/// `--dump-config` into a closed standard output.
#[test]
fn f_dump_config_closed() -> Result<(), TestError> {
    let run = sipnab(&["-D"], &Out::Closed)?;
    assert_refused(&run, CLOSED, "-D, closed");
    Ok(())
}

/// `--help` into a read-only standard output.
#[test]
fn f_help_read_only() -> Result<(), TestError> {
    let run = sipnab(&["--help"], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "--help, read-only");
    Ok(())
}

/// `--help` into a closed standard output.
#[test]
fn f_help_closed() -> Result<(), TestError> {
    let run = sipnab(&["--help"], &Out::Closed)?;
    assert_refused(&run, CLOSED, "--help, closed");
    Ok(())
}

/// `--version` into a read-only standard output.
#[test]
fn f_version_read_only() -> Result<(), TestError> {
    let run = sipnab(&["--version"], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "--version, read-only");
    Ok(())
}

/// `--version` into a closed standard output.
#[test]
fn f_version_closed() -> Result<(), TestError> {
    let run = sipnab(&["--version"], &Out::Closed)?;
    assert_refused(&run, CLOSED, "--version, closed");
    Ok(())
}

/// `--print-yang-module` into a read-only standard output.
#[test]
fn f_print_yang_module_read_only() -> Result<(), TestError> {
    let run = sipnab(&["--print-yang-module"], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "--print-yang-module, read-only");
    Ok(())
}

/// `--print-yang-module` into a closed standard output.
#[test]
fn f_print_yang_module_closed() -> Result<(), TestError> {
    let run = sipnab(&["--print-yang-module"], &Out::Closed)?;
    assert_refused(&run, CLOSED, "--print-yang-module, closed");
    Ok(())
}

/// `sipnab fleet --help` into a read-only standard output.
#[test]
fn f_fleet_help_read_only() -> Result<(), TestError> {
    let run = sipnab(&["fleet", "--help"], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "fleet --help, read-only");
    Ok(())
}

/// `sipnab g729 --help` into a closed standard output.
#[test]
fn f_g729_help_closed() -> Result<(), TestError> {
    let run = sipnab(&["g729", "--help"], &Out::Closed)?;
    assert_refused(&run, CLOSED, "g729 --help, closed");
    Ok(())
}

/// `--json` into an `O_PATH` descriptor, which no write can use.
#[test]
fn f_json_path_only() -> Result<(), TestError> {
    let run = sipnab(&["-N", "--json", "-I", FIXTURE], &Out::PathOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "--json, O_PATH");
    Ok(())
}

/// The MCP stdio server with a read-only wire refuses before it serves.
#[cfg(feature = "mcp")]
#[test]
fn f_mcp_stdio_read_only() -> Result<(), TestError> {
    let run = sipnab(&["--mcp", "-I", FIXTURE], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "--mcp, read-only");
    Ok(())
}

/// The MCP stdio server with a closed wire refuses before it serves.
#[cfg(feature = "mcp")]
#[test]
fn f_mcp_stdio_closed() -> Result<(), TestError> {
    let run = sipnab(&["--mcp", "-I", FIXTURE], &Out::Closed)?;
    assert_refused(&run, CLOSED, "--mcp, closed");
    Ok(())
}

/// `--completions bash` into a read-only standard output.
#[test]
fn f_completions_read_only() -> Result<(), TestError> {
    let run = sipnab(&["--completions", "bash"], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "--completions, read-only");
    Ok(())
}

/// `--completions bash` into a closed standard output.
#[test]
fn f_completions_closed() -> Result<(), TestError> {
    let run = sipnab(&["--completions", "bash"], &Out::Closed)?;
    assert_refused(&run, CLOSED, "--completions, closed");
    Ok(())
}

// ── Success: the output arrives ──────────────────────────────────────

/// `--completions bash` into a file is the script.
#[test]
fn s_completions_to_a_file() -> Result<(), TestError> {
    let (run, text) = to_file(&["--completions", "bash"])?;
    assert_delivered(&run, &text, "--completions > file");
    assert!(text.contains("sipnab"), "the script names the command");
    Ok(())
}

/// The MCP stdio server with a writable wire and no client ends cleanly.
#[cfg(feature = "mcp")]
#[test]
fn s_mcp_stdio_to_a_file_exits_0() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let run = sipnab(
        &["--mcp", "-I", FIXTURE],
        &Out::File(&dir.path().join("out")),
    )?;
    assert_eq!(run.code, Some(0), "--mcp > file exits 0\n{}", run.dump());
    Ok(())
}

/// The printed messages into a file.
#[test]
fn s_text_to_a_file() -> Result<(), TestError> {
    let (run, text) = to_file(&["-N", "-I", FIXTURE])?;
    assert_delivered(&run, &text, "text > file");
    Ok(())
}

/// `--json` into a file: one JSON object per line.
#[test]
fn s_json_to_a_file() -> Result<(), TestError> {
    let (run, text) = to_file(&["-N", "--json", "-I", FIXTURE])?;
    assert_delivered(&run, &text, "--json > file");
    for line in text.lines() {
        serde_json::from_str::<serde_json::Value>(line)
            .map_err(|e| format!("not a JSON line ({e}): {line}"))?;
    }
    Ok(())
}

/// `--json-pretty` into a file.
#[test]
fn s_json_pretty_to_a_file() -> Result<(), TestError> {
    let (run, text) = to_file(&["-N", "--json-pretty", "-I", FIXTURE])?;
    assert_delivered(&run, &text, "--json-pretty > file");
    Ok(())
}

/// The `--report` table into a file.
#[test]
fn s_report_to_a_file() -> Result<(), TestError> {
    let (run, text) = to_file(&["-N", "-q", "--report", "-I", FIXTURE])?;
    assert_delivered(&run, &text, "--report > file");
    Ok(())
}

/// `--dump-config` into a file names the version.
#[test]
fn s_dump_config_to_a_file() -> Result<(), TestError> {
    let (run, text) = to_file(&["-D"])?;
    assert_delivered(&run, &text, "-D > file");
    assert!(text.starts_with("sipnab v"), "the version line: {text}");
    Ok(())
}

/// `--help` into a file.
#[test]
fn s_help_to_a_file() -> Result<(), TestError> {
    let (run, text) = to_file(&["--help"])?;
    assert_delivered(&run, &text, "--help > file");
    assert!(text.contains("Usage"), "the help text: {text}");
    Ok(())
}

/// `--version` into a file.
#[test]
fn s_version_to_a_file() -> Result<(), TestError> {
    let (run, text) = to_file(&["--version"])?;
    assert_delivered(&run, &text, "--version > file");
    assert!(text.starts_with("sipnab "), "the version text: {text}");
    Ok(())
}

/// `--print-yang-module` into a file.
#[test]
fn s_print_yang_module_to_a_file() -> Result<(), TestError> {
    let (run, text) = to_file(&["--print-yang-module"])?;
    assert_delivered(&run, &text, "--print-yang-module > file");
    assert!(text.contains("module"), "the module text");
    Ok(())
}

/// `sipnab fleet --help` into a file.
#[test]
fn s_fleet_help_to_a_file() -> Result<(), TestError> {
    let (run, text) = to_file(&["fleet", "--help"])?;
    assert_delivered(&run, &text, "fleet --help > file");
    Ok(())
}

/// `sipnab g729 --help` into a file.
#[test]
fn s_g729_help_to_a_file() -> Result<(), TestError> {
    let (run, text) = to_file(&["g729", "--help"])?;
    assert_delivered(&run, &text, "g729 --help > file");
    Ok(())
}

/// `> /dev/null`, opened write-only, is a writable output.
#[test]
fn s_json_to_dev_null_write_only() -> Result<(), TestError> {
    let run = sipnab(&["-N", "--json", "-I", FIXTURE], &Out::NullWriteOnly)?;
    assert_eq!(run.code, Some(0), "> /dev/null exits 0\n{}", run.dump());
    Ok(())
}

/// `1<> /dev/null` is opened read-write as the runtime opens a closed
/// descriptor; the rule must not mistake it for a closed one.
#[test]
fn s_json_to_dev_null_read_write() -> Result<(), TestError> {
    let run = sipnab(&["-N", "--json", "-I", FIXTURE], &Out::NullReadWrite)?;
    assert_eq!(run.code, Some(0), "1<> /dev/null exits 0\n{}", run.dump());
    Ok(())
}

/// `--help` into `> /dev/null` exits 0.
#[test]
fn s_help_to_dev_null() -> Result<(), TestError> {
    let run = sipnab(&["--help"], &Out::NullWriteOnly)?;
    assert_eq!(
        run.code,
        Some(0),
        "--help > /dev/null exits 0\n{}",
        run.dump()
    );
    Ok(())
}

/// A closed standard input alone leaves standard output usable.
#[test]
fn s_closed_stdin_leaves_stdout_writable() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("out");
    let run = sipnab_with(
        &["-N", "--json", "-I", FIXTURE],
        &Out::File(&path),
        Also {
            close_stdin: true,
            ..Also::default()
        },
    )?;
    let text = std::fs::read_to_string(&path)?;
    assert_delivered(&run, &text, "<&- --json > file");
    Ok(())
}

// ── Edge cases ───────────────────────────────────────────────────────

/// A reader that closed the pipe (`| head`) is still not an error.
#[test]
fn e_closed_pipe_still_exits_0() -> Result<(), TestError> {
    let run = sipnab(&["-N", "--json", "-I", FIXTURE], &Out::ClosedPipe)?;
    assert_eq!(run.code, Some(0), "| head exits 0\n{}", run.dump());
    Ok(())
}

/// A full disk keeps its own code, 1, and its own reason.
#[test]
fn e_full_disk_still_exits_1() -> Result<(), TestError> {
    let run = sipnab(&["-N", "--json", "-I", FIXTURE], &Out::Full)?;
    assert_eq!(run.code, Some(1), "> /dev/full exits 1\n{}", run.dump());
    assert!(
        run.lines_with("No space left on device") >= 1,
        "the ENOSPC text\n{}",
        run.dump()
    );
    Ok(())
}

/// A run that writes nothing to standard output is not refused for it: no
/// message matches the filter, so nothing is printed (`-q` still prints a
/// line per message, so it is not this case).
#[test]
fn e_run_printing_nothing_with_closed_stdout_exits_0() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = dir.path().join("out.pcap");
    let pcap_arg = pcap.to_str().ok_or("not UTF-8")?;
    let run = sipnab(
        &[
            "-N",
            "-I",
            FIXTURE,
            "--from",
            "no-such-sender-example",
            "-O",
            pcap_arg,
        ],
        &Out::Closed,
    )?;
    assert_eq!(run.code, Some(0), "no match, >&- exits 0\n{}", run.dump());
    assert!(std::fs::metadata(&pcap)?.len() > 24, "-O was written");
    Ok(())
}

/// `-O` is still written in full when the printed messages cannot be.
#[test]
fn e_dash_o_is_written_when_stdout_is_closed() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = dir.path().join("out.pcap");
    let pcap_arg = pcap.to_str().ok_or("not UTF-8")?;
    let run = sipnab(&["-N", "-I", FIXTURE, "-O", pcap_arg], &Out::Closed)?;
    assert_refused(&run, CLOSED, "-O with >&-");
    let written = std::fs::metadata(&pcap)?.len();
    let fixture = std::fs::metadata(FIXTURE)?.len();
    assert_eq!(written, fixture, "-O holds every frame of the input");
    Ok(())
}

/// The per-message output's first failure is said once, with the reason.
#[test]
fn e_first_failure_line_is_said_once() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let cap = long_capture(dir.path(), 400)?;
    let run = sipnab(&["-N", "--json", "-I", &cap], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "400 calls, read-only");
    let firsts: Vec<&str> = run
        .stderr
        .lines()
        .filter(|l| l.starts_with(FIRST))
        .collect();
    assert_eq!(firsts.len(), 1, "one first-failure line\n{}", run.dump());
    assert!(
        firsts.iter().all(|l| l.contains(NOT_FOR_WRITING)),
        "the line names the reason\n{}",
        run.dump()
    );
    Ok(())
}

/// The first-failure line states the code the run exits with.
#[test]
fn e_first_failure_line_says_exits_6() -> Result<(), TestError> {
    let run = sipnab(&["-N", "--json", "-I", FIXTURE], &Out::Closed)?;
    let line = run
        .stderr
        .lines()
        .find(|l| l.starts_with(FIRST))
        .ok_or_else(|| run.dump())?;
    assert!(line.ends_with("and it exits 6."), "the line: {line}");
    Ok(())
}

/// The end-of-run line names the reason too.
#[test]
fn e_end_of_run_line_names_the_reason() -> Result<(), TestError> {
    let run = sipnab(&["-N", "--json", "-I", FIXTURE], &Out::ReadOnly)?;
    assert!(
        run.lines_with(&format!("Failed to write output: {NOT_FOR_WRITING}")) == 1,
        "one end-of-run line\n{}",
        run.dump()
    );
    Ok(())
}

/// With standard error closed too, nothing can be said; the code still is.
#[test]
fn e_closed_stderr_still_exits_6() -> Result<(), TestError> {
    let run = sipnab_with(
        &["-N", "--json", "-I", FIXTURE],
        &Out::ReadOnly,
        Also {
            close_stderr: true,
            ..Also::default()
        },
    )?;
    assert_eq!(run.code, Some(UNWRITABLE), "2>&- exits 6\n{}", run.dump());
    Ok(())
}

/// Standard input and standard output both closed: the output is refused.
#[test]
fn e_closed_stdin_and_stdout() -> Result<(), TestError> {
    let run = sipnab_with(
        &["-N", "--json", "-I", FIXTURE],
        &Out::Closed,
        Also {
            close_stdin: true,
            ..Also::default()
        },
    )?;
    assert_refused(&run, CLOSED, "<&- >&-");
    Ok(())
}

/// A usage error goes to standard error and keeps its code, 2.
#[test]
fn e_usage_error_with_closed_stdout_exits_2() -> Result<(), TestError> {
    let run = sipnab(&["--no-such-flag-example"], &Out::Closed)?;
    assert_eq!(run.code, Some(2), "a usage error exits 2\n{}", run.dump());
    assert_eq!(
        run.lines_with(CLOSED),
        0,
        "no stdout refusal for an error that goes to stderr\n{}",
        run.dump()
    );
    Ok(())
}

/// A usage error of `sipnab fleet` keeps its code with a read-only output.
#[test]
fn e_fleet_usage_error_read_only_exits_2() -> Result<(), TestError> {
    let run = sipnab(&["fleet", "--no-such-flag-example"], &Out::ReadOnly)?;
    assert_eq!(
        run.code,
        Some(2),
        "fleet usage error exits 2\n{}",
        run.dump()
    );
    Ok(())
}

/// `--report` with the per-message output on: one refusal per stream, one code.
#[test]
fn e_report_and_messages_read_only() -> Result<(), TestError> {
    let run = sipnab(&["-N", "--report", "-I", FIXTURE], &Out::ReadOnly)?;
    assert_refused(&run, NOT_FOR_WRITING, "messages and --report, read-only");
    Ok(())
}

/// The read-only file is left as it was: nothing was written to it.
#[test]
fn e_read_only_target_is_untouched() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ro");
    std::fs::write(&path, b"before\n")?;
    let file = std::fs::File::open(&path)?;
    let home = tempfile::tempdir()?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "--json", "-I", FIXTURE])
        .envs(run_support::config_isolation(home.path()))
        .env("SIPNAB_LOG", "off")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::null())
        .stdout(Stdio::from(file))
        .stderr(Stdio::null())
        .tied_to_test()
        .spawn()?;
    let deadline = Instant::now() + test_timeout(60);
    let code = loop {
        if let Some(st) = child.try_wait()? {
            break st.code();
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait()?;
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert_eq!(code, Some(UNWRITABLE), "the run exits 6");
    assert_eq!(std::fs::read(&path)?, b"before\n", "the file is unchanged");
    Ok(())
}

// ── The gate: every write to standard output goes through the check ──

/// Files that may name `io::stdout()` in production code, and why.
const RAW_STDOUT_ALLOWED: [(&str, &str); 7] = [
    ("src/output/stdout.rs", "the checked writer itself"),
    (
        "src/mcp/transport.rs",
        "tokio's stdout; serve_stdio refuses an unwritable one first",
    ),
    (
        "src/process_isolation/worker_process.rs",
        "the worker's pipe to its parent run, never a user's output",
    ),
    ("src/crash.rs", "terminal restore sequences on the way out"),
    (
        "src/tui/mod.rs",
        "the terminal interface draws on a terminal",
    ),
    ("src/tui/terminal_input.rs", "terminal mode switches"),
    ("src/tui/clipboard.rs", "an OSC 52 sequence to the terminal"),
];

/// Every Rust file under `dir`.
fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<(), TestError> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// The files of `src/` whose code (comments and strings blanked) names
/// `io::stdout()`. Test modules are scanned too: `production_source` ends a
/// file at its first `#[cfg(test)] mod x;` line, which in src/tui/mod.rs is
/// line 67 of 6,229 (2026-11-26), and no test module writes to stdout.
fn raw_stdout_files() -> Result<Vec<String>, TestError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files)?;
    let mut hits = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)?;
        let code = source_scan::code_only(&text);
        if code.contains("io::stdout()") {
            let rel = file.strip_prefix(root)?.to_string_lossy().into_owned();
            hits.push(rel);
        }
    }
    hits.sort();
    Ok(hits)
}

/// No other file writes to std's stdout, which hides an unwritable one.
#[test]
fn f_no_file_writes_raw_stdout() -> Result<(), TestError> {
    let allowed: Vec<&str> = RAW_STDOUT_ALLOWED.iter().map(|(f, _)| *f).collect();
    let stray: Vec<String> = raw_stdout_files()?
        .into_iter()
        .filter(|f| !allowed.contains(&f.as_str()))
        .collect();
    assert!(
        stray.is_empty(),
        "write through sipnab::output::stdout::{{handle, lock}}, not io::stdout(): {stray:?}"
    );
    Ok(())
}

/// Every allowed file still names it: a stale entry would let a new use in.
#[test]
fn e_every_allowed_file_still_uses_raw_stdout() -> Result<(), TestError> {
    let hits = raw_stdout_files()?;
    for (file, why) in RAW_STDOUT_ALLOWED {
        assert!(
            hits.iter().any(|h| h == file),
            "{file} ({why}) no longer names io::stdout(): remove its entry"
        );
    }
    Ok(())
}
