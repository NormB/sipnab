// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! FILE-2 (b): `--min-free-disk SIZE`, run through the real binary.
//!
//! A floor no disk can meet (`16777215T`, the largest value the flag takes)
//! stands in for a full disk: the check before the capture opens finds every
//! watched directory under it, so the run must not start and must exit 4.
//! A floor every disk meets (`1K`), and `0`, must leave the run as it was.
//!
//! What this file cannot reach: a disk that fills DURING a run. No test can
//! fill the file system of a temporary directory on demand without root, so
//! the crossing logic and the stop request are tested directly, in
//! `src/disk_floor.rs` (`check_with` with a probe that supplies each reading)
//! and `src/signals.rs` (the stop and its exit code).
#![cfg(feature = "native")]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

type TestError = Box<dyn std::error::Error>;

#[path = "support/run.rs"]
mod run_support;

include!("support/timeout.rs");
include!("support/child_lifetime.rs");

/// The capture every file run reads.
const FIXTURE: &str = "tests/fixtures/sip_call.pcap";

/// A floor no file system meets.
const UNMEETABLE: &str = "16777215T";

/// A path as `&str`.
fn s(p: &Path) -> Result<&str, TestError> {
    p.to_str()
        .ok_or_else(|| format!("not UTF-8: {}", p.display()).into())
}

/// One finished run.
struct Run {
    /// Standard error.
    stderr: String,
    /// The exit code; `None` when a signal ended it.
    code: Option<i32>,
}

impl Run {
    /// The run, for an assertion message.
    fn dump(&self) -> String {
        format!("code {:?}\n--- stderr ---\n{}", self.code, self.stderr)
    }
}

/// `sipnab -N args` with `SIPNAB_LOG=log`, through the shared baseline.
fn sipnab(args: &[&str], log: &str) -> Result<Run, TestError> {
    let mut argv = vec!["-N"];
    argv.extend_from_slice(args);
    let (_out, stderr, code) = run_support::run(&argv, Some(log))?;
    Ok(Run { stderr, code })
}

/// `sipnab -N args` that must end on its own within `secs` seconds; a run
/// still going at the deadline is killed and reported as `None`.
fn sipnab_within(args: &[&str], secs: u64) -> Result<Run, TestError> {
    let home = tempfile::tempdir()?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("-N")
        .args(args)
        .envs(run_support::config_isolation(home.path()))
        .env("SIPNAB_LOG", "off")
        .env("NO_COLOR", "1")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .tied_to_test()
        .spawn()?;
    let deadline = Instant::now() + test_timeout(secs);
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait()?;
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        use std::io::Read as _;
        pipe.read_to_string(&mut stderr)?;
    }
    Ok(Run {
        stderr,
        code: status.and_then(|st| st.code()),
    })
}

// --- success ---------------------------------------------------------------

/// Under the floor before the capture opens: the run does not start, says
/// which directory, how much is free and the floor, and exits 4.
#[test]
fn s_a_file_run_under_the_floor_exits_4_and_says_why() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("out.pcap");
    let run = sipnab(
        &["-I", FIXTURE, "-O", s(&out)?, "--min-free-disk", UNMEETABLE],
        "off",
    )?;
    assert_eq!(
        run.code,
        Some(4),
        "a run under its floor exits 4: {}",
        run.dump()
    );
    assert!(
        run.stderr.contains(s(dir.path())?),
        "names the directory: {}",
        run.dump()
    );
    assert!(
        run.stderr.contains("bytes"),
        "names the free bytes: {}",
        run.dump()
    );
    assert!(
        run.stderr.contains("--min-free-disk"),
        "names the flag: {}",
        run.dump()
    );
    assert!(
        !out.exists(),
        "the run did not start, so -O was not written: {}",
        run.dump()
    );
    Ok(())
}

/// A floor the disk meets leaves the run as it was: it reads its input and
/// writes -O.
#[test]
fn s_a_floor_the_disk_meets_runs_to_the_end() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("out.pcap");
    let run = sipnab(
        &["-I", FIXTURE, "-O", s(&out)?, "--min-free-disk", "1K"],
        "off",
    )?;
    assert_eq!(run.code, Some(0), "the run succeeds: {}", run.dump());
    let len = std::fs::metadata(&out)?.len();
    assert!(len > 24, "-O holds packets ({len} bytes): {}", run.dump());
    Ok(())
}

/// `0` turns the check off: even a run that writes runs to the end.
#[test]
fn s_zero_turns_the_check_off() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("out.pcap");
    let run = sipnab(
        &["-I", FIXTURE, "-O", s(&out)?, "--min-free-disk", "0"],
        "warn",
    )?;
    assert_eq!(run.code, Some(0), "the run succeeds: {}", run.dump());
    assert!(
        !run.stderr.contains("free disk"),
        "no disk line at all: {}",
        run.dump()
    );
    Ok(())
}

/// Without the flag the run never stops for disk space: the default floor
/// only warns.
#[test]
fn s_without_the_flag_the_run_goes_on() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("out.pcap");
    let run = sipnab(&["-I", FIXTURE, "-O", s(&out)?], "off")?;
    assert_eq!(run.code, Some(0), "the run succeeds: {}", run.dump());
    assert!(out.exists(), "-O was written: {}", run.dump());
    Ok(())
}

/// A live HEP listener under the floor never starts listening: it exits 4
/// on its own, well within the deadline.
#[test]
fn s_a_hep_listener_under_the_floor_does_not_start() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("live.pcap");
    let run = sipnab_within(
        &[
            "--hep-listen",
            "127.0.0.1:0",
            "-O",
            s(&out)?,
            "--min-free-disk",
            UNMEETABLE,
        ],
        20,
    )?;
    assert_eq!(
        run.code,
        Some(4),
        "a live run under its floor exits 4: {}",
        run.dump()
    );
    assert!(
        run.stderr.contains(s(dir.path())?),
        "names the directory: {}",
        run.dump()
    );
    Ok(())
}

/// `--evidence-out PATH` is watched: a run whose only output is the evidence
/// file stops for its directory.
#[test]
fn s_the_evidence_file_directory_is_watched() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let ev = dir.path().join("evidence.jsonl");
    let run = sipnab(
        &[
            "-I",
            FIXTURE,
            "--no-cli-print",
            "--evidence-out",
            s(&ev)?,
            "--min-free-disk",
            UNMEETABLE,
        ],
        "off",
    )?;
    assert_eq!(
        run.code,
        Some(4),
        "the evidence directory is under the floor: {}",
        run.dump()
    );
    assert!(
        run.stderr.contains(s(dir.path())?),
        "names it: {}",
        run.dump()
    );
    Ok(())
}

/// The stop reason reaches stderr with every log line silenced: it explains
/// the exit code.
#[test]
fn s_the_reason_is_said_with_logging_off() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("out.pcap");
    let run = sipnab(
        &["-I", FIXTURE, "-O", s(&out)?, "--min-free-disk", UNMEETABLE],
        "off",
    )?;
    assert_eq!(run.code, Some(4), "exits 4: {}", run.dump());
    assert_eq!(
        run.stderr
            .lines()
            .filter(|l| l.contains("--min-free-disk"))
            .count(),
        1,
        "exactly one reason line: {}",
        run.dump()
    );
    Ok(())
}

// --- failure ---------------------------------------------------------------

/// A value the flag does not take is a usage error: exit 2, naming the flag.
/// Given as `--min-free-disk=VALUE`, so clap does not read `-1G` as a flag.
#[test]
fn f_values_the_flag_refuses_exit_2() -> Result<(), TestError> {
    for value in [
        "",
        "500",
        "2GB",
        "1.5G",
        "-1G",
        "x",
        "16777216T",
        "+2G",
        "2 G",
    ] {
        let arg = format!("--min-free-disk={value}");
        let run = sipnab(&["-I", FIXTURE, &arg], "off")?;
        assert_eq!(run.code, Some(2), "{value:?} is refused: {}", run.dump());
        assert!(
            run.stderr.contains("--min-free-disk"),
            "{value:?} names the flag: {}",
            run.dump()
        );
    }
    Ok(())
}

/// An output in a directory that does not exist is refused by its own open
/// (exit 2), not hidden behind a low-disk stop.
#[test]
fn f_a_missing_output_directory_keeps_its_own_refusal() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let ev = dir.path().join("absent").join("evidence.jsonl");
    let run = sipnab(
        &[
            "-I",
            FIXTURE,
            "--no-cli-print",
            "--evidence-out",
            s(&ev)?,
            "--min-free-disk",
            UNMEETABLE,
        ],
        "off",
    )?;
    assert_eq!(
        run.code,
        Some(2),
        "the evidence open refuses it: {}",
        run.dump()
    );
    assert!(
        run.stderr.contains("--evidence-out"),
        "names that flag: {}",
        run.dump()
    );
    Ok(())
}

// --- edge ------------------------------------------------------------------

/// A run that writes nothing has nothing to watch: an unmeetable floor does
/// not stop it.
#[test]
fn e_a_run_that_writes_nothing_is_not_stopped() -> Result<(), TestError> {
    let run = sipnab(
        &[
            "-I",
            FIXTURE,
            "--no-cli-print",
            "--min-free-disk",
            UNMEETABLE,
        ],
        "off",
    )?;
    assert_eq!(run.code, Some(0), "no output, no watch: {}", run.dump());
    Ok(())
}

/// `--evidence-out -` writes to standard output, which has no directory.
#[test]
fn e_evidence_on_standard_output_is_not_watched() -> Result<(), TestError> {
    let run = sipnab(
        &[
            "-I",
            FIXTURE,
            "--evidence-out",
            "-",
            "--min-free-disk",
            UNMEETABLE,
        ],
        "off",
    )?;
    assert_eq!(
        run.code,
        Some(0),
        "stdout is not a directory: {}",
        run.dump()
    );
    Ok(())
}

/// Two outputs in one directory are one watched directory: one line.
#[test]
fn e_two_outputs_in_one_directory_are_said_once() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("out.pcap");
    let ev = dir.path().join("evidence.jsonl");
    let run = sipnab(
        &[
            "-I",
            FIXTURE,
            "-O",
            s(&out)?,
            "--evidence-out",
            s(&ev)?,
            "--min-free-disk",
            UNMEETABLE,
        ],
        "warn",
    )?;
    assert_eq!(run.code, Some(4), "exits 4: {}", run.dump());
    let dirname = s(dir.path())?;
    let lines = run.stderr.lines().filter(|l| l.contains(dirname)).count();
    assert_eq!(
        lines,
        2,
        "one crossing line and one stop line for the one directory: {}",
        run.dump()
    );
    Ok(())
}

/// A vCon rule directory not made yet is watched through its nearest
/// ancestor that exists: the file system it will be made on.
#[cfg(feature = "vcon")]
#[test]
fn e_a_vcon_rule_directory_not_made_yet_is_watched_through_its_ancestor() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let rule_dir = dir.path().join("vcons").join("today");
    let run = sipnab(
        &[
            "-I",
            FIXTURE,
            "--no-cli-print",
            "--export-vcon-when",
            "state == 'Completed'",
            "--export-vcon-dir",
            s(&rule_dir)?,
            "--min-free-disk",
            UNMEETABLE,
        ],
        "off",
    )?;
    assert_eq!(
        run.code,
        Some(4),
        "the rule's file system is under the floor: {}",
        run.dump()
    );
    assert!(
        run.stderr.contains(s(dir.path())?),
        "names the ancestor: {}",
        run.dump()
    );
    assert!(!rule_dir.exists(), "nothing was written: {}", run.dump());
    Ok(())
}
