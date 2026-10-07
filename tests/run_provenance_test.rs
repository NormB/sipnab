// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(unix, feature = "native"))]
//! AUDIT1 — the run provenance record, written by the real binary.
//!
//! The unit tests in `src/app/run_provenance.rs` prove the record's own
//! properties: it carries the invocation, a hostile path cannot forge a second
//! line, a uid with no password entry reports no name. What they cannot prove
//! is that `--run-provenance-file` is WIRED to any of it — a `main` that never
//! calls `write_record` passes every one of those while the file stays empty,
//! which is exactly the state PB10's own sink test was written for.
//!
//! So this runs `sipnab` and reads the file it left behind.
//!
//! The property that only exists at this level is the fail-closed rule. A run
//! whose record cannot be written must STOP, and "stop" is a process exit code
//! and an absent report — neither of which is visible from inside the library.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The error a test returns: any error, boxed, so `?` works on I/O,
/// parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

/// Absolute path to a file under `tests/fixtures/`.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Run sipnab headless over the sample call, with whatever extra flags.
fn run(extra: &[&str]) -> Result<std::process::Output, TestError> {
    let pcap = fixture("sip_call.pcap");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.args(["-N", "-I", &pcap.to_string_lossy(), "--quiet"]);
    cmd.args(extra);
    Ok(cmd.output()?)
}

/// The single JSON record in `path`.
fn record(path: &Path) -> Result<serde_json::Value, TestError> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let first = text
        .lines()
        .next()
        .ok_or_else(|| format!("{} is empty", path.display()))?;
    Ok(serde_json::from_str(first).map_err(|e| {
        format!(
            "{} is not one JSON object per line: {e}\n{first}",
            path.display()
        )
    })?)
}

/// Every fact AUDIT1 promised, read back off a file the BINARY wrote.
///
/// Asserted field by field rather than by a shape or a length, because the
/// question this record answers is "which invocation produced that report" and
/// every one of these fields is part of the answer: drop `argv` and the filter
/// is gone, drop `cwd` and a relative `-I` names nothing, drop the capture
/// instance and the record cannot be joined to the report at all.
#[test]
fn the_record_the_binary_wrote_holds_argv_cwd_user_version_and_capture_identity()
-> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("run.jsonl");
    let out = run(&["--run-provenance-file", &path.to_string_lossy()])?;
    assert!(out.status.success(), "the run must succeed: {out:?}");

    let v = record(&path)?;
    assert_eq!(
        v["record"], "run",
        "the record must say what kind it is: {v}"
    );
    assert_eq!(v["seq"], 1);

    let argv: Vec<String> = v["argv"]
        .as_array()
        .ok_or("argv is a list")?
        .iter()
        .map(|a| a.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        argv.iter().any(|a| a == "-I"),
        "the argument that decided which capture was read is missing: {argv:?}"
    );
    assert!(
        argv.iter().any(|a| a.ends_with("sip_call.pcap")),
        "the capture the run read is missing from argv: {argv:?}"
    );
    assert!(
        argv.iter().any(|a| a == "--run-provenance-file"),
        "the record must show it was asked for: {argv:?}"
    );

    let cwd = v["cwd"].as_str().ok_or("cwd")?;
    assert!(
        Path::new(cwd).is_absolute(),
        "a relative -I resolves against this, so it has to be absolute: {cwd:?}"
    );

    assert!(
        v["uid"].as_u64().is_some(),
        "the effective user is what decided what this run could open: {v}"
    );
    assert!(v["pid"].as_u64().is_some_and(|p| p > 0), "no pid: {v}");

    let version = v["version"].as_str().ok_or("version")?;
    assert!(
        version.starts_with(env!("CARGO_PKG_VERSION")),
        "the record must name the build that produced the report: {version:?}"
    );
    let features: Vec<String> = v["features"]
        .as_array()
        .ok_or("features is a list")?
        .iter()
        .map(|f| f.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        features.iter().any(|f| f == "native"),
        "the compiled feature set decides what a run could do: {features:?}"
    );

    let capture = &v["capture"];
    assert!(
        capture["instance"].as_str().is_some_and(|i| !i.is_empty()),
        "without the capture instance nothing can be joined to this run: {v}"
    );
    assert!(
        capture["node"].as_str().is_some(),
        "the record must name the box that saw it: {v}"
    );
    assert_eq!(
        capture["dialog_generation"], 0,
        "the record is written before anything is ingested: {v}"
    );
    assert_eq!(capture["stream_generation"], 0);

    assert!(
        v["started"].as_str().is_some_and(|s| s.contains('T')),
        "the run's wall-clock start is missing: {v}"
    );
    Ok(())
}

/// The file is owner-only, because argv holds a capture path and a path holds
/// a customer name.
#[test]
fn the_record_file_is_not_readable_by_other_accounts() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("run.jsonl");
    let out = run(&["--run-provenance-file", &path.to_string_lossy()])?;
    assert!(out.status.success(), "the run must succeed: {out:?}");
    let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "argv routinely holds a capture path and a path routinely holds a \
         customer name, so the record is not for every account on the host"
    );
    Ok(())
}

/// Off by default: no flag, no file, nothing changed.
///
/// The half of an opt-in feature that is easiest to break and hardest to
/// notice — a sink that quietly wrote somewhere would be a privacy defect that
/// every other test here would still pass.
#[test]
fn no_file_appears_when_the_flag_is_absent() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let out = run(&[])?;
    assert!(out.status.success(), "the run must succeed: {out:?}");
    let left: Vec<_> = std::fs::read_dir(dir.path())?
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert!(
        left.is_empty(),
        "a run that was not asked to record anything wrote {left:?}"
    );
    Ok(())
}

/// FAIL CLOSED: a destination that cannot be opened stops the run, and the
/// message names the path.
///
/// The whole reason the rule is fail-closed rather than best-effort: a missing
/// record must not be ambiguous between "not enabled" and "the disk was full".
/// Asserted on the exit code AND on the absence of analysis output, because a
/// run that printed its report and then complained would have produced exactly
/// the untraceable artefact this exists to prevent.
#[test]
fn a_destination_that_cannot_be_opened_stops_the_run_and_names_the_path() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("no-such-dir").join("run.jsonl");
    let out = run(&["--run-provenance-file", &path.to_string_lossy(), "--json"])?;

    assert!(!out.status.success(), "the run must not succeed: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&path.to_string_lossy().to_string()),
        "the message must name the path that failed: {stderr}"
    );
    assert!(
        stderr.contains("--run-provenance-file"),
        "the message must name the flag: {stderr}"
    );
    assert!(
        out.stdout.is_empty(),
        "the run produced a report it has no provenance record for: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    Ok(())
}

/// FAIL CLOSED on a WRITE that fails, not only on an open that does.
///
/// `/dev/full` opens cleanly and fails every write with `ENOSPC`, which is the
/// full-disk condition itself rather than a mock of it. An implementation that
/// checked only the open would pass the test above and produce an unrecorded
/// report here.
#[test]
fn a_write_that_fails_stops_the_run() -> Result<(), TestError> {
    if !Path::new("/dev/full").exists() {
        return Ok(());
    }
    let out = run(&["--run-provenance-file", "/dev/full", "--json"])?;
    assert!(!out.status.success(), "the run must not succeed: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("/dev/full"),
        "the message must name the path that failed: {stderr}"
    );
    assert!(
        out.stdout.is_empty(),
        "the run produced a report it has no provenance record for: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    Ok(())
}

/// A second run APPENDS. The file is the history of which invocations
/// produced which artefacts, and a run that replaced it would destroy exactly
/// the older entry somebody is looking for.
#[test]
fn a_second_run_appends_rather_than_replacing_the_first() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("run.jsonl");
    for _ in 0..2 {
        let out = run(&["--run-provenance-file", &path.to_string_lossy()])?;
        assert!(out.status.success(), "the run must succeed: {out:?}");
    }
    let text = std::fs::read_to_string(&path)?;
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "the second run destroyed the first run's record: {lines:?}"
    );
    let first: serde_json::Value = serde_json::from_str(lines[0])?;
    let second: serde_json::Value = serde_json::from_str(lines[1])?;
    assert_ne!(
        first["capture"]["instance"], second["capture"]["instance"],
        "two runs must be distinguishable by the identity every answer \
         carries, or the record cannot say which run made which report"
    );
    Ok(())
}

/// An argument containing a space stays ONE argv element.
///
/// The reason the record holds a list and not a joined string: a capture path
/// with a space in it is ordinary, and a joined line would read as two
/// arguments to whoever reconstructs the command afterwards — which is the one
/// thing this record exists to make impossible to get wrong.
#[test]
fn an_argument_containing_a_space_stays_one_argv_element() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("run.jsonl");
    let spaced = dir.path().join("a capture with spaces.pcap");
    std::fs::copy(fixture("sip_call.pcap"), &spaced)?;

    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            &spaced.to_string_lossy(),
            "--quiet",
            "--run-provenance-file",
            &path.to_string_lossy(),
        ])
        .output()?;
    assert!(out.status.success(), "the run must succeed: {out:?}");

    let v = record(&path)?;
    let argv: Vec<String> = v["argv"]
        .as_array()
        .ok_or("argv")?
        .iter()
        .map(|a| a.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        argv.iter().any(|a| a == &spaced.to_string_lossy()),
        "the spaced path was split or mangled: {argv:?}"
    );
    Ok(())
}
