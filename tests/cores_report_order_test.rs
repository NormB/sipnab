// SPDX-License-Identifier: MIT OR Apache-2.0

//! A report must not depend on `--cores`.
//!
//! `--cores N` shards an offline capture by host pair across N workers and
//! merges their stores. The merged report has to list calls and streams in
//! the order the capture shows them, which is the order `--cores 1` lists
//! them in, whatever the core count.

#[path = "support/synthetic_captures.rs"]
mod synthetic_captures;

#[path = "support/codecs.rs"]
mod codecs;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The report part of a run's standard output: everything from the dialog
/// table's header on. The per-message lines before it are a separate
/// question (whether `--cores` prints them at all).
fn report(capture: &std::path::Path, cores: &str) -> Result<String, TestError> {
    report_of(&[capture], cores)
}

/// [`report`] for an `-I` set of several files.
fn report_of(captures: &[&std::path::Path], cores: &str) -> Result<String, TestError> {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.arg("-N");
    for capture in captures {
        cmd.arg("-I").arg(capture);
    }
    let out = cmd.args(["--report", "--cores", cores]).output()?;
    assert!(out.status.success(), "--cores {cores} failed: {out:?}");
    let stdout = String::from_utf8(out.stdout)?;
    let start = stdout
        .find("Call-ID ")
        .ok_or_else(|| format!("--cores {cores} printed no dialog table:\n{stdout}"))?;
    Ok(stdout[start..].to_string())
}

#[test]
fn every_core_count_reports_calls_and_streams_in_capture_order() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let capture = dir.path().join("interleaved.pcap");
    std::fs::write(&capture, synthetic_captures::interleaved_calls())?;

    let single = report(&capture, "1")?;
    // The capture opens the calls in Call-ID order 0..5, so that is the
    // order the single-threaded report lists them in.
    let calls: Vec<usize> = (0..6)
        .map(|i| {
            single
                .find(&format!("interleaved-{i}@"))
                .ok_or_else(|| format!("call {i} missing from:\n{single}"))
        })
        .collect::<Result<_, _>>()?;
    assert!(
        calls.windows(2).all(|w| w[0] < w[1]),
        "--cores 1 does not list the calls in capture order:\n{single}"
    );
    for cores in ["2", "3", "4"] {
        assert_eq!(
            report(&capture, cores)?,
            single,
            "--cores {cores} reports a different order than --cores 1"
        );
    }
    Ok(())
}

/// Two files read as one set: every core count lists both files' calls in
/// the order the set was read, as `--cores 1` does.
#[test]
fn every_core_count_reports_a_two_file_set_in_read_order() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let first = dir.path().join("first.pcap");
    let second = dir.path().join("second.pcap");
    std::fs::write(&first, synthetic_captures::interleaved_calls())?;
    std::fs::write(&second, synthetic_captures::sip_call())?;
    let single = report_of(&[&first, &second], "1")?;
    assert!(
        single.contains("test-call-1@") && single.contains("interleaved-5@"),
        "--cores 1 did not read both files:\n{single}"
    );
    for cores in ["2", "3", "4"] {
        assert_eq!(
            report_of(&[&first, &second], cores)?,
            single,
            "--cores {cores} reports the set in a different order than --cores 1"
        );
    }
    Ok(())
}
