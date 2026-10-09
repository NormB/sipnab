//! The no-SIP guidance on a capture that holds RTP and no SIP, end to end.
//!
//! The run summary used to end with "Use --report to see stream details."
//! even when the operator had passed `--report` and the stream table was in
//! the same run's output. These tests drive the real binary on such a capture
//! and check both halves: with `--report` the table prints and the hint does
//! not; without it the hint still prints.
//!
//! # The fixture
//!
//! `tests/fixtures/rtpengine-media-only.pcap` is synthetic (see
//! `tests/PROVENANCE.md`): four RTP streams through a media relay, and no SIP
//! or relay control traffic at all. That makes it the media-only case this
//! message exists for.
#![cfg(feature = "native")]

use std::path::PathBuf;
use std::process::Command;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The text that suggests the flag.
const HINT: &str = "Use --report to see stream details.";
/// The finding itself, printed with or without the report.
const FINDING: &str = "No SIP signaling found, but 40 RTP packets across 4 stream(s) were parsed.";

fn fixture() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rtpengine-media-only.pcap")
        .to_string_lossy()
        .into_owned()
}

/// Run sipnab on the fixture and return `(stdout, stderr)`.
///
/// The report goes to stdout and the run summary, which carries the
/// guidance, goes to stderr; both are checked.
fn run(extra: &[&str]) -> Result<(String, String), TestError> {
    let path = fixture();
    let mut args = vec!["-N", "-I", path.as_str()];
    args.extend_from_slice(extra);
    args.push("--no-cli-print");
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(&args)
        .env("SIPNAB_LOG", "warn")
        .output()?;
    assert!(
        out.status.success(),
        "sipnab exited {:?}; stderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// With `--report`, the stream table is printed and the summary does not
/// tell the operator to pass the flag they passed.
#[test]
fn with_report_the_streams_print_and_the_flag_is_not_suggested() -> Result<(), TestError> {
    let (stdout, stderr) = run(&["--report"])?;
    assert!(
        stdout.contains("Orphaned Streams:") && stdout.contains("192.0.2.40:38156"),
        "the stream report must actually print in this run:\n{stdout}"
    );
    assert!(
        stderr.contains(FINDING),
        "the media-only finding must still be stated:\n{stderr}"
    );
    assert!(
        !stdout.contains(HINT) && !stderr.contains(HINT),
        "the run already printed the report, so the flag must not be \
         suggested.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    Ok(())
}

/// The same with `--json`: the table still prints, so the hint stays away.
#[test]
fn with_report_and_json_the_flag_is_not_suggested() -> Result<(), TestError> {
    let (stdout, stderr) = run(&["--report", "--json"])?;
    assert!(
        stdout.contains("Orphaned Streams:"),
        "the stream report must actually print in this run:\n{stdout}"
    );
    assert!(
        !stdout.contains(HINT) && !stderr.contains(HINT),
        "the run already printed the report, so the flag must not be \
         suggested.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    Ok(())
}

/// Negative control: without `--report` there is no stream table, and the
/// hint that points at the flag is printed.
#[test]
fn without_report_the_hint_is_printed() -> Result<(), TestError> {
    let (stdout, stderr) = run(&[])?;
    assert!(
        !stdout.contains("Orphaned Streams:"),
        "no stream report was asked for:\n{stdout}"
    );
    assert!(
        stderr.contains(&format!("{FINDING} {HINT}")),
        "the run must point at --report:\n{stderr}"
    );
    Ok(())
}
