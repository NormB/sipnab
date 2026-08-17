// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "native")]

//! `--show-frame` closes the loop that #128 stage 4 opened.
//!
//! Stage 4 put a frame pointer on the output surfaces. #228 was that nothing in
//! the shipped binary could follow one: `capture::resolve` had no caller outside
//! its own module, so the pointer was a stable identifier and nothing more.
//!
//! The refusals are the point, not the retrieval. Handing back the bytes at an
//! ordinal without checking them is the failure the whole feature exists to
//! prevent -- the operator gets a frame, believes it is the frame the finding
//! was about, and has no way to learn the capture was rotated underneath them.
//! So the tests that matter here are the ones asserting it says no.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn show_frame(pointer: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("--show-frame")
        .arg(pointer)
        .output()
        .expect("run sipnab --show-frame")
}

/// A pointer as a surface actually emits it, so the test cannot drift from the
/// wire format by constructing one by hand.
fn emitted_pointer() -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "--json-dialogs", "-I"])
        .arg(fixture("sip_call.pcap"))
        .output()
        .expect("run sipnab --json-dialogs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with('{'))
        .expect("--json-dialogs emitted no JSON object");
    let v: serde_json::Value = serde_json::from_str(line).expect("parse NDJSON line");
    v.get("frame")
        .and_then(|f| f.as_str())
        .unwrap_or_else(|| panic!("--json-dialogs emitted no `frame`: {line}"))
        .to_string()
}

/// The whole loop: a surface emits a pointer, the CLI follows it.
#[test]
fn a_pointer_emitted_by_json_dialogs_can_be_followed() {
    let out = show_frame(&emitted_pointer());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "following an emitted pointer failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.starts_with("VERIFIED"),
        "an emitted pointer carries a digest, so it must resolve VERIFIED; got: {stdout}"
    );
    // It printed the actual frame, not just a status line.
    assert!(
        stdout.contains("INVITE"),
        "the hexdump does not contain the INVITE this dialog opened with; got: {stdout}"
    );
}

/// The human-typed form works and is labeled honestly.
#[test]
fn a_pointer_without_a_digest_is_printed_but_called_unverified() {
    let full = emitted_pointer();
    let short = full
        .split_once('@')
        .expect("emitted form carries a digest")
        .0;

    let out = show_frame(short);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "the short form must still resolve");
    assert!(
        stdout.starts_with("UNVERIFIED"),
        "a pointer with no digest must not be reported as verified; got: {stdout}"
    );
    assert!(
        stdout.contains("not checked against anything"),
        "the caveat must be stated, not implied by a one-word label; got: {stdout}"
    );
}

/// The refusal that matters: same ordinal and digest, different capture.
#[test]
fn a_capture_that_changed_is_refused_rather_than_answered() {
    let full = emitted_pointer();
    let tail = full.rsplit_once('#').expect("pointer has a tail").1;
    let elsewhere = format!("{}#{tail}", fixture("udp_5060.pcap").display());

    let out = show_frame(&elsewhere);
    assert!(
        !out.status.success(),
        "a digest mismatch returned success; the bytes at that ordinal were \
         handed over as though they were the right ones"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing"),
        "the refusal must say so plainly; got: {stderr}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "nothing may be printed to stdout when the pointer is refused -- a \
         hexdump above an error still reads as an answer"
    );
}

/// An ordinal past the end names the real count rather than guessing.
#[test]
fn an_ordinal_past_the_end_is_refused_with_the_real_count() {
    let out = show_frame(&format!("{}#99999", fixture("sip_call.pcap").display()));
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("holds 7 frame(s)"),
        "the refusal should say how many frames are actually there; got: {stderr}"
    );
}

/// Unreadable source, and garbage input, are distinguishable from a refusal.
#[test]
fn unreadable_and_malformed_are_reported_separately() {
    let missing = show_frame("/nonexistent/nowhere.pcap#0");
    assert_eq!(
        missing.status.code(),
        Some(1),
        "an unreadable source is a refusal (1), not a usage error"
    );
    assert!(String::from_utf8_lossy(&missing.stderr).contains("cannot read"));

    let garbage = show_frame("not-a-pointer");
    assert_eq!(
        garbage.status.code(),
        Some(2),
        "input that is not a pointer is a usage error (2), not a refusal"
    );
}
