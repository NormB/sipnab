// SPDX-License-Identifier: MIT OR Apache-2.0

//! `-c` / `--calls-only` keeps only calls on every dialog output.
//!
//! A call is a dialog an INVITE started (`sip::matcher::calls_only_admits`).
//! Issue #474 asked for sngrep's `-c`, which shows only such dialogs. sipnab
//! had the flag, but only the per-message printout applied it: `--json-dialogs`
//! and `--report` still listed the OPTIONS, REGISTER and SUBSCRIBE dialogs.
//! These tests run the binary on two captures that hold both kinds.

use std::process::Command;

type TestError = Box<dyn std::error::Error>;

/// A capture with three OPTIONS pings and one INVITE call (rejected with 488).
const MIXED: &str = "tests/pcap-samples/sip-488-codec-reject.pcapng";

/// A capture with one INVITE, one OPTIONS, one REGISTER and two SUBSCRIBE
/// dialogs.
const ASTERISK: &str = "tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap";

/// Run sipnab headless on `capture` with `args`, returning stdout.
fn run(capture: &str, args: &[&str]) -> Result<String, TestError> {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "-I", capture, "--no-cli-print"])
        .args(args)
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "sipnab {args:?} on {capture} exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// The `(method, call_id)` of every dialog `--json-dialogs` prints.
fn dialogs(capture: &str, args: &[&str]) -> Result<Vec<(String, String)>, TestError> {
    let mut all = vec!["--json-dialogs"];
    all.extend_from_slice(args);
    let mut out = Vec::new();
    for line in run(capture, &all)?.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)?;
        out.push((
            v["method"]
                .as_str()
                .ok_or("a dialog has a method")?
                .to_owned(),
            v["call_id"]
                .as_str()
                .ok_or("a dialog has a call_id")?
                .to_owned(),
        ));
    }
    Ok(out)
}

#[test]
fn json_dialogs_with_calls_only_lists_only_the_call() -> Result<(), TestError> {
    let without = dialogs(MIXED, &[])?;
    assert_eq!(
        without.iter().filter(|(m, _)| m == "OPTIONS").count(),
        3,
        "the fixture holds three OPTIONS dialogs: {without:?}"
    );
    let with = dialogs(MIXED, &["-c"])?;
    assert_eq!(
        with,
        vec![("INVITE".to_owned(), "codec-reject-synth".to_owned())],
        "-c must keep the INVITE dialog and nothing else"
    );
    Ok(())
}

#[test]
fn report_with_calls_only_shows_no_options_ping() -> Result<(), TestError> {
    let without = run(MIXED, &["--report"])?;
    assert!(without.contains("options-ping-a"), "{without}");
    let with = run(MIXED, &["--report", "--calls-only"])?;
    assert!(
        with.contains("codec-reject-synth"),
        "the call is reported: {with}"
    );
    assert!(
        !with.contains("options-ping"),
        "--calls-only reported an OPTIONS dialog:\n{with}"
    );
    Ok(())
}

#[test]
fn calls_only_and_filter_both_apply() -> Result<(), TestError> {
    // The one call in the fixture failed, so a filter for completed dialogs
    // selects only OPTIONS pings, and -c removes those.
    let completed = dialogs(MIXED, &["--filter", "state == 'Completed'"])?;
    assert_eq!(completed.len(), 3, "{completed:?}");
    let both = dialogs(MIXED, &["-c", "--filter", "state == 'Completed'"])?;
    assert!(both.is_empty(), "-c with the filter kept {both:?}");
    let failed = dialogs(MIXED, &["-c", "--filter", "state == 'Failed'"])?;
    assert_eq!(failed.len(), 1, "{failed:?}");
    Ok(())
}

#[test]
fn calls_only_drops_register_subscribe_and_options() -> Result<(), TestError> {
    let without = dialogs(ASTERISK, &[])?;
    for m in ["REGISTER", "SUBSCRIBE", "OPTIONS", "INVITE"] {
        assert!(
            without.iter().any(|(x, _)| x == m),
            "the fixture holds a {m} dialog: {without:?}"
        );
    }
    let with = dialogs(ASTERISK, &["-c"])?;
    assert!(!with.is_empty(), "the INVITE dialog is kept");
    assert!(
        with.iter().all(|(m, _)| m == "INVITE"),
        "-c kept a dialog that is not a call: {with:?}"
    );
    Ok(())
}
