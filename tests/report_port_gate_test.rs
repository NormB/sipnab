// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--report` states the SIP a port gate set aside, as every other output does.
//!
//! A message on a port outside `--portrange` (default 5060-5061) is counted and
//! never analyzed. The run summary on stderr says so ("NOT ANALYZED"),
//! `--analyze` says so ("THIS ANALYSIS IS INCOMPLETE"), a vCon says so
//! ("INCOMPLETE: a port gate discarded"), and `GET /v1/stats` and the MCP
//! `capture_status` tool carry the count. `--report` printed its tables with
//! no word about it, so a report read on its own looked like a report about
//! every call in the capture.
//!
//! These tests run the binary over a capture with one call on 5060 and one on
//! 5080, and read stdout, which is where the report is.

#![cfg(feature = "native")]

use std::process::Command;

#[path = "support/pcap_build.rs"]
mod pcap_build;

type TestError = Box<dyn std::error::Error>;

/// One call on 5060 and one on `port`, each seven messages.
fn two_calls(port: u16) -> Vec<Vec<u8>> {
    let mut frames = pcap_build::sip_call_frames("inside@port-gate", "in1", "alice", "bob");
    let a = [10, 1, 0, 1];
    let b = [10, 2, 0, 1];
    for (i, msg) in pcap_build::sip_call("outside@port-gate", "out1", "carol", "dave")
        .iter()
        .enumerate()
    {
        let (src, dst) = if matches!(i, 0 | 4 | 5) {
            (a, b)
        } else {
            (b, a)
        };
        frames.push(pcap_build::udp_frame(src, dst, port, port, msg.as_bytes()));
    }
    frames
}

/// Run `sipnab -N -I <pcap> --no-config` plus `extra` over `frames`; returns
/// stdout, stderr and the exit code.
fn run(frames: &[Vec<u8>], extra: &[&str]) -> Result<(String, String, i32), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = dir.path().join("capture.pcap");
    pcap_build::write_pcap(&pcap, frames)?;
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", &pcap.to_string_lossy(), "--no-config"])
        .args(extra)
        .output()?;
    Ok((
        String::from_utf8(out.stdout)?,
        String::from_utf8(out.stderr)?,
        out.status.code().ok_or("killed by a signal")?,
    ))
}

/// The report names the SIP `--portrange` set aside, with the count stderr
/// gives, and the run still exits 0: the range is what the operator asked
/// for, not a failure.
#[test]
fn the_report_states_sip_outside_the_portrange() -> Result<(), TestError> {
    let (out, err, code) = run(&two_calls(5080), &["--report", "--no-cli-print"])?;
    assert_eq!(code, 0, "a port range is not a failed run:\n{err}");
    assert!(
        out.contains("inside@port-gate"),
        "positive control: the call on 5060 is in the report:\n{out}"
    );
    assert!(
        err.contains("NOT ANALYZED: 7 further SIP message(s)"),
        "positive control: stderr counts the seven messages on 5080:\n{err}"
    );
    assert!(
        out.contains("INCOMPLETE RUN"),
        "the report does not say it is missing SIP:\n{out}"
    );
    assert!(
        out.contains(
            "7 SIP message(s) were seen on ports outside --portrange and were not \
             analyzed; re-run with --portrange 1-65535 to include them"
        ),
        "the report does not name the SIP outside --portrange:\n{out}"
    );
    Ok(())
}

/// With the range widened nothing is set aside, and the report says nothing
/// extra.
#[test]
fn a_report_with_nothing_set_aside_has_no_notice() -> Result<(), TestError> {
    let (out, err, code) = run(
        &two_calls(5080),
        &["--report", "--no-cli-print", "--portrange", "1-65535"],
    )?;
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("outside@port-gate"),
        "positive control: the widened range analyzes the call on 5080:\n{out}"
    );
    assert!(!out.contains("INCOMPLETE RUN"), "{out}");
    Ok(())
}

/// SIP over WebSocket on a port outside the WebSocket port set is the other
/// port gate, and the report names it in the words stderr uses.
#[test]
fn the_report_states_sip_outside_the_websocket_ports() -> Result<(), TestError> {
    let (out, err, code) = run(
        &pcap_build::ws_sip_call("ws-gate", 8081),
        &["--report", "--no-cli-print", "--portrange", "1-65535"],
    )?;
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains(
            "SIP-over-WebSocket message(s) arrived on ports outside the WebSocket port set"
        ),
        "positive control: stderr names the WebSocket gate:\n{err}"
    );
    assert!(
        out.contains("INCOMPLETE RUN")
            && out.contains(
                "SIP-over-WebSocket message(s) arrived on ports outside the WebSocket \
                 port set and were not analyzed"
            ),
        "the report does not name the SIP outside the WebSocket ports:\n{out}"
    );
    Ok(())
}

/// The set-aside SIP does not change the `--json-dialogs` stream: the run's
/// input was read in full, so no `sipnab_run` trailer is added, as with
/// retention.
#[test]
fn json_dialogs_gets_no_trailer_for_a_port_gate_alone() -> Result<(), TestError> {
    let (out, err, code) = run(&two_calls(5080), &["--json-dialogs", "--no-cli-print"])?;
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("inside@port-gate"), "positive control:\n{out}");
    assert!(!out.contains("sipnab_run"), "{out}");
    Ok(())
}
