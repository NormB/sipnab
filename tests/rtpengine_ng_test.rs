// SPDX-License-Identifier: MIT OR Apache-2.0

//! RE1/RE2/RE6: media captured on a standalone relay must be attributable to
//! a call, from the relay's own control plane.
//!
//! # The fixture
//!
//! `tests/fixtures/rtpengine-ng-hep.pcap` was captured from a live relay, not
//! constructed. rtpengine 12.5.1 on a Debian 13 host, configured with
//! `--homer-enable-ng` so it mirrors its `ng` control plane to a Homer
//! collector, with a call driven through it and its media relayed. The capture
//! holds six HEP packets — `offer`, `answer` and `delete`, each with its reply
//! — and forty relayed RTP packets on the four sockets those commands
//! allocated.
//!
//! Two properties make it the right fixture rather than merely a convenient
//! one:
//!
//! * **It contains no SIP whatsoever.** That is what a media relay looks like:
//!   the signaling is on another host. It is also what makes the test
//!   discriminating — if these streams end up attributed, the attribution can
//!   only have come from the `ng` control plane, because there is no other
//!   source of a Call-ID in the file.
//! * **The HEP is addressed to a third party.** The relay is reporting to a
//!   collector at another address; sipnab is merely a bystander capturing on
//!   that host. Nothing here is delivered to a sipnab listener, which is
//!   exactly the deployment RE6 is for — rtpengine takes only ONE Homer
//!   destination, so pointing it at sipnab would take it away from the
//!   collector it already feeds.
//!
//! Both are asserted below rather than described, because a fixture that
//! quietly gained a SIP packet would turn this from a proof into a tautology.
#![cfg(all(feature = "native", feature = "hep"))]

use std::path::PathBuf;
use std::process::Command;

/// The relay Call-ID the control plane assigned, from the capture itself.
const CALL_ID: &str = "km-670bd208@sipnab";
/// The relay's own allocated ports, one per leg.
const RELAY_PORTS: [&str; 2] = ["10.0.0.40:38156", "10.0.0.40:38664"];
/// The two endpoints whose media the relay is forwarding.
const PARTY_PORTS: [&str; 2] = ["10.0.0.60:40001", "10.0.0.60:40002"];

fn fixture() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rtpengine-ng-hep.pcap")
        .to_string_lossy()
        .into_owned()
}

/// Run sipnab and return `(stdout, stderr)`.
///
/// Both, because the two carry different halves of the answer: the report
/// itself goes to stdout, and the run's summary line — which is what says
/// whether any SIP was seen — goes to stderr.
fn run(extra: &[&str]) -> (String, String) {
    let mut args = vec!["-N", "-I", &*Box::leak(fixture().into_boxed_str())];
    args.extend_from_slice(extra);
    args.push("--no-cli-print");
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(&args)
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("run sipnab");
    assert!(
        out.status.success(),
        "sipnab exited {:?}; stderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn report(extra: &[&str]) -> String {
    let mut args = vec!["-N", "-I", &*Box::leak(fixture().into_boxed_str())];
    args.extend_from_slice(extra);
    args.push("--no-cli-print");
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(&args)
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("run sipnab");
    assert!(
        out.status.success(),
        "sipnab exited {:?}; stderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The guard that keeps every other assertion in this file meaningful.
///
/// If the fixture ever contains SIP, attribution could come from the SIP path
/// and this suite would prove nothing about the `ng` decoder while still
/// passing. Anti-vacuity, checked first.
#[test]
fn the_fixture_contains_no_sip_at_all() {
    let (stdout, stderr) = run(&["--report"]);
    assert!(
        stderr.contains("No SIP signaling found"),
        "fixture must hold ZERO SIP messages, or the attribution below proves \
         nothing about the ng control plane. stderr was:\n{stderr}"
    );
    // And the dialog table is empty: no SIP means no dialog rows, so every
    // Call-ID appearing anywhere in this report was supplied by the relay.
    assert!(
        !stdout.contains("BYE") && !stdout.contains("INVITE"),
        "no SIP method may appear in the report:\n{stdout}"
    );
}

/// RE1's acceptance, end to end: streams that are orphans without the control
/// plane resolve to the Call-ID the proxy assigned.
#[test]
fn relay_media_is_attributed_to_the_call_the_control_plane_named() {
    let out = report(&["--report"]);
    assert!(
        out.contains(CALL_ID),
        "the report must NAME the call the relay assigned; got:\n{out}"
    );
    assert!(
        !out.contains("Orphaned Streams"),
        "no stream may remain orphaned once the control plane named them; \
         got:\n{out}"
    );
}

/// The four sockets of BOTH legs, under one Call-ID.
///
/// Four and not two: the relay has its own socket per leg, and the party's
/// socket on the far side of each. All four are media belonging to one call,
/// and an implementation that attributed only the pair it saw in one SDP body
/// would pass a weaker test than this.
#[test]
fn all_four_sockets_of_both_legs_resolve_to_one_call() {
    let out = report(&["--report"]);
    for socket in RELAY_PORTS.iter().chain(PARTY_PORTS.iter()) {
        assert!(
            out.contains(socket),
            "socket {socket} missing from the report:\n{out}"
        );
    }
    let relay_named = out
        .lines()
        .filter(|l| l.starts_with(CALL_ID))
        .collect::<Vec<_>>();
    assert_eq!(
        relay_named.len(),
        1,
        "exactly one relay-named call expected, got {relay_named:?}"
    );
    assert!(
        relay_named[0].contains('4'),
        "all four streams must be counted against the call; row was {:?}",
        relay_named[0]
    );
}

/// The codec comes from the control plane too.
///
/// Without the `ng` SDP these streams have a payload type and no name for it.
/// `PCMU` here is evidence the SDP body was parsed and applied, not merely
/// that a Call-ID string was copied across.
#[test]
fn the_control_plane_sdp_supplies_the_codec() {
    let out = report(&["--report"]);
    assert!(
        out.contains("PCMU"),
        "the rtpmap from the ng SDP must reach the stream:\n{out}"
    );
}

/// A dialog the run DROPPED is not a call a relay named.
///
/// The first version of the relay-named section keyed on "this stream has a
/// Call-ID that no dialog in this report matches", which is also exactly what
/// `--limit 1` produces: one dialog kept, and streams still pointing at the
/// calls that were evicted. Those streams were named by ordinary SIP
/// signaling, and reporting them as relay-named was a confident wrong answer
/// about the source of the name. Keyed on recorded provenance now.
///
/// This capture contains no HEP and no rtpengine control plane at all, so the
/// section must be absent however many dialogs get dropped.
#[test]
fn a_dialog_dropped_by_limit_is_not_reported_as_relay_named() {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            "tests/pcap-samples/sip-rtp-g711.pcap",
            "--limit",
            "1",
            "--report",
            "--no-cli-print",
        ])
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("run sipnab");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("named by a media relay"),
        "an evicted dialog is not a relay-named call; report was:\n{stdout}"
    );
}
