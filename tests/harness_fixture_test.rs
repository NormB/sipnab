// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every fixture promoted out of the harness has a test that asserts the claim
//! its `**Pins:**` line makes.
//!
//! `tests/pcap-samples/PROVENANCE.md` records what each promoted capture is
//! FOR, and `every_committed_capture_fixture_says_where_it_came_from` makes
//! that record non-optional. A sentence is not an assertion, though: LIVE2 in
//! `docs/design/backlog.md` asks for fixtures promoted "as named, documented
//! fixtures — the scenario that produced them, the anchor and direction in
//! force, and the finding they are meant to pin", and a finding that is only
//! written down is one nobody notices losing.
//!
//! So this file is the other half. One test per promoted fixture, asserting
//! what its entry claims, in a file whose whole subject is that pairing.

use std::process::Command;

/// Run the binary and return stdout, stderr and the exit code.
fn run(args: &[&str]) -> (String, String, i32) {
    run_at_log_level("warn", args)
}

/// [`run`] at a chosen log level.
///
/// The end-of-run summary — "N packets captured, N SIP messages, N RTP packets
/// across N streams" — is an `info` log line, so a test asserting on it has to
/// ask for one. It is worth asserting on: that sentence is what an operator
/// reads, and it is where a stream sipnab invented would appear.
fn run_at_log_level(level: &str, args: &[&str]) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("SIPNAB_LOG", level)
        .output()
        .expect("failed to execute sipnab");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code().unwrap_or(-1),
    )
}

/// `opensips-direct-media-proxy-view.pcap`: a complete dialog and no streams.
///
/// The capture's `**Pins:**` line, in full: *the proxy-side view of a call with
/// NO media anchor: OpenSIPS relays the signaling and the media goes
/// endpoint-to-endpoint, so a capture at the proxy holds a complete dialog and
/// ZERO RTP streams. The control case for stream attribution -- sipnab must
/// report no streams rather than infer them from SDP.*
///
/// **Zero streams is the assertion, not an absence of one.** The dialog's SDP
/// names an audio endpoint on both sides, so a reconstruction that trusted the
/// offer rather than the wire would report streams here — with a codec, a
/// direction and a MOS, all of them invented from a negotiation whose media
/// never came near this capture point. That is the failure mode `HX2` calls
/// the control the other two anchors are measured against, and it needs a
/// capture where the right answer is nothing.
///
/// It is a real OpenSIPS 3.6.7 exchange rather than a hand-built one: SIPp
/// placed the call through the proxy with `MEDIA_ANCHOR=none`, and tcpdump —
/// not sipnab — wrote the file inside the proxy's network namespace.
#[test]
fn direct_media_proxy_view_has_a_complete_dialog_and_no_streams() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/pcap-samples/opensips-direct-media-proxy-view.pcap"
    );
    let (stdout, stderr, code) = run(&["-N", "-I", path, "--json-dialogs", "--no-cli-print"]);
    assert_eq!(code, 0, "sipnab should exit cleanly; stderr:\n{stderr}");

    let dialogs: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v.get("call_id").is_some())
        .collect();
    assert_eq!(
        dialogs.len(),
        1,
        "the capture holds exactly one call; got {}:\n{stdout}",
        dialogs.len()
    );
    let dialog = &dialogs[0];
    assert_eq!(
        dialog["state"].as_str(),
        Some("Completed"),
        "the call completed — INVITE through BYE is inside the capture window"
    );
    assert_eq!(
        dialog["final_status_code"].as_u64(),
        Some(200),
        "answered, not merely attempted"
    );

    // The premise the zero-stream assertion rests on: the SDP DID advertise
    // audio. Without this the test would pass just as well against a capture
    // that negotiated nothing, which proves nothing about attribution.
    let offered: Vec<&str> = dialog["sdp_timeline"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| e["codecs"].as_array())
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .collect()
        })
        .unwrap_or_default();
    assert!(
        offered.contains(&"PCMA"),
        "the SDP must offer audio for the zero-stream claim to mean anything; \
         offered: {offered:?}"
    );
    assert!(
        dialog["streams"].as_array().is_none_or(|s| s.is_empty()),
        "the dialog must carry no streams: {}",
        dialog["streams"]
    );

    // The claim. A proxy that anchors nothing sees no media, and sipnab must
    // say so rather than manufacture a stream from the SDP it did see.
    let (streams, stderr, code) =
        run_at_log_level("info", &["-N", "-I", path, "--report", "--no-cli-print"]);
    assert_eq!(code, 0, "sipnab should exit cleanly; stderr:\n{stderr}");
    let all = format!("{streams}{stderr}");
    assert!(
        all.contains("0 RTP packets across 0 streams"),
        "a capture at a proxy with no media anchor must report no streams; got:\n{all}"
    );
}
