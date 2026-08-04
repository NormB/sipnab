// SPDX-License-Identifier: MIT OR Apache-2.0

//! A BSD loopback capture must report the SIP it contains.
//!
//! `tcpdump -i lo0` on FreeBSD, OpenBSD, NetBSD or macOS writes DLT_NULL (link
//! type 0) or DLT_LOOP (108): a 4-byte address-family word where Ethernet
//! would be, then the IP header. That is what every trace of a softphone
//! talking to a proxy on the same host looks like, and it is the shape of
//! `tests/pcap-samples/h263-over-rtp.pcap`.
//!
//! sipnab had no arm for either link type. `parse_packet` returned
//! `UnsupportedLinkType` for all 49 frames, the run printed "No SIP traffic
//! found. Check that the capture contains SIP packets" and exited 0 — a
//! confident wrong answer about a capture holding a complete INVITE/200/ACK
//! exchange and 45 RTP packets, which is worse than a crash because nothing
//! downstream can tell it from an empty file.
//!
//! Every number here is EXACT and was read off the fixture itself before the
//! decoder was written: 49 frames, of which 4 are UDP port 5060 carrying one
//! Call-ID (INVITE, 100 Trying, 200 OK, ACK) and 45 are the H.263 RTP stream.
//! 4 + 45 = 49 accounts for every frame in the file, so a decoder that drops
//! even one fails here rather than rounding to "some SIP".
#![cfg(feature = "native")]

use std::path::PathBuf;
use std::process::Command;

/// The DLT_NULL sample: 49 frames, all BSD loopback.
const FIXTURE: &str = "tests/pcap-samples/h263-over-rtp.pcap";

/// The single Call-ID the fixture carries.
const CALL_ID: &str = "NmNhYWNhMjY0Y2M0OTc4YTI2MzgzZTNlYTRhZTMxNTE.";

/// SIP messages in the fixture: INVITE, 100 Trying, 200 OK, ACK.
const EXPECTED_MSG_COUNT: usize = 4;

/// Dialogs in the fixture: one call.
const EXPECTED_DIALOG_COUNT: usize = 1;

/// RTP packets in the fixture's single H.263 stream. `EXPECTED_MSG_COUNT` plus
/// this is 49 — every frame the file holds.
const EXPECTED_RTP_PACKETS: u64 = 45;

/// The message sipnab printed for this capture before DLT_NULL was decoded.
const WRONG_ANSWER: &str = "No SIP traffic found.";

/// Absolute path to a file in the repository.
fn repo_path(rel: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

/// Run the compiled `sipnab` binary with `SIPNAB_LOG=warn`.
///
/// # Arguments
/// * `args` — CLI arguments to pass.
///
/// # Returns
/// `(stdout, stderr, exit_code)`.
///
/// # Side effects
/// Spawns the compiled `sipnab` binary as a subprocess.
fn run_sipnab(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("failed to execute sipnab");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// Every JSON object on stdout that carries `key`, in order.
///
/// The NDJSON streams share stdout with human output, so only lines that parse
/// as a JSON object are taken, and `key` separates the per-message objects
/// (`cseq`) from the per-dialog ones (`msg_count`).
fn json_objects(stdout: &str, key: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v.get(key).is_some())
        .collect()
}

/// The fixture yields exactly the four messages it carries, in order, between
/// the loopback addresses it carries them between.
///
/// The addresses are asserted because they are what proves the 4-byte family
/// word was consumed rather than read as part of the IP header: get the offset
/// wrong and either nothing parses or the "addresses" come out of the middle
/// of the header.
#[test]
fn null_loopback_capture_yields_the_exact_messages_it_contains() {
    let (stdout, stderr, code) = run_sipnab(&["-N", "-I", &repo_path(FIXTURE), "--json"]);
    assert_eq!(code, 0, "sipnab exited {code}; stderr:\n{stderr}");

    let msgs = json_objects(&stdout, "cseq");
    assert_eq!(
        msgs.len(),
        EXPECTED_MSG_COUNT,
        "expected exactly {EXPECTED_MSG_COUNT} SIP messages from {FIXTURE}, got {}:\n{stdout}",
        msgs.len()
    );

    let summary: Vec<String> = msgs
        .iter()
        .map(|m| match (m.get("method"), m.get("status_code")) {
            (Some(method), _) => method.as_str().unwrap_or("?").to_string(),
            (None, Some(code)) => code.to_string(),
            _ => "?".to_string(),
        })
        .collect();
    assert_eq!(summary, vec!["INVITE", "100", "200", "ACK"]);

    for m in &msgs {
        assert_eq!(m["call_id"], serde_json::json!(CALL_ID));
        assert_eq!(m["src"], serde_json::json!("127.0.0.1"));
        assert_eq!(m["dst"], serde_json::json!("127.0.0.1"));
        assert_eq!(m["transport"], serde_json::json!("UDP"));
    }
    assert_eq!(msgs[0]["src_port"], serde_json::json!(13764));
    assert_eq!(msgs[0]["dst_port"], serde_json::json!(5060));
}

/// The fixture yields exactly one dialog, of exactly four messages, answered
/// 200 — and the 45 RTP packets that account for every remaining frame.
#[test]
fn null_loopback_capture_yields_the_exact_dialog_it_contains() {
    let (stdout, stderr, code) = run_sipnab(&[
        "-N",
        "-I",
        &repo_path(FIXTURE),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(code, 0, "sipnab exited {code}; stderr:\n{stderr}");

    let dialogs = json_objects(&stdout, "msg_count");
    assert_eq!(
        dialogs.len(),
        EXPECTED_DIALOG_COUNT,
        "expected exactly {EXPECTED_DIALOG_COUNT} dialog from {FIXTURE}, got {}:\n{stdout}",
        dialogs.len()
    );

    let d = &dialogs[0];
    assert_eq!(d["call_id"], serde_json::json!(CALL_ID));
    assert_eq!(d["msg_count"], serde_json::json!(EXPECTED_MSG_COUNT));
    assert_eq!(d["method"], serde_json::json!("INVITE"));
    assert_eq!(d["final_status_code"], serde_json::json!(200));
    assert_eq!(d["final_status_reason"], serde_json::json!("OK"));

    // The media half of the file: one stream, every packet of it. This is what
    // rules out "the SIP was recovered and the other 45 frames were dropped".
    let streams = d["streams"].as_array().expect("dialog carries streams");
    assert_eq!(streams.len(), 1, "expected exactly one RTP stream");
    assert_eq!(
        streams[0]["packets"],
        serde_json::json!(EXPECTED_RTP_PACKETS)
    );
    assert_eq!(streams[0]["codec"], serde_json::json!("H263"));
}

/// The report renders the call rather than claiming the capture holds no SIP.
///
/// The advice line goes to stderr and the table to stdout, so both streams are
/// checked — asserting only on stdout would be an assertion that cannot fail.
#[test]
fn null_loopback_capture_report_does_not_deny_the_sip() {
    let (stdout, stderr, code) = run_sipnab(&[
        "-N",
        "-I",
        &repo_path(FIXTURE),
        "--report",
        "--no-cli-print",
    ]);
    assert_eq!(code, 0, "sipnab exited {code}; stderr:\n{stderr}");

    for (stream, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(
            !text.contains(WRONG_ANSWER),
            "{stream} still denies the SIP in a capture that holds \
             {EXPECTED_MSG_COUNT} messages:\n{text}"
        );
    }

    // The table truncates the Call-ID with an ellipsis, so anchor on the
    // leading portion it prints AND on the line start.
    let shown = &CALL_ID[..27];
    let row = stdout
        .lines()
        .find(|l| l.starts_with(shown))
        .unwrap_or_else(|| panic!("report has no dialog row for {CALL_ID}:\n{stdout}"));
    assert!(
        row.split_whitespace().any(|f| f == "4"),
        "dialog row reports a message count other than {EXPECTED_MSG_COUNT}: {row}"
    );
    assert!(
        row.contains("200"),
        "dialog row reports no final status code: {row}"
    );
}

/// Sharding across `--cores` does not change the result.
///
/// The `--cores N` dispatcher shards on a cheap host-pair peek that reads the
/// link and IP headers directly instead of going through the full parse. A
/// peek that does not understand a link type the full parse does understand is
/// a split brain: the two dispatch sites disagree about the same frame.
#[test]
fn null_loopback_capture_shards_identically_across_cores() {
    let path = repo_path(FIXTURE);
    let one = run_sipnab(&["-N", "-I", &path, "--json-dialogs", "--no-cli-print"]);
    let two = run_sipnab(&[
        "-N",
        "-I",
        &path,
        "--cores",
        "2",
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(one.2, 0, "single-core run failed:\n{}", one.1);
    assert_eq!(two.2, 0, "--cores 2 run failed:\n{}", two.1);

    let a = json_objects(&one.0, "msg_count");
    let b = json_objects(&two.0, "msg_count");
    assert_eq!(a.len(), EXPECTED_DIALOG_COUNT, "single-core dialog count");
    assert_eq!(b.len(), EXPECTED_DIALOG_COUNT, "--cores 2 dialog count");
    assert_eq!(
        b[0]["msg_count"],
        serde_json::json!(EXPECTED_MSG_COUNT),
        "--cores 2 lost messages the single-core run found"
    );
    assert_eq!(a[0]["call_id"], b[0]["call_id"]);
}
