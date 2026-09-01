// SPDX-License-Identifier: MIT OR Apache-2.0

//! Three link-layer framings, end to end, against capture files.
//!
//! Each of these link types had decoder code and no capture behind it:
//!
//! * **DLT_LOOP (108)** — OpenBSD loopback encapsulation. It was implemented
//!   alongside DLT_NULL and covered only by frames synthesized inside a unit
//!   test, so nothing exercised the reader, the pipeline and the report
//!   against a real file. `tests/link_layer_decap_test.rs` does exactly that
//!   for DLT_NULL against `h263-over-rtp.pcap`; this is the missing half.
//! * **DLT_LINUX_SLL (113) / DLT_LINUX_SLL2 (276) carrying PPPoE.** What
//!   `tcpdump -i any` writes on a BNG/BRAS, where the access encapsulation is
//!   PPPoE. sipnab decapsulated PPPoE behind Ethernet and skipped a flat
//!   header length on the cooked link types, so the whole of an access
//!   network's traffic reached the IP slicer at the PPPoE header — whose
//!   first nibble is 1 — and came back "unsupported IP version 1" or "not
//!   IP". Counted, but not read.
//!
//! The fixtures are synthetic and generated: `python3
//! tests/gen-link-type-samples.py` writes them and the same script in check
//! mode reports drift. Every count below is EXACT and was chosen in that
//! generator, not read off a run: seven SIP messages, one dialog, two RTP
//! streams of ten packets each, 7 + 20 = 27 frames, which accounts for every
//! frame in each file. A decoder that drops one fails here rather than
//! rounding to "some SIP".
#![cfg(feature = "native")]

use std::path::PathBuf;
use std::process::Command;

/// The DLT_LOOP fixture: a loopback capture of one complete call.
const LOOP_FIXTURE: &str = "tests/pcap-samples/loopback-dlt-loop.pcap";
/// The DLT_LINUX_SLL fixture: PPPoE inside cooked capture v1.
const SLL_FIXTURE: &str = "tests/pcap-samples/linux-sll-pppoe.pcap";
/// The DLT_LINUX_SLL2 fixture: PPPoE inside cooked capture v2.
const SLL2_FIXTURE: &str = "tests/pcap-samples/linux-sll2-pppoe.pcap";

/// The Call-ID each fixture carries. One per file, so a test that reads the
/// wrong fixture fails loudly instead of passing on a coincidence.
const LOOP_CALL_ID: &str = "synthetic-dlt-loop-call@example.com";
const SLL_CALL_ID: &str = "synthetic-linux-sll-call@example.com";
const SLL2_CALL_ID: &str = "synthetic-linux-sll2-call@example.com";

/// SIP messages per fixture: INVITE, 100, 180, 200, ACK, BYE, 200.
const EXPECTED_MSG_COUNT: usize = 7;

/// Dialogs per fixture: one complete call.
const EXPECTED_DIALOG_COUNT: usize = 1;

/// RTP streams per fixture: one per direction.
const EXPECTED_STREAM_COUNT: usize = 2;

/// RTP packets in each stream. `EXPECTED_MSG_COUNT` plus two of these is 27 —
/// every frame each file holds.
const EXPECTED_RTP_PACKETS: u64 = 10;

/// The message sipnab prints for a capture it decodes nothing from.
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

/// The seven messages a fixture carries, in the order it carries them.
fn assert_messages(fixture: &str, call_id: &str) {
    let (stdout, stderr, code) = run_sipnab(&["-N", "-I", &repo_path(fixture), "--json"]);
    assert_eq!(
        code, 0,
        "sipnab exited {code} on {fixture}; stderr:\n{stderr}"
    );

    let msgs = json_objects(&stdout, "cseq");
    assert_eq!(
        msgs.len(),
        EXPECTED_MSG_COUNT,
        "expected exactly {EXPECTED_MSG_COUNT} SIP messages from {fixture}, got {}:\n{stdout}",
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
    assert_eq!(
        summary,
        vec!["INVITE", "100", "180", "200", "ACK", "BYE", "200"],
        "{fixture}"
    );

    for m in &msgs {
        assert_eq!(m["call_id"], serde_json::json!(call_id), "{fixture}");
        assert_eq!(m["transport"], serde_json::json!("UDP"), "{fixture}");
    }
}

/// The one dialog a fixture carries, its outcome, and both media streams.
///
/// The streams are asserted because they are what rules out "the SIP was
/// recovered and the other twenty frames were dropped": the link decoder runs
/// on every frame, not only the ones that turn out to be SIP.
fn assert_dialog(fixture: &str, call_id: &str) {
    let (stdout, stderr, code) = run_sipnab(&[
        "-N",
        "-I",
        &repo_path(fixture),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(
        code, 0,
        "sipnab exited {code} on {fixture}; stderr:\n{stderr}"
    );

    let dialogs = json_objects(&stdout, "msg_count");
    assert_eq!(
        dialogs.len(),
        EXPECTED_DIALOG_COUNT,
        "expected exactly {EXPECTED_DIALOG_COUNT} dialog from {fixture}, got {}:\n{stdout}",
        dialogs.len()
    );

    let d = &dialogs[0];
    assert_eq!(d["call_id"], serde_json::json!(call_id));
    assert_eq!(d["msg_count"], serde_json::json!(EXPECTED_MSG_COUNT));
    assert_eq!(d["method"], serde_json::json!("INVITE"));
    assert_eq!(d["final_status_code"], serde_json::json!(200));
    assert_eq!(d["final_status_reason"], serde_json::json!("OK"));
    assert_eq!(d["state"], serde_json::json!("Completed"));

    let streams = d["streams"].as_array().expect("dialog carries streams");
    assert_eq!(streams.len(), EXPECTED_STREAM_COUNT, "{fixture} streams");
    for s in streams {
        assert_eq!(s["packets"], serde_json::json!(EXPECTED_RTP_PACKETS));
        assert_eq!(s["codec"], serde_json::json!("PCMU"));
        assert_eq!(s["loss_pct"], serde_json::json!(0.0));
    }
}

/// `--cores 2` finds the same dialog the single-threaded run finds.
///
/// The dispatcher shards on a cheap host-pair peek that reads the link and IP
/// headers directly instead of going through the full parse. A peek that does
/// not understand a link type the full parse understands is a split brain:
/// the two dispatch sites disagree about the same frame, and the failure is
/// quiet — everything lands on worker 0, or worse, a flow's packets scatter.
fn assert_cores_parity(fixture: &str) {
    let path = repo_path(fixture);
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
    assert_eq!(one.2, 0, "single-core run failed on {fixture}:\n{}", one.1);
    assert_eq!(two.2, 0, "--cores 2 run failed on {fixture}:\n{}", two.1);

    let a = json_objects(&one.0, "msg_count");
    let b = json_objects(&two.0, "msg_count");
    assert_eq!(a.len(), EXPECTED_DIALOG_COUNT, "{fixture} single-core");
    assert_eq!(b.len(), EXPECTED_DIALOG_COUNT, "{fixture} --cores 2");
    assert_eq!(a[0]["call_id"], b[0]["call_id"], "{fixture}");
    assert_eq!(
        b[0]["msg_count"],
        serde_json::json!(EXPECTED_MSG_COUNT),
        "--cores 2 lost messages the single-core run found in {fixture}"
    );
    let streams = b[0]["streams"].as_array().expect("streams under --cores 2");
    assert_eq!(streams.len(), EXPECTED_STREAM_COUNT, "{fixture} --cores 2");
}

/// The report renders the call rather than claiming the capture holds no SIP.
fn assert_report_does_not_deny(fixture: &str, call_id: &str) {
    let (stdout, stderr, code) = run_sipnab(&[
        "-N",
        "-I",
        &repo_path(fixture),
        "--report",
        "--no-cli-print",
    ]);
    assert_eq!(
        code, 0,
        "sipnab exited {code} on {fixture}; stderr:\n{stderr}"
    );

    for (stream, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(
            !text.contains(WRONG_ANSWER),
            "{stream} still denies the SIP in {fixture}, which holds \
             {EXPECTED_MSG_COUNT} messages:\n{text}"
        );
    }

    // The table truncates the Call-ID with an ellipsis, so anchor on the
    // leading portion it prints AND on the line start.
    let shown = &call_id[..20];
    let row = stdout
        .lines()
        .find(|l| l.starts_with(shown))
        .unwrap_or_else(|| panic!("report has no dialog row for {call_id}:\n{stdout}"));
    assert!(
        row.split_whitespace().any(|f| f == "7"),
        "dialog row reports a message count other than {EXPECTED_MSG_COUNT}: {row}"
    );
    assert!(
        row.contains("200"),
        "dialog row reports no final status code: {row}"
    );
}

// ── DLT_LOOP (108) ────────────────────────────────────────────────────

/// A DLT_LOOP capture yields the exact call it contains.
#[test]
fn dlt_loop_capture_yields_the_exact_messages_it_contains() {
    assert_messages(LOOP_FIXTURE, LOOP_CALL_ID);
}

/// …one dialog, completed 200, with both media streams intact.
#[test]
fn dlt_loop_capture_yields_the_exact_dialog_it_contains() {
    assert_dialog(LOOP_FIXTURE, LOOP_CALL_ID);
}

/// …and the report says so.
#[test]
fn dlt_loop_capture_report_does_not_deny_the_sip() {
    assert_report_does_not_deny(LOOP_FIXTURE, LOOP_CALL_ID);
}

/// …and `--cores 2` agrees.
#[test]
fn dlt_loop_capture_shards_identically_across_cores() {
    assert_cores_parity(LOOP_FIXTURE);
}

/// DLT_LOOP's address family is big-endian, and this fixture proves it is
/// read that way rather than passing under either reading.
///
/// DLT_NULL (0) and DLT_LOOP (108) differ in exactly one thing: DLT_NULL's
/// 4-byte address family is in the writing host's byte order, DLT_LOOP's is
/// always in network order. sipnab therefore accepts either reading on
/// DLT_NULL and only the big-endian one on DLT_LOOP.
///
/// A fixture alone cannot demonstrate that: `00 00 00 02` is AF_INET
/// big-endian, and a decoder that wrongly accepted host order too would still
/// read it. So this test builds the counter-example — the same capture with
/// every family word byte-swapped to `02 00 00 00`, the little-endian
/// spelling a DLT_NULL capture from an x86 host would carry — and requires
/// sipnab to find nothing in it. Family 0x02000000 is not AF_INET, and a
/// decoder that "helpfully" swapped it would erase the one distinction the
/// link type exists to make.
#[test]
fn dlt_loop_rejects_the_host_order_address_family_the_link_type_forbids() {
    let original = std::fs::read(repo_path(LOOP_FIXTURE)).expect("read the DLT_LOOP fixture");

    // Classic little-endian pcap: a 24-byte file header, then per-packet
    // 16-byte records (ts_sec, ts_usec, caplen, origlen) each followed by
    // `caplen` bytes whose first four are the DLT_LOOP address family.
    let mut swapped = original.clone();
    let mut off = 24;
    let mut frames = 0;
    while off + 16 <= swapped.len() {
        let caplen = u32::from_le_bytes(swapped[off + 8..off + 12].try_into().unwrap()) as usize;
        let body = off + 16;
        assert!(body + 4 <= swapped.len(), "truncated fixture record");
        swapped[body..body + 4].reverse();
        frames += 1;
        off = body + caplen;
    }
    assert_eq!(
        frames, 27,
        "the DLT_LOOP fixture must hold 27 frames: 7 SIP + 20 RTP"
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("host-order-family.pcap");
    std::fs::write(&path, &swapped).expect("write the byte-swapped copy");

    let (stdout, _stderr, code) = run_sipnab(&[
        "-N",
        "-I",
        path.to_str().unwrap(),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(
        code, 0,
        "sipnab should exit 0 on a capture it cannot decode"
    );
    assert!(
        json_objects(&stdout, "msg_count").is_empty(),
        "a DLT_LOOP capture whose address family is host-order is not AF_INET, \
         and reading it as one would erase the only difference between \
         DLT_LOOP and DLT_NULL:\n{stdout}"
    );

    // …and the unmodified fixture does decode, so the assertion above is not
    // passing because the harness cannot read either file.
    let (ok_stdout, _, ok_code) = run_sipnab(&[
        "-N",
        "-I",
        &repo_path(LOOP_FIXTURE),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(ok_code, 0);
    assert_eq!(
        json_objects(&ok_stdout, "msg_count").len(),
        EXPECTED_DIALOG_COUNT
    );
}

// ── PPPoE inside Linux cooked capture (SLL / SLL2) ────────────────────

/// A `-i any` capture of a PPPoE access link yields the call it contains.
#[test]
fn linux_sll_pppoe_capture_yields_the_exact_messages_it_contains() {
    assert_messages(SLL_FIXTURE, SLL_CALL_ID);
}

/// …one dialog, completed 200, with both media streams intact.
#[test]
fn linux_sll_pppoe_capture_yields_the_exact_dialog_it_contains() {
    assert_dialog(SLL_FIXTURE, SLL_CALL_ID);
}

/// …and the report says so.
#[test]
fn linux_sll_pppoe_capture_report_does_not_deny_the_sip() {
    assert_report_does_not_deny(SLL_FIXTURE, SLL_CALL_ID);
}

/// …and `--cores 2` agrees, which is where a peek that skipped a flat 16
/// bytes past the PPPoE header would show up.
#[test]
fn linux_sll_pppoe_capture_shards_identically_across_cores() {
    assert_cores_parity(SLL_FIXTURE);
}

/// The same call, in the SLL2 header, whose protocol type sits at offset 0
/// rather than 14.
#[test]
fn linux_sll2_pppoe_capture_yields_the_exact_messages_it_contains() {
    assert_messages(SLL2_FIXTURE, SLL2_CALL_ID);
}

/// …one dialog, completed 200, with both media streams intact.
#[test]
fn linux_sll2_pppoe_capture_yields_the_exact_dialog_it_contains() {
    assert_dialog(SLL2_FIXTURE, SLL2_CALL_ID);
}

/// …and the report says so.
#[test]
fn linux_sll2_pppoe_capture_report_does_not_deny_the_sip() {
    assert_report_does_not_deny(SLL2_FIXTURE, SLL2_CALL_ID);
}

/// …and `--cores 2` agrees.
#[test]
fn linux_sll2_pppoe_capture_shards_identically_across_cores() {
    assert_cores_parity(SLL2_FIXTURE);
}

/// The three fixtures are what the generator writes, byte for byte.
///
/// A capture fixture is only as trustworthy as its provenance: these files
/// are load-bearing (the counts above are asserted against them) and the
/// repository is public, so "generated by a script in the tree" has to stay
/// true rather than being true on the day they were added. The same script in
/// check mode is the proof.
#[test]
fn the_link_type_fixtures_match_their_generator() {
    let out = Command::new("python3")
        .arg("tests/gen-link-type-samples.py")
        .arg("--check")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output();
    let Ok(out) = out else {
        // No python3 on this machine: the fixtures are still checked in and
        // every other test here reads them. Skipping is honest; failing would
        // report a toolchain gap as a capture defect.
        eprintln!("skipping: python3 is not available to check fixture drift");
        return;
    };
    assert!(
        out.status.success(),
        "tests/pcap-samples link-type fixtures have drifted from \
         tests/gen-link-type-samples.py:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
