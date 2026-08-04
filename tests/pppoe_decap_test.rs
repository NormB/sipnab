// SPDX-License-Identifier: MIT OR Apache-2.0

//! A PPPoE-encapsulated capture must report the SIP it contains.
//!
//! PPPoE (RFC 2516) is the access encapsulation on DSL and much FTTH, so an
//! operator who captures on that segment gets EtherType 0x8864 on every frame.
//! sipnab sliced such a frame as Ethernet, found no network layer, dropped it
//! at debug level, and printed "No SIP traffic found. Check that the capture
//! contains SIP packets" — pointing the operator at a port range that was never
//! the problem. That is the failure class this project cares most about: not
//! silence, but a confident wrong answer about customer traffic.
//!
//! `tests/pcap-samples/DTMFsipinfo.pcap` is 32 PPPoE Session frames carrying
//! one complete call. Every assertion here is on the RENDERED result — the
//! dialog JSON and the report body a user actually reads — never on a
//! parse-layer predicate, and every count is EXACT. A `> 0` assertion would
//! pass on a decapsulator that recovered a single frame out of 32.
//!
//! The expected values were established by running sipnab's own pipeline over a
//! control capture: the identical fixture with the 8 PPPoE + PPP bytes removed
//! from each frame and the EtherType rewritten to 0x0800, everything else
//! byte-for-byte unchanged.

use std::path::PathBuf;
use std::process::Command;

/// The one PPPoE capture in the sample set: 32 frames, all EtherType 0x8864.
const FIXTURE: &str = "tests/pcap-samples/DTMFsipinfo.pcap";

/// The single Call-ID the fixture carries.
const CALL_ID: &str = "2091060b-146f-e011-809a-0019cb53db77@admind-desktop";

/// Every SIP message in the fixture, counted by tshark and by sipnab's own
/// pipeline on the de-encapsulated control.
const EXPECTED_MSG_COUNT: u64 = 32;

/// The message sipnab printed for this capture before PPPoE was decapsulated.
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

/// Every `--json-dialogs` object on stdout, in order.
///
/// `--json-dialogs` shares stdout with the per-message stream, so only lines
/// that parse as a JSON object are taken.
fn dialog_objects(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v.get("call_id").is_some())
        .collect()
}

/// The fixture yields exactly one dialog of exactly 32 messages, answered 200.
///
/// These are the numbers sipnab's own pipeline produces for the identical
/// traffic without the PPPoE headers, so any decapsulation that drops, doubles
/// or mis-attributes a frame fails here rather than rounding to "some SIP".
#[test]
fn pppoe_capture_yields_the_exact_dialog_it_contains() {
    let (stdout, stderr, code) = run_sipnab(&[
        "-N",
        "-I",
        &repo_path(FIXTURE),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(code, 0, "sipnab exited {code}; stderr:\n{stderr}");

    let dialogs = dialog_objects(&stdout);
    assert_eq!(
        dialogs.len(),
        1,
        "expected exactly one dialog from {FIXTURE}, got {}:\n{stdout}",
        dialogs.len()
    );
    let d = &dialogs[0];
    assert_eq!(d["call_id"], serde_json::json!(CALL_ID));
    assert_eq!(
        d["msg_count"],
        serde_json::json!(EXPECTED_MSG_COUNT),
        "message count for {CALL_ID}"
    );
    assert_eq!(d["method"], serde_json::json!("INVITE"));
    assert_eq!(d["final_status_code"], serde_json::json!(200));
    assert_eq!(d["final_status_reason"], serde_json::json!("OK"));
    assert_eq!(d["from"], serde_json::json!("admind"));
    assert_eq!(d["to"], serde_json::json!("echo"));
}

/// `--report` renders the call rather than claiming the capture holds no SIP.
///
/// The report body is what an operator reads, so it is asserted directly: a
/// dialog row for the fixture's Call-ID, carrying the exact message count, and
/// no trace of the old wrong answer. That advice line is written to stderr, so
/// both streams are checked — asserting only on stdout would be an assertion
/// that cannot fail.
#[test]
fn pppoe_capture_report_is_not_empty_and_does_not_deny_the_sip() {
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
    // leading portion it prints AND on the line start — the Call-ID also
    // appears mid-line in the per-message stream, which is a different claim.
    let shown = &CALL_ID[..27];
    let row = stdout
        .lines()
        .find(|l| l.starts_with(shown))
        .unwrap_or_else(|| panic!("report has no dialog row for {CALL_ID}:\n{stdout}"));
    assert!(
        row.split_whitespace().any(|f| f == "32"),
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
/// link and IP headers directly instead of going through the full parse. If
/// that peek does not understand PPPoE it returns `None`, every packet lands on
/// worker 0, and the two dispatch sites disagree about what a frame contains.
#[test]
fn pppoe_capture_shards_identically_across_cores() {
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

    let a = dialog_objects(&one.0);
    let b = dialog_objects(&two.0);
    assert_eq!(a.len(), 1, "single-core dialog count");
    assert_eq!(b.len(), 1, "--cores 2 dialog count");
    assert_eq!(
        b[0]["msg_count"],
        serde_json::json!(EXPECTED_MSG_COUNT),
        "--cores 2 lost messages the single-core run found"
    );
    assert_eq!(a[0]["call_id"], b[0]["call_id"]);
}
