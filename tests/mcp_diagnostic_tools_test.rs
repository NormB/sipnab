// SPDX-License-Identifier: MIT OR Apache-2.0

//! The diagnostic MCP tools must give the RIGHT answer on real captures.
//!
//! Unit tests over synthetic dialogs prove the code paths run. They do not
//! prove the tools are *correct*, and a diagnostic tool that returns a
//! confident wrong answer is worse than one that errors: an operator working a
//! production outage spends their scarcest resource acting on it.
//!
//! That failure nearly shipped here. `check_codec_negotiation` was demonstrated
//! against `sip-488-codec-reject.pcapng` — a capture whose *name* implies codec
//! data — and returned empty lists. The tool was right (that capture carries no
//! `m=audio` line at all) but nothing proved it, and an identical output would
//! have come from a broken extractor. The lesson is not "add a test"; it is
//! that a plausible-looking result is not evidence.
//!
//! So every test here runs the real binary over a real capture and asserts a
//! specific expected value that was verified independently — from the SDP in
//! the packets, not from what the tool returned.
//!
//! `#![cfg(feature = "mcp")]` because these drive the MCP surface.

#![cfg(feature = "mcp")]

use std::process::Command;

/// Call one MCP tool over stdio against a capture, returning its JSON result.
///
/// Thin wrapper over [`call_tool_with_args`] so both paths share the
/// wait-for-capture logic. They were separate implementations and only one had
/// the fix, which is how the same race would have come back through the other
/// door.
fn call_tool(pcap: &str, tool: &str, args: serde_json::Value) -> serde_json::Value {
    let msg = call_tool_with_args(pcap, &[], tool, args);
    let text = msg["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool {tool} returned no text: {msg}"));
    serde_json::from_str(text).expect("tool result is JSON")
}

/// The largest fixture in the tree: 1334 dialogs, 127 of them failed.
///
/// Pagination defects only show on a capture bigger than one page. Every
/// smaller fixture fits inside the default `limit` of 50, where a tool that
/// silently drops the remainder looks identical to one that returns everything.
const BRANCH: &str = "tests/pcap-samples/sipp-branch-scenario.pcapng";

/// Four RTP streams, no dialogs: two PCMU and two G722, all orphaned.
///
/// Two properties earn this fixture its place. Nothing here is reachable
/// through `rtp_stats { call_id }` at all — with no dialog to name, the
/// per-call tool cannot see a single one of these streams. And the codecs
/// split exactly along the MOS grounding line: G.711 has a published ITU-T
/// G.113 impairment value, G.722 has none, so a MOS threshold applied to all
/// four would be selecting half its answer from a placeholder.
const CODECS: &str = "tests/pcap-samples/codec-negotiation.pcap";

/// First Call-ID in a capture, so tests do not hardcode one that may change.
fn first_call_id(pcap: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-N",
            "-I",
            pcap,
            "--json-dialogs",
            "--no-cli-print",
            "--quiet",
        ])
        .output()
        .expect("spawn sipnab");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines().filter(|l| l.trim_start().starts_with('{')) {
        let v: serde_json::Value = serde_json::from_str(line).expect("dialog line");
        if let Some(id) = v["call_id"].as_str() {
            return id.to_string();
        }
    }
    panic!("no dialogs in {pcap}");
}

const G711: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// A G.711 call must report PCMU on both sides and a real intersection.
///
/// Verified independently against the capture's SDP: the offer carries PCMU,
/// the answer carries PCMU plus telephone-event. An empty result here — the
/// shape that nearly shipped unnoticed — now fails.
#[test]
fn codec_negotiation_reports_the_real_codecs() {
    let call_id = first_call_id(G711);
    let v = call_tool(
        G711,
        "check_codec_negotiation",
        serde_json::json!({"call_id": call_id}),
    );

    let offered: Vec<String> = serde_json::from_value(v["offered"].clone()).expect("offered");
    let answered: Vec<String> = serde_json::from_value(v["answered"].clone()).expect("answered");
    let common: Vec<String> = serde_json::from_value(v["common"].clone()).expect("common");

    assert!(
        offered.iter().any(|c| c == "PCMU"),
        "the offer carries PCMU; got {offered:?}. An empty list here is the \
         exact shape a broken extractor produces"
    );
    assert!(
        answered.iter().any(|c| c == "PCMU"),
        "the answer carries PCMU; got {answered:?}"
    );
    assert_eq!(common, vec!["PCMU".to_string()], "PCMU is the agreed codec");
    assert_eq!(v["result"], "ok");
    assert!(v["sdp_exchange_count"].as_u64().unwrap_or(0) >= 2);
}

/// A dialog with no SDP must say so, not claim the far end failed to answer.
///
/// The dialog under test is the OPTIONS keepalive at the head of
/// `sip-488-codec-reject.pcapng`, which genuinely carries no body. Reporting
/// "no_answer" would send an operator hunting a reply that was never expected.
///
/// The Call-ID is named rather than taken from [`first_call_id`]. This test
/// previously relied on that helper and on a comment asserting the whole
/// capture "carries no m=audio line at all" — both wrong. The helper returns
/// the first dialog, which is this OPTIONS exchange, while the comment
/// described the INVITE, which offers `m=audio 0 RTP/AVP 0`. The test passed
/// for a reason unrelated to what it claimed to check, so an extractor change
/// would not have been caught here.
#[test]
fn codec_negotiation_distinguishes_absent_sdp_from_an_unanswered_offer() {
    const CAPTURE: &str = "tests/pcap-samples/sip-488-codec-reject.pcapng";
    let v = call_tool(
        CAPTURE,
        "check_codec_negotiation",
        serde_json::json!({"call_id": "options-ping-a-synth@192.168.10.13"}),
    );
    assert_eq!(
        v["result"], "no_sdp_in_capture",
        "an OPTIONS exchange with no body must report absent SDP, not a \
         missing answer; got {}",
        v["result"]
    );
}

/// The 488 INVITE in the same capture offers a codec, and it must be named.
///
/// `m=audio 0 RTP/AVP 0` carries no `a=rtpmap`, because RFC 3551 does not
/// require one for a static payload type. Payload 0 is permanently PCMU. This
/// reported `offered: []` until the static table landed, which reaches an
/// operator as "the caller offered nothing" — a different and wrong diagnosis
/// for a call rejected with 488.
#[test]
fn codec_negotiation_names_a_static_payload_type_with_no_rtpmap() {
    const CAPTURE: &str = "tests/pcap-samples/sip-488-codec-reject.pcapng";
    let v = call_tool(
        CAPTURE,
        "check_codec_negotiation",
        serde_json::json!({"call_id": "codec-reject-synth"}),
    );
    let offered: Vec<String> = serde_json::from_value(v["offered"].clone()).expect("offered");
    assert_eq!(
        offered,
        vec!["PCMU".to_string()],
        "payload type 0 is PCMU by RFC 3551 Table 4 with or without an rtpmap; \
         got {offered:?}"
    );
    assert_eq!(v["final_status_code"], 488);
}

/// Codec names differing only in case are the SAME codec.
///
/// `SIP_CALL_RTP_G711` offers `PCMA`/`PCMU` and answers `pcma`/`pcmu` — the
/// spelling each vendor chose, and RFC 4855 §1 makes the encoding name
/// case-insensitive. Comparing with an exact string match reported
/// `no_common_codec` on a call that answered **200 OK** and carried real G.711
/// audio.
///
/// That is the worst failure this tool has: not an error, but a confident
/// wrong answer pointing at a codec mismatch that does not exist. An operator
/// mid-outage would go reconfigure a working codec list.
#[test]
fn codec_comparison_ignores_case_because_rfc_4855_does() {
    const MIXED_CASE: &str = "tests/pcap-samples/SIP_CALL_RTP_G711";
    let v = call_tool(
        MIXED_CASE,
        "check_codec_negotiation",
        serde_json::json!({"call_id": "12013223@200.57.7.195"}),
    );

    let offered: Vec<String> = serde_json::from_value(v["offered"].clone()).expect("offered");
    let answered: Vec<String> = serde_json::from_value(v["answered"].clone()).expect("answered");
    let common: Vec<String> = serde_json::from_value(v["common"].clone()).expect("common");

    // The wire spelling is evidence and must survive into the report.
    assert!(
        offered.iter().any(|c| c == "PCMA"),
        "the offer's own spelling must be preserved; got {offered:?}"
    );
    assert!(
        answered.iter().any(|c| c == "pcma"),
        "the answer's own spelling must be preserved; got {answered:?}"
    );

    let lower: Vec<String> = common.iter().map(|c| c.to_lowercase()).collect();
    assert!(
        lower.iter().any(|c| c == "pcma") && lower.iter().any(|c| c == "pcmu"),
        "PCMA and PCMU appear on both sides and must be common; got {common:?}"
    );
    assert_eq!(
        v["result"], "ok",
        "this call answered 200 OK and carried G.711; reporting \
         no_common_codec sends an operator after a mismatch that is not there"
    );
}

/// The signaling/media split is the first triage decision, so it must be right.
///
/// This capture has clean signaling (200 OK) and one-way audio, so the verdict
/// must be "media". Calling it "signaling" would send an operator to the SIP
/// side of a problem that is entirely in RTP.
#[test]
fn triage_calls_one_way_audio_a_media_problem() {
    let call_id = first_call_id(G711);
    let v = call_tool(G711, "triage_call", serde_json::json!({"call_id": call_id}));

    assert_eq!(
        v["verdict"], "media",
        "clean signaling with one-way audio is a MEDIA problem: {v}"
    );
    assert_eq!(v["signaling"]["problem"], false);
    assert_eq!(v["media"]["problem"], true);
    assert_eq!(v["media"]["one_way_audio"], true);
}

/// A failed call with no media must land on the signaling side.
#[test]
fn triage_calls_a_failed_call_a_signalling_problem() {
    const FAIL: &str = "tests/pcap-samples/sip-auth-failure.pcapng";
    let call_id = first_call_id(FAIL);
    let v = call_tool(FAIL, "triage_call", serde_json::json!({"call_id": call_id}));
    assert_eq!(
        v["verdict"], "signaling",
        "a 403 with no streams is a signaling problem: {v}"
    );
    assert_eq!(v["signaling"]["problem"], true);
}

/// The registry lookup must return the real meaning, not a plausible sentence.
#[test]
fn explain_response_code_returns_registry_text() {
    let v = call_tool(
        G711,
        "explain_response_code",
        serde_json::json!({"code": 488}),
    );
    assert_eq!(v["class"], "failure");
    assert_eq!(v["registered"], true);
    let text = v["explanation"].as_str().unwrap_or_default();
    assert!(
        text.contains("Codec"),
        "488's explanation must name codec negotiation; got {text:?}"
    );
}

/// The SDP timeline must carry the codecs, not an empty shell.
#[test]
fn sdp_timeline_carries_codecs() {
    let call_id = first_call_id(G711);
    let v = call_tool(
        G711,
        "get_sdp_timeline",
        serde_json::json!({"call_id": call_id}),
    );
    let exchanges = v["exchanges"].as_array().expect("exchanges array");
    assert!(!exchanges.is_empty(), "G.711 call must have SDP exchanges");
    assert!(
        exchanges.iter().any(|e| {
            e["codecs"]
                .as_array()
                .is_some_and(|c| c.iter().any(|x| x == "PCMU"))
        }),
        "at least one exchange must list PCMU; got {exchanges:?}"
    );
}

/// A window covering the capture returns dialogs; one before it returns none.
///
/// Both directions, because a filter that returns everything regardless is
/// indistinguishable from a working one if you only test the positive case.
#[test]
fn search_by_time_actually_filters() {
    let wide = call_tool(
        G711,
        "search_by_time",
        serde_json::json!({"start": "2000-01-01T00:00:00Z"}),
    );
    let n_wide = wide["dialogs"].as_array().map(Vec::len).unwrap_or(0);
    assert!(
        n_wide > 0,
        "a window covering everything must match: {wide}"
    );

    let narrow = call_tool(
        G711,
        "search_by_time",
        serde_json::json!({"start": "1990-01-01T00:00:00Z", "end": "1990-01-02T00:00:00Z"}),
    );
    let n_narrow = narrow["dialogs"].as_array().map(Vec::len).unwrap_or(0);
    assert_eq!(
        n_narrow, 0,
        "a window before the capture must match nothing: {narrow}"
    );
}

/// Comparing a dialog with itself must report no differences.
///
/// The cheapest possible check that the differ actually compares rather than
/// always returning a fixed list.
#[test]
fn compare_dialogs_finds_no_difference_between_a_call_and_itself() {
    let call_id = first_call_id(G711);
    let v = call_tool(
        G711,
        "compare_dialogs",
        serde_json::json!({"call_id_a": call_id, "call_id_b": call_id}),
    );
    let diffs = v["differences"].as_array().expect("differences array");
    assert!(
        diffs.is_empty(),
        "a call compared with itself differs in nothing; got {diffs:?}"
    );
}

/// `capture_status` must report the file it was actually given.
#[test]
fn capture_status_names_the_real_source() {
    let v = call_tool(G711, "capture_status", serde_json::json!({}));
    assert_eq!(v["source"], "file");
    assert!(
        v["name"].as_str().unwrap_or_default().contains("g711"),
        "must name the capture it opened; got {}",
        v["name"]
    );
    assert_eq!(v["unsaved"], false, "a file replay is already on disk");
}

// ── file tools and shutdown ──────────────────────────────────────────
//
// These write to disk and stop processes, so "it returned something" is not
// evidence. Each test asserts the artifact exists and is right, or that the
// refusal actually refused.

// The stdio session harness, `call_tool_with_args` and `ok_payload` moved to
// `tests/support/mcp.rs` when `mcp_open_capture_test.rs` needed the same
// handshake and the same wait-for-the-capture-to-drain loop. Two copies of that
// wait is exactly the shape this file's own header warns about: the race was
// fixed in one of two helpers once already.
#[path = "support/mcp.rs"]
mod support;
use support::{McpSession, call_tool_with_args, ok_payload};

fn tmp_root(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sipnab-mcp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create temp root");
    d
}

/// `export_capture` must produce a real, non-empty pcap.
#[test]
fn export_capture_writes_a_real_pcap() {
    let root = tmp_root("export");
    let msg = call_tool_with_args(
        G711,
        &["--mcp-file-root", root.to_str().unwrap()],
        "export_capture",
        serde_json::json!({"filename": "out.pcap"}),
    );
    let v = ok_payload(&msg);
    assert!(
        v["messages"].as_u64().unwrap_or(0) > 0,
        "exported nothing: {v}"
    );

    let written = root.join("out.pcap");
    assert!(written.is_file(), "no file at {}", written.display());
    let bytes = std::fs::metadata(&written).expect("stat").len();
    assert!(
        bytes > 24,
        "pcap is only {bytes} bytes — header but no packets"
    );

    // Prove the artifact is usable, not merely present: sipnab must read back
    // the dialogs it just wrote. A file that only *looks* like a pcap is the
    // failure this catches.
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-N",
            "-I",
            written.to_str().unwrap(),
            "--json-dialogs",
            "--no-cli-print",
            "--quiet",
        ])
        .output()
        .expect("re-read the export");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let dialogs = stdout
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .count();
    assert!(dialogs > 0, "the exported pcap parsed back to zero dialogs");
}

/// The file tools must refuse a path, not just a `..` sequence.
#[test]
fn file_tools_refuse_anything_that_is_not_a_bare_filename() {
    let root = tmp_root("traversal");
    for bad in [
        "../escape.pcap",
        "/etc/passwd",
        "sub/dir.pcap",
        "..",
        "a/../../b.pcap",
    ] {
        let msg = call_tool_with_args(
            G711,
            &["--mcp-file-root", root.to_str().unwrap()],
            "export_capture",
            serde_json::json!({"filename": bad}),
        );
        let err = msg["error"]["message"].as_str().unwrap_or_default();
        // Assert WHY it was refused, not merely that it was.
        //
        // The first version checked only that an error came back, and passed
        // against a deliberately weakened validator: "/etc/passwd" and
        // "sub/dir.pcap" still errored, but from the filesystem — permission
        // denied, no such directory — after the code had already accepted them
        // and tried the write. On a server running as root, or with a
        // writable subdirectory, the same input would have succeeded. A
        // security test that cannot tell "refused" from "attempted and failed"
        // is not testing the guard.
        assert!(
            err.contains("bare filename"),
            "filename {bad:?} must be refused BY VALIDATION, not by the \
             filesystem happening to reject it; got {err:?}"
        );
    }
    // And nothing escaped onto disk.
    assert!(!std::path::Path::new("/tmp/escape.pcap").exists());
}

/// A file tool must not write over the capture the server is reading.
///
/// `--mcp-file-root` and `-I` routinely name the same directory — that is the
/// natural setup, one folder of captures — so `export_capture` with the input's
/// own filename is one autocompletion away, and an agent choosing a name has no
/// way to know which files are inputs. The export truncated the capture it was
/// reading, and the capture is frequently the only copy.
#[test]
fn export_capture_refuses_to_overwrite_the_capture_being_read() {
    let root = tmp_root("export-over-input");
    let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(G711);
    let input = root.join("incident.pcap");
    std::fs::copy(&src, &input).expect("stage the input inside the file root");
    let before = std::fs::read(&input).expect("read input");

    let msg = call_tool_with_args(
        input.to_str().expect("utf8 path"),
        &["--mcp-file-root", root.to_str().unwrap()],
        "export_capture",
        serde_json::json!({"filename": "incident.pcap"}),
    );

    let err = msg["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err.contains("would overwrite"),
        "export_capture must refuse to write over its own input; got {msg}"
    );
    let after = std::fs::read(&input).expect("the input capture must still exist");
    assert!(
        after == before,
        "the capture being read was modified by export_capture"
    );
}

/// Without `--mcp-file-root` the file tools refuse rather than guessing a path.
#[test]
fn file_tools_are_disabled_without_a_configured_root() {
    let msg = call_tool_with_args(
        G711,
        &[],
        "export_capture",
        serde_json::json!({"filename": "x.pcap"}),
    );
    let err = msg["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err.contains("--mcp-file-root"),
        "the refusal must name the flag that enables it; got {err:?}"
    );
}

/// `shutdown_server` is refused unless the operator opted in.
#[test]
fn shutdown_is_refused_without_the_opt_in_flag() {
    let msg = call_tool_with_args(G711, &[], "shutdown_server", serde_json::json!({}));
    let err = msg["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err.contains("--mcp-allow-shutdown"),
        "refusal must name the flag; got {err:?}"
    );
}

/// Even when permitted, the default call is a dry run that stops nothing.
#[test]
fn shutdown_defaults_to_a_dry_run() {
    let msg = call_tool_with_args(
        G711,
        &["--mcp-allow-shutdown"],
        "shutdown_server",
        serde_json::json!({}),
    );
    let v = ok_payload(&msg);
    assert_eq!(
        v["dry_run"], true,
        "omitting dry_run must NOT stop the server"
    );
    assert_eq!(v["would_stop"], false);
}

/// `list_captures` finds a capture in the root and ignores other files.
#[test]
fn list_captures_lists_only_captures() {
    let root = tmp_root("list");
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(G711),
        root.join("sample.pcap"),
    )
    .expect("copy fixture");
    std::fs::write(root.join("notes.txt"), b"not a capture").expect("write decoy");

    let v = ok_payload(&call_tool_with_args(
        G711,
        &["--mcp-file-root", root.to_str().unwrap()],
        "list_captures",
        serde_json::json!({}),
    ));
    let names: Vec<String> = v["captures"]
        .as_array()
        .expect("captures array")
        .iter()
        .map(|c| c["filename"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(names.contains(&"sample.pcap".to_string()), "got {names:?}");
    assert!(
        !names.contains(&"notes.txt".to_string()),
        "listed a non-capture"
    );
}

/// `rtp_stats` must say whether its MOS is grounded.
///
/// `estimate_mos` returns 4.216 for AMR, AMR-WB, EVS, G.722 *and* for a stream
/// whose codec was never identified — the placeholder arm and the unknown arm
/// are the same number. An agent reading a bare `mos: 4.2` cannot tell a real
/// G.711 estimate from a guess, and will reason about it either way.
///
/// The G.711 fixture must therefore report grounded, and the field must be
/// present at all — its absence is what let the guess pass as a measurement.
#[test]
fn rtp_stats_declares_whether_the_mos_is_grounded() {
    let call_id = first_call_id(G711);
    let v = call_tool(G711, "rtp_stats", serde_json::json!({"call_id": call_id}));
    let streams = v["streams"].as_array().expect("streams array");
    assert!(!streams.is_empty(), "the G.711 fixture has RTP: {v}");

    for s in streams {
        assert!(
            s.get("mos_grounded").is_some(),
            "every stream must declare mos_grounded, or a placeholder MOS is \
             indistinguishable from a measurement: {s}"
        );
        // The flag has to be attached to something. `rtp_stats` builds on the
        // NDJSON stream shape, which carries no `mos` field — so the grounding
        // flag shipped first describing a number that was not in the payload,
        // which is worse than silence: it implies a MOS is present.
        let mos = s["mos"]
            .as_f64()
            .unwrap_or_else(|| panic!("every stream must carry the mos itself: {s}"));
        assert!(
            (1.0..=4.5).contains(&mos),
            "a MOS outside 1.0..=4.5 is not on the G.107 scale: {mos}"
        );
    }
    // PCMU has a published ITU-T G.113 impairment value.
    assert!(
        streams.iter().any(|s| s["mos_grounded"] == true),
        "the PCMU stream must report a GROUNDED mos: {streams:?}"
    );
}

// ── bounded answers: the count, the flag, and the way to the rest ────
//
// A truncated list that does not say it was truncated is the worst failure on
// this surface, because the consumer is a language model. An agent asked "how
// many calls failed?" counts the rows it received and answers with confidence.
// `list_dialogs` returned 50 of 2311 dialogs on a production capture as a bare
// JSON array — no total, no flag, and no cursor, so the other 2261 were not
// merely unshown, they were unreachable at any `limit`.

/// `list_dialogs` must report the size of the answer it did not send.
#[test]
fn list_dialogs_reports_the_total_behind_a_truncated_page() {
    let v = call_tool(BRANCH, "list_dialogs", serde_json::json!({"limit": 5}));

    let dialogs = v["dialogs"]
        .as_array()
        .unwrap_or_else(|| panic!("list_dialogs must return an object with `dialogs`: {v}"));
    assert_eq!(dialogs.len(), 5, "limit 5 must return 5 rows: {v}");
    assert_eq!(
        v["returned"], 5,
        "`returned` must match the row count so an agent need not count: {v}"
    );
    assert_eq!(
        v["total_matched"], 1334,
        "this fixture holds 1334 dialogs and the response must say so — an \
         agent that counts 5 rows and answers '5 calls' is the defect: {v}"
    );
    assert_eq!(v["truncated"], true, "5 of 1334 is a truncated answer: {v}");
    assert!(
        v["next_cursor"].is_string(),
        "a truncated page must carry the cursor that reaches the rest: {v}"
    );
}

/// An unbounded-enough page reports `truncated: false` and no cursor.
///
/// The negative half. A tool hard-coding `truncated: true` would pass the test
/// above and be just as useless.
#[test]
fn list_dialogs_says_so_when_the_page_is_the_whole_answer() {
    let v = call_tool(
        BRANCH,
        "list_dialogs",
        serde_json::json!({"filter": "state == 'Failed' AND msg_count > 5", "limit": 1000}),
    );
    let n = v["dialogs"].as_array().map(Vec::len).unwrap_or(0);
    assert_eq!(n, 6, "6 dialogs in this fixture match: {v}");
    assert_eq!(v["total_matched"], n, "every match fitted in the page: {v}");
    assert_eq!(v["truncated"], false, "nothing was withheld: {v}");
    assert_eq!(
        v["next_cursor"],
        serde_json::Value::Null,
        "a complete answer has nothing to continue from: {v}"
    );
}

/// Paging with the cursor must reach every dialog exactly once.
///
/// The point of the cursor, and the assertion that distinguishes it from a
/// `limit` that merely shows more: the union of the pages is the store, with no
/// dialog dropped at a page boundary and none returned twice.
#[test]
fn list_dialogs_cursor_reaches_every_dialog_exactly_once() {
    let mut session = McpSession::start(BRANCH, &[]);
    let mut seen: Vec<String> = Vec::new();
    let mut cursor = serde_json::Value::Null;
    let mut pages = 0;

    loop {
        let mut args = serde_json::json!({"limit": 300});
        if let Some(c) = cursor.as_str() {
            args["cursor"] = serde_json::json!(c);
        }
        let v = session.ok("list_dialogs", args);
        for d in v["dialogs"].as_array().expect("dialogs array") {
            seen.push(d["call_id"].as_str().expect("call_id").to_string());
        }
        pages += 1;
        assert!(pages < 20, "paging did not terminate after {pages} pages");
        cursor = v["next_cursor"].clone();
        if cursor.is_null() {
            assert_eq!(v["truncated"], false, "the last page is not truncated: {v}");
            break;
        }
    }

    assert!(
        pages > 1,
        "limit 300 over 1334 dialogs must take several pages"
    );
    let unique: std::collections::BTreeSet<&String> = seen.iter().collect();
    assert_eq!(
        unique.len(),
        seen.len(),
        "a dialog came back on two pages: {} rows, {} distinct",
        seen.len(),
        unique.len()
    );
    assert_eq!(
        seen.len(),
        1334,
        "paging must reach all 1334 dialogs; got {}. A dialog lost at a page \
         boundary is exactly what a bare-timestamp cursor does to a tie group",
        seen.len()
    );
}

/// A cursor past the end returns an empty final page, not an error.
#[test]
fn list_dialogs_cursor_past_the_end_returns_an_empty_page() {
    let v = call_tool(
        BRANCH,
        "list_dialogs",
        serde_json::json!({"cursor": "2099-01-01T00:00:00Z|zzzz"}),
    );
    assert_eq!(v["dialogs"].as_array().map(Vec::len), Some(0));
    assert_eq!(v["truncated"], false);
    assert_eq!(v["next_cursor"], serde_json::Value::Null);
    assert_eq!(
        v["total_matched"], 1334,
        "the total describes the store, not the page — it must not go to zero \
         because the caller paged past the end: {v}"
    );
}

/// A malformed cursor is refused by name rather than treated as absent.
#[test]
fn list_dialogs_refuses_a_cursor_that_is_not_a_timestamp() {
    let msg = call_tool_with_args(
        BRANCH,
        &[],
        "list_dialogs",
        serde_json::json!({"cursor": "yesterday|abc"}),
    );
    let err = msg["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err.contains("RFC 3339"),
        "the refusal must name the format it wanted; got {err:?}. Silently \
         restarting from the beginning would loop an agent forever"
    );
}

/// `find_problems` carries the same total, flag and cursor as `list_dialogs`.
#[test]
fn find_problems_reports_the_total_behind_a_truncated_page() {
    let v = call_tool(BRANCH, "find_problems", serde_json::json!({"limit": 4}));
    assert_eq!(v["dialogs"].as_array().map(Vec::len), Some(4), "{v}");
    assert_eq!(
        v["total_matched"], 127,
        "127 dialogs in this fixture match the 'problems' alias, and an agent \
         asked how many calls failed must be able to say 127: {v}"
    );
    assert_eq!(v["truncated"], true, "{v}");
    assert!(v["next_cursor"].is_string(), "{v}");
}

// ── filters where the triage actually starts ─────────────────────────

/// `find_problems` must accept a filter, and it must narrow rather than widen.
///
/// Both counts are asserted. A `filter` parameter that parses and is then
/// ignored returns the unfiltered 127 and looks like it worked.
#[test]
fn find_problems_filter_narrows_the_matching_kinds() {
    let mut session = McpSession::start(BRANCH, &[]);

    let all = session.ok("find_problems", serde_json::json!({"limit": 1000}));
    assert_eq!(all["total_matched"], 127, "unfiltered baseline: {all}");

    let narrowed = session.ok(
        "find_problems",
        serde_json::json!({"filter": "msg_count > 5", "limit": 1000}),
    );
    assert_eq!(
        narrowed["total_matched"], 6,
        "6 of the 127 problem dialogs carry more than 5 messages; a `filter` \
         that parses and is then dropped reports all 127: {narrowed}"
    );

    // And the rows really satisfy both halves, not just the alias.
    for d in narrowed["dialogs"].as_array().expect("dialogs") {
        assert_eq!(d["state"], "Failed", "the alias still applies: {d}");
        assert!(
            d["msg_count"].as_u64().unwrap_or(0) > 5,
            "the filter still applies: {d}"
        );
    }
}

/// An unparseable filter on `find_problems` is refused, not ignored.
#[test]
fn find_problems_refuses_an_unparseable_filter() {
    let msg = call_tool_with_args(
        BRANCH,
        &[],
        "find_problems",
        serde_json::json!({"filter": "msg_count >>>> "}),
    );
    let err = msg["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err.contains("filter"),
        "the refusal must name the filter; got {err:?}"
    );
}

/// `search_by_time` must accept a filter so a window and a symptom are one call.
#[test]
fn search_by_time_filter_narrows_the_window() {
    let mut session = McpSession::start(BRANCH, &[]);
    let window = serde_json::json!({
        "start": "2016-11-17T21:52:35Z", "end": "2016-11-17T21:53:00Z", "limit": 1000
    });

    let all = session.ok("search_by_time", window.clone());
    assert_eq!(all["total_matched"], 247, "unfiltered window: {all}");

    let mut filtered = window.clone();
    filtered["filter"] = serde_json::json!("state == 'Failed'");
    let v = session.ok("search_by_time", filtered);
    assert_eq!(
        v["total_matched"], 16,
        "16 of the 247 dialogs in this window failed; 247 here means the \
         filter was accepted and discarded: {v}"
    );
    for d in v["dialogs"].as_array().expect("dialogs") {
        assert_eq!(d["state"], "Failed", "{d}");
    }
}

/// `search_by_time` also accepts the alias vocabulary, not only raw DSL.
#[test]
fn search_by_time_filter_accepts_a_diagnostic_alias() {
    let v = call_tool(
        BRANCH,
        "search_by_time",
        serde_json::json!({
            "start": "2016-11-17T21:52:35Z", "end": "2016-11-17T21:53:00Z",
            "filter": "problems", "limit": 1000
        }),
    );
    assert_eq!(
        v["total_matched"], 16,
        "the 'problems' alias must expand here exactly as it does for \
         list_dialogs: {v}"
    );
}

// ── capture-wide RTP, and the MOS it refuses to guess with ───────────

/// Capture-wide `rtp_stats` reaches streams no Call-ID can name.
///
/// This fixture has four RTP streams and zero dialogs. `rtp_stats { call_id }`
/// cannot return one of them — there is no Call-ID to pass. An orphaned stream
/// is not an edge case either; it is what a one-way-audio or NAT problem looks
/// like from the media side.
#[test]
fn rtp_stats_capture_wide_reaches_streams_with_no_dialog() {
    let v = call_tool(CODECS, "rtp_stats", serde_json::json!({}));
    let streams = v["streams"].as_array().expect("streams array");
    assert_eq!(
        streams.len(),
        4,
        "this capture carries 4 streams and none of them belongs to a \
         dialog: {v}"
    );
    assert_eq!(v["total_matched"], 4, "{v}");
    assert_eq!(v["truncated"], false, "{v}");
    for s in streams {
        assert!(
            s.get("mos_grounded").is_some(),
            "every row must declare whether its MOS means anything: {s}"
        );
        assert!(s["ssrc"].is_string(), "{s}");
    }
}

/// A MOS threshold must not select on a placeholder.
///
/// `estimate_mos` returns the same number for G.722 as for a stream whose codec
/// was never identified, because ITU-T G.113 publishes no impairment value for
/// it. Thresholding that number is picking calls to investigate out of a guess.
/// So a MOS bound excludes ungrounded streams and REPORTS HOW MANY it excluded:
/// "2 bad streams" and "2 bad streams plus 2 I cannot score" are different
/// answers, and only one of them is honest.
#[test]
fn rtp_stats_capture_wide_excludes_ungrounded_streams_from_a_mos_threshold() {
    let v = call_tool(CODECS, "rtp_stats", serde_json::json!({"max_mos": 4.5}));
    let streams = v["streams"].as_array().expect("streams array");

    assert_eq!(
        streams.len(),
        2,
        "only the two PCMU streams can be scored against a MOS bound; the two \
         G722 streams score 4.2 from a placeholder and must not be selected \
         by it: {v}"
    );
    for s in streams {
        assert_eq!(
            s["mos_grounded"], true,
            "a MOS bound must return only grounded rows: {s}"
        );
        assert_eq!(s["codec"], "PCMU", "{s}");
        assert!(
            s["mos"].as_f64().unwrap_or(9.9) < 4.5,
            "the bound must actually apply: {s}"
        );
    }
    assert_eq!(
        v["ungrounded_excluded"], 2,
        "the two G722 streams were skipped and the count must say so — an \
         agent told '2 streams' and not told '2 more could not be scored' \
         reports a clean capture: {v}"
    );
    assert_eq!(
        v["total_matched"], 2,
        "the total counts what the bound could judge: {v}"
    );
}

/// Without a MOS bound nothing is excluded and the count says zero.
///
/// The other half of the pair. A tool hard-coding `ungrounded_excluded` would
/// pass the test above.
#[test]
fn rtp_stats_capture_wide_excludes_nothing_without_a_mos_bound() {
    let v = call_tool(CODECS, "rtp_stats", serde_json::json!({}));
    assert_eq!(
        v["ungrounded_excluded"], 0,
        "an unbounded query judges no MOS, so it withholds nothing: {v}"
    );
    let codecs: Vec<&str> = v["streams"]
        .as_array()
        .expect("streams")
        .iter()
        .filter_map(|s| s["codec"].as_str())
        .collect();
    assert!(
        codecs.contains(&"G722"),
        "the ungrounded streams are still listed when nothing thresholds \
         them; got {codecs:?}"
    );
}

/// A MOS bound alongside a Call-ID is refused rather than quietly dropped.
#[test]
fn rtp_stats_refuses_a_mos_bound_on_a_single_call() {
    let call_id = first_call_id(G711);
    let msg = call_tool_with_args(
        G711,
        &[],
        "rtp_stats",
        serde_json::json!({"call_id": call_id, "max_mos": 4.0}),
    );
    let err = msg["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err.contains("call_id"),
        "the refusal must name the conflicting argument; got {err:?}"
    );
}

/// Capture-wide `rtp_stats` pages, and the pages cover every stream once.
#[test]
fn rtp_stats_capture_wide_cursor_reaches_every_stream_exactly_once() {
    let mut session = McpSession::start(CODECS, &[]);
    let mut seen: Vec<String> = Vec::new();
    let mut cursor = serde_json::Value::Null;

    for page in 0..10 {
        let mut args = serde_json::json!({"limit": 1});
        if let Some(c) = cursor.as_str() {
            args["cursor"] = serde_json::json!(c);
        }
        let v = session.ok("rtp_stats", args);
        assert_eq!(v["total_matched"], 4, "page {page}: {v}");
        for s in v["streams"].as_array().expect("streams") {
            seen.push(format!(
                "{}|{}|{}",
                s["ssrc"].as_str().unwrap_or_default(),
                s["src"].as_str().unwrap_or_default(),
                s["dst"].as_str().unwrap_or_default()
            ));
        }
        cursor = v["next_cursor"].clone();
        if cursor.is_null() {
            break;
        }
    }

    let unique: std::collections::BTreeSet<&String> = seen.iter().collect();
    assert_eq!(
        unique.len(),
        4,
        "paging must reach all 4 streams; got {seen:?}"
    );
    assert_eq!(seen.len(), 4, "a stream came back twice: {seen:?}");
}

/// The single-call shape is unchanged: `{ call_id, streams, diagnosis }`.
///
/// Adding a capture-wide mode must not move the per-call answer, which the
/// documented examples and every existing client read.
#[test]
fn rtp_stats_single_call_shape_is_untouched() {
    let call_id = first_call_id(G711);
    let v = call_tool(G711, "rtp_stats", serde_json::json!({"call_id": call_id}));
    assert_eq!(v["call_id"], call_id, "{v}");
    assert!(v["streams"].is_array(), "{v}");
    assert!(
        v["diagnosis"].is_object(),
        "the per-call media diagnosis must survive: {v}"
    );
    assert!(
        v.get("total_matched").is_none(),
        "the single-call response is not a page and must not grow page \
         fields: {v}"
    );
}

/// The placeholder note must read as a sentence, not a column of spaces.
///
/// The note is written into a JSON string an agent reads verbatim. It shipped
/// with a 38-space run in the middle from a wrapped string literal, which is
/// the kind of thing a model quotes back to an operator.
#[test]
fn the_ungrounded_mos_note_has_no_stray_whitespace() {
    let v = call_tool(CODECS, "rtp_stats", serde_json::json!({}));
    let note = v["streams"]
        .as_array()
        .expect("streams")
        .iter()
        .find_map(|s| s["mos_note"].as_str())
        .expect("a G722 stream must carry the placeholder note");
    assert!(
        !note.contains("  "),
        "the note contains a run of spaces and reaches an operator that way: \
         {note:?}"
    );
}
