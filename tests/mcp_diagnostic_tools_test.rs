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

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

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
        serde_json::json!({"call_id": "0076da05-6f74-4bd0-8351-179edaca8596"}),
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
        serde_json::json!({"call_id": "NA4y5nr9Jk"}),
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

/// The signalling/media split is the first triage decision, so it must be right.
///
/// This capture has clean signalling (200 OK) and one-way audio, so the verdict
/// must be "media". Calling it "signalling" would send an operator to the SIP
/// side of a problem that is entirely in RTP.
#[test]
fn triage_calls_one_way_audio_a_media_problem() {
    let call_id = first_call_id(G711);
    let v = call_tool(G711, "triage_call", serde_json::json!({"call_id": call_id}));

    assert_eq!(
        v["verdict"], "media",
        "clean signalling with one-way audio is a MEDIA problem: {v}"
    );
    assert_eq!(v["signalling"]["problem"], false);
    assert_eq!(v["media"]["problem"], true);
    assert_eq!(v["media"]["one_way_audio"], true);
}

/// A failed call with no media must land on the signalling side.
#[test]
fn triage_calls_a_failed_call_a_signalling_problem() {
    const FAIL: &str = "tests/pcap-samples/sip-auth-failure.pcapng";
    let call_id = first_call_id(FAIL);
    let v = call_tool(FAIL, "triage_call", serde_json::json!({"call_id": call_id}));
    assert_eq!(
        v["verdict"], "signalling",
        "a 403 with no streams is a signalling problem: {v}"
    );
    assert_eq!(v["signalling"]["problem"], true);
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
// evidence. Each test asserts the artefact exists and is right, or that the
// refusal actually refused.

/// Call a tool with extra CLI args, waiting for the capture to load first.
///
/// Returns the raw JSON-RPC message so callers can assert on errors as well as
/// results.
///
/// The wait matters: without it these tests raced the pcap reader and passed on
/// Linux by luck, while macOS saw an empty store and reported "no messages are
/// held", "call_id not found" and an empty dialog list. A test that wins a race
/// on one platform is an unobserved failure, not a pass. Polling
/// `capture_status` until the file source drains is exactly what that tool is
/// for.
fn call_tool_with_args(
    pcap: &str,
    extra: &[&str],
    tool: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let mut argv: Vec<&str> = vec!["--mcp", "-N", "-I", pcap, "--quiet"];
    argv.extend_from_slice(extra);
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(manifest)
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sipnab --mcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        writeln!(
            stdin,
            "{}",
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                           "clientInfo": {"name": "t", "version": "1"}}
            })
        )
        .expect("write initialize");
        writeln!(
            stdin,
            "{}",
            serde_json::json!({
                "jsonrpc": "2.0", "method": "notifications/initialized"
            })
        )
        .expect("write initialized");
        stdin.flush().expect("flush");
    }

    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);

    // Bounded, so a genuine hang fails the test rather than running forever.
    const MAX_POLLS: usize = 200;
    let mut loaded = false;
    for poll in 0..MAX_POLLS {
        {
            let stdin = child.stdin.as_mut().expect("stdin");
            writeln!(
                stdin,
                "{}",
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 1000 + poll, "method": "tools/call",
                    "params": {"name": "capture_status", "arguments": {}}
                })
            )
            .expect("write capture_status");
            stdin.flush().expect("flush");
        }
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                panic!("sipnab closed stdout while waiting for capture_status");
            }
            let Ok(msg) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                continue;
            };
            if msg["id"] == serde_json::json!(1000 + poll) {
                let text = msg["result"]["content"][0]["text"].as_str().unwrap_or("{}");
                let v: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
                loaded = v["source_exhausted"] == true;
                break;
            }
        }
        if loaded {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(loaded, "capture never finished loading for {pcap}");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        writeln!(
            stdin,
            "{}",
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": tool, "arguments": args}
            })
        )
        .expect("write tool call");
        stdin.flush().expect("flush");
    }

    let mut out = None;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
            continue;
        };
        if msg["id"] == 2 {
            out = Some(msg);
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    out.unwrap_or_else(|| panic!("tool {tool} produced no response"))
}

/// Unwrap a successful tool result to its parsed JSON payload.
fn ok_payload(msg: &serde_json::Value) -> serde_json::Value {
    let text = msg["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("expected success, got {msg}"));
    serde_json::from_str(text).expect("payload is JSON")
}

fn tmp_root(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sipnab-mcp-{name}"));
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

    // Prove the artefact is usable, not merely present: sipnab must read back
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
    }
    // PCMU has a published ITU-T G.113 impairment value.
    assert!(
        streams.iter().any(|s| s["mos_grounded"] == true),
        "the PCMU stream must report a GROUNDED mos: {streams:?}"
    );
}
