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
fn call_tool(pcap: &str, tool: &str, args: serde_json::Value) -> serde_json::Value {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(manifest)
        .args(["--mcp", "-N", "-I", pcap, "--quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sipnab --mcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for line in [
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                           "clientInfo": {"name": "t", "version": "1"}}
            }),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": tool, "arguments": args}
            }),
        ] {
            writeln!(stdin, "{line}").expect("write request");
        }
        stdin.flush().expect("flush");
    }

    let stdout = child.stdout.take().expect("stdout");
    let mut result = None;
    for line in BufReader::new(stdout).lines() {
        let line = line.expect("read line");
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if msg["id"] == 2 {
            let text = msg["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or_else(|| panic!("tool {tool} returned no text: {msg}"));
            result = Some(serde_json::from_str(text).expect("tool result is JSON"));
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    result.unwrap_or_else(|| panic!("tool {tool} produced no result"))
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

/// A capture with no SDP must say so, not claim the far end failed to answer.
///
/// `sip-488-codec-reject.pcapng` carries no `m=audio` line at all. Reporting
/// "no_answer" would send an operator hunting a reply that was never expected.
#[test]
fn codec_negotiation_distinguishes_absent_sdp_from_an_unanswered_offer() {
    const NO_SDP: &str = "tests/pcap-samples/sip-488-codec-reject.pcapng";
    let call_id = first_call_id(NO_SDP);
    let v = call_tool(
        NO_SDP,
        "check_codec_negotiation",
        serde_json::json!({"call_id": call_id}),
    );
    let result = v["result"].as_str().unwrap_or_default();
    assert!(
        result == "no_sdp_in_capture" || result == "sdp_present_but_no_codecs",
        "a capture with no m=audio must not report 'no_answer'; got {result:?}"
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
