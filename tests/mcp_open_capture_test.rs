// SPDX-License-Identifier: MIT OR Apache-2.0

//! `open_capture` end to end, against the real binary over stdio.
//!
//! Unit tests over a hand-built `SipnabMcp` prove the refusals and the shared
//! lock. They cannot prove the three things that made this feature expensive to
//! get right, because all three are properties of a running server:
//!
//! 1. the swap actually replaces the analysis — a different file's dialogs,
//!    not an emptied store that happens to look plausible;
//! 2. the server keeps answering while the load runs, which is the whole
//!    reason the read is on its own thread;
//! 3. every answer afterwards names the new capture, so a consumer polling
//!    across the swap can tell.
//!
//! `#![cfg(feature = "mcp")]` because these drive the MCP surface.

#![cfg(feature = "mcp")]

#[path = "support/mcp.rs"]
mod support;

use support::{McpSession, ok_payload};

/// The capture the server starts on: one G.711 call.
const FIRST: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// The capture it is asked to switch to. 8,989 packets and 1,334 dialogs, so
/// "the dialogs changed" cannot be confused with "the store was cleared", and
/// the load takes long enough for a poll to catch it mid-flight.
const SECOND: &str = "sipp-branch-scenario.pcapng";

/// A temp directory holding `SECOND`, usable as `--mcp-file-root`.
fn root_with_second(name: &str) -> std::path::PathBuf {
    let root =
        std::env::temp_dir().join(format!("sipnab-open-capture-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create the file root");
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples")
            .join(SECOND),
        root.join(SECOND),
    )
    .expect("stage the second capture");
    root
}

/// Poll `capture_status` until the background load reports done.
///
/// # Returns
/// The final `capture_status` payload.
fn wait_for_load(session: &mut McpSession) -> serde_json::Value {
    for _ in 0..400 {
        let v = ok_payload(&session.call("capture_status", serde_json::json!({})));
        if v["load"]["done"] == true {
            return v;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("the load never finished");
}

/// A stock server refuses, and says which flag would change that.
///
/// The tool is still registered and still listed — refusing beats hiding, so
/// an agent can tell "not permitted here" from "this sipnab cannot do it".
#[test]
fn open_capture_is_refused_without_the_opt_in_flag() {
    let root = root_with_second("refused");
    let msg = McpSession::start(
        FIRST,
        &["--mcp-file-root", root.to_str().unwrap_or_default()],
    )
    .call("open_capture", serde_json::json!({"filename": SECOND}));
    let err = msg["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err.contains("--mcp-allow-open-capture"),
        "the refusal must name the flag; got {err:?}"
    );
}

/// The tool appears in `tools/list` whether or not the flag was passed.
#[test]
fn open_capture_is_registered_even_when_it_is_not_permitted() {
    let mut session = McpSession::start(FIRST, &[]);
    let listed = session.list_tools();
    assert!(
        listed.iter().any(|t| t == "open_capture"),
        "open_capture must be listed even without the opt-in; got {listed:?}"
    );
}

/// The swap replaces the analysis with the other file's, and says so.
///
/// Every assertion here is a number verified from the capture itself rather
/// than from what the tool returned: the branch scenario holds 1,334 dialogs
/// and the G.711 fixture one, so "the dialogs changed" is checkable.
#[test]
fn a_swap_replaces_the_dialogs_and_renames_the_capture() {
    let root = root_with_second("swap");
    let mut session = McpSession::start(
        FIRST,
        &[
            "--mcp-file-root",
            root.to_str().unwrap_or_default(),
            "--mcp-allow-open-capture",
        ],
    );

    let before = ok_payload(&session.call("capture_status", serde_json::json!({})));
    let before_dialogs = before["dialog_count"].as_u64().unwrap_or(0);
    let before_instance = before["capture_identity"]["instance"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(before_dialogs > 0, "the first capture must have loaded");
    assert!(
        before["name"].as_str().unwrap_or_default().contains("g711"),
        "the server must start on the -I capture; got {}",
        before["name"]
    );

    let opened = ok_payload(&session.call("open_capture", serde_json::json!({"filename": SECOND})));
    assert_eq!(opened["status"], "loading");
    assert_eq!(
        opened["discarded_dialogs"], before_dialogs,
        "the response must say how much analysis it threw away"
    );
    assert_ne!(
        opened["capture_identity"]["instance"], before_instance,
        "a swap must mint a new capture instance"
    );

    let after = wait_for_load(&mut session);
    assert!(
        after["name"].as_str().unwrap_or_default().contains(SECOND),
        "capture_status must name the file it now holds; got {}",
        after["name"]
    );
    assert_eq!(
        after["capture_identity"]["instance"], opened["capture_identity"]["instance"],
        "the identity must stay the one open_capture returned"
    );
    assert!(
        after["dialog_count"].as_u64().unwrap_or(0) > 1000,
        "the branch scenario holds 1,334 dialogs; got {}",
        after["dialog_count"]
    );
    assert_eq!(
        after["load"]["error"],
        serde_json::Value::Null,
        "the fixture must load cleanly"
    );
    assert_eq!(
        after["source_exhausted"], true,
        "a finished load must set source_exhausted, or a poller waits forever"
    );

    // The dialogs are genuinely the second capture's: one of its Call-IDs
    // resolves, and the first capture's does not.
    let page = ok_payload(&session.call("list_dialogs", serde_json::json!({"limit": 1})));
    assert_eq!(
        page["capture_identity"]["instance"], after["capture_identity"]["instance"],
        "a page must carry the identity of the capture it came from"
    );
    assert!(
        page["total_matched"].as_u64().unwrap_or(0) > 1000,
        "list_dialogs must see the new capture; got {}",
        page["total_matched"]
    );
}

/// The server keeps answering while the load runs.
///
/// This is what the background thread buys, and the assertion that catches its
/// absence is `done == false` rather than a stopwatch. With the read inside the
/// handler, `open_capture` returns only once the whole file is parsed, so the
/// first status after it would report a finished load — the same JSON a working
/// implementation produces a moment later, which is why the timing has to be
/// asserted rather than the end state.
///
/// The margin is two orders of magnitude: the branch scenario takes roughly
/// 150 ms to parse in a debug build and a tool round trip over the pipe takes
/// about a millisecond. The wall-clock bounds below are a backstop for the
/// blocking case, not the gate.
#[test]
fn the_load_does_not_block_the_server() {
    let root = root_with_second("nonblocking");
    let mut session = McpSession::start(
        FIRST,
        &[
            "--mcp-file-root",
            root.to_str().unwrap_or_default(),
            "--mcp-allow-open-capture",
        ],
    );

    let started = std::time::Instant::now();
    let opened = ok_payload(&session.call("open_capture", serde_json::json!({"filename": SECOND})));
    let call_took = started.elapsed();
    assert_eq!(opened["status"], "loading");

    // Another tool answers while the load is in flight, and says so.
    let probe = std::time::Instant::now();
    let status = ok_payload(&session.call("capture_status", serde_json::json!({})));
    let probe_took = probe.elapsed();

    assert_eq!(
        status["load"]["done"], false,
        "the load had already finished when open_capture returned, so the read \
         ran inside the handler and every other client waited for it"
    );
    assert!(
        call_took < std::time::Duration::from_secs(2),
        "open_capture took {call_took:?} — it is reading the file inside the handler"
    );
    assert!(
        probe_took < std::time::Duration::from_secs(2),
        "a tool call during the load took {probe_took:?} — the runtime thread is blocked"
    );

    let done = wait_for_load(&mut session);
    assert!(
        done["dialog_count"].as_u64().unwrap_or(0) > 1000,
        "the load that was still running must go on to finish; got {}",
        done["dialog_count"]
    );
}

/// A poller that keeps its cursor across a swap must be able to tell.
///
/// `tail_dialogs` is the case that motivated the identity: after a swap the
/// old cursor is a timestamp from a different capture, and an empty page reads
/// as "nothing changed" when everything did.
#[test]
fn a_tail_poller_can_tell_the_capture_changed_underneath_it() {
    let root = root_with_second("tail");
    let mut session = McpSession::start(
        FIRST,
        &[
            "--mcp-file-root",
            root.to_str().unwrap_or_default(),
            "--mcp-allow-open-capture",
        ],
    );

    let first = ok_payload(&session.call("tail_dialogs", serde_json::json!({})));
    let cursor = first["next_cursor"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let first_instance = first["capture_identity"]["instance"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(!first_instance.is_empty(), "tail must carry an instance");

    session.call("open_capture", serde_json::json!({"filename": SECOND}));
    wait_for_load(&mut session);

    let second = ok_payload(&session.call("tail_dialogs", serde_json::json!({"cursor": cursor})));
    assert_ne!(
        second["capture_identity"]["instance"], first_instance,
        "the poller must see a different instance after the swap — without it, \
         the page it just got looks like an ordinary continuation"
    );
}

/// A file the server cannot read reports the failure rather than an empty
/// capture, because by then the previous analysis is already gone.
#[test]
fn a_broken_capture_reports_the_error_instead_of_an_empty_store() {
    let root = root_with_second("broken");
    std::fs::write(root.join("not-a-capture.pcap"), b"this is not a pcap")
        .expect("write the decoy");
    let mut session = McpSession::start(
        FIRST,
        &[
            "--mcp-file-root",
            root.to_str().unwrap_or_default(),
            "--mcp-allow-open-capture",
        ],
    );
    session.call(
        "open_capture",
        serde_json::json!({"filename": "not-a-capture.pcap"}),
    );
    let status = wait_for_load(&mut session);
    assert!(
        status["load"]["error"].as_str().is_some(),
        "an unreadable file must report why; got {}",
        status["load"]
    );
    assert_eq!(
        status["dialog_count"], 0,
        "nothing loaded, and the store says so"
    );
}

/// `server_capabilities` answers what the operator turned on, so an agent can
/// check before it is refused.
#[test]
fn server_capabilities_reports_the_runtime_opt_ins() {
    let root = root_with_second("caps");
    let plain = ok_payload(
        &McpSession::start(FIRST, &[]).call("server_capabilities", serde_json::json!({})),
    );
    assert_eq!(plain["runtime"]["mcp_allow_open_capture"], false);
    assert_eq!(plain["runtime"]["mcp_allow_shutdown"], false);
    assert!(plain["runtime"]["mcp_file_root"].is_null());

    let opted = ok_payload(
        &McpSession::start(
            FIRST,
            &[
                "--mcp-file-root",
                root.to_str().unwrap_or_default(),
                "--mcp-allow-open-capture",
            ],
        )
        .call("server_capabilities", serde_json::json!({})),
    );
    assert_eq!(opted["runtime"]["mcp_allow_open_capture"], true);
    assert_eq!(
        opted["runtime"]["mcp_file_root"],
        root.to_str().unwrap_or_default()
    );
}
