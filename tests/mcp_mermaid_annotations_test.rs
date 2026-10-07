// SPDX-License-Identifier: MIT OR Apache-2.0

//! MCP's Mermaid ladder carries what the ladder knows, not bare arrows.
//!
//! The TUI's export annotated each arrow with its time offset, the post-dial
//! delay and SDP changes; `render_ladder` with `format: "mermaid"` drew the
//! same call as bare arrows, so an agent handed a diagram of a problem call
//! got a picture of the protocol rather than of the call.

#![cfg(all(feature = "native", feature = "mcp"))]

#[path = "support/mcp.rs"]
mod mcp;

use mcp::McpSession;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn text(msg: &serde_json::Value) -> String {
    msg["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text payload: {msg}"))
        .to_string()
}

#[test]
fn the_mermaid_ladder_notes_offsets_and_post_dial_delay() {
    let mut session = McpSession::start_or_panic(&fixture("sip_call.pcap"), &["--no-config"]);
    let list: serde_json::Value = serde_json::from_str(&text(
        &session.call_or_panic("list_dialogs", serde_json::json!({})),
    ))
    .expect("list_dialogs JSON");
    let call_id = list["dialogs"][0]["call_id"]
        .as_str()
        .expect("one dialog")
        .to_string();
    let diagram = text(&session.call_or_panic(
        "render_ladder",
        serde_json::json!({ "call_id": call_id, "format": "mermaid" }),
    ));
    assert!(diagram.contains("sequenceDiagram"), "{diagram}");
    assert!(
        diagram.contains("Note right of"),
        "no notes at all:\n{diagram}"
    );
    assert!(
        diagram.contains("+0.000s"),
        "no offset on the INVITE:\n{diagram}"
    );
    assert!(
        diagram.contains("+0.500s \u{b7} PDD 500ms"),
        "the 180 must carry its offset and the post-dial delay:\n{diagram}"
    );
}
