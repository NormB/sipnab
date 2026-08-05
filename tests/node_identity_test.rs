// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--node-name` end to end, against the real binary.
//!
//! Unit tests cover the clipping and the fact that a node survives a capture
//! rotation. What they cannot cover is the part that decides whether the
//! feature works in a deployment: that the flag on the command line is what
//! lands in `capture_identity.node` on the wire.
//!
//! That path runs CLI parse -> `plan()` -> a process-global `OnceLock` ->
//! `CaptureIdentity::etag()`, and the `OnceLock` is the risk: the FIRST writer
//! wins, so a `set_node_name` call sequenced after anything that mints an
//! identity would be silently ignored and every answer would carry the hostname
//! while the operator's command line said otherwise. A unit test cannot see
//! that ordering, because it does not run `plan()`.
//!
//! `#![cfg(feature = "mcp")]` because reading the value back needs a tool call.

#![cfg(feature = "mcp")]

#[path = "support/mcp.rs"]
mod support;

use support::{McpSession, ok_payload};

const CAPTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// The flag reaches the wire, on every response rather than a special one.
#[test]
fn the_node_name_flag_lands_in_capture_identity() {
    let mut session = McpSession::start(CAPTURE, &["--node-name", "sbc-edge-1"]);

    for tool in ["stats", "capture_status"] {
        let v = ok_payload(&session.call(tool, serde_json::json!({})));
        assert_eq!(
            v["capture_identity"]["node"], "sbc-edge-1",
            "{tool} must say which box answered it"
        );
    }
}

/// Without the flag a node is still reported — never blank.
///
/// A missing node is worse than a hostname: an agent correlating across servers
/// would group every unnamed node together as one box.
#[test]
fn a_node_is_always_reported_even_with_no_flag() {
    let mut session = McpSession::start(CAPTURE, &[]);
    let v = ok_payload(&session.call("stats", serde_json::json!({})));
    let node = v["capture_identity"]["node"].as_str().unwrap_or_default();
    assert!(
        !node.is_empty(),
        "a blank node would merge every unnamed server into one"
    );
}

/// Two servers given different names stay distinguishable — the whole point.
#[test]
fn two_servers_with_different_names_are_told_apart() {
    let mut a = McpSession::start(CAPTURE, &["--node-name", "pbx-1"]);
    let mut b = McpSession::start(CAPTURE, &["--node-name", "pbx-2"]);

    let va = ok_payload(&a.call("stats", serde_json::json!({})));
    let vb = ok_payload(&b.call("stats", serde_json::json!({})));

    assert_eq!(va["capture_identity"]["node"], "pbx-1");
    assert_eq!(vb["capture_identity"]["node"], "pbx-2");
    assert_ne!(
        va["capture_identity"]["node"], vb["capture_identity"]["node"],
        "an agent must be able to attribute a fact to the box that saw it"
    );
}
