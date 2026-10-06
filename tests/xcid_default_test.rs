// SPDX-License-Identifier: MIT OR Apache-2.0

//! The shipped run follows no correlation header until one is configured.
//!
//! `X-Call-ID` used to be a built-in default, and four code comments kept
//! saying so after it stopped being one (`config.rs`, `parallel.rs`, two in
//! `dialog_store.rs`). The store-level unit test pins the `DialogStore`
//! default; this pins what the comments actually describe, the binary: every
//! entry point builds its store from `[sip] xcid_headers` with
//! `unwrap_or_default()`, so an unset key must mean no header strategy, and
//! the key must turn it on.
//!
//! Driven through the real binary's MCP surface, where `find_correlated`
//! names the strategy that matched.
#![cfg(all(feature = "native", feature = "mcp"))]

#[path = "support/mcp.rs"]
mod mcp;
#[path = "support/pcap_build.rs"]
mod pcap_build;

use mcp::McpSession;
use pcap_build::{udp_frame, write_pcap_at};

/// An `INVITE` with nothing that links it to another call except, when
/// `x_call_id` is given, an `X-Call-ID` header naming that call.
fn invite(call_id: &str, branch: &str, x_call_id: Option<&str>) -> Vec<u8> {
    let xcid = x_call_id.map_or_else(String::new, |root| format!("X-Call-ID: {root}\r\n"));
    let msg = format!(
        "INVITE sip:bob@10.2.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bK{branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@10.1.0.1>;tag=t{branch}\r\n\
         To: <sip:bob@10.2.0.1>\r\n\
         Call-ID: {call_id}\r\n\
         {xcid}CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@10.1.0.1:5060>\r\n\
         Content-Length: 0\r\n\r\n"
    );
    udp_frame([10, 1, 0, 1], [10, 2, 0, 1], 5060, 5060, msg.as_bytes())
}

/// Two legs 30 seconds apart, far outside the timing heuristic's window, the
/// second pointing at the first with `X-Call-ID`. Returns the capture path.
fn capture(dir: &std::path::Path) -> String {
    let path = dir.join("xcid.pcap");
    write_pcap_at(
        &path,
        &[
            (invite("a-leg@10.1.0.1", "-a", None), 0),
            (
                invite("b-leg@10.1.0.1", "-b", Some("a-leg@10.1.0.1")),
                30_000_000,
            ),
        ],
        1,
    );
    path.to_str().expect("utf-8 path").to_string()
}

/// The strategies `find_correlated` names for `call_id`.
fn strategies(session: &mut McpSession, call_id: &str) -> Vec<String> {
    let msg = session.call("find_correlated", serde_json::json!({ "call_id": call_id }));
    assert!(
        msg.get("error").is_none(),
        "find_correlated must answer, got: {msg}"
    );
    let text = msg["result"]["content"][0]["text"]
        .as_str()
        .expect("text payload")
        .to_string();
    let value: serde_json::Value = serde_json::from_str(&text).expect("payload is JSON");
    value["legs"]
        .as_array()
        .map(|legs| {
            legs.iter()
                .filter_map(|l| l["strategy"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Write `body` as a config file in `dir` and return its path.
fn config(dir: &std::path::Path, body: &str) -> String {
    let path = dir.join("sipnab.toml");
    std::fs::write(&path, body).expect("write config");
    path.to_str().expect("utf-8 path").to_string()
}

/// No configuration: the header is in the capture and is not followed.
#[test]
fn an_unconfigured_run_follows_no_correlation_header() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = capture(dir.path());
    let mut session = McpSession::start(&pcap, &["--no-config"]);
    assert!(
        strategies(&mut session, "a-leg@10.1.0.1").is_empty(),
        "X-Call-ID is not a default; the legs must not correlate"
    );
}

/// `[sip] xcid_headers` naming the header turns the strategy on.
#[test]
fn the_configured_header_correlates_the_legs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = capture(dir.path());
    let cfg = config(dir.path(), "[sip]\nxcid_headers = [\"X-Call-ID\"]\n");
    let mut session = McpSession::start(&pcap, &["--config", &cfg]);
    assert_eq!(
        strategies(&mut session, "a-leg@10.1.0.1"),
        vec!["x_call_id".to_string()],
        "the configured header must reach the store that answers"
    );
}

/// An explicit empty list is the same as no key: no header strategy.
#[test]
fn an_empty_header_list_follows_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = capture(dir.path());
    let cfg = config(dir.path(), "[sip]\nxcid_headers = []\n");
    let mut session = McpSession::start(&pcap, &["--config", &cfg]);
    assert!(
        strategies(&mut session, "a-leg@10.1.0.1").is_empty(),
        "an empty list must not bring the old default back"
    );
}
