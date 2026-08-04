// SPDX-License-Identifier: MIT OR Apache-2.0

//! `save_findings` end to end, against the real binary over stdio.
//!
//! Unit tests over a hand-built `SipnabMcp` already prove the refusals, the
//! bounds and the dead end. What they cannot prove is the thing that decides
//! whether the feature is safe in a deployment: that `--mcp-allow-save-findings`
//! is what arms it, on a real process, parsed by the real CLI and threaded
//! through the real server construction.
//!
//! That path — flag, to `RunPlan`, to `with_save_findings()`, to the handler's
//! first statement — is four hops long, and a break anywhere in it fails in the
//! dangerous direction: a server that accepts writes nobody asked it to accept.
//! A unit test that calls `with_save_findings()` directly cannot see any of it,
//! because it starts at the far end.
//!
//! `#![cfg(feature = "mcp")]` because these drive the MCP surface.

#![cfg(feature = "mcp")]

#[path = "support/mcp.rs"]
mod support;

use support::{ok_payload, McpSession};

/// Any capture will do: findings are about what the agent concluded, not about
/// what the store holds.
const CAPTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// Without the flag, a real server refuses — and says which flag would permit
/// it, so an operator reading the error knows what to change.
#[test]
fn a_stock_server_refuses_to_record_and_names_the_flag() {
    let mut session = McpSession::start(CAPTURE, &[]);
    let reply = session.call(
        "save_findings",
        serde_json::json!({ "summary": "should not be recorded" }),
    );
    let text = serde_json::to_string(&reply).unwrap_or_default();
    assert!(
        text.contains("--mcp-allow-save-findings"),
        "a refusal must name the flag that would permit it: {text}"
    );
}

/// With the flag, the same call is accepted, and the reply states the two
/// things a caller cannot otherwise know: that nothing will read this back, and
/// where a human will find it.
#[test]
fn the_flag_arms_the_write_and_the_reply_says_where_it_went() {
    let mut session = McpSession::start(CAPTURE, &["--mcp-allow-save-findings"]);
    let v = ok_payload(&session.call(
        "save_findings",
        serde_json::json!({
            "summary": "the 488 was a codec mismatch",
            "call_id": "example@host",
        }),
    ));
    assert_eq!(v["seq"], 0, "the first finding of a process is seq 0");
    assert_eq!(v["recorded_total"], 1);
    assert_eq!(v["truncated"], false);
    assert_eq!(
        v["readable_over_mcp"], false,
        "the reply must state the dead end rather than leave an agent to discover it"
    );
    assert!(
        v["delivered_to"]
            .as_str()
            .unwrap_or_default()
            .contains("log"),
        "the reply must say where a human reads this: {}",
        v["delivered_to"]
    );
    assert!(
        v["capture_identity"]["dialog_generation"].is_u64(),
        "a finding carries the same provenance as every other response"
    );
}

/// The bound is visible before it bites, not only when it refuses.
#[test]
fn remaining_counts_down_across_calls_on_a_live_server() {
    let mut session = McpSession::start(CAPTURE, &["--mcp-allow-save-findings"]);
    let first = ok_payload(&session.call("save_findings", serde_json::json!({ "summary": "one" })));
    let second = ok_payload(&session.call("save_findings", serde_json::json!({ "summary": "two" })));

    let (a, b) = (
        first["remaining"].as_u64().unwrap_or(0),
        second["remaining"].as_u64().unwrap_or(0),
    );
    assert!(a > 0 && b == a - 1, "remaining must count down: {a} then {b}");
    assert_eq!(second["seq"], 1, "sequence numbers are monotonic per process");
}

/// The tool appears in the registry whether or not it is armed.
///
/// Hiding an unarmed tool would be worse than listing it: an agent would have
/// no way to learn the capability exists and no error text pointing at the flag,
/// so the operator would be debugging a silence.
#[test]
fn the_tool_is_listed_even_on_a_server_that_will_refuse_it() {
    let mut session = McpSession::start(CAPTURE, &[]);
    assert!(
        session.list_tools().iter().any(|t| t == "save_findings"),
        "save_findings must be discoverable so its refusal can teach the flag"
    );
}
