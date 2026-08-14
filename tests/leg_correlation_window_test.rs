// SPDX-License-Identifier: MIT OR Apache-2.0

//! The B2BUA timing heuristic's window reaches the run that applies it.
//!
//! Six of the seven strategies `find_correlated` runs compare an identifier,
//! and every one of them fails the moment the B2BUA in the middle rewrites the
//! identifier — which is what a B2BUA is for. The seventh, the timing
//! heuristic, is what is left, and it asked one question with a compiled-in
//! answer: were the two legs created within two seconds of each other.
//!
//! Two seconds is a lightly-loaded PBX placing the outbound leg immediately.
//! It is not an LNP or ENUM dip, an LCR cascade trying carriers in order, or a
//! PSTN gateway waiting on a first provider to time out — all of which put the
//! outbound INVITE seconds after the inbound one, and all of which are the
//! ordinary shape of the SBC-to-PBX correlation this is for.
//!
//! Driven through the real binary's MCP surface, because that is where an
//! operator or an agent asks the question.
#![cfg(all(feature = "native", feature = "mcp"))]

#[path = "support/mcp.rs"]
mod mcp;
#[path = "support/pcap_build.rs"]
mod pcap_build;

use mcp::McpSession;
use pcap_build::{udp_frame, write_pcap_at};

/// The one address pair both legs share, which is all the timing heuristic has
/// to go on besides the clock.
const A: [u8; 4] = [10, 1, 0, 1];
/// The far side of both legs.
const B: [u8; 4] = [10, 2, 0, 1];

/// A bare `INVITE`: no SDP, no `Session-ID`, no `X-Call-ID`, no
/// `P-Charging-Vector`.
///
/// Every omission is deliberate. Each of those headers drives one of the six
/// identifier strategies, and any one of them present would correlate the two
/// legs on its own — leaving the window this test is about untested while the
/// test still passed.
fn bare_invite(call_id: &str, branch: &str, to_user: &str) -> Vec<u8> {
    let msg = format!(
        "INVITE sip:{to_user}@10.2.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bK{branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@10.1.0.1>;tag=t{branch}\r\n\
         To: <sip:{to_user}@10.2.0.1>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@10.1.0.1:5060>\r\n\
         Content-Length: 0\r\n\r\n"
    );
    udp_frame(A, B, 5060, 5060, msg.as_bytes())
}

/// Ask `find_correlated` about `call_id` and report the strategies it named.
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

/// The declared window is what decides whether two legs of one call correlate.
///
/// The inbound leg arrives, the B2BUA dips a number database, and the outbound
/// leg goes out three seconds later. Nothing else in either message links
/// them, so the shipped two seconds is the whole answer — and it is a "no".
#[test]
fn the_leg_correlation_window_decides_whether_a_dipped_call_correlates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dipped.pcap");
    write_pcap_at(
        &path,
        &[
            (bare_invite("inbound-leg@10.1.0.1", "-in", "18005550100"), 0),
            (
                bare_invite("outbound-leg@10.1.0.1", "-out", "18005550100"),
                3_000_000,
            ),
        ],
        1,
    );
    let pcap = path.to_str().expect("utf-8 path").to_string();

    let mut shipped = McpSession::start(&pcap, &["--no-config"]);
    assert!(
        strategies(&mut shipped, "inbound-leg@10.1.0.1").is_empty(),
        "three seconds is outside the shipped two-second window, so the two \
         legs of this call do not correlate at all"
    );
    drop(shipped);

    let mut widened =
        McpSession::start(&pcap, &["--no-config", "--leg-correlation-window", "5000"]);
    assert_eq!(
        strategies(&mut widened, "inbound-leg@10.1.0.1"),
        vec!["timing_heuristic".to_string()],
        "--leg-correlation-window 5000 must reach the store that answers, and \
         the strategy must still be named as the guess it is"
    );
}

/// The config key reaches the same store, and the flag outranks it.
#[test]
fn the_leg_correlation_window_resolves_flag_over_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dipped-cfg.pcap");
    write_pcap_at(
        &path,
        &[
            (
                bare_invite("cfg-inbound@10.1.0.1", "-cin", "18005550101"),
                0,
            ),
            (
                bare_invite("cfg-outbound@10.1.0.1", "-cout", "18005550101"),
                3_000_000,
            ),
        ],
        1,
    );
    let pcap = path.to_str().expect("utf-8 path").to_string();

    let cfg_path = dir.path().join("sipnab.toml");
    std::fs::write(&cfg_path, "[sip]\nleg_correlation_window_ms = 5000\n").expect("write config");
    let cfg = cfg_path.to_str().expect("utf-8 path").to_string();

    let mut declared = McpSession::start(&pcap, &["--config", &cfg]);
    assert_eq!(
        strategies(&mut declared, "cfg-inbound@10.1.0.1"),
        vec!["timing_heuristic".to_string()],
        "[sip] leg_correlation_window_ms = 5000 must reach the store"
    );
    drop(declared);

    let mut overridden = McpSession::start(
        &pcap,
        &["--config", &cfg, "--leg-correlation-window", "2000"],
    );
    assert!(
        strategies(&mut overridden, "cfg-inbound@10.1.0.1").is_empty(),
        "--leg-correlation-window must beat the config key"
    );
}
