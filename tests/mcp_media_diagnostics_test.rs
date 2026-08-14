// SPDX-License-Identifier: MIT OR Apache-2.0

//! `media_diagnostics` reaches the media facts sipnab already computes.
//!
//! Six diagnostics were fully computed and unreachable over MCP before this
//! tool existed. Each was verified in the tree rather than assumed:
//!
//! * **QoS marking** — new in this change, and the reason it is grouped here:
//!   an agent reading jitter without knowing which queue the packets were in
//!   is reading a symptom with the cause withheld.
//! * **Clock grounding and measured jitter** —
//!   `StreamStore::clock_grounding` and `StreamStore::measured_jitter_ms` had
//!   NO consumer anywhere in the tree. The second is the jitter analogue of
//!   `mos_grounded`: it returns `None` rather than a number derived from a
//!   clock rate nobody stated.
//! * **Delay provenance** — `DelaySource` reached the TUI only, while the MOS
//!   it feeds was already published over MCP. An agent could read the score
//!   and not that its delay term was assumed.
//! * **Silence and comfort noise** — TUI only.
//! * **Endpoint-reported RTCP** (`RemoteReceptionReport`) — computed, stored,
//!   and read by nothing outside its own module's tests.
//! * **Endpoint-reported RTCP XR VoIP metrics** — TUI only.
//!
//! The last two are the reason this tool has a fence of its own around a whole
//! sub-object. They are numbers a remote endpoint asserted in an
//! unauthenticated datagram about a path segment sipnab is not necessarily
//! watching. Merging them with sipnab's own measurements would make a
//! spoofable claim indistinguishable from an observation, which is the same
//! failure `mos_grounded` exists to prevent one level down.
//!
//! Every test drives the real binary over a real capture and asserts a value
//! verified independently from the packets, never from what the tool returned.

#![cfg(feature = "mcp")]

#[path = "support/mcp.rs"]
mod support;
use support::{call_tool_with_args, ok_payload};

/// A G.711 call: two streams, PCMU both ways, every frame unmarked.
const G711: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// The Call-ID of the one dialog in [`G711`], read from its INVITE.
const G711_CALL: &str = "1-1966@10.0.2.20";

/// Call `media_diagnostics` and return its payload.
fn diagnostics(pcap: &str, call_id: &str) -> serde_json::Value {
    let msg = call_tool_with_args(
        pcap,
        &[],
        "media_diagnostics",
        serde_json::json!({ "call_id": call_id }),
    );
    ok_payload(&msg)
}

/// The QoS marking of a real capture reaches the agent, named.
///
/// Every frame in [`G711`] carries TOS 0x00, so DSCP is 0 — the default PHB.
/// That is the finding, not the absence of one: media in the default queue is
/// the most common cause of jitter that adding bandwidth does not fix. A tool
/// that omitted the key here would report the fault as "unknown".
#[test]
fn qos_marking_is_reported_and_named_for_a_real_capture() {
    let v = diagnostics(G711, G711_CALL);
    let streams = v["streams"].as_array().expect("streams array");
    assert!(
        !streams.is_empty(),
        "sip-rtp-g711.pcap carries RTP for this dialog; an empty list is the \
         shape a broken lookup produces: {v}"
    );

    for s in streams {
        let qos = &s["qos"];
        assert_eq!(
            qos["marking_observed"], true,
            "these frames came off the wire with an IP header, so the marking \
             was observed: {qos}"
        );
        assert_eq!(qos["dscp"], 0, "every frame in {G711} carries TOS 0x00");
        assert!(
            qos["name"]
                .as_str()
                .unwrap_or_default()
                .contains("best effort"),
            "DSCP 0 is the default PHB and must be named, not left as a bare \
             number an operator has to look up: {qos}"
        );
        assert_eq!(
            qos["expedited"], false,
            "0 is not EF, and saying so is the actionable half of the finding"
        );
        assert!(
            qos.get("remarked_to").is_none(),
            "nothing re-marked this stream, so the key must be absent rather \
             than repeating the same number: {qos}"
        );
    }
}

/// Jitter carries its grounding, the way MOS carries `mos_grounded`.
///
/// PCMU is payload type 0, whose 8 kHz clock RFC 3551 Table 4 fixes, so the
/// jitter here IS a measurement and must say so. The interesting half is the
/// other branch: a stream whose clock rate was assumed must report no measured
/// jitter at all rather than a number scaled by a divisor nobody stated.
#[test]
fn jitter_declares_whether_its_clock_rate_was_grounded() {
    let v = diagnostics(G711, G711_CALL);
    let streams = v["streams"].as_array().expect("streams array");
    assert!(!streams.is_empty(), "no streams: {v}");

    for s in streams {
        let jitter = &s["jitter"];
        assert_eq!(
            jitter["grounded"], true,
            "payload type 0 has an RFC 3551 clock rate, so this jitter is a \
             measurement: {jitter}"
        );
        assert_eq!(
            jitter["clock_basis"], "rfc3551",
            "the basis must be named, not merely flagged: {jitter}"
        );
        assert!(
            jitter["measured_ms"].is_number(),
            "a grounded stream has a measured jitter: {jitter}"
        );
        assert!(
            jitter.get("note").is_none(),
            "a grounded figure needs no caveat: {jitter}"
        );
    }
}

/// The delay term behind the published MOS says where it came from.
///
/// [`G711`] carries no RTCP and the server was started with no declared
/// one-way delay, so the delay is assumed — and an agent reading a MOS built
/// on it needs to know that before it reasons about the score. This is the
/// fact that reached the TUI and stopped there.
#[test]
fn the_delay_behind_the_mos_declares_that_it_was_assumed() {
    let v = diagnostics(G711, G711_CALL);
    let streams = v["streams"].as_array().expect("streams array");
    assert!(!streams.is_empty(), "no streams: {v}");

    for s in streams {
        let delay = &s["delay"];
        assert_eq!(
            delay["assumed"], true,
            "this capture holds no RTCP and nothing was declared, so the \
             delay term is a default: {delay}"
        );
        assert!(
            delay["one_way_ms"].is_number(),
            "the assumed figure is still reported — withholding it would hide \
             which number the MOS was built on: {delay}"
        );
        assert!(
            delay["source"].as_str().is_some_and(|s| !s.is_empty()),
            "the provenance is named: {delay}"
        );
    }
}

/// A capture with no RTCP says the endpoint reported nothing.
///
/// The opposite of an empty object: absent RTCP and a remote endpoint that
/// reported perfect quality must not look the same. `endpoint_reported` is
/// omitted entirely when nothing arrived.
#[test]
fn absent_rtcp_is_reported_as_absent_rather_than_as_a_clean_report() {
    let v = diagnostics(G711, G711_CALL);
    let streams = v["streams"].as_array().expect("streams array");
    assert!(!streams.is_empty(), "no streams: {v}");

    for s in streams {
        assert!(
            s.get("endpoint_reported").is_none(),
            "no RTCP arrived for this stream, so there is no endpoint claim to \
             report. An empty object here reads as 'the far end said \
             everything was fine': {s}"
        );
    }
}

/// A dialog with no media says the question does not apply.
///
/// The precedent is `diagnose_registration`'s `applicable: false`. Returning
/// an empty stream list for a call that never carried RTP reads as "the media
/// was checked and was fine", which is a confident wrong answer about a call
/// whose media was never seen.
#[test]
fn a_dialog_with_no_media_says_so_rather_than_returning_an_empty_list() {
    const NO_MEDIA: &str = "tests/pcap-samples/sip-register.pcap";
    let msg = call_tool_with_args(
        NO_MEDIA,
        &[],
        "media_diagnostics",
        serde_json::json!({ "call_id": first_call_id(NO_MEDIA) }),
    );
    let v = ok_payload(&msg);
    assert_eq!(
        v["applicable"], false,
        "a REGISTER dialog carries no media; the answer is that the question \
         does not apply: {v}"
    );
    assert!(
        v["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "an inapplicable answer states why: {v}"
    );
}

/// First Call-ID in a capture, so no test hardcodes one that may change.
fn first_call_id(pcap: &str) -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "-I", pcap, "--json-dialogs", "--quiet"])
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
