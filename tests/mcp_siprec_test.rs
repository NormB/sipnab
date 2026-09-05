// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIPREC metadata reaches an agent, from a capture rather than a fixture.
//!
//! The unit tests in `sip::siprec` drive the parser with metadata built from
//! OpenSIPS's own generator. This one drives the whole path: a pcap in, the
//! real binary, the MCP tool out. Between those two is everything a fixture
//! cannot reach -- multipart framing, the boundary parameter, `Content-Length`,
//! and whether `dialog_store` recognizes the body at all.
//!
//! That middle section is where the feature was actually broken: the parser
//! had worked for a long time and no surface read it, so a parser test could
//! not have told anyone the feature was missing.

#![cfg(feature = "mcp")]

#[path = "support/mcp.rs"]
mod support;
use support::{call_tool_with_args, ok_payload};

/// A SIPREC INVITE toward a recording server, carrying the multipart body an
/// SRC sends: the session SDP and the `application/rs-metadata+xml` part.
///
/// The metadata is byte-for-byte the shape
/// `modules/siprec/siprec_body.c::srs_build_xml` writes in OpenSIPS 4.0.1 --
/// `datamode`, `nameID aor`, integer stream labels, and the
/// `participantstreamassoc` blocks that carry ownership. It is generator-
/// derived rather than captured off a wire: OpenSIPS's `siprec` module refuses
/// to start a session without an engaged `rtp_relay` context, and no media
/// relay is available in this harness. Everything about the message shape is
/// taken from the module's own source rather than invented.
const SIPREC: &str = "tests/pcap-samples/siprec-opensips-invite.pcap";

/// The Call-ID of the SIPREC dialog in [`SIPREC`].
const SIPREC_CALL: &str = "4f1c0a2e-siprec@172.28.0.31";

/// A call with no SIPREC at all, for the negative path.
const G711: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// The Call-ID of the one dialog in [`G711`].
const G711_CALL: &str = "1-1966@10.0.2.20";

/// Call `siprec_metadata` and return its payload.
fn siprec(pcap: &str, call_id: &str) -> serde_json::Value {
    let msg = call_tool_with_args(
        pcap,
        &[],
        "siprec_metadata",
        serde_json::json!({ "call_id": call_id }),
    );
    ok_payload(&msg)
}

/// The recording metadata of a real SIPREC INVITE reaches the agent whole.
#[test]
fn a_siprec_invite_yields_its_metadata_through_the_tool() {
    let v = siprec(SIPREC, SIPREC_CALL);
    assert_eq!(
        v["recorded"], true,
        "a dialog whose INVITE carries rs-metadata is recorded: {v}"
    );
    let sr = &v["siprec"];
    assert_eq!(sr["session_id"], "4f1c0a2e");
    assert_eq!(
        sr["mode"], "complete",
        "the mode comes from <datamode>, which is what an SRC writes: {sr}"
    );
    assert_eq!(
        sr["participants"].as_array().map(Vec::len),
        Some(2),
        "both participants: {sr}"
    );
    assert_eq!(
        sr["streams"].as_array().map(Vec::len),
        Some(3),
        "three recorded streams: {sr}"
    );
}

/// Each recorded stream names the participant that sends it.
///
/// The association is not in the stream element. It is in
/// `participantstreamassoc`, and without reading that this is null on every
/// stream -- which is the state this surface was built in.
#[test]
fn each_recorded_stream_names_the_party_that_sends_it() {
    let v = siprec(SIPREC, SIPREC_CALL);
    let streams = v["siprec"]["streams"].as_array().expect("streams array");
    let owner = |id: &str| {
        streams
            .iter()
            .find(|s| s["stream_id"] == id)
            .unwrap_or_else(|| panic!("stream {id} present"))["participant_id"]
            .clone()
    };
    assert_eq!(owner("1a2b3c4d"), "9b2d1f00", "Alice's audio is Alice's");
    assert_eq!(
        owner("2b3c4d5e"),
        "9b2d1f00",
        "and so is her video -- a second stream for one party is the audio and \
         video case, which is the reason labels matter"
    );
    assert_eq!(
        owner("3c4d5e6f"),
        "c7e40a13",
        "Bob's audio is Bob's, though Alice receives it: <recv> is not ownership"
    );
}

/// Each stream carries the label that names its `m=` line.
#[test]
fn each_recorded_stream_carries_its_m_line_label() {
    let v = siprec(SIPREC, SIPREC_CALL);
    let labels: Vec<String> = v["siprec"]["streams"]
        .as_array()
        .expect("streams array")
        .iter()
        .map(|s| s["label"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        labels,
        ["0", "1", "2"],
        "the SDP label is the only route from a recorded stream to the media \
         description it was cut from"
    );
}

/// A participant's AOR and display name survive the whole path.
#[test]
fn a_participants_identity_reaches_the_agent() {
    let v = siprec(SIPREC, SIPREC_CALL);
    let ps = v["siprec"]["participants"]
        .as_array()
        .expect("participants");
    assert_eq!(ps[0]["aor"], "sip:alice@example.invalid");
    assert_eq!(ps[0]["name"], "Alice");
    assert_eq!(
        ps[1]["aor"], "sip:bob@example.invalid",
        "the second nameID is self-closing, which is what an SRC writes when \
         it has no display name: {ps:?}"
    );
    assert!(
        ps[1].get("name").is_none(),
        "and no name is invented for it: {ps:?}"
    );
}

/// A call with no SIPREC says so, and says what that does and does not mean.
#[test]
fn a_call_with_no_siprec_is_reported_as_such_without_overclaiming() {
    let v = siprec(G711, G711_CALL);
    assert_eq!(v["recorded"], false);
    let reason = v["reason"].as_str().expect("a reason is given");
    assert!(
        reason.contains("capture point"),
        "the absence must be attributed to what sipnab saw, not asserted as \
         the call having gone unrecorded: {reason}"
    );
}
