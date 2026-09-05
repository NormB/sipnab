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

/// A Call-ID the store does not hold is refused, not answered.
///
/// `recorded: false` is the answer for a call sipnab HAS and that carried no
/// recording. A call it does not have is a different fact, and collapsing the
/// two would let an agent typo a Call-ID and read the result as "that call was
/// not recorded".
#[test]
fn an_unknown_call_id_is_refused_rather_than_answered() {
    let msg = call_tool_with_args(
        SIPREC,
        &[],
        "siprec_metadata",
        serde_json::json!({ "call_id": "no-such-call@nowhere.invalid" }),
    );
    assert!(
        msg["error"].is_object(),
        "an unknown call must be an error, not a recorded=false answer: {msg}"
    );
    let code = msg["error"]["code"].as_i64().unwrap_or_default();
    assert_eq!(code, -32602, "invalid_params is the JSON-RPC code: {msg}");
}

/// The answer says how much of the capture stands behind it.
///
/// Every capture-derived tool carries this, and an agent reading a recording
/// off a truncated capture needs to know the capture was truncated. The
/// completeness gate requires a probe for it; this is the assertion.
#[test]
fn the_answer_says_how_much_of_the_capture_it_read() {
    let v = siprec(SIPREC, SIPREC_CALL);
    assert_eq!(
        v["source_exhausted"], true,
        "a whole pcap was read to the end: {v}"
    );
    assert_eq!(
        v["source_stopped_early"], false,
        "and nothing stopped it early: {v}"
    );
}

/// The answer identifies the capture it came from.
///
/// Two runs over different pcaps can return the same recording session id --
/// a fixture replayed twice does exactly that -- and an agent caching answers
/// needs to tell them apart.
#[test]
fn the_answer_identifies_the_capture_it_came_from() {
    let v = siprec(SIPREC, SIPREC_CALL);
    let id = &v["capture_identity"];
    assert!(
        id["instance"].is_string(),
        "the capture identity names the instance: {v}"
    );
    assert!(
        id["dialog_generation"].is_number(),
        "and the store generation behind the answer: {v}"
    );
}

/// A recorded call is an ordinary dialog everywhere else.
///
/// SIPREC is a property of a call, not a separate kind of object. If reading
/// the metadata required a different listing, an agent would have to know to
/// ask -- and the calls it did not know to ask about are exactly the ones it
/// would miss.
#[test]
fn a_recorded_call_still_appears_in_the_ordinary_dialog_listing() {
    let msg = call_tool_with_args(
        SIPREC,
        &[],
        "list_dialogs",
        serde_json::json!({ "limit": 10 }),
    );
    let v = ok_payload(&msg);
    let ids: Vec<&str> = v["dialogs"]
        .as_array()
        .map(|a| a.iter().filter_map(|d| d["call_id"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        ids.contains(&SIPREC_CALL),
        "the recording dialog must be listed like any other: {ids:?}"
    );
}
