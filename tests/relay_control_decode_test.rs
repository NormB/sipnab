// SPDX-License-Identifier: MIT OR Apache-2.0

//! `NgControlDecoder` — the `ng` implementation of the relay control seam.
//!
//! The seam declares what a control message IS; this decoder is the only thing
//! that turns bytes into one, and `decode_ng` publishes whatever it says. Its
//! gates elsewhere only ever reached the `unresolvable` branch (a pointer at a
//! file that is not there), so nothing exercised the decode itself.
//!
//! What matters here is not that a command decodes. It is the pair of facts
//! `decode_ng` reports ALONGSIDE the command, because those are what tell an
//! analyst whether to believe it:
//!
//! - **Delivery.** `Encapsulated` can have been authenticated on the way in;
//!   `BareDatagram` cannot have been, by anything.
//! - **`on_believed_mirror_port`.** For a sniffed mirror this is the entire
//!   reason sipnab credits the message. Reporting `Some(true)` for a datagram
//!   that arrived somewhere else would launder an unbelieved message into a
//!   believed one, which is the failure the port gate exists to prevent.
//!
//! The reply case is the sharpest. An rtpengine `ng` REPLY carries no
//! `command` and no `call-id` — the correlation-id chunk is the ONLY thing
//! naming the call, and it lives in the envelope rather than the message. A
//! decoder that reads the message and drops the envelope loses the call
//! entirely, and does it silently: every field it does return is correct.

#![cfg(all(feature = "hep", feature = "native", not(target_arch = "wasm32")))]

use sipnab::relay::{ControlDecoder, ControlDelivery};
use sipnab::rtpengine::NgControlDecoder;

/// The only port a sniffed mirror is believed on.
const MIRROR_PORT: u16 = 9060;

/// A port that is not it, and is otherwise unremarkable.
const OTHER_PORT: u16 = 9061;

/// One HEP v3 chunk, vendor 0.
fn chunk(out: &mut Vec<u8>, chunk_type: u16, data: &[u8]) {
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&chunk_type.to_be_bytes());
    out.extend_from_slice(&((6 + data.len()) as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// An `ng` OFFER: names its own call and carries SDP.
fn offer() -> Vec<u8> {
    let sdp = "v=0\r\nc=IN IP4 192.0.2.10\r\nm=audio 40001 RTP/AVP 0";
    format!(
        "cookie1 d7:command5:offer7:call-id18:km-670bd208@sipnab8:from-tag5:ftag13:sdp{}:{sdp}e",
        sdp.len()
    )
    .into_bytes()
}

/// An `ng` REPLY as rtpengine really sends it: no `command`, no `call-id`.
fn reply() -> Vec<u8> {
    let sdp = "v=0\r\nc=IN IP4 192.0.2.20\r\nm=audio 38664 RTP/AVP 0";
    format!("cookie1 d3:sdp{}:{sdp}6:result2:oke", sdp.len()).into_bytes()
}

/// A media-creating command, which is counted rather than attributed.
fn start_recording() -> Vec<u8> {
    b"cookie1 d7:command15:start recording7:call-id8:rec-1234e".to_vec()
}

/// Wrap one `ng` body in a HEP v3 datagram under rtpengine's capture protocol.
fn hep(body: &[u8], correlation_id: Option<&str>) -> Vec<u8> {
    let mut inner = Vec::new();
    chunk(&mut inner, 0x0001, &[2]); // IPv4
    chunk(&mut inner, 0x0002, &[17]); // UDP
    chunk(&mut inner, 0x0003, &[127, 0, 0, 1]);
    chunk(&mut inner, 0x0004, &[127, 0, 0, 1]);
    chunk(&mut inner, 0x0007, &43734u16.to_be_bytes());
    chunk(&mut inner, 0x0008, &2223u16.to_be_bytes());
    chunk(&mut inner, 0x0009, &1_700_000_000u32.to_be_bytes());
    chunk(&mut inner, 0x000a, &0u32.to_be_bytes());
    chunk(&mut inner, 0x000b, &[0x3d]); // rtpengine's ng capture protocol
    chunk(&mut inner, 0x000c, &2001u32.to_be_bytes());
    if let Some(id) = correlation_id {
        chunk(&mut inner, 0x0011, id.as_bytes());
    }
    chunk(&mut inner, 0x000f, body);

    let mut pkt = Vec::with_capacity(6 + inner.len());
    pkt.extend_from_slice(b"HEP3");
    pkt.extend_from_slice(&((6 + inner.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&inner);
    pkt
}

/// A bare datagram decodes, and claims no port authority it does not have.
///
/// `on_believed_mirror_port` must be `None` rather than `Some(false)`. The two
/// read very differently: `Some(false)` says the port gate was consulted and
/// refused, `None` says the question does not apply. A bare `ng` datagram is
/// not believed on any port, so there is no gate verdict to report, and
/// reporting one would be inventing an answer nobody produced.
#[test]
fn a_bare_datagram_decodes_and_reports_no_port_verdict() {
    let got = NgControlDecoder
        .decode(&offer(), MIRROR_PORT)
        .expect("a bare ng offer is a control message");

    assert_eq!(got.delivery, ControlDelivery::BareDatagram);
    assert_eq!(got.message.command.as_deref(), Some("offer"));
    assert_eq!(got.message.call_id.as_deref(), Some("km-670bd208@sipnab"));
    assert!(got.message.sdp_bytes.is_some_and(|n| n > 0));
    assert_eq!(
        got.on_believed_mirror_port, None,
        "a bare datagram is believed on no port, so there is no verdict to give"
    );
    assert_eq!(got.correlation_id, None);
}

/// An encapsulated message on the mirror port reports the port verdict it earned.
#[test]
fn an_encapsulated_message_on_the_mirror_port_is_reported_as_such() {
    let got = NgControlDecoder
        .decode(&hep(&offer(), Some("km-670bd208@sipnab")), MIRROR_PORT)
        .expect("a HEP-wrapped ng offer is a control message");

    assert_eq!(got.delivery, ControlDelivery::Encapsulated);
    assert_eq!(got.message.command.as_deref(), Some("offer"));
    assert_eq!(
        got.on_believed_mirror_port,
        Some(true),
        "9060 is the believed mirror port"
    );
}

/// The SAME datagram off the mirror port must not be reported as believed.
///
/// This is the pair that matters. Everything else about the two answers is
/// identical, so a decoder that hard-coded `Some(true)` — or that read the port
/// from the HEP envelope, which the SENDER writes, rather than from where the
/// datagram actually landed — would pass the test above and fail this one.
#[test]
fn the_same_datagram_off_the_mirror_port_is_not_reported_as_believed() {
    let datagram = hep(&offer(), Some("km-670bd208@sipnab"));

    let believed = NgControlDecoder.decode(&datagram, MIRROR_PORT).unwrap();
    let not = NgControlDecoder.decode(&datagram, OTHER_PORT).unwrap();

    assert_eq!(believed.on_believed_mirror_port, Some(true));
    assert_eq!(
        not.on_believed_mirror_port,
        Some(false),
        "the port gate refused this one, and the decode must say so"
    );
    assert_eq!(
        believed.message.command, not.message.command,
        "the MESSAGE is the same; only where it landed differs"
    );
}

/// A reply names its call only through the envelope, and that must survive.
///
/// An `ng` REPLY carries the half with the relay's own allocated ports and has
/// no `call-id` of its own. Drop the correlation-id and the answer is a decode
/// of a message about no call at all — every field returned still correct.
#[test]
fn a_reply_keeps_the_correlation_id_that_names_its_call() {
    let got = NgControlDecoder
        .decode(&hep(&reply(), Some("km-670bd208@sipnab")), MIRROR_PORT)
        .expect("a HEP-wrapped ng reply is a control message");

    assert_eq!(
        got.message.command, None,
        "a reply carries no command; inventing one would be worse than none"
    );
    assert_eq!(
        got.message.call_id, None,
        "a reply carries no call-id of its own"
    );
    assert_eq!(
        got.correlation_id.as_deref(),
        Some("km-670bd208@sipnab"),
        "the envelope is the ONLY thing naming this call, and it must survive \
         the decode"
    );
    assert!(got.message.sdp_bytes.is_some_and(|n| n > 0));
}

/// A media-creating command keeps its name rather than collapsing to a verb.
///
/// `NgCommand::MediaCreating` and `NgCommand::Other` both carry the spelling
/// the relay used, and the seam reports it verbatim. Mapping either to a fixed
/// string would tell an analyst "a command happened" while withholding which.
#[test]
fn a_media_creating_command_keeps_the_name_the_relay_used() {
    let got = NgControlDecoder
        .decode(&start_recording(), MIRROR_PORT)
        .expect("start recording is a control message");

    assert_eq!(got.message.command.as_deref(), Some("start recording"));
    assert_eq!(got.message.call_id.as_deref(), Some("rec-1234"));
    assert_eq!(
        got.message.sdp_bytes, None,
        "this command carries no SDP, and a zero would read as an empty body"
    );
}

/// Anything that is not a control message decodes to nothing.
///
/// Each case is a different way to be wrong, and `None` is the only honest
/// answer to all of them: a partial decode of a non-message is a claim about a
/// call that was never named.
#[test]
fn a_payload_that_is_not_a_control_message_decodes_to_nothing() {
    for (what, bytes) in [
        ("empty", Vec::new()),
        ("a SIP request", b"OPTIONS sip:a@b SIP/2.0\r\n\r\n".to_vec()),
        ("a cookie with no body", b"cookie1 ".to_vec()),
        (
            "a truncated dictionary",
            b"cookie1 d7:command5:offe".to_vec(),
        ),
        ("HEP framing with no ng inside", hep(b"not bencode", None)),
    ] {
        assert!(
            NgControlDecoder.decode(&bytes, MIRROR_PORT).is_none(),
            "{what} is not a control message and must decode to nothing"
        );
    }
}
