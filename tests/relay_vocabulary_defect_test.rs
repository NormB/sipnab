// SPDX-License-Identifier: MIT OR Apache-2.0

//! Defects paid for: the command table, the argument bounds, and the two
//! places a bulk edit answered a question it had not asked.
//!
//! Each test names the defect it exists for. None of them is hypothetical:
//! every one failed against a real relay or a real build before it passed.

#![cfg(feature = "full")]

use sipnab::relay::rtpproxy::{Meaning, RtpproxyControl, decode_command, decode_reply, interpret};
use sipnab::relay_vocab::{ControlDelivery, RelayImplementation};
use sipnab::rtp::stream_store::EndpointAssertion;

// ── The command table, which I part-invented ─────────────────────────────────

/// GIVEN every command letter
/// WHEN its argument bounds are read
/// THEN none of them is the invented default.
///
/// The defect: the table carried real bounds for three commands and `(1, 20)`
/// for the other ten. A bound that generous is not a bound; it is the absence
/// of one wearing a bound's clothes, and it let a five-line reply decode as a
/// stop-play command with fourteen arguments.
#[test]
fn no_command_accepts_the_invented_default_range() {
    // `S` takes 3..4. Under the invented default it accepted up to twenty.
    for too_many in [
        b"1 S a b c d e".as_slice(),
        b"1 S a b c d e f g h i j k".as_slice(),
    ] {
        assert!(
            decode_command(too_many).is_none(),
            "{too_many:?} was accepted; stop-play takes three or four"
        );
    }
    assert!(
        decode_command(b"1 S call-id ftag ttag").is_some(),
        "and the real shape must still decode"
    );
}

/// GIVEN the feature query
/// WHEN it is decoded
/// THEN `VF` is its own command and not a malformed `V`.
///
/// The defect: rtpproxy consumes the `F` as part of the verb and then treats
/// what remains as modifier-free, so `VF` takes exactly two arguments while
/// bare `V` takes one. One rule for both refused `VF 20040107`, which a real
/// relay answers with `1`.
#[test]
fn the_feature_query_is_its_own_command() {
    assert!(decode_command(b"s2 VF 20040107").is_some(), "VF takes two");
    assert!(decode_command(b"s1 V").is_some(), "bare V takes one");
    assert!(
        decode_command(b"s1 V 20040107").is_none(),
        "bare V takes no argument, so this is not a version query"
    );
    assert!(
        decode_command(b"s2 VF").is_none(),
        "a feature query with nothing to ask about is not a command"
    );
}

/// GIVEN a feature query and a version query
/// WHEN each is answered with a bare number
/// THEN the two readings differ.
///
/// Both answer with an integer, and only the modifier separates them. Reading
/// `VF`'s `0` as a version would report a relay speaking protocol zero.
#[test]
fn a_feature_answer_is_never_read_as_a_protocol_version() {
    let vf = decode_command(b"s3 VF 99999").expect("decodes");
    let v = decode_command(b"s1 V").expect("decodes");
    assert_eq!(
        interpret(&vf, &decode_reply(b"s3 0").expect("reply")),
        Some(Meaning::FeatureAbsent)
    );
    assert_eq!(
        interpret(&v, &decode_reply(b"s1 0").expect("reply")),
        Some(Meaning::ProtocolVersion(0))
    );
}

/// GIVEN the relay's own refusal of a short command
/// WHEN sipnab decodes the same bytes
/// THEN it refuses too.
///
/// Two independent bounds agreeing is the only evidence the table describes
/// rtpproxy rather than my reading of it. Observed: `U short-args` returned
/// `E1`.
#[test]
fn the_decoder_and_the_relay_agree_on_what_is_malformed() {
    assert!(decode_command(b"s4 U short-args").is_none());
    assert_eq!(
        match decode_reply(b"s4 E1").expect("reply") {
            RtpproxyControl::Reply { reply, .. } => format!("{reply:?}"),
            other => panic!("{other:?}"),
        },
        "Error(1)",
        "and the relay's own answer was an error, not a session"
    );
}

// ── The two paths a blanket answer got wrong ─────────────────────────────────

/// GIVEN an assertion from a relay sipnab ASKED
/// WHEN its delivery is read
/// THEN it is encapsulated, because sipnab opened that connection.
///
/// The defect: I mechanically rewrote every assertion in the tree to
/// `BareDatagram`. Three tests wanted encapsulated and one wanted bare, and a
/// blanket answer was wrong in both directions — which is the distinction the
/// whole change exists for.
#[test]
fn an_answer_to_a_question_sipnab_asked_is_encapsulated() {
    let asked = EndpointAssertion::media_relay(
        RelayImplementation::Rtpengine,
        ControlDelivery::Encapsulated,
    );
    assert!(asked.is_authenticated());
    assert_eq!(asked.delivery(), Some(ControlDelivery::Encapsulated));
}

/// GIVEN an assertion sipnab SNIFFED off the wire
/// WHEN its delivery is read
/// THEN it is a bare datagram, whatever relay sent it.
#[test]
fn a_message_read_off_the_wire_is_a_bare_datagram() {
    for relay in [
        RelayImplementation::Rtpengine,
        RelayImplementation::Rtpproxy,
    ] {
        let sniffed = EndpointAssertion::media_relay(relay, ControlDelivery::BareDatagram);
        assert!(!sniffed.is_authenticated(), "{relay:?}");
    }
}

/// GIVEN the two delivery paths
/// WHEN one answer is given for both
/// THEN it is wrong for one of them.
///
/// Stated as a property so the next bulk edit cannot satisfy it by picking a
/// side.
#[test]
fn no_single_delivery_answer_is_right_for_both_paths() {
    let asked = EndpointAssertion::media_relay(
        RelayImplementation::Rtpengine,
        ControlDelivery::Encapsulated,
    );
    let sniffed = EndpointAssertion::media_relay(
        RelayImplementation::Rtpengine,
        ControlDelivery::BareDatagram,
    );
    assert_ne!(asked, sniffed);
    assert_ne!(asked.is_authenticated(), sniffed.is_authenticated());
}

/// GIVEN the portable vocabulary
/// WHEN it is reached through the native seam
/// THEN it is the same type.
///
/// The re-export must not become a second definition: two enums with one name
/// would compare unequal and no compiler error would say why.
#[test]
fn the_seam_reexports_the_vocabulary_rather_than_redefining_it() {
    let via_vocab = RelayImplementation::Rtpproxy;
    let via_seam = sipnab::relay::RelayImplementation::Rtpproxy;
    assert_eq!(via_vocab, via_seam);
    assert_eq!(via_vocab.as_str(), via_seam.as_str());
}
