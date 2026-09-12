// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a reply MEANS, which depends on the command it answers.
//!
//! Written before the behavior exists. Observed against rtpproxy 3.2.0 in the
//! harness on 2026-09-12:
//!
//! ```text
//! d_1 D retry-call ftag   ->  d_1 0          success
//! s3  VF 99999            ->  s3 0           feature NOT supported
//! s7  X                   ->  s7 0           success
//! s2  VF 20040107         ->  s2 1           feature supported
//! s1  V                   ->  s1 20040107    the protocol version
//! ```
//!
//! Five replies, three of them the single character `0`, meaning success,
//! not-supported and success again. The number alone says nothing; the command
//! it answers is what gives it meaning, and the cookie is what pairs them.
//!
//! A decoder reporting all three as `Number(0)` hands a reader a value they
//! must interpret by remembering what was asked — which is the kind of
//! interpretation that gets done wrong once and then trusted.

#![cfg(feature = "full")]

use sipnab::relay::rtpproxy::{Meaning, RtpproxyControl, decode_command, decode_reply, interpret};

/// The WHOLE decoded reply, cookie included.
///
/// Not just the `Reply`: the cookie is what pairs it with a command, and a
/// helper that dropped it would make the pairing test unwritable -- the one
/// test that matters most here.
fn reply_of(bytes: &[u8]) -> RtpproxyControl {
    match decode_reply(bytes) {
        Some(r @ RtpproxyControl::Reply { .. }) => r,
        other => panic!("expected a reply, got {other:?}"),
    }
}

// ── The same number, three meanings ──────────────────────────────────────────

/// GIVEN a delete answered with zero
/// WHEN the reply is interpreted against its command
/// THEN it means the session was torn down.
#[test]
fn zero_after_a_delete_means_success() {
    let cmd = decode_command(b"d_1 D retry-call ftag").expect("decodes");
    assert_eq!(
        interpret(&cmd, &reply_of(b"d_1 0")),
        Some(Meaning::Succeeded)
    );
}

/// GIVEN a feature query answered with zero
/// WHEN the reply is interpreted against its command
/// THEN it means the feature is absent, NOT that anything succeeded.
///
/// The same byte as a successful delete. Reporting both as `Number(0)` leaves
/// a reader to remember which question was asked.
#[test]
fn zero_after_a_feature_query_means_unsupported() {
    let cmd = decode_command(b"s3 VF 99999").expect("decodes");
    assert_eq!(
        interpret(&cmd, &reply_of(b"s3 0")),
        Some(Meaning::FeatureAbsent)
    );
}

/// GIVEN the two zero replies
/// WHEN their meanings are compared
/// THEN they differ.
#[test]
fn the_same_zero_does_not_mean_the_same_thing_twice() {
    let deleted = interpret(
        &decode_command(b"d_1 D c ftag").expect("decodes"),
        &reply_of(b"d_1 0"),
    );
    let unsupported = interpret(
        &decode_command(b"s3 VF 99999").expect("decodes"),
        &reply_of(b"s3 0"),
    );
    assert_ne!(deleted, unsupported);
}

/// GIVEN a feature query answered with one
/// WHEN it is interpreted
/// THEN the feature is present.
#[test]
fn one_after_a_feature_query_means_supported() {
    let cmd = decode_command(b"s2 VF 20040107").expect("decodes");
    assert_eq!(
        interpret(&cmd, &reply_of(b"s2 1")),
        Some(Meaning::FeaturePresent)
    );
}

/// GIVEN a delete-all answered with zero
/// WHEN it is interpreted
/// THEN it means success, like the single delete.
#[test]
fn zero_after_delete_all_means_success_too() {
    let cmd = decode_command(b"s7 X").expect("decodes");
    assert_eq!(
        interpret(&cmd, &reply_of(b"s7 0")),
        Some(Meaning::Succeeded)
    );
}

/// GIVEN a version command answered with a large number
/// WHEN it is interpreted
/// THEN it is a protocol version, not a count and not a success code.
#[test]
fn a_number_after_a_version_command_is_a_version() {
    let cmd = decode_command(b"s1 V").expect("decodes");
    assert_eq!(
        interpret(&cmd, &reply_of(b"s1 20040107")),
        Some(Meaning::ProtocolVersion(20_040_107))
    );
}

/// GIVEN an update answered with a port and address
/// WHEN it is interpreted
/// THEN it is an allocation, whatever the verb.
#[test]
fn a_media_reply_is_an_allocation_regardless_of_the_verb() {
    let cmd = decode_command(b"s5 Uc8 nl-call 172.28.0.21 6000 ftag").expect("decodes");
    assert_eq!(
        interpret(&cmd, &reply_of(b"s5 31008 172.28.0.12")),
        Some(Meaning::Allocated {
            port: 31008,
            address: "172.28.0.12".to_string()
        })
    );
}

// ── Pairing is the precondition ──────────────────────────────────────────────

/// GIVEN a reply whose cookie does not match the command
/// WHEN interpretation is attempted
/// THEN it refuses rather than interpreting against the wrong question.
///
/// The cookie is the only thing pairing them. Interpreting a reply against a
/// command it did not answer produces a confident statement about the wrong
/// call, which is worse than declining.
#[test]
fn a_reply_is_never_interpreted_against_another_commands_cookie() {
    let cmd = decode_command(b"d_1 D retry-call ftag").expect("decodes");
    assert_eq!(
        interpret(&cmd, &reply_of(b"OTHER 0")),
        None,
        "mismatched cookies must not be paired"
    );
}

/// GIVEN an error reply
/// WHEN it is interpreted against its command
/// THEN the error code survives interpretation.
///
/// `E1` is what the relay really returned for an `U` with too few arguments,
/// which is the same command my own decoder refuses. Two independent bounds
/// agreeing is worth more than either alone.
#[test]
fn an_error_reply_keeps_its_code_through_interpretation() {
    let cmd = decode_command(b"s9 D call ftag").expect("decodes");
    assert_eq!(
        interpret(&cmd, &reply_of(b"s9 E1")),
        Some(Meaning::Failed(1))
    );
}

/// GIVEN the command the relay itself rejected with E1
/// WHEN sipnab decodes it
/// THEN sipnab rejects it too.
///
/// Observed: `s4 U short-args` returned `s4 E1`. The relay counts arguments
/// and so does this decoder, and they agree on the same input — which is the
/// only evidence that the bounds table describes rtpproxy rather than my
/// reading of it.
#[test]
fn the_decoder_refuses_what_the_relay_refused() {
    assert!(
        decode_command(b"s4 U short-args").is_none(),
        "the relay answered E1 for this; a decoder that accepted it would be \
         reporting a call the relay never created"
    );
}
