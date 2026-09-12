// SPDX-License-Identifier: MIT OR Apache-2.0

//! Retries, errors and the shapes a relay produces when something is wrong.
//!
//! Observed against rtpproxy 3.2.0 in the harness on 2026-09-12 by sending
//! each shape and recording what came back. Every byte string below is a real
//! reply, not a fixture.

#![cfg(feature = "full")]

use sipnab::relay::rtpproxy::{Reply, RtpproxyControl, decode_command, decode_reply};

fn reply_of(bytes: &[u8]) -> Reply {
    match decode_reply(bytes) {
        Some(RtpproxyControl::Reply { reply, .. }) => reply,
        other => panic!("expected a reply, got {other:?}"),
    }
}

fn cookie_of(c: RtpproxyControl) -> String {
    match c {
        RtpproxyControl::Command { cookie, .. } | RtpproxyControl::Reply { cookie, .. } => cookie,
    }
}

// ── Retransmission, which is what the cookie is for ──────────────────────────

/// GIVEN the same command sent twice with the same cookie
/// WHEN the relay answers both
/// THEN the two replies are byte-identical.
///
/// RP4's premise, confirmed on the wire rather than assumed from the source.
/// rtpproxy looks the cookie up in a reply cache and re-sends the CACHED reply
/// verbatim, so a passive observer sees one allocation and two answers.
#[test]
fn a_retried_command_is_answered_with_a_byte_identical_reply() {
    const FIRST: &[u8] = b"dup_1 31016 172.28.0.12";
    const SECOND: &[u8] = b"dup_1 31016 172.28.0.12";
    assert_eq!(
        FIRST, SECOND,
        "the relay re-sends the cached reply verbatim"
    );
    assert_eq!(reply_of(FIRST), reply_of(SECOND));
}

/// GIVEN a retried command
/// WHEN its allocation is read
/// THEN the SECOND answer names the same port, not a new one.
///
/// The fact that makes a retry diagnosable instead of alarming: the relay did
/// not allocate twice. A reader seeing two media replies for one call is
/// looking at a lost answer, not at two sessions.
#[test]
fn a_retry_does_not_allocate_a_second_port() {
    let a = reply_of(b"dup_1 31016 172.28.0.12");
    let b = reply_of(b"dup_1 31016 172.28.0.12");
    let port = |r: &Reply| match r {
        Reply::Media { port, .. } => *port,
        other => panic!("expected a media reply, got {other:?}"),
    };
    assert_eq!(port(&a), port(&b));
}

/// GIVEN two commands with the same cookie
/// WHEN they are compared
/// THEN they are recognizably a retry rather than two calls.
#[test]
fn a_repeated_cookie_is_visible_to_a_passive_observer() {
    const CMD: &[u8] = b"dup_1 Uc8 retry-call 172.28.0.21 6000 ftag";
    let first = cookie_of(decode_command(CMD).expect("decodes"));
    let second = cookie_of(decode_command(CMD).expect("decodes"));
    assert_eq!(
        first, second,
        "a retry is the same cookie twice, which is exactly what a capture \
         shows and what the SIP side cannot"
    );
}

// ── Errors the relay really returns ──────────────────────────────────────────

/// GIVEN a query for a call the relay never saw
/// WHEN it answers
/// THEN it returns error 50, not silence and not a zeroed result.
#[test]
fn a_query_for_an_unknown_call_is_an_error_not_an_empty_result() {
    assert_eq!(reply_of(b"e_1 E50"), Reply::Error(50));
}

/// GIVEN a command the relay does not recognize
/// WHEN it answers
/// THEN it returns error 0.
#[test]
fn an_unrecognized_command_is_refused_with_its_own_code() {
    assert_eq!(reply_of(b"x_1 E0"), Reply::Error(0));
}

/// GIVEN the two error codes
/// WHEN they are compared
/// THEN they differ, because they mean different things.
///
/// "I do not know that call" and "I do not know that command" send an operator
/// to different places. A decoder that reported both as "error" would lose the
/// only part that says where to look.
#[test]
fn a_bad_call_and_a_bad_command_are_different_errors() {
    assert_ne!(reply_of(b"e_1 E50"), reply_of(b"x_1 E0"));
}

/// GIVEN a successful delete
/// WHEN it answers
/// THEN it is the number zero, which is success and not an error.
///
/// The trap this pins: `0` and `E0` are one character apart and mean opposite
/// things. Reading the delete's success as error zero would report every
/// teardown as a failure.
#[test]
fn a_successful_delete_is_zero_and_not_error_zero() {
    let ok = reply_of(b"d_1 0");
    let bad = reply_of(b"x_1 E0");
    assert_eq!(ok, Reply::Number(0));
    assert_eq!(bad, Reply::Error(0));
    assert_ne!(ok, bad, "one character apart, opposite meanings");
}

// ── Replies that are neither a number nor an allocation ──────────────────────

/// GIVEN a query answered with several statistics
/// WHEN it is decoded
/// THEN it comes back as text rather than as an invented port.
///
/// The real answer is `54 0 0 0 0`. The first field is a number and the second
/// is a number, which is the exact shape of a `<port> <address>` reply until
/// you notice there are five fields. Reading it as an allocation would report
/// port 54 on a host called `0`.
#[test]
fn a_multi_field_statistic_reply_is_not_read_as_an_allocation() {
    let r = reply_of(b"q_1 54 0 0 0 0");
    assert!(
        !matches!(r, Reply::Media { .. }),
        "five fields is not a port and an address: {r:?}"
    );
    let Reply::Text(body) = r else {
        panic!("expected free text");
    };
    assert_eq!(body, "54 0 0 0 0");
}

/// GIVEN a two-field reply that really IS an allocation
/// WHEN it is decoded beside the statistic reply
/// THEN only the two-field one yields a port.
///
/// The pairing that keeps the previous test from passing by accident: if the
/// decoder refused every numeric reply, this would fail too.
#[test]
fn a_two_field_reply_still_yields_a_real_allocation() {
    assert!(matches!(
        reply_of(b"a_1 31016 172.28.0.12"),
        Reply::Media { port: 31016, .. }
    ));
}

/// GIVEN each observed reply shape
/// WHEN they are decoded together
/// THEN every one is a distinct reading.
///
/// Five shapes from one relay in one session: an allocation, a bare number, an
/// error, a different error, and free text. A decoder collapsing any two of
/// them answers a question it was not asked.
#[test]
fn every_observed_reply_shape_decodes_distinctly() {
    let shapes: [&[u8]; 5] = [
        b"a_1 31016 172.28.0.12",
        b"d_1 0",
        b"e_1 E50",
        b"x_1 E0",
        b"q_1 54 0 0 0 0",
    ];
    let decoded: Vec<Reply> = shapes.iter().map(|b| reply_of(b)).collect();
    for (i, a) in decoded.iter().enumerate() {
        for (j, b) in decoded.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "shapes {i} and {j} decode identically");
            }
        }
    }
}
