// SPDX-License-Identifier: MIT OR Apache-2.0

//! The decoder against control traffic a real OpenSIPS actually sent.
//!
//! Every byte string here was captured on 2026-09-12 from the harness running
//! `ANCHOR=rtpproxy`: OpenSIPS 172.28.0.10 driving rtpproxy 3.2.0 on
//! 172.28.0.12:22223, for a SIPp call that relayed 9000 RTP packets each way.
//!
//! # Why these and not more fixtures
//!
//! Fixtures written from a reading of rtpproxy's source are a second opinion
//! about that source. These are the wire, and they already carry two things a
//! reading had not shown me: the cookie's real shape, and real command
//! modifiers.

#![cfg(feature = "full")]

use sipnab::relay::rtpproxy::{
    Reply, RtpproxyControl, Stream, creates, decode_command, decode_reply,
};

/// The offer OpenSIPS sent, verbatim.
const OFFER: &[u8] = b"29_6976_4 Uc8,101 1-32@172.28.0.21 172.28.0.21 6000 32SIPpTag091;1";
/// The relay's answer to it, verbatim.
const OFFER_REPLY: &[u8] = b"29_6976_4 31032 172.28.0.12";
/// The lookup that completed the call, verbatim.
const LOOKUP: &[u8] =
    b"29_6976_5 Lc8 1-32@172.28.0.21 172.28.0.20 6000 32SIPpTag091;1 1SIPpTag013;1";
/// The relay's answer to that, verbatim.
const LOOKUP_REPLY: &[u8] = b"29_6976_5 31000 172.28.0.12";

// ── The commands ─────────────────────────────────────────────────────────────

/// GIVEN the offer a real OpenSIPS sent
/// WHEN it is decoded
/// THEN it is an update carrying the call-id, and it creates ordinary media.
#[test]
fn the_real_offer_decodes_as_a_media_creating_update() {
    let RtpproxyControl::Command {
        cookie, verb, args, ..
    } = decode_command(OFFER).expect("the offer decodes")
    else {
        panic!("expected a command");
    };
    assert_eq!(cookie, "29_6976_4");
    assert_eq!(verb, 'U');
    assert_eq!(args.first().map(String::as_str), Some("1-32@172.28.0.21"));
    assert_eq!(creates(verb), Some(Stream::Ordinary));
}

/// GIVEN the same offer
/// WHEN its modifiers are read
/// THEN `c8,101` comes back verbatim and uninterpreted.
///
/// The thing source-reading had not shown me. rtpproxy attaches modifiers to
/// the verb letter, the backlog entry recorded no grammar for them, and real
/// traffic carries them on every call. Preserving them whole is the only
/// honest option: inventing a meaning for `c8,101` would be asserting a
/// grammar nobody promised.
#[test]
fn real_modifiers_survive_verbatim_and_uninterpreted() {
    let RtpproxyControl::Command { modifiers, .. } = decode_command(OFFER).expect("decodes") else {
        panic!("expected a command");
    };
    assert_eq!(modifiers, "c8,101");
}

/// GIVEN the lookup that completed the call
/// WHEN it is decoded
/// THEN it carries both tags and stays inside LOOKUP's bounds.
#[test]
fn the_real_lookup_decodes_with_both_tags() {
    let RtpproxyControl::Command {
        verb,
        modifiers,
        args,
        ..
    } = decode_command(LOOKUP).expect("the lookup decodes")
    else {
        panic!("expected a command");
    };
    assert_eq!(verb, 'L');
    assert_eq!(modifiers, "c8");
    assert_eq!(args.len(), 5, "call-id, address, port, from-tag, to-tag");
    assert_eq!(args[4], "1SIPpTag013;1", "the to-tag completes the dialog");
}

/// GIVEN both real commands
/// WHEN their argument counts are checked
/// THEN each sits inside the bounds its own verb declares.
///
/// The offer is five and the lookup six, against `UPDATE` 5..8 and
/// `LOOKUP` 5..6. The lookup sits exactly on its upper bound, which is the
/// value most likely to be off by one in a table typed from memory.
#[test]
fn real_traffic_sits_inside_the_declared_argument_bounds() {
    for (bytes, want) in [(OFFER, 4usize), (LOOKUP, 5usize)] {
        let RtpproxyControl::Command { args, .. } = decode_command(bytes).expect("decodes") else {
            panic!("expected a command");
        };
        assert_eq!(args.len(), want);
    }
}

// ── The replies ──────────────────────────────────────────────────────────────

/// GIVEN the relay's answer to the offer
/// WHEN it is decoded
/// THEN it is a media reply naming the port it allocated.
#[test]
fn the_real_offer_reply_names_the_allocated_port() {
    let RtpproxyControl::Reply { cookie, reply } = decode_reply(OFFER_REPLY).expect("decodes")
    else {
        panic!("expected a reply");
    };
    assert_eq!(cookie, "29_6976_4");
    assert_eq!(
        reply,
        Reply::Media {
            port: 31032,
            address: "172.28.0.12".to_string()
        }
    );
}

/// GIVEN both replies
/// WHEN their ports are checked
/// THEN both land in rtpproxy's configured range and outside rtpengine's.
#[test]
fn both_real_replies_allocated_inside_the_relays_own_range() {
    for (bytes, want) in [(OFFER_REPLY, 31032u16), (LOOKUP_REPLY, 31000u16)] {
        let RtpproxyControl::Reply { reply, .. } = decode_reply(bytes).expect("decodes") else {
            panic!("expected a reply");
        };
        let Reply::Media { port, .. } = reply else {
            panic!("expected a media reply");
        };
        assert_eq!(port, want);
        assert!((31000..=31050).contains(&port), "{port} outside the range");
        assert!(
            !(30000..=30050).contains(&port),
            "{port} in the other anchor's range"
        );
    }
}

// ── Pairing, which is what a cookie is for ───────────────────────────────────

/// GIVEN a command and its reply
/// WHEN their cookies are compared
/// THEN they match, which is how a passive observer pairs them.
#[test]
fn a_real_command_and_its_reply_share_a_cookie() {
    let cookie = |c: RtpproxyControl| match c {
        RtpproxyControl::Command { cookie, .. } | RtpproxyControl::Reply { cookie, .. } => cookie,
    };
    assert_eq!(
        cookie(decode_command(OFFER).expect("offer")),
        cookie(decode_reply(OFFER_REPLY).expect("reply"))
    );
    assert_eq!(
        cookie(decode_command(LOOKUP).expect("lookup")),
        cookie(decode_reply(LOOKUP_REPLY).expect("reply"))
    );
}

/// GIVEN the two exchanges of one call
/// WHEN their cookies are compared
/// THEN they differ, so two commands are never mistaken for a retransmission.
///
/// The real cookies are `29_6976_4` and `29_6976_5`: a shared prefix and a
/// rising suffix. A pairing rule that matched on the prefix would read every
/// call as one retried command, which is exactly the finding RP4 is for.
#[test]
fn two_exchanges_in_one_call_carry_different_cookies() {
    let cookie = |c: RtpproxyControl| match c {
        RtpproxyControl::Command { cookie, .. } | RtpproxyControl::Reply { cookie, .. } => cookie,
    };
    let first = cookie(decode_command(OFFER).expect("offer"));
    let second = cookie(decode_command(LOOKUP).expect("lookup"));
    assert_ne!(first, second);
    assert!(
        first.rsplit_once('_').map(|(p, _)| p) == second.rsplit_once('_').map(|(p, _)| p),
        "they really do share a prefix, so a prefix match would collapse them"
    );
}

// ── Direction, against real bytes ────────────────────────────────────────────

/// GIVEN a real reply
/// WHEN the command parser is offered it
/// THEN it refuses, because a reply is not a command.
#[test]
fn the_command_parser_refuses_a_real_reply() {
    assert!(
        decode_command(OFFER_REPLY).is_none(),
        "a media reply starts with digits after the cookie, which no command \
         letter can be"
    );
}

/// GIVEN a real command
/// WHEN the reply parser is offered it
/// THEN it does not report an allocated port.
///
/// It decodes as free text rather than refusing, and that is correct: a reply
/// parser's job is to read whatever the relay sent, and only DIRECTION says
/// this came from the wrong side. What it must never do is invent a port.
#[test]
fn the_reply_parser_never_invents_a_port_from_a_command() {
    let decoded = decode_reply(OFFER).expect("it reads as text");
    let RtpproxyControl::Reply { reply, .. } = decoded else {
        panic!("expected a reply");
    };
    assert!(
        !matches!(reply, Reply::Media { .. }),
        "a command read as a reply must not yield a media allocation: {reply:?}"
    );
}
