// SPDX-License-Identifier: MIT OR Apache-2.0

//! Decoding the rtpproxy control protocol, which is text and not bencode.
//!
//! # Where these facts come from
//!
//! Every shape here traces to `sippy/rtpproxy` at `master`, recorded in the
//! RP1 backlog entry on 2026-09-10 rather than recalled. The entry is explicit
//! that the protocol must not be taken from memory, including its author's, so
//! this file implements what was read and nothing more:
//!
//! * command letters from `src/rtpp_command_parse.c`, case-insensitive
//! * `U`/`L` as the media-creating pair, from `handle_command` in
//!   `src/rtpp_command.c`
//! * `R`/`C` creating RECORDING streams, which must never be attributed as an
//!   ordinary leg
//! * the cookie as datagram-only, gated on `umode != 0`
//! * reply grammar from `src/rtpp_command_reply.c`
//! * per-command argument bounds: `UPDATE` 5..8, `LOOKUP` 5..6, `DELETE` 3..4
//!
//! # What is deliberately not decoded
//!
//! Command modifiers. rtpproxy attaches them to the verb letter, and the
//! entry recorded no grammar for them, so they are preserved verbatim and left
//! uninterpreted. Guessing at them would be inventing protocol, which is the
//! one thing the entry forbids.

#![cfg(feature = "full")]

use sipnab::relay::rtpproxy::{Reply, RtpproxyControl, Stream, decode_command, decode_reply};

/// A command, decoded.
fn cmd(text: &str) -> RtpproxyControl {
    decode_command(text.as_bytes()).unwrap_or_else(|| panic!("{text:?} did not decode"))
}

/// A reply, decoded.
fn reply(text: &str) -> RtpproxyControl {
    decode_reply(text.as_bytes()).unwrap_or_else(|| panic!("{text:?} did not decode"))
}

/// The cookie is the first token, and it comes back.
///
/// It is what pairs a reply with its command, and RP4 is built on seeing the
/// same one twice.
#[test]
fn the_cookie_is_the_first_token() {
    let RtpproxyControl::Command { cookie, verb, .. } =
        cmd("24393_4 U call-id 192.0.2.1 16384 from-tag to-tag")
    else {
        panic!("expected a command");
    };
    assert_eq!(cookie, "24393_4");
    assert_eq!(verb, 'U');
}

/// Command letters are case-insensitive, as the parser in rtpproxy is.
#[test]
fn a_lowercase_verb_is_the_same_verb() {
    let RtpproxyControl::Command { verb, .. } = cmd("1 u call-id 192.0.2.1 16384 from-tag to-tag")
    else {
        panic!("expected a command");
    };
    assert_eq!(verb, 'U', "the verb is normalized, not echoed");
}

/// `U` and `L` may create media; the rest may not.
///
/// The distinction the whole attribution path rests on. `handle_command`
/// inverts `find_stream` for every op except `UPDATE`, which is the one that
/// can create the session.
#[test]
fn only_update_and_lookup_create_ordinary_media() {
    for (verb, want) in [
        ('U', Some(Stream::Ordinary)),
        ('L', Some(Stream::Ordinary)),
        ('R', Some(Stream::Recording)),
        ('C', Some(Stream::Recording)),
        ('D', None),
        ('P', None),
        ('S', None),
        ('N', None),
        ('V', None),
        ('I', None),
        ('Q', None),
        ('X', None),
        ('G', None),
    ] {
        assert_eq!(
            sipnab::relay::rtpproxy::creates(verb),
            want,
            "verb {verb} classified wrongly"
        );
    }
}

/// A recording stream is NOT an ordinary leg, and the type says so.
///
/// This is the case the NG decoder's `MediaCreating` comment exists for:
/// attributing a recording or forking stream as an ordinary leg invents a
/// participant the call never had.
#[test]
fn a_recording_stream_is_never_an_ordinary_one() {
    assert_ne!(Stream::Recording, Stream::Ordinary);
    assert_eq!(
        sipnab::relay::rtpproxy::creates('R'),
        Some(Stream::Recording)
    );
    assert_ne!(
        sipnab::relay::rtpproxy::creates('R'),
        Some(Stream::Ordinary),
        "a recording stream attributed as a leg invents a participant"
    );
}

/// An error reply carries its code.
#[test]
fn an_error_reply_is_read_as_an_error() {
    let RtpproxyControl::Reply { cookie, reply } = reply("24393_4 E8\n") else {
        panic!("expected a reply");
    };
    assert_eq!(cookie, "24393_4");
    assert_eq!(reply, Reply::Error(8));
}

/// A media reply carries the port and address `U`/`L` return.
#[test]
fn a_media_reply_carries_the_port_and_address() {
    let RtpproxyControl::Reply { reply, .. } = reply("7 16384 192.0.2.10\n") else {
        panic!("expected a reply");
    };
    assert_eq!(
        reply,
        Reply::Media {
            port: 16384,
            address: "192.0.2.10".to_string()
        }
    );
}

/// A numeric reply is its own shape, not a media reply missing an address.
#[test]
fn a_numeric_reply_is_not_a_truncated_media_reply() {
    let RtpproxyControl::Reply { reply, .. } = reply("7 20040702\n") else {
        panic!("expected a reply");
    };
    assert_eq!(reply, Reply::Number(20_040_702));
}

/// Argument counts outside the documented bounds are refused.
///
/// `UPDATE` takes 5..8, `LOOKUP` 5..6, `DELETE` 3..4, counting the way
/// rtpproxy counts. A command with the wrong shape is not a command with a
/// missing field: decoding it anyway would report a call-id read out of the
/// wrong position.
#[test]
fn a_command_outside_its_argument_bounds_is_refused() {
    assert!(
        decode_command(b"1 U call-id").is_none(),
        "UPDATE with two args must not decode"
    );
    assert!(
        decode_command(b"1 U a b c d e f g h i j").is_none(),
        "UPDATE past its upper bound must not decode"
    );
    assert!(
        decode_command(b"1 D call-id").is_none(),
        "DELETE with two args must not decode"
    );
    assert!(
        decode_command(b"1 U call-id 192.0.2.1 16384 from-tag").is_some(),
        "and a command INSIDE its bounds must decode, or this proves nothing"
    );
}

/// Garbage is refused rather than half-read.
#[test]
fn malformed_input_is_refused() {
    let cases: [&[u8]; 6] = [
        b"",
        b"\n",
        b"onlyacookie",
        b"1 ",
        b"1 Z call-id a b c",
        &[0xFF, 0xFE, 0xFD],
    ];
    for bad in cases {
        assert!(decode_command(bad).is_none(), "{bad:?} was accepted");
    }
}

/// An unterminated line of unbounded length is refused, not buffered.
///
/// The denial-of-service shape a text protocol has and a binary one does not.
/// The NG path's sweep asserts RSS growth under 0.8 MB over 20,000 rounds;
/// this is the same concern at the parser's own boundary.
#[test]
fn an_unbounded_token_is_refused() {
    let huge = format!("{} U call-id 192.0.2.1 16384 f t", "9".repeat(100_000));
    assert!(
        decode_command(huge.as_bytes()).is_none(),
        "a cookie of unbounded length must not decode"
    );
}

// ── Against a real relay ─────────────────────────────────────────────────────
//
// Every byte string below was sent by rtpproxy 3.2.0 (`630f75e`) running on the
// lab VM beside rtpengine, captured on 2026-09-11. Fixtures written from a
// reading of the source are a second opinion about the source; these are the
// wire.

/// The `I` reply is free text, and reading it as a command was a real defect.
///
/// Found by asking a live relay rather than by review. The reply begins
/// `<cookie> sessions created: ...`, and `sessions` starts with `s`, which is
/// also the stop-play command letter. Decoding by content produced a confident
/// `S` command carrying fourteen arguments — not a refusal, a WRONG answer
/// with structure, which is the failure this whole module is careful about.
///
/// Direction decides now: a datagram from the relay is a reply, whatever its
/// second token happens to start with.
#[test]
fn the_info_reply_is_text_and_not_a_stop_play_command() {
    let observed = "c3 sessions created: 0\nactive sessions: 0\nactive streams: 0\npackets received: 0\npackets transmitted: 0\n";
    let RtpproxyControl::Reply { cookie, reply: r } = reply(observed) else {
        panic!("the info reply must decode as a reply");
    };
    assert_eq!(cookie, "c3");
    let Reply::Text(body) = r else {
        panic!("the info reply is free text, not a number or a media pair");
    };
    assert!(
        body.contains("sessions created:") && body.contains("packets transmitted:"),
        "the report must come back whole: {body:?}"
    );
}

/// The media reply a real `U` produced, port and all.
///
/// `c4 U call-abc 10.0.0.99 12000 ftag` → `c4 50282 10.0.0.40`. The port is
/// inside 41000-51000, which is rtpproxy's range on that host and deliberately
/// clear of rtpengine's 30000-40000.
#[test]
fn a_real_update_reply_decodes_to_the_port_it_allocated() {
    let RtpproxyControl::Reply { reply: r, .. } = reply("c4 50282 10.0.0.40\n") else {
        panic!("expected a reply");
    };
    assert_eq!(
        r,
        Reply::Media {
            port: 50282,
            address: "10.0.0.40".to_string()
        }
    );
}

/// Real error and version replies, exactly as the relay wrote them.
#[test]
fn real_error_and_version_replies_decode() {
    let RtpproxyControl::Reply { reply: e, .. } = reply("c7 E50\n") else {
        panic!("expected a reply");
    };
    assert_eq!(e, Reply::Error(50), "a Q for an unknown call answered E50");

    let RtpproxyControl::Reply { reply: v, .. } = reply("c1 20040107\n") else {
        panic!("expected a reply");
    };
    assert_eq!(
        v,
        Reply::Number(20_040_107),
        "the protocol version it reports"
    );
}

/// The command parser refuses the real `I` reply, on content.
///
/// This test asserted the opposite of itself an hour ago. I claimed content
/// could not separate a command from a reply, corrected the test to say so, and
/// was wrong on both counts. Two rules in `rtpp_command_parse.c` refuse this
/// datagram outright, and I had read neither:
///
/// * a command is ONE line, and this reply is five
/// * stop-play has `has_cmods = 0`, so the verb token is `S` exactly and
///   `Sessions` is not a command with modifiers
///
/// Either alone is decisive. The argument count settles it a third time: `S`
/// takes 3..4 and this carries fifteen.
#[test]
fn the_command_parser_refuses_the_real_info_reply() {
    let observed = b"c3 sessions created: 0\nactive sessions: 0\nactive streams: 0\npackets received: 0\npackets transmitted: 0\n";
    assert!(
        decode_command(observed).is_none(),
        "the command parser accepted a reply, which is the confident wrong \
         answer a live relay already demonstrated"
    );
    assert!(
        matches!(decode_reply(observed), Some(RtpproxyControl::Reply { .. })),
        "and it must still decode as what it is"
    );
}

/// A command carrying an embedded newline is refused.
///
/// The line rule on its own, away from the reply that exposed it. rtpproxy's
/// protocol is line-oriented; `split_ascii_whitespace` is not, and that gap is
/// what let a multi-line datagram parse as one command with its later lines as
/// arguments.
#[test]
fn a_command_may_not_span_lines() {
    assert!(
        decode_command(b"1 U call-id 192.0.2.1 16384 ftag\n").is_some(),
        "a trailing newline is fine, or this proves nothing"
    );
    assert!(
        decode_command(b"1 U call-id 192.0.2.1\n16384 ftag").is_none(),
        "a command split across two lines must not decode"
    );
}

/// A command that takes no modifiers gets none.
///
/// `S`, `V` and `X` carry `has_cmods = 0` in the parser. Accepting a suffix on
/// those was what made `Sessions` look like stop-play, and the rule is the
/// relay's rather than one invented here.
#[test]
fn a_command_without_modifiers_refuses_a_suffix() {
    assert!(
        decode_command(b"1 S call-id ftag ttag").is_some(),
        "bare S is a real command"
    );
    for bad in [
        b"1 Sessions call-id ftag ttag".as_slice(),
        b"1 Vx".as_slice(),
        b"1 Xyz".as_slice(),
    ] {
        assert!(
            decode_command(bad).is_none(),
            "{bad:?} carries a suffix on a command that takes none"
        );
    }
    assert!(
        decode_command(b"1 Ib").is_some(),
        "and I DOES take modifiers, so the rule must not be a blanket ban"
    );
}

/// Every command's bounds come from the parser's own table.
///
/// The first version of this carried real numbers for three commands and
/// `(1, 20)` for the other ten. A default that generous is not a bound; it is
/// the absence of one, wearing a bound's clothes.
#[test]
fn every_command_carries_the_bounds_the_relay_enforces() {
    // (verb, a shape inside its bounds, a shape outside)
    for (ok, bad) in [
        ("1 P call-id prompt ftag ttag", "1 P call-id"),
        ("1 R call-id ftag", "1 R"),
        ("1 C call-id arg ftag", "1 C call-id"),
        ("1 N call-id ftag", "1 N"),
        ("1 X", "1 X call-id"),
        ("1 V", "1 V a b c"),
    ] {
        assert!(
            decode_command(ok.as_bytes()).is_some(),
            "{ok:?} must decode"
        );
        assert!(
            decode_command(bad.as_bytes()).is_none(),
            "{bad:?} is outside the bounds the relay enforces"
        );
    }
}

// ── Behind the seam ──────────────────────────────────────────────────────────

/// The decoder registers as the seam's first implementation.
///
/// RP2 built the seam and left it with no implementer. This is the proof it
/// works, which is what that entry asked RP1 to be.
#[test]
fn the_decoder_answers_the_seam() {
    use sipnab::relay::rtpproxy::RtpproxyDecoder;
    use sipnab::relay::{ControlDecoder, ControlDelivery};

    let d = RtpproxyDecoder::on_port(7722);
    let out = d
        .decode(b"c4 U call-abc 10.0.0.99 12000 ftag\n", 7722)
        .expect("a command to the control port decodes");
    assert_eq!(out.message.command.as_deref(), Some("U"));
    assert_eq!(out.message.call_id.as_deref(), Some("call-abc"));
    assert_eq!(out.correlation_id.as_deref(), Some("c4"));
    assert_eq!(
        out.delivery,
        ControlDelivery::BareDatagram,
        "a sniffed datagram carries no credential, so it may not claim one"
    );
    assert!(
        out.message.sdp_bytes.is_none(),
        "rtpproxy's text protocol carries no SDP; claiming a byte count would \
         invent one"
    );
    assert!(
        out.on_believed_mirror_port.is_none(),
        "a bare datagram is believed on no port, which is not the same as \
         being disbelieved on this one"
    );
}

/// The same bytes from the other direction decode as a reply, not a command.
#[test]
fn the_seam_reads_direction_from_the_port() {
    use sipnab::relay::ControlDecoder;
    use sipnab::relay::rtpproxy::RtpproxyDecoder;

    let d = RtpproxyDecoder::on_port(7722);
    let from_relay = d
        .decode(b"c4 50282 10.0.0.40\n", 40000)
        .expect("a reply from the relay decodes");
    assert!(
        from_relay.message.command.is_none(),
        "a reply names no command: {:?}",
        from_relay.message.command
    );
    assert_eq!(from_relay.correlation_id.as_deref(), Some("c4"));
}

/// A command with no call-id does not borrow one from its arguments.
///
/// `V`, `I`, `X` and `G` carry `has_call_id = 0`. Reading the first argument
/// as a call-id would name a call from whatever happened to sit there.
#[test]
fn a_command_without_a_call_id_names_no_call() {
    use sipnab::relay::ControlDecoder;
    use sipnab::relay::rtpproxy::RtpproxyDecoder;

    let d = RtpproxyDecoder::on_port(7722);
    for bytes in [b"1 V".as_slice(), b"1 X".as_slice(), b"1 I".as_slice()] {
        let out = d.decode(bytes, 7722).expect("decodes");
        assert!(
            out.message.call_id.is_none(),
            "{bytes:?} named a call it does not carry: {:?}",
            out.message.call_id
        );
    }
}

/// Only ordinary media counts toward the unattributed tally.
///
/// `R` and `C` create RECORDING streams, and RE5 attributes those from the
/// recording spool rather than by decoding these commands. Counting them here
/// would double-count the thing another mechanism owns.
///
/// This asserts the CLASSIFICATION `creates`, not the process-global tally the
/// decoder increments from it. The tally is shared across every test in the
/// binary, so a before/after read of it races any concurrent test that decodes
/// an ordinary-media command -- which is exactly how this test failed in CI
/// while passing locally, on 2026-09-13. The rule is single-sourced: the
/// decoder increments the tally iff `creates(verb) == Some(Stream::Ordinary)`
/// (see `src/relay/rtpproxy.rs`), so proving the classification proves the
/// tally behavior without reading shared state.
#[test]
fn recording_commands_do_not_inflate_the_media_tally() {
    use sipnab::relay::rtpproxy::{Stream, creates};

    // The recording verbs are Recording, not Ordinary, so the decoder's
    // `creates(...) == Some(Stream::Ordinary)` guard is false for them and the
    // tally is never touched.
    for verb in ['R', 'C', 'r', 'c'] {
        assert_eq!(
            creates(verb),
            Some(Stream::Recording),
            "{verb} creates a recording stream, not an ordinary leg"
        );
        assert_ne!(
            creates(verb),
            Some(Stream::Ordinary),
            "{verb} must not be classed as ordinary media, or it would inflate \
             the unattributed tally"
        );
    }
    // And an ordinary media verb IS Ordinary, so the guard is not vacuously
    // false for everything -- without this, `creates` returning `None` for all
    // input would pass the assertions above while counting nothing ever.
    assert_eq!(
        creates('U'),
        Some(Stream::Ordinary),
        "an update/offer creates ordinary media and DOES count"
    );
}
