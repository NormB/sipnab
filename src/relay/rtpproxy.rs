// SPDX-License-Identifier: MIT OR Apache-2.0

//! The rtpproxy control protocol, which is text and not bencode.
//!
//! # Where these facts come from
//!
//! Every rule here traces to `sippy/rtpproxy` at `master`, read on 2026-09-10
//! and recorded in the RP1 backlog entry rather than recalled. That entry is
//! explicit that the protocol must not be taken from memory, including its
//! author's, so this decodes what was read and refuses the rest:
//!
//! * command letters from `src/rtpp_command_parse.c`, case-insensitive
//! * `U`/`L` as the media-creating pair, from `handle_command` in
//!   `src/rtpp_command.c`, which inverts `find_stream` for every op but
//!   `UPDATE`
//! * `R`/`C` creating RECORDING streams
//! * the cookie as datagram-only, gated on `umode != 0` with the comment
//!   *"Stream communication mode doesn't use cookie"*
//! * reply grammar from `src/rtpp_command_reply.c`
//! * argument bounds: `UPDATE` 5..8, `LOOKUP` 5..6, `DELETE` 3..4
//!
//! # A recording stream is not a leg
//!
//! `R` and `C` create streams, and attributing one as an ordinary participant
//! invents somebody the call never had. [`Stream`] keeps the two apart at the
//! type level rather than in a caller's memory, which is the same reason the
//! NG decoder carries `MediaCreating`.
//!
//! # What this deliberately does not decode
//!
//! Command modifiers. rtpproxy attaches them to the verb letter and the entry
//! recorded no grammar for them, so they are preserved verbatim and left
//! uninterpreted. Guessing would be inventing protocol.
//!
//! # There is no port to key a heuristic on
//!
//! The documented control socket is a UNIX socket, which a passive capture
//! cannot see at all, and no default UDP port is documented anywhere. So this
//! serves deployments that configured a UDP control socket, and the operator
//! has to name the port. Nothing here guesses one.

/// What a command creates, when it creates anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// A media stream between the call's own participants.
    Ordinary,
    /// A recording or forking stream. Never an ordinary leg: attributing one
    /// as a participant invents somebody the call never had.
    Recording,
}

/// A reply, in the three shapes `src/rtpp_command_reply.c` writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// `E<decimal>` — codes are in `src/rtpp_command_ecodes.h`.
    Error(u32),
    /// A bare integer, which `V` and the stats commands return.
    Number(i64),
    /// The `<port> <address>` pair `U` and `L` return.
    Media {
        /// Port the relay allocated.
        port: u16,
        /// Address it allocated the port on, as written.
        address: String,
    },
    /// Free text, which `I` and the stats commands return over several lines.
    ///
    /// Kept verbatim and unparsed. Those lines are a human-readable report
    /// whose shape is not a wire contract, and inventing a schema for them
    /// would assert a grammar the relay never offered.
    Text(String),
}

/// One decoded control datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtpproxyControl {
    /// A command from the signaling element to the relay.
    Command {
        /// Leading cookie, which pairs this with its reply.
        cookie: String,
        /// The verb, normalized to upper case.
        verb: char,
        /// Anything attached to the verb letter, preserved and uninterpreted.
        modifiers: String,
        /// Arguments after the verb, in wire order.
        args: Vec<String>,
    },
    /// A reply from the relay.
    Reply {
        /// The cookie echoed back, which is how a duplicate is visible.
        cookie: String,
        /// What it said.
        reply: Reply,
    },
}

/// Longest token this will read, in bytes.
///
/// A text protocol's denial-of-service shape is an unbounded token — a cookie
/// with no end, a line with no terminator — which a length-prefixed binary
/// protocol cannot have. rtpproxy's own buffers are far smaller than this; the
/// bound exists so a sniffed datagram cannot make the decoder allocate.
const MAX_TOKEN: usize = 512;

/// Longest datagram this will look at.
const MAX_DATAGRAM: usize = 8192;

/// What `verb` creates, or `None` when it creates nothing.
///
/// `U` may create the session and `L` looks one up; both yield ordinary media.
/// `R` and `C` create RECORDING streams, which is the distinction the whole
/// attribution path rests on.
#[must_use]
pub fn creates(verb: char) -> Option<Stream> {
    match verb.to_ascii_uppercase() {
        'U' | 'L' => Some(Stream::Ordinary),
        'R' | 'C' => Some(Stream::Recording),
        _ => None,
    }
}

/// What one command letter permits, read from `rtpp_command_parse.c`.
///
/// `(min_argc, max_argc, modifiers allowed)`, counted as rtpproxy counts: the
/// verb token plus its arguments. Every field is the value in that file's arm
/// for the letter, not a default invented here -- the first version of this
/// function carried real bounds for three commands and `(1, 20)` for the other
/// ten, which is how a five-line `I` REPLY decoded as a confident `S` command
/// with fourteen arguments.
///
/// `RTPP_QUERY_NSTATS` and the `get_stats` count are runtime values in
/// rtpproxy, so `Q` and `G` take the parser's own ceiling here. Both are
/// bounded, which is the property that matters; neither is `usize::MAX`.
fn command_rules(verb: char) -> Option<(usize, usize, bool)> {
    Some(match verb {
        'U' => (5, 8, true),
        'L' => (5, 6, true),
        'D' => (3, 4, true),
        'P' => (5, 6, true),
        'R' => (3, 4, true),
        'C' => (4, 5, true),
        // Stop-play takes NO modifiers, which is the rule that refuses
        // `Sessions` -- the first word of the `I` reply -- on its face.
        'S' => (3, 4, false),
        'N' => (3, 4, true),
        // `V` alone, or `VF <n>`; neither takes further modifiers.
        'V' => (1, 2, false),
        'I' => (1, 1, true),
        'Q' => (3, RTPC_MAX_ARGC, true),
        'X' => (1, 1, false),
        'G' => (1, RTPC_MAX_ARGC, true),
        _ => return None,
    })
}

/// Ceiling for the two commands whose real maximum is a runtime value.
///
/// `Q` is `4 + RTPP_QUERY_NSTATS` and `G` is the statistic count plus one, both
/// resolved inside rtpproxy. A fixed bound here is the honest approximation:
/// it is generous enough not to refuse real traffic and finite, which is the
/// property a sniffed datagram must not be able to defeat.
const RTPC_MAX_ARGC: usize = 64;

/// Decode one control datagram, given which way it was going.
///
/// `to_relay` is the caller's statement of direction, not a guess made here.
/// Content cannot separate the two grammars: an `I` reply begins
/// `<cookie> sessions created: ...` and `sessions` starts with the stop-play
/// letter, so parsing it as a command yields a confident wrong answer. A
/// passive observer knows the direction from the destination port, which is
/// why the seam passes one.
#[must_use]
pub fn decode(payload: &[u8], to_relay: bool) -> Option<RtpproxyControl> {
    if to_relay {
        decode_command(payload)
    } else {
        decode_reply(payload)
    }
}

/// Decode a datagram heading TO the relay, which is a command.
#[must_use]
pub fn decode_command(payload: &[u8]) -> Option<RtpproxyControl> {
    if payload.is_empty() || payload.len() > MAX_DATAGRAM {
        return None;
    }
    let text = std::str::from_utf8(payload).ok()?;
    // A command is ONE line. The protocol is line-oriented, and treating `\n`
    // as ordinary whitespace is what let a five-line reply flatten into a
    // single command carrying its later lines as arguments. Checked before
    // anything is parsed, because it is decidable from the bytes alone.
    if text.trim_end_matches(['\r', '\n']).contains(['\n', '\r']) {
        return None;
    }
    let mut tokens = text.split_ascii_whitespace();
    let cookie = tokens.next()?;
    if cookie.len() > MAX_TOKEN {
        return None;
    }
    let second = tokens.next()?;
    if second.len() > MAX_TOKEN {
        return None;
    }

    // The verb is the first character; anything after it on that token is a
    // modifier this does not interpret.
    let verb = second.chars().next()?.to_ascii_uppercase();
    let modifiers = second[verb.len_utf8()..].to_string();
    let args: Vec<String> = tokens
        .map(std::string::ToString::to_string)
        .take_while(|t| t.len() <= MAX_TOKEN)
        .collect();

    // Counted as rtpproxy counts: the verb token plus its arguments.
    let (low, high, modifiers_allowed) = command_rules(verb)?;
    if !modifiers_allowed && !modifiers.is_empty() {
        return None;
    }
    let argc = 1 + args.len();
    if argc < low || argc > high {
        return None;
    }

    Some(RtpproxyControl::Command {
        cookie: cookie.to_string(),
        verb,
        modifiers,
        args,
    })
}

/// Decode a datagram heading FROM the relay, which is a reply.
///
/// Three shapes from `src/rtpp_command_reply.c` plus the free text `I` and the
/// stats commands return. The cookie comes first in every one, which is what
/// pairs a reply with its command and what makes a retransmission visible.
#[must_use]
pub fn decode_reply(payload: &[u8]) -> Option<RtpproxyControl> {
    if payload.is_empty() || payload.len() > MAX_DATAGRAM {
        return None;
    }
    let text = std::str::from_utf8(payload).ok()?;
    let (cookie, rest) = text.split_once(char::is_whitespace)?;
    if cookie.is_empty() || cookie.len() > MAX_TOKEN {
        return None;
    }
    let rest = rest.trim_end_matches(['\r', '\n']);
    if rest.is_empty() {
        return None;
    }

    let reply = if let Some(code) = rest.strip_prefix(['E', 'e'])
        && !code.is_empty()
        && code.bytes().all(|b| b.is_ascii_digit())
    {
        Reply::Error(code.parse().ok()?)
    } else {
        let mut fields = rest.split_ascii_whitespace();
        let first = fields.next()?;
        let second = fields.next();
        match (first.bytes().all(|b| b.is_ascii_digit()), second) {
            // `<port> <address>`, and nothing after it.
            (true, Some(address)) if fields.next().is_none() && address.len() <= MAX_TOKEN => {
                Reply::Media {
                    port: first.parse().ok()?,
                    address: address.to_string(),
                }
            }
            (true, None) => Reply::Number(first.parse().ok()?),
            // Anything else is the free-text report. Kept whole rather than
            // parsed: its lines are a human-readable shape nobody promised as
            // a wire contract, and inventing a schema for them would assert a
            // grammar the relay never offered.
            _ => Reply::Text(rest.to_string()),
        }
    };

    Some(RtpproxyControl::Reply {
        cookie: cookie.to_string(),
        reply,
    })
}

/// The rtpproxy control decoder, behind the relay seam.
///
/// Holds the control port because nothing else can know it. rtpproxy documents
/// a UNIX socket, which a passive capture cannot see at all, and no default UDP
/// port is documented anywhere -- so an operator names the port or there is
/// nothing to decode. Guessing one would make every datagram on some arbitrary
/// port a candidate control message.
#[derive(Debug, Clone, Copy)]
pub struct RtpproxyDecoder {
    /// The UDP port the relay's control socket listens on.
    control_port: u16,
}

impl RtpproxyDecoder {
    /// A decoder for a relay whose control socket the operator has named.
    #[must_use]
    pub fn on_port(control_port: u16) -> Self {
        Self { control_port }
    }
}

impl super::ControlDecoder for RtpproxyDecoder {
    /// Decode a sniffed datagram, using its destination to know which way it
    /// went.
    ///
    /// This is why the seam passes a port. Commands and replies share a cookie
    /// and cannot be told apart by content alone in every case -- a real `I`
    /// reply parses as a plausible command until the line, modifier and
    /// argument-count rules refuse it, and relying on those alone would leave
    /// the next reply shape to find the same hole again.
    fn decode(&self, payload: &[u8], dst_port: u16) -> Option<super::DecodedControl> {
        let to_relay = dst_port == self.control_port;
        let decoded = decode(payload, to_relay)?;

        let (command, call_id, correlation_id) = match &decoded {
            RtpproxyControl::Command {
                cookie, verb, args, ..
            } => {
                if creates(*verb) == Some(Stream::Ordinary) {
                    super::note_media_creating_command();
                }
                // `has_call_id` is 0 for `V`, `I`, `X` and `G`; for the rest
                // the call-id is the first argument. Reading one out of a
                // command that carries none would name a call from whatever
                // happened to sit in that position.
                let call_id = match verb {
                    'V' | 'I' | 'X' | 'G' => None,
                    _ => args.first().cloned(),
                };
                (Some(verb.to_string()), call_id, Some(cookie.clone()))
            }
            RtpproxyControl::Reply { cookie, .. } => (None, None, Some(cookie.clone())),
        };

        Some(super::DecodedControl {
            // A sniffed UDP datagram is authenticated by nothing. rtpproxy's
            // text protocol carries no credential of any kind, so there is no
            // stronger claim available to make.
            delivery: super::ControlDelivery::BareDatagram,
            message: super::ControlMessage {
                command,
                call_id,
                // rtpproxy's text protocol carries no SDP. Unlike rtpengine's
                // ng, the signaling element parses and rewrites SDP itself and
                // tells the relay only addresses and ports, so `None` here is
                // a property of the protocol rather than a gap in this
                // decoder.
                sdp_bytes: None,
            },
            correlation_id,
            // A bare datagram is not believed on any port, so the question
            // does not apply -- which is not the same as answering `false`.
            on_believed_mirror_port: None,
        })
    }
}
