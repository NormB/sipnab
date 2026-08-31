// SPDX-License-Identifier: MIT OR Apache-2.0

//! rtpengine's `ng` control messages.
//!
//! The wire format is a cookie, one space, and a bencoded dictionary:
//!
//! ```text
//! 14661e9e... d7:command5:offer7:call-id18:km-670bd208@sipnab8:from-tag5:ftag13:sdp122:v=0...e
//! ```
//!
//! The cookie is rtpengine's retransmission key, not ours: it replies to a
//! repeated cookie from a cache instead of re-processing the command. That is
//! observable and it matters to anything that SENDS `ng` — reusing a cookie
//! gets a stale answer, and a control client that reused one would receive
//! port allocations belonging to a call it had already torn down.
//!
//! # Requests name their call; replies do not
//!
//! A request carries `call-id`. A REPLY carries `result` and, for `offer` and
//! `answer`, the rewritten `sdp` — and no `call-id` at all. Measured against
//! rtpengine 12.5.1, an offer reply's entire body is `d3:sdp136:v=0...e`.
//!
//! This asymmetry is the reason the delivery path was chosen the way it was.
//! The reply is the half that carries the relay's OWN allocated ports, which
//! is precisely the half worth having, and on the wire it can only be tied to
//! a call by remembering which cookie went with which `call-id`. Delivered
//! over HEP, rtpengine puts the Call-ID in the correlation-id chunk of every
//! message in both directions, so the tie arrives with the message and no
//! transaction state is needed. [`NgMessage::call_id`] is therefore `None` on
//! replies by design, and the caller supplies the correlation-id it was
//! delivered with.

use anyhow::{Result, bail, ensure};

use super::bencode::{self, Value};

/// What a control message asks rtpengine to do.
///
/// Only the three that carry the join key are named. The rest are split into
/// the ones that CREATE MEDIA — which matter because their streams would be
/// misattributed if treated as ordinary legs — and everything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NgCommand<'a> {
    /// Caller's SDP; the reply carries the port the callee will send to.
    Offer,
    /// Callee's SDP; the reply carries the port the caller will send to.
    Answer,
    /// Tears the call down and releases its ports.
    Delete,
    /// A command that creates an ADDITIONAL media stream belonging to the call
    /// without being one of its two legs: recording and forking.
    ///
    /// Deliberately not decoded into endpoints. Such a stream attributed as an
    /// ordinary leg turns a two-party call into a three-stream one, and the
    /// media analysis that judges one-way audio and asymmetry then answers a
    /// question nobody asked. Recognized only so a run can SAY it saw them.
    MediaCreating(&'a str),
    /// Anything else rtpengine understands (`ping`, `list`, `query`, ...).
    Other(&'a str),
}

impl NgCommand<'_> {
    /// Commands that create a media stream which is not one of the call's legs.
    ///
    /// From rtpengine's `ng` command set. `subscribe request`/`subscribe
    /// answer` set up a copy of a call's media for a third party; `publish`
    /// makes an inbound-only stream; `start recording` and `block`/`unblock`
    /// variants change what the relay does with media it already has.
    const MEDIA_CREATING: &'static [&'static str] = &[
        "subscribe request",
        "subscribe answer",
        "unsubscribe",
        "publish",
        "start recording",
        "stop recording",
        "start forwarding",
        "stop forwarding",
    ];

    /// Classify a command string.
    #[must_use]
    pub fn classify(name: &str) -> NgCommand<'_> {
        match name {
            "offer" => NgCommand::Offer,
            "answer" => NgCommand::Answer,
            "delete" => NgCommand::Delete,
            other if Self::MEDIA_CREATING.contains(&other) => NgCommand::MediaCreating(other),
            other => NgCommand::Other(other),
        }
    }
}

/// One decoded `ng` message, borrowing from the datagram it came from.
#[derive(Debug, Clone)]
pub struct NgMessage<'a> {
    /// rtpengine's retransmission key for this transaction.
    pub cookie: &'a [u8],
    /// The command, absent on replies.
    pub command: Option<NgCommand<'a>>,
    /// `result` — `ok`, `error`, ... — present only on replies.
    pub result: Option<&'a [u8]>,
    /// The call this names. Absent on replies; see the module note.
    pub call_id: Option<&'a [u8]>,
    /// SIP `From` tag, on requests that carry one.
    pub from_tag: Option<&'a [u8]>,
    /// SIP `To` tag, on `answer` and on later requests.
    pub to_tag: Option<&'a [u8]>,
    /// The SDP body: the offered/answered one on a request, the REWRITTEN one
    /// on a reply. Bytes, not text, and handed on unmodified.
    pub sdp: Option<&'a [u8]>,
    /// The whole decoded dictionary, for fields this struct does not name.
    pub body: Value<'a>,
}

impl<'a> NgMessage<'a> {
    /// Whether this message is a reply rather than a command.
    ///
    /// Keyed on the ABSENCE of `command` rather than the presence of `result`:
    /// a reply to `delete` carries neither an `sdp` nor anything else useful,
    /// and rtpengine's error replies vary in what they include.
    #[must_use]
    pub fn is_reply(&self) -> bool {
        self.command.is_none()
    }
}

/// Decode one `ng` datagram.
///
/// # Errors
///
/// Returns an error when the cookie/body separator is missing, when the cookie
/// is empty, or when the body is not a single well-formed bencode dictionary.
pub fn parse(input: &[u8]) -> Result<NgMessage<'_>> {
    // The separator is the FIRST space. A cookie contains none, and the body
    // begins with `d`, so scanning further would only find spaces inside SDP.
    let Some(sep) = input.iter().position(|&b| b == b' ') else {
        bail!("ng: no space separating the cookie from the body");
    };
    let cookie = &input[..sep];
    ensure!(!cookie.is_empty(), "ng: empty cookie");

    let body = bencode::decode(&input[sep + 1..])?;
    // A non-dictionary body is not an `ng` message. Checked rather than
    // assumed, because every accessor below would silently return `None` on
    // one and the message would look like an empty but valid command.
    ensure!(
        matches!(body, Value::Dict(_)),
        "ng: body is a {}, not a dictionary",
        match body {
            Value::Int(_) => "integer",
            Value::Bytes(_) => "byte string",
            Value::List(_) => "list",
            Value::Dict(_) => unreachable!("guarded by this very match"),
        }
    );

    let command = match body.get_bytes(b"command") {
        None => None,
        Some(raw) => {
            let name = std::str::from_utf8(raw)
                .map_err(|_| anyhow::anyhow!("ng: command name is not UTF-8"))?;
            Some(NgCommand::classify(name))
        }
    };

    Ok(NgMessage {
        cookie,
        command,
        result: body.get_bytes(b"result"),
        call_id: body.get_bytes(b"call-id"),
        from_tag: body.get_bytes(b"from-tag"),
        to_tag: body.get_bytes(b"to-tag"),
        sdp: body.get_bytes(b"sdp"),
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped exactly like the live offer in the committed fixture.
    fn offer_bytes() -> Vec<u8> {
        let sdp = "v=0\r\nc=IN IP4 10.0.0.60\r\nm=audio 40001 RTP/AVP 0";
        format!(
            "cookie1 d7:command5:offer7:call-id18:km-670bd208@sipnab8:from-tag5:ftag13:sdp{}:{sdp}e",
            sdp.len()
        )
        .into_bytes()
    }

    /// The offer REPLY as rtpengine actually sends it: no `call-id`, no
    /// `command`, just the rewritten SDP.
    fn offer_reply_bytes() -> Vec<u8> {
        let sdp = "v=0\r\nc=IN IP4 10.0.0.40\r\nm=audio 38664 RTP/AVP 0";
        format!("cookie1 d3:sdp{}:{sdp}6:result2:oke", sdp.len()).into_bytes()
    }

    #[test]
    fn parses_a_request_and_names_its_call() {
        let raw = offer_bytes();
        let m = parse(&raw).expect("offer parses");
        assert_eq!(m.cookie, b"cookie1");
        assert_eq!(m.command, Some(NgCommand::Offer));
        assert_eq!(m.call_id, Some(&b"km-670bd208@sipnab"[..]));
        assert_eq!(m.from_tag, Some(&b"ftag1"[..]));
        assert_eq!(m.to_tag, None);
        assert!(!m.is_reply());
        assert!(
            m.sdp.expect("sdp").starts_with(b"v=0\r\n"),
            "SDP handed on byte-exact"
        );
    }

    /// The asymmetry this whole delivery choice rests on. If this ever starts
    /// returning a call-id, the argument for HEP over a wire sniffer weakens
    /// and someone should re-read the module note before acting on it.
    #[test]
    fn a_reply_carries_the_rewritten_sdp_and_no_call_id() {
        let raw = offer_reply_bytes();
        let m = parse(&raw).expect("reply parses");
        assert!(m.is_reply(), "no command means reply");
        assert_eq!(m.command, None);
        assert_eq!(m.result, Some(&b"ok"[..]));
        assert_eq!(
            m.call_id, None,
            "rtpengine replies do NOT name the call; the correlation-id does"
        );
        assert!(
            m.sdp.expect("sdp").contains_str("38664"),
            "the reply is what carries the relay's allocated port"
        );
    }

    #[test]
    fn classifies_the_commands_that_carry_the_join_key() {
        assert_eq!(NgCommand::classify("offer"), NgCommand::Offer);
        assert_eq!(NgCommand::classify("answer"), NgCommand::Answer);
        assert_eq!(NgCommand::classify("delete"), NgCommand::Delete);
        assert_eq!(NgCommand::classify("ping"), NgCommand::Other("ping"));
    }

    /// RE5: these must be recognized distinctly so a run can report them as
    /// unattributed, rather than either attributing them or staying quiet.
    #[test]
    fn recognizes_media_creating_commands_separately() {
        for name in ["subscribe request", "publish", "start recording"] {
            assert_eq!(
                NgCommand::classify(name),
                NgCommand::MediaCreating(name),
                "{name} must be recognized as media-creating"
            );
        }
        assert_ne!(
            NgCommand::classify("start recording"),
            NgCommand::Other("start recording")
        );
    }

    #[test]
    fn rejects_a_datagram_with_no_cookie_separator() {
        assert!(parse(b"d7:command5:offere").is_err(), "no separator");
        assert!(parse(b" d7:command5:offere").is_err(), "empty cookie");
        assert!(parse(b"").is_err(), "empty datagram");
    }

    #[test]
    fn rejects_a_body_that_is_not_a_dictionary() {
        assert!(parse(b"cookie1 i5e").is_err(), "top-level int");
        assert!(parse(b"cookie1 li1ee").is_err(), "top-level list");
        assert!(parse(b"cookie1 d7:command").is_err(), "truncated");
    }

    /// The correlation-id is the ONLY thing that can name a reply's call, and
    /// the reply is the half carrying the relay's own allocated ports. If this
    /// stops working, relay-side sockets become unattributable on any capture
    /// where the parties' own addresses are not independently visible.
    #[test]
    fn a_reply_is_named_by_the_hep_correlation_id_alone() {
        let raw = offer_reply_bytes();
        let links = crate::rtpengine::sdp_links_from_ng(&raw, Some("call-from-correlation"));
        assert_eq!(links.len(), 1, "the reply's SDP has one m= line");
        let (ip, port, call_id, _media) = &links[0];
        assert_eq!(ip.to_string(), "10.0.0.40", "the RELAY's address");
        assert_eq!(*port, 38664, "the relay's own allocated port");
        assert_eq!(
            call_id, "call-from-correlation",
            "a reply carries no call-id of its own; the correlation-id names it"
        );
    }

    /// Without a correlation-id there is nothing to name a reply, and guessing
    /// would attach a relay port to whatever call was most recently seen.
    #[test]
    fn a_reply_with_no_correlation_id_attributes_nothing() {
        let raw = offer_reply_bytes();
        assert!(
            crate::rtpengine::sdp_links_from_ng(&raw, None).is_empty(),
            "an unnamed reply must contribute no endpoints"
        );
    }

    /// RE5: recording and forking commands are counted, never attributed.
    #[test]
    fn a_media_creating_command_is_counted_and_not_attributed() {
        crate::relay::reset_media_creating_count();
        let sdp = "v=0\r\nc=IN IP4 10.0.0.40\r\nm=audio 39000 RTP/AVP 0";
        let raw = format!(
            "ck d7:command15:start recording7:call-id4:cid13:sdp{}:{sdp}e",
            sdp.len()
        );
        let links = crate::rtpengine::sdp_links_from_ng(raw.as_bytes(), Some("cid1"));
        assert!(
            links.is_empty(),
            "a recording stream is not one of the call's two legs"
        );
        assert_eq!(
            crate::relay::media_creating_commands_seen(),
            1,
            "but the run must be able to SAY it saw one"
        );
    }

    /// Helper: byte-slice substring search, so the test reads as intent.
    trait ContainsStr {
        fn contains_str(&self, needle: &str) -> bool;
    }
    impl ContainsStr for &[u8] {
        fn contains_str(&self, needle: &str) -> bool {
            self.windows(needle.len()).any(|w| w == needle.as_bytes())
        }
    }
}
