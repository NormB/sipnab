// SPDX-License-Identifier: MIT OR Apache-2.0

//! Asking a relay what it is doing, without telling it to do anything (RE4).
//!
//! A passive decoder learns nothing about a call whose offer happened before
//! sipnab started, and incident response usually begins mid-call. rtpengine
//! answers two questions that close that gap: `list` returns the active
//! Call-IDs, and `query` returns, per call, the tags and their streams.
//!
//! # What this module refuses to be
//!
//! rtpengine's ng protocol also carries `offer`, `answer`, `delete` and
//! `start recording`. Every one of them CHANGES a production relay: moves
//! media, tears a call down, fills a disk. sipnab has no business sending any
//! of them, and RE7 says so in as many words.
//!
//! That is enforced by [`ReadOnlyCommand`] having only two variants rather
//! than by a rule somebody has to remember. There is no code path from this
//! module that can express `delete`, because there is no value that means it.
//! A reviewer checking "does sipnab ever tell a relay to do something" reads
//! one enum instead of auditing every call site, and a future edit that wants
//! to send one has to add a variant -- which is a visible act in a diff, not
//! an oversight.
//!
//! # Bounds this module exists to hold
//!
//! - **Never periodic.** Triggered at startup and when an unexplained stream
//!   appears. A poller is a service, and a service that talks to a production
//!   relay is a thing an operator must opt into rather than discover.
//! - **A fresh cookie per transaction.** rtpengine deduplicates on the cookie
//!   and replays the cached reply for a repeat. During RE1 development that
//!   returned ports belonging to a call that had already been deleted -- a
//!   correct-looking answer about a call that no longer existed.
//! - **An explicit control address.** Never inferred from capture traffic:
//!   the address sipnab would guess is an address it learned from packets,
//!   and sending to an address derived from a capture is how an analysis tool
//!   starts talking to a stranger.

use std::fmt;

use super::bencode::{Value, encode_dict};

/// A command that only reads. There is deliberately no way to say anything
/// else.
///
/// See the module note: the point is not that sipnab avoids sending `delete`,
/// it is that this type cannot express it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOnlyCommand {
    /// Every active Call-ID the relay knows, bounded by `limit`.
    ///
    /// rtpengine defaults to 32 and warns that raising it may exceed a UDP
    /// datagram, which is why [`ControlRequest`] carries whether the answer
    /// was complete.
    List {
        /// How many Call-IDs to ask for.
        limit: u32,
    },
    /// One call's tags and streams.
    Query {
        /// The Call-ID to ask about.
        call_id: String,
    },
}

impl ReadOnlyCommand {
    /// The ng verb, as it goes on the wire.
    #[must_use]
    pub fn verb(&self) -> &'static str {
        match self {
            Self::List { .. } => "list",
            Self::Query { .. } => "query",
        }
    }
}

impl fmt::Display for ReadOnlyCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::List { limit } => write!(f, "list(limit={limit})"),
            // The Call-ID is a caller's identifier and can be personal data;
            // it is on the wire either way, but a Display impl ends up in logs
            // that outlive the capture.
            Self::Query { .. } => write!(f, "query(call-id elided)"),
        }
    }
}

/// One transaction: a command and the cookie that identifies it.
///
/// The cookie is generated per request and never reused. See the module note
/// for what reuse cost once.
#[derive(Debug, Clone)]
pub struct ControlRequest {
    /// The command. Read-only by construction.
    pub command: ReadOnlyCommand,
    /// The per-transaction cookie.
    cookie: String,
}

impl ControlRequest {
    /// Build a request, minting a fresh cookie.
    ///
    /// `cookie_seed` is supplied by the caller rather than read from a global
    /// clock or RNG so a test can state the exact transaction it is
    /// describing. Production callers pass something that does not repeat;
    /// [`Self::cookie`] is what goes on the wire.
    #[must_use]
    pub fn new(command: ReadOnlyCommand, cookie_seed: u64) -> Self {
        Self {
            command,
            // Prefixed so a relay operator reading their own logs can tell
            // which tool asked. An unattributed cookie in a production log is
            // a small mystery somebody has to spend time on.
            cookie: format!("sipnab-{cookie_seed:016x}"),
        }
    }

    /// The cookie for this transaction.
    #[must_use]
    pub fn cookie(&self) -> &str {
        &self.cookie
    }

    /// The bytes to send: `<cookie> <bencoded dict>`.
    ///
    /// rtpengine's framing is the cookie, a space, then the message. The
    /// cookie is outside the bencode, which is why it is not a dict key.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let body = match &self.command {
            ReadOnlyCommand::List { limit } => encode_dict(vec![
                (b"command".as_slice(), Value::Bytes(b"list")),
                (b"limit".as_slice(), Value::Int(i64::from(*limit))),
            ]),
            ReadOnlyCommand::Query { call_id } => encode_dict(vec![
                (b"command".as_slice(), Value::Bytes(b"query")),
                (b"call-id".as_slice(), Value::Bytes(call_id.as_bytes())),
            ]),
        };
        let mut out = Vec::with_capacity(self.cookie.len() + 1 + body.len());
        out.extend_from_slice(self.cookie.as_bytes());
        out.push(b' ');
        out.extend_from_slice(&body);
        out
    }
}

/// What a `list` answered, and whether it answered fully.
///
/// The completeness flag is not decoration. rtpengine returns 32 Call-IDs by
/// default; covering 32 of 400 calls and saying nothing reports the other 368
/// as orphans and looks exactly like a run that worked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumeration {
    /// The Call-IDs the relay returned.
    pub call_ids: Vec<String>,
    /// Whether the relay had more than it returned.
    pub truncated: bool,
}

impl Enumeration {
    /// One line an operator reads, which says so when the answer is partial.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.truncated {
            format!(
                "{} call(s) enumerated — PARTIAL: the relay had more than it \
                 returned, so any stream not matched here may belong to a call \
                 this list never saw. Raise the limit, or enumerate over TCP \
                 where a larger answer fits.",
                self.call_ids.len()
            )
        } else {
            format!("{} call(s) enumerated, complete", self.call_ids.len())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtpengine::bencode::decode;

    /// Every cookie is different, and that is the whole point.
    ///
    /// rtpengine deduplicates on the cookie and replays the cached reply for a
    /// repeat. During RE1 development that returned ports belonging to a call
    /// that had already been deleted -- an answer that looked correct and
    /// described a call that no longer existed. A reused cookie is not a
    /// wasted round trip, it is a wrong answer.
    #[test]
    fn every_transaction_gets_its_own_cookie() {
        let a = ControlRequest::new(ReadOnlyCommand::List { limit: 32 }, 1);
        let b = ControlRequest::new(ReadOnlyCommand::List { limit: 32 }, 2);
        assert_ne!(
            a.cookie(),
            b.cookie(),
            "two transactions shared a cookie; rtpengine would replay the \
             first reply for the second"
        );
        // Same command, same seed, same cookie: the seed is what varies, so a
        // caller that fails to vary it is the bug this makes visible.
        let c = ControlRequest::new(ReadOnlyCommand::List { limit: 32 }, 1);
        assert_eq!(a.cookie(), c.cookie());
    }

    /// The cookie says who is asking.
    #[test]
    fn the_cookie_names_the_tool() {
        let r = ControlRequest::new(ReadOnlyCommand::List { limit: 8 }, 0xdead);
        assert!(
            r.cookie().starts_with("sipnab-"),
            "an unattributed cookie in a relay's log is a mystery somebody has \
             to spend time on: {}",
            r.cookie()
        );
    }

    /// The wire format is `<cookie> <bencode>`, cookie outside the dict.
    #[test]
    fn a_list_request_is_framed_and_encoded() {
        let r = ControlRequest::new(ReadOnlyCommand::List { limit: 32 }, 7);
        let wire = r.to_wire();

        let space = wire.iter().position(|b| *b == b' ').expect("framing space");
        assert_eq!(
            &wire[..space],
            r.cookie().as_bytes(),
            "the cookie must precede the message, outside the bencode"
        );

        let body = decode(&wire[space + 1..]).expect("body must be bencode");
        assert_eq!(body.get(b"command"), Some(&Value::Bytes(b"list")));
        assert_eq!(body.get(b"limit"), Some(&Value::Int(32)));
    }

    /// A query carries the Call-ID it asks about.
    #[test]
    fn a_query_request_carries_its_call_id() {
        let r = ControlRequest::new(
            ReadOnlyCommand::Query {
                call_id: "abc@example.net".to_string(),
            },
            9,
        );
        let wire = r.to_wire();
        let space = wire.iter().position(|b| *b == b' ').expect("space");
        let body = decode(&wire[space + 1..]).expect("bencode");
        assert_eq!(body.get(b"command"), Some(&Value::Bytes(b"query")));
        assert_eq!(
            body.get(b"call-id"),
            Some(&Value::Bytes(b"abc@example.net"))
        );
    }

    /// NOTHING this module can build changes the relay.
    ///
    /// The guarantee is structural: `ReadOnlyCommand` has two variants and
    /// neither is destructive, so there is no value meaning `delete`. This
    /// test is the tripwire for a future edit that adds one -- the match is
    /// exhaustive, so a new variant fails to compile here until somebody
    /// states what it is, which is a visible act in a diff rather than an
    /// oversight.
    #[test]
    fn no_command_this_module_can_build_changes_the_relay() {
        for cmd in [
            ReadOnlyCommand::List { limit: 1 },
            ReadOnlyCommand::Query {
                call_id: "x".to_string(),
            },
        ] {
            let verb = match &cmd {
                ReadOnlyCommand::List { .. } => "list",
                ReadOnlyCommand::Query { .. } => "query",
            };
            assert_eq!(cmd.verb(), verb);
            assert!(
                matches!(verb, "list" | "query"),
                "a verb that is not list or query reached the wire: {verb}"
            );

            // And the encoded form must not contain a mutating verb either --
            // a `command` key is a string, and a typo could put anything in it.
            let wire = ControlRequest::new(cmd, 1).to_wire();
            let text = String::from_utf8_lossy(&wire);
            for destructive in ["delete", "offer", "answer", "start recording", "block"] {
                assert!(
                    !text.contains(destructive),
                    "a request serialized the mutating verb {destructive:?}:\n{text}"
                );
            }
        }
    }

    /// A partial enumeration must say so, or it reports the calls it never saw
    /// as orphans and looks like it worked.
    #[test]
    fn a_truncated_enumeration_announces_itself() {
        let complete = Enumeration {
            call_ids: vec!["a".into(), "b".into()],
            truncated: false,
        };
        assert!(complete.describe().contains("complete"));
        assert!(!complete.describe().contains("PARTIAL"));

        let partial = Enumeration {
            call_ids: (0..32).map(|i| i.to_string()).collect(),
            truncated: true,
        };
        let d = partial.describe();
        assert!(
            d.contains("PARTIAL"),
            "a truncated list must announce it: {d}"
        );
        assert!(
            d.contains("may belong to a call this list never saw"),
            "the consequence is what the operator needs, not just the flag: {d}"
        );
    }

    /// A Call-ID is a caller's identifier; Display must not put it in a log.
    #[test]
    fn display_does_not_leak_the_call_id() {
        let q = ReadOnlyCommand::Query {
            call_id: "sensitive-caller@example.net".to_string(),
        };
        let shown = q.to_string();
        assert!(
            !shown.contains("sensitive-caller"),
            "Display leaked a Call-ID into a string that ends up in logs \
             outliving the capture: {shown}"
        );
    }
}
