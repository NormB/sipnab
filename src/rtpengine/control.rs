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

// The transport half only. Commands and reply parsing are pure and stay
// available everywhere, because a build that cannot TRANSMIT can still want to
// decode a relay's answer out of a capture -- and `transmit_guard` exists only
// under `native`, since that is where the sockets are.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use std::net::SocketAddr;
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use std::time::Duration;

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use crate::security::transmit_guard::TransmitPermit;

/// Largest control reply this client will read.
///
/// Transport-only, like the client that uses it.
///
/// A datagram beyond this is truncated by the kernel, and truncated bencode
/// fails to parse rather than decoding as a short list. That is the right
/// failure: a silently short enumeration is exactly what RE4 warns about.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
const MAX_REPLY_BYTES: usize = 64 * 1024;

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
/// What a relay answered, decoded from its reply.
///
/// rtpengine answers `{"result": "ok", ...}` or `{"result": "error", ...}`.
/// An error is not a transport failure and must not be reported as one: the
/// relay was reached, understood the question, and declined it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlReply {
    /// A `list` answer.
    Calls(Enumeration),
    /// The relay refused, with its own words.
    Refused {
        /// What the relay said.
        reason: String,
    },
}

/// Parse a `list` reply.
///
/// `requested` is the limit that was asked for, and it decides the truncation
/// flag: rtpengine returns at most that many and does not say whether it had
/// more, so a full answer is the only evidence available that there may be
/// more behind it. Reporting "exactly the limit" as complete is the failure
/// this flag exists to prevent -- 32 of 400 calls, silently.
///
/// # Errors
///
/// When the reply is not bencode, carries no `result`, or a `calls` entry is
/// not a byte string.
pub fn parse_list_reply(body: &[u8], requested: u32) -> anyhow::Result<ControlReply> {
    use anyhow::{Context, bail};

    let v = super::bencode::decode(body).context("rtpengine reply is not bencode")?;
    let result = match v.get(b"result") {
        Some(Value::Bytes(b)) => *b,
        _ => bail!("rtpengine reply carries no `result`"),
    };
    if result != b"ok" {
        let reason = match v.get(b"error-reason") {
            Some(Value::Bytes(b)) => String::from_utf8_lossy(b).into_owned(),
            // A refusal with no reason is still a refusal; saying "unknown" is
            // honest where inventing one is not.
            _ => "no reason given".to_string(),
        };
        return Ok(ControlReply::Refused { reason });
    }

    let mut call_ids = Vec::new();
    if let Some(Value::List(items)) = v.get(b"calls") {
        for item in items {
            match item {
                Value::Bytes(b) => call_ids.push(String::from_utf8_lossy(b).into_owned()),
                // A non-string in `calls` means the reply is not what this
                // parser thinks it is. Skipping it quietly would under-report
                // the very thing being enumerated.
                _ => bail!("a `calls` entry is not a byte string"),
            }
        }
    }

    let truncated = call_ids.len() as u32 >= requested && requested > 0;
    Ok(ControlReply::Calls(Enumeration {
        call_ids,
        truncated,
    }))
}

/// A client for one relay's control socket.
///
/// # Why the address is a constructor argument
///
/// It is never inferred from capture traffic. The address sipnab could guess
/// is one it learned from packets, and sending to an address derived from a
/// capture is how an analysis tool starts talking to a stranger -- a host that
/// was a relay when the capture was taken, and is somebody's laptop now.
///
/// # Why there is no `run` method
///
/// RE4 requires this to be triggered at startup and when an unexplained stream
/// appears, and NEVER to poll. There is no loop here and no timer: a caller who
/// wants periodic behavior has to write the loop themselves, which is a
/// visible act rather than a default. A poller is a service, and a service that
/// talks to a production relay is something an operator opts into.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub struct ControlClient {
    /// Where to send. Explicit, never derived from observed traffic.
    addr: SocketAddr,
    /// How long to wait for a reply before giving up.
    timeout: Duration,
    /// Monotonic half of the cookie.
    counter: AtomicU64,
    /// Per-client half, so two runs do not mint the same cookies.
    ///
    /// rtpengine deduplicates on the cookie and replays cached replies. A
    /// counter alone restarts at the same value every run, so a restarted
    /// sipnab would ask questions the relay believes it has already answered
    /// -- and receive the previous run's answers.
    base: u64,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
impl ControlClient {
    /// Point a client at a relay's control port.
    #[must_use]
    pub fn new(addr: SocketAddr, timeout: Duration) -> Self {
        let base = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        Self {
            addr,
            timeout,
            counter: AtomicU64::new(0),
            base,
        }
    }

    /// The relay this client talks to.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Mint a cookie seed that has not been used by this client.
    fn next_seed(&self) -> u64 {
        self.base
            .wrapping_add(self.counter.fetch_add(1, Ordering::Relaxed))
    }

    /// Ask the relay for its active Call-IDs.
    ///
    /// Requires a [`TransmitPermit`], which can only be obtained from a live
    /// capture source -- so this is uncallable on a run reading a file. That
    /// is the point: the addresses in a capture belonged to somebody at some
    /// point in the past, and an analyst opening a customer's pcap must not
    /// emit packets at them.
    ///
    /// # Errors
    ///
    /// When the socket cannot be opened, the send or receive fails or times
    /// out, or the reply does not parse. A relay that REFUSES is not an error:
    /// see [`ControlReply::Refused`].
    pub fn list(&self, _permit: &TransmitPermit, limit: u32) -> anyhow::Result<ControlReply> {
        let request = ControlRequest::new(ReadOnlyCommand::List { limit }, self.next_seed());
        let body = self.round_trip(&request)?;
        parse_list_reply(&body, limit)
    }

    /// Send one request and read one reply.
    ///
    /// UDP, because that is rtpengine's control transport. The reply buffer is
    /// bounded: a datagram larger than this is truncated by the kernel, and a
    /// truncated bencode message fails to parse rather than being read as a
    /// short list -- which is the right failure, because a silently short list
    /// is the thing RE4 is most careful about.
    fn round_trip(&self, request: &ControlRequest) -> anyhow::Result<Vec<u8>> {
        use anyhow::Context;

        // Bind to the unspecified address matching the target's family, so a
        // v6 relay is reachable without a second code path.
        // Constructed rather than parsed: there is no failure mode to handle,
        // and `expect` on a literal is a panic path the lint rightly refuses.
        let bind = SocketAddr::new(
            if self.addr.is_ipv6() {
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            } else {
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            },
            0,
        );
        let sock = std::net::UdpSocket::bind(bind).context("binding a control socket")?;
        sock.set_read_timeout(Some(self.timeout))
            .context("setting the control read timeout")?;
        // Connected UDP, so the kernel drops replies from anyone else. An
        // unconnected socket accepts a datagram from any source, and a reply
        // is trusted to describe a production relay's calls.
        sock.connect(self.addr)
            .with_context(|| format!("connecting to the relay at {}", self.addr))?;

        sock.send(&request.to_wire())
            .with_context(|| format!("sending {} to {}", request.command, self.addr))?;

        let mut buf = vec![0u8; MAX_REPLY_BYTES];
        let n = sock
            .recv(&mut buf)
            .with_context(|| format!("no reply from {} within {:?}", self.addr, self.timeout))?;
        buf.truncate(n);

        // The reply is framed exactly as the request: cookie, space, bencode.
        // A reply whose cookie is not ours answers a different question.
        let space = buf
            .iter()
            .position(|b| *b == b' ')
            .context("reply carries no cookie framing")?;
        if &buf[..space] != request.cookie().as_bytes() {
            anyhow::bail!(
                "reply cookie does not match the request; it answers a \
                 different transaction"
            );
        }
        Ok(buf[space + 1..].to_vec())
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

    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    /// A permit, for tests that must call a permit-gated function.
    ///
    /// Obtained the only way there is: from a live capture source. A test that
    /// could conjure one would prove nothing about the gate.
    fn live_permit() -> TransmitPermit {
        use crate::capture::CaptureSource;
        TransmitPermit::for_source(&CaptureSource::Live {
            device: "test0".to_string(),
        })
        .expect("a live source must grant a permit")
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    /// Stand in for a relay: answer one datagram with `reply`, echoing the
    /// cookie the client sent so the framing check passes.
    ///
    /// A real socket rather than a mocked one, because the thing most likely
    /// to be wrong is the framing and the connect/timeout handling, and a mock
    /// would assert my own assumptions back at me.
    fn fake_relay(reply_body: &'static str) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = sock.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                let req = &buf[..n];
                let space = req.iter().position(|b| *b == b' ').unwrap_or(0);
                let mut out = req[..space].to_vec();
                out.push(b' ');
                out.extend_from_slice(reply_body.as_bytes());
                let _ = sock.send_to(&out, peer);
            }
        });
        (addr, handle)
    }

    /// Build a bencode byte string for a fixture.
    ///
    /// Hand-written length prefixes are a reliable source of wrong tests: the
    /// first draft of the refusal fixture below wrote `14:unknown command`,
    /// and that string is fifteen bytes. Computed here, but deliberately NOT
    /// by calling `bencode::encode` -- a fixture built by the encoder under
    /// test cannot disagree with it, which is the disagreement a parser test
    /// exists to find.
    fn bstr(s: &str) -> String {
        format!("{}:{}", s.len(), s)
    }

    /// A real round trip: request framed, reply parsed, calls returned.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_round_trip_against_a_relay_returns_its_calls() {
        let (addr, relay) = fake_relay("d6:result2:ok5:callsl4:aaaa4:bbbbee");
        let client = ControlClient::new(addr, Duration::from_secs(2));

        let reply = client
            .list(&live_permit(), 32)
            .expect("the relay answered; parsing must succeed");
        match reply {
            ControlReply::Calls(e) => {
                assert_eq!(e.call_ids, vec!["aaaa".to_string(), "bbbb".to_string()]);
                assert!(!e.truncated, "two of thirty-two is complete");
            }
            other => panic!("expected calls, got {other:?}"),
        }
        relay.join().expect("relay thread");
    }

    /// A reply answering a DIFFERENT transaction is refused.
    ///
    /// rtpengine replays cached replies keyed on the cookie, and a stray
    /// datagram on a connected socket is possible from the same peer. A reply
    /// whose cookie is not ours describes some other question, and accepting
    /// it would attribute one call's streams to another.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_reply_with_the_wrong_cookie_is_refused() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = sock.local_addr().expect("addr");
        let relay = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            if let Ok((_, peer)) = sock.recv_from(&mut buf) {
                // Deliberately the wrong cookie.
                let _ = sock.send_to(b"sipnab-somebodyelse d6:result2:oke", peer);
            }
        });

        let client = ControlClient::new(addr, Duration::from_secs(2));
        let err = client
            .list(&live_permit(), 32)
            .expect_err("a mismatched cookie must not be accepted");
        assert!(
            err.to_string().contains("different transaction"),
            "the error must name the cause: {err}"
        );
        relay.join().expect("relay thread");
    }

    /// A relay that never answers times out rather than hanging.
    ///
    /// An analysis tool that blocks forever on a silent relay is worse than
    /// one that reports the silence: the operator is left with neither an
    /// answer nor a prompt.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_silent_relay_times_out() {
        // Bound but never read from: the port exists, nothing replies.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = sock.local_addr().expect("addr");

        let client = ControlClient::new(addr, Duration::from_millis(250));
        let start = std::time::Instant::now();
        let err = client
            .list(&live_permit(), 32)
            .expect_err("a silent relay must not succeed");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the read timeout did not apply; this would hang a run"
        );
        assert!(
            err.to_string().contains("no reply"),
            "the error must say the relay was silent: {err}"
        );
        drop(sock);
    }

    /// Two calls from one client never reuse a cookie.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_client_mints_a_fresh_cookie_per_call() {
        let client = ControlClient::new(
            "127.0.0.1:1".parse().expect("addr"),
            Duration::from_millis(1),
        );
        let a = client.next_seed();
        let b = client.next_seed();
        assert_ne!(a, b, "a client reused a cookie seed across transactions");
    }

    /// A full answer is reported as possibly truncated, because that is the
    /// only evidence rtpengine gives.
    ///
    /// It returns at most `limit` and never says whether it had more. Treating
    /// "exactly the limit" as complete is how 32 of 400 calls gets reported as
    /// the whole estate, with the other 368 looking like orphans.
    #[test]
    fn a_full_answer_is_flagged_because_more_may_exist() {
        // Fewer than asked for: the relay ran out, so this is everything.
        let body = b"d6:result2:ok5:callsl4:aaaa4:bbbbee";
        match parse_list_reply(body, 32).expect("parse") {
            ControlReply::Calls(e) => {
                assert_eq!(e.call_ids.len(), 2);
                assert!(!e.truncated, "two of thirty-two is not truncated");
            }
            other => panic!("expected calls, got {other:?}"),
        }

        // Exactly the limit: may be more behind it.
        match parse_list_reply(body, 2).expect("parse") {
            ControlReply::Calls(e) => assert!(
                e.truncated,
                "a full answer must be flagged; the relay does not say whether \
                 it had more"
            ),
            other => panic!("expected calls, got {other:?}"),
        }
    }

    /// A refusal is not a transport failure.
    ///
    /// The relay was reached, understood the question and declined it.
    /// Collapsing that into an I/O error tells an operator to check the
    /// network when the answer is in the relay's configuration.
    #[test]
    fn a_refusal_is_reported_as_a_refusal() {
        let body = format!(
            "d{}{}{}{}e",
            bstr("result"),
            bstr("error"),
            bstr("error-reason"),
            bstr("unknown command")
        );
        match parse_list_reply(body.as_bytes(), 32).expect("parse") {
            ControlReply::Refused { reason } => {
                assert!(reason.contains("unknown command"), "reason lost: {reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        // A refusal with no reason is still a refusal.
        let bare = format!("d{}{}e", bstr("result"), bstr("error"));
        match parse_list_reply(bare.as_bytes(), 32).expect("parse") {
            ControlReply::Refused { reason } => assert!(
                !reason.is_empty(),
                "a refusal with no stated reason must still say something"
            ),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A malformed reply is an error, never a quiet empty answer.
    ///
    /// An empty enumeration and an unparseable one look identical downstream:
    /// both leave every stream unmatched. One is a fact about the relay and
    /// the other is a fact about this parser.
    #[test]
    fn a_malformed_reply_is_refused_rather_than_read_as_empty() {
        for bad in [
            b"not bencode at all".as_slice(),
            // No `result` key.
            b"d5:callslee",
            // A non-string inside `calls`.
            b"d6:result2:ok5:callsli42eee",
        ] {
            assert!(
                parse_list_reply(bad, 32).is_err(),
                "a malformed reply parsed as a valid empty answer: {:?}",
                String::from_utf8_lossy(bad)
            );
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
