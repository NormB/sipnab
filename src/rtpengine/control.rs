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
    /// A `query` answer: one call, as the relay holds it.
    Call(CallView),
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
/// One relay-side port, and who the relay exchanges media with on it.
///
/// This is the join key an unexplained stream needs. sipnab sees packets
/// arriving at the relay's own address and port; the relay is the only thing
/// that knows which call that port was allocated for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStream {
    /// The relay's own address for this stream, as it appears on the wire.
    pub local_address: String,
    /// The relay's own port. The half sipnab can see without any signaling.
    pub local_port: u16,
    /// Where the relay currently sends, once it has learned it.
    pub endpoint: Option<String>,
    /// What the far side advertised in SDP, which may differ from `endpoint`
    /// behind NAT -- and the difference is often the bug being chased.
    pub advertised_endpoint: Option<String>,
    /// Whether this port carries RTCP rather than RTP, from the relay's flags.
    pub is_rtcp: bool,
    /// Every SSRC the relay has seen on this port, ingress and egress.
    ///
    /// A second join key, and a better one where a capture is taken off-path
    /// from the relay: an SSRC follows the media even when the addresses do
    /// not survive the path.
    pub ssrcs: Vec<u32>,
}

/// One side of a call, as the relay holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTag {
    /// The SIP tag identifying this side.
    pub tag: String,
    /// The tags this side exchanges media with.
    pub in_dialogue_with: Vec<String>,
    /// The codec the relay recorded for this side, where it recorded one.
    pub codec: Option<String>,
    /// Ports the relay holds for this side, RTP and RTCP together.
    pub streams: Vec<RelayStream>,
}

/// What a relay knows about one call.
///
/// The Call-ID is carried from the REQUEST, not read from the reply: a
/// rtpengine `query` answer does not echo the Call-ID it was asked about
/// (verified against 12.5.1), so pairing the answer with its question is the
/// caller's job and cannot be checked from the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallView {
    /// The Call-ID this view answers for, from the request.
    pub call_id: String,
    /// Each side of the call.
    pub tags: Vec<RelayTag>,
}

impl CallView {
    /// Find the tag holding a given relay-side port, if any.
    ///
    /// This is the whole point of asking: sipnab sees `local_port` in the
    /// capture and nothing that explains it.
    #[must_use]
    pub fn tag_for_port(&self, local_port: u16) -> Option<&RelayTag> {
        self.tags
            .iter()
            .find(|t| t.streams.iter().any(|s| s.local_port == local_port))
    }

    /// Find the tag the relay has seen a given SSRC on, if any.
    #[must_use]
    pub fn tag_for_ssrc(&self, ssrc: u32) -> Option<&RelayTag> {
        self.tags
            .iter()
            .find(|t| t.streams.iter().any(|s| s.ssrcs.contains(&ssrc)))
    }
}

/// Read one `endpoint`-shaped sub-dictionary into `address:port`.
///
/// rtpengine writes these as `{"family": .., "address": .., "port": ..}`
/// rather than as a string, so the textual form is assembled here once.
fn endpoint_str(v: Option<&Value<'_>>) -> Option<String> {
    let d = v?;
    let addr = d.get_str(b"address")?;
    let port = d.get_int(b"port")?;
    // A v6 literal needs brackets or the result cannot be parsed back.
    if addr.contains(':') {
        Some(format!("[{addr}]:{port}"))
    } else {
        Some(format!("{addr}:{port}"))
    }
}

/// Collect the SSRCs out of an `ingress SSRCs` / `egress SSRCs` list.
fn ssrcs_from(v: Option<&Value<'_>>, out: &mut Vec<u32>) {
    let Some(Value::List(items)) = v else { return };
    for item in items {
        // rtpengine writes SSRCs as signed integers; the wire value is a
        // 32-bit unsigned quantity, so it is read back through a cast rather
        // than rejected for being negative.
        if let Some(n) = item.get_int(b"SSRC") {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "an SSRC is 32 bits on the wire; bencode has only \
                          signed integers to carry it in"
            )]
            let ssrc = n as u32;
            if !out.contains(&ssrc) {
                out.push(ssrc);
            }
        }
    }
}

/// Parse a `query` reply for `call_id`.
///
/// `call_id` is the one that was ASKED about. See [`CallView`] for why it
/// cannot come from the reply.
///
/// # Errors
///
/// When the reply is not bencode or carries no `result`. A reply the relay
/// refused is not an error: see [`ControlReply::Refused`].
pub fn parse_query_reply(body: &[u8], call_id: &str) -> anyhow::Result<ControlReply> {
    use anyhow::{Context, bail};

    let v = super::bencode::decode(body).context("rtpengine reply is not bencode")?;
    let result = match v.get(b"result") {
        Some(Value::Bytes(b)) => *b,
        _ => bail!("rtpengine reply carries no `result`"),
    };
    if result != b"ok" {
        let reason = match v.get(b"error-reason") {
            Some(Value::Bytes(b)) => String::from_utf8_lossy(b).into_owned(),
            _ => "the relay refused without saying why".to_owned(),
        };
        return Ok(ControlReply::Refused { reason });
    }

    let mut tags = Vec::new();
    if let Some(Value::Dict(entries)) = v.get(b"tags") {
        for (key, tv) in entries {
            // The tag appears both as the key and inside the value. The key is
            // authoritative: it is what the relay indexes on.
            let tag = String::from_utf8_lossy(key).into_owned();

            let mut in_dialogue_with = Vec::new();
            // 12.5.1 writes `subscriptions`; older builds wrote
            // `in dialogue with`. Both are read, because a version check would
            // be a worse test than simply looking for the data.
            for key in [b"subscriptions".as_slice(), b"in dialogue with".as_slice()] {
                if let Some(Value::List(subs)) = tv.get(key) {
                    for sub in subs {
                        if let Some(other) = sub.get_str(b"tag")
                            && !in_dialogue_with.contains(&other)
                        {
                            in_dialogue_with.push(other);
                        }
                    }
                }
            }

            let mut codec = None;
            let mut streams = Vec::new();
            if let Some(Value::List(medias)) = tv.get(b"medias") {
                for media in medias {
                    if codec.is_none() {
                        codec = media.get_str(b"codec");
                    }
                    let Some(Value::List(sl)) = media.get(b"streams") else {
                        continue;
                    };
                    for s in sl {
                        let (Some(local_address), Some(port)) =
                            (s.get_str(b"local address"), s.get_int(b"local port"))
                        else {
                            // A stream with no relay-side port carries no join
                            // key, so it cannot answer the question that was
                            // asked. Skipping it is better than inventing a
                            // port for it.
                            continue;
                        };
                        let Ok(local_port) = u16::try_from(port) else {
                            continue;
                        };
                        let is_rtcp = matches!(s.get(b"flags"), Some(Value::List(f))
                            if f.iter().any(|x| matches!(x, Value::Bytes(b) if *b == b"RTCP")));
                        let mut ssrcs = Vec::new();
                        ssrcs_from(s.get(b"ingress SSRCs"), &mut ssrcs);
                        ssrcs_from(s.get(b"egress SSRCs"), &mut ssrcs);
                        streams.push(RelayStream {
                            local_address,
                            local_port,
                            endpoint: endpoint_str(s.get(b"endpoint")),
                            advertised_endpoint: endpoint_str(s.get(b"advertised endpoint")),
                            is_rtcp,
                            ssrcs,
                        });
                    }
                }
            }

            tags.push(RelayTag {
                tag,
                in_dialogue_with,
                codec,
                streams,
            });
        }
    }

    // A deterministic order, so two runs against the same relay produce the
    // same report and a diff of two reports means something changed.
    tags.sort_by(|a, b| a.tag.cmp(&b.tag));

    Ok(ControlReply::Call(CallView {
        call_id: call_id.to_owned(),
        tags,
    }))
}

/// A live `ng` control client, pointed at one relay.
///
/// Native-only and live-capture-only by construction: every method that
/// speaks to the relay demands a [`TransmitPermit`], and a permit exists only
/// where sipnab is already allowed to put packets on the wire. A run reading
/// a file cannot obtain one, so an analyst opening somebody else's pcap
/// cannot make sipnab transmit at the addresses inside it.
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

/// How long to wait for a relay's answer before giving up.
///
/// A CHOICE, not a measurement. rtpengine's control port is normally on the
/// same host or the same LAN segment as sipnab, where a reply takes
/// milliseconds; this is sized for an unreachable or wedged relay to be
/// declared so quickly rather than for a slow one to be waited out. It bounds
/// the startup snapshot, which happens before the capture opens, so an
/// operator whose relay is down waits this long per transaction and not
/// longer.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub const DEFAULT_CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

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

    /// Ask the relay about ONE call.
    ///
    /// Requires a [`TransmitPermit`] for the same reason [`Self::list`] does.
    ///
    /// The Call-ID is passed back into the parser because rtpengine's answer
    /// does not echo it: pairing the answer with its question is this method's
    /// job, and it is the only place that can do it.
    ///
    /// # Errors
    ///
    /// When the socket cannot be opened, the send or receive fails or times
    /// out, or the reply does not parse.
    pub fn query(&self, _permit: &TransmitPermit, call_id: &str) -> anyhow::Result<ControlReply> {
        let request = ControlRequest::new(
            ReadOnlyCommand::Query {
                call_id: call_id.to_owned(),
            },
            self.next_seed(),
        );
        let body = self.round_trip(&request)?;
        parse_query_reply(&body, call_id)
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
    pub(super) fn bstr(s: &str) -> String {
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

#[cfg(test)]
mod query_reply_tests {
    use super::*;

    /// A real `query` answer from rtpengine 12.5.1, captured off the harness
    /// relay while two SIPp calls were up.
    ///
    /// Recorded rather than hand-written on purpose. A fixture built from the
    /// same understanding as the parser agrees with the parser and proves
    /// nothing; this one was produced by the software this code has to read.
    const REAL_QUERY: &[u8] =
        include_bytes!("../../tests/fixtures/rtpengine/query-reply-12.5.1.bin");

    fn parsed() -> CallView {
        match parse_query_reply(REAL_QUERY, "1-9582@172.28.0.21") {
            Ok(ControlReply::Call(c)) => c,
            other => panic!("expected a call view, got {other:?}"),
        }
    }

    /// Both sides of the call are read, and the Call-ID comes from the ASK.
    #[test]
    fn real_reply_yields_both_tags_and_the_requested_call_id() {
        let call = parsed();
        assert_eq!(
            call.call_id, "1-9582@172.28.0.21",
            "the Call-ID must be the one asked about; rtpengine does not echo \
             it, so a parser that invented one would be inventing the join key"
        );
        let tags: Vec<&str> = call.tags.iter().map(|t| t.tag.as_str()).collect();
        assert_eq!(tags, ["1SIPpTag0113926", "9582SIPpTag091"]);
    }

    /// The relay-side ports are what sipnab can see in a capture, so they are
    /// what an unexplained stream is matched on.
    #[test]
    fn real_reply_yields_the_relay_side_ports() {
        let call = parsed();
        let mut ports: Vec<u16> = call
            .tags
            .iter()
            .flat_map(|t| t.streams.iter().map(|s| s.local_port))
            .collect();
        ports.sort_unstable();
        assert_eq!(
            ports,
            [30000, 30001, 30002, 30003],
            "one RTP and one RTCP port per side"
        );
        for tag in &call.tags {
            for stream in &tag.streams {
                assert_eq!(stream.local_address, "172.28.0.10");
            }
        }
    }

    /// RTP and RTCP are told apart, because reporting a relay's RTCP port as
    /// an unattributed media stream is the confusion this is meant to end.
    #[test]
    fn rtcp_ports_are_distinguished_from_rtp_ports() {
        let call = parsed();
        let rtcp: Vec<u16> = call
            .tags
            .iter()
            .flat_map(|t| t.streams.iter().filter(|s| s.is_rtcp).map(|s| s.local_port))
            .collect();
        let mut rtcp = rtcp;
        rtcp.sort_unstable();
        assert_eq!(rtcp, [30001, 30003], "the odd ports carry RTCP");
    }

    /// The endpoint and what the far side ADVERTISED are kept apart. Behind
    /// NAT they differ, and the difference is usually the bug.
    #[test]
    fn endpoint_and_advertised_endpoint_are_both_kept() {
        let call = parsed();
        let stream = call
            .tags
            .iter()
            .flat_map(|t| &t.streams)
            .find(|s| s.local_port == 30002)
            .expect("port 30002 is in the fixture");
        assert_eq!(stream.endpoint.as_deref(), Some("172.28.0.21:6000"));
        assert_eq!(
            stream.advertised_endpoint.as_deref(),
            Some("172.28.0.21:6000"),
            "on this harness they agree; they are stored separately so that a \
             capture where they do not can say so"
        );
    }

    /// The two endpoints are told apart, which the real fixture CANNOT prove.
    ///
    /// The harness has no NAT, so both fields hold the same value there and a
    /// parser that swapped them passes every test above. That is the failure
    /// mode of a recorded fixture: it is authoritative about shape and silent
    /// about any distinction its own traffic does not draw.
    ///
    /// So this one case is synthetic -- and it is the case that matters, since
    /// the two fields exist only to differ. Lengths are computed, never
    /// counted, for the reason [`super::tests::bstr`] gives.
    #[test]
    fn behind_nat_the_endpoint_and_the_advertised_endpoint_do_not_collapse() {
        use super::tests::bstr;

        // What the far side CLAIMED in SDP is a private address; where the
        // relay actually sends is the public one it learned from the packets.
        let ep = |addr: &str, port: u16| {
            format!(
                "d{}{}{}{}{}i{port}ee",
                bstr("family"),
                bstr("IPv4"),
                bstr("address"),
                bstr(addr),
                bstr("port"),
            )
        };
        let stream = format!(
            "d{}{}{}i40000e{}{}{}{}e",
            bstr("local address"),
            bstr("203.0.113.5"),
            bstr("local port"),
            bstr("advertised endpoint"),
            ep("10.1.1.9", 7000),
            bstr("endpoint"),
            ep("198.51.100.77", 34567),
        );
        // Assembled in pieces rather than as one dense format string: a
        // bencode literal is unreadable enough without counting braces too.
        let media = format!("d{}i1e{}l{stream}ee", bstr("index"), bstr("streams"),);
        let tag_entry = format!(
            "d{}l{media}e{}{}e",
            bstr("medias"),
            bstr("tag"),
            bstr("natted-tag"),
        );
        let body = format!(
            "d{}{}{}d{}{tag_entry}ee",
            bstr("result"),
            bstr("ok"),
            bstr("tags"),
            bstr("natted-tag"),
        );

        let ControlReply::Call(call) = parse_query_reply(body.as_bytes(), "nat@example.net")
            .expect("the synthetic reply must parse")
        else {
            panic!("expected a call view");
        };
        let s = &call.tags[0].streams[0];
        assert_eq!(
            s.endpoint.as_deref(),
            Some("198.51.100.77:34567"),
            "`endpoint` is where the relay SENDS -- the address it learned"
        );
        assert_eq!(
            s.advertised_endpoint.as_deref(),
            Some("10.1.1.9:7000"),
            "`advertised endpoint` is what the far side CLAIMED. Swapping \
             these reports a private address as reachable, and the gap \
             between them is usually the bug being chased"
        );
    }

    /// The SSRC is the join key that survives a capture taken off-path, where
    /// the addresses did not.
    ///
    /// The fixture's SSRC is INGRESS on one side and EGRESS on the other, so
    /// each direction is asserted at its own port. An earlier version accepted
    /// either port and passed with egress parsing deleted entirely.
    #[test]
    fn ssrcs_are_read_from_both_directions() {
        let call = parsed();
        const SSRC: u32 = 758_599_286;

        let by_port = |port: u16| -> &RelayStream {
            call.tags
                .iter()
                .flat_map(|t| &t.streams)
                .find(|s| s.local_port == port)
                .expect("port is in the fixture")
        };

        assert!(
            by_port(30002).ssrcs.contains(&SSRC),
            "the relay recorded this SSRC as INGRESS on port 30002"
        );
        assert!(
            by_port(30000).ssrcs.contains(&SSRC),
            "and as EGRESS on port 30000 -- reading only one direction loses \
             half the join keys the relay is holding"
        );
        assert!(
            by_port(30001).ssrcs.is_empty(),
            "the RTCP port carried no media, so it must claim no SSRC"
        );
    }

    /// The lookup an unexplained stream actually performs.
    ///
    /// BOTH sides are asserted, and that is the point. Checking only port
    /// 30000 passes even for a lookup that returns whichever tag comes first,
    /// because the right answer for 30000 *is* the first tag. Port 30002
    /// belongs to the other one, so it can tell a real lookup from a lucky
    /// one -- and a mutant that ignored the port survived until it was here.
    #[test]
    fn a_relay_port_finds_its_own_tag_and_its_peer() {
        let call = parsed();

        let first = call
            .tag_for_port(30000)
            .expect("port 30000 is held by a tag in the fixture");
        assert_eq!(first.tag, "1SIPpTag0113926");
        assert_eq!(
            first.in_dialogue_with,
            ["9582SIPpTag091"],
            "the other side of the call is what makes this a dialog and not \
             just a port"
        );

        let second = call
            .tag_for_port(30002)
            .expect("port 30002 is held by the other tag in the fixture");
        assert_eq!(
            second.tag, "9582SIPpTag091",
            "each port must find the tag that actually holds it"
        );
        assert_eq!(second.in_dialogue_with, ["1SIPpTag0113926"]);

        assert!(
            call.tag_for_port(30099).is_none(),
            "a port the relay does not hold must not match anything; \
             attributing a stream to the wrong call is worse than leaving it \
             an orphan"
        );
    }

    /// The codec the relay recorded, where it recorded one.
    #[test]
    fn codec_is_read_where_the_relay_recorded_one() {
        let call = parsed();
        let codecs: Vec<Option<&str>> = call.tags.iter().map(|t| t.codec.as_deref()).collect();
        assert!(
            codecs.contains(&Some("G722/8000")),
            "the relay recorded G722 on one side: {codecs:?}"
        );
    }

    /// A v6 endpoint keeps its brackets, so the result parses back.
    ///
    /// Without them `::1` and port `5060` render as `::1:5060`, which is not a
    /// socket address any parser accepts -- the port reads as another hextet.
    /// A relay on v6 would produce a join key nothing downstream could use.
    #[test]
    fn a_v6_endpoint_is_bracketed() {
        use super::tests::bstr;

        let ep = format!(
            "d{}{}{}{}{}i5060ee",
            bstr("family"),
            bstr("IPv6"),
            bstr("address"),
            bstr("2001:db8::5"),
            bstr("port"),
        );
        let stream = format!(
            "d{}{}{}i40000e{}{ep}e",
            bstr("local address"),
            bstr("2001:db8::1"),
            bstr("local port"),
            bstr("endpoint"),
        );
        let media = format!("d{}i1e{}l{stream}ee", bstr("index"), bstr("streams"));
        let tag_entry = format!(
            "d{}l{media}e{}{}e",
            bstr("medias"),
            bstr("tag"),
            bstr("v6-tag"),
        );
        let body = format!(
            "d{}{}{}d{}{tag_entry}ee",
            bstr("result"),
            bstr("ok"),
            bstr("tags"),
            bstr("v6-tag"),
        );

        let ControlReply::Call(call) =
            parse_query_reply(body.as_bytes(), "v6@example.net").expect("must parse")
        else {
            panic!("expected a call view");
        };
        let rendered = call.tags[0].streams[0]
            .endpoint
            .clone()
            .expect("the stream has an endpoint");
        assert_eq!(rendered, "[2001:db8::5]:5060");
        assert!(
            rendered.parse::<std::net::SocketAddr>().is_ok(),
            "the rendered endpoint must parse back; that is the whole reason \
             for the brackets: {rendered}"
        );
    }

    /// A refusal is the relay answering, not the transport failing.
    #[test]
    fn a_refused_query_is_reported_as_a_refusal() {
        let body = format!(
            "d{}{}{}{}e",
            super::tests::bstr("error-reason"),
            super::tests::bstr("Unknown call-id"),
            super::tests::bstr("result"),
            super::tests::bstr("error"),
        );
        match parse_query_reply(body.as_bytes(), "gone@example.net") {
            Ok(ControlReply::Refused { reason }) => assert_eq!(reason, "Unknown call-id"),
            other => panic!("a relay error must not read as a transport failure: {other:?}"),
        }
    }

    /// A truncated datagram must fail, not read as a call with no tags.
    ///
    /// This is the same failure mode the `list` cap guards: a short answer
    /// that parses is reported as a complete one, and every stream in the call
    /// stays an orphan with no sign anything went wrong.
    #[test]
    fn a_truncated_reply_fails_rather_than_reading_as_an_empty_call() {
        let short = &REAL_QUERY[..REAL_QUERY.len() / 2];
        assert!(
            parse_query_reply(short, "1-9582@172.28.0.21").is_err(),
            "half a reply must not parse as a call with no streams"
        );
    }
}
