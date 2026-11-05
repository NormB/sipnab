// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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

use crate::relay::types::{
    CallView, ControlReply, Enumeration, ReadOnlyCommand, RelayStream, RelayStreamFacts, RelayTag,
    StreamCounters,
};
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

/// Largest control reply this client will read back over a STREAM.
///
/// The datagram path is bounded by the kernel, which truncates anything past
/// its own limit. A stream is bounded by nothing, so without this the relay --
/// or whatever answered in its place on an operator-supplied address --
/// decides how much memory sipnab allocates.
///
/// Sized against the answer it exists to allow. Measured against rtpengine
/// 14.2.0.0 holding 1200 calls with 55-character Call-IDs, an enumeration of
/// 1200 is 73234 bytes; [`crate::relay::reconcile::WIDE_LIST_LIMIT`] Call-IDs
/// of a kilobyte each is the pathological end of the same shape, and that is
/// what this covers.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
const MAX_STREAM_REPLY_BYTES: usize = 1024 * 1024;

impl ReadOnlyCommand {
    /// The ng verb, as it goes on the wire.
    #[must_use]
    pub fn verb(&self) -> &'static str {
        match self {
            Self::List { .. } => "list",
            Self::Query { .. } => "query",
            Self::Statistics => "statistics",
        }
    }
}

impl fmt::Display for ReadOnlyCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::List { limit } => write!(f, "list(limit={limit})"),
            // No arguments, so nothing here can carry a caller's data.
            Self::Statistics => write!(f, "statistics"),
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
            // One key and no arguments. Nothing here is caller-supplied, so
            // there is no field an agent could aim at a host of its choosing.
            ReadOnlyCommand::Statistics => {
                encode_dict(vec![(b"command".as_slice(), Value::Bytes(b"statistics"))])
            }
        };
        let mut out = Vec::with_capacity(self.cookie.len() + 1 + body.len());
        out.extend_from_slice(self.cookie.as_bytes());
        out.push(b' ');
        out.extend_from_slice(&body);
        out
    }
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

/// Read a `stats`-shaped dictionary into counters, each field on its own.
///
/// A field the dictionary does not carry, or carries as something other than
/// a non-negative integer, is `None`: one unreadable field never takes the
/// others with it, and none is read as zero.
fn counters_from(v: Option<&Value<'_>>) -> StreamCounters {
    let field = |counter: &[u8]| {
        v.and_then(|d| d.get_int(counter))
            .and_then(|n| u64::try_from(n).ok())
    };
    StreamCounters {
        packets: field(b"packets"),
        bytes: field(b"bytes"),
        errors: field(b"errors"),
    }
}

/// Read a stream's `flags` list as the relay wrote it, or `None` when the
/// stream carries no list.
fn flags_from(v: Option<&Value<'_>>) -> Option<Vec<String>> {
    let Some(Value::List(items)) = v else {
        return None;
    };
    Some(
        items
            .iter()
            .filter_map(|x| match x {
                Value::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
                _ => None,
            })
            .collect(),
    )
}

/// Parse a `query` reply for `call_id`.
///
/// `call_id` is the one that was ASKED about. See [`CallView`] for why it
/// cannot come from the reply.
///
/// # Errors
///
/// When the reply is not bencode or carries no `result`. A reply the relay
/// Walk a bencode value into flat `name = value` pairs.
///
/// Dotted names, so a nested counter keeps the path that gives it meaning:
/// `totals.rtp.packets` says something `packets` alone does not. Byte strings
/// that are not UTF-8 are rendered as their length rather than dropped --
/// a counter sipnab cannot read is still a counter the relay reported, and
/// silently omitting it would make the answer look complete.
fn flatten_bencode(
    prefix: &str,
    value: &crate::rtpengine::bencode::Value<'_>,
    out: &mut Vec<(String, String)>,
) {
    use crate::rtpengine::bencode::Value;
    let join = |k: &str| {
        if prefix.is_empty() {
            k.to_string()
        } else {
            format!("{prefix}.{k}")
        }
    };
    match value {
        Value::Int(n) => out.push((prefix.to_string(), n.to_string())),
        Value::Bytes(b) => out.push((
            prefix.to_string(),
            std::str::from_utf8(b)
                .map_or_else(|_| format!("<{} bytes>", b.len()), ToString::to_string),
        )),
        Value::List(items) => {
            for (i, item) in items.iter().enumerate() {
                flatten_bencode(&join(&i.to_string()), item, out);
            }
        }
        Value::Dict(entries) => {
            for (k, v) in entries {
                let key = String::from_utf8_lossy(k).into_owned();
                flatten_bencode(&join(&key), v, out);
            }
        }
    }
}

/// Read a `statistics` answer into name/value pairs.
///
/// Kept as the relay wrote them. rtpengine reports a deep dictionary whose
/// keys differ between versions, and flattening it into a schema of sipnab's
/// own would freeze one version's vocabulary into a type -- the pinned-value
/// defect this repository has paid for before. A caller that wants a specific
/// counter looks it up by the name the relay used.
///
/// # Errors
///
/// When the body is not a dictionary at all.
pub fn parse_statistics_reply(body: &[u8]) -> anyhow::Result<ControlReply> {
    // `body` is the BENCODE alone. The cookie and its space are the transport's
    // framing, stripped and VALIDATED by `framed_reply_body` before this is
    // called -- so this decodes from the front and does not strip again. It
    // did strip a cookie once, which double-stripped the live path (the client
    // hands over an already-framed body) while a test that passed the raw
    // datagram masked it: the reply then decoded fine because the spurious
    // strip removed the cookie the test had left on.
    let decoded = crate::rtpengine::bencode::decode(body)
        .map_err(|e| anyhow::anyhow!("statistics reply is not bencode: {e}"))?;
    let mut pairs: Vec<(String, String)> = Vec::new();
    flatten_bencode("", &decoded, &mut pairs);
    if pairs.is_empty() {
        anyhow::bail!("statistics reply carried no counters");
    }
    pairs.sort();
    Ok(ControlReply::Statistics(pairs))
}

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
            let mut media_subscriptions = Vec::new();
            // Each `subscriptions` entry is stamped with a `type`, and the two
            // values mean different things about the call: `offer/answer` is
            // the other side of a SIP dialog, `pub/sub` is a side that merely
            // RECEIVES this one's media -- which is how relay-side recording
            // and forking are built. Reading both into one list reports a
            // recorder as the party the call is with.
            //
            // Anything that is not `pub/sub` is read as a dialog peer,
            // including an entry with no `type` at all: the only producer
            // known to write this key always writes the type beside it, so an
            // entry without one is a shape this parser has not seen, and the
            // reading that was correct before the type existed is the safer
            // one to fall back to.
            if let Some(Value::List(subs)) = tv.get(b"subscriptions") {
                for sub in subs {
                    let Some(other) = sub.get_str(b"tag") else {
                        continue;
                    };
                    let target = if sub.get_str(b"type").as_deref() == Some("pub/sub") {
                        &mut media_subscriptions
                    } else {
                        &mut in_dialogue_with
                    };
                    if !target.contains(&other) {
                        target.push(other);
                    }
                }
            }
            // Older builds carried the peer's tag DIRECTLY under
            // `in dialogue with`, as a byte string and not as a list -- there
            // was one active dialog per side before one-to-many forwarding
            // existed. Read as a list it matches nothing, and every call on
            // such a relay comes back with no other side at all.
            if let Some(other) = tv.get_str(b"in dialogue with")
                && !in_dialogue_with.contains(&other)
            {
                in_dialogue_with.push(other);
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
                        let facts = RelayStreamFacts {
                            media_index: media
                                .get_int(b"index")
                                .and_then(|n| u32::try_from(n).ok()),
                            // `stats` is what ARRIVED at this socket and
                            // `stats_out` what the relay sent from it: in a
                            // recorded one-way call the silent callee's socket
                            // has `stats.packets` 0 and `stats_out.packets`
                            // equal to the caller's `stats.packets`.
                            ingress: counters_from(s.get(b"stats")),
                            egress: counters_from(s.get(b"stats_out")),
                            last_packet: s.get_int(b"last packet"),
                            flags: flags_from(s.get(b"flags")),
                        };
                        streams.push(RelayStream {
                            local_address,
                            local_port,
                            endpoint: endpoint_str(s.get(b"endpoint")),
                            advertised_endpoint: endpoint_str(s.get(b"advertised endpoint")),
                            is_rtcp,
                            ssrcs,
                            facts,
                        });
                    }
                }
            }

            tags.push(RelayTag {
                tag,
                in_dialogue_with,
                media_subscriptions,
                codec,
                streams,
            });
        }
    }

    // A deterministic order, so two runs against the same relay produce the
    // same report and a diff of two reports means something changed.
    crate::sort::sort_by_dyn(&mut tags, &mut |a, b| a.tag.cmp(&b.tag));

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
}

/// Every cookie seed this process mints, from every [`ControlClient`].
///
/// One sequence for the whole process, not one per client. A run holds
/// several clients at once (the REST and MCP doors, the reconciler, the
/// poller), each built a few microseconds after the last. With a per-client
/// time base and counter, a client built N nanoseconds after another minted,
/// as its first cookie, that other client's (N+1)th, and rtpengine replays the
/// cached reply to a cookie it saw in the last 30 to 60 seconds, so one
/// client's question got the other's answer.
///
/// The base is the wall clock in nanoseconds the first time a seed is minted,
/// so a restarted sipnab does not reuse the previous run's cookies: it would
/// need to have minted more seeds than nanoseconds passed between the runs.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
fn process_seed() -> u64 {
    static BASE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let base = *BASE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64)
    });
    base.wrapping_add(COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Split a reply into its cookie and its body, refusing one that answers a
/// different question.
///
/// rtpengine frames a reply exactly as the request: cookie, one space, then
/// the bencode. The cookie check is not decoration -- rtpengine replays cached
/// replies keyed on the cookie, so a reply carrying somebody else's describes
/// some other call's streams.
///
/// `Ok(None)` means the framing space has not arrived yet, which only a stream
/// can be in the middle of; a datagram either carries the whole message or the
/// kernel already threw the rest away.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
fn framed_reply_body<'a>(buf: &'a [u8], cookie: &str) -> anyhow::Result<Option<&'a [u8]>> {
    let Some(space) = buf.iter().position(|b| *b == b' ') else {
        return Ok(None);
    };
    if &buf[..space] != cookie.as_bytes() {
        // ST-S4 condition 7: a reply whose cookie does not match answers a
        // different transaction (rtpengine replays cached replies keyed on the
        // cookie). It is discarded here and never interpreted; the typed marker
        // makes the surface classify it `suspect` -- the answer's own problem --
        // rather than `unreachable`, which would read as no answer at all.
        return Err(anyhow::Error::new(crate::relay::types::UntrustedReply {
            reason: "reply cookie does not match the request; it answers a \
                     different transaction"
                .to_string(),
        }));
    }
    Ok(Some(&buf[space + 1..]))
}

/// Mark a reply that ARRIVED and could not be read as untrusted.
///
/// A body that is not bencode, lacks the keys its answer needs, or a datagram
/// with no cookie framing came back from the relay's port; reported as a fetch
/// that got nothing, every surface would say "asked, nothing came back"
/// (`unreachable`) about a reply it holds. Typed as
/// [`crate::relay::types::UntrustedReply`], it classifies `suspect`, the
/// answer's own problem, as a mismatched cookie does. The parser's words travel
/// in the reason.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
fn unreadable_reply(e: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(crate::relay::types::UntrustedReply {
        reason: format!("{e:#}"),
    })
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
        Self { addr, timeout }
    }

    /// The relay this client talks to.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Mint a cookie seed that no client in this process has used.
    fn next_seed(&self) -> u64 {
        process_seed()
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
        parse_list_reply(&body, limit).map_err(unreadable_reply)
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
        parse_query_reply(&body, call_id).map_err(unreadable_reply)
    }

    /// Ask the relay for its own counters.
    ///
    /// Sent only when something asked. This is the one class of answer sipnab
    /// cannot derive from the capture -- what the relay itself has handled and
    /// dropped -- so an API caller or an agent needing it has no other source,
    /// and a run with no such question sends nothing.
    ///
    /// # Errors
    ///
    /// When the relay will not answer, or answers something unparseable.
    /// Ask the relay for its own PER-CALL counters (ST7/C2).
    ///
    /// The same `query` a caller uses for attribution, read differently: the
    /// reply's whole dict is flattened into name/value pairs -- per-stream and
    /// per-SSRC packet and byte counts, the `totals` split by RTP and RTCP --
    /// rather than into the tags-and-streams `CallView`. Both are the relay's
    /// own claim about one call, so both are `relay_reported`; this path is the
    /// counters, `query` is the topology.
    ///
    /// # Errors
    ///
    /// When the socket cannot be opened, the exchange fails or times out, or
    /// the reply does not parse.
    pub fn call_statistics(
        &self,
        _permit: &TransmitPermit,
        call_id: &str,
    ) -> anyhow::Result<ControlReply> {
        let request = ControlRequest::new(
            ReadOnlyCommand::Query {
                call_id: call_id.to_owned(),
            },
            self.next_seed(),
        );
        let body = self.round_trip(&request)?;
        // The reply is a bencode dict, framed exactly as `statistics`; the same
        // flattener reads it. A relay that does not hold the call answers
        // `result: error` / `error-reason: Unknown call-id`, which flattens to
        // those two pairs rather than to counters -- the caller sees the
        // relay's own words, not an invented "no such call".
        parse_statistics_reply(&body).map_err(unreadable_reply)
    }

    /// Ask the relay for its own counters.
    ///
    /// Sent only when something asked. This is the one class of answer sipnab
    /// cannot derive from the capture -- what the relay itself has handled and
    /// dropped -- so an API caller or an agent needing it has no other source,
    /// and a run with no such question sends nothing.
    ///
    /// # Errors
    ///
    /// When the relay will not answer, or answers something unparseable.
    pub fn statistics(&self, _permit: &TransmitPermit) -> anyhow::Result<ControlReply> {
        let request = ControlRequest::new(ReadOnlyCommand::Statistics, self.next_seed());
        let body = self.round_trip(&request)?;
        parse_statistics_reply(&body).map_err(unreadable_reply)
    }

    /// Whether this command's ANSWER is too big for a datagram to carry.
    ///
    /// The transport is chosen by the size of the answer being asked for, and
    /// by nothing else. rtpengine's own documentation warns that a `list`
    /// beyond the default "may not fit in a UDP packet, and therefore be
    /// invalid", and measurement bears it out: against 14.2.0.0 holding 1200
    /// calls, `limit: 1200` is a 73234-byte answer that draws NO reply at all
    /// over a datagram and returns in full over `listen-tcp-ng`.
    ///
    /// So availability is discovered rather than declared: a relay with no
    /// stream listener refuses the connection, the wider ask fails, and the
    /// caller keeps the capped answer it already has and says so. No flag
    /// asserts a listener that may not be there.
    fn needs_a_stream(command: &ReadOnlyCommand) -> bool {
        matches!(
            command,
            ReadOnlyCommand::List { limit }
                if *limit > crate::relay::reconcile::DEFAULT_LIST_LIMIT
        )
    }

    /// Send one request and read one reply, over whichever transport can
    /// carry the answer.
    fn round_trip(&self, request: &ControlRequest) -> anyhow::Result<Vec<u8>> {
        if Self::needs_a_stream(&request.command) {
            self.round_trip_stream(request)
        } else {
            self.round_trip_datagram(request)
        }
    }

    /// Send one request and read one reply over a stream.
    ///
    /// The framing is identical to the datagram form -- cookie, space,
    /// bencode -- and rtpengine writes it the same way on both, from one
    /// function. What differs is that a stream has no message boundary: the
    /// reply arrives in as many pieces as the network chooses, the connection
    /// stays open afterwards, and there is therefore no EOF to read up to. So
    /// the loop reads until the bencode COMPLETES, which is what rtpengine's
    /// own reader does in the other direction.
    ///
    /// Not a hypothetical: a 61034-byte answer from 14.2.0.0 arrived in two
    /// reads, so a client that treats one read as one reply parses half a
    /// message and reports a working relay as broken.
    fn round_trip_stream(&self, request: &ControlRequest) -> anyhow::Result<Vec<u8>> {
        use anyhow::Context;
        use std::io::{Read, Write};

        let mut conn = std::net::TcpStream::connect_timeout(&self.addr, self.timeout)
            .with_context(|| {
                format!(
                    "connecting to the relay at {} over a stream transport",
                    self.addr
                )
            })?;
        conn.set_read_timeout(Some(self.timeout))
            .context("setting the control read timeout")?;
        conn.set_write_timeout(Some(self.timeout))
            .context("setting the control write timeout")?;
        conn.write_all(&request.to_wire())
            .with_context(|| format!("sending {} to {}", request.command, self.addr))?;

        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            // A stream has no message boundary, so completeness is the only
            // thing that says the reply has all arrived. Asked of the parser
            // that will read it, rather than of a second scanner that could
            // disagree with it.
            if let Some(body) = framed_reply_body(&buf, request.cookie())?
                && super::bencode::decode(body).is_ok()
            {
                return Ok(body.to_vec());
            }
            if buf.len() > MAX_STREAM_REPLY_BYTES {
                anyhow::bail!(
                    "the relay's answer is larger than the {MAX_STREAM_REPLY_BYTES} \
                     byte ceiling this client reads; nothing on the far end of a \
                     stream bounds it but this"
                );
            }
            let n = conn.read(&mut chunk).with_context(|| {
                format!(
                    "no complete reply from {} within {:?} -- the answer was \
                     still arriving, or it is not a complete message",
                    self.addr, self.timeout
                )
            })?;
            if n == 0 {
                anyhow::bail!(
                    "the relay at {} closed the connection with an incomplete \
                     reply",
                    self.addr
                );
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Send one request and read one reply as a datagram.
    ///
    /// UDP, because that is rtpengine's default control transport. The reply
    /// buffer is bounded: a datagram larger than this is truncated by the
    /// kernel, and a truncated bencode message fails to parse rather than being
    /// read as a short list -- which is the right failure, because a silently
    /// short list is the thing RE4 is most careful about.
    fn round_trip_datagram(&self, request: &ControlRequest) -> anyhow::Result<Vec<u8>> {
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
        // One rule for both transports, in one place -- a second copy here is
        // a cookie check that can be fixed on one path and left wrong on the
        // other.
        let body = framed_reply_body(&buf, request.cookie())?
            .ok_or_else(|| unreadable_reply(anyhow::anyhow!("reply carries no cookie framing")))?;
        Ok(body.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtpengine::bencode::decode;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// Every cookie is different, and that is the whole point.
    ///
    /// rtpengine deduplicates on the cookie and replays the cached reply for a
    /// repeat. During RE1 development that returned ports belonging to a call
    /// that had already been deleted -- an answer that looked correct and
    /// described a call that no longer existed. A reused cookie is not a
    /// wasted round trip, it is a wrong answer.
    #[test]
    fn every_transaction_gets_its_own_cookie() -> Result<(), TestError> {
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
        Ok(())
    }

    /// The cookie says who is asking.
    #[test]
    fn the_cookie_names_the_tool() -> Result<(), TestError> {
        let r = ControlRequest::new(ReadOnlyCommand::List { limit: 8 }, 0xdead);
        assert!(
            r.cookie().starts_with("sipnab-"),
            "an unattributed cookie in a relay's log is a mystery somebody has \
             to spend time on: {}",
            r.cookie()
        );
        Ok(())
    }

    /// The wire format is `<cookie> <bencode>`, cookie outside the dict.
    #[test]
    fn a_list_request_is_framed_and_encoded() -> Result<(), TestError> {
        let r = ControlRequest::new(ReadOnlyCommand::List { limit: 32 }, 7);
        let wire = r.to_wire();

        let space = wire
            .iter()
            .position(|b| *b == b' ')
            .ok_or("framing space")?;
        assert_eq!(
            &wire[..space],
            r.cookie().as_bytes(),
            "the cookie must precede the message, outside the bencode"
        );

        let body =
            decode(&wire[space + 1..]).map_err(|e| format!("body must be bencode: {e:?}"))?;
        assert_eq!(body.get(b"command"), Some(&Value::Bytes(b"list")));
        assert_eq!(body.get(b"limit"), Some(&Value::Int(32)));
        Ok(())
    }

    /// A query carries the Call-ID it asks about.
    #[test]
    fn a_query_request_carries_its_call_id() -> Result<(), TestError> {
        let r = ControlRequest::new(
            ReadOnlyCommand::Query {
                call_id: "abc@example.net".to_string(),
            },
            9,
        );
        let wire = r.to_wire();
        let space = wire.iter().position(|b| *b == b' ').ok_or("space")?;
        let body = decode(&wire[space + 1..]).map_err(|e| format!("bencode: {e:?}"))?;
        assert_eq!(body.get(b"command"), Some(&Value::Bytes(b"query")));
        assert_eq!(
            body.get(b"call-id"),
            Some(&Value::Bytes(b"abc@example.net"))
        );
        Ok(())
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
    fn no_command_this_module_can_build_changes_the_relay() -> Result<(), TestError> {
        for cmd in [
            ReadOnlyCommand::List { limit: 1 },
            ReadOnlyCommand::Query {
                call_id: "x".to_string(),
            },
            ReadOnlyCommand::Statistics,
        ] {
            let verb = match &cmd {
                ReadOnlyCommand::List { .. } => "list",
                ReadOnlyCommand::Query { .. } => "query",
                ReadOnlyCommand::Statistics => "statistics",
            };
            assert_eq!(cmd.verb(), verb);
            assert!(
                matches!(verb, "list" | "query" | "statistics"),
                "a verb outside the read-only set reached the wire: {verb}"
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
        Ok(())
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    /// A permit, for tests that must call a permit-gated function.
    ///
    /// Obtained the only way there is: from a live capture source. A test that
    /// could conjure one would prove nothing about the gate.
    fn live_permit() -> Result<TransmitPermit, TestError> {
        use crate::capture::CaptureSource;
        Ok(TransmitPermit::for_source(&CaptureSource::Live {
            device: "test0".to_string(),
        })
        .ok_or("a live source must grant a permit")?)
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    /// Stand in for a relay: answer one datagram with `reply`, echoing the
    /// cookie the client sent so the framing check passes.
    ///
    /// A real socket rather than a mocked one, because the thing most likely
    /// to be wrong is the framing and the connect/timeout handling, and a mock
    /// would assert my own assumptions back at me.
    fn fake_relay(
        reply_body: &'static str,
    ) -> Result<(SocketAddr, std::thread::JoinHandle<()>), TestError> {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind: {e:?}"))?;
        let addr = sock.local_addr().map_err(|e| format!("addr: {e:?}"))?;
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
        Ok((addr, handle))
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
    fn a_round_trip_against_a_relay_returns_its_calls() -> Result<(), TestError> {
        let (addr, relay) = fake_relay("d6:result2:ok5:callsl4:aaaa4:bbbbee")?;
        let client = ControlClient::new(addr, Duration::from_secs(2));

        let reply = client
            .list(&live_permit()?, 32)
            .map_err(|e| format!("the relay answered; parsing must succeed: {e:?}"))?;
        match reply {
            ControlReply::Calls(e) => {
                assert_eq!(e.call_ids, vec!["aaaa".to_string(), "bbbb".to_string()]);
                assert!(!e.truncated, "two of thirty-two is complete");
            }
            other => return Err(format!("expected calls, got {other:?}").into()),
        }
        relay.join().map_err(|e| format!("relay thread: {e:?}"))?;
        Ok(())
    }

    /// A reply answering a DIFFERENT transaction is refused.
    ///
    /// rtpengine replays cached replies keyed on the cookie, and a stray
    /// datagram on a connected socket is possible from the same peer. A reply
    /// whose cookie is not ours describes some other question, and accepting
    /// it would attribute one call's streams to another.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_reply_with_the_wrong_cookie_is_refused() -> Result<(), TestError> {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind: {e:?}"))?;
        let addr = sock.local_addr().map_err(|e| format!("addr: {e:?}"))?;
        let relay = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            if let Ok((_, peer)) = sock.recv_from(&mut buf) {
                // Deliberately the wrong cookie.
                let _ = sock.send_to(b"sipnab-somebodyelse d6:result2:oke", peer);
            }
        });

        let client = ControlClient::new(addr, Duration::from_secs(2));
        let err = client
            .list(&live_permit()?, 32)
            .err()
            .ok_or("a mismatched cookie must not be accepted")?;
        assert!(
            err.to_string().contains("different transaction"),
            "the error must name the cause: {err}"
        );
        // ST-S4 condition 7: a mismatched cookie is a typed UntrustedReply, so
        // every surface classifies it SUSPECT (the answer's own problem), never
        // unreachable (asked, nothing came back).
        assert!(
            err.downcast_ref::<crate::relay::types::UntrustedReply>()
                .is_some(),
            "a mismatched cookie must be a typed UntrustedReply: {err:#}"
        );
        assert_eq!(
            crate::relay::types::fetch_error_outcome(&err),
            crate::stats_vocab::StatisticsOutcome::Suspect,
            "a reply that could not be trusted is suspect, not unreachable"
        );
        relay.join().map_err(|e| format!("relay thread: {e:?}"))?;
        Ok(())
    }

    /// A reply that arrives and cannot be read is `suspect`, never
    /// `unreachable`.
    ///
    /// `unreachable` says "asked, nothing came back", and every surface words
    /// it that way. A datagram that came back with our cookie and a body that
    /// is not bencode, or with no framing at all, did come back: it is an
    /// answer that cannot be trusted, ST-S4's suspect. Each of the four asks
    /// reads its reply through its own parser, so each is driven here.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_reply_that_arrives_and_cannot_be_read_is_suspect() -> Result<(), TestError> {
        type Ask = fn(&ControlClient, &TransmitPermit) -> anyhow::Result<ControlReply>;
        let asks: [(&str, Ask); 4] = [
            ("list", |c, p| c.list(p, 32)),
            ("query", |c, p| c.query(p, "c@192.0.2.10")),
            ("statistics", |c, p| c.statistics(p)),
            ("call_statistics", |c, p| {
                c.call_statistics(p, "c@192.0.2.10")
            }),
        ];
        // The body after our own cookie, or the whole datagram when `None`
        // marks a reply with no framing at all.
        let replies: [(&str, Option<&[u8]>); 3] = [
            ("not bencode", Some(b"this is not bencode")),
            ("an empty dictionary", Some(b"de")),
            ("no framing", None),
        ];
        for (what, body) in replies {
            for (name, ask) in asks {
                let sock =
                    std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind: {e:?}"))?;
                let addr = sock.local_addr().map_err(|e| format!("addr: {e:?}"))?;
                let relay = std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                        let space = buf[..n].iter().position(|b| *b == b' ').unwrap_or(0);
                        let out = match body {
                            Some(body) => [&buf[..=space], body].concat(),
                            None => b"garbage".to_vec(),
                        };
                        let _ = sock.send_to(&out, peer);
                    }
                });
                let client = ControlClient::new(addr, Duration::from_secs(2));
                let err = ask(&client, &live_permit()?)
                    .err()
                    .ok_or_else(|| format!("{name}, {what}: an unreadable reply was accepted"))?;
                assert_eq!(
                    crate::relay::types::fetch_error_outcome(&err),
                    crate::stats_vocab::StatisticsOutcome::Suspect,
                    "{name}, {what}: a reply came back, so it is suspect: {err:#}"
                );
                relay.join().map_err(|e| format!("relay thread: {e:?}"))?;
            }
        }
        Ok(())
    }

    /// A relay that never answers times out rather than hanging.
    ///
    /// An analysis tool that blocks forever on a silent relay is worse than
    /// one that reports the silence: the operator is left with neither an
    /// answer nor a prompt.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_silent_relay_times_out() -> Result<(), TestError> {
        // Bound but never read from: the port exists, nothing replies.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind: {e:?}"))?;
        let addr = sock.local_addr().map_err(|e| format!("addr: {e:?}"))?;

        let client = ControlClient::new(addr, Duration::from_millis(250));
        let start = std::time::Instant::now();
        let err = client
            .list(&live_permit()?, 32)
            .err()
            .ok_or("a silent relay must not succeed")?;
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the read timeout did not apply; this would hang a run"
        );
        assert!(
            err.to_string().contains("no reply"),
            "the error must say the relay was silent: {err}"
        );
        // The contrast that makes the suspect classification meaningful: a
        // timeout is UNREACHABLE (asked, nothing came back), never suspect.
        assert_eq!(
            crate::relay::types::fetch_error_outcome(&err),
            crate::stats_vocab::StatisticsOutcome::Unreachable,
            "a silent relay is unreachable, not suspect"
        );
        drop(sock);
        Ok(())
    }

    /// Two calls from one client never reuse a cookie.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_client_mints_a_fresh_cookie_per_call() -> Result<(), TestError> {
        let client = ControlClient::new(
            "127.0.0.1:1".parse().map_err(|e| format!("addr: {e:?}"))?,
            Duration::from_millis(1),
        );
        let a = client.next_seed();
        let b = client.next_seed();
        assert_ne!(a, b, "a client reused a cookie seed across transactions");
        Ok(())
    }

    /// Two clients in one process never mint the same cookie. A run holds
    /// several at once (the REST and MCP doors, the reconciler, the poller),
    /// all talking to one relay, and rtpengine replays its cached reply to a
    /// cookie it saw in the last 30 to 60 seconds, so a cookie one client
    /// reuses from another gets that other question's answer.
    ///
    /// The clients are built back to back, as `start_servers` builds the REST
    /// and MCP ones: a per-client nanosecond base puts the second client's
    /// first seed inside the first client's next million.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn two_clients_in_one_process_never_share_a_cookie() -> Result<(), TestError> {
        let addr: SocketAddr = "127.0.0.1:1".parse().map_err(|e| format!("addr: {e:?}"))?;
        let first = ControlClient::new(addr, Duration::from_millis(1));
        let second = ControlClient::new(addr, Duration::from_millis(1));
        let theirs = second.next_seed();
        for n in 0..1_000_000u64 {
            assert_ne!(
                first.next_seed(),
                theirs,
                "the first client's seed {n} is the second client's first seed"
            );
        }
        Ok(())
    }

    /// `fetch_error_outcome` classifies an untrusted reply as suspect -- the
    /// answer's own problem -- so a surface does not report it as no answer.
    #[test]
    fn an_untrusted_reply_classifies_as_suspect() -> Result<(), TestError> {
        let err = anyhow::Error::new(crate::relay::types::UntrustedReply {
            reason: "reply cookie does not match".to_string(),
        });
        assert_eq!(
            crate::relay::types::fetch_error_outcome(&err),
            crate::stats_vocab::StatisticsOutcome::Suspect,
        );
        Ok(())
    }

    /// Any other fetch failure -- a timeout, a socket error -- is unreachable:
    /// asked, and nothing valid came back. The default the classifier gives
    /// everything that is not a typed untrusted reply.
    #[test]
    fn a_plain_fetch_error_classifies_as_unreachable() -> Result<(), TestError> {
        let err = anyhow::anyhow!("no reply from the relay within 2s");
        assert_eq!(
            crate::relay::types::fetch_error_outcome(&err),
            crate::stats_vocab::StatisticsOutcome::Unreachable,
        );
        Ok(())
    }

    /// The untrusted-reply marker carries its reason through, so a surface can
    /// say why the reply was discarded rather than only that it was.
    #[test]
    fn an_untrusted_reply_carries_its_reason() -> Result<(), TestError> {
        let err = crate::relay::types::UntrustedReply {
            reason: "reply cookie does not match the request".to_string(),
        };
        assert!(
            err.to_string().contains("reply cookie does not match"),
            "the reason must travel: {err}"
        );
        Ok(())
    }

    /// A full answer is reported as possibly truncated, because that is the
    /// only evidence rtpengine gives.
    ///
    /// It returns at most `limit` and never says whether it had more. Treating
    /// "exactly the limit" as complete is how 32 of 400 calls gets reported as
    /// the whole estate, with the other 368 looking like orphans.
    #[test]
    fn a_full_answer_is_flagged_because_more_may_exist() -> Result<(), TestError> {
        // Fewer than asked for: the relay ran out, so this is everything.
        let body = b"d6:result2:ok5:callsl4:aaaa4:bbbbee";
        match parse_list_reply(body, 32).map_err(|e| format!("parse: {e:?}"))? {
            ControlReply::Calls(e) => {
                assert_eq!(e.call_ids.len(), 2);
                assert!(!e.truncated, "two of thirty-two is not truncated");
            }
            other => return Err(format!("expected calls, got {other:?}").into()),
        }

        // Exactly the limit: may be more behind it.
        match parse_list_reply(body, 2).map_err(|e| format!("parse: {e:?}"))? {
            ControlReply::Calls(e) => assert!(
                e.truncated,
                "a full answer must be flagged; the relay does not say whether \
                 it had more"
            ),
            other => return Err(format!("expected calls, got {other:?}").into()),
        }
        Ok(())
    }

    /// A refusal is not a transport failure.
    ///
    /// The relay was reached, understood the question and declined it.
    /// Collapsing that into an I/O error tells an operator to check the
    /// network when the answer is in the relay's configuration.
    #[test]
    fn a_refusal_is_reported_as_a_refusal() -> Result<(), TestError> {
        let body = format!(
            "d{}{}{}{}e",
            bstr("result"),
            bstr("error"),
            bstr("error-reason"),
            bstr("unknown command")
        );
        match parse_list_reply(body.as_bytes(), 32).map_err(|e| format!("parse: {e:?}"))? {
            ControlReply::Refused { reason } => {
                assert!(reason.contains("unknown command"), "reason lost: {reason}");
            }
            other => return Err(format!("expected a refusal, got {other:?}").into()),
        }

        // A refusal with no reason is still a refusal.
        let bare = format!("d{}{}e", bstr("result"), bstr("error"));
        match parse_list_reply(bare.as_bytes(), 32).map_err(|e| format!("parse: {e:?}"))? {
            ControlReply::Refused { reason } => assert!(
                !reason.is_empty(),
                "a refusal with no stated reason must still say something"
            ),
            other => return Err(format!("expected a refusal, got {other:?}").into()),
        }
        Ok(())
    }

    /// A malformed reply is an error, never a quiet empty answer.
    ///
    /// An empty enumeration and an unparseable one look identical downstream:
    /// both leave every stream unmatched. One is a fact about the relay and
    /// the other is a fact about this parser.
    #[test]
    fn a_malformed_reply_is_refused_rather_than_read_as_empty() -> Result<(), TestError> {
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
        Ok(())
    }

    /// A partial enumeration must say so, or it reports the calls it never saw
    /// as orphans and looks like it worked.
    #[test]
    fn a_truncated_enumeration_announces_itself() -> Result<(), TestError> {
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
        Ok(())
    }

    /// A Call-ID is a caller's identifier; Display must not put it in a log.
    #[test]
    fn display_does_not_leak_the_call_id() -> Result<(), TestError> {
        let q = ReadOnlyCommand::Query {
            call_id: "sensitive-caller@example.net".to_string(),
        };
        let shown = q.to_string();
        assert!(
            !shown.contains("sensitive-caller"),
            "Display leaked a Call-ID into a string that ends up in logs \
             outliving the capture: {shown}"
        );
        Ok(())
    }

    /// Stand in for a relay reachable on BOTH transports at ONE address, with
    /// a DIFFERENT answer on each.
    ///
    /// The two answers differ so a test can say which transport carried the
    /// question. A fake that answered identically on both could not tell a
    /// deliberate choice from a coincidence, which is the only thing these
    /// tests are for.
    ///
    /// Real sockets rather than a mock: the framing, the connect and the
    /// read loop are the parts most likely to be wrong, and a mock would
    /// assert my own assumptions back at me.
    ///
    /// Each side is named by the ONE Call-ID it answers with, and the reply is
    /// built by [`bstr`] rather than typed out: the length prefix in
    /// `18:from-the-datagram` is seventeen characters of string, and a
    /// hand-counted fixture is a test that fails for a reason that has nothing
    /// to do with the code.
    /// The threads are DETACHED rather than returned. Whichever transport the
    /// client did not choose leaves its thread blocked forever -- on `accept`
    /// or on `recv_from` -- and joining that one is a test that hangs instead
    /// of failing. Which transport goes unused is exactly what these tests
    /// vary, so there is no handle a caller could safely wait on.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    fn dual_relay(datagram_call: &str, stream_call: &str) -> Result<SocketAddr, TestError> {
        let datagram_reply = format!("d6:result2:ok5:callsl{}ee", bstr(datagram_call));
        let stream_reply = format!("d6:result2:ok5:callsl{}ee", bstr(stream_call));
        // The two protocols have separate port spaces, so one port number can
        // carry both -- which is how a relay with `listen-ng` and
        // `listen-tcp-ng` on the same port looks. Taking the stream port first
        // and then asking for the same datagram port can lose a race with
        // anything else on the box, so it is retried rather than assumed.
        let (listener, sock) = (0..32)
            .find_map(|_| {
                let l = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
                let port = l.local_addr().ok()?.port();
                let u = std::net::UdpSocket::bind(("127.0.0.1", port)).ok()?;
                Some((l, u))
            })
            .ok_or("a port free on both transports")?;
        let addr = sock.local_addr().map_err(|e| format!("addr: {e:?}"))?;

        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                let req = &buf[..n];
                let space = req.iter().position(|b| *b == b' ').unwrap_or(0);
                let mut out = req[..space].to_vec();
                out.push(b' ');
                out.extend_from_slice(datagram_reply.as_bytes());
                let _ = sock.send_to(&out, peer);
            }
        });
        std::thread::spawn(move || {
            if let Ok((conn, _)) = listener.accept() {
                answer_one_stream_request(conn, &[stream_reply.as_bytes()]);
            }
        });
        Ok(addr)
    }

    /// Read one framed request off a stream connection and answer it in the
    /// given pieces, echoing the cookie.
    ///
    /// The pieces are written separately, with a flush between, because a
    /// reader that assumes one read per reply passes against a single write
    /// and fails against a relay whose 61034-byte answer arrives in two.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    fn answer_one_stream_request(mut conn: std::net::TcpStream, pieces: &[&[u8]]) {
        use std::io::{Read, Write};
        let mut buf = [0u8; 4096];
        let Ok(n) = conn.read(&mut buf) else { return };
        let req = &buf[..n];
        let space = req.iter().position(|b| *b == b' ').unwrap_or(0);
        let mut head = req[..space].to_vec();
        head.push(b' ');
        let _ = conn.write_all(&head);
        for piece in pieces {
            let _ = conn.write_all(piece);
            let _ = conn.flush();
        }
        // Held open: a relay does not close after answering, so a reader that
        // only terminates on EOF would hang against the real thing.
        std::thread::sleep(Duration::from_millis(200));
    }

    /// An enumeration within the datagram-safe default stays on the datagram.
    ///
    /// The common case, and the one that must cost nothing new: a relay
    /// holding a handful of calls is asked exactly as it was before, with no
    /// connection opened to a port that may hold something else entirely.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_narrow_enumeration_stays_on_the_datagram_transport() -> Result<(), TestError> {
        let addr = dual_relay("from-the-datagram", "from-the-stream")?;
        let client = ControlClient::new(addr, Duration::from_secs(2));

        match client
            .list(&live_permit()?, crate::relay::reconcile::DEFAULT_LIST_LIMIT)
            .map_err(|e| format!("the relay answered: {e:?}"))?
        {
            ControlReply::Calls(e) => assert_eq!(
                e.call_ids,
                vec!["from-the-datagram".to_string()],
                "a narrow enumeration must not open a connection"
            ),
            other => return Err(format!("expected calls, got {other:?}").into()),
        }
        Ok(())
    }

    /// An enumeration past what a datagram carries goes over the stream.
    ///
    /// The reach half of RE4. Measured against rtpengine 14.2.0.0 holding
    /// 1200 calls: `list` with `limit: 1200` is a 73234-byte answer, which no
    /// UDP datagram can carry -- the request draws no reply at all -- and the
    /// identical request over the stream transport returns all 1200.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_wide_enumeration_goes_over_the_stream_transport() -> Result<(), TestError> {
        let addr = dual_relay("from-the-datagram", "from-the-stream")?;
        let client = ControlClient::new(addr, Duration::from_secs(2));

        match client
            .list(&live_permit()?, crate::relay::reconcile::WIDE_LIST_LIMIT)
            .map_err(|e| format!("the relay answered: {e:?}"))?
        {
            ControlReply::Calls(e) => assert_eq!(
                e.call_ids,
                vec!["from-the-stream".to_string()],
                "an answer this size cannot come back in a datagram"
            ),
            other => return Err(format!("expected calls, got {other:?}").into()),
        }
        Ok(())
    }

    /// A stream answer arriving in pieces is reassembled.
    ///
    /// Not a hypothetical. Measured against rtpengine 14.2.0.0: a 61034-byte
    /// `list` answer arrived in two reads, so a client that treats one read as
    /// one reply parses half a message and reports the relay as broken.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_stream_answer_split_across_writes_is_reassembled() -> Result<(), TestError> {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e:?}"))?;
        let addr = listener.local_addr().map_err(|e| format!("addr: {e:?}"))?;
        let relay = std::thread::spawn(move || {
            if let Ok((conn, _)) = listener.accept() {
                answer_one_stream_request(conn, &[b"d6:result2:ok5:callsl4:aaaa", b"4:bbbbee"]);
            }
        });

        let client = ControlClient::new(addr, Duration::from_secs(2));
        match client
            .list(&live_permit()?, crate::relay::reconcile::WIDE_LIST_LIMIT)
            .map_err(|e| format!("a reply split across writes is still one reply: {e:?}"))?
        {
            ControlReply::Calls(e) => {
                assert_eq!(e.call_ids, vec!["aaaa".to_string(), "bbbb".to_string()]);
            }
            other => return Err(format!("expected calls, got {other:?}").into()),
        }
        let _ = relay.join();
        Ok(())
    }

    /// A relay with no stream transport fails the wider ask, and says why.
    ///
    /// This IS the "where available" test: availability is discovered by
    /// asking, not declared in configuration. A relay that answers on a
    /// datagram and nothing else refuses the connection, and the caller keeps
    /// the capped answer it already has.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_relay_with_no_stream_transport_fails_the_wider_ask() -> Result<(), TestError> {
        // Answering on the datagram transport only: the address exists, and
        // nothing accepts a connection there. The TCP port number is HELD,
        // bound but never listening, because the UDP socket alone does not
        // reserve it: TCP and UDP number their ports separately, and a
        // listener from a test running alongside once sat on the same number
        // and accepted ("no complete reply from 127.0.0.1:33799 within
        // 500ms", 2026-09-19). A bound, non-listening socket refuses every
        // connection, keeps anything else from listening there, and keeps the
        // kernel from picking the port as the client's own source port.
        let mut free = None;
        for _ in 0..50 {
            let tcp = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
                .map_err(|e| format!("tcp socket: {e:?}"))?;
            let any: std::net::SocketAddr =
                "127.0.0.1:0".parse().map_err(|e| format!("addr: {e:?}"))?;
            tcp.bind(&any.into())
                .map_err(|e| format!("bind tcp: {e:?}"))?;
            let Some(addr) = tcp.local_addr().ok().and_then(|a| a.as_socket()) else {
                continue;
            };
            // The same number may already be taken on UDP; try another.
            let Ok(udp) = std::net::UdpSocket::bind(addr) else {
                continue;
            };
            free = Some((tcp, udp, addr));
            break;
        }
        let (held, sock, addr) = free.ok_or("a port free on both TCP and UDP")?;
        assert_eq!(
            std::net::TcpListener::bind(addr).err().map(|e| e.kind()),
            Some(std::io::ErrorKind::AddrInUse),
            "while this test holds the port, nothing else may listen on it"
        );

        let client = ControlClient::new(addr, Duration::from_millis(500));
        let err = client
            .list(&live_permit()?, crate::relay::reconcile::WIDE_LIST_LIMIT)
            .err()
            .ok_or("nothing accepts a connection here")?;
        assert!(
            err.to_string().contains("connecting"),
            "the operator must be told the connection is what failed, since \
             the fix is to enable one: {err:#}"
        );
        drop((held, sock));
        Ok(())
    }

    /// A stream answer past the read ceiling is refused rather than read
    /// without bound.
    ///
    /// The datagram path is bounded by the kernel; a stream is bounded by
    /// nothing but this. Without it a relay -- or anything that answered in
    /// its place -- decides how much memory sipnab allocates.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn a_stream_answer_past_the_ceiling_is_refused() -> Result<(), TestError> {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e:?}"))?;
        let addr = listener.local_addr().map_err(|e| format!("addr: {e:?}"))?;
        let relay = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 4096];
            let Ok(n) = conn.read(&mut buf) else { return };
            let space = buf[..n].iter().position(|b| *b == b' ').unwrap_or(0);
            let mut head = buf[..space].to_vec();
            head.push(b' ');
            let _ = conn.write_all(&head);
            // A bencode value that never ends: the length prefix promises more
            // than the ceiling allows, so no amount of reading completes it.
            let _ = conn.write_all(b"d6:result2:ok5:callsl");
            let filler = vec![b'x'; 64 * 1024];
            for _ in 0..(MAX_STREAM_REPLY_BYTES / filler.len() + 2) {
                if conn.write_all(b"65536:").is_err() || conn.write_all(&filler).is_err() {
                    return;
                }
            }
        });

        let client = ControlClient::new(addr, Duration::from_secs(5));
        let err = client
            .list(&live_permit()?, crate::relay::reconcile::WIDE_LIST_LIMIT)
            .err()
            .ok_or("an unbounded answer must be refused")?;
        assert!(
            err.to_string().contains("larger than"),
            "the error must name the ceiling, not look like a parse failure: {err:#}"
        );
        let _ = relay.join();
        Ok(())
    }
}

#[cfg(test)]
mod query_reply_tests {
    use super::*;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// A real `query` answer from rtpengine 12.5.1, captured off the harness
    /// relay while two SIPp calls were up.
    ///
    /// Recorded rather than hand-written on purpose. A fixture built from the
    /// same understanding as the parser agrees with the parser and proves
    /// nothing; this one was produced by the software this code has to read.
    const REAL_QUERY: &[u8] =
        include_bytes!("../../tests/fixtures/rtpengine/query-reply-12.5.1.bin");

    fn parsed() -> Result<CallView, TestError> {
        match parse_query_reply(REAL_QUERY, "1-9582@172.28.0.21") {
            Ok(ControlReply::Call(c)) => Ok(c),
            other => Err(format!("expected a call view, got {other:?}").into()),
        }
    }

    /// Both sides of the call are read, and the Call-ID comes from the ASK.
    #[test]
    fn real_reply_yields_both_tags_and_the_requested_call_id() -> Result<(), TestError> {
        let call = parsed()?;
        assert_eq!(
            call.call_id, "1-9582@172.28.0.21",
            "the Call-ID must be the one asked about; rtpengine does not echo \
             it, so a parser that invented one would be inventing the join key"
        );
        let tags: Vec<&str> = call.tags.iter().map(|t| t.tag.as_str()).collect();
        assert_eq!(tags, ["1SIPpTag0113926", "9582SIPpTag091"]);
        Ok(())
    }

    /// The relay-side ports are what sipnab can see in a capture, so they are
    /// what an unexplained stream is matched on.
    #[test]
    fn real_reply_yields_the_relay_side_ports() -> Result<(), TestError> {
        let call = parsed()?;
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
        Ok(())
    }

    /// RTP and RTCP are told apart, because reporting a relay's RTCP port as
    /// an unattributed media stream is the confusion this is meant to end.
    #[test]
    fn rtcp_ports_are_distinguished_from_rtp_ports() -> Result<(), TestError> {
        let call = parsed()?;
        let rtcp: Vec<u16> = call
            .tags
            .iter()
            .flat_map(|t| t.streams.iter().filter(|s| s.is_rtcp).map(|s| s.local_port))
            .collect();
        let mut rtcp = rtcp;
        rtcp.sort_unstable();
        assert_eq!(rtcp, [30001, 30003], "the odd ports carry RTCP");
        Ok(())
    }

    /// The endpoint and what the far side ADVERTISED are kept apart. Behind
    /// NAT they differ, and the difference is usually the bug.
    #[test]
    fn endpoint_and_advertised_endpoint_are_both_kept() -> Result<(), TestError> {
        let call = parsed()?;
        let stream = call
            .tags
            .iter()
            .flat_map(|t| &t.streams)
            .find(|s| s.local_port == 30002)
            .ok_or("port 30002 is in the fixture")?;
        assert_eq!(stream.endpoint.as_deref(), Some("172.28.0.21:6000"));
        assert_eq!(
            stream.advertised_endpoint.as_deref(),
            Some("172.28.0.21:6000"),
            "on this harness they agree; they are stored separately so that a \
             capture where they do not can say so"
        );
        Ok(())
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
    fn behind_nat_the_endpoint_and_the_advertised_endpoint_do_not_collapse() -> Result<(), TestError>
    {
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
            .map_err(|e| format!("the synthetic reply must parse: {e:?}"))?
        else {
            return Err("expected a call view".into());
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
        Ok(())
    }

    /// The SSRC is the join key that survives a capture taken off-path, where
    /// the addresses did not.
    ///
    /// The fixture's SSRC is INGRESS on one side and EGRESS on the other, so
    /// each direction is asserted at its own port. An earlier version accepted
    /// either port and passed with egress parsing deleted entirely.
    #[test]
    fn ssrcs_are_read_from_both_directions() -> Result<(), TestError> {
        let call = parsed()?;
        const SSRC: u32 = 758_599_286;

        let by_port = |port: u16| -> Result<&RelayStream, &str> {
            call.tags
                .iter()
                .flat_map(|t| &t.streams)
                .find(|s| s.local_port == port)
                .ok_or("port is in the fixture")
        };

        assert!(
            by_port(30002)?.ssrcs.contains(&SSRC),
            "the relay recorded this SSRC as INGRESS on port 30002"
        );
        assert!(
            by_port(30000)?.ssrcs.contains(&SSRC),
            "and as EGRESS on port 30000 -- reading only one direction loses \
             half the join keys the relay is holding"
        );
        assert!(
            by_port(30001)?.ssrcs.is_empty(),
            "the RTCP port carried no media, so it must claim no SSRC"
        );
        Ok(())
    }

    /// The lookup an unexplained stream actually performs.
    ///
    /// BOTH sides are asserted, and that is the point. Checking only port
    /// 30000 passes even for a lookup that returns whichever tag comes first,
    /// because the right answer for 30000 *is* the first tag. Port 30002
    /// belongs to the other one, so it can tell a real lookup from a lucky
    /// one -- and a mutant that ignored the port survived until it was here.
    #[test]
    fn a_relay_port_finds_its_own_tag_and_its_peer() -> Result<(), TestError> {
        let call = parsed()?;

        let first = call
            .tag_for_port(30000)
            .ok_or("port 30000 is held by a tag in the fixture")?;
        assert_eq!(first.tag, "1SIPpTag0113926");
        assert_eq!(
            first.in_dialogue_with,
            ["9582SIPpTag091"],
            "the other side of the call is what makes this a dialog and not \
             just a port"
        );

        let second = call
            .tag_for_port(30002)
            .ok_or("port 30002 is held by the other tag in the fixture")?;
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
        Ok(())
    }

    /// The codec the relay recorded, where it recorded one.
    #[test]
    fn codec_is_read_where_the_relay_recorded_one() -> Result<(), TestError> {
        let call = parsed()?;
        let codecs: Vec<Option<&str>> = call.tags.iter().map(|t| t.codec.as_deref()).collect();
        assert!(
            codecs.contains(&Some("G722/8000")),
            "the relay recorded G722 on one side: {codecs:?}"
        );
        Ok(())
    }

    /// A v6 endpoint keeps its brackets, so the result parses back.
    ///
    /// Without them `::1` and port `5060` render as `::1:5060`, which is not a
    /// socket address any parser accepts -- the port reads as another hextet.
    /// A relay on v6 would produce a join key nothing downstream could use.
    #[test]
    fn a_v6_endpoint_is_bracketed() -> Result<(), TestError> {
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

        let ControlReply::Call(call) = parse_query_reply(body.as_bytes(), "v6@example.net")
            .map_err(|e| format!("must parse: {e:?}"))?
        else {
            return Err("expected a call view".into());
        };
        let rendered = call.tags[0].streams[0]
            .endpoint
            .clone()
            .ok_or("the stream has an endpoint")?;
        assert_eq!(rendered, "[2001:db8::5]:5060");
        assert!(
            rendered.parse::<std::net::SocketAddr>().is_ok(),
            "the rendered endpoint must parse back; that is the whole reason \
             for the brackets: {rendered}"
        );
        Ok(())
    }

    /// A refusal is the relay answering, not the transport failing.
    #[test]
    fn a_refused_query_is_reported_as_a_refusal() -> Result<(), TestError> {
        let body = format!(
            "d{}{}{}{}e",
            super::tests::bstr("error-reason"),
            super::tests::bstr("Unknown call-id"),
            super::tests::bstr("result"),
            super::tests::bstr("error"),
        );
        match parse_query_reply(body.as_bytes(), "gone@example.net") {
            Ok(ControlReply::Refused { reason }) => assert_eq!(reason, "Unknown call-id"),
            other => {
                return Err(format!(
                    "a relay error must not read as a transport failure: {other:?}"
                )
                .into());
            }
        }
        Ok(())
    }

    /// A synthetic tag entry, assembled from its parts.
    ///
    /// The captured 12.5.1 reply had no recording running, so the shape this
    /// group is about does not appear in it. Lengths are computed, never
    /// counted, for the reason [`super::tests::bstr`] gives.
    fn subscription(tag: &str, kind: &str) -> String {
        use super::tests::bstr;
        format!(
            "d{}{}{}{}e",
            bstr("tag"),
            bstr(tag),
            bstr("type"),
            bstr(kind)
        )
    }

    /// One `tags` entry holding one relay port and the subscriptions given.
    fn tag_entry(tag: &str, port: u16, subs: &[String]) -> String {
        use super::tests::bstr;
        let stream = format!(
            "d{}{}{}i{port}ee",
            bstr("local address"),
            bstr("10.0.0.2"),
            bstr("local port"),
        );
        let media = format!("d{}i1e{}l{stream}ee", bstr("index"), bstr("streams"));
        format!(
            "d{}l{media}e{}l{}e{}{}e",
            bstr("medias"),
            bstr("subscriptions"),
            subs.concat(),
            bstr("tag"),
            bstr(tag),
        )
    }

    /// A whole `query` reply carrying the given tag entries.
    fn reply(entries: &[(&str, String)]) -> String {
        use super::tests::bstr;
        let body: String = entries
            .iter()
            .map(|(name, entry)| format!("{}{entry}", bstr(name)))
            .collect();
        format!("d{}{}{}d{body}ee", bstr("result"), bstr("ok"), bstr("tags"),)
    }

    /// A media subscriber is not the party the call is with.
    ///
    /// rtpengine stamps every `subscriptions` entry with a `type`:
    /// `offer/answer` for the other side of a SIP dialog, `pub/sub` for a
    /// media subscription -- which is exactly what relay-side recording and
    /// forking create. Reading both into one list reports a recorder as the
    /// other end of the call, so a two-party call comes back with three
    /// parties and the media analysis that judges asymmetry answers a
    /// question nobody asked.
    #[test]
    fn a_media_subscriber_is_not_reported_as_a_dialogue_peer() -> Result<(), TestError> {
        let entry = tag_entry(
            "leg-a",
            30000,
            &[
                subscription("leg-b", "offer/answer"),
                subscription("recorder", "pub/sub"),
            ],
        );
        let ControlReply::Call(call) =
            parse_query_reply(reply(&[("leg-a", entry)]).as_bytes(), "c@x")
                .map_err(|e| format!("the synthetic reply must parse: {e:?}"))?
        else {
            return Err("expected a call view".into());
        };

        assert_eq!(
            call.tags[0].in_dialogue_with,
            ["leg-b"],
            "only the offer/answer peer is the party this call is with; a \
             pub/sub subscriber listed beside it is a recorder wearing a \
             leg's clothes"
        );
        assert_eq!(
            call.tags[0].media_subscriptions,
            ["recorder"],
            "and it must not be DROPPED either -- a subscription sipnab \
             silently discards is a stream it will never explain"
        );
        Ok(())
    }

    /// The subscriber's own entry is a tag too, and it holds relay ports.
    ///
    /// `query` with no from-tag walks every monologue the call has, so a
    /// recording fork arrives as its own top-level tag with its own ports.
    /// Those ports DO belong to the call and are attributed to it; what they
    /// are not is a leg of it, and the difference has to survive the parse.
    #[test]
    fn a_tag_that_only_subscribes_is_not_a_call_leg() -> Result<(), TestError> {
        let leg = tag_entry("leg-a", 30000, &[subscription("leg-b", "offer/answer")]);
        let rec = tag_entry("recorder", 30010, &[subscription("leg-a", "pub/sub")]);
        let ControlReply::Call(call) = parse_query_reply(
            reply(&[("leg-a", leg), ("recorder", rec)]).as_bytes(),
            "c@x",
        )
        .map_err(|e| format!("the synthetic reply must parse: {e:?}"))?
        else {
            return Err("expected a call view".into());
        };

        let leg = call
            .tag_for_port(30000)
            .ok_or("the leg holds port 30000 in this reply")?;
        let rec = call
            .tag_for_port(30010)
            .ok_or("the subscriber holds port 30010 in this reply")?;
        assert!(
            !leg.is_media_subscriber(),
            "a tag with an offer/answer peer is a leg of the call"
        );
        assert!(
            rec.is_media_subscriber(),
            "a tag that only ever subscribes to another tag's media is a \
             consumer of the call, not a party to it"
        );
        Ok(())
    }

    /// The older spelling is a STRING, and reading it as a list reads nothing.
    ///
    /// rtpengine wrote `in dialogue with` as the peer's tag directly until
    /// one-to-many forwarding replaced it with the `subscriptions` list. A
    /// parser that looks for a list under that key finds a byte string, does
    /// not match, and reports every call on such a relay as having no other
    /// side -- while a comment claims both spellings are read.
    #[test]
    fn the_older_spelling_of_the_peer_is_a_string_and_is_still_read() -> Result<(), TestError> {
        use super::tests::bstr;
        let entry = format!(
            "d{}{}{}{}e",
            bstr("in dialogue with"),
            bstr("leg-b"),
            bstr("tag"),
            bstr("leg-a"),
        );
        let ControlReply::Call(call) =
            parse_query_reply(reply(&[("leg-a", entry)]).as_bytes(), "c@x")
                .map_err(|e| format!("the synthetic reply must parse: {e:?}"))?
        else {
            return Err("expected a call view".into());
        };
        assert_eq!(
            call.tags[0].in_dialogue_with,
            ["leg-b"],
            "a relay old enough to spell it this way still names the other \
             side, and sipnab must read it"
        );
        Ok(())
    }

    /// A truncated datagram must fail, not read as a call with no tags.
    ///
    /// This is the same failure mode the `list` cap guards: a short answer
    /// that parses is reported as a complete one, and every stream in the call
    /// stays an orphan with no sign anything went wrong.
    #[test]
    fn a_truncated_reply_fails_rather_than_reading_as_an_empty_call() -> Result<(), TestError> {
        let short = &REAL_QUERY[..REAL_QUERY.len() / 2];
        assert!(
            parse_query_reply(short, "1-9582@172.28.0.21").is_err(),
            "half a reply must not parse as a call with no streams"
        );
        Ok(())
    }

    /// A one-way call recorded on the harness relay (rtpengine 12.5.1,
    /// userspace): the callee sent nothing. Rewritten to RFC 5737 addresses.
    const ONE_WAY: &[u8] = include_bytes!("../../tests/fixtures/rtpengine/h-oneway-query.bencode");

    /// The stream on `port` in a parsed `reply`.
    fn stream_on(reply: &[u8], port: u16) -> Result<RelayStream, TestError> {
        let ControlReply::Call(call) = parse_query_reply(reply, "c@example.invalid")? else {
            return Err("expected a call view".into());
        };
        call.tags
            .iter()
            .flat_map(|t| t.streams.iter())
            .find(|s| s.local_port == port)
            .cloned()
            .ok_or_else(|| format!("no stream on port {port}").into())
    }

    /// Each relay socket keeps what the relay counted on it, both ways, with
    /// the time of its last packet and its flags: `stats` is what arrived,
    /// `stats_out` is what the relay sent, and the two are never swapped.
    #[test]
    fn a_socket_keeps_its_counters_both_ways_its_last_packet_and_its_flags() -> Result<(), TestError>
    {
        let caller = stream_on(ONE_WAY, 30030)?;
        assert_eq!(
            caller.facts.media_index,
            Some(1),
            "Each relay socket keeps what the relay counted on it, both ways, with the time of its last packet and its flags"
        );
        assert_eq!(
            caller.facts.ingress,
            StreamCounters {
                packets: Some(2250),
                bytes: Some(387_000),
                errors: Some(0),
            },
            "Each relay socket keeps what the relay counted on it, both ways, with the time of its last packet and its flags"
        );
        assert_eq!(
            caller.facts.egress,
            StreamCounters {
                packets: Some(0),
                bytes: Some(0),
                errors: Some(0),
            },
            "Each relay socket keeps what the relay counted on it, both ways, with the time of its last packet and its flags"
        );
        assert_eq!(
            caller.facts.last_packet,
            Some(1_793_791_903),
            "Each relay socket keeps what the relay counted on it, both ways, with the time of its last packet and its flags"
        );
        assert_eq!(
            caller.facts.flags.as_deref(),
            Some(
                &[
                    "RTP".to_string(),
                    "filled".to_string(),
                    "confirmed".to_string(),
                    "kernelized".to_string(),
                    "no kernel support".to_string(),
                ][..]
            ),
            "Each relay socket keeps what the relay counted on it, both ways, with the time of its last packet and its flags"
        );

        let callee = stream_on(ONE_WAY, 30016)?;
        assert_eq!(
            callee.facts.ingress.packets,
            Some(0),
            "Each relay socket keeps what the relay counted on it, both ways, with the time of its last packet and its flags"
        );
        assert_eq!(
            callee.facts.egress.packets,
            Some(2250),
            "Each relay socket keeps what the relay counted on it, both ways, with the time of its last packet and its flags"
        );
        assert_eq!(
            callee.facts.last_packet,
            Some(1_793_791_858),
            "Each relay socket keeps what the relay counted on it, both ways, with the time of its last packet and its flags"
        );
        Ok(())
    }

    /// `reply` with every dictionary entry named in `keys` removed, at any
    /// depth, re-encoded in its original key order. Used to build the shape a
    /// relay version that does not report a field would send, from a real one.
    fn without(reply: &[u8], keys: &[&[u8]]) -> Result<Vec<u8>, TestError> {
        use crate::rtpengine::bencode::{self, Value};
        fn strip<'a>(v: &Value<'a>, keys: &[&[u8]]) -> Value<'a> {
            match v {
                Value::Dict(entries) => Value::Dict(
                    entries
                        .iter()
                        .filter(|(k, _)| !keys.contains(k))
                        .map(|(k, v)| (*k, strip(v, keys)))
                        .collect(),
                ),
                Value::List(items) => Value::List(items.iter().map(|i| strip(i, keys)).collect()),
                other => other.clone(),
            }
        }
        let decoded = bencode::decode(reply)?;
        let mut out = Vec::new();
        bencode::encode(&strip(&decoded, keys), &mut out);
        Ok(out)
    }

    /// A relay version that reports packets and bytes but no errors keeps the
    /// packets and bytes. One missing field never takes the others with it.
    #[test]
    fn a_missing_errors_field_leaves_packets_and_bytes_reported() -> Result<(), TestError> {
        let reply = without(ONE_WAY, &[&b"errors"[..]])?;
        let caller = stream_on(&reply, 30030)?;
        assert_eq!(
            caller.facts.ingress,
            StreamCounters {
                packets: Some(2250),
                bytes: Some(387_000),
                errors: None,
            },
            "A relay version that reports packets and bytes but no errors keeps the packets and bytes"
        );
        Ok(())
    }

    /// What a reply does not carry is absent, never zero: no `stats`, no
    /// `stats_out`, no `last packet` and no `flags` read as `None`.
    #[test]
    fn what_the_reply_does_not_carry_is_absent_never_zero() -> Result<(), TestError> {
        let reply = without(
            ONE_WAY,
            &[&b"stats"[..], b"stats_out", b"last packet", b"flags"],
        )?;
        let caller = stream_on(&reply, 30030)?;
        assert_eq!(
            caller.facts.ingress,
            StreamCounters::default(),
            "What a reply does not carry is absent, never zero"
        );
        assert_eq!(
            caller.facts.egress,
            StreamCounters::default(),
            "What a reply does not carry is absent, never zero"
        );
        assert_eq!(
            caller.facts.last_packet, None,
            "What a reply does not carry is absent, never zero"
        );
        assert_eq!(
            caller.facts.flags, None,
            "What a reply does not carry is absent, never zero"
        );
        Ok(())
    }
}

/// rtpengine, as a relay the reconciler can read.
///
/// The impl lives HERE, beside the client, and that placement is the point.
/// It used to sit in `reconcile.rs` with a comment reasoning that
/// "reconciliation knows about the wire, and the wire knows nothing about
/// reconciliation" -- true while reconciliation lived under `src/rtpengine/`,
/// and inverted the moment it became the seam. A seam that names its own
/// implementation has nowhere to attach a second one, which is what
/// `relay_seam_test::the_seam_does_not_depend_on_an_implementation` now holds.
///
/// `describe` names the vendor because the seam's operator-facing messages no
/// longer can. "rtpengine at 10.0.0.1 refused to enumerate its calls" has to
/// come from somewhere, and the only layer that knows which daemon it is
/// talking to is this one.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
impl crate::relay::reconcile::ReadOnlyRelay for ControlClient {
    fn list(
        &self,
        permit: &crate::security::transmit_guard::TransmitPermit,
        limit: u32,
    ) -> anyhow::Result<ControlReply> {
        Self::list(self, permit, limit)
    }

    fn query(
        &self,
        permit: &crate::security::transmit_guard::TransmitPermit,
        call_id: &str,
    ) -> anyhow::Result<ControlReply> {
        Self::query(self, permit, call_id)
    }

    fn statistics(
        &self,
        permit: &crate::security::transmit_guard::TransmitPermit,
    ) -> anyhow::Result<ControlReply> {
        Self::statistics(self, permit)
    }

    fn call_statistics(
        &self,
        permit: &crate::security::transmit_guard::TransmitPermit,
        call_id: &str,
    ) -> anyhow::Result<ControlReply> {
        Self::call_statistics(self, permit, call_id)
    }

    fn describe(&self) -> String {
        format!("rtpengine at {}", self.addr())
    }
}

/// The relay sessions verdicts, read from real recorded replies through the
/// real parser.
///
/// The replies were recorded on 2026-11-04 from rtpengine 12.5.1.31: the `h-`
/// ones from the harness relay in userspace (`--table=-1`), the `v-` ones from
/// a lab relay forwarding in the kernel (`xt_RTPENGINE` loaded). Addresses were
/// rewritten to RFC 5737 ranges and Call-IDs and tags to example values;
/// integers and key order are as the relay wrote them. They live here rather
/// than beside the verdict rule because the rule's module may not name the
/// relay that produced them.
#[cfg(all(test, not(target_arch = "wasm32"), feature = "native"))]
mod session_fixture_tests {
    use super::*;
    use crate::output::query::relay_sessions::{
        Direction, KernelVerdict, MediaVerdict, SessionCall, SessionsAsk, SipDialog, judge_call,
        relay_sessions,
    };
    use crate::relay::reconcile::ReadOnlyRelay;

    type TestError = Box<dyn std::error::Error>;

    /// A recorded reply body by file name.
    fn fixture(name: &str) -> Result<Vec<u8>, TestError> {
        let path = format!(
            "{}/tests/fixtures/rtpengine/{name}.bencode",
            env!("CARGO_MANIFEST_DIR")
        );
        Ok(std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?)
    }

    /// The recorded `query` reply `name`, parsed and judged.
    fn judged(name: &str) -> Result<SessionCall, TestError> {
        judged_bytes(&fixture(name)?)
    }

    fn judged_bytes(body: &[u8]) -> Result<SessionCall, TestError> {
        match parse_query_reply(body, "c@example.invalid")? {
            ControlReply::Call(view) => Ok(judge_call(&view, SipDialog::NotSeenEnded)),
            other => Err(format!("expected a call view, got {other:?}").into()),
        }
    }

    /// Each direction as (sending tag, relay port, verdict, seconds behind).
    fn verdicts(call: &SessionCall) -> Vec<(String, u16, MediaVerdict, Option<i64>)> {
        call.directions
            .iter()
            .map(|d: &Direction| {
                (
                    d.from_tag.clone(),
                    d.local_port,
                    d.verdict,
                    d.no_packet_for_s,
                )
            })
            .collect()
    }

    fn row(
        tag: &str,
        port: u16,
        v: MediaVerdict,
        behind: Option<i64>,
    ) -> (String, u16, MediaVerdict, Option<i64>) {
        (tag.to_string(), port, v, behind)
    }

    /// A one-way call: the caller's media reaches the relay and the callee's
    /// never does, on both relays. The callee's socket counted 0 in and is not
    /// `confirmed`, although its `last packet` is the answer time and not the
    /// call's creation time (harness: 1793791858 against 1793791857).
    #[test]
    fn a_one_way_call_is_flowing_one_way_and_never_received_the_other() -> Result<(), TestError> {
        assert_eq!(
            verdicts(&judged("h-oneway-query")?),
            [
                row("callee-tag-1", 30016, MediaVerdict::NeverReceived, None),
                row("caller-tag-1", 30030, MediaVerdict::Flowing, None),
            ],
            "A one-way call"
        );
        assert_eq!(
            verdicts(&judged("v-oneway-kernel-query")?),
            [
                row("callee-tag-1", 32686, MediaVerdict::NeverReceived, None),
                row("caller-tag-1", 30400, MediaVerdict::Flowing, None),
            ],
            "A one-way call"
        );
        Ok(())
    }

    /// A two-way call is flowing both ways, in userspace and in the kernel.
    #[test]
    fn a_two_way_call_is_flowing_both_ways() -> Result<(), TestError> {
        for name in ["h-twoway-query", "v-twoway-kernel-query"] {
            let call = judged(name)?;
            assert_eq!(call.directions.len(), 2, "{name}");
            assert!(
                call.directions
                    .iter()
                    .all(|d| d.verdict == MediaVerdict::Flowing),
                "{name}: {:?}",
                verdicts(&call)
            );
        }
        Ok(())
    }

    /// A caller silent for 10 s (pcap ground truth 10.1 s and 10.2 s) is
    /// stalled with the lag the reply itself shows; the callee is flowing.
    #[test]
    fn a_caller_silent_for_ten_seconds_is_stalled_with_its_lag() -> Result<(), TestError> {
        let h = judged("h-silent10s-query")?;
        assert_eq!(
            verdicts(&h),
            [
                row("callee-tag-1", 30024, MediaVerdict::Flowing, None),
                row("caller-tag-1", 30026, MediaVerdict::Stalled, Some(10)),
            ],
            "A caller silent for 10 s (pcap ground truth 10.1 s and 10.2 s) is stalled with the lag the reply itself shows"
        );
        let v = judged("v-silent10s-kernel-query")?;
        let caller = v
            .directions
            .iter()
            .find(|d| d.from_tag == "caller-tag-1")
            .ok_or("a caller direction")?;
        assert_eq!(caller.verdict, MediaVerdict::Stalled, "{:?}", verdicts(&v));
        let callee = v
            .directions
            .iter()
            .find(|d| d.from_tag == "callee-tag-1")
            .ok_or("a callee direction")?;
        assert_eq!(callee.verdict, MediaVerdict::Flowing, "{:?}", verdicts(&v));
        Ok(())
    }

    /// The recorded parallel fork: the answered branch's socket counted 0 in
    /// while that party's 2260 packets were counted on the early branch's
    /// socket. No direction is judged; every socket's counters are shown.
    #[test]
    fn a_forked_call_with_an_early_media_branch_is_not_judged() -> Result<(), TestError> {
        let call = judged("h-fork-query")?;
        assert!(call.directions.is_empty(), "{:?}", verdicts(&call));
        assert!(call.unjudged.is_some(), "The recorded parallel fork");
        let ingress = |tag: &str, port: u16| {
            call.tags
                .iter()
                .find(|t| t.tag == tag)
                .and_then(|t| t.sockets.iter().find(|s| s.local_port == port))
                .and_then(|s| s.ingress.packets)
        };
        assert_eq!(
            ingress("early-tag-1", 30022),
            Some(2260),
            "The recorded parallel fork"
        );
        assert_eq!(
            ingress("callee-tag-1", 30018),
            Some(0),
            "The recorded parallel fork"
        );
        assert_eq!(
            ingress("caller-tag-1", 30008),
            Some(2189),
            "The recorded parallel fork"
        );
        Ok(())
    }

    /// Kernel forwarding: the harness relay flags every received RTP socket
    /// `kernelized` AND `no kernel support`, which is userspace; the lab relay
    /// with the module loaded flags them `kernelized` alone, which is kernel.
    #[test]
    fn kernelized_without_no_kernel_support_is_kernel_and_with_it_userspace()
    -> Result<(), TestError> {
        let rtp_kernel = |call: &SessionCall| -> Vec<KernelVerdict> {
            call.tags
                .iter()
                .flat_map(|t| t.sockets.iter())
                .filter(|s| s.kind == "rtp" && s.ingress.packets.unwrap_or(0) > 0)
                .map(|s| s.kernel)
                .collect()
        };
        assert_eq!(
            rtp_kernel(&judged("h-twoway-query")?),
            [KernelVerdict::Userspace, KernelVerdict::Userspace],
            "Kernel forwarding"
        );
        assert_eq!(
            rtp_kernel(&judged("v-twoway-kernel-query")?),
            [KernelVerdict::Kernel, KernelVerdict::Kernel],
            "Kernel forwarding"
        );
        Ok(())
    }

    /// `reply` with every dictionary entry named in `keys` removed.
    fn without(reply: &[u8], keys: &[&[u8]]) -> Result<Vec<u8>, TestError> {
        use crate::rtpengine::bencode::{self, Value};
        fn strip<'a>(v: &Value<'a>, keys: &[&[u8]]) -> Value<'a> {
            match v {
                Value::Dict(entries) => Value::Dict(
                    entries
                        .iter()
                        .filter(|(k, _)| !keys.contains(k))
                        .map(|(k, v)| (*k, strip(v, keys)))
                        .collect(),
                ),
                Value::List(items) => Value::List(items.iter().map(|i| strip(i, keys)).collect()),
                other => other.clone(),
            }
        }
        let mut out = Vec::new();
        bencode::encode(&strip(&bencode::decode(reply)?, keys), &mut out);
        Ok(out)
    }

    /// A relay version that reports no `last packet`, or no `stats`, gets
    /// `not_reported` on every direction: never `flowing`, never
    /// `never_received`.
    #[test]
    fn a_reply_without_last_packet_or_stats_is_not_reported() -> Result<(), TestError> {
        let one_way = fixture("h-oneway-query")?;
        for key in [&b"last packet"[..], b"stats"] {
            let call = judged_bytes(&without(&one_way, &[key])?)?;
            assert_eq!(
                call.directions.len(),
                2,
                "A relay version that reports no `last packet`, or no `stats`, gets `not_reported` on every direction"
            );
            assert!(
                call.directions
                    .iter()
                    .all(|d| d.verdict == MediaVerdict::NotReported),
                "{}: {:?}",
                String::from_utf8_lossy(key),
                verdicts(&call)
            );
        }
        Ok(())
    }

    /// A relay that answers from recorded bytes through the real parsers.
    struct Recorded {
        list: &'static str,
        query: &'static str,
    }

    impl ReadOnlyRelay for Recorded {
        fn list(&self, _: &TransmitPermit, limit: u32) -> anyhow::Result<ControlReply> {
            let body = fixture(self.list).map_err(|e| anyhow::anyhow!("{e}"))?;
            parse_list_reply(&body, limit)
        }
        fn query(&self, _: &TransmitPermit, call_id: &str) -> anyhow::Result<ControlReply> {
            let body = fixture(self.query).map_err(|e| anyhow::anyhow!("{e}"))?;
            parse_query_reply(&body, call_id)
        }
        fn statistics(&self, _: &TransmitPermit) -> anyhow::Result<ControlReply> {
            anyhow::bail!("not recorded")
        }
        fn describe(&self) -> String {
            "a recorded relay".to_string()
        }
    }

    fn permit() -> Result<TransmitPermit, TestError> {
        Ok(
            TransmitPermit::for_source(&crate::capture::CaptureSource::Live {
                device: "eth0".to_owned(),
            })
            .ok_or("a live source grants a permit")?,
        )
    }

    /// A relay holding 40 calls answers `limit 32` with exactly 32 and no key
    /// that says more exist: the snapshot says it may hold more. Asked for
    /// 1000 it returns all 40, and the snapshot does not.
    #[test]
    fn exactly_the_limit_returned_is_truncated_and_fewer_is_not() -> Result<(), TestError> {
        let at = chrono::Utc::now;
        let ask = |list_limit| SessionsAsk {
            selected: None,
            scan: false,
            cap: 32,
            list_limit,
        };
        let full = Recorded {
            list: "v-40calls-list-32",
            query: "v-twoway-kernel-query",
        };
        let limit = 32;
        let s = relay_sessions(&full, &permit()?, &ask(limit), &|_| false, &at);
        assert_eq!(
            (s.held, s.truncated),
            (Some(limit as usize), Some(true)),
            "a relay holding 40 calls answers `limit {limit}` with exactly {limit} and no key \
             that says more exist"
        );

        let all = Recorded {
            list: "v-40calls-list-1000",
            query: "v-twoway-kernel-query",
        };
        let s = relay_sessions(&all, &permit()?, &ask(1000), &|_| false, &at);
        assert_eq!(
            (s.held, s.truncated),
            (Some(40), Some(false)),
            "A relay holding 40 calls answers `limit 32` with exactly 32 and no key that says more exist"
        );
        assert_eq!(
            s.not_queried.len(),
            40,
            "A relay holding 40 calls answers `limit 32` with exactly 32 and no key that says more exist"
        );
        Ok(())
    }

    /// 63 s into a call, after its BYE, the relay still lists and answers for
    /// it with nothing marking it deleted. Only sipnab's own SIP can say it
    /// ended; without it, the answer says the relay may still list it.
    #[test]
    fn a_call_in_delete_delay_is_marked_only_by_sipnab_s_own_sip() -> Result<(), TestError> {
        let at = chrono::Utc::now;
        let relay = Recorded {
            list: "h-12calls-list-1000",
            query: "h-twoway-query-after-bye",
        };
        let ask = SessionsAsk {
            selected: Some("sg6-12calls-list-1000-1@example.invalid"),
            scan: false,
            cap: 32,
            list_limit: 1000,
        };
        let seen = relay_sessions(&relay, &permit()?, &ask, &|_| true, &at);
        assert_eq!(
            seen.calls[0].sip_dialog,
            SipDialog::Ended,
            "63 s into a call, after its BYE, the relay still lists and answers for it with nothing marking it deleted"
        );
        let unseen = relay_sessions(&relay, &permit()?, &ask, &|_| false, &at);
        assert_eq!(
            unseen.calls[0].sip_dialog,
            SipDialog::NotSeenEnded,
            "63 s into a call, after its BYE, the relay still lists and answers for it with nothing marking it deleted"
        );
        assert!(
            unseen
                .render(crate::output::ReportFormat::Text)
                .contains("about 30 s"),
            "63 s into a call, after its BYE, the relay still lists and answers for it with nothing marking it deleted"
        );
        Ok(())
    }
}
