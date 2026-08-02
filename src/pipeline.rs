// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-packet protocol routing: the testable core of the capture
//! pipeline.
//!
//! Extracted from main.rs so the routing logic (SIP vs RTCP vs RTP vs
//! heuristic, WebSocket unwrapping, port-range gating) is exercisable
//! as a library API instead of only through the binary.

use std::sync::Arc;

use parking_lot::RwLock;

use crate::capture::parse::{ParsedPacket, TransportProto};
use crate::capture::websocket;
use crate::rtp;
use crate::rtp::stream_store::StreamStore;
use crate::sip;
use crate::sip::dialog_store::DialogStore;

/// Check whether a source or destination port falls within the configured range.
pub fn port_in_range(src_port: u16, dst_port: u16, range: (u16, u16)) -> bool {
    let (lo, hi) = range;
    (src_port >= lo && src_port <= hi) || (dst_port >= lo && dst_port <= hi)
}

// ── What `--portrange` threw away ────────────────────────────────────
//
// The default range is `5060-5061`, and SIP on other ports is ordinary —
// carriers and SBCs use 5070, 5080 and 8090 routinely. Measured over a corpus
// of real captures, the default skips 46,421 of the 148,944 SIP messages
// sipnab can otherwise analyse (31.2%); `tshark` independently puts 49,576 of
// 152,865 SIP frames outside the range (32.4%). In `tg.pcap0` it also costs
// 1,401 of 3,712 dialogs (37.7%). The run then printed its reduced totals as
// if they were complete.
//
// Three ways to fix that were available, and only one of them is honest about
// what it costs:
//
//   * **Widen the default.** Measured on this corpus: `5060-5090` recovers
//     26,033 of the 49,576 lost messages and still loses 23,543 — 15.4% of all
//     the SIP there is, silently. Reaching 99.4% takes `5060-8090`, a
//     3,031-port default that is still arbitrary and still leaves 297 behind,
//     because the loss is spread over 1,198 distinct service ports. Widening
//     trades a silent 32% loss for a silent 15% one, which is worse than
//     leaving it alone: it looks fixed.
//   * **Sniff SIP by content on any port.** Recovers all of it, and the sniff
//     is strict enough to do it safely: unlike the payload-only RTP check that
//     invented four phantom streams from DNS, `starts_sip_message` needs a
//     literal ` SIP/2.0` version token terminating the first line, and the RTP
//     stream count is unchanged whether the gate is on or off (648 in
//     `tg.pcap0` both ways). But it makes `--portrange` a no-op for signalling,
//     which is a different promise from the one the flag documents, and the
//     gate's behaviour is pinned by tests outside this file.
//   * **Report what was skipped.** Keeps `--portrange` meaning what it says
//     and turns the silent loss into a prompt.
//
// The third is what is implemented here, and the reason is that the first two
// are the same mistake in opposite directions: both decide on the operator's
// behalf what their capture contains. Counting the loss instead lets sipnab
// say "there is SIP on 8090 that you are not seeing" — which is the fact the
// operator was missing, and which neither a wider default nor a silent
// recovery would have told them.
//
// The accounting is exact and O(1): the key is a `u16`, so the tally is a flat
// 64 K-entry table (512 KiB) allocated lazily on the first skip and never
// otherwise. An eviction policy would have been the alternative, and getting
// it wrong would under-report exactly the busiest ports the report exists to
// name.

/// One port's share of the SIP that the `--portrange` gate discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkippedPort {
    /// The service port: the destination of a request, the source of a
    /// response. Not the ephemeral client port, which would name a different
    /// number on every dialog and tell the operator nothing.
    pub port: u16,
    /// SIP messages skipped on that port.
    pub messages: u64,
}

/// What the `--portrange` gate discarded during this run.
///
/// Empty when nothing was skipped, which is the case for live capture (where
/// `PipelineOptions::sip_portrange` is `None` because BPF already filtered) and
/// for any capture whose SIP all falls inside the range.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortrangeSkipReport {
    /// Total SIP messages seen and skipped because both ports were outside
    /// the range. These appear in no count, no dialog, and no output format.
    pub messages: u64,
    /// Per-port breakdown, busiest first.
    pub ports: Vec<SkippedPort>,
}

/// Per-port tally of skipped SIP, plus the warning escalation state.
struct PortrangeSkips {
    /// Total skipped messages.
    messages: u64,
    /// Messages per service port, indexed by port. `None` until the first
    /// skip — a capture whose SIP is all in range never allocates it.
    per_port: Option<Box<[u64]>>,
    /// Skip count at which the next warning fires (1, then ×10 each time).
    next_warn: u64,
}

impl PortrangeSkips {
    /// Empty tally with the first warning armed.
    const fn new() -> Self {
        Self {
            messages: 0,
            per_port: None,
            next_warn: 1,
        }
    }
}

/// Process-global skip tally.
///
/// Global because the two places it could otherwise live are both closed:
/// `PipelineOptions` is built by exhaustive struct literals in three modules,
/// and `PacketAction` is matched exhaustively in two, so neither can gain a
/// field or a variant without editing files this change does not own. A
/// `Mutex` is affordable here precisely because it is only taken when SIP is
/// actually being discarded — never on the RTP hot path.
static PORTRANGE_SKIPS: parking_lot::Mutex<PortrangeSkips> =
    parking_lot::Mutex::new(PortrangeSkips::new());

/// Record one SIP message discarded by the `--portrange` gate.
///
/// # Arguments
///
/// * `src_port` / `dst_port` — the packet's ports, both outside the range.
/// * `payload` — the SIP bytes, read only to tell a request from a response.
/// * `range` — the configured range, quoted back in the warning.
///
/// # Side effects
///
/// Bumps the process-global tally and may emit a `WARN`. Warnings fire on the
/// 1st skip and then at each power of ten, so a capture losing millions of
/// messages costs a handful of lines and one losing three still says so.
fn record_portrange_skip(src_port: u16, dst_port: u16, payload: &[u8], range: (u16, u16)) {
    // A request's service port is its destination; a response's is its source.
    // Keying on the ephemeral side instead would scatter one proxy's traffic
    // across hundreds of ports and bury the number worth widening to.
    let service_port = if payload.starts_with(b"SIP/2.0 ") {
        src_port
    } else {
        dst_port
    };

    let warn = {
        let mut st = PORTRANGE_SKIPS.lock();
        st.messages += 1;
        let table = st
            .per_port
            .get_or_insert_with(|| vec![0u64; usize::from(u16::MAX) + 1].into_boxed_slice());
        table[usize::from(service_port)] += 1;

        if st.messages < st.next_warn {
            None
        } else {
            st.next_warn = st.messages.saturating_mul(10);
            let busiest = busiest_ports(&st, 3);
            Some((st.messages, busiest))
        }
    };

    if let Some((messages, busiest)) = warn {
        let ports = busiest
            .iter()
            .map(|p| format!("{} ({})", p.port, p.messages))
            .collect::<Vec<_>>()
            .join(", ");
        let (lo, hi) = range;
        tracing::warn!(
            "SIP outside --portrange {lo}-{hi} is being skipped: {messages} \
             message(s) so far, in no count, no dialog, and no output. \
             Busiest port(s): {ports}. Re-run with a range that covers them \
             (e.g. --portrange 1-65535) to analyse them."
        );
    }
}

/// The `n` busiest ports in `st`, busiest first.
fn busiest_ports(st: &PortrangeSkips, n: usize) -> Vec<SkippedPort> {
    let Some(ref table) = st.per_port else {
        return Vec::new();
    };
    let mut ports: Vec<SkippedPort> = table
        .iter()
        .enumerate()
        .filter(|&(_, &messages)| messages > 0)
        .map(|(port, &messages)| SkippedPort {
            // The table is indexed by `u16`, so every index fits.
            port: port as u16,
            messages,
        })
        .collect();
    // Busiest first; ties by port number so the report is deterministic.
    ports.sort_unstable_by(|a, b| b.messages.cmp(&a.messages).then(a.port.cmp(&b.port)));
    ports.truncate(n);
    ports
}

/// The SIP this run discarded because both ports fell outside `--portrange`.
///
/// The totals sipnab prints count what it analysed. This is what it saw, knew
/// was SIP, and did not analyse — the difference an operator otherwise has no
/// way to learn. Report it beside any message or dialog count that a
/// `--portrange` was applied to.
///
/// # Returns
///
/// A [`PortrangeSkipReport`] with the running total and every port that
/// carried skipped SIP, busiest first. All zeroes when nothing was skipped.
pub fn portrange_skip_report() -> PortrangeSkipReport {
    let st = PORTRANGE_SKIPS.lock();
    PortrangeSkipReport {
        messages: st.messages,
        ports: busiest_ports(&st, usize::MAX),
    }
}

/// Clear the skip tally and re-arm the warning escalation.
///
/// The tally is process-global, so a process that analyses several captures in
/// sequence (and a test that asserts on the counts) needs a way back to zero.
///
/// # Side effects
///
/// Resets the global counters and frees the per-port table.
pub fn reset_portrange_skips() {
    *PORTRANGE_SKIPS.lock() = PortrangeSkips::new();
}

// ── What ICMP said ───────────────────────────────────────────────────
//
// An ICMP error quoting a SIP request is the one packet in a capture that
// states a cause rather than implying one. sipnab dropped all of them: across
// five files of one real corpus, 3,232 SIP requests were quoted inside ICMP
// errors and appeared in no output at all, while the calls they belonged to
// were reported as "unanswered" with no explanation.
//
// This is where those quotes become evidence about a dialog. Three rules shape
// it, and each exists because the obvious alternative is wrong:
//
//   * **A quote is not a message.** It is a prefix — RFC 792 guarantees only
//     the original IP header plus 8 bytes — so it is never parsed as SIP,
//     never counted, and never appended to a dialog's `messages`. The message
//     totals sipnab prints are unchanged by this feature, which is what makes
//     the `analysed + skipped` reconciliation still mean what it says.
//   * **Unattributable evidence is reported, not dropped.** A quote that stops
//     before the `Call-ID` header cannot name a dialog. Discarding it would
//     hide the fact that the network answered; it is counted as unattributed
//     and its unreachable endpoint is still named.
//   * **The store is global.** Two closed doors and one open one: `--cores`
//     shards packets by outer host pair, and an ICMP error's host pair is
//     (router, sender) — a different pair from the dialog it describes, so
//     per-worker state would file the evidence under the wrong worker. A
//     process-global store keyed by `Call-ID` is indifferent to which thread
//     saw the packet. It is the same reasoning, and the same `Mutex`-only-
//     when-it-fires cost, as the portrange tally above.

pub use crate::capture::parse::{DialogIcmpEvidence, IcmpEvidence};

/// One endpoint that ICMP said was unreachable, with how often.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreachableEndpoint {
    /// The endpoint that did not answer.
    pub addr: std::net::IpAddr,
    /// Its port, when any quote reached the transport header.
    pub port: Option<u16>,
    /// How many ICMP errors named it.
    pub errors: u64,
    /// The most recent error's description.
    pub description: &'static str,
}

/// What ICMP reported about this run's SIP traffic.
///
/// Empty when no ICMP error quoting SIP was seen, which is the common case for
/// a healthy capture. Report it beside dialog counts: an unanswered call with
/// an ICMP error against its destination is not an unanswered call, it is a
/// closed port, and only this report knows the difference.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IcmpEvidenceReport {
    /// ICMP errors quoting a SIP request.
    pub errors: u64,
    /// How many named a `Call-ID` and were attributed to a dialog.
    pub attributed: u64,
    /// How many quoted too little to name a `Call-ID`. The evidence is real;
    /// only the dialog is unknown.
    ///
    /// `attributed + unattributed == errors`, always.
    pub unattributed: u64,
    /// Errors whose `Call-ID` was never tracked, because the store already
    /// held [`MAX_ICMP_CALL_IDS`] distinct dialogs. These reach no dialog's
    /// diagnosis; a non-zero value here means some calls carry an ICMP cause
    /// that is not shown against them.
    pub untracked_dialogs: u64,
    /// Errors whose unreachable endpoint was not tallied, because the store
    /// already held [`MAX_ICMP_ENDPOINTS`] distinct endpoints. These are
    /// missing from `endpoints`.
    ///
    /// `endpoints.map(errors).sum() + untallied_endpoints == errors`, always.
    pub untallied_endpoints: u64,
    /// Endpoints ICMP named unreachable, busiest first.
    pub endpoints: Vec<UnreachableEndpoint>,
}

/// Retained ICMP evidence, plus the counters that stay exact past the caps.
struct IcmpEvidenceStore {
    /// Evidence that named a `Call-ID`, keyed by it.
    by_call_id: std::collections::HashMap<String, DialogIcmpEvidence>,
    /// Per-endpoint tally, so an unattributable quote still names the host
    /// that failed.
    endpoints: std::collections::HashMap<(std::net::IpAddr, Option<u16>), UnreachableEndpoint>,
    /// Exact totals, unaffected by the retention caps below.
    errors: u64,
    /// Errors that named a `Call-ID`.
    attributed: u64,
    /// Errors whose quote stopped before the `Call-ID` header.
    unattributed: u64,
    /// Errors whose `Call-ID` was never tracked (dialog cap).
    untracked_dialogs: u64,
    /// Errors whose endpoint was never tallied (endpoint cap).
    untallied_endpoints: u64,
}

/// Distinct `Call-ID`s the store retains evidence for.
///
/// A capture can hold millions of ICMP errors; the totals stay exact past
/// this, and `IcmpEvidenceReport::untracked_dialogs` says how many dialogs
/// were not tracked at all. 10,000 dialogs of evidence is roughly a megabyte
/// and covers any capture a human reads.
pub const MAX_ICMP_CALL_IDS: usize = 10_000;

/// Errors retained per `Call-ID`. Past this the per-dialog COUNT still rises —
/// only the retained detail stops, because the ninth quote against one dialog
/// shows nothing the first eight did not.
pub const MAX_ICMP_PER_CALL_ID: usize = 8;

/// Distinct endpoints retained in the report.
pub const MAX_ICMP_ENDPOINTS: usize = 4_096;

impl IcmpEvidenceStore {
    /// Empty store.
    fn new() -> Self {
        Self {
            by_call_id: std::collections::HashMap::new(),
            endpoints: std::collections::HashMap::new(),
            errors: 0,
            attributed: 0,
            unattributed: 0,
            untracked_dialogs: 0,
            untallied_endpoints: 0,
        }
    }
}

/// Process-global ICMP evidence. See the note above for why it is global.
static ICMP_EVIDENCE: parking_lot::Mutex<Option<Box<IcmpEvidenceStore>>> =
    parking_lot::Mutex::new(None);

/// Whether any ICMP evidence has been recorded, readable without the lock.
///
/// Every dialog diagnosis consults the store, and the overwhelming majority of
/// captures hold no ICMP at all — so the common path must not take a mutex per
/// dialog per render. One relaxed load answers it.
static ICMP_EVIDENCE_SEEN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// A SIP request start line and the headers an ICMP quote reached.
///
/// Deliberately not a [`sip::message::SipMessage`]: the input is a prefix that
/// usually stops mid-message, and producing a `SipMessage` from it would
/// create something that could be counted, matched, or appended to a dialog.
/// This type cannot be mistaken for a message because it is not one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotedSipPrefix {
    /// The request method from the start line.
    pub method: String,
    /// `Call-ID`, when the quote reached that header. `None` is the RFC 792
    /// case, not a parse failure.
    pub call_id: Option<String>,
    /// `CSeq` header value, when quoted.
    pub cseq: Option<String>,
}

/// Read what a truncated ICMP quote reveals about the SIP request it holds.
///
/// The quote is a prefix, so this reads what is there and stops: a start line
/// that has not been terminated yet is still enough to know the method, and a
/// `Call-ID` that has been terminated is safe to use even though the message
/// itself never completes.
///
/// # Returns
///
/// `None` when `prefix` does not begin with a SIP request start line — an ICMP
/// error about an RTP packet, a DNS query, or a SIP *response* (a response is
/// not something an endpoint failed to receive on our behalf; the request it
/// answers is what the capture already holds).
///
/// # Examples
///
/// ```
/// use sipnab::pipeline::quoted_sip_prefix;
///
/// // RFC 1812-sized quote: the request line and some headers survived.
/// let q = b"OPTIONS sip:peer@example.net SIP/2.0\r\n\
///           Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
///           Call-ID: keepalive-7@192.0.2.1\r\n\
///           CSeq: 4 OPTI";
/// let p = quoted_sip_prefix(q).expect("a SIP request prefix");
/// assert_eq!(p.method, "OPTIONS");
/// assert_eq!(p.call_id.as_deref(), Some("keepalive-7@192.0.2.1"));
/// // The CSeq line was cut before its terminator, so it is not claimed.
/// assert_eq!(p.cseq, None);
///
/// // RFC 792 minimum: nothing of the message was quoted at all.
/// assert!(quoted_sip_prefix(b"").is_none());
/// ```
pub fn quoted_sip_prefix(prefix: &[u8]) -> Option<QuotedSipPrefix> {
    // The start line, terminated or not. A method is a token followed by a
    // space and a URI; requiring the ` SIP/2.0` version token as
    // `starts_sip_message` does would reject exactly the short quotes this
    // exists to read.
    let line_end = prefix
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(prefix.len());
    let start_line = prefix.get(..line_end)?;
    let mut parts = start_line.splitn(3, |&b| b == b' ');
    let method = parts.next()?;
    let uri = parts.next().unwrap_or(b"");

    // A method token is uppercase ASCII letters (RFC 3261 §7.1 permits an
    // extension-method, which is still a token), and the request URI of a SIP
    // request is a `sip:`, `sips:` or `tel:` URI. Both together are strict
    // enough that RTP, DNS and TLS records do not qualify.
    if method.is_empty()
        || !method.iter().all(|b| b.is_ascii_uppercase())
        || !(uri.starts_with(b"sip:") || uri.starts_with(b"sips:") || uri.starts_with(b"tel:"))
    {
        return None;
    }

    Some(QuotedSipPrefix {
        method: String::from_utf8_lossy(method).into_owned(),
        call_id: quoted_header(prefix, b"call-id", Some(b'i')),
        cseq: quoted_header(prefix, b"cseq", None),
    })
}

/// Read one header out of a truncated SIP prefix, or `None` if the quote ended
/// before the header's own terminator.
///
/// The terminator matters: a `Call-ID` whose line was cut mid-value would
/// otherwise be filed as a shorter, different `Call-ID` and attributed to no
/// dialog — or worse, to the wrong one.
fn quoted_header(prefix: &[u8], name: &[u8], compact: Option<u8>) -> Option<String> {
    let mut at = 0usize;
    while at < prefix.len() {
        let rest = &prefix[at..];
        let line_len = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .or_else(|| rest.iter().position(|&b| b == b'\n'))?;
        let line = &rest[..line_len];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let field = line[..colon].trim_ascii();
            let matches_long = field.len() == name.len()
                && field
                    .iter()
                    .zip(name)
                    .all(|(a, b)| a.to_ascii_lowercase() == *b);
            let matches_compact =
                compact.is_some_and(|c| field.len() == 1 && field[0].to_ascii_lowercase() == c);
            if matches_long || matches_compact {
                let value = line[colon + 1..].trim_ascii();
                if value.is_empty() {
                    return None;
                }
                return Some(String::from_utf8_lossy(value).into_owned());
            }
        }
        // Past the line and its CRLF. An empty line ends the headers.
        if line.is_empty() {
            return None;
        }
        at += line_len
            + if rest.get(line_len) == Some(&b'\r') {
                2
            } else {
                1
            };
    }
    None
}

/// Record one ICMP error as evidence about a SIP request.
///
/// Called from the ICMP arm of the packet parser, which is the only place
/// every capture path passes through. Errors whose quote is not a SIP request
/// — media, DNS, anything else — are not SIP evidence and are ignored here;
/// they remain visible to [`crate::capture::parse::parse_icmp_error`] for a
/// caller that wants them.
///
/// # Returns
///
/// `true` when the error was recorded as SIP evidence.
///
/// # Side effects
///
/// Takes the process-global evidence lock, which is only ever contended by
/// other ICMP errors.
pub fn record_icmp_error(quote: &crate::capture::parse::IcmpQuote) -> bool {
    let Some(sip) = quoted_sip_prefix(&quote.quoted_payload) else {
        return false;
    };

    let evidence = IcmpEvidence {
        timestamp: quote.timestamp,
        // The quoted datagram's DESTINATION, never the ICMP source: the former
        // did not answer, the latter is the device that noticed.
        unreachable_addr: quote.quoted_dst,
        unreachable_port: quote.quoted_dst_port,
        reported_by: quote.reporter,
        icmp_type: quote.icmp_type,
        icmp_code: quote.icmp_code,
        description: quote.description(),
        call_id: sip.call_id.clone(),
        method: Some(sip.method),
        cseq: sip.cseq,
        truncated: quote.quoted_truncated,
        quoted_bytes: quote.quoted_payload.len(),
    };

    let mut guard = ICMP_EVIDENCE.lock();
    let store = guard.get_or_insert_with(|| Box::new(IcmpEvidenceStore::new()));
    store.errors += 1;

    let endpoint_key = (evidence.unreachable_addr, evidence.unreachable_port);
    let endpoints_full = store.endpoints.len() >= MAX_ICMP_ENDPOINTS;
    if let Some(e) = store.endpoints.get_mut(&endpoint_key) {
        e.errors += 1;
        e.description = evidence.description;
    } else if endpoints_full {
        store.untallied_endpoints += 1;
    } else {
        store.endpoints.insert(
            endpoint_key,
            UnreachableEndpoint {
                addr: evidence.unreachable_addr,
                port: evidence.unreachable_port,
                errors: 1,
                description: evidence.description,
            },
        );
    }

    match &evidence.call_id {
        Some(call_id) => {
            store.attributed += 1;
            let call_ids_full = store.by_call_id.len() >= MAX_ICMP_CALL_IDS;
            if let Some(d) = store.by_call_id.get_mut(call_id) {
                // The count is exact whatever the sample cap does — a dialog
                // hit thirty times must not be reported as hit eight.
                d.errors += 1;
                if d.samples.len() < MAX_ICMP_PER_CALL_ID {
                    d.samples.push(evidence);
                }
            } else if call_ids_full {
                store.untracked_dialogs += 1;
            } else {
                store.by_call_id.insert(
                    call_id.clone(),
                    DialogIcmpEvidence {
                        errors: 1,
                        samples: vec![evidence],
                    },
                );
            }
        }
        // The quote stopped before the Call-ID header. The endpoint tally
        // above already holds what this error proves; only the dialog is
        // unknown, and the report says so rather than the error vanishing.
        None => store.unattributed += 1,
    }

    ICMP_EVIDENCE_SEEN.store(true, std::sync::atomic::Ordering::Release);
    true
}

/// Every ICMP error recorded against one `Call-ID`.
///
/// All-zero when the dialog drew no ICMP error, which is the answer for almost
/// every dialog — so this costs one relaxed atomic load and no lock until a
/// capture actually contains ICMP.
pub fn icmp_evidence_for(call_id: &str) -> DialogIcmpEvidence {
    if !ICMP_EVIDENCE_SEEN.load(std::sync::atomic::Ordering::Acquire) {
        return DialogIcmpEvidence::default();
    }
    let guard = ICMP_EVIDENCE.lock();
    guard
        .as_ref()
        .and_then(|s| s.by_call_id.get(call_id))
        .cloned()
        .unwrap_or_default()
}

/// What ICMP reported about this run's SIP traffic.
///
/// # Returns
///
/// An [`IcmpEvidenceReport`] with exact totals and every unreachable endpoint,
/// busiest first. All zeroes when no ICMP error quoted a SIP request.
pub fn icmp_evidence_report() -> IcmpEvidenceReport {
    let guard = ICMP_EVIDENCE.lock();
    let Some(store) = guard.as_ref() else {
        return IcmpEvidenceReport::default();
    };
    let mut endpoints: Vec<UnreachableEndpoint> = store.endpoints.values().cloned().collect();
    // Busiest first; ties by address then port so the report is deterministic.
    endpoints.sort_unstable_by(|a, b| {
        b.errors
            .cmp(&a.errors)
            .then(a.addr.cmp(&b.addr))
            .then(a.port.cmp(&b.port))
    });
    IcmpEvidenceReport {
        errors: store.errors,
        attributed: store.attributed,
        unattributed: store.unattributed,
        untracked_dialogs: store.untracked_dialogs,
        untallied_endpoints: store.untallied_endpoints,
        endpoints,
    }
}

/// Discard all recorded ICMP evidence.
///
/// The store is process-global, so a process analysing several captures in
/// sequence — and a test asserting on the counts — needs a way back to zero.
///
/// # Side effects
///
/// Frees the store and re-arms the no-evidence fast path.
pub fn reset_icmp_evidence() {
    *ICMP_EVIDENCE.lock() = None;
    ICMP_EVIDENCE_SEEN.store(false, std::sync::atomic::Ordering::Release);
}

/// Extract the RTP-stream link tuples `(media_ip, media_port, call_id, media)`
/// from an SDP offer/answer, one per `m=` line with a resolvable connection
/// address (media-level `c=`, else the session `c=`). Media without an address
/// is skipped. The media descriptions are cloned so codec / clock-rate can be
/// propagated to dynamic-payload-type RTP streams (e.g. Opus, H264).
///
/// The single source of truth for SDP→stream association across the live,
/// batch, and `--cores` paths. Handles multiple media streams (audio + video)
/// by returning a tuple per stream.
pub fn extract_sdp_links(
    sdp: &sip::sdp::SdpSession,
    call_id: &str,
) -> Vec<(std::net::IpAddr, u16, String, sip::sdp::SdpMedia)> {
    sdp.media
        .iter()
        .filter_map(|media| {
            sip::sdp::effective_address(media, sdp)
                .and_then(|a| a.parse::<std::net::IpAddr>().ok())
                .map(|ip| (ip, media.port, call_id.to_string(), media.clone()))
        })
        .collect()
}

/// Check if a UDP payload looks like RTCP.
///
/// Two conventions are recognized:
///
/// - Classic separate-port RTCP (RTP port + 1): an ODD destination port with
///   version=2 and a packet type in the 200-204 range.
/// - RFC 5761 RTP/RTCP multiplexing: RTP and RTCP share ONE (typically even)
///   port, so parity can no longer distinguish them. RTCP is then identified
///   by content — version=2, the RTCP packet-type byte in 192-223 (RTP payload
///   types are chosen to avoid this range precisely so the two demultiplex),
///   and an RTCP length field that frames the packet consistently. The length
///   check rejects an RTP packet whose marker+payload-type byte merely lands in
///   192-223, so muxed RTP is never misread as RTCP.
pub fn is_rtcp_packet(data: &[u8], dst_port: u16) -> bool {
    if data.len() < 8 {
        return false;
    }
    let version = (data[0] >> 6) & 0x03;
    if version != 2 {
        return false;
    }
    let pt = data[1];
    if !dst_port.is_multiple_of(2) {
        // Odd port: classic separate-port RTCP (RTP+1). The whole RFC 5761
        // range, not just SR..APP — an XR (207) here is still RTCP, and
        // rejecting it hands the datagram to the RTP path, where the first
        // report-block header reads as an SSRC and invents a stream.
        return crate::rtp::rtcp::is_rtcp_packet_type(pt);
    }
    // Even port: RFC 5761 mux. Require an RTCP packet-type byte and a
    // self-consistent length field so muxed RTP is not swallowed.
    (192..=223).contains(&pt) && rtcp_length_frames_packet(data)
}

/// Whether the first RTCP sub-packet's length field frames within `data`.
///
/// The RTCP header length (bytes 2-3) counts 32-bit words minus one, so the
/// first packet occupies `(len + 1) * 4` bytes. A real RTCP packet (or the
/// first element of a compound packet) declares at least one word beyond the
/// header and fits inside the datagram; a misread RTP packet does not. This is
/// the extra guard that keeps RFC 5761 demux from mistaking RTP for RTCP.
fn rtcp_length_frames_packet(data: &[u8]) -> bool {
    let word_len = ((data[2] as usize) << 8) | data[3] as usize;
    if word_len == 0 {
        return false;
    }
    (word_len + 1) * 4 <= data.len()
}

/// Try to unwrap a WebSocket frame from a TCP packet on common WS ports.
///
/// Returns `Some(payload)` if the packet is TCP, the destination or source
/// port is a common WebSocket port (80, 443, 8080, 8443), and the data
/// contains a valid WebSocket data frame wrapping SIP content.
pub fn try_websocket_unwrap(pp: &ParsedPacket) -> Option<Vec<u8>> {
    if pp.transport != TransportProto::Tcp {
        return None;
    }

    // Only attempt on common WebSocket ports
    let is_ws_port =
        websocket::WS_PORTS.contains(&pp.dst_port) || websocket::WS_PORTS.contains(&pp.src_port);
    if !is_ws_port {
        return None;
    }

    if !websocket::is_websocket_frame(&pp.payload) {
        return None;
    }

    match websocket::unwrap_websocket_frame(&pp.payload) {
        // `starts_sip_message`, for the same reason `classify_packet` uses it:
        // the narrower `sip::is_sip_message` would refuse to unwrap a frame
        // carrying an extension-method request, and SIP-over-WebSocket
        // (RFC 7118) is exactly where private methods turn up.
        Ok(Some(payload)) if sip::parser::starts_sip_message(&payload) => Some(payload),
        _ => None,
    }
}

/// Options controlling which protocols the pipeline tracks.
#[derive(Debug, Clone, Copy, Default)]
pub struct PipelineOptions {
    /// Skip dialog tracking for SIP messages. Classification still returns
    /// `PacketAction::Sip` (batch mode counts/matches/outputs untracked
    /// messages), but SDP link extraction is skipped and appliers must not
    /// write the dialog store.
    pub no_dialog: bool,
    /// Skip RTP/RTCP media tracking.
    pub no_rtp: bool,
    /// When set, SIP detection only considers packets with a source or
    /// destination port in this inclusive range (`--portrange` — signaling
    /// only; RTP uses SDP-negotiated dynamic ports and is never gated).
    /// `None` disables the gate (live capture, where BPF already filtered).
    pub sip_portrange: Option<(u16, u16)>,
    /// Suppress the per-packet "SIP parse error" diagnostic for SIP-looking
    /// packets that fail to parse (`--quiet-bad-parse`, sipgrep `-x`). The
    /// packet is dropped either way; only the notice is silenced.
    pub quiet_bad_parse: bool,
}

/// Optional media-decryption state threaded through the live pipeline: the SRTP
/// context (`--srtp-keys` + SDES `a=crypto`) and the DTLS-SRTP extractor
/// (`--dtls-keylog`). Both absent in non-`tls` builds; construct with
/// `Default` and populate the fields when a `tls` build has keys.
#[derive(Default)]
pub struct MediaDecrypt<'a> {
    /// SRTP context that authenticates and decrypts RTP payloads in place.
    #[cfg(feature = "tls")]
    pub srtp: Option<&'a mut crate::rtp::srtp::SrtpContext>,
    /// DTLS-SRTP extractor that recovers SRTP keys from DTLS handshakes.
    #[cfg(feature = "tls")]
    pub dtls: Option<&'a mut crate::capture::dtls::DtlsSrtpExtractor>,
    /// Holds the `'a` lifetime when neither decrypt field is compiled in.
    #[cfg(not(feature = "tls"))]
    _marker: std::marker::PhantomData<&'a ()>,
}

/// The store-mutation intent produced by `classify_packet` — the outcome of
/// classifying one packet *without touching any store or lock*. Each router
/// applies it with its own store access: the live path takes brief per-store
/// write locks (`process_packet`); the offline `--cores` and batch paths call
/// plain `&mut` stores directly. Separating the (duplicated) classification
/// from the (legitimately different) application is the core of the pipeline
/// unification (WS1).
pub enum PacketAction {
    /// Nothing to record: not SIP/RTP/RTCP, a DTLS handshake already consumed
    /// for key material, or opted out via `PipelineOptions`.
    None,
    /// A parsed SIP message plus the RTP-stream link tuples derived from its
    /// SDP (see `extract_sdp_links`). Returned even under
    /// `PipelineOptions::no_dialog` (with empty `sdp_links`) — batch mode
    /// still counts, matches, and outputs the message; appliers gate the
    /// dialog-store write on the option.
    Sip {
        /// The parsed message, to move into the dialog store.
        msg: sip::message::SipMessage,
        /// `(media_ip, media_port, call_id, media)` links to apply to streams.
        sdp_links: Vec<(std::net::IpAddr, u16, String, sip::sdp::SdpMedia)>,
    },
    /// Parsed RTCP compound-packet reports, to feed to `process_rtcp`.
    Rtcp(Vec<rtp::rtcp::RtcpPacket>),
    /// An RTP packet to record. `decrypted_payload` is `Some` only when SRTP
    /// substituted a plaintext payload; `None` means use the original
    /// `ParsedPacket` unchanged — so the common (unencrypted) path never
    /// clones the packet.
    Rtp {
        /// The parsed RTP header.
        hdr: rtp::parser::RtpHeader,
        /// SRTP-decrypted payload, if any.
        decrypted_payload: Option<bytes::Bytes>,
        /// `true` when the packet failed the strict `rtp::is_rtp_packet`
        /// pre-filter and was promoted by the consecutive-packet heuristic
        /// instead. Batch mode uses this to skip DTMF extraction and quality
        /// events for heuristic streams.
        via_heuristic: bool,
    },
}

/// Classify one parsed packet into a `PacketAction` — the lock-free core of
/// the per-packet pipeline. WebSocket unwrap, SIP parse + SDP-link extraction,
/// DTLS/SRTP key learning, RTCP parse, and RTP (header or heuristic) detection
/// all happen here, touching no store. `decrypt` is mutated in place to learn
/// SDES/DTLS keys and to decrypt SRTP payloads; `rtp_heuristic` is advanced for
/// RTP discovery. The caller applies the returned action to its stores.
pub fn classify_packet(
    pp: &ParsedPacket,
    rtp_heuristic: &mut rtp::heuristic::RtpHeuristic,
    opts: &PipelineOptions,
    decrypt: &mut MediaDecrypt<'_>,
) -> PacketAction {
    // `decrypt` is only consumed by the `tls`-gated media-decryption paths.
    #[cfg(not(feature = "tls"))]
    let _ = &decrypt;

    // Try WebSocket unwrapping for TCP on common WS ports
    let ws_payload = try_websocket_unwrap(pp);
    let effective_transport = if ws_payload.is_some() {
        TransportProto::Ws
    } else {
        pp.transport
    };
    // Owned ws frames become Bytes; otherwise share the packet buffer.
    let effective_payload: bytes::Bytes = match ws_payload {
        Some(v) => v.into(),
        None => pp.payload.clone(),
    };
    let effective_payload = &effective_payload;

    // SIP detection first — parse and derive links, touching no store. The
    // port gate applies to signaling only; RTP uses SDP-negotiated dynamic
    // ports and falls through to the media checks below.
    //
    // `sip::parser::starts_sip_message`, not `sip::is_sip_message`: the latter
    // sniffs the first line against a list of the fourteen registered methods,
    // so a request using an RFC 3261 §7.1 `extension-method` was discarded here
    // — before the parser, which handles it — and never appeared in any output.
    let sip_looks_like_sip = sip::parser::starts_sip_message(effective_payload);
    let sip_port_ok = opts
        .sip_portrange
        .is_none_or(|range| port_in_range(pp.src_port, pp.dst_port, range));
    if let Some(range) = opts.sip_portrange
        && !sip_port_ok
        && sip_looks_like_sip
    {
        // The gate is doing what `--portrange` asked, but it is discarding real
        // SIP and nothing downstream could tell. Record it so the loss is
        // reportable instead of silent; see `portrange_skip_report`.
        record_portrange_skip(pp.src_port, pp.dst_port, effective_payload, range);
    }
    if sip_port_ok && sip_looks_like_sip {
        match sip::parser::parse_sip_bytes(
            effective_payload,
            pp.timestamp,
            pp.src_addr,
            pp.dst_addr,
            pp.src_port,
            pp.dst_port,
            effective_transport,
        ) {
            Ok(sip_msg) => {
                let mut sdp_links = Vec::new();
                if !opts.no_dialog
                    && let Some(sdp) = sip_msg.sdp()
                    && let Some(call_id) = sip_msg.call_id()
                {
                    sdp_links = extract_sdp_links(&sdp, call_id);

                    // Feed SDES `a=crypto` key material into the SRTP context
                    // (mutates decrypt, not stores — so it belongs in
                    // classification). Keyed by the media's effective address
                    // even when it is not a parseable IP (hostname or absent),
                    // so key learning is never narrower than the SDP.
                    #[cfg(feature = "tls")]
                    if let Some(ctx) = decrypt.srtp.as_deref_mut() {
                        for media in &sdp.media {
                            if media.crypto.is_empty() {
                                continue;
                            }
                            let addr = sip::sdp::effective_address(media, &sdp);
                            let added = ctx.add_sdes(addr.clone(), Some(media.port), &media.crypto);
                            if added > 0 {
                                tracing::info!(
                                    "SRTP: +{added} SDES key(s) from SDP for {}:{}",
                                    addr.as_deref().unwrap_or("?"),
                                    media.port
                                );
                            }
                        }
                    }
                }
                return PacketAction::Sip {
                    msg: sip_msg,
                    sdp_links,
                };
            }
            Err(e) => {
                if !opts.quiet_bad_parse {
                    tracing::debug!("SIP parse error: {e}");
                }
                return PacketAction::None;
            }
        }
    }

    // RTP/RTCP detection
    if opts.no_rtp || pp.transport != TransportProto::Udp {
        return PacketAction::None;
    }

    // DTLS-SRTP: recover SRTP keys from DTLS handshakes and hand them to the
    // SRTP context. DTLS packets are not RTP, so consume and stop.
    #[cfg(feature = "tls")]
    if crate::capture::dtls::is_dtls(&pp.payload) {
        let keys = decrypt
            .dtls
            .as_deref_mut()
            .map(|ext| ext.process_dtls(&pp.payload))
            .unwrap_or_default();
        if !keys.is_empty()
            && let Some(ctx) = decrypt.srtp.as_deref_mut()
        {
            ctx.add_keys(keys);
        }
        return PacketAction::None;
    }

    if is_rtcp_packet(&pp.payload, pp.dst_port) {
        let rtcp_packets = rtp::rtcp::parse_rtcp(&pp.payload);
        if rtcp_packets.is_empty() {
            return PacketAction::None;
        }
        return PacketAction::Rtcp(rtcp_packets);
    }

    // `is_rtp_packet` looks at the payload only: 12+ bytes, version bits `10`,
    // payload type outside the RTCP range. That admits about a quarter of
    // arbitrary bytes on the version check alone, so on a well-known service
    // port it is not enough on its own — a DNS response from `1.1.1.1:53`
    // supplied the pattern from its transaction ID and became a one-packet
    // stream with SSRC `0x00000000`. Four such streams appeared in a
    // 1217-stream corpus of real traffic.
    //
    // Below 1024 the payload therefore has to be corroborated by the strict
    // heuristic (even destination port, three consecutive packets agreeing on
    // SSRC, payload type and sequence), which no single stray packet survives.
    // Real media is untouched: RFC 3550 §11 places RTP in the dynamic range,
    // and nothing legitimately carries it on a system port.
    let on_system_port = pp.src_port < 1024 || pp.dst_port < 1024;
    if !on_system_port
        && rtp::is_rtp_packet(&pp.payload)
        && let Ok(rtp_hdr) = rtp::parser::parse_rtp_header(&pp.payload)
    {
        // SRTP: substitute a decrypted payload when a key authenticates it.
        #[cfg(feature = "tls")]
        let decrypted_payload = decrypt
            .srtp
            .as_deref_mut()
            .and_then(|ctx| ctx.decrypt(&pp.payload, rtp_hdr.payload_offset))
            .map(bytes::Bytes::from);
        #[cfg(not(feature = "tls"))]
        let decrypted_payload = None;
        return PacketAction::Rtp {
            hdr: rtp_hdr,
            decrypted_payload,
            via_heuristic: false,
        };
    }

    if let Some(rtp_hdr) = rtp_heuristic.check(pp) {
        return PacketAction::Rtp {
            hdr: rtp_hdr,
            decrypted_payload: None,
            via_heuristic: true,
        };
    }

    PacketAction::None
}

/// Route one parsed packet into the dialog / stream stores (live/TUI path).
///
/// Classifies via `classify_packet` (lock-free), then applies the result
/// with brief per-store write locks — each store is locked once and released,
/// never both at once, to minimize contention with the TUI render thread.
///
/// `decrypt` carries optional SRTP/DTLS-SRTP key state; when present, SRTP
/// payloads are authenticated and decrypted before media analysis, SDES keys
/// are learned from SDP, and DTLS handshakes feed the SRTP key store.
pub fn process_packet(
    pp: &ParsedPacket,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    rtp_heuristic: &mut rtp::heuristic::RtpHeuristic,
    opts: &PipelineOptions,
    decrypt: &mut MediaDecrypt<'_>,
) {
    match classify_packet(pp, rtp_heuristic, opts, decrypt) {
        PacketAction::None => {}
        PacketAction::Sip { msg, sdp_links } => {
            // Classification returns Sip even with no_dialog (batch needs the
            // message); the live path simply drops untracked messages.
            if opts.no_dialog {
                return;
            }
            // Quick write to dialog store, then release.
            dialog_store.write().process_message(msg);
            // Link SDP media endpoints to RTP streams (separate lock).
            if !sdp_links.is_empty() {
                let mut ss = stream_store.write();
                for (ip, port, call_id, media) in &sdp_links {
                    ss.link_to_dialog_with_sdp(*ip, *port, call_id, media);
                }
            }
        }
        PacketAction::Rtcp(rtcp_packets) => {
            stream_store.write().process_rtcp(&rtcp_packets);
        }
        PacketAction::Rtp {
            hdr,
            decrypted_payload,
            via_heuristic: _,
        } => match decrypted_payload {
            Some(payload) => {
                let mut d = pp.clone();
                d.payload = payload;
                stream_store.write().process_rtp(&d, &hdr, d.timestamp);
            }
            None => {
                stream_store.write().process_rtp(pp, &hdr, pp.timestamp);
            }
        },
    }
}

// ── Tests ────────────────────────────────────────────────────────────

// The `--quiet-bad-parse` diagnostic gate is verified by capturing tracing
// output, which needs `tracing-subscriber` (only compiled under `native`).
#[cfg(all(test, feature = "native"))]
mod quiet_bad_parse_tests {
    //! Tests that `--quiet-bad-parse` gates only the parse-error diagnostic and
    //! never changes how a packet classifies.
    use super::*;
    use crate::capture::parse::{ParsedPacket, TransportProto};
    use chrono::Utc;
    use parking_lot::Mutex;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    /// A `tracing` writer that accumulates every emitted line into a shared
    /// buffer so a test can assert on what was (or was not) logged.
    #[derive(Clone, Default)]
    struct CaptureBuf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureBuf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureBuf {
        type Writer = CaptureBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run `f` with a thread-local DEBUG subscriber and return captured output.
    fn capture_logs(f: impl FnOnce()) -> String {
        let buf = CaptureBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(buf.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = buf.0.lock().clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Build a UDP `ParsedPacket` from 10.0.0.1:5060 → 10.0.0.2:5060 carrying
    /// `payload`, for driving `classify_packet` without a real capture.
    fn packet(payload: &[u8]) -> ParsedPacket {
        ParsedPacket {
            timestamp: Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 5060,
            dst_port: 5060,
            transport: TransportProto::Udp,
            payload: payload.to_vec().into(),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            from_hep: false,
        }
    }

    /// `is_sip_message()` accepts the `SIP/2.0 ` response prefix, but the
    /// status token `XYZ` is not numeric, so `parse_sip_bytes()` errors — this
    /// is exactly the bad-parse path `--quiet-bad-parse` controls.
    fn malformed_sip() -> ParsedPacket {
        packet(b"SIP/2.0 XYZ Bad Status\r\n\r\n")
    }

    /// A well-formed INVITE packet that parses successfully.
    fn valid_invite() -> ParsedPacket {
        packet(
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKq1\r\n\
              From: <sip:alice@example.com>;tag=q1\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: quiet-parse@test\r\n\
              CSeq: 1 INVITE\r\n\
              Content-Length: 0\r\n\r\n",
        )
    }

    /// Classify `pp` with default heuristic/decrypt state (test wrapper).
    fn classify(pp: &ParsedPacket, opts: &PipelineOptions) -> PacketAction {
        let mut heur = crate::rtp::heuristic::RtpHeuristic::new();
        let mut decrypt = MediaDecrypt::default();
        classify_packet(pp, &mut heur, opts, &mut decrypt)
    }

    /// A DNS exchange must not be reported as an RTP stream.
    ///
    /// `is_rtp_packet` is payload-only: any UDP payload of 12+ bytes whose top
    /// two bits are `10` and whose payload type is outside 72..=76 passes. The
    /// version check alone admits roughly a quarter of arbitrary bytes, and a
    /// DNS transaction ID supplies them — a response from `1.1.1.1:53` landed
    /// in a real capture as a one-packet stream with SSRC `0x00000000`. Four
    /// of them appeared in a 1217-stream corpus.
    ///
    /// The strict multi-packet heuristic would have rejected every one, but it
    /// never ran: the payload-only branch returns first. So a system port
    /// (below 1024) now has to satisfy the heuristic instead of being taken on
    /// the payload's word. Real RTP is unaffected — RFC 3550 §11 puts it in
    /// the dynamic range, and nothing legitimately carries media on port 53.
    #[test]
    fn a_dns_response_is_not_an_rtp_stream() {
        // A DNS response whose transaction ID starts 0x80: two high bits set
        // to `10`, exactly what the RTP version check looks for.
        let mut dns = vec![0x80u8, 0x81, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        dns.extend_from_slice(&[0x03, b'w', b'w', b'w', 0x00, 0x00, 0x01, 0x00, 0x01]);
        assert!(
            crate::rtp::is_rtp_packet(&dns),
            "precondition: this payload does fool the payload-only check,              which is the whole reason the port guard exists"
        );

        let mut pp = packet(&dns);
        pp.src_port = 53;
        pp.dst_port = 44326; // even, so port parity alone does not save us
        assert!(
            matches!(
                classify(&pp, &PipelineOptions::default()),
                PacketAction::None
            ),
            "a single DNS packet must not become an RTP stream"
        );

        // The other direction, to the DNS port.
        let mut pp = packet(&dns);
        pp.src_port = 44326;
        pp.dst_port = 53;
        assert!(
            matches!(
                classify(&pp, &PipelineOptions::default()),
                PacketAction::None
            ),
            "a query to port 53 must not become an RTP stream either"
        );
    }

    /// Real RTP on a dynamic port is still recognised from the payload alone.
    ///
    /// The guard must not cost the common case a single packet of latency:
    /// media on an ephemeral port is admitted immediately, without waiting for
    /// the three-packet heuristic to corroborate it.
    #[test]
    fn rtp_on_a_dynamic_port_is_still_recognised_immediately() {
        let mut rtp = vec![0x80u8, 0x00]; // V=2, PT=0 (PCMU)
        rtp.extend_from_slice(&[0x00, 0x01]); // sequence
        rtp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // timestamp
        rtp.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // SSRC
        rtp.extend_from_slice(&[0u8; 160]);

        let mut pp = packet(&rtp);
        pp.src_port = 20000;
        pp.dst_port = 20002;
        assert!(
            matches!(
                classify(&pp, &PipelineOptions::default()),
                PacketAction::Rtp { .. }
            ),
            "media on a dynamic port must still be recognised from one packet"
        );
    }

    /// RFC 5761 RTP/RTCP multiplexing: a well-formed RTCP packet arriving on an
    /// EVEN port (RTP and RTCP sharing one port) must be recognized as RTCP by
    /// content, not rejected for port parity. A malformed RTCP-looking packet
    /// whose length field does not frame the buffer stays rejected so muxed RTP
    /// is never swallowed; the classic odd-port path is unchanged.
    #[test]
    fn muxed_rtcp_on_even_port_is_recognized() {
        // RTCP Receiver Report: V=2, PT=201, length=1 word => 8 bytes total.
        let rr = [0x80u8, 201, 0, 1, 0, 0, 0, 1];
        assert!(
            is_rtcp_packet(&rr, 5000),
            "well-formed muxed RTCP on an even port must be recognized (RFC 5761)"
        );
        // Length field claims 28 bytes but only 8 are present: not real RTCP,
        // so an even-port packet like this stays RTP (must not be swallowed).
        assert!(
            !is_rtcp_packet(&[0x80, 200, 0, 6, 0, 0, 0, 1], 5000),
            "inconsistent length field on an even port is not RTCP"
        );
        // Zero-length header on an even port is also rejected.
        assert!(!is_rtcp_packet(&[0x80, 200, 0, 0, 0, 0, 0, 0], 5000));
        // Odd-port classic behavior is unchanged.
        assert!(is_rtcp_packet(&rr, 5001));
        assert!(is_rtcp_packet(&[0x80, 200, 0, 6, 0, 0, 0, 1], 30001));
    }

    /// By default a malformed SIP packet drops to `None` and emits the
    /// "SIP parse error" diagnostic.
    #[test]
    fn default_reports_bad_parse() {
        let pp = malformed_sip();
        let logs = capture_logs(|| {
            let action = classify(&pp, &PipelineOptions::default());
            assert!(matches!(action, PacketAction::None), "bad parse → None");
        });
        assert!(
            logs.contains("SIP parse error"),
            "default must emit the bad-parse diagnostic; got {logs:?}"
        );
    }

    /// With `quiet_bad_parse` set, the same malformed packet still drops but
    /// the diagnostic is silenced.
    #[test]
    fn quiet_flag_suppresses_diagnostic() {
        let pp = malformed_sip();
        let opts = PipelineOptions {
            quiet_bad_parse: true,
            ..Default::default()
        };
        let logs = capture_logs(|| {
            let action = classify(&pp, &opts);
            assert!(matches!(action, PacketAction::None), "still dropped");
        });
        assert!(
            !logs.contains("SIP parse error"),
            "quiet_bad_parse must silence the diagnostic; got {logs:?}"
        );
    }

    /// The flag never changes classification of a valid INVITE (still `Sip`).
    #[test]
    fn quiet_flag_does_not_affect_valid_sip() {
        // Adversarial: the flag must only gate the error notice, never change
        // how a well-formed message classifies.
        let pp = valid_invite();
        let opts = PipelineOptions {
            quiet_bad_parse: true,
            ..Default::default()
        };
        let action = classify(&pp, &opts);
        assert!(
            matches!(action, PacketAction::Sip { .. }),
            "valid INVITE must still classify as Sip"
        );
    }
}
