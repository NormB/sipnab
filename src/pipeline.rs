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
// sipnab can otherwise analyze (31.2%); `tshark` independently puts 49,576 of
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
//     `tg.pcap0` both ways). But it makes `--portrange` a no-op for signaling,
//     which is a different promise from the one the flag documents, and the
//     gate's behavior is pinned by tests outside this file.
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
             (e.g. --portrange 1-65535) to analyze them."
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
/// The totals sipnab prints count what it analyzed. This is what it saw, knew
/// was SIP, and did not analyze — the difference an operator otherwise has no
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
/// The tally is process-global, so a process that analyzes several captures in
/// sequence (and a test that asserts on the counts) needs a way back to zero.
///
/// # Side effects
///
/// Resets the global counters and frees the per-port table.
pub fn reset_portrange_skips() {
    *PORTRANGE_SKIPS.lock() = PortrangeSkips::new();
}

// ── What the WebSocket port set threw away ───────────────────────────
//
// The same defect as `--portrange` above, one layer down and worse, because
// `--portrange` at least SAYS what it skipped. The SIP-over-WebSocket unwrap
// only ever ran on 80, 443, 8080 and 8443 — the browser's view of the web —
// and any deployment terminating WSS elsewhere (Kamailio, OpenSIPS and Janus
// each default outside that set, and a reverse proxy forwards to whatever port
// it likes) had its entire WebRTC signaling leg vanish. Not skipped loudly:
// the frames were never recognized as SIP at all, so they reached no count, no
// dialog and no output, and no line of the report hinted they existed.
//
// The tally below closes that. The unwrap is now ATTEMPTED regardless of port
// — the frame test is two bytes, so the cost falls on TCP payloads whose first
// byte already looks like a WebSocket data frame — and a successful unwrap
// carrying real SIP is either analyzed (the port is in the set) or counted
// here (it is not). The silence was as much the bug as the ports were.

/// What the WebSocket port set discarded during this run.
///
/// Empty when nothing was skipped, which is the case for any capture whose
/// SIP-over-WebSocket all lands on the configured ports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WsPortSkipReport {
    /// Total SIP-over-WebSocket messages sipnab recognized, unwrapped far
    /// enough to confirm they were SIP, and then declined because neither port
    /// was in the configured set. These appear in no count, no dialog, and no
    /// output format.
    pub messages: u64,
    /// Per-port breakdown, busiest first.
    pub ports: Vec<SkippedPort>,
}

/// Per-port tally of skipped SIP-over-WebSocket, plus the escalation state.
struct WsPortSkips {
    /// Total skipped messages.
    messages: u64,
    /// Messages per service port, indexed by port. `None` until the first skip.
    per_port: Option<Box<[u64]>>,
    /// Skip count at which the next warning fires (1, then ×10 each time).
    next_warn: u64,
}

impl WsPortSkips {
    /// Empty tally with the first warning armed.
    const fn new() -> Self {
        Self {
            messages: 0,
            per_port: None,
            next_warn: 1,
        }
    }
}

/// Process-global skip tally, global for the reason `PORTRANGE_SKIPS` is.
static WS_PORT_SKIPS: parking_lot::Mutex<WsPortSkips> = parking_lot::Mutex::new(WsPortSkips::new());

/// Record one SIP-over-WebSocket message the port set declined to unwrap.
///
/// # Arguments
///
/// * `src_port` / `dst_port` — the packet's ports, neither in the set.
/// * `payload` — the UNWRAPPED SIP bytes, read only to tell a request from a
///   response so the service port can be named.
///
/// # Side effects
///
/// Bumps the process-global tally and may emit a `WARN`, on the same 1-then-
/// powers-of-ten escalation the portrange tally uses.
fn record_ws_port_skip(src_port: u16, dst_port: u16, payload: &[u8]) {
    // A request's service port is its destination; a response's is its source
    // — the same rule, and the same reason, as `record_portrange_skip`.
    let service_port = if payload.starts_with(b"SIP/2.0 ") {
        src_port
    } else {
        dst_port
    };

    let warn = {
        let mut st = WS_PORT_SKIPS.lock();
        st.messages += 1;
        let table = st
            .per_port
            .get_or_insert_with(|| vec![0u64; usize::from(u16::MAX) + 1].into_boxed_slice());
        table[usize::from(service_port)] += 1;

        if st.messages < st.next_warn {
            None
        } else {
            st.next_warn = st.messages.saturating_mul(10);
            let busiest = busiest_ws_ports(&st, 3);
            Some((st.messages, busiest))
        }
    };

    if let Some((messages, busiest)) = warn {
        let ports = busiest
            .iter()
            .map(|p| format!("{} ({})", p.port, p.messages))
            .collect::<Vec<_>>()
            .join(", ");
        let configured = crate::capture::websocket::ws_ports_description();
        tracing::warn!(
            "SIP-over-WebSocket outside the WebSocket port set ({configured}) is \
             being skipped: {messages} message(s) so far, in no count, no dialog, \
             and no output. Busiest port(s): {ports}. Re-run with --ws-portrange \
             covering them (e.g. --ws-portrange 1-65535) to analyze them."
        );
    }
}

/// The `n` busiest ports in `st`, busiest first.
fn busiest_ws_ports(st: &WsPortSkips, n: usize) -> Vec<SkippedPort> {
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
    ports.sort_unstable_by(|a, b| b.messages.cmp(&a.messages).then(a.port.cmp(&b.port)));
    ports.truncate(n);
    ports
}

/// The SIP-over-WebSocket this run recognized and did not analyze because
/// neither port was in the configured WebSocket set.
///
/// The counterpart of [`portrange_skip_report`] for RFC 7118 traffic, and the
/// report that did not exist at all before: a deployment terminating WSS on
/// 8081 was told nothing whatsoever. Report it beside any message or dialog
/// count taken from a capture that could carry WebSocket signaling.
///
/// # Returns
///
/// A [`WsPortSkipReport`] with the running total and every port that carried
/// skipped SIP-over-WebSocket, busiest first. All zeroes when nothing was
/// skipped.
#[must_use]
pub fn ws_port_skip_report() -> WsPortSkipReport {
    let st = WS_PORT_SKIPS.lock();
    WsPortSkipReport {
        messages: st.messages,
        ports: busiest_ws_ports(&st, usize::MAX),
    }
}

/// Clear the WebSocket skip tally and re-arm the warning escalation.
///
/// # Side effects
///
/// Resets the global counters and frees the per-port table.
pub fn reset_ws_port_skips() {
    *WS_PORT_SKIPS.lock() = WsPortSkips::new();
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
//     the `analyzed + skipped` reconciliation still mean what it says.
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
/// — media, DNS, anything else — are not SIP evidence and go to the media
/// store instead (see [`icmp_media_report`]), so that nothing parsed is
/// dropped.
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
        record_media_icmp_error(quote);
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
/// The store is process-global, so a process analyzing several captures in
/// sequence — and a test asserting on the counts — needs a way back to zero.
///
/// # Side effects
///
/// Frees the store and re-arms the no-evidence fast path. The RESOLVED media
/// findings go with it: they are an answer about the store that is being
/// discarded, and leaving them behind would let the next capture's surfaces
/// report the previous capture's flows.
pub fn reset_icmp_evidence() {
    *ICMP_EVIDENCE.lock() = None;
    ICMP_EVIDENCE_SEEN.store(false, std::sync::atomic::Ordering::Release);
    *MEDIA_ICMP.lock() = None;
    *MEDIA_ICMP_RESOLVED.lock() = None;
    MEDIA_ICMP_RESOLVED_SEEN.store(false, std::sync::atomic::Ordering::Release);
    // Whatever a test pinned is gone with the set it pinned, so the release is
    // the same call the test already makes rather than a second one it has to
    // remember.
    #[cfg(test)]
    MEDIA_ICMP_PINNED.store(false, std::sync::atomic::Ordering::Release);
}

// ── What ICMP said about media ───────────────────────────────────────
//
// The section above reads ICMP errors that quote a SIP request. This one reads
// the rest of them, and the rest of them are not noise: across one real corpus
// of fifteen captures, 544 of 3,776 ICMP errors quoted a non-SIP port, and
// `tshark` places the exact quoted 5-tuple of 543 of those in traffic the same
// corpus contains. Every one was parsed and thrown away. "Your audio is being
// sent to a host that is not listening" is one of the commonest questions this
// tool exists to answer, and the packet that answers it was in the file.
//
// The association key is the hard part and it is NOT the signaling one. A
// media datagram carries no `Call-ID`, so a quote of one has nothing to key on
// but the failed datagram's own 5-tuple and — when the router quoted past RFC
// 792's 8-byte minimum — an RTP or RTCP header. Matching those needs the
// stream store, which does not exist at parse time and, under `--cores`, is
// per-worker while this store is process-global. So recording and attribution
// are deliberately separate: the quote is filed by flow as it is parsed, and
// [`icmp_media_report`] resolves it against a `StreamStore` at the end of the
// run. That is the same split the signaling side uses (record by `Call-ID`,
// resolve at diagnosis time), for the same reason.
//
// Three rules, each because the obvious alternative is wrong:
//
//   * **A quote is not a packet.** It never creates a stream, never moves a
//     stream count, and never enters the SIP evidence report. The signaling
//     side holds that line for message counts; this holds it for stream counts.
//   * **Unmatched is reported, not dropped.** A quote that matches no stream
//     still names a real socket that a real router said was unreachable. It is
//     counted as unattributed and its endpoint is still tallied, so the report
//     distinguishes "no evidence" from "evidence sipnab could not place".
//   * **What the payload is and what it matched are different facts.** A quote
//     can be recognisably RTP and match no stream (media this capture does not
//     hold), or match a stream with no payload left to read (the RFC 792
//     minimum). Collapsing them into one "is media" flag would lose which of
//     the two a reader is looking at.

pub use crate::rtp::stream_store::{MediaAttribution, MediaMatch};

/// Distinct quoted flows the media store retains.
///
/// The totals stay exact past this; [`IcmpMediaReport::untracked_flows`] says
/// how many errors reached no flow entry at all.
pub const MAX_ICMP_MEDIA_FLOWS: usize = 4_096;

/// Errors retained per flow. Past this the per-flow COUNT still rises — only
/// the retained detail stops, because the ninth quote of one flow shows
/// nothing the first eight did not.
pub const MAX_ICMP_PER_FLOW: usize = 8;

/// What a quoted non-SIP payload turned out to be.
///
/// Read from the quote itself, never inferred from the port: a "media port" is
/// a convention, and reporting a failed DNS query as a media blackhole because
/// it used a high UDP port would be a fabricated diagnosis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotedMediaKind {
    /// An RTP header. `ssrc` is the second key onto a tracked stream.
    Rtp {
        /// Synchronization source from the RTP header.
        ssrc: u32,
        /// Payload type, so a reader knows which codec went missing.
        payload_type: u8,
    },
    /// An RTCP packet — a sender or receiver report, SDES, BYE, or feedback.
    Rtcp {
        /// Synchronization source from the report.
        ssrc: u32,
        /// RTCP packet type (200 SR, 201 RR, 202 SDES, …).
        packet_type: u8,
    },
    /// The quote carried no payload past the transport header, which is what
    /// RFC 792's 8-byte minimum guarantees and nothing more. Not a failure:
    /// the flow may still match a stream.
    Unread,
    /// Payload was present and is neither RTP nor RTCP.
    NotMedia,
}

impl QuotedMediaKind {
    /// The SSRC this payload named, when it named one.
    pub fn ssrc(self) -> Option<u32> {
        match self {
            Self::Rtp { ssrc, .. } | Self::Rtcp { ssrc, .. } => Some(ssrc),
            Self::Unread | Self::NotMedia => None,
        }
    }

    /// Whether the payload itself proves this datagram was media.
    pub fn is_media(self) -> bool {
        matches!(self, Self::Rtp { .. } | Self::Rtcp { .. })
    }
}

/// Read a quoted non-SIP UDP payload as RTP or RTCP.
///
/// # The bar is set where a false positive stops being cheap
///
/// A bare "version == 2" test passes on a quarter of all random two-bit
/// prefixes, and this module already carries the scar of a looser media check:
/// a payload-only RTP heuristic once invented four phantom streams out of DNS
/// traffic. So:
///
/// * **RTCP** must have version 2 *and* a packet type in the assigned range
///   *and* a length field that fits inside the datagram. That is roughly 19
///   bits of agreement, and it is what the corpus's media errors actually are.
/// * **RTP** must have version 2, a payload type outside 64–95 (which RFC 5761
///   §4 reserves so RTP and RTCP can be told apart on one port), no padding
///   claim it cannot support, and twelve bytes to hold a header.
///
/// Even then the answer only ever *labels* a quote. It never creates a stream
/// and never attributes one on its own: attribution is
/// [`crate::rtp::stream_store::StreamStore::attribute_media_quote`]'s job, and
/// the SSRC read here is one of the keys it is offered.
///
/// # Examples
///
/// ```
/// use sipnab::pipeline::{QuotedMediaKind, quoted_media_kind};
///
/// // An RTP header: version 2, PCMU, SSRC 0x0BADF00D.
/// let mut rtp = vec![0x80u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xA0];
/// rtp.extend_from_slice(&0x0BAD_F00Du32.to_be_bytes());
/// assert_eq!(
///     quoted_media_kind(&rtp),
///     QuotedMediaKind::Rtp { ssrc: 0x0BAD_F00D, payload_type: 0 }
/// );
///
/// // RFC 792's minimum quote reaches no payload at all.
/// assert_eq!(quoted_media_kind(&[]), QuotedMediaKind::Unread);
///
/// // A DNS query is not claimed as media.
/// let dns = [0x12u8, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
/// assert_eq!(quoted_media_kind(&dns), QuotedMediaKind::NotMedia);
/// ```
pub fn quoted_media_kind(payload: &[u8]) -> QuotedMediaKind {
    if payload.is_empty() {
        return QuotedMediaKind::Unread;
    }
    let Some(&first) = payload.first() else {
        return QuotedMediaKind::Unread;
    };
    if first >> 6 != 2 {
        return QuotedMediaKind::NotMedia;
    }
    let Some(&second) = payload.get(1) else {
        // One byte of payload is not enough to tell RTP from RTCP from
        // anything else, and guessing from it would be guessing.
        return QuotedMediaKind::Unread;
    };

    // RTCP first: its packet types occupy 192-223, which RFC 5761 §4 excludes
    // from RTP's payload-type space precisely so this test is unambiguous.
    if (192..=223).contains(&second) && payload.len() >= 8 {
        let words = u16::from_be_bytes([payload[2], payload[3]]);
        let declared = (usize::from(words) + 1) * 4;
        // A truncated quote holds less than the packet declared, so the
        // header may legitimately claim more than is here — but never less,
        // and never zero.
        if declared >= 8 {
            return QuotedMediaKind::Rtcp {
                ssrc: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
                packet_type: second,
            };
        }
        return QuotedMediaKind::NotMedia;
    }

    let payload_type = second & 0x7f;
    // 64-95 is the RTCP range under RFC 5761 multiplexing: an RTP packet must
    // not use it, so a "version 2" payload that does is not RTP.
    if (64..=95).contains(&payload_type) {
        return QuotedMediaKind::NotMedia;
    }
    if payload.len() < 12 {
        return QuotedMediaKind::Unread;
    }
    QuotedMediaKind::Rtp {
        ssrc: u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]),
        payload_type,
    }
}

/// The quoted datagram's flow: who sent it, who did not answer, and over what.
///
/// The association key for a media quote, and the reason the media store is
/// keyed differently from the signaling one. Two sockets and a transport,
/// with no room for the reporter's address — naming the router that noticed as
/// the endpoint that failed is the mistake this whole area is shaped to
/// prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuotedFlow {
    /// Source socket of the failed datagram: the sender of the media.
    pub src: std::net::SocketAddr,
    /// Destination socket: THE SOCKET THAT DID NOT ANSWER.
    pub dst: std::net::SocketAddr,
    /// Transport the failed datagram used.
    pub transport: TransportProto,
}

/// One ICMP error about a datagram that was not a SIP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaIcmpEvidence {
    /// Capture time of the ICMP error.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Who reported the failure: the ICMP message's source. A router on the
    /// path — not the endpoint that failed, and never to be named as one.
    pub reported_by: std::net::IpAddr,
    /// Raw ICMP type byte.
    pub icmp_type: u8,
    /// Raw ICMP code byte.
    pub icmp_code: u8,
    /// The network's own words for this type/code.
    pub description: &'static str,
    /// What the quoted payload turned out to be.
    pub payload: QuotedMediaKind,
    /// Whether the quote is known to be shorter than the datagram it quotes.
    pub truncated: bool,
    /// Bytes of the original transport payload the quote actually carried.
    pub quoted_bytes: usize,
}

/// Every ICMP error recorded against one quoted flow.
///
/// `errors` is exact; `samples` is capped at [`MAX_ICMP_PER_FLOW`], for the
/// same reason the signaling side caps its own: a flow hit thirty times must
/// not be reported as hit eight.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowIcmpEvidence {
    /// How many ICMP errors quoted this flow. Exact, whatever the cap.
    pub errors: u64,
    /// Retained errors, oldest first.
    pub samples: Vec<MediaIcmpEvidence>,
}

/// Retained media evidence, plus the counters that stay exact past the caps.
struct MediaIcmpStore {
    /// Evidence keyed by the quoted datagram's flow.
    by_flow: std::collections::HashMap<QuotedFlow, FlowIcmpEvidence>,
    /// Per-endpoint tally, so a quote matching no stream still names the
    /// socket that failed.
    endpoints: std::collections::HashMap<(std::net::IpAddr, Option<u16>), UnreachableEndpoint>,
    /// Exact total, unaffected by the caps below.
    errors: u64,
    /// Errors whose quote stopped before the transport header, so they have no
    /// flow to be keyed on at all.
    unkeyed: u64,
    /// Errors whose flow was never tracked, because the store was full.
    untracked_flows: u64,
    /// Errors whose endpoint was never tallied, because the store was full.
    untallied_endpoints: u64,
}

impl MediaIcmpStore {
    /// Empty store.
    fn new() -> Self {
        Self {
            by_flow: std::collections::HashMap::new(),
            endpoints: std::collections::HashMap::new(),
            errors: 0,
            unkeyed: 0,
            untracked_flows: 0,
            untallied_endpoints: 0,
        }
    }
}

/// Process-global media evidence. Global for the same reason the signaling
/// store is: `--cores` shards by outer host pair, and an ICMP error's outer
/// pair is (router, sender) — a different pair from the media it describes.
static MEDIA_ICMP: parking_lot::Mutex<Option<Box<MediaIcmpStore>>> = parking_lot::Mutex::new(None);

/// Record one ICMP error about a datagram that was not a SIP request.
///
/// Called only from [`record_icmp_error`], on the path where the quote failed
/// to parse as a SIP request start line. Filing it by flow here, and resolving
/// it against a `StreamStore` later in [`icmp_media_report`], is what lets the
/// same error be recorded under `--cores` (where no worker owns the media it
/// describes) and still be attributed to the right stream.
///
/// # Side effects
///
/// Takes the process-global media evidence lock, which is only ever contended
/// by other ICMP errors.
fn record_media_icmp_error(quote: &crate::capture::parse::IcmpQuote) {
    let evidence = MediaIcmpEvidence {
        timestamp: quote.timestamp,
        reported_by: quote.reporter,
        icmp_type: quote.icmp_type,
        icmp_code: quote.icmp_code,
        description: quote.description(),
        payload: quoted_media_kind(&quote.quoted_payload),
        truncated: quote.quoted_truncated,
        quoted_bytes: quote.quoted_payload.len(),
    };

    let mut guard = MEDIA_ICMP.lock();
    let store = guard.get_or_insert_with(|| Box::new(MediaIcmpStore::new()));
    store.errors += 1;

    // The quoted DESTINATION, never the ICMP source: the former did not
    // answer, the latter is the device that noticed.
    let endpoint_key = (quote.quoted_dst, quote.quoted_dst_port);
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
                addr: quote.quoted_dst,
                port: quote.quoted_dst_port,
                errors: 1,
                description: evidence.description,
            },
        );
    }

    // No ports means no flow: the quote stopped before the transport header,
    // or quoted a non-first fragment, which has none. The endpoint tally above
    // already holds what the error proves; only the flow is unknown, and the
    // report says so rather than the error vanishing.
    let (Some(src_port), Some(dst_port), Some(transport)) = (
        quote.quoted_src_port,
        quote.quoted_dst_port,
        quote.quoted_transport,
    ) else {
        store.unkeyed += 1;
        return;
    };
    let flow = QuotedFlow {
        src: std::net::SocketAddr::new(quote.quoted_src, src_port),
        dst: std::net::SocketAddr::new(quote.quoted_dst, dst_port),
        transport,
    };

    let flows_full = store.by_flow.len() >= MAX_ICMP_MEDIA_FLOWS;
    if let Some(f) = store.by_flow.get_mut(&flow) {
        f.errors += 1;
        if f.samples.len() < MAX_ICMP_PER_FLOW {
            f.samples.push(evidence);
        }
    } else if flows_full {
        store.untracked_flows += 1;
    } else {
        store.by_flow.insert(
            flow,
            FlowIcmpEvidence {
                errors: 1,
                samples: vec![evidence],
            },
        );
    }
}

/// One quoted flow the network reported as undeliverable, resolved against the
/// media sipnab tracked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaIcmpFinding {
    /// `address:port` that sent the datagram that failed.
    pub source: String,
    /// `address:port` of the socket that did not answer. The thing to look at.
    pub unreachable_endpoint: String,
    /// Address of the device that reported the failure. Not the fault.
    pub reported_by: String,
    /// Transport the failed datagram used.
    pub transport: &'static str,
    /// The network's own words, e.g. `port unreachable`.
    pub description: String,
    /// Raw ICMP type byte.
    pub icmp_type: u8,
    /// Raw ICMP code byte.
    pub icmp_code: u8,
    /// How many errors named this flow. Exact — not the number of retained
    /// samples, which is capped.
    pub errors: u64,
    /// What the quoted payload was.
    pub payload: QuotedMediaKind,
    /// Which rule tied this flow to tracked media, if any.
    pub matched: MediaMatch,
    /// How many tracked streams the rule matched.
    pub streams: usize,
    /// `Call-ID`s of the affected dialogs, when the match named any.
    pub call_ids: Vec<String>,
    /// Plain-language rendering, so surfaces do not each re-invent it.
    pub hint: String,
}

/// What ICMP reported about this run's non-signaling traffic.
///
/// All zeroes when no ICMP error quoted anything but SIP, which is the common
/// case for a healthy capture.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IcmpMediaReport {
    /// ICMP errors quoting a datagram that was not a SIP request.
    pub errors: u64,
    /// How many were tied to media: the quoted payload was RTP or RTCP, or the
    /// flow matched a tracked stream, or both. The rest are ordinary network
    /// failures about something else and are not claimed as audio problems.
    pub media: u64,
    /// How many were tied to a tracked stream or SDP-advertised endpoint.
    pub attributed: u64,
    /// How many matched nothing this capture holds. The evidence is real; only
    /// the stream is unknown.
    ///
    /// `attributed + unattributed == errors`, always.
    pub unattributed: u64,
    /// Errors whose quote stopped before the transport header, so they carry
    /// no flow to match at all. A subset of `unattributed`.
    pub unkeyed: u64,
    /// Errors whose flow was never tracked because the flow cap was full. A
    /// subset of `unattributed`.
    pub untracked_flows: u64,
    /// Errors whose endpoint was not tallied because the endpoint cap was
    /// full. These are missing from `endpoints`.
    pub untallied_endpoints: u64,
    /// One finding per retained flow, busiest first.
    pub flows: Vec<MediaIcmpFinding>,
    /// Endpoints ICMP named unreachable, busiest first.
    pub endpoints: Vec<UnreachableEndpoint>,
}

/// What ICMP reported about this run's media, resolved against the streams
/// sipnab tracked.
///
/// The second half of the split described at the top of this section: quotes
/// are filed by flow as they are parsed, and tied to streams here, once, at
/// the end of a run when the store is complete. Calling it earlier is not
/// wrong, only less informative — a flow whose stream has not been seen yet
/// reports as unattributed.
///
/// # Arguments
///
/// * `streams` — the run's stream store. An empty one is valid and yields a
///   report in which everything is unattributed, which is the honest answer
///   for a capture that holds no media.
///
/// # Returns
///
/// An [`IcmpMediaReport`] with exact totals, one finding per retained flow and
/// every unreachable endpoint, both busiest first.
pub fn icmp_media_report(streams: &StreamStore) -> IcmpMediaReport {
    let guard = MEDIA_ICMP.lock();
    let Some(store) = guard.as_ref() else {
        return IcmpMediaReport::default();
    };

    let mut flows: Vec<MediaIcmpFinding> = Vec::with_capacity(store.by_flow.len());
    let mut attributed = 0u64;
    let mut media = 0u64;

    for (flow, evidence) in &store.by_flow {
        // The most recent sample describes the flow's current state; the count
        // beside it is every error, retained or not.
        let Some(last) = evidence.samples.last() else {
            continue;
        };
        // Read the payload across every retained sample, not only the last.
        // Routers on one path do not all quote the same number of bytes, and
        // one quote that reached the RTP header is enough to know what the
        // flow carries — taking only the newest would throw that away because
        // a later router was stingier.
        let payload = evidence
            .samples
            .iter()
            .rev()
            .map(|s| s.payload)
            .find(|p| p.is_media())
            .unwrap_or(last.payload);

        let attribution = streams.attribute_media_quote(flow.src, flow.dst, payload.ssrc());
        // Every error on the flow is credited, not one: the match is a
        // property of the flow, and each error on it is about the same media.
        if attribution.matched != MediaMatch::None {
            attributed += evidence.errors;
        }
        // Either proof will do: a recognizable RTP header, or a match onto
        // media sipnab watched. A quote can have one without the other.
        if payload.is_media() || attribution.matched != MediaMatch::None {
            media += evidence.errors;
        }

        let hint = media_hint(flow, last, payload, evidence.errors, &attribution);
        flows.push(MediaIcmpFinding {
            source: flow.src.to_string(),
            unreachable_endpoint: flow.dst.to_string(),
            reported_by: last.reported_by.to_string(),
            transport: flow.transport.as_str(),
            description: last.description.to_string(),
            icmp_type: last.icmp_type,
            icmp_code: last.icmp_code,
            errors: evidence.errors,
            payload,
            matched: attribution.matched,
            streams: attribution.streams,
            call_ids: attribution.call_ids,
            hint,
        });
    }

    // Busiest first; ties by endpoint then source so the report is
    // deterministic across runs of a hash map.
    flows.sort_unstable_by(|a, b| {
        b.errors
            .cmp(&a.errors)
            .then(a.unreachable_endpoint.cmp(&b.unreachable_endpoint))
            .then(a.source.cmp(&b.source))
    });

    let mut endpoints: Vec<UnreachableEndpoint> = store.endpoints.values().cloned().collect();
    endpoints.sort_unstable_by(|a, b| {
        b.errors
            .cmp(&a.errors)
            .then(a.addr.cmp(&b.addr))
            .then(a.port.cmp(&b.port))
    });

    IcmpMediaReport {
        errors: store.errors,
        media,
        attributed,
        unattributed: store.errors.saturating_sub(attributed),
        unkeyed: store.unkeyed,
        untracked_flows: store.untracked_flows,
        untallied_endpoints: store.untallied_endpoints,
        flows,
        endpoints,
    }
}

// ── Getting media findings to machine-readable surfaces ──────────────
//
// [`icmp_media_report`] answers the question once, on stderr, at the end of a
// run. That left every structured surface — `--report`, `--json-dialogs`, the
// REST dialog document, MCP — unable to see a single one of these findings,
// which is the same "evidence that reaches no consumer" defect the media
// reader itself was written to remove, one layer up.
//
// Two facts decide the shape of what follows.
//
// **A media flow is not a dialog.** Most of these findings name no call at
// all: on one real corpus, 205 of 514 errors matched nothing this capture
// holds, and one more quoted too little to be keyed on a flow. A per-dialog
// surface is therefore the WRONG home for the collection — hanging the set off
// dialogs would silently drop every finding that has no dialog to hang from,
// and "silently drops the majority" is how this feature got filed in the first
// place. So the ledger is capture-wide (rendered by
// [`crate::output::dialog_report`] as its own section), and a dialog carries
// only the findings whose attribution NAMED that dialog, as a convenience view
// onto the same objects. A reader of one call still sees the capture-wide
// counters beside them, so "there is evidence here you are not looking at" is
// never invisible.
//
// **The tier is part of the finding, not decoration.** Flow (the quoted
// directed 5-tuple is exactly a tracked stream), Ssrc (read out of the quoted
// RTP/RTCP header), Endpoint, SdpEndpoint and None are five different
// strengths of claim, and a consumer that cannot tell them apart will present
// a None-tier guess with the confidence of an exact 5-tuple match. That is
// worse than omitting the finding, so every serialized finding carries
// [`MediaIcmpFinding::attribution_tier`] and no surface may emit one without
// it.
//
// The caching below exists because attribution is the one part of a finding
// that cannot be derived from the finding: the tier is a statement about the
// run's `StreamStore`, and the per-dialog and per-report renderers are handed a
// dialog's streams, never the store. Resolving once, where the store is whole,
// is also what keeps stderr, `--report` and the JSON from disagreeing about the
// same capture.

impl MediaIcmpFinding {
    /// The attribution tier, as a stable machine-readable token.
    ///
    /// The five tiers are not equally strong claims — see
    /// [`crate::rtp::stream_store::StreamStore::attribute_media_quote`] for
    /// what each one proves. Rendered from one place so no two surfaces can
    /// spell the same tier differently, and so a consumer can branch on it.
    ///
    /// # Examples
    ///
    /// ```
    /// use sipnab::pipeline::icmp_media_report;
    /// use sipnab::rtp::stream_store::StreamStore;
    ///
    /// // An empty run has no findings, so there is no tier to read.
    /// let report = icmp_media_report(&StreamStore::new(1));
    /// assert!(report.flows.is_empty());
    /// ```
    #[must_use]
    pub const fn attribution_tier(&self) -> &'static str {
        match self.matched {
            MediaMatch::Flow => "flow",
            MediaMatch::Ssrc => "ssrc",
            MediaMatch::Endpoint => "endpoint",
            MediaMatch::SdpEndpoint => "sdp_endpoint",
            MediaMatch::None => "none",
        }
    }

    /// What the quoted payload turned out to be, as a stable token.
    ///
    /// Separate from the tier because they answer different questions: this is
    /// what the router quoted, the tier is what sipnab could tie it to. A quote
    /// can be unmistakably RTP and match nothing (`rtp` + `none`), or match a
    /// stream exactly with no payload left to read (`unread` + `flow`).
    #[must_use]
    pub const fn payload_kind(&self) -> &'static str {
        match self.payload {
            QuotedMediaKind::Rtp { .. } => "rtp",
            QuotedMediaKind::Rtcp { .. } => "rtcp",
            QuotedMediaKind::Unread => "unread",
            QuotedMediaKind::NotMedia => "not_media",
        }
    }
}

/// The run's media findings, resolved once and indexed by `Call-ID`.
///
/// Built by [`resolve_icmp_media`] and read by [`icmp_media_findings`]. The
/// index is built once rather than scanned per dialog because the post-capture
/// surfaces walk every dialog in the store: a linear scan per dialog would be
/// O(dialogs × flows) for an answer that does not vary between dialogs.
#[derive(Debug, Clone, Default)]
pub struct ResolvedIcmpMedia {
    /// The capture-wide report, exactly as [`icmp_media_report`] built it.
    report: IcmpMediaReport,
    /// `Call-ID` → indices into `report.flows`.
    by_call_id: std::collections::HashMap<String, Vec<usize>>,
}

impl ResolvedIcmpMedia {
    /// Index a report by the `Call-ID`s its findings named.
    ///
    /// Public so a caller holding a report from [`icmp_media_report`] can index
    /// it without going through the process-global set — which is what lets the
    /// surfaces be tested against a known set of findings rather than against
    /// whatever the last capture left behind.
    #[must_use]
    pub fn new(report: IcmpMediaReport) -> Self {
        let mut by_call_id: std::collections::HashMap<String, Vec<usize>> =
            std::collections::HashMap::new();
        for (i, finding) in report.flows.iter().enumerate() {
            for call_id in &finding.call_ids {
                by_call_id.entry(call_id.clone()).or_default().push(i);
            }
        }
        Self { report, by_call_id }
    }

    /// The capture-wide report: every finding, with the totals that stay exact
    /// past the caps.
    #[must_use]
    pub fn report(&self) -> &IcmpMediaReport {
        &self.report
    }

    /// The findings whose attribution named this dialog, busiest first.
    ///
    /// Empty for almost every dialog, and empty for EVERY dialog when the
    /// attribution reached no tier that names a call — which is why the
    /// capture-wide [`report`](Self::report) is the ledger and this is a view
    /// onto it.
    #[must_use]
    pub fn findings_for(&self, call_id: &str) -> Vec<&MediaIcmpFinding> {
        self.by_call_id
            .get(call_id)
            .map(|idx| {
                idx.iter()
                    .filter_map(|&i| self.report.flows.get(i))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Set while a test has published a KNOWN resolved set and is asserting on it.
///
/// [`resolve_icmp_media`] publishes unconditionally, and `select_dialogs`
/// calls it on the way to every post-capture surface -- so any other test
/// rendering any surface replaces the set this one is in the middle of
/// reading. The two tests need not be related in any way: sharing a process
/// and a global is the whole of it. While this is set the resolver still
/// ANSWERS its caller with the honest resolution of the store it was handed;
/// it just does not publish, so the published set stays the one the test put
/// there. Cleared by [`reset_icmp_evidence`], which every such test calls.
#[cfg(test)]
static MEDIA_ICMP_PINNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Resolved media findings for the current run, or an empty set.
static MEDIA_ICMP_RESOLVED: parking_lot::Mutex<Option<std::sync::Arc<ResolvedIcmpMedia>>> =
    parking_lot::Mutex::new(None);

/// Set once [`resolve_icmp_media`] has run, so the per-dialog lookup on a
/// capture with no media ICMP — the common case — costs one relaxed load and
/// no lock.
static MEDIA_ICMP_RESOLVED_SEEN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The empty answer, shared so a dialog-by-dialog walk allocates nothing.
static NO_ICMP_MEDIA: std::sync::OnceLock<std::sync::Arc<ResolvedIcmpMedia>> =
    std::sync::OnceLock::new();

/// Resolve this run's media ICMP evidence against `streams` and publish it.
///
/// The single point at which a media quote acquires an attribution tier. Call
/// it once per run, from the one place holding the complete stream store; every
/// structured surface then reads the same answer through
/// [`icmp_media_findings`] instead of re-deriving it from the dialog-shaped
/// fragment it happens to have been handed.
///
/// # Arguments
///
/// * `streams` — the run's stream store, merged when the run was parallel. An
///   empty one is valid and resolves every finding to the `none` tier, which is
///   the honest answer for a capture holding no media.
///
/// # Returns
///
/// The resolved findings, indexed by `Call-ID`.
///
/// # Side effects
///
/// Replaces the process-global resolved set. Calling it again with a more
/// complete store re-resolves — the store only grows, so a later answer is
/// never weaker.
pub fn resolve_icmp_media(streams: &StreamStore) -> std::sync::Arc<ResolvedIcmpMedia> {
    let resolved = std::sync::Arc::new(ResolvedIcmpMedia::new(icmp_media_report(streams)));
    // Answer, but do not publish, while a test owns the published set. See
    // `MEDIA_ICMP_PINNED`: without this a surface test asserting on findings it
    // published loses them to any concurrent test that renders any surface.
    #[cfg(test)]
    if MEDIA_ICMP_PINNED.load(std::sync::atomic::Ordering::Acquire) {
        return resolved;
    }
    *MEDIA_ICMP_RESOLVED.lock() = Some(std::sync::Arc::clone(&resolved));
    MEDIA_ICMP_RESOLVED_SEEN.store(true, std::sync::atomic::Ordering::Release);
    resolved
}

/// This run's resolved media findings, or an empty set.
///
/// Empty is returned when nothing has resolved yet, NOT a set of findings with
/// their tiers guessed at: a finding without its tier is exactly the misleading
/// output this whole path exists to prevent, so an unresolved run reports
/// nothing rather than reporting badly.
#[must_use]
pub fn icmp_media_findings() -> std::sync::Arc<ResolvedIcmpMedia> {
    if !MEDIA_ICMP_RESOLVED_SEEN.load(std::sync::atomic::Ordering::Acquire) {
        return std::sync::Arc::clone(NO_ICMP_MEDIA.get_or_init(Default::default));
    }
    MEDIA_ICMP_RESOLVED
        .lock()
        .as_ref()
        .map(std::sync::Arc::clone)
        .unwrap_or_else(|| std::sync::Arc::clone(NO_ICMP_MEDIA.get_or_init(Default::default)))
}

/// Publish a known set of findings as this run's resolved evidence.
///
/// Test-only. The surfaces read the process-global set, so proving that a
/// finding reaches a surface means putting a KNOWN finding there — building one
/// through a capture would tie every surface test to whatever a fixture's
/// routers happened to quote, and could not produce a `sdp_endpoint` or an
/// `endpoint` tier on demand at all.
#[cfg(test)]
pub fn publish_icmp_media_for_test(resolved: ResolvedIcmpMedia) {
    *MEDIA_ICMP_RESOLVED.lock() = Some(std::sync::Arc::new(resolved));
    MEDIA_ICMP_RESOLVED_SEEN.store(true, std::sync::atomic::Ordering::Release);
    MEDIA_ICMP_PINNED.store(true, std::sync::atomic::Ordering::Release);
}

/// Render one media finding in plain language.
///
/// Kept next to the report rather than in each surface for the reason
/// [`crate::output::call_report`] states about the signaling hints: one
/// renderer means two surfaces cannot disagree about what a failure meant.
fn media_hint(
    flow: &QuotedFlow,
    last: &MediaIcmpEvidence,
    payload: QuotedMediaKind,
    errors: u64,
    attribution: &MediaAttribution,
) -> String {
    let occurrences = if errors == 1 {
        String::new()
    } else {
        format!(" ({errors} times)")
    };
    let what = match payload {
        QuotedMediaKind::Rtp { payload_type, .. } => {
            format!("RTP (payload type {payload_type})")
        }
        QuotedMediaKind::Rtcp { packet_type, .. } => format!("RTCP (type {packet_type})"),
        QuotedMediaKind::Unread | QuotedMediaKind::NotMedia => {
            format!("a {} datagram", flow.transport.as_str())
        }
    };
    let placed = match attribution.matched {
        MediaMatch::Flow => "This is one of the media streams in this capture".to_string(),
        MediaMatch::Ssrc => {
            "The SSRC in the quote belongs to a media stream in this capture".to_string()
        }
        MediaMatch::Endpoint => {
            "That socket carries one of the media streams in this capture".to_string()
        }
        MediaMatch::SdpEndpoint => {
            "That socket was negotiated in SDP for a call in this capture".to_string()
        }
        MediaMatch::None => "It matched no stream in this capture, so the evidence is \
                             reported without a call — the endpoint is real either way"
            .to_string(),
    };
    let calls = if attribution.call_ids.is_empty() {
        String::new()
    } else {
        format!(" ({} call(s) affected)", attribution.call_ids.len())
    };
    let audio = if attribution.matched == MediaMatch::None && !payload.is_media() {
        String::new()
    } else {
        " Audio sent that way is discarded before it arrives, which is heard as one-way or \
         missing audio."
            .to_string()
    };
    format!(
        "ICMP {}: {what} from {} to {} could not be delivered{occurrences}, reported by {}. \
         {placed}{calls}.{audio} {}",
        last.description,
        flow.src,
        flow.dst,
        last.reported_by,
        crate::sip::diagnosis::icmp_remedy(
            last.icmp_type,
            last.icmp_code,
            last.reported_by.is_ipv6()
        ),
    )
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

/// Apply media-relay-asserted SDP links to the stream store.
///
/// The relay half of what the `Sip` arm does inline, factored out because it
/// has to happen identically on all FOUR packet appliers — the live router,
/// the `--cores` shard, the batch path and the TUI's file-open — and this
/// codebase's most-named defect is a change that reached some of them and not
/// the others. One definition means the drift is not available to be made.
///
/// The provenance is [`rtp::stream_store::SdpProvenance::relay_asserted`] and
/// not `observed`: this endpoint is rtpengine describing a port it allocated
/// itself, which is authoritative about the socket and says nothing about
/// either party's own address (RE3).
pub fn apply_relay_control_links(
    ss: &mut rtp::stream_store::StreamStore,
    sdp_links: &[(std::net::IpAddr, u16, String, sip::sdp::SdpMedia)],
    input_origin: crate::capture::parse::InputOrigin,
    timestamp: chrono::DateTime<chrono::Utc>,
) {
    let provenance = rtp::stream_store::SdpProvenance::relay_asserted(input_origin, timestamp);
    for (ip, port, call_id, media) in sdp_links {
        ss.link_to_dialog_with_sdp_from(*ip, *port, call_id, media, provenance);
    }
}

/// Register a relay's startup snapshot as media endpoints on one store.
///
/// The counterpart to [`apply_relay_control_links`] for the half of RE4 that
/// ASKS rather than watches, and factored out for the same reason: each worker
/// builds its own [`rtp::stream_store::StreamStore`], and a snapshot that
/// reached some of them and not the others is the drift one definition makes
/// unavailable.
///
/// Registering rather than linking is what keeps the packet path free of
/// network calls. `link_endpoint_from` remembers the endpoint, so a stream
/// that appears AFTER the snapshot -- which is every stream, since the
/// snapshot is taken before the capture opens -- is attributed at creation
/// from memory.
///
/// The rtpmap is empty and the ptime absent because the relay reported neither.
/// A `query` reply names a codec but no payload type, and an rtpmap entry needs
/// both; synthesizing one would put a number sipnab was never told into a field
/// an operator reads as measured.
pub fn apply_relay_snapshot(
    ss: &mut rtp::stream_store::StreamStore,
    snapshot: &crate::relay::reconcile::RelaySnapshot,
) {
    let Some(taken_at) = snapshot.taken_at else {
        // Never asked. Not an empty relay -- see `Unattributed`.
        return;
    };
    let provenance = rtp::stream_store::SdpProvenance::relay_queried(taken_at);
    for link in &snapshot.links {
        ss.link_endpoint_from(
            link.address,
            link.port,
            &link.call_id,
            &[],
            None,
            provenance,
        );
    }
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

/// Try to unwrap a WebSocket frame from a TCP packet on a configured WS port.
///
/// Returns `Some(payload)` if the packet is TCP, the data contains a valid
/// WebSocket data frame wrapping SIP content, and the destination or source
/// port is in the WebSocket port set (`--ws-portrange` / `[capture] ws_ports`,
/// else 80, 443, 8080, 8443).
///
/// # Side effects
///
/// A frame that unwraps to real SIP on a port OUTSIDE the set is tallied by
/// `record_ws_port_skip` before `None` is returned, so
/// [`ws_port_skip_report`] can name what the set discarded. The port test
/// deliberately runs LAST: it decides whether recognized SIP is analyzed or
/// counted, and running it first is what made the loss invisible.
pub fn try_websocket_unwrap(pp: &ParsedPacket) -> Option<Vec<u8>> {
    if pp.transport != TransportProto::Tcp {
        return None;
    }

    // Two bytes, no allocation, and it rejects almost every TCP payload that
    // is not a WebSocket data frame — which is what makes running the unwrap
    // on every port affordable at all.
    if !websocket::is_websocket_frame(&pp.payload) {
        return None;
    }

    let payload = match websocket::unwrap_websocket_frame(&pp.payload) {
        // `starts_sip_message`, for the same reason `classify_packet` uses it:
        // the narrower `sip::is_sip_message` would refuse to unwrap a frame
        // carrying an extension-method request, and SIP-over-WebSocket
        // (RFC 7118) is exactly where private methods turn up.
        Ok(Some(payload)) if sip::parser::starts_sip_message(&payload) => payload,
        _ => return None,
    };

    if !websocket::is_ws_port(pp.dst_port) && !websocket::is_ws_port(pp.src_port) {
        record_ws_port_skip(pp.src_port, pp.dst_port, &payload);
        return None;
    }

    Some(payload)
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
    /// packets that fail to parse (`--quiet-bad-parse`). The
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
/// classifying one packet without touching either DIALOG STORE. Each router
/// applies it with its own store access: the live path takes brief per-store
/// write locks (`process_packet`); the offline `--cores` and batch paths call
/// plain `&mut` stores directly. Separating the (duplicated) classification
/// from the (legitimately different) application is the core of the pipeline
/// unification (WS1).
// `Sip` dominates: the enum is 288 bytes and every returned `PacketAction`
// pays it, including the `None` that most packets on a media-heavy link
// produce. Boxing `msg` would shrink it to a Vec plus a discriminant at the
// cost of one allocation per SIP message, which is plausibly the better trade
// and is tracked separately.
//
// Not done here because it is a hot-path change across 24 destructuring sites
// and the case for it rests on a packet mix nobody has measured. Adding the
// frame pointer to `SipMessage` pushed this past clippy's threshold; it did
// not create the imbalance, which predates it. Silencing with a reason beats
// either an unmeasured rewrite or a lint that everyone learns to ignore.
#[allow(clippy::large_enum_variant)]
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
    /// SDP media endpoints a MEDIA RELAY asserted about its own allocation,
    /// decoded from rtpengine's `ng` control plane.
    ///
    /// Deliberately not `Sip`. No SIP message was observed, and synthesizing
    /// one to reuse that variant would put signaling into the dialog store
    /// that nobody sent — in a tool whose whole value is saying what it
    /// actually saw. The links carry the same tuple shape as `Sip::sdp_links`
    /// so the appliers can share their linking code, but they are applied with
    /// relay provenance (`SdpProvenance::relay_asserted`) rather than the
    /// signaled provenance an SDP body on the wire would get.
    RelayControl {
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

/// Classify one parsed packet into a `PacketAction` — the store-free core of
/// the per-packet pipeline. WebSocket unwrap, SIP parse + SDP-link extraction,
/// DTLS/SRTP key learning, RTCP parse, and RTP (header or heuristic) detection
/// all happen here, touching neither the dialog store nor the stream store.
/// `decrypt` is mutated in place to learn SDES/DTLS keys and to decrypt SRTP
/// payloads; `rtp_heuristic` is advanced for RTP discovery. The caller applies
/// the returned action to its stores.
///
/// NOT lock-free, and this doc said it was until 0.5.122. Three process-global
/// side-tallies are written from here when they have something to record: the
/// `--portrange` skip counter, the LLMNR store, and the STUN tracker. Each
/// takes a mutex, and each is conditional -- a packet that is neither skipped
/// nor LLMNR nor STUN takes none of them.
///
/// The distinction matters under `--cores`. Those tallies are process-global,
/// not per-worker, so on a capture that trips one of them often, every worker
/// contends on one mutex. "Lock-free" read as a promise that adding workers
/// adds no shared state, and that is not what this function does.
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
            Ok(mut sip_msg) => {
                // Carry the frame pointer across the SIP parse boundary. The
                // parser takes bytes and addressing, deliberately — it has no
                // business knowing about captures — so the packet's provenance
                // is attached here, at the one place that holds both the
                // `ParsedPacket` and the message it produced.
                //
                // Cloning an `Option<FrameRef>` is a refcount bump on an
                // `Arc<str>` already interned once per source, plus two words.
                // Paid per SIP message rather than per packet, which on real
                // traffic is a small fraction of the frames.
                // Materialize the owned pointer HERE, where the message keeps
                // it. The parser carries a Copy locator precisely so the ~93%
                // of frames that never reach a retention site pay no refcount.
                sip_msg.frame = pp.retained_frame_ref();
                // The QoS marking rides across the same boundary and for the
                // same reason: it is a fact about the packet, the parser never
                // sees a packet, and every consumer downstream sees only the
                // message. A `Copy` byte, so this costs nothing.
                sip_msg.dscp = pp.dscp;
                // Which source delivered it, across the same boundary and for
                // the same reason. In a mixed run this is the only thing that
                // makes a HEP-reported fact distinguishable from a
                // wire-observed one, and their DISAGREEMENT is the finding the
                // next item compares for (SRC1 stage 2). Per message, never
                // per run: a composite run has no run-level answer.
                sip_msg.input_origin = Some(pp.input_origin);
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

    // LLMNR, claimed on sight and BEFORE any media check.
    //
    // LLMNR is NOT a VoIP protocol and sipnab is NOT a general dissector. It is
    // claimed here for one reason: a Windows name lookup is a DNS-format
    // message whose first two bytes are a random transaction ID, and one ID in
    // four carries `0b10` in the top two bits — the RTP version. The rest of
    // the strict RTP pre-filter (12+ bytes, a payload type outside the RTCP
    // range) a 23-byte query passes trivially. That is not hypothetical: two
    // such queries became two phantom RTP streams, SSRC 0x00000000, two packets
    // each, in a real capture. The same collision is documented below for DNS
    // from port 53, and that guard only covers ports under 1024 — LLMNR sits at
    // 5355. Claiming the packet here removes the whole class by construction
    // rather than by tuning a heuristic.
    //
    // Ahead of the `no_rtp` guard on purpose, so `--no-rtp` (which opts out of
    // MEDIA analysis) does not also empty the host roster below.
    //
    // The CONTENTS are kept for a reason unrelated to any call: a query names a
    // machine looking for a hostname and a response names the machine that owns
    // one, so the messages are the segment's host roster — and LLMNR being
    // enabled at all is the exposure the Responder tool abuses to harvest NTLM
    // credentials. It feeds nothing in the media path or in call diagnosis, and
    // it must never start to.
    if pp.transport == TransportProto::Udp
        && crate::llmnr::is_llmnr_packet(&pp.payload, pp.src_port, pp.dst_port)
    {
        match crate::llmnr::parser::parse_llmnr(&pp.payload) {
            Ok(msg) => crate::llmnr::store::record_llmnr(&msg, pp.src_addr, pp.timestamp),
            Err(e) => {
                if !opts.quiet_bad_parse {
                    tracing::debug!("LLMNR parse error: {e}");
                }
            }
        }
        // Consumed either way: a datagram on the LLMNR port whose header passed
        // the structural checks is LLMNR, and a later parse failure makes it
        // MALFORMED LLMNR, not media.
        return PacketAction::None;
    }

    // rtpengine's `ng` control plane, mirrored over HEP and observed HERE
    // rather than delivered to our own listener (RE6).
    //
    // On a standalone media relay this is the only thing that names a call.
    // Without it every stream on the box is an orphan: the relay carries no
    // SIP, so a capture there is media with nothing to attribute it to.
    //
    // Claimed off the wire on purpose. rtpengine takes exactly ONE Homer
    // destination — `--homer` is a single string, not a repeatable option —
    // so pointing it at sipnab would TAKE IT AWAY from the collector it is
    // already feeding. Reading the copy it already sends needs no
    // configuration change anywhere and leaves that pipeline untouched.
    //
    // Scoped to `ng` and nothing else. HEP carrying SIP or RTP is left to fall
    // through exactly as before, because claiming those here would change what
    // every existing capture containing HEP reports, which is a much larger
    // decision than this requirement asked for.
    //
    // Ahead of the RTP pre-filter for the same reason LLMNR is: whatever else
    // happens, these bytes must not be read as media.
    //
    // TWO arms, because there are two ways `ng` reaches sipnab and they arrive
    // in different shapes.
    //
    // This first arm is the DELIVERED one: `--hep-listen`, where sipnab is the
    // collector rtpengine exports to. The listener strips the wrapper before
    // the parser runs, so the payload here is the bare `ng` body and there is
    // no HEP header left for the second arm to find. What the wrapper said
    // travels in `pp.hep` instead — and the correlation id it carries is the
    // ONLY thing naming the call on a reply, whose body has no `call-id` at
    // all.
    //
    // This arm decoded nothing at all before 0.5.125 while the documentation
    // offered the method, and the cost of that landed on the operator rather
    // than here: rtpengine takes exactly one `--homer` destination, so anybody
    // following the page gave up their Homer collector and received no relay
    // visibility in exchange.
    #[cfg(feature = "hep")]
    if pp.transport == TransportProto::Udp
        && let Some(hep) = &pp.hep
        && crate::rtpengine::is_ng_over_hep(hep.protocol, &pp.payload)
    {
        let sdp_links =
            crate::rtpengine::sdp_links_from_ng(&pp.payload, hep.correlation_id.as_deref());
        return PacketAction::RelayControl { sdp_links };
    }

    // The second arm is the SNIFFED one: a HEP datagram read off the wire,
    // wrapper intact, on its way to somebody else's collector.
    //
    // GATED, unlike the delivered arm above. The delivered arm reaches a
    // socket an operator bound and can put behind `--hep-allow` and
    // `--hep-auth`; this one reads whatever is on the segment. Nothing
    // authenticates it, the Call-ID comes verbatim out of the correlation-id
    // chunk, and the media address comes out of the SDP — so an unbounded
    // version of this arm let anything that could transmit here name a call
    // and bind media wherever it liked. `sniffed_ng_sdp_links` holds the
    // gate, and `docs/rtpengine.md` says plainly what a sniffed assertion is
    // and is not worth.
    #[cfg(feature = "hep")]
    if pp.transport == TransportProto::Udp
        && let Some(sdp_links) = crate::rtpengine::sniffed_ng_sdp_links(pp.dst_port, &pp.payload)
    {
        // Consumed either way. A datagram that parsed as HEP and decoded as
        // `ng` is control traffic; that it named no endpoint this time (a
        // `delete`, a `ping`, a reply to one, or a refusal by the port gate)
        // is not a reason to reconsider it as media.
        return PacketAction::RelayControl { sdp_links };
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

    // TURN ChannelData: the media is four bytes in, behind a channel number
    // and a length. Unwrap and classify what is inside, or a call whose audio
    // went through a relay reports as a call with NO MEDIA — the same finding
    // sipnab gives for a call that genuinely carried nothing, which are
    // opposite conclusions rendered identically (backlog NAT4).
    //
    // Recursion terminates because the inner payload is strictly shorter than
    // the wrapper that carried it.
    if let Some(inner) = crate::stun::channel_data_payload(&pp.payload) {
        // Recorded before the recursion, and only against an allocation that
        // was actually granted: relayed media IS the traffic that kept flowing
        // past an allocation's expiry, and an activity clock that only ever
        // advanced on signaling could never show a relay torn down mid-call
        // (see `TurnAllocation::expired_before_last_activity`). The call is
        // guarded by a relaxed atomic inside, so a capture that never touched
        // a relay pays a load and no lock.
        // The WHOLE frame, not the unwrapped payload: the channel number is in
        // the header and the SSRC is inside the payload, and those two
        // together are what attribute the stream this recursion is about to
        // create back to the allocation that carried it.
        crate::stun::note_channel_data(
            std::net::SocketAddr::new(pp.src_addr, pp.src_port),
            std::net::SocketAddr::new(pp.dst_addr, pp.dst_port),
            &pp.payload,
            pp.timestamp,
        );
        let mut unwrapped = pp.clone();
        unwrapped.payload = bytes::Bytes::copy_from_slice(inner);
        return classify_packet(&unwrapped, rtp_heuristic, opts, decrypt);
    }

    // STUN: the endpoint asking the network who it is. Checked BEFORE RTP/RTCP
    // because ICE multiplexes STUN and media on one port, and `stun::parse`
    // rejects RTP outright (RTP's version bits are 0b10; STUN's top two bits
    // are always zero), so this cannot swallow media.
    //
    // Consumed and stopped: a STUN message is not SIP and not media, and
    // letting it fall through made a capture of nothing but failed NAT
    // discovery report as "no SIP traffic found".
    if let Some(stun_msg) = crate::stun::parse(&pp.payload) {
        crate::stun::note_message(
            &stun_msg,
            std::net::SocketAddr::new(pp.src_addr, pp.src_port),
            std::net::SocketAddr::new(pp.dst_addr, pp.dst_port),
            pp.timestamp,
        );
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
    relay_orphans: Option<&crate::relay::reconcile::OrphanSink>,
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
                // The endpoint remembers WHICH source advertised it and WHEN,
                // because both decide what a stream created later may claim
                // from it: a binding across sources is a weaker tie and must
                // say so, and an offer stale enough to belong to a previous
                // call on the same socket must claim nothing (F3).
                let provenance = crate::rtp::stream_store::SdpProvenance::observed(
                    pp.input_origin,
                    pp.timestamp,
                );
                for (ip, port, call_id, media) in &sdp_links {
                    ss.link_to_dialog_with_sdp_from(*ip, *port, call_id, media, provenance);
                }
            }
        }
        PacketAction::RelayControl { sdp_links } => {
            // Same gate the SIP arm uses: `--no-dialog` opts out of call
            // association, and a relay-derived association is still one.
            if opts.no_dialog {
                return;
            }
            if !sdp_links.is_empty() {
                apply_relay_control_links(
                    &mut stream_store.write(),
                    &sdp_links,
                    pp.input_origin,
                    pp.timestamp,
                );
            }
        }
        PacketAction::Rtcp(rtcp_packets) => {
            stream_store
                .write()
                .process_rtcp(&rtcp_packets, pp.timestamp);
        }
        PacketAction::Rtp {
            hdr,
            decrypted_payload,
            via_heuristic: _,
        } => {
            let mut ss = stream_store.write();
            match decrypted_payload {
                Some(payload) => {
                    let mut d = pp.clone();
                    d.payload = payload;
                    ss.process_rtp(&d, &hdr, d.timestamp);
                }
                None => {
                    ss.process_rtp(pp, &hdr, pp.timestamp);
                }
            }
            // RE4's second trigger. Drained under the write lock this branch
            // already holds -- a second acquisition per packet would be a
            // contention cost paid on every RTP packet to serve a feature
            // almost no run enables.
            let orphans = if relay_orphans.is_some() {
                ss.drain_new_orphan_sockets()
            } else {
                Vec::new()
            };
            // Released BEFORE offering. The reconciler takes this same lock to
            // apply what it learns, and the capture path must not be the one
            // holding it while handing work to the thread that wants it.
            drop(ss);
            if let Some(sink) = relay_orphans {
                for (address, port) in orphans {
                    sink.offer(address, port);
                }
            }
        }
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
            frame_bytes: None,
            frame: None,
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
            dscp: None,
            input_origin: crate::capture::parse::InputOrigin::Wire,
            hep: None,
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

    /// A Windows LLMNR query must never be classified as media.
    ///
    /// This is the whole reason sipnab decodes a protocol that has nothing to
    /// do with VoIP. The query's first two bytes are a random transaction ID,
    /// and `0x80` is also the RTP version-2 bit pattern; the rest of the strict
    /// RTP pre-filter a 23-byte query passes trivially. Two such queries became
    /// two phantom RTP streams, SSRC `0x00000000`, in a real capture. The DNS
    /// guard elsewhere in this file only covers ports below 1024, and LLMNR
    /// sits at 5355.
    ///
    /// Asserts the classifier's ACTION rather than the parser's opinion: a
    /// correct `is_llmnr_packet` proves nothing if the branch runs after the
    /// media checks.
    #[test]
    #[serial_test::serial(llmnr_store)]
    fn an_llmnr_query_is_claimed_before_any_media_check() {
        crate::llmnr::store::reset_llmnr();
        // The byte-exact query from the capture that motivated the module,
        // transaction ID 0x8006 — the ID that collided with the RTP version.
        let query: &[u8] = &[
            0x80, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, b'G',
            b'H', b'S', b'0', b'8', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        assert_eq!(query[0] >> 6, 2, "the ID really does carry RTP's version");

        let mut pp = packet(query);
        pp.src_port = 55000;
        pp.dst_port = 5355;
        let action = classify(&pp, &PipelineOptions::default());
        assert!(
            matches!(action, PacketAction::None),
            "LLMNR must be consumed, not turned into a stream"
        );

        // And the contents are kept: the roster is the only reason to decode
        // anything past the port check.
        let report = crate::llmnr::store::llmnr_report();
        assert_eq!(report.packets, 1);
        assert!(
            report.hosts.iter().any(|h| h
                .names_queried
                .iter()
                .any(|n| n.eq_ignore_ascii_case("GHS08"))),
            "the queried name belongs in the roster: {report:?}"
        );
        crate::llmnr::store::reset_llmnr();
    }

    /// RTP relayed through TURN must reach reconstruction.
    ///
    /// The wrapper puts the media four bytes in. Without unwrapping, the
    /// classifier sees a payload whose first two bits are `01` — not RTP, not
    /// SIP, not STUN — and drops it, so a call whose audio went through a relay
    /// reports as having NO MEDIA. That is the same answer sipnab gives for a
    /// call that genuinely carried nothing, and they are opposite findings.
    ///
    /// Asserts the ACTION, not the unwrap helper: a test that only checked the
    /// bytes came back out would pass even with the pipeline still dropping
    /// them.
    #[test]
    fn rtp_relayed_through_turn_is_classified_as_media() {
        let mut rtp = vec![0x80, 0x00, 0x00, 0x01];
        rtp.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]); // timestamp
        rtp.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // ssrc
        rtp.extend_from_slice(&[0xaa; 160]); // G.711-sized payload

        // Bare RTP is the control: whatever the classifier does with it, the
        // wrapped form must do the same.
        let mut bare = packet(&rtp);
        bare.src_port = 40000;
        bare.dst_port = 40002;
        let opts = PipelineOptions::default();
        let bare_action = classify(&bare, &opts);

        let mut wrapped_bytes = vec![0x40, 0x01];
        wrapped_bytes.extend_from_slice(&(rtp.len() as u16).to_be_bytes());
        wrapped_bytes.extend_from_slice(&rtp);
        let mut wrapped = packet(&wrapped_bytes);
        wrapped.src_port = 40000;
        wrapped.dst_port = 40002;
        let wrapped_action = classify(&wrapped, &opts);

        assert_eq!(
            std::mem::discriminant(&bare_action),
            std::mem::discriminant(&wrapped_action),
            "relayed media must classify as the same thing as direct media"
        );
        assert!(
            !matches!(wrapped_action, PacketAction::None),
            "TURN-relayed RTP was dropped, so a relayed call reports as having no media"
        );
        assert!(
            !matches!(bare_action, PacketAction::None),
            "the control must itself be media, or this test proves nothing"
        );
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

    /// Real RTP on a dynamic port is still recognized from the payload alone.
    ///
    /// The guard must not cost the common case a single packet of latency:
    /// media on an ephemeral port is admitted immediately, without waiting for
    /// the three-packet heuristic to corroborate it.
    #[test]
    fn rtp_on_a_dynamic_port_is_still_recognized_immediately() {
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
            "media on a dynamic port must still be recognized from one packet"
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

/// Tests for reading a quoted non-SIP payload.
///
/// The rest of the media path needs a `StreamStore` and a parsed packet and
/// lives in `tests/icmp_media_test.rs`; this is the one piece that is a pure
/// function of bytes, and it is the piece where a loose check turns unrelated
/// traffic into a fabricated media diagnosis.
#[cfg(test)]
mod relay_control_tests {
    /// The ordering RE4 actually runs in: the snapshot is taken BEFORE the
    /// capture opens, so every stream is created after it. A snapshot that
    /// only linked streams already in the store would attribute nothing at
    /// all, and the whole point of RE4 -- naming a call that was already up
    /// when sipnab started -- would silently do nothing.
    #[test]
    fn a_snapshot_attributes_a_stream_created_afterwards() {
        use crate::capture::parse::{InputOrigin, ParsedPacket, TransportProto};
        use crate::relay::reconcile::{RelayLink, RelaySnapshot};
        use crate::rtp::parser::RtpHeader;
        use crate::rtp::stream_store::{EndpointAssertion, StreamStore};
        use std::net::{IpAddr, Ipv4Addr};

        let relay = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut store = StreamStore::new(1000);
        let ts = chrono::Utc::now();

        // The relay was asked first, and answered. No stream exists yet.
        super::apply_relay_snapshot(
            &mut store,
            &RelaySnapshot {
                links: vec![RelayLink {
                    address: relay,
                    port: 30000,
                    call_id: "already-in-progress".to_owned(),
                }],
                taken_at: Some(ts),
            },
        );
        assert_eq!(
            store.streams_for("already-in-progress").count(),
            0,
            "nothing has been captured yet"
        );

        // Then media for that call turns up.
        let parsed = ParsedPacket {
            frame_bytes: None,
            frame: None,
            timestamp: ts,
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: relay,
            src_port: 20000,
            dst_port: 30000,
            transport: TransportProto::Udp,
            payload: vec![0u8; 12 + 160].into(),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            dscp: None,
            input_origin: InputOrigin::Wire,
            hep: None,
        };
        let rtp = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 160,
            ssrc: 0xDEAD_BEEF,
            payload_offset: 12,
        };
        store.process_rtp(&parsed, &rtp, ts);

        let attributed: Vec<_> = store.streams_for("already-in-progress").collect();
        assert_eq!(
            attributed.len(),
            1,
            "the stream must be named by the snapshot taken before it existed"
        );
        assert_eq!(
            attributed[0].dialog_assertion,
            Some(EndpointAssertion::MediaRelay),
            "the relay asserted this, not a party's SDP"
        );
        assert_eq!(
            attributed[0].dialog_origin, None,
            "sipnab ASKED for this endpoint rather than capturing it, so there \
             is no capture source to record -- and a binding with no source \
             withholds the cross-source claim instead of inventing one"
        );
        assert!(
            !attributed[0].dialog_bound_across_sources(),
            "an absent origin must not read as a disagreement between sources"
        );
    }

    /// The relay assertion survives all the way to a reader.
    ///
    /// The test below proves the pipeline writes the right provenance onto the
    /// stream. That is not the same as anyone being able to SEE it, and for as
    /// long as this feature existed nobody could: `dialog_assertion` was
    /// written on every binding, and `EndpointAssertion::as_str` carried a doc
    /// comment describing itself as "the name this assertion is written under
    /// on every output surface" while no output surface wrote it and nothing
    /// outside tests ever called it. The whole point of asking an rtpengine
    /// relay what it is carrying is to be able to tell its claim about a port
    /// apart from a party's claim about its own address -- and the answer
    /// reached no operator, no agent and no HTTP client.
    ///
    /// Asserted through the SHARED renderer both APIs and the call report
    /// serialize through, so this covers `GET /v1/streams/{id}`, MCP
    /// `rtp_stats` and the `streams` array of a call report at once.
    ///
    /// Gated on the ITEM rather than the module, per the pre-push hook's own
    /// advice: `crate::output` is `native`-only, and gating the whole
    /// `relay_control_tests` module would take the three tests either side of
    /// this one out of every feature combination that does not build a
    /// renderer -- which is exactly where a store-level regression would be
    /// cheapest to catch.
    #[cfg(feature = "native")]
    #[test]
    fn a_relay_assertion_reaches_the_serialized_stream() {
        use crate::capture::ParsedPacket;
        use crate::capture::parse::{InputOrigin, TransportProto};
        use crate::rtp::parser::RtpHeader;
        use crate::rtp::stream_store::StreamStore;
        use std::net::{IpAddr, Ipv4Addr};

        let relay = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 40));
        let ts = chrono::Utc::now();

        // One RTP packet at the endpoint under test, built the way production
        // builds one. Registration alone creates no stream -- a stream is a
        // thing packets made -- so without this there is nothing to serialize.
        let media = |port: u16| ParsedPacket {
            frame_bytes: None,
            frame: None,
            timestamp: ts,
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: relay,
            src_port: 20000,
            dst_port: port,
            transport: TransportProto::Udp,
            payload: vec![0u8; 12 + 160].into(),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            dscp: None,
            input_origin: InputOrigin::Wire,
            hep: None,
        };
        let rtp = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 160,
            ssrc: 0xDEAD_BEEF,
            payload_offset: 12,
        };

        let rendered = |store: &StreamStore| -> serde_json::Value {
            let stream = store.iter().next().expect("the packet created a stream");
            serde_json::from_str(&crate::output::json::stream_to_json(stream))
                .expect("the renderer emits valid JSON")
        };

        // The relay's own `ng` control plane naming a port it allocated.
        let sdp = "v=0\r\nc=IN IP4 10.0.0.40\r\nm=audio 38664 RTP/AVP 0";
        let raw = format!("ck d3:sdp{}:{sdp}6:result2:oke", sdp.len());
        let links = crate::rtpengine::sdp_links_from_ng(raw.as_bytes(), Some("cid1"));
        assert_eq!(links.len(), 1, "fixture must yield exactly one endpoint");

        let mut relay_store = StreamStore::new(1000);
        super::apply_relay_control_links(&mut relay_store, &links, InputOrigin::Hep, ts);
        relay_store.process_rtp(&media(links[0].1), &rtp, ts);
        let relay_json = rendered(&relay_store);

        assert_eq!(
            relay_json["dialog_assertion"], "media-relay",
            "a reader must be able to tell the relay named this port: {relay_json}"
        );

        // The other arm, and the reason the first one means anything. If a
        // relay assertion and an ordinary signaled one rendered the same, the
        // key would be decoration -- present, stable, and carrying nothing.
        let mut signaled_store = StreamStore::new(1000);
        signaled_store.link_to_dialog_with_sdp_from(
            links[0].0,
            links[0].1,
            &links[0].2,
            &links[0].3,
            crate::rtp::stream_store::SdpProvenance::observed(InputOrigin::Wire, ts),
        );
        signaled_store.process_rtp(&media(links[0].1), &rtp, ts);
        let signaled_json = rendered(&signaled_store);

        assert_eq!(
            signaled_json["dialog_assertion"], "signaled",
            "a party's own SDP must not read as a relay's claim: {signaled_json}"
        );
        assert_ne!(
            relay_json["dialog_assertion"], signaled_json["dialog_assertion"],
            "the two assertions must be distinguishable on the wire, or the key \
             tells a reader nothing"
        );
    }

    /// RE3, at the point it actually matters: the endpoint WRITTEN to the
    /// store must record that a media relay asserted it.
    ///
    /// The type-level test in `rtp::stream_store` proves the two provenances
    /// are distinguishable; this proves the pipeline picks the right one.
    /// Without it, swapping `relay_asserted` for `observed` here changes
    /// nothing observable and no test notices.
    #[test]
    fn relay_control_links_reach_the_store_as_a_relay_assertion() {
        use crate::capture::parse::InputOrigin;
        use crate::rtp::stream_store::{EndpointAssertion, StreamStore};

        let sdp = "v=0\r\nc=IN IP4 10.0.0.40\r\nm=audio 38664 RTP/AVP 0";
        let raw = format!("ck d3:sdp{}:{sdp}6:result2:oke", sdp.len());
        let links = crate::rtpengine::sdp_links_from_ng(raw.as_bytes(), Some("cid1"));
        assert_eq!(links.len(), 1, "fixture must yield exactly one endpoint");

        let mut store = StreamStore::new(1000);
        let ts = chrono::Utc::now();
        super::apply_relay_control_links(&mut store, &links, InputOrigin::Hep, ts);

        let (ip, port, ..) = &links[0];
        let provenance = store
            .sdp_endpoint_provenance(*ip, *port)
            .expect("the endpoint must be registered");
        assert_eq!(
            provenance.asserted_by,
            EndpointAssertion::MediaRelay,
            "an ng endpoint is the relay's assertion about its own allocation"
        );
        assert_eq!(
            provenance.origin,
            Some(InputOrigin::Hep),
            "and the transport it arrived over is recorded independently"
        );
    }
}

#[cfg(test)]
mod quoted_media_tests {
    use super::{QuotedMediaKind, quoted_media_kind};

    /// A well-formed RTP header yields its SSRC and payload type.
    #[test]
    fn an_rtp_header_yields_its_ssrc_and_payload_type() {
        let mut p = vec![0x80u8, 8]; // V=2, PT=8 (PCMA)
        p.extend_from_slice(&7u16.to_be_bytes());
        p.extend_from_slice(&1600u32.to_be_bytes());
        p.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        p.extend_from_slice(&[0u8; 160]);
        assert_eq!(
            quoted_media_kind(&p),
            QuotedMediaKind::Rtp {
                ssrc: 0x1234_5678,
                payload_type: 8
            }
        );
    }

    /// An RTCP sender report yields its SSRC and packet type.
    #[test]
    fn an_rtcp_sender_report_yields_its_ssrc() {
        let mut p = vec![0x80u8, 200]; // V=2, RC=0, PT=200 (SR)
        p.extend_from_slice(&6u16.to_be_bytes());
        p.extend_from_slice(&0x00C0_FFEEu32.to_be_bytes());
        p.extend_from_slice(&[0u8; 20]);
        assert_eq!(
            quoted_media_kind(&p),
            QuotedMediaKind::Rtcp {
                ssrc: 0x00C0_FFEE,
                packet_type: 200
            }
        );
    }

    /// RFC 792 guarantees only the IP header plus 8 bytes, which for UDP is
    /// the transport header and nothing else. That is `Unread`, not
    /// `NotMedia`: the flow may still match a stream, and saying "not media"
    /// would rule that out on no evidence.
    #[test]
    fn an_empty_quote_is_unread_not_not_media() {
        assert_eq!(quoted_media_kind(&[]), QuotedMediaKind::Unread);
    }

    /// A truncated RTP header — version and payload type readable, SSRC not —
    /// is also `Unread`. Reading an SSRC out of bytes that are not there is
    /// how a quote gets attributed to the wrong stream.
    #[test]
    fn a_quote_too_short_for_an_ssrc_is_unread() {
        assert_eq!(
            quoted_media_kind(&[0x80, 0x00, 0x00, 0x01, 0x00, 0x00]),
            QuotedMediaKind::Unread
        );
    }

    /// A DNS query is not media. Version bits of anything but 2 settle it.
    #[test]
    fn a_dns_query_is_not_media() {
        let dns = [0x12u8, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(quoted_media_kind(&dns), QuotedMediaKind::NotMedia);
    }

    /// RFC 5761 §4 reserves payload types 64-95 so RTP and RTCP can share one
    /// port unambiguously. A "version 2" datagram using one is not RTP, and
    /// claiming it is would let a whole class of traffic pass the check on two
    /// bits of agreement.
    #[test]
    fn the_rtcp_demux_range_is_not_read_as_rtp() {
        for pt in [64u8, 80, 95] {
            let mut p = vec![0x80u8, pt];
            p.extend_from_slice(&[0u8; 20]);
            assert_eq!(
                quoted_media_kind(&p),
                QuotedMediaKind::NotMedia,
                "payload type {pt} is reserved for RTCP demultiplexing"
            );
        }
    }

    /// An RTCP packet type with a length field that cannot describe even its
    /// own header is malformed, not RTCP.
    #[test]
    fn an_rtcp_length_that_cannot_hold_a_header_is_rejected() {
        // length = 0 declares 4 bytes, which is less than the 8-byte minimum
        // for a report with an SSRC.
        let p = [0x80u8, 201, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(quoted_media_kind(&p), QuotedMediaKind::NotMedia);
    }

    /// The SSRC accessor answers for both media shapes and for neither of the
    /// other two, so a caller cannot accidentally match on a zero.
    #[test]
    fn only_a_media_payload_offers_an_ssrc() {
        assert_eq!(
            QuotedMediaKind::Rtp {
                ssrc: 9,
                payload_type: 0
            }
            .ssrc(),
            Some(9)
        );
        assert_eq!(
            QuotedMediaKind::Rtcp {
                ssrc: 9,
                packet_type: 200
            }
            .ssrc(),
            Some(9)
        );
        assert_eq!(QuotedMediaKind::Unread.ssrc(), None);
        assert_eq!(QuotedMediaKind::NotMedia.ssrc(), None);
        assert!(!QuotedMediaKind::Unread.is_media());
        assert!(!QuotedMediaKind::NotMedia.is_media());
    }
}

/// Tests for the attribution tier and the resolved-findings index.
///
/// The tier is the part of a media finding a consumer cannot recover on its
/// own: `flow` is an exact directed 5-tuple match against a stream sipnab
/// watched and `none` is no match at all, and a surface that prints one where
/// it meant the other is more misleading than a surface that prints neither.
/// So the token each tier renders to is pinned here rather than left to
/// whichever surface writes it out.
/// Test-only fixtures shared with the surface test modules.
///
/// The media ICMP store is written by the PARSER, never by a constructor: a
/// quote is filed by [`record_icmp_error`] as it walks the packet. A test that
/// wants REAL evidence in the store therefore has to hand the parser a real
/// ICMP error, and more than one module wants the same one -- so it is built
/// here rather than copied into each of them, where the copies would drift.
#[cfg(test)]
pub(crate) mod test_support {
    use chrono::{TimeZone, Utc};

    /// Ethernet (DLT_EN10MB), the link type the fixture is framed for.
    const DLT_EN10MB: i32 = 1;

    /// One ICMPv4 port-unreachable quoting an RTP datagram.
    ///
    /// Quoting RTP rather than SIP is what routes it to the MEDIA store:
    /// [`super::record_icmp_error`] branches on whether the quoted payload
    /// parses as a SIP request, not on the port it was sent to.
    pub(crate) fn icmp_error_quoting_rtp() -> crate::capture::Packet {
        // V=2, PT=0 (PCMU), one sequence, one timestamp, an SSRC and audio.
        let mut rtp = vec![0x80u8, 0x00];
        rtp.extend_from_slice(&1u16.to_be_bytes());
        rtp.extend_from_slice(&160u32.to_be_bytes());
        rtp.extend_from_slice(&0x0BAD_F00Du32.to_be_bytes());
        rtp.extend_from_slice(&[0xAB; 160]);

        // The datagram that failed: 192.0.2.10:40000 -> 198.51.100.20:20000.
        let udp_len = (8 + rtp.len()) as u16;
        let quoted_len = 20 + udp_len;
        let mut quoted = Vec::with_capacity(quoted_len as usize);
        quoted.extend_from_slice(&[0x45, 0x00]);
        quoted.extend_from_slice(&quoted_len.to_be_bytes());
        quoted.extend_from_slice(&[0x00, 0x07, 0x40, 0x00, 64, 17, 0x00, 0x00]);
        quoted.extend_from_slice(&[192, 0, 2, 10]);
        quoted.extend_from_slice(&[198, 51, 100, 20]);
        quoted.extend_from_slice(&40000u16.to_be_bytes());
        quoted.extend_from_slice(&20000u16.to_be_bytes());
        quoted.extend_from_slice(&udp_len.to_be_bytes());
        quoted.extend_from_slice(&[0x00, 0x00]);
        quoted.extend_from_slice(&rtp);

        // The ICMP error carrying the news: type 3 code 3, port unreachable.
        let mut icmp = vec![3u8, 3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        icmp.extend_from_slice(&quoted);

        // Reported BY the router at 203.0.113.1, TO the sender.
        let total_len = (20 + icmp.len()) as u16;
        let mut pkt = Vec::with_capacity(14 + total_len as usize);
        pkt.extend_from_slice(&[0xAA; 6]);
        pkt.extend_from_slice(&[0xBB; 6]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        pkt.extend_from_slice(&[0x45, 0x00]);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x09, 0x00, 0x00, 64, 1, 0x00, 0x00]);
        pkt.extend_from_slice(&[203, 0, 113, 1]);
        pkt.extend_from_slice(&[192, 0, 2, 10]);
        pkt.extend_from_slice(&icmp);

        let len = pkt.len();
        crate::capture::Packet::new(
            Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0)
                .single()
                .expect("fixture timestamp"),
            pkt,
            len,
            len,
            None,
            DLT_EN10MB,
        )
    }

    /// File the fixture as evidence, through the parser every capture uses.
    ///
    /// The assertion is part of the fixture: an ICMP error that became a
    /// `ParsedPacket` would mean the packet was built wrong, and the tests
    /// downstream would then be asserting about an empty store.
    pub(crate) fn file_one_media_icmp_error() {
        let pkt = icmp_error_quoting_rtp();
        assert!(
            crate::capture::parse::parse_packet(&pkt).is_err(),
            "an ICMP error is evidence, never a ParsedPacket"
        );
    }
}

#[cfg(test)]
mod resolved_media_tests {
    use super::{
        IcmpMediaReport, MediaIcmpFinding, MediaMatch, QuotedMediaKind, ResolvedIcmpMedia,
    };

    /// One finding at `matched`, naming `call_ids`.
    fn finding(matched: MediaMatch, call_ids: &[&str]) -> MediaIcmpFinding {
        MediaIcmpFinding {
            source: "192.0.2.1:40000".to_string(),
            unreachable_endpoint: "192.0.2.2:20000".to_string(),
            reported_by: "192.0.2.9".to_string(),
            transport: "UDP",
            description: "port unreachable".to_string(),
            icmp_type: 3,
            icmp_code: 3,
            errors: 4,
            payload: QuotedMediaKind::Rtp {
                ssrc: 0x0BAD_F00D,
                payload_type: 0,
            },
            matched,
            streams: 1,
            call_ids: call_ids.iter().map(|s| (*s).to_string()).collect(),
            hint: "hint".to_string(),
        }
    }

    /// Every tier renders to its own token, and no two share one.
    ///
    /// A collision here would let a consumer branching on the token treat a
    /// guess as a measurement, which is the whole reason the tier is carried.
    #[test]
    fn each_attribution_tier_renders_to_its_own_token() {
        let tiers = [
            (MediaMatch::Flow, "flow"),
            (MediaMatch::Ssrc, "ssrc"),
            (MediaMatch::Endpoint, "endpoint"),
            (MediaMatch::SdpEndpoint, "sdp_endpoint"),
            (MediaMatch::None, "none"),
        ];
        for (matched, token) in tiers {
            assert_eq!(
                finding(matched, &[]).attribution_tier(),
                token,
                "{matched:?} must render as {token}"
            );
        }
        let mut seen: Vec<&str> = tiers.iter().map(|(_, t)| *t).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            tiers.len(),
            "two tiers share a token, so a consumer cannot tell them apart"
        );
    }

    /// The payload kind is a separate fact from the tier.
    ///
    /// A quote can be unmistakably RTP and match nothing, or match a stream
    /// exactly with no payload left to read. Collapsing the two would lose
    /// which of them a reader is looking at.
    #[test]
    fn the_payload_kind_is_reported_separately_from_the_tier() {
        let mut f = finding(MediaMatch::None, &[]);
        assert_eq!(f.payload_kind(), "rtp");
        assert_eq!(f.attribution_tier(), "none");
        f.payload = QuotedMediaKind::Rtcp {
            ssrc: 1,
            packet_type: 201,
        };
        assert_eq!(f.payload_kind(), "rtcp");
        f.payload = QuotedMediaKind::Unread;
        assert_eq!(f.payload_kind(), "unread");
        f.payload = QuotedMediaKind::NotMedia;
        assert_eq!(f.payload_kind(), "not_media");
    }

    /// The index returns a dialog's findings and nobody else's.
    #[test]
    fn the_resolved_set_indexes_findings_by_the_calls_they_named() {
        let report = IcmpMediaReport {
            errors: 12,
            flows: vec![
                finding(MediaMatch::Flow, &["a@example.com"]),
                finding(MediaMatch::Ssrc, &["a@example.com", "b@example.com"]),
                finding(MediaMatch::None, &[]),
            ],
            ..IcmpMediaReport::default()
        };
        let resolved = ResolvedIcmpMedia::new(report);

        assert_eq!(resolved.findings_for("a@example.com").len(), 2);
        assert_eq!(resolved.findings_for("b@example.com").len(), 1);
        assert!(resolved.findings_for("nobody@example.com").is_empty());
    }

    /// A finding that named no call reaches the capture-wide ledger and no
    /// dialog.
    ///
    /// This is the majority case on real traffic — 205 of 514 errors on one
    /// corpus matched nothing the capture held — and it is why the ledger is
    /// capture-wide rather than assembled from the dialogs.
    #[test]
    fn a_finding_that_named_no_call_is_still_in_the_capture_wide_ledger() {
        let report = IcmpMediaReport {
            errors: 4,
            unattributed: 4,
            flows: vec![finding(MediaMatch::None, &[])],
            ..IcmpMediaReport::default()
        };
        let resolved = ResolvedIcmpMedia::new(report);

        assert_eq!(
            resolved.report().flows.len(),
            1,
            "the ledger must hold a finding no dialog can claim"
        );
        assert!(resolved.findings_for("a@example.com").is_empty());
    }

    /// Discarding the evidence discards the resolved answer about it.
    ///
    /// The resolved set is an answer ABOUT a store; leaving it behind would let
    /// the next capture's surfaces report the previous capture's flows.
    #[test]
    #[serial_test::serial(icmp_evidence)]
    fn resetting_the_evidence_drops_the_resolved_findings() {
        let store = crate::rtp::stream_store::StreamStore::new(4);
        super::resolve_icmp_media(&store);
        assert!(
            super::MEDIA_ICMP_RESOLVED_SEEN.load(std::sync::atomic::Ordering::Acquire),
            "resolving must arm the fast path or no surface will look"
        );

        super::reset_icmp_evidence();

        assert!(
            !super::MEDIA_ICMP_RESOLVED_SEEN.load(std::sync::atomic::Ordering::Acquire),
            "a reset that leaves the resolved set armed serves stale findings"
        );
        assert_eq!(super::icmp_media_findings().report().errors, 0);
    }

    /// A reset drops the recorded EVIDENCE, not only the answer about it.
    ///
    /// These are two stores and the reset clears both, which is what makes
    /// serializing the writers sufficient. If it cleared only the resolved
    /// set, the next `resolve_icmp_media` -- which every post-capture surface
    /// reaches through `select_dialogs` -- would rebuild the same findings out
    /// of the evidence that survived, and a run that asked for a clean slate
    /// would report the previous capture's flows anyway.
    ///
    /// Drop `*MEDIA_ICMP.lock() = None;` from `reset_icmp_evidence` and the
    /// second resolve below answers `1` again.
    #[test]
    #[serial_test::serial(icmp_evidence)]
    fn resetting_drops_the_recorded_media_evidence_not_just_the_answer() {
        let store = crate::rtp::stream_store::StreamStore::new(4);
        super::reset_icmp_evidence();

        super::test_support::file_one_media_icmp_error();
        let filed = super::resolve_icmp_media(&store);
        assert_eq!(
            filed.report().errors,
            1,
            "the parser must file a non-SIP quote as media evidence"
        );

        super::reset_icmp_evidence();

        assert_eq!(
            super::resolve_icmp_media(&store).report().errors,
            0,
            "a resolve after a reset rebuilt findings from evidence the reset \
             was supposed to have discarded"
        );
        super::reset_icmp_evidence();
    }

    /// A resolve from somewhere else must not wipe a published set.
    ///
    /// `publish_icmp_media_for_test` is how every surface test puts a KNOWN
    /// set where the surface will read it. `resolve_icmp_media` is what
    /// `select_dialogs` calls, and `select_dialogs` is on the way to every
    /// post-capture surface -- so before the pin, an unrelated test rendering
    /// an unrelated surface replaced the findings this one was still asserting
    /// on, and the surface test failed claiming the surface had dropped them.
    ///
    /// Delete the `MEDIA_ICMP_PINNED` check in `resolve_icmp_media` and the
    /// published set is gone by the time it is read.
    #[test]
    #[serial_test::serial(icmp_evidence)]
    fn a_resolve_elsewhere_does_not_wipe_a_published_set() {
        super::reset_icmp_evidence();
        super::publish_icmp_media_for_test(ResolvedIcmpMedia::new(IcmpMediaReport {
            errors: 7,
            unattributed: 7,
            flows: vec![finding(MediaMatch::None, &[])],
            ..IcmpMediaReport::default()
        }));

        // What another test does on its way to rendering any surface.
        let elsewhere = super::resolve_icmp_media(&crate::rtp::stream_store::StreamStore::new(4));
        assert_eq!(
            elsewhere.report().errors,
            0,
            "the resolver still answers its own caller honestly about the \
             store it was handed"
        );

        assert_eq!(
            super::icmp_media_findings().report().errors,
            7,
            "a foreign resolve replaced the set this test published"
        );
        super::reset_icmp_evidence();
    }
}
