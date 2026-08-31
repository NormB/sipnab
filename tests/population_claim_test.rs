// SPDX-License-Identifier: MIT OR Apache-2.0

// Gated on `full` for the reason `mcp_completeness_test` is: this file drives
// every tool that takes a page-size argument, and that surface is
// FEATURE-DEPENDENT. Under a narrower combination some of these tools are not
// registered at all, and a probe that cannot reach a tool reads as a tool with
// nothing to say. The documentation and the tool inventory both describe the
// full binary, so that is the only build this comparison means anything
// against.
#![cfg(feature = "full")]
#![cfg(all(unix, feature = "mcp"))]

//! A claim about the whole capture must not be computed from one page.
//!
//! # The defect this file exists for
//!
//! `reconcile_orphans` returned `relay_was_consulted`, a boolean whose entire
//! documented purpose is separating "nobody asked" (an absence of evidence)
//! from "asked and told no" (evidence of absence). It was computed as
//! `rows.iter().any(...)` over `rows` that had ALREADY been cut to the
//! caller's `limit`. Called with `limit: 1` against a capture whose sixtieth
//! orphan is the only relay-asserted one, it answered `relay_was_consulted:
//! false` — asserting that nobody asked about a capture where a relay HAD been
//! consulted. The field inverted precisely the claim it exists to make, and it
//! did so silently: the response also carried `truncated: true`, which
//! discloses that ROWS were withheld and says nothing about the scalar beside
//! them being wrong.
//!
//! # The class, which is what is gated here
//!
//! **A capture-wide claim computed from a truncated page rather than from the
//! whole population.** Any scalar in an MCP response that describes the
//! population — a total, a count, a boolean "did we ever see X", a max or a
//! min — must be identical whether or not the caller passed a small page size.
//! A caller that pages for cheapness must not be told a different fact about
//! the capture than a caller that does not.
//!
//! Only the rows themselves, and the fields that describe THIS page, may move.
//! Those are named one by one below with the property that makes each per-page
//! rather than capture-wide; a silent skip would be the same defect wearing the
//! gate's own clothes.
//!
//! # Why this is driven over the wire
//!
//! The defect is not visible in a handler read in isolation — the buggy
//! accumulator and the correct one are three characters apart and both compile.
//! What separates them is what a client is TOLD, so a client is what asks. Two
//! calls to one loaded server, one page size apart, and the answers are
//! compared as documents.
//!
//! # Why this file builds its own capture
//!
//! The comparison is vacuous unless the fixture holds MORE rows than the small
//! page size for the tool under test: both calls then return the same page, and
//! the test passes while proving nothing. No checked-in sample carries enough
//! of every population at once — twelve plus dialogs, failed calls, several RTP
//! streams, a correlated call tree, two scanner sweeps, and five orphaned
//! streams of which exactly one is relay-asserted and is NOT on the first page.
//! So the capture is built here, and every probe asserts its own precondition
//! and FAILS rather than skipping when it does not hold.
//!
//! The private capture corpus is deliberately not used and no capture is
//! committed: the corpus is real customer traffic.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

#[path = "support/mcp.rs"]
mod mcp;
#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/source_scan.rs"]
mod source_scan;

use mcp::McpSession;

// ── the two page sizes ──────────────────────────────────────────────────

/// The small page: one row, the smallest a caller can ask for.
///
/// One rather than two because the buggy accumulator's error grows as the page
/// shrinks, so this is the reading a paging agent is most likely to get.
const SMALL_PAGE: u32 = 1;

/// The large page, above every population this fixture builds.
///
/// The server's own ceiling is `--mcp-max-rows`, itself 1000 by default, so
/// this is "as much as the surface will give" rather than an arbitrary number.
const LARGE_PAGE: u32 = 1000;

// ── the fixture's own vocabulary ────────────────────────────────────────

/// Name of the capture this file drives.
const POPULATION_CAPTURE: &str = "population.pcap";

/// A second, smaller capture, so `compare_captures` has two files to diff.
const BASELINE_CAPTURE: &str = "baseline.pcap";

/// Root of the correlated call tree, and the leg `find_correlated` starts from.
const ROOT_CALL_ID: &str = "tree-leg0@10.5.0.1";

/// The address every plain call is placed from, for `describe_endpoint`.
const CALLER_IP: &str = "10.1.0.1";

/// Plain answered calls, which is `describe_endpoint`'s population.
const PLAIN_CALLS: usize = 12;

/// Legs in the correlated tree, root included.
const TREE_LEGS: usize = 4;

/// Calls whose SDP names real media, one grounded RTP stream each.
const MEDIA_CALLS: usize = 4;

/// Unanswered INVITEs, which is what `find_problems` has to find.
const FAILED_CALLS: usize = 3;

/// RTP streams nothing in the capture ever named.
const NEVER_NAMED_ORPHANS: usize = 4;

/// The endpoint a mirrored relay control message allocates.
const RELAY_IP: [u8; 4] = [10, 0, 0, 40];
/// The port it allocates there.
const RELAY_PORT: u16 = 38664;
/// The far end of the media on that allocation.
const PARTY_IP: [u8; 4] = [10, 0, 0, 60];
/// Its port.
const PARTY_PORT: u16 = 40002;
/// The Call-ID the mirrored control message names.
const RELAY_CALL_ID: &str = "relay-orphan@sipnab";
/// The only destination port a sniffed relay mirror is believed on.
const HEP_PORT: u16 = 9060;

/// How far the orphan media is placed AFTER the control message, in seconds.
///
/// `StreamStore`'s SDP endpoint TTL is 300 s: past it a remembered endpoint
/// may no longer name a stream that did not exist yet. That is what makes this
/// stream ORPHANED while its endpoint still carries the relay's provenance,
/// which is the shape `reconcile_orphans` reports as
/// `relay-asserted-but-no-dialog` — and it is the shape a relay host really
/// produces when the signaling for a leg was never captured.
const ORPHAN_MEDIA_DELAY_SECS: u64 = 400;

/// The verdict that says a relay named an endpoint no dialog claims.
const RELAY_ASSERTED: &str = "relay-asserted-but-no-dialog";

// ── what a page may legitimately change ─────────────────────────────────

/// Keys every paging tool may move, each with the property that makes it a
/// statement about THIS page rather than about the capture.
const PER_PAGE: &[(&str, &str)] = &[
    (
        "truncated",
        "says whether the cap bit on this call, which is the one fact that \
         cannot be page-independent: it is the disclosure that a page was cut",
    ),
    (
        "returned",
        "rows in this response, so the caller never has to count the array",
    ),
    (
        "next_cursor",
        "where this page ended, which is the caller's handle for asking for \
         the next one",
    ),
];

/// A page whose rows sit one level inside the key that carries them.
///
/// `Copy` because [`PROBES`] holds it by value and every probe is read through
/// a shared reference.
///
/// `compare_captures` answers with one element per dimension and cuts the rows
/// WITHIN each element, so the element list is the same length at both page
/// sizes. Without this the row precondition would be vacuous for that tool and
/// everything inside the element -- including a per-dimension
/// `distinct_values`, which is a population claim -- would sit behind a blanket
/// exemption.
#[derive(Clone, Copy)]
struct NestedPage {
    /// Why the rows sit one level down.
    note: &'static str,
    /// The key inside each element that holds the rows.
    rows: &'static str,
    /// Keys inside an element describing that element's own page.
    per_page: &'static [(&'static str, &'static str)],
}

/// One tool driven at two page sizes, and what its answer may change.
struct PageProbe {
    /// The tool's name on the wire.
    tool: &'static str,
    /// Every argument except the page size, as JSON text. `{ROOT}`,
    /// `{POPULATION}` and `{BASELINE}` are replaced with [`ROOT_CALL_ID`],
    /// [`POPULATION_CAPTURE`] and [`BASELINE_CAPTURE`], so the fixture names
    /// live in one place.
    args: &'static str,
    /// The key holding the rows this tool pages over.
    page: &'static str,
    /// `None` when `page` is a flat array of rows the page size cuts directly.
    /// `Some` when the cut falls one level INSIDE it.
    nested: Option<NestedPage>,
    /// Keys beyond [`PER_PAGE`] this tool may move, each with the property
    /// that makes it per-page. Named rather than skipped: an unexplained
    /// exception is indistinguishable from the defect.
    per_page: &'static [(&'static str, &'static str)],
}

/// Every tool that takes a page-size argument, with the smallest call that
/// makes it answer.
///
/// The tool LIST is derived from the source by [`page_size_tools`] and checked
/// against this table in both directions, so a tool that grows a page size
/// tomorrow fails this suite rather than escaping it.
const PROBES: &[PageProbe] = &[
    PageProbe {
        tool: "list_dialogs",
        args: "{}",
        page: "dialogs",
        nested: None,
        per_page: &[],
    },
    PageProbe {
        tool: "find_problems",
        args: "{}",
        page: "dialogs",
        nested: None,
        per_page: &[],
    },
    PageProbe {
        tool: "search_messages",
        args: r#"{"query":"INVITE"}"#,
        page: "hits",
        nested: None,
        per_page: &[],
    },
    PageProbe {
        tool: "search_by_time",
        args: r#"{"start":"1970-01-01T00:00:00Z"}"#,
        page: "dialogs",
        nested: None,
        per_page: &[],
    },
    PageProbe {
        tool: "rtp_stats",
        args: "{}",
        page: "streams",
        nested: None,
        per_page: &[],
    },
    PageProbe {
        tool: "tail_dialogs",
        args: "{}",
        page: "dialogs",
        nested: None,
        per_page: &[],
    },
    PageProbe {
        tool: "security_findings",
        args: "{}",
        page: "findings",
        nested: None,
        per_page: &[],
    },
    PageProbe {
        tool: "find_correlated",
        args: r#"{"call_id":"{ROOT}"}"#,
        page: "legs",
        nested: None,
        per_page: &[],
    },
    PageProbe {
        tool: "get_call_tree",
        args: r#"{"call_id":"{ROOT}"}"#,
        page: "legs",
        nested: None,
        // `limit` here bounds the WALK, not a page over a settled population:
        // the traversal stops and the legs behind the cut are never visited,
        // so every one of these describes the legs that were reached. They are
        // exceptions because the tool cannot know the rest without walking it,
        // and `truncated` is how it says the walk stopped short.
        //
        // `total_legs` is nonetheless a hazard rather than a clean contract:
        // it is the one field on this whole surface named `total_*` that moves
        // with the page size. Recorded here rather than gated, because the
        // response schema documents it as "number of legs returned".
        per_page: &[
            (
                "total_legs",
                "legs the walk reached, root included -- documented as \
                 'number of legs returned', not as the tree's size",
            ),
            (
                "max_depth",
                "deepest hop the walk got to before the cap stopped it",
            ),
            (
                "total_messages",
                "messages across the legs that were reached",
            ),
            (
                "heuristic_edges",
                "guessed edges among the edges the walk traversed",
            ),
            (
                "first_activity",
                "earliest creation time among the legs reached",
            ),
            ("last_activity", "latest update time among the legs reached"),
        ],
    },
    PageProbe {
        tool: "top_talkers",
        args: r#"{"by":"ip"}"#,
        page: "talkers",
        nested: None,
        per_page: &[],
    },
    PageProbe {
        tool: "describe_endpoint",
        args: r#"{"ip":"10.1.0.1"}"#,
        page: "recent_dialogs",
        nested: None,
        per_page: &[],
    },
    PageProbe {
        tool: "reconcile_orphans",
        args: "{}",
        page: "orphans",
        nested: None,
        per_page: &[],
    },
    PageProbe {
        tool: "aggregate_dialogs",
        args: r#"{"group_by":"state"}"#,
        page: "buckets",
        nested: None,
        per_page: &[(
            "other_count",
            "dialogs summed into the overflow bucket because their value did \
             not make this page -- a truncated aggregate that does not say \
             what it left out is a wrong total, not a partial one",
        )],
    },
    PageProbe {
        tool: "group_dialogs",
        args: r#"{"by":"ua"}"#,
        page: "groups",
        nested: None,
        per_page: &[(
            "other_count",
            "the same overflow bucket `aggregate_dialogs` carries, for the \
             same reason",
        )],
    },
    PageProbe {
        tool: "compare_captures",
        args: r#"{"a":"{POPULATION}","b":"{BASELINE}"}"#,
        page: "dimensions",
        nested: Some(NestedPage {
            note: "one element per dimension, and the cut falls on the rows \
                   inside each -- so the dimension list is the same length at \
                   both page sizes and only its contents move",
            rows: "buckets",
            per_page: &[(
                "other",
                "the overflow bucket this dimension's rows were summed into \
                 because they did not make the page",
            )],
        }),
        per_page: &[],
    },
];

// ── anti-vacuity floors ─────────────────────────────────────────────────

/// Page-size parameter names the source must yield.
///
/// Two, because there are two vocabularies in the tree -- `limit` on the row
/// listings and `top_n` on the aggregates -- and a scan that finds one of them
/// has stopped matching the code rather than found a simpler world.
const MIN_PAGE_SIZE_PARAMS: usize = 2;

/// Tools the source must yield as taking a page size.
///
/// A derivation that matches almost nothing agrees with any implementation,
/// which is how a scanner dies quietly.
const MIN_PAGE_SIZE_TOOLS: usize = 12;

/// Keys the comparison must actually have compared.
///
/// Without a floor, an exception list that grew to cover every key would leave
/// this suite green with nothing left to check.
const MIN_COMPARED_KEYS: usize = 85;

/// Population-wide keys every single probe must contribute.
const MIN_KEYS_PER_TOOL: usize = 2;

/// Orphans the fixture must hold for the `reconcile_orphans` pin to mean
/// anything.
const MIN_ORPHANS: usize = 3;

// ── building the capture ────────────────────────────────────────────────

/// One RTP packet with a G.711 payload.
fn rtp_packet(seq: u16, ssrc: u32) -> Vec<u8> {
    let mut rtp = vec![0x80, 0x00];
    rtp.extend_from_slice(&seq.to_be_bytes());
    rtp.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    rtp.extend_from_slice(&ssrc.to_be_bytes());
    rtp.extend_from_slice(&[0xff; 160]);
    rtp
}

/// One HEP v3 chunk, vendor 0.
fn hep_chunk(out: &mut Vec<u8>, chunk_type: u16, data: &[u8]) {
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&chunk_type.to_be_bytes());
    out.extend_from_slice(&((6 + data.len()) as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// A mirrored rtpengine `ng` REPLY under HEP, naming `call_id`'s allocation.
///
/// Shaped like the live reply in `tests/fixtures/rtpengine-ng-hep.pcap`, and
/// like the one `rtpengine_sniffed_ng_gate_test` proves is believed on the HEP
/// port. A reply carries no `call-id` of its own, so the correlation-id chunk
/// is what names the call.
fn hep_ng_reply(call_id: &str, media_ip: [u8; 4], media_port: u16) -> Vec<u8> {
    let addr = format!(
        "{}.{}.{}.{}",
        media_ip[0], media_ip[1], media_ip[2], media_ip[3]
    );
    let sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {addr}\r\ns=-\r\nc=IN IP4 {addr}\r\nt=0 0\r\n\
         m=audio {media_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    );
    let payload = format!("cookie1 d3:sdp{}:{sdp}6:result2:oke", sdp.len()).into_bytes();

    let mut body = Vec::new();
    hep_chunk(&mut body, 0x0001, &[2]); // IPv4
    hep_chunk(&mut body, 0x0002, &[17]); // UDP
    hep_chunk(&mut body, 0x0003, &[127, 0, 0, 1]);
    hep_chunk(&mut body, 0x0004, &[127, 0, 0, 1]);
    hep_chunk(&mut body, 0x0007, &43734u16.to_be_bytes());
    hep_chunk(&mut body, 0x0008, &2223u16.to_be_bytes());
    hep_chunk(&mut body, 0x0009, &1_700_000_000u32.to_be_bytes());
    hep_chunk(&mut body, 0x000a, &0u32.to_be_bytes());
    hep_chunk(&mut body, 0x000b, &[0x3d]); // rtpengine's ng capture protocol
    hep_chunk(&mut body, 0x000c, &2001u32.to_be_bytes());
    hep_chunk(&mut body, 0x0011, call_id.as_bytes());
    hep_chunk(&mut body, 0x000f, &payload);

    let mut pkt = Vec::with_capacity(6 + body.len());
    pkt.extend_from_slice(b"HEP3");
    pkt.extend_from_slice(&((6 + body.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}

/// An INVITE answered `486 Busy Here`, which is a problem `find_problems` finds.
fn failed_call(n: usize) -> Vec<Vec<u8>> {
    let (a, b) = ([10, 3, 0, 1], [10, 4, 0, 1]);
    let via = format!("Via: SIP/2.0/UDP 10.3.0.1:5060;branch=z9hG4bKfail{n}\r\n");
    let from = format!("From: <sip:busy{n}@10.3.0.1>;tag=ftag{n}\r\n");
    let to = format!("To: <sip:none{n}@10.4.0.1>");
    let to_tagged = format!("{to};tag=ft{n}\r\n");
    let cid = format!("Call-ID: failed-{n}@10.3.0.1\r\n");
    vec![
        pcap_build::udp_frame(
            a,
            b,
            5060,
            5060,
            format!(
                "INVITE sip:none{n}@10.4.0.1 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to}\r\n\
                 {cid}CSeq: 1 INVITE\r\nContact: <sip:busy{n}@10.3.0.1:5060>\r\n\
                 Content-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        ),
        pcap_build::udp_frame(
            b,
            a,
            5060,
            5060,
            format!(
                "SIP/2.0 486 Busy Here\r\n{via}{from}{to_tagged}{cid}CSeq: 1 INVITE\r\n\
                 Content-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        ),
        pcap_build::udp_frame(
            a,
            b,
            5060,
            5060,
            format!(
                "ACK sip:none{n}@10.4.0.1 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to_tagged}\
                 {cid}CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        ),
    ]
}

/// One leg of the correlated tree.
///
/// `x_call_id` is the identifier the walk follows: a leg carrying `X-Call-ID`
/// pointing at another leg's Call-ID is an IDENTIFIER match, not the timing
/// heuristic, so the tree is the same on every run.
fn tree_leg(n: usize, x_call_id: Option<&str>) -> Vec<Vec<u8>> {
    let (a, b) = ([10, 5, 0, 1], [10, 6, 0, 1]);
    let via = format!("Via: SIP/2.0/UDP 10.5.0.1:5060;branch=z9hG4bKtree{n}\r\n");
    let from = format!("From: <sip:leg{n}@10.5.0.1>;tag=ttag{n}\r\n");
    let to = format!("To: <sip:dest{n}@10.6.0.1>");
    let to_tagged = format!("{to};tag=tt{n}\r\n");
    let cid = format!("Call-ID: tree-leg{n}@10.5.0.1\r\n");
    let xcid = x_call_id.map_or_else(String::new, |root| format!("X-Call-ID: {root}\r\n"));
    let ua = format!("User-Agent: tree-agent-{n}\r\n");
    vec![
        pcap_build::udp_frame(
            a,
            b,
            5060,
            5060,
            format!(
                "INVITE sip:dest{n}@10.6.0.1 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to}\r\n\
                 {cid}{xcid}{ua}CSeq: 1 INVITE\r\nContact: <sip:leg{n}@10.5.0.1:5060>\r\n\
                 Content-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        ),
        pcap_build::udp_frame(
            b,
            a,
            5060,
            5060,
            format!(
                "SIP/2.0 200 OK\r\n{via}{from}{to_tagged}{cid}CSeq: 1 INVITE\r\n\
                 Contact: <sip:dest{n}@10.6.0.1:5060>\r\nContent-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        ),
        pcap_build::udp_frame(
            a,
            b,
            5060,
            5060,
            format!(
                "ACK sip:dest{n}@10.6.0.1 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to_tagged}\
                 {cid}CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        ),
    ]
}

/// An answered call whose SDP names media, plus the RTP that flows on it.
///
/// Grounded rather than orphaned on purpose: `rtp_stats` reports streams it
/// can ground, so a fixture of nothing but orphans would page over an empty
/// population.
fn media_call(n: usize) -> Vec<Vec<u8>> {
    let octet = (n + 1) as u8;
    let (a, b) = ([10, 7, 0, octet], [10, 8, 0, octet]);
    let a_ip = format!("10.7.0.{octet}");
    let b_ip = format!("10.8.0.{octet}");
    let a_port = 20000 + 2 * n as u16;
    let b_port = 30000 + 2 * n as u16;
    let sdp = |ip: &str, port: u16| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        )
    };
    let offer = sdp(&a_ip, a_port);
    let answer = sdp(&b_ip, b_port);
    let via = format!("Via: SIP/2.0/UDP {a_ip}:5060;branch=z9hG4bKmed{n}\r\n");
    let from = format!("From: <sip:m{n}@{a_ip}>;tag=mt{n}\r\n");
    let to = format!("To: <sip:p{n}@{b_ip}>");
    let to_tagged = format!("{to};tag=mtt{n}\r\n");
    let cid = format!("Call-ID: media-{n}@{a_ip}\r\n");
    let ua = format!("User-Agent: media-agent-{n}\r\n");

    let mut frames = vec![
        pcap_build::udp_frame(
            a,
            b,
            5060,
            5060,
            format!(
                "INVITE sip:p{n}@{b_ip} SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to}\r\n{cid}\
                 {ua}CSeq: 1 INVITE\r\nContact: <sip:m{n}@{a_ip}:5060>\r\n\
                 Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{offer}",
                offer.len()
            )
            .as_bytes(),
        ),
        pcap_build::udp_frame(
            b,
            a,
            5060,
            5060,
            format!(
                "SIP/2.0 200 OK\r\n{via}{from}{to_tagged}{cid}CSeq: 1 INVITE\r\n\
                 Contact: <sip:p{n}@{b_ip}:5060>\r\nContent-Type: application/sdp\r\n\
                 Content-Length: {}\r\n\r\n{answer}",
                answer.len()
            )
            .as_bytes(),
        ),
        pcap_build::udp_frame(
            a,
            b,
            5060,
            5060,
            format!(
                "ACK sip:p{n}@{b_ip} SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to_tagged}{cid}\
                 CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        ),
    ];
    for seq in 0..20u16 {
        frames.push(pcap_build::udp_frame(
            a,
            b,
            a_port,
            b_port,
            &rtp_packet(seq, 0x5000 + n as u32),
        ));
    }
    frames.push(pcap_build::udp_frame(
        a,
        b,
        5060,
        5060,
        format!(
            "BYE sip:p{n}@{b_ip} SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to_tagged}{cid}\
             CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
        )
        .as_bytes(),
    ));
    frames.push(pcap_build::udp_frame(
        b,
        a,
        5060,
        5060,
        format!(
            "SIP/2.0 200 OK\r\n{via}{from}{to_tagged}{cid}CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
        )
        .as_bytes(),
    ));
    frames
}

/// An extension sweep from one source, which arms a `scanner` finding.
///
/// Distinct callees are what the enumeration signal counts and a unique branch
/// per request is what stops the detector reading them as one retransmitted
/// transaction — the same shape `accused_sources_test` builds.
fn sweep(src: [u8; 4], tag: &str, probes: usize) -> Vec<Vec<u8>> {
    let addr = format!("{}.{}.{}.{}", src[0], src[1], src[2], src[3]);
    (0..probes)
        .map(|n| {
            pcap_build::udp_frame(
                src,
                [198, 51, 100, 1],
                5060,
                5060,
                format!(
                    "INVITE sip:ext{n}@198.51.100.1 SIP/2.0\r\n\
                     Via: SIP/2.0/UDP {addr}:5060;branch=z9hG4bK-{tag}-{n}\r\n\
                     From: <sip:probe@{addr}>;tag={tag}\r\n\
                     To: <sip:ext{n}@198.51.100.1>\r\n\
                     Call-ID: {tag}-{n}@{addr}\r\n\
                     CSeq: 1 INVITE\r\nMax-Forwards: 70\r\n\
                     User-Agent: friendly-scanner\r\nContent-Length: 0\r\n\r\n"
                )
                .as_bytes(),
            )
        })
        .collect()
}

/// Write the capture every probe is driven against.
///
/// Timestamps are explicit rather than a fixed cadence because the orphan
/// media has to land [`ORPHAN_MEDIA_DELAY_SECS`] after the control message
/// that names its endpoint; a 1 ms-per-frame capture cannot express that gap
/// at all, and without it the relay-asserted stream is simply attributed and
/// there is no orphan to find.
fn write_population_capture(path: &Path) {
    let mut timed: Vec<(Vec<u8>, u64)> = Vec::new();
    let mut at = 0u64;
    let mut push = |frames: Vec<Vec<u8>>, at: &mut u64| {
        for f in frames {
            timed.push((f, *at));
            *at += 1_000;
        }
    };

    for n in 0..PLAIN_CALLS {
        push(
            pcap_build::sip_call_frames(
                &format!("plain-{n}@{CALLER_IP}"),
                &format!("plain{n}"),
                &format!("caller{n}"),
                &format!("callee{n}"),
            ),
            &mut at,
        );
    }
    for n in 0..FAILED_CALLS {
        push(failed_call(n), &mut at);
    }
    // The root first, then every other leg pointing back at it.
    push(tree_leg(0, None), &mut at);
    for n in 1..TREE_LEGS {
        push(tree_leg(n, Some(ROOT_CALL_ID)), &mut at);
    }
    for n in 0..MEDIA_CALLS {
        push(media_call(n), &mut at);
    }
    push(sweep([198, 51, 100, 7], "sweepa", 14), &mut at);
    push(sweep([198, 51, 100, 8], "sweepb", 14), &mut at);

    // The relay's own statement about its allocation, mirrored to a collector
    // and seen on the wire.
    push(
        vec![pcap_build::udp_frame(
            RELAY_IP,
            PARTY_IP,
            59652,
            HEP_PORT,
            &hep_ng_reply(RELAY_CALL_ID, RELAY_IP, RELAY_PORT),
        )],
        &mut at,
    );

    // Past the endpoint TTL, so what follows is unattributed media.
    at += ORPHAN_MEDIA_DELAY_SECS * 1_000_000;

    // The never-named orphans come FIRST, so the relay-asserted one below is
    // not on the first page. That ordering is the whole point of the pin: read
    // off a page of one, `relay_was_consulted` sees only a `never-named` row.
    for k in 0..NEVER_NAMED_ORPHANS {
        let port = 41000 + 2 * k as u16;
        for seq in 0..6u16 {
            push(
                vec![pcap_build::udp_frame(
                    [10, 9, 0, 1],
                    [10, 9, 0, 2],
                    port,
                    port + 1000,
                    &rtp_packet(seq, 0xAA00 + k as u32),
                )],
                &mut at,
            );
        }
    }
    for seq in 0..6u16 {
        push(
            vec![pcap_build::udp_frame(
                PARTY_IP,
                RELAY_IP,
                PARTY_PORT,
                RELAY_PORT,
                &rtp_packet(seq, 0x1111_2222),
            )],
            &mut at,
        );
    }

    pcap_build::write_pcap_at(path, &timed, 1);
}

/// A smaller capture, so `compare_captures` has a baseline to diff against.
fn write_baseline_capture(path: &Path) {
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for n in 0..5 {
        frames.extend(pcap_build::sip_call_frames(
            &format!("baseline-{n}@{CALLER_IP}"),
            &format!("base{n}"),
            &format!("bcaller{n}"),
            &format!("bcallee{n}"),
        ));
    }
    pcap_build::write_pcap(path, &frames);
}

// ── the enumeration, derived from the source ────────────────────────────

/// Every `.rs` file under `src/mcp`, cut to its production half.
fn mcp_sources() -> Vec<(PathBuf, String)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/mcp");
    let mut out = Vec::new();
    for dir in [root.clone(), root.join("tools")] {
        for entry in std::fs::read_dir(&dir).expect("read src/mcp").flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("read a source file");
                let production = source_scan::production_source(&text).to_string();
                out.push((path, production));
            }
        }
    }
    assert!(
        out.len() >= 10,
        "only {} source files found under src/mcp; the scan is looking in the \
         wrong place",
        out.len()
    );
    out
}

/// The identifier `text` starts with.
fn leading_ident(text: &str) -> String {
    text.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// Parameter names that bound a page, read out of the source.
///
/// The marker is `resolve_limit_with_cap(params.X` — the one helper every
/// paging handler routes its caller's request through, and the place the
/// server's `--mcp-max-rows` ceiling is applied. Deriving the VOCABULARY this
/// way rather than typing it is what keeps the gate from going stale the day a
/// tool names its page size something new: `limit` and `top_n` are both in the
/// tree already, and nothing says a third is impossible.
fn page_size_param_names(sources: &[(PathBuf, String)]) -> Vec<String> {
    let mut names = Vec::new();
    for (_, src) in sources {
        for marker in ["resolve_limit_with_cap(params.", "resolve_limit(params."] {
            for (idx, _) in src.match_indices(marker) {
                let name = leading_ident(&src[idx + marker.len()..]);
                if !name.is_empty() && !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names.sort();
    names
}

/// Parameter structs declaring one of `names` as an optional row count.
///
/// Returns `(struct name, parameter name)`.
fn page_size_params_structs(
    names: &[String],
    sources: &[(PathBuf, String)],
) -> Vec<(String, String)> {
    const DECL: &str = "pub struct ";
    let mut found = Vec::new();
    for (_, src) in sources {
        for (start, _) in src.match_indices(DECL) {
            let after = &src[start + DECL.len()..];
            let name = leading_ident(after);
            if name.is_empty() {
                continue;
            }
            // A struct body ends at the first `}` in the first column, which is
            // where rustfmt puts it and where the next item begins.
            let body_end = after.find("\n}").map_or(after.len(), |e| e + 2);
            let body = &after[..body_end];
            for param in names {
                if body.contains(&format!("pub {param}: Option<u32>")) {
                    found.push((name.clone(), param.clone()));
                }
            }
        }
    }
    found
}

/// Every tool that takes a page size, and which parameter carries it.
///
/// Each handler runs from its `#[tool(` attribute to the next one, which is a
/// superset of its signature and therefore cannot MISS the `Parameters<…>` it
/// destructures — the same cut the `capture_derived_tools` helper in
/// `tests/mcp_completeness_test.rs`
/// makes for the same reason.
fn page_size_tools() -> Vec<(String, String)> {
    let sources = mcp_sources();
    let params = page_size_param_names(&sources);
    assert!(
        params.len() >= MIN_PAGE_SIZE_PARAMS,
        "only {} page-size parameter name(s) derived from src/mcp ({params:?}); \
         `limit` and `top_n` are both in the tree, so a scan that finds fewer \
         has stopped matching the code",
        params.len()
    );
    let structs = page_size_params_structs(&params, &sources);
    assert!(
        !structs.is_empty(),
        "no parameter struct declares any of {params:?} as an Option<u32>; the \
         struct scan matched nothing"
    );

    let mut found: Vec<(String, String)> = Vec::new();
    for (_, src) in &sources {
        let starts: Vec<usize> = src.match_indices("#[tool(").map(|(i, _)| i).collect();
        for (n, start) in starts.iter().enumerate() {
            let end = starts.get(n + 1).copied().unwrap_or(src.len());
            let block = &src[*start..end];
            let Some(tool) = block
                .split_once("name = \"")
                .and_then(|(_, rest)| rest.split_once('"'))
                .map(|(name, _)| name)
            else {
                continue;
            };
            for (struct_name, param) in &structs {
                if block.contains(&format!("Parameters<{struct_name}>")) {
                    let entry = (tool.to_string(), param.clone());
                    if !found.contains(&entry) {
                        found.push(entry);
                    }
                }
            }
        }
    }
    found.sort();
    found
}

// ── driving the wire ────────────────────────────────────────────────────

/// The probe's arguments with the page size set to `page`.
fn args_at(probe: &PageProbe, param: &str, page: u32) -> Value {
    let text = probe
        .args
        .replace("{ROOT}", ROOT_CALL_ID)
        .replace("{POPULATION}", POPULATION_CAPTURE)
        .replace("{BASELINE}", BASELINE_CAPTURE);
    let mut args: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{}: probe arguments are not JSON: {e}", probe.tool));
    args[param] = json!(page);
    args
}

/// Call `probe.tool` at `page` rows and return the parsed payload.
fn answer_at(session: &mut McpSession, probe: &PageProbe, param: &str, page: u32) -> Value {
    let reply = session.call(probe.tool, args_at(probe, param, page));
    assert_ne!(
        reply["result"]["isError"],
        json!(true),
        "{} refused its probe at {param}={page}: {reply}",
        probe.tool
    );
    assert!(
        reply.get("error").is_none(),
        "{} errored at {param}={page}: {reply}",
        probe.tool
    );
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{}: no text content block in {reply}", probe.tool));
    serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("{}: payload is not JSON: {e}\n{text}", probe.tool))
}

/// Compare the parts of a nested page's elements that describe the capture.
///
/// Returns how many keys were compared, so the caller's floor counts them and
/// a nested page cannot quietly contribute nothing.
fn compare_nested_elements(
    probe: &PageProbe,
    nested: NestedPage,
    small: &[Value],
    large: &[Value],
    param: &str,
) -> usize {
    let mut compared = 0usize;
    for (index, (small_el, large_el)) in small.iter().zip(large).enumerate() {
        let inner = |el: &Value, page: u32| {
            el[nested.rows].as_array().map(Vec::len).unwrap_or_else(|| {
                panic!(
                    "{}: element {index} has no `{}` array at {param}={page}: {el}",
                    probe.tool, nested.rows
                )
            })
        };
        let small_len = inner(small_el, SMALL_PAGE);
        let large_len = inner(large_el, LARGE_PAGE);
        assert!(
            small_len < large_len,
            "{}: element {index} returned {small_len} row(s) at \
             {param}={SMALL_PAGE} and {large_len} at {param}={LARGE_PAGE}. The \
             cut has to reach inside the element or nothing here is being \
             compared.",
            probe.tool
        );

        let mut keys: Vec<&String> = small_el
            .as_object()
            .unwrap_or_else(|| panic!("{}: element {index} is not an object", probe.tool))
            .keys()
            .collect();
        for key in large_el.as_object().into_iter().flat_map(|o| o.keys()) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        for key in keys {
            if key == nested.rows || nested.per_page.iter().any(|(k, _)| k == key) {
                continue;
            }
            compared += 1;
            assert_eq!(
                small_el.get(key),
                large_el.get(key),
                "{}: element {index}'s `{key}` describes the capture, and it \
                 moved when the caller asked for {SMALL_PAGE} row(s) instead \
                 of {LARGE_PAGE}: {:?} against {:?}",
                probe.tool,
                small_el.get(key),
                large_el.get(key)
            );
        }
    }
    compared
}

/// The `(rows returned, the object that has to disclose the cut)` pairs one
/// answer offers: one for a flat page, one per element for a nested one.
fn disclosure_subjects<'a>(probe: &PageProbe, answer: &'a Value) -> Vec<(usize, &'a Value)> {
    match probe.nested {
        None => vec![(answer[probe.page].as_array().map_or(0, Vec::len), answer)],
        Some(nested) => answer[probe.page]
            .as_array()
            .into_iter()
            .flatten()
            .map(|el| (el[nested.rows].as_array().map_or(0, Vec::len), el))
            .collect(),
    }
}

/// Does `subject` say, on its own, that rows were withheld?
///
/// Any of the four disclosures this surface uses. The last is the general one:
/// a count of the population beside a shorter page IS the statement that rows
/// were withheld, and it is what `find_correlated` -- which carries no
/// `truncated` at all -- rests on.
fn discloses_a_cut(subject: &Value, rows: usize) -> bool {
    let rows = rows as u64;
    subject["truncated"] == json!(true)
        || subject["next_cursor"].is_string()
        || subject["other_count"].as_u64().is_some_and(|n| n > 0)
        || subject.as_object().into_iter().flatten().any(|(k, v)| {
            (k.starts_with("total_") || k.starts_with("distinct_"))
                && v.as_u64().is_some_and(|n| n > rows)
        })
}

/// A loaded server over a freshly built capture, plus the directory holding it.
///
/// The directory is returned because dropping it deletes the capture out from
/// under the running server.
fn loaded_session() -> (tempfile::TempDir, McpSession) {
    let dir = tempfile::tempdir().expect("temp dir");
    let capture = dir.path().join(POPULATION_CAPTURE);
    write_population_capture(&capture);
    write_baseline_capture(&dir.path().join(BASELINE_CAPTURE));

    let root = dir.path().to_string_lossy().into_owned();
    let session = McpSession::start(
        capture.to_str().expect("utf-8 capture path"),
        // `--kill-scanner` arms the one detector this fixture trips, so
        // `security_findings` has a population rather than an empty list that
        // would make its comparison vacuous. `--mcp-file-root` is what lets
        // `compare_captures` reach the two files.
        &["--kill-scanner", "--mcp-file-root", &root],
    );
    (dir, session)
}

/// The page-size parameter derived for `tool`.
fn param_for(derived: &[(String, String)], tool: &str) -> String {
    derived
        .iter()
        .find(|(t, _)| t == tool)
        .map(|(_, p)| p.clone())
        .unwrap_or_else(|| {
            panic!(
                "{tool} is probed here and no page-size parameter was derived \
                 for it from src/mcp"
            )
        })
}

// ── the derivation is real, and the table matches it ────────────────────

/// The scan finds a real population, and the table names exactly that set.
///
/// Both directions. A table entry the source does not yield is a probe of
/// something that no longer pages; a derived tool the table does not name is a
/// tool nobody is comparing, which is how this gate would go stale the day one
/// is added.
#[test]
fn the_page_size_surface_is_derived_and_fully_probed() {
    let derived = page_size_tools();
    assert!(
        derived.len() >= MIN_PAGE_SIZE_TOOLS,
        "only {} page-size tool(s) derived from src/mcp: {derived:?}. A \
         derivation that matches almost nothing agrees with any \
         implementation.",
        derived.len()
    );

    let missing: Vec<&String> = derived
        .iter()
        .filter(|(tool, _)| !PROBES.iter().any(|p| p.tool == tool))
        .map(|(tool, _)| tool)
        .collect();
    assert!(
        missing.is_empty(),
        "these tools take a page size and nothing here checks that their \
         capture-wide claims survive one: {missing:?}"
    );

    let stale: Vec<&str> = PROBES
        .iter()
        .map(|p| p.tool)
        .filter(|tool| !derived.iter().any(|(t, _)| t == tool))
        .collect();
    assert!(
        stale.is_empty(),
        "these are probed here and the source no longer gives them a page-size \
         parameter: {stale:?}"
    );
}

/// Every probed tool is a tool the server really registers.
#[test]
fn every_probed_tool_is_registered() {
    let (_dir, mut session) = loaded_session();
    let registered = session.list_tools();
    assert!(
        registered.len() >= 40,
        "only {} tools registered; tools/list stopped answering",
        registered.len()
    );
    for probe in PROBES {
        assert!(
            registered.iter().any(|r| r == probe.tool),
            "{} is probed here and the server does not register it",
            probe.tool
        );
    }
}

// ── the class ───────────────────────────────────────────────────────────

/// A small page must not change what the answer says about the capture.
///
/// One test over every paging tool rather than one per tool, because the
/// property is the same property: the rows are the caller's business and the
/// population is not.
#[test]
fn a_page_size_never_moves_a_capture_wide_claim() {
    let derived = page_size_tools();
    let (_dir, mut session) = loaded_session();

    let mut compared = 0usize;
    for probe in PROBES {
        let param = param_for(&derived, probe.tool);
        let small = answer_at(&mut session, probe, &param, SMALL_PAGE);
        let large = answer_at(&mut session, probe, &param, LARGE_PAGE);

        // The precondition, asserted rather than assumed. Without it a fixture
        // that ran out of rows would make both calls return the same page and
        // this comparison would pass having compared a document to itself.
        let small_page = small.get(probe.page).unwrap_or_else(|| {
            panic!(
                "{}: no `{}` in the answer at {param}={SMALL_PAGE}: {small}",
                probe.tool, probe.page
            )
        });
        let large_page = large.get(probe.page).unwrap_or_else(|| {
            panic!(
                "{}: no `{}` in the answer at {param}={LARGE_PAGE}: {large}",
                probe.tool, probe.page
            )
        });
        assert_ne!(
            small_page, large_page,
            "{}: {param}={SMALL_PAGE} returned the same `{}` as \
             {param}={LARGE_PAGE}, so nothing here is being compared. Give the \
             fixture more rows for this tool.",
            probe.tool, probe.page
        );
        let (Some(small_rows), Some(large_rows)) = (small_page.as_array(), large_page.as_array())
        else {
            panic!(
                "{}: `{}` is not an array at both page sizes",
                probe.tool, probe.page
            )
        };
        let mut nested_compared = 0usize;
        match probe.nested {
            None => assert!(
                small_rows.len() < large_rows.len(),
                "{}: {param}={SMALL_PAGE} returned {} row(s) and \
                 {param}={LARGE_PAGE} returned {}. The small page has to be \
                 SHORTER or the cut never happened.",
                probe.tool,
                small_rows.len(),
                large_rows.len()
            ),
            Some(nested) => {
                assert_eq!(
                    small_rows.len(),
                    large_rows.len(),
                    "{}: `{}` holds its rows one level down because {}, and \
                     its own length moved anyway. The excuse has rotted; \
                     delete it.",
                    probe.tool,
                    probe.page,
                    nested.note
                );
                nested_compared =
                    compare_nested_elements(probe, nested, small_rows, large_rows, &param);
            }
        }

        let mut keys: Vec<&String> = small
            .as_object()
            .unwrap_or_else(|| panic!("{}: the answer is not an object", probe.tool))
            .keys()
            .collect();
        for key in large.as_object().into_iter().flat_map(|o| o.keys()) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }

        let mut per_tool = nested_compared;
        compared += nested_compared;
        for key in keys {
            if key == probe.page
                || PER_PAGE.iter().any(|(k, _)| k == key)
                || probe.per_page.iter().any(|(k, _)| k == key)
            {
                continue;
            }
            per_tool += 1;
            compared += 1;
            assert_eq!(
                small.get(key),
                large.get(key),
                "{}: `{key}` describes the capture, and it moved when the \
                 caller asked for {SMALL_PAGE} row(s) instead of \
                 {LARGE_PAGE}: {:?} against {:?}. A scalar computed off a \
                 truncated page reports a fact about the page as a fact about \
                 the capture.",
                probe.tool,
                small.get(key),
                large.get(key)
            );
        }
        assert!(
            per_tool >= MIN_KEYS_PER_TOOL,
            "{}: only {per_tool} population key(s) survived the exception \
             list, so this tool contributes nothing. The excuses have become \
             the coverage.",
            probe.tool
        );
    }

    assert!(
        compared >= MIN_COMPARED_KEYS,
        "only {compared} key(s) were compared across {} tools; this gate is \
         checking almost nothing",
        PROBES.len()
    );
}

/// Every named exception is a real one: it only moves on a page that says it
/// was cut.
///
/// This is what keeps the exception list from being a silent skip. A field
/// excused as per-page must be accompanied, in the SAME response, by the
/// disclosure that rows were withheld — otherwise a caller cannot tell a short
/// page from a small population, and the excuse is doing the defect's work.
#[test]
fn a_page_that_withheld_rows_says_so() {
    let derived = page_size_tools();
    let (_dir, mut session) = loaded_session();

    let mut checked = 0usize;
    for probe in PROBES {
        let param = param_for(&derived, probe.tool);
        let small = answer_at(&mut session, probe, &param, SMALL_PAGE);
        let subjects = disclosure_subjects(probe, &small);
        assert!(
            !subjects.is_empty(),
            "{}: nothing in the answer holds rows, so this probe checks \
             nothing: {small}",
            probe.tool
        );
        for (rows, subject) in subjects {
            assert!(
                discloses_a_cut(subject, rows),
                "{}: a page of {rows} row(s) says nothing about having \
                 withheld any -- no `truncated`, no `next_cursor`, no overflow \
                 bucket and no count above the rows returned. A caller cannot \
                 tell this from a population that only had {rows}: {subject}",
                probe.tool
            );
            checked += 1;
        }
    }
    assert!(
        checked >= PROBES.len(),
        "only {checked} subject(s) were checked for disclosure across {} \
         probes; every probe has to offer at least one",
        PROBES.len()
    );
}

// ── the pin for the instance ────────────────────────────────────────────

/// `relay_was_consulted` is true even when the relay-asserted orphan is off
/// the page.
///
/// The regression pin for the exact defect: the accumulator has to run over
/// EVERY orphan, not over the ones that fit under `limit`. The fixture places
/// the relay-asserted stream last on purpose and the test asserts that
/// placement, because a fixture whose relay orphan happens to sort first would
/// pass against the buggy accumulator and say nothing.
#[test]
fn reconcile_orphans_reports_a_relay_it_could_not_fit_on_the_page() {
    let (_dir, mut session) = loaded_session();

    let whole = mcp::ok_payload(&session.call("reconcile_orphans", json!({"limit": LARGE_PAGE})));
    let orphans = whole["orphans"]
        .as_array()
        .unwrap_or_else(|| panic!("no orphans array: {whole}"));
    assert!(
        orphans.len() >= MIN_ORPHANS,
        "the fixture holds only {} orphan(s); with fewer than {MIN_ORPHANS} \
         there is no page for a relay assertion to fall off: {whole}",
        orphans.len()
    );
    assert_eq!(
        whole["total_orphans"].as_u64(),
        Some(orphans.len() as u64),
        "the untruncated answer must count what it returned: {whole}"
    );

    let relay_at = orphans
        .iter()
        .position(|o| o["reason"] == json!(RELAY_ASSERTED))
        .unwrap_or_else(|| {
            panic!(
                "no orphan is `{RELAY_ASSERTED}`, so the fixture never got a \
                 relay assertion into the store and this pin would pass \
                 against the defect: {whole}"
            )
        });
    assert!(
        relay_at >= SMALL_PAGE as usize,
        "the relay-asserted orphan is at index {relay_at}, which is ON the \
         first page of {SMALL_PAGE}. The buggy accumulator would see it there \
         and this test would prove nothing."
    );

    let page = mcp::ok_payload(&session.call("reconcile_orphans", json!({"limit": SMALL_PAGE})));
    let rows = page["orphans"]
        .as_array()
        .unwrap_or_else(|| panic!("no orphans array: {page}"));
    assert_eq!(
        rows.len(),
        SMALL_PAGE as usize,
        "the page really is one row: {page}"
    );
    assert!(
        rows.iter().all(|o| o["reason"] != json!(RELAY_ASSERTED)),
        "the one row on this page must NOT be the relay-asserted orphan, or \
         the accumulator never had to look past it: {page}"
    );
    assert_eq!(
        page["truncated"],
        json!(true),
        "a page of {SMALL_PAGE} over {} orphans withheld rows: {page}",
        orphans.len()
    );
    assert_eq!(
        page["relay_was_consulted"],
        json!(true),
        "a relay WAS consulted about this capture and the row proving it did \
         not fit on the page. `false` here turns an absence of evidence into \
         evidence of absence, which is the one reading this field exists to \
         prevent: {page}"
    );
    assert_eq!(
        page["total_orphans"], whole["total_orphans"],
        "the count of orphans is a fact about the capture, not about the \
         page: {page}"
    );
}

/// A fix that always says `true` is no fix. A capture nobody asked about must
/// still say so.
///
/// Without this the accumulator could be hard-wired to `true` and every
/// assertion above would still pass — which is the same defect pointed the
/// other way, and it would read as a relay having answered for a capture where
/// none was ever consulted.
#[test]
fn reconcile_orphans_does_not_invent_a_consultation() {
    let dir = tempfile::tempdir().expect("temp dir");
    let capture = dir.path().join("no-relay.pcap");

    // The same orphan media, and no control message naming any of it.
    let mut timed: Vec<(Vec<u8>, u64)> = Vec::new();
    let mut at = 0u64;
    for k in 0..NEVER_NAMED_ORPHANS {
        let port = 41000 + 2 * k as u16;
        for seq in 0..6u16 {
            timed.push((
                pcap_build::udp_frame(
                    [10, 9, 0, 1],
                    [10, 9, 0, 2],
                    port,
                    port + 1000,
                    &rtp_packet(seq, 0xAA00 + k as u32),
                ),
                at,
            ));
            at += 1_000;
        }
    }
    pcap_build::write_pcap_at(&capture, &timed, 1);

    let mut session = McpSession::start(capture.to_str().expect("utf-8 path"), &[]);
    for page in [SMALL_PAGE, LARGE_PAGE] {
        let answer = mcp::ok_payload(&session.call("reconcile_orphans", json!({"limit": page})));
        assert!(
            answer["total_orphans"].as_u64().unwrap_or_default() >= MIN_ORPHANS as u64,
            "this capture is nothing but orphans and the tool found none: {answer}"
        );
        assert_eq!(
            answer["relay_was_consulted"],
            json!(false),
            "no relay was consulted about this capture, and saying otherwise \
             would dress an unanswered question as an answered one: {answer}"
        );
    }
}
