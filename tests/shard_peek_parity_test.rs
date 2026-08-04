// SPDX-License-Identifier: MIT OR Apache-2.0

//! Differential parity gate: the `--cores` shard peek against the full parse.
//!
//! # What this file exists to make impossible
//!
//! `--cores N` runs a serial dispatcher in front of N workers. The dispatcher
//! calls `peek_host_pair`, which reads only the link + IP headers to get an
//! **outer** host pair, and hashes that pair to choose a worker. The worker
//! then runs the full parse. Two different walks over the same headers, and
//! nothing has ever compared them.
//!
//! When they disagree, nothing says so. The two failure shapes are not equally
//! bad, and the difference is the reason this gate asserts exact values rather
//! than `is_some()`:
//!
//! * **`None` where the full parse succeeds — a LOAD-BALANCE failure.** The
//!   dispatcher's fallback for an unreadable frame is worker 0. Every frame on
//!   the affected link lands on one core; `--cores 16` runs at `--cores 1` and
//!   reports nothing. That is what a peek that stopped at MACsec (0x88E5) did
//!   to a MACsec link, and what a peek that skipped a flat 16 bytes did to
//!   every tagged `-i any` capture on Linux — the default invocation.
//!
//! * **A WRONG pair where the full parse succeeds — a CORRECTNESS failure.**
//!   Each worker owns its own reassembly state, so a flow whose packets are
//!   hashed inconsistently is torn in half: IP fragments of one datagram and
//!   TCP segments of one stream end up on different workers, and neither can
//!   put them back together. Nothing errors; a call simply stops being in the
//!   output. That is what a peek that read a legacy-QinQ (0x9100) VLAN TCI as
//!   an IP header did — it returned a host pair built from TTL, protocol and
//!   checksum bytes, which is *worse* than returning nothing.
//!
//! # How the enumeration is kept honest
//!
//! Three earlier instances of this defect were each found by a person staring
//! at one encapsulation. A hand-written list of cases rots exactly the way the
//! hand-written per-case tests did, so the list here is **checked against the
//! parser's own source**, three ways:
//!
//! 1. **Exhaustive match on `LinkType` (in `src/capture/parse.rs`).** Both
//!    `peek_host_pair` and `slice_link_layer` dispatch on the same closed enum
//!    with no wildcard arm, so a new link type is a COMPILE error in both
//!    until each has an arm for it. That is the primary gate and it needs no
//!    test to fire. [`the_shard_peek_dispatch_is_exhaustive_over_link_type`]
//!    keeps the wildcard from being reintroduced.
//! 2. **One `LinkType` variant per `DLT_*` constant, and every DLT in the case
//!    table** — [`every_link_type_the_parser_decodes_has_a_parity_case`]. A new
//!    variant that never reaches this file fails here.
//! 3. **Every EtherType the walks follow has a case** —
//!    [`every_ethertype_the_ethernet_walk_follows_has_a_parity_case`] and
//!    [`every_ethertype_the_cooked_walk_follows_has_a_parity_case`]. An
//!    encapsulation is *not* a `LinkType` variant — it is an arm of
//!    `eth_payload`'s or `sll_payload`'s `match`, where the compiler cannot
//!    help — so those arms are read out of the source and required to appear
//!    in the table below.
//!
//! ## What this does NOT cover, stated rather than implied
//!
//! * **Network- and transport-layer tunnels.** IP-in-IP, GRE, AH, VXLAN,
//!   GTP-U, Geneve, Teredo and L2TP are deliberately NOT followed by the peek:
//!   those headers appear only in a datagram's *first* fragment, so following
//!   them would scatter one datagram's fragments across workers. The peek
//!   reports the tunnel's own endpoints. `tests/tunnel_integration_test.rs`
//!   pins that decision; this file does not restate it.
//! * **Frame shapes, not just header types.** The table is one representative
//!   frame per encapsulation. Truncation at every byte boundary, hostile
//!   nesting and malformed headers are the fuzz corpus's job, not this gate's.
//! * **The EtherType arms of a *tunnel* decoder** (`tunnel::nsh`,
//!   `tunnel::l2`) beyond the entry points `eth_payload` names.
//! * **Anything a link type's `Other` fallback does.** Where a walk cannot
//!   name the payload, the peek and the parse each make a decision; the table
//!   pins the decision, but the compiler does not.

use chrono::{TimeZone, Utc};
use sipnab::capture::packet::Packet;
use sipnab::capture::parse::{parse_packet, peek_host_pair};
use std::collections::BTreeSet;
use std::net::IpAddr;

// ── the known endpoints every readable case must resolve to ───────────

/// The IPv4 source every readable case carries. Deliberately not
/// `0.0.0.0`/`127.0.0.1`: every octet is non-zero and none of them appears in
/// a VLAN TCI, a MACsec SecTAG or an MPLS label, so a peek that read the wrong
/// offset cannot land on these bytes by accident.
const V4_SRC: [u8; 4] = [198, 51, 100, 7];
/// The IPv4 destination every readable case carries.
const V4_DST: [u8; 4] = [203, 0, 113, 9];

/// `2001:db8::1` — the IPv6 source every readable case carries.
const V6_SRC: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];
/// `2001:db8::2` — the IPv6 destination every readable case carries.
const V6_DST: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
];

fn v4_pair() -> (IpAddr, IpAddr) {
    (IpAddr::from(V4_SRC), IpAddr::from(V4_DST))
}

fn v6_pair() -> (IpAddr, IpAddr) {
    (IpAddr::from(V6_SRC), IpAddr::from(V6_DST))
}

// ── frame builders ────────────────────────────────────────────────────

/// A UDP datagram on 5060 carrying enough bytes to be a transport layer.
fn udp(payload: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&5060u16.to_be_bytes());
    d.extend_from_slice(&5060u16.to_be_bytes());
    d.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    d.extend_from_slice(&[0x00, 0x00]); // checksum elided
    d.extend_from_slice(payload);
    d
}

/// The transport payload every case carries — short, and not SIP, because
/// this gate is about addressing, not about dialogs.
fn body() -> Vec<u8> {
    b"parity".to_vec()
}

/// An IPv4 header (IHL 5, no options) over UDP.
fn ip4() -> Vec<u8> {
    let payload = udp(&body());
    let mut h = vec![0x45, 0x00];
    h.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    h.extend_from_slice(&[0x00, 0x01]); // identification
    h.extend_from_slice(&[0x40, 0x00]); // DF
    h.push(64); // TTL
    h.push(17); // UDP
    h.extend_from_slice(&[0x00, 0x00]); // checksum elided
    h.extend_from_slice(&V4_SRC);
    h.extend_from_slice(&V4_DST);
    h.extend_from_slice(&payload);
    h
}

/// An IPv6 header (no extension headers) over UDP.
fn ip6() -> Vec<u8> {
    let payload = udp(&body());
    let mut h = vec![0x60, 0x00, 0x00, 0x00];
    h.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    h.push(17); // next header: UDP
    h.push(64); // hop limit
    h.extend_from_slice(&V6_SRC);
    h.extend_from_slice(&V6_DST);
    h.extend_from_slice(&payload);
    h
}

/// An Ethernet II frame. The source MAC's Group bit is clear because IEEE
/// 802.3 §3.2.3 reserves it in the Source Address field and the inner-frame
/// decoders use it as a plausibility gate.
fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0xAA; 6];
    f.extend_from_slice(&[0xBA; 6]);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A VLAN tag control information field: PCP 2, DEI clear, VID `100 + i`.
///
/// The priority is not decoration. PCP 2 puts `0x40` in the TCI's first octet,
/// and `0x40 >> 4` is 4 — the version nibble of IPv4 — so a walk that reads a
/// TCI as an IP header does not merely fail on these frames, it FABRICATES a
/// host pair out of the tag and the bytes behind it. That is what the legacy
/// 0x9100 instance of this defect did, and a tag built with priority 0 would
/// let the same bug come back looking like a harmless `None`.
fn tci(i: usize) -> [u8; 2] {
    (0x4000u16 | (100 + i as u16)).to_be_bytes()
}

/// An Ethernet frame whose EtherType chain is `tags` (outermost first) ending
/// at `inner`, e.g. `&[0x88A8, 0x8100]` for 802.1ad QinQ.
fn eth_tagged(tags: &[u16], inner: u16, payload: &[u8]) -> Vec<u8> {
    let mut chain = Vec::new();
    for (i, tag) in tags.iter().enumerate() {
        chain.extend_from_slice(&tag.to_be_bytes());
        chain.extend_from_slice(&tci(i));
    }
    // The chain above is TPID/TCI pairs; the outermost TPID is the frame's own
    // EtherType, so shift by one and append the innermost protocol.
    let mut f = vec![0xAA; 6];
    f.extend_from_slice(&[0xBA; 6]);
    f.extend_from_slice(&chain[..2]);
    for i in 1..tags.len() {
        f.extend_from_slice(&chain[i * 4 - 2..i * 4]); // TCI
        f.extend_from_slice(&chain[i * 4..i * 4 + 2]); // next TPID
    }
    f.extend_from_slice(&chain[tags.len() * 4 - 2..tags.len() * 4]); // last TCI
    f.extend_from_slice(&inner.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A PPPoE Session header (RFC 2516 §4) followed by the PPP Protocol field
/// and `payload`.
fn pppoe(ppp_proto: u16, payload: &[u8]) -> Vec<u8> {
    pppoe_coded(0x11, 0x00, ppp_proto, payload)
}

/// A PPPoE header with explicit VER/TYPE and CODE, so the non-session shapes
/// can be built too.
fn pppoe_coded(ver_type: u8, code: u8, ppp_proto: u16, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![ver_type, code];
    h.extend_from_slice(&0x0001u16.to_be_bytes()); // SESSION_ID
    h.extend_from_slice(&((2 + payload.len()) as u16).to_be_bytes()); // LENGTH
    h.extend_from_slice(&ppp_proto.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

/// One MPLS label stack entry (RFC 3032 §2.1): 20-bit label, 3-bit TC, the S
/// bit, then TTL.
fn mpls_label(label: u32, bottom: bool) -> [u8; 4] {
    ((label << 12) | (u32::from(bottom) << 8) | 64).to_be_bytes()
}

/// An NSH MD Type 1 header (RFC 8300 §2.2): Base + Service Path + the
/// mandatory 16 octets of fixed context, so Length is exactly 6 words.
fn nsh(next_proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0x00, 0x06, 0x01, next_proto];
    h.extend_from_slice(&[0x00, 0x00, 0x00, 0xFF]); // SPI 0, SI 255
    h.extend_from_slice(&[0u8; 16]); // fixed context headers
    h.extend_from_slice(payload);
    h
}

/// Wrap a complete Ethernet frame in a Provider Backbone Bridge I-TAG (IEEE
/// Std 802.1Q-2014 §9.7). The last 12 octets of the 16-octet I-TAG *are* the
/// customer frame's own C-DA and C-SA, so the customer frame follows the
/// 4-octet flags/I-SID directly.
fn pbb(customer: &[u8]) -> Vec<u8> {
    let mut f = vec![0xCC; 6]; // B-DA
    f.extend_from_slice(&[0xDD; 6]); // B-SA
    f.extend_from_slice(&0x88E7u16.to_be_bytes());
    f.push(0x00); // I-PCP / I-DEI / UCA / Res1 / Res2 all clear
    f.extend_from_slice(&[0x00, 0x00, 0x64]); // I-SID 100
    f.extend_from_slice(customer);
    f
}

/// Insert a MACsec SecTAG (IEEE Std 802.1AE-2018 §9.3) between the source MAC
/// and the EtherType that was already there — the transparent insertion the
/// standard describes, with no SCI.
fn macsec(tci_an: u8, base: &[u8]) -> Vec<u8> {
    let mut f = base[0..12].to_vec();
    f.extend_from_slice(&0x88E5u16.to_be_bytes());
    f.push(tci_an); // TCI / AN
    f.push(0x00); // SL
    f.extend_from_slice(&1u32.to_be_bytes()); // PN
    f.extend_from_slice(&base[12..]); // the displaced EtherType onward
    f
}

/// A Linux SLL v1 cooked header (libpcap `SLL_HDR_LEN` = 16) with the given
/// ARPHRD_ type and protocol field, followed by `payload`.
fn sll(arphrd: u16, proto: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&0u16.to_be_bytes()); // packet type: to us
    f.extend_from_slice(&arphrd.to_be_bytes());
    f.extend_from_slice(&6u16.to_be_bytes()); // address length
    f.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0, 0]); // address
    f.extend_from_slice(&proto.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A Linux SLL2 cooked header (20 octets, protocol field at offset 0).
fn sll2(arphrd: u16, proto: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&proto.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes()); // reserved MBZ
    f.extend_from_slice(&2u32.to_be_bytes()); // interface index
    f.extend_from_slice(&arphrd.to_be_bytes());
    f.push(0); // packet type: to us
    f.push(6); // address length
    f.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0, 0]); // address
    f.extend_from_slice(payload);
    f
}

/// A cooked frame carrying a re-inserted VLAN tag.
///
/// libpcap puts a tag the kernel stripped back at `SLL_HDR_LEN - 2`
/// (`set_vlan_offset`, `pcap-linux.c`), i.e. **over** the protocol field: the
/// protocol field becomes the TPID and the payload begins with the TCI and
/// then the protocol the tag encapsulates. Skipping a flat header length here
/// is the third confirmed instance of this defect class.
fn sll_tagged(tags: &[u16], inner: u16, payload: &[u8]) -> Vec<u8> {
    sll(1, tags[0], &vlan_bodies(tags, inner, payload))
}

/// The SLL2 shape of the same thing. libpcap does not re-insert tags on SLL2
/// (`set_vlan_offset` leaves `vlan_offset` at -1 for every other link type),
/// so this arm is unreachable from libpcap's own writer — it is here because
/// `sll_payload` walks it for symmetry and both paths must therefore agree.
fn sll2_tagged(tags: &[u16], inner: u16, payload: &[u8]) -> Vec<u8> {
    sll2(1, tags[0], &vlan_bodies(tags, inner, payload))
}

/// Which cooked-capture version a case is built for.
///
/// A two-variant enum rather than two parallel blocks of cases: SLL2 is not a
/// longer SLL, and every encapsulation has to be proven on both, so the case
/// list is written once and the layout differences live here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cooked {
    V1,
    V2,
}

impl Cooked {
    fn tag(self) -> &'static str {
        match self {
            Self::V1 => "SLL",
            Self::V2 => "SLL2",
        }
    }

    fn dlt(self) -> &'static str {
        match self {
            Self::V1 => "DLT_LINUX_SLL",
            Self::V2 => "DLT_LINUX_SLL2",
        }
    }

    fn dlt_value(self) -> i32 {
        match self {
            Self::V1 => 113,
            Self::V2 => 276,
        }
    }

    fn plain(self, arphrd: u16, proto: u16, payload: &[u8]) -> Vec<u8> {
        match self {
            Self::V1 => sll(arphrd, proto, payload),
            Self::V2 => sll2(arphrd, proto, payload),
        }
    }

    fn tagged(self, tags: &[u16], inner: u16, payload: &[u8]) -> Vec<u8> {
        match self {
            Self::V1 => sll_tagged(tags, inner, payload),
            Self::V2 => sll2_tagged(tags, inner, payload),
        }
    }
}

/// The tag bodies that follow a cooked protocol field that has become a TPID:
/// TCI, then either the next TPID or the encapsulated protocol.
fn vlan_bodies(tags: &[u16], inner: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    for (i, _) in tags.iter().enumerate() {
        b.extend_from_slice(&tci(i)); // TCI
        match tags.get(i + 1) {
            Some(next) => b.extend_from_slice(&next.to_be_bytes()),
            None => b.extend_from_slice(&inner.to_be_bytes()),
        }
    }
    b.extend_from_slice(payload);
    b
}

/// An IEEE 802.1D Configuration BPDU behind an 802.2 LLC header — what a
/// Linux bridge puts on the wire, and what `-i any` writes with the cooked
/// protocol field set to 0x0004 (libpcap's "802.2 LLC").
///
/// This frame is the fourth instance of the defect class. LLC's DSAP is 0x42
/// for STP, and `0x42 >> 4` is 4 — the version nibble of IPv4 — so a peek that
/// skips a flat header length and trusts the nibble reads the root bridge's
/// MAC as a source address and the root path cost as a destination.
fn stp_bpdu() -> Vec<u8> {
    let mut f = vec![0x42, 0x42, 0x03]; // LLC: DSAP, SSAP, control (UI)
    f.extend_from_slice(&[0x00, 0x00]); // protocol identifier
    f.extend_from_slice(&[0x00, 0x00]); // version, BPDU type (configuration)
    f.push(0x00); // flags
    f.extend_from_slice(&[0x80, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // root ID
    f.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // root path cost
    f.extend_from_slice(&[0x80, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // bridge ID
    f.extend_from_slice(&[0x80, 0x01]); // port ID
    f.extend_from_slice(&[0x00, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x0F]); // timers
    f
}

/// A BSD loopback frame (DLT_NULL / DLT_LOOP): a 4-octet address family, then
/// the IP header.
fn loopback(af: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut f = af.to_vec();
    f.extend_from_slice(payload);
    f
}

/// A PPP frame in RFC 1662 §3.1 HDLC-like framing: All-Stations, Unnumbered
/// Information, then the PPP Protocol field.
fn ppp_hdlc(proto: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0xFF, 0x03];
    f.extend_from_slice(&proto.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A PPP frame with no framing: the PPP Protocol field is the first octet
/// pair, which libpcap's LINKTYPE_PPP description allows.
fn ppp_bare(proto: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = proto.to_be_bytes().to_vec();
    f.extend_from_slice(payload);
    f
}

// ── the case table ────────────────────────────────────────────────────

/// What `peek_host_pair` must return for a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    /// Exactly this outer host pair — and, because the enumerated
    /// encapsulations are all link-layer, exactly what the full parse
    /// resolves too.
    Ipv4,
    /// Exactly the IPv6 pair, same rule.
    Ipv6,
    /// `None`, as a deliberate and documented decision. The full parse must
    /// refuse the frame as well: a `None` against a parse that succeeds is a
    /// load-balance collapse, and this is what distinguishes the two.
    Nothing(&'static str),
}

/// One enumerated frame shape.
struct Case {
    /// Human label, used in every failure message.
    what: String,
    /// The `DLT_*` constant NAME in `src/capture/parse.rs` this case
    /// exercises. A name, not a number, so the coverage gate can prove the
    /// number this file uses is the number the parser uses.
    dlt: &'static str,
    /// The DLT number this file believes `dlt` has.
    dlt_value: i32,
    /// Every `ETHERTYPE_*` constant NAME the link walk must traverse to reach
    /// this frame's IP header. Empty where the link type has no EtherType
    /// chain at all (loopback, PPP, bare IP).
    ethertypes: &'static [&'static str],
    /// The frame.
    frame: Vec<u8>,
    /// What the peek must return.
    want: Want,
}

// Built section by section rather than as one `vec![]` literal: the sections
// are the taxonomy this gate is organised around, and a single 400-line
// expression would hide it.
#[allow(clippy::vec_init_then_push)]
fn cases() -> Vec<Case> {
    let v4 = ip4();
    let v6 = ip6();
    let mut c = Vec::new();

    // ── Ethernet II ───────────────────────────────────────────────────
    c.push(Case {
        what: "EN10MB / plain / IPv4".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_IPV4"],
        frame: eth(0x0800, &v4),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "EN10MB / plain / IPv6".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_IPV6"],
        frame: eth(0x86DD, &v6),
        want: Want::Ipv6,
    });
    c.push(Case {
        what: "EN10MB / 802.1Q / IPv4".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_VLAN"],
        frame: eth_tagged(&[0x8100], 0x0800, &v4),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "EN10MB / 802.1Q / IPv6".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_VLAN"],
        frame: eth_tagged(&[0x8100], 0x86DD, &v6),
        want: Want::Ipv6,
    });
    c.push(Case {
        what: "EN10MB / 802.1ad QinQ (0x88A8 + 0x8100) / IPv4".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_QINQ"],
        frame: eth_tagged(&[0x88A8, 0x8100], 0x0800, &v4),
        want: Want::Ipv4,
    });
    // Instance 1 of the defect class: the peek did not skip this tag, read the
    // TCI as an IP header, and returned a pair built from TTL, protocol and
    // checksum bytes.
    c.push(Case {
        what: "EN10MB / legacy QinQ (0x9100 + 0x8100) / IPv4".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_VLAN_LEGACY"],
        frame: eth_tagged(&[0x9100, 0x8100], 0x0800, &v4),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "EN10MB / three stacked tags (the cap) / IPv4".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_VLAN"],
        frame: eth_tagged(&[0x88A8, 0x8100, 0x8100], 0x0800, &v4),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "EN10MB / four stacked tags (past the cap)".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_VLAN"],
        frame: eth_tagged(&[0x88A8, 0x8100, 0x8100, 0x8100], 0x0800, &v4),
        want: Want::Nothing(
            "past MAX_VLAN_TAGS, which is etherparse's LINK_EXTS_CAP: the full \
             parse cannot see this frame's IP header either",
        ),
    });
    c.push(Case {
        what: "EN10MB / PPPoE Session / IPv4".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_PPPOE_SESSION"],
        frame: eth(0x8864, &pppoe(0x0021, &v4)),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "EN10MB / PPPoE Session / IPv6".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_PPPOE_SESSION"],
        frame: eth(0x8864, &pppoe(0x0057, &v6)),
        want: Want::Ipv6,
    });
    c.push(Case {
        what: "EN10MB / 802.1Q + PPPoE Session / IPv4".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_VLAN", "ETHERTYPE_PPPOE_SESSION"],
        frame: eth_tagged(&[0x8100], 0x8864, &pppoe(0x0021, &v4)),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "EN10MB / PPPoE Discovery (PADI)".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &[],
        frame: eth(0x8863, &pppoe_coded(0x11, 0x09, 0x0021, &v4)),
        want: Want::Nothing("Discovery carries TLV tags, not a PPP frame"),
    });
    c.push(Case {
        what: "EN10MB / MPLS unicast (0x8847) / IPv4".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_MPLS_UNICAST"],
        frame: eth(0x8847, &[&mpls_label(16_000, true)[..], &v4].concat()),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "EN10MB / MPLS upstream-assigned (0x8848) / IPv6".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_MPLS_UPSTREAM"],
        frame: eth(0x8848, &[&mpls_label(16_001, true)[..], &v6].concat()),
        want: Want::Ipv6,
    });
    c.push(Case {
        what: "EN10MB / NSH (0x894F) / IPv4".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_NSH"],
        frame: eth(0x894F, &nsh(0x01, &v4)),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "EN10MB / NSH (0x894F) / IPv6".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_NSH"],
        frame: eth(0x894F, &nsh(0x02, &v6)),
        want: Want::Ipv6,
    });
    c.push(Case {
        what: "EN10MB / PBB I-TAG (0x88E7) / IPv4".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_PBB_ITAG"],
        frame: pbb(&eth(0x0800, &v4)),
        want: Want::Ipv4,
    });
    // Instance 2 of the defect class: etherparse decodes MACsec natively, so
    // the full parse worked while the peek returned None for EVERY frame on a
    // MACsec link.
    c.push(Case {
        what: "EN10MB / MACsec integrity-only (0x88E5) / IPv4".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_MACSEC"],
        frame: macsec(0x00, &eth(0x0800, &v4)),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "EN10MB / MACsec integrity-only + 802.1Q / IPv4".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_MACSEC", "ETHERTYPE_VLAN"],
        frame: macsec(0x00, &eth_tagged(&[0x8100], 0x0800, &v4)),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "EN10MB / MACsec encrypted (E and C set)".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &["ETHERTYPE_MACSEC"],
        frame: macsec(0x0C, &eth(0x0800, &v4)),
        want: Want::Nothing("the Secure Data is ciphertext; there is no host pair in it"),
    });
    c.push(Case {
        what: "EN10MB / ARP".into(),
        dlt: "DLT_EN10MB",
        dlt_value: 1,
        ethertypes: &[],
        frame: eth(0x0806, &[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]),
        want: Want::Nothing("ARP is not IP; there is no host pair to shard on"),
    });

    // ── Linux cooked capture, v1 and v2 ───────────────────────────────
    //
    // Built as pairs so the two versions cannot drift apart: SLL2 is not a
    // longer SLL, its protocol field moved to offset 0 and the header grew by
    // four bytes, so a case on one proves nothing about the other.
    for cooked in [Cooked::V1, Cooked::V2] {
        let tag = cooked.tag();
        let dlt = cooked.dlt();
        let dlt_value = cooked.dlt_value();
        c.push(Case {
            what: format!("{tag} / plain / IPv4"),
            dlt,
            dlt_value,
            ethertypes: &["ETHERTYPE_IPV4"],
            frame: cooked.plain(1, 0x0800, &v4),
            want: Want::Ipv4,
        });
        c.push(Case {
            what: format!("{tag} / plain / IPv6"),
            dlt,
            dlt_value,
            ethertypes: &["ETHERTYPE_IPV6"],
            frame: cooked.plain(1, 0x86DD, &v6),
            want: Want::Ipv6,
        });
        // Instance 3 of the defect class: libpcap re-inserts a stripped tag
        // OVER the protocol field, `-i any` is the default invocation on
        // Linux, and every frame of a tagged cooked capture sharded to
        // worker 0.
        c.push(Case {
            what: format!("{tag} / re-inserted 802.1Q tag / IPv4"),
            dlt,
            dlt_value,
            ethertypes: &["ETHERTYPE_VLAN"],
            frame: cooked.tagged(&[0x8100], 0x0800, &v4),
            want: Want::Ipv4,
        });
        c.push(Case {
            what: format!("{tag} / re-inserted 802.1Q tag / IPv6"),
            dlt,
            dlt_value,
            ethertypes: &["ETHERTYPE_VLAN"],
            frame: cooked.tagged(&[0x8100], 0x86DD, &v6),
            want: Want::Ipv6,
        });
        c.push(Case {
            what: format!("{tag} / re-inserted QinQ tag (0x88A8 + 0x8100) / IPv4"),
            dlt,
            dlt_value,
            ethertypes: &["ETHERTYPE_QINQ"],
            frame: cooked.tagged(&[0x88A8, 0x8100], 0x0800, &v4),
            want: Want::Ipv4,
        });
        c.push(Case {
            what: format!("{tag} / re-inserted legacy tag (0x9100 + 0x8100) / IPv4"),
            dlt,
            dlt_value,
            ethertypes: &["ETHERTYPE_VLAN_LEGACY"],
            frame: cooked.tagged(&[0x9100, 0x8100], 0x0800, &v4),
            want: Want::Ipv4,
        });
        // ARPHRD_PPP (512) is what `-i any` stamps on a frame from `ppp0`, and
        // it is one of the types `etherparse` refuses outright — so this case
        // also exercises the parse's manual header-skip fallback.
        c.push(Case {
            what: format!("{tag} / PPPoE Session / IPv4"),
            dlt,
            dlt_value,
            ethertypes: &["ETHERTYPE_PPPOE_SESSION"],
            frame: cooked.plain(512, 0x8864, &pppoe(0x0021, &v4)),
            want: Want::Ipv4,
        });
        c.push(Case {
            what: format!("{tag} / PPPoE Session / IPv6"),
            dlt,
            dlt_value,
            ethertypes: &["ETHERTYPE_PPPOE_SESSION"],
            frame: cooked.plain(512, 0x8864, &pppoe(0x0057, &v6)),
            want: Want::Ipv6,
        });
        c.push(Case {
            what: format!("{tag} / 802.1Q tag + PPPoE Session / IPv4"),
            dlt,
            dlt_value,
            ethertypes: &["ETHERTYPE_VLAN", "ETHERTYPE_PPPOE_SESSION"],
            frame: cooked.tagged(&[0x8100], 0x8864, &pppoe(0x0021, &v4)),
            want: Want::Ipv4,
        });
        c.push(Case {
            what: format!("{tag} / ARPHRD_NETLINK (824)"),
            dlt,
            dlt_value,
            ethertypes: &[],
            frame: cooked.plain(824, 0x0800, &v4),
            want: Want::Nothing(
                "on ARPHRD_NETLINK the protocol field is a Netlink protocol \
                 number, not an EtherType, so the bytes after the header are \
                 not the IP datagram the number would suggest",
            ),
        });
        // 0x0004 is what libpcap's LINKTYPE_LINUX_SLL page lists as 802.2 LLC.
        // The payload begins with DSAP/SSAP, and 0x42 is the Spanning Tree
        // Protocol's — which a Linux bridge under `-i any` produces all day.
        // 0x42 >> 4 is 4: the version nibble of IPv4.
        c.push(Case {
            what: format!("{tag} / 802.2 LLC (protocol 0x0004), an STP BPDU"),
            dlt,
            dlt_value,
            ethertypes: &[],
            frame: cooked.plain(1, 0x0004, &stp_bpdu()),
            want: Want::Nothing("an 802.2 LLC payload is not an IP header"),
        });
    }

    // ── raw and bare IP ───────────────────────────────────────────────
    c.push(Case {
        what: "RAW / IPv4".into(),
        dlt: "DLT_RAW",
        dlt_value: 12,
        ethertypes: &[],
        frame: v4.clone(),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "RAW / IPv6".into(),
        dlt: "DLT_RAW",
        dlt_value: 12,
        ethertypes: &[],
        frame: v6.clone(),
        want: Want::Ipv6,
    });
    c.push(Case {
        what: "RAW / version 5".into(),
        dlt: "DLT_RAW",
        dlt_value: 12,
        ethertypes: &[],
        frame: {
            let mut f = v4.clone();
            f[0] = 0x55;
            f
        },
        want: Want::Nothing("neither IPv4 nor IPv6"),
    });
    c.push(Case {
        what: "IPV4 / IPv4".into(),
        dlt: "DLT_IPV4",
        dlt_value: 228,
        ethertypes: &[],
        frame: v4.clone(),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "IPV4 / an IPv6 datagram".into(),
        dlt: "DLT_IPV4",
        dlt_value: 228,
        ethertypes: &[],
        frame: v6.clone(),
        want: Want::Nothing(
            "LINKTYPE_IPV4 says IPv6 packets in this capture are errors, so \
             the version nibble is checked against the link type",
        ),
    });
    c.push(Case {
        what: "IPV6 / IPv6".into(),
        dlt: "DLT_IPV6",
        dlt_value: 229,
        ethertypes: &[],
        frame: v6.clone(),
        want: Want::Ipv6,
    });
    c.push(Case {
        what: "IPV6 / an IPv4 datagram".into(),
        dlt: "DLT_IPV6",
        dlt_value: 229,
        ethertypes: &[],
        frame: v4.clone(),
        want: Want::Nothing("the mirror of the DLT_IPV4 rule"),
    });

    // ── BSD loopback ──────────────────────────────────────────────────
    c.push(Case {
        what: "NULL / AF_INET, host byte order / IPv4".into(),
        dlt: "DLT_NULL",
        dlt_value: 0,
        ethertypes: &[],
        frame: loopback([2, 0, 0, 0], &v4),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "NULL / AF_INET, network byte order / IPv4".into(),
        dlt: "DLT_NULL",
        dlt_value: 0,
        ethertypes: &[],
        frame: loopback([0, 0, 0, 2], &v4),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "NULL / AF_INET6 = 30 (macOS), host byte order / IPv6".into(),
        dlt: "DLT_NULL",
        dlt_value: 0,
        ethertypes: &[],
        frame: loopback([30, 0, 0, 0], &v6),
        want: Want::Ipv6,
    });
    c.push(Case {
        what: "NULL / AF_UNSPEC".into(),
        dlt: "DLT_NULL",
        dlt_value: 0,
        ethertypes: &[],
        frame: loopback([0, 0, 0, 0], &v4),
        want: Want::Nothing("AF_UNSPEC names no IP family"),
    });
    c.push(Case {
        what: "LOOP / AF_INET, network byte order / IPv4".into(),
        dlt: "DLT_LOOP",
        dlt_value: 108,
        ethertypes: &[],
        frame: loopback([0, 0, 0, 2], &v4),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "LOOP / AF_INET6 = 24, network byte order / IPv6".into(),
        dlt: "DLT_LOOP",
        dlt_value: 108,
        ethertypes: &[],
        frame: loopback([0, 0, 0, 24], &v6),
        want: Want::Ipv6,
    });
    c.push(Case {
        what: "LOOP / AF_INET in host byte order".into(),
        dlt: "DLT_LOOP",
        dlt_value: 108,
        ethertypes: &[],
        frame: loopback([2, 0, 0, 0], &v4),
        want: Want::Nothing(
            "DLT_LOOP carries the family in network byte order always — that \
             is the entire reason OpenBSD defined a second link type",
        ),
    });

    // ── PPP as a link layer ───────────────────────────────────────────
    c.push(Case {
        what: "PPP / HDLC-framed / IPv4".into(),
        dlt: "DLT_PPP",
        dlt_value: 9,
        ethertypes: &[],
        frame: ppp_hdlc(0x0021, &v4),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "PPP / unframed / IPv6".into(),
        dlt: "DLT_PPP",
        dlt_value: 9,
        ethertypes: &[],
        frame: ppp_bare(0x0057, &v6),
        want: Want::Ipv6,
    });
    c.push(Case {
        what: "PPP / LCP".into(),
        dlt: "DLT_PPP",
        dlt_value: 9,
        ethertypes: &[],
        frame: ppp_bare(0xC021, &v4),
        want: Want::Nothing("LCP is real PPP traffic and carries no IP datagram"),
    });
    c.push(Case {
        what: "PPP_SERIAL / HDLC-framed / IPv4".into(),
        dlt: "DLT_PPP_SERIAL",
        dlt_value: 50,
        ethertypes: &[],
        frame: ppp_hdlc(0x0021, &v4),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "PPP_SERIAL / no address+control octets".into(),
        dlt: "DLT_PPP_SERIAL",
        dlt_value: 50,
        ethertypes: &[],
        frame: ppp_bare(0x0021, &v4),
        want: Want::Nothing(
            "libpcap says LINKTYPE_PPP_HDLC frames include the RFC 1662 §3.1 \
             address and control fields, so a frame without them is refused \
             rather than guessed at",
        ),
    });
    c.push(Case {
        what: "PPP_ETHER / PPPoE Session / IPv4".into(),
        dlt: "DLT_PPP_ETHER",
        dlt_value: 51,
        ethertypes: &[],
        frame: pppoe(0x0021, &v4),
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "PPP_ETHER / PPPoE Session, protocol-field-compressed / IPv4".into(),
        dlt: "DLT_PPP_ETHER",
        dlt_value: 51,
        ethertypes: &[],
        frame: {
            // RFC 2516 §7 makes PFC "NOT RECOMMENDED", not forbidden: a
            // one-octet Protocol field of 0x21.
            let mut h = vec![0x11, 0x00];
            h.extend_from_slice(&0x0001u16.to_be_bytes());
            h.extend_from_slice(&((1 + v4.len()) as u16).to_be_bytes());
            h.push(0x21);
            h.extend_from_slice(&v4);
            h
        },
        want: Want::Ipv4,
    });
    c.push(Case {
        what: "PPP_ETHER / PPPoE Discovery CODE".into(),
        dlt: "DLT_PPP_ETHER",
        dlt_value: 51,
        ethertypes: &[],
        frame: pppoe_coded(0x11, 0x09, 0x0021, &v4),
        want: Want::Nothing("a non-zero CODE means the payload is TAGs, not a PPP frame"),
    });

    c
}

fn packet(case: &Case) -> Packet {
    let len = case.frame.len();
    Packet::new(
        Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
        case.frame.clone(),
        len,
        len,
        None,
        case.dlt_value,
    )
}

// ── the gate ──────────────────────────────────────────────────────────

/// Every enumerated frame resolves to the EXACT host pair it carries, or to
/// `None` for a documented reason.
///
/// Exact values, never `is_some()`: the 0x9100 instance of this defect
/// returned `Some` for every frame it fabricated a pair for, so an
/// `is_some()` assertion would have passed on it.
#[test]
fn shard_peek_returns_the_exact_outer_pair_for_every_encapsulation() {
    let mut wrong = Vec::new();
    for case in cases() {
        let (want, why) = match case.want {
            Want::Ipv4 => (Some(v4_pair()), "the pair the frame carries"),
            Want::Ipv6 => (Some(v6_pair()), "the pair the frame carries"),
            Want::Nothing(reason) => (None, reason),
        };
        let got = peek_host_pair(&packet(&case));
        if got != want {
            wrong.push(format!(
                "  {}: want {want:?}, got {got:?}\n      because: {why}",
                case.what
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "the --cores shard peek returned the wrong host pair for {} \
         encapsulation(s):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The differential: the peek and the full parse must agree about every
/// LINK-LAYER encapsulation, in both directions.
///
/// A link-layer header is re-applied to every frame by the forwarding element,
/// so it is on every fragment of a datagram — which is why the peek follows it
/// and why the two walks must not disagree. The three failure classes are
/// named separately because they cost different things:
///
/// * peek `None`, parse OK → every frame on the link lands on worker 0.
/// * peek `Some(x)`, parse OK with `y != x` → the flow is torn across workers
///   and each worker's reassembly sees half of it.
/// * peek `Some(_)`, parse refuses → a shard key for a frame that is about to
///   be discarded. Not a correctness loss, but it is the signature of a
///   fabricated read, so it is enumerated rather than tolerated.
#[test]
fn shard_peek_and_full_parse_agree_on_every_link_layer_encapsulation() {
    let mut collapse = Vec::new();
    let mut torn = Vec::new();
    let mut fabricated = Vec::new();

    for case in cases() {
        let pkt = packet(&case);
        let peek = peek_host_pair(&pkt);
        let parsed = parse_packet(&pkt);
        match (peek, parsed) {
            (Some(p), Ok(full)) => {
                if p != (full.src_addr, full.dst_addr) {
                    torn.push(format!(
                        "  {}: peek {p:?}, full parse {:?}",
                        case.what,
                        (full.src_addr, full.dst_addr)
                    ));
                }
            }
            (None, Ok(full)) => collapse.push(format!(
                "  {}: peek None, full parse {:?}",
                case.what,
                (full.src_addr, full.dst_addr)
            )),
            (Some(p), Err(e)) => fabricated.push(format!(
                "  {}: peek {p:?}, full parse refused ({e})",
                case.what
            )),
            (None, Err(_)) => {}
        }
    }

    assert!(
        torn.is_empty(),
        "CORRECTNESS: the shard peek and the full parse disagree about the \
         host pair for {} encapsulation(s). Each worker owns its own \
         reassembly, so a flow keyed inconsistently is split and neither half \
         reassembles:\n{}",
        torn.len(),
        torn.join("\n")
    );
    assert!(
        collapse.is_empty(),
        "LOAD BALANCE: the shard peek returns None where the full parse \
         succeeds for {} encapsulation(s), so every frame on such a link \
         shards to worker 0:\n{}",
        collapse.len(),
        collapse.join("\n")
    );
    assert!(
        fabricated.is_empty(),
        "FABRICATION: the shard peek invented a host pair for {} frame(s) the \
         full parse refuses:\n{}",
        fabricated.len(),
        fabricated.join("\n")
    );
}

// ── coverage gates: the enumeration must not be hand-maintained ───────

/// The parser's source, read once per gate.
fn parse_source() -> String {
    let path = format!("{}/src/capture/parse.rs", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// The body of a top-level `fn` — from its signature to the first `}` in
/// column 0.
fn body_of(src: &str, signature: &str) -> String {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` not found in src/capture/parse.rs"));
    let rest = &src[start..];
    let end = rest
        .find("\n}\n")
        .unwrap_or_else(|| panic!("no closing brace for `{signature}`"));
    rest[..end].to_string()
}

/// The `{ … }` block introduced by `header`, brace-balanced.
fn block_after(body: &str, header: &str) -> String {
    let start = body
        .find(header)
        .unwrap_or_else(|| panic!("`{header}` not found"));
    let open = start + header.len() - 1;
    let bytes = body.as_bytes();
    let mut depth = 0usize;
    for (i, b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return body[open..=i].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("`{header}` is not brace-balanced");
}

/// Every `const DLT_*: i32 = N;` the parser declares.
fn declared_dlts(src: &str) -> Vec<(String, i32)> {
    let re = regex::Regex::new(r"(?m)^const (DLT_[A-Z0-9_]+): i32 = (-?\d+);").expect("regex");
    let found: Vec<_> = re
        .captures_iter(src)
        .map(|c| (c[1].to_string(), c[2].parse::<i32>().expect("DLT number")))
        .collect();
    assert!(
        found.len() >= 11,
        "the DLT scan found only {} constants — the regex has drifted from the \
         source and this gate would pass vacuously",
        found.len()
    );
    found
}

/// Every variant of the `LinkType` enum.
fn link_type_variants(src: &str) -> Vec<String> {
    let block = block_after(src, "enum LinkType {");
    let re = regex::Regex::new(r"(?m)^    ([A-Z][A-Za-z0-9]*),$").expect("regex");
    let found: Vec<_> = re.captures_iter(&block).map(|c| c[1].to_string()).collect();
    assert!(
        found.len() >= 11,
        "the LinkType variant scan found only {} variants — the regex has \
         drifted and this gate would pass vacuously",
        found.len()
    );
    found
}

/// Every link type the parser decodes is exercised, at the number the parser
/// gives it.
///
/// Two halves, because two things can rot: a `LinkType` variant that no case
/// reaches, and a DLT constant whose number this file copied wrongly.
#[test]
fn every_link_type_the_parser_decodes_has_a_parity_case() {
    let src = parse_source();
    let declared = declared_dlts(&src);
    let variants = link_type_variants(&src);

    assert_eq!(
        variants.len(),
        declared.len(),
        "LinkType has {} variants but the parser declares {} DLT constants; \
         the enum is the closed set the peek and the parse both dispatch on, \
         so exactly one variant per link type is the invariant",
        variants.len(),
        declared.len()
    );

    let cases = cases();
    let covered: BTreeSet<&str> = cases.iter().map(|c| c.dlt).collect();
    let missing: Vec<&String> = declared
        .iter()
        .map(|(n, _)| n)
        .filter(|n| !covered.contains(n.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "these link types are decoded by the parser and have no parity case, \
         so the peek could diverge on them unnoticed: {missing:?}"
    );

    for (name, value) in &declared {
        for case in cases.iter().filter(|c| c.dlt == name) {
            assert_eq!(
                case.dlt_value, *value,
                "{} uses {} for {name}, but the parser declares {value}",
                case.what, case.dlt_value
            );
        }
    }

    let unknown: Vec<&str> = covered
        .iter()
        .copied()
        .filter(|n| !declared.iter().any(|(d, _)| d == n))
        .collect();
    assert!(
        unknown.is_empty(),
        "these cases name a DLT constant the parser does not declare: {unknown:?}"
    );
}

/// Every EtherType the Ethernet walk follows is exercised on EN10MB.
///
/// The encapsulations are arms of `eth_payload`'s `match`, not `LinkType`
/// variants, so the compiler cannot force a new one into this file. Reading
/// the arms out of the source is what replaces that.
#[test]
fn every_ethertype_the_ethernet_walk_follows_has_a_parity_case() {
    let src = parse_source();
    let walked = ethertypes_in(&body_of(&src, "fn eth_payload("));
    let covered = covered_ethertypes(|c| c.dlt == "DLT_EN10MB");
    let missing: Vec<&String> = walked.difference(&covered).collect();
    assert!(
        missing.is_empty(),
        "`eth_payload` follows these EtherTypes and no EN10MB parity case \
         exercises them: {missing:?}"
    );
}

/// Every EtherType the cooked-capture walk follows is exercised on BOTH SLL
/// versions.
///
/// Both, because SLL2 is not a longer SLL — its protocol field moved to offset
/// 0 — so a case on one proves nothing about the other.
#[test]
fn every_ethertype_the_cooked_walk_follows_has_a_parity_case() {
    let src = parse_source();
    let walked = ethertypes_in(&body_of(&src, "fn sll_payload("));
    for dlt in ["DLT_LINUX_SLL", "DLT_LINUX_SLL2"] {
        let covered = covered_ethertypes(|c| c.dlt == dlt);
        let missing: Vec<&String> = walked.difference(&covered).collect();
        assert!(
            missing.is_empty(),
            "`sll_payload` follows these EtherTypes and no {dlt} parity case \
             exercises them: {missing:?}"
        );
    }
}

/// Every `ETHERTYPE_*` constant a function body mentions.
fn ethertypes_in(body: &str) -> BTreeSet<String> {
    let re = regex::Regex::new(r"ETHERTYPE_[A-Z0-9_]+").expect("regex");
    let found: BTreeSet<String> = re.find_iter(body).map(|m| m.as_str().to_string()).collect();
    assert!(
        found.len() >= 6,
        "the EtherType scan found only {} constants — the regex has drifted \
         and this gate would pass vacuously",
        found.len()
    );
    found
}

/// The EtherTypes the case table exercises for the cases `pick` selects.
fn covered_ethertypes(pick: impl Fn(&Case) -> bool) -> BTreeSet<String> {
    cases()
        .iter()
        .filter(|c| pick(c))
        .flat_map(|c| c.ethertypes.iter().map(|e| (*e).to_string()))
        .collect()
}

/// The characters of a brace-balanced block that sit at depth 1 — i.e. the
/// `match`'s own arm patterns, with the body of every arm removed.
///
/// Needed because the arms legitimately contain wildcards of their own: the
/// Ethernet arm matches on `EthPayload` and ends `_ => Ok(sliced)`, which is
/// correct and unrelated. Only a wildcard over the LINK TYPE is the defect.
fn top_level_of(block: &str) -> String {
    let mut out = String::new();
    let mut depth = 0usize;
    for ch in block.chars() {
        match ch {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
        if depth == 1 {
            out.push(ch);
        }
    }
    assert!(
        out.contains("=>"),
        "the depth-1 projection found no match arms, so this gate would pass \
         vacuously"
    );
    out
}

/// The shard peek dispatches on the closed `LinkType` enum with no wildcard
/// arm, so a link type the full parse learns is a COMPILE error here until the
/// peek learns it too.
///
/// This is the gate that makes the whole class impossible rather than merely
/// detected: the three confirmed instances were all found by a person looking
/// at one case, and the fourth encapsulation would have diverged the same way.
#[test]
fn the_shard_peek_dispatch_is_exhaustive_over_link_type() {
    let src = parse_source();
    let wildcard = regex::Regex::new(r"(^|[^A-Za-z0-9_])_([^A-Za-z0-9_]|$)").expect("regex");
    for func in ["fn peek_host_pair(", "fn slice_link_layer<'a>("] {
        // Both functions bind the resolved link type to `link` and match on
        // it; `LinkType::from_dlt` is what turns an unrecognised DLT number
        // away BEFORE the dispatch, which is what lets the dispatch be
        // exhaustive at all.
        let body = body_of(&src, func);
        assert!(
            body.contains("LinkType::from_dlt("),
            "`{func}` no longer resolves the DLT number to the closed LinkType \
             set, so its dispatch cannot be exhaustive"
        );
        let arms = top_level_of(&block_after(&body, "match link {"));
        assert!(
            arms.contains("LinkType::"),
            "`{func}` no longer dispatches on the LinkType enum:\n{arms}"
        );
        assert!(
            !wildcard.is_match(&arms),
            "`{func}` dispatches on LinkType with a wildcard arm, so a link \
             type added to the other walk compiles silently here instead of \
             failing. A wildcard is exactly how the peek and the full parse \
             came to know different sets of link types.\n{arms}"
        );
    }
}
