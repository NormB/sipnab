// SPDX-License-Identifier: MIT OR Apache-2.0

//! UDP-port-keyed tunnel decapsulators: GTP-U, VXLAN, Geneve, Teredo,
//! UDP-encapsulated ESP, and L2TPv2.
//!
//! Every function here takes the **UDP payload** — the bytes after the 8-byte
//! UDP header, bounded by the UDP Length field — plus `base`, that payload's
//! absolute offset within the frame slice. Offsets in the returned [`Inner`]
//! are therefore absolute within the frame, per the module contract.
//!
//! Taking the payload rather than `(frame, offset)` is deliberate. Ethernet
//! pads short frames out to 60 octets, so the frame's tail is *not* the
//! datagram's tail: a NAT-keepalive (RFC 3948 §2.3, exactly one octet of
//! payload) inside IPv4/UDP inside Ethernet is 43 octets on the wire and 60
//! in the capture. A decoder that measured "how much payload is left" from
//! `frame.len()` would see 18 octets where the sender wrote 1, and every
//! length-consistency check below would be checking against padding.
//!
//! # Why destination port only
//!
//! A UDP port is not a protocol identity. Every port in this module is
//! specified as a *destination* port; the matching source port is, in each
//! spec, explicitly a locally-chosen or hash-derived ephemeral value:
//!
//! - GTP-U — TS 29.281 §4.4.2.3: "The UDP Destination Port number shall be
//!   2152 ... The UDP Source Port is a locally allocated port number".
//! - VXLAN — RFC 7348 §5: source port "calculated using a hash of fields from
//!   the inner packet ... RECOMMENDED that the value be in the
//!   dynamic/private port range 49152-65535".
//! - Geneve — RFC 8926 §3.3: "the entire 16-bit range MAY be used to maximize
//!   entropy" for the source port.
//!
//! So an ordinary RTP stream can and does carry 2152, 4789 or 6081 as its
//! ephemeral *source* port. Matching that would read voice samples as a
//! tunnel header and invent an inner call. This module never looks at the
//! source port, and [`decap`] takes only the destination — the type signature
//! is the enforcement.
//!
//! # What every decoder must survive
//!
//! Ports are matched, then the header is *proved*. Each decoder validates the
//! fixed version/reserved bits its spec pins, checks declared lengths against
//! the actual buffer, and requires the first inner header to be structurally
//! plausible before it will report an offset. Anything that disagrees is
//! `None`.
//!
//! One pleasing consequence, worth stating because it is what the RTP
//! rejection tests actually exercise: RFC 3550 §5.1 fixes the top two bits of
//! an RTP packet's first octet to `10` (version 2). Those same two bits are
//! fixed to something else by *five of the six* encapsulations here — VXLAN's
//! flags octet must be `0x08`, Geneve's version must be 0, GTP-U's version
//! must be 1 with PT set, Teredo's first octet is either `0x00` or an IPv6
//! version nibble of 6, and L2TP's T bit must be 0 for a data message. Every
//! one of them rejects RTP on the first byte read.

use super::Inner;

// ── Well-known destination ports ──────────────────────────────────────

/// L2TP, RFC 2661 §8.1: "L2TP uses the registered UDP port 1701".
const PORT_L2TP: u16 = 1701;
/// GTP-U, TS 29.281 §4.4.2.3: "The UDP Destination Port number shall be 2152.
/// It is the registered port number for GTP-U."
const PORT_GTPU: u16 = 2152;
/// Teredo, RFC 4380 §2.7: "The UDP port number at which Teredo servers are
/// waiting for packets. The value of this port is 3544."
const PORT_TEREDO: u16 = 3544;
/// UDP-encapsulated ESP / IKE, RFC 3948 §2.2 ("IKE Header Format for Port
/// 4500").
const PORT_ESP_IN_UDP: u16 = 4500;
/// VXLAN, RFC 7348 §5: "IANA has assigned the value 4789 for the VXLAN UDP
/// port, and this value SHOULD be used by default as the destination UDP
/// port."
const PORT_VXLAN: u16 = 4789;
/// Geneve, RFC 8926 §3.3: "IANA has assigned port 6081 as the fixed well-known
/// destination port for Geneve."
const PORT_GENEVE: u16 = 6081;

/// Lowest destination port this module claims.
const PORT_SPAN_LO: u16 = PORT_L2TP;
/// Width of the window between the lowest and highest claimed port.
const PORT_SPAN_WIDTH: u16 = PORT_GENEVE - PORT_L2TP;

/// Dispatch a UDP payload to the decapsulator for its destination port.
///
/// `payload` is the UDP payload; `base` is that payload's absolute offset in
/// the frame slice, which is added to every offset in the result.
///
/// Returns `None` when the port is not one this module claims, or when the
/// payload fails the claimed protocol's structural validation.
pub(crate) fn decap(payload: &[u8], base: usize, dst_port: u16) -> Option<Inner> {
    // This runs on EVERY UDP packet in the capture, and almost none of them
    // are tunnelled, so saying no has to be nearly free. One wrapping
    // subtract and one unsigned compare reject every port outside
    // [1701, 6081] — which is the whole RTP/RTCP convention (16384-32767,
    // RFC 3551 §8 and every SBC's default), the Linux ephemeral range
    // (32768-60999), and the IANA dynamic range (49152-65535). SIP's 5060
    // falls inside the window and pays for the match below; that is the
    // price of the window being contiguous, and it is three compares.
    if dst_port.wrapping_sub(PORT_SPAN_LO) > PORT_SPAN_WIDTH {
        return None;
    }
    match dst_port {
        PORT_GTPU => gtpu(payload, base),
        PORT_VXLAN => vxlan(payload, base),
        PORT_GENEVE => geneve(payload, base),
        PORT_TEREDO => teredo(payload, base),
        PORT_ESP_IN_UDP => esp_in_udp(payload),
        PORT_L2TP => l2tp(payload, base),
        _ => None,
    }
}

// ── GTP-U (3GPP TS 29.281) ────────────────────────────────────────────

/// Mandatory part of the GTP-U header: flags, message type, length, TEID.
/// TS 29.281 §5.1: "The GTP-U header is a variable length header whose
/// minimum length is 8 bytes."
const GTPU_HEADER_MIN: usize = 8;
/// The optional block — Sequence Number (2), N-PDU Number (1), Next Extension
/// Header Type (1). Figure 5.1-1 NOTE 4 makes it all-or-nothing: the fields
/// "shall be present if and only if any one or more of the S, PN and E flags
/// are set", so a lone S flag still costs four octets, not two.
const GTPU_OPTIONAL_BLOCK: usize = 4;
/// Octet 1 bits 8-4: Version (3 bits), Protocol Type, and the spare bit.
const GTPU_VERSION_PT_SPARE_MASK: u8 = 0xF8;
/// The only acceptable value of [`GTPU_VERSION_PT_SPARE_MASK`]: Version 1
/// ("The version number shall be set to '1'"), PT 1 (GTP rather than the GTP'
/// charging protocol of TS 32.295, whose header fields differ), spare 0.
///
/// The spare bit is checked deliberately, against the spec's own advice —
/// NOTE 0 says "It shall be sent as '0'. The receiver shall not evaluate this
/// bit." A GTP-U *endpoint* must not evaluate it, because a future release
/// may define it and the endpoint would then drop traffic it should forward.
/// A passive analyser is in the opposite position: it has no traffic to drop,
/// and the bit is one more place where an RTP packet masquerading as GTP-U
/// gives itself away. If 3GPP ever assigns it, this constant is where the
/// change lands.
const GTPU_VERSION_1_PT_GTP: u8 = 0x30;
/// Extension header flag (E), octet 1 bit 3.
const GTPU_FLAG_E: u8 = 0x04;
/// Sequence number flag (S), octet 1 bit 2.
const GTPU_FLAG_S: u8 = 0x02;
/// N-PDU number flag (PN), octet 1 bit 1.
const GTPU_FLAG_PN: u8 = 0x01;
/// Message Type 255. Table 6.1-1 and §7.3: "A G-PDU is a packet including a
/// GTP-U header and a T-PDU." Every other user-plane type — Echo Request (1),
/// Echo Response (2), Error Indication (26), Supported Extension Headers
/// Notification (31), End Marker (254) — carries information elements or
/// nothing at all, so decoding one as a packet would invent a flow.
const GTPU_MSG_G_PDU: u8 = 255;
/// Ceiling on the extension-header chain.
///
/// The walk is already bounded — every hop advances at least four octets and
/// is checked against the buffer — so this is not what stops a runaway. It
/// stops a *plausible* runaway: a 1500-octet payload of attacker-chosen
/// length bytes can chain ~370 four-octet extensions, all in bounds, and burn
/// that work on every packet. TS 29.281 §5.2.1 defines two user-plane
/// extension header types; real traffic stacks one.
const GTPU_MAX_EXTENSION_HEADERS: usize = 8;

/// Decapsulate a GTP-U G-PDU (3GPP TS 29.281), returning where the T-PDU
/// starts.
///
/// This is the encapsulation that matters most here: VoLTE/VoNR signalling
/// crosses the mobile core inside GTP-U, so an operator capturing on S1-U,
/// S5/S8 or N3 sees UDP/2152 and — until this function existed — no SIP at
/// all.
///
/// The header is variable-length, driven by the E/S/PN flags and then by a
/// chain of extension headers whose lengths are attacker-controlled input.
/// Every read is bounds-checked and the chain walk is capped; anything that
/// disagrees with §5.1 or §5.2.1 yields `None`.
pub(crate) fn gtpu(payload: &[u8], base: usize) -> Option<Inner> {
    let first = *payload.first()?;
    if first & GTPU_VERSION_PT_SPARE_MASK != GTPU_VERSION_1_PT_GTP {
        return None;
    }
    if *payload.get(1)? != GTPU_MSG_G_PDU {
        return None;
    }

    // §5.1 Length: "the length in octets of the payload, i.e. the rest of the
    // packet following the mandatory part of the GTP header (that is the
    // first 8 octets). The Sequence Number, the N-PDU Number or any Extension
    // headers shall be considered to be part of the payload, i.e. included in
    // the length count."
    //
    // So the whole PDU is 8 + Length octets, and the captured payload can
    // only ever be *shorter* than that — a snaplen truncates, nothing pads
    // (the UDP Length field, not the frame, bounds this slice). A payload
    // longer than the header claims is not GTP-U.
    let declared = usize::from(u16::from_be_bytes([*payload.get(2)?, *payload.get(3)?]));
    if GTPU_HEADER_MIN + declared < payload.len() {
        return None;
    }

    // The TEID is read only to prove it is present. It is deliberately not
    // validated: §5.1 says a peer "shall not assign the value 'all zeros' to
    // its own TEID", but immediately adds that for backward compatibility a
    // receiver "shall accept this value as valid and send the subsequent
    // G-PDU with the TEID field in the header set to the value 'all zeros'".
    // A non-zero-TEID gate would therefore drop conforming traffic.
    payload.get(4..GTPU_HEADER_MIN)?;

    let mut off = GTPU_HEADER_MIN;
    let mut next_extension = 0u8;
    if first & (GTPU_FLAG_E | GTPU_FLAG_S | GTPU_FLAG_PN) != 0 {
        // Reading the last octet of the block proves all four are present.
        let next = *payload.get(off + 3)?;
        if first & GTPU_FLAG_E != 0 {
            next_extension = next;
        }
        off += GTPU_OPTIONAL_BLOCK;
    }

    // §5.2.1: "The Extension Header Length field specifies the length of the
    // particular Extension header in 4 octets units" and "m+1 = n*4 octets,
    // where n is a positive integer" — so the header occupies exactly n*4
    // octets counted from its own Length field, and its final octet is the
    // Next Extension Header Type. "If no such Header follows, then the value
    // of the Next Extension Header Type shall be 0."
    let mut walked = 0usize;
    while next_extension != 0 {
        walked += 1;
        if walked > GTPU_MAX_EXTENSION_HEADERS {
            return None;
        }
        let units = usize::from(*payload.get(off)?);
        if units == 0 {
            // n is "a positive integer". Zero would leave `off` exactly where
            // it was, so the walk re-reads the same octet; the cap above is
            // what actually stops that, and mutation testing confirms both
            // paths return `None`. This branch is a cost bound, not a
            // correctness gate: it ends a hostile chain in one iteration
            // instead of eight.
            return None;
        }
        let end = off.checked_add(units.checked_mul(4)?)?;
        // Reading the last octet proves the whole extension is in the buffer.
        next_extension = *payload.get(end.checked_sub(1)?)?;
        off = end;
    }

    let inner = payload.get(off..)?;
    if !plausible_inner_ip(inner) {
        return None;
    }
    Some(Inner::Ip(base.checked_add(off)?))
}

// ── VXLAN (RFC 7348) ──────────────────────────────────────────────────

/// The fixed 8-octet VXLAN header (RFC 7348 §5).
const VXLAN_HEADER_LEN: usize = 8;
/// The only conforming value of the VXLAN flags octet: the I flag set, the
/// seven R bits clear.
///
/// RFC 7348 §5: "the I flag MUST be set to 1 for a valid VXLAN Network ID
/// (VNI). The other 7 bits (designated "R") are reserved fields and MUST be
/// set to zero on transmission and ignored on receipt."
///
/// The "ignored on receipt" half is deliberately not honoured. Ignoring the R
/// bits would cost seven bits of the structural evidence that this payload is
/// a tunnel header rather than the first octet of a media packet, and a
/// passive analyser pays nothing for strictness: the sender is required to
/// zero them. The known casualty is VXLAN-GBP
/// (`draft-smith-vxlan-group-policy`), which repurposes an R bit and the
/// 24-bit Reserved field for a Group Policy ID on this same port; it is
/// rejected here on purpose, because accepting arbitrary bits in those
/// positions is exactly what makes an RTP payload look like a VXLAN header.
const VXLAN_FLAGS_I_ONLY: u8 = 0x08;

/// Decapsulate VXLAN (RFC 7348 §5), returning where the inner Ethernet frame
/// starts.
///
/// The payload is a complete Ethernet II frame, not a packet, so the result
/// is [`Inner::Ethernet`].
pub(crate) fn vxlan(payload: &[u8], base: usize) -> Option<Inner> {
    if *payload.first()? != VXLAN_FLAGS_I_ONLY {
        return None;
    }
    // "Reserved fields (24 bits and 8 bits): MUST be set to zero on
    // transmission and ignored on receipt." Same reasoning as the flags: 32
    // fixed-zero bits are the single strongest piece of evidence this module
    // has that a payload really is VXLAN.
    if payload.get(1..4)?.iter().any(|&b| b != 0) {
        return None;
    }
    // Octets 4-6 are the VNI and may hold anything.
    if *payload.get(7)? != 0 {
        return None;
    }

    let inner = payload.get(VXLAN_HEADER_LEN..)?;
    if !plausible_inner_ethernet(inner) {
        return None;
    }
    Some(Inner::Ethernet(base.checked_add(VXLAN_HEADER_LEN)?))
}

// ── Geneve (RFC 8926) ─────────────────────────────────────────────────

/// The fixed 8-octet Geneve tunnel header, before any options.
const GENEVE_HEADER_MIN: usize = 8;
/// Ver, the top 2 bits of octet 0. RFC 8926 §3.4: "The current version number
/// is 0. Packets received by a tunnel endpoint with an unknown version MUST
/// be dropped."
const GENEVE_VER_MASK: u8 = 0xC0;
/// Opt Len, the low 6 bits of octet 0, "expressed in 4-byte multiples, not
/// including the 8-byte fixed tunnel header".
const GENEVE_OPT_LEN_MASK: u8 = 0x3F;
/// O, the control-packet bit of octet 1.
const GENEVE_FLAG_O: u8 = 0x80;
/// The 6 reserved bits of octet 1, "which MUST be zero on transmission".
///
/// The C bit (0x40) is deliberately *not* in this mask: it means "one or more
/// options has the critical bit set", which obliges a tunnel *endpoint* to
/// parse the options. A passive observer that skips options by Opt Len is
/// unaffected, and RFC 8926 §3.4 is explicit that "Transit devices MUST NOT
/// drop packets on the basis of this bit."
const GENEVE_RSVD_MASK: u8 = 0x3F;
/// A Geneve option's fixed header: Option Class (2), Type (1), R+Length (1).
const GENEVE_OPTION_HEADER_LEN: usize = 4;
/// The 3 R bits of a Geneve option's fourth octet, "reserved for future use.
/// These bits MUST be zero on transmission".
const GENEVE_OPTION_R_MASK: u8 = 0xE0;
/// A Geneve option's Length, the low 5 bits of its fourth octet, "expressed
/// in 4-byte multiples, excluding the option header".
const GENEVE_OPTION_LEN_MASK: u8 = 0x1F;
/// Protocol Type for an Ethernet payload. RFC 8926 §3.4 describes the field
/// as following "the Ethertype convention, with Ethernet itself being
/// represented by the value 0x6558" (Trans Ether Bridging).
const GENEVE_PROTO_ETHERNET: u16 = 0x6558;
/// Label reported for a Geneve control packet.
const GENEVE_CONTROL_LABEL: &str = "Geneve control packet";

/// Decapsulate Geneve (RFC 8926), returning where the payload starts.
///
/// Geneve's Protocol Type is an EtherType, so the payload may be an Ethernet
/// frame (0x6558) or a bare IP packet, and the result varies accordingly.
///
/// The variable-length options are not merely skipped by Opt Len — they are
/// walked, and their lengths must sum to exactly the region Opt Len declares.
/// That is a requirement, not a heuristic: RFC 8926 §3.5 says "Packets in
/// which the total length of all options is not equal to the 'Opt Len' in the
/// base header are invalid and MUST be silently dropped if received by a
/// tunnel endpoint that processes the options." It also happens to be the
/// strongest single check in this function, because arbitrary bytes almost
/// never sum to a preordained total.
pub(crate) fn geneve(payload: &[u8], base: usize) -> Option<Inner> {
    let ver_opt_len = *payload.first()?;
    if ver_opt_len & GENEVE_VER_MASK != 0 {
        return None;
    }
    let flags = *payload.get(1)?;
    if flags & GENEVE_RSVD_MASK != 0 {
        return None;
    }
    let protocol = u16::from_be_bytes([*payload.get(2)?, *payload.get(3)?]);
    // Octets 4-6 are the VNI; octet 7 is "Reserved field, which MUST be zero
    // on transmission".
    if *payload.get(7)? != 0 {
        return None;
    }

    let options_end = GENEVE_HEADER_MIN
        .checked_add(usize::from(ver_opt_len & GENEVE_OPT_LEN_MASK).checked_mul(4)?)?;
    let mut off = GENEVE_HEADER_MIN;
    while off < options_end {
        // Bounded by construction: Opt Len is 6 bits, so `options_end` is at
        // most 8 + 252, and every iteration advances by at least the 4-octet
        // option header — 63 iterations, worst case.
        let r_and_len = *payload.get(off + 3)?;
        if r_and_len & GENEVE_OPTION_R_MASK != 0 {
            return None;
        }
        let data = usize::from(r_and_len & GENEVE_OPTION_LEN_MASK).checked_mul(4)?;
        off = off
            .checked_add(GENEVE_OPTION_HEADER_LEN)?
            .checked_add(data)?;
    }
    if off != options_end {
        // The last option overshot the declared region.
        return None;
    }

    let inner = payload.get(options_end..)?;
    if flags & GENEVE_FLAG_O != 0 {
        // "This packet contains a control message. Tunnel endpoints MUST NOT
        // forward the payload, and transit devices MUST NOT attempt to
        // interpret it." Reporting it opaque obeys that and still tells the
        // operator the tunnel is there — which is the whole point of the
        // `Opaque` variant.
        return Some(Inner::Opaque(GENEVE_CONTROL_LABEL));
    }

    let at = base.checked_add(options_end)?;
    match protocol {
        GENEVE_PROTO_ETHERNET if plausible_inner_ethernet(inner) => Some(Inner::Ethernet(at)),
        // The Protocol Type and the inner version nibble must agree: a header
        // that says IPv4 over a packet that says IPv6 is not a Geneve packet.
        ETHERTYPE_IPV4 if plausible_inner_ipv4(inner) => Some(Inner::Ip(at)),
        ETHERTYPE_IPV6 if plausible_inner_ipv6(inner) => Some(Inner::Ip(at)),
        _ => None,
    }
}

// ── Teredo (RFC 4380) ─────────────────────────────────────────────────

/// The origin indication encapsulation, "an 8-octet element" (RFC 4380
/// §5.1.1): the `00 00` marker, an obfuscated port, an obfuscated IPv4
/// address.
const TEREDO_ORIGIN_LEN: usize = 8;
/// The fixed part of the authentication encapsulation: the `00 01` marker,
/// ID-len and AU-len (4), then — after the two variable fields — "an 8-octet
/// nonce, and ... a confirmation byte" (9).
const TEREDO_AUTH_FIXED_LEN: usize = 13;
/// The Global Teredo IPv6 Service Prefix, RFC 4380 §2.6: "An IPv6 addressing
/// prefix whose value is 2001:0000:/32."
const TEREDO_PREFIX: [u8; 4] = [0x20, 0x01, 0x00, 0x00];
/// The IPv6 link-local prefix a qualifying Teredo client sources from.
///
/// RFC 4380 §5.1: "In some cases, Teredo nodes use link-local addresses.
/// These addresses contain a link-local prefix (FE80::/64) and a 64-bit
/// identifier" — so the whole first half of the address is fixed, not just
/// the ten bits of the fe80::/10 block RFC 4291 §2.5.6 reserves.
const IPV6_TEREDO_LINK_LOCAL_PREFIX: [u8; 8] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0];
/// The link-local scope all-routers multicast address FF02::2, the
/// destination of the Router Solicitation a Teredo client sends while
/// qualifying (RFC 4380 §5.2.1).
const IPV6_ALL_ROUTERS: [u8; 16] = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

/// Decapsulate Teredo (RFC 4380 §5.1.1), returning where the IPv6 packet
/// starts.
///
/// The UDP payload is an IPv6 packet, optionally behind an authentication
/// encapsulation and/or an origin indication. The two are told apart by their
/// first two octets — `00 01` and `00 00` — which "enables differentiation
/// from IPv6 packets", since a real IPv6 packet starts with a version nibble
/// of 6. Their order is fixed: "the authentication encapsulation MUST be the
/// first element in the UDP payload".
///
/// # What this deliberately does not match
///
/// Only traffic *to* UDP 3544 is decapsulated, and 3544 is the port "at which
/// Teredo servers are waiting for packets" (§2.7) — so this sees the
/// client→server leg and nothing else. Server→client traffic (source 3544,
/// destination the client's ephemeral port) and client↔client bubbles (no
/// 3544 at either end) are invisible here. Reaching them would mean trusting
/// a source port, and IPv6-in-UDP is too weak a shape to carry that: a 4-bit
/// version nibble and a length field that snaplen truncation forces us to
/// check loosely is not enough evidence to start reporting inner addresses.
pub(crate) fn teredo(payload: &[u8], base: usize) -> Option<Inner> {
    let mut off = 0usize;

    if payload.get(off) == Some(&0x00) && payload.get(off + 1) == Some(&0x01) {
        let id_len = usize::from(*payload.get(off + 2)?);
        let au_len = usize::from(*payload.get(off + 3)?);
        off = off
            .checked_add(TEREDO_AUTH_FIXED_LEN)?
            .checked_add(id_len)?
            .checked_add(au_len)?;
    }
    if payload.get(off) == Some(&0x00) && payload.get(off + 1) == Some(&0x00) {
        off = off.checked_add(TEREDO_ORIGIN_LEN)?;
    }

    let inner = payload.get(off..)?;
    if !plausible_inner_ipv6(inner) || !teredo_addressed(inner) {
        return None;
    }
    Some(Inner::Ip(base.checked_add(off)?))
}

/// Whether an IPv6 packet's addresses are consistent with it having arrived
/// on a Teredo server's port.
///
/// This is the check that makes the Teredo decoder safe on a port with only
/// four bits of protocol shape to offer. RFC 4380 §5.2.3 lists exactly what a
/// server accepts on 3544, and every accepted case names a Teredo or
/// link-local address:
///
/// - rule 4 — a Router Solicitation whose "IPv6 source address is an IPv6
///   link-local address" and whose destination "is the link-local scope all
///   routers multicast address (FF02::2)": the qualification exchange, before
///   the client has a Teredo address at all;
/// - rule 5 — "the IPv6 source address is a Teredo IPv6 address";
/// - rule 6 — the source is not a Teredo address but "the IPv6 destination
///   address is a Teredo address allocated through this server".
///
/// Rule 7 is "In all other cases, the packet MUST be silently discarded", so
/// refusing to decapsulate anything else is not extra strictness — it is the
/// same rule the server itself applies.
fn teredo_addressed(ip6: &[u8]) -> bool {
    let (Some(src), Some(dst)) = (ip6.get(8..24), ip6.get(24..40)) else {
        return false;
    };
    if src.starts_with(&TEREDO_PREFIX) || dst.starts_with(&TEREDO_PREFIX) {
        return true;
    }
    src.starts_with(&IPV6_TEREDO_LINK_LOCAL_PREFIX) && dst == IPV6_ALL_ROUTERS
}

// ── UDP-encapsulated ESP (RFC 3948) ───────────────────────────────────

/// Smallest payload that can be an ESP packet: a 4-octet SPI, a 4-octet
/// Sequence Number, and one 4-octet word to hold — at minimum — the Pad
/// Length and Next Header fields that RFC 4303 §2.4 requires to be "right
/// aligned within a 4-byte word". Any real SA adds an IV and an ICV on top.
const ESP_MIN_LEN: usize = 12;
/// Label reported for an ESP payload.
const ESP_LABEL: &str = "UDP-encapsulated ESP";

/// Classify a UDP payload on port 4500 as ESP, IKE, or a NAT-keepalive
/// (RFC 3948 §2).
///
/// Port 4500 multiplexes three things, and RFC 3948 gives an exact
/// discriminator for each:
///
/// - IKE (§2.2) is preceded by a Non-ESP Marker, "4 zero-valued bytes
///   aligning with the SPI field of an ESP packet". It is key exchange, not a
///   tunnel, and carries no user packet — `None`.
/// - A NAT-keepalive (§2.3) is "a one-octet-long payload with the value
///   0xFF". It carries nothing — `None`, rather than being counted as a
///   tunnel whose contents could not be read.
/// - Anything else is ESP, whose "SPI field ... MUST NOT be a zero value"
///   (§2.1) — which is precisely what makes the marker unambiguous.
///
/// ESP returns [`Inner::Opaque`], never an offset. The payload is encrypted;
/// there is no honest way to report what is inside it. "IPsec-encrypted, not
/// decoded" is a diagnosis an operator can act on — it explains a capture
/// that looks empty — and it is the reason this function exists at all.
///
/// # The one decoder that cannot reject RTP
///
/// Every other decapsulator in this module refuses a media packet on
/// structure. ESP cannot: past the SPI, every octet is ciphertext by design,
/// so there is nothing left to check beyond a length floor and RFC 4303
/// §2.4's 4-octet alignment — and a 20 ms G.711 frame is 172 octets, which
/// satisfies both. An RTP stream sent *to* port 4500 is therefore reported as
/// ESP.
///
/// That is acceptable, and it is acceptable for a specific reason rather than
/// as a concession: the wrong answer here is `Opaque`, which invents no
/// address, no port and no dialog. It costs one line of "encrypted payload"
/// in a report. It is not in the same category as the failure this module
/// exists to prevent, which is a fabricated call.
pub(crate) fn esp_in_udp(payload: &[u8]) -> Option<Inner> {
    // Two checks, and between them they also dispose of the NAT-keepalive:
    // its "one-octet-long payload with the value 0xFF" is neither long enough
    // nor 4-octet aligned, so it never reaches the ESP verdict. (There was a
    // separate `matches!(payload, [0xFF])` branch here; mutation testing
    // showed removing it changed no outcome, so it went.)
    //
    // RFC 4303 §2.4: padding ensures "the resulting ciphertext terminates on
    // a 4-byte boundary ... to ensure that the ICV field (if present) is
    // aligned on a 4-byte boundary". Every ICV defined for ESP is itself a
    // multiple of 4 octets, so the whole packet is. NOTE: that last step is a
    // derivation from the set of defined integrity algorithms, not a sentence
    // in the RFC — it is the one check here without a verbatim citation.
    if payload.len() < ESP_MIN_LEN || !payload.len().is_multiple_of(4) {
        return None;
    }
    if payload.get(..4)?.iter().all(|&b| b == 0) {
        return None;
    }
    Some(Inner::Opaque(ESP_LABEL))
}

// ── L2TP (RFC 2661) ───────────────────────────────────────────────────

/// Ver, the low 4 bits of octet 1 of the L2TP header.
const L2TP_VER_MASK: u8 = 0x0F;
/// RFC 2661 §3.1: "Ver MUST be 2 ... The value 1 is reserved to permit
/// detection of L2F packets should they arrive intermixed with L2TP packets.
/// Packets received with an unknown Ver field MUST be discarded."
const L2TP_VERSION_2: u8 = 2;
/// T, the message type bit: "set to 0 for a data message and 1 for a control
/// message".
const L2TP_FLAG_T: u8 = 0x80;
/// L, the Length-present bit.
const L2TP_FLAG_L: u8 = 0x40;
/// S, the Ns/Nr-present bit.
const L2TP_FLAG_S: u8 = 0x08;
/// O, the Offset-Size-present bit.
const L2TP_FLAG_O: u8 = 0x02;
/// The x bits of octet 0 in `|T|L|x|x|S|x|O|P|`. "All reserved bits MUST be
/// set to 0 on outgoing messages and ignored on incoming messages" — checked
/// anyway, for the same reason as VXLAN's R bits.
const L2TP_RESERVED_OCTET0: u8 = 0x34;
/// The x bits of octet 1, ahead of the Ver nibble.
const L2TP_RESERVED_OCTET1: u8 = 0xF0;
/// PPP Address field, RFC 1662 §3.1: the all-stations address 0xFF.
const PPP_ADDRESS: u8 = 0xFF;
/// PPP Control field, RFC 1662 §3.1: Unnumbered Information, 0x03.
const PPP_CONTROL: u8 = 0x03;
/// PPP Protocol field for IPv4.
///
/// PPP Protocol numbers are their own IANA registry and are NOT EtherTypes —
/// 0x0021 here, not 0x0800.
const PPP_PROTO_IPV4: u16 = 0x0021;
/// PPP Protocol field for IPv6 (see [`PPP_PROTO_IPV4`] on the registry).
const PPP_PROTO_IPV6: u16 = 0x0057;

/// Decapsulate an L2TPv2 data message (RFC 2661), returning where the IP
/// packet inside its PPP frame starts.
///
/// # Scope, and what is deliberately left undone
///
/// L2TP is the messiest protocol in this module and this function implements
/// exactly one shape of it: an **L2TPv2 data message carrying a PPP frame
/// carrying IP**. That is the shape a broadband LAC/LNS pair puts SIP inside,
/// and it is fully determined by the bytes on the wire. The rest is not
/// half-supported, it is refused:
///
/// - **L2TPv2 control messages** (T = 1) carry AVPs, not a PPP frame.
///   Rejected.
/// - **L2TPv3 over UDP** (Ver = 3, RFC 3931 §4.1.2.1) is rejected outright,
///   and this is the important one. Its data header is followed by a Cookie
///   of 0, 4 or 8 octets, and RFC 3931 §4.1 is unambiguous about where that
///   length comes from: "The Session ID alone provides the necessary context
///   for all further packet processing, including the presence, size, and
///   value of the Cookie." That context lives in the control channel, which
///   this decoder does not have and a mid-stream capture may never contain.
///   The pseudowire type — Ethernet, PPP, HDLC, Frame Relay — is negotiated
///   there too, so even given the cookie length the payload's *type* would be
///   a guess. Guessing between "skip 0 octets" and "skip 8 octets" and
///   between "this is Ethernet" and "this is PPP" is precisely how a
///   decapsulator invents a flow, so L2TPv3 stays unimplemented until
///   somebody wires control-channel state into it.
/// - **L2F** (Ver = 1) shares this port and is rejected by the version check.
/// - **L2TP over IP** (protocol 115, RFC 3931 §4.1.1) is not a UDP tunnel and
///   is out of this module's scope entirely.
/// - **Non-IP PPP payloads** — LCP, IPCP, MPLS-over-PPP, bridging — are
///   rejected: they are real traffic, but none of them is an IP datagram.
///
/// # Direction
///
/// Only traffic to UDP 1701 is matched. RFC 2661 §8.1 lets the far end reply
/// from an arbitrary port — "The recipient picks a free port on its own
/// system (which may or may not be 1701)" — so on such a tunnel only the
/// initiator→responder half is decoded. Implementations overwhelmingly use
/// 1701 in both directions, where both halves are covered.
pub(crate) fn l2tp(payload: &[u8], base: usize) -> Option<Inner> {
    let octet0 = *payload.first()?;
    let octet1 = *payload.get(1)?;
    if octet1 & L2TP_VER_MASK != L2TP_VERSION_2 {
        return None;
    }
    if octet0 & L2TP_FLAG_T != 0 {
        return None;
    }
    if octet0 & L2TP_RESERVED_OCTET0 != 0 || octet1 & L2TP_RESERVED_OCTET1 != 0 {
        return None;
    }

    let mut off = 2usize;
    if octet0 & L2TP_FLAG_L != 0 {
        // "The Length field indicates the total length of the message in
        // octets" — so, as with GTP-U, the capture can be shorter than the
        // declaration but never longer.
        let declared = usize::from(u16::from_be_bytes([
            *payload.get(off)?,
            *payload.get(off + 1)?,
        ]));
        if declared < payload.len() {
            return None;
        }
        off += 2;
    }

    // RFC 2661 §5.3: "The value of 0 for Session ID and Tunnel ID is special
    // and MUST NOT be used as an Assigned Session ID or Assigned Tunnel ID",
    // and a zero Session ID appears only "during establishment of a new
    // session or tunnel" — i.e. on control messages, which T already
    // excluded. A data message therefore always carries two non-zero ids,
    // and requiring them buys 32 bits of structure on a header that is
    // otherwise only 12 fixed bits deep.
    let tunnel_id = u16::from_be_bytes([*payload.get(off)?, *payload.get(off + 1)?]);
    let session_id = u16::from_be_bytes([*payload.get(off + 2)?, *payload.get(off + 3)?]);
    if tunnel_id == 0 || session_id == 0 {
        return None;
    }
    off += 4;

    if octet0 & L2TP_FLAG_S != 0 {
        // Ns and Nr. Reading the last octet proves both are present.
        payload.get(off + 3)?;
        off += 4;
    }
    if octet0 & L2TP_FLAG_O != 0 {
        // "The Offset Size field, if present, specifies the number of octets
        // past the L2TP header at which the payload data is expected to
        // start. Actual data within the offset padding is undefined."
        //
        // The wording is ambiguous about what "past the L2TP header" is
        // measured from; this reads it the way every deployed implementation
        // does — the pad follows the two-octet Offset Size field — and the
        // bounds check below means a wrong reading fails closed rather than
        // reporting an offset into the middle of a PPP frame.
        let pad = usize::from(u16::from_be_bytes([
            *payload.get(off)?,
            *payload.get(off + 1)?,
        ]));
        off = off.checked_add(2)?.checked_add(pad)?;
    }

    let ip_at = ppp_ip_offset(payload, off)?;
    let inner = payload.get(ip_at..)?;
    if !plausible_inner_ip(inner) {
        return None;
    }
    Some(Inner::Ip(base.checked_add(ip_at)?))
}

/// Offset of the IP header inside the PPP frame beginning at `ppp_off`.
///
/// RFC 2661 §5.3 has the LAC forward PPP frames "stripped of CRC, link
/// framing, and transparency bytes", which removes RFC 1662's HDLC flags,
/// escapes and FCS but not the frame's own Address and Control octets, so
/// they are skipped when present. A peer that negotiated ACFC omits them and
/// the frame starts at the Protocol field instead.
///
/// Returns `None` for a truncated frame or a PPP protocol that carries no IP.
fn ppp_ip_offset(d: &[u8], ppp_off: usize) -> Option<usize> {
    let mut off = ppp_off;
    if d.get(off) == Some(&PPP_ADDRESS) && d.get(off + 1) == Some(&PPP_CONTROL) {
        off += 2;
    }
    let first = *d.get(off)?;
    if first & 1 == 1 {
        // Protocol-Field Compression: a 1-octet field. RFC 1661 §2 assigns
        // PPP Protocol values so that the least significant octet is odd and
        // the most significant octet even, so an odd first byte can only be a
        // compressed field.
        return match u16::from(first) {
            PPP_PROTO_IPV4 | PPP_PROTO_IPV6 => off.checked_add(1),
            _ => None,
        };
    }
    match u16::from_be_bytes([first, *d.get(off + 1)?]) {
        PPP_PROTO_IPV4 | PPP_PROTO_IPV6 => off.checked_add(2),
        _ => None,
    }
}

// ── inner-header plausibility gates ───────────────────────────────────

/// EtherType for IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for IPv6.
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// Smallest IPv4 header, RFC 791 §3.1 (IHL 5, no options).
const IPV4_HEADER_MIN: usize = 20;
/// The IPv6 fixed header, RFC 8200 §3.
const IPV6_HEADER_LEN: usize = 40;

/// EtherTypes an inner Ethernet frame is allowed to carry.
///
/// This is an allow-list, and its job is arithmetic rather than taste: eight
/// accepted values out of 65536 is thirteen bits of evidence that the octets
/// at offset 12 of the claimed frame are an EtherType and not the middle of a
/// voice payload. Every entry either is, or can lead to, something this tool
/// parses — IP directly, or through a VLAN tag, a PPPoE session or an MPLS
/// label stack — with ARP included because an overlay carries a great deal of
/// it and rejecting it would inflate the "tunnel I could not decode" count
/// with frames that were never going to contain a call.
const INNER_ETHERTYPES: [u16; 8] = [
    ETHERTYPE_IPV4,
    0x0806, // ARP
    0x8100, // 802.1Q VLAN
    0x8847, // MPLS, unicast
    0x8848, // MPLS, upstream-assigned label (RFC 5332)
    ETHERTYPE_IPV6,
    0x8864, // PPPoE Session
    0x88A8, // 802.1ad provider bridging
];

/// Whether `d` plausibly begins an IPv4 or IPv6 packet.
///
/// Callers must pass a slice that ends where the inner packet ends — every
/// tunnel in this module bounds its payload by the UDP Length field, so that
/// holds — because the length checks below compare the header's declared size
/// against `d.len()`.
fn plausible_inner_ip(d: &[u8]) -> bool {
    plausible_inner_ipv4(d) || plausible_inner_ipv6(d)
}

/// Whether `d` plausibly begins an IPv4 packet (RFC 791 §3.1).
///
/// A bare IPv4 header is not much structure — roughly thirteen bits' worth —
/// so this is a sanity check on top of a tunnel header that has already been
/// proved, never evidence on its own.
fn plausible_inner_ipv4(d: &[u8]) -> bool {
    // The fixed header is 20 octets. A capture truncated inside it cannot be
    // handed on as "an IP packet starts here": the caller would parse
    // whatever follows the cut as header fields.
    if d.len() < IPV4_HEADER_MIN {
        return false;
    }
    let Some(&version_ihl) = d.first() else {
        return false;
    };
    if version_ihl >> 4 != 4 {
        return false;
    }
    // "IHL is the length of the internet header in 32 bit words, and thus
    // points to the beginning of the data. Note that the minimum value for a
    // correct header is 5."
    let ihl = usize::from(version_ihl & 0x0F);
    if ihl < 5 {
        return false;
    }
    let (Some(&hi), Some(&lo)) = (d.get(2), d.get(3)) else {
        return false;
    };
    // Total Length covers header plus data, so it cannot be smaller than the
    // header, and — the capture being bounded by the datagram — cannot be
    // smaller than what we hold. A snaplen makes it larger; nothing makes it
    // smaller.
    let total = usize::from(u16::from_be_bytes([hi, lo]));
    if total < ihl * 4 || total < d.len() {
        return false;
    }
    // Bit 0 of the Flags field is "reserved, must be zero".
    if d.get(6).is_none_or(|&f| f & 0x80 != 0) {
        return false;
    }
    // Time to Live: "if this field contains the value zero, then the datagram
    // must be destroyed" — such a packet is never seen inside a live tunnel.
    d.get(8).is_some_and(|&ttl| ttl != 0)
}

/// Whether `d` plausibly begins an IPv6 packet (RFC 8200 §3).
fn plausible_inner_ipv6(d: &[u8]) -> bool {
    // As for IPv4: the 40-octet fixed header must be present in full.
    if d.len() < IPV6_HEADER_LEN {
        return false;
    }
    let Some(&version) = d.first() else {
        return false;
    };
    if version >> 4 != 6 {
        return false;
    }
    let (Some(&hi), Some(&lo)) = (d.get(4), d.get(5)) else {
        return false;
    };
    // Payload Length is "length of the IPv6 payload ... in octets", i.e.
    // everything after the 40-octet fixed header. Same asymmetry as IPv4: a
    // truncated capture holds less than the header declares, never more.
    //
    // A Payload Length of zero means a Jumbo Payload option follows (RFC
    // 2675); such a packet is rejected here, which is correct for every
    // encapsulation in this module — none of them carries a jumbogram.
    if 40 + usize::from(u16::from_be_bytes([hi, lo])) < d.len() {
        return false;
    }
    // Hop Limit: "decremented by 1 by each node that forwards the packet. The
    // packet is discarded if Hop Limit is decremented to zero."
    d.get(7).is_some_and(|&hop| hop != 0)
}

/// Whether `d` plausibly begins an Ethernet II frame.
fn plausible_inner_ethernet(d: &[u8]) -> bool {
    // No explicit length floor: the reads below are `.get()`, and reaching
    // octet 13 is exactly the 14-octet Ethernet II header. Mutation testing
    // confirmed a separate `d.len() < 14` guard changed no outcome.
    //
    // The Group bit is "the bottom bit of the first octet" of a MAC address
    // (RFC 7042 §2.1) and marks a multicast identifier. IEEE 802.3 clause
    // 3.2.3 reserves that bit in the *Source* Address field and requires it
    // to be transmitted as 0: a frame is sent by a station, and a station
    // never has a group address. Half of all random octets fail this.
    if d.get(6).is_none_or(|&b| b & 0x01 != 0) {
        return false;
    }
    let (Some(&hi), Some(&lo)) = (d.get(12), d.get(13)) else {
        return false;
    };
    INNER_ETHERTYPES.contains(&u16::from_be_bytes([hi, lo]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── builders ──────────────────────────────────────────────────────

    /// A realistic RTP packet: the RFC 3550 §5.1 fixed header (V=2, P=0, X=0,
    /// CC=0, M=0, PT=0 — PCMU, RFC 3551 §6) followed by 160 octets of G.711
    /// µ-law, i.e. one 20 ms frame at 8 kHz. This is the single most common
    /// payload on a VoIP wire and the thing every decoder here must refuse.
    fn rtp_pcmu() -> Vec<u8> {
        let mut p = Vec::with_capacity(172);
        p.push(0x80); // V=2, P=0, X=0, CC=0
        p.push(0x00); // M=0, PT=0 (PCMU)
        p.extend_from_slice(&4242u16.to_be_bytes()); // sequence number
        p.extend_from_slice(&100_000u32.to_be_bytes()); // timestamp
        p.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // SSRC
        // Speech-like, not a constant: a payload of identical octets could let
        // a decoder pass or fail for reasons unrelated to its header checks.
        for i in 0..160u32 {
            p.push(u8::try_from((0x30 + i * 7) % 251).unwrap());
        }
        p
    }

    /// A well-formed IPv4 packet of exactly `total` octets (`total >= 20`).
    fn ipv4(total: usize) -> Vec<u8> {
        let mut p = vec![0u8; total];
        p[0] = 0x45; // version 4, IHL 5
        p[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        p[8] = 64; // TTL
        p[9] = 17; // UDP
        p
    }

    /// A well-formed IPv6 packet with `payload` octets after the 40-octet
    /// fixed header.
    fn ipv6(payload: usize) -> Vec<u8> {
        let mut p = vec![0u8; 40 + payload];
        p[0] = 0x60; // version 6
        p[4..6].copy_from_slice(&u16::try_from(payload).unwrap().to_be_bytes());
        p[6] = 17; // next header: UDP
        p[7] = 64; // hop limit
        p
    }

    /// A Teredo client's IPv6 packet: source inside the Global Teredo IPv6
    /// Service Prefix 2001:0000::/32 (RFC 4380 §2.6).
    fn ipv6_from_teredo(payload: usize) -> Vec<u8> {
        let mut p = ipv6(payload);
        p[8..12].copy_from_slice(&[0x20, 0x01, 0x00, 0x00]);
        p
    }

    /// An Ethernet II frame carrying `ethertype` over `payload` octets.
    /// Source MAC 02:…:02 is locally administered and individual, so its
    /// Group bit (RFC 7042 §2.1 — the bottom bit of the first octet) is 0.
    fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Assemble a GTP-U PDU. `first` is octet 1 (Version/PT/spare/E/S/PN),
    /// `msg` the Message Type, `after` everything the flags call for (the
    /// 4-octet optional block plus any extension headers), and `inner` the
    /// T-PDU. Length is filled in per TS 29.281 §5.1: "the length in octets
    /// of the payload, i.e. the rest of the packet following the mandatory
    /// part of the GTP header (that is the first 8 octets)".
    fn gtpu_pdu(first: u8, msg: u8, teid: u32, after: &[u8], inner: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(first);
        p.push(msg);
        let len = u16::try_from(after.len() + inner.len()).unwrap();
        p.extend_from_slice(&len.to_be_bytes());
        p.extend_from_slice(&teid.to_be_bytes());
        p.extend_from_slice(after);
        p.extend_from_slice(inner);
        p
    }

    /// A conforming GTP-U G-PDU with no optional fields, carrying `inner`.
    fn gtpu_ok(inner: &[u8]) -> Vec<u8> {
        gtpu_pdu(0x30, 255, 0x1234_5678, &[], inner)
    }

    /// Assemble a VXLAN PDU (RFC 7348 §5).
    fn vxlan_pdu(flags: u8, rsvd24: [u8; 3], vni: [u8; 3], rsvd8: u8, inner: &[u8]) -> Vec<u8> {
        let mut p = vec![flags];
        p.extend_from_slice(&rsvd24);
        p.extend_from_slice(&vni);
        p.push(rsvd8);
        p.extend_from_slice(inner);
        p
    }

    /// A conforming VXLAN PDU carrying `inner` as its Ethernet frame.
    fn vxlan_ok(inner: &[u8]) -> Vec<u8> {
        vxlan_pdu(0x08, [0, 0, 0], [0, 0x30, 0x39], 0, inner)
    }

    /// Assemble a Geneve PDU (RFC 8926 §3.1). `ver_optlen` is octet 0
    /// (Ver in the top 2 bits, Opt Len in the low 6), `flags` is octet 1
    /// (O, C, then 6 reserved bits).
    fn geneve_pdu(ver_optlen: u8, flags: u8, proto: u16, options: &[u8], inner: &[u8]) -> Vec<u8> {
        let mut p = vec![ver_optlen, flags];
        p.extend_from_slice(&proto.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x30, 0x39, 0x00]); // VNI + Reserved
        p.extend_from_slice(options);
        p.extend_from_slice(inner);
        p
    }

    /// One 4-octet Geneve option with no option data (Length 0).
    fn geneve_option_empty() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x00]
    }

    /// Assemble a Teredo authentication encapsulation (RFC 4380 §5.1.1):
    /// `00 01 ID-len AU-len`, then the client id, the authentication value,
    /// an 8-octet nonce and a confirmation byte.
    fn teredo_auth(id_len: u8, au_len: u8) -> Vec<u8> {
        let mut p = vec![0x00, 0x01, id_len, au_len];
        p.extend(std::iter::repeat_n(0xAA, usize::from(id_len)));
        p.extend(std::iter::repeat_n(0xBB, usize::from(au_len)));
        p.extend_from_slice(&[0; 8]); // nonce
        p.push(0x00); // confirmation byte
        p
    }

    /// A Teredo origin indication (RFC 4380 §5.1.1): 8 octets beginning
    /// `00 00`.
    fn teredo_origin() -> Vec<u8> {
        vec![0x00, 0x00, 0xFE, 0xAE, 0xFE, 0xFD, 0xFC, 0xFB]
    }

    /// Which optional fields an assembled L2TPv2 message carries.
    #[derive(Default, Clone, Copy)]
    struct L2tpShape {
        /// T bit: a control message rather than a data message.
        control: bool,
        /// L bit: the Length field is present.
        length: bool,
        /// S bit: Ns and Nr are present.
        sequence: bool,
        /// O bit: the Offset Size field is present, declaring this many pad
        /// octets after it.
        offset_pad: Option<u16>,
    }

    /// Assemble an L2TPv2 message (RFC 2661 §3.1). The Length field, when the
    /// L bit is set, is filled in as the total message length.
    fn l2tpv2(shape: L2tpShape, tunnel: u16, session: u16, body: &[u8]) -> Vec<u8> {
        let mut flags: u16 = 2; // Ver = 2
        if shape.control {
            flags |= 0x8000;
        }
        if shape.length {
            flags |= 0x4000;
        }
        if shape.sequence {
            flags |= 0x0800;
        }
        if shape.offset_pad.is_some() {
            flags |= 0x0200;
        }
        let mut p = flags.to_be_bytes().to_vec();
        let len_at = if shape.length {
            p.extend_from_slice(&[0, 0]);
            Some(2usize)
        } else {
            None
        };
        p.extend_from_slice(&tunnel.to_be_bytes());
        p.extend_from_slice(&session.to_be_bytes());
        if shape.sequence {
            p.extend_from_slice(&[0, 1, 0, 2]); // Ns, Nr
        }
        if let Some(pad) = shape.offset_pad {
            p.extend_from_slice(&pad.to_be_bytes());
            p.extend(std::iter::repeat_n(0xCC, usize::from(pad)));
        }
        p.extend_from_slice(body);
        if let Some(at) = len_at {
            let total = u16::try_from(p.len()).unwrap();
            p[at..at + 2].copy_from_slice(&total.to_be_bytes());
        }
        p
    }

    /// A plain L2TPv2 data message: no Length, no sequence numbers, no
    /// offset.
    fn l2tp_data(body: &[u8]) -> Vec<u8> {
        l2tpv2(L2tpShape::default(), 7, 9, body)
    }

    /// A PPP frame carrying an IPv4 packet: Address 0xFF, Control 0x03, the
    /// PPP Protocol field for IPv4 (0x0021), then the packet.
    fn ppp_ipv4(inner: &[u8]) -> Vec<u8> {
        let mut p = vec![0xFF, 0x03, 0x00, 0x21];
        p.extend_from_slice(inner);
        p
    }

    // ── GTP-U ─────────────────────────────────────────────────────────

    #[test]
    fn gtpu_g_pdu_without_optional_fields_puts_the_t_pdu_at_eight() {
        let p = gtpu_ok(&ipv4(40));
        assert_eq!(gtpu(&p, 0), Some(Inner::Ip(8)));
        assert_eq!(gtpu(&p, 100), Some(Inner::Ip(108)));
    }

    #[test]
    fn gtpu_sequence_flag_adds_the_whole_four_octet_optional_block() {
        // TS 29.281 §5.1 NOTE 4: the Sequence Number, N-PDU Number and Next
        // Extension Header Type "shall be present if and only if any one or
        // more of the S, PN and E flags are set" — all four octets, not just
        // the two the S flag names.
        let p = gtpu_pdu(0x32, 255, 1, &[0, 7, 0, 0], &ipv4(40));
        assert_eq!(gtpu(&p, 0), Some(Inner::Ip(12)));
    }

    #[test]
    fn gtpu_pn_flag_alone_also_adds_all_four_optional_octets() {
        let p = gtpu_pdu(0x31, 255, 1, &[0, 0, 9, 0], &ipv4(40));
        assert_eq!(gtpu(&p, 0), Some(Inner::Ip(12)));
    }

    #[test]
    fn gtpu_a_next_extension_type_is_ignored_when_the_e_flag_is_clear() {
        // §5.1, E flag: "When it is set to '0', the Next Extension Header
        // field either is not present or, if present, shall not be
        // interpreted." The S flag alone brings the four-octet block into
        // existence, and §5.1 tells the sender to zero the unused fields —
        // but a receiver that walked a chain out of whatever is actually in
        // that octet would follow attacker-chosen lengths on a packet with
        // no extension headers at all.
        let p = gtpu_pdu(0x32, 255, 1, &[0, 7, 0, 0x40], &ipv4(40));
        assert_eq!(gtpu(&p, 0), Some(Inner::Ip(12)));
    }

    #[test]
    fn gtpu_one_extension_header_is_walked() {
        // E set; Next Extension Header Type 0x40 (UDP Port), one 4-octet
        // extension whose own next-type is 0 (no more).
        let p = gtpu_pdu(
            0x34,
            255,
            1,
            &[0, 0, 0, 0x40, 0x01, 0x12, 0x34, 0x00],
            &ipv4(40),
        );
        assert_eq!(gtpu(&p, 0), Some(Inner::Ip(16)));
    }

    #[test]
    fn gtpu_a_chain_of_two_extension_headers_is_walked() {
        let after = [
            0, 0, 0, 0x40, 0x01, 0x12, 0x34, 0xC0, 0x01, 0x00, 0x05, 0x00,
        ];
        let p = gtpu_pdu(0x34, 255, 1, &after, &ipv4(40));
        assert_eq!(gtpu(&p, 0), Some(Inner::Ip(20)));
    }

    #[test]
    fn gtpu_extension_header_length_is_read_in_four_octet_units() {
        // TS 29.281 §5.2.1: "The Extension Header Length field specifies the
        // length of the particular Extension header in 4 octets units."
        // Length 2 means the extension occupies 8 octets.
        let after = [0, 0, 0, 0xC0, 0x02, 1, 2, 3, 4, 5, 6, 0x00];
        let p = gtpu_pdu(0x34, 255, 1, &after, &ipv4(40));
        assert_eq!(gtpu(&p, 0), Some(Inner::Ip(20)));
    }

    #[test]
    fn gtpu_accepts_an_inner_ipv6_t_pdu() {
        let p = gtpu_ok(&ipv6(8));
        assert_eq!(gtpu(&p, 0), Some(Inner::Ip(8)));
    }

    #[test]
    fn gtpu_accepts_an_all_zero_teid() {
        // TS 29.281 §5.1 permits it "for backward compatibility": a peer that
        // was handed an all-zero TEID "shall accept this value as valid and
        // send the subsequent G-PDU with the TEID field ... set to the value
        // 'all zeros'". A non-zero-TEID gate would drop real traffic.
        let p = gtpu_pdu(0x30, 255, 0, &[], &ipv4(40));
        assert_eq!(gtpu(&p, 0), Some(Inner::Ip(8)));
    }

    #[test]
    fn gtpu_rejects_every_control_plane_message_type() {
        // Table 6.1-1: only 255 (G-PDU) is "a packet including a GTP-U header
        // and a T-PDU". The rest carry information elements or nothing.
        for msg in [1u8, 2, 26, 31, 254, 0, 100] {
            let p = gtpu_pdu(0x30, msg, 1, &[], &ipv4(40));
            assert_eq!(gtpu(&p, 0), None, "message type {msg} must not decap");
        }
    }

    #[test]
    fn gtpu_rejects_a_version_other_than_one() {
        for ver in [0u8, 2, 3, 4, 5, 6, 7] {
            let p = gtpu_pdu((ver << 5) | 0x10, 255, 1, &[], &ipv4(40));
            assert_eq!(gtpu(&p, 0), None, "version {ver} must not decap");
        }
    }

    #[test]
    fn gtpu_rejects_gtp_prime() {
        // PT = 0 selects GTP' (TS 32.295), whose header fields "may be
        // different in GTP' than in GTP".
        let p = gtpu_pdu(0x20, 255, 1, &[], &ipv4(40));
        assert_eq!(gtpu(&p, 0), None);
    }

    #[test]
    fn gtpu_rejects_a_set_spare_bit() {
        let p = gtpu_pdu(0x38, 255, 1, &[], &ipv4(40));
        assert_eq!(gtpu(&p, 0), None);
    }

    #[test]
    fn gtpu_rejects_a_length_field_that_undercounts_the_payload() {
        let mut p = gtpu_ok(&ipv4(40));
        p[2..4].copy_from_slice(&10u16.to_be_bytes()); // says 10, carries 40
        assert_eq!(gtpu(&p, 0), None);
    }

    #[test]
    fn gtpu_accepts_a_length_field_that_overcounts_a_truncated_capture() {
        // A snaplen'd capture legitimately holds less than the header claims.
        let mut p = gtpu_ok(&ipv4(400));
        p.truncate(8 + 60);
        assert_eq!(gtpu(&p, 0), Some(Inner::Ip(8)));
    }

    #[test]
    fn gtpu_rejects_a_zero_length_extension_header() {
        // Length 0 would advance the walk by nothing. TS 29.281 §5.2.1:
        // "m+1 = n*4 octets, where n is a positive integer".
        let p = gtpu_pdu(0x34, 255, 1, &[0, 0, 0, 0x40, 0x00, 0, 0, 0], &ipv4(40));
        assert_eq!(gtpu(&p, 0), None);
    }

    #[test]
    fn gtpu_rejects_an_extension_chain_that_runs_past_the_payload() {
        let p = gtpu_pdu(0x34, 255, 1, &[0, 0, 0, 0x40, 0xFF, 0, 0, 0], &ipv4(40));
        assert_eq!(gtpu(&p, 0), None);
    }

    #[test]
    fn gtpu_rejects_an_extension_chain_longer_than_the_cap() {
        // Nine chained 4-octet extensions, each pointing at the next.
        let mut after = vec![0, 0, 0, 0x40];
        for _ in 0..9 {
            after.extend_from_slice(&[0x01, 0x00, 0x00, 0x40]);
        }
        let last = after.len() - 1;
        after[last] = 0x00;
        let p = gtpu_pdu(0x34, 255, 1, &after, &ipv4(40));
        assert_eq!(gtpu(&p, 0), None);
    }

    #[test]
    fn gtpu_rejects_a_t_pdu_whose_version_nibble_is_neither_four_nor_six() {
        let p = gtpu_ok(&[0u8; 40]);
        assert_eq!(gtpu(&p, 0), None);
    }

    #[test]
    fn gtpu_rejects_an_inner_ipv4_header_with_a_short_ihl() {
        let mut inner = ipv4(40);
        inner[0] = 0x44; // IHL 4 — below the 20-octet minimum header
        let p = gtpu_ok(&inner);
        assert_eq!(gtpu(&p, 0), None);
    }

    #[test]
    fn gtpu_truncated_at_every_boundary_returns_none() {
        let full = gtpu_pdu(
            0x34,
            255,
            1,
            &[0, 0, 0, 0x40, 0x01, 0x12, 0x34, 0x00],
            &ipv4(40),
        );
        for cut in 0..16 {
            assert_eq!(gtpu(&full[..cut], 0), None, "truncated to {cut} octets");
        }
    }

    // ── VXLAN ─────────────────────────────────────────────────────────

    #[test]
    fn vxlan_puts_the_inner_ethernet_frame_at_eight() {
        let p = vxlan_ok(&eth(0x0800, &ipv4(40)));
        assert_eq!(vxlan(&p, 0), Some(Inner::Ethernet(8)));
        assert_eq!(vxlan(&p, 50), Some(Inner::Ethernet(58)));
    }

    #[test]
    fn vxlan_rejects_a_clear_i_flag() {
        // RFC 7348 §5: "the I flag MUST be set to 1 for a valid VXLAN Network
        // ID (VNI)".
        let p = vxlan_pdu(0x00, [0, 0, 0], [0, 0x30, 0x39], 0, &eth(0x0800, &ipv4(40)));
        assert_eq!(vxlan(&p, 0), None);
    }

    #[test]
    fn vxlan_rejects_each_reserved_flag_bit_on_its_own() {
        for bit in [0x01u8, 0x02, 0x04, 0x10, 0x20, 0x40, 0x80] {
            let p = vxlan_pdu(
                0x08 | bit,
                [0, 0, 0],
                [0, 0x30, 0x39],
                0,
                &eth(0x0800, &ipv4(40)),
            );
            assert_eq!(vxlan(&p, 0), None, "reserved flag bit {bit:#04x}");
        }
    }

    #[test]
    fn vxlan_rejects_a_nonzero_twenty_four_bit_reserved_field() {
        for r in [[1u8, 0, 0], [0, 1, 0], [0, 0, 1]] {
            let p = vxlan_pdu(0x08, r, [0, 0x30, 0x39], 0, &eth(0x0800, &ipv4(40)));
            assert_eq!(vxlan(&p, 0), None, "reserved {r:?}");
        }
    }

    #[test]
    fn vxlan_rejects_a_nonzero_trailing_reserved_octet() {
        let p = vxlan_pdu(0x08, [0, 0, 0], [0, 0x30, 0x39], 1, &eth(0x0800, &ipv4(40)));
        assert_eq!(vxlan(&p, 0), None);
    }

    #[test]
    fn vxlan_rejects_a_group_addressed_inner_source_mac() {
        let mut frame = eth(0x0800, &ipv4(40));
        frame[6] |= 0x01; // Group bit set on the source address
        let p = vxlan_ok(&frame);
        assert_eq!(vxlan(&p, 0), None);
    }

    #[test]
    fn vxlan_rejects_an_inner_ethertype_it_cannot_lead_anywhere_with() {
        for et in [0x0000u16, 0x0005, 0x88CC, 0x88E5, 0x8100 - 1] {
            let p = vxlan_ok(&eth(et, &ipv4(40)));
            assert_eq!(vxlan(&p, 0), None, "ethertype {et:#06x}");
        }
    }

    #[test]
    fn vxlan_accepts_a_vlan_tagged_inner_frame() {
        let p = vxlan_ok(&eth(0x8100, &ipv4(40)));
        assert_eq!(vxlan(&p, 0), Some(Inner::Ethernet(8)));
    }

    #[test]
    fn vxlan_truncated_at_every_boundary_returns_none() {
        let full = vxlan_ok(&eth(0x0800, &ipv4(40)));
        for cut in 0..22 {
            assert_eq!(vxlan(&full[..cut], 0), None, "truncated to {cut} octets");
        }
    }

    // ── Geneve ────────────────────────────────────────────────────────

    #[test]
    fn geneve_without_options_puts_the_inner_frame_at_eight() {
        let p = geneve_pdu(0x00, 0x00, 0x6558, &[], &eth(0x0800, &ipv4(40)));
        assert_eq!(geneve(&p, 0), Some(Inner::Ethernet(8)));
        assert_eq!(geneve(&p, 7), Some(Inner::Ethernet(15)));
    }

    #[test]
    fn geneve_opt_len_is_counted_in_four_octet_multiples() {
        // RFC 8926 §3.4: Opt Len is "the length of the option fields,
        // expressed in 4-byte multiples". Two 4-octet options → Opt Len 2.
        let mut opts = geneve_option_empty();
        opts.extend(geneve_option_empty());
        let p = geneve_pdu(0x02, 0x00, 0x6558, &opts, &eth(0x0800, &ipv4(40)));
        assert_eq!(geneve(&p, 0), Some(Inner::Ethernet(16)));
    }

    #[test]
    fn geneve_option_data_is_counted_in_four_octet_multiples() {
        // One option with Length 2 → 4 octets of header plus 8 of data.
        let mut opts = vec![0x01, 0x02, 0x03, 0x02];
        opts.extend_from_slice(&[0; 8]);
        let p = geneve_pdu(0x03, 0x00, 0x6558, &opts, &eth(0x0800, &ipv4(40)));
        assert_eq!(geneve(&p, 0), Some(Inner::Ethernet(20)));
    }

    #[test]
    fn geneve_ipv4_protocol_type_yields_an_ip_offset() {
        let p = geneve_pdu(0x00, 0x00, 0x0800, &[], &ipv4(40));
        assert_eq!(geneve(&p, 0), Some(Inner::Ip(8)));
    }

    #[test]
    fn geneve_ipv6_protocol_type_yields_an_ip_offset() {
        let p = geneve_pdu(0x00, 0x00, 0x86DD, &[], &ipv6(8));
        assert_eq!(geneve(&p, 0), Some(Inner::Ip(8)));
    }

    #[test]
    fn geneve_rejects_a_protocol_type_that_disagrees_with_the_inner_version_nibble() {
        // A header that says IPv4 over a packet that says IPv6 is not a
        // Geneve packet, and vice versa.
        let v4_over_v6 = geneve_pdu(0x00, 0x00, 0x0800, &[], &ipv6(8));
        assert_eq!(geneve(&v4_over_v6, 0), None);
        let v6_over_v4 = geneve_pdu(0x00, 0x00, 0x86DD, &[], &ipv4(40));
        assert_eq!(geneve(&v6_over_v4, 0), None);
    }

    #[test]
    fn geneve_control_packet_is_reported_opaque_not_decapsulated() {
        // RFC 8926 §3.4, O bit: "Tunnel endpoints MUST NOT forward the
        // payload, and transit devices MUST NOT attempt to interpret it."
        let p = geneve_pdu(0x00, 0x80, 0x6558, &[], &eth(0x0800, &ipv4(40)));
        assert_eq!(geneve(&p, 0), Some(Inner::Opaque("Geneve control packet")));
    }

    #[test]
    fn geneve_critical_options_bit_does_not_block_decapsulation() {
        // The C bit tells an *endpoint* it must parse options. A passive
        // observer that skips them by Opt Len is unaffected.
        let p = geneve_pdu(0x00, 0x40, 0x6558, &[], &eth(0x0800, &ipv4(40)));
        assert_eq!(geneve(&p, 0), Some(Inner::Ethernet(8)));
    }

    #[test]
    fn geneve_rejects_a_nonzero_version() {
        for ver in [1u8, 2, 3] {
            let p = geneve_pdu(ver << 6, 0x00, 0x6558, &[], &eth(0x0800, &ipv4(40)));
            assert_eq!(geneve(&p, 0), None, "version {ver}");
        }
    }

    #[test]
    fn geneve_rejects_a_nonzero_reserved_field() {
        for bit in [0x01u8, 0x02, 0x04, 0x08, 0x10, 0x20] {
            let p = geneve_pdu(0x00, bit, 0x6558, &[], &eth(0x0800, &ipv4(40)));
            assert_eq!(geneve(&p, 0), None, "rsvd bit {bit:#04x}");
        }
    }

    #[test]
    fn geneve_rejects_a_nonzero_reserved_octet_after_the_vni() {
        let mut p = geneve_pdu(0x00, 0x00, 0x6558, &[], &eth(0x0800, &ipv4(40)));
        p[7] = 0x01;
        assert_eq!(geneve(&p, 0), None);
    }

    #[test]
    fn geneve_rejects_options_that_do_not_sum_to_opt_len() {
        // RFC 8926 §3.5: "Packets in which the total length of all options is
        // not equal to the 'Opt Len' in the base header are invalid and MUST
        // be silently dropped".
        //
        // Opt Len is 2, so the options region is octets 8..16 and the payload
        // would begin at 16 — where a perfectly good Ethernet frame has been
        // placed. The single option declares 8 octets of data, so the walk
        // lands at 20 instead. Without the equality check this decodes to
        // `Ethernet(16)`: a real frame, at a real offset, from a packet whose
        // own header says the boundary is somewhere else.
        let mut opts = vec![0x01, 0x02, 0x03, 0x02];
        opts.extend_from_slice(&[0xAA; 4]);
        let p = geneve_pdu(0x02, 0x00, 0x6558, &opts, &eth(0x0800, &ipv4(40)));
        assert_eq!(geneve(&p, 0), None);
    }

    #[test]
    fn geneve_rejects_a_nonzero_option_r_flag() {
        for bit in [0x20u8, 0x40, 0x80] {
            let opts = vec![0x01, 0x02, 0x03, bit];
            let p = geneve_pdu(0x01, 0x00, 0x6558, &opts, &eth(0x0800, &ipv4(40)));
            assert_eq!(geneve(&p, 0), None, "option R bit {bit:#04x}");
        }
    }

    #[test]
    fn geneve_rejects_opt_len_running_past_the_payload() {
        let p = geneve_pdu(0x3F, 0x00, 0x6558, &[], &eth(0x0800, &ipv4(40)));
        assert_eq!(geneve(&p, 0), None);
    }

    #[test]
    fn geneve_rejects_a_protocol_type_it_cannot_lead_anywhere_with() {
        for proto in [0x0000u16, 0x0806, 0x8847, 0x894F] {
            let p = geneve_pdu(0x00, 0x00, proto, &[], &eth(0x0800, &ipv4(40)));
            assert_eq!(geneve(&p, 0), None, "protocol type {proto:#06x}");
        }
    }

    #[test]
    fn geneve_rejects_an_ethernet_payload_that_is_not_a_frame() {
        let mut frame = eth(0x0800, &ipv4(40));
        frame[6] |= 0x01; // group-addressed source MAC
        let p = geneve_pdu(0x00, 0x00, 0x6558, &[], &frame);
        assert_eq!(geneve(&p, 0), None);
    }

    #[test]
    fn geneve_truncated_at_every_boundary_returns_none() {
        let full = geneve_pdu(
            0x01,
            0x00,
            0x6558,
            &geneve_option_empty(),
            &eth(0x0800, &ipv4(40)),
        );
        for cut in 0..26 {
            assert_eq!(geneve(&full[..cut], 0), None, "truncated to {cut} octets");
        }
    }

    // ── Teredo ────────────────────────────────────────────────────────

    #[test]
    fn teredo_simple_encapsulation_starts_at_zero() {
        let p = ipv6_from_teredo(8);
        assert_eq!(teredo(&p, 0), Some(Inner::Ip(0)));
        assert_eq!(teredo(&p, 42), Some(Inner::Ip(42)));
    }

    #[test]
    fn teredo_origin_indication_is_skipped() {
        let mut p = teredo_origin();
        p.extend(ipv6_from_teredo(8));
        assert_eq!(teredo(&p, 0), Some(Inner::Ip(8)));
    }

    #[test]
    fn teredo_authentication_header_is_skipped() {
        let auth = teredo_auth(4, 16);
        let mut p = auth.clone();
        p.extend(ipv6_from_teredo(8));
        assert_eq!(teredo(&p, 0), Some(Inner::Ip(auth.len())));
    }

    #[test]
    fn teredo_authentication_precedes_origin_indication() {
        // RFC 4380 §5.1.1: "the authentication encapsulation MUST be the
        // first element in the UDP payload".
        let auth = teredo_auth(0, 0);
        let mut p = auth.clone();
        p.extend(teredo_origin());
        p.extend(ipv6_from_teredo(8));
        assert_eq!(teredo(&p, 0), Some(Inner::Ip(auth.len() + 8)));
    }

    #[test]
    fn teredo_accepts_a_link_local_router_solicitation() {
        // RFC 4380 §5.2.1 qualification: the client has no Teredo address
        // yet, so the RS goes from its link-local address to FF02::2.
        let mut p = ipv6(24);
        p[6] = 58; // ICMPv6
        p[8..10].copy_from_slice(&[0xFE, 0x80]);
        p[24..26].copy_from_slice(&[0xFF, 0x02]);
        p[39] = 0x02;
        assert_eq!(teredo(&p, 0), Some(Inner::Ip(0)));
    }

    #[test]
    fn teredo_accepts_a_native_source_bound_for_a_teredo_destination() {
        // RFC 4380 §5.2.3 rule 6: source not a Teredo address, destination a
        // Teredo address allocated through this server — "SHOULD be accepted".
        let mut p = ipv6(8);
        p[24..28].copy_from_slice(&[0x20, 0x01, 0x00, 0x00]);
        assert_eq!(teredo(&p, 0), Some(Inner::Ip(0)));
    }

    #[test]
    fn teredo_rejects_a_source_outside_the_link_local_prefix() {
        // FEC0::/10 is site-local (deprecated), not link-local; and an
        // address that starts FE80 but carries bits in the rest of the /64 is
        // not the FE80::/64 form RFC 4380 §5.1 describes.
        for prefix in [
            [0xFE, 0xC0, 0, 0, 0, 0, 0, 0],
            [0xFE, 0x00, 0, 0, 0, 0, 0, 0],
            [0xFE, 0x80, 0, 0, 0, 0, 0, 1],
        ] {
            let mut p = ipv6(24);
            p[6] = 58; // ICMPv6
            p[8..16].copy_from_slice(&prefix);
            p[24..26].copy_from_slice(&[0xFF, 0x02]);
            p[39] = 0x02;
            assert_eq!(teredo(&p, 0), None, "source prefix {prefix:?}");
        }
    }

    #[test]
    fn teredo_rejects_a_link_local_source_not_bound_for_all_routers() {
        // RFC 4380 §5.2.3 rule 4 admits a link-local source only when the
        // destination "is the link-local scope all routers multicast address
        // (FF02::2)". A link-local source with any other destination falls to
        // rule 7, "silently discarded".
        let mut p = ipv6(24);
        p[6] = 58; // ICMPv6
        p[8..10].copy_from_slice(&[0xFE, 0x80]);
        p[24..26].copy_from_slice(&[0xFF, 0x02]);
        p[39] = 0x01; // FF02::1, all-nodes, not all-routers
        assert_eq!(teredo(&p, 0), None);
    }

    #[test]
    fn teredo_rejects_a_packet_with_no_teredo_address_at_either_end() {
        let p = ipv6(8); // both ends all-zero
        assert_eq!(teredo(&p, 0), None);
    }

    #[test]
    fn teredo_rejects_a_version_nibble_that_is_not_six() {
        for nib in [0x40u8, 0x50, 0x70, 0x80, 0x90] {
            let mut p = ipv6_from_teredo(8);
            p[0] = nib;
            assert_eq!(teredo(&p, 0), None, "version nibble {nib:#04x}");
        }
    }

    #[test]
    fn teredo_rejects_an_ipv6_payload_length_that_undercounts_the_capture() {
        let mut p = ipv6_from_teredo(64);
        p[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(teredo(&p, 0), None);
    }

    #[test]
    fn teredo_rejects_an_authentication_header_longer_than_the_payload() {
        let mut p = vec![0x00, 0x01, 0xFF, 0xFF];
        p.extend(ipv6_from_teredo(8));
        assert_eq!(teredo(&p, 0), None);
    }

    #[test]
    fn teredo_truncated_at_every_boundary_returns_none() {
        let mut full = teredo_origin();
        full.extend(ipv6_from_teredo(8));
        for cut in 0..48 {
            assert_eq!(teredo(&full[..cut], 0), None, "truncated to {cut} octets");
        }
    }

    // ── UDP-encapsulated ESP ──────────────────────────────────────────

    #[test]
    fn esp_with_a_nonzero_spi_is_reported_opaque() {
        let mut p = 0x1234_5678u32.to_be_bytes().to_vec(); // SPI
        p.extend_from_slice(&1u32.to_be_bytes()); // sequence number
        p.extend_from_slice(&[0xAB; 24]); // IV + ciphertext + ICV
        assert_eq!(esp_in_udp(&p), Some(Inner::Opaque("UDP-encapsulated ESP")));
    }

    #[test]
    fn esp_rejects_the_non_esp_marker_that_introduces_ike() {
        // RFC 3948 §2.2: "A Non-ESP Marker is 4 zero-valued bytes aligning
        // with the SPI field of an ESP packet." IKE carries no user packet.
        let mut p = vec![0u8; 4];
        p.extend_from_slice(&[0x11; 28]); // IKE header
        assert_eq!(esp_in_udp(&p), None);
    }

    #[test]
    fn esp_rejects_a_nat_keepalive() {
        // RFC 3948 §2.3: "The sender MUST use a one-octet-long payload with
        // the value 0xFF."
        assert_eq!(esp_in_udp(&[0xFF]), None);
    }

    #[test]
    fn esp_rejects_a_payload_that_is_not_a_multiple_of_four_octets() {
        let mut p = 0x1234_5678u32.to_be_bytes().to_vec();
        p.extend_from_slice(&[0xAB; 27]);
        assert_eq!(esp_in_udp(&p), None);
    }

    #[test]
    fn esp_rejects_a_payload_below_the_structural_minimum() {
        for len in [0usize, 4, 8] {
            let p = vec![0x11u8; len];
            assert_eq!(esp_in_udp(&p), None, "{len} octets");
        }
    }

    // ── L2TP ──────────────────────────────────────────────────────────

    #[test]
    fn l2tpv2_data_message_with_a_ppp_ipv4_frame() {
        let p = l2tp_data(&ppp_ipv4(&ipv4(40)));
        assert_eq!(l2tp(&p, 0), Some(Inner::Ip(10)));
        assert_eq!(l2tp(&p, 3), Some(Inner::Ip(13)));
    }

    #[test]
    fn l2tpv2_length_flag_inserts_two_octets_before_the_tunnel_id() {
        let p = l2tpv2(
            L2tpShape {
                length: true,
                ..L2tpShape::default()
            },
            7,
            9,
            &ppp_ipv4(&ipv4(40)),
        );
        assert_eq!(l2tp(&p, 0), Some(Inner::Ip(12)));
    }

    #[test]
    fn l2tpv2_sequence_flag_inserts_ns_and_nr() {
        let p = l2tpv2(
            L2tpShape {
                sequence: true,
                ..L2tpShape::default()
            },
            7,
            9,
            &ppp_ipv4(&ipv4(40)),
        );
        assert_eq!(l2tp(&p, 0), Some(Inner::Ip(14)));
    }

    #[test]
    fn l2tpv2_offset_size_field_and_its_padding_are_skipped() {
        let p = l2tpv2(
            L2tpShape {
                offset_pad: Some(5),
                ..L2tpShape::default()
            },
            7,
            9,
            &ppp_ipv4(&ipv4(40)),
        );
        assert_eq!(l2tp(&p, 0), Some(Inner::Ip(17)));
    }

    #[test]
    fn l2tpv2_all_optional_fields_together() {
        // flags 2 + Length 2 + Tunnel 2 + Session 2 + Ns/Nr 4 + Offset Size 2
        // + 3 pad = 17, then PPP FF 03 00 21 = 4.
        let p = l2tpv2(
            L2tpShape {
                length: true,
                sequence: true,
                offset_pad: Some(3),
                ..L2tpShape::default()
            },
            7,
            9,
            &ppp_ipv4(&ipv4(40)),
        );
        assert_eq!(l2tp(&p, 0), Some(Inner::Ip(21)));
    }

    #[test]
    fn l2tpv2_accepts_a_ppp_frame_without_address_and_control() {
        let mut body = vec![0x00, 0x21];
        body.extend(ipv4(40));
        let p = l2tp_data(&body);
        assert_eq!(l2tp(&p, 0), Some(Inner::Ip(8)));
    }

    #[test]
    fn l2tpv2_accepts_a_protocol_field_compressed_ppp_frame() {
        let mut body = vec![0xFF, 0x03, 0x21];
        body.extend(ipv4(40));
        let p = l2tp_data(&body);
        assert_eq!(l2tp(&p, 0), Some(Inner::Ip(9)));
    }

    #[test]
    fn l2tpv2_accepts_a_ppp_ipv6_frame() {
        let mut body = vec![0xFF, 0x03, 0x00, 0x57];
        body.extend(ipv6(8));
        let p = l2tp_data(&body);
        assert_eq!(l2tp(&p, 0), Some(Inner::Ip(10)));
    }

    #[test]
    fn l2tp_rejects_a_control_message() {
        // T = 1: the payload is AVPs, not a PPP frame.
        let p = l2tpv2(
            L2tpShape {
                control: true,
                length: true,
                sequence: true,
                ..L2tpShape::default()
            },
            7,
            9,
            &ppp_ipv4(&ipv4(40)),
        );
        assert_eq!(l2tp(&p, 0), None);
    }

    #[test]
    fn l2tp_rejects_version_one_which_is_l2f() {
        // RFC 2661 §8.1: "Port 1701 is used for both L2F and L2TP packets.
        // The Version field ... L2F uses a value of 1".
        let mut p = l2tp_data(&ppp_ipv4(&ipv4(40)));
        p[1] = 1;
        assert_eq!(l2tp(&p, 0), None);
    }

    #[test]
    fn l2tp_rejects_version_three_because_the_cookie_length_is_unknowable() {
        // RFC 3931 §4.1: "The Session ID alone provides the necessary context
        // for all further packet processing, including the presence, size,
        // and value of the Cookie" — context this decoder does not have.
        let mut p = l2tp_data(&ppp_ipv4(&ipv4(40)));
        p[1] = 3;
        assert_eq!(l2tp(&p, 0), None);
    }

    #[test]
    fn l2tp_rejects_a_set_reserved_bit() {
        for (byte, bit) in [(0usize, 0x20u8), (0, 0x10), (0, 0x04), (1, 0x10), (1, 0x80)] {
            let mut p = l2tp_data(&ppp_ipv4(&ipv4(40)));
            p[byte] |= bit;
            assert_eq!(l2tp(&p, 0), None, "reserved bit {bit:#04x} in octet {byte}");
        }
    }

    #[test]
    fn l2tp_rejects_a_zero_tunnel_or_session_id() {
        // RFC 2661 §5.3: "The value of 0 for Session ID and Tunnel ID is
        // special and MUST NOT be used as an Assigned Session ID or Assigned
        // Tunnel ID" — a data message always carries assigned, non-zero ids.
        for (t, s) in [(0u16, 9u16), (7, 0), (0, 0)] {
            let p = l2tpv2(L2tpShape::default(), t, s, &ppp_ipv4(&ipv4(40)));
            assert_eq!(l2tp(&p, 0), None, "tunnel {t} session {s}");
        }
    }

    #[test]
    fn l2tp_rejects_a_length_field_that_undercounts_the_message() {
        let mut p = l2tpv2(
            L2tpShape {
                length: true,
                ..L2tpShape::default()
            },
            7,
            9,
            &ppp_ipv4(&ipv4(40)),
        );
        p[2..4].copy_from_slice(&12u16.to_be_bytes());
        assert_eq!(l2tp(&p, 0), None);
    }

    #[test]
    fn l2tp_rejects_a_ppp_protocol_that_is_not_ip() {
        for proto in [0xC021u16, 0x8021, 0x0057 + 1, 0x0000] {
            let mut body = vec![0xFF, 0x03];
            body.extend_from_slice(&proto.to_be_bytes());
            body.extend(ipv4(40));
            let p = l2tp_data(&body);
            assert_eq!(l2tp(&p, 0), None, "PPP protocol {proto:#06x}");
        }
    }

    #[test]
    fn l2tp_rejects_an_offset_size_that_runs_past_the_payload() {
        let mut p = l2tpv2(
            L2tpShape {
                offset_pad: Some(2),
                ..L2tpShape::default()
            },
            7,
            9,
            &ppp_ipv4(&ipv4(40)),
        );
        p[6..8].copy_from_slice(&4000u16.to_be_bytes());
        assert_eq!(l2tp(&p, 0), None);
    }

    #[test]
    fn l2tp_truncated_at_every_boundary_returns_none() {
        let full = l2tpv2(
            L2tpShape {
                length: true,
                sequence: true,
                offset_pad: Some(3),
                ..L2tpShape::default()
            },
            7,
            9,
            &ppp_ipv4(&ipv4(40)),
        );
        for cut in 0..24 {
            assert_eq!(l2tp(&full[..cut], 0), None, "truncated to {cut} octets");
        }
    }

    // ── dispatch ──────────────────────────────────────────────────────

    #[test]
    fn dispatch_routes_each_claimed_destination_port() {
        assert_eq!(decap(&gtpu_ok(&ipv4(40)), 0, PORT_GTPU), Some(Inner::Ip(8)));
        assert_eq!(
            decap(&vxlan_ok(&eth(0x0800, &ipv4(40))), 0, PORT_VXLAN),
            Some(Inner::Ethernet(8))
        );
        assert_eq!(
            decap(
                &geneve_pdu(0x00, 0x00, 0x6558, &[], &eth(0x0800, &ipv4(40))),
                0,
                PORT_GENEVE
            ),
            Some(Inner::Ethernet(8))
        );
        assert_eq!(
            decap(&ipv6_from_teredo(8), 0, PORT_TEREDO),
            Some(Inner::Ip(0))
        );
        let mut esp = 0x1234_5678u32.to_be_bytes().to_vec();
        esp.extend_from_slice(&[0xAB; 28]);
        assert_eq!(
            decap(&esp, 0, PORT_ESP_IN_UDP),
            Some(Inner::Opaque("UDP-encapsulated ESP"))
        );
        assert_eq!(
            decap(&l2tp_data(&ppp_ipv4(&ipv4(40))), 0, PORT_L2TP),
            Some(Inner::Ip(10))
        );
    }

    #[test]
    fn dispatch_adds_the_base_offset_to_every_result() {
        assert_eq!(
            decap(&gtpu_ok(&ipv4(40)), 64, PORT_GTPU),
            Some(Inner::Ip(72))
        );
    }

    #[test]
    fn dispatch_returns_none_for_an_unclaimed_destination_port() {
        let p = gtpu_ok(&ipv4(40));
        for port in [
            0u16, 53, 5060, 5061, 1700, 1702, 2151, 2153, 6080, 6082, 16384, 65535,
        ] {
            assert_eq!(decap(&p, 0, port), None, "port {port}");
        }
    }

    #[test]
    fn dispatch_never_looks_at_the_source_port() {
        // The realistic false positive: an RTP stream whose ephemeral source
        // port happens to be a tunnel port, sent to an ordinary media port.
        // Only the destination is consulted, so nothing matches at all.
        let rtp = rtp_pcmu();
        for dst in [5004u16, 16384, 40000] {
            assert_eq!(decap(&rtp, 0, dst), None, "media destination {dst}");
        }
    }

    #[test]
    fn a_realistic_rtp_packet_is_rejected_on_every_decapsulating_port() {
        // The heart of the false-positive defence. If any of these ever
        // returns an offset, sipnab is inventing a call out of voice samples.
        let rtp = rtp_pcmu();
        assert_eq!(gtpu(&rtp, 0), None);
        assert_eq!(vxlan(&rtp, 0), None);
        assert_eq!(geneve(&rtp, 0), None);
        assert_eq!(teredo(&rtp, 0), None);
        assert_eq!(l2tp(&rtp, 0), None);
        for port in [PORT_GTPU, PORT_VXLAN, PORT_GENEVE, PORT_TEREDO, PORT_L2TP] {
            assert_eq!(decap(&rtp, 0, port), None, "destination port {port}");
        }
    }

    #[test]
    fn rtp_sent_to_port_4500_is_opaque_and_that_is_the_correct_answer() {
        // ESP is the one decoder that cannot structurally reject RTP: past
        // the SPI every octet is ciphertext, so there is nothing left to
        // check. That is safe *because* the answer is `Opaque` — it reports
        // "encrypted payload, cannot decode", which invents no addresses, no
        // ports and no dialog. A wrong `Opaque` costs one line of diagnosis;
        // a wrong `Ip` would cost a fabricated call.
        //
        // Asserted rather than merely commented so that anyone who later
        // makes ESP return an offset has to come here and confront it.
        assert_eq!(
            esp_in_udp(&rtp_pcmu()),
            Some(Inner::Opaque("UDP-encapsulated ESP"))
        );
    }

    #[test]
    fn every_decoder_survives_an_empty_payload() {
        assert_eq!(gtpu(&[], 0), None);
        assert_eq!(vxlan(&[], 0), None);
        assert_eq!(geneve(&[], 0), None);
        assert_eq!(teredo(&[], 0), None);
        assert_eq!(esp_in_udp(&[]), None);
        assert_eq!(l2tp(&[], 0), None);
        for port in [
            PORT_L2TP,
            PORT_GTPU,
            PORT_TEREDO,
            PORT_ESP_IN_UDP,
            PORT_VXLAN,
            PORT_GENEVE,
        ] {
            assert_eq!(decap(&[], 0, port), None, "port {port}");
        }
    }

    // ── inner-header plausibility gates ───────────────────────────────

    #[test]
    fn inner_ipv4_gate_accepts_a_well_formed_header() {
        assert!(plausible_inner_ipv4(&ipv4(40)));
        assert!(plausible_inner_ip(&ipv4(40)));
    }

    #[test]
    fn inner_ipv4_gate_rejects_a_version_nibble_that_is_not_four() {
        let mut p = ipv4(40);
        p[0] = 0x55;
        assert!(!plausible_inner_ipv4(&p));
    }

    #[test]
    fn inner_ipv4_gate_rejects_an_ihl_below_five() {
        let mut p = ipv4(40);
        p[0] = 0x44;
        assert!(!plausible_inner_ipv4(&p));
    }

    #[test]
    fn inner_ipv4_gate_rejects_a_total_length_below_the_header() {
        // IHL 15 declares a 60-octet header, so a Total Length of 40 is
        // shorter than the header it is supposed to contain — while still
        // covering all 40 captured octets, so the separate "undercounts the
        // capture" check stays silent and this one has to do the work.
        let mut p = ipv4(40);
        p[0] = 0x4F;
        assert!(!plausible_inner_ipv4(&p));
    }

    #[test]
    fn inner_ipv4_gate_rejects_a_total_length_that_undercounts_the_capture() {
        let mut p = ipv4(40);
        p[2..4].copy_from_slice(&24u16.to_be_bytes());
        assert!(!plausible_inner_ipv4(&p));
    }

    #[test]
    fn inner_ipv4_gate_accepts_a_total_length_that_overcounts_a_truncated_capture() {
        let mut p = ipv4(400);
        p.truncate(40);
        assert!(plausible_inner_ipv4(&p));
    }

    #[test]
    fn inner_ipv4_gate_rejects_the_reserved_flag_bit() {
        let mut p = ipv4(40);
        p[6] |= 0x80;
        assert!(!plausible_inner_ipv4(&p));
    }

    #[test]
    fn inner_ipv4_gate_rejects_a_zero_time_to_live() {
        let mut p = ipv4(40);
        p[8] = 0;
        assert!(!plausible_inner_ipv4(&p));
    }

    #[test]
    fn inner_ipv4_gate_rejects_a_header_shorter_than_twenty_octets() {
        let full = ipv4(40);
        for cut in 0..IPV4_HEADER_MIN {
            assert!(!plausible_inner_ipv4(&full[..cut]), "{cut} octets");
            assert!(!plausible_inner_ip(&full[..cut]), "{cut} octets");
        }
    }

    #[test]
    fn inner_ipv6_gate_accepts_a_well_formed_header() {
        assert!(plausible_inner_ipv6(&ipv6(8)));
        assert!(plausible_inner_ip(&ipv6(8)));
    }

    #[test]
    fn inner_ipv6_gate_rejects_a_version_nibble_that_is_not_six() {
        let mut p = ipv6(8);
        p[0] = 0x40;
        assert!(!plausible_inner_ipv6(&p));
    }

    #[test]
    fn inner_ipv6_gate_rejects_a_payload_length_that_undercounts_the_capture() {
        let mut p = ipv6(64);
        p[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert!(!plausible_inner_ipv6(&p));
    }

    #[test]
    fn inner_ipv6_gate_rejects_a_zero_hop_limit() {
        let mut p = ipv6(8);
        p[7] = 0;
        assert!(!plausible_inner_ipv6(&p));
    }

    #[test]
    fn inner_ipv6_gate_rejects_a_header_shorter_than_forty_octets() {
        let full = ipv6(8);
        for cut in 0..IPV6_HEADER_LEN {
            assert!(!plausible_inner_ipv6(&full[..cut]), "{cut} octets");
            assert!(!plausible_inner_ip(&full[..cut]), "{cut} octets");
        }
    }

    #[test]
    fn inner_ethernet_gate_accepts_every_allowed_ethertype() {
        for et in INNER_ETHERTYPES {
            assert!(plausible_inner_ethernet(&eth(et, &ipv4(40))), "{et:#06x}");
        }
    }

    #[test]
    fn inner_ethernet_gate_rejects_a_group_addressed_source_mac() {
        let mut f = eth(ETHERTYPE_IPV4, &ipv4(40));
        f[6] |= 0x01;
        assert!(!plausible_inner_ethernet(&f));
    }

    #[test]
    fn inner_ethernet_gate_rejects_a_frame_shorter_than_its_header() {
        let full = eth(ETHERTYPE_IPV4, &ipv4(40));
        for cut in 0..14 {
            assert!(!plausible_inner_ethernet(&full[..cut]), "{cut} octets");
        }
    }
}
