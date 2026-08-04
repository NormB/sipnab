// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network Service Header decapsulation (RFC 8300).
//!
//! Reached via EtherType `0x894F`. The IEEE Registration Authority's public
//! listing still gives that codepoint the reference `draft-ietf-sfc-nsh-18`;
//! that draft became **RFC 8300** in January 2018, and the RFC is what is
//! implemented here.
//!
//! That citation is **stale, not wrong**, and the distinction matters to
//! anyone auditing this module. draft-18 §2.2 Figure 2 is byte-for-byte
//! identical to RFC 8300 §2.2 Figure 3 — same 6-bit TTL, same 6-bit Length,
//! same four unassigned bits above a 4-bit MD Type — and draft-18 carries the
//! same TTL paragraph the RFC does. The two Length rules differ only in
//! wording ("MUST be of value 0x6" versus "MUST be 0x6"), an editorial
//! rewrite of one rule, not a normative divergence. Nothing here needs
//! draft-versus-RFC compatibility handling, and anyone who goes looking for
//! it is chasing a distinction that does not exist.
//!
//! The layout that genuinely lacks a TTL — six reserved flag bits and an
//! 8-bit MD Type — is draft-11/-12. TTL entered the base header at draft-13
//! and was stable from there through -28 and into the RFC. An earlier version
//! of this comment attributed that older shape to draft-18 and used it to
//! justify the module's design; that was wrong on the facts, and the
//! justification it supported was never needed. Cite the RFC because it is
//! the published standard, not because the draft said something different.
//!
//! # What is validated, and why it has to be
//!
//! NSH is a fixed 4-octet Base Header followed by a 4-octet Service Path
//! Header and then metadata whose shape the MD Type selects. Everything this
//! module needs is in the Base Header (RFC 8300 §2.2, Figure 3):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Ver|O|U|    TTL    |   Length  |U|U|U|U|MD Type| Next Protocol |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Note the widths: Ver is 2 bits, TTL is **6**, and Length is **6** — not 8.
//! Length is a count of 4-byte words, so a 6-bit field can address at most 252
//! octets of header, and reading it as a byte count (or as 8 bits) puts the
//! payload offset somewhere the payload is not.
//!
//! Unlike the port-keyed tunnels, NSH is not reached by guesswork — an
//! EtherType is a definite statement. The validation here therefore does not
//! exist to decide *whether* this is NSH; it exists because the Length field
//! is the only thing standing between a hostile 6-bit integer and an offset
//! this code hands to the rest of the parser.

use super::{Inner, mpls};

/// Octets in the NSH Base Header + Service Path Header, the part that is
/// present regardless of MD Type ("The format of the Base Header and the
/// Service Path Header is invariant and not affected by MD Type", §2.2).
const NSH_FIXED: usize = 8;

/// Octets per unit of the Length field (§2.2: "The total length, in 4-byte
/// words, of the NSH").
const LENGTH_WORD: usize = 4;

/// The only NSH version this decoder — or any decoder — may accept.
///
/// §2.2: "It MUST be set to 0x0 by the sender, in this first revision of the
/// NSH. If a packet presumed to carry an NSH header is received at an SFF, and
/// the SFF does not understand the version of the protocol ... the packet MUST
/// be discarded."
const NSH_VERSION: u8 = 0;

/// MD Type 0x1: fixed-length context header, and §2.2 pins the size exactly —
/// "The length MUST be 0x6 for MD Type 0x1", i.e. 4 + 4 + 16 = 24 octets.
const MD_TYPE_FIXED: u8 = 0x1;
/// Length, in 4-byte words, that MD Type 0x1 mandates.
const MD_FIXED_LENGTH: u8 = 0x6;
/// MD Type 0x2: optional variable-length context headers; §2.2 requires the
/// length "MUST be 0x2 or greater", where exactly 0x2 means no context
/// headers at all.
const MD_TYPE_VARIABLE: u8 = 0x2;
/// Smallest legal Length, in 4-byte words, for MD Type 0x2.
const MD_VARIABLE_MIN_LENGTH: u8 = 0x2;

// Next Protocol values this decoder acts on (§2.2 / IANA "NSH Next Protocol").
// Everything else is refused; see [`decap`].
/// Next Protocol 0x1: IPv4.
const NEXT_PROTO_IPV4: u8 = 0x1;
/// Next Protocol 0x2: IPv6.
const NEXT_PROTO_IPV6: u8 = 0x2;
/// Next Protocol 0x3: Ethernet.
const NEXT_PROTO_ETHERNET: u8 = 0x3;
/// Next Protocol 0x5: MPLS.
const NEXT_PROTO_MPLS: u8 = 0x5;

/// Minimum octets that must have been captured at the returned offset for the
/// payload kind being claimed: the IPv4 fixed header, whose addresses end at
/// octet 20 (RFC 791 §3.1); the IPv6 fixed header (RFC 8200 §3); and an
/// Ethernet II header through its EtherType.
///
/// These bound nothing about the *wire* — Total Length and Payload Length are
/// never compared against the captured length, because a capture taken with a
/// snaplen legitimately holds far less than the header advertises. They bound
/// what this decoder is willing to point at: an offset to a header that was
/// cut off before its addresses is an offset nothing downstream can use, and
/// returning one converts a clean miss into a parse failure further along.
const IPV4_FIXED_HEADER: usize = 20;
/// Octets in the IPv6 fixed header (RFC 8200 §3); see [`IPV4_FIXED_HEADER`].
const IPV6_FIXED_HEADER: usize = 40;
/// Octets in an Ethernet II header through the EtherType; see
/// [`IPV4_FIXED_HEADER`].
const ETHERNET_II_HEADER: usize = 14;

/// Decapsulate a Network Service Header and report what it carries.
///
/// `off` is the offset of the NSH Base Header — the byte after the `0x894F`
/// EtherType. The returned offset is absolute within `d`.
///
/// Returns `None` — never a panic, never a read past `d` — for a truncated
/// header, a version this specification does not define, an MD Type whose
/// metadata layout is unknown, a Length that contradicts the MD Type or runs
/// off the captured frame, a Next Protocol that is not supported, or an inner
/// header whose version nibble contradicts the Next Protocol.
pub(crate) fn decap(d: &[u8], off: usize) -> Option<Inner> {
    let base: [u8; 4] = d.get(off..off.checked_add(4)?)?.try_into().ok()?;

    // Ver occupies the top 2 bits of octet 0.
    //
    // This gate does more work than "reject a malformed header": §2.2 notes
    // that "given the widespread implementation of existing hardware that uses
    // the first nibble after an MPLS label stack for Equal-Cost Multipath
    // (ECMP) decision processing, this document reserves version 01b. This
    // value MUST NOT be used in future versions of the protocol." Version 01b
    // would put 0x4..0x7 in the first nibble — the IPv4 codepoint. Refusing
    // every non-zero version is therefore both what the RFC demands today and
    // permanently safe against the one value that could alias IPv4.
    if base[0] >> 6 != NSH_VERSION {
        return None;
    }

    // The O bit (octet 0, bit 5) is read by nobody here on purpose. §2.2 says
    // implementations that do not support SFC OAM "SHOULD discard packets with
    // O bit set", but that sentence is addressed to SFs, SFFs, SFC proxies and
    // classifiers — nodes that would otherwise *act* on an OAM packet. A
    // passive capture tool acts on nothing, and the O bit does not make the
    // Next Protocol field untrue. Discarding here would delete a class of
    // frames from an operator's diagnosis for no gain in safety.
    //
    // The U bits (octet 0 bit 4, and the top nibble of octet 2) are likewise
    // not checked, and this one is normative: "Unassigned bits MUST be set to
    // zero upon origination, and they MUST be ignored and preserved unmodified
    // by other NSH supporting elements. At reception, all elements MUST NOT
    // modify their actions based on these unknown bits." A reserved-bit gate
    // is the right instinct on most headers and the wrong one here — it would
    // break the forward compatibility those bits exist to provide.

    // Length: 6 bits, low end of octet 1. TTL takes bits 4..9 and is not used.
    let length = base[1] & 0x3F;
    let md_type = base[2] & 0x0F;

    // §2.2 makes the legal Length a function of the MD Type, which is what
    // makes this check worth anything: a self-consistent pair is much harder
    // to hit by accident than either field alone. Every other MD Type is
    // refused outright — 0x0 is reserved ("Implementations SHOULD silently
    // discard"), 0xF is RFC 3692 experimentation ("SHOULD silently discard"
    // unless explicitly configured, which this is not), and 0x3..=0xE are
    // unassigned. "Packets with MD Type values not supported by an
    // implementation MUST be silently dropped." An unknown MD Type means an
    // unknown metadata layout, so the Length field is the *only* thing that
    // could locate the payload — and a guess resting on one unvalidated 6-bit
    // integer is exactly the fabrication this module exists to avoid.
    let ok = match md_type {
        MD_TYPE_FIXED => length == MD_FIXED_LENGTH,
        MD_TYPE_VARIABLE => length >= MD_VARIABLE_MIN_LENGTH,
        _ => false,
    };
    if !ok {
        return None;
    }

    let header_len = usize::from(length) * LENGTH_WORD;
    debug_assert!(header_len >= NSH_FIXED);
    let at = off.checked_add(header_len)?;

    match base[3] {
        // The version nibble is checked against the Next Protocol the header
        // just claimed. Two independent fields agreeing is the cheapest real
        // evidence available, and disagreement means one of them is wrong —
        // in which case the offset is not to be trusted either.
        NEXT_PROTO_IPV4 => ip_payload(d, at, 4, IPV4_FIXED_HEADER),
        NEXT_PROTO_IPV6 => ip_payload(d, at, 6, IPV6_FIXED_HEADER),
        // An Ethernet payload starts at its destination MAC, with no version
        // field or any other invariant to test — §2.2 offers nothing further,
        // and inventing a check (multicast bit, OUI plausibility) would reject
        // real frames to no end. All that is left is insisting the header was
        // actually captured.
        NEXT_PROTO_ETHERNET => captured(d, at, ETHERNET_II_HEADER).map(|()| Inner::Ethernet(at)),
        // Delegated rather than reimplemented, so MPLS-under-NSH gets the same
        // bottom-of-stack discrimination and the same refusals as MPLS
        // anywhere else.
        NEXT_PROTO_MPLS => mpls::decap(d, at),
        // Everything else, deliberately. 0x0 is "None" (RFC 8393). 0x4 is
        // hierarchical NSH, which §2.2 places "outside the scope of this
        // specification" and which would also make this function recursive.
        // 0x6 is IOAM (RFC 9452) and 0x7 SFC Active OAM (RFC 9516) — headers
        // this code cannot walk, so their offsets are unknown. 0xFE and 0xFF
        // are experiments. §2.2: "Packets with Next Protocol values not
        // supported SHOULD be silently dropped by default."
        _ => None,
    }
}

/// An inner IP header that both matches the promised `version` and was
/// captured in full.
///
/// The two conditions answer different questions and neither subsumes the
/// other: the version nibble is about whether the Next Protocol field told the
/// truth, and `need` is about whether there is enough header here to be worth
/// reporting. A test that only ever exercises them together will pass with
/// either one deleted, which is why the fixtures for each are sized so the
/// other cannot mask it.
fn ip_payload(d: &[u8], at: usize, version: u8, need: usize) -> Option<Inner> {
    if d.get(at)? >> 4 != version {
        return None;
    }
    captured(d, at, need)?;
    Some(Inner::Ip(at))
}

/// `Some(())` when `d` holds `need` octets starting at `at`.
fn captured(d: &[u8], at: usize, need: usize) -> Option<()> {
    d.get(at..at.checked_add(need)?).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::tunnel::Inner;

    /// Where the NSH Base Header starts in every fixture — non-zero so a
    /// decoder that measured from the wrong base cannot pass by accident.
    const OFF: usize = 14;

    /// Build an NSH Base Header + Service Path Header, padded out to the
    /// `length` the Base Header claims.
    ///
    /// `ver`/`o`/`ttl`/`length`/`md_type`/`next_proto` are written exactly as
    /// given so a test can put an illegal value in any one of them.
    fn nsh(ver: u8, o: bool, ttl: u8, length: u8, md_type: u8, next_proto: u8) -> Vec<u8> {
        let b0 = ((ver & 0x03) << 6) | (u8::from(o) << 5) | ((ttl >> 2) & 0x0F);
        let b1 = ((ttl & 0x03) << 6) | (length & 0x3F);
        let b2 = md_type & 0x0F;
        let mut h = vec![b0, b1, b2, next_proto];
        // Service Path Header: SPI 0x00_0102, SI 0xFF.
        h.extend_from_slice(&[0x00, 0x01, 0x02, 0xFF]);
        // Pad out to `length` 4-byte words; a length below 2 leaves it short.
        h.resize(usize::from(length) * 4, 0u8);
        h
    }

    fn ipv4() -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0] = 0x45;
        h[3] = 20;
        h[9] = 17;
        h
    }

    fn ipv6() -> Vec<u8> {
        let mut h = vec![0u8; 40];
        h[0] = 0x60;
        h[6] = 17;
        h[7] = 64;
        h
    }

    /// A minimal Ethernet II frame: dst MAC, src MAC, EtherType IPv4.
    fn eth() -> Vec<u8> {
        let mut f = vec![0x02u8; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&ipv4());
        f
    }

    fn frame(parts: &[&[u8]]) -> Vec<u8> {
        let mut d = vec![0xAAu8; OFF];
        for p in parts {
            d.extend_from_slice(p);
        }
        d
    }

    #[test]
    fn md_type_one_with_ipv4_next_protocol_decaps_past_twenty_four_octets() {
        // RFC 8300 §2.2: Length MUST be 0x6 for MD Type 0x1 => 24 octets.
        let d = frame(&[&nsh(0, false, 63, 6, 1, 1), &ipv4()]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 24)));
    }

    #[test]
    fn md_type_two_with_no_context_headers_decaps_past_eight_octets() {
        // RFC 8300 §2.2: "With MD Type 0x2, a length of 0x2 implies there are
        // no Context Headers."
        let d = frame(&[&nsh(0, false, 63, 2, 2, 1), &ipv4()]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 8)));
    }

    #[test]
    fn md_type_two_with_variable_context_headers_honours_the_length_field() {
        let d = frame(&[&nsh(0, false, 63, 9, 2, 2), &ipv6()]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 36)));
    }

    #[test]
    fn next_protocol_ethernet_yields_an_ethernet_frame_offset() {
        let d = frame(&[&nsh(0, false, 63, 6, 1, 3), &eth()]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ethernet(OFF + 24)));
    }

    #[test]
    fn next_protocol_mpls_delegates_to_the_label_stack_decoder() {
        // RFC 8300 §2.2 Next Protocol 0x5. One bottom-of-stack label, then
        // IPv4 — the MPLS decoder's own discrimination applies.
        let lse = (0x0_1234u32 << 12) | 0x0000_0100 | 64;
        let mut payload = lse.to_be_bytes().to_vec();
        payload.extend_from_slice(&ipv4());
        let d = frame(&[&nsh(0, false, 63, 6, 1, 5), &payload]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 28)));
    }

    #[test]
    fn a_nonzero_version_is_rejected() {
        // RFC 8300 §2.2: "the packet MUST be discarded". Version 01b is
        // additionally reserved forever, so all three non-zero values are
        // permanent rejects.
        for ver in [1u8, 2, 3] {
            let d = frame(&[&nsh(ver, false, 63, 6, 1, 1), &ipv4()]);
            assert_eq!(decap(&d, OFF), None, "version {ver} must be rejected");
        }
    }

    #[test]
    fn md_type_one_with_a_length_other_than_six_is_rejected() {
        for length in [0u8, 1, 2, 5, 7, 8, 63] {
            let d = frame(&[&nsh(0, false, 63, length, 1, 1), &ipv4()]);
            assert_eq!(
                decap(&d, OFF),
                None,
                "MD Type 1 length {length} must be rejected"
            );
        }
    }

    #[test]
    fn md_type_two_with_a_length_below_two_is_rejected() {
        for length in [0u8, 1] {
            let d = frame(&[&nsh(0, false, 63, length, 2, 1), &ipv4()]);
            assert_eq!(
                decap(&d, OFF),
                None,
                "MD Type 2 length {length} must be rejected"
            );
        }
    }

    #[test]
    fn the_reserved_and_experimental_md_types_are_rejected() {
        // 0x0 is reserved ("SHOULD silently discard"), 0xF is RFC 3692
        // experimentation, 0x3..=0xE are unassigned. None may be guessed.
        for md in [0u8, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
            let d = frame(&[&nsh(0, false, 63, 6, md, 1), &ipv4()]);
            assert_eq!(decap(&d, OFF), None, "MD Type {md:#x} must be rejected");
        }
    }

    #[test]
    fn unsupported_next_protocol_values_are_rejected() {
        // 0x0 None (RFC 8393), 0x4 hierarchical NSH (out of scope in the
        // RFC), 0x6 IOAM, 0x7 SFC Active OAM, 0xFE/0xFF experimental, and
        // everything unassigned.
        for np in [0u8, 4, 6, 7, 0x20, 0x80, 0xFD, 0xFE, 0xFF] {
            let d = frame(&[&nsh(0, false, 63, 6, 1, np), &ipv4()]);
            assert_eq!(
                decap(&d, OFF),
                None,
                "Next Protocol {np:#x} must be rejected"
            );
        }
    }

    #[test]
    fn next_protocol_ipv4_over_a_payload_that_is_not_ipv4_is_rejected() {
        // The payload is 40 octets — comfortably more than the 20 an IPv4
        // header needs — so the version nibble is the only thing that can
        // reject it. Sizing this fixture short would let the length check
        // pass the test while the version check was broken.
        let d = frame(&[&nsh(0, false, 63, 6, 1, 1), &ipv6()]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn next_protocol_ipv6_over_a_payload_that_is_not_ipv6_is_rejected() {
        // Padded to 40 octets for the reason above, mirrored: an IPv6 claim
        // needs 40, so a bare 20-octet IPv4 header would have been rejected
        // on length no matter what the version check did.
        let mut not_v6 = ipv4();
        not_v6.resize(40, 0u8);
        let d = frame(&[&nsh(0, false, 63, 6, 1, 2), &not_v6]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn the_unassigned_flag_bits_are_ignored_not_enforced() {
        // RFC 8300 §2.2: unassigned bits "MUST be ignored and preserved
        // unmodified ... At reception, all elements MUST NOT modify their
        // actions based on these unknown bits." Rejecting on them would
        // break forward compatibility by design.
        let mut d = frame(&[&nsh(0, false, 63, 6, 1, 1), &ipv4()]);
        d[OFF] |= 0b0001_0000; // the U bit beside the O bit
        d[OFF + 2] |= 0b1111_0000; // the four U bits above MD Type
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 24)));
    }

    #[test]
    fn the_oam_bit_does_not_change_the_decap() {
        // We are a passive observer, not an SFF: §2.2's "SHOULD discard" is
        // addressed to SF/SFF/proxy/classifier implementations, and the O bit
        // says the packet is OAM, not that Next Protocol has become a lie.
        let d = frame(&[&nsh(0, true, 63, 6, 1, 1), &ipv4()]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 24)));
    }

    #[test]
    fn a_payload_shorter_than_the_header_it_claims_is_rejected() {
        // The Next Protocol and the version nibble can agree perfectly and
        // still leave nothing usable: an offset into an IPv4 header cut off
        // before its addresses is a miss dressed up as a decap.
        let mut short = ipv4();
        short.truncate(19);
        let d = frame(&[&nsh(0, false, 63, 6, 1, 1), &short]);
        assert_eq!(decap(&d, OFF), None);

        let mut short6 = ipv6();
        short6.truncate(39);
        let d = frame(&[&nsh(0, false, 63, 6, 1, 2), &short6]);
        assert_eq!(decap(&d, OFF), None);

        let mut short_eth = eth();
        short_eth.truncate(13);
        let d = frame(&[&nsh(0, false, 63, 6, 1, 3), &short_eth]);
        assert_eq!(decap(&d, OFF), None);
        let d = frame(&[&nsh(0, false, 63, 6, 1, 3), &eth()[..14]]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ethernet(OFF + 24)));
    }

    #[test]
    fn a_length_that_runs_past_the_captured_frame_is_rejected() {
        let mut d = frame(&[&nsh(0, false, 63, 2, 2, 1), &ipv4()]);
        d[OFF + 1] = (d[OFF + 1] & 0xC0) | 0x3F; // Length 63 => 252 octets
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn a_header_whose_length_consumes_the_whole_frame_is_rejected() {
        // Length exactly equal to the remaining bytes leaves zero payload;
        // there is nothing to point at, so this is a miss.
        let d = frame(&[&nsh(0, false, 63, 2, 2, 1)]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn truncation_at_every_boundary_yields_none_and_never_panics() {
        let d = frame(&[&nsh(0, false, 63, 6, 1, 1), &ipv4()]);
        let full = d.len();
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 24)));
        for cut in 0..full {
            assert_eq!(
                decap(&d[..cut], OFF),
                None,
                "a frame truncated to {cut} bytes must not decap"
            );
        }
    }

    #[test]
    fn an_offset_past_the_end_of_the_frame_yields_none() {
        let d = frame(&[&nsh(0, false, 63, 6, 1, 1), &ipv4()]);
        assert_eq!(decap(&d, d.len()), None);
        assert_eq!(decap(&d, usize::MAX), None);
        assert_eq!(decap(&d, usize::MAX - 3), None);
        assert_eq!(decap(&[], 0), None);
    }

    #[test]
    fn an_rtp_packet_read_as_an_nsh_header_is_rejected() {
        // Not reachable through EtherType 0x894F, but a generic dispatcher
        // could hand this decoder anything. RTP version 2 sets the top two
        // bits, which is NSH version 0b10 — rejected on the version alone.
        let mut rtp = vec![0x80u8, 0x08, 0x12, 0x34];
        rtp.extend_from_slice(&[0xD5; 160]);
        let d = frame(&[&rtp]);
        assert_eq!(decap(&d, OFF), None);
    }
}
