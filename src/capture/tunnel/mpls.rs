// SPDX-License-Identifier: MIT OR Apache-2.0

//! MPLS label stack decapsulation (RFC 3032, RFC 4182, RFC 5332).
//!
//! Reached three ways, all of which hand this module the offset of the first
//! label stack entry:
//!
//! * EtherType `0x8847` or `0x8848` on Ethernet. RFC 5332 §4 **replaced**
//!   RFC 3032 §5's unicast/multicast split: `0x8847` now marks "an MPLS packet"
//!   generally, and `0x8848` is "used only when an MPLS packet whose top label
//!   is upstream-assigned is carried in a multicast ethernet frame". The older
//!   "MPLS multicast" gloss — still what the IEEE RA listing prints — describes
//!   a semantic that has not been current since 2008. Either codepoint
//!   introduces the same label stack encoding, which is all this module cares
//!   about.
//! * IP protocol number 137 (MPLS-in-IP, RFC 4023). RFC 5332 §7 amended
//!   RFC 4023 so that 137 is used "whether or not the encapsulated MPLS packet
//!   is an MPLS multicast packet" — there is no second protocol number to
//!   handle.
//! * NSH Next Protocol `0x5` (RFC 8300 §2.2), via [`super::nsh`].
//!
//! # The hard part: an MPLS payload does not say what it is
//!
//! RFC 3032 §2.2 is explicit: "the label stack does not contain any field
//! which explicitly identifies the network layer protocol. This means that the
//! identity of the network layer protocol must be inferable from the value of
//! the label which is popped from the bottom of the stack, possibly along with
//! the contents of the network layer header itself." The label→protocol
//! binding lives in the control plane (LDP/BGP/RSVP-TE), which a packet
//! capture does not have. So the only evidence available offline is the second
//! half of that sentence: the contents of the header itself.
//!
//! The discrimination rule implemented here is the one the deployed MPLS data
//! plane already runs on, and the reason the IETF made it safe to run on:
//!
//! * RFC 4928 §2 records the existing hardware behavior — "by inspecting the
//!   first nibble beyond the label stack, existing equipment infers that a
//!   packet is not IPv4 or IPv6 if the value of the nibble ... is not 0x4 or
//!   0x6 respectively", and "most deployed LSRs will treat a packet whose
//!   first nibble is equal to 0x4 as if the payload were IPv4".
//! * RFC 4385 §2 turns that into a normative constraint on everyone else: "PW
//!   packets carried over an MPLS PSN MUST NOT start with the value 4 (IPv4)
//!   or the value 6 (IPv6) in the first nibble", and assigns first-nibble 0 to
//!   the PW control word (§3) and 1 to the PW associated channel (§5).
//!
//! So the nibble is not a guess this code invented; it is the discriminator
//! the encapsulations were designed around. What this module adds on top is
//! shape validation of the first inner header, because a nibble is four bits
//! and four bits are not enough to bet a fabricated call on.
//!
//! What is deliberately **not** attempted: guessing the payload of a
//! pseudowire. A PW carries Ethernet, ATM, Frame Relay, HDLC or TDM depending
//! on a PW type that is signaled by LDP and never appears on the wire. Every
//! one of those would produce a different — and, for four of the five,
//! fictional — inner packet. They are reported as [`Inner::Opaque`] instead,
//! which is a diagnosis the operator can act on rather than a flow that never
//! existed.

use super::Inner;

/// Bytes in one label stack entry (RFC 3032 §2.1: "Each label stack entry is
/// represented by 4 octets").
const LABEL_STACK_ENTRY: usize = 4;

/// Bit mask of the S (Bottom of Stack) bit within a big-endian label stack
/// entry: RFC 3032 §2.1 puts Label in bits 0–19, Exp in 20–22, S in bit 23,
/// TTL in 24–31, so S is bit 8 of the low half-word.
const S_BIT: u32 = 0x0000_0100;

/// Right shift that isolates the 20-bit Label from a stack entry.
const LABEL_SHIFT: u32 = 12;

/// Cap on how many label stack entries are walked before giving up.
///
/// RFC 3032 sets no maximum depth, and neither does any RFC since. Real
/// stacks are shallow — a segment-routing stack of eight is already unusual —
/// so the constant is not a compatibility limit so much as a termination
/// guarantee: capture data is attacker-controlled, and a frame in which the S
/// bit is simply never set must not turn into a walk the length of the buffer.
/// A stack deeper than this is reported as "not decoded" rather than
/// half-decoded.
pub(crate) const MAX_LABEL_STACK_DEPTH: usize = 16;

/// IPv4 Explicit NULL (RFC 3032 §2.1 / RFC 7274 §3): the payload is IPv4.
const LABEL_IPV4_EXPLICIT_NULL: u32 = 0;
/// IPv6 Explicit NULL (RFC 3032 §2.1 / RFC 7274 §3): the payload is IPv6.
const LABEL_IPV6_EXPLICIT_NULL: u32 = 2;
/// Implicit NULL (RFC 3032 §2.1): an LSR "would never actually [push] a label
/// whose value is 3", so this value never legitimately appears on the wire.
const LABEL_IMPLICIT_NULL: u32 = 3;
/// Router Alert (RFC 3032 §2.1): "legal anywhere in the label stack except at
/// the bottom", so finding it at the bottom means the stack was misread.
const LABEL_ROUTER_ALERT: u32 = 1;
/// Entropy Label Indicator (RFC 6790 §4.2): an ELI is always followed by the
/// Entropy Label itself, so it cannot be the bottom entry.
const LABEL_ENTROPY_INDICATOR: u32 = 7;
/// Generic Associated Channel Label (RFC 5586 §4.2): at the bottom of the
/// stack it "MUST always be followed by an ACH", never by a user packet.
const LABEL_GAL: u32 = 13;

/// Smallest legal IPv4 IHL, in 32-bit words (RFC 791 §3.1).
const IPV4_MIN_IHL: usize = 5;
/// Octets of IPv4 header that must be captured before the packet is worth
/// reporting: the addresses end at octet 20.
const IPV4_FIXED_HEADER: usize = 20;
/// Octets in the IPv6 fixed header (RFC 8200 §3).
const IPV6_FIXED_HEADER: usize = 40;

/// The result of walking a label stack to its bottom entry.
///
/// `depth` and `bottom_label` are carried out because the walk already has
/// them in registers and the reporting layer wants them: "MPLS, 3 labels,
/// bottom 16011" is a far more useful line in a diagnosis than "MPLS", and a
/// caller that only needs the offset can ignore both fields for free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LabelStack {
    /// Number of stack entries, counting the bottom-of-stack entry.
    pub(crate) depth: u8,
    /// The 20-bit Label value of the bottom-of-stack entry.
    pub(crate) bottom_label: u32,
    /// Absolute offset of the first octet after the bottom-of-stack entry.
    pub(crate) payload_off: usize,
}

/// Walk the label stack that begins at `off` and report where it ends.
///
/// `off` is the offset of the first label stack entry — for Ethernet, the byte
/// after the `0x8847`/`0x8848` EtherType; for MPLS-in-IP, the byte after the
/// IP header. The returned `payload_off` is absolute within `d`.
///
/// Returns `None` — never a panic, never a read past `d` — for a truncated
/// stack, a stack whose S bit is never set within [`MAX_LABEL_STACK_DEPTH`],
/// or a stack containing the Implicit NULL label.
pub(crate) fn label_stack(d: &[u8], off: usize) -> Option<LabelStack> {
    let mut cur = off;
    for depth in 1..=MAX_LABEL_STACK_DEPTH {
        let end = cur.checked_add(LABEL_STACK_ENTRY)?;
        let entry: [u8; LABEL_STACK_ENTRY] = d.get(cur..end)?.try_into().ok()?;
        let raw = u32::from_be_bytes(entry);
        let label = raw >> LABEL_SHIFT;

        // RFC 3032 §2.1 on the Implicit NULL Label: it "should never actually
        // appear in the encapsulation". Seeing it means these four octets are
        // not a label stack entry — most likely they are not a label stack at
        // all — and continuing would compute a payload offset from bytes that
        // describe something else entirely.
        if label == LABEL_IMPLICIT_NULL {
            return None;
        }

        cur = end;
        if raw & S_BIT != 0 {
            return Some(LabelStack {
                depth: u8::try_from(depth).ok()?,
                bottom_label: label,
                payload_off: cur,
            });
        }
    }
    None
}

/// Decapsulate an MPLS label stack and report what follows it.
///
/// `off` is the offset of the first label stack entry (see [`label_stack`]).
///
/// Yields [`Inner::Ip`] only when the first inner header both carries the
/// right version nibble *and* holds together structurally; [`Inner::Opaque`]
/// for a pseudowire or an associated channel, whose payloads are genuinely
/// not identifiable from the wire; and `None` for everything else, including
/// every truncation.
pub(crate) fn decap(d: &[u8], off: usize) -> Option<Inner> {
    let stack = label_stack(d, off)?;
    let at = stack.payload_off;
    let nibble = d.get(at)? >> 4;

    // A bottom label of 0 or 2 is a *stronger* statement than the nibble: the
    // Explicit NULLs say outright which network layer follows (RFC 3032 §2.1).
    // Where the label and the nibble disagree, one of the two readings is
    // wrong and there is no way to tell which, so neither is used.
    //
    // The check is on the *bottom* label only. RFC 4182 removed RFC 3032's
    // "these labels are only legal at the bottom of the stack" restriction —
    // "this restriction is now removed, so that these label values may legally
    // occur anywhere in the stack" — so an Explicit NULL further up says
    // nothing about the payload and must not be treated as if it did.
    // Three more special-purpose labels constrain the payload just as hard,
    // and reading them costs the same compare. IANA's Special-Purpose MPLS
    // Label Values registry is the index; each rule below is the defining
    // RFC's, not an inference from the registry:
    //
    //   1  Router Alert (RFC 3032 §2.1) — "legal anywhere in the label stack
    //      except at the bottom". At the bottom, the stack was misread.
    //   7  Entropy Label Indicator (RFC 6790 §4.2) — an ELI is always followed
    //      by the Entropy Label itself, so it can never be the bottom entry.
    //  13  GAL (RFC 5586 §4.2) — "Where the GAL is at the bottom of the label
    //      stack ... then it MUST always be followed by an ACH", and an ACH
    //      begins with nibble 0001 (RFC 4385 §5). A GAL bottom over an IP
    //      nibble is therefore as contradictory as Explicit NULL over the
    //      wrong version.
    //
    // KNOWN LIMIT, stated rather than implied: RFC 5586 §4.2 also says the GAL
    // "MUST NOT appear in the label stack when transporting normal user-plane
    // packets" — which is not bottom-scoped. A GAL further up the stack over
    // an IP payload is equally non-conformant and is NOT rejected here, because
    // distinguishing user-plane from OAM at an arbitrary depth needs context
    // this decoder does not have. Bottom-only is what can be decided from the
    // bytes alone.
    match stack.bottom_label {
        LABEL_IPV4_EXPLICIT_NULL if nibble != 4 => return None,
        LABEL_IPV6_EXPLICIT_NULL if nibble != 6 => return None,
        LABEL_ROUTER_ALERT | LABEL_ENTROPY_INDICATOR => return None,
        LABEL_GAL if nibble != 1 => return None,
        _ => {}
    }

    match nibble {
        4 => ipv4_is_self_consistent(d, at).map(|()| Inner::Ip(at)),
        6 => ipv6_header_captured(d, at).map(|()| Inner::Ip(at)),
        0 => pw_control_word(d, at),
        1 => associated_channel(d, at),
        // RFC 4385 §2 deprecates every other first-nibble value for a PW, and
        // no IP version uses one. Whatever it is, this code does not know.
        _ => None,
    }
}

/// Reject an "IPv4 header" that cannot be one.
///
/// Called only from the `nibble == 4` arm of [`decap`], so the version is
/// already established and is deliberately not re-tested here — a branch that
/// cannot be taken is a branch no test can hold to account, and this file
/// would rather have one fewer line than one unfalsifiable one.
///
/// The nibble alone is four bits, and four bits show up by chance roughly once
/// every sixteen frames in any byte an attacker or a bare Ethernet pseudowire
/// puts under the bottom label. Two more facts from RFC 791 §3.1 are free:
///
/// * IHL is "the length of the internet header in 32 bit words, and thus
///   points to the beginning of the data. Note that the minimum value for a
///   correct header is 5" — so IHL < 5 is impossible.
/// * Total Length "is the length of the datagram, measured in octets,
///   including internet header and data" — so it cannot be smaller than the
///   header it includes.
///
/// Total Length is deliberately **not** compared against `d.len()`. A capture
/// taken with a snaplen routinely holds "Total Length says 1500, caplen is
/// 96"; treating that as a contradiction would reject ordinary traffic. Only
/// the header's internal consistency is checked, plus the presence of the
/// 20 octets that contain the addresses — without those there is nothing to
/// report even on success.
fn ipv4_is_self_consistent(d: &[u8], at: usize) -> Option<()> {
    let vihl = *d.get(at)?;
    let ihl = usize::from(vihl & 0x0F);
    if ihl < IPV4_MIN_IHL {
        return None;
    }
    let total = u16::from_be_bytes([*d.get(at + 2)?, *d.get(at + 3)?]);
    // ihl is at most 15, so ihl * 4 is at most 60 — no overflow is reachable.
    if usize::from(total) < ihl * LABEL_STACK_ENTRY {
        return None;
    }
    let end = at.checked_add(IPV4_FIXED_HEADER)?;
    d.get(at..end)?;
    Some(())
}

/// Require that a whole IPv6 fixed header was captured.
///
/// The name is the whole story, and that is the point: IPv6 gives a decoder
/// far less to work with than IPv4. RFC 8200 §3 removed the header checksum
/// and the header-length field and left no field whose value constrains
/// another; Payload Length cannot be checked against the captured length for
/// the snaplen reason given above; and every Traffic Class, Flow Label and Hop
/// Limit value is legal. After the version nibble, which [`decap`] has already
/// matched on, there is nothing left to verify that would be honest.
///
/// So an inner IPv6 header rests on four bits of evidence where an inner IPv4
/// header rests on four bits plus two consistency relations. That asymmetry is
/// exactly why the bottom-label cross-check in [`decap`] carries more weight
/// for v6 than for v4, and why the MPLS-under-NSH path is worth having: there,
/// the Next Protocol field says which it is.
fn ipv6_header_captured(d: &[u8], at: usize) -> Option<()> {
    let end = at.checked_add(IPV6_FIXED_HEADER)?;
    d.get(at..end)?;
    Some(())
}

/// A first nibble of 0 means a PW MPLS Control Word (RFC 4385 §3).
///
/// The generic form constrains exactly one thing — "Bits 0..3 differ from the
/// first four bits of an IP packet and hence provide the necessary MPLS
/// payload discrimination" — and leaves the remaining 28 bits to the PW
/// encapsulation. Even the preferred form (Flags/FRG/Length/Sequence Number)
/// puts no value out of range, so there is nothing further to validate beyond
/// the control word actually having been captured.
///
/// What follows the control word is not knowable here: RFC 4385 §2 has the PW
/// set-up protocol decide the payload type, and LDP signaling is not in the
/// capture. Returning [`Inner::Opaque`] says precisely that.
fn pw_control_word(d: &[u8], at: usize) -> Option<Inner> {
    let end = at.checked_add(LABEL_STACK_ENTRY)?;
    d.get(at..end)?;
    Some(Inner::Opaque("mpls-pseudowire"))
}

/// A first nibble of 1 means a PW Associated Channel Header (RFC 4385 §5),
/// generalised to the Generic Associated Channel by RFC 5586.
///
/// "Bits 0..3 MUST be 0001. This allows the packet to be distinguished from an
/// IP packet and from a PW data packet." The Version field is the one other
/// checkable value: RFC 4385 §5 "defines version 0", so anything else is a
/// format this decoder has never seen.
///
/// The 8-bit Reserved field is deliberately not checked. RFC 4385 §5 says it
/// "MUST be sent as 0, and ignored on reception" — enforcing a field the
/// standard tells receivers to ignore would reject conforming traffic the
/// moment anything ever puts it to use.
///
/// The channel carries OAM (BFD, LSP-Ping, and the rest of the Channel Type
/// registry), not user traffic, so there is no call inside to be found.
fn associated_channel(d: &[u8], at: usize) -> Option<Inner> {
    let end = at.checked_add(LABEL_STACK_ENTRY)?;
    d.get(at..end)?;
    if d.get(at)? & 0x0F != 0 {
        return None;
    }
    Some(Inner::Opaque("mpls-g-ach"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::tunnel::Inner;

    /// Offset the label stack starts at in every fixture: a plain Ethernet
    /// header's 14 bytes. Deliberately non-zero so an implementation that
    /// measured from the wrong base fails instead of coincidentally passing.
    const OFF: usize = 14;

    /// One label stack entry, encoded per RFC 3032 §2.1 Figure 1
    /// (Label 20 bits, Exp 3, S 1, TTL 8).
    fn lse(label: u32, exp: u8, bottom: bool, ttl: u8) -> [u8; 4] {
        (((label & 0x000F_FFFF) << 12)
            | (u32::from(exp & 0x07) << 9)
            | (u32::from(bottom) << 8)
            | u32::from(ttl))
        .to_be_bytes()
    }

    /// A 20-octet IPv4 header that is internally consistent: version 4,
    /// IHL 5, Total Length 20.
    fn ipv4() -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0] = 0x45;
        h[2] = 0x00;
        h[3] = 20;
        h[9] = 17; // UDP
        h
    }

    /// A 40-octet IPv6 fixed header: version 6, Payload Length 0, Next
    /// Header UDP, Hop Limit 64.
    fn ipv6() -> Vec<u8> {
        let mut h = vec![0u8; 40];
        h[0] = 0x60;
        h[6] = 17;
        h[7] = 64;
        h
    }

    /// Prepend the Ethernet-sized prefix so every fixture starts at `OFF`.
    fn frame(parts: &[&[u8]]) -> Vec<u8> {
        let mut d = vec![0xAAu8; OFF];
        for p in parts {
            d.extend_from_slice(p);
        }
        d
    }

    #[test]
    fn single_entry_stack_reports_depth_bottom_label_and_payload_offset() {
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &ipv4()]);
        assert_eq!(
            label_stack(&d, OFF),
            Some(LabelStack {
                depth: 1,
                bottom_label: 0x0_1234,
                payload_off: OFF + 4,
            })
        );
    }

    #[test]
    fn three_entry_stack_reports_depth_three_and_the_bottom_label() {
        let d = frame(&[
            &lse(0x0_AAAA, 5, false, 64),
            &lse(0x0_BBBB, 0, false, 63),
            &lse(0xF_FFFF, 0, true, 62),
            &ipv4(),
        ]);
        assert_eq!(
            label_stack(&d, OFF),
            Some(LabelStack {
                depth: 3,
                bottom_label: 0xF_FFFF,
                payload_off: OFF + 12,
            })
        );
    }

    #[test]
    fn ipv4_under_the_bottom_label_decaps_to_the_payload_offset() {
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &ipv4()]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 4)));
    }

    #[test]
    fn ipv6_under_the_bottom_label_decaps_to_the_payload_offset() {
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &ipv6()]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 4)));
    }

    #[test]
    fn ipv4_explicit_null_bottom_label_accepts_an_ipv4_payload() {
        let d = frame(&[&lse(0, 0, true, 64), &ipv4()]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 4)));
    }

    #[test]
    fn ipv6_explicit_null_bottom_label_accepts_an_ipv6_payload() {
        let d = frame(&[&lse(2, 0, true, 64), &ipv6()]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 4)));
    }

    #[test]
    fn explicit_null_that_contradicts_the_payload_version_is_rejected() {
        // Bottom label 0 promises IPv4 (RFC 3032 §2.1) but the payload is v6.
        let d = frame(&[&lse(0, 0, true, 64), &ipv6()]);
        assert_eq!(decap(&d, OFF), None);
        // ... and the mirror image.
        let d = frame(&[&lse(2, 0, true, 64), &ipv4()]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn explicit_null_is_accepted_above_the_bottom_of_the_stack() {
        // RFC 4182 removed RFC 3032's "bottom of stack only" restriction, so
        // an explicit NULL in a non-bottom position is legal and must not
        // constrain the payload type.
        let d = frame(&[&lse(0, 0, false, 64), &lse(0x0_5555, 0, true, 63), &ipv6()]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 8)));
    }

    #[test]
    fn router_alert_at_the_bottom_of_the_stack_is_rejected() {
        // RFC 3032 §2.1: label 1 is "legal anywhere in the label stack except
        // at the bottom". A conformant sender cannot produce this, so the
        // stack was misread and the bytes after it are not an IP header.
        let d = frame(&[&lse(LABEL_ROUTER_ALERT, 0, true, 64), &ipv4()]);
        assert_eq!(decap(&d, OFF), None);
        // Above the bottom it is legal and must not constrain the payload.
        let d = frame(&[
            &lse(LABEL_ROUTER_ALERT, 0, false, 64),
            &lse(0x0_5555, 0, true, 63),
            &ipv4(),
        ]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 8)));
    }

    #[test]
    fn entropy_label_indicator_at_the_bottom_of_the_stack_is_rejected() {
        // RFC 6790 §4.2: an ELI is always followed by the Entropy Label, so it
        // is never the bottom entry.
        let d = frame(&[&lse(LABEL_ENTROPY_INDICATOR, 0, true, 64), &ipv4()]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn gal_at_the_bottom_must_be_followed_by_an_associated_channel() {
        // RFC 5586 §4.2: "Where the GAL is at the bottom of the label stack
        // ... it MUST always be followed by an ACH". An ACH opens with nibble
        // 0001 (RFC 4385 §5), so a GAL over an IPv4 header is contradictory in
        // exactly the way an Explicit NULL over the wrong version is.
        let d = frame(&[&lse(LABEL_GAL, 0, true, 64), &ipv4()]);
        assert_eq!(decap(&d, OFF), None);

        // The conformant shape still decodes: GAL bottom, then an ACH.
        let ach = [0x10, 0x00, 0x00, 0x21];
        let d = frame(&[&lse(LABEL_GAL, 0, true, 64), &ach]);
        assert_eq!(decap(&d, OFF), Some(Inner::Opaque("mpls-g-ach")));
    }

    #[test]
    fn pseudowire_control_word_is_opaque_not_ip() {
        // RFC 4385 §3: first nibble 0000. The PW type is signaled by LDP,
        // never on the wire, so the payload is undecodable — but it is
        // emphatically not an IP packet.
        let mut cw = vec![0x00u8, 0x00, 0x00, 0x01];
        cw.extend_from_slice(&[0xDE; 60]);
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &cw]);
        assert_eq!(decap(&d, OFF), Some(Inner::Opaque("mpls-pseudowire")));
    }

    #[test]
    fn generic_associated_channel_is_opaque() {
        // RFC 4385 §5: first nibble 0001, Version 0, then Channel Type.
        let mut ach = vec![0x10u8, 0x00, 0x00, 0x21];
        ach.extend_from_slice(&[0xDE; 60]);
        let d = frame(&[&lse(13, 0, true, 64), &ach]);
        assert_eq!(decap(&d, OFF), Some(Inner::Opaque("mpls-g-ach")));
    }

    #[test]
    fn associated_channel_with_a_nonzero_version_is_rejected() {
        let mut ach = vec![0x13u8, 0x00, 0x00, 0x21];
        ach.extend_from_slice(&[0xDE; 60]);
        let d = frame(&[&lse(13, 0, true, 64), &ach]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn an_unrecognised_first_nibble_is_rejected() {
        for nibble in [0x2u8, 0x3, 0x5, 0x7, 0x8, 0x9, 0xA, 0xF] {
            let mut payload = vec![nibble << 4];
            payload.extend_from_slice(&[0x11; 63]);
            let d = frame(&[&lse(0x0_1234, 0, true, 64), &payload]);
            assert_eq!(decap(&d, OFF), None, "nibble {nibble:#x} must not decap");
        }
    }

    #[test]
    fn an_rtp_packet_mistaken_for_a_label_stack_payload_is_rejected() {
        // RTP version 2 puts 0b10 in the top bits, i.e. first nibble 0x8.
        let mut rtp = vec![0x80u8, 0x08, 0x12, 0x34];
        rtp.extend_from_slice(&[0xD5; 160]);
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &rtp]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn ipv4_with_an_ihl_below_five_is_rejected() {
        let mut h = ipv4();
        h[0] = 0x44; // version 4, IHL 4 — impossible, the header is 5 words min
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &h]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn ipv4_whose_total_length_is_below_its_own_header_length_is_rejected() {
        let mut h = ipv4();
        h[0] = 0x46; // IHL 6 => 24-octet header
        h[3] = 20; // but Total Length says the whole datagram is 20
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &h]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn a_customer_mac_address_that_starts_with_nibble_four_is_rejected() {
        // A bare Ethernet pseudowire (no control word) puts the customer's
        // destination MAC directly under the bottom label. 40-1C-... has the
        // IPv4 version nibble but IHL 0, so the shape check catches it.
        let mut mac = vec![0x40u8, 0x1C, 0x2D, 0x3E, 0x4F, 0x50];
        mac.extend_from_slice(&[0x66; 58]);
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &mac]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn a_stack_that_never_sets_the_bottom_bit_is_rejected() {
        let mut parts: Vec<u8> = Vec::new();
        for _ in 0..MAX_LABEL_STACK_DEPTH + 4 {
            parts.extend_from_slice(&lse(0x0_1234, 0, false, 64));
        }
        parts.extend_from_slice(&ipv4());
        let d = frame(&[&parts]);
        assert_eq!(label_stack(&d, OFF), None);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn a_stack_exactly_at_the_depth_limit_is_accepted() {
        let mut parts: Vec<u8> = Vec::new();
        for i in 0..MAX_LABEL_STACK_DEPTH {
            let bottom = i == MAX_LABEL_STACK_DEPTH - 1;
            parts.extend_from_slice(&lse(0x0_1000 + i as u32, 0, bottom, 64));
        }
        parts.extend_from_slice(&ipv4());
        let d = frame(&[&parts]);
        assert_eq!(
            label_stack(&d, OFF),
            Some(LabelStack {
                depth: MAX_LABEL_STACK_DEPTH as u8,
                bottom_label: 0x0_1000 + (MAX_LABEL_STACK_DEPTH as u32 - 1),
                payload_off: OFF + 4 * MAX_LABEL_STACK_DEPTH,
            })
        );
    }

    #[test]
    fn one_entry_past_the_depth_limit_is_rejected() {
        let mut parts: Vec<u8> = Vec::new();
        for i in 0..=MAX_LABEL_STACK_DEPTH {
            let bottom = i == MAX_LABEL_STACK_DEPTH;
            parts.extend_from_slice(&lse(0x0_1000 + i as u32, 0, bottom, 64));
        }
        parts.extend_from_slice(&ipv4());
        let d = frame(&[&parts]);
        assert_eq!(label_stack(&d, OFF), None);
    }

    #[test]
    fn the_implicit_null_label_is_rejected_wherever_it_appears() {
        // RFC 3032 §2.1: label 3 "should never actually appear in the
        // encapsulation".
        let d = frame(&[&lse(3, 0, true, 64), &ipv4()]);
        assert_eq!(label_stack(&d, OFF), None);
        let d = frame(&[&lse(3, 0, false, 64), &lse(0x0_1234, 0, true, 63), &ipv4()]);
        assert_eq!(label_stack(&d, OFF), None);
    }

    #[test]
    fn truncation_at_every_boundary_yields_none_and_never_panics() {
        let d = frame(&[
            &lse(0x0_AAAA, 0, false, 64),
            &lse(0x0_BBBB, 0, true, 63),
            &ipv4(),
        ]);
        let full = d.len();
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 8)));
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
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &ipv4()]);
        assert_eq!(decap(&d, d.len()), None);
        assert_eq!(decap(&d, d.len() + 1), None);
        assert_eq!(decap(&d, usize::MAX), None);
        assert_eq!(label_stack(&d, usize::MAX - 2), None);
    }

    #[test]
    fn an_empty_frame_yields_none() {
        assert_eq!(decap(&[], 0), None);
        assert_eq!(label_stack(&[], 0), None);
    }

    #[test]
    fn a_snapped_ipv4_header_shorter_than_twenty_octets_is_rejected() {
        // The addresses live at octets 12..20; without them there is nothing
        // to report, so a header cut short is a miss, not a decap.
        let mut short = ipv4();
        short.truncate(19);
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &short]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn a_snapped_ipv6_header_shorter_than_forty_octets_is_rejected() {
        let mut short = ipv6();
        short.truncate(39);
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &short]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn a_control_word_truncated_below_four_octets_is_rejected() {
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &[0x00u8, 0x00, 0x00]]);
        assert_eq!(decap(&d, OFF), None);
    }

    #[test]
    fn a_bare_ethernet_pseudowire_that_aliases_an_ipv4_header_is_a_known_miss() {
        // Recorded, not aspirational. An Ethernet pseudowire carried without
        // a control word (RFC 4448 makes it optional) puts the customer MAC
        // straight under the bottom label. If that MAC happens to begin
        // 45-00 and the next two octets happen to be >= 20 as a big-endian
        // u16, nothing on the wire distinguishes it from an IPv4 header, and
        // this decoder reports IP. RFC 4385 §2 exists precisely because the
        // whole deployed MPLS data plane has this ambiguity; the only real
        // fix is control-plane state we do not have. Asserted so that anyone
        // who later believes the discrimination is exact is corrected here.
        let mut mac = vec![0x45u8, 0x00, 0x05, 0xDC];
        mac.extend_from_slice(&[0x66; 60]);
        let d = frame(&[&lse(0x0_1234, 0, true, 64), &mac]);
        assert_eq!(decap(&d, OFF), Some(Inner::Ip(OFF + 4)));
    }
}
