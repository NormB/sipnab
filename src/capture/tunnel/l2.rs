// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ethernet-layer encapsulations: PBB I-TAG and MACsec.
//!
//! Both are IEEE tags rather than IETF tunnels, both are reached by EtherType,
//! and both wrap something the rest of the parser already knows how to read —
//! but only if the tag's variable geometry is resolved correctly first.
//!
//! In both entry points `off` is the offset of the tag *body*: the byte after
//! the EtherType, which the caller has already consumed. IEEE Std 802.1AE
//! numbers the MACsec EtherType as SecTAG octets 1–2, so `off` here is SecTAG
//! octet 3 — the TCI/AN octet — and every offset below is quoted against that
//! base, not against the standard's octet numbering.

use super::Inner;

// ── PBB I-TAG (IEEE Std 802.1Q, EtherType 0x88E7) ─────────────────────

/// Octets of I-TAG TCI before the encapsulated customer frame begins.
///
/// IEEE Std 802.1Q-2014 §9.7 Figure 9-2 lays the 16-octet I-TAG TCI out as
/// octet 1 of flags, octets 2–4 of I-SID, octets 5–10 of C-DA and octets
/// 11–16 of C-SA. C-DA *is* the customer frame's destination MAC, so the
/// encapsulated Ethernet II frame starts at octet 5 — four octets in.
const ITAG_FLAGS_AND_ISID: usize = 4;

/// Full length of the I-TAG TCI (§9.7: "The I-TAG TCI field is 16 octets in
/// length"). Required to be present so the customer source address is not
/// half-captured.
const ITAG_TCI_LEN: usize = 16;

/// Mask of the Res2 field in I-TCI octet 1: bits 2..1 (§9.7 Figure 9-2).
const ITAG_RES2_MASK: u8 = 0x03;

/// The null I-SID (Table 9-3): reserved for implementation use and "shall not
/// be ... transmitted in an I-TAG header".
const ISID_NULL: u32 = 0x00_0000;
/// The wildcard I-SID (Table 9-3): a management match-any value, likewise
/// never transmitted.
const ISID_WILDCARD: u32 = 0xFF_FFFF;

/// Offset of C-SA octet 1 within the I-TAG TCI (§9.7 Figure 9-2: C-SA is
/// octets 11–16).
const ITAG_CSA: usize = 10;

/// The I/G bit: IEEE Std 802.1Q-2014 §9.7 h) says the C-SA field holds "the
/// octet containing the I/G bit in the lowest numbered octet", and IEEE Std
/// 802 assigns that bit 0 for an individual address and 1 for a group address.
const MAC_GROUP_BIT: u8 = 0x01;

/// Octets in an Ethernet II header, through the EtherType. Required before
/// any [`Inner::Ethernet`] offset is returned: this bounds what the decoder is
/// willing to point at, never what the wire said. See the same reasoning in
/// [`super::nsh`].
const ETHERNET_II_HEADER: usize = 14;

/// Decapsulate a Provider Backbone Bridge I-TAG and report the customer frame.
///
/// `off` is the offset of the I-TAG TCI — the byte after the `0x88E7`
/// EtherType. Yields [`Inner::Ethernet`], because §9.7 g)/h) put the
/// encapsulated customer destination and source MAC addresses inside the tag
/// itself: what follows the I-SID is a complete Ethernet II frame, tags and
/// all, not a bare network-layer packet.
///
/// Returns `None` — never a panic, never a read past `d` — for a truncated
/// tag, a non-zero Res2, or a reserved I-SID.
///
/// The 802.1ah feature that defined this tag was folded into IEEE Std 802.1Q
/// in the 2011 revision; §9.7 is quoted from 802.1Q-2014 here, which is the
/// current home of the normative text.
pub(crate) fn itag_decap(d: &[u8], off: usize) -> Option<Inner> {
    let end = off.checked_add(ITAG_TCI_LEN)?;
    let tci = d.get(off..end)?;
    let flags = *tci.first()?;

    // Res2 is enforced and Res1 is not, and the asymmetry is the standard's,
    // not this code's. §9.7 d) on Res1: it "contains a value of zero when the
    // tag is encoded, and is ignored when the tag is decoded". §9.7 e) on
    // Res2: it "contains a value of zero when the tag is encoded. The frame
    // will be discarded if this field contains a nonzero value when the tag is
    // decoded." Enforcing both would reject frames a conforming bridge
    // forwards; enforcing neither would drop a real structural check on a
    // header that is otherwise almost all free-form.
    if flags & ITAG_RES2_MASK != 0 {
        return None;
    }

    // I-PCP, I-DEI and UCA are read by nobody: priority and drop eligibility
    // do not move the customer frame, and UCA (§9.7 c)) tells a Backbone
    // Service Instance Multiplex Entity which addresses to *use* — it does not
    // change whether C-DA and C-SA are present, because the fields are fixed
    // members of a 16-octet tag either way.

    let isid = u32::from_be_bytes([0, *tci.get(1)?, *tci.get(2)?, *tci.get(3)?]);
    // Table 9-3: 0x000000 and 0xFFFFFF "shall not be configured as an
    // identifier for a backbone service instance or transmitted in an I-TAG
    // header" — the first is the null/deleted I-SID used in ISIS-SPB TLVs, the
    // second a management wildcard. Neither can legitimately be on the wire,
    // so seeing one means these octets are not an I-TAG.
    if isid == ISID_NULL || isid == ISID_WILDCARD {
        return None;
    }

    // A plausibility gate, and the I-TAG needs one: strip out I-PCP, I-DEI,
    // UCA and Res1 — all of which are free-form — and the whole 16-octet tag
    // offers exactly two bits of Res2 and two forbidden I-SIDs to test. That
    // leaves arbitrary bytes passing about a quarter of the time, which for a
    // decoder that fabricates a call when it is wrong is far too often.
    //
    // C-SA is a source address: §9.7 h) defines it as "the address in the
    // source_address parameter", §8.7 has a bridge learn from a source address
    // "if and only if the source address is an individual address, i.e., is
    // not a group address", and §20.33.1 discards outright when "the I/G bit
    // of the source_address indicates a Group address". A group-addressed
    // C-SA is therefore not something that was ever legitimately encapsulated.
    //
    // The cost is stated rather than hidden: a genuinely malformed I-TAG whose
    // C-SA has the I/G bit set is missed. That is the direction this module
    // errs in on purpose.
    if d.get(off.checked_add(ITAG_CSA)?)? & MAC_GROUP_BIT != 0 {
        return None;
    }

    let customer = off.checked_add(ITAG_FLAGS_AND_ISID)?;
    captured(d, customer, ETHERNET_II_HEADER)?;
    Some(Inner::Ethernet(customer))
}

// ── MACsec (IEEE Std 802.1AE, EtherType 0x88E5) ───────────────────────

/// SecTAG octets that always follow the MACsec EtherType: TCI/AN, SL and the
/// 32 least significant bits of the PN (IEEE Std 802.1AE-2018 §9.3
/// Figure 9-2). The SecTAG is 8 octets counting the EtherType, so 6 here.
const SECTAG_MIN: usize = 6;

/// Octets the SCI adds when the SC bit is set (§9.9: the SCI "is encoded in
/// octets 9 through 16 of the SecTAG"), taking the SecTAG to 16 octets.
const SECTAG_SCI: usize = 8;

// TCI bit masks against SecTAG octet 3. IEEE Std 802.1AE-2006 Figure 9-4
// assigns, from bit 8 down: V, ES, SC, SCB, E, C, then a 2-bit AN.
//
// The 2018 revision's Figure 9-4 is defective here: it prints "SH" over bit 4
// and "E" over bit 3, names that appear nowhere else in the document — §9.5's
// own prose discusses only the E and C bits, and §9.12 f)/g) test "the C and
// SC bits". The 2006 figure, which the 2018 text otherwise reproduces
// verbatim, reads "E" at bit 4 and "C" at bit 3. The standard's own test
// vectors settle it: Table C-2 ("Integrity protection") carries TCI/AN 0x22
// with the Secure Data byte-for-byte equal to the unprotected User Data of
// Table C-1, and Table C-32 ("Confidentiality protection") carries 0x2E with
// the Secure Data cipher-dependent. 0x2E ^ 0x22 == 0x0C, so bits 4 and 3
// together are what confidentiality sets. The 2006 layout is implemented.
/// V (version), TCI bit 8. §9.5: "The version number shall be 0".
const TCI_V: u8 = 0x80;
/// ES (End Station), TCI bit 7: the SCI is derived from the source MAC.
const TCI_ES: u8 = 0x40;
/// SC, TCI bit 6: an SCI is explicitly encoded, lengthening the SecTAG by 8.
const TCI_SC: u8 = 0x20;
/// SCB (EPON Single Copy Broadcast), TCI bit 5.
const TCI_SCB: u8 = 0x10;
/// E (Encryption), TCI bit 4: set "if and only if confidentiality is being
/// provided" (§9.5).
const TCI_E: u8 = 0x08;
/// C (Changed Text), TCI bit 3: clear "if and only if the Secure Data is
/// exactly the same as the User Data and the ICV is 16 octets long" (§9.5).
const TCI_C: u8 = 0x04;

/// Mask of the reserved pair in the SL octet: §9.7 "Bits 7 and 8 of octet 4
/// shall be zero", restated as validity condition §9.12 e).
const SL_RESERVED: u8 = 0xC0;

/// A validated MACsec SecTAG: where its payload starts, and whether that
/// payload can be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SecTag {
    /// Absolute offset of the first Secure Data octet.
    ///
    /// When `opaque` is false this is also the first octet of the original
    /// frame's User Data, which begins with the EtherType that MACsec
    /// displaced (IEEE Std 802.1AE-2018 Annex C.1 shows the User Data of an
    /// integrity-protected frame starting "08 00 ...").
    pub(crate) payload_off: usize,
    /// True when the Secure Data cannot be recovered from the frame alone.
    pub(crate) opaque: bool,
}

/// Validate a MACsec SecTAG and report its geometry.
///
/// `off` is the offset of SecTAG octet 3 — the byte after the `0x88E5`
/// EtherType.
///
/// This is the entry point a link-layer walk wants, and the only one this
/// module offers: MACsec is a transparent insertion between the source MAC and
/// the EtherType that was there before (§6.2, Figure 6-2), so a caller that is
/// already walking an EtherType chain only needs to know how many octets to
/// step over and whether stepping is worthwhile. Unlike the other tunnels
/// here, MACsec produces no inner *frame* — the original destination and
/// source MAC addresses stay in the outer header — so there is nothing for an
/// [`Inner`]-returning decapsulator to describe that `payload_off` does not
/// already say.
///
/// A sibling `macsec_decap` did once resolve the User Data's EtherType itself
/// and yield [`Inner::Ip`]. It was deleted rather than kept beside this
/// function, because resolving that EtherType means walking any VLAN tags §6.2
/// places "within the Secure Data portion of the MACsec frame" — and that walk
/// is arithmetic `eth_payload_offset` in `parse.rs` already owns, under a
/// doc comment that says so: "One copy of this arithmetic on purpose: two
/// would be two places for an encapsulated packet's start offset to drift."
/// A second copy reachable only from its own unit tests is worse than no copy
/// at all: it can drift away from the live path while its tests keep passing,
/// reporting assurance about code no packet ever reaches. Callers resolve the
/// User Data with the EtherType walk they already have, starting at
/// `payload_off`.
///
/// Returns `None` — never a panic, never a read past `d` — for a truncated
/// SecTAG, a non-zero version, a self-contradictory TCI, a non-zero reserved
/// pair in SL, or a frame with no Secure Data at all.
pub(crate) fn macsec_sectag(d: &[u8], off: usize) -> Option<SecTag> {
    let tci = *d.get(off)?;

    // §9.12 c): "The V bit in the TCI is clear." §9.5 explains what is at
    // stake: "Future versions of the MACsec protocol may use additional bits
    // of the TCI to encode the version number. The fields and format of the
    // remainder of the MPDU may change if the version number changes." A set V
    // bit means every offset computed below would be computed from a layout
    // this code has never seen.
    if tci & TCI_V != 0 {
        return None;
    }

    // §9.12 d): "If the ES or the SCB bit in the TCI is set, then the SC bit
    // is clear." ES says the SCI is derivable from the source MAC and SCB says
    // it is the reserved EPON broadcast value; either together with SC claims
    // the SCI is both implied and explicitly encoded, which leaves the SecTAG
    // length — and therefore every subsequent offset — undetermined.
    let sc = tci & TCI_SC != 0;
    if sc && tci & (TCI_ES | TCI_SCB) != 0 {
        return None;
    }

    // §9.12 e): bits 7 and 8 of the SL octet are reserved and must be clear.
    // The SL value itself is not used: it locates the ICV, and this module
    // reports where the payload begins, not where it ends.
    if d.get(off.checked_add(1)?)? & SL_RESERVED != 0 {
        return None;
    }

    let e = tci & TCI_E != 0;
    let c = tci & TCI_C != 0;

    // §9.5: "If the Encryption (E) bit is set and the Changed Text (C) bit is
    // clear, the frame is not processed by the SecY (10.6) but is reserved for
    // use by the KaY." §10.6 is blunter — "Frames with a SecTAG that has the
    // TCI E bit set but the C bit clear are discarded". This is not a data
    // frame whose payload happens to be unreadable; it is not a data frame.
    // Reporting it as Opaque would tell an operator there is traffic inside.
    if e && !c {
        return None;
    }

    let header = if sc {
        SECTAG_MIN.checked_add(SECTAG_SCI)?
    } else {
        SECTAG_MIN
    };
    let payload_off = off.checked_add(header)?;

    // §9.10: "The Secure Data field is never of zero length, since the
    // primitives of the MAC Service require a non-null MSDU (User Data)
    // parameter." An offset one past the end of what was captured points at
    // nothing, so it is not an offset worth returning.
    d.get(payload_off)?;

    // MACsec does not always encrypt, and treating it as if it did throws away
    // traffic that is sitting in the capture in plain text. §9.5: "the E bit
    // is set if and only if confidentiality is being provided and is clear if
    // integrity only is being provided", and when the Default Cipher Suite is
    // used for integrity only "the Secure Data is the unmodified User Data ...
    // the data conveyed by MACsec is available to applications ... that need
    // to see the data but are not trusted with the SAK". Both bits clear is
    // therefore fully readable plaintext.
    //
    // Both bits set is confidentiality — "If both the C bit and E bit are set,
    // confidentiality of the original User Data is being provided."
    //
    // E clear with C set is the subtle one, and it is still opaque: some
    // cipher suites transform or extend the data even for integrity only, and
    // §9.5 says "Recovery of the data from a MACsec frame with the E bit clear
    // and the C bit set requires knowledge of the Cipher Suite at a minimum.
    // That information is not provided in the MACsec frame." Not encrypted,
    // but not recoverable either — which is exactly what Opaque means.
    Some(SecTag {
        payload_off,
        opaque: c,
    })
}

/// `Some(())` when `d` holds `need` octets starting at `at`.
fn captured(d: &[u8], at: usize, need: usize) -> Option<()> {
    d.get(at..at.checked_add(need)?).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::tunnel::Inner;

    /// Where the tag body starts in every fixture — i.e. just past the
    /// EtherType, which the caller has already consumed. Non-zero so a
    /// decoder measuring from the wrong base cannot pass by accident.
    const OFF: usize = 14;

    fn ipv4() -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0] = 0x45;
        h[3] = 20;
        h[9] = 17;
        h
    }

    /// Customer Ethernet II frame carried inside an I-TAG: C-DA, C-SA, then
    /// the customer's own EtherType and payload.
    fn customer_frame() -> Vec<u8> {
        let mut f = vec![0x11u8; 6]; // C-DA
        f.extend_from_slice(&[0x22u8; 6]); // C-SA
        f.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        f.extend_from_slice(&ipv4());
        f
    }

    /// I-TAG TCI octet 1 per IEEE Std 802.1Q-2014 Figure 9-2:
    /// bits 8..6 I-PCP, bit 5 I-DEI, bit 4 UCA, bit 3 Res1, bits 2..1 Res2.
    fn itag_flags(pcp: u8, dei: bool, uca: bool, res1: bool, res2: u8) -> u8 {
        ((pcp & 0x07) << 5)
            | (u8::from(dei) << 4)
            | (u8::from(uca) << 3)
            | (u8::from(res1) << 2)
            | (res2 & 0x03)
    }

    /// A full I-TAG body (I-TCI octets 1..4) followed by the customer frame.
    fn itag(flags: u8, isid: u32) -> Vec<u8> {
        let mut t = vec![flags];
        t.extend_from_slice(&isid.to_be_bytes()[1..4]);
        t.extend_from_slice(&customer_frame());
        t
    }

    /// SecTAG octet 3 (TCI + AN) per IEEE Std 802.1AE-2006 Figure 9-4:
    /// bit 8 V, 7 ES, 6 SC, 5 SCB, 4 E, 3 C, bits 2..1 AN.
    #[allow(clippy::fn_params_excessive_bools)]
    fn tci(v: bool, es: bool, sc: bool, scb: bool, e: bool, c: bool, an: u8) -> u8 {
        (u8::from(v) << 7)
            | (u8::from(es) << 6)
            | (u8::from(sc) << 5)
            | (u8::from(scb) << 4)
            | (u8::from(e) << 3)
            | (u8::from(c) << 2)
            | (an & 0x03)
    }

    /// A MACsec SecTAG body (octets 3..) followed by `secure_data`.
    ///
    /// `sl` is the Short Length octet; the SCI is emitted iff the SC bit is
    /// set in `tci_an`, which is what makes the SecTAG variable-length.
    fn sectag(tci_an: u8, sl: u8, secure_data: &[u8]) -> Vec<u8> {
        let mut t = vec![tci_an, sl];
        t.extend_from_slice(&[0xB2, 0xC2, 0x84, 0x65]); // PN
        if tci_an & 0x20 != 0 {
            t.extend_from_slice(&[0x12, 0x15, 0x35, 0x24, 0xC0, 0x89, 0x5E, 0x81]); // SCI
        }
        t.extend_from_slice(secure_data);
        t
    }

    /// MACsec Secure Data for an integrity-only frame: the User Data begins
    /// with the original EtherType (IEEE Std 802.1AE-2018 Annex C.1 shows
    /// exactly this, "08 00 ..."), then the IP header, then the 16-octet ICV.
    fn user_data_ipv4() -> Vec<u8> {
        let mut u = vec![0x08u8, 0x00];
        u.extend_from_slice(&ipv4());
        u.extend_from_slice(&[0x5Au8; 16]); // ICV
        u
    }

    fn frame(parts: &[&[u8]]) -> Vec<u8> {
        let mut d = vec![0xAAu8; OFF];
        for p in parts {
            d.extend_from_slice(p);
        }
        d
    }

    // ── PBB I-TAG (IEEE Std 802.1Q, EtherType 0x88E7) ─────────────────

    #[test]
    fn an_itag_yields_the_customer_frame_four_octets_in() {
        // I-TCI octets 1..4 are flags + I-SID; C-DA starts at octet 5.
        let d = frame(&[&itag(itag_flags(3, false, true, false, 0), 0x00_1234)]);
        assert_eq!(itag_decap(&d, OFF), Some(Inner::Ethernet(OFF + 4)));
    }

    #[test]
    fn a_nonzero_res2_is_rejected() {
        // IEEE Std 802.1Q-2014 §9.7 e): "The frame will be discarded if this
        // field contains a nonzero value when the tag is decoded."
        for res2 in [1u8, 2, 3] {
            let d = frame(&[&itag(itag_flags(0, false, false, false, res2), 0x00_1234)]);
            assert_eq!(itag_decap(&d, OFF), None, "Res2 {res2} must be rejected");
        }
    }

    #[test]
    fn a_nonzero_res1_is_ignored_not_rejected() {
        // IEEE Std 802.1Q-2014 §9.7 d): Res1 "is ignored when the tag is
        // decoded" — the asymmetry with Res2 is deliberate in the standard.
        let d = frame(&[&itag(itag_flags(0, false, false, true, 0), 0x00_1234)]);
        assert_eq!(itag_decap(&d, OFF), Some(Inner::Ethernet(OFF + 4)));
    }

    #[test]
    fn the_priority_and_drop_eligible_bits_do_not_affect_the_decap() {
        for pcp in 0..8u8 {
            for dei in [false, true] {
                let d = frame(&[&itag(itag_flags(pcp, dei, false, false, 0), 0x00_ABCD)]);
                assert_eq!(itag_decap(&d, OFF), Some(Inner::Ethernet(OFF + 4)));
            }
        }
    }

    #[test]
    fn the_reserved_isid_values_are_rejected() {
        // IEEE Std 802.1Q-2014 Table 9-3: both 0x000000 and 0xFFFFFF "shall
        // not be ... transmitted in an I-TAG header".
        for isid in [0x00_0000u32, 0xFF_FFFF] {
            let d = frame(&[&itag(itag_flags(0, false, false, false, 0), isid)]);
            assert_eq!(itag_decap(&d, OFF), None, "I-SID {isid:#08x} is illegal");
        }
    }

    #[test]
    fn an_itag_truncated_before_the_customer_ethertype_is_rejected() {
        // The I-TAG TCI is 16 octets: 4 of flags+I-SID, then C-DA and C-SA.
        // `Inner::Ethernet` promises a complete Ethernet II frame, so the
        // customer EtherType at octets 17-18 has to be there too — an offset
        // to a frame with no EtherType is one nothing downstream can walk.
        let full = itag(itag_flags(0, false, false, false, 0), 0x00_1234);
        for cut in 0..18 {
            let d = frame(&[&full[..cut]]);
            assert_eq!(
                itag_decap(&d, OFF),
                None,
                "an I-TAG cut to {cut} octets must not decap"
            );
        }
        let d = frame(&[&full[..18]]);
        assert_eq!(itag_decap(&d, OFF), Some(Inner::Ethernet(OFF + 4)));
    }

    #[test]
    fn a_group_addressed_customer_source_address_is_rejected() {
        // IEEE Std 802.1Q-2014 §8.7 / §20.33.1: a source address is an
        // individual address; the I/G bit is bit 1 of its lowest-numbered
        // octet, which is C-SA octet 1 (I-TAG TCI octet 11).
        let mut d = frame(&[&itag(itag_flags(0, false, false, false, 0), 0x00_1234)]);
        assert_eq!(itag_decap(&d, OFF), Some(Inner::Ethernet(OFF + 4)));
        d[OFF + 10] |= 0x01;
        assert_eq!(itag_decap(&d, OFF), None);
    }

    #[test]
    fn a_group_addressed_customer_destination_address_is_accepted() {
        // C-DA is a destination: broadcast and multicast are entirely normal
        // there, so the I/G gate must apply to C-SA only.
        let mut d = frame(&[&itag(itag_flags(0, false, false, false, 0), 0x00_1234)]);
        d[OFF + 4] |= 0x01;
        assert_eq!(itag_decap(&d, OFF), Some(Inner::Ethernet(OFF + 4)));
    }

    #[test]
    fn an_itag_offset_past_the_end_of_the_frame_yields_none() {
        let d = frame(&[&itag(itag_flags(0, false, false, false, 0), 0x00_1234)]);
        assert_eq!(itag_decap(&d, d.len()), None);
        assert_eq!(itag_decap(&d, usize::MAX), None);
        assert_eq!(itag_decap(&[], 0), None);
    }

    // ── MACsec (IEEE Std 802.1AE, EtherType 0x88E5) ───────────────────

    #[test]
    fn an_integrity_only_sectag_without_an_sci_is_six_octets_and_readable() {
        // E and C both clear: "the Secure Data is the unmodified User Data"
        // (IEEE Std 802.1AE-2018 §9.5). SecTAG octets 3..8 => 6 octets past
        // the EtherType, then the User Data's own EtherType, then the IP.
        let d = frame(&[&sectag(
            tci(false, false, false, false, false, false, 1),
            0x2A,
            &user_data_ipv4(),
        )]);
        assert_eq!(
            macsec_sectag(&d, OFF),
            Some(SecTag {
                payload_off: OFF + 6,
                opaque: false,
            })
        );
        // Readable means the caller's own EtherType walk resumes exactly here,
        // on the EtherType MACsec displaced (Annex C.1: "08 00 ...").
        assert_eq!(&d[OFF + 6..OFF + 8], &[0x08, 0x00]);
    }

    #[test]
    fn an_integrity_only_sectag_with_an_sci_is_fourteen_octets_and_readable() {
        // The SC bit adds the 8-octet SCI. This is IEEE Std 802.1AE-2018
        // Table C-2 verbatim: TCI/AN 0x22, SL 0x2A, PN, SCI, plaintext.
        let d = frame(&[&sectag(0x22, 0x2A, &user_data_ipv4())]);
        assert_eq!(
            macsec_sectag(&d, OFF),
            Some(SecTag {
                payload_off: OFF + 14,
                opaque: false,
            })
        );
        assert_eq!(&d[OFF + 14..OFF + 16], &[0x08, 0x00]);
    }

    #[test]
    fn a_confidentiality_protected_frame_is_opaque() {
        // Table C-32 verbatim: TCI/AN 0x2E — SC, E and C all set.
        let d = frame(&[&sectag(0x2E, 0x00, &[0x99u8; 64])]);
        assert_eq!(
            macsec_sectag(&d, OFF),
            Some(SecTag {
                payload_off: OFF + 14,
                opaque: true,
            })
        );
    }

    #[test]
    fn integrity_with_a_transforming_cipher_suite_is_opaque() {
        // E clear, C set: §9.5 — "Recovery of the data ... requires knowledge
        // of the Cipher Suite at a minimum. That information is not provided
        // in the MACsec frame." Readable it is not, encrypted it is not
        // either, so it is still opaque rather than a payload or a silent drop.
        // The geometry is still reported: the SecTAG is well formed, and only
        // what sits past it is unrecoverable.
        let d = frame(&[&sectag(
            tci(false, false, true, false, false, true, 0),
            0x00,
            &[0x99u8; 64],
        )]);
        assert_eq!(
            macsec_sectag(&d, OFF),
            Some(SecTag {
                payload_off: OFF + 14,
                opaque: true,
            })
        );
    }

    #[test]
    fn the_kay_reserved_e_set_c_clear_combination_is_rejected() {
        // §9.5: "If the Encryption (E) bit is set and the Changed Text (C)
        // bit is clear, the frame is not processed by the SecY ... but is
        // reserved for use by the KaY", and §10.6 discards it. It is not a
        // data frame at all, so there is no payload to claim.
        let d = frame(&[&sectag(
            tci(false, false, true, false, true, false, 0),
            0x00,
            &[0x99u8; 64],
        )]);
        assert_eq!(macsec_sectag(&d, OFF), None);
    }

    #[test]
    fn a_nonzero_version_bit_is_rejected() {
        // §9.12 c): "The V bit in the TCI is clear." §9.5 warns that the
        // remainder of the MPDU may be laid out differently if it is not.
        let d = frame(&[&sectag(
            tci(true, false, true, false, false, false, 0),
            0x2A,
            &user_data_ipv4(),
        )]);
        assert_eq!(macsec_sectag(&d, OFF), None);
    }

    #[test]
    fn es_or_scb_set_together_with_sc_is_rejected() {
        // §9.12 d): "If the ES or the SCB bit in the TCI is set, then the SC
        // bit is clear." The combination is self-contradictory: it claims the
        // SCI is both implied and explicitly encoded, so the SecTAG length is
        // ambiguous and every offset downstream would be a guess.
        let es_and_sc = tci(false, true, true, false, false, false, 0);
        let d = frame(&[&sectag(es_and_sc, 0x2A, &user_data_ipv4())]);
        assert_eq!(macsec_sectag(&d, OFF), None);

        let scb_and_sc = tci(false, false, true, true, false, false, 0);
        let d = frame(&[&sectag(scb_and_sc, 0x2A, &user_data_ipv4())]);
        assert_eq!(macsec_sectag(&d, OFF), None);
    }

    #[test]
    fn the_end_station_bit_alone_keeps_the_short_sectag() {
        // ES set without SC: the SCI is derived from the source MAC and is
        // not encoded, so the SecTAG stays 8 octets (6 past the EtherType).
        let d = frame(&[&sectag(
            tci(false, true, false, false, false, false, 0),
            0x2A,
            &user_data_ipv4(),
        )]);
        assert_eq!(
            macsec_sectag(&d, OFF),
            Some(SecTag {
                payload_off: OFF + 6,
                opaque: false,
            })
        );
    }

    #[test]
    fn a_nonzero_reserved_pair_in_the_short_length_octet_is_rejected() {
        // §9.7: "Bits 7 and 8 of octet 4 shall be zero", restated as a
        // validity condition in §9.12 e).
        for sl in [0x40u8, 0x80, 0xC0] {
            let d = frame(&[&sectag(0x22, sl, &user_data_ipv4())]);
            assert_eq!(
                macsec_sectag(&d, OFF),
                None,
                "SL {sl:#04x} must be rejected"
            );
        }
    }

    #[test]
    fn the_association_number_does_not_affect_the_sectag_geometry() {
        // AN selects the SA within the SC; it changes no offset and no bit
        // this module reads, so all four values must give the same answer.
        for an in 0..4u8 {
            let d = frame(&[&sectag(
                tci(false, false, true, false, false, false, an),
                0x2A,
                &user_data_ipv4(),
            )]);
            assert_eq!(
                macsec_sectag(&d, OFF),
                Some(SecTag {
                    payload_off: OFF + 14,
                    opaque: false,
                }),
                "AN {an} must not move the payload"
            );
        }
    }

    #[test]
    fn a_vlan_tag_inside_the_secure_data_is_left_for_the_caller() {
        // IEEE Std 802.1AE-2018 §6.2 / Figure 6-2 puts the VLAN TAG in "the
        // initial octets of the MSDU", i.e. inside the Secure Data — so
        // `payload_off` lands on the C-TAG EtherType, not past it. Stepping
        // over the tag is the caller's EtherType walk, which owns the only
        // copy of that arithmetic; this module must not do it a second time.
        let mut user = vec![0x81u8, 0x00, 0x00, 0x64, 0x08, 0x00];
        user.extend_from_slice(&ipv4());
        user.extend_from_slice(&[0x5Au8; 16]);
        let d = frame(&[&sectag(0x22, 0x00, &user)]);
        assert_eq!(
            macsec_sectag(&d, OFF),
            Some(SecTag {
                payload_off: OFF + 14,
                opaque: false,
            })
        );
        assert_eq!(&d[OFF + 14..OFF + 16], &[0x81, 0x00]);
    }

    #[test]
    fn a_non_ip_ethertype_in_the_secure_data_still_reports_the_sectag() {
        // ARP inside an integrity-only MACsec frame. Whether the User Data is
        // IP is not a MACsec question: the SecTAG is well formed either way,
        // and the caller's EtherType walk is what decides there is no IP here.
        let mut user = vec![0x08u8, 0x06];
        user.extend_from_slice(&[0x00u8; 28]);
        user.extend_from_slice(&[0x5Au8; 16]);
        let d = frame(&[&sectag(0x22, 0x00, &user)]);
        assert_eq!(
            macsec_sectag(&d, OFF),
            Some(SecTag {
                payload_off: OFF + 14,
                opaque: false,
            })
        );
        assert_eq!(&d[OFF + 14..OFF + 16], &[0x08, 0x06]);
    }

    #[test]
    fn macsec_truncation_at_every_boundary_yields_none_and_never_panics() {
        let full = sectag(0x22, 0x2A, &user_data_ipv4());
        let d = frame(&[&full]);
        let whole = Some(SecTag {
            payload_off: OFF + 14,
            opaque: false,
        });
        assert_eq!(macsec_sectag(&d, OFF), whole);

        // The SecTAG becomes readable the moment its own 14 octets are all
        // present *and* one octet of Secure Data follows it — §9.10's "never
        // of zero length" is the last condition to be satisfied, so the
        // boundary is OFF + 14 + 1. Everything past that octet, including the
        // whole IP header and the ICV, is the caller's problem, so the answer
        // must not change again. That boundary is asserted exactly rather than
        // as "None until the last byte", which would have been true only by
        // accident of the fixture.
        let first_readable = OFF + 14 + 1;
        for cut in 0..first_readable {
            assert_eq!(
                macsec_sectag(&d[..cut], OFF),
                None,
                "a frame truncated to {cut} bytes has no readable SecTAG"
            );
        }
        for cut in first_readable..=d.len() {
            assert_eq!(
                macsec_sectag(&d[..cut], OFF),
                whole,
                "a frame truncated to {cut} bytes holds a whole SecTAG"
            );
        }
    }

    #[test]
    fn a_sectag_with_no_secure_data_at_all_is_rejected() {
        // §9.10: "The Secure Data field is never of zero length."
        let d = frame(&[&sectag(0x22, 0x00, &[])]);
        assert_eq!(macsec_sectag(&d, OFF), None);
    }

    #[test]
    fn a_macsec_offset_past_the_end_of_the_frame_yields_none() {
        let d = frame(&[&sectag(0x22, 0x2A, &user_data_ipv4())]);
        assert_eq!(macsec_sectag(&d, d.len()), None);
        assert_eq!(macsec_sectag(&d, usize::MAX), None);
        assert_eq!(macsec_sectag(&d, usize::MAX - 4), None);
        assert_eq!(macsec_sectag(&[], 0), None);
    }

    #[test]
    fn an_rtp_packet_read_as_a_sectag_or_an_itag_is_rejected() {
        // RTP version 2 sets bit 8 of the first octet, which is the MACsec
        // V bit — rejected before any offset is computed. For the I-TAG the
        // payload's Res2 and I-SID happen to be legal, and the C-SA I/G gate
        // is what catches it: 0xD5 is a group address.
        let mut rtp = vec![0x80u8, 0x08, 0x12, 0x34];
        rtp.extend_from_slice(&[0xD5; 160]);
        let d = frame(&[&rtp]);
        assert_eq!(macsec_sectag(&d, OFF), None);
        assert_eq!(itag_decap(&d, OFF), None);
    }
}
