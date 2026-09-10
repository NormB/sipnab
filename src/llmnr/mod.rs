// SPDX-License-Identifier: MIT OR Apache-2.0

//! LLMNR (RFC 4795) decoding.
//!
//! Link-Local Multicast Name Resolution is Windows' fallback for names DNS
//! cannot answer: the host multicasts the query to `224.0.0.252:5355` or
//! `[ff02::1:3]:5355` and whoever owns the name replies. It is ambient LAN
//! chatter, and it is in essentially every enterprise capture.
//!
//! It must be identified here whatever else happens, because the alternative
//! is not "ignored", it is "misread as media". An LLMNR query is a DNS-format
//! message whose first two bytes are a random transaction ID, and one in four
//! of those IDs has `0b10` in the top two bits: the RTP version. The rest of
//! the strict RTP pre-filter (12+ bytes, payload type outside the RTCP range)
//! a 23-byte query passes trivially. That is not hypothetical — it is where
//! this module came from. A real capture produced two phantom RTP streams,
//! SSRC `0x00000000`, two packets each, from a Windows host looking up a
//! hostname. The same collision is already documented for DNS responses from
//! port 53; the guard that catches those only applies below port 1024, and
//! LLMNR sits at 5355.
//!
//! Claiming the packet during classification, before any media check, removes
//! the whole class by construction rather than by heuristic tuning.
//!
//! **Scope.** sipnab is not a general dissector; it decodes SIP/VoIP and the
//! protocols a call depends on. LLMNR is decoded anyway, for a reason that has
//! nothing to do with name resolution: the messages carry a host roster. A
//! query names a machine looking for something, a response names a machine
//! that owns a hostname and gives its address, and together they answer "whose
//! LAN is this capture from" without sending a packet. That, and the fact that
//! LLMNR being enabled at all is a security finding — it is the protocol the
//! Responder tool abuses to harvest NTLM credentials — is the whole
//! justification. See [`store`] for what is kept.
//!
//! Nothing here feeds call diagnosis, and it must not start to.

pub mod parser;
pub mod store;

/// The IANA-assigned LLMNR port, for both UDP and TCP (RFC 4795 §2).
pub const PORT: u16 = 5355;

/// Fixed DNS/LLMNR header length: ID(2) + flags(2) + four section counts(8).
pub const HEADER_LEN: usize = 12;

/// Whether a UDP payload on this port pair is an LLMNR message.
///
/// LLMNR has no magic cookie — the format is bare DNS — so the
/// port is load-bearing evidence and is checked first. The structural checks
/// after it exist so that a stray datagram sent to 5355 is not decoded as a
/// name lookup:
///
///   * the header must fit;
///   * the opcode must be 0, the only one LLMNR defines (RFC 4795 §2.1.1);
///   * the Z field is reserved and must be zero (ibid.);
///   * a query must ask exactly one question (RFC 4795 §2.1.1: "senders MUST
///     send LLMNR queries with QDCOUNT set to one");
///   * a query must carry RCODE zero (ibid.: "In an LLMNR query, the sender
///     MUST set RCODE to zero");
///   * a query must not set TC (ibid.: "The 'TC' bit MUST NOT be set in an
///     LLMNR query") — a query that did not fit is one nobody can answer.
///
/// The last three are query-only, and deliberately. A responder sets RCODE and
/// the RFC forbids TC only on queries, so applying either to both directions
/// would reject real answers while every negative test went on passing.
///
/// Together those reject the arbitrary-bytes case while admitting every
/// conformant message, which is the same trade the STUN cookie makes for
/// free.
pub fn is_llmnr_packet(data: &[u8], src_port: u16, dst_port: u16) -> bool {
    if src_port != PORT && dst_port != PORT {
        return false;
    }
    if data.len() < HEADER_LEN {
        return false;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    // OPCODE is bits 14..11; LLMNR defines only 0 (standard query).
    if (flags >> 11) & 0x0f != 0 {
        return false;
    }
    // Z is bits 7..4, reserved, must be zero.
    if (flags >> 4) & 0x0f != 0 {
        return false;
    }
    let is_response = flags & 0x8000 != 0;
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    // Exactly one question on a query. A response echoes the question back,
    // so the same holds there in practice, but the RFC only mandates it for
    // senders — so a response is admitted with any count, keeping even a
    // non-conformant responder out of the media path, which is the outcome
    // this whole module exists to produce.
    if !is_response && qdcount != 1 {
        return false;
    }
    // Two more query-only rules from the same section, and the same trade.
    // RCODE is bits 3..0: "In an LLMNR query, the sender MUST set RCODE to
    // zero; the responder ignores the RCODE and assumes it to be zero." TC is
    // bit 9: "The 'TC' bit MUST NOT be set in an LLMNR query" — a query that
    // did not fit is a query nobody can answer.
    //
    // Five bits, on a decoder whose only other evidence is a port number.
    // Query-only for the reason above: a responder sets RCODE, so applying
    // either rule to both directions would reject real answers.
    if !is_response && (flags & 0x000f != 0 || flags & 0x0200 != 0) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real LLMNR query for the name "GHS08", byte-exact from the capture
    /// that motivated this module. Transaction ID `0x8006` is the one that
    /// collided with the RTP version bits.
    const QUERY: &[u8] = &[
        0x80, 0x06, // transaction ID — 0x80 is also RTP version 2
        0x00, 0x00, // flags: query, opcode 0
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        0x05, b'G', b'H', b'S', b'0', b'8', 0x00, // QNAME "GHS08"
        0x00, 0x01, // QTYPE = A
        0x00, 0x01, // QCLASS = IN
    ];

    #[test]
    fn detects_a_query_on_the_llmnr_port() {
        assert!(is_llmnr_packet(QUERY, 51391, PORT));
    }

    #[test]
    fn rejects_the_same_bytes_off_port() {
        assert!(!is_llmnr_packet(QUERY, 40000, 40001));
    }

    #[test]
    fn rejects_payload_shorter_than_the_header() {
        assert!(!is_llmnr_packet(&QUERY[..11], 51391, PORT));
    }

    #[test]
    fn rejects_a_nonzero_opcode() {
        let mut data = QUERY.to_vec();
        data[2] = 0x28; // opcode 5
        assert!(!is_llmnr_packet(&data, 51391, PORT));
    }

    #[test]
    fn rejects_a_nonzero_reserved_field() {
        let mut data = QUERY.to_vec();
        data[3] = 0x10; // Z = 1
        assert!(!is_llmnr_packet(&data, 51391, PORT));
    }

    #[test]
    fn rejects_a_query_that_asks_nothing() {
        let mut data = QUERY.to_vec();
        data[5] = 0x00; // QDCOUNT = 0
        assert!(!is_llmnr_packet(&data, 51391, PORT));
    }

    /// RFC 4795 section 2.1.1: *"In an LLMNR query, the sender MUST set RCODE
    /// to zero"*.
    ///
    /// Four more bits that are zero in every conformant query, on a decoder
    /// whose only other evidence is a port number. The responder ignores
    /// RCODE, so this holds for queries alone --- which is where the
    /// discrimination is needed, since a query is what a stray datagram would
    /// be mistaken for.
    #[test]
    fn rejects_a_query_carrying_a_response_code() {
        for rcode in 1u8..=15 {
            let mut data = QUERY.to_vec();
            data[3] = rcode;
            assert!(
                !is_llmnr_packet(&data, 51391, PORT),
                "RCODE {rcode} in a query is non-conformant and spends a \
                 discriminator this module needs"
            );
        }
    }

    /// RFC 4795 section 2.1.1: *"The 'TC' bit MUST NOT be set in an LLMNR
    /// query"*.
    ///
    /// One more bit, and unlike RCODE this one is a positive prohibition
    /// rather than a default: a truncated QUERY is meaningless, because a
    /// query that did not fit is a query nobody can answer.
    #[test]
    fn rejects_a_truncated_query() {
        let mut data = QUERY.to_vec();
        data[2] |= 0x02; // TC
        assert!(!is_llmnr_packet(&data, 51391, PORT));
    }

    /// A response may carry both, and is still admitted.
    ///
    /// The positive control for the two rules above. Responders set RCODE, and
    /// the RFC forbids TC only on queries --- so a rule applied to both
    /// directions would reject real answers, and every negative assertion
    /// above would still pass while the module quietly stopped seeing half of
    /// LLMNR.
    #[test]
    fn a_response_may_carry_a_response_code_and_the_truncation_bit() {
        let mut data = QUERY.to_vec();
        data[2] = 0x80 | 0x02; // QR = 1, TC = 1
        data[3] = 0x03; // RCODE = NXDOMAIN
        assert!(is_llmnr_packet(&data, PORT, 51391));
    }

    /// The defect in one assertion: this payload passes sipnab's strict RTP
    /// pre-filter, so if LLMNR is not claimed first it becomes a media stream.
    #[test]
    fn the_colliding_query_would_otherwise_pass_the_rtp_filter() {
        assert!(
            crate::rtp::is_rtp_packet(QUERY),
            "if this ever stops being true the RTP filter changed; the LLMNR \
             claim must still come first, but this test no longer proves why"
        );
        assert!(is_llmnr_packet(QUERY, 51391, PORT));
    }
}
