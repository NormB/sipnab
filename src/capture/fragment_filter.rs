// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Capture-filter terms that let IP fragments reach reassembly (issue #926).
//!
//! A SIP message larger than the path MTU travels as IP fragments, and only
//! the first fragment carries the UDP or TCP header. Every later fragment is
//! bare IP with no ports, so a filter made of port tests rejects it in the
//! kernel. Reassembly then never receives it, the message is lost, and no
//! counter moves: the kernel did not drop the fragment, the filter declined
//! it.
//!
//! This module holds the one rule for which fragments a capture filter
//! passes, in the spellings sipnab needs:
//!
//! * [`fragment_arm`]: the term the auto-generated filter adds for an IP
//!   header right behind the link-layer header. Written with libpcap's
//!   `ip[]` and `ip6[]`, which libpcap places per link type, so the same
//!   string works on Ethernet, Linux cooked v1 and v2, raw IP and loopback.
//! * [`ipv4_fragment_at`] and [`ipv6_fragment_at`]: the same test for an IP
//!   header at a fixed offset inside a VLAN tag, QinQ, PPPoE or MPLS, which
//!   the encapsulated arms of the generated filter probe.
//! * [`OPERATOR_FRAGMENT_CLAUSE`] and [`with_fragment_clause`]: the short
//!   clause an operator appends to a filter of their own.
//!
//! [`misses_later_fragments`] decides whether an operator's filter is blind
//! to later fragments, for the startup warning.
//!
//! # Which fragments
//!
//! Every fragment, the first one included, of a datagram whose IP protocol
//! is one that reassembly turns into something sipnab reads
//! ([`REASSEMBLED_PROTOCOLS`]). The first fragment is passed whatever its
//! ports: the later ones cannot be told apart by port, so admitting only
//! some first fragments would leave the later fragments of every other
//! datagram as entries that never complete. Admitted whole, a datagram that
//! is not SIP is reassembled, read and discarded at once.
//!
//! # Limits
//!
//! * IPv6: a Fragment header directly behind the IPv6 header, or behind one
//!   Hop-by-Hop, Routing or Destination Options header, is matched on
//!   untagged traffic. Classic BPF has no loop, so a Fragment header behind
//!   two or more extension headers is not. Inside an encapsulation, only a
//!   Fragment header directly behind the IPv6 header is matched.
//! * SCTP (132) splits large messages into DATA chunks itself and normally
//!   sets Don't Fragment, so its fragments are rare; they are passed and read
//!   like UDP's when a sender does fragment.

/// IP protocols whose fragments reassembly turns into something sipnab
/// reads: UDP (17), TCP (6), ESP (50, read when NULL-encrypted) and SCTP
/// (132).
///
/// Taken from what `PacketProcessor` does with a completed datagram: it
/// re-reads a UDP, TCP or SCTP header, and unwraps a NULL-encrypted ESP
/// payload first. Any other protocol is handed on as raw bytes no decoder
/// reads.
pub const REASSEMBLED_PROTOCOLS: [u8; 4] = [17, 6, 50, 132];

/// The IPv6 extension headers [`fragment_arm`] steps over, one of them, to
/// find a Fragment header behind it: Hop-by-Hop Options (0), Routing (43)
/// and Destination Options (60).
///
/// All three share the generic length field ([RFC 8200 section 4.3](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.3)):
/// byte 1 is the length in 8-octet units, not counting the first 8.
pub const IPV6_HEADERS_BEFORE_FRAGMENT: [u8; 3] = [0, 43, 60];

/// The IPv6 Next Header value of a Fragment header.
const IPV6_FRAGMENT_HEADER: u8 = 44;

/// The clause an operator appends to a port-based filter of their own so
/// that it passes IP fragments: every later IPv4 fragment, and every IPv6
/// packet whose next header is a Fragment header.
///
/// Shorter than [`fragment_arm`], because a person types it. It leaves the
/// IPv4 first fragment to the operator's own port test, which matches it:
/// the first fragment carries the ports. An IPv6 first fragment does not
/// match a libpcap `port` test, which reads the base header's next-header
/// field, so the IPv6 half takes every fragment.
pub const OPERATOR_FRAGMENT_CLAUSE: &str = "(ip[6:2] & 0x1fff != 0) or (ip6[6] = 44)";

/// "`byte` names one of [`REASSEMBLED_PROTOCOLS`]", as a BPF term.
fn reassembled_protocol(byte: &str) -> String {
    let terms: Vec<String> = REASSEMBLED_PROTOCOLS
        .iter()
        .map(|p| format!("{byte} = {p}"))
        .collect();
    format!("({})", terms.join(" or "))
}

/// The term the auto-generated filter adds so that IP fragments of the
/// protocols reassembly reads pass the kernel, for an IP header right behind
/// the link-layer header.
///
/// IPv4: the More Fragments bit or a non-zero offset (`& 0x3fff`), so the
/// first fragment and every later one. The flags word and the protocol byte
/// sit at fixed offsets whatever the header length, so IPv4 options do not
/// matter. IPv6: a Fragment header directly behind the IPv6 header, or behind
/// one of [`IPV6_HEADERS_BEFORE_FRAGMENT`].
#[must_use]
pub fn fragment_arm() -> String {
    let v4 = format!(
        "(ip[6:2] & 0x3fff != 0 and {})",
        reassembled_protocol("ip[9]")
    );
    let v6 = format!(
        "(ip6[6] = {IPV6_FRAGMENT_HEADER} and {})",
        reassembled_protocol("ip6[40]")
    );
    // One extension header first: it starts at 40, its byte 1 is its
    // length in 8-octet units beyond the first 8, so the Fragment header
    // behind it starts at 48 + 8 * ip6[41], and byte 0 there names what
    // the fragments carry.
    let before: Vec<String> = IPV6_HEADERS_BEFORE_FRAGMENT
        .iter()
        .map(|h| format!("ip6[6] = {h}"))
        .collect();
    let v6_behind_one = format!(
        "(({}) and ip6[40] = {IPV6_FRAGMENT_HEADER} and {})",
        before.join(" or "),
        reassembled_protocol("ip6[48 + ip6[41] * 8]")
    );
    format!("({v4} or {v6} or {v6_behind_one})")
}

/// [`fragment_arm`]'s IPv4 test for an IP header `ip_off` bytes into the
/// frame, as absolute-offset terms.
///
/// Checks the version nibble rather than the whole first byte, so a header
/// with options matches too.
#[must_use]
pub fn ipv4_fragment_at(ip_off: usize) -> String {
    format!(
        "(ether[{ip_off}] & 0xf0 = 0x40 and ether[{flags}:2] & 0x3fff != 0 and {})",
        reassembled_protocol(&format!("ether[{}]", ip_off + 9)),
        flags = ip_off + 6,
    )
}

/// [`fragment_arm`]'s IPv6 test for an IPv6 header `ip_off` bytes into the
/// frame, as absolute-offset terms: a Fragment header directly behind the
/// base header, carrying one of [`REASSEMBLED_PROTOCOLS`].
///
/// Leaves the version check to the caller, which already makes it for the
/// port test at the same offset.
#[must_use]
pub fn ipv6_fragment_at(ip_off: usize) -> String {
    format!(
        "(ether[{nh}] = {IPV6_FRAGMENT_HEADER} and {})",
        reassembled_protocol(&format!("ether[{}]", ip_off + 40)),
        nh = ip_off + 6,
    )
}

/// `filter` with [`OPERATOR_FRAGMENT_CLAUSE`] appended, ready to paste.
///
/// The operator's expression is parenthesized, so an `and` inside it still
/// narrows only what it narrowed before.
#[must_use]
pub fn with_fragment_clause(filter: &str) -> String {
    format!("({}) or {OPERATOR_FRAGMENT_CLAUSE}", filter.trim())
}

/// Text that shows a filter tests ports: libpcap's `port`/`portrange`
/// (with `src`/`dst`, `udp`/`tcp` qualifiers), and a transport-relative
/// load (`udp[2:2]`), which libpcap also limits to the first fragment.
const PORT_TOKENS: [&str; 4] = ["port", "udp[", "tcp[", "sctp["];

/// Text that shows a filter already handles IP fragments: a read of the IPv4
/// flags word, its fragment masks in hex or decimal, a test of the IPv6 next
/// header, or `protochain`, which walks IPv6 extension headers.
///
/// Matched after spaces are removed and the text is lower-cased.
const FRAGMENT_TOKENS: [&str; 8] = [
    "ip[6",
    "0x1fff",
    "0x3fff",
    "8191",
    "16383",
    "ip6[6]",
    "protochain",
    "proto44",
];

/// Whether `filter` tests ports and lets no later IP fragment through, so a
/// SIP message larger than the path MTU never reaches reassembly.
///
/// Three questions, all of which must say "blind":
///
/// 1. The text tests a port (`PORT_TOKENS`). A filter that selects on
///    hosts or protocols alone passes fragments of what it selects.
/// 2. The text shows no fragment handling (`FRAGMENT_TOKENS`). This is what
///    covers a clause the probes below cannot reach, such as
///    `host 192.0.2.1 and (port 5060 or ip[6:2] & 0x1fff != 0)`.
/// 3. libpcap, compiling `filter`, rejects a later IPv4 fragment and a later
///    IPv6 fragment of a UDP datagram. This is what covers a filter whose
///    meaning differs from its words, such as `not port 22`, which passes
///    every later fragment.
///
/// A filter that does not compile is reported as not blind: the capture
/// refuses it with libpcap's own message, which is the one to read.
#[must_use]
pub fn misses_later_fragments(filter: &str) -> bool {
    let squeezed: String = filter
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if !PORT_TOKENS.iter().any(|t| squeezed.contains(t)) {
        return false;
    }
    if FRAGMENT_TOKENS.iter().any(|t| squeezed.contains(t)) {
        return false;
    }
    !passes_a_later_fragment(filter)
}

/// Whether libpcap, compiling `filter` for Ethernet, accepts a later IPv4
/// fragment or a later IPv6 fragment of a UDP datagram; `true` as well when
/// it does not compile, so that libpcap's own refusal is the only message.
///
/// Runs once, at startup, on a dead handle: no device and no privilege.
fn passes_a_later_fragment(filter: &str) -> bool {
    let Ok(cap) = pcap::Capture::dead(pcap::Linktype::ETHERNET) else {
        return true;
    };
    let Ok(program) = cap.compile(filter, true) else {
        return true;
    };
    [later_ipv4_fragment_probe(), later_ipv6_fragment_probe()]
        .iter()
        .any(|frame| program.filter(frame))
}

/// An Ethernet frame holding the last IPv4 fragment (offset 1480 bytes) of
/// a UDP datagram between two RFC 5737 addresses: no ports in it.
fn later_ipv4_fragment_probe() -> Vec<u8> {
    let mut f: Vec<u8> = vec![
        0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02,
    ];
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(&[0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x00, 185, 64, 17, 0, 0]);
    f.extend_from_slice(&[203, 0, 113, 10, 203, 0, 113, 20]);
    f.resize(14 + 60, b'X');
    f
}

/// An Ethernet frame holding the last IPv6 fragment (offset 1448 bytes) of
/// a UDP datagram between two RFC 3849 addresses: no ports in it.
fn later_ipv6_fragment_probe() -> Vec<u8> {
    let mut f: Vec<u8> = vec![
        0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02,
    ];
    f.extend_from_slice(&[0x86, 0xdd]);
    f.extend_from_slice(&[0x60, 0, 0, 0, 0x00, 0x30, IPV6_FRAGMENT_HEADER, 64]);
    f.extend_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]);
    f.extend_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
    ]);
    // Fragment header: next header UDP, offset 181 units, M clear.
    f.extend_from_slice(&[17, 0, 0x05, 0xa8, 0, 0, 0x12, 0x34]);
    f.resize(14 + 40 + 48, b'X');
    f
}

#[cfg(test)]
pub(crate) mod test_frames {
    //! Frames for driving a compiled filter with `pcap`'s offline filter:
    //! IPv4 and IPv6 fragments, link-layer headers and encapsulations.
    //!
    //! Shared with the generated-filter tests in `crate::app::bootstrap`, so
    //! the fragment shapes are written once.
    //!
    //! Addresses are RFC 5737 and RFC 3849 documentation addresses.

    /// IPv4 Don't Fragment bit, in the flags/offset word.
    pub const DF: u16 = 0x4000;
    /// IPv4 More Fragments bit, in the flags/offset word.
    pub const MF: u16 = 0x2000;

    /// An IPv4 header of `20 + options.len()` bytes followed by `body`, with
    /// the flags/offset word `flags_offset` and protocol `proto`.
    ///
    /// `options` must be a multiple of four bytes long.
    pub fn ipv4(proto: u8, flags_offset: u16, options: &[u8], body: &[u8]) -> Vec<u8> {
        let hlen = 20 + options.len();
        let total = hlen + body.len();
        let mut v: Vec<u8> = vec![0x40 | (hlen / 4) as u8, 0x00];
        v.extend_from_slice(&(total as u16).to_be_bytes());
        v.extend_from_slice(&0x1234u16.to_be_bytes());
        v.extend_from_slice(&flags_offset.to_be_bytes());
        v.extend_from_slice(&[64, proto, 0x00, 0x00]);
        v.extend_from_slice(&[203, 0, 113, 10]);
        v.extend_from_slice(&[203, 0, 113, 20]);
        v.extend_from_slice(options);
        v.extend_from_slice(body);
        v
    }

    /// A UDP header for `payload` between `sport` and `dport`, then the
    /// payload.
    pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + payload.len());
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00]);
        v.extend_from_slice(payload);
        v
    }

    /// Split the IP payload `datagram` (transport header included) into
    /// IPv4 fragments of at most `mtu` bytes each, protocol `proto`.
    ///
    /// Every fragment but the last carries a multiple of eight bytes, as
    /// RFC 791 requires.
    pub fn ipv4_fragments(proto: u8, datagram: &[u8], mtu: usize) -> Vec<Vec<u8>> {
        let per = (mtu - 20) / 8 * 8;
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < datagram.len() {
            let end = (at + per).min(datagram.len());
            let more = if end < datagram.len() { MF } else { 0 };
            out.push(ipv4(proto, more | (at / 8) as u16, &[], &datagram[at..end]));
            at = end;
        }
        out
    }

    /// An IPv6 header (next header `next`) followed by `body`.
    pub fn ipv6(next: u8, body: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = vec![0x60, 0x00, 0x00, 0x00];
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(&[next, 64]);
        v.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ]);
        v.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
        ]);
        v.extend_from_slice(body);
        v
    }

    /// An 8-byte IPv6 Fragment header: next header `next`, offset `offset`
    /// in 8-octet units, More Fragments `more`, identification 0x1234.
    pub fn ipv6_fragment_header(next: u8, offset: u16, more: bool) -> Vec<u8> {
        let mut v: Vec<u8> = vec![next, 0];
        v.extend_from_slice(&((offset << 3) | u16::from(more)).to_be_bytes());
        v.extend_from_slice(&0x1234u32.to_be_bytes());
        v
    }

    /// An IPv6 fragment: base header, Fragment header, then `chunk`.
    pub fn ipv6_fragment(next: u8, offset: u16, more: bool, chunk: &[u8]) -> Vec<u8> {
        let mut body = ipv6_fragment_header(next, offset, more);
        body.extend_from_slice(chunk);
        ipv6(44, &body)
    }

    /// An IPv6 fragment behind one extension header of kind `ext` (0, 43 or
    /// 60) that is `8 * (len_units + 1)` bytes long.
    pub fn ipv6_fragment_behind(
        ext: u8,
        len_units: u8,
        next: u8,
        offset: u16,
        more: bool,
        chunk: &[u8],
    ) -> Vec<u8> {
        let mut body: Vec<u8> = vec![44, len_units];
        body.resize(8 * (usize::from(len_units) + 1), 0);
        body.extend_from_slice(&ipv6_fragment_header(next, offset, more));
        body.extend_from_slice(chunk);
        ipv6(ext, &body)
    }

    /// A 14-byte Ethernet header (RFC 7042 documentation MACs).
    pub fn eth(ethertype: u16) -> Vec<u8> {
        let mut v: Vec<u8> = vec![
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02,
        ];
        v.extend_from_slice(&ethertype.to_be_bytes());
        v
    }

    /// A 16-byte `DLT_LINUX_SLL` header, protocol last.
    pub fn sll(ethertype: u16) -> Vec<u8> {
        let mut v: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x06];
        v.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00]);
        v.extend_from_slice(&ethertype.to_be_bytes());
        v
    }

    /// A 20-byte `DLT_LINUX_SLL2` header, protocol first.
    pub fn sll2(ethertype: u16) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(20);
        v.extend_from_slice(&ethertype.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x06]);
        v.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00]);
        v
    }

    /// `ip` behind an Ethernet header naming IPv4 or IPv6 by its version.
    pub fn on_eth(ip: &[u8]) -> Vec<u8> {
        let mut f = eth(ethertype_of(ip));
        f.extend_from_slice(ip);
        f
    }

    /// The OPTIONS request from issue #926's reproduction script, byte for
    /// byte: a 3,200-byte `X-Pad` header makes it three fragments at an MTU
    /// of 1500.
    pub fn issue_926_options() -> Vec<u8> {
        let dst = "192.0.2.10";
        let b = "0a1b2c3d";
        format!(
            "OPTIONS sip:t@{dst}:5060 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK{b}\r\n\
             Max-Forwards: 70\r\nFrom: <sip:t@192.0.2.20>;tag={b}\r\nTo: <sip:t@{dst}>\r\n\
             Call-ID: frag-{b}\r\nCSeq: 1 OPTIONS\r\n\
             X-Pad: {}\r\nContent-Length: 0\r\n\r\n",
            "X".repeat(3200)
        )
        .into_bytes()
    }

    /// The EtherType for the IP packet `ip`, by its version nibble.
    pub fn ethertype_of(ip: &[u8]) -> u16 {
        if ip.first().is_some_and(|b| b >> 4 == 6) {
            0x86dd
        } else {
            0x0800
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_frames::{
        DF, MF, eth, ethertype_of, ipv4, ipv4_fragments, ipv6, ipv6_fragment, ipv6_fragment_behind,
        ipv6_fragment_header, on_eth, sll, sll2, udp,
    };
    use super::*;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// A SIP payload large enough to need fragments.
    fn sip_payload(len: usize) -> Vec<u8> {
        let mut m = b"OPTIONS sip:t@203.0.113.20:5060 SIP/2.0\r\n".to_vec();
        m.resize(len, b'X');
        m
    }

    /// Compile `filter` for `linktype` and say whether it accepts `frame`.
    fn accepts(linktype: pcap::Linktype, filter: &str, frame: &[u8]) -> Result<bool, TestError> {
        let cap = pcap::Capture::dead(linktype).map_err(|e| format!("dead handle: {e}"))?;
        let prog = cap
            .compile(filter, true)
            .map_err(|e| format!("{filter:?} must compile: {e}"))?;
        Ok(prog.filter(frame))
    }

    /// [`accepts`] on Ethernet.
    fn eth_accepts(filter: &str, frame: &[u8]) -> Result<bool, TestError> {
        accepts(pcap::Linktype::ETHERNET, filter, frame)
    }

    /// The three IPv4 fragments of a 3,500-byte UDP SIP datagram at MTU 1500.
    fn three_v4_fragments() -> Vec<Vec<u8>> {
        ipv4_fragments(17, &udp(5060, 5060, &sip_payload(3500)), 1500)
    }

    // ── fragment_arm: success ──────────────────────────────────────────

    #[test]
    fn the_arm_passes_every_fragment_of_a_fragmented_udp_datagram() -> Result<(), TestError> {
        let frags = three_v4_fragments();
        assert_eq!(frags.len(), 3, "the datagram must split into three");
        for (i, f) in frags.iter().enumerate() {
            assert!(
                eth_accepts(&fragment_arm(), &on_eth(f))?,
                "fragment {i} of 3 must pass the fragment arm"
            );
        }
        Ok(())
    }

    #[test]
    fn the_arm_passes_a_first_fragment_with_mf_and_offset_zero() -> Result<(), TestError> {
        let first = ipv4(17, MF, &[], &udp(40000, 40002, &[0u8; 64]));
        assert!(
            eth_accepts(&fragment_arm(), &on_eth(&first))?,
            "MF with offset 0 is a first fragment, ports or not"
        );
        Ok(())
    }

    #[test]
    fn the_arm_passes_a_fragment_whose_header_has_options() -> Result<(), TestError> {
        let middle = ipv4(17, MF | 185, &[1, 1, 1, 0], &[0u8; 64]);
        assert!(
            eth_accepts(&fragment_arm(), &on_eth(&middle))?,
            "IPv4 options move the payload, not the flags word"
        );
        Ok(())
    }

    #[test]
    fn the_arm_passes_later_fragments_of_tcp_and_esp() -> Result<(), TestError> {
        for proto in [6u8, 50] {
            let last = ipv4(proto, 185, &[], &[0u8; 64]);
            assert!(
                eth_accepts(&fragment_arm(), &on_eth(&last))?,
                "protocol {proto} is reassembled, so its fragments pass"
            );
        }
        Ok(())
    }

    #[test]
    fn the_arm_passes_ipv6_first_and_later_fragments() -> Result<(), TestError> {
        let first = ipv6_fragment(17, 0, true, &udp(5060, 5060, &[0u8; 64]));
        let later = ipv6_fragment(17, 181, false, &[0u8; 64]);
        for (what, f) in [("first", first), ("later", later)] {
            assert!(
                eth_accepts(&fragment_arm(), &on_eth(&f))?,
                "the IPv6 {what} fragment must pass"
            );
        }
        Ok(())
    }

    #[test]
    fn the_arm_passes_an_ipv6_fragment_behind_one_extension_header() -> Result<(), TestError> {
        for ext in IPV6_HEADERS_BEFORE_FRAGMENT {
            for len_units in [0u8, 2] {
                let f = ipv6_fragment_behind(ext, len_units, 17, 181, false, &[0u8; 64]);
                assert!(
                    eth_accepts(&fragment_arm(), &on_eth(&f))?,
                    "a fragment behind extension header {ext} of {len_units} units must pass"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn the_arm_follows_the_ip_header_on_every_link_type() -> Result<(), TestError> {
        let later = ipv4(17, 185, &[], &[0u8; 64]);
        let later6 = ipv6_fragment(17, 181, false, &[0u8; 64]);
        for (name, lt, link) in [
            (
                "Linux cooked v1",
                pcap::Linktype::LINUX_SLL,
                sll as fn(u16) -> Vec<u8>,
            ),
            (
                "Linux cooked v2",
                pcap::Linktype::LINUX_SLL2,
                sll2 as fn(u16) -> Vec<u8>,
            ),
        ] {
            for ip in [&later, &later6] {
                let mut f = link(ethertype_of(ip));
                f.extend_from_slice(ip);
                assert!(
                    accepts(lt, &fragment_arm(), &f)?,
                    "a later fragment behind {name} must pass"
                );
            }
        }
        assert!(
            accepts(pcap::Linktype(12), &fragment_arm(), &later)?,
            "a later fragment on raw IP must pass"
        );
        Ok(())
    }

    #[test]
    fn the_arm_passes_the_last_fragment_at_the_highest_offset() -> Result<(), TestError> {
        let last = ipv4(17, 0x1fff, &[], &[0u8; 8]);
        assert!(
            eth_accepts(&fragment_arm(), &on_eth(&last))?,
            "offset 0x1fff with MF clear is still a fragment"
        );
        Ok(())
    }

    // ── fragment_arm: failure ──────────────────────────────────────────

    #[test]
    fn the_arm_rejects_an_unfragmented_datagram() -> Result<(), TestError> {
        for (what, word) in [("DF set", DF), ("no flags", 0u16)] {
            let whole = ipv4(17, word, &[], &udp(5060, 5060, b"OPTIONS"));
            assert!(
                !eth_accepts(&fragment_arm(), &on_eth(&whole))?,
                "an unfragmented datagram ({what}) is the port arms' business"
            );
        }
        Ok(())
    }

    #[test]
    fn the_arm_rejects_fragments_of_protocols_reassembly_does_not_read() -> Result<(), TestError> {
        for proto in [1u8, 47, 51] {
            let later = ipv4(proto, 185, &[], &[0u8; 64]);
            assert!(
                !eth_accepts(&fragment_arm(), &on_eth(&later))?,
                "protocol {proto}: reassembly reads nothing from it"
            );
        }
        Ok(())
    }

    #[test]
    fn the_arm_rejects_ipv6_fragments_of_other_protocols() -> Result<(), TestError> {
        for next in [58u8, 47] {
            let later = ipv6_fragment(next, 181, false, &[0u8; 64]);
            assert!(
                !eth_accepts(&fragment_arm(), &on_eth(&later))?,
                "IPv6 fragment carrying {next} must not pass"
            );
        }
        Ok(())
    }

    #[test]
    fn the_arm_rejects_unfragmented_ipv6() -> Result<(), TestError> {
        let whole = ipv6(17, &udp(5060, 5060, b"OPTIONS"));
        assert!(
            !eth_accepts(&fragment_arm(), &on_eth(&whole))?,
            "unfragmented IPv6 UDP is the port arms' business"
        );
        let mut dest_opts: Vec<u8> = vec![17, 0, 0, 0, 0, 0, 0, 0];
        dest_opts.extend_from_slice(&udp(5060, 5060, b"OPTIONS"));
        assert!(
            !eth_accepts(&fragment_arm(), &on_eth(&ipv6(60, &dest_opts)))?,
            "a Destination Options header with no Fragment header behind it"
        );
        Ok(())
    }

    #[test]
    fn the_arm_rejects_non_ip_frames() -> Result<(), TestError> {
        let mut arp = eth(0x0806);
        arp.extend_from_slice(&[0u8; 28]);
        assert!(
            !eth_accepts(&fragment_arm(), &arp)?,
            "ARP is not IP and must not pass"
        );
        Ok(())
    }

    #[test]
    fn the_arm_rejects_a_tagged_fragment_which_the_encapsulated_arms_own() -> Result<(), TestError>
    {
        let mut f = eth(0x8100);
        f.extend_from_slice(&[0x00, 0x64, 0x08, 0x00]);
        f.extend_from_slice(&ipv4(17, 185, &[], &[0u8; 64]));
        assert!(
            !eth_accepts(&fragment_arm(), &f)?,
            "ip[] reads only untagged IPv4; VLAN is ipv4_fragment_at's"
        );
        Ok(())
    }

    // ── fragment_arm: edge ─────────────────────────────────────────────

    #[test]
    fn the_flag_bits_alone_do_not_make_a_fragment() -> Result<(), TestError> {
        for (what, word) in [("reserved bit", 0x8000u16), ("DF", DF), ("both", 0xc000)] {
            let whole = ipv4(17, word, &[], &udp(1, 2, &[0u8; 8]));
            assert!(
                !eth_accepts(&fragment_arm(), &on_eth(&whole))?,
                "{what} without MF or an offset is not a fragment"
            );
        }
        Ok(())
    }

    #[test]
    fn a_frame_cut_before_the_protocol_byte_is_rejected() -> Result<(), TestError> {
        let later = ipv4(17, 185, &[], &[0u8; 64]);
        let cut = &on_eth(&later)[..14 + 8];
        assert!(
            !eth_accepts(&fragment_arm(), cut)?,
            "a load past the end of the frame rejects it"
        );
        Ok(())
    }

    #[test]
    fn an_ipv6_fragment_behind_two_extension_headers_is_the_stated_limit() -> Result<(), TestError>
    {
        let mut body: Vec<u8> = vec![60, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&[44, 0, 0, 0, 0, 0, 0, 0]);
        body.extend_from_slice(&ipv6_fragment_header(17, 181, false));
        body.extend_from_slice(&[0u8; 64]);
        let f = on_eth(&ipv6(0, &body));
        assert!(
            !eth_accepts(&fragment_arm(), &f)?,
            "classic BPF has no loop: two extension headers before the \
             Fragment header are documented as not matched"
        );
        Ok(())
    }

    #[test]
    fn the_arm_compiles_on_every_link_type_sipnab_opens() -> Result<(), TestError> {
        for lt in [
            pcap::Linktype::ETHERNET,
            pcap::Linktype::LINUX_SLL,
            pcap::Linktype::LINUX_SLL2,
            pcap::Linktype(12),
            pcap::Linktype::NULL,
            pcap::Linktype::LOOP,
        ] {
            let cap = pcap::Capture::dead(lt).map_err(|e| format!("dead {lt:?}: {e}"))?;
            cap.compile(&fragment_arm(), true)
                .map_err(|e| format!("the arm must compile on {lt:?}: {e}"))?;
        }
        Ok(())
    }

    #[test]
    fn the_protocol_list_is_what_reassembly_reads() -> Result<(), TestError> {
        let tcp_header = {
            let mut h = vec![0u8; 20];
            h[12] = 0x50;
            h
        };
        assert!(
            crate::capture::parse::reparse_transport(17, &udp(1, 2, b"x")).is_some(),
            "reassembly re-reads UDP"
        );
        assert!(
            crate::capture::parse::reparse_transport(6, &tcp_header).is_some(),
            "reassembly re-reads TCP"
        );
        assert!(
            crate::capture::parse::reparse_transport(132, &[0u8; 40]).is_some(),
            "reassembly re-reads SCTP"
        );
        assert!(
            crate::capture::parse::reparse_transport(1, &[0u8; 40]).is_none(),
            "nor ICMP, which is why it is left out"
        );
        assert_eq!(
            REASSEMBLED_PROTOCOLS,
            [17, 6, 50, 132],
            "UDP, TCP, ESP, which reassembly unwraps first, and SCTP"
        );
        Ok(())
    }

    // ── SCTP (132), SCTP-REASSEMBLED-NOT-READ ──────────────────────────

    /// The three IPv4 fragments of a 3,500-byte SCTP packet at MTU 1500.
    fn three_sctp_v4_fragments() -> Vec<Vec<u8>> {
        let mut sctp = vec![0x13, 0xc4, 0x13, 0xc4, 0, 0, 0, 1, 0, 0, 0, 0];
        sctp.extend_from_slice(&sip_payload(3500));
        ipv4_fragments(132, &sctp, 1500)
    }

    /// Every IPv4 fragment of an SCTP packet passes the arm.
    #[test]
    fn the_arm_passes_every_fragment_of_an_sctp_packet() -> Result<(), TestError> {
        let frags = three_sctp_v4_fragments();
        assert_eq!(frags.len(), 3, "three fragments");
        for (i, f) in frags.iter().enumerate() {
            assert!(
                eth_accepts(&fragment_arm(), &on_eth(f))?,
                "SCTP fragment {i} must pass"
            );
        }
        Ok(())
    }

    /// A later IPv4 SCTP fragment, which names no port, passes.
    #[test]
    fn the_arm_passes_a_later_sctp_fragment() -> Result<(), TestError> {
        let later = ipv4(132, 185, &[], &[0u8; 64]);
        assert!(
            eth_accepts(&fragment_arm(), &on_eth(&later))?,
            "later SCTP fragment"
        );
        Ok(())
    }

    /// A first IPv4 SCTP fragment with header options passes.
    #[test]
    fn the_arm_passes_an_sctp_fragment_with_ip_options() -> Result<(), TestError> {
        let first = ipv4(132, MF, &[1, 1, 1, 0], &[0u8; 64]);
        assert!(
            eth_accepts(&fragment_arm(), &on_eth(&first))?,
            "options + MF"
        );
        Ok(())
    }

    /// IPv6 first and later SCTP fragments pass.
    #[test]
    fn the_arm_passes_ipv6_sctp_fragments() -> Result<(), TestError> {
        for (offset, more) in [(0u16, true), (181, false)] {
            let f = ipv6_fragment(132, offset, more, &[0u8; 64]);
            assert!(
                eth_accepts(&fragment_arm(), &on_eth(&f))?,
                "IPv6 SCTP fragment at {offset} must pass"
            );
        }
        Ok(())
    }

    /// An IPv6 SCTP fragment behind each extension header the arm steps over.
    #[test]
    fn the_arm_passes_an_ipv6_sctp_fragment_behind_one_extension_header() -> Result<(), TestError> {
        for ext in IPV6_HEADERS_BEFORE_FRAGMENT {
            let f = ipv6_fragment_behind(ext, 1, 132, 181, false, &[0u8; 64]);
            assert!(
                eth_accepts(&fragment_arm(), &on_eth(&f))?,
                "SCTP fragment behind extension header {ext}"
            );
        }
        Ok(())
    }

    /// The arm passes SCTP fragments on every link type sipnab opens.
    #[test]
    fn the_arm_passes_sctp_fragments_on_cooked_links() -> Result<(), TestError> {
        let later = ipv4(132, 185, &[], &[0u8; 64]);
        let mut v1 = sll(0x0800);
        v1.extend_from_slice(&later);
        let mut v2 = sll2(0x0800);
        v2.extend_from_slice(&later);
        assert!(
            accepts(pcap::Linktype::LINUX_SLL, &fragment_arm(), &v1)?,
            "Linux cooked v1"
        );
        assert!(
            accepts(pcap::Linktype::LINUX_SLL2, &fragment_arm(), &v2)?,
            "Linux cooked v2"
        );
        assert!(
            accepts(pcap::Linktype(12), &fragment_arm(), &later)?,
            "raw IP"
        );
        Ok(())
    }

    /// A whole SCTP packet is not a fragment: the port test owns it.
    #[test]
    fn the_arm_rejects_a_whole_sctp_packet() -> Result<(), TestError> {
        let whole = ipv4(132, DF, &[], &[0u8; 64]);
        assert!(
            !eth_accepts(&fragment_arm(), &on_eth(&whole))?,
            "DF, offset 0"
        );
        let whole6 = ipv6(132, &[0u8; 64]);
        assert!(
            !eth_accepts(&fragment_arm(), &on_eth(&whole6))?,
            "IPv6, no Fragment header"
        );
        Ok(())
    }

    /// An SCTP fragment cut before its protocol byte is rejected.
    #[test]
    fn a_cut_sctp_fragment_is_rejected() -> Result<(), TestError> {
        let later = on_eth(&ipv4(132, 185, &[], &[0u8; 64]));
        assert!(
            !eth_accepts(&fragment_arm(), &later[..14 + 9])?,
            "cut before byte 9"
        );
        Ok(())
    }

    /// The offset arms (VLAN, QinQ, PPPoE, MPLS) pass SCTP fragments.
    #[test]
    fn the_offset_arms_pass_tagged_sctp_fragments() -> Result<(), TestError> {
        for (what, ip) in [
            ("IPv4", ipv4(132, 185, &[], &[0u8; 64])),
            ("IPv6", ipv6_fragment(132, 181, false, &[0u8; 64])),
        ] {
            let filter = format!(
                "{} or (ether[18] & 0xf0 = 0x60 and {})",
                ipv4_fragment_at(18),
                ipv6_fragment_at(18)
            );
            let mut f = eth(0x8100);
            f.extend_from_slice(&[0x00, 0x64]);
            f.extend_from_slice(&ethertype_of(&ip).to_be_bytes());
            f.extend_from_slice(&ip);
            assert!(
                eth_accepts(&filter, &f)?,
                "a VLAN-tagged {what} SCTP fragment"
            );
        }
        Ok(())
    }

    /// The offset arm finds an SCTP fragment at the QinQ offset (22).
    #[test]
    fn the_offset_arm_passes_an_sctp_fragment_inside_qinq() -> Result<(), TestError> {
        let ip = ipv4(132, 185, &[], &[0u8; 64]);
        let mut f = eth(0x88a8);
        f.extend_from_slice(&[0x00, 0x64, 0x81, 0x00, 0x00, 0xc8, 0x08, 0x00]);
        f.extend_from_slice(&ip);
        assert!(
            eth_accepts(&ipv4_fragment_at(22), &f)?,
            "QinQ SCTP fragment"
        );
        Ok(())
    }

    /// The offset arms name 132 in both their IPv4 and IPv6 forms.
    #[test]
    fn the_offset_arms_name_sctp() {
        assert!(
            ipv4_fragment_at(18).contains("ether[27] = 132"),
            "IPv4 at 18"
        );
        assert!(
            ipv6_fragment_at(18).contains("ether[58] = 132"),
            "IPv6 at 18"
        );
    }

    /// The operator clause, appended to an SCTP port filter, passes every
    /// SCTP fragment.
    #[test]
    fn the_clause_makes_an_sctp_port_filter_pass_every_fragment() -> Result<(), TestError> {
        let filter = with_fragment_clause("sctp port 5060");
        for (i, f) in three_sctp_v4_fragments().iter().enumerate() {
            assert!(eth_accepts(&filter, &on_eth(f))?, "fragment {i}");
        }
        Ok(())
    }

    /// Without the clause, an SCTP port filter passes the first fragment only.
    #[test]
    fn an_sctp_port_filter_alone_passes_the_first_fragment_only() -> Result<(), TestError> {
        let frags = three_sctp_v4_fragments();
        let passed: Vec<bool> = frags
            .iter()
            .map(|f| eth_accepts("sctp port 5060", &on_eth(f)))
            .collect::<Result<_, _>>()?;
        assert_eq!(
            passed,
            vec![true, false, false],
            "only the first names the port"
        );
        Ok(())
    }

    // ── absolute-offset arms ───────────────────────────────────────────

    #[test]
    fn the_offset_arms_pass_tagged_fragments() -> Result<(), TestError> {
        let filter = format!(
            "{} or (ether[18] & 0xf0 = 0x60 and {})",
            ipv4_fragment_at(18),
            ipv6_fragment_at(18)
        );
        for (what, ip, tpid) in [
            ("IPv4", ipv4(17, 185, &[], &[0u8; 64]), 0x0800u16),
            (
                "IPv4 with options",
                ipv4(17, MF | 2, &[1, 1, 1, 0], &[0u8; 64]),
                0x0800,
            ),
            ("IPv6", ipv6_fragment(17, 181, false, &[0u8; 64]), 0x86dd),
        ] {
            let mut f = eth(0x8100);
            f.extend_from_slice(&[0x00, 0x64]);
            f.extend_from_slice(&tpid.to_be_bytes());
            f.extend_from_slice(&ip);
            assert!(
                eth_accepts(&filter, &f)?,
                "a VLAN-tagged {what} fragment must pass"
            );
        }
        Ok(())
    }

    #[test]
    fn the_offset_arms_reject_whole_datagrams_and_other_protocols() -> Result<(), TestError> {
        let filter = format!(
            "{} or (ether[18] & 0xf0 = 0x60 and {})",
            ipv4_fragment_at(18),
            ipv6_fragment_at(18)
        );
        for (what, ip) in [
            ("whole IPv4", ipv4(17, DF, &[], &udp(5060, 5060, b"x"))),
            ("ICMP fragment", ipv4(1, 185, &[], &[0u8; 64])),
            ("whole IPv6", ipv6(17, &udp(5060, 5060, b"x"))),
            ("ICMPv6 fragment", ipv6_fragment(58, 181, false, &[0u8; 64])),
        ] {
            let mut f = eth(0x8100);
            f.extend_from_slice(&[0x00, 0x64]);
            f.extend_from_slice(&ethertype_of(&ip).to_be_bytes());
            f.extend_from_slice(&ip);
            assert!(!eth_accepts(&filter, &f)?, "{what} must not pass");
        }
        Ok(())
    }

    #[test]
    fn the_ipv4_offset_arm_checks_the_version() -> Result<(), TestError> {
        let mut f = eth(0x8100);
        f.extend_from_slice(&[0x00, 0x64, 0x86, 0xdd]);
        let mut six = ipv6(17, &udp(5060, 5060, &[0u8; 64]));
        // Bytes 6-9 of the IPv6 header would read as a fragment word and a
        // UDP protocol byte to a test that skipped the version.
        six[6] = 0x20;
        six[7] = 0x01;
        six[9] = 17;
        f.extend_from_slice(&six);
        assert!(
            !eth_accepts(&ipv4_fragment_at(18), &f)?,
            "an IPv6 header is not an IPv4 fragment"
        );
        Ok(())
    }

    // ── the operator clause ────────────────────────────────────────────

    #[test]
    fn the_clause_makes_a_port_filter_pass_every_fragment() -> Result<(), TestError> {
        let fixed = with_fragment_clause("port 5060 or port 5061");
        let mut frames: Vec<Vec<u8>> = three_v4_fragments().iter().map(|f| on_eth(f)).collect();
        frames.push(on_eth(&ipv6_fragment(
            17,
            0,
            true,
            &udp(5060, 5060, &[0u8; 64]),
        )));
        frames.push(on_eth(&ipv6_fragment(17, 181, false, &[0u8; 64])));
        for (i, f) in frames.iter().enumerate() {
            assert!(eth_accepts(&fixed, f)?, "frame {i} must pass {fixed}");
        }
        Ok(())
    }

    #[test]
    fn the_clause_keeps_what_the_operator_narrowed() -> Result<(), TestError> {
        let fixed = with_fragment_clause("port 5060 and host 198.51.100.1");
        let whole = on_eth(&ipv4(17, DF, &[], &udp(5060, 5060, b"OPTIONS")));
        assert!(
            !eth_accepts(&fixed, &whole)?,
            "an unfragmented datagram from another host stays out: {fixed}"
        );
        assert!(
            fixed.starts_with("(port 5060 and host 198.51.100.1) or "),
            "the operator's text is parenthesized: {fixed}"
        );
        Ok(())
    }

    #[test]
    fn the_clause_is_the_one_the_issue_verified_plus_ipv6() -> Result<(), TestError> {
        assert!(
            OPERATOR_FRAGMENT_CLAUSE.contains("ip[6:2] & 0x1fff != 0"),
            "the IPv4 half is the clause the reporter measured: {OPERATOR_FRAGMENT_CLAUSE}"
        );
        assert!(
            OPERATOR_FRAGMENT_CLAUSE.contains("ip6[6] = 44"),
            "the IPv6 half matches the Fragment header: {OPERATOR_FRAGMENT_CLAUSE}"
        );
        Ok(())
    }

    #[test]
    fn the_detector_is_satisfied_by_its_own_fix() -> Result<(), TestError> {
        for f in [
            "port 5060",
            "port 5060 or port 5061",
            "portrange 5060-5061",
            "udp dst port 9060",
            "tcp port 5061 and host 192.0.2.1",
        ] {
            assert!(misses_later_fragments(f), "{f} is blind before the fix");
            let fixed = with_fragment_clause(f);
            assert!(
                !misses_later_fragments(&fixed),
                "the fixed filter is not: {fixed}"
            );
        }
        Ok(())
    }

    // ── misses_later_fragments: success (blind filters found) ──────────

    #[test]
    fn the_reporters_filter_is_blind() -> Result<(), TestError> {
        assert!(
            misses_later_fragments("port 5060 or port 5061"),
            "the filter from issue #926 rejects every later fragment"
        );
        Ok(())
    }

    #[test]
    fn port_forms_are_all_found_blind() -> Result<(), TestError> {
        for f in [
            "portrange 5060-5061",
            "udp port 5060",
            "src port 5060",
            "udp dst port 9060",
            "tcp port 5061",
            "host 192.0.2.1 and port 5060",
            "udp[2:2] = 5060",
            "tcp dst portrange 5060-5061",
        ] {
            assert!(misses_later_fragments(f), "{f} rejects later fragments");
        }
        Ok(())
    }

    // ── misses_later_fragments: failure (no warning) ───────────────────

    #[test]
    fn filters_without_a_port_test_are_not_blind() -> Result<(), TestError> {
        for f in ["udp", "host 192.0.2.1", "ip", "net 192.0.2.0/24", ""] {
            assert!(
                !misses_later_fragments(f),
                "{f:?} passes fragments of what it selects"
            );
        }
        Ok(())
    }

    #[test]
    fn the_reporters_workaround_is_not_blind() -> Result<(), TestError> {
        let f = "(port 5060 or port 5061) or (ip[6:2] & 0x1fff != 0)";
        assert!(!misses_later_fragments(f), "{f} is the measured workaround");
        Ok(())
    }

    #[test]
    fn a_filter_that_passes_fragments_in_meaning_is_not_blind() -> Result<(), TestError> {
        for f in [
            "not port 22",
            "port 5060 or udp",
            "port 5060 or ip proto 17",
        ] {
            assert!(!misses_later_fragments(f), "{f} passes later fragments");
        }
        Ok(())
    }

    #[test]
    fn a_fragment_clause_the_probe_cannot_reach_is_still_seen() -> Result<(), TestError> {
        for f in [
            "host 192.0.2.1 and (port 5060 or ip[6:2] & 0x1fff != 0)",
            "host 192.0.2.1 and (port 5060 or ip6[6] = 44)",
            "port 5060 or (ip[6:2] & 8191 != 0 and host 192.0.2.1)",
            "port 5060 or (ip6 protochain 44 and host 2001:db8::1)",
        ] {
            assert!(!misses_later_fragments(f), "{f} handles fragments");
        }
        Ok(())
    }

    #[test]
    fn a_filter_that_does_not_compile_is_left_to_libpcap() -> Result<(), TestError> {
        for f in ["port", "PORT 5060", "port 5060 or"] {
            assert!(
                !misses_later_fragments(f),
                "{f:?}: the capture refuses it with libpcap's own message"
            );
        }
        Ok(())
    }

    // ── misses_later_fragments: edge ───────────────────────────────────

    #[test]
    fn spacing_and_case_do_not_hide_a_fragment_clause() -> Result<(), TestError> {
        for f in [
            "host 192.0.2.1 and (port 5060 or IP [ 6 : 2 ] & 0X1FFF != 0)",
            "host 192.0.2.1 and (port 5060 or ip6 [6] = 44)",
        ] {
            assert!(!misses_later_fragments(f), "{f} handles fragments");
        }
        Ok(())
    }

    #[test]
    fn a_v4_only_clause_still_satisfies_the_probe() -> Result<(), TestError> {
        // The probe needs either family: an operator who added the IPv4
        // clause has answered the question for their network.
        assert!(
            !misses_later_fragments("port 5060 or (ip[6:2] & 0x1fff != 0)"),
            "the IPv4 clause alone passes the IPv4 probe"
        );
        Ok(())
    }
}
