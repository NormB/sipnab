//! Raw IPv4/UDP datagram construction for source-spoofed scanner-kill
//! responses.
//!
//! The scanner-kill worker sends its SIP response so it appears to originate
//! from the `ip:port` the scanner targeted (the victim), not from sipnab's own
//! ephemeral port. That requires forging the IP and UDP headers and injecting
//! the result through a raw socket (`IP_HDRINCL`); the kernel still handles L2
//! (ARP, routing). These builders produce the fully-formed, checksummed
//! datagram and are pure (no I/O), so the header/checksum logic is unit-tested
//! against golden bytes independently of any privileged socket.

use std::net::SocketAddrV4;

/// IPv4 header length without options, in bytes.
const IPV4_HEADER_LEN: usize = 20;
/// UDP header length, in bytes.
const UDP_HEADER_LEN: usize = 8;
/// IANA protocol number for UDP.
const IPPROTO_UDP: u8 = 17;

/// Largest UDP payload that fits in a single IPv4 datagram
/// (`u16::MAX` total length − IPv4 header − UDP header).
const MAX_UDP_PAYLOAD_V4: usize = u16::MAX as usize - IPV4_HEADER_LEN - UDP_HEADER_LEN;

/// Build a complete IPv4 + UDP datagram with the given (possibly spoofed)
/// source, destination, and payload.
///
/// Returns the wire bytes (20-byte IPv4 header + 8-byte UDP header + payload)
/// with correct IPv4 header checksum and UDP checksum, ready to hand to a
/// raw `IP_HDRINCL` socket. Returns `None` if `payload` is too large to fit in
/// a single IPv4 datagram.
pub fn build_ipv4_udp(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > MAX_UDP_PAYLOAD_V4 {
        return None;
    }

    let total_len = (IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len()) as u16;
    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;

    let mut pkt = Vec::with_capacity(total_len as usize);

    // ── IPv4 header ──
    pkt.push(0x45); // version 4, IHL 5 (no options)
    pkt.push(0x00); // DSCP / ECN
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // identification
    pkt.extend_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, fragment offset 0
    pkt.push(64); // TTL
    pkt.push(IPPROTO_UDP);
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    pkt.extend_from_slice(&src.ip().octets());
    pkt.extend_from_slice(&dst.ip().octets());
    let ip_csum = checksum16(&pkt[..IPV4_HEADER_LEN]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // ── UDP header ──
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    pkt.extend_from_slice(payload);

    // UDP checksum covers a pseudo-header + the UDP header + payload.
    let mut pseudo = Vec::with_capacity(12 + udp_len as usize);
    pseudo.extend_from_slice(&src.ip().octets());
    pseudo.extend_from_slice(&dst.ip().octets());
    pseudo.push(0);
    pseudo.push(IPPROTO_UDP);
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    pseudo.extend_from_slice(&pkt[IPV4_HEADER_LEN..]); // UDP header (csum 0) + payload
    let mut udp_csum = checksum16(&pseudo);
    // A computed checksum of zero is transmitted as all-ones; zero means
    // "no checksum" in UDP and must never be sent for a real checksum.
    if udp_csum == 0 {
        udp_csum = 0xffff;
    }
    let udp_csum_off = IPV4_HEADER_LEN + 6;
    pkt[udp_csum_off..udp_csum_off + 2].copy_from_slice(&udp_csum.to_be_bytes());

    Some(pkt)
}

/// Internet checksum (RFC 1071): one's-complement sum of 16-bit big-endian
/// words, with a trailing odd byte padded with a zero low byte.
fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(a: [u8; 4], p: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(a), p)
    }

    /// Independent reference implementation of the internet checksum, used to
    /// cross-check the builder's own checksums.
    fn ref_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn builds_expected_header_fields() {
        let src = addr([10, 0, 0, 1], 5060);
        let dst = addr([192, 168, 1, 9], 40000);
        let payload = b"SIP/2.0 403 Forbidden\r\n\r\n";
        let pkt = build_ipv4_udp(src, dst, payload).expect("should build");

        assert_eq!(pkt.len(), 20 + 8 + payload.len());
        assert_eq!(pkt[0], 0x45, "version/IHL");
        assert_eq!(pkt[9], 17, "protocol UDP");
        assert_eq!(&pkt[2..4], &((20 + 8 + payload.len()) as u16).to_be_bytes());
        assert_eq!(&pkt[12..16], &[10, 0, 0, 1], "source IP (spoofed)");
        assert_eq!(&pkt[16..20], &[192, 168, 1, 9], "dest IP");
        // UDP ports
        assert_eq!(
            &pkt[20..22],
            &5060u16.to_be_bytes(),
            "udp src port (spoofed)"
        );
        assert_eq!(&pkt[22..24], &40000u16.to_be_bytes(), "udp dst port");
        assert_eq!(
            &pkt[24..26],
            &((8 + payload.len()) as u16).to_be_bytes(),
            "udp len"
        );
    }

    #[test]
    fn ip_header_checksum_is_valid() {
        let pkt = build_ipv4_udp(addr([10, 0, 0, 1], 5060), addr([10, 0, 0, 2], 5060), b"x")
            .expect("build");
        // A correct IPv4 header checksums to zero when re-summed including the
        // checksum field.
        assert_eq!(ref_checksum(&pkt[..20]), 0, "IP header must checksum to 0");
        // And the stored checksum matches an independent computation over the
        // header with the checksum field zeroed.
        let mut hdr = pkt[..20].to_vec();
        hdr[10] = 0;
        hdr[11] = 0;
        assert_eq!(u16::from_be_bytes([pkt[10], pkt[11]]), ref_checksum(&hdr));
    }

    #[test]
    fn udp_checksum_is_valid() {
        let src = addr([10, 0, 0, 1], 5060);
        let dst = addr([10, 0, 0, 2], 5061);
        let payload = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let pkt = build_ipv4_udp(src, dst, payload).expect("build");

        // Rebuild the pseudo-header + UDP segment (with the real checksum in
        // place) and confirm it re-sums to zero — the receiver's validity test.
        let udp_len = (8 + payload.len()) as u16;
        let mut check = Vec::new();
        check.extend_from_slice(&[10, 0, 0, 1]);
        check.extend_from_slice(&[10, 0, 0, 2]);
        check.push(0);
        check.push(17);
        check.extend_from_slice(&udp_len.to_be_bytes());
        check.extend_from_slice(&pkt[20..]);
        assert_eq!(ref_checksum(&check), 0, "UDP checksum must validate to 0");
        assert_ne!(&pkt[26..28], &[0, 0], "checksum must be present, not zero");
    }

    #[test]
    fn empty_payload_still_builds_valid_headers() {
        // The worker guards against empty responses, but the builder must not
        // panic or produce a malformed datagram on an empty payload.
        let pkt = build_ipv4_udp(addr([10, 0, 0, 1], 5060), addr([10, 0, 0, 2], 5060), b"")
            .expect("build");
        assert_eq!(pkt.len(), 28);
        assert_eq!(&pkt[24..26], &8u16.to_be_bytes(), "udp len is header-only");
        assert_eq!(ref_checksum(&pkt[..20]), 0);
    }

    #[test]
    fn adversarial_payload_bytes_are_carried_verbatim() {
        // Embedded NUL, high bytes, backslash, CR/LF must appear untouched
        // after the 28-byte header, and both checksums must still validate.
        let payload = vec![0x00u8, 0xff, b'\\', 0x0d, 0x0a, 0x80, 0x7f, 0x00, b'S'];
        let pkt = build_ipv4_udp(
            addr([172, 16, 0, 1], 5060),
            addr([172, 16, 0, 9], 5062),
            &payload,
        )
        .expect("build");
        assert_eq!(&pkt[28..], &payload[..], "payload carried byte-for-byte");
        assert_eq!(ref_checksum(&pkt[..20]), 0);

        let udp_len = (8 + payload.len()) as u16;
        let mut check = Vec::new();
        check.extend_from_slice(&[172, 16, 0, 1]);
        check.extend_from_slice(&[172, 16, 0, 9]);
        check.push(0);
        check.push(17);
        check.extend_from_slice(&udp_len.to_be_bytes());
        check.extend_from_slice(&pkt[20..]);
        assert_eq!(
            ref_checksum(&check),
            0,
            "UDP checksum valid for binary payload"
        );
    }

    #[test]
    fn oversize_payload_rejected() {
        let too_big = vec![0u8; MAX_UDP_PAYLOAD_V4 + 1];
        assert!(
            build_ipv4_udp(
                addr([10, 0, 0, 1], 5060),
                addr([10, 0, 0, 2], 5060),
                &too_big
            )
            .is_none()
        );
        // Exactly the maximum still builds.
        let max = vec![0u8; MAX_UDP_PAYLOAD_V4];
        assert!(
            build_ipv4_udp(addr([10, 0, 0, 1], 5060), addr([10, 0, 0, 2], 5060), &max).is_some()
        );
    }
}
