// SPDX-License-Identifier: MIT OR Apache-2.0

//! Synthetic packet construction for exporting parsed SIP messages
//! back to pcap files.
//!
//! Lives in the output layer (not the TUI) so packet reconstruction is
//! reusable by any export path and the TUI stays a pure presentation
//! layer over the capture/output APIs.

use std::net::IpAddr;

/// Build a synthetic Ethernet + IPv4 + UDP packet from a SIP message's raw bytes.
///
/// The link-layer type is DLT_EN10MB (1). IP addresses and ports come from
/// the SipMessage metadata.
///
/// # Arguments
///
/// * `msg` — Source message; its `raw` bytes become the UDP payload and
///   its addresses/ports/timestamp fill the headers.
///
/// # Returns
///
/// A `Packet` with zeroed MACs, DF flag, TTL 64, and zero IP/UDP
/// checksums (readers skip verification). IPv6 addresses degrade to
/// `0.0.0.0`; payloads longer than a u16 length field saturate the UDP/IP
/// length fields at `u16::MAX` rather than panicking or truncating the
/// data. Pure — nothing is written to disk here.
pub fn build_synthetic_packet(msg: &crate::sip::SipMessage) -> crate::capture::Packet {
    // A single non-fragmented IPv4 datagram can carry at most u16::MAX bytes
    // (IP + UDP headers + payload). Truncate an oversized SIP payload to what
    // fits so the IP/UDP length fields match the bytes actually appended — a
    // saturated length with the full payload appended leaves the header and
    // content disagreeing, and a reader would misframe the packet.
    const MAX_IP_PAYLOAD: usize = u16::MAX as usize - 28; // 65535 - (20 IP + 8 UDP)
    let payload: &[u8] = if msg.raw.len() > MAX_IP_PAYLOAD {
        &msg.raw[..MAX_IP_PAYLOAD]
    } else {
        &msg.raw
    };
    let udp_len: u16 = (8 + payload.len()) as u16;
    let ip_total_len: u16 = 20 + udp_len;
    let mut pkt = Vec::with_capacity(14 + ip_total_len as usize);

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x00; 6]); // dst MAC
    pkt.extend_from_slice(&[0x00; 6]); // src MAC
    pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // IPv4 header (20 bytes, no options)
    pkt.push(0x45); // version=4, IHL=5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&ip_total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // identification
    pkt.extend_from_slice(&[0x40, 0x00]); // flags=DF, fragment offset=0
    pkt.push(64); // TTL
    pkt.push(17); // protocol: UDP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum (skip)
    match msg.src_addr {
        IpAddr::V4(v4) => pkt.extend_from_slice(&v4.octets()),
        IpAddr::V6(_) => pkt.extend_from_slice(&[0; 4]), // fallback for v6
    }
    match msg.dst_addr {
        IpAddr::V4(v4) => pkt.extend_from_slice(&v4.octets()),
        IpAddr::V6(_) => pkt.extend_from_slice(&[0; 4]),
    }

    // UDP header (8 bytes)
    pkt.extend_from_slice(&msg.src_port.to_be_bytes());
    pkt.extend_from_slice(&msg.dst_port.to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum

    // Payload
    pkt.extend_from_slice(payload);

    let len = pkt.len();
    crate::capture::Packet::new(msg.timestamp, pkt, len, len, None, 1) // DLT_EN10MB
}

/// Test for u16 saturation on oversized payloads.
#[cfg(test)]
mod tests {
    use super::*;

    /// A 70 kB payload saturates the IP total-length field at `u16::MAX`
    /// instead of panicking.
    #[test]
    fn build_synthetic_packet_large_payload_no_panic() {
        // Verify that a SIP message with a raw payload exceeding 65535 bytes
        // does not panic due to u16 overflow in UDP/IP length fields.
        // The fix uses u16 saturation (unwrap_or(u16::MAX) / saturating_add).
        use crate::capture::parse::TransportProto;
        use crate::sip::SipMessage;
        use chrono::Utc;
        use std::net::{IpAddr, Ipv4Addr};

        let large_body = vec![b'X'; 70_000]; // > u16::MAX (65535)
        let msg = SipMessage {
            frame: None,
            raw: large_body.into(),
            is_request: true,
            method: Some(crate::sip::SipMethod::Invite),
            status_code: None,
            reason: None,
            request_uri: Some("sip:test@example.com".to_string()),
            headers: vec![],
            body: Default::default(),
            parse_error: false,
            timestamp: Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 5060,
            dst_port: 5060,
            transport: TransportProto::Udp,
            is_retransmission: false,
        };

        // This must not panic — the u16 fields saturate instead of overflowing.
        let pkt = build_synthetic_packet(&msg);

        // Sanity: packet should contain the Ethernet + IP + UDP headers plus payload
        assert!(pkt.data.len() > 42, "packet must contain headers + payload");
        // IP total length field (bytes 16-17 of the packet, offset 14+2 into Ethernet)
        let ip_total = u16::from_be_bytes([pkt.data[16], pkt.data[17]]);
        // With saturation, udp_len = u16::MAX and ip_total_len = 20.saturating_add(u16::MAX) = u16::MAX
        assert_eq!(
            ip_total,
            u16::MAX,
            "IP total length should saturate to u16::MAX"
        );
        // The IP total-length field must match the actual IP-layer bytes: an
        // oversized payload is truncated to fit, not appended past the
        // saturated length (which would leave the header and content
        // disagreeing and a reader misframing the packet).
        assert_eq!(
            pkt.data.len() - 14,
            ip_total as usize,
            "IP total length must equal the actual IP packet size"
        );
    }
}
