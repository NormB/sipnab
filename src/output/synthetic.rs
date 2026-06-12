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
pub fn build_synthetic_packet(msg: &crate::sip::SipMessage) -> crate::capture::Packet {
    let payload = &msg.raw;
    // Saturate instead of silently truncating for large payloads
    let udp_len: u16 = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let ip_total_len: u16 = 20u16.saturating_add(udp_len);
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

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
