// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz TCP stream reassembly with a structured segment stream: the
//! input is decoded as a sequence of pseudo-segments (flags, port
//! selector, sequence number, payload), so out-of-order/overlapping/
//! reset/replayed segment interleavings are all reachable. Buffering
//! must stay bounded and flushing must never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::capture::parse::{ParsedPacket, TcpFlags};
use sipnab::capture::reassembly::TcpReassembler;
use sipnab::net::TransportProto;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    let mut reassembler = TcpReassembler::with_limits(16, std::time::Duration::from_secs(60));
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Pseudo-segment wire format: flags(1) port_sel(1) seq(4) len(1) payload(len).
    let mut rest = data;
    while rest.len() >= 7 {
        let flags_b = rest[0];
        let port_sel = rest[1];
        let seq = u32::from_le_bytes([rest[2], rest[3], rest[4], rest[5]]);
        let plen = rest[6] as usize;
        rest = &rest[7..];
        let take = plen.min(rest.len());
        let payload = &rest[..take];
        rest = &rest[take..];

        let pkt = ParsedPacket {
            frame: None,
            timestamp: chrono::Utc::now(),
            src_addr: src,
            dst_addr: dst,
            // A few distinct streams so eviction/interleaving is exercised.
            src_port: 40000 + (port_sel & 0x07) as u16,
            dst_port: 5060,
            transport: TransportProto::Tcp,
            payload: bytes::Bytes::copy_from_slice(payload),
            ip_id: None,
            tcp_seq: Some(seq),
            tcp_flags: Some(TcpFlags {
                syn: flags_b & 0x01 != 0,
                ack: flags_b & 0x02 != 0,
                fin: flags_b & 0x04 != 0,
                rst: flags_b & 0x08 != 0,
                psh: flags_b & 0x10 != 0,
            }),
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 6,
            dscp: None,
            from_hep: false,
        };
        for flushed in reassembler.insert(&pkt) {
            let _ = flushed.len();
        }
    }
    reassembler.sweep();
});
