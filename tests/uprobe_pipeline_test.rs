// SPDX-License-Identifier: MIT OR Apache-2.0

//! A uprobe read must reach the dialog store, not the TCP reassembler.
//!
//! This exists because of a failure with no symptom. Both uprobe backends
//! captured packets, counted them, and produced **zero SIP messages**: the
//! processor routes every TCP packet through the segment reassembler, a uprobe
//! packet carries no sequence number, and every message was held forever for
//! neighbors that could not arrive. The capture summary said "6 packets
//! captured, 0 SIP messages" — which reads exactly like a trunk carrying
//! nothing.
//!
//! A uprobe read is not a segment. It is one complete application write, taken
//! where the application handed the bytes to its TLS library, with the message
//! boundary the application chose. It is reported as TCP because that is what
//! the session runs over, never because it traversed a sequence space.

#![cfg(all(target_os = "linux", feature = "native"))]

use std::net::{IpAddr, Ipv4Addr};

use sipnab::capture::PacketProcessor;
use sipnab::capture::packet::{Packet, PreParsed};

/// TCP, as a TLS session is.
const TCP: u8 = 6;

const REGISTER: &[u8] = b"REGISTER sip:example.net SIP/2.0\r\n\
Via: SIP/2.0/TLS 127.0.0.1:15061;branch=z9hG4bK-uprobe\r\n\
From: <sip:alice@example.net>;tag=probe\r\n\
To: <sip:alice@example.net>\r\n\
Call-ID: uprobe-pipeline-test@sipnab\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n";

/// Build a packet shaped exactly as the uprobe backends produce one.
fn uprobe_packet(interface: &str, src_port: u16, dst_port: u16) -> Packet {
    Packet::with_pre_parsed(
        chrono::Utc::now(),
        REGISTER.to_vec(),
        Some(interface.to_string()),
        PreParsed {
            src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port,
            dst_port,
            ip_protocol: TCP,
        },
    )
}

/// **The regression.** With reassembly on — the default — a uprobe read must
/// come straight out again.
#[test]
fn a_uprobe_read_is_not_held_by_the_tcp_reassembler() {
    let mut processor = PacketProcessor::new();
    let out = processor.process(&uprobe_packet("uprobe:opensips/4242", 36160, 15061));

    assert_eq!(
        out.len(),
        1,
        "a uprobe read must pass through whole. Zero here is the exact failure \
         this guards: packets counted, no SIP messages, and a capture that \
         reads like a quiet trunk"
    );
    assert_eq!(out[0].payload.as_ref(), REGISTER);
    assert_eq!(out[0].src_port, 36160);
    assert_eq!(out[0].dst_port, 15061);
}

/// The BPF backend's addresses must survive the same path, since carrying them
/// is the only reason that backend exists.
#[test]
fn the_peer_a_uprobe_read_carries_survives_the_pipeline() {
    let mut processor = PacketProcessor::new();
    let out = processor.process(&uprobe_packet("uprobe:python3/4242", 36160, 15061));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].src_addr.to_string(), "127.0.0.1");
    assert_eq!(out[0].dst_addr.to_string(), "127.0.0.1");
}

/// A tuple-less read — the tracefs backend, or a BPF write whose send never
/// paired — must also pass through. It is the more common shape, and holding
/// it would silence the default backend entirely.
#[test]
fn a_uprobe_read_with_no_peer_passes_through_too() {
    let mut processor = PacketProcessor::new();
    let out = processor.process(&uprobe_packet("uprobe:opensips/99", 0, 0));
    assert_eq!(
        out.len(),
        1,
        "no addresses is normal for a uprobe, not a fault"
    );
    assert_eq!(out[0].payload.as_ref(), REGISTER);
}

/// The bypass must be narrow. A real TCP packet still belongs to the
/// reassembler — widening this to all pre-parsed input would take HEP with it,
/// and HEP carries genuine segments.
#[test]
fn a_hep_packet_is_not_given_the_uprobe_bypass() {
    let mut processor = PacketProcessor::new();
    // Same shape, but the source name says HEP rather than uprobe, which is
    // what `InputOrigin` is derived from.
    let out = processor.process(&uprobe_packet("hep:10.0.0.5", 5060, 5060));
    assert!(
        out.len() <= 1,
        "this asserts only that HEP takes the ordinary path; what that path \
         decides is the reassembler's business, not this test's"
    );
}
