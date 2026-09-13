// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST7 / C4: sipnab's OWN per-call RTP packet count, the `sipnab_measured`
//! side of `--relay-compare`.
//!
//! `StreamStore::measured_packet_count_for` sums the packets sipnab captured
//! and correlated to one Call-ID. It is bounded by what reached the capture
//! point -- not what the relay saw -- and the comparison's note says so. These
//! gates drive the real correlation path (record packets, link the endpoint to
//! a call) so the sum reflects what a live run would measure, not a hand-set
//! field.

#![cfg(feature = "full")]

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, Utc};

use sipnab::capture::parse::{InputOrigin, ParsedPacket, TransportProto};
use sipnab::rtp::parser::parse_rtp_header;
use sipnab::rtp::stream_store::StreamStore;

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("valid timestamp")
}

fn ip(octets: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(octets))
}

/// One synthetic PCMU packet on the given 4-tuple.
fn rtp_packet(
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    ssrc: u32,
    seq: u16,
) -> ParsedPacket {
    let mut payload = Vec::with_capacity(172);
    payload.push(0x80);
    payload.push(0x00); // PT 0, PCMU
    payload.extend_from_slice(&seq.to_be_bytes());
    payload.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    payload.extend_from_slice(&ssrc.to_be_bytes());
    payload.extend_from_slice(&[0x7F; 160]);

    ParsedPacket {
        frame_bytes: None,
        frame: None,
        timestamp: ts(0),
        src_addr: src,
        dst_addr: dst,
        src_port,
        dst_port,
        transport: TransportProto::Udp,
        payload: payload.into(),
        ip_id: None,
        tcp_seq: None,
        tcp_flags: None,
        fragment_offset: None,
        more_fragments: false,
        ip_protocol: 17,
        dscp: None,
        input_origin: InputOrigin::Wire,
        hep: None,
    }
}

/// Record `n` RTP packets on the given 4-tuple into `store`.
fn record_n(
    store: &mut StreamStore,
    n: u16,
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    ssrc: u32,
) {
    for i in 0..n {
        let parsed = rtp_packet(src, src_port, dst, dst_port, ssrc, 100 + i);
        let hdr = parse_rtp_header(&parsed.payload).expect("synthetic RTP header");
        store.process_rtp(&parsed, &hdr, ts(i64::from(i)));
    }
}

/// A call's measured count sums every stream linked to its Call-ID: two legs of
/// one call add up, and a stream on a different call does not leak in.
#[test]
fn measured_count_sums_the_calls_streams_only() {
    let mut ss = StreamStore::new(64);

    // Call A, leg one: 10 packets from 192.0.2.10:20000.
    record_n(
        &mut ss,
        10,
        ip([192, 0, 2, 10]),
        20000,
        ip([198, 51, 100, 1]),
        40000,
        0x1111,
    );
    // Call A, leg two: 6 packets from 192.0.2.11:20002.
    record_n(
        &mut ss,
        6,
        ip([192, 0, 2, 11]),
        20002,
        ip([198, 51, 100, 1]),
        40002,
        0x2222,
    );
    // Call B: 7 packets from 192.0.2.20:21000.
    record_n(
        &mut ss,
        7,
        ip([192, 0, 2, 20]),
        21000,
        ip([198, 51, 100, 2]),
        41000,
        0x3333,
    );

    ss.link_endpoint(ip([192, 0, 2, 10]), 20000, "call-A", &[]);
    ss.link_endpoint(ip([192, 0, 2, 11]), 20002, "call-A", &[]);
    ss.link_endpoint(ip([192, 0, 2, 20]), 21000, "call-B", &[]);

    assert_eq!(
        ss.measured_packet_count_for("call-A"),
        16,
        "both legs of call A sum: 10 + 6"
    );
    assert_eq!(
        ss.measured_packet_count_for("call-B"),
        7,
        "call B is its own stream only"
    );
}

/// A call sipnab saw no packets for measures zero -- a real answer (sipnab saw
/// none), not a crash and not a missing value.
#[test]
fn a_call_with_no_streams_measures_zero() {
    let ss = StreamStore::new(64);
    assert_eq!(ss.measured_packet_count_for("nobody"), 0);
}

/// An unlinked stream is not counted for any call: a packet sipnab captured but
/// could not correlate to a Call-ID is not attributed to one.
#[test]
fn an_unlinked_stream_is_not_attributed_to_a_call() {
    let mut ss = StreamStore::new(64);
    record_n(
        &mut ss,
        9,
        ip([192, 0, 2, 30]),
        22000,
        ip([198, 51, 100, 3]),
        42000,
        0x4444,
    );
    // Never linked to any Call-ID.
    assert_eq!(
        ss.measured_packet_count_for("call-A"),
        0,
        "an orphan stream belongs to no call"
    );
}
