// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Captures for the `--cores` parity tests (`tests/cores_parity_test.rs`).
//!
//! Each builder returns the frames of one capture in READ order with their
//! capture times, so a capture whose timestamps are not monotonic can be
//! written as it is. Addresses are RFC 5737 documentation addresses and every
//! SIP name is under `example.com`.
//!
//! The host pairs are chosen so the traffic of one call spreads over several
//! `--cores` workers; each test checks that with `sipnab::parallel::shard_for`
//! rather than assuming it.
#![allow(dead_code)]

/// Seconds since the epoch of every capture's first frame:
/// 2023-11-14T22:13:20Z, a multiple of the five-second sweep interval.
pub const EPOCH: u64 = 1_700_000_000;

/// One second, in the microseconds a frame's offset is written in.
pub const SECOND: u64 = 1_000_000;

/// One frame and its capture time, in microseconds after [`EPOCH`].
pub type Frame = (u64, Vec<u8>);

/// A classic little-endian microsecond Ethernet pcap of `frames`, written in
/// the order given.
#[must_use]
pub fn pcap(frames: &[Frame]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65_535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (at, frame) in frames {
        let secs = EPOCH + at / SECOND;
        out.extend_from_slice(&(secs as u32).to_le_bytes());
        out.extend_from_slice(&((at % SECOND) as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
    }
    out
}

/// One's-complement checksum of an IPv4 header.
fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in data.chunks(2) {
        let hi = u32::from(word[0]) << 8;
        let lo = word.get(1).map_or(0, |b| u32::from(*b));
        sum += hi | lo;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An Ethernet, IPv4 and UDP frame carrying `payload`.
#[must_use]
pub fn udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut ip = Vec::with_capacity(20);
    ip.extend_from_slice(&[0x45, 0x00]);
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, 17, 0x00, 0x00]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let ck = checksum16(&ip);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());
    let mut frame = Vec::with_capacity(14 + total);
    frame.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]);
    frame.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&sport.to_be_bytes());
    frame.extend_from_slice(&dport.to_be_bytes());
    frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(payload);
    frame
}

/// An RTP packet: version 2, no marker, `pt`, `seq`, `ts`, `ssrc`, then
/// `len` bytes of payload.
#[must_use]
pub fn rtp(pt: u8, seq: u16, ts: u32, ssrc: u32, len: usize) -> Vec<u8> {
    let mut p = vec![0x80, pt & 0x7f];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.resize(12 + len, 0xd5);
    p
}

/// A dotted-quad of `ip`.
fn dotted(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// The two ends of one SIP exchange: who sends the requests, and who answers.
#[derive(Clone, Copy, Debug)]
pub struct Leg {
    /// The caller's address.
    pub caller: [u8; 4],
    /// The callee's address.
    pub callee: [u8; 4],
}

/// A SIP request from the caller of `leg` to its callee.
#[must_use]
pub fn request(leg: Leg, method: &str, call_id: &str, cseq: u32, body: &str) -> Vec<u8> {
    let src = dotted(leg.caller);
    let ctype = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/sdp\r\n".to_string()
    };
    let msg = format!(
        "{method} sip:bob@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP {src}:5060;branch=z9hG4bK-{cseq}-{method}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@example.com>;tag=from-{call_id}\r\n\
         To: <sip:bob@example.com>;tag=to-{call_id}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} {method}\r\n\
         Contact: <sip:alice@{src}:5060>\r\n\
         {ctype}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    udp(leg.caller, leg.callee, 5060, 5060, msg.as_bytes())
}

/// A SIP response from the callee of `leg` to `method`'s request `cseq`.
#[must_use]
pub fn response(
    leg: Leg,
    code: u16,
    method: &str,
    call_id: &str,
    cseq: u32,
    body: &str,
) -> Vec<u8> {
    let (src, dst) = (dotted(leg.caller), dotted(leg.callee));
    let reason = match code {
        100 => "Trying",
        180 => "Ringing",
        200 => "OK",
        486 => "Busy Here",
        _ => "Other",
    };
    let ctype = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/sdp\r\n".to_string()
    };
    let msg = format!(
        "SIP/2.0 {code} {reason}\r\n\
         Via: SIP/2.0/UDP {src}:5060;branch=z9hG4bK-{cseq}-{method}\r\n\
         From: <sip:alice@example.com>;tag=from-{call_id}\r\n\
         To: <sip:bob@example.com>;tag=to-{call_id}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} {method}\r\n\
         Contact: <sip:bob@{dst}:5060>\r\n\
         {ctype}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    udp(leg.callee, leg.caller, 5060, 5060, msg.as_bytes())
}

/// The frames of an answered call on `leg`, starting `at` and one
/// millisecond apart: INVITE, 100, 180, 200, ACK.
#[must_use]
pub fn answered_call(leg: Leg, call_id: &str, at: u64) -> Vec<Frame> {
    vec![
        (at, request(leg, "INVITE", call_id, 1, "")),
        (at + 1_000, response(leg, 100, "INVITE", call_id, 1, "")),
        (at + 2_000, response(leg, 180, "INVITE", call_id, 1, "")),
        (at + 3_000, response(leg, 200, "INVITE", call_id, 1, "")),
        (at + 4_000, request(leg, "ACK", call_id, 1, "")),
    ]
}

/// `count` in-dialog `INFO` requests with their `200 OK`s on `leg`, from CSeq
/// `first_cseq`, starting `at` and spaced `step` microseconds apart: two
/// messages each, so a dialog grows past the idle-compaction keep limit.
#[must_use]
pub fn infos(
    leg: Leg,
    call_id: &str,
    first_cseq: u32,
    count: u32,
    at: u64,
    step: u64,
) -> Vec<Frame> {
    (0..count)
        .flat_map(|i| {
            let cseq = first_cseq + i;
            let t = at + u64::from(i) * step;
            [
                (t, request(leg, "INFO", call_id, cseq, "")),
                (t + step / 2, response(leg, 200, "INFO", call_id, cseq, "")),
            ]
        })
        .collect()
}

/// `count` RTP packets of one stream from `src`:`sport` to `dst`:`dport`,
/// 20 ms apart from `at`, payload type `pt`, with a 0..3 ms arrival wobble
/// so jitter is measurable.
#[must_use]
pub fn rtp_stream(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    ssrc: u32,
    pt: u8,
    first_seq: u16,
    count: u16,
    at: u64,
) -> Vec<Frame> {
    (0..count)
        .map(|i| {
            let wobble = u64::from(i % 4) * 1_000;
            let seq = first_seq.wrapping_add(i);
            (
                at + u64::from(i) * 20_000 + wobble,
                udp(
                    src.0,
                    dst.0,
                    src.1,
                    dst.1,
                    &rtp(pt, seq, u32::from(seq) * 960, ssrc, 80),
                ),
            )
        })
        .collect()
}

/// An rtpengine `ng` `offer` for `call_id` whose SDP puts `opus` (dynamic
/// payload type 96, 48 kHz) at `media`:`port`, mirrored by the relay over HEP
/// from `relay` to the collector `homer` on the HEP port 9060.
#[must_use]
pub fn ng_offer_over_hep(
    relay: [u8; 4],
    homer: [u8; 4],
    call_id: &str,
    cookie: &str,
    media: [u8; 4],
    port: u16,
    at: u64,
) -> Frame {
    let addr = dotted(media);
    let sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {addr}\r\ns=-\r\nc=IN IP4 {addr}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 96\r\na=rtpmap:96 opus/48000/2\r\na=sendrecv\r\n"
    );
    let body = format!(
        "d7:command5:offer7:call-id{}:{call_id}3:sdp{}:{sdp}e",
        call_id.len(),
        sdp.len()
    );
    let ng = format!("{cookie} {body}");
    let secs = (EPOCH + at / SECOND) as u32;
    let usecs = (at % SECOND) as u32;
    let hep = hep_ng(call_id, secs, usecs, ng.as_bytes());
    (at, udp(relay, homer, 47_000, 9060, &hep))
}

/// A HEP v3 datagram mirroring one `ng` message of `call_id`.
fn hep_ng(call_id: &str, sec: u32, usec: u32, payload: &[u8]) -> Vec<u8> {
    fn chunk(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&((6 + data.len()) as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    let mut body = Vec::new();
    chunk(&mut body, 0x0001, &[2]);
    chunk(&mut body, 0x0002, &[17]);
    chunk(&mut body, 0x0007, &40_000u16.to_be_bytes());
    chunk(&mut body, 0x0008, &2223u16.to_be_bytes());
    chunk(&mut body, 0x0009, &sec.to_be_bytes());
    chunk(&mut body, 0x000a, &usec.to_be_bytes());
    chunk(&mut body, 0x000b, &[0x3d]);
    chunk(&mut body, 0x000c, &2001u32.to_be_bytes());
    chunk(&mut body, 0x0003, &[127, 0, 0, 1]);
    chunk(&mut body, 0x0004, &[127, 0, 0, 1]);
    chunk(&mut body, 0x0011, call_id.as_bytes());
    chunk(&mut body, 0x000f, payload);
    let mut out = Vec::with_capacity(6 + body.len());
    out.extend_from_slice(b"HEP3");
    out.extend_from_slice(&((6 + body.len()) as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// An rtpproxy `U` command from `proxy`:`pport` to the control socket
/// `relay`:7722 naming `call_id`, and the relay's reply opening `port` on
/// `media`, one millisecond apart from `at`.
#[must_use]
pub fn rtpproxy_update(
    proxy: ([u8; 4], u16),
    relay: [u8; 4],
    cookie: &str,
    call_id: &str,
    media: [u8; 4],
    port: u16,
    at: u64,
) -> Vec<Frame> {
    let command = format!("{cookie} U {call_id} 198.51.100.200 40000 ftag-{call_id}\n");
    let reply = format!("{cookie} {port} {}\n", dotted(media));
    vec![
        (at, udp(proxy.0, relay, proxy.1, 7722, command.as_bytes())),
        (
            at + 1_000,
            udp(relay, proxy.0, 7722, proxy.1, reply.as_bytes()),
        ),
    ]
}

/// An rtpproxy command from `proxy`:`pport` to `relay`:7722 under `cookie`
/// that opens nothing (`I`, the info query), for retry counting.
#[must_use]
pub fn rtpproxy_info(proxy: ([u8; 4], u16), relay: [u8; 4], cookie: &str, at: u64) -> Frame {
    let command = format!("{cookie} I\n");
    (at, udp(proxy.0, relay, proxy.1, 7722, command.as_bytes()))
}

/// The rtpproxy control socket the fixtures use.
pub const RTPPROXY_CONTROL: &str = "192.0.2.40:7722";
