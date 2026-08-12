// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal pcap writer for flag-behaviour tests.
//!
//! Several CLI flags can only be exercised against traffic the three checked-in
//! fixtures do not contain: `--limit`/`--rotate` needs more dialogs than
//! `sip_call.pcap` has, `--strip-secrets` needs a Decryption Secrets Block that
//! no sample carries, and `--hep-parse` needs HEP-encapsulated SIP. Without a
//! way to build those, the flags stayed in the untested baseline — and some
//! were counted as covered purely because their names appeared in a comment.
//!
//! `pcap` is an optional *main* dependency, so integration tests cannot use it.
//! The classic pcap format is small enough to emit directly, and doing so keeps
//! these tests free of a dev-dependency and of any capture device.
#![allow(dead_code)]

use std::path::Path;

/// Ethernet + IPv4 + UDP frame carrying `payload`.
pub fn udp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    let mut ip = Vec::with_capacity(20);
    ip.extend_from_slice(&[0x45, 0x00]);
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, 17, 0x00, 0x00]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let ck = checksum16(&ip);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());

    let mut frame = Vec::with_capacity(14 + total_len);
    // dst MAC, src MAC, ethertype IPv4
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&sport.to_be_bytes());
    frame.extend_from_slice(&dport.to_be_bytes());
    frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
    // UDP checksum 0 = "not computed", legal for IPv4.
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(payload);
    frame
}

/// Ethernet + IPv4 + TCP frame carrying `payload`.
///
/// `flags` is the raw TCP flag byte (`0x02` SYN, `0x10` ACK, `0x08` PSH,
/// `0x01` FIN). A segment without PSH or FIN stays buffered in the
/// reassembler, which is what the `max_reassembly` probe needs: several
/// connections held open at once.
pub fn tcp_frame(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&[0, 0, 0, 0]); // ack
    tcp.extend_from_slice(&[0x50, flags]); // data offset 5 words + flags
    tcp.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]); // window, csum 0, urgent
    tcp.extend_from_slice(payload);

    let total_len = 20 + tcp.len();
    let mut ip = Vec::with_capacity(20);
    ip.extend_from_slice(&[0x45, 0x00]);
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, 6, 0x00, 0x00]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let ck = checksum16(&ip);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());

    let mut frame = Vec::with_capacity(14 + total_len);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame
}

/// Frames for `flows` distinct TCP connections, each leaving one partial SIP
/// message parked in the reassembler.
///
/// Every flow sends a SYN and then one un-pushed segment whose
/// `Content-Length` promises a body it never delivers, so the reassembler
/// holds all `flows` streams at once. Above the session cap it must evict.
pub fn partial_tcp_sip_flows(flows: usize) -> Vec<Vec<u8>> {
    let a = [10, 1, 0, 1];
    let b = [10, 2, 0, 1];
    let mut frames = Vec::with_capacity(flows * 2);
    for i in 0..flows {
        let sport = 40_000 + i as u16;
        let partial = format!(
            "INVITE sip:bob@10.2.0.1 SIP/2.0\r\n\
             Via: SIP/2.0/TCP 10.1.0.1:{sport};branch=z9hG4bKtcp{i}\r\n\
             From: <sip:alice@10.1.0.1>;tag=t{i}\r\n\
             To: <sip:bob@10.2.0.1>\r\n\
             Call-ID: tcp-flow-{i}\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 500\r\n\r\npartial"
        );
        frames.push(tcp_frame(a, b, sport, 5060, 1000, 0x02, b""));
        frames.push(tcp_frame(a, b, sport, 5060, 1001, 0x10, partial.as_bytes()));
    }
    frames
}

/// One INVITE whose `From` header line carries `pad` filler bytes.
///
/// `From` is the padded header on purpose: `--json` prints it, so a header
/// line dropped for exceeding `max_header_line` is visible in the output
/// rather than only in the parser's internals.
pub fn invite_with_long_from(call_id: &str, pad: usize) -> Vec<u8> {
    let filler = "X".repeat(pad);
    let msg = format!(
        "INVITE sip:bob@10.2.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bK{call_id}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@10.1.0.1>;tag=t1;pad={filler}\r\n\
         To: <sip:bob@10.2.0.1>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    );
    udp_frame([10, 1, 0, 1], [10, 2, 0, 1], 5060, 5060, msg.as_bytes())
}

/// One INVITE carrying `pad_headers` filler headers ahead of `From`.
///
/// Pushing `From` past the header count means a run that stops parsing at
/// `max_headers_per_message` prints no `from` field, so the cap shows up in
/// `--json` output.
pub fn invite_with_padded_headers(call_id: &str, pad_headers: usize) -> Vec<u8> {
    let mut filler = String::new();
    for i in 0..pad_headers {
        filler.push_str(&format!("X-Pad{i}: v{i}\r\n"));
    }
    let msg = format!(
        "INVITE sip:bob@10.2.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bK{call_id}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         {filler}\
         From: <sip:alice@10.1.0.1>;tag=t1\r\n\
         To: <sip:bob@10.2.0.1>\r\n\
         Content-Length: 0\r\n\r\n"
    );
    udp_frame([10, 1, 0, 1], [10, 2, 0, 1], 5060, 5060, msg.as_bytes())
}

/// Write `frames` as a little-endian, Ethernet-linktype pcap.
///
/// Timestamps advance 1 ms per frame so dialog durations and ordering are
/// well-defined rather than all-zero.
pub fn write_pcap(path: &Path, frames: &[Vec<u8>]) {
    write_pcap_with_linktype(path, frames, 1);
}

/// Write `frames` as a little-endian pcap declaring link type `network`.
///
/// The link type is the whole point for the undecodable-frame suite: a
/// capture sipnab has no decoder for is the case whose failure mode was a
/// confident zero, and it can only be built by choosing the DLT in the file
/// header. `write_pcap` is this with `network = 1` (Ethernet).
///
/// Timestamps advance 1 ms per frame so dialog durations and ordering are
/// well-defined rather than all-zero.
pub fn write_pcap_with_linktype(path: &Path, frames: &[Vec<u8>], network: u32) {
    let timed: Vec<_> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| (f.clone(), i as u64 * 1_000))
        .collect();
    write_pcap_at(path, &timed, network);
}

/// Write frames at explicit microsecond offsets from the capture's start.
///
/// The fixed 1 ms cadence above cannot express a capture that goes QUIET, and
/// silence is the whole input to some behaviour: idle-dialog compaction fires
/// on the gap between a dialog's last message and the capture's final
/// timestamp, so a fixture whose frames are 1 ms apart can never be idle under
/// any window an operator would set. This is the writer for those; the cadence
/// version delegates here so both derive from one header layout.
///
/// Offsets are added to a fixed base second, so a fixture's absolute times are
/// reproducible across runs.
pub fn write_pcap_at(path: &Path, frames: &[(Vec<u8>, u64)], network: u32) {
    const BASE_SECS: u64 = 1_700_000_000;
    let mut out = Vec::new();
    // magic, version 2.4, thiszone, sigfigs, snaplen, network
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&network.to_le_bytes());

    for (f, offset_usec) in frames {
        let secs = BASE_SECS + offset_usec / 1_000_000;
        let usec = (offset_usec % 1_000_000) as u32;
        out.extend_from_slice(&(secs as u32).to_le_bytes());
        out.extend_from_slice(&usec.to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    std::fs::write(path, out).expect("write pcap");
}

/// The seven messages of one complete call, as SIP payloads.
///
/// `branch` is threaded through so callers can build two transactions that
/// share a Call-ID but differ by transaction branch, which is what a re-INVITE
/// or a forked request looks like on the wire.
pub fn sip_call(call_id: &str, branch: &str, from_user: &str, to_user: &str) -> Vec<String> {
    let src = "10.1.0.1";
    let dst = "10.2.0.1";
    let via = format!("Via: SIP/2.0/UDP {src}:5060;branch=z9hG4bK{branch}\r\n");
    let from = format!("From: <sip:{from_user}@{src}>;tag=tag-{branch}\r\n");
    let to_h = format!("To: <sip:{to_user}@{dst}>");
    let to_tagged = format!("{to_h};tag=totag-{branch}\r\n");
    let cid = format!("Call-ID: {call_id}\r\n");

    vec![
        format!(
            "INVITE sip:{to_user}@{dst} SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to_h}\r\n{cid}\
             CSeq: 1 INVITE\r\nContact: <sip:{from_user}@{src}:5060>\r\nContent-Length: 0\r\n\r\n"
        ),
        format!(
            "SIP/2.0 100 Trying\r\n{via}{from}{to_h}\r\n{cid}CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ),
        format!(
            "SIP/2.0 180 Ringing\r\n{via}{from}{to_tagged}{cid}CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ),
        format!(
            "SIP/2.0 200 OK\r\n{via}{from}{to_tagged}{cid}CSeq: 1 INVITE\r\nContact: <sip:{to_user}@{dst}:5060>\r\nContent-Length: 0\r\n\r\n"
        ),
        format!(
            "ACK sip:{to_user}@{dst} SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to_tagged}{cid}CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
        ),
        format!(
            "BYE sip:{to_user}@{dst} SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to_tagged}{cid}CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
        ),
        format!(
            "SIP/2.0 200 OK\r\n{via}{from}{to_tagged}{cid}CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
        ),
    ]
}

/// Frames for a call, alternating direction the way a real exchange does.
pub fn sip_call_frames(
    call_id: &str,
    branch: &str,
    from_user: &str,
    to_user: &str,
) -> Vec<Vec<u8>> {
    let a = [10, 1, 0, 1];
    let b = [10, 2, 0, 1];
    sip_call(call_id, branch, from_user, to_user)
        .iter()
        .enumerate()
        .map(|(i, msg)| {
            // requests (0, 4, 5) go a->b; responses come back b->a
            let from_caller = matches!(i, 0 | 4 | 5);
            if from_caller {
                udp_frame(a, b, 5060, 5060, msg.as_bytes())
            } else {
                udp_frame(b, a, 5060, 5060, msg.as_bytes())
            }
        })
        .collect()
}

/// Write a pcapng containing SHB + IDB + a Decryption Secrets Block + one EPB.
///
/// None of the 31 checked-in sample captures carries a DSB, so `--strip-secrets`
/// — whose entire job is removing them — had nothing to be tested against.
///
/// `secrets` is embedded as a TLS key-log DSB (`TLSK`), the type Wireshark and
/// sipnab both write for `--tls-key` material.
pub fn write_pcapng_with_dsb(path: &Path, secrets: &str, frame: &[u8]) {
    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        // total = 12 (type + 2x length) + padded body
        let pad = (4 - body.len() % 4) % 4;
        let total = 12 + body.len() + pad;
        let mut b = Vec::with_capacity(total);
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(&(total as u32).to_le_bytes());
        b.extend_from_slice(body);
        b.extend(std::iter::repeat_n(0u8, pad));
        b.extend_from_slice(&(total as u32).to_le_bytes());
        b
    }

    let mut out = Vec::new();

    // Section Header: byte-order magic, version 1.0, section length -1.
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    out.extend_from_slice(&block(0x0a0d_0d0a, &shb));

    // Interface Description: Ethernet, snaplen 65535.
    let mut idb = Vec::new();
    idb.extend_from_slice(&1u16.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&block(0x0000_0001, &idb));

    // Decryption Secrets: type + length + the key-log text.
    let mut dsb = Vec::new();
    dsb.extend_from_slice(&0x544c_534bu32.to_le_bytes()); // "TLSK"
    dsb.extend_from_slice(&(secrets.len() as u32).to_le_bytes());
    dsb.extend_from_slice(secrets.as_bytes());
    out.extend_from_slice(&block(0x0000_000a, &dsb));

    // Enhanced Packet: interface 0, zero timestamp, one frame.
    let mut epb = Vec::new();
    epb.extend_from_slice(&0u32.to_le_bytes());
    epb.extend_from_slice(&0u32.to_le_bytes());
    epb.extend_from_slice(&0u32.to_le_bytes());
    epb.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    epb.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    epb.extend_from_slice(frame);
    let pad = (4 - frame.len() % 4) % 4;
    epb.extend(std::iter::repeat_n(0u8, pad));
    out.extend_from_slice(&block(0x0000_0006, &epb));

    std::fs::write(path, out).expect("write pcapng");
}

/// Count blocks of `kind` in a pcapng file. Used to assert a DSB is present
/// before stripping and absent afterwards.
pub fn count_pcapng_blocks(path: &Path, kind: u32) -> usize {
    let d = std::fs::read(path).expect("read pcapng");
    let mut off = 0usize;
    let mut n = 0usize;
    while off + 12 <= d.len() {
        let bt = u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]]);
        let bl = u32::from_le_bytes([d[off + 4], d[off + 5], d[off + 6], d[off + 7]]) as usize;
        if bl < 12 {
            break;
        }
        if bt == kind {
            n += 1;
        }
        off += bl;
    }
    n
}

/// One's-complement checksum over a 16-bit-aligned buffer.
fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
