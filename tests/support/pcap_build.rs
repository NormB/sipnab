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

/// Wrap `payload` in an unmasked WebSocket text frame (RFC 6455 §5.2).
pub fn ws_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x81u8]; // FIN + opcode 1 (text)
    match payload.len() {
        n if n < 126 => out.push(n as u8),
        n => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// Frames for one answered call carried as SIP-over-WebSocket (RFC 7118) over
/// TCP on `ws_port`.
///
/// The whole point is `ws_port`: with a port outside sipnab's WebSocket set
/// this capture used to produce nothing at all — no dialog, no message count
/// and no notice — which is what a deployment terminating WSS on 8081 saw of
/// its entire WebRTC signalling leg.
pub fn ws_sip_call(call_id: &str, ws_port: u16) -> Vec<Vec<u8>> {
    let a = [10, 3, 0, 1];
    let b = [10, 3, 0, 2];
    let client = 51_000u16;
    let via = format!("Via: SIP/2.0/WS 10.3.0.1:{client};branch=z9hG4bKws{call_id}\r\n");
    let from = "From: <sip:alice@10.3.0.1>;tag=w1\r\n";
    let to = "To: <sip:bob@10.3.0.2>";
    let cid = format!("Call-ID: {call_id}\r\n");
    let invite = format!(
        "INVITE sip:bob@10.3.0.2 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to}\r\n{cid}\
         CSeq: 1 INVITE\r\nContact: <sip:alice@10.3.0.1;transport=ws>\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let ok = format!(
        "SIP/2.0 200 OK\r\n{via}{from}{to};tag=w2\r\n{cid}CSeq: 1 INVITE\r\n\
         Contact: <sip:bob@10.3.0.2;transport=ws>\r\nContent-Length: 0\r\n\r\n"
    );
    vec![
        tcp_frame(a, b, client, ws_port, 1000, 0x02, b""),
        tcp_frame(
            a,
            b,
            client,
            ws_port,
            1001,
            0x18,
            &ws_frame(invite.as_bytes()),
        ),
        tcp_frame(b, a, ws_port, client, 2000, 0x18, &ws_frame(ok.as_bytes())),
    ]
}

/// Frames for one answered call whose INVITE carries a `body` byte body over
/// TCP, followed on the same connection by the `ACK` and the `BYE`.
///
/// A carrier trunk reaches this shape with an ISUP-encapsulated multipart body
/// or a long `Record-Route` set. The segments carry no `PSH` until the last,
/// so the reassembler has to buffer the lot — and above its ceiling it flushes
/// mid-message, which destroys the framing for everything behind the cut. The
/// `ACK` and the `BYE` are there to make that visible: they are short, valid,
/// unremarkable messages that simply cease to exist, and the truncated INVITE
/// in front of them is reported as malformed by a peer that sent it whole.
///
/// `push_every_segment` chooses which of sipnab's two ceilings the message
/// meets. Without it the segments accumulate and the REASSEMBLY buffer decides;
/// with it every segment is delivered on arrival, so the message is instead
/// held as a partial between flushes and the LEFTOVER ceiling decides. A stack
/// that sets `PSH` per write is ordinary, so a fix to one ceiling and not the
/// other would work on half the trunks in the world.
pub fn tcp_sip_call_with_body(
    call_id: &str,
    body: usize,
    push_every_segment: bool,
) -> Vec<Vec<u8>> {
    let a = [10, 4, 0, 1];
    let b = [10, 4, 0, 2];
    let client = 52_000u16;
    let via = format!("Via: SIP/2.0/TCP 10.4.0.1:{client};branch=z9hG4bKbig{call_id}\r\n");
    let from = "From: <sip:alice@10.4.0.1>;tag=b1\r\n";
    let to = "To: <sip:bob@10.4.0.2>;tag=b2\r\n";
    let cid = format!("Call-ID: {call_id}\r\n");
    let request = |method: &str, cseq: &str, extra: String| {
        format!(
            "{method} sip:bob@10.4.0.2 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to}{cid}\
             CSeq: {cseq}\r\nContact: <sip:alice@10.4.0.1;transport=tcp>\r\n{extra}"
        )
    };
    let invite = request(
        "INVITE",
        "1 INVITE",
        format!(
            "Content-Type: application/octet-stream\r\nContent-Length: {body}\r\n\r\n{}",
            "X".repeat(body)
        ),
    );
    let ack = request("ACK", "1 ACK", "Content-Length: 0\r\n\r\n".into());
    let bye = request("BYE", "2 BYE", "Content-Length: 0\r\n\r\n".into());
    let ok = format!(
        "SIP/2.0 200 OK\r\n{via}{from}{to}{cid}CSeq: 1 INVITE\r\n\
         Contact: <sip:bob@10.4.0.2;transport=tcp>\r\nContent-Length: 0\r\n\r\n"
    );

    // ~1400-byte segments. PSH on the last one always, and on every one when
    // the caller asks: without a push the reassembler buffers, and with one it
    // delivers immediately and the partial is held a layer up instead.
    let stream = format!("{invite}{ack}{bye}");
    let bytes = stream.as_bytes();
    let mut frames = vec![tcp_frame(a, b, client, 5060, 1000, 0x02, b"")];
    let mut seq = 1001u32;
    let mut offset = 0usize;
    while offset < bytes.len() {
        let end = (offset + 1400).min(bytes.len());
        let last = end == bytes.len();
        frames.push(tcp_frame(
            a,
            b,
            client,
            5060,
            seq,
            if last || push_every_segment {
                0x18
            } else {
                0x10
            },
            &bytes[offset..end],
        ));
        seq += (end - offset) as u32;
        offset = end;
    }
    frames.push(tcp_frame(b, a, 5060, client, 2000, 0x18, ok.as_bytes()));
    frames
}

/// [`sdp_call_with_lossy_rtp`] at an explicit packetization cadence, timed.
///
/// The fixed 1 ms frame cadence the untimed writer applies cannot express a
/// codec's packetization interval, and that interval is the whole input to
/// burst and gap DURATIONS: a stream whose packets are 1 ms apart infers no
/// plausible ptime at all. G.729 at 30 ms and a satellite trunk at 40 ms are
/// ordinary, and this is how a fixture says so.
pub fn sdp_call_with_lossy_rtp_at(
    call_id: &str,
    packets: u16,
    losses_per_ten: u16,
    ptime_ms: u64,
) -> Vec<(Vec<u8>, u64)> {
    let frames = sdp_call_with_lossy_rtp(call_id, packets, losses_per_ten);
    // The signalling frames bracket the media: three ahead of it (INVITE, 200,
    // ACK) and two behind (BYE, 200). Only the RTP in between carries the
    // cadence; the rest keeps the 1 ms spacing so ordering stays well-defined.
    let media = frames.len() - 5;
    // Each surviving packet is timed by its own SEQUENCE NUMBER, not by its
    // position in the list. A lost packet still occupied its slot on the wire,
    // so closing the gap it left would compress the wall clock by the loss
    // rate and every inference off inter-arrival would read low by exactly
    // that factor — which is the mistake this fixture exists to expose in the
    // code, not to make.
    let kept: Vec<u64> = (0..packets)
        .filter(|seq| seq % 10 >= losses_per_ten)
        .map(u64::from)
        .collect();
    assert_eq!(kept.len(), media, "the loss pattern must match the frames");
    let media_us = |n: usize| 10_000 + kept[n] * ptime_ms * 1_000;
    let end_us = media_us(media - 1);
    frames
        .into_iter()
        .enumerate()
        .map(|(i, f)| {
            let us = match i {
                i if i < 3 => i as u64 * 1_000,
                i if i < 3 + media => media_us(i - 3),
                i => end_us + (i - 2 - media) as u64 * 1_000,
            };
            (f, us)
        })
        .collect()
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

/// One INVITE with no `Max-Forwards`, which trips exactly one lint rule.
///
/// `cseq` is threaded through so a caller can build many of them inside ONE
/// dialog: the per-rule cap is per rule per dialog, so a fixture that spread
/// the repeats over forty dialogs could never reach it.
pub fn invite_without_max_forwards(call_id: &str, branch: &str, cseq: u32) -> Vec<u8> {
    let msg = format!(
        "INVITE sip:bob@10.2.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bK{branch}\r\n\
         From: <sip:alice@10.1.0.1>;tag=t1\r\n\
         To: <sip:bob@10.2.0.1>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} INVITE\r\n\
         Contact: <sip:alice@10.1.0.1:5060>\r\n\
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

/// Wrap `data` in a gzip member built from STORED (uncompressed) deflate
/// blocks.
///
/// `flate2` is a main dependency, so an integration test cannot compress with
/// it — and a checked-in `.gz` fixture would be a binary blob nobody can read
/// a diff of. Stored blocks are the one deflate encoding short enough to emit
/// by hand, and every gzip reader accepts them, which is all a test of the
/// INFLATION CAP needs: the cap counts bytes coming out, not how they were
/// packed.
pub fn gzip_stored(data: &[u8]) -> Vec<u8> {
    // Fixed header: magic, deflate method, no flags, no mtime, no extra
    // flags, unknown OS.
    let mut out = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff];
    let mut chunks = data.chunks(0xffff).peekable();
    if chunks.peek().is_none() {
        // One final, empty stored block: an empty member still has to say
        // where the stream ends.
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
    }
    while let Some(chunk) = chunks.next() {
        let len = chunk.len() as u16;
        out.push(u8::from(chunks.peek().is_none())); // BFINAL, BTYPE=00
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// CRC-32 (IEEE, reflected) over `data`, for the gzip trailer.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            // Branchless reflected update: subtract the low bit from zero to
            // build an all-ones or all-zeros mask.
            crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// Frames for one answered call whose SDP anchors an RTP stream, followed by
/// that stream with `losses_per_ten` of every ten sequence numbers missing.
///
/// An orphan RTP stream reaches no batch surface — `--json-dialogs` prints
/// dialogs — so a capture that exercises per-stream loss retention has to
/// carry the signalling that anchors the media to a call. The SDP offer names
/// the caller's port and the answer the callee's, which is what links the
/// stream to the dialog.
pub fn sdp_call_with_lossy_rtp(call_id: &str, packets: u16, losses_per_ten: u16) -> Vec<Vec<u8>> {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let sdp = |ip: &str, port: u16| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        )
    };
    let offer = sdp("10.0.0.1", 20000);
    let answer = sdp("10.0.0.2", 30000);
    let via = "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKlossy\r\n";
    let from = "From: <sip:a@10.0.0.1>;tag=t1\r\n";
    let to = "To: <sip:b@10.0.0.2>";
    let to_tagged = "To: <sip:b@10.0.0.2>;tag=t2\r\n";
    let cid = format!("Call-ID: {call_id}\r\n");

    let mut frames = vec![
        udp_frame(
            A,
            B,
            5060,
            5060,
            format!(
                "INVITE sip:b@10.0.0.2 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to}\r\n{cid}\
             CSeq: 1 INVITE\r\nContact: <sip:a@10.0.0.1:5060>\r\n\
             Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{offer}",
                offer.len()
            )
            .as_bytes(),
        ),
        udp_frame(
            B,
            A,
            5060,
            5060,
            format!(
                "SIP/2.0 200 OK\r\n{via}{from}{to_tagged}{cid}CSeq: 1 INVITE\r\n\
             Contact: <sip:b@10.0.0.2:5060>\r\nContent-Type: application/sdp\r\n\
             Content-Length: {}\r\n\r\n{answer}",
                answer.len()
            )
            .as_bytes(),
        ),
        udp_frame(
            A,
            B,
            5060,
            5060,
            format!(
                "ACK sip:b@10.0.0.2 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to_tagged}{cid}\
             CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        ),
    ];
    for seq in 0..packets {
        if seq % 10 < losses_per_ten {
            continue; // the packet the capture never saw
        }
        let mut rtp = vec![0x80, 0x00];
        rtp.extend_from_slice(&seq.to_be_bytes());
        rtp.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
        rtp.extend_from_slice(&0x1122_3344u32.to_be_bytes());
        rtp.extend_from_slice(&[0xff; 160]);
        frames.push(udp_frame(A, B, 20000, 30000, &rtp));
    }
    frames.push(udp_frame(
        A,
        B,
        5060,
        5060,
        format!(
            "BYE sip:b@10.0.0.2 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to_tagged}{cid}\
         CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
        )
        .as_bytes(),
    ));
    frames.push(udp_frame(
        B,
        A,
        5060,
        5060,
        format!(
            "SIP/2.0 200 OK\r\n{via}{from}{to_tagged}{cid}CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
        )
        .as_bytes(),
    ));
    frames
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
