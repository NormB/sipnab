// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The SDP part of a `multipart/*` body links the call's RTP, as an
//! `application/sdp` body does, on the batch path and on the `--cores` path.
//!
//! A SIP-I call carries its session description and its ISUP message side by
//! side in one `multipart/mixed` body
//! ([RFC 3204 section 4.1](https://www.rfc-editor.org/rfc/rfc3204.html#section-4.1)),
//! and the ISUP part is binary
//! ([RFC 3204 section 3.1](https://www.rfc-editor.org/rfc/rfc3204.html#section-3.1):
//! "Encoding scheme: binary"). A SIPREC recording session carries its SDP
//! beside the recording metadata the same way
//! ([RFC 7866 section 9.1](https://www.rfc-editor.org/rfc/rfc7866.html#section-9.1)).
//! sipnab read SDP only from a whole `application/sdp` body, so neither call's
//! RTP was bound to the call.
//!
//! Every capture here is written by this file into a temporary directory:
//! [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737.html) addresses,
//! `example.com` names and 555-01xx numbers, and an ISUP message made of
//! arbitrary bytes. Nothing is committed.
#![cfg(feature = "native")]

use std::path::Path;
use std::process::Command;

#[path = "support/pcap_build.rs"]
mod pcap_build;

use pcap_build::{udp_frame, write_pcap_at};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The originating gateway's signaling address.
const A: [u8; 4] = [192, 0, 2, 10];
/// The terminating gateway's signaling address.
const B: [u8; 4] = [198, 51, 100, 20];
/// The originating gateway's media address. Not the signaling address, as
/// on a gateway with a separate media interface: `--cores` shards by host
/// pair, so media between the signaling hosts would always reach the worker
/// that owns the SIP, and parity would hold without any copy of the SDP.
const A_MEDIA: [u8; 4] = [192, 0, 2, 11];
/// The terminating gateway's media address.
const B_MEDIA: [u8; 4] = [198, 51, 100, 21];
/// The originating gateway's media port.
const A_PORT: u16 = 40000;
/// The terminating gateway's media port.
const B_PORT: u16 = 50000;
/// RTP packets sent each way.
const PACKETS: u16 = 50;

/// The `--cores` values every parity check compares with `--cores 1`.
const CORES: [&str; 4] = ["2", "3", "4", "8"];

/// The SIP-I call's Call-ID.
const SIP_I_CALL: &str = "sip-i-1@192.0.2.10";

/// A binary ISUP message: not UTF-8, and holding a CR LF pair, as an
/// arbitrary binary body may. The bytes are made up; the called number in
/// them is 555-0100.
const ISUP: &[u8] = &[
    0x01, 0x00, 0x60, 0x01, 0x0a, 0x00, 0x02, 0x0d, 0x0a, 0x0a, 0x83, 0x90, 0x55, 0x05, 0x01, 0x00,
    0xff, 0x0f, 0xc3, 0x28, 0x00,
];

/// An SDP description of one PCMU stream on `ip:port`.
fn sdp(ip: &str, port: u16, direction: &str) -> String {
    format!(
        "v=0\r\no=- 7 7 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na={direction}\r\n"
    )
}

/// A `multipart/mixed` body under `boundary`: each part's headers and bytes,
/// framed as [RFC 2046 section 5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1)
/// writes them.
fn multipart(boundary: &str, parts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (headers, bytes) in parts {
        body.extend_from_slice(format!("--{boundary}\r\n{headers}\r\n\r\n").as_bytes());
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

/// A SIP message: `head` (start line and headers, each ending CR LF), then
/// `Content-Type` when given, `Content-Length` and `body`.
fn message(head: &str, content_type: Option<&str>, body: &[u8]) -> Vec<u8> {
    let ct = content_type.map_or_else(String::new, |ct| format!("Content-Type: {ct}\r\n"));
    let mut out = format!("{head}{ct}Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}

/// An RTP packet of PCMU silence.
fn rtp(seq: u16, ssrc: u32) -> Vec<u8> {
    let mut p = vec![0x80, 0x00];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(&[0xff; 160]);
    p
}

/// A body: a whole `application/sdp` description, or a SIP-I `multipart/mixed`
/// one, or a `multipart/mixed` one with no SDP part at all.
#[derive(Clone, Copy)]
enum Body {
    /// `application/sdp`.
    Sdp,
    /// SDP then binary ISUP, the RFC 3204 section 4.1 shape.
    SipI,
    /// Binary ISUP and a text part, no SDP.
    NoSdpPart,
}

/// The `Content-Type` and body bytes for `sdp_text` as `kind`.
fn body(kind: Body, sdp_text: &str) -> (String, Vec<u8>) {
    let boundary = "unique-boundary-1";
    // RFC 3204 section 3.1: `version` is required and free-form, `base` is
    // optional and one of its Table 1 values. The `Content-Type` is folded,
    // as the section 4.1 example folds it.
    let isup_headers = "Content-Type: application/ISUP; version=itu-t;\r\n base=itu-t92+\r\n\
                        Content-Disposition: signal; handling=optional";
    match kind {
        Body::Sdp => ("application/sdp".to_string(), sdp_text.as_bytes().to_vec()),
        // RFC 3204 section 4.1 writes the SDP part's type in capitals.
        Body::SipI => (
            format!("multipart/mixed; boundary={boundary}"),
            multipart(
                boundary,
                &[
                    ("Content-Type: application/SDP", sdp_text.as_bytes()),
                    (isup_headers, ISUP),
                ],
            ),
        ),
        Body::NoSdpPart => (
            format!("multipart/mixed; boundary={boundary}"),
            multipart(
                boundary,
                &[
                    (isup_headers, ISUP),
                    ("Content-Type: text/plain", sdp_text.as_bytes()),
                ],
            ),
        ),
    }
}

/// A complete call from A to B: INVITE with the offer as `offer`, 200 OK with
/// the answer as `answer`, ACK, [`PACKETS`] RTP packets each way, BYE and its
/// 200 OK.
fn call(offer: Body, answer: Body) -> Vec<(Vec<u8>, u64)> {
    let via = "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKsipi1\r\n";
    let from = "From: <sip:+15550100@example.com>;tag=a1\r\n";
    let to = "To: <sip:+15550199@example.com>\r\n";
    let to_tagged = "To: <sip:+15550199@example.com>;tag=b1\r\n";
    let cid = format!("Call-ID: {SIP_I_CALL}\r\n");
    let (offer_ct, offer_body) = body(offer, &sdp("192.0.2.11", A_PORT, "sendrecv"));
    let (answer_ct, answer_body) = body(answer, &sdp("198.51.100.21", B_PORT, "sendrecv"));
    let invite = message(
        &format!(
            "INVITE sip:+15550199@example.com SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to}{cid}\
             CSeq: 1 INVITE\r\nContact: <sip:+15550100@192.0.2.10:5060>\r\nMIME-Version: 1.0\r\n"
        ),
        Some(&offer_ct),
        &offer_body,
    );
    let ok = message(
        &format!(
            "SIP/2.0 200 OK\r\n{via}{from}{to_tagged}{cid}CSeq: 1 INVITE\r\n\
             Contact: <sip:+15550199@198.51.100.20:5060>\r\nMIME-Version: 1.0\r\n"
        ),
        Some(&answer_ct),
        &answer_body,
    );
    let ack = message(
        &format!(
            "ACK sip:+15550199@198.51.100.20:5060 SIP/2.0\r\n{via}Max-Forwards: 70\r\n\
             {from}{to_tagged}{cid}CSeq: 1 ACK\r\n"
        ),
        None,
        b"",
    );
    let mut frames = vec![
        (udp_frame(A, B, 5060, 5060, &invite), 0),
        (udp_frame(B, A, 5060, 5060, &ok), 10_000),
        (udp_frame(A, B, 5060, 5060, &ack), 20_000),
    ];
    for seq in 0..PACKETS {
        let at = 100_000 + u64::from(seq) * 20_000;
        frames.push((
            udp_frame(A_MEDIA, B_MEDIA, A_PORT, B_PORT, &rtp(seq, 0x0a0a_0a0a)),
            at,
        ));
        frames.push((
            udp_frame(B_MEDIA, A_MEDIA, B_PORT, A_PORT, &rtp(seq, 0x0b0b_0b0b)),
            at + 1_000,
        ));
    }
    let end = 100_000 + u64::from(PACKETS) * 20_000 + 100_000;
    let bye = message(
        &format!(
            "BYE sip:+15550199@198.51.100.20:5060 SIP/2.0\r\n{via}Max-Forwards: 70\r\n\
             {from}{to_tagged}{cid}CSeq: 2 BYE\r\n"
        ),
        None,
        b"",
    );
    let bye_ok = message(
        &format!("SIP/2.0 200 OK\r\n{via}{from}{to_tagged}{cid}CSeq: 2 BYE\r\n"),
        None,
        b"",
    );
    frames.push((udp_frame(A, B, 5060, 5060, &bye), end));
    frames.push((udp_frame(B, A, 5060, 5060, &bye_ok), end + 10_000));
    frames
}

/// The Call-ID of the recording session.
const RS_CALL: &str = "rs-1@192.0.2.31";
/// The SRC.
const SRC: [u8; 4] = [192, 0, 2, 31];
/// The SRS.
const SRS: [u8; 4] = [192, 0, 2, 30];
/// Where the SRC sends the recorded media from: a media relay beside it.
const SRC_MEDIA: [u8; 4] = [192, 0, 2, 33];
/// Where the SRS receives it.
const SRS_MEDIA: [u8; 4] = [192, 0, 2, 34];
/// The SRC's sending ports, one per recorded stream.
const SRC_PORTS: [u16; 2] = [20000, 20002];
/// The SRS's receiving ports.
const SRS_PORTS: [u16; 2] = [30000, 30002];

/// RFC 7865 metadata naming two participants, each sending one stream.
const METADATA: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<recording xmlns='urn:ietf:params:xml:ns:recording:1'>\r\n\
<datamode>complete</datamode>\r\n\
<session session_id=\"c2Vzc2lvbg\"></session>\r\n\
<participant participant_id=\"cGFydC1h\">\r\n\
<nameID aor=\"sip:+15550101@example.com\"><name>A</name></nameID>\r\n\
</participant>\r\n\
<participant participant_id=\"cGFydC1i\">\r\n\
<nameID aor=\"sip:+15550102@example.com\"><name>B</name></nameID>\r\n\
</participant>\r\n\
<stream stream_id=\"c3RyLTA\" session_id=\"c2Vzc2lvbg\"><label>0</label></stream>\r\n\
<stream stream_id=\"c3RyLTE\" session_id=\"c2Vzc2lvbg\"><label>1</label></stream>\r\n\
<participantstreamassoc participant_id=\"cGFydC1h\"><send>c3RyLTA</send></participantstreamassoc>\r\n\
<participantstreamassoc participant_id=\"cGFydC1i\"><send>c3RyLTE</send></participantstreamassoc>\r\n\
</recording>";

/// A SIPREC recording session: the SRC's INVITE carries a labeled SDP offer
/// beside the metadata, the SRS answers with a plain `application/sdp` body
/// when `answered`, and the SRC sends [`PACKETS`] packets on each recorded
/// stream.
fn recording_session(answered: bool) -> Vec<(Vec<u8>, u64)> {
    let via = "Via: SIP/2.0/UDP 192.0.2.31:5060;branch=z9hG4bKrs1\r\n";
    let from = "From: <sip:src@192.0.2.31>;tag=s1\r\n";
    let to = "To: <sip:srs@192.0.2.30>\r\n";
    let to_tagged = "To: <sip:srs@192.0.2.30>;tag=r1\r\n";
    let cid = format!("Call-ID: {RS_CALL}\r\n");
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.33\r\ns=-\r\nc=IN IP4 192.0.2.33\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:0\r\na=sendonly\r\n\
         m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:1\r\na=sendonly\r\n",
        SRC_PORTS[0], SRC_PORTS[1]
    );
    let answer = format!(
        "v=0\r\no=- 2 2 IN IP4 192.0.2.34\r\ns=-\r\nc=IN IP4 192.0.2.34\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:0\r\na=recvonly\r\n\
         m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:1\r\na=recvonly\r\n",
        SRS_PORTS[0], SRS_PORTS[1]
    );
    let invite = message(
        &format!(
            "INVITE sip:srs@192.0.2.30 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to}{cid}\
             CSeq: 1 INVITE\r\nContact: <sip:src@192.0.2.31:5060>;+sip.src\r\n\
             Require: siprec\r\nMIME-Version: 1.0\r\n"
        ),
        Some("multipart/mixed; boundary=rs-boundary"),
        &multipart(
            "rs-boundary",
            &[
                ("Content-Type: application/sdp", offer.as_bytes()),
                (
                    "Content-Type: application/rs-metadata+xml\r\n\
                     Content-Disposition: recording-session",
                    METADATA.as_bytes(),
                ),
            ],
        ),
    );
    let mut frames = vec![(udp_frame(SRC, SRS, 5060, 5060, &invite), 0)];
    if answered {
        let ok = message(
            &format!(
                "SIP/2.0 200 OK\r\n{via}{from}{to_tagged}{cid}CSeq: 1 INVITE\r\n\
                 Contact: <sip:srs@192.0.2.30:5060>\r\n"
            ),
            Some("application/sdp"),
            answer.as_bytes(),
        );
        frames.push((udp_frame(SRS, SRC, 5060, 5060, &ok), 10_000));
    }
    for seq in 0..PACKETS {
        let at = 100_000 + u64::from(seq) * 20_000;
        for (i, ssrc) in [0x5151_0000_u32, 0x5252_0000].into_iter().enumerate() {
            frames.push((
                udp_frame(
                    SRC_MEDIA,
                    SRS_MEDIA,
                    SRC_PORTS[i],
                    SRS_PORTS[i],
                    &rtp(seq, ssrc),
                ),
                at + i as u64 * 1_000,
            ));
        }
    }
    frames
}

/// One stream as `--json-dialogs` prints it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Stream {
    /// The Call-ID of the dialog the stream is printed under.
    printed_under: String,
    /// The Call-ID the stream is bound to.
    bound_to: Option<String>,
    /// `ip:port` it is sent from.
    src: String,
    /// `ip:port` it is sent to.
    dst: String,
    /// Packets counted.
    packets: u64,
}

/// Write `frames` into `dir` and return the capture's path.
fn capture(dir: &Path, frames: &[(Vec<u8>, u64)]) -> Result<String, TestError> {
    let path = dir.join("call.pcap");
    write_pcap_at(&path, frames, 1)?;
    Ok(path
        .to_str()
        .ok_or("the temp path is not UTF-8")?
        .to_string())
}

/// `sipnab -N -I <pcap> --json-dialogs <extra>`: its stdout, and every
/// stream of every dialog it prints, sorted.
fn run(pcap: &str, extra: &[&str]) -> Result<(String, Vec<Stream>), TestError> {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", pcap, "--no-cli-print", "--json-dialogs"])
        .args(extra)
        .env("SIPNAB_LOG", "warn")
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "sipnab {extra:?} exited {:?}; stderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    let stdout = String::from_utf8(out.stdout)?;
    let mut streams = Vec::new();
    for line in stdout.lines().filter(|l| l.starts_with('{')) {
        let dialog: serde_json::Value = serde_json::from_str(line)?;
        let call_id = dialog["call_id"].as_str().ok_or("a dialog has a call_id")?;
        for s in dialog["streams"].as_array().into_iter().flatten() {
            streams.push(Stream {
                printed_under: call_id.to_string(),
                bound_to: s["associated_dialog"].as_str().map(str::to_string),
                src: s["src"].as_str().ok_or("a stream has src")?.to_string(),
                dst: s["dst"].as_str().ok_or("a stream has dst")?.to_string(),
                packets: s["packets"].as_u64().ok_or("a stream has packets")?,
            });
        }
    }
    streams.sort();
    Ok((stdout, streams))
}

/// The two streams of the A-B call, each bound to `call` and printed under it.
fn both_directions(call: &str) -> Vec<Stream> {
    let a = format!("192.0.2.11:{A_PORT}");
    let b = format!("198.51.100.21:{B_PORT}");
    let stream = |src: &str, dst: &str| Stream {
        printed_under: call.to_string(),
        bound_to: Some(call.to_string()),
        src: src.to_string(),
        dst: dst.to_string(),
        packets: u64::from(PACKETS),
    };
    let mut v = vec![stream(&a, &b), stream(&b, &a)];
    v.sort();
    v
}

/// A SIP-I call, offer and answer both `multipart/mixed` with a binary ISUP
/// part, binds both of its RTP streams to the call.
#[test]
fn a_sip_i_call_binds_its_rtp_to_the_call() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), &call(Body::SipI, Body::SipI))?;
    let (out, streams) = run(&pcap, &[])?;
    assert_eq!(streams, both_directions(SIP_I_CALL), "{out}");
    Ok(())
}

/// The SIP-I call gives the same output with one core and with several:
/// every worker learns the call's media sockets from the multipart SDP.
#[test]
fn a_sip_i_call_is_reported_the_same_with_one_core_and_with_several() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), &call(Body::SipI, Body::SipI))?;
    let (one_out, one) = run(&pcap, &["--cores", "1"])?;
    assert_eq!(one, both_directions(SIP_I_CALL), "--cores 1:\n{one_out}");
    for cores in CORES {
        let (out, streams) = run(&pcap, &["--cores", cores])?;
        assert_eq!(streams, one, "--cores {cores} against --cores 1:\n{out}");
        assert_eq!(out, one_out, "--cores {cores} prints what --cores 1 prints");
    }
    Ok(())
}

/// The SDP may sit in either message: a multipart offer answered by a plain
/// `application/sdp` body, and a plain offer answered by a multipart body,
/// each bind both streams.
#[test]
fn either_side_of_the_offer_answer_may_be_multipart() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    for (offer, answer) in [(Body::SipI, Body::Sdp), (Body::Sdp, Body::SipI)] {
        let pcap = capture(dir.path(), &call(offer, answer))?;
        let (out, streams) = run(&pcap, &[])?;
        assert_eq!(streams, both_directions(SIP_I_CALL), "{out}");
    }
    Ok(())
}

/// Negative control: a `multipart/mixed` body whose parts are ISUP and plain
/// text holds no session description, so it links nothing, even though the
/// text part reads as SDP.
#[test]
fn a_multipart_body_with_no_sdp_part_binds_no_rtp() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), &call(Body::NoSdpPart, Body::NoSdpPart))?;
    for cores in ["1"].into_iter().chain(CORES) {
        let (out, streams) = run(&pcap, &["--cores", cores])?;
        assert!(
            streams.is_empty(),
            "--cores {cores}: no SDP part, no stream bound:\n{out}"
        );
    }
    Ok(())
}

/// The SIPREC recording session's two streams, each bound to it once.
fn recorded_streams() -> Vec<Stream> {
    let mut v: Vec<Stream> = (0..2)
        .map(|i| Stream {
            printed_under: RS_CALL.to_string(),
            bound_to: Some(RS_CALL.to_string()),
            src: format!("192.0.2.33:{}", SRC_PORTS[i]),
            dst: format!("192.0.2.34:{}", SRS_PORTS[i]),
            packets: u64::from(PACKETS),
        })
        .collect();
    v.sort();
    v
}

/// A SIPREC session answered by the SRS: each recorded stream is bound to the
/// recording session once, as one stream, on one core and on four. The
/// SRS's plain answer already named the receiving sockets; the SRC's
/// multipart offer now names the sending ones too, and the two must still
/// describe one stream each, not two.
#[test]
fn an_answered_recording_session_binds_each_stream_once() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), &recording_session(true))?;
    for cores in ["1"].into_iter().chain(CORES) {
        let (out, streams) = run(&pcap, &["--cores", cores])?;
        assert_eq!(streams, recorded_streams(), "--cores {cores}:\n{out}");
    }
    Ok(())
}

/// A SIPREC session whose answer the capture missed: only the SRC's multipart
/// offer names the streams' sockets, and it binds them.
#[test]
fn an_unanswered_recording_session_binds_its_streams_from_the_offer() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), &recording_session(false))?;
    for cores in ["1"].into_iter().chain(CORES) {
        let (out, streams) = run(&pcap, &["--cores", cores])?;
        assert_eq!(streams, recorded_streams(), "--cores {cores}:\n{out}");
    }
    Ok(())
}
