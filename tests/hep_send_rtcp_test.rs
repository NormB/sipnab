// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--hep-send` forwards RTCP in the form HOMER keeps.
//!
//! sipnab sent RTCP as the raw binary datagram in HEP protocol type 5, with no
//! correlation chunk. HOMER's collector, heplify-server, stores type 5 only
//! when the correlation ID is non-empty (`database/postgres.go`, line 187), and
//! homer-ui reads what it stored with `JSON.parse`. So none of it reached
//! HOMER, and nothing said so.
//!
//! This runs the real binary over a capture holding one call (SIP with SDP,
//! RTP, RTCP both ways) and one RTCP flow no SDP names, forwards it to a
//! collector socket this test owns, and parses every datagram that arrives.

#![cfg(all(unix, feature = "hep"))]

use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

#[path = "support/pcap_build.rs"]
mod pcap_build;

include!("support/timeout.rs");

use pcap_build::{udp_frame, write_pcap};
use sipnab::capture::hep::{HepPacket, HepProtocol, parse_hep};

type TestError = Box<dyn std::error::Error>;

/// The call's Call-ID: what every forwarded report must carry.
const CALL_ID: &str = "rtcp-to-homer-1@10.0.0.1";

const A: [u8; 4] = [10, 0, 0, 1];
const B: [u8; 4] = [10, 0, 0, 2];

/// A real sender report followed by SDES, as captured (heplify v1.67.1,
/// `protos/rtcp_test.go` line 79): SSRC 0x58f33dea, 749 packets sent.
const CAPTURED_SR_SDES: &[u8] = &[
    0x81, 0xc8, 0x0, 0xc, 0x58, 0xf3, 0x3d, 0xea, 0x0, 0x2, 0x4f, 0xfb, 0x82, 0x8f, 0x5b, 0x92,
    0x11, 0x4a, 0xc, 0x42, 0x0, 0x0, 0x2, 0xed, 0x0, 0x1, 0xca, 0xcf, 0xd2, 0xbd, 0x4e, 0x3e, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x0, 0x0, 0x14, 0x86, 0xe9, 0xf, 0x9d, 0x0, 0x3, 0x44,
    0xdd, 0x81, 0xca, 0x0, 0x8, 0x58, 0xf3, 0x3d, 0xea, 0x1, 0x16, 0x41, 0x43, 0x4c, 0x54, 0x50,
    0x20, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x20, 0x33,
    0x30, 0x0, 0x0, 0x0, 0x0,
];

/// A receiver report from SSRC 0xd2bd4e3e about 0x58f33dea: 2 lost, jitter 37.
const RECEIVER_REPORT: &[u8] = &[
    0x81, 0xc9, 0x00, 0x07, 0xd2, 0xbd, 0x4e, 0x3e, 0x58, 0xf3, 0x3d, 0xea, 0x02, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// SDP naming `ip`:`port` for PCMU.
fn sdp(ip: &str, port: u16) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    )
}

/// One answered call A:20000 <-> B:30000 with RTP and RTCP both ways, plus an
/// RTCP flow between two hosts no SDP named.
fn capture() -> Vec<Vec<u8>> {
    let via = "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKrtcp\r\n";
    let from = "From: <sip:a@10.0.0.1>;tag=t1\r\n";
    let to = "To: <sip:b@10.0.0.2>;tag=t2\r\n";
    let cid = format!("Call-ID: {CALL_ID}\r\n");
    let (offer, answer) = (sdp("10.0.0.1", 20000), sdp("10.0.0.2", 30000));
    let sip = |src, dst, text: String| udp_frame(src, dst, 5060, 5060, text.as_bytes());

    let mut frames = vec![
        sip(
            A,
            B,
            format!(
                "INVITE sip:b@10.0.0.2 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}\
                 To: <sip:b@10.0.0.2>\r\n{cid}CSeq: 1 INVITE\r\nContact: <sip:a@10.0.0.1>\r\n\
                 Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{offer}",
                offer.len()
            ),
        ),
        sip(
            B,
            A,
            format!(
                "SIP/2.0 200 OK\r\n{via}{from}{to}{cid}CSeq: 1 INVITE\r\n\
                 Contact: <sip:b@10.0.0.2>\r\nContent-Type: application/sdp\r\n\
                 Content-Length: {}\r\n\r\n{answer}",
                answer.len()
            ),
        ),
        sip(
            A,
            B,
            format!(
                "ACK sip:b@10.0.0.2 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to}{cid}\
                 CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
            ),
        ),
    ];
    for seq in 0u16..20 {
        let mut rtp = vec![0x80, 0x00];
        rtp.extend_from_slice(&seq.to_be_bytes());
        rtp.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
        rtp.extend_from_slice(&0x58f3_3deau32.to_be_bytes());
        rtp.extend_from_slice(&[0xff; 160]);
        frames.push(udp_frame(A, B, 20000, 30000, &rtp));
    }
    frames.push(udp_frame(A, B, 20001, 30001, CAPTURED_SR_SDES));
    frames.push(udp_frame(B, A, 30001, 20001, RECEIVER_REPORT));
    // A report between two hosts no SDP in this capture named.
    frames.push(udp_frame(
        [10, 9, 9, 9],
        [10, 9, 9, 8],
        40001,
        40003,
        RECEIVER_REPORT,
    ));
    frames.push(sip(
        A,
        B,
        format!(
            "BYE sip:b@10.0.0.2 SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}{to}{cid}\
             CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
        ),
    ));
    frames.push(sip(
        B,
        A,
        format!("SIP/2.0 200 OK\r\n{via}{from}{to}{cid}CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"),
    ));
    frames
}

/// Run `sipnab -N -I <capture> --hep-send` at a collector this test owns and
/// return every datagram that reached it, parsed.
fn forward_capture() -> Result<Vec<HepPacket>, TestError> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let pcap = dir.path().join("rtcp-call.pcap");
    write_pcap(&pcap, &capture()).map_err(|e| format!("write the capture: {e}"))?;

    let collector =
        UdpSocket::bind(("127.0.0.1", 0)).map_err(|e| format!("bind loopback collector: {e}"))?;
    let port = collector
        .local_addr()
        .map_err(|e| format!("collector addr: {e}"))?
        .port();
    collector
        .set_read_timeout(Some(test_timeout(5)))
        .map_err(|e| format!("collector read timeout: {e}"))?;
    let (tx, rx) = mpsc::channel();
    let drain = thread::spawn(move || {
        let mut buf = [0u8; 65535];
        let mut got = Vec::new();
        while let Ok(n) = collector.recv(&mut buf) {
            got.push(buf[..n].to_vec());
        }
        let _ = tx.send(got);
    });

    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I"])
        .arg(&pcap)
        .args(["--hep-send", &format!("127.0.0.1:{port}"), "--no-cli-print"])
        .env("SIPNAB_LOG", "warn")
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("run sipnab --hep-send: {e}"))?;
    assert!(
        out.status.success(),
        "sipnab exited {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let datagrams = rx
        .recv_timeout(test_timeout(20))
        .map_err(|e| format!("the collector thread reports: {e}"))?;
    drain
        .join()
        .map_err(|e| format!("join the collector thread: {e:?}"))?;
    let mut parsed = Vec::with_capacity(datagrams.len());
    for d in &datagrams {
        parsed.push(
            parse_hep(d).map_err(|e| format!("every datagram is HEP the parser reads: {e:?}"))?,
        );
    }
    Ok(parsed)
}

/// The whole contract in one run, since each assertion is about the same
/// forwarded capture: type 5 is heplify's JSON and carries the call's
/// Call-ID; RTCP no SDP explains is not sent; SIP still goes, without a
/// correlation chunk; RTP never goes.
#[test]
fn hep_send_forwards_rtcp_as_json_carrying_the_call_id() -> Result<(), TestError> {
    let got = forward_capture()?;

    let rtcp: Vec<&HepPacket> = got
        .iter()
        .filter(|p| p.protocol == HepProtocol::Rtcp)
        .collect();
    assert_eq!(
        rtcp.len(),
        2,
        "both of the call's reports, and not the stranger's, are forwarded: {:?}",
        rtcp.iter()
            .map(|p| (p.src_port, p.dst_port))
            .collect::<Vec<_>>()
    );
    for p in &rtcp {
        assert_eq!(
            p.correlation_id.as_deref(),
            Some(CALL_ID),
            "a type 5 report from port {} carries the wrong correlation ID",
            p.src_port
        );
        assert!(
            [20001, 30001].contains(&p.src_port),
            "a report from port {} is not the call's",
            p.src_port
        );
    }

    let sr = rtcp
        .iter()
        .find(|p| p.src_port == 20001)
        .ok_or("the sender report")?;
    let body: serde_json::Value =
        serde_json::from_slice(&sr.payload).map_err(|e| format!("the type 5 body is JSON: {e}"))?;
    assert_eq!(body["type"], 200);
    assert_eq!(body["ssrc"], 0x58f3_3dea_u32);
    assert_eq!(body["sender_information"]["packets"], 749);
    assert_eq!(body["sender_information"]["octets"], 117_455);
    assert_eq!(body["report_blocks"][0]["source_ssrc"], 0xd2bd_4e3e_u32);

    let rr = rtcp
        .iter()
        .find(|p| p.src_port == 30001)
        .ok_or("the receiver report")?;
    let body: serde_json::Value =
        serde_json::from_slice(&rr.payload).map_err(|e| format!("the type 5 body is JSON: {e}"))?;
    assert_eq!(body["type"], 201);
    assert_eq!(body["report_blocks"][0]["packets_lost"], 2);
    assert_eq!(body["report_blocks"][0]["ia_jitter"], 37);

    let sip: Vec<&HepPacket> = got
        .iter()
        .filter(|p| p.protocol == HepProtocol::Sip)
        .collect();
    assert_eq!(sip.len(), 5, "INVITE, 200, ACK, BYE, 200");
    assert!(
        sip.iter().all(|p| p.correlation_id.is_none()),
        "SIP is sent without a correlation chunk, as heplify sends it"
    );

    assert_eq!(
        got.len(),
        rtcp.len() + sip.len(),
        "something other than the call's SIP and RTCP was forwarded (RTP?): {:?}",
        got.iter()
            .map(|p| (p.protocol, p.src_port, p.dst_port))
            .collect::<Vec<_>>()
    );
    Ok(())
}
