// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-packet protocol-routing pipeline must be a testable library
//! API, not code buried in main.rs. These tests drive
//! `sipnab::pipeline::process_packet` directly: SIP packets land in the
//! dialog store, RTP/RTCP in the stream store, and the opt-out flags are
//! honored — without spawning the binary.
#![cfg(feature = "native")]

use chrono::Utc;
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use sipnab::capture::parse::{ParsedPacket, TransportProto};
use sipnab::pipeline::{self, PipelineOptions};
use sipnab::rtp::heuristic::RtpHeuristic;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;

/// Builds a UDP `ParsedPacket` between 10.0.0.1 and 10.0.0.2 with the given
/// payload and ports.
///
/// # Arguments
/// * `payload` — raw application payload bytes.
/// * `src_port` / `dst_port` — UDP ports stamped on the packet.
fn parsed(payload: Vec<u8>, src_port: u16, dst_port: u16) -> ParsedPacket {
    ParsedPacket {
        timestamp: Utc::now(),
        src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
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
        from_hep: false,
    }
}

/// A minimal parseable SIP INVITE with Call-ID `pipeline-1@test` and no body.
fn invite() -> Vec<u8> {
    b"INVITE sip:bob@example.com SIP/2.0\r\n\
      Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKpipe\r\n\
      From: <sip:alice@example.com>;tag=p1\r\n\
      To: <sip:bob@example.com>\r\n\
      Call-ID: pipeline-1@test\r\n\
      CSeq: 1 INVITE\r\n\
      Content-Length: 0\r\n\r\n"
        .to_vec()
}

/// An INVITE (Call-ID `pipeline-sdp@test`) carrying a one-media PCMU SDP offer
/// with a correct Content-Length.
fn invite_with_sdp() -> Vec<u8> {
    let sdp = b"v=0\r\n\
o=- 1 1 IN IP4 10.0.0.9\r\n\
s=call\r\n\
c=IN IP4 10.0.0.9\r\n\
t=0 0\r\n\
m=audio 40000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n";
    let mut msg = format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKpipesdp\r\n\
         From: <sip:alice@example.com>;tag=p2\r\n\
         To: <sip:bob@example.com>\r\n\
         Call-ID: pipeline-sdp@test\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n",
        sdp.len()
    )
    .into_bytes();
    msg.extend_from_slice(sdp);
    msg
}

/// A valid RTP packet (V=2, PT=0) with the given SSRC and sequence number and
/// a 160-byte payload.
fn rtp_packet(ssrc: u32, seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0x00];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 1]);
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(&[0xaa; 160]);
    p
}

/// In-process pipeline harness: fresh dialog/stream stores plus an RTP
/// heuristic, driven through `pipeline::process_packet`.
struct Harness {
    ds: Arc<RwLock<DialogStore>>,
    ss: Arc<RwLock<StreamStore>>,
    heuristic: RtpHeuristic,
}

impl Harness {
    /// Builds a harness with empty 100-capacity stores and a fresh heuristic.
    fn new() -> Self {
        Self {
            ds: Arc::new(RwLock::new(DialogStore::new(100, false))),
            ss: Arc::new(RwLock::new(StreamStore::new(100))),
            heuristic: RtpHeuristic::new(),
        }
    }

    /// Routes one parsed packet through `process_packet` into the harness
    /// stores with a default `MediaDecrypt`.
    fn run(&mut self, pp: &ParsedPacket, opts: &PipelineOptions) {
        let mut decrypt = pipeline::MediaDecrypt::default();
        pipeline::process_packet(
            pp,
            &self.ds,
            &self.ss,
            &mut self.heuristic,
            opts,
            &mut decrypt,
        );
    }
}

/// Processing an INVITE creates exactly one dialog (retrievable by Call-ID)
/// and leaves the stream store empty.
#[test]
fn sip_invite_lands_in_dialog_store() {
    let mut h = Harness::new();
    h.run(&parsed(invite(), 5060, 5060), &PipelineOptions::default());
    assert_eq!(h.ds.read().len(), 1, "INVITE must create a dialog");
    assert!(h.ds.read().get("pipeline-1@test").is_some());
    assert!(h.ss.read().is_empty(), "no RTP yet");
}

/// Processing an RTP packet creates exactly one stream and no dialogs.
#[test]
fn rtp_lands_in_stream_store() {
    let mut h = Harness::new();
    h.run(
        &parsed(rtp_packet(0xABCD, 1), 20000, 30000),
        &PipelineOptions::default(),
    );
    assert_eq!(h.ss.read().len(), 1, "RTP must create a stream");
    assert!(h.ds.read().is_empty());
}

/// With `no_rtp` set, an RTP packet leaves the stream store empty.
#[test]
fn no_rtp_option_skips_media() {
    let mut h = Harness::new();
    let opts = PipelineOptions {
        no_rtp: true,
        ..Default::default()
    };
    h.run(&parsed(rtp_packet(0xABCD, 1), 20000, 30000), &opts);
    assert!(h.ss.read().is_empty(), "no_rtp must skip RTP tracking");
}

/// With `no_dialog` set, an INVITE leaves the dialog store empty.
#[test]
fn no_dialog_option_skips_sip_tracking() {
    let mut h = Harness::new();
    let opts = PipelineOptions {
        no_dialog: true,
        ..Default::default()
    };
    h.run(&parsed(invite(), 5060, 5060), &opts);
    assert!(
        h.ds.read().is_empty(),
        "no_dialog must skip dialog tracking"
    );
}

/// `port_in_range` matches when either src or dst is inside the inclusive
/// range, including the degenerate single-port case.
#[test]
fn port_in_range_is_inclusive_and_either_direction() {
    assert!(pipeline::port_in_range(5060, 9999, (5060, 5061)));
    assert!(pipeline::port_in_range(9999, 5061, (5060, 5061)));
    assert!(!pipeline::port_in_range(5059, 5062, (5060, 5061)));
    // Degenerate single-port range
    assert!(pipeline::port_in_range(5060, 1, (5060, 5060)));
}

/// `is_rtcp_packet` requires an odd destination port and a full valid RTCP
/// header — even ports and truncated packets are rejected.
#[test]
fn rtcp_detection_requires_odd_port_and_valid_header() {
    // Valid RTCP SR header (V=2, PT=200) on an odd port
    let rtcp = vec![0x80, 200, 0, 6, 0, 0, 0, 1];
    assert!(pipeline::is_rtcp_packet(&rtcp, 30001));
    assert!(
        !pipeline::is_rtcp_packet(&rtcp, 30000),
        "even dst port is RTP, not RTCP"
    );
    assert!(!pipeline::is_rtcp_packet(&[0x80, 200], 30001), "too short");
}

/// Buffer-sharing contract: a SIP message parsed from a packet payload
/// must keep `raw` as a VIEW of that payload's buffer (refcounted), not
/// a second copy — and storing it in the dialog store must not copy
/// either.
#[test]
fn sip_message_raw_shares_payload_buffer() {
    let payload: bytes::Bytes = invite().into();
    let msg = sipnab::sip::parser::parse_sip_bytes(
        &payload,
        Utc::now(),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("INVITE parses");
    let range = payload.as_ptr_range();
    assert!(
        range.contains(&msg.raw.as_ptr()),
        "SipMessage.raw must view the payload buffer (zero-copy)"
    );
    assert!(
        msg.body.is_empty() || range.contains(&msg.body.as_ptr()),
        "SipMessage.body must view the payload buffer too"
    );
}

/// `extract_sdp_links` is the single source of truth for SDP→stream
/// association across the live, batch, and `--jobs` paths. It must return
/// one link tuple per addressable `m=` line — so an audio+video offer
/// yields both — using the session-level `c=` when a media has no own.
#[test]
fn extract_sdp_links_covers_all_media_streams() {
    let sdp = sipnab::sip::sdp::parse_sdp(
        b"v=0\r\n\
o=- 1 1 IN IP4 10.0.0.9\r\n\
s=call\r\n\
c=IN IP4 10.0.0.9\r\n\
t=0 0\r\n\
m=audio 40000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
m=video 40002 RTP/AVP 96\r\n\
a=rtpmap:96 H264/90000\r\n",
    )
    .expect("SDP parses");

    let links = pipeline::extract_sdp_links(&sdp, "av@test");
    assert_eq!(links.len(), 2, "both audio and video must be linked");

    let audio = links
        .iter()
        .find(|(_, p, _, _)| *p == 40000)
        .expect("audio");
    let video = links
        .iter()
        .find(|(_, p, _, _)| *p == 40002)
        .expect("video");
    assert_eq!(audio.0, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
    assert_eq!(audio.2, "av@test");
    assert_eq!(video.3.media_type, "video");
    assert!(
        video.3.rtpmap.iter().any(|r| r.encoding == "H264"),
        "cloned media must carry the video rtpmap"
    );
}

/// Media with no resolvable connection address (no media `c=`, no session
/// `c=`) is skipped rather than linked to a bogus endpoint.
#[test]
fn extract_sdp_links_skips_media_without_address() {
    let sdp = sipnab::sip::sdp::parse_sdp(
        b"v=0\r\n\
o=- 1 1 IN IP4 10.0.0.9\r\n\
s=call\r\n\
t=0 0\r\n\
m=audio 40000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n",
    )
    .expect("SDP parses");
    let links = pipeline::extract_sdp_links(&sdp, "noaddr@test");
    assert!(links.is_empty(), "no c= line ⇒ no links");
}

/// `classify_packet` is the lock-free core: it must classify a packet into the
/// right `PacketAction` without touching any store. These pin the mapping the
/// four routers all depend on (WS1).
#[test]
fn classify_maps_packets_to_actions() {
    use pipeline::{PacketAction, classify_packet};
    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions::default();
    let mut decrypt = pipeline::MediaDecrypt::default();

    // SIP INVITE → Sip action carrying the parsed message.
    let sip_pp = parsed(invite(), 5060, 5060);
    match classify_packet(&sip_pp, &mut heuristic, &opts, &mut decrypt) {
        PacketAction::Sip { msg, .. } => {
            assert_eq!(msg.call_id(), Some("pipeline-1@test"));
        }
        _ => panic!("SIP packet must classify as Sip"),
    }

    // RTP → Rtp action, no decrypted payload (unencrypted path never clones),
    // and detected by the RTP header — not the heuristic.
    let rtp_pp = parsed(rtp_packet(0x1234, 1), 40000, 40001);
    match classify_packet(&rtp_pp, &mut heuristic, &opts, &mut decrypt) {
        PacketAction::Rtp {
            hdr,
            decrypted_payload,
            via_heuristic,
        } => {
            assert_eq!(hdr.ssrc, 0x1234);
            assert!(decrypted_payload.is_none());
            assert!(!via_heuristic, "header-detected RTP is not heuristic");
        }
        _ => panic!("RTP packet must classify as Rtp"),
    }

    // Non-SIP, non-RTP payload → None.
    let junk = parsed(b"GET / HTTP/1.1\r\n\r\n".to_vec(), 80, 12345);
    assert!(matches!(
        classify_packet(&junk, &mut heuristic, &opts, &mut decrypt),
        PacketAction::None
    ));
}

/// `no_dialog` still classifies SIP as `Sip` (batch needs the message) but
/// with empty sdp_links; `no_rtp` classifies an RTP packet as `None`.
#[test]
fn classify_honors_opt_outs() {
    use pipeline::{PacketAction, classify_packet};
    let mut heuristic = RtpHeuristic::new();
    let mut decrypt = pipeline::MediaDecrypt::default();

    // no_dialog: a SIP packet still classifies as Sip — batch mode needs the
    // parsed message for counting/matching/output even when dialog tracking is
    // off — but SDP link extraction is skipped (nothing will consume it), and
    // the appliers gate the dialog-store write.
    let no_dialog = PipelineOptions {
        no_dialog: true,
        ..Default::default()
    };
    let sip_pp = parsed(invite_with_sdp(), 5060, 5060);
    match classify_packet(&sip_pp, &mut heuristic, &no_dialog, &mut decrypt) {
        PacketAction::Sip { msg, sdp_links } => {
            assert_eq!(msg.call_id(), Some("pipeline-sdp@test"));
            assert!(
                sdp_links.is_empty(),
                "no_dialog must skip SDP link extraction"
            );
        }
        _ => panic!("no_dialog SIP must still classify as Sip"),
    }

    // no_rtp: an RTP packet classifies as None.
    let no_rtp = PipelineOptions {
        no_rtp: true,
        ..Default::default()
    };
    let rtp_pp = parsed(rtp_packet(0x2222, 1), 40000, 40001);
    assert!(matches!(
        classify_packet(&rtp_pp, &mut heuristic, &no_rtp, &mut decrypt),
        PacketAction::None
    ));
}

/// SIP detection is gated by `sip_portrange` when set (the batch and `--jobs`
/// contract: `--portrange` filters signaling only, never media), and ungated
/// when `None` (the live-TUI contract, where BPF already filtered).
#[test]
fn classify_gates_sip_by_portrange() {
    use pipeline::{PacketAction, classify_packet};
    let mut heuristic = RtpHeuristic::new();
    let mut decrypt = pipeline::MediaDecrypt::default();
    let gated = PipelineOptions {
        sip_portrange: Some((5060, 5061)),
        ..Default::default()
    };

    // In range: classifies as Sip.
    let in_range = parsed(invite(), 5060, 9999);
    assert!(matches!(
        classify_packet(&in_range, &mut heuristic, &gated, &mut decrypt),
        PacketAction::Sip { .. }
    ));

    // Out of range: the SIP branch is skipped entirely (text payload then
    // fails RTP/RTCP detection → None).
    let out_of_range = parsed(invite(), 9998, 9999);
    assert!(matches!(
        classify_packet(&out_of_range, &mut heuristic, &gated, &mut decrypt),
        PacketAction::None
    ));

    // Ungated (None): any port classifies as Sip.
    let ungated = PipelineOptions::default();
    let any_port = parsed(invite(), 9998, 9999);
    assert!(matches!(
        classify_packet(&any_port, &mut heuristic, &ungated, &mut decrypt),
        PacketAction::Sip { .. }
    ));
}

/// Heuristically-discovered RTP (payload that fails the strict `is_rtp_packet`
/// pre-filter but is promoted by the consecutive-packet heuristic) must be
/// flagged `via_heuristic`, so appliers can distinguish it (batch skips DTMF /
/// quality events for heuristic streams).
#[test]
fn classify_flags_heuristic_rtp() {
    use pipeline::{PacketAction, classify_packet};
    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions::default();
    let mut decrypt = pipeline::MediaDecrypt::default();

    // PT 72 is rejected by `is_rtp_packet` (RTCP SR collision window) but
    // accepted by the header parser — exactly the heuristic's territory.
    // Three consecutive incrementing packets on an even dst port promote.
    let mut promoted = 0u32;
    for seq in 1u16..=4 {
        let mut p = vec![0x80, 72];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 1]);
        p.extend_from_slice(&0xFEEDu32.to_be_bytes());
        p.extend_from_slice(&[0xaa; 60]);
        let pp = parsed(p, 41000, 42000);
        match classify_packet(&pp, &mut heuristic, &opts, &mut decrypt) {
            PacketAction::Rtp {
                hdr, via_heuristic, ..
            } => {
                assert!(via_heuristic, "PT-72 flow is heuristic-detected");
                assert_eq!(hdr.ssrc, 0xFEED);
                promoted += 1;
            }
            PacketAction::None => {}
            _ => panic!("unexpected classification for heuristic RTP"),
        }
    }
    assert!(
        promoted > 0,
        "the consecutive-packet heuristic must promote this flow"
    );
}

/// A TLS-decrypted synthetic packet (transport stamped `Tls` by the batch
/// decrypt glue) classifies as Sip carrying that transport — and never falls
/// into the UDP-only media path.
#[test]
fn classify_carries_tls_transport() {
    use pipeline::{PacketAction, classify_packet};
    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions::default();
    let mut decrypt = pipeline::MediaDecrypt::default();

    let mut pp = parsed(invite(), 5061, 5061);
    pp.transport = TransportProto::Tls;
    match classify_packet(&pp, &mut heuristic, &opts, &mut decrypt) {
        PacketAction::Sip { msg, .. } => {
            assert_eq!(msg.transport, TransportProto::Tls);
        }
        _ => panic!("TLS-decrypted SIP must classify as Sip"),
    }
}
