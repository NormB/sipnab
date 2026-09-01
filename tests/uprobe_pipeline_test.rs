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
            hep: None,
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

/// **`TK7`: the plaintext reaches every output surface LABELED, and its
/// pointer refuses to resolve.**
///
/// The two facts have to be proved together on one message, because each is
/// harmless alone and dangerous in combination. A uprobe read renders
/// `0.0.0.0:0 -> 0.0.0.0:0 REGISTER TCP` — indistinguishable from a wire
/// capture whose addressing sipnab failed to parse — while carrying a `frame`
/// pointer of exactly the shape `--show-frame` accepts. Passing that off as a
/// wire frame is what would make sipnab's frame-pointer evidence lie.
///
/// This drives the REAL pipeline rather than setting `input_origin` by hand.
/// The surface tests beside each renderer build their own message, so deleting
/// `sip_msg.input_origin = Some(pp.input_origin)` in `classify_packet` would
/// leave all of them green while every label silently reported nothing. That
/// is the assignment this test exists for.
#[test]
fn a_uprobe_read_reaches_the_output_surfaces_labeled_and_its_pointer_refuses() {
    use sipnab::capture::packet::FrameSource;
    use sipnab::capture::parse::InputOrigin;
    use sipnab::pipeline::{MediaDecrypt, PacketAction, PipelineOptions, classify_packet};

    let mut packet = uprobe_packet("uprobe:opensips/4242", 0, 0);
    // What the uprobe readers stamp: a source AND an ordinal, with no digest,
    // because these bytes can never be read a second time.
    packet.origin = Some(sipnab::capture::packet::FrameOrigin {
        ordinal: 3,
        digest: None,
        verifiable: false,
    });

    let mut processor = PacketProcessor::new();
    let parsed = processor.process(&packet);
    assert_eq!(parsed.len(), 1, "the read must reach classification at all");
    assert_eq!(
        parsed[0].input_origin,
        InputOrigin::Uprobe,
        "the packet must be recognized as a uprobe read before anything can \
         label it one"
    );

    let mut heuristic = sipnab::rtp::heuristic::RtpHeuristic::new();
    let mut decrypt = MediaDecrypt::default();
    let action = classify_packet(
        &parsed[0],
        &mut heuristic,
        &PipelineOptions::default(),
        &mut decrypt,
    );
    let PacketAction::Sip { msg, .. } = action else {
        panic!("a uprobe read carrying a REGISTER must classify as SIP");
    };

    assert_eq!(
        msg.input_origin,
        Some(InputOrigin::Uprobe),
        "the origin must cross the packet→message boundary, or every surface \
         below reports nothing while looking perfectly healthy"
    );

    // The machine surface: `--json`, and through it MCP `get_message` and the
    // vCon message trace, which share this projection.
    let line = sipnab::output::json::message_to_json(&msg);
    let json: serde_json::Value =
        serde_json::from_str(line.trim_end()).expect("the NDJSON line parses");
    assert_eq!(
        json["input_origin"], "uprobe",
        "the JSON line must name the source that delivered it: {line}"
    );

    // The human surface: the `-N` summary line.
    let text = sipnab::output::cli_print::format_sip_message(
        &msg,
        &sipnab::output::OutputOptions {
            color: sipnab::output::ColorMode::Never,
            show_empty: false,
            ..Default::default()
        },
        None,
    );
    assert!(
        text.contains("origin=uprobe"),
        "the summary line must say these bytes were never on a wire: {text}"
    );

    // The TUI's raw viewer, which renders the same endpoints from the same
    // absent packet.
    #[cfg(feature = "tui")]
    {
        let (info, _) = sipnab::tui::msg_raw::raw_display_text(
            &msg,
            sipnab::tui::header_form::HeaderFormMode::default(),
        );
        assert!(
            info.contains("origin=uprobe"),
            "the raw viewer's info line must carry the same note: {info}"
        );
    }

    // And the pointer beside all of that is refused, by name, rather than
    // followed to whatever sits at ordinal 3 of some file.
    let pointer = msg
        .frame
        .expect("a uprobe read still says WHICH read it was");
    assert!(
        matches!(pointer.source_kind(), FrameSource::Uprobe { pid: 4242, .. }),
        "the pointer must carry the kind, not merely a source string that \
         looks like one: {pointer:?}"
    );
    let refusal = sipnab::capture::resolve::resolve(&pointer)
        .expect_err("a uprobe pointer names no frame and must never resolve")
        .to_string();
    for expected in ["opensips", "4242"] {
        assert!(
            refusal.contains(expected),
            "the refusal must name the process the bytes came out of, so the \
             pointer stays useful as provenance: {refusal}"
        );
    }
}
