// SPDX-License-Identifier: MIT OR Apache-2.0

//! An AMR-WB stream reads the same on every surface an operator has open.
//!
//! # The gap this closes
//!
//! `score_amr_wb` and the three `StreamSummary` fields shipped first, which
//! gave REST, MCP and the JSON save a wideband MOS for free — they all project
//! through that one type. The terminal does not. `render_stream_detail` reads
//! the stream directly and computed only the narrowband figure, so an operator
//! watching the TUI saw a G.107 score for an AMR-WB call while the REST
//! response beside it carried `MOS_CQEW` on the G.107.1 scale. Two doors, two
//! numbers, one stream.
//!
//! # Why the stream is built through the real path
//!
//! The mode is not on the codec name. It comes from the AMR payload headers,
//! and only after an `a=fmtp` line pins the packing — a stream whose packing
//! nobody declared reads no frame types at all, deliberately, because
//! bandwidth-efficient and octet-aligned put the frame type in different bits.
//! So this offers SDP and sends payloads rather than assigning fields: a test
//! that set `amr_frame_types_seen` by hand would pass over a pipeline that
//! never fills it.

#![cfg(all(feature = "tui", feature = "native"))]

use chrono::{DateTime, TimeZone, Utc};
use sipnab::capture::parse::{InputOrigin, ParsedPacket, TransportProto};
use sipnab::rtp::parser::RtpHeader;
use sipnab::rtp::stream::StreamKey;
use sipnab::rtp::stream_store::StreamStore;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const SSRC: u32 = 0x0BAD_F00D;
const PT: u8 = 96;

fn ts(ms: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000, 0)
        .single()
        .expect("a fixed timestamp")
        + chrono::TimeDelta::milliseconds(ms)
}

fn src_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}

fn key() -> StreamKey {
    StreamKey {
        ssrc: SSRC,
        src: SocketAddr::new(src_ip(), 20000),
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
    }
}

/// One octet-aligned AMR frame of type `ft`, RFC 4867 §4.4.
///
/// Byte 0 is the payload header (CMR in the top nibble). Byte 1 is the single
/// table-of-contents entry: `F` clear because there is one frame, then the
/// frame type, then the quality bit.
fn amr_payload(ft: u8) -> Vec<u8> {
    let mut p = vec![0xF0]; // CMR 15 = no mode request
    p.push(((ft & 0x0F) << 3) | 0x04);
    p.extend_from_slice(&[0x00; 60]);
    p
}

fn packet(seq: u16, at: DateTime<Utc>, ft: u8) -> ParsedPacket {
    let mut payload = vec![0x80, PT];
    payload.extend_from_slice(&seq.to_be_bytes());
    payload.extend_from_slice(&(u32::from(seq) * 320).to_be_bytes());
    payload.extend_from_slice(&SSRC.to_be_bytes());
    payload.extend_from_slice(&amr_payload(ft));
    ParsedPacket {
        frame_bytes: None,
        frame: None,
        timestamp: at,
        src_addr: src_ip(),
        dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: 20000,
        dst_port: 30000,
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

fn header(seq: u16) -> RtpHeader {
    RtpHeader {
        version: 2,
        padding: false,
        extension: false,
        csrc_count: 0,
        marker: false,
        payload_type: PT,
        sequence: seq,
        timestamp: u32::from(seq) * 320,
        ssrc: SSRC,
        payload_offset: 12,
    }
}

/// A store holding one AMR-WB stream whose payloads all pinned mode `ft`.
///
/// The SDP is offered first so the packing is known before the first payload
/// arrives, which is the order a real capture produces: the INVITE precedes
/// the media.
fn store_with_amr_wb(codec: &str, ft: u8) -> StreamStore {
    let sdp = format!(
        "v=0\r\n\
         o=- 0 0 IN IP4 10.0.0.1\r\n\
         s=-\r\n\
         c=IN IP4 10.0.0.1\r\n\
         t=0 0\r\n\
         m=audio 20000 RTP/AVP {PT}\r\n\
         a=rtpmap:{PT} {codec}/16000/1\r\n\
         a=fmtp:{PT} octet-align=1\r\n"
    );
    let session = sipnab::sip::sdp::parse_sdp(sdp.as_bytes()).expect("the fixture SDP parses");
    let media = session
        .media
        .first()
        .expect("the fixture has one media description");

    let mut store = StreamStore::new(16);
    store.link_to_dialog_with_sdp(src_ip(), 20000, "call-1", media);
    for seq in 0u16..8 {
        let at = ts(i64::from(seq) * 20);
        store.process_rtp(&packet(seq, at, ft), &header(seq), at);
    }
    store
}

/// Render the stream-detail pane to text, the way an operator sees it.
fn pane(store: &StreamStore) -> String {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use sipnab::tui::Theme;
    use sipnab::tui::stream_detail::{StreamDetailDisplay, render_stream_detail};

    let theme = Theme::default();
    let mut terminal = Terminal::new(TestBackend::new(140, 50)).expect("test terminal");
    terminal
        .draw(|frame| {
            let area = frame.area();
            render_stream_detail(
                frame,
                area,
                &key(),
                store,
                0,
                &StreamDetailDisplay {
                    declared_one_way_delay_ms: None,
                    theme: &theme,
                    resolver: &sipnab::names::NameResolver::new(),
                    name_mode: sipnab::names::NameMode::Off,
                    quality_bands: &sipnab::rtp::bands::QualityBands::default(),
                },
            );
        })
        .expect("render");
    let buf = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "));
        }
        out.push('\n');
    }
    out
}

/// The fixture reaches the pipeline, not just the test.
///
/// Every assertion below is about what the pane shows for an AMR-WB stream
/// with a pinned mode. If the SDP link or the payload decode silently failed,
/// the stream would be an ordinary one with no mode and the wideband
/// assertions would report the absence of a feature rather than a broken
/// fixture.
#[test]
fn the_fixture_really_pins_a_mode() {
    let store = store_with_amr_wb("AMR-WB", 2);
    let stream = store.get(&key()).expect("the stream exists");
    assert_eq!(stream.codec.as_deref(), Some("AMR-WB"));
    assert_eq!(
        stream.amr_mode_kbps(),
        Some(12.65),
        "frame type 2 is 12.65 kbit/s; a None here means the packing was never \
         pinned or the payload never decoded"
    );
}

/// The terminal shows the wideband score, and says which scale it is on.
#[test]
fn the_stream_detail_pane_shows_the_wideband_score() {
    let screen = pane(&store_with_amr_wb("AMR-WB", 2));
    assert!(
        screen.contains("MOS_CQEW"),
        "the pane does not name the wideband scale, so its number reads as a \
         G.107 one:\n{screen}"
    );
    assert!(
        screen.contains("12.65"),
        "the pane does not say which of the nine modes it scored, and they \
         span a full MOS point:\n{screen}"
    );
    assert!(
        screen.contains("monotic"),
        "the pane does not say which listening context it read, and the two \
         differ by 15 R-points at the lowest mode:\n{screen}"
    );
}

/// A G.711 call gets no wideband line at all.
///
/// Not "unavailable" — nobody attempted it. A row saying a wideband score is
/// unavailable for a narrowband codec would be true and useless, and would
/// train the eye to skip the field on the streams where it matters.
#[test]
fn a_narrowband_stream_gets_no_wideband_line() {
    let screen = pane(&store_with_amr_wb("PCMU", 2));
    assert!(
        !screen.contains("MOS_CQEW"),
        "a PCMU stream is showing a wideband row:\n{screen}"
    );
}

/// An AMR-WB mode with no published value says so in words.
///
/// The REST surface carries `unpublished_mode`; a terminal gets the sentence.
/// What both refuse to do is show a number, because there is none to show and
/// a blank reads as a bug rather than as a gap in the tables.
#[test]
fn an_unscorable_mode_says_why_rather_than_going_blank() {
    // Frame type 8 is 23.85 kbit/s under loss, which Table IV.4 does not
    // publish a Bpl,wb for at all. Built with loss by dropping sequence
    // numbers, so the refusal is the one a real lossy stream would get.
    let mut store = StreamStore::new(16);
    let sdp = format!(
        "v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n\
         m=audio 20000 RTP/AVP {PT}\r\na=rtpmap:{PT} AMR-WB/16000/1\r\n\
         a=fmtp:{PT} octet-align=1\r\n"
    );
    let session = sipnab::sip::sdp::parse_sdp(sdp.as_bytes()).expect("parses");
    store.link_to_dialog_with_sdp(
        src_ip(),
        20000,
        "call-1",
        session.media.first().expect("one media"),
    );
    // Sequence numbers 0, 2, 4 ... so half the packets are missing.
    for step in 0u16..8 {
        let seq = step * 2;
        let at = ts(i64::from(seq) * 20);
        store.process_rtp(&packet(seq, at, 8), &header(seq), at);
    }
    let screen = pane(&store);
    assert!(
        screen.contains("not computable under loss"),
        "a stream sipnab cannot score wideband must say why:\n{screen}"
    );
}
