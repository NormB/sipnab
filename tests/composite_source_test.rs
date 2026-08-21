// SPDX-License-Identifier: MIT OR Apache-2.0

//! One process, two capture sources: a HEP mirror for signaling and the local
//! NIC for media (SRC1, `docs/design/simultaneous-capture-sources.md`).
//!
//! Raised by Dan Jenkins ([@danjenkins](https://github.com/danjenkins)) from
//! OpenSIPS deployment experience: when eCapture keylog extraction proves
//! fragile against a given daemon, OpenSIPS's own HEP mirror is a far more
//! robust way to obtain decrypted SIP — it is already plaintext at the source
//! and involves no key extraction at all. Taking it used to cost every RTP
//! stream, because `plan()` resolved the capture source through a single
//! if/else chain in which `-d` sits above `-L`, so `-d eth0 -L 0.0.0.0:9060`
//! bound no HEP socket and said nothing about it.
//!
//! # What these tests pin
//!
//! **Composition.** Both flags together must produce a source carrying BOTH
//! members, and the run must feed one channel from both.
//!
//! **Correlation, and its absence.** The dialog-to-stream binding is already
//! source-agnostic: it is keyed on the SDP media endpoint, a bare
//! `(IpAddr, u16)`, so a HEP-delivered INVITE populates the same map entry a
//! NIC-captured one would. These tests assert that it works ACROSS sources,
//! that it is order-independent, and — the tests that matter more — that a
//! non-match stays a non-match. A stream attributed to the wrong dialog is
//! worse than an unattributed one, because the wrong attribution arrives
//! looking like a measurement.
//!
//! **Refusals.** The combinations that would produce a wrong answer exit 2
//! with a message naming the reason, rather than silently dropping a source
//! the way `-d` + `-L` used to drop the listener.
#![cfg(feature = "native")]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use parking_lot::RwLock;
use sipnab::app::bootstrap;
use sipnab::capture::CaptureSource;
use sipnab::capture::PacketProcessor;
use sipnab::capture::packet::{Packet, PreParsed};
use sipnab::cli::Cli;
use sipnab::config::Config;
use sipnab::pipeline::{MediaDecrypt, PipelineOptions, process_packet};
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;

#[path = "support/pcap_build.rs"]
mod pcap_build;
use pcap_build::udp_frame;

/// UDP, as both the HEP-mirrored signaling and the media are.
const UDP: u8 = 17;

/// A real capture, because `plan()` resolves `-I` before returning.
const FIXTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// Parses `args` as if typed on a `sipnab` command line.
fn cli(args: &[&str]) -> Cli {
    let mut full = vec!["sipnab"];
    full.extend_from_slice(args);
    Cli::parse_from_args(full)
}

// ── The composite source ────────────────────────────────────────────────

/// `-d` and `-L` together must yield BOTH members, not the first one.
///
/// This is the defect SRC1 names: the chain resolved to one source by type,
/// `-d` sat above `-L`, and the listener evaporated with no diagnostic.
#[test]
fn a_live_device_and_a_hep_listener_compose_into_one_source() {
    let p = bootstrap::plan(
        &cli(&["-N", "-d", "eth9", "-L", "127.0.0.1:19060"]),
        &Config::default(),
    )
    .expect("plan");

    let members = match p.source {
        Some(CaptureSource::Composite(ref m)) => m,
        other => panic!("-d with -L must compose, got {other:?}"),
    };
    assert_eq!(
        members.len(),
        2,
        "exactly the two members named: {members:?}"
    );
    assert!(
        matches!(members[0], CaptureSource::Live { ref device } if device == "eth9"),
        "the NIC supplies media and must come first: {members:?}"
    );
    assert!(
        matches!(members[1], CaptureSource::Hep { ref bind_addr, .. } if bind_addr == "127.0.0.1:19060"),
        "the HEP listener must survive the chain: {members:?}"
    );
}

/// A device named in the CONFIG FILE composes exactly as `-d` does.
///
/// Both arms of the chain build the identical `CaptureSource::Live`, and
/// nothing downstream can see which one produced it. Composing only for the
/// flag would make the same invocation behave differently depending on where
/// the device name was written, which is a distinction with no mechanism
/// behind it.
#[test]
fn a_config_file_device_composes_with_a_hep_listener_too() {
    let mut config = Config::default();
    config.capture.device = Some("cfg0".into());

    let p = bootstrap::plan(&cli(&["-N", "-L", "127.0.0.1:19060"]), &config).expect("plan");
    let members = match p.source {
        Some(CaptureSource::Composite(ref m)) => m,
        other => panic!("a config device with -L must compose, got {other:?}"),
    };
    assert!(
        matches!(members[0], CaptureSource::Live { ref device } if device == "cfg0"),
        "{members:?}"
    );
    assert!(
        matches!(members[1], CaptureSource::Hep { .. }),
        "{members:?}"
    );
}

/// Each flag alone must be exactly what it was. A composite is what the PAIR
/// means, never what one of them means.
#[test]
fn either_flag_alone_still_resolves_to_a_single_source() {
    let p = bootstrap::plan(&cli(&["-N", "-d", "eth9"]), &Config::default()).expect("plan");
    assert!(
        matches!(p.source, Some(CaptureSource::Live { .. })),
        "-d alone is still one live source: {:?}",
        p.source
    );

    let p =
        bootstrap::plan(&cli(&["-N", "-L", "127.0.0.1:19060"]), &Config::default()).expect("plan");
    assert!(
        matches!(p.source, Some(CaptureSource::Hep { .. })),
        "-L alone is still one HEP source: {:?}",
        p.source
    );
}

// ── Refusals: the combinations that would produce a wrong answer ─────────

/// `-I` with `-L` is refused, and the message says why it is a SECURITY
/// refusal rather than a scheduling one.
///
/// File packets parse as `InputOrigin::Wire`, and the per-packet
/// scanner-kill gate admits `Wire` unconditionally. Today that conflation is
/// safe only because `TransmitPermit::for_source` refuses a `File` run
/// outright. Pair `File` with `Hep` and the source-level refusal disappears
/// while the per-packet gate waves file-origin packets through — sipnab
/// transmitting at historical third-party addresses.
#[test]
fn an_input_file_with_a_hep_listener_is_refused_with_the_security_reason() {
    let err = bootstrap::plan(
        &cli(&["-N", "-I", FIXTURE, "-L", "127.0.0.1:19060"]),
        &Config::default(),
    )
    .err()
    .expect("-I with -L must be refused, not silently resolved to the file");

    assert_eq!(err.exit_code, 2, "an argument refusal exits 2: {err:?}");
    let m = &err.message;
    assert!(m.contains("-I") && m.contains("-L"), "name both flags: {m}");
    assert!(
        m.contains("historical") || m.contains("third part"),
        "the refusal must state the security reason, not say \"unsupported\": {m}"
    );
}

/// `-O` alongside a composite is refused, and the message names `--hep-send`.
///
/// The two members disagree about the link type: live capture yields
/// `DLT_EN10MB`, while a HEP packet carries `link_type = 0` and a `data`
/// buffer holding the bare transport payload. Classic pcap refuses the second
/// member outright, and WHICH member gets refused depends on which packet
/// arrives first — so the run would fail non-deterministically. pcapng is
/// worse: it appends a second interface and writes bare SIP text as if it
/// were a frame of the declared link type.
#[test]
fn writing_a_capture_file_from_a_composite_is_refused() {
    // A unique directory per process: `plan()` never opens this path, but a
    // fixed one under /tmp is shared state two concurrent runs would collide
    // on, and a collision here would look like a flaky refusal.
    let dir = tempfile::tempdir().expect("temp dir");
    let out = dir.path().join("out.pcap");
    let out_s = out.to_string_lossy().to_string();

    let err = bootstrap::plan(
        &cli(&["-N", "-d", "eth9", "-L", "127.0.0.1:19060", "-O", &out_s]),
        &Config::default(),
    )
    .err()
    .expect("-O with a composite must be refused");

    assert_eq!(err.exit_code, 2, "{err:?}");
    assert!(err.message.contains("-O"), "name the flag: {}", err.message);
    assert!(
        err.message.contains("--hep-send"),
        "name the alternative for an operator who wanted the signaling \
         forwarded rather than written: {}",
        err.message
    );
}

/// `--multi-device` with `-L` is refused: composing a DEVICE LIST with a HEP
/// member is reasonable and belongs to stage three, not to this one.
#[test]
fn multi_device_with_a_hep_listener_is_refused() {
    let err = bootstrap::plan(
        &cli(&[
            "-N",
            "--multi-device",
            "-d",
            "eth9,eth8",
            "-L",
            "127.0.0.1:19060",
        ]),
        &Config::default(),
    )
    .err()
    .expect("--multi-device with -L must be refused");

    assert_eq!(err.exit_code, 2, "{err:?}");
    assert!(
        err.message.contains("--multi-device") && err.message.contains("-L"),
        "name both: {}",
        err.message
    );
}

// ── The correlation seam ────────────────────────────────────────────────

/// The Call-ID every correlation test keys on.
const CALL_ID: &str = "composite-src1@sipnab.test";

/// The media socket the HEP-delivered SDP advertises, and the one the
/// synthetic RTP actually flows to.
const MEDIA_IP: [u8; 4] = [198, 51, 100, 7];
const MEDIA_PORT: u16 = 20000;

/// The far end of the media flow, which the NIC also sees.
const PEER_IP: [u8; 4] = [198, 51, 100, 9];
const PEER_PORT: u16 = 20002;

/// An INVITE whose SDP advertises `ip:port` for `call_id`.
fn invite_with_sdp(call_id: &str, ip: [u8; 4], port: u16) -> Vec<u8> {
    let ip_s = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    let sdp = format!(
        "v=0\r\n\
         o=- 1 1 IN IP4 {ip_s}\r\n\
         s=-\r\n\
         c=IN IP4 {ip_s}\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=ptime:20\r\n"
    );
    format!(
        "INVITE sip:bob@example.net SIP/2.0\r\n\
         Via: SIP/2.0/UDP 203.0.113.1:5060;branch=z9hG4bK-{call_id}\r\n\
         From: <sip:alice@example.net>;tag=a1\r\n\
         To: <sip:bob@example.net>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {len}\r\n\
         \r\n\
         {sdp}",
        len = sdp.len()
    )
    .into_bytes()
}

/// A packet shaped exactly as `capture::hep::hep_to_packet` produces one:
/// pre-parsed addressing, `link_type = 0`, and a `hep:` source name — which
/// is what `InputOrigin::Hep` is derived from.
fn hep_packet(payload: Vec<u8>, capture_id: u32) -> Packet {
    Packet::with_pre_parsed(
        chrono::Utc::now(),
        payload,
        Some(format!("hep:{capture_id}@203.0.113.1:9060")),
        PreParsed {
            src_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
            src_port: 5060,
            dst_port: 5060,
            ip_protocol: UDP,
        },
    )
}

/// A minimal RTP packet: version 2, PCMU, no CSRCs, 160 bytes of payload.
fn rtp_payload(ssrc: u32, seq: u16, ts: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(12 + 160);
    p.push(0x80); // V=2, no padding, no extension, CC=0
    p.push(0x00); // M=0, PT=0 (PCMU)
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(&[0xFF; 160]);
    p
}

/// A packet shaped as the LIVE reader produces one: a real Ethernet frame
/// off a named device, so it parses as `InputOrigin::Wire`.
fn wire_rtp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, seq: u16) -> Packet {
    let frame = udp_frame(
        src,
        dst,
        sport,
        dport,
        &rtp_payload(0x0BADF00D, seq, 160 * u32::from(seq)),
    );
    let len = frame.len();
    Packet::with_source(
        chrono::Utc::now(),
        frame,
        len,
        len,
        Some(Arc::from("eth9")),
        1, // DLT_EN10MB
    )
}

/// The two stores plus the machinery `process_packet` needs, driven exactly
/// as the live path drives them.
struct Mixed {
    processor: PacketProcessor,
    dialogs: Arc<RwLock<DialogStore>>,
    streams: Arc<RwLock<StreamStore>>,
    heuristic: sipnab::rtp::heuristic::RtpHeuristic,
    opts: PipelineOptions,
}

impl Mixed {
    fn new() -> Self {
        Self {
            processor: PacketProcessor::new(),
            dialogs: Arc::new(RwLock::new(DialogStore::new(64, false))),
            streams: Arc::new(RwLock::new(StreamStore::new(64))),
            heuristic: sipnab::rtp::heuristic::RtpHeuristic::default(),
            opts: PipelineOptions {
                no_dialog: false,
                no_rtp: false,
                // None, as a live capture does: BPF already filtered.
                sip_portrange: None,
                quiet_bad_parse: true,
            },
        }
    }

    /// Feed one packet from EITHER source through the same pipeline the
    /// composite run feeds — which is the point: one channel, one consumer.
    fn feed(&mut self, pkt: &Packet) {
        for pp in self.processor.process(pkt) {
            process_packet(
                &pp,
                &self.dialogs,
                &self.streams,
                &mut self.heuristic,
                &self.opts,
                &mut MediaDecrypt::default(),
            );
        }
    }

    /// The Call-ID the one stream in the store is bound to, if any.
    fn only_stream_dialog(&self) -> Option<String> {
        let s = self.streams.read();
        let mut it = s.iter();
        let first = it.next().expect("exactly one stream was fed");
        assert!(it.next().is_none(), "this helper expects one stream");
        first.associated_dialog.clone()
    }

    fn stream_count(&self) -> usize {
        self.streams.read().iter().count()
    }

    fn dialog_count(&self) -> usize {
        self.dialogs.read().iter().count()
    }
}

/// **The happy path.** A HEP-delivered INVITE and NIC-captured RTP for the
/// same call bind, with no new correlation code: the SDP endpoint map is
/// keyed on `(IpAddr, u16)` and never consults the capture source.
#[test]
fn hep_signaling_binds_the_stream_the_nic_captured() {
    let mut m = Mixed::new();
    m.feed(&hep_packet(
        invite_with_sdp(CALL_ID, MEDIA_IP, MEDIA_PORT),
        2001,
    ));
    for seq in 0..5u16 {
        m.feed(&wire_rtp(PEER_IP, PEER_PORT, MEDIA_IP, MEDIA_PORT, seq));
    }

    assert_eq!(m.dialog_count(), 1, "the HEP INVITE must build a dialog");
    assert_eq!(m.stream_count(), 1, "the wire RTP must build a stream");
    assert_eq!(
        m.only_stream_dialog().as_deref(),
        Some(CALL_ID),
        "a stream the NIC captured must bind to the dialog HEP delivered"
    );
}

/// **Reverse order.** A HEP hop is a network delay, so RTP captured locally
/// can reach the pipeline before the INVITE that describes it. The binding is
/// order-independent by construction — `resolve_from_sdp` handles SDP-then-RTP
/// and the endpoint sweep handles RTP-then-SDP — and this pins that it stays
/// so once two sources make the inversion ordinary rather than exotic.
#[test]
fn rtp_arriving_before_the_hep_invite_still_binds() {
    let mut m = Mixed::new();
    for seq in 0..5u16 {
        m.feed(&wire_rtp(PEER_IP, PEER_PORT, MEDIA_IP, MEDIA_PORT, seq));
    }
    assert_eq!(
        m.only_stream_dialog(),
        None,
        "before the INVITE arrives the stream must claim no dialog"
    );

    m.feed(&hep_packet(
        invite_with_sdp(CALL_ID, MEDIA_IP, MEDIA_PORT),
        2001,
    ));
    assert_eq!(
        m.only_stream_dialog().as_deref(),
        Some(CALL_ID),
        "the late INVITE must sweep the endpoint index and claim the stream"
    );
}

/// **No false binding.** A HEP dialog advertising one socket must not claim a
/// stream on a different one. This is the test that fails if someone
/// "improves" cross-source matching with a timing fallback: on a busy proxy
/// dozens of calls answer per second and every one starts media, so "the
/// stream started 40 ms after the 200 OK" is a coincidence detector.
#[test]
fn a_hep_dialog_does_not_claim_a_stream_on_a_different_socket() {
    let mut m = Mixed::new();
    // The mirror says media is at MEDIA_PORT; the NIC sees it somewhere else,
    // which is what a media relay rewriting the SDP produces.
    m.feed(&hep_packet(
        invite_with_sdp(CALL_ID, MEDIA_IP, MEDIA_PORT),
        2001,
    ));
    for seq in 0..5u16 {
        m.feed(&wire_rtp(PEER_IP, PEER_PORT, MEDIA_IP, 30000, seq));
    }

    assert_eq!(m.dialog_count(), 1, "the dialog still exists");
    assert_eq!(m.stream_count(), 1, "the stream still exists");
    assert_eq!(
        m.only_stream_dialog(),
        None,
        "an unmatched stream must stay ORPHANED. A stream attributed to the \
         wrong dialog is worse than an unattributed one, because the wrong \
         attribution arrives looking like a measurement"
    );
}

/// **A HEP dialog whose media never arrives.** Definite rather than silent:
/// the dialog exists and NO stream is fabricated for it. A stream is only
/// ever created from real RTP packets, and there are none.
#[test]
fn a_hep_dialog_with_no_local_media_creates_no_stream() {
    let mut m = Mixed::new();
    m.feed(&hep_packet(
        invite_with_sdp(CALL_ID, MEDIA_IP, MEDIA_PORT),
        2001,
    ));

    assert_eq!(m.dialog_count(), 1, "the HEP dialog is present");
    assert_eq!(
        m.stream_count(),
        0,
        "an SDP endpoint is a promise about media, not evidence of it"
    );
}

/// **A local stream with no HEP dialog.** Orphaned immediately, with no
/// timeout to wait out and no dialog invented for it.
#[test]
fn wire_media_with_no_hep_dialog_is_orphaned() {
    let mut m = Mixed::new();
    for seq in 0..5u16 {
        m.feed(&wire_rtp(PEER_IP, PEER_PORT, MEDIA_IP, MEDIA_PORT, seq));
    }

    assert_eq!(m.dialog_count(), 0, "no signaling arrived");
    assert_eq!(m.stream_count(), 1);
    assert_eq!(m.only_stream_dialog(), None, "an orphan must say so");
    assert_eq!(
        m.streams.read().orphaned_count(),
        1,
        "and must be counted as one"
    );
}

/// **Wrong-node collision (F2), pinned as it behaves today.**
///
/// `sdp_endpoints` is keyed on `(IpAddr, u16)` with no node dimension, so two
/// HEP senders can both claim `198.51.100.7:20000`. The last offer wins and
/// the stream binds to it. RFC 1918 space repeats across sites, so this is
/// ordinary rather than exotic — and it is the reason stage one is documented
/// for ONE HEP node. This test pins the current answer so that adding the
/// node dimension shows up as a CHANGE rather than as a silent improvement
/// nobody can date.
#[test]
fn two_hep_nodes_advertising_one_socket_collide_and_the_last_offer_wins() {
    let mut m = Mixed::new();
    m.feed(&hep_packet(
        invite_with_sdp("node-a-call@site1", MEDIA_IP, MEDIA_PORT),
        1,
    ));
    m.feed(&hep_packet(
        invite_with_sdp("node-b-call@site2", MEDIA_IP, MEDIA_PORT),
        2,
    ));
    for seq in 0..5u16 {
        m.feed(&wire_rtp(PEER_IP, PEER_PORT, MEDIA_IP, MEDIA_PORT, seq));
    }

    assert_eq!(m.dialog_count(), 2, "both nodes' dialogs exist");
    assert_eq!(
        m.only_stream_dialog().as_deref(),
        Some("node-b-call@site2"),
        "TODAY the last offer wins. This is a known wrong-attribution mode \
         (F2), confined by documenting stage one as single-node; when the \
         node dimension lands this assertion must be updated deliberately"
    );
}

// ── Stage 2: provenance and honest limits ───────────────────────────────
//
// Stage one made the two sources run together. Nothing downstream could then
// say which of them produced any given fact, which is the substrate the next
// item (SRC2) needs: HEP reports what the proxy BELIEVES it did, the wire
// reports what actually left the box, and their DISAGREEMENT is the finding.
// A disagreement between two facts is only visible once each fact knows where
// it came from.

/// The same HEP packet as [`hep_packet`], at a chosen capture-clock time.
///
/// Timestamps are a parameter here because the endpoint TTL is measured on
/// the CAPTURE clock, not on wall time: a run replaying a capture must reach
/// the same answer as the live run that produced it.
fn hep_packet_at(payload: Vec<u8>, capture_id: u32, ts: chrono::DateTime<chrono::Utc>) -> Packet {
    let mut p = hep_packet(payload, capture_id);
    p.timestamp = ts;
    p
}

/// A SIP message the NIC captured itself: a real Ethernet frame on 5060, so
/// it parses as `InputOrigin::Wire` exactly as a live-captured INVITE does.
fn wire_sip(payload: &[u8], ts: chrono::DateTime<chrono::Utc>) -> Packet {
    let frame = udp_frame([203, 0, 113, 1], [203, 0, 113, 2], 5060, 5060, payload);
    let len = frame.len();
    let mut p = Packet::with_source(ts, frame, len, len, Some(Arc::from("eth9")), 1);
    p.timestamp = ts;
    p
}

/// [`wire_rtp`] at a chosen capture-clock time.
fn wire_rtp_at(
    src: [u8; 4],
    sport: u16,
    dst: [u8; 4],
    dport: u16,
    seq: u16,
    ts: chrono::DateTime<chrono::Utc>,
) -> Packet {
    let mut p = wire_rtp(src, sport, dst, dport, seq);
    p.timestamp = ts;
    p
}

/// A fixed capture-clock origin, so every timing assertion below is a
/// difference between two stated instants rather than a race with `now()`.
fn t0() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap_or_default()
}

/// **An SDP endpoint older than the TTL does not claim a new stream (F3).**
///
/// `sdp_endpoints` was bounded by insertion order with oldest-out eviction and
/// no notion of age, which was sized for a minutes-long pcap read. This
/// feature's deployment shape is a process running for days beside a media
/// gateway that cycles a finite RTP port range, so a stale entry can outlive
/// its call and claim the next stream on that socket — a wrong attribution,
/// which arrives looking like a measurement.
///
/// Both directions asserted: fresh still binds, stale does not.
#[test]
fn an_sdp_endpoint_older_than_the_ttl_does_not_claim_a_new_stream() {
    // Control: within the TTL the binding is unchanged.
    let mut fresh = Mixed::new();
    fresh.feed(&hep_packet_at(
        invite_with_sdp(CALL_ID, MEDIA_IP, MEDIA_PORT),
        2001,
        t0(),
    ));
    for seq in 0..5u16 {
        fresh.feed(&wire_rtp_at(
            PEER_IP,
            PEER_PORT,
            MEDIA_IP,
            MEDIA_PORT,
            seq,
            t0() + chrono::Duration::seconds(10),
        ));
    }
    assert_eq!(
        fresh.only_stream_dialog().as_deref(),
        Some(CALL_ID),
        "media 10s after the offer is the ordinary case and must still bind"
    );

    // The failure this exists to prevent: media on the same socket long after
    // the offer that named it, which on a port-cycling gateway is a DIFFERENT
    // call.
    let mut stale = Mixed::new();
    stale.feed(&hep_packet_at(
        invite_with_sdp(CALL_ID, MEDIA_IP, MEDIA_PORT),
        2001,
        t0(),
    ));
    for seq in 0..5u16 {
        stale.feed(&wire_rtp_at(
            PEER_IP,
            PEER_PORT,
            MEDIA_IP,
            MEDIA_PORT,
            seq,
            t0() + chrono::Duration::seconds(3600),
        ));
    }
    assert_eq!(
        stale.stream_count(),
        1,
        "the stream still exists — the TTL withholds an attribution, it does \
         not discard media"
    );
    assert_eq!(
        stale.only_stream_dialog(),
        None,
        "an offer an hour stale must not name a new stream's dialog. A media \
         gateway cycles a finite port range, so the next call on that socket \
         would inherit the previous call's identity"
    );
}

/// **The cross-source flag marks a stream bound ACROSS sources, and only
/// one.**
///
/// A cross-source binding is a weaker tie than a same-source one: the SDP came
/// from what the proxy said it did, the media from what the NIC saw, and the
/// two can disagree. The output must say so rather than present both as
/// "associated", which is what lets an operator discount a suspicious
/// attribution instead of trusting it.
///
/// The second half is the half that can rot: a flag that is always set says
/// nothing at all.
#[test]
fn the_cross_source_flag_marks_only_a_stream_bound_across_sources() {
    // HEP signaling, wire media — the deployment this whole feature is for.
    let mut across = Mixed::new();
    across.feed(&hep_packet_at(
        invite_with_sdp(CALL_ID, MEDIA_IP, MEDIA_PORT),
        2001,
        t0(),
    ));
    for seq in 0..5u16 {
        across.feed(&wire_rtp_at(
            PEER_IP,
            PEER_PORT,
            MEDIA_IP,
            MEDIA_PORT,
            seq,
            t0() + chrono::Duration::seconds(1),
        ));
    }
    let flagged = {
        let s = across.streams.read();
        let st = s.iter().next().expect("one stream").clone();
        assert_eq!(
            st.associated_dialog.as_deref(),
            Some(CALL_ID),
            "the binding itself must still happen"
        );
        st.dialog_bound_across_sources()
    };
    assert!(
        flagged,
        "a stream whose media came off the NIC and whose dialog came over HEP \
         is a weaker tie than a same-source one and must say so"
    );

    // Same INVITE, captured on the NIC instead. Same binding, no flag.
    let mut within = Mixed::new();
    within.feed(&wire_sip(
        &invite_with_sdp(CALL_ID, MEDIA_IP, MEDIA_PORT),
        t0(),
    ));
    for seq in 0..5u16 {
        within.feed(&wire_rtp_at(
            PEER_IP,
            PEER_PORT,
            MEDIA_IP,
            MEDIA_PORT,
            seq,
            t0() + chrono::Duration::seconds(1),
        ));
    }
    let same_source = {
        let s = within.streams.read();
        let st = s.iter().next().expect("one stream").clone();
        assert_eq!(
            st.associated_dialog.as_deref(),
            Some(CALL_ID),
            "a same-source run must bind exactly as before"
        );
        st.dialog_bound_across_sources()
    };
    assert!(
        !same_source,
        "signaling and media from the SAME source must not be flagged; a flag \
         that is always set carries no information"
    );

    // Reverse order, which a HEP hop makes ordinary rather than exotic: the
    // media arrives first and the mirrored INVITE sweeps the endpoint index
    // afterwards. That is a SECOND place the binding is made, and a flag
    // written at only one of them would report a cross-source tie as a
    // same-source one exactly when the network is slowest.
    let mut reversed = Mixed::new();
    for seq in 0..5u16 {
        reversed.feed(&wire_rtp_at(
            PEER_IP,
            PEER_PORT,
            MEDIA_IP,
            MEDIA_PORT,
            seq,
            t0(),
        ));
    }
    reversed.feed(&hep_packet_at(
        invite_with_sdp(CALL_ID, MEDIA_IP, MEDIA_PORT),
        2001,
        t0() + chrono::Duration::seconds(1),
    ));
    let late_bind = {
        let s = reversed.streams.read();
        let st = s.iter().next().expect("one stream").clone();
        assert_eq!(
            st.associated_dialog.as_deref(),
            Some(CALL_ID),
            "the late INVITE must still claim the stream"
        );
        st.dialog_bound_across_sources()
    };
    assert!(
        late_bind,
        "a binding made by the endpoint sweep must record its source exactly \
         as one made at stream creation does"
    );
}

/// **A live-captured stream has a resolvable `first_frame`.**
///
/// `Packet::frame_ref` requires BOTH a source name and an ordinal, and the
/// live reader stamped only the name — so in a mixed run every `first_frame`
/// was `None` and no stream could name the packet it began at. No test could
/// assert this before stage two, because there was nothing to assert.
///
/// "Resolvable" here means the pointer is well-formed and round-trips through
/// the text form an operator types. A live frame's bytes are gone the instant
/// they are read, so nothing can hand them back and `resolve` refusing is the
/// honest answer rather than a defect — which is also why the stamp carries no
/// digest.
///
/// **What this does not reach.** `capture_live_fanout` needs a real device and
/// CAP_NET_RAW, so no test drives its loop. This exercises the two production
/// pieces the loop composes — the counter it holds and the propagation from
/// packet to stream — and the one line joining them is covered only by review.
#[test]
fn a_live_captured_stream_has_a_resolvable_first_frame() {
    use sipnab::capture::packet::FrameCounter;

    let mut m = Mixed::new();
    // One counter for the device, exactly as the live reader keeps one.
    let mut frames = FrameCounter::new();
    let mut feed = |m: &mut Mixed, dport: u16, seq: u16| {
        let mut pkt = wire_rtp_at(PEER_IP, PEER_PORT, MEDIA_IP, dport, seq, t0());
        pkt.origin = Some(frames.next_origin());
        m.feed(&pkt);
    };
    // Frames 0..2 open one stream, frames 3..4 a second on another socket, so
    // the SECOND stream's pointer can only be right if the counter advanced
    // across the first stream's frames. A stuck counter passes an assertion
    // about frame 0 alone.
    for seq in 0..3u16 {
        feed(&mut m, MEDIA_PORT, seq);
    }
    for seq in 0..2u16 {
        feed(&mut m, MEDIA_PORT + 2, seq);
    }

    let mut pointers: Vec<String> = {
        let s = m.streams.read();
        s.iter()
            .map(|st| {
                st.first_frame
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| {
                        panic!(
                            "a live-captured stream must name the frame it \
                             began at; before stage two the live reader \
                             stamped no ordinal, so this was always None"
                        )
                    })
            })
            .collect()
    };
    pointers.sort();
    assert_eq!(
        pointers,
        vec!["eth9#0".to_string(), "eth9#3".to_string()],
        "FIRST frame, never latest, and numbered within the device: a stream \
         citing whichever frame arrived last names real bytes that are not the \
         ones described"
    );

    let minted = {
        let s = m.streams.read();
        s.iter()
            .find(|st| st.key.dst.port() == MEDIA_PORT)
            .and_then(|st| st.first_frame.clone())
            .expect("the first stream keeps its pointer")
    };
    let round_trip = sipnab::capture::resolve::parse_pointer("eth9#0").expect(
        "the pointer an operator reads off a report must parse back to the \
         one the run minted",
    );
    assert_eq!(
        round_trip, minted,
        "the text form and the in-memory form must be the same pointer"
    );
}
