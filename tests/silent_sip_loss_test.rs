// SPDX-License-Identifier: MIT OR Apache-2.0

//! Two ways real SIP used to leave the pipeline without a trace.
//!
//! Both were found by reading sipnab's own totals back against `tshark` over a
//! corpus of real captures, and both are silent: nothing in any output format
//! said a message had been seen and dropped.
//!
//! 1. **Extension methods.** [`sipnab::sip::is_sip_message`] sniffs the first
//!    line against a hard-coded list of fourteen registered methods. RFC 3261
//!    §7.1 defines `Method` as those six plus `extension-method = token`, so a
//!    request whose method is a token the list does not name failed the sniff
//!    and never reached the parser — which would have parsed it fine, since
//!    [`sipnab::SipMethod::parse`] already keeps unknown tokens in `Custom`.
//!    Kamailio's `KDMQ` is 11,623 messages of the corpus; 1,215 of `tg.pcap0`'s
//!    13,451 (9%).
//!
//! 2. **The `--portrange` gate.** The default `5060-5061` skips SIP
//!    classification on every other port, and the run then reports the reduced
//!    totals as if they were complete. 32% of the corpus's SIP has neither port
//!    in that range. The gate itself is what the operator asked for, so it
//!    stays — but what it discarded is now counted and reported instead of
//!    vanishing.
//!
//! 3. **The WebSocket port set.** SIP-over-WebSocket (RFC 7118) was unwrapped
//!    only on 80, 443, 8080 and 8443, which is the browser's view of the web
//!    and not a deployment's. Kamailio, OpenSIPS and Janus each default to WSS
//!    outside that set, and behind a reverse proxy sipnab sees whatever port
//!    the proxy forwards to — so a whole WebRTC signalling leg vanished. Worse
//!    than case 2, which at least says what it skipped: there was no report of
//!    any kind. The set is now settable (`--ws-portrange`) and what falls
//!    outside it is counted and attributed to a port.
#![cfg(feature = "native")]

use chrono::Utc;
use std::net::{IpAddr, Ipv4Addr};

use sipnab::SipMethod;
use sipnab::capture::parse::{ParsedPacket, TransportProto};
use sipnab::pipeline::{
    self, MediaDecrypt, PacketAction, PipelineOptions, classify_packet, portrange_skip_report,
};
use sipnab::rtp::heuristic::RtpHeuristic;

/// Build a UDP `ParsedPacket` carrying `payload` between the given ports.
fn parsed(payload: Vec<u8>, src_port: u16, dst_port: u16) -> ParsedPacket {
    ParsedPacket {
        frame: None,
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
        dscp: None,
        from_hep: false,
    }
}

/// A well-formed request with method `method` and Call-ID `call_id`.
fn request(method: &str, call_id: &str) -> Vec<u8> {
    format!(
        "{method} sip:node@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:8090;branch=z9hG4bKext\r\n\
         From: <sip:a@example.com>;tag=e1\r\n\
         To: <sip:node@example.com>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 {method}\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

/// Classify `pp` with a fresh heuristic and no media decryption.
fn classify(pp: &ParsedPacket, opts: &PipelineOptions) -> PacketAction {
    let mut heur = RtpHeuristic::new();
    let mut decrypt = MediaDecrypt::default();
    classify_packet(pp, &mut heur, opts, &mut decrypt)
}

// ── 1. Extension methods ─────────────────────────────────────────────

/// A request whose method is an extension token still classifies as SIP, and
/// keeps its own method name.
///
/// This is the whole defect: `KDMQ` is a perfectly ordinary Kamailio DMQ
/// request with a Call-ID that belongs in a dialog, and it was discarded before
/// the parser ever saw it because the first-line sniffer only knew fourteen
/// method names. The dialog state machine has no rule for it — that is fine and
/// expected, `update_state` falls to the generic handler — but "we cannot model
/// its state" is not a reason to pretend the packet did not arrive.
#[test]
fn an_extension_method_request_is_not_dropped() {
    let pp = parsed(request("KDMQ", "ext-kdmq@test"), 8090, 8090);
    let action = classify(&pp, &PipelineOptions::default());
    let PacketAction::Sip { msg, .. } = action else {
        panic!("an extension-method request must classify as SIP, not vanish");
    };
    assert!(msg.is_request, "KDMQ is a request");
    assert_eq!(
        msg.method,
        Some(SipMethod::Custom("KDMQ".into())),
        "the method must be reported under its own name, not renamed or erased"
    );
    assert_eq!(msg.call_id(), Some("ext-kdmq@test"));
}

/// Several unrelated extension methods, so the fix is not a special case for
/// one vendor's token.
#[test]
fn extension_methods_generally_survive() {
    // Real deployments: Kamailio DMQ, the RFC 2976-era INFO relatives, and
    // tokens using the punctuation RFC 3261's `token` production allows.
    for method in ["KDMQ", "SERVICE", "QAUTH", "SPIRIT", "DO", "X-VENDOR.PING"] {
        let pp = parsed(request(method, "ext@test"), 5060, 5060);
        let PacketAction::Sip { msg, .. } = classify(&pp, &PipelineOptions::default()) else {
            panic!("{method} must classify as SIP");
        };
        assert_eq!(
            msg.method.as_ref().map(SipMethod::as_str),
            Some(method),
            "{method} must keep its name"
        );
    }
}

/// The sniff stays strict: accepting extension methods must not turn the
/// pipeline into "any text is SIP". Every input here is a plausible near-miss
/// that a looser check would swallow.
///
/// The predicate is asserted **directly**, not only through `classify_packet`.
/// Going through classification alone is not enough: `parse_sip_bytes` rejects
/// a non-SIP first line anyway, so a sniff that had grown to accept HTTP would
/// still produce `PacketAction::None` and look fine. It would not be fine — the
/// sniff is also what decides whether an out-of-`--portrange` packet is
/// recorded as discarded SIP, and there is no parser behind that decision to
/// catch the mistake. A loose sniff would report an operator's HTTP traffic as
/// SIP they are failing to analyse.
#[test]
fn extension_method_acceptance_stays_strict() {
    let cases: &[(&str, &[u8])] = &[
        ("HTTP request", b"OPTIONS / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("HTTP GET", b"GET /index.html HTTP/1.1\r\n\r\n"),
        ("RTSP", b"DESCRIBE rtsp://x/y RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
        ("SIP version glued to the URI", b"FOO sip:aSIP/2.0\r\n\r\n"),
        // Ends in the version token and opens with a registered method, but
        // carries no request-URI. The known-method sniffer accepted this and
        // `parse_first_line` then rejected it, so a non-message cost a "SIP
        // parse error" diagnostic; here it is simply not a request line.
        ("no request-URI at all", b"INFO SIP/2.0\r\n\r\n"),
        ("request-URI is only whitespace", b"INFO   SIP/2.0\r\n\r\n"),
        (
            "control bytes in the method",
            b"\x01\x02\x03 sip:x SIP/2.0\r\n\r\n",
        ),
        ("empty method", b" sip:x SIP/2.0\r\n\r\n"),
        ("no CRLF", b"KDMQ sip:x SIP/2.0"),
        (
            "binary/RTP-shaped",
            &[0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
        // A method token longer than any real one: the sniff gives up at the
        // cap instead of scanning on into a binary payload that happens to
        // open with token-legal bytes.
        (
            "over-long method token",
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA sip:x SIP/2.0\r\n\r\n",
        ),
    ];
    for (name, payload) in cases {
        assert!(
            !sipnab::sip::parser::starts_sip_message(payload),
            "{name} must not be sniffed as SIP"
        );
        let pp = parsed(payload.to_vec(), 5060, 5060);
        assert!(
            !matches!(
                classify(&pp, &PipelineOptions::default()),
                PacketAction::Sip { .. }
            ),
            "{name} must not classify as SIP either"
        );
    }
}

/// No message that used to be analysed is lost.
///
/// The precise property, and the one that matters: **anything the old
/// known-method sniffer accepted and the parser then parsed successfully, the
/// extension-aware sniff also accepts.** The two predicates live in different
/// modules and can drift, and the whole point of widening one is that nothing
/// falls out of the other end while doing it.
///
/// The claim is deliberately not "accepts everything the old one did". The old
/// sniffer accepted `INFO SIP/2.0` — a registered method, the version token,
/// and no request-URI — which `parse_first_line` then rejected. Dropping that
/// earlier is a tightening on input that was never a message, and the
/// parse-succeeds qualifier is what distinguishes the two.
#[test]
fn no_message_the_old_sniff_analysed_is_lost() {
    const METHODS: [&str; 14] = [
        "INVITE",
        "ACK",
        "BYE",
        "CANCEL",
        "REGISTER",
        "OPTIONS",
        "PRACK",
        "SUBSCRIBE",
        "NOTIFY",
        "PUBLISH",
        "INFO",
        "REFER",
        "MESSAGE",
        "UPDATE",
    ];
    let mut inputs: Vec<Vec<u8>> = METHODS.iter().map(|m| request(m, "sup@test")).collect();
    for extra in [
        &b"SIP/2.0 200 OK\r\nCall-ID: x\r\nCSeq: 1 INVITE\r\n\r\n"[..],
        b"SIP/2.0 401 Unauthorized\r\n\r\n",
        // Adversarial first lines: multi-SP tolerance, a URI holding a space,
        // no URI, glued version token, non-SIP text, truncation.
        b"INVITE  sip:x@example.com SIP/2.0\r\nCall-ID: m@t\r\n\r\n",
        b"INVITE O sip:x@example.com SIP/2.0\r\nCall-ID: s@t\r\n\r\n",
        b"INFO SIP/2.0\r\n\r\n",
        b"INVITE sip:aSIP/2.0\r\n\r\n",
        b"GET / HTTP/1.1\r\n\r\n",
        b"not sip at all",
        b"",
        b"SIP",
        b"SIP/2.0 ",
    ] {
        inputs.push(extra.to_vec());
    }

    let mut checked = 0usize;
    for input in &inputs {
        if !sipnab::sip::is_sip_message(input) {
            continue;
        }
        let parses = sipnab::sip::parser::parse_sip(
            input,
            Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .is_ok();
        if !parses {
            continue;
        }
        checked += 1;
        assert!(
            sipnab::sip::parser::starts_sip_message(input),
            "the extension-aware sniff rejected input #{checked}, which the \
             known-method sniff accepted and the parser parsed — widening the \
             method set must never narrow anything else"
        );
    }
    // More is fine — bump this. FEWER means inputs stopped reaching the
    // comparison at all, and the property above would then be passing
    // vacuously rather than proving anything.
    assert_eq!(
        checked, 18,
        "expected 18 inputs to be accepted-and-parseable under the old sniff"
    );
}

// ── 2. The --portrange gate reports what it discarded ────────────────

/// SIP outside the port range is still skipped — the gate is what the operator
/// asked for — but it is now counted and attributed to a port instead of
/// disappearing.
#[test]
#[serial_test::serial(portrange_skips)]
fn portrange_skips_are_counted_not_silent() {
    let gated = PipelineOptions {
        sip_portrange: Some((5060, 5061)),
        ..Default::default()
    };
    pipeline::reset_portrange_skips();

    // Two requests to a service on 8090 and one response back from it.
    for i in 0..2 {
        let pp = parsed(request("OPTIONS", &format!("oor-{i}@test")), 41000, 8090);
        assert!(
            matches!(classify(&pp, &gated), PacketAction::None),
            "the gate still skips: --portrange means what it says"
        );
    }
    let resp = parsed(
        b"SIP/2.0 200 OK\r\nCall-ID: oor-r@test\r\nCSeq: 1 OPTIONS\r\n\r\n".to_vec(),
        8090,
        41000,
    );
    assert!(matches!(classify(&resp, &gated), PacketAction::None));

    let report = portrange_skip_report();
    assert_eq!(
        report.messages, 3,
        "every skipped SIP message must be counted"
    );
    assert_eq!(
        report.ports.first().map(|p| p.port),
        Some(8090),
        "the skip must be attributed to the service port — the destination of a \
         request and the source of a response — so the operator is told which \
         --portrange to widen to, not an ephemeral client port"
    );
    assert_eq!(report.ports[0].messages, 3);
}

/// Non-SIP traffic outside the range is not counted as a skipped SIP message.
///
/// This is where a loose sniff does real damage. Everywhere else the parser
/// sits behind the sniff and rejects whatever it wrongly admitted; here there
/// is nothing behind it, and a false positive becomes sipnab telling an
/// operator they have unanalysed SIP on a port carrying their web traffic.
/// Ports outside `--portrange` are, by construction, exactly where the
/// non-SIP protocols live.
#[test]
#[serial_test::serial(portrange_skips)]
fn portrange_skips_count_only_sip() {
    let gated = PipelineOptions {
        sip_portrange: Some((5060, 5061)),
        // Media tracking off: this test is only about what the skip counter
        // does, and RTP on 40000/40001 would otherwise classify as Rtp.
        no_rtp: true,
        ..Default::default()
    };
    pipeline::reset_portrange_skips();

    let mut rtp = vec![0x80u8, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF];
    rtp.extend_from_slice(&[0u8; 160]);
    for _ in 0..50 {
        let pp = parsed(rtp.clone(), 40000, 40001);
        assert!(matches!(classify(&pp, &gated), PacketAction::None));
    }
    // Text protocols that share SIP's request-line shape, on the ports they
    // really run on. HTTP even shares the OPTIONS method token.
    let text: &[(&[u8], u16, u16)] = &[
        (b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n", 44321, 80),
        (b"OPTIONS / HTTP/1.1\r\nHost: x\r\n\r\n", 44322, 8080),
        (b"POST /api HTTP/1.1\r\nHost: x\r\n\r\n", 44323, 443),
        (
            b"DESCRIBE rtsp://x/y RTSP/1.0\r\nCSeq: 1\r\n\r\n",
            44324,
            554,
        ),
        (b"\x00\x01\x02 garbage", 40000, 40001),
    ];
    for (payload, sp, dp) in text {
        let pp = parsed(payload.to_vec(), *sp, *dp);
        assert!(matches!(classify(&pp, &gated), PacketAction::None));
    }

    assert_eq!(
        portrange_skip_report().messages,
        0,
        "only SIP counts as skipped SIP — reporting HTTP or RTSP here would \
         send an operator widening --portrange onto a web server"
    );
}

/// In-range SIP is classified and never counted as a skip, and an ungated
/// pipeline (`sip_portrange: None`, the live-TUI contract where BPF already
/// filtered) records no skips at all.
#[test]
#[serial_test::serial(portrange_skips)]
fn in_range_and_ungated_traffic_records_no_skips() {
    pipeline::reset_portrange_skips();

    let gated = PipelineOptions {
        sip_portrange: Some((5060, 5061)),
        ..Default::default()
    };
    let pp = parsed(request("INVITE", "in-range@test"), 41000, 5060);
    assert!(matches!(classify(&pp, &gated), PacketAction::Sip { .. }));
    assert_eq!(
        portrange_skip_report().messages,
        0,
        "SIP inside the range was analysed AND reported as skipped — the report \
         would claim a loss that did not happen, and every count would appear \
         to be missing traffic that is right there in the output"
    );

    let ungated = PipelineOptions::default();
    let pp = parsed(request("INVITE", "ungated@test"), 8090, 8090);
    assert!(matches!(classify(&pp, &ungated), PacketAction::Sip { .. }));
    assert_eq!(
        portrange_skip_report().messages,
        0,
        "an ungated pipeline (sip_portrange: None — live capture, where BPF \
         already filtered) reported a skip; with no range configured there is \
         nothing to skip and nothing to widen"
    );
}

// ── 3. The WebSocket port set reports what it discarded ──────────────

/// Wrap `payload` in an unmasked WebSocket text frame (RFC 6455 §5.2).
///
/// Server-to-client frames are unmasked and client-to-server ones are masked;
/// the unwrap handles both, and the unmasked form is the one a test can read.
fn ws_frame(payload: &[u8]) -> Vec<u8> {
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

/// Build a TCP `ParsedPacket` carrying `payload` between the given ports.
fn parsed_tcp(payload: Vec<u8>, src_port: u16, dst_port: u16) -> ParsedPacket {
    ParsedPacket {
        transport: TransportProto::Tcp,
        ip_protocol: 6,
        ..parsed(payload, src_port, dst_port)
    }
}

/// SIP-over-WebSocket on a port outside the set is still skipped — replacing
/// the set is what `--ws-portrange` means — but it is now counted and
/// attributed to a port instead of disappearing without a word.
///
/// 8081 is not a contrived number: it is where a WSS listener behind a reverse
/// proxy commonly lands, and on such a capture every line of sipnab's output
/// used to be consistent with "this deployment has no WebRTC".
#[test]
#[serial_test::serial(ws_port_skips)]
fn websocket_skips_are_counted_not_silent() {
    sipnab::capture::websocket::set_ws_port_range(None);
    pipeline::reset_ws_port_skips();
    // Ungated: this test is about the WebSocket set, and the --portrange gate
    // would otherwise claim the same packets first.
    let opts = PipelineOptions::default();

    for i in 0..2 {
        let pp = parsed_tcp(
            ws_frame(&request("INVITE", &format!("ws-{i}@test"))),
            51000,
            8081,
        );
        assert!(
            matches!(classify(&pp, &opts), PacketAction::None),
            "the set still gates: --ws-portrange means what it says"
        );
    }
    let resp = parsed_tcp(
        ws_frame(b"SIP/2.0 200 OK\r\nCall-ID: ws-r@test\r\nCSeq: 1 INVITE\r\n\r\n"),
        8081,
        51000,
    );
    assert!(matches!(classify(&resp, &opts), PacketAction::None));

    let report = pipeline::ws_port_skip_report();
    assert_eq!(
        report.messages, 3,
        "every SIP-over-WebSocket message the port set declined must be counted \
         — before this there was no report at all and the leg was invisible"
    );
    assert_eq!(
        report.ports.first().map(|p| p.port),
        Some(8081),
        "the skip must be attributed to the service port — the destination of a \
         request and the source of a response — so the operator is told which \
         --ws-portrange to widen to, not an ephemeral browser port"
    );
    assert_eq!(report.ports[0].messages, 3);
}

/// A declared range REPLACES the shipped set: 8081 is unwrapped and 443 is
/// then the port that gets counted.
///
/// Asserting both halves in one test is deliberate. A range that merely ADDED
/// to the shipped set would pass the first half and fail the second, and
/// "added" is the reading an operator would not discover until a port they
/// meant to exclude turned up in their dialogs.
#[test]
#[serial_test::serial(ws_port_skips)]
fn a_declared_ws_range_replaces_the_shipped_set() {
    sipnab::capture::websocket::set_ws_port_range(Some((8081, 8081)));
    pipeline::reset_ws_port_skips();
    let opts = PipelineOptions::default();

    let pp = parsed_tcp(ws_frame(&request("INVITE", "ws-on@test")), 51000, 8081);
    let PacketAction::Sip { msg, .. } = classify(&pp, &opts) else {
        panic!("--ws-portrange 8081-8081 must unwrap SIP-over-WebSocket on 8081");
    };
    assert_eq!(msg.call_id(), Some("ws-on@test"));
    assert_eq!(
        pipeline::ws_port_skip_report().messages,
        0,
        "traffic the declared range covers was analysed AND reported as skipped"
    );

    let shipped_port = parsed_tcp(ws_frame(&request("INVITE", "ws-443@test")), 51001, 443);
    assert!(
        matches!(classify(&shipped_port, &opts), PacketAction::None),
        "a declared range replaces the shipped set, exactly as --portrange does"
    );
    assert_eq!(
        pipeline::ws_port_skip_report()
            .ports
            .first()
            .map(|p| p.port),
        Some(443),
        "and what the replacement excluded must be reported, or narrowing the \
         set recreates the silence this whole tally exists to end"
    );

    sipnab::capture::websocket::set_ws_port_range(None);
}

/// Non-SIP WebSocket traffic outside the set is not counted as skipped SIP.
///
/// The same hazard `portrange_skips_count_only_sip` guards, and sharper here:
/// ports outside the WebSocket set are where ordinary web sockets live, and a
/// browser's chat or telemetry socket must not send an operator widening
/// `--ws-portrange` onto their application traffic. The unwrap is attempted on
/// every port now, so only the SIP test stands between the two.
#[test]
#[serial_test::serial(ws_port_skips)]
fn websocket_skips_count_only_sip() {
    sipnab::capture::websocket::set_ws_port_range(None);
    pipeline::reset_ws_port_skips();
    let opts = PipelineOptions {
        no_rtp: true,
        ..Default::default()
    };

    for payload in [
        &b"{\"type\":\"chat\",\"body\":\"hello\"}"[..],
        &b"GET /socket HTTP/1.1\r\nHost: x\r\n\r\n"[..],
        &b"\x00\x01\x02 not text at all"[..],
    ] {
        let pp = parsed_tcp(ws_frame(payload), 51002, 9443);
        assert!(matches!(classify(&pp, &opts), PacketAction::None));
    }
    // A TCP payload that is not a WebSocket frame at all must not be tallied
    // either, however SIP-shaped it looks.
    let bare = parsed_tcp(request("INVITE", "bare-tcp@test"), 51003, 9443);
    let _ = classify(&bare, &opts);

    assert_eq!(
        pipeline::ws_port_skip_report().messages,
        0,
        "only SIP-over-WebSocket counts as skipped SIP-over-WebSocket — \
         reporting a chat socket here would send an operator widening \
         --ws-portrange onto their own application"
    );
}
