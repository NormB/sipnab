// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! OpenSIPS `topology_hiding("C")`: the two legs of a call joined by the
//! `E_SIPNAB_TH_MAP` event OpenSIPS sends with `event_datagram` (#617).
//!
//! `tests/fixtures/th-mapping/opensips-4.0-events.pcap` was recorded by
//! `harness/th-mapping/capture.sh` from OpenSIPS 4.0.2 running the script the
//! guide shows: three calls through `topology_hiding("C")`, each with the
//! event OpenSIPS sent to 192.0.2.1:9060. Every address is RFC 5737 and
//! every Call-ID host `example.com`.

#![cfg(all(feature = "hep", feature = "native"))]

use std::net::{IpAddr, Ipv4Addr};

use chrono::Utc;
use sipnab::capture::packet::{HepOrigin, Packet, PreParsed};
use sipnab::capture::parse::parse_packet;
use sipnab::pipeline::{self, PacketAction, PipelineOptions};
use sipnab::rtp::heuristic::RtpHeuristic;
use sipnab::sip::th_mapping::{EventRefusal, ThMapping};

type TestError = Box<dyn std::error::Error>;

/// The datagram OpenSIPS 4.0.2 sent for call 1 of the fixture, byte for byte.
const EVENT: &str = r#"{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":{"callee_call_id":"DLGCH_fl0RBn4kMSMPFR0PPjk8NmETCgM-","caller_call_id":"1-th-map@example.com"}}"#;

/// One datagram as the HEP listener hands it to the pipeline: `json_event`
/// says whether the listener took it for an event or a HEP packet.
fn delivered(body: &[u8], json_event: bool) -> Packet {
    Packet::with_pre_parsed(
        Utc::now(),
        body.to_vec(),
        Some("hep-event:192.0.2.10".to_string()),
        PreParsed {
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            src_port: 0,
            dst_port: 9060,
            ip_protocol: 17,
            hep: Some(HepOrigin {
                protocol: 0,
                correlation_id: None,
                sniffed_on_port: None,
                json_event,
            }),
            vcon: None,
        },
    )
}

/// The action's variant, for failure messages: `PacketAction` has no
/// `Debug`.
fn kind(action: &PacketAction) -> &'static str {
    match action {
        PacketAction::None => "None",
        PacketAction::Sip { .. } => "Sip",
        PacketAction::ThMapping(Ok(_)) => "ThMapping(Ok)",
        PacketAction::ThMapping(Err(_)) => "ThMapping(Err)",
        PacketAction::RelayControl(_) => "RelayControl",
        PacketAction::Rtcp(_) => "Rtcp",
        PacketAction::Rtp { .. } => "Rtp",
    }
}

fn classify(packet: &Packet) -> Result<PacketAction, TestError> {
    let parsed = parse_packet(packet)?;
    let mut heuristic = RtpHeuristic::new();
    let mut decrypt = pipeline::MediaDecrypt::default();
    Ok(pipeline::classify_packet(
        &parsed,
        &mut heuristic,
        &PipelineOptions::default(),
        &mut decrypt,
    ))
}

/// An event the listener took for one is classified as a mapping, parsed.
#[test]
fn an_event_from_the_listener_is_classified_as_a_mapping() -> Result<(), TestError> {
    let action = classify(&delivered(EVENT.as_bytes(), true))?;
    let PacketAction::ThMapping(Ok(mapping)) = action else {
        return Err(format!(
            "the event must be classified as a mapping: {}",
            kind(&action)
        )
        .into());
    };
    assert_eq!(
        mapping,
        ThMapping {
            caller_call_id: "1-th-map@example.com".into(),
            callee_call_id: "DLGCH_fl0RBn4kMSMPFR0PPjk8NmETCgM-".into(),
        },
        "the two Call-IDs OpenSIPS named"
    );
    Ok(())
}

/// A datagram the listener took for an event that is not one is still the
/// mapping path's to count, as refused, rather than offered to SIP or RTP.
#[test]
fn a_bad_event_is_classified_as_a_refused_mapping() -> Result<(), TestError> {
    let action = classify(&delivered(b"{not json", true))?;
    assert!(
        matches!(action, PacketAction::ThMapping(Err(EventRefusal::NotJson))),
        "a bad event is counted as a refused mapping: {}",
        kind(&action)
    );
    Ok(())
}

/// The same bytes NOT marked as an event (a HEP payload, or anything off the
/// wire) are never taken for a mapping: only the listener's check makes one.
#[test]
fn the_same_bytes_not_marked_as_an_event_are_not_a_mapping() -> Result<(), TestError> {
    let action = classify(&delivered(EVENT.as_bytes(), false))?;
    assert!(
        !matches!(action, PacketAction::ThMapping(_)),
        "only a datagram the listener marked may become a mapping: {}",
        kind(&action)
    );
    Ok(())
}

// ---- End to end: the OpenSIPS capture replayed into a live listener ----

/// The capture `harness/th-mapping/capture.sh` recorded from OpenSIPS 4.0.2.
const FIXTURE: &str = "tests/fixtures/th-mapping/opensips-4.0-events.pcap";

/// The three calls: caller-side Call-ID and the callee-side one OpenSIPS
/// wrote, as the events in the capture name them.
const CALLS: [(&str, &str); 3] = [
    ("1-th-map@example.com", "DLGCH_fl0RBn4kMSMPFR0PPjk8NmETCgM-"),
    ("2-th-map@example.com", "DLGCH_fV0RBn4kMSMPFR0PPjk8NmETCgM-"),
    ("3-th-map@example.com", "DLGCH_fF0RBn4kMSMPFR0PPjk8NmETCgM-"),
];

/// One UDP datagram from the capture.
struct Datagram {
    src: std::net::SocketAddr,
    dst: std::net::SocketAddr,
    payload: Vec<u8>,
}

/// The UDP datagrams of a classic little-endian Ethernet pcap, in order.
fn datagrams(path: &str) -> Result<Vec<Datagram>, TestError> {
    let bytes = std::fs::read(path)?;
    let u16be = |b: &[u8], i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
    let u32le = |b: &[u8], i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    assert_eq!(u32le(&bytes, 0), 0xa1b2_c3d4, "a classic microsecond pcap");
    let mut out = Vec::new();
    let mut at = 24;
    while at + 16 <= bytes.len() {
        let caplen = u32le(&bytes, at + 8) as usize;
        let frame = &bytes[at + 16..at + 16 + caplen];
        at += 16 + caplen;
        // Ethernet II, IPv4, UDP: all the harness's network carries.
        if u16be(frame, 12) != 0x0800 || frame[23] != 17 {
            continue;
        }
        let ihl = usize::from(frame[14] & 0x0f) * 4;
        let ip = |i: usize| {
            IpAddr::V4(Ipv4Addr::new(
                frame[i],
                frame[i + 1],
                frame[i + 2],
                frame[i + 3],
            ))
        };
        let udp = 14 + ihl;
        let len = usize::from(u16be(frame, udp + 4));
        out.push(Datagram {
            src: std::net::SocketAddr::new(ip(26), u16be(frame, udp)),
            dst: std::net::SocketAddr::new(ip(30), u16be(frame, udp + 2)),
            payload: frame[udp + 8..udp + len].to_vec(),
        });
    }
    Ok(out)
}

/// The capture split into its SIP datagrams and its event datagrams (those
/// to port 9060).
fn sip_and_events() -> Result<(Vec<Datagram>, Vec<Vec<u8>>), TestError> {
    let (events, sip): (Vec<Datagram>, Vec<Datagram>) = datagrams(FIXTURE)?
        .into_iter()
        .partition(|d| d.dst.port() == 9060);
    assert_eq!(events.len(), 3, "one event per call in the capture");
    assert!(sip.len() > 30, "the three calls' SIP: {}", sip.len());
    Ok((sip, events.into_iter().map(|d| d.payload).collect()))
}

/// A headless sipnab whose only source is `--hep-listen`, with REST up.
struct Listener {
    child: std::process::Child,
    hep: std::net::SocketAddr,
    api: String,
    log: std::sync::mpsc::Receiver<String>,
}

impl Listener {
    /// `sipnab -N --hep-listen 127.0.0.1:0 --api 127.0.0.1:0` plus `extra`,
    /// once both report the address they bound.
    fn start(extra: &[&str]) -> Result<Self, TestError> {
        Self::launch(true, extra)
    }

    /// The same with no REST API: a run that ends when `--duration` says,
    /// where a server would keep the process up.
    fn start_without_api(extra: &[&str]) -> Result<Self, TestError> {
        Self::launch(false, extra)
    }

    fn launch(api: bool, extra: &[&str]) -> Result<Self, TestError> {
        use std::io::BufRead;
        let api_args: &[&str] = if api { &["--api", "127.0.0.1:0"] } else { &[] };
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(["-N", "--hep-listen", "127.0.0.1:0"])
            .args(api_args)
            .args(["--config", "/dev/null"])
            .args(extra)
            .env("SIPNAB_LOG", "info")
            .env("NO_COLOR", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        let stderr = child.stderr.take().ok_or("piped stderr")?;
        let (tx, log) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                let _ = tx.send(line);
            }
        });
        let mut hep: Option<std::net::SocketAddr> = None;
        // With no API there is no address to wait for.
        let mut api: Option<String> = api_args.is_empty().then(String::new);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while (hep.is_none() || api.is_none()) && std::time::Instant::now() < deadline {
            let Ok(line) = log.recv_timeout(std::time::Duration::from_millis(200)) else {
                if let Ok(Some(status)) = child.try_wait() {
                    return Err(format!("sipnab exited early: {status}").into());
                }
                continue;
            };
            if let Some(rest) = line.split("HEP listener started on ").nth(1) {
                hep = rest.split_whitespace().next().map(str::parse).transpose()?;
            }
            if let Some(rest) = line.split("REST API listening on ").nth(1) {
                api = Some(rest.trim().to_string());
            }
        }
        let (Some(hep), Some(api)) = (hep, api) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("sipnab did not report both listeners".into());
        };
        Ok(Self {
            child,
            hep,
            api,
            log,
        })
    }

    /// Send `sip` as HEP3 SIP, stamped now as a live sender would, and each
    /// event as it is, from one loopback socket.
    fn send(
        &self,
        sip: &[Datagram],
        events: &[Vec<u8>],
        events_first: bool,
    ) -> Result<(), TestError> {
        use sipnab::capture::hep::{HepEndpoint, HepProtocol, build_hep_v3};
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let send_events = || -> Result<(), TestError> {
            for e in events {
                socket.send_to(e, self.hep)?;
            }
            Ok(())
        };
        if events_first {
            send_events()?;
        }
        for d in sip {
            let endpoint = HepEndpoint {
                src_addr: d.src.ip(),
                dst_addr: d.dst.ip(),
                src_port: d.src.port(),
                dst_port: d.dst.port(),
                transport: sipnab::net::TransportProto::Udp,
            };
            let hep = build_hep_v3(
                &endpoint,
                Utc::now(),
                HepProtocol::Sip,
                2001,
                None,
                &d.payload,
            );
            socket.send_to(&hep, self.hep)?;
        }
        if !events_first {
            send_events()?;
        }
        Ok(())
    }

    /// `GET path` on the REST API, as JSON.
    fn get(&self, path: &str) -> Result<serde_json::Value, TestError> {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(&self.api)?;
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.api
        )?;
        let mut text = String::new();
        s.read_to_string(&mut text)?;
        let body = text.split("\r\n\r\n").nth(1).ok_or("an HTTP response")?;
        Ok(serde_json::from_str(body)?)
    }

    /// Poll `/v1/stats` until `done` holds, or fail after ten seconds.
    fn wait_for(
        &self,
        what: &str,
        done: impl Fn(&serde_json::Value) -> bool,
    ) -> Result<serde_json::Value, TestError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let stats = self.get("/v1/stats")?;
            if done(&stats) {
                return Ok(stats);
            }
            if std::time::Instant::now() > deadline {
                return Err(format!("{what} never happened: {stats}").into());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// `/v1/dialogs/{call_id}/correlated`.
    fn correlated(&self, call_id: &str) -> Result<serde_json::Value, TestError> {
        self.get(&format!("/v1/dialogs/{call_id}/correlated"))
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The legs of a `/correlated` answer joined by a mapping.
fn mapped_legs(v: &serde_json::Value) -> Vec<String> {
    v["legs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|l| l["method"] == "mapping")
                .filter_map(|l| l["call_id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The capture OpenSIPS produced, replayed into a live listener with the
/// events after the SIP and, in a second run, before it: each callee leg is
/// joined to its own caller leg by the mapping, at 100, and to no other.
#[test]
fn the_captured_events_join_each_call_whichever_arrives_first() -> Result<(), TestError> {
    let (sip, events) = sip_and_events()?;
    for events_first in [false, true] {
        let when = if events_first { "before" } else { "after" };
        let l = Listener::start(&["--hep-allow", "127.0.0.1/32"])?;
        l.send(&sip, &events, events_first)?;
        l.wait_for("three accepted events and six dialogs", |s| {
            s["th_mappings"]["accepted"] == 3 && s["dialogs"]["total"] == 6
        })?;
        for (caller, callee) in CALLS {
            let v = l.correlated(callee)?;
            assert_eq!(mapped_legs(&v), [caller], "events {when} the SIP: {v}");
            let leg = v["legs"]
                .as_array()
                .and_then(|a| a.iter().find(|x| x["call_id"] == caller))
                .ok_or("the caller leg")?;
            assert_eq!(leg["strategy"], "th_callid_mapping", "{v}");
            assert_eq!(leg["score"], 100, "{v}");
            assert_eq!(leg["identifier_match"], true, "{v}");
            assert_eq!(
                v["th_callid"], "mapped",
                "the callee leg says it was mapped: {v}"
            );
            let back = l.correlated(caller)?;
            assert_eq!(
                mapped_legs(&back),
                [callee],
                "and from the caller side: {back}"
            );
        }
        let stats = l.get("/v1/stats")?;
        assert_eq!(
            stats["th_mappings"]["pending"], 0,
            "every mapping has its legs: {stats}"
        );
    }
    Ok(())
}

/// The same events sent three times are one mapping each; a fourth event
/// that pairs call 1's caller with call 2's callee is refused, and both
/// mappings it touches stop joining.
#[test]
fn repeats_are_harmless_and_a_conflict_joins_nothing() -> Result<(), TestError> {
    let (sip, events) = sip_and_events()?;
    let l = Listener::start(&["--hep-allow", "127.0.0.1/32"])?;
    let thrice: Vec<Vec<u8>> = events.iter().cycle().take(9).cloned().collect();
    l.send(&sip, &thrice, false)?;
    l.wait_for("nine events", |s| {
        s["th_mappings"]["accepted"] == 3 && s["th_mappings"]["duplicate"] == 6
    })?;
    assert_eq!(
        mapped_legs(&l.correlated(CALLS[0].1)?),
        [CALLS[0].0],
        "repeats change nothing"
    );
    let crossed = format!(
        r#"{{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":{{"caller_call_id":"{}","callee_call_id":"{}"}}}}"#,
        CALLS[0].0, CALLS[1].1
    );
    l.send(&[], &[crossed.into_bytes()], false)?;
    l.wait_for("the conflict", |s| s["th_mappings"]["conflict"] == 1)?;
    for (call, other) in [(0, 1), (1, 0)] {
        let v = l.correlated(CALLS[call].1)?;
        assert!(
            mapped_legs(&v).is_empty(),
            "call {call}'s legs must not join: {v}"
        );
        assert_eq!(v["th_callid"], "conflict", "and the leg says why: {v}");
        assert!(
            !mapped_legs(&v).contains(&CALLS[other].0.to_string()),
            "never to the other call: {v}"
        );
    }
    assert_eq!(
        mapped_legs(&l.correlated(CALLS[2].1)?),
        [CALLS[2].0],
        "the call the conflict did not name still joins"
    );
    Ok(())
}

/// A listener with no `--hep-allow` admits the SIP over HEP but refuses
/// every event, counts the refusal under its own reason, and joins nothing.
#[test]
fn without_an_allowlist_events_are_refused_and_counted() -> Result<(), TestError> {
    let (sip, events) = sip_and_events()?;
    let l = Listener::start(&[])?;
    l.send(&sip, &events, false)?;
    l.wait_for("the SIP", |s| s["dialogs"]["total"] == 6)?;
    let senders = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let v = l.get("/v1/hep/senders")?;
            if v["refused_by_reason"]["event_sender_not_listed"] == 3
                || std::time::Instant::now() > deadline
            {
                break v;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    };
    assert_eq!(
        senders["refused_by_reason"]["event_sender_not_listed"], 3,
        "each event refused under its own reason: {senders}"
    );
    let stats = l.get("/v1/stats")?;
    assert_eq!(
        stats["th_mappings"]["accepted"], 0,
        "nothing accepted: {stats}"
    );
    assert!(
        mapped_legs(&l.correlated(CALLS[0].1)?).is_empty(),
        "nothing joined"
    );
    Ok(())
}

/// A live run says at its end what the events did.
#[test]
fn a_live_run_ends_with_the_event_counts() -> Result<(), TestError> {
    let (sip, events) = sip_and_events()?;
    let mut l = Listener::start_without_api(&["--hep-allow", "127.0.0.1/32", "--duration", "4"])?;
    l.send(&sip, &events, false)?;
    let status = l.child.wait()?;
    assert!(status.success(), "the run ends cleanly: {status}");
    let log: Vec<String> = l.log.try_iter().collect();
    let line = log
        .iter()
        .find(|line| line.contains("E_SIPNAB_TH_MAP event(s)"))
        .ok_or_else(|| format!("no end-of-run line in:\n{}", log.join("\n")))?;
    assert!(line.contains("3 accepted"), "{line}");
    assert!(line.contains("0 waiting"), "{line}");
    Ok(())
}

/// The fenced blocks of `md` whose opening fence is exactly `fence`.
fn fenced_blocks(md: &str, fence: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut lines = md.lines();
    while let Some(line) = lines.next() {
        if line == fence {
            let body: Vec<&str> = lines.by_ref().take_while(|l| *l != "```").collect();
            out.push(body.join("\n"));
        }
    }
    out
}

/// The guide's OpenSIPS lines, after `@SIPNAB@` becomes its `127.0.0.1:9060`.
fn rendered_template() -> Result<String, TestError> {
    Ok(
        std::fs::read_to_string("harness/th-mapping/opensips.cfg.tmpl")?
            .replace("@SIPNAB@", "127.0.0.1:9060"),
    )
}

/// The guide's OpenSIPS lines for the event are the ones
/// `harness/th-mapping/e2e.sh` ran against OpenSIPS 4.0.2, 4.0.1 and 3.6.9,
/// character for character (the request-route block one tab deeper), with
/// `@SIPNAB@` as the guide's `127.0.0.1:9060`; and its JSON example is the
/// datagram OpenSIPS 4.0.2 sent.
#[test]
fn the_guides_event_lines_are_the_ones_the_harness_ran() -> Result<(), TestError> {
    let guide = std::fs::read_to_string("docs/opensips-sipnab.md")?;
    let template = rendered_template()?;
    let blocks: Vec<String> = fenced_blocks(&guide, "```text")
        .into_iter()
        .filter(|b| {
            b.contains("loadmodule") || b.contains("subscribe_event(") || b.contains("raise_event(")
        })
        .collect();
    assert_eq!(
        blocks.len(),
        3,
        "the module, the subscription and the raise: {blocks:?}"
    );
    for block in &blocks {
        let indented: Vec<String> = block.lines().map(|l| format!("\t{l}")).collect();
        assert!(
            template.contains(block.as_str()) || template.contains(&indented.join("\n")),
            "the guide's block is not in the harness template:\n{block}"
        );
    }
    let json = fenced_blocks(&guide, "```json")
        .into_iter()
        .find(|b| b.starts_with(r#"{"jsonrpc""#) && b.contains("E_SIPNAB_TH_MAP"))
        .ok_or("the guide shows the datagram")?;
    let (_, events) = sip_and_events()?;
    assert_eq!(
        json.as_bytes(),
        events[0].as_slice(),
        "the guide's datagram is the one OpenSIPS sent"
    );
    Ok(())
}

/// The guide's complete `opensips.cfg` is the harness template that
/// `harness/th-mapping/e2e.sh` ran, every line below the template's comment
/// header, with `@SIPNAB@` as the guide's `127.0.0.1:9060`: so the two
/// cannot drift apart.
#[test]
fn the_guides_complete_config_is_the_harness_template() -> Result<(), TestError> {
    let guide = std::fs::read_to_string("docs/opensips-sipnab.md")?;
    let configs: Vec<String> = fenced_blocks(&guide, "```cfg")
        .into_iter()
        .filter(|b| b.contains("E_SIPNAB_TH_MAP"))
        .collect();
    assert_eq!(
        configs.len(),
        1,
        "the guide shows one complete opensips.cfg for the event"
    );
    let template = rendered_template()?;
    let body: Vec<&str> = template
        .lines()
        .skip_while(|l| l.starts_with('#'))
        .collect();
    assert_eq!(
        configs[0],
        body.join("\n").trim_end(),
        "the guide's opensips.cfg differs from harness/th-mapping/opensips.cfg.tmpl"
    );
    Ok(())
}
