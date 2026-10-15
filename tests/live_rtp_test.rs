// SPDX-License-Identifier: MIT OR Apache-2.0

//! Live media out: a `[[vcon.rule]]` with `live_rtp = "host:port"` sends each
//! matching call's decoded audio to that UDP target as RTP with an L16
//! payload ([RFC 3551 section 4.5.11]), 16 kHz mono in 20 ms packets, one
//! stream with its own SSRC per leg, with a JSON `start` message before the
//! first packet and a `stop` message after the last.
//!
//! The consumer here is a stub: a UDP socket on loopback that records every
//! datagram, as a local speech-to-text service's ingest port would receive
//! them. A datagram whose first byte is `{` is a control message; one whose
//! first two bits are `10` is RTP version 2.
//!
//! [RFC 3551 section 4.5.11]: https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.11
#![cfg(feature = "vcon")]

#[path = "support/pcap_build.rs"]
mod pcap_build;

use std::net::UdpSocket;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

type TestError = Box<dyn std::error::Error>;

/// The dynamic payload type the stream carries (RFC 3551 section 6).
const L16_PAYLOAD_TYPE: u8 = 96;
/// Samples in one 20 ms packet at 16 kHz.
const SAMPLES_PER_PACKET: usize = 320;

/// One RTP packet the stub received.
#[derive(Debug, Clone)]
struct Rtp {
    marker: bool,
    payload_type: u8,
    seq: u16,
    ts: u32,
    ssrc: u32,
    samples: Vec<i16>,
}

/// One datagram the stub received, in arrival order.
#[derive(Debug, Clone)]
enum Item {
    Rtp(Rtp),
    Control(serde_json::Value),
}

/// Read one datagram as RTP or as a control message.
fn parse(datagram: &[u8]) -> Result<Item, TestError> {
    if datagram.first() == Some(&b'{') {
        return Ok(Item::Control(serde_json::from_slice(datagram)?));
    }
    if datagram.len() < 12 || datagram[0] >> 6 != 2 {
        return Err(format!("neither JSON nor RTP v2: {datagram:02x?}").into());
    }
    assert_eq!(datagram[0] & 0x3F, 0, "no padding, extension or CSRC");
    let payload = &datagram[12..];
    assert_eq!(payload.len() % 2, 0, "L16 is two bytes a sample");
    Ok(Item::Rtp(Rtp {
        marker: datagram[1] & 0x80 != 0,
        payload_type: datagram[1] & 0x7F,
        seq: u16::from_be_bytes([datagram[2], datagram[3]]),
        ts: u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]),
        ssrc: u32::from_be_bytes([datagram[8], datagram[9], datagram[10], datagram[11]]),
        // Network byte order, RFC 3551 section 4.5.11.
        samples: payload
            .chunks(2)
            .map(|b| i16::from_be_bytes([b[0], b[1]]))
            .collect(),
    }))
}

/// A run of sipnab over `pcap` with a config whose rule body is `rule`
/// (`{target}` replaced by the stub's address), and what the stub received.
struct Run {
    code: Option<i32>,
    stderr: String,
    items: Vec<Item>,
}

fn run(dir: &Path, pcap: &str, rule: &str, extra: &[&str]) -> Result<Run, TestError> {
    // A replayed file is sent faster than real time, so the stub asks for
    // the largest receive buffer the host allows, as a consumer would.
    let raw = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    raw.set_recv_buffer_size(8 * 1024 * 1024)?;
    raw.bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 0)).into())?;
    let sock: UdpSocket = raw.into();
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let target = sock.local_addr()?.to_string();
    let cfg = dir.join("sipnab.toml");
    std::fs::write(
        &cfg,
        format!(
            "[[vcon.rule]]\nname = \"fork\"\ndir = \"{}\"\naudio = \"omit\"\n{}\n",
            dir.join("spool").display(),
            rule.replace("{target}", &target)
        ),
    )?;
    let done = Arc::new(AtomicBool::new(false));
    let reader = {
        let done = Arc::clone(&done);
        std::thread::spawn(move || -> Vec<Vec<u8>> {
            let mut got = Vec::new();
            let mut buf = vec![0u8; 65_536];
            loop {
                match sock.recv(&mut buf) {
                    Ok(n) => got.push(buf[..n].to_vec()),
                    Err(_) if done.load(Ordering::SeqCst) => return got,
                    Err(_) => {}
                }
            }
        })
    };
    let cfg = cfg.to_str().ok_or("utf-8 path")?;
    let mut args = vec!["-N", "-I", pcap, "--config", cfg];
    args.extend_from_slice(extra);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(&args)
        .env("NO_COLOR", "1")
        .output()?;
    done.store(true, Ordering::SeqCst);
    let datagrams = reader.join().map_err(|_| "the stub receiver panicked")?;
    let items = datagrams
        .iter()
        .map(|d| parse(d))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Run {
        code: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        items,
    })
}

/// Whether the stub received every RTP packet the stop messages say was sent.
fn lossless(items: &[Item]) -> bool {
    let sent = streams(items);
    controls(items)
        .iter()
        .filter(|v| v["type"] == "stop")
        .flat_map(|v| legs_of(v))
        .filter(|l| l["status"] == "sending")
        .all(|l| {
            let got = sent
                .iter()
                .find(|(s, _)| l["ssrc"] == *s)
                .map_or(0, |(_, p)| p.len());
            l["packets"] == got
        })
}

/// [`run`], again while the stub lost datagrams, at most three times.
///
/// UDP on loopback drops a datagram when the receiving socket's buffer is
/// full, which a stub starved of CPU on a loaded test host can let happen.
/// The stop message counts what sipnab sent, so a loss is told apart from a
/// defect: a run whose stop counts match what arrived is judged on every
/// packet, and one whose counts do not is a lost datagram, not a verdict.
fn run_lossless(dir: &Path, pcap: &str, rule: &str, extra: &[&str]) -> Result<Run, TestError> {
    let mut last = run(dir, pcap, rule, extra)?;
    for _ in 1..3 {
        if lossless(&last.items) {
            break;
        }
        last = run(dir, pcap, rule, extra)?;
    }
    assert!(
        lossless(&last.items),
        "the stub lost datagrams in three runs"
    );
    Ok(last)
}

fn tone(stream: usize, frame: usize, i: usize) -> u8 {
    ((stream * 41 + frame * 7 + i) % 251) as u8
}

/// A capture of `kept` and `other`, one second of PCMU each way each, both
/// ending with a BYE; `header` goes on the INVITE of `kept`, and `profile` is
/// both calls' SDP transport.
fn capture(dir: &Path, header: Option<&str>, profile: &str) -> Result<String, TestError> {
    let leg = |call_id, net: u8, header| {
        pcap_build::g711_leg_with_profile(
            &pcap_build::G711Leg {
                call_id,
                caller: ([10, net, 0, 1], 20000, 0x1000_0000 | u32::from(net)),
                callee: ([10, net, 0, 2], 30000, 0x2000_0000 | u32::from(net)),
                header,
                start_us: u64::from(net) * 10_000,
                ends: true,
            },
            1,
            tone,
            profile,
        )
    };
    let mut frames = leg("kept", 1, header);
    frames.extend(leg("other", 2, None));
    frames.sort_by_key(|(_, at)| *at);
    let path = dir.join("calls.pcap");
    pcap_build::write_pcap_at(&path, &frames, 1)?;
    Ok(path.to_str().ok_or("utf-8 path")?.to_owned())
}

/// The control messages of `items`, in order.
fn controls(items: &[Item]) -> Vec<&serde_json::Value> {
    items
        .iter()
        .filter_map(|i| match i {
            Item::Control(v) => Some(v),
            Item::Rtp(_) => None,
        })
        .collect()
}

/// The RTP packets of `items`, grouped by SSRC in order of first arrival.
fn streams(items: &[Item]) -> Vec<(u32, Vec<Rtp>)> {
    let mut out: Vec<(u32, Vec<Rtp>)> = Vec::new();
    for item in items {
        if let Item::Rtp(p) = item {
            match out.iter_mut().find(|(s, _)| *s == p.ssrc) {
                Some((_, v)) => v.push(p.clone()),
                None => out.push((p.ssrc, vec![p.clone()])),
            }
        }
    }
    out
}

/// Where in `items` a predicate first and last holds.
fn position(items: &[Item], f: impl Fn(&Item) -> bool) -> (Option<usize>, Option<usize>) {
    (items.iter().position(&f), items.iter().rposition(&f))
}

/// The leg objects a control message carries: `legs` of a start or a stop,
/// or the one `leg` of a leg message.
fn legs_of(v: &serde_json::Value) -> Vec<&serde_json::Value> {
    match (v.get("legs"), v.get("leg")) {
        (Some(serde_json::Value::Array(a)), _) => a.iter().collect(),
        (_, Some(l)) => vec![l],
        _ => Vec::new(),
    }
}

/// Every sent stream is well formed RTP: L16 payload type, a marker on the
/// first packet only, sequence numbers that step by one, timestamps that step
/// by the samples of the packet before, 20 ms packets but for the last.
fn assert_well_formed(packets: &[Rtp]) {
    assert!(!packets.is_empty());
    for (n, p) in packets.iter().enumerate() {
        assert_eq!(p.payload_type, L16_PAYLOAD_TYPE, "packet {n}");
        assert_eq!(
            p.marker,
            n == 0,
            "the marker is on the first packet only: {n}"
        );
        assert!(p.samples.len() <= SAMPLES_PER_PACKET, "packet {n}");
        if n + 1 < packets.len() {
            assert_eq!(p.samples.len(), SAMPLES_PER_PACKET, "packet {n} is 20 ms");
        }
        if n > 0 {
            let prev = &packets[n - 1];
            assert_eq!(p.seq, prev.seq.wrapping_add(1), "sequence step at {n}");
            assert_eq!(
                p.ts,
                prev.ts.wrapping_add(prev.samples.len() as u32),
                "timestamp step at {n}"
            );
        }
    }
}

/// A two-way call replayed from a committed capture comes out as one RTP
/// stream per leg: distinct SSRCs, every packet well formed, the sample count
/// the decoded audio's at 16 kHz, a `start` before the first packet and a
/// `stop` after the last, and nothing for the capture's other call.
///
/// `SIP_CALL_RTP_G711` holds call `12013223@200.57.7.195` with G.711 A-law
/// at 8 kHz each way, so each leg is resampled to 16 kHz: twice the samples
/// the capture carries. The capture ends before that call's BYE, so its stop
/// comes when the capture does.
#[test]
fn a_replayed_call_is_one_rtp_stream_per_leg() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/pcap-samples/SIP_CALL_RTP_G711"
    );
    let r = run_lossless(
        dir.path(),
        pcap,
        "when = \"call_id == '12013223@200.57.7.195'\"\nlive_rtp = \"{target}\"",
        &[],
    )?;
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    let ctl = controls(&r.items);
    assert!(
        ctl.iter().all(|v| v["call_id"] == "12013223@200.57.7.195"),
        "only the matching call is announced: {ctl:#?}"
    );
    let sent = streams(&r.items);
    assert_eq!(sent.len(), 2, "one stream per leg");
    assert!(!r.stderr.contains("could not be sent"), "{}", r.stderr);
    assert_ne!(sent[0].0, sent[1].0, "each leg has its own SSRC");

    let (first_start, last_start) = position(
        &r.items,
        |i| matches!(i, Item::Control(v) if v["type"] == "start"),
    );
    assert_eq!(first_start, Some(0), "the start comes first");
    assert_eq!(first_start, last_start, "one start per call");
    let (stop, last_stop) = position(
        &r.items,
        |i| matches!(i, Item::Control(v) if v["type"] == "stop"),
    );
    assert_eq!(stop, Some(r.items.len() - 1), "the stop comes last");
    assert_eq!(stop, last_stop, "one stop per call");
    let stop = ctl.last().ok_or("a stop")?;
    assert_eq!(stop["reason"], "the capture ended", "{stop}");
    assert_eq!(stop["rule"], "fork");

    for (ssrc, packets) in &sent {
        assert_well_formed(packets);
        // Announced, with its codec and the capture's side of the mapping,
        // before its first packet.
        let first_rtp = r
            .items
            .iter()
            .position(|i| matches!(i, Item::Rtp(p) if p.ssrc == *ssrc))
            .ok_or("a packet")?;
        let announced = r.items[..first_rtp].iter().any(
            |i| matches!(i, Item::Control(v) if legs_of(v).iter().any(|l| l["ssrc"] == *ssrc)),
        );
        assert!(
            announced,
            "SSRC {ssrc:#x} is announced before its first packet"
        );
        let leg = legs_of(stop)
            .into_iter()
            .find(|l| l["ssrc"] == *ssrc)
            .ok_or("the stop names every sent leg")?;
        assert_eq!(leg["status"], "sending");
        assert_eq!(leg["encoding"], "L16");
        assert_eq!(leg["rate"], 16000);
        assert_eq!(leg["channels"], 1);
        assert_eq!(leg["payload_type"], 96);
        assert_eq!(leg["captured"]["codec"], "PCMA");
        assert_eq!(leg["captured"]["rate"], 8000);
        let samples: usize = packets.iter().map(|p| p.samples.len()).sum();
        assert_eq!(leg["samples"], samples, "the stop counts what was sent");
        assert_eq!(leg["packets"], packets.len());
        // The capture's payload bytes, from the UDP lengths `tshark` reads:
        // 200.57.7.196:40376 sends 891 packets, 875 with 160 A-law bytes and
        // 16 with one; 200.57.7.204:8000 sends 548, each with 160. Each byte
        // is one 8 kHz sample, two at 16 kHz.
        let (packets, bytes) = match leg["captured"]["ssrc"].as_u64() {
            Some(0x58F3_3DEA) => (891, 875 * 160 + 16),
            Some(0xD2BD_4E3E) => (548, 548 * 160),
            other => return Err(format!("an unexpected captured SSRC {other:?}").into()),
        };
        assert_eq!(leg["captured"]["packets"], packets, "{leg}");
        assert_eq!(samples, bytes * 2, "{leg}");
    }
    Ok(())
}

/// The samples are the call's audio: every other one is the G.711 decode of
/// the captured byte, which the 8 to 16 kHz interpolation keeps exactly. A
/// call the rule does not match sends nothing at all, and a call that ends
/// with a BYE stops with that reason.
#[test]
fn a_call_no_rule_matches_sends_nothing() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), None, "RTP/AVP")?;
    let r = run_lossless(
        dir.path(),
        &pcap,
        "when = \"call_id == 'kept'\"\nlive_rtp = \"{target}\"",
        &[],
    )?;
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    let ctl = controls(&r.items);
    assert!(ctl.iter().all(|v| v["call_id"] == "kept"), "{ctl:#?}");
    let sent = streams(&r.items);
    assert_eq!(sent.len(), 2, "the matching call's two legs, nothing else");
    let stop = ctl.last().ok_or("a stop")?;
    assert_eq!(stop["type"], "stop");
    assert_eq!(stop["reason"], "the call ended");
    for (ssrc, packets) in &sent {
        assert_well_formed(packets);
        let leg = legs_of(stop)
            .into_iter()
            .find(|l| l["ssrc"] == *ssrc)
            .ok_or("the stop names the leg")?;
        // The caller sends from port 20000: stream 0 of the tone.
        let stream = usize::from(leg["captured"]["src"] != "10.1.0.1:20000");
        let pcm: Vec<i16> = packets.iter().flat_map(|p| p.samples.clone()).collect();
        assert_eq!(pcm.len(), 50 * 160 * 2);
        for frame in 0..50 {
            let bytes: Vec<u8> = (0..160).map(|i| tone(stream, frame, i)).collect();
            let decoded =
                sipnab::rtp::g711::decode_frame(sipnab::rtp::g711::G711Codec::Ulaw, &bytes);
            for (i, s) in decoded.iter().enumerate() {
                assert_eq!(pcm[(frame * 160 + i) * 2], *s, "frame {frame} sample {i}");
            }
        }
    }
    Ok(())
}

/// A call `--content-deny-header` withholds is not sent, while the call
/// beside it is.
#[test]
fn a_denied_call_sends_nothing() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), Some("X-No-Record: 1"), "RTP/AVP")?;
    let r = run_lossless(
        dir.path(),
        &pcap,
        "when = \"method == 'INVITE'\"\nlive_rtp = \"{target}\"",
        &["--content-deny-header", "X-No-Record"],
    )?;
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    let ctl = controls(&r.items);
    assert!(
        ctl.iter().all(|v| v["call_id"] == "other"),
        "the denied call is never announced: {ctl:#?}"
    );
    let kinds: Vec<&serde_json::Value> = ctl.iter().map(|v| &v["type"]).collect();
    assert_eq!(kinds.first(), Some(&&"start".into()), "{ctl:#?}");
    assert_eq!(kinds.last(), Some(&&"stop".into()), "{ctl:#?}");
    assert_eq!(
        kinds.iter().filter(|k| **k == "start").count(),
        1,
        "{ctl:#?}"
    );
    assert_eq!(streams(&r.items).len(), 2, "the other call's legs only");
    Ok(())
}

/// A leg negotiated as SRTP that no key decrypted sends no audio, and the
/// control messages say why.
#[test]
fn an_undecrypted_srtp_leg_sends_no_audio_and_says_why() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), None, "RTP/SAVP")?;
    let r = run(
        dir.path(),
        &pcap,
        "when = \"call_id == 'kept'\"\nlive_rtp = \"{target}\"",
        &[],
    )?;
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(
        streams(&r.items).is_empty(),
        "no audio it could not decrypt"
    );
    let ctl = controls(&r.items);
    assert_eq!(
        ctl.first().map(|v| &v["type"]),
        Some(&"start".into()),
        "{ctl:#?}"
    );
    let stop = ctl.last().ok_or("a stop")?;
    assert_eq!(stop["type"], "stop");
    let legs = legs_of(stop);
    assert_eq!(legs.len(), 2, "{stop}");
    for leg in legs {
        assert_eq!(leg["status"], "withheld", "{leg}");
        assert!(
            leg.get("ssrc").is_none(),
            "a withheld leg has no stream: {leg}"
        );
        assert!(
            leg["reason"]
                .as_str()
                .is_some_and(|r| r.contains("decrypt")),
            "{leg}"
        );
        assert_eq!(leg["undecrypted_packets"], 50, "{leg}");
    }
    Ok(())
}

/// Plain RTP has no encryption and no authentication, so a target off
/// loopback is refused at startup, naming the key and its opt-in. With the
/// opt-in the run starts, and says it is sending a capture file's audio.
#[test]
fn an_off_loopback_target_needs_the_opt_in() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), None, "RTP/AVP")?;
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737). The rule matches no call, so
    // nothing is sent there when the run is allowed to start.
    let rule = "when = \"call_id == 'nobody'\"\nlive_rtp = \"192.0.2.1:40000\"";
    let refused = run(dir.path(), &pcap, rule, &[])?;
    assert_eq!(
        refused.code,
        Some(1),
        "a refused config-file value: {}",
        refused.stderr
    );
    assert!(refused.stderr.contains("live_rtp"), "{}", refused.stderr);
    assert!(
        refused.stderr.contains("live_rtp_allow_remote"),
        "{}",
        refused.stderr
    );
    assert!(
        refused.stderr.contains("192.0.2.1:40000"),
        "{}",
        refused.stderr
    );

    let allowed = run(
        dir.path(),
        &pcap,
        &format!("{rule}\nlive_rtp_allow_remote = true"),
        &[],
    )?;
    assert_eq!(allowed.code, Some(0), "{}", allowed.stderr);
    assert!(
        allowed.stderr.contains("capture FILE"),
        "a file source is announced: {}",
        allowed.stderr
    );
    Ok(())
}

/// A `--cores` run does not fork live audio, and says so rather than
/// leaving a rule that looks armed and sends nothing.
#[test]
fn a_cores_run_says_it_sends_nothing() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), None, "RTP/AVP")?;
    let r = run(
        dir.path(),
        &pcap,
        "when = \"call_id == 'kept'\"\nlive_rtp = \"{target}\"",
        &["--cores", "2"],
    )?;
    assert!(r.items.is_empty(), "{:?}", r.items);
    assert!(
        r.stderr.contains("live_rtp") && r.stderr.contains("sends nothing"),
        "{}",
        r.stderr
    );
    Ok(())
}

/// The fork sends under its own permit, minted only from an
/// `OperatorDestination`, and nothing converts into it: an address read out
/// of a capture has no route to becoming a target. Source shape, as
/// `tests/hep_send_file_export_test.rs` pins the HEP permit, because there is
/// no runtime signal for a conversion nobody wrote yet.
#[test]
fn nothing_converts_into_the_live_rtp_permit() -> Result<(), TestError> {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/output/live_rtp.rs"
    ))?;
    assert!(
        src.contains("pub struct LiveRtpPermit(());"),
        "the permit keeps its private unit field"
    );
    assert!(src.contains("pub fn for_destination(destination: &OperatorDestination) -> Self"));
    for line in src.lines().map(str::trim_start) {
        if line.starts_with("impl") && line.contains("for LiveRtpPermit") {
            return Err(format!("`{line}` is a second way to make the permit").into());
        }
    }
    // The one function that sends takes the permit.
    assert!(src.contains("fn transmit(&self, _permit: &LiveRtpPermit, bytes: &[u8]) -> bool"));
    Ok(())
}
