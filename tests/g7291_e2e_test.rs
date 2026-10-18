// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//! G.729.1 through the shipped binary: a call whose SDP offers
//! `a=rtpmap:96 G7291/16000` (RFC 4749), read from a capture built here, its
//! audio exported in a vCon with `--retain-audio` and sent by a live RTP
//! rule.
//!
//! sipnab decodes the G.729.1 core layer: the first 20 octets of each 20 ms
//! frame, two G.729 frames, decoded by the G.729 decoder to 8 kHz. The
//! frames' core layers here are the G.729 frames of the committed G.729
//! sample capture, so every expected sample comes from the g729 crate's
//! decoder fed the same frames. The layers above 8 kbit/s are filler octets
//! the decoder must never read.
//!
//! The tables are never committed (docs/g729.md). Each test installs them
//! with `sipnab g729 install --from` on the ITU-T package that
//! `scripts/fetch-g729-vectors.py` fetches; a missing package FAILS the test
//! with that command.
#![cfg(all(feature = "g729", feature = "vcon"))]

#[path = "support/pcap_build.rs"]
mod pcap_build;

use std::path::{Path, PathBuf};
use std::process::Output;

type TestError = Box<dyn std::error::Error>;

/// The committed G.729 call whose frames become the G.729.1 cores.
const SAMPLE: &str = "tests/pcap-samples/sip-rtp-g729a.pcap";
/// The Call-ID of the call built here.
const CALL: &str = "g7291-call@192.0.2.10";
/// The dynamic payload type the SDP binds to G7291/16000.
const PT: u8 = 96;
/// What a run without the tables says, as for G.729.
const NOT_INSTALLED: &str =
    "G.729 not decoded: codebook tables not installed; run sipnab g729 install";
/// The statement every surface makes about decoded G.729.1 audio.
const CORE_LAYER: &str =
    "this audio is the G.729.1 core layer (8 kbit/s) decoded as G.729 at 8 kHz";
/// A core SID: an Annex B SID frame.
const SID: [u8; 2] = [0x4c, 0x90];

/// The extracted ITU-T package, `crates/g729/test-vectors/itu-source`.
fn package_dir() -> Result<PathBuf, TestError> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/g729/test-vectors/itu-source");
    if dir.is_dir() {
        Ok(dir)
    } else {
        Err(format!(
            "the ITU-T G.729 package is not fetched ({} is missing): run \
             `python3 scripts/fetch-g729-vectors.py` from the repository root",
            dir.display()
        )
        .into())
    }
}

/// Run the binary with `home` as `$HOME` and `$XDG_CONFIG_HOME`.
fn sipnab(home: &Path, args: &[&str]) -> Result<Output, TestError> {
    Ok(std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env_remove("SIPNAB_CONFIG")
        .env("NO_COLOR", "1")
        .output()?)
}

/// A data directory with the tables installed by the shipped command.
fn installed() -> Result<tempfile::TempDir, TestError> {
    let home = tempfile::tempdir()?;
    let package = package_dir()?;
    let package = package.to_str().ok_or("a UTF-8 path")?;
    let out = sipnab(
        home.path(),
        &["g729", "install", "--yes", "--no-config", "--from", package],
    )?;
    if !out.status.success() {
        return Err(format!(
            "sipnab g729 install failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(home)
}

/// The installed tables, for the reference decoder.
fn tables(home: &Path) -> Result<g729::Tables, TestError> {
    Ok(g729::Tables::from_bytes(&std::fs::read(
        home.join("sipnab").join("g729-tables.bin"),
    )?)?)
}

/// The G.729 frames of the sample capture, in order: 425 packets of two.
fn sample_frames() -> Result<Vec<[u8; 10]>, TestError> {
    let pcap = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(SAMPLE))?;
    let mut frames = Vec::new();
    let mut at = 24;
    while at + 16 <= pcap.len() {
        let caplen = u32::from_le_bytes(pcap[at + 8..at + 12].try_into()?) as usize;
        let frame = &pcap[at + 16..at + 16 + caplen];
        // Ethernet 14, IPv4 20, UDP 8 to port 6000, RTP 12.
        if frame.len() > 54 && frame[23] == 17 && u16::from_be_bytes([frame[36], frame[37]]) == 6000
        {
            let (chunks, rest) = frame[54..].as_chunks::<10>();
            assert!(rest.is_empty(), "whole G.729 frames");
            frames.extend_from_slice(chunks);
        }
        at += 16 + caplen;
    }
    assert_eq!(frames.len(), 850, "the sample's G.729 frames");
    Ok(frames)
}

/// One G.729.1 frame at frame type `ft` whose core is `core`, the higher
/// layers 0xA5.
fn g7291_frame(ft: u8, core: &[[u8; 10]]) -> Vec<u8> {
    let octets = g729::g7291::Rate::from_ft(ft).map_or(20, g729::g7291::Rate::frame_octets);
    let mut frame = core.concat();
    frame.resize(octets, 0xa5);
    frame
}

/// A payload of `frames` frames at frame type `ft` (MBS 15), their cores
/// taken in order from `cores`.
fn speech_payload(ft: u8, cores: &[[u8; 10]]) -> Vec<u8> {
    let mut payload = vec![0xf0 | ft];
    for core in cores.chunks(2) {
        payload.extend(g7291_frame(ft, core));
    }
    payload
}

/// A payload holding a 6-octet SID alone (FT 14) whose core is [`SID`].
fn sid_payload() -> Vec<u8> {
    vec![0xfe, SID[0], SID[1] | 1, 0x12, 0x34, 0x56, 0x78]
}

/// One RTP packet of the call: its sequence number, timestamp and payload.
struct Packet {
    seq: u16,
    ts: u32,
    payload: Vec<u8>,
}

/// `cores.len() / (2 * per_packet)` packets of `per_packet` frames at `ft`,
/// sequence numbers from 0 and timestamps 320 a frame.
fn speech_packets(ft: u8, cores: &[[u8; 10]], per_packet: usize) -> Vec<Packet> {
    cores
        .chunks(2 * per_packet)
        .enumerate()
        .map(|(i, chunk)| Packet {
            seq: i as u16,
            ts: (i * per_packet * 320) as u32,
            payload: speech_payload(ft, chunk),
        })
        .collect()
}

/// A capture of one call: INVITE and 200 offering G7291/16000 on payload
/// type 96, ACK, `packets` from caller to callee 20 ms apart, then BYE and
/// its 200.
fn capture(dir: &Path, packets: &[Packet]) -> Result<String, TestError> {
    let (a, b) = ([192, 0, 2, 10], [192, 0, 2, 20]);
    let (a_port, b_port) = (40000u16, 50000u16);
    let sdp = |ip: &str, port: u16| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP {PT}\r\na=rtpmap:{PT} G7291/16000\r\n\
             a=fmtp:{PT} dtx=1\r\na=ptime:20\r\n"
        )
    };
    let offer = sdp("192.0.2.10", a_port);
    let answer = sdp("192.0.2.20", b_port);
    let common = format!(
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKg7291\r\n\
         From: <sip:a@192.0.2.10>;tag=t1\r\nCall-ID: {CALL}\r\n"
    );
    let sip = |src, dst, text: String| pcap_build::udp_frame(src, dst, 5060, 5060, text.as_bytes());
    let mut frames = vec![
        (
            sip(
                a,
                b,
                format!(
                    "INVITE sip:b@192.0.2.20 SIP/2.0\r\n{common}To: <sip:b@192.0.2.20>\r\n\
                     Max-Forwards: 70\r\nCSeq: 1 INVITE\r\nContact: <sip:a@192.0.2.10>\r\n\
                     Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{offer}",
                    offer.len()
                ),
            ),
            0u64,
        ),
        (
            sip(
                b,
                a,
                format!(
                    "SIP/2.0 200 OK\r\n{common}To: <sip:b@192.0.2.20>;tag=t2\r\n\
                     CSeq: 1 INVITE\r\nContact: <sip:b@192.0.2.20>\r\n\
                     Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{answer}",
                    answer.len()
                ),
            ),
            1_000,
        ),
        (
            sip(
                a,
                b,
                format!(
                    "ACK sip:b@192.0.2.20 SIP/2.0\r\n{common}To: <sip:b@192.0.2.20>;tag=t2\r\n\
                     Max-Forwards: 70\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
                ),
            ),
            2_000,
        ),
    ];
    let start = 10_000u64;
    for p in packets {
        let mut rtp = vec![0x80, PT];
        rtp.extend_from_slice(&p.seq.to_be_bytes());
        rtp.extend_from_slice(&p.ts.to_be_bytes());
        rtp.extend_from_slice(&0x7291_0001u32.to_be_bytes());
        rtp.extend_from_slice(&p.payload);
        // Capture time follows the RTP timestamp: 16 ticks a millisecond.
        let at = start + u64::from(p.ts) * 1_000 / 16;
        frames.push((pcap_build::udp_frame(a, b, a_port, b_port, &rtp), at));
    }
    let end = frames.last().map_or(start, |f| f.1) + 20_000;
    frames.push((
        sip(
            a,
            b,
            format!(
                "BYE sip:b@192.0.2.20 SIP/2.0\r\n{common}To: <sip:b@192.0.2.20>;tag=t2\r\n\
                 Max-Forwards: 70\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
            ),
        ),
        end,
    ));
    frames.push((
        sip(
            b,
            a,
            format!(
                "SIP/2.0 200 OK\r\n{common}To: <sip:b@192.0.2.20>;tag=t2\r\n\
                 CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
            ),
        ),
        end + 1_000,
    ));
    let path = dir.join("g7291.pcap");
    pcap_build::write_pcap_at(&path, &frames, 1)?;
    Ok(path.to_str().ok_or("a UTF-8 path")?.to_owned())
}

/// The run's output for `--retain-audio --export-vcon CALL` over `pcap`.
fn export_run(home: &Path, pcap: &str) -> Result<Output, TestError> {
    sipnab(
        home,
        &[
            "-N",
            "-q",
            "--no-cli-print",
            "--no-config",
            "-I",
            pcap,
            "--retain-audio",
            "--export-vcon",
            CALL,
        ],
    )
}

/// The vCon `--export-vcon CALL` writes for `pcap`.
fn export(home: &Path, pcap: &str) -> Result<serde_json::Value, TestError> {
    let out = export_run(home, pcap)?;
    if !out.status.success() {
        return Err(format!("export failed: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

/// The WAV inside the container's `recording` Dialog Object.
fn recording_wav(vcon: &serde_json::Value) -> Result<Vec<u8>, TestError> {
    use base64::Engine;
    let recording = vcon["dialog"]
        .as_array()
        .ok_or("dialog is not an array")?
        .iter()
        .find(|d| d["type"] == "recording" && d.get("body").is_some())
        .ok_or_else(|| format!("no recording with a body: {vcon}"))?;
    let body = recording["body"].as_str().ok_or("body is not a string")?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body.trim_end_matches('='))?)
}

/// A PCM WAV's rate, channel count and samples.
fn wav_samples(wav: &[u8]) -> Result<(u32, u16, Vec<i16>), TestError> {
    if wav.get(..4) != Some(b"RIFF") || wav.get(8..12) != Some(b"WAVE") {
        return Err("not a WAV".into());
    }
    let (mut rate, mut channels, mut at) = (0u32, 0u16, 12usize);
    while at + 8 <= wav.len() {
        let id = &wav[at..at + 4];
        let len = u32::from_le_bytes(wav[at + 4..at + 8].try_into()?) as usize;
        let body = wav.get(at + 8..at + 8 + len).ok_or("a truncated chunk")?;
        if id == b"fmt " {
            channels = u16::from_le_bytes(body[2..4].try_into()?);
            rate = u32::from_le_bytes(body[4..8].try_into()?);
        } else if id == b"data" {
            let samples = body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| i16::from_le_bytes(*b))
                .collect();
            return Ok((rate, channels, samples));
        }
        at += 8 + len + (len & 1);
    }
    Err("no data chunk".into())
}

/// What the g729 crate's decoder produces for `frames`, from a fresh state.
fn reference(tables: &g729::Tables, frames: &[g729::Frame<'_>]) -> Vec<i16> {
    let mut decoder = g729::Decoder::new(tables);
    let mut out = Vec::new();
    let mut pcm = [0i16; g729::FRAME_SAMPLES];
    for frame in frames {
        decoder.decode(*frame, &mut pcm);
        out.extend_from_slice(&pcm);
    }
    out
}

/// Every core as a voice frame.
fn voice(cores: &[[u8; 10]]) -> Vec<g729::Frame<'_>> {
    cores.iter().map(g729::Frame::Voice).collect()
}

/// The first sample at which `got` leaves `want`, for a short failure.
fn first_difference(got: &[i16], want: &[i16]) -> Option<usize> {
    if got.len() != want.len() {
        return Some(got.len().min(want.len()));
    }
    got.iter().zip(want).position(|(a, b)| a != b)
}

// ── S1 ─────────────────────────────────────────────────────────────────

/// Given `a=rtpmap:96 G7291/16000`, the stream on payload type 96 is named
/// G7291 and runs on the 16 kHz clock: 100 packets 320 ticks apart export as
/// 100 frames of 20 ms, with no gap.
#[test]
fn s1_an_sdp_g7291_stream_is_named_and_clocked_at_16_khz() -> Result<(), TestError> {
    let home = installed()?;
    let cores = sample_frames()?;
    let pcap = capture(home.path(), &speech_packets(0, &cores[..200], 1))?;
    let vcon = export(home.path(), &pcap)?;
    let text = vcon.to_string();
    assert!(
        text.contains("\"codec\":\"G7291\""),
        "the stream is G7291: {text}"
    );
    let (rate, channels, samples) = wav_samples(&recording_wav(&vcon)?)?;
    assert_eq!((rate, channels), (8000, 1));
    assert_eq!(samples.len(), 100 * 160, "100 frames of 20 ms at 8 kHz");
    assert!(
        !text.contains("where the RTP timestamps show no audio arrived"),
        "{text}"
    );
    Ok(())
}

// ── S2 ─────────────────────────────────────────────────────────────────

/// At 32 kbit/s (FT 11) each frame decodes its first 20 octets as two G.729
/// frames, to 8 kHz, sample for sample what the G.729 decoder gives them.
#[test]
fn s2_a_32_kbit_s_stream_exports_its_core_at_8_khz() -> Result<(), TestError> {
    let home = installed()?;
    let cores = sample_frames()?;
    let pcap = capture(home.path(), &speech_packets(11, &cores, 1))?;
    let vcon = export(home.path(), &pcap)?;
    let (rate, channels, samples) = wav_samples(&recording_wav(&vcon)?)?;
    assert_eq!((rate, channels), (8000, 1));
    let want = reference(&tables(home.path())?, &voice(&cores));
    assert_eq!(
        first_difference(&samples, &want),
        None,
        "the export left the reference"
    );
    Ok(())
}

// ── S3 ─────────────────────────────────────────────────────────────────

/// Packets of two 20 kbit/s frames (FT 5) yield 320 samples each, oldest
/// frame first.
#[test]
fn s3_several_frames_a_packet_decode_oldest_first() -> Result<(), TestError> {
    let home = installed()?;
    let cores = sample_frames()?;
    let packets = speech_packets(5, &cores, 2);
    assert_eq!(
        packets.len(),
        213,
        "850 cores: 212 packets of two frames and one of one"
    );
    let pcap = capture(home.path(), &packets)?;
    let vcon = export(home.path(), &pcap)?;
    let (_, _, samples) = wav_samples(&recording_wav(&vcon)?)?;
    let want = reference(&tables(home.path())?, &voice(&cores));
    assert_eq!(
        first_difference(&samples, &want),
        None,
        "the export left the reference"
    );
    Ok(())
}

// ── S4 ─────────────────────────────────────────────────────────────────

/// FT 15 (no data) packets carry no audio and are not a loss: the time they
/// stand for is untransmitted frames, nothing failed and nothing was lost.
#[test]
fn s4_no_data_packets_decode_nothing_and_are_no_loss() -> Result<(), TestError> {
    let home = installed()?;
    let cores = sample_frames()?;
    let mut packets = speech_packets(0, &cores[..100], 1);
    for k in 0..10u16 {
        packets.push(Packet {
            seq: 50 + k,
            ts: (50 + u32::from(k)) * 320,
            payload: vec![0xff],
        });
    }
    for (k, chunk) in cores[100..200].chunks(2).enumerate() {
        packets.push(Packet {
            seq: 60 + k as u16,
            ts: (60 + k as u32) * 320,
            payload: speech_payload(0, chunk),
        });
    }
    let pcap = capture(home.path(), &packets)?;
    let vcon = export(home.path(), &pcap)?;
    let (_, _, samples) = wav_samples(&recording_wav(&vcon)?)?;
    let mut frames = voice(&cores[..100]);
    frames.extend([g729::Frame::NoTx; 20]);
    frames.extend(voice(&cores[100..200]));
    let want = reference(&tables(home.path())?, &frames);
    assert_eq!(
        first_difference(&samples, &want),
        None,
        "the export left the reference"
    );
    let text = vcon.to_string();
    assert!(!text.contains("failed to decode"), "{text}");
    Ok(())
}

/// FT 12 is reserved: the whole payload is ignored and counted, and its
/// 20 ms are concealed as a lost frame.
#[test]
fn s4_a_reserved_frame_type_is_ignored_and_counted() -> Result<(), TestError> {
    let home = installed()?;
    let cores = sample_frames()?;
    let mut packets = speech_packets(0, &cores[..100], 1);
    packets[20].payload[0] = 0xfc;
    let pcap = capture(home.path(), &packets)?;
    let vcon = export(home.path(), &pcap)?;
    let text = vcon.to_string();
    assert!(text.contains("1 frame(s) failed to decode"), "{text}");
    let (_, _, samples) = wav_samples(&recording_wav(&vcon)?)?;
    let mut frames = voice(&cores[..40]);
    frames.extend([g729::Frame::Erased; 2]);
    frames.extend(voice(&cores[42..100]));
    let want = reference(&tables(home.path())?, &frames);
    assert_eq!(
        first_difference(&samples, &want),
        None,
        "the export left the reference"
    );
    Ok(())
}

// ── S5 ─────────────────────────────────────────────────────────────────

/// A 6-octet SID alone (FT 14) drives the Annex B comfort noise from its
/// core SID, through the pause that follows it.
#[test]
fn s5_a_sid_drives_the_comfort_noise() -> Result<(), TestError> {
    let home = installed()?;
    let cores = sample_frames()?;
    let mut packets = speech_packets(0, &cores[..100], 1);
    packets.push(Packet {
        seq: 50,
        ts: 50 * 320,
        payload: sid_payload(),
    });
    // Nine 20 ms frames not sent, then speech again on the next sequence
    // number.
    for (k, chunk) in cores[100..200].chunks(2).enumerate() {
        packets.push(Packet {
            seq: 51 + k as u16,
            ts: (60 + k as u32) * 320,
            payload: speech_payload(0, chunk),
        });
    }
    let pcap = capture(home.path(), &packets)?;
    let vcon = export(home.path(), &pcap)?;
    let (_, _, samples) = wav_samples(&recording_wav(&vcon)?)?;
    let mut frames = voice(&cores[..100]);
    frames.extend([g729::Frame::Sid(&SID), g729::Frame::NoTx]);
    frames.extend([g729::Frame::NoTx; 18]);
    frames.extend(voice(&cores[100..200]));
    let want = reference(&tables(home.path())?, &frames);
    assert_eq!(
        first_difference(&samples, &want),
        None,
        "the export left the reference"
    );
    let noise = &samples[100 * 80..120 * 80];
    assert!(
        noise.iter().any(|&s| s != 0),
        "comfort noise is not silence"
    );
    Ok(())
}

// ── S7 ─────────────────────────────────────────────────────────────────

/// Without the tables the stream is left out, the vCon names the reason
/// and the command G.729 names, and stderr says it once.
#[test]
fn s7_without_tables_the_stream_is_left_out_naming_the_command() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let cores = sample_frames()?;
    let pcap = capture(home.path(), &speech_packets(11, &cores[..100], 1))?;
    let out = export_run(home.path(), &pcap)?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let vcon: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    assert!(recording_wav(&vcon).is_err(), "no recording without tables");
    let text = vcon.to_string();
    assert!(text.contains(NOT_INSTALLED), "{text}");
    assert!(text.contains("G7291"), "the omitted codec is named: {text}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.matches(NOT_INSTALLED).count(), 1, "stderr: {err}");
    Ok(())
}

// ── S8 ─────────────────────────────────────────────────────────────────

/// The vCon's caveat and the WAV's own note both say the audio is the
/// G.729.1 core layer decoded as G.729 at 8 kHz, and name the bit rates the
/// stream used.
#[test]
fn s8_the_vcon_and_the_wav_say_what_the_audio_is() -> Result<(), TestError> {
    let home = installed()?;
    let cores = sample_frames()?;
    let mut packets = speech_packets(11, &cores[..100], 1);
    packets.extend(
        speech_packets(1, &cores[100..200], 1)
            .into_iter()
            .map(|p| Packet {
                seq: p.seq + 50,
                ts: p.ts + 50 * 320,
                payload: p.payload,
            }),
    );
    let pcap = capture(home.path(), &packets)?;
    let vcon = export(home.path(), &pcap)?;
    let text = vcon.to_string();
    assert!(text.contains(CORE_LAYER), "{text}");
    assert!(
        text.contains("the stream's frames were sent at 12 and 32 kbit/s"),
        "{text}"
    );
    assert!(text.contains("are not decoded"), "{text}");
    let wav = String::from_utf8_lossy(&recording_wav(&vcon)?).into_owned();
    assert!(wav.contains(CORE_LAYER), "the WAV's note says it too");
    Ok(())
}

/// The live RTP route: the leg's control messages say what the audio is,
/// and the stop message names the bit rate; the audio itself is sent.
#[test]
fn s8_the_live_rtp_route_says_what_the_audio_is() -> Result<(), TestError> {
    use std::net::UdpSocket;
    let home = installed()?;
    let cores = sample_frames()?;
    let pcap = capture(home.path(), &speech_packets(11, &cores[..100], 1))?;
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    sock.set_read_timeout(Some(std::time::Duration::from_millis(200)))?;
    let cfg = home.path().join("live.toml");
    std::fs::write(
        &cfg,
        format!(
            "[[vcon.rule]]\nname = \"fork\"\ndir = \"{}\"\naudio = \"omit\"\n\
             when = \"call_id == '{CALL}'\"\nlive_rtp = \"{}\"\n",
            home.path().join("spool").display(),
            sock.local_addr()?
        ),
    )?;
    let receiver = std::thread::spawn(move || {
        let mut got: Vec<Vec<u8>> = Vec::new();
        let mut buf = vec![0u8; 65_536];
        let mut quiet = 0;
        while quiet < 15 {
            match sock.recv(&mut buf) {
                Ok(n) => {
                    quiet = 0;
                    got.push(buf[..n].to_vec());
                }
                Err(_) => quiet += 1,
            }
        }
        got
    });
    let cfg = cfg.to_str().ok_or("a UTF-8 path")?;
    let out = sipnab(home.path(), &["-N", "-I", &pcap, "--config", cfg])?;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let datagrams = receiver.join().map_err(|_| "the receiver panicked")?;
    let controls: Vec<serde_json::Value> = datagrams
        .iter()
        .filter(|d| d.first() == Some(&b'{'))
        .map(|d| serde_json::from_slice(d))
        .collect::<Result<_, _>>()?;
    let stop = controls
        .iter()
        .find(|v| v["type"] == "stop")
        .ok_or_else(|| format!("a stop message: {controls:?}"))?;
    let leg = &stop["legs"][0];
    assert_eq!(leg["status"], "sending", "{stop}");
    assert_eq!(leg["captured"]["codec"], "G7291", "{stop}");
    let said = leg["decoded_as"]
        .as_str()
        .ok_or_else(|| format!("decoded_as: {stop}"))?;
    assert!(said.contains(CORE_LAYER), "{said}");
    assert!(said.contains("sent at 32 kbit/s"), "{said}");
    let rtp = datagrams
        .iter()
        .filter(|d| d.first().is_some_and(|b| b >> 6 == 2));
    assert!(rtp.count() > 0, "the audio is sent");
    Ok(())
}

// ── S9 ─────────────────────────────────────────────────────────────────

/// Malformed payloads (empty, a header alone, a frame cut short, a
/// remainder that is no SID) never stop the run, and no audio comes from
/// octets that are not a whole core: the empty payload is a lost packet,
/// concealed, and the others decode only their whole frames.
#[test]
fn s9_malformed_packets_never_panic_and_yield_no_partial_audio() -> Result<(), TestError> {
    let home = installed()?;
    let cores = sample_frames()?;
    let mut packets = speech_packets(0, &cores[..20], 1);
    let mut tail = speech_payload(0, &cores[20..22]);
    tail.extend_from_slice(&[0x11; 5]);
    let bad: [Vec<u8>; 4] = [
        Vec::new(),
        vec![0xf0],
        speech_payload(0, &cores[20..22])[..16].to_vec(),
        tail,
    ];
    for (k, payload) in bad.into_iter().enumerate() {
        packets.push(Packet {
            seq: 10 + k as u16,
            ts: (10 + k as u32) * 320,
            payload,
        });
    }
    packets.push(Packet {
        seq: 14,
        ts: 14 * 320,
        payload: speech_payload(0, &cores[22..24]),
    });
    let pcap = capture(home.path(), &packets)?;
    let out = export_run(home.path(), &pcap)?;
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    let vcon: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let text = vcon.to_string();
    // An RTP packet with an empty payload carries nothing to retain, so it
    // is a packet missing from the stream, not a payload that failed.
    assert!(!text.contains("failed to decode"), "{text}");
    let (_, _, samples) = wav_samples(&recording_wav(&vcon)?)?;
    // Twenty cores, the empty payload's 20 ms concealed as a lost packet,
    // the header alone and the cut frame decoding nothing (their 40 ms is no
    // loss: their sequence numbers arrived), the frame with the stray 5
    // octets, then the last frame.
    let mut frames = voice(&cores[..20]);
    frames.extend([g729::Frame::Erased; 2]);
    frames.extend([g729::Frame::NoTx; 4]);
    frames.extend(voice(&cores[20..24]));
    let want = reference(&tables(home.path())?, &frames);
    assert_eq!(
        first_difference(&samples, &want),
        None,
        "the export left the reference"
    );
    Ok(())
}
