// SPDX-License-Identifier: MIT OR Apache-2.0

//! WAV export decodes a buffer the capture run has to have filled.
//!
//! `export_dialog_to_wav` reads `RtpStream::payload_buffer`, and that buffer
//! is only written when the stream store has audio payload RETENTION on. The
//! decision is made once, when the run builds its stores, and it is invisible
//! from the export: a call whose media sipnab measured in full looks exactly
//! like a call with no media once retention was off.
//!
//! That is not a hypothetical. sipnab's MCP `export_audio` tool runs in batch
//! mode, and batch mode used to turn retention off unconditionally, so the tool
//! could not succeed for any call in any capture — it failed saying "No audio
//! streams with captured data found", which reads as a statement about the call
//! rather than about the run. A batch run now retains exactly when it is an MCP
//! run AND the operator passed `--retain-audio` — the only batch configuration
//! that can read the buffers back, gated on explicit consent because call
//! audio is content, not signalling (`app::batch::apply_audio_retention`).
//!
//! Both halves stay worth pinning against a real capture, because both are
//! still reachable — the second is what every non-MCP batch run does:
//!
//! - With retention on — what any run that intends to export audio must do —
//!   the export produces a WAV of the media that was actually on the wire.
//! - With retention off, the export refuses, and its refusal reports the
//!   measurement (packets, codec) and names retention, rather than denying the
//!   call had audio.

#![cfg(feature = "native")]

use std::path::PathBuf;

use parking_lot::RwLock;
use std::sync::Arc;

use sipnab::capture::Packet;
use sipnab::capture::parse::parse_packet;
use sipnab::capture::pcap_reader::PcapReader;
use sipnab::pipeline::{self, MediaDecrypt, PipelineOptions};
use sipnab::rtp::audio_export::export_dialog_to_wav;
use sipnab::rtp::heuristic::RtpHeuristic;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;

/// A checked-in SIP + G.711 capture: one call, PCMU media both ways.
const SAMPLE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// Replay `SAMPLE` through the real pipeline into fresh stores, and return
/// them with the Call-ID of the first dialog seen.
///
/// `retain_audio` is the one setting under test: `true` is a stream store's
/// default, `false` is what batch mode does to it.
fn replay(retain_audio: bool) -> (Arc<RwLock<DialogStore>>, Arc<RwLock<StreamStore>>, String) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SAMPLE);
    let bytes = std::fs::read(&path).expect("read sample capture");

    let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
    let ss = Arc::new(RwLock::new(StreamStore::new(100)));
    ss.write().set_audio_capture(retain_audio);
    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions {
        // The sample's signalling is on 5060, but do not make the test depend
        // on that: the gate exists for live capture.
        sip_portrange: None,
        ..Default::default()
    };

    let reader = PcapReader::new(&bytes).expect("open sample capture");
    for pkt in reader {
        let ts = chrono::DateTime::from_timestamp(
            i64::from(pkt.timestamp_secs),
            pkt.timestamp_usecs.saturating_mul(1000),
        )
        .expect("valid capture timestamp");
        let len = pkt.data.len();
        let packet = Packet::new(
            ts,
            pkt.data,
            len,
            pkt.orig_len as usize,
            pkt.interface,
            pkt.link_type as i32,
        );
        let Ok(parsed) = parse_packet(&packet) else {
            continue;
        };
        let mut decrypt = MediaDecrypt::default();
        pipeline::process_packet(&parsed, &ds, &ss, &mut heuristic, &opts, &mut decrypt);
    }

    let call_id = ds
        .read()
        .iter()
        .next()
        .map(|d| d.call_id.clone())
        .expect("the sample capture holds at least one dialog");
    (ds, ss, call_id)
}

/// Read a WAV header the way any player does: RIFF/WAVE magic, then the fmt
/// chunk's channel count, sample rate and bits per sample, then the data
/// chunk's byte length. Hand-read so the assertion does not go through the
/// code that wrote it.
fn wav_header(path: &std::path::Path) -> (u16, u32, u16, usize) {
    let b = std::fs::read(path).expect("read wav");
    assert!(b.len() > 44, "a WAV needs a header and some samples");
    assert_eq!(&b[0..4], b"RIFF", "not a RIFF file");
    assert_eq!(&b[8..12], b"WAVE", "not a WAVE file");
    let channels = u16::from_le_bytes(b[22..24].try_into().expect("2 bytes"));
    let rate = u32::from_le_bytes(b[24..28].try_into().expect("4 bytes"));
    let bits = u16::from_le_bytes(b[34..36].try_into().expect("2 bytes"));
    let data_len = u32::from_le_bytes(b[40..44].try_into().expect("4 bytes")) as usize;
    (channels, rate, bits, data_len)
}

/// With retention on, a real capture exports real audio: the samples are the
/// call's G.711 media, decoded at its clock rate, and they are not silence.
#[test]
fn retained_payload_exports_the_call_audio() {
    let (_ds, ss, call_id) = replay(true);
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("call.wav");

    let store = ss.read();
    let streams: Vec<&sipnab::rtp::stream::RtpStream> = store.streams_for(&call_id).collect();
    assert!(
        !streams.is_empty(),
        "the sample capture's call must have RTP streams"
    );

    let summary = export_dialog_to_wav(&streams, &path).expect("retained audio must export");
    assert!(
        summary.contains("mu-law") || summary.contains("A-law"),
        "the sample is G.711: {summary}"
    );

    let (channels, rate, bits, data_len) = wav_header(&path);
    assert!(
        (1..=2).contains(&channels),
        "mono or stereo, got {channels}"
    );
    assert_eq!(rate, 8000, "G.711 decodes at its 8 kHz clock");
    assert_eq!(bits, 16, "export is 16-bit linear PCM");
    assert!(
        data_len >= 8000 * usize::from(channels),
        "at least half a second of audio, got {data_len} bytes"
    );

    // Not a file of zeroes: an export that silently wrote silence would pass
    // every structural check above.
    let bytes = std::fs::read(&path).expect("read wav");
    assert!(
        bytes[44..].iter().any(|&b| b != 0),
        "the exported samples must be the captured audio, not silence"
    );
}

/// With retention off — what batch mode, and so every MCP `export_audio`
/// call, does today — the export cannot succeed, and must not pretend the
/// call had no audio. It reports what sipnab measured and names retention.
#[test]
fn unretained_payload_refuses_and_names_retention() {
    let (_ds, ss, call_id) = replay(false);
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("call.wav");

    let store = ss.read();
    let streams: Vec<&sipnab::rtp::stream::RtpStream> = store.streams_for(&call_id).collect();
    assert!(
        !streams.is_empty(),
        "the streams are tracked either way — only their payload is not kept"
    );
    let observed: u64 = streams.iter().map(|s| s.packet_count).sum();
    assert!(observed > 0, "sipnab measured the media");

    let err = export_dialog_to_wav(&streams, &path).expect_err("nothing was retained to decode");
    let msg = err.to_string();

    assert!(
        msg.contains(&observed.to_string()),
        "the refusal must report the {observed} packets sipnab measured: {msg}"
    );
    assert!(
        msg.contains("retention") || msg.contains("retained"),
        "the refusal must name retention as the reason: {msg}"
    );
    assert!(
        !msg.contains("No audio streams with captured data"),
        "the old wording denies the call had audio: {msg}"
    );
    assert!(!path.exists(), "a refused export leaves no file behind");
}
