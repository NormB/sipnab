// SPDX-License-Identifier: MIT OR Apache-2.0

//! Retained audio stays with its own call when two calls reuse one SSRC.
//!
//! Two features meet here. Since 0.5.212 a stream that reuses an SSRC and
//! socket pair after an earlier call is a new session of its own (#465), and
//! since 0.5.214 `--retain-audio` keeps each stream's whole audio under one
//! `[limits] max_audio_bytes` budget. Each was tested alone; this runs both
//! on one capture. The capture is [`pcap_build::calls_reusing_media`]: two
//! complete calls, one after the other, with identical SSRCs and sockets, each
//! carrying one second of PCMU each way (50 packets of 160 samples).
//!
//! Each call's vCon must carry exactly its own second of audio per direction:
//! 8000 samples per channel. 16000 would mean the second call's audio was
//! appended to the first call's stream; 0 or a short count would mean the
//! second session lost frames to the first one's retention.

#[path = "support/pcap_build.rs"]
mod pcap_build;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pcap_build::{REUSED_MEDIA_AUDIO_PACKETS, calls_reusing_media, write_pcap_at};

type TestError = Box<dyn std::error::Error>;

const CALLS: [&str; 2] = ["reuse-1@10.0.0.1", "reuse-2@10.0.0.1"];

/// Samples one PCMU packet of the fixture carries.
const SAMPLES_PER_PACKET: usize = 160;

/// Export `call_id`'s vCon from `pcap` with its audio retained.
fn export(pcap: &std::path::Path, call_id: &str) -> Result<serde_json::Value, TestError> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "-q", "--no-cli-print", "-I"])
        .arg(pcap)
        .args(["--retain-audio", "--export-vcon", call_id])
        .env("NO_COLOR", "1")
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "export of {call_id} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

/// The sample count of each channel of the WAV the container carries.
fn channel_lengths(vcon: &serde_json::Value) -> Result<Vec<usize>, TestError> {
    let recording = vcon["dialog"]
        .as_array()
        .ok_or("dialog is an array")?
        .iter()
        .find(|d| d["type"] == "recording" && d.get("body").is_some())
        .ok_or_else(|| format!("no recording carries audio: {:#}", vcon["dialog"]))?;
    let wav = URL_SAFE_NO_PAD.decode(recording["body"].as_str().ok_or("body is a string")?)?;
    if wav.get(0..4) != Some(b"RIFF") || wav.get(8..12) != Some(b"WAVE") {
        return Err("the body is not a RIFF/WAVE file".into());
    }
    let (mut at, mut channels) = (12usize, 0usize);
    while at + 8 <= wav.len() {
        let id = &wav[at..at + 4];
        let len = u32::from_le_bytes(wav[at + 4..at + 8].try_into()?) as usize;
        let chunk = wav
            .get(at + 8..at + 8 + len)
            .ok_or("a chunk runs past the file")?;
        if id == b"fmt " {
            channels = usize::from(u16::from_le_bytes(chunk[2..4].try_into()?));
        } else if id == b"data" {
            if channels == 0 {
                return Err("data before fmt".into());
            }
            let samples = chunk.len() / 2;
            return Ok(vec![samples / channels; channels]);
        }
        at += 8 + len + (len & 1);
    }
    Err("the WAV has no data chunk".into())
}

#[test]
fn each_call_reusing_an_ssrc_keeps_exactly_its_own_audio() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = dir.path().join("reused-media.pcap");
    write_pcap_at(&pcap, &calls_reusing_media(&CALLS, 8_000), 1)?;

    let want = usize::from(REUSED_MEDIA_AUDIO_PACKETS) * SAMPLES_PER_PACKET;
    for call in CALLS {
        let lengths = channel_lengths(&export(&pcap, call)?)?;
        assert_eq!(
            lengths,
            vec![want, want],
            "{call}: each direction carries {want} samples on the wire; the \
             container must hold exactly those, not the other call's as well"
        );
    }
    Ok(())
}
