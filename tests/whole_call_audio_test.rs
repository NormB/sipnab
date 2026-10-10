// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--retain-audio` keeps WHOLE calls, and says so when it cannot.
//!
//! Until 2026-10 every stream's retained payload was a ring of 1500 frames,
//! 30 seconds of 20 ms G.711. A 60 second call exported with `--retain-audio`
//! kept only its last 30 seconds, and the vCon said PARTIAL. The default is
//! now the whole call, bounded instead by one retention budget across every
//! stream, `[limits] max_audio_bytes`.
//!
//! Every test here drives the shipped binary over a synthetic capture whose
//! audio is known byte for byte, decodes the WAV the vCon carries, and
//! compares it with what was on the wire. Three properties, each with the
//! case that would pass vacuously beside it:
//!
//! * with default limits, a 60 second and a 10 minute call come back whole:
//!   every frame, every sample, in order, and no PARTIAL note;
//! * an explicit `[limits] max_audio_frames` still caps each stream, and the
//!   vCon names the frames it dropped;
//! * a `[limits] max_audio_bytes` budget below the call's size stops retention
//!   at the budget, and the vCon names the budget and the frames it released.
#![cfg(all(feature = "native", feature = "vcon"))]

#[path = "support/pcap_build.rs"]
mod pcap_build;

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sipnab::rtp::g711::{G711Codec, decode_frame};

type TestError = Box<dyn std::error::Error>;

/// The synthetic call's Call-ID.
const CALL_ID: &str = "whole-call-audio@10.0.0.1";

/// Payload bytes per frame: 20 ms of 8 kHz G.711.
const FRAME_BYTES: usize = 160;

/// Frames per second per stream at 20 ms packetization.
const FRAMES_PER_SEC: usize = 50;

/// The mu-law byte the capture carries in `frame` of the stream `stream`
/// (0 = caller, 1 = callee), at payload offset `i`.
///
/// Distinct per frame and per stream, so a dropped, duplicated or reordered
/// frame, or the two channels swapped, changes the decoded samples.
fn payload_byte(stream: usize, frame: usize, i: usize) -> u8 {
    ((frame * 31 + i * 7 + stream * 101) % 251) as u8
}

/// Write a capture of one answered G.711 call lasting `secs` seconds, media
/// both ways at 20 ms, carrying [`payload_byte`], and return its path.
fn write_call(dir: &Path, secs: usize) -> Result<PathBuf, TestError> {
    let frames = pcap_build::g711_call_both_ways(CALL_ID, secs, payload_byte);
    let path = dir.join(format!("call-{secs}s.pcap"));
    pcap_build::write_pcap_at(&path, &frames, 1)?;
    Ok(path)
}

/// Export the call's vCon with `--retain-audio`, optionally under a config
/// file holding `limits_toml` in its `[limits]` table.
fn export(
    dir: &Path,
    pcap: &Path,
    limits_toml: Option<&str>,
) -> Result<serde_json::Value, TestError> {
    let pcap_s = pcap.display().to_string();
    let mut args: Vec<String> = [
        "-N",
        "-q",
        "--no-cli-print",
        "-I",
        &pcap_s,
        "--retain-audio",
        // A 10 minute stereo WAV is about 19 MB, over the 5 MiB default
        // inline budget; that budget is a different limit from the one under
        // test, so it is raised out of the way.
        "--vcon-max-inline-media",
        "64",
        "--export-vcon",
        CALL_ID,
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    if let Some(limits) = limits_toml {
        let config = dir.join("limits.toml");
        std::fs::write(&config, format!("[limits]\n{limits}\n"))?;
        args.push("--config".to_owned());
        args.push(config.display().to_string());
    }
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(&args)
        .env("NO_COLOR", "1")
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "export failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

/// The WAV the container carries: its channel count and the samples of each
/// channel.
fn carried_channels(vcon: &serde_json::Value) -> Result<Vec<Vec<i16>>, TestError> {
    let recording = vcon["dialog"]
        .as_array()
        .ok_or("dialog is an array")?
        .iter()
        .find(|d| d["type"] == "recording" && d.get("body").is_some())
        .ok_or_else(|| format!("no recording carries audio: {:#}", vcon["dialog"]))?;
    let body = recording["body"].as_str().ok_or("body is a string")?;
    let wav = URL_SAFE_NO_PAD.decode(body)?;
    if wav.get(0..4) != Some(b"RIFF") || wav.get(8..12) != Some(b"WAVE") {
        return Err("the body is not a RIFF/WAVE file".into());
    }
    let mut at = 12;
    let mut channels = 0usize;
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
            let samples: Vec<i16> = chunk
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| i16::from_le_bytes(*b))
                .collect();
            let mut out = vec![Vec::new(); channels];
            for (n, s) in samples.into_iter().enumerate() {
                out[n % channels].push(s);
            }
            return Ok(out);
        }
        at += 8 + len + (len & 1);
    }
    Err("the WAV has no data chunk".into())
}

/// The samples stream `stream` carried on the wire, frames `from..to`.
fn wire_samples(stream: usize, from: usize, to: usize) -> Vec<i16> {
    (from..to)
        .flat_map(|frame| {
            let bytes: Vec<u8> = (0..FRAME_BYTES)
                .map(|i| payload_byte(stream, frame, i))
                .collect();
            decode_frame(G711Codec::Ulaw, &bytes)
        })
        .collect()
}

/// The `capture_completeness.media_note` of the container's analysis.
fn media_note(vcon: &serde_json::Value) -> Result<String, TestError> {
    let analysis = vcon["analysis"]
        .as_array()
        .ok_or("analysis is an array")?
        .first()
        .ok_or("one analysis entry")?;
    let body: serde_json::Value = match &analysis["body"] {
        serde_json::Value::String(s) => serde_json::from_str(s)?,
        other => other.clone(),
    };
    Ok(body["capture_completeness"]["media_note"]
        .as_str()
        .ok_or_else(|| format!("no media_note: {:#}", body["capture_completeness"]))?
        .to_owned())
}

/// Assert both channels hold every frame of a `secs` second call, sample for
/// sample, and the container says nothing is missing.
fn assert_whole(vcon: &serde_json::Value, secs: usize) -> Result<(), TestError> {
    let channels = carried_channels(vcon)?;
    assert_eq!(channels.len(), 2, "both directions are carried");
    let frames = secs * FRAMES_PER_SEC;
    let expected = [wire_samples(0, 0, frames), wire_samples(1, 0, frames)];
    for (n, channel) in channels.iter().enumerate() {
        assert_eq!(
            channel.len(),
            frames * FRAME_BYTES,
            "channel {n} holds {} of {} samples: {:.1} s of a {secs} s call",
            channel.len(),
            frames * FRAME_BYTES,
            channel.len() as f64 / 8000.0
        );
        assert!(
            expected.iter().any(|e| e == channel),
            "channel {n} is not the audio either stream carried, in order"
        );
    }
    assert_ne!(
        channels[0], channels[1],
        "the channels are the two directions"
    );
    let note = media_note(vcon)?;
    assert!(
        !note.contains("PARTIAL"),
        "a whole call says nothing is missing: {note}"
    );
    assert!(
        !vcon["dialog"]
            .as_array()
            .ok_or("dialog is an array")?
            .iter()
            .any(|d| d["type"] == "recording-set"),
        "a whole call needs no recording-set"
    );
    Ok(())
}

/// A 60 second call, default limits: every frame of both directions.
///
/// The case that motivated the change: under the old 1500-frame ring this
/// export held the last 30 seconds and said PARTIAL.
#[test]
fn a_sixty_second_call_is_exported_whole_by_default() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = write_call(dir.path(), 60)?;
    let vcon = export(dir.path(), &pcap, None)?;
    assert_whole(&vcon, 60)
}

/// A 10 minute call, default limits and so the default budget: whole.
#[test]
fn a_ten_minute_call_is_exported_whole_by_default() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = write_call(dir.path(), 600)?;
    let vcon = export(dir.path(), &pcap, None)?;
    assert_whole(&vcon, 600)
}

/// An explicit `[limits] max_audio_frames` still caps each stream, keeps the
/// END of the call, and the vCon counts the frames dropped from both streams.
#[test]
fn an_explicit_frame_cap_still_caps_and_says_partial() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = write_call(dir.path(), 60)?;
    let vcon = export(dir.path(), &pcap, Some("max_audio_frames = 1000"))?;
    let channels = carried_channels(&vcon)?;
    let expected = [wire_samples(0, 2000, 3000), wire_samples(1, 2000, 3000)];
    for channel in &channels {
        assert_eq!(
            channel.len(),
            1000 * FRAME_BYTES,
            "the cap holds 1000 frames"
        );
        assert!(
            expected.iter().any(|e| e == channel),
            "the cap keeps the last 1000 frames of the stream"
        );
    }
    let note = media_note(&vcon)?;
    assert!(
        note.contains("PARTIAL: the payload ring wrapped and dropped 4000 earlier frame(s)"),
        "3000 frames into a cap of 1000 drops 2000 per stream, 4000 in all: {note}"
    );
    Ok(())
}

/// A budget below the call's size stops retention at the budget, and the
/// vCon names the budget and the frames it released.
///
/// 1 MiB is the smallest budget the config accepts. The call carries 6000
/// frames of 160 bytes. The store charges each frame 232 bytes for its payload
/// allocation, and each stream's buffer 32 bytes per slot of capacity, so
/// between 264 bytes per frame (every buffer exactly full) and 296 (every
/// buffer just doubled) are charged. That bounds how many frames
/// fit, and so how many must have been released, from both sides.
#[test]
fn a_reached_budget_releases_audio_and_says_partial() -> Result<(), TestError> {
    use sipnab::rtp::stream_store::{AUDIO_SLOT_BYTES, audio_payload_charge};
    const BUDGET: usize = 1_048_576;
    let dir = tempfile::tempdir()?;
    let pcap = write_call(dir.path(), 60)?;
    let vcon = export(dir.path(), &pcap, Some("max_audio_bytes = 1048576"))?;
    let note = media_note(&vcon)?;
    let lead = "PARTIAL: the [limits] max_audio_bytes retention budget was reached and released ";
    let released: usize = note
        .split(lead)
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .ok_or_else(|| format!("the note names the budget and the count: {note}"))?
        .parse()?;
    let per_frame = audio_payload_charge(FRAME_BYTES);
    let most_kept = BUDGET / (per_frame + AUDIO_SLOT_BYTES);
    let least_kept = BUDGET / (per_frame + 2 * AUDIO_SLOT_BYTES);
    assert!(
        (6000 - most_kept..=6000 - least_kept).contains(&released),
        "{released} released; a 1 MiB budget keeps between {least_kept} and {most_kept} \
         of 6000 frames"
    );
    let channels = carried_channels(&vcon)?;
    let whole_newer = wire_samples(1, 0, 3000);
    assert!(
        channels.contains(&whole_newer),
        "the newer stream stays whole while the older one is released first"
    );
    // A stereo WAV pads its shorter channel with silence at the end, so the
    // older stream's channel is its last frames followed by zeros.
    let mut older = wire_samples(0, released, 3000);
    older.resize(whole_newer.len(), 0);
    assert!(
        channels.contains(&older),
        "the older stream keeps its last {} frames, in order",
        3000 - released
    );
    assert!(
        vcon["dialog"]
            .as_array()
            .ok_or("dialog is an array")?
            .iter()
            .any(|d| d["type"] == "recording-set"),
        "a file missing the start of the call is wrapped in a recording-set"
    );
    Ok(())
}
