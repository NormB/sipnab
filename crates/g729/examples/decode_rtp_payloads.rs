// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Decode G.729 RTP payloads, listed one per line in a text file, to a
//! 16-bit mono WAV file at 8000 Hz.
//!
//! ```text
//! cargo run -p sipnab-g729 --features std --example decode_rtp_payloads -- TABLES PAYLOADS.txt OUT.wav
//! ```
//!
//! TABLES is the table file that the `import_tables` example writes. Each
//! line of PAYLOADS.txt is one RTP payload in hexadecimal (the bytes after
//! the RTP header), in sequence-number order. A line holding the word `LOST`
//! marks a packet that did not arrive. Blank lines and lines starting with
//! `#` are skipped. `examples/payloads.txt` is a sample.
//!
//! A payload is 10 octets per 10 ms frame, optionally followed by one
//! 2-octet SID frame (RFC 3551 section 4.5.6). The example splits each
//! payload with `bitstream::split_rtp` and decodes the frames, then the SID
//! frame. For a lost packet it decodes `Frame::Erased` once per frame of the
//! packet before it, the usual length of a packet in the stream, so the
//! output keeps its timing and the decoder conceals the gap.

#[path = "support/wav.rs"]
mod wav;

use g729::bitstream::split_rtp;
use g729::{Decoder, FRAME_SAMPLES, Frame, Tables};

/// The bytes of a hexadecimal string, or why it is not one.
fn hex_bytes(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            text.get(at..at + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("not hex at column {}", at + 1))
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let (Some(tables), Some(input), Some(output)) = (args.next(), args.next(), args.next()) else {
        return Err("usage: decode_rtp_payloads TABLES PAYLOADS.txt OUT.wav".into());
    };
    let tables = Tables::from_bytes(&std::fs::read(&tables)?)?;
    let mut decoder = Decoder::new(&tables);
    let text = std::fs::read_to_string(&input)?;

    let mut pcm: Vec<i16> = Vec::new();
    let mut frame_pcm = [0i16; FRAME_SAMPLES];
    let (mut packets, mut lost, mut voice_frames, mut sid_frames, mut concealed) = (0, 0, 0, 0, 0);
    // Frames in the last packet that arrived: the length assumed for a lost one.
    let mut frames_per_packet = 1;
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        packets += 1;
        if line == "LOST" {
            lost += 1;
            for _ in 0..frames_per_packet {
                decoder.decode(Frame::Erased, &mut frame_pcm);
                pcm.extend_from_slice(&frame_pcm);
                concealed += 1;
            }
            continue;
        }
        let payload = hex_bytes(line).map_err(|e| format!("line {}: {e}", index + 1))?;
        // 10n octets of frames, then an optional 2-octet SID frame.
        let (voice, sid) = split_rtp(&payload).map_err(|length| {
            format!(
                "line {}: a payload of {} octets is neither 10n nor 10n + 2",
                index + 1,
                length.0
            )
        })?;
        for frame in voice {
            decoder.decode(Frame::Voice(frame), &mut frame_pcm);
            pcm.extend_from_slice(&frame_pcm);
        }
        if let Some(sid) = sid {
            decoder.decode(Frame::Sid(sid), &mut frame_pcm);
            pcm.extend_from_slice(&frame_pcm);
        }
        voice_frames += voice.len();
        sid_frames += usize::from(sid.is_some());
        let frames = voice.len() + usize::from(sid.is_some());
        if frames > 0 {
            frames_per_packet = frames;
        }
    }
    std::fs::write(&output, wav::wav_bytes(&pcm)?)?;
    println!(
        "{packets} packets ({lost} lost): {voice_frames} speech frames, {sid_frames} SID frames, \
         {concealed} concealed frames; {} samples, written to {}",
        pcm.len(),
        std::path::Path::new(&output).display()
    );
    Ok(())
}
