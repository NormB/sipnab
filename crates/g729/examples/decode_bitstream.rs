// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Decode an ITU-T G.192 serial file (the `.BIT` / `.bit` test vectors of the
//! ITU-T G.729 package) to a 16-bit mono WAV file at 8000 Hz.
//!
//! ```text
//! cargo run -p sipnab-g729 --features std --example decode_bitstream -- TABLES IN.BIT OUT.wav
//! ```
//!
//! TABLES is the table file that the `import_tables` example writes. Each
//! G.192 frame becomes one 10 ms decoder frame: speech, SID, untransmitted
//! (`Frame::NoTx`) or erased (`Frame::Erased`), so the WAV holds 80 samples
//! per frame of the input. The WAV's sample data equals the ITU-T expected
//! output file (`.PST` / `.out`) byte for byte; `tests/examples.rs` checks it.

#[path = "support/wav.rs"]
mod wav;

use g729::bitstream::{SerialFrame, g192_frames};
use g729::{Decoder, FRAME_SAMPLES, Tables};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let (Some(tables), Some(input), Some(output)) = (args.next(), args.next(), args.next()) else {
        return Err("usage: decode_bitstream TABLES IN.BIT OUT.wav".into());
    };
    let tables = Tables::from_bytes(&std::fs::read(&tables)?)?;
    let mut decoder = Decoder::new(&tables);
    let bitstream = std::fs::read(&input)?;

    let mut pcm: Vec<i16> = Vec::new();
    let mut counts = [0usize; 4];
    let mut frame_pcm = [0i16; FRAME_SAMPLES];
    for serial in g192_frames(&bitstream) {
        let serial = serial?;
        counts[match serial {
            SerialFrame::Speech(_) => 0,
            SerialFrame::Sid(_) => 1,
            SerialFrame::NoTx => 2,
            SerialFrame::Erased => 3,
        }] += 1;
        decoder.decode(serial.frame(), &mut frame_pcm);
        pcm.extend_from_slice(&frame_pcm);
    }
    std::fs::write(&output, wav::wav_bytes(&pcm)?)?;
    println!(
        "{} frames ({} speech, {} SID, {} untransmitted, {} erased), {} samples, written to {}",
        counts.iter().sum::<usize>(),
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        pcm.len(),
        std::path::Path::new(&output).display()
    );
    Ok(())
}
