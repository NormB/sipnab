// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Shared helpers of the g729 integration tests: where the fetched ITU files
//! live, and the tables imported from them.
//!
//! The test vectors and the table sources are never committed (spec decision
//! D4). A missing file FAILS the test with the command that fetches it; it is
//! never a skip (spec decision D5).

#[cfg(g729_oracle)]
pub mod trace;

use std::path::PathBuf;
use std::sync::OnceLock;

/// The command that fetches everything these tests read.
pub const FETCH: &str = "python3 scripts/fetch-g729-vectors.py";

/// The result type of the tests: a failure is an error, never a panic.
pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The directory `scripts/fetch-g729-vectors.py` fills: `$G729_VECTORS`,
/// else `crates/g729/test-vectors`.
pub fn vectors_dir() -> Result<PathBuf, String> {
    let dir = std::env::var_os("G729_VECTORS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors"));
    if dir.join("itu-source").is_dir() && dir.join("annex-a").is_dir() {
        Ok(dir)
    } else {
        Err(format!(
            "G.729 test files missing under {}: run `{FETCH}` from the repository root",
            dir.display()
        ))
    }
}

/// The extracted ITU source directory the importer reads.
pub fn source_dir() -> Result<PathBuf, String> {
    Ok(vectors_dir()?.join("itu-source"))
}

/// A fetched file, or an error naming the fetch command.
pub fn read_vector(rel: &str) -> Result<Vec<u8>, String> {
    let path = vectors_dir()?.join(rel);
    std::fs::read(&path).map_err(|e| {
        format!(
            "G.729 test vector {} unreadable ({e}): run `{FETCH}`",
            path.display()
        )
    })
}

/// The table file built by the real import path, once per test binary.
pub fn table_file() -> Result<&'static [u8], String> {
    static FILE: OnceLock<Result<Vec<u8>, String>> = OnceLock::new();
    FILE.get_or_init(|| {
        g729::import_from_itu(&source_dir()?)
            .map_err(|e| format!("import_from_itu failed: {e}; run `{FETCH}`"))
    })
    .as_deref()
    .map_err(Clone::clone)
}

/// The tables loaded from [`table_file`].
pub fn tables() -> Result<&'static g729::Tables, String> {
    static TABLES: OnceLock<Result<g729::Tables, String>> = OnceLock::new();
    TABLES
        .get_or_init(|| {
            g729::Tables::from_bytes(table_file()?).map_err(|e| format!("imported table file: {e}"))
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Every 16-bit little-endian sample of a PCM file.
pub fn samples(bytes: &[u8]) -> Vec<i16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| i16::from_le_bytes(*b))
        .collect()
}

/// Decode a G.192 file from a fresh decoder.
pub fn decode_g192(tables: &g729::Tables, input: &[u8], name: &str) -> Result<Vec<i16>, String> {
    use g729::bitstream;
    use g729::{Decoder, FRAME_SAMPLES};
    let mut dec = Decoder::new(tables);
    let mut out = Vec::new();
    let mut pcm = [0i16; FRAME_SAMPLES];
    for frame in bitstream::g192_frames(input) {
        let frame = frame.map_err(|e| format!("{name}: {e}"))?;
        dec.decode(frame.frame(), &mut pcm);
        out.extend_from_slice(&pcm);
    }
    Ok(out)
}

/// Require every sample equal; otherwise an error naming the first
/// differing frame and sample and the count of differing samples.
pub fn compare(name: &str, got: &[i16], expected: &[i16]) -> Result<(), String> {
    use g729::FRAME_SAMPLES;
    if got.len() != expected.len() {
        return Err(format!(
            "{name}: {} samples decoded, {} expected",
            got.len(),
            expected.len()
        ));
    }
    let mut diffs = (0..got.len()).filter(|&i| got[i] != expected[i]);
    let Some(first) = diffs.next() else {
        return Ok(());
    };
    Err(format!(
        "{name}: first difference at frame {}, sample {} (decoded {}, expected {}); {} of {} samples differ",
        first / FRAME_SAMPLES,
        first % FRAME_SAMPLES,
        got[first],
        expected[first],
        1 + diffs.count(),
        got.len()
    ))
}

/// The 16 decoder conformance pairs (input bit stream, expected output),
/// relative to the vectors directory (spec fact F4).
pub const PAIRS: [(&str, &str); 16] = [
    ("annex-a/ALGTHM.BIT", "annex-a/ALGTHM.PST"),
    ("annex-a/ERASURE.BIT", "annex-a/ERASURE.PST"),
    ("annex-a/FIXED.BIT", "annex-a/FIXED.PST"),
    ("annex-a/LSP.BIT", "annex-a/LSP.PST"),
    ("annex-a/OVERFLOW.BIT", "annex-a/OVERFLOW.PST"),
    ("annex-a/PARITY.BIT", "annex-a/PARITY.PST"),
    ("annex-a/PITCH.BIT", "annex-a/PITCH.PST"),
    ("annex-a/SPEECH.BIT", "annex-a/SPEECH.PST"),
    ("annex-a/TAME.BIT", "annex-a/TAME.PST"),
    ("annex-a/TEST.BIT", "annex-a/TEST.pst"),
    ("annex-b/tstseq1a.bit", "annex-b/tstseq1a.out"),
    ("annex-b/tstseq2a.bit", "annex-b/tstseq2a.out"),
    ("annex-b/tstseq3a.bit", "annex-b/tstseq3a.out"),
    ("annex-b/tstseq4a.bit", "annex-b/tstseq4a.out"),
    ("annex-b/tstseq5.bit", "annex-b/tstseq5a.out"),
    ("annex-b/tstseq6.bit", "annex-b/tstseq6a.out"),
];

/// One frame of a G.729.1 ITU-T G.192 file (the format the G.729.1 package's
/// readme gives: a synchronization word, a size word, then one word per bit,
/// 0x0081 for 1 and 0x007F for 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct G7291Serial {
    /// Whether the synchronization word is 0x6B21 (a good frame).
    pub good: bool,
    /// The frame's bit count: 0 untransmitted, 15, 24 or 43 a SID, 160 to
    /// 640 a frame at 8 to 32 kbit/s.
    pub bits: usize,
    /// The bits packed most significant first, zero-padded to whole octets:
    /// the frame as RFC 4749 carries it.
    pub octets: Vec<u8>,
}

/// Every frame of a G.729.1 G.192 file.
pub fn g7291_g192(bytes: &[u8], name: &str) -> Result<Vec<G7291Serial>, String> {
    let words: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|w| u16::from_le_bytes(*w))
        .collect();
    let mut frames = Vec::new();
    let mut at = 0;
    while at < words.len() {
        let (Some(&sync), Some(&size)) = (words.get(at), words.get(at + 1)) else {
            return Err(format!("{name}: truncated header at word {at}"));
        };
        let bits = usize::from(size);
        let body = words
            .get(at + 2..at + 2 + bits)
            .ok_or_else(|| format!("{name}: truncated frame at word {at}"))?;
        let mut octets = vec![0u8; bits.div_ceil(8)];
        for (k, word) in body.iter().enumerate() {
            match word {
                0x0081 => octets[k / 8] |= 0x80 >> (k % 8),
                0x007f | 0 => {}
                other => return Err(format!("{name}: bit word {other:#06x} at word {at}")),
            }
        }
        frames.push(G7291Serial {
            good: sync == g729::bitstream::SYNC_GOOD,
            bits,
            octets,
        });
        at += 2 + bits;
    }
    Ok(frames)
}

/// The frames of a G.729-format G.192 file of the G.729.1 package, whose
/// SID frames are 15 bits (the G.729 package's are 16, the last a pad bit).
pub fn g729_serial(bytes: &[u8], name: &str) -> Result<Vec<g729::bitstream::SerialFrame>, String> {
    use g729::bitstream::SerialFrame;
    g7291_g192(bytes, name)?
        .into_iter()
        .map(
            |frame| match (frame.good, frame.bits, frame.octets.as_slice()) {
                (false, _, _) => Ok(SerialFrame::Erased),
                (true, 0, _) => Ok(SerialFrame::NoTx),
                (true, 15 | 16, &[first, second]) => Ok(SerialFrame::Sid([first, second & 0xfe])),
                (true, 80, octets) => octets
                    .try_into()
                    .map(SerialFrame::Speech)
                    .map_err(|_| format!("{name}: an 80-bit frame")),
                (true, bits, _) => Err(format!("{name}: a G.729 frame of {bits} bits")),
            },
        )
        .collect()
}
