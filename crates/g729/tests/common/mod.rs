// SPDX-License-Identifier: MIT OR Apache-2.0

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
