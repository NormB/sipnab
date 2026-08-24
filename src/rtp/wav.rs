// SPDX-License-Identifier: MIT OR Apache-2.0

//! WAV file writer (RIFF/WAVE PCM format).
//!
//! Writes 16-bit linear PCM WAV files with standard 44-byte headers.
//! Supports mono and stereo at arbitrary sample rates (typically 8000 Hz
//! for G.711 telephony audio).

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Write PCM samples to a WAV file.
///
/// Creates a standard RIFF WAVE file with:
/// - Format: PCM (format tag 1)
/// - Bit depth: 16 bits per sample
/// - Sample rate and channel count as specified
///
/// # Arguments
///
/// * `path` — Output file path
/// * `samples` — Interleaved 16-bit PCM samples (for stereo: L, R, L, R, ...)
/// * `sample_rate` — Samples per second per channel (e.g., 8000)
/// * `channels` — Number of audio channels (1 = mono, 2 = stereo)
pub fn write_wav(path: &Path, samples: &[i16], sample_rate: u32, channels: u16) -> Result<()> {
    write_wav_with_provenance(path, samples, sample_rate, channels, None)
}

/// Build the `LIST`/`INFO` chunk carrying a comment, or nothing for `None`.
///
/// `ICMT` is RIFF's comment field. The chunk is optional and unknown chunks
/// are skipped by every reader, so a player that has never heard of it plays
/// the audio unchanged -- the same property that lets the pcapng writer put a
/// section comment on an exported capture.
///
/// Sized and padded per RIFF: every chunk body is padded to an even length,
/// and the pad byte is NOT counted in the size field. Getting that wrong
/// shifts every following chunk by one byte, which is how a file with a
/// comment plays as noise.
fn info_chunk(comment: Option<&str>) -> Vec<u8> {
    let Some(comment) = comment else {
        return Vec::new();
    };
    // NUL-terminated per the INFO convention.
    let mut text: Vec<u8> = comment.as_bytes().to_vec();
    text.push(0);
    let icmt_size = text.len() as u32;
    let icmt_pad = usize::from(!text.len().is_multiple_of(2));

    let mut out = Vec::new();
    // LIST body = "INFO" + "ICMT" + size + text (+ pad)
    let list_size = 4 + 4 + 4 + text.len() + icmt_pad;
    out.extend_from_slice(b"LIST");
    out.extend_from_slice(&(list_size as u32).to_le_bytes());
    out.extend_from_slice(b"INFO");
    out.extend_from_slice(b"ICMT");
    out.extend_from_slice(&icmt_size.to_le_bytes());
    out.extend_from_slice(&text);
    if icmt_pad == 1 {
        out.push(0);
    }
    out
}

/// [`write_wav`], with a comment recorded inside the file.
///
/// An exported WAV used to be bytes and nothing else: no Call-ID, no source
/// capture, and no way to tell a file holding a whole call from one holding
/// the last thirty seconds of it. Everything sipnab knew about the export
/// lived in a string returned to whoever ran it, and was gone the moment that
/// scrolled away -- while the file went on being forwarded, attached to
/// tickets and played months later.
///
/// The pcapng writer already solved this with a section comment, for the same
/// reason and in the same words: it "reaches the engineer holding the file".
/// This is that, for audio.
pub fn write_wav_with_provenance(
    path: &Path,
    samples: &[i16],
    sample_rate: u32,
    channels: u16,
    comment: Option<&str>,
) -> Result<()> {
    let bytes = wav_bytes(samples, sample_rate, channels, comment);

    let mut file = std::fs::File::create(path)
        .with_context(|| format!("Failed to create WAV file: {}", path.display()))?;
    file.write_all(&bytes)?;
    file.flush()?;
    Ok(())
}

/// [`write_wav_with_provenance`], rendered to memory instead of to a path.
///
/// The one place the RIFF layout is written. A vCon carries its media INLINE —
/// `docs/design/vcon.md` §2.5 refuses a by-reference `url` because sipnab hosts
/// nothing — so the exporter needs the same bytes without a file to put them
/// in. Building them with a second writer would be two encoders of one format,
/// and the failure that invites is not a crash: it is a container whose
/// `content_hash` verifies against audio that differs from the `.wav` an
/// operator exported beside it, which reads as tampering rather than as drift.
///
/// The chunk order is load-bearing and is argued at the call site below: the
/// note follows `data` so a fixed-offset reader still finds the samples where a
/// classic 44-byte WAV puts them.
#[must_use]
pub fn wav_bytes(
    samples: &[i16],
    sample_rate: u32,
    channels: u16,
    comment: Option<&str>,
) -> Vec<u8> {
    let bits_per_sample: u16 = 16;
    let byte_rate = sample_rate * u32::from(channels) * u32::from(bits_per_sample) / 8;
    let block_align = channels * bits_per_sample / 8;
    let data_size = (samples.len() * 2) as u32;
    let info = info_chunk(comment);
    // RIFF chunk size = everything after this field. 36 is the classic
    // header's remainder; the INFO chunk adds its own full length.
    let file_size = 36 + data_size + info.len() as u32;

    let mut out: Vec<u8> = Vec::with_capacity(44 + samples.len() * 2 + info.len());

    // RIFF header
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&file_size.to_le_bytes());
    out.extend_from_slice(b"WAVE");

    // fmt sub-chunk
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes()); // sub-chunk size (PCM = 16)
    out.extend_from_slice(&1u16.to_le_bytes()); // audio format (1 = PCM)
    out.extend_from_slice(&channels.to_le_bytes());
    out.extend_from_slice(&sample_rate.to_le_bytes());
    out.extend_from_slice(&byte_rate.to_le_bytes());
    out.extend_from_slice(&block_align.to_le_bytes());
    out.extend_from_slice(&bits_per_sample.to_le_bytes());

    // data sub-chunk
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_size.to_le_bytes());

    // Samples as little-endian i16
    for &sample in samples {
        out.extend_from_slice(&sample.to_le_bytes());
    }

    // INFO goes AFTER `data`, and the ordering is the whole decision.
    //
    // Before `data` it is found by anything scanning for metadata, and it
    // moves `data` off the byte offset that a classic 44-byte WAV puts it at.
    // Every reader that seeks to a fixed offset instead of walking chunks then
    // reads the comment as its sample count -- which is not hypothetical:
    // sipnab's own `wav_header` test helper does exactly that, and reported
    // 328 bytes of audio for a file holding a second of it.
    //
    // After `data`, the first 44 bytes are byte-identical to what sipnab wrote
    // before this existed, so every one of those readers is unaffected, and
    // compliant readers walk to the end and find the note. An artefact's first
    // duty is to play; the note is worth nothing in a file nobody can open.
    out.extend_from_slice(&info);
    out
}

/// Unit tests for the RIFF/WAVE PCM writer.
#[cfg(test)]
mod tests {
    use super::*;

    /// Writing samples creates a file of header + payload size on disk.
    #[test]
    fn write_wav_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.wav");

        let samples: Vec<i16> = vec![0, 1000, -1000, 5000, -5000];
        write_wav(&path, &samples, 8000, 1).unwrap();

        assert!(path.exists(), "WAV file should be created");
        let metadata = std::fs::metadata(&path).unwrap();
        // 44-byte header + 5 samples * 2 bytes = 54 bytes
        assert_eq!(metadata.len(), 54);
    }

    /// The written RIFF/fmt/data headers carry the expected field values.
    #[test]
    fn write_wav_header_correct() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.wav");

        // 160 samples = 20ms at 8kHz mono
        let samples: Vec<i16> = (0..160).map(|i| (i * 100) as i16).collect();
        write_wav(&path, &samples, 8000, 1).unwrap();

        let data = std::fs::read(&path).unwrap();

        // RIFF header
        assert_eq!(&data[0..4], b"RIFF");
        assert_eq!(&data[8..12], b"WAVE");

        // fmt chunk
        assert_eq!(&data[12..16], b"fmt ");
        let fmt_size = u32::from_le_bytes(data[16..20].try_into().unwrap());
        assert_eq!(fmt_size, 16); // PCM format

        let audio_format = u16::from_le_bytes(data[20..22].try_into().unwrap());
        assert_eq!(audio_format, 1); // PCM

        let channels = u16::from_le_bytes(data[22..24].try_into().unwrap());
        assert_eq!(channels, 1);

        let sample_rate = u32::from_le_bytes(data[24..28].try_into().unwrap());
        assert_eq!(sample_rate, 8000);

        // data chunk
        assert_eq!(&data[36..40], b"data");
        let data_size = u32::from_le_bytes(data[40..44].try_into().unwrap());
        assert_eq!(data_size, 320); // 160 samples * 2 bytes

        // Total file size
        assert_eq!(data.len(), 44 + 320);
    }

    /// A 2-channel write records channel count and block align correctly.
    #[test]
    fn write_stereo_wav() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stereo.wav");

        // 320 interleaved samples (160 per channel)
        let samples: Vec<i16> = (0..320).map(|i| (i * 50) as i16).collect();
        write_wav(&path, &samples, 8000, 2).unwrap();

        let data = std::fs::read(&path).unwrap();
        let channels = u16::from_le_bytes(data[22..24].try_into().unwrap());
        assert_eq!(channels, 2);

        let block_align = u16::from_le_bytes(data[32..34].try_into().unwrap());
        assert_eq!(block_align, 4); // 2 channels * 2 bytes
    }

    /// Writing zero samples produces a header-only 44-byte file.
    #[test]
    fn write_empty_wav() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.wav");

        write_wav(&path, &[], 8000, 1).unwrap();

        let data = std::fs::read(&path).unwrap();
        assert_eq!(data.len(), 44); // header only
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::info_chunk;

    /// RIFF pads every chunk body to an even length, and the pad byte is NOT
    /// counted in the size field. Miscount it and every following chunk shifts
    /// by one byte, which is how a file carrying a note plays as noise.
    ///
    /// Both parities, because removing the pad entirely survived a mutation
    /// run: the end-to-end export test happened to produce an even-length
    /// comment, so the odd case -- the only one where the pad exists -- was
    /// never executed.
    #[test]
    fn the_info_chunk_pads_to_an_even_length_without_counting_the_pad() {
        for comment in ["odd", "even"] {
            let chunk = info_chunk(Some(comment));
            assert!(!chunk.is_empty(), "a comment must produce a chunk");
            assert_eq!(&chunk[0..4], b"LIST");
            assert_eq!(&chunk[8..12], b"INFO");
            assert_eq!(&chunk[12..16], b"ICMT");

            // The declared ICMT size counts the text and its NUL, never the pad.
            let icmt_size = u32::from_le_bytes(chunk[16..20].try_into().expect("size")) as usize;
            assert_eq!(
                icmt_size,
                comment.len() + 1,
                "ICMT size must be the text plus its NUL terminator"
            );

            // The whole chunk must be even, or the next chunk starts misaligned.
            assert!(
                chunk.len().is_multiple_of(2),
                "chunk for {comment:?} is {} bytes, which leaves every following \
                 chunk offset by one",
                chunk.len()
            );

            // And LIST's own size field must describe what follows it exactly.
            let list_size = u32::from_le_bytes(chunk[4..8].try_into().expect("size")) as usize;
            assert_eq!(
                list_size + 8,
                chunk.len(),
                "LIST size disagrees with the bytes actually emitted"
            );
        }
    }

    /// No comment means no chunk at all, not an empty one.
    #[test]
    fn no_comment_writes_no_chunk() {
        assert!(info_chunk(None).is_empty());
    }
}
