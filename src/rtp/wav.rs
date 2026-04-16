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
    let bits_per_sample: u16 = 16;
    let byte_rate = sample_rate * u32::from(channels) * u32::from(bits_per_sample) / 8;
    let block_align = channels * bits_per_sample / 8;
    let data_size = (samples.len() * 2) as u32;
    let file_size = 36 + data_size; // RIFF chunk size = file size - 8

    let mut file = std::fs::File::create(path)
        .with_context(|| format!("Failed to create WAV file: {}", path.display()))?;

    // RIFF header
    file.write_all(b"RIFF")?;
    file.write_all(&file_size.to_le_bytes())?;
    file.write_all(b"WAVE")?;

    // fmt sub-chunk
    file.write_all(b"fmt ")?;
    file.write_all(&16u32.to_le_bytes())?; // sub-chunk size (PCM = 16)
    file.write_all(&1u16.to_le_bytes())?; // audio format (1 = PCM)
    file.write_all(&channels.to_le_bytes())?;
    file.write_all(&sample_rate.to_le_bytes())?;
    file.write_all(&byte_rate.to_le_bytes())?;
    file.write_all(&block_align.to_le_bytes())?;
    file.write_all(&bits_per_sample.to_le_bytes())?;

    // data sub-chunk
    file.write_all(b"data")?;
    file.write_all(&data_size.to_le_bytes())?;

    // Write samples as little-endian i16
    for &sample in samples {
        file.write_all(&sample.to_le_bytes())?;
    }

    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn write_empty_wav() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.wav");

        write_wav(&path, &[], 8000, 1).unwrap();

        let data = std::fs::read(&path).unwrap();
        assert_eq!(data.len(), 44); // header only
    }
}
