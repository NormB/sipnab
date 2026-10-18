// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The three examples, run as a user runs them (`cargo run --example`), with
//! their output checked:
//!
//! - `import_tables` builds the same table file from the package zip and from
//!   a directory extracted from it, and that file is the one
//!   `import_from_itu` returns;
//! - `decode_bitstream` turns ITU-T G.192 vectors into WAV files whose sample
//!   data equals the ITU-T expected output byte for byte;
//! - `decode_rtp_payloads` decodes frames, trailing SID frames and lost
//!   packets as the decoder does frame by frame, and gives the committed
//!   sample file's expected length.
//!
//! The examples need the fetched ITU-T package, as the conformance tests do;
//! a missing one fails the test, naming the fetch command. CI runs this file
//! in its own step after fetching the package (.github/workflows/ci.yml).

pub mod common;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use g729::FRAME_SAMPLES;

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// Run `cargo run --example NAME -- ARGS` for this crate; its stdout, or an
/// error holding its stderr.
fn run_example(name: &str, args: &[&OsStr]) -> Result<String, String> {
    let output = Command::new(env!("CARGO"))
        .current_dir(MANIFEST_DIR)
        .args(["run", "--quiet", "-p", "sipnab-g729", "--features", "std"])
        .args(["--example", name, "--"])
        .args(args)
        .output()
        .map_err(|e| format!("cannot run cargo: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "example {name} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// An empty directory of this test's own, under cargo's scratch directory.
fn scratch(test: &str) -> Result<PathBuf, String> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("g729-examples-{test}"));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir)
}

/// The table file `import_from_itu` returns, written into `dir`.
fn table_file_in(dir: &Path) -> Result<PathBuf, String> {
    let path = dir.join("g729-tables.bin");
    std::fs::write(&path, common::table_file()?).map_err(|e| format!("{e}"))?;
    Ok(path)
}

/// The samples of a WAV file the examples write, after checking its header
/// says 16-bit mono PCM at 8000 Hz and its data length.
fn wav_samples(wav: &[u8]) -> Result<Vec<i16>, String> {
    let header = wav.get(..44).ok_or("WAV shorter than its header")?;
    let u16_at = |at: usize| u16::from_le_bytes([header[at], header[at + 1]]);
    let u32_at = |at: usize| {
        u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
    };
    let data_len = wav.len() - 44;
    assert_eq!(&header[..4], b"RIFF");
    assert_eq!(u32_at(4) as usize, 36 + data_len);
    assert_eq!(&header[8..16], b"WAVEfmt ");
    assert_eq!((u32_at(16), u16_at(20), u16_at(22)), (16, 1, 1));
    assert_eq!((u32_at(24), u32_at(28)), (8000, 16000));
    assert_eq!((u16_at(32), u16_at(34)), (2, 16));
    assert_eq!(&header[36..40], b"data");
    assert_eq!(u32_at(40) as usize, data_len);
    Ok(common::samples(&wav[44..]))
}

/// A zip of every file below `dir`, as the package zip holds them.
fn zip_directory(dir: &Path, zip_path: &Path) -> common::TestResult {
    use std::io::Write;
    let mut writer = zip::ZipWriter::new(std::fs::File::create(zip_path)?);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let name = path.strip_prefix(dir)?.to_string_lossy().into_owned();
                writer.start_file(name, options)?;
                writer.write_all(&std::fs::read(&path)?)?;
            }
        }
    }
    writer.finish()?;
    Ok(())
}

#[test]
fn import_tables_builds_one_file_from_a_zip_and_from_a_directory() -> common::TestResult {
    let dir = scratch("import")?;
    let package_dir = common::source_dir()?;
    let package_zip = dir.join("package.zip");
    zip_directory(&package_dir, &package_zip)?;

    let from_dir = dir.join("from-dir.bin");
    let from_zip = dir.join("from-zip.bin");
    run_example(
        "import_tables",
        &[package_dir.as_os_str(), from_dir.as_os_str()],
    )?;
    run_example(
        "import_tables",
        &[package_zip.as_os_str(), from_zip.as_os_str()],
    )?;

    let built = std::fs::read(&from_dir)?;
    assert_eq!(built.len(), g729::FILE_LEN);
    assert_eq!(built, std::fs::read(&from_zip)?, "zip and directory differ");
    assert_eq!(built, common::table_file()?, "differs from import_from_itu");
    g729::Tables::from_bytes(&built)?;
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// Run decode_bitstream on a vector; require the WAV's sample data to equal
/// the expected output file byte for byte.
fn decode_bitstream_matches(bit: &str, expected: &str, summary: &str) -> common::TestResult {
    let dir = scratch(&bit.replace(['/', '.'], "-"))?;
    let tables = table_file_in(&dir)?;
    let input = common::vectors_dir()?.join(bit);
    let wav_path = dir.join("out.wav");
    let stdout = run_example(
        "decode_bitstream",
        &[tables.as_os_str(), input.as_os_str(), wav_path.as_os_str()],
    )?;
    assert!(stdout.starts_with(summary), "{stdout}");
    let wav = std::fs::read(&wav_path)?;
    wav_samples(&wav)?;
    let expected_bytes = common::read_vector(expected)?;
    assert!(
        wav[44..] == expected_bytes[..],
        "{bit}: WAV data differs from {expected}"
    );
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn decode_bitstream_reproduces_speech_pst() -> common::TestResult {
    decode_bitstream_matches(
        "annex-a/SPEECH.BIT",
        "annex-a/SPEECH.PST",
        "3750 frames (3750 speech, 0 SID, 0 untransmitted, 0 erased), 300000 samples",
    )
}

#[test]
fn decode_bitstream_reproduces_erasure_pst() -> common::TestResult {
    decode_bitstream_matches(
        "annex-a/ERASURE.BIT",
        "annex-a/ERASURE.PST",
        "300 frames (240 speech, 0 SID, 0 untransmitted, 60 erased), 24000 samples",
    )
}

#[test]
fn decode_bitstream_reproduces_tstseq1a_out() -> common::TestResult {
    decode_bitstream_matches(
        "annex-b/tstseq1a.bit",
        "annex-b/tstseq1a.out",
        "998 frames (485 speech, 85 SID, 428 untransmitted, 0 erased), 79840 samples",
    )
}

#[test]
fn decode_rtp_payloads_fills_the_sample_files_lost_packet() -> common::TestResult {
    let dir = scratch("rtp-sample")?;
    let tables = table_file_in(&dir)?;
    let input = Path::new(MANIFEST_DIR).join("examples/payloads.txt");
    let wav_path = dir.join("out.wav");
    let stdout = run_example(
        "decode_rtp_payloads",
        &[tables.as_os_str(), input.as_os_str(), wav_path.as_os_str()],
    )?;
    // 2 + 2 frames, 2 concealed for the lost packet, 2 frames, 1 frame and
    // a SID frame, a SID frame: 11 frames.
    assert!(
        stdout.starts_with(
            "6 packets (1 lost): 7 speech frames, 2 SID frames, 2 concealed frames; 880 samples"
        ),
        "{stdout}"
    );
    assert_eq!(
        wav_samples(&std::fs::read(&wav_path)?)?.len(),
        11 * FRAME_SAMPLES
    );
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// Needs Annex B: the last packet carries a SID frame.
#[cfg(feature = "annex-b")]
#[test]
fn decode_rtp_payloads_decodes_as_the_decoder_does_frame_by_frame() -> common::TestResult {
    use g729::bitstream::{SerialFrame, g192_frames};
    use g729::{Decoder, Frame};

    let speech = common::read_vector("annex-a/SPEECH.BIT")?;
    let frames: Vec<[u8; 10]> = g192_frames(&speech)
        .take(12)
        .map(|f| match f {
            Ok(SerialFrame::Speech(bytes)) => Ok(bytes),
            other => Err(format!("SPEECH.BIT: {other:?}")),
        })
        .collect::<Result<_, _>>()?;
    let comfort = common::read_vector("annex-b/tstseq1a.bit")?;
    let sid = g192_frames(&comfort)
        .find_map(|f| match f {
            Ok(SerialFrame::Sid(bytes)) => Some(bytes),
            _ => None,
        })
        .ok_or("tstseq1a.bit has no SID frame")?;

    // Six packets of two frames; the third is lost; the last carries a SID.
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut text = String::new();
    let mut expected = Vec::new();
    let tables = common::tables()?;
    let mut decoder = Decoder::new(tables);
    let mut pcm = [0i16; FRAME_SAMPLES];
    for (packet, pair) in frames.chunks(2).enumerate() {
        if packet == 2 {
            text.push_str("LOST\n");
            for _ in pair {
                decoder.decode(Frame::Erased, &mut pcm);
                expected.extend_from_slice(&pcm);
            }
            continue;
        }
        let mut payload: Vec<u8> = pair.iter().flatten().copied().collect();
        for frame in pair {
            decoder.decode(Frame::Voice(frame), &mut pcm);
            expected.extend_from_slice(&pcm);
        }
        if packet == 5 {
            payload.extend_from_slice(&sid);
            decoder.decode(Frame::Sid(&sid), &mut pcm);
            expected.extend_from_slice(&pcm);
        }
        text.push_str(&hex(&payload));
        text.push('\n');
    }

    let dir = scratch("rtp-vectors")?;
    let table_path = table_file_in(&dir)?;
    let input = dir.join("payloads.txt");
    std::fs::write(&input, text)?;
    let wav_path = dir.join("out.wav");
    let stdout = run_example(
        "decode_rtp_payloads",
        &[
            table_path.as_os_str(),
            input.as_os_str(),
            wav_path.as_os_str(),
        ],
    )?;
    assert!(
        stdout.starts_with(
            "6 packets (1 lost): 10 speech frames, 1 SID frames, 2 concealed frames; 1040 samples"
        ),
        "{stdout}"
    );
    let got = wav_samples(&std::fs::read(&wav_path)?)?;
    common::compare("decode_rtp_payloads", &got, &expected)?;
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// The README shows the examples' WAV writer; the two must not drift apart.
#[test]
fn the_readme_shows_the_examples_wav_writer() -> common::TestResult {
    let support = std::fs::read_to_string(Path::new(MANIFEST_DIR).join("examples/support/wav.rs"))?;
    let readme = std::fs::read_to_string(Path::new(MANIFEST_DIR).join("README.md"))?;
    let start = support
        .find("/// A 16-bit mono WAV file")
        .ok_or("examples/support/wav.rs: no wav_bytes doc comment")?;
    let function = &support[start..];
    assert!(
        readme.contains(function),
        "README.md does not hold examples/support/wav.rs's wav_bytes verbatim"
    );
    Ok(())
}
