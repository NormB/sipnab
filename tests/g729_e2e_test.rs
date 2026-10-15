// SPDX-License-Identifier: MIT OR Apache-2.0
//! G.729 through the shipped binary: `sipnab g729 install`, then a vCon export
//! of a G.729 call with `--retain-audio`.
//!
//! The tables are never committed (docs/g729.md). Each test installs them
//! into a data directory of its own by running `sipnab g729 install --from`
//! on the ITU-T package `scripts/fetch-g729-vectors.py` fetches. A missing
//! package FAILS the test with that command, as the g729 crate's own tests
//! do; it is never a skip.
#![cfg(all(feature = "g729", feature = "vcon"))]

use std::path::{Path, PathBuf};
use std::process::Output;

type TestError = Box<dyn std::error::Error>;

/// A two-party call with one G.729 stream: 425 RTP packets of two 10-octet
/// frames each, timestamps 160 apart, so 68,000 samples at 8 kHz.
const SAMPLE: &str = "tests/pcap-samples/sip-rtp-g729a.pcap";
/// Its Call-ID.
const CALL: &str = "1-24411@10.0.2.20";
/// Samples the sample's stream decodes to.
const SAMPLE_SAMPLES: usize = 425 * 160;
/// The message for a stream whose tables are not installed.
const NOT_INSTALLED: &str =
    "G.729 not decoded: codebook tables not installed; run sipnab g729 install";

/// The extracted ITU-T package, `crates/g729/test-vectors/itu-source`.
fn package_dir() -> Result<PathBuf, TestError> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/g729/test-vectors/itu-source");
    if dir.is_dir() {
        Ok(dir)
    } else {
        Err(format!(
            "the ITU-T G.729 package is not fetched ({} is missing): run \
             `python3 scripts/fetch-g729-vectors.py` from the repository root",
            dir.display()
        )
        .into())
    }
}

/// Run the binary with `home` as `$HOME` and `$XDG_CONFIG_HOME`, so the
/// default table file is `home/sipnab/g729-tables.bin` and no config file of
/// the host is read.
fn sipnab(home: &Path, args: &[&str]) -> Result<Output, TestError> {
    Ok(std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env_remove("SIPNAB_CONFIG")
        .env("NO_COLOR", "1")
        .output()?)
}

/// A data directory with the tables installed by the shipped command.
fn installed() -> Result<tempfile::TempDir, TestError> {
    let home = tempfile::tempdir()?;
    let package = package_dir()?;
    let package = package.to_str().ok_or("a UTF-8 path")?;
    let out = sipnab(
        home.path(),
        &["g729", "install", "--yes", "--no-config", "--from", package],
    )?;
    if !out.status.success() {
        return Err(format!(
            "sipnab g729 install failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(home)
}

/// The vCon `--export-vcon CALL` writes for `pcap`.
fn export(home: &Path, pcap: &str, extra: &[&str]) -> Result<serde_json::Value, TestError> {
    let mut args = vec![
        "-N",
        "-q",
        "--no-cli-print",
        "--no-config",
        "-I",
        pcap,
        "--retain-audio",
        "--export-vcon",
        CALL,
    ];
    args.extend_from_slice(extra);
    let out = sipnab(home, &args)?;
    if !out.status.success() {
        return Err(format!("export failed: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

/// The WAV inside the container's `recording` Dialog Object.
fn recording_wav(vcon: &serde_json::Value) -> Result<Vec<u8>, TestError> {
    use base64::Engine;
    let recording = vcon["dialog"]
        .as_array()
        .ok_or("dialog is not an array")?
        .iter()
        .find(|d| d["type"] == "recording" && d.get("body").is_some())
        .ok_or_else(|| format!("no recording with a body: {vcon}"))?;
    let body = recording["body"].as_str().ok_or("body is not a string")?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body.trim_end_matches('='))?)
}

/// A PCM WAV's rate, channel count and samples.
fn wav_samples(wav: &[u8]) -> Result<(u32, u16, Vec<i16>), TestError> {
    if wav.get(..4) != Some(b"RIFF") || wav.get(8..12) != Some(b"WAVE") {
        return Err("not a WAV".into());
    }
    let (mut rate, mut channels, mut at) = (0u32, 0u16, 12usize);
    while at + 8 <= wav.len() {
        let id = &wav[at..at + 4];
        let len = u32::from_le_bytes(wav[at + 4..at + 8].try_into()?) as usize;
        let body = wav.get(at + 8..at + 8 + len).ok_or("a truncated chunk")?;
        if id == b"fmt " {
            channels = u16::from_le_bytes(body[2..4].try_into()?);
            rate = u32::from_le_bytes(body[4..8].try_into()?);
        } else if id == b"data" {
            let samples = body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| i16::from_le_bytes(*b))
                .collect();
            return Ok((rate, channels, samples));
        }
        at += 8 + len + (len & 1);
    }
    Err("no data chunk".into())
}

/// sha256 of the samples, as little-endian bytes.
fn pcm_sha256(samples: &[i16]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for s in samples {
        h.update(s.to_le_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The sample call exports to a mono 8 kHz WAV of exactly its 425 packets'
/// length, and its samples are pinned.
#[test]
fn the_sample_call_exports_its_full_duration() -> Result<(), TestError> {
    let home = installed()?;
    let vcon = export(home.path(), SAMPLE, &[])?;
    let (rate, channels, samples) = wav_samples(&recording_wav(&vcon)?)?;
    assert_eq!((rate, channels), (8000, 1));
    assert_eq!(samples.len(), SAMPLE_SAMPLES);
    assert!(
        samples.iter().any(|&s| s != 0),
        "decoded speech is not silence"
    );
    assert_eq!(
        pcm_sha256(&samples),
        "3036177349e0862123c59023af025f0ac948b32519bb3dcfd24884526c7cc2e6",
        "the decoded samples changed"
    );
    Ok(())
}

/// `--g729-tables` names the file; nothing is needed in the data directory.
#[test]
fn the_flag_names_the_table_file() -> Result<(), TestError> {
    let installed = installed()?;
    let file = installed.path().join("sipnab").join("g729-tables.bin");
    let file = file.to_str().ok_or("a UTF-8 path")?;
    let empty = tempfile::tempdir()?;
    let vcon = export(empty.path(), SAMPLE, &["--g729-tables", file])?;
    let (_, _, samples) = wav_samples(&recording_wav(&vcon)?)?;
    assert_eq!(samples.len(), SAMPLE_SAMPLES);
    Ok(())
}

/// The sample, rewritten: RTP packet 100 lost, and the last packet carrying
/// one voice frame and a trailing 2-octet SID frame (RFC 3551 section 4.5.6).
fn lossy_sample(out: &Path) -> Result<(), TestError> {
    let pcap = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(SAMPLE))?;
    let link = u32::from_le_bytes(pcap[20..24].try_into()?);
    if pcap[..4] != [0xd4, 0xc3, 0xb2, 0xa1] || link != 1 {
        return Err("expected a little-endian Ethernet pcap".into());
    }
    let mut records: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut at = 24;
    while at + 16 <= pcap.len() {
        let caplen = u32::from_le_bytes(pcap[at + 8..at + 12].try_into()?) as usize;
        records.push((
            pcap[at..at + 16].to_vec(),
            pcap[at + 16..at + 16 + caplen].to_vec(),
        ));
        at += 16 + caplen;
    }
    // Ethernet 14, IPv4 20 (no options in this capture), UDP 8, RTP 12.
    let is_rtp = |frame: &[u8]| {
        frame.len() > 54 && frame[23] == 17 && u16::from_be_bytes([frame[36], frame[37]]) == 6000
    };
    let rtp: Vec<usize> = (0..records.len())
        .filter(|&i| is_rtp(&records[i].1))
        .collect();
    assert_eq!(rtp.len(), 425, "the sample's RTP packets");
    let last = *rtp.last().ok_or("an RTP packet")?;
    {
        let frame = &mut records[last].1;
        frame.truncate(54 + 10);
        frame.extend_from_slice(&[0x4c, 0x90]);
        let ip_len = u16::try_from(frame.len() - 14)?;
        frame[16..18].copy_from_slice(&ip_len.to_be_bytes());
        let udp_len = u16::try_from(frame.len() - 34)?;
        frame[38..40].copy_from_slice(&udp_len.to_be_bytes());
        frame[40..42].copy_from_slice(&[0, 0]);
        frame[24..26].copy_from_slice(&[0, 0]);
        let sum = (14..34)
            .step_by(2)
            .map(|i| u32::from(u16::from_be_bytes([frame[i], frame[i + 1]])))
            .sum::<u32>();
        let folded = (sum & 0xffff) + (sum >> 16);
        let checksum = !u16::try_from((folded & 0xffff) + (folded >> 16))?;
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        let len = u32::try_from(frame.len())?.to_le_bytes();
        records[last].0[8..12].copy_from_slice(&len);
        records[last].0[12..16].copy_from_slice(&len);
    }
    records.remove(rtp[100]);
    let mut bytes = pcap[..24].to_vec();
    for (header, frame) in records {
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&frame);
    }
    std::fs::write(out, bytes)?;
    Ok(())
}

/// A lost packet and a trailing SID frame: the export keeps the call's
/// length, the lost packet's 20 ms holds the decoder's concealment rather
/// than zeros, and the export names the gap.
#[test]
fn a_lost_packet_and_a_trailing_sid_decode_to_the_right_length() -> Result<(), TestError> {
    let home = installed()?;
    let pcap = home.path().join("lossy.pcap");
    lossy_sample(&pcap)?;
    let vcon = export(home.path(), pcap.to_str().ok_or("a UTF-8 path")?, &[])?;
    let (_, _, samples) = wav_samples(&recording_wav(&vcon)?)?;
    assert_eq!(samples.len(), SAMPLE_SAMPLES);
    let lost = &samples[100 * 160..101 * 160];
    assert!(
        lost.iter().any(|&s| s != 0),
        "the lost packet is concealed, not silent"
    );
    let text = vcon.to_string();
    assert!(text.contains("20 ms in 1 gap"), "the gap is named: {text}");
    assert!(
        text.contains("the G.729 decoder's loss concealment or comfort noise"),
        "the note says what the gap holds: {text}"
    );
    assert!(
        !text.contains("is silence in this file"),
        "a concealed G.729 gap is not silence: {text}"
    );
    Ok(())
}

/// One pcap record: its 16-octet record header and its frame.
type Record = (Vec<u8>, Vec<u8>);

/// The sample's 24-octet pcap file header and its records.
fn sample_records() -> Result<(Vec<u8>, Vec<Record>), TestError> {
    let pcap = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(SAMPLE))?;
    let link = u32::from_le_bytes(pcap[20..24].try_into()?);
    if pcap[..4] != [0xd4, 0xc3, 0xb2, 0xa1] || link != 1 {
        return Err("expected a little-endian Ethernet pcap".into());
    }
    let mut records: Vec<Record> = Vec::new();
    let mut at = 24;
    while at + 16 <= pcap.len() {
        let caplen = u32::from_le_bytes(pcap[at + 8..at + 12].try_into()?) as usize;
        records.push((
            pcap[at..at + 16].to_vec(),
            pcap[at + 16..at + 16 + caplen].to_vec(),
        ));
        at += 16 + caplen;
    }
    Ok((pcap[..24].to_vec(), records))
}

/// Whether `frame` is one of the sample's RTP packets: Ethernet 14, IPv4 20
/// (no options in this capture), UDP 8 to port 6000, RTP 12.
fn is_sample_rtp(frame: &[u8]) -> bool {
    frame.len() > 54 && frame[23] == 17 && u16::from_be_bytes([frame[36], frame[37]]) == 6000
}

/// An RTP frame's sequence number, at offset 44 of the sample's frames.
fn rtp_sequence(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[44], frame[45]])
}

/// The sample, rewritten as a call under discontinuous transmission whose
/// SID frame was lost: RTP packets 100 to 149 are removed, and packets 150
/// on are renumbered to follow packet 99 with ONE sequence number missing.
/// Packet 100 is the lost packet; 101 to 149 are a pause in which the sender
/// sent nothing. Returns each remaining RTP packet's payload, in order.
fn lost_sid_then_a_pause_sample(out: &Path) -> Result<Vec<Vec<u8>>, TestError> {
    let (head, mut records) = sample_records()?;
    let rtp: Vec<usize> = (0..records.len())
        .filter(|&i| is_sample_rtp(&records[i].1))
        .collect();
    assert_eq!(rtp.len(), 425, "the sample's RTP packets");
    for pair in rtp.windows(2) {
        let (a, b) = (&records[pair[0]].1, &records[pair[1]].1);
        assert_eq!(
            rtp_sequence(b),
            rtp_sequence(a).wrapping_add(1),
            "the sample's sequence numbers are consecutive"
        );
    }
    for &i in &rtp[150..] {
        let frame = &mut records[i].1;
        let renumbered = rtp_sequence(frame).wrapping_sub(49);
        frame[44..46].copy_from_slice(&renumbered.to_be_bytes());
        // No UDP checksum, rather than a stale one.
        frame[40..42].copy_from_slice(&[0, 0]);
    }
    let payloads: Vec<Vec<u8>> = rtp[..100]
        .iter()
        .chain(&rtp[150..])
        .map(|&i| records[i].1[54..].to_vec())
        .collect();
    let removed: std::collections::BTreeSet<usize> = rtp[100..150].iter().copied().collect();
    let mut bytes = head;
    for (i, (header, frame)) in records.into_iter().enumerate() {
        if !removed.contains(&i) {
            bytes.extend_from_slice(&header);
            bytes.extend_from_slice(&frame);
        }
    }
    std::fs::write(out, bytes)?;
    Ok(payloads)
}

/// A G.729 call under discontinuous transmission whose SID frame was lost,
/// through the shipped binary: `--retain-audio --export-vcon` decodes it to
/// what the g729 crate's decoder produces when fed the true frame types,
/// sample for sample: the 100 packets of speech, the lost SID packet's one
/// frame erased, 99 untransmitted frames, the 275 packets of speech. An
/// Annex B pause starts with a one-frame SID packet, so that is the packet
/// whose sequence number is missing.
/// Filled from the last frame type alone, the pause was concealed as speech.
#[test]
fn a_lost_sid_before_a_pause_exports_as_the_true_frames() -> Result<(), TestError> {
    let home = installed()?;
    let pcap = home.path().join("dtx.pcap");
    let payloads = lost_sid_then_a_pause_sample(&pcap)?;
    let vcon = export(home.path(), pcap.to_str().ok_or("a UTF-8 path")?, &[])?;
    let (_, _, samples) = wav_samples(&recording_wav(&vcon)?)?;

    let tables = g729::Tables::from_bytes(&std::fs::read(
        home.path().join("sipnab").join("g729-tables.bin"),
    )?)?;
    let mut decoder = g729::Decoder::new(&tables);
    let mut expected: Vec<i16> = Vec::new();
    let mut pcm = [0i16; g729::FRAME_SAMPLES];
    let mut decode = |frame: g729::Frame<'_>, expected: &mut Vec<i16>| {
        decoder.decode(frame, &mut pcm);
        expected.extend_from_slice(&pcm);
    };
    for (i, payload) in payloads.iter().enumerate() {
        if i == 100 {
            decode(g729::Frame::Erased, &mut expected);
            for _ in 0..99 {
                decode(g729::Frame::NoTx, &mut expected);
            }
        }
        assert_eq!(payload.len(), 20, "two speech frames per packet");
        for frame in payload.as_chunks::<10>().0 {
            decode(g729::Frame::Voice(frame), &mut expected);
        }
    }
    assert_eq!(expected.len(), SAMPLE_SAMPLES);
    assert_eq!(samples.len(), expected.len());
    let first_difference = samples.iter().zip(&expected).position(|(a, b)| a != b);
    assert_eq!(first_difference, None, "the export left the reference");
    Ok(())
}

/// Without the tables, the vCon carries no recording of the G.729 stream and
/// names the reason and the command.
#[test]
fn without_tables_the_vcon_names_the_omission_and_the_command() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let vcon = export(home.path(), SAMPLE, &[])?;
    assert!(recording_wav(&vcon).is_err(), "no recording without tables");
    let text = vcon.to_string();
    assert!(text.contains(NOT_INSTALLED), "{text}");
    Ok(())
}

/// A run that meets G.729 audio it cannot decode says so once on stderr,
/// naming the command, even under `-q`: the vCon note alone is easy to miss,
/// and the run still exits 0 because everything else in it succeeded.
#[test]
fn without_tables_a_run_says_so_once_on_stderr() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let out = sipnab(
        home.path(),
        &[
            "-N",
            "-q",
            "--no-cli-print",
            "--no-config",
            "-I",
            SAMPLE,
            "--retain-audio",
            "--export-vcon",
            CALL,
        ],
    )?;
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.matches(NOT_INSTALLED).count(), 1, "stderr: {err}");
    Ok(())
}

/// `sipnab g729 status` says not installed, then installed with the path and
/// the values hash.
#[test]
fn status_follows_the_install() -> Result<(), TestError> {
    let empty = tempfile::tempdir()?;
    let out = sipnab(empty.path(), &["g729", "status", "--no-config"])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("not installed"));
    let home = installed()?;
    let out = sipnab(home.path(), &["g729", "status", "--no-config"])?;
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("installed"), "{text}");
    assert!(text.contains("g729-tables.bin"), "{text}");
    assert!(
        text.contains("e4846d29f3da09451781e61187fceac230d12cb0c6be0a85348a524137852ac2"),
        "{text}"
    );
    Ok(())
}
