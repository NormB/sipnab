// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! FILE-1: `--autostop filesize:N` stops after N MiB of output, also when
//! `--split` rotates that output across several files.
//!
//! The stop used to read the writer's per-file counter, which every rotation
//! sets back to the new file's header size. With a split smaller than the
//! limit the counter never reached it, and the run wrote its whole input: a
//! 2 MiB limit on a 1 MiB split of a 5.7 MiB capture wrote 5.7 MiB.
//!
//! The reference for every split run here is the same run without `--split`,
//! where the per-file counter and the run total are one number: a split run
//! must stop at the same frame. Classic pcap counts records only, so the two
//! stop at exactly the same frame; pcapng counts each split file's header
//! too, so a split run may stop up to one frame per file earlier.
#![cfg(feature = "native")]

use std::path::{Path, PathBuf};

type TestError = Box<dyn std::error::Error>;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

/// UDP payload of every input frame. A classic record is then
/// 16 + 14 + 20 + 8 + 1400 = 1458 bytes.
const PAYLOAD: usize = 1400;

/// Bytes of one classic pcap record of an input frame.
const RECORD: u64 = 16 + 14 + 20 + 8 + PAYLOAD as u64;

/// One MiB, the unit of both `--split filesize` and `--autostop filesize`.
const MIB: u64 = 1024 * 1024;

/// Frames in the default input: about 5.7 MiB, more than every limit below.
const FRAMES: usize = 4096;

/// What one run left behind.
#[derive(Debug)]
struct Outcome {
    /// Frames in every output file still on disk.
    frames: usize,
    /// Bytes of every output file still on disk.
    bytes: u64,
    /// Output file names, sorted.
    files: Vec<String>,
    /// The highest split sequence number on disk (0 for the base file).
    last_seq: u32,
    /// The run's stderr.
    stderr: String,
    /// The run's exit code.
    code: Option<i32>,
}

/// Write an input capture of `frames` UDP frames between documentation
/// addresses (RFC 5737) to a port no dissector claims; zero payload bytes.
fn input(dir: &Path, frames: usize, payload: usize) -> Result<PathBuf, TestError> {
    let path = dir.join("in.pcap");
    let frame = pcap_build::udp_frame(
        [192, 0, 2, 1],
        [192, 0, 2, 2],
        40000,
        40002,
        &vec![0; payload],
    );
    pcap_build::write_pcap(&path, &vec![frame; frames])?;
    Ok(path)
}

/// Frames in one classic pcap file: walk the records after the 24-byte
/// global header.
fn classic_frames(path: &Path) -> Result<usize, TestError> {
    let d = std::fs::read(path)?;
    let mut off = 24usize;
    let mut n = 0;
    while off + 16 <= d.len() {
        let incl = u32::from_le_bytes([d[off + 8], d[off + 9], d[off + 10], d[off + 11]]) as usize;
        off += 16 + incl;
        n += 1;
    }
    Ok(n)
}

/// The split sequence number in a file name `out_00007.pcap`, 0 for `out.pcap`.
fn seq_of(name: &str) -> Result<u32, TestError> {
    let stem = name.split('.').next().ok_or("a file name")?;
    match stem.rsplit_once('_') {
        Some((_, digits)) => Ok(digits.parse()?),
        None => Ok(0),
    }
}

/// Run `sipnab -N -I <input> -O <out> [args]` into a fresh directory and
/// read what it wrote.
fn capture(input: &Path, pcapng: bool, args: &[&str]) -> Result<Outcome, TestError> {
    let outdir = tempfile::tempdir()?;
    let out = outdir
        .path()
        .join(if pcapng { "out.pcapng" } else { "out.pcap" });
    let mut argv = vec![
        "-N",
        "-I",
        input.to_str().ok_or("utf-8")?,
        "-O",
        out.to_str().ok_or("utf-8")?,
    ];
    if pcapng {
        argv.push("--pcapng");
    }
    argv.extend_from_slice(args);
    let (_, stderr, code) = run_support::run(&argv, Some("info"))?;
    let mut files = Vec::new();
    for entry in std::fs::read_dir(outdir.path())? {
        files.push(entry?.file_name().to_string_lossy().into_owned());
    }
    files.sort();
    let mut frames = 0;
    let mut bytes = 0;
    let mut last_seq = 0;
    for name in &files {
        let path = outdir.path().join(name);
        bytes += std::fs::metadata(&path)?.len();
        frames += if pcapng {
            pcap_build::count_pcapng_blocks(&path, 6)?
        } else {
            classic_frames(&path)?
        };
        last_seq = last_seq.max(seq_of(name)?);
    }
    Ok(Outcome {
        frames,
        bytes,
        files,
        last_seq,
        stderr,
        code,
    })
}

/// The default input in a fresh directory.
fn default_input() -> Result<(tempfile::TempDir, PathBuf), TestError> {
    let dir = tempfile::tempdir()?;
    let path = input(dir.path(), FRAMES, PAYLOAD)?;
    Ok((dir, path))
}

/// Frames a classic run limited to `mib` MiB writes: the first record at
/// which the record total reaches the limit.
fn classic_stop(mib: u64) -> usize {
    (mib * MIB).div_ceil(RECORD) as usize
}

/// A classic split run stops at the same frame as the run without a split.
fn classic_split_matches_unsplit(split: &str, limit: &str, mib: u64) -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let whole = capture(&input, false, &["--autostop", limit])?;
    let split = capture(&input, false, &["--split", split, "--autostop", limit])?;
    assert_eq!(whole.code, Some(0), "unsplit run: {}", whole.stderr);
    assert_eq!(split.code, Some(0), "split run: {}", split.stderr);
    assert_eq!(
        whole.frames,
        classic_stop(mib),
        "the unsplit run stops at the first record past {mib} MiB"
    );
    assert_eq!(
        split.frames, whole.frames,
        "the split run ({:?}) must stop where the unsplit run stops",
        split.files
    );
    assert!(
        split.files.len() > 1,
        "the split rotated: {:?}",
        split.files
    );
    Ok(())
}

/// A pcapng split run stops within one frame per file of the unsplit run,
/// and its files hold at least the limit.
fn pcapng_split_matches_unsplit(split: &str, limit: &str, mib: u64) -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let whole = capture(&input, true, &["--autostop", limit])?;
    let split = capture(&input, true, &["--split", split, "--autostop", limit])?;
    assert_eq!(split.code, Some(0), "split run: {}", split.stderr);
    let slack = split.files.len();
    assert!(
        split.frames <= whole.frames && split.frames + slack >= whole.frames,
        "split {} frames in {:?}, unsplit {} frames",
        split.frames,
        split.files,
        whole.frames
    );
    assert!(
        split.bytes >= mib * MIB,
        "the files hold the limit: {}",
        split.bytes
    );
    assert!(
        split.bytes < mib * MIB + RECORD + 4096,
        "no more than one frame past the limit: {} bytes",
        split.bytes
    );
    Ok(())
}

// ── SUCCESS ──────────────────────────────────────────────────────────────

/// The reported case: a 1 MiB split under a 2 MiB limit.
#[test]
fn a_classic_split_of_1_stops_at_2_mib() -> Result<(), TestError> {
    classic_split_matches_unsplit("filesize:1", "filesize:2", 2)
}

/// Three files' worth of limit over 1 MiB splits.
#[test]
fn a_classic_split_of_1_stops_at_3_mib() -> Result<(), TestError> {
    classic_split_matches_unsplit("filesize:1", "filesize:3", 3)
}

/// A split of 2 under a limit of 3: one rotation, then the stop.
#[test]
fn a_classic_split_of_2_stops_at_3_mib() -> Result<(), TestError> {
    classic_split_matches_unsplit("filesize:2", "filesize:3", 3)
}

/// A limit of 5 over 1 MiB splits: five rotations before the stop.
#[test]
fn a_classic_split_of_1_stops_at_5_mib() -> Result<(), TestError> {
    classic_split_matches_unsplit("filesize:1", "filesize:5", 5)
}

/// pcapng, the reported shape.
#[test]
fn a_pcapng_split_of_1_stops_at_2_mib() -> Result<(), TestError> {
    pcapng_split_matches_unsplit("filesize:1", "filesize:2", 2)
}

/// pcapng over three files.
#[test]
fn a_pcapng_split_of_1_stops_at_3_mib() -> Result<(), TestError> {
    pcapng_split_matches_unsplit("filesize:1", "filesize:3", 3)
}

/// pcapng, one rotation.
#[test]
fn a_pcapng_split_of_2_stops_at_3_mib() -> Result<(), TestError> {
    pcapng_split_matches_unsplit("filesize:2", "filesize:3", 3)
}

/// The stop comes before the input ends: the run did not just read it all.
#[test]
fn the_split_run_stops_before_its_input_ends() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:2"],
    )?;
    assert!(
        o.frames < FRAMES,
        "{} of {FRAMES} frames written: the stop never came",
        o.frames
    );
    Ok(())
}

/// The files hold the limit, and one frame past it at most.
#[test]
fn the_split_files_hold_the_limit_and_no_more() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:2"],
    )?;
    let records = o.bytes - 24 * o.files.len() as u64;
    assert!(
        records >= 2 * MIB,
        "{records} record bytes, below the limit"
    );
    assert!(
        records < 2 * MIB + RECORD,
        "{records} record bytes, past one frame"
    );
    Ok(())
}

/// The run says why it stopped.
#[test]
fn the_split_run_says_the_filesize_limit_was_reached() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:2"],
    )?;
    assert!(
        o.stderr
            .contains("Autostop: filesize limit reached (2 MiB)"),
        "stderr names the stop:\n{}",
        o.stderr
    );
    Ok(())
}

/// A ring buffer of one file: the deleted files were output too, so the run
/// stops at the same split number as the run that keeps every file.
#[test]
fn a_ring_of_one_stops_at_the_same_split() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let all = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:3"],
    )?;
    let ring = capture(
        &input,
        false,
        &[
            "--split",
            "filesize:1",
            "--split-keep",
            "1",
            "--autostop",
            "filesize:3",
        ],
    )?;
    assert_eq!(ring.code, Some(0), "{}", ring.stderr);
    assert_eq!(ring.files.len(), 1, "one file kept: {:?}", ring.files);
    assert_eq!(ring.last_seq, all.last_seq, "the same last split");
    assert_eq!(all.last_seq, 2, "the stop came in the third file");
    Ok(())
}

/// A ring of two, the same way.
#[test]
fn a_ring_of_two_stops_at_the_same_split() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let all = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:3"],
    )?;
    let ring = capture(
        &input,
        false,
        &[
            "--split",
            "filesize:1",
            "--split-keep",
            "2",
            "--autostop",
            "filesize:3",
        ],
    )?;
    assert_eq!(ring.files.len(), 2, "two files kept: {:?}", ring.files);
    assert_eq!(ring.last_seq, all.last_seq, "the same last split");
    // 720 records fill a 1 MiB file; 2158 records reach 3 MiB: files 0, 1, 2.
    assert_eq!(ring.last_seq, 2, "the stop came in the third file");
    Ok(())
}

/// A pcapng ring of one stops too.
#[test]
fn a_pcapng_ring_of_one_stops() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let ring = capture(
        &input,
        true,
        &[
            "--split",
            "filesize:1",
            "--split-keep",
            "1",
            "--autostop",
            "filesize:2",
        ],
    )?;
    assert_eq!(ring.code, Some(0), "{}", ring.stderr);
    assert!(
        ring.last_seq <= 2,
        "stopped by split 2, at {}",
        ring.last_seq
    );
    Ok(())
}

/// A duration split that never fires in a fast file run leaves the size
/// stop as it is without a split.
#[test]
fn a_duration_split_keeps_the_size_stop() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &["--split", "duration:3600", "--autostop", "filesize:2"],
    )?;
    assert_eq!(o.frames, classic_stop(2), "files {:?}", o.files);
    Ok(())
}

/// The run that stopped on the limit exits 0.
#[test]
fn the_split_run_that_stopped_exits_0() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:2"],
    )?;
    assert_eq!(o.code, Some(0), "{}", o.stderr);
    Ok(())
}

/// `--count` below the size limit still stops first with a split.
#[test]
fn a_smaller_count_stops_first() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &[
            "--split",
            "filesize:1",
            "--autostop",
            "filesize:3",
            "-n",
            "1000",
        ],
    )?;
    assert_eq!(o.frames, 1000, "the count stops first: {:?}", o.files);
    Ok(())
}

/// The size limit below `--count` stops first with a split.
#[test]
fn a_smaller_size_limit_stops_before_the_count() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &[
            "--split",
            "filesize:1",
            "--autostop",
            "filesize:2",
            "-n",
            "4000",
        ],
    )?;
    assert_eq!(
        o.frames,
        classic_stop(2),
        "the size stops first: {:?}",
        o.files
    );
    Ok(())
}

// ── FAILURE ──────────────────────────────────────────────────────────────

/// A limit above the input: no stop, every frame is written, across splits.
#[test]
fn a_limit_above_the_input_writes_every_frame() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:50"],
    )?;
    assert_eq!(o.code, Some(0), "{}", o.stderr);
    assert_eq!(o.frames, FRAMES, "every frame: {:?}", o.files);
    assert!(
        !o.stderr.contains("Autostop: filesize limit reached"),
        "no stop was reached:\n{}",
        o.stderr
    );
    Ok(())
}

/// The same for pcapng.
#[test]
fn a_pcapng_limit_above_the_input_writes_every_frame() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        true,
        &["--split", "filesize:1", "--autostop", "filesize:50"],
    )?;
    assert_eq!(o.frames, FRAMES, "every frame: {:?}", o.files);
    Ok(())
}

/// A zero limit is refused before anything is written, with a split too.
#[test]
fn a_zero_limit_with_a_split_is_refused() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:0"],
    )?;
    assert_eq!(o.code, Some(2), "{}", o.stderr);
    assert!(o.files.is_empty(), "nothing written: {:?}", o.files);
    assert!(o.stderr.contains("must be > 0"), "{}", o.stderr);
    Ok(())
}

/// A limit that is not a number is refused, with a split too.
#[test]
fn a_non_numeric_limit_with_a_split_is_refused() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:two"],
    )?;
    assert_eq!(o.code, Some(2), "{}", o.stderr);
    assert!(o.files.is_empty(), "nothing written: {:?}", o.files);
    Ok(())
}

/// A zero split under a size limit is refused before anything is written.
#[test]
fn a_zero_split_under_a_limit_is_refused() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:0", "--autostop", "filesize:2"],
    )?;
    assert_eq!(o.code, Some(2), "{}", o.stderr);
    assert!(o.files.is_empty(), "nothing written: {:?}", o.files);
    assert!(o.stderr.contains("must be > 0"), "{}", o.stderr);
    Ok(())
}

/// A rotation that cannot create its file still fails the run (exit 1)
/// when a size limit is also set; the stop does not hide it.
#[test]
fn a_failed_rotation_under_a_limit_still_exits_1() -> Result<(), TestError> {
    let (dir, input) = default_input()?;
    let outdir = tempfile::tempdir()?;
    let out = outdir.path().join("out.pcap");
    std::fs::create_dir(outdir.path().join("out_00001.pcap"))?;
    let (_, stderr, code) = run_support::run(
        &[
            "-N",
            "-I",
            input.to_str().ok_or("utf-8")?,
            "-O",
            out.to_str().ok_or("utf-8")?,
            "--split",
            "filesize:1",
            "--autostop",
            "filesize:3",
        ],
        Some("error"),
    )?;
    drop(dir);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("out_00001.pcap"), "{stderr}");
    Ok(())
}

/// Without `-O` there is no output to measure: the size limit never stops
/// the run, which reads its whole input and exits 0.
#[test]
fn without_an_output_the_size_limit_never_stops() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let (_, stderr, code) = run_support::run(
        &[
            "-N",
            "-I",
            input.to_str().ok_or("utf-8")?,
            "--autostop",
            "filesize:1",
        ],
        Some("info"),
    )?;
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        !stderr.contains("Autostop: filesize limit reached"),
        "no output, no size stop:\n{stderr}"
    );
    Ok(())
}

// ── EDGE ─────────────────────────────────────────────────────────────────

/// A limit equal to the split size stops at the end of the first file.
#[test]
fn a_limit_equal_to_the_split_stops_in_the_first_file() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:1"],
    )?;
    assert_eq!(o.frames, classic_stop(1), "files {:?}", o.files);
    assert!(o.last_seq <= 1, "at most one rotation: {:?}", o.files);
    Ok(())
}

/// A limit below the split size: no rotation, one file, the same stop.
#[test]
fn a_limit_below_the_split_writes_one_file() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:4", "--autostop", "filesize:2"],
    )?;
    assert_eq!(o.files, vec!["out.pcap".to_string()], "one file");
    assert_eq!(o.frames, classic_stop(2), "the same stop");
    Ok(())
}

/// Small frames: many more records to the limit, the same stop rule.
#[test]
fn small_frames_stop_at_the_limit_too() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let input = input(dir.path(), 60_000, 10)?;
    let record = 16 + 14 + 20 + 8 + 10;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:2"],
    )?;
    assert_eq!(
        o.frames as u64,
        (2 * MIB).div_ceil(record),
        "files {:?}",
        o.files
    );
    Ok(())
}

/// An input exactly as large as the limit: everything is written and the
/// last record is the one that reaches it.
#[test]
fn an_input_that_ends_at_the_limit_is_written_whole() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let n = classic_stop(2);
    let input = input(dir.path(), n, PAYLOAD)?;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:2"],
    )?;
    assert_eq!(o.frames, n, "files {:?}", o.files);
    Ok(())
}

/// The split files keep their sequence: base file, then _00001, _00002.
#[test]
fn the_files_of_a_stopped_split_run_are_in_sequence() -> Result<(), TestError> {
    let (_d, input) = default_input()?;
    let o = capture(
        &input,
        false,
        &["--split", "filesize:1", "--autostop", "filesize:3"],
    )?;
    let seqs: Vec<u32> = o
        .files
        .iter()
        .map(|f| seq_of(f))
        .collect::<Result<_, _>>()?;
    let expected: Vec<u32> = (0..=o.last_seq).collect();
    assert_eq!(seqs, expected, "no gap: {:?}", o.files);
    Ok(())
}
