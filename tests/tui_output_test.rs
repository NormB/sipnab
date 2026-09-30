// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TUI's `-O`, driven the way its processing thread drives it.
//!
//! The processing thread runs inside `run_tui_mode` and owns the terminal, so
//! nothing could test what it wrote. Its per-packet work --- open `-O` on the
//! first packet, hold or write the packet, reassemble, run the pipeline with
//! the media keys and the decrypted export, write what has waited long enough
//! --- is `tui_process_packet`, and its end of run is `TuiOutput::close`. The
//! thread calls exactly these, so these tests reach the TUI's `-O` with real
//! captures (PCAPX-DEC-TUI, backlog 2026-09-29). The TUI decrypts SRTP but not
//! TLS, so in `--pcap-export-mode decrypted` its SRTP comes out as RTP and its
//! TLS as captured, counted.

#![cfg(all(feature = "tui", feature = "tls", feature = "native"))]

use std::sync::Arc;

use clap::Parser;
use parking_lot::RwLock;
use sipnab::app::tui_mode::{TuiMedia, TuiOutput, tui_pipeline_options, tui_process_packet};
use sipnab::capture::{Packet, PacketProcessor, ParsedPacket};
use sipnab::cli::Cli;
use sipnab::rtp::heuristic::RtpHeuristic;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;

#[path = "support/encrypted_captures.rs"]
mod encrypted_captures;
#[path = "support/pcap_build.rs"]
mod pcap_build;

use encrypted_captures::*;

/// Frames read back from an export, each with its PCAP-NG comments.
type Frames = Vec<(Vec<u8>, Vec<String>)>;

/// `frames` as packets captured `every_ms` apart.
fn packets_every(frames: &[Vec<u8>], every_ms: i64) -> Vec<Packet> {
    let base = chrono::Utc::now();
    frames
        .iter()
        .enumerate()
        .map(|(i, f)| Packet {
            timestamp: base + chrono::Duration::milliseconds(i as i64 * every_ms),
            data: f.clone().into(),
            caplen: f.len(),
            origlen: f.len(),
            interface: None,
            link_type: 1,
            pre_parsed: None,
            origin: None,
        })
        .collect()
}

/// What one TUI run wrote and said.
struct Run {
    /// Frames in the `-O` file, with their PCAP-NG comments.
    frames: Frames,
    /// The section comment, when PCAP-NG.
    section: Vec<String>,
    /// The decrypted export's counts line, when there is one.
    summary: Option<String>,
    /// Parsed packets the pipeline observed (the live detectors' view).
    observed: usize,
    /// The step's first error, if any.
    error: Option<String>,
    _dir: tempfile::TempDir,
}

fn tui_run(frames: &[Vec<u8>], mode: &str, paused: bool, stopped: bool) -> Run {
    let dir = tempfile::tempdir().expect("dir");
    let out = dir.path().join("tui.pcapng");
    let cli = Cli::parse_from([
        "sipnab",
        "--pcapng",
        "-O",
        out.to_str().expect("utf-8"),
        "--pcap-export-mode",
        mode,
    ]);
    run_with(&cli, &out, frames, paused, stopped, dir)
}

fn run_with(
    cli: &Cli,
    out: &std::path::Path,
    frames: &[Vec<u8>],
    paused: bool,
    stopped: bool,
    dir: tempfile::TempDir,
) -> Run {
    run_spaced(cli, out, frames, 1, paused, stopped, dir)
}

fn run_spaced(
    cli: &Cli,
    out: &std::path::Path,
    frames: &[Vec<u8>],
    every_ms: i64,
    paused: bool,
    stopped: bool,
    dir: tempfile::TempDir,
) -> Run {
    let mut output = TuiOutput::new(cli, (None, None, None));
    let mut media = TuiMedia::from_cli(cli);
    let mut processor = PacketProcessor::new();
    let ds = Arc::new(RwLock::new(DialogStore::new(64, false)));
    let ss = Arc::new(RwLock::new(StreamStore::new(64)));
    let mut heuristic = RtpHeuristic::new();
    let opts = tui_pipeline_options(cli, false);
    let mut observed = 0usize;
    let mut error = None;
    for p in packets_every(frames, every_ms) {
        if let Err(e) = tui_process_packet(
            &p,
            &mut output,
            &mut processor,
            &ds,
            &ss,
            &mut heuristic,
            &opts,
            &mut media,
            None,
            paused,
            |_: &ParsedPacket| observed += 1,
        ) {
            error = Some(e.to_string());
            break;
        }
    }
    let summary = output.close(stopped);
    let (frames, section) = read_pcapng(out);
    Run {
        frames,
        section,
        summary,
        observed,
        error,
        _dir: dir,
    }
}

fn read_pcapng(path: &std::path::Path) -> (Frames, Vec<String>) {
    use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketOption;
    use pcap_file::pcapng::blocks::section_header::SectionHeaderOption;
    let Ok(raw) = std::fs::read(path) else {
        return (Vec::new(), Vec::new());
    };
    let mut reader = pcap_file::pcapng::PcapNgReader::new(&raw[..]).expect("pcapng");
    let section = reader
        .section()
        .options
        .iter()
        .filter_map(|o| match o {
            SectionHeaderOption::Comment(c) => Some(c.to_string()),
            _ => None,
        })
        .collect();
    let mut frames = Vec::new();
    while let Some(block) = reader.next_block() {
        if let pcap_file::pcapng::Block::EnhancedPacket(epb) = block.expect("block") {
            let comments = epb
                .options
                .iter()
                .filter_map(|o| match o {
                    EnhancedPacketOption::Comment(c) => Some(c.to_string()),
                    _ => None,
                })
                .collect();
            frames.push((epb.data.to_vec(), comments));
        }
    }
    (frames, section)
}

/// UDP payloads from `sport` to `dport` in Ethernet/IPv4 frames.
fn udp_payloads(frames: &Frames, sport: u16, dport: u16) -> Vec<Vec<u8>> {
    frames
        .iter()
        .filter(|(f, _)| f.len() > 42 && f[23] == 17)
        .filter(|(f, _)| {
            u16::from_be_bytes([f[34], f[35]]) == sport
                && u16::from_be_bytes([f[36], f[37]]) == dport
        })
        .map(|(f, _)| f[42..].to_vec())
        .collect()
}

#[test]
fn in_decrypted_mode_the_tuis_srtp_comes_out_as_rtp() {
    let r = tui_run(&sdes_call_frames(), "decrypted", false, false);
    assert!(r.error.is_none(), "{:?}", r.error);
    let rtp = udp_payloads(&r.frames, 40_000, 50_000);
    assert_eq!(rtp.len(), 6, "every DTMF packet");
    for (i, p) in rtp.iter().enumerate() {
        assert_eq!(p.len(), 16, "RTP header and 4-byte event, no auth tag");
        assert_eq!(p[12], if i < 3 { 4 } else { 2 }, "the decrypted digit");
    }
}

#[test]
fn the_tuis_rebuilt_frames_say_what_they_were_decrypted_from() {
    let r = tui_run(&sdes_call_frames(), "decrypted", false, false);
    let labeled: Vec<&Vec<String>> = r
        .frames
        .iter()
        .map(|(_, c)| c)
        .filter(|c| !c.is_empty())
        .collect();
    assert_eq!(labeled.len(), 6);
    assert!(
        labeled
            .iter()
            .all(|c| c == &&vec!["sipnab: decrypted from SRTP".to_string()])
    );
    assert!(
        r.section.iter().any(|c| c.contains("decrypted by sipnab")),
        "{:?}",
        r.section
    );
}

#[test]
fn the_tui_copies_tls_as_captured_and_counts_it() {
    let input = tls_session_frames();
    let r = tui_run(&input, "decrypted", false, false);
    let written: Vec<Vec<u8>> = r.frames.iter().map(|(f, _)| f.clone()).collect();
    assert_eq!(
        written, input,
        "the TUI does not decrypt TLS: every frame as captured"
    );
    let summary = r.summary.expect("a counts line in decrypted mode");
    assert!(
        summary.contains("4 TLS segments copied as captured"),
        "{summary}"
    );
}

#[test]
fn a_stopped_tui_writes_nothing_it_held_and_says_so() {
    let r = tui_run(&sdes_call_frames(), "decrypted", false, true);
    assert!(
        r.frames.is_empty(),
        "stop means stop: {} frames written",
        r.frames.len()
    );
    let summary = r.summary.expect("a counts line");
    assert!(summary.contains("8 discarded at stop"), "{summary}");
}

#[test]
fn in_raw_mode_every_packet_is_written_as_captured() {
    let input = sdes_call_frames();
    let r = tui_run(&input, "raw", false, false);
    let written: Vec<Vec<u8>> = r.frames.iter().map(|(f, _)| f.clone()).collect();
    assert_eq!(written, input);
    assert!(r.summary.is_none(), "no decrypted export, no counts line");
}

#[test]
fn a_paused_tui_still_writes_but_does_not_analyze() {
    let input = sdes_call_frames();
    let r = tui_run(&input, "raw", true, false);
    assert_eq!(
        r.frames.len(),
        input.len(),
        "a paused capture keeps writing"
    );
    assert_eq!(r.observed, 0, "and analyzes nothing");
    let running = tui_run(&input, "raw", false, false);
    assert!(
        running.observed > 0,
        "positive control: an unpaused run observes"
    );
}

#[test]
fn an_output_that_cannot_be_opened_stops_the_thread_with_an_error() {
    let dir = tempfile::tempdir().expect("dir");
    let out = dir.path().join("no-such-dir").join("tui.pcapng");
    let cli = Cli::parse_from(["sipnab", "--pcapng", "-O", out.to_str().expect("utf-8")]);
    let r = run_with(&cli, &out, &sdes_call_frames(), false, false, dir);
    let e = r.error.expect("an error");
    assert!(e.contains("Failed to open output file"), "{e}");
}

/// The thread writes what has waited long enough after every packet, not
/// only at the end: over a capture longer than the 5 s window, the frames that
/// waited it out are in the file even when the run is then stopped, and only
/// the ones still waiting are discarded.
#[test]
fn frames_that_waited_long_enough_are_written_before_a_stop() {
    let dir = tempfile::tempdir().expect("dir");
    let out = dir.path().join("tui.pcapng");
    let cli = Cli::parse_from([
        "sipnab",
        "--pcapng",
        "-O",
        out.to_str().expect("utf-8"),
        "--pcap-export-mode",
        "decrypted",
    ]);
    // Eight packets one second apart, at 0..7 s. When the last arrives the
    // window's edge is at 2 s, and a frame AT the edge has waited the whole
    // window: the ones at 0, 1 and 2 s leave, the other five are still held.
    let r = run_spaced(&cli, &out, &sdes_call_frames(), 1_000, false, true, dir);
    assert_eq!(
        r.frames.len(),
        3,
        "the frames the window had passed were written"
    );
    let summary = r.summary.expect("a counts line");
    assert!(summary.contains("5 discarded at stop"), "{summary}");
}
