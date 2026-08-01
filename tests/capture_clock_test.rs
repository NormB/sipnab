// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline analysis must not depend on how fast the machine reads the file.
//!
//! The periodic sweep (idle-dialog compaction + RTP orphan flagging) used to
//! be gated on wall-clock time and to compare `Utc::now()` against *packet*
//! timestamps. Offline those two clocks are unrelated: a capture recorded in
//! 2023 and read in 2026 is three years "idle" the instant it is loaded, so
//! every sweep that happened to fire truncated every dialog to
//! `KEEP_MESSAGES_PER_IDLE_DIALOG` and flagged every unassociated stream as
//! orphaned. How many sweeps fired was decided by how long the *read* took —
//! a debug build and a release build over the same bytes printed different
//! reports, and so did the same build on a loaded machine.
//!
//! Two properties are pinned here, and both are needed: the first alone is
//! satisfied by never sweeping offline, the second alone is satisfied by
//! sweeping on wall time as long as the machine is consistently slow.
//!
//! 1. [`offline_report_is_identical_fast_and_slow`] — the same capture read at
//!    two very different speeds produces byte-identical output.
//! 2. [`offline_compaction_follows_capture_time`] — compaction and orphan
//!    flagging still happen offline, driven by the capture's own timeline.
#![cfg(feature = "native")]

use std::path::Path;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

/// Call-ID of the long dialog both fixtures build.
const CALL_ID: &str = "long-dialog-1@10.1.0.1";

/// SSRC of the unassociated (no SDP) RTP stream both fixtures build.
const SSRC: &str = "0x11223344";

/// Messages in the long dialog: comfortably over
/// `KEEP_MESSAGES_PER_IDLE_DIALOG` (20), so a wrongly-fired compaction is
/// unmistakable in the report's `Msgs` column.
const DIALOG_MESSAGES: usize = 44;

/// Caller-side address of the synthetic capture.
const A: [u8; 4] = [10, 1, 0, 1];
/// Callee-side address of the synthetic capture.
const B: [u8; 4] = [10, 2, 0, 1];

/// One `(capture-time offset in microseconds, frame)` record.
type Record = (u64, Vec<u8>);

/// Write `records` as a little-endian Ethernet pcap, honoring each record's
/// own capture-time offset.
///
/// `pcap_build::write_pcap` hard-codes a 1 ms step, which cannot express
/// either fixture here: one needs a multi-second span so `--replay` produces a
/// genuinely slow read, the other needs a span longer than the ten-minute idle
/// threshold.
fn write_pcap_at(path: &Path, records: &[Record]) {
    /// Arbitrary fixed epoch for the capture (2023-11-14T22:13:20Z). Fixed so
    /// the fixture bytes are reproducible; in the past so that any code still
    /// comparing packet time against `Utc::now()` sees a huge idle age.
    const BASE_SECS: u64 = 1_700_000_000;

    let mut out = Vec::new();
    // magic, version 2.4, thiszone, sigfigs, snaplen, network=1 (Ethernet)
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());

    for (offset_us, frame) in records {
        let secs = BASE_SECS + offset_us / 1_000_000;
        let usecs = offset_us % 1_000_000;
        out.extend_from_slice(&(secs as u32).to_le_bytes());
        out.extend_from_slice(&(usecs as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
    }
    std::fs::write(path, out).expect("write pcap");
}

/// The [`DIALOG_MESSAGES`] SIP payloads of one long call, paired with the
/// direction each travels (`true` = caller → callee).
///
/// INVITE / 100 / 180 / 200 / ACK, then nineteen in-dialog OPTIONS
/// transactions, then BYE. The trailing `200 OK` for the INVITE matters to the
/// assertions: it is among the *oldest* messages, so a compaction that keeps
/// only the last twenty drops it and the report's `Code` column falls back to
/// `-`.
fn long_dialog_messages() -> Vec<(bool, String)> {
    let via = |b: &str| format!("Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bK{b}\r\n");
    let from = "From: <sip:alice@10.1.0.1>;tag=t1\r\n";
    let to = "To: <sip:bob@10.2.0.1>";
    let to_tagged = "To: <sip:bob@10.2.0.1>;tag=b1\r\n";
    let cid = format!("Call-ID: {CALL_ID}\r\n");

    let mut msgs = vec![
        (
            true,
            format!(
                "INVITE sip:bob@10.2.0.1 SIP/2.0\r\n{}Max-Forwards: 70\r\n{from}{to}\r\n{cid}\
                 CSeq: 1 INVITE\r\nContact: <sip:alice@10.1.0.1:5060>\r\nContent-Length: 0\r\n\r\n",
                via("inv")
            ),
        ),
        (
            false,
            format!(
                "SIP/2.0 100 Trying\r\n{}{from}{to}\r\n{cid}CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
                via("inv")
            ),
        ),
        (
            false,
            format!(
                "SIP/2.0 180 Ringing\r\n{}{from}{to_tagged}{cid}CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
                via("inv")
            ),
        ),
        (
            false,
            format!(
                "SIP/2.0 200 OK\r\n{}{from}{to_tagged}{cid}CSeq: 1 INVITE\r\n\
                 Contact: <sip:bob@10.2.0.1:5060>\r\nContent-Length: 0\r\n\r\n",
                via("inv")
            ),
        ),
        (
            true,
            format!(
                "ACK sip:bob@10.2.0.1 SIP/2.0\r\n{}Max-Forwards: 70\r\n{from}{to_tagged}{cid}\
                 CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n",
                via("ack")
            ),
        ),
    ];
    for i in 0..19 {
        let cseq = 2 + i;
        msgs.push((
            true,
            format!(
                "OPTIONS sip:bob@10.2.0.1 SIP/2.0\r\n{}Max-Forwards: 70\r\n{from}{to_tagged}{cid}\
                 CSeq: {cseq} OPTIONS\r\nContent-Length: 0\r\n\r\n",
                via(&format!("opt{i}"))
            ),
        ));
        msgs.push((
            false,
            format!(
                "SIP/2.0 200 OK\r\n{}{from}{to_tagged}{cid}CSeq: {cseq} OPTIONS\r\nContent-Length: 0\r\n\r\n",
                via(&format!("opt{i}"))
            ),
        ));
    }
    msgs.push((
        true,
        format!(
            "BYE sip:bob@10.2.0.1 SIP/2.0\r\n{}Max-Forwards: 70\r\n{from}{to_tagged}{cid}\
             CSeq: 30 BYE\r\nContent-Length: 0\r\n\r\n",
            via("bye")
        ),
    ));
    assert_eq!(msgs.len(), DIALOG_MESSAGES, "fixture message count");
    msgs
}

/// The long dialog's frames, the first at `start_us` and one every
/// `step_us` afterwards.
fn dialog_records(start_us: u64, step_us: u64) -> Vec<Record> {
    long_dialog_messages()
        .into_iter()
        .enumerate()
        .map(|(i, (from_caller, msg))| {
            let frame = if from_caller {
                pcap_build::udp_frame(A, B, 5060, 5060, msg.as_bytes())
            } else {
                pcap_build::udp_frame(B, A, 5060, 5060, msg.as_bytes())
            };
            (start_us + i as u64 * step_us, frame)
        })
        .collect()
}

/// `count` RTP frames on a port pair no SDP ever announced, so the stream
/// stays unassociated and is a candidate for orphan flagging.
fn rtp_records(start_us: u64, step_us: u64, count: u64) -> Vec<Record> {
    (0..count)
        .map(|n| {
            let seq = (n + 1) as u16;
            let mut payload = Vec::with_capacity(172);
            payload.push(0x80); // version 2, no padding/extension/CSRC
            payload.push(0x00); // payload type 0 (PCMU), no marker
            payload.extend_from_slice(&seq.to_be_bytes());
            payload.extend_from_slice(&(160 * (n as u32 + 1)).to_be_bytes());
            payload.extend_from_slice(&0x1122_3344u32.to_be_bytes());
            payload.extend(std::iter::repeat_n(0u8, 160));
            (
                start_us + n * step_us,
                pcap_build::udp_frame(A, B, 40000, 40002, &payload),
            )
        })
        .collect()
}

/// `count` non-SIP, non-RTP UDP frames whose only job is to advance the
/// capture clock.
///
/// Port 9999 is outside the default SIP port range and the leading zero byte
/// fails the RTP version check, so these packets contribute nothing to the
/// report — they only move the capture's timeline forward.
fn filler_records(start_us: u64, step_us: u64, count: u64) -> Vec<Record> {
    (0..count)
        .map(|n| {
            (
                start_us + n * step_us,
                pcap_build::udp_frame(A, B, 9999, 9999, b"\x00\x00\x00\x00filler"),
            )
        })
        .collect()
}

/// Run `sipnab --report` over `pcap`, asserting exit 0, and return stdout.
fn report(pcap: &Path, extra: &[&str]) -> String {
    let path = pcap.to_str().expect("utf-8 fixture path");
    let mut args = vec!["-N", "-I", path, "--report", "--no-cli-print", "-q"];
    args.extend_from_slice(extra);
    let (stdout, stderr, code) = run_support::run(&args, Some("off"));
    assert_eq!(code, Some(0), "sipnab {args:?} failed: {stderr}");
    stdout
}

/// The `Msgs` column of the report row for [`CALL_ID`].
///
/// Read from the right: `Msgs` is third-from-last (`… Msgs PDD Tags`), which
/// survives a `Duration` cell that splits into two tokens (`1m 30s`).
fn dialog_msg_count(report: &str) -> usize {
    let row = report
        .lines()
        .find(|l| l.starts_with(CALL_ID))
        .unwrap_or_else(|| panic!("no report row for {CALL_ID} in:\n{report}"));
    let fields: Vec<&str> = row.split_whitespace().collect();
    let msgs = fields[fields.len() - 3];
    msgs.parse()
        .unwrap_or_else(|e| panic!("Msgs cell {msgs:?} of row {row:?} is not a count: {e}"))
}

/// Reading the same capture fast and slowly must produce the same report.
///
/// The fixture spans just over seven seconds of capture time, so `--replay`
/// (which reproduces the original inter-packet gaps) takes over seven wall
/// seconds while a plain read takes milliseconds. The five-second sweep timer
/// therefore fires during the slow read and not during the fast one — the
/// exact asymmetry that used to change the answer.
///
/// This cannot flake in the failing direction: once both clocks come from the
/// packets, the report is a pure function of the fixture bytes, so a loaded or
/// slow CI machine changes neither run. A machine slow enough to spend five
/// wall seconds on a 130-packet file would make the two runs agree, not
/// disagree — the failure mode is a missed regression, never a false alarm.
#[test]
fn offline_report_is_identical_fast_and_slow() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("speed.pcap");

    // 44 SIP messages over the first 3.44 s, then RTP out to ~7.2 s. All of
    // the dialog is in before the five-second wall-clock sweep would land, so
    // a wrongly-fired compaction cannot be refilled by later messages.
    let mut records = dialog_records(0, 80_000);
    records.extend(rtp_records(3_600_000, 40_000, 90));
    write_pcap_at(&pcap, &records);

    let fast = report(&pcap, &[]);
    let slow = report(&pcap, &["--replay"]);

    assert_eq!(
        fast, slow,
        "offline report changed with read speed.\n--- fast read ---\n{fast}\n--- slow read (--replay) ---\n{slow}"
    );
    assert_eq!(
        dialog_msg_count(&fast),
        DIALOG_MESSAGES,
        "the fast read lost messages from {CALL_ID}:\n{fast}"
    );
    // Equality alone does not pin the orphan rule: with a capture-paced sweep,
    // a `mark_orphaned` still measuring against `Utc::now()` flags the stream
    // in BOTH runs and they stay identical. The stream lives under four
    // seconds of capture time against a thirty-second timeout, so the only
    // correct answer is "not orphaned".
    assert!(
        !fast.contains("Orphaned Streams:"),
        "stream {SSRC} lived under four seconds of capture time but was flagged \
         orphaned against a 30 s timeout:\n{fast}"
    );
}

/// Offline sweeps still fire — on the capture's clock.
///
/// The guard against speed dependence must not become "never sweep offline":
/// a capture that really does contain a ten-minute idle gap must still be
/// compacted, and a stream unassociated for more than thirty seconds of
/// capture time must still be flagged orphaned. Both are asserted from a fast
/// read, where wall time never gets anywhere near those thresholds.
#[test]
fn offline_compaction_follows_capture_time() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("idle.pcap");

    // The dialog and the RTP burst finish inside the first six seconds; filler
    // packets then carry the capture clock out to fifteen minutes, well past
    // both the ten-minute idle-compaction threshold and the thirty-second
    // orphan timeout.
    let mut records = dialog_records(0, 80_000);
    records.extend(rtp_records(4_000_000, 20_000, 100));
    records.extend(filler_records(10_000_000, 5_000_000, 179));
    write_pcap_at(&pcap, &records);

    let out = report(&pcap, &[]);

    assert_eq!(
        dialog_msg_count(&out),
        20,
        "a dialog idle for five minutes of capture time was not compacted to \
         KEEP_MESSAGES_PER_IDLE_DIALOG:\n{out}"
    );
    let orphans = out
        .split_once("Orphaned Streams:")
        .map(|(_, tail)| tail)
        .unwrap_or_else(|| panic!("no orphaned-stream section:\n{out}"));
    assert!(
        orphans.contains(SSRC),
        "stream {SSRC} was unassociated for fourteen minutes of capture time but \
         was not flagged orphaned:\n{out}"
    );
}
