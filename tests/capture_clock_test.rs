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
//!
//! Two more pin the same sweep across the `--cores` boundary, where it was
//! absent entirely: the parallel path merged its workers' stores and reported
//! them unswept, so the same bytes produced one answer at `--cores 1` and
//! another at `--cores 4`.
//!
//! 3. [`cores_flags_the_same_orphans_as_the_single_threaded_path`] — the
//!    `Orphaned Streams:` section is the same on both paths.
//! 4. [`cores_compacts_idle_dialogs_like_the_single_threaded_path`] — an idle
//!    dialog keeps the same message count on both paths.
#![cfg(feature = "native")]

use std::path::Path;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

/// Call-ID of the long dialog both fixtures build.
const CALL_ID: &str = "long-dialog-1@10.1.0.1";

/// Call-ID of the second leg's dialog in the two-host-pair fixture.
const CALL_ID_2: &str = "long-dialog-2@10.3.0.1";

/// SSRC of the unassociated (no SDP) RTP stream both fixtures build.
const SSRC: &str = "0x11223344";

/// SSRC of the unassociated RTP stream on the two-host-pair fixture's second
/// leg, spelled as the report prints it.
const SSRC_2: &str = "0x55667788";

/// Numeric form of [`SSRC`], which the RTP frames carry.
const SSRC_BITS: u32 = 0x1122_3344;

/// Numeric form of [`SSRC_2`].
const SSRC_2_BITS: u32 = 0x5566_7788;

/// Messages in the long dialog: comfortably over
/// `KEEP_MESSAGES_PER_IDLE_DIALOG` (20), so a wrongly-fired compaction is
/// unmistakable in the report's `Msgs` column.
const DIALOG_MESSAGES: usize = 44;

/// Messages an idle dialog keeps, `KEEP_MESSAGES_PER_IDLE_DIALOG`.
const KEPT_WHEN_IDLE: usize = 20;

/// Caller-side address of the synthetic capture.
const A: [u8; 4] = [10, 1, 0, 1];
/// Callee-side address of the synthetic capture.
const B: [u8; 4] = [10, 2, 0, 1];
/// Caller-side address of the second host pair.
const C: [u8; 4] = [10, 3, 0, 1];
/// Callee-side address of the second host pair.
const D: [u8; 4] = [10, 4, 0, 1];

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
    dialog_records_between(A, B, CALL_ID, start_us, step_us)
}

/// The long dialog carried between `a` and `b` under `call_id`.
///
/// The message bodies are the same ones [`long_dialog_messages`] builds, with
/// the Call-ID substituted: the dialog store groups by Call-ID, so a second
/// copy on a second host pair reconstructs as a second dialog. The host pair is
/// what decides the `--cores` worker, which is the point of the second leg —
/// see [`two_leg_idle_capture`].
fn dialog_records_between(
    a: [u8; 4],
    b: [u8; 4],
    call_id: &str,
    start_us: u64,
    step_us: u64,
) -> Vec<Record> {
    long_dialog_messages()
        .into_iter()
        .enumerate()
        .map(|(i, (from_caller, msg))| {
            let msg = msg.replace(CALL_ID, call_id);
            let frame = if from_caller {
                pcap_build::udp_frame(a, b, 5060, 5060, msg.as_bytes())
            } else {
                pcap_build::udp_frame(b, a, 5060, 5060, msg.as_bytes())
            };
            (start_us + i as u64 * step_us, frame)
        })
        .collect()
}

/// `count` RTP frames on a port pair no SDP ever announced, so the stream
/// stays unassociated and is a candidate for orphan flagging.
fn rtp_records(start_us: u64, step_us: u64, count: u64) -> Vec<Record> {
    rtp_records_between(A, B, SSRC_BITS, start_us, step_us, count)
}

/// [`rtp_records`] on an explicit host pair and SSRC, so the fixture can carry
/// one unassociated stream per `--cores` worker.
fn rtp_records_between(
    a: [u8; 4],
    b: [u8; 4],
    ssrc: u32,
    start_us: u64,
    step_us: u64,
    count: u64,
) -> Vec<Record> {
    (0..count)
        .map(|n| {
            let seq = (n + 1) as u16;
            let mut payload = Vec::with_capacity(172);
            payload.push(0x80); // version 2, no padding/extension/CSRC
            payload.push(0x00); // payload type 0 (PCMU), no marker
            payload.extend_from_slice(&seq.to_be_bytes());
            payload.extend_from_slice(&(160 * (n as u32 + 1)).to_be_bytes());
            payload.extend_from_slice(&ssrc.to_be_bytes());
            payload.extend(std::iter::repeat_n(0u8, 160));
            (
                start_us + n * step_us,
                pcap_build::udp_frame(a, b, 40000, 40002, &payload),
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

/// The `Msgs` column of the report row for `call_id`.
///
/// Read from the right: `Msgs` is third-from-last (`… Msgs PDD Tags`), which
/// survives a `Duration` cell that splits into two tokens (`1m 30s`).
fn dialog_msg_count(report: &str, call_id: &str) -> usize {
    let row = report
        .lines()
        .find(|l| l.starts_with(call_id))
        .unwrap_or_else(|| panic!("no report row for {call_id} in:\n{report}"));
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
        dialog_msg_count(&fast, CALL_ID),
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
        dialog_msg_count(&out, CALL_ID),
        KEPT_WHEN_IDLE,
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

// ── `--cores` parity: the sweep must cross the parallel boundary ────

/// Rows in the report's `Orphaned Streams:` section, zero when the section is
/// absent — which is how the report says "none".
///
/// Every row starts with the SSRC as `0x{:08x}` and the section is the last one
/// the report prints, so a prefix count over the tail is exact. Counting rows
/// rather than comparing the rendered section keeps the assertion on the
/// classification under test and off the column widths.
fn orphan_rows(report: &str) -> usize {
    orphan_section(report)
        .lines()
        .filter(|l| l.starts_with("0x"))
        .count()
}

/// Everything the report printed after `Orphaned Streams:`, or the empty
/// string when it printed no such section.
fn orphan_section(report: &str) -> &str {
    report
        .split_once("Orphaned Streams:")
        .map_or("", |(_, tail)| tail)
}

/// Write the two-host-pair idle capture both parity tests read.
///
/// Leg one (`A`↔`B`) carries the long dialog, an unassociated RTP stream, and
/// then filler packets that walk the capture clock out to fifteen minutes. Leg
/// two (`C`↔`D`) carries the same two shapes and STOPS at ~6.5 s.
///
/// The second leg is what makes this fixture able to fail. `--cores` shards by
/// host pair, so the two legs land on different workers, and leg two's worker
/// sees nothing after 6.5 s. A sweep run per worker would measure leg two
/// against its own local last packet, find it neither ten minutes idle nor
/// thirty seconds unassociated, and leave it alone — a third answer, agreeing
/// with neither path. Only a single sweep at the whole capture's final
/// timestamp reproduces what the single-threaded run reports.
fn two_leg_idle_capture(path: &Path) {
    let mut records = dialog_records(0, 80_000);
    records.extend(rtp_records(4_000_000, 20_000, 100));
    records.extend(dialog_records_between(C, D, CALL_ID_2, 100_000, 80_000));
    records.extend(rtp_records_between(
        C,
        D,
        SSRC_2_BITS,
        4_500_000,
        20_000,
        100,
    ));
    records.extend(filler_records(10_000_000, 5_000_000, 179));
    // A pcap reader trusts file order, and so does the capture clock.
    records.sort_by_key(|(offset_us, _)| *offset_us);
    write_pcap_at(path, &records);
}

/// Fail loudly when the fixture's two legs no longer land on different
/// `--cores 4` workers.
///
/// The sharding hash is an implementation detail that may change. If it ever
/// maps both pairs to one worker the parity tests still pass, but they stop
/// discriminating a single post-merge sweep from a per-worker one — the
/// quietest way for this coverage to rot.
fn legs_shard_apart() {
    let shard = |x: [u8; 4], y: [u8; 4]| {
        sipnab::parallel::shard_for(std::net::IpAddr::from(x), std::net::IpAddr::from(y), 4)
    };
    assert_ne!(
        shard(A, B),
        shard(C, D),
        "both fixture legs now shard to one worker, so the fixture can no \
         longer tell a post-merge sweep from a per-worker sweep"
    );
}

/// `--cores` must flag the same orphaned streams as the single-threaded path.
///
/// The parallel path never swept. It merged its workers' stores, resolved
/// stream↔dialog association globally, and reported the result unflagged: on
/// one reference-corpus set the single-threaded run listed 80 orphaned streams
/// and `--cores 4` listed none, with those same streams appearing in the
/// ordinary RTP section as though they belonged to a call. The header was
/// missing altogether, so nothing on the page said the classification had not
/// been made.
///
/// The equality is asserted against a count the single-threaded path is also
/// pinned to, so "both agree on none" cannot pass this test.
#[test]
fn cores_flags_the_same_orphans_as_the_single_threaded_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("cores-orphans.pcap");
    two_leg_idle_capture(&pcap);
    legs_shard_apart();

    let single = report(&pcap, &[]);
    let cores = report(&pcap, &["--cores", "4"]);

    assert_eq!(
        orphan_rows(&single),
        2,
        "the fixture must produce two orphaned streams single-threaded, or \
         this test passes on two empty sections:\n{single}"
    );
    assert_eq!(
        orphan_rows(&cores),
        orphan_rows(&single),
        "--cores reported a different number of orphaned streams for the same \
         bytes.\n--- single ---\n{single}\n--- cores 4 ---\n{cores}"
    );
    let orphans = orphan_section(&cores);
    for ssrc in [SSRC, SSRC_2] {
        assert!(
            orphans.contains(ssrc),
            "stream {ssrc} was unassociated for the whole capture and must be \
             flagged orphaned under --cores too:\n{cores}"
        );
    }
}

/// `--cores` must sweep on the CAPTURE's clock, like the single-threaded path.
///
/// The parity the two tests above assert is satisfied by a sweep that reads
/// `Utc::now()`, because every dialog and stream in that fixture is genuinely
/// idle and genuinely unassociated — a wall clock reaches the same verdict for
/// the wrong reason. This capture is the opposite case: it spans seven seconds
/// recorded years ago, so nothing in it is ten minutes idle or thirty seconds
/// unassociated in capture time, while EVERYTHING in it is by the wall clock.
///
/// A `--cores` sweep on wall time therefore compacts a dialog that was never
/// idle and flags a stream that lived four seconds — the exact defect #57
/// removed from the single-threaded path, reintroduced behind a flag.
#[test]
fn cores_sweeps_on_capture_time_not_wall_time() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("cores-short.pcap");

    let mut records = dialog_records(0, 80_000);
    records.extend(rtp_records(3_600_000, 40_000, 90));
    write_pcap_at(&pcap, &records);

    let single = report(&pcap, &[]);
    let cores = report(&pcap, &["--cores", "4"]);

    assert_eq!(
        dialog_msg_count(&single, CALL_ID),
        DIALOG_MESSAGES,
        "the fixture must keep every message single-threaded, or this test \
         cannot tell a capture-clock sweep from a wall-clock one:\n{single}"
    );
    assert_eq!(
        dialog_msg_count(&cores, CALL_ID),
        DIALOG_MESSAGES,
        "--cores compacted a dialog that was idle for three seconds of capture \
         time, which only a wall-clock sweep would do:\n{cores}"
    );
    assert_eq!(
        orphan_rows(&cores),
        0,
        "--cores flagged a stream that lived under four seconds of capture time \
         against a 30 s timeout:\n{cores}"
    );
}

/// `--cores` must compact idle dialogs like the single-threaded path.
///
/// Compaction is the memory bound, so skipping it under `--cores` also meant
/// the parallel path's retained-message count was whatever the capture held —
/// on the same reference corpus, 84,882 retained messages against the
/// single-threaded path's 84,568.
///
/// Both dialogs are checked. Leg two's is the one a per-worker sweep would
/// leave alone, because its own worker's last packet is fourteen minutes
/// before the capture's.
#[test]
fn cores_compacts_idle_dialogs_like_the_single_threaded_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("cores-idle.pcap");
    two_leg_idle_capture(&pcap);
    legs_shard_apart();

    let single = report(&pcap, &[]);
    let cores = report(&pcap, &["--cores", "4"]);

    for call_id in [CALL_ID, CALL_ID_2] {
        // Positive control: the single-threaded path really did compact, so a
        // change that stopped BOTH paths sweeping fails here rather than
        // passing on an agreed 44.
        assert_eq!(
            dialog_msg_count(&single, call_id),
            KEPT_WHEN_IDLE,
            "{call_id} was idle for minutes of capture time and must be \
             compacted single-threaded, or the parity below is vacuous:\n{single}"
        );
        assert_eq!(
            dialog_msg_count(&cores, call_id),
            dialog_msg_count(&single, call_id),
            "--cores kept a different number of messages for {call_id}.\
             \n--- single ---\n{single}\n--- cores 4 ---\n{cores}"
        );
    }
}
