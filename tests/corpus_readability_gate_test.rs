// SPDX-License-Identifier: MIT OR Apache-2.0

//! A capture nobody could open must not read as a capture that held nothing.
//!
//! Every corpus suite walks `SIPNAB_CORPUS` the same way: take each regular
//! file, try to open it, and `continue` on the `Err`. A file the reader refuses
//! therefore contributes nothing to the totals and says nothing on the way out,
//! so the binary reports `ok` having measured one capture fewer than the
//! operator believes. That is how a merged pcapng sat in the corpus entirely
//! unread while all fourteen corpus binaries passed (RDR1), and the reader
//! shipped in 0.5.118 fixes exactly that one class and leaves the silence in
//! place for the next.
//!
//! This binary is the missing measurement. It sweeps the corpus once, counts
//! every capture it could not read, prints the count whether or not it is zero,
//! and fails when it exceeds [`readability::UNREAD_FLOOR`].
//!
//! Three design choices are load-bearing, and all three are gated below:
//!
//! 1. **A count, not a per-file warning.** A warning printed during a passing
//!    run is not read — that is the same defect at a lower volume, and this
//!    repository has already paid for it once with a skip notice that libtest
//!    captured and discarded. So the sweep ends in an assertion.
//! 2. **An empty sweep is a failure.** A corpus with no captures in it would
//!    otherwise satisfy "nothing was unread" perfectly, which is the shape of
//!    passing over nothing.
//! 3. **Both read paths.** The sweep opens each capture the way the corpus
//!    suites do *and* the way the product does. Gating only the suites' own
//!    reader would leave the gate blind to RDR1 itself, whose file `PcapReader`
//!    accepted and libpcap refused.
//!
//! # Running
//!
//! The corpus gate runs when `SIPNAB_CORPUS` names a directory of captures and
//! skips, audibly, when it does not. The synthetic-fixture tests build their
//! own corpora in a temp directory and run everywhere: the real corpus is never
//! committed, so a gate proved only against it is proved nowhere CI can see.
#![cfg(feature = "native")]

use std::io::Write;
use std::path::Path;
use std::process::Command;

#[path = "support/corpus.rs"]
mod corpus_support;
#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/corpus_readability.rs"]
mod readability;

/// A capture with one SIP datagram in it — something the reader accepts and
/// that yields a packet, so it lands in the `read` column.
fn write_readable_capture(path: &Path) {
    let frame = pcap_build::udp_frame(
        [192, 0, 2, 1],
        [192, 0, 2, 2],
        5060,
        5060,
        b"OPTIONS sip:probe SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n",
    );
    pcap_build::write_pcap(path, &[frame]);
}

/// Run the gate in a child process against `root`, returning `(stderr, code)`.
///
/// A child rather than a direct call, and deliberately without `--nocapture`:
/// the property under test is that the gate reaches the *process's* verdict —
/// a non-zero exit and a line on a stderr libtest would otherwise have
/// swallowed. A helper that returns a struct can be right while the suite
/// still reports `ok`, which is the entire defect this file exists about.
fn run_gate(root: &Path) -> (String, Option<i32>) {
    let exe = std::env::current_exe().expect("current_exe");
    let out = Command::new(exe)
        .args(["corpus_readability_probe", "--exact", "--ignored"])
        .env(corpus_support::ENV_VAR, root)
        .output()
        .expect("spawn self");
    (
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

/// The gate itself, spawned by the fixture tests against a synthetic corpus and
/// run by [`every_capture_under_the_corpus_root_is_actually_read`] against the
/// real one. Ignored so a normal pass of this binary never fires it twice.
#[test]
#[ignore = "spawned against a synthetic corpus root by the gate tests in this file"]
fn corpus_readability_probe() {
    let root = corpus_support::root().expect("the probe must run with the corpus set");
    readability::survey(&root).assert_every_capture_was_read();
}

/// A capture the reader refuses is counted, named, and fails the run.
///
/// The fixture is a file with a capture-shaped name and bytes that are not a
/// capture — the cheapest stand-in for "the next unreadable class", which by
/// definition is not one anybody can write a decoder for in advance. Before
/// this gate existed the same directory produced a green run from every corpus
/// binary in the tree.
#[test]
fn an_unopenable_capture_fails_the_gate_and_is_counted() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_readable_capture(&dir.path().join("readable.pcap"));
    std::fs::write(dir.path().join("refused.pcap"), b"not a capture at all")
        .expect("write the unopenable fixture");

    let (stderr, code) = run_gate(dir.path());
    assert_ne!(
        code,
        Some(0),
        "a corpus holding a capture nothing can open must fail the run, not warn \
         inside a passing one. Child stderr was: {stderr:?}"
    );
    assert!(
        stderr.contains("refused.pcap"),
        "the failure must name the file that went unread, or whoever hits it has \
         to re-derive the sweep by hand: {stderr:?}"
    );
    assert!(
        stderr.contains(readability::REPORT_MARKER),
        "the sweep must report its counts on the failing path too: {stderr:?}"
    );
}

/// The count is reported even when it is zero.
///
/// This is the difference between a gate and a warning. "1 unread" is only
/// legible against a run that says "0 unread" when all is well, and a number
/// that appears solely on failure leaves a passing run claiming nothing about
/// how much of the corpus it actually read.
#[test]
fn a_readable_corpus_passes_and_still_reports_what_it_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_readable_capture(&dir.path().join("one.pcap"));
    write_readable_capture(&dir.path().join("two.pcapng"));

    let (stderr, code) = run_gate(dir.path());
    assert_eq!(
        code,
        Some(0),
        "a corpus whose captures all open must pass: {stderr:?}"
    );
    assert!(
        stderr.contains(readability::REPORT_MARKER),
        "a passing sweep must still say how many captures it read and how many it \
         could not: {stderr:?}"
    );
    assert!(
        stderr.contains("2 read"),
        "the report must carry the count of captures actually read: {stderr:?}"
    );
    assert!(
        stderr.contains("0 unread"),
        "the report must state the unread count explicitly, including when it is \
         zero: {stderr:?}"
    );
}

/// Files that are not captures are not captures.
///
/// The corpus root holds logs, scripts and an archive beside the captures. A
/// gate that counted those as unread would fire on every run, and a gate that
/// fires on every run gets its floor raised until it fires on nothing — which
/// is how a ratchet becomes a rubber stamp.
#[test]
fn a_file_that_is_not_a_capture_is_not_counted_as_unread() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_readable_capture(&dir.path().join("real.pcap"));
    std::fs::write(dir.path().join("notes.txt"), b"a note").expect("write");
    std::fs::write(dir.path().join("run.sh"), b"#!/bin/sh\nexit 0\n").expect("write");
    std::fs::write(dir.path().join("bundle.zip"), b"PK\x03\x04nope").expect("write");

    let (stderr, code) = run_gate(dir.path());
    assert_eq!(
        code,
        Some(0),
        "logs, scripts and archives beside the captures must not trip the gate: {stderr:?}"
    );
    assert!(
        stderr.contains("3 not captures"),
        "the sweep must account for every file it walked, so the non-captures are \
         counted rather than dropped: {stderr:?}"
    );
}

/// A capture-shaped name is enough to demand a successful open.
///
/// Magic alone is not: a file truncated to nothing, or written by a tool that
/// died before its header, has no magic to recognize and would be waved through
/// as "not a capture". The corpus is a directory of captures — a `.pcap` in it
/// that holds no capture is a finding, not a stray file.
#[test]
fn a_capture_shaped_name_with_no_magic_is_still_demanded_to_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_readable_capture(&dir.path().join("real.pcap"));
    std::fs::write(dir.path().join("truncated.pcapng"), b"").expect("write");

    let (stderr, code) = run_gate(dir.path());
    assert_ne!(
        code,
        Some(0),
        "an empty file named like a capture must be reported, not classified away: {stderr:?}"
    );
    assert!(
        stderr.contains("truncated.pcapng"),
        "the failure must name it: {stderr:?}"
    );
}

/// A pcap header with no records is "opened it, found nothing" — which is the
/// other half of the distinction this gate exists to draw, and is also unread.
///
/// libpcap and the pure-Rust reader both accept a bare 24-byte global header,
/// so this file passes every `PcapReader::new` in the tree and then contributes
/// zero packets to every total. Indistinguishable, from the totals alone, from
/// a capture that was never opened.
#[test]
fn a_capture_that_opens_and_yields_no_packets_is_unread() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_readable_capture(&dir.path().join("real.pcap"));
    pcap_build::write_pcap(&dir.path().join("headers-only.pcap"), &[]);

    let (stderr, code) = run_gate(dir.path());
    assert_ne!(
        code,
        Some(0),
        "a capture that opens and yields nothing must be reported as unread: {stderr:?}"
    );
    assert!(
        stderr.contains("headers-only.pcap"),
        "the failure must name it: {stderr:?}"
    );
}

/// The RDR1 class, generated rather than borrowed from the corpus.
///
/// A pcapng whose two interfaces disagree on link type and snaplen is the file
/// libpcap refuses on two independent grounds, and per-packet encapsulation is
/// the point of one, so there is no normalization that makes libpcap read it.
/// `PcapReader` has always taken the link type per packet and accepts it, which
/// is exactly why the corpus suites were green over a file `sipnab -r` could
/// not open at all.
///
/// So the gate has to hold BOTH readers to it. It passes today because
/// `capture::merged` shipped in 0.5.118; delete that arm from the product and
/// this test goes red — which is the whole of what RDR2 asks for, proved
/// against a fixture built here rather than against a corpus that is never
/// committed.
#[test]
fn a_merged_pcapng_must_open_through_the_product_read_path_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sip = b"OPTIONS sip:probe SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n";
    let eth = pcap_build::udp_frame([192, 0, 2, 1], [192, 0, 2, 2], 5060, 5060, sip);
    let raw_ip = pcap_build::strip_ethernet(&pcap_build::udp_frame(
        [192, 0, 2, 3],
        [192, 0, 2, 4],
        5060,
        5060,
        sip,
    ));
    // Interface 0 is Ethernet at snaplen 65535, interface 1 raw IP at 2048.
    pcap_build::write_pcapng_multi_iface(
        &dir.path().join("merged.pcapng"),
        &[(0, eth), (1, raw_ip)],
    );

    let (stderr, code) = run_gate(dir.path());
    assert_eq!(
        code,
        Some(0),
        "a merged pcapng is readable since 0.5.118 and must count as read: {stderr:?}"
    );
    assert!(
        stderr.contains("1 read"),
        "the merged capture must land in the read column, not be classified away: {stderr:?}"
    );
}

/// An empty corpus fails rather than satisfying the gate vacuously.
#[test]
fn a_corpus_with_no_captures_fails_rather_than_passing_over_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("readme.txt"), b"no captures here").expect("write");

    let (stderr, code) = run_gate(dir.path());
    assert_ne!(
        code,
        Some(0),
        "zero captures satisfies \"nothing was unread\" perfectly and proves nothing: {stderr:?}"
    );
}

/// The report reaches a stderr libtest would have swallowed.
///
/// [`run_gate`] spawns without `--nocapture`, which is the exact condition the
/// corpus skip notice died under: `eprintln!` goes through the print machinery
/// libtest redirects per test and discards on success, so a report written that
/// way would exist, compile, and reach nobody.
#[test]
fn the_report_survives_libtests_output_capture() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_readable_capture(&dir.path().join("one.pcap"));

    let (stderr, _) = run_gate(dir.path());
    assert!(
        stderr.contains(readability::REPORT_MARKER),
        "the sweep's report left no trace on a captured stderr: {stderr:?}"
    );
    assert_eq!(
        stderr.matches(readability::REPORT_MARKER).count(),
        1,
        "one report line per binary, not one per capture — a wall of lines is the \
         same failure in a louder font: {stderr:?}"
    );
}

/// The gate, against the real corpus.
///
/// Skips, audibly, when `SIPNAB_CORPUS` is unset. When it is set this is the
/// only test in the tree that can tell "read it, found nothing" from "never
/// opened it" across the whole corpus.
#[test]
fn every_capture_under_the_corpus_root_is_actually_read() {
    let Some(root) = corpus_support::root() else {
        // Audible, and to the REAL stderr, for the same reason `announce()`
        // writes there: libtest throws its buffer away when a test passes, so
        // a skip announced with `eprintln!` is printed on exactly the runs
        // nobody reads. A silent skip here would be this gate committing the
        // defect it exists to catch -- a measurement that did not happen,
        // reported as one that passed.
        let mut err = std::io::stderr();
        let _ = writeln!(
            err,
            "CORPUS READABILITY: SKIPPED — SIPNAB_CORPUS is unset, so no \
             capture was checked. Set it to validate: \
             SIPNAB_CORPUS=/path/to/pcaps cargo test --features full"
        );
        return;
    };
    readability::survey(&root).assert_every_capture_was_read();
}
