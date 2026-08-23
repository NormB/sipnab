// SPDX-License-Identifier: MIT OR Apache-2.0

//! The end-of-capture summary names the sources the detectors accused (BA1).
//!
//! The detectors answer per message, which is the right shape for
//! `--kill-scanner` acting on one packet and the wrong shape for the question
//! an operator asks after a capture: which addresses were probing me. The
//! summary groups the findings the detectors already produced.
//!
//! Driven through the real binary rather than by calling the grouping function
//! directly. The grouping has unit tests of its own; what those cannot show is
//! that `batch` ever CALLS it — a module nothing reaches is the defect this
//! whole feature replaced, so the wiring is what this file proves.
#![cfg(all(feature = "native", feature = "tls", feature = "hep"))]

use std::path::Path;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

use pcap_build::{udp_frame, write_pcap};

/// An `INVITE` to `ext<n>@` from one source, with a unique branch.
///
/// Distinct callees are what the enumeration signal counts, and a unique
/// branch per request is what stops the detector reading them as one
/// retransmitted transaction.
fn probe(n: usize) -> Vec<u8> {
    let sip = format!(
        "INVITE sip:ext{n}@198.51.100.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bK-sweep-{n}\r\n\
         From: <sip:probe@198.51.100.7>;tag=sweep\r\n\
         To: <sip:ext{n}@198.51.100.1>\r\n\
         Call-ID: sweep-{n}@198.51.100.7\r\n\
         CSeq: 1 INVITE\r\n\
         Max-Forwards: 70\r\n\
         User-Agent: friendly-scanner\r\n\
         Content-Length: 0\r\n\r\n"
    );
    udp_frame(
        [198, 51, 100, 7],
        [198, 51, 100, 1],
        5060,
        5060,
        sip.as_bytes(),
    )
}

/// A sweep from one address is reported as ONE accused source, not N findings.
#[test]
fn the_summary_names_the_source_behind_a_sweep() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pcap = tmp.path().join("sweep.pcap");

    // Twelve distinct extensions, none answered: past both the enumeration
    // threshold and the rate threshold, and unanswered is the evidence the
    // rate test rests on.
    let frames: Vec<Vec<u8>> = (0..12).map(probe).collect();
    write_pcap(Path::new(&pcap), &frames);

    let (stdout, stderr, code) = run_support::run(
        &[
            "-N",
            "-I",
            pcap.to_str().expect("utf-8 path"),
            "--portrange",
            "1-65535",
            "--kill-scanner",
        ],
        None,
    );
    let out = format!("{stdout}{stderr}");
    assert_eq!(code, Some(0), "run failed:\n{out}");

    assert!(
        out.contains("named by security detections"),
        "a twelve-extension sweep from one address produced no accusation \
         summary, so batch is not reaching security::sources::accused:\n{out}"
    );
    assert!(
        out.contains("198.51.100.7"),
        "the summary did not name the source it accused:\n{out}"
    );
    // The grouping is the point: one summary line for the source, however
    // many findings name it. Counted on the ACCUSATION lines rather than on
    // every appearance of the address -- the packet echo prints the address
    // once per frame, and a bare `matches` over the whole output measured
    // that instead, which is the count this assertion exists to ignore.
    let summary_lines = out.lines().filter(|l| l.contains("finding(s)")).count();
    assert_eq!(
        summary_lines, 1,
        "the summary carries {summary_lines} accusation lines; one source \
         sweeping is one line:\n{out}"
    );
}

/// An ordinary answered call must not be accused, or the summary is noise.
#[test]
fn an_ordinary_call_is_not_accused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pcap = tmp.path().join("ordinary.pcap");

    let invite = udp_frame(
        [198, 51, 100, 20],
        [198, 51, 100, 1],
        5060,
        5060,
        b"INVITE sip:bob@198.51.100.1 SIP/2.0\r\n\
          Via: SIP/2.0/UDP 198.51.100.20:5060;branch=z9hG4bK-ok-1\r\n\
          From: <sip:alice@198.51.100.20>;tag=a\r\n\
          To: <sip:bob@198.51.100.1>\r\n\
          Call-ID: ordinary-1@198.51.100.20\r\n\
          CSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
    );
    write_pcap(Path::new(&pcap), &[invite]);

    let (stdout, stderr, code) = run_support::run(
        &[
            "-N",
            "-I",
            pcap.to_str().expect("utf-8 path"),
            "--portrange",
            "1-65535",
            "--kill-scanner",
        ],
        None,
    );
    let out = format!("{stdout}{stderr}");
    assert_eq!(code, Some(0), "run failed:\n{out}");
    assert!(
        !out.contains("named by security detections"),
        "one ordinary INVITE was accused; the summary would be noise:\n{out}"
    );
}
