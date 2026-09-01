// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--recommend-block` turns an accusation into a rule an operator can run
//! (BA2), and never into one sipnab applied.
//!
//! BA1 ended at *"this address was named by these detections"*. That is the
//! answer to "who", and an operator still has to translate it into a firewall
//! by hand — which is the step where the address gets mistyped, the port gets
//! guessed, and the customer who also placed a real call gets banned.
//!
//! Driven through the real binary. The renderer has unit tests of its own for
//! the dialects and the IPv6 split; what those cannot show is that `batch`
//! ever CALLS it, and an unreachable module is the defect BA1 already retired
//! 575 lines over.
#![cfg(all(feature = "native", feature = "tls", feature = "hep"))]

use std::path::Path;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

use pcap_build::{udp_frame, write_pcap};

/// The address every fixture in this file accuses.
const SCANNER: [u8; 4] = [198, 51, 100, 7];
/// The address the fixtures' traffic is aimed at.
const SERVER: [u8; 4] = [198, 51, 100, 1];

/// An `INVITE` to `ext<n>@` from [`SCANNER`], with a unique branch.
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
    udp_frame(SCANNER, SERVER, 5060, 5060, sip.as_bytes())
}

/// Write a sweep fixture and run sipnab over it with the given extra flags.
fn sweep_run(dir: &Path, extra: &[&str]) -> (String, i32) {
    let pcap = dir.join("sweep.pcap");
    let frames: Vec<Vec<u8>> = (0..12).map(probe).collect();
    write_pcap(&pcap, &frames);

    let mut args = vec![
        "-N",
        "-I",
        pcap.to_str().expect("utf-8 path"),
        "--portrange",
        "1-65535",
        "--kill-scanner",
    ];
    args.extend_from_slice(extra);
    let (stdout, stderr, code) = run_support::run(&args, None);
    (
        format!("{stdout}{stderr}"),
        code.expect("sipnab was killed by a signal"),
    )
}

/// The block names the address and carries a rule the operator can run.
#[test]
fn a_swept_source_gets_a_rule_naming_it() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (out, code) = sweep_run(tmp.path(), &["--recommend-block", "nftables"]);
    assert_eq!(code, 0, "run failed:\n{out}");

    assert!(
        out.contains("block recommendation"),
        "--recommend-block produced no recommendation block for a \
         twelve-extension sweep, so batch is not reaching \
         security::recommend:\n{out}"
    );
    assert!(
        out.contains("nft "),
        "the nftables dialect emitted no nft command:\n{out}"
    );
    assert!(
        out.contains("198.51.100.7"),
        "the rule does not name the address it is about:\n{out}"
    );
}

/// The bound BA2 draws is stated in the output, not only in the docs.
///
/// sipnab RECOMMENDS: it applies nothing, reaches no firewall and holds no
/// credential. An operator reading a block of root-shell commands has to be
/// told which side of that line it is on, in the block itself — a caveat one
/// page away is a caveat that was not read.
#[test]
fn the_block_says_sipnab_applied_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (out, code) = sweep_run(tmp.path(), &["--recommend-block", "all"]);
    assert_eq!(code, 0, "run failed:\n{out}");

    assert!(
        out.contains("has applied nothing"),
        "the recommendation does not say sipnab applied nothing:\n{out}"
    );
}

/// The counter-evidence is in the SAME block as the accusation.
///
/// The fixture is the case BA2 was written about: one address that trips a
/// detector AND completed a registration. The behavioral entry is opened by
/// the plain REGISTER, `established` is set by the `200 OK` answering it, and
/// the scanner-UA request that follows is what files the finding. A rule
/// generated from that finding alone would disconnect a working peer.
#[test]
fn an_established_source_carries_its_counter_evidence() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pcap = tmp.path().join("customer.pcap");

    let register = udp_frame(
        SCANNER,
        SERVER,
        5060,
        5060,
        b"REGISTER sip:198.51.100.1 SIP/2.0\r\n\
          Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bK-reg-1\r\n\
          From: <sip:alice@198.51.100.1>;tag=r1\r\n\
          To: <sip:alice@198.51.100.1>\r\n\
          Call-ID: reg-1@198.51.100.7\r\n\
          CSeq: 1 REGISTER\r\nMax-Forwards: 70\r\n\
          User-Agent: Polycom/5.9\r\nContent-Length: 0\r\n\r\n",
    );
    let ok = udp_frame(
        SERVER,
        SCANNER,
        5060,
        5060,
        b"SIP/2.0 200 OK\r\n\
          Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bK-reg-1\r\n\
          From: <sip:alice@198.51.100.1>;tag=r1\r\n\
          To: <sip:alice@198.51.100.1>;tag=s1\r\n\
          Call-ID: reg-1@198.51.100.7\r\n\
          CSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n",
    );
    // The finding. A UA signature, not a behavioral one: `established_factor`
    // deliberately makes a registered peer far harder to accuse on volume, so
    // a rate-based fixture would be arguing with the detector instead of
    // exercising the counter-evidence.
    let scan = udp_frame(
        SCANNER,
        SERVER,
        5060,
        5060,
        b"OPTIONS sip:198.51.100.1 SIP/2.0\r\n\
          Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bK-scan-1\r\n\
          From: <sip:probe@198.51.100.7>;tag=s\r\n\
          To: <sip:198.51.100.1>\r\n\
          Call-ID: scan-1@198.51.100.7\r\n\
          CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\
          User-Agent: friendly-scanner\r\nContent-Length: 0\r\n\r\n",
    );
    write_pcap(&pcap, &[register, ok, scan]);

    let (stdout, stderr, code) = run_support::run(
        &[
            "-N",
            "-I",
            pcap.to_str().expect("utf-8 path"),
            "--portrange",
            "1-65535",
            "--kill-scanner",
            "--recommend-block",
            "iptables",
        ],
        None,
    );
    let out = format!("{stdout}{stderr}");
    assert_eq!(code, Some(0), "run failed:\n{out}");

    assert!(
        out.contains("block recommendation"),
        "the scanner-UA request was not accused, so this fixture proves \
         nothing about counter-evidence:\n{out}"
    );
    assert!(
        out.contains("COUNTER-EVIDENCE"),
        "the block carries no counter-evidence line:\n{out}"
    );
    assert!(
        out.contains("also completed a registration or a call"),
        "the source completed a registration and the block does not say so, \
         so a copy-paste bans a working peer:\n{out}"
    );

    // Not merely stated: withheld. Every command in a block about a source
    // with a relationship is commented out, so the block cannot be run by
    // accident against a customer.
    let live_command = out
        .lines()
        .map(str::trim_start)
        .find(|l| l.starts_with("iptables") || l.starts_with("ip6tables"));
    assert!(
        live_command.is_none(),
        "a block about an established source offers a runnable command: {}",
        live_command.unwrap_or_default()
    );
}

/// A capture with no accusation recommends no rule — and says which silence
/// it is.
///
/// The anti-vacuity half of the gate above: a generator that emits a block for
/// everybody would pass every assertion in this file and be useless.
#[test]
fn an_unaccused_capture_recommends_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pcap = tmp.path().join("ordinary.pcap");

    let invite = udp_frame(
        [198, 51, 100, 20],
        SERVER,
        5060,
        5060,
        b"INVITE sip:bob@198.51.100.1 SIP/2.0\r\n\
          Via: SIP/2.0/UDP 198.51.100.20:5060;branch=z9hG4bK-ok-1\r\n\
          From: <sip:alice@198.51.100.20>;tag=a\r\n\
          To: <sip:bob@198.51.100.1>\r\n\
          Call-ID: ordinary-1@198.51.100.20\r\n\
          CSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
    );
    write_pcap(&pcap, &[invite]);

    let (stdout, stderr, code) = run_support::run(
        &[
            "-N",
            "-I",
            pcap.to_str().expect("utf-8 path"),
            "--portrange",
            "1-65535",
            "--kill-scanner",
            "--recommend-block",
            "all",
        ],
        None,
    );
    let out = format!("{stdout}{stderr}");
    assert_eq!(code, Some(0), "run failed:\n{out}");

    assert!(
        !out.contains("block recommendation"),
        "an ordinary INVITE produced a firewall rule:\n{out}"
    );
    assert!(
        out.contains("no source was accused"),
        "an empty recommendation says nothing about WHY it is empty, which \
         reads as an all-clear:\n{out}"
    );
}

/// The flag prints to stdout, so it carries the same `-N` requirement as the
/// other output flags.
#[test]
fn recommend_block_requires_headless_mode() {
    let (stdout, stderr, code) = run_support::run(&["--recommend-block", "nftables"], None);
    let out = format!("{stdout}{stderr}");
    assert_ne!(code, Some(0), "the run should have been refused:\n{out}");
    assert!(
        out.contains("--recommend-block"),
        "the refusal does not name the flag that caused it:\n{out}"
    );
    // Pinned to the headless refusal specifically. Asserting only "refused"
    // would pass against a build that has no such flag at all — clap rejects
    // an unknown argument non-zero and quotes it back, which is a different
    // failure wearing this test's evidence.
    assert!(
        out.contains("require -N/--no-tui mode"),
        "the run was refused for some other reason than the -N requirement, \
         so this test proves nothing about the flag:\n{out}"
    );
}
