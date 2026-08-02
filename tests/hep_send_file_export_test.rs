// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--hep-send` on a capture FILE must say that the file's contents are
//! leaving the machine.
//!
//! `--hep-send <ADDR>` is a deliberate export to a collector the operator
//! named on the command line, and it stays allowed on a capture file:
//! replaying an archived capture into a Homer instance is a real workflow.
//! That makes it a different question from the scanner-kill path, where
//! sipnab picks the destination out of addresses recorded in the capture and
//! answers third parties who never asked to hear from it (see
//! `offline_never_transmits_test.rs`). Nobody consents to that one. Somebody
//! typed this one.
//!
//! What was missing is the telling. `sipnab -I customer.pcap --hep-send
//! collector:9060` used to log one line — "HEP sender targeting …" — and then
//! forward every SIP message in the capture: request lines, headers, URIs and
//! bodies, unfiltered. An engineer smoke-testing a HEP pipeline against a
//! customer capture has no reason to read that line as "the whole capture is
//! about to leave this box". These tests pin the announcement that now fires
//! before the first packet is read, and pin that the forwarding itself still
//! works.
//!
//! # Why the assertions here are credible
//!
//! The collector is a **real UDP socket on loopback**, bound by this test
//! process, and the counts are of datagrams that actually arrived at it — not
//! of calls to a send function. `harness_observes_a_transmit_when_one_happens`
//! proves the socket can see a datagram by the same route, so a zero count
//! cannot pass for the wrong reason, and
//! `hep_send_on_a_file_source_still_forwards_the_capture` proves the export
//! was not quietly broken in the name of safety.
#![cfg(all(unix, feature = "hep"))]

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

include!("support/timeout.rs");

/// The phrase the file-export announcement must carry. Anchored on the exact
/// wording rather than a loose keyword: "file" and "HEP" both appear in
/// unrelated startup lines, and a substring match on those would let this test
/// pass while the run said nothing about the capture leaving the machine.
const NOTICE_ANCHOR: &str = "capture FILE";

/// Bind a loopback collector socket and return it with the port it got.
fn bound_collector() -> (UdpSocket, u16) {
    let sock = UdpSocket::bind(("127.0.0.1", 0)).expect("bind loopback collector");
    let port = sock.local_addr().expect("collector local addr").port();
    (sock, port)
}

/// The fixture capture forwarded by these tests.
fn fixture_capture() -> String {
    format!(
        "{}/tests/fixtures/sip_call.pcap",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// What one `--hep-send` run produced: the datagrams that reached the
/// collector and the stderr the run wrote.
struct ExportRun {
    /// Number of datagrams that arrived at the collector socket.
    datagrams: usize,
    /// Total bytes across those datagrams.
    bytes: usize,
    /// How many of them began with the `HEP3` magic.
    hep3: usize,
    /// When the first datagram arrived, if any did.
    first_datagram_at: Option<Instant>,
    /// Everything the run wrote to stderr.
    stderr: String,
    /// When the announcement line was seen on stderr, if it was.
    notice_at: Option<Instant>,
    /// The process exit code.
    code: Option<i32>,
}

/// Run `sipnab -N -I <fixture> --hep-send 127.0.0.1:<port>` against a
/// collector this test owns, draining both the socket and stderr while it
/// runs, and return what was observed.
///
/// Both drains are timestamped so a caller can assert the operator was told
/// *before* anything left, which is the whole point of an announcement.
fn run_export(collector: UdpSocket, port: u16) -> ExportRun {
    let target = format!("127.0.0.1:{port}");
    let pcap = fixture_capture();

    // Drain the collector on its own thread: the run must not block on a full
    // socket buffer, and the arrival time of the first datagram is an
    // assertion below.
    collector
        .set_read_timeout(Some(test_timeout(5)))
        .expect("collector read timeout");
    let (count_tx, count_rx) = mpsc::channel();
    let collector_thread = thread::spawn(move || {
        let mut buf = [0u8; 65535];
        let (mut datagrams, mut bytes, mut hep3) = (0usize, 0usize, 0usize);
        let mut first_at: Option<Instant> = None;
        while let Ok((n, _from)) = collector.recv_from(&mut buf) {
            datagrams += 1;
            bytes += n;
            if n >= 4 && &buf[..4] == b"HEP3" {
                hep3 += 1;
            }
            first_at.get_or_insert_with(Instant::now);
        }
        let _ = count_tx.send((datagrams, bytes, hep3, first_at));
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", &pcap, "--hep-send", &target, "--no-cli-print"])
        .env("SIPNAB_LOG", "warn")
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sipnab --hep-send");

    // Read stderr line by line so the announcement can be timestamped as it
    // arrives; tracing writes each event to stderr unbuffered.
    let err_pipe = child.stderr.take().expect("stderr pipe");
    let err_thread = thread::spawn(move || {
        let mut text = String::new();
        let mut notice_at: Option<Instant> = None;
        for line in BufReader::new(err_pipe).lines().map_while(Result::ok) {
            if line.contains(NOTICE_ANCHOR) && notice_at.is_none() {
                notice_at = Some(Instant::now());
            }
            text.push_str(&line);
            text.push('\n');
        }
        (text, notice_at)
    });

    let status = child.wait().expect("wait for sipnab");
    let (stderr, notice_at) = err_thread.join().expect("join stderr reader");
    let (datagrams, bytes, hep3, first_datagram_at) = count_rx
        .recv_timeout(test_timeout(20))
        .expect("collector thread must report a count");
    collector_thread.join().expect("join collector thread");

    ExportRun {
        datagrams,
        bytes,
        hep3,
        first_datagram_at,
        stderr,
        notice_at,
        code: status.code(),
    }
}

/// The collector really can see a datagram sent to it by the same route
/// `--hep-send` uses. Without this control, every count assertion in this file
/// could be passing because the socket observes nothing at all.
#[test]
fn harness_observes_a_transmit_when_one_happens() {
    let (sock, port) = bound_collector();
    sock.set_read_timeout(Some(test_timeout(5)))
        .expect("read timeout");
    let sender = UdpSocket::bind(("127.0.0.1", 0)).expect("bind control sender");
    sender
        .send_to(b"HEP3\x00\x06", ("127.0.0.1", port))
        .expect("send control datagram");

    let mut buf = [0u8; 65535];
    let (n, _from) = sock.recv_from(&mut buf).expect(
        "the control datagram must arrive — otherwise this harness cannot \
         observe a HEP export at all",
    );
    assert_eq!(n, 6, "control datagram truncated");
}

/// A file source plus `--hep-send` must announce that the capture's contents
/// are what leaves, naming the flag and the destination.
///
/// One log line saying "HEP sender targeting <addr>" is what this replaces. It
/// describes the socket, not the consequence, and an engineer pointing a HEP
/// pipeline at a customer capture reads right past it.
#[test]
fn hep_send_on_a_file_source_announces_what_leaves_the_machine() {
    let (sock, port) = bound_collector();
    let run = run_export(sock, port);

    assert!(
        run.stderr.contains(NOTICE_ANCHOR),
        "reading a capture FILE with --hep-send must say so before forwarding \
         it; stderr said:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("--hep-send"),
        "the announcement must name the flag that causes the export; \
         stderr said:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(&format!("127.0.0.1:{port}")),
        "the announcement must name the destination the capture goes to; \
         stderr said:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("sip_call.pcap"),
        "the announcement must name the capture whose contents leave; \
         stderr said:\n{}",
        run.stderr
    );
}

/// The operator gets the announcement *before* the first datagram leaves.
///
/// A warning that arrives after the capture has already been forwarded is a
/// record, not a warning.
#[test]
fn the_announcement_precedes_the_first_datagram() {
    let (sock, port) = bound_collector();
    let run = run_export(sock, port);

    let notice_at = run.notice_at.unwrap_or_else(|| {
        panic!(
            "no file-export announcement was seen on stderr at all; \
             stderr said:\n{}",
            run.stderr
        )
    });
    let first_datagram_at = run.first_datagram_at.unwrap_or_else(|| {
        panic!(
            "no datagram reached the collector, so this test cannot order the \
             announcement against it; stderr said:\n{}",
            run.stderr
        )
    });

    assert!(
        notice_at <= first_datagram_at,
        "the announcement must reach the operator before any of the capture \
         does; it arrived {:?} after the first datagram",
        notice_at.duration_since(first_datagram_at)
    );
}

/// Every `.rs` file under `src/`, concatenated, for the source-shape guard
/// below.
fn crate_sources() -> String {
    fn walk(dir: &std::path::Path, out: &mut String) {
        let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {dir:?}: {e}"));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
                out.push('\n');
            }
        }
    }
    let mut out = String::new();
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut out,
    );
    out
}

/// What stops a recorded address becoming an export target is the *absence* of
/// a constructor, and an absence is exactly what a later patch restores without
/// anyone noticing. This pins it.
///
/// `HepExportPermit` needs an `OperatorDestination`, and an
/// `OperatorDestination` may only be built from a flag or a config value. Add
/// `impl From<SocketAddr> for OperatorDestination` and the whole guarantee is
/// gone — a call site could then export to an address lifted straight out of
/// the capture, which is the failure `TransmitPermit` exists to prevent on the
/// scanner-kill path. The two permits converting into one another would lose
/// the distinction the same way.
///
/// Verified as source shape rather than behaviour because there is no runtime
/// signal for a conversion nobody wrote yet.
#[test]
fn nothing_can_convert_an_address_or_the_other_permit_into_an_export_permit() {
    let src = crate_sources();

    // Any conversion trait implemented FOR either type hands out an instance
    // without going through the operator's flag. The scan is line based
    // because rustfmt keeps an `impl … for …` header on one line.
    for line in src.lines().map(str::trim_start) {
        if !line.starts_with("impl") {
            continue;
        }
        for target in ["OperatorDestination", "HepExportPermit"] {
            let Some(at) = line.find(&format!("for {target}")) else {
                continue;
            };
            let header = &line[..at];
            for conversion in ["From", "TryFrom", "FromStr", "Into", "Default"] {
                assert!(
                    !header.contains(conversion),
                    "`{line}` would let something other than an operator's \
                     flag produce a HEP export target. That absent \
                     constructor IS the export guard — an address read out of \
                     a capture must have no route to becoming a destination."
                );
            }
        }
    }

    // The two permits answer different questions — "this run watches a live
    // source" and "the operator named this destination" — and must not stand
    // in for one another.
    for needle in [
        "TransmitPermit> for HepExportPermit",
        "HepExportPermit> for TransmitPermit",
    ] {
        assert!(
            !src.contains(needle),
            "`impl {needle}` would let a live capture license an export, or an \
             operator's collector license answering a scanner recorded in a \
             file. Neither follows from the other."
        );
    }

    // Both types keep private fields: that is what makes their one
    // constructor the only route, exactly as `TransmitPermit(())` does.
    assert!(
        src.contains("pub struct HepExportPermit(());"),
        "HepExportPermit must keep its private unit field — `pub struct \
         HepExportPermit(pub ())` would let any module conjure a permit."
    );
    // The body only — the `pub struct …` header says nothing about the fields.
    let header = "pub struct OperatorDestination {";
    let fields_start = src
        .find(header)
        .expect("the OperatorDestination declaration must exist")
        + header.len();
    let fields = &src[fields_start..];
    let fields_end = fields
        .find("\n}\n")
        .expect("the OperatorDestination declaration must terminate");
    assert!(
        !fields[..fields_end].contains("pub "),
        "OperatorDestination must keep private fields, or a struct literal \
         becomes a second constructor that skips `from_cli_flag`."
    );

    // And nothing capture-derived may reach the destination's constructors.
    let block_start = src
        .find("impl OperatorDestination {")
        .expect("the OperatorDestination impl block must exist");
    let block = &src[block_start..];
    let block_end = block
        .find("\n}\n")
        .expect("the OperatorDestination impl block must terminate");
    let block = &block[..block_end];
    for capture_derived in ["IpAddr", "SocketAddr", "SipMessage", "HepPacket", "Packet"] {
        assert!(
            !block.contains(capture_derived),
            "`impl OperatorDestination` mentions `{capture_derived}`. A \
             destination must come from a flag or a config file, never from \
             something the capture supplied."
        );
    }
}

/// The export still works. `--hep-send` names a collector the operator chose,
/// so the fix for the silence is to speak, not to block: a refusal here would
/// break replaying an archived capture into a Homer instance, which is the
/// workflow the flag exists for.
#[test]
fn hep_send_on_a_file_source_still_forwards_the_capture() {
    let (sock, port) = bound_collector();
    let run = run_export(sock, port);

    assert_eq!(run.code, Some(0), "the run itself must still succeed");
    assert!(
        run.datagrams > 0,
        "--hep-send on a capture file must still forward it — the \
         announcement is the fix, not a refusal; stderr said:\n{}",
        run.stderr
    );
    assert_eq!(
        run.hep3, run.datagrams,
        "every forwarded datagram must be HEP3 ({} of {} were, {} bytes total)",
        run.hep3, run.datagrams, run.bytes
    );
}
