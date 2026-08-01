// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading a capture FILE must never put a packet on the network.
//!
//! The scanner-kill path (`--kill-scanner`, `-K/--kill-target`) answers a
//! detected scanner with a real SIP response. That is a defensible thing to do
//! while watching a live interface the operator owns: the addresses are
//! current, and the scanner is there now.
//!
//! Applied to a capture file it is not defensible at all. `-I customer.pcap`
//! reads addresses that were recorded at some point in the past — a customer's
//! production endpoints, or arbitrary internet hosts in a forensic capture,
//! possibly reassigned since. Nothing about handing a tool a file suggests the
//! tool will emit traffic, and the analyst is very often not on the network the
//! capture came from. The harm is silent, immediate, and irreversible.
//!
//! # How these tests contain the harm they reproduce
//!
//! The synthetic capture names **127.0.0.1 on a port this test process itself
//! owns** as the scanner. Loopback cannot leave the host, and the only listener
//! is the test's own socket. So a regression makes a packet arrive *here*, in a
//! socket we control, instead of at a third party.
//!
//! # Why the "nothing was transmitted" assertion is credible
//!
//! Three properties together, not the timeout alone:
//!
//! 1. The assertion is made at a **real socket**, on the exact address the
//!    capture records, in a separate process from the one under test. It is not
//!    "the send function was not called" — it is "nothing reached a socket".
//! 2. The same test asserts the scanner **was detected** on the same run
//!    (`--fail2ban` prints the event). Without that, a silent-green test could
//!    equally be reporting that detection never ran, that the pcap was
//!    unreadable, or that the binary exited early — the exact false negatives a
//!    bare "nothing arrived" cannot distinguish.
//! 3. The harness is proven capable of *observing* a transmit: this file's
//!    `harness_observes_a_transmit_when_one_happens` sends one datagram to the
//!    same socket by the same route and requires it to arrive. A listener that
//!    can never receive anything would pass every no-transmit assertion.

use std::net::UdpSocket;
use std::time::Duration;

#[path = "support/pcap_build.rs"]
mod pcap_build;

/// How long to wait for a datagram that must never come. Long enough that a
/// slow machine cannot manufacture a false green, short enough for CI.
const QUIET_WINDOW: Duration = Duration::from_secs(3);

/// Bind a loopback UDP socket and return it with the port it got.
///
/// The port is what the synthetic capture will record as the scanner's source
/// port, so any kill response is addressed straight back here.
fn bound_listener() -> (UdpSocket, u16) {
    let sock = UdpSocket::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let port = sock.local_addr().expect("local addr").port();
    sock.set_read_timeout(Some(QUIET_WINDOW))
        .expect("set read timeout");
    (sock, port)
}

/// Write a one-packet capture holding a SIP OPTIONS from `127.0.0.1:port`
/// carrying a scanner User-Agent, and return its path.
fn scanner_capture(dir: &std::path::Path, port: u16) -> std::path::PathBuf {
    let msg = format!(
        "OPTIONS sip:target@127.0.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bK-offline-kill\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:scanner@127.0.0.1>;tag=offline1\r\n\
         To: <sip:target@127.0.0.1>\r\n\
         Call-ID: offline-kill-guard\r\n\
         CSeq: 1 OPTIONS\r\n\
         User-Agent: friendly-scanner\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let frame = pcap_build::udp_frame([127, 0, 0, 1], [127, 0, 0, 1], port, 5060, msg.as_bytes());
    let path = dir.join("scanner.pcap");
    pcap_build::write_pcap(&path, &[frame]);
    path
}

/// A fresh temp directory for one test's capture.
fn tmp_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sipnab-offline-transmit-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create temp dir");
    d
}

/// Run sipnab over `pcap` with the given extra flags, returning
/// `(stdout, stderr, exit_code)`.
fn run_offline(pcap: &std::path::Path, extra: &[&str]) -> (String, String, Option<i32>) {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "-I"])
        .arg(pcap)
        .args(["--fail2ban", "--no-cli-print"])
        .args(extra)
        .env("SIPNAB_LOG", "info")
        .env("NO_COLOR", "1");
    let out = cmd.output().expect("spawn sipnab");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

/// Assert that nothing at all arrived on `sock` within the quiet window.
fn assert_silent(sock: &UdpSocket, what: &str) {
    let mut buf = [0u8; 4096];
    match sock.recv_from(&mut buf) {
        Ok((n, from)) => panic!(
            "{what}: sipnab TRANSMITTED {n} bytes to the address recorded in the \
             capture (seen arriving from {from}). Offline analysis must never \
             put a packet on the network. First bytes: {:?}",
            String::from_utf8_lossy(&buf[..n.min(120)])
        ),
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {}
        Err(e) => panic!("{what}: unexpected socket error waiting for silence: {e}"),
    }
}

/// The listener really can see a datagram sent to it by the same route the
/// kill path would use. Without this control, every "nothing arrived"
/// assertion in this file could be passing for the wrong reason.
#[test]
fn harness_observes_a_transmit_when_one_happens() {
    let (sock, port) = bound_listener();
    let sender = UdpSocket::bind(("127.0.0.1", 0)).expect("bind sender");
    sender
        .send_to(b"SIP/2.0 200 OK\r\n\r\n", ("127.0.0.1", port))
        .expect("send control datagram");

    let mut buf = [0u8; 4096];
    let (n, _from) = sock.recv_from(&mut buf).expect(
        "the control datagram must arrive — otherwise this harness \
                 cannot detect a transmit at all",
    );
    assert!(n > 0, "control datagram was empty");
}

/// `--kill-scanner` while reading a FILE must detect the scanner and transmit
/// nothing.
#[test]
fn kill_scanner_on_a_capture_file_transmits_nothing() {
    let (sock, port) = bound_listener();
    let dir = tmp_dir("kill-scanner");
    let pcap = scanner_capture(&dir, port);

    let (stdout, stderr, code) = run_offline(&pcap, &["--kill-scanner"]);

    // Detection must still have happened — otherwise the silence below proves
    // nothing about the transmit guard.
    assert!(
        stdout.contains("scanner_detected"),
        "the scanner in the capture must still be DETECTED offline; \
         without that this test's silence is meaningless.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(code, Some(0), "the analysis itself must still succeed");

    assert_silent(&sock, "--kill-scanner -I file");
}

/// `-K/--kill-target` while reading a FILE must transmit nothing either. It
/// spawns the kill worker on its own, without `--kill-scanner`.
#[test]
fn kill_target_on_a_capture_file_transmits_nothing() {
    let (sock, port) = bound_listener();
    let dir = tmp_dir("kill-target");
    let pcap = scanner_capture(&dir, port);
    let target = format!("127.0.0.1:{port}");

    let (stdout, stderr, code) = run_offline(&pcap, &["-K", &target]);

    assert!(
        stdout.contains("scanner_detected"),
        "the targeted source must still be REPORTED offline.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(code, Some(0), "the analysis itself must still succeed");

    assert_silent(&sock, "-K -I file");
}

/// `--kill-spoof raw` must not turn the file path back into a transmitting
/// one, and must not fail the run either: there is nothing to spoof offline,
/// so the raw socket is never wanted and its absence is not an error.
#[test]
fn kill_spoof_raw_on_a_capture_file_transmits_nothing() {
    let (sock, port) = bound_listener();
    let dir = tmp_dir("kill-spoof-raw");
    let pcap = scanner_capture(&dir, port);

    let (stdout, stderr, code) = run_offline(&pcap, &["--kill-scanner", "--kill-spoof", "raw"]);

    assert_eq!(
        code,
        Some(0),
        "--kill-spoof raw on a FILE must not fail the analysis (there is \
         nothing to spoof).\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_silent(&sock, "--kill-scanner --kill-spoof raw -I file");
}

/// The refusal must be visible: an operator who asked for a kill and got
/// analysis instead has to be told, or they will believe the defence is armed.
///
/// Asserted against the exact phrase the refusal uses, not a loose keyword —
/// a substring like "offline" appears in unrelated log lines and would let
/// this test pass while the message said nothing about the kill path.
#[test]
fn offline_kill_request_is_reported_not_silently_dropped() {
    let (_sock, port) = bound_listener();
    let dir = tmp_dir("reported");
    let pcap = scanner_capture(&dir, port);

    let (_stdout, stderr, _code) = run_offline(&pcap, &["--kill-scanner"]);

    assert!(
        stderr.contains("offline analysis never transmits"),
        "the run must say why no kill response was sent when reading a file; \
         got stderr: {stderr}"
    );
}
