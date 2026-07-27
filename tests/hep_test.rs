// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end HEP tests (verification plan M3 — T3.6).
//!
//! Drives the real `sipnab` HEP surfaces over UDP:
//!   * `--hep-listen` ingests synthetic HEP3 datagrams → SIP message surfaces
//!   * `--hep-allow` CIDR allowlist accepts loopback / rejects an excluded range
//!   * `--hep-rate-limit` drops a burst above the threshold
//!   * `--hep-send` forwards captured SIP as HEP3 to a collector socket
//!
//! HEP3 datagrams are built with the production encoder
//! (`sipnab::capture::hep::build_hep_v3`) so the test exercises the real wire
//! format the listener parses.
#![cfg(all(unix, feature = "hep"))]

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};

#[path = "support/mod.rs"]
mod support;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use sipnab::capture::hep::{HepEndpoint, HepProtocol, build_hep_v3};

/// Call-ID embedded in the synthetic INVITE; tests grep stdout for it.
const CALL_ID: &str = "hep-test-call-1@127.0.0.1";

/// A minimal but parseable SIP INVITE used as the HEP payload.
fn invite_bytes() -> Vec<u8> {
    let msg = format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKhep\r\n\
         From: <sip:alice@example.com>;tag=1\r\n\
         To: <sip:bob@example.com>\r\n\
         Call-ID: {CALL_ID}\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    );
    msg.into_bytes()
}

/// A HEP3 datagram wrapping `payload` as a loopback SIP/UDP message, built
/// with the production `build_hep_v3` encoder.
///
/// # Arguments
/// * `payload` — the SIP message bytes to encapsulate.
///
/// # Returns
/// The encoded HEP3 datagram.
fn hep3_sip(payload: &[u8]) -> Vec<u8> {
    let ep = HepEndpoint {
        src_addr: "127.0.0.1".parse().unwrap(),
        dst_addr: "127.0.0.1".parse().unwrap(),
        src_port: 5060,
        dst_port: 5062,
    };
    build_hep_v3(&ep, Utc::now(), HepProtocol::Sip, 0, None, payload)
}

/// A spawned `sipnab --hep-listen` process with line-buffered stdout/stderr.
struct HepListener {
    child: Child,
    port: u16,
    stdout_rx: mpsc::Receiver<String>,
    stderr_rx: mpsc::Receiver<String>,
}

impl HepListener {
    /// Spawn `sipnab -N --hep-listen 127.0.0.1:0 --json` plus `extra_args`,
    /// scraping the actual bound UDP port from the startup log.
    ///
    /// # Side effects
    /// Spawns the sipnab binary (killed on drop), which binds an ephemeral
    /// loopback UDP port; panics if no port is reported within 10s.
    fn spawn(extra_args: &[&str]) -> HepListener {
        Self::spawn_with_log("info", extra_args)
    }

    /// As [`spawn`], with an explicit `SIPNAB_LOG` level (the per-packet
    /// rate-limit drop is logged at `debug`, so that test needs `debug`).
    fn spawn_with_log(log: &str, extra_args: &[&str]) -> HepListener {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
        // This listener is torn down with Child::kill() (SIGKILL), which leaves
        // a truncated .profraw under coverage.
        support::discard_coverage_profile(&mut cmd);
        cmd.args(["-N", "--hep-listen", "127.0.0.1:0", "--json", "--quiet"]);
        cmd.args(extra_args);
        cmd.env("SIPNAB_LOG", log);
        cmd.env("NO_COLOR", "1");
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("spawn sipnab --hep-listen");
        let stdout_rx = line_reader(child.stdout.take().expect("stdout"));
        let (stderr_tx, stderr_rx) = mpsc::channel();
        let stderr = child.stderr.take().expect("stderr");
        let mut port = None;
        // Scrape the bound port from stderr; forward the rest to stderr_rx.
        let (port_tx, port_rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Some(rest) = line.split("HEP listener started on ").nth(1)
                    && let Some(p) = rest.trim().rsplit(':').next()
                    && let Ok(p) = p.parse::<u16>()
                {
                    let _ = port_tx.send(p);
                }
                let _ = stderr_tx.send(line);
            }
        });

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(p) = port_rx.recv_timeout(Duration::from_millis(200)) {
                port = Some(p);
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!("sipnab --hep-listen exited early: {status}");
            }
        }
        let port = port.unwrap_or_else(|| {
            let _ = child.kill();
            panic!("HEP listener did not report a bound port within 10s");
        });

        HepListener {
            child,
            port,
            stdout_rx,
            stderr_rx,
        }
    }

    /// Send a datagram to the listener from a fresh loopback UDP socket.
    ///
    /// # Side effects
    /// Binds an ephemeral UDP socket for the send.
    fn send(&self, datagram: &[u8]) {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        sock.send_to(datagram, ("127.0.0.1", self.port))
            .expect("send HEP");
    }

    /// Wait up to `wait` for a stdout JSON line containing `needle`.
    ///
    /// # Returns
    /// The matching line, or `None` on timeout.
    fn wait_for_stdout(&self, needle: &str, wait: Duration) -> Option<String> {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if let Ok(line) = self.stdout_rx.recv_timeout(Duration::from_millis(100))
                && line.contains(needle)
            {
                return Some(line);
            }
        }
        None
    }

    /// Wait up to `wait` for a stderr line containing `needle`.
    ///
    /// # Returns
    /// True if a matching line arrived before the deadline.
    fn wait_for_stderr(&self, needle: &str, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if let Ok(line) = self.stderr_rx.recv_timeout(Duration::from_millis(100))
                && line.contains(needle)
            {
                return true;
            }
        }
        false
    }
}

impl Drop for HepListener {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Drain a child stream into a channel of lines on a background thread.
///
/// # Arguments
/// * `r` — readable stream (child stdout/stderr) to drain.
///
/// # Returns
/// Receiver yielding each line as it arrives.
///
/// # Side effects
/// Spawns a detached reader thread that runs until the stream closes.
fn line_reader<R: std::io::Read + Send + 'static>(r: R) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(r).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// A synthetic HEP3-wrapped INVITE sent to `--hep-listen` surfaces on `--json`
/// stdout with the right method and Call-ID.
#[test]
fn hep_listener_ingests_synthetic_hep3() {
    let srv = HepListener::spawn(&["--hep-allow", "127.0.0.1/32"]);
    srv.send(&hep3_sip(&invite_bytes()));

    let line = srv
        .wait_for_stdout(CALL_ID, Duration::from_secs(5))
        .expect("HEP-ingested INVITE must surface on --json stdout");
    let msg: serde_json::Value = serde_json::from_str(&line).expect("ndjson");
    assert_eq!(msg["method"], "INVITE");
    assert_eq!(msg["call_id"], CALL_ID);
}

/// With `--hep-allow 10.0.0.0/8`, a loopback-sourced datagram is rejected by
/// the allowlist before it can surface on stdout — proven by the positive
/// per-packet drop log, not by waiting out a window of stdout silence.
#[test]
fn hep_allowlist_rejects_source_outside_cidr() {
    // Loopback packets come from 127.0.0.1, which is NOT in 10.0.0.0/8, so the
    // allowlist must drop them. Run at debug so the per-packet allowlist drop is
    // logged, and synchronize on that event instead of proving a negative by
    // waiting for a fixed period of stdout silence.
    let srv = HepListener::spawn_with_log("debug", &["--hep-allow", "10.0.0.0/8"]);
    srv.send(&hep3_sip(&invite_bytes()));

    // Positive proof of the drop: the listener logs the allowlist rejection for
    // this exact packet. That check runs before any pipeline output, so once we
    // observe it the INVITE has been discarded and can never reach stdout.
    assert!(
        srv.wait_for_stderr(
            "Dropping HEP packet from non-allowed source",
            Duration::from_secs(5),
        ),
        "a packet from a non-allowlisted source must be dropped by the allowlist"
    );

    // Having synchronized on the drop, confirm the Call-ID never surfaced. This
    // is now a bounded check taken *after* the packet is fully handled, not a
    // race against a timing window.
    assert!(
        srv.wait_for_stdout(CALL_ID, Duration::from_millis(200))
            .is_none(),
        "a dropped packet must never surface on --json stdout"
    );
}

/// A 20-datagram burst against `--hep-rate-limit 1` logs a
/// "rate limit exceeded" drop (visible at debug log level).
#[test]
fn hep_rate_limit_drops_burst() {
    // rate-limit 1/s, then fire a burst well above it within the same second.
    // The drop is logged at debug level, so run the listener at debug.
    let srv = HepListener::spawn_with_log(
        "debug",
        &["--hep-allow", "127.0.0.1/32", "--hep-rate-limit", "1"],
    );
    for _ in 0..20 {
        srv.send(&hep3_sip(&invite_bytes()));
    }
    assert!(
        srv.wait_for_stderr("rate limit exceeded", Duration::from_secs(5)),
        "a burst above --hep-rate-limit must log a drop"
    );
}

/// `--hep-send` forwards fixture SIP to a collector UDP socket, and the first
/// received datagram starts with the `HEP3` magic.
#[test]
fn hep_send_forwards_captured_sip_as_hep3() {
    // Bind a collector UDP socket; have sipnab forward a fixture's SIP to it.
    let collector = UdpSocket::bind("127.0.0.1:0").expect("bind collector");
    collector
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let target = format!("127.0.0.1:{}", collector.local_addr().unwrap().port());

    let pcap = format!(
        "{}/tests/fixtures/sip_call.pcap",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut sender = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    support::discard_coverage_profile(&mut sender);
    let mut child = sender
        .args(["-N", "-I", &pcap, "--hep-send", &target, "--quiet"])
        .env("SIPNAB_LOG", "warn")
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sipnab --hep-send");

    let mut buf = [0u8; 65535];
    let (n, _from) = collector
        .recv_from(&mut buf)
        .expect("collector must receive a forwarded HEP datagram");
    assert!(n >= 6, "datagram too short to be HEP3");
    assert_eq!(&buf[..4], b"HEP3", "forwarded datagram must be HEP3");

    let _ = child.kill();
    let _ = child.wait();
}
