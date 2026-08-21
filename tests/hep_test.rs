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

include!("support/timeout.rs");

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
        transport: sipnab::net::TransportProto::Udp,
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

        let deadline = Instant::now() + test_timeout(10);
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
        .wait_for_stdout(CALL_ID, test_timeout(5))
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
            test_timeout(5),
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

/// A HEP3 datagram whose HMAC token is stamped `skew` seconds in the past.
///
/// Built with the production token encoder, so the only thing wrong with it is
/// the clock — which is the condition the acceptance window is about.
fn hep3_sip_hmac_skewed(key: &str, payload: &[u8], skew: u64, nonce_byte: u8) -> Vec<u8> {
    use sipnab::capture::hep::{build_hep_v3_bytes, build_hmac_auth_token};
    let ep = HepEndpoint {
        src_addr: "127.0.0.1".parse().unwrap(),
        dst_addr: "127.0.0.1".parse().unwrap(),
        src_port: 5060,
        dst_port: 5062,
        transport: sipnab::net::TransportProto::Udp,
    };
    let ts = (Utc::now().timestamp().max(0) as u64).saturating_sub(skew);
    let nonce = [nonce_byte; 16];
    let token = build_hmac_auth_token(key.as_bytes(), ts, &nonce, payload);
    build_hep_v3_bytes(&ep, Utc::now(), HepProtocol::Sip, 0, Some(&token), payload)
}

/// `--hep-hmac-window` decides whether a clock-skewed agent is heard at all.
///
/// The failure this settles is the hardest one on a collector to attribute: a
/// sender whose clock is out by more than the window has EVERY packet dropped,
/// and the symptom is a collector that receives nothing — which an operator
/// reads as routing, or a firewall, or the agent being down. The observation
/// here is the packet itself surfacing on stdout, not a log line, because
/// "was this agent heard" is the question the window answers.
///
/// Ninety seconds of skew: outside the shipped thirty, inside a widened one.
#[test]
fn hep_hmac_window_decides_whether_a_skewed_sender_is_heard() {
    const KEY: &str = "hmac-window-probe-key";
    let payload = invite_bytes();

    let shipped = HepListener::spawn(&[
        "--hep-allow",
        "127.0.0.1/32",
        "--hep-auth",
        KEY,
        "--hep-auth-mode",
        "hmac",
    ]);
    shipped.send(&hep3_sip_hmac_skewed(KEY, &payload, 90, 0xA1));
    assert!(
        shipped
            .wait_for_stdout(CALL_ID, Duration::from_millis(750))
            .is_none(),
        "ninety seconds of skew is outside the shipped thirty-second window, so \
         the packet must be dropped — otherwise this test cannot tell the \
         window apart from no window at all"
    );
    drop(shipped);

    let widened = HepListener::spawn(&[
        "--hep-allow",
        "127.0.0.1/32",
        "--hep-auth",
        KEY,
        "--hep-auth-mode",
        "hmac",
        "--hep-hmac-window",
        "120",
    ]);
    widened.send(&hep3_sip_hmac_skewed(KEY, &payload, 90, 0xB2));
    let line = widened
        .wait_for_stdout(CALL_ID, test_timeout(5))
        .expect("--hep-hmac-window 120 must let the same ninety-second skew through");
    let msg: serde_json::Value = serde_json::from_str(&line).expect("ndjson");
    assert_eq!(msg["call_id"], CALL_ID);
}

/// The refusal warning quotes the window this run is enforcing.
///
/// The message names the number so an operator can tell "the sender is 40 s out
/// of a 30 s window" from "the sender is 4000 s out"; a warning that quoted a
/// constant while the run enforced something else would send them to check the
/// wrong clock.
#[test]
fn the_skew_warning_quotes_the_configured_window() {
    const KEY: &str = "hmac-window-message-key";
    let srv = HepListener::spawn_with_log(
        "debug",
        &[
            "--hep-allow",
            "127.0.0.1/32",
            "--hep-auth",
            KEY,
            "--hep-auth-mode",
            "hmac",
            "--hep-hmac-window",
            "45",
        ],
    );
    srv.send(&hep3_sip_hmac_skewed(KEY, &invite_bytes(), 600, 0xC3));
    assert!(
        srv.wait_for_stderr("outside the 45s", test_timeout(5)),
        "the skew warning must quote the window this run enforces, not a constant"
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
        srv.wait_for_stderr("rate limit exceeded", test_timeout(5)),
        "a burst above --hep-rate-limit must log a drop"
    );
}

/// `--hep-send` forwards fixture SIP to a collector UDP socket, and the first
/// received datagram starts with the `HEP3` magic.
#[test]
fn hep_send_forwards_captured_sip_as_hep3() {
    // Bind a collector UDP socket; have sipnab forward a fixture's SIP to it.
    let collector = UdpSocket::bind("127.0.0.1:0").expect("bind collector");
    collector.set_read_timeout(Some(test_timeout(5))).unwrap();
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

// ── -d and -L in one process (SRC1) ────────────────────────────────────

/// Whether this process can open a live capture device.
///
/// Read from `/proc/self/status` so the assertion below is specific to the
/// environment rather than accepting either outcome. `None` when it cannot be
/// determined (non-Linux / no `/proc`).
fn can_live_capture() -> Option<bool> {
    // CAP_NET_RAW is capability bit 13 in the Linux capability bitmask.
    const CAP_NET_RAW: u64 = 1 << 13;
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let euid: u32 = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())?;
    if euid == 0 {
        return Some(true);
    }
    let cap_eff: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())?;
    Some(cap_eff & CAP_NET_RAW != 0)
}

/// **`-d` with `-L` runs both, and the process says so.**
///
/// This is SRC1 end to end at the process level: the two flags used to parse
/// happily together and `-d` simply won, so `sipnab -d lo -L 127.0.0.1:9060`
/// bound no HEP socket and printed nothing about it — an operator's belief that
/// a listener was up went uncontradicted for the life of the run. Raised by Dan
/// Jenkins ([@danjenkins](https://github.com/danjenkins)) from OpenSIPS
/// deployment experience.
///
/// The startup line is asserted unconditionally because it is emitted by
/// `plan()`, before any device is opened, so it holds with or without capture
/// privileges. What follows the line is split on the probed capability rather
/// than accepting either outcome: with privileges both members open and the
/// mirrored INVITE surfaces on stdout; without them the interface member fails
/// and takes the whole session down, which is the one-fails-all rule a
/// composite inherits from `--multi-device`.
#[test]
fn a_live_device_and_a_hep_listener_run_in_one_process() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    support::discard_coverage_profile(&mut cmd);
    cmd.args([
        "-N",
        "-d",
        "lo",
        "--hep-listen",
        "127.0.0.1:0",
        "--json",
        "--quiet",
        "--duration",
        "3s",
        // Media ports only: the mirror already carries the signaling, and
        // without this the interface member would capture the same messages a
        // second time (see the composite filter warning).
        "udp portrange 10000-20000",
    ]);
    cmd.env("SIPNAB_LOG", "info");
    cmd.env("NO_COLOR", "1");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn sipnab -d lo -L");
    let stdout_rx = line_reader(child.stdout.take().expect("stdout"));
    let stderr_rx = line_reader(child.stderr.take().expect("stderr"));

    // Collect stderr until the process ends or the deadline passes, scraping
    // the composite announcement and the bound HEP port out of it.
    let deadline = Instant::now() + test_timeout(20);
    let mut stderr_lines: Vec<String> = Vec::new();
    let mut hep_port: Option<u16> = None;
    let mut announced = false;
    while Instant::now() < deadline {
        match stderr_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                if line.contains("Capturing from two sources in one process") {
                    announced = true;
                }
                if let Some(rest) = line.split("HEP listener started on ").nth(1)
                    && let Some(p) = rest.trim().rsplit(':').next()
                    && let Ok(p) = p.parse::<u16>()
                {
                    hep_port = Some(p);
                }
                stderr_lines.push(line);
            }
            Err(_) => {
                if announced && (hep_port.is_some() || child.try_wait().ok().flatten().is_some()) {
                    break;
                }
            }
        }
    }
    let log = stderr_lines.join("\n");

    assert!(
        announced,
        "a two-source run must announce itself: an operator reading a log has \
         no other way to tell which run they are looking at.\n{log}"
    );
    assert!(
        log.contains("device 'lo'") && log.contains("HEP listener 127.0.0.1:"),
        "the announcement must name BOTH members:\n{log}"
    );

    match can_live_capture() {
        // Privileged: both members opened, and the HEP member accepts.
        Some(true) => {
            let port = hep_port.unwrap_or_else(|| {
                let _ = child.kill();
                panic!("the HEP member must bind and report its port:\n{log}");
            });
            let sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
            sock.send_to(&hep3_sip(&invite_bytes()), ("127.0.0.1", port))
                .expect("send HEP");

            let found = {
                let deadline = Instant::now() + test_timeout(10);
                let mut hit = false;
                while Instant::now() < deadline {
                    if let Ok(line) = stdout_rx.recv_timeout(Duration::from_millis(100))
                        && line.contains(CALL_ID)
                    {
                        hit = true;
                        break;
                    }
                }
                hit
            };
            assert!(
                found,
                "the HEP member must deliver signaling while the interface \
                 member holds the capture open — that pair is the whole \
                 feature:\n{log}"
            );
        }
        // Unprivileged: the interface member cannot open, and one member
        // failing dooms the session rather than leaving a half-capture that
        // silently covers only the HEP side.
        Some(false) => {
            let status = {
                let deadline = Instant::now() + test_timeout(20);
                let mut seen = None;
                while Instant::now() < deadline {
                    if let Ok(Some(s)) = child.try_wait() {
                        seen = Some(s);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                seen
            };
            let status = status.unwrap_or_else(|| {
                let _ = child.kill();
                panic!("without capture rights the run must end, not hang:\n{log}");
            });
            assert_eq!(
                status.code(),
                Some(1),
                "a member that cannot open is an environment failure (exit 1), \
                 and it must take the whole composite down:\n{log}"
            );
        }
        None => eprintln!(
            "skipping the privileged half: cannot determine capture capability \
             (no /proc/self/status)"
        ),
    }

    let _ = child.kill();
    let _ = child.wait();
}
