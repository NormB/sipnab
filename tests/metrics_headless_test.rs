// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--metrics` must bind in HEADLESS mode, which is how servers run it.
//!
//! The defect this guards: `start_metrics_server` had exactly one call site, in
//! `src/app/tui_mode.rs`, so `sipnab -N --metrics 127.0.0.1:PORT` bound nothing.
//! Every container, systemd unit and remote deployment runs `-N`.
//!
//! It survived review because everything around it looked wired. The address
//! parsed. A non-loopback bind without `--metrics-auth` was refused, so the flag
//! visibly validated its input. And a comment in `bootstrap.rs` stated that
//! "batch starts its own metrics server" — which was false, and is exactly the
//! kind of reassuring note that stops a reader checking.
//!
//! So this asserts the EFFECT, on the real binary: the endpoint answers and the
//! body carries the metric families. A test that only checked the flag parsed,
//! or that a listener existed, would have passed against the broken build —
//! `--metrics 127.0.0.1:0` binds a port the OS picks and the process would
//! still have served nothing.

#![cfg(all(feature = "metrics", feature = "native"))]

use std::io::{BufRead, BufReader};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Ask the OS for a free port, then release it.
///
/// `--metrics 127.0.0.1:0` would let sipnab pick, but the port it chose is only
/// in its log, and racing a log parse is how this test would go flaky.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let p = l.local_addr().expect("read it back").port();
    drop(l);
    p
}

fn sipnab_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("test binary path");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("sipnab")
}

/// The whole point: headless, and the endpoint actually answers.
///
/// Driven with `--hep-listen` rather than `-I <file>`, and the reason is
/// measured: a headless FILE run lives about 20 ms — it reads the pcap, prints
/// and exits — so any poll loop races a process that has already gone. That is
/// also why metrics on a file run are close to useless in practice. A HEP
/// listener is the honest headless shape: long-lived, unprivileged, and exactly
/// how a collector deployment runs.
#[test]
fn metrics_binds_and_answers_in_headless_mode() {
    let hep = free_port();
    let metrics = free_port();
    let addr = format!("127.0.0.1:{metrics}");

    let mut child = Command::new(sipnab_bin())
        .args([
            "-N",
            "--hep-listen",
            &format!("127.0.0.1:{hep}"),
            "--metrics",
            &addr,
            "--quiet",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sipnab");

    let mut body = String::new();
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Ok(mut s) = std::net::TcpStream::connect(&addr) {
            use std::io::Write;
            let _ = write!(
                s,
                "GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
            );
            let mut r = BufReader::new(s);
            let mut line = String::new();
            while r.read_line(&mut line).unwrap_or(0) > 0 {
                body.push_str(&line);
                line.clear();
            }
            if !body.is_empty() {
                break;
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !body.is_empty(),
        "nothing answered on {addr} in headless mode — this is the defect: \
         --metrics parses, validates and binds nothing under -N"
    );
    assert!(
        body.contains("200 OK"),
        "the endpoint answered but not with 200: {}",
        body.lines().next().unwrap_or("<empty>")
    );
    // A real metric family, not merely a 200: a handler returning an empty body
    // would satisfy the check above while exposing nothing.
    assert!(
        body.contains("sipnab_"),
        "the response carries no sipnab metric family, so the endpoint answers \
         without exposing anything: {body}"
    );
    // The capture-queue gauge specifically, because it is the one that depends
    // on a meter being threaded through rather than on the stores alone.
    //
    // Only its PRESENCE is asserted, and the limit is worth naming: an idle
    // listener has nothing in flight, so the gauge reads 0 whether the meter is
    // wired or missing, and no scrape can tell those apart at rest. What rules
    // out the missing case is the type — `BatchRunner::new` takes a
    // `CaptureMeter`, not an `Option`, so the headless path cannot compile
    // while passing nothing. This checks the family did not vanish.
    assert!(
        body.contains("sipnab_capture_queue_depth_packets"),
        "the capture-queue gauge is missing from the scrape: {body}"
    );
}

/// The safety refusal still applies headless — it is not TUI-only either.
///
/// A non-loopback bind with no auth publishes dialog and security counters to
/// anyone who can reach it. That refusal lived in the same function that was
/// never called from this path, so it needs the same proof.
///
/// Driven from a FILE, unlike the test above, and for the opposite reason. The
/// refusal is non-fatal — sipnab declines the bind and carries on capturing —
/// so against a long-lived `--hep-listen` run `.output()` waits for a stdout
/// that never closes and the test hangs rather than fails. A file run exits on
/// its own, which is what makes the refusal observable in a collected stderr.
#[test]
fn a_non_loopback_bind_without_auth_is_still_refused_headless() {
    let out = Command::new(sipnab_bin())
        .args([
            "-N",
            "-I",
            "tests/pcap-samples/sip-rtp-g711.pcap",
            "--metrics",
            "0.0.0.0:19998",
        ])
        .output()
        .expect("run sipnab");

    let err = String::from_utf8_lossy(&out.stderr);

    // The EFFECT, and the reason this assertion is phrased as an absence: the
    // obvious version — stderr mentions "metrics" and "auth" or "loopback" —
    // passes against a build with the refusal deleted, because the very next
    // branch warns "metrics server bound non-loopback (...) with Basic auth
    // only". Two log lines, both matching, opposite meanings. Only "did the
    // listener come up" tells them apart, so that is what is asserted.
    assert!(
        !err.contains("listening on 0.0.0.0:19998"),
        "the metrics server BOUND a routable address with no credentials — the \
         refusal did not fire, and dialog and security counters are now public: {err}"
    );
    // And it must say so, rather than declining in silence: an operator who
    // asked for a metrics endpoint and got none needs to know why.
    assert!(
        err.contains("refuses to start"),
        "the bind was refused without naming the refusal, so the operator sees \
         only a missing endpoint: {err}"
    );
}

/// Scrape `/metrics` from a headless run started with `extra`.
///
/// # Side effects
/// Spawns the compiled `sipnab` binary against a HEP listener and kills it.
fn scrape_with(extra: &[&str]) -> String {
    let hep = free_port();
    let metrics = free_port();
    let addr = format!("127.0.0.1:{metrics}");

    let mut args = vec![
        "-N".to_string(),
        "--hep-listen".to_string(),
        format!("127.0.0.1:{hep}"),
        "--metrics".to_string(),
        addr.clone(),
        "--quiet".to_string(),
        "--no-config".to_string(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_string()));

    // stderr is KEPT, not discarded. This loop used to give up after six
    // seconds and assert "nothing answered on <addr>", which is the same
    // message whether sipnab was slow to bind, exited immediately on a bad
    // argument, or lost the race for an ephemeral port that `free_port` had
    // already released. On 2026-09-10 it failed exactly that way on a macOS
    // runner and the log said nothing more than the port number.
    let mut child = Command::new(sipnab_bin())
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sipnab");

    // Thirty seconds, not six. A cold CI runner spawning a freshly linked
    // binary is slower than a warm laptop by more than the old budget
    // allowed, and the loop exits the moment the endpoint answers, so a
    // generous ceiling costs nothing when things work.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut body = String::new();
    let mut died: Option<ExitStatus> = None;
    while Instant::now() < deadline {
        // Ask whether the process is still alive BEFORE waiting again. A dead
        // child cannot start answering later, and burning the rest of the
        // budget on one turns a precise failure into a timeout.
        if let Ok(Some(status)) = child.try_wait() {
            died = Some(status);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(mut s) = std::net::TcpStream::connect(&addr) {
            use std::io::Write;
            let _ = write!(
                s,
                "GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
            );
            let mut r = BufReader::new(s);
            let mut line = String::new();
            while r.read_line(&mut line).unwrap_or(0) > 0 {
                body.push_str(&line);
                line.clear();
            }
            if !body.is_empty() {
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let stderr = child
        .stderr
        .take()
        .map(|mut e| {
            use std::io::Read;
            let mut buf = String::new();
            let _ = e.read_to_string(&mut buf);
            buf
        })
        .unwrap_or_default();
    assert!(!body.is_empty(), "{}", scrape_failure(&addr, died, &stderr));
    body
}

/// Why a scrape came back empty, in words rather than a port number.
///
/// Pure, so the diagnosis itself has a test: the branch that matters is the
/// one nobody sees until CI is already red, and a message that cannot
/// distinguish "slow" from "dead" is the reason a flake stays a mystery.
fn scrape_failure(addr: &str, died: Option<ExitStatus>, stderr: &str) -> String {
    let cause = match died {
        Some(status) => format!(
            "sipnab EXITED before the endpoint answered ({status}), so this is \
             not slowness"
        ),
        None => "sipnab was still running and never answered, so it is slow to \
                 bind or bound somewhere else"
            .to_string(),
    };
    let tail: String = stderr.lines().rev().take(5).collect::<Vec<_>>().join("\n");
    format!(
        "nothing answered on {addr}: {cause}.\nIts stderr:\n{}",
        if tail.is_empty() {
            "<empty>".to_string()
        } else {
            tail
        }
    )
}

/// A dead child and a slow one must not read the same.
///
/// The failure this replaced said only "nothing answered on 127.0.0.1:49772",
/// which is true of a process that crashed at startup and of one that was
/// merely slower than the budget. Those need opposite responses, and the log
/// is the only place anyone can tell them apart.
#[test]
fn a_failed_scrape_says_whether_the_process_died() {
    let alive = scrape_failure("127.0.0.1:9", None, "");
    assert!(
        alive.contains("still running"),
        "a slow start must not read as a crash: {alive}"
    );

    let bin = sipnab_bin();
    let status = Command::new(bin)
        .arg("--this-flag-does-not-exist")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("a real exit status");
    let dead = scrape_failure("127.0.0.1:9", Some(status), "error: unexpected argument");
    assert!(
        dead.contains("EXITED"),
        "a crashed process must not read as slowness: {dead}"
    );
    assert!(
        dead.contains("unexpected argument"),
        "the child's own words are the evidence; without them the log says \
         only that something did not answer: {dead}"
    );
}

/// The published histogram buckets are DERIVED from the thresholds this run
/// diagnoses and colors with, so every boundary sipnab reports on is a
/// boundary Grafana can express.
///
/// The shipped sets could not express sipnab's own numbers. The PDD buckets
/// stopped at 10 s while `[diagnosis] post_dial_delay_secs` defaults to 11, so
/// no query over this endpoint could reproduce the SLA sipnab was itself
/// applying, and on an international trunk every observation landed in `+Inf`
/// carrying no information at all. The jitter buckets carried the 50 ms bad
/// boundary and not the 30 ms warn boundary beneath it.
#[test]
fn the_published_buckets_are_derived_from_this_runs_thresholds() {
    let shipped = scrape_with(&[]);
    assert!(
        shipped.contains(r#"sipnab_pdd_seconds_bucket{le="11"}"#),
        "the shipped post-dial-delay threshold of 11 s must be a bucket \
         boundary, or no query here can reproduce sipnab's own finding:\n{shipped}"
    );
    assert!(
        shipped.contains(r#"sipnab_jitter_ms_bucket{le="30"}"#),
        "the shipped 30 ms jitter warn boundary must be a bucket boundary:\n{shipped}"
    );

    let tuned = scrape_with(&[
        "--pdd-threshold",
        "4",
        "--jitter-warn-ms",
        "12",
        "--loss-bad-pct",
        "3",
        "--mos-warn",
        "4.2",
    ]);
    assert!(
        tuned.contains(r#"sipnab_pdd_seconds_bucket{le="4"}"#),
        "--pdd-threshold 4 must move the boundary the endpoint \
         publishes:\n{tuned}"
    );
    assert!(
        tuned.contains(r#"sipnab_jitter_ms_bucket{le="12"}"#),
        "--jitter-warn-ms 12 must move the jitter boundary:\n{tuned}"
    );
    assert!(
        tuned.contains(r#"sipnab_loss_percent_bucket{le="3"}"#),
        "--loss-bad-pct 3 must move the loss boundary:\n{tuned}"
    );
    assert!(
        tuned.contains(r#"sipnab_mos_bucket{le="4.2"}"#),
        "--mos-warn 4.2 must move the MOS boundary:\n{tuned}"
    );
}
