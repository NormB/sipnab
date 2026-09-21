// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--relay-stats`, `--relay-stats-list`, `--relay-stats-call`,
//! `--relay-stats-interval` and `--relay-compare`, end to end against a relay
//! that answers.
//!
//! `relay_stats_cli_test` pins the decision that precedes a fetch; this file
//! pins what the run does with the answer. The two halves were tested apart
//! because a fetch transmits, and a file-backed run -- the only kind the
//! suite could drive -- holds no transmit permit.
//!
//! # How a run here holds a permit without touching the network
//!
//! A HEP listener is a live source (`TransmitPermit::for_source` grants one to
//! `Hep`), and it binds `127.0.0.1:0`. The relay is a UDP socket this test
//! owns, also on loopback, answering the ng framing -- `<cookie> <bencode>` --
//! with committed replies captured from rtpengine 12.5.1. Every datagram the
//! run sends goes to that socket and nowhere else.
//!
//! # Why every run ends with SIGTERM
//!
//! A live run lasts until it is stopped. SIGTERM is the signal sipnab turns
//! into a clean shutdown, so the post-capture comparison runs, the exit status
//! means something, and the child writes its coverage profile -- which a
//! SIGKILLed child never does.

#![cfg(feature = "full")]

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// The Call-ID every per-call question names.
const CALL_ID: &str = "1-4242@192.0.2.10";

/// Longest any single wait in this file lasts. Generous, because the binary
/// may be instrumented and the host loaded; a passing run waits far less.
const WAIT: Duration = Duration::from_secs(30);

/// What the fake relay does with one request.
enum Answer {
    /// Reply with this bencode body, framed with the request's own cookie.
    Body(Vec<u8>),
    /// Reply with exactly these bytes, cookie and all.
    Raw(Vec<u8>),
    /// Say nothing, so the client times out.
    Silent,
}

/// A loopback UDP socket that answers rtpengine ng requests.
struct FakeRelay {
    addr: SocketAddr,
    /// Every verb asked, in arrival order.
    asked: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FakeRelay {
    /// Start answering; `answer` receives the verb and how many times that
    /// verb has been asked before.
    fn start(mut answer: impl FnMut(&str, usize) -> Answer + Send + 'static) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind the fake relay");
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("read timeout");
        let addr = sock.local_addr().expect("relay address");
        let asked = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (asked_t, stop_t) = (Arc::clone(&asked), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            let mut counts: std::collections::HashMap<String, usize> = Default::default();
            while !stop_t.load(Ordering::Relaxed) {
                let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let req = &buf[..n];
                let space = req.iter().position(|b| *b == b' ').unwrap_or(0);
                let cookie = req[..space].to_vec();
                let verb = verb_of(&req[space..]);
                asked_t.lock().expect("asked lock").push(verb.clone());
                let seen = counts.entry(verb.clone()).or_default();
                let nth = *seen;
                *seen += 1;
                let out = match answer(&verb, nth) {
                    Answer::Body(body) => {
                        let mut out = cookie;
                        out.push(b' ');
                        out.extend_from_slice(&body);
                        out
                    }
                    Answer::Raw(bytes) => bytes,
                    Answer::Silent => continue,
                };
                let _ = sock.send_to(&out, peer);
            }
        });
        Self {
            addr,
            asked,
            stop,
            thread: Some(thread),
        }
    }

    /// The verbs asked so far.
    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("asked lock").clone()
    }
}

impl Drop for FakeRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The ng verb in a request body: the value of its `command` key.
fn verb_of(body: &[u8]) -> String {
    let key = b"7:command";
    let Some(at) = body.windows(key.len()).position(|w| w == key) else {
        return String::new();
    };
    let rest = &body[at + key.len()..];
    let colon = rest.iter().position(|b| *b == b':').unwrap_or(0);
    let len: usize = std::str::from_utf8(&rest[..colon])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    String::from_utf8_lossy(&rest[colon + 1..colon + 1 + len]).into_owned()
}

/// A committed rtpengine reply, without the cookie it was captured with.
fn fixture_body(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/relay/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let space = raw
        .iter()
        .position(|b| *b == b' ')
        .expect("cookie separator");
    raw[space + 1..].to_vec()
}

/// An empty, complete `list` answer: the relay holds no calls right now.
fn no_calls() -> Answer {
    Answer::Body(b"d5:callsle6:result2:oke".to_vec())
}

/// rtpengine's refusal for a call it does not hold.
fn unknown_call() -> Answer {
    Answer::Body(b"d12:error-reason15:Unknown call-id6:result5:errore".to_vec())
}

/// A running `sipnab -N -L 127.0.0.1:0` with both output streams drained.
struct Run {
    child: Child,
    stdout: mpsc::Receiver<String>,
    stderr: mpsc::Receiver<String>,
    out: Vec<String>,
    err: Vec<String>,
    _home: tempfile::TempDir,
}

/// Drain `r` into a channel of lines on a background thread.
fn lines_of<R: std::io::Read + Send + 'static>(r: R) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(r).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

impl Run {
    /// Start a HEP-listening run pointed at `relay`, plus `extra` flags, and
    /// wait until its capture is open.
    fn start(relay: &FakeRelay, extra: &[&str]) -> Self {
        Self::start_with_control(&relay.addr.to_string(), extra)
    }

    /// As [`Run::start`], naming `control` verbatim as the relay address.
    fn start_with_control(control: &str, extra: &[&str]) -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(["-N", "-L", "127.0.0.1:0", "--rtpengine-control", control])
            .args(extra)
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path())
            .env_remove("SIPNAB_CONFIG")
            .env("SIPNAB_LOG", "info")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sipnab -L");
        let stdout = lines_of(child.stdout.take().expect("stdout"));
        let stderr = lines_of(child.stderr.take().expect("stderr"));
        let mut run = Self {
            child,
            stdout,
            stderr,
            out: Vec::new(),
            err: Vec::new(),
            _home: home,
        };
        assert!(
            run.wait_stderr("HEP listener started on"),
            "the HEP capture never opened:\n{}",
            run.err.join("\n")
        );
        run
    }

    /// Wait for a stderr line containing `needle`.
    fn wait_stderr(&mut self, needle: &str) -> bool {
        if self.err.iter().any(|l| l.contains(needle)) {
            return true;
        }
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if let Ok(line) = self.stderr.recv_timeout(Duration::from_millis(100)) {
                let hit = line.contains(needle);
                self.err.push(line);
                if hit {
                    return true;
                }
            }
        }
        false
    }

    /// Wait until `count` stdout lines contain `needle`.
    fn wait_stdout(&mut self, needle: &str, count: usize) -> bool {
        let deadline = Instant::now() + WAIT;
        loop {
            if self.out.iter().filter(|l| l.contains(needle)).count() >= count {
                return true;
            }
            if Instant::now() > deadline {
                return false;
            }
            if let Ok(line) = self.stdout.recv_timeout(Duration::from_millis(100)) {
                self.out.push(line);
            }
        }
    }

    /// SIGTERM the run and collect everything it printed.
    fn finish(mut self) -> Finished {
        let pid = libc::pid_t::try_from(self.child.id()).expect("pid fits pid_t");
        // SAFETY: signaling a child this test spawned and still owns.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let deadline = Instant::now() + WAIT;
        let code = loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                break status.code();
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        while let Ok(line) = self.stdout.recv_timeout(Duration::from_millis(300)) {
            self.out.push(line);
        }
        while let Ok(line) = self.stderr.recv_timeout(Duration::from_millis(300)) {
            self.err.push(line);
        }
        Finished {
            code,
            stdout: self.out.join("\n"),
            stderr: self.err.join("\n"),
        }
    }
}

/// A run that ends in a panic -- a failing assertion before `finish` -- still
/// reaps its child. Without this every red run left an idle listener behind.
/// A child `finish` already reaped is past `try_wait`, so this is a no-op then.
impl Drop for Run {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// What a finished run left behind.
struct Finished {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Finished {
    /// Both streams, for failure messages.
    fn dump(&self) -> String {
        format!("--- stdout\n{}\n--- stderr\n{}", self.stdout, self.stderr)
    }
}

/// The ordinary live run: the one-shot table prints before capture starts, the
/// poller prints on its interval, and the post-capture comparison says the
/// relay holds the call while sipnab captured no RTP for it.
///
/// The comparison is reported as a gap, not as `1862 vs 0`: sipnab created no
/// stream for the call, so its side is absent rather than a measured zero.
#[test]
fn a_live_run_prints_the_table_polls_it_and_reports_a_call_it_saw_no_media_for() {
    let relay = FakeRelay::start(|verb, _| match verb {
        "list" => no_calls(),
        "statistics" => Answer::Body(fixture_body("rtpengine-statistics-12.5.1.bencode")),
        "query" => Answer::Body(fixture_body("rtpengine-query-12.5.1.bencode")),
        _ => Answer::Silent,
    });
    let label = format!("rtpengine at {}", relay.addr);
    let mut run = Run::start(
        &relay,
        &[
            "--relay-stats",
            "--relay-stats-interval",
            "1",
            "--relay-compare",
            CALL_ID,
        ],
    );
    assert!(
        run.wait_stdout(&format!("Relay statistics ({label}, asked "), 1),
        "the one-shot table must print:\n{}",
        run.out.join("\n")
    );
    assert!(
        run.wait_stdout(", every 1s)", 2),
        "the poller must print on its interval, more than once:\n{}",
        run.out.join("\n")
    );
    let done = run.finish();

    assert_eq!(done.code, Some(0), "{}", done.dump());
    assert!(
        done.stderr.contains(&format!(
            "reports 1862 RTP packet(s) for call {CALL_ID}, but sipnab captured no RTP"
        )),
        "the relay's per-call total is reported as unmatched, not compared to zero:\n{}",
        done.dump()
    );
    let asked = relay.asked();
    assert_eq!(asked.first().map(String::as_str), Some("list"), "{asked:?}");
    assert_eq!(
        asked.last().map(String::as_str),
        Some("query"),
        "the comparison asks last, after the capture drained: {asked:?}"
    );
    assert!(
        asked.iter().filter(|v| *v == "statistics").count() >= 3,
        "one ask plus at least two polls: {asked:?}"
    );
}

/// `--json` turns the name list into one JSON document, and a relay that
/// does not hold the compared call is reported as refusing, in its own words.
#[test]
fn the_name_list_prints_as_json_and_an_unknown_call_is_a_refusal() {
    let relay = FakeRelay::start(|verb, _| match verb {
        "list" => no_calls(),
        "statistics" => Answer::Body(fixture_body("rtpengine-statistics-12.5.1.bencode")),
        "query" => unknown_call(),
        _ => Answer::Silent,
    });
    let mut run = Run::start(
        &relay,
        &["--json", "--relay-stats-list", "--relay-compare", CALL_ID],
    );
    assert!(
        run.wait_stdout("\"names\"", 1),
        "the name list must print as JSON:\n{}",
        run.out.join("\n")
    );
    let done = run.finish();

    assert_eq!(done.code, Some(0), "{}", done.dump());
    let line = done
        .stdout
        .lines()
        .find(|l| l.contains("\"names\""))
        .expect("the names document");
    let v: serde_json::Value = serde_json::from_str(line).expect("one JSON document per line");
    assert_eq!(v["relay"], format!("rtpengine at {}", relay.addr));
    let names = v["names"].as_array().expect("names is a list");
    assert!(
        names
            .iter()
            .any(|n| n.as_str().is_some_and(|s| s.contains("managedsessions"))),
        "the relay's own counter names are listed: {names:?}"
    );
    assert!(
        done.stderr.contains(&format!(
            "refused the per-call statistics request for call {CALL_ID}: Unknown call-id"
        )),
        "{}",
        done.dump()
    );
}

/// `--relay-stats-call` prints that call's counters, labeled with the call.
#[test]
fn a_per_call_ask_prints_that_calls_counters() {
    let relay = FakeRelay::start(|verb, _| match verb {
        "list" => no_calls(),
        "query" => Answer::Body(fixture_body("rtpengine-query-12.5.1.bencode")),
        _ => Answer::Silent,
    });
    let label = format!("rtpengine at {}, call {CALL_ID}", relay.addr);
    let mut run = Run::start(&relay, &["--relay-stats-call", CALL_ID]);
    assert!(
        run.wait_stdout(&format!("Relay statistics ({label}, asked "), 1),
        "{}",
        run.out.join("\n")
    );
    assert!(
        run.wait_stdout("totals.RTP.packets", 1),
        "the per-call counters are printed:\n{}",
        run.out.join("\n")
    );
    let done = run.finish();
    assert_eq!(done.code, Some(0), "{}", done.dump());
}

/// A per-call ask the relay refuses prints no table, only the refusal.
#[test]
fn a_refused_per_call_ask_prints_the_relays_reason_and_no_table() {
    let relay = FakeRelay::start(|verb, _| match verb {
        "list" => no_calls(),
        "query" => unknown_call(),
        _ => Answer::Silent,
    });
    let mut run = Run::start(&relay, &["--relay-stats-call", CALL_ID]);
    assert!(
        run.wait_stderr(&format!(
            "refused the statistics request for call {CALL_ID}: Unknown call-id"
        )),
        "{}",
        run.err.join("\n")
    );
    let done = run.finish();
    assert_eq!(done.code, Some(0), "{}", done.dump());
    assert!(
        !done.stdout.contains("Relay statistics"),
        "a refusal is never tiered into counter rows:\n{}",
        done.dump()
    );
}

/// A reply carrying somebody else's cookie is discarded and called suspect,
/// never read as statistics.
#[test]
fn a_reply_to_another_transaction_is_reported_suspect() {
    let relay = FakeRelay::start(|verb, _| match verb {
        "list" => no_calls(),
        "statistics" => Answer::Raw(b"sipnab-somebodyelse d6:result2:oke".to_vec()),
        _ => Answer::Silent,
    });
    let mut run = Run::start(&relay, &["--relay-stats"]);
    assert!(
        run.wait_stderr("the reply was discarded and not read (suspect)"),
        "{}",
        run.err.join("\n")
    );
    let done = run.finish();
    assert_eq!(done.code, Some(0), "{}", done.dump());
    assert!(!done.stdout.contains("Relay statistics"), "{}", done.dump());
}

/// A relay that never answers is reported as asked-and-silent -- by the
/// one-shot ask, by the poller, and by the comparison, which still states
/// what sipnab measured.
#[test]
fn a_silent_relay_is_reported_as_unanswered_by_every_form() {
    let relay = FakeRelay::start(|verb, _| match verb {
        "list" => no_calls(),
        _ => Answer::Silent,
    });
    let mut run = Run::start(
        &relay,
        &[
            "--relay-stats",
            "--relay-stats-interval",
            "1",
            "--relay-compare",
            CALL_ID,
        ],
    );
    assert!(
        run.wait_stderr("did not answer the statistics request"),
        "{}",
        run.err.join("\n")
    );
    assert!(
        run.wait_stderr("did not answer the polled statistics request"),
        "{}",
        run.err.join("\n")
    );
    let done = run.finish();
    assert_eq!(done.code, Some(0), "{}", done.dump());
    assert!(
        done.stderr.contains(&format!(
            "did not answer the per-call statistics request for call {CALL_ID}"
        )) && done.stderr.contains("sipnab measured 0 RTP packet(s)"),
        "{}",
        done.dump()
    );
}

/// A cumulative counter that goes down between two polls is flagged as a
/// probable relay restart, and each reading still prints.
#[test]
fn a_counter_that_steps_backwards_between_polls_is_flagged_suspect() {
    let relay = FakeRelay::start(|verb, nth| match verb {
        "list" => no_calls(),
        "statistics" => {
            // Five sessions, then three: impossible for a counter that only
            // accumulates, unless the relay restarted in between.
            let sessions = if nth == 0 { 5 } else { 3 };
            Answer::Body(
                format!("d6:result2:ok10:statisticsd8:sessionsi{sessions}eee").into_bytes(),
            )
        }
        _ => Answer::Silent,
    });
    let mut run = Run::start(&relay, &["--relay-stats-interval", "1"]);
    assert!(
        run.wait_stderr("stepped backwards 5 -> 3 between polls"),
        "{}",
        run.err.join("\n")
    );
    let done = run.finish();
    assert_eq!(done.code, Some(0), "{}", done.dump());
    assert!(
        done.stdout.matches(", every 1s)").count() >= 2,
        "both readings print; the suspect one is not dropped:\n{}",
        done.dump()
    );
}

/// A relay address that is not an address and port asks nothing -- and the
/// one-shot ask, the poller and the comparison each say so, rather than
/// reading as a relay that holds no calls.
///
/// The poller used to take its permit from the reconciler, which exists only
/// when the address parsed, so this LIVE run was told its poll was refused
/// because it "reads a file" and to capture live instead -- a fix it had
/// already made. The refusal has to name the address, like its siblings do.
#[test]
fn an_unparseable_relay_address_asks_nothing_and_every_form_says_so() {
    let mut run = Run::start_with_control(
        "relay-without-a-port",
        &[
            "--relay-stats",
            "--relay-stats-interval",
            "1",
            "--relay-compare",
            CALL_ID,
        ],
    );
    assert!(
        run.wait_stderr("nothing is polled"),
        "{}",
        run.err.join("\n")
    );
    let done = run.finish();
    assert_eq!(done.code, Some(0), "{}", done.dump());
    for form in ["nothing was asked", "nothing is polled"] {
        assert!(done.stderr.contains(form), "{form}: {}", done.dump());
    }
    assert_eq!(
        done.stderr
            .matches("relay-without-a-port is not an address and port")
            .count(),
        4,
        "startup snapshot, one-shot ask, poller and comparison each refuse:\n{}",
        done.dump()
    );
    assert!(
        !done.stdout.contains("Relay statistics"),
        "nothing was asked, so nothing may print as an answer:\n{}",
        done.dump()
    );
    assert!(
        !done.stderr.contains("on a run that reads a file"),
        "this run is live; blaming a file sends the operator nowhere:\n{}",
        done.dump()
    );
}
