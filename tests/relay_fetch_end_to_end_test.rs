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

include!("support/timeout.rs");
include!("support/teardown.rs");

type TestError = Box<dyn std::error::Error>;

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
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}

impl FakeRelay {
    /// Start answering; `answer` receives the verb and how many times that
    /// verb has been asked before.
    fn start(
        mut answer: impl FnMut(&str, usize) -> Answer + Send + 'static,
    ) -> Result<Self, TestError> {
        let sock = UdpSocket::bind("127.0.0.1:0")?;
        sock.set_read_timeout(Some(Duration::from_millis(100)))?;
        let addr = sock.local_addr()?;
        let asked = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (asked_t, stop_t) = (Arc::clone(&asked), Arc::clone(&stop));
        let thread = std::thread::spawn(move || -> Result<(), String> {
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
                asked_t
                    .lock()
                    .map_err(|e| e.to_string())?
                    .push(verb.clone());
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
            Ok(())
        });
        Ok(Self {
            addr,
            asked,
            stop,
            thread: Some(thread),
        })
    }

    /// The verbs asked so far.
    fn asked(&self) -> Result<Vec<String>, TestError> {
        Ok(self.asked.lock().map_err(|e| e.to_string())?.clone())
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
fn fixture_body(name: &str) -> Result<Vec<u8>, TestError> {
    let path = format!("{}/tests/fixtures/relay/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?;
    let space = raw
        .iter()
        .position(|b| *b == b' ')
        .ok_or("cookie separator")?;
    Ok(raw[space + 1..].to_vec())
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
    fn start(relay: &FakeRelay, extra: &[&str]) -> Result<Self, TestError> {
        Self::start_with_control(&relay.addr.to_string(), extra)
    }

    /// As [`Run::start`], naming `control` verbatim as the relay address.
    fn start_with_control(control: &str, extra: &[&str]) -> Result<Self, TestError> {
        let home = tempfile::tempdir()?;
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
            .spawn()?;
        let stdout = lines_of(child.stdout.take().ok_or("stdout")?);
        let stderr = lines_of(child.stderr.take().ok_or("stderr")?);
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
        Ok(run)
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
        let code = terminate_within(&mut self.child, WAIT)
            .ok()
            .and_then(|status| status.code());
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
        let _ = terminate(&mut self.child);
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
fn a_live_run_prints_the_table_polls_it_and_reports_a_call_it_saw_no_media_for()
-> Result<(), TestError> {
    let statistics = fixture_body("rtpengine-statistics-12.5.1.bencode")?;
    let query = fixture_body("rtpengine-query-12.5.1.bencode")?;
    let relay = FakeRelay::start(move |verb, _| match verb {
        "list" => no_calls(),
        "statistics" => Answer::Body(statistics.clone()),
        "query" => Answer::Body(query.clone()),
        _ => Answer::Silent,
    })?;
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
    )?;
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
    let asked = relay.asked()?;
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
    Ok(())
}

/// `--json` turns the name list into one JSON document, and a relay that
/// does not hold the compared call is reported as refusing, in its own words.
#[test]
fn the_name_list_prints_as_json_and_an_unknown_call_is_a_refusal() -> Result<(), TestError> {
    let statistics = fixture_body("rtpengine-statistics-12.5.1.bencode")?;
    let relay = FakeRelay::start(move |verb, _| match verb {
        "list" => no_calls(),
        "statistics" => Answer::Body(statistics.clone()),
        "query" => unknown_call(),
        _ => Answer::Silent,
    })?;
    let mut run = Run::start(
        &relay,
        &["--json", "--relay-stats-list", "--relay-compare", CALL_ID],
    )?;
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
        .ok_or("the names document")?;
    let v: serde_json::Value = serde_json::from_str(line)?;
    assert_eq!(v["relay"], format!("rtpengine at {}", relay.addr));
    let names = v["names"].as_array().ok_or("names is a list")?;
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
    Ok(())
}

/// `--relay-stats-call` prints that call's counters, labeled with the call.
#[test]
fn a_per_call_ask_prints_that_calls_counters() -> Result<(), TestError> {
    let query = fixture_body("rtpengine-query-12.5.1.bencode")?;
    let relay = FakeRelay::start(move |verb, _| match verb {
        "list" => no_calls(),
        "query" => Answer::Body(query.clone()),
        _ => Answer::Silent,
    })?;
    let label = format!("rtpengine at {}, call {CALL_ID}", relay.addr);
    let mut run = Run::start(&relay, &["--relay-stats-call", CALL_ID])?;
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
    Ok(())
}

/// A per-call ask the relay refuses prints no table, only the refusal.
#[test]
fn a_refused_per_call_ask_prints_the_relays_reason_and_no_table() -> Result<(), TestError> {
    let relay = FakeRelay::start(|verb, _| match verb {
        "list" => no_calls(),
        "query" => unknown_call(),
        _ => Answer::Silent,
    })?;
    let mut run = Run::start(&relay, &["--relay-stats-call", CALL_ID])?;
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
    Ok(())
}

/// A reply carrying somebody else's cookie is discarded and called suspect,
/// never read as statistics.
#[test]
fn a_reply_to_another_transaction_is_reported_suspect() -> Result<(), TestError> {
    let relay = FakeRelay::start(|verb, _| match verb {
        "list" => no_calls(),
        "statistics" => Answer::Raw(b"sipnab-somebodyelse d6:result2:oke".to_vec()),
        _ => Answer::Silent,
    })?;
    let mut run = Run::start(&relay, &["--relay-stats"])?;
    assert!(
        run.wait_stderr("the reply was discarded and not read (suspect)"),
        "{}",
        run.err.join("\n")
    );
    let done = run.finish();
    assert_eq!(done.code, Some(0), "{}", done.dump());
    assert!(!done.stdout.contains("Relay statistics"), "{}", done.dump());
    Ok(())
}

/// A relay that never answers is reported as asked-and-silent -- by the
/// one-shot ask, by the poller, and by the comparison, which still states
/// what sipnab measured.
#[test]
fn a_silent_relay_is_reported_as_unanswered_by_every_form() -> Result<(), TestError> {
    let relay = FakeRelay::start(|verb, _| match verb {
        "list" => no_calls(),
        _ => Answer::Silent,
    })?;
    let mut run = Run::start(
        &relay,
        &[
            "--relay-stats",
            "--relay-stats-interval",
            "1",
            "--relay-compare",
            CALL_ID,
        ],
    )?;
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
    Ok(())
}

/// Under `--json` each polled reading is one JSON object that says it was
/// polled and at what interval, the same form the one-shot ask prints.
#[test]
fn a_polled_reading_honors_json() -> Result<(), TestError> {
    let statistics = fixture_body("rtpengine-statistics-12.5.1.bencode")?;
    let relay = FakeRelay::start(move |verb, _| match verb {
        "list" => no_calls(),
        "statistics" => Answer::Body(statistics.clone()),
        _ => Answer::Silent,
    })?;
    let mut run = Run::start(&relay, &["--json", "--relay-stats-interval", "1"])?;
    assert!(
        run.wait_stdout("\"origin\":\"polled\"", 1),
        "a polled reading must print as JSON:\n{}",
        run.out.join("\n")
    );
    let done = run.finish();
    assert_eq!(done.code, Some(0), "{}", done.dump());
    let line = done
        .stdout
        .lines()
        .find(|l| l.contains("\"origin\":\"polled\""))
        .ok_or_else(|| format!("no polled JSON line:\n{}", done.dump()))?;
    let value: serde_json::Value = serde_json::from_str(line)
        .map_err(|e| format!("one JSON object per line: {e:?}\n{line}"))?;
    assert_eq!(value["interval_secs"], 1, "{line}");
    Ok(())
}

/// A media stream nothing in the signaling explains is offered to the
/// reconciler, which asks the relay again (RE4's second trigger).
///
/// The relay holds no call, so the startup snapshot is one `list`; an RTP
/// stream arriving over the HEP listener with no SDP behind it is an orphan,
/// and offering it makes the reconciler re-enumerate: a second `list`.
#[test]
fn an_unexplained_stream_is_offered_to_the_reconciler() -> Result<(), TestError> {
    let relay = FakeRelay::start(|verb, _| match verb {
        "list" => no_calls(),
        _ => Answer::Silent,
    })?;
    let run = Run::start(&relay, &[])?;
    let port: u16 = run
        .err
        .iter()
        .find_map(|l| l.split("HEP listener started on ").nth(1))
        .and_then(|rest| rest.trim().rsplit(':').next())
        .and_then(|p| p.parse().ok())
        .ok_or("the listener names its port")?;

    let mut rtp = vec![0x80, 0x00, 0x00, 0x01, 0, 0, 0, 160, 0x0a, 0x0b, 0x0c, 0x0d];
    rtp.extend_from_slice(&[0xff; 160]);
    let endpoint = sipnab::capture::hep::HepEndpoint {
        src_addr: "192.0.2.50".parse()?,
        dst_addr: "192.0.2.60".parse()?,
        src_port: 40000,
        dst_port: 40002,
        transport: sipnab::net::TransportProto::Udp,
    };
    let datagram = sipnab::capture::hep::build_hep_v3(
        &endpoint,
        chrono::Utc::now(),
        sipnab::capture::hep::HepProtocol::Rtp,
        0,
        None,
        &rtp,
    );
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    sender.send_to(&datagram, ("127.0.0.1", port))?;

    let deadline = Instant::now() + WAIT;
    while relay.asked()?.iter().filter(|v| *v == "list").count() < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let asked = relay.asked()?;
    let done = run.finish();
    assert_eq!(done.code, Some(0), "{}", done.dump());
    assert!(
        asked.iter().filter(|v| *v == "list").count() >= 2,
        "the orphan stream must reach the reconciler, which asks the relay again: \
         {asked:?}\n{}",
        done.dump()
    );
    Ok(())
}

/// A poll whose round trip outlasts the interval says the cadence slipped.
///
/// The relay stays silent, so each poll waits out the control timeout (two
/// seconds), twice the one-second interval. The serial poll loop cannot
/// stack requests, so the cadence slows; the poller has to say so rather
/// than leave the operator reading readings further apart than they asked
/// for with nothing explaining why.
#[test]
fn a_poll_slower_than_its_interval_says_the_cadence_slipped() -> Result<(), TestError> {
    let relay = FakeRelay::start(|verb, _| match verb {
        "list" => no_calls(),
        _ => Answer::Silent,
    })?;
    let mut run = Run::start(&relay, &["--relay-stats-interval", "1"])?;
    assert!(
        run.wait_stderr("longer than the 1s interval; the polling cadence has slipped"),
        "{}",
        run.err.join("\n")
    );
    let done = run.finish();
    assert_eq!(done.code, Some(0), "{}", done.dump());
    Ok(())
}

/// A cumulative counter that goes down between two polls is flagged as a
/// probable relay restart, and each reading still prints.
#[test]
fn a_counter_that_steps_backwards_between_polls_is_flagged_suspect() -> Result<(), TestError> {
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
    })?;
    let mut run = Run::start(&relay, &["--relay-stats-interval", "1"])?;
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
    Ok(())
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
fn an_unparseable_relay_address_asks_nothing_and_every_form_says_so() -> Result<(), TestError> {
    let mut run = Run::start_with_control(
        "relay-without-a-port",
        &[
            "--relay-stats",
            "--relay-stats-interval",
            "1",
            "--relay-compare",
            CALL_ID,
        ],
    )?;
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
    Ok(())
}
