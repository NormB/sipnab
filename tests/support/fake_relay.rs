// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A relay that answers rtpengine's ng control protocol on loopback, and the
//! sipnab runs that ask it.
//!
//! A run that asks a relay transmits, so it needs a live source. A HEP
//! listener is one (`-L 127.0.0.1:0`), and it needs no privileges. The relay
//! is a UDP socket the test owns, which answers the ng framing, `<cookie>
//! <bencode>`. Every datagram the run sends goes to that socket and nowhere
//! else.
//!
//! `relay_fetch_end_to_end_test.rs` and `howto_claims_test.rs` both use it,
//! with `#[path = "support/fake_relay.rs"] mod fake_relay;`.

#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

include!("timeout.rs");
include!("teardown.rs");
include!("drain.rs");
include!("child_lifetime.rs");

/// Any error a helper here can return; `?` converts into it.
pub type TestError = Box<dyn std::error::Error>;

/// Longest any single wait in this file lasts. Generous, because the binary
/// may be instrumented and the host loaded; a passing run waits far less.
pub const WAIT: Duration = Duration::from_secs(30);

/// What the fake relay does with one request.
pub enum Answer {
    /// Reply with this bencode body, framed with the request's own cookie.
    Body(Vec<u8>),
    /// Reply with exactly these bytes, cookie and all.
    Raw(Vec<u8>),
    /// Say nothing, so the client times out.
    Silent,
}

/// A loopback UDP socket that answers rtpengine ng requests.
pub struct FakeRelay {
    pub addr: SocketAddr,
    /// Every verb asked, in arrival order.
    pub asked: Arc<Mutex<Vec<String>>>,
    /// Every request body, cookie removed, in arrival order.
    pub requests: Arc<Mutex<Vec<Vec<u8>>>>,
    pub stop: Arc<AtomicBool>,
    pub thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}

impl FakeRelay {
    /// Start answering; `answer` receives the verb and how many times that
    /// verb has been asked before.
    pub fn start(
        mut answer: impl FnMut(&str, usize) -> Answer + Send + 'static,
    ) -> Result<Self, TestError> {
        let sock = UdpSocket::bind("127.0.0.1:0")?;
        sock.set_read_timeout(Some(Duration::from_millis(100)))?;
        let addr = sock.local_addr()?;
        let asked = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (asked_t, stop_t) = (Arc::clone(&asked), Arc::clone(&stop));
        let requests_t = Arc::clone(&requests);
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
                requests_t
                    .lock()
                    .map_err(|e| e.to_string())?
                    .push(req[space..].to_vec());
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
            requests,
            stop,
            thread: Some(thread),
        })
    }

    /// The verbs asked so far.
    pub fn asked(&self) -> Result<Vec<String>, TestError> {
        Ok(self.asked.lock().map_err(|e| e.to_string())?.clone())
    }

    /// The request bodies received so far, cookie removed.
    pub fn requests(&self) -> Result<Vec<Vec<u8>>, TestError> {
        Ok(self.requests.lock().map_err(|e| e.to_string())?.clone())
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
pub fn verb_of(body: &[u8]) -> String {
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
pub fn fixture_body(name: &str) -> Result<Vec<u8>, TestError> {
    let path = format!("{}/tests/fixtures/relay/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?;
    let space = raw
        .iter()
        .position(|b| *b == b' ')
        .ok_or("cookie separator")?;
    Ok(raw[space + 1..].to_vec())
}

/// An empty, complete `list` answer: the relay holds no calls right now.
pub fn no_calls() -> Answer {
    Answer::Body(b"d5:callsle6:result2:oke".to_vec())
}

/// rtpengine's refusal for a call it does not hold.
pub fn unknown_call() -> Answer {
    Answer::Body(b"d12:error-reason15:Unknown call-id6:result5:errore".to_vec())
}

/// A running `sipnab -N -L 127.0.0.1:0` with both output streams drained.
pub struct Run {
    pub child: Child,
    pub stdout: mpsc::Receiver<String>,
    pub stderr: mpsc::Receiver<String>,
    pub out: Vec<String>,
    pub err: Vec<String>,
    pub _home: tempfile::TempDir,
}

/// Drain `r` into a channel of lines on a background thread.
pub fn lines_of<R: std::io::Read + Send + 'static>(r: R) -> mpsc::Receiver<String> {
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
    pub fn start(relay: &FakeRelay, extra: &[&str]) -> Result<Self, TestError> {
        Self::start_with_control(&relay.addr.to_string(), extra)
    }

    /// As [`Run::start`], naming `control` verbatim as the relay address.
    pub fn start_with_control(control: &str, extra: &[&str]) -> Result<Self, TestError> {
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
            .tied_to_test()
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
    pub fn wait_stderr(&mut self, needle: &str) -> bool {
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
    pub fn wait_stdout(&mut self, needle: &str, count: usize) -> bool {
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
    pub fn finish(mut self) -> Finished {
        let code = terminate_within(&mut self.child, WAIT)
            .ok()
            .and_then(|status| status.code());
        self.out
            .extend(drain_closed(&self.stdout, test_timeout(10)));
        self.err
            .extend(drain_closed(&self.stderr, test_timeout(10)));
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
pub struct Finished {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Finished {
    /// Both streams, for failure messages.
    pub fn dump(&self) -> String {
        format!("--- stdout\n{}\n--- stderr\n{}", self.stdout, self.stderr)
    }
}

/// A `list` answer naming `ids`.
pub fn calls(ids: &[&str]) -> Answer {
    let mut body = b"d5:callsl".to_vec();
    for id in ids {
        body.extend_from_slice(format!("{}:{id}", id.len()).as_bytes());
    }
    body.extend_from_slice(b"e6:result2:oke");
    Answer::Body(body)
}

/// Run `sipnab -N <args>` to its exit, failing the test if it outlives
/// [`WAIT`]. `--relay-holdings` answers and exits before a capture opens, so
/// none of these runs needs a signal to end.
pub fn run_to_exit(args: &[&str]) -> Result<Finished, TestError> {
    let home = tempfile::tempdir()?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("-N")
        .args(args)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env_remove("SIPNAB_CONFIG")
        .env("SIPNAB_LOG", "info")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .tied_to_test()
        .spawn()?;
    let stdout = lines_of(child.stdout.take().ok_or("stdout")?);
    let stderr = lines_of(child.stderr.take().ok_or("stderr")?);
    let deadline = Instant::now() + WAIT;
    let code = loop {
        if let Some(status) = child.try_wait()? {
            break status.code();
        }
        if Instant::now() > deadline {
            let _ = terminate(&mut child);
            return Err(format!("sipnab {args:?} did not exit within {WAIT:?}").into());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let drain =
        |rx: mpsc::Receiver<String>| -> String { drain_closed(&rx, test_timeout(10)).join("\n") };
    Ok(Finished {
        code,
        stdout: drain(stdout),
        stderr: drain(stderr),
    })
}

/// A recorded `query` reply body from `tests/fixtures/rtpengine/`, recorded
/// from rtpengine 12.5.1 on 2026-11-04 and rewritten to RFC 5737 addresses.
pub fn recorded(name: &str) -> Result<Vec<u8>, TestError> {
    let path = format!(
        "{}/tests/fixtures/rtpengine/{name}.bencode",
        env!("CARGO_MANIFEST_DIR")
    );
    Ok(std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?)
}
