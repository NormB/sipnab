// SPDX-License-Identifier: MIT OR Apache-2.0

//! A headless `sipnab -N` run serving `--metrics`, on ports the kernel chose.
//!
//! Both of the run's listeners are started on `127.0.0.1:0`. The harnesses
//! this replaces bound an ephemeral port, read the number, RELEASED the port,
//! and started sipnab on the number. In that gap any parallel test could be
//! given the same port, and sipnab then exited with "Failed to bind metrics
//! server ... Address already in use" (PORT-RACE-HEP). With port 0 the port is
//! the run's from the moment it exists, and the run's own log line is the one
//! place its number is written down, so that is where it is read.
//!
//! Used by `metrics_headless_test` and `config_wiring_test`;
//! `#![allow(dead_code)]` because each consumer uses only part of it.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// What the metrics server logs once it holds its socket; the address it
/// actually bound follows.
const LISTENING: &str = "Prometheus metrics server listening on ";

/// A running headless sipnab with its metrics endpoint up.
pub struct HeadlessMetrics {
    /// The process. The caller stops it (see `teardown.rs`).
    pub child: Child,
    /// `host:port` the metrics server reported binding.
    pub addr: String,
    /// Stderr, one line per message, fed by a reader thread.
    lines: mpsc::Receiver<String>,
    /// Every stderr line read so far.
    seen: Vec<String>,
}

/// The address the metrics server's startup line names, if `line` is that
/// line.
pub fn metrics_addr(line: &str) -> Option<SocketAddr> {
    line.split(LISTENING)
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

impl HeadlessMetrics {
    /// Spawn `bin -N --hep-listen 127.0.0.1:0 --metrics 127.0.0.1:0 --quiet`
    /// followed by `extra`, and wait up to `wait` for the metrics server to
    /// report the address it bound.
    ///
    /// The HEP listener is there only to keep a headless run alive: a file
    /// run reads its capture and exits in milliseconds.
    ///
    /// # Errors
    ///
    /// The child exited first, or never reported an address within `wait`.
    /// The message carries its exit status and stderr, and the child has been
    /// reaped.
    pub fn spawn(bin: &Path, extra: &[&str], wait: Duration) -> Result<Self, String> {
        let mut child = Command::new(bin)
            .args([
                "-N",
                "--hep-listen",
                "127.0.0.1:0",
                "--metrics",
                "127.0.0.1:0",
                "--quiet",
            ])
            .args(extra)
            // `--quiet` silences the console; the log level named here still
            // writes the startup line this harness reads.
            .env("SIPNAB_LOG", "info")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", bin.display()))?;
        let stderr = child.stderr.take().expect("stderr is piped");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        let mut seen = Vec::new();
        let by = Instant::now() + wait;
        loop {
            match lines.recv_timeout(Duration::from_millis(100)) {
                Ok(line) => {
                    let addr = metrics_addr(&line);
                    seen.push(line);
                    if let Some(addr) = addr {
                        return Ok(Self {
                            child,
                            addr: addr.to_string(),
                            lines,
                            seen,
                        });
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                // Stderr closed: the process is gone or going.
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let status = child.wait();
                    return Err(format!(
                        "sipnab exited ({status:?}) before its metrics server reported \
                         an address. Its stderr:\n{}",
                        seen.join("\n")
                    ));
                }
            }
            if Instant::now() >= by {
                let _ = child.kill();
                let status = child.wait();
                return Err(format!(
                    "sipnab's metrics server reported no address within {wait:?} \
                     (killed: {status:?}). Its stderr:\n{}",
                    seen.join("\n")
                ));
            }
        }
    }

    /// Every stderr line the run has written so far.
    pub fn stderr(&mut self) -> String {
        while let Ok(line) = self.lines.try_recv() {
            self.seen.push(line);
        }
        self.seen.join("\n")
    }
}
