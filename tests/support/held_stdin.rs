// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A `sipnab` run whose standard input is a pipe the test holds open, for
//! the tests that stop a run while it waits on that input
//! (STDIN-READ-IGNORES-STOP).
//!
//! The pipe's write end stays open until the test closes it, so the run sees
//! no end-of-file and keeps waiting. The test signals the run only by the pid
//! it recorded at spawn, after checking that the pid is still this child
//! running this binary, and a run still alive at the deadline, or when the
//! value drops, is killed and reaped: a failing test leaves no process
//! behind.
//!
//! Linux only: readiness is read from `/proc/<pid>/status`.

use std::io::Read as _;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// One run of the sipnab binary with a held standard input.
pub struct HeldStdin {
    /// The run, spawned by this value and not yet reaped.
    child: Child,
    /// The pid recorded at spawn: the only process this value signals.
    pid: libc::pid_t,
    /// The write end of the run's standard input, open until dropped.
    stdin: Option<ChildStdin>,
    /// The thread reading the run's stderr, so a full pipe never blocks it.
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
    /// Whether the run has been reaped.
    reaped: bool,
}

impl HeldStdin {
    /// Start the sipnab binary with `args`, `SIPNAB_LOG=info`, stdout
    /// discarded, and stdin a pipe this value holds open.
    pub fn spawn(args: &[String]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(args)
            .env("SIPNAB_LOG", "info")
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .tied_to_test()
            .spawn()?;
        let pid = libc::pid_t::try_from(child.id())?;
        let stdin = child.stdin.take();
        let stderr = child.stderr.take().map(|mut err| {
            thread::spawn(move || {
                let mut text = Vec::new();
                let _ = err.read_to_end(&mut text);
                text
            })
        });
        Ok(HeldStdin {
            child,
            pid,
            stdin,
            stderr,
            reaped: false,
        })
    }

    /// Wait until the run has installed its SIGTERM handler, the step before
    /// which a signal would end it by its default action. A signal sent after
    /// this reaches sipnab's own handler.
    #[allow(dead_code)]
    pub fn wait_for_handlers(
        &mut self,
        within: Duration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + within;
        // SigCgt is a hex mask; signal n is bit n - 1.
        let bit = 1u64 << (libc::SIGTERM - 1);
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                return Err(format!("sipnab exited before it was signaled: {status}").into());
            }
            let status = std::fs::read_to_string(format!("/proc/{}/status", self.pid))?;
            let caught = status
                .lines()
                .find_map(|l| l.strip_prefix("SigCgt:"))
                .map(str::trim)
                .map(|hex| u64::from_str_radix(hex, 16))
                .transpose()?
                .ok_or("no SigCgt line")?;
            if caught & bit != 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(
                    format!("sipnab installed no SIGTERM handler within {within:?}").into(),
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Send `signal` to the run, by the pid recorded at spawn, once it is
    /// confirmed to be this unreaped child running the sipnab binary.
    #[allow(dead_code)]
    pub fn signal(&mut self, signal: libc::c_int) -> Result<(), Box<dyn std::error::Error>> {
        if self.reaped || self.child.try_wait()?.is_some() {
            return Err("the run already exited".into());
        }
        let exe = std::fs::read_link(format!("/proc/{}/exe", self.pid))?;
        let want = std::fs::canonicalize(env!("CARGO_BIN_EXE_sipnab"))?;
        if exe != want {
            return Err(format!("pid {} runs {}, not sipnab", self.pid, exe.display()).into());
        }
        // SAFETY: kill(2) on this value's own child, which is unreaped, so the
        // pid cannot have been reused.
        if unsafe { libc::kill(self.pid, signal) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// The pid recorded at spawn.
    #[allow(dead_code)]
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Wait up to `within` for the run to exit: its status and its stderr.
    /// A run still alive at the deadline is killed and reaped, and the result
    /// is an error naming `after`.
    #[allow(dead_code)]
    pub fn wait_for_exit(
        &mut self,
        within: Duration,
        after: &str,
    ) -> Result<(ExitStatus, String), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                let err = self
                    .stderr
                    .take()
                    .map(|t| t.join().unwrap_or_default())
                    .unwrap_or_default();
                return Ok((status, String::from_utf8_lossy(&err).into_owned()));
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                self.reaped = true;
                return Err(format!("sipnab was still running {within:?} after {after}").into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for HeldStdin {
    fn drop(&mut self) {
        drop(self.stdin.take());
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

include!("child_lifetime.rs");
