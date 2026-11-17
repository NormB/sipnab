// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A TFPS for the action service's tests: bans and unbans in memory, records
//! every call, and notes whether the journal on disk already held the intent
//! when it was called. Shared so the service's tests cannot drift apart on
//! what TFPS does.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sipnab::security::actions::{ActionPolicy, TfpsActions, TfpsReply};

/// The error a fallible helper here returns: any error, boxed, so `?` works
/// on every error type alike.
pub type TestError = Box<dyn std::error::Error>;

pub const T0: u64 = 1_790_600_000;

pub fn addr(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, n))
}

/// How long a held call waits for its release at most. It only ends a test
/// whose release never comes (the code under test waited for the call it
/// should not have waited for); a released call goes on at once.
pub const HOLD_CEILING: std::time::Duration = std::time::Duration::from_secs(60);

/// A gate a fake call waits at until the test opens it.
#[derive(Default)]
pub struct Hold {
    open: Mutex<bool>,
    opened: std::sync::Condvar,
    /// Set when a wait reached its ceiling with the gate still shut.
    outlasted: std::sync::atomic::AtomicBool,
}

impl Hold {
    /// Open the gate: every wait, now and later, returns.
    pub fn release(&self) {
        if let Ok(mut open) = self.open.lock() {
            *open = true;
        }
        self.opened.notify_all();
    }

    /// Wait until the gate is opened, or `ceiling` has passed.
    ///
    /// # Returns
    /// `true` when the gate was opened; `false` at the ceiling, which is
    /// also recorded for [`Hold::outlasted`].
    pub fn wait(&self, ceiling: std::time::Duration) -> bool {
        let Ok(open) = self.open.lock() else {
            return false;
        };
        let opened = self
            .opened
            .wait_timeout_while(open, ceiling, |open| !*open)
            .map(|(open, _)| *open)
            .unwrap_or(false);
        if !opened {
            self.outlasted
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        opened
    }

    /// Whether a wait ran to its ceiling with the gate shut.
    pub fn outlasted(&self) -> bool {
        self.outlasted.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Sets its flag when dropped, so every way out of a call sets it.
struct Finished<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for Finished<'_> {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A TFPS that bans and unbans in memory, records every call, and notes
/// whether the journal on disk already held the intent when it was called.
#[derive(Default)]
pub struct FakeTfps {
    pub journal_dir: PathBuf,
    pub calls: Mutex<Vec<String>>,
    pub intent_on_disk_when_called: Mutex<Vec<bool>>,
    pub banned: Mutex<Vec<(Ipv4Addr, Option<u64>)>>,
    pub unreachable: bool,
    /// Answer every unban `not-blocked`, as TFPS does when the ban went
    /// between listing it and lifting it.
    pub unban_not_blocked: bool,
    /// Hold every ban in flight until [`Hold::release`] is called on
    /// `ban_hold`, to catch one in flight without betting on how long it
    /// takes.
    pub ban_held: bool,
    /// What a held ban waits on.
    pub ban_hold: Hold,
    /// Set as a ban starts, before it is held.
    pub ban_started: std::sync::atomic::AtomicBool,
    /// Set as a ban returns.
    pub ban_finished: std::sync::atomic::AtomicBool,
    /// Apply every ban, then lose its answer, as a `tfps_ctl` does that
    /// writes the block map and then times out, exits with no result, or
    /// answers in a shape sipnab cannot read.
    pub ban_answer_lost: bool,
    /// The same, for every unban.
    pub unban_answer_lost: bool,
}

impl FakeTfps {
    pub fn new(journal_dir: &Path) -> Arc<Self> {
        Arc::new(Self {
            journal_dir: journal_dir.to_path_buf(),
            ..Self::default()
        })
    }

    pub fn journal_text(&self) -> String {
        let mut out = String::new();
        if let Ok(rd) = std::fs::read_dir(&self.journal_dir) {
            let mut paths: Vec<PathBuf> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
            paths.sort();
            for p in paths {
                if p.extension().is_some_and(|e| e == "jsonl") {
                    out.push_str(&std::fs::read_to_string(p).unwrap_or_default());
                }
            }
        }
        out
    }

    pub fn calls(&self) -> Result<Vec<String>, TestError> {
        Ok(self.calls.lock().map_err(|e| e.to_string())?.clone())
    }
}

impl TfpsActions for FakeTfps {
    fn ban(&self, ip: Ipv4Addr, ttl_secs: u64, now_unix: u64) -> Result<TfpsReply, String> {
        let journal = self.journal_text();
        self.intent_on_disk_when_called
            .lock()
            .map_err(|e| e.to_string())?
            .push(journal.contains("\"action_intent\"") && journal.contains(&ip.to_string()));
        self.ban_started
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if self.ban_held {
            self.ban_hold.wait(HOLD_CEILING);
        }
        let _finished = Finished(&self.ban_finished);
        self.calls
            .lock()
            .map_err(|e| e.to_string())?
            .push(format!("ban {ip} {ttl_secs}"));
        self.banned
            .lock()
            .map_err(|e| e.to_string())?
            .push((ip, Some(now_unix + ttl_secs)));
        if self.ban_answer_lost {
            return Ok(TfpsReply::Unanswered(
                "tfps_ctl did not finish within 10.0s and was stopped".into(),
            ));
        }
        Ok(TfpsReply::Applied)
    }

    fn unban(&self, ip: Ipv4Addr) -> Result<TfpsReply, String> {
        self.calls
            .lock()
            .map_err(|e| e.to_string())?
            .push(format!("unban {ip}"));
        if self.unban_not_blocked {
            return Ok(TfpsReply::Refused("not-blocked".into()));
        }
        let mut b = self.banned.lock().map_err(|e| e.to_string())?;
        let before = b.len();
        b.retain(|(a, _)| *a != ip);
        if self.unban_answer_lost {
            return Ok(TfpsReply::Unanswered(
                "tfps_ctl exited 1 with no result".into(),
            ));
        }
        Ok(if b.len() < before {
            TfpsReply::Applied
        } else {
            TfpsReply::Refused("not-blocked".into())
        })
    }

    fn banned(&self) -> Result<Vec<(Ipv4Addr, Option<u64>)>, String> {
        if self.unreachable {
            return Err("tfps_ctl not reachable".into());
        }
        Ok(self.banned.lock().map_err(|e| e.to_string())?.clone())
    }
}

pub fn enabled(flag: &str) -> Result<ActionPolicy, TestError> {
    Ok(ActionPolicy::from_settings(&[flag.to_string()], &[])?)
}
