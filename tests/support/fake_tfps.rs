// SPDX-License-Identifier: MIT OR Apache-2.0

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
    /// How long each ban takes, to catch one in flight.
    pub ban_takes: Option<std::time::Duration>,
    /// Set as a ban starts, before it waits `ban_takes`.
    pub ban_started: std::sync::atomic::AtomicBool,
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
        if let Some(d) = self.ban_takes {
            std::thread::sleep(d);
        }
        self.calls
            .lock()
            .map_err(|e| e.to_string())?
            .push(format!("ban {ip} {ttl_secs}"));
        self.banned
            .lock()
            .map_err(|e| e.to_string())?
            .push((ip, Some(now_unix + ttl_secs)));
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
