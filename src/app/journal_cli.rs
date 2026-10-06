// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--journal-show` and `--revert-actions`: seeing and backing out, from the
//! local command line, what sipnab did to other systems.
//!
//! Both run and exit before any capture opens. `--journal-show` only reads,
//! so it works while a running sipnab holds the journal. `--revert-actions`
//! writes, so it takes the journal like any sipnab would, and works with
//! actions switched off: after abuse, switching them off is the first thing
//! an operator does, and recovery must not need them switched back on.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use crate::cli::Cli;
use crate::config::Config;
use crate::journal::ledger::Ledger;
use crate::journal::{Journal, JournalError, Record};
use crate::security::actions::{
    ActionError, ActionLimits, ActionService, PreviousRun, RevertReport, RevertTarget, Reverter,
    TfpsCtl,
};

/// Seconds of refusals `--journal-show` reports.
const REFUSALS_WINDOW_SECS: u64 = 3_600;

/// Handle `--journal-show` or `--revert-actions` and return the exit code,
/// or `None` when neither was given.
pub fn run(cli: &Cli, config: &Config) -> Option<i32> {
    let now_unix = now_unix();
    if cli.security_args.journal_show {
        let dir = cli.journal_dir(config);
        println!("{}", show(&dir, &Journal::read(&dir), now_unix));
        return Some(0);
    }
    let target = cli.security_args.revert_actions.as_deref()?;
    let (text, code) = revert(cli, config, target, now_unix);
    if code == 0 {
        println!("{text}");
    } else {
        stderr_line!("{text}");
    }
    Some(code)
}

/// The current time, Unix seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A Unix time as an RFC 3339 UTC timestamp.
fn stamp(unix: u64) -> String {
    i64::try_from(unix)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map_or_else(
            || unix.to_string(),
            |t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        )
}

/// What `--journal-show` prints for the journal in `dir`, as `read` found it,
/// at `now_unix`.
#[must_use]
pub fn show(
    dir: &Path,
    read: &Result<crate::journal::Recovered, JournalError>,
    now_unix: u64,
) -> String {
    let mut out = String::new();
    let records = match read {
        Ok(r) => &r.records,
        Err(e @ JournalError::Absent(_)) => return e.to_string(),
        Err(e) => return format!("the actions journal cannot be read: {e}"),
    };
    let ledger = Ledger::from_records(records, now_unix);
    let _ = writeln!(out, "Actions journal at {}", dir.display());
    let _ = writeln!(
        out,
        "Last run: {}",
        match PreviousRun::of(records) {
            PreviousRun::None => "none",
            PreviousRun::Stopped => "stopped cleanly",
            PreviousRun::Ended => {
                "no stop record: still running, or it crashed, was killed or lost power; \
                 anything it left in doubt is checked against TFPS at the next start"
            }
        }
    );

    let held = ledger.owned_newest_first();
    if held.is_empty() {
        let _ = writeln!(out, "Held: none");
    } else {
        let _ = writeln!(
            out,
            "Held: bans sipnab placed that are still in force, newest first ({})",
            held.len()
        );
        for o in held {
            let _ = writeln!(
                out,
                "  {}  {}  until {}  asked by {} over {}",
                o.id,
                o.address,
                stamp(o.expires),
                o.caller,
                o.surface
            );
        }
    }

    let doubt = ledger.in_doubt();
    if doubt.is_empty() {
        let _ = writeln!(out, "In doubt: none");
    } else {
        let _ = writeln!(
            out,
            "In doubt: actions that started and never finished ({}); new actions wait until \
             TFPS answers for them",
            doubt.len()
        );
        for i in &doubt {
            let verb = serde_json::to_value(i.verb)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            let _ = writeln!(out, "  {}  {verb} {}  at {}", i.id, i.address, stamp(i.at));
        }
    }

    let unknown = ledger.unknown();
    if unknown.is_empty() {
        let _ = writeln!(out, "Not provably sipnab's: none");
    } else {
        let _ = writeln!(
            out,
            "Not provably sipnab's: bans TFPS shows that sipnab cannot prove it placed ({}); \
             never reverted",
            unknown.len()
        );
        for i in unknown {
            let _ = writeln!(out, "  {}  (action {})", i.address, i.id);
        }
    }

    let refusals = refusals_since(records, now_unix.saturating_sub(REFUSALS_WINDOW_SECS));
    if refusals.is_empty() {
        let _ = write!(out, "Refusals in the last hour: none");
    } else {
        let total: u64 = refusals.values().sum();
        let _ = writeln!(out, "Refusals in the last hour: {total}");
        let mut lines: Vec<String> = refusals
            .iter()
            .map(|((caller, reason), n)| format!("  {n}  {caller}  {reason}"))
            .collect();
        lines.sort();
        let _ = write!(out, "{}", lines.join("\n"));
    }
    out
}

/// Refusals at or after `since`, counted by caller and reason, folded ones
/// included.
fn refusals_since(records: &[Record], since: u64) -> BTreeMap<(String, String), u64> {
    let mut counts = BTreeMap::new();
    for r in records {
        let b = &r.body;
        let text = |k: &str| b[k].as_str().unwrap_or_default().to_string();
        match r.kind.as_str() {
            "action_refused" if b["at"].as_u64().is_some_and(|at| at >= since) => {
                *counts.entry((text("caller"), text("reason"))).or_insert(0) += 1;
            }
            "refusals_summary" if b["minute_start"].as_u64().is_some_and(|at| at >= since) => {
                for c in b["counts"].as_array().into_iter().flatten() {
                    let key = (
                        c["caller"].as_str().unwrap_or_default().to_string(),
                        c["reason"].as_str().unwrap_or_default().to_string(),
                    );
                    *counts.entry(key).or_insert(0) += c["folded"].as_u64().unwrap_or(0);
                }
            }
            _ => {}
        }
    }
    counts
}

/// Run `--revert-actions target`: the report and the exit code.
fn revert(cli: &Cli, config: &Config, target: &str, now_unix: u64) -> (String, i32) {
    let dir = cli.journal_dir(config);
    let target = if target == "all" {
        RevertTarget::All
    } else {
        RevertTarget::One(target.to_string())
    };
    // Nothing to revert where nothing was recorded; opening would create a
    // journal only to say so.
    if let Err(e @ JournalError::Absent(_)) = Journal::read(&dir) {
        return match target {
            RevertTarget::All => (format!("{e}; nothing to revert"), 0),
            RevertTarget::One(_) => (ActionError::NotOwned.to_string(), 1),
        };
    }
    // The policy and limits do not govern a local revert, but a journal
    // started without them would log a run with none.
    let policy = cli.action_policy(config).unwrap_or_default();
    let limits = cli
        .action_limits(config)
        .unwrap_or_else(|_| ActionLimits::default());
    let tfps = Arc::new(TfpsCtl::new(cli.tfps_locator(config)));
    let started = ActionService::start(
        policy,
        limits,
        &dir,
        tfps,
        now_unix,
        std::time::Instant::now(),
    );
    let service = match started {
        Ok((service, _)) => service,
        Err(e) => {
            let mut text = format!("actions journal {}: {e}", dir.display());
            if text.contains("in use by another sipnab") {
                text.push_str(
                    ". Revert through the sipnab that holds it: POST /v1/actions/revert over \
                     REST, or the actions_revert MCP tool. Or stop it and run this again.",
                );
            }
            return (text, 2);
        }
    };
    let done = service.revert(Reverter::Local, target, now_unix, std::time::Instant::now());
    // This run ends here, and says so: otherwise the next sipnab to start
    // would read it as a crash.
    service.stop(now_unix);
    match done {
        Ok(report) => {
            let code = i32::from(!report.failed.is_empty() || !report.left.is_empty());
            (describe(&report), code)
        }
        Err(e @ ActionError::NotOwned) => (e.to_string(), 1),
        Err(e) => (e.to_string(), 2),
    }
}

/// A revert report, one line per thing done or not done.
#[must_use]
pub fn describe(report: &RevertReport) -> String {
    let mut lines = Vec::new();
    if report.reverted.is_empty()
        && report.lapsed.is_empty()
        && report.failed.is_empty()
        && report.skipped_unknown.is_empty()
    {
        lines.push("Nothing to revert: sipnab holds no ban.".to_string());
    }
    for id in &report.reverted {
        lines.push(format!("Reverted {id}"));
    }
    for address in &report.lapsed {
        lines.push(format!(
            "Already lifted: TFPS no longer held the ban on {address}; sipnab no longer holds it"
        ));
    }
    for address in &report.skipped_unknown {
        lines.push(format!(
            "Left alone: {address} is banned, but sipnab cannot prove it placed that ban"
        ));
    }
    for f in &report.failed {
        lines.push(format!("Not reverted {} ({}): {}", f.id, f.address, f.why));
    }
    if !report.left.is_empty() {
        lines.push(format!(
            "Not reached, a rate limit stopped the revert: {}",
            report.left.join(", ")
        ));
    }
    lines.join("\n")
}
