// SPDX-License-Identifier: MIT OR Apache-2.0

//! Backing out a bad or stale update, and keeping the journal bounded
//! (JOURNAL + ACTIONS-HARDEN; approved spec 2026-09-28).
//!
//! Written before the behavior exists. Norm, 2026-09-28: "there must be
//! recovery tests that can back out a bad or stale update". From the approved
//! journal spec:
//!
//! * revert one action by id, or everything sipnab did that is still in
//!   effect, newest first, each journaled as its own revert; from the local
//!   command line this works even with actions switched off;
//! * sipnab compares what it owns with TFPS once a minute and before every
//!   revert, and a ban TFPS dropped early is journaled `lapsed_by_peer`;
//! * a segment closes at its size limit and the next opens with a
//!   checkpoint, so pruning old segments loses nothing still in force;
//! * a flood of refusals costs a few records a minute, not one each.

#![cfg(all(unix, feature = "full"))]

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipnab::journal::JournalLimits;
use sipnab::security::actions::{
    ActionError, ActionLimits, ActionPolicy, ActionService, ActionSurface, PreviousRun,
    RevertTarget, Reverter,
};

#[path = "support/fake_tfps.rs"]
mod fake_tfps;

use fake_tfps::{FakeTfps, T0, addr, enabled_or_panic};

struct Rig {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    tfps: Arc<FakeTfps>,
    t0: Instant,
}

fn rig() -> Rig {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("journal");
    let tfps = FakeTfps::new(&dir);
    Rig {
        _tmp: tmp,
        dir,
        tfps,
        t0: Instant::now(),
    }
}

/// Limits loose enough that a test is never throttled unless it means to be.
fn roomy() -> ActionLimits {
    ActionLimits::new(1_000, 1_000, Duration::from_millis(1)).expect("limits")
}

fn start_with(r: &Rig, policy: ActionPolicy, limits: ActionLimits, now: u64) -> ActionService {
    ActionService::start_with(
        policy,
        limits,
        &r.dir,
        r.tfps.clone(),
        JournalLimits::default(),
        now,
        r.t0,
    )
    .expect("start")
    .0
}

fn ban(svc: &ActionService, r: &Rig, n: u8, at: u64) -> String {
    svc.ban(ActionSurface::Rest, "token:ops", addr(n), None, at, r.t0)
        .expect("ban")
        .id
}

fn kinds(r: &Rig) -> Vec<String> {
    r.tfps
        .journal_text()
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("record");
            v["kind"].as_str().unwrap_or_default().to_string()
        })
        .collect()
}

// ── revert ───────────────────────────────────────────────────────────────

#[test]
fn revert_one_lifts_that_ban_and_journals_the_revert() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    let first = ban(&svc, &r, 20, T0);
    let _second = ban(&svc, &r, 21, T0);
    let report = svc
        .revert(
            Reverter::Local,
            RevertTarget::One(first.clone()),
            T0 + 5,
            r.t0,
        )
        .expect("revert");
    assert_eq!(report.reverted, std::slice::from_ref(&first));
    assert!(svc.owned(addr(20)).is_none(), "ownership ended");
    assert!(svc.owned(addr(21)).is_some(), "the other ban stands");
    assert_eq!(
        r.tfps.calls_or_panic().last().map(String::as_str),
        Some("unban 198.51.100.20")
    );
    let k = kinds(&r);
    assert!(k.contains(&"revert_intent".to_string()), "{k:?}");
    assert!(k.contains(&"revert_outcome".to_string()), "{k:?}");
    assert!(
        r.tfps
            .journal_text()
            .contains(&format!("\"reverts\":\"{first}\"")),
        "the revert names the action it backs out"
    );
}

#[test]
fn revert_all_lifts_every_owned_ban_newest_first() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    let a = ban(&svc, &r, 20, T0);
    let b = ban(&svc, &r, 21, T0 + 1);
    let c = ban(&svc, &r, 22, T0 + 2);
    let report = svc
        .revert(Reverter::Local, RevertTarget::All, T0 + 5, r.t0)
        .expect("revert all");
    assert_eq!(report.reverted, [c, b, a], "newest first");
    let unbans: Vec<String> = r
        .tfps
        .calls_or_panic()
        .into_iter()
        .filter(|c| c.starts_with("unban"))
        .collect();
    assert_eq!(
        unbans,
        [
            "unban 198.51.100.22",
            "unban 198.51.100.21",
            "unban 198.51.100.20"
        ]
    );
    for n in 20..=22 {
        assert!(svc.owned(addr(n)).is_none());
    }
}

#[test]
fn the_local_operator_can_revert_with_actions_switched_off() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    let id = ban(&svc, &r, 20, T0);
    drop(svc);
    // After abuse the first thing an operator does is switch actions off;
    // recovery must not require switching them back on.
    let svc = start_with(&r, ActionPolicy::default(), roomy(), T0 + 10);
    let report = svc
        .revert(Reverter::Local, RevertTarget::All, T0 + 10, r.t0)
        .expect("revert with actions off");
    assert_eq!(report.reverted, [id]);
    assert_eq!(
        r.tfps.calls_or_panic().last().map(String::as_str),
        Some("unban 198.51.100.20")
    );
}

#[test]
fn a_remote_revert_needs_actions_enabled_and_counts_against_the_limits() {
    let r = rig();
    let svc = start_with(
        &r,
        enabled_or_panic("tfps:mcp"),
        ActionLimits::default(),
        T0,
    );
    let err = svc
        .revert(
            Reverter::Surface {
                surface: ActionSurface::Rest,
                caller: "token:ops",
            },
            RevertTarget::All,
            T0,
            r.t0,
        )
        .expect_err("REST is not enabled");
    assert!(matches!(err, ActionError::NotEnabled(_)), "{err:?}");
    // Over MCP it is an action: ban then revert the same address within the
    // cooldown, and the revert waits.
    let id = svc
        .ban(ActionSurface::Mcp, "stdio", addr(20), None, T0, r.t0)
        .expect("ban")
        .id;
    let err = svc
        .revert(
            Reverter::Surface {
                surface: ActionSurface::Mcp,
                caller: "stdio",
            },
            RevertTarget::One(id),
            T0,
            r.t0,
        )
        .expect_err("within the address cooldown");
    assert!(matches!(err, ActionError::Throttled(_)), "{err:?}");
    assert!(svc.owned(addr(20)).is_some());
}

#[test]
fn revert_of_an_id_sipnab_does_not_own_is_refused() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    let err = svc
        .revert(
            Reverter::Local,
            RevertTarget::One("a-not-a-real-id".into()),
            T0,
            r.t0,
        )
        .expect_err("no such owned action");
    assert_eq!(err, ActionError::NotOwned);
    assert!(
        r.tfps
            .calls_or_panic()
            .iter()
            .all(|c| !c.starts_with("unban"))
    );
}

#[test]
fn revert_all_skips_a_ban_it_cannot_prove_it_placed() {
    // A crash between intent and outcome, and TFPS then shows the address
    // banned with an expiry the intent does not match: `unknown`, not owned,
    // and revert-all leaves it alone and says so.
    let r = rig();
    {
        let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
        let _ = ban(&svc, &r, 21, T0);
    }
    // Forge the crash: an intent with no outcome, for an address TFPS shows
    // banned by someone else, until a different time.
    r.tfps
        .banned
        .lock()
        .unwrap()
        .push((Ipv4Addr::new(198, 51, 100, 30), Some(T0 + 99_999)));
    {
        // A crash between the intent and the outcome: the intent written the
        // way the service writes it, and nothing after.
        let (mut j, _) = sipnab::journal::Journal::open(&r.dir, "crashed-run").expect("open");
        j.append(
            "action_intent",
            serde_json::json!({"id": "a-crash", "target": "tfps", "verb": "ban",
                "address": "198.51.100.30", "at": T0 + 1, "ttl_secs": 3600,
                "expires": T0 + 3601, "surface": "rest", "caller": "token:ops"}),
        )
        .expect("intent");
    }
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0 + 2);
    let report = svc
        .revert(Reverter::Local, RevertTarget::All, T0 + 3, r.t0)
        .expect("revert all");
    assert_eq!(report.skipped_unknown, ["198.51.100.30"]);
    assert!(
        !r.tfps
            .calls_or_panic()
            .contains(&"unban 198.51.100.30".to_string()),
        "{:?}",
        r.tfps.calls_or_panic()
    );
}

// ── stale bans ───────────────────────────────────────────────────────────

#[test]
fn a_ban_tfps_dropped_early_is_journaled_as_lapsed_and_ownership_ends() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    let _ = ban(&svc, &r, 20, T0);
    // TFPS restarted and forgot its manual bans.
    r.tfps.banned.lock().unwrap().clear();
    let report = svc.reconcile(T0 + 60).expect("reconcile");
    assert_eq!(report.lapsed, 1);
    assert!(svc.owned(addr(20)).is_none());
    assert!(kinds(&r).contains(&"lapsed_by_peer".to_string()));
    // The next check finds nothing new to say.
    assert_eq!(svc.reconcile(T0 + 120).expect("reconcile").lapsed, 0);
}

#[test]
fn a_ban_past_its_expiry_is_not_lapsed_by_the_peer() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    let _ = svc
        .ban(
            ActionSurface::Rest,
            "token:ops",
            addr(20),
            Some(60),
            T0,
            r.t0,
        )
        .expect("ban");
    r.tfps.banned.lock().unwrap().clear();
    let report = svc.reconcile(T0 + 61).expect("reconcile");
    assert_eq!(
        report.lapsed, 0,
        "it expired as asked; TFPS dropped nothing"
    );
    assert!(!kinds(&r).contains(&"lapsed_by_peer".to_string()));
}

#[test]
fn reconcile_with_tfps_unreachable_changes_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("journal");
    let tfps = Arc::new(FakeTfps {
        journal_dir: dir.clone(),
        unreachable: true,
        ..FakeTfps::default()
    });
    let (svc, _) = ActionService::start_with(
        enabled_or_panic("tfps:rest"),
        roomy(),
        &dir,
        tfps.clone(),
        JournalLimits::default(),
        T0,
        Instant::now(),
    )
    .expect("start");
    let _ = svc
        .ban(
            ActionSurface::Rest,
            "token:ops",
            addr(20),
            None,
            T0,
            Instant::now(),
        )
        .expect("ban");
    let err = svc.reconcile(T0 + 60).expect_err("TFPS unreachable");
    assert!(matches!(err, ActionError::Tfps(_)), "{err:?}");
    assert!(svc.owned(addr(20)).is_some(), "nothing is assumed");
}

#[test]
fn a_revert_of_a_ban_tfps_already_dropped_ends_ownership_as_lapsed() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    let id = ban(&svc, &r, 20, T0);
    r.tfps.banned.lock().unwrap().clear();
    let report = svc
        .revert(Reverter::Local, RevertTarget::One(id), T0 + 5, r.t0)
        .expect("revert");
    assert!(report.reverted.is_empty(), "{report:?}");
    assert_eq!(report.lapsed, ["198.51.100.20"]);
    assert!(svc.owned(addr(20)).is_none());
    assert!(
        r.tfps
            .calls_or_panic()
            .iter()
            .all(|c| !c.starts_with("unban")),
        "the check before the revert found it gone, so TFPS is not asked"
    );
}

// ── bounds ───────────────────────────────────────────────────────────────

#[test]
fn a_full_segment_rolls_over_with_a_checkpoint_and_pruning_loses_nothing_in_force() {
    let r = rig();
    let small = JournalLimits {
        segment_bytes: 2_048,
        retention: Duration::ZERO,
    };
    let (svc, _) = ActionService::start_with(
        enabled_or_panic("tfps:rest"),
        roomy(),
        &r.dir,
        r.tfps.clone(),
        small,
        T0,
        r.t0,
    )
    .expect("start");
    for n in 1..=30 {
        let _ = ban(&svc, &r, n, T0 + u64::from(n));
    }
    drop(svc);
    let segments = std::fs::read_dir(&r.dir)
        .expect("dir")
        .filter(|e| {
            e.as_ref()
                .is_ok_and(|e| e.path().extension().is_some_and(|x| x == "jsonl"))
        })
        .count();
    assert!(segments >= 1, "{segments}");
    assert!(
        kinds(&r).first().map(String::as_str) == Some("checkpoint"),
        "the oldest segment left opens with a checkpoint: {:?}",
        kinds(&r).first()
    );
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0 + 40);
    for n in 1..=30 {
        assert!(svc.owned(addr(n)).is_some(), "ban {n} survived the prune");
    }
}

#[test]
fn a_flood_of_refusals_costs_a_few_records_a_minute() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    for _ in 0..500 {
        let _ = svc.ban(
            ActionSurface::Rest,
            "token:flood",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
            T0,
            r.t0,
        );
    }
    let refused = kinds(&r).iter().filter(|k| *k == "action_refused").count();
    assert_eq!(
        refused, 1,
        "the first of the minute in full, the rest counted"
    );
    // A minute later, the count is written once.
    let _ = svc.ban(
        ActionSurface::Rest,
        "token:flood",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        T0 + 60,
        r.t0,
    );
    let text = r.tfps.journal_text();
    let summary: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("record"))
        .filter(|v| v["kind"] == "refusals_summary")
        .collect();
    assert_eq!(summary.len(), 1, "{summary:?}");
    assert_eq!(summary[0]["counts"][0]["caller"], "token:flood");
    assert_eq!(summary[0]["counts"][0]["reason"], "address");
    assert_eq!(summary[0]["counts"][0]["folded"], 499);
}

#[test]
fn folding_is_per_caller_and_reason_so_a_flood_hides_no_one_else() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    for _ in 0..50 {
        let _ = svc.ban(
            ActionSurface::Rest,
            "token:flood",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
            T0,
            r.t0,
        );
    }
    let _ = svc.ban(
        ActionSurface::Rest,
        "token:other",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        T0,
        r.t0,
    );
    let text = r.tfps.journal_text();
    assert!(
        text.contains("\"caller\":\"token:other\""),
        "another caller's first refusal is written in full"
    );
}

#[test]
fn revert_all_is_newest_first_even_for_bans_in_the_same_second() {
    // Ids end in a counter; compared as text, `-10` sorts before `-9`.
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    let ids: Vec<String> = (1..=12).map(|n| ban(&svc, &r, n, T0)).collect();
    let report = svc
        .revert(Reverter::Local, RevertTarget::All, T0 + 5, r.t0)
        .expect("revert all");
    let newest_first: Vec<String> = ids.into_iter().rev().collect();
    assert_eq!(report.reverted, newest_first);
}

#[test]
fn a_ban_that_went_between_the_check_and_the_unban_ends_as_lapsed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("journal");
    let tfps = Arc::new(FakeTfps {
        journal_dir: dir.clone(),
        unban_not_blocked: true,
        ..FakeTfps::default()
    });
    let t0 = Instant::now();
    let (svc, _) = ActionService::start_with(
        enabled_or_panic("tfps:rest"),
        roomy(),
        &dir,
        tfps.clone(),
        JournalLimits::default(),
        T0,
        t0,
    )
    .expect("start");
    let id = svc
        .ban(ActionSurface::Rest, "token:ops", addr(20), None, T0, t0)
        .expect("ban")
        .id;
    let report = svc
        .revert(Reverter::Local, RevertTarget::One(id), T0 + 5, t0)
        .expect("revert");
    assert!(report.reverted.is_empty(), "{report:?}");
    assert_eq!(report.lapsed, ["198.51.100.20"]);
    assert!(svc.owned(addr(20)).is_none());
    assert!(tfps.journal_text().contains("\"lapsed_by_peer\""));
}

#[test]
fn a_ban_tfps_dropped_while_sipnab_was_down_is_found_at_start() {
    let r = rig();
    {
        let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
        let _ = ban(&svc, &r, 20, T0);
    }
    r.tfps.banned.lock().unwrap().clear();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0 + 30);
    assert!(svc.owned(addr(20)).is_none());
    assert!(kinds(&r).contains(&"lapsed_by_peer".to_string()));
}

#[test]
fn refusals_from_many_callers_stay_bounded() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    for n in 0..6_000 {
        let _ = svc.ban(
            ActionSurface::Rest,
            &format!("token:sybil-{n}"),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
            T0,
            r.t0,
        );
    }
    let refused = kinds(&r).iter().filter(|k| *k == "action_refused").count();
    assert!(
        refused <= 4_097,
        "{refused} records for one minute's refusals"
    );
}

// ── the check while running ──────────────────────────────────────────────

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

#[test]
fn the_watch_finds_a_dropped_ban_without_anyone_asking() {
    let r = rig();
    let now = now_unix();
    let svc = Arc::new(start_with(&r, enabled_or_panic("tfps:rest"), roomy(), now));
    let _ = svc
        .ban(ActionSurface::Rest, "token:ops", addr(20), None, now, r.t0)
        .expect("ban");
    let _watch = ActionService::watch(&svc, Duration::from_millis(20)).expect("spawn");
    r.tfps.banned.lock().unwrap().clear();
    let deadline = Instant::now() + Duration::from_secs(5);
    while svc.owned(addr(20)).is_some() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(svc.owned(addr(20)).is_none(), "the watch never noticed");
    assert!(kinds(&r).contains(&"lapsed_by_peer".to_string()));
}

#[test]
fn the_watch_ends_when_the_service_does() {
    let r = rig();
    let svc = Arc::new(start_with(
        &r,
        enabled_or_panic("tfps:rest"),
        roomy(),
        now_unix(),
    ));
    let watch = ActionService::watch(&svc, Duration::from_millis(10)).expect("spawn");
    drop(svc);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !watch.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(watch.is_finished(), "the watch outlived the service");
}

// ── stop and crash ───────────────────────────────────────────────────────

#[test]
fn a_clean_stop_is_journaled_and_the_next_start_knows() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    let _ = ban(&svc, &r, 20, T0);
    assert!(
        svc.stop(T0 + 1),
        "nothing was in flight, so the record is written"
    );
    drop(svc);
    assert!(kinds(&r).contains(&"run_stop".to_string()));
    let (_, report) = ActionService::start_with(
        enabled_or_panic("tfps:rest"),
        roomy(),
        &r.dir,
        r.tfps.clone(),
        JournalLimits::default(),
        T0 + 2,
        r.t0,
    )
    .expect("start");
    assert_eq!(report.previous_run, PreviousRun::Stopped);
}

#[test]
fn without_a_stop_record_the_next_start_reads_a_crash() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    let _ = ban(&svc, &r, 20, T0);
    drop(svc);
    let (_, report) = ActionService::start_with(
        enabled_or_panic("tfps:rest"),
        roomy(),
        &r.dir,
        r.tfps.clone(),
        JournalLimits::default(),
        T0 + 2,
        r.t0,
    )
    .expect("start");
    assert_eq!(report.previous_run, PreviousRun::Ended);
}

#[test]
fn the_first_start_has_no_previous_run() {
    let r = rig();
    let (_, report) = ActionService::start_with(
        enabled_or_panic("tfps:rest"),
        roomy(),
        &r.dir,
        r.tfps.clone(),
        JournalLimits::default(),
        T0,
        r.t0,
    )
    .expect("start");
    assert_eq!(report.previous_run, PreviousRun::None);
}

#[test]
fn a_stop_does_not_wait_for_an_action_in_flight_and_admits_no_new_one() {
    // Stop means stop: an action whose TFPS call is still running is not
    // waited for. Its intent stays in doubt and the next start resolves it.
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("journal");
    let tfps = Arc::new(FakeTfps {
        journal_dir: dir.clone(),
        ban_takes: Some(Duration::from_secs(2)),
        ..FakeTfps::default()
    });
    let t0 = Instant::now();
    let (svc, _) = ActionService::start_with(
        enabled_or_panic("tfps:rest"),
        roomy(),
        &dir,
        tfps.clone(),
        JournalLimits::default(),
        T0,
        t0,
    )
    .expect("start");
    let svc = Arc::new(svc);
    let in_flight = {
        let svc = svc.clone();
        std::thread::spawn(move || {
            let _ = svc.ban(ActionSurface::Rest, "token:ops", addr(20), None, T0, t0);
        })
    };
    while !tfps.ban_started.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(5));
    }
    let asked = Instant::now();
    let written = svc.stop(T0 + 1);
    assert!(
        asked.elapsed() < Duration::from_millis(500),
        "stop waited {:?} for the action in flight",
        asked.elapsed()
    );
    assert!(!written, "no stop record while an action is in flight");
    let err = svc
        .ban(ActionSurface::Rest, "token:ops", addr(21), None, T0 + 1, t0)
        .expect_err("stopping");
    assert!(matches!(err, ActionError::JournalUnusable(_)), "{err:?}");
    in_flight.join().expect("join");
}

#[test]
fn an_earlier_clean_stop_does_not_hide_a_later_crash() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    assert!(svc.stop(T0));
    drop(svc);
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0 + 1);
    let _ = ban(&svc, &r, 20, T0 + 1);
    drop(svc); // no stop: this run crashed
    let (_, report) = ActionService::start_with(
        enabled_or_panic("tfps:rest"),
        roomy(),
        &r.dir,
        r.tfps.clone(),
        JournalLimits::default(),
        T0 + 2,
        r.t0,
    )
    .expect("start");
    assert_eq!(report.previous_run, PreviousRun::Ended);
}

#[test]
fn an_unban_tfps_answers_not_blocked_ends_ownership_as_lapsed() {
    let r = rig();
    let svc = start_with(&r, enabled_or_panic("tfps:rest"), roomy(), T0);
    let _ = ban(&svc, &r, 20, T0);
    // TFPS dropped it, and nothing has checked since.
    r.tfps.banned.lock().unwrap().clear();
    let done = svc
        .unban(
            ActionSurface::Rest,
            "token:ops",
            addr(20),
            T0 + 5,
            r.t0 + Duration::from_secs(5),
        )
        .expect("unban");
    assert!(!done.applied);
    assert_eq!(done.refused.as_deref(), Some("not-blocked"));
    assert!(svc.owned(addr(20)).is_none(), "sipnab no longer holds it");
    assert!(kinds(&r).contains(&"lapsed_by_peer".to_string()));
}
