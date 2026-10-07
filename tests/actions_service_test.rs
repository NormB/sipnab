// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every action goes through one service, in one order, journaled
//! (JOURNAL + ACTIONS-HARDEN; approved spec 2026-09-28).
//!
//! Written before the behavior exists. The order the spec fixes:
//!
//! 1. the policy enables this target on this surface;
//! 2. the address and the lifetime are allowed;
//! 3. the rate limits admit it;
//! 4. the intent is written and synced to the journal;
//! 5. only then is TFPS asked;
//! 6. the outcome is journaled and the ledger updated.
//!
//! TFPS is a fake that records each call and, at the moment it is called,
//! reads the journal from disk: that is how step 4 before step 5 is proven
//! rather than assumed.

#![cfg(all(unix, feature = "full"))]

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipnab::security::actions::{
    ActionError, ActionLimits, ActionPolicy, ActionService, ActionSurface, BanRule,
};

#[path = "support/fake_tfps.rs"]
mod fake_tfps;

use fake_tfps::{FakeTfps, T0, TestError, addr, enabled};

struct Rig {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    tfps: Arc<FakeTfps>,
    t0: Instant,
}

fn rig() -> Result<Rig, TestError> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("journal");
    let tfps = FakeTfps::new(&dir);
    Ok(Rig {
        _tmp: tmp,
        dir,
        tfps,
        t0: Instant::now(),
    })
}

fn start(r: &Rig, policy: ActionPolicy) -> Result<ActionService, TestError> {
    Ok(ActionService::start(
        policy,
        ActionLimits::default(),
        &r.dir,
        r.tfps.clone(),
        T0,
        r.t0,
    )?
    .0)
}

// ── the order ────────────────────────────────────────────────────────────

#[test]
fn not_enabled_refuses_before_anything_and_journals_the_refusal() -> Result<(), TestError> {
    let r = rig()?;
    let svc = start(&r, ActionPolicy::default())?;
    let err = svc
        .ban(ActionSurface::Rest, "token:ops", addr(20), None, T0, r.t0)
        .err()
        .ok_or("expected an error: not enabled")?;
    assert!(matches!(err, ActionError::NotEnabled(_)), "{err:?}");
    assert!(r.tfps.calls()?.is_empty());
    assert!(r.tfps.journal_text().contains("\"action_refused\""));
    Ok(())
}

#[test]
fn an_enabled_ban_is_journaled_before_tfps_is_asked() -> Result<(), TestError> {
    let r = rig()?;
    let svc = start(&r, enabled("tfps:rest")?)?;
    let done = svc.ban(
        ActionSurface::Rest,
        "token:ops",
        addr(20),
        Some(600),
        T0,
        r.t0,
    )?;
    assert_eq!(r.tfps.calls()?, ["ban 198.51.100.20 600"]);
    assert_eq!(
        *r.tfps
            .intent_on_disk_when_called
            .lock()
            .map_err(|e| e.to_string())?,
        [true],
        "the intent must be on disk when TFPS is asked"
    );
    let journal = r.tfps.journal_text();
    let intent = journal.find("\"action_intent\"").ok_or("intent")?;
    let outcome = journal.find("\"action_outcome\"").ok_or("outcome")?;
    assert!(intent < outcome);
    assert!(journal.contains(&format!("\"id\":\"{}\"", done.id)));
    assert_eq!(svc.owned(addr(20)).map(|o| o.id), Some(done.id));
    Ok(())
}

#[test]
fn an_address_that_is_never_banned_is_refused_before_tfps() -> Result<(), TestError> {
    let r = rig()?;
    let svc = start(&r, enabled("tfps:rest")?)?;
    let err = svc
        .ban(
            ActionSurface::Rest,
            "token:ops",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
            T0,
            r.t0,
        )
        .err()
        .ok_or("expected an error: loopback")?;
    assert_eq!(err, ActionError::Rule(BanRule::Loopback));
    assert!(r.tfps.calls()?.is_empty());
    Ok(())
}

#[test]
fn a_ban_that_would_never_expire_is_refused_before_tfps() -> Result<(), TestError> {
    let r = rig()?;
    let svc = start(&r, enabled("tfps:rest")?)?;
    let err = svc
        .ban(
            ActionSurface::Rest,
            "token:ops",
            addr(20),
            Some(0),
            T0,
            r.t0,
        )
        .err()
        .ok_or("expected an error: forever")?;
    assert_eq!(err, ActionError::Rule(BanRule::Forever));
    assert!(r.tfps.calls()?.is_empty());
    Ok(())
}

#[test]
fn a_flood_reaches_tfps_only_as_often_as_the_limits_allow() -> Result<(), TestError> {
    let r = rig()?;
    let svc = start(&r, enabled("tfps:rest")?)?;
    let mut throttled = 0;
    for i in 0..50u8 {
        if let Err(ActionError::Throttled(_)) =
            svc.ban(ActionSurface::Rest, "token:stolen", addr(i), None, T0, r.t0)
        {
            throttled += 1;
        }
    }
    assert_eq!(r.tfps.calls()?.len(), 5, "the per-caller limit");
    assert_eq!(throttled, 45);
    Ok(())
}

// ── ownership ────────────────────────────────────────────────────────────

#[test]
fn an_address_sipnab_did_not_ban_cannot_be_unbanned_through_it() -> Result<(), TestError> {
    let r = rig()?;
    r.tfps
        .banned
        .lock()
        .map_err(|e| e.to_string())?
        .push((Ipv4Addr::new(198, 51, 100, 99), None));
    let svc = start(&r, enabled("tfps:rest")?)?;
    let err = svc
        .unban(ActionSurface::Rest, "token:stolen", addr(99), T0, r.t0)
        .err()
        .ok_or("expected an error: not ours")?;
    assert_eq!(err, ActionError::NotOwned);
    assert!(r.tfps.calls()?.is_empty(), "TFPS's own ban is untouched");
    Ok(())
}

#[test]
fn an_owned_ban_can_be_unbanned_and_ownership_ends() -> Result<(), TestError> {
    let r = rig()?;
    let svc = start(&r, enabled("tfps:rest")?)?;
    svc.ban(ActionSurface::Rest, "token:ops", addr(20), None, T0, r.t0)?;
    svc.unban(
        ActionSurface::Rest,
        "token:ops",
        addr(20),
        T0 + 61,
        r.t0 + Duration::from_secs(61),
    )?;
    assert!(svc.owned(addr(20)).is_none());
    assert_eq!(
        r.tfps.calls()?,
        ["ban 198.51.100.20 3600", "unban 198.51.100.20"]
    );
    Ok(())
}

// ── across a restart ─────────────────────────────────────────────────────

#[test]
fn ownership_and_limits_survive_a_restart() -> Result<(), TestError> {
    let r = rig()?;
    {
        let svc = start(&r, enabled("tfps:rest")?)?;
        for i in 0..5u8 {
            svc.ban(ActionSurface::Rest, "token:stolen", addr(i), None, T0, r.t0)?;
        }
    }
    let svc = start(&r, enabled("tfps:rest")?)?;
    assert!(
        svc.owned(addr(3)).is_some(),
        "ownership came back from the journal"
    );
    let err = svc
        .ban(
            ActionSurface::Rest,
            "token:stolen",
            addr(9),
            None,
            T0 + 5,
            r.t0 + Duration::from_secs(5),
        )
        .err()
        .ok_or(concat!(
            "expected an error: ",
            "the caller's minute is still spent after the restart"
        ))?;
    assert!(matches!(err, ActionError::Throttled(_)), "{err:?}");
    Ok(())
}

#[test]
fn an_action_in_doubt_after_a_crash_is_resolved_against_tfps_at_start() -> Result<(), TestError> {
    let r = rig()?;
    {
        // A crash between the intent and the outcome: write the intent the
        // way the service does, then stop before asking TFPS.
        let (mut j, _) = sipnab::journal::Journal::open(&r.dir, "crashed-run")?;
        j.append(
            "action_intent",
            serde_json::json!({"id": "a-crash", "target": "tfps", "verb": "ban",
                "address": "198.51.100.20", "at": T0, "ttl_secs": 3600,
                "expires": T0 + 3600, "surface": "rest", "caller": "token:ops"}),
        )?;
    }
    // TFPS did place it before the crash.
    r.tfps
        .banned
        .lock()
        .map_err(|e| e.to_string())?
        .push((Ipv4Addr::new(198, 51, 100, 20), Some(T0 + 3600)));
    let (svc, report) = ActionService::start(
        enabled("tfps:rest")?,
        ActionLimits::default(),
        &r.dir,
        r.tfps.clone(),
        T0 + 30,
        r.t0,
    )?;
    assert_eq!(report.reconciled, 1);
    assert_eq!(
        svc.owned(addr(20)).map(|o| o.id),
        Some("a-crash".to_string())
    );
    assert!(r.tfps.journal_text().contains("\"reconciled\""));
    Ok(())
}

#[test]
fn with_tfps_unreachable_at_start_actions_stay_refused_until_it_answers() -> Result<(), TestError> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("journal");
    {
        let (mut j, _) = sipnab::journal::Journal::open(&dir, "crashed-run")?;
        j.append(
            "action_intent",
            serde_json::json!({"id": "a-crash", "target": "tfps", "verb": "ban",
                "address": "198.51.100.20", "at": T0, "ttl_secs": 3600,
                "expires": T0 + 3600, "surface": "rest", "caller": "token:ops"}),
        )?;
    }
    let tfps = Arc::new(FakeTfps {
        journal_dir: dir.clone(),
        unreachable: true,
        ..FakeTfps::default()
    });
    let t0 = Instant::now();
    let (svc, report) = ActionService::start(
        enabled("tfps:rest")?,
        ActionLimits::default(),
        &dir,
        tfps.clone(),
        T0 + 30,
        t0,
    )?;
    assert_eq!(report.still_in_doubt, 1);
    let err = svc
        .ban(
            ActionSurface::Rest,
            "token:ops",
            addr(21),
            None,
            T0 + 31,
            t0,
        )
        .err()
        .ok_or("expected an error: in doubt")?;
    assert_eq!(err, ActionError::InDoubt(1));
    assert!(tfps.calls()?.is_empty());
    Ok(())
}

// ── the journal itself ───────────────────────────────────────────────────

#[test]
fn a_damaged_journal_turns_actions_off_and_says_why() -> Result<(), TestError> {
    let r = rig()?;
    {
        let svc = start(&r, enabled("tfps:rest")?)?;
        svc.ban(ActionSurface::Rest, "token:ops", addr(20), None, T0, r.t0)?;
        svc.ban(ActionSurface::Rest, "token:ops", addr(21), None, T0, r.t0)?;
    }
    let seg = r.dir.join("journal-000001.jsonl");
    let text = std::fs::read_to_string(&seg)?;
    std::fs::write(&seg, text.replacen("198.51.100.20", "198.51.100.66", 1))?;
    let (svc, report) = ActionService::start(
        enabled("tfps:rest")?,
        ActionLimits::default(),
        &r.dir,
        r.tfps.clone(),
        T0 + 100,
        r.t0,
    )?;
    assert!(
        report.disabled.is_some(),
        "the report says why actions are off"
    );
    let err = svc
        .ban(
            ActionSurface::Rest,
            "token:ops",
            addr(30),
            None,
            T0 + 100,
            r.t0,
        )
        .err()
        .ok_or("expected an error: actions off")?;
    match err {
        ActionError::JournalUnusable(why) => assert!(
            why.contains("damaged") && why.contains("record"),
            "the refusal names the damage and where it is: {why}"
        ),
        other => return Err(format!("expected JournalUnusable, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn a_second_sipnab_on_the_same_journal_is_refused_at_start() -> Result<(), TestError> {
    let r = rig()?;
    let _first = start(&r, enabled("tfps:rest")?)?;
    let second = ActionService::start(
        enabled("tfps:rest")?,
        ActionLimits::default(),
        &r.dir,
        r.tfps.clone(),
        T0,
        r.t0,
    );
    assert!(matches!(second, Err(ActionError::JournalUnusable(_))));
    Ok(())
}
