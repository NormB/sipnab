// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a restarted sipnab knows from its journal, and how it resolves an
//! action left in doubt (JOURNAL, approved spec 2026-09-28).
//!
//! Written before the behavior exists. The ledger is rebuilt from journal
//! records alone, so every rule here is a pure function over records and what
//! TFPS reports; nothing needs TFPS, a kernel or a clock.

#![cfg(all(unix, feature = "full"))]

use serde_json::json;
use sipnab::journal::Record;
use sipnab::journal::ledger::{Ledger, Resolution, TfpsView};

const T0: u64 = 1_790_600_000;

fn rec(seq: u64, kind: &str, body: serde_json::Value) -> Record {
    Record {
        seq,
        ts: String::new(),
        run: "run-1".to_string(),
        kind: kind.to_string(),
        body,
    }
}

fn ban_intent(seq: u64, id: &str, address: &str, at: u64, ttl: u64) -> Record {
    rec(
        seq,
        "action_intent",
        json!({"id": id, "target": "tfps", "verb": "ban", "address": address,
               "at": at, "ttl_secs": ttl, "expires": at + ttl,
               "surface": "rest", "caller": "token:ops"}),
    )
}

fn unban_intent(seq: u64, id: &str, address: &str, at: u64) -> Record {
    rec(
        seq,
        "action_intent",
        json!({"id": id, "target": "tfps", "verb": "unban", "address": address,
               "at": at, "surface": "rest", "caller": "token:ops"}),
    )
}

fn outcome(seq: u64, id: &str, result: &str) -> Record {
    rec(seq, "action_outcome", json!({"id": id, "result": result}))
}

// ── what is owned ────────────────────────────────────────────────────────

#[test]
fn an_applied_ban_is_owned_until_it_expires() {
    let l = Ledger::from_records(
        &[
            ban_intent(1, "a-1", "198.51.100.20", T0, 3600),
            outcome(2, "a-1", "applied"),
        ],
        T0 + 10,
    );
    let owned = l.owned("198.51.100.20").expect("owned");
    assert_eq!(owned.id, "a-1");
    assert_eq!(owned.expires, T0 + 3600);
    let later = Ledger::from_records(
        &[
            ban_intent(1, "a-1", "198.51.100.20", T0, 3600),
            outcome(2, "a-1", "applied"),
        ],
        T0 + 3600,
    );
    assert!(
        later.owned("198.51.100.20").is_none(),
        "expired, so no longer in force"
    );
}

#[test]
fn a_refused_or_failed_ban_is_not_owned() {
    for result in ["refused", "failed"] {
        let l = Ledger::from_records(
            &[
                ban_intent(1, "a-1", "198.51.100.20", T0, 3600),
                outcome(2, "a-1", result),
            ],
            T0 + 10,
        );
        assert!(l.owned("198.51.100.20").is_none(), "{result}");
    }
}

#[test]
fn an_applied_unban_ends_ownership() {
    let l = Ledger::from_records(
        &[
            ban_intent(1, "a-1", "198.51.100.20", T0, 3600),
            outcome(2, "a-1", "applied"),
            unban_intent(3, "a-2", "198.51.100.20", T0 + 60),
            outcome(4, "a-2", "applied"),
        ],
        T0 + 70,
    );
    assert!(l.owned("198.51.100.20").is_none());
}

#[test]
fn a_ban_tfps_dropped_early_is_no_longer_owned() {
    let l = Ledger::from_records(
        &[
            ban_intent(1, "a-1", "198.51.100.20", T0, 3600),
            outcome(2, "a-1", "applied"),
            rec(
                3,
                "lapsed_by_peer",
                json!({"id": "a-1", "address": "198.51.100.20"}),
            ),
        ],
        T0 + 70,
    );
    assert!(l.owned("198.51.100.20").is_none());
}

#[test]
fn owned_bans_are_listed_newest_first_for_revert_all() {
    let l = Ledger::from_records(
        &[
            ban_intent(1, "a-1", "198.51.100.20", T0, 3600),
            outcome(2, "a-1", "applied"),
            ban_intent(3, "a-2", "198.51.100.21", T0 + 5, 3600),
            outcome(4, "a-2", "applied"),
        ],
        T0 + 10,
    );
    let ids: Vec<&str> = l
        .owned_newest_first()
        .iter()
        .map(|o| o.id.as_str())
        .collect();
    assert_eq!(ids, ["a-2", "a-1"]);
}

// ── what is in doubt ─────────────────────────────────────────────────────

#[test]
fn an_intent_with_no_outcome_is_in_doubt() {
    let l = Ledger::from_records(&[ban_intent(1, "a-1", "198.51.100.20", T0, 3600)], T0 + 10);
    let doubt = l.in_doubt();
    assert_eq!(doubt.len(), 1);
    assert_eq!(doubt[0].id, "a-1");
    assert!(
        l.owned("198.51.100.20").is_none(),
        "not owned until resolved"
    );
}

#[test]
fn a_reconciled_intent_is_no_longer_in_doubt() {
    let l = Ledger::from_records(
        &[
            ban_intent(1, "a-1", "198.51.100.20", T0, 3600),
            rec(
                2,
                "reconciled",
                json!({"id": "a-1", "resolution": "applied"}),
            ),
        ],
        T0 + 10,
    );
    assert!(l.in_doubt().is_empty());
    assert!(
        l.owned("198.51.100.20").is_some(),
        "reconciled as applied: owned"
    );
}

#[test]
fn an_unknown_resolution_is_listed_and_never_owned() {
    let l = Ledger::from_records(
        &[
            ban_intent(1, "a-1", "198.51.100.20", T0, 3600),
            rec(
                2,
                "reconciled",
                json!({"id": "a-1", "resolution": "unknown"}),
            ),
        ],
        T0 + 10,
    );
    assert!(l.owned("198.51.100.20").is_none());
    assert_eq!(l.unknown().len(), 1);
}

// ── resolving an action left in doubt (the spec's table) ─────────────────

fn intent_of(r: &Record) -> sipnab::journal::ledger::Intent {
    Ledger::from_records(std::slice::from_ref(r), T0 + 1).in_doubt()[0].clone()
}

#[test]
fn every_row_of_the_in_doubt_table() {
    let ban = intent_of(&ban_intent(1, "a-1", "198.51.100.20", T0, 3600));
    let unban = intent_of(&unban_intent(1, "a-2", "198.51.100.20", T0));
    let banned = |expires: Option<u64>| TfpsView::Banned { expires };
    assert_eq!(ban.resolve(TfpsView::Absent), Some(Resolution::NotApplied));
    assert_eq!(
        ban.resolve(banned(Some(T0 + 3600))),
        Some(Resolution::Applied)
    );
    assert_eq!(
        ban.resolve(banned(Some(T0 + 3604))),
        Some(Resolution::Applied),
        "within 5 s"
    );
    assert_eq!(
        ban.resolve(banned(Some(T0 + 3606))),
        Some(Resolution::Unknown),
        "beyond 5 s"
    );
    assert_eq!(
        ban.resolve(banned(None)),
        Some(Resolution::Unknown),
        "TFPS says forever"
    );
    assert_eq!(unban.resolve(TfpsView::Absent), Some(Resolution::Applied));
    assert_eq!(
        unban.resolve(banned(Some(T0 + 99))),
        Some(Resolution::NotApplied)
    );
    assert_eq!(ban.resolve(TfpsView::Unreachable), None, "stays in doubt");
    assert_eq!(unban.resolve(TfpsView::Unreachable), None, "stays in doubt");
}

// ── limits rebuilt after a restart ───────────────────────────────────────

#[test]
fn the_last_minute_of_actions_is_available_to_rebuild_the_limits() {
    let l = Ledger::from_records(
        &[
            ban_intent(1, "a-1", "198.51.100.20", T0, 3600),
            outcome(2, "a-1", "applied"),
            ban_intent(3, "a-2", "198.51.100.21", T0 + 50, 3600),
            outcome(4, "a-2", "applied"),
        ],
        T0 + 70,
    );
    let recent = l.recent_actions(T0 + 70, 60);
    assert_eq!(recent.len(), 1, "only the action inside the last 60 s");
    assert_eq!(recent[0].address, "198.51.100.21");
    assert_eq!(recent[0].caller, "token:ops");
    assert_eq!(recent[0].at, T0 + 50);
}

#[test]
fn refused_actions_count_for_nothing_when_rebuilding_limits() {
    let l = Ledger::from_records(
        &[rec(
            1,
            "action_refused",
            json!({"caller": "token:x", "address": "198.51.100.9", "reason": "rate", "at": T0}),
        )],
        T0 + 1,
    );
    assert!(l.recent_actions(T0 + 1, 60).is_empty());
}

// ── checkpoints ──────────────────────────────────────────────────────────

#[test]
fn a_checkpoint_carries_owned_bans_forward_and_round_trips() {
    let before = Ledger::from_records(
        &[
            ban_intent(1, "a-1", "198.51.100.20", T0, 3600),
            outcome(2, "a-1", "applied"),
        ],
        T0 + 10,
    );
    let state = before.checkpoint_state();
    let after = Ledger::from_records(&[rec(9, "checkpoint", json!({"state": state}))], T0 + 20);
    let owned = after
        .owned("198.51.100.20")
        .expect("carried by the checkpoint");
    assert_eq!(owned.id, "a-1");
    assert_eq!(owned.expires, T0 + 3600);
}

#[test]
fn a_checkpoint_carries_actions_still_in_doubt() {
    let before = Ledger::from_records(&[ban_intent(1, "a-1", "198.51.100.20", T0, 3600)], T0 + 1);
    let state = before.checkpoint_state();
    let after = Ledger::from_records(&[rec(9, "checkpoint", json!({"state": state}))], T0 + 2);
    assert_eq!(after.in_doubt().len(), 1);
}

#[test]
fn records_after_a_checkpoint_apply_on_top_of_it() {
    let before = Ledger::from_records(
        &[
            ban_intent(1, "a-1", "198.51.100.20", T0, 3600),
            outcome(2, "a-1", "applied"),
        ],
        T0 + 10,
    );
    let after = Ledger::from_records(
        &[
            rec(9, "checkpoint", json!({"state": before.checkpoint_state()})),
            unban_intent(10, "a-2", "198.51.100.20", T0 + 60),
            outcome(11, "a-2", "applied"),
        ],
        T0 + 70,
    );
    assert!(after.owned("198.51.100.20").is_none());
}

#[test]
fn an_unrecognized_record_kind_is_ignored_not_fatal() {
    let l = Ledger::from_records(&[rec(1, "run_start", json!({"version": "0.5.196"}))], T0);
    assert!(l.in_doubt().is_empty());
}

#[test]
fn a_checkpoint_never_carries_a_ban_that_has_expired() {
    // The purge on reading the clock: an expired ban must not travel forward
    // in a checkpoint and be read back as state.
    let l = Ledger::from_records(
        &[
            ban_intent(1, "a-1", "198.51.100.20", T0, 60),
            outcome(2, "a-1", "applied"),
        ],
        T0 + 120,
    );
    let state = l.checkpoint_state();
    assert_eq!(
        state["owned"],
        json!({}),
        "an expired ban must not be carried forward as owned: {state}"
    );
}

#[test]
fn a_ban_already_expired_when_its_record_arrives_is_not_owned() {
    // Applied at runtime, after the ledger's clock was set: the answer must
    // still respect expiry, whatever order records and the clock arrive in.
    let mut l = Ledger::from_records(&[], T0 + 7200);
    l.apply(&ban_intent(1, "a-1", "198.51.100.20", T0, 60));
    l.apply(&outcome(2, "a-1", "applied"));
    assert!(l.owned("198.51.100.20").is_none());
    assert!(l.owned_newest_first().is_empty());
}

#[test]
fn tfps_dropping_an_old_ban_does_not_end_a_newer_one_on_the_same_address() {
    let l = Ledger::from_records(
        &[
            ban_intent(1, "a-1", "198.51.100.20", T0, 3600),
            outcome(2, "a-1", "applied"),
            unban_intent(3, "a-2", "198.51.100.20", T0 + 10),
            outcome(4, "a-2", "applied"),
            ban_intent(5, "a-3", "198.51.100.20", T0 + 20, 3600),
            outcome(6, "a-3", "applied"),
            rec(
                7,
                "lapsed_by_peer",
                json!({"id": "a-1", "address": "198.51.100.20"}),
            ),
        ],
        T0 + 30,
    );
    assert_eq!(l.owned("198.51.100.20").map(|o| o.id.as_str()), Some("a-3"));
}
