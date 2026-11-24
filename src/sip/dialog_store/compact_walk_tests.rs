// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Which dialogs an idle sweep asks "has this dialog been quiet past the idle
//! window?", and that the answer the sweep acts on is unchanged.
//!
//! A sweep visits every dialog. A dialog holding no more messages than
//! [`keep_messages_per_idle_dialog`] has nothing compaction could remove, so
//! the sweep must not spend the time arithmetic on it: that arithmetic was
//! most of [`compact_dialog`]'s cost in a profile of a SIP-only batch run.
//! [`IDLE_CHECKS`](super::IDLE_CHECKS) counts the questions asked on this
//! thread.
//!
//! Every fixture is synthetic: RFC 5737 documentation addresses and
//! `example.com` names. Each fixture dialog holds only `INVITE`s with distinct
//! CSeqs, so the only anchor is the first `INVITE` and compaction of an idle
//! dialog with `n > keep` messages removes exactly `n - keep`.

use super::{
    DialogStore, compact_dialog, idle_checks_on_this_thread, idle_compact_after,
    keep_messages_per_idle_dialog,
};
use crate::net::TransportProto;
use crate::sip::dialog::SipDialog;
use crate::sip::parser::parse_sip;
use crate::test_utils::build_sip_message as build_sip;
use chrono::{DateTime, TimeDelta, Utc};
use std::net::{IpAddr, Ipv4Addr};

type TestError = Box<dyn std::error::Error>;

/// The time every fixture message carries: 2024-06-15 12:00:00 UTC.
fn sent_at() -> Result<DateTime<Utc>, TestError> {
    Ok(
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0)
            .single()
            .ok_or("a valid UTC time")?,
    )
}

/// A sweep time far enough after [`sent_at`] that every fixture dialog is idle.
fn idle_sweep() -> Result<DateTime<Utc>, TestError> {
    Ok(sent_at()? + idle_compact_after() + TimeDelta::seconds(1))
}

/// A sweep time inside the idle window: every fixture dialog is active.
fn active_sweep() -> Result<DateTime<Utc>, TestError> {
    Ok(sent_at()? + TimeDelta::seconds(30))
}

/// One `INVITE` of `call_id` with CSeq `seq`, sent at [`sent_at`] from
/// 192.0.2.10 to 198.51.100.20.
fn invite(call_id: &str, seq: usize) -> Result<crate::sip::SipMessage, TestError> {
    let raw = build_sip(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            &format!("Call-ID: {call_id}"),
            &format!("CSeq: {seq} INVITE"),
            "Content-Length: 0",
        ],
        b"",
    );
    parse_sip(
        &raw,
        sent_at()?,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        5060,
        5060,
        TransportProto::Udp,
    )
    .map_err(|e| format!("the fixture INVITE should parse: {e:?}").into())
}

/// Feed `n` distinct `INVITE`s of `call_id` (at least one) into `store`.
fn add_dialog(store: &mut DialogStore, call_id: &str, n: usize) -> Result<(), TestError> {
    for seq in 1..=n.max(1) {
        store.process_message(invite(call_id, seq)?);
    }
    Ok(())
}

/// A store holding one dialog per entry of `lengths`, named `d0`, `d1`, ...
fn store_of(lengths: &[usize]) -> Result<DialogStore, TestError> {
    let mut store = DialogStore::new(1000, false);
    for (i, n) in lengths.iter().enumerate() {
        add_dialog(&mut store, &format!("d{i}@example.com"), *n)?;
    }
    Ok(store)
}

/// One dialog with `n` stored messages, taken out of its store; `n == 0`
/// gives a dialog whose message list is empty.
fn dialog_of(n: usize) -> Result<SipDialog, TestError> {
    let mut store = store_of(&[n])?;
    let mut dialog = store
        .dialogs
        .shift_remove("d0@example.com")
        .ok_or("the fixture dialog is in the store")?;
    assert_eq!(
        dialog.messages.len(),
        n.max(1),
        "the fixture holds the messages it was given"
    );
    if n == 0 {
        dialog.messages.clear();
    }
    Ok(dialog)
}

/// `compact_dialog(dialog, now)`, with how many idle questions it asked.
fn compact_counting(dialog: &mut SipDialog, now: DateTime<Utc>) -> (usize, usize) {
    let before = idle_checks_on_this_thread();
    let evicted = compact_dialog(dialog, now);
    (evicted, idle_checks_on_this_thread() - before)
}

/// The rule as it stood before the length was tested first: idle by the
/// time arithmetic, then over the keep limit. For these INVITE-only
/// fixtures an idle dialog over the limit loses exactly `n - keep`.
fn evicted_by_the_old_rule(n: usize, latest: DateTime<Utc>, now: DateTime<Utc>) -> usize {
    let keep = keep_messages_per_idle_dialog();
    if now - latest <= idle_compact_after() || n <= keep {
        0
    } else {
        n - keep
    }
}

// ── No question asked: nothing to remove ────────────────────────────

/// A short idle dialog is not asked: it has nothing compaction could remove.
#[test]
fn a_short_idle_dialog_is_not_asked_whether_it_is_idle() -> Result<(), TestError> {
    let mut dialog = dialog_of(3)?;
    let (evicted, asked) = compact_counting(&mut dialog, idle_sweep()?);
    assert_eq!(asked, 0, "a 3-message dialog was asked whether it is idle");
    assert_eq!(evicted, 0, "a 3-message dialog lost messages");
    assert_eq!(dialog.messages.len(), 3, "a 3-message dialog changed");
    Ok(())
}

/// A short active dialog is not asked either.
#[test]
fn a_short_active_dialog_is_not_asked_whether_it_is_idle() -> Result<(), TestError> {
    let mut dialog = dialog_of(3)?;
    let (evicted, asked) = compact_counting(&mut dialog, active_sweep()?);
    assert_eq!(
        asked, 0,
        "a 3-message active dialog was asked whether it is idle"
    );
    assert_eq!(evicted, 0, "a 3-message active dialog lost messages");
    Ok(())
}

/// A dialog holding exactly the keep limit is not asked and keeps everything.
#[test]
fn a_dialog_at_exactly_the_keep_limit_is_not_asked() -> Result<(), TestError> {
    let keep = keep_messages_per_idle_dialog();
    let mut dialog = dialog_of(keep)?;
    let (evicted, asked) = compact_counting(&mut dialog, idle_sweep()?);
    assert_eq!(asked, 0, "a dialog of exactly {keep} messages was asked");
    assert_eq!(
        evicted, 0,
        "a dialog of exactly {keep} messages lost messages"
    );
    assert_eq!(dialog.messages.len(), keep, "a dialog at the limit changed");
    Ok(())
}

/// A one-message dialog is not asked.
#[test]
fn a_one_message_dialog_is_not_asked() -> Result<(), TestError> {
    let mut dialog = dialog_of(1)?;
    let (evicted, asked) = compact_counting(&mut dialog, idle_sweep()?);
    assert_eq!(
        asked, 0,
        "a one-message dialog was asked whether it is idle"
    );
    assert_eq!(evicted, 0, "a one-message dialog lost its message");
    Ok(())
}

/// A dialog whose message list is empty is not asked and removes nothing.
#[test]
fn a_dialog_with_no_stored_messages_is_not_asked() -> Result<(), TestError> {
    let mut dialog = dialog_of(0)?;
    let (evicted, asked) = compact_counting(&mut dialog, idle_sweep()?);
    assert_eq!(asked, 0, "an empty dialog was asked whether it is idle");
    assert_eq!(evicted, 0, "an empty dialog reported evictions");
    Ok(())
}

/// A sweep over a store of short dialogs asks none of them.
#[test]
fn a_sweep_over_short_dialogs_asks_none_of_them() -> Result<(), TestError> {
    let mut store = store_of(&[2; 50])?;
    let before = idle_checks_on_this_thread();
    let stats = store.compact_idle(idle_sweep()?);
    let asked = idle_checks_on_this_thread() - before;
    assert_eq!(
        asked, 0,
        "a sweep over 50 two-message dialogs asked {asked}"
    );
    assert_eq!(stats.dialogs_compacted, 0, "{stats:?}");
    assert_eq!(stats.messages_evicted, 0, "{stats:?}");
    Ok(())
}

/// After compaction a dialog sits at the keep limit, so the next sweep does
/// not ask it again.
#[test]
fn a_compacted_dialog_is_not_asked_by_the_next_sweep() -> Result<(), TestError> {
    let keep = keep_messages_per_idle_dialog();
    let mut dialog = dialog_of(keep + 1)?;
    let (first, asked_first) = compact_counting(&mut dialog, idle_sweep()?);
    assert_eq!(
        (first, asked_first),
        (1, 1),
        "the first sweep compacts and asks once"
    );
    let (second, asked_second) = compact_counting(&mut dialog, idle_sweep()?);
    assert_eq!(
        asked_second, 0,
        "a dialog at the keep limit was asked again"
    );
    assert_eq!(second, 0, "a second sweep removed messages");
    Ok(())
}

// ── Asked: something to remove ──────────────────────────────────────

/// A sweep over a mixed store asks only the dialogs over the keep limit.
#[test]
fn a_sweep_asks_only_the_dialogs_over_the_keep_limit() -> Result<(), TestError> {
    let keep = keep_messages_per_idle_dialog();
    let mut store = store_of(&[2, keep + 3, 5, keep, keep + 1, 1, keep + 9, 4])?;
    let before = idle_checks_on_this_thread();
    let stats = store.compact_idle(idle_sweep()?);
    let asked = idle_checks_on_this_thread() - before;
    assert_eq!(
        asked, 3,
        "three dialogs are over the keep limit; {asked} were asked"
    );
    assert_eq!(stats.dialogs_compacted, 3, "{stats:?}");
    assert_eq!(stats.messages_evicted, 3 + 1 + 9, "{stats:?}");
    Ok(())
}

/// A dialog one message over the limit is asked once and loses one message.
#[test]
fn a_dialog_one_over_the_keep_limit_is_asked_and_compacted() -> Result<(), TestError> {
    let keep = keep_messages_per_idle_dialog();
    let mut dialog = dialog_of(keep + 1)?;
    let (evicted, asked) = compact_counting(&mut dialog, idle_sweep()?);
    assert_eq!(asked, 1, "a dialog over the limit was asked {asked} times");
    assert_eq!(evicted, 1, "one message over the limit is one eviction");
    assert_eq!(
        dialog.messages.len(),
        keep,
        "the dialog ends at the keep limit"
    );
    Ok(())
}

/// A long active dialog is asked, and keeps every message.
#[test]
fn a_long_active_dialog_is_asked_and_kept() -> Result<(), TestError> {
    let keep = keep_messages_per_idle_dialog();
    let mut dialog = dialog_of(keep + 5)?;
    let (evicted, asked) = compact_counting(&mut dialog, active_sweep()?);
    assert_eq!(asked, 1, "a long dialog was asked {asked} times");
    assert_eq!(evicted, 0, "an active dialog lost messages");
    assert_eq!(dialog.messages.len(), keep + 5, "an active dialog changed");
    Ok(())
}

/// A long dialog quiet exactly the idle window is not idle.
#[test]
fn a_long_dialog_quiet_exactly_the_idle_window_is_kept() -> Result<(), TestError> {
    let keep = keep_messages_per_idle_dialog();
    let mut dialog = dialog_of(keep + 5)?;
    let (evicted, asked) = compact_counting(&mut dialog, sent_at()? + idle_compact_after());
    assert_eq!(asked, 1, "a long dialog was asked {asked} times");
    assert_eq!(evicted, 0, "quiet exactly the idle window is not idle");
    Ok(())
}

/// A long dialog quiet one nanosecond past the idle window is compacted.
#[test]
fn a_long_dialog_one_nanosecond_past_the_idle_window_is_compacted() -> Result<(), TestError> {
    let keep = keep_messages_per_idle_dialog();
    let mut dialog = dialog_of(keep + 5)?;
    let now = sent_at()? + idle_compact_after() + TimeDelta::nanoseconds(1);
    let (evicted, asked) = compact_counting(&mut dialog, now);
    assert_eq!(asked, 1, "a long dialog was asked {asked} times");
    assert_eq!(evicted, 5, "one nanosecond past the window is idle");
    assert_eq!(
        dialog.messages.len(),
        keep,
        "the dialog ends at the keep limit"
    );
    Ok(())
}

// ── The answer is unchanged ─────────────────────────────────────────

/// Every length around the keep limit, at every sweep time around the idle
/// window (including a sweep before the messages were sent), removes what the
/// old rule removed.
#[test]
fn every_length_and_sweep_time_evicts_what_the_old_rule_evicted() -> Result<(), TestError> {
    let keep = keep_messages_per_idle_dialog();
    let window = idle_compact_after();
    let offsets = [
        -TimeDelta::seconds(1),
        TimeDelta::zero(),
        TimeDelta::seconds(30),
        window - TimeDelta::nanoseconds(1),
        window,
        window + TimeDelta::nanoseconds(1),
        window + TimeDelta::seconds(1),
        TimeDelta::days(365),
    ];
    let lengths = [0, 1, 2, keep - 1, keep, keep + 1, keep + 2, keep + 7];
    for n in lengths {
        for offset in offsets {
            let mut dialog = dialog_of(n)?;
            let latest = dialog.latest_message_at;
            let now = latest + offset;
            let expected = evicted_by_the_old_rule(dialog.messages.len(), latest, now);
            let (evicted, _) = compact_counting(&mut dialog, now);
            assert_eq!(
                evicted, expected,
                "{n} messages, sweep {offset:?} after the newest: evicted {evicted}, the old rule evicted {expected}"
            );
            assert_eq!(
                dialog.messages.len(),
                n - expected,
                "{n} messages, sweep {offset:?} after the newest: wrong length left"
            );
        }
    }
    Ok(())
}
