// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! What a finished batch run does with its dialog and stream stores.
//!
//! Freeing the dialog store at the end of a batch run cost 91,177,493
//! instructions of 4,821,571,309 (1.89%) in a callgrind profile of a SIP-only
//! capture: one reference-count decrement and one free per retained message
//! part, for memory the operating system takes back a moment later when the
//! process exits. [`run`](super::run) therefore hands the stores back as
//! [`RunStores`] instead of dropping them, and the binary passes them to
//! [`RunStores::release_run_and_exit`], which keeps them in a process-wide
//! [`ExitHold`] and exits.
//!
//! Two properties are tested here:
//! - a held value stays alive and reachable (so Valgrind's memcheck counts it
//!   as "still reachable", which its verdict passes, never as "lost");
//! - a [`RunStores`] that is NOT handed to the exit path frees both stores when
//!   it is dropped, so a caller that keeps running after a run leaks nothing.
//!
//! The wire from `main` to [`RunStores::release_run_and_exit`] ends the
//! process, so no test can call it in-process. The source tests at the end pin
//! that the process-wide hold is reached only from that function, and that the
//! function never returns.
//!
//! Every fixture is synthetic: RFC 5737 documentation addresses and
//! `example.com` names.

use super::{ExitHold, RunStores};
use crate::net::TransportProto;
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;
use crate::sip::parser::parse_sip;
use crate::test_utils::build_sip_message as build_sip;
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

type TestError = Box<dyn std::error::Error>;

/// Counts how many times a value of this type was dropped.
struct DropCount(Arc<AtomicUsize>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A counter and a value that bumps it once when dropped.
fn counted() -> (Arc<AtomicUsize>, DropCount) {
    let count = Arc::new(AtomicUsize::new(0));
    let value = DropCount(Arc::clone(&count));
    (count, value)
}

/// One `INVITE` with Call-ID `call_id`, from 192.0.2.10 to 198.51.100.20.
fn invite(call_id: &str) -> Result<crate::sip::SipMessage, TestError> {
    let raw = build_sip(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            &format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    let at = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0)
        .single()
        .ok_or("a valid UTC time")?;
    parse_sip(
        &raw,
        at,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        5060,
        5060,
        TransportProto::Udp,
    )
    .map_err(|e| format!("the fixture INVITE should parse: {e:?}").into())
}

/// A weak handle to a run's dialog store.
type WeakDialogs = Weak<RwLock<DialogStore>>;
/// A weak handle to a run's stream store.
type WeakStreams = Weak<RwLock<StreamStore>>;

/// Stores of a run that saw `dialogs` calls, with weak handles to both.
fn stores_with(dialogs: usize) -> Result<(RunStores, WeakDialogs, WeakStreams), TestError> {
    let mut store = DialogStore::new(1000, false);
    for i in 0..dialogs {
        store.process_message(invite(&format!("c{i}@example.com"))?);
    }
    let dialogs = Arc::new(RwLock::new(store));
    let streams = Arc::new(RwLock::new(StreamStore::new(16)));
    let (wd, ws) = (Arc::downgrade(&dialogs), Arc::downgrade(&streams));
    Ok((RunStores::new(dialogs, streams), wd, ws))
}

// --- success: a held value stays alive -------------------------------------

#[test]
fn a_held_value_is_not_dropped() {
    let hold = ExitHold::new();
    let (count, value) = counted();
    hold.hold(value);
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "a value handed to the hold must not be dropped"
    );
}

#[test]
fn the_hold_counts_each_value_it_keeps() {
    let hold = ExitHold::new();
    for _ in 0..3 {
        hold.hold(counted().1);
    }
    assert_eq!(hold.len(), 3, "three values handed over, three kept");
}

#[test]
fn held_run_stores_keep_the_dialog_store_and_its_dialogs() -> Result<(), TestError> {
    let hold = ExitHold::new();
    let (stores, dialogs, _) = stores_with(4)?;
    hold.hold(stores);
    let kept = dialogs
        .upgrade()
        .ok_or("the held dialog store must still be alive")?;
    assert_eq!(
        kept.read().len(),
        4,
        "the held store still holds its 4 dialogs"
    );
    Ok(())
}

#[test]
fn held_run_stores_keep_the_stream_store() -> Result<(), TestError> {
    let hold = ExitHold::new();
    let (stores, _, streams) = stores_with(1)?;
    hold.hold(stores);
    assert!(
        streams.upgrade().is_some(),
        "the held stream store must still be alive"
    );
    Ok(())
}

#[test]
fn run_stores_hold_exactly_the_stores_they_were_given() {
    let dialogs = Arc::new(RwLock::new(DialogStore::new(16, false)));
    let streams = Arc::new(RwLock::new(StreamStore::new(16)));
    let stores = RunStores::new(Arc::clone(&dialogs), Arc::clone(&streams));
    assert!(
        Arc::ptr_eq(&stores.dialogs, &dialogs),
        "RunStores must carry the run's own dialog store, not a copy"
    );
    assert!(
        Arc::ptr_eq(&stores.streams, &streams),
        "RunStores must carry the run's own stream store, not a copy"
    );
}

#[test]
fn values_held_from_another_thread_are_kept() {
    let hold = ExitHold::new();
    let (count, value) = counted();
    std::thread::scope(|s| {
        s.spawn(|| hold.hold(value));
    });
    assert_eq!(
        hold.len(),
        1,
        "the value handed over on another thread is kept"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "the value handed over on another thread is not dropped"
    );
}

#[test]
fn dropping_a_hold_frees_every_value_once() {
    let count = Arc::new(AtomicUsize::new(0));
    {
        let hold = ExitHold::new();
        for _ in 0..3 {
            hold.hold(DropCount(Arc::clone(&count)));
        }
    }
    assert_eq!(
        count.load(Ordering::SeqCst),
        3,
        "a hold owns its values: dropping it drops each exactly once"
    );
}

#[test]
fn the_exit_path_keeps_both_stores_of_a_batch_run() -> Result<(), TestError> {
    let hold = ExitHold::new();
    let (stores, dialogs, streams) = stores_with(2)?;
    RunStores::keep(Some(stores), &hold);
    assert_eq!(
        hold.len(),
        1,
        "the run's stores are handed over as one value"
    );
    assert!(
        dialogs.upgrade().is_some() && streams.upgrade().is_some(),
        "both stores stay alive in the hold"
    );
    Ok(())
}

// --- failure: what is not handed to the exit path is freed -----------------

#[test]
fn dropped_run_stores_free_the_dialog_store() -> Result<(), TestError> {
    let (stores, dialogs, _) = stores_with(3)?;
    drop(stores);
    assert!(
        dialogs.upgrade().is_none(),
        "a run that keeps going must not keep its dialog store alive"
    );
    Ok(())
}

#[test]
fn dropped_run_stores_free_the_stream_store() -> Result<(), TestError> {
    let (stores, _, streams) = stores_with(3)?;
    drop(stores);
    assert!(
        streams.upgrade().is_none(),
        "a run that keeps going must not keep its stream store alive"
    );
    Ok(())
}

#[test]
fn a_value_not_handed_over_is_dropped() {
    let hold = ExitHold::new();
    let (count, value) = counted();
    drop(value);
    assert_eq!(count.load(Ordering::SeqCst), 1, "the counter sees a drop");
    assert_eq!(hold.len(), 0, "nothing was handed to the hold");
}

#[test]
fn run_stores_add_no_reference_of_their_own() {
    let dialogs = Arc::new(RwLock::new(DialogStore::new(16, false)));
    let streams = Arc::new(RwLock::new(StreamStore::new(16)));
    let stores = RunStores::new(Arc::clone(&dialogs), Arc::clone(&streams));
    assert_eq!(
        Arc::strong_count(&dialogs),
        2,
        "RunStores holds one reference to the dialog store, no more"
    );
    drop(stores);
    assert_eq!(
        Arc::strong_count(&dialogs),
        1,
        "dropping RunStores gives its dialog-store reference back"
    );
    assert_eq!(
        Arc::strong_count(&streams),
        1,
        "dropping RunStores gives its stream-store reference back"
    );
}

#[test]
fn holding_one_run_does_not_keep_another() -> Result<(), TestError> {
    let hold = ExitHold::new();
    let (kept, kept_dialogs, _) = stores_with(1)?;
    let (dropped, dropped_dialogs, _) = stores_with(1)?;
    hold.hold(kept);
    drop(dropped);
    assert!(
        kept_dialogs.upgrade().is_some(),
        "the held run's dialog store stays alive"
    );
    assert!(
        dropped_dialogs.upgrade().is_none(),
        "the other run's dialog store is freed"
    );
    Ok(())
}

#[test]
fn a_shared_store_outlives_dropped_run_stores_only_through_its_other_owner() -> Result<(), TestError>
{
    let (stores, dialogs, _) = stores_with(2)?;
    // A companion server's clone of the same store.
    let server = dialogs.upgrade().ok_or("the store is alive")?;
    drop(stores);
    assert_eq!(
        server.read().len(),
        2,
        "the server's clone still reads the store"
    );
    drop(server);
    assert!(
        dialogs.upgrade().is_none(),
        "with the server's clone gone the store is freed"
    );
    Ok(())
}

// --- edge -----------------------------------------------------------------

#[test]
fn the_exit_path_after_a_run_without_stores_keeps_nothing() {
    let hold = ExitHold::new();
    RunStores::keep(None, &hold);
    assert_eq!(
        hold.len(),
        0,
        "a run with no stores (the TUI) hands nothing over"
    );
}

#[test]
fn a_new_hold_is_empty() {
    assert_eq!(ExitHold::new().len(), 0, "a new hold keeps nothing");
}

#[test]
fn a_hold_can_be_a_static() {
    static HOLD: ExitHold = ExitHold::new();
    let before = HOLD.len();
    HOLD.hold(0_u8);
    assert_eq!(
        HOLD.len(),
        before + 1,
        "a static hold keeps what it is given"
    );
}

#[test]
fn empty_run_stores_are_held_and_freed_like_full_ones() -> Result<(), TestError> {
    let hold = ExitHold::new();
    let (held, held_dialogs, _) = stores_with(0)?;
    let (dropped, dropped_dialogs, _) = stores_with(0)?;
    hold.hold(held);
    drop(dropped);
    assert!(
        held_dialogs.upgrade().is_some(),
        "an empty held store stays alive"
    );
    assert!(
        dropped_dialogs.upgrade().is_none(),
        "an empty dropped store is freed"
    );
    Ok(())
}

#[test]
fn a_zero_sized_value_is_counted() {
    let hold = ExitHold::new();
    hold.hold(());
    assert_eq!(
        hold.len(),
        1,
        "a zero-sized value still counts as one held value"
    );
}

#[test]
fn ten_thousand_values_are_all_kept() {
    let hold = ExitHold::new();
    let count = Arc::new(AtomicUsize::new(0));
    for _ in 0..10_000 {
        hold.hold(DropCount(Arc::clone(&count)));
    }
    assert_eq!(hold.len(), 10_000, "every value handed over is kept");
    assert_eq!(count.load(Ordering::SeqCst), 0, "none of them is dropped");
}

// --- source pins: only the exit path reaches the process-wide hold ---------

/// The parent module's source, as compiled.
const BATCH_RS: &str = include_str!("../batch.rs");

#[test]
fn the_process_wide_hold_is_named_in_exactly_two_places() {
    let uses = BATCH_RS.matches("EXIT_HOLD").count();
    assert_eq!(
        uses, 2,
        "EXIT_HOLD must appear only in its declaration and in \
         RunStores::release_run_and_exit (found {uses})"
    );
}

#[test]
fn the_only_use_of_the_process_wide_hold_is_inside_a_function_that_never_returns()
-> Result<(), TestError> {
    let decl = BATCH_RS
        .find("static EXIT_HOLD")
        .ok_or("the static EXIT_HOLD declaration")?;
    let use_at = BATCH_RS
        .match_indices("EXIT_HOLD")
        .map(|(i, _)| i)
        .find(|&i| i != decl + "static ".len())
        .ok_or("one use of EXIT_HOLD besides its declaration")?;
    let fn_at = BATCH_RS[..use_at]
        .rfind("fn ")
        .ok_or("a function around the use of EXIT_HOLD")?;
    let signature = BATCH_RS[fn_at..use_at]
        .split('{')
        .next()
        .ok_or("the enclosing function's signature")?;
    assert!(
        signature.starts_with("fn release_run_and_exit(stores: Option<Self>"),
        "EXIT_HOLD must be reached only from RunStores::release_run_and_exit, \
         found it in `{signature}`"
    );
    assert!(
        signature.trim_end().ends_with("-> !"),
        "the function that fills EXIT_HOLD must never return, found `{signature}`"
    );
    Ok(())
}
