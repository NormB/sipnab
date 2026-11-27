// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Where the store leaves the message it is given, and the index lookups a
//! caller uses after the message has moved into the store.
//!
//! The batch runner folds every SIP message into the store and then still
//! reads it: the DSL filter, the detectors and the per-message output all run
//! after the dialog update. It used to clone the message for the store and
//! keep the original. [`DialogStore::process_message_capped`] takes the
//! message by value and answers [`Placed`]: `Stored` when the store holds it
//! as the newest message of a dialog, `Returned` (the message itself,
//! unchanged) when the store did not keep it. [`DialogStore::placed`] reads
//! the message back from either.
//!
//! "Unchanged" and "the same message" are checked by the address of the raw
//! buffer: a clone of a `SipMessage` shares the buffer too, so the checks
//! that the message was MOVED compare the address of the header vector,
//! which a clone allocates anew.
//!
//! Every fixture is synthetic: RFC 5737 documentation addresses and
//! `example.com` names.

use super::{DialogAt, DialogStore, DialogTracking, Placed, Tracked, key_lookups_on_this_thread};
use crate::capture::parse::InputOrigin;
use crate::net::TransportProto;
use crate::sip::SipMessage;
use crate::sip::dialog::DialogState;
use crate::sip::parser::parse_sip;
use crate::sip::sdp::SdpRead;
use crate::test_utils::build_sip_message as build_sip;
use chrono::{DateTime, TimeDelta, Utc};
use std::net::{IpAddr, Ipv4Addr};

type TestError = Box<dyn std::error::Error>;

/// A per-dialog message cap large enough that no fixture reaches it.
const ROOMY: usize = 500;

/// The time the first fixture message carries: 2024-06-15 12:00:00 UTC.
fn t0() -> Result<DateTime<Utc>, TestError> {
    Ok(
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0)
            .single()
            .ok_or("a valid UTC time")?,
    )
}

/// `secs` seconds after [`t0`].
fn at(secs: i64) -> Result<DateTime<Utc>, TestError> {
    Ok(t0()? + TimeDelta::seconds(secs))
}

/// Parse `raw` as sent at `ts` from 192.0.2.10 to 198.51.100.20 over UDP.
fn parse(raw: &[u8], ts: DateTime<Utc>) -> Result<SipMessage, TestError> {
    parse_sip(
        raw,
        ts,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        5060,
        5060,
        TransportProto::Udp,
    )
    .map_err(|e| format!("the fixture should parse: {e:?}").into())
}

/// A request `method` of `call_id` with CSeq `seq` and top-Via branch
/// `branch`, sent at `ts`.
fn request(
    method: &str,
    call_id: &str,
    seq: u32,
    branch: &str,
    ts: DateTime<Utc>,
) -> Result<SipMessage, TestError> {
    let raw = build_sip(
        &format!("{method} sip:bob@example.com SIP/2.0"),
        &[
            &format!("Via: SIP/2.0/UDP 192.0.2.10:5060;branch={branch}"),
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            &format!("Call-ID: {call_id}"),
            &format!("CSeq: {seq} {method}"),
            "Content-Length: 0",
        ],
        b"",
    );
    parse(&raw, ts)
}

/// An `INVITE` of `call_id` with CSeq `seq` (branch `z9hG4bK-<seq>`) at [`t0`].
fn invite(call_id: &str, seq: u32) -> Result<SipMessage, TestError> {
    request("INVITE", call_id, seq, &format!("z9hG4bK-{seq}"), t0()?)
}

/// A response `status` to `INVITE` CSeq `seq` of `call_id`, sent at `ts`.
fn response(
    status: u16,
    call_id: &str,
    seq: u32,
    ts: DateTime<Utc>,
) -> Result<SipMessage, TestError> {
    let raw = build_sip(
        &format!("SIP/2.0 {status} Status"),
        &[
            &format!("Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-{seq}"),
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>;tag=t2",
            &format!("Call-ID: {call_id}"),
            &format!("CSeq: {seq} INVITE"),
            "Content-Length: 0",
        ],
        b"",
    );
    parse(&raw, ts)
}

/// A request with no Call-ID header.
fn without_call_id() -> Result<SipMessage, TestError> {
    let raw = build_sip(
        "OPTIONS sip:bob@example.com SIP/2.0",
        &[
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-x",
            "CSeq: 1 OPTIONS",
            "Content-Length: 0",
        ],
        b"",
    );
    parse(&raw, t0()?)
}

/// A response with a Call-ID but no CSeq: it names no method, so it cannot
/// open a dialog.
fn response_without_cseq(call_id: &str) -> Result<SipMessage, TestError> {
    let raw = build_sip(
        "SIP/2.0 200 OK",
        &[&format!("Call-ID: {call_id}"), "Content-Length: 0"],
        b"",
    );
    parse(&raw, t0()?)
}

/// `msg` as delivered by `origin`.
fn from(mut msg: SipMessage, origin: InputOrigin) -> SipMessage {
    msg.input_origin = Some(origin);
    msg
}

/// The identity of a message's storage: the addresses of its raw buffer and
/// of its header vector. A move keeps both; a clone keeps only the first.
fn identity(msg: &SipMessage) -> (usize, usize) {
    (msg.raw.as_ptr() as usize, msg.headers.as_ptr() as usize)
}

/// Process `msg` with the roomy cap and the SDP unread.
fn put(store: &mut DialogStore, msg: SipMessage) -> Placed {
    store.process_message_capped(msg, &SdpRead::Unread, ROOMY)
}

/// Process `msg` with per-dialog cap `cap`.
fn put_capped(store: &mut DialogStore, msg: SipMessage, cap: usize) -> Placed {
    store.process_message_capped(msg, &SdpRead::Unread, cap)
}

/// The index a `Stored` answer names, or an error naming what came instead.
fn stored_index(placed: &Placed) -> Result<usize, TestError> {
    match placed {
        Placed::Stored(i) => Ok(*i),
        Placed::Returned(_) => Err("the store should have kept the message".into()),
    }
}

/// The message a `Returned` answer carries, or an error.
fn returned(placed: &Placed) -> Result<&SipMessage, TestError> {
    match placed {
        Placed::Returned(m) => Ok(m),
        Placed::Stored(i) => Err(format!("the store should not have kept it (Stored({i}))").into()),
    }
}

/// How many messages the dialog under `key` holds.
fn stored_count(store: &DialogStore, key: &str) -> usize {
    store.dialogs.get(key).map_or(0, |d| d.messages.len())
}

// ── Success: the store keeps the message ─────────────────────────────

/// The first message of a call opens the store's first dialog: index 0.
#[test]
fn a_message_that_opens_the_first_dialog_is_stored_at_index_0() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let placed = put(&mut store, invite("a@example.com", 1)?);
    assert_eq!(stored_index(&placed)?, 0, "the first dialog is at index 0");
    Ok(())
}

/// A second call opens the second dialog: index 1.
#[test]
fn a_message_that_opens_a_second_dialog_is_stored_at_index_1() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    let placed = put(&mut store, invite("b@example.com", 1)?);
    assert_eq!(stored_index(&placed)?, 1, "the second dialog is at index 1");
    Ok(())
}

/// A later message of the first call is stored in the first dialog, even
/// after another dialog was opened.
#[test]
fn an_in_dialog_message_is_stored_at_its_dialogs_index() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    put(&mut store, invite("b@example.com", 1)?);
    let placed = put(&mut store, response(200, "a@example.com", 1, at(1)?)?);
    assert_eq!(
        stored_index(&placed)?,
        0,
        "the 200 belongs to the first dialog"
    );
    Ok(())
}

/// `placed` answers the dialog's newest stored message for `Stored`.
#[test]
fn placed_reads_the_newest_stored_message_of_the_dialog() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    let placed = put(&mut store, response(180, "a@example.com", 1, at(1)?)?);
    let read = store.placed(&placed).ok_or("a stored message reads back")?;
    let newest = store
        .dialogs
        .get("a@example.com")
        .and_then(|d| d.messages.last())
        .ok_or("the dialog holds messages")?;
    assert!(
        std::ptr::eq(read, newest),
        "placed must answer the stored message itself, not a copy"
    );
    Ok(())
}

/// An in-dialog message is moved into the store: its header vector is the
/// one the caller built, so no clone was made.
#[test]
fn an_in_dialog_message_is_moved_not_cloned() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    let msg = response(200, "a@example.com", 1, at(1)?)?;
    let before = identity(&msg);
    let placed = put(&mut store, msg);
    let read = store.placed(&placed).ok_or("a stored message reads back")?;
    assert_eq!(
        identity(read),
        before,
        "the store holds the caller's message, moved"
    );
    Ok(())
}

/// The message read back carries what the caller gave.
#[test]
fn a_stored_message_reads_back_with_its_fields() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    let msg = response(486, "a@example.com", 1, at(2)?)?;
    let (raw, ts, code) = (msg.raw.clone(), msg.timestamp, msg.status_code);
    let placed = put(&mut store, msg);
    let read = store.placed(&placed).ok_or("a stored message reads back")?;
    assert_eq!(read.raw, raw, "same bytes");
    assert_eq!(read.timestamp, ts, "same timestamp");
    assert_eq!(read.status_code, code, "same status");
    assert_eq!(read.call_id(), Some("a@example.com"), "same Call-ID");
    Ok(())
}

/// Storing adds exactly one message to the dialog.
#[test]
fn a_stored_message_adds_exactly_one_message() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    put(&mut store, response(100, "a@example.com", 1, at(1)?)?);
    let before = stored_count(&store, "a@example.com");
    put(&mut store, response(180, "a@example.com", 1, at(2)?)?);
    assert_eq!(
        stored_count(&store, "a@example.com"),
        before + 1,
        "one message more"
    );
    Ok(())
}

/// A retransmission under the cap is stored, and the stored copy is marked.
#[test]
fn a_retransmission_under_the_cap_is_stored_and_marked() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    let placed = put(&mut store, invite("a@example.com", 1)?);
    assert_eq!(stored_index(&placed)?, 0, "stored in its dialog");
    let read = store.placed(&placed).ok_or("a stored message reads back")?;
    assert!(
        read.is_retransmission,
        "the stored retransmission is marked"
    );
    Ok(())
}

/// Under Branch tracking, a new branch of a known Call-ID opens a new unit
/// and is stored there.
#[test]
fn a_new_branch_under_branch_tracking_is_stored_in_a_new_unit() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.set_tracking(DialogTracking::Branch);
    put(
        &mut store,
        request("INVITE", "a@example.com", 1, "z9hG4bK-1", t0()?)?,
    );
    let placed = put(
        &mut store,
        request("BYE", "a@example.com", 2, "z9hG4bK-2", at(5)?)?,
    );
    assert_eq!(
        stored_index(&placed)?,
        1,
        "the BYE's own unit is the second"
    );
    Ok(())
}

/// Under Branch tracking, a message of a known branch is stored in that
/// branch's unit.
#[test]
fn a_known_branch_under_branch_tracking_is_stored_in_its_unit() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.set_tracking(DialogTracking::Branch);
    put(
        &mut store,
        request("INVITE", "a@example.com", 1, "z9hG4bK-1", t0()?)?,
    );
    put(
        &mut store,
        request("BYE", "a@example.com", 2, "z9hG4bK-2", at(5)?)?,
    );
    let placed = put(&mut store, response(100, "a@example.com", 1, at(1)?)?);
    assert_eq!(
        stored_index(&placed)?,
        0,
        "the 100 belongs to the INVITE's unit"
    );
    Ok(())
}

/// A dialog opened after a rotating eviction is stored at the index it was
/// inserted at, which names the new dialog.
#[test]
fn a_dialog_opened_after_an_eviction_is_stored_at_its_new_index() -> Result<(), TestError> {
    let mut store = DialogStore::new(2, true);
    put(&mut store, invite("a@example.com", 1)?);
    put(&mut store, invite("b@example.com", 1)?);
    let placed = put(&mut store, invite("c@example.com", 1)?);
    let index = stored_index(&placed)?;
    let read = store.placed(&placed).ok_or("a stored message reads back")?;
    assert_eq!(
        read.call_id(),
        Some("c@example.com"),
        "the index names the new dialog"
    );
    assert_eq!(index, store.dialogs.len() - 1, "inserted last");
    Ok(())
}

/// `process_message_tracked` applies the store's cap and answers `Stored`.
#[test]
fn process_message_tracked_answers_stored() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let tracked = store.process_message_tracked(invite("a@example.com", 1)?, &SdpRead::Unread);
    assert_eq!(
        stored_index(&tracked.placed)?,
        0,
        "stored under the default cap"
    );
    Ok(())
}

/// `find_dialog` finds a dialog by its exact key.
#[test]
fn find_dialog_finds_an_exact_key() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    put(&mut store, invite("b@example.com", 1)?);
    assert_eq!(
        store.find_dialog("b@example.com"),
        Some(DialogAt {
            index: 1,
            exact: true
        }),
        "b is the second dialog, by its exact key"
    );
    Ok(())
}

/// `dialog_at` answers the dialog at an index.
#[test]
fn dialog_at_answers_the_dialog_at_the_index() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    put(&mut store, invite("b@example.com", 1)?);
    let dialog = store.dialog_at(1).ok_or("index 1 holds a dialog")?;
    assert_eq!(dialog.call_id, "b@example.com", "index 1 is b");
    Ok(())
}

/// `exact_dialog_mut` answers an exact hit and counts a generation, as
/// `get_mut` does.
#[test]
fn exact_dialog_mut_answers_an_exact_hit_and_counts_a_generation() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    let found = store.find_dialog("a@example.com");
    let before = store.generation();
    let dialog = store.exact_dialog_mut(found).ok_or("an exact hit")?;
    dialog.tags.push("x".to_string());
    assert_eq!(store.generation(), before + 1, "one generation, as get_mut");
    assert!(
        store.get("a@example.com").is_some_and(|d| d.tags == ["x"]),
        "the change landed on the dialog"
    );
    Ok(())
}

/// `get` answers the same dialog `find_dialog` and `dialog_at` do.
#[test]
fn get_agrees_with_find_dialog_and_dialog_at() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    for i in 0..5 {
        put(&mut store, invite(&format!("d{i}@example.com"), 1)?);
    }
    let found = store.find_dialog("d3@example.com").ok_or("d3 is tracked")?;
    let by_index = store.dialog_at(found.index).ok_or("its index holds it")?;
    let by_get = store.get("d3@example.com").ok_or("get finds d3")?;
    assert!(std::ptr::eq(by_index, by_get), "one dialog, two lookups");
    Ok(())
}

/// One hundred calls: each opening message is stored at its call's index.
#[test]
fn each_of_a_hundred_calls_is_stored_at_its_own_index() -> Result<(), TestError> {
    let mut store = DialogStore::new(1000, false);
    for i in 0..100 {
        let placed = put(&mut store, invite(&format!("n{i}@example.com"), 1)?);
        assert_eq!(stored_index(&placed)?, i, "call {i} is the {i}th dialog");
    }
    Ok(())
}

/// With a method filter on, a later message of a kept dialog is stored.
#[test]
fn a_kept_dialogs_later_message_is_stored_under_a_method_filter() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.set_drop_methods(vec!["OPTIONS".to_string()]);
    put(&mut store, invite("a@example.com", 1)?);
    let placed = put(&mut store, response(200, "a@example.com", 1, at(1)?)?);
    assert_eq!(stored_index(&placed)?, 0, "the kept dialog stores its 200");
    Ok(())
}

// ── Failure: the store does not keep the message ─────────────────────

/// A message with no Call-ID is handed back, the same message, and opens
/// nothing.
#[test]
fn a_message_without_a_call_id_is_returned_as_it_was() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let msg = without_call_id()?;
    let before = identity(&msg);
    let placed = put(&mut store, msg);
    assert_eq!(
        identity(returned(&placed)?),
        before,
        "the caller's own message"
    );
    assert_eq!(store.dialogs.len(), 0, "no dialog");
    Ok(())
}

/// A response that names no method cannot open a dialog and is handed back.
#[test]
fn a_message_that_cannot_open_a_dialog_is_returned() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let placed = put(&mut store, response_without_cseq("a@example.com")?);
    assert_eq!(
        returned(&placed)?.call_id(),
        Some("a@example.com"),
        "the message came back"
    );
    assert_eq!(store.dialogs.len(), 0, "no dialog");
    Ok(())
}

/// A message of a method the filter drops is handed back.
#[test]
fn a_message_dropped_by_method_is_returned() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.set_drop_methods(vec!["OPTIONS".to_string()]);
    let placed = put(
        &mut store,
        request("OPTIONS", "o@example.com", 1, "z9hG4bK-o", t0()?)?,
    );
    returned(&placed)?;
    assert_eq!(store.messages_dropped_by_method, 1, "counted as dropped");
    Ok(())
}

/// The second message of a Call-ID the method filter refused is handed back.
#[test]
fn a_later_message_of_a_refused_call_id_is_returned() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.set_drop_methods(vec!["OPTIONS".to_string()]);
    put(
        &mut store,
        request("OPTIONS", "o@example.com", 1, "z9hG4bK-o", t0()?)?,
    );
    let msg = response(200, "o@example.com", 1, at(1)?)?;
    let before = identity(&msg);
    let placed = put(&mut store, msg);
    assert_eq!(
        identity(returned(&placed)?),
        before,
        "the caller's own message"
    );
    assert_eq!(store.messages_dropped_by_method, 2, "both counted");
    Ok(())
}

/// A new Call-ID at capacity without rotation is refused and handed back.
#[test]
fn a_new_call_at_capacity_without_rotation_is_returned() -> Result<(), TestError> {
    let mut store = DialogStore::new(1, false);
    put(&mut store, invite("a@example.com", 1)?);
    let msg = invite("b@example.com", 1)?;
    let before = identity(&msg);
    let placed = put(&mut store, msg);
    assert_eq!(
        identity(returned(&placed)?),
        before,
        "the caller's own message"
    );
    assert_eq!(store.capacity_dialogs_dropped, 1, "counted as refused");
    assert_eq!(store.dialogs.len(), 1, "the store did not grow");
    Ok(())
}

/// A copy of a stored message from another source is handed back unchanged,
/// and the original records the other source.
#[test]
fn a_copy_from_another_source_is_returned_unchanged() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(
        &mut store,
        from(invite("a@example.com", 1)?, InputOrigin::Wire),
    );
    let copy = from(invite("a@example.com", 1)?, InputOrigin::Hep);
    let before = identity(&copy);
    let placed = put(&mut store, copy);
    let back = returned(&placed)?;
    assert_eq!(identity(back), before, "the caller's own message");
    assert_eq!(back.also_seen_by, 0, "the copy itself is not changed");
    assert!(!back.is_retransmission, "a copy is not a retransmission");
    assert_eq!(
        stored_count(&store, "a@example.com"),
        1,
        "only the original is stored"
    );
    let original = store
        .dialogs
        .get("a@example.com")
        .and_then(|d| d.messages.first())
        .ok_or("the original is stored")?;
    assert_ne!(
        original.also_seen_by, 0,
        "the original records the copy's source"
    );
    Ok(())
}

/// A new message of a dialog at its cap is handed back.
#[test]
fn a_new_message_of_a_full_dialog_is_returned() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put_capped(&mut store, invite("a@example.com", 1)?, 2);
    put_capped(&mut store, response(100, "a@example.com", 1, at(1)?)?, 2);
    let msg = response(180, "a@example.com", 1, at(2)?)?;
    let before = identity(&msg);
    let placed = put_capped(&mut store, msg, 2);
    assert_eq!(
        identity(returned(&placed)?),
        before,
        "the caller's own message"
    );
    assert_eq!(stored_count(&store, "a@example.com"), 2, "the cap held");
    Ok(())
}

/// A retransmission of a dialog at its cap is handed back NOT marked: only a
/// stored retransmission is marked, so the caller's message is as it gave it.
#[test]
fn a_retransmission_of_a_full_dialog_is_returned_unmarked() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put_capped(&mut store, invite("a@example.com", 1)?, 1);
    let placed = put_capped(&mut store, invite("a@example.com", 1)?, 1);
    assert!(
        !returned(&placed)?.is_retransmission,
        "the returned message is unmarked"
    );
    Ok(())
}

/// A retransmission past the cap is still counted.
#[test]
fn a_returned_retransmission_is_still_counted() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put_capped(&mut store, invite("a@example.com", 1)?, 1);
    let placed = put_capped(&mut store, invite("a@example.com", 1)?, 1);
    returned(&placed)?;
    let dialog = store.get("a@example.com").ok_or("the dialog is tracked")?;
    assert_eq!(dialog.timing.total_retransmits(), 1, "counted");
    Ok(())
}

/// A message past the cap still advances the dialog's state.
#[test]
fn a_returned_message_still_advances_the_dialog() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put_capped(&mut store, invite("a@example.com", 1)?, 1);
    let placed = put_capped(&mut store, response(486, "a@example.com", 1, at(1)?)?, 1);
    returned(&placed)?;
    let dialog = store.get("a@example.com").ok_or("the dialog is tracked")?;
    assert_ne!(
        dialog.state(),
        &DialogState::Trying,
        "the 486 moved the state"
    );
    assert_eq!(dialog.updated_at, at(1)?, "and the time");
    Ok(())
}

/// `placed` reads a returned message out of the answer itself.
#[test]
fn placed_reads_a_returned_message_from_the_answer() -> Result<(), TestError> {
    let store = &mut DialogStore::new(100, false);
    let placed = put(store, without_call_id()?);
    let inside = returned(&placed)?;
    let read = store
        .placed(&placed)
        .ok_or("a returned message reads back")?;
    assert!(std::ptr::eq(read, inside), "the message inside the answer");
    Ok(())
}

/// An index that names no dialog reads back nothing.
#[test]
fn placed_reads_nothing_for_an_index_with_no_dialog() {
    let store = DialogStore::new(100, false);
    assert!(
        store.placed(&Placed::Stored(99)).is_none(),
        "no dialog at index 99"
    );
}

/// `find_dialog` finds nothing for a Call-ID the store does not track.
#[test]
fn find_dialog_finds_nothing_for_an_unknown_call_id() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    assert_eq!(store.find_dialog("z@example.com"), None, "not tracked");
    Ok(())
}

/// `exact_dialog_mut` with nothing found answers nothing, and still counts
/// a generation, as `get_mut` of an unknown Call-ID does.
#[test]
fn exact_dialog_mut_of_nothing_still_counts_a_generation() {
    let mut store = DialogStore::new(100, false);
    let before = store.generation();
    assert!(store.exact_dialog_mut(None).is_none(), "nothing to answer");
    assert_eq!(store.generation(), before + 1, "one generation, as get_mut");
}

/// `dialog_at` past the end answers nothing.
#[test]
fn dialog_at_past_the_end_answers_nothing() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    assert!(store.dialog_at(1).is_none(), "only index 0 holds a dialog");
    Ok(())
}

/// A message of a Call-ID refused at capacity is handed back every time.
#[test]
fn every_message_of_a_refused_call_is_returned() -> Result<(), TestError> {
    let mut store = DialogStore::new(1, false);
    put(&mut store, invite("a@example.com", 1)?);
    for seq in 1..=3 {
        let placed = put(&mut store, invite("b@example.com", seq)?);
        returned(&placed)?;
    }
    assert_eq!(
        store.capacity_dialogs_dropped, 1,
        "the Call-ID counted once"
    );
    Ok(())
}

/// With an admission matcher, a message it refuses opens nothing and is
/// handed back.
#[cfg(feature = "native")]
#[test]
fn a_message_the_admission_matcher_refuses_is_returned() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let cli = crate::cli::Cli::parse_from_args(["sipnab", "-e", "^REGISTER"]);
    let matcher =
        crate::sip::matcher::SipMatcher::new(&cli, cli.matching_args.match_expr.as_deref())
            .map_err(|e| format!("matcher: {e:?}"))?;
    store.set_admission(Some(matcher));
    let msg = invite("a@example.com", 1)?;
    let before = identity(&msg);
    let placed = put(&mut store, msg);
    assert_eq!(
        identity(returned(&placed)?),
        before,
        "the caller's own message"
    );
    assert_eq!(store.dialogs.len(), 0, "no dialog");
    Ok(())
}

// ── Edge cases ───────────────────────────────────────────────────────

/// A dialog always keeps its opening message, even under a cap of 0.
#[test]
fn a_cap_of_zero_still_stores_the_opening_message() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let placed = put_capped(&mut store, invite("a@example.com", 1)?, 0);
    assert_eq!(stored_index(&placed)?, 0, "the opening message is stored");
    Ok(())
}

/// Under a cap of 0, every later message is handed back.
#[test]
fn a_cap_of_zero_returns_every_later_message() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put_capped(&mut store, invite("a@example.com", 1)?, 0);
    let placed = put_capped(&mut store, response(200, "a@example.com", 1, at(1)?)?, 0);
    returned(&placed)?;
    Ok(())
}

/// Under a cap of 1, the second message is handed back.
#[test]
fn a_cap_of_one_returns_the_second_message() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put_capped(&mut store, invite("a@example.com", 1)?, 1);
    let placed = put_capped(&mut store, response(200, "a@example.com", 1, at(1)?)?, 1);
    returned(&placed)?;
    Ok(())
}

/// The message that fills the dialog to its cap is stored; the next is not.
#[test]
fn the_message_that_reaches_the_cap_is_stored_and_the_next_returned() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put_capped(&mut store, invite("a@example.com", 1)?, 3);
    put_capped(&mut store, response(100, "a@example.com", 1, at(1)?)?, 3);
    let third = put_capped(&mut store, response(180, "a@example.com", 1, at(2)?)?, 3);
    assert_eq!(
        stored_index(&third)?,
        0,
        "the third fills the cap and is stored"
    );
    let fourth = put_capped(&mut store, response(200, "a@example.com", 1, at(3)?)?, 3);
    returned(&fourth)?;
    Ok(())
}

/// A retransmission that fills the dialog to its cap is stored and marked.
#[test]
fn a_retransmission_that_reaches_the_cap_is_stored_and_marked() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put_capped(&mut store, invite("a@example.com", 1)?, 2);
    let placed = put_capped(&mut store, invite("a@example.com", 1)?, 2);
    let read = store.placed(&placed).ok_or("stored")?;
    assert!(read.is_retransmission, "marked");
    Ok(())
}

/// Under Branch tracking, `find_dialog` of a bare Call-ID finds the first
/// unit by prefix, and says the hit was not exact.
#[test]
fn find_dialog_under_branch_tracking_finds_by_prefix() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.set_tracking(DialogTracking::Branch);
    put(
        &mut store,
        request("INVITE", "a@example.com", 1, "z9hG4bK-1", t0()?)?,
    );
    put(
        &mut store,
        request("BYE", "a@example.com", 2, "z9hG4bK-2", at(5)?)?,
    );
    assert_eq!(
        store.find_dialog("a@example.com"),
        Some(DialogAt {
            index: 0,
            exact: false
        }),
        "the first unit, by prefix"
    );
    Ok(())
}

/// `exact_dialog_mut` of a prefix hit answers nothing, as `get_mut` of the
/// bare Call-ID does, and still counts a generation.
#[test]
fn exact_dialog_mut_of_a_prefix_hit_answers_nothing() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.set_tracking(DialogTracking::Branch);
    put(
        &mut store,
        request("INVITE", "a@example.com", 1, "z9hG4bK-1", t0()?)?,
    );
    let found = store.find_dialog("a@example.com");
    assert!(found.is_some(), "the prefix hit exists");
    let before = store.generation();
    assert!(
        store.exact_dialog_mut(found).is_none(),
        "get_mut would miss"
    );
    assert!(store.get_mut("a@example.com").is_none(), "and it does");
    assert_eq!(store.generation(), before + 2, "both counted a generation");
    Ok(())
}

/// Under Branch tracking, `get` still answers the dialog `find_dialog` names.
#[test]
fn get_under_branch_tracking_agrees_with_find_dialog() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.set_tracking(DialogTracking::Branch);
    put(
        &mut store,
        request("INVITE", "a@example.com", 1, "z9hG4bK-1", t0()?)?,
    );
    put(
        &mut store,
        request("BYE", "a@example.com", 2, "z9hG4bK-2", at(5)?)?,
    );
    let found = store.find_dialog("a@example.com").ok_or("found")?;
    let by_index = store.dialog_at(found.index).ok_or("its index holds it")?;
    let by_get = store.get("a@example.com").ok_or("get finds it")?;
    assert!(std::ptr::eq(by_index, by_get), "one dialog, two lookups");
    Ok(())
}

/// A `Stored` index of a dialog whose messages were all removed reads back
/// nothing rather than another message.
#[test]
fn placed_reads_nothing_from_a_dialog_with_no_messages() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let placed = put(&mut store, invite("a@example.com", 1)?);
    if let Some(d) = store.dialogs.get_mut("a@example.com") {
        d.messages.clear();
    }
    assert!(store.placed(&placed).is_none(), "nothing stored to read");
    Ok(())
}

/// An eviction moves the dialogs down; the index answered after it names the
/// new dialog, and an index answered before it names another one.
#[test]
fn an_eviction_moves_the_indices_and_the_new_answer_follows() -> Result<(), TestError> {
    let mut store = DialogStore::new(2, true);
    put(&mut store, invite("a@example.com", 1)?);
    let b = put(&mut store, invite("b@example.com", 1)?);
    assert_eq!(stored_index(&b)?, 1, "b was second");
    let c = put(&mut store, invite("c@example.com", 1)?);
    let read_c = store.placed(&c).ok_or("c reads back")?;
    assert_eq!(
        read_c.call_id(),
        Some("c@example.com"),
        "c's answer names c"
    );
    let read_b = store.placed(&b).ok_or("index 1 holds a dialog")?;
    assert_eq!(
        read_b.call_id(),
        Some("c@example.com"),
        "an index is valid only until the store changes again"
    );
    Ok(())
}

/// Every message counts one generation, kept or not, as before.
#[test]
fn every_message_counts_one_generation_kept_or_not() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let g0 = store.generation();
    put(&mut store, invite("a@example.com", 1)?);
    put(&mut store, without_call_id()?);
    put_capped(&mut store, response(200, "a@example.com", 1, at(1)?)?, 1);
    assert_eq!(
        store.generation(),
        g0 + 3,
        "three messages, three generations"
    );
    Ok(())
}

/// `process_message` still keeps a message, its answer dropped.
#[test]
fn process_message_still_keeps_the_message() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.process_message(invite("a@example.com", 1)?);
    store.process_message(response(200, "a@example.com", 1, at(1)?)?);
    assert_eq!(stored_count(&store, "a@example.com"), 2, "both stored");
    Ok(())
}

/// A second copy from the SAME source is a retransmission, not a copy: it is
/// stored and marked.
#[test]
fn a_second_delivery_by_the_same_source_is_stored_as_a_retransmission() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(
        &mut store,
        from(invite("a@example.com", 1)?, InputOrigin::Wire),
    );
    let placed = put(
        &mut store,
        from(invite("a@example.com", 1)?, InputOrigin::Wire),
    );
    let read = store.placed(&placed).ok_or("stored")?;
    assert!(read.is_retransmission, "a retransmission");
    Ok(())
}

/// A copy from another source outside the copy window is not a copy: it is
/// stored as a retransmission.
#[test]
fn a_late_delivery_by_another_source_is_stored_as_a_retransmission() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(
        &mut store,
        from(invite("a@example.com", 1)?, InputOrigin::Wire),
    );
    let mut late = from(invite("a@example.com", 1)?, InputOrigin::Hep);
    late.timestamp = at(10)?;
    let placed = put(&mut store, late);
    let read = store.placed(&placed).ok_or("stored")?;
    assert!(read.is_retransmission, "a retransmission");
    Ok(())
}

/// A returned message's Call-ID can still find its dialog: the step a caller
/// takes after the message came back.
#[test]
fn a_returned_messages_call_id_finds_its_dialog() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put_capped(&mut store, invite("a@example.com", 1)?, 1);
    let placed = put_capped(&mut store, response(200, "a@example.com", 1, at(1)?)?, 1);
    let id = store
        .placed(&placed)
        .and_then(SipMessage::call_id)
        .ok_or("the message has a Call-ID")?;
    assert_eq!(
        store.find_dialog(id),
        Some(DialogAt {
            index: 0,
            exact: true
        }),
        "its dialog"
    );
    Ok(())
}

/// The opening message of a dialog reads back with the caller's bytes.
#[test]
fn an_opening_message_reads_back_with_the_callers_bytes() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let msg = invite("a@example.com", 7)?;
    let raw = msg.raw.as_ptr() as usize;
    let placed = put(&mut store, msg);
    let read = store.placed(&placed).ok_or("stored")?;
    assert_eq!(read.raw.as_ptr() as usize, raw, "the same buffer");
    assert_eq!(read.cseq().map(|c| c.0), Some(7), "the same CSeq");
    Ok(())
}

/// An empty store finds nothing and reads back nothing at index 0.
#[test]
fn an_empty_store_finds_nothing() {
    let store = DialogStore::new(100, false);
    assert_eq!(store.find_dialog("a@example.com"), None, "nothing tracked");
    assert!(store.dialog_at(0).is_none(), "no dialog at 0");
    assert!(
        store.placed(&Placed::Stored(0)).is_none(),
        "nothing to read"
    );
}

// ── Lookups: reading back costs none ─────────────────────────────────

/// How many hash lookups of the dialog map `f` makes on this thread.
fn lookups_during<T>(f: impl FnOnce() -> T) -> (usize, T) {
    let before = key_lookups_on_this_thread();
    let out = f();
    (key_lookups_on_this_thread() - before, out)
}

/// Reading a stored message back is an index into the map, not a lookup.
#[test]
fn reading_a_stored_message_back_costs_no_lookup() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    let placed = put(&mut store, response(180, "a@example.com", 1, at(1)?)?);
    let (lookups, read) = lookups_during(|| store.placed(&placed).is_some());
    assert!(read, "the message reads back");
    assert_eq!(lookups, 0, "no lookup to read it back");
    Ok(())
}

/// Reading a returned message back costs no lookup either.
#[test]
fn reading_a_returned_message_back_costs_no_lookup() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let placed = put(&mut store, without_call_id()?);
    let (lookups, read) = lookups_during(|| store.placed(&placed).is_some());
    assert!(read, "the message reads back");
    assert_eq!(lookups, 0, "no lookup to read it back");
    Ok(())
}

/// The store's own work on an in-dialog message is one lookup.
#[test]
fn an_in_dialog_message_costs_the_store_one_lookup() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    let msg = response(180, "a@example.com", 1, at(1)?)?;
    let (lookups, placed) = lookups_during(|| put(&mut store, msg));
    stored_index(&placed)?;
    assert_eq!(lookups, 1, "one lookup for the message");
    Ok(())
}

/// `get` of a known Call-ID is one lookup, as it was.
#[test]
fn get_of_a_known_call_id_costs_one_lookup() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    let (lookups, found) = lookups_during(|| store.get("a@example.com").is_some());
    assert!(found, "found");
    assert_eq!(lookups, 1, "one lookup");
    Ok(())
}

/// `dialog_at` and `exact_dialog_mut` on a found dialog cost no lookup.
#[test]
fn index_access_costs_no_lookup() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    let found = store.find_dialog("a@example.com");
    let at = found.ok_or("found")?;
    let (lookups, both) = lookups_during(|| {
        let read = store.dialog_at(at.index).is_some();
        read && store.exact_dialog_mut(found).is_some()
    });
    assert!(both, "both answer the dialog");
    assert_eq!(lookups, 0, "indices, not lookups");
    Ok(())
}

// ── process_message_tracked: the batch runner's three answers ────────
//
// The batch runner asked three questions of each message: the state of the
// dialog `get` finds for its Call-ID before it, where the message went, and
// what `find_dialog` finds for that Call-ID after it. It asked them with three
// lookups. `process_message_tracked` answers all three; these tests hold its
// answers equal to that composition, step by step, on every path a message
// can take, and the stores equal at the end.

/// The composition the batch runner made before `process_message_tracked`:
/// the reference every answer is compared with.
fn composed(store: &mut DialogStore, msg: SipMessage, cap: usize) -> Tracked {
    let before = msg
        .call_id()
        .and_then(|id| store.get(id))
        .map(|d| d.state().clone());
    let placed = store.process_message_capped(msg, &SdpRead::Unread, cap);
    let found = store
        .placed(&placed)
        .and_then(SipMessage::call_id)
        .map(|id| store.find_dialog(id));
    Tracked {
        placed,
        before,
        found,
    }
}

/// One answer in a form two stores' answers compare by: the index a stored
/// message went to, or the Call-ID of a returned one; the state before; the
/// dialog found after.
#[derive(Debug, PartialEq)]
struct Answer {
    stored: Option<usize>,
    returned: Option<Option<String>>,
    before: Option<DialogState>,
    found: Option<Option<DialogAt>>,
}

/// `tracked` as an [`Answer`].
fn answer_of(tracked: &Tracked) -> Answer {
    let (stored, returned) = match &tracked.placed {
        Placed::Stored(i) => (Some(*i), None),
        Placed::Returned(m) => (None, Some(m.call_id().map(str::to_owned))),
    };
    Answer {
        stored,
        returned,
        before: tracked.before.clone(),
        found: tracked.found,
    }
}

/// One dialog as [`summary`] lists it: its key, state, message count, tags.
type DialogSummary = (String, DialogState, usize, Vec<String>);

/// What a store holds, in order: each key, its dialog's state, its message
/// count and its tags, then the generation counter.
fn summary(store: &DialogStore) -> (Vec<DialogSummary>, u64) {
    let dialogs = store
        .dialogs
        .iter()
        .map(|(k, d)| {
            (
                k.clone(),
                d.state().clone(),
                d.messages.len(),
                d.tags.clone(),
            )
        })
        .collect();
    (dialogs, store.generation)
}

/// How a scenario's two stores are made.
struct Setup {
    max_dialogs: usize,
    rotate: bool,
    cap: usize,
    configure: fn(&mut DialogStore) -> Result<(), TestError>,
}

/// Configures nothing.
fn configure_nothing(_: &mut DialogStore) -> Result<(), TestError> {
    Ok(())
}

/// A store of 100 dialogs, no rotation, the roomy cap, nothing configured.
const PLAIN: Setup = Setup {
    max_dialogs: 100,
    rotate: false,
    cap: ROOMY,
    configure: configure_nothing,
};

/// Feed the messages `script` builds to two stores made by `setup`, one
/// through `process_message_tracked_capped` and one through [`composed`]:
/// every answer must be equal, and the stores equal at the end.
///
/// # Returns
///
/// The answers, for a test that also checks what they are.
fn agree(
    setup: &Setup,
    script: impl Fn() -> Result<Vec<SipMessage>, TestError>,
) -> Result<Vec<Answer>, TestError> {
    let mut fast = DialogStore::new(setup.max_dialogs, setup.rotate);
    let mut reference = DialogStore::new(setup.max_dialogs, setup.rotate);
    (setup.configure)(&mut fast)?;
    (setup.configure)(&mut reference)?;
    let mut answers = Vec::new();
    for (step, (a, b)) in script()?.into_iter().zip(script()?).enumerate() {
        let got = answer_of(&fast.process_message_tracked_capped(a, &SdpRead::Unread, setup.cap));
        let want = answer_of(&composed(&mut reference, b, setup.cap));
        assert_eq!(
            got, want,
            "step {step}: the tracked answer and the composed one"
        );
        answers.push(got);
    }
    assert_eq!(
        summary(&fast),
        summary(&reference),
        "the stores end the same"
    );
    Ok(answers)
}

/// A whole INVITE dialog: INVITE, 100, 180, 200, ACK, BYE, 200 to the BYE.
fn whole_call(call_id: &str) -> Result<Vec<SipMessage>, TestError> {
    Ok(vec![
        invite(call_id, 1)?,
        response(100, call_id, 1, at(0)?)?,
        response(180, call_id, 1, at(1)?)?,
        response(200, call_id, 1, at(2)?)?,
        request("ACK", call_id, 1, "z9hG4bK-ack", at(3)?)?,
        request("BYE", call_id, 2, "z9hG4bK-bye", at(9)?)?,
        bye_ok(call_id)?,
    ])
}

/// The 200 OK to the BYE (CSeq 2) of `call_id`.
fn bye_ok(call_id: &str) -> Result<SipMessage, TestError> {
    let raw = build_sip(
        "SIP/2.0 200 OK",
        &[
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-bye",
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>;tag=t2",
            &format!("Call-ID: {call_id}"),
            "CSeq: 2 BYE",
            "Content-Length: 0",
        ],
        b"",
    );
    parse(&raw, at(9)?)
}

// Success: the paths that keep the message.

/// A whole call: the answers agree, and they are the expected ones.
#[test]
fn tracked_agrees_on_a_whole_call() -> Result<(), TestError> {
    let answers = agree(&PLAIN, || whole_call("w@example.com"))?;
    let first = answers.first().ok_or("an answer")?;
    assert_eq!(first.before, None, "no dialog before the INVITE");
    assert_eq!(
        first.found,
        Some(Some(DialogAt {
            index: 0,
            exact: true
        })),
        "the INVITE's dialog is at 0"
    );
    let last = answers.last().ok_or("an answer")?;
    assert_eq!(
        last.stored,
        Some(0),
        "the BYE's 200 is stored in the call's dialog"
    );
    Ok(())
}

/// The state before is the dialog's state before the message, not after.
#[test]
fn tracked_answers_the_state_before_the_message() -> Result<(), TestError> {
    let answers = agree(&PLAIN, || {
        Ok(vec![
            invite("s@example.com", 1)?,
            response(180, "s@example.com", 1, at(1)?)?,
            response(200, "s@example.com", 1, at(2)?)?,
        ])
    })?;
    let states_before: Vec<_> = answers.iter().map(|a| a.before.clone()).collect();
    assert_eq!(
        states_before,
        [None, Some(DialogState::Trying), Some(DialogState::Ringing)],
        "each answer names the state the message found"
    );
    Ok(())
}

/// Two calls interleaved: each message's answers name its own dialog.
#[test]
fn tracked_agrees_on_two_interleaved_calls() -> Result<(), TestError> {
    agree(&PLAIN, || {
        let mut a = whole_call("a@example.com")?.into_iter();
        let mut b = whole_call("b@example.com")?.into_iter();
        let mut both = Vec::new();
        loop {
            match (a.next(), b.next()) {
                (None, None) => break,
                (x, y) => both.extend(x.into_iter().chain(y)),
            }
        }
        Ok(both)
    })?;
    Ok(())
}

/// Retransmissions of the INVITE and the 180 are stored and agree.
#[test]
fn tracked_agrees_on_retransmissions() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            invite("r@example.com", 1)?,
            invite("r@example.com", 1)?,
            response(180, "r@example.com", 1, at(1)?)?,
            response(180, "r@example.com", 1, at(1)?)?,
        ])
    })?;
    Ok(())
}

/// A capture that starts mid-call: the 180 comes before any INVITE.
#[test]
fn tracked_agrees_when_the_capture_starts_mid_call() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            response(180, "m@example.com", 1, t0()?)?,
            response(200, "m@example.com", 1, at(1)?)?,
            request("BYE", "m@example.com", 2, "z9hG4bK-bye", at(5)?)?,
        ])
    })?;
    Ok(())
}

/// A hundred calls, each opened and answered.
#[test]
fn tracked_agrees_on_a_hundred_calls() -> Result<(), TestError> {
    let answers = agree(&PLAIN, || {
        let mut msgs = Vec::new();
        for n in 0..100 {
            let id = format!("h{n}@example.com");
            msgs.push(invite(&id, 1)?);
            msgs.push(response(200, &id, 1, at(1)?)?);
        }
        Ok(msgs)
    })?;
    assert_eq!(answers.len(), 200, "every message answered");
    Ok(())
}

// Failure: the paths that hand the message back.

/// A message with no Call-ID: no state before, nothing found, returned.
#[test]
fn tracked_agrees_on_a_message_without_a_call_id() -> Result<(), TestError> {
    let answers = agree(&PLAIN, || Ok(vec![without_call_id()?]))?;
    let only = answers.first().ok_or("an answer")?;
    assert_eq!(only.found, None, "no Call-ID, nothing to find");
    assert_eq!(only.returned, Some(None), "handed back without a Call-ID");
    Ok(())
}

/// A message that cannot open a dialog, then the call's INVITE.
#[test]
fn tracked_agrees_on_a_message_that_cannot_open_a_dialog() -> Result<(), TestError> {
    let answers = agree(&PLAIN, || {
        Ok(vec![
            response_without_cseq("n@example.com")?,
            invite("n@example.com", 1)?,
        ])
    })?;
    let first = answers.first().ok_or("an answer")?;
    assert_eq!(first.found, Some(None), "a Call-ID, but no dialog");
    Ok(())
}

/// The method filter refuses a call, and every later message of it.
#[test]
fn tracked_agrees_under_the_method_filter() -> Result<(), TestError> {
    let setup = Setup {
        configure: |store| {
            store.set_drop_methods(vec!["OPTIONS".to_string()]);
            Ok(())
        },
        ..PLAIN
    };
    agree(&setup, || {
        Ok(vec![
            request("OPTIONS", "o@example.com", 1, "z9hG4bK-o", t0()?)?,
            response(200, "o@example.com", 1, at(1)?)?,
            invite("k@example.com", 1)?,
            response(180, "k@example.com", 1, at(1)?)?,
        ])
    })?;
    Ok(())
}

/// The admission matcher refuses an INVITE and admits a REGISTER.
#[test]
fn tracked_agrees_under_the_admission_matcher() -> Result<(), TestError> {
    let setup = Setup {
        configure: |store| {
            let cli = crate::cli::Cli::parse_from_args(["sipnab", "-e", "^REGISTER"]);
            let matcher =
                crate::sip::matcher::SipMatcher::new(&cli, cli.matching_args.match_expr.as_deref())
                    .map_err(|e| format!("matcher: {e:?}"))?;
            store.set_admission(Some(matcher));
            Ok(())
        },
        ..PLAIN
    };
    agree(&setup, || {
        Ok(vec![
            invite("i@example.com", 1)?,
            request("REGISTER", "g@example.com", 1, "z9hG4bK-g", t0()?)?,
            response(180, "i@example.com", 1, at(1)?)?,
        ])
    })?;
    Ok(())
}

/// A full store without rotation refuses a new call and its later messages.
#[test]
fn tracked_agrees_at_capacity_without_rotation() -> Result<(), TestError> {
    let setup = Setup {
        max_dialogs: 1,
        ..PLAIN
    };
    agree(&setup, || {
        Ok(vec![
            invite("a@example.com", 1)?,
            invite("b@example.com", 1)?,
            response(180, "b@example.com", 1, at(1)?)?,
            response(180, "a@example.com", 1, at(1)?)?,
        ])
    })?;
    Ok(())
}

/// Messages past a dialog's message cap are handed back; the dialog is
/// still found after each.
#[test]
fn tracked_agrees_past_the_message_cap() -> Result<(), TestError> {
    let setup = Setup { cap: 1, ..PLAIN };
    let answers = agree(&setup, || whole_call("c@example.com"))?;
    let last = answers.last().ok_or("an answer")?;
    assert!(last.returned.is_some(), "past the cap, handed back");
    assert_eq!(
        last.found,
        Some(Some(DialogAt {
            index: 0,
            exact: true
        })),
        "the dialog is still found"
    );
    Ok(())
}

// Edge cases.

/// A rotating store evicts, which moves every index: the answers follow.
#[test]
fn tracked_agrees_through_evictions() -> Result<(), TestError> {
    let setup = Setup {
        max_dialogs: 2,
        rotate: true,
        ..PLAIN
    };
    agree(&setup, || {
        let mut msgs = Vec::new();
        for n in 0..6 {
            let id = format!("e{n}@example.com");
            msgs.push(invite(&id, 1)?);
            msgs.push(response(180, &id, 1, at(1)?)?);
        }
        msgs.push(response(200, "e0@example.com", 1, at(2)?)?);
        msgs.push(response(200, "e5@example.com", 1, at(2)?)?);
        Ok(msgs)
    })?;
    Ok(())
}

/// A cap of zero keeps only each dialog's opening message.
#[test]
fn tracked_agrees_at_a_cap_of_zero() -> Result<(), TestError> {
    let setup = Setup { cap: 0, ..PLAIN };
    agree(&setup, || whole_call("z@example.com"))?;
    Ok(())
}

/// Branch tracking: `get` of a Call-ID finds the first unit, which may not
/// be the unit the message goes to. The answers still agree.
#[test]
fn tracked_agrees_under_branch_tracking() -> Result<(), TestError> {
    let setup = Setup {
        configure: |store| {
            store.set_tracking(DialogTracking::Branch);
            Ok(())
        },
        ..PLAIN
    };
    let answers = agree(&setup, || {
        Ok(vec![
            request("INVITE", "b@example.com", 1, "z9hG4bK-1", t0()?)?,
            request("BYE", "b@example.com", 2, "z9hG4bK-2", at(5)?)?,
            response(100, "b@example.com", 1, at(1)?)?,
            bye_ok("b@example.com")?,
        ])
    })?;
    let bye = answers.get(1).ok_or("an answer")?;
    assert_eq!(bye.stored, Some(1), "the BYE opens its own unit");
    assert_eq!(
        bye.before,
        Some(DialogState::Trying),
        "get found the INVITE's unit"
    );
    Ok(())
}

/// Branch tracking with a whole call and a second call.
#[test]
fn tracked_agrees_on_whole_calls_under_branch_tracking() -> Result<(), TestError> {
    let setup = Setup {
        configure: |store| {
            store.set_tracking(DialogTracking::Branch);
            Ok(())
        },
        ..PLAIN
    };
    agree(&setup, || {
        let mut msgs = whole_call("x@example.com")?;
        msgs.extend(whole_call("y@example.com")?);
        Ok(msgs)
    })?;
    Ok(())
}

// The cost: lookups of the dialog map per message.

/// The lookups one tracked message costs on `store`.
fn tracked_lookups(store: &mut DialogStore, msg: SipMessage) -> (usize, Tracked) {
    lookups_during(|| store.process_message_tracked_capped(msg, &SdpRead::Unread, ROOMY))
}

/// An in-dialog message costs one lookup: the store's own.
#[test]
fn a_tracked_in_dialog_message_costs_one_lookup() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    put(&mut store, invite("a@example.com", 1)?);
    let (lookups, tracked) =
        tracked_lookups(&mut store, response(180, "a@example.com", 1, at(1)?)?);
    stored_index(&tracked.placed)?;
    assert_eq!(lookups, 1, "one lookup answers all three questions");
    Ok(())
}

/// The message that opens a dialog costs one lookup: the miss.
#[test]
fn a_tracked_opening_message_costs_one_lookup() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let (lookups, tracked) = tracked_lookups(&mut store, invite("a@example.com", 1)?);
    stored_index(&tracked.placed)?;
    assert_eq!(lookups, 1, "one lookup for a new dialog");
    Ok(())
}

/// A message the method filter refuses costs one lookup.
#[test]
fn a_tracked_refused_message_costs_one_lookup() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.set_drop_methods(vec!["OPTIONS".to_string()]);
    let (lookups, tracked) = tracked_lookups(
        &mut store,
        request("OPTIONS", "o@example.com", 1, "z9hG4bK-o", t0()?)?,
    );
    returned(&tracked.placed)?;
    assert_eq!(lookups, 1, "one lookup for a refused message");
    Ok(())
}

/// A new call in a full rotating store costs one lookup, eviction included.
#[test]
fn a_tracked_message_that_evicts_costs_one_lookup() -> Result<(), TestError> {
    let mut store = DialogStore::new(1, true);
    put(&mut store, invite("a@example.com", 1)?);
    let (lookups, tracked) = tracked_lookups(&mut store, invite("b@example.com", 1)?);
    stored_index(&tracked.placed)?;
    assert_eq!(lookups, 1, "one lookup, eviction included");
    Ok(())
}

/// A message without a Call-ID costs no lookup.
#[test]
fn a_tracked_message_without_a_call_id_costs_no_lookup() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let (lookups, _) = tracked_lookups(&mut store, without_call_id()?);
    assert_eq!(lookups, 0, "nothing to look up");
    Ok(())
}

/// Branch tracking asks separately: `get` and `find_dialog` each look up the
/// bare Call-ID (a miss) and then the key of its first unit, and the store
/// looks up the unit's own key. Five lookups, and no scan of every key.
#[test]
fn a_tracked_message_under_branch_tracking_costs_five_lookups() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.set_tracking(DialogTracking::Branch);
    put(
        &mut store,
        request("INVITE", "a@example.com", 1, "z9hG4bK-1", t0()?)?,
    );
    let scans_before = super::prefix_scans_on_this_thread();
    let (lookups, _) = tracked_lookups(&mut store, response(100, "a@example.com", 1, at(1)?)?);
    assert_eq!(
        lookups, 5,
        "get and find_dialog two each, the store's own one"
    );
    assert_eq!(
        super::prefix_scans_on_this_thread() - scans_before,
        0,
        "no scan of every key"
    );
    Ok(())
}

// ── More paths, each differential against the old composition ────────

/// A response `status` to `method` CSeq `seq` of `call_id`, with top-Via
/// branch `branch`, sent at `ts`.
fn response_to(
    status: u16,
    method: &str,
    call_id: &str,
    seq: u32,
    branch: &str,
    ts: DateTime<Utc>,
) -> Result<SipMessage, TestError> {
    let raw = build_sip(
        &format!("SIP/2.0 {status} Status"),
        &[
            &format!("Via: SIP/2.0/UDP 192.0.2.10:5060;branch={branch}"),
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>;tag=t2",
            &format!("Call-ID: {call_id}"),
            &format!("CSeq: {seq} {method}"),
            "Content-Length: 0",
        ],
        b"",
    );
    parse(&raw, ts)
}

/// An INVITE whose Call-ID header line is `line`, exactly as written.
fn invite_with_call_id_line(line: &str) -> Result<SipMessage, TestError> {
    let raw = build_sip(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-raw",
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            line,
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    parse(&raw, t0()?)
}

/// Branch tracking, otherwise [`PLAIN`].
fn branch_tracking(store: &mut DialogStore) -> Result<(), TestError> {
    store.set_tracking(DialogTracking::Branch);
    Ok(())
}

// Success: more dialog kinds.

/// A REGISTER and its 200: a registration dialog.
#[test]
fn tracked_agrees_on_a_registration() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            request("REGISTER", "reg@example.com", 1, "z9hG4bK-r1", t0()?)?,
            response_to(401, "REGISTER", "reg@example.com", 1, "z9hG4bK-r1", at(0)?)?,
            request("REGISTER", "reg@example.com", 2, "z9hG4bK-r2", at(1)?)?,
            response_to(200, "REGISTER", "reg@example.com", 2, "z9hG4bK-r2", at(1)?)?,
        ])
    })?;
    Ok(())
}

/// A SUBSCRIBE, its 200, then a NOTIFY in the dialog.
#[test]
fn tracked_agrees_on_a_subscription() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            request("SUBSCRIBE", "sub@example.com", 1, "z9hG4bK-s1", t0()?)?,
            response_to(200, "SUBSCRIBE", "sub@example.com", 1, "z9hG4bK-s1", at(0)?)?,
            request("NOTIFY", "sub@example.com", 2, "z9hG4bK-s2", at(1)?)?,
            response_to(200, "NOTIFY", "sub@example.com", 2, "z9hG4bK-s2", at(1)?)?,
        ])
    })?;
    Ok(())
}

/// An OPTIONS ping and its 200.
#[test]
fn tracked_agrees_on_an_options_ping() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            request("OPTIONS", "opt@example.com", 1, "z9hG4bK-o1", t0()?)?,
            response_to(200, "OPTIONS", "opt@example.com", 1, "z9hG4bK-o1", at(0)?)?,
        ])
    })?;
    Ok(())
}

/// A call canceled while ringing: CANCEL, its 200, the 487.
#[test]
fn tracked_agrees_on_a_canceled_call() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            invite("can@example.com", 1)?,
            response(180, "can@example.com", 1, at(1)?)?,
            request("CANCEL", "can@example.com", 1, "z9hG4bK-1", at(2)?)?,
            response_to(200, "CANCEL", "can@example.com", 1, "z9hG4bK-1", at(2)?)?,
            response(487, "can@example.com", 1, at(2)?)?,
        ])
    })?;
    Ok(())
}

/// A call redirected by a 302.
#[test]
fn tracked_agrees_on_a_redirected_call() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            invite("red@example.com", 1)?,
            response(302, "red@example.com", 1, at(1)?)?,
            request("ACK", "red@example.com", 1, "z9hG4bK-1", at(1)?)?,
        ])
    })?;
    Ok(())
}

/// A call refused by a 486.
#[test]
fn tracked_agrees_on_a_failed_call() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            invite("busy@example.com", 1)?,
            response(100, "busy@example.com", 1, at(0)?)?,
            response(486, "busy@example.com", 1, at(1)?)?,
            request("ACK", "busy@example.com", 1, "z9hG4bK-1", at(1)?)?,
        ])
    })?;
    Ok(())
}

/// An answered call re-INVITEd in the dialog.
#[test]
fn tracked_agrees_on_a_re_invite() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            invite("re@example.com", 1)?,
            response(200, "re@example.com", 1, at(1)?)?,
            request("INVITE", "re@example.com", 2, "z9hG4bK-2", at(5)?)?,
            response(200, "re@example.com", 2, at(5)?)?,
        ])
    })?;
    Ok(())
}

/// An answered call transferred with REFER and its 202.
#[test]
fn tracked_agrees_on_a_transfer() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            invite("ref@example.com", 1)?,
            response(200, "ref@example.com", 1, at(1)?)?,
            request("REFER", "ref@example.com", 2, "z9hG4bK-2", at(5)?)?,
            response_to(202, "REFER", "ref@example.com", 2, "z9hG4bK-2", at(5)?)?,
        ])
    })?;
    Ok(())
}

// Failure: more refusals.

/// Under an admission matcher that admits INVITEs, a dialog's later
/// messages are kept and a call that starts mid-dialog is refused.
#[test]
fn tracked_agrees_when_admission_refuses_mid_dialog() -> Result<(), TestError> {
    let setup = Setup {
        configure: |store| {
            let cli = crate::cli::Cli::parse_from_args(["sipnab", "-e", "^INVITE"]);
            let matcher =
                crate::sip::matcher::SipMatcher::new(&cli, cli.matching_args.match_expr.as_deref())
                    .map_err(|e| format!("matcher: {e:?}"))?;
            store.set_admission(Some(matcher));
            Ok(())
        },
        ..PLAIN
    };
    agree(&setup, || {
        Ok(vec![
            invite("adm@example.com", 1)?,
            response(180, "adm@example.com", 1, at(1)?)?,
            response(180, "mid@example.com", 1, at(1)?)?,
            response(200, "adm@example.com", 1, at(2)?)?,
            response(200, "mid@example.com", 1, at(2)?)?,
        ])
    })?;
    Ok(())
}

/// A rotating store evicts a call, and a retransmission of its INVITE
/// arrives after: it opens the call again and evicts another.
#[test]
fn tracked_agrees_when_an_eviction_races_a_retransmission() -> Result<(), TestError> {
    let setup = Setup {
        max_dialogs: 2,
        rotate: true,
        ..PLAIN
    };
    agree(&setup, || {
        Ok(vec![
            invite("a@example.com", 1)?,
            invite("b@example.com", 1)?,
            invite("c@example.com", 1)?,
            invite("a@example.com", 1)?,
            response(180, "b@example.com", 1, at(1)?)?,
            response(180, "a@example.com", 1, at(1)?)?,
        ])
    })?;
    Ok(())
}

/// A cap of 3: the third message reaches it exactly and is stored, the
/// fourth and a retransmission of the third are handed back.
#[test]
fn tracked_agrees_when_the_cap_is_reached_exactly() -> Result<(), TestError> {
    let setup = Setup { cap: 3, ..PLAIN };
    let answers = agree(&setup, || {
        Ok(vec![
            invite("cap@example.com", 1)?,
            response(100, "cap@example.com", 1, at(0)?)?,
            response(180, "cap@example.com", 1, at(1)?)?,
            response(200, "cap@example.com", 1, at(2)?)?,
            response(180, "cap@example.com", 1, at(1)?)?,
        ])
    })?;
    let third = answers.get(2).ok_or("an answer")?;
    assert_eq!(
        third.stored,
        Some(0),
        "the message that reaches the cap is stored"
    );
    let fourth = answers.get(3).ok_or("an answer")?;
    assert!(fourth.returned.is_some(), "the next is handed back");
    Ok(())
}

/// A malformed Call-ID header (a value with no `@` and stray bytes) still
/// keys a dialog by the text as written.
#[test]
fn tracked_agrees_on_a_malformed_call_id() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            invite_with_call_id_line("Call-ID: <<not a call id>>;;")?,
            invite_with_call_id_line("Call-ID: <<not a call id>>;;")?,
            invite("ok@example.com", 1)?,
        ])
    })?;
    Ok(())
}

/// A copy of a stored message from another source is handed back, and the
/// dialog is still found.
#[test]
fn tracked_agrees_on_a_copy_from_another_source() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            from(invite("src@example.com", 1)?, InputOrigin::Wire),
            from(invite("src@example.com", 1)?, InputOrigin::Hep),
            from(
                response(180, "src@example.com", 1, at(1)?)?,
                InputOrigin::Wire,
            ),
        ])
    })?;
    Ok(())
}

/// A full store without rotation refuses several new calls, each counted
/// once, while the kept call goes on.
#[test]
fn tracked_agrees_when_capacity_refuses_many_calls() -> Result<(), TestError> {
    let setup = Setup {
        max_dialogs: 1,
        ..PLAIN
    };
    agree(&setup, || {
        let mut msgs = vec![invite("kept@example.com", 1)?];
        for n in 0..5 {
            let id = format!("refused{n}@example.com");
            msgs.push(invite(&id, 1)?);
            msgs.push(invite(&id, 1)?);
        }
        msgs.push(response(200, "kept@example.com", 1, at(2)?)?);
        Ok(msgs)
    })?;
    Ok(())
}

/// The method filter refuses a Call-ID by its first message; an INVITE of
/// the same Call-ID later is refused too.
#[test]
fn tracked_agrees_when_a_refused_call_id_sends_an_invite() -> Result<(), TestError> {
    let setup = Setup {
        configure: |store| {
            store.set_drop_methods(vec!["OPTIONS".to_string()]);
            Ok(())
        },
        ..PLAIN
    };
    agree(&setup, || {
        Ok(vec![
            request("OPTIONS", "same@example.com", 1, "z9hG4bK-o", t0()?)?,
            invite("same@example.com", 2)?,
            response(200, "same@example.com", 2, at(1)?)?,
        ])
    })?;
    Ok(())
}

/// A response with no CSeq for a dialog the store holds.
#[test]
fn tracked_agrees_on_an_in_dialog_message_without_a_cseq() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            invite("nc@example.com", 1)?,
            response_without_cseq("nc@example.com")?,
            response(200, "nc@example.com", 1, at(1)?)?,
        ])
    })?;
    Ok(())
}

// Edge cases: odd keys and sizes.

/// A store of one dialog with rotation: every new call evicts the last.
#[test]
fn tracked_agrees_at_capacity_one_with_rotation() -> Result<(), TestError> {
    let setup = Setup {
        max_dialogs: 1,
        rotate: true,
        ..PLAIN
    };
    agree(&setup, || {
        let mut msgs = Vec::new();
        for n in 0..4 {
            let id = format!("one{n}@example.com");
            msgs.push(invite(&id, 1)?);
            msgs.push(response(180, &id, 1, at(1)?)?);
        }
        msgs.push(response(200, "one0@example.com", 1, at(2)?)?);
        Ok(msgs)
    })?;
    Ok(())
}

/// A Call-ID header with an empty value.
#[test]
fn tracked_agrees_on_an_empty_call_id() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            invite_with_call_id_line("Call-ID:")?,
            invite_with_call_id_line("Call-ID: ")?,
            invite("after-empty@example.com", 1)?,
        ])
    })?;
    Ok(())
}

/// Call-IDs that differ only in letter case are two keys.
#[test]
fn tracked_agrees_on_call_ids_that_differ_in_case() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            invite("Case@Example.com", 1)?,
            invite("case@example.com", 1)?,
            response(180, "CASE@EXAMPLE.COM", 1, at(1)?)?,
            response(180, "case@example.com", 1, at(1)?)?,
        ])
    })?;
    Ok(())
}

/// Call-IDs that differ only in surrounding or inner whitespace.
#[test]
fn tracked_agrees_on_call_ids_that_differ_in_whitespace() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            invite_with_call_id_line("Call-ID: ws@example.com")?,
            invite_with_call_id_line("Call-ID:    ws@example.com   ")?,
            invite_with_call_id_line("Call-ID: ws @example.com")?,
            invite_with_call_id_line("Call-ID:\tws@example.com")?,
        ])
    })?;
    Ok(())
}

/// Ten thousand calls, interleaved in waves of 100.
#[test]
fn tracked_agrees_on_ten_thousand_interleaved_calls() -> Result<(), TestError> {
    let setup = Setup {
        max_dialogs: 20_000,
        ..PLAIN
    };
    let answers = agree(&setup, || {
        let mut msgs = Vec::new();
        for wave in 0..100 {
            for step in 0..3 {
                for n in 0..100 {
                    let id = format!("w{wave}-{n}@example.com");
                    msgs.push(match step {
                        0 => invite(&id, 1)?,
                        1 => response(180, &id, 1, at(1)?)?,
                        _ => response(200, &id, 1, at(2)?)?,
                    });
                }
            }
        }
        Ok(msgs)
    })?;
    assert_eq!(answers.len(), 30_000, "every message answered");
    Ok(())
}

/// Branch tracking with Call-IDs where one is a prefix of another: the
/// `Call-ID` + newline prefix keeps them apart.
#[test]
fn tracked_agrees_under_branch_tracking_with_a_prefix_collision() -> Result<(), TestError> {
    let setup = Setup {
        configure: branch_tracking,
        ..PLAIN
    };
    agree(&setup, || {
        Ok(vec![
            request("INVITE", "p@example.com.x", 1, "z9hG4bK-1", t0()?)?,
            request("INVITE", "p@example.com", 1, "z9hG4bK-1", at(1)?)?,
            response(100, "p@example.com", 1, at(1)?)?,
            request("BYE", "p@example.com.x", 2, "z9hG4bK-2", at(5)?)?,
            response(100, "p@example.com.x", 1, at(6)?)?,
        ])
    })?;
    Ok(())
}

/// Branch tracking with messages that carry no branch: they key by the
/// Call-ID alone, next to units keyed by branch.
#[test]
fn tracked_agrees_under_branch_tracking_without_branches() -> Result<(), TestError> {
    let setup = Setup {
        configure: branch_tracking,
        ..PLAIN
    };
    agree(&setup, || {
        Ok(vec![
            response_without_cseq("nb@example.com")?,
            request("INVITE", "nb@example.com", 1, "", t0()?)?,
            request("INVITE", "nb@example.com", 2, "z9hG4bK-2", at(1)?)?,
            response(100, "nb@example.com", 2, at(1)?)?,
        ])
    })?;
    Ok(())
}

/// A Call-ID of 2,000 characters.
#[test]
fn tracked_agrees_on_a_very_long_call_id() -> Result<(), TestError> {
    let long = format!("{}@example.com", "x".repeat(2_000));
    agree(&PLAIN, || {
        Ok(vec![invite(&long, 1)?, response(200, &long, 1, at(1)?)?])
    })?;
    Ok(())
}

/// A Call-ID with non-ASCII characters.
#[test]
fn tracked_agrees_on_a_non_ascii_call_id() -> Result<(), TestError> {
    agree(&PLAIN, || {
        Ok(vec![
            invite("çå-ü@example.com", 1)?,
            response(180, "çå-ü@example.com", 1, at(1)?)?,
            invite("ca-u@example.com", 1)?,
        ])
    })?;
    Ok(())
}
