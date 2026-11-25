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

use super::{DialogAt, DialogStore, DialogTracking, Placed, key_lookups_on_this_thread};
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

/// `process_message_placed` applies the store's cap and answers `Stored`.
#[test]
fn process_message_placed_answers_stored() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let placed = store.process_message_placed(invite("a@example.com", 1)?, &SdpRead::Unread);
    assert_eq!(stored_index(&placed)?, 0, "stored under the default cap");
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
