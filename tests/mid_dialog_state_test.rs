// SPDX-License-Identifier: MIT OR Apache-2.0

//! A capture that begins mid-dialog must still report how the call ended.
//!
//! Starting a capture while calls are already up is the normal way this tool
//! is used, and it is the case the dialog state machine used to get wrong: the
//! first message of a call was then a `BYE` or a `CANCEL`, `SipDialog::new`
//! labeled the dialog with that method, and `update_state` dispatched on the
//! label — so every later message went to the generic handler, which inspects
//! only responses and has no rule for either request. The call sat at `Trying`,
//! reported as still in progress, with a complete message log to make it look
//! right.
//!
//! Every test here drives [`DialogStore::process_message`], the live path, and
//! asserts the state an operator is shown plus the two gauges that state feeds.
//! Asserting the state alone would miss the part that costs money: `Trying` is
//! in the active set and is not `InCall`, so a mid-dialog-seeded call is wrong
//! in both directions on the numbers an operator graphs.
//!
//! # The trap this file also pins
//!
//! The obvious fix — route a `BYE` or `CANCEL` to the INVITE machine, since
//! neither can open a dialog (RFC 3261 §9, §15) — is right about the machine
//! and wrong if it stops there. The INVITE machine's `2xx` arm answers the
//! call, and a `BYE` and a `CANCEL` each have a `2xx` of their own. Dispatching
//! on the dialog FAMILY alone therefore lets `200 OK (CSeq 1 CANCEL)` walk into
//! the arm that means "the callee picked up", and a canceled call reports
//! `InCall`. `a_200_to_the_cancel_does_not_answer_the_call` and
//! `a_capture_opening_on_the_200_to_a_bye_reports_the_call_completed` are that
//! cell, in both directions.
#![cfg(feature = "native")]

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, TimeZone, Utc};
use sipnab::DialogStore;
use sipnab::net::TransportProto;
use sipnab::sip::dialog::DialogState;
use sipnab::sip::message::SipMessage;
use sipnab::sip::parser::parse_sip_bytes;

const CALLER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
const CALLEE: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));

/// The Call-ID every message below shares — one call, seen from its middle.
const CALL_ID: &str = "mid-dialog@198.51.100.10";

/// Both tags are present on every message: a capture that opens mid-dialog
/// sees a confirmed dialog, never the tagless early one.
const IDENTITY: &str = "From: <sip:1001@198.51.100.10>;tag=caller-tag\r\n\
     To: <sip:1002@198.51.100.20>;tag=callee-tag\r\n\
     Call-ID: mid-dialog@198.51.100.10\r\n";

/// Parse one hand-written message at `offset_ms` past a fixed base time.
///
/// `from_caller` picks the direction, so the store sees a two-sided
/// conversation rather than one address talking to itself.
fn msg(offset_ms: i64, from_caller: bool, raw: String) -> SipMessage {
    let base: DateTime<Utc> = Utc
        .with_ymd_and_hms(2026, 3, 4, 9, 0, 0)
        .single()
        .expect("valid base timestamp");
    let (src, dst) = if from_caller {
        (CALLER, CALLEE)
    } else {
        (CALLEE, CALLER)
    };
    parse_sip_bytes(
        &bytes::Bytes::from(raw),
        base + chrono::Duration::milliseconds(offset_ms),
        src,
        dst,
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("hand-written fixture must parse")
}

/// A request of `method` at `offset_ms`, sent by the caller.
fn request(offset_ms: i64, method: &str, cseq: u32) -> SipMessage {
    msg(
        offset_ms,
        true,
        format!(
            "{method} sip:1002@198.51.100.20 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-{method}\r\n\
             {IDENTITY}CSeq: {cseq} {method}\r\nContent-Length: 0\r\n\r\n"
        ),
    )
}

/// A response at `offset_ms` whose CSeq names `cseq_method`, sent by the
/// callee. The CSeq method is the transaction the response belongs to, and it
/// is the coordinate the whole file turns on.
fn response(offset_ms: i64, code: u16, reason: &str, cseq: u32, cseq_method: &str) -> SipMessage {
    msg(
        offset_ms,
        false,
        format!(
            "SIP/2.0 {code} {reason}\r\n\
             Via: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-{cseq_method}\r\n\
             {IDENTITY}CSeq: {cseq} {cseq_method}\r\nContent-Length: 0\r\n\r\n"
        ),
    )
}

/// Feed `msgs` to a fresh store in the order given and report the dialog's
/// state together with the two counts published from it.
fn replay(msgs: Vec<SipMessage>) -> (DialogState, usize, usize) {
    let mut store = DialogStore::new(64, false);
    let last = msgs.last().expect("at least one message").timestamp;
    for m in msgs {
        store.process_message(m);
    }
    let dialog = store
        .get(CALL_ID)
        .expect("a mid-dialog capture still yields a dialog");
    let state = dialog.state().clone();
    (
        state,
        store.active_dialog_count_at(last),
        store.active_call_count_at(last),
    )
}

/// The capture opens on the `BYE`: the call ended normally and the store must
/// say so, not report it as still being set up.
///
/// RFC 3261 §15.1.1 — a `BYE` terminates an established session, so the only
/// dialog a `BYE` can belong to is an INVITE one, and its arrival is proof the
/// call is over.
#[test]
fn a_capture_opening_on_a_bye_reports_the_call_completed() {
    // The BYE alone, before its answer: the request is itself the evidence,
    // and asserting only the two-message case would pass on a machine that
    // ignored the BYE and read the 200 that followed it.
    let (on_the_bye, _, _) = replay(vec![request(0, "BYE", 2)]);
    assert_eq!(
        on_the_bye,
        DialogState::Completed,
        "the BYE itself ends the call; nothing later is needed to say so"
    );

    let (state, active_dialogs, active_calls) = replay(vec![
        request(0, "BYE", 2),
        response(20, 200, "OK", 2, "BYE"),
    ]);
    assert_eq!(
        state,
        DialogState::Completed,
        "a capture opening on the BYE must report the call as completed"
    );
    assert_eq!(
        active_dialogs, 0,
        "a completed call is not an active dialog; leaving it in `Trying` \
         inflates the gauge an operator alerts on"
    );
    assert_eq!(
        active_calls, 0,
        "a completed call is not a call in progress"
    );
}

/// The capture opens on the `CANCEL`: the caller gave up, and the 487 that
/// follows belongs to the INVITE transaction, not to the `CANCEL`.
///
/// RFC 3261 §9.1 — `CANCEL` has no meaning outside a pending INVITE.
#[test]
fn a_capture_opening_on_a_cancel_reports_the_call_cancelled() {
    let (state, active_dialogs, active_calls) = replay(vec![
        request(0, "CANCEL", 1),
        response(50, 487, "Request Terminated", 1, "INVITE"),
    ]);
    assert_eq!(
        state,
        DialogState::Canceled,
        "a capture opening on the CANCEL must report the call as canceled"
    );
    assert_eq!(active_dialogs, 0, "a canceled call is not an active dialog");
    assert_eq!(
        active_calls, 0,
        "a canceled call was never a call in progress"
    );
}

/// The `200 OK` acknowledging a `CANCEL` must not be read as the callee
/// answering.
///
/// This is the cell a family-only dispatch gets wrong. `CANCEL` belongs to the
/// INVITE dialog family, so a fix that dispatches on family alone routes this
/// `200` into the arm that means "the call was established" and reports a
/// canceled call as `InCall` — a worse answer than the `Trying` it replaced,
/// because `InCall` is counted as a live channel. The response's CSeq method,
/// not its family, says which transaction it answers (RFC 3261 §8.1.1.5).
#[test]
fn a_200_to_the_cancel_does_not_answer_the_call() {
    let (state, _, active_calls) = replay(vec![
        request(0, "CANCEL", 1),
        response(10, 200, "OK", 1, "CANCEL"),
        response(50, 487, "Request Terminated", 1, "INVITE"),
    ]);
    assert_eq!(
        state,
        DialogState::Canceled,
        "the 200 answers the CANCEL transaction, not the INVITE — the call \
         was canceled and must not report as established"
    );
    assert_eq!(
        active_calls, 0,
        "reporting a canceled call as a live channel is worse than reporting \
         it as still ringing"
    );
}

/// The capture opens on the `200 OK` to a `BYE`, with the `BYE` itself before
/// the first captured packet.
///
/// The dialog method comes from the response's CSeq, so this is a `BYE`-seeded
/// dialog whose only message is a `2xx`. It must report `Completed` — and in
/// particular must not report `InCall`, which is where a family-only dispatch
/// sends it.
#[test]
fn a_capture_opening_on_the_200_to_a_bye_reports_the_call_completed() {
    let (state, active_dialogs, active_calls) = replay(vec![response(0, 200, "OK", 2, "BYE")]);
    assert_eq!(
        state,
        DialogState::Completed,
        "a 200 to a BYE ends a call; it does not establish one"
    );
    assert_eq!(active_dialogs, 0, "the call is over");
    assert_eq!(
        active_calls, 0,
        "a 200 to a BYE must never count as a channel in use"
    );
}

/// A call whose `BYE` was lost still ends, because the `200` answering that
/// `BYE` is proof the far end terminated the session.
///
/// RFC 3261 §15.1.2 — the UAS answers a `BYE` only after ending the session,
/// so the `2xx` is evidence about the call even though it answers a different
/// transaction. Without this cell an answered call whose `BYE` fell outside the
/// capture — a dropped UDP packet, a one-directional tap, a rotated file — sits
/// in `InCall` and is counted as a channel in use for as long as the store
/// keeps it, which is the failure mode `active_call_count` exists to avoid.
#[test]
fn a_call_whose_bye_was_missed_still_ends_on_the_200_that_answered_it() {
    let (state, _, active_calls) = replay(vec![
        response(0, 200, "OK", 1, "INVITE"),
        request(10, "ACK", 1),
        // The BYE itself is absent — only the answer to it was captured.
        response(60_000, 200, "OK", 2, "BYE"),
    ]);
    assert_eq!(
        state,
        DialogState::Completed,
        "the 200 answering a BYE is proof the session ended"
    );
    assert_eq!(
        active_calls, 0,
        "a call that ended must leave the concurrent-call figure"
    );
}

/// A late `487` cannot un-answer a call the capture saw answered, and a `2xx`
/// to the INVITE still wins a race with a `CANCEL`.
///
/// RFC 3261 §9.1 and §15 — once the UAS has sent a final `2xx` the `CANCEL`
/// has no effect. Kept here because the mid-dialog dispatch is the change most
/// likely to break it: both messages now reach the same machine from a
/// `CANCEL`-seeded dialog.
#[test]
fn a_2xx_beats_the_cancel_and_a_later_487_does_not_undo_it() {
    let (state, _, active_calls) = replay(vec![
        request(0, "CANCEL", 1),
        response(30, 200, "OK", 1, "INVITE"),
        response(60, 487, "Request Terminated", 1, "INVITE"),
    ]);
    assert_eq!(
        state,
        DialogState::InCall,
        "the callee answered before the CANCEL landed; the call is up"
    );
    assert_eq!(active_calls, 1, "an answered call is a channel in use");
}

/// An `ACK`-seeded dialog stays in setup rather than claiming an outcome it
/// never observed.
///
/// An `ACK` proves the INVITE got a final response, but not which one, so
/// nothing here says the call was answered, failed or ended. What it must NOT
/// do is take an outcome from a response that belongs to some other
/// transaction: before this change a `200` whose CSeq said `ACK` reported the
/// call `Completed`, which is a statement about a call nobody watched end.
#[test]
fn an_ack_seeded_dialog_claims_no_outcome_from_a_response_to_the_ack() {
    let (state, _, _) = replay(vec![
        request(0, "ACK", 1),
        response(10, 200, "OK", 1, "ACK"),
    ]);
    assert_eq!(
        state,
        DialogState::Trying,
        "nothing observed says how this call ended, so nothing may claim it did"
    );
}
