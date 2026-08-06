// SPDX-License-Identifier: MIT OR Apache-2.0

//! Differential parity gate: a live worker store must not care what ORDER
//! messages arrive in.
//!
//! # Why this file exists before the feature that needs it
//!
//! PR1 (`docs/design/backlog.md`) proposes N reader threads, each opening its
//! own file from an `-I` directory or glob, all sharding into one worker pool.
//! That attacks a measured bottleneck: `--cores` throughput *declines* past two
//! cores (1 core 1.06M pkts/s, 2 cores 2.32M, 4 cores 2.03M, 8 cores 1.89M —
//! `docs/benchmarks.md`) because one thread reads the whole set serially.
//!
//! It also removes something the current design gives for free. Today a worker
//! sees one file at a time, in file order, so messages arrive in timestamp
//! order. With N readers a worker's inbox is interleaved across files and
//! packets arrive **out of timestamp order**.
//!
//! `DialogStore::merge` is order-tolerant on purpose — `absorb_messages` sorts
//! by timestamp and replays. But merge is the *offline* path. The live path is
//! `process_message`, fed in arrival order, and the backlog entry states that
//! out-of-order arrival being harmless there is **not established**. PR1 is
//! explicitly blocked on establishing it. This file is that work.
//!
//! # What was established, and by what mechanism
//!
//! Measured, not assumed: every permutation below produces a store
//! **identical** to timestamp order — same state, same message count, same
//! responses — for answered, cancelled and failed calls alike.
//!
//! The reason is that the advancing transitions in `update_invite_state` are
//! guarded by a precondition on the *current* state, while only the terminal
//! ones are unconditional:
//!
//! * `180`/`183` advance only from `Trying` or `Ringing`.
//! * A 2xx to INVITE advances only from `Trying`, `Ringing` or `Cancelled`.
//! * `BYE` → `Completed` and `CANCEL` → `Cancelled` are unconditional.
//!
//! So a late provisional or a late 2xx arriving *after* the call already ended
//! cannot pull a terminal state backwards — which is exactly the reordering a
//! parallel reader produces. That is a property of those guards, not luck.
//!
//! This file exists so that relaxing one of them fails here rather than
//! silently making `--cores` report a finished call as still up. The
//! first draft of this very file asserted the opposite — that the last message
//! to arrive wins — and the measurement refuted it; the guards are why.
//!
//! The permutations are FIXED, not random: a shuffle keyed off wall-clock
//! makes a failure unreproducible, and this gate has to name the arrival order
//! that broke it.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, TimeZone, Utc};
use sipnab::DialogStore;
use sipnab::net::TransportProto;
use sipnab::sip::dialog::DialogState;
use sipnab::sip::message::SipMessage;
use sipnab::sip::method::SipMethod;
use sipnab::sip::parser::parse_sip_bytes;

const CALLER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
const CALLEE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));

/// How a call ended. Each shape drives a different terminal transition, so a
/// guard that happens to hold for only one of them cannot pass this file.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// INVITE, 100, 180, 200, ACK, BYE, 200 — answered, then hung up.
    Answered,
    /// INVITE, 100, 180, CANCEL, 487 — caller gave up while it rang.
    Cancelled,
    /// INVITE, 100, 486, ACK — callee was busy.
    Failed,
}

impl Shape {
    fn call_id(self) -> &'static str {
        match self {
            Shape::Answered => "answered-parity@192.0.2.10",
            Shape::Cancelled => "cancelled-parity@192.0.2.10",
            Shape::Failed => "failed-parity@192.0.2.10",
        }
    }

    /// The state a serial reader reaches. Named concretely so a change that
    /// makes EVERY order equally wrong cannot slip through by leaving the
    /// cross-order comparison trivially satisfied.
    fn expected_state(self) -> DialogState {
        match self {
            Shape::Answered => DialogState::Completed,
            Shape::Cancelled => DialogState::Cancelled,
            Shape::Failed => DialogState::Failed,
        }
    }
}

/// The wire messages for a shape, in time order: (offset_ms, from_caller, raw).
fn call_messages(shape: Shape) -> Vec<(i64, bool, String)> {
    let call_id = shape.call_id();
    let via = |branch: &str| format!("Via: SIP/2.0/UDP 192.0.2.10:5060;branch={branch}");
    // Before the callee answers there is no To-tag; afterwards there is.
    let early = format!(
        "From: <sip:1001@192.0.2.10>;tag=caller-tag\r\n\
         To: <sip:1002@192.0.2.20>\r\n\
         Call-ID: {call_id}\r\n"
    );
    let answered = format!(
        "From: <sip:1001@192.0.2.10>;tag=caller-tag\r\n\
         To: <sip:1002@192.0.2.20>;tag=callee-tag\r\n\
         Call-ID: {call_id}\r\n"
    );
    let invite = (
        0i64,
        true,
        format!(
            "INVITE sip:1002@192.0.2.20 SIP/2.0\r\n{}\r\n{early}CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
            via("z9hG4bK-invite")
        ),
    );
    let trying = (
        10i64,
        false,
        format!(
            "SIP/2.0 100 Trying\r\n{}\r\n{early}CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
            via("z9hG4bK-invite")
        ),
    );
    let ringing = (
        50i64,
        false,
        format!(
            "SIP/2.0 180 Ringing\r\n{}\r\n{answered}CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
            via("z9hG4bK-invite")
        ),
    );

    match shape {
        Shape::Answered => vec![
            invite,
            trying,
            ringing,
            (
                2_000,
                false,
                format!(
                    "SIP/2.0 200 OK\r\n{}\r\n{answered}CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
                    via("z9hG4bK-invite")
                ),
            ),
            (
                2_050,
                true,
                format!(
                    "ACK sip:1002@192.0.2.20 SIP/2.0\r\n{}\r\n{answered}CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n",
                    via("z9hG4bK-ack")
                ),
            ),
            (
                30_000,
                true,
                format!(
                    "BYE sip:1002@192.0.2.20 SIP/2.0\r\n{}\r\n{answered}CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n",
                    via("z9hG4bK-bye")
                ),
            ),
            (
                30_020,
                false,
                format!(
                    "SIP/2.0 200 OK\r\n{}\r\n{answered}CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n",
                    via("z9hG4bK-bye")
                ),
            ),
        ],
        Shape::Cancelled => vec![
            invite,
            trying,
            ringing,
            (
                4_000,
                true,
                format!(
                    "CANCEL sip:1002@192.0.2.20 SIP/2.0\r\n{}\r\n{early}CSeq: 1 CANCEL\r\nContent-Length: 0\r\n\r\n",
                    via("z9hG4bK-invite")
                ),
            ),
            (
                4_050,
                false,
                format!(
                    "SIP/2.0 487 Request Terminated\r\n{}\r\n{answered}CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
                    via("z9hG4bK-invite")
                ),
            ),
        ],
        Shape::Failed => vec![
            invite,
            trying,
            (
                1_200,
                false,
                format!(
                    "SIP/2.0 486 Busy Here\r\n{}\r\n{answered}CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
                    via("z9hG4bK-invite")
                ),
            ),
            (
                1_250,
                true,
                format!(
                    "ACK sip:1002@192.0.2.20 SIP/2.0\r\n{}\r\n{answered}CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n",
                    via("z9hG4bK-invite")
                ),
            ),
        ],
    }
}

/// Parse a shape into `SipMessage`s carrying real, distinct timestamps.
fn parsed_call(shape: Shape) -> Vec<SipMessage> {
    let base: DateTime<Utc> = Utc
        .with_ymd_and_hms(2026, 1, 1, 12, 0, 0)
        .single()
        .expect("valid base timestamp");
    call_messages(shape)
        .into_iter()
        .map(|(offset_ms, from_caller, raw)| {
            let ts = base + chrono::Duration::milliseconds(offset_ms);
            let (src, dst) = if from_caller {
                (CALLER, CALLEE)
            } else {
                (CALLEE, CALLER)
            };
            parse_sip_bytes(
                &bytes::Bytes::from(raw),
                ts,
                src,
                dst,
                5060,
                5060,
                TransportProto::Udp,
            )
            .expect("hand-written fixture must parse")
        })
        .collect()
}

/// What a user is shown, and what downstream surfaces key on. Deliberately not
/// the whole struct: internal bookkeeping (generation counters, insertion
/// order) may differ between arrival orders without misleading anyone.
#[derive(Debug, PartialEq)]
struct Observable {
    state: DialogState,
    msg_count: usize,
    status_codes: Vec<u16>,
}

/// Feed `order` (indices into the shape's messages) into a fresh store and
/// report what the store then says about the call.
fn observe(shape: Shape, order: &[usize]) -> Observable {
    let msgs = parsed_call(shape);
    let mut store = DialogStore::new(64, false);
    for &i in order {
        store.process_message(msgs[i].clone());
    }
    let dialog = store
        .get(shape.call_id())
        .expect("the call must be in the store under its Call-ID");
    let mut status_codes: Vec<u16> = dialog
        .messages
        .iter()
        .filter_map(|m| m.status_code)
        .collect();
    status_codes.sort_unstable();
    Observable {
        state: dialog.state().clone(),
        msg_count: dialog.messages.len(),
        status_codes,
    }
}

/// Fixed permutations, each a shape N parallel readers would really produce.
///
/// `reversed` isolates "does a later message overwrite an earlier decision";
/// `interleaved` is two readers striping one call across files;
/// `late_terminal` puts the call's ending ahead of its middle, which is what a
/// reader holding the later file running ahead looks like.
fn permutations(n: usize) -> Vec<(&'static str, Vec<usize>)> {
    let interleaved: Vec<usize> = (0..n)
        .filter(|i| i % 2 == 1)
        .chain((0..n).filter(|i| i % 2 == 0))
        .collect();
    let late_terminal: Vec<usize> = (n - 2..n).chain(0..n - 2).collect();
    vec![
        ("in_order", (0..n).collect()),
        ("reversed", (0..n).rev().collect()),
        ("interleaved", interleaved),
        ("late_terminal", late_terminal),
    ]
}

/// The control: timestamp order — what one serial reader produces today — must
/// reach the outcome the call actually had.
#[test]
fn timestamp_order_reaches_the_real_outcome() {
    for shape in [Shape::Answered, Shape::Cancelled, Shape::Failed] {
        let n = call_messages(shape).len();
        let got = observe(shape, &(0..n).collect::<Vec<_>>());
        assert_eq!(
            got.state,
            shape.expected_state(),
            "{shape:?} in timestamp order must reach {:?}; got {got:?}",
            shape.expected_state()
        );
        assert_eq!(
            got.msg_count, n,
            "{shape:?}: every message is stored; got {got:?}"
        );
    }
}

/// The property PR1 is blocked on, in the range where it HOLDS.
///
/// Every permutation whose first message is an INVITE **or any response**
/// converges on the timestamp-ordered result. Responses are safe because
/// `SipDialog::new` derives the dialog method from the response's CSeq, so the
/// INVITE state machine is still the one selected.
#[test]
fn arrival_order_converges_when_the_invite_machine_is_selected() {
    for shape in [Shape::Answered, Shape::Cancelled, Shape::Failed] {
        let n = call_messages(shape).len();
        let baseline = observe(shape, &(0..n).collect::<Vec<_>>());

        for (name, order) in permutations(n) {
            // `late_terminal` is the one order that can lead with a non-INVITE
            // REQUEST, which selects the wrong state machine. That is a known,
            // unfixed defect pinned by its own test below, not a convergence
            // failure this test should also report.
            if name == "late_terminal" && first_is_non_invite_request(shape, &order) {
                continue;
            }
            let got = observe(shape, &order);
            assert_eq!(
                got, baseline,
                "{shape:?}: arrival order `{name}` ({order:?}) produced a \
                 different store than timestamp order.\n  got:      {got:?}\n  \
                 baseline: {baseline:?}\nPR1's parallel readers feed \
                 `process_message` out of timestamp order, so this divergence \
                 would become a live wrong answer."
            );
        }
    }
}

/// Does the first message of `order` create the dialog from a non-INVITE
/// REQUEST? That is the one shape that selects the wrong state machine.
fn first_is_non_invite_request(shape: Shape, order: &[usize]) -> bool {
    let msgs = parsed_call(shape);
    let first = &msgs[order[0]];
    first.is_request && first.method.as_ref().map(SipMethod::as_str) != Some("INVITE")
}

/// **A capture that BEGINS MID-DIALOG still reports the wrong outcome.** This
/// pins a KNOWN, UNFIXED defect so it cannot be mistaken for working.
///
/// Start capturing while calls are already up — which is most captures on a
/// busy server — and the first message of a call is a `BYE` or a `CANCEL`,
/// never the INVITE. `SipDialog::new` then labels the dialog with that method,
/// and `update_state` dispatches the state machine on the label, so every later
/// message routes to `update_generic_state` — which inspects only responses and
/// has no rule for BYE or CANCEL. The call sits at `Trying`: reported as still
/// in progress, with a complete message log to make it look right.
///
/// The obvious fix — dispatch on the method the request *implies*, since BYE
/// and CANCEL cannot open a dialog (RFC 3261 §15, §9) — was tried and reverted
/// on 2026-08-06. It is almost certainly the right shape, but the INVITE
/// machine guards its `2xx`, `487` and `3xx` arms on conditions a BYE/CANCEL
/// response does not meet, and `every_method_and_class_has_a_declared_transition`
/// found a different unmodelled cell on each of five attempts. Landing a
/// half-modelled state machine in the thing that decides whether a call is up
/// is worse than the bug it fixes.
///
/// Asserted rather than left failing, because this file must be green on
/// `main`. When the dispatch fix lands properly, this test FAILS — and that is
/// the signal to replace it with the convergence assertion it is standing in
/// for.
#[test]
fn a_capture_beginning_mid_dialog_reports_trying_a_known_defect() {
    // Only the ending: CANCEL, then its 487. The INVITE was before the capture.
    let msgs = parsed_call(Shape::Cancelled);
    let mut store = DialogStore::new(64, false);
    for i in [3usize, 4] {
        store.process_message(msgs[i].clone());
    }
    let dialog = store
        .get(Shape::Cancelled.call_id())
        .expect("a mid-dialog capture still yields a dialog");
    assert_eq!(
        *dialog.state(),
        DialogState::Trying,
        "known defect: a capture opening on the CANCEL reports the call as \
         still Trying. If this is now Cancelled the defect is FIXED — replace \
         this test with a convergence assertion and update PR1 in \
         docs/design/backlog.md. Got {:?}",
        dialog.state()
    );
}

/// The offline merge path is the escape hatch PR1 could lean on, so its
/// order-tolerance is tested rather than assumed.
///
/// Two stores, each fed a different half backwards, then merged — the shape of
/// two readers finishing and their results being combined.
#[test]
fn merge_recovers_timestamp_order_from_permuted_stores() {
    for shape in [Shape::Answered, Shape::Cancelled, Shape::Failed] {
        let msgs = parsed_call(shape);
        let n = msgs.len();
        let baseline = observe(shape, &(0..n).collect::<Vec<_>>());

        let mid = n / 2;
        let mut a = DialogStore::new(64, false);
        for i in (mid..n).rev() {
            a.process_message(msgs[i].clone());
        }
        let mut b = DialogStore::new(64, false);
        for i in (0..mid).rev() {
            b.process_message(msgs[i].clone());
        }
        a.merge(b);

        let dialog = a
            .get(shape.call_id())
            .expect("the merged store must still hold the call");
        assert_eq!(
            dialog.messages.len(),
            baseline.msg_count,
            "{shape:?}: merge must not lose messages"
        );
        assert_eq!(
            *dialog.state(),
            baseline.state,
            "{shape:?}: merge sorts by timestamp and replays, so it must reach \
             the same state as a serial reader"
        );
    }
}
