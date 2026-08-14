// SPDX-License-Identifier: MIT OR Apache-2.0

//! The dialog transition table: one total function, no wildcard arms.
//!
//! [`update_state`](super::dialog::update_state) used to be four handlers
//! chosen by the method that happened to open the dialog, each restating its
//! own ranges inline. That key is wrong twice over, and both errors show up on
//! the same traffic: a capture that starts while calls are already up.
//!
//! # The two coordinates a SIP response actually has
//!
//! **Which machine.** A `BYE` or a `CANCEL` cannot open a dialog (RFC 3261
//! §9.1, §15.1), so a dialog seeded by one is an INVITE dialog seen from its
//! middle. Dispatching on the seed sent those to a handler that inspects only
//! responses and has no rule for either request, and the call reported `Trying`
//! forever. [`family_of_seed`] is that correction, and it is the whole of it:
//! the seed method is still what the user is shown, and the dialog's initial
//! state is still whatever [`SipDialog::new`](super::dialog::SipDialog::new)
//! chose.
//!
//! **Which transaction.** Family is not enough, and this is the part that
//! makes the obvious fix worse than the defect it closes. `INVITE`, `ACK`,
//! `BYE`, `CANCEL` and `PRACK` all belong to the INVITE family, and four of
//! them carry responses of their own. A `2xx` means "the callee picked up"
//! only when it answers the INVITE transaction; the same code answering a
//! `CANCEL` means "your cancellation was received", and answering a `BYE`
//! means "the call you already ended is ended". Route by family alone and
//! `200 OK (CSeq 1 CANCEL)` lands in the arm that establishes a call — so a
//! cancelled call reports `InCall`, counted as a live channel. The response's
//! CSeq method names its transaction (RFC 3261 §8.1.1.5) and that is the
//! coordinate [`Arrival::Response`] carries.
//!
//! # What "total" means here, and why there is no "cannot occur"
//!
//! A capture tool sees malformed and adversarial traffic by definition —
//! scanner detection is a shipped feature — so any (family, arrival, state)
//! triple can appear on a wire. A table whose completeness rested on cells
//! marked impossible would assert something about the world this tool's own
//! threat model denies. Every cell therefore yields either [`Cell::To`], a
//! move, or [`Cell::Stay`], a no-change carrying a reason a reader can
//! disagree with. `stay_reasons_are_never_empty` makes that a gate rather than
//! a convention.
//!
//! Totality is the compiler's job, not a test's. The family and class matches
//! below carry no wildcard arm, and the state predicates
//! ([`invite_undecided`], [`invite_answerable`]) enumerate every
//! [`DialogState`]. Adding a variant to any of the three enums is a compile
//! error at each cell it affects, which is stronger and cheaper than any sweep.

use super::dialog::DialogState;
use super::method::SipMethod;
use super::response_codes::{ResponseClass, response_class};

/// Which state machine governs a dialog.
///
/// Derived from the method that opened the dialog by [`family_of_seed`], and
/// never from the arriving message: the family says which rules apply, while
/// the arriving message says which transaction it belongs to. Both are needed,
/// and a `NOTIFY` is the message that proves it — the same request ends a
/// transfer inside an INVITE dialog (RFC 3515 §2.4.6) and activates a
/// subscription inside a SUBSCRIBE one (RFC 6665 §4.1.2), and nothing on the
/// message distinguishes the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    /// An INVITE dialog: a call being set up, up, or torn down. Carries
    /// INVITE, ACK, CANCEL, BYE and PRACK transactions.
    Invite,
    /// A REGISTER binding (RFC 3261 §10).
    Register,
    /// A subscription (RFC 6665 §4), carrying SUBSCRIBE and NOTIFY.
    Subscribe,
    /// Everything with no dialog machine of its own: OPTIONS, MESSAGE,
    /// PUBLISH, INFO, UPDATE, REFER, standalone NOTIFY, extension methods.
    Standalone,
}

/// What arrived, reduced to the two things that decide a transition.
///
/// A response is identified by the transaction it answers, never by its own
/// position in the dialog — which is the distinction the four
/// `cseq_method == "INVITE"` string comparisons in the old handler were
/// making, one arm at a time.
#[derive(Debug)]
pub(crate) enum Arrival<'a> {
    /// A request, with the `Subscription-State` value token (RFC 6665 §8.4)
    /// when it carries one. Only `NOTIFY` reads it.
    Request {
        /// The request's own method — the transaction it opens.
        method: &'a SipMethod,
        /// The `Subscription-State` value token, parameters stripped.
        subscription_state: Option<&'a str>,
    },
    /// A response, identified by the CSeq method of the transaction it
    /// answers. `None` when the message carries no parseable CSeq, which
    /// names no transaction at all.
    Response {
        /// The transaction this response answers.
        cseq_method: Option<&'a SipMethod>,
        /// The status code, classified through
        /// [`response_class`](super::response_codes::response_class).
        code: u16,
    },
}

/// One cell of the transition table.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Cell {
    /// The arrival moves the dialog to this state.
    To(DialogState),
    /// The arrival is legal here and correctly changes nothing. The reason
    /// belongs in the table, not in a comment near it.
    Stay(&'static str),
}

/// Which machine a dialog opened by `method` belongs to.
///
/// Five methods map to [`Family::Invite`]. `INVITE` opens the dialog; `ACK`
/// (RFC 3261 §13.2.2.4), `BYE` (§15.1), `CANCEL` (§9.1) and `PRACK` (RFC 3262
/// §4) each presuppose one and cannot open anything, so seeing one first means
/// the capture began mid-dialog rather than that a new kind of dialog started.
///
/// `UPDATE`, `INFO`, `REFER` and `NOTIFY` stay in [`Family::Standalone`] even
/// though each usually runs inside some other dialog. Reassigning them would
/// also change what a dialog seeded by one *starts* as, and nothing observed in
/// such a capture says whether that call was ever answered — a separate
/// question, deliberately left open in `docs/design/mid-dialog-state-machine.md`
/// rather than answered by a side effect of this dispatch.
pub(crate) fn family_of_seed(method: &SipMethod) -> Family {
    match method {
        SipMethod::Invite
        | SipMethod::Ack
        | SipMethod::Bye
        | SipMethod::Cancel
        | SipMethod::Prack => Family::Invite,
        SipMethod::Register => Family::Register,
        SipMethod::Subscribe => Family::Subscribe,
        SipMethod::Options
        | SipMethod::Notify
        | SipMethod::Publish
        | SipMethod::Info
        | SipMethod::Refer
        | SipMethod::Message
        | SipMethod::Update
        | SipMethod::Custom(_) => Family::Standalone,
    }
}

/// Has the INVITE transaction yet to reach an outcome?
///
/// Exhaustive on purpose: a new [`DialogState`] variant must be classified
/// here rather than inherit a wildcard's answer.
fn invite_undecided(state: &DialogState) -> bool {
    match state {
        DialogState::Trying | DialogState::Ringing => true,
        DialogState::InCall
        | DialogState::Completed
        | DialogState::Cancelled
        | DialogState::Failed
        | DialogState::Redirected
        | DialogState::Registered
        | DialogState::Expired
        | DialogState::Pending
        | DialogState::Active
        | DialogState::Terminated
        | DialogState::Transferring => false,
    }
}

/// Is the call still running, in the sense that a `BYE` could end it?
///
/// Wider than [`invite_undecided`] by the two states an established call sits
/// in. Used only by the `2xx`-to-a-`BYE` cell, which is the one response
/// outside the INVITE transaction that carries evidence about the session.
fn invite_live(state: &DialogState) -> bool {
    match state {
        DialogState::Trying
        | DialogState::Ringing
        | DialogState::InCall
        | DialogState::Transferring => true,
        DialogState::Completed
        | DialogState::Cancelled
        | DialogState::Failed
        | DialogState::Redirected
        | DialogState::Registered
        | DialogState::Expired
        | DialogState::Pending
        | DialogState::Active
        | DialogState::Terminated => false,
    }
}

/// May a final response to the INVITE still decide this call?
///
/// [`invite_undecided`] plus `Cancelled`: a `2xx` beats a `CANCEL` because
/// once the UAS has sent a final `2xx` the `CANCEL` has no effect (RFC 3261
/// §9.1, §15), and a `487` re-confirms a cancellation the `CANCEL` already
/// recorded.
fn invite_answerable(state: &DialogState) -> bool {
    match state {
        DialogState::Trying | DialogState::Ringing | DialogState::Cancelled => true,
        DialogState::InCall
        | DialogState::Completed
        | DialogState::Failed
        | DialogState::Redirected
        | DialogState::Registered
        | DialogState::Expired
        | DialogState::Pending
        | DialogState::Active
        | DialogState::Terminated
        | DialogState::Transferring => false,
    }
}

/// The transition `arrival` causes in a `family` dialog currently in `state`.
///
/// Pure: it reads nothing but its arguments and writes nothing.
/// [`update_state`](super::dialog::update_state) is the only caller that
/// applies the result.
pub(crate) fn transition(family: Family, arrival: &Arrival<'_>, state: &DialogState) -> Cell {
    match arrival {
        Arrival::Request {
            method,
            subscription_state,
        } => request_cell(family, method, *subscription_state, state),
        Arrival::Response { cseq_method, code } => {
            response_cell(family, *cseq_method, *code, state)
        }
    }
}

/// The request half of the table.
fn request_cell(
    family: Family,
    method: &SipMethod,
    subscription_state: Option<&str>,
    state: &DialogState,
) -> Cell {
    match family {
        Family::Invite => match method {
            // RFC 3261 §9.1: a CANCEL asks the UAS to stop the pending
            // INVITE. Unconditional — the CANCEL is proof it was asked, and a
            // 2xx that beat it re-establishes the call through the response
            // half of the table.
            SipMethod::Cancel => Cell::To(DialogState::Cancelled),
            // RFC 3261 §15.1: a BYE terminates the session.
            SipMethod::Bye => Cell::To(DialogState::Completed),
            // RFC 3515 §2: a REFER inside an established call asks for a
            // transfer. Outside one it names no call to move.
            SipMethod::Refer => {
                if *state == DialogState::InCall {
                    Cell::To(DialogState::Transferring)
                } else {
                    Cell::Stay("a REFER outside an established call starts no transfer to show")
                }
            }
            // RFC 3515 §2.4.6: the implicit subscription a REFER creates ends
            // with a terminated NOTIFY, and the call carries on. Any other
            // NOTIFY in an INVITE dialog reports event state, not call state.
            SipMethod::Notify => {
                if *state == DialogState::Transferring && subscription_state == Some("terminated") {
                    Cell::To(DialogState::InCall)
                } else {
                    Cell::Stay("a NOTIFY in an INVITE dialog reports event state, not call state")
                }
            }
            SipMethod::Ack => Cell::Stay("an ACK confirms a final response already accounted for"),
            SipMethod::Invite | SipMethod::Update | SipMethod::Prack | SipMethod::Info => {
                Cell::Stay(
                    "a re-INVITE, UPDATE, PRACK or INFO renegotiates inside the call and \
                 does not end it",
                )
            }
            SipMethod::Options
            | SipMethod::Message
            | SipMethod::Publish
            | SipMethod::Register
            | SipMethod::Subscribe
            | SipMethod::Custom(_) => {
                Cell::Stay("this request opens its own transaction and decides no call")
            }
        },
        Family::Register => Cell::Stay(
            "a REGISTER dialog is decided by the registrar's answer, not by asking again",
        ),
        Family::Subscribe => match method {
            // RFC 6665 §4.1.2: a NOTIFY proves the subscription exists, and
            // may arrive before the 200 that would otherwise establish it.
            SipMethod::Notify => Cell::To(DialogState::Active),
            SipMethod::Subscribe
            | SipMethod::Invite
            | SipMethod::Ack
            | SipMethod::Bye
            | SipMethod::Cancel
            | SipMethod::Register
            | SipMethod::Options
            | SipMethod::Prack
            | SipMethod::Publish
            | SipMethod::Info
            | SipMethod::Refer
            | SipMethod::Message
            | SipMethod::Update
            | SipMethod::Custom(_) => {
                Cell::Stay("only a NOTIFY reports the state of a subscription")
            }
        },
        Family::Standalone => {
            Cell::Stay("a dialog with no machine of its own is decided by its responses")
        }
    }
}

/// The response half of the table.
fn response_cell(
    family: Family,
    cseq_method: Option<&SipMethod>,
    code: u16,
    state: &DialogState,
) -> Cell {
    let class = response_class(code);
    match family {
        // The only family carrying more than one kind of transaction, and so
        // the only one that has to ask which transaction answered.
        Family::Invite => match cseq_method {
            Some(SipMethod::Invite) => invite_response_cell(class, code, state),
            // RFC 3261 §15.1.2: a UAS answers a BYE only after terminating the
            // session, so the 2xx is proof the call ended even when the BYE
            // itself fell outside the capture. Without this a call whose BYE
            // was missed sits in `InCall` and is counted as a channel in use
            // for as long as the store keeps it.
            Some(SipMethod::Bye) if class == ResponseClass::Success => {
                if invite_live(state) {
                    Cell::To(DialogState::Completed)
                } else {
                    Cell::Stay("the call already ended; the answer to its BYE adds nothing")
                }
            }
            // RFC 3261 §9.1 draws the opposite conclusion for the sibling
            // case, and the difference is the whole reason the transaction is
            // a coordinate: a 200 to a CANCEL says only that the cancellation
            // was received. The 487 to the INVITE is what says the call ended.
            Some(_) => Cell::Stay(
                "this response answers a CANCEL, ACK, PRACK or failed BYE transaction, \
                 not the INVITE that decides the call",
            ),
            None => Cell::Stay("a response with no CSeq names no transaction to attribute it to"),
        },
        Family::Register => match class {
            ResponseClass::Success => Cell::To(DialogState::Registered),
            ResponseClass::Redirect => Cell::To(DialogState::Redirected),
            ResponseClass::Declined | ResponseClass::Failure => Cell::To(DialogState::Failed),
            ResponseClass::Challenge => {
                Cell::Stay("a challenge is intermediate: the client re-registers with credentials")
            }
            ResponseClass::Provisional => Cell::Stay("a provisional response binds nothing yet"),
            ResponseClass::Cancelled => {
                Cell::Stay("a 487 ends an INVITE transaction; a REGISTER has none")
            }
        },
        Family::Subscribe => match class {
            ResponseClass::Success => Cell::To(DialogState::Active),
            ResponseClass::Redirect => Cell::To(DialogState::Redirected),
            ResponseClass::Declined | ResponseClass::Failure => Cell::To(DialogState::Terminated),
            ResponseClass::Challenge => {
                Cell::Stay("a challenge is intermediate: the client re-subscribes with credentials")
            }
            ResponseClass::Provisional => {
                Cell::Stay("a provisional response establishes no subscription yet")
            }
            ResponseClass::Cancelled => {
                Cell::Stay("a 487 ends an INVITE transaction; a subscription has none")
            }
        },
        Family::Standalone => match class {
            ResponseClass::Success => Cell::To(DialogState::Completed),
            ResponseClass::Redirect => Cell::To(DialogState::Redirected),
            ResponseClass::Declined | ResponseClass::Failure => Cell::To(DialogState::Failed),
            ResponseClass::Challenge => {
                Cell::Stay("a challenge is intermediate: the client retries with credentials")
            }
            ResponseClass::Provisional => Cell::Stay("a provisional response settles nothing"),
            ResponseClass::Cancelled => {
                Cell::Stay("a 487 ends an INVITE transaction; this dialog has none")
            }
        },
    }
}

/// The INVITE family's response arms, once the transaction is known to be the
/// INVITE itself.
///
/// Every arm is guarded on the current state, and that guard — not the CSeq
/// comparison it used to sit beside — is the rule: once a final response has
/// decided the call, a later message about the same transaction may not
/// re-decide it. That property is what makes the live store's answer
/// independent of the order packets arrive in.
fn invite_response_cell(class: ResponseClass, code: u16, state: &DialogState) -> Cell {
    match class {
        // RFC 3261 §21.1.2 and §21.1.5: only 180 and 183 report alerting or
        // early media. 100, 181, 182 and 199 report progress and decide
        // nothing.
        ResponseClass::Provisional => {
            if matches!(code, 180 | 183) && invite_undecided(state) {
                Cell::To(DialogState::Ringing)
            } else {
                Cell::Stay("a provisional response reports progress and decides no outcome")
            }
        }
        // RFC 3261 §13.3.1: the 2xx establishes the session. §9.1: it also
        // beats a CANCEL that has not yet been answered.
        ResponseClass::Success => {
            if invite_answerable(state) {
                Cell::To(DialogState::InCall)
            } else {
                Cell::Stay("the call already has an outcome; a later 2xx cannot re-answer it")
            }
        }
        // RFC 3261 §15.1.2: the 487 is itself proof the INVITE transaction
        // ended, so having captured the CANCEL is not a precondition.
        ResponseClass::Cancelled => {
            if invite_answerable(state) {
                Cell::To(DialogState::Cancelled)
            } else {
                Cell::Stay("once a 2xx established the call a late 487 must not un-answer it")
            }
        }
        // RFC 3261 §21.3: a redirect ends this dialog and sends the caller to
        // the Contact it names, which is a new dialog with a new Call-ID.
        // Neither a failure nor an answer.
        ResponseClass::Redirect => {
            if invite_undecided(state) {
                Cell::To(DialogState::Redirected)
            } else {
                Cell::Stay("a redirect after the call was decided routes nothing")
            }
        }
        ResponseClass::Declined | ResponseClass::Failure => {
            if invite_undecided(state) {
                Cell::To(DialogState::Failed)
            } else {
                Cell::Stay("the call already has an outcome; a later failure cannot take it back")
            }
        }
        // RFC 3261 §22.2: the caller retries with credentials, so a challenge
        // ends nothing. Marking it Failed here made the 2xx that followed
        // unable to recover, because its guard admits only the pre-answer
        // states.
        ResponseClass::Challenge => {
            Cell::Stay("a challenge is intermediate: the caller retries with credentials")
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Properties of the table, quantified over every cell it declares.
///
/// These replace a differential against a second hand-written expectation
/// table. That arrangement could only ever report which of two hand-written
/// tables an edit had moved, and the way to make it green was to edit the
/// expectation to match — at which point it restated the implementation
/// instead of stating a rule. A property fails on a table nobody wrote twice.
#[cfg(test)]
mod tests {
    use super::*;

    /// Every [`DialogState`] variant. Kept as a list because the sweeps below
    /// have to *enumerate* states, which a `match` cannot do; the exhaustive
    /// matches in [`invite_undecided`] and [`invite_answerable`] are what stop
    /// a new variant going unnoticed, and `every_dialog_state_is_swept` holds
    /// this list to them.
    const STATES: [DialogState; 13] = [
        DialogState::Trying,
        DialogState::Ringing,
        DialogState::InCall,
        DialogState::Completed,
        DialogState::Cancelled,
        DialogState::Failed,
        DialogState::Redirected,
        DialogState::Registered,
        DialogState::Expired,
        DialogState::Pending,
        DialogState::Active,
        DialogState::Terminated,
        DialogState::Transferring,
    ];

    /// Every family.
    const FAMILIES: [Family; 4] = [
        Family::Invite,
        Family::Register,
        Family::Subscribe,
        Family::Standalone,
    ];

    /// The fourteen methods of the IANA registry plus one extension token, so
    /// the `Custom` arm is a swept cell and not a wildcard escape.
    fn methods() -> Vec<SipMethod> {
        vec![
            SipMethod::Invite,
            SipMethod::Ack,
            SipMethod::Bye,
            SipMethod::Cancel,
            SipMethod::Register,
            SipMethod::Options,
            SipMethod::Prack,
            SipMethod::Subscribe,
            SipMethod::Notify,
            SipMethod::Publish,
            SipMethod::Info,
            SipMethod::Refer,
            SipMethod::Message,
            SipMethod::Update,
            SipMethod::Custom("KDMQ".into()),
        ]
    }

    /// Every code in the IANA registry, mirrored from
    /// `docs/sip-response-codes.md`.
    const CODES: [u16; 75] = [
        100, 180, 181, 182, 183, 199, 200, 202, 204, 300, 301, 302, 305, 380, 400, 401, 402, 403,
        404, 405, 406, 407, 408, 410, 412, 413, 414, 415, 416, 417, 420, 421, 422, 423, 424, 425,
        428, 429, 430, 433, 436, 437, 438, 439, 440, 469, 470, 480, 481, 482, 483, 484, 485, 486,
        487, 488, 489, 491, 493, 494, 500, 501, 502, 503, 504, 505, 513, 555, 580, 600, 603, 604,
        606, 607, 608,
    ];

    /// The `Subscription-State` value tokens a NOTIFY can carry (RFC 6665
    /// §8.4), plus the absent case.
    const SUB_STATES: [Option<&str>; 4] =
        [None, Some("active"), Some("pending"), Some("terminated")];

    /// Call `visit` once per declared cell, with the coordinate that produced
    /// it. One enumerator, so no property can silently sweep a narrower space
    /// than another.
    fn for_every_cell(mut visit: impl FnMut(Family, &Arrival<'_>, &DialogState, &Cell)) {
        let methods = methods();
        for family in FAMILIES {
            for state in &STATES {
                for method in &methods {
                    for subscription_state in SUB_STATES {
                        let arrival = Arrival::Request {
                            method,
                            subscription_state,
                        };
                        let cell = transition(family, &arrival, state);
                        visit(family, &arrival, state, &cell);
                    }
                    for code in CODES {
                        let arrival = Arrival::Response {
                            cseq_method: Some(method),
                            code,
                        };
                        let cell = transition(family, &arrival, state);
                        visit(family, &arrival, state, &cell);
                    }
                }
                for code in CODES {
                    let arrival = Arrival::Response {
                        cseq_method: None,
                        code,
                    };
                    let cell = transition(family, &arrival, state);
                    visit(family, &arrival, state, &cell);
                }
            }
        }
    }

    /// The sweep visits the arithmetic number of cells, so a family or state
    /// that stopped being enumerated fails here rather than going unchecked.
    #[test]
    fn the_sweep_covers_every_declared_cell() {
        let mut cells = 0usize;
        for_every_cell(|_, _, _, _| cells += 1);
        let per_state = methods().len() * (SUB_STATES.len() + CODES.len()) + CODES.len();
        assert_eq!(
            cells,
            FAMILIES.len() * STATES.len() * per_state,
            "the enumerator built {cells} cells; a coordinate stopped being swept"
        );
    }

    /// Every state the table can move to is reached by at least one cell, and
    /// every state is used as a starting point.
    ///
    /// A declared transition nobody can reach is indistinguishable from a
    /// typo, and this is the difference between a complete table and a
    /// complete-and-exercised one.
    #[test]
    fn every_declared_destination_is_reachable_and_every_state_is_swept() {
        let mut reached: Vec<DialogState> = Vec::new();
        let mut started: Vec<DialogState> = Vec::new();
        for_every_cell(|_, _, state, cell| {
            if !started.contains(state) {
                started.push(state.clone());
            }
            if let Cell::To(next) = cell
                && !reached.contains(next)
            {
                reached.push(next.clone());
            }
        });
        assert_eq!(
            started.len(),
            STATES.len(),
            "the sweep started from {} of {} states",
            started.len(),
            STATES.len()
        );
        // Nine of the thirteen states are destinations. `Expired` has no
        // transition into it yet (nothing parses a REGISTER expiry), `Trying`
        // and `Pending` are only ever initial states set by `SipDialog::new`,
        // and no arrival moves a dialog back into either.
        for want in [
            DialogState::Ringing,
            DialogState::InCall,
            DialogState::Completed,
            DialogState::Cancelled,
            DialogState::Failed,
            DialogState::Redirected,
            DialogState::Registered,
            DialogState::Active,
            DialogState::Terminated,
            DialogState::Transferring,
        ] {
            assert!(
                reached.contains(&want),
                "no cell in the table ever produces {want:?}"
            );
        }
    }

    /// Every `Stay` carries a reason, and the reason says something.
    ///
    /// This is the mechanism that makes "a declared reason it changes nothing"
    /// a gate rather than a convention: an empty string would compile.
    #[test]
    fn stay_reasons_are_never_empty() {
        let mut checked = 0usize;
        for_every_cell(|family, arrival, state, cell| {
            if let Cell::Stay(reason) = cell {
                assert!(
                    reason.trim().len() > 10,
                    "{family:?} in {state:?} receiving {arrival:?} declares no usable \
                     reason for changing nothing: {reason:?}"
                );
                checked += 1;
            }
        });
        assert!(
            checked > 0,
            "no Stay cell was examined — the sweep proved nothing"
        );
    }

    /// Only the INVITE transaction may say how a call was answered.
    ///
    /// The rule the four `cseq_method == "INVITE"` comparisons were each
    /// expressing separately, stated once and stated more exactly than they
    /// managed. A response is evidence about its OWN transaction: a `2xx` to a
    /// `BYE` proves the session ended (RFC 3261 §15.1.2), which is why
    /// `Completed` is the one destination allowed here — but no response
    /// outside the INVITE transaction may ring the call, answer it, fail it or
    /// redirect it. A `200` to a `CANCEL` is exactly that trap: it means the
    /// cancellation was received and nothing more (§9.1), and a dispatch keyed
    /// on family alone reads it as the callee picking up.
    #[test]
    fn only_the_invite_transaction_decides_how_a_call_was_answered() {
        let methods = methods();
        let mut completions = 0usize;
        for state in &STATES {
            for method in &methods {
                if *method == SipMethod::Invite {
                    continue;
                }
                for code in CODES {
                    let arrival = Arrival::Response {
                        cseq_method: Some(method),
                        code,
                    };
                    let cell = transition(Family::Invite, &arrival, state);
                    let Cell::To(next) = cell else { continue };
                    assert_eq!(
                        next,
                        DialogState::Completed,
                        "a {code} answering a {method} transaction moved an INVITE dialog \
                         from {state:?} to {next:?}, which is a claim about the INVITE"
                    );
                    assert_eq!(
                        (method, response_class(code)),
                        (&SipMethod::Bye, ResponseClass::Success),
                        "only a 2xx to a BYE is evidence the session ended"
                    );
                    completions += 1;
                }
            }
        }
        assert!(
            completions > 0,
            "no 2xx-to-a-BYE cell was reached — the sweep proved nothing"
        );
    }

    /// Nothing takes an answered call back to a state that means "still being
    /// set up".
    ///
    /// The live store is fed in arrival order, and a parallel reader delivers
    /// a call's messages out of timestamp order. This property is why the
    /// store's answer does not depend on that order.
    #[test]
    fn no_cell_returns_a_decided_call_to_setup() {
        for_every_cell(|family, arrival, state, cell| {
            let decided = matches!(
                state,
                DialogState::InCall
                    | DialogState::Completed
                    | DialogState::Cancelled
                    | DialogState::Failed
                    | DialogState::Redirected
                    | DialogState::Transferring
            );
            if !decided {
                return;
            }
            if let Cell::To(next) = cell {
                assert!(
                    !matches!(next, DialogState::Trying | DialogState::Ringing),
                    "{family:?} in {state:?} receiving {arrival:?} went back to {next:?}"
                );
            }
        });
    }

    /// A provisional response and a challenge never decide an outcome.
    ///
    /// Both are intermediate by definition — the caller is still waiting, or
    /// is about to retry with credentials — so neither may reach a terminal
    /// state. A challenge that reached `Failed` is the defect that made a
    /// challenged-then-answered call report `Failed`.
    #[test]
    fn provisional_and_challenge_never_decide_an_outcome() {
        let methods = methods();
        for family in FAMILIES {
            for state in &STATES {
                for method in &methods {
                    for code in CODES {
                        let class = response_class(code);
                        if !matches!(class, ResponseClass::Provisional | ResponseClass::Challenge) {
                            continue;
                        }
                        let arrival = Arrival::Response {
                            cseq_method: Some(method),
                            code,
                        };
                        let cell = transition(family, &arrival, state);
                        let Cell::To(next) = cell else { continue };
                        assert_eq!(
                            next,
                            DialogState::Ringing,
                            "{family:?} in {state:?} let a {code} ({class:?}) decide the \
                             dialog"
                        );
                    }
                }
            }
        }
    }

    /// The 2xx-versus-CANCEL race resolves the way RFC 3261 §9.1 says.
    ///
    /// A `2xx` to the INVITE from `Cancelled` reaches `InCall` — the callee
    /// picked up before the cancellation landed — and no `487` may then move
    /// the answered call.
    #[test]
    fn a_2xx_beats_a_cancel_and_a_487_cannot_undo_it() {
        for code in [200u16, 202, 204] {
            assert_eq!(
                transition(
                    Family::Invite,
                    &Arrival::Response {
                        cseq_method: Some(&SipMethod::Invite),
                        code,
                    },
                    &DialogState::Cancelled,
                ),
                Cell::To(DialogState::InCall),
                "a {code} to the INVITE must win the race with a CANCEL"
            );
        }
        assert!(
            matches!(
                transition(
                    Family::Invite,
                    &Arrival::Response {
                        cseq_method: Some(&SipMethod::Invite),
                        code: 487,
                    },
                    &DialogState::InCall,
                ),
                Cell::Stay(_)
            ),
            "a late 487 must not un-answer an established call"
        );
    }

    /// A BYE ends the call and a CANCEL cancels it, whatever else the capture
    /// saw first.
    ///
    /// The mid-dialog defect in one assertion: these two requests are the ones
    /// a capture of a busy server sees first, and both were reaching a handler
    /// with no rule for them.
    #[test]
    fn a_bye_completes_and_a_cancel_cancels_from_every_state() {
        for state in &STATES {
            assert_eq!(
                transition(
                    Family::Invite,
                    &Arrival::Request {
                        method: &SipMethod::Bye,
                        subscription_state: None,
                    },
                    state,
                ),
                Cell::To(DialogState::Completed),
                "a BYE in {state:?} must end the call"
            );
            assert_eq!(
                transition(
                    Family::Invite,
                    &Arrival::Request {
                        method: &SipMethod::Cancel,
                        subscription_state: None,
                    },
                    state,
                ),
                Cell::To(DialogState::Cancelled),
                "a CANCEL in {state:?} must cancel the call"
            );
        }
    }

    /// The five methods that cannot open a dialog select the INVITE machine;
    /// the four whose own dialog is an open question do not.
    #[test]
    fn only_the_methods_that_presuppose_an_invite_join_its_family() {
        for method in [
            SipMethod::Invite,
            SipMethod::Ack,
            SipMethod::Bye,
            SipMethod::Cancel,
            SipMethod::Prack,
        ] {
            assert_eq!(
                family_of_seed(&method),
                Family::Invite,
                "{method} belongs to an INVITE dialog and cannot open one of its own"
            );
        }
        for method in [
            SipMethod::Update,
            SipMethod::Info,
            SipMethod::Refer,
            SipMethod::Notify,
            SipMethod::Options,
            SipMethod::Message,
            SipMethod::Publish,
            SipMethod::Custom("KDMQ".into()),
        ] {
            assert_eq!(
                family_of_seed(&method),
                Family::Standalone,
                "{method} must not silently acquire an INVITE dialog's initial state"
            );
        }
        assert_eq!(family_of_seed(&SipMethod::Register), Family::Register);
        assert_eq!(family_of_seed(&SipMethod::Subscribe), Family::Subscribe);
    }

    /// A NOTIFY means different things in different families, which is why the
    /// dialog's own family stays a parameter of the table.
    #[test]
    fn a_notify_is_read_against_the_family_it_arrives_in() {
        let terminated = Arrival::Request {
            method: &SipMethod::Notify,
            subscription_state: Some("terminated"),
        };
        assert_eq!(
            transition(Family::Invite, &terminated, &DialogState::Transferring),
            Cell::To(DialogState::InCall),
            "the transfer subscription ended and the call carries on"
        );
        assert_eq!(
            transition(Family::Invite, &terminated, &DialogState::InCall),
            Cell::Stay("a NOTIFY in an INVITE dialog reports event state, not call state"),
            "a NOTIFY must not move an established call"
        );
        assert_eq!(
            transition(Family::Subscribe, &terminated, &DialogState::Pending),
            Cell::To(DialogState::Active),
            "a NOTIFY proves the subscription exists"
        );
    }
}
