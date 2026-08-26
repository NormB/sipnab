// SPDX-License-Identifier: GPL-3.0-or-later
//! Whether content may still reach disk on this run.
//!
//! The command line decides what a run is allowed to persist. This gate lets
//! an operator take that back mid-run without stopping capture, and it moves
//! in one direction only: it can close what the command line opened, and it
//! can never open what the command line never authorized.

use std::sync::atomic::{AtomicBool, Ordering};

/// Whether content may still reach disk on this run.
///
/// Two values, and the asymmetry between them is the whole type. `authorized`
/// is what the command line granted and never changes. `enabled` is what an
/// operator can move over REST. `writes_permitted` is their conjunction, so a
/// run invoked without persistence flags has nothing for the socket to switch
/// on, however many times it is asked.
///
/// The gate narrows and never widens because the command line and a network
/// request are not peers. An operator at a terminal chose what this process may
/// keep; a caller holding an API token is asking that process to keep less. The
/// first is authority and the second is a request, and a control that let a
/// request restore authority would mean a stolen token could turn recording on
/// rather than only off.
///
/// Held behind an `Arc` and read from the exporter, written from an axum
/// handler task. `Relaxed` ordering suffices: this flag carries no other state
/// with it, and a writer racing the exporter by one container is a race the
/// operator already accepted by closing the gate mid-run rather than before it.
pub struct PersistenceGate {
    /// What an operator last asked for, recorded as asked.
    ///
    /// Deliberately NOT narrowed on the way in. The ceiling is applied once,
    /// in [`Self::writes_permitted`], because a rule enforced in two places is
    /// a rule that can be deleted from one of them and go on passing every
    /// test: with `set` also masking, dropping the ceiling from the read
    /// changed no observable behavior at all.
    enabled: AtomicBool,
    /// The ceiling the command line set. Fixed at construction.
    authorized: bool,
    /// Set the first time a gate that WAS writing stopped, and never cleared.
    ///
    /// Sticky because the container is written at the end of a run, by which
    /// time the gate may be open again. A live read of `writes_permitted`
    /// would report the final state and lose the fact that recording stopped
    /// partway -- which is the fact a reader comparing this capture against a
    /// switch's records needs, and the only one they cannot recover from the
    /// capture itself.
    closed_during_run: AtomicBool,
}

impl PersistenceGate {
    /// A gate whose ceiling is `authorized`, open as far as that allows.
    ///
    /// A run authorized to persist starts persisting: the flag on the command
    /// line is the operator's instruction, and requiring a REST call to
    /// activate it would make every capture depend on a second step nobody
    /// asked for.
    #[must_use]
    pub const fn new(authorized: bool) -> Self {
        Self {
            // `true` means "no operator has narrowed this yet", not "open".
            // The ceiling is not applied here on purpose: `authorized` appears
            // in exactly one expression in this type, and an initial value
            // that also carried it would put it in two.
            //
            // On an unauthorized gate this value is unobservable through the
            // public surface, so `new(authorized)` here would be an equivalent
            // mutant that no test can kill. Rather than leave a survivor for a
            // later reader to chase, the honest default is written down.
            enabled: AtomicBool::new(true),
            authorized,
            closed_during_run: AtomicBool::new(false),
        }
    }

    /// Whether content may reach disk right now.
    #[must_use]
    pub fn writes_permitted(&self) -> bool {
        self.authorized && self.enabled.load(Ordering::Relaxed)
    }

    /// What the command line granted, whatever the gate currently reports.
    ///
    /// Reported alongside `writes_permitted` so a caller can tell a gate an
    /// operator closed from one that was never open. Without it a client that
    /// asked to enable persistence on an unauthorized run reads its own
    /// `enabled: false` back and cannot tell whether the request failed, was
    /// ignored, or raced another operator closing the gate.
    #[must_use]
    pub const fn authorized(&self) -> bool {
        self.authorized
    }

    /// Move the gate, returning what it now reports.
    ///
    /// The return value is the gate's state and not the caller's request, so a
    /// caller that asked to open an unauthorized run is told `false` at the
    /// point of asking rather than discovering it later, or never.
    ///
    /// The request is stored as made and narrowed on the way out, which keeps
    /// the ceiling in one place. It also means an unauthorized gate remembers
    /// having been asked to open, and reports `false` regardless.
    pub fn set(&self, want: bool) -> bool {
        // Read BEFORE the store, so the record is of an observed transition
        // rather than of a request. Asking an open gate to open closes
        // nothing, and asking an unauthorized gate to close stops nothing that
        // was running -- neither belongs in a container's caveat, which is
        // read as "an operator stopped this capture recording".
        let was_permitted = self.writes_permitted();
        self.enabled.store(want, Ordering::Relaxed);
        let now = self.writes_permitted();
        if was_permitted && !now {
            self.closed_during_run.store(true, Ordering::Relaxed);
        }
        now
    }

    /// Whether content stopped reaching disk at some point during this run.
    ///
    /// Sticky: it stays true after the gate reopens. `false` on a run nobody
    /// touched and on a run the command line never authorized, because neither
    /// had anything stopped.
    #[must_use]
    pub fn closed_during_run(&self) -> bool {
        self.closed_during_run.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// The plain case the gate exists for: a run started with persistence
    /// flags, and an operator who wants it to stop.
    #[test]
    fn the_gate_can_close_what_the_command_line_opened() {
        let gate = PersistenceGate::new(true);
        assert!(gate.writes_permitted(), "authorized runs start open");
        assert!(!gate.set(false), "closing reports the gate as closed");
        assert!(!gate.writes_permitted(), "and it stays closed");
    }

    /// The property that makes this a gate rather than a switch. A REST caller
    /// is not a second command line.
    #[test]
    fn the_gate_cannot_open_what_the_command_line_never_authorized() {
        let gate = PersistenceGate::new(false);
        assert!(!gate.writes_permitted());
        assert!(
            !gate.set(true),
            "enabling on a run with no persistence flags must report that it \
             enabled nothing, not report success"
        );
        assert!(!gate.writes_permitted());
    }

    /// `set` returns the gate's state, not the caller's request.
    ///
    /// A mutant returning `want` passes both tests above on the authorized
    /// gate and fails only here, where the unauthorized gate is asked to open
    /// and the return value is read rather than a later `writes_permitted`.
    #[test]
    fn set_reports_the_gate_not_the_request() {
        for authorized in [true, false] {
            for want in [true, false] {
                let gate = PersistenceGate::new(authorized);
                let reported = gate.set(want);
                assert_eq!(
                    reported,
                    gate.writes_permitted(),
                    "set(authorized={authorized}, want={want}) must return what \
                     a following writes_permitted() would say"
                );
                assert_eq!(
                    reported,
                    want && authorized,
                    "and that is the request narrowed by the ceiling"
                );
            }
        }
    }

    /// No sequence of API calls can widen an unauthorized run.
    ///
    /// The single case above proves one call cannot. This proves no run of
    /// calls can, which is the claim the flag makes to an operator who has to
    /// trust it: a run started without persistence flags never writes content,
    /// whatever anyone does to the socket.
    #[test]
    fn no_sequence_of_calls_can_open_an_unauthorized_gate() {
        let gate = PersistenceGate::new(false);
        for bits in 0u32..64 {
            for step in 0..6 {
                let want = bits & (1 << step) != 0;
                assert!(
                    !gate.set(want),
                    "sequence {bits:#08b} opened a gate the command line never \
                     authorized, at step {step}"
                );
                assert!(!gate.writes_permitted());
            }
        }
    }

    /// An authorized gate is exactly as open as the last `set` left it.
    ///
    /// Guards against a latch — an implementation that, once closed, refuses
    /// to reopen. That would be safe but wrong: the operator who closed the
    /// gate at three in the morning has to be able to open it again at four
    /// without restarting capture and losing the dialog table.
    #[test]
    fn an_authorized_gate_tracks_the_last_request() {
        let gate = PersistenceGate::new(true);
        for bits in 0u32..64 {
            let mut last = true;
            for step in 0..6 {
                last = bits & (1 << step) != 0;
                gate.set(last);
            }
            assert_eq!(
                gate.writes_permitted(),
                last,
                "sequence {bits:#08b} left the gate disagreeing with its last set"
            );
            gate.set(true);
        }
    }

    /// Repeating a request changes nothing.
    #[test]
    fn moving_the_gate_where_it_already_is_is_idempotent() {
        let gate = PersistenceGate::new(true);
        assert!(!gate.set(false));
        assert!(!gate.set(false), "closing a closed gate keeps it closed");
        assert!(gate.set(true));
        assert!(gate.set(true), "opening an open gate keeps it open");
    }

    /// `authorized` is visible so a caller can tell "you closed it" from
    /// "there was nothing to close".
    ///
    /// The REST response reports both, because a 200 carrying only
    /// `enabled: false` reads as success to a client that asked to enable.
    #[test]
    fn the_ceiling_is_readable_so_denied_is_distinguishable_from_off() {
        let never = PersistenceGate::new(false);
        let closed = PersistenceGate::new(true);
        closed.set(false);

        assert_eq!(never.writes_permitted(), closed.writes_permitted());
        assert!(
            !never.authorized(),
            "a run with no persistence flags reports no authority"
        );
        assert!(
            closed.authorized(),
            "a run that was authorized still reports it after closing, so a \
             client can tell its close took effect"
        );
    }

    /// A close is remembered after the gate reopens.
    ///
    /// The container written at the end of a run has to say that recording
    /// stopped partway, and by then the gate may be open again. A live read of
    /// `writes_permitted` would report the final state and lose the fact.
    #[test]
    fn a_close_is_remembered_after_the_gate_reopens() {
        let gate = PersistenceGate::new(true);
        assert!(!gate.closed_during_run(), "nothing has happened yet");

        gate.set(false);
        assert!(gate.closed_during_run());
        gate.set(true);
        assert!(
            gate.closed_during_run(),
            "reopening does not un-happen the close the container has to report"
        );
    }

    /// A run nobody touched reports no close.
    ///
    /// The clause it drives makes every container read as suspect, so it must
    /// fire on a real event and not on the mere existence of a gate.
    #[test]
    fn an_untouched_gate_reports_no_close() {
        let gate = PersistenceGate::new(true);
        for _ in 0..3 {
            gate.set(true);
        }
        assert!(
            !gate.closed_during_run(),
            "asking an open gate to open did not close anything"
        );
    }

    /// A run the command line never authorized reports no close either.
    ///
    /// `set(false)` on such a gate changes nothing, because there was nothing
    /// to change. Latching there would put "the operator closed the
    /// persistence gate" into a container from a run where no operator did.
    #[test]
    fn an_unauthorized_gate_reports_no_close() {
        let gate = PersistenceGate::new(false);
        gate.set(false);
        gate.set(true);
        gate.set(false);
        assert!(
            !gate.closed_during_run(),
            "nothing was writing, so nothing was stopped"
        );
    }

    /// The record survives every later request.
    #[test]
    fn no_sequence_of_calls_erases_a_close() {
        let gate = PersistenceGate::new(true);
        gate.set(false);
        for bits in 0u32..32 {
            for step in 0..5 {
                gate.set(bits & (1 << step) != 0);
                assert!(
                    gate.closed_during_run(),
                    "sequence {bits:#07b} erased the record at step {step}"
                );
            }
        }
    }

    /// Every holder sees the record, not just the one that closed the gate.
    #[test]
    fn the_record_is_shared_like_the_gate() {
        let gate = Arc::new(PersistenceGate::new(true));
        let rest_door = Arc::clone(&gate);
        rest_door.set(false);
        assert!(
            gate.closed_during_run(),
            "the exporter reads the record the socket wrote"
        );
    }

    /// The ceiling is fixed at construction and nothing moves it.
    #[test]
    fn the_ceiling_never_moves() {
        let gate = PersistenceGate::new(true);
        for want in [false, true, false, false, true] {
            gate.set(want);
            assert!(gate.authorized(), "set must not touch the ceiling");
        }
        let denied = PersistenceGate::new(false);
        for want in [true, false, true] {
            denied.set(want);
            assert!(!denied.authorized());
        }
    }

    /// One gate, shared — not a copy per door.
    ///
    /// The REST handler and the exporter hold `Arc` clones of the same gate.
    /// A per-door copy would let the socket report a closed gate while the
    /// exporter went on writing, which is the exact failure the control is
    /// there to prevent.
    #[test]
    fn every_holder_sees_one_gate() {
        let gate = Arc::new(PersistenceGate::new(true));
        let rest_door = Arc::clone(&gate);
        let exporter = Arc::clone(&gate);

        rest_door.set(false);
        assert!(
            !exporter.writes_permitted(),
            "the exporter must see the close the socket made"
        );
        rest_door.set(true);
        assert!(exporter.writes_permitted());
    }

    /// A close made on one thread is visible to a reader on another.
    ///
    /// `Relaxed` ordering is enough for a single flag with no other state
    /// riding on it, and this pins that: the value crosses threads, so a
    /// future edit cannot quietly make the gate thread-local.
    #[test]
    fn a_close_crosses_threads() {
        let gate = Arc::new(PersistenceGate::new(true));
        let closer = Arc::clone(&gate);
        std::thread::spawn(move || closer.set(false))
            .join()
            .expect("the closing thread finished");
        assert!(
            !gate.writes_permitted(),
            "a close made on another thread must be visible here"
        );
    }

    /// The gate is `Send + Sync`, because `ApiState` is cloned into every
    /// axum handler task and the exporter reads it from the capture thread.
    #[test]
    fn the_gate_can_be_shared_across_tasks() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PersistenceGate>();
    }
}
