// SPDX-License-Identifier: MIT OR Apache-2.0

//! An `--on-dialog` / `--on-quality` hook that fails says so.
//!
//! These hooks are an automated-response path: an operator wires one to a
//! firewall command and, seeing nothing in the log, concludes the ban landed.
//! The reaper used to match the child's exit status with a wildcard and throw
//! it away, so a command that exited 7 and a command that exited 0 produced
//! byte-identical output — silence, in both cases. Silence that means "it
//! worked" and silence that means "it never worked" are the two answers an
//! operator must never have to distinguish.
//!
//! This test drives only the public API a real run drives (`fire_dialog_event`
//! and dropping the engine) and asserts on what an operator actually reads:
//! the log. It therefore compiles and runs unchanged against the defective
//! code, where it fails.
//!
//! # Why this lives in its own test binary
//!
//! `tracing` caches each callsite's interest process-wide, decided by whoever
//! reaches it first. In a binary where another test also reaps a failed hook
//! with no subscriber installed, these callsites get cached as "never" and the
//! scoped subscriber below captures nothing, at random. One test per binary
//! makes the capture deterministic. (Same reasoning as
//! `scanner_kill_reporting_test.rs`.)

// The whole file: the capturing subscriber is only ever constructed by the one
// test below, so a build without `native` would see it as dead code and
// `-D warnings` would reject it.
#![cfg(feature = "native")]

use std::sync::{Arc, Mutex};

/// Collects `tracing` events emitted on the current thread.
#[derive(Clone, Default)]
struct EventCapture {
    /// Every event seen, as `(level, rendered message)`.
    events: Arc<Mutex<Vec<(tracing::Level, String)>>>,
}

impl EventCapture {
    /// Rendered messages recorded from `start` onwards.
    fn since(&self, start: usize) -> Vec<(tracing::Level, String)> {
        self.events.lock().expect("capture mutex")[start..].to_vec()
    }

    /// How many events have been recorded so far.
    fn len(&self) -> usize {
        self.events.lock().expect("capture mutex").len()
    }
}

impl tracing::Subscriber for EventCapture {
    fn enabled(&self, _md: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct MsgVisitor(String);
        impl tracing::field::Visit for MsgVisitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, "{value:?}");
                }
            }
        }
        let mut visitor = MsgVisitor(String::new());
        event.record(&mut visitor);
        if let Ok(mut events) = self.events.lock() {
            events.push((*event.metadata().level(), visitor.0));
        }
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Assembles a raw SIP message from a first line, header lines, and a body.
fn build_sip(first_line: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(first_line.as_bytes());
    msg.extend_from_slice(b"\r\n");
    for h in headers {
        msg.extend_from_slice(h.as_bytes());
        msg.extend_from_slice(b"\r\n");
    }
    msg.extend_from_slice(b"\r\n");
    msg.extend_from_slice(body);
    msg
}

/// A minimal dialog to fire hooks with.
fn make_dialog() -> sipnab::sip::dialog::SipDialog {
    use std::net::{IpAddr, Ipv4Addr};
    let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
    let raw = build_sip(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            "Call-ID: exit-status@example.com",
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    let msg = sipnab::sip::parse_sip(
        &raw,
        ts,
        localhost,
        localhost,
        5060,
        5060,
        sipnab::capture::parse::TransportProto::Udp,
    )
    .expect("parse");
    sipnab::sip::dialog::SipDialog::new(&msg).expect("dialog")
}

/// Fire the hook repeatedly until `done` reports true, or give up.
///
/// Reaping happens on the way into a spawn, so the only way to make a finished
/// child's status observable through the public API is to fire again. Each
/// iteration therefore both books the previous child's outcome and starts one
/// more; the sleep keeps a ten-second budget from becoming thousands of
/// processes.
fn fire_until(
    engine: &mut sipnab::output::event_exec::EventExecEngine,
    dialog: &sipnab::sip::dialog::SipDialog,
    mut done: impl FnMut() -> bool,
) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        engine.fire_dialog_event(dialog);
        if done() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    done()
}

/// Fire the hook `n` times, pausing between fires so each `sh -c` has exited
/// before the next fire reaps it.
fn fire_n(
    engine: &mut sipnab::output::event_exec::EventExecEngine,
    dialog: &sipnab::sip::dialog::SipDialog,
    n: usize,
) {
    for _ in 0..n {
        engine.fire_dialog_event(dialog);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// A hook that exits non-zero is reported with its exit status and its command;
/// a hook that exits zero is not. Both totals are stated at teardown.
#[test]
fn failing_hook_is_distinguishable_from_a_succeeding_one() {
    use sipnab::output::event_exec::EventExecEngine;

    let dialog = make_dialog();
    let capture = EventCapture::default();

    // Everything the engines do — including their Drop — happens inside the
    // subscriber scope, because the teardown totals are part of what is asserted.
    tracing::subscriber::with_default(capture.clone(), || {
        tracing::callsite::rebuild_interest_cache();

        // ── The failing hook ────────────────────────────────────────────
        let failing_start = capture.len();
        let mut failing = EventExecEngine::new(Some("exit 7".to_string()), None, 0, 3.0);
        let saw_failure = fire_until(&mut failing, &dialog, || {
            capture
                .since(failing_start)
                .iter()
                .any(|(level, msg)| *level == tracing::Level::WARN && msg.contains("exit 7"))
        });
        let failing_events = capture.since(failing_start);
        assert!(
            saw_failure,
            "a hook that exits 7 must be reported at WARN, naming the command \
             that failed; captured instead: {failing_events:?}"
        );
        // The exit status itself, not just the fact of failure and not just the
        // command's name: an operator debugging a broken ban command needs the
        // code it returned. `ExitStatus` renders as "exit status: 7" on unix and
        // "exit code: 7" elsewhere; either carries the number.
        assert!(
            failing_events.iter().any(|(level, msg)| {
                *level == tracing::Level::WARN
                    && (msg.contains("status: 7") || msg.contains("code: 7"))
            }),
            "the report must carry the exit status the command returned; \
             captured: {failing_events:?}"
        );
        let failing_teardown_start = capture.len();
        drop(failing);
        let failing_teardown = capture.since(failing_teardown_start);
        assert!(
            failing_teardown
                .iter()
                .any(|(_, msg)| msg.contains("Event exec totals") && msg.contains("failed")),
            "teardown must state the run's hook totals; captured: {failing_teardown:?}"
        );

        // ── Positive control: the succeeding hook ───────────────────────
        // Without this, an implementation that warned about every reaped child
        // — or that reported a total of nothing — would pass the assertions
        // above while telling an operator exactly as little as before.
        let ok_start = capture.len();
        let mut succeeding = EventExecEngine::new(Some("exit 0".to_string()), None, 0, 3.0);
        fire_n(&mut succeeding, &dialog, 10);
        drop(succeeding);
        let ok_events = capture.since(ok_start);
        assert!(
            !ok_events
                .iter()
                .any(|(level, _)| *level == tracing::Level::WARN),
            "a hook that exits 0 must produce no warning at all; captured: {ok_events:?}"
        );
        let totals = ok_events
            .iter()
            .find(|(_, msg)| msg.contains("Event exec totals"))
            .unwrap_or_else(|| {
                panic!(
                    "teardown must state the totals for a clean run too; captured: {ok_events:?}"
                )
            });
        // Anchored on the surrounding punctuation: "10 succeeded" contains
        // "0 succeeded", and a bare substring check would call a ledger of
        // zeroes a pass.
        assert!(
            totals.1.contains("succeeded, 0 failed") && !totals.1.contains("run, 0 succeeded"),
            "the clean run's totals must show real successes and no failures, \
             not a ledger of zeroes; got: {totals:?}"
        );
    });
}
