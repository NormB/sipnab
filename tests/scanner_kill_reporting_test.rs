// SPDX-License-Identifier: MIT OR Apache-2.0

//! The scanner-kill defense reports what it did.
//!
//! Nothing in production reads `ScannerKillHandle::counts()`, so the summary
//! logged when the worker shuts down is how an operator learns the kill path
//! ran at all — and whether a flood outran it. An outcome computed and then
//! discarded is exactly how the wedge this defense recovered from began, so
//! the reporting is asserted rather than assumed.
//!
//! # Why this lives in its own test binary
//!
//! `tracing` caches each callsite's interest process-wide, decided by whoever
//! reaches it first. In a binary where other tests also shut a kill worker
//! down — with no subscriber installed — the summary's callsite gets cached
//! as "never" and a scoped subscriber here captures nothing, at random. One
//! test per binary makes the capture deterministic.

// The whole file, not just the test: the capturing subscriber below is only
// ever constructed by that test, so a build without `native` sees it as dead
// code and `-D warnings` rejects it.
#![cfg(feature = "native")]

use std::sync::{Arc, Mutex};

/// Collects `tracing` events emitted on the current thread.
#[derive(Clone, Default)]
struct EventCapture {
    /// Every event seen, as `(level, rendered message)`.
    events: Arc<Mutex<Vec<(tracing::Level, String)>>>,
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

/// Shutting the worker down logs what the defense did.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
#[test]
fn shutdown_reports_what_the_kill_defense_did() {
    use sipnab::process_isolation::{KillRequest, spawn_scanner_kill_worker};
    use sipnab::security::transmit_guard::TransmitPermit;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    // The worker only exists for a live source; a run reading a capture file
    // gets no permit and therefore no worker. This test declares the live
    // source exactly as a real run does and sends only to loopback.
    let permit = TransmitPermit::for_source(&sipnab::capture::CaptureSource::Live {
        device: "lo".to_string(),
    })
    .expect("a live source grants a transmit permit");
    let mut handle = spawn_scanner_kill_worker(Some(10), None, permit).expect("spawn worker");

    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    handle
        .send_kill(KillRequest::SendResponse {
            dst_addr: loopback,
            dst_port: 59_994,
            src_addr: loopback,
            src_port: 5060,
            response_bytes: b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        })
        .expect("a fresh worker must accept a request");

    // Wait for the outcome to be booked so the totals are not a race with the
    // worker.
    let deadline = Instant::now() + Duration::from_secs(10);
    while handle.counts().outcomes() == 0 {
        assert!(
            Instant::now() < deadline,
            "the worker never produced an outcome"
        );
        std::thread::yield_now();
    }
    let counts = handle.counts();

    let capture = EventCapture::default();
    tracing::subscriber::with_default(capture.clone(), || {
        // Belt and braces if a second test is ever added to this binary.
        tracing::callsite::rebuild_interest_cache();
        handle.shutdown();
    });

    let events = capture.events.lock().expect("capture mutex");
    let reported = events
        .iter()
        .any(|(_, msg)| msg.contains("Scanner-kill totals") && msg.contains("1 sent"));
    assert!(
        reported,
        "shutdown must log the kill totals (counts were {counts:?}); captured: {events:?}"
    );
}
