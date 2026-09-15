// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runtime re-application of the capture filter (the TUI BPF editor's apply).
//!
//! The TUI event loop and the capture loop(s) run on different threads, and a
//! live capture may run several fanout sockets -- each its own loop with its
//! own pcap handle -- or one loop per interface under `--multi-device`. A
//! [`FilterControl`], shared behind an `Arc`, carries a new filter from the TUI
//! to every loop: the TUI stamps a request with a rising generation; each loop
//! polls the generation (a cheap atomic load, where it already polls shutdown)
//! and, when it rises, reads the pending filter and installs it on its own
//! handle. Outcomes travel back on a channel the TUI drains.
//!
//! libpcap's `pcap_setfilter` validates before it swaps: on a compile error the
//! running filter is left in place, so a bad expression never takes the capture
//! down. The install goes through the [`FilterSink`] trait so the poll/apply/
//! report logic is driven by a test double -- a live `Capture` needs a device
//! and cannot be exercised from a unit test.
//!
//! Spec: `docs/design/tui-bpf-filter-editing.md` (Runtime re-apply).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

/// A capture loop's report after attempting to install a new filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterApplyOutcome {
    /// libpcap accepted and installed the filter; it applies to new packets.
    Applied {
        /// The request generation this outcome answers.
        generation: u64,
    },
    /// libpcap rejected it; the running filter is unchanged. Carries the error
    /// (a DLT the operator's expression cannot compile against, say) so the TUI
    /// can show it rather than silently keeping the old filter.
    Rejected {
        /// The request generation this outcome answers.
        generation: u64,
        /// libpcap's own error message.
        error: String,
    },
}

/// Shared filter-reconfigure control: one writer (the TUI), N pollers (loops).
#[derive(Debug)]
pub struct FilterControl {
    /// Bumped on each request; a loop compares it against the generation it
    /// last installed. An atomic so the poll is a load, not a lock, on the
    /// capture hot path.
    generation: AtomicU64,
    /// The filter requested under the current generation. Locked only when the
    /// generation has actually risen, never on the common (unchanged) poll.
    pending: Mutex<String>,
}

impl FilterControl {
    /// A control with no request pending (generation 0).
    #[must_use]
    pub fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            pending: Mutex::new(String::new()),
        }
    }

    /// TUI side: request that `bpf` be installed, returning the new generation.
    ///
    /// The payload is stored BEFORE the generation is bumped, so a loop that
    /// observes the new generation always reads a filter at least as new -- it
    /// can never see the higher generation paired with the older filter.
    pub fn request(&self, bpf: String) -> u64 {
        *self.pending.lock() = bpf;
        self.generation.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Loop side: given the generation this loop last installed, return the
    /// pending `(generation, filter)` if a newer request stands, else `None`.
    #[must_use]
    pub fn poll(&self, installed: u64) -> Option<(u64, String)> {
        let current = self.generation.load(Ordering::SeqCst);
        if current == installed {
            return None;
        }
        Some((current, self.pending.lock().clone()))
    }
}

impl Default for FilterControl {
    fn default() -> Self {
        Self::new()
    }
}

/// What a capture loop and the TUI each hold: the shared control plus the
/// channel a loop reports outcomes on. Cloneable, so each fanout thread carries
/// its own copy.
#[derive(Clone)]
pub struct ReconfigureHandle {
    /// The shared control the loop polls.
    pub control: Arc<FilterControl>,
    /// Where the loop reports the outcome of an install.
    pub outcomes: crossbeam_channel::Sender<FilterApplyOutcome>,
}

/// Something a compiled BPF filter can be installed on. Implemented for a live
/// `Capture`; a test double stands in where a real device cannot.
pub trait FilterSink {
    /// Compile and install `bpf`, returning libpcap's error message on failure.
    /// Validates before it swaps: on failure the previous filter stands.
    fn install_filter(&mut self, bpf: &str) -> Result<(), String>;
}

impl FilterSink for pcap::Capture<pcap::Active> {
    fn install_filter(&mut self, bpf: &str) -> Result<(), String> {
        self.filter(bpf, true).map_err(|e| e.to_string())
    }
}

/// Poll `handle` for a pending filter and, if one stands, install it on `sink`
/// and report the outcome. Returns the generation this loop has now installed
/// through (unchanged when nothing was pending), which the caller threads back
/// in on the next poll.
///
/// This is the whole per-loop reconfigure step, driven by a `sink` so it is
/// testable without a device: the live wiring is the one-line [`FilterSink`]
/// impl for `Capture<Active>`, which the initial filter apply at capture open
/// already exercises.
pub fn apply_pending<S: FilterSink>(
    sink: &mut S,
    handle: &ReconfigureHandle,
    installed: u64,
) -> u64 {
    let Some((generation, bpf)) = handle.control.poll(installed) else {
        return installed;
    };
    let outcome = match sink.install_filter(&bpf) {
        Ok(()) => FilterApplyOutcome::Applied { generation },
        Err(error) => FilterApplyOutcome::Rejected { generation, error },
    };
    // The receiver is the TUI; if it has gone away the capture simply keeps
    // running the filter it just installed, so a send error is not fatal.
    let _ = handle.outcomes.send(outcome);
    generation
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test double: records the filters it was asked to install and returns a
    /// preset result, so the poll/apply/report logic can be driven without a
    /// live capture.
    struct MockSink {
        installed: Vec<String>,
        result: Result<(), String>,
    }
    impl FilterSink for MockSink {
        fn install_filter(&mut self, bpf: &str) -> Result<(), String> {
            self.installed.push(bpf.to_string());
            self.result.clone()
        }
    }

    fn handle() -> (
        ReconfigureHandle,
        crossbeam_channel::Receiver<FilterApplyOutcome>,
    ) {
        let (tx, rx) = crossbeam_channel::unbounded();
        (
            ReconfigureHandle {
                control: Arc::new(FilterControl::new()),
                outcomes: tx,
            },
            rx,
        )
    }

    /// A fresh control has generation 0 and nothing pending for a loop at 0.
    #[test]
    fn a_fresh_control_has_nothing_pending() {
        let c = FilterControl::new();
        assert_eq!(c.poll(0), None, "no request yet");
    }

    /// A request bumps the generation and hands the loop the new filter once.
    #[test]
    fn a_request_is_seen_once_per_generation() {
        let c = FilterControl::new();
        let g = c.request("udp port 5060".to_string());
        assert_eq!(g, 1, "the first request is generation 1");
        assert_eq!(
            c.poll(0),
            Some((1, "udp port 5060".to_string())),
            "a loop at generation 0 sees the request"
        );
        assert_eq!(
            c.poll(1),
            None,
            "a loop that already installed generation 1 sees nothing"
        );
    }

    /// The latest request wins: a loop that missed an intermediate generation
    /// still converges on the newest filter.
    #[test]
    fn the_latest_request_wins() {
        let c = FilterControl::new();
        c.request("port 5060".to_string());
        let g = c.request("port 5080".to_string());
        assert_eq!(g, 2);
        assert_eq!(c.poll(0), Some((2, "port 5080".to_string())));
    }

    /// apply_pending installs a pending filter, reports Applied, and advances
    /// the installed generation so the next poll is a no-op.
    #[test]
    fn apply_pending_installs_and_reports_success() {
        let (h, rx) = handle();
        h.control.request("udp port 5060".to_string());
        let mut sink = MockSink {
            installed: Vec::new(),
            result: Ok(()),
        };
        let now = apply_pending(&mut sink, &h, 0);
        assert_eq!(now, 1, "the installed generation advances");
        assert_eq!(
            sink.installed,
            vec!["udp port 5060".to_string()],
            "installed once"
        );
        assert_eq!(
            rx.try_recv(),
            Ok(FilterApplyOutcome::Applied { generation: 1 })
        );

        // Nothing pending now: no install, no report, generation unchanged.
        let now2 = apply_pending(&mut sink, &h, now);
        assert_eq!(now2, 1);
        assert_eq!(sink.installed.len(), 1, "not installed again");
        assert!(rx.try_recv().is_err(), "no second outcome");
    }

    /// A rejected install reports the error and leaves nothing else changed;
    /// the generation still advances so the loop does not retry a bad filter.
    #[test]
    fn apply_pending_reports_a_rejection() {
        let (h, rx) = handle();
        h.control.request("garbage and and".to_string());
        let mut sink = MockSink {
            installed: Vec::new(),
            result: Err("syntax error".to_string()),
        };
        let now = apply_pending(&mut sink, &h, 0);
        assert_eq!(
            now, 1,
            "the generation advances so the bad filter is not retried"
        );
        assert_eq!(
            rx.try_recv(),
            Ok(FilterApplyOutcome::Rejected {
                generation: 1,
                error: "syntax error".to_string()
            })
        );
    }

    /// With nothing pending, apply_pending installs nothing and returns the
    /// same generation.
    #[test]
    fn apply_pending_is_a_noop_when_nothing_pending() {
        let (h, _rx) = handle();
        let mut sink = MockSink {
            installed: Vec::new(),
            result: Ok(()),
        };
        assert_eq!(apply_pending(&mut sink, &h, 0), 0);
        assert!(sink.installed.is_empty());
    }
}
