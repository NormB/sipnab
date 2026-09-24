// SPDX-License-Identifier: MIT OR Apache-2.0

//! Break a live read that will not return on its own (NM2).
//!
//! The live loop stops by checking the shutdown flag and the `--duration`
//! limit between reads, and on the Linux packet socket every read comes back
//! within the poll interval, so those checks run. libpcap's netmap module does
//! not come back. `pcap_netmap_dispatch` loops `nm_dispatch` then `poll()`
//! until a frame arrives, and a poll timeout or an interrupting signal just
//! goes round again: the only way out is `p->break_loop`, which it checks at
//! the top of each pass. On a silent link `pcap_next_ex` therefore never
//! returned, and sipnab was still running 8 s after SIGTERM.
//!
//! A [`Breaker`] is a small thread beside the capture that watches the same
//! stop conditions the loop checks and calls `pcap_breakloop` when one holds.
//! libpcap then returns `PCAP_ERROR_BREAK` from the blocked read, which the
//! loop treats as a clean stop. It stops immediately: a stop never waits for
//! more traffic, and nothing still queued is kept.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

/// Whether a capture has to stop now: a stop was requested, or the
/// `--duration` limit has run out.
///
/// The same conditions the live loop checks between reads, in one place so
/// the thread that breaks a blocked read cannot disagree with the loop about
/// when to stop.
pub(crate) fn stop_due(shutdown: bool, elapsed: Duration, duration: Option<Duration>) -> bool {
    shutdown || duration.is_some_and(|limit| elapsed >= limit)
}

/// A thread that calls `breakloop` once `should_stop` holds, and is joined
/// when dropped.
pub(crate) struct Breaker {
    /// Set when the capture ends by itself, so the thread exits without
    /// breaking anything.
    done: Arc<AtomicBool>,
    /// The watching thread, taken and joined on drop.
    thread: Option<JoinHandle<()>>,
}

impl Breaker {
    /// Watch `should_stop` every `interval`, and call `breakloop` once, the
    /// first time it holds.
    pub(crate) fn spawn(
        name: String,
        should_stop: impl Fn() -> bool + Send + 'static,
        breakloop: impl Fn() + Send + 'static,
        interval: Duration,
    ) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let watching = Arc::clone(&done);
        let thread = std::thread::Builder::new().name(name).spawn(move || {
            // `park_timeout` rather than `sleep`, so a drop's `unpark`
            // ends the wait at once instead of after a full interval.
            while !watching.load(Ordering::Acquire) {
                if should_stop() {
                    breakloop();
                    return;
                }
                std::thread::park_timeout(interval);
            }
        });
        // A thread that cannot start leaves the capture as it was before this
        // module existed: stoppable by the loop's own checks, just not out of
        // a read that never returns. Better that than refusing to capture.
        let thread = match thread {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::warn!(
                    "Could not start the capture's stop watcher ({e}); a silent \
                     netmap link may not stop until a frame arrives"
                );
                None
            }
        };
        Self { done, thread }
    }
}

impl Drop for Breaker {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    const TICK: Duration = Duration::from_millis(10);

    #[test]
    fn a_stop_request_or_a_spent_duration_is_due_and_nothing_else_is() {
        let s = Duration::from_secs;
        assert!(stop_due(true, s(0), None), "a stop request");
        assert!(stop_due(false, s(5), Some(s(5))), "the duration reached");
        assert!(stop_due(false, s(6), Some(s(5))), "the duration passed");
        assert!(!stop_due(false, s(4), Some(s(5))), "time still left");
        assert!(
            !stop_due(false, s(3600), None),
            "no duration never runs out"
        );
    }

    /// The netmap shape: a read that loops until its break flag is set, and
    /// never returns for any other reason. The breaker has to be what ends it.
    #[test]
    fn a_stop_request_breaks_a_read_that_never_returns_by_itself() {
        let stop = Arc::new(AtomicBool::new(false));
        let break_flag = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let breaker = {
            let (stop, break_flag, calls) = (stop.clone(), break_flag.clone(), calls.clone());
            Breaker::spawn(
                "test-breaker".into(),
                move || stop.load(Ordering::Acquire),
                move || {
                    calls.fetch_add(1, Ordering::AcqRel);
                    break_flag.store(true, Ordering::Release);
                },
                TICK,
            )
        };
        let reader = {
            let break_flag = break_flag.clone();
            std::thread::spawn(move || {
                while !break_flag.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !reader.is_finished(),
            "nothing may break the read before a stop"
        );
        stop.store(true, Ordering::Release);
        let by = Instant::now() + Duration::from_secs(5);
        while !reader.is_finished() {
            assert!(Instant::now() < by, "the stop request never broke the read");
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(breaker);
        assert_eq!(calls.load(Ordering::Acquire), 1, "break exactly once");
    }

    /// A capture that ends by itself (a count reached, a file exhausted) drops
    /// its breaker at once: the thread exits without breaking, and the drop
    /// does not wait out an interval to find that out.
    #[test]
    fn a_capture_that_ends_on_its_own_is_never_broken_nor_held_up() {
        let calls = Arc::new(AtomicUsize::new(0));
        let breaker = {
            let calls = calls.clone();
            Breaker::spawn(
                "test-breaker".into(),
                || false,
                move || {
                    calls.fetch_add(1, Ordering::AcqRel);
                },
                Duration::from_secs(30),
            )
        };
        assert!(breaker.thread.is_some(), "the breaker runs a thread");
        // Let the thread reach its wait first. Dropped at once, it can see
        // `done` before it ever parks, and the drop proves nothing about
        // waking a thread that is waiting.
        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        drop(breaker);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "dropping waited {:?} for a 30 s interval",
            started.elapsed()
        );
        assert_eq!(calls.load(Ordering::Acquire), 0, "nothing was stopping");
    }
}
