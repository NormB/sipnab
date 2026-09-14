// SPDX-License-Identifier: MIT OR Apache-2.0

//! The thread that polls a relay's statistics on an interval (ST4 / C5).
//!
//! # Why a thread, and why a timer here when the reconciler has none
//!
//! [`crate::app::relay_reconciler`] is deliberately not a poller: it wakes only
//! when the capture path finds a stream nothing explains. This is the opposite
//! -- an operator asked, with `--relay-stats-interval`, for the relay's own
//! counters on a clock. It runs on its own thread for the same reason the
//! reconciler does: a poll is a blocking UDP round trip with a timeout measured
//! in seconds, and making it from the packet path would drop packets while the
//! relay is quiet.
//!
//! # What bounds it (ST4)
//!
//! The interval itself. The loop asks once, then waits the whole interval
//! before asking again, and the NEXT poll only begins once the previous one
//! returns -- so a slow relay slows the cadence rather than stacking
//! outstanding requests. There is no separate rate limiter because the shape of
//! the loop is the limiter: one transaction per interval, never overlapping.
//! This is also why ST9's "a timer fires while a previous poll is outstanding"
//! cannot happen here -- the poll is synchronous on this one thread.
//!
//! # Shutdown
//!
//! A `Receiver<()>` whose sender the capture owner drops when capture ends.
//! [`wait_outcome`] turns each `recv_timeout` result into the loop's decision:
//! a timeout is time to poll, and either a signal or a closed channel is time
//! to stop. Because the wait is `recv_timeout`, shutdown is prompt -- the
//! thread does not sleep out the rest of an interval after being told to stop.

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

/// What the loop does after one `recv_timeout` on the shutdown channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The interval elapsed with no shutdown: time to poll the relay.
    Poll,
    /// Told to stop, or the channel closed: end the loop.
    Stop,
}

/// Decide the loop's next move from a `recv_timeout` result (the pure core).
///
/// A `Timeout` means the interval passed without a shutdown, so poll. Anything
/// else -- an actual `()` signal (`Ok`) or a dropped sender (`Disconnected`) --
/// means stop. Kept pure and separate so the cadence-versus-shutdown decision
/// is tested without real time or a real relay.
#[must_use]
pub fn wait_outcome(recv: Result<(), RecvTimeoutError>) -> WaitOutcome {
    match recv {
        Err(RecvTimeoutError::Timeout) => WaitOutcome::Poll,
        Ok(()) | Err(RecvTimeoutError::Disconnected) => WaitOutcome::Stop,
    }
}

/// Poll on `interval` until told to stop, calling `poll` once per interval.
///
/// The first poll happens after one interval, not immediately: the flag asks
/// for the relay's counters *over time*, and a run's startup snapshot already
/// covers "right now". `poll` is injected so the loop is driven in a test with
/// no relay; in production it is the fetch-and-print closure [`spawn`] builds.
pub fn poll_loop<F: FnMut()>(interval: Duration, shutdown: &Receiver<()>, mut poll: F) {
    while wait_outcome(shutdown.recv_timeout(interval)) == WaitOutcome::Poll {
        poll();
    }
}

/// Spawn the poll thread.
///
/// `poll` is the action to run each interval -- in production, a closure that
/// fetches the relay's statistics and prints them marked as a poll. The
/// returned handle is joined by the capture owner after it drops the shutdown
/// sender, so a run never outlives its poller.
///
/// # Errors
///
/// When the thread cannot be spawned. A run whose poller will not start is
/// still worth capturing, so the caller reports and continues.
pub fn spawn<F: FnMut() + Send + 'static>(
    interval: Duration,
    shutdown: Receiver<()>,
    poll: F,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("rtpengine-poll".to_owned())
        .spawn(move || poll_loop(interval, &shutdown, poll))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::sync_channel;

    /// A timeout is the signal to poll.
    #[test]
    fn a_timeout_means_poll() {
        assert_eq!(
            wait_outcome(Err(RecvTimeoutError::Timeout)),
            WaitOutcome::Poll
        );
    }

    /// An explicit shutdown signal stops the loop.
    #[test]
    fn a_signal_means_stop() {
        assert_eq!(wait_outcome(Ok(())), WaitOutcome::Stop);
    }

    /// A closed channel (the sender dropped at capture end) stops the loop --
    /// the ordinary way a run ends its poller.
    #[test]
    fn a_closed_channel_means_stop() {
        assert_eq!(
            wait_outcome(Err(RecvTimeoutError::Disconnected)),
            WaitOutcome::Stop
        );
    }

    /// Dropping the sender ends the loop -- it does not hang waiting out the
    /// interval, and it does not poll after being told to stop.
    #[test]
    fn dropping_the_sender_ends_the_loop_without_polling() {
        let (tx, rx) = sync_channel::<()>(0);
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        // A long interval: if shutdown were not prompt, this test would hang far
        // past its own timeout rather than finish.
        let handle = spawn(Duration::from_secs(3600), rx, move || {
            c.fetch_add(1, Ordering::SeqCst);
        })
        .expect("spawns");
        drop(tx);
        handle
            .join()
            .expect("the loop ends when the channel closes");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no poll fires when shutdown arrives before the first interval"
        );
    }

    /// The loop calls `poll` once per elapsed interval and keeps going until the
    /// channel closes.
    ///
    /// Driven with a ZERO interval -- every `recv_timeout` returns `Timeout` at
    /// once -- and a sender the poll closure drops after a fixed number of calls,
    /// so the count is EXACT and no wall clock decides it. The earlier form slept
    /// 150ms at a 20ms interval and asserted "at least a couple"; a loaded CI
    /// runner fired only one and the suite went red, so the repeated-poll
    /// behavior is pinned deterministically here instead.
    #[test]
    fn poll_loop_polls_once_per_interval_until_the_channel_closes() {
        let (tx, rx) = sync_channel::<()>(0);
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let mut tx = Some(tx);
        poll_loop(Duration::ZERO, &rx, move || {
            // Drop the sender after the third poll; the next recv_timeout then
            // reads Disconnected and the loop stops.
            if c.fetch_add(1, Ordering::SeqCst) + 1 == 3 {
                tx.take();
            }
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "poll runs once per interval, repeatedly, until the channel closes"
        );
    }

    /// A stop signal already waiting ends the loop before any poll -- the
    /// `Ok(())` arm of `wait_outcome`, exercised through the real loop rather
    /// than in isolation.
    #[test]
    fn poll_loop_does_not_poll_when_a_signal_is_already_waiting() {
        let (tx, rx) = sync_channel::<()>(1);
        tx.send(()).expect("buffered send has room");
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        poll_loop(Duration::ZERO, &rx, move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        // `tx` outlives the loop, so the first recv reads the buffered signal,
        // not a disconnect.
        drop(tx);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a pending stop signal ends the loop before the first poll"
        );
    }

    /// A channel closed before the loop starts ends it before any poll -- the
    /// `Disconnected` arm, through the real loop.
    #[test]
    fn poll_loop_does_not_poll_when_the_channel_is_already_closed() {
        let (tx, rx) = sync_channel::<()>(0);
        drop(tx);
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        poll_loop(Duration::ZERO, &rx, move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a closed channel ends the loop before the first poll"
        );
    }
}
