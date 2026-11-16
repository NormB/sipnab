// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//! One blocking socket call, bounded by a deadline and tried again when a
//! signal interrupts it.
//!
//! A read or a send on a socket with a timeout fails with `EINTR` when any
//! handled signal reaches the thread, even with `SA_RESTART` (signal(7)), and
//! sipnab handles `SIGINT`, `SIGTERM`, `SIGUSR1` and `SIGHUP`
//! ([`crate::signals`]). Without a retry an interrupted call reads as a real
//! failure: an engine that was about to answer as one that did not answer
//! (under the library test suite, 1.5 s waits ended after 0.7 s with
//! `Interrupted system call (os error 4)`), a datagram that was about to
//! leave as one that was dropped. The rtpengine control client's reads and
//! send and the live RTP sender go through [`retry_until`].

use std::io::ErrorKind;
use std::time::{Duration, Instant};

/// Run `attempt` with what is left of the time until `deadline`, again
/// whenever it fails with `Interrupted`, until `deadline`.
///
/// `attempt` is given the time left, which it sets as the socket's timeout.
/// Any other answer, success or failure, is returned at once. Past `deadline`
/// this fails as a timeout does, `WouldBlock`; `attempt` is not called with
/// no time left.
///
/// # Errors
///
/// What `attempt` returns other than `Interrupted`, or `WouldBlock` at the
/// deadline.
pub(crate) fn retry_until<T>(
    deadline: Instant,
    now: &dyn Fn() -> Instant,
    mut attempt: impl FnMut(Duration) -> std::io::Result<T>,
) -> std::io::Result<T> {
    loop {
        let left = deadline.saturating_duration_since(now());
        if left.is_zero() {
            return Err(ErrorKind::WouldBlock.into());
        }
        match attempt(left) {
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            done => return done,
        }
    }
}

/// Send with `send` within `limit` from now: `send` is given the time left,
/// which it sets as the socket's write timeout, and is called again when a
/// signal interrupts it.
///
/// A UDP send waits for room in the socket buffer only up to its write
/// timeout; a signal that arrives during that wait ends it with
/// `Interrupted`, which is not a datagram that could not leave.
///
/// # Errors
///
/// What `send` returns other than `Interrupted`, or `WouldBlock` when
/// `limit` has passed.
pub(crate) fn send_within(
    limit: Duration,
    now: &dyn Fn() -> Instant,
    send: impl FnMut(Duration) -> std::io::Result<usize>,
) -> std::io::Result<usize> {
    retry_until(now() + limit, now, send)
}

/// [`retry_until`]: a call a signal interrupts is retried with what is left
/// of its timeout, and nothing else is.
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    type TestError = Box<dyn std::error::Error>;

    /// A clock that moves `step` each time it is read.
    fn stepping(start: Instant, step: Duration) -> impl Fn() -> Instant {
        let reads = Cell::new(0_u32);
        move || {
            let t = start + step * reads.get();
            reads.set(reads.get() + 1);
            t
        }
    }

    /// An interrupted call is tried again, and its answer is the answer.
    #[test]
    fn an_interrupted_read_is_retried_and_answers() -> Result<(), TestError> {
        let start = Instant::now();
        let clock = stepping(start, Duration::from_millis(100));
        let mut tries = 0;
        let got = retry_until(start + Duration::from_secs(2), &clock, |_| {
            tries += 1;
            if tries < 3 {
                Err(ErrorKind::Interrupted.into())
            } else {
                Ok(42)
            }
        })?;
        assert_eq!((got, tries), (42, 3), "the third try answered");
        Ok(())
    }

    /// Interrupted until the deadline, the call fails as a timeout does.
    #[test]
    fn interrupted_until_the_deadline_is_a_timeout() {
        let start = Instant::now();
        let clock = stepping(start, Duration::from_millis(500));
        let mut tries = 0;
        let got: std::io::Result<()> = retry_until(start + Duration::from_secs(2), &clock, |_| {
            tries += 1;
            Err(ErrorKind::Interrupted.into())
        });
        assert_eq!(
            got.map_err(|e| e.kind()),
            Err(ErrorKind::WouldBlock),
            "interrupted to the deadline reads as a timeout"
        );
        assert_eq!(tries, 4, "tried at 0, 0.5, 1 and 1.5 s, not at 2 s");
    }

    /// Each try is given only what is left of the timeout.
    #[test]
    fn each_try_gets_what_is_left_of_the_timeout() {
        let start = Instant::now();
        let clock = stepping(start, Duration::from_millis(600));
        let given = RefCell::new(Vec::new());
        let _: std::io::Result<()> = retry_until(start + Duration::from_secs(2), &clock, |left| {
            given.borrow_mut().push(left);
            Err(ErrorKind::Interrupted.into())
        });
        assert_eq!(
            given.into_inner(),
            vec![
                Duration::from_millis(2000),
                Duration::from_millis(1400),
                Duration::from_millis(800),
                Duration::from_millis(200),
            ],
            "each try gets only what is left",
        );
    }

    /// Any other failure is returned at once, not retried.
    #[test]
    fn any_other_failure_is_not_retried() {
        let start = Instant::now();
        let clock = stepping(start, Duration::from_millis(1));
        let mut tries = 0;
        let got: std::io::Result<()> = retry_until(start + Duration::from_secs(2), &clock, |_| {
            tries += 1;
            Err(ErrorKind::ConnectionRefused.into())
        });
        assert_eq!(
            got.map_err(|e| e.kind()),
            Err(ErrorKind::ConnectionRefused),
            "a refused connection is not retried"
        );
        assert_eq!(tries, 1, "tried once");
    }

    /// A clock read only by the code under test, starting at `start`.
    fn clock(step_ms: u64) -> (Instant, impl Fn() -> Instant) {
        let start = Instant::now();
        (start, stepping(start, Duration::from_millis(step_ms)))
    }

    // SUCCESS

    #[test]
    fn a_send_that_leaves_at_once_is_sent_once() -> Result<(), TestError> {
        let (_, now) = clock(1);
        let mut tries = 0;
        let sent = send_within(Duration::from_millis(20), &now, |_| {
            tries += 1;
            Ok(12)
        })?;
        assert_eq!((sent, tries), (12, 1), "one try, its byte count");
        Ok(())
    }

    #[test]
    fn a_send_a_signal_interrupts_once_is_sent() -> Result<(), TestError> {
        let (_, now) = clock(1);
        let mut tries = 0;
        let sent = send_within(Duration::from_millis(20), &now, |_| {
            tries += 1;
            if tries == 1 {
                Err(ErrorKind::Interrupted.into())
            } else {
                Ok(12)
            }
        })?;
        assert_eq!((sent, tries), (12, 2), "the second try sent it");
        Ok(())
    }

    #[test]
    fn a_send_interrupted_three_times_within_its_limit_is_sent() -> Result<(), TestError> {
        let (_, now) = clock(2);
        let mut tries = 0;
        let sent = send_within(Duration::from_millis(20), &now, |_| {
            tries += 1;
            if tries <= 3 {
                Err(ErrorKind::Interrupted.into())
            } else {
                Ok(7)
            }
        })?;
        assert_eq!((sent, tries), (7, 4), "the fourth try sent it");
        Ok(())
    }

    // FAILURE

    #[test]
    fn a_send_that_times_out_is_not_retried() {
        let (_, now) = clock(1);
        let mut tries = 0;
        let got = send_within(Duration::from_millis(20), &now, |_| {
            tries += 1;
            Err(ErrorKind::WouldBlock.into())
        });
        assert_eq!(
            got.map_err(|e| e.kind()),
            Err(ErrorKind::WouldBlock),
            "a timeout fails"
        );
        assert_eq!(tries, 1, "a real timeout is not tried again");
    }

    #[test]
    fn a_refused_send_is_not_retried() {
        let (_, now) = clock(1);
        let mut tries = 0;
        let got = send_within(Duration::from_millis(20), &now, |_| {
            tries += 1;
            Err(ErrorKind::ConnectionRefused.into())
        });
        assert_eq!(
            got.map_err(|e| e.kind()),
            Err(ErrorKind::ConnectionRefused),
            "a refusal fails as itself"
        );
        assert_eq!(tries, 1, "a refusal is not tried again");
    }

    #[test]
    fn a_send_interrupted_past_its_limit_fails_as_a_timeout() {
        let (_, now) = clock(8);
        let mut tries = 0;
        let got = send_within(Duration::from_millis(20), &now, |_| {
            tries += 1;
            Err(ErrorKind::Interrupted.into())
        });
        assert_eq!(
            got.map_err(|e| e.kind()),
            Err(ErrorKind::WouldBlock),
            "interrupted to the limit is a timeout, not an interruption"
        );
        assert_eq!(
            tries, 2,
            "the limit starts at 0 ms; tried at 8 and 16 ms, not at 24 ms"
        );
    }

    // EDGE

    #[test]
    fn each_send_try_gets_only_what_is_left_of_the_limit() {
        let (_, now) = clock(6);
        let given = RefCell::new(Vec::new());
        let _ = send_within(Duration::from_millis(20), &now, |left| {
            given.borrow_mut().push(left);
            Err(ErrorKind::Interrupted.into())
        });
        assert_eq!(
            given.into_inner(),
            vec![
                Duration::from_millis(14),
                Duration::from_millis(8),
                Duration::from_millis(2),
            ],
            "the limit is counted from the first clock read, each try gets the rest"
        );
    }

    #[test]
    fn a_send_with_no_time_is_not_tried() {
        let (_, now) = clock(1);
        let mut tries = 0;
        let got = send_within(Duration::ZERO, &now, |_| {
            tries += 1;
            Ok(1)
        });
        assert_eq!(
            got.map_err(|e| e.kind()),
            Err(ErrorKind::WouldBlock),
            "no time, no send"
        );
        assert_eq!(tries, 0, "send is not called with no time left");
    }

    #[test]
    fn an_interruption_then_a_refusal_answers_the_refusal() {
        let (_, now) = clock(1);
        let mut tries = 0;
        let got = send_within(Duration::from_millis(20), &now, |_| {
            tries += 1;
            if tries == 1 {
                Err(ErrorKind::Interrupted.into())
            } else {
                Err(ErrorKind::ConnectionRefused.into())
            }
        });
        assert_eq!(
            got.map_err(|e| e.kind()),
            Err(ErrorKind::ConnectionRefused),
            "the answer after the retry is the answer"
        );
        assert_eq!(tries, 2, "retried once, then the refusal stands");
    }
}
