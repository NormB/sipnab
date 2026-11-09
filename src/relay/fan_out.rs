// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Put one question to every listed engine at once.
//!
//! A question asked of every engine the run lists (startup reconciliation,
//! the relay's own counters, the lists that find an unseen call's engine)
//! used to ask them one after another. Each engine's control timeout is 2 s
//! ([`crate::rtpengine::control::DEFAULT_CONTROL_TIMEOUT`]), so an engine
//! that does not answer cost 2 s, and every further dead engine cost 2 s more.
//! Asked at once, the question costs the slowest engine's answer: one timeout
//! however many engines are down.
//!
//! # The bounds
//!
//! - **One thread per engine, for one question.** [`ask_each`] spawns one
//!   scoped thread per item and joins every one before it returns, so no
//!   thread outlives the question and none is left behind when an ask panics.
//!   An engine is asked one question at a time, which is one control socket
//!   at a time: a question never holds more sockets than there are engines.
//! - **Configured order.** The answers come back in the order the engines
//!   were given, whatever order they arrive in, so every surface still prints
//!   `--rtpengine-control` first and then each engine row in turn.
//! - **Nothing shared between engines.** Each engine keeps its own ceiling of
//!   control transactions, because each thread works on one engine's state
//!   and nothing else.

/// Ask each of `items` with `ask`, all at once, and return the answers in the
/// order of `items`.
///
/// One scoped thread per item. Every thread is joined before this returns.
/// Zero or one item is asked on the calling thread, since there is nothing to
/// wait on in parallel. When the system refuses a thread, that item is asked
/// on the calling thread after the others have been started, so the answer is
/// still there and only that item's wait is added.
///
/// # Panics
///
/// When an `ask` panics, the panic is raised again here once every other
/// thread has finished, as it would have been raised had the items been asked
/// one after another.
pub fn ask_each<I, T, F>(items: Vec<I>, ask: F) -> Vec<T>
where
    I: Send,
    T: Send,
    F: Fn(I) -> T + Sync,
{
    if items.len() < 2 {
        return items.into_iter().map(ask).collect();
    }
    // Each item waits in its own slot, so an item whose thread the system
    // refused is still there to be asked on this thread.
    let slots: Vec<parking_lot::Mutex<Option<I>>> = items
        .into_iter()
        .map(|i| parking_lot::Mutex::new(Some(i)))
        .collect();
    let ask = &ask;
    std::thread::scope(|scope| {
        let threads: Vec<_> = slots
            .iter()
            .map(|slot| {
                std::thread::Builder::new()
                    .name("relay-ask".to_owned())
                    .spawn_scoped(scope, move || slot.lock().take().map(ask))
                    .ok()
            })
            .collect();
        slots
            .iter()
            .zip(threads)
            .filter_map(|(slot, thread)| {
                let answered = match thread.map(std::thread::ScopedJoinHandle::join) {
                    Some(Ok(answer)) => answer,
                    Some(Err(panic)) => std::panic::resume_unwind(panic),
                    None => None,
                };
                answered.or_else(|| slot.lock().take().map(ask))
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engines::Gate;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    type TestError = Box<dyn std::error::Error>;

    /// The answers are in the order the items were given.
    #[test]
    fn the_answers_come_back_in_the_order_given() {
        let out = ask_each(vec![3, 1, 2], |n| n * 10);
        assert_eq!(out, vec![30, 10, 20], "each answer in its item's place");
    }

    /// Every item is asked at the same time: each reaches a gate that opens
    /// only when all of them are there. Asked in turn, the first waits alone
    /// and gives up.
    #[test]
    fn every_item_is_asked_at_the_same_time() {
        let gate = Gate::new(4);
        let out = ask_each(vec![0, 1, 2, 3], |_| gate.arrive(Duration::from_secs(5)));
        assert_eq!(out, vec![true; 4], "all four were waiting together");
    }

    /// Each item is asked once, never twice and never skipped.
    #[test]
    fn each_item_is_asked_exactly_once() {
        let asked: Vec<AtomicUsize> = (0..5).map(|_| AtomicUsize::new(0)).collect();
        let _ = ask_each((0..5).collect(), |i: usize| {
            asked[i].fetch_add(1, Ordering::SeqCst)
        });
        let counts: Vec<usize> = asked.iter().map(|a| a.load(Ordering::SeqCst)).collect();
        assert_eq!(counts, vec![1; 5], "each item asked once");
    }

    /// No items asks nothing and answers nothing.
    #[test]
    fn no_items_asks_nothing() {
        let asked = AtomicUsize::new(0);
        let out: Vec<()> = ask_each(Vec::<u8>::new(), |_| {
            asked.fetch_add(1, Ordering::SeqCst);
        });
        assert!(out.is_empty(), "no items, no answers");
        assert_eq!(asked.load(Ordering::SeqCst), 0, "and nothing asked");
    }

    /// One item is asked on the calling thread: there is nothing to wait on
    /// in parallel, so no thread is started.
    #[test]
    fn one_item_is_asked_on_the_callers_thread() {
        let caller = std::thread::current().id();
        let out = ask_each(vec![()], |()| std::thread::current().id());
        assert_eq!(out, vec![caller], "one item runs on the caller's thread");
    }

    /// Several items are each asked on a thread of their own, never two on
    /// one and never on the caller's.
    #[test]
    fn several_items_each_get_a_thread_of_their_own() {
        let caller = std::thread::current().id();
        let ids = ask_each(vec![(); 3], |()| std::thread::current().id());
        assert!(!ids.contains(&caller), "not on the caller: {ids:?}");
        let mut distinct = ids.clone();
        distinct.sort_by_key(|id| format!("{id:?}"));
        distinct.dedup();
        assert_eq!(distinct.len(), 3, "three threads: {ids:?}");
    }

    /// No more asks are in flight at once than there are items: one per
    /// item, which for an engine is one socket.
    #[test]
    fn no_more_asks_are_in_flight_than_items() {
        let in_flight = AtomicUsize::new(0);
        let most = AtomicUsize::new(0);
        let gate = Gate::new(3);
        let _ = ask_each(vec![(); 3], |()| {
            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            most.fetch_max(now, Ordering::SeqCst);
            let _ = gate.arrive(Duration::from_secs(5));
            in_flight.fetch_sub(1, Ordering::SeqCst);
        });
        assert_eq!(
            most.load(Ordering::SeqCst),
            3,
            "all three at once, never more"
        );
        assert_eq!(in_flight.load(Ordering::SeqCst), 0, "every ask finished");
    }

    /// Answers that arrive last-first still come back first-first.
    #[test]
    fn answers_that_arrive_in_reverse_keep_the_given_order() {
        let finished = std::sync::Mutex::new(Vec::new());
        let out = ask_each(vec![0_u64, 1, 2], |i| {
            std::thread::sleep(Duration::from_millis(150 * (2 - i)));
            if let Ok(mut f) = finished.lock() {
                f.push(i);
            }
            i
        });
        assert_eq!(
            finished.lock().map(|f| f.clone()).unwrap_or_default(),
            vec![2, 1, 0],
            "the fixture made them finish in reverse"
        );
        assert_eq!(out, vec![0, 1, 2], "the answers are in the given order");
    }

    /// A panicking ask is raised again, and only after every other ask has
    /// finished: no thread is left running.
    #[test]
    fn a_panicking_ask_is_raised_after_the_others_finish() -> Result<(), TestError> {
        let finished = AtomicUsize::new(0);
        // catch_unwind: the panic is the input under test, caught so the test
        // can check it was raised again and when.
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ask_each(vec![0_u64, 1, 2], |i| {
                if i == 0 {
                    panic!("engine 0 panicked");
                }
                std::thread::sleep(Duration::from_millis(200));
                finished.fetch_add(1, Ordering::SeqCst);
            })
        }));
        let payload = caught.err().ok_or("the panic must be raised again")?;
        let message = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        assert_eq!(
            message, "engine 0 panicked",
            "the panic raised again is the ask's own"
        );
        assert_eq!(
            finished.load(Ordering::SeqCst),
            2,
            "both other asks finished before the panic was raised"
        );
        Ok(())
    }
}
