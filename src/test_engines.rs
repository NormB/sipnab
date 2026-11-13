// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Engines for tests: local UDP sockets that answer as rtpengine frames a
//! reply, late, cut short, or never.
//!
//! Real sockets rather than doubles, because what a dead engine costs is a
//! socket's read timeout, and a double would assert that cost back at the
//! test. Each engine's thread is joined when the engine is dropped.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// A `list` reply naming one call, which also reads as `statistics`
/// (its flattened pairs are the engine's counters).
pub(crate) const LIST_BODY: &[u8] = b"d6:result2:ok5:callsl20:up-1@example.invalidee";

/// A reply cut off part way through its dictionary.
pub(crate) const CUT_BODY: &[u8] = b"d6:result2:ok5:callsl20:up-1@exa";

/// How a fake engine answers each datagram.
#[derive(Clone, Copy)]
enum Reply {
    /// The body after the request's cookie, sent after the delay.
    Body(&'static [u8], Duration),
    /// Read the request and send nothing.
    Silent,
}

/// One fake engine, serving until dropped.
pub(crate) struct FakeEngine {
    /// Where it listens.
    pub(crate) addr: SocketAddr,
    /// Datagrams it has read.
    seen: Arc<AtomicUsize>,
    /// Tells the thread to stop.
    stop: Arc<AtomicBool>,
    /// The serving thread, joined on drop.
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FakeEngine {
    /// An engine that answers every request with `body` after `delay`.
    pub(crate) fn answering(body: &'static [u8], delay: Duration) -> std::io::Result<Self> {
        Self::serve(Reply::Body(body, delay))
    }

    /// An engine that answers every request with [`LIST_BODY`] at once.
    pub(crate) fn live() -> std::io::Result<Self> {
        Self::answering(LIST_BODY, Duration::ZERO)
    }

    /// An engine that reads every request and never answers.
    pub(crate) fn dead() -> std::io::Result<Self> {
        Self::serve(Reply::Silent)
    }

    /// An engine that answers every request with [`CUT_BODY`].
    pub(crate) fn cut() -> std::io::Result<Self> {
        Self::answering(CUT_BODY, Duration::ZERO)
    }

    /// The engine as the subject of a sentence, as its client describes
    /// it, so a test names it without naming the implementation.
    pub(crate) fn describe(&self) -> String {
        client(self.addr, TIMEOUT).describe()
    }

    /// The client that asks this engine, giving up after [`TIMEOUT`].
    pub(crate) fn control_client(&self) -> crate::rtpengine::control::ControlClient {
        crate::rtpengine::control::ControlClient::new(self.addr, TIMEOUT)
    }

    /// Requests it has read so far.
    pub(crate) fn requests(&self) -> usize {
        self.seen.load(Ordering::SeqCst)
    }

    fn serve(reply: Reply) -> std::io::Result<Self> {
        let sock = UdpSocket::bind("127.0.0.1:0")?;
        sock.set_read_timeout(Some(Duration::from_millis(20)))?;
        let addr = sock.local_addr()?;
        let seen = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_seen, thread_stop) = (Arc::clone(&seen), Arc::clone(&stop));
        let handle = std::thread::Builder::new()
            .name("fake-engine".to_owned())
            .spawn(move || {
                let mut buf = [0u8; 4096];
                while !thread_stop.load(Ordering::SeqCst) {
                    let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                        continue;
                    };
                    thread_seen.fetch_add(1, Ordering::SeqCst);
                    let Reply::Body(body, delay) = reply else {
                        continue;
                    };
                    std::thread::sleep(delay);
                    let space = buf[..n].iter().position(|b| *b == b' ').unwrap_or(0);
                    let out = [&buf[..=space], body].concat();
                    let _ = sock.send_to(&out, peer);
                }
            })?;
        Ok(Self {
            addr,
            seen,
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for FakeEngine {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A gate every one of `n` callers must reach before any passes, so a
/// test can tell asks made at once from asks made in turn without timing
/// them: asked in turn, the first caller waits alone and gives up.
pub(crate) struct Gate {
    n: usize,
    arrived: std::sync::Mutex<usize>,
    all_here: std::sync::Condvar,
}

impl Gate {
    /// A gate for `n` callers.
    pub(crate) fn new(n: usize) -> Self {
        Self {
            n,
            arrived: std::sync::Mutex::new(0),
            all_here: std::sync::Condvar::new(),
        }
    }

    /// Arrive, and wait up to `limit` for the rest. True when all `n`
    /// arrived in time.
    pub(crate) fn arrive(&self, limit: Duration) -> bool {
        let Ok(mut arrived) = self.arrived.lock() else {
            return false;
        };
        *arrived += 1;
        self.all_here.notify_all();
        match self
            .all_here
            .wait_timeout_while(arrived, limit, |a| *a < self.n)
        {
            Ok((_, waited)) => !waited.timed_out(),
            Err(_) => false,
        }
    }
}

/// The order callers finish in, set by an event and not by time: each
/// caller finishes only once a given number of others have, so a test can
/// make work started first finish last on a host of any load. Sleeps of
/// different lengths do not: a loaded CI runner ran two of them out of order.
pub(crate) struct FinishOrder<T> {
    finished: std::sync::Mutex<Vec<T>>,
    one_more: std::sync::Condvar,
}

impl<T: Clone> FinishOrder<T> {
    /// Nobody has finished.
    pub(crate) fn new() -> Self {
        Self {
            finished: std::sync::Mutex::new(Vec::new()),
            one_more: std::sync::Condvar::new(),
        }
    }

    /// Wait up to `limit` until `earlier` callers have finished, then
    /// finish as `who`. True when that many had finished in time.
    ///
    /// A caller that gives up at `limit` is recorded all the same, so the
    /// order a test then reads shows what happened and no thread waits for
    /// ever.
    pub(crate) fn finish_after(&self, earlier: usize, who: T, limit: Duration) -> bool {
        let Ok(finished) = self.finished.lock() else {
            return false;
        };
        let Ok((mut finished, waited)) = self
            .one_more
            .wait_timeout_while(finished, limit, |f| f.len() < earlier)
        else {
            return false;
        };
        finished.push(who);
        self.one_more.notify_all();
        !waited.timed_out()
    }

    /// Who has finished, first to last.
    pub(crate) fn order(&self) -> Vec<T> {
        self.finished.lock().map(|f| f.clone()).unwrap_or_default()
    }
}

/// A relay client for the engine at `addr`, giving up after `timeout`.
pub(crate) fn client(
    addr: SocketAddr,
    timeout: Duration,
) -> Arc<dyn crate::relay::reconcile::ReadOnlyRelay + Send + Sync> {
    Arc::new(crate::rtpengine::control::ControlClient::new(addr, timeout))
}

/// Routing whose default engine is `engines[0]` and whose ng engine rows
/// name the rest, in order, each reached by a real client that gives up
/// after `timeout`.
///
/// # Errors
///
/// When `engines` is empty or names one address twice.
pub(crate) fn routing(
    engines: &[&FakeEngine],
    timeout: Duration,
) -> Result<crate::relay::engines::EngineRouting, Box<dyn std::error::Error>> {
    let (first, rest) = engines.split_first().ok_or("at least one engine")?;
    let rows = rest
        .iter()
        .map(|e| crate::relay::engines::NgEngineRow {
            homer_id: None,
            control: e.addr,
        })
        .collect();
    Ok(crate::relay::engines::EngineRouting::new(
        crate::relay::engines::EngineRules {
            sdp: None,
            ng: crate::relay::engines::NgEngineMap::new(rows)?,
        },
        first.addr,
        false,
        Arc::new(move |control| client(control, timeout)),
    ))
}

/// How long a test engine's client waits for a reply.
///
/// Long enough that the scheduling delay of a loaded host stays well
/// inside the margin [`one_timeout`] allows: with 500 ms, one run of the
/// library suite on a host at load 34 on 14 cores measured 1.04 s for a
/// question that waits one timeout, past the bound of two. The tests wait
/// out three or more dead engines, so asked in turn they would take
/// three timeouts, 4.5 s, against a bound of 3 s.
pub(crate) const TIMEOUT: Duration = Duration::from_millis(1500);

/// Whether `took` is the cost of one timeout rather than of several in
/// turn: at least one [`TIMEOUT`] and short of two.
pub(crate) fn one_timeout(took: Duration) -> bool {
    took >= TIMEOUT && took < TIMEOUT * 2
}

/// A permit, which only a live source can grant.
pub(crate) fn live_permit()
-> Result<crate::security::transmit_guard::TransmitPermit, Box<dyn std::error::Error>> {
    Ok(crate::security::transmit_guard::TransmitPermit::for_source(
        &crate::capture::CaptureSource::Live {
            device: "eth0".to_owned(),
        },
    )
    .ok_or("a live source grants a permit")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A caller that waits for nobody records at once, and reports that it
    /// did not give up.
    #[test]
    fn a_caller_that_waits_for_nobody_finishes_at_once() {
        let order = FinishOrder::new();
        assert!(
            order.finish_after(0, "a", Duration::from_secs(30)),
            "nothing to wait for"
        );
        assert_eq!(order.order(), vec!["a"], "it is recorded");
    }

    /// Callers started in any order finish in the order their counts name:
    /// each waits for that many others to have finished, and is released by
    /// their finishing, long before its limit. A caller nobody releases
    /// stays its whole limit, and at the limit can still find its count
    /// reached.
    #[test]
    fn callers_finish_in_the_order_their_counts_name() {
        let order = FinishOrder::new();
        let started = std::time::Instant::now();
        let in_turn = std::thread::scope(|scope| {
            // The counts name an order that is neither the order started in
            // nor its reverse: threads that did not wait have been seen to
            // finish in each of those two.
            let threads: Vec<_> = [2_usize, 0, 3, 1]
                .into_iter()
                .enumerate()
                .map(|(i, earlier)| {
                    let order = &order;
                    scope.spawn(move || order.finish_after(earlier, i, Duration::from_secs(30)))
                })
                .collect();
            threads
                .into_iter()
                .map(|t| t.join().unwrap_or(false))
                .collect::<Vec<_>>()
        });
        assert_eq!(in_turn, vec![true; 4], "none gave up its wait");
        assert_eq!(
            order.order(),
            vec![1, 3, 0, 2],
            "each finished after as many others as its count"
        );
        let took = started.elapsed();
        assert!(
            took < Duration::from_secs(30),
            "each was released by a finish, not by its 30 s limit: took {took:?}"
        );
    }

    /// A caller whose turn never comes gives up at its limit, says so, and
    /// is still recorded, so a test's assertion on the order shows what
    /// happened and no thread waits for ever.
    #[test]
    fn a_caller_whose_turn_never_comes_gives_up_and_says_so() {
        let order = FinishOrder::new();
        assert!(
            !order.finish_after(1, "alone", Duration::from_millis(20)),
            "nobody finished before it, so it gave up"
        );
        assert_eq!(order.order(), vec!["alone"], "recorded all the same");
    }

    /// A caller that arrives once its count is already reached does not
    /// wait: with no limit at all it finishes and reports that it did not
    /// give up.
    #[test]
    fn a_caller_whose_count_is_already_reached_does_not_wait() {
        let order = FinishOrder::new();
        assert!(
            order.finish_after(0, "first", Duration::ZERO),
            "the first waits for nobody"
        );
        assert!(
            order.finish_after(1, "second", Duration::ZERO),
            "one had finished, which is the count the second names"
        );
        assert!(
            !order.finish_after(3, "third", Duration::ZERO),
            "two have finished, not three, and it has no time to wait"
        );
        assert_eq!(order.order(), vec!["first", "second", "third"], "in turn");
    }
}
