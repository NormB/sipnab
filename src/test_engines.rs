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
#[derive(Clone)]
enum Reply {
    /// The body after the request's cookie, sent after the delay.
    Body(&'static [u8], Duration),
    /// Read the request and send nothing.
    Silent,
    /// Hold the first request until every engine of the group holds one,
    /// then answer [`LIST_BODY`]; give up, and answer nothing from then on,
    /// when they do not within the time given.
    Together(Arc<Together>, Duration),
}

/// How many engines of one [`FakeEngine::asked_together`] group hold their
/// first request right now.
struct Together {
    /// The size of the group.
    n: usize,
    /// Engines holding. One that gives up no longer holds.
    holding: std::sync::Mutex<usize>,
    /// Signaled at each arrival.
    one_more: std::sync::Condvar,
}

impl Together {
    /// Hold for up to `limit`. True when all `n` held at the same moment.
    fn hold(&self, limit: Duration) -> bool {
        let Ok(mut holding) = self.holding.lock() else {
            return false;
        };
        *holding += 1;
        self.one_more.notify_all();
        let Ok((mut holding, waited)) = self
            .one_more
            .wait_timeout_while(holding, limit, |h| *h < self.n)
        else {
            return false;
        };
        if waited.timed_out() {
            // Whoever asked has given up as well: this engine is no longer
            // one a later arrival finds waiting.
            *holding -= 1;
            return false;
        }
        true
    }
}

/// The wait of the clients of [`FakeEngine::asked_together`] engines, by the
/// engine's address. [`client_wait`] reads it, so a test's own harness builds
/// a patient client without knowing which kind of engine it was handed.
fn patient() -> &'static std::sync::Mutex<std::collections::HashMap<SocketAddr, Duration>> {
    static PATIENT: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<SocketAddr, Duration>>,
    > = std::sync::OnceLock::new();
    PATIENT.get_or_init(Default::default)
}

/// One fake engine, serving until dropped.
pub(crate) struct FakeEngine {
    /// Where it listens.
    pub(crate) addr: SocketAddr,
    /// Datagrams it has read.
    seen: Arc<AtomicUsize>,
    /// Whether it answered the first datagram it read.
    answered_first: Arc<AtomicBool>,
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

    /// `n` engines that answer only when asked at once: each holds the first
    /// request it reads until all `n` hold one, then answers [`LIST_BODY`].
    /// See [`all_answered`].
    pub(crate) fn asked_together(n: usize) -> std::io::Result<Vec<Self>> {
        Self::asked_together_within(n, PATIENCE)
    }

    /// As [`Self::asked_together`], holding for `patience`.
    pub(crate) fn asked_together_within(
        n: usize,
        patience: Duration,
    ) -> std::io::Result<Vec<Self>> {
        let group = Arc::new(Together {
            n,
            holding: std::sync::Mutex::new(0),
            one_more: std::sync::Condvar::new(),
        });
        (0..n)
            .map(|_| {
                let engine = Self::serve(Reply::Together(Arc::clone(&group), patience))?;
                if let Ok(mut waits) = patient().lock() {
                    waits.insert(engine.addr, patience);
                }
                Ok(engine)
            })
            .collect()
    }

    /// `total` engines in the shape of the dead-engine tests: a live one at
    /// index `live_at` (clamped to the end) and, in every other place, one
    /// of an [`Self::asked_together`] group of `total - 1`.
    pub(crate) fn together_beside_a_live_one(
        total: usize,
        live_at: usize,
    ) -> std::io::Result<Vec<Self>> {
        let mut engines = Self::asked_together(total.saturating_sub(1))?;
        engines.insert(live_at.min(engines.len()), Self::live()?);
        Ok(engines)
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
        crate::rtpengine::control::ControlClient::new(self.addr, client_wait(self.addr, TIMEOUT))
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
        let answered_first = Arc::new(AtomicBool::new(false));
        let (thread_seen, thread_stop) = (Arc::clone(&seen), Arc::clone(&stop));
        let thread_answered = Arc::clone(&answered_first);
        let handle = std::thread::Builder::new()
            .name("fake-engine".to_owned())
            .spawn(move || {
                let mut buf = [0u8; 4096];
                while !thread_stop.load(Ordering::SeqCst) {
                    let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                        continue;
                    };
                    let first = thread_seen.fetch_add(1, Ordering::SeqCst) == 0;
                    let body = match &reply {
                        Reply::Silent => continue,
                        Reply::Body(body, delay) => {
                            std::thread::sleep(*delay);
                            *body
                        }
                        Reply::Together(group, patience) => {
                            // Only the first request holds. A later one is
                            // answered when the first was, and never when the
                            // first gave up: one engine asked twice must not
                            // read as two engines asked at once.
                            let together = if first {
                                group.hold(*patience)
                            } else {
                                thread_answered.load(Ordering::SeqCst)
                            };
                            if !together {
                                continue;
                            }
                            LIST_BODY
                        }
                    };
                    if first {
                        thread_answered.store(true, Ordering::SeqCst);
                    }
                    let space = buf[..n].iter().position(|b| *b == b' ').unwrap_or(0);
                    let out = [&buf[..=space], body].concat();
                    let _ = sock.send_to(&out, peer);
                }
            })?;
        Ok(Self {
            addr,
            seen,
            answered_first,
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for FakeEngine {
    fn drop(&mut self) {
        if let Ok(mut waits) = patient().lock() {
            waits.remove(&self.addr);
        }
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

/// How long a client of the engine at `addr` waits: `asked`, or the
/// engine's own patience when it is one of [`FakeEngine::asked_together`].
pub(crate) fn client_wait(addr: SocketAddr, asked: Duration) -> Duration {
    patient()
        .lock()
        .ok()
        .and_then(|waits| waits.get(&addr).copied())
        .unwrap_or(asked)
}

/// A relay client for the engine at `addr`, giving up after `timeout`, or
/// after the engine's own patience ([`client_wait`]).
pub(crate) fn client(
    addr: SocketAddr,
    timeout: Duration,
) -> Arc<dyn crate::relay::reconcile::ReadOnlyRelay + Send + Sync> {
    Arc::new(crate::rtpengine::control::ControlClient::new(
        addr,
        client_wait(addr, timeout),
    ))
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
pub(crate) const TIMEOUT: Duration = Duration::from_millis(1500);

/// Whether `took` is at least one [`TIMEOUT`]: the caller did wait for its
/// dead engines.
///
/// It has no upper bound. "Short of two timeouts" stood here as the proof
/// that dead engines are asked at once and not in turn, first with a 500 ms
/// timeout and then with 1.5 s, and a loaded host broke each: 1.04 s against
/// a bound of 1 s, then 3.07 s against a bound of 3 s (load 36 on 14 cores,
/// 2026-11-14). How long a wait takes on a busy host has no bound a test can
/// name. What the tests mean is "asked at once", and
/// [`FakeEngine::asked_together`] with [`all_answered`] shows that with no
/// clock.
pub(crate) fn waited_a_timeout(took: Duration) -> bool {
    took >= TIMEOUT
}

/// How long an engine of [`FakeEngine::asked_together`] holds its first
/// request for the others, and how long its client waits for it.
///
/// Long, because nothing waits it out when the engines are asked at once:
/// they answer as soon as the last of them holds a request. Only a caller
/// that asks one after another pays it, and that caller fails its test.
pub(crate) const PATIENCE: Duration = Duration::from_secs(10);

/// Whether every engine answered the first request it read.
///
/// For engines of [`FakeEngine::asked_together`] that is true only when all
/// of them held a request at the same moment: they were asked at once, not
/// one after another. No clock is read, so a loaded host cannot change the
/// answer of a caller that does ask at once.
pub(crate) fn all_answered<'a>(engines: impl IntoIterator<Item = &'a FakeEngine>) -> bool {
    engines
        .into_iter()
        .all(|engine| engine.answered_first.load(Ordering::SeqCst))
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

    /// Ask `engine` once from a socket of its own and wait up to `wait` for
    /// its answer.
    ///
    /// A read that a signal interrupts goes on for the time that remains: a
    /// read with a timeout ends with `EINTR` whatever `SA_RESTART` says, and
    /// a caller that took that for "no answer" would stop waiting early and
    /// ask the next engine while this one still holds.
    fn ask(engine: &FakeEngine, wait: Duration) -> std::io::Result<bool> {
        let sock = UdpSocket::bind("127.0.0.1:0")?;
        sock.send_to(b"1 d7:command4:liste", engine.addr)?;
        let until = std::time::Instant::now() + wait;
        let mut buf = [0u8; 256];
        loop {
            let left = until.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Ok(false);
            }
            sock.set_read_timeout(Some(left))?;
            match sock.recv_from(&mut buf) {
                Ok(_) => return Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Ok(false),
            }
        }
    }

    /// A hold short enough for a test that waits it out.
    const SHORT: Duration = Duration::from_millis(150);

    /// Engines asked at once all answer, long before their patience ends.
    #[test]
    fn engines_asked_at_once_all_answer() -> std::io::Result<()> {
        let engines = FakeEngine::asked_together(3)?;
        let answers: Vec<bool> = std::thread::scope(|scope| {
            let threads: Vec<_> = engines
                .iter()
                .map(|e| scope.spawn(move || ask(e, PATIENCE).unwrap_or(false)))
                .collect();
            threads
                .into_iter()
                .map(|t| t.join().unwrap_or(false))
                .collect()
        });
        assert_eq!(answers, vec![true; 3], "each caller had its answer");
        assert!(all_answered(&engines), "all three held a request at once");
        Ok(())
    }

    /// Engines asked one after another never hold a request at the same
    /// moment, so none answers.
    #[test]
    fn engines_asked_in_turn_do_not_answer() -> std::io::Result<()> {
        let engines = FakeEngine::asked_together_within(3, SHORT)?;
        let mut answers = Vec::new();
        for engine in &engines {
            answers.push(ask(engine, SHORT * 2)?);
        }
        assert_eq!(answers, vec![false; 3], "no caller had an answer");
        assert!(!all_answered(&engines), "they were asked in turn");
        Ok(())
    }

    /// The last engine asked in turn does not answer because the earlier
    /// ones were asked before it: an engine that gave up no longer holds.
    #[test]
    fn an_engine_that_gave_up_does_not_count_for_a_later_one() -> std::io::Result<()> {
        let engines = FakeEngine::asked_together_within(2, SHORT)?;
        assert!(!ask(&engines[0], SHORT * 2)?, "the first waited alone");
        assert!(
            !ask(&engines[1], SHORT * 2)?,
            "the second arrived after the first gave up, and waited alone too"
        );
        assert!(!all_answered(&engines), "neither answered");
        Ok(())
    }

    /// One engine asked twice does not stand in for two engines.
    #[test]
    fn one_engine_asked_twice_is_not_two_engines() -> std::io::Result<()> {
        let engines = FakeEngine::asked_together_within(2, SHORT)?;
        assert!(
            !ask(&engines[0], SHORT * 2)?,
            "the first request waited alone"
        );
        assert!(
            !ask(&engines[0], SHORT * 2)?,
            "a second request to the same engine fills nothing"
        );
        assert!(!all_answered(&engines), "the other engine was never asked");
        Ok(())
    }

    /// An engine whose first request waited alone stays silent, also when a
    /// later round asks it beside the rest: only first requests hold.
    #[test]
    fn an_engine_that_gave_up_stays_silent_in_a_later_round() -> std::io::Result<()> {
        let engines = FakeEngine::asked_together_within(2, SHORT)?;
        assert!(
            !ask(&engines[0], SHORT * 2)?,
            "the first request waited alone"
        );
        let answers: Vec<bool> = std::thread::scope(|scope| {
            let threads: Vec<_> = engines
                .iter()
                .map(|e| scope.spawn(move || ask(e, SHORT * 2).unwrap_or(true)))
                .collect();
            threads
                .into_iter()
                .map(|t| t.join().unwrap_or(true))
                .collect()
        });
        assert_eq!(
            answers,
            vec![false; 2],
            "the first engine's second request does not hold, so the other waits alone"
        );
        assert!(
            !all_answered(&engines),
            "neither answered its first request"
        );
        Ok(())
    }

    /// All but one asked at once is not all: nobody answers.
    #[test]
    fn all_but_one_asked_at_once_do_not_answer() -> std::io::Result<()> {
        let engines = FakeEngine::asked_together_within(3, SHORT)?;
        let answers: Vec<bool> = std::thread::scope(|scope| {
            let threads: Vec<_> = engines[..2]
                .iter()
                .map(|e| scope.spawn(move || ask(e, SHORT * 2).unwrap_or(true)))
                .collect();
            threads
                .into_iter()
                .map(|t| t.join().unwrap_or(true))
                .collect()
        });
        assert_eq!(answers, vec![false; 2], "the third never held a request");
        assert!(!all_answered(&engines), "two of three is not all");
        Ok(())
    }

    /// Once all have answered together, a later request is answered at once.
    #[test]
    fn after_answering_together_an_engine_answers_again() -> std::io::Result<()> {
        let engines = FakeEngine::asked_together(2)?;
        std::thread::scope(|scope| {
            for e in &engines {
                scope.spawn(move || ask(e, PATIENCE));
            }
        });
        assert!(all_answered(&engines), "both held a request at once");
        assert!(
            ask(&engines[0], PATIENCE)?,
            "a path that asks an engine a second question still gets its answer"
        );
        Ok(())
    }

    /// The client of such an engine waits as long as the engine holds, and
    /// the client of any other engine waits what its test asked for.
    #[test]
    fn the_client_of_an_engine_asked_together_waits_its_patience() -> std::io::Result<()> {
        let engines = FakeEngine::asked_together(2)?;
        let addr = engines[0].addr;
        assert_eq!(
            client_wait(addr, TIMEOUT),
            PATIENCE,
            "a client that gave up at TIMEOUT would fail on a slow host"
        );
        let dead = FakeEngine::dead()?;
        assert_eq!(client_wait(dead.addr, TIMEOUT), TIMEOUT, "any other engine");
        drop(engines);
        assert_eq!(
            client_wait(addr, TIMEOUT),
            TIMEOUT,
            "a dropped engine leaves nothing behind for the next socket on its port"
        );
        Ok(())
    }

    /// An engine that is not of that kind answers its first request or does
    /// not, as its kind says.
    #[test]
    fn all_answered_reads_the_ordinary_engines_too() -> std::io::Result<()> {
        let live = FakeEngine::live()?;
        assert!(ask(&live, PATIENCE)?, "a live engine answers");
        assert!(all_answered([&live]), "it answered its first request");
        let dead = FakeEngine::dead()?;
        assert!(!ask(&dead, SHORT)?, "a dead engine does not");
        assert!(
            !all_answered([&live, &dead]),
            "one of the two did not answer"
        );
        assert!(
            !all_answered([&FakeEngine::live()?]),
            "an engine never asked"
        );
        Ok(())
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
