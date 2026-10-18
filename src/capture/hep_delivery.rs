// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The `--hep-send` delivery thread: a bounded store-and-forward queue
//! between the capture and the collector.
//!
//! # Why this exists
//!
//! The capture loop used to write each HEP packet to the collector itself.
//! A collector that stopped reading stalled the capture; every redial of a
//! collector that had gone away held the capture for the dial; and a failed
//! write lost the packet. Other HEP agents' most-reported failures are the
//! same ones (heplify#323, captagent#101, heplify#297).
//!
//! The first connection is still made at startup, by the sender, and a
//! collector that refuses it stops the run with exit 2. This thread takes
//! over once the run has started.
//!
//! # The shape
//!
//! The capture thread [`push`](HepDelivery::push)es the finished packet into
//! a queue and returns: one short mutex hold, never a system call on the
//! network, and no allocation beyond the queue's own amortized growth (the
//! packet's buffer is moved in, not copied). One thread per exporter owns the
//! connection, takes packets from the front of the queue in order, and
//! writes them.
//!
//! # While the collector is unreachable
//!
//! A packet whose write fails goes back to the FRONT of the queue, and the
//! thread redials with exponential backoff ([`backoff_delay`]) from
//! `backoff_first` up to `backoff_cap`. Every dial and every write is bounded
//! by the `--hep-send-timeout`, so a blackholed collector costs one timeout
//! per attempt on THIS thread and nothing on the capture's. When the
//! collector answers, the queue is replayed in the order it was captured,
//! then the live feed continues behind it.
//!
//! # The bound, and what happens at it
//!
//! The queue holds at most `queue_bytes` of packet bytes. At the bound the
//! OLDEST packet is dropped, and counted as `queue_full`. Drop-oldest rather
//! than drop-newest because of where the hole ends up: an outage longer than
//! the queue loses a stretch of traffic either way, and with drop-oldest that
//! stretch is at the START of the outage, so what is replayed runs straight
//! into the live feed with no gap. Drop-newest would keep the start and cut
//! the stretch nearest to now -- the calls still in progress, which are the
//! ones an operator opening HOMER after an outage is looking for. The packet
//! the thread is holding for its next attempt sits at the front of the queue
//! and counts toward the bound like any other.
//!
//! # Delivery guarantee
//!
//! At-least-once across a reconnect, for every packet the sender still
//! holds: a write that failed partway is resent whole on the next
//! connection, so a collector that kept the first fragment can see that
//! packet twice. What the kernel had already ACCEPTED is out of the sender's
//! hands: a collector that vanishes without closing its connection can take
//! the unacknowledged contents of the socket's send buffer with it, and no
//! error ever names them. Before each write the connection is checked for an
//! orderly close by the collector (a pending FIN or RST), so a collector that
//! is stopped and restarted loses nothing; one that disappears silently can.
//!
//! # UDP
//!
//! UDP has no connection, and the sender's socket is unconnected, so the
//! kernel reports nothing about a collector that is down: no ICMP
//! port-unreachable reaches it as an error. A UDP send fails only when the
//! local stack refuses it, and then the packet is held and retried like a
//! failed TCP write. An outage of the collector itself is invisible over UDP,
//! which is what TCP or TLS are for.
//!
//! # Stop means stop
//!
//! On SIGINT or SIGTERM the queue is DISCARDED, never flushed, and the number
//! discarded is counted as `stopped`. Captured SIP carries credentials,
//! numbers and media keys, and data that outlives a stop is data an operator
//! believed was gone. The thread checks the stop flag before every write, so
//! nothing starts going out after the signal; a write already under way when
//! it lands is the one exception, and stopping also shuts the socket down
//! under it. The END OF THE INPUT is not a stop: a file read to its end
//! delivers what is queued, giving up (`unsent_at_exit`) only if the
//! collector stays unreachable for the grace period.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

use super::hep::HepExportPermit;
use super::hep_export::{DropReason, ExportFailure, HepExportCounters};

/// Why a link could not deliver: the failing step, and the error.
#[derive(Debug)]
pub(crate) struct SinkFailure {
    /// The step that failed, as the export counters name it.
    pub(crate) kind: ExportFailure,
    /// What the operating system or TLS said.
    pub(crate) error: std::io::Error,
}

impl SinkFailure {
    /// A failure at `kind`, carrying `error`.
    pub(crate) fn at(kind: ExportFailure, error: std::io::Error) -> Self {
        Self { kind, error }
    }
}

/// One transport's connection to the collector, as the delivery thread uses
/// it. Each method runs on the delivery thread only.
pub(crate) trait HepLink: Send {
    /// Whether a connection is in place to write to. Always true for UDP,
    /// which has none to lose.
    fn is_connected(&self) -> bool;

    /// Make the connection, within the link's own timeout.
    ///
    /// # Errors
    ///
    /// The step that failed: `Connect` for the TCP dial, `TlsHandshake` for
    /// the session on top of it.
    fn connect(&mut self) -> Result<(), SinkFailure>;

    /// Write one whole packet. On failure the link drops its connection, so
    /// the next attempt dials again.
    ///
    /// # Errors
    ///
    /// The step that failed, normally `Write`.
    fn send(&mut self, pkt: &[u8]) -> Result<(), SinkFailure>;

    /// A second handle on the live socket, which [`HepDelivery::stop`] shuts
    /// down to abort a write blocked inside the kernel. `None` when there is
    /// no stream to abort.
    fn abort_handle(&self) -> Option<std::net::TcpStream> {
        None
    }

    /// The local address of the live connection, for the startup log.
    ///
    /// # Errors
    ///
    /// There is no connection, or the socket cannot say.
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Err(std::io::ErrorKind::NotConnected.into())
    }
}

/// Asks whether the run has been told to stop: the process's signal flag in
/// production, a test's own flag in tests.
pub(crate) type StopCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// How the delivery thread behaves.
#[derive(Clone)]
pub(crate) struct DeliveryOpts {
    /// Packet bytes the queue may hold before it drops the oldest.
    pub(crate) queue_bytes: usize,
    /// Delay before the second attempt after a failure; doubles per failure.
    pub(crate) backoff_first: Duration,
    /// Longest delay between attempts.
    pub(crate) backoff_cap: Duration,
    /// The run's stop flag, checked before every write.
    pub(crate) stop_requested: StopCheck,
    /// The collector as the operator named it, for log lines.
    pub(crate) label: String,
}

/// The delay before the attempt that follows `failures` consecutive failed
/// ones.
///
/// Zero before any failure; then `first`, doubling per further failure, never
/// above `cap`. Pure, so the schedule is a fact a test can read.
#[must_use]
pub(crate) fn backoff_delay(first: Duration, cap: Duration, failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    let shift = (failures - 1).min(31);
    first.checked_mul(1u32 << shift).map_or(cap, |d| d.min(cap))
}

/// The queue the capture fills and the delivery thread empties.
struct Queue {
    /// Packets in capture order, each with its sequence number.
    items: VecDeque<(u64, Vec<u8>)>,
    /// Bytes of the packets in `items`.
    bytes: usize,
    /// The bound on `bytes`.
    limit: usize,
    /// The sequence number the next pushed packet gets.
    next_seq: u64,
    /// Set once by [`HepDelivery::halt`]; nothing is queued after it.
    halted: bool,
    /// Set by [`HepDelivery::finish`]: retry now rather than wait out the
    /// backoff, because the run is waiting on this queue.
    hurry: bool,
}

/// What the capture side and the delivery thread share.
struct Shared {
    /// The queue, and the halt flag that guards it.
    queue: Mutex<Queue>,
    /// Wakes the thread when a packet arrives or the run ends.
    wake: Condvar,
    /// Held across every write, so a halt can wait out the one under way.
    gate: Mutex<()>,
    /// The live socket, for aborting a write blocked inside the kernel.
    abort: Mutex<Option<std::net::TcpStream>>,
    /// The exporter's counters.
    counters: HepExportCounters,
    /// The run's stop flag.
    stop_requested: StopCheck,
}

impl Shared {
    /// Whether the thread must not send another packet.
    fn halted(&self) -> bool {
        self.queue.lock().halted || (self.stop_requested)()
    }

    /// Wait until a packet is queued. False when the run halted first.
    fn wait_for_work(&self) -> bool {
        let mut q = self.queue.lock();
        loop {
            if q.halted || (self.stop_requested)() {
                return false;
            }
            if !q.items.is_empty() {
                return true;
            }
            // A signal sets a flag and notifies nobody, so the wait is
            // bounded and the flag re-read.
            self.wake.wait_for(&mut q, POLL);
        }
    }

    /// Sleep until `at`. False when the run halted first; returns early when
    /// the run is hurrying the queue out.
    fn sleep_until(&self, at: Instant) -> bool {
        let mut q = self.queue.lock();
        loop {
            if q.halted || (self.stop_requested)() {
                return false;
            }
            let now = Instant::now();
            // `hurry` cuts ONE wait short and is spent doing it: the backoff
            // still governs the attempts after that, or a collector that is
            // down would be dialed in a tight loop for the whole grace period.
            if now >= at || std::mem::take(&mut q.hurry) {
                return true;
            }
            self.wake.wait_for(&mut q, (at - now).min(POLL));
        }
    }

    /// Take the oldest packet.
    fn pop(&self) -> Option<(u64, Vec<u8>)> {
        let mut q = self.queue.lock();
        let item = q.items.pop_front()?;
        q.bytes -= item.1.len();
        Some(item)
    }

    /// Put back a packet whose attempt failed, at the front where it came
    /// from. If the queue filled while it was out, it is now the oldest
    /// packet and the bound drops it, exactly as it would have dropped it
    /// had it never left.
    fn put_back(&self, item: (u64, Vec<u8>)) {
        let mut q = self.queue.lock();
        if q.halted {
            return;
        }
        if q.bytes + item.1.len() > q.limit {
            self.counters.record_dropped(DropReason::QueueFull, 1);
            return;
        }
        q.bytes += item.1.len();
        q.items.push_front(item);
    }
}

/// How often a waiting thread re-reads the stop flag, which a signal sets
/// without notifying anybody.
const POLL: Duration = Duration::from_millis(50);

/// The delivery side of one `--hep-send` exporter: the queue, and the thread
/// that empties it into the collector.
pub(crate) struct HepDelivery {
    /// The state the capture side and the thread share.
    shared: Arc<Shared>,
    /// The delivery thread, until it is waited for.
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl HepDelivery {
    /// Start the delivery thread over `link`.
    ///
    /// Taking the [`HepExportPermit`] keeps the answer to "what can put a
    /// packet on the network" where it was: the thread that writes to the
    /// collector cannot be started without proof the operator named it.
    ///
    /// # Errors
    ///
    /// The thread cannot be spawned.
    ///
    /// # Side effects
    ///
    /// Spawns the `hep-send` thread, which owns `link` from here on.
    pub(crate) fn start(
        _permit: &HepExportPermit,
        link: Box<dyn HepLink>,
        counters: HepExportCounters,
        opts: DeliveryOpts,
    ) -> std::io::Result<Self> {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue {
                items: VecDeque::new(),
                bytes: 0,
                limit: opts.queue_bytes,
                next_seq: 0,
                halted: false,
                hurry: false,
            }),
            wake: Condvar::new(),
            gate: Mutex::new(()),
            abort: Mutex::new(link.abort_handle()),
            counters,
            stop_requested: Arc::clone(&opts.stop_requested),
        });
        let thread_shared = Arc::clone(&shared);
        let worker = std::thread::Builder::new()
            .name("hep-send".to_string())
            .spawn(move || deliver(&thread_shared, link, &opts))?;
        Ok(Self {
            shared,
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Hand one finished packet to the queue. Never touches the network and
    /// never waits on it: the only wait is the queue's mutex, which the
    /// delivery thread holds for a pop or a push and never across I/O.
    ///
    /// At the bound the oldest packets are dropped, and counted, until this
    /// one fits. After a halt the packet is counted and discarded.
    pub(crate) fn push(&self, pkt: Vec<u8>) {
        let counters = &self.shared.counters;
        counters.record_queued();
        {
            let mut q = self.shared.queue.lock();
            if q.halted {
                counters.record_dropped(DropReason::Stopped, 1);
                return;
            }
            if pkt.len() > q.limit {
                counters.record_dropped(DropReason::QueueFull, 1);
                return;
            }
            while q.bytes + pkt.len() > q.limit {
                let Some((_, old)) = q.items.pop_front() else {
                    break;
                };
                q.bytes -= old.len();
                counters.record_dropped(DropReason::QueueFull, 1);
            }
            let seq = q.next_seq;
            q.next_seq += 1;
            q.bytes += pkt.len();
            q.items.push_back((seq, pkt));
        }
        self.shared.wake.notify_one();
    }

    /// Stop: discard everything queued, count it as `stopped`, and make sure
    /// nothing more is sent. No flush, by design.
    ///
    /// # Returns
    ///
    /// How many packets were discarded.
    pub(crate) fn stop(&self) -> u64 {
        self.halt(DropReason::Stopped)
    }

    /// The input has ended: wait for the queue to empty, then end the thread.
    ///
    /// Gives up when no packet has been delivered for `idle` -- the collector
    /// is not coming back within the run -- and discards what is left as
    /// `unsent_at_exit`. A stop signal while waiting discards it as `stopped`
    /// instead, at once.
    ///
    /// # Returns
    ///
    /// How many packets were discarded.
    pub(crate) fn finish(&self, idle: Duration) -> u64 {
        self.shared.queue.lock().hurry = true;
        self.shared.wake.notify_all();
        let counters = &self.shared.counters;
        let mut last_sent = counters.snapshot().sent;
        let mut progress_at = Instant::now();
        loop {
            if (self.shared.stop_requested)() {
                return self.halt(DropReason::Stopped);
            }
            let snap = counters.snapshot();
            if snap.depth() == 0 {
                return self.halt(DropReason::UnsentAtExit);
            }
            if snap.sent != last_sent {
                last_sent = snap.sent;
                progress_at = Instant::now();
            } else if progress_at.elapsed() >= idle {
                return self.halt(DropReason::UnsentAtExit);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// End the thread and discard what it still holds as `reason`.
    ///
    /// The order is the guarantee. Halting first stops new packets being
    /// queued and the thread starting another write; shutting the socket
    /// down aborts a write blocked in the kernel; taking the gate waits out
    /// a write that was already under way, so the count below sees its
    /// result. Only then is the remainder counted, from the identity
    /// `queued = sent + dropped + depth`, which also covers the packet the
    /// thread had taken out of the queue.
    fn halt(&self, reason: DropReason) -> u64 {
        {
            let mut q = self.shared.queue.lock();
            if q.halted {
                return 0;
            }
            q.halted = true;
        }
        self.shared.wake.notify_all();
        if let Some(sock) = self.shared.abort.lock().take() {
            let _ = sock.shutdown(std::net::Shutdown::Both);
        }
        drop(self.shared.gate.lock());
        let mut q = self.shared.queue.lock();
        q.items.clear();
        q.bytes = 0;
        let discarded = self.shared.counters.snapshot().depth();
        self.shared.counters.record_dropped(reason, discarded);
        discarded
    }

    /// Wait up to `within` for the delivery thread to exit.
    #[cfg(test)]
    fn join_within(&self, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        let mut slot = self.worker.lock();
        let Some(handle) = slot.as_ref() else {
            return true;
        };
        while !handle.is_finished() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        if let Some(h) = slot.take() {
            let _ = h.join();
        }
        true
    }
}

impl Drop for HepDelivery {
    /// Dropping the exporter is a stop: discard, never flush. The thread is
    /// not joined -- a dial in progress may hold it for one timeout -- but it
    /// sends nothing more.
    fn drop(&mut self) {
        self.halt(DropReason::Stopped);
        drop(self.worker.lock().take());
    }
}

/// The delivery thread: take the oldest packet, make sure there is a
/// connection, write it; on failure put it back and back off.
fn deliver(shared: &Shared, mut link: Box<dyn HepLink>, opts: &DeliveryOpts) {
    let counters = &shared.counters;
    // A link handed over without a connection starts in an outage.
    let mut outage = !link.is_connected();
    let mut failures: u32 = 0;
    let mut retry_at = Instant::now();
    // Packets numbered below this were queued before the collector last came
    // back, so delivering them is a replay.
    let mut replay_below: u64 = 0;
    loop {
        if !shared.wait_for_work() {
            return;
        }
        if failures > 0 && !shared.sleep_until(retry_at) {
            return;
        }
        if !link.is_connected() {
            match link.connect() {
                Ok(()) => *shared.abort.lock() = link.abort_handle(),
                Err(f) => {
                    counters.record_failure(f.kind);
                    note_failure(opts, &f, &mut outage, &mut failures, &mut retry_at);
                    continue;
                }
            }
        }
        let Some((seq, pkt)) = shared.pop() else {
            continue;
        };
        let gate = shared.gate.lock();
        if shared.halted() {
            return;
        }
        match link.send(&pkt) {
            Ok(()) => {
                if outage {
                    outage = false;
                    failures = 0;
                    replay_below = shared.queue.lock().next_seq;
                    counters.record_reconnect();
                    tracing::info!(
                        "HEP collector {} is reachable again; replaying {} queued packet(s)",
                        opts.label,
                        replay_below - seq
                    );
                }
                counters.record_sent();
                if seq < replay_below {
                    counters.record_replayed();
                }
            }
            Err(f) => {
                counters.record_failure(f.kind);
                shared.put_back((seq, pkt));
                note_failure(opts, &f, &mut outage, &mut failures, &mut retry_at);
            }
        }
        drop(gate);
    }
}

/// Record one failed attempt: enter the outage (logged once, at its start),
/// and schedule the next attempt on the backoff.
fn note_failure(
    opts: &DeliveryOpts,
    f: &SinkFailure,
    outage: &mut bool,
    failures: &mut u32,
    retry_at: &mut Instant,
) {
    if !*outage {
        tracing::warn!(
            "HEP collector {} unreachable ({}: {}); queueing up to {} KiB and retrying",
            opts.label,
            f.kind.as_str(),
            f.error,
            opts.queue_bytes / 1024
        );
    }
    *outage = true;
    *failures = failures.saturating_add(1);
    *retry_at = Instant::now() + backoff_delay(opts.backoff_first, opts.backoff_cap, *failures);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::hep::{HEP_SEND_FLAG, OperatorDestination};
    use crate::capture::hep_export::DropReason;
    use parking_lot::{Condvar, Mutex};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    type TestError = Box<dyn std::error::Error>;

    /// How long a test waits for something that must happen before calling
    /// it a failure. A hang detector, not a speed claim: every wait below
    /// polls a condition and returns the moment it holds.
    const MUST_HAPPEN: Duration = Duration::from_secs(30);

    /// What a [`ScriptLink`] does, set by the test while the worker runs.
    #[derive(Default)]
    struct ScriptState {
        /// Whether the collector answers: `connect` and `send` succeed.
        up: bool,
        /// Whether a connection is in place.
        connected: bool,
        /// While set, `send` waits inside the link, as a write to a peer that
        /// reads nothing waits inside the kernel.
        block: bool,
        /// Sends waiting inside the link right now.
        blocked_now: usize,
        /// Every packet the link delivered, in order.
        delivered: Vec<Vec<u8>>,
        /// Calls to `connect`.
        dials: usize,
        /// While set, `connect` waits inside the link, as a dial to a slow
        /// collector waits out its timeout.
        block_connect: bool,
        /// Dials waiting inside the link right now.
        connecting_now: usize,
        /// Results `connect` returns before it follows `up`.
        connect_plan: Vec<ExportFailure>,
        /// Results `send` returns before it follows `up`.
        send_plan: Vec<ExportFailure>,
    }

    /// The shared script: the test drives it, the link obeys it.
    #[derive(Clone, Default)]
    struct Script(Arc<(Mutex<ScriptState>, Condvar)>);

    impl Script {
        fn set(&self, f: impl FnOnce(&mut ScriptState)) {
            let (m, c) = &*self.0;
            f(&mut m.lock());
            c.notify_all();
        }

        fn get<T>(&self, f: impl FnOnce(&ScriptState) -> T) -> T {
            f(&self.0.0.lock())
        }

        /// Wait until `cond` holds, or fail the test naming `what`.
        fn wait(&self, what: &str, cond: impl Fn(&ScriptState) -> bool) {
            let (m, c) = &*self.0;
            let deadline = Instant::now() + MUST_HAPPEN;
            let mut s = m.lock();
            while !cond(&s) {
                assert!(Instant::now() < deadline, "never happened: {what}");
                c.wait_for(&mut s, Duration::from_millis(20));
            }
        }
    }

    /// A link that does what the script says.
    struct ScriptLink(Script);

    impl HepLink for ScriptLink {
        fn is_connected(&self) -> bool {
            self.0.get(|s| s.connected)
        }

        fn connect(&mut self) -> Result<(), SinkFailure> {
            let (m, c) = &*self.0.0;
            let mut s = m.lock();
            s.dials += 1;
            c.notify_all();
            if s.block_connect {
                s.connecting_now += 1;
                c.notify_all();
                while s.block_connect {
                    c.wait(&mut s);
                }
                s.connecting_now -= 1;
            }
            if !s.connect_plan.is_empty() {
                let kind = s.connect_plan.remove(0);
                return Err(SinkFailure::at(kind, std::io::Error::other("scripted")));
            }
            if s.up {
                s.connected = true;
                Ok(())
            } else {
                Err(SinkFailure::at(
                    ExportFailure::Connect,
                    std::io::ErrorKind::ConnectionRefused.into(),
                ))
            }
        }

        fn send(&mut self, pkt: &[u8]) -> Result<(), SinkFailure> {
            let (m, c) = &*self.0.0;
            let mut s = m.lock();
            if s.block {
                s.blocked_now += 1;
                c.notify_all();
                while s.block {
                    c.wait(&mut s);
                }
                s.blocked_now -= 1;
            }
            if !s.send_plan.is_empty() {
                let kind = s.send_plan.remove(0);
                s.connected = false;
                c.notify_all();
                return Err(SinkFailure::at(kind, std::io::Error::other("scripted")));
            }
            if s.up {
                s.delivered.push(pkt.to_vec());
                c.notify_all();
                Ok(())
            } else {
                s.connected = false;
                c.notify_all();
                Err(SinkFailure::at(
                    ExportFailure::Write,
                    std::io::ErrorKind::BrokenPipe.into(),
                ))
            }
        }
    }

    /// Releases every blocked send when a test ends, failed or not, so a red
    /// run leaves no thread parked inside the link.
    struct Unblock(Script);

    impl Drop for Unblock {
        fn drop(&mut self) {
            self.0.set(|s| {
                s.block = false;
                s.up = false;
            });
        }
    }

    /// A delivery over `script`, with a queue of `queue_bytes`, retries every
    /// millisecond or so, and its stop flag in `stop`.
    fn delivery(
        script: &Script,
        queue_bytes: usize,
        stop: &Arc<AtomicBool>,
    ) -> Result<(Arc<HepDelivery>, HepExportCounters), TestError> {
        let destination = OperatorDestination::from_cli_flag(HEP_SEND_FLAG, "192.0.2.10:9061");
        let permit = HepExportPermit::for_destination(&destination);
        let counters = HepExportCounters::new("tcp");
        let flag = Arc::clone(stop);
        let d = HepDelivery::start(
            &permit,
            Box::new(ScriptLink(script.clone())),
            counters.clone(),
            DeliveryOpts {
                queue_bytes,
                backoff_first: Duration::from_millis(1),
                backoff_cap: Duration::from_millis(5),
                stop_requested: Arc::new(move || flag.load(Ordering::SeqCst)),
                label: "192.0.2.10:9061".to_string(),
            },
        )
        .map_err(|e| format!("start the delivery thread: {e}"))?;
        Ok((Arc::new(d), counters))
    }

    /// Packet `i`: its number, padded to `len` bytes so byte bounds are exact.
    fn numbered(i: usize, len: usize) -> Vec<u8> {
        let mut p = format!("{i:08}").into_bytes();
        p.resize(len, b'.');
        p
    }

    /// The numbers of `packets`, in order.
    fn numbers(packets: &[Vec<u8>]) -> Result<Vec<usize>, TestError> {
        let mut out = Vec::with_capacity(packets.len());
        for p in packets {
            let digits = p.get(..8).ok_or("a numbered packet")?;
            out.push(std::str::from_utf8(digits)?.parse()?);
        }
        Ok(out)
    }

    /// Wait for `cond` over the counters, or fail naming `what`.
    fn wait_counters(
        counters: &HepExportCounters,
        what: &str,
        cond: impl Fn(&crate::capture::hep_export::HepExportSnapshot) -> bool,
    ) {
        let deadline = Instant::now() + MUST_HAPPEN;
        loop {
            let snap = counters.snapshot();
            if cond(&snap) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "never happened: {what}: {snap:?}"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// **The packet path never waits on the network.** The link is held
    /// blocked inside a write — exactly what a collector that accepts the
    /// connection and reads nothing does to a TCP sender once the socket
    /// buffers fill — and ten thousand packets are then offered.
    ///
    /// The bound asserted is not a speed. It is an ordering: every one of the
    /// ten thousand offers RETURNS while the link is provably still blocked
    /// (one send parked inside it, nothing delivered). A packet path that
    /// waited on the link even once could not finish while the link is held,
    /// whatever the machine's load, so no timing in this test can make it
    /// pass or fail spuriously; the deadline only turns that hang into a red
    /// result instead of a stuck run.
    #[test]
    fn the_packet_path_never_waits_on_a_link_that_is_blocked() -> Result<(), TestError> {
        const OFFERED: usize = 10_000;
        let script = Script::default();
        script.set(|s| {
            s.up = true;
            s.connected = true;
            s.block = true;
        });
        let stop = Arc::new(AtomicBool::new(false));
        let (d, counters) = delivery(&script, 64 << 20, &stop)?;
        // After `d`, so it drops FIRST: a halt waits out a parked write.
        let _unblock = Unblock(script.clone());

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let pusher = Arc::clone(&d);
        std::thread::spawn(move || {
            for i in 0..OFFERED {
                pusher.push(numbered(i, 32));
            }
            let _ = done_tx.send(());
        });

        script.wait("a send parked inside the link", |s| s.blocked_now == 1);
        assert!(
            done_rx.recv_timeout(MUST_HAPPEN).is_ok(),
            "the packet path waited on a blocked link: {OFFERED} offers did not \
             return while one write was parked in it"
        );
        assert_eq!(
            script.get(|s| (s.blocked_now, s.delivered.len())),
            (1, 0),
            "every offer returned while the link was still blocked"
        );
        assert_eq!(counters.snapshot().queued, OFFERED as u64);

        // Positive control: the same packets, all of them, in order, once the
        // link lets go -- so the offers above were really handed over.
        script.set(|s| s.block = false);
        script.wait("every packet delivered", |s| s.delivered.len() == OFFERED);
        assert_eq!(
            numbers(&script.get(|s| s.delivered.clone()))?,
            (0..OFFERED).collect::<Vec<_>>()
        );
        Ok(())
    }

    /// **A collector down for N packets gets every one of them, in order, once
    /// it is back**, and the replayed count is exactly N.
    #[test]
    fn a_collector_down_for_n_packets_gets_all_of_them_in_order_when_it_returns()
    -> Result<(), TestError> {
        const N: usize = 40;
        let script = Script::default();
        script.set(|s| {
            s.up = true;
            s.connected = true;
        });
        let stop = Arc::new(AtomicBool::new(false));
        let (d, counters) = delivery(&script, 64 << 20, &stop)?;
        // After `d`, so it drops FIRST: a halt waits out a parked write.
        let _unblock = Unblock(script.clone());

        d.push(numbered(0, 64));
        script.wait("the packet before the outage", |s| s.delivered.len() == 1);

        script.set(|s| s.up = false);
        for i in 1..=N {
            d.push(numbered(i, 64));
        }
        wait_counters(&counters, "a failed attempt during the outage", |s| {
            s.failed() > 0
        });
        script.set(|s| s.up = true);

        script.wait("every packet after the outage", |s| {
            s.delivered.len() == N + 1
        });
        wait_counters(&counters, "the queue emptied", |s| s.depth() == 0);
        assert_eq!(
            numbers(&script.get(|s| s.delivered.clone()))?,
            (0..=N).collect::<Vec<_>>(),
            "every SIP packet arrives, in order, none twice"
        );
        let snap = counters.snapshot();
        assert_eq!(snap.replayed, N as u64, "{snap:?}");
        assert_eq!(snap.sent, N as u64 + 1, "{snap:?}");
        assert_eq!(snap.dropped_total(), 0, "{snap:?}");
        assert_eq!(snap.reconnects, 1, "one outage, one recovery: {snap:?}");
        Ok(())
    }

    /// **A collector that is down when the sender starts is retried, not
    /// abandoned**: what was offered meanwhile arrives once it answers.
    #[test]
    fn a_collector_down_at_start_gets_the_feed_once_it_answers() -> Result<(), TestError> {
        const N: usize = 12;
        let script = Script::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (d, counters) = delivery(&script, 64 << 20, &stop)?;
        // After `d`, so it drops FIRST: a halt waits out a parked write.
        let _unblock = Unblock(script.clone());
        for i in 0..N {
            d.push(numbered(i, 64));
        }
        script.wait("the sender retrying", |s| s.dials >= 3);
        script.set(|s| s.up = true);
        script.wait("delivery resumed", |s| s.delivered.len() == N);
        assert_eq!(
            numbers(&script.get(|s| s.delivered.clone()))?,
            (0..N).collect::<Vec<_>>()
        );
        wait_counters(&counters, "every packet counted", |s| {
            s.replayed == N as u64
        });
        Ok(())
    }

    /// **A full queue drops the OLDEST packet and counts every drop.**
    ///
    /// Ten packets fit; twenty-five are offered while the collector is down.
    /// Exactly fifteen are dropped as `queue_full`, and the ten that arrive
    /// once it answers are the LAST ten -- the window that joins the live feed
    /// with no gap.
    #[test]
    fn a_full_queue_drops_the_oldest_and_counts_each_drop() -> Result<(), TestError> {
        const LEN: usize = 100;
        const FITS: usize = 10;
        const OFFERED: usize = 25;
        let script = Script::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (d, counters) = delivery(&script, FITS * LEN, &stop)?;
        // After `d`, so it drops FIRST: a halt waits out a parked write.
        let _unblock = Unblock(script.clone());
        for i in 0..OFFERED {
            d.push(numbered(i, LEN));
        }
        let snap = counters.snapshot();
        assert_eq!(snap.queued, OFFERED as u64, "{snap:?}");
        assert_eq!(
            snap.dropped[DropReason::QueueFull.index()],
            (OFFERED - FITS) as u64,
            "{snap:?}"
        );
        assert_eq!(snap.dropped_total(), (OFFERED - FITS) as u64, "{snap:?}");
        assert_eq!(snap.depth(), FITS as u64, "{snap:?}");

        script.set(|s| s.up = true);
        script.wait("the queue delivered", |s| s.delivered.len() == FITS);
        assert_eq!(
            numbers(&script.get(|s| s.delivered.clone()))?,
            (OFFERED - FITS..OFFERED).collect::<Vec<_>>(),
            "drop-oldest: the newest packets survive, in order"
        );
        wait_counters(&counters, "all replayed", |s| s.replayed == FITS as u64);
        Ok(())
    }

    /// **A stop discards the queue, counts what it discarded, and nothing is
    /// sent after it.** The collector comes back AFTER the stop; the worker
    /// must have exited without delivering a byte of what was queued.
    #[test]
    fn a_stop_discards_the_queue_and_nothing_is_sent_after_it() -> Result<(), TestError> {
        const N: usize = 12;
        let script = Script::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (d, counters) = delivery(&script, 64 << 20, &stop)?;
        // After `d`, so it drops FIRST: a halt waits out a parked write.
        let _unblock = Unblock(script.clone());
        for i in 0..N {
            d.push(numbered(i, 64));
        }
        script.wait("the worker trying to deliver", |s| s.dials >= 1);

        stop.store(true, Ordering::SeqCst);
        assert_eq!(d.stop(), N as u64, "the discard is the whole queue");
        script.set(|s| s.up = true);
        assert!(
            d.join_within(MUST_HAPPEN),
            "the delivery thread outlived the stop"
        );
        assert!(
            script.get(|s| s.delivered.is_empty()),
            "a packet was sent after the stop"
        );
        let snap = counters.snapshot();
        assert_eq!(snap.dropped[DropReason::Stopped.index()], N as u64);
        assert_eq!(snap.depth(), 0, "{snap:?}");

        // An offer after the stop is counted and discarded, never queued.
        d.push(numbered(99, 64));
        let snap = counters.snapshot();
        assert_eq!(snap.dropped[DropReason::Stopped.index()], N as u64 + 1);
        assert_eq!(snap.depth(), 0, "{snap:?}");
        Ok(())
    }

    /// **A stop signal mid-write lets that one write finish and starts no
    /// other.** The signal is the run's own flag, seen by the worker before
    /// the queue is discarded: between the signal and the discard nothing
    /// new goes out.
    #[test]
    fn a_signal_during_a_write_lets_it_finish_and_starts_no_other() -> Result<(), TestError> {
        let script = Script::default();
        script.set(|s| {
            s.up = true;
            s.connected = true;
            s.block = true;
        });
        let stop = Arc::new(AtomicBool::new(false));
        let (d, counters) = delivery(&script, 64 << 20, &stop)?;
        // After `d`, so it drops FIRST: a halt waits out a parked write.
        let _unblock = Unblock(script.clone());
        for i in 0..5 {
            d.push(numbered(i, 64));
        }
        script.wait("the first write parked", |s| s.blocked_now == 1);
        stop.store(true, Ordering::SeqCst);
        script.set(|s| s.block = false);
        assert!(
            d.join_within(MUST_HAPPEN),
            "the worker kept going after the signal"
        );
        assert_eq!(
            numbers(&script.get(|s| s.delivered.clone()))?,
            vec![0],
            "only the write already under way completes"
        );
        assert_eq!(d.stop(), 4);
        let snap = counters.snapshot();
        assert_eq!((snap.sent, snap.depth()), (1, 0), "{snap:?}");
        Ok(())
    }

    /// **A stop signal during a dial sends nothing once the dial succeeds.**
    /// A dial can take a whole timeout; the signal lands while it is under
    /// way, and the collector then answers. The thread has a connection and
    /// a full queue, and must still write nothing: the stop is checked again
    /// right before the write, not only before the dial.
    #[test]
    fn a_signal_during_a_dial_sends_nothing_once_it_connects() -> Result<(), TestError> {
        let script = Script::default();
        script.set(|s| {
            s.up = true;
            s.block_connect = true;
        });
        let stop = Arc::new(AtomicBool::new(false));
        let (d, counters) = delivery(&script, 64 << 20, &stop)?;
        // After `d`, so it drops FIRST: a halt waits out a parked write.
        let _unblock = Unblock(script.clone());
        for i in 0..3 {
            d.push(numbered(i, 64));
        }
        script.wait("the dial parked", |s| s.connecting_now == 1);
        stop.store(true, Ordering::SeqCst);
        script.set(|s| s.block_connect = false);
        assert!(
            d.join_within(MUST_HAPPEN),
            "the worker kept going after the signal"
        );
        assert!(
            script.get(|s| s.delivered.is_empty()),
            "a packet went out after the signal: {:?}",
            numbers(&script.get(|s| s.delivered.clone()))?
        );
        assert!(script.get(|s| s.connected), "control: the dial succeeded");
        assert_eq!(d.stop(), 3);
        assert_eq!(counters.snapshot().depth(), 0);
        Ok(())
    }

    /// **The end of the input delivers what is queued** -- it is not a stop --
    /// once the collector answers within the grace period.
    #[test]
    fn the_end_of_the_input_delivers_what_is_queued() -> Result<(), TestError> {
        let script = Script::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (d, counters) = delivery(&script, 64 << 20, &stop)?;
        // After `d`, so it drops FIRST: a halt waits out a parked write.
        let _unblock = Unblock(script.clone());
        for i in 0..6 {
            d.push(numbered(i, 64));
        }
        let up_later = script.clone();
        std::thread::spawn(move || {
            up_later.wait("a retry before the collector answers", |s| s.dials >= 2);
            up_later.set(|s| s.up = true);
        });
        assert_eq!(d.finish(MUST_HAPPEN), 0, "nothing left undelivered");
        assert_eq!(
            numbers(&script.get(|s| s.delivered.clone()))?,
            (0..6).collect::<Vec<_>>()
        );
        assert_eq!(counters.snapshot().dropped_total(), 0);
        Ok(())
    }

    /// **The end of the input gives up on a collector that never answers**,
    /// and counts what it gave up as `unsent_at_exit` -- not as a stop.
    #[test]
    fn the_end_of_the_input_gives_up_on_a_collector_that_never_answers() -> Result<(), TestError> {
        let script = Script::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (d, counters) = delivery(&script, 64 << 20, &stop)?;
        // After `d`, so it drops FIRST: a halt waits out a parked write.
        let _unblock = Unblock(script.clone());
        for i in 0..7 {
            d.push(numbered(i, 64));
        }
        assert_eq!(d.finish(Duration::from_millis(200)), 7);
        let snap = counters.snapshot();
        assert_eq!(snap.dropped[DropReason::UnsentAtExit.index()], 7);
        assert_eq!(snap.dropped[DropReason::Stopped.index()], 0);
        assert!(d.join_within(MUST_HAPPEN), "the worker outlived the finish");
        Ok(())
    }

    /// **Every failed attempt is counted under the step that failed**, and a
    /// failure loses nothing: the packet is tried again. Distinct numbers per
    /// kind, so one counted under a neighbor's name shows as a wrong number.
    #[test]
    fn every_failed_attempt_is_counted_under_its_own_kind_and_loses_nothing()
    -> Result<(), TestError> {
        let script = Script::default();
        script.set(|s| {
            s.up = true;
            s.connect_plan = vec![
                ExportFailure::Connect,
                ExportFailure::TlsHandshake,
                ExportFailure::TlsHandshake,
            ];
            s.send_plan = vec![
                ExportFailure::Write,
                ExportFailure::Write,
                ExportFailure::Write,
            ];
        });
        let stop = Arc::new(AtomicBool::new(false));
        let (d, counters) = delivery(&script, 64 << 20, &stop)?;
        // After `d`, so it drops FIRST: a halt waits out a parked write.
        let _unblock = Unblock(script.clone());
        d.push(numbered(0, 64));
        d.push(numbered(1, 64));
        script.wait("both delivered", |s| s.delivered.len() == 2);
        wait_counters(&counters, "settled", |s| s.depth() == 0);
        let snap = counters.snapshot();
        assert_eq!(snap.failures[ExportFailure::Connect.index()], 1, "{snap:?}");
        assert_eq!(
            snap.failures[ExportFailure::TlsHandshake.index()],
            2,
            "{snap:?}"
        );
        assert_eq!(snap.failures[ExportFailure::Write.index()], 3, "{snap:?}");
        assert_eq!(snap.sent, 2, "{snap:?}");
        assert_eq!(snap.dropped_total(), 0, "{snap:?}");
        assert_eq!(
            numbers(&script.get(|s| s.delivered.clone()))?,
            vec![0, 1],
            "in order, none twice"
        );
        Ok(())
    }

    /// The retry delay doubles from the first delay and stops at the cap.
    #[test]
    fn the_retry_delay_doubles_up_to_its_cap() -> Result<(), TestError> {
        let first = Duration::from_millis(100);
        let cap = Duration::from_secs(5);
        let delays: Vec<u128> = (1..=10)
            .map(|n| backoff_delay(first, cap, n).as_millis())
            .collect();
        assert_eq!(
            delays,
            vec![100, 200, 400, 800, 1600, 3200, 5000, 5000, 5000, 5000]
        );
        assert_eq!(backoff_delay(first, cap, u32::MAX), cap, "no overflow");
        assert_eq!(backoff_delay(first, cap, 0), Duration::ZERO);
        Ok(())
    }
}
