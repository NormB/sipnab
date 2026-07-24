// SPDX-License-Identifier: MIT OR Apache-2.0

//! Auto-grow, capped packet channel for the capture → processing pipeline.
//!
//! Replaces a fixed `crossbeam_channel::bounded(N)` (which preallocates its ring
//! and so never shrinks when idle) with a **count-capped semaphore over an
//! unbounded channel**:
//!
//! - storage is [`crossbeam_channel::unbounded`] — its segment list grows under
//!   load and frees segments as they drain, so idle memory returns to ~0;
//! - a `bounded::<()>(capacity)` permit pool caps how many packets may be
//!   in flight at once, providing the same blocking backpressure as a bounded
//!   channel.
//!
//! Crossbeam owns all the blocking, so we inherit correct sender wakeups, prompt
//! disconnect detection (a dropped [`PacketRx`] makes parked [`PacketTx::send`]
//! return `Err`, mirroring the old `tx.send(..).is_err()` capture-loop break),
//! and reasonable fairness — without a hand-rolled `Condvar`. A *count* cap makes
//! every packet cost exactly one permit, so packet size never matters and there
//! is no oversized-packet deadlock.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TrySendError, bounded, unbounded};

use super::packet::Packet;

/// Minimum wait before a fall-back blocking send counts as a genuine
/// backpressure block in [`CaptureMeter::backpressure_blocks`].
///
/// A failed `try_send` often races a receiver that frees the slot within the
/// same instant; the follow-up blocking send then completes in microseconds
/// (an uncontended crossbeam handoff is sub-microsecond). Counting those
/// races would overstate blocking by orders of magnitude. 1 ms is ~1000× the
/// instant-recovery timescale yet far below the capture loop's own 100 ms
/// idle-poll granularity: a sender that waited this long was genuinely
/// parked behind a saturated pipeline.
const GENUINE_BLOCK_THRESHOLD: Duration = Duration::from_millis(1);

/// Lock-free, cheaply-clonable view of the channel's load, for metrics. Read it
/// off the hot path (e.g. from the metrics thread); never gated on a lock.
#[derive(Clone)]
pub struct CaptureMeter {
    /// Packets sent but not yet received (shared across all handles).
    in_flight: Arc<AtomicUsize>,
    /// Cumulative count of sends that genuinely blocked at the capacity cap
    /// (waited ≥ [`GENUINE_BLOCK_THRESHOLD`]).
    backpressure_blocks: Arc<AtomicU64>,
    /// Cumulative count of sends that found the channel at capacity
    /// (`try_send` failed), including instant recoveries.
    capacity_hits: Arc<AtomicU64>,
}

impl CaptureMeter {
    /// Create a meter with both counters at zero. Returns the meter; the
    /// clones handed to `PacketTx`/`PacketRx` share the same atomics.
    fn new() -> Self {
        Self {
            in_flight: Arc::new(AtomicUsize::new(0)),
            backpressure_blocks: Arc::new(AtomicU64::new(0)),
            capacity_hits: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Packets currently buffered (sent but not yet received).
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Total times a send genuinely blocked because the cap was reached —
    /// i.e. it waited at least the genuine-block threshold (1 ms;
    /// `GENUINE_BLOCK_THRESHOLD`) for a slot. A
    /// failed `try_send` whose fall-back send completed instantly (the
    /// receiver freed a slot within the same moment) is *not* counted here;
    /// see [`capacity_hits`](Self::capacity_hits) for that raw contention
    /// signal.
    pub fn backpressure_blocks(&self) -> u64 {
        self.backpressure_blocks.load(Ordering::Relaxed)
    }

    /// Total times a send found the channel at capacity (`try_send` failed),
    /// whether or not the fall-back blocking send then had to wait
    /// meaningfully. Always ≥ [`backpressure_blocks`](Self::backpressure_blocks).
    pub fn capacity_hits(&self) -> u64 {
        self.capacity_hits.load(Ordering::Relaxed)
    }
}

/// Error returned by [`PacketTx::send`] when the receiver is gone. Zero-sized
/// (we don't hand the packet back — the channel is dead, so it would be
/// dropped anyway), which keeps `send`'s `Result` small.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed;

/// Sending half. `Clone` (each capture device/thread gets its own handle); all
/// clones share one permit pool and meter.
#[derive(Clone)]
pub struct PacketTx {
    /// Unbounded storage channel the packets actually travel through.
    data_tx: Sender<Packet>,
    /// "In-flight slots": a `bounded(capacity)` channel used as a semaphore.
    /// `send` fills a slot (blocks when full = at cap); `recv` frees one.
    slot_tx: Sender<()>,
    /// Shared load counters updated on every send.
    meter: CaptureMeter,
}

/// Receiving half (single consumer in both TUI and batch modes).
pub struct PacketRx {
    /// Unbounded storage channel the packets actually travel through.
    data_rx: Receiver<Packet>,
    /// Receiving side of the permit pool; one token is drained per packet
    /// received, freeing a slot for a blocked sender.
    slot_rx: Receiver<()>,
    /// Shared load counters updated on every receive.
    meter: CaptureMeter,
}

/// Create a capped, auto-shrinking packet channel holding at most `capacity`
/// in-flight packets. Construction is O(1) (no permit pre-fill).
///
/// # Arguments
///
/// * `capacity` — maximum packets in flight at once; `0` is clamped to `1`.
///
/// # Returns
///
/// The `(PacketTx, PacketRx)` pair sharing one permit pool and one meter.
pub fn packet_channel(capacity: usize) -> (PacketTx, PacketRx) {
    let capacity = capacity.max(1);
    let (data_tx, data_rx) = unbounded::<Packet>();
    // Starts empty; becomes full when `capacity` packets are in flight.
    let (slot_tx, slot_rx) = bounded::<()>(capacity);
    let meter = CaptureMeter::new();
    (
        PacketTx {
            data_tx,
            slot_tx,
            meter: meter.clone(),
        },
        PacketRx {
            data_rx,
            slot_rx,
            meter,
        },
    )
}

impl PacketTx {
    /// Enqueue a packet, blocking while the cap is reached (backpressure).
    /// Returns `Err(Closed)` if the receiver has been dropped, so callers can
    /// break their capture loop exactly as with the old `crossbeam` sender
    /// (`tx.send(..).is_err()`).
    ///
    /// # Side effects
    ///
    /// May block the calling thread until a permit frees up. Increments the
    /// shared meter's `capacity_hits` counter whenever the cap is found full,
    /// its `backpressure_blocks` counter only when the fall-back send then
    /// waited ≥ the 1 ms `GENUINE_BLOCK_THRESHOLD` (a failed `try_send` instantly
    /// rescued by a concurrent receive is a hit, not a block), and its
    /// `in_flight` counter once a slot is claimed (decremented again if
    /// the receiver disappears before the packet is enqueued).
    pub fn send(&self, packet: Packet) -> Result<(), Closed> {
        // Claim an in-flight slot (one per packet). Fast path is a non-blocking
        // try_send; only when the cap is reached do we count a capacity hit,
        // wait, and time the wait to decide whether it was a genuine block.
        // A dropped receiver drops `slot_rx`, so the wait/try ends in
        // `Disconnected` and we surface `Err` (capture loop breaks).
        match self.slot_tx.try_send(()) {
            Ok(()) => {}
            Err(TrySendError::Full(())) => {
                self.meter.capacity_hits.fetch_add(1, Ordering::Relaxed);
                let wait_start = std::time::Instant::now();
                if self.slot_tx.send(()).is_err() {
                    return Err(Closed);
                }
                if wait_start.elapsed() >= GENUINE_BLOCK_THRESHOLD {
                    self.meter
                        .backpressure_blocks
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(TrySendError::Disconnected(())) => return Err(Closed),
        }
        self.meter.in_flight.fetch_add(1, Ordering::Relaxed);
        match self.data_tx.send(packet) {
            Ok(()) => Ok(()),
            Err(crossbeam_channel::SendError(_)) => {
                // Receiver gone between claiming the slot and enqueueing.
                self.meter.in_flight.fetch_sub(1, Ordering::Relaxed);
                Err(Closed)
            }
        }
    }

    /// A metrics handle for this channel (cheap clone of the shared meter).
    pub fn meter(&self) -> CaptureMeter {
        self.meter.clone()
    }
}

impl PacketRx {
    /// Receive a packet, returning its permit to the pool so a blocked sender
    /// can proceed.
    ///
    /// # Arguments
    ///
    /// * `timeout` — how long to block waiting for a packet.
    ///
    /// # Errors
    ///
    /// `RecvTimeoutError::Timeout` when no packet arrives within `timeout`;
    /// `RecvTimeoutError::Disconnected` when all senders are gone and the
    /// channel is drained.
    ///
    /// # Side effects
    ///
    /// Blocks up to `timeout`. On success, decrements the meter's `in_flight`
    /// counter and drains one permit token so a blocked sender can proceed.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Packet, RecvTimeoutError> {
        let pkt = self.data_rx.recv_timeout(timeout)?;
        self.meter.in_flight.fetch_sub(1, Ordering::Relaxed);
        // Free the slot this packet occupied so a blocked sender can proceed.
        // There is exactly one slot token per in-flight packet, so this never
        // blocks; ignore the error that arises only if all senders are gone.
        let _ = self.slot_rx.try_recv();
        Ok(pkt)
    }

    /// Drain all immediately-available packets, returning each one's permit.
    ///
    /// # Returns
    ///
    /// A non-blocking iterator that ends as soon as the channel is empty.
    ///
    /// # Side effects
    ///
    /// For each packet actually yielded, decrements the meter's `in_flight`
    /// counter and drains one permit token (effects happen lazily as the
    /// iterator is advanced, not when `try_iter` is called).
    pub fn try_iter(&self) -> impl Iterator<Item = Packet> + '_ {
        self.data_rx.try_iter().inspect(move |_pkt| {
            self.meter.in_flight.fetch_sub(1, Ordering::Relaxed);
            let _ = self.slot_rx.try_recv();
        })
    }

    /// A metrics handle for this channel (cheap clone of the shared meter).
    pub fn meter(&self) -> CaptureMeter {
        self.meter.clone()
    }

    /// `true` when no packet is immediately available. The batch loop uses
    /// this to flush its buffered output sink exactly when the pipeline goes
    /// idle (lock-free peek at the underlying channel).
    pub fn is_empty(&self) -> bool {
        self.data_rx.is_empty()
    }
}

/// Tests for the capped packet channel: backpressure blocking, permit
/// return, disconnect semantics, and meter accuracy.
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Build a test packet with a `size`-byte zeroed payload (epoch
    /// timestamp, Ethernet link type). Returns the `Packet`.
    fn pkt(size: usize) -> Packet {
        let ts = chrono::DateTime::from_timestamp(0, 0).unwrap();
        Packet::new(ts, vec![0u8; size], size, size, None, 1)
    }

    /// A send beyond `capacity` blocks and only completes after a receive
    /// returns a permit; the backpressure counter records the completed
    /// block (a stall is counted once its duration is known — while the
    /// sender is still parked, `capacity_hits` is the live signal).
    #[test]
    fn capacity_blocks_until_a_credit_is_returned() {
        let (tx, rx) = packet_channel(2);
        tx.send(pkt(64)).unwrap();
        tx.send(pkt(64)).unwrap();
        assert_eq!(tx.meter().in_flight(), 2);

        // Third send must block (cap reached).
        let tx2 = tx.clone();
        let h = std::thread::spawn(move || tx2.send(pkt(64)));
        std::thread::sleep(Duration::from_millis(100));
        assert!(!h.is_finished(), "send should block at capacity");
        assert!(tx.meter().capacity_hits() >= 1, "cap hit is visible live");

        // Receiving one packet returns a credit and unblocks the sender.
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            h.join().unwrap().is_ok(),
            "send should unblock after a recv"
        );
        assert_eq!(tx.meter().in_flight(), 2);
        // The ~100ms stall is recorded once the send completed.
        assert!(tx.meter().backpressure_blocks() >= 1);
    }

    /// Receiving every queued packet restores the full permit pool so a
    /// fresh full batch of sends succeeds without blocking.
    #[test]
    fn drain_restores_the_full_pool() {
        let (tx, rx) = packet_channel(3);
        for _ in 0..3 {
            tx.send(pkt(16)).unwrap();
        }
        for _ in 0..3 {
            rx.recv_timeout(Duration::from_secs(1)).unwrap();
        }
        assert_eq!(tx.meter().in_flight(), 0);
        // Pool fully restored: 3 more sends succeed without blocking.
        for _ in 0..3 {
            tx.send(pkt(16)).unwrap();
        }
        assert_eq!(tx.meter().in_flight(), 3);
    }

    /// Dropping the receiver wakes a sender parked at the cap with `Err`,
    /// and subsequent sends also fail.
    #[test]
    fn dropping_receiver_makes_a_parked_send_return_err() {
        let (tx, rx) = packet_channel(1);
        tx.send(pkt(16)).unwrap(); // pool now empty
        let tx2 = tx.clone();
        let h = std::thread::spawn(move || tx2.send(pkt(16)));
        std::thread::sleep(Duration::from_millis(100));
        assert!(!h.is_finished(), "second send blocks at cap=1");
        drop(rx); // receiver gone → parked sender must wake with Err
        assert!(
            h.join().unwrap().is_err(),
            "parked send must return Err when the receiver drops"
        );
        // A fresh send also errors now.
        assert!(tx.send(pkt(16)).is_err());
    }

    /// With every sender dropped, `recv_timeout` reports `Disconnected`
    /// rather than timing out.
    #[test]
    fn dropping_all_senders_disconnects_receiver() {
        let (tx, rx) = packet_channel(4);
        drop(tx);
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Disconnected)
        ));
    }

    /// Cloned senders draw from one shared permit pool: total in-flight is
    /// capped across all clones, not per handle.
    #[test]
    fn cloned_senders_share_one_cap() {
        let (tx, rx) = packet_channel(3);
        let tx2 = tx.clone();
        tx.send(pkt(8)).unwrap();
        tx2.send(pkt(8)).unwrap();
        tx.send(pkt(8)).unwrap(); // 3 in flight across both handles
        let tx3 = tx2.clone();
        let h = std::thread::spawn(move || tx3.send(pkt(8)));
        std::thread::sleep(Duration::from_millis(100));
        assert!(!h.is_finished(), "total in-flight is capped across clones");
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(h.join().unwrap().is_ok());
    }

    /// `try_iter` yields every queued packet and returns each one's permit,
    /// leaving the pool full again.
    #[test]
    fn try_iter_drains_and_returns_credits() {
        let (tx, rx) = packet_channel(5);
        for _ in 0..5 {
            tx.send(pkt(8)).unwrap();
        }
        let drained: Vec<_> = rx.try_iter().collect();
        assert_eq!(drained.len(), 5);
        assert_eq!(tx.meter().in_flight(), 0);
        // Credits returned → can send a full batch again.
        for _ in 0..5 {
            tx.send(pkt(8)).unwrap();
        }
    }

    /// The cap counts packets, not bytes: a 64 KiB payload still costs
    /// exactly one permit.
    #[test]
    fn oversized_payload_costs_one_credit() {
        // A large packet still takes exactly one permit (count cap, not bytes).
        let (tx, rx) = packet_channel(1);
        tx.send(pkt(65535)).unwrap();
        let tx2 = tx.clone();
        let h = std::thread::spawn(move || tx2.send(pkt(65535)));
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !h.is_finished(),
            "cap=1 blocks the second packet regardless of size"
        );
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(h.join().unwrap().is_ok());
    }

    /// `is_empty` reflects pending packets: true when fresh, false after a
    /// send, true again after draining or disconnect.
    #[test]
    fn is_empty_tracks_pending_packets() {
        let (tx, rx) = packet_channel(2);
        assert!(rx.is_empty(), "fresh channel starts empty");
        tx.send(pkt(8)).unwrap();
        assert!(!rx.is_empty(), "a sent packet must be visible");
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(rx.is_empty(), "drained channel is empty again");
        drop(tx);
        assert!(rx.is_empty(), "disconnected channel reads as empty");
    }

    /// A failed `try_send` whose fall-back blocking send completes almost
    /// immediately (the receiver freed a slot within the same instant) is a
    /// capacity hit, not a genuine block. With cap=1 and an eagerly-draining
    /// receiver the sender trips the cap constantly but essentially never
    /// waits, so `backpressure_blocks` must stay (near) zero — one count per
    /// cap hit would overstate blocking by orders of magnitude.
    #[test]
    fn instant_recovery_cap_hit_is_not_a_genuine_block() {
        const N: u64 = 10_000;
        let (tx, rx) = packet_channel(1);
        let consumer = std::thread::spawn(move || {
            for _ in 0..N {
                rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
        });
        for _ in 0..N {
            tx.send(pkt(8)).unwrap();
        }
        consumer.join().unwrap();
        let blocks = tx.meter().backpressure_blocks();
        let hits = tx.meter().capacity_hits();
        assert!(
            blocks < 100,
            "instant recoveries must not count as genuine blocks, got {blocks}"
        );
        assert!(hits > 0, "a cap-1 ping-pong must hit the cap");
        assert!(
            blocks * 2 < hits,
            "genuine blocks ({blocks}) must be far rarer than raw capacity hits ({hits})"
        );
    }

    /// A send that stalls for tens of milliseconds behind a slow receiver is
    /// a genuine backpressure block and must be counted (as must the raw
    /// capacity hit).
    #[test]
    fn sustained_stall_is_counted_as_genuine_block() {
        let (tx, rx) = packet_channel(1);
        tx.send(pkt(8)).unwrap(); // cap reached, no cap hit yet
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            rx.recv_timeout(Duration::from_secs(5)).unwrap();
            rx // keep the receiver alive until the parked send completes
        });
        tx.send(pkt(8)).unwrap(); // waits ~50ms for the freed slot
        let _rx = h.join().unwrap();
        assert_eq!(
            tx.meter().backpressure_blocks(),
            1,
            "a ~50ms stall is a genuine block"
        );
        assert_eq!(
            tx.meter().capacity_hits(),
            1,
            "the stall also counts as a capacity hit"
        );
    }

    /// `packet_channel(0)` clamps the cap to 1 so one send still succeeds.
    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let (tx, rx) = packet_channel(0);
        tx.send(pkt(8)).unwrap(); // cap clamped to >=1, so one send succeeds
        assert_eq!(tx.meter().in_flight(), 1);
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }
}
