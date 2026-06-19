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

/// Lock-free, cheaply-clonable view of the channel's load, for metrics. Read it
/// off the hot path (e.g. from the metrics thread); never gated on a lock.
#[derive(Clone)]
pub struct CaptureMeter {
    in_flight: Arc<AtomicUsize>,
    backpressure_blocks: Arc<AtomicU64>,
}

impl CaptureMeter {
    fn new() -> Self {
        Self {
            in_flight: Arc::new(AtomicUsize::new(0)),
            backpressure_blocks: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Packets currently buffered (sent but not yet received).
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Total times a send had to block because the cap was reached.
    pub fn backpressure_blocks(&self) -> u64 {
        self.backpressure_blocks.load(Ordering::Relaxed)
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
    data_tx: Sender<Packet>,
    /// "In-flight slots": a `bounded(capacity)` channel used as a semaphore.
    /// `send` fills a slot (blocks when full = at cap); `recv` frees one.
    slot_tx: Sender<()>,
    meter: CaptureMeter,
}

/// Receiving half (single consumer in both TUI and batch modes).
pub struct PacketRx {
    data_rx: Receiver<Packet>,
    slot_rx: Receiver<()>,
    meter: CaptureMeter,
}

/// Create a capped, auto-shrinking packet channel holding at most `capacity`
/// in-flight packets. Construction is O(1) (no permit pre-fill).
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
    pub fn send(&self, packet: Packet) -> Result<(), Closed> {
        // Claim an in-flight slot (one per packet). Fast path is a non-blocking
        // try_send; only when the cap is reached do we count a backpressure
        // block and wait. A dropped receiver drops `slot_rx`, so the wait/try
        // ends in `Disconnected` and we surface `Err` (capture loop breaks).
        match self.slot_tx.try_send(()) {
            Ok(()) => {}
            Err(TrySendError::Full(())) => {
                self.meter
                    .backpressure_blocks
                    .fetch_add(1, Ordering::Relaxed);
                if self.slot_tx.send(()).is_err() {
                    return Err(Closed);
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

    /// A metrics handle for this channel.
    pub fn meter(&self) -> CaptureMeter {
        self.meter.clone()
    }
}

impl PacketRx {
    /// Receive a packet, returning its permit to the pool so a blocked sender
    /// can proceed.
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
    pub fn try_iter(&self) -> impl Iterator<Item = Packet> + '_ {
        self.data_rx.try_iter().inspect(move |_pkt| {
            self.meter.in_flight.fetch_sub(1, Ordering::Relaxed);
            let _ = self.slot_rx.try_recv();
        })
    }

    /// A metrics handle for this channel.
    pub fn meter(&self) -> CaptureMeter {
        self.meter.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pkt(size: usize) -> Packet {
        let ts = chrono::DateTime::from_timestamp(0, 0).unwrap();
        Packet::new(ts, vec![0u8; size], size, size, None, 1)
    }

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
        assert!(tx.meter().backpressure_blocks() >= 1);

        // Receiving one packet returns a credit and unblocks the sender.
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            h.join().unwrap().is_ok(),
            "send should unblock after a recv"
        );
        assert_eq!(tx.meter().in_flight(), 2);
    }

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

    #[test]
    fn dropping_all_senders_disconnects_receiver() {
        let (tx, rx) = packet_channel(4);
        drop(tx);
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Disconnected)
        ));
    }

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

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let (tx, rx) = packet_channel(0);
        tx.send(pkt(8)).unwrap(); // cap clamped to >=1, so one send succeeds
        assert_eq!(tx.meter().in_flight(), 1);
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }
}
