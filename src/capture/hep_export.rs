// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a `--hep-send` exporter knows about its own deliveries.
//!
//! # Why this exists
//!
//! A failed forward used to be one `debug!` line and nothing else, so an agent
//! whose collector was unreachable, or whose certificate it no longer
//! accepted, kept capturing and reported nothing wrong at the default log
//! level. The collector side can now say who stopped sending; this is the same
//! question answered from the other end.
//!
//! # What "sent" means depends on the transport
//!
//! Over TCP and TLS a packet counts as sent once it is written to the
//! connection, and a write that fails is counted. Over UDP a packet counts once
//! the kernel takes it: a collector that is down produces no error at all, so
//! a UDP exporter can report sends and never delivery, and the snapshot says
//! so rather than letting a climbing counter read as proof.
//!
//! # Every packet ends in exactly one place
//!
//! The sender runs off the capture thread, so every packet the capture offers
//! is `queued`, and from there it is either `sent`, `dropped` for a named
//! reason, or still waiting. `queued = sent + dropped + depth` always holds,
//! and [`HepExportSnapshot::depth`] is computed from that identity rather than
//! kept as a fourth counter that could drift from the other three. A
//! `failure` is one failed delivery ATTEMPT, not a lost packet: the packet
//! stays queued and is tried again, so the loss count is `dropped`, never
//! `failed`.
//!
//! # Why it is not behind the `hep` feature
//!
//! The sender writes these counters, and the runtime collector, the metrics
//! exposition and the end-of-run line read them. The readers are not all
//! behind `hep`, for the reason `capture::hep_roster` gives.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Why one export failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExportFailure {
    /// The connection to the collector could not be made (refused,
    /// unreachable, timed out).
    Connect,
    /// A connection was made and the TLS handshake failed: the collector's
    /// certificate is not one this sender accepts, or the session broke.
    TlsHandshake,
    /// The packet could not be written to an established connection or
    /// handed to the socket.
    Write,
}

impl ExportFailure {
    /// Every kind, in declaration order; [`Self::index`] is each one's slot.
    pub const ALL: [Self; 3] = [Self::Connect, Self::TlsHandshake, Self::Write];

    /// How many kinds there are, for arrays indexed by [`Self::index`].
    pub const COUNT: usize = Self::ALL.len();

    /// This kind's slot in [`Self::ALL`]; exhaustive, so a new kind fails to
    /// compile here until it is given one.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Connect => 0,
            Self::TlsHandshake => 1,
            Self::Write => 2,
        }
    }

    /// The machine name every surface reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::TlsHandshake => "tls_handshake",
            Self::Write => "write",
        }
    }
}

/// Why a queued packet was discarded without being delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DropReason {
    /// The queue was at its bound while the collector was unreachable, and
    /// this was the OLDEST packet in it. The queue keeps the most recent
    /// window, so what it replays joins the live feed with no gap.
    QueueFull,
    /// The run was stopped (SIGINT/SIGTERM) with this packet still queued.
    /// Nothing is flushed at a stop: that is a security rule, not a gap.
    Stopped,
    /// The input ended and the collector stayed unreachable for the whole
    /// grace period the sender allows at the end of a run.
    UnsentAtExit,
}

impl DropReason {
    /// Every reason, in declaration order; [`Self::index`] is each one's slot.
    pub const ALL: [Self; 3] = [Self::QueueFull, Self::Stopped, Self::UnsentAtExit];

    /// How many reasons there are, for arrays indexed by [`Self::index`].
    pub const COUNT: usize = Self::ALL.len();

    /// This reason's slot in [`Self::ALL`]; exhaustive, so a new reason fails
    /// to compile here until it is given one.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::QueueFull => 0,
            Self::Stopped => 1,
            Self::UnsentAtExit => 2,
        }
    }

    /// The machine name every surface reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
            Self::Stopped => "stopped",
            Self::UnsentAtExit => "unsent_at_exit",
        }
    }
}

/// The shared counters one `--hep-send` exporter keeps. Cheap to clone: every
/// clone counts into the same atomics.
#[derive(Debug, Clone)]
pub struct HepExportCounters {
    /// The counts, shared by every clone.
    inner: Arc<Inner>,
}

/// The atomics behind [`HepExportCounters`].
#[derive(Debug)]
struct Inner {
    /// The transport the exporter speaks: `udp`, `tcp` or `tls`.
    transport: &'static str,
    /// Packets delivered as far as the transport can tell.
    sent: AtomicU64,
    /// Failures by kind, indexed by [`ExportFailure::index`].
    failures: [AtomicU64; ExportFailure::COUNT],
    /// Times the collector became reachable again after an outage.
    reconnects: AtomicU64,
    /// Packets the capture handed to the sender's queue.
    queued: AtomicU64,
    /// Packets delivered after waiting out an outage in the queue.
    replayed: AtomicU64,
    /// Packets discarded undelivered, by reason, indexed by
    /// [`DropReason::index`].
    dropped: [AtomicU64; DropReason::COUNT],
}

/// A point-in-time copy of an exporter's counters, for the surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HepExportSnapshot {
    /// The transport the exporter speaks.
    pub transport: &'static str,
    /// Packets delivered as far as the transport can tell.
    pub sent: u64,
    /// Failures by kind, indexed by [`ExportFailure::index`].
    pub failures: [u64; ExportFailure::COUNT],
    /// Times the collector became reachable again after an outage.
    pub reconnects: u64,
    /// Packets the capture handed to the sender's queue.
    pub queued: u64,
    /// Packets delivered after waiting out an outage in the queue.
    pub replayed: u64,
    /// Packets discarded undelivered, by reason, indexed by
    /// [`DropReason::index`].
    pub dropped: [u64; DropReason::COUNT],
}

impl HepExportCounters {
    /// Counters for an exporter speaking `transport` (`udp`, `tcp`, `tls`).
    #[must_use]
    pub fn new(transport: &'static str) -> Self {
        Self {
            inner: Arc::new(Inner {
                transport,
                sent: AtomicU64::new(0),
                failures: [const { AtomicU64::new(0) }; ExportFailure::COUNT],
                reconnects: AtomicU64::new(0),
                queued: AtomicU64::new(0),
                replayed: AtomicU64::new(0),
                dropped: [const { AtomicU64::new(0) }; DropReason::COUNT],
            }),
        }
    }

    /// One packet delivered as far as the transport can tell.
    pub fn record_sent(&self) {
        self.inner.sent.fetch_add(1, Ordering::Relaxed);
    }

    /// One export failed for `kind`.
    pub fn record_failure(&self, kind: ExportFailure) {
        self.inner.failures[kind.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// The collector answered again after an outage.
    pub fn record_reconnect(&self) {
        self.inner.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    /// One packet handed to the sender's queue.
    pub fn record_queued(&self) {
        self.inner.queued.fetch_add(1, Ordering::Relaxed);
    }

    /// One packet delivered after waiting out an outage.
    pub fn record_replayed(&self) {
        self.inner.replayed.fetch_add(1, Ordering::Relaxed);
    }

    /// `n` packets discarded undelivered for `reason`.
    pub fn record_dropped(&self, reason: DropReason, n: u64) {
        self.inner.dropped[reason.index()].fetch_add(n, Ordering::Relaxed);
    }

    /// Packets dropped for `reason` so far.
    #[must_use]
    pub fn dropped(&self, reason: DropReason) -> u64 {
        self.inner.dropped[reason.index()].load(Ordering::Relaxed)
    }

    /// Failures of `kind` so far.
    #[must_use]
    pub fn failures(&self, kind: ExportFailure) -> u64 {
        self.inner.failures[kind.index()].load(Ordering::Relaxed)
    }

    /// The counters, now.
    #[must_use]
    pub fn snapshot(&self) -> HepExportSnapshot {
        let mut failures = [0u64; ExportFailure::COUNT];
        for kind in ExportFailure::ALL {
            failures[kind.index()] = self.failures(kind);
        }
        let mut dropped = [0u64; DropReason::COUNT];
        for reason in DropReason::ALL {
            dropped[reason.index()] = self.dropped(reason);
        }
        let sent = self.inner.sent.load(Ordering::Relaxed);
        let replayed = self.inner.replayed.load(Ordering::Relaxed);
        let reconnects = self.inner.reconnects.load(Ordering::Relaxed);
        // `queued` is read LAST: a packet is counted queued before it can be
        // sent or dropped, so reading it after the others can only make the
        // derived depth briefly too high, never too low.
        let queued = self.inner.queued.load(Ordering::Relaxed);
        HepExportSnapshot {
            transport: self.inner.transport,
            sent,
            failures,
            reconnects,
            queued,
            replayed,
            dropped,
        }
    }
}

impl HepExportSnapshot {
    /// Every failure, of any kind.
    #[must_use]
    pub fn failed(&self) -> u64 {
        self.failures
            .iter()
            .copied()
            .fold(0u64, u64::saturating_add)
    }

    /// Every packet discarded undelivered, for any reason.
    #[must_use]
    pub fn dropped_total(&self) -> u64 {
        self.dropped.iter().copied().fold(0u64, u64::saturating_add)
    }

    /// Packets queued and neither sent nor dropped yet: what the sender holds
    /// now. Derived from `queued = sent + dropped + depth` rather than kept as
    /// its own counter, so it cannot disagree with the other three.
    #[must_use]
    pub fn depth(&self) -> u64 {
        self.queued
            .saturating_sub(self.sent)
            .saturating_sub(self.dropped_total())
    }

    /// What "sent" means on this transport, in words.
    #[must_use]
    pub fn delivery(&self) -> &'static str {
        if self.transport == "udp" {
            "handed to the kernel: UDP reports no delivery, so a collector that \
             is down produces no failure here unless its host refuses with ICMP"
        } else {
            "written to the connection: a write that fails is counted, the \
             packet stays queued, and the sender dials again with backoff"
        }
    }

    /// The line a headless run logs at its end.
    ///
    /// # Arguments
    ///
    /// * `destination` — the collector, as the operator named it.
    #[must_use]
    pub fn summary_line(&self, destination: &str) -> String {
        let kinds: Vec<String> = ExportFailure::ALL
            .iter()
            .filter(|k| self.failures[k.index()] > 0)
            .map(|k| format!("{} {}", k.as_str(), self.failures[k.index()]))
            .collect();
        let failed = if kinds.is_empty() {
            "none failed".to_string()
        } else {
            format!("{} failed attempt(s) ({})", self.failed(), kinds.join(", "))
        };
        let reasons: Vec<String> = DropReason::ALL
            .iter()
            .filter(|r| self.dropped[r.index()] > 0)
            .map(|r| format!("{} {}", r.as_str(), self.dropped[r.index()]))
            .collect();
        let dropped = if reasons.is_empty() {
            "none dropped".to_string()
        } else {
            format!("{} dropped ({})", self.dropped_total(), reasons.join(", "))
        };
        format!(
            "HEP export to {destination} over {}: {} packet(s) sent, {} queued, {} \
             replayed after an outage, {dropped}, {} still queued, {failed}, {} \
             reconnect(s); sent means {}",
            self.transport,
            self.sent,
            self.queued,
            self.replayed,
            self.depth(),
            self.reconnects,
            self.delivery()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kind sits at its own index and has its own name.
    #[test]
    fn every_failure_kind_has_its_own_slot_and_name() {
        let names: std::collections::BTreeSet<&str> =
            ExportFailure::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), ExportFailure::COUNT);
        for (i, k) in ExportFailure::ALL.iter().enumerate() {
            assert_eq!(k.index(), i);
        }
    }

    /// The end-of-run line names each failing kind, and a UDP exporter's line
    /// says it can claim nothing about delivery.
    #[test]
    fn the_summary_line_names_the_failures_and_what_sent_means() {
        let c = HepExportCounters::new("tcp");
        for _ in 0..9 {
            c.record_queued();
        }
        c.record_sent();
        c.record_sent();
        c.record_replayed();
        c.record_failure(ExportFailure::Connect);
        c.record_failure(ExportFailure::Connect);
        c.record_reconnect();
        c.record_dropped(DropReason::QueueFull, 3);
        c.record_dropped(DropReason::Stopped, 1);
        let line = c.snapshot().summary_line("192.0.2.10:9061");
        for needle in [
            "192.0.2.10:9061",
            "over tcp",
            "2 packet(s) sent",
            "9 queued",
            "1 replayed after an outage",
            "4 dropped (queue_full 3, stopped 1)",
            "3 still queued",
            "2 failed attempt(s) (connect 2)",
            "1 reconnect(s)",
        ] {
            assert!(line.contains(needle), "`{needle}` missing from: {line}");
        }
        assert!(
            !line.contains("unsent_at_exit"),
            "a reason with no drops is not named: {line}"
        );
        let udp = HepExportCounters::new("udp")
            .snapshot()
            .summary_line("192.0.2.10:9060");
        assert!(udp.contains("UDP reports no delivery"), "{udp}");
        assert!(udp.contains("none failed"), "{udp}");
        assert!(udp.contains("none dropped"), "{udp}");
    }

    /// **Every packet ends in exactly one place**: the depth is what is left
    /// of `queued` after `sent` and every drop reason, so a drop counted under
    /// any reason shrinks it, and it never wraps below zero.
    #[test]
    fn the_depth_is_queued_less_sent_less_every_drop() {
        let c = HepExportCounters::new("tcp");
        for _ in 0..10 {
            c.record_queued();
        }
        c.record_sent();
        assert_eq!(c.snapshot().depth(), 9);
        for (i, reason) in DropReason::ALL.into_iter().enumerate() {
            c.record_dropped(reason, 2);
            assert_eq!(
                c.snapshot().depth(),
                9 - 2 * (i as u64 + 1),
                "{} not subtracted",
                reason.as_str()
            );
        }
        c.record_dropped(DropReason::Stopped, 50);
        assert_eq!(c.snapshot().depth(), 0, "saturates, never wraps");
    }

    /// Every drop reason sits at its own index and has its own name.
    #[test]
    fn every_drop_reason_has_its_own_slot_and_name() {
        let names: std::collections::BTreeSet<&str> =
            DropReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(names.len(), DropReason::COUNT);
        for (i, r) in DropReason::ALL.iter().enumerate() {
            assert_eq!(r.index(), i);
        }
    }
}
