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
    /// Connections rebuilt after one broke, stream transports only.
    reconnects: AtomicU64,
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
    /// Connections rebuilt after one broke.
    pub reconnects: u64,
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

    /// One connection rebuilt after the previous one broke.
    pub fn record_reconnect(&self) {
        self.inner.reconnects.fetch_add(1, Ordering::Relaxed);
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
        HepExportSnapshot {
            transport: self.inner.transport,
            sent: self.inner.sent.load(Ordering::Relaxed),
            failures,
            reconnects: self.inner.reconnects.load(Ordering::Relaxed),
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

    /// What "sent" means on this transport, in words.
    #[must_use]
    pub fn delivery(&self) -> &'static str {
        if self.transport == "udp" {
            "handed to the kernel: UDP reports no delivery, so a collector that \
             is down produces no failure here"
        } else {
            "written to the connection: a write that fails is counted, and the \
             next packet dials again"
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
            format!("{} failed ({})", self.failed(), kinds.join(", "))
        };
        format!(
            "HEP export to {destination} over {}: {} packet(s) sent, {failed}, {} \
             reconnect(s); sent means {}",
            self.transport,
            self.sent,
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
        c.record_sent();
        c.record_failure(ExportFailure::Connect);
        c.record_failure(ExportFailure::Connect);
        c.record_reconnect();
        let line = c.snapshot().summary_line("192.0.2.10:9061");
        for needle in [
            "192.0.2.10:9061",
            "over tcp",
            "1 packet(s) sent",
            "2 failed (connect 2)",
        ] {
            assert!(line.contains(needle), "`{needle}` missing from: {line}");
        }
        let udp = HepExportCounters::new("udp")
            .snapshot()
            .summary_line("192.0.2.10:9060");
        assert!(udp.contains("UDP reports no delivery"), "{udp}");
        assert!(udp.contains("none failed"), "{udp}");
    }
}
