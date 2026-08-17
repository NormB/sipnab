// SPDX-License-Identifier: MIT OR Apache-2.0

//! Whether this host's clock is disciplined, and by how much it might be wrong.
//!
//! # Why a capture tool cares
//!
//! Inside ONE capture, clock error barely matters: one clock stamped every
//! packet, so the intervals between them are right even if the absolute time is
//! hours out. Every timing figure sipnab reports from a single capture — PDD,
//! call duration, jitter — is a difference, and a constant offset cancels.
//!
//! Across TWO captures on two hosts it stops canceling, and one strategy
//! depends on it directly. `find_correlated`'s `timing_heuristic` matches
//! dialogs created within two seconds of each other, and two seconds is smaller
//! than the skew an undisciplined host accumulates in a day. The failure is
//! silent in both directions: an SBC three seconds ahead of a PBX fails to
//! correlate legs that belong together, and a slow clock pulls unrelated legs
//! inside the window and correlates them. Neither announces itself — the caller
//! just gets a call tree that is confidently wrong about which leg went where.
//!
//! So this module does not fix clocks. It reports what the kernel already knows
//! about this one, so a consumer correlating across nodes can decide whether a
//! time-based match is worth anything here.
//!
//! # Where the numbers come from
//!
//! `adjtimex(2)`, which is how the kernel exposes its NTP discipline state.
//! Nothing is shelled out to and no daemon is contacted: `chronyc` or `ntpq`
//! would mean a dependency on which daemon happens to be installed, and would
//! report the daemon's opinion rather than the clock the timestamps came from.
//! The kernel's view is the one that stamped the packets.
//!
//! Everything here is an integer or a bool, so it can travel inside
//! `capture_health` without weakening that tool's counters-only guarantee.

/// What the kernel knows about this host's clock discipline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "mcp", derive(serde::Serialize))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct ClockDiscipline {
    /// True when the kernel considers the clock synchronized to a time source.
    ///
    /// False means `STA_UNSYNC` is set: no daemon is disciplining this clock,
    /// or it has lost its source. A cross-node time comparison against a host
    /// reporting `false` is a guess about a guess.
    pub synchronized: bool,
    /// Kernel's maximum error estimate, microseconds.
    ///
    /// The bound that matters for cross-node work: it grows without limit while
    /// a clock is undisciplined, so a large value is the signal that a
    /// two-second correlation window means nothing on this box.
    pub max_error_us: i64,
    /// Kernel's estimated error, microseconds. Usually far smaller than
    /// `max_error_us`, and an estimate rather than a bound.
    pub est_error_us: i64,
    /// False when this platform cannot report discipline at all.
    ///
    /// Distinguishes "the clock is not synchronized" from "we could not ask",
    /// which are different facts and would otherwise both read as a bad clock.
    /// A caller must not treat unavailability as a failed clock.
    pub available: bool,
}

impl ClockDiscipline {
    /// What to report where the kernel cannot be asked.
    ///
    /// `synchronized` is false and `available` is false, and the pair is the
    /// point: a consumer that checks only `synchronized` sees the cautious
    /// answer, and one that checks `available` learns that the caution is
    /// ignorance rather than measurement.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            synchronized: false,
            max_error_us: 0,
            est_error_us: 0,
            available: false,
        }
    }
}

/// Read the kernel's clock discipline state.
///
/// Never fails: a platform that cannot answer returns
/// [`ClockDiscipline::unavailable`], because a capture-health probe that
/// errored would take the rest of the report down with it.
#[must_use]
pub fn discipline() -> ClockDiscipline {
    #[cfg(all(target_os = "linux", feature = "native"))]
    {
        read_linux()
    }
    #[cfg(not(all(target_os = "linux", feature = "native")))]
    {
        ClockDiscipline::unavailable()
    }
}

/// Read the kernel's NTP discipline state through `adjtimex(2)`.
///
/// Linux-only and `native`-only, because it needs `libc`.
#[cfg(all(target_os = "linux", feature = "native"))]
fn read_linux() -> ClockDiscipline {
    // `STA_UNSYNC` (0x0040) is set when the clock is NOT synchronized. The
    // sense is inverted from what the field name suggests, which is worth
    // stating: reading it as "synced" is a one-character bug that reports every
    // undisciplined host as healthy.
    const STA_UNSYNC: i32 = 0x0040;

    // SAFETY: `timex` is a plain C struct of integers with no invariants, so an
    // all-zero bit pattern is a valid value of it.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: `tx` is a live, initialized local, and the pointer stays valid
    // for the whole call. `modes` was zeroed above, which means QUERY ONLY —
    // adjtimex reads that field first and mutates no clock state when it is 0,
    // so this cannot step on a running time daemon. The kernel writes only
    // within the struct it was handed.
    let rc = unsafe { libc::adjtimex(&raw mut tx) };
    if rc < 0 {
        return ClockDiscipline::unavailable();
    }
    ClockDiscipline {
        synchronized: (tx.status & STA_UNSYNC) == 0,
        max_error_us: tx.maxerror as i64,
        est_error_us: tx.esterror as i64,
        available: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_is_cautious_and_says_why() {
        let c = ClockDiscipline::unavailable();
        assert!(!c.synchronized, "the cautious answer for an unknown clock");
        assert!(
            !c.available,
            "and it must be distinguishable from a measured bad clock"
        );
    }

    /// Reading it never panics and never errors, whatever the host.
    ///
    /// This runs in CI on machines whose clock state is not ours to control, so
    /// it asserts the CONTRACT rather than a value: a probe that could fail
    /// would take the rest of `capture_health` down with it.
    #[test]
    fn reading_the_discipline_is_total() {
        let c = discipline();
        if c.available {
            // A real reading: the kernel's max error is never negative.
            assert!(
                c.max_error_us >= 0,
                "a maximum error cannot be negative: {}",
                c.max_error_us
            );
        } else {
            assert!(!c.synchronized, "unavailable must not claim synchronized");
        }
    }

    /// On Linux with `native`, the probe must actually reach the kernel.
    ///
    /// Without this, a `discipline()` that always returned `unavailable()`
    /// would pass every other test here while reporting nothing useful — the
    /// silent-zero shape, applied to a diagnostic.
    #[cfg(all(target_os = "linux", feature = "native"))]
    #[test]
    fn on_linux_the_kernel_actually_answers() {
        assert!(
            discipline().available,
            "adjtimex must answer on Linux; an unavailable reading here means \
             the probe is not wired to anything"
        );
    }
}
