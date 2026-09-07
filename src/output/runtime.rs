// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runtime statistics: what sipnab is doing, and what it is costing the host.
//!
//! # Why this module exists
//!
//! sipnab exports 32 Prometheus metrics and none of them is reachable over MCP
//! or REST. The metrics listener is also off by default, so on most
//! deployments those numbers exist in-process and nothing can read them — an
//! agent asked "is this server healthy" cannot enable a listener to find out.
//!
//! Two things here are genuinely new rather than a parity fix. sipnab could not
//! state its own resident set size, thread count or file-descriptor count at
//! all; and it could not say what fraction of the host it was using, which is
//! the question that matters when a capture box slows down. A capture that is
//! itself the reason the proxy started dropping calls is the worst failure this
//! tool can have, and it was invisible.
//!
//! # Reading the host honestly
//!
//! Inside a container the real denominators are the cgroup's limits, not the
//! machine's. A percentage computed against the wrong total is worse than no
//! percentage, because it will be believed — so the answer names which
//! denominator it used, and reports absence rather than zero on a platform
//! where a figure was never readable.

use serde::Serialize;

/// The memory share at or above which sipnab is called a load-bearing
/// consumer of its host.
///
/// Ten percent, deliberately low. The question this answers is "could sipnab
/// be part of why this box is struggling", and on a capture host that is worth
/// raising early — a false "look at me" costs a glance, a missed one costs an
/// outage nobody attributes correctly.
pub const SIGNIFICANT_MEMORY_PCT: f64 = 10.0;

/// What sipnab's own process is consuming.
///
/// Every field is optional because the sources are platform-specific: `None`
/// means "not readable here", which is a different fact from `0` and must not
/// be rendered as one.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcessStats {
    /// Resident set size, bytes. The number an operator reaches for first.
    pub rss_bytes: Option<u64>,
    /// Virtual size, bytes.
    pub virtual_bytes: Option<u64>,
    /// OS threads in this process.
    pub threads: Option<u64>,
    /// Open file descriptors.
    pub open_fds: Option<u64>,
    /// CPU seconds consumed, user plus system.
    pub cpu_seconds: Option<f64>,
}

/// The host's totals, or the cgroup's limits when sipnab runs inside one.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HostStats {
    /// Total memory, bytes.
    pub memory_total_bytes: Option<u64>,
    /// Memory available for a new allocation without swapping, bytes.
    pub memory_available_bytes: Option<u64>,
    /// Logical CPUs.
    pub cpus: Option<u64>,
    /// Which denominator the figures above came from: `"host"` or `"cgroup"`.
    ///
    /// Named rather than assumed. A memory percentage against the machine's
    /// total is wrong by a large factor inside a container with a small limit,
    /// and a reader cannot tell which they were given unless it is stated.
    pub basis: &'static str,
}

/// sipnab's share of the host, computed only where both halves are known.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ImpactStats {
    /// Resident set as a percentage of [`HostStats::memory_total_bytes`].
    pub memory_pct: Option<f64>,
    /// Whether sipnab is a load-bearing consumer on this host right now.
    ///
    /// The judgment, not just the arithmetic. `capture_health` is the
    /// precedent: it turns counters into a verdict rather than leaving the
    /// division to the reader.
    pub significant: Option<bool>,
    /// Why [`Self::significant`] says what it says, including the threshold.
    pub note: Option<String>,
}

/// Read `/proc/self/status`, `/proc/self/stat` and `/proc/self/fd`.
///
/// # Returns
///
/// Whatever could be read. On a platform without `/proc` every field is
/// `None`, which the surfaces render as absent rather than as zero.
#[must_use]
pub fn process_stats() -> ProcessStats {
    let mut out = ProcessStats::default();

    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            // These are in kB, per the kernel's own formatting.
            let kb = || -> Option<u64> { value.split_whitespace().next()?.parse::<u64>().ok() };
            match key {
                "VmRSS" => out.rss_bytes = kb().map(|k| k * 1024),
                "VmSize" => out.virtual_bytes = kb().map(|k| k * 1024),
                "Threads" => out.threads = value.trim().parse().ok(),
                _ => {}
            }
        }
    }

    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        // Fields 14 and 15 are utime and stime in clock ticks. The comm field
        // may contain spaces and parentheses, so the scan starts after the
        // LAST ')' rather than splitting the whole line.
        if let Some(after) = stat.rfind(')').map(|i| &stat[i + 1..]) {
            let f: Vec<&str> = after.split_whitespace().collect();
            // After the ')' the first field is state, so utime is index 11.
            if let (Some(u), Some(s)) = (f.get(11), f.get(12))
                && let (Ok(u), Ok(s)) = (u.parse::<u64>(), s.parse::<u64>())
            {
                // 100 ticks per second is the near-universal USER_HZ. It is a
                // constant rather than a syscall because getting it wrong
                // scales the answer, and no supported platform differs.
                out.cpu_seconds = Some((u + s) as f64 / 100.0);
            }
        }
    }

    if let Ok(fds) = std::fs::read_dir("/proc/self/fd") {
        // The read_dir handle is itself one of the descriptors it counts, so
        // the figure is one high for an instant. Left uncorrected: pretending
        // to a precision the sampling does not have would be worse than being
        // one out on a number whose purpose is "am I near the limit".
        out.open_fds = Some(fds.count() as u64);
    }

    out
}

/// Read the host's totals, preferring a cgroup limit where one applies.
#[must_use]
pub fn host_stats() -> HostStats {
    let mut out = HostStats {
        basis: "host",
        ..HostStats::default()
    };

    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let kb = value
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|k| k * 1024);
            match key {
                "MemTotal" => out.memory_total_bytes = kb,
                "MemAvailable" => out.memory_available_bytes = kb,
                _ => {}
            }
        }
    }
    out.cpus = std::thread::available_parallelism()
        .ok()
        .map(|n| n.get() as u64);

    // cgroup v2. `max` means unlimited, in which case the machine's total is
    // the honest denominator and the basis stays "host".
    if let Ok(limit) = std::fs::read_to_string("/sys/fs/cgroup/memory.max")
        && let Ok(bytes) = limit.trim().parse::<u64>()
    {
        out.memory_total_bytes = Some(bytes);
        out.basis = "cgroup";
    }

    out
}

/// sipnab's share of the host, and whether that share is load-bearing.
///
/// # Arguments
///
/// * `process` — sipnab's own consumption.
/// * `host` — the totals to divide by.
/// * `significant_pct` — the memory share at or above which sipnab is called a
///   load-bearing consumer.
#[must_use]
pub fn impact(process: &ProcessStats, host: &HostStats, significant_pct: f64) -> ImpactStats {
    let Some((rss, total)) = process.rss_bytes.zip(host.memory_total_bytes) else {
        // Half the division missing means no percentage at all. Reporting one
        // side as a ratio of nothing is the confidently wrong number this
        // module exists to avoid.
        return ImpactStats::default();
    };
    if total == 0 {
        return ImpactStats::default();
    }
    let pct = (rss as f64 / total as f64) * 100.0;
    let significant = pct >= significant_pct;
    ImpactStats {
        memory_pct: Some(pct),
        significant: Some(significant),
        note: Some(format!(
            "sipnab holds {pct:.1}% of the {} memory total; \
             the threshold for load-bearing is {significant_pct:.1}%",
            host.basis
        )),
    }
}

/// What an interface itself reports, as distinct from what sipnab's capture
/// handle saw.
///
/// # Why both halves are needed
///
/// sipnab reads `pcap::Stat` — `ps_recv`, `ps_drop`, `ps_ifdrop` — which are
/// scoped to its own handle: what sipnab saw, and what was discarded on the way
/// to it. Those say nothing about the interface. And the distinction decides
/// the remedy: `ps_ifdrop` climbing with `rx_missed_errors` is a NIC that
/// cannot keep up, fixed with ring size or coalescing; `ps_drop` climbing alone
/// is sipnab's own read loop falling behind, fixed with `--buffer` or a
/// tighter filter. Opposite fixes, and the handle counter alone cannot tell
/// them apart.
#[derive(Debug, Clone, Default, Serialize)]
pub struct InterfaceStats {
    /// The interface name.
    pub name: String,
    /// Link state from `operstate`.
    pub operstate: Option<String>,
    /// Negotiated speed in Mbit/s, when the driver reports one.
    pub speed_mbps: Option<u64>,
    /// MTU.
    pub mtu: Option<u64>,
    /// Packets received by the interface.
    pub rx_packets: Option<u64>,
    /// Bytes received by the interface.
    pub rx_bytes: Option<u64>,
    /// Receive errors.
    pub rx_errors: Option<u64>,
    /// Packets the interface dropped.
    pub rx_dropped: Option<u64>,
    /// Packets missed because the NIC could not keep up.
    ///
    /// The counter to read beside sipnab's `ps_ifdrop`: the two rising together
    /// name the hardware rather than the reader.
    pub rx_missed_errors: Option<u64>,
}

/// Read one interface's statistics from `/sys/class/net`.
///
/// # Arguments
///
/// * `name` — the interface, as sipnab was asked to capture on.
///
/// # Returns
///
/// Whatever the kernel exposes. Fields the driver does not implement come back
/// `None` rather than zero — `speed` in particular is absent on virtual
/// interfaces, and reporting `0 Mbit/s` for one would read as a dead link.
#[must_use]
pub fn interface_stats(name: &str) -> InterfaceStats {
    // The name comes from the command line, but it is joined into a path, so
    // anything that could climb out of the directory is refused outright.
    if name.is_empty() || name.contains(['/', '\\']) || name.contains("..") {
        return InterfaceStats {
            name: name.to_string(),
            ..InterfaceStats::default()
        };
    }
    let base = std::path::Path::new("/sys/class/net").join(name);
    let read = |leaf: &str| -> Option<String> {
        std::fs::read_to_string(base.join(leaf))
            .ok()
            .map(|v| v.trim().to_string())
    };
    let num = |leaf: &str| -> Option<u64> { read(leaf)?.parse().ok() };

    InterfaceStats {
        name: name.to_string(),
        operstate: read("operstate"),
        // A down or virtual interface reports -1, which is "unknown", not a
        // speed. Parsing it as u64 fails and yields None, which is correct.
        speed_mbps: num("speed"),
        mtu: num("mtu"),
        rx_packets: num("statistics/rx_packets"),
        rx_bytes: num("statistics/rx_bytes"),
        rx_errors: num("statistics/rx_errors"),
        rx_dropped: num("statistics/rx_dropped"),
        rx_missed_errors: num("statistics/rx_missed_errors"),
    }
}

/// A store's occupancy against the cap that bounds it.
///
/// `dialogs_active` alone is a number; beside `max_dialogs` it is a decision.
/// An operator who cannot see occupancy learns about eviction by noticing that
/// calls have gone missing.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Occupancy {
    /// What the store holds now.
    pub used: u64,
    /// What it can hold.
    pub capacity: u64,
    /// `used` as a percentage of `capacity`, absent when the cap is zero.
    pub pct: Option<f64>,
}

impl Occupancy {
    /// Build one, refusing to divide by a zero capacity.
    #[must_use]
    pub fn new(used: u64, capacity: u64) -> Self {
        Self {
            used,
            capacity,
            pct: (capacity > 0).then(|| (used as f64 / capacity as f64) * 100.0),
        }
    }
}

/// Everything `runtime_stats` and `GET /v1/runtime` answer with.
///
/// One structure, one derivation, both surfaces — a statistic reachable from
/// one interface and not the other is the parity defect this project has
/// already fixed twice.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RuntimeStats {
    /// Wire-format version of this envelope.
    pub schema_version: u32,
    /// sipnab's own process.
    pub process: ProcessStats,
    /// The host, or the cgroup when sipnab runs inside one.
    pub host: HostStats,
    /// sipnab's share of it, and whether that share is load-bearing.
    pub impact: ImpactStats,
    /// Per-capture-interface counters, from the interface rather than from
    /// sipnab's handle.
    pub interfaces: Vec<InterfaceStats>,
    /// Dialog-store occupancy against its cap.
    pub dialogs: Occupancy,
    /// Stream-store occupancy against its cap.
    pub streams: Occupancy,
    /// Packets the capture path has seen.
    pub capture_packets_total: u64,
    /// Packets waiting in the capture queue.
    pub capture_queue_depth_packets: u64,
    /// Times the capture path blocked because the queue was full.
    pub capture_backpressure_blocks_total: u64,
    /// Seconds since this process started serving.
    pub uptime_seconds: u64,
    /// Rates across a sampling window, when one was asked for.
    ///
    /// Absent by default: every counter above is cumulative, and measuring a
    /// rate costs a wait. "1,284,301 messages" answers nothing an operator
    /// asked; "312 per second, of which 190 are OPTIONS" answers the question
    /// they actually have.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rates: Option<Rates>,
}

/// A rate measured across a window, with the window that was actually used.
///
/// # Why the window is reported back
///
/// A rate over a window shorter than the sample has no population behind it.
/// Reporting the window that was applied — not the one requested — is the same
/// rule `min_sample` enforces in `expect.rs`, and it lets a reader see that
/// they asked for one second and got the floor.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Rates {
    /// The window actually sampled, seconds.
    pub window_seconds: u64,
    /// Packets per second across the window.
    pub packets_per_second: f64,
    /// Dialogs opened per second across the window.
    pub calls_per_second: f64,
    /// Dialogs opened per second, split by the method that opened them.
    ///
    /// The breakdown is the point. A rate that does not separate INVITE from
    /// OPTIONS describes the keepalive plane rather than the calls — on one
    /// real capture 98 of 110 problem rows were OPTIONS — and an undifferentiated
    /// total is the same mistake `by_method` exists to fix on the dialog page.
    pub calls_per_second_by_method: Vec<(String, f64)>,
}

/// The longest window either surface will sample a rate across.
///
/// A rate costs a wait, and the wait is time the caller spends blocked on one
/// answer. Thirty seconds is long enough to smooth a bursty INVITE rate — on a
/// trunk carrying 10,000 packets per second it observes 300,000 packets — and
/// short enough to stay inside the deadline an MCP client or an HTTP caller
/// gives one request.
pub const MAX_SAMPLE_SECONDS: u32 = 30;

/// Clamp a requested sample window to [`MAX_SAMPLE_SECONDS`], refusing zero.
///
/// This lives beside the rate arithmetic rather than beside either caller
/// because MCP and REST have to refuse and clamp identically. A window one
/// surface accepts and the other rejects is a parity break a reader discovers
/// by asking twice and getting two answers.
///
/// # Arguments
///
/// * `requested` — the window the caller asked for, in seconds.
///
/// # Errors
///
/// Returns the sentence to show the caller when `requested` is zero. Zero is
/// refused rather than answered with an empty window because a response of
/// zero deltas is exactly what a healthy quiet capture looks like, and the
/// caller would have no way to tell the two apart.
pub fn resolve_sample_seconds(requested: u32) -> Result<u32, &'static str> {
    if requested == 0 {
        return Err("sample_seconds must be at least 1. A zero-second window \
                    observes nothing, and a response of zero deltas reads as a \
                    quiet capture.");
    }
    Ok(requested.min(MAX_SAMPLE_SECONDS))
}

/// One end of a rate measurement.
#[derive(Debug, Clone)]
pub struct RateSample {
    /// Packets the capture path had seen.
    packets: u64,
    /// Dialogs held, by opening method.
    by_method: Vec<(String, usize)>,
    /// Dialogs held in total.
    dialogs: usize,
    /// When this was taken.
    at: std::time::Instant,
}

impl RateSample {
    /// Take a sample from the dialog store and the capture counters.
    #[must_use]
    pub fn read(dialogs: &crate::sip::dialog_store::DialogStore) -> Self {
        Self {
            packets: crate::capture::captured_packets(),
            by_method: crate::sip::dialog::method_breakdown(dialogs.iter()),
            dialogs: dialogs.len(),
            at: std::time::Instant::now(),
        }
    }
}

/// Turn two samples into rates.
///
/// # Arguments
///
/// * `before`, `after` — the two ends of the window.
///
/// # Returns
///
/// The rates, with every figure zero when no time elapsed — a division by a
/// zero window would otherwise publish an infinity as a measurement.
#[must_use]
pub fn rates(before: &RateSample, after: &RateSample) -> Rates {
    let secs = after.at.duration_since(before.at).as_secs_f64();
    if secs <= 0.0 {
        return Rates::default();
    }
    let per = |a: u64, b: u64| (a.saturating_sub(b)) as f64 / secs;

    let mut by_method: Vec<(String, f64)> = Vec::new();
    for (method, count) in &after.by_method {
        let was = before
            .by_method
            .iter()
            .find(|(m, _)| m == method)
            .map_or(0, |(_, c)| *c);
        let delta = count.saturating_sub(was) as f64 / secs;
        by_method.push((method.clone(), delta));
    }
    // Dominant first, then by name — the same ordering `method_breakdown`
    // uses, so a reader comparing the two sees one order.
    crate::sort::sort_by_dyn(
        &mut by_method,
        &mut |a: &(String, f64), b: &(String, f64)| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        },
    );

    Rates {
        window_seconds: secs.round() as u64,
        packets_per_second: per(after.packets, before.packets),
        calls_per_second: (after.dialogs.saturating_sub(before.dialogs)) as f64 / secs,
        calls_per_second_by_method: by_method,
    }
}

/// Assemble the runtime answer both surfaces return.
///
/// # Arguments
///
/// * `dialogs` — the dialog store, for occupancy against its cap.
/// * `streams` — the stream store, likewise.
/// * `meter` — the capture channel's meter, when a live capture owns one.
/// * `interfaces` — the interfaces sipnab was asked to capture on.
/// * `uptime_seconds` — how long this process has been serving.
/// * `significant_pct` — the memory share at which sipnab is called
///   load-bearing on this host.
///
/// # Returns
///
/// One [`RuntimeStats`], built once so MCP and REST cannot report different
/// numbers for the same process.
#[must_use]
pub fn collect(
    dialogs: &crate::sip::dialog_store::DialogStore,
    streams: &crate::rtp::stream_store::StreamStore,
    meter: Option<&crate::capture::channel::CaptureMeter>,
    interfaces: &[String],
    uptime_seconds: u64,
    significant_pct: f64,
) -> RuntimeStats {
    let process = process_stats();
    let host = host_stats();
    let impact = impact(&process, &host, significant_pct);
    RuntimeStats {
        schema_version: 1,
        process,
        host,
        impact,
        interfaces: interfaces.iter().map(|n| interface_stats(n)).collect(),
        dialogs: Occupancy::new(dialogs.len() as u64, dialogs.max_dialogs() as u64),
        streams: Occupancy::new(streams.len() as u64, streams.max_streams() as u64),
        capture_packets_total: crate::capture::captured_packets(),
        capture_queue_depth_packets: meter.map_or(0, |m| m.in_flight() as u64),
        capture_backpressure_blocks_total: meter.map_or(0, CaptureMeterExt::blocks),
        uptime_seconds,
        rates: None,
    }
}

/// Reads the meter's backpressure counter through a named function, so
/// `map_or` above does not need a closure that borrows.
trait CaptureMeterExt {
    /// Times the capture path blocked because the queue was full.
    fn blocks(&self) -> u64;
}

impl CaptureMeterExt for crate::capture::channel::CaptureMeter {
    fn blocks(&self) -> u64 {
        self.backpressure_blocks()
    }
}

#[cfg(test)]
mod tests {
    /// Rates divide the delta by the window that actually elapsed.
    #[test]
    fn rates_are_the_delta_over_the_window() {
        let t0 = std::time::Instant::now();
        let before = RateSample {
            packets: 1000,
            by_method: vec![("INVITE".into(), 10), ("OPTIONS".into(), 100)],
            dialogs: 110,
            at: t0,
        };
        let after = RateSample {
            packets: 3000,
            by_method: vec![("INVITE".into(), 14), ("OPTIONS".into(), 300)],
            dialogs: 314,
            at: t0 + std::time::Duration::from_secs(2),
        };
        let r = rates(&before, &after);
        assert_eq!(r.window_seconds, 2);
        assert!((r.packets_per_second - 1000.0).abs() < 0.01, "2000 over 2s");
        assert!((r.calls_per_second - 102.0).abs() < 0.01, "204 over 2s");
    }

    /// The breakdown is dominant-first, and it separates the keepalive plane.
    ///
    /// The reason the field exists: a rate that does not split INVITE from
    /// OPTIONS describes whatever the deployment does most, which in the field
    /// is the keepalive plane rather than the calls.
    #[test]
    fn the_rate_breakdown_puts_the_dominant_method_first() {
        let t0 = std::time::Instant::now();
        let before = RateSample {
            packets: 0,
            by_method: vec![("INVITE".into(), 0), ("OPTIONS".into(), 0)],
            dialogs: 0,
            at: t0,
        };
        let after = RateSample {
            packets: 0,
            by_method: vec![("INVITE".into(), 2), ("OPTIONS".into(), 98)],
            dialogs: 100,
            at: t0 + std::time::Duration::from_secs(1),
        };
        let r = rates(&before, &after);
        assert_eq!(
            r.calls_per_second_by_method[0].0, "OPTIONS",
            "dominant first"
        );
        assert!((r.calls_per_second_by_method[0].1 - 98.0).abs() < 0.01);
        assert_eq!(r.calls_per_second_by_method[1].0, "INVITE");
    }

    /// A zero window publishes zeros, never an infinity.
    ///
    /// Dividing a delta by no elapsed time yields `inf`, and an infinity
    /// rendered as a measurement is the confidently wrong number this module
    /// refuses everywhere else.
    #[test]
    fn a_zero_window_yields_no_rate_rather_than_an_infinity() {
        let t0 = std::time::Instant::now();
        let s = RateSample {
            packets: 5,
            by_method: vec![("INVITE".into(), 1)],
            dialogs: 1,
            at: t0,
        };
        let r = rates(&s, &s);
        assert_eq!(r.window_seconds, 0);
        assert!(r.packets_per_second.is_finite() && r.packets_per_second == 0.0);
        assert!(r.calls_per_second == 0.0);
    }

    /// A counter that went backwards does not produce a negative rate.
    ///
    /// A store that evicted between the two reads holds fewer dialogs at the
    /// end than at the start. That is eviction, not negative traffic.
    #[test]
    fn an_evicting_store_does_not_report_a_negative_rate() {
        let t0 = std::time::Instant::now();
        let before = RateSample {
            packets: 100,
            by_method: vec![("INVITE".into(), 50)],
            dialogs: 50,
            at: t0,
        };
        let after = RateSample {
            packets: 100,
            by_method: vec![("INVITE".into(), 10)],
            dialogs: 10,
            at: t0 + std::time::Duration::from_secs(1),
        };
        let r = rates(&before, &after);
        assert!(r.calls_per_second >= 0.0, "got {}", r.calls_per_second);
        assert!(r.calls_per_second_by_method[0].1 >= 0.0);
    }

    /// A real interface reports its own counters.
    ///
    /// Loopback exists on every Linux host and is the one interface a test can
    /// rely on. The point is that these come from the INTERFACE, not from
    /// sipnab's capture handle.
    #[test]
    fn an_interface_reports_its_own_counters() {
        let lo = interface_stats("lo");
        assert_eq!(lo.name, "lo");
        assert!(lo.mtu.expect("lo has an MTU") > 0);
        assert!(lo.rx_packets.is_some(), "the kernel exposes rx_packets");
        assert_eq!(
            lo.operstate.as_deref(),
            Some("unknown"),
            "loopback is always 'unknown'"
        );
    }

    /// A speed the driver does not report is absent, not zero.
    ///
    /// Loopback reports `-1` for speed, meaning unknown. Rendering that as
    /// `0 Mbit/s` would read as a dead link on an interface that is fine.
    #[test]
    fn an_unreported_speed_is_absent_rather_than_zero() {
        assert_eq!(interface_stats("lo").speed_mbps, None);
    }

    /// An interface that does not exist yields a named row of unknowns.
    ///
    /// Not an error: an operator who mistypes `--device` should see which name
    /// was looked up, and every counter absent, rather than a stack of zeros
    /// that look like a quiet interface.
    #[test]
    fn a_missing_interface_is_all_unknowns_but_keeps_its_name() {
        let s = interface_stats("definitely-not-an-interface");
        assert_eq!(s.name, "definitely-not-an-interface");
        assert!(s.mtu.is_none() && s.rx_packets.is_none() && s.operstate.is_none());
    }

    /// A name that could climb out of /sys/class/net is refused.
    ///
    /// The name reaches this function from the command line and is joined into
    /// a path. Reading an arbitrary file and reporting it as interface
    /// statistics would be an information leak, so traversal is refused before
    /// any filesystem access.
    #[test]
    fn a_traversing_interface_name_reads_nothing() {
        for bad in ["../../etc/passwd", "..", "eth0/../../..", "a/b", "a\\b"] {
            let s = interface_stats(bad);
            assert!(
                s.mtu.is_none() && s.rx_packets.is_none() && s.operstate.is_none(),
                "{bad:?} must read nothing"
            );
            assert_eq!(s.name, bad, "but the name asked for is still reported");
        }
    }

    use super::*;

    /// sipnab can state its own resident set size.
    ///
    /// It could not, at all, before this — which is the first number an
    /// operator reaches for when a capture box slows down.
    #[test]
    fn the_process_reports_its_own_memory() {
        let p = process_stats();
        let rss = p.rss_bytes.expect("Linux exposes VmRSS");
        assert!(rss > 0, "a running process holds some memory");
        assert!(
            p.virtual_bytes.expect("VmSize") >= rss,
            "virtual size is never below resident"
        );
    }

    /// Threads, descriptors and CPU time are all readable.
    #[test]
    fn the_process_reports_threads_descriptors_and_cpu() {
        let p = process_stats();
        assert!(p.threads.expect("Threads") >= 1, "at least this one");
        assert!(
            p.open_fds.expect("/proc/self/fd") >= 3,
            "stdio alone is three"
        );
        assert!(
            p.cpu_seconds.expect("utime+stime").is_finite(),
            "CPU time is a real number"
        );
    }

    /// The host's totals are read, and the basis is named.
    ///
    /// Naming it is the point: a percentage against the machine's total is
    /// wrong by a large factor inside a container with a small limit, and a
    /// reader cannot tell which they were given unless the answer says.
    #[test]
    fn the_host_totals_name_their_basis() {
        let h = host_stats();
        assert!(h.memory_total_bytes.expect("MemTotal") > 0);
        assert!(h.cpus.expect("available_parallelism") >= 1);
        assert!(
            matches!(h.basis, "host" | "cgroup"),
            "the basis must be one of the two, got {}",
            h.basis
        );
    }

    /// The impact percentage is computed from both halves.
    #[test]
    fn impact_divides_the_process_by_the_host() {
        let p = ProcessStats {
            rss_bytes: Some(2 * 1024 * 1024 * 1024),
            ..ProcessStats::default()
        };
        let h = HostStats {
            memory_total_bytes: Some(8 * 1024 * 1024 * 1024),
            basis: "host",
            ..HostStats::default()
        };
        let i = impact(&p, &h, 10.0);
        assert!((i.memory_pct.expect("both halves known") - 25.0).abs() < 0.01);
        assert_eq!(i.significant, Some(true), "25% is past a 10% threshold");
        assert!(
            i.note.expect("a note").contains("host"),
            "the basis is named"
        );
    }

    /// Below the threshold sipnab is not called load-bearing.
    ///
    /// The negative case: a verdict that is always `true` is not a verdict.
    #[test]
    fn a_small_share_is_not_load_bearing() {
        let p = ProcessStats {
            rss_bytes: Some(64 * 1024 * 1024),
            ..ProcessStats::default()
        };
        let h = HostStats {
            memory_total_bytes: Some(128 * 1024 * 1024 * 1024),
            basis: "host",
            ..HostStats::default()
        };
        let i = impact(&p, &h, 10.0);
        assert_eq!(i.significant, Some(false));
        assert!(i.memory_pct.expect("known") < 1.0);
    }

    /// A missing half yields no percentage rather than a wrong one.
    ///
    /// The rule this module is built on: reporting one side as a ratio of
    /// nothing is the confidently wrong number to avoid. `None` says "not
    /// known here", which is a different fact from zero.
    #[test]
    fn a_missing_half_yields_no_percentage() {
        let known = ProcessStats {
            rss_bytes: Some(1024),
            ..ProcessStats::default()
        };
        let host = HostStats {
            memory_total_bytes: Some(4096),
            basis: "host",
            ..HostStats::default()
        };
        assert!(
            impact(&ProcessStats::default(), &host, 10.0)
                .memory_pct
                .is_none()
        );
        assert!(
            impact(&known, &HostStats::default(), 10.0)
                .memory_pct
                .is_none()
        );
        // And a zero denominator is a missing half, not a division by zero.
        let zero = HostStats {
            memory_total_bytes: Some(0),
            basis: "host",
            ..HostStats::default()
        };
        assert!(impact(&known, &zero, 10.0).memory_pct.is_none());
    }
    /// A zero window is refused rather than answered.
    ///
    /// The negative case that matters: an empty window returns zero deltas,
    /// and zero deltas is what a healthy quiet capture reports. Answering it
    /// would hand the caller a number they cannot distinguish from silence.
    #[test]
    fn a_zero_sample_window_is_refused() {
        let refused = resolve_sample_seconds(0).expect_err("zero must not resolve");
        assert!(
            refused.contains("at least 1"),
            "the refusal has to say what to send instead: {refused}"
        );
    }

    /// A window inside the cap is returned unchanged.
    #[test]
    fn a_sample_window_inside_the_cap_is_returned_unchanged() {
        for requested in [1u32, 5, 29, MAX_SAMPLE_SECONDS] {
            assert_eq!(
                resolve_sample_seconds(requested),
                Ok(requested),
                "{requested}s is inside the cap and must survive intact"
            );
        }
    }

    /// A window past the cap is clamped, not refused.
    ///
    /// Clamping rather than refusing is deliberate: the caller still gets a
    /// measurement, and `Rates::window_seconds` reports the window that was
    /// actually used so the clamp is visible rather than silent.
    #[test]
    fn a_sample_window_past_the_cap_is_clamped_not_refused() {
        for requested in [MAX_SAMPLE_SECONDS + 1, 600, u32::MAX] {
            assert_eq!(
                resolve_sample_seconds(requested),
                Ok(MAX_SAMPLE_SECONDS),
                "{requested}s must come back as the cap"
            );
        }
    }

    /// The cap is a real bound, not a value large enough to never bite.
    ///
    /// A cap of `u32::MAX` would pass both tests above while holding a caller
    /// open for 136 years, so the bound itself is asserted.
    #[test]
    fn the_sample_cap_is_a_window_a_caller_can_wait_out() {
        assert!(
            (1..=60).contains(&MAX_SAMPLE_SECONDS),
            "MAX_SAMPLE_SECONDS is {MAX_SAMPLE_SECONDS}s; a cap outside a \
             minute is not a window a synchronous caller waits out"
        );
    }
}
