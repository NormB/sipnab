//! Live network device capture.
//!
//! Opens a pcap handle on a network interface in promiscuous mode and sends
//! captured packets through a crossbeam channel. The capture loop respects
//! the global shutdown flag from [`crate::signals`] and applies optional BPF
//! filters, packet count limits, and duration limits.

use super::channel::PacketTx;
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};

use super::CaptureConfig;
use super::packet::Packet;
use crate::signals;

/// How long [`wait_readable`] blocks before returning control to the capture
/// loop so it can re-check the shutdown flag and the count/duration limits.
///
/// pcap's own read timeout is unreliable on the Linux `any` pseudo-device and
/// some drivers (it may not fire at all when the interface is idle), so we do
/// not depend on it for liveness — we poll the capture fd ourselves with this
/// bounded interval. This is what makes `--duration` / Ctrl-C take effect even
/// when no packets are arriving.
#[cfg(unix)]
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Result of waiting for a capture fd to become readable.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitResult {
    /// Data is available; call `next_packet()`.
    Readable,
    /// The wait window elapsed with no data — re-check loop conditions.
    TimedOut,
}

/// Convert a [`Duration`](std::time::Duration) into a `poll(2)` timeout in
/// milliseconds, clamped to `[0, c_int::MAX]`.
///
/// The clamp is load-bearing: an unchecked cast of a large duration can wrap to
/// a negative value, and a negative `poll` timeout means "block forever" — the
/// exact failure mode we are fixing. We never want that, so we saturate.
#[cfg(unix)]
fn poll_timeout_millis(timeout: std::time::Duration) -> libc::c_int {
    timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int
}

/// Wait up to `timeout` for `fd` to become readable.
///
/// Returns [`WaitResult::Readable`] as soon as data is available, or
/// [`WaitResult::TimedOut`] when the window elapses (or a signal interrupts the
/// call — surfacing promptly lets the loop notice a shutdown request). A closed
/// or otherwise invalid fd (`POLLNVAL`) is reported as an error rather than a
/// spurious `Readable`, which — paired with a non-blocking `next_packet()` that
/// returns nothing — would otherwise hot-spin.
#[cfg(unix)]
fn wait_readable(
    fd: std::os::unix::io::RawFd,
    timeout: std::time::Duration,
) -> std::io::Result<WaitResult> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe {
        libc::poll(
            &mut pfd as *mut libc::pollfd,
            1,
            poll_timeout_millis(timeout),
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        // EINTR: a signal arrived. Treat as a timeout so the loop re-checks the
        // shutdown flag immediately instead of erroring out.
        if err.kind() == std::io::ErrorKind::Interrupted {
            return Ok(WaitResult::TimedOut);
        }
        return Err(err);
    }
    if ret == 0 {
        return Ok(WaitResult::TimedOut);
    }
    if pfd.revents & libc::POLLNVAL != 0 {
        return Err(std::io::Error::other("poll: invalid capture fd (POLLNVAL)"));
    }
    // POLLIN, or POLLERR/POLLHUP — let next_packet() surface any real error.
    Ok(WaitResult::Readable)
}

/// Run a live capture loop on the given network device.
///
/// Opens the device with the parameters from `config`, applies any BPF filter,
/// then loops reading packets until shutdown is requested, the count limit is
/// reached, or the duration limit expires.
///
/// This function blocks and is intended to be called from a dedicated thread.
pub fn capture_live(
    device: &str,
    config: &CaptureConfig,
    tx: PacketTx,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> Result<()> {
    // The "any" pseudo-device on Linux does not support promiscuous mode.
    let use_promisc = device != "any";

    let mut cap = match pcap::Capture::from_device(device)
        .with_context(|| format!("Failed to open device '{device}'"))
        .and_then(|inactive| {
            inactive
                .promisc(use_promisc)
                .snaplen(config.snaplen as i32)
                .buffer_size((config.buffer_mb * 1_000_000) as i32)
                .timeout(100) // Return from next_packet every 100ms even without traffic
                // Deliver packets as soon as they arrive instead of waiting for
                // the kernel buffer to fill. Required for the poll()-driven loop
                // below: without it, poll() on the capture fd won't report the
                // socket readable promptly in non-blocking mode.
                .immediate_mode(true)
                .open()
                .with_context(|| format!("Failed to activate capture on '{device}'"))
        }) {
        Ok(cap) => cap,
        Err(e) => {
            if let Some(ready) = ready_tx {
                let _ = ready.send(Err(format!("{e:#}")));
            }
            return Err(e);
        }
    };

    if let Some(ref bpf) = config.bpf_filter
        && let Err(e) = cap.filter(bpf, true)
    {
        let err = anyhow::Error::new(e).context(format!("Failed to compile BPF filter: {bpf}"));
        if let Some(ready) = ready_tx {
            let _ = ready.send(Err(format!("{err:#}")));
        }
        return Err(err);
    }

    // Put the handle into non-blocking mode. The capture loop drives its own
    // liveness by polling the fd (see `wait_readable`), so individual reads
    // must never block — otherwise an idle interface would stall the loop and
    // `--duration` / Ctrl-C would not take effect until the next packet.
    #[cfg(unix)]
    let mut cap = match cap.setnonblock() {
        Ok(c) => c,
        Err(e) => {
            let err = anyhow::Error::new(e)
                .context(format!("Failed to set non-blocking mode on '{device}'"));
            if let Some(ready) = ready_tx {
                let _ = ready.send(Err(format!("{err:#}")));
            }
            return Err(err);
        }
    };

    // Selectable fd for poll(2). On Linux this is the packet-socket fd and is
    // valid for the lifetime of the capture.
    #[cfg(unix)]
    let poll_fd = {
        use std::os::unix::io::AsRawFd;
        cap.as_raw_fd()
    };

    // Signal that the capture device is open and ready.
    if let Some(ready) = ready_tx {
        let _ = ready.send(Ok(()));
    }

    let link_type = cap.get_datalink().0;
    let interface_name = Some(device.to_string());
    let start = std::time::Instant::now();
    let mut count: u64 = 0;

    tracing::info!(
        "Capturing on '{device}' (link_type={link_type}, snaplen={})",
        config.snaplen
    );

    loop {
        if signals::shutdown_requested() {
            tracing::debug!("Shutdown requested, stopping live capture");
            break;
        }

        if let Some(max_count) = config.count
            && count >= max_count
        {
            tracing::debug!("Reached packet count limit ({max_count})");
            break;
        }

        if let Some(duration) = config.duration
            && start.elapsed() >= duration
        {
            tracing::debug!("Reached duration limit ({duration:?})");
            break;
        }

        // Bounded wait so the loop re-checks shutdown/count/duration roughly
        // every POLL_INTERVAL even when the interface is completely idle. This
        // is what stops `--duration` from hanging on a quiet link.
        #[cfg(unix)]
        match wait_readable(poll_fd, POLL_INTERVAL) {
            Ok(WaitResult::Readable) => {}
            Ok(WaitResult::TimedOut) => continue,
            Err(e) => {
                tracing::error!("poll on capture fd for '{device}' failed: {e}");
                return Err(e).context("Fatal capture error while polling capture fd");
            }
        }

        match cap.next_packet() {
            Ok(pkt) => {
                let ts = pcap_ts_to_chrono(pkt.header.ts);
                let packet = Packet::new(
                    ts,
                    pkt.data.to_vec(),
                    pkt.header.caplen as usize,
                    pkt.header.len as usize,
                    interface_name.clone(),
                    link_type,
                );

                if tx.send(packet).is_err() {
                    tracing::debug!("Receiver dropped, stopping live capture");
                    break;
                }

                count += 1;
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Normal: timeout fired with no packets available
                continue;
            }
            Err(e) => {
                tracing::error!("Capture error on '{device}': {e}");
                // pcap errors on live devices are generally fatal
                return Err(e).context("Fatal capture error");
            }
        }
    }

    tracing::info!("Live capture on '{device}' finished: {count} packets");
    Ok(())
}

/// Packets whose pcap timestamp could not be converted and were stamped
/// with the wall clock instead. A non-zero value means capture timing
/// analysis (PDD, delta times, call duration) is unreliable for this run.
pub static INVALID_PCAP_TIMESTAMPS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Convert a pcap `libc::timeval` to a chrono UTC datetime.
///
/// A corrupt timeval (out-of-range seconds, or microseconds outside
/// `0..1_000_000`) falls back to the current wall clock — but loudly:
/// the event is counted in [`INVALID_PCAP_TIMESTAMPS`] and warned about
/// (rate-limited), because silently substituted timestamps corrupt every
/// downstream timing computation.
fn pcap_ts_to_chrono(ts: libc::timeval) -> DateTime<Utc> {
    let sec = ts.tv_sec;
    let usec = ts.tv_usec;
    let converted = if (0..1_000_000).contains(&usec) {
        Utc.timestamp_opt(sec, usec as u32 * 1000).single()
    } else {
        None
    };
    converted.unwrap_or_else(|| {
        let n = INVALID_PCAP_TIMESTAMPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if n == 1 || n.is_multiple_of(10_000) {
            tracing::warn!(
                "invalid pcap timestamp (tv_sec={sec}, tv_usec={usec}); \
                 stamping packet with current time ({n} occurrence(s) so far) — \
                 timing analysis for this capture is unreliable"
            );
        }
        Utc::now()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn tv(sec: i64, usec: i64) -> libc::timeval {
        libc::timeval {
            tv_sec: sec as _,
            tv_usec: usec as _,
        }
    }

    // ── poll_timeout_millis: overflow-safe Duration → c_int conversion ────
    #[cfg(unix)]
    mod poll_timeout {
        use super::*;
        use std::time::Duration;

        #[test]
        fn zero_duration_is_zero() {
            assert_eq!(poll_timeout_millis(Duration::ZERO), 0);
        }

        #[test]
        fn normal_duration_converts_exactly() {
            assert_eq!(poll_timeout_millis(Duration::from_millis(100)), 100);
        }

        #[test]
        fn boundary_at_int_max_is_preserved() {
            let max = libc::c_int::MAX;
            assert_eq!(poll_timeout_millis(Duration::from_millis(max as u64)), max);
        }

        #[test]
        fn overflowing_duration_clamps_not_wraps() {
            // A huge duration must clamp to c_int::MAX, never wrap to a small or
            // negative value (negative = "block forever" in poll(2) — the bug).
            let huge = Duration::from_millis(u64::MAX);
            assert_eq!(poll_timeout_millis(huge), libc::c_int::MAX);
            assert!(poll_timeout_millis(huge) > 0);
        }

        #[test]
        fn one_past_int_max_clamps() {
            let over = Duration::from_millis(libc::c_int::MAX as u64 + 1);
            assert_eq!(poll_timeout_millis(over), libc::c_int::MAX);
        }
    }

    // ── wait_readable: a BOUNDED wait that returns even with no data ──────
    // This is the property the idle capture loop lacked, which let --duration
    // hang. Tested deterministically with a pipe — no capture privileges.
    #[cfg(unix)]
    mod wait_readable_tests {
        use super::*;
        use std::os::unix::io::RawFd;
        use std::time::{Duration, Instant};

        /// (read_fd, write_fd)
        fn make_pipe() -> (RawFd, RawFd) {
            let mut fds = [0 as libc::c_int; 2];
            let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
            assert_eq!(r, 0, "pipe(2) failed: {}", std::io::Error::last_os_error());
            (fds[0], fds[1])
        }

        fn close(fd: RawFd) {
            unsafe { libc::close(fd) };
        }

        #[test]
        fn times_out_on_idle_fd() {
            // The regression test: nothing is ever written, yet the wait MUST
            // return (TimedOut) within roughly the timeout — not block forever.
            let (r, w) = make_pipe();
            let start = Instant::now();
            let res = wait_readable(r, Duration::from_millis(80)).expect("poll ok");
            let elapsed = start.elapsed();
            assert_eq!(res, WaitResult::TimedOut);
            assert!(
                elapsed >= Duration::from_millis(40),
                "returned too early: {elapsed:?}"
            );
            assert!(
                elapsed < Duration::from_secs(3),
                "did not return promptly: {elapsed:?}"
            );
            close(r);
            close(w);
        }

        #[test]
        fn returns_readable_when_data_present() {
            let (r, w) = make_pipe();
            let n = unsafe { libc::write(w, b"x".as_ptr() as *const libc::c_void, 1) };
            assert_eq!(n, 1, "write failed");
            let start = Instant::now();
            // Generous timeout: must come back fast because data is ready.
            let res = wait_readable(r, Duration::from_secs(5)).expect("poll ok");
            assert_eq!(res, WaitResult::Readable);
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "should return immediately when readable"
            );
            close(r);
            close(w);
        }

        #[test]
        fn zero_timeout_returns_immediately() {
            let (r, w) = make_pipe();
            let start = Instant::now();
            let res = wait_readable(r, Duration::ZERO).expect("poll ok");
            assert_eq!(res, WaitResult::TimedOut);
            assert!(start.elapsed() < Duration::from_millis(500));
            close(r);
            close(w);
        }

        #[test]
        fn invalid_fd_is_an_error_not_a_spin() {
            // Adversarial: a closed fd yields POLLNVAL. wait_readable must
            // surface an error (fatal) rather than report Readable, which —
            // paired with a no-op next_packet — would hot-spin forever.
            let (r, w) = make_pipe();
            close(r);
            let res = wait_readable(r, Duration::from_millis(50));
            assert!(res.is_err(), "closed fd must error, got {res:?}");
            close(w);
        }
    }

    #[test]
    fn valid_timestamp_converts_exactly() {
        let dt = pcap_ts_to_chrono(tv(1_700_000_000, 123_456));
        assert_eq!(dt.timestamp(), 1_700_000_000);
        assert_eq!(dt.timestamp_subsec_micros(), 123_456);
    }

    #[test]
    fn usec_boundary_999_999_is_valid() {
        let dt = pcap_ts_to_chrono(tv(0, 999_999));
        assert_eq!(dt.timestamp(), 0);
        assert_eq!(dt.timestamp_subsec_micros(), 999_999);
    }

    #[test]
    fn zero_timestamp_is_valid_epoch() {
        // A pcap with tv_sec = 0 is a real (if odd) timestamp, not an error:
        // it must convert to the epoch, not fall back to "now".
        let dt = pcap_ts_to_chrono(tv(0, 0));
        assert_eq!(dt.timestamp(), 0);
        assert_eq!(dt.timestamp_subsec_micros(), 0);
    }

    #[test]
    fn negative_usec_does_not_panic_and_is_counted() {
        // Corrupted tv_usec: `as u32` wraps -1 to u32::MAX, and the old
        // `* 1000` overflowed (panic in debug builds). Must instead fall
        // back cleanly and count the event.
        let before = INVALID_PCAP_TIMESTAMPS.load(Ordering::Relaxed);
        let dt = pcap_ts_to_chrono(tv(1_700_000_000, -1));
        let after = INVALID_PCAP_TIMESTAMPS.load(Ordering::Relaxed);
        assert!(after > before, "invalid timestamp must be counted");
        // Fallback stamps with "now" (within a generous window).
        assert!((Utc::now() - dt).num_seconds().abs() < 60);
    }

    #[test]
    fn oversized_usec_falls_back_and_is_counted() {
        // tv_usec must be < 1_000_000; 5_000_000 is corrupt.
        let before = INVALID_PCAP_TIMESTAMPS.load(Ordering::Relaxed);
        let dt = pcap_ts_to_chrono(tv(1_700_000_000, 5_000_000));
        let after = INVALID_PCAP_TIMESTAMPS.load(Ordering::Relaxed);
        assert!(after > before, "invalid timestamp must be counted");
        assert!((Utc::now() - dt).num_seconds().abs() < 60);
    }

    #[test]
    fn out_of_range_sec_falls_back_and_is_counted() {
        let before = INVALID_PCAP_TIMESTAMPS.load(Ordering::Relaxed);
        let dt = pcap_ts_to_chrono(tv(i64::MAX, 0));
        let after = INVALID_PCAP_TIMESTAMPS.load(Ordering::Relaxed);
        assert!(after > before, "invalid timestamp must be counted");
        assert!((Utc::now() - dt).num_seconds().abs() < 60);
    }
}
