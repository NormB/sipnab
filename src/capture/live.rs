//! Live network device capture.
//!
//! Opens a pcap handle on a network interface in promiscuous mode and sends
//! captured packets through a crossbeam channel. The capture loop respects
//! the global shutdown flag from [`crate::signals`] and applies optional BPF
//! filters, packet count limits, and duration limits.

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use crossbeam_channel::Sender;

use super::CaptureConfig;
use super::packet::Packet;
use crate::signals;

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
    tx: Sender<Packet>,
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
    let sec = ts.tv_sec as i64;
    let usec = ts.tv_usec as i64;
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
