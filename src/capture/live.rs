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
    let mut cap = match pcap::Capture::from_device(device)
        .with_context(|| format!("Failed to open device '{device}'"))
        .and_then(|inactive| {
            inactive
                .promisc(true)
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

    log::info!(
        "Capturing on '{device}' (link_type={link_type}, snaplen={})",
        config.snaplen
    );

    loop {
        if signals::shutdown_requested() {
            log::debug!("Shutdown requested, stopping live capture");
            break;
        }

        if let Some(max_count) = config.count
            && count >= max_count
        {
            log::debug!("Reached packet count limit ({max_count})");
            break;
        }

        if let Some(duration) = config.duration
            && start.elapsed() >= duration
        {
            log::debug!("Reached duration limit ({duration:?})");
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
                    log::debug!("Receiver dropped, stopping live capture");
                    break;
                }

                count += 1;
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Normal: timeout fired with no packets available
                continue;
            }
            Err(e) => {
                log::error!("Capture error on '{device}': {e}");
                // pcap errors on live devices are generally fatal
                return Err(e).context("Fatal capture error");
            }
        }
    }

    log::info!("Live capture on '{device}' finished: {count} packets");
    Ok(())
}

/// Convert a pcap `libc::timeval` to a chrono UTC datetime.
fn pcap_ts_to_chrono(ts: libc::timeval) -> DateTime<Utc> {
    Utc.timestamp_opt(ts.tv_sec, (ts.tv_usec as u32) * 1000)
        .single()
        .unwrap_or_else(Utc::now)
}
