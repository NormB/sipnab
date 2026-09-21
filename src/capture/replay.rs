// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read a capture file into a fresh pair of stores, off the live path.
//!
//! One reader, shared: the MCP `open_capture` background loader and the
//! `compare_captures` tool both read a pcap into a `DialogStore`/`StreamStore`
//! this way, and so does the REST `GET /v1/captures/compare` route. It routes
//! every packet through [`crate::pipeline::process_packet`] — the same applier
//! the live path uses — so a file read here is analyzed exactly as an `-I` one.
//!
//! The SIP port gate is off, which is what the TUI's interactive open does: it
//! is the direction that cannot under-report, because every port is considered.
//!
//! It REPORTS whether it stopped early rather than acting on that itself. A
//! truncated dump is the normal state of a rotating capture's newest member, so
//! the read keeps what it parsed and says so; a caller tracking capture
//! completeness ([`crate::mcp::completeness`]) notes it, and a one-shot reader
//! that only wants the counts ignores it. `src/capture/` cannot depend on
//! `src/mcp/`, which is the second reason the note lives at the call site.

use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;
use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// What one capture read produced.
pub struct ReadOutcome {
    /// Packets read before the loop ended.
    pub packets: u64,
    /// The error that ended the read early — a file that would not open, or a
    /// shutdown mid-read. `None` on a clean EOF and on a soft mid-file
    /// truncation (the packets already parsed stay in the stores).
    pub error: Option<String>,
    /// True when the read ended before the file did, by ANY path: an open
    /// failure, a shutdown request, or a truncated dump. Every count is then a
    /// floor, not a total.
    pub stopped_early: bool,
}

/// Read every packet of `path` into the two stores.
///
/// Routes through [`crate::pipeline::process_packet`] — the same applier the
/// live path uses — rather than a second classify-and-store loop, so an opened
/// capture is analyzed exactly as an `-I` one is.
///
/// # Returns
///
/// A [`ReadOutcome`]: the packet count, the error that stopped the read (if
/// any), and whether it stopped before the file ended. A file that will not
/// open reports zero packets, the reason, and `stopped_early`.
#[must_use]
pub fn read_into_stores(
    path: &Path,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    progress: &AtomicU64,
) -> ReadOutcome {
    // The guard owns any decompressed temp file (libpcap cannot read gzip) and
    // must outlive the read loop, so keep it bound for the whole function.
    let (mut cap, _gz_guard) = match crate::capture::file::open_offline(path) {
        Ok(opened) => opened,
        Err(e) => {
            // Zero of the file was read — the most partial read there is.
            return ReadOutcome {
                packets: 0,
                error: Some(format!("{e:#}")),
                stopped_early: true,
            };
        }
    };
    let link_type = cap.get_datalink().0;
    let mut rtp_heuristic = crate::rtp::heuristic::RtpHeuristic::new();
    let opts = crate::pipeline::PipelineOptions::default();
    let mut packets = 0u64;

    loop {
        // A load must not outlive a SIGTERM. Without this a multi-gigabyte read
        // holds the process open long after the operator asked it to stop.
        if crate::signals::shutdown_requested() {
            return ReadOutcome {
                packets,
                error: Some("shutdown requested during the load".to_string()),
                stopped_early: true,
            };
        }
        let pkt = match cap.next_packet() {
            Ok(pkt) => pkt,
            // Clean EOF: the file ended where the file ends.
            Err(pcap::Error::NoMorePackets) => break,
            // Anything else is a read that ended before the FILE did — a
            // truncated dump is the common one, and the normal state of a ring
            // buffer's newest member. The packets already parsed stay in the
            // stores, exactly as the CLI keeps them; what changes is that the
            // outcome now says the read is partial.
            Err(e) => {
                tracing::warn!(
                    "capture '{}' stopped early after {packets} packet(s): {e}",
                    path.display()
                );
                return ReadOutcome {
                    packets,
                    error: None,
                    stopped_early: true,
                };
            }
        };
        packets += 1;
        progress.store(packets, Ordering::Relaxed);

        // The shared, hardened converter: an out-of-range or nanosecond
        // tv_usec (crafted or high-precision capture) is rejected and counted
        // rather than overflowing here.
        let ts = crate::capture::file::pcap_ts_to_chrono(pkt.header.ts);
        let packet = crate::capture::Packet::new(
            ts,
            pkt.data.to_vec(),
            pkt.header.caplen as usize,
            pkt.header.len as usize,
            None,
            link_type,
        );
        // Counted exactly as the `-I` reader counts: a snapped frame as
        // snapped, a frame that produced nothing as undecodable.
        let Ok(parsed) = crate::capture::decode_captured_frame(&packet) else {
            continue;
        };
        if parsed.payload.is_empty() {
            continue;
        }
        // No decryption keys on this path, so no substituted plaintext.
        let mut decrypt = crate::pipeline::MediaDecrypt::default();
        crate::pipeline::process_packet(
            &parsed,
            dialog_store,
            stream_store,
            &mut rtp_heuristic,
            &opts,
            &mut decrypt,
            // RE4 asks a live relay. This path reads a FILE, whose calls ended
            // in the past, so there is nothing here to ask about.
            None,
        );
    }
    ReadOutcome {
        packets,
        error: None,
        stopped_early: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::dialog_store::DialogStore;

    /// A real capture reads into the stores and reports a clean, complete read.
    #[test]
    fn a_clean_read_fills_the_stores_and_reports_complete() {
        let ds = Arc::new(RwLock::new(DialogStore::new(1000, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(1000)));
        let progress = AtomicU64::new(0);
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples/sip-rtp-g711.pcap");

        let outcome = read_into_stores(&path, &ds, &ss, &progress);

        assert!(outcome.packets > 0, "the fixture has packets");
        assert!(outcome.error.is_none(), "a readable file is not an error");
        assert!(
            !outcome.stopped_early,
            "a file read to EOF did not stop early"
        );
        assert!(!ds.read().is_empty(), "the read produced dialogs");
    }

    /// A file that does not exist reports zero packets, an error, and — the bit
    /// a completeness tracker needs — that the read never covered the file.
    #[test]
    fn a_missing_file_reports_stopped_early_with_zero_packets() {
        let ds = Arc::new(RwLock::new(DialogStore::new(16, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(16)));
        let progress = AtomicU64::new(0);
        let path = std::path::Path::new("/nonexistent/definitely-not-here.pcap");

        let outcome = read_into_stores(path, &ds, &ss, &progress);

        assert_eq!(outcome.packets, 0);
        assert!(outcome.error.is_some(), "an unreadable file is an error");
        assert!(
            outcome.stopped_early,
            "zero of the file was read — the most partial read there is"
        );
    }

    /// A frame the capture cut short is counted as snapped on this reader too,
    /// so `open_capture`, `compare_captures` and the REST compare route report
    /// the capture quality an `-I` run of the same file reports.
    #[test]
    #[serial_test::serial(undecodable_tally)]
    fn a_snapped_frame_is_counted_on_the_replay_reader() {
        crate::capture::reset_undecodable_frames();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("snapped.pcap");
        std::fs::write(&path, crate::test_utils::one_record_pcap(64, 1500)).expect("write");
        let ds = Arc::new(RwLock::new(DialogStore::new(16, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(16)));
        let progress = AtomicU64::new(0);

        let outcome = read_into_stores(&path, &ds, &ss, &progress);

        assert_eq!(outcome.packets, 1, "the one record is read");
        assert_eq!(
            crate::capture::snapped_frames(),
            1,
            "64 of 1500 bytes is a snapped frame"
        );
        crate::capture::reset_undecodable_frames();
    }
}
