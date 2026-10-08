// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read a capture file into a fresh pair of stores, off the live path.
//!
//! One reader, shared: the MCP `open_capture` background loader and the
//! `compare_captures` tool both read a pcap into a `DialogStore`/`StreamStore`
//! this way, and so does the REST `GET /v1/captures/compare` route. It routes
//! every packet through [`crate::pipeline::apply_hep_parse`] and then
//! [`crate::pipeline::process_packet`] — the same applier the live path uses —
//! with the caller's [`crate::pipeline::PipelineOptions`].
//!
//! The options are the caller's, not this module's. The servers pass the run's
//! (built by `crate::app::server_pipeline_options`), so a file read here
//! applies the run's `--hep-parse`, `--portrange`, `--no-rtp`, `--no-dialog`,
//! `--rtpproxy-control` and `--quiet-bad-parse` as `-I` on the same command
//! line does. Before they were threaded through, this reader used the
//! defaults, and a HEP copy opened through MCP or REST showed no SIP while the
//! same file given to `-I -E` decoded in full.
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

/// Read every packet of `path` into the two stores, classified with `opts`.
///
/// Each packet is unwrapped by [`crate::pipeline::apply_hep_parse`] when
/// `opts.hep_parse` is set, then routed through
/// [`crate::pipeline::process_packet`] — the same applier the live path uses —
/// rather than a second classify-and-store loop. `opts.sip_portrange` gates
/// signaling, and `no_rtp`, `no_dialog`, `rtpproxy_control` and
/// `quiet_bad_parse` apply as they do on the live path. Given the run's
/// options, an opened capture is analyzed as the same file given to `-I` with
/// the same flags; what this reader does not do is decrypt (it holds no keys)
/// or ask a relay about the media (the calls in a file ended in the past).
///
/// # Returns
///
/// A [`ReadOutcome`]: the packet count, the error that stopped the read (if
/// any), and whether it stopped before the file ended. A file that will not
/// open reports zero packets, the reason, and `stopped_early`.
///
/// An archive (`.tar`, `.tgz`, a `.pcap.gz` inside either) is read as the set
/// of captures it holds, in first-packet order, into the same two stores —
/// the resolution `-I` uses, through [`super::input_set::resolve_set`]. A
/// member that is not a capture is named in the log with its reason; one the
/// archive cut short, or a walk that stopped early, makes the read
/// `stopped_early`, because every count is then a floor.
#[must_use]
pub fn read_into_stores(
    path: &Path,
    opts: &crate::pipeline::PipelineOptions,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    progress: &AtomicU64,
) -> ReadOutcome {
    read_into_stores_until(path, opts, dialog_store, stream_store, progress, &|| None)
}

/// [`read_into_stores`], stopping before the next packet once `stop` names a
/// reason.
///
/// `stop` is asked before every packet, beside the SIGTERM check the reader
/// already makes, so a caller with its own reason to end a read (a deadline, a
/// cancel) ends it mid-file rather than after the file. A read `stop` ended
/// reports the reason as its error and `stopped_early`, exactly as a shutdown
/// does. It is asked often, so it must be cheap: an atomic load and a clock
/// read are the intended cost.
///
/// # Returns
///
/// The same [`ReadOutcome`] [`read_into_stores`] returns.
#[must_use]
pub fn read_into_stores_until(
    path: &Path,
    opts: &crate::pipeline::PipelineOptions,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    progress: &AtomicU64,
    stop: &dyn Fn() -> Option<String>,
) -> ReadOutcome {
    let holds_members = super::archive::holds_members(path);
    if !holds_members {
        return read_one(path, opts, dialog_store, stream_store, progress, stop);
    }
    let set = match super::input_set::resolve_set(
        &[path.display().to_string()],
        &super::input_set::ResolveOptions::default(),
    ) {
        Ok(set) => set,
        Err(e) => {
            return ReadOutcome {
                packets: 0,
                error: Some(format!("{e:#}")),
                stopped_early: true,
            };
        }
    };
    let mut total = ReadOutcome {
        packets: 0,
        error: None,
        stopped_early: set.incomplete(),
    };
    for input in set.iter() {
        let before = total.packets;
        let member_progress = AtomicU64::new(0);
        let one = read_one(
            &input.path,
            opts,
            dialog_store,
            stream_store,
            &member_progress,
            stop,
        );
        total.packets = before + one.packets;
        progress.store(total.packets, Ordering::Relaxed);
        total.stopped_early |= one.stopped_early;
        if one.error.is_some() {
            total.error = one.error;
            break;
        }
    }
    total
}

/// Read one capture file into the stores. See [`read_into_stores`].
fn read_one(
    path: &Path,
    opts: &crate::pipeline::PipelineOptions,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    progress: &AtomicU64,
    stop: &dyn Fn() -> Option<String>,
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
        if let Some(reason) = stop() {
            return ReadOutcome {
                packets,
                error: Some(reason),
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
                    super::archive::source_name(path)
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
        // `--hep-parse`, by the rule every packet router applies. `None` is a
        // HEP datagram whose transport no rule names, already counted. This is
        // the only unwrap: neither `process_packet` nor the classifier it calls
        // reads `opts.hep_parse`.
        let Some(parsed) = crate::pipeline::apply_hep_parse(&parsed, opts.hep_parse) else {
            continue;
        };
        // No decryption keys on this path, so no substituted plaintext.
        let mut decrypt = crate::pipeline::MediaDecrypt::default();
        crate::pipeline::process_packet(
            &parsed,
            dialog_store,
            stream_store,
            &mut rtp_heuristic,
            opts,
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
    use crate::pipeline::PipelineOptions;
    use crate::sip::dialog_store::DialogStore;

    type TestError = Box<dyn std::error::Error>;

    /// Read `bytes`, written to a temporary capture file, with `opts`.
    fn read_bytes_with(
        bytes: &[u8],
        opts: &PipelineOptions,
    ) -> Result<(ReadOutcome, Arc<RwLock<DialogStore>>), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("capture.pcap");
        std::fs::write(&path, bytes)?;
        let ds = Arc::new(RwLock::new(DialogStore::new(16, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(16)));
        let outcome = read_into_stores(&path, opts, &ds, &ss, &AtomicU64::new(0));
        Ok((outcome, ds))
    }

    /// `--hep-parse` reaches this reader. With it, a HEP copy reads as the SIP
    /// inside: the dialog carries the INNER addresses and the time the HEP
    /// header carries, not the loopback datagram's. Without it the same file
    /// holds no SIP, because the payload is a HEP header. Both directions are
    /// asserted, so the test is of the option and not of the parser.
    #[cfg(feature = "hep")]
    #[test]
    fn the_callers_hep_parse_reads_a_hep_copy_as_the_sip_inside() -> Result<(), TestError> {
        let hep_time = chrono::DateTime::from_timestamp(1_718_000_000, 250_000_000)
            .ok_or("a valid HEP time")?;
        let pcap = crate::test_utils::hep_invite_pcap("replay-hep@x", hep_time);

        let on = PipelineOptions {
            hep_parse: true,
            ..PipelineOptions::default()
        };
        let (outcome, ds) = read_bytes_with(&pcap, &on)?;
        assert_eq!(outcome.packets, 1, "the one HEP datagram is read");
        let store = ds.read();
        let dialog = store
            .get("replay-hep@x")
            .ok_or("with hep_parse the INVITE inside the HEP copy must be a dialog")?;
        assert_eq!(dialog.src_addr, std::net::IpAddr::from([10, 1, 0, 1]));
        assert_eq!(dialog.dst_addr, std::net::IpAddr::from([10, 2, 0, 1]));
        assert_eq!(dialog.src_port, 5060, "the inner source port, not 40000");
        assert_eq!(
            dialog.created_at, hep_time,
            "the HEP header's time, not the pcap record's"
        );
        drop(store);

        let (outcome, ds) = read_bytes_with(&pcap, &PipelineOptions::default())?;
        assert_eq!(outcome.packets, 1);
        assert!(
            ds.read().is_empty(),
            "without hep_parse the HEP payload stays opaque, so no dialog"
        );
        Ok(())
    }

    /// The caller's SIP port gate reaches this reader, as `--portrange` does on
    /// `-I`: a range that excludes the fixture's signaling port leaves no
    /// dialog, and no gate leaves the fixture's dialogs.
    #[test]
    #[serial_test::serial(portrange_skips)]
    fn the_callers_port_range_gates_signaling_on_this_reader() -> Result<(), TestError> {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/pcap-samples/sip-rtp-g711.pcap"),
        )?;
        let (_, open) = read_bytes_with(&bytes, &PipelineOptions::default())?;
        assert!(!open.read().is_empty(), "the fixture holds dialogs");

        let gated = PipelineOptions {
            sip_portrange: Some((5999, 5999)),
            ..PipelineOptions::default()
        };
        let (outcome, ds) = read_bytes_with(&bytes, &gated)?;
        assert!(outcome.packets > 0, "the packets are still read");
        assert!(
            ds.read().is_empty(),
            "a range that excludes 5060 must drop the signaling, as on -I"
        );
        crate::pipeline::reset_portrange_skips();
        Ok(())
    }

    /// A real capture reads into the stores and reports a clean, complete read.
    #[test]
    fn a_clean_read_fills_the_stores_and_reports_complete() -> Result<(), TestError> {
        let ds = Arc::new(RwLock::new(DialogStore::new(1000, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(1000)));
        let progress = AtomicU64::new(0);
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples/sip-rtp-g711.pcap");

        let outcome = read_into_stores(&path, &PipelineOptions::default(), &ds, &ss, &progress);

        assert!(outcome.packets > 0, "the fixture has packets");
        assert!(outcome.error.is_none(), "a readable file is not an error");
        assert!(
            !outcome.stopped_early,
            "a file read to EOF did not stop early"
        );
        assert!(!ds.read().is_empty(), "the read produced dialogs");
        Ok(())
    }

    /// A caller's stop reason ends the read before the next packet, mid-file,
    /// and is reported as the read's error with `stopped_early`.
    ///
    /// The stop is asked to fire on its fourth look, so exactly three packets
    /// are read from a fixture that holds many more: a reader that consulted
    /// it only between files would read the whole file and report no error.
    #[test]
    fn a_stop_reason_ends_the_read_before_the_next_packet() -> Result<(), TestError> {
        let ds = Arc::new(RwLock::new(DialogStore::new(1000, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(1000)));
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples/sip-rtp-g711.pcap");
        let whole = read_into_stores(
            &path,
            &PipelineOptions::default(),
            &ds,
            &ss,
            &AtomicU64::new(0),
        );
        assert!(
            whole.packets > 3,
            "the fixture holds more than three packets"
        );

        let looks = AtomicU64::new(0);
        let stop =
            || (looks.fetch_add(1, Ordering::Relaxed) >= 3).then(|| "asked to stop".to_string());
        let progress = AtomicU64::new(0);
        let outcome = read_into_stores_until(
            &path,
            &PipelineOptions::default(),
            &Arc::new(RwLock::new(DialogStore::new(1000, false))),
            &Arc::new(RwLock::new(StreamStore::new(1000))),
            &progress,
            &stop,
        );
        assert_eq!(outcome.packets, 3, "three looks passed, the fourth stopped");
        assert_eq!(progress.load(Ordering::Relaxed), 3);
        assert_eq!(outcome.error.as_deref(), Some("asked to stop"));
        assert!(outcome.stopped_early, "a stopped read is a partial read");
        Ok(())
    }

    /// A file that does not exist reports zero packets, an error, and — the bit
    /// a completeness tracker needs — that the read never covered the file.
    #[test]
    fn a_missing_file_reports_stopped_early_with_zero_packets() -> Result<(), TestError> {
        let ds = Arc::new(RwLock::new(DialogStore::new(16, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(16)));
        let progress = AtomicU64::new(0);
        let path = std::path::Path::new("/nonexistent/definitely-not-here.pcap");

        let outcome = read_into_stores(path, &PipelineOptions::default(), &ds, &ss, &progress);

        assert_eq!(outcome.packets, 0);
        assert!(outcome.error.is_some(), "an unreadable file is an error");
        assert!(
            outcome.stopped_early,
            "zero of the file was read — the most partial read there is"
        );
        Ok(())
    }

    /// An archive is read as the set it is: every capture member lands in the
    /// same stores, exactly as reading each member on its own would put it
    /// there. This is what MCP `open_capture`, `compare_captures`,
    /// `find_in_captures` and the REST compare route all read through.
    #[test]
    fn an_archive_reads_every_member_into_the_stores() -> Result<(), TestError> {
        use crate::capture::archive::tar::testutil::{Spec, build};
        use std::io::Write;
        let samples =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pcap-samples");
        let a =
            std::fs::read(samples.join("sip-rtp-g711.pcap")).map_err(|e| format!("a: {e:?}"))?;
        let b =
            std::fs::read(samples.join("sip-register.pcap")).map_err(|e| format!("b: {e:?}"))?;

        let count = |path: &std::path::Path| {
            let ds = Arc::new(RwLock::new(DialogStore::new(1000, false)));
            let ss = Arc::new(RwLock::new(StreamStore::new(1000)));
            let outcome = read_into_stores(
                path,
                &PipelineOptions::default(),
                &ds,
                &ss,
                &AtomicU64::new(0),
            );
            assert!(outcome.error.is_none(), "{:?}", outcome.error);
            (outcome.packets, ds.read().len(), ss.read().len())
        };
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        std::fs::write(dir.path().join("a.pcap"), &a).map_err(|e| format!("a: {e:?}"))?;
        std::fs::write(dir.path().join("b.pcap"), &b).map_err(|e| format!("b: {e:?}"))?;
        let (pa, da, sa) = count(&dir.path().join("a.pcap"));
        let (pb, db, sb) = count(&dir.path().join("b.pcap"));

        let tar = build(&[Spec::file("a.pcap", &a), Spec::file("b.pcap", &b)]);
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&tar).map_err(|e| format!("gzip: {e:?}"))?;
        let tgz = dir.path().join("both.tgz");
        std::fs::write(&tgz, enc.finish().map_err(|e| format!("gzip: {e:?}"))?)
            .map_err(|e| format!("tgz: {e:?}"))?;

        assert_eq!(count(&tgz), (pa + pb, da + db, sa + sb));
        Ok(())
    }

    /// A frame the capture cut short is counted as snapped on this reader too,
    /// so `open_capture`, `compare_captures` and the REST compare route report
    /// the capture quality an `-I` run of the same file reports.
    #[test]
    #[serial_test::serial(undecodable_tally)]
    fn a_snapped_frame_is_counted_on_the_replay_reader() -> Result<(), TestError> {
        crate::capture::reset_undecodable_frames();
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = dir.path().join("snapped.pcap");
        std::fs::write(&path, crate::test_utils::one_record_pcap(64, 1500))
            .map_err(|e| format!("write: {e:?}"))?;
        let ds = Arc::new(RwLock::new(DialogStore::new(16, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(16)));
        let progress = AtomicU64::new(0);

        let outcome = read_into_stores(&path, &PipelineOptions::default(), &ds, &ss, &progress);

        assert_eq!(outcome.packets, 1, "the one record is read");
        assert_eq!(
            crate::capture::snapped_frames(),
            1,
            "64 of 1500 bytes is a snapped frame"
        );
        crate::capture::reset_undecodable_frames();
        Ok(())
    }
}
