// SPDX-License-Identifier: MIT OR Apache-2.0

//! The background capture load behind `open_capture`.
//!
//! # Why this is a thread and not a task
//!
//! The REST API and the MCP server share ONE thread running one
//! `tokio::runtime::Builder::new_current_thread()` ([`crate::app::servers`]).
//! Reading a multi-gigabyte pcap inside a tool handler blocks that thread for
//! the whole read: every other MCP tool call and every REST request queues
//! behind it, and nothing catches it. `clippy::await_holding_lock` does not
//! fire, because no lock is held across an await — the handler simply never
//! yields.
//!
//! So the read runs on a plain OS thread that the runtime never waits on, and
//! the tool returns as soon as the thread starts. This is the TUI's `pcap-load`
//! design ported: a worker writing through the shared `Arc<RwLock<..>>` stores,
//! a packet counter the caller polls, and an outcome taken exactly once. What
//! differs is who polls — the TUI's event loop does it every tick, and here the
//! agent does it by calling `capture_status`.
//!
//! # The store writes
//!
//! The worker is a second writer against stores that invariant 1 gives one
//! writer (see `docs/internals/invariants.md`). Two conditions make that safe
//! and `open_capture` enforces both before spawning: the original source must
//! be a file rather than a live interface, and it must already be exhausted, so
//! the first writer has finished for good. Routing every packet through
//! [`crate::pipeline::process_packet`] keeps the per-store write locks as brief
//! here as on the live path.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::{Mutex, RwLock};

use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;

/// What a finished load leaves behind for the poller.
#[derive(Debug, Clone)]
pub struct LoadOutcome {
    /// Packets read from the file.
    pub packets: u64,
    /// Dialogs the stores hold now.
    pub dialogs: usize,
    /// RTP streams the stores hold now.
    pub streams: usize,
    /// Why the load stopped early, when it did.
    ///
    /// A partial load is still reported as done with whatever it managed to
    /// read: a truncated pcap is the normal state of a ring buffer's newest
    /// member, and discarding the dialogs already parsed out of it would lose
    /// more than the error costs.
    pub error: Option<String>,
}

/// Progress of one background load, shared between the worker and the pollers.
///
/// Every field is written by the worker and read by tool handlers, so nothing
/// here needs a lock except the outcome, which moves once.
#[derive(Debug)]
pub struct CaptureLoad {
    /// Capture instance this load fills. Identical to the id `capture_status`
    /// reports, so a poller can tell the answer belongs to the load it started.
    pub instance: String,
    /// The file being read, as the caller named it.
    pub filename: String,
    /// Packets read so far. Moves while `done` is false.
    pub packets: AtomicU64,
    /// Set once the worker has finished and `outcome` holds its result.
    pub done: AtomicBool,
    /// The finished load's counts, present once `done`.
    pub outcome: Mutex<Option<LoadOutcome>>,
    /// When the load started, for the elapsed figure.
    pub started: std::time::Instant,
}

impl CaptureLoad {
    /// A load of `filename` filling capture `instance`, before the worker runs.
    fn new(filename: &str, instance: &str) -> Self {
        Self {
            instance: instance.to_string(),
            filename: filename.to_string(),
            packets: AtomicU64::new(0),
            done: AtomicBool::new(false),
            outcome: Mutex::new(None),
            started: std::time::Instant::now(),
        }
    }

    /// Whether the worker has finished.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }
}

/// Start reading `path` into the stores on a background thread.
///
/// The caller has already rotated the capture identity and cleared the stores
/// under its own lock; this function only fills them.
///
/// # Arguments
///
/// * `path` — the capture file, already resolved inside the file root.
/// * `filename` — the bare name the caller asked for, for progress reports.
/// * `instance` — the capture-instance id this load belongs to.
/// * `dialog_store` / `stream_store` — the same shared stores every reader
///   queries, so an agent watches the dialogs appear rather than waiting for a
///   swap at the end.
/// * `source_exhausted` — the shared flag `tail_dialogs` reports. Cleared
///   before the worker starts and set when it finishes, so a poller learns the
///   new capture is complete exactly as it did for the original one.
///
/// # Returns
///
/// The progress handle, as soon as the thread is running.
///
/// # Errors
///
/// Fails only when the thread cannot be spawned. A file that cannot be opened
/// is reported through [`LoadOutcome::error`] instead, because by then the
/// stores are already cleared and the caller needs the outcome channel to say
/// so.
///
/// # Side effects
///
/// Spawns a detached OS thread named `mcp-pcap-load` which writes both stores,
/// updates the progress counter, and sets `source_exhausted` when it stops.
pub fn spawn(
    path: PathBuf,
    filename: &str,
    instance: &str,
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
    source_exhausted: Option<Arc<AtomicBool>>,
) -> std::io::Result<Arc<CaptureLoad>> {
    let load = Arc::new(CaptureLoad::new(filename, instance));
    if let Some(flag) = source_exhausted.as_ref() {
        flag.store(false, Ordering::Relaxed);
    }
    let worker = Arc::clone(&load);
    std::thread::Builder::new()
        .name("mcp-pcap-load".to_string())
        .spawn(move || {
            let result = read_into_stores(&path, &dialog_store, &stream_store, &worker.packets);
            let (packets, error) = match result {
                Ok(packets) => (packets, None),
                Err((packets, e)) => (packets, Some(e)),
            };
            let dialogs = dialog_store.read().len();
            let streams = stream_store.read().len();
            *worker.outcome.lock() = Some(LoadOutcome {
                packets,
                dialogs,
                streams,
                error,
            });
            if let Some(flag) = source_exhausted {
                flag.store(true, Ordering::Relaxed);
            }
            // Release, paired with the Acquire in `finished`: the outcome must
            // be visible to whoever sees `done`.
            worker.done.store(true, Ordering::Release);
            tracing::info!(
                "MCP open_capture finished '{}': {packets} packets, {dialogs} dialogs, \
                 {streams} streams",
                worker.filename
            );
        })?;
    Ok(load)
}

/// Read every packet of `path` into the two stores.
///
/// Routes through [`crate::pipeline::process_packet`] — the same applier the
/// live path uses — rather than a second classify-and-store loop, so an opened
/// capture is analysed exactly as an `-I` one is.
///
/// The SIP port gate is off (`sip_portrange: None`), which is what the TUI's
/// interactive open does. It is also the direction that cannot under-report:
/// `--portrange` narrows which ports count as SIP, and a capture opened here
/// is read with every port considered.
///
/// # Returns
///
/// Packets read.
///
/// # Errors
///
/// The packets read before the failure, and the message. A file that will not
/// open reports zero and the reason.
fn read_into_stores(
    path: &Path,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    progress: &AtomicU64,
) -> Result<u64, (u64, String)> {
    // The guard owns any decompressed temp file (libpcap cannot read gzip) and
    // must outlive the read loop, so keep it bound for the whole function.
    let (mut cap, _gz_guard) = match crate::capture::file::open_offline(path) {
        Ok(opened) => opened,
        Err(e) => return Err((0, format!("{e:#}"))),
    };
    let link_type = cap.get_datalink().0;
    let mut rtp_heuristic = crate::rtp::heuristic::RtpHeuristic::new();
    let opts = crate::pipeline::PipelineOptions::default();
    let mut packets = 0u64;

    loop {
        // A load must not outlive a SIGTERM. Without this a multi-gigabyte
        // read holds the process open long after the operator asked it to
        // stop, and the packets go nowhere anyone will see.
        if crate::signals::shutdown_requested() {
            return Err((packets, "shutdown requested during the load".to_string()));
        }
        let pkt = match cap.next_packet() {
            Ok(pkt) => pkt,
            Err(_) => break,
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
        let Ok(parsed) = crate::capture::parse::parse_packet(&packet) else {
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
        );
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real capture must reach the stores through the worker, not merely
    /// leave the thread running.
    #[test]
    fn a_spawned_load_fills_the_stores_and_reports_counts() {
        let dialog_store = Arc::new(RwLock::new(DialogStore::new(1000, false)));
        let stream_store = Arc::new(RwLock::new(StreamStore::new(1000)));
        let exhausted = Arc::new(AtomicBool::new(true));
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples/sip-rtp-g711.pcap");

        let load = spawn(
            path,
            "sip-rtp-g711.pcap",
            "test-instance",
            Arc::clone(&dialog_store),
            Arc::clone(&stream_store),
            Some(Arc::clone(&exhausted)),
        )
        .expect("spawn the load worker");

        // The flag must drop while the load runs, or a poller believes the new
        // capture is already complete.
        for _ in 0..400 {
            if load.finished() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(load.finished(), "the load never finished");

        let outcome = load.outcome.lock().clone().expect("an outcome");
        assert_eq!(outcome.error, None, "the fixture must load cleanly");
        assert!(outcome.packets > 0, "no packets were read");
        assert!(outcome.dialogs > 0, "no dialogs reached the store");
        assert_eq!(
            outcome.dialogs,
            dialog_store.read().len(),
            "the outcome must describe the store it filled"
        );
        assert!(
            exhausted.load(Ordering::Relaxed),
            "the source-exhausted flag must be set when the load finishes"
        );
        assert_eq!(load.instance, "test-instance");
    }

    /// A file that cannot be read reports the failure rather than a silent
    /// empty capture — the stores are already cleared by then, so "zero
    /// dialogs" and "the file was not there" must not look identical.
    #[test]
    fn a_missing_file_reports_an_error_outcome() {
        let dialog_store = Arc::new(RwLock::new(DialogStore::new(1000, false)));
        let stream_store = Arc::new(RwLock::new(StreamStore::new(1000)));
        let load = spawn(
            std::path::PathBuf::from("/nonexistent/sipnab-open-capture-test.pcap"),
            "sipnab-open-capture-test.pcap",
            "test-instance",
            dialog_store,
            stream_store,
            None,
        )
        .expect("spawn the load worker");
        for _ in 0..400 {
            if load.finished() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(load.finished(), "the load never finished");
        let outcome = load.outcome.lock().clone().expect("an outcome");
        assert!(
            outcome.error.is_some(),
            "an unreadable file must report why, got {outcome:?}"
        );
        assert_eq!(outcome.packets, 0);
    }
}
