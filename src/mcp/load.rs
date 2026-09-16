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
    // The previous capture's partial-read record belongs to the previous
    // capture. Carrying it forward would report a sound file as unsound for the
    // life of the process, and `open_capture` has already rotated the identity
    // every later answer carries.
    super::completeness::clear_source_stopped_early();
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

/// Read every packet of `path` into the two stores, tracking completeness.
///
/// A thin wrapper over [`crate::capture::replay::read_into_stores`], the shared
/// non-mcp reader. This layer adds the one thing that reader deliberately does
/// NOT: on a read that ended before the file did — an open failure, a shutdown,
/// or a truncated dump — it sets the MCP completeness flag, so `capture_health`
/// and every other tool can say the stores it answers from are partial (VAL2).
/// The reader stays surface-agnostic because `src/capture/` cannot depend on
/// `src/mcp/`.
///
/// # Returns
///
/// Packets read.
///
/// # Errors
///
/// The packets read before the failure, and the message. A file that will not
/// open reports zero and the reason.
pub(crate) fn read_into_stores(
    path: &Path,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    progress: &AtomicU64,
) -> Result<u64, (u64, String)> {
    let outcome =
        crate::capture::replay::read_into_stores(path, dialog_store, stream_store, progress);
    if outcome.stopped_early {
        super::completeness::note_source_stopped_early();
    }
    match outcome.error {
        Some(e) => Err((outcome.packets, e)),
        None => Ok(outcome.packets),
    }
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
