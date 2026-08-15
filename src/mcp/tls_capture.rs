// SPDX-License-Identifier: MIT OR Apache-2.0

//! The background uprobe capture behind `start_tls_capture`.
//!
//! # Why an agent may start this at all
//!
//! Every other capture on sipnab's MCP surface is a **file**: `open_capture`
//! swaps one pcap for another inside a directory an operator named. This one
//! installs kernel probes on a running process's TLS library, which is a
//! different kind of act, and it carries its own opt-in
//! (`--mcp-allow-tls-capture`) for exactly that reason.
//!
//! # The single-writer rule
//!
//! sipnab's stores have one writer (invariant 1, `docs/internals/invariants.md`).
//! A uprobe capture is a **live** writer that never finishes on its own, so it
//! may only start when the existing source has stopped for good: a file source,
//! already exhausted. `start_tls_capture` enforces that before spawning, the
//! same precondition `open_capture` uses and for the same reason.
//!
//! # Privilege
//!
//! Installing a uprobe needs root at the moment of the install, and sipnab
//! routinely drops privileges after opening its capture devices. A server that
//! has dropped cannot install probes, and the tool says so with the reason
//! rather than returning an empty capture that looks like a quiet trunk.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::{Mutex, RwLock};

use crate::capture::UprobeTarget;
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;

/// What a finished uprobe capture leaves behind for the poller.
#[derive(Debug, Clone)]
pub struct TlsCaptureOutcome {
    /// SIP messages the probes delivered and the acceptance rules kept.
    pub messages: u64,
    /// Records the kernel dropped because the reader fell behind.
    ///
    /// Reported rather than folded into the message count: these are messages
    /// that existed and are missing, which is a different fact from a quiet
    /// trunk and the only one an agent could not otherwise discover.
    pub lost: u64,
    /// Why the capture stopped, when it was not an ordinary stop.
    pub error: Option<String>,
}

/// A running uprobe capture, shared between its worker and the tool handlers.
#[derive(Debug)]
pub struct TlsCapture {
    /// Capture instance this fills, matching what `capture_status` reports.
    pub instance: String,
    /// The libraries being probed, as `path:symbol`, for progress reports.
    pub targets: Vec<String>,
    /// SIP messages delivered so far.
    pub messages: AtomicU64,
    /// Set by `stop_tls_capture` and by shutdown; the worker checks it.
    pub stop: AtomicBool,
    /// Set once the worker has finished and `outcome` holds its result.
    pub done: AtomicBool,
    /// The finished capture's counts, present once `done`.
    pub outcome: Mutex<Option<TlsCaptureOutcome>>,
    /// When the capture started, for the elapsed figure.
    pub started: std::time::Instant,
}

impl TlsCapture {
    /// A capture of `targets` filling `instance`, before the worker runs.
    fn new(targets: Vec<String>, instance: &str) -> Self {
        Self {
            instance: instance.to_string(),
            targets,
            messages: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            done: AtomicBool::new(false),
            outcome: Mutex::new(None),
            started: std::time::Instant::now(),
        }
    }

    /// A handle with no worker behind it, for tests that exercise the
    /// stop protocol without installing anything in a kernel.
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test(targets: Vec<String>, instance: &str) -> Self {
        Self::new(targets, instance)
    }

    /// Whether the worker has finished.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Ask the worker to stop. Returns once the request is recorded, not once
    /// the probes are gone — poll [`Self::finished`] for that.
    ///
    /// The probes outlive the process if it dies without removing them, which
    /// is why the worker owns them and removes them on the way out rather than
    /// this function trying to.
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Start a uprobe capture on `targets`, filling the shared stores.
///
/// # Errors
///
/// Fails only when the thread cannot be spawned. An attach that fails — no
/// permission, no tracefs, a symbol that will not resolve — is reported through
/// [`TlsCaptureOutcome::error`], because a caller that already saw the capture
/// start needs the outcome channel to learn it did not.
///
/// # Side effects
///
/// Spawns a detached OS thread named `mcp-tls-capture` which installs kernel
/// uprobes, writes both stores, and removes the probes before it exits.
pub fn spawn(
    targets: Vec<UprobeTarget>,
    instance: &str,
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
) -> std::io::Result<Arc<TlsCapture>> {
    let described = targets
        .iter()
        .map(|t| format!("{}:{}", t.library, t.symbol))
        .collect();
    let capture = Arc::new(TlsCapture::new(described, instance));
    let worker = Arc::clone(&capture);

    std::thread::Builder::new()
        .name("mcp-tls-capture".to_string())
        .spawn(move || {
            let (messages, lost, error) = run(&targets, &worker, &dialog_store, &stream_store);
            *worker.outcome.lock() = Some(TlsCaptureOutcome {
                messages,
                lost,
                error,
            });
            // Release, paired with the Acquire in `finished`: the outcome must
            // be visible to whoever sees `done`.
            worker.done.store(true, Ordering::Release);
            tracing::info!(
                "MCP start_tls_capture finished: {messages} SIP message(s), \
                 {lost} record(s) lost. Probes removed."
            );
        })?;
    Ok(capture)
}

/// Attach, drain until asked to stop, and process everything into the stores.
///
/// Returns `(messages, lost, error)`.
#[cfg(all(target_os = "linux", feature = "native"))]
fn run(
    targets: &[UprobeTarget],
    capture: &TlsCapture,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
) -> (u64, u64, Option<String>) {
    use crate::capture::uprobe::reader::{Target, UprobeReader};

    let attach: Vec<Target> = targets
        .iter()
        .map(|t| Target {
            library: std::path::PathBuf::from(&t.library),
            symbol: t.symbol.clone(),
        })
        .collect();

    let mut reader = match UprobeReader::attach_many(
        std::path::Path::new(crate::capture::uprobe::TRACEFS),
        &attach,
    ) {
        Ok(r) => r,
        Err(e) => return (0, 0, Some(format!("attach failed: {e}"))),
    };

    // Unbounded in effect: the reader hands packets over synchronously inside
    // `drain_once`, and this thread drains them immediately afterwards. A small
    // bounded channel would deadlock the very thread that must empty it.
    let (tx, rx) = crate::capture::channel::packet_channel(4096);
    let mut rtp_heuristic = crate::rtp::heuristic::RtpHeuristic::new();
    let opts = crate::pipeline::PipelineOptions::default();
    let mut messages = 0u64;

    while !capture.stop.load(Ordering::Relaxed) && !crate::signals::shutdown_requested() {
        let sent = reader.drain_once(&tx);
        for packet in rx.try_iter() {
            let parsed = match crate::capture::parse::parse_packet(&packet) {
                Ok(p) => p,
                Err(e) => {
                    crate::capture::record_undecodable(&e, crate::capture::FrameFacts::UNRECORDED);
                    continue;
                }
            };
            if parsed.payload.is_empty() {
                continue;
            }
            // These bytes arrived as plaintext already; nothing to decrypt.
            let mut decrypt = crate::pipeline::MediaDecrypt::default();
            crate::pipeline::process_packet(
                &parsed,
                dialog_store,
                stream_store,
                &mut rtp_heuristic,
                &opts,
                &mut decrypt,
            );
            messages += 1;
            capture.messages.store(messages, Ordering::Relaxed);
        }
        if sent == 0 {
            // A probe fires only when the application writes, which on a quiet
            // trunk is rarely. Sleeping beats spinning every ring.
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    let lost = reader.lost();
    // `reader` drops here: rings first, then probes, which is the only order
    // the kernel accepts.
    drop(reader);
    (messages, lost, None)
}

/// Everywhere else this is unreachable — `start_tls_capture` refuses before
/// spawning — but it must still compile, and it must not report a silent
/// success if it ever runs.
#[cfg(not(all(target_os = "linux", feature = "native")))]
fn run(
    _targets: &[UprobeTarget],
    _capture: &TlsCapture,
    _dialog_store: &Arc<RwLock<DialogStore>>,
    _stream_store: &Arc<RwLock<StreamStore>>,
) -> (u64, u64, Option<String>) {
    (
        0,
        0,
        Some(
            "uprobe capture needs Linux kernel uprobes and a sipnab built with \
             the `native` feature"
                .to_string(),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The handle must describe what it is probing before any packet arrives —
    /// an agent polls this to learn whether the capture it asked for is the one
    /// that started.
    #[test]
    fn the_handle_names_its_targets_up_front() {
        let c = TlsCapture::new(vec!["/usr/lib/libssl.so.3:SSL_write".to_string()], "cap-1");
        assert_eq!(c.instance, "cap-1");
        assert_eq!(c.targets, vec!["/usr/lib/libssl.so.3:SSL_write"]);
        assert_eq!(c.messages.load(Ordering::Relaxed), 0);
        assert!(!c.finished(), "nothing has run yet");
    }

    /// Stopping is a request, not an act: the worker owns the probes and must
    /// remove them itself, in the one order the kernel accepts.
    #[test]
    fn requesting_a_stop_is_recorded_without_claiming_the_capture_ended() {
        let c = TlsCapture::new(vec!["x:y".to_string()], "cap-2");
        c.request_stop();
        assert!(c.stop.load(Ordering::Relaxed));
        assert!(
            !c.finished(),
            "the probes are still installed until the worker removes them, and \
             reporting otherwise would have an agent believe the kernel is clean"
        );
    }
}
