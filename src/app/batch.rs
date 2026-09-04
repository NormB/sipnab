// SPDX-License-Identifier: MIT OR Apache-2.0

//! Batch (non-interactive) mode: the state and receive loop behind every
//! headless run (`--no-tui`, `--mcp`, replay, `--cores`).
//!
//! `BatchRunner` owns what used to be ~25 loose locals in main.rs — the
//! writer, detector engines, decryption state, counters, and companion-server
//! handles — built once in `BatchRunner::new` and consumed by the receive
//! loop. `run` is the single entry point the binary dispatches to (WS2).

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use smallvec::{SmallVec, smallvec};

use crate::capture::{self, CaptureConfig, ParsedPacket, PcapExportMode, PcapWriter};
use crate::cli::Cli;
use crate::config::Config;
use crate::output::{self, EventExecEngine, OutputOptions, ReportFormat};
use crate::process_isolation::{self, KillRequest, ScannerKillHandle};
use crate::rtp::{self, stream_store::StreamStore};
use crate::security::{
    self as sec, AlertEngine, AlertRule, DigestLeakDetector, FraudDetector, RegFloodDetector,
    ScannerDetector,
};
use crate::signals;
use crate::sip::{self, dialog_store::DialogStore, dsl::FilterExpr, matcher::SipMatcher};

#[cfg(feature = "tls")]
use crate::capture::decrypt::TlsDecryptor;
#[cfg(any(feature = "hep", feature = "tls", test))]
use crate::capture::parse::TransportProto;
#[cfg(feature = "tls")]
use crate::capture::tls;

// ── Sweep clock ────────────────────────────────────────────────────

/// Which clock drives the periodic sweep, and what "now" the sweep's
/// age-based cutoffs are measured against.
///
/// Live capture and offline replay genuinely differ, and forcing one rule on
/// both is what broke offline analysis:
///
/// * **Live** — packets arrive as they happen, so wall time *is* capture time.
///   `Instant::elapsed` paces the sweep and `Utc::now()` is the right "now".
/// * **Offline (`-I`)** — packet timestamps have no relationship to
///   `Utc::now()`. A capture recorded in 2023 and read in 2026 is three years
///   "idle" the moment it is loaded, so every sweep that fired compacted every
///   dialog down to
///   [`keep_messages_per_idle_dialog`](crate::sip::dialog_store::keep_messages_per_idle_dialog)
///   and flagged every unassociated stream as orphaned. Worse, *how many*
///   sweeps fired was decided by how long the read took: a debug build lost
///   messages a release build kept, over the same bytes and the same commit.
///   Offline the clock therefore comes from the packets themselves — the
///   timestamp of the most recent one processed — so the answer is a function
///   of the capture, not of the machine.
///
/// The capture clock is threaded through explicitly rather than kept in a
/// global: the receive loop already sees every packet's timestamp, and a
/// process-wide "current packet time" would be wrong the moment two captures
/// are analyzed at once (the parallel `--cores` path, the API server).
#[derive(Debug)]
pub(crate) enum SweepClock {
    /// Live capture: wall time.
    Live {
        /// When the last sweep ran.
        last_sweep: std::time::Instant,
    },
    /// Offline capture: the timeline recorded in the file.
    Capture {
        /// Timestamp of the most recent packet seen, or `None` before the
        /// first packet arrives.
        latest_packet: Option<chrono::DateTime<chrono::Utc>>,
        /// Capture time at which the last sweep ran. Seeded from the first
        /// packet, so the first sweep is one interval into the capture — the
        /// same offset the live path gets from starting its timer at loop
        /// entry.
        last_sweep: Option<chrono::DateTime<chrono::Utc>>,
    },
}

impl SweepClock {
    /// A clock for a run reading `offline` (`-I`) or from a live device.
    pub(crate) fn new(offline: bool) -> Self {
        if offline {
            Self::Capture {
                latest_packet: None,
                last_sweep: None,
            }
        } else {
            Self::Live {
                last_sweep: std::time::Instant::now(),
            }
        }
    }

    /// Record a packet's capture timestamp. No-op for a live run, whose clock
    /// is the wall clock.
    ///
    /// The stored value never moves backwards: captures do contain
    /// out-of-order timestamps (the replay reader skips negative deltas for
    /// the same reason), and a single reordered packet must not rewind the
    /// sweep schedule.
    pub(crate) fn observe(&mut self, ts: chrono::DateTime<chrono::Utc>) {
        if let Self::Capture { latest_packet, .. } = self
            && latest_packet.is_none_or(|latest| ts > latest)
        {
            *latest_packet = Some(ts);
        }
    }

    /// Claim a sweep if one is due, returning the "now" its age cutoffs must
    /// be measured against.
    ///
    /// Claiming and marking are one operation so the two can never disagree —
    /// a separate `is_due()` / `mark_swept()` pair invites a caller that
    /// sweeps with one instant and records another.
    ///
    /// # Side effects
    ///
    /// Advances the recorded last-sweep time when it returns `Some`.
    pub(crate) fn take_due(&mut self, interval: std::time::Duration) -> Option<CaptureNow> {
        match self {
            Self::Live { last_sweep } => {
                if last_sweep.elapsed() < interval {
                    return None;
                }
                *last_sweep = std::time::Instant::now();
                Some(CaptureNow(chrono::Utc::now()))
            }
            Self::Capture {
                latest_packet,
                last_sweep,
            } => {
                // Nothing has been read yet: there is no capture time to
                // sweep against, and nothing in the stores to sweep.
                let now = (*latest_packet)?;
                let Some(previous) = *last_sweep else {
                    // First packet: start the clock, do not sweep on it.
                    *last_sweep = Some(now);
                    return None;
                };
                let elapsed = now.signed_duration_since(previous).to_std().ok()?;
                if elapsed < interval {
                    return None;
                }
                *last_sweep = Some(now);
                Some(CaptureNow(now))
            }
        }
    }

    /// The "now" a FINAL, end-of-run sweep measures its cutoffs against: the
    /// last packet's capture timestamp offline, wall time live.
    ///
    /// [`take_due`](Self::take_due) answers "is the next periodic sweep due
    /// yet". This answers "the reading is over — what time is it". The
    /// `--cores` path needs the second question and cannot ask the first: its
    /// stores are thread-local until the workers join, so there is no merged
    /// store to sweep until every packet has been read. It sweeps once, after
    /// the merge, against this instant.
    ///
    /// Reading the clock rather than starting a new one is what keeps that
    /// sweep a function of the capture's bytes instead of of the reader's
    /// speed — the property this type exists to hold.
    ///
    /// # Returns
    ///
    /// `None` offline when no packet was ever read: there is no capture time
    /// to measure against, and an empty store has nothing to sweep.
    ///
    /// Unlike `take_due` this records nothing, so calling it does not disturb
    /// the periodic schedule.
    pub(crate) fn final_now(&self) -> Option<CaptureNow> {
        match self {
            Self::Live { .. } => Some(CaptureNow(chrono::Utc::now())),
            Self::Capture { latest_packet, .. } => latest_packet.map(CaptureNow),
        }
    }
}

/// The "now" a sweep measures its age cutoffs against: wall time for a live
/// capture, the latest packet's timestamp for an offline one.
///
/// A newtype rather than a bare `DateTime<Utc>` so a future caller cannot
/// quietly substitute `Utc::now()` where the capture clock is required — the
/// defect this whole type exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CaptureNow(chrono::DateTime<chrono::Utc>);

impl CaptureNow {
    /// The instant itself, for the store APIs that take a plain timestamp.
    pub(crate) fn get(self) -> chrono::DateTime<chrono::Utc> {
        self.0
    }
}

// ── Bundled parameter structs ──────────────────────────────────────

/// Security detection engines bundle.
struct DetectionEngines {
    /// UA/behavioral SIP-scanner detector (`--kill-scanner`).
    scanner: Option<ScannerDetector>,
    /// Toll-fraud pattern detector (`--fraud-detect`).
    fraud: Option<FraudDetector>,
    /// Digest-authentication credential-leak detector (`--digest-leak`).
    digest: Option<DigestLeakDetector>,
    /// REGISTER-flood detector (`--reg-flood`).
    reg_flood: Option<RegFloodDetector>,
    /// Shared with the MCP server (when --mcp is on) so the
    /// `security_findings` tool can read the FindingsHistory ring buffer.
    alerts: Arc<RwLock<AlertEngine>>,
    /// Channel to the isolated scanner-kill worker thread; `None` when no
    /// kill feature is active (or the worker failed to spawn).
    kill_handle: Option<ScannerKillHandle>,
    /// SIP status code sent in kill responses (`--kill-response`).
    kill_response_code: u16,
    /// Targeted-kill directives (`-K` / `--kill-target`): any SIP request whose
    /// source matches is killed regardless of UA/behavioral detection.
    kill_targets: Vec<sec::scanner_kill::KillTarget>,
}

impl DetectionEngines {
    /// The rule names this run can actually file a finding under, sorted.
    ///
    /// Read from the detectors themselves rather than from the flags that built
    /// them, because the flags are not the arming condition: `-K/--kill-target`
    /// files `scanner` findings with no `ScannerDetector` present, and
    /// `--fraud-detect` is one of several inputs to `build_fraud_detector`. A
    /// list derived from flags would be a second opinion about what is armed,
    /// and the MCP `security_findings` tool would report it as fact.
    ///
    /// Every name here is one of
    /// [`crate::mcp::server::SECURITY_FINDING_KINDS`], pinned by
    /// `security_findings_kinds_match_the_names_the_detectors_file_under`.
    fn armed_kinds(&self) -> Vec<&'static str> {
        let mut armed = Vec::new();
        if self.scanner.is_some() || !self.kill_targets.is_empty() {
            armed.push("scanner");
        }
        if self.fraud.is_some() {
            armed.push("fraud");
        }
        if self.digest.is_some() {
            armed.push("digest");
        }
        if self.reg_flood.is_some() {
            armed.push("reg_flood");
        }
        armed.sort_unstable();
        armed
    }
}

/// Packet processing counters and state.
struct PacketCounters {
    /// Total SIP messages classified so far.
    sip_count: u64,
    /// Total RTP packets classified so far.
    rtp_count: u64,
    /// Timestamp of the previously emitted SIP message, for `--delta-time`.
    prev_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// Remaining trailing-context (`-A`) budget; re-armed by each direct match.
    trailing_remaining: usize,
    /// Call-IDs of dialogs "armed" by a `-e` payload match. Once a dialog is
    /// armed, every subsequent message of it is emitted (dialog-following).
    followed_dialogs: std::collections::HashSet<String>,
    /// Completed RFC 4733 telephone-event (DTMF) digits decoded so far
    /// (`--telephone-event`).
    dtmf_count: u64,
}

/// Owned batch-mode processing components, built by the binary's
/// bootstrap and handed to `run`.
pub struct BatchProcessing {
    /// Header-level SIP matcher (`-m`, `--method`, ...).
    pub matcher: SipMatcher,
    /// Compiled `--filter` DSL expression, when given.
    pub filter_expr: Option<FilterExpr>,
    /// Compiled `--export-vcon-when` expression, resolved by the plan.
    pub vcon_filter_expr: Option<FilterExpr>,
    /// Per-message output formatting options.
    pub output_opts: OutputOptions,
    /// `--on-*` event execution engine.
    pub event_exec: EventExecEngine,
    /// Every capture file the run reads, resolved and in read order; empty for
    /// live and HEP sources.
    ///
    /// Carried rather than re-derived from `cli`, because `cli.primary_input()`
    /// returns the first `-I` ARGUMENT — which chronological reordering often
    /// makes not the first file read, and which for `-I /pcaps` is a directory
    /// (#48).
    pub input_files: Vec<PathBuf>,
    /// What the relay said it was holding when sipnab started (RE4); empty
    /// unless `--rtpengine-control` was given on a live run.
    ///
    /// Carried from `Launched` for the same reason `keylog_source` is: it was
    /// obtained before the capture opened, and it cannot be obtained again
    /// here -- asking a second time would be the periodic behavior RE4 exists
    /// not to have.
    pub relay: crate::app::bootstrap::RelayControl,
    /// Streaming keylog source opened in the privileged window — a FIFO named
    /// by `--keylog`, or the descriptor given to `--keylog-fd`.
    ///
    /// Carried from `Launched` rather than opened here, because by the time
    /// this runs the process may have chrooted and dropped to an unprivileged
    /// user, and the producer's pipe usually lives where it can no longer
    /// reach.
    #[cfg(feature = "tls")]
    pub keylog_source: Option<crate::capture::keylog_source::KeylogSource>,
}

/// Immutable batch-mode configuration for packet processing.
struct BatchContext<'a> {
    /// Header-level SIP matcher (`-m`, `--method`, ...).
    matcher: &'a SipMatcher,
    /// Compiled `--filter` DSL expression, when given.
    filter_expr: &'a Option<FilterExpr>,
    /// Per-message output formatting options.
    output_opts: &'a OutputOptions,
    /// Full parsed CLI, consulted for the many per-message flags.
    cli: &'a Cli,
    /// Skip all RTP processing (`--no-rtp` or config equivalent).
    no_rtp: bool,
    /// Trailing-context budget granted per direct match (`-A N`).
    after_count: usize,
    /// SIP signaling port range; RTP is never gated by it.
    portrange: (u16, u16),
}

/// Mutable processing state for the main receive loop.
struct ProcessingState<'a> {
    /// Dialog store (already write-locked by the caller).
    dialog_store: &'a mut DialogStore,
    /// RTP stream store (already write-locked by the caller).
    stream_store: &'a mut StreamStore,
    /// Heuristic RTP detector for streams with no SDP linkage.
    rtp_heuristic: &'a mut rtp::heuristic::RtpHeuristic,
    /// `--on-*` event execution engine (dialog + quality events).
    event_exec: &'a mut EventExecEngine,
    /// SRTP decryption context (keys from `--srtp-keys` + SDES `a=crypto`),
    /// used to authenticate and decrypt RTP payloads before media analysis.
    #[cfg(feature = "tls")]
    srtp: Option<&'a mut crate::rtp::srtp::SrtpContext>,
    /// DTLS-SRTP extractor (`--dtls-keylog`): recovers SRTP keys from observed
    /// DTLS handshakes and feeds them into `srtp`.
    #[cfg(feature = "tls")]
    dtls: Option<&'a mut crate::capture::dtls::DtlsSrtpExtractor>,
    /// `--group-by` buffer. `Some` reroutes per-message output into it so the
    /// capture can be replayed grouped at the end; `None` keeps the ordinary
    /// streaming path, including the allocation-free `--json` fast path.
    group: Option<&'a mut output::group::GroupBuffer>,
}

// ── Deferred side effects ──────────────────────────────────────────

/// Everything one packet wants to do to the world outside the two store write
/// locks, held until those locks are released.
///
/// The receive loop takes the dialog store's write lock and the stream store's
/// write lock together, for the whole of a packet's processing. That much is
/// forced: classification reads both, and a message that creates a dialog also
/// links the SDP endpoints its media will arrive on. What is *not* forced is
/// what used to run in there with them:
///
/// * `--on-dialog-exec` / `--on-quality-exec` reached
///   `Command::new("sh").spawn()` — a real `fork`/`exec`, hundreds of
///   microseconds, against a per-packet budget of hundreds of nanoseconds.
///   Every reader of either store waited for the kernel to build a process
///   image.
/// * every `AlertEngine::fire` took a THIRD lock under the two, and reached a
///   second `spawn` inside it.
/// * per-message output went straight at the stdout sink, so a buffer fill put
///   a `write(2)` in there too.
///
/// None of the three needs either store: they need bytes that were already
/// read out of it. So the locked section now produces those bytes and this
/// type carries them out, where [`Self::drain`] replays them. The stores are
/// still updated under the locks — only the side effects moved.
///
/// One instance is reused for the whole run, so the buffers reach their
/// high-water mark once instead of being allocated per packet.
struct DeferredEffects {
    /// Bytes bound for the per-message output sink.
    out: DeferredOutput,
    /// Alert firings, in the order they were raised.
    alerts: Vec<DeferredAlert>,
    /// Where `--evidence-out` publishes findings, when the operator asked for
    /// it. Opened once when the run starts, so a bad path fails then and not
    /// an hour into a capture.
    evidence: Option<sec::evidence::EvidenceSink>,
}

/// One `AlertEngine::fire` call raised while the store guards were held.
///
/// Every field is owned or `Copy`, so nothing here borrows the store the
/// detector read — which is what lets the call, and the `sh -c` spawn inside
/// it, happen after the guards drop.
struct DeferredAlert {
    /// Rule name the finding is filed under (`"scanner"`, `"fraud"`, …).
    kind: &'static str,
    /// Source address the finding is about.
    src_ip: std::net::IpAddr,
    /// Human-readable detail line, already formatted and owned.
    detail: String,
    /// CAPTURE time of the event, which every threshold and cooldown in the
    /// alert engine is measured against. Taken from the packet, so deferring
    /// the call cannot move it — a replay still gives the same answer as
    /// watching it live.
    at: chrono::DateTime<chrono::Utc>,
}

/// The output one packet produces, composed under the store guards and handed
/// to the real sink once they drop.
///
/// Deliberately shaped like the slice of [`output::BatchSink`] the emitters
/// use (`write_str`, `write_fmt`, `writer`, `record`, `end_message`), so the
/// call sites read the same and the bytes are the same bytes in the same
/// order. The only difference is where they land first.
struct DeferredOutput {
    /// Emitted bytes, in emission order.
    ///
    /// Reused across packets. That is what keeps the `--json` path
    /// allocation-free after the write moved off the sink: `write_message_json`
    /// still serializes straight into a buffer with no per-message `String`,
    /// and the buffer stops growing once it has seen the largest message.
    bytes: Vec<u8>,
    /// First non-`BrokenPipe` error raised by a serializer writing into
    /// `bytes`. Handed to the sink at drain time rather than dropped, so a
    /// serialization failure still decides the run's exit code.
    hard_error: Option<std::io::Error>,
    /// `--line-buffer` message boundaries crossed while the guards were held.
    ///
    /// Replayed against the sink at drain time, so one flush per message is
    /// still one flush per message rather than one per packet.
    message_ends: usize,
}

impl DeferredOutput {
    /// An empty buffer.
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            hard_error: None,
            message_ends: 0,
        }
    }

    /// Record `r` unless it succeeded or failed with `BrokenPipe`, keeping the
    /// first — the same rule, and for the same reason, as
    /// [`output::BatchSink::record`].
    fn record(&mut self, r: std::io::Result<()>) {
        if let Err(e) = r
            && e.kind() != std::io::ErrorKind::BrokenPipe
            && self.hard_error.is_none()
        {
            self.hard_error = Some(e);
        }
    }

    /// Append a string.
    fn write_str(&mut self, s: &str) {
        self.bytes.extend_from_slice(s.as_bytes());
    }

    /// Append formatted output (enables `write!(out, ...)`).
    fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) {
        let r = std::io::Write::write_fmt(&mut self.bytes, args);
        self.record(r);
    }

    /// Direct access to the byte buffer, for the zero-copy serializers that
    /// took [`output::BatchSink::writer`]. Errors bypass this type's tracking,
    /// so callers feed the result back through [`Self::record`].
    fn writer(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    /// Mark the end of one message. The flush it may imply happens at drain
    /// time, since flushing a buffer the sink has not been given yet would
    /// write nothing.
    fn end_message(&mut self) {
        self.message_ends += 1;
    }

    /// Hand this packet's bytes to `sink` and reset for the next packet.
    ///
    /// One `write_all` per packet rather than one per emitter. The sink's own
    /// 64 KiB buffering is untouched, so the syscall count downstream is what
    /// it always was and the bytes are byte-identical to what the emitters
    /// used to write directly.
    fn drain_into<W: std::io::Write>(&mut self, sink: &mut output::BatchSink<W>) {
        // Fed first: it happened before any of the bytes could reach the sink,
        // and the sink keeps the FIRST error it is told about.
        if let Some(e) = self.hard_error.take() {
            sink.record(Err(e));
        }
        if !self.bytes.is_empty() {
            let r = sink.writer().write_all(&self.bytes);
            sink.record(r);
            self.bytes.clear();
        }
        for _ in 0..self.message_ends {
            sink.end_message();
        }
        self.message_ends = 0;
    }
}

impl DeferredEffects {
    /// An empty set of effects.
    fn new() -> Self {
        Self {
            out: DeferredOutput::new(),
            alerts: Vec::new(),
            evidence: None,
        }
    }

    /// Replay everything the packet queued, now that both store guards have
    /// dropped. The single place the deferred work is performed.
    ///
    /// Output first: stdout is the run's primary evidence stream, and reaching
    /// the sink is what makes it real. The alert firings follow, each taking
    /// and releasing the alert lock on its own — exactly as the five call sites
    /// used to, so the findings history and the `--alert-exec` budgets see the
    /// same sequence of calls with the same capture timestamps. The `--on-*`
    /// hook commands go last. None of the three is nested under a store lock
    /// any more, which is the whole point: the alert engine was a third lock in
    /// that stack with no written ordering rule, and a `sh -c` spawn ran with
    /// all three held.
    ///
    /// # Arguments
    ///
    /// * `sink` — the buffered stdout sink the queued bytes belong to.
    /// * `alerts` — the shared alert engine, locked once per queued finding.
    /// * `event_exec` — the hook engine holding this packet's decided-but-
    ///   unspawned commands. Passed in rather than queued here because the
    ///   requests were built from a dialog or a stream and the engine that
    ///   decided them also owns the rate limit and child list that bound them.
    ///
    /// # Side effects
    ///
    /// Writes to `sink` and may flush it (`--line-buffer`); takes the alert
    /// engine's write lock once per queued alert and through it may write to
    /// stderr and syslog and spawn `--alert-exec` children; and spawns the
    /// queued `--on-dialog-exec` / `--on-quality-exec` children. Every process
    /// this run
    /// creates from the packet path is created here.
    fn drain<W: std::io::Write>(
        &mut self,
        sink: &mut output::BatchSink<W>,
        alerts: &Arc<RwLock<AlertEngine>>,
        event_exec: &mut EventExecEngine,
    ) {
        self.out.drain_into(sink);
        for alert in self.alerts.drain(..) {
            alerts
                .write()
                .fire(alert.kind, alert.src_ip, &alert.detail, alert.at);
        }
        event_exec.dispatch_pending();
    }
}

/// Resolve the pcap file a `--tshark-filter` / `--wireshark` command should
/// reference. Precedence: the input file (`-I`, offline analysis), then the
/// file the live capture was written to (`-O`).
///
/// # Errors
///
/// Returns a message when neither is set: a live capture that saves no pcap
/// leaves nothing for `tshark -r` to read, so emitting a placeholder path
/// (the old `capture.pcap`) would only produce a command that fails.
/// # A multi-file set is REFUSED, not partly served
///
/// `tshark -r` takes one file. Given a set, the old code emitted the first `-I`
/// ARGUMENT and a `-Y` filter naming every Call-ID sipnab had found — including
/// Call-IDs that exist only in the files that command never opens. Measured:
/// `-I sip-rtp-g711.pcap -I sip-register.pcap --wireshark` printed a command
/// reading only the first, whose filter named three Call-IDs, the first of
/// which lives only in the second file. Pasted into a terminal it returns a
/// strict subset of what sipnab just reported, with nothing saying so, exit 0.
///
/// A command covering half the evidence is worse than no command, because the
/// operator has no way to tell which half. So this refuses and names every
/// file, the same call `--strip-secrets` already makes for the same reason.
fn tshark_input_file(files: &[PathBuf], output: Option<&str>) -> Result<String, String> {
    match files {
        [] => output.map(str::to_string).ok_or_else(|| {
            "no pcap to read: pass -I <file> to analyze a capture file, or -O <file> \
             to save the live capture so tshark has a file to read"
                .to_string()
        }),
        [one] => Ok(one.display().to_string()),
        many => Err(format!(
            "the input is {} files and `tshark -r` reads one, so no single \
             command covers this run. The display filter below names Call-IDs \
             from all of them; a command reading only one would silently return \
             a subset. Files: {}",
            many.len(),
            many.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Capture split/stop policy resolved from the CLI.
pub struct CapturePolicy {
    /// Rotate the output file after this many bytes (`--split-size`).
    pub split_bytes: Option<u64>,
    /// Rotate the output file after this duration (`--split-time`).
    pub split_duration: Option<std::time::Duration>,
    /// Keep only the newest N split files, deleting the rest (`--split-keep`).
    ///
    /// `None` — the default, and what `--split-keep 0` resolves to — keeps
    /// every file. Nothing this run wrote is deleted unless an operator asked
    /// for a ring buffer in so many words.
    pub split_keep: Option<u32>,
    /// Stop capturing after this duration (`--autostop duration:N`).
    pub autostop_duration: Option<std::time::Duration>,
    /// Stop after the output file reaches this many BYTES
    /// (`--autostop filesize:N`, N mebibytes).
    ///
    /// Bytes, matching `split_bytes` above: both are compared against
    /// `PcapWriter::bytes_written`, and the megabyte figure this used to hold
    /// left the comparison site converting — with a different multiplier than
    /// `--split filesize` used for the same word.
    pub autostop_filesize_bytes: Option<u64>,
    /// SIP signaling port range (`--portrange`); media is never gated.
    pub portrange: (u16, u16),
}

/// Build the `ParallelConfig` shared by both offline multi-core paths
/// (`run_cores_file` and the `--cores N` arm of `run`) from the CLI, config,
/// resolved port range, and `no_rtp` decision — keeping the two call sites in
/// lockstep instead of duplicating the field-by-field construction.
fn parallel_config(
    cli: &Cli,
    config: &Config,
    portrange: (u16, u16),
    no_rtp: bool,
) -> crate::parallel::ParallelConfig {
    crate::parallel::ParallelConfig {
        cores: cli.limits_args.cores,
        max_streams: cli.max_streams_limit(config),
        max_dialogs: cli.dialog_limit(config),
        rotate: cli.rotate_enabled(),
        max_reassembly: cli.max_reassembly_limit(config),
        portrange,
        no_dialog: cli.dialog_args.no_dialog,
        dialog_tracking: cli.dialog_args.dialog_track.unwrap_or_default(),
        no_rtp,
        quiet_bad_parse: cli.capture_args.quiet_bad_parse,
        xcid_headers: config.sip.xcid_headers.clone().unwrap_or_default(),
        leg_correlation_window_ms: cli.leg_correlation_window_ms(config),
        retain_audio: audio_retention_wanted(cli),
        max_audio_frames: config.limits.max_audio_frames.unwrap_or(1500) as usize,
        reassembly: !cli.capture_args.no_reassembly,
        parse_limit: cli.capture_args.limitlen,
    }
}

/// Spawn the scanner-kill worker with this run's transmit ceiling.
///
/// A function rather than an inline `match` so the ceiling is provably applied:
/// the worker reads `None` as "use your own default", so the wiring is
/// invisible from the call site and the unit test below drives this instead.
///
/// # Side effects
///
/// Starts a thread that TRANSMITS UDP. Requires a `TransmitPermit`, which only
/// a live source can produce.
fn spawn_kill_worker(
    cli: &Cli,
    config: &Config,
    raw_kill_sock: Option<crate::process_isolation::RawKillSocket>,
    permit: crate::security::transmit_guard::TransmitPermit,
) -> Option<ScannerKillHandle> {
    let rate = cli.kill_rate_limit(config);
    match process_isolation::spawn_scanner_kill_worker(Some(rate), raw_kill_sock, permit) {
        Ok(handle) => Some(handle),
        Err(e) => {
            tracing::error!("Failed to spawn scanner-kill worker: {e}");
            None
        }
    }
}

/// Build the fraud detector this run will use, if it asked for one.
///
/// Both operator inputs the detector takes arrive here: the declared business
/// hours, without which the off-hours detection has no "outside" to test
/// against and cannot fire at all, and the four trigger points. The detector
/// used to be constructed as `FraudDetector::new(None)`, so it shipped with
/// its own constants and one whole detection unreachable.
fn build_fraud_detector(cli: &Cli, config: &Config) -> Option<FraudDetector> {
    if !(cli.security_args.fraud_detect || config.security.fraud_detect.unwrap_or(false)) {
        return None;
    }
    // Already refused by `Cli::validate` and `SecurityConfig::validate`, so
    // reaching the error arm means a caller skipped both. Say so rather than
    // running a detector that is quietly missing a detection.
    let business_hours = cli.business_hours(config).unwrap_or_else(|e| {
        tracing::error!("{e}; off-hours fraud detection is OFF for this run");
        None
    });
    let mut watch = cli.fraud_destinations();
    if watch.is_empty() {
        watch = crate::cli::parse_destination_list(
            config.security.fraud_destination.as_deref().unwrap_or(""),
        );
    }
    Some(
        FraudDetector::with_thresholds(business_hours, cli.fraud_thresholds(config))
            .with_destination_watch(crate::security::destination::DialPlan::common(), watch),
    )
}

/// Whether a `--fail2ban` run has nothing armed that could ever write a jail
/// line, so the operator should be told at startup that the log will stay
/// empty by design.
///
/// Three sites write a jail line, each behind its own producer: a scanner
/// detection (`--kill-scanner` / `--kill-ua`), a `-K`/`--kill-target` match,
/// and a registration flood (`--reg-flood`). The warning is right only when
/// all three are absent. It used to read the scanner detector alone, so
/// `-d eth0 --reg-flood --fail2ban -N` announced "this run will emit nothing"
/// and then wrote `reg_flood src=` lines into the log it had just called
/// empty -- the exact false claim the warning exists to prevent, pointed the
/// other way.
///
/// A function of three booleans rather than of the detectors themselves, so
/// every combination is a unit test and the rule cannot be re-derived from
/// the flags at the call site.
///
/// # Arguments
///
/// * `scanner` — a scanner detector is armed.
/// * `kill_target` — at least one `-K`/`--kill-target` directive was given.
/// * `reg_flood` — a registration-flood detector is armed.
///
/// # Returns
///
/// `true` when no jail line can be written by this run.
fn fail2ban_would_emit_nothing(scanner: bool, kill_target: bool, reg_flood: bool) -> bool {
    !scanner && !kill_target && !reg_flood
}

/// Build the alert engine with every operator-set budget applied.
///
/// A function rather than four statements inline, so the budgets are testable
/// as a unit: both of them are `set_*` calls on an engine that works perfectly
/// well without them, which is precisely the shape that goes missing.
fn build_alert_engine(
    cli: &Cli,
    config: &Config,
    rules: Vec<AlertRule>,
    exec_cmd: Option<String>,
) -> AlertEngine {
    let mut engine = AlertEngine::new(rules, exec_cmd);
    // Without this the global budget sits at its default and --exec-rate-limit
    // is silently inert on the alert path -- the same shape as #35, #55, #63
    // and #83, where a flag parsed, validated, and did nothing.
    engine.set_exec_rate_limit(cli.exec_args.exec_rate_limit);
    // Same shape: the ring buffer sat at its compiled-in depth and
    // `set_findings_capacity` was reachable only from the module's own tests,
    // so an operator polling `security_findings` on a busy registrar silently
    // lost the oldest detections at 1000 with no way to ask for more.
    engine.set_findings_capacity(cli.findings_history(config));
    engine
}

/// Run the conformance linter over every dialog and print the findings.
///
/// # Returns
///
/// `true` when a finding reached `--lint-fail-on`, i.e. the caller must exit 3.
///
/// # Why this is a function and not two copies
///
/// Both the batch path and `--cores` need it, and this tree has been bitten
/// repeatedly by one input getting two answers depending on which path read it
/// — the BPF refusal, the sweep, the range-overlap warning. A linter that
/// reported different findings under `--cores` would be the same defect with a
/// worse blast radius, because the whole point of the gate is that its verdict
/// is trustworthy.
fn run_lint_stage(cli: &Cli, config: &Config, ds: &crate::sip::dialog_store::DialogStore) -> bool {
    if !cli.output_args.lint {
        return false;
    }
    let threshold = cli
        .output_args
        .lint_fail_on
        .as_deref()
        .and_then(crate::sip::lint::Severity::from_name);

    let suppressions = match lint_suppressions(cli) {
        Ok(file) => file,
        Err(reason) => {
            eprintln!("{reason}");
            // The invocation was wrong, which is exit 2. Not 3: a pipeline has
            // to tell "this capture is non-conformant" apart from "sipnab was
            // asked to read a file that is not there", and only the first is a
            // fact about the traffic.
            std::process::exit(2);
        }
    };

    let mut lint_config =
        crate::sip::lint::LintConfig::new().with_max_per_rule(cli.lint_max_per_rule(config));
    if let Some(file) = &suppressions {
        lint_config = lint_config.with_suppression_file(file);
    }
    let linter = crate::sip::lint::Linter::new(lint_config);

    let mut total = 0usize;
    let mut tripped = false;
    let mut withheld = crate::sip::lint::WithheldCounts::default();
    for dialog in ds.iter() {
        let outcome = linter.lint_dialog_detailed(dialog);
        withheld.suppressed += outcome.withheld.suppressed;
        withheld.below_severity += outcome.withheld.below_severity;
        withheld.capped += outcome.withheld.capped;
        for f in outcome.findings {
            total += 1;
            if threshold.is_some_and(|t| f.severity >= t) {
                tripped = true;
            }
            println!(
                "{}: {} [{}] {} (RFC {} §{}) observed={} expected={}",
                f.severity.as_str(),
                f.rule_id,
                dialog.call_id,
                f.explanation,
                f.rfc,
                f.section,
                f.observed,
                f.expected,
            );
        }
    }
    let dialogs = ds.len();
    // Name the denominator: "0 findings" over 0 dialogs and over 900 are
    // different answers and only one is good news.
    eprintln!("Lint: {total} finding(s) across {dialogs} dialog(s)");
    // Suppression never hides itself, on this surface as on the MCP one. A
    // short finding list has to say why it is short, and "which file" is the
    // actionable half: discovery may have climbed several directories to reach
    // a `.sipnablint` nobody on this pipeline knew about.
    if let Some(file) = &suppressions {
        eprintln!(
            "Lint: suppressions from {} ({} pattern(s)), {} finding(s) silenced",
            file.path().display(),
            file.patterns().len(),
            withheld.suppressed,
        );
    }
    if withheld.capped > 0 {
        eprintln!(
            "Lint: {} finding(s) dropped by the per-rule cap of {}",
            withheld.capped,
            cli.lint_max_per_rule(config),
        );
    }
    tripped
}

/// The `.sipnablint` governing this run, named or discovered, or nothing.
///
/// `--lint-no-suppress` wins over both. Otherwise `--lint-suppress-file` wins
/// over discovery, and discovery starts at the directory holding the FIRST
/// `-I` argument — the same directory the MCP tools walk up from, so the two
/// surfaces read the same file for the same capture.
///
/// Live capture has no such directory, so nothing is discovered there. A
/// `-I` naming a directory or a glob is used as given when it is itself a
/// directory, and by its parent otherwise: `--lint-suppress-file` is the way
/// to be explicit about a layout this cannot guess.
///
/// # Errors
///
/// Returns a ready-to-print reason when a file that was named, or was found on
/// disk, cannot be read.
fn lint_suppressions(cli: &Cli) -> Result<Option<crate::sip::lint::SuppressionFile>, String> {
    if cli.output_args.lint_no_suppress {
        return Ok(None);
    }
    let explicit = cli.output_args.lint_suppress_file.as_deref();
    let dir = cli.capture_args.input.first().map(|first| {
        let path = std::path::Path::new(first);
        if path.is_dir() {
            path.to_path_buf()
        } else {
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map_or_else(
                    || std::path::PathBuf::from("."),
                    std::path::Path::to_path_buf,
                )
        }
    });
    crate::sip::lint::SuppressionFile::resolve(explicit, dir.as_deref()).map_err(|e| match explicit
    {
        Some(name) => format!("cannot read suppression file '{name}': {e}"),
        None => format!("cannot read the discovered .sipnablint: {e}"),
    })
}

/// Multi-core offline file reconstruction (`--cores N` with `-I`, single
/// device): read the capture files directly and shard packets across N worker
/// threads, fusing read+peek+shard into one stage — no capture reader
/// thread, no semaphore channel. Reports and exits; advanced per-message
/// features use the single-threaded path.
///
/// # Arguments
///
/// * `cli` — parsed flags; `cli.limits_args.cores` gives the worker count.
/// * `config` — loaded configuration for `no_rtp` / X-CID fallbacks.
/// * `capture_config` — capture parameters forwarded to the file reader.
/// * `portrange` — SIP signaling port range for classification.
/// * `paths` — the RESOLVED capture files, in read order, taken from
///   `RunPlan::source`.
///
///   Not re-derived from `cli` here. `-I` accepts a directory, a glob and
///   repeated occurrences, and `cli.primary_input()` returns the first `-I`
///   *argument* — which for `-I /pcaps` is a directory. Handing that to the
///   pcap opener made `--cores` open a directory as a capture and report
///   nothing at all: 18948 dialogs without `--cores`, 0 with `--cores 4`, exit
///   code 0, no error. `bootstrap::plan` has already resolved and
///   timestamp-ordered the set, and resolution opens every file to order it —
///   so re-resolving here would pay that cost twice and give the two paths a
///   second chance to disagree.
/// * `filter` — the compiled `--filter` expression, or `None`. This path emits
///   no per-message stream, so the reports are the only output there is: an
///   unfiltered report here means `--filter` did nothing at all under
///   `--cores`.
///
/// # Side effects
///
/// Spawns N worker threads inside `run_offline_parallel_file`, prints the
/// post-capture reports and summary to stdout/stderr, and exits the
/// process with code 1 when reconstruction fails.
pub fn run_cores_file(
    cli: &Cli,
    config: &Config,
    capture_config: &CaptureConfig,
    portrange: (u16, u16),
    paths: &[PathBuf],
    filter: Option<&FilterExpr>,
    vcon_filter: Option<&FilterExpr>,
) {
    if paths.is_empty() {
        // Unreachable through `main`: `RunMode::CoresFile` requires `-I`, and
        // `input_set::resolve` already failed the run if nothing resolved. Say
        // so loudly anyway rather than exiting 0 with an empty report, which is
        // precisely the failure this path used to have.
        tracing::error!("--cores: no capture files to read");
        std::process::exit(1);
    }
    let no_rtp = cli.capture_args.no_rtp || config.capture.no_rtp.unwrap_or(false);
    let pcfg = parallel_config(cli, config, portrange, no_rtp);
    match crate::parallel::run_offline_parallel_file(paths, capture_config, pcfg) {
        Ok(r) => {
            // The return value is the "report could not be produced" signal and
            // was dropped here, so an unknown --call-report id or an unwritable
            // stdout exited 0 on the --cores path while exiting 1 elsewhere.
            // No companion server runs on the --cores path, so there is no
            // gate anyone could have moved and the command line governs.
            let reports_ok = generate_reports(
                cli,
                &r.dialog_store,
                &r.stream_store,
                filter,
                vcon_filter,
                r.total_count,
                None,
            );
            if !cli.mode_args.quiet {
                tracing::info!(
                    "sipnab: {} packets, {} SIP messages, {} RTP packets across {} streams ({} cores)",
                    r.total_count,
                    r.sip_count,
                    r.rtp_count,
                    r.stream_store.len(),
                    cli.limits_args.cores,
                );
                report_undecodable(r.total_count);
                report_icmp_summary(&r.stream_store);
                report_impossible_rates(&r.stream_store);
                report_retention_losses(&r.dialog_store);
                report_capture_quality();
                report_llmnr_summary();
            }
            // Same linter, same catalog, same exit code as the batch path.
            // Wired here because a gate that silently passes under `--cores` is
            // worse than no gate: a pipeline adding `--cores 8` for speed would
            // stop failing on non-conformant captures and nothing would say so
            // (#147).
            let lint_tripped = run_lint_stage(cli, config, &r.dialog_store);
            // Same rule as the batch path, for the same reason a gate that
            // silently passes under `--cores` is worse than no gate: a
            // truncated member of the set or a `--plugin` that would not load
            // must not exit 0 here while exiting 1 there. Both readers record
            // through the one `ReadTally::report`, so the two paths cannot
            // reach different verdicts about the same file set.
            if !reports_ok || crate::output::run_integrity::run_failed() {
                std::process::exit(1);
            }
            if lint_tripped {
                std::process::exit(3);
            }
        }
        Err(e) => {
            tracing::error!("multi-core reconstruction failed: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Whether this run should retain RTP payload bytes.
///
/// Retention costs a per-packet payload clone, so it stays off unless
/// something in *this* run can read the buffers back AND the operator asked
/// for it. Batch reporting cannot read them. The MCP server can — its
/// `export_audio` tool decodes exactly these buffers — but "can read" stopped
/// being the whole condition: call audio is content, not signaling, and
/// holding it in memory for every MCP session whether or not anything will
/// ever export it made a privacy decision on the operator's behalf. The
/// consent half is `--retain-audio`, which clap ties to `--mcp` so the
/// wasteful combination (retain with no reader) is unrepresentable rather
/// than silently ignored.
///
/// Both conjuncts stay in the predicate even though clap enforces the
/// implication: the `&&` is what makes this function true on its own terms,
/// not true-by-way-of-a-parser-constraint someone can relax later without
/// looking here.
///
/// The TUI keeps its own retention decision in `tui_mode.rs`, which is why its
/// F2 WAV export always worked against the same decoder.
pub(crate) fn audio_retention_wanted(cli: &Cli) -> bool {
    cli.mcp_args.mcp && cli.mcp_args.retain_audio
}

/// Arm the store's retention from that decision, and report what was decided.
///
/// One function rather than an `if` at the construction site, because the site
/// had exactly the bug that shape invites: `if audio_retention_wanted(&cli) {
/// ss.set_audio_capture(true); ... }` with no `else`. `StreamStore::new` arms
/// retention by default — correctly, for the TUI, whose stream-detail view
/// plays a stream straight out of `payload_buffer` (`app::tui_mode` builds its
/// own store and keeps that default). So the one-armed `if` gated the operator
/// *notice* and never the behavior, and every batch run buffered audio nothing
/// in it could read: up to 1500 frames per stream across up to 50,000 streams
/// at the defaults, bounded per frame only by snaplen.
///
/// It stayed latent because the auto-BPF filter is `portrange 5060-5061`, so no
/// RTP reaches the store to retain. It arms the moment an operator widens the
/// filter to capture media — the first thing they do when they want audio.
///
/// A one-armed `if` cannot express "exactly when"; an assignment can. Taking
/// `&mut StreamStore` keeps the decision and its effect inseparable, so a test
/// can hold the store afterwards and read back what a run would actually do.
fn apply_audio_retention(ss: &mut StreamStore, cli: &Cli) -> bool {
    let wanted = audio_retention_wanted(cli);
    ss.set_audio_capture(wanted);
    wanted
}

/// Report any stream whose measured rate exceeds what its codec can produce.
///
/// # Why this is worth a line of output
///
/// Reading two byte-identical copies of a capture as one `-I` set reports a
/// PCMU stream at 128 kbps over an unchanged span. G.711 is 64 kbps by
/// definition — the figure is impossible, not merely high — and the run said
/// nothing. Doubled message counts and doubled packet counts read as a busier
/// network rather than a duplicated input, which is the sharpest failure mode
/// the multi-file feature has (#72).
///
/// It says WHAT happened and does not guess WHY. Duplicate input is the common
/// cause; a clock-rate error, a timestamp bug or a misidentified payload type
/// land here too. Deliberately not de-duplication: two legitimate captures of
/// one call from different vantage points are a real and useful input, and
/// silently collapsing them would destroy the asymmetry analysis that exists to
/// compare the two directions.
fn report_impossible_rates(streams: &crate::rtp::stream_store::StreamStore) {
    let mut worst: Option<(f64, String)> = None;
    let mut count = 0usize;
    for st in streams.iter() {
        if let Some(mult) = st.impossible_rate_multiple() {
            count += 1;
            let label = format!(
                "{} ssrc={:08x} {} -> {}",
                st.codec.as_deref().unwrap_or("?"),
                st.key.ssrc,
                st.key.src,
                st.key.dst
            );
            if worst.as_ref().is_none_or(|(m, _)| mult > *m) {
                worst = Some((mult, label));
            }
        }
    }
    if let Some((mult, label)) = worst {
        tracing::warn!(
            "IMPOSSIBLE RATE: {count} stream(s) carry more payload than their \
             codec can produce — worst is {label} at {mult:.1}x its ceiling. \
             The most common cause is the same traffic read twice: a directory \
             holding a capture and its backup, or one call captured at two \
             hops. Counts and rates in this run are inflated by that factor. \
             sipnab does not de-duplicate, because two vantage points on one \
             call are a legitimate input."
        );
    }
}

/// Report what the dialog store shed, beside the totals that hide it.
///
/// The packet and message counters sit UPSTREAM of the store, so they count
/// what arrived rather than what was kept. On the corpus that gap is real: 314
/// messages evicted from 65 dialogs while the summary reported 103,234 SIP
/// messages and said nothing, because the only other signal is a `debug!` line
/// nobody sees at the default level.
///
/// Three distinct loss channels, each silent until now, and each meaning
/// something different to an operator:
/// - idle compaction drops MESSAGES from dialogs it keeps
/// - at capacity with `--no-rotate`, a new dialog is REJECTED, so the earliest
///   calls are the ones you keep
/// - at capacity while rotating, the OLDEST dialog is discarded instead
///
/// Silent when nothing was shed, so a clean run stays quiet — the same rule
/// the `-I` resolution accounting follows.
fn report_retention_losses(dialogs: &DialogStore) {
    if let Some(msg) = retention_summary(dialogs) {
        tracing::warn!("{msg}");
    }
}

/// The retention sentence, or `None` when the store shed nothing.
///
/// Split from the logging so the wording is testable: the value of this line
/// is entirely in what it says, and a test that only checked "something was
/// logged" would pass on a sentence naming the wrong number.
fn retention_summary(dialogs: &DialogStore) -> Option<String> {
    let msgs = dialogs.total_idle_messages_evicted();
    let dropped = dialogs.total_capacity_dialogs_dropped();
    let rotated = dialogs.total_capacity_dialogs_evicted();
    if msgs == 0 && dropped == 0 && rotated == 0 {
        return None;
    }

    let mut parts: Vec<String> = Vec::new();
    if msgs > 0 {
        parts.push(format!(
            "{msgs} message(s) evicted from retained dialogs by idle compaction"
        ));
    }
    if dropped > 0 {
        parts.push(format!(
            "{dropped} new dialog(s) refused at capacity (--no-rotate keeps the earliest)"
        ));
    }
    if rotated > 0 {
        parts.push(format!(
            "{rotated} oldest dialog(s) discarded at capacity by rotation"
        ));
    }

    Some(format!(
        "retention: {}. The message and packet counts above are what sipnab READ, \
         not what it kept — raise --limit, or --max-streams, to keep more.",
        parts.join("; ")
    ))
}

/// Report what the CAPTURE lost, beside the totals that hide it.
///
/// The sibling of [`report_retention_losses`], one layer further upstream. That
/// one reports what the store shed after sipnab read it; this reports what
/// sipnab never read at all, because the kernel or the NIC threw it away first.
/// Both matter for the same reason and were both silent: a count of what
/// arrived reads as a count of what happened.
///
/// Three channels, each meaning something different to an operator, and each
/// with a different remedy — which is why they are named separately rather than
/// summed:
/// - **kernel-buffer drops** ([`KERNEL_DROPPED`]) — the ring was full; raise
///   `-B/--buffer`, narrow the BPF, or cut `--snaplen`
/// - **interface/driver drops** ([`IFACE_DROPPED`]) — never reached libpcap; a
///   bigger buffer cannot recover these, look at the NIC and its offloads
/// - **invalid timestamps** ([`INVALID_PCAP_TIMESTAMPS`]) — packets stamped
///   with the wall clock because their pcap timestamp was corrupt, which makes
///   every timing figure (post-dial delay, jitter, MOS) unreliable
///
/// Silent when the capture was clean, so a good run stays quiet — the same rule
/// [`retention_summary`] follows.
/// Report Binding Requests that never came back.
///
/// Separate from `capture_quality`, which is about what sipnab RECEIVED. This
/// is about what the NETWORK did: the frames arrived perfectly, and the answer
/// to them did not. Reported even when the capture holds no SIP at all, which
/// is the case that most needs it — a capture of nothing but failed NAT
/// discovery used to read as "no SIP traffic found", which is true and useless.
fn report_stun_failures() {
    let (unanswered, answered) = crate::stun::unanswered_requests();
    if unanswered.is_empty() {
        return;
    }
    let total = unanswered.len() as u64 + answered;
    for req in unanswered.iter().take(5) {
        let who = req
            .software
            .as_deref()
            .map(|s| format!(" ({s})"))
            .unwrap_or_default();
        tracing::warn!(
            "STUN/TURN: {} sent {} to {} {} time(s) and got no reply{who}. \
             An endpoint that cannot learn its reflexive address falls back to \
             advertising its PRIVATE address in SDP, which the far end cannot route \
             back to — the usual cause of a call that signals cleanly and carries \
             audio one way. Note WHAT is missing: no reply at all, rather than a \
             refusal. Silence points at something dropping the packets in the path \
             rather than at the server refusing them, and on school, campus and \
             corporate networks the usual culprit is a security appliance — web \
             filter, secure web gateway, firewall or IPS — discarding UDP it does \
             not recognize. Check whether such a device sits in this path and \
             whether it permits UDP to the STUN/TURN port before suspecting the \
             server.",
            req.from,
            req.method,
            req.to,
            req.attempts,
        );
    }
    if unanswered.len() > 5 {
        tracing::warn!(
            "STUN: {} further unanswered binding request(s) not listed.",
            unanswered.len() - 5
        );
    }
    tracing::warn!(
        "STUN/TURN: {} of {total} transaction(s) went unanswered.",
        unanswered.len()
    );
    let challenges = crate::stun::auth_challenges();
    if challenges > 0 {
        // Said separately because it points somewhere else entirely: the path
        // works and the server answered, so nothing here is a firewall
        // problem. An operator who reads only the line above goes hunting a
        // dropped packet that was never dropped.
        tracing::warn!(
            "STUN/TURN: {challenges} transaction(s) were answered with an \
             AUTHENTICATION challenge (a realm was offered). Those are not a \
             blocked path -- the server was reachable and asked for \
             credentials. Check the endpoint's STUN/TURN username and password \
             rather than the network."
        );
    }
}

/// Print the capture-quality line and the STUN/TURN failures beside it.
///
/// Two different claims, reported together because an operator reads them
/// together: capture quality is about what sipnab RECEIVED, and the STUN line
/// is about what the NETWORK did with what it sent.
fn report_capture_quality() {
    if let Some(msg) = capture_quality_summary() {
        tracing::warn!("{msg}");
    }
    report_stun_failures();
    // Called here rather than inside `report_stun_failures`, which returns
    // early on a capture with nothing unanswered: an allocation can lapse on a
    // capture where every transaction was answered promptly, and that is in
    // fact the ordinary shape of it — the Allocate succeeded, the Refresh was
    // never sent, and nothing ever went unanswered.
    report_lapsed_allocations();
    // Its own call rather than a tail of the one above, which returns early
    // on a capture where nothing lapsed: a role conflict is routinely the
    // only NAT finding a capture holds, and hanging it off an unrelated
    // early return would have silenced it on exactly those captures.
    report_ice_role_conflicts(&crate::stun::report());
}

/// Report TURN allocations that were still carrying traffic after the lifetime
/// they were last granted had run out.
///
/// The one condition sipnab reports that has NO other symptom: a TURN server
/// tears an allocation down when its lifetime lapses, and the relayed media
/// stops with it — mid-call, with no SIP message anywhere to explain why. A
/// reader looking at the signaling sees a healthy call that went quiet.
///
/// Stated as "no Refresh was SEEN" rather than "no Refresh was sent": a
/// capture that started late or lost a packet cannot tell those apart, and
/// claiming the second would blame the client for the capture's gap.
///
/// # Side effects
///
/// Writes warnings to the tracing log; silent when nothing lapsed.
fn report_lapsed_allocations() {
    let report = crate::stun::report();
    let lapsed: Vec<&crate::stun::TurnAllocation> = report.lapsed_allocations().collect();
    if lapsed.is_empty() {
        return;
    }
    tracing::warn!(
        "TURN: {} allocation(s) were still carrying traffic after the lifetime they were \
         last granted had run out, with no Refresh seen in between. A relay tears an \
         allocation down when its lifetime lapses and the media stops with it, mid-call, \
         with no SIP message to say why.",
        lapsed.len()
    );
    for alloc in lapsed.iter().take(5) {
        tracing::warn!(
            "TURN:   {} -> {}: {} lifetime, {} refresh(es) seen, traffic continued {}s past \
             expiry",
            alloc.client,
            alloc.server,
            alloc
                .lifetime_secs
                .map(|s| format!("{s}s"))
                .unwrap_or_else(|| "unknown".to_string()),
            alloc.refreshes,
            alloc.seconds_past_expiry().unwrap_or_default(),
        );
        // The media that was on the relay when it was torn down. Without it
        // the warning names an allocation and an operator has no way to reach
        // the call that went quiet, which is the only reason they are reading
        // it. Silent when no relayed frame was seen on the allocation — that
        // is a real and different answer, not a zero worth printing.
        if let Some(label) = alloc.relayed_media_label() {
            tracing::warn!("TURN:     media on it: {label}");
        }
    }
    if lapsed.len() > 5 {
        tracing::warn!(
            "TURN:   ... and {} further lapsed allocation(s) not listed.",
            lapsed.len() - 5
        );
    }
}

/// Report candidate pairs where the two ICE agents disagreed about which of
/// them was in charge.
///
/// Reported beside the lapsed allocations rather than under `--stun` alone for
/// the reason that finding is: a capture read WITHOUT the flag must still say
/// it. RFC 8445 §7.3.1.1 lets ICE resolve a role conflict itself, so this is
/// not always fatal — and the line says which of the two it was, because
/// warning at full weight about a conflict the agents fixed in one round trip
/// is how a reader learns to skip the warning that matters.
///
/// # Side effects
///
/// Writes warnings to the tracing log; silent when no conflict was seen.
fn report_ice_role_conflicts(report: &crate::stun::StunReport) {
    let ice = report.ice_summary();
    if ice.role_conflicts_total == 0 {
        return;
    }
    tracing::warn!(
        "ICE: {} candidate pair(s) show a role conflict -- both agents claimed the same \
         role, or one answered 487 Role Conflict (RFC 8445 section 7.3.1.1). The usual \
         source is two endpoints configured with the same role, or a B2BUA relaying one \
         side's role attribute to the other.",
        ice.role_conflicts_total
    );
    for conflict in ice.role_conflicts.iter().take(5) {
        tracing::warn!(
            "ICE:   {} <-> {}: {} 487 response(s){}",
            conflict.a,
            conflict.b,
            conflict.role_conflict_responses,
            if conflict.resolved {
                ", resolved -- a pair between them was nominated anyway, so it cost a round \
                 trip of repeated checks rather than the call"
            } else {
                ", UNRESOLVED -- no pair between them was ever nominated, so this is a \
                 candidate cause of media that never started"
            }
        );
    }
    if ice.role_conflicts.len() > 5 {
        tracing::warn!(
            "ICE:   ... and {} further conflicted pair(s) not listed.",
            ice.role_conflicts.len() - 5
        );
    }
}

/// The capture-quality sentence, or `None` when nothing was lost.
///
/// Split from the logging for the same reason as [`retention_summary`]: the
/// whole value is in what it says, and a test asserting only that "something
/// was logged" would pass on a sentence naming the wrong number.
fn capture_quality_summary() -> Option<String> {
    let (dropped, if_dropped) = crate::capture::live::kernel_drop_counts();
    let bad_ts =
        crate::capture::live::INVALID_PCAP_TIMESTAMPS.load(std::sync::atomic::Ordering::Relaxed);
    // A fourth channel, and the only one that is about sipnab rather than the
    // host: a frame that ARRIVED intact and produced nothing because no
    // decoder here could read it. Omitting it meant a capture sipnab
    // understood 0% of reported its quality as "fine".
    let undecodable = crate::capture::undecodable_report();
    // A fifth channel, and the only one that is neither loss nor a decode
    // failure: frames the capture's snaplen cut short before sipnab saw them.
    // The `--snaplen` warnings elsewhere fire once per run and so cannot say
    // how MUCH of a capture arrived truncated; a run that decoded every packet
    // and snapped 94% of them is not a clean capture (CT3).
    let snapped = crate::capture::snapped_frames();
    if dropped == 0 && if_dropped == 0 && bad_ts == 0 && undecodable.frames == 0 && snapped == 0 {
        return None;
    }

    let mut parts: Vec<String> = Vec::new();
    if dropped > 0 {
        parts.push(format!(
            "{dropped} packet(s) dropped by the kernel capture buffer \
             (raise -B/--buffer, narrow the BPF filter, or lower --snaplen)"
        ));
    }
    if if_dropped > 0 {
        parts.push(format!(
            "{if_dropped} packet(s) dropped by the interface or its driver \
             (a bigger buffer cannot recover these — check the NIC and its offloads)"
        ));
    }
    if bad_ts > 0 {
        parts.push(format!(
            "{bad_ts} packet(s) had a corrupt capture timestamp and were stamped \
             with the wall clock (timing analysis is unreliable for this run)"
        ));
    }
    if undecodable.frames > 0 {
        // Count and pointer, not the full breakdown: the NOT DECODED notice
        // prints immediately before this at every one of the three summary
        // sites, and repeating its reason list verbatim would turn a warning
        // that only fires when something is wrong into something to skim.
        parts.push(format!(
            "{} frame(s) reached sipnab intact and could not be decoded at all, so \
             nothing in them was analyzed (see the NOT DECODED line above for which \
             link types, EtherTypes and IP protocols)",
            undecodable.frames
        ));
    }

    if snapped > 0 {
        // Named as truncation, not loss: the frames arrived and mostly decoded.
        // What is missing is payload, which is why the remedy is a snaplen and
        // not a buffer.
        parts.push(format!(
            "{snapped} frame(s) arrived truncated by the capture's snaplen \
             (headers kept, payload cut short — raise --snaplen if you need RTP \
             payload, audio export or a faithful -O re-emit)"
        ));
    }

    Some(format!(
        "capture quality: {}. THIS ANALYSIS IS INCOMPLETE — the counts above are \
         what sipnab RECEIVED AND UNDERSTOOD, not what crossed the wire. See \
         docs/tuning-capture.md.",
        parts.join("; ")
    ))
}

/// Share of frames that must fail to decode before the notice stops being
/// informational and starts refusing to let a zero read as a finding.
///
/// Half. Below it, undecodable frames are ordinary background — ARP, LLDP, a
/// tunnel sipnab does not strip — and a capture full of SIP still reports
/// every message. At or above it, the totals describe a minority of the
/// capture, and the honest reading of a zero is "unknown", not "none".
const BLIND_RUN_SHARE: f64 = 50.0;

/// The reasons in a report, busiest first, each with its number and count.
///
/// The number is the deliverable. "Unsupported link type" names no capture
/// format; "unsupported link type 0" names `DLT_NULL` and the `editcap` that
/// converts it. "Unknown EtherType" names nothing; "0x8847" names MPLS on the
/// span port.
fn reason_list(report: &crate::capture::UndecodableReport) -> String {
    report.reason_list()
}

/// What this run could not decode, as the line a summary prints — or `None`
/// when every frame decoded.
///
/// The sibling of [`capture_quality_summary`] and of
/// `pipeline::portrange_skip_report`, and the answer to the same shape of
/// question: the totals sipnab prints describe what it UNDERSTOOD, and
/// without this line they read as describing the capture.
///
/// The defect in full: `tests/pcap-samples/h263-over-rtp.pcap` carries
/// `INVITE sip:auto@localhost SIP/2.0` on UDP 5060 and, on a link type sipnab
/// How many stored findings the end-of-capture accusation summary reads.
///
/// The alert engine keeps a bounded history; this reads it whole rather than
/// a page of it, because a summary built from the newest N findings would
/// silently drop the quietest source -- which is the one an operator is least
/// likely to have noticed already.
const ACCUSED_FINDING_SCAN_CAP: usize = 10_000;

/// had no decoder for, produced "49 packets captured, 0 SIP messages, 0 RTP
/// packets across 0 streams", then "No SIP traffic found.", then exit 0 —
/// character for character what a perfect read of a capture holding no SIP
/// produces. Nothing in the output separated "there is no SIP here" from "I
/// could not read one single frame of this".
///
/// # Arguments
///
/// * `report` — the run's undecodable tally.
/// * `frames_read` — frames handed to the parser, the denominator for the
///   share. A zero here suppresses the share rather than dividing by it.
///
/// # Returns
///
/// The notice, or `None` when nothing failed to decode — a clean run stays
/// quiet, the same rule [`retention_summary`] follows.
fn undecodable_summary(
    report: &crate::capture::UndecodableReport,
    frames_read: u64,
) -> Option<String> {
    if report.frames == 0 {
        return None;
    }

    let mut msg = format!("NOT DECODED: {} of {frames_read} frame(s)", report.frames);
    // Guarding the divide rather than assuming: `frames_read` comes from a
    // different counter than `report.frames`, and a share of infinity printed
    // beside a real count would discredit both.
    let share = if frames_read > 0 {
        let pct = report.frames as f64 * 100.0 / frames_read as f64;
        msg.push_str(&format!(" ({pct:.1}%)"));
        pct
    } else {
        0.0
    };
    msg.push_str(&format!(
        " produced nothing and are in none of the counts above. Reasons: {}",
        reason_list(report)
    ));
    if report.reasons_dropped > 0 {
        msg.push_str(&format!(
            "; plus {} further frame(s) whose reason was not retained (the capture \
             carried more distinct reasons than the tally holds)",
            report.reasons_dropped
        ));
    }
    msg.push('.');

    // Two tiers, because "most of it" and "all of it" are different findings
    // and the second is the one this whole feature exists for: at 100% the
    // totals above describe nothing at all, and every one of them is a zero
    // that means "unknown".
    if frames_read > 0 && report.frames >= frames_read {
        msg.push_str(
            " NOTHING IN THIS CAPTURE WAS READ — every frame failed to decode, so the \
             totals above describe no traffic whatsoever and a zero among them is not \
             evidence of absence.",
        );
    } else if share >= BLIND_RUN_SHARE {
        msg.push_str(
            " THIS ANALYSIS IS MOSTLY BLIND — the totals above describe the minority \
             of the capture sipnab could read, so a zero among them is not evidence \
             of absence.",
        );
    }
    Some(msg)
}

/// TLS library paths mapped by processes on this host, for the diagnostic that
/// would otherwise tell an operator how to look them up themselves.
///
/// Best-effort and never fatal: discovery walks `/proc`, and a host where it
/// finds nothing (no permission, no such process, not Linux) simply gets the
/// wording that does not name paths. Deliberately the ONLY place this platform
/// split is written.
fn mapped_tls_libraries() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        let mut paths: Vec<String> = crate::capture::uprobe::discover::discover()
            .into_iter()
            .map(|lib| lib.path.display().to_string())
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// What a run says about TLS application data it saw and could not read.
///
/// Split out as a pure function for the same reason as [`no_sip_guidance`]:
/// the whole value is in WHICH sentence it chooses, and the three cases have
/// three different remedies. Getting that wrong sends an operator to restart
/// production trunks when the real problem is that no key material ever
/// reached sipnab.
///
/// Before this existed the failure was silent. `--keylog` reports the keys it
/// loaded, the decryptor reports each session it derived, and a record that
/// opens under none of them is dropped without a word — so a capture full of
/// SIP that sipnab held as ciphertext and a capture with no SIP in it printed
/// character for character the same thing. A no-op that reports success is
/// worse than a crash.
///
/// # Returns
///
/// The lines to print, in order; empty when there is nothing to report,
/// which is every run that decrypted everything it saw and every run with no
/// TLS in it at all.
fn tls_decrypt_guidance(
    tls: &crate::capture::TlsDecryptReport,
    mapped_libs: &[String],
) -> Vec<String> {
    let mut lines = late_hold_guidance(tls);
    lines.extend(unread_guidance(tls, mapped_libs));
    lines
}

/// What the late-keylog hold discarded, and what it was still holding when the
/// run ended.
///
/// Reported on runs that decrypted successfully as well as runs that did not,
/// which is the whole point: an eviction only happens on a capture that was
/// otherwise working, so the early return in [`unread_guidance`] is exactly
/// where this fact was being dropped. Both counters existed and reached
/// nobody.
///
/// The two are separate lines because they are separate problems. Ciphertext
/// discarded before a key arrived is fixed by starting the key source earlier
/// or raising the bound. Records still held at the end mean the keys never
/// came at all, and starting earlier fixes nothing.
fn late_hold_guidance(tls: &crate::capture::TlsDecryptReport) -> Vec<String> {
    let mut lines = Vec::new();
    if tls.late_evicted > 0 {
        lines.push(format!(
            "sipnab discarded {} TLS record(s) held from before a key arrived: the \
             late-decrypt hold is bounded ({} MiB total, {} record(s) per direction, \
             {}s), and it filled before any key matched them. Start the key source \
             before the capture, or expect the first message of a call to be missing.",
            tls.late_evicted,
            crate::capture::REWIND_BUDGET_BYTES / (1024 * 1024),
            crate::capture::MAX_REWIND_PER_DIRECTION,
            crate::capture::REWIND_MAX_AGE_SECS,
        ));
    }
    if tls.late_still_held > 0 {
        lines.push(format!(
            "{} TLS record(s) were still waiting when the run ended: no key ever \
             arrived for them. Nothing was discarded and starting the capture \
             earlier would not have helped -- the key source never produced those \
             secrets.",
            tls.late_still_held
        ));
    }
    lines
}

/// Why ciphertext went unread, and what to change.
fn unread_guidance(tls: &crate::capture::TlsDecryptReport, mapped_libs: &[String]) -> Vec<String> {
    // Any successful decrypt at all proves the keys, the sequence numbers and
    // the session matching work, so the run has nothing to explain.
    if !tls.read_nothing() {
        return Vec::new();
    }
    let unread = tls.app_data_records;

    // Keys arrived and none of them became a session. For TLS 1.2 that is the
    // ServerHello: `CLIENT_RANDOM` gives the master secret, and the server
    // random and cipher suite needed to expand it into record keys are in the
    // handshake. A capture that joined mid-stream holds the secret and no way
    // to use it — and no later packet will supply what is missing.
    if tls.sessions_with_keys == 0 && tls.keylog_entries > 0 {
        return vec![
            format!(
                "sipnab loaded {} keylog line(s) and built no session from any of them, \
                 so the {} TLS application-data record(s) in this capture went unread.",
                tls.keylog_entries, tls.app_data_records,
            ),
            "The handshake is missing. A TLS 1.2 key log gives the master secret; the server \
             random and cipher suite that expand it into record keys are in the ServerHello, \
             and a capture that started after the connection did never saw one. Nothing later \
             in the capture can supply them."
                .to_string(),
            "Capture the handshake: restart the connection while the capture is running, or \
             capture continuously from before the connections you want to read."
                .to_string(),
        ];
    }

    // No session and no keys either, so no secret sipnab holds belongs to this
    // traffic. Restarting a connection would produce a fresh handshake that
    // is just as unreadable; the fix is upstream, at the key source.
    if tls.sessions_with_keys == 0 {
        let mut lines = vec![
            format!(
                "sipnab could not decrypt {unread} TLS application-data record(s): it holds \
                 no key material for any session in this capture, so this run says nothing \
                 about what that traffic contained."
            ),
            "A keylog producer only records keys for what it attached to. Check both \
             halves of that: the TLS library — eCapture picks one by looking at curl, \
             which need not be the one the SIP daemon maps, so pass --libssl with the \
             path the daemon shows in /proc/<daemon-pid>/maps — and the process, since \
             --pid pins it to a single worker while a forking daemon spreads \
             connections across all of them. Give sipnab --keylog-watch so keys minted \
             after it starts are read too."
                .to_string(),
        ];
        // Naming what this host maps beats explaining how to look it up, and
        // sipnab already enumerates exactly this for `--uprobe-list`. Every
        // path is offered, never one chosen: picking for the operator is the
        // guess this exists to remove.
        if !mapped_libs.is_empty() {
            lines.push(format!(
                "This host maps {}. Pass the one the SIP daemon uses, e.g. \
                 `ecapture tls -m keylog -k keys.log --libssl={}`.",
                mapped_libs.join(", "),
                mapped_libs[0],
            ));
            lines.push(
                "Or skip the external extractor: `sudo sipnab --uprobe-list` reports \
                 what each process maps, and `sudo sipnab -N --uprobe-tls` probes every \
                 mapped TLS library itself, with no --libssl to choose and no keylog."
                    .to_string(),
            );
        }
        return lines;
    }

    // Keys matched sessions and the records still would not open. The record
    // sequence number is the difference, and it is not on the wire.
    // Sessions were built and not one record opened under them. The record
    // sequence number is what is left, and it is not on the wire.
    vec![
        format!(
            "sipnab holds keys for {} TLS session(s) and could not decrypt any of the \
                 {} application-data record(s) it saw.",
            tls.sessions_with_keys, tls.app_data_records,
        ),
        format!(
            "The usual cause is a capture that began against connections which were \
                 already running. A TLS record is numbered by a counter both endpoints keep \
                 privately, nothing on the wire carries it, and sipnab searches only the \
                 first {} records of a stream for it — a trunk that has been up for hours \
                 is far past that. Capturing the handshake does not help; the counter \
                 depends on how many records have gone by since.",
            crate::capture::TLS_SEQ_LOCKON_WINDOW,
        ),
        "Restart the connection while the capture is running — bounce the far end, or \
             the daemon — so the stream is captured from its first record."
            .to_string(),
    ]
}

/// The guidance a run prints when it found no SIP at all.
///
/// Split out as a pure function because the whole value is in WHICH sentence
/// it chooses. "No SIP traffic found." is a claim about the wire, and a run
/// that could not decode the capture has no basis for it — that unqualified
/// sentence is the defect's last mile, the point where an unread capture is
/// finally reported to the operator as an empty one.
///
/// # Arguments
///
/// * `rtp_packets` / `streams` — RTP parsed this run. Any RTP at all proves
///   the capture was readable, so the media-only message stands unchanged.
/// * `undecodable` — the run's undecodable tally.
/// * `frames_read` — frames handed to the parser.
/// * `tls` — what TLS decryption achieved. Ciphertext this run could not read
///   is the same disclaimer one layer up: SIP may well have been present and
///   simply unreadable, so the plain sentence has no basis.
///
/// # Returns
///
/// The lines to print, in order.
fn no_sip_guidance(
    rtp_packets: u64,
    streams: usize,
    undecodable: &crate::capture::UndecodableReport,
    frames_read: u64,
    tls: &crate::capture::TlsDecryptReport,
) -> Vec<String> {
    // RTP was parsed, so the capture demonstrably decoded: media-only, not
    // unreadable. Undecodable background here changes nothing.
    if rtp_packets > 0 {
        return vec![format!(
            "No SIP signaling found, but {rtp_packets} RTP packets across {streams} \
             stream(s) were parsed. Use --report to see stream details."
        )];
    }

    if undecodable.frames > 0 {
        let share = if frames_read > 0 {
            format!(
                " ({:.1}%)",
                undecodable.frames as f64 * 100.0 / frames_read as f64
            )
        } else {
            String::new()
        };
        return vec![
            format!(
                "No SIP traffic was decoded — but {} of {frames_read} frame(s){share} could \
                 not be decoded at all, so this is not a finding that the capture contains \
                 no SIP. Undecodable: {}.",
                undecodable.frames,
                reason_list(undecodable)
            ),
            "Fix the decode before reading anything into the zero above: convert the \
             capture (editcap -T ether) or open an issue naming the number(s) reported."
                .to_string(),
        ];
    }

    // TLS application data went unread, so SIP may well have been present and
    // simply unreadable. `tls_decrypt_guidance` has already printed the counts
    // and the remedy; this only refuses to contradict them.
    if tls.read_nothing() {
        return vec![
            "No SIP traffic was decoded, but TLS application data in this capture could \
             not be decrypted (see above), so this is not a finding that the capture \
             contains no SIP."
                .to_string(),
        ];
    }

    // STUN was decoded, so this capture is not empty — it is a NAT-discovery
    // failure. Saying "no SIP traffic found, check for SIP packets" here is
    // true and useless: it sends the operator looking for a capture problem
    // when the capture already holds the answer.
    let (unanswered, answered) = crate::stun::unanswered_requests();
    if !unanswered.is_empty() {
        let first = &unanswered[0];
        return vec![
            format!(
                "No SIP traffic found, but this capture is not empty: {} of {} STUN/TURN \
                 transaction(s) went unanswered — {} sent {} to {} {} time(s) and got \
                 nothing back.",
                unanswered.len(),
                unanswered.len() as u64 + answered,
                first.from,
                first.method,
                first.to,
                first.attempts,
            ),
            "That is a NAT-discovery failure, not a missing capture. An endpoint that \
             cannot learn its reflexive address advertises its PRIVATE address in SDP, \
             and the far end then sends media to somewhere it cannot reach — a call \
             that signals cleanly and carries audio one way."
                .to_string(),
            "The requests drew no reply at all rather than a refusal, which points at \
             something in the path discarding them rather than at the server. On \
             school, campus and corporate networks that is most often a security \
             appliance — web filter, secure web gateway, firewall or IPS — dropping \
             UDP it does not recognize. Confirm whether one sits in this path and \
             whether it permits UDP to the STUN/TURN port."
                .to_string(),
        ];
    }

    vec![
        "No SIP traffic found. Check that the capture contains SIP packets (typically UDP port 5060-5061)."
            .to_string(),
        "Tip: Use 'sipnab -N -I file.pcap --hexdump' to inspect raw packet content.".to_string(),
    ]
}

/// Print the undecodable notice for a finished run, when there is one.
///
/// Called from all three batch summary sites for the reason
/// [`report_icmp_summary`] is: a notice that exists on one path and not the
/// others makes `--cores N` and `--cores 1` disagree about the same capture.
///
/// # Arguments
///
/// * `frames_read` — frames handed to the parser, for the share.
///
/// # Side effects
///
/// Writes one line to stderr when anything failed to decode.
fn report_undecodable(frames_read: u64) {
    if let Some(msg) = undecodable_summary(&crate::capture::undecodable_report(), frames_read) {
        eprintln!("{msg}");
    }
}

/// Print the LLMNR host inventory for a finished run.
///
/// Called from all three batch summary sites for the reason
/// [`report_icmp_summary`] is: a notice that exists on one path and not the
/// others makes `--cores N` and `--cores 1` disagree about the same capture.
///
/// This says nothing about any call, and must never start to. LLMNR is not a
/// VoIP protocol and sipnab is not a general dissector — it is decoded because
/// a Windows name lookup is a DNS-format message whose transaction ID supplies
/// the RTP version bits one time in four, and real captures produced phantom
/// RTP streams from exactly that. Having claimed the packet, keeping what it
/// says costs nothing and answers a question a capture taken to diagnose a
/// phone happens to contain the answer to: whose LAN is this. LLMNR being
/// enabled at all is the second half of the finding — it is the protocol
/// Responder abuses to harvest NTLM credentials.
///
/// # Side effects
///
/// Writes to stderr only when the run saw LLMNR; a capture without it stays
/// byte-identical to one from before this existed.
fn report_llmnr_summary() {
    let llmnr = crate::llmnr::store::llmnr_report();
    if llmnr.is_empty() {
        return;
    }
    eprintln!(
        "LLMNR: {} packet(s) from {} host(s) — Windows name resolution is active on this \
         segment. It is the protocol Responder abuses to harvest NTLM credentials, and is \
         normally disabled by policy.",
        llmnr.packets,
        llmnr.hosts.len()
    );

    // Names a host answered for identify that host; names nothing answered for
    // are lookups that failed on this segment. Two different findings, so two
    // different lines.
    let claimed = llmnr.claimed_names();
    if !claimed.is_empty() {
        eprintln!(
            "LLMNR: hostname(s) claimed on this segment: {}.",
            join_capped(&claimed, 8)
        );
    }
    let unresolved = llmnr.unresolved_names();
    if !unresolved.is_empty() {
        eprintln!(
            "LLMNR: name(s) queried that nothing answered for: {}.",
            join_capped(&unresolved, 8)
        );
    }
    for host in llmnr.hosts.iter().take(8) {
        if host.names_queried.is_empty() {
            continue;
        }
        eprintln!(
            "LLMNR:   {} looked up {}",
            host.addr,
            join_capped(
                &host
                    .names_queried
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                8
            )
        );
    }
    if llmnr.hosts.len() > 8 {
        eprintln!("LLMNR:   ... and {} more host(s).", llmnr.hosts.len() - 8);
    }
    // A cap that silently swallowed evidence would make the roster above read
    // as complete when it is not.
    if llmnr.dropped_hosts > 0 || llmnr.dropped_names > 0 {
        eprintln!(
            "LLMNR: {} host(s) and {} name(s) were not retained (tracking caps); the packet \
             count above stays exact.",
            llmnr.dropped_hosts, llmnr.dropped_names
        );
    }
}

/// Join at most `max` items, saying how many were withheld. Shared by the
/// LLMNR lines above, which each need the same "show some, count the rest"
/// treatment.
fn join_capped(items: &[&str], max: usize) -> String {
    if items.len() <= max {
        return items.join(", ");
    }
    format!(
        "{}, and {} more",
        items[..max].join(", "),
        items.len() - max
    )
}

/// Build this mode's stream store, with everything a live run owes it.
///
/// Extracted from `run` so the wiring inside it can be TESTED. `run` takes a
/// live capture handle and never returns until the capture ends, so anything
/// left inline here is pinned only by the fact that it compiles -- and "the
/// snapshot reaches the store" is exactly the kind of claim that compiles
/// perfectly while being false, because the store would simply be empty.
fn build_live_stream_store(
    cli: &Cli,
    config: &Config,
    relay_snapshot: &crate::relay::reconcile::RelaySnapshot,
) -> StreamStore {
    let mut ss = StreamStore::new(cli.max_streams_limit(config));
    if let Some(max_frames) = config.limits.max_audio_frames {
        ss.set_max_audio_frames(max_frames as usize);
    }
    // RE4: what the relay said it was holding when sipnab started, so a call
    // already in progress is named by its first packet rather than arriving as
    // an orphan.
    crate::pipeline::apply_relay_snapshot(&mut ss, relay_snapshot);
    if apply_audio_retention(&mut ss, cli) {
        // Retention changes this run's memory profile, so state the bound
        // rather than letting an operator discover it under load.
        let frames = config.limits.max_audio_frames.unwrap_or(1500);
        let streams = cli.max_streams_limit(config);
        tracing::info!(
            "RTP payload retention is on so the MCP export_audio tool can decode it: \
             up to {frames} frame(s) per stream across at most {streams} stream(s). \
             Lower [limits] max_audio_frames or --max-streams to bound it further."
        );
    }
    ss
}

/// Print the ICMP evidence summary for a finished run.
///
/// Called from all three batch summary sites rather than written inline,
/// because it used to live only in the single-threaded one — so `--cores N`
/// printed no ICMP summary at all, and the two paths disagreed about what the
/// same capture contained.
fn report_icmp_summary(streams: &crate::rtp::stream_store::StreamStore) {
    let icmp = crate::pipeline::icmp_evidence_report();
    if icmp.errors > 0 {
        let top: Vec<String> = icmp
            .endpoints
            .iter()
            .take(5)
            .map(|e| match e.port {
                Some(p) => format!("{}:{} ({}, {})", e.addr, p, e.errors, e.description),
                None => format!("{} ({}, {})", e.addr, e.errors, e.description),
            })
            .collect();
        eprintln!(
            "ICMP: {} error(s) quoting a SIP request, naming {} unreachable endpoint(s). \
             Busiest: {}.",
            icmp.errors,
            icmp.endpoints.len(),
            top.join(", ")
        );
        // A cap that silently swallowed evidence would make the numbers above
        // understate the problem, so say when one bit.
        if icmp.unattributed > 0 || icmp.untracked_dialogs > 0 {
            eprintln!(
                "ICMP: {} error(s) quoted too little to name a Call-ID and {} more reached no \
                 dialog because the tracking cap was full — real evidence that appears against \
                 no call.",
                icmp.unattributed, icmp.untracked_dialogs
            );
        }
    }

    // A media quote that matched no stream is still printed. Dropping it would
    // hide that the network answered, which is the whole point of reading ICMP.
    let media = crate::pipeline::icmp_media_report(streams);
    if media.errors > 0 {
        eprintln!(
            "ICMP: {} error(s) quoting non-SIP traffic, {} of them media, across {} flow(s). \
             Attributed to a stream or SDP endpoint: {}; matched nothing this capture holds: {}.",
            media.errors,
            media.media,
            media.flows.len(),
            media.attributed,
            media.unattributed,
        );
        for f in media.flows.iter().take(5) {
            eprintln!("  {}", f.hint);
        }
        if media.unkeyed > 0 || media.untracked_flows > 0 {
            eprintln!(
                "ICMP: {} media error(s) quoted too little to name a flow and {} more reached no \
                 flow because the tracking cap was full.",
                media.unkeyed, media.untracked_flows
            );
        }
    }
}

/// Run batch mode to completion: the multi-core offline fast path when
/// `--cores N` applies, otherwise the single-threaded `BatchRunner`.
///
/// # Arguments
///
/// * `cli` / `config` — parsed flags and loaded configuration (owned; this
///   is the mode's terminal consumer).
/// * `capture_config` — capture limits (`--count`, `--duration`) enforced
///   by the receive loop.
/// * `handle` — the running capture thread's handle, joined at EOF.
/// * `rx` — receiving side of the packet channel.
/// * `batch` — pre-built matcher/filter/output/event-exec components.
/// * `policy` — split/autostop policy resolved from the CLI.
/// * `raw_kill_sock` — raw socket opened during the privileged window for
///   source-spoofed kill responses, when active.
///
/// # Side effects
///
/// The multi-core arm spawns worker threads, joins the capture thread, and
/// prints reports; the single-threaded arm builds a `BatchRunner` (which
/// spawns the kill worker and companion-server thread) and drives its
/// receive loop to completion. Either way this function blocks until the
/// batch run is over.
#[expect(clippy::too_many_arguments)]
pub fn run(
    cli: Cli,
    config: &Config,
    capture_config: CaptureConfig,
    handle: capture::CaptureHandle,
    rx: capture::channel::PacketRx,
    batch: BatchProcessing,
    policy: CapturePolicy,
    raw_kill_sock: Option<crate::process_isolation::RawKillSocket>,
) {
    let portrange = policy.portrange;
    let no_rtp = cli.capture_args.no_rtp || config.capture.no_rtp.unwrap_or(false);
    // 17p. Offline multi-core reconstruction (`--cores N`, N>1). Shard parsed
    // packets by host pair across N workers with thread-local stores, merge, and
    // report — covers dialog + RTP-stream reconstruction and `--report`/`--json`.
    // Advanced features (live, per-message output ordering, security detectors,
    // SRTP) use the single-threaded path below; this branch only triggers for an
    // offline input file.
    if cli.limits_args.cores > 1 && cli.has_input() {
        let pcfg = parallel_config(&cli, config, portrange, no_rtp);
        let result = crate::parallel::run_offline_parallel(rx, pcfg);
        let _ = handle.thread.join();
        // As above: no companion server on this path, so no gate to consult.
        let reports_ok = generate_reports(
            &cli,
            &result.dialog_store,
            &result.stream_store,
            batch.filter_expr.as_ref(),
            batch.vcon_filter_expr.as_ref(),
            result.total_count,
            None,
        );
        if !cli.mode_args.quiet {
            tracing::info!(
                "sipnab: {} packets, {} SIP messages, {} RTP packets across {} streams ({} cores)",
                result.total_count,
                result.sip_count,
                result.rtp_count,
                result.stream_store.len(),
                cli.limits_args.cores,
            );
            report_undecodable(result.total_count);
            report_icmp_summary(&result.stream_store);
            report_impossible_rates(&result.stream_store);
            report_retention_losses(&result.dialog_store);
            report_capture_quality();
            report_llmnr_summary();
        }
        if !reports_ok {
            std::process::exit(1);
        }
        return;
    }

    // Derived from the source the capture thread actually opened, not from the
    // flags — `-I` beating `-d`, device auto-detection and `--hep-listen` are
    // all already resolved into `handle.source`, so re-deriving it from `cli`
    // here would be a second copy of that precedence to get wrong.
    let transmit_permit =
        crate::security::transmit_guard::TransmitPermit::for_source(&handle.source);

    let runner = match BatchRunner::new(
        cli,
        config,
        batch,
        policy,
        raw_kill_sock,
        transmit_permit,
        // Taken before `rx` is moved into `run_loop`: the meter is a cheap
        // clonable view of the same queue, so the metrics thread can read the
        // depth while the receive loop owns the receiver.
        #[cfg(feature = "metrics")]
        rx.meter(),
    ) {
        Ok(runner) => runner,
        Err(fatal) => {
            // `handle`'s thread has been running since bootstrap::launch, and
            // it owns the capture source. Exiting straight from here abandons
            // it mid-read — which is what ThreadSanitizer reported as a thread
            // leak on the --api-tls-cert fail-fast path. Stop it and reap it
            // first; this is the only scope that holds both the handle and the
            // receiver, which is why the error had to travel here to be
            // handled.
            fatal.exit_after(|| capture::stop_and_join(handle, rx));
        }
    };
    runner.run_loop(capture_config, handle, rx);
}

/// All owned batch-mode state: writer, detector engines, decryption state,
/// stores, and companion-server handles. Built once by `BatchRunner::new`
/// (bootstrap steps 16-17), consumed by `BatchRunner::run_loop` (step 18).
pub struct BatchRunner {
    /// Parsed command-line flags (owned for the life of the run).
    cli: Cli,
    /// Loaded configuration (cloned; consulted for NRB name resolution).
    config: Config,
    /// Header-level SIP matcher (`-m`, `--method`, ...).
    matcher: SipMatcher,
    /// Compiled `--filter` DSL expression, when given.
    filter_expr: Option<FilterExpr>,
    /// Compiled `--export-vcon-when` expression, resolved by the plan.
    vcon_filter_expr: Option<FilterExpr>,
    /// Per-message output formatting options.
    output_opts: OutputOptions,
    /// `--on-*` event execution engine.
    event_exec: EventExecEngine,
    /// `-O` output writer; `None` until the first packet supplies the
    /// link type (opened lazily in `run_loop`).
    writer: Option<PcapWriter>,
    /// Every capture file this run reads, resolved and in read order.
    ///
    /// Kept because several late-stage features need the SET and `cli` can only
    /// give the first `-I` argument (#48).
    input_files: Vec<PathBuf>,
    /// Write pcapng (with DSB/NRB blocks) instead of classic pcap.
    use_pcapng: bool,
    /// What payload variant `-O` records (decrypted / encrypted+DSB / raw).
    export_mode: PcapExportMode,
    /// `--hep-send` forwarder for matched SIP messages, when configured.
    #[cfg(feature = "hep")]
    hep_sender: Option<crate::capture::hep::HepSender>,
    /// IP/TCP reassembly and parse front-end for raw captured packets.
    processor: capture::PacketProcessor,
    /// Dialog store; shared with the companion servers via the lock.
    dialog_store: Arc<RwLock<DialogStore>>,
    /// RTP stream store; shared with the companion servers via the lock.
    stream_store: Arc<RwLock<StreamStore>>,
    /// Where a stream nothing explains is offered to the reconciler (RE4).
    ///
    /// `None` unless `--rtpengine-control` gave this run a relay to ask, in
    /// which case the store is also recording those sockets. The two are set
    /// up together or not at all: recording with nothing to drain the buffer
    /// would fill it for no one.
    relay_orphans: Option<crate::relay::reconcile::OrphanSink>,
    /// The reconciler thread, joined after the loop so its summary prints.
    relay_thread: Option<std::thread::JoinHandle<()>>,
    /// Heuristic RTP detector for streams with no SDP linkage.
    rtp_heuristic: rtp::heuristic::RtpHeuristic,
    /// Skip all RTP processing (`--no-rtp` or config equivalent).
    no_rtp: bool,
    /// Security detectors, alert engine, and kill-worker handle.
    engines: DetectionEngines,
    /// SIP-over-TLS decryptor (`--keylog` / `--tls-key`), when configured.
    #[cfg(feature = "tls")]
    tls_decryptor: Option<TlsDecryptor>,
    /// Holds a TLS record split across TCP segments until it completes —
    /// see [`crate::capture::tls::TlsRecordReassembler`].
    #[cfg(feature = "tls")]
    tls_reassembler: crate::capture::tls::TlsRecordReassembler,
    /// SRTP media decryption context (`--srtp-keys` + learned SDES keys).
    #[cfg(feature = "tls")]
    srtp_context: Option<crate::rtp::srtp::SrtpContext>,
    /// DTLS-SRTP key extractor (`--dtls-keylog`), when configured.
    #[cfg(feature = "tls")]
    dtls_extractor: Option<crate::capture::dtls::DtlsSrtpExtractor>,
    /// Handles to the companion-server thread (REST API / MCP), when any
    /// server started.
    servers: Option<crate::app::servers::ServerHandles>,
    /// Split/autostop policy resolved from the CLI.
    policy: CapturePolicy,
    /// Where `--evidence-out` publishes findings. Opened in `new`, so an
    /// unwritable path is an error before the first packet, not an hour in.
    evidence: Option<sec::evidence::EvidenceSink>,
}

impl BatchRunner {
    /// Build every piece of batch state (bootstrap steps 16-17): output
    /// writer policy, HEP sender, stores, security detectors + alert engine,
    /// TLS/SRTP/DTLS decryption state, and the companion servers.
    ///
    /// # Arguments
    ///
    /// * `cli` / `config` — parsed flags and loaded configuration.
    /// * `batch` — pre-built matcher/filter/output/event-exec components.
    /// * `policy` — split/autostop policy resolved from the CLI.
    /// * `raw_kill_sock` — raw socket for spoofed kill responses, handed to
    ///   the kill worker when spawned.
    /// * `capture_meter` — cheaply-clonable view of the packet queue's depth,
    ///   taken from the receiver in `run` because this is where the metrics
    ///   server is started. Threaded through rather than left `None`:
    ///   `sipnab_capture_queue_depth_packets` is written unconditionally, so
    ///   an absent meter does not omit the gauge, it publishes a hard `0` —
    ///   and headless is now the path that actually serves metrics.
    ///
    /// # Side effects
    ///
    /// Spawns the isolated scanner-kill worker thread when any kill feature
    /// is active; reads TLS keylog / RSA key / SRTP key / DTLS keylog files
    /// and embedded pcapng secrets from disk; starts the companion REST
    /// API + MCP servers on their shared runtime thread; logs progress via
    /// `tracing`.
    ///
    /// # Errors
    ///
    /// An unloadable `--tls-key`, `--srtp-keys` or `--dtls-keylog` file (exit
    /// code 1), or a companion-server configuration error (exit code 2).
    ///
    /// These used to call `std::process::exit` here. They cannot: the capture
    /// thread is already running by this point — `bootstrap::launch` spawned it
    /// before batch mode was entered — and this function does not own its
    /// handle, so exiting from here abandons a thread that still holds an open
    /// capture source. ThreadSanitizer reported exactly that as a thread leak
    /// on the `--api-tls-cert` fail-fast path. Returning lets `run` stop the
    /// capture thread first, which is the only place that can.
    fn new(
        cli: Cli,
        config: &Config,
        mut batch: BatchProcessing,
        policy: CapturePolicy,
        raw_kill_sock: Option<crate::process_isolation::RawKillSocket>,
        transmit_permit: Option<crate::security::transmit_guard::TransmitPermit>,
        #[cfg(feature = "metrics")] capture_meter: crate::capture::channel::CaptureMeter,
    ) -> Result<Self, crate::app::bootstrap::PlanError> {
        let matcher = batch.matcher;
        // Moved here with its siblings rather than taken later from a `mut`
        // binding. The field is gated on `tls`, so a `mut` on the parameter is
        // an unused-mut error in every combination without it -- which
        // `--features full` cannot see, because full includes tls.
        #[cfg(feature = "tls")]
        let preopened_keylog = batch.keylog_source;
        let input_files = batch.input_files;
        let filter_expr = batch.filter_expr;
        let vcon_filter_expr = batch.vcon_filter_expr;
        let output_opts = batch.output_opts;
        let event_exec = batch.event_exec;
        // 16. Output writer placeholder for -O — opened lazily on the first
        //     packet in run_loop, once the link type is known.
        let writer: Option<PcapWriter> = None;
        let use_pcapng = cli.capture_args.pcapng;
        let export_mode = PcapExportMode::parse_mode(&cli.tls_args.pcap_export_mode)
            .unwrap_or(PcapExportMode::Decrypted);

        // 16a. Initialize HEP sender if --hep-send is set
        #[cfg(feature = "hep")]
        let hep_sender: Option<crate::capture::hep::HepSender> =
            if let Some(ref addr) = cli.hep_args.hep_send {
                let capture_id = cli.hep_args.hep_id.unwrap_or(1);
                let hep_auth = match cli.resolve_hep_auth() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!("HEP auth: {e}");
                        None
                    }
                };
                let authenticated = hep_auth.is_some();
                // Mint the destination here rather than inside the constructor, so
                // the type is proven at the call site. While the constructor took a
                // &str, any future caller could mint a destination from an arbitrary
                // string -- which is the hole the permit type exists to close.
                let destination = crate::capture::hep::OperatorDestination::from_cli_flag(
                    crate::capture::hep::HEP_SEND_FLAG,
                    addr,
                );
                let transport = cli.hep_send_transport();
                match crate::capture::hep::HepSender::for_destination(
                    &destination,
                    crate::capture::hep::HepSenderOpts {
                        capture_id,
                        auth_key: hep_auth,
                        auth_mode: cli.hep_args.hep_auth_mode,
                        transport,
                        tls_ca: cli.hep_args.hep_tls_ca.as_deref(),
                    },
                ) {
                    Ok(sender) => {
                        tracing::info!(
                            "HEP sender targeting {addr} over {transport} (capture id \
                             {capture_id}{})",
                            if authenticated { ", authenticated" } else { "" }
                        );
                        Some(sender)
                    }
                    Err(e) => {
                        tracing::error!("Failed to create HEP sender: {e}");
                        None
                    }
                }
            } else {
                None
            };

        // 17. Initialize processing state
        //
        // Stores live behind Arc<RwLock<...>> from the start so the API server
        // (when --api is set) reads from the SAME store the packet loop writes
        // to, eliminating the prior mirror-and-double-parse pattern. In the
        // common single-writer batch case the locks are uncontested.
        let processor =
            capture::PacketProcessor::with_max_sessions(cli.max_reassembly_limit(config))
                .with_reassembly(!cli.capture_args.no_reassembly)
                .with_parse_limit(cli.capture_args.limitlen);
        let dialog_store: Arc<RwLock<DialogStore>> = Arc::new(RwLock::new(
            {
                let mut ds = DialogStore::new(cli.dialog_limit(config), cli.rotate_enabled());
                // The wiring whose absence made the old --dialog-track a dead
                // flag: declared, parsed, and never handed to anything.
                ds.set_tracking(cli.dialog_args.dialog_track.unwrap_or_default());
                ds
            }
            .with_xcid_headers(config.sip.xcid_headers.clone().unwrap_or_default())
            .with_leg_correlation_window_ms(cli.leg_correlation_window_ms(config)),
        ));
        let no_rtp = cli.capture_args.no_rtp || config.capture.no_rtp.unwrap_or(false);
        let stream_store: Arc<RwLock<StreamStore>> = Arc::new(RwLock::new(
            build_live_stream_store(&cli, config, &batch.relay.snapshot),
        ));

        // RE4's second trigger, set up exactly as the TUI mode sets it up: the
        // store records the sockets of streams nothing explains only when
        // there is a reconciler to offer them to, and the reconciler asks on
        // its own thread so this loop never waits on a relay.
        // Captured BEFORE the take below moves the reconciler onto its own
        // thread. `query_relay` needs only the PERMIT, which is `Copy`, and a
        // separate client of its own -- sharing the live reconciler would put
        // an agent's question in line behind RE4's orphan work, and RE4's rule
        // is that it never polls.
        #[cfg(feature = "mcp")]
        let relay_query_permit = batch.relay.ready.as_ref().map(|r| r.permit);
        let (relay_orphans, relay_thread) = match batch.relay.ready.take() {
            Some(ready) => {
                let (sink, orphan_rx) = crate::relay::reconcile::orphan_channel();
                stream_store.write().record_new_orphans(true);
                match crate::app::relay_reconciler::spawn(
                    ready.reconciler,
                    ready.permit,
                    orphan_rx,
                    Arc::clone(&stream_store),
                ) {
                    Ok(join) => (Some(sink), Some(join)),
                    Err(e) => {
                        tracing::warn!(
                            "could not start the rtpengine reconciler ({e}); streams the \
                             signaling does not explain will stay unattributed"
                        );
                        stream_store.write().record_new_orphans(false);
                        (None, None)
                    }
                }
            }
            None => (None, None),
        };

        let rtp_heuristic = rtp::heuristic::RtpHeuristic::new();

        // 17a. Initialize security detectors
        let kill_scanner_active =
            cli.security_args.kill_scanner || config.security.kill_scanner.unwrap_or(false);

        // Targeted-kill directives (-K). Already validated in Cli::validate();
        // reparse here and skip (loudly) any that somehow fail so a bad entry
        // can't take the whole run down mid-capture.
        let kill_targets: Vec<sec::scanner_kill::KillTarget> = cli
            .security_args
            .kill_target
            .iter()
            .filter_map(|spec| match sec::scanner_kill::KillTarget::parse(spec) {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::error!("Ignoring invalid --kill-target '{spec}': {e}");
                    None
                }
            })
            .collect();
        // The kill worker is needed whenever we may emit a kill response —
        // detection-driven (--kill-scanner) OR targeted (-K) — and permitted
        // only when this run watches a live source. `transmit_permit` is None
        // for a capture file, and the worker's constructor takes one by value,
        // so an offline run cannot build a transmitting worker at all. The
        // operator was told why in `bootstrap::plan`; detection, alerting,
        // `--fail2ban` output and reporting all continue below.
        let kill_worker_active =
            (kill_scanner_active || !kill_targets.is_empty()) && transmit_permit.is_some();

        // Deliberately NOT armed by `--fail2ban` alone. The obvious wiring —
        // "the flag feeds a banning tool, so give it a detector" — was measured
        // on a real carrier trunk and produces 7008 detections naming 180
        // peers, because the behavioral signature counts OPTIONS and the
        // busiest "scanners" are the carrier's own PBXes sending keepalives
        // (2713 from one peer in 11 seconds). That is the same mass-ban as the
        // blanket emission this replaced, only wearing the authority of a real
        // detection. Arm it once the signature can tell a keepalive from an
        // enumeration; until then `--fail2ban` warns rather than lying.
        let scanner_detector = if kill_scanner_active {
            let custom = cli
                .security_args
                .kill_ua
                .as_deref()
                .map(|s| vec![s.to_string()])
                .unwrap_or_default();
            // `with_thresholds`, not `new`: the trigger points reach the run
            // from here or they reach nothing. `ScannerDetector::new` keeps its
            // compiled-in numbers, which is the shape #68 found six detectors
            // in — a resolver that passes its own unit test and changes nothing
            // an operator sees. See the comment on `SipnabMcp::row_cap`.
            Some(ScannerDetector::with_thresholds(
                &custom,
                cli.scanner_thresholds(config),
            ))
        } else {
            None
        };

        // Built here, ahead of the warning below, because it is one of the
        // three producers that warning has to consult.
        let reg_flood_detector = if cli.security_args.reg_flood {
            Some(RegFloodDetector::new(cli.reg_flood_threshold(config)))
        } else {
            None
        };

        // An operator who asked for fail2ban output and gets an empty file will
        // read it as "nothing attacked me", which is the most dangerous way for
        // a security tool to be silent. Say so once, at the start -- and only
        // when it is true: every producer of a jail line is consulted, not the
        // scanner detector alone, so `--reg-flood --fail2ban` is not told its
        // log will stay empty and then handed lines for it.
        if cli.output_args.fail2ban
            && fail2ban_would_emit_nothing(
                scanner_detector.is_some(),
                !kill_targets.is_empty(),
                reg_flood_detector.is_some(),
            )
        {
            tracing::warn!(
                "--fail2ban writes scanner and registration-flood detections, but no \
                 detector is running, so this run will emit nothing. An empty jail log \
                 means 'nothing was detected', not 'nothing happened'. Add --kill-scanner \
                 to detect scanners (offline it only reports; it never transmits), \
                 --kill-ua <substring> to match a specific agent, -K/--kill-target <addr> \
                 to name one, or --reg-flood to detect registration floods."
            );
        }

        // The jail line passes the same origin gate as the kill response: a
        // HEP sender asserts the inner addresses, so a detection carried by
        // HEP names whatever source the sender chose, and a ban on that name
        // is a ban the sender picked. Nothing HEP-origin reaches the log
        // without the opt-in -- and an operator watching a HEP feed with
        // --fail2ban would otherwise read the empty file as an all-clear.
        if cli.output_args.fail2ban
            && !cli.security_args.hep_allow_kill
            && (cli.hep_args.hep_listen.is_some() || cli.hep_args.hep_parse)
        {
            tracing::warn!(
                "--fail2ban writes nothing for detections carried by HEP: the inner \
                 addresses are the sender's claim, and a jail line would ban whatever \
                 address it chose. Pass --hep-allow-kill to admit them once the feed is \
                 authenticated (--hep-auth) and trusted."
            );
        }

        // 17a-2. Spawn scanner-kill worker thread (D16: process isolation)
        let scanner_kill_handle: Option<ScannerKillHandle> =
            match (kill_worker_active, transmit_permit) {
                (true, Some(permit)) => spawn_kill_worker(&cli, config, raw_kill_sock, permit),
                _ => None,
            };
        let kill_response_code = cli.kill_response_code(config);

        let fraud_detector = build_fraud_detector(&cli, config);

        let digest_detector = if cli.security_args.digest_leak {
            Some(DigestLeakDetector::new())
        } else {
            None
        };

        // 17b. Initialize alert engine from --alert rules and --alert-exec,
        //      falling back to config.security.alert and config.security.alert_exec
        let effective_alert_sources: &[String] = if cli.security_args.alert.is_empty() {
            config.security.alert.as_deref().unwrap_or(&[])
        } else {
            &cli.security_args.alert
        };
        // `--alert` is declared as a CHANNEL flag — "syslog", "json", "exec" —
        // and every documented example passes a channel name. It used to be fed
        // straight to `AlertRule::parse`, whose grammar is
        // `<name>:<threshold>/<window>`, so `--alert syslog` failed to parse,
        // warned, and enabled nothing. The docs taught it anyway, including a
        // line claiming it wrote to LOCAL0. For a security path that is the
        // worst shape of bug: the operator believes alerting is on.
        //
        // A bare word is now a channel, as advertised. A value containing ':'
        // is still parsed as a rule, so anyone who discovered the old grammar
        // from the source keeps working.
        let mut alert_channel_syslog = false;
        let mut alert_channel_json = false;
        let mut alert_rules: Vec<AlertRule> = Vec::new();
        for spec in effective_alert_sources.iter() {
            let value = spec.trim();
            if value.contains(':') {
                match AlertRule::parse(value) {
                    Ok(r) => alert_rules.push(r),
                    Err(e) => tracing::warn!("Skipping invalid alert rule '{}': {}", value, e),
                }
                continue;
            }
            match value.to_ascii_lowercase().as_str() {
                "syslog" => alert_channel_syslog = true,
                "json" => alert_channel_json = true,
                // The exec channel is the presence of --alert-exec; naming it
                // here is accepted so the documented triple all work, but it
                // cannot invent a command.
                "exec" => {
                    if cli.security_args.alert_exec.is_none()
                        && config.security.alert_exec.is_none()
                    {
                        tracing::warn!(
                            "--alert exec given without --alert-exec <CMD>; no command to run"
                        );
                    }
                }
                other => tracing::warn!(
                    "Unknown alert channel '{other}'. Valid channels: syslog, json, exec. \
                     (A value containing ':' is treated as an alert rule.)"
                ),
            }
        }
        let effective_alert_exec = cli
            .security_args
            .alert_exec
            .clone()
            .or(config.security.alert_exec.clone());
        let mut alert_engine = build_alert_engine(&cli, config, alert_rules, effective_alert_exec);
        if cli.security_args.syslog || alert_channel_syslog {
            alert_engine.set_syslog(true);
        }
        if cli.security_args.alert_json || alert_channel_json {
            alert_engine.set_json_output(true);
        }
        let alert_engine = Arc::new(RwLock::new(alert_engine));

        let engines = DetectionEngines {
            scanner: scanner_detector,
            fraud: fraud_detector,
            digest: digest_detector,
            reg_flood: reg_flood_detector,
            alerts: alert_engine,
            kill_handle: scanner_kill_handle,
            kill_response_code,
            kill_targets,
        };

        // 17c. Initialize TLS decryptor if --keylog and/or --tls-key is provided
        #[cfg(feature = "tls")]
        let mut tls_decryptor: Option<TlsDecryptor> = if cli.tls_args.keylog.is_some()
            || cli.tls_args.tls_key.is_some()
            || cli.tls_args.keylog_fd.is_some()
        {
            // A source opened in the privileged window supersedes the path:
            // it is already open, and for a FIFO the path must not be
            // opened a second time. `--keylog-fd` has no path at all.
            let preopened = preopened_keylog;
            let keylog_path = if preopened.is_some() {
                None
            } else {
                cli.tls_args.keylog.as_deref().map(std::path::Path::new)
            };
            let crypto = crate::crypto::default_backend();
            match TlsDecryptor::new(keylog_path, crypto) {
                Ok(mut d) => {
                    if let Some(records) = cli.tls_args.tls_lockon_window {
                        d.set_lockon_window(records);
                    }
                    // Only a source that can GROW mid-run makes the
                    // late-decrypt hold worth paying for: a plain `--keylog`
                    // file is read once and a record that fails against it now
                    // fails against it forever.
                    d.set_keys_may_still_arrive(
                        cli.tls_args.keylog_watch || cli.tls_args.keylog_fd.is_some(),
                    );
                    if let Some(source) = preopened {
                        d.set_keylog_source(source);
                        // Drain once, HERE, before a single packet is
                        // processed. The sweep loop below also polls, but
                        // an offline replay (`-I`) can read the whole file
                        // and finish before the first sweep ever runs — so
                        // relying on the sweep alone made `--keylog-fd`
                        // load zero keys and decrypt nothing, while
                        // reporting only that the descriptor was adopted.
                        match d.poll_keylog_file() {
                            Ok(0) => {}
                            Ok(n) => tracing::info!(
                                "sipnab: TLS decryption active ({n} key(s) from the keylog \
                                     stream). Decrypted traffic visible in output."
                            ),
                            Err(e) => tracing::warn!("Keylog stream read failed: {e}"),
                        }
                    }
                    if d.keylog_entry_count() > 0 {
                        tracing::info!(
                            "sipnab: TLS decryption active (keylog loaded). \
                         Decrypted traffic visible in output."
                        );
                    }
                    // Load the RSA private key for TLS 1.2 RSA-key-exchange decryption.
                    if let Some(ref keyfile) = cli.tls_args.tls_key {
                        match crate::capture::rsa_key::RsaKey::from_pem_file(std::path::Path::new(
                            keyfile,
                        )) {
                            Ok(k) => {
                                d.set_rsa_key(k);
                                tracing::info!(
                                    "sipnab: TLS decryption active (--tls-key loaded; \
                                 decrypts TLS 1.2 RSA-key-exchange handshakes only)."
                                );
                            }
                            Err(e) => {
                                return Err(crate::app::bootstrap::PlanError {
                                    exit_code: 1,
                                    message: format!("Failed to load --tls-key {keyfile}: {e}"),
                                });
                            }
                        }
                    }
                    // Published so a server can tell "no keys were supplied"
                    // from "keys were supplied and opened nothing". Both render
                    // as `decrypted_records: 0`, and they are opposite findings
                    // with opposite remedies.
                    crate::capture::note_tls_decryptor_installed(
                        d.keylog_entry_count(),
                        d.report().sessions_with_keys,
                    );
                    Some(d)
                }
                Err(e) => {
                    tracing::error!("Failed to initialize TLS decryptor: {e}");
                    None
                }
            }
        } else {
            None
        };

        // Same bound as the packet-level TCP/SIP reassembler
        // (`PacketProcessor::with_max_sessions`) — one held-partial entry
        // per concurrent TLS stream direction, same eviction policy.
        #[cfg(feature = "tls")]
        let tls_reassembler =
            crate::capture::tls::TlsRecordReassembler::new(cli.max_reassembly_limit(config));

        // 17d. Feed TLS secrets embedded in a pcapng (Decryption Secrets Block) into
        // the decryptor, so a self-contained capture decrypts without an external
        // --keylog. Creates a decryptor on demand when the file carries secrets.
        //
        // EVERY file in the set, not `cli.primary_input()`. That returned the
        // first `-I` ARGUMENT, so with `-I plain.pcapng -I withdsb.pcapng` the
        // secrets in the SECOND file were never loaded: zero "TLS decryption"
        // lines, and the run read exactly like a capture that carried no keys.
        // A directory holding both did the same. Chronological reordering makes
        // the first argument often not even the first file read (#48).
        #[cfg(feature = "tls")]
        for path in &input_files {
            let shown = path.display();
            if let Some(ref mut dec) = tls_decryptor {
                let added = crate::capture::decrypt::feed_embedded_secrets(path, dec);
                if added > 0 {
                    tracing::info!("TLS decryption: +{added} embedded DSB secret(s) from {shown}");
                }
            } else if let Ok(meta) = crate::capture::pcapng_meta::read_pcapng_metadata(path)
                && !meta.tls_secrets.is_empty()
                && let Ok(mut d) = TlsDecryptor::new(None, crate::crypto::default_backend())
            {
                let added: usize = meta.tls_secrets.iter().map(|s| d.add_keylog_text(s)).sum();
                if added > 0 {
                    tracing::info!(
                        "TLS decryption active: {added} secret(s) from embedded DSB in {shown}"
                    );
                    // Same publication as the keylog path above. Reached only
                    // when the embedded DSB block actually yielded secrets --
                    // a probe decryptor that found none is dropped without
                    // being announced, because it decrypted nothing and
                    // announcing it would read as a failed attempt.
                    crate::capture::note_tls_decryptor_installed(
                        d.keylog_entry_count(),
                        d.report().sessions_with_keys,
                    );
                    tls_decryptor = Some(d);
                }
            }
        }

        // 17e. Initialize the SRTP decryption context from --srtp-keys (and, later,
        // SDES `a=crypto` lines fed in as SDP is parsed). Authenticated RTP payloads
        // are decrypted in place before stream/audio analysis.
        #[cfg(feature = "tls")]
        let srtp_context: Option<crate::rtp::srtp::SrtpContext> =
            if let Some(ref keyfile) = cli.tls_args.srtp_keys {
                match crate::rtp::srtp::SrtpContext::from_key_file(
                    std::path::Path::new(keyfile),
                    crate::crypto::default_backend(),
                ) {
                    Ok(ctx) => {
                        tracing::info!(
                            "SRTP decryption active: {} key(s) from {keyfile}",
                            ctx.key_count()
                        );
                        Some(ctx)
                    }
                    Err(e) => {
                        return Err(crate::app::bootstrap::PlanError {
                            exit_code: 1,
                            message: format!("Failed to load --srtp-keys {keyfile}: {e}"),
                        });
                    }
                }
            } else {
                // No key file, but SDES keys may still arrive via SDP — start empty
                // and let `add_sdes` populate it as `a=crypto` lines are seen.
                Some(crate::rtp::srtp::SrtpContext::new(
                    Vec::new(),
                    crate::crypto::default_backend(),
                ))
            };

        // 17f. Initialize the DTLS-SRTP extractor from --dtls-keylog. It recovers
        // SRTP master keys from the DTLS handshake (RFC 5764 exporter) and feeds
        // them into the SRTP context as handshakes are observed.
        #[cfg(feature = "tls")]
        let dtls_extractor: Option<crate::capture::dtls::DtlsSrtpExtractor> =
            if let Some(ref keylog) = cli.tls_args.dtls_keylog {
                match crate::capture::dtls::DtlsSrtpExtractor::from_keylog_file(
                    std::path::Path::new(keylog),
                    crate::crypto::default_backend(),
                ) {
                    Ok(ex) => {
                        tracing::info!(
                            "DTLS-SRTP active: {} keylog entr(ies) from {keylog}",
                            ex.keylog_len()
                        );
                        Some(ex)
                    }
                    Err(e) => {
                        return Err(crate::app::bootstrap::PlanError {
                            exit_code: 1,
                            message: format!("Failed to load --dtls-keylog {keylog}: {e}"),
                        });
                    }
                }
            } else {
                None
            };

        // Start the companion servers (REST API + MCP) on one shared runtime
        // thread. They read the SAME stores the packet loop writes to — no
        // mirror, no second parse; MCP additionally reads the AlertEngine for
        // the security_findings tool.
        let servers = crate::app::servers::start_servers(
            &cli,
            &dialog_store,
            &stream_store,
            Some(&engines.alerts),
            crate::app::servers::Selection {
                mcp_row_cap: cli.mcp_row_cap(config),
                mcp_body_cap: cli.mcp_body_cap(config),
                mcp_wait_seconds: cli.mcp_wait_cap(config),
                api_row_cap: cli.api_row_cap(config),
                api_rate_limit_per_peer: cli.api_peer_rate_limit(config),
                max_tracked_peers: cli.tracked_peer_capacity(config),
                metrics_max_conn: cli.metrics_conn_cap(config),
                mcp_max_findings: cli.mcp_findings_cap(config),
                tfps: cli.tfps_locator(config),
                api: true,
                mcp: true,
                // The whole point of #159: headless is where --metrics is
                // actually used, and it was the one path that never started it.
                metrics: true,
                // What `security_findings` reports as `armed_kinds`. Taken from
                // the detectors this run built, so an agent reading an empty
                // findings list can tell "nothing was watching" from "the
                // traffic was clean".
                armed_detections: engines.armed_kinds(),
            },
            // Captured above, before the reconciler moved to its own thread.
            // `None` here is what makes `query_relay` refuse: on a file-backed
            // run no permit exists to capture.
            #[cfg(feature = "mcp")]
            relay_query_permit,
            // The meter travels from `run`, where the receiver lives. Passing
            // `None` here would not omit `sipnab_capture_queue_depth_packets`
            // — that gauge is written unconditionally — it would publish a
            // confident `0` for the queue depth on every headless deployment,
            // which is the same defect this ticket is fixing, one layer down.
            #[cfg(feature = "metrics")]
            Some(capture_meter),
        )
        .map_err(|e| crate::app::bootstrap::PlanError {
            exit_code: 2,
            message: e.to_string(),
        })?;

        // Fail before the first packet: an operator who mistyped the path
        // should learn now, not after an hour of capture and a lost finding.
        let evidence = match cli.security_args.evidence_out.as_deref() {
            None => None,
            Some(target) => Some(sec::evidence::EvidenceSink::open(target).map_err(|e| {
                crate::app::bootstrap::PlanError {
                    exit_code: 2,
                    message: format!("--evidence-out {target}: {e}"),
                }
            })?),
        };
        Ok(Self {
            cli,
            config: config.clone(),
            matcher,
            filter_expr,
            vcon_filter_expr,
            output_opts,
            event_exec,
            writer,
            input_files,
            use_pcapng,
            export_mode,
            #[cfg(feature = "hep")]
            hep_sender,
            processor,
            dialog_store,
            stream_store,
            rtp_heuristic,
            no_rtp,
            engines,
            #[cfg(feature = "tls")]
            tls_decryptor,
            #[cfg(feature = "tls")]
            tls_reassembler,
            #[cfg(feature = "tls")]
            srtp_context,
            #[cfg(feature = "tls")]
            dtls_extractor,
            servers,
            policy,
            relay_orphans,
            relay_thread,
            evidence,
        })
    }

    /// The main receive loop (step 18) plus end-of-capture reporting and the
    /// server keep-alive tail. Consumes the runner.
    ///
    /// # Arguments
    ///
    /// * `capture_config` — supplies the `--count` / `--duration` stop
    ///   limits.
    /// * `handle` — capture-thread handle, joined once the channel drains.
    /// * `rx` — receiving side of the packet channel.
    ///
    /// # Side effects
    ///
    /// Blocks until capture ends: drains the packet channel, mutates the
    /// shared stores, lazily opens and writes the `-O` output file
    /// (embedding DSB/NRB blocks for pcapng), emits per-message output
    /// through the buffered stdout sink, fires alert/exec events, sweeps
    /// reassembly and detector state every 5 s, and honors the
    /// count/duration/autostop stop conditions. On exit it flushes the
    /// sink and writer, shuts down the kill worker, joins the capture
    /// thread, flips the MCP `source_exhausted` flag, prints reports and
    /// the summary, and — when a companion server is running — parks until
    /// shutdown is requested or the MCP stdio client disconnects. Exits
    /// the process on a failed output-file open (code 1), a failed
    /// `--call-report` lookup (code 1), or a failed output-file *write* or
    /// final flush (code 1) — the last of which previously logged and exited
    /// 0, so a capture truncated by ENOSPC reported success.
    fn run_loop(
        self,
        capture_config: CaptureConfig,
        handle: capture::CaptureHandle,
        rx: capture::channel::PacketRx,
    ) {
        let BatchRunner {
            cli,
            config,
            matcher,
            filter_expr,
            vcon_filter_expr,
            output_opts,
            mut event_exec,
            mut writer,
            input_files,
            use_pcapng,
            export_mode,
            #[cfg(feature = "hep")]
            hep_sender,
            mut processor,
            dialog_store,
            stream_store,
            mut rtp_heuristic,
            no_rtp,
            mut engines,
            #[cfg(feature = "tls")]
            mut tls_decryptor,
            #[cfg(feature = "tls")]
            mut tls_reassembler,
            #[cfg(feature = "tls")]
            mut srtp_context,
            #[cfg(feature = "tls")]
            mut dtls_extractor,
            servers,
            policy,
            relay_orphans,
            relay_thread,
            evidence,
        } = self;
        // Reused across packets so the hand-off costs no allocation per packet.
        let mut new_orphans: Vec<(std::net::IpAddr, u16)> = Vec::new();

        // Set when writing the -O output fails. The open path a few hundred
        // lines below exits 1; the write and final-flush paths only logged,
        // so a capture truncated by ENOSPC reported success and any
        // `sipnab -O out.pcap && next-step` pipeline ran on partial data.
        let mut output_failed = false;
        // Set when the capture thread ends in an error or a panic, i.e. the
        // input was not read to the end. Separate from `output_failed` so the
        // two causes stay distinguishable in the code even though both land on
        // the same exit status: one means "what we read was not written", the
        // other "what we wrote was not all there was to read".
        let mut capture_failed = false;
        let split_bytes = policy.split_bytes;
        let split_duration = policy.split_duration;
        let split_keep = policy.split_keep;
        let portrange = policy.portrange;
        let autostop_duration = policy.autostop_duration;
        let autostop_filesize_bytes = policy.autostop_filesize_bytes;

        // --after / -A trailing context counter
        let after_count = cli.output_args.after.unwrap_or(0);

        let batch_ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli: &cli,
            no_rtp,
            after_count,
            portrange,
        };

        // --group-by buffers per-message output and replays it grouped once the
        // capture ends (see output::group for why it cannot stream, and for the
        // caps that keep an attacker-keyed map bounded). None = stream as usual.
        let mut group_buf = cli
            .output_args
            .group_by
            .as_deref()
            .and_then(|f| output::group::GroupField::parse(f).ok())
            .map(|f| output::group::GroupBuffer::new(f, cli.group_caps(&config)));

        // Wall time for a live device, the capture's own timeline for `-I`.
        // See `SweepClock` for why the two cannot share one rule.
        let mut sweep_clock = SweepClock::new(cli.has_input());
        let sweep_interval = std::time::Duration::from_secs(5);
        // --keylog-watch's own cadence — real wall time via Instant, not
        // sweep_clock. sweep_clock advances from packet timestamps, so on a
        // quiet link it never advances at all; the packet that matters is an
        // INVITE arriving after silence, and it needs the key already loaded
        // before it arrives, not in response to it. 100ms bounds the miss
        // window to a tenth of the old 5s sweep tie-in while keeping keylog
        // reads off the per-packet hot path (unbounded there, this is one
        // syscall per ~100ms wall time regardless of packet rate, not one
        // per packet against a stated >=100K pps target).
        #[cfg(feature = "tls")]
        let mut keylog_poll_clock = std::time::Instant::now();
        #[cfg(feature = "tls")]
        let keylog_poll_interval = std::time::Duration::from_millis(100);
        // How much detector state each sweep keeps. Derived from the widest
        // window this run's detectors were given rather than fixed, because
        // the sweep is what ages that state out: a constant here caps every
        // detector window at the constant, so declaring a fifteen-minute
        // wangiri window would buy a two-minute one.
        let security_max_age = cli.security_sweep_max_age(&config);

        // Shared buffered stdout sink for every per-message emitter (JSON,
        // text, fail2ban, hexdump). Flushed whenever the packet
        // channel goes idle — live output stays real-time — and at end of
        // capture; `--line-buffer` flushes after every message.
        let mut sink = output::BatchSink::stdout(cli.output_args.line_buffer);

        // Carries a packet's output, alerts and hook commands OUT of the
        // section that holds both store write locks, so the syscalls they
        // imply — `fork`/`exec` above all — happen with no lock held. Built
        // once and reused, so its buffers are allocated once for the run.
        // See `DeferredEffects`.
        let mut effects = DeferredEffects::new();
        effects.evidence = evidence;

        // 18. Main receive loop
        let start = std::time::Instant::now();
        let mut total_count: u64 = 0;
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
        };

        loop {
            if signals::shutdown_requested() {
                break;
            }

            // The stdio MCP client owns this process's lifetime, and a LIVE
            // capture has to check that here rather than after the loop.
            //
            // A file capture drains and the channel disconnects, so the loop
            // breaks on its own and reaches the keep-alive loop below, which
            // polls the same flag. A live capture never disconnects: the only
            // other exit is a signal. So a client that closed stdin -- which is
            // exactly how an MCP client shuts a stdio server down -- left the
            // process running, still capturing, until someone killed it by
            // hand. Every connect leaked another one.
            //
            // Checked before the recv rather than after, so a silent link
            // (no packets, recv timing out) still notices the client is gone.
            //
            // `request_shutdown` rather than a bare `break`: the live capture
            // thread is still blocked in libpcap and only stops when it sees
            // this flag (capture/live.rs). Breaking alone left the loop and
            // then blocked forever joining that thread -- the process still
            // did not exit, it just stopped reading. Routing through the
            // shutdown flag makes a vanished client take the identical path
            // SIGTERM already takes, which is the path that is known to work.
            if mcp_stdio_client_gone(servers.as_ref().and_then(|s| s.mcp_stdio_done.as_ref())) {
                tracing::info!("MCP client disconnected — shutting down");
                signals::request_shutdown();
                break;
            }

            // Periodic sweep of reassembly state and idle-dialog compaction
            // (every 5 seconds of capture time, which is wall time only when
            // live). Orphan status is not swept: it is derived from
            // `associated_dialog` at every read — see
            // [`crate::rtp::stream::RtpStream::orphaned`].
            if let Some(now) = sweep_clock.take_due(sweep_interval) {
                processor.sweep();
                let compacted = dialog_store.write().compact_idle(now.get());
                if compacted.messages_evicted > 0 {
                    tracing::debug!(
                        "idle-dialog compaction: dropped {} messages from {} dialogs",
                        compacted.messages_evicted,
                        compacted.dialogs_compacted
                    );
                }
                if let Some(det) = engines.scanner.as_mut() {
                    det.sweep(security_max_age);
                }
                if let Some(det) = engines.fraud.as_mut() {
                    det.sweep(security_max_age);
                }
                if let Some(det) = engines.reg_flood.as_mut() {
                    det.sweep(security_max_age);
                }
            }

            // --keylog-watch: poll for new keys in the keylog source, on its
            // own ~100ms wall-clock cadence (keylog_poll_clock above) rather
            // than tied to the 5-second reassembly/dialog sweep. A fast SIP
            // call (INVITE..ACK in well under 5s) can complete before that
            // sweep ever runs again, so a key that arrived mid-call was not
            // read until the call was already over — sipnab would log the
            // session as "ready" and never decrypt a single message from it.
            //
            // `--keylog-fd` implies the watch. A descriptor handed over by a
            // live producer has nothing to read at startup and everything
            // to read later, so requiring a second flag to look at it would
            // make the obvious invocation load no keys at all and say
            // nothing — the failure this area has already been bitten by.
            #[cfg(feature = "tls")]
            if keylog_poll_clock.elapsed() >= keylog_poll_interval
                && (cli.tls_args.keylog_watch || cli.tls_args.keylog_fd.is_some())
                && let Some(ref mut decryptor) = tls_decryptor
            {
                keylog_poll_clock = std::time::Instant::now();
                if let Err(e) = decryptor.poll_keylog_file() {
                    tracing::debug!("Keylog poll error: {e}");
                }
            }

            // Use recv_timeout so we can check shutdown periodically. Flush
            // pending output first whenever the channel has gone idle, so a
            // quiet live capture never sits on buffered messages.
            if rx.is_empty() {
                sink.flush();
            }
            let packet = match rx.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(pkt) => pkt,
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            };

            // Offline, this packet's timestamp is what "now" means to the next
            // sweep. Recorded before any parse/filter step so that a capture of
            // traffic sipnab does not decode still advances the clock — the
            // alternative would stall compaction on exactly the captures whose
            // memory growth it exists to bound.
            sweep_clock.observe(packet.timestamp);

            // Lazily initialize the writer on first packet (we need link_type)
            if writer.is_none()
                && let Some(ref output_path) = cli.capture_args.output
            {
                // Record the capture source as the pcapng interface name (SNB-0001):
                // the capture device for live, the input file for replay.
                let capture_source = cli.capture_args.device.as_deref().or(cli.primary_input());
                match PcapWriter::with_interface(
                    &PathBuf::from(output_path),
                    packet.link_type,
                    split_bytes,
                    split_duration,
                    use_pcapng,
                    export_mode,
                    capture_source,
                )
                .map(|w| w.keep_last_splits(split_keep))
                {
                    Ok(mut w) => {
                        // Write DSB with keylog content if mode requires it
                        if let Some(ref keylog_path) = cli.tls_args.keylog
                            && let Err(e) =
                                w.maybe_write_keylog_dsb(std::path::Path::new(keylog_path))
                        {
                            tracing::warn!("Failed to write DSB: {e}");
                        }
                        // Embed a Name Resolution Block when name resolution is active
                        // (SNB-0001): headless `--names`/`--resolve` should travel with
                        // the capture, mirroring the TUI save path. Before packets.
                        if use_pcapng {
                            let (resolver, mode) = crate::app::build_resolver(&cli, &config);
                            if mode != crate::names::NameMode::Off {
                                let include_dns = mode == crate::names::NameMode::Dns;
                                let entries = resolver.nrb_entries(include_dns);
                                if let Err(e) = w.write_name_resolution_block(&entries) {
                                    tracing::warn!("Failed to write name resolution block: {e}");
                                }
                            }
                        }
                        writer = Some(w);
                    }
                    Err(e) => {
                        tracing::error!("Failed to open output file: {e}");
                        std::process::exit(1);
                    }
                }
            }

            // Write to output pcap if configured
            if let Some(ref mut w) = writer
                && let Err(e) = w.write(&packet)
            {
                tracing::error!("Failed to write packet: {e}");
                // Failing to OPEN the output exits 1 a few lines above; failing
                // to WRITE it used to exit 0, so `sipnab -O out.pcap && process
                // out.pcap` proceeded on a truncated capture.
                output_failed = true;
                break;
            }

            total_count += 1;

            // Parse and reassemble the packet
            let parsed_packets = processor.process(&packet);
            for pp in &parsed_packets {
                // --hep-parse: try to unwrap HEP-encapsulated packets
                #[cfg(feature = "hep")]
                let hep_unwrapped = if cli.hep_args.hep_parse {
                    unwrap_hep(pp)
                } else {
                    None
                };

                #[cfg(not(feature = "hep"))]
                let hep_unwrapped: Option<ParsedPacket> = None;

                let pp = hep_unwrapped.as_ref().unwrap_or(pp);

                // Port range filtering only applies to SIP detection — RTP uses
                // dynamic ports negotiated via SDP and must not be filtered here.
                // The filter is applied inside process_parsed_packet for SIP only.

                // Attempt TLS decryption for TCP payloads when --keylog is active.
                // Zero, one, or more synthetic packets: a TLS record spans more
                // than one captured packet often enough (large INVITE bodies
                // among them — see `TlsRecordReassembler`) that this can yield
                // more than one decrypted SIP message from a single incoming
                // packet, and can just as easily yield none yet while a record
                // is still incomplete.
                #[cfg(feature = "tls")]
                let tls_decrypted = try_tls_decrypt(pp, &mut tls_decryptor, &mut tls_reassembler);

                #[cfg(not(feature = "tls"))]
                let tls_decrypted: capture::ParsedPackets = capture::ParsedPackets::new();

                // If TLS decryption yielded one or more SIP messages, process
                // those (each already stamped Tls); otherwise fall back to the
                // original packet, exactly as the pre-reassembly `unwrap_or`
                // did for the single-message case.
                let effective_pps: SmallVec<[&ParsedPacket; 1]> = if tls_decrypted.is_empty() {
                    smallvec![pp]
                } else {
                    tls_decrypted.iter().collect()
                };

                for effective_pp in effective_pps.iter().copied() {
                    // Acquire write locks once per packet. The locks are uncontested
                    // in the no-API case; with --api, the API thread briefly waits
                    // for in-flight per-packet processing to finish.
                    //
                    // Nothing that can block belongs in this scope. Everything that
                    // used to — both `sh -c` spawn sites, the alert engine's own
                    // lock, and the stdout writes — is queued into `effects` (and
                    // into the event-exec engine's pending queue) and replayed
                    // immediately below, with the guards gone.
                    {
                        let mut ds_guard = dialog_store.write();
                        let mut ss_guard = stream_store.write();
                        let mut proc_state = ProcessingState {
                            dialog_store: &mut ds_guard,
                            stream_store: &mut ss_guard,
                            rtp_heuristic: &mut rtp_heuristic,
                            event_exec: &mut event_exec,
                            #[cfg(feature = "tls")]
                            srtp: srtp_context.as_mut(),
                            #[cfg(feature = "tls")]
                            dtls: dtls_extractor.as_mut(),
                            group: group_buf.as_mut(),
                        };
                        process_parsed_packet(
                            effective_pp,
                            &batch_ctx,
                            &mut proc_state,
                            &mut engines,
                            &mut counters,
                            &mut effects,
                        );
                        // RE4's second trigger, drained under the guard this
                        // scope already holds. Offering happens BELOW, with
                        // the guards gone: the reconciler takes this same lock
                        // to apply what it learns, and nothing that waits on
                        // another thread belongs in here.
                        if relay_orphans.is_some() {
                            new_orphans = ss_guard.drain_new_orphan_sockets();
                        }
                    }

                    // Hand off anything the packet just created that nothing
                    // explains. `offer` never blocks -- a full queue drops and
                    // counts rather than stalling the capture on a relay.
                    if let Some(ref sink) = relay_orphans {
                        for (address, port) in new_orphans.drain(..) {
                            sink.offer(address, port);
                        }
                    }

                    // Both store guards have dropped. Replay what the packet
                    // queued, in the order it was raised: output, then alert
                    // findings, then the hook commands. Draining per packet —
                    // rather than per batch, or at end of capture — is what keeps
                    // ordering identical to emitting inline.
                    effects.drain(&mut sink, &engines.alerts, &mut event_exec);

                    // --hep-send: SIP as protocol type 1, RTCP as type 5,
                    // nothing else. What is stamped and what is skipped is
                    // decided in `HepSender::forward_parsed`, where a test can
                    // reach it.
                    #[cfg(feature = "hep")]
                    if let Some(ref sender) = hep_sender
                        && let Err(e) = sender.forward_parsed(effective_pp)
                    {
                        tracing::debug!("HEP forward failed: {e:#}");
                    }
                }
            }

            // Check --count limit
            if let Some(max_count) = capture_config.count
                && total_count >= max_count
            {
                break;
            }

            // Check --duration limit
            if let Some(duration) = capture_config.duration
                && start.elapsed() >= duration
            {
                break;
            }

            // Check --autostop duration
            if let Some(autostop_dur) = autostop_duration
                && start.elapsed() >= autostop_dur
            {
                tracing::info!("Autostop: duration limit reached ({autostop_dur:?})");
                break;
            }

            // Check --autostop filesize
            if let Some(max_bytes) = autostop_filesize_bytes
                && let Some(ref w) = writer
                && w.bytes_written() >= max_bytes
            {
                tracing::info!(
                    "Autostop: filesize limit reached ({} MiB)",
                    max_bytes / crate::capture::writer::BYTES_PER_MIB
                );
                break;
            }
        }

        // A no-op today — every packet drains before the loop can break — and
        // kept because the cost of being wrong is silent data loss. A future
        // `break` added inside the per-packet body would otherwise discard that
        // packet's output, its findings and its hook commands with no error
        // anywhere, which is the failure this whole area exists to remove.
        effects.drain(&mut sink, &engines.alerts, &mut event_exec);

        // Replay any --group-by buffer before draining, so grouped output lands
        // ahead of reports exactly where the streamed output would have.
        if let Some(ref mut buf) = group_buf {
            if buf.truncated() {
                tracing::warn!("{}", buf.truncation_note());
            }
            let machine_readable =
                cli.output_args.json || cli.output_args.json_pretty || cli.output_args.fail2ban;
            for (header, chunks) in buf.drain() {
                // Headers are for humans; machine formats stay parseable, where
                // the grouping is the contiguity of the records themselves.
                if let Some(h) = header
                    && !machine_readable
                {
                    sink.write_str(&format!("\n── {h} ──\n"));
                }
                for chunk in chunks {
                    sink.write_str(&chunk);
                }
            }
        }

        // Drain the per-message output sink before anything else writes to
        // stdout (reports, wireshark/tshark lines), preserving output order.
        sink.flush();

        // A write that failed for any reason other than a closed pipe means the
        // emitted output is incomplete — same class as a truncated -O file, and
        // it must not exit 0 either.
        if let Some(e) = sink.hard_error() {
            tracing::error!("Failed to write output: {e}");
            output_failed = true;
        }

        // Flush the output writer explicitly: BufWriter's Drop discards
        // flush errors, so without this an ENOSPC at end of capture would
        // truncate the file silently with exit code 0.
        if let Some(ref mut w) = writer
            && let Err(e) = w.finish()
        {
            tracing::error!("Output file may be incomplete: {e}");
            output_failed = true;
        }

        // 19. Shut down scanner-kill worker (D16)
        if let Some(ref mut kill_handle) = engines.kill_handle {
            kill_handle.shutdown();
        }

        // 19a. Stop the rtpengine reconciler (RE4). Dropping the sink closes
        //      the hand-off queue, which is what ends its loop -- there is no
        //      flag to set and no timeout to wait out. Joining lets its
        //      summary line print, and it happens HERE rather than at the end
        //      of the function because the reporting below can exit the
        //      process outright.
        drop(relay_orphans);
        if let Some(join) = relay_thread
            && join.join().is_err()
        {
            tracing::warn!("the rtpengine reconciler thread panicked");
        }

        // 20. Wait for the capture thread to finish
        //     Drop rx first so the capture thread sees a disconnected channel
        drop(rx);
        // A capture thread that returned Err did NOT read its input to the end,
        // so every report below is drawn from a partial view. Both failure arms
        // used to log and fall through to exit 0, which made the run
        // indistinguishable from a complete one to anything reading `$?`.
        //
        // The concrete case that found this: a BPF filter that compiles against
        // the first file of a set and not against a later one. `capture_files`
        // returns Err naming the file, the warn! below swallowed it, and the run
        // printed a whole-looking summary and exited 0 — while `--cores` on the
        // same input exited 1. Two answers to one question, and the reassuring
        // one was the default path.
        //
        // A clean shutdown is not affected: `capture_live` returns Ok(()) when
        // the stop signal ends the loop and reserves Err for a failed open, a
        // rejected filter or a fatal read.
        match handle.thread.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::error!("Capture did not complete: {e:#}");
                capture_failed = true;
            }
            Err(_) => {
                tracing::error!("Capture thread panicked; the input was not read to the end");
                capture_failed = true;
            }
        }

        // 20a. The source is fully drained: flip the flag MCP's tail_dialogs
        //      reports as source_exhausted, so a polling client knows no more
        //      dialog updates will arrive.
        if let Some(ref servers) = servers
            && let Some(ref flag) = servers.source_exhausted
        {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        // 21. Post-capture output
        {
            let ds_guard = dialog_store.read();
            let ss_guard = stream_store.read();
            // The gate the REST door has been moving all run. `None` only
            // when no companion server started, which is the same run in
            // which nothing could have moved it.
            let gate = servers.as_ref().map(|s| s.persistence_gate.as_ref());
            if !generate_reports(
                &cli,
                &ds_guard,
                &ss_guard,
                filter_expr.as_ref(),
                vcon_filter_expr.as_ref(),
                total_count,
                gate,
            ) {
                std::process::exit(1);
            }
        }

        // 21z. --lint: run the RFC conformance linter over every dialog (#147).
        //
        // The linter shipped reachable only over MCP, which put the project's
        // most distinctive capability out of reach of the place it matters
        // most: a pipeline gating a proxy config change.
        let lint_gate_tripped = run_lint_stage(&cli, &config, &dialog_store.read());

        // 21a. --wireshark: print Wireshark display filter for all tracked dialogs
        if cli.output_args.wireshark {
            let ds_guard = dialog_store.read();
            let call_ids: Vec<String> = ds_guard.iter().map(|d| d.call_id.clone()).collect();
            if call_ids.is_empty() {
                eprintln!("No SIP dialogs to generate Wireshark filter for.");
            } else {
                let filter_parts: Vec<String> = call_ids
                    .iter()
                    .map(|id| format!("sip.Call-ID == \"{}\"", id))
                    .collect();
                println!("{}", filter_parts.join(" || "));
            }
        }

        // 21b. --tshark-filter: print full tshark command for matched dialogs.
        // The emitted `tshark -r <file>` must name a pcap that actually
        // exists: the input file (`-I`), or the file the live capture was
        // saved to (`-O`). A live capture with neither has no pcap for tshark
        // to read, so emit a clear error instead of a bogus `capture.pcap`.
        if cli.output_args.tshark_filter.is_some() || (cli.output_args.wireshark && cli.has_input())
        {
            let input_file = tshark_input_file(&input_files, cli.capture_args.output.as_deref());
            if let Some(ref tshark_expr) = cli.output_args.tshark_filter {
                // User provided a custom tshark filter expression.
                match &input_file {
                    Ok(file) => println!("tshark -r {file} -Y '{tshark_expr}' -V"),
                    Err(e) => tracing::error!("Cannot emit --tshark-filter command: {e}"),
                }
            } else if let Ok(file) = &input_file {
                // Generate tshark command from tracked dialogs (only when
                // --wireshark + -I; the outer guard ensures the input exists).
                let ds_guard = dialog_store.read();
                let call_ids: Vec<String> = ds_guard.iter().map(|d| d.call_id.clone()).collect();
                if !call_ids.is_empty() {
                    let filter_parts: Vec<String> = call_ids
                        .iter()
                        .map(|id| format!("sip.Call-ID == \"{}\"", id))
                        .collect();
                    println!("tshark -r {} -Y '{}' -V", file, filter_parts.join(" || "));
                }
            }
        }

        // Who the detectors accused, grouped. Every detector answers per
        // MESSAGE, which is right for `--kill-scanner` acting on one packet
        // and wrong for the question asked after a capture: which addresses
        // were probing me, and how do I know. Nothing here re-detects -- it
        // groups findings the detectors already produced, so there is one
        // detector and one set of thresholds.
        //
        // `established` is carried with the accusation rather than left in the
        // detector that already acts on it. A source that also completed a
        // registration or a call is one a block would disconnect, and learning
        // that after the block is too late.
        //
        // Computed ABOVE the `--quiet` gate, and read by two consumers below:
        // the summary, which `--quiet` silences, and `--recommend-block`,
        // which it must not. An operator who asked for a firewall rule and got
        // nothing because an unrelated flag suppressed the summary would have
        // no way to tell that from a capture with nothing in it.
        let accused_sources = {
            let findings = engines
                .alerts
                .read()
                .iter_findings(&[], None, ACCUSED_FINDING_SCAN_CAP)
                .into_iter()
                .cloned()
                .collect::<Vec<_>>();
            let refs: Vec<&crate::security::alerting::Finding> = findings.iter().collect();
            let mut accused = crate::security::sources::accused(&refs);
            for a in &mut accused {
                a.established = engines.scanner.as_ref().map(|d| d.established(&a.src_ip));
            }
            accused
        };

        // 21c. `--recommend-block`: the accusation as a rule the operator can
        // run. sipnab RECOMMENDS -- this prints text and reaches no firewall.
        if let Some(dialect) = cli.security_args.recommend_block {
            if accused_sources.is_empty() {
                print!("{}", crate::security::recommend::nothing_to_recommend());
            } else {
                for a in &accused_sources {
                    print!("{}", crate::security::recommend::recommend(a, dialect));
                }
            }
        }

        // 22. Summary
        if !cli.mode_args.quiet {
            let stream_count = stream_store.read().len();
            tracing::info!(
                "sipnab: {total_count} packets captured, {} SIP messages, {} RTP packets across {stream_count} streams",
                counters.sip_count,
                counters.rtp_count,
            );

            // The accusation summary, over the grouping computed above.
            if !accused_sources.is_empty() {
                tracing::info!(
                    "sipnab: {} source(s) named by security detections",
                    accused_sources.len()
                );
                for a in &accused_sources {
                    let rules = a.rules.iter().cloned().collect::<Vec<_>>().join(", ");
                    let counter = match a.established {
                        Some(true) => {
                            "  -- also completed a registration or call, so a block disconnects it"
                        }
                        _ => "",
                    };
                    tracing::info!(
                        "sipnab:   {} {} finding(s) [{rules}]{counter}",
                        a.src_ip,
                        a.findings
                    );
                }
            }

            // What `--split-keep` removed, counted beside what the run kept.
            // A run that deleted capture files says so in its closing line,
            // not only in the per-file log an operator may have scrolled past.
            let deleted = writer.as_ref().map_or(0, PcapWriter::splits_deleted);
            if deleted > 0 {
                tracing::info!(
                    "sipnab: {deleted} older split file(s) deleted by --split-keep \
                     (each one written by this run)"
                );
            }

            // What `--portrange` discarded, beside the totals it reduced.
            // Without this the counts above read as complete.
            let skipped = crate::pipeline::portrange_skip_report();
            if skipped.messages > 0 {
                let top: Vec<String> = skipped
                    .ports
                    .iter()
                    .take(5)
                    .map(|p| format!("{} ({})", p.port, p.messages))
                    .collect();
                eprintln!(
                    "NOT ANALYZED: {} further SIP message(s) were seen on ports outside \
                     --portrange and are in none of the totals above. Busiest: {}. \
                     Re-run with --portrange 1-65535 to include them.",
                    skipped.messages,
                    top.join(", ")
                );
            }

            // And what the WebSocket port set discarded. Reported separately
            // because it is a different loss with a different fix: the SIP
            // above was recognized and gated, this was wrapped in a WebSocket
            // frame on a port sipnab never tried to unwrap. Before this there
            // was no report at all — a deployment terminating WSS on 8081 was
            // told nothing whatsoever about its entire WebRTC signaling leg.
            let ws_skipped = crate::pipeline::ws_port_skip_report();
            if ws_skipped.messages > 0 {
                let top: Vec<String> = ws_skipped
                    .ports
                    .iter()
                    .take(5)
                    .map(|p| format!("{} ({})", p.port, p.messages))
                    .collect();
                eprintln!(
                    "NOT ANALYZED: {} SIP-over-WebSocket message(s) arrived on ports \
                     outside the WebSocket port set ({}) and are in none of the \
                     totals above. Busiest: {}. Re-run with --ws-portrange covering \
                     them (e.g. --ws-portrange 1-65535) to include them.",
                    ws_skipped.messages,
                    crate::capture::websocket::ws_ports_description(),
                    top.join(", ")
                );
            }

            // What sipnab could not decode, beside the totals that hide it.
            // Read once so the notice and the no-SIP guidance below cannot
            // disagree about the same run.
            let undecodable = crate::capture::undecodable_report();
            if let Some(msg) = undecodable_summary(&undecodable, total_count) {
                eprintln!("{msg}");
            }

            report_icmp_summary(&stream_store.read());
            report_impossible_rates(&stream_store.read());
            report_retention_losses(&dialog_store.read());
            report_capture_quality();
            report_llmnr_summary();

            // What TLS decryption achieved. Reported whether or not any SIP
            // was found, because a run that read nine records of ten and
            // printed the nine has said nothing about the tenth.
            // One last replay before the counters are read. A capture that
            // ends moments after its keys arrive -- a test call, a Ctrl-C --
            // would otherwise discard the held INVITE with nothing said: the
            // only other trigger is the next TLS packet, and there is not
            // going to be one. The recovered messages are too late to enter
            // the pipeline here, but they are NOT too late to be counted, and
            // a run that silently dropped what it was holding is exactly the
            // missing measurement this feature exists to remove.
            #[cfg(feature = "tls")]
            if let Some(ref mut d) = tls_decryptor {
                let late = d.rewind();
                if !late.is_empty() {
                    tracing::warn!(
                        "TLS late decrypt: {} record(s) opened only after the capture ended \
                         -- their keys arrived too late to place the messages in this run. \
                         Re-read the saved capture with the same keylog to see them.",
                        late.len()
                    );
                }
            }

            #[cfg(feature = "tls")]
            let tls_report = tls_decryptor
                .as_ref()
                .map(crate::capture::decrypt::TlsDecryptor::report)
                .unwrap_or_default();
            #[cfg(not(feature = "tls"))]
            let tls_report = crate::capture::TlsDecryptReport::default();
            for line in tls_decrypt_guidance(&tls_report, &mapped_tls_libraries()) {
                eprintln!("{line}");
            }

            // Guidance when no SIP signaling was found — and, when the
            // capture did not decode, a refusal to state that absence as a
            // finding. See `no_sip_guidance` for why the choice of sentence
            // is the whole point.
            if counters.sip_count == 0 {
                for line in no_sip_guidance(
                    counters.rtp_count,
                    stream_count,
                    &undecodable,
                    total_count,
                    &tls_report,
                ) {
                    eprintln!("{line}");
                }
            }
        }

        // If any companion server is running, keep the process alive so clients
        // can query the captured data. Poll the shutdown flag so SIGINT/SIGTERM
        // exits cleanly instead of blocking on a thread that never returns.
        if let Some(servers) = servers {
            #[cfg(feature = "api")]
            if cli.listener_args.api.is_some() {
                tracing::info!("API server active — press Ctrl-C to stop");
            }
            #[cfg(feature = "mcp")]
            if cli.mcp_args.mcp {
                tracing::info!("MCP server active — press Ctrl-C to stop");
            }
            while !signals::shutdown_requested() {
                // A stdio MCP client owns the lifetime: when it closes stdin the
                // serve task finishes, and there is no client left to serve — so
                // exit instead of spinning forever (otherwise the process leaks
                // until SIGINT). HTTP/API tasks only finish on a signal, so the
                // flag stays unset there.
                if mcp_stdio_client_gone(servers.mcp_stdio_done.as_ref()) {
                    tracing::info!("MCP client disconnected — shutting down");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }

        // Report a truncated output as a failure. This runs after the sink
        // flush, the writer's finish(), the kill-worker shutdown and the
        // capture-thread join, so nothing is skipped to get here — the exit
        // code is the only thing that changes.
        //
        // Reports still print above: a partial capture is worth looking at,
        // it just must not be mistaken for a whole one by a script reading $?.
        //
        // `run_integrity::run_failed()` is the FILE path's half of the same
        // rule the two flags above implement for the live path. Reading a set
        // of files deliberately continues past a truncated member and returns
        // Ok, so `capture_failed` never sees it — and a truncated pcap or a
        // `--plugin` that would not load exited 0 with a whole-looking report.
        // 1, not a new code: docs/cli-reference.md already assigns 1 to
        // "capture error, I/O error", and both of these are exactly that. 3 is
        // reserved for the opposite situation — the tool worked and the
        // CAPTURE is non-conformant — so spending it here would erase the
        // distinction it exists to make.
        if output_failed || capture_failed || crate::output::run_integrity::run_failed() {
            std::process::exit(1);
        }
        // 3, not 1. A pipeline has to tell "sipnab broke" from "the capture is
        // non-conformant": the first means investigate the tool, the second
        // means fix the config that produced the traffic. Collapsing them
        // would make a working gate indistinguishable from a broken one, and
        // 1 and 2 already mean something else (#147).
        //
        // Checked AFTER the failure codes above, so a run that both failed to
        // write its output and found lint errors reports the failure — the
        // findings came from a partial read and are not trustworthy anyway.
        if lint_gate_tripped {
            std::process::exit(3);
        }
    }
}

/// Whether the wait loop that keeps a batch run alive for its companion
/// servers should stop because the stdio MCP client has closed its end.
///
/// A stdio MCP client owns the process lifetime: once its `mcp_stdio_done`
/// flag flips (it closed stdin, so the serve task finished), there is no
/// client left to serve and the process must exit rather than spin forever.
/// The flag is `None` for HTTP/API-only runs — those finish on a signal
/// instead — so this stays `false` there, and `false` while a stdio client is
/// still connected (flag present but unset).
fn mcp_stdio_client_gone(
    mcp_stdio_done: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> bool {
    mcp_stdio_done.is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
}

// ── Packet processing ─────────────────────────────────────────────────

/// Decide whether a SIP message should be emitted, updating dialog-follow and
/// trailing-context state.
///
/// This implements two overlapping selection rules:
///
/// * **Dialog-following** (`-e`): when `follow_dialogs` is set, a
///   `direct_match` arms the message's dialog, and every later message of an
///   armed dialog is emitted regardless of its own content. Followed messages
///   are not "trailing context" and never spend the `-A` budget.
/// * **Trailing context** (`-A N`): a `direct_match` (re)arms an `after_count`
///   budget; the next non-matching messages are emitted until it drains.
///
/// With `follow_dialogs == false` the follow set stays empty and behavior is
/// identical to trailing-context-only selection.
///
/// # Arguments
///
/// * `direct_match` — the message itself passed matcher + DSL + calls-only.
/// * `call_id` — the message's Call-ID, when present.
/// * `follow_dialogs` — dialog-following (`-e`) is active.
/// * `followed` — set of armed Call-IDs; mutated when a match arms one.
/// * `trailing_remaining` — live `-A` budget; mutated as described above.
/// * `after_count` — the `-A N` budget granted per direct match.
///
/// # Returns
///
/// `true` when the message should be emitted.
fn decide_emit(
    direct_match: bool,
    call_id: Option<&str>,
    follow_dialogs: bool,
    followed: &mut std::collections::HashSet<String>,
    trailing_remaining: &mut usize,
    after_count: usize,
) -> bool {
    let followed_match = follow_dialogs && call_id.is_some_and(|id| followed.contains(id));

    // A direct match arms the dialog so its remaining messages follow.
    if direct_match
        && follow_dialogs
        && let Some(id) = call_id
    {
        followed.insert(id.to_string());
    }

    let trailing_match = *trailing_remaining > 0;
    let emit = direct_match || followed_match || trailing_match;

    if emit {
        if direct_match {
            // A fresh match re-arms the trailing (`-A`) budget.
            *trailing_remaining = after_count;
        } else if trailing_match && !followed_match {
            // Only pure trailing-context messages spend the budget; a
            // followed-dialog message emits without consuming it.
            *trailing_remaining -= 1;
        }
    }

    emit
}

/// Process a single parsed packet: classify via the shared pipeline core,
/// then apply the batch extras — counters, matcher/DSL filter, output
/// dispatch, security detectors, dialog events, DTMF, quality events.
///
/// # Arguments
///
/// * `pp` — the parsed (and possibly TLS-decrypted) packet to classify.
/// * `ctx` — immutable per-run configuration (matcher, filter, CLI, ports).
/// * `state` — mutable stores, heuristic, event engine, and media-decrypt
///   state (the store guards are held by the caller).
/// * `engines` — security detectors, alert engine, and kill-worker handle.
/// * `counters` — SIP/RTP counts and emit-selection state, updated here.
/// * `effects` — where the side effects go instead of happening. See
///   [`DeferredEffects`]: this function runs with both store write locks held,
///   and neither a `fork`/`exec` nor a third lock nor a `write(2)` belongs in
///   there. The caller replays them once the guards drop.
///
/// # Side effects
///
/// Mutates the dialog and stream stores; decrypts SRTP payloads in place via
/// the pipeline; hands kill requests to the isolated worker for detected or
/// targeted scanners; and logs DTMF/STIR-SHAKEN details. Alert findings,
/// `--on-*` exec events and hexdump/fail2ban/per-message output are QUEUED —
/// into `effects` and into the event-exec engine's own pending queue — not
/// performed.
fn process_parsed_packet(
    pp: &ParsedPacket,
    ctx: &BatchContext<'_>,
    state: &mut ProcessingState<'_>,
    engines: &mut DetectionEngines,
    counters: &mut PacketCounters,
    effects: &mut DeferredEffects,
) {
    let matcher = ctx.matcher;
    let filter_expr = ctx.filter_expr;
    let output_opts = ctx.output_opts;
    let cli = ctx.cli;
    let no_rtp = ctx.no_rtp;
    let after_count = ctx.after_count;
    let portrange = ctx.portrange;
    let dialog_store = &mut *state.dialog_store;
    let stream_store = &mut *state.stream_store;
    let event_exec = &mut *state.event_exec;
    let group = &mut state.group;
    let scanner_detector = &mut engines.scanner;
    let fraud_detector = &mut engines.fraud;
    let digest_detector = &mut engines.digest;
    let reg_flood_detector = &mut engines.reg_flood;
    let scanner_kill_handle = &engines.kill_handle;
    let kill_response_code = engines.kill_response_code;
    let kill_targets = &engines.kill_targets;
    let sip_count = &mut counters.sip_count;
    let rtp_count = &mut counters.rtp_count;
    let dtmf_count = &mut counters.dtmf_count;
    let prev_timestamp = &mut counters.prev_timestamp;
    let trailing_remaining = &mut counters.trailing_remaining;
    let followed_dialogs = &mut counters.followed_dialogs;
    // Split the borrow: the output buffer and the alert queue are disjoint
    // fields, and the emitters below interleave with the detectors.
    let DeferredEffects {
        out,
        alerts: pending_alerts,
        evidence: evidence_sink,
    } = effects;
    // Hexdump output (applies to all packets)
    if cli.output_args.hexdump && cli.mode_args.no_tui {
        let dump = output::hexdump(&pp.payload);
        write!(
            out,
            "{} {}:{} -> {}:{} {}\n{}",
            pp.timestamp.format("%H:%M:%S%.3f"),
            pp.src_addr,
            pp.src_port,
            pp.dst_addr,
            pp.dst_port,
            pp.transport,
            dump,
        );
    }

    // Classify via the shared pipeline core (WS unwrap, SIP parse + SDP link
    // extraction, SDES/DTLS key learning, RTCP/RTP/heuristic detection), then
    // apply the action with the batch extras: counters, matcher/DSL filter,
    // output dispatch, security detectors, events, DTMF.
    let opts = crate::pipeline::PipelineOptions {
        no_dialog: cli.dialog_args.no_dialog,
        no_rtp,
        sip_portrange: Some(portrange),
        quiet_bad_parse: cli.capture_args.quiet_bad_parse,
    };
    #[cfg(feature = "tls")]
    let mut decrypt = crate::pipeline::MediaDecrypt {
        srtp: state.srtp.as_deref_mut(),
        dtls: state.dtls.as_deref_mut(),
    };
    #[cfg(not(feature = "tls"))]
    let mut decrypt = crate::pipeline::MediaDecrypt::default();

    match crate::pipeline::classify_packet(pp, state.rtp_heuristic, &opts, &mut decrypt) {
        crate::pipeline::PacketAction::None => {}
        crate::pipeline::PacketAction::Sip { msg, sdp_links } => {
            let sip_msg = msg;
            *sip_count += 1;

            // Apply matcher (header-level filters)
            let matcher_pass = matcher.matches(&sip_msg);

            // Track dialog regardless of filter (needed for filter DSL evaluation)
            if !cli.dialog_args.no_dialog {
                // Fire event exec before updating state (captures state change)
                let prev_state = sip_msg
                    .call_id()
                    .and_then(|id| dialog_store.get(id))
                    .map(|d| d.state().clone());

                dialog_store.process_message(sip_msg.clone());

                // Apply --tag to the dialog
                if let Some(ref tag_label) = cli.dialog_args.tag
                    && let Some(call_id) = sip_msg.call_id()
                    && let Some(dialog) = dialog_store.get_mut(call_id)
                    && !dialog.tags.contains(tag_label)
                {
                    dialog.tags.push(tag_label.clone());
                }

                // Check if state changed, fire event
                if let Some(call_id) = sip_msg.call_id()
                    && let Some(dialog) = dialog_store.get(call_id)
                    && prev_state.as_ref() != Some(dialog.state())
                {
                    // Queued, not fired: the command is decided here (it reads
                    // the dialog, which needs this lock) and spawned by the
                    // caller once the guards drop.
                    event_exec.queue_dialog_event(dialog);
                }

                // Link SDP media endpoints to RTP streams, carrying WHERE the
                // offer came from and WHEN it was seen. Both decide what a
                // stream created later may claim from it: a binding across
                // sources is a weaker tie and must say so, and an offer stale
                // enough to belong to a previous call on the same socket must
                // claim nothing (F3).
                //
                // This applier used the provenance-less call until 0.5.122,
                // alone among the four, so `sdp_endpoint_expired` refused to
                // age ANY endpoint on the `-N -I file` path -- it declines to
                // guess an age it was never given. Nothing errored, which is
                // why it survived.
                let provenance = crate::rtp::stream_store::SdpProvenance::observed(
                    pp.input_origin,
                    pp.timestamp,
                );
                for (ip, port, call_id, media) in &sdp_links {
                    stream_store
                        .link_to_dialog_with_sdp_from(*ip, *port, call_id, media, provenance);
                }
            }

            // Apply DSL filter (evaluated after dialog update)
            let filter_pass = if let Some(expr) = &filter_expr {
                if let Some(call_id) = sip_msg.call_id() {
                    if let Some(dialog) = dialog_store.get(call_id) {
                        let dialog_streams: Vec<&crate::rtp::stream::RtpStream> =
                            stream_store.streams_for(call_id).collect();
                        expr.matches_dialog(
                            dialog,
                            &dialog_streams,
                            crate::rtp::diagnosis::CaptureMedia::of_store(stream_store),
                            crate::rtp::quality::MosDelay::from_capture(stream_store),
                        )
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                true
            };

            // Security detection: every armed detector runs here, under the
            // guards, and returns what should follow rather than doing it;
            // the effects are applied right below. The fraud detector reads
            // the dialog this message belongs to, looked up only when it is
            // armed, so an unarmed run pays no hash lookup for it.
            let dialog = if fraud_detector.is_some() {
                sip_msg.call_id().and_then(|id| dialog_store.get(id))
            } else {
                None
            };
            let mut detectors = sec::detectors::Detectors {
                scanner: scanner_detector.as_mut(),
                fraud: fraud_detector.as_mut(),
                digest: digest_detector.as_mut(),
                reg_flood: reg_flood_detector.as_mut(),
                kill_targets,
            };
            let policy = sec::detectors::Policy {
                fail2ban: cli.output_args.fail2ban,
                hep_allow_kill: cli.security_args.hep_allow_kill,
                origin: pp.input_origin,
                kill_armed: scanner_kill_handle.is_some(),
                kill_response_code,
            };
            for effect in sec::detectors::run_detectors(&mut detectors, &sip_msg, dialog, policy) {
                apply_detector_effect(
                    effect,
                    sip_msg.timestamp,
                    out,
                    pending_alerts,
                    scanner_kill_handle,
                    evidence_sink,
                    policy,
                );
            }

            // STIR/SHAKEN extraction (I1)
            #[cfg(feature = "tls")]
            if cli.security_args.stir_shaken
                && let Some(result) = sip_msg.stir_shaken()
            {
                match result {
                    Ok(info) => {
                        tracing::info!(
                            "STIR/SHAKEN: attest={:?} orig={} dest={} verified={:?}",
                            info.attestation,
                            info.orig_tn.as_deref().unwrap_or("-"),
                            info.dest_display(),
                            info.verified,
                        );
                    }
                    Err(e) => {
                        tracing::debug!("STIR/SHAKEN parse error: {e}");
                    }
                }
            }

            // I5: --calls-only: skip non-INVITE dialogs from output
            let calls_only_pass = if cli.mode_args.calls_only {
                if let Some(call_id) = sip_msg.call_id()
                    && let Some(dialog) = dialog_store.get(call_id)
                {
                    dialog.method == crate::sip::SipMethod::Invite
                } else {
                    // No dialog tracked — only show if it's an INVITE request
                    sip_msg.method.as_ref() == Some(&crate::sip::SipMethod::Invite)
                }
            } else {
                true
            };

            // Emit if the message directly matches, if it belongs to a dialog
            // armed by a `-e` payload match (dialog-following), or if trailing
            // context (`-A`) is still active.
            let direct_match = matcher_pass && filter_pass && calls_only_pass;
            let follow_dialogs = cli.matching_args.match_expr.is_some();
            let emit = decide_emit(
                direct_match,
                sip_msg.call_id(),
                follow_dialogs,
                followed_dialogs,
                trailing_remaining,
                after_count,
            );

            if emit && cli.mode_args.no_tui {
                dispatch_sip_output(
                    &sip_msg,
                    output_opts,
                    cli,
                    *prev_timestamp,
                    out,
                    group.as_deref_mut(),
                );
            }

            *prev_timestamp = Some(sip_msg.timestamp);
        }
        crate::pipeline::PacketAction::RelayControl { sdp_links } => {
            // A standalone media relay carries no SIP, so on that host this is
            // the ONLY thing that names a call. Without it every stream in the
            // capture reports orphaned.
            if !sdp_links.is_empty() {
                crate::pipeline::apply_relay_control_links(
                    stream_store,
                    &sdp_links,
                    pp.input_origin,
                    pp.timestamp,
                );
            }
        }
        crate::pipeline::PacketAction::Rtcp(rtcp_packets) => {
            stream_store.process_rtcp(&rtcp_packets, pp.timestamp);
        }
        crate::pipeline::PacketAction::Rtp {
            hdr: rtp_hdr,
            decrypted_payload,
            via_heuristic,
        } => {
            // Heuristically-discovered streams keep the pre-existing batch
            // contract: stream tracking only — no DTMF, no quality events.
            if via_heuristic {
                stream_store.process_rtp(pp, &rtp_hdr, pp.timestamp);
                *rtp_count += 1;
                return;
            }

            // SRTP: classification substituted a plaintext payload when a key
            // authenticated the packet. The auth tag is the gate — a wrong
            // key never produces plaintext.
            let srtp_decrypted: Option<ParsedPacket> = decrypted_payload.map(|plain| {
                let mut d = pp.clone();
                d.payload = plain;
                d
            });
            let rtp_pp: &ParsedPacket = srtp_decrypted.as_ref().unwrap_or(pp);

            stream_store.process_rtp(rtp_pp, &rtp_hdr, rtp_pp.timestamp);
            *rtp_count += 1;

            // DTMF extraction (I2): if --telephone-event is set and we have
            // the RTP payload after the header, attempt DTMF decode. The
            // telephone-event payload type and clock rate are negotiated in
            // SDP (`a=rtpmap:<pt> telephone-event/<clock>`), not fixed at the
            // PT 101 / 8000 Hz conventions. `process_rtp` above resolved this
            // stream's codec, payload_type, and clock_rate from that rtpmap,
            // so when the codec is telephone-event we use the stream's
            // negotiated PT and clock; otherwise fall back to the conventions
            // (e.g. a DTMF-only stream with no observed SDP).
            if cli.mode_args.telephone_event && rtp_hdr.payload_offset < rtp_pp.payload.len() {
                let rtp_payload = &rtp_pp.payload[rtp_hdr.payload_offset..];
                let key = crate::rtp::stream::StreamKey {
                    ssrc: rtp_hdr.ssrc,
                    src: std::net::SocketAddr::new(pp.src_addr, pp.src_port),
                    dst: std::net::SocketAddr::new(pp.dst_addr, pp.dst_port),
                };
                let (expected_pt, clock_rate) = stream_store
                    .get(&key)
                    .filter(|s| {
                        s.codec
                            .as_deref()
                            .is_some_and(|c| c.eq_ignore_ascii_case("telephone-event"))
                    })
                    .map(|s| (s.payload_type, s.clock_rate))
                    .unwrap_or((101, 8000));
                if let Some(dtmf) = rtp::dtmf::extract_dtmf_with_clock(
                    rtp_payload,
                    rtp_hdr.payload_type,
                    expected_pt,
                    clock_rate,
                    pp.timestamp,
                ) {
                    *dtmf_count += 1;
                    // The always-on line is masked. A decoded digit is the
                    // caller's secret — after answer these are voicemail PINs,
                    // calling-card and card numbers — and the log is the widest
                    // surface sipnab has: terminal, redirected file, journald,
                    // and any aggregate that ships it onward. Everything an
                    // operator diagnoses with (a digit arrived, when, how long,
                    // on which SSRC) survives masking; only the value does not.
                    tracing::info!(
                        "DTMF digit='{}' duration={}ms ssrc=0x{:08x}",
                        rtp::dtmf::MASKED_DIGIT,
                        dtmf.duration_ms,
                        rtp_hdr.ssrc
                    );
                    // Cleartext is an additional line, not a substitution, and
                    // it sits at `debug` — one level below the masked line's
                    // `info`. Two independent acts are therefore required to
                    // put a PIN on disk: passing --dtmf-cleartext AND raising
                    // SIPNAB_LOG to debug. Emitting it as a separate line also
                    // means turning the flag on never *removes* the diagnostic
                    // the default level already gave you.
                    if cli.mode_args.dtmf_cleartext {
                        tracing::debug!(
                            "DTMF cleartext digit='{}' duration={}ms ssrc=0x{:08x}",
                            dtmf.digit,
                            dtmf.duration_ms,
                            rtp_hdr.ssrc
                        );
                    }
                }
            }

            // Fire quality events on each RTP packet (rate-limited internally). Guard
            // on a configured command so the common no-`--on-quality` path skips the
            // StreamKey rebuild + second store lookup entirely (per-RTP-packet
            // constant-factor cut; fire_quality_event no-ops otherwise).
            if event_exec.quality_events_enabled() {
                let key = crate::rtp::stream::StreamKey {
                    ssrc: rtp_hdr.ssrc,
                    src: std::net::SocketAddr::new(pp.src_addr, pp.src_port),
                    dst: std::net::SocketAddr::new(pp.dst_addr, pp.dst_port),
                };
                if let Some(stream) = stream_store.get(&key) {
                    // Queued, not fired — same reason as the dialog event: the
                    // MOS estimate reads the stream, the `fork`/`exec` does not.
                    event_exec.queue_quality_event(
                        stream,
                        crate::rtp::quality::MosDelay::from_capture(stream_store),
                    );
                }
            }
        }
    }
}

/// Perform one effect a detector asked for: file the finding under its rule
/// name, queue the jail line, or hand the response to the kill worker.
///
/// The rule names are assigned here and nowhere else. `security::detectors`
/// says which detector fired; this is where a finding meets the vocabulary the
/// alert engine, `--alert` rules and the MCP `security_findings` tool share
/// (`SECURITY_FINDING_KINDS`, pinned to these literals by
/// `security_findings_kinds_match_the_names_the_detectors_file_under`).
///
/// # Arguments
///
/// * `effect` — what the detector decided.
/// * `at` — capture time of the message, which every threshold and cooldown
///   in the alert engine is measured against.
/// * `out` — the deferred per-message output a jail line joins.
/// * `pending_alerts` — the findings queued for the alert engine.
/// * `kill_handle` — the kill worker, when one is running.
///
/// # Side effects
///
/// Pushes onto `out` or `pending_alerts`, or sends on the kill worker's
/// channel; a failed send is reported by the handle itself, once.
fn apply_detector_effect(
    effect: sec::detectors::Effect,
    at: chrono::DateTime<chrono::Utc>,
    out: &mut DeferredOutput,
    pending_alerts: &mut Vec<DeferredAlert>,
    kill_handle: &Option<ScannerKillHandle>,
    evidence: &mut Option<sec::evidence::EvidenceSink>,
    policy: sec::detectors::Policy,
) {
    use sec::detectors::{DetectorKind, Effect, JailLine};
    if let (
        Effect::Alert {
            detector,
            src_ip,
            detail,
        },
        Some(sink),
    ) = (&effect, evidence.as_mut())
    {
        // The same origin rule the jail log follows: under HEP the inner
        // address is the sender's claim, and publishing it invites a ban on
        // an address of their choosing.
        if sec::evidence::publishable(policy.origin, policy.hep_allow_kill) {
            let line = sec::evidence::Evidence {
                src_ip: *src_ip,
                rule: sec::evidence::rule_for(*detector).to_string(),
                evidence: detail.clone(),
                ts: Some(at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            };
            if let Err(e) = sink.write(&line) {
                // Best effort, and never silent: a lost finding is a ban that
                // will not happen, and the operator has to know which.
                tracing::warn!(%src_ip, error = %e, "could not publish evidence");
            }
        }
    }
    match effect {
        Effect::Alert {
            detector,
            src_ip,
            detail,
        } => pending_alerts.push(match detector {
            DetectorKind::Scanner => DeferredAlert {
                kind: "scanner",
                src_ip,
                detail,
                at,
            },
            DetectorKind::Fraud => DeferredAlert {
                kind: "fraud",
                src_ip,
                detail,
                at,
            },
            DetectorKind::Digest => DeferredAlert {
                kind: "digest",
                src_ip,
                detail,
                at,
            },
            DetectorKind::RegFlood => DeferredAlert {
                kind: "reg_flood",
                src_ip,
                detail,
                at,
            },
        }),
        Effect::JailLine(line) => {
            let event = match line {
                JailLine::Scanner { src_ip, ua, method } => output::format_scanner_event(
                    &src_ip.to_string(),
                    ua.as_deref(),
                    method.as_deref(),
                ),
                JailLine::RegFlood { src_ip, count } => {
                    output::format_reg_flood_event(&src_ip.to_string(), count)
                }
            };
            out.write_str(&event);
            out.write_str("\n");
        }
        Effect::Kill {
            dst_addr,
            dst_port,
            src_addr,
            src_port,
            response_bytes,
        } => {
            if let Some(handle) = kill_handle {
                let _ = handle.send_kill(KillRequest::SendResponse {
                    dst_addr,
                    dst_port,
                    src_addr,
                    src_port,
                    response_bytes,
                });
            }
        }
    }
}

/// Attempt TLS decryption on a TCP payload.
///
/// If the payload looks like TLS, reassembles it against any tail held from
/// a previous call on the same stream direction (a TLS record routinely
/// spans more than one TCP segment / captured packet — see
/// [`tls::TlsRecordReassembler`]), then tries to decrypt each complete
/// ApplicationData record now available. Returns one synthetic
/// `ParsedPacket` (decrypted payload, transport stamped to reflect the TLS
/// origin) per record whose plaintext is a SIP message — zero, one, or more.
/// Returns empty for non-TCP/non-TLS payloads, when no decryptor is
/// configured, when the reassembled bytes hold no complete record yet, or
/// when nothing decrypts to SIP. As a side effect, Handshake records are fed
/// into the decryptor to capture key material.
#[cfg(feature = "tls")]
fn try_tls_decrypt(
    pp: &ParsedPacket,
    tls_decryptor: &mut Option<TlsDecryptor>,
    tls_reassembler: &mut tls::TlsRecordReassembler,
) -> capture::ParsedPackets {
    let Some(decryptor) = tls_decryptor.as_mut() else {
        return capture::ParsedPackets::new();
    };

    let mut out = capture::ParsedPackets::new();

    // Records held from before their keys existed come FIRST, because they
    // are older than the packet in hand. eCapture writes a session's secrets
    // only after the handshake, so the first application record -- the INVITE,
    // carrying the original SDP offer -- is on the wire before any keylog line
    // for it. Emitting the recovery after the current packet would reconstruct
    // the dialog out of order and put the answer before the offer.
    //
    // Each recovered message keeps the timestamp and endpoints of the packet
    // it actually arrived in, not of the replay: a recovered INVITE stamped
    // now would move post-dial delay and call duration by however long the
    // keys took.
    for recovered in decryptor.rewind_if_keys_changed() {
        // Framed, not sniffed -- for the same reason the live path below is.
        // A recovered INVITE split across two records would otherwise emit its
        // headers and drop its SDP body, which is precisely the defect this
        // whole path exists to fix, reintroduced on the recovery side.
        for msg in
            tls_reassembler.frame_plaintext(recovered.src, recovered.dst, &recovered.plaintext)
        {
            if !sip::is_sip_message(&msg) {
                continue;
            }
            let mut late = pp.clone();
            late.timestamp = recovered.timestamp;
            late.src_addr = recovered.src.ip();
            late.dst_addr = recovered.dst.ip();
            late.src_port = recovered.src.port();
            late.dst_port = recovered.dst.port();
            // The frame pointer and DSCP belong to whatever packet happened to
            // trigger the sweep, not to this message. An honest absence beats
            // another packet's ordinal and digest on the one message an
            // operator is most likely to trace back to bytes.
            late.frame = None;
            late.payload = msg.into();
            late.transport = TransportProto::Tls;
            out.push(late);
        }
    }

    // Non-TCP packets carry no TLS, but reaching this line still served a
    // purpose: the recovery above runs on ANY packet. Gating it behind the
    // TLS checks below meant a session whose keys arrived last could wait for
    // the next TLS-looking packet on that same connection -- which on a quiet
    // trunk may never come, and at end of capture never does.
    if pp.transport != TransportProto::Tcp {
        return out;
    }

    let src = std::net::SocketAddr::new(pp.src_addr, pp.src_port);
    let dst = std::net::SocketAddr::new(pp.dst_addr, pp.dst_port);

    // `is_tls` gates admission for a chunk that would START tracking this
    // stream, but must not gate one that CONTINUES an already-held partial:
    // the tail half of a TLS record split across a TCP segment boundary is
    // ciphertext with no record header of its own, and routinely fails this
    // same heuristic — which is exactly the case `TlsRecordReassembler`
    // exists to handle. Gating on it unconditionally here (as the
    // pre-reassembly version of this function did, before there was
    // anything to hold across calls) silently re-dropped every split
    // record's tail chunk before it ever reached `insert`, defeating the
    // reassembly this same patch added: the SIP message inside kept getting
    // lost the same way, just one layer further down.
    if !tls_reassembler.has_held(src, dst) && !tls::is_tls(&pp.payload) {
        return out;
    }

    let records = tls_reassembler.insert(src, dst, &pp.payload);

    for record in &records {
        // Feed Handshake records (ClientHello/ServerHello/ClientKeyExchange) so
        // the decryptor can capture randoms + the RSA-encrypted pre-master for
        // the --tls-key path and the TLS 1.2 CLIENT_RANDOM keylog path.
        if record.content_type == tls::TlsContentType::Handshake {
            decryptor.process_record(record, src, dst);
            continue;
        }
        if let Some(plaintext) = decryptor.try_decrypt_at(record, src, dst, pp.timestamp) {
            // Frame the decrypted BYTES into SIP messages rather than testing
            // this record for "does it look like SIP". A sender may write one
            // message as several records -- a real trunk sends the INVITE
            // headers in one and the SDP body in the next -- and the per-record
            // test keeps the headers while discarding the body, leaving an
            // INVITE with no offer. sipnab then stores whatever SDP the next
            // hop rewrote and reports a media mismatch that is not in the
            // capture.
            for msg in tls_reassembler.frame_plaintext(src, dst, &plaintext) {
                if !sip::is_sip_message(&msg) {
                    continue;
                }
                // A synthetic ParsedPacket carrying the decrypted SIP, stamped
                // Tls so the pipeline reports the true transport origin.
                let mut decrypted_pp = pp.clone();
                decrypted_pp.payload = msg.into();
                decrypted_pp.transport = TransportProto::Tls;
                out.push(decrypted_pp);
            }
        }
    }

    out
}

// ── SIP output dispatch ──────────────────────────────────────────────

/// Dispatch a matched SIP message to the configured output backend
/// (pretty JSON, NDJSON, fail2ban event, raw text dump, or the default
/// plain print).
///
/// # Arguments
///
/// * `msg` — the SIP message to emit.
/// * `opts` — formatting options for the default text print.
/// * `cli` — flags selecting the backend and suppression modes.
/// * `prev_timestamp` — previous message's timestamp for `--delta-time`.
/// * `out` — the packet's deferred output buffer. The store guards are held
///   for the whole of this call, so the bytes are composed here and reach the
///   real sink from [`DeferredEffects::drain`].
///
/// # Side effects
///
/// Appends to `out` (recording the per-message boundary `--line-buffer`
/// flushes on). Emits nothing in MCP mode (stdout is the JSON-RPC wire) or
/// under `--no-cli-print`.
fn dispatch_sip_output(
    msg: &sip::SipMessage,
    opts: &OutputOptions,
    cli: &Cli,
    prev_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    out: &mut DeferredOutput,
    group: Option<&mut output::group::GroupBuffer>,
) {
    // MCP mode owns stdout (JSON-RPC wire); no per-packet text/JSON output.
    #[cfg(feature = "mcp")]
    if cli.mcp_args.mcp {
        return;
    }
    // --no-cli-print suppresses every per-message dump (text/JSON/fail2ban/raw)
    // so post-capture reports (--call-report, --report) aren't drowned out.
    if cli.output_args.no_cli_print {
        return;
    }
    // --group-by cannot stream: the last packet may belong to the first group,
    // so nothing can be written until the capture ends. Render to a String and
    // buffer it. This is the one path that pays for a per-message allocation,
    // which is why the streaming branches below are left untouched.
    if let Some(buf) = group {
        if let Some(rendered) = render_sip_output(msg, opts, cli, prev_timestamp) {
            buf.push(msg, rendered);
        }
        out.end_message();
        return;
    }
    if cli.output_args.json_pretty {
        let json = output::json::message_to_json_pretty(msg);
        out.write_str(&json);
    } else if cli.output_args.json {
        // Hot path: serialize straight into the deferred buffer — no
        // per-message String, no per-message write(2). The buffer is reused
        // across packets, so this stays allocation-free after the first few
        // messages have sized it.
        // to_writer bypasses the buffer's error tracking, so hand the result
        // back: a full disk here is data loss, not a closed pipe.
        //
        // Pass the io::Error through UNWRAPPED. Boxing it (Error::other)
        // resets the kind to Other, which makes a BrokenPipe from `| head`
        // indistinguishable from ENOSPC — and then the pipeline that is
        // supposed to exit 0 exits 1.
        let r = output::json::write_message_json(msg, out.writer());
        out.record(r);
    } else if cli.output_args.fail2ban {
        // Detections only. The detector paths above write to this same buffer;
        // nothing is emitted per message here. This used to print a line for
        // every SIP request, which on a real carrier trunk named 180 distinct
        // peers — the trunk, the SBCs and the PBX — to a tool whose whole job
        // is to ban what it is handed. The branch stays so `--fail2ban` still
        // suppresses ordinary per-message output.
    } else if cli.output_args.text_dump {
        // Raw SIP message text dump
        let raw = String::from_utf8_lossy(&msg.raw);
        out.write_str(&raw);
        out.write_str("\n");
    } else {
        let text = output::cli_print::format_sip_message(msg, opts, prev_timestamp);
        out.write_str(&text);
    }

    // Records the boundary --line-buffer flushes on; the flush itself happens
    // when the buffer reaches the sink.
    out.end_message();
}

/// Render one message exactly as `dispatch_sip_output` would have written it,
/// returning the bytes instead of emitting them. Used only by `--group-by`,
/// which must hold output back until the capture ends.
///
/// # Returns
/// `None` for a mode that emits nothing for this message (`--fail2ban` skips
/// responses).
fn render_sip_output(
    msg: &sip::SipMessage,
    opts: &OutputOptions,
    cli: &Cli,
    prev_timestamp: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<String> {
    if cli.output_args.json_pretty {
        Some(output::json::message_to_json_pretty(msg))
    } else if cli.output_args.json {
        let mut bytes: Vec<u8> = Vec::new();
        output::json::write_message_json(msg, &mut bytes).ok()?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    } else if cli.output_args.fail2ban {
        // Detections only — see `dispatch_sip_output`. A request is not a
        // detection, and this is the `--group-by` twin of the same defect.
        None
    } else if cli.output_args.text_dump {
        Some(format!("{}\n", String::from_utf8_lossy(&msg.raw)))
    } else {
        Some(output::cli_print::format_sip_message(
            msg,
            opts,
            prev_timestamp,
        ))
    }
}

// ── Report generation ────────────────────────────────────────────────

/// Write `text` to stdout, returning `false` if it could not be delivered.
///
/// A `BrokenPipe` is the reader's choice (`| head`) and counts as success;
/// every other error means the output is incomplete. `print!` would panic on
/// both, which is how `--report` to a full disk exited 101 with a backtrace
/// while `-O` and `--json` reported the same condition as a clean failure.
fn write_stdout(text: &str) -> bool {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => true,
        Err(e) => {
            tracing::error!("Failed to write report: {e}");
            false
        }
    }
}

/// Unwrap a HEP datagram read off the wire, keeping what the wrapper said.
///
/// The inner payload replaces the outer one, which is the point of
/// `--hep-parse`: HEP-encapsulated SIP becomes SIP the parser can read.
///
/// The wrapper's metadata is carried onto the result, and that is not a
/// nicety. rtpengine mirrors its `ng` control plane as HEP, and the pipeline
/// recognizes it two ways -- by `pp.hep` when a listener already stripped the
/// wrapper, or by parsing the wrapper off an intact sniffed datagram. Dropping
/// the metadata here left neither arm able to fire: the wrapper was gone and
/// nothing had recorded what it said, so every mirrored control message was
/// silently discarded and every relay stream stayed unnamed. `--hep-parse` and
/// relay media-naming were mutually exclusive, and nothing said so.
///
/// `correlation_id` matters most: an `ng` REPLY carries no `call-id` at all,
/// and the correlation id is the only thing naming the call it belongs to.
#[cfg(feature = "hep")]
fn unwrap_hep(pp: &ParsedPacket) -> Option<ParsedPacket> {
    if pp.transport != TransportProto::Udp {
        return None;
    }
    let hep = crate::capture::hep::parse_hep(&pp.payload).ok()?;
    let mut unwrapped = pp.clone();
    unwrapped.payload = hep.payload.into();
    unwrapped.src_addr = hep.src_addr;
    unwrapped.dst_addr = hep.dst_addr;
    unwrapped.src_port = hep.src_port;
    unwrapped.dst_port = hep.dst_port;
    unwrapped.hep = Some(crate::capture::packet::HepOrigin {
        protocol: hep.protocol.to_byte(),
        correlation_id: hep.correlation_id.clone(),
    });
    // The inner addressing was asserted by the HEP sender, not observed on the
    // wire, so it is Hep however the wrapper arrived. Under --hep-parse the
    // wrapper is read from a pcap or interface (Wire) and cloned; without this
    // the inner source inherited Wire and passed the kill/jail origin gate,
    // leaving --hep-parse the hole kill_response_eligible closes for
    // --hep-listen.
    unwrapped.input_origin = crate::capture::parse::InputOrigin::Hep;
    Some(unwrapped)
}

/// Generate post-capture reports (`--report`, `--call-report`,
/// `--export-vcon`) from the final store contents. Returns `false` when a
/// requested report could not be produced — an unknown Call-ID at either
/// flag, or a vCon that could not reach `--vcon-out` — so the caller can exit
/// non-zero. Scripts must be able to trust the exit code.
///
/// # Arguments
///
/// * `filter` — the compiled `--filter` expression, or `None` for no filter.
///   These reports render the final stores rather than the packet stream, so
///   they must apply it themselves: it used to be consulted only as packets
///   streamed past, and every valid expression returned the whole capture
///   here, silently, exit 0. `--call-report` names one Call-ID exactly and is
///   deliberately not narrowed — a lookup by name is not a listing.
///
/// # Side effects
///
/// Prints the requested reports to stdout, the not-found error (and the
/// opt-in `SIPNAB_PERF_STATS=1` perf line) to stderr; reads the
/// `SIPNAB_PERF_STATS` environment variable.
pub fn generate_reports(
    cli: &Cli,
    dialog_store: &DialogStore,
    stream_store: &StreamStore,
    filter: Option<&FilterExpr>,
    vcon_filter: Option<&FilterExpr>,
    frames_read: u64,
    gate: Option<&crate::output::persistence::PersistenceGate>,
) -> bool {
    // SNB-0015 probe: set SIPNAB_PERF_STATS=1 to surface the per-run work that
    // scales with call count. `endpoint_link_scan_visits` is the cost that was
    // O(calls²) before the endpoint index; it now grows ~linearly with streams.
    // A value near streams² means the quadratic regression is back.
    if std::env::var_os("SIPNAB_PERF_STATS").is_some() {
        eprintln!(
            "[perf-stats] dialogs={} streams={} endpoint_link_scan_visits={} evict_shift_work={}",
            dialog_store.len(),
            stream_store.len(),
            stream_store.link_scan_iters(),
            stream_store.evict_shift_work(),
        );
    }

    // Idle compaction throws away messages sipnab captured, which makes the
    // ladder for those calls short in every report below. Recorded, not
    // treated as a failure: see `output::run_integrity` for why a configured
    // retention policy doing its job is a fact rather than a non-zero exit.
    // The store's counter is a lifetime total, so it is read here — once, with
    // the final store in hand — rather than accumulated per sweep.
    crate::output::run_integrity::record_retention_drops(
        dialog_store.total_idle_messages_evicted(),
    );

    // --plugin: load BEFORE the first report is rendered, not just before the
    // emit loop that uses them. A plugin that cannot load is still reported and
    // skipped rather than aborting — the capture already happened, and throwing
    // it away because an optional extension was misconfigured would lose real
    // data over a configuration error. But it is no longer silent: the failure
    // is recorded, the run exits non-zero, and every report below carries the
    // marker. That marker has to name the plugin failure, so the load cannot
    // happen after `--report` has already been written to stdout.
    #[cfg(feature = "plugins")]
    let plugins: Vec<crate::plugin::Plugin> = cli
        .output_args
        .plugin
        .iter()
        .filter_map(|path| match crate::plugin::Plugin::load(path) {
            Ok(p) => {
                tracing::info!("loaded plugin {}", p.name());
                Some(p)
            }
            Err(e) => {
                tracing::error!("plugin {}: {e}", path.display());
                None
            }
        })
        .collect();
    // Both numbers, from the one place that knows both: "one plugin failed"
    // and "the only plugin failed" are different reports.
    #[cfg(feature = "plugins")]
    crate::output::run_integrity::record_plugins(crate::output::run_integrity::PluginLoadOutcome {
        requested: cli.output_args.plugin.len(),
        failed: cli.output_args.plugin.len().saturating_sub(plugins.len()),
    });

    // --report: dialog summary table
    if cli.output_args.report && cli.mode_args.no_tui {
        // Filtered: the matching dialogs and the streams linked to them. With
        // no filter this is every dialog and every stream, orphans included —
        // an unfiltered report is unchanged.
        let selection = crate::sip::dsl::select_dialogs(filter, dialog_store, stream_store);
        let dialogs: Vec<&crate::sip::dialog::SipDialog> =
            selection.dialogs.iter().map(|(d, _)| *d).collect();
        // `--markdown` was read, documented and IGNORED here: the output was
        // byte-identical with and without it while the help text said "Format
        // report output as Markdown" (#89).
        let mut report = output::print_dialog_report_as(
            &dialogs,
            &selection.streams,
            if cli.output_args.markdown {
                output::ReportFormat::Markdown
            } else {
                output::ReportFormat::Text
            },
        );
        // A report drawn from a partial read must say so IN the report. The
        // exit status carries the same fact, but a reader looking at this
        // table has no `$?` in front of them, and the table itself looks
        // exactly like a whole one.
        if let Some(notice) = crate::output::run_integrity::report_notice() {
            report.push_str(&notice);
        }
        // `print!` PANICS if stdout cannot be written, so `--report > /full/disk`
        // died with exit 101 and a Rust backtrace instead of an error. A closed
        // pipe stays fine — `sipnab --report | head` must not fail — but a real
        // write error makes the report incomplete, which is a failed report.
        if !write_stdout(&report) {
            return false;
        }
    }

    // --json-dialogs: one NDJSON object per dialog
    if cli.output_args.json_dialogs && cli.mode_args.no_tui {
        // Groups the streams by Call-ID once, where the loop below used to
        // rescan the whole stream store per dialog.
        let selection = crate::sip::dsl::select_dialogs(filter, dialog_store, stream_store);
        let capture = crate::rtp::diagnosis::CaptureMedia::of_store(stream_store);
        let mut out = String::new();
        for (dialog, dialog_streams) in &selection.dialogs {
            let media = crate::rtp::diagnosis::MediaContext::for_dialog(dialog, capture);
            let mut diagnosis = crate::rtp::diagnosis::diagnose_media(dialog_streams, &media);
            crate::rtp::diagnosis::diagnose_asymmetry(
                &mut diagnosis,
                Some(dialog),
                dialog_streams,
                &crate::rtp::diagnosis::AsymmetryThresholds::default(),
            );
            let line = output::dialog_to_ndjson(dialog, dialog_streams, &diagnosis);

            #[cfg(feature = "plugins")]
            let line = apply_plugins(&plugins, dialog, &line);

            out.push_str(&line);
        }
        // The run-integrity trailer, last and only when there is something to
        // declare. NDJSON has no envelope to put a per-run fact in, so the
        // fact travels as its own line under a top-level `sipnab_run` key that
        // no dialog object has — a consumer decides what a line is by looking
        // at it, and one that assumes every line is a dialog now finds no
        // `call_id` and fails, which is the right outcome for an answer drawn
        // from a partial read. Emitted last so a streaming consumer sees the
        // dialogs first and the verdict on all of them after; absent entirely
        // on a clean run, so nothing about today's output changes for the runs
        // that had nothing wrong with them.
        if let Some(line) = crate::output::run_integrity::ndjson_line() {
            out.push_str(&line);
        }
        // Same write discipline as --report: a real write error means the
        // output is incomplete, which is a failed run, while a closed pipe
        // (`| head`) stays fine.
        if !write_stdout(&out) {
            return false;
        }
    }

    // --stun: the STUN/TURN transaction and allocation tables. Read from the
    // process-global store rather than taken as an argument, for the reason the
    // ICMP section of `print_dialog_report` is: a STUN transaction is neither a
    // `SipDialog` nor an `RtpStream`, so it cannot arrive through either slice.
    //
    // Not narrowed by `--filter`: the DSL selects dialogs, and a NAT-discovery
    // probe belongs to no dialog. Filtering it by a dialog filter would drop
    // exactly the evidence that explains why those dialogs have no media.
    if cli.output_args.stun && cli.mode_args.no_tui {
        let report = output::print_stun_report_as(
            &crate::stun::report(),
            if cli.output_args.markdown {
                output::ReportFormat::Markdown
            } else {
                output::ReportFormat::Text
            },
        );
        if !write_stdout(&report) {
            return false;
        }
    }

    // --json-stun: one NDJSON object per transaction, then one per allocation.
    if cli.output_args.json_stun && cli.mode_args.no_tui {
        let out = output::stun_report_ndjson(&crate::stun::report());
        if !write_stdout(&out) {
            return false;
        }
    }

    // --analyze / --json-analyze: every problem in the capture, worst first.
    //
    // Computed once and rendered twice: asking for both forms must not be able
    // to produce two different answers, and `analyze` reads process-global
    // stores whose contents a second call has no reason to change but no
    // guarantee not to.
    //
    // `--filter` narrows the DIALOG selection, exactly as `--report` does, and
    // narrows nothing else. See `crate::analysis::analyze` for why the
    // capture-level findings are deliberately not filtered.
    if (cli.output_args.analyze || cli.output_args.json_analyze) && cli.mode_args.no_tui {
        let analysis = crate::analysis::analyze(dialog_store, stream_store, filter, frames_read);
        if cli.output_args.analyze {
            let report = output::print_analysis_report_as(
                &analysis,
                if cli.output_args.markdown {
                    output::ReportFormat::Markdown
                } else {
                    output::ReportFormat::Text
                },
            );
            if !write_stdout(&report) {
                return false;
            }
        }
        if cli.output_args.json_analyze {
            match serde_json::to_string(&analysis) {
                Ok(mut line) => {
                    line.push('\n');
                    if !write_stdout(&line) {
                        return false;
                    }
                }
                // An analysis that will not serialize is a bug in the type, not
                // a reason to fail the whole run silently.
                Err(e) => tracing::error!("analysis serialization failed: {e}"),
            }
        }
    }

    // --call-report <call-id>: detailed single-call report
    if let Some(ref call_id) = cli.output_args.call_report {
        if let Some(dialog) = dialog_store.get(call_id) {
            let dialog_streams: Vec<&crate::rtp::stream::RtpStream> =
                stream_store.streams_for(call_id).collect();
            let media = crate::rtp::diagnosis::MediaContext::for_dialog(
                dialog,
                crate::rtp::diagnosis::CaptureMedia::of_store(stream_store),
            );
            let mut diagnosis = crate::rtp::diagnosis::diagnose_media(&dialog_streams, &media);
            crate::rtp::diagnosis::diagnose_asymmetry(
                &mut diagnosis,
                Some(dialog),
                &dialog_streams,
                &crate::rtp::diagnosis::AsymmetryThresholds::default(),
            );
            let format = if cli.output_args.json || cli.output_args.json_pretty {
                ReportFormat::Json
            } else if cli.output_args.markdown {
                ReportFormat::Markdown
            } else {
                ReportFormat::Text
            };
            let report = output::generate_call_report(dialog, &dialog_streams, &diagnosis, format);
            print!("{report}");
        } else {
            // eprintln (not tracing) so the failure is visible even with
            // logging off — it decides the process exit code.
            eprintln!("Call-ID '{call_id}' not found in tracked dialogs");
            return false;
        }
    }

    // --export-vcon <call-id>: one observed dialog as a vCon container.
    if !export_vcon(
        cli,
        vcon_filter,
        dialog_store,
        stream_store,
        frames_read,
        gate,
    ) {
        return false;
    }
    true
}

/// The export directory, created if absent.
///
/// Extracted so the failure has a RESULT rather than only a side effect. As an
/// early return inside the writer its removal was invisible: the writes that
/// followed failed too, so the run reported failure either way and no test
/// could tell the two apart. A branch nothing can distinguish is a branch
/// nothing guards.
///
/// # Errors
///
/// When `--export-vcon-dir` is absent, or the path cannot be made a directory.
#[cfg(feature = "vcon")]
fn prepare_export_dir(cli: &Cli) -> Result<&std::path::Path, String> {
    let Some(dir) = cli.output_args.export_vcon_dir.as_deref() else {
        return Err("--export-vcon-when needs --export-vcon-dir. Nothing was exported.".to_owned());
    };
    std::fs::create_dir_all(dir).map_err(|e| {
        format!(
            "Could not create the vCon directory '{}': {e}. Nothing was exported.",
            dir.display()
        )
    })?;
    Ok(dir)
}

/// The inline-media budget this run enforces, from `--vcon-max-inline-media`.
///
/// The flag is in MiB because an operator thinks in MiB; the exporter counts
/// bytes of base64url. Converting here rather than at each call site keeps one
/// definition of what the number means -- two sites doing their own arithmetic
/// is how a flag comes to mean something different depending on which export
/// path produced the container.
#[cfg(feature = "vcon")]
fn media_budget(cli: &Cli) -> Option<usize> {
    cli.output_args
        .vcon_max_inline_media
        .map(|mib| mib.saturating_mul(1024 * 1024))
}

/// The redaction policy this run exports under, or `None`.
///
/// [`Cli::validate`] has already refused `--redact` on a run that exports
/// nothing, so reaching here with the flag set means a container is about to be
/// written.
///
/// # Errors
///
/// Returns a ready-to-print reason. A key that cannot be read is fatal rather
/// than a fall back to a fresh one: an operator who named a file wanted tokens
/// that join against yesterday's export, and quietly drawing a new key would
/// produce a container that looks right and correlates with nothing.
#[cfg(feature = "vcon")]
fn redaction_policy(cli: &Cli) -> Result<Option<crate::output::redact::RedactionPolicy>, String> {
    use crate::output::redact::{RedactionKey, RedactionPolicy};
    if !cli.redacting() {
        return Ok(None);
    }
    let key = match cli.output_args.redact_key_file.as_deref() {
        Some(path) => {
            let secret = std::fs::read(path)
                .map_err(|e| format!("cannot read --redact-key-file '{}': {e}", path.display()))?;
            RedactionKey::from_secret(&secret)
        }
        None => RedactionKey::ephemeral().map_err(|e| {
            format!(
                "--redact needs a key and none was supplied, so sipnab drew one from \
                 the operating system and could not: {e}. There is no weaker fallback: \
                 a guessable key makes every token in the export reversible by anyone \
                 holding a phone book. Pass --redact-key-file, or fix the entropy source"
            )
        })?,
    };
    Ok(Some(RedactionPolicy::new(key).with_keep_prefix(
        cli.output_args.redact_keep_prefix.unwrap_or(0),
    )))
}

/// Write the token-to-original table, owner-readable only.
///
/// # Errors
///
/// Returns a ready-to-print reason. An existing file is refused rather than
/// replaced: it may be the map for containers that have already been sent
/// somewhere, and overwriting it strands them.
#[cfg(feature = "vcon")]
fn write_redaction_map(
    path: &std::path::Path,
    redactor: &crate::output::redact::Redactor<'_>,
) -> Result<usize, String> {
    use std::io::Write as _;
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(format!(
            "--redact-map '{}' already exists and sipnab will not write over it. \
             That file may be the only way back from tokens already sent somewhere",
            path.display()
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Set at CREATION, not with a chmod afterwards. Between an open and a
        // chmod the file exists at whatever the umask allows, and this file is
        // the reversal of every pseudonym in the export.
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create --redact-map '{}': {e}", path.display()))?;
    let table = redactor.mappings();
    for (token, original) in &table {
        writeln!(file, "{token}\t{original}")
            .map_err(|e| format!("writing --redact-map '{}': {e}", path.display()))?;
    }
    Ok(table.len())
}

/// Write one container per dialog the predicate selected.
///
/// Reports the count on stderr rather than staying silent. A run that matched
/// nothing and a run that wrote forty containers look identical from the shell
/// otherwise, and the first is the one an operator needs to know about --
/// `--export-vcon` already refuses silence for the same reason.
#[cfg(feature = "vcon")]
fn export_vcon_selection(
    cli: &Cli,
    vcon_filter: Option<&crate::sip::dsl::FilterExpr>,
    dialog_store: &DialogStore,
    stream_store: &StreamStore,
    frames_read: u64,
    gate: Option<&crate::output::persistence::PersistenceGate>,
) -> bool {
    let (selection, suppressed_by_deny, denied) =
        match vcon_selection(cli, vcon_filter, dialog_store, stream_store) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{e:#}");
                return false;
            }
        };
    let dir = match prepare_export_dir(cli) {
        Ok(dir) => dir,
        Err(message) => {
            eprintln!("{message}");
            return false;
        }
    };

    let policy = match redaction_policy(cli) {
        Ok(p) => p,
        Err(reason) => {
            eprintln!("{reason}");
            return false;
        }
    };
    // ONE redactor for the whole run, not one per container. The reverse table
    // it accumulates is what `--redact-map` writes, and a redactor per
    // container would hand back as many partial tables as there were dialogs.
    let redactor = policy
        .as_ref()
        .map(crate::output::redact::RedactionPolicy::redactor);

    let mut facts =
        crate::analysis::CaptureFacts::observed(dialog_store, stream_store, frames_read);
    // What this run deliberately did not write. Recorded on the facts BEFORE
    // the analysis runs, so every container built from them carries the same
    // account -- a container that named a different number from its siblings
    // would read as two runs.
    facts.dialogs_suppressed_by_deny = suppressed_by_deny;
    facts.gate_closed_during_run =
        gate.is_some_and(crate::output::persistence::PersistenceGate::closed_during_run);
    let analysis = crate::analysis::analyze_with(dialog_store, stream_store, None, &facts);
    let mut written = 0_usize;
    for (dialog, _) in &selection.dialogs {
        let container = crate::output::vcon::export_dialog(
            dialog,
            &crate::output::vcon::ExportContext {
                capture_id: crate::output::vcon::dialog_capture_id(dialog),
                facts: &facts,
                analysis: Some(&analysis),
                max_inline_media_bytes: media_budget(cli),
            },
        );
        let json = match crate::output::vcon::sealed_json(&crate::output::vcon::seal(
            container,
            redactor.as_ref(),
        )) {
            Ok(j) => j,
            Err(e) => {
                eprintln!(
                    "The vCon for Call-ID '{}' would not serialize: {e}",
                    dialog.call_id
                );
                return false;
            }
        };
        let path = dir.join(vcon_file_name(&dialog.call_id));
        if let Err(e) = write_container_atomically(&path, json.as_bytes()) {
            eprintln!(
                "Could not write '{}': {e}. {written} container(s) were written before this.",
                path.display()
            );
            return false;
        }
        if cli.output_args.vcon_digest {
            // stdout, while the summary below goes to stderr: the digests are
            // data an operator redirects to a file, and mixing them with
            // progress text would put a "Wrote N containers" line inside their
            // SHA256SUMS.
            println!("{}", digest_line(&path, json.as_bytes()));
        }
        written += 1;
    }

    // Tombstones last, and only on request. Writing them at all reveals that
    // the calls EXISTED, which is a disclosure an operator has to choose --
    // see `--content-deny-tombstone`. The default discards `denied` here.
    if cli.output_args.content_deny_tombstone {
        let header = cli
            .output_args
            .content_deny_header
            .as_deref()
            .unwrap_or("(unnamed)");
        for dialog in &denied {
            let container = crate::output::vcon::export_withheld_dialog(
                dialog,
                &crate::output::vcon::ExportContext {
                    capture_id: crate::output::vcon::dialog_capture_id(dialog),
                    facts: &facts,
                    analysis: Some(&analysis),
                    max_inline_media_bytes: media_budget(cli),
                },
                header,
            );
            let json = match crate::output::vcon::sealed_json(&crate::output::vcon::seal(
                container,
                redactor.as_ref(),
            )) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!(
                        "The withheld-dialog vCon for Call-ID '{}' would not serialize: {e}",
                        dialog.call_id
                    );
                    return false;
                }
            };
            let path = dir.join(vcon_file_name(&dialog.call_id));
            if let Err(e) = write_container_atomically(&path, json.as_bytes()) {
                eprintln!(
                    "Could not write '{}': {e}. {written} container(s) were written before this.",
                    path.display()
                );
                return false;
            }
            if cli.output_args.vcon_digest {
                println!("{}", digest_line(&path, json.as_bytes()));
            }
            written += 1;
        }
    }

    if let Some(r) = redactor.as_ref() {
        let report = r.policy().report();
        // On stderr beside the count, because an operator has to be able to
        // say what was redacted and how reversible it is without opening a
        // container. The same report travels INSIDE every container too.
        eprintln!(
            "Redaction: {} classes, key {}, {} leading digit(s) retained.",
            report.classes.len(),
            report.key_mode,
            report.keep_prefix,
        );
        if let Some(path) = cli.output_args.redact_map.as_deref() {
            match write_redaction_map(path, r) {
                Ok(n) => eprintln!(
                    "Wrote {n} token mapping(s) to '{}' (mode 0600). It reverses every \
                     pseudonym in these containers, so it is as sensitive as the capture.",
                    path.display()
                ),
                Err(reason) => {
                    eprintln!("{reason}");
                    return false;
                }
            }
        }
    }
    eprintln!("Wrote {written} vCon container(s) to '{}'.", dir.display());
    true
}

/// A container's SHA-256, in the format `sha256sum` reads and writes.
///
/// Two spaces between the digest and the name is not cosmetic: it is the
/// separator `sha256sum -c` expects for a binary-mode entry, and one space
/// makes the line unparseable to the tool this exists to interoperate with.
///
/// The NAME is the file name alone rather than the full path, so a spool
/// moved or mounted elsewhere still verifies from inside its own directory.
#[cfg(feature = "vcon")]
fn digest_line(path: &std::path::Path, bytes: &[u8]) -> String {
    // The digest comes from the exporter rather than from a second `Sha256`
    // written here. `export_vcon` publishes the same value over MCP, and two
    // implementations of "a container's digest" is the pair this repository
    // keeps finding half-fixed.
    let hex = crate::output::vcon::container_digest(bytes);
    let name = path
        .file_name()
        .map_or_else(|| std::borrow::Cow::Borrowed("-"), |n| n.to_string_lossy());
    format!("{hex}  {name}")
}

/// Where a container is staged before it takes its final name.
///
/// Beside the destination, never in the system temp directory: `rename` is
/// atomic only within one filesystem, and across a mount boundary it either
/// fails outright or degrades into a copy, which reintroduces the partial file
/// this exists to prevent.
///
/// Dot-prefixed so an ordinary directory listing does not show it. A bridge
/// polling the spool reads what it sees, and a staging file it can see is a
/// container it will eventually try to parse.
#[cfg(feature = "vcon")]
fn spool_staging_path(destination: &std::path::Path) -> PathBuf {
    let name = destination.file_name().map_or_else(
        || std::borrow::Cow::Borrowed("vcon"),
        |n| n.to_string_lossy(),
    );
    destination.with_file_name(format!(".{name}.partial"))
}

/// Write one container so a reader sees it whole or not at all.
///
/// `--export-vcon-dir` is a queue an external bridge polls, and the contract
/// it needs is that a name resolves to a complete container. `std::fs::write`
/// cannot offer that: it truncates the destination and then fills it, so every
/// byte of the write is a window in which the file exists and is invalid, and
/// a failure inside that window destroys the previous container too.
///
/// Staging plus rename removes the window. The data is flushed to the
/// filesystem before the rename so a crash cannot leave the name pointing at a
/// file whose contents have not landed.
#[cfg(feature = "vcon")]
fn write_container_atomically(destination: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let staged = spool_staging_path(destination);

    // Every failure below removes the staging file, including the ones that
    // happen before the rename is reached. Cleaning up on the rename's error
    // arm alone left a `.partial` behind whenever the WRITE failed -- a full
    // disk, which is the most likely way any of this fails, is exactly the
    // case that leaves litter and then keeps leaving it.
    let result = stage_container(&staged, bytes)
        .and_then(|()| std::fs::rename(&staged, destination))
        .and_then(|()| sync_directory_of(destination));
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    result
}

/// Write the bytes to the staging path and put them on the disk.
#[cfg(feature = "vcon")]
fn stage_container(staged: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut file = std::fs::File::create(staged)?;
    file.write_all(bytes)?;
    // Durability before visibility: a rename that beats its own data to disk
    // leaves the spool naming a container that is not there yet.
    file.sync_all()
}

/// Put the RENAME on the disk, not just the bytes it made visible.
///
/// `sync_all` on the file covers its contents. The directory entry the rename
/// created is separate metadata, and until the directory itself is synced a
/// crash can lose the entry while keeping the data — the spool then has no
/// container under a name it briefly had, which is the same defect one level
/// up from the truncation this function exists to prevent.
///
/// A filesystem that refuses `fsync` on a directory is not an error to report:
/// some network and virtual filesystems answer `EINVAL`, and the write itself
/// succeeded. Refusing the container over it would turn a durability nicety
/// into a hard failure on those mounts.
#[cfg(feature = "vcon")]
fn sync_directory_of(destination: &std::path::Path) -> std::io::Result<()> {
    let Some(parent) = destination.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    let dir = std::fs::File::open(parent)?;
    match dir.sync_all() {
        Err(e) if matches!(e.kind(), std::io::ErrorKind::InvalidInput) => Ok(()),
        other => other,
    }
}

/// A Call-ID rendered as one safe filename.
///
/// Every character outside `[A-Za-z0-9._-]` becomes `_`, and a name that
/// would still read as a traversal is prefixed. A Call-ID is text whoever
/// placed the call chose, and `--export-vcon-dir` is the first path in this
/// program built from one -- `--export-vcon` wrote to the single path an
/// operator typed and never had this exposure.
#[cfg(feature = "vcon")]
fn vcon_file_name(call_id: &str) -> String {
    let mut safe: String = call_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // No guard for an all-dots Call-ID. `.` and `..` are the two names every
    // directory already owns, and the extension below is what makes them
    // unreachable: `..` becomes `...vcon.json`. A defensive prefix here read
    // as the thing holding that property and held nothing -- removing it left
    // every test green, which is how it was found.
    safe.truncate(180);
    // A digest of the ORIGINAL Call-ID, because the stem above is lossy twice
    // over: every character outside the allowed set collapses to `_`, so `a@b`
    // and `a_b` rendered identically, and the truncation hides any difference
    // past the cut. Either collision overwrote one container with another and
    // reported nothing -- a dialog gone from an export that still looks
    // complete. The stem stays first so the directory is readable; the suffix
    // carries the distinction the stem loses.
    //
    // Sixteen hex characters of SHA-256. Short enough to leave the Call-ID
    // legible, and far past what a capture's worth of dialogs could collide on.
    let digest = <sha2::Sha256 as sha2::Digest>::digest(call_id.as_bytes());
    let short: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{safe}-{short}.vcon.json")
}

/// The dialogs `--export-vcon-when` selects, with their streams.
///
/// Delegates to [`crate::sip::dsl::select_dialogs`] rather than walking the
/// store here. That function resolves this run's ICMP media evidence against
/// the whole stream store, and `--report` and `--json-dialogs` both pass
/// through it, so a second selection path would hand containers a different
/// view of one capture from the one the report shows.
///
/// # Errors
///
/// When the expression does not parse. `--export-vcon-when` is validated
/// before the capture opens as well, so reaching this is a defect rather than
/// an operator's typo -- but returning the error costs nothing and a silent
/// empty selection would look exactly like a capture that matched nothing.
#[cfg(feature = "vcon")]
fn vcon_selection<'a>(
    cli: &Cli,
    resolved: Option<&crate::sip::dsl::FilterExpr>,
    dialog_store: &'a DialogStore,
    stream_store: &'a StreamStore,
) -> anyhow::Result<(
    crate::sip::dsl::DialogSelection<'a>,
    u64,
    Vec<&'a crate::sip::dialog::SipDialog>,
)> {
    let Some(expr) = cli.output_args.export_vcon_when.as_deref() else {
        return Ok((
            crate::sip::dsl::select_dialogs(None, dialog_store, stream_store),
            0,
            Vec::new(),
        ));
    };
    let deny = cli.output_args.content_deny_header.as_deref();
    // The PLAN resolved this, through the same path `--filter` goes through --
    // the one place a diagnostic alias expands and the operator's
    // `[diagnosis]` thresholds are read. Parsing the raw string here instead
    // is what made `--filter problems` work and `--export-vcon-when problems`
    // fail, though cli-reference.md calls them one language.
    //
    // The fallback parse is for callers with no plan (tests), and it is a
    // parse of the same string the plan would have resolved.
    let fallback;
    let parsed = match resolved {
        Some(p) => p,
        None => {
            fallback = crate::sip::dsl::FilterExpr::parse(expr).map_err(|e| {
                anyhow::anyhow!("--export-vcon-when is not a valid filter expression: {e}")
            })?;
            &fallback
        }
    };
    let selection = crate::sip::dsl::select_dialogs(Some(parsed), dialog_store, stream_store);
    // Deny is applied AFTER the predicate and can only remove. Every input
    // other than the command line narrows: nothing read off the network can
    // add a dialog the invocation did not already permit, which is why there
    // is no matching permit branch anywhere in this function.
    Ok(split_denied(selection, deny))
}

/// Partition a selection into what is exported, how many were denied, and the
/// denied dialogs themselves.
///
/// Extracted so the filter has an argument and a return value instead of only
/// a side effect on a value built three calls away. Reached through
/// `vcon_selection` it could only be exercised with a populated stream store,
/// and the test that tried compared zero streams to zero dialogs and passed
/// without touching the behavior.
///
/// `streams` is filtered alongside `dialogs` because [`crate::sip::dsl::DialogSelection`]
/// documents it as the streams linked to a SELECTED dialog, "so the media on
/// screen belongs to the calls on screen". Retaining only `dialogs` left a
/// denied dialog's media in the struct -- suppression that stops halfway, on
/// the one feature whose whole job is to suppress completely.
///
/// Deny only. Nothing here adds a dialog, because every input other than the
/// command line may only narrow.
///
/// Returns the narrowed selection, HOW MANY dialogs it removed, and the denied
/// dialogs. The count is what the container quotes and it cannot be recovered
/// later: by then the denied dialogs are gone, and a difference against the
/// unfiltered store would attribute every other reason for absence to the deny
/// rule.
///
/// The denied dialogs come back rather than being dropped on the floor so
/// `--content-deny-tombstone` can write an identity-only container for each.
/// Returning them does not export them: every caller that does not ask for
/// tombstones discards the third element, and the default is to discard it.
#[cfg(feature = "vcon")]
fn split_denied<'a>(
    mut selection: crate::sip::dsl::DialogSelection<'a>,
    deny: Option<&str>,
) -> (
    crate::sip::dsl::DialogSelection<'a>,
    u64,
    Vec<&'a crate::sip::dialog::SipDialog>,
) {
    let Some(header) = deny else {
        return (selection, 0, Vec::new());
    };
    let denied: Vec<&crate::sip::dialog::SipDialog> = selection
        .dialogs
        .iter()
        .filter(|(dialog, _)| dialog_carries_header(dialog, header))
        .map(|(dialog, _)| *dialog)
        .collect();
    let before = selection.dialogs.len();
    selection
        .dialogs
        .retain(|(dialog, _)| !dialog_carries_header(dialog, header));
    let suppressed = (before - selection.dialogs.len()) as u64;
    let kept: Vec<&crate::rtp::stream::RtpStream> = selection
        .dialogs
        .iter()
        .flat_map(|(_, streams)| streams.iter().copied())
        .collect();
    selection
        .streams
        .retain(|s| kept.iter().any(|k| std::ptr::eq(*k, *s)));
    (selection, suppressed, denied)
}

/// Whether any message in this dialog carries the named header.
///
/// Delegates to [`crate::sip::message::SipMessage::header`], which already
/// compares case-insensitively. A second comparison here would be a second
/// case rule in the tree, and the two would drift.
#[cfg(feature = "vcon")]
fn dialog_carries_header(dialog: &crate::sip::dialog::SipDialog, header: &str) -> bool {
    dialog.messages.iter().any(|m| m.header(header).is_some())
}

/// Write the `--export-vcon` container, or say why it did not.
///
/// Returns `true` when the flag was absent, so the caller reads one answer —
/// "the requested output was produced" — rather than having to know whether
/// this run asked for a container at all.
///
/// The capture analysis is run here rather than reused from `--analyze`,
/// because `--export-vcon` does not require `--analyze` and a container that
/// skipped the analysis reports its blind spots as `null`: "nobody looked",
/// which is a weaker claim than the one this run can make. It is deliberately
/// unfiltered for the reason [`crate::analysis::analyze`] gives — an
/// undecodable frame belongs to no dialog, so narrowing it would drop the
/// evidence that bounds every count in the container.
///
/// # Side effects
///
/// Writes the container to `--vcon-out` or to stdout, and every refusal to
/// stderr — `eprintln!` rather than `tracing`, matching `--call-report`,
/// because the message decides the process exit code and has to survive
/// logging being off.
#[cfg(feature = "vcon")]
fn export_vcon(
    cli: &Cli,
    vcon_filter: Option<&crate::sip::dsl::FilterExpr>,
    dialog_store: &DialogStore,
    stream_store: &StreamStore,
    frames_read: u64,
    gate: Option<&crate::output::persistence::PersistenceGate>,
) -> bool {
    // The gate is consulted here, above both export forms, because both write
    // content and a check on one of them would leave the other writing through
    // a close. It answers `true`: an operator who switched persistence off got
    // what they asked for, and turning that into a non-zero exit would make
    // every scripted run treat a deliberate act as a failure.
    if gate.is_some_and(|g| !g.writes_permitted()) {
        return true;
    }
    if cli.output_args.export_vcon_when.is_some() {
        return export_vcon_selection(
            cli,
            vcon_filter,
            dialog_store,
            stream_store,
            frames_read,
            gate,
        );
    }
    let Some(call_id) = cli.output_args.export_vcon.as_deref() else {
        return true;
    };
    let Some(dialog) = dialog_store.get(call_id) else {
        eprintln!(
            "Call-ID '{call_id}' not found in tracked dialogs, so there is no \
             dialog to export. --report lists the Call-IDs this run holds."
        );
        return false;
    };

    let facts = crate::analysis::CaptureFacts::observed(dialog_store, stream_store, frames_read);
    let analysis = crate::analysis::analyze_with(dialog_store, stream_store, None, &facts);

    // Media is attempted ALWAYS, never gated on a second flag. `--retain-audio`
    // is already the operator's opt-in: without it there is no payload to
    // decode, and the container then carries the exporter's own explanation of
    // what was measured instead of an absence a reader has to interpret.
    let dialog_streams: Vec<&crate::rtp::stream::RtpStream> =
        stream_store.streams_for(call_id).collect();
    let decoded = crate::rtp::audio_export::decode_dialog_audio(&dialog_streams);
    let reason = decoded
        .as_ref()
        .err()
        .map_or_else(String::new, |e| e.to_string());
    let audio = match decoded.as_ref() {
        Ok(audio) => crate::output::vcon::ObservedAudio::Decoded(audio),
        Err(_) => crate::output::vcon::ObservedAudio::NothingToDecode(&reason),
    };

    let container = crate::output::vcon::export_dialog_with_audio(
        dialog,
        &crate::output::vcon::ExportContext {
            capture_id: crate::output::vcon::dialog_capture_id(dialog),
            facts: &facts,
            analysis: Some(&analysis),
            max_inline_media_bytes: media_budget(cli),
        },
        audio,
    );

    let policy = match redaction_policy(cli) {
        Ok(p) => p,
        Err(reason) => {
            eprintln!("{reason}");
            return false;
        }
    };
    let redactor = policy
        .as_ref()
        .map(crate::output::redact::RedactionPolicy::redactor);

    let mut json = match crate::output::vcon::sealed_json(&crate::output::vcon::seal(
        container,
        redactor.as_ref(),
    )) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("The vCon for Call-ID '{call_id}' would not serialize: {e}");
            return false;
        }
    };
    json.push('\n');

    if let Some(r) = redactor.as_ref() {
        let report = r.policy().report();
        eprintln!(
            "Redaction: {} classes, key {}, {} leading digit(s) retained.",
            report.classes.len(),
            report.key_mode,
            report.keep_prefix,
        );
        if let Some(path) = cli.output_args.redact_map.as_deref() {
            match write_redaction_map(path, r) {
                Ok(n) => eprintln!(
                    "Wrote {n} token mapping(s) to '{}' (mode 0600).",
                    path.display()
                ),
                Err(reason) => {
                    eprintln!("{reason}");
                    return false;
                }
            }
        }
    }

    let Some(path) = cli.output_args.vcon_out.as_deref() else {
        return write_stdout(&json);
    };
    // Atomic for the sake of the sentence below: `std::fs::write` truncates
    // the destination before it fills it, so "Nothing was exported" would be
    // false exactly when it is printed -- the operator's previous export would
    // already be gone.
    if let Err(e) = write_container_atomically(path, json.as_bytes()) {
        eprintln!(
            "Could not write the vCon for Call-ID '{call_id}' to '{}': {e}. \
             Nothing was exported.",
            path.display()
        );
        return false;
    }
    true
}

/// Refuse `--export-vcon` on a build that carries no exporter.
///
/// [`Cli::validate`] refuses the same flag before any capture opens, which is
/// where an operator meets it. This second door exists because
/// [`generate_reports`] is a public entry point a library consumer can reach
/// without going through argument validation, and the failure it prevents is
/// the quiet one: returning `true` here would report a successful run that
/// wrote no container anywhere.
#[cfg(not(feature = "vcon"))]
fn export_vcon(
    cli: &Cli,
    _vcon_filter: Option<&FilterExpr>,
    _dialog_store: &DialogStore,
    _stream_store: &StreamStore,
    _frames_read: u64,
    _gate: Option<&crate::output::persistence::PersistenceGate>,
) -> bool {
    // The gate is ignored here rather than consulted, and the difference is
    // only apparent: a build without the feature writes no container by any
    // route, so there is nothing for a closed gate to stop. It is accepted so
    // both doors keep one signature -- a stub that dropped the parameter would
    // break the caller in exactly the build nobody runs the tests on.
    if cli.output_args.export_vcon.is_none() {
        return true;
    }
    eprintln!(
        "--export-vcon needs the 'vcon' Cargo feature, which this build does \
         not carry. Rebuild with --features vcon (or --features full); \
         `sipnab --version` lists the features a binary was built with."
    );
    false
}

// ── Unit tests for the batch runner's pure helpers ──────────────────────
/// Unit tests for the batch runner's pure helpers: output dispatch, report
/// generation, packet processing, targeted kills, and emit selection.
/// Run every loaded plugin over one dialog and fold their findings into the
/// emitted JSON line.
///
/// Findings land under a top-level `plugin_findings` array rather than inside
/// `signaling_diagnosis`. Keeping them separate means a reader can always tell
/// which findings sipnab stands behind and which came from third-party code —
/// and it keeps `signaling_diagnosis` matching its schema, which is
/// `additionalProperties: false`.
///
/// A plugin error is logged against that dialog and the line is emitted
/// unchanged. Losing one plugin's opinion must not cost the dialog.
#[cfg(feature = "plugins")]
fn apply_plugins(
    plugins: &[crate::plugin::Plugin],
    dialog: &crate::sip::dialog::SipDialog,
    line: &str,
) -> String {
    if plugins.is_empty() {
        return line.to_string();
    }
    let trimmed = line.trim_end();
    let input = crate::plugin::plugin_input_json(dialog, trimmed);

    let mut findings = Vec::new();
    for p in plugins {
        match p.analyze(&input) {
            Ok(fs) => findings.extend(fs),
            Err(e) => tracing::error!("plugin {} on {}: {e}", p.name(), dialog.call_id),
        }
    }
    if findings.is_empty() {
        return line.to_string();
    }

    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return line.to_string();
    };
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "plugin_findings".to_string(),
            serde_json::to_value(&findings).unwrap_or(serde_json::Value::Null),
        );
    }
    let mut out = value.to_string();
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Baseline non-interactive CLI; mutate the pub fields per test.
    /// Build a `SipMessage` for `call_id` from the shared INVITE fixture.
    fn invite_msg(call_id: &str) -> sip::message::SipMessage {
        let data = bytes::Bytes::from(invite_bytes(call_id));
        sip::parser::parse_sip_bytes(
            &data,
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("fixture parses")
    }

    /// A final response, so a fixture dialog can carry a status code the
    /// filter language can read.
    #[cfg(feature = "vcon")]
    fn response_msg(call_id: &str, code: u16, reason: &str) -> sip::message::SipMessage {
        let headers = [
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-abc".to_string(),
            "From: Alice <sip:alice@example.com>;tag=a1b2".to_string(),
            "To: Bob <sip:bob@example.com>;tag=c3d4".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".to_string(),
            "Content-Length: 0".to_string(),
        ];
        let mut msg = format!("SIP/2.0 {code} {reason}\r\n");
        for h in headers {
            msg.push_str(&h);
            msg.push_str("\r\n");
        }
        msg.push_str("\r\n");
        let data = bytes::Bytes::from(msg.into_bytes());
        sip::parser::parse_sip_bytes(
            &data,
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("fixture parses")
    }

    /// Two dialogs, one of which failed.
    #[cfg(feature = "vcon")]
    fn two_dialogs_one_failed() -> DialogStore {
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_msg("ok-call@example.com"));
        store.process_message(response_msg("ok-call@example.com", 200, "OK"));
        store.process_message(invite_msg("failed-call@example.com"));
        store.process_message(response_msg("failed-call@example.com", 486, "Busy Here"));
        store
    }

    /// `--export-vcon-when` selects the dialogs its expression matches.
    ///
    /// The predicate is the language `--filter` already speaks, so this test
    /// is also what pins that choice: a flag per policy would not answer
    /// `response_code >= 400` without new code.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_predicate_selects_only_the_dialogs_that_match() {
        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 400".to_owned());

        let (picked, _, _) =
            vcon_selection(&cli, None, &dialogs, &streams).expect("a valid predicate");
        let ids: Vec<&str> = picked
            .dialogs
            .iter()
            .map(|(d, _)| d.call_id.as_str())
            .collect();

        assert_eq!(
            ids,
            vec!["failed-call@example.com"],
            "only the failed dialog matches the predicate"
        );
    }

    /// A malformed predicate fails the run and names the flag.
    ///
    /// The failure this refuses is the quiet one: an expression that parses
    /// nowhere, a capture that finishes, an empty directory, and no error to
    /// explain it. An operator reads that as "nothing matched".
    #[cfg(feature = "vcon")]
    #[test]
    fn a_malformed_predicate_fails_the_run_rather_than_selecting_nothing() {
        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >>> 400".to_owned());

        // `let Err(..) else` rather than `expect_err`: that would need `Debug`
        // on `DialogSelection`, and widening a shared type's derives to suit
        // one test's ergonomics is a cost the type pays forever.
        let Err(err) = vcon_selection(&cli, None, &dialogs, &streams) else {
            panic!("an unparseable expression is an error, not an empty result");
        };

        assert!(
            format!("{err:#}").contains("--export-vcon-when"),
            "the message has to name the flag the operator typed: {err:#}"
        );
    }

    /// A Call-ID cannot escape the export directory.
    ///
    /// `--export-vcon-dir` is the first path in this program built from a
    /// Call-ID, and a Call-ID is text an attacker chooses. `--export-vcon`
    /// never had this exposure: it wrote to the one path an operator typed.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_call_id_cannot_escape_the_export_directory() {
        for hostile in [
            "../../etc/passwd@evil.example",
            "/absolute@evil.example",
            "a/b/c@evil.example",
            "..@evil.example",
        ] {
            let name = vcon_file_name(hostile);
            assert!(
                !name.contains('/') && !name.contains('\\'),
                "no separator survives {hostile:?}: {name}"
            );
            // NOT `!name.contains("..")`. `.._.._etc_passwd_...` is a single
            // legal filename that escapes nothing, and asserting on the
            // substring tests a proxy for the property rather than the
            // property. What matters is that the name stays one component and
            // is never `.` or `..` themselves.
            assert!(
                name != "." && name != "..",
                "{hostile:?} produced a directory's own name: {name}"
            );
            assert!(
                std::path::Path::new(&name).components().count() == 1,
                "{hostile:?} produced more than one path component: {name}"
            );
        }
    }

    /// A Call-ID of nothing but dots still yields a usable filename.
    ///
    /// Owed for the assertion I got wrong: the first version of the escape
    /// test asserted `!name.contains("..")`, which rejects a perfectly safe
    /// single filename and says nothing about the property that matters. This
    /// one names the property directly. The extension is what enforces it:
    /// `..` becomes `...vcon.json`. A defensive all-dots branch used to sit in
    /// `vcon_file_name` and removing it changed nothing, so it went.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_call_id_of_only_dots_cannot_become_a_directory_entry() {
        for dots in ["..", ".", "..."] {
            let name = vcon_file_name(dots);
            assert!(
                name != "." && name != "..",
                "{dots:?} produced a name a directory already owns: {name}"
            );
            assert!(
                name.ends_with(".vcon.json"),
                "{dots:?} lost its extension: {name}"
            );
        }
    }

    /// A Call-ID longer than the filesystem allows is truncated.
    ///
    /// Also owed for the assertion miss, and it covers a branch nothing
    /// reached: `vcon_file_name` truncates at 200 characters, and no test
    /// exercised that. Most filesystems refuse a name past 255 bytes, so an
    /// untruncated Call-ID would fail the write rather than the sanitizer --
    /// an error naming the path instead of the rule that should have caught it.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_very_long_call_id_is_truncated_to_a_writable_name() {
        let long = "x".repeat(500);
        let name = vcon_file_name(&long);
        assert!(
            name.len() < 255,
            "a {} character name will not survive the write: {}",
            name.len(),
            name.len()
        );
        assert!(
            name.ends_with(".vcon.json"),
            "truncation must not eat the extension: {name}"
        );
    }

    /// Both predicates this project documents actually parse.
    ///
    /// Owed for `every_flag_has_at_least_two_examples`. That gate proves an
    /// example EXISTS. Nothing proved the command in it runs, and a
    /// documented invocation that fails on paste is worse than none -- the
    /// reader concludes the feature is broken rather than the page.
    #[cfg(feature = "vcon")]
    #[test]
    fn every_documented_predicate_parses() {
        for expr in ["state == 'Failed'", "duration > 30 and rtp.codec == 'PCMU'"] {
            assert!(
                crate::sip::dsl::FilterExpr::parse(expr).is_ok(),
                "docs/cli-reference.md tells an operator to run {expr:?}"
            );
        }
    }

    /// A predicate matching nothing selects nothing, without erroring.
    ///
    /// The empty case has to stay distinguishable from the failure case: one
    /// is an answer about the capture, the other is an answer about the run.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_predicate_that_matches_nothing_selects_nothing() {
        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 599".to_owned());

        let (picked, _, _) =
            vcon_selection(&cli, None, &dialogs, &streams).expect("a valid predicate");

        assert!(
            picked.dialogs.is_empty(),
            "nothing in the fixture answers 599 or above: {:?}",
            picked
                .dialogs
                .iter()
                .map(|(d, _)| &d.call_id)
                .collect::<Vec<_>>()
        );
    }

    /// With no predicate the selection is every dialog.
    ///
    /// The `None` branch, which no test reached. It matters because
    /// `vcon_selection` is also the path a future caller takes when it wants
    /// the whole store, and a `None` that quietly returned nothing would look
    /// like a capture with no calls in it.
    #[cfg(feature = "vcon")]
    #[test]
    fn no_predicate_selects_every_dialog() {
        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);
        let cli = Cli::parse_from_args(["sipnab"]);

        let picked = vcon_selection(&cli, None, &dialogs, &streams)
            .expect("no predicate is not an error")
            .0;

        assert_eq!(
            picked.dialogs.len(),
            2,
            "an absent predicate narrows nothing"
        );
    }

    /// Two matching dialogs produce two distinct files.
    ///
    /// The multi-container path is the whole point of this task and nothing
    /// exercised it: the end-to-end run that proved the feature used a fixture
    /// holding ONE call, so a loop that wrote the first dialog and stopped, or
    /// that collided both onto one name, would have passed everything.
    #[cfg(feature = "vcon")]
    #[test]
    fn two_matching_dialogs_produce_two_distinct_files() {
        let a = vcon_file_name("first@example.com");
        let b = vcon_file_name("second@example.com");
        assert_ne!(a, b, "two Call-IDs must not collide onto one filename");

        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());

        let (picked, _, _) =
            vcon_selection(&cli, None, &dialogs, &streams).expect("a valid predicate");
        let names: std::collections::HashSet<String> = picked
            .dialogs
            .iter()
            .map(|(d, _)| vcon_file_name(&d.call_id))
            .collect();

        assert_eq!(
            names.len(),
            picked.dialogs.len(),
            "every selected dialog needs its own file: {names:?}"
        );
        assert!(picked.dialogs.len() >= 2, "the fixture holds two calls");
    }

    /// A `Cli` wired for a predicate export into `dir`.
    #[cfg(feature = "vcon")]
    fn cli_exporting_to(dir: &std::path::Path, expr: &str) -> Cli {
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some(expr.to_owned());
        cli.output_args.export_vcon_dir = Some(dir.to_path_buf());
        cli
    }

    // ── HEP unwrapping and the rtpengine control plane ──────────

    /// A HEP datagram carrying `payload`, announced as `proto`.
    #[cfg(feature = "hep")]
    fn hep_datagram(proto: u8, payload: &[u8], correlation: Option<&str>) -> ParsedPacket {
        use std::net::{IpAddr, Ipv4Addr};
        let endpoint = crate::capture::hep::HepEndpoint {
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
            src_port: 40000,
            dst_port: 5060,
            transport: TransportProto::Udp,
        };
        // `build_hep_v3` writes no correlation chunk, so a test that needs one
        // appends it: chunk 0x0011 in vendor 0, and the total-length field at
        // offset 4 has to grow with it or the parser stops at the old end.
        let mut bytes = crate::capture::hep::build_hep_v3(
            &endpoint,
            chrono::Utc::now(),
            crate::capture::hep::HepProtocol::Unknown(proto),
            2001,
            None,
            payload,
        );
        if let Some(cid) = correlation {
            let body = cid.as_bytes();
            let len = (6 + body.len()) as u16;
            let mut chunk = Vec::with_capacity(len as usize);
            chunk.extend_from_slice(&0u16.to_be_bytes());
            chunk.extend_from_slice(&0x0011u16.to_be_bytes());
            chunk.extend_from_slice(&len.to_be_bytes());
            chunk.extend_from_slice(body);
            bytes.extend_from_slice(&chunk);
            let total = u16::try_from(bytes.len()).expect("test datagram fits");
            bytes[4..6].copy_from_slice(&total.to_be_bytes());
        }
        ParsedPacket {
            frame_bytes: None,
            frame: None,
            timestamp: chrono::Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30)),
            src_port: 57661,
            dst_port: 9060,
            transport: TransportProto::Udp,
            payload: bytes.into(),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            dscp: None,
            input_origin: crate::capture::parse::InputOrigin::Wire,
            hep: None,
        }
    }

    /// Unwrapping keeps what the wrapper said.
    ///
    /// It did not, and the two halves of HEP support were mutually exclusive
    /// because of it: `--hep-parse` removed the wrapper, nothing recorded what
    /// it announced, and the pipeline arm that decodes rtpengine's mirrored
    /// control plane matches on exactly that. Every mirrored `ng` message was
    /// discarded in silence and every relay stream stayed unnamed.
    #[cfg(feature = "hep")]
    #[test]
    fn unwrapping_hep_carries_the_wrappers_protocol_onto_the_packet() {
        let pp = hep_datagram(
            crate::rtpengine::NG_HEP_CAPTURE_PROTO,
            b"d3:foo3:bare",
            None,
        );
        let out = unwrap_hep(&pp).expect("a HEP datagram unwraps");
        let origin = out.hep.expect(
            "the wrapper's metadata must survive: without it nothing downstream \
             can tell mirrored ng from any other UDP payload",
        );
        assert_eq!(origin.protocol, crate::rtpengine::NG_HEP_CAPTURE_PROTO);
    }

    /// The correlation id survives, because a reply has nothing else.
    ///
    /// An `ng` REPLY carries no `call-id` at all. The correlation id is the
    /// only thing naming the call it belongs to, so losing it turns every
    /// reply into control traffic about an unknown call.
    #[cfg(feature = "hep")]
    #[test]
    fn unwrapping_hep_keeps_the_correlation_id() {
        let pp = hep_datagram(
            crate::rtpengine::NG_HEP_CAPTURE_PROTO,
            b"d3:foo3:bare",
            Some("corr-42"),
        );
        let out = unwrap_hep(&pp).expect("unwraps");
        assert_eq!(
            out.hep.and_then(|h| h.correlation_id).as_deref(),
            Some("corr-42")
        );
    }

    /// An unwrapped HEP packet's addressing is sender-asserted, so it must carry
    /// `InputOrigin::Hep` -- even under `--hep-parse`.
    ///
    /// `--hep-listen` sets this already, in the network parser. `--hep-parse`
    /// reads the wrapper off a pcap or interface, where the outer packet is
    /// `Wire`, and unwraps by cloning -- so the inner addressing, which the
    /// remote sender asserted rather than sipnab observing, inherited `Wire`.
    /// Left that way it passed `kill_response_eligible`, and a forged inner
    /// source was eligible for both a jail line and a kill response: the exact
    /// hole the origin gate closes for `--hep-listen`, open on the parse path.
    #[cfg(feature = "hep")]
    #[test]
    fn unwrapping_hep_marks_the_addressing_as_sender_asserted() {
        let pp = hep_datagram(
            crate::rtpengine::NG_HEP_CAPTURE_PROTO,
            b"d3:foo3:bare",
            None,
        );
        assert_eq!(
            pp.input_origin,
            crate::capture::parse::InputOrigin::Wire,
            "the wrapper itself arrives off the wire under --hep-parse",
        );
        let out = unwrap_hep(&pp).expect("a HEP datagram unwraps");
        assert_eq!(
            out.input_origin,
            crate::capture::parse::InputOrigin::Hep,
            "the inner addressing is the sender's assertion, not observed; leaving \
             it Wire lets a forged inner source pass the kill/jail origin gate",
        );
    }

    /// The inner payload replaces the outer one, which is the point.
    #[cfg(feature = "hep")]
    #[test]
    fn unwrapping_hep_yields_the_inner_payload_and_its_addresses() {
        let inner = b"OPTIONS sip:a@b SIP/2.0\r\n\r\n";
        let pp = hep_datagram(1, inner, None);
        let out = unwrap_hep(&pp).expect("unwraps");
        assert_eq!(out.payload.as_ref(), inner, "the SIP inside is what parses");
        assert_eq!(out.dst_port, 5060, "and the addressing is the inner call's");
    }

    /// A datagram that is not HEP is left alone.
    ///
    /// `--hep-parse` runs over every UDP packet on the capture, media
    /// included. Treating a failed parse as anything but "not HEP" would drop
    /// ordinary traffic.
    #[cfg(feature = "hep")]
    #[test]
    fn a_packet_that_is_not_hep_is_not_unwrapped() {
        let mut pp = hep_datagram(1, b"x", None);
        pp.payload = bytes::Bytes::from_static(b"not a hep datagram at all");
        assert!(unwrap_hep(&pp).is_none());
    }

    /// Only UDP is considered.
    ///
    /// HEP over TCP is a different framing, and running the datagram parser
    /// over a TCP segment would either fail or, worse, half-succeed on a
    /// segment boundary.
    #[cfg(feature = "hep")]
    #[test]
    fn hep_unwrapping_ignores_non_udp() {
        let mut pp = hep_datagram(1, b"OPTIONS sip:a@b SIP/2.0\r\n\r\n", None);
        pp.transport = TransportProto::Tcp;
        assert!(unwrap_hep(&pp).is_none());
    }

    /// Unwrapped mirrored ng is still recognizable as control traffic.
    ///
    /// The end-to-end property the other tests support: after `--hep-parse`
    /// has done its work, the pipeline can still tell this was rtpengine's
    /// control plane. This is what was broken -- the harness ran for hours
    /// with correct capture, correct filters and correct features, naming
    /// nothing, because this one fact did not survive the unwrap.
    #[cfg(feature = "hep")]
    #[test]
    fn mirrored_ng_survives_unwrapping_as_control_traffic() {
        let pp = hep_datagram(
            crate::rtpengine::NG_HEP_CAPTURE_PROTO,
            b"d7:command5:offere",
            Some("c1"),
        );
        let out = unwrap_hep(&pp).expect("unwraps");
        let origin = out.hep.as_ref().expect("metadata survives");
        assert!(
            crate::rtpengine::is_ng_over_hep(origin.protocol, &out.payload),
            "an unwrapped mirrored ng message must still identify as ng, or \
             the relay names no media at all"
        );
    }

    // ── What the run records about its own suppression ──────────

    /// Every container in `dir`, sorted by filename.
    ///
    /// One function so no test picks whichever entry `read_dir` happened to
    /// yield. That shape cost a CI cycle: `a_written_container_emits_no_
    /// explicit_null` judged a whole export from one arbitrary file, passed
    /// for two releases because that file was the ANSWERED dialog, and fired
    /// the moment container names changed and the FAILED one came first.
    ///
    /// Sorted rather than merely collected, because "all of them" and "the
    /// same one every time" are different guarantees and a test usually wants
    /// both. `no_test_judges_an_export_from_one_arbitrary_directory_entry`
    /// keeps the shape from coming back.
    #[cfg(feature = "vcon")]
    fn containers_in(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .expect("readable")
            .flatten()
            .map(|e| e.path())
            .collect();
        paths.sort();
        assert!(!paths.is_empty(), "no container was written to {dir:?}");
        paths
    }

    /// Read the `capture_completeness` block out of the first container in a
    /// directory. The containers are what a consumer actually gets.
    #[cfg(feature = "vcon")]
    fn first_completeness(dir: &std::path::Path) -> serde_json::Value {
        let text = std::fs::read_to_string(&containers_in(dir)[0]).expect("readable");
        let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        let body = v["analysis"][0]["body"]
            .as_str()
            .unwrap_or_else(|| panic!("an analysis body is a string: {v}"));
        let parsed: serde_json::Value =
            serde_json::from_str(body).expect("the analysis body parses");
        parsed["capture_completeness"].clone()
    }

    /// The suppressed count reaches the container a consumer reads.
    ///
    /// Owed to a surviving mutant: deleting the line that copies the count
    /// onto the facts passed every test here, because each one stopped at the
    /// filter. The number was computed correctly and thrown away, which is the
    /// same container a reader would get if the deny flag had never fired.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_suppressed_count_reaches_the_written_container() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let mut cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_first_flagged("X-No-Record", "1"),
            &StreamStore::new(16),
            7,
            None,
        ));

        let completeness = first_completeness(tmp.path());
        assert_eq!(
            completeness["dialogs_suppressed_by_deny"], 1,
            "the container must carry what the run suppressed: {completeness}"
        );
        assert!(
            completeness["note"]
                .as_str()
                .is_some_and(|n| n.contains("1 dialog(s) carried a deny flag")),
            "and say it in the note: {completeness}"
        );
    }

    /// A run with no deny flag writes containers that claim no suppression.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_run_with_no_deny_flag_writes_a_zero() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_first_flagged("X-No-Record", "1"),
            &StreamStore::new(16),
            7,
            None,
        ));

        let completeness = first_completeness(tmp.path());
        assert_eq!(
            completeness["dialogs_suppressed_by_deny"], 0,
            "no header was named, so nothing was suppressed: {completeness}"
        );
        assert_eq!(
            completeness["gate_closed_during_run"], false,
            "and no gate was moved: {completeness}"
        );
    }

    /// A gate closed and reopened mid-run reaches the container too.
    ///
    /// The scenario the field exists for, and the only one in which a
    /// container is written AND the gate moved: an operator stops recording,
    /// then starts it again. The containers that survive are from either side
    /// of a hole, and nothing else in them says the hole is there.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_gate_closed_and_reopened_is_recorded_in_the_container() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let gate = crate::output::persistence::PersistenceGate::new(true);
        gate.set(false);
        gate.set(true);

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            Some(&gate),
        ));

        let completeness = first_completeness(tmp.path());
        assert_eq!(
            completeness["gate_closed_during_run"], true,
            "recording stopped partway and the container must say so: {completeness}"
        );
        assert!(
            completeness["note"]
                .as_str()
                .is_some_and(|n| n.contains("closed the persistence gate")),
            "and say it in the note: {completeness}"
        );
    }

    /// An untouched gate leaves the container claiming a clean run.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_untouched_gate_writes_a_container_that_claims_nothing() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let gate = crate::output::persistence::PersistenceGate::new(true);

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            Some(&gate),
        ));

        let completeness = first_completeness(tmp.path());
        assert_eq!(completeness["gate_closed_during_run"], false);
        assert!(
            completeness["note"]
                .as_str()
                .is_some_and(|n| !n.contains("persistence gate")),
            "a gate nobody touched must not be mentioned: {completeness}"
        );
    }

    /// Both new fields are always present, and never null.
    ///
    /// The module's standing contract is "absent, never null", and adding
    /// fields to a serialized struct is how a null arrives. These two are
    /// always present instead: `false` and `0` are answers, and a consumer
    /// branching on the key should not have to treat a missing key and
    /// "nothing happened" as the same thing.
    ///
    /// The plan cited an existing test by name for this step. No such test
    /// exists in the repo -- the filter matched zero tests and reported
    /// success, which is what a filter matching nothing always does.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_new_completeness_fields_are_present_and_never_null() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None,
        ));

        let completeness = first_completeness(tmp.path());
        for key in ["gate_closed_during_run", "dialogs_suppressed_by_deny"] {
            assert!(
                completeness.get(key).is_some(),
                "{key} must be present on every container: {completeness}"
            );
            assert!(
                !completeness[key].is_null(),
                "{key} must never serialize as null: {completeness}"
            );
        }
    }

    /// The deny filter reports how many dialogs it removed.
    ///
    /// The count is what the container quotes. Recomputing it later from the
    /// selection is impossible: by then the denied dialogs are gone, and a
    /// difference against the unfiltered store would also count dialogs the
    /// predicate rejected for entirely different reasons.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_deny_filter_reports_what_it_removed() {
        let dialogs = two_dialogs_first_flagged("X-No-Record", "1");
        let streams = StreamStore::new(16);
        let selection = crate::sip::dsl::select_dialogs(
            Some(&crate::sip::dsl::FilterExpr::parse("response_code >= 100").expect("parses")),
            &dialogs,
            &streams,
        );
        let before = selection.dialogs.len();

        let (kept, suppressed, _) = split_denied(selection, Some("X-No-Record"));

        assert_eq!(suppressed, 1, "one dialog carried the header");
        assert_eq!(
            kept.dialogs.len() as u64 + suppressed,
            before as u64,
            "every dialog is either kept or counted; none may vanish unrecorded"
        );
    }

    /// With no deny flag configured, nothing is reported as suppressed.
    #[cfg(feature = "vcon")]
    #[test]
    fn no_deny_flag_suppresses_nothing_and_reports_nothing() {
        let dialogs = two_dialogs_first_flagged("X-No-Record", "1");
        let streams = StreamStore::new(16);
        let selection = crate::sip::dsl::select_dialogs(
            Some(&crate::sip::dsl::FilterExpr::parse("response_code >= 100").expect("parses")),
            &dialogs,
            &streams,
        );
        let before = selection.dialogs.len();

        let (kept, suppressed, _) = split_denied(selection, None);

        assert_eq!(suppressed, 0, "no header was named, so none was honored");
        assert_eq!(kept.dialogs.len(), before, "and nothing was removed");
    }

    /// A header nobody sent suppresses nothing.
    ///
    /// Distinguishes "the filter ran and matched none" from "the filter never
    /// ran": both keep every dialog, and only the count tells them apart.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_deny_header_nobody_sent_reports_zero() {
        let dialogs = two_dialogs_first_flagged("X-No-Record", "1");
        let streams = StreamStore::new(16);
        let selection = crate::sip::dsl::select_dialogs(
            Some(&crate::sip::dsl::FilterExpr::parse("response_code >= 100").expect("parses")),
            &dialogs,
            &streams,
        );
        let before = selection.dialogs.len();

        let (kept, suppressed, _) = split_denied(selection, Some("X-Nobody-Sends-This"));

        assert_eq!(suppressed, 0);
        assert_eq!(kept.dialogs.len(), before);
    }

    // ── The runtime persistence gate ────────────────────────────

    /// The gate's whole purpose: an operator closes it and content stops.
    ///
    /// The predicate still matches, the directory still exists, the flags are
    /// unchanged. Nothing but the gate stands between this run and a container
    /// on disk, so a file appearing here means the exporter never asked.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_closed_gate_writes_no_container() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let gate = crate::output::persistence::PersistenceGate::new(true);
        gate.set(false);

        let ok = export_vcon(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            Some(&gate),
        );

        assert!(
            ok,
            "an operator who closed the gate got what they asked for; that is              not a failure and must not become a non-zero exit code"
        );
        let written: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("readable")
            .filter_map(Result::ok)
            .collect();
        assert!(
            written.is_empty(),
            "the gate was closed and {} container(s) were written anyway",
            written.len()
        );
    }

    /// The single-call form is gated too.
    ///
    /// Two entry points reach the exporter, and a check on only the predicate
    /// form would leave `--export-vcon <call-id>` writing through a closed
    /// gate -- the failure being harder to notice for affecting the older,
    /// more-used flag.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_closed_gate_stops_the_single_call_form_too() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let out = tmp.path().join("one.vcon.json");
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon = Some("failed@test".to_owned());
        cli.output_args.vcon_out = Some(out.clone());
        let gate = crate::output::persistence::PersistenceGate::new(true);
        gate.set(false);

        assert!(export_vcon(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            Some(&gate),
        ));
        assert!(
            !out.exists(),
            "--export-vcon wrote through a closed gate: {}",
            out.display()
        );
    }

    /// A gate the command line never authorized writes nothing, whatever the
    /// flags say.
    ///
    /// In production the ceiling is derived from these same flags, so this
    /// pairing cannot arise. It is tested because the gate is the authority:
    /// if a later edit ever builds one from a different source, this run
    /// writes nothing rather than falling back to the flags.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_unauthorized_gate_overrides_the_flags() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let gate = crate::output::persistence::PersistenceGate::new(false);
        gate.set(true);

        assert!(export_vcon(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            Some(&gate),
        ));
        assert_eq!(
            std::fs::read_dir(tmp.path())
                .expect("readable")
                .filter_map(Result::ok)
                .count(),
            0,
            "the gate is the authority, not the flags it was built from"
        );
    }

    /// An open gate exports exactly what no gate does.
    ///
    /// The direction this catches is a gate that quietly narrows a run nobody
    /// touched -- a check inverted, or a ceiling read from the wrong flag.
    /// Comparing the two file sets says so without pinning a count that a
    /// later fixture change would have to chase.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_open_gate_exports_exactly_what_no_gate_does() {
        let names = |dir: &std::path::Path| {
            let mut v: Vec<_> = std::fs::read_dir(dir)
                .expect("readable")
                .filter_map(Result::ok)
                .map(|e| e.file_name())
                .collect();
            v.sort_unstable();
            v
        };

        let ungated = tempfile::tempdir().expect("temp dir");
        assert!(export_vcon(
            &cli_exporting_to(ungated.path(), "response_code >= 200"),
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None,
        ));

        let gated = tempfile::tempdir().expect("temp dir");
        assert!(export_vcon(
            &cli_exporting_to(gated.path(), "response_code >= 200"),
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            Some(&crate::output::persistence::PersistenceGate::new(true)),
        ));

        let ungated_names = names(ungated.path());
        assert!(
            !ungated_names.is_empty(),
            "the fixture must write something, or this test compares two              empty directories and proves nothing"
        );
        assert_eq!(
            ungated_names,
            names(gated.path()),
            "an open gate changed what a run wrote"
        );
    }

    /// Closing and reopening restores the export.
    ///
    /// The operator who switched recording off at three in the morning has to
    /// be able to switch it back on without restarting capture. A gate that
    /// latched shut would be safe and useless.
    #[cfg(feature = "vcon")]
    #[test]
    fn reopening_the_gate_restores_the_export() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let gate = crate::output::persistence::PersistenceGate::new(true);

        gate.set(false);
        assert!(export_vcon(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            Some(&gate),
        ));
        assert_eq!(
            std::fs::read_dir(tmp.path())
                .expect("readable")
                .filter_map(Result::ok)
                .count(),
            0,
            "closed"
        );

        gate.set(true);
        assert!(export_vcon(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            Some(&gate),
        ));
        assert!(
            std::fs::read_dir(tmp.path())
                .expect("readable")
                .filter_map(Result::ok)
                .count()
                > 0,
            "reopening the gate must let the next export through"
        );
    }

    /// A run with no persistence flags is not stopped by the gate check.
    ///
    /// `export_vcon` returns early when neither flag is set, and that path
    /// must stay reachable with a closed gate: a run that writes nothing has
    /// nothing to suppress, and a `false` here would turn every ordinary
    /// capture into a non-zero exit.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_run_that_exports_nothing_is_unaffected_by_a_closed_gate() {
        let cli = Cli::parse_from_args(["sipnab"]);
        let gate = crate::output::persistence::PersistenceGate::new(false);
        assert!(export_vcon(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            Some(&gate),
        ));
    }

    /// The export directory is created when it does not exist.
    ///
    /// Owed for `every_flag_has_at_least_two_examples`. The documented
    /// invocation points at `./failed/`, a directory an operator will not have
    /// made first, so a run that refused a missing path would fail on the very
    /// command the page tells them to run.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_missing_export_directory_is_created() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path().join("does/not/exist/yet");
        assert!(!dir.exists(), "the fixture starts with no directory");

        let cli = cli_exporting_to(&dir, "response_code >= 200");
        let ok = export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None,
        );

        assert!(ok, "creating the directory is part of the job");
        assert!(dir.is_dir(), "the run must create what it was pointed at");
    }

    /// Every selected dialog gets its own file on disk.
    ///
    /// The multi-container write, end to end. `two_matching_dialogs_produce_two_distinct_files`
    /// proves the NAMES differ; this proves both files arrive. A loop that
    /// wrote the first dialog and returned would pass that one and fail this.
    #[cfg(feature = "vcon")]
    #[test]
    fn every_selected_dialog_is_written_to_its_own_file() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);

        let expected = vcon_selection(&cli, None, &dialogs, &streams)
            .expect("a valid predicate")
            .0
            .dialogs
            .len();
        assert!(expected >= 2, "the fixture holds two calls");

        assert!(export_vcon_selection(
            &cli, None, &dialogs, &streams, 7, None
        ));

        let written: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("readable")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            written.len(),
            expected,
            "{expected} dialog(s) selected, {} file(s) written: {written:?}",
            written.len()
        );
    }

    /// What lands on disk is a vCon a consumer can read.
    ///
    /// A run that wrote the right NUMBER of unparseable files would satisfy
    /// every other test here. This reads one back.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_written_container_is_valid_vcon_json() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None
        ));

        let first = containers_in(tmp.path())[0].clone();
        let text = std::fs::read_to_string(&first).expect("readable file");
        let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

        assert_eq!(v["vcon"], "0.4.0", "syntax version: {text}");
        assert!(v["uuid"].is_string(), "a container needs a uuid: {text}");
        assert!(
            v["parties"].as_array().is_some_and(|p| !p.is_empty()),
            "a container names its parties: {text}"
        );
    }

    /// A directory that cannot be written fails the run out loud.
    ///
    /// The refusal has to be a non-zero answer rather than a silent partial
    /// write: an operator scripting this reads the exit code, and a run that
    /// wrote three of forty containers and returned success is the worst
    /// outcome available.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_unwritable_export_directory_fails_the_run() {
        let tmp = tempfile::tempdir().expect("temp dir");
        // A FILE where the directory should be: `create_dir_all` cannot make a
        // directory over it, and this works without depending on running as a
        // non-root user, which a permission-bit fixture would.
        let blocked = tmp.path().join("blocked");
        std::fs::write(&blocked, b"not a directory").expect("write the blocker");

        let cli = cli_exporting_to(&blocked, "response_code >= 200");
        let ok = export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None,
        );

        assert!(!ok, "a directory that cannot exist must fail the run");
    }

    /// A predicate with no directory is refused before anything is written.
    ///
    /// clap enforces the pairing, but `export_vcon_selection` is reachable
    /// without going through argument validation -- the same reason the
    /// no-feature `export_vcon` stub exists. An unguarded `None` here would
    /// panic or, worse, pick a default directory nobody asked for.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_predicate_without_a_directory_is_refused() {
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
        // deliberately no export_vcon_dir
        let ok = export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None,
        );
        assert!(!ok, "a destination nobody named is not a destination");
    }

    /// Each file holds the dialog it is named for.
    ///
    /// Everything else here counts files or validates one in isolation. A loop
    /// that wrote the RIGHT number of containers with the WRONG dialog in each
    /// would pass all of it -- and misattributing a conversation is the exact
    /// failure this whole feature exists to avoid.
    #[cfg(feature = "vcon")]
    #[test]
    fn each_file_holds_the_dialog_it_is_named_for() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None
        ));

        for entry in std::fs::read_dir(tmp.path()).expect("readable").flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(entry.path()).expect("readable");
            let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
            let call_id = v["dialog"][0]["sip_call_id"]
                .as_str()
                .expect("the dialog names its call")
                .to_owned();
            assert_eq!(
                name,
                vcon_file_name(&call_id),
                "{name} holds {call_id}, which belongs in a differently named file"
            );
        }
    }

    /// A capture where nothing matches writes no files and still succeeds.
    ///
    /// "Nothing matched" is an answer about the capture, not a failure of the
    /// run. Exiting non-zero there would make a shell script treat a quiet
    /// morning as a broken tool.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_capture_with_no_match_writes_nothing_and_still_succeeds() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 599");
        let ok = export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None,
        );

        assert!(ok, "an empty answer is an answer, not an error");
        let n = std::fs::read_dir(tmp.path()).expect("readable").count();
        assert_eq!(n, 0, "nothing matched, so nothing should be on disk");
    }

    /// Re-running over the same directory overwrites rather than accumulating.
    ///
    /// The filename is derived from the Call-ID, so a second run over the same
    /// capture must land on the same names. Accumulating `foo (1).vcon.json`
    /// would turn a re-run into a directory nobody can reason about.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_second_run_over_one_directory_overwrites_rather_than_accumulating() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);

        assert!(export_vcon_selection(
            &cli, None, &dialogs, &streams, 7, None
        ));
        let first = std::fs::read_dir(tmp.path()).expect("readable").count();
        assert!(export_vcon_selection(
            &cli, None, &dialogs, &streams, 7, None
        ));
        let second = std::fs::read_dir(tmp.path()).expect("readable").count();

        assert_eq!(
            first, second,
            "a second run produced {second} files where the first produced {first}"
        );
    }

    /// The containers carry this capture's completeness facts, not defaults.
    ///
    /// `export_vcon_selection` builds `CaptureFacts` once and hands the same
    /// value to every container. A path that built a default instead would
    /// emit containers claiming a clean capture regardless of what the run saw,
    /// which is the "absence reads as nothing happened" failure the vCon module
    /// is built against.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_written_container_carries_this_captures_frame_count() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            4242,
            None,
        ));

        let text = std::fs::read_to_string(&containers_in(tmp.path())[0]).expect("readable");
        assert!(
            text.contains("4242"),
            "the container must carry this run's frame count, not a default: {text}"
        );
    }

    /// The directory preparation creates what is missing, and says so.
    ///
    /// Owed because the branch this covers was previously unguardable. As an
    /// early return inside the writer, deleting it changed nothing observable:
    /// the writes that followed failed too. With a `Result` the two outcomes
    /// are distinguishable, so a test can hold them apart.
    #[cfg(feature = "vcon")]
    #[test]
    fn preparing_the_export_directory_creates_a_missing_one() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path().join("a/b/c");
        let cli = cli_exporting_to(&dir, "response_code >= 200");

        let got = prepare_export_dir(&cli).expect("a creatable path is not an error");

        assert_eq!(got, dir.as_path(), "it returns the directory it prepared");
        assert!(dir.is_dir(), "and the directory now exists");
    }

    /// ...and refuses a path it cannot make a directory, naming it.
    ///
    /// The message is the whole product of the failure: an operator reads it
    /// and fixes the path. A refusal that did not name the path would send
    /// them to the flag they typed rather than the thing in the way.
    #[cfg(feature = "vcon")]
    #[test]
    fn preparing_the_export_directory_refuses_a_path_that_is_a_file() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let blocked = tmp.path().join("blocked");
        std::fs::write(&blocked, b"not a directory").expect("write the blocker");
        let cli = cli_exporting_to(&blocked, "response_code >= 200");

        let Err(message) = prepare_export_dir(&cli) else {
            panic!("a file where a directory belongs is an error");
        };

        assert!(
            message.contains("blocked"),
            "the refusal must name the path in the way: {message}"
        );
        assert!(
            message.contains("Nothing was exported"),
            "and say that nothing was written: {message}"
        );
    }

    /// Two Call-IDs that sanitize to the same stem get different filenames.
    ///
    /// `@` becomes `_`, so `a@b` and `a_b` rendered identically and the second
    /// container silently overwrote the first. A dialog vanished from the
    /// export with no error anywhere -- the worst shape of failure this
    /// feature can have, because the directory looks complete.
    #[cfg(feature = "vcon")]
    #[test]
    fn call_ids_that_sanitize_alike_do_not_collide() {
        assert_ne!(
            vcon_file_name("a@b"),
            vcon_file_name("a_b"),
            "`@` sanitizes to `_`, so these two must not share a filename"
        );
        assert_ne!(
            vcon_file_name("1-1966@10.0.2.20"),
            vcon_file_name("1-1966_10.0.2.20"),
            "a realistic Call-ID and its sanitized twin must stay distinct"
        );
    }

    /// Two Call-IDs sharing a long prefix get different filenames.
    ///
    /// The stem is truncated, so anything past the cut used to be invisible.
    /// A proxy that numbers its Call-IDs with a long constant prefix would
    /// have every call in a capture land on one file.
    #[cfg(feature = "vcon")]
    #[test]
    fn call_ids_sharing_a_long_prefix_do_not_collide() {
        let prefix = "x".repeat(250);
        assert_ne!(
            vcon_file_name(&format!("{prefix}-one")),
            vcon_file_name(&format!("{prefix}-two")),
            "a shared 250-character prefix must not erase the difference"
        );
    }

    /// One Call-ID renders to one exact filename, pinned.
    ///
    /// Comparing two calls in the same process proves nothing: anything that
    /// varies per RUN rather than per call -- a pid, a timestamp, a counter --
    /// is constant within one process and slips straight through. The first
    /// version of this test did exactly that and survived a mutant appending
    /// `std::process::id()`.
    ///
    /// So the value is pinned. A frozen constant is usually the defect this
    /// repository hunts, but here the constant IS the contract: a re-run over
    /// one capture must overwrite its own output rather than pile up beside
    /// it, and only an exact expected name can hold that.
    #[cfg(feature = "vcon")]
    #[test]
    fn one_call_id_renders_to_one_pinned_filename() {
        assert_eq!(
            vcon_file_name("1-1966@10.0.2.20"),
            "1-1966_10.0.2.20-1cc03f180ff8a774.vcon.json",
            "the name is a stable function of the Call-ID and nothing else"
        );
        assert_eq!(
            vcon_file_name(""),
            "-e3b0c44298fc1c14.vcon.json",
            "an empty Call-ID still renders to a usable, stable name"
        );
    }

    /// The readable stem survives the disambiguation.
    ///
    /// A filename that is only a digest is safe and useless: an operator
    /// scanning the directory has to open every file to find the call. The
    /// stem is what makes the directory readable, the suffix is what makes it
    /// correct.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_filename_still_carries_the_readable_call_id() {
        let name = vcon_file_name("1-1966@10.0.2.20");
        assert!(
            name.starts_with("1-1966_10.0.2.20"),
            "the sanitized Call-ID must lead the name: {name}"
        );
        assert!(
            name.ends_with(".vcon.json"),
            "and keep its extension: {name}"
        );
    }

    /// A Call-ID of only unsafe characters still yields a usable name.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_call_id_of_only_separators_still_yields_a_usable_name() {
        for id in ["///", "@@@", "\\\\", "::::"] {
            let name = vcon_file_name(id);
            assert_eq!(
                std::path::Path::new(&name).components().count(),
                1,
                "{id:?} produced more than one path component: {name}"
            );
            assert!(
                name.ends_with(".vcon.json"),
                "{id:?} lost its extension: {name}"
            );
        }
    }

    /// A Unicode Call-ID renders to an ASCII-safe name.
    ///
    /// SIP carries UTF-8 in practice, and a filename that reached the
    /// filesystem with raw multi-byte characters would behave differently on
    /// every platform this ships to.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_unicode_call_id_renders_to_an_ascii_name() {
        let name = vcon_file_name("café-ñoño@例え.jp");
        assert!(name.is_ascii(), "the name must be ASCII: {name}");
        assert_ne!(
            vcon_file_name("café@x"),
            vcon_file_name("cafe@x"),
            "two different Call-IDs must not collapse onto one name"
        );
    }

    /// The selection walks dialogs in capture order.
    ///
    /// A directory an operator reads alongside the capture should follow the
    /// call order, and `select_dialogs` documents store order. Asserting it
    /// here stops a future reorder from silently changing what an operator
    /// sees without changing any count.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_selection_follows_capture_order() {
        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());

        let ids: Vec<String> = vcon_selection(&cli, None, &dialogs, &streams)
            .expect("a valid predicate")
            .0
            .dialogs
            .iter()
            .map(|(d, _)| d.call_id.clone())
            .collect();
        let store_ids: Vec<String> = dialogs.iter().map(|d| d.call_id.clone()).collect();
        let expected: Vec<String> = store_ids.into_iter().filter(|c| ids.contains(c)).collect();

        assert_eq!(ids, expected, "the selection must not reorder the capture");
    }

    /// A predicate naming a field the language does not have is refused.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_predicate_naming_an_unknown_field_is_refused() {
        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("nonexistent_field == 'x'".to_owned());

        let Err(err) = vcon_selection(&cli, None, &dialogs, &streams) else {
            panic!("a field the DSL does not define is not a valid expression");
        };
        assert!(
            format!("{err:#}").contains("--export-vcon-when"),
            "the refusal names the flag the operator typed: {err:#}"
        );
    }

    /// A relative export directory works.
    ///
    /// The documented examples use `./failed/`, so a path resolved against the
    /// wrong base would fail on the very command the page prints.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_relative_export_directory_is_prepared() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let nested = tmp.path().join("rel");
        let cli = cli_exporting_to(&nested, "response_code >= 200");
        let got = prepare_export_dir(&cli).expect("a relative-style path is usable");
        assert!(got.is_dir(), "the directory exists after preparation");
    }

    /// One dialog keeps one uuid across two runs of the same capture.
    ///
    /// The container's uuid is derived, not random. If it rotated per run, a
    /// consumer holding yesterday's container and today's would see two
    /// conversations where there is one.
    #[cfg(feature = "vcon")]
    #[test]
    fn one_dialog_keeps_one_uuid_across_runs() {
        let read_uuid = |dir: &std::path::Path| -> String {
            let text = std::fs::read_to_string(&containers_in(dir)[0]).expect("readable");
            let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
            v["uuid"].as_str().expect("a uuid").to_owned()
        };
        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);

        let a = tempfile::tempdir().expect("temp dir");
        assert!(export_vcon_selection(
            &cli_exporting_to(a.path(), "response_code >= 486"),
            None,
            &dialogs,
            &streams,
            7,
            None,
        ));
        let b = tempfile::tempdir().expect("temp dir");
        assert!(export_vcon_selection(
            &cli_exporting_to(b.path(), "response_code >= 486"),
            None,
            &dialogs,
            &streams,
            7,
            None,
        ));

        assert_eq!(
            read_uuid(a.path()),
            read_uuid(b.path()),
            "one dialog from one capture is one conversation, run twice"
        );
    }

    /// Every container in one run carries the same capture-level facts.
    ///
    /// `export_vcon_selection` builds `CaptureFacts` once and shares it. Built
    /// per dialog it would still work, and two containers from one capture
    /// could then disagree about how many frames that capture held.
    #[cfg(feature = "vcon")]
    #[test]
    fn every_container_in_a_run_agrees_about_the_capture() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            4242,
            None,
        ));

        let counts: std::collections::HashSet<String> = std::fs::read_dir(tmp.path())
            .expect("readable")
            .flatten()
            .map(|e| {
                let text = std::fs::read_to_string(e.path()).expect("readable");
                let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
                v["analysis"][0]["body"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned()
            })
            .map(|b| {
                b.split("frames_read")
                    .nth(1)
                    .unwrap_or_default()
                    .chars()
                    .filter(char::is_ascii_digit)
                    .take(6)
                    .collect::<String>()
            })
            .collect();
        assert_eq!(counts.len(), 1, "one capture, one frame count: {counts:?}");
    }

    /// A predicate reading a media field selects without a stream store.
    ///
    /// `matches_dialog` builds a media diagnosis only when the expression
    /// needs one, and an empty store is the ordinary signaling-only case. A
    /// panic here would take out every `-I` run over a capture with no RTP.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_media_predicate_survives_an_empty_stream_store() {
        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("rtp.codec == 'PCMU'".to_owned());

        let (picked, _, _) =
            vcon_selection(&cli, None, &dialogs, &streams).expect("a valid predicate");
        assert!(
            picked.dialogs.is_empty(),
            "no streams means no dialog carries PCMU"
        );
    }

    /// An empty predicate string is refused rather than matching everything.
    ///
    /// `--export-vcon-when ''` is a plausible scripting accident, and the
    /// dangerous reading is "match everything" -- that writes a container for
    /// every call in the capture when the operator meant to write none.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_empty_predicate_is_refused_rather_than_matching_everything() {
        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some(String::new());

        match vcon_selection(&cli, None, &dialogs, &streams) {
            Err(_) => {}
            Ok((sel, _, _)) => assert!(
                sel.dialogs.is_empty(),
                "an empty expression must not select every dialog: {} selected",
                sel.dialogs.len()
            ),
        }
    }

    /// Containers land in the directory given, not the working directory.
    #[cfg(feature = "vcon")]
    #[test]
    fn containers_land_only_in_the_directory_given() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let target = tmp.path().join("target");
        let cli = cli_exporting_to(&target, "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None
        ));

        let inside = std::fs::read_dir(&target).expect("readable").count();
        let stray = std::fs::read_dir(tmp.path())
            .expect("readable")
            .flatten()
            .filter(|e| e.path() != target)
            .count();
        assert!(inside > 0, "the containers went somewhere");
        assert_eq!(stray, 0, "and nothing landed beside the directory");
    }

    /// The written file is named exactly as `vcon_file_name` renders it.
    ///
    /// The writer and the namer could drift: a writer that built its own path
    /// would pass every content test while making the sanitizer decorative.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_writer_uses_the_sanitizer_for_every_name() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let dialogs = two_dialogs_one_failed();
        let streams = StreamStore::new(16);
        assert!(export_vcon_selection(
            &cli, None, &dialogs, &streams, 7, None
        ));

        let expected: std::collections::HashSet<String> =
            vcon_selection(&cli, None, &dialogs, &streams)
                .expect("valid")
                .0
                .dialogs
                .iter()
                .map(|(d, _)| vcon_file_name(&d.call_id))
                .collect();
        let actual: std::collections::HashSet<String> = std::fs::read_dir(tmp.path())
            .expect("readable")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            actual, expected,
            "the writer must name files the way the sanitizer does"
        );
    }

    /// A container carries the observer party, never a display name.
    ///
    /// The vCon module has no `Party.name` field so the rule cannot be broken
    /// by an edit, and this asserts the property end to end through the new
    /// path rather than trusting the type alone.
    /// PV12: the digest line is one `sha256sum -c` can actually read.
    ///
    /// Not a signature, and this test is where that distinction is kept
    /// honest: a signature over sipnab's bytes cannot verify against the
    /// object a store holds, because a conserver adds fields on ingest. The
    /// digest claims only what sipnab wrote.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_digest_line_is_in_the_format_sha256sum_reads() {
        let line = digest_line(std::path::Path::new("/spool/call-id.vcon.json"), b"{}");

        // Known-answer: SHA-256 of the two bytes `{}`.
        let (hex, name) = line
            .split_once("  ")
            .expect("two spaces separate digest from name, as `sha256sum -c` requires");
        assert_eq!(
            hex, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            "the digest must be over the CONTAINER bytes and nothing else"
        );
        assert_eq!(
            name, "call-id.vcon.json",
            "the name is the file alone, so a spool that moved still verifies \
             from inside its own directory"
        );
        assert_eq!(hex.len(), 64, "SHA-256 renders as 64 hex characters");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "`sha256sum` writes lowercase hex: {hex}"
        );
    }

    /// Different bytes, different digest — and identical bytes agree.
    ///
    /// The anti-vacuity half. A digest_line that ignored its input would pass
    /// the format test above on every call.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_digest_follows_the_bytes_not_the_name() {
        let p = std::path::Path::new("a.json");
        let q = std::path::Path::new("b.json");

        let a = digest_line(p, br#"{"vcon":"0.4.0"}"#);
        let b = digest_line(p, br#"{"vcon":"0.4.1"}"#);
        assert_ne!(
            a, b,
            "one changed byte in the container must change the digest, or the \
             line certifies nothing"
        );

        let same_bytes_other_name = digest_line(q, br#"{"vcon":"0.4.0"}"#);
        assert_eq!(
            a.split_once("  ").expect("split").0,
            same_bytes_other_name.split_once("  ").expect("split").0,
            "the digest covers the bytes; renaming a container does not \
             change what it contains"
        );
    }

    /// PV13: a container appears in the spool whole or not at all.
    ///
    /// `--export-vcon-dir` is a queue an external bridge polls. A bridge that
    /// reads a file the moment it appears gets whatever bytes have landed so
    /// far, and `std::fs::write` truncates the destination and then fills it —
    /// so the window where the file exists and is invalid is the whole write.
    /// A same-directory rename has no such window: the name resolves to the
    /// old container or the new one, never to half of either.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_spool_stages_beside_its_destination_so_the_rename_is_atomic() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dest = dir.path().join("call-id.vcon.json");
        let staged = spool_staging_path(&dest);

        assert_eq!(
            staged.parent(),
            dest.parent(),
            "the staging file must share the destination's directory: a \
             rename across filesystems is not atomic and can fail outright, \
             which is exactly what staging in the system temp dir would do"
        );
        assert_ne!(
            staged, dest,
            "staging under the final name defeats the point"
        );
        assert!(
            staged
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('.')),
            "a staging file a directory listing shows is a container a bridge \
             will try to read: {}",
            staged.display()
        );
    }

    /// A completed write leaves the container and nothing else.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_completed_spool_write_leaves_no_staging_file_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dest = dir.path().join("call-id.vcon.json");

        write_container_atomically(&dest, br#"{"vcon":"0.4.0"}"#).expect("writes");

        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .expect("readable")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries,
            vec!["call-id.vcon.json".to_string()],
            "a staging file left in the spool is one a bridge eventually \
             picks up as a container: {entries:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&dest).expect("readable"),
            r#"{"vcon":"0.4.0"}"#
        );
    }

    /// A failed write leaves the PREVIOUS container intact.
    ///
    /// This is the property `fs::write` cannot offer. It opens the
    /// destination with truncate, so a write that fails after that leaves the
    /// spool holding a file that is neither the old container nor the new one
    /// — and the bridge has no way to tell.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_failed_spool_write_does_not_destroy_what_was_already_there() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dest = dir.path().join("call-id.vcon.json");
        std::fs::write(&dest, r#"{"vcon":"0.4.0","uuid":"the-old-one"}"#).expect("seed");

        // A directory where the staging file needs to be is a write that
        // cannot succeed, and it fails at the same point a full disk would.
        let staged = spool_staging_path(&dest);
        std::fs::create_dir(&staged).expect("occupy the staging name");

        assert!(
            write_container_atomically(&dest, br#"{"vcon":"0.4.0","uuid":"the-new-one"}"#).is_err(),
            "the write must report the failure rather than half-performing it"
        );
        assert_eq!(
            std::fs::read_to_string(&dest).expect("readable"),
            r#"{"vcon":"0.4.0","uuid":"the-old-one"}"#,
            "the previous container must survive a failed replacement"
        );
    }

    #[cfg(feature = "vcon")]
    #[test]
    fn a_written_container_names_no_party() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None
        ));

        let text = std::fs::read_to_string(&containers_in(tmp.path())[0]).expect("readable");
        let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        for party in v["parties"].as_array().expect("parties") {
            assert_eq!(
                party["validation"], "none",
                "every party says it is unverified: {party}"
            );
            // A `name` IS emitted -- a From header is what somebody wrote, and
            // `validation: "none"` above is what says so. The two travel
            // together or the name reads as an identity someone established.
            if party.get("name").is_some() {
                assert!(
                    party.get("validation").is_some(),
                    "a name with no `validation` beside it asserts an \
                     identity: {party}"
                );
            }
        }
    }

    /// A container from the predicate path carries no by-reference url.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_written_container_carries_no_url() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None
        ));

        let text = std::fs::read_to_string(&containers_in(tmp.path())[0]).expect("readable");
        assert!(
            !text.contains("\"url\""),
            "sipnab hosts nothing, so a container never points elsewhere: {text}"
        );
    }

    /// No container emits an explicit null.
    ///
    /// "Absent, never null" is the module's standing contract, and the
    /// container stored on thor-02 by an earlier release violates it -- with
    /// `url`, `mediatype` and `duration` all null. This asserts the property
    /// on the path this task added.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_written_container_emits_no_explicit_null() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None
        ));

        // EVERY container, not whichever one `read_dir` happened to yield
        // first. This test read one arbitrary file and passed for two
        // releases because that file was the answered dialog; the moment
        // container filenames changed, CI drew the FAILED one instead and the
        // assertion fired. A test whose verdict depends on directory order
        // is not testing what it claims to.
        let mut checked = 0;
        for entry in std::fs::read_dir(tmp.path()).expect("readable").flatten() {
            let text = std::fs::read_to_string(entry.path()).expect("readable");
            let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
            assert_no_null_in_container(&v, &text);
            checked += 1;
        }
        assert_eq!(
            checked, 2,
            "the fixture writes two containers and both must be checked"
        );
    }

    /// Assert the vCon container's OWN fields carry no explicit null.
    ///
    /// The nested `analysis[].body` is deliberately excluded, and that is not
    /// a loophole. It carries a `SignalingDiagnosis`, whose seven always-run
    /// detections document `null` as meaning "checked, not found" -- the exact
    /// opposite convention, adopted for the exact same reason this one was.
    /// The eighth detection is omitted when absent precisely BECAUSE a null
    /// there would read as "checked" on a capture that held no ICMP.
    ///
    /// A raw `text.contains(":null")` cannot tell the two apart, so it was
    /// asserting the vCon module's contract over another module's output.
    /// `capture_completeness` lives inside that same body and IS checked,
    /// because it belongs to this module.
    #[cfg(feature = "vcon")]
    fn assert_no_null_in_container(v: &serde_json::Value, text: &str) {
        fn walk(v: &serde_json::Value, path: &str, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Null => out.push(path.to_owned()),
                serde_json::Value::Object(m) => {
                    for (k, child) in m {
                        walk(child, &format!("{path}.{k}"), out);
                    }
                }
                serde_json::Value::Array(a) => {
                    for (i, child) in a.iter().enumerate() {
                        walk(child, &format!("{path}[{i}]"), out);
                    }
                }
                _ => {}
            }
        }

        let mut nulls = Vec::new();
        let mut container = v.clone();
        // Lift `capture_completeness` out of each analysis body and drop the
        // body itself: this module owns the first and not the second.
        if let Some(items) = container
            .get_mut("analysis")
            .and_then(serde_json::Value::as_array_mut)
        {
            for item in items.iter_mut() {
                let completeness = item
                    .get("body")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                    .and_then(|b| b.get("capture_completeness").cloned());
                if let Some(obj) = item.as_object_mut() {
                    obj.remove("body");
                    if let Some(c) = completeness {
                        obj.insert("capture_completeness".to_owned(), c);
                    }
                }
            }
        }
        walk(&container, "", &mut nulls);
        assert!(
            nulls.is_empty(),
            "an absent field is absent, never null -- found at {nulls:?} in: {text}"
        );
    }

    /// A real FAILED dialog's container carries the diagnosis nulls, and
    /// passes.
    ///
    /// The synthetic fixtures above prove the exclusion is drawn correctly.
    /// This proves it is drawn around something that actually happens: the
    /// 486 container is the exact file CI drew and this test drew nothing
    /// about until now. Without it the exclusion is calibrated only against
    /// JSON a test author wrote.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_failed_dialogs_container_really_does_carry_the_deliberate_nulls() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None,
        ));

        let mut saw_deliberate_nulls = false;
        for entry in std::fs::read_dir(tmp.path()).expect("readable").flatten() {
            let text = std::fs::read_to_string(entry.path()).expect("readable");
            let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
            let body: serde_json::Value = serde_json::from_str(
                v["analysis"][0]["body"]
                    .as_str()
                    .unwrap_or_else(|| panic!("an analysis body is a string: {v}")),
            )
            .expect("the analysis body parses");
            if body["signaling_diagnosis"]["abandoned"].is_null()
                && !body["signaling_diagnosis"]["final_failure"].is_null()
            {
                saw_deliberate_nulls = true;
            }
        }
        assert!(
            saw_deliberate_nulls,
            "the fixture must write a container whose diagnosis carries the \
             deliberate nulls, or the exclusion is calibrated against nothing"
        );
    }

    /// Both containers carry the completeness block, whatever the read order.
    ///
    /// The property the broken test needed and did not have: the verdict is
    /// the same for every file in the directory, so which one `read_dir`
    /// yields first cannot change the answer.
    #[cfg(feature = "vcon")]
    #[test]
    fn every_container_carries_the_completeness_block_not_just_the_first() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None,
        ));

        let mut seen = 0;
        for entry in std::fs::read_dir(tmp.path()).expect("readable").flatten() {
            let text = std::fs::read_to_string(entry.path()).expect("readable");
            let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
            let body: serde_json::Value =
                serde_json::from_str(v["analysis"][0]["body"].as_str().expect("a string body"))
                    .expect("parses");
            let c = &body["capture_completeness"];
            for key in ["gate_closed_during_run", "dialogs_suppressed_by_deny"] {
                assert!(
                    c.get(key).is_some_and(|x| !x.is_null()),
                    "{key} missing from a container: {c}"
                );
            }
            seen += 1;
        }
        assert_eq!(seen, 2, "both containers were read");
    }

    /// The null verdict is the same whichever end of the directory you start.
    ///
    /// The property the broken test needed and could not have had while it
    /// read one entry. Sorting makes the ORDER fixed; this makes the ANSWER
    /// independent of it, which is the stronger claim and the one that was
    /// actually violated: forwards the export looked clean, backwards it did
    /// not, and both were the same correct export.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_null_verdict_is_the_same_in_either_direction() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed(),
            &StreamStore::new(16),
            7,
            None,
        ));

        let paths = containers_in(tmp.path());
        assert!(
            paths.len() > 1,
            "one container cannot have an order; the fixture must write two"
        );

        let verdict = |ps: &[std::path::PathBuf]| {
            for path in ps {
                let text = std::fs::read_to_string(path).expect("readable");
                let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
                assert_no_null_in_container(&v, &text);
            }
        };
        verdict(&paths);
        let mut reversed = paths.clone();
        reversed.reverse();
        verdict(&reversed);
    }

    /// The exclusion above is narrow: a null the vCon module itself emits is
    /// still caught.
    ///
    /// Owed for the failure. Without this, the fix could be over-broad --
    /// excluding the whole analysis entry rather than only the foreign body
    /// would silence the contract everywhere it matters and no test would say
    /// so.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_null_check_still_catches_a_null_the_container_itself_emits() {
        let mut v: serde_json::Value = serde_json::json!({
            "vcon": "0.4.0",
            "parties": [{"tel": null}],
            "analysis": [{
                "type": "sipnab-analysis",
                "body": "{\"signaling_diagnosis\":{\"abandoned\":null}}"
            }]
        });
        let text = v.to_string();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_no_null_in_container(&v, &text);
        }));
        assert!(
            caught.is_err(),
            "a null on a container field must still fail the check"
        );

        // ...and the foreign body's deliberate nulls alone do NOT fail it.
        v["parties"] = serde_json::json!([{"tel": "+15551234"}]);
        let text = v.to_string();
        assert_no_null_in_container(&v, &text);
    }

    /// A null inside `capture_completeness` fails, even though it rides in the
    /// analysis body.
    ///
    /// The second half of the exclusion: this module's own block is lifted OUT
    /// of the foreign body and checked. An exclusion drawn one level too high
    /// would drop it, which is where the two new fields live.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_null_in_capture_completeness_is_caught_despite_riding_in_the_body() {
        let body = serde_json::json!({
            "capture_completeness": {"frames_read": 7, "media_note": null},
            "signaling_diagnosis": {"abandoned": null}
        })
        .to_string();
        let v = serde_json::json!({
            "vcon": "0.4.0",
            "analysis": [{"type": "sipnab-analysis", "body": body}]
        });
        let text = v.to_string();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_no_null_in_container(&v, &text);
        }));
        assert!(
            caught.is_err(),
            "capture_completeness belongs to this module and its nulls must be caught"
        );
    }

    /// An INVITE carrying one extra header, for the deny/permit fixtures.
    #[cfg(feature = "vcon")]
    fn invite_with_header(call_id: &str, name: &str, value: &str) -> sip::message::SipMessage {
        let headers = [
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-abc".to_string(),
            "From: Alice <sip:alice@example.com>;tag=a1b2".to_string(),
            "To: Bob <sip:bob@example.com>".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".to_string(),
            "Max-Forwards: 70".to_string(),
            format!("{name}: {value}"),
            "Content-Length: 0".to_string(),
        ];
        let mut msg = String::from("INVITE sip:bob@example.com SIP/2.0\r\n");
        for h in headers {
            msg.push_str(&h);
            msg.push_str("\r\n");
        }
        msg.push_str("\r\n");
        let data = bytes::Bytes::from(msg.into_bytes());
        sip::parser::parse_sip_bytes(
            &data,
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("fixture parses")
    }

    /// Two dialogs, both answered, the first carrying `name: value`.
    #[cfg(feature = "vcon")]
    fn two_dialogs_first_flagged(name: &str, value: &str) -> DialogStore {
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_with_header("flagged@example.com", name, value));
        store.process_message(response_msg("flagged@example.com", 200, "OK"));
        store.process_message(invite_msg("plain@example.com"));
        store.process_message(response_msg("plain@example.com", 200, "OK"));
        store
    }

    /// Without the flag, a denied dialog leaves no file at all.
    ///
    /// The conservative default, asserted so it cannot drift: turning
    /// suppression into a tombstone reveals the call existed, and that is the
    /// operator's decision rather than sipnab's.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_denied_dialog_writes_nothing_unless_a_tombstone_is_asked_for() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let mut cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());
        assert!(
            !cli.output_args.content_deny_tombstone,
            "the default is off"
        );

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_first_flagged("X-No-Record", "1"),
            &StreamStore::new(16),
            7,
            None
        ));

        let files = containers_in(tmp.path());
        assert_eq!(
            files.len(),
            1,
            "only the undenied dialog may produce a file: {files:?}"
        );
        let text = std::fs::read_to_string(&files[0]).expect("readable");
        assert!(
            !text.contains("flagged@example.com"),
            "the denied dialog must not appear anywhere: {text}"
        );
    }

    /// With the flag, the denied dialog gets an identity-only container.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_tombstone_declares_the_redaction_and_carries_no_trace() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let mut cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());
        cli.output_args.content_deny_tombstone = true;

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_first_flagged("X-No-Record", "1"),
            &StreamStore::new(16),
            7,
            None
        ));

        let files = containers_in(tmp.path());
        assert_eq!(files.len(), 2, "one kept, one tombstone: {files:?}");

        let tombstone = files
            .iter()
            .map(|p| std::fs::read_to_string(p).expect("readable"))
            .find(|t| t.contains("flagged@example.com"))
            .expect("the denied dialog has a container");
        let v: serde_json::Value = serde_json::from_str(&tombstone).expect("valid JSON");

        assert_eq!(
            v["redacted"]["type"], "content-withheld",
            "the withholding must be declared in the registered field: {v}"
        );
        assert!(
            v["redacted"].get("uuid").is_none(),
            "there is no unredacted instance to name: {}",
            v["redacted"]
        );
        assert!(
            !tombstone.contains("X-No-Record: "),
            "the header VALUE is content the deny rule covers: {tombstone}"
        );
        let purposes: Vec<&str> = v["attachments"]
            .as_array()
            .expect("attachments")
            .iter()
            .filter_map(|a| a["purpose"].as_str())
            .collect();
        assert!(
            !purposes.contains(&"sip-message-trace"),
            "the trace is exactly what was withheld: {purposes:?}"
        );
    }

    /// A deny header suppresses a dialog the predicate selected.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_deny_header_suppresses_a_dialog_the_predicate_selected() {
        let dialogs = two_dialogs_first_flagged("X-No-Record", "1");
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

        let ids: Vec<String> = vcon_selection(&cli, None, &dialogs, &streams)
            .expect("valid")
            .0
            .dialogs
            .iter()
            .map(|(d, _)| d.call_id.clone())
            .collect();

        assert!(
            !ids.iter().any(|c| c == "flagged@example.com"),
            "the predicate selected it and the deny flag overrides that: {ids:?}"
        );
        assert!(
            ids.iter().any(|c| c == "plain@example.com"),
            "the unflagged dialog is untouched: {ids:?}"
        );
    }

    /// A permit header NEVER causes a container to exist.
    ///
    /// The one test here guarding a security property rather than a
    /// correctness one. A header asking to be recorded is an assertion by
    /// whoever sent the request, and this module already refuses that class of
    /// claim -- every party carries `validation: "none"`. Acting on one to be
    /// MORE conservative costs a container nobody kept. Acting on one to
    /// RETAIN content hands the retention decision to anyone who can set a
    /// header.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_permit_header_never_causes_a_container_to_exist() {
        // The predicate selects NOTHING. The permit header sits on a dialog
        // it rejected.
        let dialogs = two_dialogs_first_flagged("X-Record-Session", "yes");
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 599".to_owned());
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

        let (picked, _, _) = vcon_selection(&cli, None, &dialogs, &streams).expect("valid");

        assert!(
            picked.dialogs.is_empty(),
            "a header asking to be recorded must never add a dialog the \
             predicate rejected -- that hands retention to anyone who can set \
             a header: {:?}",
            picked
                .dialogs
                .iter()
                .map(|(d, _)| &d.call_id)
                .collect::<Vec<_>>()
        );
    }

    /// The deny match is case-insensitive, as SIP header names are.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_deny_header_matches_regardless_of_case() {
        let dialogs = two_dialogs_first_flagged("x-no-record", "1");
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

        let ids: Vec<String> = vcon_selection(&cli, None, &dialogs, &streams)
            .expect("valid")
            .0
            .dialogs
            .iter()
            .map(|(d, _)| d.call_id.clone())
            .collect();

        assert!(
            !ids.iter().any(|c| c == "flagged@example.com"),
            "RFC 3261 7.3.1 makes header names case-insensitive, so a filter \
             keyed on exact case is one an ordinary peer walks through: {ids:?}"
        );
    }

    /// Presence suppresses, whatever the value says.
    ///
    /// A rule keyed on a value raises the question of what an unrecognized
    /// value means, and the only safe answer to "I do not understand this deny
    /// flag" is to deny.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_deny_header_suppresses_on_presence_not_value() {
        for value in ["", "0", "false", "no", "anything at all"] {
            let dialogs = two_dialogs_first_flagged("X-No-Record", value);
            let streams = StreamStore::new(16);
            let mut cli = Cli::parse_from_args(["sipnab"]);
            cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
            cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

            let ids: Vec<String> = vcon_selection(&cli, None, &dialogs, &streams)
                .expect("valid")
                .0
                .dialogs
                .iter()
                .map(|(d, _)| d.call_id.clone())
                .collect();

            assert!(
                !ids.iter().any(|c| c == "flagged@example.com"),
                "value {value:?} must not re-enable the dialog: {ids:?}"
            );
        }
    }

    /// With no header named, the feature is inert.
    #[cfg(feature = "vcon")]
    #[test]
    fn no_deny_header_named_means_nothing_is_suppressed() {
        let dialogs = two_dialogs_first_flagged("X-No-Record", "1");
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
        // no content_deny_header

        let n = vcon_selection(&cli, None, &dialogs, &streams)
            .expect("valid")
            .0
            .dialogs
            .len();
        assert_eq!(n, 2, "sipnab ships no opinion about which header you use");
    }

    /// An RtpStream fixture, so the deny filter can be given media to drop.
    #[cfg(feature = "vcon")]
    fn rtp_stream_fixture(port: u16) -> crate::rtp::stream::RtpStream {
        use crate::rtp::stream::{RtpStream, StreamKey};
        let key = StreamKey {
            src: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port),
            dst: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), port + 1),
            ssrc: u32::from(port),
        };
        let hdr = crate::rtp::parser::RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 100,
            timestamp: 0,
            ssrc: u32::from(port),
            payload_offset: 12,
        };
        RtpStream::new(key, &hdr, chrono::Utc::now())
    }

    /// Suppressing a dialog suppresses its media too.
    ///
    /// `DialogSelection::streams` is documented as the streams linked to a
    /// SELECTED dialog, "so the media on screen belongs to the calls on
    /// screen". Retaining only `dialogs` left a denied dialog's media in the
    /// struct -- suppression that stops halfway, on the one feature whose
    /// whole job is to suppress completely.
    ///
    /// The first version of this test ran through `vcon_selection` with an
    /// EMPTY stream store, so it compared zero to zero and passed without
    /// touching the behavior. This one hands the filter real media.
    #[cfg(feature = "vcon")]
    #[test]
    fn suppressing_a_dialog_suppresses_its_media_too() {
        let store = two_dialogs_first_flagged("X-No-Record", "1");
        let dialogs: Vec<&crate::sip::dialog::SipDialog> = store.iter().collect();
        let flagged_media = rtp_stream_fixture(20000);
        let plain_media = rtp_stream_fixture(20010);

        let selection = crate::sip::dsl::DialogSelection {
            dialogs: dialogs
                .iter()
                .map(|d| {
                    let media = if d.call_id == "flagged@example.com" {
                        vec![&flagged_media]
                    } else {
                        vec![&plain_media]
                    };
                    (*d, media)
                })
                .collect(),
            streams: vec![&flagged_media, &plain_media],
        };
        assert_eq!(selection.streams.len(), 2, "the fixture carries media");

        let (filtered, _, _) = split_denied(selection, Some("X-No-Record"));

        assert_eq!(filtered.dialogs.len(), 1, "the flagged dialog is gone");
        assert_eq!(
            filtered.streams.len(),
            1,
            "and its media went with it -- suppression is not partial"
        );
        assert!(
            std::ptr::eq(filtered.streams[0], &plain_media),
            "the surviving stream belongs to the surviving dialog"
        );
    }

    /// With no header named the filter returns the selection untouched.
    ///
    /// The `None` branch of `apply_deny_filter`, which nothing reached
    /// directly. A branch that quietly dropped media when the feature is OFF
    /// would break every run that does not use it.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_deny_filter_with_no_header_changes_nothing() {
        let store = two_dialogs_first_flagged("X-No-Record", "1");
        let dialogs: Vec<&crate::sip::dialog::SipDialog> = store.iter().collect();
        let media = rtp_stream_fixture(20000);
        let selection = crate::sip::dsl::DialogSelection {
            dialogs: dialogs.iter().map(|d| (*d, vec![&media])).collect(),
            streams: vec![&media],
        };

        let (out, _, _) = split_denied(selection, None);

        assert_eq!(out.dialogs.len(), 2, "no header named, nothing suppressed");
        assert_eq!(out.streams.len(), 1, "and no media dropped");
    }

    /// The filter never grows the selection, whatever the header.
    ///
    /// The narrowing rule as a property rather than a case: every input other
    /// than the command line may only subtract. A future edit that added a
    /// dialog here -- for a permit header, for a special value, for anything
    /// read off the wire -- breaks this without needing that specific case
    /// to be imagined first.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_deny_filter_never_grows_the_selection() {
        let store = two_dialogs_first_flagged("X-Record-Session", "yes");
        let dialogs: Vec<&crate::sip::dialog::SipDialog> = store.iter().collect();
        let media = rtp_stream_fixture(20000);
        for header in [
            "X-No-Record",
            "X-Record-Session",
            "Privacy",
            "Absent-Header",
        ] {
            let selection = crate::sip::dsl::DialogSelection {
                dialogs: dialogs.iter().map(|d| (*d, vec![&media])).collect(),
                streams: vec![&media],
            };
            let before = selection.dialogs.len();
            let after = split_denied(selection, Some(header)).0.dialogs.len();
            assert!(
                after <= before,
                "{header} grew the selection from {before} to {after}"
            );
        }
    }

    /// A deny header on a later message suppresses the dialog.
    ///
    /// The flag can arrive on the 200, not only the INVITE -- a B2BUA that
    /// decides on answer marks it there. Checking only the first message
    /// would miss every one of those.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_deny_header_on_a_later_message_still_suppresses() {
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_msg("late@example.com"));
        store.process_message(response_msg_with_header(
            "late@example.com",
            200,
            "OK",
            "X-No-Record",
            "1",
        ));
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

        let n = vcon_selection(&cli, None, &store, &streams)
            .expect("valid")
            .0
            .dialogs
            .len();
        assert_eq!(
            n, 0,
            "a flag on the answer counts as much as one on the INVITE"
        );
    }

    /// The FLAG's case does not have to match the header's.
    ///
    /// The earlier case test varied the header on the wire. This varies what
    /// the operator typed, which is the half a `to_lowercase` on only one side
    /// would break.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_deny_flag_name_may_differ_in_case_from_the_header() {
        let dialogs = two_dialogs_first_flagged("X-No-Record", "1");
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
        cli.output_args.content_deny_header = Some("x-NO-record".to_owned());

        let ids: Vec<String> = vcon_selection(&cli, None, &dialogs, &streams)
            .expect("valid")
            .0
            .dialogs
            .iter()
            .map(|(d, _)| d.call_id.clone())
            .collect();
        assert!(
            !ids.iter().any(|c| c == "flagged@example.com"),
            "what the operator typed is case-insensitive too: {ids:?}"
        );
    }

    /// Both deny headers this project documents are usable as written.
    ///
    /// `docs/cli-reference.md` prints `X-No-Record` and `Privacy`. A name the
    /// flag cannot accept would fail on the command the page tells an operator
    /// to run.
    #[cfg(feature = "vcon")]
    #[test]
    fn every_documented_deny_header_is_usable() {
        for header in ["X-No-Record", "Privacy"] {
            let dialogs = two_dialogs_first_flagged(header, "id");
            let streams = StreamStore::new(16);
            let mut cli = Cli::parse_from_args(["sipnab"]);
            cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
            cli.output_args.content_deny_header = Some(header.to_owned());

            let ids: Vec<String> = vcon_selection(&cli, None, &dialogs, &streams)
                .expect("valid")
                .0
                .dialogs
                .iter()
                .map(|(d, _)| d.call_id.clone())
                .collect();
            assert!(
                !ids.iter().any(|c| c == "flagged@example.com"),
                "{header} is documented, so it has to work: {ids:?}"
            );
        }
    }

    /// A response carrying one extra header.
    #[cfg(feature = "vcon")]
    fn response_msg_with_header(
        call_id: &str,
        code: u16,
        reason: &str,
        name: &str,
        value: &str,
    ) -> sip::message::SipMessage {
        let headers = [
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-abc".to_string(),
            "From: Alice <sip:alice@example.com>;tag=a1b2".to_string(),
            "To: Bob <sip:bob@example.com>;tag=c3d4".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".to_string(),
            format!("{name}: {value}"),
            "Content-Length: 0".to_string(),
        ];
        let mut msg = format!("SIP/2.0 {code} {reason}\r\n");
        for h in headers {
            msg.push_str(&h);
            msg.push_str("\r\n");
        }
        msg.push_str("\r\n");
        let data = bytes::Bytes::from(msg.into_bytes());
        sip::parser::parse_sip_bytes(
            &data,
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("fixture parses")
    }

    // ── Capture-quality reporting (CT1/G1) ───────────────────────────────

    /// A clean capture must stay quiet, for the same reason a clean retention
    /// run does: a warning that fires on every run is one operators skim past.
    ///
    /// Every one of the four counters this reads is process-global, and it
    /// reads each of them TWICE — once directly, once inside
    /// `capture_quality_summary` — so it holds the key of every group that
    /// writes one. Holding only `kernel_drop_counts` (which is where this
    /// started) left the undecodable tally and the invalid-timestamp counter
    /// free to move between the two reads and flip the branch under it.
    #[test]
    #[serial_test::serial(invalid_timestamps, kernel_drop_counts, undecodable_tally)]
    fn a_clean_capture_reports_no_quality_loss() {
        // One of the four is resettable, so start it from a known zero rather
        // than from whatever ran before. The other three are monotonic with no
        // reset, so the invariant that actually matters is asserted instead:
        // silence iff all four signals are zero.
        crate::capture::reset_undecodable_frames();
        let (dropped, if_dropped) = crate::capture::live::kernel_drop_counts();
        let bad_ts = crate::capture::live::INVALID_PCAP_TIMESTAMPS
            .load(std::sync::atomic::Ordering::Relaxed);
        let undecodable = crate::capture::undecodable_frames();
        let summary = capture_quality_summary();
        if dropped == 0 && if_dropped == 0 && bad_ts == 0 && undecodable == 0 {
            assert_eq!(summary, None, "a clean capture must report nothing");
        } else {
            assert!(
                summary.is_some(),
                "counters are nonzero ({dropped}/{if_dropped}/{bad_ts}/{undecodable}) \
                 so the summary must not be silent"
            );
        }
    }

    // ── Frames sipnab could not decode ──────────────────────────────
    //
    // The defect these gate: a capture sipnab decoded 0% of printed
    // "N packets captured, 0 SIP messages, 0 RTP packets across 0 streams"
    // and then "No SIP traffic found.", exit 0 — textually identical to a
    // clean read of a capture that genuinely holds no SIP.

    /// Build a report by hand so the wording is gated without driving the
    /// process-global tally.
    fn undecodable_of(
        frames: u64,
        reasons: &[(crate::capture::UndecodableReason, u64)],
    ) -> crate::capture::UndecodableReport {
        crate::capture::UndecodableReport {
            frames,
            reasons: reasons
                .iter()
                .map(|&(reason, frames)| crate::capture::UndecodableTally { reason, frames })
                .collect(),
            reasons_dropped: 0,
        }
    }

    /// A run that decoded everything says nothing — the same rule the
    /// retention and capture-quality summaries follow.
    #[test]
    fn a_fully_decoded_run_reports_no_undecodable_frames() {
        assert_eq!(undecodable_summary(&undecodable_of(0, &[]), 4_212), None);
    }

    /// The notice names the count, the proportion, and every reason WITH its
    /// number. "Unsupported link type" without the "0" names no capture
    /// format, and an operator cannot act on it.
    #[test]
    fn the_notice_names_the_count_the_share_and_the_numbers() {
        let msg = undecodable_summary(
            &undecodable_of(
                49,
                &[(
                    crate::capture::UndecodableReason::UnsupportedLinkType(0),
                    49,
                )],
            ),
            49,
        )
        .expect("49 undecodable frames must be reported");
        assert!(msg.starts_with("NOT DECODED:"), "wrong prefix: {msg}");
        assert!(msg.contains("49 of 49 frame(s)"), "counts missing: {msg}");
        assert!(msg.contains("100.0%"), "share missing: {msg}");
        assert!(
            msg.contains("unsupported link type 0 (49)"),
            "the DLT NUMBER must appear with its count: {msg}"
        );
    }

    /// A high share must be EMPHATIC. Getting zero from a capture that was
    /// almost entirely unreadable is a different statement from getting zero
    /// from a clean read, and the notice has to say which one happened.
    #[test]
    fn a_high_undecodable_share_is_emphatic() {
        // Half the capture: mostly blind, but something was read.
        let mostly = undecodable_summary(
            &undecodable_of(
                50,
                &[(
                    crate::capture::UndecodableReason::UnsupportedLinkType(0),
                    50,
                )],
            ),
            100,
        )
        .expect("reported");
        assert!(
            mostly.contains("THIS ANALYSIS IS MOSTLY BLIND"),
            "half a capture unread must be emphatic: {mostly}"
        );
        assert!(
            mostly.contains("not evidence of absence"),
            "a blind run must refuse to let a zero read as a finding: {mostly}"
        );

        // All of it: a different and stronger finding, and the one this whole
        // counter exists for.
        let nothing = undecodable_summary(
            &undecodable_of(
                49,
                &[(
                    crate::capture::UndecodableReason::UnsupportedLinkType(0),
                    49,
                )],
            ),
            49,
        )
        .expect("reported");
        assert!(
            nothing.contains("NOTHING IN THIS CAPTURE WAS READ"),
            "100% unread is not 'mostly': {nothing}"
        );
        assert!(
            !nothing.contains("MOSTLY BLIND"),
            "the two tiers must not both fire: {nothing}"
        );

        // One undecodable ARP frame in a healthy capture is normal traffic and
        // must NOT trigger the emphatic wording, or the signal is worthless.
        let noise = undecodable_summary(
            &undecodable_of(1, &[(crate::capture::UndecodableReason::NotIp(None), 1)]),
            10_000,
        )
        .expect("still reported");
        assert!(
            !noise.contains("not evidence of absence"),
            "ordinary non-IP background must not be alarming: {noise}"
        );
        assert!(
            noise.contains("1 of 10000 frame(s)"),
            "it is still reported, with its numbers: {noise}"
        );
    }

    /// Reasons the tally could not keep are declared, so the breakdown never
    /// silently fails to add up to the total.
    #[test]
    fn dropped_reasons_are_declared_not_hidden() {
        let mut report = undecodable_of(
            30,
            &[(
                crate::capture::UndecodableReason::UnsupportedLinkType(0),
                26,
            )],
        );
        report.reasons_dropped = 4;
        let msg = undecodable_summary(&report, 30).expect("reported");
        assert!(
            msg.contains("4 further frame(s) whose reason was not retained"),
            "the unnamed frames must be declared: {msg}"
        );
    }

    /// A capture sipnab decoded none of is a QUALITY finding. Before this,
    /// `capture_quality_summary` returned `None` unless the kernel or the NIC
    /// had dropped something, so a run that understood 0% reported "fine".
    #[test]
    #[serial_test::serial(kernel_drop_counts, undecodable_tally)]
    fn undecodable_frames_are_a_capture_quality_signal() {
        crate::capture::reset_undecodable_frames();
        assert!(
            !capture_quality_summary().is_some_and(|s| s.contains("could not be decoded")),
            "precondition: nothing undecodable yet"
        );

        // Drive the real swallow site: one frame on a link type with no decoder.
        let mut proc = crate::capture::PacketProcessor::new();
        let data = vec![0u8; 64];
        let n = data.len();
        proc.process(&crate::capture::Packet::new(
            chrono::Utc::now(),
            data,
            n,
            n,
            None,
            147,
        ));

        let msg = capture_quality_summary()
            .expect("a frame sipnab could not decode is a quality finding");
        assert!(
            msg.contains("1 frame(s) reached sipnab intact and could not be decoded"),
            "the count must be named: {msg}"
        );
        // The reason list is NOT repeated here — `report_undecodable` prints
        // it immediately above at every summary site — but this line must
        // point at it rather than leaving the count unexplained.
        assert!(
            msg.contains("see the NOT DECODED line above"),
            "the quality line must point at the breakdown: {msg}"
        );
        crate::capture::reset_undecodable_frames();
    }

    /// A TLS report with `sessions` keyed sessions, `seen` ApplicationData
    /// records offered and `decrypted` of them opened.
    fn tls_report(sessions: usize, seen: u64, decrypted: u64) -> crate::capture::TlsDecryptReport {
        crate::capture::TlsDecryptReport {
            // Sessions only exist because entries were loaded; a run with no
            // sessions in these fixtures is a run with no key material.
            keylog_entries: sessions * 2,
            sessions_with_keys: sessions,
            app_data_records: seen,
            decrypted_records: decrypted,
            late_recovered: 0,
            late_evicted: 0,
            late_still_held: 0,
        }
    }

    /// A TLS 1.2 keylog line binds to a session only through the handshake:
    /// `CLIENT_RANDOM` carries the master secret, and the server random and
    /// cipher suite that turn it into record keys are in the ServerHello. A
    /// capture that joined mid-stream has the secret and no way to use it —
    /// which is a third failure, with a third remedy, and must not be
    /// described as key material that never arrived.
    #[test]
    fn keys_that_bound_to_no_handshake_name_the_missing_handshake() {
        let lines = tls_decrypt_guidance(
            &crate::capture::TlsDecryptReport {
                keylog_entries: 6,
                sessions_with_keys: 0,
                app_data_records: 4,
                decrypted_records: 0,
                late_recovered: 0,
                late_evicted: 0,
                late_still_held: 0,
            },
            &[],
        );
        let joined = lines.join("\n");
        assert!(
            joined.contains("handshake"),
            "the missing handshake must be named: {joined}"
        );
        assert!(
            joined.contains('6') && joined.contains('4'),
            "keys loaded and records seen must both be named: {joined}"
        );
        assert!(
            !joined.contains("--libssl"),
            "keys DID arrive, so the key-source remedy is the wrong one: {joined}"
        );
    }

    /// A run that decrypted nothing says so, with the counts that distinguish
    /// "no keys matched" from "keys matched and the records still would not
    /// open", and names the remedy.
    ///
    /// This is the reported defect: the operator supplies a keylog, is told
    /// the keys loaded, and is then told no SIP was found — three true
    /// statements that together assert the opposite of what happened.
    #[test]
    fn a_run_that_decrypted_no_tls_says_so_with_counts_and_a_remedy() {
        let lines = tls_decrypt_guidance(&tls_report(2, 9, 0), &[]);
        let joined = lines.join("\n");
        assert!(
            joined.contains('9') && joined.contains('2'),
            "records seen and sessions keyed must both be named: {joined}"
        );
        assert!(
            joined.contains("already running") || joined.contains("mid-stream"),
            "the cause must be named: {joined}"
        );
        assert!(
            joined.to_lowercase().contains("restart"),
            "the remedy must be actionable: {joined}"
        );
    }

    /// Keys that matched nothing is a different failure with a different fix,
    /// so it must not be described as a mid-stream capture.
    #[test]
    fn tls_records_with_no_matching_keys_get_their_own_remedy() {
        let lines = tls_decrypt_guidance(&tls_report(0, 40, 0), &[]);
        let joined = lines.join("\n");
        assert!(
            joined.contains("40"),
            "the record count must be named: {joined}"
        );
        assert!(
            joined.contains("--libssl") || joined.contains("keylog"),
            "the remedy must point at where keys come from: {joined}"
        );
        assert!(
            !joined.to_lowercase().contains("restart"),
            "restarting a connection does not fix absent key material: {joined}"
        );
    }

    /// Advice a tool can replace with an answer is a gap.
    ///
    /// The no-key-material branch told the operator to derive a `--libssl`
    /// path from `/proc/<pid>/maps` themselves. sipnab already enumerates
    /// exactly that for `--uprobe-list`, so when discovery found libraries it
    /// must name them, and end in something pasteable rather than a procedure.
    #[test]
    fn no_key_material_names_the_libraries_this_host_maps() {
        let libs = vec![
            "/usr/lib/x86_64-linux-gnu/libssl.so.3".to_string(),
            "/opt/openssl/lib/libssl.so.1.1".to_string(),
        ];
        let joined = tls_decrypt_guidance(&tls_report(0, 40, 0), &libs).join("\n");
        assert!(
            joined.contains("/usr/lib/x86_64-linux-gnu/libssl.so.3"),
            "the library this host actually maps must be named: {joined}"
        );
        assert!(
            joined.contains("/opt/openssl/lib/libssl.so.1.1"),
            "a second mapped library must not be dropped -- picking one for the \
             operator is the guess this exists to remove: {joined}"
        );
        assert!(
            joined.contains("--uprobe-tls"),
            "the path that needs no external extractor must be offered: {joined}"
        );
    }

    /// A host where discovery finds nothing keeps the wording that does not
    /// promise paths, rather than emitting an empty list as if it were an
    /// answer.
    #[test]
    fn no_discovered_libraries_falls_back_to_the_generic_remedy() {
        let joined = tls_decrypt_guidance(&tls_report(0, 40, 0), &[]).join("\n");
        assert!(
            joined.contains("--libssl"),
            "the generic remedy must survive: {joined}"
        );
        assert!(
            !joined.contains("sipnab found no"),
            "an empty discovery must not be narrated as a finding: {joined}"
        );
    }

    /// A run that decrypted anything must stay quiet about the rest.
    ///
    /// Written the other way round first — "a partial read must not be
    /// silent" — until a real capture disproved it. Of twelve
    /// ApplicationData records in a healthy TLS 1.3 session, five were
    /// EncryptedExtensions, Certificate, CertificateVerify and the two
    /// Finished messages: application-data FRAMING, sealed under the
    /// handshake traffic secrets, carrying no application data and opened by
    /// no key sipnab loads. Reporting the difference as loss would have cried
    /// wolf on every capture that includes a handshake.
    #[test]
    fn a_partial_read_says_nothing_because_the_handshake_is_not_a_loss() {
        assert!(
            tls_decrypt_guidance(&tls_report(1, 12, 7), &[]).is_empty(),
            "seven of twelve is a normal TLS 1.3 handshake, not five lost records"
        );
    }

    /// Records the hold discarded before a key arrived must be reported on a
    /// run that decrypted everything ELSE, which is exactly the run the old
    /// early return stayed silent on.
    ///
    /// Without the eviction count, "we never had the keys for those records"
    /// and "we had them and had already thrown the ciphertext away" produce
    /// the same output, and only one of them is fixed by starting the key
    /// source earlier.
    #[test]
    fn an_eviction_is_reported_on_a_run_that_decrypted_everything_else() {
        let mut report = tls_report(1, 12, 12);
        report.late_evicted = 3;
        let joined = tls_decrypt_guidance(&report, &[]).join("\n");
        assert!(
            joined.contains('3'),
            "the eviction count must reach the operator, got: {joined:?}"
        );
        assert!(
            joined.contains("before a key"),
            "the line must say WHY the records went, got: {joined:?}"
        );
    }

    /// Keys that never came are a different fact from ciphertext already
    /// discarded, and the run has to separate them.
    #[test]
    fn records_still_waiting_at_the_end_are_reported_separately() {
        let mut report = tls_report(1, 12, 12);
        report.late_still_held = 5;
        let joined = tls_decrypt_guidance(&report, &[]).join("\n");
        assert!(
            joined.contains('5') && joined.contains("no key"),
            "records still held must be named as keys that never arrived, got: {joined:?}"
        );
        // And the two must not be conflated.
        assert!(
            !joined.contains("before a key"),
            "nothing was evicted, so no eviction line: {joined:?}"
        );
    }

    /// A run with no TLS at all, or one that decrypted everything it saw, has
    /// nothing to report — the notice must not fire on healthy runs.
    #[test]
    fn a_clean_or_absent_tls_run_reports_nothing() {
        assert!(
            tls_decrypt_guidance(&tls_report(0, 0, 0), &[]).is_empty(),
            "no TLS in the capture"
        );
        assert!(
            tls_decrypt_guidance(&tls_report(1, 12, 12), &[]).is_empty(),
            "everything decrypted"
        );
        assert!(
            tls_decrypt_guidance(&tls_report(0, 0, 0), &[]).is_empty(),
            "a capture with no TLS in it at all"
        );
    }

    /// With ciphertext it could not read, the run must not state the absence
    /// of SIP as a finding — the same rule the undecodable-frame branch
    /// enforces one layer down.
    #[test]
    fn no_sip_over_undecrypted_tls_is_never_stated_as_a_finding() {
        let lines = no_sip_guidance(0, 0, &undecodable_of(0, &[]), 42, &tls_report(1, 9, 0));
        let joined = lines.join("\n");
        assert!(
            !joined.contains("No SIP traffic found."),
            "the unqualified finding must not appear: {joined}"
        );
        assert!(
            joined.contains("could not decrypt") || joined.contains("not a finding"),
            "the run must disclaim the zero: {joined}"
        );
    }

    /// With no SIP, no RTP and a clean decode, the unqualified "No SIP traffic
    /// found." stands — that IS the finding.
    #[test]
    fn a_clean_read_with_no_sip_states_it_plainly() {
        let lines = no_sip_guidance(0, 0, &undecodable_of(0, &[]), 4_212, &tls_report(0, 0, 0));
        assert!(
            lines.iter().any(|l| l == "No SIP traffic found. Check that the capture contains SIP packets (typically UDP port 5060-5061)."),
            "a clean read must say so plainly: {lines:?}"
        );
    }

    /// With undecodable frames, "No SIP traffic found." must NOT be printed
    /// unqualified. This is the whole defect: the sentence asserts a fact
    /// about the wire that the run has no basis for.
    #[test]
    fn no_sip_after_a_failed_decode_is_never_stated_as_a_finding() {
        let lines = no_sip_guidance(
            0,
            0,
            &undecodable_of(
                49,
                &[(
                    crate::capture::UndecodableReason::UnsupportedLinkType(0),
                    49,
                )],
            ),
            49,
            &tls_report(0, 0, 0),
        );
        let joined = lines.join("\n");
        assert!(
            !joined.contains("No SIP traffic found."),
            "the unqualified finding must not appear: {joined}"
        );
        assert!(
            joined.contains("not a finding that the capture contains no SIP"),
            "the run must disclaim the zero: {joined}"
        );
        assert!(
            joined.contains("unsupported link type 0"),
            "the reason and its number must be named: {joined}"
        );
    }

    /// RTP with no SIP proves the capture WAS readable, so that message is
    /// unchanged even though a few frames (ARP, say) did not decode.
    #[test]
    fn media_only_capture_keeps_its_own_message() {
        let lines = no_sip_guidance(
            120,
            2,
            &undecodable_of(3, &[(crate::capture::UndecodableReason::NotIp(None), 3)]),
            500,
            &tls_report(0, 0, 0),
        );
        let joined = lines.join("\n");
        assert!(
            joined.contains(
                "No SIP signaling found, but 120 RTP packets across 2 stream(s) were parsed"
            ),
            "a demonstrably readable capture keeps its message: {joined}"
        );
    }

    /// Kernel-buffer and interface drops must be named SEPARATELY, with their
    /// own counts and their own remedies. Summing them would tell an operator
    /// to raise `-B` for a driver drop that a bigger buffer cannot fix — the
    /// single most common wrong response to a drop counter.
    #[test]
    #[serial_test::serial(kernel_drop_counts)]
    fn kernel_and_interface_drops_are_reported_separately_with_remedies() {
        use std::sync::atomic::Ordering::Relaxed;
        let before_k = crate::capture::live::KERNEL_DROPPED.load(Relaxed);
        let before_i = crate::capture::live::IFACE_DROPPED.load(Relaxed);
        crate::capture::live::KERNEL_DROPPED.fetch_add(7, Relaxed);
        crate::capture::live::IFACE_DROPPED.fetch_add(3, Relaxed);

        let msg = capture_quality_summary().expect("drops must be reported");

        assert!(
            msg.contains(&format!("{} packet(s) dropped by the kernel", before_k + 7)),
            "kernel drops must be named with their count: {msg}"
        );
        assert!(
            msg.contains(&format!(
                "{} packet(s) dropped by the interface",
                before_i + 3
            )),
            "interface drops must be named with their count: {msg}"
        );
        assert!(
            msg.contains("-B/--buffer"),
            "the kernel-drop remedy must be named: {msg}"
        );
        assert!(
            msg.contains("cannot recover these"),
            "interface drops must say a bigger buffer will not help: {msg}"
        );
        assert!(
            msg.contains("INCOMPLETE"),
            "the summary must say the analysis is incomplete: {msg}"
        );

        crate::capture::live::KERNEL_DROPPED.fetch_sub(7, Relaxed);
        crate::capture::live::IFACE_DROPPED.fetch_sub(3, Relaxed);
    }

    /// A run that shed nothing must stay quiet.
    ///
    /// Without this the obvious implementation — always print the counters —
    /// would pass the other test while adding a line to every clean run, and a
    /// warning that fires constantly is one operators learn to skim past.
    #[test]
    fn a_run_that_kept_everything_reports_no_retention_loss() {
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_msg("kept-1@example.com"));

        assert_eq!(
            retention_summary(&store),
            None,
            "nothing was shed, so there is nothing to warn about"
        );
    }

    /// A dialog discarded at capacity must be named, with its count.
    ///
    /// The defect this closes: three separate loss counters existed, each
    /// carefully documented, and NONE had a consumer outside its own unit test.
    /// On the corpus 402 messages were evicted while the summary reported
    /// 103,234 SIP messages and said nothing, because the packet counters sit
    /// upstream of the store — they count what arrived, not what was kept.
    #[test]
    fn a_dialog_discarded_at_capacity_is_named_with_its_count() {
        // Capacity one, rotating: the second dialog displaces the first.
        let mut store = DialogStore::new(1, true);
        store.process_message(invite_msg("first@example.com"));
        store.process_message(invite_msg("second@example.com"));

        assert_eq!(
            store.total_capacity_dialogs_evicted(),
            1,
            "the fixture must actually evict, or this test proves nothing"
        );

        let msg = retention_summary(&store).expect("an eviction must be reported");
        assert!(
            msg.contains('1') && msg.contains("discarded at capacity"),
            "the warning must carry the count and the cause: {msg}"
        );
        assert!(
            msg.contains("what sipnab READ"),
            "it must say the totals above are not what was kept: {msg}"
        );
    }

    /// Retention requires a reader AND the operator's consent — both, not
    /// either.
    ///
    /// The history is two defects in opposite directions. First retention was
    /// hardcoded off, so `export_audio` decoded an always-empty buffer and
    /// failed for every call in every capture. Then the fix armed it for
    /// EVERY `--mcp` run, holding call audio in memory whether or not
    /// anything would ever export it — a privacy decision made on the
    /// operator's behalf. Each single-conjunct predicate looks reasonable
    /// alone, which is why all four combinations are pinned.
    #[test]
    fn audio_payload_is_retained_exactly_when_asked_and_readable() {
        let mut cli = base_cli();

        cli.mcp_args.mcp = false;
        cli.mcp_args.retain_audio = false;
        assert!(
            !audio_retention_wanted(&cli),
            "a plain batch run has no reader, so it must not pay the clone"
        );

        cli.mcp_args.mcp = true;
        cli.mcp_args.retain_audio = false;
        assert!(
            !audio_retention_wanted(&cli),
            "enabling an MCP server is not consent to hold call audio in \
             memory — this is the arming-by-default the opt-in exists to end"
        );

        cli.mcp_args.mcp = false;
        cli.mcp_args.retain_audio = true;
        assert!(
            !audio_retention_wanted(&cli),
            "clap refuses this combination at parse time (--retain-audio \
             requires --mcp), but the predicate must hold on its own: \
             retaining with no reader spends memory nothing can read back"
        );

        cli.mcp_args.mcp = true;
        cli.mcp_args.retain_audio = true;
        assert!(
            audio_retention_wanted(&cli),
            "export_audio decodes these buffers; with retention off it cannot succeed"
        );
    }

    /// `--retain-audio` without `--mcp` is refused at parse time, not
    /// silently accepted and ignored.
    ///
    /// A flag that parses and does nothing is the `--alert` defect (#35) in
    /// new clothes; the clap `requires` makes the combination
    /// unrepresentable, and this pins that it stays declared.
    #[test]
    fn retain_audio_without_mcp_is_a_parse_error() {
        use clap::Parser as _;
        let err = Cli::try_parse_from(["sipnab", "-N", "--retain-audio"]);
        assert!(
            err.is_err(),
            "--retain-audio without --mcp must be refused at parse time; \
             accepting it silently retains nothing and says nothing"
        );
    }

    /// The store a run configures must end up in the state the predicate asked
    /// for — which is a different claim from the one above, and the one that
    /// was false in shipped builds.
    ///
    /// `audio_payload_is_retained_exactly_when_mcp_can_read_it` asserts the
    /// decision and stops there. It passed throughout, because the decision was
    /// always right; what was missing was applying it. The construction site
    /// read `if wanted { set(true) }` with no `else`, and `StreamStore::new`
    /// defaults retention ON for the TUI, so a non-MCP batch run computed
    /// "false" and then retained anyway. Testing a predicate cannot catch a
    /// caller that ignores it, so this reads the state back off the store.
    #[test]
    fn a_batch_run_leaves_the_store_in_the_state_the_predicate_asked_for() {
        let mut cli = base_cli();

        cli.mcp_args.mcp = false;
        let mut ss = StreamStore::new(16);
        assert!(
            ss.audio_capture(),
            "precondition: the default is ON, which is why the false case is \
             the one that needs applying"
        );
        assert!(!apply_audio_retention(&mut ss, &cli));
        assert!(
            !ss.audio_capture(),
            "a non-MCP run must leave retention OFF; leaving the constructor's \
             default in place buffers up to 1500 frames per stream that nothing \
             in this run can read"
        );

        cli.mcp_args.mcp = true;
        cli.mcp_args.retain_audio = true;
        let mut ss = StreamStore::new(16);
        assert!(apply_audio_retention(&mut ss, &cli));
        assert!(
            ss.audio_capture(),
            "export_audio decodes payload_buffer, so a consenting MCP run must retain"
        );

        // The middle state — MCP on, consent absent — is the arming-by-default
        // this ticket removed, and it must land OFF on the store, not just in
        // the predicate.
        cli.mcp_args.retain_audio = false;
        let mut ss = StreamStore::new(16);
        assert!(!apply_audio_retention(&mut ss, &cli));
        assert!(
            !ss.audio_capture(),
            "an MCP run without --retain-audio must not hold call audio"
        );
    }

    fn base_cli() -> Cli {
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.mode_args.no_tui = true;
        cli
    }

    /// The relay's startup snapshot must reach the store THIS mode builds.
    ///
    /// The headless and TUI modes build their stream stores in two different
    /// files. Wiring one and not the other would name a mid-call in the TUI
    /// and leave the identical call an orphan under `-N`, which is the harder
    /// bug to see: nothing errors, the run just attributes less.
    #[test]
    fn the_relay_snapshot_reaches_the_store_this_mode_builds() {
        use crate::relay::reconcile::{RelayLink, RelaySnapshot};
        use crate::rtp::stream_store::EndpointAssertion;
        use std::net::{IpAddr, Ipv4Addr};

        let relay = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let snapshot = RelaySnapshot {
            links: vec![RelayLink {
                address: relay,
                port: 30000,
                call_id: "already-in-progress".to_owned(),
            }],
            taken_at: Some(chrono::Utc::now()),
        };

        let ss = build_live_stream_store(&base_cli(), &Config::default(), &snapshot);

        let provenance = ss
            .sdp_endpoint_provenance(relay, 30000)
            .expect("the snapshot must be registered on this mode's store");
        assert_eq!(
            provenance.asserted_by,
            EndpointAssertion::MediaRelay,
            "the relay asserted this allocation; no party's SDP did"
        );
    }

    /// A run that never asked registers nothing, rather than registering an
    /// endpoint stamped with a moment nothing happened at.
    #[test]
    fn a_run_that_never_asked_registers_no_relay_endpoint() {
        use crate::relay::reconcile::RelaySnapshot;
        use std::net::{IpAddr, Ipv4Addr};

        let ss =
            build_live_stream_store(&base_cli(), &Config::default(), &RelaySnapshot::default());

        assert_eq!(
            ss.sdp_endpoint_provenance(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
            None
        );
    }

    /// The companion-server wait loop exits only once a stdio MCP client has
    /// actually closed its end — never for an HTTP/API-only run, and not while
    /// a stdio client is still connected. Guards the exit path that stops a
    /// finished-stdio run from spinning until SIGINT.
    #[test]
    fn mcp_stdio_client_gone_signals_exit_only_when_flag_set() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // No stdio MCP client (HTTP/API-only run): the loop keeps running and
        // exits on a signal instead, so this must stay false.
        assert!(!mcp_stdio_client_gone(None));

        // A stdio client is connected but has not closed stdin yet: keep serving.
        let flag = Arc::new(AtomicBool::new(false));
        assert!(!mcp_stdio_client_gone(Some(&flag)));

        // The client closed stdin -> the serve task flipped the flag -> exit.
        flag.store(true, Ordering::Relaxed);
        assert!(mcp_stdio_client_gone(Some(&flag)));
    }

    /// Raw bytes of a minimal but well-formed SIP INVITE for `call_id`.
    /// (`crate::test_utils` is `#[cfg(test)]`-gated in the lib and so is not
    /// visible from the binary's own test build — inline the construction.)
    fn invite_bytes(call_id: &str) -> Vec<u8> {
        let headers = [
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-abc".to_string(),
            "From: Alice <sip:alice@example.com>;tag=a1b2".to_string(),
            "To: Bob <sip:bob@example.com>".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".to_string(),
            "Max-Forwards: 70".to_string(),
            "Contact: <sip:alice@10.0.0.1:5060>".to_string(),
            "Content-Length: 0".to_string(),
        ];
        let mut msg = String::from("INVITE sip:bob@example.com SIP/2.0\r\n");
        for h in headers {
            msg.push_str(&h);
            msg.push_str("\r\n");
        }
        msg.push_str("\r\n");
        msg.into_bytes()
    }

    /// A UDP `ParsedPacket` from 10.0.0.1 to 10.0.0.2 carrying `payload`.
    fn parsed_sip_packet(payload: Vec<u8>, src_port: u16, dst_port: u16) -> ParsedPacket {
        ParsedPacket {
            frame_bytes: None,
            frame: None,
            timestamp: chrono::Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            transport: TransportProto::Udp,
            payload: bytes::Bytes::from(payload),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            dscp: None,
            input_origin: crate::capture::parse::InputOrigin::Wire,
            hep: None,
        }
    }

    /// Raw bytes of an INVITE whose SDP negotiates a telephone-event codec at
    /// payload type `pt` and `clock` Hz, with media at 10.0.0.2:`media_port`.
    fn invite_with_te_sdp(call_id: &str, media_port: u16, pt: u8, clock: u32) -> Vec<u8> {
        let sdp = format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 10.0.0.2\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.2\r\n\
             t=0 0\r\n\
             m=audio {media_port} RTP/AVP {pt}\r\n\
             a=rtpmap:{pt} telephone-event/{clock}\r\n"
        );
        let headers = [
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-te".to_string(),
            "From: Alice <sip:alice@example.com>;tag=a1b2".to_string(),
            "To: Bob <sip:bob@example.com>".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".to_string(),
            "Max-Forwards: 70".to_string(),
            "Contact: <sip:alice@10.0.0.1:5060>".to_string(),
            "Content-Type: application/sdp".to_string(),
            format!("Content-Length: {}", sdp.len()),
        ];
        let mut msg = String::from("INVITE sip:bob@example.com SIP/2.0\r\n");
        for h in headers {
            msg.push_str(&h);
            msg.push_str("\r\n");
        }
        msg.push_str("\r\n");
        msg.push_str(&sdp);
        msg.into_bytes()
    }

    /// A UDP RTP packet to 10.0.0.2:`dst_port` carrying a completed RFC 4733
    /// telephone-event (E bit set) for `event` with `duration_ts` timestamp
    /// units, using RTP payload type `pt` and the given `ssrc`.
    fn rtp_dtmf_packet(
        dst_port: u16,
        pt: u8,
        ssrc: u32,
        event: u8,
        duration_ts: u16,
    ) -> ParsedPacket {
        let mut payload: Vec<u8> = vec![
            0x80,      // V=2, no padding/extension, 0 CSRC
            pt & 0x7F, // marker=0 + payload type
            0x00,
            0x01, // sequence
            0x00,
            0x00,
            0x00,
            0x00, // RTP timestamp
        ];
        payload.extend_from_slice(&ssrc.to_be_bytes());
        // telephone-event descriptor: event, E-bit(0x80)+volume, duration.
        payload.push(event);
        payload.push(0x80);
        payload.extend_from_slice(&duration_ts.to_be_bytes());
        ParsedPacket {
            frame_bytes: None,
            frame: None,
            timestamp: chrono::Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 40001,
            dst_port,
            transport: TransportProto::Udp,
            payload: bytes::Bytes::from(payload),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            dscp: None,
            input_origin: crate::capture::parse::InputOrigin::Wire,
            hep: None,
        }
    }

    /// Drive an ordered sequence of packets through one shared set of stores
    /// (so an SDP offer seen in packet N informs stream resolution for a later
    /// RTP packet) and return the number of DTMF digits decoded.
    fn drive_packets_dtmf(cli: &Cli, packets: &[ParsedPacket], portrange: (u16, u16)) -> u64 {
        let matcher = SipMatcher::new(cli, None).expect("matcher");
        let filter_expr: Option<FilterExpr> = None;
        let output_opts = OutputOptions::default();
        let mut dialog_store = DialogStore::new(100, false);
        let mut stream_store = StreamStore::new(100);
        let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();
        let mut event_exec = EventExecEngine::new(
            None,
            None,
            0,
            0.0,
            crate::output::event_exec::DEFAULT_QUEUE_DEPTH,
        );
        let mut engines = DetectionEngines {
            scanner: None,
            fraud: None,
            digest: None,
            reg_flood: None,
            alerts: Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None))),
            kill_handle: None,
            kill_response_code: 0,
            kill_targets: Vec::new(),
        };
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
        };
        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            after_count: 0,
            portrange,
        };
        let mut sink = output::BatchSink::new(Vec::new(), false);
        let mut effects = DeferredEffects::new();
        for pp in packets {
            let mut state = ProcessingState {
                dialog_store: &mut dialog_store,
                stream_store: &mut stream_store,
                rtp_heuristic: &mut rtp_heuristic,
                event_exec: &mut event_exec,
                #[cfg(feature = "tls")]
                srtp: None,
                #[cfg(feature = "tls")]
                dtls: None,
                group: None,
            };
            process_parsed_packet(
                pp,
                &ctx,
                &mut state,
                &mut engines,
                &mut counters,
                &mut effects,
            );
            // Same drain the receive loop performs once the guards drop.
            effects.drain(&mut sink, &engines.alerts, &mut event_exec);
        }
        counters.dtmf_count
    }

    /// A telephone-event stream negotiated at a non-101 payload type must be
    /// decoded using the SDP-negotiated PT — not the hard-coded 101. Feeding
    /// the SDP offer (PT 96) then an RTP DTMF packet with PT 96 yields one
    /// decoded digit; the pre-fix code (expecting PT 101) decoded zero.
    #[test]
    fn dtmf_honors_negotiated_non_101_payload_type() {
        let mut cli = base_cli();
        cli.mode_args.telephone_event = true;
        let packets = [
            parsed_sip_packet(invite_with_te_sdp("dtmf-96@x", 40000, 96, 8000), 5060, 5060),
            rtp_dtmf_packet(40000, 96, 0x1111_2222, 5, 800),
        ];
        let dtmf = drive_packets_dtmf(&cli, &packets, (5060, 5061));
        assert_eq!(dtmf, 1, "negotiated PT 96 telephone-event must decode");
    }

    /// The negotiated telephone-event clock rate is plumbed through alongside
    /// the PT: a wideband (16000 Hz) rtpmap still decodes the completed event.
    /// (Both PT and clock come from the same resolved-stream lookup, so a
    /// non-default clock also exercises the clock-rate wiring.)
    #[test]
    fn dtmf_honors_negotiated_wideband_clock() {
        let mut cli = base_cli();
        cli.mode_args.telephone_event = true;
        let packets = [
            parsed_sip_packet(
                invite_with_te_sdp("dtmf-wb@x", 40000, 100, 16000),
                5060,
                5060,
            ),
            rtp_dtmf_packet(40000, 100, 0x3333_4444, 7, 320),
        ];
        let dtmf = drive_packets_dtmf(&cli, &packets, (5060, 5061));
        assert_eq!(dtmf, 1, "negotiated 16 kHz telephone-event must decode");
    }

    /// With no SDP telephone-event negotiation seen, the PT 101 convention is
    /// the fallback: a PT-101 DTMF packet still decodes.
    #[test]
    fn dtmf_falls_back_to_pt_101_without_sdp() {
        let mut cli = base_cli();
        cli.mode_args.telephone_event = true;
        let packets = [rtp_dtmf_packet(40000, 101, 0x5555_6666, 9, 800)];
        let dtmf = drive_packets_dtmf(&cli, &packets, (5060, 5061));
        assert_eq!(dtmf, 1, "PT 101 fallback must decode when no SDP is seen");
    }

    // ── tshark_input_file ──────────────────────────────────────────────

    /// The input file (`-I`) is preferred, and wins over any output file.
    #[test]
    fn tshark_input_file_prefers_input() {
        let one = [PathBuf::from("in.pcap")];
        assert_eq!(
            tshark_input_file(&one, Some("out.pcap")).unwrap(),
            "in.pcap"
        );
        assert_eq!(tshark_input_file(&one, None).unwrap(), "in.pcap");
    }

    /// A custom `--tshark-filter` on a live capture WITHOUT `-I` references
    /// the real saved pcap (`-O`) instead of the old `capture.pcap` placeholder.
    #[test]
    fn tshark_input_file_custom_filter_without_input_uses_output() {
        let f = tshark_input_file(&[], Some("saved.pcap"))
            .expect("a saved output file is a valid tshark source");
        assert_eq!(f, "saved.pcap");
    }

    /// A live capture with neither `-I` nor `-O` has no pcap for tshark to
    /// read: error clearly rather than emitting a bogus `capture.pcap`.
    #[test]
    fn tshark_input_file_no_input_no_output_errors() {
        let err = tshark_input_file(&[], None)
            .expect_err("no pcap source must be an error, not a placeholder");
        assert!(!err.contains("capture.pcap"), "must not name a placeholder");
        assert!(err.contains("-I") && err.contains("-O"), "got: {err}");
    }

    /// A multi-file set REFUSES rather than naming one file (#48).
    ///
    /// `tshark -r` reads one file. Emitting the first alongside a `-Y` filter
    /// built from every dialog sipnab found produces a command that returns a
    /// strict SUBSET of what sipnab just reported, with nothing saying so and
    /// exit 0. Measured with `-I sip-rtp-g711.pcap -I sip-register.pcap`: the
    /// filter named three Call-IDs, the first of which lives only in the file
    /// that command never opens.
    ///
    /// A command covering half the evidence is worse than no command, because
    /// the operator cannot tell which half. The refusal names every file so
    /// they can run one per file deliberately.
    #[test]
    fn tshark_input_file_refuses_a_multi_file_set_and_names_them_all() {
        let set = [
            PathBuf::from("first.pcap"),
            PathBuf::from("second.pcap"),
            PathBuf::from("third.pcap"),
        ];
        let err = tshark_input_file(&set, None)
            .expect_err("a set tshark cannot read in one command must be refused");
        for f in ["first.pcap", "second.pcap", "third.pcap"] {
            assert!(
                err.contains(f),
                "the refusal must name every file so the operator can run one \
                 command per file: {f} missing from {err}"
            );
        }
        // Refuses even when -O could supply a single readable path: the
        // output holds what was CAPTURED, not the files being analyzed, so
        // pointing tshark at it would answer a different question quietly.
        assert!(
            tshark_input_file(&set, Some("saved.pcap")).is_err(),
            "-O must not paper over a multi-file input set"
        );
    }

    // ── dispatch_sip_output ────────────────────────────────────────────

    // ── The startup warning about an empty jail log ──────────────────

    /// With nothing armed that writes a jail line, the warning must print:
    /// an empty jail log reads as "nothing attacked me", and startup is the
    /// one moment the run can say otherwise. The negative control for the
    /// three producer tests below.
    #[test]
    fn fail2ban_with_no_producer_armed_warns_of_the_coming_silence() {
        assert!(
            fail2ban_would_emit_nothing(false, false, false),
            "nothing armed: the run really will emit nothing, and must say so"
        );
    }

    /// `--reg-flood --fail2ban` writes `reg_flood src=` lines, so the run
    /// must not announce that it will emit nothing. It did: the warning
    /// looked at the scanner detector alone, so `-d eth0 --reg-flood
    /// --fail2ban -N` printed "this run will emit nothing" and then wrote
    /// jail lines.
    #[test]
    fn an_armed_reg_flood_detector_is_a_jail_line_producer() {
        assert!(
            !fail2ban_would_emit_nothing(false, false, true),
            "--reg-flood writes jail lines; the warning would be a false claim"
        );
    }

    /// A `-K`/`--kill-target` match writes a `scanner_detected` line with no
    /// scanner detector present, so it is a producer too.
    #[test]
    fn a_kill_target_is_a_jail_line_producer() {
        assert!(
            !fail2ban_would_emit_nothing(false, true, false),
            "-K writes jail lines; the warning would be a false claim"
        );
    }

    /// `--kill-scanner` / `--kill-ua` arm the scanner detector, the one
    /// producer the warning always knew about.
    #[test]
    fn an_armed_scanner_detector_is_a_jail_line_producer() {
        assert!(
            !fail2ban_would_emit_nothing(true, false, false),
            "--kill-scanner writes jail lines; the warning would be a false claim"
        );
    }

    /// Every combination of the three producers: the warning is right
    /// exactly when all of them are absent.
    #[test]
    fn the_warning_is_right_exactly_when_every_producer_is_absent() {
        for scanner in [false, true] {
            for kill_target in [false, true] {
                for reg_flood in [false, true] {
                    let armed = scanner || kill_target || reg_flood;
                    assert_eq!(
                        fail2ban_would_emit_nothing(scanner, kill_target, reg_flood),
                        !armed,
                        "scanner={scanner} kill_target={kill_target} reg_flood={reg_flood}"
                    );
                }
            }
        }
    }

    // ── The jail line and where its address came from ────────────────

    /// Raw bytes of a REGISTER from 10.0.0.1 on transaction `branch`,
    /// carrying an `Authorization` header when `with_credentials` is set.
    fn register_bytes(branch: &str, with_credentials: bool) -> Vec<u8> {
        let auth = if with_credentials {
            "Authorization: Digest username=\"u\", realm=\"r\", nonce=\"n\", uri=\"sip:r\", \
             response=\"0\"\r\n"
        } else {
            ""
        };
        format!(
            "REGISTER sip:10.0.0.2 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch={branch}\r\n\
             From: <sip:u@10.0.0.2>;tag=f1\r\n\
             To: <sip:u@10.0.0.2>\r\n\
             Call-ID: {branch}@10.0.0.1\r\n\
             CSeq: 1 REGISTER\r\n\
             Max-Forwards: 70\r\n\
             {auth}Content-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    /// Raw bytes of the registrar's 401 answering `register_bytes(branch, ..)`.
    fn challenge_bytes(branch: &str) -> Vec<u8> {
        format!(
            "SIP/2.0 401 Unauthorized\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch={branch}\r\n\
             From: <sip:u@10.0.0.2>;tag=f1\r\n\
             To: <sip:u@10.0.0.2>;tag=t1\r\n\
             Call-ID: {branch}@10.0.0.1\r\n\
             CSeq: 1 REGISTER\r\n\
             Content-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    /// Raw bytes of an OPTIONS from 10.0.0.1 announcing a scanner's
    /// User-Agent, which the signature rule matches on sight.
    fn scanner_options_bytes() -> Vec<u8> {
        b"OPTIONS sip:10.0.0.2 SIP/2.0\r\n\
          Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-scan\r\n\
          From: <sip:x@10.0.0.1>;tag=s1\r\n\
          To: <sip:x@10.0.0.2>\r\n\
          Call-ID: scan@10.0.0.1\r\n\
          CSeq: 1 OPTIONS\r\n\
          Max-Forwards: 70\r\n\
          User-Agent: friendly-scanner\r\n\
          Content-Length: 0\r\n\r\n"
            .to_vec()
    }

    /// A UDP `ParsedPacket` carrying `payload` from `src` to `dst` on 5060,
    /// with its addressing attributed to `origin`.
    fn parsed_sip_from(
        origin: crate::capture::parse::InputOrigin,
        payload: Vec<u8>,
        src: [u8; 4],
        dst: [u8; 4],
    ) -> ParsedPacket {
        let mut pp = parsed_sip_packet(payload, 5060, 5060);
        pp.src_addr = IpAddr::V4(Ipv4Addr::from(src));
        pp.dst_addr = IpAddr::V4(Ipv4Addr::from(dst));
        pp.input_origin = origin;
        pp
    }

    /// Three credentialed REGISTERs from 10.0.0.1, each refused by 10.0.0.2:
    /// one more challenged failure than a threshold of 2 allows.
    fn refused_registrations(origin: crate::capture::parse::InputOrigin) -> Vec<ParsedPacket> {
        (0..3)
            .flat_map(|i| {
                let branch = format!("z9hG4bK-f2b-{i}");
                [
                    parsed_sip_from(
                        origin,
                        register_bytes(&branch, true),
                        [10, 0, 0, 1],
                        [10, 0, 0, 2],
                    ),
                    parsed_sip_from(
                        origin,
                        challenge_bytes(&branch),
                        [10, 0, 0, 2],
                        [10, 0, 0, 1],
                    ),
                ]
            })
            .collect()
    }

    /// Detection engines with nothing armed; each test arms what it needs.
    fn unarmed_engines() -> DetectionEngines {
        DetectionEngines {
            scanner: None,
            fraud: None,
            digest: None,
            reg_flood: None,
            alerts: Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None))),
            kill_handle: None,
            kill_response_code: 0,
            kill_targets: Vec::new(),
        }
    }

    /// A `-N --fail2ban` command line.
    fn fail2ban_cli() -> Cli {
        let mut cli = base_cli();
        cli.output_args.fail2ban = true;
        cli
    }

    /// Drive `packets` through the headless loop with `engines`, returning
    /// what reached the per-message sink and how many alert firings were
    /// queued on the way -- the two halves of a detection: the line a jail
    /// bans on, and the finding a human reads. Only the first is
    /// origin-gated, and a test of the gate has to show the second survived.
    fn drive_detections(
        cli: &Cli,
        engines: &mut DetectionEngines,
        packets: &[ParsedPacket],
    ) -> (String, usize) {
        let portrange = (5060, 5061);
        let matcher = SipMatcher::new(cli, None).expect("matcher");
        let filter_expr: Option<FilterExpr> = None;
        let output_opts = OutputOptions {
            color: output::ColorMode::Never,
            ..Default::default()
        };
        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            after_count: 0,
            portrange,
        };
        let mut dialog_store = DialogStore::new(100, false);
        let mut stream_store = StreamStore::new(100);
        let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();
        let mut event_exec = EventExecEngine::new(
            None,
            None,
            0,
            0.0,
            crate::output::event_exec::DEFAULT_QUEUE_DEPTH,
        );
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
        };
        let mut effects = DeferredEffects::new();
        let mut sink = output::BatchSink::new(Vec::new(), false);
        let mut queued = 0usize;
        for pp in packets {
            let mut state = ProcessingState {
                dialog_store: &mut dialog_store,
                stream_store: &mut stream_store,
                rtp_heuristic: &mut rtp_heuristic,
                event_exec: &mut event_exec,
                #[cfg(feature = "tls")]
                srtp: None,
                #[cfg(feature = "tls")]
                dtls: None,
                group: None,
            };
            process_parsed_packet(pp, &ctx, &mut state, engines, &mut counters, &mut effects);
            queued += effects.alerts.len();
            effects.drain(&mut sink, &engines.alerts, &mut event_exec);
        }
        sink.flush();
        (
            String::from_utf8(sink.into_inner()).expect("output is utf-8"),
            queued,
        )
    }

    /// A registration flood carried by HEP never reaches the jail log
    /// without the opt-in, and still reaches the alert path.
    ///
    /// `--hep-listen 0.0.0.0:9060 --hep-allow 198.51.100.0/24 --reg-flood
    /// --fail2ban`: any host in that range, or a UDP source spoofed into it, sends
    /// HEP-wrapped REGISTERs whose inner source is the customer's SBC, and
    /// the jail bans the SBC. The kill path has refused sender-asserted
    /// addressing without `--hep-allow-kill` since SN-01; the ban path wrote
    /// the line unconditionally, and a firewall rule outlives the process
    /// that asked for it.
    #[test]
    fn hep_origin_reg_flood_never_reaches_the_jail_log() {
        use crate::capture::parse::InputOrigin;
        let mut cli = fail2ban_cli();
        let armed = || {
            let mut engines = unarmed_engines();
            engines.reg_flood = Some(RegFloodDetector::new(2));
            engines
        };

        let (out, queued) =
            drive_detections(&cli, &mut armed(), &refused_registrations(InputOrigin::Hep));
        assert!(
            queued >= 1,
            "the detection must still reach the alert path -- tier 1 is not origin-gated \
             -- but {queued} firings were queued"
        );
        assert!(
            !out.contains("reg_flood src="),
            "a registration flood whose addressing a HEP sender asserted reached the jail \
             log:\n{out}"
        );

        // Control: the same flood read off the wire is written.
        let (out, _) = drive_detections(
            &cli,
            &mut armed(),
            &refused_registrations(InputOrigin::Wire),
        );
        assert!(
            out.contains("reg_flood src=10.0.0.1 count=3"),
            "control: a wire-origin flood must reach the jail log, else the gate above is \
             vacuous:\n{out}"
        );

        // Opt-in: --hep-allow-kill admits HEP-origin detections to the log the
        // same way it admits them to the wire.
        cli.security_args.hep_allow_kill = true;
        let (out, _) =
            drive_detections(&cli, &mut armed(), &refused_registrations(InputOrigin::Hep));
        assert!(
            out.contains("reg_flood src=10.0.0.1 count=3"),
            "--hep-allow-kill must admit a HEP-origin flood to the jail log:\n{out}"
        );
    }

    /// The scanner-signature site: same rule.
    #[test]
    fn hep_origin_scanner_detection_never_reaches_the_jail_log() {
        use crate::capture::parse::InputOrigin;
        let cli = fail2ban_cli();
        let armed = || {
            let mut engines = unarmed_engines();
            engines.scanner = Some(ScannerDetector::new(&[]));
            engines
        };
        let probe = |origin| {
            vec![parsed_sip_from(
                origin,
                scanner_options_bytes(),
                [10, 0, 0, 1],
                [10, 0, 0, 2],
            )]
        };

        let (out, queued) = drive_detections(&cli, &mut armed(), &probe(InputOrigin::Hep));
        assert_eq!(
            queued, 1,
            "the signature match must still be queued as an alert"
        );
        assert!(
            !out.contains("scanner_detected"),
            "a scanner detection whose addressing a HEP sender asserted reached the jail \
             log:\n{out}"
        );

        let (out, _) = drive_detections(&cli, &mut armed(), &probe(InputOrigin::Wire));
        assert!(
            out.contains("scanner_detected src=10.0.0.1"),
            "control: a wire-origin detection must reach the jail log:\n{out}"
        );
    }

    /// The `-K/--kill-target` site: same rule. The operator named the
    /// address, which is why `-K` may transmit at all -- but under HEP the
    /// address a packet claims to come from is still the sender's word, and
    /// a jail line names that claim.
    #[test]
    fn hep_origin_kill_target_match_never_reaches_the_jail_log() {
        use crate::capture::parse::InputOrigin;
        let cli = fail2ban_cli();
        let armed = || {
            let mut engines = unarmed_engines();
            engines.kill_targets =
                vec![sec::scanner_kill::KillTarget::parse("10.0.0.1").expect("target")];
            engines
        };
        let request = |origin| {
            vec![parsed_sip_from(
                origin,
                register_bytes("z9hG4bK-kt", false),
                [10, 0, 0, 1],
                [10, 0, 0, 2],
            )]
        };

        let (out, queued) = drive_detections(&cli, &mut armed(), &request(InputOrigin::Hep));
        assert_eq!(
            queued, 1,
            "the kill-target match must still be queued as an alert"
        );
        assert!(
            !out.contains("scanner_detected"),
            "a kill-target match whose addressing a HEP sender asserted reached the jail \
             log:\n{out}"
        );

        let (out, _) = drive_detections(&cli, &mut armed(), &request(InputOrigin::Wire));
        assert!(
            out.contains("scanner_detected src=10.0.0.1"),
            "control: a wire-origin match must reach the jail log:\n{out}"
        );
    }

    /// A uprobe read carries no addressing at all, and no opt-in reaches it:
    /// `--hep-allow-kill` is about HEP, and bytes lifted out of a process
    /// name no socket a firewall could ban.
    #[test]
    fn uprobe_origin_never_reaches_the_jail_log_even_with_the_opt_in() {
        use crate::capture::parse::InputOrigin;
        let mut cli = fail2ban_cli();
        cli.security_args.hep_allow_kill = true;
        let mut engines = unarmed_engines();
        engines.reg_flood = Some(RegFloodDetector::new(2));

        let (out, queued) = drive_detections(
            &cli,
            &mut engines,
            &refused_registrations(InputOrigin::Uprobe),
        );
        assert!(queued >= 1, "the detection must still reach the alert path");
        assert!(
            !out.contains("reg_flood src="),
            "a uprobe-origin flood reached the jail log under --hep-allow-kill, which is an \
             opt-in about HEP and must not reach input that has no address at all:\n{out}"
        );
    }

    /// Every output backend (default text, JSON, pretty JSON, fail2ban, raw
    /// dump, suppressed, line-buffered) produces its expected bytes.
    #[test]
    fn dispatch_sip_output_all_modes() {
        let data = bytes::Bytes::from(invite_bytes("disp-1@example.com"));
        let msg = sip::parser::parse_sip_bytes(
            &data,
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("invite should parse");
        // Force color OFF so the expected text output is deterministic even
        // when the test runner is attached to a TTY.
        let opts = OutputOptions {
            color: output::ColorMode::Never,
            ..Default::default()
        };
        let sink_bytes = |cli: &Cli, prev: Option<chrono::DateTime<chrono::Utc>>| {
            // Round-trip through the real sink, so this still asserts on the
            // bytes an operator receives rather than on the deferred buffer.
            let mut out = DeferredOutput::new();
            dispatch_sip_output(&msg, &opts, cli, prev, &mut out, None);
            let mut sink = output::BatchSink::new(Vec::new(), cli.output_args.line_buffer);
            out.drain_into(&mut sink);
            sink.flush();
            sink.into_inner()
        };

        // Default plain print: byte-identical to format_sip_message.
        let out = sink_bytes(&base_cli(), None);
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            crate::output::cli_print::format_sip_message(&msg, &opts, None),
        );

        // JSON: byte-identical to message_to_json (NDJSON line + newline).
        let mut cli = base_cli();
        cli.output_args.json = true;
        assert_eq!(
            String::from_utf8(sink_bytes(&cli, None)).expect("utf8"),
            output::json::message_to_json(&msg),
        );

        // Pretty JSON: byte-identical to message_to_json_pretty.
        let mut cli = base_cli();
        cli.output_args.json_pretty = true;
        assert_eq!(
            String::from_utf8(sink_bytes(&cli, None)).expect("utf8"),
            output::json::message_to_json_pretty(&msg),
        );

        // fail2ban: a plain request is NOT a detection, so nothing is written.
        // This assertion used to require an event line for any request, which
        // is the whole defect: fail2ban bans what it is handed, and every peer
        // on a trunk sends requests. Detections reach the sink from the
        // detector paths, not from here.
        let mut cli = base_cli();
        cli.output_args.fail2ban = true;
        let out = String::from_utf8(sink_bytes(&cli, None)).expect("utf8");
        assert!(
            out.is_empty(),
            "an ordinary request must produce no fail2ban output, got {out:?}"
        );

        // raw text dump: raw message + newline.
        let mut cli = base_cli();
        cli.output_args.text_dump = true;
        let out = String::from_utf8(sink_bytes(&cli, None)).expect("utf8");
        assert!(out.starts_with("INVITE sip:bob@example.com SIP/2.0"));
        assert!(out.ends_with('\n'));

        // suppressed entirely.
        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;
        assert!(sink_bytes(&cli, None).is_empty());

        // line-buffer flush branch still writes the message.
        let mut cli = base_cli();
        cli.output_args.line_buffer = true;
        assert!(!sink_bytes(&cli, Some(chrono::Utc::now())).is_empty());
    }

    // ── generate_reports ───────────────────────────────────────────────

    /// `--report` and `--call-report` run without panicking on empty stores,
    /// unknown Call-IDs, and a tracked dialog across all report formats.
    #[test]
    fn generate_reports_summary_and_call_report() {
        let mut dialog_store = DialogStore::new(100, false);
        let stream_store = StreamStore::new(100);

        // Empty --report summary path.
        let mut cli = base_cli();
        cli.output_args.report = true;
        generate_reports(&cli, &dialog_store, &stream_store, None, None, 0, None);

        // --call-report for an unknown Call-ID hits the "not found" warn arm.
        let mut cli = base_cli();
        cli.output_args.call_report = Some("does-not-exist".to_string());
        generate_reports(&cli, &dialog_store, &stream_store, None, None, 0, None);

        // Insert a dialog, then --call-report finds it across all formats.
        let call_id = "report-1@example.com";
        let data = bytes::Bytes::from(invite_bytes(call_id));
        let msg = sip::parser::parse_sip_bytes(
            &data,
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .unwrap();
        dialog_store.process_message(msg);
        assert!(dialog_store.get(call_id).is_some());

        let formats: [fn(&mut Cli); 3] = [
            |_c| {},
            |c| c.output_args.json = true,
            |c| c.output_args.markdown = true,
        ];
        for setup in formats {
            let mut cli = base_cli();
            cli.output_args.call_report = Some(call_id.to_string());
            setup(&mut cli);
            generate_reports(&cli, &dialog_store, &stream_store, None, None, 0, None);
        }
    }

    // ── process_parsed_packet ──────────────────────────────────────────

    /// Build the engine/state/context scaffolding and drive a single packet,
    /// returning the resulting (sip_count, rtp_count).
    fn drive_packet(cli: &Cli, pp: &ParsedPacket, portrange: (u16, u16)) -> (u64, u64) {
        let matcher = SipMatcher::new(cli, None).expect("matcher");
        let filter_expr: Option<FilterExpr> = None;
        let output_opts = OutputOptions::default();

        let mut dialog_store = DialogStore::new(100, false);
        let mut stream_store = StreamStore::new(100);
        let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();
        let mut event_exec = EventExecEngine::new(
            None,
            None,
            0,
            0.0,
            crate::output::event_exec::DEFAULT_QUEUE_DEPTH,
        );

        let mut engines = DetectionEngines {
            scanner: None,
            fraud: None,
            digest: None,
            reg_flood: None,
            alerts: Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None))),
            kill_handle: None,
            kill_response_code: 0,
            kill_targets: Vec::new(),
        };
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
        };

        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            after_count: 0,
            portrange,
        };
        let mut effects = DeferredEffects::new();
        // Scoped so the borrow of `event_exec` ends before the drain, the
        // way the receive loop's lock scope does.
        {
            let mut state = ProcessingState {
                dialog_store: &mut dialog_store,
                stream_store: &mut stream_store,
                rtp_heuristic: &mut rtp_heuristic,
                event_exec: &mut event_exec,
                #[cfg(feature = "tls")]
                srtp: None,
                #[cfg(feature = "tls")]
                dtls: None,
                group: None,
            };
            process_parsed_packet(
                pp,
                &ctx,
                &mut state,
                &mut engines,
                &mut counters,
                &mut effects,
            );
        }
        let mut sink = output::BatchSink::new(Vec::new(), false);
        effects.drain(&mut sink, &engines.alerts, &mut event_exec);
        (counters.sip_count, counters.rtp_count)
    }

    /// Drive one packet with `--kill-target` directives active and return the
    /// detail lines of any "scanner" findings the alert engine recorded. Uses
    /// `kill_handle: None`, so no socket send is attempted — the targeted-kill
    /// alert still fires before the (absent) worker handoff.
    fn drive_kill_targets(cli: &Cli, pp: &ParsedPacket, targets: &[&str]) -> Vec<String> {
        let matcher = SipMatcher::new(cli, None).expect("matcher");
        let filter_expr: Option<FilterExpr> = None;
        let output_opts = OutputOptions::default();
        let mut dialog_store = DialogStore::new(100, false);
        let mut stream_store = StreamStore::new(100);
        let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();
        let mut event_exec = EventExecEngine::new(
            None,
            None,
            0,
            0.0,
            crate::output::event_exec::DEFAULT_QUEUE_DEPTH,
        );

        let kill_targets = targets
            .iter()
            .map(|s| sec::scanner_kill::KillTarget::parse(s).expect("valid target"))
            .collect();
        let alerts = Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None)));
        let mut engines = DetectionEngines {
            scanner: None,
            fraud: None,
            digest: None,
            reg_flood: None,
            alerts: Arc::clone(&alerts),
            kill_handle: None,
            kill_response_code: 200,
            kill_targets,
        };
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
        };
        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            after_count: 0,
            portrange: (5060, 5061),
        };
        let mut effects = DeferredEffects::new();
        // Scoped so the borrow of `event_exec` ends before the drain, the
        // way the receive loop's lock scope does.
        {
            let mut state = ProcessingState {
                dialog_store: &mut dialog_store,
                stream_store: &mut stream_store,
                rtp_heuristic: &mut rtp_heuristic,
                event_exec: &mut event_exec,
                #[cfg(feature = "tls")]
                srtp: None,
                #[cfg(feature = "tls")]
                dtls: None,
                group: None,
            };
            process_parsed_packet(
                pp,
                &ctx,
                &mut state,
                &mut engines,
                &mut counters,
                &mut effects,
            );
        }
        // The findings only exist once the effects are replayed: the detector
        // decides under the store guards, the alert engine fires after them.
        let mut sink = output::BatchSink::new(Vec::new(), false);
        effects.drain(&mut sink, &engines.alerts, &mut event_exec);

        alerts
            .read()
            .iter_findings(&["scanner"], None, 16)
            .into_iter()
            .map(|f| f.detail.clone())
            .collect()
    }

    /// A request whose source IP:port falls inside a `--kill-target` range
    /// fires a kill-target scanner alert.
    #[test]
    fn kill_target_matching_request_fires_kill_alert() {
        // parsed_sip_packet sources from 10.0.0.1; src_port 5075 is inside the
        // target's 5060-5090 range → the targeted kill must fire.
        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;
        let pp = parsed_sip_packet(invite_bytes("kt-hit@example.com"), 5075, 5060);
        let details = drive_kill_targets(&cli, &pp, &["10.0.0.1:5060-5090"]);
        assert!(
            details.iter().any(|d| d.contains("detection=kill-target")),
            "expected a kill-target alert, got {details:?}"
        );
    }

    /// A source port outside the target's range must not trigger a kill.
    #[test]
    fn kill_target_out_of_range_port_does_not_fire() {
        // src_port 6000 is outside 5060-5090 → no targeted kill.
        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;
        let pp = parsed_sip_packet(invite_bytes("kt-miss@example.com"), 6000, 5060);
        let details = drive_kill_targets(&cli, &pp, &["10.0.0.1:5060-5090"]);
        assert!(
            !details.iter().any(|d| d.contains("kill-target")),
            "should not kill a source outside the port range, got {details:?}"
        );
    }

    /// A source IP different from the target's must not trigger a kill.
    #[test]
    fn kill_target_wrong_ip_does_not_fire() {
        // Target a different IP than the packet's source (10.0.0.1) → no kill.
        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;
        let pp = parsed_sip_packet(invite_bytes("kt-ip@example.com"), 5075, 5060);
        let details = drive_kill_targets(&cli, &pp, &["10.0.0.99:5060-5090"]);
        assert!(
            !details.iter().any(|d| d.contains("kill-target")),
            "should not kill a non-targeted source IP, got {details:?}"
        );
    }

    // ── Deferred side effects (LK1) ────────────────────────────────────

    /// Wait for `path` to hold at least one byte, so a test can assert the
    /// hook COMMAND ran rather than only that a process was created. Returns
    /// `false` on timeout, which fails the test rather than hanging the suite.
    fn wait_for_marker(path: &std::path::Path) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::time::Instant::now() < deadline {
            if std::fs::metadata(path).is_ok_and(|m| m.len() > 0) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    /// The receive loop's contract, asserted directly: a packet processed with
    /// both store write locks held RAISES its side effects and PERFORMS none
    /// of them. They happen only once the guards are gone.
    ///
    /// This is the defect the deferral exists to close. `Command::new("sh")
    /// .spawn()` is a real `fork`/`exec` — hundreds of microseconds against a
    /// per-packet budget of hundreds of nanoseconds — and it used to run with
    /// the dialog store's write lock and the stream store's write lock both
    /// held, so every reader of either store waited for the kernel to build a
    /// process image. The alert engine's own lock was taken beneath those two,
    /// with a second spawn inside it, on an ordering rule written down nowhere.
    ///
    /// Nothing about a capture's OUTPUT changes if that regresses, which is
    /// why every assertion here is about WHEN, not about what.
    #[test]
    fn side_effects_are_raised_under_the_guards_and_performed_after_them() {
        let dir = tempfile::tempdir().expect("temp dir");
        let marker = dir.path().join("hook-ran");
        // `>>` opens with O_APPEND, so the file's existence and length are
        // evidence the shell command itself ran.
        let hook = format!("printf x >> {}", marker.display());

        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;

        let matcher = SipMatcher::new(&cli, None).expect("matcher");
        let filter_expr: Option<FilterExpr> = None;
        let output_opts = OutputOptions::default();
        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli: &cli,
            no_rtp: false,
            after_count: 0,
            portrange: (5060, 5090),
        };

        // Stores behind the same locks the receive loop shares with the
        // companion servers, so the guards under test are the real ones.
        let dialog_store = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let stream_store = Arc::new(RwLock::new(StreamStore::new(100)));
        let alerts = Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None)));
        let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();
        let mut event_exec = EventExecEngine::new(
            Some(hook),
            None,
            0,
            3.0,
            crate::output::event_exec::DEFAULT_QUEUE_DEPTH,
        );
        let mut engines = DetectionEngines {
            scanner: None,
            fraud: None,
            digest: None,
            reg_flood: None,
            alerts: Arc::clone(&alerts),
            kill_handle: None,
            kill_response_code: 200,
            // Matches the fixture's 10.0.0.1:5075 source, so one packet raises
            // both a hook command and an alert.
            kill_targets: vec![
                sec::scanner_kill::KillTarget::parse("10.0.0.1:5060-5090").expect("valid target"),
            ],
        };
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
        };
        let mut effects = DeferredEffects::new();
        let pp = parsed_sip_packet(invite_bytes("lk1@example.com"), 5075, 5060);

        {
            let mut ds_guard = dialog_store.write();
            let mut ss_guard = stream_store.write();
            {
                let mut state = ProcessingState {
                    dialog_store: &mut ds_guard,
                    stream_store: &mut ss_guard,
                    rtp_heuristic: &mut rtp_heuristic,
                    event_exec: &mut event_exec,
                    #[cfg(feature = "tls")]
                    srtp: None,
                    #[cfg(feature = "tls")]
                    dtls: None,
                    group: None,
                };
                process_parsed_packet(
                    &pp,
                    &ctx,
                    &mut state,
                    &mut engines,
                    &mut counters,
                    &mut effects,
                );
            }

            // The guards are demonstrably still held: an unrelated reader
            // cannot get in. Without this the assertions below would also pass
            // on a version that released the locks early.
            assert!(
                dialog_store.try_read().is_none(),
                "the dialog store's write guard must still be held here"
            );
            assert!(
                stream_store.try_read().is_none(),
                "the stream store's write guard must still be held here"
            );

            assert_eq!(
                event_exec.outcomes().spawned,
                0,
                "no fork/exec may happen while both store write locks are held"
            );
            assert_eq!(
                event_exec.pending_depth(),
                1,
                "the hook must be DECIDED under the guards and parked"
            );
            assert_eq!(
                effects.alerts.len(),
                1,
                "the alert must be queued under the guards, not fired"
            );
            assert!(
                alerts
                    .try_write()
                    .is_some_and(|e| e.iter_findings(&[], None, 8).is_empty()),
                "the alert engine's lock must be free and untouched under the store guards"
            );
            assert!(
                !marker.exists(),
                "the hook command must not have run yet: {}",
                marker.display()
            );
        }

        // Guards gone. Everything queued now happens, in the order it was
        // raised — exactly what the receive loop does after its lock scope.
        let mut sink = output::BatchSink::new(Vec::new(), false);
        effects.drain(&mut sink, &engines.alerts, &mut event_exec);

        assert_eq!(
            event_exec.outcomes().spawned,
            1,
            "the hook must be spawned once the guards are released"
        );
        assert_eq!(event_exec.pending_depth(), 0, "nothing may be left parked");
        assert!(effects.alerts.is_empty(), "the alert queue must be drained");

        let details: Vec<String> = alerts
            .read()
            .iter_findings(&["scanner"], None, 8)
            .into_iter()
            .map(|f| f.detail.clone())
            .collect();
        assert!(
            details.iter().any(|d| d.contains("detection=kill-target")),
            "the deferred alert must reach the engine, got {details:?}"
        );

        assert!(
            wait_for_marker(&marker),
            "the hook command itself must run, not just be spawned"
        );
    }

    /// Deferring output must not reorder it: within a packet the emitters land
    /// in the order they ran, and packet N's bytes land entirely before packet
    /// N+1's.
    ///
    /// Emission used to go straight at the sink, so ordering was whatever the
    /// call order was. Now it goes through a per-packet buffer, and "the same
    /// capture produces byte-identical output" rests on that buffer being
    /// FIFO and drained per packet rather than per batch.
    #[test]
    fn deferred_output_preserves_emission_order() {
        let mut cli = base_cli();
        // Two emitters in one packet: the hexdump block first, then the raw
        // message dump. Their relative order is the intra-packet assertion.
        cli.output_args.hexdump = true;
        cli.output_args.text_dump = true;

        let first = parsed_sip_packet(invite_bytes("ord-1@example.com"), 5060, 5060);
        let second = parsed_sip_packet(invite_bytes("ord-2@example.com"), 5060, 5060);
        let out = drive_packets_output(&cli, &[first.clone(), second.clone()], (5060, 5061));

        // Intra-packet: the hexdump of the first packet precedes its raw dump.
        let hex_at = out
            .find(&output::hexdump(&first.payload))
            .expect("the first packet's hexdump block must be present");
        let raw = String::from_utf8_lossy(&first.payload).into_owned();
        let raw_at = out
            .rfind(&raw)
            .expect("the first packet's raw dump must be present");
        assert!(
            hex_at < raw_at,
            "hexdump must precede the message it dumps (hex at {hex_at}, raw at {raw_at})"
        );

        // Cross-packet: everything the first packet emitted precedes anything
        // the second emitted.
        let second_at = out
            .find(&output::hexdump(&second.payload))
            .expect("the second packet's hexdump block must be present");
        assert!(
            raw_at < second_at,
            "packet 1's output must land entirely before packet 2's \
             (packet 1 raw at {raw_at}, packet 2 hexdump at {second_at})"
        );
        assert_eq!(
            out.matches("ord-1@example.com").count(),
            out.matches("ord-2@example.com").count(),
            "both packets must emit the same shape of output"
        );
    }

    /// Drive packets through the real lock-then-drain shape and return every
    /// byte that reached the sink, as the operator's stdout would have seen it.
    fn drive_packets_output(cli: &Cli, packets: &[ParsedPacket], portrange: (u16, u16)) -> String {
        let matcher = SipMatcher::new(cli, None).expect("matcher");
        let filter_expr: Option<FilterExpr> = None;
        let output_opts = OutputOptions {
            color: output::ColorMode::Never,
            ..Default::default()
        };
        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            after_count: 0,
            portrange,
        };
        let dialog_store = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let stream_store = Arc::new(RwLock::new(StreamStore::new(100)));
        let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();
        let mut event_exec = EventExecEngine::new(
            None,
            None,
            0,
            0.0,
            crate::output::event_exec::DEFAULT_QUEUE_DEPTH,
        );
        let mut engines = DetectionEngines {
            scanner: None,
            fraud: None,
            digest: None,
            reg_flood: None,
            alerts: Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None))),
            kill_handle: None,
            kill_response_code: 0,
            kill_targets: Vec::new(),
        };
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
        };
        let mut effects = DeferredEffects::new();
        let mut sink = output::BatchSink::new(Vec::new(), cli.output_args.line_buffer);
        for pp in packets {
            {
                let mut ds_guard = dialog_store.write();
                let mut ss_guard = stream_store.write();
                let mut state = ProcessingState {
                    dialog_store: &mut ds_guard,
                    stream_store: &mut ss_guard,
                    rtp_heuristic: &mut rtp_heuristic,
                    event_exec: &mut event_exec,
                    #[cfg(feature = "tls")]
                    srtp: None,
                    #[cfg(feature = "tls")]
                    dtls: None,
                    group: None,
                };
                process_parsed_packet(
                    pp,
                    &ctx,
                    &mut state,
                    &mut engines,
                    &mut counters,
                    &mut effects,
                );
            }
            effects.drain(&mut sink, &engines.alerts, &mut event_exec);
        }
        sink.flush();
        String::from_utf8(sink.into_inner()).expect("output is utf-8")
    }

    /// A writer that counts flushes and can be told to fail, so the deferred
    /// buffer's flush and error handling are testable without a real pipe.
    struct FlushProbe {
        /// Bytes written through.
        buf: Vec<u8>,
        /// How many times `flush` was called.
        flushes: usize,
    }

    impl std::io::Write for FlushProbe {
        /// Append `data` and report it fully written.
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.buf.extend_from_slice(data);
            Ok(data.len())
        }
        /// Count the flush; always succeeds.
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    /// `DeferredOutput` stands in for the sink faithfully: bytes come out in
    /// the order they went in, a `--line-buffer` message boundary still causes
    /// exactly one flush per message, and an error raised while composing
    /// still reaches the sink's exit-code channel instead of vanishing.
    #[test]
    fn deferred_output_replays_bytes_flushes_and_errors() {
        let mut out = DeferredOutput::new();
        out.write_str("alpha");
        write!(out, "-{}-", 42);
        out.end_message();
        out.write_str("beta");
        out.end_message();

        let mut sink = output::BatchSink::new(
            FlushProbe {
                buf: Vec::new(),
                flushes: 0,
            },
            // --line-buffer on, so each recorded boundary must flush.
            true,
        );
        out.drain_into(&mut sink);
        assert_eq!(
            String::from_utf8_lossy(&sink.get_ref().buf),
            "alpha-42-beta",
            "bytes must replay in emission order"
        );
        assert_eq!(
            sink.get_ref().flushes,
            2,
            "each message boundary must still flush exactly once"
        );

        // Reused for the next packet, and empty.
        assert!(out.bytes.is_empty());
        assert_eq!(out.message_ends, 0);

        // An error raised while composing survives to the sink, which is what
        // decides the run's exit code. Only the FIRST is kept, and a closed
        // downstream pipe is still not an error.
        out.record(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)));
        assert!(
            out.hard_error.is_none(),
            "a broken pipe must stay swallowed"
        );
        out.record(Err(std::io::Error::other("disk full")));
        out.record(Err(std::io::Error::other("later, ignored")));
        out.drain_into(&mut sink);
        assert_eq!(
            sink.hard_error().map(std::string::ToString::to_string),
            Some("disk full".to_string()),
            "the first hard error must reach the sink"
        );
    }

    /// Drive a packet through `process_parsed_packet` with an active SRTP
    /// context, returning the rtp_count so wiring can be asserted.
    #[cfg(feature = "tls")]
    fn drive_packet_with_srtp(
        cli: &Cli,
        pp: &ParsedPacket,
        portrange: (u16, u16),
        srtp: &mut crate::rtp::srtp::SrtpContext,
    ) -> u64 {
        let matcher = SipMatcher::new(cli, None).expect("matcher");
        let filter_expr: Option<FilterExpr> = None;
        let output_opts = OutputOptions::default();
        let mut dialog_store = DialogStore::new(100, false);
        let mut stream_store = StreamStore::new(100);
        let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();
        let mut event_exec = EventExecEngine::new(
            None,
            None,
            0,
            0.0,
            crate::output::event_exec::DEFAULT_QUEUE_DEPTH,
        );
        let mut engines = DetectionEngines {
            scanner: None,
            fraud: None,
            digest: None,
            reg_flood: None,
            alerts: Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None))),
            kill_handle: None,
            kill_response_code: 0,
            kill_targets: Vec::new(),
        };
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
        };
        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            after_count: 0,
            portrange,
        };
        let mut effects = DeferredEffects::new();
        // Scoped so the borrow of `event_exec` ends before the drain, the
        // way the receive loop's lock scope does.
        {
            let mut state = ProcessingState {
                dialog_store: &mut dialog_store,
                stream_store: &mut stream_store,
                rtp_heuristic: &mut rtp_heuristic,
                event_exec: &mut event_exec,
                srtp: Some(srtp),
                dtls: None,
                group: None,
            };
            process_parsed_packet(
                pp,
                &ctx,
                &mut state,
                &mut engines,
                &mut counters,
                &mut effects,
            );
        }
        let mut sink = output::BatchSink::new(Vec::new(), false);
        effects.drain(&mut sink, &engines.alerts, &mut event_exec);
        counters.rtp_count
    }

    /// A plaintext (non-SRTP) RTP packet must pass through an active SRTP
    /// context untouched: the auth tag never verifies on ordinary RTP, so the
    /// pipeline must NOT mangle it as a false "decryption". This guards the
    /// wiring's safety property at the binary layer.
    #[cfg(feature = "tls")]
    #[test]
    fn srtp_context_never_false_decrypts_plain_rtp() {
        use crate::rtp::srtp::{SrtpContext, SrtpKeyMaterial, SrtpSuite};

        // A loaded context with one master key.
        let key = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: vec![0x01u8; 16],
            master_salt: vec![0x02u8; 14],
            ssrc: None,
            media_addr: None,
            media_port: None,
        };
        let mut srtp = SrtpContext::new(vec![key], crate::crypto::default_backend());

        // Ordinary RTP: 12-byte header (V=2, PT=0/PCMU) + 20 bytes payload.
        let mut payload = vec![0x80u8, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x10, 0x00];
        payload.extend_from_slice(&[0x00, 0x00, 0xAB, 0xCD]); // SSRC
        payload.extend_from_slice(&[0x7Fu8; 20]); // PCMU silence-ish payload
        let pp = ParsedPacket {
            payload: payload.into(),
            ..parsed_sip_packet(invite_bytes("x@y"), 40000, 40000)
        };

        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;
        let rtp = drive_packet_with_srtp(&cli, &pp, (5060, 5061), &mut srtp);
        assert_eq!(rtp, 1, "the RTP packet must still be counted/processed");
        assert_eq!(
            srtp.decrypted_count, 0,
            "ordinary RTP must never be falsely decrypted (auth-tag gate)"
        );
    }

    /// A valid INVITE on the SIP port increments the SIP counter.
    #[test]
    fn process_parsed_packet_counts_sip() {
        let mut cli = base_cli();
        cli.output_args.no_cli_print = true; // keep test output quiet
        let pp = parsed_sip_packet(invite_bytes("ppp-1@example.com"), 5060, 5060);
        let (sip, _rtp) = drive_packet(&cli, &pp, (5060, 5061));
        assert_eq!(sip, 1, "one SIP message should be counted");
    }

    /// Garbage payloads and SIP messages outside the port range are not
    /// counted as SIP.
    #[test]
    fn process_parsed_packet_ignores_non_sip_and_out_of_range() {
        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;

        // Garbage payload on the SIP port: not a SIP message -> no count.
        let pp = parsed_sip_packet(b"\x00\x01\x02not-sip-at-all".to_vec(), 5060, 5060);
        let (sip, _rtp) = drive_packet(&cli, &pp, (5060, 5061));
        assert_eq!(sip, 0);

        // A valid SIP message but on a port outside the SIP range -> skipped.
        let pp = parsed_sip_packet(invite_bytes("oor-1@example.com"), 40000, 40001);
        let (sip, _rtp) = drive_packet(&cli, &pp, (5060, 5061));
        assert_eq!(sip, 0);
    }

    // ── decide_emit: dialog-following (`-e`) + trailing context (`-A`) ────

    use std::collections::HashSet;

    /// Convenience: run decide_emit with fresh trailing/no -A, follow on.
    fn emit_follow(direct: bool, call_id: Option<&str>, followed: &mut HashSet<String>) -> bool {
        let mut trailing = 0usize;
        decide_emit(direct, call_id, true, followed, &mut trailing, 0)
    }

    /// A direct match arms its dialog; later non-matching messages of that
    /// dialog still emit while unrelated dialogs stay silent.
    #[test]
    fn follow_arms_dialog_then_emits_rest() {
        let mut followed = HashSet::new();
        // A direct match on dialog X arms it and emits.
        assert!(emit_follow(true, Some("X"), &mut followed));
        // A later non-matching message of X is still emitted (followed).
        assert!(emit_follow(false, Some("X"), &mut followed));
        assert!(emit_follow(false, Some("X"), &mut followed));
        // An unrelated dialog Y that never matched is not emitted.
        assert!(!emit_follow(false, Some("Y"), &mut followed));
    }

    /// With follow off, matching is strictly per-message and no dialog is
    /// ever armed.
    #[test]
    fn no_follow_when_expression_absent() {
        // follow_dialogs = false → per-message semantics, no arming.
        let mut followed = HashSet::new();
        let mut trailing = 0usize;
        assert!(decide_emit(
            true,
            Some("X"),
            false,
            &mut followed,
            &mut trailing,
            0
        ));
        // Next non-matching message of X must NOT be emitted (no dialog-follow).
        assert!(!decide_emit(
            false,
            Some("X"),
            false,
            &mut followed,
            &mut trailing,
            0
        ));
        assert!(
            followed.is_empty(),
            "follow set must stay empty when inactive"
        );
    }

    /// `-A 2` without follow: a match shows the next two messages, then the
    /// budget is exhausted.
    #[test]
    fn trailing_context_preserved_without_follow() {
        // -A 2, no match-expression: a match shows the next 2 messages, then stops.
        let mut followed = HashSet::new();
        let mut trailing = 0usize;
        assert!(decide_emit(
            true,
            Some("X"),
            false,
            &mut followed,
            &mut trailing,
            2
        ));
        assert_eq!(trailing, 2);
        assert!(decide_emit(
            false,
            Some("X"),
            false,
            &mut followed,
            &mut trailing,
            2
        ));
        assert_eq!(trailing, 1);
        assert!(decide_emit(
            false,
            Some("Y"),
            false,
            &mut followed,
            &mut trailing,
            2
        ));
        assert_eq!(trailing, 0);
        // Budget exhausted → no more trailing emits.
        assert!(!decide_emit(
            false,
            Some("Z"),
            false,
            &mut followed,
            &mut trailing,
            2
        ));
    }

    /// A followed-dialog message emits without spending the `-A` budget;
    /// only pure trailing-context messages consume it.
    #[test]
    fn followed_messages_do_not_consume_trailing_budget() {
        // With both -A 1 and a match-expression: a followed-dialog message is
        // emitted but must not spend the trailing budget meant for context.
        let mut followed = HashSet::new();
        let mut trailing = 0usize;
        // Direct match on X arms X and sets trailing budget to 1.
        assert!(decide_emit(
            true,
            Some("X"),
            true,
            &mut followed,
            &mut trailing,
            1
        ));
        assert_eq!(trailing, 1);
        // A followed message of X emits but leaves the budget untouched.
        assert!(decide_emit(
            false,
            Some("X"),
            true,
            &mut followed,
            &mut trailing,
            1
        ));
        assert_eq!(trailing, 1, "followed message must not decrement -A budget");
        // An unrelated dialog Y consumes the trailing budget as pure context.
        assert!(decide_emit(
            false,
            Some("Y"),
            true,
            &mut followed,
            &mut trailing,
            1
        ));
        assert_eq!(trailing, 0);
    }

    /// A match without a Call-ID emits but cannot arm any dialog.
    #[test]
    fn follow_with_missing_call_id_does_not_arm_or_panic() {
        // A direct match with no Call-ID cannot arm any dialog.
        let mut followed = HashSet::new();
        assert!(emit_follow(true, None, &mut followed));
        assert!(followed.is_empty(), "no Call-ID must not arm a dialog");
        // A subsequent Call-ID-less non-match is not emitted.
        assert!(!emit_follow(false, None, &mut followed));
    }

    /// Call-IDs with NUL/backslash/tab bytes round-trip through the follow
    /// set without corruption.
    #[test]
    fn follow_handles_adversarial_call_id_bytes() {
        // Call-IDs with backslashes / embedded NUL must round-trip through the
        // follow set unharmed.
        let weird = "call\u{0}id\\weird\t";
        let mut followed = HashSet::new();
        assert!(emit_follow(true, Some(weird), &mut followed));
        assert!(emit_follow(false, Some(weird), &mut followed));
        assert!(!emit_follow(false, Some("other"), &mut followed));
    }

    // ── SweepClock ─────────────────────────────────────────────────

    /// A fixed capture epoch years behind wall time, so any wall-clock
    /// contamination of the offline path is unmissable.
    fn cap_ts(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("valid timestamp")
    }

    /// Five seconds, the sweep interval the receive loops use.
    const FIVE: std::time::Duration = std::time::Duration::from_secs(5);

    /// Offline, the sweep is paced by the capture's timeline: no packets means
    /// no sweep, however long the process has been running.
    #[test]
    fn capture_clock_does_not_sweep_without_packets() {
        let mut clock = SweepClock::new(true);
        assert_eq!(clock.take_due(FIVE), None);
        // The first packet only starts the clock.
        clock.observe(cap_ts(0));
        assert_eq!(clock.take_due(FIVE), None);
    }

    /// Offline, a sweep is due once the CAPTURE has advanced by the interval,
    /// and its "now" is the packet time — not `Utc::now()`.
    #[test]
    fn capture_clock_sweeps_on_packet_time() {
        let mut clock = SweepClock::new(true);
        clock.observe(cap_ts(0));
        assert_eq!(clock.take_due(FIVE), None);

        clock.observe(cap_ts(4));
        assert_eq!(clock.take_due(FIVE), None, "4 s of capture is not 5");

        clock.observe(cap_ts(5));
        assert_eq!(
            clock.take_due(FIVE),
            Some(CaptureNow(cap_ts(5))),
            "sweep must run at the packet's time, not the wall clock's"
        );
        // ...and not again until another interval of capture time passes.
        assert_eq!(clock.take_due(FIVE), None);
        clock.observe(cap_ts(9));
        assert_eq!(clock.take_due(FIVE), None);
        clock.observe(cap_ts(10));
        assert_eq!(clock.take_due(FIVE), Some(CaptureNow(cap_ts(10))));
    }

    /// The whole point: how long the read takes cannot change the offline
    /// sweep schedule. Two clocks fed the same timestamps agree even though
    /// one of them has real time passing between the calls.
    #[test]
    fn capture_clock_is_independent_of_wall_time() {
        let stamps = [0, 2, 4, 6, 8, 10, 12];
        let sweep = |pause: std::time::Duration| {
            let mut clock = SweepClock::new(true);
            let mut fired = Vec::new();
            for s in stamps {
                clock.observe(cap_ts(s));
                if let Some(now) = clock.take_due(FIVE) {
                    fired.push(now.get());
                }
                std::thread::sleep(pause);
            }
            fired
        };
        let fast = sweep(std::time::Duration::ZERO);
        let slow = sweep(std::time::Duration::from_millis(20));
        assert_eq!(fast, slow, "offline sweep schedule moved with wall time");
        assert_eq!(fast, vec![cap_ts(6), cap_ts(12)]);
    }

    /// An out-of-order packet must not rewind the capture clock: a stale
    /// timestamp would otherwise postpone every later sweep.
    #[test]
    fn capture_clock_never_moves_backwards() {
        let mut clock = SweepClock::new(true);
        clock.observe(cap_ts(0));
        assert_eq!(clock.take_due(FIVE), None);
        clock.observe(cap_ts(10));
        clock.observe(cap_ts(3)); // reordered arrival
        assert_eq!(
            clock.take_due(FIVE),
            Some(CaptureNow(cap_ts(10))),
            "a reordered packet rewound the capture clock, postponing the sweep"
        );
    }

    /// The end-of-run sweep's "now" is the capture's LAST timestamp, whatever
    /// the periodic schedule happened to land on. `--cores` reads this to
    /// sweep its merged stores once, so a value short of the final packet
    /// would leave the last stretch of the capture unswept.
    #[test]
    fn final_now_is_the_captures_last_timestamp() {
        let mut clock = SweepClock::new(true);
        assert_eq!(clock.final_now(), None, "nothing read, nothing to sweep");
        clock.observe(cap_ts(0));
        assert_eq!(clock.final_now(), Some(CaptureNow(cap_ts(0))));
        assert_eq!(
            clock.take_due(FIVE),
            None,
            "the first packet only starts the periodic clock"
        );
        clock.observe(cap_ts(900));
        assert_eq!(
            clock.final_now(),
            Some(CaptureNow(cap_ts(900))),
            "the final sweep must measure against the last packet"
        );
        // A periodic sweep in between must not move it, and reading it must
        // not consume anything: the two questions are independent.
        assert_eq!(clock.take_due(FIVE), Some(CaptureNow(cap_ts(900))));
        assert_eq!(clock.final_now(), Some(CaptureNow(cap_ts(900))));
        assert_eq!(clock.final_now(), Some(CaptureNow(cap_ts(900))));
    }

    /// Live, the end-of-run sweep is wall time — the same split `take_due`
    /// makes. A live run's packets carry arrival times, so the two clocks
    /// agree there and only the offline path needs the capture's own.
    #[test]
    fn final_now_is_wall_time_on_a_live_run() {
        let mut clock = SweepClock::new(false);
        clock.observe(cap_ts(0)); // years in the past, must be ignored
        let now = clock.final_now().expect("a live clock always has a now");
        assert!(
            chrono::Utc::now().signed_duration_since(now.get()) < chrono::TimeDelta::seconds(5),
            "a live final sweep's now must be wall time, got {:?}",
            now.get()
        );
    }

    /// Live capture keeps wall time, where it is correct: packet timestamps
    /// are ignored and the sweep is due after the interval really elapses.
    #[test]
    fn live_clock_uses_wall_time_and_ignores_packet_time() {
        let mut clock = SweepClock::new(false);
        // A packet from the distant past cannot make a live sweep due.
        clock.observe(cap_ts(0));
        assert_eq!(clock.take_due(FIVE), None);
        // ...and a zero interval makes one due immediately, on wall time.
        let now = clock
            .take_due(std::time::Duration::ZERO)
            .expect("elapsed >= 0 always");
        assert!(
            chrono::Utc::now().signed_duration_since(now.get()) < chrono::TimeDelta::seconds(5),
            "a live sweep's now must be wall time, got {:?}",
            now.get()
        );
    }

    // ── Operator-set thresholds reach the things that enforce them ───────

    /// `--kill-rate-limit` bounds the responses the worker actually sends.
    ///
    /// The observation is the worker's own ledger of what went on the wire,
    /// not the number handed to the constructor: the worker reads `None` as
    /// "use your own default", so a wiring that forgot the ceiling would still
    /// produce a worker, still rate-limit at 10/s, and pass any test that only
    /// looked at the resolver.
    ///
    /// Each request goes to a DIFFERENT loopback destination, because a
    /// per-destination cap of 3/minute sits underneath the global one and
    /// would otherwise be what bounds the run. Every packet is addressed to
    /// `127.0.0.0/8`, so nothing leaves the machine.
    #[test]
    fn the_configured_kill_rate_limit_bounds_what_the_worker_sends() {
        use crate::security::transmit_guard::TransmitPermit;

        /// Send `n` kill responses to `n` distinct loopback destinations
        /// through a worker built from `args`, and return what it did.
        fn sent_under(args: &[&str], n: u8) -> crate::process_isolation::KillCounts {
            let cli = Cli::parse_from_args(args.iter().copied());
            let config = Config::default();
            let permit = TransmitPermit::for_source(&crate::capture::CaptureSource::Live {
                device: "lo".to_string(),
            })
            .expect("a live source yields a permit");
            let mut handle = spawn_kill_worker(&cli, &config, None, permit)
                .expect("the worker thread must spawn");
            for i in 0..n {
                let dst = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2 + i));
                let _ = handle.send_kill(KillRequest::SendResponse {
                    dst_addr: dst,
                    dst_port: 9,
                    src_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    src_port: 5060,
                    response_bytes: b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
                });
            }
            handle.shutdown();
            handle.counts()
        }

        let tight = sent_under(&["sipnab", "--kill-rate-limit", "1"], 20);
        assert_eq!(
            tight.outcomes(),
            20,
            "every request must reach an outcome, or the counts below mean nothing"
        );
        assert_eq!(
            tight.sent, 1,
            "--kill-rate-limit 1 must let exactly one response onto the wire in \
             the first second; the worker sent {}",
            tight.sent
        );
        assert!(
            tight.rate_limited >= 19,
            "the other 19 must be suppressed, not sent; got {} suppressed",
            tight.rate_limited
        );

        // And a ceiling ABOVE the built-in 10 is honored, or the setting can
        // only ever tighten — half a knob.
        let wide = sent_under(&["sipnab", "--kill-rate-limit", "100"], 20);
        assert_eq!(
            wide.rate_limited, 0,
            "--kill-rate-limit 100 must not suppress 20 responses; got {} suppressed",
            wide.rate_limited
        );
    }

    /// `--findings-history` bounds what the findings buffer actually retains.
    ///
    /// Built through the same helper the run uses, so deleting the
    /// `set_findings_capacity` line leaves the engine at its compiled-in 1000
    /// and this fails. The observation is what `iter_findings` returns — the
    /// surface an agent reads — not the field the setter wrote.
    #[test]
    fn the_configured_findings_history_bounds_what_is_retained() {
        fn retained(args: &[&str], config: &Config, fired: u32) -> usize {
            let mut engine = build_alert_engine(
                &Cli::parse_from_args(args.iter().copied()),
                config,
                Vec::new(),
                None,
            );
            let at = chrono::Utc::now();
            for n in 0..fired {
                engine.fire(
                    "scanner",
                    IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n)),
                    "detection=behavioral",
                    at,
                );
            }
            engine.iter_findings(&[], None, 10_000).len()
        }

        assert_eq!(
            retained(
                &["sipnab", "--findings-history", "3"],
                &Config::default(),
                10
            ),
            3,
            "--findings-history 3 must bound the buffer to three findings"
        );
        let mut config = Config::default();
        config.security.findings_history = Some(4);
        assert_eq!(
            retained(&["sipnab"], &config, 10),
            4,
            "[security] findings_history must reach the engine"
        );
        assert_eq!(
            retained(&["sipnab", "--findings-history", "2"], &config, 10),
            2,
            "--findings-history must beat [security] findings_history"
        );
        assert_eq!(
            retained(&["sipnab"], &Config::default(), 10),
            10,
            "with nothing declared, ten findings must all be kept"
        );
    }
}
