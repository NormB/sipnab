// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Batch (non-interactive) mode: the state and receive loop behind every
//! headless run (`--no-tui`, `--mcp`, replay, `--cores`).
//!
//! `BatchRunner` owns what used to be ~25 loose locals in main.rs — the
//! writer, detector engines, decryption state, counters, and companion-server
//! handles — built once in `BatchRunner::new` and consumed by the receive
//! loop. `run` is the single entry point the binary dispatches to (WS2).

use crate::output::stdout::{out, outln};
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use smallvec::SmallVec;

use crate::capture::{self, CaptureConfig, ParsedPacket, PcapExportMode, PcapWriter};
use crate::cli::Cli;
use crate::config::Config;
use crate::output::{self, EventExecEngine, OutputOptions, ReportFormat};
use crate::process_isolation::{KillRequest, ScannerKillHandle};
use crate::rtp::{self, stream_store::StreamStore};
use crate::security::{
    self as sec, AlertEngine, AlertRule, DigestLeakDetector, FraudDetector, RegFloodDetector,
    ScannerDetector,
};
use crate::signals;
use crate::sip::{self, dialog_store::DialogStore, dsl::FilterExpr, matcher::SipMatcher};

#[cfg(feature = "tls")]
use crate::capture::decrypt::TlsDecryptor;
#[cfg(any(feature = "tls", test))]
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
    /// Channel to the scanner-kill worker process; `None` when no kill
    /// feature is active (or the worker failed to start).
    kill_handle: Option<ScannerKillHandle>,
    /// SIP status code sent in kill responses (`--kill-response`).
    kill_response_code: u16,
    /// Targeted-kill directives (`-K` / `--kill-target`): any SIP request whose
    /// source matches is killed regardless of UA/behavioral detection.
    kill_targets: Vec<sec::scanner_kill::KillTarget>,
    /// `--kill-scanner-detect-only` / `[security] kill_scanner_detect_only`:
    /// scanners are detected and never answered.
    detect_only: bool,
}

impl DetectionEngines {
    /// Whether this run answers the scanners it detects, for the startup
    /// summary and the `scanner_response` field of `security_findings`.
    fn scanner_response(&self) -> crate::security::findings::ScannerResponse {
        crate::security::findings::ScannerResponse::for_run(
            self.scanner.is_some() || !self.kill_targets.is_empty(),
            self.detect_only,
            self.kill_handle.is_some(),
        )
    }

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

    /// Age out detector state older than `max_age`, and refresh what the
    /// registration-flood detector says it cannot see.
    fn sweep(&mut self, max_age: std::time::Duration) {
        if let Some(det) = self.scanner.as_mut() {
            det.sweep(max_age);
        }
        if let Some(det) = self.fraud.as_mut() {
            det.sweep(max_age);
        }
        if let Some(det) = self.reg_flood.as_mut() {
            det.sweep(max_age);
            // Refresh what the detector says it cannot see, so the
            // MCP and REST findings pages carry it on a live run too.
            // Filed rather than logged: it is a standing condition,
            // not an event, and a log line every five seconds is noise.
            let gap = det.observation_gap(false);
            self.alerts.write().set_observation_gap("reg_flood", gap);
        }
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
    /// Which telephone-event end packets have already been counted.
    ///
    /// [RFC 4733 section 2.5.1.4](https://www.rfc-editor.org/rfc/rfc4733.html#section-2.5.1.4) makes a sender transmit the final packet of an event
    /// three times, so one keypress arrived as three events and was counted
    /// three times.
    dtmf_seen: rtp::dtmf::DtmfDedupe,
}

/// Owned batch-mode processing components, built by the binary's
/// bootstrap and handed to `run`.
pub struct BatchProcessing {
    /// Header-level SIP matcher (`-m`, `--method`, ...).
    pub matcher: SipMatcher,
    /// Compiled `--filter` DSL expression, when given.
    pub filter_expr: Option<FilterExpr>,
    /// Compiled `--export-vcon-when` expression, resolved by the plan.
    pub vcon_rules: Vec<VconRule>,
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
    /// Decode RFC 4733 telephone events: `--telephone-event`, or a
    /// `[[vcon.rule]]` with `dtmf_events`, which writes them.
    telephone_events: bool,
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
    /// `--pcap-export-mode decrypted` (PCAPX-DEC): told when this packet's
    /// SRTP decrypted, or it was RTCP, so the export can rewrite or count it.
    #[cfg(feature = "tls")]
    export: Option<&'a mut crate::capture::decrypted_export::DecryptedExport>,
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
        // A member of an archive exists only as a file sipnab extracted and
        // will delete; `tshark -r` cannot read inside the archive either.
        [one] if crate::capture::archive::is_extracted_member(one) => Err(format!(
            "the input '{}' is a member of an archive, and `tshark -r` reads one \
             capture file; extract that member and point tshark at it",
            crate::capture::archive::source_name(one)
        )),
        [one] => Ok(one.display().to_string()),
        many => Err(format!(
            "the input is {} files and `tshark -r` reads one, so no single \
             command covers this run. The display filter below names Call-IDs \
             from all of them; a command reading only one would silently return \
             a subset. Files: {}",
            many.len(),
            many.iter()
                .map(|p| crate::capture::archive::source_name(p))
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
        hep_parse: cli.hep_parse(config),
        rtpproxy_control: cli.rtp_args.rtpproxy_control,
        xcid_headers: config.sip.xcid_headers.clone().unwrap_or_default(),
        leg_correlation_window_ms: cli.leg_correlation_window_ms(config),
        retain_audio: audio_retention_wanted(cli, config),
        audio_limits: config.limits.audio_limits(),
        reassembly: !cli.capture_args.no_reassembly,
        parse_limit: cli.capture_args.limitlen,
    }
}

/// Spawn the relay-statistics poll thread when `--relay-stats-interval` asks
/// for one (ST4/C5).
///
/// Returns `(None, None)` when nothing should poll: the flag was not given, no
/// relay was named, or the run may not transmit (a file-backed run). The gate is
/// [`relay_poll_plan`](crate::app::bootstrap::relay_poll_plan), which shares its
/// rule with the one-shot ask -- polling asks the relay, and asking transmits --
/// so the two cannot drift. The `permit` argument carries whether this run holds
/// a transmit permit at all (it is `Some` only when a relay was configured on a
/// live source).
///
/// The thread transmits, so it cannot be driven from a test; the loop and its
/// shutdown are tested in [`crate::app::relay_poller`] with an injected action,
/// and the poll/refuse decision this reads is tested through `relay_poll_plan`.
/// Here the injected action is the real fetch-and-print, and this seam is
/// exercised end to end against the harness.
fn spawn_relay_stats_poller(
    cli: &Cli,
    permit: Option<crate::security::transmit_guard::TransmitPermit>,
) -> (
    Option<std::sync::mpsc::Sender<()>>,
    Option<std::thread::JoinHandle<()>>,
) {
    let Some(target) = relay_poll_target(cli, permit) else {
        return (None, None);
    };
    let interval = std::time::Duration::from_secs(target.secs);
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let mut poll = RelayStatsPoll::new(target, cli);

    match crate::app::relay_poller::spawn(interval, rx, move || poll.poll_once()) {
        Ok(join) => (Some(tx), Some(join)),
        Err(e) => {
            tracing::warn!("could not start the relay statistics poller ({e}); nothing polled");
            (None, None)
        }
    }
}

/// What a relay-statistics poll is aimed at: the interval, the relay's parsed
/// socket and the address as the operator typed it, and the permit that lets
/// the poll transmit.
struct RelayPollTarget {
    /// The interval in seconds, as the operator configured it.
    secs: u64,
    /// The relay address the operator named, carried verbatim for messages.
    addr: String,
    /// `addr`, parsed.
    socket: std::net::SocketAddr,
    /// Proof this run may transmit.
    permit: crate::security::transmit_guard::TransmitPermit,
}

/// Decide whether this run polls a relay, and at what.
///
/// `None` when nothing polls, either because no interval was given or
/// because the poll is refused; a refusal is logged with the operator's fix.
fn relay_poll_target(
    cli: &Cli,
    permit: Option<crate::security::transmit_guard::TransmitPermit>,
) -> Option<RelayPollTarget> {
    use crate::app::bootstrap::{RelayPollPlan, relay_poll_plan};

    // The precondition is ONE rule, shared with the one-shot ask
    // (`relay_stats_action`): a poll transmits on a timer, so it needs an
    // interval, a relay named, and a permit. A missing relay or permit is
    // REFUSED with the operator's fix, never a silent no-op.
    let (secs, addr) = match relay_poll_plan(
        cli.rtp_args.relay_stats_interval,
        cli.rtp_args.rtpengine_control.as_deref(),
        permit.is_some(),
    ) {
        RelayPollPlan::Idle => return None, // Nothing polls by default.
        RelayPollPlan::NotConfigured => {
            tracing::error!(
                "--relay-stats-interval needs a relay to poll. Name one with \
                 --rtpengine-control <addr>."
            );
            return None;
        }
        RelayPollPlan::NotPermitted => {
            tracing::error!(
                "--relay-stats-interval will not poll a relay on a run that reads a \
                 file: polling transmits. Poll from a live capture (-d <device>)."
            );
            return None;
        }
        RelayPollPlan::Poll { secs, addr } => (secs, addr),
    };
    // Unreachable when `None`: a `Poll` plan is produced only when
    // `permit.is_some()`.
    let permit = permit?;
    let socket = match addr.parse::<std::net::SocketAddr>() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "--rtpengine-control {addr} is not an address and port ({e}); \
                 nothing is polled."
            );
            return None;
        }
    };
    Some(RelayPollTarget {
        secs,
        addr,
        socket,
        permit,
    })
}

/// One relay-statistics poller's state, moved onto the poll thread.
struct RelayStatsPoll {
    /// Control client for the relay being polled.
    client: crate::rtpengine::control::ControlClient,
    /// Proof this run may transmit.
    permit: crate::security::transmit_guard::TransmitPermit,
    /// `rtpengine at <addr>`, the name every line about this relay uses.
    label: String,
    /// The poll interval, in seconds as configured.
    secs: u64,
    /// The poll interval.
    interval: std::time::Duration,
    /// Captured before the closure moves: each polled reading honors --json the
    /// same way the one-shot forms do.
    json: bool,
    /// `--json-pretty`, captured the same way.
    json_pretty: bool,
    /// Holds the previous poll's raw pairs so a counter that steps backwards --
    /// which a cumulative counter cannot do without a reset -- is caught between
    /// polls (ST-S4 condition 6). rtpproxy publishes no uptime, so a decrease is
    /// the only in-band signal it restarted.
    previous: Option<Vec<(String, String)>>,
}

impl RelayStatsPoll {
    /// A poller for `target`, printing in the output form `cli` asked for.
    fn new(target: RelayPollTarget, cli: &Cli) -> Self {
        use crate::rtpengine::control::{ControlClient, DEFAULT_CONTROL_TIMEOUT};
        Self {
            client: ControlClient::new(target.socket, DEFAULT_CONTROL_TIMEOUT),
            permit: target.permit,
            label: format!("rtpengine at {}", target.addr),
            secs: target.secs,
            interval: std::time::Duration::from_secs(target.secs),
            json: cli.output_args.json,
            json_pretty: cli.output_args.json_pretty,
            previous: None,
        }
    }

    /// Ask the relay once and print what it answered.
    fn poll_once(&mut self) {
        // Time the round trip. The serial loop never overlaps polls, so a relay
        // slower than the interval slows the cadence rather than stacking
        // requests; a poll whose own round trip overran the interval is where
        // that slip happens, and it is said plainly rather than left silent
        // (ST-S4 condition 13, the visibility half).
        let started = std::time::Instant::now();
        let result = self.client.statistics(&self.permit);
        let elapsed = started.elapsed();
        if crate::app::relay_poller::cadence_slipped(elapsed, self.interval) {
            tracing::warn!(
                "{}: this poll's round trip took {elapsed:.1?}, longer than the {}s \
                 interval; the polling cadence has slipped and is slower than requested.",
                self.label,
                self.secs
            );
        }
        match result {
            Ok(crate::relay::types::ControlReply::Statistics(pairs)) => self.on_statistics(pairs),
            Ok(other) => tracing::error!("{} answered {other:?}, not statistics", self.label),
            Err(e) => {
                tracing::error!(
                    "{} did not answer the polled statistics request ({e})",
                    self.label
                );
            }
        }
    }

    /// Check one reading against the previous one, then print it.
    fn on_statistics(&mut self, pairs: Vec<(String, String)>) {
        use crate::stats_vocab::{counter_stepped_backwards, relay_reported, resolve_for_wire};
        if let Some(prev) = &self.previous
            && let Some(step) = counter_stepped_backwards(prev, &pairs)
        {
            // Suspect, not a drop in traffic: never smoothed, and the
            // counters below are since an unknown start after the reset.
            tracing::warn!(
                "{}: {} stepped backwards {} -> {} between polls; a cumulative \
             counter cannot decrease, so the relay probably restarted (suspect). The \
             counters below are since an unknown start.",
                self.label,
                step.name,
                step.previous,
                step.current
            );
        }
        let wire = resolve_for_wire(&relay_reported(&pairs));
        self.previous = Some(pairs);
        self.print_reading(&wire);
    }

    /// Print one reading in the form `--json` / `--json-pretty` chose.
    fn print_reading(&self, wire: &crate::stats_vocab::WireStatistics) {
        use crate::output::relay_statistics::{
            FetchOrigin, format_relay_statistics, format_relay_statistics_json, maybe_pretty,
        };
        let origin = FetchOrigin::Polled {
            every_secs: self.secs,
        };
        if self.json || self.json_pretty {
            outln!(
                "{}",
                maybe_pretty(
                    format_relay_statistics_json(wire, &self.label, chrono::Utc::now(), origin),
                    self.json_pretty
                )
            );
        } else {
            out!(
                "{}",
                format_relay_statistics(wire, &self.label, chrono::Utc::now(), origin)
            );
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
pub(crate) fn build_fraud_detector(cli: &Cli, config: &Config) -> Option<FraudDetector> {
    if !(cli.fraud_detect(config)) {
        return None;
    }
    // Already refused by `Cli::validate` and `SecurityConfig::validate`, so
    // reaching the error arm means a caller skipped both. Say so rather than
    // running a detector that is quietly missing a detection.
    let business_hours = cli.business_hours(config).unwrap_or_else(|e| {
        tracing::error!("{e}; off-hours fraud detection is OFF for this run");
        None
    });
    let watch = cli.fraud_watch(config);
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
            stderr_line!("{reason}");
            // The invocation was wrong, which is exit 2. Not 3: a pipeline has
            // to tell "this capture is non-conformant" apart from "sipnab was
            // asked to read a file that is not there", and only the first is a
            // fact about the traffic.
            crate::capture::archive::release_run_and_exit(2);
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
            outln!(
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
    stderr_line!("Lint: {total} finding(s) across {dialogs} dialog(s)");
    // Suppression never hides itself, on this surface as on the MCP one. A
    // short finding list has to say why it is short, and "which file" is the
    // actionable half: discovery may have climbed several directories to reach
    // a `.sipnablint` nobody on this pipeline knew about.
    if let Some(file) = &suppressions {
        stderr_line!(
            "Lint: suppressions from {} ({} pattern(s)), {} finding(s) silenced",
            file.path().display(),
            file.patterns().len(),
            withheld.suppressed,
        );
    }
    if withheld.capped > 0 {
        stderr_line!(
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
pub(crate) fn lint_suppressions(
    cli: &Cli,
) -> Result<Option<crate::sip::lint::SuppressionFile>, String> {
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
    vcon_rules: &[VconRule],
) {
    if paths.is_empty() {
        // Unreachable through `main`: `RunMode::CoresFile` requires `-I`, and
        // `input_set::resolve` already failed the run if nothing resolved. Say
        // so loudly anyway rather than exiting 0 with an empty report, which is
        // precisely the failure this path used to have.
        tracing::error!("--cores: no capture files to read");
        crate::capture::archive::release_run_and_exit(1);
    }
    crate::app::bootstrap::refuse_cores_without_a_view(cli, !vcon_rules.is_empty());
    let no_rtp = cli.no_rtp(config);
    let pcfg = parallel_config(cli, config, portrange, no_rtp);
    let pre_opened = match crate::app::bootstrap::prepare_cores_inputs(
        cli,
        config,
        paths,
        capture_config.bpf_filter.is_none(),
    ) {
        Ok(set) => set,
        Err(e) => e.exit(),
    };
    let inputs = match &pre_opened {
        Some(set) => crate::parallel::Inputs::PreOpened(set),
        None => crate::parallel::Inputs::ByPath,
    };
    match crate::parallel::run_offline_parallel_set(paths, &inputs, capture_config, pcfg) {
        Ok(r) => {
            // The return value is the "report could not be produced" signal and
            // was dropped here, so an unknown --call-report id or an unwritable
            // stdout exited 0 on the --cores path while exiting 1 elsewhere.
            // No companion server runs on the --cores path, so there is no
            // gate anyone could have moved and the command line governs.
            let reports_ok = report_parallel_run(cli, config, &r, filter, vcon_rules);
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
                crate::capture::archive::release_run_and_exit(1);
            }
            if lint_tripped {
                crate::capture::archive::release_run_and_exit(3);
            }
            // The same order as the single reader's `run_exit_code`: a
            // failure, then the lint gate, then a query gate.
            if let Some(code) = crate::app::queries::gate_exit_code() {
                crate::capture::archive::release_run_and_exit(code);
            }
        }
        Err(e) => {
            tracing::error!("multi-core reconstruction failed: {e:#}");
            crate::capture::archive::release_run_and_exit(1);
        }
    }
}

/// Write a finished `--cores` run's reports and print its end-of-run summary,
/// returning whether every report could be produced.
///
/// One function for both `--cores` entry points, so the two cannot describe the
/// same run differently.
///
/// The packet count is `packets_read`, not `total_count`. The default reader
/// counts every record it read; `total_count` is what the workers PARSED, which
/// leaves out a frame no decoder could read and folds several reassembled
/// frames into one. Printing it made a 3-record capture holding one
/// undecodable frame read "2 packets" here and "3 packets" on the default
/// reader, and put that frame at "1 of 2" -- the share at which the NOT DECODED
/// notice calls a run mostly blind.
///
/// # Arguments
///
/// * `cli` — the parsed command line: the report flags and `--quiet`.
/// * `config` — the loaded config, for the thresholds a query resolves.
/// * `r` — the merged result of the parallel run.
/// * `filter` / `vcon_filter` — the compiled `--filter` expressions, as
///   [`generate_reports`] takes them.
///
/// # Side effects
///
/// Writes the requested reports to stdout, and unless `--quiet` logs the
/// summary line and prints the undecodable, ICMP, rate, retention,
/// capture-quality and LLMNR notices.
fn report_parallel_run(
    cli: &Cli,
    config: &Config,
    r: &crate::parallel::ReconResult,
    filter: Option<&FilterExpr>,
    vcon_rules: &[VconRule],
) -> bool {
    let reports_ok = generate_reports(
        cli,
        config,
        CaptureRead {
            dialogs: &r.dialog_store,
            streams: &r.stream_store,
            frames_read: r.packets_read,
        },
        filter,
        vcon_rules,
        None,
        // `--cores` reads files only, so there was no live export to follow.
        VconRunEnd::Whole,
    );
    if !cli.mode_args.quiet {
        tracing::info!(
            "sipnab: {} packets, {} SIP messages, {} RTP packets across {} streams ({} cores)",
            r.packets_read,
            r.sip_count,
            r.rtp_count,
            r.stream_store.len(),
            cli.limits_args.cores,
        );
        report_undecodable(r.packets_read);
        report_icmp_summary(&r.stream_store);
        report_relay_retries(&r.stream_store);
        report_impossible_rates(&r.stream_store);
        report_retention_losses(&r.dialog_store);
        report_capture_quality();
        report_llmnr_summary();
    }
    reports_ok
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
pub(crate) fn audio_retention_wanted(cli: &Cli, config: &Config) -> bool {
    // `--retain-audio` alone, not `--mcp && --retain-audio`. The conjunction
    // was right while the MCP server was the only thing that could read the
    // buffers back; the amplitude measurement in the media diagnosis reads
    // them now, on `--call-report` and `--json-dialogs`, and an operator who
    // asked for audio retention on a plain batch run would otherwise have got
    // silence with no explanation.
    //
    // A `[[vcon.rule]]` with `audio = "inline"` is the same consent, written in
    // the config: that rule's containers carry the audio, which has to be
    // retained to be carried.
    cli.mcp_args.retain_audio
        // Asking for one call's audio as a WAV is the same consent, given
        // for the run that writes it.
        || cli.call_query_args.export_audio.is_some()
        || config.vcon.rule.iter().any(|r| {
            matches!(
                RuleAudio::parse(r.audio.as_deref()),
                Ok(RuleAudio::Inline | RuleAudio::Url)
            )
        })
        // A live-audio rule serves the retained audio as it arrives.
        || config.vcon.rule.iter().any(|r| r.live_audio == Some(true))
        // So does a live RTP fork, which sends it.
        || config.vcon.rule.iter().any(|r| r.live_rtp.is_some())
        // An enrichment that sends audio needs the audio retained to send it.
        || config.vcon.enrich.iter().any(|e| {
            e.send
                .as_ref()
                .is_none_or(|send| send.iter().any(|w| w == "audio"))
        })
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
/// in it could read: the whole of every stream at the defaults, bounded only by
/// the 1 GiB `[limits] max_audio_bytes` budget across all streams.
///
/// It stayed latent because the auto-BPF filter is `portrange 5060-5061`, so no
/// RTP reaches the store to retain. It arms the moment an operator widens the
/// filter to capture media — the first thing they do when they want audio.
///
/// A one-armed `if` cannot express "exactly when"; an assignment can. Taking
/// `&mut StreamStore` keeps the decision and its effect inseparable, so a test
/// can hold the store afterwards and read back what a run would actually do.
fn apply_audio_retention(ss: &mut StreamStore, cli: &Cli, config: &Config) -> bool {
    let wanted = audio_retention_wanted(cli, config);
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
/// One line per relay control socket whose commands were retried (RP4).
///
/// A retry is a command repeating a cookie already seen: the proxy sent it
/// again because it did not hear an answer in time. One sent after the
/// relay's answer was already on the wire means that answer was lost or late
/// on its way back. From the SIP side a control channel losing answers shows
/// only as a proxy that is sometimes slow. Empty for a clean channel.
fn relay_retry_lines(counts: &[crate::relay_vocab::ControlChannelCounts]) -> Vec<String> {
    counts
        .iter()
        .filter(|c| c.retried_commands > 0)
        .map(|c| {
            format!(
                "{} at {}: {} of {} control commands were retried (the same cookie sent \
                 again), {} after the relay's answer was already on the wire. A retry \
                 means the proxy did not hear an answer in time; one sent after the \
                 answer means that answer was lost or late on its way back.",
                c.implementation.as_str(),
                c.relay,
                c.retried_commands,
                c.commands,
                c.retried_after_answer,
            )
        })
        .collect()
}

/// Warn about retried relay commands. See [`relay_retry_lines`].
///
/// # Side effects
///
/// Writes warnings to the tracing log; silent when no command was retried.
fn report_relay_retries(store: &crate::rtp::stream_store::StreamStore) {
    for line in relay_retry_lines(&store.relay_control_summary()) {
        tracing::warn!("{line}");
    }
}

/// Report Binding Requests that never came back.
///
/// Separate from `capture_quality`, which is about what sipnab RECEIVED. This
/// is about what the NETWORK did: the frames arrived perfectly, and the answer
/// to them did not. Reported even when the capture holds no SIP at all, which
/// is the case that most needs it — a capture of nothing but failed NAT
/// discovery used to read as "no SIP traffic found", which is true and useless.
fn report_stun_failures() {
    let (unanswered, answered) = crate::stun::unanswered_requests();
    for line in stun_failure_lines(&unanswered, answered, crate::stun::auth_challenges()) {
        tracing::warn!("{line}");
    }
}

/// How many entries an end-of-run NAT finding lists before it counts the rest.
const NAT_FINDING_LIST_CAP: usize = 5;

/// The lines [`report_stun_failures`] logs, in order; empty when nothing went
/// unanswered.
///
/// # Arguments
///
/// * `unanswered` — every request that drew no reply.
/// * `answered` — how many transactions did draw one, for the total.
/// * `challenges` — transactions answered with an authentication challenge.
///   Reported only beside unanswered requests, never on its own.
fn stun_failure_lines(
    unanswered: &[crate::stun::UnansweredRequest],
    answered: u64,
    challenges: u64,
) -> Vec<String> {
    if unanswered.is_empty() {
        return Vec::new();
    }
    let total = unanswered.len() as u64 + answered;
    let mut lines: Vec<String> = unanswered
        .iter()
        .take(NAT_FINDING_LIST_CAP)
        .map(unanswered_request_line)
        .collect();
    if unanswered.len() > NAT_FINDING_LIST_CAP {
        lines.push(format!(
            "STUN: {} further unanswered binding request(s) not listed.",
            unanswered.len() - NAT_FINDING_LIST_CAP
        ));
    }
    lines.push(format!(
        "STUN/TURN: {} of {total} transaction(s) went unanswered.",
        unanswered.len()
    ));
    if challenges > 0 {
        // Said separately because it points somewhere else entirely: the path
        // works and the server answered, so nothing here is a firewall
        // problem. An operator who reads only the line above goes hunting a
        // dropped packet that was never dropped.
        lines.push(format!(
            "STUN/TURN: {challenges} transaction(s) were answered with an \
             AUTHENTICATION challenge (a realm was offered). Those are not a \
             blocked path -- the server was reachable and asked for \
             credentials. Check the endpoint's STUN/TURN username and password \
             rather than the network."
        ));
    }
    lines
}

/// One unanswered request as the sentence [`report_stun_failures`] logs.
fn unanswered_request_line(req: &crate::stun::UnansweredRequest) -> String {
    let who = req
        .software
        .as_deref()
        .map(|s| format!(" ({s})"))
        .unwrap_or_default();
    format!(
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
        req.from, req.method, req.to, req.attempts,
    )
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
    for line in lapsed_allocation_lines(&lapsed) {
        tracing::warn!("{line}");
    }
}

/// The lines [`report_lapsed_allocations`] logs, in order; empty when nothing
/// lapsed.
fn lapsed_allocation_lines(lapsed: &[&crate::stun::TurnAllocation]) -> Vec<String> {
    if lapsed.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "TURN: {} allocation(s) were still carrying traffic after the lifetime they were \
         last granted had run out, with no Refresh seen in between. A relay tears an \
         allocation down when its lifetime lapses and the media stops with it, mid-call, \
         with no SIP message to say why.",
        lapsed.len()
    )];
    for alloc in lapsed.iter().take(NAT_FINDING_LIST_CAP) {
        lines.push(format!(
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
        ));
        // The media that was on the relay when it was torn down. Without it
        // the warning names an allocation and an operator has no way to reach
        // the call that went quiet, which is the only reason they are reading
        // it. Silent when no relayed frame was seen on the allocation — that
        // is a real and different answer, not a zero worth printing.
        if let Some(label) = alloc.relayed_media_label() {
            lines.push(format!("TURN:     media on it: {label}"));
        }
    }
    if lapsed.len() > NAT_FINDING_LIST_CAP {
        lines.push(format!(
            "TURN:   ... and {} further lapsed allocation(s) not listed.",
            lapsed.len() - NAT_FINDING_LIST_CAP
        ));
    }
    lines
}

/// Report candidate pairs where the two ICE agents disagreed about which of
/// them was in charge.
///
/// Reported beside the lapsed allocations rather than under `--stun` alone for
/// the reason that finding is: a capture read WITHOUT the flag must still say
/// it. [RFC 8445 section 7.3.1.1](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.3.1.1) lets ICE resolve a role conflict itself, so this is
/// not always fatal — and the line says which of the two it was, because
/// warning at full weight about a conflict the agents fixed in one round trip
/// is how a reader learns to skip the warning that matters.
///
/// # Side effects
///
/// Writes warnings to the tracing log; silent when no conflict was seen.
fn report_ice_role_conflicts(report: &crate::stun::StunReport) {
    for line in ice_role_conflict_lines(&report.ice_summary()) {
        tracing::warn!("{line}");
    }
}

/// The lines [`report_ice_role_conflicts`] logs, in order; empty when no
/// conflict was seen.
fn ice_role_conflict_lines(ice: &crate::stun::IceSummary) -> Vec<String> {
    if ice.role_conflicts_total == 0 {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "ICE: {} candidate pair(s) show a role conflict -- both agents claimed the same \
         role, or one answered 487 Role Conflict (RFC 8445 section 7.3.1.1). The usual \
         source is two endpoints configured with the same role, or a B2BUA relaying one \
         side's role attribute to the other.",
        ice.role_conflicts_total
    )];
    for conflict in ice.role_conflicts.iter().take(NAT_FINDING_LIST_CAP) {
        lines.push(format!(
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
        ));
    }
    if ice.role_conflicts.len() > NAT_FINDING_LIST_CAP {
        lines.push(format!(
            "ICE:   ... and {} further conflicted pair(s) not listed.",
            ice.role_conflicts.len() - NAT_FINDING_LIST_CAP
        ));
    }
    lines
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
    // The frames in BOTH of the last two channels: cut short and then
    // undecodable. They are reported with the snapped frames, because a frame
    // the snaplen cut did not reach sipnab intact, and the undecodable
    // sentence below says the ones it counts did.
    let snapped_undecodable = crate::capture::snapped_undecodable_frames();
    let intact_undecodable = undecodable.frames.saturating_sub(snapped_undecodable);
    // A sixth: holes in TCP streams that no captured packet filled. Reading
    // resumed at the next message behind each, so what is missing is the
    // data in the hole and any message it cut.
    let (holes, hole_bytes) = crate::capture::reassembly::tcp_gaps_skipped();
    if dropped == 0
        && if_dropped == 0
        && bad_ts == 0
        && undecodable.frames == 0
        && snapped == 0
        && holes == 0
    {
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
    if intact_undecodable > 0 {
        // Count and pointer, not the full breakdown: the NOT DECODED notice
        // prints immediately before this at every one of the three summary
        // sites, and repeating its reason list verbatim would turn a warning
        // that only fires when something is wrong into something to skim.
        parts.push(format!(
            "{intact_undecodable} frame(s) reached sipnab intact and could not be decoded \
             at all, so nothing in them was analyzed (see the NOT DECODED line above for \
             which link types, EtherTypes and IP protocols)"
        ));
    }

    if snapped > 0 && snapped_undecodable == 0 {
        // Named as truncation, not loss: the frames arrived and decoded. What
        // is missing is payload, which is why the remedy is a snaplen and not
        // a buffer.
        parts.push(format!(
            "{snapped} frame(s) arrived truncated by the capture's snaplen \
             (headers kept, payload cut short — raise --snaplen if you need RTP \
             payload, audio export or a faithful -O re-emit)"
        ));
    } else if snapped > 0 {
        // Some were cut too short to decode at all. "Headers kept" would be
        // false of those, and they are in the NOT DECODED line rather than in
        // any analysis, so the sentence says so and the remedy is the same.
        parts.push(format!(
            "{snapped} frame(s) arrived truncated by the capture's snaplen and \
             {snapped_undecodable} of them were cut too short to decode at all, so \
             nothing in those was analyzed (raise --snaplen)"
        ));
    }

    if holes > 0 {
        parts.push(format!(
            "{holes} hole(s) in TCP streams, {hole_bytes} byte(s) of sequence space the \
             capture never held, were skipped: reading resumed at the next SIP message \
             behind each, and a message the hole cut is lost (packets the capture point \
             missed)"
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

/// How many stored findings the end-of-capture accusation summary reads.
///
/// The alert engine keeps a bounded history; this reads it whole rather than
/// a page of it, because a summary built from the newest N findings would
/// silently drop the quietest source -- which is the one an operator is least
/// likely to have noticed already.
const ACCUSED_FINDING_SCAN_CAP: usize = 10_000;

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
/// * `report_printed` — whether this run prints the `--report` tables (see
///   [`report_tables_print`]). When it does, the media-only message does not
///   suggest `--report`, because the operator already passed it.
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
    report_printed: bool,
    undecodable: &crate::capture::UndecodableReport,
    frames_read: u64,
    tls: &crate::capture::TlsDecryptReport,
) -> Vec<String> {
    // RTP was parsed, so the capture demonstrably decoded: media-only, not
    // unreadable. Undecodable background here changes nothing. The hint to
    // pass `--report` is left out when this run prints the report already.
    if rtp_packets > 0 {
        let finding = format!(
            "No SIP signaling found, but {rtp_packets} RTP packets across {streams} \
             stream(s) were parsed."
        );
        if report_printed {
            return vec![finding];
        }
        return vec![format!("{finding} Use --report to see stream details.")];
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
        stderr_line!("{msg}");
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
    stderr_line!(
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
        stderr_line!(
            "LLMNR: hostname(s) claimed on this segment: {}.",
            join_capped(&claimed, 8)
        );
    }
    let unresolved = llmnr.unresolved_names();
    if !unresolved.is_empty() {
        stderr_line!(
            "LLMNR: name(s) queried that nothing answered for: {}.",
            join_capped(&unresolved, 8)
        );
    }
    for host in llmnr.hosts.iter().take(8) {
        if host.names_queried.is_empty() {
            continue;
        }
        stderr_line!(
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
        stderr_line!("LLMNR:   ... and {} more host(s).", llmnr.hosts.len() - 8);
    }
    // A cap that silently swallowed evidence would make the roster above read
    // as complete when it is not.
    if llmnr.dropped_hosts > 0 || llmnr.dropped_names > 0 {
        stderr_line!(
            "LLMNR: {} host(s) and {} name(s) were not retained (tracking caps); the packet \
             count above stays exact.",
            llmnr.dropped_hosts,
            llmnr.dropped_names
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
    ss.set_audio_limits(config.limits.audio_limits());
    // RE4: what the relay said it was holding when sipnab started, so a call
    // already in progress is named by its first packet rather than arriving as
    // an orphan.
    crate::pipeline::apply_relay_snapshot(&mut ss, relay_snapshot);
    if apply_audio_retention(&mut ss, cli, config) {
        // Retention changes this run's memory profile, so state the bound
        // rather than letting an operator discover it under load.
        tracing::info!("{}", retention_bound_message(ss.audio_limits()));
    }
    ss
}

/// The line a live run logs when it turns audio retention on: what it keeps
/// and what bounds it, so the bound is stated rather than discovered under
/// load.
fn retention_bound_message(limits: crate::rtp::stream_store::AudioLimits) -> String {
    let per_stream = limits.max_frames.map_or_else(
        || "whole calls".to_owned(),
        |f| format!("up to {f} frame(s) per stream"),
    );
    format!(
        "RTP payload retention is on so the MCP export_audio tool can decode it: \
         {per_stream}, inside a budget of {} byte(s) across every stream. At the \
         budget the oldest stream's earliest frames are released first, and its \
         export says so. Set [limits] max_audio_bytes to change the budget.",
        limits.max_bytes
    )
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
        stderr_line!(
            "ICMP: {} error(s) quoting a SIP request, naming {} unreachable endpoint(s). \
             Busiest: {}.",
            icmp.errors,
            icmp.endpoints.len(),
            top.join(", ")
        );
        // A cap that silently swallowed evidence would make the numbers above
        // understate the problem, so say when one bit.
        if icmp.unattributed > 0 || icmp.untracked_dialogs > 0 {
            stderr_line!(
                "ICMP: {} error(s) quoted too little to name a Call-ID and {} more reached no \
                 dialog because the tracking cap was full — real evidence that appears against \
                 no call.",
                icmp.unattributed,
                icmp.untracked_dialogs
            );
        }
    }

    // A media quote that matched no stream is still printed. Dropping it would
    // hide that the network answered, which is the whole point of reading ICMP.
    let media = crate::pipeline::icmp_media_report(streams);
    if media.errors > 0 {
        stderr_line!(
            "ICMP: {} error(s) quoting non-SIP traffic, {} of them media, across {} flow(s). \
             Attributed to a stream or SDP endpoint: {}; matched nothing this capture holds: {}.",
            media.errors,
            media.media,
            media.flows.len(),
            media.attributed,
            media.unattributed,
        );
        for f in media.flows.iter().take(5) {
            stderr_line!("  {}", f.hint);
        }
        if media.unkeyed > 0 || media.untracked_flows > 0 {
            stderr_line!(
                "ICMP: {} media error(s) quoted too little to name a flow and {} more reached no \
                 flow because the tracking cap was full.",
                media.unkeyed,
                media.untracked_flows
            );
        }
    }
}

/// The running capture batch mode consumes: what `bootstrap::launch` started
/// for it.
pub struct CaptureFeed {
    /// The capture thread's handle, joined at EOF.
    pub handle: capture::CaptureHandle,
    /// Receiving side of the packet channel.
    pub rx: capture::channel::PacketRx,
    /// The scanner-kill worker process `bootstrap::launch` started, when this
    /// run answers scanners.
    pub kill_worker: Option<ScannerKillHandle>,
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
/// * `feed` — the running capture this mode consumes.
/// * `batch` — pre-built matcher/filter/output/event-exec components.
/// * `policy` — split/autostop policy resolved from the CLI.
///
/// # Side effects
///
/// The multi-core arm spawns worker threads, joins the capture thread, and
/// prints reports; the single-threaded arm builds a `BatchRunner` (which
/// takes over the kill worker process and spawns the companion-server
/// thread) and drives its receive loop to completion. Either way this
/// function blocks until the batch run is over.
pub fn run(
    cli: Cli,
    config: &Config,
    capture_config: CaptureConfig,
    feed: CaptureFeed,
    batch: BatchProcessing,
    policy: CapturePolicy,
) {
    let CaptureFeed {
        handle,
        rx,
        kill_worker,
    } = feed;
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
        kill_worker,
        transmit_permit,
        // Taken before `rx` is moved into `run_loop`: the meter is a cheap
        // clonable view of the same queue, so the metrics thread can read the
        // depth while the receive loop owns the receiver.
        //
        // No longer gated on `metrics`. The scrape endpoint was the first
        // reader but not the only one — `runtime_stats` and `GET /v1/runtime`
        // report queue depth and backpressure too, and both published a
        // confident `0` for them while this stayed behind that feature.
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
    /// The run's export rules, resolved by the plan.
    vcon_rules: Vec<VconRule>,
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
    /// Recent raw frames, when `--mcp-evidence-ring` asked for them.
    ///
    /// The SAME object the MCP server reads, so a pointer resolves to the
    /// bytes the capture loop actually read rather than to a copy made for the
    /// surface that answers it.
    evidence_ring: Option<Arc<RwLock<crate::capture::evidence_ring::EvidenceRing>>>,
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
    /// Shutdown sender for the relay-statistics poll thread (ST4/C5); dropping
    /// it ends the poll loop. `None` unless `--relay-stats-interval` asked for a
    /// poll on a live run with a relay to ask.
    relay_poll_shutdown: Option<std::sync::mpsc::Sender<()>>,
    /// The relay-statistics poll thread, joined after the loop.
    relay_poll_thread: Option<std::thread::JoinHandle<()>>,
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
    /// What this run may do to other systems; told when the run stops, so
    /// the journal can record a clean stop.
    actions: crate::security::actions::Actions,
    /// Split/autostop policy resolved from the CLI.
    policy: CapturePolicy,
    /// Where `--evidence-out` publishes findings. Opened in `new`, so an
    /// unwritable path is an error before the first packet, not an hour in.
    evidence: Option<sec::evidence::EvidenceSink>,
}

/// The `--hep-send` forwarder, when one was asked for.
///
/// # Errors
///
/// An unusable HEP auth secret, or a sender that could not be created (exit
/// code 2).
#[cfg(feature = "hep")]
fn build_hep_sender(
    cli: &Cli,
    config: &Config,
    capture_meter: &crate::capture::channel::CaptureMeter,
) -> Result<Option<crate::capture::hep::HepSender>, crate::app::bootstrap::PlanError> {
    let Some(ref addr) = cli.hep_args.hep_send else {
        return Ok(None);
    };
    let capture_id = cli.hep_args.hep_id.unwrap_or(1);
    // Fatal, as `-L` makes the same refusal: logging it and sending
    // anyway forwarded the capture's signaling unauthenticated,
    // which is the silent disabling the resolver exists to prevent.
    let hep_auth = cli
        .resolve_hep_auth()
        .map_err(|e| crate::app::bootstrap::PlanError {
            exit_code: 2,
            message: format!("HEP auth: {e}"),
        })?;
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
    let (tls_ca, tls_extra_ca) = cli.hep_tls_trust(config);
    let sender = crate::capture::hep::HepSender::for_destination(
        &destination,
        crate::capture::hep::HepSenderOpts {
            capture_id,
            auth_key: hep_auth,
            auth_mode: cli.hep_args.hep_auth_mode,
            transport,
            tls_ca: tls_ca.as_deref(),
            tls_extra_ca: tls_extra_ca.as_deref(),
            queue_bytes: cli.hep_send_queue_bytes(config),
            timeout: cli.hep_send_timeout(config),
        },
    )
    // Fatal, as `--metrics` and `--api` are: `--hep-send` asks
    // for forwarding, and a run that cannot forward has not
    // done what it was asked. Logging this and carrying on
    // exited 0, so `sipnab ... --hep-send x && echo forwarded`
    // printed `forwarded` with nothing sent.
    .map_err(|e| crate::app::bootstrap::PlanError {
        exit_code: 2,
        message: format!("Failed to create HEP sender: {e:#}"),
    })?;
    tracing::info!(
        "HEP sender targeting {addr} over {transport} (capture id \
         {capture_id}{})",
        if authenticated { ", authenticated" } else { "" }
    );
    // On the meter every surface already holds, so
    // `runtime_stats`, `GET /v1/runtime`, the metrics
    // exposition and the end-of-run line read one set of
    // counters.
    capture_meter.attach_hep_export(sender.counters());
    Ok(Some(sender))
}

/// The dialog store a batch run writes, with the operator's limit, rotation,
/// tracking, correlation headers and leg-correlation window applied.
fn build_live_dialog_store(cli: &Cli, config: &Config) -> DialogStore {
    let mut ds = DialogStore::new(cli.dialog_limit(config), cli.rotate_enabled());
    // The wiring whose absence made the old --dialog-track a dead
    // flag: declared, parsed, and never handed to anything.
    ds.set_tracking(cli.dialog_args.dialog_track.unwrap_or_default());
    ds.with_xcid_headers(config.sip.xcid_headers.clone().unwrap_or_default())
        .with_leg_correlation_window_ms(cli.leg_correlation_window_ms(config))
}

/// Start the rtpengine reconciler (RE4) on its own thread, when this run has
/// one ready, and switch the store to recording the sockets it is offered.
///
/// Returns the sink the receive loop offers orphan sockets to and the
/// thread's handle; both `None` when there is no reconciler or it could not
/// start, in which case the store records nothing for it.
fn spawn_relay_reconciler(
    ready: Option<crate::app::bootstrap::ReadyReconciler>,
    stream_store: &Arc<RwLock<StreamStore>>,
) -> (
    Option<crate::relay::reconcile::OrphanSink>,
    Option<std::thread::JoinHandle<()>>,
) {
    let Some(ready) = ready else {
        return (None, None);
    };
    let (sink, orphan_rx) = crate::relay::reconcile::orphan_channel();
    stream_store.write().record_new_orphans(true);
    match crate::app::relay_reconciler::spawn(
        ready.reconciler,
        ready.permit,
        orphan_rx,
        Arc::clone(stream_store),
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

/// Build every security detector this run arms, keep the scanner-kill worker
/// only when it will be used, and build the alert engine (steps 17a-17b).
fn build_detection_engines(
    cli: &Cli,
    config: &Config,
    kill_worker: Option<ScannerKillHandle>,
    transmit_permit: Option<crate::security::transmit_guard::TransmitPermit>,
) -> DetectionEngines {
    // 17a. Initialize security detectors
    let kill_scanner_active = cli.scanner_detection(config);
    let kill_targets = parse_kill_targets(cli);
    // The kill worker is needed whenever we may emit a kill response —
    // detection-driven (--kill-scanner) OR targeted (-K) — and permitted
    // only when this run watches a live source. `transmit_permit` is None
    // for a capture file, and the worker's constructor takes one by value,
    // so an offline run cannot start a transmitting worker at all. The
    // operator was told why in `bootstrap::plan`; detection, alerting,
    // `--fail2ban` output and reporting all continue below.
    //
    // The worker rule is `bootstrap::kill_worker_wanted`, the one that
    // decided whether to start it, so detect-only keeps no worker here
    // either.
    let kill_worker_active =
        crate::app::bootstrap::kill_worker_wanted(cli, config) && transmit_permit.is_some();

    let scanner_detector = build_scanner_detector(cli, config, kill_scanner_active);

    // Built here, ahead of the warning below, because it is one of the
    // three producers that warning has to consult.
    let reg_flood_detector = cli
        .security_args
        .reg_flood
        .then(|| RegFloodDetector::with_policy(cli.reg_flood_policy(config)));

    warn_about_fail2ban_gaps(
        cli,
        config,
        fail2ban_would_emit_nothing(
            scanner_detector.is_some(),
            !kill_targets.is_empty(),
            reg_flood_detector.is_some(),
        ),
    );

    // 17a-2. The scanner-kill worker process (D16: process isolation).
    // Started by `bootstrap::launch` in the privileged window -- before
    // the chroot and the sandboxes, each of which can stop the exec it
    // needs -- from `bootstrap::kill_worker_wanted` and the same permit. The filter is the backstop for the two rules ever
    // disagreeing: a worker this run would not use is shut down here
    // rather than left holding send descriptors.
    let scanner_kill_handle: Option<ScannerKillHandle> = kill_worker.filter(|_| kill_worker_active);

    DetectionEngines {
        scanner: scanner_detector,
        fraud: build_fraud_detector(cli, config),
        digest: cli.security_args.digest_leak.then(DigestLeakDetector::new),
        reg_flood: reg_flood_detector,
        alerts: Arc::new(RwLock::new(build_configured_alert_engine(cli, config))),
        kill_handle: scanner_kill_handle,
        kill_response_code: cli.kill_response_code(config),
        kill_targets,
        detect_only: cli.kill_scanner_detect_only(config),
    }
}

/// Targeted-kill directives (-K). Already validated in Cli::validate();
/// reparse here and skip (loudly) any that somehow fail so a bad entry
/// can't take the whole run down mid-capture.
fn parse_kill_targets(cli: &Cli) -> Vec<sec::scanner_kill::KillTarget> {
    cli.security_args
        .kill_target
        .iter()
        .filter_map(|spec| match sec::scanner_kill::KillTarget::parse(spec) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!("Ignoring invalid --kill-target '{spec}': {e}");
                None
            }
        })
        .collect()
}

/// The scanner detector, when `--kill-scanner` (or its config key) arms it.
///
/// Deliberately NOT armed by `--fail2ban` alone. The obvious wiring —
/// "the flag feeds a banning tool, so give it a detector" — was measured
/// on a real carrier trunk and produces 7008 detections naming 180
/// peers, because the behavioral signature counts OPTIONS and the
/// busiest "scanners" are the carrier's own PBXes sending keepalives
/// (2713 from one peer in 11 seconds). That is the same mass-ban as the
/// blanket emission this replaced, only wearing the authority of a real
/// detection. Arm it once the signature can tell a keepalive from an
/// enumeration; until then `--fail2ban` warns rather than lying.
fn build_scanner_detector(
    cli: &Cli,
    config: &Config,
    kill_scanner_active: bool,
) -> Option<ScannerDetector> {
    if !kill_scanner_active {
        return None;
    }
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
}

/// Say at startup when `--fail2ban` will write less than an operator expects.
///
/// `emits_nothing` is [`fail2ban_would_emit_nothing`] for the detectors this
/// run armed.
fn warn_about_fail2ban_gaps(cli: &Cli, config: &Config, emits_nothing: bool) {
    // An operator who asked for fail2ban output and gets an empty file will
    // read it as "nothing attacked me", which is the most dangerous way for
    // a security tool to be silent. Say so once, at the start -- and only
    // when it is true: every producer of a jail line is consulted, not the
    // scanner detector alone, so `--reg-flood --fail2ban` is not told its
    // log will stay empty and then handed lines for it.
    if cli.output_args.fail2ban && emits_nothing {
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
        && (cli.hep_args.hep_listen.is_some() || cli.hep_parse(config))
    {
        tracing::warn!(
            "--fail2ban writes nothing for detections carried by HEP: the inner \
             addresses are the sender's claim, and a jail line would ban whatever \
             address it chose. Pass --hep-allow-kill to admit them once the feed is \
             authenticated (--hep-auth) and trusted."
        );
    }
}

/// What the `--alert` values asked for.
#[derive(Debug, Default)]
struct AlertSources {
    /// Every value that parsed as a rule.
    rules: Vec<AlertRule>,
    /// `syslog` was named as a channel.
    syslog: bool,
    /// `json` was named as a channel.
    json: bool,
    /// One sentence per value that could not be used, in the order given.
    warnings: Vec<String>,
}

/// Read the `--alert` values.
///
/// `--alert` is declared as a CHANNEL flag — "syslog", "json", "exec" —
/// and every documented example passes a channel name. It used to be fed
/// straight to `AlertRule::parse`, whose grammar is
/// `<name>:<threshold>/<window>`, so `--alert syslog` failed to parse,
/// warned, and enabled nothing. The docs taught it anyway, including a
/// line claiming it wrote to LOCAL0. For a security path that is the
/// worst shape of bug: the operator believes alerting is on.
///
/// A bare word is now a channel, as advertised. A value containing ':'
/// is still parsed as a rule, so anyone who discovered the old grammar
/// from the source keeps working.
///
/// # Arguments
///
/// * `specs` — the `--alert` values, or the configured ones.
/// * `exec_configured` — whether an `--alert-exec` command exists.
fn parse_alert_sources(specs: &[String], exec_configured: bool) -> AlertSources {
    let mut sources = AlertSources::default();
    for spec in specs {
        let value = spec.trim();
        if value.contains(':') {
            match AlertRule::parse(value) {
                Ok(r) => sources.rules.push(r),
                Err(e) => sources
                    .warnings
                    .push(format!("Skipping invalid alert rule '{value}': {e}")),
            }
            continue;
        }
        use crate::security::alerting::names_channel;
        if names_channel(value, "syslog") {
            sources.syslog = true;
        } else if names_channel(value, "json") {
            sources.json = true;
        } else if names_channel(value, "exec") {
            // The exec channel is the presence of --alert-exec; naming it
            // here is accepted so the documented triple all work, but it
            // cannot invent a command.
            if !exec_configured {
                sources.warnings.push(
                    "--alert exec given without --alert-exec <CMD>; no command to run".to_owned(),
                );
            }
        } else {
            sources.warnings.push(format!(
                "Unknown alert channel '{}'. Valid channels: syslog, json, exec. \
                 (A value containing ':' is treated as an alert rule.)",
                value.to_ascii_lowercase()
            ));
        }
    }
    sources
}

/// 17b. Initialize alert engine from --alert rules and --alert-exec,
///      falling back to config.security.alert and config.security.alert_exec
fn build_configured_alert_engine(cli: &Cli, config: &Config) -> AlertEngine {
    // One resolver for the flags and `[security]` together, the one the
    // startup precedence tests read.
    let settings = cli.alert_settings(config);
    let sources = parse_alert_sources(&settings.sources, settings.exec.is_some());
    for warning in &sources.warnings {
        tracing::warn!("{warning}");
    }
    let mut alert_engine = build_alert_engine(cli, config, sources.rules, settings.exec);
    if settings.syslog {
        alert_engine.set_syslog(true);
    }
    if settings.json {
        alert_engine.set_json_output(true);
    }
    alert_engine
}

/// The selection of tools, budgets and surfaces the companion servers start
/// with, resolved from the CLI and the configuration.
fn server_selection(
    cli: &Cli,
    config: &Config,
    evidence_ring: Option<Arc<RwLock<crate::capture::evidence_ring::EvidenceRing>>>,
    actions: &crate::security::actions::Actions,
    engines: &DetectionEngines,
) -> crate::app::servers::Selection {
    crate::app::servers::Selection {
        evidence_ring,
        mcp_tools: cli.mcp_tool_selection(config).unwrap_or_default(),
        mcp_output_schemas: cli.mcp_output_schemas(config),
        api_allowed_hosts: cli.api_allowed_hosts(config),
        api_tls: cli.api_tls_files(config),
        mcp_tls: cli.mcp_tls_files(config),
        metrics_tls: cli.metrics_tls_files(config),
        mcp_row_cap: cli.mcp_row_cap(config),
        mcp_body_cap: cli.mcp_body_cap(config),
        mcp_response_cap: cli.mcp_response_cap(config),
        mcp_wait_seconds: cli.mcp_wait_cap(config),
        mcp_sweep: cli.mcp_sweep_limits(config),
        mcp_sweep_jobs: cli.mcp_sweep_job_limits(config),
        api_row_cap: cli.api_row_cap(config),
        api_rate_limit_per_peer: cli.api_peer_rate_limit(config),
        max_tracked_peers: cli.tracked_peer_capacity(config),
        metrics_max_conn: cli.metrics_conn_cap(config),
        actions: actions.clone(),
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
        // Whether those scanners are also answered: `scanner` in the list
        // above says only that they are detected.
        scanner_response: engines.scanner_response(),
        pipeline_options: crate::app::server_pipeline_options(cli, config),
        alias_thresholds: cli.alias_thresholds(config),
        vcon_spools: crate::app::vcon_spool::spools(cli, config),
        vcon_fetch: config.vcon_fetch.clone(),
        live_audio: crate::app::bootstrap::live_audio_filters(cli, config),
    }
}

/// Open the `--evidence-out` sink, when one was asked for.
///
/// Fail before the first packet: an operator who mistyped the path
/// should learn now, not after an hour of capture and a lost finding.
///
/// # Errors
///
/// A target that cannot be opened (exit code 2).
fn open_evidence_sink(
    cli: &Cli,
) -> Result<Option<sec::evidence::EvidenceSink>, crate::app::bootstrap::PlanError> {
    let Some(target) = cli.security_args.evidence_out.as_deref() else {
        return Ok(None);
    };
    sec::evidence::EvidenceSink::open(target)
        .map(Some)
        .map_err(|e| crate::app::bootstrap::PlanError {
            exit_code: 2,
            message: format!("--evidence-out {target}: {e}"),
        })
}

/// TLS, SRTP and DTLS-SRTP decryption state for one run (steps 17c-17f).
#[cfg(feature = "tls")]
struct MediaDecryption {
    /// SIP-over-TLS decryptor (`--keylog` / `--tls-key` / embedded secrets).
    tls_decryptor: Option<TlsDecryptor>,
    /// Holds a TLS record split across TCP segments until it completes.
    tls_reassembler: crate::capture::tls::TlsRecordReassembler,
    /// SRTP media decryption context (`--srtp-keys` + learned SDES keys).
    srtp_context: Option<crate::rtp::srtp::SrtpContext>,
    /// DTLS-SRTP key extractor (`--dtls-keylog`).
    dtls_extractor: Option<crate::capture::dtls::DtlsSrtpExtractor>,
}

#[cfg(feature = "tls")]
impl MediaDecryption {
    /// Load every key source this run names.
    ///
    /// # Errors
    ///
    /// An unloadable `--tls-key`, `--srtp-keys` or `--dtls-keylog` file (exit
    /// code 1).
    fn load(
        cli: &Cli,
        config: &Config,
        preopened_keylog: Option<crate::capture::keylog_source::KeylogSource>,
        input_files: &[PathBuf],
    ) -> Result<Self, crate::app::bootstrap::PlanError> {
        let mut tls_decryptor = build_tls_decryptor(cli, preopened_keylog)?;

        // Same bound as the packet-level TCP/SIP reassembler
        // (`PacketProcessor::with_max_sessions`) — one held-partial entry
        // per concurrent TLS stream direction, same eviction policy.
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
        for path in input_files {
            feed_embedded_tls_secrets(path, &mut tls_decryptor);
        }

        Ok(Self {
            tls_decryptor,
            tls_reassembler,
            srtp_context: load_srtp_context(cli)?,
            dtls_extractor: load_dtls_extractor(cli)?,
        })
    }
}

/// 17c. Initialize TLS decryptor if --keylog and/or --tls-key is provided
///
/// # Errors
///
/// An unloadable `--keylog` or `--tls-key` file (exit code 1), refused the
/// way `--dtls-keylog` and `--srtp-keys` are.
#[cfg(feature = "tls")]
fn build_tls_decryptor(
    cli: &Cli,
    preopened: Option<crate::capture::keylog_source::KeylogSource>,
) -> Result<Option<TlsDecryptor>, crate::app::bootstrap::PlanError> {
    if !(cli.tls_args.keylog.is_some()
        || cli.tls_args.tls_key.is_some()
        || cli.tls_args.keylog_fd.is_some())
    {
        return Ok(None);
    }
    // A source opened in the privileged window supersedes the path:
    // it is already open, and for a FIFO the path must not be
    // opened a second time. `--keylog-fd` has no path at all.
    let keylog_path = if preopened.is_some() {
        None
    } else {
        cli.tls_args.keylog.as_deref().map(std::path::Path::new)
    };
    let crypto = crate::crypto::default_backend();
    let mut d = TlsDecryptor::new(keylog_path, crypto).map_err(|e| {
        // `{:#}`: the whole chain. `{}` printed only the outermost
        // context, "Loading keylog from <path>", which reads the same for
        // a typo, a permission problem and a file the producer has not
        // written yet. A run that asked for decryption and cannot have it
        // stops, as `--tls-key` and `--dtls-keylog` do: it used to go on
        // without a decryptor and exit 0.
        crate::app::bootstrap::PlanError {
            exit_code: 1,
            message: format!(
                "Failed to load --keylog {}: {e:#}",
                cli.tls_args.keylog.as_deref().unwrap_or_default()
            ),
        }
    })?;
    if let Some(records) = cli.tls_args.tls_lockon_window {
        d.set_lockon_window(records);
    }
    d.set_keys_may_still_arrive(keylog_may_grow(cli));
    if let Some(source) = preopened {
        adopt_keylog_stream(&mut d, source);
    }
    if d.keylog_entry_count() > 0 {
        tracing::info!(
            "sipnab: TLS decryption active (keylog loaded). \
                         Decrypted traffic visible in output."
        );
    }
    // Load the RSA private key for TLS 1.2 RSA-key-exchange decryption.
    if let Some(ref keyfile) = cli.tls_args.tls_key {
        load_tls_rsa_key(&mut d, keyfile)?;
    }
    // Published so a server can tell "no keys were supplied"
    // from "keys were supplied and opened nothing". Both render
    // as `decrypted_records: 0`, and they are opposite findings
    // with opposite remedies.
    crate::capture::note_tls_decryptor_installed(
        d.keylog_entry_count(),
        d.report().sessions_with_keys,
    );
    Ok(Some(d))
}

/// Whether this run's keylog source can grow while it runs.
///
/// Only a source that can GROW mid-run makes the
/// late-decrypt hold worth paying for: a plain `--keylog`
/// file is read once and a record that fails against it now
/// fails against it forever.
#[cfg(feature = "tls")]
fn keylog_may_grow(cli: &Cli) -> bool {
    cli.tls_args.keylog_watch || cli.tls_args.keylog_fd.is_some()
}

/// Hand the decryptor a keylog stream opened in the privileged window, and
/// read what it already holds.
#[cfg(feature = "tls")]
fn adopt_keylog_stream(d: &mut TlsDecryptor, source: crate::capture::keylog_source::KeylogSource) {
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

/// Load `--tls-key` into the decryptor.
///
/// # Errors
///
/// A key file that cannot be loaded (exit code 1).
#[cfg(feature = "tls")]
fn load_tls_rsa_key(
    d: &mut TlsDecryptor,
    keyfile: &str,
) -> Result<(), crate::app::bootstrap::PlanError> {
    let k = crate::capture::rsa_key::RsaKey::from_pem_file(std::path::Path::new(keyfile)).map_err(
        |e| crate::app::bootstrap::PlanError {
            exit_code: 1,
            message: format!("Failed to load --tls-key {keyfile}: {e:#}"),
        },
    )?;
    d.set_rsa_key(k);
    tracing::info!(
        "sipnab: TLS decryption active (--tls-key loaded; \
                                 decrypts TLS 1.2 RSA-key-exchange handshakes only)."
    );
    Ok(())
}

/// Feed the TLS secrets embedded in one capture file into `decryptor`,
/// creating a decryptor when there was none and the file carries secrets.
#[cfg(feature = "tls")]
fn feed_embedded_tls_secrets(path: &std::path::Path, decryptor: &mut Option<TlsDecryptor>) {
    let shown = path.display();
    if let Some(dec) = decryptor.as_mut() {
        let added = crate::capture::decrypt::feed_embedded_secrets(path, dec);
        if added > 0 {
            tracing::info!("TLS decryption: +{added} embedded DSB secret(s) from {shown}");
        }
        return;
    }
    if let Some(d) = decryptor_from_embedded_secrets(path) {
        *decryptor = Some(d);
    }
}

/// A decryptor holding the secrets embedded in `path`, or `None` when the
/// file is not a pcapng, carries no secrets, or none of them loaded.
#[cfg(feature = "tls")]
fn decryptor_from_embedded_secrets(path: &std::path::Path) -> Option<TlsDecryptor> {
    let meta = crate::capture::pcapng_meta::read_pcapng_metadata(path).ok()?;
    if meta.tls_secrets.is_empty() {
        return None;
    }
    let mut d = TlsDecryptor::new(None, crate::crypto::default_backend()).ok()?;
    let added: usize = meta.tls_secrets.iter().map(|s| d.add_keylog_text(s)).sum();
    if added == 0 {
        return None;
    }
    tracing::info!(
        "TLS decryption active: {added} secret(s) from embedded DSB in {}",
        path.display()
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
    Some(d)
}

/// 17e. Initialize the SRTP decryption context from --srtp-keys (and, later,
/// SDES `a=crypto` lines fed in as SDP is parsed). Authenticated RTP payloads
/// are decrypted in place before stream/audio analysis.
///
/// # Errors
///
/// A key file that cannot be loaded (exit code 1).
#[cfg(feature = "tls")]
fn load_srtp_context(
    cli: &Cli,
) -> Result<Option<crate::rtp::srtp::SrtpContext>, crate::app::bootstrap::PlanError> {
    let Some(ref keyfile) = cli.tls_args.srtp_keys else {
        // No key file, but SDES keys may still arrive via SDP — start empty
        // and let `add_sdes` populate it as `a=crypto` lines are seen.
        return Ok(Some(crate::rtp::srtp::SrtpContext::new(
            Vec::new(),
            crate::crypto::default_backend(),
        )));
    };
    let ctx = crate::rtp::srtp::SrtpContext::from_key_file(
        std::path::Path::new(keyfile),
        crate::crypto::default_backend(),
    )
    .map_err(|e| crate::app::bootstrap::PlanError {
        exit_code: 1,
        message: format!("Failed to load --srtp-keys {keyfile}: {e:#}"),
    })?;
    tracing::info!(
        "SRTP decryption active: {} key(s) from {keyfile}",
        ctx.key_count()
    );
    // A WARNING, not only the info line above: a manual key
    // file is a testing and debugging aid, and a run at the
    // warn level (`-q`) must still say that hand-supplied
    // key material is in use.
    tracing::warn!("manual SRTP keys loaded from {keyfile} — use only in test environments");
    Ok(Some(ctx))
}

/// 17f. Initialize the DTLS-SRTP extractor from --dtls-keylog. It recovers
/// SRTP master keys from the DTLS handshake (RFC 5764 exporter) and feeds
/// them into the SRTP context as handshakes are observed.
///
/// # Errors
///
/// A keylog that cannot be loaded (exit code 1).
#[cfg(feature = "tls")]
fn load_dtls_extractor(
    cli: &Cli,
) -> Result<Option<crate::capture::dtls::DtlsSrtpExtractor>, crate::app::bootstrap::PlanError> {
    let Some(ref keylog) = cli.tls_args.dtls_keylog else {
        return Ok(None);
    };
    let ex = crate::capture::dtls::DtlsSrtpExtractor::from_keylog_file(
        std::path::Path::new(keylog),
        crate::crypto::default_backend(),
    )
    .map_err(|e| crate::app::bootstrap::PlanError {
        exit_code: 1,
        message: format!("Failed to load --dtls-keylog {keylog}: {e:#}"),
    })?;
    tracing::info!(
        "DTLS-SRTP active: {} keylog entr(ies) from {keylog}",
        ex.keylog_len()
    );
    Ok(Some(ex))
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
    /// * `kill_worker` — the scanner-kill worker process, started by
    ///   `bootstrap::launch` in the privileged window.
    /// * `capture_meter` — cheaply-clonable view of the packet queue's depth,
    ///   taken from the receiver in `run` because this is where the metrics
    ///   server is started. Threaded through rather than left `None`:
    ///   `sipnab_capture_queue_depth_packets` is written unconditionally, so
    ///   an absent meter does not omit the gauge, it publishes a hard `0` —
    ///   and headless is now the path that actually serves metrics.
    ///
    /// # Side effects
    ///
    /// Takes over the scanner-kill worker process `bootstrap::launch`
    /// started, when any kill feature is active; reads TLS keylog / RSA key / SRTP key / DTLS keylog files
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
        kill_worker: Option<ScannerKillHandle>,
        transmit_permit: Option<crate::security::transmit_guard::TransmitPermit>,
        capture_meter: crate::capture::channel::CaptureMeter,
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
        let vcon_rules = batch.vcon_rules;
        let output_opts = batch.output_opts;
        let event_exec = batch.event_exec;
        // 16. Output writer placeholder for -O — opened lazily on the first
        //     packet in run_loop, once the link type is known.
        let writer: Option<PcapWriter> = None;
        let use_pcapng = cli.capture_args.pcapng;
        let export_mode = cli.tls_args.pcap_export_mode;

        // 16a. Initialize HEP sender if --hep-send is set
        #[cfg(feature = "hep")]
        let hep_sender = build_hep_sender(&cli, config, &capture_meter)?;

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
        // The ring both halves share: the capture loop writes recent frames
        // into it and the MCP resolver reads them back. One object, so a
        // pointer resolves to the bytes that were read rather than to a copy
        // made for the surface that answers.
        //
        // `None` unless an operator asked. This is memory spent on a running
        // capture, and spending it silently is not a default anybody chose.
        let evidence_ring = cli.mcp_args.mcp_evidence_ring.map(|mib| {
            std::sync::Arc::new(parking_lot::RwLock::new(
                crate::capture::evidence_ring::EvidenceRing::with_capacity_bytes(
                    mib.saturating_mul(1024 * 1024),
                ),
            ))
        });

        let dialog_store: Arc<RwLock<DialogStore>> =
            Arc::new(RwLock::new(build_live_dialog_store(&cli, config)));
        let no_rtp = cli.no_rtp(config);
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
        #[cfg(any(feature = "api", feature = "mcp"))]
        let relay_query_permit = batch.relay.ready.as_ref().map(|r| r.permit);
        // The poller transmits on its own thread with its own client, exactly
        // like `query_relay`, so it needs only the `Copy` permit -- and it must
        // not ride the reconciler's cadence (there is none) or its transaction
        // budget (orphan attribution must not compete with a poll). Taken from
        // the SOURCE, like `transmit_permit`, not from the reconciler: that
        // exists only when the address parsed, so a live run with a malformed
        // address was refused as one that "reads a file".
        let relay_poll_permit = transmit_permit;
        let (relay_orphans, relay_thread) =
            spawn_relay_reconciler(batch.relay.ready.take(), &stream_store);

        // C5: poll the relay's statistics on the operator's interval, if one
        // was given. Its own thread, its own client, gated like every other
        // relay-stats form (a relay named and a permit in hand); nothing polls
        // otherwise.
        let (relay_poll_shutdown, relay_poll_thread) =
            spawn_relay_stats_poller(&cli, relay_poll_permit);

        let rtp_heuristic = rtp::heuristic::RtpHeuristic::new();

        // 17a-17b. Security detectors, the kill worker and the alert engine.
        let engines = build_detection_engines(&cli, config, kill_worker, transmit_permit);

        // 17c-17f. TLS, SRTP and DTLS-SRTP decryption state.
        #[cfg(feature = "tls")]
        let MediaDecryption {
            tls_decryptor,
            tls_reassembler,
            srtp_context,
            dtls_extractor,
        } = MediaDecryption::load(&cli, config, preopened_keylog, &input_files)?;

        // Actions, with their journal, before any server listens: a journal
        // that cannot be used refuses the run here.
        let actions = crate::app::servers::start_actions(&cli, config).map_err(|message| {
            crate::app::bootstrap::PlanError {
                exit_code: 2,
                message,
            }
        })?;

        // Start the companion servers (REST API + MCP) on one shared runtime
        // thread. They read the SAME stores the packet loop writes to — no
        // mirror, no second parse; MCP additionally reads the AlertEngine for
        // the security_findings tool.
        let servers = crate::app::servers::start_servers(
            &cli,
            &dialog_store,
            &stream_store,
            Some(&engines.alerts),
            server_selection(&cli, config, evidence_ring.clone(), &actions, &engines),
            // Captured above, before the reconciler moved to its own thread.
            // `None` here is what makes `query_relay` (and GET /v1/relay/...)
            // refuse: on a file-backed run no permit exists to capture.
            #[cfg(any(feature = "api", feature = "mcp"))]
            relay_query_permit,
            // The meter travels from `run`, where the receiver lives. Passing
            // `None` here would not omit `sipnab_capture_queue_depth_packets`
            // — that gauge is written unconditionally — it would publish a
            // confident `0` for the queue depth on every headless deployment,
            // which is the same defect this ticket is fixing, one layer down.
            Some(capture_meter),
        )
        .map_err(|e| crate::app::bootstrap::PlanError {
            exit_code: 2,
            message: e.to_string(),
        })?;

        let evidence = open_evidence_sink(&cli)?;
        Ok(Self {
            cli,
            config: config.clone(),
            matcher,
            filter_expr,
            vcon_rules,
            output_opts,
            event_exec,
            writer,
            input_files,
            use_pcapng,
            export_mode,
            #[cfg(feature = "hep")]
            hep_sender,
            processor,
            evidence_ring: evidence_ring.clone(),
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
            actions,
            policy,
            relay_orphans,
            relay_thread,
            relay_poll_shutdown,
            relay_poll_thread,
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
        mut self,
        capture_config: CaptureConfig,
        handle: capture::CaptureHandle,
        rx: capture::channel::PacketRx,
    ) {
        let mut lp = ReceiveLoop::new(&mut self);

        // Taken before `rx` is dropped at the end of the loop: the meter is
        // where a HEP listener hangs its sender roster, and `--hep-senders`
        // reads it once the capture has drained.
        let capture_meter = rx.meter();

        // 18. Main receive loop
        while self
            .receive_step(&mut lp, &capture_config, &rx)
            .is_continue()
        {}

        // Read once, here, before anything below can ask for a shutdown of its
        // own: a live run stopped by a signal (or by its MCP client going
        // away) writes no vCon at its end. See `VconRunEnd::Stopped`.
        #[cfg(feature = "vcon")]
        let live_vcon = lp.live_vcon.take();
        #[cfg(feature = "vcon")]
        let vcon_end = vcon_run_end(live_vcon.as_deref(), signals::shutdown_requested());
        #[cfg(feature = "vcon")]
        self.finish_live_rtp(&mut lp);
        #[cfg(not(feature = "vcon"))]
        let vcon_end = VconRunEnd::Whole;

        self.flush_run_output(&mut lp);

        // The capture is over, so nothing more can answer an open REGISTER:
        // settle what `--reg-flood` could not establish, file it for the
        // findings pages, and say it once.
        self.settle_reg_flood_gap();
        self.stop_workers();

        // 20. Wait for the capture thread to finish
        //     Drop rx first so the capture thread sees a disconnected channel
        drop(rx);
        // A capture thread that returned Err did NOT read its input to the end,
        // so every report below is drawn from a partial view. See
        // `capture_read_to_end`.
        if !capture_read_to_end(handle.thread.join()) {
            lp.capture_failed = true;
        }

        // 20a. The source is fully drained: flip the flag MCP's tail_dialogs
        //      reports as source_exhausted, so a polling client knows no more
        //      dialog updates will arrive.
        if let Some(ref servers) = self.servers
            && let Some(ref flag) = servers.source_exhausted
        {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        // 21. Post-capture output
        self.write_end_reports(lp.total_count, vcon_end);
        // A sweep that could not write a container it owed said so when
        // it happened; the exit status says it again for a script.
        #[cfg(feature = "vcon")]
        if live_vcon
            .as_ref()
            .is_some_and(|trackers| trackers.iter().any(LiveVconTracker::failed))
        {
            crate::capture::archive::release_run_and_exit(1);
        }

        self.report_hep_exports(&capture_meter);

        // 21b. --relay-compare <CALL-ID>: the relay's own per-call RTP count
        //      beside what sipnab measured (ST7 / C4). Here, not at startup,
        //      because sipnab's measured tally is only final once the capture
        //      has drained; the relay is asked once, now. `handle.source` is
        //      still readable after the thread join above (a partial move of
        //      `handle.thread`), and it, not `cli`, is what the transmit permit
        //      derives from -- the same source the capture actually opened.
        if let Some(call_id) = self.cli.rtp_args.relay_compare.as_deref() {
            let ss_guard = self.stream_store.read();
            crate::app::bootstrap::report_relay_comparison(
                &self.cli,
                &handle.source,
                call_id,
                &ss_guard,
            );
        }

        // 21z. --lint: run the RFC conformance linter over every dialog (#147).
        //
        // The linter shipped reachable only over MCP, which put the project's
        // most distinctive capability out of reach of the place it matters
        // most: a pipeline gating a proxy config change.
        let lint_gate_tripped = run_lint_stage(&self.cli, &self.config, &self.dialog_store.read());

        self.print_wireshark_filter();
        self.print_tshark_command();

        // Who the detectors accused, grouped. Computed ABOVE the `--quiet`
        // gate, and read by two consumers below: the summary, which `--quiet`
        // silences, and `--recommend-block`, which it must not. See
        // `accused_sources`.
        let accused = accused_sources(&self.engines);

        // 21c. `--recommend-block`: the accusation as a rule the operator can
        // run. sipnab RECOMMENDS -- this prints text and reaches no firewall.
        if let Some(dialect) = self.cli.security_args.recommend_block {
            print_block_recommendations(&accused, dialect);
        }

        // 22. Summary
        if !self.cli.mode_args.quiet {
            self.print_run_summary(&lp, &accused);
        }

        // If any companion server is running, keep the process alive so clients
        // can query the captured data.
        if let Some(servers) = self.servers.take() {
            serve_until_shutdown(&self.cli, &servers);
        }

        // A clean stop, journaled if no action is in flight; one that is
        // stays in doubt for the next start, and is not waited for.
        self.actions.stop(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        );

        if let Some(code) = run_exit_code(RunOutcome {
            output_failed: lp.output_failed,
            capture_failed: lp.capture_failed,
            run_failed: crate::output::run_integrity::run_failed(),
            lint_gate_tripped,
            query_gate: crate::app::queries::gate_exit_code(),
        }) {
            crate::capture::archive::release_run_and_exit(code);
        }
    }

    /// One pass of the receive loop: the stop checks, the periodic work, one
    /// receive, the packets it produced, and the limits. `Break` ends the
    /// loop.
    fn receive_step(
        &mut self,
        lp: &mut ReceiveLoop,
        capture_config: &CaptureConfig,
        rx: &capture::channel::PacketRx,
    ) -> std::ops::ControlFlow<()> {
        use std::ops::ControlFlow;
        if signals::shutdown_requested() {
            return ControlFlow::Break(());
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
        if mcp_stdio_client_gone(
            self.servers
                .as_ref()
                .and_then(|s| s.mcp_stdio_done.as_ref()),
        ) {
            tracing::info!("MCP client disconnected — shutting down");
            signals::request_shutdown();
            return ControlFlow::Break(());
        }

        self.sweep_if_due(lp);
        #[cfg(feature = "vcon")]
        self.fork_live_rtp_if_due(lp);
        #[cfg(feature = "tls")]
        self.poll_keylog_if_due(lp);

        let Some(parsed_packets) = self.receive(lp, rx)? else {
            return ControlFlow::Continue(());
        };
        self.process_packets(lp, &parsed_packets);

        // The decrypted export: write what has waited long enough.
        #[cfg(feature = "tls")]
        if let (Some(x), Some(w)) = (lp.decrypted_export.as_mut(), self.writer.as_mut())
            && !write_decrypted_frames(w, x.ready())
        {
            lp.output_failed = true;
        }

        if self.limit_reached(lp, capture_config) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }

    /// Periodic sweep of reassembly state and idle-dialog compaction
    /// (every 5 seconds of capture time, which is wall time only when
    /// live). Orphan status is not swept: it is derived from
    /// `associated_dialog` at every read — see
    /// [`crate::rtp::stream::RtpStream::orphaned`].
    fn sweep_if_due(&mut self, lp: &mut ReceiveLoop) {
        let Some(now) = lp.sweep_clock.take_due(SWEEP_INTERVAL) else {
            return;
        };
        self.processor.sweep();
        #[cfg(feature = "vcon")]
        let live_vcon = &mut lp.live_vcon;
        let compacted = sweep_dialog_store(&self.dialog_store, now.get(), |ds| {
            #[cfg(feature = "vcon")]
            if let Some(trackers) = live_vcon.as_mut() {
                let ss = self.stream_store.read();
                let gate = self.servers.as_ref().map(|s| s.persistence_gate.as_ref());
                let read = CaptureRead {
                    dialogs: ds,
                    streams: &ss,
                    frames_read: lp.total_count,
                };
                if self.vcon_rules.is_empty() {
                    if let Some(tracker) = trackers.first_mut() {
                        live_vcon_sweep(&self.cli, None, read, gate, tracker, now.get());
                    }
                } else {
                    live_rules_sweep(&self.cli, &self.vcon_rules, read, gate, trackers, now.get());
                }
            }
            #[cfg(not(feature = "vcon"))]
            let _ = ds;
        });
        // After the sweep, which held the stream store for reading: the calls
        // it wrote give their retained audio back.
        #[cfg(feature = "vcon")]
        if let Some(trackers) = lp.live_vcon.as_mut() {
            let mut streams = self.stream_store.write();
            let released = trackers
                .iter_mut()
                .map(|t| release_exported_audio(t, &mut streams))
                .fold(0u64, u64::saturating_add);
            drop(streams);
            if released > 0 {
                tracing::debug!(
                    "released {released} retained audio frame(s) of calls whose vCon was written"
                );
            }
        }
        if compacted.messages_evicted > 0 {
            tracing::debug!(
                "idle-dialog compaction: dropped {} messages from {} dialogs",
                compacted.messages_evicted,
                compacted.dialogs_compacted
            );
        }
        self.engines.sweep(lp.security_max_age);
    }

    /// `live_rtp`: send what the matching calls retained since the last look,
    /// every `live_rtp::POLL` of wall time.
    #[cfg(feature = "vcon")]
    fn fork_live_rtp_if_due(&mut self, lp: &mut ReceiveLoop) {
        let Some(fork) = lp.live_rtp.as_mut() else {
            return;
        };
        if fork.due() {
            self.live_rtp_pass(fork, false);
        }
    }

    /// One look of `fork` at the stores, and its datagrams sent.
    #[cfg(feature = "vcon")]
    fn live_rtp_pass(&self, fork: &mut crate::output::live_rtp::Forwarder, input_ended: bool) {
        let out = {
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            fork.pass(
                &ds,
                &ss,
                self.cli.output_args.content_deny_header.as_deref(),
                input_ended,
            )
        };
        fork.send(&out);
    }

    /// The end of the run for `live_rtp`: on a stop request, every call's
    /// stop at once with nothing more of its audio; otherwise what is still
    /// queued, paced, and then each call's stop.
    #[cfg(feature = "vcon")]
    fn finish_live_rtp(&self, lp: &mut ReceiveLoop) {
        let Some(mut fork) = lp.live_rtp.take() else {
            return;
        };
        loop {
            if signals::shutdown_requested() {
                let out = fork.stop_all();
                fork.send(&out);
                break;
            }
            self.live_rtp_pass(&mut fork, true);
            if fork.is_idle() {
                break;
            }
            std::thread::sleep(crate::output::live_rtp::POLL);
        }
        if fork.unsent() > 0 {
            tracing::warn!(
                "live_rtp: {} datagram(s) could not be sent to their target",
                fork.unsent()
            );
        }
    }

    /// --keylog-watch: poll for new keys in the keylog source, on its
    /// own ~100ms wall-clock cadence (keylog_poll_clock above) rather
    /// than tied to the 5-second reassembly/dialog sweep. A fast SIP
    /// call (INVITE..ACK in well under 5s) can complete before that
    /// sweep ever runs again, so a key that arrived mid-call was not
    /// read until the call was already over — sipnab would log the
    /// session as "ready" and never decrypt a single message from it.
    ///
    /// `--keylog-fd` implies the watch. A descriptor handed over by a
    /// live producer has nothing to read at startup and everything
    /// to read later, so requiring a second flag to look at it would
    /// make the obvious invocation load no keys at all and say
    /// nothing — the failure this area has already been bitten by.
    #[cfg(feature = "tls")]
    fn poll_keylog_if_due(&mut self, lp: &mut ReceiveLoop) {
        let watching = self.cli.tls_args.keylog_watch || self.cli.tls_args.keylog_fd.is_some();
        if keylog_poll_due(watching, || lp.keylog_poll_clock.elapsed())
            && let Some(ref mut decryptor) = self.tls_decryptor
        {
            lp.keylog_poll_clock = std::time::Instant::now();
            if let Err(e) = decryptor.poll_keylog_file() {
                tracing::debug!("Keylog poll error: {e}");
            }
        }
    }

    /// Wait up to 100 ms for the next packet and turn it into parsed packets.
    ///
    /// `Continue(None)` when nothing arrived in time, `Continue(Some(..))`
    /// with the packet's parsed packets, and `Break` when the input has ended
    /// and its end has been processed, or the `-O` output could not be
    /// written.
    fn receive(
        &mut self,
        lp: &mut ReceiveLoop,
        rx: &capture::channel::PacketRx,
    ) -> std::ops::ControlFlow<(), Option<capture::ParsedPackets>> {
        use std::ops::ControlFlow;
        // Use recv_timeout so we can check shutdown periodically. Flush
        // pending output first whenever the channel has gone idle, so a
        // quiet live capture never sits on buffered messages.
        if rx.is_empty() {
            lp.sink.flush();
        }
        match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(packet) => match self.ingest(lp, &packet) {
                ControlFlow::Continue(parsed) => ControlFlow::Continue(Some(parsed)),
                ControlFlow::Break(()) => ControlFlow::Break(()),
            },
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => ControlFlow::Continue(None),
            // The input ended. One more pass carries what only its end
            // could release -- a TCP message held behind a hole the capture
            // never filled -- through the same per-packet body below; the
            // pass after that leaves.
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) if !lp.input_ended => {
                lp.input_ended = true;
                ControlFlow::Continue(Some(self.finish_input()))
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => ControlFlow::Break(()),
        }
    }

    /// What only the end of the input can release.
    fn finish_input(&mut self) -> capture::ParsedPackets {
        // A WebSocket frame begun in a decrypted record and never
        // finished is counted, never dropped in silence.
        #[cfg(feature = "tls")]
        for e in self.tls_reassembler.finish_websocket() {
            crate::capture::record_undecodable(&e, crate::capture::FrameFacts::UNRECORDED);
        }
        self.processor.finish()
    }

    /// Record one captured packet: advance the clock, write it to `-O`, keep
    /// it in the evidence ring, and parse it.
    ///
    /// `Break` when the `-O` output could not be written.
    fn ingest(
        &mut self,
        lp: &mut ReceiveLoop,
        packet: &capture::Packet,
    ) -> std::ops::ControlFlow<(), capture::ParsedPackets> {
        // Offline, this packet's timestamp is what "now" means to the next
        // sweep. Recorded before any parse/filter step so that a capture of
        // traffic sipnab does not decode still advances the clock — the
        // alternative would stall compaction on exactly the captures whose
        // memory growth it exists to bound.
        lp.sweep_clock.observe(packet.timestamp);

        // Lazily initialize the writer on first packet (we need link_type)
        if self.writer.is_none()
            && let Some(ref output_path) = self.cli.capture_args.output
        {
            self.writer = Some(self.open_output_writer(&PathBuf::from(output_path), packet));
        }

        self.write_to_output(lp, packet)?;

        lp.total_count += 1;

        self.retain_evidence(packet);

        // Parse and reassemble the packet
        std::ops::ControlFlow::Continue(self.processor.process(packet))
    }

    /// Open the `-O` output file for a capture whose first packet is
    /// `packet`, with its preamble written. Exits the process (code 1) when
    /// the file cannot be opened.
    fn open_output_writer(
        &self,
        output_path: &std::path::Path,
        packet: &capture::Packet,
    ) -> PcapWriter {
        // Record the capture source as the pcapng interface name (SNB-0001):
        // the capture device for live, the input file for replay.
        let capture_source = self
            .cli
            .capture_args
            .device
            .as_deref()
            .or(self.cli.primary_input());
        // A decrypted export says so in its section comment.
        #[cfg(feature = "tls")]
        let section_note = (self.export_mode == PcapExportMode::Decrypted)
            .then(|| capture::decrypted_export::SECTION_NOTE.to_string());
        #[cfg(not(feature = "tls"))]
        let section_note: Option<String> = None;
        match PcapWriter::with_provenance(
            output_path,
            packet.link_type,
            crate::capture::PcapWriterOptions {
                max_file_bytes: self.policy.split_bytes,
                max_file_duration: self.policy.split_duration,
                pcapng: self.use_pcapng,
                export_mode: self.export_mode,
                interface: capture_source,
                provenance: section_note,
                create: crate::new_file::CreateMode::Replace,
            },
        )
        .map(|w| w.keep_last_splits(self.policy.split_keep))
        {
            Ok(mut w) => {
                self.write_output_preamble(&mut w);
                w
            }
            Err(e) => {
                tracing::error!(
                    "{}",
                    crate::capture::writer::describe_output_error(
                        &e,
                        crate::privilege::dropped_to()
                    )
                );
                crate::capture::archive::release_run_and_exit(1);
            }
        }
    }

    /// The blocks a new `-O` file carries before its first packet.
    fn write_output_preamble(&self, w: &mut PcapWriter) {
        // Write DSB with keylog content if mode requires it
        if let Some(ref keylog_path) = self.cli.tls_args.keylog
            && let Err(e) = w.maybe_write_keylog_dsb(std::path::Path::new(keylog_path))
        {
            tracing::warn!("Failed to write DSB: {e:#}");
        }
        // Embed a Name Resolution Block when name resolution is active
        // (SNB-0001): headless `--names`/`--resolve` should travel with
        // the capture, mirroring the TUI save path. Before packets.
        if !self.use_pcapng {
            return;
        }
        let (resolver, mode) = crate::app::build_resolver(&self.cli, &self.config);
        if mode != crate::names::NameMode::Off {
            let include_dns = mode == crate::names::NameMode::Dns;
            let entries = resolver.nrb_entries(include_dns);
            if let Err(e) = w.write_name_resolution_block(&entries) {
                tracing::warn!("Failed to write name resolution block: {e:#}");
            }
        }
    }

    /// Write to output pcap if configured. A decrypted export holds
    /// the packet instead, and writes it once its wait is over.
    ///
    /// `Break` when the write failed.
    fn write_to_output(
        &mut self,
        lp: &mut ReceiveLoop,
        packet: &capture::Packet,
    ) -> std::ops::ControlFlow<()> {
        #[cfg(feature = "tls")]
        let held = match lp.decrypted_export.as_mut() {
            Some(x) if self.writer.is_some() => {
                x.captured(packet);
                true
            }
            _ => false,
        };
        #[cfg(not(feature = "tls"))]
        let held = false;
        if !held
            && let Some(ref mut w) = self.writer
            && let Err(e) = w.write(packet)
        {
            log_packet_write_error(&e);
            // Failing to OPEN the output exits 1 a few lines above; failing
            // to WRITE it used to exit 0, so `sipnab -O out.pcap && process
            // out.pcap` proceeded on a truncated capture.
            lp.output_failed = true;
            return std::ops::ControlFlow::Break(());
        }
        std::ops::ControlFlow::Continue(())
    }

    /// Retain the raw frame when an operator asked for a window into
    /// live capture. Only for sources that cannot be re-read: a capture
    /// file can be seeked, so spending memory to hold its bytes buys
    /// nothing a second read would not give for free.
    fn retain_evidence(&self, packet: &capture::Packet) {
        if let Some(ring) = self.evidence_ring.as_ref()
            && let Some(origin) = packet.origin
            && !origin.verifiable
            && let Some(source) = packet.interface.as_ref()
            && let Some(source) = crate::capture::packet::intern_source(source)
        {
            ring.write()
                .insert(source, origin.ordinal, packet.data.clone());
        }
    }

    /// Run every parsed packet one capture produced through the pipeline.
    fn process_packets(&mut self, lp: &mut ReceiveLoop, parsed_packets: &capture::ParsedPackets) {
        for pp in parsed_packets {
            // --hep-parse: unwrap HEP-encapsulated packets, by the rule
            // every router applies. `None` is a HEP datagram whose
            // transport no rule names, already counted.
            let Some(hep_unwrapped) =
                crate::pipeline::apply_hep_parse(pp, self.cli.hep_parse(&self.config))
            else {
                continue;
            };
            let pp: &ParsedPacket = &hep_unwrapped;

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
            let effective_pps = self.decrypt_tls(lp, pp);

            #[cfg(not(feature = "tls"))]
            let effective_pps: SmallVec<[std::borrow::Cow<'_, ParsedPacket>; 1]> =
                smallvec::smallvec![std::borrow::Cow::Borrowed(pp)];

            for effective_pp in effective_pps.iter().map(|p| p.as_ref()) {
                self.process_effective_packet(lp, effective_pp);
            }
        }
    }

    /// The packets one parsed packet becomes once TLS decryption has seen
    /// it, with what was decrypted told to the decrypted export.
    #[cfg(feature = "tls")]
    fn decrypt_tls<'p>(
        &mut self,
        lp: &mut ReceiveLoop,
        pp: &'p ParsedPacket,
    ) -> SmallVec<[std::borrow::Cow<'p, ParsedPacket>; 1]> {
        let tls_yield = try_tls_decrypt(pp, &mut self.tls_decryptor, &mut self.tls_reassembler);
        if let Some(x) = lp.decrypted_export.as_mut() {
            for d in tls_yield.recovered.iter().chain(tls_yield.decrypted.iter()) {
                x.sip_decrypted(
                    std::net::SocketAddr::new(d.src_addr, d.src_port),
                    std::net::SocketAddr::new(d.dst_addr, d.dst_port),
                    d.timestamp,
                    &d.payload,
                    if d.transport == TransportProto::Wss {
                        capture::decrypted_export::Source::Wss
                    } else {
                        capture::decrypted_export::Source::Tls
                    },
                );
            }
        }
        packets_after_tls(pp, tls_yield)
    }

    /// Classify one packet under both store locks, then perform what it
    /// queued with the locks released.
    fn process_effective_packet(&mut self, lp: &mut ReceiveLoop, effective_pp: &ParsedPacket) {
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
            let batch_ctx = BatchContext {
                matcher: &self.matcher,
                filter_expr: &self.filter_expr,
                output_opts: &self.output_opts,
                cli: &self.cli,
                no_rtp: self.no_rtp,
                // --after / -A trailing context counter
                after_count: self.cli.output_args.after.unwrap_or(0),
                portrange: self.policy.portrange,
                telephone_events: self.cli.mode_args.telephone_event
                    || self.vcon_rules.iter().any(|r| r.additions.dtmf_events),
            };
            let mut ds_guard = self.dialog_store.write();
            let mut ss_guard = self.stream_store.write();
            let mut proc_state = ProcessingState {
                dialog_store: &mut ds_guard,
                stream_store: &mut ss_guard,
                rtp_heuristic: &mut self.rtp_heuristic,
                event_exec: &mut self.event_exec,
                #[cfg(feature = "tls")]
                srtp: self.srtp_context.as_mut(),
                #[cfg(feature = "tls")]
                dtls: self.dtls_extractor.as_mut(),
                #[cfg(feature = "tls")]
                export: lp.decrypted_export.as_mut(),
                group: lp.group_buf.as_mut(),
            };
            process_parsed_packet(
                effective_pp,
                &batch_ctx,
                &mut proc_state,
                &mut self.engines,
                &mut lp.counters,
                &mut lp.effects,
            );
            // RE4's second trigger, drained under the guard this
            // scope already holds. Offering happens BELOW, with
            // the guards gone: the reconciler takes this same lock
            // to apply what it learns, and nothing that waits on
            // another thread belongs in here.
            if self.relay_orphans.is_some() {
                lp.new_orphans = ss_guard.drain_new_orphan_sockets();
            }
        }

        // Hand off anything the packet just created that nothing
        // explains. `offer` never blocks -- a full queue drops and
        // counts rather than stalling the capture on a relay.
        if let Some(ref sink) = self.relay_orphans {
            for (address, port) in lp.new_orphans.drain(..) {
                sink.offer(address, port);
            }
        }

        // Both store guards have dropped. Replay what the packet
        // queued, in the order it was raised: output, then alert
        // findings, then the hook commands. Draining per packet —
        // rather than per batch, or at end of capture — is what keeps
        // ordering identical to emitting inline.
        lp.effects
            .drain(&mut lp.sink, &self.engines.alerts, &mut self.event_exec);

        // --hep-send: SIP as protocol type 1, RTCP as type 5,
        // nothing else. What is stamped and what is skipped is
        // decided in `HepSender::forward_parsed`, where a test can
        // reach it. The closure names an RTCP report's call from the SDP
        // endpoints the stream store holds; the guard is a read, taken only
        // for RTCP, after the write guards above have dropped.
        #[cfg(feature = "hep")]
        if let Some(ref sender) = self.hep_sender
            && let Err(e) = sender.forward_parsed(effective_pp, |rtcp| {
                self.stream_store
                    .read()
                    .call_for_rtcp(
                        (rtcp.src_addr, rtcp.src_port),
                        (rtcp.dst_addr, rtcp.dst_port),
                        rtcp.timestamp,
                    )
                    .map(str::to_owned)
            })
        {
            tracing::debug!("HEP forward failed: {e:#}");
        }
    }

    /// Whether a `--count`, `--duration` or `--autostop` limit has been
    /// reached.
    fn limit_reached(&self, lp: &ReceiveLoop, capture_config: &CaptureConfig) -> bool {
        // Check --count limit
        if let Some(max_count) = capture_config.count
            && lp.total_count >= max_count
        {
            return true;
        }

        // Check --duration limit
        if let Some(duration) = capture_config.duration
            && lp.start.elapsed() >= duration
        {
            return true;
        }
        self.autostop_reached(lp)
    }

    /// Whether an `--autostop` duration or file-size limit has been reached,
    /// saying which when one has.
    fn autostop_reached(&self, lp: &ReceiveLoop) -> bool {
        // Check --autostop duration
        if let Some(autostop_dur) = self.policy.autostop_duration
            && lp.start.elapsed() >= autostop_dur
        {
            tracing::info!("Autostop: duration limit reached ({autostop_dur:?})");
            return true;
        }

        // Check --autostop filesize
        if let Some(max_bytes) = self.policy.autostop_filesize_bytes
            && let Some(ref w) = self.writer
            && w.bytes_written() >= max_bytes
        {
            tracing::info!(
                "Autostop: filesize limit reached ({} MiB)",
                max_bytes / crate::capture::writer::BYTES_PER_MIB
            );
            return true;
        }
        false
    }

    /// Everything the run still holds for stdout and `-O`, written out once
    /// the loop has ended.
    fn flush_run_output(&mut self, lp: &mut ReceiveLoop) {
        // A no-op today — every packet drains before the loop can break — and
        // kept because the cost of being wrong is silent data loss. A future
        // `break` added inside the per-packet body would otherwise discard that
        // packet's output, its findings and its hook commands with no error
        // anywhere, which is the failure this whole area exists to remove.
        lp.effects
            .drain(&mut lp.sink, &self.engines.alerts, &mut self.event_exec);

        // Replay any --group-by buffer before draining, so grouped output lands
        // ahead of reports exactly where the streamed output would have.
        if let Some(ref mut buf) = lp.group_buf {
            let machine_readable = self.cli.output_args.json
                || self.cli.output_args.json_pretty
                || self.cli.output_args.fail2ban;
            replay_group_buffer(buf, &mut lp.sink, machine_readable);
        }

        // Drain the per-message output sink before anything else writes to
        // stdout (reports, wireshark/tshark lines), preserving output order.
        lp.sink.flush();

        // A write that failed for any reason other than a closed pipe means the
        // emitted output is incomplete — same class as a truncated -O file, and
        // it must not exit 0 either.
        if let Some(e) = lp.sink.hard_error() {
            tracing::error!("Failed to write output: {e}");
            lp.output_failed = true;
        }

        // The decrypted export's held frames: a stop discards them (stop means
        // stop), the end of the input writes them. Then the counts, once.
        #[cfg(feature = "tls")]
        if let Some(x) = lp.decrypted_export.take()
            && !finish_decrypted_export(x, self.writer.as_mut())
        {
            lp.output_failed = true;
        }

        // Flush the output writer explicitly: BufWriter's Drop discards
        // flush errors, so without this an ENOSPC at end of capture would
        // truncate the file silently with exit code 0.
        if let Some(ref mut w) = self.writer
            && let Err(e) = w.finish()
        {
            tracing::error!("Output file may be incomplete: {e:#}");
            lp.output_failed = true;
        }
    }

    /// File and say what `--reg-flood` could not establish.
    ///
    /// A warning rather than a finding — it names no source and reaches no
    /// jail, because a REGISTER count with no outcome behind it is a volume,
    /// and the detector refuses to act on volume.
    fn settle_reg_flood_gap(&mut self) {
        if let Some(det) = self.engines.reg_flood.as_mut() {
            let gap = det.observation_gap(true);
            if let Some(gap) = &gap {
                tracing::warn!("{}", gap.detail);
            }
            self.engines
                .alerts
                .write()
                .set_observation_gap("reg_flood", gap);
        }
    }

    /// Stop the scanner-kill worker and the relay threads.
    fn stop_workers(&mut self) {
        // 19. Shut down scanner-kill worker (D16)
        if let Some(ref mut kill_handle) = self.engines.kill_handle {
            kill_handle.shutdown();
        }

        // 19a. Stop the rtpengine reconciler (RE4). Dropping the sink closes
        //      the hand-off queue, which is what ends its loop -- there is no
        //      flag to set and no timeout to wait out. Joining lets its
        //      summary line print, and it happens HERE rather than at the end
        //      of the function because the reporting below can exit the
        //      process outright.
        drop(self.relay_orphans.take());
        join_reporting_panic(
            self.relay_thread.take(),
            "the rtpengine reconciler thread panicked",
        );

        // The stats poller (C5) stops the same way: dropping its shutdown sender
        // closes the channel its loop waits on, so `recv_timeout` returns at
        // once rather than sleeping out the interval. Joined here, beside the
        // reconciler, because the reporting below can exit the process.
        drop(self.relay_poll_shutdown.take());
        join_reporting_panic(
            self.relay_poll_thread.take(),
            "the relay statistics poll thread panicked",
        );
    }

    /// `--report`, `--call-report`, `--export-vcon` and the other reports
    /// drawn from the final stores. Exits the process (code 1) when one that
    /// was asked for could not be produced.
    fn write_end_reports(&self, frames_read: u64, vcon_end: VconRunEnd<'_>) {
        let ds_guard = self.dialog_store.read();
        let ss_guard = self.stream_store.read();
        // The gate the REST door has been moving all run. `None` only
        // when no companion server started, which is the same run in
        // which nothing could have moved it.
        let gate = self.servers.as_ref().map(|s| s.persistence_gate.as_ref());
        if !generate_reports(
            &self.cli,
            &self.config,
            CaptureRead {
                dialogs: &ds_guard,
                streams: &ss_guard,
                frames_read,
            },
            self.filter_expr.as_ref(),
            &self.vcon_rules,
            gate,
            vcon_end,
        ) {
            crate::capture::archive::release_run_and_exit(1);
        }
    }

    /// What the HEP listener and the HEP exporter did, once the capture has
    /// drained so the counts are final.
    fn report_hep_exports(&self, capture_meter: &crate::capture::channel::CaptureMeter) {
        // 21-hep. --hep-senders: who fed the listener, who went silent, who
        //      it refused.
        if self.cli.hep_args.hep_senders
            && !print_hep_senders(capture_meter.hep_roster(), self.cli.output_args.json)
        {
            crate::capture::archive::release_run_and_exit(1);
        }

        // 21-hep-send. End the exporter's delivery thread. `finish` makes the
        //      one decision: a stop signal discards the queue at once (stop
        //      means stop -- no flush of captured data), and the end of the
        //      input delivers it, waiting a bounded time for an unreachable
        //      collector. Then what the exporter delivered, replayed, dropped
        //      and failed, said once. At `warn` when anything failed or was
        //      dropped, so a collector that went away is visible at the
        //      default level.
        #[cfg(feature = "hep")]
        if let Some(ref sender) = self.hep_sender {
            sender.finish();
        }
        if let (Some(counters), Some(dest)) = (
            capture_meter.hep_export(),
            self.cli.hep_args.hep_send.as_deref(),
        ) {
            let snap = counters.snapshot();
            let line = snap.summary_line(dest);
            if snap.failed() > 0 || snap.dropped_total() > 0 {
                tracing::warn!("{line}");
            } else {
                tracing::info!("{line}");
            }
        }
    }

    /// The Call-IDs of every tracked dialog, in store order.
    fn tracked_call_ids(&self) -> Vec<String> {
        self.dialog_store
            .read()
            .iter()
            .map(|d| d.call_id.clone())
            .collect()
    }

    /// 21a. --wireshark: print Wireshark display filter for all tracked dialogs
    fn print_wireshark_filter(&self) {
        if !self.cli.output_args.wireshark {
            return;
        }
        let call_ids = self.tracked_call_ids();
        if call_ids.is_empty() {
            stderr_line!("No SIP dialogs to generate Wireshark filter for.");
        } else {
            // Escape each Call-ID before it lands inside the display
            // filter's quoted string — a raw Call-ID could close the string
            // and OR in a catch-all that silently matches almost everything.
            outln!(
                "{}",
                crate::output::wireshark::call_id_display_filter(&call_ids)
            );
        }
    }

    /// 21b. --tshark-filter: print full tshark command for matched dialogs.
    /// The emitted `tshark -r <file>` must name a pcap that actually
    /// exists: the input file (`-I`), or the file the live capture was
    /// saved to (`-O`). A live capture with neither has no pcap for tshark
    /// to read, so emit a clear error instead of a bogus `capture.pcap`.
    fn print_tshark_command(&self) {
        let args = &self.cli.output_args;
        if !(args.tshark_filter.is_some() || (args.wireshark && self.cli.has_input())) {
            return;
        }
        let input_file =
            tshark_input_file(&self.input_files, self.cli.capture_args.output.as_deref());
        if let Some(ref tshark_expr) = args.tshark_filter {
            // User provided a custom tshark filter expression.
            match &input_file {
                // Shell-quote the file name and the filter: an operator
                // pastes this command, so a name or expression carrying a
                // single quote must not break out of the `-Y '…'` word.
                Ok(file) => outln!(
                    "{}",
                    crate::output::wireshark::generate_tshark_command(
                        None,
                        Some(file.as_str()),
                        None,
                        Some(tshark_expr.as_str()),
                    )
                ),
                Err(e) => tracing::error!("Cannot emit --tshark-filter command: {e}"),
            }
        } else if let Ok(file) = &input_file {
            // Generate tshark command from tracked dialogs (only when
            // --wireshark + -I; the outer guard ensures the input exists).
            let call_ids = self.tracked_call_ids();
            if !call_ids.is_empty() {
                // Escape the Call-IDs into the display filter, then
                // shell-quote the whole command so a crafted Call-ID neither
                // breaks the filter nor injects a shell command a copy-paste
                // would run.
                let filter = crate::output::wireshark::call_id_display_filter(&call_ids);
                outln!(
                    "{}",
                    crate::output::wireshark::generate_tshark_command(
                        None,
                        Some(file.as_str()),
                        None,
                        Some(&filter),
                    )
                );
            }
        }
    }

    /// The end-of-run summary on stderr (step 22): totals, accused sources,
    /// what was deleted, skipped and not decoded, and the decryption and
    /// no-SIP guidance.
    fn print_run_summary(
        &mut self,
        lp: &ReceiveLoop,
        accused: &[crate::security::sources::AccusedSource],
    ) {
        let total_count = lp.total_count;
        let stream_count = self.stream_store.read().len();
        tracing::info!(
            "sipnab: {total_count} packets captured, {} SIP messages, {} RTP packets across {stream_count} streams",
            lp.counters.sip_count,
            lp.counters.rtp_count,
        );

        // The accusation summary, over the grouping computed above.
        log_accused_sources(accused);

        log_detect_only_summary(&self.engines);

        // What `--split-keep` removed, counted beside what the run kept.
        // A run that deleted capture files says so in its closing line,
        // not only in the per-file log an operator may have scrolled past.
        let deleted = self.writer.as_ref().map_or(0, PcapWriter::splits_deleted);
        if deleted > 0 {
            tracing::info!(
                "sipnab: {deleted} older split file(s) deleted by --split-keep \
                 (each one written by this run)"
            );
        }

        report_port_skips();

        // What sipnab could not decode, beside the totals that hide it.
        // Read once so the notice and the no-SIP guidance below cannot
        // disagree about the same run.
        let undecodable = crate::capture::undecodable_report();
        if let Some(msg) = undecodable_summary(&undecodable, total_count) {
            stderr_line!("{msg}");
        }

        report_icmp_summary(&self.stream_store.read());
        report_relay_retries(&self.stream_store.read());
        report_impossible_rates(&self.stream_store.read());
        report_retention_losses(&self.dialog_store.read());
        report_capture_quality();
        report_llmnr_summary();

        // What TLS decryption achieved. Reported whether or not any SIP
        // was found, because a run that read nine records of ten and
        // printed the nine has said nothing about the tenth.
        #[cfg(feature = "tls")]
        if let Some(ref mut d) = self.tls_decryptor {
            report_late_tls_decrypts(d);
        }

        #[cfg(feature = "tls")]
        let tls_report = self
            .tls_decryptor
            .as_ref()
            .map(crate::capture::decrypt::TlsDecryptor::report)
            .unwrap_or_default();
        #[cfg(not(feature = "tls"))]
        let tls_report = crate::capture::TlsDecryptReport::default();
        for line in tls_decrypt_guidance(&tls_report, &mapped_tls_libraries()) {
            stderr_line!("{line}");
        }

        // Guidance when no SIP signaling was found — and, when the
        // capture did not decode, a refusal to state that absence as a
        // finding. See `no_sip_guidance` for why the choice of sentence
        // is the whole point.
        if lp.counters.sip_count == 0 {
            for line in no_sip_guidance(
                lp.counters.rtp_count,
                stream_count,
                report_tables_print(&self.cli),
                &undecodable,
                total_count,
                &tls_report,
            ) {
                stderr_line!("{line}");
            }
        }
    }
}

/// How often `--keylog-watch` reads the keylog source: real wall time via
/// `Instant`, not the sweep clock.
///
/// The sweep clock advances from packet timestamps, so on a quiet link it
/// never advances at all; the packet that matters is an INVITE arriving after
/// silence, and it needs the key already loaded before it arrives, not in
/// response to it. 100ms bounds the miss window to a tenth of the old 5s
/// sweep tie-in while keeping keylog reads off the per-packet hot path
/// (unbounded there, this is one syscall per ~100ms wall time regardless of
/// packet rate, not one per packet against a stated >=100K pps target).
#[cfg(feature = "tls")]
const KEYLOG_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Whether the keylog poll is due: a watch is set and
/// [`KEYLOG_POLL_INTERVAL`] has passed since the last poll. `since_last` reads
/// the clock, and is called only when a watch is set: the receive loop asks
/// once per packet, and a clock read per packet cost 7.6% of the cycles of a
/// single-core file run.
#[cfg(feature = "tls")]
fn keylog_poll_due(watching: bool, since_last: impl FnOnce() -> std::time::Duration) -> bool {
    watching && since_last() >= KEYLOG_POLL_INTERVAL
}

/// What the receive loop carries from one packet to the next, and what the
/// steps after it read.
struct ReceiveLoop {
    /// Reused across packets so the hand-off costs no allocation per packet.
    new_orphans: Vec<(std::net::IpAddr, u16)>,
    /// Set when writing the -O output fails. The open path exits 1; the
    /// write and final-flush paths only logged, so a capture truncated by
    /// ENOSPC reported success and any `sipnab -O out.pcap && next-step`
    /// pipeline ran on partial data.
    output_failed: bool,
    /// `--pcap-export-mode decrypted` (PCAPX-DEC): `-O` goes through a short
    /// reorder buffer that rewrites what sipnab decrypted as plaintext.
    #[cfg(feature = "tls")]
    decrypted_export: Option<capture::decrypted_export::DecryptedExport>,
    /// Set when the capture thread ends in an error or a panic, i.e. the
    /// input was not read to the end. Separate from `output_failed` so the
    /// two causes stay distinguishable in the code even though both land on
    /// the same exit status: one means "what we read was not written", the
    /// other "what we wrote was not all there was to read".
    capture_failed: bool,
    /// --group-by buffers per-message output and replays it grouped once the
    /// capture ends (see output::group for why it cannot stream, and for the
    /// caps that keep an attacker-keyed map bounded). None = stream as usual.
    group_buf: Option<output::group::GroupBuffer>,
    /// Wall time for a live device, the capture's own timeline for `-I`.
    /// See `SweepClock` for why the two cannot share one rule.
    sweep_clock: SweepClock,
    /// What the live vCon export has written so far. `None` unless this is
    /// a live run with `--export-vcon-when` or `--export-vcon`; see
    /// `Cli::exports_vcon_live`.
    #[cfg(feature = "vcon")]
    live_vcon: Option<Vec<LiveVconTracker>>,
    /// The live RTP fork of the rules with a `live_rtp` target.
    #[cfg(feature = "vcon")]
    live_rtp: Option<crate::output::live_rtp::Forwarder>,
    /// When `--keylog-watch` last read the keylog source; see
    /// [`KEYLOG_POLL_INTERVAL`].
    #[cfg(feature = "tls")]
    keylog_poll_clock: std::time::Instant,
    /// How much detector state each sweep keeps. Derived from the widest
    /// window this run's detectors were given rather than fixed, because
    /// the sweep is what ages that state out: a constant here caps every
    /// detector window at the constant, so declaring a fifteen-minute
    /// wangiri window would buy a two-minute one.
    security_max_age: std::time::Duration,
    /// Shared buffered stdout sink for every per-message emitter (JSON,
    /// text, fail2ban, hexdump). Flushed whenever the packet
    /// channel goes idle — live output stays real-time — and at end of
    /// capture; `--line-buffer` flushes after every message.
    sink: output::BatchSink<std::io::BufWriter<std::io::Stdout>>,
    /// Carries a packet's output, alerts and hook commands OUT of the
    /// section that holds both store write locks, so the syscalls they
    /// imply — `fork`/`exec` above all — happen with no lock held. Built
    /// once and reused, so its buffers are allocated once for the run.
    /// See `DeferredEffects`.
    effects: DeferredEffects,
    /// When the receive loop started, for `--duration` and `--autostop`.
    start: std::time::Instant,
    /// Frames read from the capture source.
    total_count: u64,
    /// Set once the capture channel closes, so the end-of-input release
    /// runs exactly once.
    input_ended: bool,
    /// SIP/RTP counts and emit-selection state.
    counters: PacketCounters,
}

impl ReceiveLoop {
    /// The loop's starting state for `runner`, taking its `--evidence-out`
    /// sink into the deferred effects.
    fn new(runner: &mut BatchRunner) -> Self {
        let mut effects = DeferredEffects::new();
        effects.evidence = runner.evidence.take();
        let cli = &runner.cli;
        Self {
            new_orphans: Vec::new(),
            output_failed: false,
            #[cfg(feature = "tls")]
            decrypted_export: (runner.export_mode == PcapExportMode::Decrypted
                && cli.capture_args.output.is_some())
            .then(|| {
                capture::decrypted_export::DecryptedExport::new(
                    capture::decrypted_export::reorder_window(),
                    capture::decrypted_export::REORDER_BYTE_CAP,
                )
            }),
            capture_failed: false,
            group_buf: cli
                .output_args
                .group_by
                .as_deref()
                .and_then(|f| output::group::GroupField::parse(f).ok())
                .map(|f| output::group::GroupBuffer::new(f, cli.group_caps(&runner.config))),
            sweep_clock: SweepClock::new(cli.has_input()),
            #[cfg(feature = "vcon")]
            live_vcon: start_live_vcon(cli, &runner.config, &runner.vcon_rules),
            #[cfg(feature = "vcon")]
            live_rtp: crate::output::live_rtp::Forwarder::new(&runner.vcon_rules),
            #[cfg(feature = "tls")]
            keylog_poll_clock: std::time::Instant::now(),
            security_max_age: cli.security_sweep_max_age(&runner.config),
            sink: output::BatchSink::stdout(cli.output_args.line_buffer),
            effects,
            start: std::time::Instant::now(),
            total_count: 0,
            input_ended: false,
            counters: PacketCounters {
                sip_count: 0,
                rtp_count: 0,
                prev_timestamp: None,
                trailing_remaining: 0,
                followed_dialogs: std::collections::HashSet::new(),
                dtmf_count: 0,
                dtmf_seen: rtp::dtmf::DtmfDedupe::default(),
            },
        }
    }
}

/// Log a failed `-O` packet write, with the reason the output could not be
/// written.
fn log_packet_write_error(e: &anyhow::Error) {
    tracing::error!(
        "Failed to write packet: {}",
        crate::capture::writer::describe_output_error(e, crate::privilege::dropped_to())
    );
}

/// Write decrypted-export frames to `-O`, oldest first, stopping at the
/// first that fails. Returns `false` when one failed.
#[cfg(feature = "tls")]
fn write_decrypted_frames(
    w: &mut PcapWriter,
    frames: Vec<capture::decrypted_export::ExportFrame>,
) -> bool {
    for frame in frames {
        if let Err(e) = capture::decrypted_export::write_frame(w, &frame) {
            log_packet_write_error(&e);
            return false;
        }
    }
    true
}

/// The decrypted export's held frames at the end of the run: a stop discards
/// them (stop means stop), the end of the input writes them. Then the
/// counts, once. Returns `false` when a held frame could not be written.
#[cfg(feature = "tls")]
fn finish_decrypted_export(
    mut x: capture::decrypted_export::DecryptedExport,
    writer: Option<&mut PcapWriter>,
) -> bool {
    let mut written = true;
    if signals::shutdown_requested() {
        x.discard();
    } else if let Some(w) = writer {
        written = write_decrypted_frames(w, x.finish());
    }
    stderr_line!("sipnab: {}", x.counts().summary_line());
    written
}

/// Write a `--group-by` buffer to the sink, one group at a time.
///
/// Headers are for humans; machine formats stay parseable, where the
/// grouping is the contiguity of the records themselves.
fn replay_group_buffer<W: std::io::Write>(
    buf: &mut output::group::GroupBuffer,
    sink: &mut output::BatchSink<W>,
    machine_readable: bool,
) {
    if buf.truncated() {
        tracing::warn!("{}", buf.truncation_note());
    }
    for (header, chunks) in buf.drain() {
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

/// Join a helper thread, warning with `panicked` if it panicked.
fn join_reporting_panic(thread: Option<std::thread::JoinHandle<()>>, panicked: &str) {
    if let Some(join) = thread
        && join.join().is_err()
    {
        tracing::warn!("{panicked}");
    }
}

/// Whether the capture thread read its input to the end, from what joining
/// it returned; a thread that did not is logged.
///
/// A capture thread that returned Err did NOT read its input to the end,
/// so every report is drawn from a partial view. Both failure arms
/// used to log and fall through to exit 0, which made the run
/// indistinguishable from a complete one to anything reading `$?`.
///
/// The concrete case that found this: a BPF filter that compiles against
/// the first file of a set and not against a later one. `capture_files`
/// returns Err naming the file, the warn! swallowed it, and the run
/// printed a whole-looking summary and exited 0 — while `--cores` on the
/// same input exited 1. Two answers to one question, and the reassuring
/// one was the default path.
///
/// A clean shutdown is not affected: `capture_live` returns Ok(()) when
/// the stop signal ends the loop and reserves Err for a failed open, a
/// rejected filter or a fatal read.
fn capture_read_to_end(joined: std::thread::Result<anyhow::Result<()>>) -> bool {
    match joined {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            tracing::error!("Capture did not complete: {e:#}");
            false
        }
        Err(_) => {
            tracing::error!("Capture thread panicked; the input was not read to the end");
            false
        }
    }
}

/// Who the detectors accused, grouped.
///
/// Every detector answers per MESSAGE, which is right for `--kill-scanner`
/// acting on one packet and wrong for the question asked after a capture:
/// which addresses were probing me, and how do I know. Nothing here
/// re-detects -- it groups findings the detectors already produced, so
/// there is one detector and one set of thresholds.
///
/// `established` is carried with the accusation rather than left in the
/// detector that already acts on it. A source that also completed a
/// registration or a call is one a block would disconnect, and learning
/// that after the block is too late.
///
/// Computed ABOVE the `--quiet` gate, and read by two consumers: the
/// summary, which `--quiet` silences, and `--recommend-block`, which it
/// must not. An operator who asked for a firewall rule and got nothing
/// because an unrelated flag suppressed the summary would have no way to
/// tell that from a capture with nothing in it.
fn accused_sources(engines: &DetectionEngines) -> Vec<crate::security::sources::AccusedSource> {
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
}

/// `--recommend-block`: one rule per accused source in `dialect`, or the
/// sentence saying there is nothing to block.
fn print_block_recommendations(
    accused: &[crate::security::sources::AccusedSource],
    dialect: crate::security::recommend::BlockDialect,
) {
    if accused.is_empty() {
        out!("{}", crate::security::recommend::nothing_to_recommend());
    } else {
        for a in accused {
            out!("{}", crate::security::recommend::recommend(a, dialect));
        }
    }
}

/// A detect-only run says so at the end too, where the scanner-kill totals
/// line would be on a run that answers scanners.
fn log_detect_only_summary(engines: &DetectionEngines) {
    if engines.scanner_response() == crate::security::findings::ScannerResponse::DetectOnly {
        tracing::info!("{}", crate::security::transmit_guard::DETECT_ONLY_SUMMARY);
    }
}

/// The accusation summary: how many sources the detections named, and each
/// one with its findings, its rules, and whether a block would disconnect it.
fn log_accused_sources(accused: &[crate::security::sources::AccusedSource]) {
    if accused.is_empty() {
        return;
    }
    tracing::info!(
        "sipnab: {} source(s) named by security detections",
        accused.len()
    );
    for a in accused {
        let rules = a.rules.iter().cloned().collect::<Vec<_>>().join(", ");
        let counter = match a.established {
            Some(true) => "  -- also completed a registration or call, so a block disconnects it",
            _ => "",
        };
        tracing::info!(
            "sipnab:   {} {} finding(s) [{rules}]{counter}",
            a.src_ip,
            a.findings
        );
    }
}

/// The busiest ports in a skip report, as `port (messages)`, at most five.
fn busiest_skipped_ports(ports: &[crate::pipeline::SkippedPort]) -> String {
    let top: Vec<String> = ports
        .iter()
        .take(5)
        .map(|p| format!("{} ({})", p.port, p.messages))
        .collect();
    top.join(", ")
}

/// What `--portrange` and the WebSocket port set discarded, beside the totals
/// they reduced.
fn report_port_skips() {
    // What `--portrange` discarded, beside the totals it reduced.
    // Without this the counts above read as complete.
    let skipped = crate::pipeline::portrange_skip_report();
    if skipped.messages > 0 {
        stderr_line!(
            "NOT ANALYZED: {} further SIP message(s) were seen on ports outside \
             --portrange and are in none of the totals above. Busiest: {}. \
             Re-run with --portrange 1-65535 to include them.",
            skipped.messages,
            busiest_skipped_ports(&skipped.ports)
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
        stderr_line!(
            "NOT ANALYZED: {} SIP-over-WebSocket message(s) arrived on ports \
             outside the WebSocket port set ({}) and are in none of the \
             totals above. Busiest: {}. Re-run with --ws-portrange covering \
             them (e.g. --ws-portrange 1-65535) to include them.",
            ws_skipped.messages,
            crate::capture::websocket::ws_ports_description(),
            busiest_skipped_ports(&ws_skipped.ports)
        );
    }
}

/// One last replay before the counters are read. A capture that
/// ends moments after its keys arrive -- a test call, a Ctrl-C --
/// would otherwise discard the held INVITE with nothing said: the
/// only other trigger is the next TLS packet, and there is not
/// going to be one. The recovered messages are too late to enter
/// the pipeline here, but they are NOT too late to be counted, and
/// a run that silently dropped what it was holding is exactly the
/// missing measurement this feature exists to remove.
#[cfg(feature = "tls")]
fn report_late_tls_decrypts(d: &mut TlsDecryptor) {
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

/// Keep the process alive while a companion server is running, so clients
/// can query the captured data. Poll the shutdown flag so SIGINT/SIGTERM
/// exits cleanly instead of blocking on a thread that never returns.
fn serve_until_shutdown(cli: &Cli, servers: &crate::app::servers::ServerHandles) {
    announce_servers(cli);
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

/// Say which companion servers are keeping the process alive.
fn announce_servers(cli: &Cli) {
    #[cfg(feature = "api")]
    if cli.listener_args.api.is_some() {
        tracing::info!("API server active — press Ctrl-C to stop");
    }
    #[cfg(feature = "mcp")]
    if cli.mcp_args.mcp {
        tracing::info!("MCP server active — press Ctrl-C to stop");
    }
    #[cfg(not(any(feature = "api", feature = "mcp")))]
    let _ = cli;
}

/// How a batch run went, as far as its exit status is concerned.
#[derive(Debug, Clone, Copy, Default)]
struct RunOutcome {
    /// Writing `-O` or the per-message output failed.
    output_failed: bool,
    /// The capture thread did not read its input to the end.
    capture_failed: bool,
    /// A file in the set was truncated or a `--plugin` would not load
    /// (`run_integrity::run_failed`).
    run_failed: bool,
    /// `--lint` found what its gate fails on.
    lint_gate_tripped: bool,
    /// The exit status a query gate (`--expect`) asked for, when not 0.
    query_gate: Option<i32>,
}

/// The exit code a batch run ends with, or `None` to exit 0.
///
/// Report a truncated output as a failure. This runs after the sink
/// flush, the writer's finish(), the kill-worker shutdown and the
/// capture-thread join, so nothing is skipped to get here — the exit
/// code is the only thing that changes.
///
/// Reports still print first: a partial capture is worth looking at,
/// it just must not be mistaken for a whole one by a script reading $?.
///
/// `run_integrity::run_failed()` is the FILE path's half of the same
/// rule the two flags implement for the live path. Reading a set
/// of files deliberately continues past a truncated member and returns
/// Ok, so `capture_failed` never sees it — and a truncated pcap or a
/// `--plugin` that would not load exited 0 with a whole-looking report.
/// 1, not a new code: docs/cli-reference.md already assigns 1 to
/// "capture error, I/O error", and both of these are exactly that. 3 is
/// reserved for the opposite situation — the tool worked and the
/// CAPTURE is non-conformant — so spending it here would erase the
/// distinction it exists to make.
///
/// 3, not 1, for the lint gate. A pipeline has to tell "sipnab broke" from
/// "the capture is non-conformant": the first means investigate the tool,
/// the second means fix the config that produced the traffic. Collapsing
/// them would make a working gate indistinguishable from a broken one, and
/// 1 and 2 already mean something else (#147).
///
/// The failure codes win over the lint gate, so a run that both failed to
/// write its output and found lint errors reports the failure — the
/// findings came from a partial read and are not trustworthy anyway.
fn run_exit_code(outcome: RunOutcome) -> Option<i32> {
    if outcome.output_failed || outcome.capture_failed || outcome.run_failed {
        Some(1)
    } else if outcome.lint_gate_tripped {
        Some(3)
    } else {
        outcome.query_gate
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
    let cli = ctx.cli;
    // Hexdump output (applies to all packets)
    if cli.output_args.hexdump && cli.mode_args.no_tui {
        write_hexdump(&mut effects.out, pp);
    }

    // Classify via the shared pipeline core (WS unwrap, SIP parse + SDP link
    // extraction, SDES/DTLS key learning, RTCP/RTP/heuristic detection), then
    // apply the action with the batch extras: counters, matcher/DSL filter,
    // output dispatch, security detectors, events, DTMF.
    let opts = crate::app::pipeline_options(
        cli,
        crate::app::PipelineDecisions {
            no_rtp: ctx.no_rtp,
            // The packet loop already applied `--hep-parse` before this packet
            // reached here; unwrapping SIP a second time would find no HEP.
            hep_parse: false,
            sip_portrange: Some(ctx.portrange),
        },
    );
    #[cfg(feature = "tls")]
    let mut decrypt = crate::pipeline::MediaDecrypt {
        srtp: state.srtp.as_deref_mut(),
        dtls: state.dtls.as_deref_mut(),
        export: None,
    };
    #[cfg(not(feature = "tls"))]
    let mut decrypt = crate::pipeline::MediaDecrypt::default();

    let action = crate::pipeline::classify_packet(pp, state.rtp_heuristic, &opts, &mut decrypt);
    let mut packet = PacketPass {
        ctx,
        state,
        engines,
        counters,
        effects,
    };
    match action {
        crate::pipeline::PacketAction::None => {}
        crate::pipeline::PacketAction::Sip { msg, sdp_links } => {
            packet.on_sip(pp, &msg, &sdp_links);
        }
        crate::pipeline::PacketAction::RelayControl(message) => {
            // A standalone media relay carries no SIP, so on that host this is
            // the ONLY thing that names a call. Without it every stream in the
            // capture reports orphaned.
            if message.carries_anything() {
                crate::pipeline::apply_relay_control(
                    packet.state.stream_store,
                    &message,
                    pp.input_origin,
                    pp.timestamp,
                );
            }
        }
        crate::pipeline::PacketAction::Rtcp(rtcp_packets) => {
            #[cfg(feature = "tls")]
            if let Some(x) = packet.state.export.as_deref_mut() {
                x.rtcp_seen(std::net::SocketAddr::new(pp.src_addr, pp.src_port));
            }
            packet
                .state
                .stream_store
                .process_rtcp(&rtcp_packets, pp.timestamp, pp.frame);
        }
        crate::pipeline::PacketAction::Rtp {
            hdr,
            decrypted_payload,
            via_heuristic,
        } => packet.on_rtp(pp, &hdr, decrypted_payload, via_heuristic),
    }
}

/// `--hexdump`: the packet's addressing line and its payload as hex.
#[inline]
fn write_hexdump(out: &mut DeferredOutput, pp: &ParsedPacket) {
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

/// Everything one classified packet is applied to: the run's configuration,
/// the locked stores, the detectors, the counters and the deferred effects.
///
/// Built once per packet from the references [`process_parsed_packet`] was
/// given, so the per-action methods share one set of borrows instead of each
/// taking six parameters.
struct PacketPass<'p, 'c, 's> {
    /// Immutable per-run configuration (matcher, filter, CLI, ports).
    ctx: &'p BatchContext<'c>,
    /// The locked stores, heuristic, event engine and media-decrypt state.
    state: &'p mut ProcessingState<'s>,
    /// Security detectors, alert engine, and kill-worker handle.
    engines: &'p mut DetectionEngines,
    /// SIP/RTP counts and emit-selection state.
    counters: &'p mut PacketCounters,
    /// Where the side effects go instead of happening.
    effects: &'p mut DeferredEffects,
}

impl PacketPass<'_, '_, '_> {
    /// A SIP message: dialog tracking, the matcher and the DSL filter,
    /// detectors, STIR/SHAKEN, `--calls-only`, and per-message output.
    #[inline]
    fn on_sip(
        &mut self,
        pp: &ParsedPacket,
        sip_msg: &sip::SipMessage,
        sdp_links: &[(std::net::IpAddr, u16, String, sip::sdp::SdpMedia)],
    ) {
        let cli = self.ctx.cli;
        self.counters.sip_count += 1;

        // Apply matcher (header-level filters)
        let matcher_pass = self.ctx.matcher.matches(sip_msg);

        // Track dialog regardless of filter (needed for filter DSL evaluation)
        if !cli.dialog_args.no_dialog {
            self.track_dialog(pp, sip_msg, sdp_links);
        }

        // Apply DSL filter (evaluated after dialog update)
        let filter_pass = dsl_filter_passes(
            self.ctx.filter_expr.as_ref(),
            sip_msg,
            self.state.dialog_store,
            self.state.stream_store,
        );

        self.run_detectors(pp, sip_msg);

        // STIR/SHAKEN extraction (I1)
        #[cfg(feature = "tls")]
        if cli.security_args.stir_shaken {
            log_stir_shaken(sip_msg);
        }

        // I5: --calls-only keeps every message of an INVITE dialog and
        // drops dialogs that are not calls. One rule, asked of the dialog.
        let calls_only_pass = !cli.mode_args.calls_only || {
            let dialog = sip_msg
                .call_id()
                .and_then(|id| self.state.dialog_store.get(id));
            crate::sip::matcher::calls_only_admits(
                dialog.as_ref().map(|d| &d.method),
                sip_msg.method.as_ref(),
            )
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
            &mut self.counters.followed_dialogs,
            &mut self.counters.trailing_remaining,
            self.ctx.after_count,
        );

        if emit && cli.mode_args.no_tui {
            dispatch_sip_output(
                sip_msg,
                self.ctx.output_opts,
                cli,
                self.counters.prev_timestamp,
                &mut self.effects.out,
                self.state.group.as_deref_mut(),
            );
        }

        self.counters.prev_timestamp = Some(sip_msg.timestamp);
    }

    /// Fold a SIP message into its dialog, tag it, queue a dialog event when
    /// its state changed, and link the SDP endpoints it carried.
    #[inline]
    fn track_dialog(
        &mut self,
        pp: &ParsedPacket,
        sip_msg: &sip::SipMessage,
        sdp_links: &[(std::net::IpAddr, u16, String, sip::sdp::SdpMedia)],
    ) {
        let cli = self.ctx.cli;
        let dialog_store = &mut *self.state.dialog_store;
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
            self.state.event_exec.queue_dialog_event(dialog);
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
        let provenance =
            crate::rtp::stream_store::SdpProvenance::observed(pp.input_origin, pp.timestamp);
        for (ip, port, call_id, media) in sdp_links {
            self.state
                .stream_store
                .link_to_dialog_with_sdp_from(*ip, *port, call_id, media, provenance);
        }
    }

    /// Security detection: every armed detector runs here, under the
    /// guards, and returns what should follow rather than doing it;
    /// the effects are applied right below. The fraud detector reads
    /// the dialog this message belongs to, looked up only when it is
    /// armed, so an unarmed run pays no hash lookup for it.
    #[inline]
    fn run_detectors(&mut self, pp: &ParsedPacket, sip_msg: &sip::SipMessage) {
        let cli = self.ctx.cli;
        let engines = &mut *self.engines;
        let dialog = if engines.fraud.is_some() {
            sip_msg
                .call_id()
                .and_then(|id| self.state.dialog_store.get(id))
        } else {
            None
        };
        let mut detectors = sec::detectors::Detectors {
            scanner: engines.scanner.as_mut(),
            fraud: engines.fraud.as_mut(),
            digest: engines.digest.as_mut(),
            reg_flood: engines.reg_flood.as_mut(),
            kill_targets: &engines.kill_targets,
        };
        let policy = sec::detectors::Policy {
            fail2ban: cli.output_args.fail2ban,
            hep_allow_kill: cli.security_args.hep_allow_kill,
            origin: pp.input_origin,
            kill_armed: engines.kill_handle.is_some(),
            kill_response_code: engines.kill_response_code,
        };
        // Split the borrow: the output buffer and the alert queue are disjoint
        // fields, and the emitters below interleave with the detectors.
        let DeferredEffects {
            out,
            alerts: pending_alerts,
            evidence: evidence_sink,
        } = &mut *self.effects;
        for effect in sec::detectors::run_detectors(&mut detectors, sip_msg, dialog, policy) {
            apply_detector_effect(
                effect,
                sip_msg.timestamp,
                out,
                pending_alerts,
                &engines.kill_handle,
                evidence_sink,
                policy,
            );
        }
    }

    /// An RTP packet: stream tracking, then DTMF and quality events for
    /// streams the signaling explains.
    #[inline]
    fn on_rtp(
        &mut self,
        pp: &ParsedPacket,
        rtp_hdr: &rtp::parser::RtpHeader,
        decrypted_payload: Option<bytes::Bytes>,
        via_heuristic: bool,
    ) {
        // Heuristically-discovered streams keep the pre-existing batch
        // contract: stream tracking only — no DTMF, no quality events.
        if via_heuristic {
            self.state
                .stream_store
                .process_rtp(pp, rtp_hdr, pp.timestamp);
            self.counters.rtp_count += 1;
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
        #[cfg(feature = "tls")]
        if let (Some(x), Some(plain)) = (self.state.export.as_deref_mut(), srtp_decrypted.as_ref())
        {
            x.srtp_decrypted(&plain.payload);
        }

        // Told apart, because the store keeps an SRTP stream's payload only
        // when it is plaintext.
        if srtp_decrypted.is_some() {
            self.state
                .stream_store
                .process_decrypted_rtp(rtp_pp, rtp_hdr, rtp_pp.timestamp);
        } else {
            self.state
                .stream_store
                .process_rtp(rtp_pp, rtp_hdr, rtp_pp.timestamp);
        }
        self.counters.rtp_count += 1;

        // DTMF extraction (I2): if --telephone-event is set and we have
        // the RTP payload after the header, attempt DTMF decode.
        if self.ctx.telephone_events && rtp_hdr.payload_offset < rtp_pp.payload.len() {
            self.extract_dtmf(pp, rtp_pp, rtp_hdr);
        }

        // Fire quality events on each RTP packet (rate-limited internally). Guard
        // on a configured command so the common no-`--on-quality` path skips the
        // StreamKey rebuild + second store lookup entirely (per-RTP-packet
        // constant-factor cut; fire_quality_event no-ops otherwise).
        if self.state.event_exec.quality_events_enabled() {
            let key = stream_key_of(pp, rtp_hdr);
            if let Some(stream) = self.state.stream_store.get_live(&key) {
                // Queued, not fired — same reason as the dialog event: the
                // MOS estimate reads the stream, the `fork`/`exec` does not.
                self.state.event_exec.queue_quality_event(
                    stream,
                    crate::rtp::quality::MosDelay::from_capture(self.state.stream_store),
                );
            }
        }
    }

    /// Decode one RFC 4733 telephone-event packet and log the digit, once per
    /// event.
    ///
    /// The telephone-event payload type and clock rate are negotiated in
    /// SDP (`a=rtpmap:<pt> telephone-event/<clock>`), any dynamic PT, and
    /// are read per packet from the rtpmap of the session that owns the
    /// stream ([`StreamStore::negotiated_rtpmap`]). Per packet, not from the
    /// stream's codec: a sender commonly puts the events on the SSRC that
    /// carries its audio, so the stream's codec is the audio codec. PT 101
    /// at 8000 Hz is read only when no SDP ties the stream to a session, or
    /// that session negotiated no telephone-event
    /// ([`rtp::dtmf::FALLBACK_TELEPHONE_EVENT`]).
    #[inline]
    fn extract_dtmf(
        &mut self,
        pp: &ParsedPacket,
        rtp_pp: &ParsedPacket,
        rtp_hdr: &rtp::parser::RtpHeader,
    ) {
        let rtp_payload = &rtp_pp.payload[rtp_hdr.payload_offset..];
        let key = stream_key_of(pp, rtp_hdr);
        let Some((expected_pt, clock_rate)) = rtp::dtmf::telephone_event_format(
            self.state.stream_store.negotiated_rtpmap(&key),
            rtp_hdr.payload_type,
        ) else {
            return;
        };
        if let Some(dtmf) = rtp::dtmf::extract_dtmf_with_clock(
            rtp_payload,
            rtp_hdr.payload_type,
            expected_pt,
            clock_rate,
            pp.timestamp,
        ) && !self.counters.dtmf_seen.is_duplicate(
            rtp_hdr.ssrc,
            rtp_hdr.timestamp,
            rtp_payload.first().copied().unwrap_or(0),
        ) {
            self.counters.dtmf_count += 1;
            log_dtmf_digit(&dtmf, rtp_hdr.ssrc, self.ctx.cli.mode_args.dtmf_cleartext);
            self.state.stream_store.record_key_press(&key, dtmf);
        }
    }
}

/// The stream an RTP packet belongs to: its SSRC and its socket pair.
///
/// Session 0 always, because a packet carries no session: look it up with
/// [`crate::rtp::stream_store::StreamStore::get_live`], which resolves it to
/// the stream of the call the packet belongs to.
#[inline]
fn stream_key_of(
    pp: &ParsedPacket,
    rtp_hdr: &rtp::parser::RtpHeader,
) -> crate::rtp::stream::StreamKey {
    crate::rtp::stream::StreamKey {
        ssrc: rtp_hdr.ssrc,
        src: std::net::SocketAddr::new(pp.src_addr, pp.src_port),
        dst: std::net::SocketAddr::new(pp.dst_addr, pp.dst_port),
        session: 0,
    }
}

/// Log one decoded DTMF digit.
fn log_dtmf_digit(dtmf: &rtp::dtmf::DtmfEvent, ssrc: u32, cleartext: bool) {
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
        ssrc
    );
    // Cleartext is an additional line, not a substitution, and
    // it sits at `debug` — one level below the masked line's
    // `info`. Two independent acts are therefore required to
    // put a PIN on disk: passing --dtmf-cleartext AND raising
    // SIPNAB_LOG to debug. Emitting it as a separate line also
    // means turning the flag on never *removes* the diagnostic
    // the default level already gave you.
    if cleartext {
        tracing::debug!(
            "DTMF cleartext digit='{}' duration={}ms ssrc=0x{:08x}",
            dtmf.digit,
            dtmf.duration_ms,
            ssrc
        );
    }
}

/// Whether a SIP message passes the `--filter` DSL, evaluated against the
/// dialog it belongs to after that dialog was updated. No filter passes
/// everything; a message with no Call-ID, or whose dialog is not tracked,
/// passes nothing.
#[inline]
fn dsl_filter_passes(
    filter_expr: Option<&FilterExpr>,
    sip_msg: &sip::SipMessage,
    dialog_store: &DialogStore,
    stream_store: &StreamStore,
) -> bool {
    let Some(expr) = filter_expr else {
        return true;
    };
    let Some(call_id) = sip_msg.call_id() else {
        return false;
    };
    let Some(dialog) = dialog_store.get(call_id) else {
        return false;
    };
    let dialog_streams: Vec<&crate::rtp::stream::RtpStream> =
        stream_store.streams_for(call_id).collect();
    expr.matches_dialog(
        dialog,
        &dialog_streams,
        crate::rtp::diagnosis::CaptureMedia::of_store(stream_store),
        crate::rtp::quality::MosDelay::from_capture(stream_store),
    )
}

/// Log every STIR/SHAKEN Identity header a message carries.
///
/// EVERY Identity header. [RFC 8224 section 4](https://www.rfc-editor.org/rfc/rfc8224.html#section-4) permits more than one,
/// and a diverted call under RFC 8946 carries a `ppt=shaken`
/// PASSporT plus a `ppt=div` one — reading only the first made
/// the second invisible on every surface.
#[cfg(feature = "tls")]
fn log_stir_shaken(sip_msg: &sip::SipMessage) {
    for result in sip_msg.stir_shaken_all() {
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
            // WARN, not debug. An Identity header that will not
            // parse is a forged or corrupted token, and at debug
            // it was indistinguishable from a message carrying
            // none — measured across four verbosity levels, and
            // none of them printed it.
            Err(e) => {
                tracing::warn!("STIR/SHAKEN: unparseable Identity header: {e}");
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
/// The SIP messages in one direction's decrypted TLS plaintext, each with the
/// transport it arrived over.
///
/// A connection that is a WebSocket session goes through that direction's
/// WebSocket stream, which joins a frame across TLS records, several frames
/// in one record, and a message across its fragments, and each SIP message
/// out of it is labeled WSS ([RFC 7118](https://www.rfc-editor.org/rfc/rfc7118.html)).
/// Anything else is framed as SIP over TLS, not sniffed: a sender may write
/// one SIP message as several records, and testing each record for SIP keeps
/// an INVITE's headers and drops its SDP body.
///
/// The session is recognized by its bytes, never by port: TLS already said
/// this is an encrypted session, and a WSS server listens wherever it was
/// configured to (the lab's OpenSIPS used 7443). OpenSIPS writes each frame's
/// header and payload as two TLS records, and reading each record as one
/// whole frame lost every message it sent (found reproducing issue #301).
///
/// # Side effects
///
/// Counts every WebSocket frame or message it cannot decode as NOT DECODED.
#[cfg(feature = "tls")]
fn sip_in_plaintext(
    src: std::net::SocketAddr,
    dst: std::net::SocketAddr,
    plaintext: &[u8],
    tls_reassembler: &mut tls::TlsRecordReassembler,
) -> Vec<(Vec<u8>, TransportProto)> {
    if let Some(ws) = tls_reassembler.websocket_plaintext(src, dst, plaintext) {
        for e in &ws.undecodable {
            crate::capture::record_undecodable(e, crate::capture::FrameFacts::UNRECORDED);
        }
        return ws
            .messages
            .into_iter()
            .filter(|m| sip::parser::starts_sip_message(m))
            .map(|m| (m, TransportProto::Wss))
            .collect();
    }
    tls_reassembler
        .frame_plaintext(src, dst, plaintext)
        .into_iter()
        .filter(|msg| sip::is_sip_message(msg))
        .map(|msg| (msg, TransportProto::Tls))
        .collect()
}

/// The SIP messages in TLS records held from before their keys existed and
/// opened now that the keys arrived, one wire packet each.
///
/// Each message keeps the timestamp and endpoints of the packet its record
/// actually arrived in, not of the replay: a recovered INVITE stamped now
/// would move post-dial delay and call duration by however long the keys
/// took. It is built from its record, never from the packet that triggered
/// the sweep: that packet's frame pointer, DSCP, origin and HEP metadata
/// describe it, not this message.
#[cfg(feature = "tls")]
fn recovered_packets(
    recovered: Vec<crate::capture::decrypt::RecoveredRecord>,
    tls_reassembler: &mut tls::TlsRecordReassembler,
) -> capture::ParsedPackets {
    let mut out = capture::ParsedPackets::new();
    for record in recovered {
        for (msg, transport) in
            sip_in_plaintext(record.src, record.dst, &record.plaintext, tls_reassembler)
        {
            out.push(ParsedPacket {
                frame: None,
                frame_bytes: None,
                timestamp: record.timestamp,
                src_addr: record.src.ip(),
                dst_addr: record.dst.ip(),
                src_port: record.src.port(),
                dst_port: record.dst.port(),
                transport,
                payload: msg.into(),
                ip_id: None,
                tcp_seq: None,
                tcp_flags: None,
                fragment_offset: None,
                more_fragments: false,
                ip_protocol: TransportProto::Tls.ip_proto_number(),
                dscp: None,
                // Held records are only ever wire TLS: HEP input never
                // enters decryption.
                input_origin: crate::capture::parse::InputOrigin::Wire,
                hep: None,
            });
        }
    }
    out
}

/// What TLS decryption made of one packet in hand.
#[cfg(feature = "tls")]
#[derive(Default)]
struct TlsYield {
    /// SIP messages from records held from before their keys existed, opened
    /// now that the keys arrived. They belong to earlier packets, not to the
    /// one in hand.
    recovered: capture::ParsedPackets,
    /// SIP messages decrypted out of the packet in hand.
    decrypted: capture::ParsedPackets,
}

/// The packets to analyze for one packet in hand, given what TLS decryption
/// made of it.
///
/// Key recovery adds to the packet in hand and never replaces it. The
/// recovery runs on whatever packet follows the keys, and when its messages
/// stood in for that packet, the packet was lost: a lab run under `-d any
/// --keylog <file> --keylog-watch -L` lost a HEP BYE that way (issue #301).
///
/// # Returns
///
/// The packets to analyze in capture-time order, borrowing `pp` when it
/// passes through unchanged.
#[cfg(feature = "tls")]
fn packets_after_tls(
    pp: &ParsedPacket,
    tls_yield: TlsYield,
) -> SmallVec<[std::borrow::Cow<'_, ParsedPacket>; 1]> {
    // Records held from before their keys existed come FIRST, because they
    // are older than the packet in hand. eCapture writes a session's secrets
    // only after the handshake, so the first application record -- the INVITE,
    // carrying the original SDP offer -- is on the wire before any keylog line
    // for it.
    let mut out: SmallVec<[std::borrow::Cow<'_, ParsedPacket>; 1]> = tls_yield
        .recovered
        .into_iter()
        .map(std::borrow::Cow::Owned)
        .collect();
    // The packet in hand: its decrypted SIP messages when it yielded any,
    // otherwise the packet itself, whether or not a recovery ran on it.
    if tls_yield.decrypted.is_empty() {
        out.push(std::borrow::Cow::Borrowed(pp));
    } else {
        out.extend(tls_yield.decrypted.into_iter().map(std::borrow::Cow::Owned));
    }
    // Stable, so messages sharing a timestamp keep the order they were framed
    // in. Recovered records are older than the packet in hand, so this
    // normally only orders the recovered ones among themselves.
    out.sort_by_key(|p| p.timestamp);
    out
}

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
) -> TlsYield {
    let Some(decryptor) = tls_decryptor.as_mut() else {
        return TlsYield::default();
    };

    // Records held from before their keys existed. They run on ANY packet,
    // TLS or not, because the packet that follows the keys is whatever the
    // capture happens to hold next. Framed here, before the packet in hand,
    // because they are older and share its per-direction WebSocket and SIP
    // framing state: a frame begun in a held record ends in a later one.
    let recovered = recovered_packets(decryptor.rewind_if_keys_changed(), tls_reassembler);
    let mut out = capture::ParsedPackets::new();

    // Non-TCP packets carry no TLS, but reaching this line still served a
    // purpose: the recovery above runs on ANY packet. Gating it behind the
    // TLS checks below meant a session whose keys arrived last could wait for
    // the next TLS-looking packet on that same connection -- which on a quiet
    // trunk may never come, and at end of capture never does.
    if pp.transport != TransportProto::Tcp {
        return TlsYield {
            recovered,
            decrypted: out,
        };
    }

    // A HEP message is plaintext a proxy already decrypted, whatever transport
    // its sender named, so it has nothing to give TLS decryption. It must also
    // take nothing: under `-d any --keylog <file> -L` the wire leg and the
    // tracer's copy of it share an address pair, and admitting the copy here
    // appended its SIP text to the wire's held partial record, which then
    // never decrypted (issue #301). `InputOrigin::Hep` marks both
    // `--hep-listen` and `--hep-parse` input.
    //
    // A message rebuilt from a stored vCon is plaintext for the same reason:
    // the container stored the decoded message.
    if matches!(
        pp.input_origin,
        crate::capture::parse::InputOrigin::Hep | crate::capture::parse::InputOrigin::Vcon
    ) {
        return TlsYield {
            recovered,
            decrypted: out,
        };
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
        return TlsYield {
            recovered,
            decrypted: out,
        };
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
            for (msg, transport) in sip_in_plaintext(src, dst, &plaintext, tls_reassembler) {
                // A synthetic ParsedPacket carrying the decrypted SIP, stamped
                // with the transport it arrived over (TLS or WSS).
                let mut decrypted_pp = pp.clone();
                decrypted_pp.payload = msg.into();
                decrypted_pp.transport = transport;
                out.push(decrypted_pp);
            }
        }
    }

    TlsYield {
        recovered,
        decrypted: out,
    }
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

/// Print `--hep-senders`: the listener's roster as the text table, or with
/// `--json` as one JSON object on its own line — the shape
/// `GET /v1/hep/senders` and the MCP `hep_senders` tool return.
///
/// # Arguments
///
/// * `roster` — the roster the listener hung on the capture meter, or `None`
///   when no listener ran, which prints the "no listener" answer rather than
///   an empty table.
/// * `json` — whether the run is in `--json` mode.
///
/// # Returns
///
/// `false` when stdout could not be written, which makes the output
/// incomplete.
fn print_hep_senders(roster: Option<&crate::capture::hep_roster::HepRoster>, json: bool) -> bool {
    let report = crate::capture::hep_roster::senders_report(roster, usize::MAX);
    let text = if json {
        match serde_json::to_string(&report) {
            Ok(line) => format!("{line}\n"),
            Err(e) => {
                tracing::error!("--hep-senders: the roster did not serialize: {e}");
                return false;
            }
        }
    } else {
        report.to_text()
    };
    write_stdout(&text)
}

/// Write `text` to stdout, returning `false` if it could not be delivered.
///
/// A `BrokenPipe` is the reader's choice (`| head`) and counts as success;
/// every other error means the output is incomplete. `print!` would panic on
/// both, which is how `--report` to a full disk exited 101 with a backtrace
/// while `-O` and `--json` reported the same condition as a clean failure.
pub(crate) fn write_stdout(text: &str) -> bool {
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

/// What the run has read so far: both stores and the frame count behind them.
///
/// The three travel together into every end-of-run and live export step, so
/// they are one value rather than three parameters a call site could pair up
/// wrongly (a store from one read beside the frame count of another).
#[derive(Clone, Copy)]
pub struct CaptureRead<'a> {
    /// The dialogs read.
    pub dialogs: &'a DialogStore,
    /// The RTP streams read.
    pub streams: &'a StreamStore,
    /// Frames read to build them.
    pub frames_read: u64,
}

/// Generate post-capture reports (`--report`, `--call-report`,
/// `--export-vcon`) from the final store contents. Returns `false` when a
/// requested report could not be produced — an unknown Call-ID at either
/// flag, or a vCon that could not reach `--vcon-out` — so the caller can exit
/// non-zero. Scripts must be able to trust the exit code.
///
/// # Arguments
///
/// * `config` — the loaded config, for the thresholds the one-shot queries
///   resolve (see `app::queries`).
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
    config: &Config,
    read: CaptureRead<'_>,
    filter: Option<&FilterExpr>,
    vcon_rules: &[VconRule],
    gate: Option<&crate::output::persistence::PersistenceGate>,
    vcon_end: VconRunEnd<'_>,
) -> bool {
    let CaptureRead {
        dialogs: dialog_store,
        streams: stream_store,
        frames_read,
    } = read;
    report_perf_stats(dialog_store, stream_store);
    // A window holding none of the capture's dialogs leaves every listing
    // below empty; say why on stderr, where it cannot corrupt a JSON stream.
    if let Some(notice) = time_window_notice(cli, dialog_store) {
        stderr_line!("{notice}");
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
    let plugins = load_report_plugins(cli);

    let reports = EndOfRunReports {
        cli,
        read,
        filter,
        #[cfg(feature = "plugins")]
        plugins: &plugins,
    };
    // In this order, and each one only if every one before it succeeded: a
    // report that could not be written stops the rest, so the exit status
    // speaks for the first failure.
    reports.dialog_table()
        && reports.json_dialogs()
        && reports.stun_tables()
        && reports.analysis()
        && reports.call_report()
        // --export-vcon <call-id>: one observed dialog as a vCon container.
        && export_vcon(
            cli,
            vcon_rules,
            dialog_store,
            stream_store,
            frames_read,
            gate,
            vcon_end,
        )
        // The one-shot query flags (`--talkers`, `--call-tree`, `--expect`
        // and the rest), answered from these same final stores through the
        // same compiled filter. See `app::queries`.
        && super::queries::render(&super::queries::QueryContext::new(
            cli,
            config,
            dialog_store,
            stream_store,
            filter,
        ))
}

/// What `--since`/`--until` found when the window itself holds no dialog of
/// the capture: the explicit empty answer, naming the window and the span the
/// capture's dialogs do cover, so an empty listing is not mistaken for a
/// capture with nothing in it or a filter that matched nothing.
///
/// `None` when no window was given, or when some dialog falls inside it (an
/// empty answer then comes from `--filter`, not from the window).
fn time_window_notice(cli: &Cli, dialogs: &DialogStore) -> Option<String> {
    let (since, until) = (cli.matching_args.since, cli.matching_args.until);
    if since.is_none() && until.is_none() {
        return None;
    }
    let mut span: Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> = None;
    for d in dialogs.iter() {
        if crate::cursor::in_time_window(d.created_at, since, until) {
            return None;
        }
        span = Some(match span {
            None => (d.created_at, d.created_at),
            Some((lo, hi)) => (lo.min(d.created_at), hi.max(d.created_at)),
        });
    }
    let instant =
        |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
    let window = format!(
        "[{}, {})",
        since.map_or_else(|| "unbounded".to_string(), instant),
        until.map_or_else(|| "unbounded".to_string(), instant),
    );
    Some(match span {
        Some((first, last)) => format!(
            "--since/--until: no dialog's first message falls in {window}; this \
             capture's dialogs begin between {} and {}",
            instant(first),
            instant(last),
        ),
        None => format!("--since/--until: no dialog in {window}; the capture holds no dialog"),
    })
}

/// SNB-0015 probe: set SIPNAB_PERF_STATS=1 to surface the per-run work that
/// scales with call count. `endpoint_link_scan_visits` is the cost that was
/// O(calls²) before the endpoint index; it now grows ~linearly with streams.
/// A value near streams² means the quadratic regression is back.
fn report_perf_stats(dialog_store: &DialogStore, stream_store: &StreamStore) {
    if std::env::var_os("SIPNAB_PERF_STATS").is_some() {
        stderr_line!(
            "[perf-stats] dialogs={} streams={} endpoint_link_scan_visits={} evict_shift_work={}",
            dialog_store.len(),
            stream_store.len(),
            stream_store.link_scan_iters(),
            stream_store.evict_shift_work(),
        );
    }
}

/// Load every `--plugin`, logging each one that loaded and each one that did
/// not, and record how many of the requested plugins failed.
#[cfg(feature = "plugins")]
fn load_report_plugins(cli: &Cli) -> Vec<crate::plugin::Plugin> {
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
    crate::output::run_integrity::record_plugins(crate::output::run_integrity::PluginLoadOutcome {
        requested: cli.output_args.plugin.len(),
        failed: cli.output_args.plugin.len().saturating_sub(plugins.len()),
    });
    plugins
}

/// Whether this run prints the `--report` dialog and stream tables.
///
/// One rule read in two places: [`EndOfRunReports::dialog_table`], which
/// prints the tables, and the run summary, whose no-SIP guidance must not
/// tell the operator to pass `--report` when the tables are already printed.
fn report_tables_print(cli: &Cli) -> bool {
    cli.output_args.report && cli.mode_args.no_tui
}

/// The vCon container section of `--report`: every stored vCon container
/// the run met, read or skipped, as rows and totals in the table format, or
/// as one JSON line under `--json` / `--json-pretty`. Empty when the run met
/// no container.
///
/// Not narrowed by `--filter`: a container is an input, like a capture file,
/// not a dialog.
///
/// # Arguments
///
/// * `cli` — the output flags that pick the form.
/// * `dialogs` — the store the read containers were rebuilt into.
fn vcon_containers_section(cli: &Cli, dialogs: &DialogStore) -> String {
    let containers = crate::output::dialog_report::vcon_containers_report(
        &crate::capture::vcon_input::read_report(),
        &crate::capture::vcon_input::skipped_report(),
        dialogs,
    );
    if cli.output_args.json || cli.output_args.json_pretty {
        crate::output::dialog_report::vcon_containers_json_line(
            &containers,
            cli.output_args.json_pretty,
        )
    } else {
        crate::output::dialog_report::render_vcon_containers(&containers, table_report_format(cli))
    }
}

/// What `--report` prints for a run whose `-I` resolved to no readable
/// file: the vCon container section, so a directory whose every container
/// was skipped is still reported with each reason. Empty when `--report`
/// prints no tables, or when `-I` met no vCon container.
///
/// The run still fails afterwards, with the exit code and message it has
/// without `--report`.
pub(crate) fn unread_input_report(cli: &Cli) -> String {
    if !report_tables_print(cli) {
        return String::new();
    }
    // Nothing was read, so no call was rebuilt: the store is empty.
    vcon_containers_section(cli, &DialogStore::new(0, false))
}

/// The table format `--markdown` picks for the human-readable reports.
pub(crate) fn table_report_format(cli: &Cli) -> output::ReportFormat {
    if cli.output_args.markdown {
        output::ReportFormat::Markdown
    } else {
        output::ReportFormat::Text
    }
}

/// The format `--call-report` renders in: JSON under `--json` or
/// `--json-pretty`, otherwise the table format.
fn call_report_format(cli: &Cli) -> ReportFormat {
    if cli.output_args.json || cli.output_args.json_pretty {
        ReportFormat::Json
    } else if cli.output_args.markdown {
        ReportFormat::Markdown
    } else {
        ReportFormat::Text
    }
}

/// Everything the end-of-run reports render from.
///
/// Each method writes one requested report and returns `false` only when that
/// report was asked for and could not be produced; a report that was not asked
/// for returns `true`.
struct EndOfRunReports<'a> {
    /// Which reports were asked for, and in what form.
    cli: &'a Cli,
    /// The final stores and the frame count behind them.
    read: CaptureRead<'a>,
    /// The compiled `--filter` expression, or `None` for no filter.
    filter: Option<&'a FilterExpr>,
    /// The `--plugin`s that loaded, applied to each `--json-dialogs` line.
    #[cfg(feature = "plugins")]
    plugins: &'a [crate::plugin::Plugin],
}

impl EndOfRunReports<'_> {
    /// --report: dialog summary table
    fn dialog_table(&self) -> bool {
        if !report_tables_print(self.cli) {
            return true;
        }
        // Filtered: the matching dialogs and the streams linked to them. With
        // no filter this is every dialog and every stream, orphans included —
        // an unfiltered report is unchanged.
        let selection =
            crate::sip::dsl::select_dialogs(self.filter, self.read.dialogs, self.read.streams);
        let dialogs: Vec<&crate::sip::dialog::SipDialog> =
            selection.dialogs.iter().map(|(d, _)| *d).collect();
        // `--markdown` was read, documented and IGNORED here: the output was
        // byte-identical with and without it while the help text said "Format
        // report output as Markdown" (#89).
        let mut report = output::print_dialog_report_as(
            &dialogs,
            &selection.streams,
            table_report_format(self.cli),
        );
        report.push_str(&vcon_containers_section(self.cli, self.read.dialogs));
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
        write_stdout(&report)
    }

    /// --json-dialogs: one NDJSON object per dialog
    fn json_dialogs(&self) -> bool {
        if !(self.cli.output_args.json_dialogs && self.cli.mode_args.no_tui) {
            return true;
        }
        let stream_store = self.read.streams;
        // Groups the streams by Call-ID once, where the loop below used to
        // rescan the whole stream store per dialog.
        let selection =
            crate::sip::dsl::select_dialogs(self.filter, self.read.dialogs, stream_store);
        let capture = crate::rtp::diagnosis::CaptureMedia::of_store(stream_store);
        // Resolved once for the whole run: every dialog's streams are scored on
        // the same evidence, and re-resolving per dialog would let two records
        // of one capture disagree about the path they measured. `from_capture`
        // for the reason the two other MOS sites in this function use it —
        // `generate_reports` is handed the stores and not the config, so the
        // operator's `--one-way-delay` is not reachable here and saying so is
        // better than pretending it was consulted.
        let delay = crate::rtp::quality::MosDelay::from_capture(stream_store);
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
            let line = output::dialog_to_ndjson(dialog, dialog_streams, &diagnosis, delay);

            #[cfg(feature = "plugins")]
            let line = apply_plugins(self.plugins, dialog, &line);

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
        write_stdout(&out)
    }

    /// --stun: the STUN/TURN transaction and allocation tables. Read from the
    /// process-global store rather than taken as an argument, for the reason
    /// the ICMP section of `print_dialog_report` is: a STUN transaction is
    /// neither a `SipDialog` nor an `RtpStream`, so it cannot arrive through
    /// either slice.
    ///
    /// Not narrowed by `--filter`: the DSL selects dialogs, and a NAT-discovery
    /// probe belongs to no dialog. Filtering it by a dialog filter would drop
    /// exactly the evidence that explains why those dialogs have no media.
    ///
    /// --json-stun: one NDJSON object per transaction, then one per allocation.
    fn stun_tables(&self) -> bool {
        let cli = self.cli;
        if cli.output_args.stun
            && cli.mode_args.no_tui
            && !write_stdout(&output::print_stun_report_as(
                &crate::stun::report(),
                table_report_format(cli),
            ))
        {
            return false;
        }
        if cli.output_args.json_stun && cli.mode_args.no_tui {
            return write_stdout(&output::stun_report_ndjson(&crate::stun::report()));
        }
        true
    }

    /// --analyze / --json-analyze / --yang-analyze: every problem in the
    /// capture, worst first.
    ///
    /// Computed once and rendered up to three times: asking for several forms
    /// must not be able to produce different answers, and `analyze` reads
    /// process-global stores whose contents a second call has no reason to
    /// change but no guarantee not to.
    ///
    /// `--filter` narrows the DIALOG selection, exactly as `--report` does, and
    /// narrows nothing else. See `crate::analysis::analyze` for why the
    /// capture-level findings are deliberately not filtered.
    fn analysis(&self) -> bool {
        let args = &self.cli.output_args;
        if !((args.analyze || args.json_analyze || args.yang_analyze) && self.cli.mode_args.no_tui)
        {
            return true;
        }
        let analysis = crate::analysis::analyze(
            self.read.dialogs,
            self.read.streams,
            self.filter,
            self.read.frames_read,
        );
        (!args.analyze
            || write_stdout(&output::print_analysis_report_as(
                &analysis,
                table_report_format(self.cli),
            )))
            && (!args.json_analyze || write_json_analysis(&analysis))
            && (!args.yang_analyze || write_yang_analysis(&analysis))
    }

    /// --call-report <call-id>: detailed single-call report
    fn call_report(&self) -> bool {
        let Some(ref call_id) = self.cli.output_args.call_report else {
            return true;
        };
        let stream_store = self.read.streams;
        let Some(dialog) = self.read.dialogs.get(call_id) else {
            // eprintln (not tracing) so the failure is visible even with
            // logging off — it decides the process exit code.
            stderr_line!("Call-ID '{call_id}' not found in tracked dialogs");
            return false;
        };
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
        let report = output::generate_call_report(
            dialog,
            &dialog_streams,
            &diagnosis,
            call_report_format(self.cli),
            crate::rtp::quality::MosDelay::from_capture(stream_store),
        );
        out!("{report}");
        true
    }
}

/// `--json-analyze`: the analysis as one JSON line. `false` only when the
/// line could not be written.
fn write_json_analysis(analysis: &crate::analysis::CaptureAnalysis) -> bool {
    match serde_json::to_string(analysis) {
        Ok(mut line) => {
            line.push('\n');
            write_stdout(&line)
        }
        // An analysis that will not serialize is a bug in the type, not
        // a reason to fail the whole run silently.
        Err(e) => {
            tracing::error!("analysis serialization failed: {e}");
            true
        }
    }
}

/// `--yang-analyze`: the same analysis, RFC 7951-encoded against
/// `sipnab-diagnosis`: a transform of the serialization just written, never a
/// second reading. `false` only when the line could not be written.
fn write_yang_analysis(analysis: &crate::analysis::CaptureAnalysis) -> bool {
    match crate::analysis::yang::to_rfc7951(analysis)
        .and_then(|doc| crate::analysis::yang::to_line(&doc))
    {
        Ok(line) => write_stdout(&line),
        Err(e) => {
            tracing::error!("RFC 7951 encoding failed: {e}");
            true
        }
    }
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
#[cfg(test)]
fn prepare_export_dir(cli: &Cli) -> Result<&std::path::Path, String> {
    prepare_target_dir(&VconTarget::from_flags(cli, None)?)
}

/// A rule's export directory, created if absent: the one place every export
/// path makes the directory it writes to.
///
/// # Errors
///
/// When the path cannot be made a directory; the message names the path and
/// the rule.
#[cfg(feature = "vcon")]
fn prepare_target_dir<'a>(target: &VconTarget<'a>) -> Result<&'a std::path::Path, String> {
    std::fs::create_dir_all(target.dir).map_err(|e| {
        target.say(&format!(
            "Could not create the vCon directory '{}': {e}. Nothing was exported.",
            target.dir.display()
        ))
    })?;
    Ok(target.dir)
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

/// How often the receive loop sweeps its stores, and how long a finished call
/// must stay quiet before a live run writes its vCon.
///
/// One constant for both on purpose. A settle period shorter than the sweep
/// would be unobservable (nothing looks between sweeps), and a longer one would
/// only delay every container by whole sweeps. With the two equal, a matching
/// call's container is written by the second sweep after its last message at
/// the latest: about ten seconds.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Which dialogs the live vCon export has already written, and at which
/// `updated_at`.
///
/// Keyed by Call-ID and holding the `updated_at` the container was built at,
/// so a dialog that changes after it was written (a `2xx` that raced a
/// `CANCEL`, a late `BYE`) is written again with what it became. Entries for
/// dialogs the store no longer holds are pruned every sweep, so the map is
/// bounded by the store it describes rather than by the length of the run.
///
/// The end-of-run export reads it too: a live run that ends on its own writes
/// only what the sweeps did not, because a forwarder that already took a
/// container out of the spool would otherwise get it twice.
#[derive(Debug, Default)]
pub struct LiveVconTracker {
    /// Call-ID to the `updated_at` its container was written at.
    written: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
    /// Call-ID to when its container was first written: the `created_at` a
    /// `live = true` rule, or a sealing rule, keeps on every rewrite.
    first_written: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
    /// Call-ID (the first leg's, for a call container) to how many sealed
    /// instances a sealing rule has written for it, which names the next
    /// instance's uuid under `sealed_updates = "new-uuid"`.
    sealed_instances: std::collections::HashMap<String, u32>,
    /// Set when a sweep could not write a container it owed, so the run can
    /// end non-zero instead of reporting an export that did not happen.
    failed: bool,
    /// Call-IDs written since their retained audio was last released, for
    /// [`release_exported_audio`].
    unreleased: Vec<String>,
    /// Calls written by one rule whose audio an inline-audio rule still owes,
    /// re-examined every sweep by [`live_rules_sweep`].
    #[cfg(feature = "vcon")]
    held: Vec<String>,
    /// Containers the live sweeps wrote over the whole run, rewrites included.
    /// Never pruned, unlike `written`, so the end-of-run line can report what
    /// the run wrote.
    containers_written: usize,
}

impl LiveVconTracker {
    /// The `updated_at` this dialog's container was written at, if one was.
    #[must_use]
    pub fn written_at(&self, call_id: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        self.written.get(call_id).copied()
    }

    /// Record that `call_id`'s container was written at `updated_at`.
    pub fn record(&mut self, call_id: &str, updated_at: chrono::DateTime<chrono::Utc>) {
        self.written.insert(call_id.to_owned(), updated_at);
        self.unreleased.push(call_id.to_owned());
    }

    /// Forget every dialog `still_held` says the store no longer holds.
    pub fn prune(&mut self, still_held: impl Fn(&str) -> bool) {
        self.written.retain(|call_id, _| still_held(call_id));
        self.first_written.retain(|call_id, _| still_held(call_id));
        self.sealed_instances
            .retain(|call_id, _| still_held(call_id));
    }

    /// How many dialogs are tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.written.len()
    }

    /// Whether nothing is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.written.is_empty()
    }

    /// How many containers the live sweeps wrote over the whole run.
    #[must_use]
    pub fn containers_written(&self) -> usize {
        self.containers_written
    }

    /// Whether a sweep failed to write a container it owed.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Log why a sweep could not write a container it owed, and remember
    /// that it failed so the run ends non-zero.
    #[cfg(feature = "vcon")]
    fn fail(&mut self, message: &str) {
        tracing::error!("{message}");
        self.failed = true;
    }
}

/// Release the retained audio of every call a live sweep wrote since the last
/// release, and return how many frames were released.
///
/// The written container carries the audio, so holding it until the stream
/// store evicts the stream would grow retention with the length of the run.
/// Each stream counts what it released, so a later export of the same call
/// (the call changed and is written again, or `export_audio` is asked for it)
/// says the audio was released and why, rather than reading as a call with
/// none.
#[cfg(feature = "vcon")]
fn release_exported_audio(tracker: &mut LiveVconTracker, streams: &mut StreamStore) -> u64 {
    std::mem::take(&mut tracker.unreleased)
        .iter()
        .map(|call_id| streams.release_audio_for(call_id))
        .fold(0u64, u64::saturating_add)
}

/// What the end-of-run vCon export owes, given how the run went.
///
/// A `-I` run, and any run without the live export, writes every selected
/// dialog at its end, as it always has. A live run has already written what
/// finished while it ran, so its end depends on WHY it ended.
#[derive(Debug, Clone, Copy)]
pub enum VconRunEnd<'a> {
    /// Write every selected dialog.
    Whole,
    /// A live run stopped by a signal (or by the MCP client going away, which
    /// takes the same path): write nothing. Stopping sipnab must leave no
    /// residual data behind, so a stop is never a flush.
    Stopped,
    /// A live run that ended on its own (`--duration`, autostop): write the
    /// selected dialogs the live sweeps have not already written at their
    /// current `updated_at`.
    AfterLive(&'a [LiveVconTracker]),
}

/// What the end-of-run export owes a run, from whether it exported live and
/// whether a signal stopped it.
#[cfg(feature = "vcon")]
fn vcon_run_end(live: Option<&[LiveVconTracker]>, stopped_by_signal: bool) -> VconRunEnd<'_> {
    match live {
        None => VconRunEnd::Whole,
        Some(_) if stopped_by_signal => VconRunEnd::Stopped,
        Some(tracker) => VconRunEnd::AfterLive(tracker),
    }
}

/// One sweep's dialog work, in the order it has to happen: `live_export`
/// first, then idle compaction.
///
/// Compaction trims an idle dialog's messages, so an export that ran after it
/// would write a container with the middle of the call missing. Kept in one
/// small function so that order is a fact a test can check, rather than two
/// adjacent lines in the receive loop that a later edit can swap.
fn sweep_dialog_store(
    dialog_store: &RwLock<DialogStore>,
    now: chrono::DateTime<chrono::Utc>,
    live_export: impl FnOnce(&DialogStore),
) -> crate::sip::dialog_store::CompactStats {
    live_export(&dialog_store.read());
    dialog_store.write().compact_idle(now)
}

/// Whether the live sweeps already wrote this dialog's container at its
/// current `updated_at`, so the end of the run does not owe it again.
#[cfg(feature = "vcon")]
fn written_live(live: Option<&LiveVconTracker>, dialog: &crate::sip::dialog::SipDialog) -> bool {
    live.is_some_and(|t| t.written_at(&dialog.call_id) == Some(dialog.updated_at))
}

/// How long a dialog must stay quiet before a live sweep writes it, as the
/// predicate takes it: one [`SWEEP_INTERVAL`].
#[cfg(feature = "vcon")]
fn live_settle() -> chrono::TimeDelta {
    chrono::TimeDelta::from_std(SWEEP_INTERVAL).unwrap_or(chrono::TimeDelta::MAX)
}

/// The name the rule `--export-vcon-when` with `--export-vcon-dir` make goes by.
pub const FLAG_RULE: &str = "--export-vcon-when";

/// What a rule's containers carry of a call's audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAudio {
    /// The audio the run retained, inline in a `recording` Dialog Object,
    /// within the inline budget.
    Inline,
    /// No audio: the container records that none was considered.
    Omit,
    /// The audio, written to a WAV beside the container and named by URL
    /// (`audio_url_base` plus the file name) with its hash.
    Url,
}

impl RuleAudio {
    /// A `[[vcon.rule]]` `audio` value: `inline`, `omit`, or unset, which is
    /// `omit` -- call audio is kept only on the operator's explicit word.
    ///
    /// # Errors
    ///
    /// Any other value, as the text to report.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value {
            None | Some("omit") => Ok(Self::Omit),
            Some("inline") => Ok(Self::Inline),
            Some("url") => Ok(Self::Url),
            Some(other) => Err(format!("audio = '{other}'; use 'inline', 'url' or 'omit'")),
        }
    }
}

/// The format of the audio a rule's containers carry: the `[[vcon.rule]]`
/// `audio_format` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleAudioFormat {
    /// RIFF/WAVE, 16-bit linear PCM, `audio/x-wav`. The default.
    #[default]
    Wav,
    /// Ogg Opus, `audio/ogg`: the Opus codec (RFC 6716) in an Ogg stream
    /// (RFC 7845), at [`crate::rtp::ogg_opus::BITRATE_PER_CHANNEL`]. Needs
    /// the `opus` Cargo feature.
    Opus,
}

impl RuleAudioFormat {
    /// Whether this build can write [`Self::Opus`].
    pub const OPUS_BUILT: bool = cfg!(feature = "opus");

    /// A `[[vcon.rule]]` `audio_format` value: `wav`, `opus`, or unset,
    /// which is `wav`. `opus_built` says whether this build has the `opus`
    /// feature ([`Self::OPUS_BUILT`]); a test passes either.
    ///
    /// # Errors
    ///
    /// Any other value, and `opus` when `opus_built` is false, as the text
    /// to report.
    pub fn parse(value: Option<&str>, opus_built: bool) -> Result<Self, String> {
        match value {
            None | Some("wav") => Ok(Self::Wav),
            Some("opus") if opus_built => Ok(Self::Opus),
            Some("opus") => Err(
                "audio_format = 'opus', and this sipnab was built without the \
                 `opus` feature, which writes Ogg Opus. The static musl builds do not have it. \
                 Use audio_format = 'wav', or a build with the feature"
                    .to_owned(),
            ),
            Some(other) => Err(format!("audio_format = '{other}'; use 'wav' or 'opus'")),
        }
    }

    /// The `mediatype` a recording in this format carries.
    #[cfg(feature = "vcon")]
    #[must_use]
    pub fn mediatype(self) -> &'static str {
        match self {
            Self::Wav => crate::output::vcon::RECORDING_MEDIATYPE,
            Self::Opus => crate::output::vcon::OGG_OPUS_MEDIATYPE,
        }
    }

    /// The file extension of a recording in this format.
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            Self::Wav => "wav",
            Self::Opus => "ogg",
        }
    }

    /// The format's name, as a refusal names it.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Wav => "WAV",
            Self::Opus => "Ogg Opus",
        }
    }

    /// `audio` in this format: `None` for WAV, which is `audio.wav` itself.
    ///
    /// # Errors
    ///
    /// When the encoder refuses the audio, as the text to report.
    pub fn encode(
        self,
        audio: &crate::rtp::audio_export::DialogAudio,
    ) -> Result<Option<Vec<u8>>, String> {
        match self {
            Self::Wav => Ok(None),
            #[cfg(feature = "opus")]
            Self::Opus => crate::rtp::ogg_opus::encode_dialog_audio(audio)
                .map(Some)
                .map_err(|e| format!("{e:#}")),
            #[cfg(not(feature = "opus"))]
            Self::Opus => {
                let _ = audio;
                Self::parse(Some("opus"), false).map(|_| None)
            }
        }
    }

    /// The recording `audio` carries in this format, given what
    /// [`Self::encode`] returned for it.
    #[cfg(feature = "vcon")]
    #[must_use]
    pub fn recording<'a>(
        self,
        audio: &'a crate::rtp::audio_export::DialogAudio,
        encoded: Option<&'a [u8]>,
    ) -> crate::output::vcon::EncodedRecording<'a> {
        match encoded {
            Some(bytes) => crate::output::vcon::EncodedRecording {
                bytes,
                mediatype: self.mediatype(),
                format: self.label(),
            },
            None => crate::output::vcon::EncodedRecording::wav(audio),
        }
    }
}

/// How a rule divides a call that crossed a B2BUA or a PBX, and so is several
/// dialogs, into containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleGrouping {
    /// One container per dialog, each naming the containers of the call's
    /// other legs and how strongly each is tied.
    Leg,
    /// One container per call, holding every leg, with the ties between the
    /// legs stated in it.
    Call,
}

impl RuleGrouping {
    /// A `[[vcon.rule]]` `grouping` value: `leg`, `call`, or unset, which is
    /// `leg` -- a timing tie can be wrong, and merging on one would put two
    /// unrelated calls in one container.
    ///
    /// # Errors
    ///
    /// Any other value, as the text to report.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value {
            None | Some("leg") => Ok(Self::Leg),
            Some("call") => Ok(Self::Call),
            Some(other) => Err(format!("grouping = '{other}'; use 'leg' or 'call'")),
        }
    }
}

/// What a rule that seals its containers (`encrypt_to`) writes when a call it
/// already wrote changes: the `[[vcon.rule]]` `sealed_updates` key.
///
/// [Section 4.1.9 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.9):
/// "A signed or encrypted vCon cannot be modified without invalidating it.
/// In these cases, to allow for adding of additional information a new vCon
/// instance version MUST be created." A rule that does not seal rewrites its
/// container in place, which the draft permits for the unsigned form, and
/// this setting does not apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SealedUpdates {
    /// Each later write is a new instance with its own uuid, naming the
    /// instance before it in `amended`. The earlier files stay. The default.
    #[default]
    NewUuid,
    /// Each later write replaces the file under the same uuid. Departs from
    /// section 4.1.9 and from section 4.1.2 ("The UUID value MUST be globally
    /// unique"); startup warns.
    SameUuid,
    /// Nothing is written until the call ends; then the container is sealed
    /// once.
    FinalOnly,
}

impl SealedUpdates {
    /// The three names, as configuration spells them.
    pub const NAMES: [&'static str; 3] = ["new-uuid", "same-uuid", "final-only"];

    /// A `[[vcon.rule]]` `sealed_updates` value: `new-uuid`, `same-uuid`,
    /// `final-only`, or unset, which is `new-uuid`.
    ///
    /// # Errors
    ///
    /// Any other value, as the text to report.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value {
            None | Some("new-uuid") => Ok(Self::NewUuid),
            Some("same-uuid") => Ok(Self::SameUuid),
            Some("final-only") => Ok(Self::FinalOnly),
            Some(other) => Err(format!(
                "sealed_updates = '{other}'; use '{}', '{}' or '{}'",
                Self::NAMES[0],
                Self::NAMES[1],
                Self::NAMES[2]
            )),
        }
    }
}

/// One export rule, resolved: a `[[vcon.rule]]`, or the rule
/// `--export-vcon-when` with `--export-vcon-dir` make.
#[derive(Debug, Clone)]
pub struct VconRule {
    /// The rule's name, used in the run's report.
    pub name: String,
    /// The compiled filter a call must match, `--since`/`--until` included.
    pub filter: FilterExpr,
    /// The directory the rule writes to.
    pub dir: std::path::PathBuf,
    /// What each container carries of the call's audio.
    pub audio: RuleAudio,
    /// The rule's inline-media budget in bytes; `None` uses the run's
    /// (`--vcon-max-inline-media`).
    pub max_inline: Option<usize>,
    /// The base URL a `Url` rule names its audio files under, without a
    /// trailing `/`.
    pub audio_url_base: Option<String>,
    /// The format of the audio each container carries.
    pub audio_format: RuleAudioFormat,
    /// One container per leg, or one per call.
    pub grouping: RuleGrouping,
    /// The `[[vcon.enrich]]` services this rule's calls go to, in order.
    pub enrich: Vec<std::sync::Arc<crate::app::vcon_enrich::Service>>,
    /// Whether the REST API serves this rule's calls' audio while they are in
    /// progress.
    pub live_audio: bool,
    /// Where each matching call's audio is sent as RTP while it is captured
    /// (`live_rtp`); `None` sends nothing.
    pub live_rtp: Option<crate::output::live_rtp::Target>,
    /// Whether a live capture writes each call as it starts and rewrites it
    /// as it changes.
    pub live: bool,
    /// What the rule signs and encrypts its containers with; `None` writes
    /// the unsigned form.
    pub sealing: Option<std::sync::Arc<crate::output::vcon_jose::Sealing>>,
    /// What a sealing rule writes when a call it already wrote changes.
    pub sealed_updates: SealedUpdates,
    /// What the rule adds to each container it writes.
    pub additions: RuleAdditions,
}

impl VconRule {
    /// The startup warning this rule's `sealed_updates` calls for, if any.
    #[must_use]
    pub fn sealed_updates_warning(&self) -> Option<String> {
        (self.sealing.is_some() && self.sealed_updates == SealedUpdates::SameUuid).then(|| {
            format!(
                "[[vcon.rule]] '{}' has sealed_updates = 'same-uuid': each change to a call \
                 rewrites its sealed container under the same uuid. This departs from \
                 draft-ietf-vcon-vcon-core-04 section 4.1.9 (\"a new vCon instance version \
                 MUST be created\") and section 4.1.2 (\"The UUID value MUST be globally \
                 unique\"); 'new-uuid' writes each change as a new instance instead",
                self.name
            )
        })
    }
}

/// What a rule adds to each container beyond what every export carries.
///
/// One value rather than one field per addition, so a new addition reaches
/// every place a rule is resolved and written without a new parameter.
#[derive(Debug, Clone, Default)]
pub struct RuleAdditions {
    /// `sip_messages`: the initial INVITE, its final response and their SDP
    /// as attachments ([`crate::output::vcon::add_sip_message_attachments`]).
    pub sip_messages: bool,
    /// `dtmf_events`: `keydown` and `keyup` in the signaling object's
    /// `party_history`, from INFO `application/dtmf-relay` and RFC 4733
    /// telephone events ([`crate::output::vcon::add_key_events`]).
    pub dtmf_events: bool,
    /// The `tags` attachment: set for a `[[vcon.rule]]`, which has a name,
    /// and `None` for the flag rule, which has none.
    pub tags: Option<RuleTags>,
    /// The headers that fill the CC extension's Dialog parameters
    /// (`crate::output::vcon::add_cc_fields`).
    pub cc: RuleCcHeaders,
}

/// The `[[vcon.rule]]` keys `campaign_header`, `skill_header` and
/// `interaction_id_header`: the SIP header that fills each contact-center
/// Dialog parameter.
#[derive(Debug, Clone, Default)]
pub struct RuleCcHeaders {
    /// The header whose value is `campaign`.
    pub campaign: Option<String>,
    /// The header whose value is `skill`.
    pub skill: Option<String>,
    /// The header whose value is `interaction_id`.
    pub interaction_id: Option<String>,
}

/// What a rule's `tags` attachment names
/// ([`crate::output::vcon::add_tags`]).
#[derive(Debug, Clone)]
pub struct RuleTags {
    /// The rule's name.
    pub rule: String,
    /// Each `@name` the rule's `when` references, in the order it first
    /// appears, with its own compiled expansion: the container is tagged
    /// with each one the call matches.
    pub filters: Vec<(String, FilterExpr)>,
}

/// How long a dialog that has not ended must have had no SIP and no RTP
/// before a live sweep writes it anyway.
///
/// A call whose BYE never reached sipnab (a phone that lost power, a capture
/// point that missed one packet) otherwise stays running and is never
/// written. A call on hold for longer than this is written early, with its
/// completeness note saying it had not ended, and written again under the
/// same name when the BYE arrives.
#[cfg(feature = "vcon")]
const LIVE_IDLE_WRITE: std::time::Duration = std::time::Duration::from_secs(120);

/// The live vCon export's tracker, when this run exports live, after saying
/// whatever [`live_compaction_warning`] has to say about the run's settings.
#[cfg(feature = "vcon")]
fn start_live_vcon(
    cli: &Cli,
    config: &crate::config::Config,
    rules: &[VconRule],
) -> Option<Vec<LiveVconTracker>> {
    // A `[[vcon.rule]]` makes a live run export as `--export-vcon-when` does.
    let live = cli.exports_vcon_live() || (!cli.has_input() && !rules.is_empty());
    if let Some(warning) = live_compaction_warning(config.limits.idle_compact_after_secs, live) {
        tracing::warn!("{warning}");
    }
    // One tracker per rule, and one for `--export-vcon <CALL-ID>`, which has
    // no rule.
    live.then(|| {
        (0..rules.len().max(1))
            .map(|_| LiveVconTracker::default())
            .collect()
    })
}

/// What a live vCon export says at startup when idle compaction can run
/// before the export writes a call: `[limits] idle_compact_after_secs`
/// shorter than [`LIVE_IDLE_WRITE`]. Compaction keeps the opening request and
/// the outcome but can drop the messages between them, and the container is
/// built from what is left. `None` when there is nothing to say.
#[cfg(feature = "vcon")]
fn live_compaction_warning(
    idle_compact_after_secs: Option<u64>,
    live_export: bool,
) -> Option<String> {
    let secs = idle_compact_after_secs?;
    if !live_export || secs >= LIVE_IDLE_WRITE.as_secs() {
        return None;
    }
    Some(format!(
        "[limits] idle_compact_after_secs is {secs}, shorter than the {} s a live vCon \
         export waits before it writes a call that has not ended, so idle compaction \
         can drop that call's middle messages before its container is written. Set \
         it to {} or more to keep them.",
        LIVE_IDLE_WRITE.as_secs(),
        LIVE_IDLE_WRITE.as_secs()
    ))
}

/// The two waits a live sweep applies, as the predicate takes them.
#[cfg(feature = "vcon")]
#[derive(Debug, Clone, Copy)]
struct LiveTiming {
    /// How long an ended dialog stays quiet before it is written: a
    /// retransmitted BYE or a late 200 may still arrive.
    settle: chrono::TimeDelta,
    /// How long a dialog that has not ended stays quiet, signaling and media
    /// both, before it is written anyway.
    idle: chrono::TimeDelta,
}

/// The waits the live export uses.
#[cfg(feature = "vcon")]
fn live_timing() -> LiveTiming {
    LiveTiming {
        settle: live_settle(),
        idle: chrono::TimeDelta::from_std(LIVE_IDLE_WRITE).unwrap_or(chrono::TimeDelta::MAX),
    }
}

/// Whether a live sweep writes this dialog's container now.
///
/// Pure, and every input an argument, so each condition can be driven on its
/// own. An ended dialog is written once it has been quiet for
/// `timing.settle`, measured from `updated_at`; a dialog that has not ended
/// is written once it has been quiet for `timing.idle`, measured from
/// `quiet_since`, the later of its last SIP message and its last RTP packet.
/// Either way it is not written again at the same `updated_at`.
#[cfg(feature = "vcon")]
fn live_vcon_due(
    state: &crate::sip::dialog::DialogState,
    quiet_since: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    timing: LiveTiming,
    already_exported_at: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    let quiet_long_enough = if state.is_final() {
        now - updated_at >= timing.settle
    } else {
        now - quiet_since >= timing.idle
    };
    quiet_long_enough && already_exported_at != Some(updated_at)
}

/// The later of a dialog's last SIP message and its streams' last packet.
#[cfg(feature = "vcon")]
fn quiet_since(
    dialog: &crate::sip::dialog::SipDialog,
    streams: &[&crate::rtp::stream::RtpStream],
) -> chrono::DateTime<chrono::Utc> {
    streams
        .iter()
        .map(|s| s.last_seen)
        .fold(dialog.updated_at, std::cmp::max)
}

/// The live vCon export for one sweep: write every dialog that matches
/// `--export-vcon-when` and [`live_vcon_due`] says is due (ended and quiet for
/// the settle period, or not ended and idle for [`LIVE_IDLE_WRITE`]), or, for
/// `--export-vcon <CALL-ID>`, that one call under the same rule (see
/// [`live_single_vcon_sweep`]).
///
/// Selection goes through [`vcon_selection`], the path the end-of-run export
/// takes, so the predicate and the deny header mean the same thing in both.
/// The capture analysis only runs when at least one dialog is due, because a
/// sweep with nothing to write should cost a selection and nothing more.
///
/// A failure is logged and remembered on the tracker rather than ending the
/// capture: the next sweep tries again, and the run exits non-zero at its end.
///
/// Returns how many containers this sweep wrote.
#[cfg(feature = "vcon")]
fn live_vcon_sweep(
    cli: &Cli,
    vcon_filter: Option<&crate::sip::dsl::FilterExpr>,
    read: CaptureRead<'_>,
    gate: Option<&crate::output::persistence::PersistenceGate>,
    tracker: &mut LiveVconTracker,
    now: chrono::DateTime<chrono::Utc>,
) -> usize {
    let CaptureRead {
        dialogs: dialog_store,
        streams: stream_store,
        frames_read,
    } = read;
    tracker.prune(|call_id| dialog_store.get(call_id).is_some());
    // The gate at write time decides, as it does at the end of a run.
    if gate.is_some_and(|g| !g.writes_permitted()) {
        return 0;
    }
    if let Some(call_id) = cli.output_args.export_vcon.as_deref() {
        return live_single_vcon_sweep(
            cli,
            call_id,
            dialog_store,
            stream_store,
            frames_read,
            tracker,
            now,
        );
    }
    let target = match VconTarget::from_flags(cli, vcon_filter) {
        Ok(t) => t,
        Err(message) => {
            tracker.fail(&message);
            return 0;
        }
    };
    live_target_sweep(
        cli,
        &target,
        CaptureRead {
            dialogs: dialog_store,
            streams: stream_store,
            frames_read,
        },
        gate,
        tracker,
        now,
    )
    .0
}

/// One rule's share of a live sweep: write every dialog the rule selects that
/// [`live_vcon_due`] says is due, into the rule's directory, with the rule's
/// audio setting.
///
/// Returns how many containers it wrote, and the Call-IDs the rule selected
/// (which the audio release reads: see [`live_rules_sweep`]).
#[cfg(feature = "vcon")]
fn live_target_sweep(
    cli: &Cli,
    target: &VconTarget<'_>,
    read: CaptureRead<'_>,
    gate: Option<&crate::output::persistence::PersistenceGate>,
    tracker: &mut LiveVconTracker,
    now: chrono::DateTime<chrono::Utc>,
) -> (usize, Vec<String>) {
    let CaptureRead {
        dialogs: dialog_store,
        streams: stream_store,
        frames_read,
    } = read;
    let (selection, suppressed_by_deny, _denied) =
        match vcon_selection(cli, target.filter, dialog_store, stream_store) {
            Ok(s) => s,
            Err(e) => {
                tracker.fail(&target.say(&format!("{e:#}")));
                return (0, Vec::new());
            }
        };
    let selected: Vec<String> = selection
        .dialogs
        .iter()
        .map(|(dialog, _)| dialog.call_id.clone())
        .collect();
    let units = live_units(
        target.grouping,
        target.live,
        dialog_store,
        selection
            .dialogs
            .iter()
            .map(|(dialog, streams)| (*dialog, streams.as_slice())),
        tracker,
        now,
    );
    let units: Vec<ContainerUnit<'_>> = units
        .into_iter()
        .filter(|unit| {
            let before = unit
                .key()
                .and_then(|k| tracker.sealed_instances.get(k))
                .copied()
                .unwrap_or(0);
            sealed_write_allowed(target, unit, before, false)
        })
        .collect();
    if units.is_empty() {
        return (0, selected);
    }
    let dir = match prepare_target_dir(target) {
        Ok(dir) => dir,
        Err(message) => {
            tracker.fail(&message);
            return (0, selected);
        }
    };
    let outcome = write_vcon_containers(
        cli,
        target,
        &VconBatch {
            dialog_store,
            stream_store,
            frames_read,
            gate,
            suppressed_by_deny,
            defer_enrichment: true,
            first_written: Some(&tracker.first_written),
            sealed_instances: Some(&tracker.sealed_instances),
            now,
        },
        &units,
        None,
    );
    let written = *outcome.as_ref().unwrap_or_else(|(n, _)| n);
    if target.live || target.sealing.is_some() {
        for dialog in units.iter().take(written).flat_map(ContainerUnit::legs) {
            tracker
                .first_written
                .entry(dialog.call_id.clone())
                .or_insert(now);
        }
    }
    if target.sealing.is_some() {
        for key in units.iter().take(written).filter_map(ContainerUnit::key) {
            let count = tracker.sealed_instances.entry(key.to_owned()).or_insert(0);
            *count = count.saturating_add(1);
        }
    }
    (settle_live_writes(tracker, &units, dir, outcome), selected)
}

/// Every rule's share of a live sweep, then which written calls may give
/// their retained audio back.
///
/// A call's audio is released only when every inline-audio rule that selects
/// it has written it at its current `updated_at`. A rule that omits audio, or
/// an inline rule whose filter only matches the call later, would otherwise
/// leave the next inline container with the audio already gone. A call held
/// back is looked at again on the next sweep.
///
/// Returns how many containers the sweep wrote across every rule.
#[cfg(feature = "vcon")]
fn live_rules_sweep(
    cli: &Cli,
    rules: &[VconRule],
    read: CaptureRead<'_>,
    gate: Option<&crate::output::persistence::PersistenceGate>,
    trackers: &mut [LiveVconTracker],
    now: chrono::DateTime<chrono::Utc>,
) -> usize {
    let dialog_store = read.dialogs;
    for tracker in trackers.iter_mut() {
        tracker.prune(|call_id| dialog_store.get(call_id).is_some());
    }
    if gate.is_some_and(|g| !g.writes_permitted()) {
        return 0;
    }
    let mut written = 0usize;
    let mut inline_selected: Vec<(usize, Vec<String>)> = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        let Some(tracker) = trackers.get_mut(i) else {
            continue;
        };
        let (n, selected) = live_target_sweep(cli, &VconTarget::of(rule), read, gate, tracker, now);
        written = written.saturating_add(n);
        if rule.audio == RuleAudio::Inline {
            inline_selected.push((i, selected));
        }
    }
    let Some((first, rest)) = trackers.split_first_mut() else {
        return written;
    };
    let mut candidates = std::mem::take(&mut first.held);
    candidates.append(&mut first.unreleased);
    for t in rest.iter_mut() {
        candidates.append(&mut t.unreleased);
    }
    candidates.sort();
    candidates.dedup();
    for call_id in candidates {
        let owed = dialog_store.get(&call_id).is_some_and(|dialog| {
            inline_selected.iter().any(|(i, selected)| {
                let at = if *i == 0 {
                    first.written_at(&call_id)
                } else {
                    rest.get(i - 1).and_then(|t| t.written_at(&call_id))
                };
                selected.contains(&call_id) && at != Some(dialog.updated_at)
            })
        });
        if owed {
            first.held.push(call_id);
        } else {
            first.unreleased.push(call_id);
        }
    }
    written
}

/// The dialogs among `selected` that a live sweep at `now` writes, by
/// [`live_vcon_due`] against what `tracker` says was already written.
#[cfg(feature = "vcon")]
fn live_due_dialogs<'a>(
    selected: impl Iterator<
        Item = (
            &'a crate::sip::dialog::SipDialog,
            &'a [&'a crate::rtp::stream::RtpStream],
        ),
    >,
    tracker: &LiveVconTracker,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<&'a crate::sip::dialog::SipDialog> {
    let timing = live_timing();
    selected
        .filter(|(dialog, streams)| {
            live_vcon_due(
                dialog.state(),
                quiet_since(dialog, streams),
                dialog.updated_at,
                now,
                timing,
                tracker.written_at(&dialog.call_id),
            )
        })
        .map(|(dialog, _)| dialog)
        .collect()
}

/// The containers one live sweep writes for a rule: each dialog that
/// [`live_vcon_due`] says is due, or, for `grouping = "call"`, each call one
/// of whose legs is due and all of whose legs have settled -- due now, or
/// already written as they stand. A call with a leg still in progress waits,
/// so its container is never written with a leg missing that is still
/// arriving.
#[cfg(feature = "vcon")]
fn live_units<'a>(
    grouping: RuleGrouping,
    live: bool,
    store: &'a DialogStore,
    selected: impl Iterator<
        Item = (
            &'a crate::sip::dialog::SipDialog,
            &'a [&'a crate::rtp::stream::RtpStream],
        ),
    >,
    tracker: &LiveVconTracker,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<ContainerUnit<'a>> {
    let selected: Vec<_> = selected.collect();
    // A `live = true` rule writes a call whenever it changed since its last
    // write, from the first message on; any other waits for the call to end
    // or go idle.
    let due: Vec<&crate::sip::dialog::SipDialog> = if live {
        selected
            .iter()
            .map(|(d, _)| *d)
            .filter(|d| tracker.written_at(&d.call_id) != Some(d.updated_at))
            .collect()
    } else {
        live_due_dialogs(selected.iter().copied(), tracker, now)
    };
    match grouping {
        RuleGrouping::Leg => due
            .into_iter()
            .map(|d| ContainerUnit::Leg(d, false))
            .collect(),
        RuleGrouping::Call => {
            let is_due =
                |d: &crate::sip::dialog::SipDialog| due.iter().any(|x| x.call_id == d.call_id);
            let settled = |d: &crate::sip::dialog::SipDialog| {
                is_due(d) || tracker.written_at(&d.call_id) == Some(d.updated_at)
            };
            let dialogs: Vec<_> = selected.iter().map(|(d, _)| *d).collect();
            call_groups(store, &dialogs)
                .into_iter()
                .filter(|g| g.legs.iter().any(|d| is_due(d)) && g.legs.iter().all(|d| settled(d)))
                .map(ContainerUnit::Call)
                .collect()
        }
    }
}

/// Record what one live sweep wrote and say what happened.
///
/// Every leg of the first `written` of `units` is recorded on the tracker, the count is
/// logged, and a failure is logged and remembered so the run exits non-zero.
/// Returns how many containers the sweep wrote.
#[cfg(feature = "vcon")]
fn settle_live_writes(
    tracker: &mut LiveVconTracker,
    units: &[ContainerUnit<'_>],
    dir: &std::path::Path,
    outcome: Result<usize, (usize, String)>,
) -> usize {
    let (written, failure) = match outcome {
        Ok(n) => (n, None),
        Err((n, message)) => (n, Some(message)),
    };
    for dialog in units.iter().take(written).flat_map(ContainerUnit::legs) {
        tracker.record(&dialog.call_id, dialog.updated_at);
    }
    tracker.containers_written = tracker.containers_written.saturating_add(written);
    if written > 0 {
        tracing::info!(
            "Wrote {written} vCon container(s) to '{}' for calls that ended.",
            dir.display()
        );
    }
    if let Some(message) = failure {
        tracker.fail(&message);
    }
    written
}

/// One live sweep's share of `--export-vcon <CALL-ID>`: write that call's
/// container once it is due by [`live_vcon_due`], the rule the
/// `--export-vcon-when` spool follows, and record it on the tracker.
///
/// A call the store does not hold (yet) is not an error here: it may still
/// arrive, and the end of a run that ends on its own says so if it never did.
/// The container goes through [`write_single_vcon`], the writer the end-of-run
/// export uses, so it is the same container whichever of the two wrote it.
///
/// Returns how many containers this sweep wrote: 0 or 1.
#[cfg(feature = "vcon")]
fn live_single_vcon_sweep(
    cli: &Cli,
    call_id: &str,
    dialog_store: &DialogStore,
    stream_store: &StreamStore,
    frames_read: u64,
    tracker: &mut LiveVconTracker,
    now: chrono::DateTime<chrono::Utc>,
) -> usize {
    let Some(dialog) = dialog_store.get(call_id) else {
        return 0;
    };
    let streams: Vec<&crate::rtp::stream::RtpStream> = stream_store.streams_for(call_id).collect();
    if !live_vcon_due(
        dialog.state(),
        quiet_since(dialog, &streams),
        dialog.updated_at,
        now,
        live_timing(),
        tracker.written_at(call_id),
    ) {
        return 0;
    }
    if !write_single_vcon(cli, dialog, dialog_store, stream_store, frames_read) {
        tracker.failed = true;
        return 0;
    }
    tracker.record(call_id, dialog.updated_at);
    tracing::info!("Wrote the vCon container for Call-ID '{call_id}', which ended.");
    1
}

/// The capture a batch of containers is drawn from, and what the run
/// withheld from it.
#[derive(Clone, Copy)]
#[cfg(feature = "vcon")]
struct VconBatch<'a> {
    /// Every dialog the run holds; the analysis is drawn from all of them.
    dialog_store: &'a DialogStore,
    /// Every stream the run holds.
    stream_store: &'a StreamStore,
    /// Frames read so far, for the capture facts.
    frames_read: u64,
    /// The REST persistence gate, when a companion server runs.
    gate: Option<&'a crate::output::persistence::PersistenceGate>,
    /// How many dialogs the deny header removed from the selection.
    suppressed_by_deny: u64,
    /// A live sweep: enrichment runs on the queue's worker rather than
    /// holding the sweep. Never set for the end-of-run export, which waits.
    defer_enrichment: bool,
    /// When each call's container was first written, which a `live = true`
    /// rule's rewrites keep as `created_at`.
    first_written: Option<&'a std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>>,
    /// How many sealed instances each call already has, which names the next
    /// instance's uuid for a `sealed_updates = "new-uuid"` rule.
    sealed_instances: Option<&'a std::collections::HashMap<String, u32>>,
    /// The moment this write happens: a live sweep's clock, so a container's
    /// `updated_at` and the tracker's record of it are one value.
    now: chrono::DateTime<chrono::Utc>,
}

/// Decode the audio sipnab retained for one dialog's streams.
///
/// Media is attempted ALWAYS, never gated on a second flag. `--retain-audio`
/// is already the operator's opt-in: without it there is no payload to
/// decode, and the container then carries the exporter's own explanation of
/// what was measured instead of an absence a reader has to interpret.
///
/// Both export paths call this, the single-call `--export-vcon` and the
/// `--export-vcon-when` spool, so one call gets the same audio from either.
/// The spool path once used the signaling-only exporter and dropped it.
#[cfg(feature = "vcon")]
fn decode_observed_audio(
    stream_store: &StreamStore,
    call_id: &str,
) -> anyhow::Result<crate::rtp::audio_export::DialogAudio> {
    let streams: Vec<&crate::rtp::stream::RtpStream> = stream_store.streams_for(call_id).collect();
    crate::rtp::audio_export::decode_dialog_audio(&streams)
}

/// What the exporter is told about a dialog's audio, from
/// [`decode_observed_audio`]'s result and its error text.
///
/// A redacted export is told the audio is withheld, whatever was decoded:
/// redaction deletes audio, and an exporter handed audio it must then lose
/// writes a `recording` Dialog Object with nothing in it. The one place both
/// writers decide this, so the single-call export and the spool cannot differ.
#[cfg(feature = "vcon")]
fn observed_audio<'a>(
    decoded: &'a anyhow::Result<crate::rtp::audio_export::DialogAudio>,
    reason: &'a str,
    redacting: bool,
    encoded: Option<(RuleAudioFormat, &'a [u8])>,
) -> crate::output::vcon::ObservedAudio<'a> {
    match decoded.as_ref() {
        _ if redacting => crate::output::vcon::ObservedAudio::WithheldByRedaction,
        Ok(audio) => match encoded {
            Some((format, bytes)) => crate::output::vcon::ObservedAudio::Encoded(
                audio,
                format.recording(audio, Some(bytes)),
            ),
            None => crate::output::vcon::ObservedAudio::Decoded(audio),
        },
        Err(_) => crate::output::vcon::ObservedAudio::NothingToDecode(reason),
    }
}

/// Write one container per dialog in `dialogs`, and a withheld-dialog
/// container per dialog in `tombstones`, into `target`'s directory with its
/// audio setting.
///
/// THE writer: the end-of-run export and every live sweep call it, so a
/// container means the same thing whichever of them wrote it. `--vcon-digest`
/// prints one line per container here, on stdout.
///
/// The capture facts and analysis are built once per call and shared by every
/// container in it, and not built at all when there is nothing to write.
///
/// # Errors
///
/// `(written, message)`: how many containers were written before the one that
/// failed, and a message naming it. Dialogs are written in order, so the first
/// `written` of `dialogs` are on disk.
#[cfg(feature = "vcon")]
fn write_vcon_containers(
    cli: &Cli,
    target: &VconTarget<'_>,
    batch: &VconBatch<'_>,
    units: &[ContainerUnit<'_>],
    redactor: Option<&crate::output::redact::Redactor<'_>>,
) -> Result<usize, (usize, String)> {
    if units.is_empty() {
        return Ok(0);
    }
    let dir = target.dir;
    let mut facts = crate::analysis::CaptureFacts::observed(
        batch.dialog_store,
        batch.stream_store,
        batch.frames_read,
    );
    // What this run deliberately did not write. Recorded on the facts BEFORE
    // the analysis runs, so every container built from them carries the same
    // account -- a container that named a different number from its siblings
    // would read as two runs.
    facts.dialogs_suppressed_by_deny = batch.suppressed_by_deny;
    facts.gate_closed_during_run = batch
        .gate
        .is_some_and(crate::output::persistence::PersistenceGate::closed_during_run);
    let analysis =
        crate::analysis::analyze_with(batch.dialog_store, batch.stream_store, None, &facts);
    let header = cli
        .output_args
        .content_deny_header
        .as_deref()
        .unwrap_or("(unnamed)");
    let writer = LegWriter {
        cli,
        target,
        batch,
        facts: &facts,
        analysis: &analysis,
        header,
        redactor,
    };
    let mut written = 0_usize;
    for unit in units {
        let (container, root, what) = match unit {
            ContainerUnit::Leg(dialog, withheld) => (
                writer.leg(dialog, *withheld, true, written)?,
                *dialog,
                if *withheld {
                    "withheld-dialog vCon"
                } else {
                    "vCon"
                },
            ),
            ContainerUnit::Call(group) => {
                let mut legs = Vec::with_capacity(group.legs.len());
                for dialog in &group.legs {
                    legs.push(writer.leg(dialog, false, false, written)?);
                }
                let uuid = crate::output::vcon::call_uuid(
                    &group.legs,
                    crate::output::vcon::dialog_capture_id(group.legs[0]),
                );
                let Some(container) =
                    crate::output::vcon::merge_call_legs(legs, &group.ties, uuid, group.truncated)
                else {
                    continue;
                };
                (container, group.legs[0], "call vCon")
            }
        };
        let mut container = container;
        // A withheld container carries the caveat alone.
        if let Some(tags) = &target.additions.tags
            && !matches!(unit, ContainerUnit::Leg(_, true))
        {
            let matched = matched_filters(&tags.filters, unit.legs(), batch.stream_store);
            crate::output::vcon::add_tags(&mut container, unit.legs(), &tags.rule, &matched);
        }
        let ended = unit.ended();
        // Only a live capture has first-write times; on an `-I` run a live
        // rule writes what any rule writes. A sealing rule's later instance
        // keeps the first `created_at` too, whether or not the rule is live.
        // The first write's `created_at` is the tracker's clock, the value
        // the tracker records, so a later instance repeats it exactly.
        if let (true, Some(first_written)) =
            (target.live || target.sealing.is_some(), batch.first_written)
        {
            let now = batch.now;
            let first = first_written.get(&root.call_id).copied();
            container.created_at = first.unwrap_or(now).to_rfc3339();
            if target.live || first.is_some() {
                container.updated_at = Some(now.to_rfc3339());
            }
        }
        // core-04 section 4.1.9: a sealed container is never modified; a
        // later version is a new instance naming the prior one.
        let sealed_before = batch
            .sealed_instances
            .and_then(|m| m.get(&root.call_id))
            .copied()
            .unwrap_or(0);
        if target.sealing.is_some()
            && target.sealed_updates == SealedUpdates::NewUuid
            && sealed_before > 0
        {
            let base = std::mem::take(&mut container.uuid);
            container.uuid = crate::output::vcon::revision_uuid(&base, sealed_before);
            container.amended = Some(crate::output::vcon::Amended {
                uuid: crate::output::vcon::revision_uuid(&base, sealed_before - 1),
            });
        }
        // An encrypted container is named by its uuid: a Call-ID can carry
        // host names and addresses, and the name is not encrypted.
        let path = if target.sealing.is_some() {
            dir.join(encrypted_file_name(&container.uuid))
        } else {
            dir.join(vcon_spool_name(&root.call_id, redactor))
        };
        if !target.enrich.is_empty()
            && !matches!(unit, ContainerUnit::Leg(_, true))
            && (ended || !target.live)
        {
            if batch.defer_enrichment {
                match queue_enrichment(
                    cli,
                    container,
                    unit.legs(),
                    batch.stream_store,
                    target,
                    &path,
                    crate::app::vcon_enrich::queue(),
                ) {
                    None => {
                        written += 1;
                        continue;
                    }
                    Some(handed_back) => container = handed_back,
                }
            } else {
                enrich_container(&mut container, unit.legs(), batch.stream_store, target);
            }
        }
        let json =
            crate::output::vcon::sealed_json(&crate::output::vcon::seal(container, redactor))
                .map_err(|e| {
                    (
                        written,
                        format!(
                            "The {what} for Call-ID '{}' would not serialize: {e}",
                            spool_call_id(&root.call_id, redactor)
                        ),
                    )
                })?;
        let bytes =
            sealed_bytes(json, target.sealing.map(std::sync::Arc::as_ref)).map_err(|e| {
                (
                    written,
                    format!(
                        "The {what} for Call-ID '{}' could not be encrypted: {e}",
                        spool_call_id(&root.call_id, redactor)
                    ),
                )
            })?;
        write_container_atomically(&path, &bytes).map_err(|e| {
            (
                written,
                format!(
                    "Could not write '{}': {e}. {written} container(s) were written before this.",
                    path.display()
                ),
            )
        })?;
        if cli.output_args.vcon_digest {
            // stdout, while the summary goes to stderr: the digests are data
            // an operator redirects to a file, and mixing them with progress
            // text would put a "Wrote N containers" line inside their
            // SHA256SUMS.
            outln!("{}", digest_line(&path, &bytes));
        }
        written += 1;
    }
    Ok(written)
}

/// The names of `filters` that at least one of `legs` matches, in order.
///
/// Each leg is judged as the rule's own `when` judges it: with its streams,
/// the capture's media facts and the delay basis `select_dialogs` uses.
#[cfg(feature = "vcon")]
fn matched_filters<'f>(
    filters: &'f [(String, FilterExpr)],
    legs: &[&crate::sip::dialog::SipDialog],
    streams: &StreamStore,
) -> Vec<&'f str> {
    let capture = crate::rtp::diagnosis::CaptureMedia::of_store(streams);
    let delay = crate::rtp::quality::MosDelay::from_capture(streams);
    filters
        .iter()
        .filter(|(_, filter)| {
            legs.iter().any(|leg| {
                let own: Vec<&crate::rtp::stream::RtpStream> =
                    streams.streams_for(&leg.call_id).collect();
                filter.matches_dialog(leg, &own, capture, delay)
            })
        })
        .map(|(name, _)| name.as_str())
        .collect()
}

/// The bytes a rule writes for the serialized container `json`: `json`
/// itself, or with `sealing` its encrypted form under the container's uuid.
#[cfg(feature = "vcon")]
fn sealed_bytes(
    json: String,
    sealing: Option<&crate::output::vcon_jose::Sealing>,
) -> Result<Vec<u8>, String> {
    let Some(sealing) = sealing else {
        return Ok(json.into_bytes());
    };
    let value: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| format!("the container is not JSON: {e}"))?;
    let uuid = value["uuid"].as_str().unwrap_or_default();
    sealing.seal(json.as_bytes(), uuid)
}

/// Each leg's audio, owned, with the leg's signaling object in `container`:
/// what an enrichment service is sent.
#[cfg(feature = "vcon")]
fn leg_audio(
    container: &crate::output::vcon::Vcon,
    legs: &[&crate::sip::dialog::SipDialog],
    streams: &StreamStore,
) -> Vec<crate::app::vcon_enrich::OwnedLegAudio> {
    legs.iter()
        .filter_map(|leg| {
            let dialog = container
                .dialog
                .iter()
                .position(|d| d.sip_call_id == leg.call_id)?;
            let audio = decode_observed_audio(streams, &leg.call_id).ok()?;
            Some(crate::app::vcon_enrich::OwnedLegAudio {
                dialog,
                sip_call_id: leg.call_id.clone(),
                wav: audio.wav,
            })
        })
        .collect()
}

/// Say on stderr which of `records` did not succeed, for the call `call_id`.
#[cfg(feature = "vcon")]
fn report_enrichment(label: &str, call_id: &str, records: &[crate::app::vcon_enrich::Record]) {
    for record in records {
        if record.outcome != crate::app::vcon_enrich::Outcome::Ok {
            stderr_line!(
                "{label}[[vcon.enrich]] '{}' for Call-ID '{call_id}': {}: {}. The container \
                 is written without its analysis and records this.",
                record.service,
                record.outcome.as_str(),
                record.detail
            );
        }
    }
}

/// Send `container` to `target`'s enrichment services, with each leg's audio,
/// and say on stderr what did not succeed.
#[cfg(feature = "vcon")]
fn enrich_container(
    container: &mut crate::output::vcon::Vcon,
    legs: &[&crate::sip::dialog::SipDialog],
    streams: &StreamStore,
    target: &VconTarget<'_>,
) {
    let owned = leg_audio(container, legs, streams);
    let audio: Vec<crate::app::vcon_enrich::LegAudio<'_>> = owned
        .iter()
        .map(|a| crate::app::vcon_enrich::LegAudio {
            dialog: a.dialog,
            sip_call_id: &a.sip_call_id,
            wav: &a.wav,
        })
        .collect();
    let records = crate::app::vcon_enrich::enrich(container, &audio, target.enrich);
    let call_id = legs.first().map_or("", |d| d.call_id.as_str());
    report_enrichment(&target.say(""), call_id, &records);
}

/// Hand a live call's container to the enrichment queue, whose worker
/// enriches it and writes it to `path`. `None` when queued; the container
/// back, with every service recorded `queue-full`, when the queue had no
/// room, for the caller to write at once.
#[cfg(feature = "vcon")]
fn queue_enrichment(
    cli: &Cli,
    container: crate::output::vcon::Vcon,
    legs: &[&crate::sip::dialog::SipDialog],
    streams: &StreamStore,
    target: &VconTarget<'_>,
    path: &std::path::Path,
    queue: &crate::app::vcon_enrich::Queue,
) -> Option<crate::output::vcon::Vcon> {
    let audio = leg_audio(&container, legs, streams);
    let label = target.say("");
    let call_id = legs.first().map_or_else(String::new, |d| d.call_id.clone());
    let digest = cli.output_args.vcon_digest;
    let path = path.to_path_buf();
    let sealing = target.sealing.cloned();
    let finish: crate::app::vcon_enrich::Finish = Box::new(move |container, records| {
        report_enrichment(&label, &call_id, &records);
        let written = crate::output::vcon::sealed_json(&crate::output::vcon::seal(container, None))
            .map_err(|e| e.to_string())
            .and_then(|json| sealed_bytes(json, sealing.as_deref()))
            .and_then(|bytes| {
                write_container_atomically(&path, &bytes)
                    .map(|()| bytes)
                    .map_err(|e| e.to_string())
            });
        match written {
            Ok(bytes) if digest => outln!("{}", digest_line(&path, &bytes)),
            Ok(_) => {}
            Err(e) => stderr_line!(
                "{label}Could not write '{}' after enrichment: {e}",
                path.display()
            ),
        }
    });
    let job = crate::app::vcon_enrich::Job {
        container,
        audio,
        services: target.enrich.to_vec(),
        finish,
    };
    match queue.submit(job) {
        Ok(()) => None,
        Err(job) => {
            let mut container = job.container;
            let records = crate::app::vcon_enrich::queue_full_records(target.enrich);
            crate::app::vcon_enrich::attach(&mut container, &records);
            let call_id = legs.first().map_or("", |d| d.call_id.as_str());
            report_enrichment(&target.say(""), call_id, &records);
            Some(container)
        }
    }
}

/// One container's worth of a rule's export: a dialog on its own, withheld or
/// not, or every selected leg of one call.
#[cfg(feature = "vcon")]
enum ContainerUnit<'d> {
    /// One dialog, and whether its content is withheld.
    Leg(&'d crate::sip::dialog::SipDialog, bool),
    /// The legs of one call, for a `grouping = "call"` rule.
    Call(CallGroup<'d>),
}

#[cfg(feature = "vcon")]
impl<'d> ContainerUnit<'d> {
    /// The dialogs this unit's container holds.
    fn legs(&self) -> &[&'d crate::sip::dialog::SipDialog] {
        match self {
            Self::Leg(dialog, _) => std::slice::from_ref(dialog),
            Self::Call(group) => &group.legs,
        }
    }

    /// The Call-ID a container's records are keyed on: the dialog's, or the
    /// first leg's for a call.
    fn key(&self) -> Option<&'d str> {
        self.legs().first().map(|d| d.call_id.as_str())
    }

    /// Whether every dialog in the unit has ended.
    fn ended(&self) -> bool {
        self.legs().iter().all(|d| d.state().is_final())
    }
}

/// Whether a sealing `target` writes `unit` now, by its `sealed_updates`.
///
/// Only `final-only` holds a write back: until every leg has ended, unless
/// `run_ended` (the end-of-run export, after which nothing more is
/// captured), and for good once one sealed instance was written. Every other
/// target writes whatever is due.
#[cfg(feature = "vcon")]
fn sealed_write_allowed(
    target: &VconTarget<'_>,
    unit: &ContainerUnit<'_>,
    sealed_before: u32,
    run_ended: bool,
) -> bool {
    if target.sealing.is_none() || target.sealed_updates != SealedUpdates::FinalOnly {
        return true;
    }
    sealed_before == 0 && (run_ended || unit.ended())
}

/// The containers one rule writes for `dialogs` and `tombstones`, as its
/// grouping divides them. Tombstones last, one per dialog, whatever the
/// grouping: every full container is on disk before the first of them.
#[cfg(feature = "vcon")]
fn container_units<'d>(
    grouping: RuleGrouping,
    store: &'d DialogStore,
    dialogs: &[&'d crate::sip::dialog::SipDialog],
    tombstones: &[&'d crate::sip::dialog::SipDialog],
) -> Vec<ContainerUnit<'d>> {
    let full: Vec<ContainerUnit<'d>> = match grouping {
        RuleGrouping::Leg => dialogs
            .iter()
            .map(|d| ContainerUnit::Leg(d, false))
            .collect(),
        RuleGrouping::Call => call_groups(store, dialogs)
            .into_iter()
            .map(ContainerUnit::Call)
            .collect(),
    };
    full.into_iter()
        .chain(tombstones.iter().map(|d| ContainerUnit::Leg(d, true)))
        .collect()
}

/// The legs of one call a `grouping = "call"` rule writes as one container.
#[cfg(feature = "vcon")]
#[derive(Debug)]
pub(crate) struct CallGroup<'d> {
    /// The legs, earliest first.
    pub(crate) legs: Vec<&'d crate::sip::dialog::SipDialog>,
    /// The ties the correlation walk followed between them, by position in
    /// `legs`.
    pub(crate) ties: Vec<crate::output::vcon::LegTie>,
    /// Whether the walk stopped at [`CALL_LEG_CAP`] with legs left.
    pub(crate) truncated: bool,
}

/// The most legs one call container holds. A walk that reaches it stops, and
/// the container says the call may have more.
#[cfg(feature = "vcon")]
pub(crate) const CALL_LEG_CAP: usize = 16;

/// `dialogs` divided into calls: each dialog with every other dialog in
/// `dialogs` that the correlation walk ([`DialogStore::correlation_tree`])
/// reaches from it.
///
/// Only dialogs in `dialogs` are grouped. A leg the rule did not select, or
/// whose content a deny header withheld, is in no call container, as it would
/// be in no leg container. Each dialog is in exactly one group: the walk
/// starts from the earliest dialog not yet placed.
#[cfg(feature = "vcon")]
pub(crate) fn call_groups<'d>(
    store: &'d DialogStore,
    dialogs: &[&'d crate::sip::dialog::SipDialog],
) -> Vec<CallGroup<'d>> {
    let mut order: Vec<&crate::sip::dialog::SipDialog> = dialogs.to_vec();
    order.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.call_id.cmp(&b.call_id))
    });
    let selected: std::collections::HashSet<&str> =
        order.iter().map(|d| d.call_id.as_str()).collect();
    let mut placed: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut groups = Vec::new();
    for start in &order {
        if placed.contains(start.call_id.as_str()) {
            continue;
        }
        let tree = store.correlation_tree(&start.call_id, CALL_LEG_CAP);
        let walked = tree.as_ref().map_or_else(Vec::new, |t| t.legs.clone());
        let mut legs: Vec<&crate::sip::dialog::SipDialog> = walked
            .iter()
            .filter(|leg| {
                selected.contains(leg.call_id.as_str()) && !placed.contains(leg.call_id.as_str())
            })
            .filter_map(|leg| store.get(&leg.call_id))
            .collect();
        if legs.is_empty() {
            legs.push(start);
        }
        legs.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.call_id.cmp(&b.call_id))
        });
        let position = |call_id: &str| legs.iter().position(|d| d.call_id == call_id);
        let ties = walked
            .iter()
            .filter_map(|leg| {
                let from = position(leg.parent_call_id.as_deref()?)?;
                let to = position(&leg.call_id)?;
                Some(crate::output::vcon::LegTie {
                    from,
                    to,
                    strategy: leg.strategy?,
                    identifier_match: leg.identifier_match?,
                    score: leg.score?,
                })
            })
            .collect();
        for leg in &legs {
            placed.insert(leg.call_id.as_str());
        }
        groups.push(CallGroup {
            truncated: tree.is_some_and(|t| t.truncated),
            legs,
            ties,
        });
    }
    groups
}

/// What every container one writer call builds shares: the run, the rule,
/// and the capture-wide facts.
#[cfg(feature = "vcon")]
struct LegWriter<'a> {
    /// The run's flags.
    cli: &'a Cli,
    /// The rule being written.
    target: &'a VconTarget<'a>,
    /// The stores and counts the containers are built from.
    batch: &'a VconBatch<'a>,
    /// What the run observed outside any one dialog.
    facts: &'a crate::analysis::CaptureFacts,
    /// The capture analysis built from `facts`.
    analysis: &'a crate::analysis::CaptureAnalysis,
    /// The deny header a withheld container names.
    header: &'a str,
    /// The redaction the containers are sealed under, if any.
    redactor: Option<&'a crate::output::redact::Redactor<'a>>,
}

#[cfg(feature = "vcon")]
impl LegWriter<'_> {
    /// One dialog's container, withheld or with the rule's audio, naming the
    /// call's other legs when `link` is set.
    ///
    /// A `url` rule's WAV is written here, beside where the container will
    /// go, so the file the container names exists before the container does.
    ///
    /// # Errors
    ///
    /// `(written, message)` when the WAV could not be written.
    fn leg(
        &self,
        dialog: &crate::sip::dialog::SipDialog,
        withheld: bool,
        link: bool,
        written: usize,
    ) -> Result<crate::output::vcon::Vcon, (usize, String)> {
        let mut container = self.leg_container(dialog, withheld, link, written)?;
        // A withheld container carries the caveat alone, so nothing is added
        // to it.
        if !withheld {
            self.add(&mut container, dialog);
        }
        Ok(container)
    }

    /// What the rule adds to one leg's container (see [`RuleAdditions`]).
    ///
    /// Added to the leg, before any merge, so `grouping = "call"` moves the
    /// added party and dialog indices with the rest of the leg's.
    fn add(
        &self,
        container: &mut crate::output::vcon::Vcon,
        dialog: &crate::sip::dialog::SipDialog,
    ) {
        let additions = self.target.additions;
        if additions.sip_messages {
            let budget = self
                .target
                .max_inline
                .or_else(|| media_budget(self.cli))
                .unwrap_or(crate::output::vcon::MAX_INLINE_MEDIA_BYTES);
            crate::output::vcon::add_sip_message_attachments(container, dialog, budget);
        }
        crate::output::vcon::add_cc_fields(
            container,
            dialog,
            crate::output::vcon::CcHeaders {
                campaign: additions.cc.campaign.as_deref(),
                skill: additions.cc.skill.as_deref(),
                interaction_id: additions.cc.interaction_id.as_deref(),
            },
        );
        if additions.dtmf_events {
            let presses: Vec<crate::output::vcon::RtpKeyPress> = self
                .batch
                .stream_store
                .streams_for(&dialog.call_id)
                .flat_map(|stream| {
                    stream
                        .key_presses
                        .iter()
                        .map(|press| crate::output::vcon::RtpKeyPress {
                            src: stream.key.src,
                            dst: stream.key.dst,
                            digit: press.digit,
                            ended_at: press.timestamp,
                            duration_ms: press.duration_ms,
                        })
                })
                .collect();
            crate::output::vcon::add_key_events(container, dialog, &presses);
        }
    }

    /// One dialog's container as the export builds it, before the rule's
    /// additions.
    ///
    /// # Errors
    ///
    /// As [`Self::leg`].
    fn leg_container(
        &self,
        dialog: &crate::sip::dialog::SipDialog,
        withheld: bool,
        link: bool,
        written: usize,
    ) -> Result<crate::output::vcon::Vcon, (usize, String)> {
        let Self {
            cli,
            target,
            batch,
            facts,
            analysis,
            header,
            redactor,
        } = *self;
        let media = crate::output::vcon::media_quality_for(batch.stream_store, &dialog.call_id);
        let related = if link {
            crate::output::vcon::related_legs(batch.dialog_store, dialog)
        } else {
            Vec::new()
        };
        let context = crate::output::vcon::ExportContext {
            capture_id: crate::output::vcon::dialog_capture_id(dialog),
            facts,
            analysis: Some(analysis),
            max_inline_media_bytes: target.max_inline.or_else(|| media_budget(cli)),
            media: &media,
            related_legs: &related,
        };
        if withheld {
            return Ok(crate::output::vcon::export_withheld_dialog(
                dialog, &context, header,
            ));
        }
        // A live rule's call in progress carries no audio: the audio is
        // added once the call has ended, inline or by URL.
        if target.audio == RuleAudio::Omit || (target.live && !dialog.state().is_final()) {
            return Ok(crate::output::vcon::export_dialog_with_audio(
                dialog,
                &context,
                crate::output::vcon::ObservedAudio::NotConsidered,
            ));
        }
        let decoded = decode_observed_audio(batch.stream_store, &dialog.call_id);
        let reason = decoded
            .as_ref()
            .err()
            .map_or_else(String::new, |e| e.to_string());
        // The rule's format, encoded once: the inline body and the file
        // beside the container are the same bytes. Redaction carries no
        // audio, so nothing is encoded for it.
        let format = target.audio_format;
        let encoded = match (decoded.as_ref(), redactor) {
            (Ok(decoded_audio), None) => format.encode(decoded_audio).map_err(|e| {
                (
                    written,
                    format!(
                        "The audio of Call-ID '{}' could not be encoded as {}: {e}. \
                         {written} container(s) were written before this.",
                        spool_call_id(&dialog.call_id, None),
                        format.label()
                    ),
                )
            })?,
            _ => None,
        };
        let referenced = match (target.audio, target.url_base, decoded.as_ref(), redactor) {
            (RuleAudio::Url, Some(base), Ok(decoded_audio), None) => {
                let recording = format.recording(decoded_audio, encoded.as_deref());
                let (name, file) = media_file(target, &dialog.call_id, recording, format)
                    .map_err(|e| (written, e))?;
                let path = target.dir.join(&name);
                write_container_atomically(&path, &file).map_err(|e| {
                    (
                        written,
                        format!(
                            "Could not write '{}': {e}. {written} container(s) were \
                             written before this.",
                            path.display()
                        ),
                    )
                })?;
                Some((decoded_audio, format!("{base}/{name}"), file))
            }
            _ => None,
        };
        let observed = match &referenced {
            Some((decoded_audio, url, file)) => crate::output::vcon::ObservedAudio::Referenced(
                decoded_audio,
                crate::output::vcon::ReferencedRecording {
                    url,
                    mediatype: format.mediatype(),
                    file,
                },
            ),
            None => observed_audio(
                &decoded,
                &reason,
                redactor.is_some(),
                encoded.as_deref().map(|bytes| (format, bytes)),
            ),
        };
        Ok(crate::output::vcon::export_dialog_with_audio(
            dialog, &context, observed,
        ))
    }
}

/// Write one container per dialog the predicate selected.
///
/// Reports the count on stderr rather than staying silent. A run that matched
/// nothing and a run that wrote forty containers look identical from the shell
/// otherwise, and the first is the one an operator needs to know about --
/// `--export-vcon` already refuses silence for the same reason.
///
/// Test-only: the run reaches the same code through [`export_vcon`], which
/// passes what the live sweeps wrote to [`export_vcon_selection_after`]. The
/// tests that pin the end-of-run behavior of a whole selection call it here.
#[cfg(all(feature = "vcon", test))]
fn export_vcon_selection(
    cli: &Cli,
    vcon_filter: Option<&crate::sip::dsl::FilterExpr>,
    dialog_store: &DialogStore,
    stream_store: &StreamStore,
    frames_read: u64,
    gate: Option<&crate::output::persistence::PersistenceGate>,
) -> bool {
    export_vcon_selection_after(
        cli,
        vcon_filter,
        dialog_store,
        stream_store,
        frames_read,
        gate,
        None,
    )
}

/// Where one export rule writes and what it writes: the resolved form every
/// export path works from, so `--export-vcon-when` and a `[[vcon.rule]]` take
/// one route.
#[cfg(feature = "vcon")]
#[derive(Debug, Clone, Copy)]
struct VconTarget<'a> {
    /// The rule's filter. `None` falls back to `--export-vcon-when`, for the
    /// callers with no plan (tests); see [`vcon_selection`].
    filter: Option<&'a crate::sip::dsl::FilterExpr>,
    /// The directory the rule writes to.
    dir: &'a std::path::Path,
    /// What each container carries of the call's audio.
    audio: RuleAudio,
    /// The rule's inline-media budget in bytes; `None` uses the run's.
    max_inline: Option<usize>,
    /// The base URL a `Url` rule names its audio files under.
    url_base: Option<&'a str>,
    /// The format of the audio each container carries.
    audio_format: RuleAudioFormat,
    /// Write each call as it starts and rewrite it as it changes.
    live: bool,
    /// Sign and encrypt each container; `None` writes the unsigned form.
    sealing: Option<&'a std::sync::Arc<crate::output::vcon_jose::Sealing>>,
    /// What a sealing target writes when a call it already wrote changes.
    sealed_updates: SealedUpdates,
    /// One container per leg, or one per call.
    grouping: RuleGrouping,
    /// The enrichment services, in order.
    enrich: &'a [std::sync::Arc<crate::app::vcon_enrich::Service>],
    /// The `[[vcon.rule]]` name, for the run's report; `None` for the flag
    /// rule, whose lines read as they always have.
    label: Option<&'a str>,
    /// What the rule adds to each container.
    additions: &'a RuleAdditions,
}

/// The additions of a rule that adds nothing: the flag rule's.
#[cfg(feature = "vcon")]
static NO_ADDITIONS: RuleAdditions = RuleAdditions {
    sip_messages: false,
    dtmf_events: false,
    tags: None,
    cc: RuleCcHeaders {
        campaign: None,
        skill: None,
        interaction_id: None,
    },
};

#[cfg(feature = "vcon")]
impl<'a> VconTarget<'a> {
    /// The target a resolved rule describes.
    fn of(rule: &'a VconRule) -> Self {
        Self {
            filter: Some(&rule.filter),
            dir: &rule.dir,
            audio: rule.audio,
            max_inline: rule.max_inline,
            url_base: rule.audio_url_base.as_deref(),
            audio_format: rule.audio_format,
            grouping: rule.grouping,
            live: rule.live,
            sealing: rule.sealing.as_ref(),
            sealed_updates: rule.sealed_updates,
            enrich: &rule.enrich,
            label: (rule.name != FLAG_RULE).then_some(rule.name.as_str()),
            additions: &rule.additions,
        }
    }

    /// The flag rule's target, from `--export-vcon-dir` and `filter`.
    ///
    /// # Errors
    ///
    /// When `--export-vcon-dir` is absent.
    fn from_flags(
        cli: &'a Cli,
        filter: Option<&'a crate::sip::dsl::FilterExpr>,
    ) -> Result<Self, String> {
        let dir = cli.output_args.export_vcon_dir.as_deref().ok_or_else(|| {
            "--export-vcon-when needs --export-vcon-dir. Nothing was exported.".to_owned()
        })?;
        Ok(Self {
            filter,
            dir,
            audio: RuleAudio::Inline,
            max_inline: None,
            url_base: None,
            audio_format: RuleAudioFormat::Wav,
            grouping: RuleGrouping::Leg,
            live: false,
            sealing: None,
            sealed_updates: SealedUpdates::NewUuid,
            enrich: &[],
            label: None,
            additions: &NO_ADDITIONS,
        })
    }

    /// `line`, prefixed with the rule's name when it has one.
    fn say(&self, line: &str) -> String {
        match self.label {
            Some(name) => format!("[[vcon.rule]] '{name}': {line}"),
            None => line.to_owned(),
        }
    }
}

/// [`export_vcon_selection`], leaving out every dialog `live` already wrote
/// at its current `updated_at`.
#[cfg(feature = "vcon")]
fn export_vcon_selection_after(
    cli: &Cli,
    vcon_filter: Option<&crate::sip::dsl::FilterExpr>,
    dialog_store: &DialogStore,
    stream_store: &StreamStore,
    frames_read: u64,
    gate: Option<&crate::output::persistence::PersistenceGate>,
    live: Option<&LiveVconTracker>,
) -> bool {
    let target = match VconTarget::from_flags(cli, vcon_filter) {
        Ok(t) => t,
        Err(message) => {
            stderr_line!("{message}");
            return false;
        }
    };
    export_targets_after(
        cli,
        &[(target, live)],
        &VconBatch {
            dialog_store,
            stream_store,
            frames_read,
            gate,
            suppressed_by_deny: 0,
            defer_enrichment: false,
            first_written: None,
            sealed_instances: None,
            now: chrono::Utc::now(),
        },
    )
}

/// The end-of-run export of every target, each leaving out what its live
/// tracker already wrote. One redactor serves every target, so a pseudonym
/// means the same in every rule's containers, and `--redact-map` is written
/// once, after all of them.
#[cfg(feature = "vcon")]
fn export_targets_after(
    cli: &Cli,
    targets: &[(VconTarget<'_>, Option<&LiveVconTracker>)],
    batch: &VconBatch<'_>,
) -> bool {
    let policy = match redaction_policy(cli) {
        Ok(p) => p,
        Err(reason) => {
            stderr_line!("{reason}");
            return false;
        }
    };
    // ONE redactor for the whole run, not one per container. The reverse table
    // it accumulates is what `--redact-map` writes, and a redactor per
    // container would hand back as many partial tables as there were dialogs.
    let redactor = policy
        .as_ref()
        .map(crate::output::redact::RedactionPolicy::redactor);

    for (target, live) in targets {
        if !export_target(cli, target, *live, batch, redactor.as_ref()) {
            return false;
        }
    }

    if let Some(r) = redactor.as_ref() {
        let report = r.policy().report();
        // On stderr beside the count, because an operator has to be able to
        // say what was redacted and how reversible it is without opening a
        // container. The same report travels INSIDE every container too.
        stderr_line!(
            "Redaction: {} classes, key {}, {} leading digit(s) retained.",
            report.classes.len(),
            report.key_mode,
            report.keep_prefix,
        );
        if let Some(path) = cli.output_args.redact_map.as_deref() {
            match write_redaction_map(path, r) {
                Ok(n) => stderr_line!(
                    "Wrote {n} token mapping(s) to '{}' (mode 0600). It reverses every \
                     pseudonym in these containers, so it is as sensitive as the capture.",
                    path.display()
                ),
                Err(reason) => {
                    stderr_line!("{reason}");
                    return false;
                }
            }
        }
    }
    true
}

/// One target's share of the end-of-run export: select, write, and say what
/// was written. `false` when it could not.
#[cfg(feature = "vcon")]
fn export_target(
    cli: &Cli,
    target: &VconTarget<'_>,
    live: Option<&LiveVconTracker>,
    batch: &VconBatch<'_>,
    redactor: Option<&crate::output::redact::Redactor<'_>>,
) -> bool {
    let (selection, suppressed_by_deny, denied) =
        match vcon_selection(cli, target.filter, batch.dialog_store, batch.stream_store) {
            Ok(s) => s,
            Err(e) => {
                stderr_line!("{}", target.say(&format!("{e:#}")));
                return false;
            }
        };
    if let Err(message) = prepare_target_dir(target) {
        stderr_line!("{message}");
        return false;
    }
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = selection
        .dialogs
        .iter()
        .map(|(dialog, _)| *dialog)
        .filter(|dialog| !written_live(live, dialog))
        .collect();
    // Tombstones only on request. Writing them at all reveals that the calls
    // EXISTED, which is a disclosure an operator has to choose -- see
    // `--content-deny-tombstone`. The default discards `denied` here.
    let tombstones: &[&crate::sip::dialog::SipDialog] = if cli.output_args.content_deny_tombstone {
        &denied
    } else {
        &[]
    };
    let units: Vec<ContainerUnit<'_>> =
        container_units(target.grouping, batch.dialog_store, &dialogs, tombstones)
            .into_iter()
            .filter(|unit| {
                let before = unit
                    .key()
                    .and_then(|k| live.and_then(|t| t.sealed_instances.get(k)))
                    .copied()
                    .unwrap_or(0);
                sealed_write_allowed(target, unit, before, true)
            })
            .collect();
    let written = match write_vcon_containers(
        cli,
        target,
        &VconBatch {
            suppressed_by_deny,
            first_written: live.map(|t| &t.first_written),
            sealed_instances: live.map(|t| &t.sealed_instances),
            ..*batch
        },
        &units,
        redactor,
    ) {
        Ok(n) => n,
        Err((_, message)) => {
            stderr_line!("{}", target.say(&message));
            return false;
        }
    };
    stderr_line!(
        "{}",
        target.say(&end_of_run_vcon_summary(
            written,
            live.map_or(0, LiveVconTracker::containers_written),
            target.dir
        ))
    );
    true
}

/// The line the end of a `--export-vcon-when` run prints about the spool.
///
/// `at_end` is what the end-of-run export wrote and `live` what the live
/// sweeps wrote while the capture ran. A live run usually writes every
/// container as its call ends, so the end of the run writes none, and a bare
/// count of zero would read as a run that exported nothing.
#[cfg(feature = "vcon")]
fn end_of_run_vcon_summary(at_end: usize, live: usize, dir: &std::path::Path) -> String {
    let dir = dir.display();
    match (at_end, live) {
        (n, 0) => format!("Wrote {n} vCon container(s) to '{dir}'."),
        (0, live) => format!(
            "Wrote no further vCon containers to '{dir}' at the end of the run; \
             {live} container(s) were written there as their calls ended."
        ),
        (n, live) => format!(
            "Wrote {n} more vCon container(s) to '{dir}' at the end of the run, \
             {} in total with the {live} written as their calls ended.",
            n.saturating_add(live)
        ),
    }
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

/// The Call-ID a container's spool file is named after: the container's own.
///
/// Under `--redact` that is the pseudonym the container carries in
/// `sip_call_id` ([`crate::output::redact::Redactor::opaque`], the rule the
/// container's redaction applies), not the Call-ID on the wire. The raw one
/// embeds the caller's host -- `1-1966@10.0.2.20` -- and the file name travels
/// further than the container: into `--vcon-digest` lines, the forwarder's
/// `delivered/` and `failed/` directories, its `error.json` records and every
/// line it logs. A name built from the raw Call-ID published what the
/// container hid. Naming the file after the container's token keeps a file
/// pairable with the Call-ID inside it.
///
/// One redactor per run, so one Call-ID gets one token, and a key from
/// `--redact-key-file` gives it the same token on the next run, which keeps a
/// re-export overwriting its own file.
#[cfg(feature = "vcon")]
fn spool_call_id(call_id: &str, redactor: Option<&crate::output::redact::Redactor<'_>>) -> String {
    match redactor {
        Some(r) => r.opaque(call_id),
        None => call_id.to_owned(),
    }
}

/// The audio file name beside a container: the container's name with
/// `.<extension>` in place of `.vcon.json`, so the two sort together and
/// share the digest that keeps Call-IDs apart.
#[cfg(feature = "vcon")]
fn vcon_media_name(container: &str, extension: &str) -> String {
    format!("{}.{extension}", container.trim_end_matches(".vcon.json"))
}

/// The name and bytes of the audio file a `url` rule writes beside a
/// container: `recording` as written, or, for a rule that encrypts, its
/// encrypted form.
///
/// An encrypting rule's file is a JWE to each of the rule's recipients
/// ([`crate::output::vcon_jose::Sealing::encrypt_file`]). It is named
/// `<content_hash>.<extension>.jwe`, by the hash of the ciphertext, because
/// the name is not encrypted and a Call-ID can carry host names and
/// addresses; the container is named by its uuid for the same reason.
///
/// The recording's `content_hash` is over these bytes, the ciphertext.
/// core-04 section 2.2 defines the hash over "the body of the content at the
/// given url", and the body served is the JWE. The draft does not say
/// whether `mediatype` describes that served body or the media inside it.
/// sipnab names the media inside (`audio/x-wav` or `audio/ogg`), which a
/// reader needs once it has decrypted the file, and the JWE's `cty` names the
/// same type.
#[cfg(feature = "vcon")]
fn media_file<'a>(
    target: &VconTarget<'_>,
    call_id: &str,
    recording: crate::output::vcon::EncodedRecording<'a>,
    format: RuleAudioFormat,
) -> Result<(String, std::borrow::Cow<'a, [u8]>), String> {
    // A rule that signs without encrypting writes the file as it is: the
    // signed container names its `content_hash`.
    match target.sealing.filter(|s| !s.recipients.is_empty()) {
        None => Ok((
            vcon_media_name(&vcon_spool_name(call_id, None), format.extension()),
            recording.bytes.into(),
        )),
        Some(sealing) => {
            let sealed = sealing
                .encrypt_file(recording.bytes, recording.mediatype)
                .map_err(|e| {
                    format!(
                        "The audio of Call-ID '{}' could not be encrypted: {e}",
                        spool_call_id(call_id, None)
                    )
                })?;
            let name = format!(
                "{}.{}.jwe",
                crate::output::vcon::content_hash(&sealed),
                format.extension()
            );
            Ok((name, sealed.into()))
        }
    }
}

/// The spool file name for `call_id`'s container: [`vcon_file_name`] of
/// [`spool_call_id`].
#[cfg(feature = "vcon")]
fn vcon_spool_name(
    call_id: &str,
    redactor: Option<&crate::output::redact::Redactor<'_>>,
) -> String {
    vcon_file_name(&spool_call_id(call_id, redactor))
}

/// The file an encrypting rule writes a container to: `<uuid>.vcon.json`.
/// A uuid sipnab generates is already safe in a path; anything else goes
/// through [`vcon_file_name`].
#[cfg(feature = "vcon")]
fn encrypted_file_name(uuid: &str) -> String {
    if crate::app::vcon_forward::is_path_uuid(uuid) {
        format!("{uuid}.vcon.json")
    } else {
        vcon_file_name(uuid)
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
    // No separate guard for an all-dots Call-ID. `.` and `..` are the two
    // names every directory already owns, and the suffix below is what makes
    // them unreachable: `..` becomes `_.-<digest>.vcon.json`. A defensive prefix here read
    // as the thing holding that property and held nothing -- removing it left
    // every test green, which is how it was found.
    // A leading dot would make the container look like sipnab's own staging
    // file (`.<name>.partial`), which every spool reader skips by contract, so
    // the container would be written and never forwarded. `_` keeps the name
    // visible; the digest below still separates `.x` from `_x`.
    if safe.starts_with('.') {
        safe.replace_range(..1, "_");
    }
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
    // A rule's own filter decides when there is one. Only a caller with no
    // plan (tests) falls back to parsing `--export-vcon-when`, and with
    // neither, everything is selected.
    let expr = match (resolved, cli.output_args.export_vcon_when.as_deref()) {
        (Some(_), _) => "",
        (None, Some(expr)) => expr,
        (None, None) => {
            return Ok((
                crate::sip::dsl::select_dialogs(None, dialog_store, stream_store),
                0,
                Vec::new(),
            ));
        }
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
    crate::output::vcon::denied_by_header(dialog, Some(header))
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
/// stderr — `stderr_line!` rather than `tracing`, matching `--call-report`,
/// because the message decides the process exit code and has to survive
/// logging being off.
#[cfg(feature = "vcon")]
fn export_vcon(
    cli: &Cli,
    rules: &[VconRule],
    dialog_store: &DialogStore,
    stream_store: &StreamStore,
    frames_read: u64,
    gate: Option<&crate::output::persistence::PersistenceGate>,
    end: VconRunEnd<'_>,
) -> bool {
    // The gate is consulted here, above both export forms, because both write
    // content and a check on one of them would leave the other writing through
    // a close. It answers `true`: an operator who switched persistence off got
    // what they asked for, and turning that into a non-zero exit would make
    // every scripted run treat a deliberate act as a failure.
    if gate.is_some_and(|g| !g.writes_permitted()) {
        return true;
    }
    let live = match end {
        VconRunEnd::Whole => None,
        // Answered `true`: a stop that writes nothing is what was asked for,
        // not a failed export. See `VconRunEnd::Stopped`.
        VconRunEnd::Stopped => return true,
        VconRunEnd::AfterLive(trackers) => Some(trackers),
    };
    // A live run that ended on its own finishes the calls still waiting for
    // enrichment before the end-of-run export; each is bounded by its
    // services' timeouts. A stopped run returned above: stop means stop.
    if live.is_some() && rules.iter().any(|r| !r.enrich.is_empty()) {
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(crate::app::vcon_enrich::MAX_TIMEOUT_SECS);
        if !crate::app::vcon_enrich::queue().drain(deadline) {
            stderr_line!(
                "Calls were still waiting for [[vcon.enrich]] after an hour; their \
                 containers are not written."
            );
        }
    }
    if !rules.is_empty() {
        let targets: Vec<(VconTarget<'_>, Option<&LiveVconTracker>)> = rules
            .iter()
            .enumerate()
            .map(|(i, rule)| (VconTarget::of(rule), live.and_then(|t| t.get(i))))
            .collect();
        return export_targets_after(
            cli,
            &targets,
            &VconBatch {
                dialog_store,
                stream_store,
                frames_read,
                gate,
                suppressed_by_deny: 0,
                defer_enrichment: false,
                first_written: None,
                sealed_instances: None,
                now: chrono::Utc::now(),
            },
        );
    }
    let live = live.and_then(<[LiveVconTracker]>::first);
    if cli.output_args.export_vcon_when.is_some() {
        return export_vcon_selection_after(
            cli,
            None,
            dialog_store,
            stream_store,
            frames_read,
            gate,
            live,
        );
    }
    let Some(call_id) = cli.output_args.export_vcon.as_deref() else {
        return true;
    };
    let Some(dialog) = dialog_store.get(call_id) else {
        stderr_line!(
            "Call-ID '{call_id}' not found in tracked dialogs, so there is no \
             dialog to export. --report lists the Call-IDs this run holds."
        );
        return false;
    };
    // A live run that ended on its own: the sweep already wrote this call
    // when it ended, and writing it again unchanged would hand a reader of
    // `--vcon-out` (or of stdout) the same container twice.
    if written_live(live, dialog) {
        return true;
    }
    write_single_vcon(cli, dialog, dialog_store, stream_store, frames_read)
}

/// Build the `--export-vcon` container for `dialog` and write it to
/// `--vcon-out`, atomically, or to stdout; say on stderr why it did not.
///
/// THE single-call writer: the end-of-run export and every live sweep call
/// it, so the container is the same whichever of them wrote it.
///
/// The capture analysis is run here rather than reused from `--analyze`,
/// because `--export-vcon` does not require `--analyze` (see [`export_vcon`]).
#[cfg(feature = "vcon")]
fn write_single_vcon(
    cli: &Cli,
    dialog: &crate::sip::dialog::SipDialog,
    dialog_store: &DialogStore,
    stream_store: &StreamStore,
    frames_read: u64,
) -> bool {
    let call_id = dialog.call_id.as_str();
    let facts = crate::analysis::CaptureFacts::observed(dialog_store, stream_store, frames_read);
    let analysis = crate::analysis::analyze_with(dialog_store, stream_store, None, &facts);

    // Media is attempted ALWAYS, never gated on a second flag. `--retain-audio`
    // is already the operator's opt-in: without it there is no payload to
    // decode, and the container then carries the exporter's own explanation of
    // what was measured instead of an absence a reader has to interpret.
    let media = crate::output::vcon::media_quality_for(stream_store, call_id);
    let decoded = decode_observed_audio(stream_store, call_id);
    let reason = decoded
        .as_ref()
        .err()
        .map_or_else(String::new, |e| e.to_string());
    // The policy before the export, because it decides what the exporter is
    // told about the audio: a redacted container is built without it.
    let policy = match redaction_policy(cli) {
        Ok(p) => p,
        Err(reason) => {
            stderr_line!("{reason}");
            return false;
        }
    };
    let redactor = policy
        .as_ref()
        .map(crate::output::redact::RedactionPolicy::redactor);

    let audio = observed_audio(&decoded, &reason, redactor.is_some(), None);

    let container = crate::output::vcon::export_dialog_with_audio(
        dialog,
        &crate::output::vcon::ExportContext {
            capture_id: crate::output::vcon::dialog_capture_id(dialog),
            facts: &facts,
            analysis: Some(&analysis),
            max_inline_media_bytes: media_budget(cli),
            media: &media,
            related_legs: &crate::output::vcon::related_legs(dialog_store, dialog),
        },
        audio,
    );

    let mut json = match crate::output::vcon::sealed_json(&crate::output::vcon::seal(
        container,
        redactor.as_ref(),
    )) {
        Ok(json) => json,
        Err(e) => {
            stderr_line!("The vCon for Call-ID '{call_id}' would not serialize: {e}");
            return false;
        }
    };
    json.push('\n');

    if let Some(r) = redactor.as_ref() {
        let report = r.policy().report();
        stderr_line!(
            "Redaction: {} classes, key {}, {} leading digit(s) retained.",
            report.classes.len(),
            report.key_mode,
            report.keep_prefix,
        );
        if let Some(path) = cli.output_args.redact_map.as_deref() {
            match write_redaction_map(path, r) {
                Ok(n) => stderr_line!(
                    "Wrote {n} token mapping(s) to '{}' (mode 0600).",
                    path.display()
                ),
                Err(reason) => {
                    stderr_line!("{reason}");
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
        stderr_line!(
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
    _rules: &[VconRule],
    _dialog_store: &DialogStore,
    _stream_store: &StreamStore,
    _frames_read: u64,
    _gate: Option<&crate::output::persistence::PersistenceGate>,
    _end: VconRunEnd<'_>,
) -> bool {
    // The gate is ignored here rather than consulted, and the difference is
    // only apparent: a build without the feature writes no container by any
    // route, so there is nothing for a closed gate to stop. It is accepted so
    // both doors keep one signature -- a stub that dropped the parameter would
    // break the caller in exactly the build nobody runs the tests on.
    // The same rule validate() applies, so the two doors cannot disagree
    // about which flags this build refuses (VCON-NOFEAT-1: this door used to
    // check --export-vcon alone and pass --export-vcon-when through).
    match cli.vcon_refusal(false) {
        None => true,
        Some(refusal) => {
            stderr_line!("{refusal}.");
            false
        }
    }
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

    /// Without `--keylog-watch` or `--keylog-fd` the keylog poll reads no
    /// clock: the receive loop asks once per packet, and the clock read cost
    /// 7.6% of the cycles of a single-core file run (perf, 2026-10-11).
    #[cfg(feature = "tls")]
    #[test]
    fn keylog_poll_reads_no_clock_when_not_watching() {
        let read = std::cell::Cell::new(0);
        let since = || {
            read.set(read.get() + 1);
            KEYLOG_POLL_INTERVAL
        };
        assert!(!keylog_poll_due(false, since));
        assert_eq!(read.get(), 0, "the clock was read with no watch set");
        assert!(keylog_poll_due(true, since));
        assert_eq!(read.get(), 1);
    }

    /// With a watch set, the poll is due once the interval has passed.
    #[cfg(feature = "tls")]
    #[test]
    fn keylog_poll_is_due_after_the_interval() {
        let short = KEYLOG_POLL_INTERVAL - std::time::Duration::from_millis(1);
        assert!(!keylog_poll_due(true, || short));
        assert!(keylog_poll_due(true, || KEYLOG_POLL_INTERVAL));
    }

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// The `--cores` paths take their correlation headers from the same key,
    /// with the same default: none. Each worker builds its own store from
    /// `ParallelConfig`, and a parallel run serves no query surface that
    /// could show a correlation, so the conversion is what is tested.
    #[test]
    fn parallel_config_follows_no_correlation_header_unless_configured() {
        let cli = Cli::parse_from_args(["sipnab"]);
        let unset = Config::default();
        assert!(
            parallel_config(&cli, &unset, (1, 65535), false)
                .xcid_headers
                .is_empty(),
            "X-Call-ID is not a default"
        );
        let mut set = Config::default();
        set.sip.xcid_headers = Some(vec!["X-Call-ID".to_string()]);
        assert_eq!(
            parallel_config(&cli, &set, (1, 65535), false).xcid_headers,
            vec!["X-Call-ID".to_string()]
        );
    }

    /// Baseline non-interactive CLI; mutate the pub fields per test.
    /// Build a `SipMessage` for `call_id` from the shared INVITE fixture.
    fn invite_msg(call_id: &str) -> Result<sip::message::SipMessage, TestError> {
        let data = bytes::Bytes::from(invite_bytes(call_id));
        Ok(sip::parser::parse_sip_bytes(
            &data,
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .map_err(|e| format!("fixture parses: {e:?}"))?)
    }

    /// A final response, so a fixture dialog can carry a status code the
    /// filter language can read.
    #[cfg(feature = "vcon")]
    fn response_msg(
        call_id: &str,
        code: u16,
        reason: &str,
    ) -> Result<sip::message::SipMessage, TestError> {
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
        Ok(sip::parser::parse_sip_bytes(
            &data,
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .map_err(|e| format!("fixture parses: {e:?}"))?)
    }

    /// Two dialogs, one of which failed.
    #[cfg(feature = "vcon")]
    fn two_dialogs_one_failed() -> Result<DialogStore, TestError> {
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_msg("ok-call@example.com")?);
        store.process_message(response_msg("ok-call@example.com", 200, "OK")?);
        store.process_message(invite_msg("failed-call@example.com")?);
        store.process_message(response_msg("failed-call@example.com", 486, "Busy Here")?);
        Ok(store)
    }

    /// A dialog the store does not hold is still its own call: the walk
    /// finds nothing from it, and it is grouped alone rather than dropped.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_dialog_the_store_lacks_is_a_call_of_its_own() -> Result<(), TestError> {
        let store = two_dialogs_one_failed()?;
        let outsider = crate::sip::dialog::SipDialog::new(&invite_msg("outside@example.com")?)
            .ok_or("an INVITE opens a dialog")?;
        let held = store.get("ok-call@example.com").ok_or("held dialog")?;
        let groups = call_groups(&store, &[held, &outsider]);
        let calls: Vec<Vec<&str>> = groups
            .iter()
            .map(|g| g.legs.iter().map(|d| d.call_id.as_str()).collect())
            .collect();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(calls.contains(&vec!["outside@example.com"]), "{calls:?}");
        assert!(calls.contains(&vec!["ok-call@example.com"]), "{calls:?}");
        Ok(())
    }

    // ── Live vCon export (LIVE-VCON-1) ─────────────────────────────

    /// The settle period the live export uses, as the predicate takes it.
    #[cfg(feature = "vcon")]
    fn settle() -> Result<chrono::TimeDelta, TestError> {
        Ok(chrono::TimeDelta::from_std(SWEEP_INTERVAL)
            .map_err(|e| format!("five seconds fits: {e:?}"))?)
    }

    /// The time of a live sweep that finds every dialog in `store` settled:
    /// one sweep interval and a second after its newest message.
    ///
    /// Read off the store rather than the clock. The dialogs are stamped with
    /// the time they were built, so a sweep time taken from `Utc::now()`
    /// before them, or on a thread that stalls between the two, can land
    /// before they settle, and the sweep then writes nothing. Under the full
    /// suite on a loaded host `a_live_sweep_writes_a_call_once_per_rule` did
    /// exactly that.
    #[cfg(feature = "vcon")]
    fn swept_after(store: &DialogStore) -> Result<chrono::DateTime<chrono::Utc>, TestError> {
        let newest = store
            .iter()
            .map(|d| d.updated_at)
            .max()
            .ok_or("the store holds a dialog")?;
        Ok(newest + settle()? + chrono::TimeDelta::seconds(1))
    }

    /// A resolved rule over `expr`, writing to `dir` with `audio`.
    #[cfg(feature = "vcon")]
    fn test_rule(
        name: &str,
        expr: &str,
        dir: &std::path::Path,
        audio: RuleAudio,
    ) -> Result<VconRule, TestError> {
        Ok(VconRule {
            name: name.to_owned(),
            filter: crate::sip::dsl::FilterExpr::parse(expr)?,
            dir: dir.to_path_buf(),
            audio,
            max_inline: None,
            audio_url_base: None,
            audio_format: RuleAudioFormat::Wav,
            grouping: RuleGrouping::Leg,
            enrich: Vec::new(),
            live_audio: false,
            live_rtp: None,
            live: false,
            sealing: None,
            sealed_updates: SealedUpdates::NewUuid,
            additions: RuleAdditions::default(),
        })
    }

    /// A live sweep writes a due call once per rule that selects it, into each
    /// rule's directory, on each rule's own tracker.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_sweep_writes_a_call_once_per_rule() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let rules = vec![
            test_rule(
                "a",
                "response_code >= 400",
                &tmp.path().join("a"),
                RuleAudio::Inline,
            )?,
            test_rule(
                "b",
                "response_code >= 400",
                &tmp.path().join("b"),
                RuleAudio::Omit,
            )?,
            test_rule(
                "c",
                "response_code == 299",
                &tmp.path().join("c"),
                RuleAudio::Omit,
            )?,
        ];
        let mut trackers: Vec<LiveVconTracker> =
            (0..3).map(|_| LiveVconTracker::default()).collect();
        let dialogs = two_dialogs_one_failed()?;
        let later = swept_after(&dialogs)?;
        let n = live_rules_sweep(
            &Cli::parse_from_args(["sipnab"]),
            &rules,
            CaptureRead {
                dialogs: &dialogs,
                streams: &StreamStore::new(16),
                frames_read: 4,
            },
            None,
            &mut trackers,
            later,
        );
        assert_eq!(n, 2, "one container for rule a and one for rule b");
        for (dir, want) in [("a", 1), ("b", 1), ("c", 0)] {
            let got = std::fs::read_dir(tmp.path().join(dir))
                .map(|d| d.count())
                .unwrap_or(0);
            assert_eq!(got, want, "rule {dir}");
        }
        assert!(trackers[0].written_at("failed-call@example.com").is_some());
        assert!(trackers[1].written_at("failed-call@example.com").is_some());
        assert!(trackers[2].written_at("failed-call@example.com").is_none());
        Ok(())
    }

    /// A live `grouping = "call"` rule writes a call once every leg it
    /// selects has settled, as one container, and records every leg.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_call_rule_waits_for_every_leg() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dir = tmp.path().join("calls");
        let mut rule = test_rule("calls", "call_id =~ '.'", &dir, RuleAudio::Omit)?;
        rule.grouping = RuleGrouping::Call;
        let rules = vec![rule];
        let mut store = DialogStore::new(16, true).with_xcid_headers(vec!["X-Call-ID".into()]);
        store.process_message(invite_msg("a-leg@example.com")?);
        store.process_message(response_msg("a-leg@example.com", 486, "Busy Here")?);
        store.process_message(invite_with_header(
            "b-leg@example.com",
            "X-Call-ID",
            "a-leg@example.com",
        )?);
        let streams = StreamStore::new(16);
        let cli = Cli::parse_from_args(["sipnab"]);
        let mut trackers = vec![LiveVconTracker::default()];
        let files = || std::fs::read_dir(&dir).map(|d| d.count()).unwrap_or(0);

        let later = swept_after(&store)?;
        let read = CaptureRead {
            dialogs: &store,
            streams: &streams,
            frames_read: 3,
        };
        let n = live_rules_sweep(&cli, &rules, read, None, &mut trackers, later);
        assert_eq!(n, 0, "b-leg is still ringing, so the call is not written");
        assert_eq!(files(), 0);

        store.process_message(response_msg("b-leg@example.com", 486, "Busy Here")?);
        let later = swept_after(&store)?;
        let read = CaptureRead {
            dialogs: &store,
            streams: &streams,
            frames_read: 4,
        };
        let n = live_rules_sweep(&cli, &rules, read, None, &mut trackers, later);
        assert_eq!(n, 1, "one container for the call");
        assert_eq!(files(), 1);
        for leg in ["a-leg@example.com", "b-leg@example.com"] {
            assert!(trackers[0].written_at(leg).is_some(), "{leg} recorded");
        }
        let n = live_rules_sweep(&cli, &rules, read, None, &mut trackers, later);
        assert_eq!(n, 0, "nothing changed, nothing rewritten");
        Ok(())
    }

    /// A live sweep hands an enriching rule's call to the enrichment queue and
    /// goes on; the worker enriches the container and writes it.
    ///
    /// The service does not answer until the test releases it, so "the sweep
    /// did not wait" is observed as an order of events, not a duration: the
    /// sweep returns while the service is still held, and nothing is written
    /// until it is let go. A sweep that waited for the service would write
    /// the container itself, after the service gave up holding (60 s), and
    /// the file it wrote is what fails the test. A bound of 900 ms against a
    /// one-second service measured the machine as much as the sweep, and
    /// failed in 14 of 450 runs with the load average between 170 and 370.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_sweep_queues_enrichment_and_the_worker_writes() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let script = tmp.path().join("stt.sh");
        let release = tmp.path().join("release");
        // Written by a child process, so this one never holds a writable
        // descriptor a sibling test's fork could inherit (ETXTBSY on exec).
        let mut writer = std::process::Command::new("sh")
            .args(["-c", "cat >\"$1\" && chmod 700 \"$1\"", "sh"])
            .arg(&script)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("{e:?}"))?;
        std::io::Write::write_all(
            &mut writer.stdin.take().ok_or("the writer's stdin")?,
            format!(
                "#!/bin/sh\ncat > /dev/null\ni=0\n\
                 while [ ! -e '{}' ] && [ \"$i\" -lt 600 ]; do sleep 0.1; i=$((i+1)); done\n\
                 printf '%s' '{{\"analysis\":[{{\"type\":\
                 \"transcript\",\"vendor\":\"t\",\"encoding\":\"none\",\"body\":\"x\"}}]}}'\n",
                release.display()
            )
            .as_bytes(),
        )
        .map_err(|e| format!("{e:?}"))?;
        assert!(writer.wait().map_err(|e| format!("{e:?}"))?.success());
        let dir = tmp.path().join("calls");
        let mut rule = test_rule("calls", "response_code >= 400", &dir, RuleAudio::Omit)?;
        rule.enrich = crate::app::vcon_enrich::services(
            &[crate::config::VconEnrichConfig {
                name: "stt".into(),
                rules: vec!["calls".into()],
                command: Some(script),
                ..Default::default()
            }],
            &["calls"],
        )?;
        let rules = vec![rule];
        let store = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let mut trackers = vec![LiveVconTracker::default()];
        let later = swept_after(&store)?;
        let read = CaptureRead {
            dialogs: &store,
            streams: &streams,
            frames_read: 4,
        };
        let n = live_rules_sweep(
            &Cli::parse_from_args(["sipnab"]),
            &rules,
            read,
            None,
            &mut trackers,
            later,
        );
        assert_eq!(n, 1, "the call is counted when it is queued");
        let written = std::fs::read_dir(&dir).map_or(0, Iterator::count);
        assert_eq!(
            written, 0,
            "the sweep returned after the container was written, so it waited \
             for the service it should have queued"
        );
        std::fs::write(&release, b"").map_err(|e| format!("{e:?}"))?;
        // A ceiling on a wait that ends as soon as the worker is done, not a
        // measurement: once the script sees the release file, the worker has
        // only the service's answer left to attach and write.
        assert!(
            crate::app::vcon_enrich::queue()
                .drain(std::time::Instant::now() + std::time::Duration::from_secs(60)),
            "the worker finished"
        );
        let file = std::fs::read_dir(&dir)
            .map_err(|e| format!("{e:?}"))?
            .filter_map(Result::ok)
            .find(|e| e.path().to_string_lossy().ends_with(".vcon.json"))
            .ok_or("a container")?;
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(file.path()).map_err(|e| format!("{e:?}"))?)?;
        assert!(
            v["analysis"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x["type"] == "transcript")),
            "{v}"
        );
        Ok(())
    }

    /// The enrichment worker writes a call of an encrypting rule in the
    /// encrypted form, as the direct write does.
    #[cfg(all(feature = "vcon", unix))]
    #[test]
    fn the_enrichment_worker_writes_an_encrypting_rules_call_encrypted() -> Result<(), TestError> {
        use std::os::unix::fs::PermissionsExt as _;
        let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let key = tmp.path().join("sign.key");
        std::fs::copy(format!("{fixtures}/fake_grp.key"), &key).map_err(|e| format!("{e:?}"))?;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{e:?}"))?;
        let cert = std::path::PathBuf::from(format!("{fixtures}/fake_grp.crt"));
        let mut rule = test_rule("calls", "method == 'INVITE'", tmp.path(), RuleAudio::Omit)?;
        rule.sealing = Some(std::sync::Arc::new(crate::output::vcon_jose::load_sealing(
            std::slice::from_ref(&cert),
            &key,
            &cert,
        )?));
        rule.enrich = crate::app::vcon_enrich::services(
            &[crate::config::VconEnrichConfig {
                name: "stt".into(),
                rules: vec!["calls".into()],
                command: Some("/bin/true".into()),
                ..Default::default()
            }],
            &["calls"],
        )?;
        let store = two_dialogs_one_failed()?;
        let dialog = store.get("ok-call@example.com").ok_or("fixture")?;
        let container = crate::output::vcon::export_dialog(
            dialog,
            &crate::output::vcon::ExportContext {
                capture_id: "x",
                facts: &crate::analysis::CaptureFacts::default(),
                analysis: None,
                max_inline_media_bytes: None,
                media: &[],
                related_legs: &[],
            },
        );
        let path = tmp.path().join("x.vcon.json");
        let queue = crate::app::vcon_enrich::Queue::start(4);
        let back = queue_enrichment(
            &Cli::parse_from_args(["sipnab"]),
            container,
            &[dialog],
            &StreamStore::new(16),
            &VconTarget::of(&rule),
            &path,
            &queue,
        );
        assert!(back.is_none(), "queued");
        assert!(queue.drain(std::time::Instant::now() + std::time::Duration::from_secs(30)));
        let bytes = std::fs::read(&path).map_err(|e| format!("{e:?}"))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(
            crate::output::vcon_jose::form_of(&value),
            crate::output::vcon_jose::Form::Encrypted,
            "{value}"
        );
        let pem = std::fs::read_to_string(format!("{fixtures}/fake_grp.key"))
            .map_err(|e| format!("{e:?}"))?;
        let inner =
            crate::output::vcon_jose::verify(&crate::output::vcon_jose::decrypt(&bytes, &pem)?)?;
        let inner: serde_json::Value = serde_json::from_slice(&inner)?;
        assert!(inner["analysis"].is_array(), "{inner}");
        Ok(())
    }

    /// A call that finds the enrichment queue full comes back to be written at
    /// once, recording every service as `queue-full`.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_full_enrichment_queue_hands_the_call_back_saying_so() -> Result<(), TestError> {
        let queue = crate::app::vcon_enrich::Queue::start(0);
        let (open, gate) = std::sync::mpsc::channel::<()>();
        let blocker = crate::app::vcon_enrich::Job {
            container: crate::output::vcon::Vcon {
                vcon: "0.4.0",
                uuid: String::new(),
                created_at: String::new(),
                updated_at: None,
                subject: String::new(),
                redacted: None,
                amended: None,
                extensions: Vec::new(),
                parties: Vec::new(),
                dialog: Vec::new(),
                attachments: Vec::new(),
                analysis: Vec::new(),
            },
            audio: Vec::new(),
            services: Vec::new(),
            finish: Box::new(move |_, _| {
                let _ = gate.recv();
            }),
        };
        // A rendezvous queue takes a job only while the worker waits for one.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut held = queue.submit(blocker);
        while let Err(job) = held {
            assert!(
                std::time::Instant::now() < deadline,
                "the worker never took a job"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
            held = queue.submit(*job);
        }
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let mut rule = test_rule("calls", "method == 'INVITE'", tmp.path(), RuleAudio::Omit)?;
        rule.enrich = crate::app::vcon_enrich::services(
            &[crate::config::VconEnrichConfig {
                name: "stt".into(),
                rules: vec!["calls".into()],
                command: Some("/bin/true".into()),
                ..Default::default()
            }],
            &["calls"],
        )?;
        let store = two_dialogs_one_failed()?;
        let dialog = store.get("ok-call@example.com").ok_or("fixture")?;
        let container = crate::output::vcon::export_dialog(
            dialog,
            &crate::output::vcon::ExportContext {
                capture_id: "x",
                facts: &crate::analysis::CaptureFacts::default(),
                analysis: None,
                max_inline_media_bytes: None,
                media: &[],
                related_legs: &[],
            },
        );
        let target = VconTarget::of(&rule);
        let back = queue_enrichment(
            &Cli::parse_from_args(["sipnab"]),
            container,
            &[dialog],
            &StreamStore::new(16),
            &target,
            &tmp.path().join("x.vcon.json"),
            &queue,
        )
        .ok_or("the call comes back")?;
        let attachment = back
            .attachments
            .iter()
            .find(|a| a.purpose == crate::app::vcon_enrich::ENRICHMENT_PURPOSE)
            .ok_or("an enrichment attachment")?;
        let body = &attachment.body;
        assert_eq!(body["services"][0]["outcome"], "queue-full", "{body}");
        assert_eq!(body["services"][0]["sent"], serde_json::json!([]), "{body}");
        let _ = open.send(());
        Ok(())
    }

    /// A `live = true` rule writes a call's container as soon as the call
    /// starts, rewrites it in place under the same uuid each time the call
    /// changes, keeping `created_at` and moving `updated_at`, and writes
    /// nothing when nothing changed.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_rule_writes_at_call_start_and_rewrites_in_place() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dir = tmp.path().join("live");
        let mut rule = test_rule("live", "method == 'INVITE'", &dir, RuleAudio::Omit)?;
        rule.live = true;
        let rules = vec![rule];
        let cli = Cli::parse_from_args(["sipnab"]);
        let streams = StreamStore::new(16);
        let mut trackers = vec![LiveVconTracker::default()];
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_msg("live-call@example.com")?);
        let read_one = |store: &DialogStore| -> Result<serde_json::Value, TestError> {
            let entries: Vec<_> = std::fs::read_dir(&dir)
                .map_err(|e| format!("{e:?}"))?
                .filter_map(Result::ok)
                .filter(|e| e.path().to_string_lossy().ends_with(".vcon.json"))
                .collect();
            assert_eq!(entries.len(), 1, "one file, rewritten in place");
            let _ = store;
            Ok(serde_json::from_slice(
                &std::fs::read(entries[0].path()).map_err(|e| format!("{e:?}"))?,
            )?)
        };
        let sweep = |store: &DialogStore, trackers: &mut Vec<LiveVconTracker>| {
            live_rules_sweep(
                &cli,
                &rules,
                CaptureRead {
                    dialogs: store,
                    streams: &streams,
                    frames_read: 1,
                },
                None,
                trackers,
                // No settle period: a live rule writes at once.
                chrono::Utc::now(),
            )
        };

        assert_eq!(
            sweep(&store, &mut trackers),
            1,
            "written as the call starts"
        );
        let first = read_one(&store)?;
        assert!(first["updated_at"].is_string(), "{first}");
        let completeness = |v: &serde_json::Value| -> Result<serde_json::Value, TestError> {
            let body = v["attachments"]
                .as_array()
                .ok_or("attachments")?
                .iter()
                .find(|a| a["purpose"] == "sipnab-capture-completeness")
                .map(|a| a["body"].clone())
                .ok_or("completeness")?;
            Ok(body)
        };
        assert_eq!(completeness(&first)?["call_ended"], false);

        assert_eq!(sweep(&store, &mut trackers), 0, "nothing changed");

        std::thread::sleep(std::time::Duration::from_millis(5));
        store.process_message(response_msg("live-call@example.com", 486, "Busy Here")?);
        assert_eq!(
            sweep(&store, &mut trackers),
            1,
            "rewritten as the call ends"
        );
        let last = read_one(&store)?;
        assert_eq!(last["uuid"], first["uuid"], "the same container");
        assert_eq!(last["created_at"], first["created_at"], "created once");
        assert!(
            last["updated_at"].as_str() > first["updated_at"].as_str(),
            "{} then {}",
            first["updated_at"],
            last["updated_at"]
        );
        assert_eq!(completeness(&last)?["call_ended"], true);
        Ok(())
    }

    /// A sealing rule over the fixture keys, writing to `dir`, with
    /// `sealed_updates`.
    #[cfg(all(feature = "vcon", unix))]
    fn sealed_rule(
        dir: &std::path::Path,
        keys: &std::path::Path,
        live: bool,
        sealed_updates: SealedUpdates,
    ) -> Result<VconRule, TestError> {
        use std::os::unix::fs::PermissionsExt as _;
        let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");
        let key = keys.join("sign.key");
        std::fs::copy(format!("{fixtures}/fake_grp.key"), &key).map_err(|e| format!("{e:?}"))?;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{e:?}"))?;
        let cert = std::path::PathBuf::from(format!("{fixtures}/fake_grp.crt"));
        let mut rule = test_rule("sealed", "method == 'INVITE'", dir, RuleAudio::Omit)?;
        rule.live = live;
        rule.sealing = Some(std::sync::Arc::new(crate::output::vcon_jose::load_sealing(
            std::slice::from_ref(&cert),
            &key,
            &cert,
        )?));
        rule.sealed_updates = sealed_updates;
        Ok(rule)
    }

    /// Every sealed container in `dir`, decrypted and verified, by file name.
    #[cfg(all(feature = "vcon", unix))]
    fn opened_containers(dir: &std::path::Path) -> Result<Vec<serde_json::Value>, TestError> {
        let key = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/vcon-jose/fake_grp.key"
        ))
        .map_err(|e| format!("{e:?}"))?;
        let mut paths: Vec<std::path::PathBuf> = match std::fs::read_dir(dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.to_string_lossy().ends_with(".vcon.json"))
                .collect(),
            Err(_) => Vec::new(),
        };
        paths.sort();
        let mut out = Vec::new();
        for path in paths {
            let bytes = std::fs::read(&path).map_err(|e| format!("{e:?}"))?;
            let jws = crate::output::vcon_jose::decrypt(&bytes, &key)?;
            out.push(serde_json::from_slice(&crate::output::vcon_jose::verify(
                &jws,
            )?)?);
        }
        Ok(out)
    }

    /// Run one call through a sealing rule's live sweeps: the INVITE, then a
    /// 180, then a 486, a second apart, one sweep after each. Returns what
    /// each sweep wrote.
    #[cfg(all(feature = "vcon", unix))]
    fn sealed_sweeps(rule: VconRule) -> Result<Vec<usize>, TestError> {
        Ok(sealed_run(rule, &[(180, "Ringing"), (486, "Busy Here")], false)?.0)
    }

    /// The INVITE, then each of `responses`, a second apart, one live sweep
    /// after each; then, with `end_run`, the end-of-run export. Returns what
    /// each sweep wrote and what the end-of-run export wrote.
    #[cfg(all(feature = "vcon", unix))]
    fn sealed_run(
        rule: VconRule,
        responses: &[(u16, &str)],
        end_run: bool,
    ) -> Result<(Vec<usize>, bool), TestError> {
        let rules = vec![rule];
        let cli = Cli::parse_from_args(["sipnab"]);
        let streams = StreamStore::new(16);
        let mut trackers = vec![LiveVconTracker::default()];
        let mut store = DialogStore::new(16, true);
        let mut wrote = Vec::new();
        let mut messages = vec![invite_msg("sealed-call@example.com")?];
        for (code, reason) in responses {
            messages.push(response_msg("sealed-call@example.com", *code, reason)?);
        }
        // Fixed message times, so two runs observe the same call.
        let start = chrono::DateTime::parse_from_rfc3339("2026-01-05T12:00:00Z")
            .map_err(|e| format!("{e:?}"))?
            .with_timezone(&chrono::Utc);
        for (seconds, mut message) in (0_i64..).zip(messages) {
            message.timestamp = start + chrono::TimeDelta::seconds(seconds);
            store.process_message(message);
            wrote.push(live_rules_sweep(
                &cli,
                &rules,
                CaptureRead {
                    dialogs: &store,
                    streams: &streams,
                    frames_read: 1,
                },
                None,
                &mut trackers,
                chrono::Utc::now(),
            ));
        }
        let ended = end_run
            && export_targets_after(
                &cli,
                &[(VconTarget::of(&rules[0]), trackers.first())],
                &VconBatch {
                    dialog_store: &store,
                    stream_store: &streams,
                    frames_read: 1,
                    gate: None,
                    suppressed_by_deny: 0,
                    defer_enrichment: false,
                    first_written: None,
                    sealed_instances: None,
                    now: chrono::Utc::now(),
                },
            );
        Ok((wrote, ended))
    }

    /// The containers of `sealed_sweeps`, ordered as written: the first has
    /// no `amended`, and each later one names the one before it.
    #[cfg(all(feature = "vcon", unix))]
    fn in_chain_order(all: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
        let mut used = vec![false; all.len()];
        let mut ordered = Vec::new();
        let mut prior: Option<usize> = None;
        loop {
            let next = (0..all.len()).find(|&i| {
                !used[i]
                    && match prior {
                        None => all[i].get("amended").is_none(),
                        Some(p) => all[i]["amended"]["uuid"] == all[p]["uuid"],
                    }
            });
            let Some(i) = next else {
                break;
            };
            used[i] = true;
            ordered.push(all[i].clone());
            prior = Some(i);
        }
        for (i, v) in all.iter().enumerate() {
            if !used[i] {
                ordered.push(v.clone());
            }
        }
        ordered
    }

    /// `sealed_updates = "new-uuid"` (the default): a sealing rule's later
    /// write of a call is a new instance with its own uuid, naming the prior
    /// instance in `amended`, keeping the first `created_at`, and the earlier
    /// files stay.
    ///
    /// [Section 4.1.9 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.9):
    /// "A signed or encrypted vCon cannot be modified without invalidating
    /// it. In these cases, to allow for adding of additional information a new
    /// vCon instance version MUST be created."
    #[cfg(all(feature = "vcon", unix))]
    #[test]
    fn a_sealed_rewrite_is_a_new_instance_naming_the_prior_one() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dir = tmp.path().join("sealed");
        let rule = sealed_rule(&dir, tmp.path(), true, SealedUpdates::NewUuid)?;
        assert_eq!(sealed_sweeps(rule)?, [1, 1, 1], "one write per change");
        let chain = in_chain_order(opened_containers(&dir)?);
        assert_eq!(chain.len(), 3, "three instances, none replaced");
        let uuids: Vec<&str> = chain.iter().filter_map(|v| v["uuid"].as_str()).collect();
        assert_eq!(uuids.len(), 3);
        assert!(
            uuids[0] != uuids[1] && uuids[1] != uuids[2] && uuids[0] != uuids[2],
            "the three instances have three different uuids"
        );
        assert!(chain[0].get("amended").is_none());
        assert_eq!(chain[1]["amended"]["uuid"], uuids[0]);
        assert_eq!(chain[2]["amended"]["uuid"], uuids[1]);
        for v in &chain {
            assert_eq!(v["created_at"], chain[0]["created_at"], "created once");
            assert!(v["updated_at"].is_string());
        }
        assert_eq!(
            chain[2]["uuid"],
            crate::output::vcon::revision_uuid(uuids[0], 2)
        );
        Ok(())
    }

    /// Two runs over the same call give the same uuid chain: each later uuid
    /// is a function of the first and the revision number, not of the clock.
    #[cfg(all(feature = "vcon", unix))]
    #[test]
    fn a_sealed_uuid_chain_is_the_same_on_every_run() -> Result<(), TestError> {
        let mut chains = Vec::new();
        for _ in 0..2 {
            let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
            let dir = tmp.path().join("sealed");
            sealed_sweeps(sealed_rule(&dir, tmp.path(), true, SealedUpdates::NewUuid)?)?;
            let chain: Vec<serde_json::Value> = in_chain_order(opened_containers(&dir)?)
                .iter()
                .map(|v| v["uuid"].clone())
                .collect();
            chains.push(chain);
        }
        assert_eq!(chains[0].len(), 3, "{chains:?}");
        assert_eq!(chains[0], chains[1]);
        Ok(())
    }

    /// `sealed_updates = "same-uuid"`: the sealed file is rewritten under the
    /// one uuid, as before the setting existed, with no `amended`.
    #[cfg(all(feature = "vcon", unix))]
    #[test]
    fn same_uuid_rewrites_the_sealed_file_in_place() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dir = tmp.path().join("sealed");
        let rule = sealed_rule(&dir, tmp.path(), true, SealedUpdates::SameUuid)?;
        assert_eq!(sealed_sweeps(rule)?, [1, 1, 1]);
        let all = opened_containers(&dir)?;
        assert_eq!(all.len(), 1, "one file, rewritten");
        assert!(all[0].get("amended").is_none());
        Ok(())
    }

    /// `same-uuid` on a sealing rule is warned about at startup, naming the
    /// rule and the two sections it departs from; nothing else is.
    #[cfg(all(feature = "vcon", unix))]
    #[test]
    fn only_a_sealing_same_uuid_rule_is_warned_about() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dir = tmp.path().join("sealed");
        let warning = sealed_rule(&dir, tmp.path(), true, SealedUpdates::SameUuid)?
            .sealed_updates_warning()
            .ok_or("same-uuid on a sealing rule warns")?;
        for needle in [
            "'sealed'",
            "same-uuid",
            "section 4.1.9",
            "section 4.1.2",
            "MUST",
        ] {
            assert!(
                warning.contains(needle),
                "the startup warning lacks a required phrase"
            );
        }
        for updates in [SealedUpdates::NewUuid, SealedUpdates::FinalOnly] {
            let rule = sealed_rule(&dir, tmp.path(), true, updates)?;
            assert_eq!(rule.sealed_updates_warning(), None, "{updates:?}");
        }
        let mut unsealed = test_rule("plain", "method == 'INVITE'", &dir, RuleAudio::Omit)?;
        unsealed.sealed_updates = SealedUpdates::SameUuid;
        assert_eq!(unsealed.sealed_updates_warning(), None, "nothing is sealed");
        Ok(())
    }

    /// `sealed_updates = "final-only"`: nothing is written while the call is
    /// in progress, then one sealed container once it ends, and no further
    /// one after that.
    #[cfg(all(feature = "vcon", unix))]
    #[test]
    fn final_only_seals_once_when_the_call_ends() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dir = tmp.path().join("sealed");
        let rule = sealed_rule(&dir, tmp.path(), true, SealedUpdates::FinalOnly)?;
        assert_eq!(
            sealed_sweeps(rule)?,
            [0, 0, 1],
            "nothing before the call ends, then one write"
        );
        let all = opened_containers(&dir)?;
        assert_eq!(all.len(), 1);
        let body = all[0]["attachments"]
            .as_array()
            .ok_or("attachments")?
            .iter()
            .find(|a| a["purpose"] == "sipnab-capture-completeness")
            .map(|a| a["body"].clone())
            .ok_or("completeness")?;
        assert_eq!(body["call_ended"], true, "{body}");
        assert!(all[0].get("amended").is_none());
        Ok(())
    }

    /// A sealing rule that is not `live` writes a call once it ends or has
    /// been quiet for the idle period (the fixture's messages are months old,
    /// so the INVITE alone is idle), and each later change is a new instance
    /// naming the one before, with the first `created_at`.
    #[cfg(all(feature = "vcon", unix))]
    #[test]
    fn a_sealed_rewrite_by_a_rule_that_is_not_live_is_a_new_instance() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dir = tmp.path().join("sealed");
        let rule = sealed_rule(&dir, tmp.path(), false, SealedUpdates::NewUuid)?;
        let (wrote, _) = sealed_run(rule, &[(486, "Busy Here"), (486, "Busy Here")], false)?;
        assert_eq!(wrote, [1, 1, 1], "idle, ended, then changed");
        let chain = in_chain_order(opened_containers(&dir)?);
        assert_eq!(chain.len(), 3);
        for i in 1..3 {
            assert_eq!(chain[i]["amended"]["uuid"], chain[i - 1]["uuid"]);
            assert_ne!(chain[i]["uuid"], chain[i - 1]["uuid"]);
            assert_eq!(
                chain[i]["created_at"], chain[0]["created_at"],
                "created once"
            );
            assert!(chain[i]["updated_at"].is_string());
        }
        assert!(chain[0].get("updated_at").is_none());
        Ok(())
    }

    /// `final-only` seals a call once: a change after the sealed write, and
    /// the end of the run, write nothing more.
    #[cfg(all(feature = "vcon", unix))]
    #[test]
    fn final_only_never_seals_a_call_twice() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dir = tmp.path().join("sealed");
        let rule = sealed_rule(&dir, tmp.path(), true, SealedUpdates::FinalOnly)?;
        let (wrote, exported) = sealed_run(rule, &[(486, "Busy Here"), (486, "Busy Here")], true)?;
        assert_eq!(wrote, [0, 1, 0], "one sealed write, at the end of the call");
        assert!(exported, "the end-of-run export succeeds");
        assert_eq!(opened_containers(&dir)?.len(), 1);
        Ok(())
    }

    /// `final-only` on a call still in progress when the run ends: nothing
    /// while it runs, then one sealed container at the end of the run, which
    /// records that the call had not ended. Nothing more is captured after
    /// that, so this is the call's last state.
    #[cfg(all(feature = "vcon", unix))]
    #[test]
    fn final_only_seals_an_unended_call_once_when_the_run_ends() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dir = tmp.path().join("sealed");
        let rule = sealed_rule(&dir, tmp.path(), true, SealedUpdates::FinalOnly)?;
        let (wrote, exported) = sealed_run(rule, &[(180, "Ringing")], true)?;
        assert_eq!(wrote, [0, 0], "nothing while the call runs");
        assert!(exported, "the end-of-run export succeeds");
        let all = opened_containers(&dir)?;
        assert_eq!(all.len(), 1);
        let ended = all[0]["attachments"]
            .as_array()
            .ok_or("attachments")?
            .iter()
            .find(|a| a["purpose"] == "sipnab-capture-completeness")
            .map(|a| a["body"]["call_ended"].clone())
            .ok_or("completeness")?;
        assert_eq!(ended, false);
        Ok(())
    }

    /// `audio_format`: unset and `wav` are WAV, `opus` is Ogg Opus in a build
    /// with the `opus` feature and refused, naming the feature, in one
    /// without; any other value is refused naming both.
    #[test]
    fn audio_format_parses_wav_and_opus_and_refuses_opus_without_the_feature() {
        for built in [true, false] {
            assert_eq!(
                RuleAudioFormat::parse(None, built),
                Ok(RuleAudioFormat::Wav)
            );
            assert_eq!(
                RuleAudioFormat::parse(Some("wav"), built),
                Ok(RuleAudioFormat::Wav)
            );
            let other = RuleAudioFormat::parse(Some("mp3"), built);
            assert_eq!(
                other,
                Err("audio_format = 'mp3'; use 'wav' or 'opus'".to_owned())
            );
        }
        assert_eq!(
            RuleAudioFormat::parse(Some("opus"), true),
            Ok(RuleAudioFormat::Opus)
        );
        let refused = RuleAudioFormat::parse(Some("opus"), false)
            .err()
            .unwrap_or_default();
        assert!(refused.contains("`opus` feature"), "{refused}");
        assert_eq!(RuleAudioFormat::OPUS_BUILT, cfg!(feature = "opus"));
    }

    /// The three `sealed_updates` names parse, unset is `new-uuid`, and any
    /// other value is refused naming all three.
    #[cfg(feature = "vcon")]
    #[test]
    fn sealed_updates_parses_its_three_names_and_refuses_others() {
        assert_eq!(SealedUpdates::parse(None), Ok(SealedUpdates::NewUuid));
        assert_eq!(
            SealedUpdates::parse(Some("new-uuid")),
            Ok(SealedUpdates::NewUuid)
        );
        assert_eq!(
            SealedUpdates::parse(Some("same-uuid")),
            Ok(SealedUpdates::SameUuid)
        );
        assert_eq!(
            SealedUpdates::parse(Some("final-only")),
            Ok(SealedUpdates::FinalOnly)
        );
        for bad in ["", "new_uuid", "New-UUID", "always"] {
            let parsed = SealedUpdates::parse(Some(bad));
            assert!(parsed.is_err(), "'{bad}' parsed as {parsed:?}");
            let why = parsed.err().unwrap_or_default();
            for name in SealedUpdates::NAMES {
                assert!(why.contains(name), "{bad}: {why}");
            }
        }
    }

    /// The vCon a rule writes for one call at the end of a run, read back.
    #[cfg(feature = "vcon")]
    fn only_container(dir: &std::path::Path) -> Result<serde_json::Value, TestError> {
        let entries: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| format!("{e:?}"))?
            .filter_map(Result::ok)
            .filter(|e| e.path().to_string_lossy().ends_with(".vcon.json"))
            .collect();
        assert_eq!(entries.len(), 1, "one container in {}", dir.display());
        Ok(serde_json::from_slice(
            &std::fs::read(entries[0].path()).map_err(|e| format!("{e:?}"))?,
        )?)
    }

    /// `live = true` means something only on a live capture: an `-I` run
    /// writes the container a rule without it writes, with no `updated_at`.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_rule_on_a_file_run_writes_what_any_rule_writes() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let mut live = test_rule(
            "live",
            "method == 'INVITE'",
            &tmp.path().join("live"),
            RuleAudio::Omit,
        )?;
        live.live = true;
        let plain = test_rule(
            "plain",
            "method == 'INVITE'",
            &tmp.path().join("plain"),
            RuleAudio::Omit,
        )?;
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_msg("file-call@example.com")?);
        store.process_message(response_msg("file-call@example.com", 486, "Busy Here")?);
        assert!(export_vcon(
            &Cli::parse_from_args(["sipnab"]),
            &[live, plain],
            &store,
            &StreamStore::new(16),
            1,
            None,
            VconRunEnd::Whole,
        ));
        let live = only_container(&tmp.path().join("live"))?;
        let plain = only_container(&tmp.path().join("plain"))?;
        assert!(plain.get("updated_at").is_none(), "{plain}");
        assert!(live.get("updated_at").is_none(), "{live}");
        Ok(())
    }

    /// The end of a live run that rewrites a call a `live = true` rule wrote
    /// while it was in progress keeps the `created_at` of its first write.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_end_of_a_live_run_keeps_a_live_rule_s_first_write_time() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dir = tmp.path().join("live");
        let mut rule = test_rule("live", "method == 'INVITE'", &dir, RuleAudio::Omit)?;
        rule.live = true;
        let rules = vec![rule];
        let cli = Cli::parse_from_args(["sipnab"]);
        let streams = StreamStore::new(16);
        let mut trackers = vec![LiveVconTracker::default()];
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_msg("end-call@example.com")?);
        assert_eq!(
            live_rules_sweep(
                &cli,
                &rules,
                CaptureRead {
                    dialogs: &store,
                    streams: &streams,
                    frames_read: 1,
                },
                None,
                &mut trackers,
                chrono::Utc::now(),
            ),
            1
        );
        let first = only_container(&dir)?;
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.process_message(response_msg("end-call@example.com", 486, "Busy Here")?);
        assert!(export_vcon(
            &cli,
            &rules,
            &store,
            &streams,
            1,
            None,
            VconRunEnd::AfterLive(&trackers),
        ));
        let last = only_container(&dir)?;
        assert_eq!(last["uuid"], first["uuid"], "the same container");
        assert_eq!(last["created_at"], first["created_at"], "created once");
        assert!(
            last["updated_at"].as_str() > first["updated_at"].as_str(),
            "{} then {}",
            first["updated_at"],
            last["updated_at"]
        );
        Ok(())
    }

    /// A call an omit rule wrote keeps its audio while an inline-audio rule
    /// that selects it has not written it, and gives it back once it has.
    #[cfg(feature = "vcon")]
    #[test]
    fn audio_is_held_until_every_inline_rule_has_written_the_call() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let blocked = tmp.path().join("blocked");
        std::fs::write(
            &blocked,
            b"a file where the inline rule's directory belongs",
        )
        .map_err(|e| format!("{e:?}"))?;
        let rules = vec![
            test_rule(
                "omit",
                "response_code >= 400",
                &tmp.path().join("omit"),
                RuleAudio::Omit,
            )?,
            test_rule(
                "inline",
                "response_code >= 400",
                &blocked,
                RuleAudio::Inline,
            )?,
        ];
        let mut trackers: Vec<LiveVconTracker> =
            (0..2).map(|_| LiveVconTracker::default()).collect();
        let read_store = two_dialogs_one_failed()?;
        let later = swept_after(&read_store)?;
        let streams = StreamStore::new(16);
        let read = CaptureRead {
            dialogs: &read_store,
            streams: &streams,
            frames_read: 4,
        };
        let cli = Cli::parse_from_args(["sipnab"]);
        live_rules_sweep(&cli, &rules, read, None, &mut trackers, later);
        let call = "failed-call@example.com".to_string();
        assert!(
            trackers[0].written_at(&call).is_some(),
            "the omit rule wrote it"
        );
        assert!(trackers[1].failed(), "the inline rule could not");
        assert!(trackers[0].held.contains(&call), "so its audio is held");
        assert!(!trackers[0].unreleased.contains(&call), "and not released");

        // The inline rule's directory becomes writable: the next sweep writes
        // the call there and releases its audio.
        std::fs::remove_file(&blocked).map_err(|e| format!("{e:?}"))?;
        live_rules_sweep(&cli, &rules, read, None, &mut trackers, later);
        assert!(
            trackers[1].written_at(&call).is_some(),
            "the inline rule wrote it"
        );
        assert!(
            !trackers[0].held.contains(&call),
            "nothing is held any more"
        );
        assert!(trackers[0].unreleased.contains(&call), "so it is released");
        Ok(())
    }

    /// A final dialog quiet for the settle period, never written, is due.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_final_settled_unwritten_dialog_is_due() -> Result<(), TestError> {
        let t = chrono::Utc::now();
        assert!(live_vcon_due(
            &sip::dialog::DialogState::Completed,
            t,
            t,
            t + settle()?,
            timing()?,
            None
        ));
        Ok(())
    }

    /// A final dialog still inside the settle period is not due yet: a
    /// retransmitted BYE or a late 200 may still arrive.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_final_dialog_inside_the_settle_period_is_not_due() -> Result<(), TestError> {
        let t = chrono::Utc::now();
        let just_short = t + settle()? - chrono::TimeDelta::milliseconds(1);
        assert!(!live_vcon_due(
            &sip::dialog::DialogState::Completed,
            t,
            t,
            just_short,
            timing()?,
            None
        ));
        Ok(())
    }

    /// The timing the live export uses, as the predicate takes it.
    #[cfg(feature = "vcon")]
    fn timing() -> Result<LiveTiming, TestError> {
        Ok(LiveTiming {
            settle: settle()?,
            idle: chrono::TimeDelta::from_std(LIVE_IDLE_WRITE)
                .map_err(|e| format!("the idle period fits: {e:?}"))?,
        })
    }

    /// Idle compaction can drop a call's middle messages before a live export
    /// writes it when `[limits] idle_compact_after_secs` is shorter than the
    /// live idle period. A live export says so at startup; a long enough
    /// setting, or a run with no live export, says nothing.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_compaction_period_shorter_than_the_live_idle_write_is_warned() {
        let idle = LIVE_IDLE_WRITE.as_secs();
        let warning = live_compaction_warning(Some(idle - 1), true).unwrap_or_default();
        assert!(warning.contains("idle_compact_after_secs"), "{warning}");
        assert!(warning.contains(&format!("{}", idle - 1)), "{warning}");
        assert!(live_compaction_warning(Some(idle), true).is_none());
        assert!(
            live_compaction_warning(None, true).is_none(),
            "the default is 600 s"
        );
        assert!(live_compaction_warning(Some(1), false).is_none());
    }

    /// A running dialog is written once it has had no SIP and no RTP for the
    /// idle period, and not before: a call whose BYE was lost was never
    /// written live, and a call on hold a little while is not written early.
    /// Walks every state `is_final` rejects.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_running_dialog_is_due_only_after_the_idle_period() -> Result<(), TestError> {
        let t = chrono::Utc::now();
        let idle = timing()?.idle;
        let running: Vec<_> = sip::dialog::DialogState::ALL
            .into_iter()
            .filter(|s| !s.is_final())
            .collect();
        assert!(!running.is_empty(), "the walk must cover something");
        for state in running {
            let just_short = t + idle - chrono::TimeDelta::milliseconds(1);
            assert!(
                !live_vcon_due(&state, t, t, just_short, timing()?, None),
                "{state:?} quiet for less than the idle period is not written yet"
            );
            assert!(
                live_vcon_due(&state, t, t, t + idle, timing()?, None),
                "{state:?} quiet for the idle period is written, so a lost BYE \
                 still produces a container"
            );
        }
        Ok(())
    }

    /// RTP keeps a running call open: quiet signaling with media still
    /// flowing is a call in progress, not an abandoned one.
    #[cfg(feature = "vcon")]
    #[test]
    fn media_keeps_a_running_dialog_from_being_written() -> Result<(), TestError> {
        let t = chrono::Utc::now();
        let idle = timing()?.idle;
        let media_until = t + chrono::TimeDelta::seconds(100);
        assert!(!live_vcon_due(
            &sip::dialog::DialogState::InCall,
            media_until,
            t,
            t + idle,
            timing()?,
            None
        ));
        assert!(live_vcon_due(
            &sip::dialog::DialogState::InCall,
            media_until,
            t,
            media_until + idle,
            timing()?,
            None
        ));
        Ok(())
    }

    /// A dialog is quiet from the later of its last SIP message and its
    /// streams' last packet, so media alone keeps a held call from looking idle.
    #[cfg(feature = "vcon")]
    #[test]
    fn quiet_since_is_the_later_of_signaling_and_media() -> Result<(), TestError> {
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_msg("quiet@example.com")?);
        let dialog = store
            .get("quiet@example.com")
            .ok_or("the INVITE made a dialog")?;
        assert_eq!(quiet_since(dialog, &[]), dialog.updated_at);
        let mut early = rtp_stream_fixture(4000);
        early.last_seen = dialog.updated_at - chrono::TimeDelta::seconds(5);
        let mut late = rtp_stream_fixture(4002);
        late.last_seen = dialog.updated_at + chrono::TimeDelta::seconds(90);
        assert_eq!(quiet_since(dialog, &[&early]), dialog.updated_at);
        assert_eq!(quiet_since(dialog, &[&early, &late]), late.last_seen);
        Ok(())
    }

    /// A running dialog written after the idle period is not written again
    /// until it changes; the BYE that ends it later is a change, and rewrites.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_idle_written_dialog_is_rewritten_only_when_it_changes() -> Result<(), TestError> {
        let t = chrono::Utc::now();
        let later = t + timing()?.idle * 2;
        assert!(!live_vcon_due(
            &sip::dialog::DialogState::InCall,
            t,
            t,
            later,
            timing()?,
            Some(t)
        ));
        let bye = later;
        assert!(live_vcon_due(
            &sip::dialog::DialogState::Completed,
            bye,
            bye,
            bye + settle()?,
            timing()?,
            Some(t)
        ));
        Ok(())
    }

    /// A dialog already written at its current `updated_at` is not written
    /// again; one that changed since is.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_dialog_is_written_again_only_when_it_changed() -> Result<(), TestError> {
        let t = chrono::Utc::now();
        let now = t + settle()?;
        let state = sip::dialog::DialogState::Failed;
        assert!(
            !live_vcon_due(&state, t, t, now, timing()?, Some(t)),
            "written at this updated_at already"
        );
        assert!(
            live_vcon_due(
                &state,
                t,
                t,
                now,
                timing()?,
                Some(t - chrono::TimeDelta::seconds(1))
            ),
            "the dialog changed after it was written, so it is owed again"
        );
        Ok(())
    }

    /// The tracker forgets dialogs the store no longer holds and keeps the
    /// rest, so it cannot outgrow the store it describes.
    #[test]
    fn the_live_tracker_prunes_dialogs_the_store_dropped() {
        let t = chrono::Utc::now();
        let mut tracker = LiveVconTracker::default();
        tracker.record("kept", t);
        tracker.record("gone", t);
        tracker.prune(|id| id == "kept");
        assert_eq!(tracker.len(), 1, "only the held dialog survives");
        assert_eq!(tracker.written_at("kept"), Some(t));
        assert_eq!(tracker.written_at("gone"), None);
    }

    /// A live sweep writes the ended, settled, matching dialog, not the
    /// running one, and does not write it twice.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_sweep_writes_ended_settled_calls_once() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let mut tracker = LiveVconTracker::default();
        let later = swept_after(&dialogs)?;

        let n = live_vcon_sweep(
            &cli,
            None,
            CaptureRead {
                dialogs: &dialogs,
                streams: &streams,
                frames_read: 4,
            },
            None,
            &mut tracker,
            later,
        );
        assert_eq!(n, 1, "only the failed (ended) call is due");
        let files = containers_in(tmp.path())?;
        assert_eq!(files.len(), 1, "{files:?}");
        let text = std::fs::read_to_string(&files[0]).map_err(|e| format!("readable: {e:?}"))?;
        assert!(text.contains("failed-call@example.com"), "{text}");
        assert!(!tracker.failed());

        let again = live_vcon_sweep(
            &cli,
            None,
            CaptureRead {
                dialogs: &dialogs,
                streams: &streams,
                frames_read: 4,
            },
            None,
            &mut tracker,
            later,
        );
        assert_eq!(again, 0, "a written call is not written again unchanged");
        Ok(())
    }

    /// One 20 ms PCMU frame from `10.0.0.1:src_port`, sequence `seq`.
    #[cfg(feature = "vcon")]
    fn pcmu_frame(
        src_port: u16,
        ssrc: u32,
        seq: u16,
    ) -> (ParsedPacket, crate::rtp::parser::RtpHeader) {
        let mut payload = vec![0x80, 0x00];
        payload.extend_from_slice(&seq.to_be_bytes());
        payload.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
        payload.extend_from_slice(&ssrc.to_be_bytes());
        payload.extend_from_slice(&[0x55; 160]);
        let header = crate::rtp::parser::RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: seq,
            timestamp: u32::from(seq) * 160,
            ssrc,
            payload_offset: 12,
        };
        let packet = ParsedPacket {
            src_port,
            payload: bytes::Bytes::from(payload),
            ..rtp_dtmf_packet(30000, 0, ssrc, 0, 0)
        };
        (packet, header)
    }

    /// A live sweep's written calls release their retained audio, and only
    /// theirs, so ended calls do not accumulate audio for the whole run.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_sweep_releases_the_audio_of_the_calls_it_wrote() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let dialogs = two_dialogs_one_failed()?;
        let mut streams = StreamStore::new(16);
        for (port, ssrc) in [(40010u16, 0xF001u32), (40011, 0xF002)] {
            for seq in 0..50u16 {
                let (packet, header) = pcmu_frame(port, ssrc, seq);
                streams.process_rtp(&packet, &header, packet.timestamp);
            }
        }
        let caller = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        streams.link_to_dialog(caller, 40010, "failed-call@example.com");
        streams.link_to_dialog(caller, 40011, "ok-call@example.com");
        let mut tracker = LiveVconTracker::default();
        let later = swept_after(&dialogs)?;

        let written = live_vcon_sweep(
            &cli,
            None,
            CaptureRead {
                dialogs: &dialogs,
                streams: &streams,
                frames_read: 4,
            },
            None,
            &mut tracker,
            later,
        );
        assert_eq!(written, 1, "only the ended call is written");
        assert_eq!(
            release_exported_audio(&mut tracker, &mut streams),
            50,
            "the written call's 50 frames are released"
        );
        let ended = streams
            .streams_for("failed-call@example.com")
            .next()
            .ok_or("the ended call's stream")?;
        assert!(ended.payload_buffer.is_empty());
        assert_eq!(ended.payload_frames_released_after_export, 50);
        let ongoing = streams
            .streams_for("ok-call@example.com")
            .next()
            .ok_or("the ongoing call's stream")?;
        assert_eq!(
            ongoing.payload_buffer.len(),
            50,
            "a call not written keeps its audio"
        );
        assert_eq!(
            release_exported_audio(&mut tracker, &mut streams),
            0,
            "a call is released once"
        );
        Ok(())
    }

    /// A live sweep that owes a container and cannot create the directory
    /// for it writes nothing and marks the run failed, so it ends non-zero.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_sweep_that_cannot_create_its_directory_fails_the_run() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let blocker = tmp.path().join("a-file");
        std::fs::write(&blocker, b"not a directory").map_err(|e| format!("write: {e:?}"))?;
        let cli = cli_exporting_to(&blocker.join("spool"), "response_code >= 200");
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let mut tracker = LiveVconTracker::default();
        let later = swept_after(&dialogs)?;

        let n = live_vcon_sweep(
            &cli,
            None,
            CaptureRead {
                dialogs: &dialogs,
                streams: &streams,
                frames_read: 4,
            },
            None,
            &mut tracker,
            later,
        );
        assert_eq!(n, 0);
        assert!(
            tracker.failed(),
            "a container owed and not written fails the run"
        );
        assert!(
            tracker.is_empty(),
            "nothing was written, so nothing is recorded"
        );
        Ok(())
    }

    /// A gate closed at sweep time writes nothing, and that is not a failure:
    /// the operator closed it.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_sweep_behind_a_closed_gate_writes_nothing_and_fails_nothing() -> Result<(), TestError>
    {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let mut tracker = LiveVconTracker::default();
        let later = swept_after(&dialogs)?;
        let gate = crate::output::persistence::PersistenceGate::new(false);

        let n = live_vcon_sweep(
            &cli,
            None,
            CaptureRead {
                dialogs: &dialogs,
                streams: &streams,
                frames_read: 4,
            },
            Some(&gate),
            &mut tracker,
            later,
        );
        assert_eq!(n, 0);
        assert_eq!(
            std::fs::read_dir(tmp.path())
                .map_err(|e| format!("readable: {e:?}"))?
                .count(),
            0,
            "a closed gate writes nothing"
        );
        assert!(!tracker.failed());
        Ok(())
    }

    /// A live sweep inside the settle period writes nothing and creates no
    /// directory: the analysis and the directory wait for a due dialog.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_sweep_before_the_settle_period_writes_nothing() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let spool = tmp.path().join("spool");
        let cli = cli_exporting_to(&spool, "response_code >= 200");
        let mut tracker = LiveVconTracker::default();
        let n = live_vcon_sweep(
            &cli,
            None,
            CaptureRead {
                dialogs: &two_dialogs_one_failed()?,
                streams: &StreamStore::new(16),
                frames_read: 4,
            },
            None,
            &mut tracker,
            chrono::Utc::now(),
        );
        assert_eq!(n, 0);
        assert!(!spool.exists(), "nothing was due, so nothing was created");
        Ok(())
    }

    /// The deny header applies to the live export exactly as at the end of a
    /// run, because both select through `vcon_selection`.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_sweep_honors_the_deny_header() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let mut cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_with_header(
            "denied@example.com",
            "X-No-Record",
            "1",
        )?);
        store.process_message(response_msg("denied@example.com", 486, "Busy Here")?);
        let mut tracker = LiveVconTracker::default();
        let later = swept_after(&store)?;
        let n = live_vcon_sweep(
            &cli,
            None,
            CaptureRead {
                dialogs: &store,
                streams: &StreamStore::new(16),
                frames_read: 2,
            },
            None,
            &mut tracker,
            later,
        );
        assert_eq!(n, 0, "a denied call must not be written live");
        Ok(())
    }

    /// A signal stop writes nothing at the end of a live run; a natural end
    /// writes what the sweeps did not; a run with no live export writes all.
    #[cfg(feature = "vcon")]
    #[test]
    fn how_a_run_ended_decides_what_its_end_writes() {
        let tracker = LiveVconTracker::default();
        assert!(matches!(
            vcon_run_end(Some(std::slice::from_ref(&tracker)), true),
            VconRunEnd::Stopped
        ));
        assert!(matches!(
            vcon_run_end(Some(std::slice::from_ref(&tracker)), false),
            VconRunEnd::AfterLive(_)
        ));
        assert!(matches!(vcon_run_end(None, true), VconRunEnd::Whole));
        assert!(matches!(vcon_run_end(None, false), VconRunEnd::Whole));
    }

    /// The end of a signal-stopped live run writes no container, and says
    /// it succeeded: the stop is what the operator asked for.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_stopped_live_run_writes_nothing_at_its_end() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let spool = tmp.path().join("spool");
        assert!(export_vcon(
            &cli_exporting_to(&spool, "response_code >= 200"),
            &[],
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            4,
            None,
            VconRunEnd::Stopped,
        ));
        assert!(!spool.exists(), "a stop is never a flush");
        Ok(())
    }

    /// A live run that ends on its own skips what the sweeps already wrote at
    /// the same `updated_at`, and writes a dialog that changed since.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_natural_end_skips_what_the_live_sweeps_wrote() -> Result<(), TestError> {
        let dialogs = two_dialogs_one_failed()?;
        let failed = dialogs.get("failed-call@example.com").ok_or("fixture")?;
        let ok = dialogs.get("ok-call@example.com").ok_or("fixture")?;

        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let mut tracker = LiveVconTracker::default();
        tracker.record(&failed.call_id, failed.updated_at);
        assert!(export_vcon(
            &cli_exporting_to(tmp.path(), "response_code >= 200"),
            &[],
            &dialogs,
            &StreamStore::new(16),
            4,
            None,
            VconRunEnd::AfterLive(std::slice::from_ref(&tracker)),
        ));
        let names: Vec<String> = containers_in(tmp.path())?
            .iter()
            .map(|p| std::fs::read_to_string(p).map_err(|e| format!("readable: {e:?}")))
            .collect::<Result<_, _>>()?;
        assert_eq!(names.len(), 1, "only the call the sweeps did not write");
        assert!(names[0].contains("ok-call@example.com"));

        let changed = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let mut stale = LiveVconTracker::default();
        stale.record(
            &failed.call_id,
            failed.updated_at - chrono::TimeDelta::seconds(1),
        );
        stale.record(&ok.call_id, ok.updated_at);
        assert!(export_vcon(
            &cli_exporting_to(changed.path(), "response_code >= 200"),
            &[],
            &dialogs,
            &StreamStore::new(16),
            4,
            None,
            VconRunEnd::AfterLive(std::slice::from_ref(&stale)),
        ));
        let files = containers_in(changed.path())?;
        assert_eq!(files.len(), 1, "{files:?}");
        let text = std::fs::read_to_string(&files[0]).map_err(|e| format!("readable: {e:?}"))?;
        assert!(
            text.contains("failed-call@example.com"),
            "a call that changed after it was written is written again"
        );
        Ok(())
    }

    /// A `Cli` exporting the one call `call_id` to `out`, as
    /// `--export-vcon <call_id> --vcon-out <out>` would.
    #[cfg(feature = "vcon")]
    fn cli_exporting_one(out: &std::path::Path, call_id: &str) -> Cli {
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon = Some(call_id.to_owned());
        cli.output_args.vcon_out = Some(out.to_path_buf());
        cli
    }

    /// The end-of-run line never reports a misleading zero.
    ///
    /// A replay call logged `Wrote 1 vCon container(s) ... for calls that
    /// ended` from the live sweep and then `Wrote 0 vCon container(s)` to the
    /// same directory at the end of the run, which reads as an export that
    /// wrote nothing.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_end_of_run_vcon_line_reports_what_the_run_wrote() {
        let dir = std::path::Path::new("spool");
        assert_eq!(
            end_of_run_vcon_summary(3, 0, dir),
            "Wrote 3 vCon container(s) to 'spool'.",
            "a run with no live sweeps keeps the line scripts already read"
        );
        assert_eq!(
            end_of_run_vcon_summary(0, 0, dir),
            "Wrote 0 vCon container(s) to 'spool'.",
            "a run that wrote nothing at all still says so"
        );
        assert_eq!(
            end_of_run_vcon_summary(0, 1, dir),
            "Wrote no further vCon containers to 'spool' at the end of the run; \
             1 container(s) were written there as their calls ended."
        );
        assert_eq!(
            end_of_run_vcon_summary(2, 1, dir),
            "Wrote 2 more vCon container(s) to 'spool' at the end of the run, \
             3 in total with the 1 written as their calls ended."
        );
    }

    /// The tracker counts every container a live sweep wrote, and pruning a
    /// dialog the store dropped does not lower the count.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_sweep_counts_the_containers_it_wrote() -> Result<(), TestError> {
        let dialogs = two_dialogs_one_failed()?;
        let failed = dialogs.get("failed-call@example.com").ok_or("fixture")?;
        let ok = dialogs.get("ok-call@example.com").ok_or("fixture")?;
        let mut tracker = LiveVconTracker::default();
        let dir = std::path::Path::new("spool");
        assert_eq!(
            settle_live_writes(
                &mut tracker,
                &[
                    ContainerUnit::Leg(failed, false),
                    ContainerUnit::Leg(ok, false)
                ],
                dir,
                Ok(2)
            ),
            2
        );
        assert_eq!(tracker.containers_written(), 2);
        assert_eq!(
            settle_live_writes(
                &mut tracker,
                &[ContainerUnit::Leg(ok, false)],
                dir,
                Err((0, "disk full".into()))
            ),
            0
        );
        assert_eq!(
            tracker.containers_written(),
            2,
            "a failed write adds nothing"
        );
        tracker.prune(|_| false);
        assert_eq!(
            tracker.containers_written(),
            2,
            "what the run wrote stays written after the store drops the dialog"
        );
        Ok(())
    }

    /// A dialog the tracker holds at its current `updated_at` was written
    /// live; one it holds at an older one, or not at all, was not.
    #[cfg(feature = "vcon")]
    #[test]
    fn written_live_means_written_at_the_current_updated_at() -> Result<(), TestError> {
        let dialogs = two_dialogs_one_failed()?;
        let failed = dialogs.get("failed-call@example.com").ok_or("fixture")?;
        assert!(
            !written_live(None, failed),
            "no live export, nothing written"
        );
        let mut tracker = LiveVconTracker::default();
        assert!(!written_live(Some(&tracker), failed));
        tracker.record(
            &failed.call_id,
            failed.updated_at - chrono::TimeDelta::seconds(1),
        );
        assert!(
            !written_live(Some(&tracker), failed),
            "it changed after it was written"
        );
        tracker.record(&failed.call_id, failed.updated_at);
        assert!(written_live(Some(&tracker), failed));
        Ok(())
    }

    /// STOP-AUDIT-1: a live sweep writes the `--export-vcon` call to
    /// `--vcon-out` once it has ended and settled, records it, and does not
    /// write it again unchanged. Before the settle period it writes nothing.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_sweep_writes_the_single_call_once_it_ends_and_settles() -> Result<(), TestError> {
        const CALL: &str = "failed-call@example.com";
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let out = tmp.path().join("one.json");
        let cli = cli_exporting_one(&out, CALL);
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let mut tracker = LiveVconTracker::default();

        let early = live_vcon_sweep(
            &cli,
            None,
            CaptureRead {
                dialogs: &dialogs,
                streams: &streams,
                frames_read: 4,
            },
            None,
            &mut tracker,
            chrono::Utc::now(),
        );
        assert_eq!(early, 0, "inside the settle period nothing is due");
        assert!(!out.exists(), "a call that has not settled is not written");

        let later = swept_after(&dialogs)?;
        let n = live_vcon_sweep(
            &cli,
            None,
            CaptureRead {
                dialogs: &dialogs,
                streams: &streams,
                frames_read: 4,
            },
            None,
            &mut tracker,
            later,
        );
        assert_eq!(n, 1, "the ended, settled call is written");
        assert!(!tracker.failed());
        let text = std::fs::read_to_string(&out)
            .map_err(|e| format!("the container was written: {e:?}"))?;
        let json: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("valid JSON: {e:?}"))?;
        assert!(json["uuid"].is_string(), "not a vCon: {json}");
        assert!(text.contains(CALL), "{text}");
        assert!(!text.contains("ok-call@example.com"), "only the named call");
        let updated_at = dialogs.get(CALL).ok_or("fixture")?.updated_at;
        assert_eq!(tracker.written_at(CALL), Some(updated_at));

        std::fs::remove_file(&out).map_err(|e| format!("remove: {e:?}"))?;
        let again = live_vcon_sweep(
            &cli,
            None,
            CaptureRead {
                dialogs: &dialogs,
                streams: &streams,
                frames_read: 4,
            },
            None,
            &mut tracker,
            later,
        );
        assert_eq!(again, 0, "a written call is not written again unchanged");
        assert!(!out.exists());
        Ok(())
    }

    /// A live sweep writes the `--export-vcon` call while it is still running
    /// only once it has been idle for [`LIVE_IDLE_WRITE`], and the container
    /// then says the call had not ended. This replaced the rule that a running
    /// call is never written, which left a call whose BYE was lost with no
    /// container at all.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_live_sweep_writes_a_running_single_call_only_after_the_idle_period()
    -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let out = tmp.path().join("one.json");
        let cli = cli_exporting_one(&out, "ok-call@example.com");
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let read = || CaptureRead {
            dialogs: &dialogs,
            streams: &streams,
            frames_read: 4,
        };
        let updated = dialogs
            .get("ok-call@example.com")
            .ok_or("the fixture holds the call")?
            .updated_at;
        let idle = chrono::TimeDelta::from_std(LIVE_IDLE_WRITE)?;
        let mut tracker = LiveVconTracker::default();

        let early = live_vcon_sweep(
            &cli,
            None,
            read(),
            None,
            &mut tracker,
            updated + idle - chrono::TimeDelta::seconds(1),
        );
        assert_eq!(early, 0);
        assert!(
            !out.exists(),
            "a running call is not written before it idles"
        );

        let late = live_vcon_sweep(&cli, None, read(), None, &mut tracker, updated + idle);
        assert_eq!(late, 1);
        let written = std::fs::read_to_string(&out)?;
        assert!(
            written.contains("had not ended"),
            "the container says the call had not ended: {written}"
        );
        assert!(!tracker.failed());
        Ok(())
    }

    /// STOP-AUDIT-1: the end of a signal-stopped live run writes no
    /// `--export-vcon` container, and answers success.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_stopped_live_run_writes_no_single_call_container() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let out = tmp.path().join("one.json");
        assert!(export_vcon(
            &cli_exporting_one(&out, "failed-call@example.com"),
            &[],
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            4,
            None,
            VconRunEnd::Stopped,
        ));
        assert!(!out.exists(), "a stop is never a flush");
        Ok(())
    }

    /// STOP-AUDIT-1: a live run that ends on its own writes the
    /// `--export-vcon` call only when the sweeps have not already written it
    /// at its current `updated_at`, and still reports a call that never
    /// appeared.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_natural_end_writes_the_single_call_only_if_the_sweeps_did_not() -> Result<(), TestError> {
        const CALL: &str = "failed-call@example.com";
        let dialogs = two_dialogs_one_failed()?;
        let updated_at = dialogs.get(CALL).ok_or("fixture")?.updated_at;
        let run = |tracker: &LiveVconTracker, call_id: &str, out: &std::path::Path| {
            export_vcon(
                &cli_exporting_one(out, call_id),
                &[],
                &dialogs,
                &StreamStore::new(16),
                4,
                None,
                VconRunEnd::AfterLive(std::slice::from_ref(tracker)),
            )
        };
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;

        let mut written = LiveVconTracker::default();
        written.record(CALL, updated_at);
        let out = tmp.path().join("written.json");
        assert!(run(&written, CALL, &out));
        assert!(
            !out.exists(),
            "the sweep already wrote it at this updated_at"
        );

        let mut stale = LiveVconTracker::default();
        stale.record(CALL, updated_at - chrono::TimeDelta::seconds(1));
        let out = tmp.path().join("stale.json");
        assert!(run(&stale, CALL, &out));
        let text = std::fs::read_to_string(&out)
            .map_err(|e| format!("changed since, so written: {e:?}"))?;
        assert!(text.contains(CALL), "{text}");

        let out = tmp.path().join("never.json");
        assert!(
            !run(&LiveVconTracker::default(), CALL, &out) || out.exists(),
            "a call the sweeps never wrote is written at a natural end"
        );
        assert!(out.exists(), "a call the sweeps never wrote is written");

        let out = tmp.path().join("absent.json");
        assert!(
            !run(&LiveVconTracker::default(), "absent@example.com", &out),
            "a call that never appeared is still an error"
        );
        assert!(!out.exists());
        Ok(())
    }

    /// The live export sees a dialog BEFORE idle compaction trims it.
    ///
    /// Compaction keeps at most `keep_messages_per_idle_dialog` (20 by
    /// default) messages of a dialog idle past the window (10 minutes by
    /// default). A 27-message dialog swept eleven minutes after its last
    /// message is trimmed by compaction, so the export callback must see all
    /// 27 and the store must hold fewer afterwards: the second half proves
    /// the fixture is one compaction actually touches.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_sweep_exports_before_it_compacts() -> Result<(), TestError> {
        const CALL: &str = "long-call@example.com";
        let store = RwLock::new(DialogStore::new(16, true));
        {
            let mut ds = store.write();
            ds.process_message(invite_msg(CALL)?);
            for _ in 0..25 {
                ds.process_message(response_msg(CALL, 180, "Ringing")?);
            }
            ds.process_message(response_msg(CALL, 486, "Busy Here")?);
        }
        let before = store.read().get(CALL).ok_or("tracked")?.messages.len();
        assert!(before > 20, "the fixture must exceed the retention cap");

        let mut seen = None;
        let now = chrono::Utc::now() + chrono::TimeDelta::minutes(11);
        sweep_dialog_store(&store, now, |ds| {
            seen = ds.get(CALL).map(|d| d.messages.len());
        });
        let seen = seen.ok_or("tracked")?;
        assert_eq!(seen, before, "the export must see the untrimmed dialog");
        assert!(
            store.read().get(CALL).ok_or("tracked")?.messages.len() < before,
            "compaction must have run after it, or this test proves nothing"
        );
        Ok(())
    }

    /// `--export-vcon-when` selects the dialogs its expression matches.
    ///
    /// The predicate is the language `--filter` already speaks, so this test
    /// is also what pins that choice: a flag per policy would not answer
    /// `response_code >= 400` without new code.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_predicate_selects_only_the_dialogs_that_match() -> Result<(), TestError> {
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 400".to_owned());

        let (picked, _, _) = vcon_selection(&cli, None, &dialogs, &streams)
            .map_err(|e| format!("a valid predicate: {e:?}"))?;
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
        Ok(())
    }

    /// A malformed predicate fails the run and names the flag.
    ///
    /// The failure this refuses is the quiet one: an expression that parses
    /// nowhere, a capture that finishes, an empty directory, and no error to
    /// explain it. An operator reads that as "nothing matched".
    #[cfg(feature = "vcon")]
    #[test]
    fn a_malformed_predicate_fails_the_run_rather_than_selecting_nothing() -> Result<(), TestError>
    {
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >>> 400".to_owned());

        // `let Err(..) else` rather than `expect_err`: that would need `Debug`
        // on `DialogSelection`, and widening a shared type's derives to suit
        // one test's ergonomics is a cost the type pays forever.
        let Err(err) = vcon_selection(&cli, None, &dialogs, &streams) else {
            return Err("an unparseable expression is an error, not an empty result".into());
        };

        assert!(
            format!("{err:#}").contains("--export-vcon-when"),
            "the message has to name the flag the operator typed: {err:#}"
        );
        Ok(())
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

    /// A Call-ID that starts with a dot still yields a name a spool reader
    /// treats as a container.
    ///
    /// The spool contract makes a dot-prefixed name sipnab's staging file
    /// (`.<name>.partial`), and every reader that follows it, the
    /// `--vcon-forward` forwarder and `vcon_forward.py` among them, skips
    /// dot-prefixed names. A container named `.abc-….vcon.json` was therefore
    /// written and never delivered by any of them.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_call_id_starting_with_a_dot_yields_a_visible_name() {
        for call_id in [".abc@192.0.2.1", "..", ".", "...x"] {
            let name = vcon_file_name(call_id);
            assert!(
                !name.starts_with('.'),
                "{call_id:?} produced a dot-prefixed name every spool reader skips: {name}"
            );
        }
        assert_ne!(
            vcon_file_name(".abc@192.0.2.1"),
            vcon_file_name("_abc@192.0.2.1"),
            "the digest of the ORIGINAL Call-ID still tells the two apart"
        );
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
    fn a_predicate_that_matches_nothing_selects_nothing() -> Result<(), TestError> {
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 599".to_owned());

        let (picked, _, _) = vcon_selection(&cli, None, &dialogs, &streams)
            .map_err(|e| format!("a valid predicate: {e:?}"))?;

        assert!(
            picked.dialogs.is_empty(),
            "nothing in the fixture answers 599 or above: {:?}",
            picked
                .dialogs
                .iter()
                .map(|(d, _)| &d.call_id)
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    /// With no predicate the selection is every dialog.
    ///
    /// The `None` branch, which no test reached. It matters because
    /// `vcon_selection` is also the path a future caller takes when it wants
    /// the whole store, and a `None` that quietly returned nothing would look
    /// like a capture with no calls in it.
    #[cfg(feature = "vcon")]
    #[test]
    fn no_predicate_selects_every_dialog() -> Result<(), TestError> {
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let cli = Cli::parse_from_args(["sipnab"]);

        let picked = vcon_selection(&cli, None, &dialogs, &streams)
            .map_err(|e| format!("no predicate is not an error: {e:?}"))?
            .0;

        assert_eq!(
            picked.dialogs.len(),
            2,
            "an absent predicate narrows nothing"
        );
        Ok(())
    }

    /// Two matching dialogs produce two distinct files.
    ///
    /// The multi-container path is the whole point of this task and nothing
    /// exercised it: the end-to-end run that proved the feature used a fixture
    /// holding ONE call, so a loop that wrote the first dialog and stopped, or
    /// that collided both onto one name, would have passed everything.
    #[cfg(feature = "vcon")]
    #[test]
    fn two_matching_dialogs_produce_two_distinct_files() -> Result<(), TestError> {
        let a = vcon_file_name("first@example.com");
        let b = vcon_file_name("second@example.com");
        assert_ne!(a, b, "two Call-IDs must not collide onto one filename");

        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());

        let (picked, _, _) = vcon_selection(&cli, None, &dialogs, &streams)
            .map_err(|e| format!("a valid predicate: {e:?}"))?;
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
        Ok(())
    }

    /// A `Cli` wired for a predicate export into `dir`.
    #[cfg(feature = "vcon")]
    fn cli_exporting_to(dir: &std::path::Path, expr: &str) -> Cli {
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some(expr.to_owned());
        cli.output_args.export_vcon_dir = Some(dir.to_path_buf());
        cli
    }

    // ── HEP input and TLS decryption (issue #301) ────────────────

    /// A HEP message never enters TLS decryption, and the wire's TLS state
    /// for the same address pair survives it.
    ///
    /// The merged setup the issue describes, `-d any --keylog <file> -L`, has
    /// the wire leg and the tracer's decrypted copy of it on ONE address pair.
    /// `try_tls_decrypt` admitted any TCP payload for a pair that holds a
    /// partial TLS record, so a HEP message marked TCP (IP protocol 6) was
    /// appended to the wire's held ciphertext: the next wire record then
    /// parsed with SIP text inside it and never decrypted. A HEP payload is
    /// plaintext a proxy already decrypted, so it has nothing to give TLS
    /// decryption and must take nothing from it.
    #[cfg(feature = "tls")]
    #[test]
    fn a_hep_message_leaves_the_wire_tls_state_for_its_address_pair_alone() -> Result<(), TestError>
    {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 40000);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)), 5061);
        let packet = |payload: &[u8], origin| ParsedPacket {
            frame: None,
            frame_bytes: None,
            timestamp: chrono::Utc::now(),
            src_addr: src.ip(),
            dst_addr: dst.ip(),
            src_port: src.port(),
            dst_port: dst.port(),
            transport: TransportProto::Tcp,
            payload: bytes::Bytes::copy_from_slice(payload),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 6,
            dscp: None,
            input_origin: origin,
            hep: None,
        };
        let mut decryptor = Some(
            TlsDecryptor::new(None, crate::crypto::default_backend())
                .map_err(|e| format!("a decryptor: {e:?}"))?,
        );
        let mut reassembler = tls::TlsRecordReassembler::new(16);

        // A 64-byte application-data record, split: the wire capture holds
        // the header and the first 10 bytes of its body.
        let body: Vec<u8> = (0u8..64).collect();
        let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x40];
        record.extend_from_slice(&body);
        let (head, tail) = record.split_at(15);
        let wire = packet(head, crate::capture::parse::InputOrigin::Wire);
        assert!(
            try_tls_decrypt(&wire, &mut decryptor, &mut reassembler)
                .decrypted
                .is_empty()
        );
        assert!(
            reassembler.has_held(src, dst),
            "the wire's partial record is held"
        );

        // The tracer's decrypted copy of a message on the same pair.
        let sip = b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP x;branch=z9hG4bK1\r\n\
                    Call-ID: hep-tls-state@x\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
        let hep = packet(sip, crate::capture::parse::InputOrigin::Hep);
        assert!(
            try_tls_decrypt(&hep, &mut decryptor, &mut reassembler)
                .decrypted
                .is_empty(),
            "a HEP message is plaintext already; TLS decryption yields nothing for it"
        );
        assert_eq!(
            hep.payload.as_ref(),
            &sip[..],
            "and it is delivered as it arrived"
        );

        // The rest of the wire record completes it exactly, with its own bytes.
        let records = reassembler.insert(src, dst, tail);
        assert_eq!(
            records.len(),
            1,
            "the held record completes on its own tail"
        );
        assert_eq!(
            records[0].payload, body,
            "the wire record must hold only wire bytes; HEP text inside it means \
             the plaintext was appended to the held ciphertext"
        );
        assert!(!reassembler.has_held(src, dst), "nothing is left over");
        Ok(())
    }

    // ── Key recovery never costs the packet in hand ─────────────

    /// A packet at `ts` on 192.0.2.10:40000 -> 192.0.2.20:5061 carrying
    /// `payload`, arrived through `origin`.
    #[cfg(feature = "tls")]
    fn packet_at(
        ts: chrono::DateTime<chrono::Utc>,
        payload: &[u8],
        transport: TransportProto,
        origin: crate::capture::parse::InputOrigin,
    ) -> ParsedPacket {
        use std::net::{IpAddr, Ipv4Addr};
        ParsedPacket {
            frame: None,
            frame_bytes: None,
            timestamp: ts,
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
            src_port: 40000,
            dst_port: 5061,
            transport,
            payload: bytes::Bytes::copy_from_slice(payload),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 6,
            dscp: Some(46),
            input_origin: origin,
            hep: None,
        }
    }

    /// A record held from the wire and opened when its keys arrived.
    #[cfg(feature = "tls")]
    fn recovered_at(
        ts: chrono::DateTime<chrono::Utc>,
        call_id: &str,
    ) -> Result<crate::capture::decrypt::RecoveredRecord, TestError> {
        Ok(crate::capture::decrypt::RecoveredRecord {
            plaintext: format!(
                "INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: {call_id}\r\n\
                 CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
            )
            .into_bytes(),
            timestamp: ts,
            src: "198.51.100.1:5061".parse()?,
            dst: "198.51.100.2:40001".parse()?,
        })
    }

    #[cfg(feature = "tls")]
    fn t(ms: i64) -> Result<chrono::DateTime<chrono::Utc>, TestError> {
        Ok(
            chrono::DateTime::from_timestamp_millis(1_790_000_000_000 + ms)
                .ok_or("from_timestamp_millis returned None")?,
        )
    }

    /// **The packet whose arrival triggers key recovery is still analyzed.**
    ///
    /// When the keys for held wire records arrive, the next packet runs the
    /// recovery, whatever that packet is. The recovered messages were then
    /// analyzed INSTEAD of it, so that packet vanished: a lab run under
    /// `-d any --keylog <file> --keylog-watch -L` lost a HEP BYE this way on
    /// every build, and 0.5.187 lost a different message in the same run.
    /// The recovered messages were also clones of it, so they claimed its
    /// origin: wire records reported as HEP input.
    #[cfg(feature = "tls")]
    #[test]
    fn key_recovery_keeps_the_hep_packet_in_hand_and_its_own_origin() -> Result<(), TestError> {
        use crate::capture::parse::InputOrigin;
        let bye = packet_at(
            t(5)?,
            b"BYE sip:bob@example.com SIP/2.0\r\nCall-ID: hep-bye\r\n\r\n",
            TransportProto::Tcp,
            InputOrigin::Hep,
        );
        let tls_yield = TlsYield {
            recovered: recovered_packets(
                vec![recovered_at(t(1)?, "wire-invite")?],
                &mut tls::TlsRecordReassembler::new(16),
            ),
            decrypted: capture::ParsedPackets::new(),
        };
        let out = packets_after_tls(&bye, tls_yield);
        let out: Vec<&ParsedPacket> = out.iter().map(|p| p.as_ref()).collect();
        assert_eq!(
            out.len(),
            2,
            "the recovered INVITE AND the HEP BYE: {out:#?}"
        );

        let invite = out[0];
        assert!(invite.payload.starts_with(b"INVITE"), "{invite:#?}");
        assert_eq!(
            invite.input_origin,
            InputOrigin::Wire,
            "a held record came off the wire"
        );
        assert!(invite.hep.is_none());
        assert_eq!(invite.transport, TransportProto::Tls);
        assert_eq!(invite.dscp, None, "the trigger's DSCP is not the record's");
        assert_eq!(invite.src_port, 5061, "the record's own endpoints");

        assert!(
            std::ptr::eq(out[1], &bye),
            "the HEP BYE passes through as it arrived"
        );
        assert_eq!(out[1].input_origin, InputOrigin::Hep);
        Ok(())
    }

    /// The same for a wire packet that is not TLS at all.
    #[cfg(feature = "tls")]
    #[test]
    fn key_recovery_keeps_a_plain_wire_packet_in_hand() -> Result<(), TestError> {
        use crate::capture::parse::InputOrigin;
        let options = packet_at(
            t(5)?,
            b"OPTIONS sip:x SIP/2.0\r\n\r\n",
            TransportProto::Udp,
            InputOrigin::Wire,
        );
        let tls_yield = TlsYield {
            recovered: recovered_packets(
                vec![recovered_at(t(1)?, "wire-invite")?],
                &mut tls::TlsRecordReassembler::new(16),
            ),
            decrypted: capture::ParsedPackets::new(),
        };
        let out = packets_after_tls(&options, tls_yield);
        assert_eq!(out.len(), 2, "the recovered INVITE and the OPTIONS in hand");
        assert!(std::ptr::eq(out[1].as_ref(), &options));
        Ok(())
    }

    /// Everything one packet yields is analyzed in capture-time order: held
    /// records are older than the packet whose arrival released them, and a
    /// dialog rebuilt out of order would put the answer before the offer.
    #[cfg(feature = "tls")]
    #[test]
    fn key_recovery_and_the_packet_in_hand_come_out_in_time_order() -> Result<(), TestError> {
        use crate::capture::parse::InputOrigin;
        let in_hand = packet_at(t(5)?, b"x", TransportProto::Udp, InputOrigin::Wire);
        let tls_yield = TlsYield {
            recovered: recovered_packets(
                vec![
                    recovered_at(t(3)?, "second")?,
                    recovered_at(t(1)?, "first")?,
                ],
                &mut tls::TlsRecordReassembler::new(16),
            ),
            decrypted: capture::ParsedPackets::new(),
        };
        let out = packets_after_tls(&in_hand, tls_yield);
        let times: Vec<_> = out.iter().map(|p| p.timestamp).collect();
        assert_eq!(times, vec![t(1)?, t(3)?, t(5)?]);
        Ok(())
    }

    /// A held WSS record opened by key recovery is SIP over WSS too. The lab's
    /// WSS leg decrypted through exactly this path (12 records recovered, no
    /// SIP), because keys arrive after the handshake.
    #[cfg(feature = "tls")]
    #[test]
    fn a_recovered_websocket_frame_is_sip_over_wss() -> Result<(), TestError> {
        use crate::capture::parse::InputOrigin;
        let sip = b"INVITE sip:bob@x SIP/2.0\r\nCall-ID: wss-recovered\r\n\r\n";
        let mut frame = vec![0x81u8, sip.len() as u8];
        frame.extend_from_slice(sip);
        let mut record = recovered_at(t(1)?, "unused")?;
        record.plaintext = frame;
        let in_hand = packet_at(t(5)?, b"x", TransportProto::Udp, InputOrigin::Wire);
        let tls_yield = TlsYield {
            recovered: recovered_packets(vec![record], &mut tls::TlsRecordReassembler::new(16)),
            decrypted: capture::ParsedPackets::new(),
        };
        let out = packets_after_tls(&in_hand, tls_yield);
        assert_eq!(out.len(), 2, "{out:#?}");
        assert_eq!(out[0].transport, TransportProto::Wss);
        assert_eq!(
            out[0].payload.as_ref(),
            &sip[..],
            "the frame's payload, unwrapped"
        );
        Ok(())
    }

    /// A WebSocket connection yields only its SIP messages, labeled WSS: not
    /// the HTTP upgrade, not a control frame, not a data frame of something
    /// else. A TLS connection that never started WebSocket stays SIP over TLS.
    #[cfg(feature = "tls")]
    #[test]
    fn a_websocket_connection_yields_only_its_sip_messages() -> Result<(), TestError> {
        let a: std::net::SocketAddr = "192.0.2.1:40000".parse()?;
        let b: std::net::SocketAddr = "192.0.2.2:7443".parse()?;
        let mut r = tls::TlsRecordReassembler::new(16);
        let mut ping = vec![0x89u8, 4];
        ping.extend_from_slice(b"ping");
        let mut not_sip = vec![0x81u8, 5];
        not_sip.extend_from_slice(b"hello");
        let options = b"OPTIONS sip:x SIP/2.0\r\n\r\n";
        let mut sip = vec![0x81u8, options.len() as u8];
        sip.extend_from_slice(options);
        for plaintext in [
            &b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"[..],
            &ping[..],
            &not_sip[..],
        ] {
            assert!(
                sip_in_plaintext(a, b, plaintext, &mut r).is_empty(),
                "{plaintext:?}"
            );
        }
        assert_eq!(
            sip_in_plaintext(a, b, &sip, &mut r),
            vec![(options.to_vec(), TransportProto::Wss)]
        );

        let c: std::net::SocketAddr = "192.0.2.3:40001".parse()?;
        let invite = b"INVITE sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            sip_in_plaintext(c, b, invite, &mut r),
            vec![(invite.to_vec(), TransportProto::Tls)],
            "no WebSocket on this connection"
        );
        Ok(())
    }

    // ── HEP unwrapping and the rtpengine control plane ──────────

    /// `unwrap_hep` for a datagram every test here expects to unwrap.
    #[cfg(feature = "hep")]
    fn unwrapped(pp: &ParsedPacket) -> Result<Option<ParsedPacket>, TestError> {
        Ok(crate::pipeline::unwrap_hep(pp)
            .transpose()
            .map_err(|e| format!("a transport the HEP rule names: {e:?}"))?)
    }

    /// `hep_datagram` with its IP protocol chunk rewritten to `ip_proto`.
    #[cfg(feature = "hep")]
    fn hep_datagram_with_ip_proto(ip_proto: u8, payload: &[u8]) -> Result<ParsedPacket, TestError> {
        let mut pp = hep_datagram(1, payload, None)?;
        let mut bytes = pp.payload.to_vec();
        let chunk = [0u8, 0, 0, 2, 0, 7];
        let at = bytes
            .windows(chunk.len())
            .position(|w| w == chunk)
            .ok_or("the encoder writes an IP protocol chunk")?;
        bytes[at + chunk.len()] = ip_proto;
        pp.payload = bytes.into();
        Ok(pp)
    }

    /// `--hep-parse` reads the transport by the rule `--hep-listen` uses
    /// (issue #301). It kept the outer datagram's UDP, so the same OpenSIPS
    /// or Kamailio feed read TLS through a socket and UDP from a file.
    #[cfg(feature = "hep")]
    #[test]
    fn unwrapping_hep_takes_the_transport_from_the_hep_rule() -> Result<(), TestError> {
        let invite = |via: &str| {
            format!("INVITE sip:b@x SIP/2.0\r\nVia: SIP/2.0/{via} x;branch=z9hG4bK1\r\n\r\n")
        };
        for (ip_proto, via, want) in [
            (22u8, "TLS", TransportProto::Tls),
            (22, "WSS", TransportProto::Wss),
            (50, "WSS", TransportProto::Wss),
            (6, "WS", TransportProto::Ws),
            (6, "TCP", TransportProto::Tcp),
            (17, "UDP", TransportProto::Udp),
        ] {
            let pp = hep_datagram_with_ip_proto(ip_proto, invite(via).as_bytes())?;
            let out = unwrapped(&pp)?.ok_or("a HEP datagram unwraps")?;
            assert_eq!(out.transport, want, "HEP protocol {ip_proto}, Via {via}");
            assert_eq!(
                out.ip_protocol, ip_proto,
                "the number as the sender stated it"
            );
        }
        Ok(())
    }

    /// A HEP datagram whose number no rule names is refused by that number,
    /// so the caller counts it NOT DECODED as `--hep-listen` does, rather than
    /// reading it as UDP.
    #[cfg(feature = "hep")]
    #[test]
    fn unwrapping_hep_with_an_unknown_ip_protocol_is_refused_by_number() -> Result<(), TestError> {
        let pp = hep_datagram_with_ip_proto(99, b"INVITE sip:b@x SIP/2.0\r\n\r\n")?;
        match crate::pipeline::unwrap_hep(&pp) {
            Some(Err(crate::error::CaptureError::UnsupportedIpProtocol(99))) => {}
            other => return Err(format!("expected a refusal naming 99, got {other:?}").into()),
        }
        Ok(())
    }

    /// A HEP datagram carrying `payload`, announced as `proto`.
    #[cfg(feature = "hep")]
    fn hep_datagram(
        proto: u8,
        payload: &[u8],
        correlation: Option<&str>,
    ) -> Result<ParsedPacket, TestError> {
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
            let total =
                u16::try_from(bytes.len()).map_err(|e| format!("test datagram fits: {e:?}"))?;
            bytes[4..6].copy_from_slice(&total.to_be_bytes());
        }
        Ok(ParsedPacket {
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
        })
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
    fn unwrapping_hep_carries_the_wrappers_protocol_onto_the_packet() -> Result<(), TestError> {
        let pp = hep_datagram(
            crate::rtpengine::NG_HEP_CAPTURE_PROTO,
            b"d3:foo3:bare",
            None,
        )?;
        let out = unwrapped(&pp)?.ok_or("a HEP datagram unwraps")?;
        let origin = out.hep.ok_or(
            "the wrapper's metadata must survive: without it nothing downstream \
             can tell mirrored ng from any other UDP payload",
        )?;
        assert_eq!(origin.protocol, crate::rtpengine::NG_HEP_CAPTURE_PROTO);
        Ok(())
    }

    /// The correlation id survives, because a reply has nothing else.
    ///
    /// An `ng` REPLY carries no `call-id` at all. The correlation id is the
    /// only thing naming the call it belongs to, so losing it turns every
    /// reply into control traffic about an unknown call.
    #[cfg(feature = "hep")]
    #[test]
    fn unwrapping_hep_keeps_the_correlation_id() -> Result<(), TestError> {
        let pp = hep_datagram(
            crate::rtpengine::NG_HEP_CAPTURE_PROTO,
            b"d3:foo3:bare",
            Some("corr-42"),
        )?;
        let out = unwrapped(&pp)?.ok_or("unwraps")?;
        assert_eq!(
            out.hep.and_then(|h| h.correlation_id).as_deref(),
            Some("corr-42")
        );
        Ok(())
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
    fn unwrapping_hep_marks_the_addressing_as_sender_asserted() -> Result<(), TestError> {
        let pp = hep_datagram(
            crate::rtpengine::NG_HEP_CAPTURE_PROTO,
            b"d3:foo3:bare",
            None,
        )?;
        assert_eq!(
            pp.input_origin,
            crate::capture::parse::InputOrigin::Wire,
            "the wrapper itself arrives off the wire under --hep-parse",
        );
        let out = unwrapped(&pp)?.ok_or("a HEP datagram unwraps")?;
        assert_eq!(
            out.input_origin,
            crate::capture::parse::InputOrigin::Hep,
            "the inner addressing is the sender's assertion, not observed; leaving \
             it Wire lets a forged inner source pass the kill/jail origin gate",
        );
        Ok(())
    }

    /// The inner payload replaces the outer one, which is the point.
    #[cfg(feature = "hep")]
    #[test]
    fn unwrapping_hep_yields_the_inner_payload_and_its_addresses() -> Result<(), TestError> {
        let inner = b"OPTIONS sip:a@b SIP/2.0\r\n\r\n";
        let pp = hep_datagram(1, inner, None)?;
        let out = unwrapped(&pp)?.ok_or("unwraps")?;
        assert_eq!(out.payload.as_ref(), inner, "the SIP inside is what parses");
        assert_eq!(out.dst_port, 5060, "and the addressing is the inner call's");
        Ok(())
    }

    /// A datagram that is not HEP is left alone.
    ///
    /// `--hep-parse` runs over every UDP packet on the capture, media
    /// included. Treating a failed parse as anything but "not HEP" would drop
    /// ordinary traffic.
    #[cfg(feature = "hep")]
    #[test]
    fn a_packet_that_is_not_hep_is_not_unwrapped() -> Result<(), TestError> {
        let mut pp = hep_datagram(1, b"x", None)?;
        pp.payload = bytes::Bytes::from_static(b"not a hep datagram at all");
        assert!(crate::pipeline::unwrap_hep(&pp).is_none());
        Ok(())
    }

    /// Only UDP is considered.
    ///
    /// HEP over TCP is a different framing, and running the datagram parser
    /// over a TCP segment would either fail or, worse, half-succeed on a
    /// segment boundary.
    #[cfg(feature = "hep")]
    #[test]
    fn hep_unwrapping_ignores_non_udp() -> Result<(), TestError> {
        let mut pp = hep_datagram(1, b"OPTIONS sip:a@b SIP/2.0\r\n\r\n", None)?;
        pp.transport = TransportProto::Tcp;
        assert!(crate::pipeline::unwrap_hep(&pp).is_none());
        Ok(())
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
    fn mirrored_ng_survives_unwrapping_as_control_traffic() -> Result<(), TestError> {
        let pp = hep_datagram(
            crate::rtpengine::NG_HEP_CAPTURE_PROTO,
            b"d7:command5:offere",
            Some("c1"),
        )?;
        let out = unwrapped(&pp)?.ok_or("unwraps")?;
        let origin = out.hep.as_ref().ok_or("metadata survives")?;
        assert!(
            crate::rtpengine::is_ng_over_hep(origin.protocol, &out.payload),
            "an unwrapped mirrored ng message must still identify as ng, or \
             the relay names no media at all"
        );
        Ok(())
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
    fn containers_in(dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>, TestError> {
        let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .map_err(|e| format!("readable: {e:?}"))?
            .flatten()
            .map(|e| e.path())
            .collect();
        paths.sort();
        assert!(!paths.is_empty(), "no container was written to {dir:?}");
        Ok(paths)
    }

    /// Read the `capture_completeness` block out of the first container in a
    /// directory. The containers are what a consumer actually gets.
    #[cfg(feature = "vcon")]
    fn first_completeness(dir: &std::path::Path) -> Result<serde_json::Value, TestError> {
        let text = std::fs::read_to_string(&containers_in(dir)?[0])
            .map_err(|e| format!("readable: {e:?}"))?;
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("valid JSON: {e:?}"))?;
        let body = &v["analysis"][0]["body"];
        if !body.is_object() {
            return Err("an analysis body is the object itself".into());
        }
        Ok(body["capture_completeness"].clone())
    }

    /// The suppressed count reaches the container a consumer reads.
    ///
    /// Owed to a surviving mutant: deleting the line that copies the count
    /// onto the facts passed every test here, because each one stopped at the
    /// filter. The number was computed correctly and thrown away, which is the
    /// same container a reader would get if the deny flag had never fired.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_suppressed_count_reaches_the_written_container() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let mut cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_first_flagged("X-No-Record", "1")?,
            &StreamStore::new(16),
            7,
            None,
        ));

        let completeness = first_completeness(tmp.path())?;
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
        Ok(())
    }

    /// A run with no deny flag writes containers that claim no suppression.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_run_with_no_deny_flag_writes_a_zero() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_first_flagged("X-No-Record", "1")?,
            &StreamStore::new(16),
            7,
            None,
        ));

        let completeness = first_completeness(tmp.path())?;
        assert_eq!(
            completeness["dialogs_suppressed_by_deny"], 0,
            "no header was named, so nothing was suppressed: {completeness}"
        );
        assert_eq!(
            completeness["gate_closed_during_run"], false,
            "and no gate was moved: {completeness}"
        );
        Ok(())
    }

    /// A gate closed and reopened mid-run reaches the container too.
    ///
    /// The scenario the field exists for, and the only one in which a
    /// container is written AND the gate moved: an operator stops recording,
    /// then starts it again. The containers that survive are from either side
    /// of a hole, and nothing else in them says the hole is there.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_gate_closed_and_reopened_is_recorded_in_the_container() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let gate = crate::output::persistence::PersistenceGate::new(true);
        gate.set(false);
        gate.set(true);

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            Some(&gate),
        ));

        let completeness = first_completeness(tmp.path())?;
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
        Ok(())
    }

    /// An untouched gate leaves the container claiming a clean run.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_untouched_gate_writes_a_container_that_claims_nothing() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let gate = crate::output::persistence::PersistenceGate::new(true);

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            Some(&gate),
        ));

        let completeness = first_completeness(tmp.path())?;
        assert_eq!(completeness["gate_closed_during_run"], false);
        assert!(
            completeness["note"]
                .as_str()
                .is_some_and(|n| !n.contains("persistence gate")),
            "a gate nobody touched must not be mentioned: {completeness}"
        );
        Ok(())
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
    fn the_new_completeness_fields_are_present_and_never_null() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None,
        ));

        let completeness = first_completeness(tmp.path())?;
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
        Ok(())
    }

    /// The deny filter reports how many dialogs it removed.
    ///
    /// The count is what the container quotes. Recomputing it later from the
    /// selection is impossible: by then the denied dialogs are gone, and a
    /// difference against the unfiltered store would also count dialogs the
    /// predicate rejected for entirely different reasons.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_deny_filter_reports_what_it_removed() -> Result<(), TestError> {
        let dialogs = two_dialogs_first_flagged("X-No-Record", "1")?;
        let streams = StreamStore::new(16);
        let selection = crate::sip::dsl::select_dialogs(
            Some(
                &crate::sip::dsl::FilterExpr::parse("response_code >= 100")
                    .map_err(|e| format!("parses: {e:?}"))?,
            ),
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
        Ok(())
    }

    /// With no deny flag configured, nothing is reported as suppressed.
    #[cfg(feature = "vcon")]
    #[test]
    fn no_deny_flag_suppresses_nothing_and_reports_nothing() -> Result<(), TestError> {
        let dialogs = two_dialogs_first_flagged("X-No-Record", "1")?;
        let streams = StreamStore::new(16);
        let selection = crate::sip::dsl::select_dialogs(
            Some(
                &crate::sip::dsl::FilterExpr::parse("response_code >= 100")
                    .map_err(|e| format!("parses: {e:?}"))?,
            ),
            &dialogs,
            &streams,
        );
        let before = selection.dialogs.len();

        let (kept, suppressed, _) = split_denied(selection, None);

        assert_eq!(suppressed, 0, "no header was named, so none was honored");
        assert_eq!(kept.dialogs.len(), before, "and nothing was removed");
        Ok(())
    }

    /// A header nobody sent suppresses nothing.
    ///
    /// Distinguishes "the filter ran and matched none" from "the filter never
    /// ran": both keep every dialog, and only the count tells them apart.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_deny_header_nobody_sent_reports_zero() -> Result<(), TestError> {
        let dialogs = two_dialogs_first_flagged("X-No-Record", "1")?;
        let streams = StreamStore::new(16);
        let selection = crate::sip::dsl::select_dialogs(
            Some(
                &crate::sip::dsl::FilterExpr::parse("response_code >= 100")
                    .map_err(|e| format!("parses: {e:?}"))?,
            ),
            &dialogs,
            &streams,
        );
        let before = selection.dialogs.len();

        let (kept, suppressed, _) = split_denied(selection, Some("X-Nobody-Sends-This"));

        assert_eq!(suppressed, 0);
        assert_eq!(kept.dialogs.len(), before);
        Ok(())
    }

    // ── The runtime persistence gate ────────────────────────────

    /// The gate's whole purpose: an operator closes it and content stops.
    ///
    /// The predicate still matches, the directory still exists, the flags are
    /// unchanged. Nothing but the gate stands between this run and a container
    /// on disk, so a file appearing here means the exporter never asked.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_closed_gate_writes_no_container() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let gate = crate::output::persistence::PersistenceGate::new(true);
        gate.set(false);

        let ok = export_vcon(
            &cli,
            &[],
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            Some(&gate),
            VconRunEnd::Whole,
        );

        assert!(
            ok,
            "an operator who closed the gate got what they asked for; that is \
              not a failure and must not become a non-zero exit code"
        );
        let written: Vec<_> = std::fs::read_dir(tmp.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .filter_map(Result::ok)
            .collect();
        assert!(
            written.is_empty(),
            "the gate was closed and {} container(s) were written anyway",
            written.len()
        );
        Ok(())
    }

    /// The single-call form is gated too.
    ///
    /// Two entry points reach the exporter, and a check on only the predicate
    /// form would leave `--export-vcon <call-id>` writing through a closed
    /// gate -- the failure being harder to notice for affecting the older,
    /// more-used flag.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_closed_gate_stops_the_single_call_form_too() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let out = tmp.path().join("one.vcon.json");
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon = Some("failed@test".to_owned());
        cli.output_args.vcon_out = Some(out.clone());
        let gate = crate::output::persistence::PersistenceGate::new(true);
        gate.set(false);

        assert!(export_vcon(
            &cli,
            &[],
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            Some(&gate),
            VconRunEnd::Whole,
        ));
        assert!(
            !out.exists(),
            "--export-vcon wrote through a closed gate: {}",
            out.display()
        );
        Ok(())
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
    fn an_unauthorized_gate_overrides_the_flags() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let gate = crate::output::persistence::PersistenceGate::new(false);
        gate.set(true);

        assert!(export_vcon(
            &cli,
            &[],
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            Some(&gate),
            VconRunEnd::Whole,
        ));
        assert_eq!(
            std::fs::read_dir(tmp.path())
                .map_err(|e| format!("readable: {e:?}"))?
                .filter_map(Result::ok)
                .count(),
            0,
            "the gate is the authority, not the flags it was built from"
        );
        Ok(())
    }

    /// An open gate exports exactly what no gate does.
    ///
    /// The direction this catches is a gate that quietly narrows a run nobody
    /// touched -- a check inverted, or a ceiling read from the wrong flag.
    /// Comparing the two file sets says so without pinning a count that a
    /// later fixture change would have to chase.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_open_gate_exports_exactly_what_no_gate_does() -> Result<(), TestError> {
        let names = |dir: &std::path::Path| -> Result<Vec<_>, TestError> {
            let mut v: Vec<_> = std::fs::read_dir(dir)
                .map_err(|e| format!("readable: {e:?}"))?
                .filter_map(Result::ok)
                .map(|e| e.file_name())
                .collect();
            v.sort_unstable();
            Ok(v)
        };

        let ungated = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        assert!(export_vcon(
            &cli_exporting_to(ungated.path(), "response_code >= 200"),
            &[],
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None,
            VconRunEnd::Whole,
        ));

        let gated = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        assert!(export_vcon(
            &cli_exporting_to(gated.path(), "response_code >= 200"),
            &[],
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            Some(&crate::output::persistence::PersistenceGate::new(true)),
            VconRunEnd::Whole,
        ));

        let ungated_names = names(ungated.path())?;
        assert!(
            !ungated_names.is_empty(),
            "the fixture must write something, or this test compares two \
              empty directories and proves nothing"
        );
        assert_eq!(
            ungated_names,
            names(gated.path())?,
            "an open gate changed what a run wrote"
        );
        Ok(())
    }

    /// Closing and reopening restores the export.
    ///
    /// The operator who switched recording off at three in the morning has to
    /// be able to switch it back on without restarting capture. A gate that
    /// latched shut would be safe and useless.
    #[cfg(feature = "vcon")]
    #[test]
    fn reopening_the_gate_restores_the_export() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let gate = crate::output::persistence::PersistenceGate::new(true);

        gate.set(false);
        assert!(export_vcon(
            &cli,
            &[],
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            Some(&gate),
            VconRunEnd::Whole,
        ));
        assert_eq!(
            std::fs::read_dir(tmp.path())
                .map_err(|e| format!("readable: {e:?}"))?
                .filter_map(Result::ok)
                .count(),
            0,
            "closed"
        );

        gate.set(true);
        assert!(export_vcon(
            &cli,
            &[],
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            Some(&gate),
            VconRunEnd::Whole,
        ));
        assert!(
            std::fs::read_dir(tmp.path())
                .map_err(|e| format!("readable: {e:?}"))?
                .filter_map(Result::ok)
                .count()
                > 0,
            "reopening the gate must let the next export through"
        );
        Ok(())
    }

    /// A run with no persistence flags is not stopped by the gate check.
    ///
    /// `export_vcon` returns early when neither flag is set, and that path
    /// must stay reachable with a closed gate: a run that writes nothing has
    /// nothing to suppress, and a `false` here would turn every ordinary
    /// capture into a non-zero exit.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_run_that_exports_nothing_is_unaffected_by_a_closed_gate() -> Result<(), TestError> {
        let cli = Cli::parse_from_args(["sipnab"]);
        let gate = crate::output::persistence::PersistenceGate::new(false);
        assert!(export_vcon(
            &cli,
            &[],
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            Some(&gate),
            VconRunEnd::Whole,
        ));
        Ok(())
    }

    /// The export directory is created when it does not exist.
    ///
    /// Owed for `every_flag_has_at_least_two_examples`. The documented
    /// invocation points at `./failed/`, a directory an operator will not have
    /// made first, so a run that refused a missing path would fail on the very
    /// command the page tells them to run.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_missing_export_directory_is_created() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dir = tmp.path().join("does/not/exist/yet");
        assert!(!dir.exists(), "the fixture starts with no directory");

        let cli = cli_exporting_to(&dir, "response_code >= 200");
        let ok = export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None,
        );

        assert!(ok, "creating the directory is part of the job");
        assert!(dir.is_dir(), "the run must create what it was pointed at");
        Ok(())
    }

    /// Every selected dialog gets its own file on disk.
    ///
    /// The multi-container write, end to end. `two_matching_dialogs_produce_two_distinct_files`
    /// proves the NAMES differ; this proves both files arrive. A loop that
    /// wrote the first dialog and returned would pass that one and fail this.
    #[cfg(feature = "vcon")]
    #[test]
    fn every_selected_dialog_is_written_to_its_own_file() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);

        let expected = vcon_selection(&cli, None, &dialogs, &streams)
            .map_err(|e| format!("a valid predicate: {e:?}"))?
            .0
            .dialogs
            .len();
        assert!(expected >= 2, "the fixture holds two calls");

        assert!(export_vcon_selection(
            &cli, None, &dialogs, &streams, 7, None
        ));

        let written: Vec<_> = std::fs::read_dir(tmp.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            written.len(),
            expected,
            "{expected} dialog(s) selected, {} file(s) written: {written:?}",
            written.len()
        );
        Ok(())
    }

    /// What lands on disk is a vCon a consumer can read.
    ///
    /// A run that wrote the right NUMBER of unparseable files would satisfy
    /// every other test here. This reads one back.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_written_container_is_valid_vcon_json() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None
        ));

        let first = containers_in(tmp.path())?[0].clone();
        let text = std::fs::read_to_string(&first).map_err(|e| format!("readable file: {e:?}"))?;
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("valid JSON: {e:?}"))?;

        assert_eq!(v["vcon"], "0.4.0", "syntax version: {text}");
        assert!(v["uuid"].is_string(), "a container needs a uuid: {text}");
        assert!(
            v["parties"].as_array().is_some_and(|p| !p.is_empty()),
            "a container names its parties: {text}"
        );
        Ok(())
    }

    /// A directory that cannot be written fails the run out loud.
    ///
    /// The refusal has to be a non-zero answer rather than a silent partial
    /// write: an operator scripting this reads the exit code, and a run that
    /// wrote three of forty containers and returned success is the worst
    /// outcome available.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_unwritable_export_directory_fails_the_run() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        // A FILE where the directory should be: `create_dir_all` cannot make a
        // directory over it, and this works without depending on running as a
        // non-root user, which a permission-bit fixture would.
        let blocked = tmp.path().join("blocked");
        std::fs::write(&blocked, b"not a directory")
            .map_err(|e| format!("write the blocker: {e:?}"))?;

        let cli = cli_exporting_to(&blocked, "response_code >= 200");
        let ok = export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None,
        );

        assert!(!ok, "a directory that cannot exist must fail the run");
        Ok(())
    }

    /// A predicate with no directory is refused before anything is written.
    ///
    /// clap enforces the pairing, but `export_vcon_selection` is reachable
    /// without going through argument validation -- the same reason the
    /// no-feature `export_vcon` stub exists. An unguarded `None` here would
    /// panic or, worse, pick a default directory nobody asked for.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_predicate_without_a_directory_is_refused() -> Result<(), TestError> {
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
        // deliberately no export_vcon_dir
        let ok = export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None,
        );
        assert!(!ok, "a destination nobody named is not a destination");
        Ok(())
    }

    /// Each file holds the dialog it is named for.
    ///
    /// Everything else here counts files or validates one in isolation. A loop
    /// that wrote the RIGHT number of containers with the WRONG dialog in each
    /// would pass all of it -- and misattributing a conversation is the exact
    /// failure this whole feature exists to avoid.
    #[cfg(feature = "vcon")]
    #[test]
    fn each_file_holds_the_dialog_it_is_named_for() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None
        ));

        for entry in std::fs::read_dir(tmp.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let text =
                std::fs::read_to_string(entry.path()).map_err(|e| format!("readable: {e:?}"))?;
            let v: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("valid JSON: {e:?}"))?;
            let call_id = v["dialog"][0]["sip_call_id"]
                .as_str()
                .ok_or("the dialog names its call")?
                .to_owned();
            assert_eq!(
                name,
                vcon_file_name(&call_id),
                "{name} holds {call_id}, which belongs in a differently named file"
            );
        }
        Ok(())
    }

    /// A capture where nothing matches writes no files and still succeeds.
    ///
    /// "Nothing matched" is an answer about the capture, not a failure of the
    /// run. Exiting non-zero there would make a shell script treat a quiet
    /// morning as a broken tool.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_capture_with_no_match_writes_nothing_and_still_succeeds() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 599");
        let ok = export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None,
        );

        assert!(ok, "an empty answer is an answer, not an error");
        let n = std::fs::read_dir(tmp.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .count();
        assert_eq!(n, 0, "nothing matched, so nothing should be on disk");
        Ok(())
    }

    /// Re-running over the same directory overwrites rather than accumulating.
    ///
    /// The filename is derived from the Call-ID, so a second run over the same
    /// capture must land on the same names. Accumulating `foo (1).vcon.json`
    /// would turn a re-run into a directory nobody can reason about.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_second_run_over_one_directory_overwrites_rather_than_accumulating() -> Result<(), TestError>
    {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);

        assert!(export_vcon_selection(
            &cli, None, &dialogs, &streams, 7, None
        ));
        let first = std::fs::read_dir(tmp.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .count();
        assert!(export_vcon_selection(
            &cli, None, &dialogs, &streams, 7, None
        ));
        let second = std::fs::read_dir(tmp.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .count();

        assert_eq!(
            first, second,
            "a second run produced {second} files where the first produced {first}"
        );
        Ok(())
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
    fn a_written_container_carries_this_captures_frame_count() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            4242,
            None,
        ));

        let text = std::fs::read_to_string(&containers_in(tmp.path())?[0])
            .map_err(|e| format!("readable: {e:?}"))?;
        assert!(
            text.contains("4242"),
            "the container must carry this run's frame count, not a default: {text}"
        );
        Ok(())
    }

    /// The directory preparation creates what is missing, and says so.
    ///
    /// Owed because the branch this covers was previously unguardable. As an
    /// early return inside the writer, deleting it changed nothing observable:
    /// the writes that followed failed too. With a `Result` the two outcomes
    /// are distinguishable, so a test can hold them apart.
    #[cfg(feature = "vcon")]
    #[test]
    fn preparing_the_export_directory_creates_a_missing_one() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dir = tmp.path().join("a/b/c");
        let cli = cli_exporting_to(&dir, "response_code >= 200");

        let got = prepare_export_dir(&cli)
            .map_err(|e| format!("a creatable path is not an error: {e:?}"))?;

        assert_eq!(got, dir.as_path(), "it returns the directory it prepared");
        assert!(dir.is_dir(), "and the directory now exists");
        Ok(())
    }

    /// ...and refuses a path it cannot make a directory, naming it.
    ///
    /// The message is the whole product of the failure: an operator reads it
    /// and fixes the path. A refusal that did not name the path would send
    /// them to the flag they typed rather than the thing in the way.
    #[cfg(feature = "vcon")]
    #[test]
    fn preparing_the_export_directory_refuses_a_path_that_is_a_file() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let blocked = tmp.path().join("blocked");
        std::fs::write(&blocked, b"not a directory")
            .map_err(|e| format!("write the blocker: {e:?}"))?;
        let cli = cli_exporting_to(&blocked, "response_code >= 200");

        let Err(message) = prepare_export_dir(&cli) else {
            return Err("a file where a directory belongs is an error".into());
        };

        assert!(
            message.contains("blocked"),
            "the refusal must name the path in the way: {message}"
        );
        assert!(
            message.contains("Nothing was exported"),
            "and say that nothing was written: {message}"
        );
        Ok(())
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

    /// The redactor every spool-name test below pseudonymizes under.
    #[cfg(feature = "vcon")]
    fn spool_name_policy() -> crate::output::redact::RedactionPolicy {
        crate::output::redact::RedactionPolicy::new(
            crate::output::redact::RedactionKey::from_secret(crate::test_material::key_bytes(
                "spool-name-test",
            )),
        )
    }

    /// Without redaction the spool name is the Call-ID's, unchanged.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_unredacted_spool_name_is_the_call_id_name() {
        for call_id in ["1-1966@10.0.2.20", "a@b", "..", ".hidden@192.0.2.1"] {
            assert_eq!(vcon_spool_name(call_id, None), vcon_file_name(call_id));
        }
    }

    /// Under redaction the spool name carries none of the Call-ID: not its
    /// local part, not its host, in either spelling the sanitizer produces.
    /// It is the name of the token the CONTAINER carries, so one rule names
    /// both and a reader can still pair a file with the Call-ID inside it.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_redacted_spool_name_is_the_pseudonymized_call_id_name() {
        let policy = spool_name_policy();
        let r = policy.redactor();
        let call_id = "1-1966@10.0.2.20";
        let name = vcon_spool_name(call_id, Some(&r));
        for raw in ["1-1966", "10.0.2.20", "10_0_2_20"] {
            assert!(!name.contains(raw), "'{name}' carries '{raw}'");
        }
        assert_eq!(name, vcon_file_name(&r.opaque(call_id)));
        // A Call-ID with no `@` takes the other branch of the pseudonym.
        let bare = vcon_spool_name("abc123xyz", Some(&r));
        assert!(!bare.contains("abc123xyz"), "'{bare}'");
    }

    /// The name is stable within a run and across runs under one key: a
    /// re-export overwrites its own file rather than adding a second one,
    /// which is what makes the directory a queue.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_redacted_spool_name_is_stable_under_one_key() {
        let policy = spool_name_policy();
        let (first, second) = (policy.redactor(), policy.redactor());
        let call_id = "stable@192.0.2.7";
        let name = vcon_spool_name(call_id, Some(&first));
        assert_eq!(name, vcon_spool_name(call_id, Some(&first)));
        assert_eq!(name, vcon_spool_name(call_id, Some(&second)));
    }

    /// Call-IDs that sanitize alike still get distinct names when redacted:
    /// the digest-suffix collision handling holds on the redacted path too.
    #[cfg(feature = "vcon")]
    #[test]
    fn redacted_call_ids_that_sanitize_alike_do_not_collide() {
        let policy = spool_name_policy();
        let r = policy.redactor();
        let pairs = [
            ("a@b", "a_b"),
            ("1-1966@10.0.2.20", "1-1966_10.0.2.20"),
            ("x@host.example", "x@host_example"),
        ];
        for (one, two) in pairs {
            assert_ne!(
                vcon_spool_name(one, Some(&r)),
                vcon_spool_name(two, Some(&r)),
                "'{one}' and '{two}' must not share a redacted spool name"
            );
        }
        let long = "p".repeat(300);
        assert_ne!(
            vcon_spool_name(&format!("{long}1"), Some(&r)),
            vcon_spool_name(&format!("{long}2"), Some(&r)),
            "Call-IDs differing past the truncation must stay distinct"
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
    fn the_selection_follows_capture_order() -> Result<(), TestError> {
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());

        let ids: Vec<String> = vcon_selection(&cli, None, &dialogs, &streams)
            .map_err(|e| format!("a valid predicate: {e:?}"))?
            .0
            .dialogs
            .iter()
            .map(|(d, _)| d.call_id.clone())
            .collect();
        let store_ids: Vec<String> = dialogs.iter().map(|d| d.call_id.clone()).collect();
        let expected: Vec<String> = store_ids.into_iter().filter(|c| ids.contains(c)).collect();

        assert_eq!(ids, expected, "the selection must not reorder the capture");
        Ok(())
    }

    /// A predicate naming a field the language does not have is refused.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_predicate_naming_an_unknown_field_is_refused() -> Result<(), TestError> {
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("nonexistent_field == 'x'".to_owned());

        let Err(err) = vcon_selection(&cli, None, &dialogs, &streams) else {
            return Err("a field the DSL does not define is not a valid expression".into());
        };
        assert!(
            format!("{err:#}").contains("--export-vcon-when"),
            "the refusal names the flag the operator typed: {err:#}"
        );
        Ok(())
    }

    /// A relative export directory works.
    ///
    /// The documented examples use `./failed/`, so a path resolved against the
    /// wrong base would fail on the very command the page prints.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_relative_export_directory_is_prepared() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let nested = tmp.path().join("rel");
        let cli = cli_exporting_to(&nested, "response_code >= 200");
        let got = prepare_export_dir(&cli)
            .map_err(|e| format!("a relative-style path is usable: {e:?}"))?;
        assert!(got.is_dir(), "the directory exists after preparation");
        Ok(())
    }

    /// One dialog keeps one uuid across two runs of the same capture.
    ///
    /// The container's uuid is derived, not random. If it rotated per run, a
    /// consumer holding yesterday's container and today's would see two
    /// conversations where there is one.
    #[cfg(feature = "vcon")]
    #[test]
    fn one_dialog_keeps_one_uuid_across_runs() -> Result<(), TestError> {
        let read_uuid = |dir: &std::path::Path| -> Result<String, TestError> {
            let text = std::fs::read_to_string(&containers_in(dir)?[0])
                .map_err(|e| format!("readable: {e:?}"))?;
            let v: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("valid JSON: {e:?}"))?;
            Ok(v["uuid"].as_str().ok_or("a uuid")?.to_owned())
        };
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);

        let a = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        assert!(export_vcon_selection(
            &cli_exporting_to(a.path(), "response_code >= 486"),
            None,
            &dialogs,
            &streams,
            7,
            None,
        ));
        let b = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        assert!(export_vcon_selection(
            &cli_exporting_to(b.path(), "response_code >= 486"),
            None,
            &dialogs,
            &streams,
            7,
            None,
        ));

        assert_eq!(
            read_uuid(a.path())?,
            read_uuid(b.path())?,
            "one dialog from one capture is one conversation, run twice"
        );
        Ok(())
    }

    /// Every container in one run carries the same capture-level facts.
    ///
    /// `export_vcon_selection` builds `CaptureFacts` once and shares it. Built
    /// per dialog it would still work, and two containers from one capture
    /// could then disagree about how many frames that capture held.
    #[cfg(feature = "vcon")]
    #[test]
    fn every_container_in_a_run_agrees_about_the_capture() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            4242,
            None,
        ));

        let counts: std::collections::HashSet<String> = std::fs::read_dir(tmp.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .flatten()
            .map(|e| -> Result<String, TestError> {
                let text =
                    std::fs::read_to_string(e.path()).map_err(|e| format!("readable: {e:?}"))?;
                let v: serde_json::Value =
                    serde_json::from_str(&text).map_err(|e| format!("valid JSON: {e:?}"))?;
                Ok(v["analysis"][0]["body"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
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
        Ok(())
    }

    /// A predicate reading a media field selects without a stream store.
    ///
    /// `matches_dialog` builds a media diagnosis only when the expression
    /// needs one, and an empty store is the ordinary signaling-only case. A
    /// panic here would take out every `-I` run over a capture with no RTP.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_media_predicate_survives_an_empty_stream_store() -> Result<(), TestError> {
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("rtp.codec == 'PCMU'".to_owned());

        let (picked, _, _) = vcon_selection(&cli, None, &dialogs, &streams)
            .map_err(|e| format!("a valid predicate: {e:?}"))?;
        assert!(
            picked.dialogs.is_empty(),
            "no streams means no dialog carries PCMU"
        );
        Ok(())
    }

    /// An empty predicate string is refused rather than matching everything.
    ///
    /// `--export-vcon-when ''` is a plausible scripting accident, and the
    /// dangerous reading is "match everything" -- that writes a container for
    /// every call in the capture when the operator meant to write none.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_empty_predicate_is_refused_rather_than_matching_everything() -> Result<(), TestError> {
        let dialogs = two_dialogs_one_failed()?;
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
        Ok(())
    }

    /// Containers land in the directory given, not the working directory.
    #[cfg(feature = "vcon")]
    #[test]
    fn containers_land_only_in_the_directory_given() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let target = tmp.path().join("target");
        let cli = cli_exporting_to(&target, "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None
        ));

        let inside = std::fs::read_dir(&target)
            .map_err(|e| format!("readable: {e:?}"))?
            .count();
        let stray = std::fs::read_dir(tmp.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .flatten()
            .filter(|e| e.path() != target)
            .count();
        assert!(inside > 0, "the containers went somewhere");
        assert_eq!(stray, 0, "and nothing landed beside the directory");
        Ok(())
    }

    /// The written file is named exactly as `vcon_file_name` renders it.
    ///
    /// The writer and the namer could drift: a writer that built its own path
    /// would pass every content test while making the sanitizer decorative.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_writer_uses_the_sanitizer_for_every_name() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        let dialogs = two_dialogs_one_failed()?;
        let streams = StreamStore::new(16);
        assert!(export_vcon_selection(
            &cli, None, &dialogs, &streams, 7, None
        ));

        let expected: std::collections::HashSet<String> =
            vcon_selection(&cli, None, &dialogs, &streams)
                .map_err(|e| format!("valid: {e:?}"))?
                .0
                .dialogs
                .iter()
                .map(|(d, _)| vcon_file_name(&d.call_id))
                .collect();
        let actual: std::collections::HashSet<String> = std::fs::read_dir(tmp.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            actual, expected,
            "the writer must name files the way the sanitizer does"
        );
        Ok(())
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
    fn a_digest_line_is_in_the_format_sha256sum_reads() -> Result<(), TestError> {
        let line = digest_line(std::path::Path::new("/spool/call-id.vcon.json"), b"{}");

        // Known-answer: SHA-256 of the two bytes `{}`.
        let (hex, name) = line
            .split_once("  ")
            .ok_or("two spaces separate digest from name, as `sha256sum -c` requires")?;
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
        Ok(())
    }

    /// Different bytes, different digest — and identical bytes agree.
    ///
    /// The anti-vacuity half. A digest_line that ignored its input would pass
    /// the format test above on every call.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_digest_follows_the_bytes_not_the_name() -> Result<(), TestError> {
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
            a.split_once("  ").ok_or("split")?.0,
            same_bytes_other_name.split_once("  ").ok_or("split")?.0,
            "the digest covers the bytes; renaming a container does not \
             change what it contains"
        );
        Ok(())
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
    fn the_spool_stages_beside_its_destination_so_the_rename_is_atomic() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
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
        Ok(())
    }

    /// A completed write leaves the container and nothing else.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_completed_spool_write_leaves_no_staging_file_behind() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dest = dir.path().join("call-id.vcon.json");

        write_container_atomically(&dest, br#"{"vcon":"0.4.0"}"#)
            .map_err(|e| format!("writes: {e:?}"))?;

        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<_, _>>()
            .map_err(|e| format!("entry: {e:?}"))?;
        assert_eq!(
            entries,
            vec!["call-id.vcon.json".to_string()],
            "a staging file left in the spool is one a bridge eventually \
             picks up as a container: {entries:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&dest).map_err(|e| format!("readable: {e:?}"))?,
            r#"{"vcon":"0.4.0"}"#
        );
        Ok(())
    }

    /// A failed write leaves the PREVIOUS container intact.
    ///
    /// This is the property `fs::write` cannot offer. It opens the
    /// destination with truncate, so a write that fails after that leaves the
    /// spool holding a file that is neither the old container nor the new one
    /// — and the bridge has no way to tell.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_failed_spool_write_does_not_destroy_what_was_already_there() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let dest = dir.path().join("call-id.vcon.json");
        std::fs::write(&dest, r#"{"vcon":"0.4.0","uuid":"the-old-one"}"#)
            .map_err(|e| format!("seed: {e:?}"))?;

        // A directory where the staging file needs to be is a write that
        // cannot succeed, and it fails at the same point a full disk would.
        let staged = spool_staging_path(&dest);
        std::fs::create_dir(&staged).map_err(|e| format!("occupy the staging name: {e:?}"))?;

        assert!(
            write_container_atomically(&dest, br#"{"vcon":"0.4.0","uuid":"the-new-one"}"#).is_err(),
            "the write must report the failure rather than half-performing it"
        );
        assert_eq!(
            std::fs::read_to_string(&dest).map_err(|e| format!("readable: {e:?}"))?,
            r#"{"vcon":"0.4.0","uuid":"the-old-one"}"#,
            "the previous container must survive a failed replacement"
        );
        Ok(())
    }

    #[cfg(feature = "vcon")]
    #[test]
    fn a_written_container_names_no_party() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None
        ));

        let text = std::fs::read_to_string(&containers_in(tmp.path())?[0])
            .map_err(|e| format!("readable: {e:?}"))?;
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("valid JSON: {e:?}"))?;
        for party in v["parties"].as_array().ok_or("parties")? {
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
        Ok(())
    }

    /// A container from the predicate path carries no by-reference url.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_written_container_carries_no_url() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None
        ));

        let text = std::fs::read_to_string(&containers_in(tmp.path())?[0])
            .map_err(|e| format!("readable: {e:?}"))?;
        assert!(
            !text.contains("\"url\""),
            "sipnab hosts nothing, so a container never points elsewhere: {text}"
        );
        Ok(())
    }

    /// No container emits an explicit null.
    ///
    /// "Absent, never null" is the module's standing contract, and the
    /// container stored on the development host by an earlier release violates it -- with
    /// `url`, `mediatype` and `duration` all null. This asserts the property
    /// on the path this task added.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_written_container_emits_no_explicit_null() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
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
        for entry in std::fs::read_dir(tmp.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .flatten()
        {
            let text =
                std::fs::read_to_string(entry.path()).map_err(|e| format!("readable: {e:?}"))?;
            let v: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("valid JSON: {e:?}"))?;
            assert_no_null_in_container(&v, &text);
            checked += 1;
        }
        assert_eq!(
            checked, 2,
            "the fixture writes two containers and both must be checked"
        );
        Ok(())
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
    fn a_failed_dialogs_container_really_does_carry_the_deliberate_nulls() -> Result<(), TestError>
    {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None,
        ));

        let mut saw_deliberate_nulls = false;
        for entry in std::fs::read_dir(tmp.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .flatten()
        {
            let text =
                std::fs::read_to_string(entry.path()).map_err(|e| format!("readable: {e:?}"))?;
            let v: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("valid JSON: {e:?}"))?;
            let body = &v["analysis"][0]["body"];
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
        Ok(())
    }

    /// Both containers carry the completeness block, whatever the read order.
    ///
    /// The property the broken test needed and did not have: the verdict is
    /// the same for every file in the directory, so which one `read_dir`
    /// yields first cannot change the answer.
    #[cfg(feature = "vcon")]
    #[test]
    fn every_container_carries_the_completeness_block_not_just_the_first() -> Result<(), TestError>
    {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None,
        ));

        let mut seen = 0;
        for entry in std::fs::read_dir(tmp.path())
            .map_err(|e| format!("readable: {e:?}"))?
            .flatten()
        {
            let text =
                std::fs::read_to_string(entry.path()).map_err(|e| format!("readable: {e:?}"))?;
            let v: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("valid JSON: {e:?}"))?;
            let c = &v["analysis"][0]["body"]["capture_completeness"];
            for key in ["gate_closed_during_run", "dialogs_suppressed_by_deny"] {
                assert!(
                    c.get(key).is_some_and(|x| !x.is_null()),
                    "{key} missing from a container: {c}"
                );
            }
            seen += 1;
        }
        assert_eq!(seen, 2, "both containers were read");
        Ok(())
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
    fn the_null_verdict_is_the_same_in_either_direction() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_one_failed()?,
            &StreamStore::new(16),
            7,
            None,
        ));

        let paths = containers_in(tmp.path())?;
        assert!(
            paths.len() > 1,
            "one container cannot have an order; the fixture must write two"
        );

        let verdict = |ps: &[std::path::PathBuf]| -> Result<(), TestError> {
            for path in ps {
                let text = std::fs::read_to_string(path).map_err(|e| format!("readable: {e:?}"))?;
                let v: serde_json::Value =
                    serde_json::from_str(&text).map_err(|e| format!("valid JSON: {e:?}"))?;
                assert_no_null_in_container(&v, &text);
            }
            Ok(())
        };
        verdict(&paths)?;
        let mut reversed = paths.clone();
        reversed.reverse();
        verdict(&reversed)?;
        Ok(())
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
                "body": {"signaling_diagnosis": {"abandoned": null}}
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
        });
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
    fn invite_with_header(
        call_id: &str,
        name: &str,
        value: &str,
    ) -> Result<sip::message::SipMessage, TestError> {
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
        Ok(sip::parser::parse_sip_bytes(
            &data,
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .map_err(|e| format!("fixture parses: {e:?}"))?)
    }

    /// Two dialogs, both answered, the first carrying `name: value`.
    #[cfg(feature = "vcon")]
    fn two_dialogs_first_flagged(name: &str, value: &str) -> Result<DialogStore, TestError> {
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_with_header("flagged@example.com", name, value)?);
        store.process_message(response_msg("flagged@example.com", 200, "OK")?);
        store.process_message(invite_msg("plain@example.com")?);
        store.process_message(response_msg("plain@example.com", 200, "OK")?);
        Ok(store)
    }

    /// Without the flag, a denied dialog leaves no file at all.
    ///
    /// The conservative default, asserted so it cannot drift: turning
    /// suppression into a tombstone reveals the call existed, and that is the
    /// operator's decision rather than sipnab's.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_denied_dialog_writes_nothing_unless_a_tombstone_is_asked_for() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let mut cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());
        assert!(
            !cli.output_args.content_deny_tombstone,
            "the default is off"
        );

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_first_flagged("X-No-Record", "1")?,
            &StreamStore::new(16),
            7,
            None
        ));

        let files = containers_in(tmp.path())?;
        assert_eq!(
            files.len(),
            1,
            "only the undenied dialog may produce a file: {files:?}"
        );
        let text = std::fs::read_to_string(&files[0]).map_err(|e| format!("readable: {e:?}"))?;
        assert!(
            !text.contains("flagged@example.com"),
            "the denied dialog must not appear anywhere: {text}"
        );
        Ok(())
    }

    /// With the flag, the denied dialog gets an identity-only container.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_tombstone_declares_the_redaction_and_carries_no_trace() -> Result<(), TestError> {
        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let mut cli = cli_exporting_to(tmp.path(), "response_code >= 200");
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());
        cli.output_args.content_deny_tombstone = true;

        assert!(export_vcon_selection(
            &cli,
            None,
            &two_dialogs_first_flagged("X-No-Record", "1")?,
            &StreamStore::new(16),
            7,
            None
        ));

        let files = containers_in(tmp.path())?;
        assert_eq!(files.len(), 2, "one kept, one tombstone: {files:?}");

        let tombstone = files
            .iter()
            .map(|p| std::fs::read_to_string(p).map_err(|e| format!("readable: {e:?}")))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|t| t.contains("flagged@example.com"))
            .ok_or("the denied dialog has a container")?;
        let v: serde_json::Value =
            serde_json::from_str(&tombstone).map_err(|e| format!("valid JSON: {e:?}"))?;

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
            .ok_or("attachments")?
            .iter()
            .filter_map(|a| a["purpose"].as_str())
            .collect();
        assert!(
            !purposes.contains(&"sip-message-trace"),
            "the trace is exactly what was withheld: {purposes:?}"
        );
        Ok(())
    }

    /// A deny header suppresses a dialog the predicate selected.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_deny_header_suppresses_a_dialog_the_predicate_selected() -> Result<(), TestError> {
        let dialogs = two_dialogs_first_flagged("X-No-Record", "1")?;
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

        let ids: Vec<String> = vcon_selection(&cli, None, &dialogs, &streams)
            .map_err(|e| format!("valid: {e:?}"))?
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
        Ok(())
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
    fn a_permit_header_never_causes_a_container_to_exist() -> Result<(), TestError> {
        // The predicate selects NOTHING. The permit header sits on a dialog
        // it rejected.
        let dialogs = two_dialogs_first_flagged("X-Record-Session", "yes")?;
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 599".to_owned());
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

        let (picked, _, _) =
            vcon_selection(&cli, None, &dialogs, &streams).map_err(|e| format!("valid: {e:?}"))?;

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
        Ok(())
    }

    /// The deny match is case-insensitive, as SIP header names are.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_deny_header_matches_regardless_of_case() -> Result<(), TestError> {
        let dialogs = two_dialogs_first_flagged("x-no-record", "1")?;
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

        let ids: Vec<String> = vcon_selection(&cli, None, &dialogs, &streams)
            .map_err(|e| format!("valid: {e:?}"))?
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
        Ok(())
    }

    /// Presence suppresses, whatever the value says.
    ///
    /// A rule keyed on a value raises the question of what an unrecognized
    /// value means, and the only safe answer to "I do not understand this deny
    /// flag" is to deny.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_deny_header_suppresses_on_presence_not_value() -> Result<(), TestError> {
        for value in ["", "0", "false", "no", "anything at all"] {
            let dialogs = two_dialogs_first_flagged("X-No-Record", value)?;
            let streams = StreamStore::new(16);
            let mut cli = Cli::parse_from_args(["sipnab"]);
            cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
            cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

            let ids: Vec<String> = vcon_selection(&cli, None, &dialogs, &streams)
                .map_err(|e| format!("valid: {e:?}"))?
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
        Ok(())
    }

    /// With no header named, the feature is inert.
    #[cfg(feature = "vcon")]
    #[test]
    fn no_deny_header_named_means_nothing_is_suppressed() -> Result<(), TestError> {
        let dialogs = two_dialogs_first_flagged("X-No-Record", "1")?;
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
        // no content_deny_header

        let n = vcon_selection(&cli, None, &dialogs, &streams)
            .map_err(|e| format!("valid: {e:?}"))?
            .0
            .dialogs
            .len();
        assert_eq!(n, 2, "sipnab ships no opinion about which header you use");
        Ok(())
    }

    /// An RtpStream fixture, so the deny filter can be given media to drop.
    #[cfg(feature = "vcon")]
    fn rtp_stream_fixture(port: u16) -> crate::rtp::stream::RtpStream {
        use crate::rtp::stream::{RtpStream, StreamKey};
        let key = StreamKey {
            src: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port),
            dst: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), port + 1),
            ssrc: u32::from(port),
            session: 0,
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
    fn suppressing_a_dialog_suppresses_its_media_too() -> Result<(), TestError> {
        let store = two_dialogs_first_flagged("X-No-Record", "1")?;
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
        Ok(())
    }

    /// With no header named the filter returns the selection untouched.
    ///
    /// The `None` branch of `apply_deny_filter`, which nothing reached
    /// directly. A branch that quietly dropped media when the feature is OFF
    /// would break every run that does not use it.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_deny_filter_with_no_header_changes_nothing() -> Result<(), TestError> {
        let store = two_dialogs_first_flagged("X-No-Record", "1")?;
        let dialogs: Vec<&crate::sip::dialog::SipDialog> = store.iter().collect();
        let media = rtp_stream_fixture(20000);
        let selection = crate::sip::dsl::DialogSelection {
            dialogs: dialogs.iter().map(|d| (*d, vec![&media])).collect(),
            streams: vec![&media],
        };

        let (out, _, _) = split_denied(selection, None);

        assert_eq!(out.dialogs.len(), 2, "no header named, nothing suppressed");
        assert_eq!(out.streams.len(), 1, "and no media dropped");
        Ok(())
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
    fn the_deny_filter_never_grows_the_selection() -> Result<(), TestError> {
        let store = two_dialogs_first_flagged("X-Record-Session", "yes")?;
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
        Ok(())
    }

    /// A deny header on a later message suppresses the dialog.
    ///
    /// The flag can arrive on the 200, not only the INVITE -- a B2BUA that
    /// decides on answer marks it there. Checking only the first message
    /// would miss every one of those.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_deny_header_on_a_later_message_still_suppresses() -> Result<(), TestError> {
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_msg("late@example.com")?);
        store.process_message(response_msg_with_header(
            "late@example.com",
            200,
            "OK",
            "X-No-Record",
            "1",
        )?);
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
        cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

        let n = vcon_selection(&cli, None, &store, &streams)
            .map_err(|e| format!("valid: {e:?}"))?
            .0
            .dialogs
            .len();
        assert_eq!(
            n, 0,
            "a flag on the answer counts as much as one on the INVITE"
        );
        Ok(())
    }

    /// The FLAG's case does not have to match the header's.
    ///
    /// The earlier case test varied the header on the wire. This varies what
    /// the operator typed, which is the half a `to_lowercase` on only one side
    /// would break.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_deny_flag_name_may_differ_in_case_from_the_header() -> Result<(), TestError> {
        let dialogs = two_dialogs_first_flagged("X-No-Record", "1")?;
        let streams = StreamStore::new(16);
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
        cli.output_args.content_deny_header = Some("x-NO-record".to_owned());

        let ids: Vec<String> = vcon_selection(&cli, None, &dialogs, &streams)
            .map_err(|e| format!("valid: {e:?}"))?
            .0
            .dialogs
            .iter()
            .map(|(d, _)| d.call_id.clone())
            .collect();
        assert!(
            !ids.iter().any(|c| c == "flagged@example.com"),
            "what the operator typed is case-insensitive too: {ids:?}"
        );
        Ok(())
    }

    /// Both deny headers this project documents are usable as written.
    ///
    /// `docs/cli-reference.md` prints `X-No-Record` and `Privacy`. A name the
    /// flag cannot accept would fail on the command the page tells an operator
    /// to run.
    #[cfg(feature = "vcon")]
    #[test]
    fn every_documented_deny_header_is_usable() -> Result<(), TestError> {
        for header in ["X-No-Record", "Privacy"] {
            let dialogs = two_dialogs_first_flagged(header, "id")?;
            let streams = StreamStore::new(16);
            let mut cli = Cli::parse_from_args(["sipnab"]);
            cli.output_args.export_vcon_when = Some("response_code >= 200".to_owned());
            cli.output_args.content_deny_header = Some(header.to_owned());

            let ids: Vec<String> = vcon_selection(&cli, None, &dialogs, &streams)
                .map_err(|e| format!("valid: {e:?}"))?
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
        Ok(())
    }

    /// A response carrying one extra header.
    #[cfg(feature = "vcon")]
    fn response_msg_with_header(
        call_id: &str,
        code: u16,
        reason: &str,
        name: &str,
        value: &str,
    ) -> Result<sip::message::SipMessage, TestError> {
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
        Ok(sip::parser::parse_sip_bytes(
            &data,
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .map_err(|e| format!("fixture parses: {e:?}"))?)
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
    fn the_notice_names_the_count_the_share_and_the_numbers() -> Result<(), TestError> {
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
        .ok_or("49 undecodable frames must be reported")?;
        assert!(msg.starts_with("NOT DECODED:"), "wrong prefix: {msg}");
        assert!(msg.contains("49 of 49 frame(s)"), "counts missing: {msg}");
        assert!(msg.contains("100.0%"), "share missing: {msg}");
        assert!(
            msg.contains("unsupported link type 0 (49)"),
            "the DLT NUMBER must appear with its count: {msg}"
        );
        Ok(())
    }

    /// A high share must be EMPHATIC. Getting zero from a capture that was
    /// almost entirely unreadable is a different statement from getting zero
    /// from a clean read, and the notice has to say which one happened.
    #[test]
    fn a_high_undecodable_share_is_emphatic() -> Result<(), TestError> {
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
        .ok_or("reported")?;
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
        .ok_or("reported")?;
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
        .ok_or("still reported")?;
        assert!(
            !noise.contains("not evidence of absence"),
            "ordinary non-IP background must not be alarming: {noise}"
        );
        assert!(
            noise.contains("1 of 10000 frame(s)"),
            "it is still reported, with its numbers: {noise}"
        );
        Ok(())
    }

    /// Reasons the tally could not keep are declared, so the breakdown never
    /// silently fails to add up to the total.
    #[test]
    fn dropped_reasons_are_declared_not_hidden() -> Result<(), TestError> {
        let mut report = undecodable_of(
            30,
            &[(
                crate::capture::UndecodableReason::UnsupportedLinkType(0),
                26,
            )],
        );
        report.reasons_dropped = 4;
        let msg = undecodable_summary(&report, 30).ok_or("reported")?;
        assert!(
            msg.contains("4 further frame(s) whose reason was not retained"),
            "the unnamed frames must be declared: {msg}"
        );
        Ok(())
    }

    /// A capture sipnab decoded none of is a QUALITY finding. Before this,
    /// `capture_quality_summary` returned `None` unless the kernel or the NIC
    /// had dropped something, so a run that understood 0% reported "fine".
    #[test]
    #[serial_test::serial(kernel_drop_counts, undecodable_tally)]
    fn undecodable_frames_are_a_capture_quality_signal() -> Result<(), TestError> {
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
            .ok_or("a frame sipnab could not decode is a quality finding")?;
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
        Ok(())
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

    /// docs/tls-capture.md and its hand-kept site page quote both late-hold
    /// lines in full, as this function renders them, so a reader can match
    /// the text a run prints.
    ///
    /// The pages once quoted the eviction line cut off after its bounds,
    /// which dropped the advice the line ends with. Whitespace is collapsed
    /// on both sides because the pages wrap the quote across lines.
    #[test]
    fn tls_capture_doc_quotes_both_late_hold_lines_in_full() -> Result<(), TestError> {
        fn collapse(s: &str) -> String {
            s.split_whitespace().collect::<Vec<_>>().join(" ")
        }
        let mut report = tls_report(1, 12, 12);
        report.late_evicted = 3;
        report.late_still_held = 5;
        let lines = late_hold_guidance(&report);
        assert_eq!(
            lines.len(),
            2,
            "both late-hold lines must render: {lines:?}"
        );
        for rel in ["docs/tls-capture.md", "website/content/docs/tls-capture.md"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
            let page = collapse(
                &std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?,
            );
            for line in &lines {
                assert!(
                    page.contains(&collapse(line)),
                    "{rel} must quote this line in full:\n{line}"
                );
            }
        }
        Ok(())
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
        let lines = no_sip_guidance(
            0,
            0,
            false,
            &undecodable_of(0, &[]),
            42,
            &tls_report(1, 9, 0),
        );
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
        let lines = no_sip_guidance(
            0,
            0,
            false,
            &undecodable_of(0, &[]),
            4_212,
            &tls_report(0, 0, 0),
        );
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
            false,
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
            false,
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

    /// A run that prints the `--report` tables must not tell the operator to
    /// pass `--report`: they passed it, and the stream table is in the same
    /// run's output. The counts stay, because they are the finding.
    #[test]
    fn media_only_capture_with_the_report_printed_does_not_suggest_report() {
        let lines = no_sip_guidance(
            40,
            4,
            true,
            &undecodable_of(0, &[]),
            40,
            &tls_report(0, 0, 0),
        );
        let joined = lines.join("\n");
        assert!(
            !joined.contains("--report"),
            "the run already prints the report, so the flag must not be suggested: {joined}"
        );
        assert_eq!(
            lines,
            vec![
                "No SIP signaling found, but 40 RTP packets across 4 stream(s) were parsed."
                    .to_string()
            ],
        );
    }

    /// Negative control for the test above: without the report, the hint that
    /// points at `--report` is still printed, word for word.
    #[test]
    fn media_only_capture_without_the_report_still_suggests_report() {
        let lines = no_sip_guidance(
            40,
            4,
            false,
            &undecodable_of(0, &[]),
            40,
            &tls_report(0, 0, 0),
        );
        assert_eq!(
            lines,
            vec![
                "No SIP signaling found, but 40 RTP packets across 4 stream(s) were parsed. \
                 Use --report to see stream details."
                    .to_string()
            ],
        );
    }

    /// Whether the report prints changes only the media-only message. Every
    /// branch reached with no RTP prints the same lines either way. Serialized
    /// with the STUN store because the last branch reads it.
    #[test]
    #[serial_test::serial(stun_store)]
    fn the_report_flag_changes_no_other_no_sip_branch() {
        let cases = [
            (
                undecodable_of(49, &[(crate::capture::UndecodableReason::NotIp(None), 49)]),
                50,
                tls_report(0, 0, 0),
            ),
            (undecodable_of(0, &[]), 42, tls_report(1, 9, 0)),
            (undecodable_of(0, &[]), 4_212, tls_report(0, 0, 0)),
        ];
        for (undecodable, frames, tls) in &cases {
            let with = no_sip_guidance(0, 0, true, undecodable, *frames, tls);
            let without = no_sip_guidance(0, 0, false, undecodable, *frames, tls);
            assert!(!with.is_empty(), "every no-SIP branch prints guidance");
            assert_eq!(
                with, without,
                "only the media-only message may depend on the report"
            );
        }
    }

    /// Kernel-buffer and interface drops must be named SEPARATELY, with their
    /// own counts and their own remedies. Summing them would tell an operator
    /// to raise `-B` for a driver drop that a bigger buffer cannot fix — the
    /// single most common wrong response to a drop counter.
    #[test]
    #[serial_test::serial(kernel_drop_counts)]
    fn kernel_and_interface_drops_are_reported_separately_with_remedies() -> Result<(), TestError> {
        use std::sync::atomic::Ordering::Relaxed;
        let before_k = crate::capture::live::KERNEL_DROPPED.load(Relaxed);
        let before_i = crate::capture::live::IFACE_DROPPED.load(Relaxed);
        crate::capture::live::KERNEL_DROPPED.fetch_add(7, Relaxed);
        crate::capture::live::IFACE_DROPPED.fetch_add(3, Relaxed);

        let msg = capture_quality_summary().ok_or("drops must be reported")?;

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
        Ok(())
    }

    /// A run that shed nothing must stay quiet.
    ///
    /// Without this the obvious implementation — always print the counters —
    /// would pass the other test while adding a line to every clean run, and a
    /// warning that fires constantly is one operators learn to skim past.
    #[test]
    fn a_run_that_kept_everything_reports_no_retention_loss() -> Result<(), TestError> {
        let mut store = DialogStore::new(16, true);
        store.process_message(invite_msg("kept-1@example.com")?);

        assert_eq!(
            retention_summary(&store),
            None,
            "nothing was shed, so there is nothing to warn about"
        );
        Ok(())
    }

    /// A dialog discarded at capacity must be named, with its count.
    ///
    /// The defect this closes: three separate loss counters existed, each
    /// carefully documented, and NONE had a consumer outside its own unit test.
    /// On the corpus 402 messages were evicted while the summary reported
    /// 103,234 SIP messages and said nothing, because the packet counters sit
    /// upstream of the store — they count what arrived, not what was kept.
    #[test]
    fn a_dialog_discarded_at_capacity_is_named_with_its_count() -> Result<(), TestError> {
        // Capacity one, rotating: the second dialog displaces the first.
        let mut store = DialogStore::new(1, true);
        store.process_message(invite_msg("first@example.com")?);
        store.process_message(invite_msg("second@example.com")?);

        assert_eq!(
            store.total_capacity_dialogs_evicted(),
            1,
            "the fixture must actually evict, or this test proves nothing"
        );

        let msg = retention_summary(&store).ok_or("an eviction must be reported")?;
        assert!(
            msg.contains('1') && msg.contains("discarded at capacity"),
            "the warning must carry the count and the cause: {msg}"
        );
        assert!(
            msg.contains("what sipnab READ"),
            "it must say the totals above are not what was kept: {msg}"
        );
        Ok(())
    }

    /// Retention follows the operator's consent, and NOTHING else.
    ///
    /// The history is three defects, and they point in different directions.
    /// First retention was hardcoded off, so `export_audio` decoded an
    /// always-empty buffer and failed for every call in every capture. Then
    /// the fix armed it for EVERY `--mcp` run, holding call audio in memory
    /// whether or not anything would ever export it — a privacy decision made
    /// on the operator's behalf. Then the fix for THAT required `--mcp`
    /// alongside the opt-in, which was right while the MCP server was the only
    /// consumer and became wrong the moment the amplitude measurement started
    /// reading the same buffers on `--call-report` and `--json-dialogs`.
    ///
    /// So all four combinations are still pinned, and the rule they pin is now
    /// the single conjunct: `--retain-audio`, whatever else the run is doing.
    /// The privacy half is unchanged and is the one that matters — enabling a
    /// server is still not consent to hold call audio.
    /// A `[[vcon.rule]]` that asks for `audio = "inline"` is consent to keep
    /// call audio, as `--retain-audio` is. A rule that omits audio, or says
    /// nothing, keeps none.
    #[cfg(feature = "vcon")]
    #[test]
    fn an_inline_audio_rule_retains_audio_and_no_other_rule_does() {
        let rule = |audio: Option<&str>| crate::config::VconRuleConfig {
            name: "r".into(),
            when: "method == 'INVITE'".into(),
            dir: Some("/d".into()),
            audio: audio.map(str::to_owned),
            max_inline_media_mib: None,
            audio_url_base: None,
            audio_format: None,
            grouping: None,
            live_audio: None,
            live: None,
            encrypt_to: None,
            sign_key: None,
            sign_cert: None,
            ..Default::default()
        };
        let mut config = crate::config::Config::default();
        assert!(!audio_retention_wanted(&base_cli(), &config));
        config.vcon.rule = vec![rule(None), rule(Some("omit"))];
        assert!(!audio_retention_wanted(&base_cli(), &config));
        config.vcon.rule.push(rule(Some("inline")));
        assert!(audio_retention_wanted(&base_cli(), &config));
    }

    #[test]
    fn audio_payload_is_retained_exactly_when_asked_and_readable() {
        let mut cli = base_cli();

        cli.mcp_args.mcp = false;
        cli.mcp_args.retain_audio = false;
        assert!(
            !audio_retention_wanted(&cli, &Config::default()),
            "a run that did not ask for audio must not pay the clone"
        );

        cli.mcp_args.mcp = true;
        cli.mcp_args.retain_audio = false;
        assert!(
            !audio_retention_wanted(&cli, &Config::default()),
            "enabling an MCP server is not consent to hold call audio in \
             memory — this is the arming-by-default the opt-in exists to end"
        );

        cli.mcp_args.mcp = false;
        cli.mcp_args.retain_audio = true;
        assert!(
            audio_retention_wanted(&cli, &Config::default()),
            "a plain batch run has a reader now: the amplitude measurement in \
             the media diagnosis, which is the one finding that needs the \
             samples and reaches every surface a diagnosis reaches"
        );

        cli.mcp_args.mcp = true;
        cli.mcp_args.retain_audio = true;
        assert!(
            audio_retention_wanted(&cli, &Config::default()),
            "export_audio decodes these buffers; with retention off it cannot succeed"
        );
    }

    /// `--retain-audio` stands on its own.
    ///
    /// It used to carry a clap `requires = "mcp"`, and the reasoning was
    /// sound: a flag that parses and does nothing is the `--alert` defect (#35)
    /// in new clothes, and the MCP server was the only thing that could read
    /// the buffers back. The amplitude measurement reads them now on a plain
    /// batch run, so the constraint would keep the one finding that needs
    /// samples behind a server nobody analyzing a pcap wants to start.
    ///
    /// Both halves are asserted: that it parses, and that the run it produces
    /// actually retains. Parsing alone would be the `--alert` defect again.
    #[test]
    fn retain_audio_stands_alone_now_that_a_batch_run_reads_it() -> Result<(), TestError> {
        use clap::Parser as _;
        let cli = Cli::try_parse_from([
            "sipnab",
            "-N",
            "-I",
            "tests/pcap-samples/sip-rtp-g711.pcap",
            "--retain-audio",
        ])
        .map_err(|e| format!("--retain-audio must parse without --mcp: {e:?}"))?;
        assert!(
            audio_retention_wanted(&cli, &Config::default()),
            "it parsed and then retained nothing, which is a flag that does \
             nothing wearing a different hat"
        );
        Ok(())
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
        assert!(!apply_audio_retention(&mut ss, &cli, &Config::default()));
        assert!(
            !ss.audio_capture(),
            "a non-MCP run must leave retention OFF; leaving the constructor's \
             default in place buffers every stream's audio, up to the 1 GiB \
             budget, that nothing in this run can read"
        );

        cli.mcp_args.mcp = true;
        cli.mcp_args.retain_audio = true;
        let mut ss = StreamStore::new(16);
        assert!(apply_audio_retention(&mut ss, &cli, &Config::default()));
        assert!(
            ss.audio_capture(),
            "export_audio decodes payload_buffer, so a consenting MCP run must retain"
        );

        // The middle state — MCP on, consent absent — is the arming-by-default
        // this ticket removed, and it must land OFF on the store, not just in
        // the predicate.
        cli.mcp_args.retain_audio = false;
        let mut ss = StreamStore::new(16);
        assert!(!apply_audio_retention(&mut ss, &cli, &Config::default()));
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
    fn the_relay_snapshot_reaches_the_store_this_mode_builds() -> Result<(), TestError> {
        use crate::relay::reconcile::{RelayLink, RelaySnapshot};
        use crate::rtp::stream_store::EndpointAssertion;
        use std::net::{IpAddr, Ipv4Addr};

        let relay = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let snapshot = RelaySnapshot {
            implementation: crate::relay::RelayImplementation::Rtpengine,
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
            .ok_or("the snapshot must be registered on this mode's store")?;
        assert_eq!(
            provenance.asserted_by,
            EndpointAssertion::media_relay(
                crate::relay::RelayImplementation::Rtpengine,
                crate::relay::ControlDelivery::Encapsulated
            ),
            "the relay asserted this allocation; no party's SDP did"
        );
        Ok(())
    }

    /// `[limits] max_audio_frames` and `max_audio_bytes` reach the store a
    /// live capture builds, and unset means the whole call inside the default
    /// budget.
    #[test]
    fn the_live_store_takes_the_configured_audio_limits() {
        use crate::relay::reconcile::RelaySnapshot;
        use crate::rtp::stream_store::{AudioLimits, MIN_MAX_AUDIO_BYTES};
        let unset =
            build_live_stream_store(&base_cli(), &Config::default(), &RelaySnapshot::default());
        assert_eq!(unset.audio_limits(), AudioLimits::default());
        assert_eq!(unset.audio_limits().max_frames, None, "the whole call");
        let mut config = Config::default();
        config.limits.max_audio_frames = Some(700);
        config.limits.max_audio_bytes = Some(MIN_MAX_AUDIO_BYTES * 3);
        let set = build_live_stream_store(&base_cli(), &config, &RelaySnapshot::default());
        assert_eq!(
            set.audio_limits(),
            AudioLimits {
                max_frames: Some(700),
                max_bytes: (MIN_MAX_AUDIO_BYTES * 3) as usize,
            }
        );
    }

    /// The `--cores` paths take the same audio limits from the same keys.
    #[test]
    fn parallel_config_takes_the_configured_audio_limits() {
        let cli = Cli::parse_from_args(["sipnab"]);
        let mut config = Config::default();
        config.limits.max_audio_bytes = Some(5 * 1024 * 1024);
        assert_eq!(
            parallel_config(&cli, &config, (1, 65535), false).audio_limits,
            config.limits.audio_limits()
        );
        assert_eq!(
            parallel_config(&cli, &Config::default(), (1, 65535), false).audio_limits,
            crate::rtp::stream_store::AudioLimits::default()
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
    fn drive_packets_dtmf(
        cli: &Cli,
        packets: &[ParsedPacket],
        portrange: (u16, u16),
    ) -> Result<u64, TestError> {
        let matcher = SipMatcher::new(cli, None).map_err(|e| format!("matcher: {e:?}"))?;
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
            detect_only: false,
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
            dtmf_seen: rtp::dtmf::DtmfDedupe::default(),
        };
        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            telephone_events: cli.mode_args.telephone_event,
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
                #[cfg(feature = "tls")]
                export: None,
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
        Ok(counters.dtmf_count)
    }

    /// A telephone-event stream negotiated at a non-101 payload type must be
    /// decoded using the SDP-negotiated PT — not the hard-coded 101. Feeding
    /// the SDP offer (PT 96) then an RTP DTMF packet with PT 96 yields one
    /// decoded digit; the pre-fix code (expecting PT 101) decoded zero.
    #[test]
    fn dtmf_honors_negotiated_non_101_payload_type() -> Result<(), TestError> {
        let mut cli = base_cli();
        cli.mode_args.telephone_event = true;
        let packets = [
            parsed_sip_packet(invite_with_te_sdp("dtmf-96@x", 40000, 96, 8000), 5060, 5060),
            rtp_dtmf_packet(40000, 96, 0x1111_2222, 5, 800),
        ];
        let dtmf = drive_packets_dtmf(&cli, &packets, (5060, 5061))?;
        assert_eq!(dtmf, 1, "negotiated PT 96 telephone-event must decode");
        Ok(())
    }

    /// The negotiated telephone-event clock rate is plumbed through alongside
    /// the PT: a wideband (16000 Hz) rtpmap still decodes the completed event.
    /// (Both PT and clock come from the same resolved-stream lookup, so a
    /// non-default clock also exercises the clock-rate wiring.)
    #[test]
    fn dtmf_honors_negotiated_wideband_clock() -> Result<(), TestError> {
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
        let dtmf = drive_packets_dtmf(&cli, &packets, (5060, 5061))?;
        assert_eq!(dtmf, 1, "negotiated 16 kHz telephone-event must decode");
        Ok(())
    }

    /// With no SDP telephone-event negotiation seen, the PT 101 convention is
    /// the fallback: a PT-101 DTMF packet still decodes.
    #[test]
    fn dtmf_falls_back_to_pt_101_without_sdp() -> Result<(), TestError> {
        let mut cli = base_cli();
        cli.mode_args.telephone_event = true;
        let packets = [rtp_dtmf_packet(40000, 101, 0x5555_6666, 9, 800)];
        let dtmf = drive_packets_dtmf(&cli, &packets, (5060, 5061))?;
        assert_eq!(dtmf, 1, "PT 101 fallback must decode when no SDP is seen");
        Ok(())
    }

    /// `tests/pcap-samples/SIP_DTMF2.cap`, parsed: every frame sipnab
    /// decodes, in capture order.
    fn sip_dtmf2_packets() -> Result<Vec<ParsedPacket>, TestError> {
        let data = std::fs::read("tests/pcap-samples/SIP_DTMF2.cap")?;
        let mut packets = Vec::new();
        for record in crate::capture::pcap_reader::PcapReader::new(&data)? {
            let at = chrono::DateTime::from_timestamp(
                i64::from(record.timestamp_secs),
                record.timestamp_usecs * 1000,
            )
            .ok_or("a capture timestamp")?;
            let caplen = record.data.len();
            let frame = crate::capture::packet::Packet::new(
                at,
                record.data,
                caplen,
                record.orig_len as usize,
                None,
                record.link_type as i32,
            );
            if let Ok(pp) = crate::capture::parse::parse_packet(&frame) {
                packets.push(pp);
            }
        }
        Ok(packets)
    }

    /// The seven keys of `SIP_DTMF2.cap` land on the stream its dialog owns.
    ///
    /// The capture's 200 OK binds `a=rtpmap:96 telephone-event/8000`, and the
    /// events ride PT 96 on the SSRC that carries the PCMA audio, sent from
    /// 192.168.105.172:4376, a socket no SDP in the dialog advertised, to
    /// 192.168.105.110:4376, the socket the 200 OK advertised. The stream is
    /// tied to the dialog by that destination, the same link every other
    /// stream gets, so the keys are recorded there.
    #[test]
    fn a_dynamic_telephone_event_type_on_the_audio_ssrc_is_decoded() -> Result<(), TestError> {
        let mut cli = base_cli();
        cli.mode_args.telephone_event = true;
        let packets = sip_dtmf2_packets()?;
        let driven = drive_packets_kept(
            &cli,
            &packets,
            EventExecEngine::new(
                None,
                None,
                0,
                0.0,
                crate::output::event_exec::DEFAULT_QUEUE_DEPTH,
            ),
        )?;
        assert_eq!(driven.counters.dtmf_count, 7);
        let sender: std::net::SocketAddr = "192.168.105.172:4376".parse()?;
        let pressed: Vec<(std::net::SocketAddr, String)> = driven
            .streams
            .streams_for("25672@192.168.105.110")
            .flat_map(|s| {
                s.key_presses
                    .iter()
                    .map(move |p| (s.key.src, p.digit.to_string()))
            })
            .collect();
        let expected: Vec<(std::net::SocketAddr, String)> =
            "6789123".chars().map(|d| (sender, d.to_string())).collect();
        assert_eq!(pressed, expected);
        Ok(())
    }

    /// What [`drive_packets_kept`] leaves behind: the counters, the stream
    /// store and the event engine, with nothing drained or spawned.
    struct DrivenPackets {
        counters: PacketCounters,
        streams: StreamStore,
        event_exec: EventExecEngine,
    }

    /// Drive packets through one shared set of stores, as
    /// [`drive_packets_dtmf`] does, but keep the state for inspection and
    /// never drain the deferred effects, so no queued hook is spawned.
    fn drive_packets_kept(
        cli: &Cli,
        packets: &[ParsedPacket],
        mut event_exec: EventExecEngine,
    ) -> Result<DrivenPackets, TestError> {
        let matcher = SipMatcher::new(cli, None).map_err(|e| format!("matcher: {e:?}"))?;
        let filter_expr: Option<FilterExpr> = None;
        let output_opts = OutputOptions::default();
        let mut dialog_store = DialogStore::new(100, false);
        let mut stream_store = StreamStore::new(100);
        let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();
        let mut engines = DetectionEngines {
            scanner: None,
            fraud: None,
            digest: None,
            reg_flood: None,
            alerts: Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None))),
            kill_handle: None,
            detect_only: false,
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
            dtmf_seen: rtp::dtmf::DtmfDedupe::default(),
        };
        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            telephone_events: cli.mode_args.telephone_event,
            after_count: 0,
            portrange: (5060, 5061),
        };
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
                #[cfg(feature = "tls")]
                export: None,
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
        Ok(DrivenPackets {
            counters,
            streams: stream_store,
            event_exec,
        })
    }

    /// An RTP packet to `dst_port` with sequence number `seq`, built on the
    /// telephone-event fixture so only the addressing and sequence differ.
    fn rtp_packet_seq(dst_port: u16, seq: u16, ssrc: u32) -> ParsedPacket {
        let mut pp = rtp_dtmf_packet(dst_port, 0, ssrc, 1, 160);
        let mut payload = pp.payload.to_vec();
        payload[2..4].copy_from_slice(&seq.to_be_bytes());
        pp.payload = bytes::Bytes::from(payload);
        pp
    }

    /// A stream found only by the heuristic is counted in the run's RTP total
    /// like any other: the total and the packets the store recorded agree.
    ///
    /// Port 1000 is a system port, so the payload check alone cannot admit
    /// these packets and only the heuristic's three-in-a-row rule does.
    #[test]
    fn a_heuristic_rtp_packet_is_counted_in_the_rtp_total() -> Result<(), TestError> {
        let cli = base_cli();
        let packets: Vec<ParsedPacket> = (1..=4)
            .map(|seq| rtp_packet_seq(1000, seq, 0x0bad_cafe))
            .collect();
        let driven = drive_packets_kept(
            &cli,
            &packets,
            EventExecEngine::new(
                None,
                None,
                0,
                0.0,
                crate::output::event_exec::DEFAULT_QUEUE_DEPTH,
            ),
        )?;
        let stored: u64 = driven.streams.iter().map(|s| s.packet_count).sum();
        assert!(stored > 0, "the heuristic must have admitted the flow");
        assert_eq!(driven.counters.rtp_count, stored);
        Ok(())
    }

    /// An RTP packet on a stream the signaling explains queues a quality
    /// event when `--on-quality` is configured and the estimate is below the
    /// threshold. The command is queued, not spawned: the caller spawns it
    /// once the store guards drop.
    #[test]
    fn an_rtp_packet_below_the_quality_threshold_queues_a_quality_event() -> Result<(), TestError> {
        let cli = base_cli();
        let packets = [
            parsed_sip_packet(invite_with_te_sdp("quality@x", 40000, 96, 8000), 5060, 5060),
            rtp_packet_seq(40000, 1, 0x1234_5678),
        ];
        let driven = drive_packets_kept(
            &cli,
            &packets,
            EventExecEngine::new(
                None,
                Some("true".to_owned()),
                10,
                5.0,
                crate::output::event_exec::DEFAULT_QUEUE_DEPTH,
            ),
        )?;
        assert_eq!(driven.counters.rtp_count, 1);
        assert_eq!(
            driven.event_exec.pending_depth(),
            1,
            "a MOS estimate under a 5.0 threshold queues one event"
        );
        Ok(())
    }

    /// A reconciler that starts switches the store to recording the
    /// sockets of streams nothing explains, so the receive loop has
    /// something to offer it; with no reconciler nothing is recorded.
    ///
    /// Nothing is offered here, so the reconciler thread never asks its
    /// relay: dropping the sink ends its loop.
    #[test]
    fn a_started_reconciler_makes_the_store_record_orphan_sockets() -> Result<(), TestError> {
        let store = Arc::new(RwLock::new(StreamStore::new(16)));
        let (none_sink, none_thread) = spawn_relay_reconciler(None, &store);
        assert!(none_sink.is_none() && none_thread.is_none());

        let ready = crate::app::bootstrap::ReadyReconciler {
            reconciler: crate::relay::reconcile::Reconciler::new(
                crate::rtpengine::control::ControlClient::new(
                    "127.0.0.1:9"
                        .parse()
                        .map_err(|e| format!("address: {e:?}"))?,
                    std::time::Duration::from_millis(50),
                ),
            ),
            permit: crate::security::transmit_guard::TransmitPermit::for_source(
                &crate::capture::CaptureSource::Live {
                    device: "lo".to_owned(),
                },
            )
            .ok_or("a live source grants a permit")?,
        };
        let (sink, thread) = spawn_relay_reconciler(Some(ready), &store);
        assert!(sink.is_some() && thread.is_some());

        let pp = rtp_packet_seq(40000, 1, 0x0a0b_0c0d);
        let hdr =
            rtp::parser::parse_rtp_header(&pp.payload).map_err(|e| format!("rtp header: {e:?}"))?;
        store.write().process_rtp(&pp, &hdr, pp.timestamp);
        let recorded = store.write().drain_new_orphan_sockets();
        assert!(
            !recorded.is_empty(),
            "a stream nothing explains is recorded for the reconciler"
        );

        drop(sink);
        thread
            .ok_or("thread")?
            .join()
            .map_err(|e| format!("reconciler thread ends cleanly: {e:?}"))?;
        Ok(())
    }

    // ── tshark_input_file ──────────────────────────────────────────────

    /// The input file (`-I`) is preferred, and wins over any output file.
    #[test]
    fn tshark_input_file_prefers_input() -> Result<(), TestError> {
        let one = [PathBuf::from("in.pcap")];
        assert_eq!(tshark_input_file(&one, Some("out.pcap"))?, "in.pcap");
        assert_eq!(tshark_input_file(&one, None)?, "in.pcap");
        Ok(())
    }

    /// A custom `--tshark-filter` on a live capture WITHOUT `-I` references
    /// the real saved pcap (`-O`) instead of the old `capture.pcap` placeholder.
    #[test]
    fn tshark_input_file_custom_filter_without_input_uses_output() -> Result<(), TestError> {
        let f = tshark_input_file(&[], Some("saved.pcap"))
            .map_err(|e| format!("a saved output file is a valid tshark source: {e:?}"))?;
        assert_eq!(f, "saved.pcap");
        Ok(())
    }

    /// A live capture with neither `-I` nor `-O` has no pcap for tshark to
    /// read: error clearly rather than emitting a bogus `capture.pcap`.
    #[test]
    fn tshark_input_file_no_input_no_output_errors() -> Result<(), TestError> {
        let err = tshark_input_file(&[], None)
            .err()
            .ok_or("no pcap source must be an error, not a placeholder")?;
        assert!(!err.contains("capture.pcap"), "must not name a placeholder");
        assert!(err.contains("-I") && err.contains("-O"), "got: {err}");
        Ok(())
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
    fn tshark_input_file_refuses_a_multi_file_set_and_names_them_all() -> Result<(), TestError> {
        let set = [
            PathBuf::from("first.pcap"),
            PathBuf::from("second.pcap"),
            PathBuf::from("third.pcap"),
        ];
        let err = tshark_input_file(&set, None)
            .err()
            .ok_or("a set tshark cannot read in one command must be refused")?;
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
        Ok(())
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
            detect_only: false,
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
    ) -> Result<(String, usize), TestError> {
        let portrange = (5060, 5061);
        let matcher = SipMatcher::new(cli, None).map_err(|e| format!("matcher: {e:?}"))?;
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
            telephone_events: cli.mode_args.telephone_event,
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
            dtmf_seen: rtp::dtmf::DtmfDedupe::default(),
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
                #[cfg(feature = "tls")]
                export: None,
                group: None,
            };
            process_parsed_packet(pp, &ctx, &mut state, engines, &mut counters, &mut effects);
            queued += effects.alerts.len();
            effects.drain(&mut sink, &engines.alerts, &mut event_exec);
        }
        sink.flush();
        Ok((
            String::from_utf8(sink.into_inner()).map_err(|e| format!("output is utf-8: {e:?}"))?,
            queued,
        ))
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
    fn hep_origin_reg_flood_never_reaches_the_jail_log() -> Result<(), TestError> {
        use crate::capture::parse::InputOrigin;
        let mut cli = fail2ban_cli();
        let armed = || {
            let mut engines = unarmed_engines();
            engines.reg_flood = Some(RegFloodDetector::new(2));
            engines
        };

        let (out, queued) =
            drive_detections(&cli, &mut armed(), &refused_registrations(InputOrigin::Hep))?;
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
        )?;
        assert!(
            out.contains("reg_flood src=10.0.0.1 count=3"),
            "control: a wire-origin flood must reach the jail log, else the gate above is \
             vacuous:\n{out}"
        );

        // Opt-in: --hep-allow-kill admits HEP-origin detections to the log the
        // same way it admits them to the wire.
        cli.security_args.hep_allow_kill = true;
        let (out, _) =
            drive_detections(&cli, &mut armed(), &refused_registrations(InputOrigin::Hep))?;
        assert!(
            out.contains("reg_flood src=10.0.0.1 count=3"),
            "--hep-allow-kill must admit a HEP-origin flood to the jail log:\n{out}"
        );
        Ok(())
    }

    /// The scanner-signature site: same rule.
    #[test]
    fn hep_origin_scanner_detection_never_reaches_the_jail_log() -> Result<(), TestError> {
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

        let (out, queued) = drive_detections(&cli, &mut armed(), &probe(InputOrigin::Hep))?;
        assert_eq!(
            queued, 1,
            "the signature match must still be queued as an alert"
        );
        assert!(
            !out.contains("scanner_detected"),
            "a scanner detection whose addressing a HEP sender asserted reached the jail \
             log:\n{out}"
        );

        let (out, _) = drive_detections(&cli, &mut armed(), &probe(InputOrigin::Wire))?;
        assert!(
            out.contains("scanner_detected src=10.0.0.1"),
            "control: a wire-origin detection must reach the jail log:\n{out}"
        );
        Ok(())
    }

    /// The `-K/--kill-target` site: same rule. The operator named the
    /// address, which is why `-K` may transmit at all -- but under HEP the
    /// address a packet claims to come from is still the sender's word, and
    /// a jail line names that claim.
    #[test]
    fn hep_origin_kill_target_match_never_reaches_the_jail_log() -> Result<(), TestError> {
        use crate::capture::parse::InputOrigin;
        let cli = fail2ban_cli();
        let armed = || -> Result<_, TestError> {
            let mut engines = unarmed_engines();
            engines.kill_targets = vec![
                sec::scanner_kill::KillTarget::parse("10.0.0.1")
                    .map_err(|e| format!("target: {e:?}"))?,
            ];
            Ok(engines)
        };
        let request = |origin| {
            vec![parsed_sip_from(
                origin,
                register_bytes("z9hG4bK-kt", false),
                [10, 0, 0, 1],
                [10, 0, 0, 2],
            )]
        };

        let (out, queued) = drive_detections(&cli, &mut armed()?, &request(InputOrigin::Hep))?;
        assert_eq!(
            queued, 1,
            "the kill-target match must still be queued as an alert"
        );
        assert!(
            !out.contains("scanner_detected"),
            "a kill-target match whose addressing a HEP sender asserted reached the jail \
             log:\n{out}"
        );

        let (out, _) = drive_detections(&cli, &mut armed()?, &request(InputOrigin::Wire))?;
        assert!(
            out.contains("scanner_detected src=10.0.0.1"),
            "control: a wire-origin match must reach the jail log:\n{out}"
        );
        Ok(())
    }

    /// A uprobe read carries no addressing at all, and no opt-in reaches it:
    /// `--hep-allow-kill` is about HEP, and bytes lifted out of a process
    /// name no socket a firewall could ban.
    #[test]
    fn uprobe_origin_never_reaches_the_jail_log_even_with_the_opt_in() -> Result<(), TestError> {
        use crate::capture::parse::InputOrigin;
        let mut cli = fail2ban_cli();
        cli.security_args.hep_allow_kill = true;
        let mut engines = unarmed_engines();
        engines.reg_flood = Some(RegFloodDetector::new(2));

        let (out, queued) = drive_detections(
            &cli,
            &mut engines,
            &refused_registrations(InputOrigin::Uprobe),
        )?;
        assert!(queued >= 1, "the detection must still reach the alert path");
        assert!(
            !out.contains("reg_flood src="),
            "a uprobe-origin flood reached the jail log under --hep-allow-kill, which is an \
             opt-in about HEP and must not reach input that has no address at all:\n{out}"
        );
        Ok(())
    }

    /// Every output backend (default text, JSON, pretty JSON, fail2ban, raw
    /// dump, suppressed, line-buffered) produces its expected bytes.
    #[test]
    fn dispatch_sip_output_all_modes() -> Result<(), TestError> {
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
        .map_err(|e| format!("invite should parse: {e:?}"))?;
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
            String::from_utf8(out).map_err(|e| format!("utf8: {e:?}"))?,
            crate::output::cli_print::format_sip_message(&msg, &opts, None),
        );

        // JSON: byte-identical to message_to_json (NDJSON line + newline).
        let mut cli = base_cli();
        cli.output_args.json = true;
        assert_eq!(
            String::from_utf8(sink_bytes(&cli, None)).map_err(|e| format!("utf8: {e:?}"))?,
            output::json::message_to_json(&msg),
        );

        // Pretty JSON: byte-identical to message_to_json_pretty.
        let mut cli = base_cli();
        cli.output_args.json_pretty = true;
        assert_eq!(
            String::from_utf8(sink_bytes(&cli, None)).map_err(|e| format!("utf8: {e:?}"))?,
            output::json::message_to_json_pretty(&msg),
        );

        // fail2ban: a plain request is NOT a detection, so nothing is written.
        // This assertion used to require an event line for any request, which
        // is the whole defect: fail2ban bans what it is handed, and every peer
        // on a trunk sends requests. Detections reach the sink from the
        // detector paths, not from here.
        let mut cli = base_cli();
        cli.output_args.fail2ban = true;
        let out = String::from_utf8(sink_bytes(&cli, None)).map_err(|e| format!("utf8: {e:?}"))?;
        assert!(
            out.is_empty(),
            "an ordinary request must produce no fail2ban output, got {out:?}"
        );

        // raw text dump: raw message + newline.
        let mut cli = base_cli();
        cli.output_args.text_dump = true;
        let out = String::from_utf8(sink_bytes(&cli, None)).map_err(|e| format!("utf8: {e:?}"))?;
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
        Ok(())
    }

    // ── generate_reports ───────────────────────────────────────────────

    /// The report chain ends in the one-shot query dispatcher, and a query
    /// that cannot be answered fails the chain the way a failed report does.
    /// `--cores` reaches the same chain through `report_parallel_run`.
    #[test]
    fn the_report_chain_ends_in_the_query_dispatcher() -> Result<(), TestError> {
        let dialog_store = DialogStore::new(10, false);
        let stream_store = StreamStore::new(10);
        let run = |cli: &Cli| {
            generate_reports(
                cli,
                &Config::default(),
                CaptureRead {
                    dialogs: &dialog_store,
                    streams: &stream_store,
                    frames_read: 0,
                },
                None,
                &[],
                None,
                VconRunEnd::Whole,
            )
        };
        let mut cli = base_cli();
        assert!(run(&cli), "no query asked for: the chain succeeds");
        cli.test_one_shots.push(crate::cli::OneShot {
            name: crate::app::queries::TEST_FAILING_QUERY,
            active: true,
            implies_no_tui: true,
            owns_stdout: true,
        });
        assert!(!run(&cli), "a query that failed must fail the chain");
        Ok(())
    }

    /// A window that holds none of the capture's dialogs says so, with the
    /// window and the span the dialogs cover; a window holding one says
    /// nothing, and so does a run with no window.
    #[test]
    fn a_window_holding_no_dialog_is_an_explicit_empty_answer() -> Result<(), TestError> {
        let mut store = DialogStore::new(10, false);
        for (id, when) in [
            ("a@example.com", "2023-11-14T22:13:20Z"),
            ("b@example.com", "2023-11-14T22:13:32Z"),
        ] {
            let data = bytes::Bytes::from(invite_bytes(id));
            store.process_message(sip::parser::parse_sip_bytes(
                &data,
                crate::cursor::parse_instant(when)?,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                5060,
                5060,
                TransportProto::Udp,
            )?);
        }
        let with = |args: &[&str]| {
            let mut argv = vec!["sipnab", "-N", "-I", "x.pcap"];
            argv.extend_from_slice(args);
            Cli::parse_from_args(argv)
        };
        let notice = time_window_notice(&with(&["--since", "2030-01-01T00:00:00Z"]), &store)
            .ok_or("a window past the capture must say so")?;
        assert!(notice.contains("2030-01-01T00:00:00Z"), "{notice}");
        assert!(
            notice.contains("2023-11-14T22:13:20Z") && notice.contains("2023-11-14T22:13:32Z"),
            "names the span the dialogs cover: {notice}"
        );
        // The upper bound is exclusive: a window ending AT the first dialog
        // holds none of them.
        assert!(time_window_notice(&with(&["--until", "2023-11-14T22:13:20Z"]), &store).is_some());
        assert_eq!(
            time_window_notice(&with(&["--until", "2023-11-14T22:13:21Z"]), &store),
            None
        );
        assert_eq!(time_window_notice(&with(&[]), &store), None);
        let empty = DialogStore::new(10, false);
        let none = time_window_notice(&with(&["--since", "2030-01-01T00:00:00Z"]), &empty)
            .ok_or("an empty capture in a window says so too")?;
        assert!(none.contains("no dialog"), "{none}");
        Ok(())
    }

    /// `--report` and `--call-report` run without panicking on empty stores,
    /// unknown Call-IDs, and a tracked dialog across all report formats.
    #[test]
    fn generate_reports_summary_and_call_report() -> Result<(), TestError> {
        let mut dialog_store = DialogStore::new(100, false);
        let stream_store = StreamStore::new(100);

        // Empty --report summary path.
        let mut cli = base_cli();
        cli.output_args.report = true;
        generate_reports(
            &cli,
            &Config::default(),
            CaptureRead {
                dialogs: &dialog_store,
                streams: &stream_store,
                frames_read: 0,
            },
            None,
            &[],
            None,
            VconRunEnd::Whole,
        );

        // --call-report for an unknown Call-ID hits the "not found" warn arm.
        let mut cli = base_cli();
        cli.output_args.call_report = Some("does-not-exist".to_string());
        generate_reports(
            &cli,
            &Config::default(),
            CaptureRead {
                dialogs: &dialog_store,
                streams: &stream_store,
                frames_read: 0,
            },
            None,
            &[],
            None,
            VconRunEnd::Whole,
        );

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
        )?;
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
            generate_reports(
                &cli,
                &Config::default(),
                CaptureRead {
                    dialogs: &dialog_store,
                    streams: &stream_store,
                    frames_read: 0,
                },
                None,
                &[],
                None,
                VconRunEnd::Whole,
            );
        }
        Ok(())
    }

    // ── process_parsed_packet ──────────────────────────────────────────

    /// Build the engine/state/context scaffolding and drive a single packet,
    /// returning the resulting (sip_count, rtp_count).
    fn drive_packet(
        cli: &Cli,
        pp: &ParsedPacket,
        portrange: (u16, u16),
    ) -> Result<(u64, u64), TestError> {
        let matcher = SipMatcher::new(cli, None).map_err(|e| format!("matcher: {e:?}"))?;
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
            detect_only: false,
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
            dtmf_seen: rtp::dtmf::DtmfDedupe::default(),
        };

        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            telephone_events: cli.mode_args.telephone_event,
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
                #[cfg(feature = "tls")]
                export: None,
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
        Ok((counters.sip_count, counters.rtp_count))
    }

    /// Drive one packet with `--kill-target` directives active and return the
    /// detail lines of any "scanner" findings the alert engine recorded. Uses
    /// `kill_handle: None`, so no socket send is attempted — the targeted-kill
    /// alert still fires before the (absent) worker handoff.
    fn drive_kill_targets(
        cli: &Cli,
        pp: &ParsedPacket,
        targets: &[&str],
    ) -> Result<Vec<String>, TestError> {
        let matcher = SipMatcher::new(cli, None).map_err(|e| format!("matcher: {e:?}"))?;
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
            .map(|s| {
                sec::scanner_kill::KillTarget::parse(s).map_err(|e| format!("valid target: {e:?}"))
            })
            .collect::<Result<_, _>>()?;
        let alerts = Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None)));
        let mut engines = DetectionEngines {
            scanner: None,
            fraud: None,
            digest: None,
            reg_flood: None,
            alerts: Arc::clone(&alerts),
            kill_handle: None,
            detect_only: false,
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
            dtmf_seen: rtp::dtmf::DtmfDedupe::default(),
        };
        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            telephone_events: cli.mode_args.telephone_event,
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
                #[cfg(feature = "tls")]
                export: None,
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

        Ok(alerts
            .read()
            .iter_findings(&["scanner"], None, 16)
            .into_iter()
            .map(|f| f.detail.clone())
            .collect())
    }

    /// A request whose source IP:port falls inside a `--kill-target` range
    /// fires a kill-target scanner alert.
    #[test]
    fn kill_target_matching_request_fires_kill_alert() -> Result<(), TestError> {
        // parsed_sip_packet sources from 10.0.0.1; src_port 5075 is inside the
        // target's 5060-5090 range → the targeted kill must fire.
        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;
        let pp = parsed_sip_packet(invite_bytes("kt-hit@example.com"), 5075, 5060);
        let details = drive_kill_targets(&cli, &pp, &["10.0.0.1:5060-5090"])?;
        assert!(
            details.iter().any(|d| d.contains("detection=kill-target")),
            "expected a kill-target alert, got {details:?}"
        );
        Ok(())
    }

    /// A source port outside the target's range must not trigger a kill.
    #[test]
    fn kill_target_out_of_range_port_does_not_fire() -> Result<(), TestError> {
        // src_port 6000 is outside 5060-5090 → no targeted kill.
        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;
        let pp = parsed_sip_packet(invite_bytes("kt-miss@example.com"), 6000, 5060);
        let details = drive_kill_targets(&cli, &pp, &["10.0.0.1:5060-5090"])?;
        assert!(
            !details.iter().any(|d| d.contains("kill-target")),
            "should not kill a source outside the port range, got {details:?}"
        );
        Ok(())
    }

    /// A source IP different from the target's must not trigger a kill.
    #[test]
    fn kill_target_wrong_ip_does_not_fire() -> Result<(), TestError> {
        // Target a different IP than the packet's source (10.0.0.1) → no kill.
        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;
        let pp = parsed_sip_packet(invite_bytes("kt-ip@example.com"), 5075, 5060);
        let details = drive_kill_targets(&cli, &pp, &["10.0.0.99:5060-5090"])?;
        assert!(
            !details.iter().any(|d| d.contains("kill-target")),
            "should not kill a non-targeted source IP, got {details:?}"
        );
        Ok(())
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
    fn side_effects_are_raised_under_the_guards_and_performed_after_them() -> Result<(), TestError>
    {
        let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let marker = dir.path().join("hook-ran");
        // `>>` opens with O_APPEND, so the file's existence and length are
        // evidence the shell command itself ran.
        let hook = format!("printf x >> {}", marker.display());

        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;

        let matcher = SipMatcher::new(&cli, None).map_err(|e| format!("matcher: {e:?}"))?;
        let filter_expr: Option<FilterExpr> = None;
        let output_opts = OutputOptions::default();
        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli: &cli,
            no_rtp: false,
            telephone_events: cli.mode_args.telephone_event,
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
            detect_only: false,
            kill_response_code: 200,
            // Matches the fixture's 10.0.0.1:5075 source, so one packet raises
            // both a hook command and an alert.
            kill_targets: vec![
                sec::scanner_kill::KillTarget::parse("10.0.0.1:5060-5090")
                    .map_err(|e| format!("valid target: {e:?}"))?,
            ],
        };
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
            dtmf_seen: rtp::dtmf::DtmfDedupe::default(),
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
                    #[cfg(feature = "tls")]
                    export: None,
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
        Ok(())
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
    fn deferred_output_preserves_emission_order() -> Result<(), TestError> {
        let mut cli = base_cli();
        // Two emitters in one packet: the hexdump block first, then the raw
        // message dump. Their relative order is the intra-packet assertion.
        cli.output_args.hexdump = true;
        cli.output_args.text_dump = true;

        let first = parsed_sip_packet(invite_bytes("ord-1@example.com"), 5060, 5060);
        let second = parsed_sip_packet(invite_bytes("ord-2@example.com"), 5060, 5060);
        let out = drive_packets_output(&cli, &[first.clone(), second.clone()], (5060, 5061))?;

        // Intra-packet: the hexdump of the first packet precedes its raw dump.
        let hex_at = out
            .find(&output::hexdump(&first.payload))
            .ok_or("the first packet's hexdump block must be present")?;
        let raw = String::from_utf8_lossy(&first.payload).into_owned();
        let raw_at = out
            .rfind(&raw)
            .ok_or("the first packet's raw dump must be present")?;
        assert!(
            hex_at < raw_at,
            "hexdump must precede the message it dumps (hex at {hex_at}, raw at {raw_at})"
        );

        // Cross-packet: everything the first packet emitted precedes anything
        // the second emitted.
        let second_at = out
            .find(&output::hexdump(&second.payload))
            .ok_or("the second packet's hexdump block must be present")?;
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
        Ok(())
    }

    /// Drive packets through the real lock-then-drain shape and return every
    /// byte that reached the sink, as the operator's stdout would have seen it.
    fn drive_packets_output(
        cli: &Cli,
        packets: &[ParsedPacket],
        portrange: (u16, u16),
    ) -> Result<String, TestError> {
        let matcher = SipMatcher::new(cli, None).map_err(|e| format!("matcher: {e:?}"))?;
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
            telephone_events: cli.mode_args.telephone_event,
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
            detect_only: false,
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
            dtmf_seen: rtp::dtmf::DtmfDedupe::default(),
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
                    #[cfg(feature = "tls")]
                    export: None,
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
        Ok(String::from_utf8(sink.into_inner()).map_err(|e| format!("output is utf-8: {e:?}"))?)
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
    ) -> Result<u64, TestError> {
        Ok(drive_packets_with_srtp(cli, std::slice::from_ref(pp), portrange, srtp)?.0)
    }

    /// [`drive_packet_with_srtp`] over several packets in order, returning
    /// the rtp_count and the stream store they filled.
    #[cfg(feature = "tls")]
    fn drive_packets_with_srtp(
        cli: &Cli,
        pps: &[ParsedPacket],
        portrange: (u16, u16),
        srtp: &mut crate::rtp::srtp::SrtpContext,
    ) -> Result<(u64, StreamStore), TestError> {
        let matcher = SipMatcher::new(cli, None).map_err(|e| format!("matcher: {e:?}"))?;
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
            detect_only: false,
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
            dtmf_seen: rtp::dtmf::DtmfDedupe::default(),
        };
        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            telephone_events: cli.mode_args.telephone_event,
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
                #[cfg(feature = "tls")]
                export: None,
                group: None,
            };
            for pp in pps {
                process_parsed_packet(
                    pp,
                    &ctx,
                    &mut state,
                    &mut engines,
                    &mut counters,
                    &mut effects,
                );
            }
        }
        let mut sink = output::BatchSink::new(Vec::new(), false);
        effects.drain(&mut sink, &engines.alerts, &mut event_exec);
        Ok((counters.rtp_count, stream_store))
    }

    /// A plaintext (non-SRTP) RTP packet must pass through an active SRTP
    /// context untouched: the auth tag never verifies on ordinary RTP, so the
    /// pipeline must NOT mangle it as a false "decryption". This guards the
    /// wiring's safety property at the binary layer.
    #[cfg(feature = "tls")]
    #[test]
    fn srtp_context_never_false_decrypts_plain_rtp() -> Result<(), TestError> {
        use crate::rtp::srtp::{SrtpContext, SrtpKeyMaterial, SrtpSuite};

        // A loaded context with one master key.
        let key = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: crate::test_material::bytes_for(
                "batch-srtp-context-never-false-decrypts-plain-rtp-master-key",
                16,
            ),
            master_salt: crate::test_material::bytes_for(
                "batch-srtp-context-never-false-decrypts-plain-rtp-master-salt",
                14,
            ),
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
        let rtp = drive_packet_with_srtp(&cli, &pp, (5060, 5061), &mut srtp)?;
        assert_eq!(rtp, 1, "the RTP packet must still be counted/processed");
        assert_eq!(
            srtp.decrypted_count, 0,
            "ordinary RTP must never be falsely decrypted (auth-tag gate)"
        );
        Ok(())
    }

    /// An INVITE offering PCMU at 10.0.0.2:40000 under `proto`, with the
    /// given `a=crypto` line when there is one.
    #[cfg(feature = "tls")]
    fn invite_with_srtp_offer(call_id: &str, proto: &str, crypto: Option<&str>) -> Vec<u8> {
        let mut sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 10.0.0.2\r\ns=-\r\nc=IN IP4 10.0.0.2\r\nt=0 0\r\n\
             m=audio 40000 {proto} 0\r\na=rtpmap:0 PCMU/8000\r\n"
        );
        if let Some(c) = crypto {
            sdp.push_str(&format!("a=crypto:{c}\r\n"));
        }
        let mut msg = String::from("INVITE sip:bob@example.com SIP/2.0\r\n");
        for h in [
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-srtp".to_string(),
            "From: Alice <sip:alice@example.com>;tag=a1".to_string(),
            "To: Bob <sip:bob@example.com>".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".to_string(),
            "Contact: <sip:alice@10.0.0.1:5060>".to_string(),
            "Content-Type: application/sdp".to_string(),
            format!("Content-Length: {}", sdp.len()),
        ] {
            msg.push_str(&h);
            msg.push_str("\r\n");
        }
        msg.push_str("\r\n");
        msg.push_str(&sdp);
        msg.into_bytes()
    }

    /// The batch path keeps SRTP audio it decrypted and keeps none it could
    /// not.
    ///
    /// Real SRTP: the packets are encrypted and authenticated with an SDES
    /// key. Offered with its `a=crypto` line, the key decrypts them and the
    /// plaintext is kept. Offered as `UDP/TLS/RTP/SAVP` with no key (DTLS-SRTP
    /// and no `--dtls-keylog`), the same packets are ciphertext and nothing
    /// is kept. Before the fix the second case kept every payload as PCMU.
    #[cfg(feature = "tls")]
    #[test]
    fn the_batch_path_keeps_decrypted_srtp_audio_and_no_ciphertext() -> Result<(), TestError> {
        use base64::Engine as _;
        let master_key = crate::test_material::bytes_for(
            "batch-the-batch-path-keeps-decrypted-srtp-audio-and-no-ciphertext-master-key",
            16,
        );
        let master_salt = crate::test_material::bytes_for(
            "batch-the-batch-path-keeps-decrypted-srtp-audio-and-no-ciphertext-master-salt",
            14,
        );
        let mut inline = master_key.clone();
        inline.extend_from_slice(&master_salt);
        let crypto = format!(
            "1 AES_CM_128_HMAC_SHA1_80 inline:{}",
            base64::engine::general_purpose::STANDARD.encode(&inline)
        );
        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;

        let media = |invite: Vec<u8>| -> Result<Vec<ParsedPacket>, TestError> {
            let mut pps = vec![parsed_sip_packet(invite, 5060, 5060)];
            for seq in 1..=5u16 {
                let packet = crate::rtp::srtp::test_support::build_srtp_packet(
                    &master_key,
                    &master_salt,
                    0x5157_0001,
                    seq,
                    0,
                    &[0xFFu8; 160],
                )?;
                pps.push(ParsedPacket {
                    payload: packet.into(),
                    ..parsed_sip_packet(Vec::new(), 30000, 40000)
                });
            }
            Ok(pps)
        };

        let mut srtp =
            crate::rtp::srtp::SrtpContext::new(Vec::new(), crate::crypto::default_backend());
        let keyed = media(invite_with_srtp_offer(
            "srtp-keyed@test",
            "RTP/SAVP",
            Some(&crypto),
        ))?;
        let (rtp, store) = drive_packets_with_srtp(&cli, &keyed, (5060, 5061), &mut srtp)?;
        assert_eq!(rtp, 5);
        let stream = store.iter().next().ok_or("the media made a stream")?;
        assert_eq!(stream.srtp_decrypted_packets, 5, "the SDES key decrypts");
        assert_eq!(stream.payload_buffer.len(), 5, "and the plaintext is kept");
        assert!(
            stream
                .payload_buffer
                .iter()
                .all(|f| f.payload == vec![0xFFu8; 160]),
            "the kept payload is the plaintext, not the ciphertext"
        );

        let mut srtp =
            crate::rtp::srtp::SrtpContext::new(Vec::new(), crate::crypto::default_backend());
        let unkeyed = media(invite_with_srtp_offer(
            "srtp-dtls@test",
            "UDP/TLS/RTP/SAVP",
            None,
        ))?;
        let (rtp, store) = drive_packets_with_srtp(&cli, &unkeyed, (5060, 5061), &mut srtp)?;
        assert_eq!(rtp, 5, "the packets are still counted and measured");
        let stream = store.iter().next().ok_or("the media made a stream")?;
        assert!(
            stream.payload_buffer.is_empty(),
            "ciphertext must not be kept as audio: {} frame(s) kept",
            stream.payload_buffer.len()
        );
        assert_eq!(stream.srtp_undecrypted_packets, 5);
        Ok(())
    }

    /// A valid INVITE on the SIP port increments the SIP counter.
    #[test]
    fn process_parsed_packet_counts_sip() -> Result<(), TestError> {
        let mut cli = base_cli();
        cli.output_args.no_cli_print = true; // keep test output quiet
        let pp = parsed_sip_packet(invite_bytes("ppp-1@example.com"), 5060, 5060);
        let (sip, _rtp) = drive_packet(&cli, &pp, (5060, 5061))?;
        assert_eq!(sip, 1, "one SIP message should be counted");
        Ok(())
    }

    /// Garbage payloads and SIP messages outside the port range are not
    /// counted as SIP.
    #[test]
    fn process_parsed_packet_ignores_non_sip_and_out_of_range() -> Result<(), TestError> {
        let mut cli = base_cli();
        cli.output_args.no_cli_print = true;

        // Garbage payload on the SIP port: not a SIP message -> no count.
        let pp = parsed_sip_packet(b"\x00\x01\x02not-sip-at-all".to_vec(), 5060, 5060);
        let (sip, _rtp) = drive_packet(&cli, &pp, (5060, 5061))?;
        assert_eq!(sip, 0);

        // A valid SIP message but on a port outside the SIP range -> skipped.
        let pp = parsed_sip_packet(invite_bytes("oor-1@example.com"), 40000, 40001);
        let (sip, _rtp) = drive_packet(&cli, &pp, (5060, 5061))?;
        assert_eq!(sip, 0);
        Ok(())
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
    fn cap_ts(secs: i64) -> Result<chrono::DateTime<chrono::Utc>, TestError> {
        Ok(chrono::DateTime::from_timestamp(1_700_000_000 + secs, 0).ok_or("valid timestamp")?)
    }

    /// Five seconds, the sweep interval the receive loops use.
    const FIVE: std::time::Duration = std::time::Duration::from_secs(5);

    /// Offline, the sweep is paced by the capture's timeline: no packets means
    /// no sweep, however long the process has been running.
    #[test]
    fn capture_clock_does_not_sweep_without_packets() -> Result<(), TestError> {
        let mut clock = SweepClock::new(true);
        assert_eq!(clock.take_due(FIVE), None);
        // The first packet only starts the clock.
        clock.observe(cap_ts(0)?);
        assert_eq!(clock.take_due(FIVE), None);
        Ok(())
    }

    /// Offline, a sweep is due once the CAPTURE has advanced by the interval,
    /// and its "now" is the packet time — not `Utc::now()`.
    #[test]
    fn capture_clock_sweeps_on_packet_time() -> Result<(), TestError> {
        let mut clock = SweepClock::new(true);
        clock.observe(cap_ts(0)?);
        assert_eq!(clock.take_due(FIVE), None);

        clock.observe(cap_ts(4)?);
        assert_eq!(clock.take_due(FIVE), None, "4 s of capture is not 5");

        clock.observe(cap_ts(5)?);
        assert_eq!(
            clock.take_due(FIVE),
            Some(CaptureNow(cap_ts(5)?)),
            "sweep must run at the packet's time, not the wall clock's"
        );
        // ...and not again until another interval of capture time passes.
        assert_eq!(clock.take_due(FIVE), None);
        clock.observe(cap_ts(9)?);
        assert_eq!(clock.take_due(FIVE), None);
        clock.observe(cap_ts(10)?);
        assert_eq!(clock.take_due(FIVE), Some(CaptureNow(cap_ts(10)?)));
        Ok(())
    }

    /// The whole point: how long the read takes cannot change the offline
    /// sweep schedule. Two clocks fed the same timestamps agree even though
    /// one of them has real time passing between the calls.
    #[test]
    fn capture_clock_is_independent_of_wall_time() -> Result<(), TestError> {
        let stamps = [0, 2, 4, 6, 8, 10, 12];
        let sweep = |pause: std::time::Duration| -> Result<Vec<_>, TestError> {
            let mut clock = SweepClock::new(true);
            let mut fired = Vec::new();
            for s in stamps {
                clock.observe(cap_ts(s)?);
                if let Some(now) = clock.take_due(FIVE) {
                    fired.push(now.get());
                }
                std::thread::sleep(pause);
            }
            Ok(fired)
        };
        let fast = sweep(std::time::Duration::ZERO)?;
        let slow = sweep(std::time::Duration::from_millis(20))?;
        assert_eq!(fast, slow, "offline sweep schedule moved with wall time");
        assert_eq!(fast, vec![cap_ts(6)?, cap_ts(12)?]);
        Ok(())
    }

    /// An out-of-order packet must not rewind the capture clock: a stale
    /// timestamp would otherwise postpone every later sweep.
    #[test]
    fn capture_clock_never_moves_backwards() -> Result<(), TestError> {
        let mut clock = SweepClock::new(true);
        clock.observe(cap_ts(0)?);
        assert_eq!(clock.take_due(FIVE), None);
        clock.observe(cap_ts(10)?);
        clock.observe(cap_ts(3)?); // reordered arrival
        assert_eq!(
            clock.take_due(FIVE),
            Some(CaptureNow(cap_ts(10)?)),
            "a reordered packet rewound the capture clock, postponing the sweep"
        );
        Ok(())
    }

    /// The end-of-run sweep's "now" is the capture's LAST timestamp, whatever
    /// the periodic schedule happened to land on. `--cores` reads this to
    /// sweep its merged stores once, so a value short of the final packet
    /// would leave the last stretch of the capture unswept.
    #[test]
    fn final_now_is_the_captures_last_timestamp() -> Result<(), TestError> {
        let mut clock = SweepClock::new(true);
        assert_eq!(clock.final_now(), None, "nothing read, nothing to sweep");
        clock.observe(cap_ts(0)?);
        assert_eq!(clock.final_now(), Some(CaptureNow(cap_ts(0)?)));
        assert_eq!(
            clock.take_due(FIVE),
            None,
            "the first packet only starts the periodic clock"
        );
        clock.observe(cap_ts(900)?);
        assert_eq!(
            clock.final_now(),
            Some(CaptureNow(cap_ts(900)?)),
            "the final sweep must measure against the last packet"
        );
        // A periodic sweep in between must not move it, and reading it must
        // not consume anything: the two questions are independent.
        assert_eq!(clock.take_due(FIVE), Some(CaptureNow(cap_ts(900)?)));
        assert_eq!(clock.final_now(), Some(CaptureNow(cap_ts(900)?)));
        assert_eq!(clock.final_now(), Some(CaptureNow(cap_ts(900)?)));
        Ok(())
    }

    /// Live, the end-of-run sweep is wall time — the same split `take_due`
    /// makes. A live run's packets carry arrival times, so the two clocks
    /// agree there and only the offline path needs the capture's own.
    #[test]
    fn final_now_is_wall_time_on_a_live_run() -> Result<(), TestError> {
        let mut clock = SweepClock::new(false);
        clock.observe(cap_ts(0)?); // years in the past, must be ignored
        let now = clock.final_now().ok_or("a live clock always has a now")?;
        assert!(
            chrono::Utc::now().signed_duration_since(now.get()) < chrono::TimeDelta::seconds(5),
            "a live final sweep's now must be wall time, got {:?}",
            now.get()
        );
        Ok(())
    }

    /// Live capture keeps wall time, where it is correct: packet timestamps
    /// are ignored and the sweep is due after the interval really elapses.
    #[test]
    fn live_clock_uses_wall_time_and_ignores_packet_time() -> Result<(), TestError> {
        let mut clock = SweepClock::new(false);
        // A packet from the distant past cannot make a live sweep due.
        clock.observe(cap_ts(0)?);
        assert_eq!(clock.take_due(FIVE), None);
        // ...and a zero interval makes one due immediately, on wall time.
        let now = clock
            .take_due(std::time::Duration::ZERO)
            .ok_or("elapsed >= 0 always")?;
        assert!(
            chrono::Utc::now().signed_duration_since(now.get()) < chrono::TimeDelta::seconds(5),
            "a live sweep's now must be wall time, got {:?}",
            now.get()
        );
        Ok(())
    }

    // ── Operator-set thresholds reach the things that enforce them ───────

    /// `--kill-rate-limit` bounds the responses the worker actually admits.
    ///
    /// The observation is the decision loop's own outcomes, not the number
    /// handed to a constructor: the worker is given its ceiling on its command
    /// line, so a wiring that dropped it would still produce a worker, still
    /// rate-limit at the built-in 10/s, and pass any test that only looked at
    /// the resolver. So the chain is driven end to end short of the exec --
    /// flags to `bootstrap::kill_worker_spawn`, that to the worker's argv, the
    /// argv through the worker's OWN parser, and the parsed ceiling into the
    /// loop that decides. `tests/scanner_kill_process_test.rs` drives the exec
    /// hop itself, with a real worker process.
    ///
    /// Each request goes to a DIFFERENT destination, because a per-destination
    /// cap of 3/minute sits underneath the global one and would otherwise be
    /// what bounds the run. Nothing is transmitted: the loop holds no socket,
    /// so an admitted request reports that it had nothing to send on -- which
    /// is exactly how it shows it got past both limiters.
    #[test]
    fn the_configured_kill_rate_limit_bounds_what_the_worker_sends() -> Result<(), TestError> {
        use crate::process_isolation::worker_process::{FdPlan, decisions_for_argv};
        use crate::process_isolation::{KillResponse, worker_args};

        /// Run `n` kill requests to `n` distinct destinations through the
        /// decision loop a worker started for `args` would run, and return
        /// `(admitted, rate_limited)`.
        fn admitted_under(args: &[&str], n: u8) -> Result<(usize, usize), TestError> {
            let cli = Cli::parse_from_args(args.iter().copied());
            let spawn = crate::app::bootstrap::kill_worker_spawn(&cli, &Config::default())
                .map_err(|e| format!("this test binary can read its own path: {e:?}"))?;
            let argv = worker_args(&spawn, FdPlan::new([])).to_args();
            let requests = (0..n)
                .map(|i| KillRequest::SendResponse {
                    dst_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1 + i)),
                    dst_port: 9,
                    src_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200)),
                    src_port: 5060,
                    response_bytes: b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
                })
                .collect();
            let outcomes = decisions_for_argv(&argv, requests)?;
            assert_eq!(
                outcomes.len(),
                usize::from(n),
                "every request must reach an outcome, or the counts below mean nothing"
            );
            let admitted = outcomes
                .iter()
                .filter(|o| matches!(o, KillResponse::Error { .. }))
                .count();
            let limited = outcomes
                .iter()
                .filter(|o| matches!(o, KillResponse::RateLimited))
                .count();
            Ok((admitted, limited))
        }

        let (admitted, limited) = admitted_under(&["sipnab", "--kill-rate-limit", "1"], 20)?;
        assert_eq!(
            admitted, 1,
            "--kill-rate-limit 1 must let exactly one response through in the \
             first second; the worker admitted {admitted}"
        );
        assert_eq!(
            limited, 19,
            "the other 19 must be suppressed, not sent; got {limited} suppressed"
        );

        // And a ceiling ABOVE the built-in 10 is honored, or the setting can
        // only ever tighten — half a knob.
        let (_, limited) = admitted_under(&["sipnab", "--kill-rate-limit", "100"], 20)?;
        assert_eq!(
            limited, 0,
            "--kill-rate-limit 100 must not suppress 20 responses; got {limited} suppressed"
        );
        Ok(())
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

/// The small pure helpers behind the end-of-run notices and the detector
/// construction the TUI shares with batch mode.
#[cfg(test)]
mod notice_helper_tests {
    use super::*;
    use clap::Parser as _;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// A list within the cap is joined whole, with nothing said about a rest.
    #[test]
    fn a_list_within_the_cap_is_joined_whole() {
        assert_eq!(join_capped(&["a", "b", "c"], 3), "a, b, c");
    }

    /// A list past the cap shows the first `max` and counts the rest, so a
    /// roster that was cut never reads as complete.
    #[test]
    fn a_list_past_the_cap_counts_what_it_withheld() {
        assert_eq!(
            join_capped(&["a", "b", "c", "d", "e"], 2),
            "a, b, and 3 more"
        );
    }

    /// A malformed business-hours spec that slipped past validation still
    /// arms the fraud detector -- without the off-hours rule, and saying so --
    /// rather than dropping every fraud detection along with it.
    #[test]
    fn a_malformed_business_hours_spec_still_arms_the_fraud_detector() {
        let mut cli = Cli::parse_from(["sipnab", "--fraud-detect"]);
        cli.security_args.business_hours = Some("nine-to-five".to_string());
        assert!(
            build_fraud_detector(&cli, &Config::default()).is_some(),
            "the rest of fraud detection must survive a bad off-hours spec"
        );
    }

    /// Without `--fraud-detect` or `[security] fraud_detect`, nothing is
    /// built: the partner that keeps the case above from passing vacuously.
    #[test]
    fn no_fraud_flag_builds_no_fraud_detector() {
        let cli = Cli::parse_from(["sipnab"]);
        assert!(build_fraud_detector(&cli, &Config::default()).is_none());
    }

    /// A snapped frame that produced nothing is counted as SNAPPED in the
    /// capture-quality line, and never among the frames that "reached sipnab
    /// intact" -- the same line says it arrived truncated, and one frame cannot
    /// be both.
    ///
    /// An intact frame no decoder could read is still reported as intact, so
    /// the partition is asserted from both sides.
    #[test]
    #[serial_test::serial(invalid_timestamps, kernel_drop_counts, undecodable_tally)]
    fn a_snapped_frame_is_never_said_to_have_reached_sipnab_intact() -> Result<(), TestError> {
        crate::capture::reset_undecodable_frames();
        let mut proc = crate::capture::PacketProcessor::new();
        // Intact, on a link type with no decoder.
        proc.process(&crate::capture::Packet::new(
            chrono::Utc::now(),
            vec![0u8; 64],
            64,
            64,
            None,
            147,
        ));
        // Ethernet + IPv4 + UDP whose header promises 40 bytes, 10 of them
        // never captured.
        let mut frame = vec![0xAAu8; 12];
        frame.extend_from_slice(&[0x08, 0x00, 0x45, 0x00, 0x00, 40]);
        frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, 17, 0x00, 0x00]);
        frame.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        frame.extend_from_slice(&[0x13, 0xc4, 0x13, 0xc4, 0x00, 20, 0x00, 0x00]);
        frame.extend_from_slice(&[b'x'; 2]);
        let n = frame.len();
        proc.process(&crate::capture::Packet::new(
            chrono::Utc::now(),
            frame,
            n,
            n + 10,
            None,
            1,
        ));

        let msg = capture_quality_summary().ok_or("both frames are quality findings")?;
        assert!(
            msg.contains("1 frame(s) reached sipnab intact and could not be decoded"),
            "only the intact frame arrived intact: {msg}"
        );
        assert!(
            msg.contains(
                "1 frame(s) arrived truncated by the capture's snaplen and 1 of them \
                 were cut too short to decode at all"
            ),
            "the snapped frame is reported as snapped, and as producing nothing: {msg}"
        );
        crate::capture::reset_undecodable_frames();
        Ok(())
    }
}

/// The end-of-run NAT findings, as the lines they log.
///
/// `report_stun_failures`, `report_lapsed_allocations` and
/// `report_ice_role_conflicts` read process-global state and write to the
/// tracing log, so neither side can be driven from a test. The sentences are
/// the whole value of each finding, so they are built by pure functions and
/// tested here, and the reporters only log what those return.
#[cfg(test)]
mod nat_finding_line_tests {
    use super::*;
    use std::net::SocketAddr;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    fn addr(s: &str) -> Result<SocketAddr, TestError> {
        Ok(s.parse()?)
    }

    fn unanswered(
        n: u16,
        software: Option<&str>,
    ) -> Result<crate::stun::UnansweredRequest, TestError> {
        Ok(crate::stun::UnansweredRequest {
            from: addr(&format!("192.0.2.10:{}", 5000 + n))?,
            to: addr("198.51.100.20:3478")?,
            attempts: 3,
            software: software.map(str::to_string),
            method: "Binding".to_string(),
        })
    }

    /// Nothing unanswered says nothing, even when a challenge was seen: the
    /// challenge sentence qualifies the unanswered one and never stands alone.
    #[test]
    fn no_unanswered_request_produces_no_stun_line() {
        assert!(stun_failure_lines(&[], 4, 2).is_empty());
    }

    /// One unanswered request names who asked whom, how often, and the
    /// software it announced; the total counts answered transactions too.
    #[test]
    fn an_unanswered_request_is_named_and_counted_against_the_total() -> Result<(), TestError> {
        let lines = stun_failure_lines(&[unanswered(1, Some("probe/1.0"))?], 2, 0);
        assert_eq!(lines.len(), 2, "{lines:#?}");
        assert!(
            lines[0].starts_with(
                "STUN/TURN: 192.0.2.10:5001 sent Binding to 198.51.100.20:3478 3 time(s) and \
                 got no reply (probe/1.0)."
            ),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains("security appliance"), "{}", lines[0]);
        assert_eq!(
            lines[1],
            "STUN/TURN: 1 of 3 transaction(s) went unanswered."
        );
        Ok(())
    }

    /// A request with no SOFTWARE attribute names no software.
    #[test]
    fn an_unanswered_request_without_software_names_none() -> Result<(), TestError> {
        let lines = stun_failure_lines(&[unanswered(1, None)?], 0, 0);
        assert!(
            lines[0].contains("3 time(s) and got no reply. An endpoint"),
            "{}",
            lines[0]
        );
        Ok(())
    }

    /// Five are listed and the rest counted, so a long list stays readable
    /// and never reads as complete.
    #[test]
    fn past_five_unanswered_requests_the_rest_are_counted() -> Result<(), TestError> {
        let many: Vec<_> = (0..7)
            .map(|n| unanswered(n, None))
            .collect::<Result<_, _>>()?;
        let lines = stun_failure_lines(&many, 1, 0);
        assert_eq!(lines.len(), 7, "{lines:#?}");
        assert!(lines[4].contains("192.0.2.10:5004 sent"), "{}", lines[4]);
        assert_eq!(
            lines[5],
            "STUN: 2 further unanswered binding request(s) not listed."
        );
        assert_eq!(
            lines[6],
            "STUN/TURN: 7 of 8 transaction(s) went unanswered."
        );
        Ok(())
    }

    /// Exactly five lists all five and adds no "further" line.
    #[test]
    fn exactly_five_unanswered_requests_need_no_further_line() -> Result<(), TestError> {
        let five: Vec<_> = (0..5)
            .map(|n| unanswered(n, None))
            .collect::<Result<_, _>>()?;
        let lines = stun_failure_lines(&five, 0, 0);
        assert_eq!(lines.len(), 6, "{lines:#?}");
        assert!(!lines.iter().any(|l| l.contains("further")), "{lines:#?}");
        Ok(())
    }

    /// An authentication challenge is said separately, after the total,
    /// because it points at credentials rather than at the path.
    #[test]
    fn an_authentication_challenge_is_its_own_line() -> Result<(), TestError> {
        let lines = stun_failure_lines(&[unanswered(1, None)?], 0, 2);
        assert_eq!(lines.len(), 3, "{lines:#?}");
        assert!(
            lines[2].starts_with(
                "STUN/TURN: 2 transaction(s) were answered with an AUTHENTICATION challenge"
            ),
            "{}",
            lines[2]
        );
        Ok(())
    }

    fn allocation(
        n: u16,
        lifetime: Option<u32>,
        channels: bool,
    ) -> Result<crate::stun::TurnAllocation, TestError> {
        let t0 = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0)
            .ok_or("a valid timestamp")?;
        Ok(crate::stun::TurnAllocation {
            client: addr(&format!("192.0.2.20:{}", 6000 + n))?,
            server: addr("198.51.100.30:3478")?,
            relayed_address: None,
            lifetime_secs: lifetime,
            allocated_at: t0,
            refreshed_at: None,
            refreshes: 0,
            last_activity: t0 + chrono::TimeDelta::seconds(700),
            released: false,
            channels: if channels {
                vec![crate::stun::RelayChannel {
                    channel: 0x4001,
                    peer: None,
                    bound: true,
                    frames: 9,
                    bytes: 900,
                    first_seen: t0,
                    last_seen: t0,
                    ssrcs: vec![0x1122_3344],
                    ssrcs_dropped: 0,
                }]
            } else {
                Vec::new()
            },
            unattributed_frames: 0,
        })
    }

    /// Nothing lapsed says nothing.
    #[test]
    fn no_lapsed_allocation_produces_no_turn_line() {
        assert!(lapsed_allocation_lines(&[]).is_empty());
    }

    /// The count, then each allocation with its lifetime and how far past
    /// expiry traffic ran, then the media that was on it.
    #[test]
    fn a_lapsed_allocation_is_described_with_the_media_on_it() -> Result<(), TestError> {
        let a = allocation(1, Some(600), true)?;
        let lines = lapsed_allocation_lines(&[&a]);
        assert_eq!(lines.len(), 3, "{lines:#?}");
        assert!(
            lines[0].starts_with("TURN: 1 allocation(s) were still carrying traffic"),
            "{}",
            lines[0]
        );
        assert_eq!(
            lines[1],
            "TURN:   192.0.2.20:6001 -> 198.51.100.30:3478: 600s lifetime, 0 refresh(es) \
             seen, traffic continued 100s past expiry"
        );
        assert!(
            lines[2].starts_with("TURN:     media on it: 9 frame(s) on channel 0x4001"),
            "{}",
            lines[2]
        );
        Ok(())
    }

    /// An allocation with no granted lifetime says "unknown", and one with no
    /// relayed frame gets no media line: absence is a different answer.
    #[test]
    fn an_unknown_lifetime_and_no_media_are_said_plainly() -> Result<(), TestError> {
        let a = allocation(1, None, false)?;
        let lines = lapsed_allocation_lines(&[&a]);
        assert_eq!(lines.len(), 2, "{lines:#?}");
        assert!(
            lines[1].contains(": unknown lifetime, 0 refresh(es) seen, traffic continued 0s"),
            "{}",
            lines[1]
        );
        Ok(())
    }

    /// Five are listed and the rest counted.
    #[test]
    fn past_five_lapsed_allocations_the_rest_are_counted() -> Result<(), TestError> {
        let all: Vec<_> = (0..6)
            .map(|n| allocation(n, Some(600), false))
            .collect::<Result<_, _>>()?;
        let refs: Vec<&crate::stun::TurnAllocation> = all.iter().collect();
        let lines = lapsed_allocation_lines(&refs);
        assert_eq!(lines.len(), 7, "{lines:#?}");
        assert!(lines[5].contains("192.0.2.20:6004 ->"), "{}", lines[5]);
        assert_eq!(
            lines[6],
            "TURN:   ... and 1 further lapsed allocation(s) not listed."
        );
        Ok(())
    }

    fn conflict(n: u16, resolved: bool) -> Result<crate::stun::IceRoleConflict, TestError> {
        Ok(crate::stun::IceRoleConflict {
            a: addr(&format!("192.0.2.11:{}", 50000 + n))?,
            b: addr("203.0.113.11:16002")?,
            role: None,
            role_conflict_responses: 2,
            resolved,
        })
    }

    fn ice(conflicts: Vec<crate::stun::IceRoleConflict>, total: u64) -> crate::stun::IceSummary {
        crate::stun::IceSummary {
            role_conflicts: conflicts,
            role_conflicts_total: total,
            ..Default::default()
        }
    }

    /// No conflict says nothing.
    #[test]
    fn no_role_conflict_produces_no_ice_line() {
        assert!(ice_role_conflict_lines(&ice(Vec::new(), 0)).is_empty());
    }

    /// Each conflict carries its verdict: resolved costs a round trip,
    /// unresolved is a candidate cause of media that never started.
    #[test]
    fn each_role_conflict_says_whether_it_was_resolved() -> Result<(), TestError> {
        let lines = ice_role_conflict_lines(&ice(vec![conflict(1, true)?, conflict(2, false)?], 2));
        assert_eq!(lines.len(), 3, "{lines:#?}");
        assert!(
            lines[0].starts_with("ICE: 2 candidate pair(s) show a role conflict"),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].starts_with(
                "ICE:   192.0.2.11:50001 <-> 203.0.113.11:16002: 2 487 response(s), resolved --"
            ),
            "{}",
            lines[1]
        );
        assert!(
            lines[2].starts_with(
                "ICE:   192.0.2.11:50002 <-> 203.0.113.11:16002: 2 487 response(s), UNRESOLVED --"
            ),
            "{}",
            lines[2]
        );
        Ok(())
    }

    /// Five are listed and the rest counted from the retained list.
    #[test]
    fn past_five_role_conflicts_the_rest_are_counted() -> Result<(), TestError> {
        let all: Vec<_> = (0..8)
            .map(|n| conflict(n, false))
            .collect::<Result<_, _>>()?;
        let lines = ice_role_conflict_lines(&ice(all, 8));
        assert_eq!(lines.len(), 7, "{lines:#?}");
        assert_eq!(
            lines[6],
            "ICE:   ... and 3 further conflicted pair(s) not listed."
        );
        Ok(())
    }
}

/// How `--alert` values are read: a bare word is a channel, a value holding
/// ':' is a rule, and everything that cannot be used is reported.
#[cfg(test)]
mod alert_source_tests {
    use super::*;

    fn specs(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    /// The documented channels switch their output on, in any case and with
    /// surrounding whitespace.
    #[test]
    fn channel_names_switch_their_channel_on() {
        let parsed = parse_alert_sources(&specs(&[" Syslog ", "JSON"]), false);
        assert!(parsed.syslog && parsed.json);
        assert!(parsed.rules.is_empty());
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
    }

    /// Nothing named leaves both channels off.
    #[test]
    fn no_channel_named_leaves_both_off() {
        let parsed = parse_alert_sources(&[], false);
        assert!(!parsed.syslog && !parsed.json);
        assert!(parsed.rules.is_empty() && parsed.warnings.is_empty());
    }

    /// A value containing ':' is parsed as a rule; an invalid one is skipped
    /// with a warning naming it, and never read as a channel.
    #[test]
    fn a_value_with_a_colon_is_a_rule() {
        let parsed = parse_alert_sources(&specs(&["scanner:5/60s", "syslog:bad"]), false);
        assert_eq!(parsed.rules.len(), 1);
        assert!(!parsed.syslog, "a rule-shaped value is never a channel");
        assert_eq!(parsed.warnings.len(), 1, "{:?}", parsed.warnings);
        assert!(
            parsed.warnings[0].starts_with("Skipping invalid alert rule 'syslog:bad': "),
            "{}",
            parsed.warnings[0]
        );
    }

    /// `exec` is accepted, and warns only when no command was configured.
    #[test]
    fn exec_warns_only_without_a_command() {
        let without = parse_alert_sources(&specs(&["exec"]), false);
        assert_eq!(
            without.warnings,
            vec!["--alert exec given without --alert-exec <CMD>; no command to run".to_owned()]
        );
        let with = parse_alert_sources(&specs(&["exec"]), true);
        assert!(with.warnings.is_empty(), "{:?}", with.warnings);
        assert!(!with.syslog && !with.json);
    }

    /// An unknown word is named back with the valid channels.
    #[test]
    fn an_unknown_channel_is_named_with_the_valid_ones() {
        let parsed = parse_alert_sources(&specs(&["pager"]), false);
        assert_eq!(
            parsed.warnings,
            vec![
                "Unknown alert channel 'pager'. Valid channels: syslog, json, exec. \
                 (A value containing ':' is treated as an alert rule.)"
                    .to_owned()
            ]
        );
    }
}

/// The run state `BatchRunner::new` builds from the command line: detectors,
/// the `--evidence-out` sink and the TLS decryptor.
#[cfg(test)]
mod run_state_builder_tests {
    use super::*;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    fn cli(args: &[&str]) -> Cli {
        let mut all = vec!["sipnab"];
        all.extend_from_slice(args);
        Cli::parse_from_args(all)
    }

    /// `--digest-leak` arms the digest detector and nothing else, and
    /// `--reg-flood` arms the flood detector and not the digest one.
    #[test]
    fn each_detector_flag_arms_its_own_detector() {
        let config = Config::default();
        let digest = build_detection_engines(&cli(&["--digest-leak"]), &config, None, None);
        assert!(digest.digest.is_some());
        assert!(digest.reg_flood.is_none() && digest.scanner.is_none());
        assert_eq!(digest.armed_kinds(), vec!["digest"]);

        let flood = build_detection_engines(&cli(&["--reg-flood"]), &config, None, None);
        assert!(flood.reg_flood.is_some());
        assert!(flood.digest.is_none());
        assert_eq!(flood.armed_kinds(), vec!["reg_flood"]);

        let none = build_detection_engines(&cli(&[]), &config, None, None);
        assert!(none.armed_kinds().is_empty());
    }

    /// `--kill-scanner-detect-only` builds the scanner detector on its own,
    /// from the flag or the config key, exactly as `--kill-scanner` does.
    #[test]
    fn detect_only_builds_the_scanner_detector() {
        let flag = build_detection_engines(
            &cli(&["--kill-scanner-detect-only"]),
            &Config::default(),
            None,
            None,
        );
        assert!(flag.scanner.is_some(), "the flag must build the detector");
        assert_eq!(flag.armed_kinds(), vec!["scanner"]);
        assert!(flag.kill_handle.is_none(), "detect-only answers nothing");
        assert_eq!(
            flag.scanner_response(),
            crate::security::findings::ScannerResponse::DetectOnly,
            "security_findings must report detect_only"
        );

        let kill =
            build_detection_engines(&cli(&["--kill-scanner"]), &Config::default(), None, None);
        assert_eq!(
            kill.scanner_response(),
            crate::security::findings::ScannerResponse::NotAnswering,
            "--kill-scanner with no worker running answers nothing, and says so"
        );

        let mut config = Config::default();
        config.security.kill_scanner_detect_only = Some(true);
        let key = build_detection_engines(&cli(&[]), &config, None, None);
        assert!(
            key.scanner.is_some(),
            "the config key must build the detector"
        );
    }

    /// `--evidence-out` opens the sink it names before the first packet; no
    /// flag opens nothing; an unopenable target refuses the run with exit 2.
    #[test]
    fn evidence_out_opens_its_sink_or_refuses_the_run() -> Result<(), TestError> {
        assert!(
            open_evidence_sink(&cli(&[]))
                .map_err(|e| format!("no flag: {e:?}"))?
                .is_none()
        );

        let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e:?}"))?;
        let target = tmp.path().join("evidence.ndjson");
        let target = target.to_str().ok_or("utf-8 path")?;
        assert!(
            open_evidence_sink(&cli(&["--evidence-out", target]))
                .map_err(|e| format!("a writable target opens: {e:?}"))?
                .is_some()
        );

        let blocked = tmp.path().join("missing-dir").join("evidence.ndjson");
        let err = open_evidence_sink(&cli(&[
            "--evidence-out",
            blocked.to_str().ok_or("utf-8 path")?,
        ]))
        .err()
        .ok_or("an unopenable target is refused")?;
        assert_eq!(err.exit_code, 2);
        assert!(
            err.message.starts_with("--evidence-out "),
            "{}",
            err.message
        );
        Ok(())
    }

    /// `--tls-key` loads the RSA key into the decryptor; a key file that
    /// cannot be read refuses the run with exit 1.
    #[cfg(feature = "tls")]
    #[test]
    fn tls_key_is_loaded_into_the_decryptor_or_refuses_the_run() -> Result<(), TestError> {
        let key = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tls_rsa/key.pem"
        );
        let d = build_tls_decryptor(&cli(&["--tls-key", key]), None)
            .map_err(|e| format!("a readable key loads: {e:?}"))?
            .ok_or("a key asks for a decryptor")?;
        assert!(d.has_rsa_key());

        let err = build_tls_decryptor(&cli(&["--tls-key", "/nonexistent/key.pem"]), None)
            .err()
            .ok_or("an unreadable key is refused")?;
        assert_eq!(err.exit_code, 1);
        assert!(
            err.message
                .starts_with("Failed to load --tls-key /nonexistent/key.pem: "),
            "{}",
            err.message
        );
        // The OS reason, which sits under the anyhow context. Formatting the
        // error with `{e}` printed the context alone, so the operator was
        // told the file could not be read and never why.
        assert!(
            err.message.contains("No such file or directory"),
            "{}",
            err.message
        );
        Ok(())
    }

    /// An unreadable `--srtp-keys` or `--dtls-keylog` names the OS reason,
    /// which sits under the loader's anyhow context and `{e}` dropped.
    #[cfg(feature = "tls")]
    #[test]
    fn unreadable_srtp_and_dtls_key_files_name_the_os_reason() -> Result<(), TestError> {
        let srtp = load_srtp_context(&cli(&["--srtp-keys", "/nonexistent/s.keys"]))
            .err()
            .ok_or("an unreadable --srtp-keys is refused")?;
        assert!(
            srtp.message.contains("No such file or directory"),
            "{}",
            srtp.message
        );
        let dtls = load_dtls_extractor(&cli(&["--dtls-keylog", "/nonexistent/d.log"]))
            .err()
            .ok_or("an unreadable --dtls-keylog is refused")?;
        assert!(
            dtls.message.contains("No such file or directory"),
            "{}",
            dtls.message
        );
        Ok(())
    }

    /// A `--keylog` that cannot be read refuses the run with exit 1, as an
    /// unreadable `--tls-key` and `--dtls-keylog` do. It used to be logged
    /// and the run went on without a decryptor, exiting 0.
    #[cfg(feature = "tls")]
    #[test]
    fn unreadable_keylog_refuses_the_run_like_the_other_key_files() -> Result<(), TestError> {
        let err = build_tls_decryptor(&cli(&["--keylog", "/nonexistent/keys.log"]), None)
            .err()
            .ok_or("an unreadable keylog is refused")?;
        assert_eq!(err.exit_code, 1);
        assert!(
            err.message
                .starts_with("Failed to load --keylog /nonexistent/keys.log: "),
            "{}",
            err.message
        );
        assert!(
            err.message.contains("No such file or directory"),
            "{}",
            err.message
        );
        Ok(())
    }

    /// No key source asks for no decryptor.
    #[cfg(feature = "tls")]
    #[test]
    fn no_key_source_builds_no_decryptor() -> Result<(), TestError> {
        assert!(
            build_tls_decryptor(&cli(&[]), None)
                .map_err(|e| format!("ok: {e:?}"))?
                .is_none()
        );
        Ok(())
    }

    /// Only a keylog source that can grow mid-run is worth the late-decrypt
    /// hold: `--keylog-watch` and `--keylog-fd` can, a plain `--keylog` file
    /// cannot.
    #[cfg(feature = "tls")]
    #[test]
    fn only_a_watched_or_streamed_keylog_may_still_grow() {
        assert!(!keylog_may_grow(&cli(&["--keylog", "/tmp/k.log"])));
        assert!(keylog_may_grow(&cli(&[
            "--keylog",
            "/tmp/k.log",
            "--keylog-watch"
        ])));
        assert!(keylog_may_grow(&cli(&["--keylog-fd", "3"])));
    }
}

/// The decisions the end of a batch run takes: its exit status, whether the
/// capture was read to the end, and how a skip report names its ports.
#[cfg(test)]
mod run_end_tests {
    use super::*;

    /// A clean run with nothing tripped exits 0.
    #[test]
    fn a_clean_run_exits_zero() {
        assert_eq!(run_exit_code(RunOutcome::default()), None);
    }

    /// Each failure on its own exits 1.
    #[test]
    fn every_failure_exits_one() {
        for outcome in [
            RunOutcome {
                output_failed: true,
                ..RunOutcome::default()
            },
            RunOutcome {
                capture_failed: true,
                ..RunOutcome::default()
            },
            RunOutcome {
                run_failed: true,
                ..RunOutcome::default()
            },
        ] {
            assert_eq!(run_exit_code(outcome), Some(1), "{outcome:?}");
        }
    }

    /// A tripped lint gate alone exits 3, which means "the capture is
    /// non-conformant" rather than "sipnab broke".
    #[test]
    fn a_tripped_lint_gate_exits_three() {
        assert_eq!(
            run_exit_code(RunOutcome {
                lint_gate_tripped: true,
                ..RunOutcome::default()
            }),
            Some(3)
        );
    }

    /// A query gate's code (`--expect`) is the run's exit when nothing failed
    /// and the lint gate did not trip; a failure and the lint gate both win
    /// over it.
    #[test]
    fn a_query_gate_sets_the_exit_after_failures_and_the_lint_gate() {
        let gated = |outcome: RunOutcome| {
            run_exit_code(RunOutcome {
                query_gate: Some(2),
                ..outcome
            })
        };
        assert_eq!(gated(RunOutcome::default()), Some(2));
        assert_eq!(
            gated(RunOutcome {
                capture_failed: true,
                ..RunOutcome::default()
            }),
            Some(1)
        );
        assert_eq!(
            gated(RunOutcome {
                lint_gate_tripped: true,
                ..RunOutcome::default()
            }),
            Some(3)
        );
    }

    /// A failure wins over the lint gate: findings drawn from a partial read
    /// are not trustworthy.
    #[test]
    fn a_failure_wins_over_the_lint_gate() {
        assert_eq!(
            run_exit_code(RunOutcome {
                capture_failed: true,
                lint_gate_tripped: true,
                ..RunOutcome::default()
            }),
            Some(1)
        );
    }

    /// Only a thread that returned `Ok` read its input to the end; an error
    /// and a panic both did not.
    #[test]
    fn only_an_ok_capture_thread_read_its_input_to_the_end() {
        assert!(capture_read_to_end(Ok(Ok(()))));
        assert!(!capture_read_to_end(Ok(Err(anyhow::anyhow!(
            "filter rejected"
        )))));
        assert!(!capture_read_to_end(Err(Box::new("panicked"))));
    }

    /// At most five ports, busiest first as given, each with its count.
    #[test]
    fn a_skip_report_names_at_most_five_ports() {
        let ports: Vec<crate::pipeline::SkippedPort> = (0..7)
            .map(|n| crate::pipeline::SkippedPort {
                port: 5070 + n,
                messages: u64::from(10 - n),
            })
            .collect();
        assert_eq!(
            busiest_skipped_ports(&ports),
            "5070 (10), 5071 (9), 5072 (8), 5073 (7), 5074 (6)"
        );
        assert_eq!(busiest_skipped_ports(&ports[..1]), "5070 (10)");
    }
}
