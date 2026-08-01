// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process isolation for dangerous operations (D16).
//!
//! Provides thread-based isolation for scanner-kill and API operations.
//! The scanner-kill worker runs in a dedicated thread with its own rate
//! limiter, receiving kill requests via a crossbeam channel. This limits
//! blast radius: a bug in the kill path cannot corrupt the main capture
//! pipeline or dialog tracking state.
//!
//! # The capture thread never waits on this module
//!
//! Isolation is only isolation if the isolated thread cannot stall the one
//! that feeds it. The capture loop offers kill requests *while holding the
//! dialog and stream write locks*, so a wait here is a wait for packet
//! processing and for every reader of those stores — the REST API, the TUI
//! and every MCP tool. Both channels in this module are therefore offered to
//! and never waited on, in both directions, and what would have been
//! backpressure is a counted, logged drop instead ([`KillCounts`]).
//!
//! It used to be the other way round. The worker published each outcome with
//! a blocking send onto a 256-slot channel that nothing in production drained;
//! it stalled on outcome 257, stopped draining requests, the request queue
//! filled behind it, and the capture thread blocked forever handing over the
//! next one. `--kill-scanner` on busy traffic therefore froze the capture and
//! the whole MCP surface, permanently, after about 512 detections.
//!
//! Future enhancement: replace threads with `fork()`/`Command` for true
//! process-level isolation with separate address spaces.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use crossbeam_channel::{Receiver, Sender, TrySendError};
use serde::{Deserialize, Serialize};

use crate::security::transmit_guard::TransmitPermit;

/// `IPV6_HDRINCL` socket option (Linux ≥4.5) — not exposed by the `libc`
/// crate, so we name the kernel constant directly.
#[cfg(target_os = "linux")]
const IPV6_HDRINCL: libc::c_int = 36;

/// Raw sockets (`IP_HDRINCL` / `IPV6_HDRINCL`) for source-spoofed
/// scanner-kill responses.
///
/// Must be opened during the privileged window (before `drop_privileges`),
/// since they need `CAP_NET_RAW`; they are then moved into the worker thread
/// and remain usable after the drop. Linux-only — on other platforms `open`
/// returns an error and the worker falls back to the ephemeral UDP send. Each
/// family is opened best-effort: a host without an IPv6 stack still spoofs
/// IPv4, and vice-versa.
pub struct RawKillSocket {
    /// Raw IPv4 send socket (`IP_HDRINCL`); `None` if that family failed to open.
    #[cfg(target_os = "linux")]
    fd_v4: Option<std::os::fd::OwnedFd>,
    /// Raw IPv6 send socket; `None` if that family failed to open.
    #[cfg(target_os = "linux")]
    fd_v6: Option<std::os::fd::OwnedFd>,
}

impl RawKillSocket {
    /// Open a raw `SOCK_RAW`/`IPPROTO_RAW` socket for `domain`. `IPPROTO_RAW`
    /// already implies header inclusion (we supply the full IP header). For
    /// IPv4 we still set `IP_HDRINCL` explicitly (`hdrincl`); for IPv6 the
    /// `IPPROTO_RAW` socket includes the header implicitly and setting
    /// `IPV6_HDRINCL` is unnecessary and rejected on some kernels, so it is
    /// applied best-effort and its failure is ignored.
    #[cfg(target_os = "linux")]
    fn open_family(
        domain: libc::c_int,
        hdrincl: Option<(libc::c_int, libc::c_int)>,
        hdrincl_required: bool,
    ) -> std::io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::FromRawFd;
        // SAFETY: raw syscall; the returned fd is immediately adopted by an
        // OwnedFd so it is closed exactly once on drop.
        let fd = unsafe { libc::socket(domain, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, valid, owned descriptor from socket() above;
        // adopting it here gives it a single owner that closes it on drop.
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        if let Some((level, name)) = hdrincl {
            let one: libc::c_int = 1;
            // SAFETY: fd is valid; &one outlives the call.
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    name,
                    std::ptr::addr_of!(one).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc < 0 && hdrincl_required {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(owned)
    }

    /// Open the raw IPv4 and IPv6 send sockets. Requires `CAP_NET_RAW`; call
    /// before dropping privileges. Succeeds if at least one family opens; the
    /// IPv4 error is surfaced when both fail (the common permission case).
    #[cfg(target_os = "linux")]
    pub fn open() -> std::io::Result<Self> {
        let v4 = Self::open_family(
            libc::AF_INET,
            Some((libc::IPPROTO_IP, libc::IP_HDRINCL)),
            true,
        );
        // IPPROTO_RAW already includes the IPv6 header; IPV6_HDRINCL is a
        // best-effort belt-and-braces (ignored if the kernel rejects it).
        let v6 = Self::open_family(
            libc::AF_INET6,
            Some((libc::IPPROTO_IPV6, IPV6_HDRINCL)),
            false,
        );
        match (v4, v6) {
            (Ok(a), b) => Ok(Self {
                fd_v4: Some(a),
                fd_v6: b.ok(),
            }),
            (Err(_), Ok(b)) => Ok(Self {
                fd_v4: None,
                fd_v6: Some(b),
            }),
            // Both failed — report the IPv4 error (usually EPERM).
            (Err(e4), Err(_)) => Err(e4),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open() -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "raw-socket kill-response spoofing is only supported on Linux",
        ))
    }

    /// Send a pre-built IPv4 datagram (its own IP header carries the spoofed
    /// source) to `dst`. The kernel routes on `dst`; the datagram's L3/L4
    /// headers are ours.
    ///
    /// The `TransmitPermit` is the offline-analysis gate: it can only be
    /// obtained from a live capture source, so this function is uncallable on a
    /// run that is reading a file. See [`crate::security::transmit_guard`].
    #[cfg(target_os = "linux")]
    fn send_to_v4(
        &self,
        _permit: &TransmitPermit,
        packet: &[u8],
        dst: SocketAddrV4,
    ) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        let fd = self.fd_v4.as_ref().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Unsupported, "no IPv4 raw socket")
        })?;
        // SAFETY: sockaddr_in is a plain-old-data C struct; an all-zero bit
        // pattern is a valid (unspecified) value that we fully populate below.
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = dst.port().to_be();
        sa.sin_addr.s_addr = u32::from_ne_bytes(dst.ip().octets());
        // SAFETY: fd is valid; packet slice and sockaddr outlive the call.
        let n = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                std::ptr::addr_of!(sa).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Send a pre-built IPv6 datagram (its own IPv6 header carries the spoofed
    /// source) to `dst`. Gated on a `TransmitPermit` for the same reason as
    /// [`Self::send_to_v4`].
    #[cfg(target_os = "linux")]
    fn send_to_v6(
        &self,
        _permit: &TransmitPermit,
        packet: &[u8],
        dst: std::net::SocketAddrV6,
    ) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        let fd = self.fd_v6.as_ref().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Unsupported, "no IPv6 raw socket")
        })?;
        // SAFETY: sockaddr_in6 is a plain-old-data C struct; an all-zero bit
        // pattern is a valid value that we fully populate below.
        let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        // Raw IPv6 sockets require sin6_port == 0 (the real dest port lives in
        // our own UDP header); a nonzero value here yields EINVAL.
        sa.sin6_port = 0;
        sa.sin6_addr.s6_addr = dst.ip().octets();
        // SAFETY: fd is valid; packet slice and sockaddr outlive the call.
        let n = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                std::ptr::addr_of!(sa).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    #[cfg(not(target_os = "linux"))]
    fn send_to_v4(
        &self,
        _permit: &TransmitPermit,
        _packet: &[u8],
        _dst: SocketAddrV4,
    ) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "raw-socket send is only supported on Linux",
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn send_to_v6(
        &self,
        _permit: &TransmitPermit,
        _packet: &[u8],
        _dst: std::net::SocketAddrV6,
    ) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "raw-socket send is only supported on Linux",
        ))
    }
}

/// An ephemeral UDP send socket for scanner-kill responses.
///
/// A newtype around `UdpSocket` whose only purpose is to make the permit
/// mandatory: a bare `UdpSocket` field would let a future edit call
/// `send_to` with no proof the run is live, which is exactly the mistake this
/// module now refuses to make possible. See
/// [`crate::security::transmit_guard`].
struct KillUdpSocket(UdpSocket);

impl KillUdpSocket {
    /// Bind an ephemeral send socket, or `None` when that family is
    /// unavailable (e.g. a host with no IPv6 stack).
    fn bind(addr: (IpAddr, u16)) -> Option<Self> {
        UdpSocket::bind(addr).ok().map(Self)
    }

    /// Send `buf` to `dst`. Requires a [`TransmitPermit`], so it is uncallable
    /// while reading a capture file.
    fn send_to(
        &self,
        _permit: &TransmitPermit,
        buf: &[u8],
        dst: (IpAddr, u16),
    ) -> std::io::Result<usize> {
        self.0.send_to(buf, dst)
    }
}

/// Count of scanner-kill responses sent via the source-spoofed raw path.
static KILL_SENT_RAW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Count of scanner-kill responses sent via the ephemeral UDP fallback.
static KILL_SENT_EPHEMERAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Increment the per-mode scanner-kill send counter.
fn inc_kill_response_sent(raw: bool) {
    let c = if raw {
        &KILL_SENT_RAW
    } else {
        &KILL_SENT_EPHEMERAL
    };
    c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Scanner-kill responses sent, as `(raw, ephemeral)`, for the metrics
/// exporter. Process-global and monotonic.
pub fn kill_responses_sent() -> (u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (
        KILL_SENT_RAW.load(Relaxed),
        KILL_SENT_EPHEMERAL.load(Relaxed),
    )
}

/// Message types sent from the main thread to the scanner-kill worker.
#[derive(Debug, Serialize, Deserialize)]
pub enum KillRequest {
    /// Request to send a SIP response to a scanner.
    SendResponse {
        /// Destination IP address (the scanner).
        dst_addr: IpAddr,
        /// Destination transport port (the scanner's source port).
        dst_port: u16,
        /// Spoof source: the victim IP the scanner targeted. Used as the
        /// forged source when raw-socket spoofing is active; ignored by the
        /// ephemeral fallback.
        src_addr: IpAddr,
        /// Spoof source port: the victim port the scanner targeted.
        src_port: u16,
        /// Pre-built SIP response bytes to inject.
        response_bytes: Vec<u8>,
    },
    /// Gracefully shut down the worker thread.
    Shutdown,
}

/// Response from the scanner-kill worker back to the main thread.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KillResponse {
    /// Response was successfully transmitted to the scanner over UDP.
    Sent,
    /// Request was dropped due to rate limiting.
    RateLimited,
    /// Request was rejected for a policy reason.
    Rejected {
        /// Human-readable rejection reason.
        reason: String,
    },
    /// An error occurred processing the request.
    Error {
        /// Error description.
        message: String,
    },
}

/// What the scanner-kill defense actually did, as a snapshot.
///
/// This is the *ledger*: every request the worker took a decision on is
/// counted here, and it is complete whether or not anybody is reading the
/// per-event stream behind [`ScannerKillHandle::try_recv_response`]. Getting
/// that the wrong way round is the whole of the defect this type exists to
/// close — outcomes used to live only in a bounded channel nothing drained,
/// so they were both invisible and, once 256 of them had piled up, fatal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KillCounts {
    /// Responses the worker put on the wire.
    pub sent: u64,
    /// Requests suppressed by the global or per-destination rate limiter.
    pub rate_limited: u64,
    /// Requests refused on policy grounds: a broadcast/multicast destination
    /// or an empty response body.
    pub rejected: u64,
    /// Requests that reached a socket and failed there.
    pub errored: u64,
    /// Kill requests the capture thread could not hand over because the
    /// worker's queue was full, and which were therefore dropped.
    ///
    /// Dropping is deliberate: the capture thread holds the dialog and stream
    /// write locks while it offers a request, so waiting there stops the
    /// capture and every reader of those locks. A nonzero value means the
    /// responder fell behind a flood, not that anything is broken — under a
    /// flood almost every queued request would have been rate-limited anyway.
    pub dropped_requests: u64,
    /// Outcomes that did not fit on the observation channel because nothing
    /// was draining it.
    ///
    /// They are still counted in the four class totals above; only the
    /// per-event stream lost them.
    pub unobserved_outcomes: u64,
}

impl KillCounts {
    /// Total requests the worker took a decision on — sent, rate-limited,
    /// rejected and errored together.
    ///
    /// Every request accepted by [`ScannerKillHandle::send_kill`] ends up in
    /// exactly one of those four classes, so this is what an accepted request
    /// count must eventually equal.
    pub fn outcomes(&self) -> u64 {
        self.sent + self.rate_limited + self.rejected + self.errored
    }

    /// Whether anything was dropped — either a request the capture thread
    /// could not hand over, or an outcome that did not fit on the stream.
    pub fn any_dropped(&self) -> bool {
        self.dropped_requests > 0 || self.unobserved_outcomes > 0
    }
}

/// The live counters behind [`KillCounts`], shared by the handle and the
/// worker thread.
///
/// Every mutator is a relaxed atomic add: recording an outcome must never be
/// able to block, because the thread doing the recording is the one answering
/// scanners, and the thread reading the result is the one capturing packets.
#[derive(Debug, Default)]
struct KillTally {
    /// See [`KillCounts::sent`].
    sent: AtomicU64,
    /// See [`KillCounts::rate_limited`].
    rate_limited: AtomicU64,
    /// See [`KillCounts::rejected`].
    rejected: AtomicU64,
    /// See [`KillCounts::errored`].
    errored: AtomicU64,
    /// See [`KillCounts::dropped_requests`].
    dropped_requests: AtomicU64,
    /// See [`KillCounts::unobserved_outcomes`].
    unobserved_outcomes: AtomicU64,
    /// Set the first time a request is dropped, so the operator is told once
    /// rather than once per dropped packet.
    drop_reported: AtomicBool,
    /// Set the first time an outcome does not fit on the observation channel.
    unobserved_reported: AtomicBool,
}

impl KillTally {
    /// Record one worker decision. Called before the outcome is offered to
    /// anyone, so an outcome is on the books even if nothing ever reads it.
    fn record(&self, outcome: &KillResponse) {
        let counter = match outcome {
            KillResponse::Sent => &self.sent,
            KillResponse::RateLimited => &self.rate_limited,
            KillResponse::Rejected { .. } => &self.rejected,
            KillResponse::Error { .. } => &self.errored,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a kill request that was dropped because the worker's queue was
    /// full, and say so once.
    fn note_dropped_request(&self) {
        self.dropped_requests.fetch_add(1, Ordering::Relaxed);
        if !self.drop_reported.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "scanner-kill: the worker's request queue is full \
                 ({KILL_REQUEST_CAPACITY} pending) and kill responses are now \
                 being DROPPED. They are dropped rather than queued because \
                 the capture thread offers them while holding the dialog and \
                 stream locks, and waiting there would stop the capture and \
                 every reader of those locks. Detection, alerting and \
                 reporting are unaffected; the running total is logged when \
                 the worker shuts down."
            );
        }
    }

    /// Count an outcome that did not fit on the observation channel, and say
    /// so once.
    fn note_unobserved_outcome(&self) {
        self.unobserved_outcomes.fetch_add(1, Ordering::Relaxed);
        if !self.unobserved_reported.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "scanner-kill: nothing is draining the kill-outcome channel, \
                 so individual outcomes are no longer observable through it. \
                 They are still counted — see ScannerKillHandle::counts() and \
                 the totals logged at shutdown."
            );
        }
    }

    /// Take a consistent-enough snapshot for reporting. The counters are read
    /// one at a time, so a snapshot taken mid-flood may be a few events stale;
    /// it is never wrong about what has already been counted.
    fn snapshot(&self) -> KillCounts {
        KillCounts {
            sent: self.sent.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            errored: self.errored.load(Ordering::Relaxed),
            dropped_requests: self.dropped_requests.load(Ordering::Relaxed),
            unobserved_outcomes: self.unobserved_outcomes.load(Ordering::Relaxed),
        }
    }
}

/// Handle for the main thread to communicate with the scanner-kill worker.
///
/// Sending a `KillRequest` offers it to the worker thread. Call
/// `shutdown` to cleanly stop the worker.
///
/// # Why nothing here blocks
///
/// The thread that calls [`Self::send_kill`] is the capture thread, and it
/// calls it while holding the dialog and stream write locks. Anything that
/// blocks it therefore stops packet processing *and* every consumer of those
/// stores — the REST API, the TUI and the whole MCP surface, not just the
/// kill path. So the request queue is offered to, never waited on, and the
/// worker publishes outcomes the same way. What would have been backpressure
/// is a counted drop instead: see [`KillCounts`].
pub struct ScannerKillHandle {
    /// Channel to queue kill requests for the worker thread. `None` after
    /// [`Self::shutdown`], which drops the sender so the worker's channel
    /// disconnects and it is guaranteed to exit.
    tx: Option<Sender<KillRequest>>,
    /// Best-effort channel of per-request outcomes sent back by the worker.
    resp_rx: Receiver<KillResponse>,
    /// Join handle for the worker thread; taken on shutdown.
    thread: Option<std::thread::JoinHandle<()>>,
    /// Set on the first failed send so a dead worker is reported exactly
    /// once, loudly, instead of every kill attempt silently vanishing.
    defense_disabled: AtomicBool,
    /// The authoritative record of what the worker did, shared with it.
    tally: Arc<KillTally>,
}

impl ScannerKillHandle {
    /// Offer a kill request to the worker thread. Never blocks.
    ///
    /// Returns `Ok(())` if the request was queued. The outcome is recorded in
    /// [`Self::counts`] and, best-effort, published on the channel behind
    /// [`Self::try_recv_response`].
    ///
    /// # Errors
    ///
    /// * `TrySendError::Full` — the worker is behind and the request was
    ///   dropped. Counted in [`KillCounts::dropped_requests`] and warned about
    ///   once. The alternative, waiting, wedges the capture thread and
    ///   everything reading the stores it has locked.
    /// * `TrySendError::Disconnected` — the worker thread has died (panic or
    ///   unexpected exit) or has already been shut down. An error is logged
    ///   once and [`Self::defense_disabled`] reports `true` from then on: the
    ///   kill defense is gone for the rest of the run.
    pub fn send_kill(&self, request: KillRequest) -> Result<(), TrySendError<KillRequest>> {
        let Some(tx) = self.tx.as_ref() else {
            self.report_defense_disabled();
            return Err(TrySendError::Disconnected(request));
        };
        match tx.try_send(request) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(request)) => {
                self.tally.note_dropped_request();
                Err(TrySendError::Full(request))
            }
            Err(TrySendError::Disconnected(request)) => {
                self.report_defense_disabled();
                Err(TrySendError::Disconnected(request))
            }
        }
    }

    /// Report, exactly once, that the kill defense is no longer armed.
    fn report_defense_disabled(&self) {
        if !self.defense_disabled.swap(true, Ordering::Relaxed) {
            tracing::error!(
                "scanner-kill worker thread is dead (panicked or exited \
                 unexpectedly); the --kill-scanner defense is DISABLED for \
                 the rest of this run — scanners will be detected but no \
                 longer answered"
            );
        }
    }

    /// Whether the worker thread is still running.
    pub fn is_alive(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// Whether the kill defense has been marked dead (a send failed because
    /// the worker exited). Once true, stays true.
    pub fn defense_disabled(&self) -> bool {
        self.defense_disabled.load(Ordering::Relaxed)
    }

    /// What this worker has done so far: sends, suppressions, refusals,
    /// failures, and anything dropped.
    ///
    /// This is the reachable form of the kill outcome. It does not depend on
    /// anybody polling [`Self::try_recv_response`], which is exactly why it
    /// exists.
    pub fn counts(&self) -> KillCounts {
        self.tally.snapshot()
    }

    /// Try to receive one outcome from the worker (non-blocking).
    ///
    /// Best-effort: this is a stream of individual outcomes for a caller that
    /// wants them as they happen, and outcomes that did not fit while nobody
    /// was draining it are missing from it (counted in
    /// [`KillCounts::unobserved_outcomes`]). [`Self::counts`] is the complete
    /// record; use this only when the individual events matter.
    pub fn try_recv_response(&self) -> Option<KillResponse> {
        self.resp_rx.try_recv().ok()
    }

    /// Shut down the worker thread, wait for it to exit, and log what the
    /// defense did.
    pub fn shutdown(&mut self) {
        // Ask the worker to stop, then DROP the sender. The ask is
        // best-effort — the queue may be full, and waiting for a slot is the
        // blocking this type exists to avoid — so the sender being dropped is
        // what actually guarantees an exit: the worker drains whatever is
        // queued, sees a disconnected channel, and returns. Keeping the
        // sender alive after a failed ask would leave the worker parked in
        // `recv()` forever with this thread parked in `join()`.
        if let Some(tx) = self.tx.take() {
            let _ = tx.try_send(KillRequest::Shutdown);
        }
        if let Some(handle) = self.thread.take() {
            if let Err(e) = handle.join() {
                tracing::error!("Scanner-kill worker thread panicked: {e:?}");
            }
            self.log_totals();
        }
    }

    /// Log what the kill defense did over the run. Warns when anything was
    /// dropped, so a flood that outran the responder is visible without
    /// anyone having asked for counters.
    fn log_totals(&self) {
        let counts = self.counts();
        if counts.any_dropped() {
            tracing::warn!(
                "Scanner-kill totals: {} sent, {} rate-limited, {} rejected, \
                 {} failed; {} request(s) dropped because the worker was \
                 behind, {} outcome(s) unobserved because nothing was reading \
                 the outcome channel",
                counts.sent,
                counts.rate_limited,
                counts.rejected,
                counts.errored,
                counts.dropped_requests,
                counts.unobserved_outcomes,
            );
        } else {
            tracing::info!(
                "Scanner-kill totals: {} sent, {} rate-limited, {} rejected, {} failed",
                counts.sent,
                counts.rate_limited,
                counts.rejected,
                counts.errored,
            );
        }
    }
}

impl Drop for ScannerKillHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Fixed-window rate limiter for scanner-kill responses.
///
/// Limits the number of responses sent per second to prevent the kill
/// mechanism from becoming an amplification vector. Counts within a
/// one-second window and resets the count when the window rolls over (a
/// fixed-window counter, not a continuously-refilling token bucket).
struct RateLimiter {
    /// Maximum responses permitted per one-second window.
    max_per_second: u32,
    /// Responses sent so far in the current window.
    count_this_window: u32,
    /// When the current window began; the window rolls over one second later.
    window_start: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter with the given maximum requests per second.
    fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            count_this_window: 0,
            window_start: Instant::now(),
        }
    }

    /// Check whether a request is allowed. Returns `true` if under the limit.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start).as_secs() >= 1 {
            self.count_this_window = 0;
            self.window_start = now;
        }
        if self.count_this_window < self.max_per_second {
            self.count_this_window += 1;
            true
        } else {
            false
        }
    }
}

/// Per-destination IP rate limiter to prevent amplification attacks.
///
/// Limits the number of responses to any single destination IP to
/// `MAX_PER_DST_PER_MINUTE` within a fixed (tumbling) one-minute window: the
/// per-IP counter and window start are reset the first time `allow` is called
/// 60s or more after the window began, not continuously as a sliding window
/// would.
struct PerDstRateLimiter {
    /// Map of destination IP to (window start, count).
    buckets: HashMap<IpAddr, (Instant, u32)>,
    /// When the O(n) sweep last ran, so it is amortized to at most once per
    /// second instead of on every send (the same pattern as the HEP replay
    /// cache's `HmacNonceCache::should_prune`). `None` until the first sweep.
    last_cleanup: Option<Instant>,
}

/// Maximum responses per destination IP per minute.
const MAX_PER_DST_PER_MINUTE: u32 = 3;

impl PerDstRateLimiter {
    /// Create an empty per-destination limiter (no buckets yet).
    fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            last_cleanup: None,
        }
    }

    /// Check whether a response to `dst` is allowed. Returns `true` if under limit.
    fn allow(&mut self, dst: IpAddr) -> bool {
        let now = Instant::now();
        let entry = self.buckets.entry(dst).or_insert((now, 0));

        // Reset window if more than 60 seconds have passed
        if now.duration_since(entry.0).as_secs() >= 60 {
            *entry = (now, 0);
        }

        if entry.1 < MAX_PER_DST_PER_MINUTE {
            entry.1 += 1;
            true
        } else {
            false
        }
    }

    /// Remove entries older than 2 minutes to prevent memory growth. O(n) in
    /// the number of tracked destinations; call via [`Self::cleanup_if_due`]
    /// so it is not paid on every send.
    fn cleanup(&mut self, now: Instant) {
        self.buckets
            .retain(|_, (start, _)| now.duration_since(*start).as_secs() < 120);
    }

    /// Run [`Self::cleanup`] at most once per second. Amortizing is
    /// behavior-preserving: eviction only bounds memory — an entry that
    /// outlives its 60s window is still reset by the window check in
    /// [`Self::allow`], so a not-yet-swept stale bucket never over-limits or
    /// under-limits a destination. The first call always sweeps.
    fn cleanup_if_due(&mut self, now: Instant) {
        match self.last_cleanup {
            Some(prev) if now.duration_since(prev).as_secs() < 1 => {}
            _ => {
                self.last_cleanup = Some(now);
                self.cleanup(now);
            }
        }
    }
}

/// Scanner-kill worker that runs in a dedicated thread.
///
/// Receives `KillRequest`s via channel, validates them, applies rate
/// limiting (both global and per-destination-IP), and transmits the SIP
/// response to the scanner over UDP.
///
/// The response leaves from an ephemeral source port on `sock_v4`/`sock_v6`
/// (bound once at spawn), not from the SIP listener port the scanner
/// originally targeted — sipnab is a passive sniffer and does not own that
/// socket. Scanners that key on the SIP transaction (Call-ID / branch /
/// CSeq / To-tag) accept it regardless; matching the source port would
/// require raw sockets (`CAP_NET_RAW`) and is left as a future enhancement.
struct ScannerKillWorker {
    /// Inbound channel of kill requests from the main thread.
    rx: Receiver<KillRequest>,
    /// Best-effort outbound channel of per-request outcomes back to the main
    /// thread. Offered to, never waited on — see [`ScannerKillHandle`].
    resp_tx: Sender<KillResponse>,
    /// The authoritative record of outcomes, shared with the handle.
    tally: Arc<KillTally>,
    /// Global responses-per-second limiter.
    rate_limiter: RateLimiter,
    /// Per-destination-IP limiter (amplification mitigation).
    per_dst_limiter: PerDstRateLimiter,
    /// UDP socket for IPv4 destinations (bound to `0.0.0.0:0`); `None` if the
    /// bind failed at spawn.
    sock_v4: Option<KillUdpSocket>,
    /// UDP socket for IPv6 destinations (bound to `[::]:0`); `None` if the
    /// bind failed at spawn.
    sock_v6: Option<KillUdpSocket>,
    /// Raw socket for source-spoofed IPv4 responses, opened privileged and
    /// moved in at spawn. `None` → the ephemeral UDP send is used.
    raw_sock: Option<RawKillSocket>,
    /// Proof that this run watches a live source. Required to construct the
    /// worker at all, and handed to every send below, so a worker reading a
    /// capture file cannot exist and could not transmit if it did.
    permit: TransmitPermit,
}

impl ScannerKillWorker {
    /// Run the worker loop until a `Shutdown` request is received or the
    /// channel disconnects.
    fn run(mut self) {
        tracing::info!(
            "Scanner-kill worker started (rate limit: {}/sec)",
            self.rate_limiter.max_per_second
        );

        loop {
            let request = match self.rx.recv() {
                Ok(req) => req,
                Err(_) => {
                    tracing::debug!("Scanner-kill channel disconnected, worker exiting");
                    break;
                }
            };

            match request {
                KillRequest::Shutdown => {
                    tracing::info!("Scanner-kill worker shutting down");
                    break;
                }
                KillRequest::SendResponse {
                    dst_addr,
                    dst_port,
                    src_addr,
                    src_port,
                    response_bytes,
                } => {
                    let response =
                        self.process_send(dst_addr, dst_port, src_addr, src_port, &response_bytes);
                    // Book the outcome BEFORE offering it to anyone. The
                    // tally is what makes the outcome reachable; the channel
                    // is a convenience on top of it.
                    self.tally.record(&response);
                    // Offer, never wait. Blocking here is the defect: nothing
                    // in production drains this channel, so the worker stalled
                    // on outcome 257, stopped draining requests, and the
                    // capture thread — holding the dialog and stream write
                    // locks — blocked handing over request ~513. The capture
                    // and every reader of those locks stopped with it.
                    // `Disconnected` needs no note: the handle is gone, so
                    // there is no longer anyone to tell.
                    if let Err(TrySendError::Full(_)) = self.resp_tx.try_send(response) {
                        self.tally.note_unobserved_outcome();
                    }
                }
            }
        }
    }

    /// Validate and process a single send request.
    fn process_send(
        &mut self,
        dst_addr: IpAddr,
        dst_port: u16,
        src_addr: IpAddr,
        src_port: u16,
        response_bytes: &[u8],
    ) -> KillResponse {
        // Reject broadcast addresses
        if is_broadcast_or_multicast(dst_addr) {
            let reason = format!("rejected broadcast/multicast destination: {dst_addr}");
            tracing::warn!("Scanner-kill: {reason}");
            return KillResponse::Rejected { reason };
        }

        // Reject empty responses
        if response_bytes.is_empty() {
            return KillResponse::Rejected {
                reason: "empty response bytes".to_string(),
            };
        }

        // Apply global rate limit
        if !self.rate_limiter.allow() {
            tracing::debug!("Scanner-kill: rate limited response to {dst_addr}:{dst_port}");
            return KillResponse::RateLimited;
        }

        // Apply per-destination-IP rate limit (M6: amplification mitigation)
        if !self.per_dst_limiter.allow(dst_addr) {
            tracing::debug!("Scanner-kill: per-destination rate limited for {dst_addr}:{dst_port}");
            return KillResponse::RateLimited;
        }

        // Periodic cleanup of per-dst limiter (amortized to once per second so
        // the O(n) sweep is not paid on every send).
        self.per_dst_limiter.cleanup_if_due(Instant::now());

        // Prefer a source-spoofed raw send when a raw socket is available. The
        // forged source is the victim ip:port the scanner targeted, so the
        // reply appears to come from the SIP listener rather than sipnab's
        // ephemeral port. Build the datagram for the matching address family
        // (mixed families never occur — src and dst come from one packet) and
        // fall back to the plain UDP send on any failure.
        if let Some(raw) = self.raw_sock.as_ref() {
            let spoofed: Option<std::io::Result<usize>> = match (dst_addr, src_addr) {
                (IpAddr::V4(dst_v4), IpAddr::V4(src_v4)) => {
                    let dst = SocketAddrV4::new(dst_v4, dst_port);
                    let src = SocketAddrV4::new(src_v4, src_port);
                    crate::security::kill_packet::build_ipv4_udp(src, dst, response_bytes)
                        .map(|pkt| raw.send_to_v4(&self.permit, &pkt, dst))
                }
                (IpAddr::V6(dst_v6), IpAddr::V6(src_v6)) => {
                    let dst = std::net::SocketAddrV6::new(dst_v6, dst_port, 0, 0);
                    let src = std::net::SocketAddrV6::new(src_v6, src_port, 0, 0);
                    crate::security::kill_packet::build_ipv6_udp(src, dst, response_bytes)
                        .map(|pkt| raw.send_to_v6(&self.permit, &pkt, dst))
                }
                _ => None,
            };
            match spoofed {
                Some(Ok(_)) => {
                    inc_kill_response_sent(true);
                    tracing::info!(
                        "Scanner-kill: sent {} byte spoofed response to {dst_addr}:{dst_port} (source {src_addr}:{src_port})",
                        response_bytes.len(),
                    );
                    return KillResponse::Sent;
                }
                Some(Err(e)) => {
                    // Raw send failed at runtime; fall through to the ephemeral
                    // path rather than dropping the response.
                    tracing::warn!(
                        "Scanner-kill: spoofed send to {dst_addr}:{dst_port} failed ({e}); falling back to ephemeral source"
                    );
                }
                None => {}
            }
        }

        // Ephemeral fallback: plain UDP send from our own source port.
        let sock = match dst_addr {
            IpAddr::V4(_) => self.sock_v4.as_ref(),
            IpAddr::V6(_) => self.sock_v6.as_ref(),
        };
        let Some(sock) = sock else {
            let message = format!("no UDP socket available for {dst_addr}");
            tracing::error!("Scanner-kill: {message}");
            return KillResponse::Error { message };
        };
        match sock.send_to(&self.permit, response_bytes, (dst_addr, dst_port)) {
            Ok(n) => {
                inc_kill_response_sent(false);
                tracing::info!("Scanner-kill: sent {n} byte response to {dst_addr}:{dst_port}");
                KillResponse::Sent
            }
            Err(e) => {
                let message = format!("send to {dst_addr}:{dst_port} failed: {e}");
                tracing::warn!("Scanner-kill: {message}");
                KillResponse::Error { message }
            }
        }
    }
}

/// Check whether an IP address is broadcast or multicast.
fn is_broadcast_or_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

/// Default rate limit for scanner-kill responses (per second).
const DEFAULT_RATE_LIMIT: u32 = 10;

/// How many kill requests may be in flight to the worker before further ones
/// are dropped rather than made to wait.
///
/// The depth only has to cover a burst: the worker's per-request cost is a
/// rate-limit check plus, for the few that pass it, one `sendto`. Anything
/// deeper than a burst is a queue of responses to scanner packets that are
/// already stale by the time they would be sent.
const KILL_REQUEST_CAPACITY: usize = 256;

/// How many outcomes may be waiting on the observation channel before further
/// ones are counted-but-not-streamed.
const KILL_OUTCOME_CAPACITY: usize = 256;

/// Spawn the scanner-kill worker thread and return a handle for communication.
///
/// The worker runs in a dedicated thread with its own rate limiter. Kill
/// requests are sent via the returned `ScannerKillHandle`. The worker
/// validates destinations (rejecting broadcast/multicast), applies rate
/// limiting (both global and per-destination-IP), and logs responses.
///
/// # Arguments
///
/// * `rate_limit` — Maximum responses per second. Pass `None` for the
///   default of 10/sec.
/// * `raw_sock` — Raw IPv4 socket for source-spoofed responses, opened during
///   the privileged window. Pass `None` to always use the ephemeral UDP send.
/// * `permit` — proof, obtained from the capture source, that this run watches
///   a live source. There is no way to spawn a transmitting worker for a run
///   that is reading a capture file: see [`crate::security::transmit_guard`].
///
/// # Errors
///
/// Returns an error if the worker thread cannot be spawned.
pub fn spawn_scanner_kill_worker(
    rate_limit: Option<u32>,
    raw_sock: Option<RawKillSocket>,
    permit: TransmitPermit,
) -> Result<ScannerKillHandle, std::io::Error> {
    let rate = rate_limit.unwrap_or(DEFAULT_RATE_LIMIT);
    let (tx, rx) = crossbeam_channel::bounded(KILL_REQUEST_CAPACITY);
    let (resp_tx, resp_rx) = crossbeam_channel::bounded(KILL_OUTCOME_CAPACITY);
    let tally = Arc::new(KillTally::default());

    // Bind the send sockets once, up front. Either family may be unavailable
    // (e.g. no IPv6 stack); a destination whose family has no socket is
    // reported as an error at send time rather than silently dropped.
    let sock_v4 = KillUdpSocket::bind((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let sock_v6 = KillUdpSocket::bind((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0));
    if sock_v4.is_none() && sock_v6.is_none() {
        tracing::error!(
            "Scanner-kill: could not bind any UDP send socket; kill responses will error"
        );
    }

    let worker = ScannerKillWorker {
        rx,
        resp_tx,
        tally: Arc::clone(&tally),
        rate_limiter: RateLimiter::new(rate),
        per_dst_limiter: PerDstRateLimiter::new(),
        sock_v4,
        sock_v6,
        raw_sock,
        permit,
    };

    let thread = std::thread::Builder::new()
        .name("scanner-kill".to_string())
        .spawn(move || worker.run())?;

    Ok(ScannerKillHandle {
        tx: Some(tx),
        resp_rx,
        thread: Some(thread),
        defense_disabled: AtomicBool::new(false),
        tally,
    })
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! Scanner-kill worker tests: source-spoofed and ephemeral sends, rate
    //! limiting, broadcast/multicast rejection, verbatim delivery, and dead-
    //! worker detection. Raw-socket spoof tests self-skip without `CAP_NET_RAW`.
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// A transmit permit standing for a live capture.
    ///
    /// These tests exercise the sending worker, so they must declare a live
    /// source exactly as a real run does — there is no back door, which is the
    /// point of the guard. Every send below goes to loopback only.
    fn live_permit() -> TransmitPermit {
        TransmitPermit::for_source(&crate::capture::CaptureSource::Live {
            device: "lo".to_string(),
        })
        .expect("a live source must grant a transmit permit")
    }

    /// A worker reading a capture file cannot be spawned: the permit its
    /// constructor requires does not exist for a file source. This is the
    /// compile-time half of the offline-transmit guard, asserted here as the
    /// runtime fact it derives from.
    #[test]
    fn a_file_source_yields_no_permit_so_no_worker_can_be_spawned() {
        let file = crate::capture::CaptureSource::File {
            paths: vec![std::path::PathBuf::from("/tmp/evidence.pcap")],
        };
        assert!(
            TransmitPermit::for_source(&file).is_none(),
            "spawn_scanner_kill_worker takes a TransmitPermit by value, so a \
             None here means no kill worker can exist on a file run"
        );
    }

    /// Poll the response channel until a response arrives or `deadline`
    /// expires — replaces fixed sleeps (fast when fast, CI-tolerant).
    fn recv_response_within(
        handle: &ScannerKillHandle,
        deadline: std::time::Duration,
    ) -> Option<KillResponse> {
        let start = std::time::Instant::now();
        loop {
            if let Some(r) = handle.try_recv_response() {
                return Some(r);
            }
            if start.elapsed() > deadline {
                return None;
            }
            std::thread::yield_now();
        }
    }

    /// The IPv4 loopback address (test destination/source shorthand).
    fn localhost_v4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// A minimal valid SIP 200 OK response body for kill-send tests.
    fn sample_response() -> Vec<u8> {
        b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()
    }

    /// The per-destination limiter's O(n) sweep is amortized to at most once
    /// per second: a second `cleanup_if_due` within the same 1s window is a
    /// no-op (it does not sweep), while a call ≥1s later sweeps again. Uses an
    /// injected monotonic `now` so no wall-clock sleeping is needed.
    #[test]
    fn per_dst_cleanup_is_amortized_to_once_per_second() {
        use std::time::Duration;
        let t0 = Instant::now();
        let mut lim = PerDstRateLimiter::new();
        let stale_a: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let stale_b: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));

        // A bucket whose window started >120s before `now` is sweep-eligible.
        lim.buckets.insert(stale_a, (t0, 3));
        lim.cleanup_if_due(t0 + Duration::from_secs(200));
        assert!(
            !lim.buckets.contains_key(&stale_a),
            "first due cleanup must sweep the stale bucket"
        );

        // A second call <1s after the last sweep must NOT sweep — proof the
        // O(n) work is amortized, not paid every call.
        lim.buckets.insert(stale_b, (t0, 3));
        lim.cleanup_if_due(t0 + Duration::from_secs(200) + Duration::from_millis(500));
        assert!(
            lim.buckets.contains_key(&stale_b),
            "cleanup within the same 1s window must be skipped (amortized)"
        );

        // ≥1s after the last sweep it runs again and prunes the stale bucket.
        lim.cleanup_if_due(t0 + Duration::from_secs(202));
        assert!(
            !lim.buckets.contains_key(&stale_b),
            "cleanup must run again once ≥1s has elapsed"
        );
    }

    /// Source-spoofed raw send: the datagram must arrive at the listener with
    /// the **forged victim** source ip:port, not sipnab's own. Requires
    /// `CAP_NET_RAW`; skipped (not failed) when the raw socket can't be opened,
    /// so unprivileged CI stays green. Run under sudo to exercise it.
    #[test]
    fn spoofed_send_forges_source_ip_and_port() {
        let raw = match RawKillSocket::open() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping spoof test: raw socket unavailable ({e})");
                return;
            }
        };

        let listener = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind listener");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let port = listener.local_addr().expect("local addr").port();

        // Forge the source as a distinctive loopback "victim" the scanner
        // would have targeted.
        let victim_ip = Ipv4Addr::new(127, 0, 0, 9);
        let victim_port = 5060u16;

        let mut handle =
            spawn_scanner_kill_worker(Some(10), Some(raw), live_permit()).expect("spawn worker");
        let payload = b"SIP/2.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                dst_port: port,
                src_addr: IpAddr::V4(victim_ip),
                src_port: victim_port,
                response_bytes: payload.clone(),
            })
            .expect("send should succeed");

        let mut buf = [0u8; 2048];
        let (n, from) = listener
            .recv_from(&mut buf)
            .expect("listener must receive the spoofed packet");
        assert_eq!(&buf[..n], &payload[..], "payload delivered verbatim");
        assert_eq!(
            from.ip(),
            IpAddr::V4(victim_ip),
            "source IP must be the forged victim, not sipnab's"
        );
        assert_eq!(
            from.port(),
            victim_port,
            "source port must be the forged victim port"
        );

        let resp = recv_response_within(&handle, std::time::Duration::from_secs(5));
        assert_eq!(resp, Some(KillResponse::Sent));

        let (raw_sent, _ephemeral) = kill_responses_sent();
        assert!(raw_sent >= 1, "raw-mode send counter must have incremented");

        handle.shutdown();
    }

    /// IPv6 source-spoofed raw send: the datagram must arrive at a `::1`
    /// listener with the **forged** source port (an ephemeral send would show a
    /// random port). Requires `CAP_NET_RAW`; skipped when unprivileged.
    #[test]
    fn spoofed_send_forges_source_over_ipv6() {
        let raw = match RawKillSocket::open() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping v6 spoof test: raw socket unavailable ({e})");
                return;
            }
        };

        let listener = match std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping v6 spoof test: no IPv6 loopback ({e})");
                return;
            }
        };
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let port = listener.local_addr().expect("local addr").port();

        // Forge a distinctive source port; the address is ::1 (the only v6
        // loopback that delivers), so the port is the discriminating field.
        let victim_port = 5060u16;

        let mut handle =
            spawn_scanner_kill_worker(Some(10), Some(raw), live_permit()).expect("spawn worker");
        let payload = b"SIP/2.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                dst_port: port,
                src_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                src_port: victim_port,
                response_bytes: payload.clone(),
            })
            .expect("send should succeed");

        let mut buf = [0u8; 2048];
        let (n, from) = match listener.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                // Some environments block raw v6 loopback injection; treat as a
                // skip rather than a hard failure (the builder is unit-tested).
                eprintln!("skipping v6 spoof test: no packet received ({e})");
                handle.shutdown();
                return;
            }
        };
        assert_eq!(&buf[..n], &payload[..], "payload delivered verbatim");
        assert_eq!(from.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST), "source is ::1");
        assert_eq!(
            from.port(),
            victim_port,
            "source port must be the forged victim port, not an ephemeral one"
        );

        handle.shutdown();
    }

    /// A queued kill request is processed and answered with `Sent`.
    #[test]
    fn handle_send_and_receive() {
        let mut handle =
            spawn_scanner_kill_worker(Some(10), None, live_permit()).expect("spawn worker");

        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: localhost_v4(),
                dst_port: 5060,
                src_addr: localhost_v4(),
                src_port: 5060,
                response_bytes: sample_response(),
            })
            .expect("send should succeed");

        let resp = recv_response_within(&handle, std::time::Duration::from_secs(5));
        assert_eq!(resp, Some(KillResponse::Sent));

        handle.shutdown();
    }

    /// With a 10/sec limit, 15 requests (to distinct dst IPs) yield exactly 10
    /// `Sent` and 5 `RateLimited`.
    #[test]
    fn rate_limiter_enforces_limit() {
        let mut handle =
            spawn_scanner_kill_worker(Some(10), None, live_permit()).expect("spawn worker");

        // Send 15 requests to different destination IPs so the per-dst
        // limiter doesn't interfere with the global rate limit test. Loopback
        // (127.0.0.0/8) so the now-real UDP send never leaves the host.
        for i in 0..15u8 {
            let dst = IpAddr::V4(Ipv4Addr::new(127, 0, 0, i.wrapping_add(1)));
            let _ = handle.send_kill(KillRequest::SendResponse {
                dst_addr: dst,
                dst_port: 5060,
                src_addr: localhost_v4(),
                src_port: 5060,
                response_bytes: sample_response(),
            });
        }

        // Drain until all 15 responses have arrived.
        let mut sent_count = 0u32;
        let mut limited_count = 0u32;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while sent_count + limited_count < 15 {
            match handle.try_recv_response() {
                Some(KillResponse::Sent) => sent_count += 1,
                Some(KillResponse::RateLimited) => limited_count += 1,
                Some(_) => {}
                None => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "worker should answer all 15 requests within 5s \
                         (got {sent_count} sent / {limited_count} limited)"
                    );
                    std::thread::yield_now();
                }
            }
        }

        assert_eq!(sent_count, 10, "should allow exactly 10 in one window");
        assert_eq!(limited_count, 5, "should rate-limit the remaining 5");

        handle.shutdown();
    }

    /// A broadcast destination is rejected.
    #[test]
    fn broadcast_address_rejected() {
        let mut handle =
            spawn_scanner_kill_worker(Some(10), None, live_permit()).expect("spawn worker");

        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: IpAddr::V4(Ipv4Addr::BROADCAST),
                dst_port: 5060,
                src_addr: localhost_v4(),
                src_port: 5060,
                response_bytes: sample_response(),
            })
            .expect("send should succeed");

        let resp = recv_response_within(&handle, std::time::Duration::from_secs(5));
        assert!(
            matches!(resp, Some(KillResponse::Rejected { .. })),
            "broadcast should be rejected"
        );

        handle.shutdown();
    }

    /// An IPv4 multicast destination is rejected.
    #[test]
    fn multicast_v4_rejected() {
        let mut handle =
            spawn_scanner_kill_worker(Some(10), None, live_permit()).expect("spawn worker");

        // 224.0.0.1 is multicast
        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
                dst_port: 5060,
                src_addr: localhost_v4(),
                src_port: 5060,
                response_bytes: sample_response(),
            })
            .expect("send should succeed");

        let resp = recv_response_within(&handle, std::time::Duration::from_secs(5));
        assert!(
            matches!(resp, Some(KillResponse::Rejected { .. })),
            "multicast should be rejected"
        );

        handle.shutdown();
    }

    /// An IPv6 multicast destination is rejected.
    #[test]
    fn multicast_v6_rejected() {
        let mut handle =
            spawn_scanner_kill_worker(Some(10), None, live_permit()).expect("spawn worker");

        // ff02::1 is IPv6 multicast
        let multicast_v6 = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: multicast_v6,
                dst_port: 5060,
                src_addr: localhost_v4(),
                src_port: 5060,
                response_bytes: sample_response(),
            })
            .expect("send should succeed");

        let resp = recv_response_within(&handle, std::time::Duration::from_secs(5));
        assert!(
            matches!(resp, Some(KillResponse::Rejected { .. })),
            "IPv6 multicast should be rejected"
        );

        handle.shutdown();
    }

    /// `shutdown` joins the worker thread without panicking.
    #[test]
    fn shutdown_exits_cleanly() {
        let mut handle =
            spawn_scanner_kill_worker(Some(10), None, live_permit()).expect("spawn worker");
        handle.shutdown();
        // No panic, thread joined successfully
    }

    /// An empty response body is rejected.
    #[test]
    fn empty_response_rejected() {
        let mut handle =
            spawn_scanner_kill_worker(Some(10), None, live_permit()).expect("spawn worker");

        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: localhost_v4(),
                dst_port: 5060,
                src_addr: localhost_v4(),
                src_port: 5060,
                response_bytes: vec![],
            })
            .expect("send should succeed");

        let resp = recv_response_within(&handle, std::time::Duration::from_secs(5));
        assert!(
            matches!(resp, Some(KillResponse::Rejected { .. })),
            "empty response should be rejected"
        );

        handle.shutdown();
    }

    /// The worker actually puts the response bytes on the wire (a real UDP
    /// listener receives them), not merely logs them.
    #[test]
    fn process_send_actually_transmits_over_udp() {
        // The worker must put the response bytes on the wire, not just log
        // them. Bind a real UDP listener and assert it receives the datagram.
        let listener = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind listener");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let port = listener.local_addr().expect("local addr").port();

        let mut handle =
            spawn_scanner_kill_worker(Some(10), None, live_permit()).expect("spawn worker");
        let payload = b"SIP/2.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: localhost_v4(),
                dst_port: port,
                src_addr: localhost_v4(),
                src_port: 5060,
                response_bytes: payload.clone(),
            })
            .expect("send should succeed");

        let mut buf = [0u8; 2048];
        let (n, _from) = listener
            .recv_from(&mut buf)
            .expect("listener must receive the kill packet");
        assert_eq!(
            &buf[..n],
            &payload[..],
            "listener must receive the exact response bytes"
        );

        let resp = recv_response_within(&handle, std::time::Duration::from_secs(5));
        assert_eq!(resp, Some(KillResponse::Sent));

        handle.shutdown();
    }

    /// Response bytes with embedded NUL and high bytes are delivered verbatim.
    #[test]
    fn transmits_response_bytes_verbatim_including_nul() {
        // Adversarial: response bytes carrying embedded NUL and high bytes
        // must be delivered verbatim — no truncation, no re-encoding.
        let listener = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind listener");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let port = listener.local_addr().expect("local addr").port();

        let mut handle =
            spawn_scanner_kill_worker(Some(10), None, live_permit()).expect("spawn worker");
        let payload = vec![
            0x00u8, 0xff, b'S', b'I', b'P', b'\\', 0x0d, 0x0a, 0x00, 0x80, 0x7f,
        ];
        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: localhost_v4(),
                dst_port: port,
                src_addr: localhost_v4(),
                src_port: 5060,
                response_bytes: payload.clone(),
            })
            .expect("send should succeed");

        let mut buf = [0u8; 2048];
        let (n, _from) = listener
            .recv_from(&mut buf)
            .expect("listener must receive the kill packet");
        assert_eq!(
            &buf[..n],
            &payload[..],
            "binary response bytes must be delivered byte-for-byte"
        );

        handle.shutdown();
    }

    /// The `RateLimiter` allows exactly `max_per_second` then denies.
    #[test]
    fn rate_limiter_unit_allows_within_limit() {
        let mut limiter = RateLimiter::new(5);
        for _ in 0..5 {
            assert!(limiter.allow());
        }
        assert!(!limiter.allow(), "6th request should be rejected");
    }

    /// A fresh worker reports alive/not-disabled; after shutdown it is gone.
    #[test]
    fn is_alive_true_for_running_worker() {
        let mut handle =
            spawn_scanner_kill_worker(Some(10), None, live_permit()).expect("spawn worker");
        assert!(handle.is_alive(), "freshly spawned worker must be alive");
        assert!(!handle.defense_disabled());
        handle.shutdown();
        assert!(!handle.is_alive(), "after shutdown the worker is gone");
    }

    /// A dead worker reports not-alive, and a send fails (not silently
    /// vanishes) while marking the defense disabled.
    #[test]
    fn worker_panic_is_detected_and_send_fails_loudly() {
        // Build a handle around a worker thread that dies immediately
        // (simulating a panic in the worker loop): its rx end drops on
        // unwind, exactly like a real panic in ScannerKillWorker::run.
        let (tx, rx) = crossbeam_channel::bounded::<KillRequest>(KILL_REQUEST_CAPACITY);
        let (_resp_tx, resp_rx) = crossbeam_channel::bounded::<KillResponse>(KILL_OUTCOME_CAPACITY);
        let thread = std::thread::Builder::new()
            .name("scanner-kill-test".to_string())
            .spawn(move || {
                let _owned = rx;
                panic!("simulated worker crash");
            })
            .expect("spawn");

        // Wait for the thread to finish dying.
        while !thread.is_finished() {
            std::thread::yield_now();
        }

        let mut handle = ScannerKillHandle {
            tx: Some(tx),
            resp_rx,
            thread: Some(thread),
            defense_disabled: AtomicBool::new(false),
            tally: Arc::new(KillTally::default()),
        };

        assert!(!handle.is_alive(), "dead worker must report not-alive");

        let result = handle.send_kill(KillRequest::SendResponse {
            dst_addr: localhost_v4(),
            dst_port: 5060,
            src_addr: localhost_v4(),
            src_port: 5060,
            response_bytes: sample_response(),
        });
        assert!(result.is_err(), "send to dead worker must fail, not vanish");
        assert!(
            handle.defense_disabled(),
            "failed send must mark the defense as disabled"
        );

        // shutdown() joins the panicked thread without propagating the panic.
        handle.shutdown();
    }

    /// A kill flood must never block the thread that reports the kill.
    ///
    /// `send_kill` is called from the packet loop while it holds the dialog
    /// and stream write locks, so anything that blocks it stops the capture
    /// AND every reader of those stores — the REST API, the TUI, and every
    /// MCP tool, not just the kill one.
    ///
    /// The block was two bounded channels deep, so this drives the real
    /// capacities rather than a shrunk stand-in: nothing in production drains
    /// the outcome channel, so the worker stalled publishing outcome
    /// `KILL_OUTCOME_CAPACITY + 1`, therefore stopped draining requests, the
    /// request queue filled behind it, and request
    /// `KILL_REQUEST_CAPACITY + KILL_OUTCOME_CAPACITY + 1` blocked forever.
    /// This test never reads the outcome channel — reproducing production
    /// exactly — and the flood is sized past both bounds. The producer runs on
    /// its own thread and reports back, so the assertion is a timeout and a
    /// regression fails instead of hanging CI.
    #[test]
    fn a_kill_flood_never_blocks_the_sender() {
        // Comfortably past request-capacity + outcome-capacity, so the stall
        // is reached even when the worker drains a good share on the way.
        let flood = 2 * (KILL_REQUEST_CAPACITY + KILL_OUTCOME_CAPACITY);
        // Never implicitly dropped: `Drop` calls `shutdown`, which joins the
        // worker, and `join` has no timeout — so a wedged worker would hang
        // the whole test binary during teardown instead of failing here. Only
        // the success path, which has just proved the worker is still
        // draining, shuts down.
        let handle = std::mem::ManuallyDrop::new(Arc::new(
            spawn_scanner_kill_worker(Some(u32::MAX), None, live_permit()).expect("spawn worker"),
        ));
        // One loopback destination: the per-destination limiter caps real
        // sends at 3/min, so exactly three datagrams reach 127.0.0.1 and every
        // other outcome is a rate-limit decision. Nothing leaves the host.
        let dst = localhost_v4();
        let producer = Arc::clone(&handle);
        let (done_tx, done_rx) = crossbeam_channel::bounded::<usize>(1);
        let flooder = std::thread::Builder::new()
            .name("kill-flood".to_string())
            .spawn(move || {
                let mut accepted = 0usize;
                for _ in 0..flood {
                    if producer
                        .send_kill(KillRequest::SendResponse {
                            dst_addr: dst,
                            dst_port: 59_999,
                            src_addr: dst,
                            src_port: 5060,
                            response_bytes: sample_response(),
                        })
                        .is_ok()
                    {
                        accepted += 1;
                    }
                }
                let _ = done_tx.send(accepted);
            })
            .expect("spawn flood producer");

        let accepted = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or_else(|_| {
                panic!(
                    "send_kill blocked: {flood} kill requests did not drain in 10s. \
                     The kill side channel has wedged its producer — in production \
                     that producer is the capture loop, holding the dialog and \
                     stream write locks, so the capture and every MCP tool stop \
                     with it."
                )
            });
        flooder.join().expect("flood producer must not panic");
        assert!(accepted > 0, "the flood must actually reach the worker");

        // The worker must still be draining. Nothing here reads the outcome
        // channel — production does not either — so a worker that waits to
        // publish an outcome stops taking requests altogether and the ledger
        // stops advancing. That is the wedge seen from the outside, and it is
        // what used to back up into the capture thread.
        let deadline = Instant::now() + std::time::Duration::from_secs(20);
        let counts = loop {
            let counts = handle.counts();
            if counts.outcomes() == accepted as u64 {
                break counts;
            }
            assert!(
                Instant::now() < deadline,
                "the worker stopped: only {} of {accepted} accepted requests \
                 became outcomes. It is stuck publishing an outcome that \
                 nothing is reading, which is where the capture thread ends up \
                 queued behind it. counts={counts:?}",
                counts.outcomes()
            );
            std::thread::yield_now();
        };

        // Nothing vanished: every request was either handed over or counted
        // as a deliberate drop. A `try_send` that dropped silently would trade
        // the hang for silent loss, which is the same class of bug.
        assert_eq!(
            accepted as u64 + counts.dropped_requests,
            flood as u64,
            "every offered request must be either accepted or counted as \
             dropped; accepted={accepted} counts={counts:?}"
        );

        // Only reached with a healthy worker, so this join cannot hang.
        drop(std::mem::ManuallyDrop::into_inner(handle));
    }

    /// Outcomes stay reachable when the observation channel overflows.
    ///
    /// The channel is a convenience stream; the tally is the record. Feeding
    /// twice the channel's capacity through a worker nobody is listening to
    /// must leave every outcome counted, with the exact shortfall attributed
    /// to the stream rather than lost.
    #[test]
    fn outcomes_are_counted_even_when_nothing_reads_the_stream() {
        let total = 2 * KILL_OUTCOME_CAPACITY;
        // Never implicitly dropped. `Drop` calls `shutdown`, which joins the
        // worker, and `join` has no timeout — so if this test ever fails
        // because the worker is wedged, unwinding would join a thread that
        // never returns and hang the whole test binary. Leaking the handle on
        // the failing path is what keeps the deadline below a *failure*
        // rather than a hang. The success path shuts down explicitly.
        let handle = std::mem::ManuallyDrop::new(
            spawn_scanner_kill_worker(Some(u32::MAX), None, live_permit()).expect("spawn worker"),
        );
        // A loopback destination distinct from the flood test's, so the two
        // do not share a per-destination bucket when run concurrently.
        let dst = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let deadline = Instant::now() + std::time::Duration::from_secs(20);

        // Retry a full queue rather than giving up, so all `total` requests
        // reach the worker and the arithmetic below is exact. (Production
        // never retries — one detected scanner is one offer — so the refusals
        // this loop provokes inflate `dropped_requests` here in a way a real
        // run's would not. `a_refused_request_is_counted_not_silently_dropped`
        // pins that counter down separately.)
        for i in 0..total {
            loop {
                match handle.send_kill(KillRequest::SendResponse {
                    dst_addr: dst,
                    dst_port: 59_998,
                    src_addr: dst,
                    src_port: 5060,
                    response_bytes: sample_response(),
                }) {
                    Ok(()) => break,
                    Err(TrySendError::Full(_)) => {
                        assert!(
                            Instant::now() < deadline,
                            "the worker stopped draining requests after {i} of {total} \
                             — it is stuck publishing an outcome nobody is reading"
                        );
                        std::thread::yield_now();
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        panic!("worker died after {i} of {total} requests")
                    }
                }
            }
        }

        // Every accepted request must land in exactly one outcome class, and
        // the stream's shortfall must be attributed rather than lost: the
        // channel holds the first `KILL_OUTCOME_CAPACITY` outcomes and the
        // rest are counted as unobserved.
        //
        // Waited for rather than sampled once. The worker books an outcome
        // and notes its unobservability as two relaxed atomic adds, so a
        // single snapshot taken between them is legitimately half-updated —
        // the invariant is eventual, and the deadline is what turns "never"
        // into a failure.
        let unobserved_expected = (total - KILL_OUTCOME_CAPACITY) as u64;
        let counts = loop {
            let counts = handle.counts();
            if counts.outcomes() == total as u64
                && counts.unobserved_outcomes == unobserved_expected
            {
                break counts;
            }
            assert!(
                Instant::now() < deadline,
                "the ledger never reconciled: expected {total} outcomes with \
                 {unobserved_expected} of them unobserved (the \
                 {KILL_OUTCOME_CAPACITY}-slot stream holds the rest), got \
                 {counts:?}"
            );
            std::thread::yield_now();
        };

        assert!(
            counts.any_dropped(),
            "an overflowing stream must be visible, not silent: {counts:?}"
        );

        // Only reached when the worker is healthy, so this join cannot hang.
        std::mem::ManuallyDrop::into_inner(handle).shutdown();
    }

    /// A request the worker has no room for is counted, not silently dropped.
    ///
    /// Trading a hang for silent loss is the same defect wearing a different
    /// hat, so the refusal has to leave a mark. Deterministic: a one-slot
    /// queue with nothing draining it takes exactly one request, and the two
    /// that follow are refused and counted.
    #[test]
    fn a_refused_request_is_counted_not_silently_dropped() {
        let (tx, rx) = crossbeam_channel::bounded::<KillRequest>(1);
        let (_resp_tx, resp_rx) = crossbeam_channel::bounded::<KillResponse>(KILL_OUTCOME_CAPACITY);
        // Hold the receiving end so the channel is full, not disconnected —
        // a full queue and a dead worker are different failures.
        let _rx = rx;
        let handle = Arc::new(ScannerKillHandle {
            tx: Some(tx),
            resp_rx,
            thread: None,
            defense_disabled: AtomicBool::new(false),
            tally: Arc::new(KillTally::default()),
        });

        // Offered from another thread behind a timeout: if `send_kill` ever
        // waits for a slot again, that wait is the capture thread's, so this
        // must fail rather than hang the suite.
        let offerer = Arc::clone(&handle);
        let (done_tx, done_rx) = crossbeam_channel::bounded::<usize>(1);
        std::thread::Builder::new()
            .name("kill-offer-test".to_string())
            .spawn(move || {
                let mut refused = 0usize;
                for _ in 0..3 {
                    let result = offerer.send_kill(KillRequest::SendResponse {
                        dst_addr: localhost_v4(),
                        dst_port: 59_996,
                        src_addr: localhost_v4(),
                        src_port: 5060,
                        response_bytes: sample_response(),
                    });
                    if matches!(result, Err(TrySendError::Full(_))) {
                        refused += 1;
                    }
                }
                let _ = done_tx.send(refused);
            })
            .expect("spawn offer thread");

        let refused = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect(
                "send_kill waited for a slot on a full queue instead of \
                 refusing — in production that wait is the capture thread's, \
                 taken while it holds the dialog and stream write locks",
            );
        assert_eq!(
            refused, 2,
            "the one free slot takes the first request; the next two must be \
             refused as Full, not reported as a dead worker"
        );

        let counts = handle.counts();
        assert_eq!(
            counts.dropped_requests, 2,
            "both refusals must be counted: {counts:?}"
        );
        assert!(
            counts.any_dropped(),
            "a dropped kill response must be visible: {counts:?}"
        );
        assert!(
            !handle.defense_disabled(),
            "a full queue is backpressure, not a dead worker — the defense is \
             still armed"
        );
    }

    /// `shutdown` returns even when the request queue is full.
    ///
    /// Now that `send_kill` never waits, the queue can still be full when the
    /// run ends, and the `Shutdown` message then does not fit. Shutdown must
    /// not wait for a slot (that is the blocking this type exists to avoid),
    /// so it drops the sender instead: the worker drains what is queued, sees
    /// a disconnected channel and exits. Keeping the sender alive after a
    /// failed ask would park the worker in `recv()` and this thread in
    /// `join()` forever.
    #[test]
    fn shutdown_returns_even_when_the_request_queue_is_full() {
        let (tx, rx) = crossbeam_channel::bounded::<KillRequest>(2);
        let (_resp_tx, resp_rx) = crossbeam_channel::bounded::<KillResponse>(KILL_OUTCOME_CAPACITY);
        // A worker that is not draining yet, so the queue is still full when
        // shutdown asks it to stop. It then drains until the channel is
        // disconnected — the same exit condition as the real worker loop.
        let thread = std::thread::Builder::new()
            .name("scanner-kill-slow-test".to_string())
            .spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                while rx.recv().is_ok() {}
            })
            .expect("spawn");
        for _ in 0..2 {
            tx.try_send(KillRequest::SendResponse {
                dst_addr: localhost_v4(),
                dst_port: 59_997,
                src_addr: localhost_v4(),
                src_port: 5060,
                response_bytes: sample_response(),
            })
            .expect("filling a 2-slot queue must succeed");
        }
        let mut handle = ScannerKillHandle {
            tx: Some(tx),
            resp_rx,
            thread: Some(thread),
            defense_disabled: AtomicBool::new(false),
            tally: Arc::new(KillTally::default()),
        };

        let (done_tx, done_rx) = crossbeam_channel::bounded::<()>(1);
        std::thread::Builder::new()
            .name("kill-shutdown-test".to_string())
            .spawn(move || {
                handle.shutdown();
                let _ = done_tx.send(());
            })
            .expect("spawn shutdown thread");

        done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect(
                "shutdown blocked with a full request queue: the worker never \
                 saw a disconnect, so it is parked in recv() and shutdown is \
                 parked in join()",
            );
    }

    /// `is_broadcast_or_multicast` classifies broadcast/multicast vs unicast.
    #[test]
    fn broadcast_multicast_detection() {
        assert!(is_broadcast_or_multicast(IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(is_broadcast_or_multicast(IpAddr::V4(Ipv4Addr::new(
            224, 0, 0, 1
        ))));
        assert!(is_broadcast_or_multicast(IpAddr::V6(Ipv6Addr::new(
            0xff02, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_broadcast_or_multicast(IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(!is_broadcast_or_multicast(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }
}
