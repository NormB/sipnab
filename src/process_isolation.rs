// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process isolation for dangerous operations (D16).
//!
//! Provides thread-based isolation for scanner-kill and API operations.
//! The scanner-kill worker runs in a dedicated thread with its own rate
//! limiter, receiving kill requests via a crossbeam channel. This limits
//! blast radius: a bug in the kill path cannot corrupt the main capture
//! pipeline or dialog tracking state.
//!
//! Future enhancement: replace threads with `fork()`/`Command` for true
//! process-level isolation with separate address spaces.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, UdpSocket};
use std::time::Instant;

use crossbeam_channel::{Receiver, Sender};
use serde::{Deserialize, Serialize};

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
    #[cfg(target_os = "linux")]
    fn send_to_v4(&self, packet: &[u8], dst: SocketAddrV4) -> std::io::Result<usize> {
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
    /// source) to `dst`.
    #[cfg(target_os = "linux")]
    fn send_to_v6(&self, packet: &[u8], dst: std::net::SocketAddrV6) -> std::io::Result<usize> {
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
    fn send_to_v4(&self, _packet: &[u8], _dst: SocketAddrV4) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "raw-socket send is only supported on Linux",
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn send_to_v6(&self, _packet: &[u8], _dst: std::net::SocketAddrV6) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "raw-socket send is only supported on Linux",
        ))
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

/// Handle for the main thread to communicate with the scanner-kill worker.
///
/// Sending a `KillRequest` queues it for the worker thread. Call
/// `shutdown` to cleanly stop the worker.
pub struct ScannerKillHandle {
    /// Channel to queue kill requests for the worker thread.
    tx: Sender<KillRequest>,
    /// Channel of per-request outcomes sent back by the worker.
    resp_rx: Receiver<KillResponse>,
    /// Join handle for the worker thread; taken on shutdown.
    thread: Option<std::thread::JoinHandle<()>>,
    /// Set on the first failed send so a dead worker is reported exactly
    /// once, loudly, instead of every kill attempt silently vanishing.
    defense_disabled: std::sync::atomic::AtomicBool,
}

impl ScannerKillHandle {
    /// Send a kill request to the worker thread.
    ///
    /// Returns `Ok(())` if the request was queued. The actual send result
    /// can be retrieved via `recv_response`.
    ///
    /// If the worker thread has died (panic or unexpected exit), the send
    /// fails, an error is logged once, and `defense_disabled` reports `true`
    /// from then on — the kill defense is gone for the rest of the run.
    pub fn send_kill(
        &self,
        request: KillRequest,
    ) -> Result<(), crossbeam_channel::SendError<KillRequest>> {
        let result = self.tx.send(request);
        if result.is_err()
            && !self
                .defense_disabled
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::error!(
                "scanner-kill worker thread is dead (panicked or exited \
                 unexpectedly); the --kill-scanner defense is DISABLED for \
                 the rest of this run — scanners will be detected but no \
                 longer answered"
            );
        }
        result
    }

    /// Whether the worker thread is still running.
    pub fn is_alive(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// Whether the kill defense has been marked dead (a send failed because
    /// the worker exited). Once true, stays true.
    pub fn defense_disabled(&self) -> bool {
        self.defense_disabled
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Try to receive a response from the worker (non-blocking).
    pub fn try_recv_response(&self) -> Option<KillResponse> {
        self.resp_rx.try_recv().ok()
    }

    /// Shut down the worker thread and wait for it to exit.
    pub fn shutdown(&mut self) {
        // Send shutdown request (ignore error if channel is already closed)
        let _ = self.tx.send(KillRequest::Shutdown);
        if let Some(handle) = self.thread.take()
            && let Err(e) = handle.join()
        {
            tracing::error!("Scanner-kill worker thread panicked: {e:?}");
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
/// `MAX_PER_DST_PER_MINUTE` within a sliding one-minute window.
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
    /// Outbound channel of per-request outcomes back to the main thread.
    resp_tx: Sender<KillResponse>,
    /// Global responses-per-second limiter.
    rate_limiter: RateLimiter,
    /// Per-destination-IP limiter (amplification mitigation).
    per_dst_limiter: PerDstRateLimiter,
    /// UDP socket for IPv4 destinations (bound to `0.0.0.0:0`); `None` if the
    /// bind failed at spawn.
    sock_v4: Option<UdpSocket>,
    /// UDP socket for IPv6 destinations (bound to `[::]:0`); `None` if the
    /// bind failed at spawn.
    sock_v6: Option<UdpSocket>,
    /// Raw socket for source-spoofed IPv4 responses, opened privileged and
    /// moved in at spawn. `None` → the ephemeral UDP send is used.
    raw_sock: Option<RawKillSocket>,
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
                    // Best-effort send of response; ignore if main thread dropped its end
                    let _ = self.resp_tx.send(response);
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
                        .map(|pkt| raw.send_to_v4(&pkt, dst))
                }
                (IpAddr::V6(dst_v6), IpAddr::V6(src_v6)) => {
                    let dst = std::net::SocketAddrV6::new(dst_v6, dst_port, 0, 0);
                    let src = std::net::SocketAddrV6::new(src_v6, src_port, 0, 0);
                    crate::security::kill_packet::build_ipv6_udp(src, dst, response_bytes)
                        .map(|pkt| raw.send_to_v6(&pkt, dst))
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
        match sock.send_to(response_bytes, (dst_addr, dst_port)) {
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
///
/// # Errors
///
/// Returns an error if the worker thread cannot be spawned.
pub fn spawn_scanner_kill_worker(
    rate_limit: Option<u32>,
    raw_sock: Option<RawKillSocket>,
) -> Result<ScannerKillHandle, std::io::Error> {
    let rate = rate_limit.unwrap_or(DEFAULT_RATE_LIMIT);
    let (tx, rx) = crossbeam_channel::bounded(256);
    let (resp_tx, resp_rx) = crossbeam_channel::bounded(256);

    // Bind the send sockets once, up front. Either family may be unavailable
    // (e.g. no IPv6 stack); a destination whose family has no socket is
    // reported as an error at send time rather than silently dropped.
    let sock_v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok();
    let sock_v6 = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).ok();
    if sock_v4.is_none() && sock_v6.is_none() {
        tracing::error!(
            "Scanner-kill: could not bind any UDP send socket; kill responses will error"
        );
    }

    let worker = ScannerKillWorker {
        rx,
        resp_tx,
        rate_limiter: RateLimiter::new(rate),
        per_dst_limiter: PerDstRateLimiter::new(),
        sock_v4,
        sock_v6,
        raw_sock,
    };

    let thread = std::thread::Builder::new()
        .name("scanner-kill".to_string())
        .spawn(move || worker.run())?;

    Ok(ScannerKillHandle {
        tx,
        resp_rx,
        thread: Some(thread),
        defense_disabled: std::sync::atomic::AtomicBool::new(false),
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

        let mut handle = spawn_scanner_kill_worker(Some(10), Some(raw)).expect("spawn worker");
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

        let mut handle = spawn_scanner_kill_worker(Some(10), Some(raw)).expect("spawn worker");
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
        let mut handle = spawn_scanner_kill_worker(Some(10), None).expect("spawn worker");

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
        let mut handle = spawn_scanner_kill_worker(Some(10), None).expect("spawn worker");

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
        let mut handle = spawn_scanner_kill_worker(Some(10), None).expect("spawn worker");

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
        let mut handle = spawn_scanner_kill_worker(Some(10), None).expect("spawn worker");

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
        let mut handle = spawn_scanner_kill_worker(Some(10), None).expect("spawn worker");

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
        let mut handle = spawn_scanner_kill_worker(Some(10), None).expect("spawn worker");
        handle.shutdown();
        // No panic, thread joined successfully
    }

    /// An empty response body is rejected.
    #[test]
    fn empty_response_rejected() {
        let mut handle = spawn_scanner_kill_worker(Some(10), None).expect("spawn worker");

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

        let mut handle = spawn_scanner_kill_worker(Some(10), None).expect("spawn worker");
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

        let mut handle = spawn_scanner_kill_worker(Some(10), None).expect("spawn worker");
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
        let mut handle = spawn_scanner_kill_worker(Some(10), None).expect("spawn worker");
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
        let (tx, rx) = crossbeam_channel::bounded::<KillRequest>(256);
        let (_resp_tx, resp_rx) = crossbeam_channel::bounded::<KillResponse>(256);
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
            tx,
            resp_rx,
            thread: Some(thread),
            defense_disabled: std::sync::atomic::AtomicBool::new(false),
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
