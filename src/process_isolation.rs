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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::Instant;

use crossbeam_channel::{Receiver, Sender};
use serde::{Deserialize, Serialize};

/// Message types sent from the main thread to the scanner-kill worker.
#[derive(Debug, Serialize, Deserialize)]
pub enum KillRequest {
    /// Request to send a SIP response to a scanner.
    SendResponse {
        /// Destination IP address.
        dst_addr: IpAddr,
        /// Destination transport port.
        dst_port: u16,
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
/// Sending a [`KillRequest`] queues it for the worker thread. Call
/// [`shutdown`](ScannerKillHandle::shutdown) to cleanly stop the worker.
pub struct ScannerKillHandle {
    tx: Sender<KillRequest>,
    resp_rx: Receiver<KillResponse>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// Set on the first failed send so a dead worker is reported exactly
    /// once, loudly, instead of every kill attempt silently vanishing.
    defense_disabled: std::sync::atomic::AtomicBool,
}

impl ScannerKillHandle {
    /// Send a kill request to the worker thread.
    ///
    /// Returns `Ok(())` if the request was queued. The actual send result
    /// can be retrieved via [`recv_response`](ScannerKillHandle::recv_response).
    ///
    /// If the worker thread has died (panic or unexpected exit), the send
    /// fails, an error is logged once, and [`defense_disabled`]
    /// (ScannerKillHandle::defense_disabled) reports `true` from then on —
    /// the kill defense is gone for the rest of the run.
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

/// Token-bucket rate limiter for scanner-kill responses.
///
/// Limits the number of responses sent per second to prevent the kill
/// mechanism from becoming an amplification vector.
struct RateLimiter {
    max_per_second: u32,
    count_this_window: u32,
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
}

/// Maximum responses per destination IP per minute.
const MAX_PER_DST_PER_MINUTE: u32 = 3;

impl PerDstRateLimiter {
    fn new() -> Self {
        Self {
            buckets: HashMap::new(),
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

    /// Remove entries older than 2 minutes to prevent memory growth.
    fn cleanup(&mut self) {
        let now = Instant::now();
        self.buckets
            .retain(|_, (start, _)| now.duration_since(*start).as_secs() < 120);
    }
}

/// Scanner-kill worker that runs in a dedicated thread.
///
/// Receives [`KillRequest`]s via channel, validates them, applies rate
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
    rx: Receiver<KillRequest>,
    resp_tx: Sender<KillResponse>,
    rate_limiter: RateLimiter,
    per_dst_limiter: PerDstRateLimiter,
    /// UDP socket for IPv4 destinations (bound to `0.0.0.0:0`); `None` if the
    /// bind failed at spawn.
    sock_v4: Option<UdpSocket>,
    /// UDP socket for IPv6 destinations (bound to `[::]:0`); `None` if the
    /// bind failed at spawn.
    sock_v6: Option<UdpSocket>,
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
                    response_bytes,
                } => {
                    let response = self.process_send(dst_addr, dst_port, &response_bytes);
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

        // Periodic cleanup of per-dst limiter
        self.per_dst_limiter.cleanup();

        // Transmit the response to the scanner over UDP.
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
/// requests are sent via the returned [`ScannerKillHandle`]. The worker
/// validates destinations (rejecting broadcast/multicast), applies rate
/// limiting (both global and per-destination-IP), and logs responses.
///
/// # Arguments
///
/// * `rate_limit` — Maximum responses per second. Pass `None` for the
///   default of 10/sec.
///
/// # Errors
///
/// Returns an error if the worker thread cannot be spawned.
pub fn spawn_scanner_kill_worker(
    rate_limit: Option<u32>,
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

    fn localhost_v4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn sample_response() -> Vec<u8> {
        b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()
    }

    #[test]
    fn handle_send_and_receive() {
        let mut handle = spawn_scanner_kill_worker(Some(10)).expect("spawn worker");

        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: localhost_v4(),
                dst_port: 5060,
                response_bytes: sample_response(),
            })
            .expect("send should succeed");

        let resp = recv_response_within(&handle, std::time::Duration::from_secs(5));
        assert_eq!(resp, Some(KillResponse::Sent));

        handle.shutdown();
    }

    #[test]
    fn rate_limiter_enforces_limit() {
        let mut handle = spawn_scanner_kill_worker(Some(10)).expect("spawn worker");

        // Send 15 requests to different destination IPs so the per-dst
        // limiter doesn't interfere with the global rate limit test. Loopback
        // (127.0.0.0/8) so the now-real UDP send never leaves the host.
        for i in 0..15u8 {
            let dst = IpAddr::V4(Ipv4Addr::new(127, 0, 0, i.wrapping_add(1)));
            let _ = handle.send_kill(KillRequest::SendResponse {
                dst_addr: dst,
                dst_port: 5060,
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

    #[test]
    fn broadcast_address_rejected() {
        let mut handle = spawn_scanner_kill_worker(Some(10)).expect("spawn worker");

        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: IpAddr::V4(Ipv4Addr::BROADCAST),
                dst_port: 5060,
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

    #[test]
    fn multicast_v4_rejected() {
        let mut handle = spawn_scanner_kill_worker(Some(10)).expect("spawn worker");

        // 224.0.0.1 is multicast
        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
                dst_port: 5060,
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

    #[test]
    fn multicast_v6_rejected() {
        let mut handle = spawn_scanner_kill_worker(Some(10)).expect("spawn worker");

        // ff02::1 is IPv6 multicast
        let multicast_v6 = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: multicast_v6,
                dst_port: 5060,
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

    #[test]
    fn shutdown_exits_cleanly() {
        let mut handle = spawn_scanner_kill_worker(Some(10)).expect("spawn worker");
        handle.shutdown();
        // No panic, thread joined successfully
    }

    #[test]
    fn empty_response_rejected() {
        let mut handle = spawn_scanner_kill_worker(Some(10)).expect("spawn worker");

        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: localhost_v4(),
                dst_port: 5060,
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

    #[test]
    fn process_send_actually_transmits_over_udp() {
        // The worker must put the response bytes on the wire, not just log
        // them. Bind a real UDP listener and assert it receives the datagram.
        let listener = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind listener");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let port = listener.local_addr().expect("local addr").port();

        let mut handle = spawn_scanner_kill_worker(Some(10)).expect("spawn worker");
        let payload = b"SIP/2.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: localhost_v4(),
                dst_port: port,
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

    #[test]
    fn transmits_response_bytes_verbatim_including_nul() {
        // Adversarial: response bytes carrying embedded NUL and high bytes
        // must be delivered verbatim — no truncation, no re-encoding.
        let listener = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind listener");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        let port = listener.local_addr().expect("local addr").port();

        let mut handle = spawn_scanner_kill_worker(Some(10)).expect("spawn worker");
        let payload = vec![
            0x00u8, 0xff, b'S', b'I', b'P', b'\\', 0x0d, 0x0a, 0x00, 0x80, 0x7f,
        ];
        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: localhost_v4(),
                dst_port: port,
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

    #[test]
    fn rate_limiter_unit_allows_within_limit() {
        let mut limiter = RateLimiter::new(5);
        for _ in 0..5 {
            assert!(limiter.allow());
        }
        assert!(!limiter.allow(), "6th request should be rejected");
    }

    #[test]
    fn is_alive_true_for_running_worker() {
        let mut handle = spawn_scanner_kill_worker(Some(10)).expect("spawn worker");
        assert!(handle.is_alive(), "freshly spawned worker must be alive");
        assert!(!handle.defense_disabled());
        handle.shutdown();
        assert!(!handle.is_alive(), "after shutdown the worker is gone");
    }

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
