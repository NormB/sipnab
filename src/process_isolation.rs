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
use std::net::IpAddr;
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
    /// Response was successfully sent (or logged, before pcap injection is wired).
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
}

impl ScannerKillHandle {
    /// Send a kill request to the worker thread.
    ///
    /// Returns `Ok(())` if the request was queued. The actual send result
    /// can be retrieved via [`recv_response`](ScannerKillHandle::recv_response).
    pub fn send_kill(
        &self,
        request: KillRequest,
    ) -> Result<(), crossbeam_channel::SendError<KillRequest>> {
        self.tx.send(request)
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
            log::error!("Scanner-kill worker thread panicked: {e:?}");
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
/// limiting (both global and per-destination-IP), and (in future) injects
/// SIP responses via pcap.
struct ScannerKillWorker {
    rx: Receiver<KillRequest>,
    resp_tx: Sender<KillResponse>,
    rate_limiter: RateLimiter,
    per_dst_limiter: PerDstRateLimiter,
}

impl ScannerKillWorker {
    /// Run the worker loop until a `Shutdown` request is received or the
    /// channel disconnects.
    fn run(mut self) {
        log::info!(
            "Scanner-kill worker started (rate limit: {}/sec)",
            self.rate_limiter.max_per_second
        );

        loop {
            let request = match self.rx.recv() {
                Ok(req) => req,
                Err(_) => {
                    log::debug!("Scanner-kill channel disconnected, worker exiting");
                    break;
                }
            };

            match request {
                KillRequest::Shutdown => {
                    log::info!("Scanner-kill worker shutting down");
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
            log::warn!("Scanner-kill: {reason}");
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
            log::debug!("Scanner-kill: rate limited response to {dst_addr}:{dst_port}");
            return KillResponse::RateLimited;
        }

        // Apply per-destination-IP rate limit (M6: amplification mitigation)
        if !self.per_dst_limiter.allow(dst_addr) {
            log::debug!("Scanner-kill: per-destination rate limited for {dst_addr}:{dst_port}");
            return KillResponse::RateLimited;
        }

        // Periodic cleanup of per-dst limiter
        self.per_dst_limiter.cleanup();

        // Log the response (actual pcap injection is a future enhancement)
        log::info!(
            "Scanner-kill: would send {} byte response to {dst_addr}:{dst_port}",
            response_bytes.len(),
        );

        KillResponse::Sent
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

    let worker = ScannerKillWorker {
        rx,
        resp_tx,
        rate_limiter: RateLimiter::new(rate),
        per_dst_limiter: PerDstRateLimiter::new(),
    };

    let thread = std::thread::Builder::new()
        .name("scanner-kill".to_string())
        .spawn(move || worker.run())?;

    Ok(ScannerKillHandle {
        tx,
        resp_rx,
        thread: Some(thread),
    })
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

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

        // Give the worker a moment to process
        std::thread::sleep(std::time::Duration::from_millis(50));

        let resp = handle.try_recv_response();
        assert_eq!(resp, Some(KillResponse::Sent));

        handle.shutdown();
    }

    #[test]
    fn rate_limiter_enforces_limit() {
        let mut handle = spawn_scanner_kill_worker(Some(10)).expect("spawn worker");

        // Send 15 requests to different destination IPs so the per-dst
        // limiter doesn't interfere with the global rate limit test.
        for i in 0..15u8 {
            let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i.wrapping_add(1)));
            let _ = handle.send_kill(KillRequest::SendResponse {
                dst_addr: dst,
                dst_port: 5060,
                response_bytes: sample_response(),
            });
        }

        // Give the worker time to process all
        std::thread::sleep(std::time::Duration::from_millis(100));

        let mut sent_count = 0u32;
        let mut limited_count = 0u32;

        while let Some(resp) = handle.try_recv_response() {
            match resp {
                KillResponse::Sent => sent_count += 1,
                KillResponse::RateLimited => limited_count += 1,
                _ => {}
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

        std::thread::sleep(std::time::Duration::from_millis(50));

        let resp = handle.try_recv_response();
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

        std::thread::sleep(std::time::Duration::from_millis(50));

        let resp = handle.try_recv_response();
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

        std::thread::sleep(std::time::Duration::from_millis(50));

        let resp = handle.try_recv_response();
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

        std::thread::sleep(std::time::Duration::from_millis(50));

        let resp = handle.try_recv_response();
        assert!(
            matches!(resp, Some(KillResponse::Rejected { .. })),
            "empty response should be rejected"
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
