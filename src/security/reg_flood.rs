//! Registration flood detection.
//!
//! Tracks REGISTER request rates and authentication failure rates per source
//! IP to detect brute-force registration attacks. Alerts when the configured
//! threshold is exceeded within a one-second sliding window.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use crate::sip::SipMessage;

/// Default REGISTER-per-second threshold.
const DEFAULT_THRESHOLD: u32 = 50;

/// Per-source registration flood tracking state.
struct RegFloodState {
    /// Number of REGISTER requests in the current window.
    register_count: u32,
    /// Number of 401/407 responses (failed auth) in the current window.
    auth_fail_count: u32,
    /// Start of the current one-second measurement window.
    window_start: Instant,
}

/// Alert produced when a registration flood is detected.
#[derive(Debug, Clone)]
pub struct RegFloodAlert {
    /// Source IP address of the flood.
    pub src_ip: IpAddr,
    /// Number of REGISTER requests in the current window.
    pub register_count: u32,
    /// Number of authentication failures in the current window.
    pub auth_fail_count: u32,
    /// Configured threshold that was exceeded.
    pub threshold: u32,
}

/// Maximum entries in the sources map.
const MAX_SOURCE_ENTRIES: usize = 10_000;

/// Detects registration flood attacks by tracking per-source REGISTER rates.
pub struct RegFloodDetector {
    /// Per-source tracking state.
    sources: HashMap<IpAddr, RegFloodState>,
    /// REGISTER-per-second alert threshold.
    threshold: u32,
}

impl RegFloodDetector {
    /// Create a new registration flood detector with the given threshold.
    ///
    /// # Arguments
    ///
    /// * `threshold` — Maximum REGISTER requests per second before alerting.
    ///   Use `0` for the default threshold of 50/sec.
    pub fn new(threshold: u32) -> Self {
        Self {
            sources: HashMap::new(),
            threshold: if threshold == 0 {
                DEFAULT_THRESHOLD
            } else {
                threshold
            },
        }
    }

    /// Check a SIP message for registration flood conditions.
    ///
    /// Tracks REGISTER request rates per source IP and 401/407 response
    /// rates per destination IP (the source being probed). Returns an
    /// alert when the threshold is exceeded.
    #[must_use]
    pub fn check(&mut self, msg: &SipMessage) -> Option<RegFloodAlert> {
        let now = Instant::now();

        if msg.is_request && msg.method.as_deref() == Some("REGISTER") {
            // Cap the sources map to prevent memory exhaustion (H4)
            if self.sources.len() >= MAX_SOURCE_ENTRIES
                && !self.sources.contains_key(&msg.src_addr)
                && let Some(oldest_ip) = self
                    .sources
                    .iter()
                    .min_by_key(|(_, s)| s.window_start)
                    .map(|(&ip, _)| ip)
            {
                self.sources.remove(&oldest_ip);
            }

            let state = self.sources.entry(msg.src_addr).or_insert(RegFloodState {
                register_count: 0,
                auth_fail_count: 0,
                window_start: now,
            });

            // Reset window if more than 1 second has passed
            if now.duration_since(state.window_start).as_secs() >= 1 {
                state.register_count = 0;
                state.auth_fail_count = 0;
                state.window_start = now;
            }

            state.register_count += 1;

            if state.register_count > self.threshold {
                return Some(RegFloodAlert {
                    src_ip: msg.src_addr,
                    register_count: state.register_count,
                    auth_fail_count: state.auth_fail_count,
                    threshold: self.threshold,
                });
            }
        }

        // Track 401/407 failures — attribute to the destination (the target
        // being brute-forced is the original REGISTER sender, which is the
        // dst_addr of the response).
        if !msg.is_request
            && let Some(code) = msg.status_code
            && (code == 401 || code == 407)
        {
            let state = self.sources.entry(msg.dst_addr).or_insert(RegFloodState {
                register_count: 0,
                auth_fail_count: 0,
                window_start: now,
            });

            if now.duration_since(state.window_start).as_secs() >= 1 {
                state.register_count = 0;
                state.auth_fail_count = 0;
                state.window_start = now;
            }

            state.auth_fail_count += 1;
        }

        None
    }

    /// Remove tracking entries older than `max_age`.
    pub fn sweep(&mut self, max_age: std::time::Duration) {
        let now = Instant::now();
        self.sources
            .retain(|_, state| now.duration_since(state.window_start) < max_age);
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn attacker_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))
    }

    fn other_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100))
    }

    use crate::test_utils::build_sip_message as build_sip;

    fn make_register(src: IpAddr, call_id: &str) -> SipMessage {
        let raw = build_sip(
            "REGISTER sip:registrar@example.com SIP/2.0",
            &[
                "From: <sip:user@example.com>;tag=r1",
                "To: <sip:user@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 REGISTER",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, ts(), src, localhost(), 5060, 5060, "UDP").expect("parse")
    }

    #[test]
    fn flood_detected_above_threshold() {
        let mut detector = RegFloodDetector::new(50);

        // Send 60 REGISTERs from attacker — should trigger after 50
        let mut triggered = false;
        for i in 0..60 {
            let msg = make_register(attacker_ip(), &format!("flood-{i}@test"));
            if detector.check(&msg).is_some() {
                triggered = true;
            }
        }

        assert!(triggered, "should detect flood at 60 REGs/s (threshold 50)");
    }

    #[test]
    fn below_threshold_no_alert() {
        let mut detector = RegFloodDetector::new(50);

        // Send 40 REGISTERs — should not trigger
        for i in 0..40 {
            let msg = make_register(attacker_ip(), &format!("ok-{i}@test"));
            assert!(
                detector.check(&msg).is_none(),
                "should not alert at {i} REGs (threshold 50)"
            );
        }
    }

    #[test]
    fn different_sources_independent() {
        let mut detector = RegFloodDetector::new(50);

        // Send 30 from attacker_ip and 30 from other_ip — neither should trigger
        for i in 0..30 {
            let msg1 = make_register(attacker_ip(), &format!("src1-{i}@test"));
            assert!(detector.check(&msg1).is_none());

            let msg2 = make_register(other_ip(), &format!("src2-{i}@test"));
            assert!(detector.check(&msg2).is_none());
        }
    }

    #[test]
    fn auth_failure_tracking() {
        let mut detector = RegFloodDetector::new(50);

        // Send a REGISTER from attacker
        let reg = make_register(attacker_ip(), "auth-test@test");
        detector.check(&reg);

        // Send a 401 response back to the attacker
        let raw = build_sip(
            "SIP/2.0 401 Unauthorized",
            &[
                "From: <sip:user@example.com>;tag=r1",
                "To: <sip:user@example.com>;tag=r2",
                "Call-ID: auth-test@test",
                "CSeq: 1 REGISTER",
                "Content-Length: 0",
            ],
            b"",
        );
        let resp =
            parse_sip(&raw, ts(), localhost(), attacker_ip(), 5060, 5060, "UDP").expect("parse");
        detector.check(&resp);

        // Verify the attacker's state includes the auth failure
        let state = detector.sources.get(&attacker_ip()).expect("state exists");
        assert_eq!(state.auth_fail_count, 1, "should track auth failure");
    }

    #[test]
    fn default_threshold() {
        let detector = RegFloodDetector::new(0);
        assert_eq!(
            detector.threshold, DEFAULT_THRESHOLD,
            "threshold=0 should use default"
        );
    }

    #[test]
    fn alert_includes_counts() {
        let mut detector = RegFloodDetector::new(5);

        let mut alert = None;
        for i in 0..10 {
            let msg = make_register(attacker_ip(), &format!("count-{i}@test"));
            if let Some(a) = detector.check(&msg) {
                alert = Some(a);
            }
        }

        let alert = alert.expect("should have triggered");
        assert!(alert.register_count > 5);
        assert_eq!(alert.threshold, 5);
        assert_eq!(alert.src_ip, attacker_ip());
    }
}
