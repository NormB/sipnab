//! SIP scanner and reconnaissance tool detection.
//!
//! Detects SIP scanning activity through two methods:
//! - **User-Agent pattern matching** against known scanner signatures
//!   (friendly-scanner, sipvicious, etc.) and user-defined patterns.
//! - **Behavioral analysis** detecting high-rate REGISTER/OPTIONS probing
//!   from a single source without valid authentication.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use log;
use regex::{Regex, RegexBuilder};

use crate::sip::SipMessage;

/// Known SIP scanner User-Agent patterns (case-insensitive).
const KNOWN_SCANNER_PATTERNS: &[&str] = &[
    "friendly-scanner",
    "sipvicious",
    "sipcli",
    "sipsak",
    "sundayddr",
    "VaxSIPUserAgent",
    "sip-scan",
];

/// Number of requests from the same source within the behavioral window
/// that triggers a behavioral detection alert.
const BEHAVIORAL_THRESHOLD: u32 = 10;

/// Behavioral detection window in seconds.
const BEHAVIORAL_WINDOW_SECS: u64 = 5;

/// Tracks per-source behavioral state for probe detection.
struct BehavioralState {
    register_count: u32,
    options_count: u32,
    invite_count: u32,
    first_seen: Instant,
    last_seen: Instant,
}

/// Alert produced when scanner activity is detected.
#[derive(Debug, Clone)]
pub struct ScannerAlert {
    /// Source IP address of the scanner.
    pub src_ip: IpAddr,
    /// User-Agent string from the message (if present).
    pub ua: String,
    /// SIP method of the triggering message.
    pub method: String,
    /// How the scanner was detected: `"ua_pattern"` or `"behavioral"`.
    pub detection_method: String,
}

/// Maximum compiled regex size in bytes to prevent ReDoS.
const REGEX_SIZE_LIMIT: usize = 1_000_000;

/// Maximum entries in the behavioral tracking map.
const MAX_BEHAVIORAL_ENTRIES: usize = 10_000;

/// Detects SIP scanners via UA signature matching and behavioral heuristics.
pub struct ScannerDetector {
    /// Compiled regex patterns for known scanner User-Agents.
    known_patterns: Vec<Regex>,
    /// Per-source behavioral tracking state.
    behavioral: HashMap<IpAddr, BehavioralState>,
}

impl ScannerDetector {
    /// Create a new scanner detector.
    ///
    /// # Arguments
    ///
    /// * `custom_patterns` — Additional User-Agent regex patterns to match
    ///   (e.g., from `--kill-ua`). Invalid or oversized patterns are silently skipped.
    pub fn new(custom_patterns: &[String]) -> Self {
        let mut patterns = Vec::with_capacity(KNOWN_SCANNER_PATTERNS.len() + custom_patterns.len());

        // Compile built-in patterns (case-insensitive, size-limited)
        for pat in KNOWN_SCANNER_PATTERNS {
            if let Ok(re) = RegexBuilder::new(&format!("(?i){pat}"))
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
            {
                patterns.push(re);
            }
        }

        // Compile user-supplied patterns (size-limited to prevent ReDoS)
        for pat in custom_patterns {
            match RegexBuilder::new(&format!("(?i){pat}"))
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
            {
                Ok(re) => patterns.push(re),
                Err(e) => {
                    log::warn!("Skipping invalid or oversized --kill-ua pattern '{pat}': {e}");
                }
            }
        }

        Self {
            known_patterns: patterns,
            behavioral: HashMap::new(),
        }
    }

    /// Check a SIP message for scanner activity.
    ///
    /// Returns a [`ScannerAlert`] if the message matches a known scanner
    /// pattern or if the source IP's behavioral profile exceeds the
    /// probing threshold.
    pub fn check(&mut self, msg: &SipMessage) -> Option<ScannerAlert> {
        let method = if msg.is_request {
            msg.method.as_deref().unwrap_or("UNKNOWN")
        } else {
            return None; // Only check requests
        };

        let ua = msg.user_agent().unwrap_or("").to_string();

        // Check UA pattern match
        if !ua.is_empty() {
            for pattern in &self.known_patterns {
                if pattern.is_match(&ua) {
                    return Some(ScannerAlert {
                        src_ip: msg.src_addr,
                        ua,
                        method: method.to_string(),
                        detection_method: "ua_pattern".to_string(),
                    });
                }
            }
        }

        // Behavioral analysis: track REGISTER/OPTIONS/INVITE rates
        if matches!(method, "REGISTER" | "OPTIONS" | "INVITE") {
            let now = Instant::now();

            // Cap the behavioral map to prevent memory exhaustion (H4)
            if self.behavioral.len() >= MAX_BEHAVIORAL_ENTRIES
                && !self.behavioral.contains_key(&msg.src_addr)
            {
                // Evict the oldest entry by first_seen
                if let Some(oldest_ip) = self
                    .behavioral
                    .iter()
                    .min_by_key(|(_, s)| s.first_seen)
                    .map(|(&ip, _)| ip)
                {
                    self.behavioral.remove(&oldest_ip);
                }
            }

            let state = self
                .behavioral
                .entry(msg.src_addr)
                .or_insert(BehavioralState {
                    register_count: 0,
                    options_count: 0,
                    invite_count: 0,
                    first_seen: now,
                    last_seen: now,
                });

            // Reset window if expired
            if now.duration_since(state.first_seen).as_secs() > BEHAVIORAL_WINDOW_SECS {
                state.register_count = 0;
                state.options_count = 0;
                state.invite_count = 0;
                state.first_seen = now;
            }

            match method {
                "REGISTER" => state.register_count += 1,
                "OPTIONS" => state.options_count += 1,
                "INVITE" => state.invite_count += 1,
                _ => {}
            }
            state.last_seen = now;

            let probe_count = state.register_count + state.options_count;
            if probe_count > BEHAVIORAL_THRESHOLD {
                return Some(ScannerAlert {
                    src_ip: msg.src_addr,
                    ua,
                    method: method.to_string(),
                    detection_method: "behavioral".to_string(),
                });
            }
        }

        None
    }

    /// Remove behavioral tracking entries older than `max_age`.
    pub fn sweep(&mut self, max_age: std::time::Duration) {
        let now = std::time::Instant::now();
        self.behavioral
            .retain(|_, state| now.duration_since(state.last_seen) < max_age);
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn scanner_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))
    }

    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn build_sip(first_line: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(first_line.as_bytes());
        msg.extend_from_slice(b"\r\n");
        for h in headers {
            msg.extend_from_slice(h.as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        msg.extend_from_slice(body);
        msg
    }

    fn make_request_with_ua(method: &str, ua: &str, src: IpAddr) -> SipMessage {
        let raw = build_sip(
            &format!("{method} sip:target@example.com SIP/2.0"),
            &[
                "From: <sip:scanner@example.com>;tag=s1",
                "To: <sip:target@example.com>",
                "Call-ID: scan-test@example.com",
                &format!("CSeq: 1 {method}"),
                &format!("User-Agent: {ua}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, ts(), src, localhost(), 5060, 5060, "UDP").expect("should parse")
    }

    fn make_request_no_ua(method: &str, src: IpAddr, call_id: &str) -> SipMessage {
        let raw = build_sip(
            &format!("{method} sip:target@example.com SIP/2.0"),
            &[
                "From: <sip:scanner@example.com>;tag=s1",
                "To: <sip:target@example.com>",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: 1 {method}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, ts(), src, localhost(), 5060, 5060, "UDP").expect("should parse")
    }

    #[test]
    fn detect_friendly_scanner_ua() {
        let mut detector = ScannerDetector::new(&[]);
        let msg = make_request_with_ua("OPTIONS", "friendly-scanner", scanner_ip());

        let alert = detector.check(&msg);
        assert!(alert.is_some(), "should detect friendly-scanner");
        let alert = alert.unwrap();
        assert_eq!(alert.detection_method, "ua_pattern");
        assert_eq!(alert.ua, "friendly-scanner");
    }

    #[test]
    fn detect_sipvicious_ua() {
        let mut detector = ScannerDetector::new(&[]);
        let msg = make_request_with_ua("REGISTER", "sipvicious/0.3.4", scanner_ip());

        let alert = detector.check(&msg);
        assert!(alert.is_some(), "should detect sipvicious");
        let alert = alert.unwrap();
        assert_eq!(alert.detection_method, "ua_pattern");
    }

    #[test]
    fn normal_ua_not_detected() {
        let mut detector = ScannerDetector::new(&[]);
        let msg = make_request_with_ua("INVITE", "Oasis/4.0", localhost());

        let alert = detector.check(&msg);
        assert!(alert.is_none(), "normal UA should not trigger alert");
    }

    #[test]
    fn behavioral_detection_high_rate() {
        let mut detector = ScannerDetector::new(&[]);
        let src = scanner_ip();

        // Send 15 REGISTERs from same IP — should trigger after >10
        for i in 0..15 {
            let msg = make_request_no_ua("REGISTER", src, &format!("reg-{i}@test"));
            let alert = detector.check(&msg);
            if i > BEHAVIORAL_THRESHOLD as usize {
                assert!(
                    alert.is_some(),
                    "should detect behavioral scanning at message {i}"
                );
                if let Some(a) = alert {
                    assert_eq!(a.detection_method, "behavioral");
                }
            }
        }
    }

    #[test]
    fn custom_kill_ua_detected() {
        let custom = vec!["my-scanner".to_string()];
        let mut detector = ScannerDetector::new(&custom);
        let msg = make_request_with_ua("OPTIONS", "my-scanner/1.0", scanner_ip());

        let alert = detector.check(&msg);
        assert!(alert.is_some(), "should detect custom --kill-ua pattern");
        let alert = alert.unwrap();
        assert_eq!(alert.detection_method, "ua_pattern");
    }

    #[test]
    fn response_messages_ignored() {
        let mut detector = ScannerDetector::new(&[]);
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: resp-test@example.com",
                "CSeq: 1 OPTIONS",
                "User-Agent: friendly-scanner",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg =
            parse_sip(&raw, ts(), scanner_ip(), localhost(), 5060, 5060, "UDP").expect("parse");
        assert!(
            detector.check(&msg).is_none(),
            "responses should not trigger scanner alerts"
        );
    }
}
