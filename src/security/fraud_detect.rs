//! Toll fraud detection heuristics for SIP traffic.
//!
//! Analyzes call patterns to detect common telecom fraud techniques:
//! - **Volume spikes** — sudden traffic bursts from a single source
//! - **Wangiri** — short-duration calls to premium/international numbers
//! - **Sequential scanning** — calls to consecutive number ranges
//! - **Off-hours** — calls placed outside configured business hours

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use chrono::Timelike;

use crate::sip::SipMessage;
use crate::sip::dialog::SipDialog;

/// Window for volume spike detection (seconds).
const VOLUME_WINDOW_SECS: u64 = 60;

/// Multiplier for volume spike detection: >5x the baseline rate.
const VOLUME_SPIKE_MULTIPLIER: u32 = 5;

/// Minimum calls before a volume spike can be detected.
const VOLUME_SPIKE_MIN_CALLS: u32 = 6;

/// Window for wangiri pattern detection (seconds).
const WANGIRI_WINDOW_SECS: u64 = 60;

/// Minimum short calls to same prefix for wangiri detection.
const WANGIRI_THRESHOLD: u32 = 3;

/// Call duration below which a call is considered "short" (seconds).
const SHORT_CALL_SECS: u64 = 3;

/// Minimum sequential numbers to trigger sequential scanning detection.
const SEQUENTIAL_THRESHOLD: usize = 3;

/// Per-source call tracking state.
struct CallPattern {
    /// Recent calls: (timestamp, destination number).
    calls: Vec<(Instant, String)>,
    /// Number of calls shorter than [`SHORT_CALL_SECS`].
    short_calls: u32,
    /// Baseline rate (calls per minute, rolling average).
    baseline_rate: f64,
}

/// Classification of detected fraud activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FraudType {
    /// Sudden volume increase from a single source.
    VolumeSpike,
    /// Short-duration calls to the same number prefix (premium fraud).
    Wangiri,
    /// Calls to sequential number ranges (toll fraud probing).
    SequentialScanning,
    /// Call placed outside configured business hours.
    OffHours,
}

/// Alert produced when fraud activity is detected.
#[derive(Debug, Clone)]
pub struct FraudAlert {
    /// Source IP address of the suspicious traffic.
    pub src_ip: IpAddr,
    /// Type of fraud detected.
    pub alert_type: FraudType,
    /// Human-readable description of the detection.
    pub detail: String,
}

/// Maximum entries in the call patterns map.
const MAX_PATTERN_ENTRIES: usize = 10_000;

/// Detects toll fraud patterns in SIP call traffic.
pub struct FraudDetector {
    /// Per-source call pattern tracking.
    call_patterns: HashMap<IpAddr, CallPattern>,
    /// Configured business hours as `(start_hour, end_hour)` in 24h format.
    /// `None` disables off-hours detection.
    business_hours: Option<(u8, u8)>,
}

impl FraudDetector {
    /// Create a new fraud detector.
    ///
    /// # Arguments
    ///
    /// * `business_hours` — Optional business hours as `(start_hour, end_hour)`
    ///   in 24-hour format. Calls outside this window trigger off-hours alerts.
    ///   For example, `Some((8, 18))` means 08:00-18:00.
    pub fn new(business_hours: Option<(u8, u8)>) -> Self {
        Self {
            call_patterns: HashMap::new(),
            business_hours,
        }
    }

    /// Check a SIP message and its associated dialog for fraud indicators.
    ///
    /// Only INVITE requests are analyzed. Returns the first matching fraud
    /// alert, or `None` if no fraud is detected.
    #[must_use]
    pub fn check(&mut self, msg: &SipMessage, dialog: &SipDialog) -> Option<FraudAlert> {
        // Only analyze INVITE requests
        if !msg.is_request || msg.method.as_deref() != Some("INVITE") {
            return None;
        }

        let destination = msg.to_user().unwrap_or_default();
        let now = Instant::now();

        // Cap the call patterns map to prevent memory exhaustion (H4)
        if self.call_patterns.len() >= MAX_PATTERN_ENTRIES
            && !self.call_patterns.contains_key(&msg.src_addr)
        {
            // Evict the entry with the oldest last call
            if let Some(oldest_ip) = self
                .call_patterns
                .iter()
                .min_by_key(|(_, p)| p.calls.first().map(|(t, _)| *t))
                .map(|(&ip, _)| ip)
            {
                self.call_patterns.remove(&oldest_ip);
            }
        }

        let pattern = self
            .call_patterns
            .entry(msg.src_addr)
            .or_insert(CallPattern {
                calls: Vec::new(),
                short_calls: 0,
                baseline_rate: 1.0,
            });

        // Record the call
        pattern.calls.push((now, destination.clone()));

        // Track short calls from dialog duration
        let duration = dialog
            .updated_at
            .signed_duration_since(dialog.created_at)
            .num_seconds()
            .unsigned_abs();
        if duration < SHORT_CALL_SECS {
            pattern.short_calls += 1;
        }

        // Prune calls outside the volume window
        pattern
            .calls
            .retain(|(t, _)| now.duration_since(*t).as_secs() <= VOLUME_WINDOW_SECS);

        // Off-hours detection
        if let Some((start, end)) = self.business_hours {
            let hour = msg.timestamp.hour() as u8;
            let outside = if start <= end {
                hour < start || hour >= end
            } else {
                // Wraps midnight: e.g., (22, 6) means 22:00-06:00 is business
                hour < start && hour >= end
            };
            if outside {
                return Some(FraudAlert {
                    src_ip: msg.src_addr,
                    alert_type: FraudType::OffHours,
                    detail: format!(
                        "call at {}:00 outside business hours ({start}:00-{end}:00)",
                        hour
                    ),
                });
            }
        }

        // Volume spike detection
        let current_count = pattern.calls.len() as u32;
        if current_count >= VOLUME_SPIKE_MIN_CALLS
            && current_count > (pattern.baseline_rate as u32) * VOLUME_SPIKE_MULTIPLIER
        {
            return Some(FraudAlert {
                src_ip: msg.src_addr,
                alert_type: FraudType::VolumeSpike,
                detail: format!(
                    "{current_count} calls in {VOLUME_WINDOW_SECS}s (baseline: {:.1}/min)",
                    pattern.baseline_rate
                ),
            });
        }

        // Wangiri detection: short calls to same prefix
        if let Some(alert) = check_wangiri(msg.src_addr, pattern) {
            return Some(alert);
        }

        // Sequential scanning detection
        if let Some(alert) = check_sequential(msg.src_addr, pattern) {
            return Some(alert);
        }

        // Update baseline (exponential moving average)
        pattern.baseline_rate = pattern.baseline_rate * 0.9 + current_count as f64 * 0.1;

        None
    }

    /// Remove call pattern entries older than `max_age`.
    pub fn sweep(&mut self, max_age: std::time::Duration) {
        let now = Instant::now();
        for pattern in self.call_patterns.values_mut() {
            pattern
                .calls
                .retain(|(t, _)| now.duration_since(*t) < max_age);
        }
        // Drop sources with no remaining calls
        self.call_patterns.retain(|_, p| !p.calls.is_empty());
    }
}

/// Check for wangiri pattern: multiple short calls to same number prefix.
fn check_wangiri(src_ip: IpAddr, pattern: &CallPattern) -> Option<FraudAlert> {
    if pattern.short_calls < WANGIRI_THRESHOLD {
        return None;
    }

    let now = Instant::now();

    // Group recent short-duration calls by prefix (first 6 digits)
    let mut prefix_counts: HashMap<&str, u32> = HashMap::new();
    for (t, dest) in &pattern.calls {
        if now.duration_since(*t).as_secs() <= WANGIRI_WINDOW_SECS {
            let prefix_len = dest.len().min(6);
            let prefix = &dest[..prefix_len];
            if !prefix.is_empty() {
                *prefix_counts.entry(prefix).or_insert(0) += 1;
            }
        }
    }

    for (prefix, count) in &prefix_counts {
        if *count > WANGIRI_THRESHOLD {
            return Some(FraudAlert {
                src_ip,
                alert_type: FraudType::Wangiri,
                detail: format!(
                    "{count} short calls to prefix '{prefix}' in {WANGIRI_WINDOW_SECS}s"
                ),
            });
        }
    }

    None
}

/// Check for sequential number scanning (N, N+1, N+2, ...).
fn check_sequential(src_ip: IpAddr, pattern: &CallPattern) -> Option<FraudAlert> {
    if pattern.calls.len() < SEQUENTIAL_THRESHOLD {
        return None;
    }

    // Extract numeric destinations and sort
    let mut numbers: Vec<u64> = pattern
        .calls
        .iter()
        .filter_map(|(_, dest)| {
            // Strip any leading '+' and parse as integer
            let cleaned: String = dest.chars().filter(|c| c.is_ascii_digit()).collect();
            cleaned.parse::<u64>().ok()
        })
        .collect();

    numbers.sort_unstable();
    numbers.dedup();

    if numbers.len() < SEQUENTIAL_THRESHOLD {
        return None;
    }

    // Look for runs of sequential numbers
    let mut run_length = 1_usize;
    for window in numbers.windows(2) {
        if window[1] == window[0] + 1 {
            run_length += 1;
            if run_length >= SEQUENTIAL_THRESHOLD {
                return Some(FraudAlert {
                    src_ip,
                    alert_type: FraudType::SequentialScanning,
                    detail: format!(
                        "sequential dialing detected: {run_length} consecutive numbers ending at {}",
                        window[1]
                    ),
                });
            }
        } else {
            run_length = 1;
        }
    }

    None
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::dialog::SipDialog;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn attacker_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))
    }

    fn ts() -> DateTime<Utc> {
        // Use a time that's within default business hours (14:00 UTC)
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 14, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    fn make_invite(to_user: &str, src: IpAddr, call_id: &str) -> SipMessage {
        let raw = build_sip(
            &format!("INVITE sip:{to_user}@example.com SIP/2.0"),
            &[
                "From: <sip:attacker@example.com>;tag=f1",
                &format!("To: <sip:{to_user}@example.com>"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, ts(), src, localhost(), 5060, 5060, "UDP").expect("should parse")
    }

    fn make_dialog_from_msg(msg: &SipMessage) -> SipDialog {
        SipDialog::new(msg).expect("should create dialog")
    }

    #[test]
    fn wangiri_pattern_detected() {
        let mut detector = FraudDetector::new(None);
        let src = attacker_ip();

        // Simulate 5 short calls to +44900xxx prefix
        let mut alert = None;
        for i in 0..5 {
            let dest = format!("+44900{i:03}");
            let call_id = format!("wangiri-{i}@test");
            let msg = make_invite(&dest, src, &call_id);
            let mut dialog = make_dialog_from_msg(&msg);
            // Make it a short call (< 3s)
            dialog.updated_at = dialog.created_at + TimeDelta::seconds(1);
            alert = detector.check(&msg, &dialog);
        }

        assert!(alert.is_some(), "should detect wangiri pattern");
        let alert = alert.unwrap();
        assert_eq!(alert.alert_type, FraudType::Wangiri);
        assert!(alert.detail.contains("short calls to prefix"));
    }

    #[test]
    fn sequential_scanning_detected() {
        let mut detector = FraudDetector::new(None);
        let src = attacker_ip();

        let mut alert = None;
        for i in 1..=5 {
            let dest = format!("+155500{i}");
            let call_id = format!("seq-{i}@test");
            let msg = make_invite(&dest, src, &call_id);
            let mut dialog = make_dialog_from_msg(&msg);
            // Give the dialog a non-short duration so it doesn't
            // trigger wangiri detection before sequential scanning
            dialog.updated_at = dialog.created_at + TimeDelta::seconds(30);
            alert = detector.check(&msg, &dialog);
        }

        assert!(alert.is_some(), "should detect sequential scanning");
        let alert = alert.unwrap();
        assert_eq!(alert.alert_type, FraudType::SequentialScanning);
        assert!(alert.detail.contains("sequential dialing"));
    }

    #[test]
    fn normal_call_pattern_not_detected() {
        let mut detector = FraudDetector::new(None);
        let src = attacker_ip();

        // Two normal calls to different destinations with realistic durations
        let msg1 = make_invite("+18005551234", src, "normal-1@test");
        let mut dialog1 = make_dialog_from_msg(&msg1);
        dialog1.updated_at = dialog1.created_at + TimeDelta::seconds(120);
        assert!(detector.check(&msg1, &dialog1).is_none());

        let msg2 = make_invite("+442071234567", src, "normal-2@test");
        let mut dialog2 = make_dialog_from_msg(&msg2);
        dialog2.updated_at = dialog2.created_at + TimeDelta::seconds(180);
        assert!(
            detector.check(&msg2, &dialog2).is_none(),
            "normal calls should not trigger fraud detection"
        );
    }

    #[test]
    fn off_hours_detection() {
        let mut detector = FraudDetector::new(Some((8, 18)));

        // Create a message at 03:00 (outside business hours)
        let raw = build_sip(
            "INVITE sip:+18005551234@example.com SIP/2.0",
            &[
                "From: <sip:caller@example.com>;tag=f1",
                "To: <sip:+18005551234@example.com>",
                "Call-ID: offhours@test",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let early_ts = chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 3, 0, 0).unwrap();
        let msg = parse_sip(
            &raw,
            early_ts,
            attacker_ip(),
            localhost(),
            5060,
            5060,
            "UDP",
        )
        .expect("parse");
        let dialog = make_dialog_from_msg(&msg);

        let alert = detector.check(&msg, &dialog);
        assert!(alert.is_some(), "should detect off-hours call");
        let alert = alert.unwrap();
        assert_eq!(alert.alert_type, FraudType::OffHours);
        assert!(alert.detail.contains("outside business hours"));
    }

    #[test]
    fn non_invite_ignored() {
        let mut detector = FraudDetector::new(None);
        let raw = build_sip(
            "REGISTER sip:registrar@example.com SIP/2.0",
            &[
                "From: <sip:user@example.com>;tag=r1",
                "To: <sip:user@example.com>",
                "Call-ID: reg@test",
                "CSeq: 1 REGISTER",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg =
            parse_sip(&raw, ts(), attacker_ip(), localhost(), 5060, 5060, "UDP").expect("parse");
        let dialog = make_dialog_from_msg(&msg);

        assert!(
            detector.check(&msg, &dialog).is_none(),
            "REGISTER should not trigger fraud detection"
        );
    }
}
