// SPDX-License-Identifier: MIT OR Apache-2.0

//! VoIP security detection: SIP scanner detection, toll fraud, registration
//! flooding, digest credential leaks, and alerting.
//!
//! This module provides real-time detection of SIP security threats including
//! scanner reconnaissance, toll fraud patterns, digest authentication
//! vulnerabilities, registration floods, and a rule-based alerting engine.

pub mod alerting;
pub mod digest_leak;
pub mod fraud_detect;
pub mod kill_packet;
pub mod reg_flood;
pub mod scanner_detect;
pub mod scanner_kill;
pub mod sources;
// Names `capture::CaptureSource`, which exists only in native builds; gated to
// match `crate::process_isolation`, the module whose sends it guards.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod transmit_guard;

pub use alerting::{AlertEngine, AlertRule};
pub use digest_leak::{DigestAlert, DigestLeakDetector, DigestVulnerability};
pub use fraud_detect::{FraudAlert, FraudDetector, FraudType};
pub use reg_flood::{RegFloodAlert, RegFloodDetector};
pub use scanner_detect::{ScannerAlert, ScannerDetector};

// ── Alert counter ─────────────────────────────────────────────────────

/// Alerts emitted since the process started, keyed by the rule name that
/// fired — the source of `sipnab_security_alerts_total{type}`.
///
/// A `BTreeMap` so the scrape reads label values already in a stable order,
/// and process-global for the same reason the capture counter is: the
/// alerting engine lives on the capture thread while the scrape runs on a
/// server thread, and neither owns the other.
static ALERTS_BY_TYPE: parking_lot::Mutex<std::collections::BTreeMap<String, u64>> =
    parking_lot::Mutex::new(std::collections::BTreeMap::new());

/// Cap on distinct rule names tracked, plus one slot for the overflow
/// bucket.
///
/// Rule names come from `--alert-rule` and the built-in detectors, so the
/// real set is small; the cap exists so a caller that ever derives a name
/// from packet data cannot turn a metric label into unbounded memory (and
/// unbounded scrape cardinality). Alerts beyond the cap still count, under
/// [`OVERFLOW_ALERT_TYPE`], rather than being dropped silently.
const MAX_ALERT_TYPES: usize = 128;

/// Label the counter uses once [`MAX_ALERT_TYPES`] distinct rule names have
/// been seen. A visible bucket beats a silent drop: the total stays right
/// even when the breakdown cannot.
const OVERFLOW_ALERT_TYPE: &str = "other";

/// Count one emitted security alert under the rule that fired.
///
/// Call this where the alert is actually emitted — after the alerting
/// engine's cooldown check — so the metric counts alerts an operator saw,
/// not detections that were deduplicated away.
///
/// # Arguments
///
/// * `alert_type` — the rule name (`scanner`, `fraud`, `reg_flood`, …).
///
/// # Side effects
///
/// Increments the process-wide per-type alert counter read by
/// [`alerts_by_type`], and so by the next `/metrics` scrape.
pub fn record_alert(alert_type: &str) {
    record_into(&mut ALERTS_BY_TYPE.lock(), alert_type);
}

/// Counting rule behind [`record_alert`], over a caller-supplied map so the
/// cap and the overflow bucket are testable without touching the global one.
///
/// # Arguments
///
/// * `counts` — the per-type counter map to update.
/// * `alert_type` — the rule name that fired.
fn record_into(counts: &mut std::collections::BTreeMap<String, u64>, alert_type: &str) {
    if let Some(count) = counts.get_mut(alert_type) {
        *count = count.saturating_add(1);
    } else if counts.len() < MAX_ALERT_TYPES {
        counts.insert(alert_type.to_string(), 1);
    } else {
        let overflow = counts.entry(OVERFLOW_ALERT_TYPE.to_string()).or_insert(0);
        *overflow = overflow.saturating_add(1);
    }
}

/// Alerts emitted since start, by rule name, in label order.
///
/// # Returns
///
/// `(rule name, count)` pairs; empty when no alert has fired.
pub fn alerts_by_type() -> Vec<(String, u64)> {
    ALERTS_BY_TYPE
        .lock()
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect()
}

/// Tests for the per-type alert counter's cap and overflow bucket.
#[cfg(test)]
mod tests {
    use super::*;

    /// A recorded alert appears under its own rule name and accumulates.
    #[test]
    fn record_alert_counts_per_type() {
        let kind = "security_mod_test_rule";
        let before = alerts_by_type()
            .into_iter()
            .find(|(k, _)| k == kind)
            .map_or(0, |(_, v)| v);

        record_alert(kind);
        record_alert(kind);

        let after = alerts_by_type()
            .into_iter()
            .find(|(k, _)| k == kind)
            .map_or(0, |(_, v)| v);
        assert_eq!(after, before + 2, "two alerts of one type count twice");
    }

    /// Past the distinct-type cap, alerts land in the overflow bucket instead
    /// of growing the label set without bound.
    ///
    /// Driven through `record_into` on a local map: filling the global one
    /// would leave every later test in this binary counting into the
    /// overflow bucket.
    #[test]
    fn distinct_types_are_capped_with_an_overflow_bucket() {
        let mut counts = std::collections::BTreeMap::new();
        for i in 0..(MAX_ALERT_TYPES * 2) {
            record_into(&mut counts, &format!("cap_probe_{i}"));
        }

        assert!(
            counts.len() <= MAX_ALERT_TYPES + 1,
            "label set must stay bounded (the cap plus the overflow bucket), \
             saw {} types",
            counts.len()
        );
        assert_eq!(
            counts.get(OVERFLOW_ALERT_TYPE).copied(),
            Some(MAX_ALERT_TYPES as u64),
            "every alert past the cap must be counted under `{OVERFLOW_ALERT_TYPE}`"
        );
    }
}
