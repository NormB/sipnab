// SPDX-License-Identifier: MIT OR Apache-2.0

//! A fired security alert must move `sipnab_security_alerts_total{type}`.
//!
//! `AlertEngine::fire` in `src/security/alerting.rs` is the single funnel every
//! detector's alert passes through, so the increment belongs there and nowhere
//! else — one call site rather than one per detector, which is what keeps a new
//! detector counted without anyone remembering to count it.
//!
//! WHERE IN `fire` MATTERS. The call sits past the threshold and the cooldown,
//! beside the `cooldowns.insert` that commits the firing, so the metric counts
//! alerts an operator actually saw and matches the `true` that `fire` returns.
//! Counting at entry would tally every suppressed repeat and make one noisy
//! source read as a storm — the opposite of what
//! `sipnab_security_alerts_total{type}` is for, and the same confusion #96
//! removed when 25,738 scanner alerts turned out to be 21.
//!
//! This test was `#[ignore]`d while the increment site sat in a file another
//! agent held, so the gap stayed visible in the tree rather than living in a
//! hand-off note. The call has landed and the attribute is gone.
#![cfg(feature = "native")]

use std::net::{IpAddr, Ipv4Addr};

use sipnab::output::prometheus::{PrometheusMetrics, format_metrics};
use sipnab::security::AlertEngine;

/// An alert that passes the cooldown is counted under its rule name and
/// reaches the exposition; one suppressed by the cooldown is not counted
/// again.
#[test]
fn firing_an_alert_moves_the_metric() {
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let mut engine = AlertEngine::new(vec![], None);
    let now = chrono::Utc::now();

    let before = sipnab::security::alerts_by_type()
        .into_iter()
        .find(|(k, _)| k == "scanner")
        .map_or(0, |(_, v)| v);

    assert!(engine.fire("scanner", ip, "probe", now));
    let metrics = PrometheusMetrics::for_scrape();
    assert_eq!(
        metrics.security_alerts_total.get("scanner").copied(),
        Some(before + 1),
        "a fired alert must be counted"
    );
    assert!(format_metrics(&metrics).contains(&format!(
        r#"sipnab_security_alerts_total{{type="scanner"}} {}"#,
        before + 1
    )));

    // Same source, same rule, inside the default 60-second cooldown:
    // suppressed, so the metric must not move again.
    assert!(!engine.fire("scanner", ip, "probe", now));
    assert_eq!(
        PrometheusMetrics::for_scrape()
            .security_alerts_total
            .get("scanner")
            .copied(),
        Some(before + 1),
        "a cooldown-suppressed alert must not be counted"
    );
}
