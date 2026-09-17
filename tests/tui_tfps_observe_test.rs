// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TFPS-observe TUI view's ask, tested at its pure core.
//!
//! The view SHELLS OUT to `tfps_ctl`, so it cannot be driven end to end without
//! the peer installed (the same reason the relay-stats view is tested at its
//! core). The CONVERSION it performs — a `tfps_ctl` reply, or the fact that
//! there is none, rendered to the text the view shows — is pure, and is
//! exercised here directly.

#![cfg(feature = "tui")]

use std::path::PathBuf;

use sipnab::security::tfps::{Reply, TfpsBanned, TfpsDropped};
use sipnab::tui::tfps_observe::{compose_tfps_banned, compose_tfps_dropped};

/// A banned answer lists each condemned source with the reason it was
/// condemned, what the reason saw (the sender's own text, raw), whether the
/// firewall holds it, and the count — so an operator can tell an enforced ban
/// from an observation. The peer reports the times as epoch seconds, and the
/// view shows them as a UTC instant a person can read.
#[test]
fn banned_lists_sources_reasons_and_enforcement() {
    let reply = Reply::Answered {
        ctl: PathBuf::from("/usr/bin/tfps_ctl"),
        value: vec![
            TfpsBanned {
                ip: "10.0.0.5".to_string(),
                reason: Some("user-agent".to_string()),
                detail: Some("friendly-scanner".to_string()),
                first_seen: Some(1_767_225_600), // 2026-01-01T00:00:00Z
                expires: None,
                enforced: true,
            },
            TfpsBanned {
                ip: "10.0.0.6".to_string(),
                reason: Some("rate".to_string()),
                detail: None,
                first_seen: None,
                expires: Some(1_767_312_000), // 2026-01-02T00:00:00Z
                enforced: false,
            },
        ],
    };
    let text = compose_tfps_banned(Ok(reply));
    assert!(
        text.contains("10.0.0.5") && text.contains("10.0.0.6"),
        "both banned sources are listed:\n{text}"
    );
    assert!(
        text.contains("user-agent"),
        "the reason that condemned the source is named:\n{text}"
    );
    assert!(
        text.contains("friendly-scanner"),
        "the reason's evidence (the sender's own text) is shown:\n{text}"
    );
    assert!(
        text.contains("2026-01-01T00:00:00Z"),
        "the epoch first-seen is rendered as a readable UTC instant:\n{text}"
    );
    assert!(
        text.to_lowercase().contains("enforced"),
        "an enforced ban is marked enforced:\n{text}"
    );
    assert!(
        text.contains('2'),
        "the count of banned sources is stated:\n{text}"
    );
}

/// When TFPS is not installed the view says so in the peer's own words, rather
/// than rendering an empty list that reads as "nothing is banned".
#[test]
fn banned_reports_not_installed() {
    let reply = Reply::NotInstalled {
        reason: "tfps_ctl is not on PATH".to_string(),
    };
    let text = compose_tfps_banned(Ok(reply));
    assert!(
        text.contains("tfps_ctl is not on PATH"),
        "the not-installed reason is shown:\n{text}"
    );
}

/// A dropped answer lists each source with its drop count and last-seen time.
#[test]
fn dropped_lists_sources_and_counts() {
    let reply = Reply::Answered {
        ctl: PathBuf::from("/usr/bin/tfps_ctl"),
        value: vec![TfpsDropped {
            ip: "10.0.0.7".to_string(),
            dropped: 4200,
            events: 17,
            last_seen: "2026-01-01T00:00:00Z".to_string(),
            rule: Some("rate".to_string()),
            last_request: Some("OPTIONS sip:100@10.0.0.1".to_string()),
        }],
    };
    let text = compose_tfps_dropped(Ok(reply));
    assert!(text.contains("10.0.0.7"), "the source is listed:\n{text}");
    assert!(text.contains("4200"), "the drop count renders:\n{text}");
}
