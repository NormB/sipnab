// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which sources this capture accused, and of what (BA1).
//!
//! [`ScannerDetector`](super::ScannerDetector) and the other detectors answer
//! per message: this request, from this address, tripped this rule. That is
//! the right shape for a live gate — `--kill-scanner` acts on one packet — and
//! the wrong shape for the question an operator asks after the fact, which is
//! *who is probing me, and how do I know*.
//!
//! Answering it by re-detecting would be a second, weaker detector beside the
//! one that already exists. So this reads the findings the detectors ALREADY
//! produced and groups them, and holds no signal logic of its own.
//!
//! # Counter-evidence belongs beside the accusation
//!
//! `established` — has this source ever completed a registration or a call —
//! already softens the verdict inside the detector, through
//! `ScannerThresholds::established_factor`. It was never SHOWN. An operator
//! deciding whether to block an address needs it in the same place as the
//! reason to block: a source that also placed a real call is one a block would
//! disconnect, and finding that out a page away, or after the block, is
//! finding it out too late.

use std::collections::BTreeSet;
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use super::alerting::Finding;

/// One source, and every rule it tripped in this capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccusedSource {
    /// Where it came from.
    pub src_ip: IpAddr,
    /// How many findings name it.
    pub findings: u64,
    /// Which rules fired, deduplicated and in a stable order.
    ///
    /// A set rather than a count: three `scanner` findings and one each of
    /// three different rules are the same number and not the same evidence.
    pub rules: BTreeSet<String>,
    /// First finding about this source.
    pub first_seen: DateTime<Utc>,
    /// Most recent finding about this source.
    pub last_seen: DateTime<Utc>,
    /// Whether this source ever completed a registration or a call.
    ///
    /// Counter-evidence, carried deliberately and set by the caller, which is
    /// the only party holding detector state. `None` when nobody asked the
    /// detector — which is honestly different from "asked, and it had not".
    pub established: Option<bool>,
}

/// Group findings by source.
///
/// Ordered by finding count descending, then by address, so the output is
/// stable across runs and diffable between captures.
#[must_use]
pub fn accused(findings: &[&Finding]) -> Vec<AccusedSource> {
    // BTreeMap, not HashMap: the tie-break below is by address, and building
    // the groups in address order means the sort only has to be stable rather
    // than total. A hash order would make two runs over one capture disagree
    // on which of two equally busy sources came first.
    let mut by_src: std::collections::BTreeMap<IpAddr, AccusedSource> =
        std::collections::BTreeMap::new();

    for f in findings {
        match by_src.get_mut(&f.src_ip) {
            Some(a) => {
                a.findings += 1;
                a.rules.insert(f.rule_name.clone());
                a.first_seen = a.first_seen.min(f.timestamp);
                a.last_seen = a.last_seen.max(f.timestamp);
            }
            None => {
                by_src.insert(
                    f.src_ip,
                    AccusedSource {
                        src_ip: f.src_ip,
                        findings: 1,
                        rules: BTreeSet::from([f.rule_name.clone()]),
                        first_seen: f.timestamp,
                        last_seen: f.timestamp,
                        established: None,
                    },
                );
            }
        }
    }

    let mut out: Vec<AccusedSource> = by_src.into_values().collect();
    // Busiest first. `sort_by_key` is stable, so the BTreeMap's address order
    // survives as the tie-break without being restated here, and `Reverse`
    // gets the descending order without a comparator clippy reads as a
    // hand-rolled key sort.
    out.sort_by_key(|a| std::cmp::Reverse(a.findings));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a finding without dragging the alert engine in.
    fn f(ip: &str, rule: &str, secs: i64) -> Finding {
        Finding {
            rule_name: rule.to_string(),
            src_ip: ip.parse().expect("test ip"),
            detail: String::new(),
            timestamp: DateTime::from_timestamp(secs, 0).expect("test timestamp"),
        }
    }

    #[test]
    fn one_source_many_findings_becomes_one_row() {
        let all = [
            f("198.51.100.7", "scanner", 10),
            f("198.51.100.7", "scanner", 20),
        ];
        let refs: Vec<&Finding> = all.iter().collect();
        let out = accused(&refs);
        assert_eq!(out.len(), 1, "two findings from one address are one source");
        assert_eq!(out[0].findings, 2);
        assert_eq!(out[0].first_seen, all[0].timestamp);
        assert_eq!(out[0].last_seen, all[1].timestamp);
    }

    /// The distinction the `rules` set exists to keep: three findings of one
    /// rule and one each of three rules have the same count and are not the
    /// same evidence.
    #[test]
    fn distinct_rules_are_kept_apart_from_repeat_findings() {
        let repeat = [
            f("198.51.100.7", "scanner", 1),
            f("198.51.100.7", "scanner", 2),
            f("198.51.100.7", "scanner", 3),
        ];
        let varied = [
            f("198.51.100.8", "scanner", 1),
            f("198.51.100.8", "reg-flood", 2),
            f("198.51.100.8", "digest-leak", 3),
        ];
        let rr: Vec<&Finding> = repeat.iter().collect();
        let vr: Vec<&Finding> = varied.iter().collect();
        assert_eq!(accused(&rr)[0].findings, accused(&vr)[0].findings);
        assert_eq!(accused(&rr)[0].rules.len(), 1);
        assert_eq!(accused(&vr)[0].rules.len(), 3);
    }

    /// Busiest first, then by address, so two runs over one capture agree.
    #[test]
    fn output_is_ordered_and_stable() {
        let all = [
            f("198.51.100.9", "scanner", 1),
            f("198.51.100.7", "scanner", 2),
            f("198.51.100.7", "scanner", 3),
            f("198.51.100.8", "scanner", 4),
        ];
        let refs: Vec<&Finding> = all.iter().collect();
        let out = accused(&refs);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].src_ip.to_string(), "198.51.100.7", "busiest first");
        assert_eq!(out[1].src_ip.to_string(), "198.51.100.8", "then by address");
        assert_eq!(out[2].src_ip.to_string(), "198.51.100.9");
    }

    /// Nobody asked the detector, so the field says so rather than claiming
    /// the source has no relationship.
    #[test]
    fn established_is_unknown_until_a_caller_supplies_it() {
        let all = [f("198.51.100.7", "scanner", 1)];
        let refs: Vec<&Finding> = all.iter().collect();
        assert_eq!(accused(&refs)[0].established, None);
    }

    #[test]
    fn no_findings_accuse_nobody() {
        assert!(accused(&[]).is_empty());
    }
}
