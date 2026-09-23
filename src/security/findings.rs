// SPDX-License-Identifier: MIT OR Apache-2.0

//! The findings page shared by the MCP `security_findings` tool and the REST
//! `GET /v1/security/findings` route.
//!
//! The ring walk itself lives on [`AlertEngine::iter_findings`]; this module
//! holds the three things both surfaces agreed on and would otherwise copy: the
//! `kinds` vocabulary check (with the `reg-flood`/`reg_flood` near-miss hint),
//! the `since` cursor parse, and the page assembly that turns "an empty list"
//! into two distinguishable answers — nothing tripped, or nothing was armed to
//! trip.
//!
//! It returns RAW data: the `detail` line each detector wrote, unfenced. A
//! surface renders it — MCP fences the attacker-controlled banner half of the
//! `detail`, REST hands a SOC dashboard the value it keys on.

use crate::security::alerting::{AlertEngine, ObservationGap};
use chrono::{DateTime, Utc};
use std::net::IpAddr;

/// The four detector kinds a finding can be filed under, sorted.
///
/// One list, shared: the MCP tool advertises exactly these as its filter
/// vocabulary, and a REST caller filters on the same set. The names are the
/// rule names the detectors [`AlertEngine::fire`] under, not the `--alert`
/// grammar's spellings (`reg-flood`), which is why the parse offers the hyphen
/// form as a near miss rather than accepting it.
pub const SECURITY_FINDING_KINDS: [&str; 4] = ["digest", "fraud", "reg_flood", "scanner"];

/// The note returned when no detector is armed, so an empty findings list is
/// not misread as a clean bill of health.
pub const NO_DETECTOR_NOTE: &str = "No detection rule is armed on this server, \
    so no finding could have been recorded. An empty findings list here means \
    nothing was watching, NOT that the traffic was clean. Arm a detector with \
    --kill-scanner, --fraud-detect, --digest-leak or --reg-flood and re-run the \
    capture.";

/// One finding, raw: the `detail` is exactly what the detector wrote, unfenced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
    /// The rule that fired — one of [`SECURITY_FINDING_KINDS`].
    pub rule_name: String,
    /// The source address the finding is about.
    pub src_ip: IpAddr,
    /// The detector's own detail line, raw (a surface fences it).
    pub detail: String,
    /// When the finding fired.
    pub timestamp: DateTime<Utc>,
}

/// The findings page a surface renders, raw.
///
/// `total_matched` counts every finding the filter admits, not just the page,
/// so a bounded page is never mistaken for the whole ring. `armed_kinds` and
/// `detection_armed` are the load-bearing distinction: `rows` empty with
/// `detection_armed` false means nothing was watching, not that nothing tripped.
#[derive(Debug, Clone)]
pub struct FindingsReport {
    /// Up to `limit` findings, newest first, raw.
    pub rows: Vec<FindingRow>,
    /// Every finding the filter admits across the whole ring.
    pub total_matched: usize,
    /// True when `total_matched` exceeds what `rows` carries.
    pub truncated: bool,
    /// Which detectors are armed on this server.
    pub armed_kinds: Vec<String>,
    /// False when no detector is armed — see [`NO_DETECTOR_NOTE`].
    pub detection_armed: bool,
    /// Present only when `detection_armed` is false.
    pub note: Option<String>,
    /// What an armed detector says it cannot see in this capture, narrowed to
    /// `kinds`. Empty rows beside a non-empty entry here mean "could not
    /// tell", not "nothing tripped".
    pub observation_gaps: Vec<ObservationGap>,
}

/// Validate a `kinds` filter and parse a `since` cursor.
///
/// Returns the owned inputs [`build_report`] takes. The error is a message each
/// surface maps to its own type (MCP `invalid_params`, REST `400`).
///
/// # Errors
///
/// A message naming the four kinds (and the near miss, if any) when a kind is
/// outside the vocabulary, or naming the format when `since` is not RFC 3339.
pub fn parse_query(
    kinds: &[String],
    since: Option<&str>,
) -> Result<(Vec<String>, Option<DateTime<Utc>>), String> {
    for k in kinds {
        if !SECURITY_FINDING_KINDS.contains(&k.as_str()) {
            // Name the near miss. `reg-flood` is the spelling the `--alert`
            // grammar uses for the same detector, so an operator who wrote one
            // reaches for it here first.
            let suggestion = SECURITY_FINDING_KINDS
                .iter()
                .find(|known| known.replace('_', "-") == k.replace('_', "-").to_lowercase())
                .map(|known| format!(" (did you mean '{known}'?)"))
                .unwrap_or_default();
            return Err(format!(
                "unknown kind '{k}', expected one of: {}{suggestion}",
                SECURITY_FINDING_KINDS.join(", ")
            ));
        }
    }
    let since = match since {
        Some(s) => Some(
            DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("since must be RFC 3339: {e}"))?
                .with_timezone(&Utc),
        ),
        None => None,
    };
    Ok((kinds.to_vec(), since))
}

/// Build the findings page from the engine (read-locked by the caller) and the
/// armed-detector list.
///
/// Walks the WHOLE ring to count `total_matched`, then keeps the first `limit`:
/// a truncated scan cannot report what it truncated. The ring is bounded by
/// `--findings-history`, so the walk is bounded too. Pass `engine: None` (a
/// build with no alert engine) to get an empty page with the armed-state note.
#[must_use]
pub fn build_report(
    engine: Option<&AlertEngine>,
    armed: &[String],
    kinds: &[String],
    since: Option<DateTime<Utc>>,
    limit: usize,
) -> FindingsReport {
    let observation_gaps = engine.map_or_else(Vec::new, |e| {
        let kinds_ref: Vec<&str> = kinds.iter().map(String::as_str).collect();
        e.observation_gaps(&kinds_ref)
    });
    let (rows, total_matched) = match engine {
        Some(e) => {
            let kinds_ref: Vec<&str> = kinds.iter().map(String::as_str).collect();
            let raw = e.iter_findings(&kinds_ref, since, usize::MAX);
            let total = raw.len();
            let page: Vec<FindingRow> = raw
                .iter()
                .take(limit)
                .map(|f| FindingRow {
                    rule_name: f.rule_name.clone(),
                    src_ip: f.src_ip,
                    detail: f.detail.clone(),
                    timestamp: f.timestamp,
                })
                .collect();
            (page, total)
        }
        None => (Vec::new(), 0),
    };
    let detection_armed = !armed.is_empty();
    FindingsReport {
        truncated: total_matched > limit,
        rows,
        total_matched,
        armed_kinds: armed.to_vec(),
        detection_armed,
        note: (!detection_armed).then(|| NO_DETECTOR_NOTE.to_string()),
        observation_gaps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::alerting::AlertEngine;
    use chrono::{TimeZone, Utc};

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap() + chrono::Duration::seconds(secs)
    }

    /// Seed three findings from three sources (so no cooldown suppresses them):
    /// two `scanner`, one `fraud`.
    fn seeded_engine() -> AlertEngine {
        let mut e = AlertEngine::new(Vec::new(), None);
        e.fire(
            "scanner",
            "10.0.0.1".parse().unwrap(),
            "ua=sipvicious",
            at(0),
        );
        e.fire(
            "scanner",
            "10.0.0.2".parse().unwrap(),
            "ua=friendly-scanner",
            at(1),
        );
        e.fire(
            "fraud",
            "10.0.0.3".parse().unwrap(),
            "irsf destination",
            at(2),
        );
        e
    }

    /// A kind outside the four is refused, and the `--alert`-grammar spelling
    /// `reg-flood` is named as the near miss for `reg_flood`.
    #[test]
    fn parse_query_refuses_an_unknown_kind_and_hints_the_near_miss() {
        let err = parse_query(&["bogus".to_string()], None).expect_err("unknown kind");
        assert!(
            err.contains("unknown kind 'bogus'"),
            "names the kind: {err}"
        );
        assert!(err.contains("scanner"), "names the vocabulary: {err}");

        let hint = parse_query(&["reg-flood".to_string()], None).expect_err("hyphen form");
        assert!(
            hint.contains("did you mean 'reg_flood'?"),
            "hints the underscore spelling: {hint}"
        );

        // A valid kind and a valid cursor parse.
        let (kinds, since) =
            parse_query(&["scanner".to_string()], Some("2024-01-15T12:00:00Z")).expect("valid");
        assert_eq!(kinds, vec!["scanner".to_string()]);
        assert!(since.is_some());
    }

    /// `since` must be RFC 3339.
    #[test]
    fn parse_query_rejects_a_malformed_since() {
        let err = parse_query(&[], Some("last tuesday")).expect_err("bad since");
        assert!(err.contains("RFC 3339"), "names the format: {err}");
    }

    /// The page bounds `rows` to `limit` but `total_matched` counts every
    /// admitted finding, and `truncated` says the page is short. The armed list
    /// is reported and, being non-empty, no note is attached.
    #[test]
    fn build_report_bounds_the_page_but_counts_every_match() {
        let engine = seeded_engine();
        let armed = vec!["scanner".to_string(), "fraud".to_string()];
        let r = build_report(Some(&engine), &armed, &[], None, 2);

        assert_eq!(r.rows.len(), 2, "the page is bounded by limit");
        assert_eq!(r.total_matched, 3, "but every match is counted");
        assert!(r.truncated, "the page is short of the total");
        assert!(r.detection_armed, "two detectors are armed");
        assert!(r.note.is_none(), "an armed server attaches no note");
        assert_eq!(r.armed_kinds, armed);
    }

    /// A `kinds` filter narrows both the page and the total.
    #[test]
    fn build_report_filters_by_kind() {
        let engine = seeded_engine();
        let armed = vec!["scanner".to_string()];
        let r = build_report(Some(&engine), &armed, &["fraud".to_string()], None, 50);
        assert_eq!(r.total_matched, 1, "only the one fraud finding");
        assert_eq!(r.rows[0].rule_name, "fraud");
        // Raw: the detail is the detector's own line, unfenced.
        assert_eq!(r.rows[0].detail, "irsf destination");
    }

    /// A detector's standing observation gap rides on the page beside the
    /// findings, narrowed by the same `kinds` filter, and a detector that
    /// withdraws it takes it off the page.
    #[test]
    fn build_report_carries_the_observation_gaps() {
        let mut engine = seeded_engine();
        let gap = ObservationGap {
            rule_name: "reg_flood".to_string(),
            reason: "no_answers".to_string(),
            seen: 12,
            unestablished: 12,
            detail: "no answers".to_string(),
        };
        engine.set_observation_gap("reg_flood", Some(gap.clone()));
        let armed = vec!["reg_flood".to_string()];

        let all = build_report(Some(&engine), &armed, &[], None, 50);
        assert_eq!(all.observation_gaps, vec![gap.clone()]);
        let flood = build_report(Some(&engine), &armed, &["reg_flood".to_string()], None, 50);
        assert_eq!(flood.observation_gaps, vec![gap]);
        let scanner = build_report(Some(&engine), &armed, &["scanner".to_string()], None, 50);
        assert!(
            scanner.observation_gaps.is_empty(),
            "a kinds filter that excludes reg_flood excludes its gap"
        );

        engine.set_observation_gap("reg_flood", None);
        assert!(
            build_report(Some(&engine), &armed, &[], None, 50)
                .observation_gaps
                .is_empty(),
            "a withdrawn gap leaves the page"
        );
    }

    /// With no engine and nothing armed, the page is empty AND carries the note
    /// that says so — the distinction a bare `[]` cannot draw.
    #[test]
    fn build_report_without_a_detector_explains_the_empty_list() {
        let r = build_report(None, &[], &[], None, 50);
        assert!(r.rows.is_empty());
        assert_eq!(r.total_matched, 0);
        assert!(!r.detection_armed);
        assert!(
            r.note
                .as_deref()
                .is_some_and(|n| n.contains("nothing was watching")),
            "the empty list is explained, not left ambiguous"
        );
    }
}
