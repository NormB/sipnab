// SPDX-License-Identifier: MIT OR Apache-2.0

//! Scoring `scanner_detect` against an EXTERNAL oracle.
//!
//! [`scanner_signature_corpus_test`] already replays a real corpus and checks
//! every behavioral alert against an oracle derived *from the packets* — an
//! independent count of rejected and unanswered probe transactions. That answers
//! "is this alert supported by something in the capture".
//!
//! It cannot answer "was this source actually hostile", because nothing in a
//! capture says so. `docs/design/threat-mitigation-hooks.md` §7 names the
//! missing artifact: *a labeled corpus — real traffic with known scanners
//! marked — measured for both false-positive and false-negative rate*, and
//! calls it the prerequisite for every automated-response decision the project
//! has deferred.
//!
//! TFPS decides exactly that, continuously, and can now export it. This file
//! reads that export and scores the detector against it.
//!
//! # TFPS is optional
//!
//! TFPS is software an operator may or may not have installed, in the same
//! category as rtpengine, OpenSIPS, Kamailio or Asterisk — a machine might have
//! several, or none. sipnab carries **no dependency on it**: these labels are
//! read as plain JSON, there is no `tfps` crate in the manifest, and with the
//! environment unset every test here that needs one skips, exactly as its
//! sibling does without `SIPNAB_CORPUS`.
//!
//! A laptop with none of that installed runs sipnab and captures traffic
//! normally. That is the ordinary case, not a fallback.
//!
//! # Running
//!
//! ```text
//! TFPS_LABELS=/path/labels.jsonl SIPNAB_CORPUS=/path/pcaps \
//!     cargo test --all-features --test tfps_label_corpus_test -- --nocapture
//! ```
//!
//! The corpus and the labels both describe real traffic and are assumed to
//! contain PII: neither is committed. The run prints the SOURCE ADDRESSES under
//! each outcome -- recalled, missed, false positive, flagged but unlabeled --
//! to the operator who owns both files, because a count alone was how
//! "recalled 1 of 15" got attributed to the wrong address by hand. Nothing
//! else derived from a packet or a label -- Call-ID, user part, header text --
//! is printed, and no output of this run is committed. The committed fixture
//! is synthetic, from RFC 5737's documentation ranges, and exists to pin the
//! format the two projects agreed on.
#![cfg(feature = "native")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use sipnab::security::ScannerDetector;

#[path = "support/corpus.rs"]
mod corpus_support;

/// A verdict TFPS reached about one source, at one moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub ip: String,
    pub rule: String,
    pub verdict: Verdict,
    /// Set only when an operator lifted the block — a human saying the machine
    /// was wrong, and the strongest negative in the set.
    pub unbanned_at: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Condemned and enforced.
    Blocked,
    /// Condemned while observing only.
    WouldBlock,
    /// Tripped a rule and was trusted anyway — the hard negative.
    Exempt,
}

/// What the corpus says about a source, once every event for it is considered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ground {
    /// TFPS condemned it and no operator disagreed.
    Hostile,
    /// TFPS exempted it, or an operator lifted its block.
    Benign,
}

/// The score, and the evidence needed to distrust it.
///
/// Every outcome carries the addresses behind it, not a count. A count is
/// what the harness used to print, and it was read backwards: "recalled 1 of
/// 15" says one source was caught and leaves a human to guess which.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Score {
    pub hostile: usize,
    pub benign: usize,
    /// Hostile sources sipnab also flagged.
    pub recalled: BTreeSet<String>,
    /// Hostile sources that appear in the corpus and were not flagged.
    ///
    /// "Appear in the corpus" is the whole of the definition. A hostile
    /// source TFPS saw in a window the pcaps do not cover was never shown to
    /// the detector, and charging it as a miss would score the capture's
    /// coverage rather than the detector.
    pub missed: BTreeSet<String>,
    /// Benign sources sipnab flagged anyway.
    pub false_positives: BTreeSet<String>,
    /// Sources sipnab flagged that the labels say nothing about at all.
    pub flagged_unlabeled: BTreeSet<String>,
}

/// Parse the export. One JSON object per line.
///
/// Structural, not via a shared type: sipnab has no dependency on TFPS and this
/// is the seam where one would otherwise creep in.
fn parse_labels(src: &str) -> Result<Vec<Label>, String> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("label line {}: {e}", i + 1))?;
        let get = |k: &str| -> Result<String, String> {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .ok_or_else(|| format!("label line {}: no {k:?}", i + 1))
        };
        let verdict = match get("verdict")?.as_str() {
            "blocked" => Verdict::Blocked,
            "would-block" => Verdict::WouldBlock,
            "exempt" => Verdict::Exempt,
            // Refused rather than assumed. A verdict this reader does not know
            // is a newer TFPS, and guessing would put the source on one side of
            // the score with nothing behind the choice.
            other => {
                return Err(format!("label line {}: unknown verdict {other:?}", i + 1));
            }
        };
        out.push(Label {
            ip: get("ip")?,
            rule: get("rule")?,
            verdict,
            // Absent and null are both "no lift"; the exporter writes null.
            unbanned_at: v
                .get("unbanned_at")
                .and_then(serde_json::Value::as_u64)
                .map(|n| n as u32),
        });
    }
    Ok(out)
}

/// Collapse every event for a source into one ground truth.
///
/// Benign evidence wins. An exemption means the source tripped a rule and was
/// trusted anyway; an operator lift means a human looked at a block and
/// disagreed with it. Either outranks the condemnation it sits beside, because
/// both are somebody deciding the machine was wrong about that address, and a
/// condemnation is only ever the machine.
fn ground_truth(labels: &[Label]) -> BTreeMap<String, Ground> {
    let mut out: BTreeMap<String, Ground> = BTreeMap::new();
    for l in labels {
        let this = if l.verdict == Verdict::Exempt || l.unbanned_at.is_some() {
            Ground::Benign
        } else {
            Ground::Hostile
        };
        out.entry(l.ip.clone())
            .and_modify(|g| {
                if this == Ground::Benign {
                    *g = Ground::Benign;
                }
            })
            .or_insert(this);
    }
    out
}

/// Score what sipnab flagged against that ground truth.
///
/// # Arguments
///
/// * `truth` — every labeled source and which side it is on.
/// * `flagged` — every source sipnab reported.
/// * `present` — every source address that sent at least one SIP message in
///   the corpus. A hostile source outside this set is not a miss: the detector
///   was never shown it.
fn score(
    truth: &BTreeMap<String, Ground>,
    flagged: &BTreeSet<String>,
    present: &BTreeSet<String>,
) -> Score {
    let mut s = Score::default();
    for (ip, g) in truth {
        match g {
            Ground::Hostile => {
                s.hostile += 1;
                if !flagged.contains(ip) && present.contains(ip) {
                    s.missed.insert(ip.clone());
                }
            }
            Ground::Benign => s.benign += 1,
        }
    }
    for ip in flagged {
        match truth.get(ip) {
            Some(Ground::Hostile) => {
                s.recalled.insert(ip.clone());
            }
            Some(Ground::Benign) => {
                s.false_positives.insert(ip.clone());
            }
            // Kept apart and never folded into either rate. TFPS saw a window
            // sipnab did not, or the reverse; calling that a false positive
            // would charge the detector for a source nobody labeled.
            None => {
                s.flagged_unlabeled.insert(ip.clone());
            }
        }
    }
    s
}

/// How many labels each rule contributed — the §6 falsification check, made
/// automatic rather than left as a step somebody has to remember.
fn rule_breakdown(labels: &[Label]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for l in labels {
        *out.entry(l.rule.clone()).or_insert(0) += 1;
    }
    out
}

const GOLDEN: &str = include_str!("fixtures/tfps-labels-golden.jsonl");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agreed_format_is_accepted() {
        let labels = parse_labels(GOLDEN).expect("the golden fixture must parse");
        assert_eq!(labels.len(), 5, "every line is a label");
        let verdicts: BTreeSet<Verdict> = labels.iter().map(|l| l.verdict).collect();
        assert_eq!(
            verdicts,
            BTreeSet::from([Verdict::Blocked, Verdict::WouldBlock, Verdict::Exempt]),
            "all three verdicts must be understood"
        );
    }

    /// A line this reader cannot understand must be an error, never a silently
    /// dropped label. A corpus quietly missing rows scores a detector against
    /// less evidence than it claims.
    #[test]
    fn an_unreadable_line_is_an_error_not_a_skipped_label() {
        let bad = format!("{GOLDEN}\nnot json at all\n");
        assert!(
            parse_labels(&bad).is_err(),
            "an unparseable line must fail loudly; dropping it would shrink the corpus in silence"
        );
    }

    /// An unknown verdict is the shape a future TFPS release takes. Guessing
    /// would put a source on the wrong side of the score.
    #[test]
    fn an_unknown_verdict_is_refused_rather_than_guessed() {
        let line = r#"{"ip":"192.0.2.1","rule":"x","detail":"d","first_seen":1,"expires":null,"unbanned_at":null,"enforced":false,"verdict":"quarantined"}"#;
        assert!(
            parse_labels(line).is_err(),
            "an unknown verdict must not be assumed benign"
        );
    }

    #[test]
    fn a_condemnation_is_hostile_and_an_exemption_is_benign() {
        let t = ground_truth(&parse_labels(GOLDEN).unwrap());
        assert_eq!(t.get("198.51.100.10"), Some(&Ground::Hostile), "blocked");
        assert_eq!(
            t.get("198.51.100.12"),
            Some(&Ground::Hostile),
            "would-block"
        );
        assert_eq!(
            t.get("192.0.2.5"),
            Some(&Ground::Benign),
            "exempt by ignoreip"
        );
        assert_eq!(
            t.get("192.0.2.6"),
            Some(&Ground::Benign),
            "exempt as a registered peer"
        );
    }

    /// The gold negative outranks the condemnation it followed. That is the
    /// whole reason the operator unban is recorded.
    #[test]
    fn an_operator_lift_turns_a_condemnation_into_a_benign_source() {
        let t = ground_truth(&parse_labels(GOLDEN).unwrap());
        assert_eq!(
            t.get("198.51.100.11"),
            Some(&Ground::Benign),
            "a human lifted this block; the machine was wrong about it"
        );
    }

    /// Every hostile and benign source of the fixture is in the corpus.
    fn everyone_present() -> BTreeSet<String> {
        ground_truth(&parse_labels(GOLDEN).unwrap())
            .keys()
            .cloned()
            .collect()
    }

    /// The score NAMES each source under its outcome. A count alone was how
    /// "recalled 1 of 15" got read as the wrong address: the harness said one
    /// source was caught and a human guessed which, and guessed backwards.
    #[test]
    fn the_score_separates_recall_from_false_positives() {
        let t = ground_truth(&parse_labels(GOLDEN).unwrap());
        let flagged = BTreeSet::from([
            "198.51.100.10".to_string(), // hostile, caught
            "192.0.2.5".to_string(),     // benign, flagged anyway
            "203.0.113.99".to_string(),  // nothing is known about it
        ]);
        let s = score(&t, &flagged, &everyone_present());
        assert_eq!(s.hostile, 2);
        assert_eq!(s.benign, 3);
        assert_eq!(s.recalled, BTreeSet::from(["198.51.100.10".to_string()]));
        assert_eq!(
            s.missed,
            BTreeSet::from(["198.51.100.12".to_string()]),
            "the other hostile source was in the corpus and not flagged"
        );
        assert_eq!(s.false_positives, BTreeSet::from(["192.0.2.5".to_string()]));
        assert_eq!(
            s.flagged_unlabeled,
            BTreeSet::from(["203.0.113.99".to_string()]),
            "a flagged source the labels say nothing about is neither a hit nor a miss"
        );
    }

    /// A hostile source that never appears in the pcaps is not a miss.
    ///
    /// TFPS saw a window sipnab did not. Charging the detector for a source it
    /// was never shown would score the capture's coverage, not the detector,
    /// and make every corpus narrower than the ban log read as a detector
    /// failure.
    #[test]
    fn a_hostile_source_absent_from_the_corpus_is_not_a_miss() {
        let t = ground_truth(&parse_labels(GOLDEN).unwrap());
        // Only one of the two hostile sources ever sent a packet.
        let present = BTreeSet::from(["198.51.100.10".to_string()]);
        let s = score(&t, &BTreeSet::new(), &present);
        assert_eq!(
            s.missed,
            BTreeSet::from(["198.51.100.10".to_string()]),
            "the hostile source that WAS in the corpus and went unflagged is the miss"
        );
        assert!(
            !s.missed.contains("198.51.100.12"),
            "198.51.100.12 is hostile but sent nothing sipnab could have seen"
        );
        assert_eq!(
            s.hostile, 2,
            "absence from the corpus does not change the labels"
        );
    }

    /// NEGATIVE CONTROL. A detector that flags nothing must score zero recall
    /// and zero false positives — not an empty score that reads as perfect —
    /// and every hostile source in the corpus is then a named miss.
    #[test]
    fn flagging_nothing_scores_no_recall_rather_than_no_error() {
        let t = ground_truth(&parse_labels(GOLDEN).unwrap());
        let s = score(&t, &BTreeSet::new(), &everyone_present());
        assert!(s.recalled.is_empty());
        assert!(s.false_positives.is_empty());
        assert!(s.flagged_unlabeled.is_empty());
        assert_eq!(
            s.missed,
            BTreeSet::from(["198.51.100.10".to_string(), "198.51.100.12".to_string()]),
            "flagging nothing misses every hostile source the corpus holds"
        );
        assert!(
            s.hostile > 0,
            "the ground truth must not be empty, or this proves nothing"
        );
    }

    /// The review's §6: if the labels turn out to be dominated by a reputation
    /// feed rather than observed behavior, the corpus scores IP lists and not
    /// signatures. Reporting the breakdown makes that visible without anyone
    /// having to remember to look.
    #[test]
    fn the_rule_breakdown_is_reported() {
        let b = rule_breakdown(&parse_labels(GOLDEN).unwrap());
        assert_eq!(b.get("scanner"), Some(&1));
        assert_eq!(b.get("injection"), Some(&1));
        assert_eq!(b.get("reg-scan"), Some(&1));
        assert_eq!(
            b.values().sum::<usize>(),
            5,
            "every label is attributed to a rule"
        );
    }
}

// ---- The corpus-driven half ----

/// The label export named by `TFPS_LABELS`, or `None` when the operator has not
/// pointed us at one.
///
/// Absent is the ordinary case. TFPS is optional software; a machine may have
/// it, or several other peers, or none at all.
fn labels_path() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var("TFPS_LABELS").ok()?);
    if !p.is_file() {
        eprintln!("TFPS_LABELS is set but is not a readable file — skipping");
        return None;
    }
    Some(p)
}

#[test]
fn scanner_detect_is_scored_against_the_ban_log() {
    let (Some(labels_file), Some(root)) = (labels_path(), corpus_support::root()) else {
        return;
    };
    let raw = std::fs::read_to_string(&labels_file).expect("TFPS_LABELS must be readable");
    let labels = parse_labels(&raw).expect("the label export must parse");
    assert!(
        !labels.is_empty(),
        "TFPS_LABELS holds no labels — this test would pass without proving anything"
    );

    let captures = corpus_support::captures(&root);
    assert!(
        !captures.is_empty(),
        "SIPNAB_CORPUS holds no readable capture with SIP in it"
    );

    let truth = ground_truth(&labels);
    let mut flagged: BTreeSet<String> = BTreeSet::new();
    // Every source that sent anything: the population the detector was shown,
    // which is what decides whether an unflagged hostile source is a miss.
    let mut present: BTreeSet<String> = BTreeSet::new();
    for (_, msgs) in &captures {
        let mut det = ScannerDetector::new(&[]);
        for msg in msgs {
            present.insert(msg.src_addr.to_string());
            if let Some(alert) = det.check(msg) {
                flagged.insert(alert.src_ip.to_string());
            }
        }
    }

    let s = score(&truth, &flagged, &present);

    // The join has to be checked before the score is believed. Two observation
    // points that barely agree about addresses are not one estate seen twice —
    // a NAT or an SBC between them breaks the join, and neither tool says so.
    let labeled_in_corpus = truth.keys().filter(|ip| present.contains(*ip)).count();
    assert!(
        labeled_in_corpus > 0,
        "not one labeled source appears in the capture: the label file and the \
         corpus do not describe the same traffic, and any score over them would \
         be arithmetic on a failed join"
    );

    // Addresses under each outcome, to the operator who owns both files.
    // Nothing else from a packet or a label is printed.
    let names = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
    eprintln!("labeled: {} hostile, {} benign", s.hostile, s.benign);
    eprintln!(
        "  {labeled_in_corpus} labeled sources appear in the corpus ({} sources sent SIP)",
        present.len()
    );
    eprintln!("sipnab flagged {} sources", flagged.len());
    eprintln!(
        "  recalled {} of {} hostile: [{}]",
        s.recalled.len(),
        s.hostile,
        names(&s.recalled)
    );
    eprintln!(
        "  missed (hostile, in the corpus, not flagged) {}: [{}]",
        s.missed.len(),
        names(&s.missed)
    );
    eprintln!(
        "  false positives {} of {} benign: [{}]",
        s.false_positives.len(),
        s.benign,
        names(&s.false_positives)
    );
    eprintln!(
        "  flagged but unlabeled {}: [{}]",
        s.flagged_unlabeled.len(),
        names(&s.flagged_unlabeled)
    );
    eprintln!("rule breakdown: {:?}", rule_breakdown(&labels));

    // §6 of the review, made automatic: if the labels are dominated by one rule
    // fed from a reputation list rather than observed behavior, this corpus
    // scores an IP list and teaches the detector nothing.
    let breakdown = rule_breakdown(&labels);
    if let Some((rule, n)) = breakdown
        .iter()
        .max_by_key(|(_, n)| **n)
        .filter(|(_, n)| **n * 2 > labels.len())
    {
        eprintln!(
            "NOTE: {n} of {} labels come from one rule ({rule}); check it is \
             behavioral before drawing conclusions about a signature",
            labels.len()
        );
    }
}

// ---- TFPS is optional, and that is a tested property ----

/// The manifest must never gain a dependency on TFPS.
///
/// # Why this is a test and not a convention
///
/// A laptop with no TFPS, no rtpengine, no OpenSIPS, no Kamailio and no
/// Asterisk must run sipnab and capture traffic, normally and without comment.
/// That is the ordinary case, not a fallback, and every optional integration is
/// measured against it.
///
/// The way that gets lost is not a decision — it is a convenience. Someone
/// wants the label type instead of parsing JSON, adds one line to the manifest,
/// and sipnab now needs another project to build. `--rtpengine-control` is an
/// `Option<String>` for the same reason; R1 does not become the first
/// exception.
#[test]
fn sipnab_does_not_depend_on_tfps() {
    let manifest = include_str!("../Cargo.toml");
    for line in manifest.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        let name = l.split(['=', ' ', '.']).next().unwrap_or("");
        assert!(
            name != "tfps" && name != "tfps-core",
            "sipnab has taken a dependency on TFPS: {l:?}. The labels are read as \
             JSON precisely so a machine without TFPS installed is unaffected."
        );
    }
}

/// With nothing configured, every corpus-backed test here must skip rather than
/// fail. A machine that has none of this software runs a green suite.
#[test]
fn nothing_configured_is_a_skip_and_not_a_failure() {
    // Deliberately reads the real environment: on a developer machine with the
    // variable unset this is the ordinary path, and in CI it always is.
    if std::env::var("TFPS_LABELS").is_err() {
        assert!(
            labels_path().is_none(),
            "with TFPS_LABELS unset there must be no label source, and the suite skips"
        );
    }
}

// ---- Owed: the contract copy on this side is enforced on this side ----
//
// The fixture is byte-identical to the one in the TFPS tree, and that was true
// when it was copied. Nothing kept it true. A gate that lives only in the other
// repository certifies the other repository's copy: this is a fact written
// twice and only one of them was being read. These mirror the assertions TFPS
// makes about its own copy, so an edit to either side fails on that side.

/// Every field on every row. Absence is never how a value is expressed, because
/// a reader in another project cannot ask what a missing key means.
#[test]
fn the_contract_fixture_carries_every_agreed_field() {
    const FIELDS: &[&str] = &[
        "ip",
        "rule",
        "detail",
        "first_seen",
        "expires",
        "unbanned_at",
        "enforced",
        "verdict",
    ];
    let rows: Vec<serde_json::Value> = GOLDEN
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("each golden line is JSON"))
        .collect();
    assert!(!rows.is_empty(), "the fixture is empty");
    for (i, r) in rows.iter().enumerate() {
        let o = r.as_object().expect("each line is an object");
        for f in FIELDS {
            assert!(o.contains_key(*f), "row {i} has no {f:?}");
        }
        assert_eq!(o.len(), FIELDS.len(), "row {i} carries an unagreed key");
    }
}

/// `expires` means three different things and the fixture must exercise all
/// three, or a reader could implement two of them and still pass here.
#[test]
fn the_contract_fixture_exercises_every_meaning_of_expires() {
    let rows: Vec<serde_json::Value> = GOLDEN
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(rows.iter().any(|r| r["expires"] == 0), "no 'never' case");
    assert!(
        rows.iter()
            .any(|r| r["expires"].as_i64().is_some_and(|v| v > 0)),
        "no real lapse time"
    );
    assert!(
        rows.iter().any(|r| r["expires"].is_null()),
        "no 'nothing was blocked' case"
    );
}
