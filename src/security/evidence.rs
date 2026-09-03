// SPDX-License-Identifier: MIT OR Apache-2.0

//! Publishing what a detector found, for a system that decides what to do.
//!
//! sipnab does not ban. Its stated reason is blast radius: a firewall entry is
//! a state change on another system, with a lifetime sipnab neither sets nor
//! knows. That objection stands, and it is an argument about who applies the
//! ban, not about who may say what they saw. So this is the other half:
//! sipnab writes one line per finding that names a source, and a system whose
//! whole job is condemning sources -- TFPS, or anything that reads JSON Lines
//! -- applies its own ignore list, its own duration and its own audit to it.
//!
//! ```text
//! sipnab -d eth0 -N --kill-scanner --evidence-out - | tfps_ctl ingest
//! ```
//!
//! The shape is fixed by `tests/fixtures/sipnab-evidence-golden.jsonl`, which
//! is byte-identical to the copy in the TFPS repository: one JSON object per
//! line, `src_ip`, `rule`, `evidence`, and `ts` when the finding carries a
//! timestamp. A reader that cannot parse a line reports it and reads the next.

use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

/// One finding, in the shape the ingest on the other side reads.
///
/// Field order is the contract: the golden fixture is compared byte for byte,
/// so `serde` writes these in declaration order and `ts` disappears entirely
/// when the finding has none rather than becoming `null`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Evidence {
    /// The source the finding is about.
    pub src_ip: IpAddr,
    /// What was found, in the emitting project's vocabulary.
    pub rule: String,
    /// Why, in one line: the detail a human or an audit row wants.
    pub evidence: String,
    /// When, RFC 3339 in UTC. Absent when the finding carries no time.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ts: Option<String>,
}

impl Evidence {
    /// The line as it goes on the wire, without its newline.
    ///
    /// # Errors
    ///
    /// When the value cannot be serialized, which for these fields means an
    /// allocation failure rather than a shape problem.
    pub fn to_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Where evidence goes: standard output, or a file opened once at startup.
///
/// Opened when the run starts, not at the first finding: a path that cannot be
/// written is an operator's mistake, and reporting it an hour into a capture,
/// after the first scanner arrives, wastes the capture and the finding.
pub enum EvidenceSink {
    /// `-`: the pipe, for `| tfps_ctl ingest`.
    Stdout,
    /// A file, opened for append so a restart adds to the record.
    File(std::fs::File),
}

impl EvidenceSink {
    /// Opens the sink named by `--evidence-out`.
    ///
    /// # Errors
    ///
    /// When the path cannot be opened for append.
    pub fn open(target: &str) -> std::io::Result<Self> {
        if target == "-" {
            return Ok(Self::Stdout);
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(Path::new(target))?;
        Ok(Self::File(file))
    }

    /// Writes one finding, newline-terminated, and flushes it.
    ///
    /// Flushed per line on purpose: the reader on the other end of a pipe acts
    /// on each finding as it arrives, and a buffered line is a ban that has
    /// not happened yet.
    ///
    /// # Errors
    ///
    /// When serialization or the write fails.
    pub fn write(&mut self, e: &Evidence) -> std::io::Result<()> {
        let line = e
            .to_line()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        match self {
            Self::Stdout => {
                let out = std::io::stdout();
                let mut lock = out.lock();
                writeln!(lock, "{line}")?;
                lock.flush()
            }
            Self::File(f) => {
                writeln!(f, "{line}")?;
                f.flush()
            }
        }
    }
}

/// Whether a finding about `origin` may be published.
///
/// The same rule the jail log follows, for the same reason: under HEP the
/// inner addresses are whatever the sender wrote, so publishing them invites
/// a ban on an address of the sender's choosing. `--hep-allow-kill` is the
/// operator saying the HEP feed is trusted; without it, a HEP-carried finding
/// keeps its alert and publishes no evidence.
#[must_use]
pub fn publishable(origin: crate::capture::parse::InputOrigin, hep_allow_kill: bool) -> bool {
    crate::security::scanner_kill::kill_response_eligible(origin, hep_allow_kill)
}

/// The rule name a detector's finding is published under.
///
/// sipnab's vocabulary, not the reader's: TFPS prefixes what it accepts with
/// `sipnab:` so an audit row says where the verdict came from. `Scanner` is
/// `scanner_detected` because that is the name the shared golden fixture
/// carries, and the fixture is the contract.
#[must_use]
pub fn rule_for(kind: crate::security::detectors::DetectorKind) -> &'static str {
    use crate::security::detectors::DetectorKind;
    match kind {
        DetectorKind::Scanner => "scanner_detected",
        DetectorKind::Fraud => "fraud",
        DetectorKind::Digest => "digest_leak",
        DetectorKind::RegFlood => "reg_flood",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::InputOrigin;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address")
    }

    fn golden() -> Vec<String> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sipnab-evidence-golden.jsonl");
        std::fs::read_to_string(p)
            .expect("the golden fixture")
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The emitted bytes are the contract, and the contract lives in a file
    /// the other project holds an identical copy of.
    #[test]
    fn a_scanner_finding_serializes_to_the_golden_line() {
        let e = Evidence {
            src_ip: ip("198.51.100.20"),
            rule: "scanner_detected".to_string(),
            evidence: r#"ua="pplsip" detection=ua_pattern"#.to_string(),
            ts: Some("2026-09-03T16:40:00Z".to_string()),
        };
        assert_eq!(e.to_line().expect("serialize"), golden()[0]);
    }

    /// A finding with no time omits the key rather than writing null: the
    /// third golden line has no `ts` at all.
    #[test]
    fn a_finding_without_a_timestamp_omits_the_key() {
        let e = Evidence {
            src_ip: ip("192.0.2.77"),
            rule: "register_scan".to_string(),
            evidence: "registers=40 success=0".to_string(),
            ts: None,
        };
        let line = e.to_line().expect("serialize");
        assert!(!line.contains("ts"), "{line}");
        assert_eq!(line, golden()[2]);
    }

    /// Every intact golden line round-trips: the reader on the other side
    /// parses exactly what this side writes.
    #[test]
    fn every_intact_golden_line_round_trips() {
        let mut parsed = 0;
        for line in golden() {
            let Ok(e) = serde_json::from_str::<Evidence>(&line) else {
                continue; // the fixture carries one torn line on purpose
            };
            assert_eq!(e.to_line().expect("serialize"), line);
            parsed += 1;
        }
        assert_eq!(parsed, 4, "four of the five golden lines are intact");
    }

    /// The torn line is torn, or the round-trip test above proves nothing
    /// about a reader's tolerance.
    #[test]
    fn the_golden_fixture_carries_one_unparseable_line() {
        let torn = golden()
            .iter()
            .filter(|l| serde_json::from_str::<Evidence>(l).is_err())
            .count();
        assert_eq!(torn, 1);
    }

    /// Wire-observed findings publish; HEP-asserted ones do not, unless the
    /// operator has said the feed is trusted.
    #[test]
    fn hep_origin_publishes_no_evidence_without_the_opt_in() {
        assert!(publishable(InputOrigin::Wire, false));
        assert!(!publishable(InputOrigin::Hep, false));
        assert!(publishable(InputOrigin::Hep, true));
        assert!(!publishable(InputOrigin::Uprobe, false));
        assert!(
            !publishable(InputOrigin::Uprobe, true),
            "there is no addressing to publish, and no opt-in reaches this arm"
        );
    }

    /// A path that cannot be opened fails when the run starts.
    #[test]
    fn an_unwritable_path_fails_at_open_not_at_the_first_finding() {
        let dir = std::env::temp_dir().join(format!("sipnab-ev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let bad = dir.join("no-such-dir").join("evidence.jsonl");
        assert!(EvidenceSink::open(&bad.to_string_lossy()).is_err());
        let good = dir.join("evidence.jsonl");
        assert!(EvidenceSink::open(&good.to_string_lossy()).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file sink appends whole lines, one per finding, flushed as it goes.
    #[test]
    fn a_file_sink_appends_one_line_per_finding() {
        let dir = std::env::temp_dir().join(format!("sipnab-ev-app-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("evidence.jsonl");
        let mut sink = EvidenceSink::open(&path.to_string_lossy()).expect("open");
        for n in 1..=3u8 {
            sink.write(&Evidence {
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, n)),
                rule: "scanner_detected".to_string(),
                evidence: format!("n={n}"),
                ts: None,
            })
            .expect("write");
        }
        let body = std::fs::read_to_string(&path).expect("read");
        assert_eq!(body.lines().count(), 3, "{body}");
        assert!(body.ends_with('\n'), "each line is terminated");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The scanner rule is the name the shared fixture carries, so a real
    /// finding and the contract line are the same bytes but for the values.
    #[test]
    fn the_scanner_rule_is_the_name_the_golden_fixture_uses() {
        use crate::security::detectors::DetectorKind;
        assert_eq!(rule_for(DetectorKind::Scanner), "scanner_detected");
        assert!(
            golden()[0].contains(r#""rule":"scanner_detected""#),
            "{}",
            golden()[0]
        );
        for k in [
            DetectorKind::Fraud,
            DetectorKind::Digest,
            DetectorKind::RegFlood,
        ] {
            assert!(!rule_for(k).is_empty());
        }
    }
}
