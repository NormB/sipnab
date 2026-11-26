// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
//! sipnab -d eth0 -N --kill-scanner --evidence-out - | <a reader of JSON Lines>
//! ```
//!
//! TFPS's reader for it, `ingest`, is on the `05-evidence-ingest` branch of
//! the NormB/tfps fork and in no TFPS build: neither sippulse/tfps `master`
//! nor any tag has it (checked 2026-09-18 at `984577dc`).
//!
//! The shape is fixed by `tests/fixtures/sipnab-evidence-golden.jsonl`, which
//! is byte-identical to the copy on that branch
//! (`crates/tfps/tests/fixtures/sipnab-evidence-golden.jsonl`): one JSON object
//! per line, `src_ip`, `rule`, `evidence`, and `ts` when the finding carries a
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
    /// `-`: standard output, for a pipe into whatever reads the lines.
    Stdout,
    /// A file, opened for append so a restart adds to the record, and
    /// opened again at `path` when log rotation moves it away.
    File {
        /// The open file.
        file: std::fs::File,
        /// The path `--evidence-out` named, which the file follows.
        path: std::path::PathBuf,
    },
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
        let path = Path::new(target);
        Ok(Self::File {
            file: Self::open_file(path)?,
            path: path.to_path_buf(),
        })
    }

    /// The one set of open flags, for the first open and every reopen after
    /// rotation.
    fn open_file(path: &Path) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
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
            Self::File { file, path } => {
                crate::append_file::reopen_if_moved(file, path, Self::open_file)?;
                writeln!(file, "{line}")?;
                file.flush()
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

    type TestError = Box<dyn std::error::Error>;

    fn ip(s: &str) -> Result<IpAddr, TestError> {
        Ok(s.parse()?)
    }

    fn golden() -> Result<Vec<String>, TestError> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sipnab-evidence-golden.jsonl");
        Ok(std::fs::read_to_string(p)?
            .lines()
            .map(str::to_string)
            .collect())
    }

    /// The emitted bytes are the contract, and the contract lives in a file
    /// the other project holds an identical copy of.
    #[test]
    fn a_scanner_finding_serializes_to_the_golden_line() -> Result<(), TestError> {
        let e = Evidence {
            src_ip: ip("198.51.100.20")?,
            rule: "scanner_detected".to_string(),
            evidence: r#"ua="pplsip" detection=ua_pattern"#.to_string(),
            ts: Some("2026-09-03T16:40:00Z".to_string()),
        };
        assert_eq!(e.to_line()?, golden()?[0]);
        Ok(())
    }

    /// A finding with no time omits the key rather than writing null: the
    /// third golden line has no `ts` at all.
    #[test]
    fn a_finding_without_a_timestamp_omits_the_key() -> Result<(), TestError> {
        let e = Evidence {
            src_ip: ip("192.0.2.77")?,
            rule: "register_scan".to_string(),
            evidence: "registers=40 success=0".to_string(),
            ts: None,
        };
        let line = e.to_line()?;
        assert!(!line.contains("ts"), "{line}");
        assert_eq!(line, golden()?[2]);
        Ok(())
    }

    /// Every intact golden line round-trips: the reader on the other side
    /// parses exactly what this side writes.
    #[test]
    fn every_intact_golden_line_round_trips() -> Result<(), TestError> {
        let mut parsed = 0;
        for line in golden()? {
            let Ok(e) = serde_json::from_str::<Evidence>(&line) else {
                continue; // the fixture carries one torn line on purpose
            };
            assert_eq!(e.to_line()?, line);
            parsed += 1;
        }
        assert_eq!(parsed, 4, "four of the five golden lines are intact");
        Ok(())
    }

    /// The torn line is torn, or the round-trip test above proves nothing
    /// about a reader's tolerance.
    #[test]
    fn the_golden_fixture_carries_one_unparseable_line() -> Result<(), TestError> {
        let torn = golden()?
            .iter()
            .filter(|l| serde_json::from_str::<Evidence>(l).is_err())
            .count();
        assert_eq!(torn, 1);
        Ok(())
    }

    /// Wire-observed findings publish; HEP-asserted ones do not, unless the
    /// operator has said the feed is trusted.
    #[test]
    fn hep_origin_publishes_no_evidence_without_the_opt_in() -> Result<(), TestError> {
        assert!(publishable(InputOrigin::Wire, false));
        assert!(!publishable(InputOrigin::Hep, false));
        assert!(publishable(InputOrigin::Hep, true));
        assert!(!publishable(InputOrigin::Uprobe, false));
        assert!(
            !publishable(InputOrigin::Uprobe, true),
            "there is no addressing to publish, and no opt-in reaches this arm"
        );
        Ok(())
    }

    /// A path that cannot be opened fails when the run starts.
    #[test]
    fn an_unwritable_path_fails_at_open_not_at_the_first_finding() -> Result<(), TestError> {
        let dir = crate::test_scratch::ScratchDir::new("sipnab-ev-")
            .map_err(|e| format!("scratch dir: {e}"))?;
        std::fs::create_dir_all(&dir)?;
        let bad = dir.join("no-such-dir").join("evidence.jsonl");
        assert!(EvidenceSink::open(&bad.to_string_lossy()).is_err());
        let good = dir.join("evidence.jsonl");
        assert!(EvidenceSink::open(&good.to_string_lossy()).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// A file sink appends whole lines, one per finding, flushed as it goes.
    #[test]
    fn a_file_sink_appends_one_line_per_finding() -> Result<(), TestError> {
        let dir = crate::test_scratch::ScratchDir::new("sipnab-ev-app-")
            .map_err(|e| format!("scratch dir: {e}"))?;
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("evidence.jsonl");
        let mut sink = EvidenceSink::open(&path.to_string_lossy())?;
        for n in 1..=3u8 {
            sink.write(&Evidence {
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, n)),
                rule: "scanner_detected".to_string(),
                evidence: format!("n={n}"),
                ts: None,
            })?;
        }
        let body = std::fs::read_to_string(&path)?;
        assert_eq!(body.lines().count(), 3, "{body}");
        assert!(body.ends_with('\n'), "each line is terminated");
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// The scanner rule is the name the shared fixture carries, so a real
    /// finding and the contract line are the same bytes but for the values.
    #[test]
    fn the_scanner_rule_is_the_name_the_golden_fixture_uses() -> Result<(), TestError> {
        use crate::security::detectors::DetectorKind;
        assert_eq!(rule_for(DetectorKind::Scanner), "scanner_detected");
        assert!(
            golden()?[0].contains(r#""rule":"scanner_detected""#),
            "{}",
            golden()?[0]
        );
        for k in [
            DetectorKind::Fraud,
            DetectorKind::Digest,
            DetectorKind::RegFlood,
        ] {
            assert!(!rule_for(k).is_empty());
        }
        Ok(())
    }
}

/// `--evidence-out PATH` under log rotation: a finding after the file was
/// renamed or removed lands in a file at the path, as the audit files do.
#[cfg(all(test, unix))]
mod rotation_follow_tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// A finding about `rule`, from an RFC 5737 address.
    fn finding(rule: &str) -> Result<Evidence, TestError> {
        Ok(Evidence {
            src_ip: "203.0.113.9".parse()?,
            rule: rule.to_string(),
            evidence: "ua=\"test\"".to_string(),
            ts: None,
        })
    }

    /// The `rule` of every line of `path`.
    fn rules(path: &Path) -> Result<Vec<String>, TestError> {
        let mut out = Vec::new();
        for line in std::fs::read_to_string(path)?.lines() {
            let e: Evidence = serde_json::from_str(line)?;
            out.push(e.rule);
        }
        Ok(out)
    }

    /// SUCCESS: after a rename the next finding is in the file at the path.
    #[test]
    fn a_finding_after_a_rename_lands_at_the_path() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("evidence.jsonl");
        let rotated = dir.path().join("evidence.jsonl.1");
        let mut sink = EvidenceSink::open(path.to_str().ok_or("utf-8 path")?)?;
        sink.write(&finding("before")?)?;
        std::fs::rename(&path, &rotated)?;
        sink.write(&finding("after")?)?;
        assert_eq!(rules(&path)?, vec!["after"], "new finding at the path");
        assert_eq!(rules(&rotated)?, vec!["before"], "old file keeps its own");
        Ok(())
    }

    /// SUCCESS: after a removal the file is created again.
    #[test]
    fn a_finding_after_a_removal_creates_the_file_again() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("evidence.jsonl");
        let mut sink = EvidenceSink::open(path.to_str().ok_or("utf-8 path")?)?;
        sink.write(&finding("before")?)?;
        std::fs::remove_file(&path)?;
        sink.write(&finding("after")?)?;
        assert_eq!(rules(&path)?, vec!["after"], "the file is created again");
        Ok(())
    }

    /// EDGE: without rotation every finding stays in the one file.
    #[test]
    fn without_rotation_every_finding_stays_in_one_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("evidence.jsonl");
        let mut sink = EvidenceSink::open(path.to_str().ok_or("utf-8 path")?)?;
        for r in ["a", "b", "c"] {
            sink.write(&finding(r)?)?;
        }
        assert_eq!(rules(&path)?, vec!["a", "b", "c"], "one file, three lines");
        Ok(())
    }

    /// EDGE: a file the rotator created is appended to, not replaced.
    #[test]
    fn a_file_created_by_the_rotator_is_appended_to() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("evidence.jsonl");
        let mut sink = EvidenceSink::open(path.to_str().ok_or("utf-8 path")?)?;
        sink.write(&finding("before")?)?;
        std::fs::rename(&path, dir.path().join("old"))?;
        let seed = finding("seeded")?.to_line()?;
        std::fs::write(&path, format!("{seed}\n"))?;
        sink.write(&finding("after")?)?;
        assert_eq!(
            rules(&path)?,
            vec!["seeded", "after"],
            "the rotator's file keeps its content and gains the finding"
        );
        Ok(())
    }

    /// FAILURE: a rotation that took the directory away is a write error.
    #[test]
    fn a_reopen_that_fails_is_an_error() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let sub = dir.path().join("out");
        std::fs::create_dir(&sub)?;
        let path = sub.join("evidence.jsonl");
        let mut sink = EvidenceSink::open(path.to_str().ok_or("utf-8 path")?)?;
        sink.write(&finding("before")?)?;
        std::fs::remove_file(&path)?;
        std::fs::remove_dir(&sub)?;
        assert!(
            sink.write(&finding("after")?).is_err(),
            "a finding with nowhere to go must be an error, not written unlinked"
        );
        Ok(())
    }

    /// FAILURE: a directory at the path is a write error.
    #[test]
    fn a_directory_at_the_path_is_an_error() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("evidence.jsonl");
        let mut sink = EvidenceSink::open(path.to_str().ok_or("utf-8 path")?)?;
        sink.write(&finding("before")?)?;
        std::fs::rename(&path, dir.path().join("old"))?;
        std::fs::create_dir(&path)?;
        assert!(
            sink.write(&finding("after")?).is_err(),
            "writing a finding to a directory must fail"
        );
        Ok(())
    }
}
