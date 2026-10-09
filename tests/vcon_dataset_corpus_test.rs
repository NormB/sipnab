// SPDX-License-Identifier: MIT OR Apache-2.0

//! The public vCon datasets, every container, against sipnab's vCon schema
//! validator. Opt-in: the datasets take about 2.3 GB of disk once fetched and are
//! not committed.
//!
//! ```sh
//! python3 scripts/fetch-vcon-datasets.py ~/vcon-datasets
//! SIPNAB_VCON_DATASETS=~/vcon-datasets \
//!     cargo test --features full --test vcon_dataset_corpus_test
//! ```
//!
//! Without the variable every test here returns early and the binary prints
//! one NOTICE line saying the gates did not run (`tests/support/corpus.rs`).
//!
//! What is asserted, and what is only reported:
//!
//! * **Asserted.** Each dataset is at the commit `PINS.tsv` names, so the
//!   numbers describe known bytes. Every container is read and judged without
//!   a panic. sipnab's verdict agrees with the `jsonschema` reference on every
//!   container, apart from the one difference the validator's own unit tests
//!   pin (`format: uuid`). The fetcher saves a sample of each dataset byte for
//!   byte and reports the validator's findings for it. The committed subset is
//!   a byte-for-byte copy of the files it names at the pinned commit.
//!   Each dataset gets exactly the counts it was measured to get (`EXPECTED`):
//!   the data is pinned, so a different answer is a change in sipnab. With
//!   the four recorded dataset issues repaired, every container is valid to
//!   both validators.
//! * **Reported.** The same counts, printed per dataset, past libtest's
//!   capture.
//!
//! None of these containers carries SIP signaling. Reading them through
//! `-I <file>.vcon.json` is not on main yet; the hook point is
//! `vcon_datasets::containers`, which both the schema pass here and that
//! future test walk.

#![cfg(all(feature = "vcon", unix))]

use std::path::Path;

#[path = "support/corpus.rs"]
mod corpus_support;

#[path = "support/vcon_datasets.rs"]
mod vcon_datasets;

use vcon_datasets::TestError;

/// How many containers of each dataset go through the fetcher: the smallest,
/// the median and the largest, so the size range is covered without serving
/// 17,000 files over loopback.
const FETCH_SAMPLE: usize = 3;

/// The dataset cache, or `None` (with the NOTICE) when it is not configured.
fn cache() -> Option<std::path::PathBuf> {
    corpus_support::vcon_datasets_root()
}

/// The commit a checkout's `.git/HEAD` names. The fetcher leaves HEAD
/// detached, so the file holds the SHA itself.
fn head_of(tree: &Path) -> Result<String, TestError> {
    let head = std::fs::read_to_string(tree.join(".git/HEAD")).map_err(|e| {
        format!(
            "{}: {e}; run scripts/fetch-vcon-datasets.py",
            tree.display()
        )
    })?;
    Ok(head.trim().to_owned())
}

/// Each dataset is present and at its pinned commit.
#[test]
fn every_dataset_is_at_its_pinned_commit() -> Result<(), TestError> {
    let Some(root) = cache() else {
        return Ok(());
    };
    for pin in vcon_datasets::pins()? {
        let head = head_of(&root.join(&pin.name))?;
        assert_eq!(
            head, pin.commit,
            "{}: the cache is at {head}, PINS.tsv pins {}; run \
             scripts/fetch-vcon-datasets.py again",
            pin.name, pin.commit
        );
    }
    Ok(())
}

/// Every container is judged, and sipnab agrees with the reference engine on
/// each one. Prints the per-dataset counts and every finding.
#[test]
fn every_container_is_judged_and_agrees_with_the_reference() -> Result<(), TestError> {
    let Some(root) = cache() else {
        return Ok(());
    };
    let reference = vcon_datasets::reference()?;
    let mut disagreements = Vec::new();
    for pin in vcon_datasets::pins()? {
        let tree = root.join(&pin.name);
        let files = vcon_datasets::containers(&tree);
        assert!(
            !files.is_empty(),
            "{}: no *.vcon.json under {}; the gate would pass on nothing",
            pin.name,
            tree.display()
        );
        let tally = vcon_datasets::tally(&tree, &files, &reference)?;
        vcon_datasets::report(&vcon_datasets::render(&pin.name, &tally));
        assert_eq!(
            tally.files,
            files.len(),
            "{}: a container was skipped",
            pin.name
        );
        assert_eq!(
            tally.valid + tally.invalid + tally.not_json.len(),
            tally.files,
            "{}: every container is valid, invalid or not JSON",
            pin.name
        );
        disagreements.extend(
            tally
                .disagreements
                .into_iter()
                .map(|(file, keys)| format!("{}/{file}: {keys:?}", pin.name)),
        );
    }
    assert!(
        disagreements.is_empty(),
        "sipnab's validator and the jsonschema reference disagree on {} container(s); \
         one of them misreads the schema:\n{}",
        disagreements.len(),
        disagreements
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    Ok(())
}

/// One dataset's measured answer.
struct Measured {
    /// The dataset, as `PINS.tsv` names it.
    name: &'static str,
    /// Containers.
    files: usize,
    /// Containers with no finding.
    valid: usize,
    /// Each finding key, with the number of containers that carry it.
    findings: &'static [(&'static str, usize)],
}

/// What each dataset was measured to hold on 2026-10-09, at its pinned
/// commit: containers, valid containers, and each finding with the number of
/// containers that carry it.
///
/// Pinned rather than only printed, because the data is pinned: the same
/// bytes must get the same answer, so a change here is a change in sipnab's
/// validator or its vendored schema. Moving a pin in `PINS.tsv` means
/// re-measuring and rewriting the row.
const EXPECTED: &[Measured] = &[
    Measured {
        name: "vcon-supreme-court-arguments",
        files: 8503,
        valid: 0,
        findings: &[(
            "/attachments/* (required): missing required properties: mediatype",
            8503,
        )],
    },
    Measured {
        name: "ietf-meeting-vcons",
        files: 8181,
        valid: 0,
        findings: &[
            (
                "/attachments/* (required): missing required properties: mediatype",
                8181,
            ),
            (
                "/dialog/* (dependencies): `url` is present, which requires: content_hash",
                4079,
            ),
        ],
    },
    Measured {
        name: "vcon-dataset-city-of-newport-ri",
        files: 115,
        valid: 0,
        findings: &[
            (
                "/attachments/* (required): missing required properties: mediatype",
                115,
            ),
            (
                "/dialog/* (dependencies): `url` is present, which requires: content_hash",
                115,
            ),
        ],
    },
    Measured {
        name: "fake-vcons",
        files: 601,
        valid: 0,
        findings: &[
            (
                "/attachments/* (required): missing required properties: mediatype",
                601,
            ),
            (
                "/attachments/* (required): missing required properties: start",
                601,
            ),
            (
                "/dialog/* (required): missing required properties: encoding",
                264,
            ),
        ],
    },
    Measured {
        name: "tadhack-2025",
        files: 43,
        valid: 0,
        findings: &[
            (
                "/attachments/* (required): missing required properties: mediatype",
                43,
            ),
            (
                "/attachments/* (required): missing required properties: start",
                43,
            ),
        ],
    },
];

/// Each dataset gets exactly the answer it was measured to get.
#[test]
fn each_dataset_gets_its_measured_answer() -> Result<(), TestError> {
    let Some(root) = cache() else {
        return Ok(());
    };
    let reference = vcon_datasets::reference()?;
    let pins = vcon_datasets::pins()?;
    assert_eq!(
        pins.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
        EXPECTED.iter().map(|e| e.name).collect::<Vec<_>>(),
        "PINS.tsv and EXPECTED name different datasets"
    );
    for Measured {
        name,
        files,
        valid,
        findings,
    } in EXPECTED
    {
        let tree = root.join(name);
        let tally = vcon_datasets::tally(&tree, &vcon_datasets::containers(&tree), &reference)?;
        let want: std::collections::BTreeMap<String, usize> = findings
            .iter()
            .map(|(k, n)| ((*k).to_owned(), *n))
            .collect();
        assert_eq!(
            (tally.files, tally.valid, &tally.by_finding),
            (*files, *valid, &want),
            "{name}: the answer changed\n{}",
            vcon_datasets::render(name, &tally)
        );
    }
    Ok(())
}

/// With the four recorded issues repaired, every container is valid to both
/// sipnab and the reference. So the recorded issues are the whole story, and
/// sipnab's VALID answer -- which no dataset container reaches unrepaired --
/// is exercised on 17,443 real containers.
#[test]
fn every_container_is_valid_once_its_recorded_issues_are_repaired() -> Result<(), TestError> {
    let Some(root) = cache() else {
        return Ok(());
    };
    let reference = vcon_datasets::reference()?;
    let mut still_invalid = Vec::new();
    let mut repaired = 0usize;
    for pin in vcon_datasets::pins()? {
        let tree = root.join(&pin.name);
        for path in vcon_datasets::containers(&tree) {
            let mut doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            vcon_datasets::repair_recorded_issues(&mut doc);
            let mine = sipnab::output::vcon_schema::validate(&doc);
            if !mine.errors.is_empty() || !reference.is_valid(&doc) {
                still_invalid.push(format!("{}: {:?}", path.display(), mine.errors));
            }
            repaired += 1;
        }
    }
    assert!(repaired > 0, "no container was read");
    assert!(
        still_invalid.is_empty(),
        "{} container(s) carry a problem beyond the recorded four:\n{}",
        still_invalid.len(),
        still_invalid
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    vcon_datasets::report(&format!(
        "{repaired} containers valid to sipnab and the reference once repaired\n"
    ));
    Ok(())
}

/// The fetcher (`--vcon-fetch-kind generic`) saves a sample of each dataset
/// byte for byte, and reports for each the findings the validator gives.
#[test]
fn the_fetcher_saves_a_sample_of_each_dataset_unchanged() -> Result<(), TestError> {
    let Some(root) = cache() else {
        return Ok(());
    };
    for pin in vcon_datasets::pins()? {
        let mut files = vcon_datasets::containers(&root.join(&pin.name));
        files.sort_by_key(|p| p.metadata().map(|m| m.len()).unwrap_or(0));
        let picks: Vec<_> = match files.len() {
            0 => Vec::new(),
            n => {
                let mut idx = vec![0, n / 2, n - 1];
                idx.dedup();
                idx.into_iter().map(|i| files[i].clone()).collect()
            }
        };
        assert!(
            !picks.is_empty() && picks.len() <= FETCH_SAMPLE,
            "{}: sample of {}",
            pin.name,
            picks.len()
        );
        let mut items = Vec::new();
        let mut expected = Vec::new();
        for path in &picks {
            let bytes = std::fs::read(path)?;
            let doc: serde_json::Value = serde_json::from_slice(&bytes)?;
            let uuid = doc["uuid"]
                .as_str()
                .ok_or(format!("{}: no uuid", path.display()))?
                .to_owned();
            expected.push((uuid.clone(), vcon_datasets::fetcher_lines(&doc)));
            items.push((uuid, bytes));
        }
        let got = vcon_datasets::fetch_round_trip(&items)?;
        for ((uuid, trip), (want_uuid, want)) in got.iter().zip(&expected) {
            assert_eq!(uuid, want_uuid);
            assert!(
                trip.identical,
                "{}/{uuid}: the saved file differs",
                pin.name
            );
            assert_eq!(
                &trip.fetcher_findings, want,
                "{}/{uuid}: the fetcher's findings differ from the validator's",
                pin.name
            );
        }
    }
    Ok(())
}

/// Each committed subset file is a byte-for-byte copy of the file its README
/// names, at the pinned commit.
#[test]
fn the_committed_subset_is_a_copy_of_the_pinned_files() -> Result<(), TestError> {
    let Some(root) = cache() else {
        return Ok(());
    };
    let mut compared = 0usize;
    for pin in vcon_datasets::pins()? {
        // Two datasets have no committed subset; tests/fixtures/vcon-datasets/README.md
        // says why.
        if !vcon_datasets::repo()
            .join(vcon_datasets::SUBSET_DIR)
            .join(&pin.name)
            .is_dir()
        {
            continue;
        }
        for row in vcon_datasets::subset_rows(&pin.name)? {
            let committed = std::fs::read(
                vcon_datasets::repo()
                    .join(vcon_datasets::SUBSET_DIR)
                    .join(&pin.name)
                    .join(&row.file),
            )?;
            let upstream = std::fs::read(root.join(&pin.name).join(&row.source))
                .map_err(|e| format!("{}/{}: {e}", pin.name, row.source))?;
            assert!(
                committed == upstream,
                "{}/{} differs from {} at {}",
                pin.name,
                row.file,
                row.source,
                pin.commit
            );
            compared += 1;
        }
    }
    assert!(compared > 0, "no subset file was compared");
    Ok(())
}
