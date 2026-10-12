// SPDX-License-Identifier: MIT OR Apache-2.0

//! The committed subset of the public vCon datasets, judged on every run.
//!
//! `tests/fixtures/vcon-datasets/` holds four containers copied byte for
//! byte from three of the datasets `PINS.tsv` pins, each with its dataset's
//! LICENSE and a README naming the source repository, the commit, the path
//! each file was copied from and its SHA-256. The full datasets are opt-in
//! (`vcon_dataset_corpus_test.rs`); this subset runs everywhere the `vcon`
//! feature does.
//!
//! What it pins, per file: the exact findings sipnab's schema validator
//! reports, that the `jsonschema` reference agrees on the verdict and on
//! where the problems are, that the file is valid once its recorded dataset
//! issues are repaired, and that `--vcon-fetch-kind generic` saves it
//! unchanged and reports the same findings.

#![cfg(all(feature = "vcon", unix))]

use std::collections::{BTreeMap, BTreeSet};

#[path = "support/vcon_datasets.rs"]
mod vcon_datasets;

use sipnab::output::vcon_schema::{SchemaFinding, validate};
use vcon_datasets::TestError;

const MEDIATYPE: &str = "/attachments/* (required): missing required properties: mediatype";
const CONTENT_HASH: &str =
    "/dialog/* (dependencies): `url` is present, which requires: content_hash";

/// Each committed file: its dataset, its name, the distinct findings, the
/// total number of findings, and the repairs that make it valid.
type Expected = (
    &'static str,
    &'static str,
    &'static [&'static str],
    usize,
    &'static [&'static str],
);

/// What each committed file was measured to get on 2026-10-09.
const EXPECTED: &[Expected] = &[
    (
        "ietf-meeting-vcons",
        "ietf105_iepg_27419.vcon.json",
        &[MEDIATYPE, CONTENT_HASH],
        6,
        &["attachment-mediatype", "dialog-content-hash"],
    ),
    (
        "ietf-meeting-vcons",
        "ietf108_sec_28277.vcon.json",
        &[MEDIATYPE],
        5,
        &["attachment-mediatype"],
    ),
    (
        "vcon-dataset-city-of-newport-ri",
        "newport_citycouncil_2025-07-30_914.vcon.json",
        &[MEDIATYPE, CONTENT_HASH],
        3,
        &["attachment-mediatype", "dialog-content-hash"],
    ),
    (
        "vcon-supreme-court-arguments",
        "91-7094_23823.vcon.json",
        &[MEDIATYPE],
        4,
        &["attachment-mediatype"],
    ),
];

/// The subset root.
fn subset() -> std::path::PathBuf {
    vcon_datasets::repo().join(vcon_datasets::SUBSET_DIR)
}

/// Every committed container, as (dataset, file name, bytes), sorted.
fn committed() -> Result<Vec<(String, String, Vec<u8>)>, TestError> {
    let root = subset();
    let mut out = Vec::new();
    for path in vcon_datasets::containers(&root) {
        let rel = path.strip_prefix(&root)?;
        let parts: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let [dataset, file] = &parts[..] else {
            return Err(format!("{} is not <dataset>/<file>", rel.display()).into());
        };
        out.push((dataset.clone(), file.clone(), std::fs::read(&path)?));
    }
    Ok(out)
}

/// The committed set is exactly the expected set: nothing added without a
/// pinned answer, nothing pinned that is gone.
#[test]
fn the_committed_files_are_exactly_the_pinned_ones() -> Result<(), TestError> {
    let have: BTreeSet<(String, String)> =
        committed()?.into_iter().map(|(d, f, _)| (d, f)).collect();
    let want: BTreeSet<(String, String)> = EXPECTED
        .iter()
        .map(|e| (e.0.to_owned(), e.1.to_owned()))
        .collect();
    assert_eq!(have, want);
    // Anti-vacuity: a subset of nothing passes every per-file test below.
    assert!(want.len() >= 4, "the subset shrank to {}", want.len());
    let datasets: BTreeSet<&str> = EXPECTED.iter().map(|e| e.0).collect();
    assert!(datasets.len() >= 3, "the subset covers {datasets:?} only");
    Ok(())
}

/// Each file gets exactly the findings it was measured to get.
#[test]
fn every_committed_file_gets_its_pinned_findings() -> Result<(), TestError> {
    let files: BTreeMap<(String, String), Vec<u8>> = committed()?
        .into_iter()
        .map(|(d, f, b)| ((d, f), b))
        .collect();
    for (dataset, file, keys, total, _) in EXPECTED {
        let bytes = files
            .get(&((*dataset).to_owned(), (*file).to_owned()))
            .ok_or(format!("{dataset}/{file} is not committed"))?;
        let report = validate(&serde_json::from_slice(bytes)?);
        let mut got: Vec<String> = report
            .errors
            .iter()
            .map(vcon_datasets::finding_key)
            .collect();
        got.sort();
        got.dedup();
        let mut want: Vec<String> = keys.iter().map(|k| (*k).to_owned()).collect();
        want.sort();
        assert_eq!(got, want, "{dataset}/{file}: {report:?}");
        assert_eq!(report.errors.len(), *total, "{dataset}/{file}: {report:?}");
    }
    Ok(())
}

/// The reference engine agrees with sipnab on every committed file, on the
/// verdict and on the instance paths.
#[test]
fn every_committed_file_agrees_with_the_reference() -> Result<(), TestError> {
    let reference = vcon_datasets::reference()?;
    let root = subset();
    let files = vcon_datasets::containers(&root);
    let tally = vcon_datasets::tally(&root, &files, &reference)?;
    assert_eq!(tally.files, EXPECTED.len());
    assert!(tally.disagreements.is_empty(), "{:?}", tally.disagreements);
    Ok(())
}

/// Repaired, each file is valid to both validators, and needed exactly the
/// repairs it was measured to need.
#[test]
fn every_committed_file_is_valid_once_its_recorded_issues_are_repaired() -> Result<(), TestError> {
    let reference = vcon_datasets::reference()?;
    let files: BTreeMap<(String, String), Vec<u8>> = committed()?
        .into_iter()
        .map(|(d, f, b)| ((d, f), b))
        .collect();
    for (dataset, file, _, _, repairs) in EXPECTED {
        let bytes = files
            .get(&((*dataset).to_owned(), (*file).to_owned()))
            .ok_or(format!("{dataset}/{file} is not committed"))?;
        let mut doc: serde_json::Value = serde_json::from_slice(bytes)?;
        let applied = vcon_datasets::repair_recorded_issues(&mut doc);
        assert_eq!(
            applied,
            repairs.iter().copied().collect::<BTreeSet<_>>(),
            "{dataset}/{file}"
        );
        let report = validate(&doc);
        assert!(report.errors.is_empty(), "{dataset}/{file}: {report:?}");
        assert!(
            reference.is_valid(&doc),
            "{dataset}/{file}: the reference refuses it"
        );
    }
    Ok(())
}

/// `--vcon-fetch-kind generic` saves each committed file unchanged, and
/// reports the validator's findings for it.
#[test]
fn the_fetcher_saves_every_committed_file_unchanged() -> Result<(), TestError> {
    let mut items = Vec::new();
    let mut want = BTreeMap::new();
    for (dataset, file, bytes) in committed()? {
        let doc: serde_json::Value = serde_json::from_slice(&bytes)?;
        let uuid = doc["uuid"]
            .as_str()
            .ok_or(format!("{dataset}/{file}: no uuid"))?
            .to_owned();
        want.insert(uuid.clone(), vcon_datasets::fetcher_lines(&doc));
        items.push((uuid, bytes));
    }
    let got = vcon_datasets::fetch_round_trip(&items)?;
    assert_eq!(got.len(), EXPECTED.len());
    for (uuid, trip) in got {
        assert!(
            trip.identical,
            "{uuid}: the saved file differs from the served one"
        );
        assert!(
            !trip.fetcher_findings.is_empty(),
            "{uuid}: every file has findings"
        );
        assert_eq!(Some(&trip.fetcher_findings), want.get(&uuid), "{uuid}");
    }
    Ok(())
}

/// Each dataset directory is a pinned dataset, carries that dataset's
/// LICENSE, and has a README naming the repository, the commit, and every
/// committed file with its source path and SHA-256.
#[test]
fn every_committed_file_says_where_it_came_from() -> Result<(), TestError> {
    let pins: BTreeMap<String, vcon_datasets::Pin> = vcon_datasets::pins()?
        .into_iter()
        .map(|p| (p.name.clone(), p))
        .collect();
    let files = committed()?;
    let datasets: BTreeSet<&String> = files.iter().map(|(d, _, _)| d).collect();
    for dataset in datasets {
        let pin = pins
            .get(dataset)
            .ok_or(format!("{dataset} is not in PINS.tsv"))?;
        let dir = subset().join(dataset);

        let read = |name: &str| {
            std::fs::read_to_string(dir.join(name)).map_err(|e| format!("{dataset}/{name}: {e}"))
        };
        let license = read("LICENSE")?;
        let heading = match pin.license.as_str() {
            "MIT" => "MIT License",
            "BSD-3-Clause" => "BSD 3-Clause License",
            other => return Err(format!("{dataset}: no LICENSE heading known for {other}").into()),
        };
        assert_eq!(license.lines().next(), Some(heading), "{dataset}/LICENSE");

        let readme = read("README.md")?;
        assert!(
            readme.contains(&pin.url),
            "{dataset}/README.md omits {}",
            pin.url
        );
        assert!(
            readme.contains(&pin.commit),
            "{dataset}/README.md omits {}",
            pin.commit
        );

        let rows = vcon_datasets::subset_rows(dataset)?;
        let listed: BTreeSet<&str> = rows.iter().map(|r| r.file.as_str()).collect();
        let present: BTreeSet<&str> = files
            .iter()
            .filter(|(d, _, _)| d == dataset)
            .map(|(_, f, _)| f.as_str())
            .collect();
        assert_eq!(
            listed, present,
            "{dataset}/README.md lists other files than are committed"
        );
        assert_eq!(
            listed.len(),
            rows.len(),
            "{dataset}/README.md lists a file twice"
        );
        for row in &rows {
            assert!(
                row.source.ends_with(&row.file),
                "{dataset}: {} is not copied from a file of the same name ({})",
                row.file,
                row.source
            );
            let bytes = std::fs::read(dir.join(&row.file))?;
            assert_eq!(
                vcon_datasets::sha256_hex(&bytes),
                row.sha256,
                "{dataset}/{}: the bytes are not the ones the README vouches for",
                row.file
            );
        }
    }
    Ok(())
}

// ---- The helpers, against built inputs ----

/// A finding at `path`, for the helper tests.
fn finding(path: &str, keyword: &'static str, detail: &str) -> SchemaFinding {
    SchemaFinding {
        instance_path: path.to_owned(),
        keyword,
        detail: detail.to_owned(),
    }
}

#[test]
fn a_finding_key_folds_array_indices() {
    let f = finding("/dialog/12/parties/3", "type", "x");
    assert_eq!(
        vcon_datasets::finding_key(&f),
        "/dialog/*/parties/* (type): x"
    );
    let root = finding("", "required", "y");
    assert_eq!(vcon_datasets::finding_key(&root), "/ (required): y");
}

#[test]
fn findings_at_other_paths_than_the_reference_are_a_disagreement() {
    let mine = [finding("/attachments/0", "required", "m")];
    let theirs: BTreeSet<String> = ["/attachments/1".to_owned()].into();
    assert!(vcon_datasets::disagrees(&mine, false, &theirs));
    let same: BTreeSet<String> = ["/attachments/0".to_owned()].into();
    assert!(!vcon_datasets::disagrees(&mine, false, &same));
}

#[test]
fn a_verdict_split_is_a_disagreement_and_the_uuid_format_is_not() {
    assert!(vcon_datasets::disagrees(&[], false, &BTreeSet::new()));
    let uuid = [finding("/uuid", "format", "`x` is not a valid uuid")];
    assert!(!vcon_datasets::disagrees(&uuid, true, &BTreeSet::new()));
    let date = [finding(
        "/created_at",
        "format",
        "`x` is not a valid date-time",
    )];
    assert!(vcon_datasets::disagrees(&date, true, &BTreeSet::new()));
}

#[test]
fn a_pin_must_name_a_full_commit() {
    assert!(vcon_datasets::parse_pins("a\thttps://h/a\tabc123\tMIT\n").is_err());
    let ok =
        vcon_datasets::parse_pins(&format!("# c\n\na\thttps://h/a\t{}\tMIT\n", "f".repeat(40)));
    assert_eq!(ok.map(|p| p.len()).ok(), Some(1));
}

#[test]
fn the_readme_table_is_read_row_by_row() {
    let text = "intro\n\n| File | Source path | SHA-256 |\n|---|---|---|\n\
                | `a.vcon.json` | `x/a.vcon.json` | `00ff` |\n\ntrailer | not | a row |\n";
    let rows = vcon_datasets::parse_subset_rows(text);
    assert_eq!(
        rows,
        vec![vcon_datasets::SubsetRow {
            file: "a.vcon.json".into(),
            source: "x/a.vcon.json".into(),
            sha256: "00ff".into(),
        }]
    );
}
