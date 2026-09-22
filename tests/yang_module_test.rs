// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `sipnab-diagnosis` YANG module is generated, committed, and complete.
//!
//! The module under `yang/` is not written by hand. It is rendered by
//! `sipnab::analysis::yang::module_text` from the node table that also drives
//! the RFC 7951 encoder, and from the finding-kind and count-label tables the
//! analysis itself uses — so a kind cannot exist in the analysis and be
//! missing from the model, and a node cannot be renamed in one place only.
//!
//! The committed file is a generated artifact, and it is regenerated with:
//!
//! ```text
//! SIPNAB_BLESS_YANG=1 cargo test --features full --test yang_module_test
//! ```
//!
//! A published revision is never edited. When a change reaches the module, a
//! new entry goes into `REVISIONS`, the new file is blessed beside the old
//! one, and `scripts/check-yang.py` holds the pair to RFC 7950 section 11 with
//! `pyang --check-update-from`. Whether the text is valid YANG at all is also
//! that script's question, asked of `pyang --lint` and `yanglint`; this file
//! asks only what Rust can answer.

#![cfg(feature = "native")]

use std::collections::BTreeSet;
use std::path::PathBuf;

use sipnab::analysis::yang;
use sipnab::analysis::{CountLabel, FindingKind};

/// The regeneration switch.
const BLESS: &str = "SIPNAB_BLESS_YANG";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Where the current revision is committed.
fn committed() -> PathBuf {
    repo().join("yang").join(yang::module_file_name())
}

/// The first line where two texts differ, for a message a reader can act on.
fn first_difference(a: &str, b: &str) -> String {
    for (i, (x, y)) in a.lines().zip(b.lines()).enumerate() {
        if x != y {
            return format!("line {}:\n  committed: {x}\n  generated: {y}", i + 1);
        }
    }
    format!(
        "one is a prefix of the other ({} vs {} lines)",
        a.lines().count(),
        b.lines().count()
    )
}

/// The committed module is exactly what the tables generate.
///
/// The drift gate. It fails when a finding kind, a count label or a node is
/// added to the analysis without the module being regenerated — which is the
/// case a consumer validating against the published module would otherwise
/// meet first.
#[test]
fn the_committed_module_is_what_the_tables_generate() {
    let generated = yang::module_text();
    let path = committed();
    if std::env::var_os(BLESS).is_some() {
        std::fs::create_dir_all(path.parent().expect("yang/")).expect("create yang/");
        std::fs::write(&path, &generated).expect("write the module");
        eprintln!("blessed {}", path.display());
        return;
    }
    let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{} is missing ({e}). Generate it with `{BLESS}=1 cargo test \
             --features full --test yang_module_test`",
            path.display()
        )
    });
    assert!(
        on_disk == generated,
        "{} is stale: {}\nIf this revision is already published, do not bless over \
         it: add a new entry to `REVISIONS` in src/analysis/yang.rs and bless that. \
         Otherwise regenerate with `{BLESS}=1 cargo test --features full --test \
         yang_module_test`.",
        path.display(),
        first_difference(&on_disk, &generated)
    );
}

/// The drift gate compares by default and blesses only when told to.
#[test]
fn the_drift_gate_compares_rather_than_blesses_by_default() {
    assert!(
        std::env::var_os(BLESS).is_none(),
        "{BLESS} is set in this run, so the drift gate rewrote the module instead \
         of checking it. It is a regeneration switch, not something to leave on"
    );
}

/// `identity NAME { base BASE; ... }` pairs, read out of module text.
///
/// The base is taken from the statement's first line only, which is where
/// the renderer puts it: scanning further would let a wrapped description
/// line that happens to begin with the word "base" answer instead.
fn identities(text: &str) -> Vec<(String, Option<String>)> {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(rest) = line.strip_prefix("identity ") else {
            continue;
        };
        let name = rest.trim_end_matches('{').trim().to_string();
        let base = lines
            .get(i + 1)
            .and_then(|next| next.strip_prefix("base "))
            .map(|b| b.trim_end_matches(';').trim().to_string());
        out.push((name, base));
    }
    out
}

/// Every finding kind and every count label is an identity in the COMMITTED
/// module, under the right base, and nothing else is.
///
/// Read from the file rather than from the generator, so this fails on a
/// stale file even when the drift gate above has been blessed past, and it
/// fails for the reason a consumer would: the identity is not in the module.
#[test]
fn every_kind_and_count_label_is_an_identity_in_the_committed_module() {
    let text = std::fs::read_to_string(committed()).expect("read the committed module");
    let found = identities(&text);
    let under = |base: &str| -> BTreeSet<String> {
        found
            .iter()
            .filter(|(_, b)| b.as_deref() == Some(base))
            .map(|(n, _)| n.clone())
            .collect()
    };
    let kinds: BTreeSet<String> = FindingKind::ALL
        .iter()
        .map(|k| k.meta().id.to_string())
        .collect();
    let labels: BTreeSet<String> = CountLabel::ALL
        .iter()
        .map(|l| l.as_str().to_string())
        .collect();
    assert!(
        kinds.len() >= 25 && labels.len() >= 20,
        "the tables are empty"
    );
    assert_eq!(
        under("finding-kind"),
        kinds,
        "the committed module's finding-kind identities are not FindingKind::ALL"
    );
    assert_eq!(
        under("count-label"),
        labels,
        "the committed module's count-label identities are not CountLabel::ALL"
    );
    let bases: BTreeSet<String> = found
        .iter()
        .filter(|(_, b)| b.is_none())
        .map(|(n, _)| n.clone())
        .collect();
    assert_eq!(
        bases,
        BTreeSet::from(["count-label".to_string(), "finding-kind".to_string()]),
        "the module defines a base identity nothing derives from, or loses one"
    );
}

/// Every revision is recorded, newest first, and every one of them is a file.
///
/// The committed files and `REVISIONS` are the same history. A file with no
/// entry is a revision nothing generates; an entry with no file is a
/// published revision `pyang --check-update-from` can no longer hold the next
/// one to.
#[test]
fn the_revision_history_and_the_committed_files_agree() {
    let dates: Vec<&str> = yang::REVISIONS.iter().map(|r| r.date).collect();
    assert_eq!(
        dates.first().copied(),
        Some(yang::REVISION),
        "the newest REVISIONS entry must be the current revision"
    );
    let mut sorted = dates.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    sorted.dedup();
    assert_eq!(sorted, dates, "REVISIONS must be unique and newest first");

    let on_disk: BTreeSet<String> = std::fs::read_dir(repo().join("yang"))
        .expect("read yang/")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".yang"))
        .collect();
    let recorded: BTreeSet<String> = dates
        .iter()
        .map(|d| format!("{}@{d}.yang", yang::MODULE))
        .collect();
    assert_eq!(
        on_disk, recorded,
        "yang/ and REVISIONS disagree about which revisions exist"
    );
}

/// `sipnab --print-yang-module` prints the committed file, byte for byte.
#[test]
fn print_yang_module_prints_the_committed_file() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("--print-yang-module")
        .output()
        .expect("spawn sipnab");
    assert!(
        out.status.success(),
        "exit {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let committed = std::fs::read(committed()).expect("read the committed module");
    assert!(
        out.stdout == committed,
        "--print-yang-module printed {} bytes that are not the {} committed",
        out.stdout.len(),
        committed.len()
    );
}
