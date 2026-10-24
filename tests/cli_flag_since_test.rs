// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The Since column of docs/cli-reference.md.
//!
//! Every flag row names the first release whose command line accepted the
//! flag, or `Unreleased`. `scripts/flag-since.py` derives the value from
//! `src/cli.rs` and the clap groups in `src/cli/*.rs` at each `vX.Y.Z` tag;
//! these gates hold the page to it:
//!
//! - every flag table carries the column, and every row a well-formed cell;
//! - every flag clap builds (and every feature-gated one) has such a row;
//! - the column equals what `scripts/flag-since.py --check` derives, which
//!   needs the release tags in the clone (CI's test jobs fetch them).
#![cfg(feature = "native")]

#[path = "support/cli_flags.rs"]
mod cli_flags;

use clap::CommandFactory;
use std::collections::BTreeMap;
use std::path::Path;

type TestError = Box<dyn std::error::Error>;

/// The header every flag table on the page carries.
const HEADER: &str = "| Flag | Value | Default | Since | Description |";

/// Index of the Since cell among a row's cells.
const SINCE: usize = 3;

/// The cells of a table row, split on unescaped `|`, each trimmed.
fn cells(row: &str) -> Vec<String> {
    let inner = row.trim().trim_start_matches('|');
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    let mut out = Vec::new();
    let mut cell = String::new();
    let mut escaped = false;
    for c in inner.chars() {
        if c == '|' && !escaped {
            out.push(cell.trim().to_string());
            cell.clear();
        } else {
            cell.push(c);
        }
        escaped = c == '\\' && !escaped;
    }
    out.push(cell.trim().to_string());
    out
}

/// The flags a row's first cell names: `--x` tokens without their dashes,
/// and the positional `<BPF_FILTER>`.
fn row_names(first: &str) -> Vec<String> {
    let mut names = Vec::new();
    for tok in first.split('`').skip(1).step_by(2) {
        if let Some(long) = tok.strip_prefix("--") {
            names.push(
                long.split(['=', ' ', '['])
                    .next()
                    .unwrap_or(long)
                    .to_string(),
            );
        } else if tok.starts_with('<') {
            names.push(tok.trim_end_matches('.').to_string());
        }
    }
    names
}

/// A Since cell is a release version or `Unreleased`, nothing else.
fn since_cell_ok(cell: &str) -> bool {
    if cell == "Unreleased" {
        return true;
    }
    let parts: Vec<&str> = cell.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Every row of every flag table, as `(line number, cells)`.
///
/// A flag table is one whose header's first cell is `Flag`. A flag table with
/// any other header is an error, so a table cannot opt out of the column.
fn flag_rows(md: &str) -> Result<Vec<(usize, Vec<String>)>, TestError> {
    let mut rows = Vec::new();
    let mut in_table = false;
    for (i, line) in md.lines().enumerate() {
        if line.starts_with("| Flag |") {
            if line.trim_end() != HEADER {
                return Err(format!(
                    "line {}: flag table header is {line:?}, not {HEADER:?}",
                    i + 1
                )
                .into());
            }
            in_table = true;
            continue;
        }
        if !line.starts_with('|') {
            in_table = false;
            continue;
        }
        if in_table && !line.starts_with("|-") {
            rows.push((i + 1, cells(line)));
        }
    }
    Ok(rows)
}

fn reference() -> Result<String, TestError> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/cli-reference.md");
    Ok(std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?)
}

#[test]
fn every_flag_row_carries_a_since_cell() -> Result<(), TestError> {
    let rows = flag_rows(&reference()?)?;
    // 337 rows on 2026-10-11. A parser that stopped finding tables would
    // otherwise pass having checked nothing.
    assert!(rows.len() >= 300, "only {} flag rows found", rows.len());
    let width = cells(HEADER).len();
    let bad: Vec<String> = rows
        .iter()
        .filter(|(_, c)| c.len() != width || !since_cell_ok(&c[SINCE]))
        .map(|(n, c)| format!("line {n}: {} cells, Since {:?}", c.len(), c.get(SINCE)))
        .collect();
    assert!(
        bad.is_empty(),
        "flag rows without a Since cell of the form X.Y.Z or Unreleased:\n{}\n\
         Fix: python3 scripts/flag-since.py --write",
        bad.join("\n")
    );
    Ok(())
}

#[test]
fn every_flag_clap_builds_has_a_row_with_a_since_cell() -> Result<(), TestError> {
    let md = reference()?;
    let mut since: BTreeMap<String, String> = BTreeMap::new();
    for (_, c) in flag_rows(&md)? {
        if let (Some(first), Some(cell)) = (c.first(), c.get(SINCE)) {
            for name in row_names(first) {
                since.insert(name, cell.clone());
            }
        }
    }
    let mut wanted: Vec<String> = cli_flags::FEATURE_GATED
        .iter()
        .map(|f| (*f).to_string())
        .collect();
    for arg in sipnab::cli::Cli::command().get_arguments() {
        let Some(long) = arg.get_long() else { continue };
        // A hidden flag may go undocumented; a documented one still needs its cell.
        if arg.is_hide_set() && !since.contains_key(long) {
            continue;
        }
        wanted.push(long.to_string());
        if let Some(aliases) = arg.get_visible_aliases() {
            wanted.extend(aliases.into_iter().map(str::to_string));
        }
    }
    assert!(
        wanted.len() >= 300,
        "only {} flags enumerated",
        wanted.len()
    );
    let bad: Vec<String> = wanted
        .iter()
        .filter(|f| !since.get(f.as_str()).is_some_and(|c| since_cell_ok(c)))
        .map(|f| format!("--{f}: {:?}", since.get(f.as_str())))
        .collect();
    assert!(
        bad.is_empty(),
        "flags with no row in docs/cli-reference.md, or a row with no valid Since cell:\n{}",
        bad.join("\n")
    );
    Ok(())
}

#[test]
fn the_since_column_is_what_tagged_history_says() -> Result<(), TestError> {
    let out = std::process::Command::new("python3")
        .arg("scripts/flag-since.py")
        .arg("--check")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()?;
    assert!(
        out.status.success(),
        "docs/cli-reference.md's Since column disagrees with the release tags \
         (exit {:?}):\n{}{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

#[test]
fn cells_split_on_unescaped_pipes_only() {
    assert_eq!(
        cells(r"| `-I` | `<FILE\|DIR>` | -- | 0.3.0 | Read. |"),
        vec!["`-I`", r"`<FILE\|DIR>`", "--", "0.3.0", "Read."]
    );
}

#[test]
fn row_names_reads_long_flags_aliases_and_the_positional() {
    assert_eq!(row_names("`-d`, `--device`"), vec!["device"]);
    assert_eq!(
        row_names("`--show-empty` (`--full`)"),
        vec!["show-empty", "full"]
    );
    assert_eq!(
        row_names("`--capture-tunnels[=PORTS]`"),
        vec!["capture-tunnels"]
    );
    assert_eq!(row_names("`<BPF_FILTER>...`"), vec!["<BPF_FILTER>"]);
}

#[test]
fn since_cell_ok_accepts_a_version_or_unreleased_only() {
    for good in ["0.3.0", "0.5.211", "10.0.12", "Unreleased"] {
        assert!(since_cell_ok(good), "{good}");
    }
    for bad in [
        "",
        "v0.5.1",
        "0.5",
        "0.5.1-beta",
        "unreleased",
        "0.5.x",
        "0..1",
    ] {
        assert!(!since_cell_ok(bad), "{bad}");
    }
}
