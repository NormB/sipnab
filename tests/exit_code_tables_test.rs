// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The exit-code tables of `docs/cli-reference.md` and `docs/errors.md` list
//! the same codes, and every code sipnab defines as a constant is in both.
//!
//! The man page's EXIT STATUS is generated from the CLI reference's table
//! (tests/man_page_test.rs), so these two tables are the ones a change can
//! leave apart. A code added to one table and not the other, or a constant
//! with no row, fails here.
#![cfg(feature = "native")]

use std::collections::BTreeSet;

type TestError = Box<dyn std::error::Error>;

/// The codes the tables list, as of the code-6 row (2026-11-26).
const DOCUMENTED: [i32; 9] = [0, 1, 2, 3, 4, 6, 101, 129, 130];

/// The codes in the `## Exit codes` section of `markdown`: each table row
/// whose first cell is a code in backticks.
fn exit_codes(markdown: &str) -> Result<BTreeSet<i32>, TestError> {
    let start = markdown
        .find("\n## Exit codes\n")
        .ok_or("no `## Exit codes` heading")?;
    let section = &markdown[start + 1..];
    let end = section[3..].find("\n## ").map_or(section.len(), |i| i + 3);
    let mut codes = BTreeSet::new();
    for line in section[..end].lines() {
        let Some(rest) = line.strip_prefix("| `") else {
            continue;
        };
        let Some((code, _)) = rest.split_once('`') else {
            continue;
        };
        if let Ok(code) = code.parse::<i32>()
            && !codes.insert(code)
        {
            return Err(format!("code {code} has two rows").into());
        }
    }
    Ok(codes)
}

/// Read a docs page of this repository.
fn page(path: &str) -> Result<String, TestError> {
    Ok(std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path),
    )?)
}

/// A table section with the given row codes, for the parser's own tests.
fn table(codes: &[&str]) -> String {
    let rows: Vec<String> = codes.iter().map(|c| format!("| `{c}` | x |")).collect();
    format!(
        "# T\n\n## Exit codes\n\n| Code | Meaning |\n|------|------|\n{}\n\n## Next\n\n| `77` | y |\n",
        rows.join("\n")
    )
}

// ── Success ──────────────────────────────────────────────────────────

/// The two tables list the same codes.
#[test]
fn s_the_two_tables_agree() -> Result<(), TestError> {
    let reference = exit_codes(&page("docs/cli-reference.md")?)?;
    let errors = exit_codes(&page("docs/errors.md")?)?;
    assert_eq!(reference, errors, "cli-reference.md and errors.md");
    Ok(())
}

/// The CLI reference lists exactly the documented codes.
#[test]
fn s_the_reference_lists_the_documented_codes() -> Result<(), TestError> {
    let reference = exit_codes(&page("docs/cli-reference.md")?)?;
    assert_eq!(
        reference,
        DOCUMENTED.into_iter().collect::<BTreeSet<_>>(),
        "cli-reference.md exit codes"
    );
    Ok(())
}

/// The unwritable-output code has a row in both tables.
#[test]
fn s_the_unwritable_code_is_documented() -> Result<(), TestError> {
    let code = sipnab::output::stdout::UNWRITABLE_EXIT_CODE;
    for path in ["docs/cli-reference.md", "docs/errors.md"] {
        assert!(
            exit_codes(&page(path)?)?.contains(&code),
            "{path} lists {code}"
        );
    }
    Ok(())
}

/// The low-disk and hang-up codes have a row in both tables.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn s_the_signal_codes_are_documented() -> Result<(), TestError> {
    for code in [
        sipnab::signals::LOW_DISK_EXIT_CODE,
        sipnab::signals::HANGUP_EXIT_CODE,
    ] {
        for path in ["docs/cli-reference.md", "docs/errors.md"] {
            assert!(
                exit_codes(&page(path)?)?.contains(&code),
                "{path} lists {code}"
            );
        }
    }
    Ok(())
}

// ── Failure: the parser and the comparison catch a drift ─────────────

/// A table that lacks a row differs from one that has it.
#[test]
fn f_a_missing_row_is_seen() -> Result<(), TestError> {
    let full = exit_codes(&table(&["0", "1", "6"]))?;
    let short = exit_codes(&table(&["0", "1"]))?;
    assert_ne!(full, short, "the missing 6 shows");
    Ok(())
}

/// A code with two rows is refused.
#[test]
fn f_a_repeated_row_is_refused() {
    assert!(
        exit_codes(&table(&["0", "6", "6"])).is_err(),
        "two rows for 6"
    );
}

/// A page with no exit-code section is refused.
#[test]
fn f_no_section_is_refused() {
    assert!(exit_codes("# T\n\n| `0` | x |\n").is_err(), "no heading");
}

// ── Edge cases ───────────────────────────────────────────────────────

/// Rows after the next heading are not part of the table.
#[test]
fn e_rows_after_the_section_are_not_read() -> Result<(), TestError> {
    let codes = exit_codes(&table(&["0"]))?;
    assert!(!codes.contains(&77), "the next section's row is not read");
    Ok(())
}

/// A row whose first cell is not a number is not a code.
#[test]
fn e_a_non_numeric_cell_is_not_a_code() -> Result<(), TestError> {
    let codes = exit_codes(&table(&["0", "NAME"]))?;
    assert_eq!(codes, BTreeSet::from([0]), "only the number");
    Ok(())
}

/// The section can be the last one on its page.
#[test]
fn e_the_section_can_end_the_page() -> Result<(), TestError> {
    let codes = exit_codes("# T\n\n## Exit codes\n\n| `0` | x |\n| `6` | y |\n")?;
    assert_eq!(codes, BTreeSet::from([0, 6]), "both rows");
    Ok(())
}
