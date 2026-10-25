// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The answers the query surfaces share.
//!
//! A query capability (the call-volume histogram, the group-by counts, the
//! talker ranking and the rest of `docs/design/par5-cli-queries.md`) has one
//! answer type and one function that builds it from the stores. The REST
//! route serializes that answer, and the CLI query flag prints it: as a table,
//! as the same table in Markdown under `--markdown`, or under `--json` as the
//! serialized answer on one line. The types live here, outside the `api`
//! feature, because the CLI needs them in every build; the REST schema
//! re-exports them under their old names, so the OpenAPI document is unchanged.
//!
//! [`table`] is the one table renderer those answers share.

use std::fmt::Write as _;

use crate::output::ReportFormat;

pub mod aggregate;
pub mod compare;
pub mod correlated;
pub mod rates;
pub mod talkers;
pub mod timeline;
pub mod tree;

/// Whether `key` is one of `dims`, the dimensions a group-by answer accepts.
///
/// # Errors
///
/// The refusal every group-by surface gives for any other key, listing the
/// real ones. `narrow_with` names how the surface narrows a count instead of
/// adding a second dimension: `` `filter` `` on REST, `--filter` on the CLI.
pub fn check_dimension_in(key: &str, dims: &[&str], narrow_with: &str) -> Result<(), String> {
    if dims.contains(&key) {
        Ok(())
    } else {
        Err(format!(
            "cannot group by '{key}'; one of: {}. One dimension only — narrow \
             with {narrow_with} rather than adding a second.",
            dims.join(", ")
        ))
    }
}

/// How many rows a ranked answer keeps when the caller names no limit:
/// REST's default page (`top_n`, `limit`) and the CLI's `--top`.
pub const DEFAULT_ROWS: usize = 50;

/// `n` and `noun`, plural unless `n` is one: `es` after a noun ending in
/// `s` ("2 timing guesses"), `s` otherwise.
#[must_use]
pub(crate) fn plural(n: u64, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else if noun.ends_with('s') {
        format!("{n} {noun}es")
    } else {
        format!("{n} {noun}s")
    }
}

/// `s` with every control character (a terminal escape sequence carried in a
/// captured header) replaced by U+FFFD, so a value read off the wire cannot
/// drive the reader's terminal. Every cell [`table`] prints goes through it,
/// and so must any wire text an answer prints outside a table.
#[must_use]
pub fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

/// Render `rows` under `headers` as a table in `format`.
///
/// Text: the header line, a rule of dashes as wide as the table, then one line
/// per row, each column padded to its widest cell and the last cell unpadded.
/// Markdown: a pipe table, with `|` inside a cell escaped. Every control
/// character in a cell (a terminal escape sequence carried in a captured
/// header) becomes U+FFFD, so a value read off the wire cannot drive the
/// reader's terminal.
///
/// # Arguments
///
/// * `format` — [`ReportFormat::Markdown`] for a pipe table; any other format
///   renders text.
/// * `headers` — the column names.
/// * `rows` — the cells, one `Vec` per row, each as long as `headers`.
#[must_use]
pub fn table(format: ReportFormat, headers: &[&str], rows: &[Vec<String>]) -> String {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(|c| clean(c)).collect())
        .collect();
    let mut out = String::new();
    if matches!(format, ReportFormat::Markdown) {
        let cell = |s: &str| s.replace('|', "\\|");
        let line = |cells: Vec<String>| format!("| {} |\n", cells.join(" | "));
        out.push_str(&line(headers.iter().map(|h| cell(h)).collect()));
        let _ = writeln!(out, "|{}", "---|".repeat(headers.len()));
        for r in &rows {
            out.push_str(&line(r.iter().map(|c| cell(c)).collect()));
        }
        return out;
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in &rows {
        for (w, c) in widths.iter_mut().zip(r) {
            *w = (*w).max(c.chars().count());
        }
    }
    let line = |cells: &[String]| -> String {
        let mut s = String::new();
        for (i, (c, w)) in cells.iter().zip(&widths).enumerate() {
            if i > 0 {
                s.push_str("  ");
            }
            if i + 1 == cells.len() {
                s.push_str(c);
            } else {
                let _ = write!(s, "{c:<w$}");
            }
        }
        s.push('\n');
        s
    };
    let header: Vec<String> = headers.iter().map(|h| (*h).to_string()).collect();
    out.push_str(&line(&header));
    let rule = widths.iter().sum::<usize>() + 2 * widths.len().saturating_sub(1);
    let _ = writeln!(out, "{}", "-".repeat(rule));
    for r in &rows {
        out.push_str(&line(r));
    }
    out
}

/// The shared renderer, driven directly.
#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<Vec<String>> {
        vec![
            vec!["2023-11-14T22:13:20+00:00".into(), "1".into()],
            vec!["x".into(), "12".into()],
        ]
    }

    /// Text pads every column but the last to its widest cell, under a rule
    /// as wide as the table.
    #[test]
    fn text_pads_columns_to_the_widest_cell() {
        let out = table(ReportFormat::Text, &["Start", "Dialogs"], &rows());
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], format!("Start{}Dialogs", " ".repeat(22)));
        assert_eq!(lines[1], "-".repeat(34));
        assert_eq!(lines[2], "2023-11-14T22:13:20+00:00  1");
        assert_eq!(lines[3], format!("x{}12", " ".repeat(26)));
    }

    /// Markdown is a pipe table whose cells escape `|`.
    #[test]
    fn markdown_is_a_pipe_table_with_escaped_pipes() {
        let out = table(
            ReportFormat::Markdown,
            &["Value", "Count"],
            &[vec!["a|b".into(), "3".into()]],
        );
        assert_eq!(out, "| Value | Count |\n|---|---|\n| a\\|b | 3 |\n");
    }

    /// A control character read off the wire never reaches the terminal.
    #[test]
    fn control_characters_become_the_replacement_character() {
        let out = table(
            ReportFormat::Text,
            &["UA"],
            &[vec!["evil\u{1b}[2Jua".into()]],
        );
        assert!(!out.contains('\u{1b}'), "{out:?}");
        assert!(out.contains("evil\u{FFFD}[2Jua"), "{out:?}");
    }

    /// One is singular, any other count plural, `es` after an `s`.
    #[test]
    fn plural_takes_es_after_s() {
        assert_eq!(plural(1, "guess"), "1 guess");
        assert_eq!(plural(2, "timing guess"), "2 timing guesses");
        assert_eq!(plural(0, "leg"), "0 legs");
    }

    /// No rows is the header and the rule, never an error.
    #[test]
    fn no_rows_is_the_header_and_rule() {
        let out = table(ReportFormat::Text, &["A", "Bb"], &[]);
        assert_eq!(out, "A  Bb\n-----\n");
    }
}
