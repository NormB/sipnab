// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A changelog entry is an outline, not a paragraph.
//!
//! The reader of `CHANGELOG.md` decides whether to upgrade and what to do
//! after. An entry of several hundred words hides the answer, so each entry
//! has one shape:
//!
//! ```text
//! - **Lead: what changed, in the user's terms.**
//!   - Effect: what the user sees or can now do.
//!   - Do: what the user must do, with the command or setting.
//!   - Limit: one limit or caveat.
//!   - Docs: [page title](docs/page.md#heading).
//! ```
//!
//! [`violations`] reads the text and reports every entry that departs from
//! it, as `[section] lead: rule`. The rule is stated for people in
//! `docs/internals/build-ci-release.md`, under "The changelog".
//!
//! The file was converted from the newest release downward, in batches.
//! [`CONVERTED_DOWN_TO`] names the oldest converted release: `[Unreleased]`
//! and every release at or above it are judged, the older sections are not.
//! Each later batch lowers the constant, and it is the only place that names
//! the boundary.

use std::path::Path;

/// The oldest release section that is held to the outline format. Lower it
/// when the sections below it are converted.
const CONVERTED_DOWN_TO: (u32, u32, u32) = (0, 5, 240);

/// The `### ` headings a judged section may carry.
const KINDS: [&str; 6] = [
    "Added",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
];

/// The labels a sub-bullet may start with.
const LABELS: [&str; 5] = ["Effect", "Do", "Limit", "Docs", "Was"];

/// The label of a credit ("Requested by", "Reported by") that an old entry
/// already carries. A rewrite keeps it word for word, as the last
/// sub-bullet; it does not count toward [`SUB_BULLETS`] and has no word
/// limit. No entry gains or loses one.
const CREDIT_LABEL: &str = "Credit";

/// The most words a lead may hold.
const LEAD_WORDS: usize = 15;

/// The most words a sub-bullet may hold after its label.
const SUB_WORDS: usize = 25;

/// The most sub-bullets under one lead.
const SUB_BULLETS: usize = 5;

/// The most data rows of an entry's table.
const TABLE_ROWS: usize = 6;

type TestError = Box<dyn std::error::Error>;

/// `0.5.244` as numbers; `None` for `Unreleased` or anything else.
fn version(label: &str) -> Option<(u32, u32, u32)> {
    let mut numbers = label.split('.').map(str::parse::<u32>);
    let version = (
        numbers.next()?.ok()?,
        numbers.next()?.ok()?,
        numbers.next()?.ok()?,
    );
    numbers.next().is_none().then_some(version)
}

/// The number of words a reader sees in `text`: a link counts its title and
/// not its address.
fn words(text: &str) -> usize {
    let mut shown = String::new();
    let mut rest = text;
    while let Some(open) = rest.find('[') {
        let (before, from) = rest.split_at(open);
        shown.push_str(before);
        let link = from.find("](").and_then(|mid| {
            let title = from.get(1..mid)?;
            let after = from.get(mid + 2..)?;
            let close = after.find(')')?;
            Some((title, after.get(close + 1..)?))
        });
        match link {
            Some((title, after)) if !title.contains('[') => {
                shown.push_str(title);
                rest = after;
            }
            _ => {
                shown.push('[');
                rest = from.get(1..).unwrap_or_default();
            }
        }
    }
    shown.push_str(rest);
    shown.split_whitespace().count()
}

/// One entry while its lines are read.
struct Entry {
    /// The lead as written, without the bullet.
    lead: String,
    /// The labels of its sub-bullets, in order.
    labels: Vec<String>,
    /// The number of tables under it.
    tables: usize,
    /// The data rows of its last table.
    rows: usize,
    /// Whether the line before was a table row.
    in_table: bool,
}

/// What a reader of the report sees of a lead: its first 80 characters.
fn shown(lead: &str) -> String {
    lead.chars().take(80).collect()
}

/// The rules an entry breaks as a whole, once its last line is read.
fn close(section: &str, entry: Option<Entry>, out: &mut Vec<String>) {
    let Some(entry) = entry else { return };
    let mut fail = |rule: String| out.push(format!("[{section}] {}: {rule}", shown(&entry.lead)));
    if entry.tables == 0 && entry.labels.is_empty() {
        fail("the entry has no sub-bullets (1 to 5, or one table)".into());
    }
    let counted = entry.labels.iter().filter(|l| *l != CREDIT_LABEL).count();
    if counted > SUB_BULLETS {
        fail(format!(
            "the entry has {counted} sub-bullets (at most {SUB_BULLETS})"
        ));
    }
    let last = entry.labels.len().saturating_sub(1);
    if entry
        .labels
        .iter()
        .enumerate()
        .any(|(at, l)| l == CREDIT_LABEL && at != last)
    {
        fail("a `Credit:` sub-bullet is not the last sub-bullet of its entry".into());
    }
    if entry.tables > 1 {
        fail(format!(
            "the entry has {} tables (at most one)",
            entry.tables
        ));
    }
    if entry.rows > TABLE_ROWS {
        fail(format!(
            "the table has {} rows (at most {TABLE_ROWS})",
            entry.rows
        ));
    }
    let says_effect = entry.labels.iter().any(|l| l == "Effect" || l == "Was");
    if entry.tables == 0 && !entry.labels.is_empty() && !says_effect {
        fail("the entry has neither an `Effect:` nor a `Was:` sub-bullet".into());
    }
}

/// The rules the lead line breaks. `rest` is the line after `- `.
fn lead_rules(rest: &str) -> Vec<String> {
    let inner = rest
        .strip_prefix("**")
        .and_then(|r| r.strip_suffix("**"))
        .filter(|inner| !inner.contains("**") && !inner.trim().is_empty());
    let Some(inner) = inner else {
        return vec!["the lead line is not one bold lead and nothing else".into()];
    };
    let count = words(inner);
    if count > LEAD_WORDS {
        return vec![format!("the lead has {count} words (at most {LEAD_WORDS})")];
    }
    Vec::new()
}

/// The label of a sub-bullet and the rules it breaks. `rest` is the line
/// after its `  - `.
fn sub_rules(rest: &str) -> (Option<String>, Vec<String>) {
    let label = LABELS
        .iter()
        .chain(std::iter::once(&CREDIT_LABEL))
        .find(|label| rest.starts_with(&format!("{label}: ")));
    let Some(label) = label else {
        return (
            None,
            vec![format!(
                "a sub-bullet does not start with `Effect:`, `Do:`, `Limit:`, `Docs:` or `Was:`: {}",
                shown(rest)
            )],
        );
    };
    let text = rest.get(label.len() + 2..).unwrap_or_default();
    let mut rules = Vec::new();
    let count = words(text);
    if count == 0 {
        rules.push(format!("the `{label}:` sub-bullet is empty"));
    }
    if count > SUB_WORDS && *label != CREDIT_LABEL {
        rules.push(format!(
            "the `{label}:` sub-bullet has {count} words (at most {SUB_WORDS})"
        ));
    }
    if *label == "Docs" && !text.contains("](") {
        rules.push("the `Docs:` sub-bullet holds no link".into());
    }
    (Some((*label).to_string()), rules)
}

/// Every departure from the outline format in `[Unreleased]` and in each
/// release section at or above `marker`, as `[section] lead: rule`.
fn violations(changelog: &str, marker: (u32, u32, u32)) -> Vec<String> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut judged = false;
    let mut entry: Option<Entry> = None;
    for line in changelog.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            close(&section, entry.take(), &mut out);
            section = rest
                .strip_prefix('[')
                .and_then(|rest| rest.split(']').next())
                .unwrap_or_default()
                .to_string();
            judged = section == "Unreleased" || version(&section).is_some_and(|v| v >= marker);
            continue;
        }
        if !judged || line.trim().is_empty() {
            continue;
        }
        let lead = entry
            .as_ref()
            .map_or_else(|| "(no entry)".to_string(), |e| shown(&e.lead));
        let mut fail = |rule: String| out.push(format!("[{section}] {lead}: {rule}"));
        let was_table = entry.as_ref().is_some_and(|e| e.in_table);
        if let Some(open) = entry.as_mut() {
            open.in_table = false;
        }
        if let Some(kind) = line.strip_prefix("### ") {
            close(&section, entry.take(), &mut out);
            if !KINDS.contains(&kind) {
                out.push(format!(
                    "[{section}] ### {kind}: the heading is not one of {}",
                    KINDS.join(", ")
                ));
            }
        } else if let Some(rest) = line.strip_prefix("- ") {
            close(&section, entry.take(), &mut out);
            for rule in lead_rules(rest) {
                out.push(format!("[{section}] {}: {rule}", shown(rest)));
            }
            entry = Some(Entry {
                lead: rest.to_string(),
                labels: Vec::new(),
                tables: 0,
                rows: 0,
                in_table: false,
            });
        } else if let Some(rest) = line.strip_prefix("  - ") {
            let (label, rules) = sub_rules(rest);
            match entry.as_mut() {
                Some(open) => open.labels.push(label.unwrap_or_default()),
                None => fail("a sub-bullet stands under no lead".into()),
            }
            for rule in rules {
                fail(rule);
            }
        } else if let Some(row) = line.strip_prefix("  |") {
            let Some(open) = entry.as_mut() else {
                fail("a table stands under no lead".into());
                continue;
            };
            if !was_table {
                open.tables += 1;
                open.rows = 0;
            } else if !row.trim_start().starts_with('-') && !row.trim_start().starts_with(':') {
                open.rows += 1;
            }
            open.in_table = true;
        } else if line.starts_with(' ') || line.starts_with('\t') {
            if line.trim_start().starts_with("- ") {
                fail(format!(
                    "a third level of nesting, or a bullet indented by other than two spaces: {}",
                    shown(line.trim())
                ));
            } else {
                fail(format!(
                    "a paragraph or a continuation line under a bullet: {}",
                    shown(line.trim())
                ));
            }
        } else if line.starts_with("Not released.") || line.starts_with("**Held:** ") {
            close(&section, entry.take(), &mut out);
        } else {
            close(&section, entry.take(), &mut out);
            out.push(format!(
                "[{section}] (no entry): text that is neither a heading nor an entry: {}",
                shown(line)
            ));
        }
    }
    close(&section, entry.take(), &mut out);
    out
}

/// The violations of one `[Unreleased]` section whose body is `body`.
fn of(body: &str) -> Vec<String> {
    violations(
        &format!("# Changelog\n\n## [Unreleased]\n\n{body}"),
        (0, 0, 0),
    )
}

/// A complete entry under `### Fixed`.
const GOOD: &str = "### Fixed\n\n- **A capture on a bridge no longer stops at the first VLAN tag.**\n  \
                    - Was: the reader ended the capture with `unsupported link type`.\n  \
                    - Effect: tagged frames are read like untagged ones.\n  \
                    - Docs: [Capture on a bridge](docs/capture.md#capture-on-a-bridge).\n";

/// `count` words, `w1 w2 ...`.
fn text_of(count: usize) -> String {
    (1..=count)
        .map(|n| format!("w{n}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Assert that `body` breaks exactly one rule, whose report holds `rule`.
fn refused(body: &str, rule: &str) {
    let found = of(body);
    assert!(
        found.len() == 1 && found.iter().all(|line| line.contains(rule)),
        "expected one violation holding {rule:?}, found {found:?}"
    );
}

/// Assert that `body` breaks no rule.
fn accepted(body: &str) {
    let found = of(body);
    assert!(found.is_empty(), "expected no violation, found {found:?}");
}

// ── Success: the shapes the rule allows ─────────────────────────────────────

#[test]
fn success_a_complete_entry_passes() {
    accepted(GOOD);
}

#[test]
fn success_an_entry_with_one_effect_line_passes() {
    accepted(
        "### Changed\n\n- **The reader keeps tagged frames.**\n  - Effect: nothing is dropped.\n",
    );
}

#[test]
fn success_a_fix_with_was_alone_passes() {
    accepted("### Fixed\n\n- **The reader keeps tagged frames.**\n  - Was: it dropped them.\n");
}

#[test]
fn success_all_five_labels_pass() {
    accepted(
        "### Fixed\n\n- **The reader keeps tagged frames.**\n  - Was: it dropped them.\n  \
         - Effect: it keeps them.\n  - Do: run `sipnab --version`.\n  - Limit: one tag only.\n  \
         - Docs: [Capture](docs/capture.md).\n",
    );
}

#[test]
fn success_a_lead_of_fifteen_words_passes() {
    accepted(&format!(
        "### Added\n\n- **{}.**\n  - Effect: yes.\n",
        text_of(LEAD_WORDS)
    ));
}

#[test]
fn success_a_sub_bullet_of_twenty_five_words_passes() {
    accepted(&format!(
        "### Added\n\n- **A lead.**\n  - Effect: {}.\n",
        text_of(SUB_WORDS)
    ));
}

#[test]
fn success_each_allowed_heading_passes() {
    for kind in KINDS {
        accepted(&format!("### {kind}\n\n- **A lead.**\n  - Effect: yes.\n"));
    }
}

#[test]
fn success_several_entries_under_one_heading_pass() {
    accepted(
        "### Added\n\n- **One.**\n  - Effect: yes.\n- **Two.**\n  - Effect: yes.\n\n- **Three.**\n  \
         - Effect: yes.\n",
    );
}

#[test]
fn success_code_spans_in_the_lead_pass() {
    accepted("### Added\n\n- **`--tls-keylog` takes a directory.**\n  - Effect: yes.\n");
}

#[test]
fn success_a_table_in_place_of_sub_bullets_passes() {
    accepted(
        "### Changed\n\n- **The history files are smaller.**\n  | File | Bytes |\n  |---|---|\n  \
         | heartbeats | 62,048 |\n  | calls | 660,654 |\n",
    );
}

#[test]
fn success_a_table_with_a_docs_line_passes() {
    accepted(
        "### Changed\n\n- **The history files are smaller.**\n  | File | Bytes |\n  |---|---|\n  \
         | heartbeats | 62,048 |\n  - Docs: [Fleet](docs/fleet.md).\n",
    );
}

#[test]
fn success_a_table_of_six_rows_passes() {
    let rows: String = (1..=TABLE_ROWS)
        .map(|n| format!("  | r{n} | {n} |\n"))
        .collect();
    accepted(&format!(
        "### Changed\n\n- **Sizes.**\n  | File | Bytes |\n  |---|---|\n{rows}"
    ));
}

#[test]
fn success_a_docs_line_with_two_links_passes() {
    accepted(
        "### Added\n\n- **A lead.**\n  - Effect: yes.\n  \
         - Docs: [How-to](docs/mcp.md#search), [reference](docs/mcp-tools-core.md#search_messages).\n",
    );
}

#[test]
fn success_a_section_with_no_entries_passes() {
    accepted("");
}

#[test]
fn success_a_held_line_passes() {
    accepted(&format!(
        "**Held:** the release waits for the signing key.\n\n{GOOD}"
    ));
}

// ── Failure: each rule, broken once ─────────────────────────────────────────

#[test]
fn failure_a_lead_of_sixteen_words_is_refused() {
    refused(
        &format!(
            "### Added\n\n- **{}.**\n  - Effect: yes.\n",
            text_of(LEAD_WORDS + 1)
        ),
        "the lead has 16 words (at most 15)",
    );
}

#[test]
fn failure_a_lead_that_is_not_bold_is_refused() {
    refused(
        "### Added\n\n- A lead.\n  - Effect: yes.\n",
        "the lead line is not one bold lead and nothing else",
    );
}

#[test]
fn failure_prose_after_the_bold_lead_is_refused() {
    refused(
        "### Added\n\n- **A lead.** And a sentence after it.\n  - Effect: yes.\n",
        "the lead line is not one bold lead and nothing else",
    );
}

#[test]
fn failure_an_entry_without_sub_bullets_is_refused() {
    refused(
        "### Added\n\n- **A lead.**\n",
        "the entry has no sub-bullets",
    );
}

#[test]
fn failure_six_sub_bullets_are_refused() {
    refused(
        "### Added\n\n- **A lead.**\n  - Effect: a.\n  - Do: b.\n  - Limit: c.\n  - Limit: d.\n  \
         - Limit: e.\n  - Docs: [f](docs/f.md).\n",
        "the entry has 6 sub-bullets (at most 5)",
    );
}

#[test]
fn failure_a_sub_bullet_without_a_label_is_refused() {
    refused(
        "### Added\n\n- **A lead.**\n  - Effect: yes.\n  - It also does this.\n",
        "a sub-bullet does not start with `Effect:`",
    );
}

#[test]
fn failure_an_unknown_label_is_refused() {
    refused(
        "### Added\n\n- **A lead.**\n  - Effect: yes.\n  - Note: this too.\n",
        "a sub-bullet does not start with `Effect:`",
    );
}

#[test]
fn failure_a_sub_bullet_of_twenty_six_words_is_refused() {
    refused(
        &format!(
            "### Added\n\n- **A lead.**\n  - Effect: {}.\n",
            text_of(SUB_WORDS + 1)
        ),
        "the `Effect:` sub-bullet has 26 words (at most 25)",
    );
}

#[test]
fn failure_an_entry_with_neither_effect_nor_was_is_refused() {
    refused(
        "### Added\n\n- **A lead.**\n  - Do: run it.\n  - Docs: [f](docs/f.md).\n",
        "neither an `Effect:` nor a `Was:`",
    );
}

#[test]
fn failure_a_third_level_is_refused() {
    refused(
        "### Added\n\n- **A lead.**\n  - Effect: yes.\n    - Deeper.\n",
        "a third level of nesting",
    );
}

#[test]
fn failure_a_paragraph_under_a_bullet_is_refused() {
    refused(
        "### Added\n\n- **A lead.**\n  - Effect: yes.\n\n  A paragraph of prose.\n",
        "a paragraph or a continuation line under a bullet",
    );
}

#[test]
fn failure_a_continuation_line_is_refused() {
    refused(
        "### Added\n\n- **A lead.**\n  - Effect: the first half\n    and the second half.\n",
        "a paragraph or a continuation line under a bullet",
    );
}

#[test]
fn failure_a_docs_line_without_a_link_is_refused() {
    refused(
        "### Added\n\n- **A lead.**\n  - Effect: yes.\n  - Docs: the fleet page.\n",
        "the `Docs:` sub-bullet holds no link",
    );
}

#[test]
fn failure_a_heading_outside_the_six_is_refused() {
    refused(
        "### Dependencies\n\n- **A lead.**\n  - Effect: yes.\n",
        "### Dependencies: the heading is not one of Added, Changed, Deprecated, Removed, Fixed, Security",
    );
}

#[test]
fn failure_a_table_of_seven_rows_is_refused() {
    let rows: String = (1..=TABLE_ROWS + 1)
        .map(|n| format!("  | r{n} | {n} |\n"))
        .collect();
    refused(
        &format!("### Changed\n\n- **Sizes.**\n  | File | Bytes |\n  |---|---|\n{rows}"),
        "the table has 7 rows (at most 6)",
    );
}

#[test]
fn failure_two_tables_are_refused() {
    refused(
        "### Changed\n\n- **Sizes.**\n  | A | B |\n  |---|---|\n  | a | 1 |\n  - Limit: one.\n  \
         | C | D |\n  |---|---|\n  | c | 2 |\n",
        "the entry has 2 tables (at most one)",
    );
}

#[test]
fn failure_a_paragraph_at_the_margin_is_refused() {
    refused(
        &format!("This release fixes two defects.\n\n{GOOD}"),
        "text that is neither a heading nor an entry",
    );
}

#[test]
fn failure_an_empty_sub_bullet_is_refused() {
    refused(
        "### Added\n\n- **A lead.**\n  - Effect: yes.\n  - Limit: \n",
        "the `Limit:` sub-bullet is empty",
    );
}

#[test]
fn failure_the_report_names_the_section_the_lead_and_the_rule() {
    let found = violations(
        "## [0.5.250] - 2026-11-13\n\n### Added\n\n- **A lead.**\n",
        (0, 5, 250),
    );
    assert_eq!(
        found,
        vec![
            "[0.5.250] **A lead.**: the entry has no sub-bullets (1 to 5, or one table)"
                .to_string()
        ],
        "the report is `[section] lead: rule`"
    );
}

#[test]
fn failure_every_broken_entry_is_reported() {
    let found = of("### Added\n\n- One.\n- **Two.**\n- **Three.**\n  - Effect: yes.\n");
    assert_eq!(
        found.len(),
        3,
        "an unbold lead, and two entries without sub-bullets: {found:?}"
    );
}

// ── Edge: boundaries of the marker and of the counting ──────────────────────

const OLD: &str =
    "- A paragraph entry of the old kind. It has prose after the lead.\n  More prose.\n";

#[test]
fn edge_a_section_below_the_marker_is_not_judged() {
    let log = format!("## [0.5.249] - 2026-11-12\n\n### Internal\n\n{OLD}");
    assert_eq!(
        violations(&log, (0, 5, 250)),
        Vec::<String>::new(),
        "0.5.249 is below the marker 0.5.250"
    );
}

#[test]
fn edge_the_section_at_the_marker_is_judged() {
    let log = format!("## [0.5.250] - 2026-11-13\n\n### Fixed\n\n{OLD}");
    assert!(
        !violations(&log, (0, 5, 250)).is_empty(),
        "0.5.250 is the marker and is judged"
    );
}

#[test]
fn edge_a_section_above_the_marker_is_judged() {
    let log = format!("## [0.5.251] - 2026-11-13\n\n### Fixed\n\n{OLD}");
    assert!(
        !violations(&log, (0, 5, 250)).is_empty(),
        "0.5.251 is above the marker and is judged"
    );
}

#[test]
fn edge_unreleased_is_judged_whatever_the_marker() {
    let log = format!("## [Unreleased]\n\n### Fixed\n\n{OLD}");
    assert!(
        !violations(&log, (9, 9, 9)).is_empty(),
        "[Unreleased] is always judged"
    );
}

#[test]
fn edge_versions_compare_as_numbers() {
    let log = format!("## [0.5.99] - 2026-01-01\n\n### Fixed\n\n{OLD}");
    assert_eq!(
        violations(&log, (0, 5, 100)),
        Vec::<String>::new(),
        "0.5.99 is below 0.5.100"
    );
}

#[test]
fn edge_judging_resumes_and_stops_at_each_heading() {
    let log = format!(
        "## [Unreleased]\n\n{GOOD}\n## [0.5.250] - 2026-11-13\n\n{GOOD}\n## [0.5.249] - 2026-11-12\n\n{OLD}"
    );
    assert_eq!(
        violations(&log, (0, 5, 250)),
        Vec::<String>::new(),
        "two converted sections above an old one"
    );
}

#[test]
fn edge_text_before_the_first_heading_is_not_judged() {
    assert_eq!(
        violations(
            "# Changelog\n\nAll notable changes.\n\n- a list in the preamble\n",
            (0, 0, 0)
        ),
        Vec::<String>::new(),
        "the preamble is no release section"
    );
}

#[test]
fn edge_a_link_counts_its_title_and_not_its_address() {
    assert_eq!(
        words("See [the fleet page](docs/fleet.md#a-very-long-anchor) now."),
        5,
        "see, the, fleet, page, now"
    );
}

#[test]
fn edge_a_bracket_that_is_no_link_is_counted_as_text() {
    assert_eq!(
        words("the `[limits]` table and a [dangling bracket"),
        7,
        "seven words separated by spaces"
    );
}

#[test]
fn edge_the_label_is_not_counted() {
    accepted(&format!(
        "### Added\n\n- **A lead.**\n  - Effect: yes.\n  - Limit: {}.\n",
        text_of(SUB_WORDS)
    ));
}

#[test]
fn edge_a_long_link_address_does_not_break_the_word_limit() {
    accepted(&format!(
        "### Added\n\n- **A lead.**\n  - Effect: yes.\n  - Docs: [{}](docs/errors.md#{}).\n",
        text_of(SUB_WORDS),
        "a-".repeat(200)
    ));
}

#[test]
fn edge_a_not_released_note_passes() {
    let log =
        "## [0.5.250] - 2026-11-13\n\nNot released. These changes first shipped in 0.5.251.\n";
    assert_eq!(
        violations(log, (0, 5, 250)),
        Vec::<String>::new(),
        "release_completeness_test requires this note"
    );
}

#[test]
fn edge_a_sub_bullet_under_no_lead_is_refused() {
    refused(
        "### Added\n\n  - Effect: yes.\n",
        "a sub-bullet stands under no lead",
    );
}

#[test]
fn edge_a_label_without_a_space_is_refused() {
    refused(
        "### Added\n\n- **A lead.**\n  - Effect: yes.\n  - Do:run it.\n",
        "a sub-bullet does not start with `Effect:`",
    );
}

#[test]
fn edge_a_lead_of_two_bold_spans_is_refused() {
    refused(
        "### Added\n\n- **A lead** and **more.**\n  - Effect: yes.\n",
        "the lead line is not one bold lead and nothing else",
    );
}

#[test]
fn edge_an_empty_bold_lead_is_refused() {
    refused(
        "### Added\n\n- ****\n  - Effect: yes.\n",
        "the lead line is not one bold lead and nothing else",
    );
}

#[test]
fn edge_a_table_separator_is_not_a_row() {
    let found = of("### Changed\n\n- **Sizes.**\n  | A | B |\n  | :--- | ---: |\n  | a | 1 |\n");
    assert_eq!(
        found,
        Vec::<String>::new(),
        "one header, one separator, one row"
    );
}

#[test]
fn edge_a_heading_with_a_suffix_is_refused() {
    refused(
        "### Added - with a subtitle\n\n- **A lead.**\n  - Effect: yes.\n",
        "the heading is not one of",
    );
}

#[test]
fn edge_the_last_entry_of_the_file_is_closed() {
    let found = violations("## [Unreleased]\n\n### Added\n\n- **A lead.**", (0, 0, 0));
    assert_eq!(
        found.len(),
        1,
        "the entry at the end of the file has no sub-bullets: {found:?}"
    );
}

// ── A credit an old entry carries ───────────────────────────────────────────

/// A credit line as an old entry carries one.
const CREDIT: &str =
    "  - Credit: Requested by A. Person ([@handle](https://example.com/handle)).\n";

#[test]
fn success_a_credit_as_the_last_sub_bullet_passes() {
    accepted(&format!(
        "### Added\n\n- **A lead.**\n  - Effect: yes.\n{CREDIT}"
    ));
}

#[test]
fn success_five_sub_bullets_and_a_credit_pass() {
    accepted(&format!(
        "### Fixed\n\n- **A lead.**\n  - Was: a.\n  - Effect: b.\n  - Do: c.\n  - Limit: d.\n  \
         - Docs: [e](docs/e.md).\n{CREDIT}"
    ));
}

#[test]
fn edge_a_credit_is_kept_word_for_word_past_the_word_limit() {
    accepted(&format!(
        "### Added\n\n- **A lead.**\n  - Effect: yes.\n  - Credit: {}.\n",
        text_of(SUB_WORDS + 10)
    ));
}

#[test]
fn failure_a_credit_before_another_sub_bullet_is_refused() {
    refused(
        &format!("### Added\n\n- **A lead.**\n{CREDIT}  - Effect: yes.\n"),
        "a `Credit:` sub-bullet is not the last",
    );
}

#[test]
fn failure_two_credits_are_refused() {
    refused(
        &format!("### Added\n\n- **A lead.**\n  - Effect: yes.\n{CREDIT}{CREDIT}"),
        "a `Credit:` sub-bullet is not the last",
    );
}

#[test]
fn failure_a_credit_alone_is_refused() {
    refused(
        &format!("### Added\n\n- **A lead.**\n{CREDIT}"),
        "neither an `Effect:` nor a `Was:`",
    );
}

#[test]
fn failure_six_sub_bullets_and_a_credit_are_refused() {
    refused(
        &format!(
            "### Added\n\n- **A lead.**\n  - Effect: a.\n  - Do: b.\n  - Limit: c.\n  - Limit: d.\n  \
             - Limit: e.\n  - Docs: [f](docs/f.md).\n{CREDIT}"
        ),
        "the entry has 6 sub-bullets (at most 5)",
    );
}

// ── The real file ───────────────────────────────────────────────────────────

fn changelog() -> Result<String, TestError> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("CHANGELOG.md");
    Ok(std::fs::read_to_string(path)?)
}

/// `[Unreleased]` and every release section from [`CONVERTED_DOWN_TO`] up
/// hold only outline entries.
#[test]
fn every_judged_section_of_the_changelog_is_an_outline() -> Result<(), TestError> {
    let found = violations(&changelog()?, CONVERTED_DOWN_TO);
    assert!(
        found.is_empty(),
        "CHANGELOG.md: {} entries depart from the outline format \
         (docs/internals/build-ci-release.md, \"The changelog\"). Each line is \
         `[section] lead: rule`:\n{}",
        found.len(),
        found.join("\n")
    );
    Ok(())
}

/// The marker names a section the file has, and the judged part holds
/// entries: a marker above every release would leave only `[Unreleased]`
/// judged without anyone seeing it.
#[test]
fn the_marker_names_a_release_section_that_holds_entries() -> Result<(), TestError> {
    let (major, minor, patch) = CONVERTED_DOWN_TO;
    let heading = format!("## [{major}.{minor}.{patch}] - ");
    let text = changelog()?;
    let at = text
        .find(&heading)
        .ok_or_else(|| format!("CHANGELOG.md has no `{heading}` heading"))?;
    let body = text.get(at..).unwrap_or_default();
    let end = body
        .get(3..)
        .and_then(|rest| rest.find("\n## "))
        .map_or(body.len(), |i| i + 3);
    let entries = body
        .get(..end)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("- **"))
        .count();
    assert!(
        entries > 0,
        "the marker section {major}.{minor}.{patch} holds no entry"
    );
    Ok(())
}

/// The sections below the marker are still old: when this fails, the marker
/// was left behind by a batch and must be lowered to the oldest converted
/// section.
#[test]
fn the_marker_is_the_oldest_converted_section() -> Result<(), TestError> {
    let text = changelog()?;
    let mut below: Option<&str> = None;
    for line in text.lines() {
        let Some(label) = line
            .strip_prefix("## [")
            .and_then(|rest| rest.split(']').next())
        else {
            continue;
        };
        if version(label).is_some_and(|v| v < CONVERTED_DOWN_TO) {
            below = Some(label);
            break;
        }
    }
    let Some(below) = below else {
        return Ok(());
    };
    let next = version(below).ok_or("a version")?;
    let one = violations(&text, next)
        .into_iter()
        .filter(|line| line.starts_with(&format!("[{below}]")))
        .count();
    assert!(
        one > 0,
        "section {below}, the first below the marker, already passes the format: \
         lower CONVERTED_DOWN_TO to the oldest converted section"
    );
    Ok(())
}
