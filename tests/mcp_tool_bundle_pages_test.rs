// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The MCP tool reference has one page per bundle, and the code decides which
//! page a tool is on.
//!
//! # Why this file exists
//!
//! `docs/mcp-tools.md` documented every MCP tool on one page of about 6,700
//! lines. The server already groups its tools into bundles
//! (`src/mcp_profile.rs`, [`sipnab::mcp_profile::BUNDLES`]), and an operator
//! loads a bundle with `--mcp-tools`, so the reference now follows the same
//! grouping: `docs/mcp-tools.md` is an index, and `docs/mcp-tools-<bundle>.md`
//! documents the tools of one bundle.
//!
//! Bundle membership is a fact in code. A page that disagrees with it sends a
//! reader who loaded `--mcp-tools signaling` looking for a tool that bundle
//! does not register. So this gate reads `BUNDLES` and fails when:
//!
//! * a tool's `###` section is on a page other than its bundle's page, or on
//!   no page at all;
//! * a page documents a tool that no bundle holds (a tool in NO bundle, which
//!   `the_bundle_catalog_is_exactly_the_registered_tools` in
//!   `src/mcp/server.rs` reports from the code side);
//! * a tool is listed in TWO bundles. `src/mcp_profile.rs` says every tool is
//!   in exactly one, and its unit test holds that; a tool in two would need a
//!   section on two pages, which is two answers to one question, so this gate
//!   refuses it as well rather than guessing which page wins;
//! * the index's bundle table or its alphabetical lookup names the wrong page,
//!   skips a tool, or lists one twice;
//! * a `docs/mcp-tools-*.md` page is left over for a bundle the code no longer
//!   has.
//!
//! Moving a tool between bundles in code therefore turns this gate red until
//! its section moves to the new page and the index row follows it.
//!
//! Gated on `mcp`: the pages document the tools that feature registers.

#![cfg(feature = "mcp")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[path = "support/markdown.rs"]
mod markdown;
#[path = "support/mcp_reference.rs"]
mod mcp_reference;

use mcp_reference::{INDEX, bundle_file, bundle_page};

/// Any error, boxed, so `?` works on I/O and lookup failures alike.
type TestError = Box<dyn std::error::Error>;

/// The header of the index's bundle table.
const BUNDLE_TABLE_HEADER: &str = "| Bundle | Tools | What its tools answer |";
/// The header of the index's alphabetical tool lookup.
const LOOKUP_HEADER: &str = "| Tool | Bundle | Returns |";
/// The header of the tool table at the top of each bundle page.
const PAGE_TABLE_HEADER: &str = "| Tool | Parameters | Returns |";

/// The names of the `` ### `tool` `` sections in `md`, in document order.
///
/// Fenced blocks are blanked first: the reference renders a sample call report
/// whose own headings must not count as sections.
fn tool_sections(md: &str) -> Vec<String> {
    markdown::blank_fences(md)
        .lines()
        .filter_map(|l| l.strip_prefix("### "))
        .filter_map(|t| t.trim().strip_prefix('`')?.strip_suffix('`'))
        .map(str::to_string)
        .collect()
}

/// The body rows of the table opened by the line `header`, each split into
/// its trimmed cells. `None` when no line equals `header`.
fn table_rows(md: &str, header: &str) -> Option<Vec<Vec<String>>> {
    let mut lines = md.lines().skip_while(|l| l.trim_end() != header);
    lines.next()?; // the header
    lines.next()?; // the separator
    Some(
        lines
            .take_while(|l| l.starts_with('|'))
            .map(|l| {
                l.trim()
                    .trim_start_matches('|')
                    .trim_end_matches('|')
                    .split(" | ")
                    .map(|c| c.trim().to_string())
                    .collect()
            })
            .collect(),
    )
}

/// `tool -> every bundle listing it`.
fn membership<'a>(bundles: &[(&'a str, &'a [&'a str])]) -> BTreeMap<&'a str, Vec<&'a str>> {
    let mut out: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (bundle, tools) in bundles {
        for tool in *tools {
            out.entry(tool).or_default().push(bundle);
        }
    }
    out
}

/// Everything wrong with the bundle pages, given the bundle table and each
/// page's text (`bundle -> text`, `None` for a page that does not exist).
///
/// Pure, so the controls below can drive it with a tree that is wrong on
/// purpose.
fn page_problems(
    bundles: &[(&str, &[&str])],
    pages: &BTreeMap<String, Option<String>>,
    index: &str,
) -> Vec<String> {
    let mut problems = Vec::new();
    let members = membership(bundles);
    for (tool, owners) in &members {
        if owners.len() > 1 {
            problems.push(format!(
                "`{tool}` is in {} bundles {owners:?}; a tool has one page, so it \
                 must be in exactly one bundle",
                owners.len()
            ));
        }
    }
    for tool in tool_sections(index) {
        problems.push(format!(
            "{INDEX} has a section for `{tool}`; tool sections belong on their \
             bundle's page, and the index only links to them"
        ));
    }
    for (bundle, tools) in bundles {
        let page = bundle_page(bundle);
        let Some(Some(text)) = pages.get(*bundle) else {
            problems.push(format!("bundle `{bundle}` has no page: {page} is missing"));
            continue;
        };
        let found = tool_sections(text);
        let mut seen = BTreeSet::new();
        for tool in &found {
            if !seen.insert(tool.as_str()) {
                problems.push(format!("{page} has two sections for `{tool}`"));
            }
            match members.get(tool.as_str()) {
                None => problems.push(format!(
                    "{page} documents `{tool}`, which no bundle in \
                     src/mcp_profile.rs holds"
                )),
                Some(owners) if !owners.contains(bundle) => problems.push(format!(
                    "{page} documents `{tool}`, which src/mcp_profile.rs puts in \
                     {owners:?}; move the section to {}",
                    bundle_page(owners[0])
                )),
                Some(_) => {}
            }
        }
        for tool in *tools {
            if !seen.contains(tool) {
                problems.push(format!(
                    "`{tool}` is in bundle `{bundle}` and {page} has no \
                     `### `{tool}`` section"
                ));
            }
        }
        match table_rows(text, PAGE_TABLE_HEADER) {
            None => problems.push(format!("{page} has no `{PAGE_TABLE_HEADER}` table")),
            Some(rows) => {
                let listed: BTreeSet<String> = rows
                    .iter()
                    .filter_map(|r| r.first())
                    .filter_map(|c| {
                        c.strip_prefix("[`")?
                            .split_once('`')
                            .map(|(n, _)| n.to_string())
                    })
                    .collect();
                let want: BTreeSet<String> = tools.iter().map(|t| (*t).to_string()).collect();
                if listed != want {
                    problems.push(format!(
                        "{page}'s tool table lists {listed:?}; bundle `{bundle}` \
                         holds {want:?}"
                    ));
                }
            }
        }
    }
    problems
}

/// Everything wrong with the index's bundle table and alphabetical lookup.
fn index_problems(bundles: &[(&str, &[&str])], index: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let members = membership(bundles);

    match table_rows(index, BUNDLE_TABLE_HEADER) {
        None => problems.push(format!("{INDEX} has no `{BUNDLE_TABLE_HEADER}` table")),
        Some(rows) => {
            let got: Vec<(String, String)> = rows
                .iter()
                .map(|r| {
                    (
                        r.first().cloned().unwrap_or_default(),
                        r.get(1).cloned().unwrap_or_default(),
                    )
                })
                .collect();
            let want: Vec<(String, String)> = bundles
                .iter()
                .map(|(b, t)| (format!("[`{b}`]({})", bundle_file(b)), t.len().to_string()))
                .collect();
            if got != want {
                problems.push(format!(
                    "{INDEX}'s bundle table reads {got:?}; src/mcp_profile.rs \
                     gives {want:?} (bundle linked to its page, then its tool count, \
                     in BUNDLES order)"
                ));
            }
        }
    }

    let Some(rows) = table_rows(index, LOOKUP_HEADER) else {
        problems.push(format!("{INDEX} has no `{LOOKUP_HEADER}` lookup table"));
        return problems;
    };
    let mut listed: Vec<String> = Vec::new();
    for row in &rows {
        let tool_cell = row.first().map_or("", String::as_str);
        let bundle_cell = row.get(1).map_or("", String::as_str);
        let Some((name, target)) = tool_cell
            .strip_prefix("[`")
            .and_then(|s| s.split_once("`]("))
            .and_then(|(n, rest)| {
                rest.strip_suffix(')')
                    .map(|t| (n.to_string(), t.to_string()))
            })
        else {
            problems.push(format!(
                "{INDEX}: lookup row `{tool_cell}` is not a link to a tool"
            ));
            continue;
        };
        listed.push(name.clone());
        let Some(owners) = members.get(name.as_str()) else {
            problems.push(format!(
                "{INDEX}: the lookup lists `{name}`, which no bundle in \
                 src/mcp_profile.rs holds"
            ));
            continue;
        };
        let bundle = owners[0];
        let want_target = format!("{}#{name}", bundle_file(bundle));
        if target != want_target {
            problems.push(format!(
                "{INDEX}: the lookup links `{name}` to `{target}`; it is in bundle \
                 `{bundle}`, so the link is `{want_target}`"
            ));
        }
        let want_bundle = format!("[{bundle}]({})", bundle_file(bundle));
        if bundle_cell != want_bundle {
            problems.push(format!(
                "{INDEX}: the lookup row for `{name}` names `{bundle_cell}`; \
                 src/mcp_profile.rs puts it in `{want_bundle}`"
            ));
        }
    }
    if listed.windows(2).any(|w| w[0] >= w[1]) {
        problems.push(format!(
            "{INDEX}: the lookup is not in strict alphabetical order, or lists a \
             tool twice: {listed:?}"
        ));
    }
    let listed: BTreeSet<&str> = listed.iter().map(String::as_str).collect();
    for tool in members.keys() {
        if !listed.contains(tool) {
            problems.push(format!("{INDEX}: the lookup has no row for `{tool}`"));
        }
    }
    problems
}

/// The pages on disk, `bundle -> text`, for every bundle in `bundles`.
fn pages_on_disk(root: &Path, bundles: &[(&str, &[&str])]) -> BTreeMap<String, Option<String>> {
    bundles
        .iter()
        .map(|(b, _)| {
            (
                (*b).to_string(),
                std::fs::read_to_string(root.join(bundle_page(b))).ok(),
            )
        })
        .collect()
}

/// The repository's tree, read by the real-tree tests.
fn real_tree() -> Result<(String, BTreeMap<String, Option<String>>), TestError> {
    let root = markdown::repo_root();
    let index = std::fs::read_to_string(root.join(INDEX))
        .map_err(|e| format!("{INDEX} is readable: {e}"))?;
    Ok((index, pages_on_disk(root, sipnab::mcp_profile::BUNDLES)))
}

/// The gate proper: every tool's section is on its bundle's page.
#[test]
fn every_tool_section_is_on_its_bundles_page() -> Result<(), TestError> {
    let (index, pages) = real_tree()?;
    let bundles = sipnab::mcp_profile::BUNDLES;
    let sections: usize = pages
        .values()
        .flatten()
        .map(|t| tool_sections(t).len())
        .sum();
    assert!(
        sections >= 40,
        "found only {sections} tool section(s) across the bundle pages; the \
         heading scan has stopped matching and the comparison proves nothing"
    );
    let problems = page_problems(bundles, &pages, &index);
    assert!(
        problems.is_empty(),
        "the bundle pages disagree with src/mcp_profile.rs:\n{}",
        problems.join("\n")
    );
    Ok(())
}

/// The index's bundle table and lookup agree with the code.
#[test]
fn the_index_lists_every_bundle_and_finds_every_tool() -> Result<(), TestError> {
    let (index, _) = real_tree()?;
    let problems = index_problems(sipnab::mcp_profile::BUNDLES, &index);
    assert!(
        problems.is_empty(),
        "{INDEX} disagrees with src/mcp_profile.rs:\n{}",
        problems.join("\n")
    );
    Ok(())
}

/// No `docs/mcp-tools-*.md` page is left for a bundle the code does not have.
///
/// A renamed or removed bundle would otherwise leave its old page published,
/// documenting tools under a name `--mcp-tools` refuses.
#[test]
fn no_page_is_left_for_a_bundle_the_code_does_not_have() -> Result<(), TestError> {
    let docs = markdown::repo_root().join("docs");
    let known: BTreeSet<String> = sipnab::mcp_profile::BUNDLES
        .iter()
        .map(|(b, _)| bundle_file(b))
        .collect();
    let mut stray = Vec::new();
    for entry in std::fs::read_dir(&docs)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.starts_with("mcp-tools-") && name.ends_with(".md") && !known.contains(&name) {
            stray.push(name);
        }
    }
    assert!(
        stray.is_empty(),
        "these pages under docs/ are named for a bundle src/mcp_profile.rs does \
         not have: {stray:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Controls: the checker run against trees that are wrong on purpose. Without
// them an empty problem list could mean a correct tree or a blind checker.
// ---------------------------------------------------------------------------

/// A two-bundle tree that is correct: index, lookup and both pages.
fn good_tree() -> (String, BTreeMap<String, Option<String>>) {
    let index = "# MCP tool reference\n\n\
        | Bundle | Tools | What its tools answer |\n|---|---|---|\n\
        | [`core`](mcp-tools-core.md) | 2 | The first questions. |\n\
        | [`media`](mcp-tools-media.md) | 1 | Media. |\n\n\
        | Tool | Bundle | Returns |\n|---|---|---|\n\
        | [`alpha`](mcp-tools-core.md#alpha) | [core](mcp-tools-core.md) | A. |\n\
        | [`beta`](mcp-tools-core.md#beta) | [core](mcp-tools-core.md) | B. |\n\
        | [`gamma`](mcp-tools-media.md#gamma) | [media](mcp-tools-media.md) | G. |\n"
        .to_string();
    let core = "# core\n\n| Tool | Parameters | Returns |\n|---|---|---|\n\
        | [`alpha`](#alpha) | -- | A |\n| [`beta`](#beta) | -- | B |\n\n\
        ## Survey\n\n### `alpha`\n\ntext\n\n```text\n### `gamma`\n```\n\n### `beta`\n\ntext\n"
        .to_string();
    let media = "# media\n\n| Tool | Parameters | Returns |\n|---|---|---|\n\
        | [`gamma`](#gamma) | -- | G |\n\n### `gamma`\n\ntext\n"
        .to_string();
    let pages = BTreeMap::from([
        ("core".to_string(), Some(core)),
        ("media".to_string(), Some(media)),
    ]);
    (index, pages)
}

const CORE: &[&str] = &["alpha", "beta"];
const MEDIA: &[&str] = &["gamma"];
const GOOD_BUNDLES: &[(&str, &[&str])] = &[("core", CORE), ("media", MEDIA)];

#[test]
fn control_a_correct_tree_has_no_problems() {
    let (index, pages) = good_tree();
    assert_eq!(
        page_problems(GOOD_BUNDLES, &pages, &index),
        Vec::<String>::new()
    );
    assert_eq!(index_problems(GOOD_BUNDLES, &index), Vec::<String>::new());
}

/// The case the gate exists for: the code moves `beta` to `media` and the
/// docs do not follow.
#[test]
fn control_a_tool_moved_in_code_but_not_in_the_docs_is_red() {
    let (index, pages) = good_tree();
    let moved: &[(&str, &[&str])] = &[("core", &["alpha"]), ("media", &["beta", "gamma"])];
    let problems = page_problems(moved, &pages, &index);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("docs/mcp-tools-core.md documents `beta`")),
        "{problems:?}"
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("docs/mcp-tools-media.md has no `### `beta``")),
        "{problems:?}"
    );
    let index_side = index_problems(moved, &index);
    assert!(
        index_side
            .iter()
            .any(|p| p.contains("links `beta` to `mcp-tools-core.md#beta`")),
        "{index_side:?}"
    );
}

#[test]
fn control_a_tool_in_two_bundles_is_red() {
    let (index, pages) = good_tree();
    let twice: &[(&str, &[&str])] = &[("core", CORE), ("media", &["beta", "gamma"])];
    let problems = page_problems(twice, &pages, &index);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("`beta` is in 2 bundles")),
        "{problems:?}"
    );
}

#[test]
fn control_a_documented_tool_in_no_bundle_is_red() {
    let (index, pages) = good_tree();
    let dropped: &[(&str, &[&str])] = &[("core", &["alpha"]), ("media", MEDIA)];
    let problems = page_problems(dropped, &pages, &index);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("documents `beta`, which no bundle")),
        "{problems:?}"
    );
    let index_side = index_problems(dropped, &index);
    assert!(
        index_side
            .iter()
            .any(|p| p.contains("lists `beta`, which no bundle")),
        "{index_side:?}"
    );
}

#[test]
fn control_a_missing_page_or_index_section_is_red() {
    let (index, mut pages) = good_tree();
    pages.insert("media".to_string(), None);
    let with_section = format!("{index}\n### `alpha`\n");
    let problems = page_problems(GOOD_BUNDLES, &pages, &with_section);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("bundle `media` has no page")),
        "{problems:?}"
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("has a section for `alpha`")),
        "{problems:?}"
    );
}

#[test]
fn control_a_bad_lookup_is_red() {
    let (index, _) = good_tree();
    let swapped = index.replace(
        "| [`alpha`](mcp-tools-core.md#alpha) | [core](mcp-tools-core.md) | A. |\n\
         | [`beta`](mcp-tools-core.md#beta) | [core](mcp-tools-core.md) | B. |\n",
        "| [`beta`](mcp-tools-core.md#beta) | [core](mcp-tools-core.md) | B. |\n\
         | [`alpha`](mcp-tools-core.md#alpha) | [media](mcp-tools-media.md) | A. |\n",
    );
    assert_ne!(swapped, index, "the control's edit did not apply");
    let problems = index_problems(GOOD_BUNDLES, &swapped);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("not in strict alphabetical order")),
        "{problems:?}"
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("row for `alpha` names `[media]")),
        "{problems:?}"
    );
    let dropped = index.replace(
        "| [`gamma`](mcp-tools-media.md#gamma) | [media](mcp-tools-media.md) | G. |\n",
        "",
    );
    assert_ne!(dropped, index, "the control's edit did not apply");
    assert!(
        index_problems(GOOD_BUNDLES, &dropped)
            .iter()
            .any(|p| p.contains("no row for `gamma`")),
    );
}

#[test]
fn control_a_wrong_bundle_table_is_red() {
    let (index, _) = good_tree();
    let wrong = index.replace(
        "| [`media`](mcp-tools-media.md) | 1 |",
        "| [`media`](mcp-tools-media.md) | 3 |",
    );
    assert_ne!(wrong, index, "the control's edit did not apply");
    assert!(
        index_problems(GOOD_BUNDLES, &wrong)
            .iter()
            .any(|p| p.contains("bundle table reads")),
    );
}
