// SPDX-License-Identifier: MIT OR Apache-2.0

//! The release each MCP tool first shipped in, read from the changelog.
//!
//! # Why this is derived rather than written down
//!
//! A "Since version" column typed by hand into the tool table is a fact with
//! no owner. It is right on the day it is written and there is nothing in the
//! repository that can ever disagree with it — which is precisely how the tool
//! table itself came to under-report the surface, and how a review read the
//! wrong tool set off the published site.
//!
//! So the column is not a source. `CHANGELOG.md` is, and it already is:
//!
//! * It is the record the release flow maintains anyway — every release writes
//!   an entry, and the release gates read that entry's version and date.
//! * A release note that adds a tool NAMES the tool. That is what a release
//!   note is for, so nothing new has to be remembered.
//! * It is append-only in practice. Version 0.5.70's entry does not change
//!   when 0.5.130 ships, so the answer for a tool added in 0.5.70 cannot move.
//! * It is `include_str!`'d here, so the bytes a person reads and the bytes
//!   this function answers from are the same bytes. There is no second copy to
//!   drift.
//!
//! The one thing a human still supplies is the release note itself, and
//! `mcp_since_version_test` fails the build when a registered tool is named in
//! none of them. That is the drift this replaces: a missing column entry used
//! to be invisible, and a missing release note now stops the build.
//!
//! # What "since" means here
//!
//! The OLDEST release whose entry names the tool. A tool mentioned again later
//! — because it grew a parameter, or was fixed — keeps its first release, so
//! the answer describes when a client could first call it rather than when it
//! was last touched.

use std::collections::BTreeMap;

/// The release notes, read at compile time.
///
/// The whole point of the module: one copy of the record, shared by the page a
/// person reads and the answer this gives.
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");

/// The release each named tool first appeared in.
///
/// Parsed once and cached: the changelog is a fixed string, so the answer
/// cannot change during a run, and every caller reads the same map.
static SINCE: std::sync::OnceLock<BTreeMap<String, String>> = std::sync::OnceLock::new();

/// The release `tool` first shipped in.
///
/// # Arguments
///
/// * `tool` — an MCP tool name, exactly as it is registered.
///
/// # Returns
///
/// The version string from the changelog heading (`0.5.70`), or `None` when no
/// release note names the tool — which is a gap in the release notes rather
/// than a tool with no release, and is asserted against in
/// `tests/mcp_since_version_test.rs`.
#[must_use]
pub fn since_version(tool: &str) -> Option<&'static str> {
    versions().get(tool).map(String::as_str)
}

/// Every tool the changelog names, with the release it first appeared in.
///
/// # Returns
///
/// A name-to-version map in name order. It carries names that are no longer
/// registered — a removed tool's release note still names it — so callers
/// intersect with the router rather than treating this as the tool list.
#[must_use]
pub fn versions() -> &'static BTreeMap<String, String> {
    SINCE.get_or_init(|| index(CHANGELOG))
}

/// Build the name-to-version index from changelog text.
///
/// Split out from [`versions`] so the parsing rules are testable against
/// hand-written fixtures rather than only against the real file, where a
/// near-miss is hard to construct on purpose.
///
/// # Arguments
///
/// * `changelog` — the changelog text, Keep a Changelog shaped: one
///   `## [version] - date` heading per release, newest first.
///
/// # Returns
///
/// Each backticked identifier found under a version heading, mapped to the
/// OLDEST version whose section names it.
fn index(changelog: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (version, body) in sections(changelog) {
        for name in backticked_identifiers(body) {
            // Oldest wins. Sections arrive newest-first, so a later mention is
            // overwritten by the earlier release as the walk goes back in
            // time -- and the comparison is made explicitly rather than
            // relying on that order, because a changelog someone reordered
            // would otherwise silently move every answer.
            match out.get(&name) {
                Some(seen) if !is_older(version, seen) => {}
                _ => {
                    out.insert(name, version.to_string());
                }
            }
        }
    }
    out
}

/// The `(version, body)` pairs in a Keep a Changelog file.
///
/// # Arguments
///
/// * `changelog` — the file text.
///
/// # Returns
///
/// One pair per `## [version]` heading, in file order. Text before the first
/// heading is not a release and is dropped, so a tool named in the preamble is
/// not attributed to a version it never shipped in.
fn sections(changelog: &str) -> Vec<(&str, &str)> {
    let mut out: Vec<(&str, &str)> = Vec::new();
    let mut pending: Option<(&str, usize)> = None;
    for (offset, line) in line_offsets(changelog) {
        let Some(version) = heading_version(line) else {
            continue;
        };
        if let Some((open, start)) = pending.take() {
            out.push((open, &changelog[start..offset]));
        }
        pending = Some((version, offset + line.len()));
    }
    if let Some((open, start)) = pending {
        out.push((open, &changelog[start..]));
    }
    out
}

/// Every line with its byte offset in `text`.
///
/// `str::lines` drops the offsets, and the section walk needs them to slice
/// bodies without copying the whole changelog per release.
fn line_offsets(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0usize;
    text.split_inclusive('\n').map(move |raw| {
        let at = offset;
        offset += raw.len();
        (at, raw.trim_end_matches(['\n', '\r']))
    })
}

/// The version in a `## [0.5.70] - 2026-08-01` heading.
///
/// # Returns
///
/// The text between the brackets, or `None` for any other line. Deliberately
/// tolerant of what follows the bracket — the date format has changed before
/// and the version is what this reads.
fn heading_version(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("## [")?;
    let end = rest.find(']')?;
    Some(&rest[..end])
}

/// Identifiers written between backticks in `body`.
///
/// A tool name in a release note is written as code, so this reads code spans
/// and nothing else: prose naming a tool without backticks would otherwise
/// match a word in an ordinary sentence.
///
/// Only spans that could BE a tool name are kept — lowercase, digits and
/// underscores, at least three characters. That drops `--mcp-max-rows`,
/// `[limits]`, `0.5.70` and every prose code span, so a release note that
/// merely mentions a flag does not mint a tool.
///
/// # Arguments
///
/// * `body` — one release section's text.
///
/// # Returns
///
/// Each qualifying identifier, possibly repeated.
fn backticked_identifiers(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else { break };
        let span = &after[..close];
        rest = &after[close + 1..];
        if span.len() >= 3
            && span
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            out.push(span.to_string());
        }
    }
    out
}

/// Whether version `a` was released before version `b`.
///
/// Compares the dotted numeric parts, so `0.5.70` is older than `0.5.130` —
/// which string order gets backwards, and which is exactly the range these
/// tools span. A pre-release suffix (`0.1.0-alpha`) sorts before the release
/// it leads to.
///
/// # Arguments
///
/// * `a`, `b` — version strings from changelog headings.
fn is_older(a: &str, b: &str) -> bool {
    sort_key(a) < sort_key(b)
}

/// The comparable form of a version heading: its numeric components, then a
/// flag that puts a pre-release ahead of the release of the same number.
///
/// A heading that is not a version at all (`Unreleased`) sorts last, so it
/// never displaces a real release as a tool's first appearance.
fn sort_key(version: &str) -> (Vec<u64>, u8) {
    let (numeric, suffix) = match version.split_once('-') {
        Some((head, _)) => (head, 0u8),
        None => (version, 1u8),
    };
    let parts: Vec<u64> = numeric
        .split('.')
        .map(|p| p.parse::<u64>().unwrap_or(u64::MAX))
        .collect();
    if parts.is_empty() || parts.contains(&u64::MAX) {
        return (vec![u64::MAX], suffix);
    }
    (parts, suffix)
}

/// Tests for the changelog parsing rules, over fixtures and over the real
/// file.
#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture in the shape of the real file: newest release first.
    const FIXTURE: &str = "\
# Changelog

Preamble prose naming `preamble_tool`, which is not a release.

## [0.5.130] - 2026-08-28

### Added

- **`late_tool`** arrived here, and `early_tool` gained a parameter.

## [0.5.70] - 2026-07-01

### Added

- **`early_tool`**, plus the `--mcp-max-rows` flag and `[limits]` section.

## [0.1.0-alpha] - 2026-01-01

- `ancient_tool` shipped in the pre-release.
";

    /// A tool named in several releases takes the oldest one.
    #[test]
    fn the_oldest_mention_wins() {
        let idx = index(FIXTURE);
        assert_eq!(idx.get("early_tool").map(String::as_str), Some("0.5.70"));
        assert_eq!(idx.get("late_tool").map(String::as_str), Some("0.5.130"));
    }

    /// Versions compare numerically, not as strings: `0.5.70` is older than
    /// `0.5.130`, which string order reverses.
    #[test]
    fn versions_compare_numerically() {
        assert!(is_older("0.5.70", "0.5.130"));
        assert!(!is_older("0.5.130", "0.5.70"));
        assert!(is_older("0.1.0-alpha", "0.1.0"));
        assert!(
            is_older("0.5.130", "Unreleased"),
            "a non-version heading must never displace a real release"
        );
    }

    /// Prose before the first heading belongs to no release.
    #[test]
    fn the_preamble_is_not_a_release() {
        assert!(
            !index(FIXTURE).contains_key("preamble_tool"),
            "a name in the preamble has no release to be attributed to"
        );
    }

    /// A flag or a config section written in backticks is not a tool name.
    #[test]
    fn flags_and_config_keys_are_not_tool_names() {
        let idx = index(FIXTURE);
        assert!(!idx.contains_key("--mcp-max-rows"));
        assert!(!idx.contains_key("[limits]"));
        assert!(!idx.keys().any(|k| k.contains('-') || k.contains('[')));
    }

    /// A pre-release heading is a release like any other.
    #[test]
    fn a_prerelease_heading_still_carries_its_tools() {
        assert_eq!(
            index(FIXTURE).get("ancient_tool").map(String::as_str),
            Some("0.1.0-alpha")
        );
    }

    /// A name that is a PREFIX of another tool's name is not confused with
    /// it. `get_dialog` and `get_dialog_report` are both real, and a
    /// substring search reports the wrong release for one of them.
    #[test]
    fn a_prefix_of_another_name_is_a_separate_tool() {
        const PAIR: &str = "\
## [0.5.130] - 2026-08-28

- `get_dialog_report` arrived.

## [0.5.70] - 2026-07-01

- `get_dialog` arrived.
";
        let idx = index(PAIR);
        assert_eq!(idx.get("get_dialog").map(String::as_str), Some("0.5.70"));
        assert_eq!(
            idx.get("get_dialog_report").map(String::as_str),
            Some("0.5.130"),
            "the longer name must not inherit the shorter one's release"
        );
    }

    /// A code span naming the FUNCTION — `tool_name()` — is not a mention of
    /// the tool.
    ///
    /// Not a hypothetical. `explain_response_code` shipped as a tool in
    /// 0.5.70, and an older 0.5.68 entry describes a fix to
    /// `explain_response_code()`, the function behind it. A rule that matched
    /// the name as a PREFIX inside a code span reported 0.5.68 — two releases
    /// before a client could call the tool at all. `git describe --contains`
    /// on the commit that first wrote `name = "explain_response_code"` names
    /// `v0.5.70`, which is what this returns.
    #[test]
    fn a_function_call_form_is_not_a_tool_mention() {
        const PAIR: &str = "\
## [0.5.70] - 2026-07-01

- Plus four from the roadmap: `explain_response_code` and three others.

## [0.5.68] - 2026-06-20

### Fixed
- `explain_response_code()` had drifted from the registry.
";
        assert_eq!(
            index(PAIR).get("explain_response_code").map(String::as_str),
            Some("0.5.70"),
            "a fix to the function behind a tool is not the release that \
             added the tool"
        );
        assert_eq!(
            since_version("explain_response_code"),
            Some("0.5.70"),
            "and the same holds against the real changelog, which carries \
             exactly this pair"
        );
    }

    /// The real changelog parses into something plausible, so a shape change
    /// that made every section empty is visible here rather than as a silent
    /// wall of `None`.
    #[test]
    fn the_real_changelog_yields_a_plausible_index() {
        let sections = sections(CHANGELOG);
        assert!(
            sections.len() >= 100,
            "found only {} release sections in CHANGELOG.md -- the heading \
             shape changed and this module is reading nothing",
            sections.len()
        );
        assert!(
            versions().len() >= 40,
            "found only {} named identifiers across every release -- the \
             backtick rule no longer matches how release notes are written",
            versions().len()
        );
    }

    /// A tool this module is asked about but the notes never named comes back
    /// `None` rather than as a guess.
    #[test]
    fn an_unnamed_tool_has_no_version() {
        assert_eq!(since_version("no_such_tool_has_ever_existed"), None);
    }

    /// Spot-check against the record: `list_dialogs` was in the first MCP
    /// release and `describe_endpoint` is recent, so an index that returned
    /// one version for everything would fail here.
    #[test]
    fn known_tools_carry_the_release_that_added_them() {
        assert_eq!(since_version("list_dialogs"), Some("0.3.2"));
        assert_eq!(since_version("describe_endpoint"), Some("0.5.130"));
        assert!(
            is_older(
                since_version("list_dialogs").unwrap_or("0.0.0"),
                since_version("describe_endpoint").unwrap_or("0.0.0")
            ),
            "the first MCP tools must predate the newest ones"
        );
    }
}
