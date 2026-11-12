// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Every task page carries the parts of a how-to, and every added feature
//! links to one.
//!
//! A page that tells a reader how to do something needs five parts: what the
//! task is for, what must be in place first (on this host and on every other
//! system), the steps, how to check the result, and what to do when it fails.
//! On 2026-11-10 a count by heading keyword found 53 of the 92 pages in
//! `docs/` with no prerequisites, verify or troubleshoot heading. Nothing
//! read the pages for those parts, so a new page could ship without them.
//!
//! This file is the one place that decides:
//!
//! - which pages are task pages ([`PAGES`]: every page in `docs/` has a
//!   [`Kind`], and only [`Kind::Task`] pages are held to the rule);
//! - which parts a task page carries and how each is recognized
//!   ([`missing_parts`] and the three heading predicates of
//!   `support/howto_parts.rs`, which `how_to_headings_stay_task_first` reads
//!   too);
//! - which task pages do not carry them yet ([`KNOWN_GAPS`], a list that is
//!   compared exactly, so a page that gains a part leaves the list and a page
//!   that loses one fails);
//! - that each "Added" entry of the changelog after [`CUTOVER`] links to a
//!   heading of a task page ([`entry_gap`]).
//!
//! How each part is recognized:
//!
//! | Part | Recognized by |
//! |---|---|
//! | Purpose | At least eight words of prose between the title and the first section |
//! | Prerequisites | A level 2 or 3 heading that starts with "Before you start", "What you need" or "Prerequisites" |
//! | Other systems | The words "other system" inside that section ("another system" and "other systems" hold them) |
//! | Steps | A fenced block outside the prerequisites, verify and troubleshoot sections |
//! | Verify | A level 2 or 3 heading that starts with "Verify", "Check that" or "Check it worked", with a fenced block in its section |
//! | Troubleshoot | A level 2 or 3 heading that starts with "Troubleshoot", or starts with "When" and contains "does not" |

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[path = "support/howto_parts.rs"]
mod howto_parts;

use howto_parts::{is_prerequisites, is_troubleshoot, is_verify};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// What a page in `docs/` is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// A tutorial or how-to guide: the reader sets out to do something.
    Task,
    /// Rows to look up: flags, keys, endpoints, tools, codes.
    Reference,
    /// Why sipnab works as it does, and what was measured or observed.
    Explanation,
    /// Many short recipes or symptoms, each sending the reader to a task page.
    Collection,
    /// The docs index and the sponsors page.
    Index,
}

/// One part of a how-to that a task page can lack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Part {
    Purpose,
    Prerequisites,
    OtherSystems,
    Steps,
    Verify,
    Troubleshoot,
}

use Kind::{Collection, Explanation, Index, Reference, Task};
use Part::{OtherSystems, Prerequisites, Purpose, Steps, Troubleshoot, Verify};

/// Every page in `docs/`, by file stem, in sorted order.
const PAGES: &[(&str, Kind)] = &[
    ("README", Index),
    ("architecture", Explanation),
    ("archives", Task),
    ("assurance-case", Explanation),
    ("asterisk", Task),
    ("asterisk-sipnab", Task),
    ("auth", Task),
    ("backers", Index),
    ("benchmarks", Explanation),
    ("call-quality", Task),
    ("capture-queries", Task),
    ("cli-reference", Reference),
    ("client-examples", Reference),
    ("config-reference", Reference),
    ("encapsulations", Reference),
    ("errors", Reference),
    ("examples", Collection),
    ("expectations", Task),
    ("fail2ban", Task),
    ("fail2ban-sipnab", Task),
    ("fault-model", Explanation),
    ("filter-dsl", Reference),
    ("first-cli-triage", Task),
    ("fleet", Task),
    ("follow-a-call", Task),
    ("freeswitch", Task),
    ("freeswitch-sipnab", Task),
    ("g729", Task),
    ("glossary", Reference),
    ("hep", Task),
    ("homer", Task),
    ("homer-sipnab", Task),
    ("install", Task),
    ("integrations", Task),
    ("kamailio", Task),
    ("kamailio-sipnab", Task),
    ("keybindings", Reference),
    ("least-privilege", Task),
    ("library", Reference),
    ("mcp", Task),
    ("mcp-deploy", Task),
    ("mcp-estate", Task),
    ("mcp-protocol", Reference),
    ("mcp-tools", Reference),
    ("mcp-tools-captures", Reference),
    ("mcp-tools-core", Reference),
    ("mcp-tools-media", Reference),
    ("mcp-tools-relay", Reference),
    ("mcp-tools-security", Reference),
    ("mcp-tools-server", Reference),
    ("mcp-tools-signaling", Reference),
    ("mcp-tools-tfps", Reference),
    ("mcp-tools-tls", Reference),
    ("mcp-tools-vcon", Reference),
    ("mos-and-codecs", Reference),
    ("mtls", Task),
    ("opensips", Task),
    ("opensips-sipnab", Task),
    ("output-formats", Reference),
    ("plugins", Task),
    ("prometheus", Task),
    ("prometheus-metrics", Reference),
    ("prometheus-sipnab", Task),
    ("real-world-captures", Explanation),
    ("relay-engines", Task),
    ("relay-statistics", Task),
    ("rest-api", Task),
    ("rtpengine", Task),
    ("rtpengine-relay", Task),
    ("rtpengine-sipnab", Task),
    ("rtpproxy-relay", Task),
    ("rtpproxy-sipnab", Task),
    ("run-as-a-service", Task),
    ("sip-header-fields", Reference),
    ("sip-lint-rules", Reference),
    ("sip-methods", Reference),
    ("sip-parameters", Reference),
    ("sip-response-codes", Reference),
    ("tfps", Task),
    ("tfps-sipnab", Task),
    ("theme-guide", Task),
    ("threat-model", Explanation),
    ("tls-capture", Task),
    ("troubleshooting", Collection),
    ("tui-walkthrough", Task),
    ("tuning-capture", Task),
    ("uprobe-walkthrough", Task),
    ("vcon", Task),
    ("vcon-harness", Task),
    ("vcon-server", Task),
    ("vcon-sipnab", Task),
    ("vcon-store", Task),
];

/// Task pages that lack a part today, with the parts each lacks, in sorted
/// order. The list is compared exactly with what the pages hold: remove a
/// page's entry in the change that gives the page its parts. Never add one
/// for a new page.
const KNOWN_GAPS: &[(&str, &[Part])] = &[
    ("fail2ban", &[OtherSystems]),
    ("fail2ban-sipnab", &[Prerequisites, Verify]),
    ("homer", &[OtherSystems, Verify]),
    ("homer-sipnab", &[Prerequisites, Verify]),
    ("prometheus", &[OtherSystems, Verify]),
    ("prometheus-sipnab", &[Prerequisites, Verify]),
    ("tfps", &[Prerequisites]),
    ("tfps-sipnab", &[Prerequisites]),
];

/// The last release cut before this gate. "Added" entries of later releases,
/// and of `[Unreleased]`, link to a heading of a task page.
const CUTOVER: (u32, u32, u32) = (0, 5, 244);

/// A heading and the lines under it, up to the next heading of the same or a
/// higher level.
#[derive(Debug, PartialEq, Eq)]
struct Section {
    level: usize,
    /// The heading text: no `#`, no backticks, no surrounding space.
    title: String,
    /// Index of the heading line.
    start: usize,
    /// Index one past the section's last line.
    end: usize,
}

/// True for a line that opens or closes a fenced block.
fn is_fence(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with("```") || line.starts_with("~~~")
}

/// The level and text of a heading line: one to six `#`, then a space.
fn heading(line: &str) -> Option<(usize, String)> {
    let level = line.chars().take_while(|c| *c == '#').count();
    if !(1..=6).contains(&level) {
        return None;
    }
    let rest = line.get(level..)?;
    if !rest.starts_with(' ') {
        return None;
    }
    let title: String = rest
        .trim()
        .trim_end_matches('#')
        .chars()
        .filter(|c| *c != '`')
        .collect();
    Some((level, title.trim().to_string()))
}

/// For each line, whether it lies inside a fenced block. The fence lines
/// themselves count as inside.
fn fenced(lines: &[&str]) -> Vec<bool> {
    let mut inside = false;
    lines
        .iter()
        .map(|line| {
            if is_fence(line) {
                inside = !inside;
                true
            } else {
                inside
            }
        })
        .collect()
}

/// The headings of a page with the line range each governs. A `#` line
/// inside a fenced block is not a heading.
fn sections(md: &str) -> Vec<Section> {
    let lines: Vec<&str> = md.lines().collect();
    let in_fence = fenced(&lines);
    let heads: Vec<(usize, usize, String)> = lines
        .iter()
        .zip(&in_fence)
        .enumerate()
        .filter(|(_, (_, fenced))| !**fenced)
        .filter_map(|(at, (line, _))| heading(line).map(|(level, title)| (at, level, title)))
        .collect();
    heads
        .iter()
        .enumerate()
        .map(|(nth, (start, level, title))| {
            let end = heads
                .iter()
                .skip(nth + 1)
                .find(|(_, next, _)| next <= level)
                .map_or(lines.len(), |(at, _, _)| *at);
            Section {
                level: *level,
                title: title.clone(),
                start: *start,
                end,
            }
        })
        .collect()
}

/// The number of words of prose between the title and the first section.
/// Lists, tables, quotes, HTML and fenced blocks are not prose.
fn purpose_words(md: &str) -> usize {
    let lines: Vec<&str> = md.lines().collect();
    let in_fence = fenced(&lines);
    lines
        .iter()
        .zip(&in_fence)
        .skip_while(|(line, fenced)| **fenced || heading(line).is_none_or(|(level, _)| level != 1))
        .skip(1)
        .take_while(|(line, fenced)| **fenced || heading(line).is_none())
        .filter(|(_, fenced)| !**fenced)
        .map(|(line, _)| line.trim())
        .filter(|line| !line.starts_with(['-', '*', '|', '>', '<', '+', '!']))
        .map(|line| line.split_whitespace().count())
        .sum()
}

/// The parts of a how-to this page lacks, in the order of [`Part`].
/// `OtherSystems` is reported only for a page that has a prerequisites
/// section: without one, `Prerequisites` covers it.
fn missing_parts(md: &str) -> Vec<Part> {
    let lines: Vec<&str> = md.lines().collect();
    let in_fence = fenced(&lines);
    let all = sections(md);
    let parts: Vec<&Section> = all.iter().filter(|s| (2..=3).contains(&s.level)).collect();
    let fences_in = |section: &Section| -> usize {
        (section.start..section.end)
            .filter(|at| in_fence.get(*at).copied().unwrap_or(false))
            .count()
    };
    let prerequisites: Vec<&Section> = parts
        .iter()
        .copied()
        .filter(|s| is_prerequisites(&s.title))
        .collect();
    let verify: Vec<&Section> = parts
        .iter()
        .copied()
        .filter(|s| is_verify(&s.title))
        .collect();
    let troubleshoot: Vec<&Section> = parts
        .iter()
        .copied()
        .filter(|s| is_troubleshoot(&s.title))
        .collect();

    let mut missing = Vec::new();
    if purpose_words(md) < 8 {
        missing.push(Purpose);
    }
    if prerequisites.is_empty() {
        missing.push(Prerequisites);
    } else if !prerequisites.iter().any(|section| {
        let body = lines
            .get(section.start..section.end)
            .map(|body| body.join(" ").to_lowercase())
            .unwrap_or_default();
        // "another system" holds the same words.
        body.contains("other system")
    }) {
        missing.push(OtherSystems);
    }
    // A step is a fenced line that no prerequisites, verify or troubleshoot
    // section holds.
    let outside = (0..lines.len())
        .filter(|at| in_fence.get(*at).copied().unwrap_or(false))
        .filter(|at| {
            !prerequisites
                .iter()
                .chain(&verify)
                .chain(&troubleshoot)
                .any(|section| (section.start..section.end).contains(at))
        })
        .count();
    if outside == 0 {
        missing.push(Steps);
    }
    if !verify.iter().any(|section| fences_in(section) > 0) {
        missing.push(Verify);
    }
    if troubleshoot.is_empty() {
        missing.push(Troubleshoot);
    }
    missing
}

/// GitHub's anchor for a heading: lowercase, backticks dropped, letters,
/// digits, `-` and `_` kept, spaces to hyphens.
fn slug(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' '))
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// `[0.5.244]` as numbers; `None` for `[Unreleased]` or anything else.
fn version(label: &str) -> Option<(u32, u32, u32)> {
    let mut numbers = label.split('.').map(str::parse::<u32>);
    let version = (
        numbers.next()?.ok()?,
        numbers.next()?.ok()?,
        numbers.next()?.ok()?,
    );
    numbers.next().is_none().then_some(version)
}

/// The "Added" entries of `[Unreleased]` and of each release after `cutover`,
/// as (release label, entry text). An entry is a `- ` line at the left margin
/// with the indented lines under it.
fn added_entries(changelog: &str, cutover: (u32, u32, u32)) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut release: Option<String> = None;
    let mut added = false;
    let mut open = false;
    for line in changelog.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            let label = rest
                .strip_prefix('[')
                .and_then(|rest| rest.split(']').next())
                .unwrap_or_default();
            let after = label == "Unreleased" || version(label).is_some_and(|v| v > cutover);
            release = after.then(|| label.to_string());
            added = false;
            open = false;
        } else if let Some(group) = line.strip_prefix("### ") {
            added = group.trim() == "Added";
            open = false;
        } else if let (Some(release), true) = (&release, added) {
            if line.starts_with("- ") {
                entries.push((release.clone(), line.to_string()));
                open = true;
            } else if open && line.starts_with(' ') && !line.trim().is_empty() {
                if let Some((_, text)) = entries.last_mut() {
                    text.push('\n');
                    text.push_str(line);
                }
            } else if !line.trim().is_empty() {
                open = false;
            }
        }
    }
    entries
}

/// The `docs/<page>.md#<anchor>` links of a changelog entry, as (page stem,
/// anchor). The anchor is empty for a link to the page alone.
fn doc_links(entry: &str) -> Vec<(String, String)> {
    entry
        .split("](docs/")
        .skip(1)
        .filter_map(|rest| rest.split(')').next())
        .filter_map(|target| {
            let (path, anchor) = target.split_once('#').unwrap_or((target, ""));
            let stem = path.strip_suffix(".md")?;
            (!stem.contains('/')).then(|| (stem.to_string(), anchor.to_string()))
        })
        .collect()
}

/// Why an "Added" entry does not lead to a how-to, or `None` when one of its
/// links is to a heading of a task page. `kind` gives a page's kind and
/// `anchors` the heading anchors a page has.
fn entry_gap(
    entry: &str,
    kind: &dyn Fn(&str) -> Option<Kind>,
    anchors: &dyn Fn(&str) -> BTreeSet<String>,
) -> Option<String> {
    let links = doc_links(entry);
    if links.is_empty() {
        return Some("no link to a page in docs/".to_string());
    }
    let mut reasons = Vec::new();
    for (stem, anchor) in &links {
        match kind(stem) {
            Some(Task) if anchor.is_empty() => {
                reasons.push(format!("docs/{stem}.md is linked without a heading"));
            }
            Some(Task) if anchors(stem).contains(anchor) => return None,
            Some(Task) => reasons.push(format!("docs/{stem}.md has no heading #{anchor}")),
            Some(other) => reasons.push(format!("docs/{stem}.md is a {other:?} page")),
            None => reasons.push(format!("docs/{stem}.md is not in PAGES")),
        }
    }
    Some(reasons.join("; "))
}

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn page_text(stem: &str) -> Result<String, TestError> {
    let path = repo().join("docs").join(format!("{stem}.md"));
    std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()).into())
}

fn page_kind(stem: &str) -> Option<Kind> {
    PAGES
        .iter()
        .find(|(name, _)| *name == stem)
        .map(|(_, kind)| *kind)
}

/// `assert_eq!` whose failure names both expressions, so the line says which
/// call of the rule gave the unexpected value. Further arguments replace
/// that message.
macro_rules! eq {
    ($left:expr, $right:expr $(,)?) => {
        assert_eq!(
            $left,
            $right,
            "`{}` did not give `{}`",
            stringify!($left),
            stringify!($right)
        )
    };
    ($left:expr, $right:expr, $($message:tt)+) => {
        assert_eq!($left, $right, $($message)+)
    };
}

/// Asserts that a heading (or fence line) is one the predicate accepts.
macro_rules! opens {
    ($predicate:ident($text:expr)) => {
        assert!(
            $predicate($text),
            "`{}` must accept {:?}",
            stringify!($predicate),
            $text
        )
    };
}

/// Asserts that a heading (or fence line) is one the predicate refuses.
macro_rules! shuts {
    ($predicate:ident($text:expr)) => {
        assert!(
            !$predicate($text),
            "`{}` must refuse {:?}",
            stringify!($predicate),
            $text
        )
    };
}

/// A page that carries every part.
const COMPLETE: &str = "\
# Read a capture

Read a capture file and list its calls, when a ticket names a time and a number.

## Before you start

- A sipnab binary.
- No change on any other system.

## List the calls

```sh
sipnab -N -I sample.pcap
```

## Check that it worked

```text
1 dialog
```

## When something does not work

The file is not a capture: see the error reference.
";

/// [`COMPLETE`] with one line replaced.
fn complete_with(from: &str, to: &str) -> Result<String, TestError> {
    if !COMPLETE.contains(from) {
        return Err(format!("the fixture has no line {from:?}").into());
    }
    Ok(COMPLETE.replacen(from, to, 1))
}

fn no_kind(_: &str) -> Option<Kind> {
    None
}

fn fixture_kind(stem: &str) -> Option<Kind> {
    match stem {
        "hep" => Some(Task),
        "cli-reference" => Some(Reference),
        _ => None,
    }
}

fn fixture_anchors(stem: &str) -> BTreeSet<String> {
    match stem {
        "hep" => ["collect-and-forward-hep", "require-a-shared-secret"]
            .iter()
            .map(ToString::to_string)
            .collect(),
        "cli-reference" => std::iter::once("capture".to_string()).collect(),
        _ => BTreeSet::new(),
    }
}

// ---------------------------------------------------------------------------
// Pages and entries that meet the rule
// ---------------------------------------------------------------------------

mod success {
    use super::*;

    #[test]
    fn a_page_with_every_part_lacks_none() {
        eq!(missing_parts(COMPLETE), Vec::<Part>::new());
    }

    #[test]
    fn what_you_need_opens_the_prerequisites() -> Result<(), TestError> {
        let page = complete_with("## Before you start", "## What you need")?;
        eq!(missing_parts(&page), Vec::<Part>::new());
        Ok(())
    }

    #[test]
    fn prerequisites_opens_the_prerequisites() -> Result<(), TestError> {
        let page = complete_with("## Before you start", "## Prerequisites")?;
        eq!(missing_parts(&page), Vec::<Part>::new());
        Ok(())
    }

    #[test]
    fn before_you_start_may_name_its_subject() {
        opens!(is_prerequisites("Before you start: your SIP server"));
    }

    #[test]
    fn verify_opens_the_check() -> Result<(), TestError> {
        let page = complete_with("## Check that it worked", "## Verify")?;
        eq!(missing_parts(&page), Vec::<Part>::new());
        Ok(())
    }

    #[test]
    fn verify_may_carry_more_words() {
        opens!(is_verify("Verify it works"));
        opens!(is_verify("Verify a download is genuine"));
    }

    #[test]
    fn check_that_opens_the_check() {
        opens!(is_verify("Check that a phone registers and calls"));
        opens!(is_verify("Check that it works"));
    }

    #[test]
    fn check_it_worked_opens_the_check() {
        opens!(is_verify("Check it worked"));
    }

    #[test]
    fn troubleshooting_opens_the_failures() -> Result<(), TestError> {
        let page = complete_with("## When something does not work", "## Troubleshooting")?;
        eq!(missing_parts(&page), Vec::<Part>::new());
        Ok(())
    }

    #[test]
    fn troubleshoot_may_name_its_subject() {
        opens!(is_troubleshoot("Troubleshoot"));
        opens!(is_troubleshoot("Troubleshoot the harness"));
    }

    #[test]
    fn when_it_does_not_opens_the_failures() {
        opens!(is_troubleshoot("When something does not work"));
        opens!(is_troubleshoot("When it does not work"));
        opens!(is_troubleshoot("When a plugin does not load"));
    }

    #[test]
    fn a_part_may_sit_at_level_three() {
        let page = COMPLETE
            .replace("## Before you start", "### Before you start")
            .replace("## Check that it worked", "### Check that it worked")
            .replace(
                "## When something does not work",
                "### When something does not work",
            );
        eq!(missing_parts(&page), Vec::<Part>::new());
    }

    #[test]
    fn another_system_states_the_other_system_changes() -> Result<(), TestError> {
        let page = complete_with(
            "- No change on any other system.",
            "- On another system: open UDP port 9060 in the firewall.",
        )?;
        eq!(missing_parts(&page), Vec::<Part>::new());
        Ok(())
    }

    #[test]
    fn other_systems_in_the_plural_states_the_changes() -> Result<(), TestError> {
        let page = complete_with(
            "- No change on any other system.",
            "**Other systems.** OpenSIPS loads `proto_hep`.",
        )?;
        eq!(missing_parts(&page), Vec::<Part>::new());
        Ok(())
    }

    #[test]
    fn a_purpose_may_wrap_over_lines() {
        let page = "# T\n\nRead a capture file\nand list its calls, when a\nticket names a time.\n\n## S\n";
        eq!(purpose_words(page), 14);
    }

    #[test]
    fn a_heading_anchor_drops_backticks_and_punctuation() {
        eq!(
            slug("Receive HEP from a SIP server"),
            "receive-hep-from-a-sip-server"
        );
        eq!(
            slug("G.729 tables (`sipnab g729`)"),
            "g729-tables-sipnab-g729"
        );
        eq!(slug("`find_problems`"), "find_problems");
    }

    #[test]
    fn an_added_entry_that_links_a_task_heading_passes() {
        let entry = "- **HEP over TLS.** See [the guide](docs/hep.md#require-a-shared-secret).";
        eq!(entry_gap(entry, &fixture_kind, &fixture_anchors), None);
    }

    #[test]
    fn one_task_link_among_reference_links_is_enough() {
        let entry = "- **X.** [flag](docs/cli-reference.md#capture), \
                     [guide](docs/hep.md#collect-and-forward-hep).";
        eq!(entry_gap(entry, &fixture_kind, &fixture_anchors), None);
    }

    #[test]
    fn unreleased_added_entries_are_read() {
        let log = "## [Unreleased]\n\n### Added\n\n- **One.** Text.\n- **Two.** Text.\n";
        let entries = added_entries(log, CUTOVER);
        eq!(
            entries,
            vec![
                ("Unreleased".to_string(), "- **One.** Text.".to_string()),
                ("Unreleased".to_string(), "- **Two.** Text.".to_string()),
            ]
        );
    }

    #[test]
    fn a_release_after_the_cutover_is_read() {
        let log = "## [0.5.245] - 2026-11-11\n\n### Added\n\n- **One.** Text.\n";
        eq!(
            added_entries(log, CUTOVER),
            vec![("0.5.245".to_string(), "- **One.** Text.".to_string())]
        );
    }
}

// ---------------------------------------------------------------------------
// Pages and entries that break the rule
// ---------------------------------------------------------------------------

mod failure {
    use super::*;

    #[test]
    fn an_empty_page_lacks_every_part() {
        eq!(
            missing_parts(""),
            vec![Purpose, Prerequisites, Steps, Verify, Troubleshoot]
        );
    }

    #[test]
    fn a_page_with_no_introduction_lacks_a_purpose() -> Result<(), TestError> {
        let page = complete_with(
            "Read a capture file and list its calls, when a ticket names a time and a number.\n",
            "",
        )?;
        eq!(missing_parts(&page), vec![Purpose]);
        Ok(())
    }

    #[test]
    fn seven_words_are_not_a_purpose() -> Result<(), TestError> {
        let page = complete_with(
            "Read a capture file and list its calls, when a ticket names a time and a number.",
            "Read a capture and list its calls.",
        )?;
        eq!(missing_parts(&page), vec![Purpose]);
        Ok(())
    }

    #[test]
    fn a_page_with_no_prerequisites_heading_lacks_them() -> Result<(), TestError> {
        let page = complete_with("## Before you start", "## Notes")?;
        eq!(missing_parts(&page), vec![Prerequisites]);
        Ok(())
    }

    #[test]
    fn tested_on_is_not_the_prerequisites() -> Result<(), TestError> {
        let page = complete_with("## Before you start", "## Tested on")?;
        eq!(missing_parts(&page), vec![Prerequisites]);
        shuts!(is_prerequisites("Tested on"));
        Ok(())
    }

    #[test]
    fn prerequisites_that_omit_other_systems_lack_them() -> Result<(), TestError> {
        let page = complete_with("- No change on any other system.\n", "")?;
        eq!(missing_parts(&page), vec![OtherSystems]);
        Ok(())
    }

    #[test]
    fn a_page_with_no_command_lacks_steps() -> Result<(), TestError> {
        let page = complete_with("```sh\nsipnab -N -I sample.pcap\n```\n", "Run sipnab.\n")?;
        eq!(missing_parts(&page), vec![Steps]);
        Ok(())
    }

    #[test]
    fn a_page_with_no_check_lacks_verify() -> Result<(), TestError> {
        let page = complete_with("## Check that it worked", "## Output")?;
        eq!(missing_parts(&page), vec![Verify]);
        Ok(())
    }

    #[test]
    fn a_check_that_shows_nothing_is_not_a_check() -> Result<(), TestError> {
        let page = complete_with("```text\n1 dialog\n```\n", "It prints one dialog.\n")?;
        eq!(missing_parts(&page), vec![Verify]);
        Ok(())
    }

    #[test]
    fn check_the_kernel_is_a_step_not_the_check() {
        shuts!(is_verify("Check the kernel"));
        shuts!(is_verify("Check what you have before going further"));
        shuts!(is_verify("Checklist"));
    }

    #[test]
    fn a_page_with_no_failures_section_lacks_troubleshoot() -> Result<(), TestError> {
        let page = complete_with("## When something does not work", "## Related")?;
        eq!(missing_parts(&page), vec![Troubleshoot]);
        Ok(())
    }

    #[test]
    fn a_limits_section_is_not_troubleshooting() {
        shuts!(is_troubleshoot("What does not work, and why"));
        shuts!(is_troubleshoot("What this does not do"));
        shuts!(is_troubleshoot("When the keys arrive after the call"));
    }

    #[test]
    fn a_part_at_level_four_does_not_count() {
        let page = COMPLETE
            .replace("## Before you start", "#### Before you start")
            .replace("## Check that it worked", "#### Check that it worked")
            .replace(
                "## When something does not work",
                "#### When something does not work",
            );
        eq!(
            missing_parts(&page),
            vec![Prerequisites, Verify, Troubleshoot]
        );
    }

    #[test]
    fn an_added_entry_with_no_link_is_a_gap() {
        let gap = entry_gap(
            "- **HEP over TLS.** It works.",
            &fixture_kind,
            &fixture_anchors,
        );
        assert!(
            gap.is_some_and(|why| why.contains("no link")),
            "no reason given"
        );
    }

    #[test]
    fn an_added_entry_that_links_only_a_reference_page_is_a_gap() {
        let entry = "- **X.** See [the flag](docs/cli-reference.md#capture).";
        let gap = entry_gap(entry, &fixture_kind, &fixture_anchors);
        assert!(
            gap.is_some_and(|why| why.contains("cli-reference")),
            "no reason given"
        );
    }

    #[test]
    fn a_link_to_a_task_page_without_a_heading_is_a_gap() {
        let entry = "- **X.** See [the guide](docs/hep.md).";
        let gap = entry_gap(entry, &fixture_kind, &fixture_anchors);
        assert!(
            gap.is_some_and(|why| why.contains("without a heading")),
            "no reason given"
        );
    }

    #[test]
    fn a_link_to_a_heading_the_task_page_lacks_is_a_gap() {
        let entry = "- **X.** See [the guide](docs/hep.md#no-such-heading).";
        let gap = entry_gap(entry, &fixture_kind, &fixture_anchors);
        assert!(
            gap.is_some_and(|why| why.contains("no-such-heading")),
            "no reason given"
        );
    }

    #[test]
    fn a_link_to_a_page_that_is_not_listed_is_a_gap() {
        let entry = "- **X.** See [the guide](docs/hep.md#collect-and-forward-hep).";
        let gap = entry_gap(entry, &no_kind, &fixture_anchors);
        assert!(
            gap.as_deref()
                .is_some_and(|why| why.contains("not in PAGES")),
            "a page with no kind cannot be a task page, got {gap:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Shapes at the edge of the rule
// ---------------------------------------------------------------------------

mod edge {
    use super::*;

    #[test]
    fn a_heading_inside_a_fenced_block_is_not_a_heading() {
        let page = "# T\n\n```sh\n## Before you start\n# comment\n```\n\n## Real\n";
        let titles: Vec<String> = sections(page).into_iter().map(|s| s.title).collect();
        eq!(titles, vec!["T".to_string(), "Real".to_string()]);
    }

    #[test]
    fn a_tilde_fence_is_a_fence() {
        let page = "# T\n\n~~~\n## Not a heading\n~~~\n";
        eq!(sections(page).len(), 1);
        opens!(is_fence("~~~"));
        opens!(is_fence("```sh"));
        shuts!(is_fence("`inline`"));
    }

    #[test]
    fn a_fence_indented_in_a_list_is_a_step() -> Result<(), TestError> {
        let page = complete_with(
            "```sh\nsipnab -N -I sample.pcap\n```\n",
            "1. Run it:\n\n   ```sh\n   sipnab -N -I sample.pcap\n   ```\n",
        )?;
        eq!(missing_parts(&page), Vec::<Part>::new());
        Ok(())
    }

    #[test]
    fn a_command_in_the_prerequisites_alone_is_not_the_steps() {
        let page = COMPLETE
            .replace("```sh\nsipnab -N -I sample.pcap\n```\n", "Run sipnab.\n")
            .replace(
                "- A sipnab binary.\n",
                "- A sipnab binary:\n\n```sh\nsipnab --version\n```\n\n",
            );
        eq!(missing_parts(&page), vec![Steps]);
    }

    #[test]
    fn a_section_ends_at_the_next_heading_of_its_level() -> Result<(), TestError> {
        // The fenced block sits under the next section, so the check has none.
        let page = complete_with(
            "```text\n1 dialog\n```\n",
            "## Output\n\n```text\n1 dialog\n```\n",
        )?;
        eq!(missing_parts(&page), vec![Verify]);
        Ok(())
    }

    #[test]
    fn a_section_keeps_its_subsections() -> Result<(), TestError> {
        let page = complete_with(
            "```text\n1 dialog\n```\n",
            "### From a file\n\n```text\n1 dialog\n```\n",
        )?;
        eq!(missing_parts(&page), Vec::<Part>::new());
        Ok(())
    }

    #[test]
    fn section_ranges_nest() {
        let page = "# T\n\n## A\n\n### A1\n\ntext\n\n## B\n";
        let got: Vec<(usize, usize, usize)> = sections(page)
            .iter()
            .map(|s| (s.level, s.start, s.end))
            .collect();
        eq!(got, vec![(1, 0, 9), (2, 2, 8), (3, 4, 8), (2, 8, 9)]);
    }

    #[test]
    fn other_systems_named_outside_the_prerequisites_do_not_count() {
        let page = COMPLETE
            .replace("- No change on any other system.\n", "")
            .replace(
                "The file is not a capture",
                "No other system is involved. The file is not a capture",
            );
        eq!(missing_parts(&page), vec![OtherSystems]);
    }

    #[test]
    fn headings_match_in_any_letter_case() {
        opens!(is_prerequisites("BEFORE YOU START"));
        opens!(is_verify("verify"));
        opens!(is_troubleshoot("TROUBLESHOOTING"));
        opens!(is_troubleshoot("when Something Does Not work"));
    }

    #[test]
    fn a_heading_title_drops_backticks_and_closing_hashes() {
        let page = "# T\n\n## Check that `sipnab` worked ##\n";
        let titles: Vec<String> = sections(page).into_iter().map(|s| s.title).collect();
        eq!(
            titles,
            vec!["T".to_string(), "Check that sipnab worked".to_string()]
        );
    }

    #[test]
    fn a_hash_without_a_space_is_not_a_heading() {
        eq!(sections("#hashtag\n\n#!shebang\n").len(), 0);
    }

    #[test]
    fn windows_line_endings_read_the_same() {
        let page = COMPLETE.replace('\n', "\r\n");
        eq!(missing_parts(&page), Vec::<Part>::new());
    }

    #[test]
    fn a_fence_left_open_runs_to_the_end() {
        let page = "# T\n\n```sh\n## Before you start\n";
        eq!(sections(page).len(), 1);
    }

    #[test]
    fn lists_tables_quotes_and_code_are_not_a_purpose() {
        let page = "# T\n\n- one two three four five six seven eight nine\n\
                    | a b c d e f g h i |\n> one two three four five six seven eight\n\
                    <!-- one two three four five six seven eight nine -->\n\
                    ```\none two three four five six seven eight nine\n```\n\n## S\n";
        eq!(purpose_words(page), 0);
    }

    #[test]
    fn prose_after_the_first_section_is_not_the_purpose() {
        let page = "# T\n\n## S\n\none two three four five six seven eight nine\n";
        eq!(purpose_words(page), 0);
    }

    #[test]
    fn eight_words_are_a_purpose() -> Result<(), TestError> {
        let page = complete_with(
            "Read a capture file and list its calls, when a ticket names a time and a number.",
            "Read a capture file and list its calls.",
        )?;
        eq!(missing_parts(&page), Vec::<Part>::new());
        Ok(())
    }

    #[test]
    fn versions_compare_as_numbers() {
        eq!(version("0.5.244"), Some((0, 5, 244)));
        eq!(version("Unreleased"), None);
        eq!(version("0.5"), None);
        eq!(version("0.5.x"), None);
        eq!(version("0.5.244.1"), None);
        assert!(
            version("0.5.1000") > version("0.5.244"),
            "1000 is after 244 as a number and before it as text"
        );
        assert!(
            version("0.6.0") > version("0.5.244"),
            "the minor number decides before the patch number"
        );
    }

    #[test]
    fn the_cutover_release_and_older_ones_are_not_read() {
        let log = "## [0.5.244] - 2026-11-10\n\n### Added\n\n- **Old.** Text.\n\n\
                   ## [0.5.9] - 2026-01-01\n\n### Added\n\n- **Older.** Text.\n";
        eq!(added_entries(log, CUTOVER), Vec::<(String, String)>::new());
    }

    #[test]
    fn entries_of_other_groups_are_not_read() {
        let log = "## [Unreleased]\n\n### Fixed\n\n- **F.** Text.\n\n### Added\n\n- **A.** Text.\n\n\
                   ### Changed\n\n- **C.** Text.\n";
        eq!(
            added_entries(log, CUTOVER),
            vec![("Unreleased".to_string(), "- **A.** Text.".to_string())]
        );
    }

    #[test]
    fn an_entry_keeps_its_indented_lines() {
        let log = "## [Unreleased]\n\n### Added\n\n- **A.** Text.\n  - sub [g](docs/hep.md#x)\n  more\n- **B.**\n";
        let entries = added_entries(log, CUTOVER);
        eq!(entries.len(), 2);
        eq!(
            entries.first().map(|(_, text)| text.as_str()),
            Some("- **A.** Text.\n  - sub [g](docs/hep.md#x)\n  more")
        );
    }

    #[test]
    fn a_link_on_a_continuation_line_counts() {
        let entry = "- **A.** Text.\n  See [the guide](docs/hep.md#collect-and-forward-hep).";
        eq!(entry_gap(entry, &fixture_kind, &fixture_anchors), None);
    }

    #[test]
    fn doc_links_are_split_into_page_and_anchor() {
        let entry = "[a](docs/hep.md#x-y) [b](docs/vcon.md) [c](https://example.com/docs/z.md#q) \
                     [d](docs/design/plan.md#p)";
        eq!(
            doc_links(entry),
            vec![
                ("hep".to_string(), "x-y".to_string()),
                ("vcon".to_string(), String::new()),
            ]
        );
    }
}

// ---------------------------------------------------------------------------
// The pages and the changelog of this repository
// ---------------------------------------------------------------------------

mod corpus {
    use super::*;

    fn gaps() -> Result<BTreeMap<String, Vec<Part>>, TestError> {
        let mut gaps = BTreeMap::new();
        for (stem, kind) in PAGES {
            if *kind != Task {
                continue;
            }
            let missing = missing_parts(&page_text(stem)?);
            if !missing.is_empty() {
                gaps.insert((*stem).to_string(), missing);
            }
        }
        Ok(gaps)
    }

    #[test]
    fn every_page_in_docs_has_a_kind() -> Result<(), TestError> {
        let mut on_disk = BTreeSet::new();
        for entry in std::fs::read_dir(repo().join("docs"))? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "md")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                on_disk.insert(stem.to_string());
            }
        }
        let listed: BTreeSet<String> = PAGES.iter().map(|(stem, _)| (*stem).to_string()).collect();
        let unlisted: Vec<&String> = on_disk.difference(&listed).collect();
        let gone: Vec<&String> = listed.difference(&on_disk).collect();
        assert!(
            unlisted.is_empty() && gone.is_empty(),
            "PAGES and docs/*.md differ. Give each new page a Kind in PAGES \
             (a page that tells the reader how to do something is a Task). \
             Not in PAGES: {unlisted:?}. In PAGES with no file: {gone:?}."
        );
        Ok(())
    }

    #[test]
    fn the_page_list_is_sorted_and_names_each_page_once() {
        let stems: Vec<&str> = PAGES.iter().map(|(stem, _)| *stem).collect();
        let mut sorted = stems.clone();
        sorted.sort_unstable();
        sorted.dedup();
        eq!(stems, sorted);
    }

    #[test]
    fn the_known_gaps_are_exactly_the_gaps() -> Result<(), TestError> {
        let known: BTreeMap<String, Vec<Part>> = KNOWN_GAPS
            .iter()
            .map(|(stem, parts)| ((*stem).to_string(), parts.to_vec()))
            .collect();
        let found = gaps()?;
        let mut report = Vec::new();
        for (stem, missing) in &found {
            match known.get(stem) {
                None => report.push(format!(
                    "docs/{stem}.md is a task page and lacks {missing:?}: add the parts \
                     (see the table at the top of this file)"
                )),
                Some(parts) if parts != missing => report.push(format!(
                    "docs/{stem}.md lacks {missing:?}, KNOWN_GAPS says {parts:?}: \
                     update its entry if parts were added, restore the part if one was lost"
                )),
                Some(_) => {}
            }
        }
        for stem in known.keys() {
            if !found.contains_key(stem) {
                report.push(format!(
                    "docs/{stem}.md has every part: remove its entry from KNOWN_GAPS"
                ));
            }
        }
        assert!(report.is_empty(), "\n{}", report.join("\n"));
        Ok(())
    }

    #[test]
    fn the_known_gaps_name_task_pages_once_in_order() {
        let stems: Vec<&str> = KNOWN_GAPS.iter().map(|(stem, _)| *stem).collect();
        let mut sorted = stems.clone();
        sorted.sort_unstable();
        sorted.dedup();
        eq!(stems, sorted);
        for (stem, parts) in KNOWN_GAPS {
            eq!(page_kind(stem), Some(Task), "{stem} is not a task page");
            assert!(!parts.is_empty(), "{stem} has an empty entry");
            let mut ordered = parts.to_vec();
            ordered.sort_unstable();
            ordered.dedup();
            eq!(parts.to_vec(), ordered, "{stem}: parts out of order");
        }
    }

    #[test]
    fn every_task_page_is_linked_from_the_docs_index() -> Result<(), TestError> {
        let index = page_text("README")?;
        let unlinked: Vec<&str> = PAGES
            .iter()
            .filter(|(_, kind)| *kind == Task)
            .map(|(stem, _)| *stem)
            .filter(|stem| !index.contains(&format!("]({stem}.md")))
            .collect();
        assert!(unlinked.is_empty(), "docs/README.md links no {unlinked:?}");
        Ok(())
    }

    #[test]
    fn every_added_entry_after_the_cutover_links_a_task_heading() -> Result<(), TestError> {
        let changelog = std::fs::read_to_string(repo().join("CHANGELOG.md"))?;
        let anchors = |stem: &str| -> BTreeSet<String> {
            page_text(stem)
                .map(|text| sections(&text).iter().map(|s| slug(&s.title)).collect())
                .unwrap_or_default()
        };
        let mut report = Vec::new();
        for (release, entry) in added_entries(&changelog, CUTOVER) {
            if let Some(why) = entry_gap(&entry, &page_kind, &anchors) {
                let head: String = entry.chars().take(90).collect();
                report.push(format!("[{release}] {head}: {why}"));
            }
        }
        assert!(
            report.is_empty(),
            "an Added entry leads to no how-to. Link each to a heading of a task page, \
             as (docs/<page>.md#<heading>):\n{}",
            report.join("\n")
        );
        Ok(())
    }

    #[test]
    fn the_changelog_reader_sees_the_releases_before_the_cutover() -> Result<(), TestError> {
        // Read with a cutover of 0.0.0, the reader must find the Added
        // entries the file is known to hold: a reader that finds none would
        // pass the test above on any changelog.
        let changelog = std::fs::read_to_string(repo().join("CHANGELOG.md"))?;
        let all = added_entries(&changelog, (0, 0, 0));
        let in_0_5_233 = all
            .iter()
            .filter(|(release, _)| release == "0.5.233")
            .count();
        eq!(in_0_5_233, 17);
        Ok(())
    }

    #[test]
    fn the_rule_finds_the_complete_pages_complete() -> Result<(), TestError> {
        // Without this, a rule that reported every part of every page as
        // missing would still agree with a KNOWN_GAPS written from it.
        for stem in ["archives", "first-cli-triage", "hep", "install", "mtls"] {
            eq!(
                missing_parts(&page_text(stem)?),
                Vec::<Part>::new(),
                "{stem}"
            );
        }
        Ok(())
    }
}
