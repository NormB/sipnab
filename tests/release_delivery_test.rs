// SPDX-License-Identifier: MIT OR Apache-2.0

//! Finished work must not sit undelivered without saying so.
//!
//! Every other gate in this repository measures whether the tree is CORRECT.
//! `release_completeness_test.rs` is the closest thing to a delivery gate and
//! all fourteen of its checks describe a release that has already been tagged:
//! does the site advertise it, does the date match, does the changelog carry an
//! entry. Not one of them can fire while work is finished, committed, green,
//! and simply not shipped.
//!
//! That gap is not hypothetical. On 2026-08-28 three P0 fixes — a filter
//! expression that aborted the process over authenticated HTTP, a HEP HMAC that
//! did not cover the addresses a packet asserts, and sniffed relay control
//! accepted from any source — sat on `main` behind a green tree while the
//! release commit kept growing. The suite was green the entire time. Nothing
//! objected, because nothing was watching the distance between "done" and
//! "deployed".
//!
//! These tests watch that distance. They are deliberately about LATENCY rather
//! than correctness: the question each one asks is not "is this right" but
//! "does anyone outside this machine have it, and if not, does the repository
//! admit that".

#![cfg(feature = "full")]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repository file, panicking with the path on failure.
fn read(rel: &str) -> String {
    let p = repo().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Run a git command in the repository and return stdout, or `None` when git
/// itself could not answer.
///
/// `None` and `Some("")` are deliberately different. A checkout with no tags
/// and a git that could not run look identical to a caller that folds them
/// together, and every gate below would then pass by examining nothing.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo())
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// A semantic version triple parsed from `0.5.130` or `v0.5.130`.
fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim().trim_start_matches('v');
    let mut it = s.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((a, b, c))
}

/// The version in `Cargo.toml`.
fn crate_version() -> (u32, u32, u32) {
    let toml = read("Cargo.toml");
    let line = toml
        .lines()
        .find(|l| l.trim_start().starts_with("version"))
        .expect("Cargo.toml has a version line");
    let raw = line.split('"').nth(1).expect("quoted version");
    parse_version(raw).unwrap_or_else(|| panic!("unparseable crate version {raw:?}"))
}

/// Every `vX.Y.Z` tag in the repository, ascending.
fn tags() -> Vec<(u32, u32, u32)> {
    let out = git(&["tag", "--list", "v*"]).unwrap_or_default();
    let mut v: Vec<_> = out.lines().filter_map(parse_version).collect();
    v.sort_unstable();
    v
}

/// The newest release tag, or `None` in a checkout that has none.
fn newest_tag() -> Option<(u32, u32, u32)> {
    tags().last().copied()
}

/// How many commits `HEAD` is ahead of the newest tag.
///
/// `None` means git could not answer — a shallow clone, a checkout with no
/// tags, or no git at all. Callers must treat that as "cannot tell" rather
/// than as zero.
fn commits_since_newest_tag() -> Option<u32> {
    let t = newest_tag()?;
    let tag = format!("v{}.{}.{}", t.0, t.1, t.2);
    git(&["rev-list", "--count", &format!("{tag}..HEAD")])?
        .parse()
        .ok()
}

/// Paths whose change since a tag means users are missing something that
/// matters, rather than a documentation tidy-up.
const SHIPPABLE: &[&str] = &["src/", "Cargo.toml", "Cargo.lock"];

/// Files changed between the newest tag and `HEAD`.
fn changed_since_newest_tag() -> Option<Vec<String>> {
    let t = newest_tag()?;
    let tag = format!("v{}.{}.{}", t.0, t.1, t.2);
    Some(
        git(&["diff", "--name-only", &format!("{tag}..HEAD")])?
            .lines()
            .map(str::to_string)
            .collect(),
    )
}

/// Whether anything shippable changed since the newest tag.
fn has_unreleased_code() -> Option<bool> {
    Some(
        changed_since_newest_tag()?
            .iter()
            .any(|f| SHIPPABLE.iter().any(|p| f.starts_with(p))),
    )
}

/// Every version heading in `CHANGELOG.md`, plus whether an `[Unreleased]`
/// heading is present.
fn changelog_sections() -> (Vec<(u32, u32, u32)>, bool) {
    let text = read("CHANGELOG.md");
    let mut versions = Vec::new();
    let mut unreleased = false;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("## ") else {
            continue;
        };
        let rest = rest.trim();
        if rest.to_ascii_lowercase().starts_with("[unreleased]") {
            unreleased = true;
            continue;
        }
        if let Some(inner) = rest.strip_prefix('[')
            && let Some(end) = inner.find(']')
            && let Some(v) = parse_version(&inner[..end])
        {
            versions.push(v);
        }
    }
    (versions, unreleased)
}

/// The body of the `[Unreleased]` section, if it has one.
fn unreleased_body() -> Option<String> {
    let text = read("CHANGELOG.md");
    let start = text
        .lines()
        .position(|l| l.starts_with("## ") && l.to_ascii_lowercase().contains("[unreleased]"))?;
    let body: Vec<&str> = text
        .lines()
        .skip(start + 1)
        .take_while(|l| !l.starts_with("## "))
        .collect();
    Some(body.join("\n"))
}

/// The version the website advertises.
fn published_version() -> (u32, u32, u32) {
    let cfg = read("website/config.toml");
    let line = cfg
        .lines()
        .find(|l| l.trim_start().starts_with("published_version"))
        .expect("website/config.toml sets published_version");
    let raw = line.split('"').nth(1).expect("quoted published_version");
    parse_version(raw).unwrap_or_else(|| panic!("unparseable published_version {raw:?}"))
}

/// Files the SECOND phase of a release touches, and nothing else.
///
/// `reference_sipnab_release_flow` is deliberately two-phase: tag and publish
/// artifacts first, then move `published_version` so the site advertises a
/// release a visitor can actually download. That second commit necessarily
/// lands AFTER the tag, and it is part of shipping that version rather than
/// new work waiting to ship.
///
/// Without this, the delivery gates below make the documented flow impossible
/// to complete: they demand a CHANGELOG entry for the very commit whose only
/// job is to advertise the entry that already exists. That is not
/// hypothetical -- it turned `main` red on 0.5.131's advertisement commit, and
/// this list is the fix.
const ADVERTISEMENT_PATHS: &[&str] = &[
    "website/config.toml",
    "docs/install.md",
    "website/content/", // the generated mirrors of the above
    "website/static/",  // llms.txt and friends, regenerated with them
    "CHANGELOG.md",     // redating the entry to the day it published
];

/// Whether every change since the newest tag is that tag's own advertisement.
///
/// Returns `None` when git cannot answer, which callers must treat as "cannot
/// tell" rather than as "yes".
fn only_advertises_the_newest_tag() -> Option<bool> {
    let changed = changed_since_newest_tag()?;
    Some(is_advertisement(
        &changed,
        published_version(),
        newest_tag()?,
    ))
}

/// The decision itself, over values rather than over the working tree.
///
/// Pure on purpose. The first version read git and the filesystem inline, and
/// two mutations survived because this tree cannot exercise the branches: the
/// changeset is never empty here, and `published_version` already equals the
/// newest tag, so deleting either check changed nothing observable. A gate
/// whose logic can only be run against one state is a gate whose logic is
/// mostly untested.
fn is_advertisement(
    changed: &[String],
    published: (u32, u32, u32),
    newest_tag: (u32, u32, u32),
) -> bool {
    // An empty changeset advertises nothing. Saying `true` here would exempt
    // the case where git reported nothing at all.
    if changed.is_empty() {
        return false;
    }
    if !changed
        .iter()
        .all(|f| ADVERTISEMENT_PATHS.iter().any(|p| f.starts_with(p)))
    {
        return false;
    }
    // It must advertise THIS tag, not merely touch those files: a commit that
    // edits config.toml while leaving the site behind the newest release is
    // ordinary work wearing the release flow's clothes.
    published == newest_tag
}

// ── A. Unreleased work must declare itself ──────────────────────────

/// Code changed since the last tag must be declared in the changelog.
///
/// **This is the gate whose absence let three P0 fixes sit unshipped.** The
/// tree was green, the suite passed, and nothing anywhere said users did not
/// have them. An `[Unreleased]` heading costs one line and turns invisible
/// latency into a visible fact.
#[test]
fn code_changed_since_the_last_tag_is_declared_in_the_changelog() {
    let Some(unreleased_code) = has_unreleased_code() else {
        // Cannot tell — say so rather than passing. A shallow clone is the
        // usual cause and is a legitimate reason not to judge.
        eprintln!("SKIP: git could not report changes since the newest tag");
        return;
    };
    if !unreleased_code {
        return;
    }
    if only_advertises_the_newest_tag() == Some(true) {
        return;
    }
    let (_, has_unreleased_heading) = changelog_sections();
    let newest_changelog = {
        let mut v = changelog_sections().0;
        v.sort_unstable();
        v.last().copied()
    };
    let ahead_of_changelog =
        newest_changelog.is_some_and(|c| c > newest_tag().unwrap_or((0, 0, 0)));
    assert!(
        has_unreleased_heading || ahead_of_changelog,
        "src/ or the manifest changed since {:?} and CHANGELOG.md has neither an \
         [Unreleased] section nor an entry for a version newer than that tag. \
         Finished work that users do not have must be visible in the tree; a \
         green suite says the code is right, not that anyone has it.",
        newest_tag()
    );
}

/// An `[Unreleased]` section must not be empty.
///
/// A heading with nothing under it is worse than no heading: it reads as "we
/// checked, there is nothing", which is the one conclusion an unreleased P0
/// disproves.
#[test]
fn an_unreleased_section_is_never_an_empty_promise() {
    let Some(body) = unreleased_body() else {
        return;
    };
    let meaningful = body
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with("###") && !t.starts_with("<!--")
        })
        .count();
    assert!(
        meaningful > 0,
        "CHANGELOG.md has an [Unreleased] heading with no entries under it. \
         Delete the heading or fill it in — an empty section claims the \
         question was asked and answered."
    );
}

/// An `[Unreleased]` section requires unreleased work to exist.
#[test]
fn an_unreleased_section_exists_only_when_something_is_unreleased() {
    let (_, has_unreleased) = changelog_sections();
    if !has_unreleased {
        return;
    }
    let Some(n) = commits_since_newest_tag() else {
        return;
    };
    assert!(
        n > 0,
        "CHANGELOG.md carries an [Unreleased] section while HEAD is exactly at \
         the newest tag. Either the section is stale from the last release or \
         the tag was moved; both make the section describe nothing."
    );
}

/// Unreleased commits are bounded, and the bound is the alarm.
///
/// Not a style rule. Each commit that lands without shipping widens the gap
/// between what is proven and what is delivered, and the failure this file
/// exists for was exactly that gap growing while every other gate stayed
/// green. The number is deliberately generous — this fires on a stall, not on
/// ordinary batching.
#[test]
fn unreleased_commits_do_not_accumulate_without_a_release() {
    const MAX_UNRELEASED_COMMITS: u32 = 25;
    let Some(n) = commits_since_newest_tag() else {
        eprintln!("SKIP: git could not count commits since the newest tag");
        return;
    };
    assert!(
        n <= MAX_UNRELEASED_COMMITS,
        "{n} commits since {:?} without a release. Cut one, or say in \
         CHANGELOG.md's [Unreleased] section why the work is being held. A \
         backlog of unreleased commits is invisible to every other gate here.",
        newest_tag()
    );
}

/// A security fix must never be quietly unreleased.
///
/// Ranked separately from ordinary code because the consequence is different:
/// an unshipped feature is a delay, an unshipped security fix is an exposure
/// with a known remedy sitting in a repository.
#[test]
fn a_security_relevant_change_since_the_tag_is_declared() {
    const SECURITY_PATHS: &[&str] = &[
        "src/capture/hep.rs",
        "src/privilege.rs",
        "src/sip/dsl.rs",
        "src/rtpengine/",
        "src/mcp/",
        "src/output/api.rs",
        "SECURITY.md",
    ];
    let Some(changed) = changed_since_newest_tag() else {
        return;
    };
    let touched: Vec<&String> = changed
        .iter()
        .filter(|f| SECURITY_PATHS.iter().any(|p| f.starts_with(p)))
        .collect();
    if touched.is_empty() {
        return;
    }
    if only_advertises_the_newest_tag() == Some(true) {
        return;
    }
    let (_, has_unreleased) = changelog_sections();
    let newest_changelog = {
        let mut v = changelog_sections().0;
        v.sort_unstable();
        v.last().copied()
    };
    let declared =
        has_unreleased || newest_changelog.is_some_and(|c| c > newest_tag().unwrap_or((0, 0, 0)));
    assert!(
        declared,
        "security-relevant files changed since {:?} and nothing in CHANGELOG.md \
         says so: {touched:?}. A fix that exists only in this repository \
         protects nobody.",
        newest_tag()
    );
}

/// The newest changelog entry is the crate version or newer.
#[test]
fn the_changelog_never_trails_the_crate_version() {
    let (mut versions, _) = changelog_sections();
    // Sections are written newest-first, so `last()` is the OLDEST entry.
    // Sorting makes the intent explicit and survives a file that is out of
    // order — which `changelog_sections_are_ordered_newest_first` catches
    // separately rather than silently compensating for here.
    versions.sort_unstable();
    let Some(newest) = versions.last().copied() else {
        panic!("CHANGELOG.md has no version sections at all");
    };
    assert!(
        newest >= crate_version(),
        "the crate is {:?} and the newest changelog entry is {newest:?}. A \
         version with no entry ships undocumented.",
        crate_version()
    );
}

/// Changelog version sections descend, newest first.
#[test]
fn changelog_sections_are_ordered_newest_first() {
    let (versions, _) = changelog_sections();
    let mut sorted = versions.clone();
    sorted.sort_unstable();
    sorted.reverse();
    let as_written: Vec<_> = versions.to_vec();
    let expected: Vec<_> = sorted;
    assert_eq!(
        as_written, expected,
        "CHANGELOG.md sections are out of order; a reader takes the first \
         entry as the newest"
    );
}

// ── B. The site must not lag silently ───────────────────────────────

/// The site never advertises a version the crate has not reached.
#[test]
fn the_site_never_advertises_a_version_ahead_of_the_crate() {
    assert!(
        published_version() <= crate_version(),
        "the site advertises {:?} and the crate is {:?}; a visitor is offered \
         something that was never built here",
        published_version(),
        crate_version()
    );
}

/// The advertised version has a tag.
#[test]
fn the_advertised_version_has_a_tag_in_this_repository() {
    let t = tags();
    if t.is_empty() {
        eprintln!("SKIP: no tags in this checkout");
        return;
    }
    assert!(
        t.contains(&published_version()),
        "the site advertises {:?}, which has no tag. published_version must \
         move only to a release that exists.",
        published_version()
    );
}

/// The site is at most one patch release behind the crate.
///
/// One is the legal interim state of the two-phase flow: the crate is bumped
/// and tagged, artifacts build, then `published_version` moves. Two means a
/// release was cut and never advertised — the failure that shipped 0.5.128 to
/// nobody.
#[test]
fn the_site_is_at_most_one_release_behind_the_crate() {
    let (cm, cn, cp) = crate_version();
    let (pm, pn, pp) = published_version();
    if (cm, cn) != (pm, pn) {
        // A minor bump is a different conversation; the patch rule does not
        // apply across it and asserting it would misfire.
        return;
    }
    assert!(
        cp.saturating_sub(pp) <= 1,
        "the crate is {:?} and the site still advertises {:?}. More than one \
         release behind means a tagged release was never advertised, which is \
         indistinguishable to a visitor from it never existing.",
        crate_version(),
        published_version()
    );
}

/// The advertised version has a changelog entry.
#[test]
fn the_advertised_version_is_described_in_the_changelog() {
    let (versions, _) = changelog_sections();
    assert!(
        versions.contains(&published_version()),
        "the site advertises {:?} and CHANGELOG.md does not describe it",
        published_version()
    );
}

/// Every tag has a changelog entry.
///
/// The reverse direction, and the one that catches a release cut in a hurry:
/// artifacts exist, the tag exists, and nothing says what changed.
#[test]
fn every_tag_is_described_in_the_changelog() {
    let (versions, _) = changelog_sections();
    let described: BTreeSet<_> = versions.into_iter().collect();
    let undescribed: Vec<_> = tags()
        .into_iter()
        .filter(|t| !described.contains(t))
        .collect();
    assert!(
        undescribed.is_empty(),
        "these tags have no changelog entry: {undescribed:?}"
    );
}

// ── C. The instruments must be able to fire ─────────────────────────

/// The tag scan found real tags.
#[test]
fn the_tag_scan_reads_a_real_repository() {
    let t = tags();
    assert!(
        !t.is_empty(),
        "no v*.*.* tags found. Every gate above that compares against a tag \
         would pass by examining nothing."
    );
    assert!(
        t.len() >= 5,
        "only {} tag(s) found; this repository has many, so the parser has \
         stopped matching",
        t.len()
    );
}

/// The changelog parser found real sections.
#[test]
fn the_changelog_parser_reads_real_sections() {
    let (versions, _) = changelog_sections();
    assert!(
        versions.len() >= 5,
        "the changelog parser found {} version section(s); it has stopped \
         matching and every comparison against it is vacuous",
        versions.len()
    );
}

/// `git` answering and `git` reporting nothing are different outcomes.
///
/// The distinction this whole file rests on. If `commits_since_newest_tag`
/// folded a git failure into `0`, every latency gate here would report a
/// perfectly shipped repository from a checkout where git does not work.
#[test]
fn a_git_failure_is_not_reported_as_zero_commits() {
    assert!(
        git(&["rev-parse", "--git-dir"]).is_some(),
        "git cannot answer here; the gates in this file must SKIP rather than \
         pass, and this test is what proves they can tell the difference"
    );
    assert!(
        git(&["cat-file", "-p", "0000000000000000000000000000000000000000"]).is_none(),
        "a failing git command returned Some(...); the helper cannot \
         distinguish 'nothing to report' from 'could not look'"
    );
}

/// The version parser accepts the forms this repository uses and rejects junk.
#[test]
fn the_version_parser_accepts_real_forms_and_rejects_junk() {
    assert_eq!(parse_version("0.5.130"), Some((0, 5, 130)));
    assert_eq!(parse_version("v0.5.130"), Some((0, 5, 130)));
    assert_eq!(parse_version(" v0.5.130 "), Some((0, 5, 130)));
    assert_eq!(
        parse_version("0.5"),
        None,
        "a two-part version is not a release"
    );
    assert_eq!(
        parse_version("0.5.130.1"),
        None,
        "four parts is not a release"
    );
    assert_eq!(parse_version("v0.5.x"), None);
    assert_eq!(parse_version(""), None);
}

/// The unreleased-section reader distinguishes absent, empty and filled.
#[test]
fn the_unreleased_reader_tells_absent_from_empty() {
    // Against the real file, whatever state it is in, the reader must return
    // a value consistent with the heading's presence.
    let text = read("CHANGELOG.md");
    let heading_present = text
        .lines()
        .any(|l| l.starts_with("## ") && l.to_ascii_lowercase().contains("[unreleased]"));
    assert_eq!(
        unreleased_body().is_some(),
        heading_present,
        "the reader disagrees with the file about whether an [Unreleased] \
         heading exists"
    );
}

/// The shippable-path list actually matches this tree's layout.
///
/// A path list that matches nothing turns `has_unreleased_code` into a
/// permanent `false`, and the loudest gate in this file would go quiet.
#[test]
fn the_shippable_path_list_matches_this_repository() {
    for p in SHIPPABLE {
        let target = repo().join(p.trim_end_matches('/'));
        assert!(
            target.exists(),
            "SHIPPABLE names {p}, which does not exist; the unreleased-code \
             check would never fire"
        );
    }
}

// ── D. The two-phase release contract, stated as states ─────────────

/// Every state between "committed" and "deployed" has a gate that can see it.
///
/// The meta-test, and the one that names the actual defect. Work passes
/// through: committed -> pushed -> tagged -> artifacts published -> advertised
/// on the site. `release_completeness_test.rs` covers the last two transitions
/// well. Nothing covered the first two, which is precisely where three P0
/// fixes stalled while every gate stayed green.
///
/// This asserts a named gate exists for each transition, so deleting one is a
/// visible act rather than a silent narrowing.
#[test]
fn every_transition_from_committed_to_deployed_has_a_gate() {
    let this_file = read("tests/release_delivery_test.rs");
    let completeness = read("tests/release_completeness_test.rs");
    let both = format!("{this_file}\n{completeness}");

    let transitions: &[(&str, &str)] = &[
        (
            "committed but unreleased",
            "code_changed_since_the_last_tag_is_declared_in_the_changelog",
        ),
        (
            "unreleased work accumulating",
            "unreleased_commits_do_not_accumulate_without_a_release",
        ),
        (
            "security fix unreleased",
            "a_security_relevant_change_since_the_tag_is_declared",
        ),
        (
            "tagged but not advertised",
            "the_site_is_at_most_one_release_behind_the_crate",
        ),
        (
            "artifacts exist, site stale",
            "the_site_advertises_the_newest_release_whose_assets_exist",
        ),
        (
            "advertised but undocumented",
            "the_advertised_version_is_described_in_the_changelog",
        ),
    ];
    let missing: Vec<&str> = transitions
        .iter()
        .filter(|(_, gate)| !both.contains(gate))
        .map(|(state, _)| *state)
        .collect();
    assert!(
        missing.is_empty(),
        "no gate covers these states between finished and delivered: \
         {missing:?}. Each uncovered state is one a green tree can sit in \
         indefinitely without anyone noticing."
    );
}

/// The crate version and the newest tag are in one of two legal states.
#[test]
fn the_crate_version_and_newest_tag_are_in_a_legal_pair() {
    let Some(t) = newest_tag() else {
        return;
    };
    let c = crate_version();
    assert!(
        c >= t,
        "the crate is {c:?} and a tag {t:?} exists ahead of it; a tag must \
         never name a version the tree has not reached"
    );
}

/// A version bump obliges a changelog entry in the same tree.
#[test]
fn a_version_bump_carries_its_changelog_entry() {
    let Some(t) = newest_tag() else {
        return;
    };
    let c = crate_version();
    if c == t {
        return;
    }
    let (versions, _) = changelog_sections();
    assert!(
        versions.contains(&c),
        "the crate was bumped to {c:?} past the newest tag {t:?} and \
         CHANGELOG.md has no entry for it. The bump and its description belong \
         in the same commit; separated, the entry is written from memory."
    );
}

/// Closed P0 backlog items must be released or declared unreleased.
///
/// Ties the backlog to delivery. An item marked done is a promise that the
/// problem is gone; while it sits untagged it is gone only here.
#[test]
fn a_p0_marked_done_is_released_or_declared() {
    let backlog = read("docs/design/backlog.md");
    let p0_start = backlog
        .find("## P0 — panics & security")
        .expect("backlog has a P0 section");
    let p0_end = backlog[p0_start..]
        .find("\n## P1")
        .map(|i| p0_start + i)
        .unwrap_or(backlog.len());
    let p0 = &backlog[p0_start..p0_end];
    let closed = p0.matches("- [x] **").count();
    assert!(
        closed >= 5,
        "only {closed} closed P0 item(s) found; the scan has stopped matching \
         and this gate proves nothing"
    );
    let open = p0.matches("- [ ] **").count();
    if open > 0 {
        // Open P0s are a different problem and are not this gate's business.
        return;
    }
    let Some(n) = commits_since_newest_tag() else {
        return;
    };
    if n == 0 {
        return;
    }
    if only_advertises_the_newest_tag() == Some(true) {
        // Phase two of this very release. Nothing is waiting to ship.
        return;
    }
    let (_, has_unreleased) = changelog_sections();
    let newest_changelog = {
        let mut v = changelog_sections().0;
        v.sort_unstable();
        v.last().copied()
    };
    let declared =
        has_unreleased || newest_changelog.is_some_and(|c| c > newest_tag().unwrap_or((0, 0, 0)));
    assert!(
        declared,
        "every P0 is closed and {n} commit(s) sit past {:?} with nothing in \
         CHANGELOG.md saying so. Closing a P0 in a repository nobody can \
         install from is half the job.",
        newest_tag()
    );
}

/// `published_version` never names a version with no changelog date.
#[test]
fn the_advertised_version_carries_a_date() {
    let text = read("CHANGELOG.md");
    let (pm, pn, pp) = published_version();
    let heading = format!("## [{pm}.{pn}.{pp}]");
    let line = text
        .lines()
        .find(|l| l.starts_with(&heading))
        .unwrap_or_else(|| panic!("no changelog heading for the advertised {pm}.{pn}.{pp}"));
    assert!(
        line.contains(" - 2"),
        "the advertised version's changelog heading carries no date: {line:?}. \
         An undated entry cannot be checked against the release."
    );
}

/// The advertisement exemption must not swallow ordinary work.
///
/// It exists so the release flow's own second phase — moving
/// `published_version` after the artifacts exist — does not read as
/// undeclared work. An exemption that also covered a `src/` change would
/// silence the gates this file is entirely about, and it would do so
/// invisibly, because the tree would simply go quiet.
#[test]
fn the_advertisement_exemption_stays_narrow() {
    // Nothing under src/ or tests/ may be reachable through it.
    for forbidden in [
        "src/main.rs",
        "src/mcp/server.rs",
        "tests/foo.rs",
        "Cargo.toml",
    ] {
        assert!(
            !ADVERTISEMENT_PATHS.iter().any(|p| forbidden.starts_with(p)),
            "{forbidden} is reachable through ADVERTISEMENT_PATHS; a code \
             change would then count as advertising a release"
        );
    }
    // And every path it does name must exist, or the exemption is describing
    // a tree that is not this one.
    for p in ADVERTISEMENT_PATHS {
        let target = repo().join(p.trim_end_matches('/'));
        assert!(
            target.exists(),
            "ADVERTISEMENT_PATHS names {p}, which does not exist here"
        );
    }
    assert!(
        ADVERTISEMENT_PATHS.len() <= 6,
        "the exemption has grown to {} paths; each one is a place undeclared \
         work can hide, so widening it should be deliberate rather than \
         incremental",
        ADVERTISEMENT_PATHS.len()
    );
}

/// The exemption applies only when the site actually names the newest tag.
///
/// Touching `website/config.toml` is not the same as advertising a release. A
/// commit that edits it while leaving `published_version` behind the newest
/// tag is ordinary work wearing the release flow's clothes, and must still be
/// declared.
#[test]
fn the_advertisement_exemption_requires_the_site_to_name_the_newest_tag() {
    let Some(tag) = newest_tag() else {
        eprintln!("SKIP: no tags in this checkout");
        return;
    };
    let ads: Vec<String> = vec!["website/config.toml".into(), "docs/install.md".into()];

    // The shape the exemption exists for: only advertisement files, and the
    // site naming the tag.
    assert!(
        is_advertisement(&ads, tag, tag),
        "the exemption must fire for the release flow's own second phase"
    );
    // Same files, but the site is a release behind: ordinary work.
    let behind = (tag.0, tag.1, tag.2.saturating_sub(1));
    assert!(
        !is_advertisement(&ads, behind, tag),
        "a commit touching the advertisement files while the site still names \
         {behind:?} against a newest tag of {tag:?} is not advertising it"
    );
    // Advertisement files plus one code file: not an advertisement.
    let mixed: Vec<String> = vec!["website/config.toml".into(), "src/main.rs".into()];
    assert!(
        !is_advertisement(&mixed, tag, tag),
        "a changeset containing code is never merely an advertisement"
    );
    // Nothing changed: nothing advertised.
    assert!(
        !is_advertisement(&[], tag, tag),
        "an empty changeset advertises nothing; returning true here would \
         exempt the case where git reported nothing at all"
    );
}
