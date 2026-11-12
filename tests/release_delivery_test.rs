// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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

#[path = "support/release_logic.rs"]
mod release_logic;
#[path = "support/release_tags.rs"]
mod release_tags;
#[path = "../src/test_scratch.rs"]
mod test_scratch;

use release_logic::{
    ADVERTISEMENT_PATHS, is_advertisement, is_advertisement_beside_dependency_bumps,
    is_dependency_bump, parse_version, unreleased_accumulation,
};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repository file, panicking with the path on failure.
fn read(rel: &str) -> Result<String, TestError> {
    let p = repo().join(rel);
    Ok(std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?)
}

/// The working backlog, which is local and gitignored (see
/// `docs/design/backlog.md`, the tracked stub). `None` in any clone that has no
/// local copy — CI included — and a gate that cannot read it must skip rather
/// than invent a verdict about work it cannot see.
fn local_backlog() -> Option<String> {
    std::fs::read_to_string(repo().join("docs/design/backlog.local.md")).ok()
}

/// Run a git command in the repository and return stdout, or `None` when git
/// itself could not answer.
///
/// `None` and `Some("")` are deliberately different. A checkout with no tags
/// and a git that could not run look identical to a caller that folds them
/// together, and every gate below would then pass by examining nothing.
fn git(args: &[&str]) -> Option<String> {
    git_stdout(Command::new("git").arg("-C").arg(repo()).args(args))
}

/// The trimmed stdout of a git command, or `None` when it could not answer.
fn git_stdout(cmd: &mut Command) -> Option<String> {
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The version in `Cargo.toml`.
fn crate_version() -> Result<(u32, u32, u32), TestError> {
    let toml = read("Cargo.toml")?;
    let line = toml
        .lines()
        .find(|l| l.trim_start().starts_with("version"))
        .ok_or("Cargo.toml has a version line")?;
    let raw = line.split('"').nth(1).ok_or("quoted version")?;
    Ok(parse_version(raw).ok_or_else(|| format!("unparseable crate version {raw:?}"))?)
}

/// Every `vX.Y.Z` tag that counts for this checkout
/// (`tests/support/release_tags.rs`), ascending.
fn tags() -> Vec<(u32, u32, u32)> {
    let out = release_tags::reachable_release_tags(&repo()).unwrap_or_default();
    let mut v: Vec<_> = out.iter().filter_map(|t| parse_version(t)).collect();
    v.sort_unstable();
    v
}

/// What a release gate should do when it cannot establish its own input.
///
/// These gates compare the tree against the newest tag, and git cannot always
/// answer: a shallow clone has no history to count, a fresh checkout has no
/// tags. Skipping is right there — refusing to judge is honest, and failing
/// would make the suite unrunnable in environments that are merely limited.
///
/// It is exactly wrong at push time. There git is present, the tags are
/// fetched, and the commit under judgement exists; a gate that still cannot
/// answer is broken rather than limited, and skipping hides that behind the
/// same green as a real pass. `.githooks/pre-push` sets
/// `SIPNAB_RELEASE_GATES_STRICT=1` to say which situation this is.
#[derive(Debug, PartialEq, Eq)]
enum CannotTell {
    /// Say so on stderr and decline to judge.
    Skip,
    /// Fail, naming what could not be established.
    Fail,
}

/// Pure, so both arms can be driven. The environment is an argument rather
/// than a read, because a test that has to set a process-global variable to
/// exercise a branch poisons every test running beside it.
fn cannot_tell_verdict(strict: bool) -> CannotTell {
    if strict {
        CannotTell::Fail
    } else {
        CannotTell::Skip
    }
}

/// Whether this run is the one that has everything it needs.
fn strict_release_gates() -> bool {
    std::env::var("SIPNAB_RELEASE_GATES_STRICT").is_ok_and(|v| v == "1")
}

/// Report a gate that cannot establish its input, and panic under strict mode.
///
/// Returns on the skip path so the caller can `return` immediately after.
fn cannot_tell(what: &str) -> Result<(), TestError> {
    match cannot_tell_verdict(strict_release_gates()) {
        CannotTell::Skip => eprintln!("SKIP: {what}"),
        CannotTell::Fail => {
            return Err(format!(
                "{what}. At push time git has everything it needs, so this is a \
             broken gate rather than a limited checkout — and a gate that \
             declines to look is indistinguishable from one that passed. \
             (Set by SIPNAB_RELEASE_GATES_STRICT=1 in .githooks/pre-push.)"
            )
            .into());
        }
    }
    Ok(())
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

/// The git arguments that list the files differing from a tag.
///
/// The tag is compared with the working tree, not with `HEAD`. Every other
/// gate in this file reads the working tree (`CHANGELOG.md`, `Cargo.toml`,
/// the site configuration), and the pre-commit hook runs these tests before
/// the commit exists. With `<tag>..HEAD`, a merge of the release into a
/// branch from before it was judged by the commit before the merge, and the
/// hook refused it on 2026-11-10: every file of the release counted as code
/// changed since the tag. In a clean checkout the two comparisons agree.
fn changed_since_args(tag: &str) -> Vec<String> {
    vec![
        "diff".to_string(),
        "--name-only".to_string(),
        tag.to_string(),
    ]
}

/// The lines of a `git diff --name-only` answer.
fn name_lines(out: &str) -> Vec<String> {
    out.lines().map(str::to_string).collect()
}

/// Files that differ between the newest tag and the working tree.
fn changed_since_newest_tag() -> Option<Vec<String>> {
    let t = newest_tag()?;
    let tag = format!("v{}.{}.{}", t.0, t.1, t.2);
    let args = changed_since_args(&tag);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    Some(name_lines(&git(&args)?))
}

/// Whether anything shippable changed since the newest tag.
fn has_unreleased_code() -> Option<bool> {
    Some(
        changed_since_newest_tag()?
            .iter()
            .any(|f| SHIPPABLE.iter().any(|p| f.starts_with(p))),
    )
}

/// The version headings in `CHANGELOG.md`, and whether an `[Unreleased]`
/// heading is present.
type ChangelogSections = (Vec<(u32, u32, u32)>, bool);

/// Every version heading in `CHANGELOG.md`, plus whether an `[Unreleased]`
/// heading is present.
fn changelog_sections() -> Result<ChangelogSections, TestError> {
    let text = read("CHANGELOG.md")?;
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
    Ok((versions, unreleased))
}

/// The body of the `[Unreleased]` section, if it has one.
fn unreleased_body() -> Result<Option<String>, TestError> {
    Ok(release_logic::unreleased_section(&read("CHANGELOG.md")?))
}

/// The version the website advertises.
fn published_version() -> Result<(u32, u32, u32), TestError> {
    let cfg = read("website/config.toml")?;
    let line = cfg
        .lines()
        .find(|l| l.trim_start().starts_with("published_version"))
        .ok_or("website/config.toml sets published_version")?;
    let raw = line.split('"').nth(1).ok_or("quoted published_version")?;
    Ok(parse_version(raw).ok_or_else(|| format!("unparseable published_version {raw:?}"))?)
}

/// Whether every change since the newest tag is that tag's own advertisement.
///
/// Returns `None` when git cannot answer, which callers must treat as "cannot
/// tell" rather than as "yes".
fn only_advertises_the_newest_tag() -> Result<Option<bool>, TestError> {
    let Some(changed) = changed_since_newest_tag() else {
        return Ok(None);
    };
    let published = published_version()?;
    let Some(tag) = newest_tag() else {
        return Ok(None);
    };
    Ok(Some(is_advertisement(&changed, published, tag)))
}

/// Whether every commit past the newest tag is a dependency bump.
///
/// The one kind of post-tag commit that legitimately declares nothing: a
/// lockfile update ships nothing a reader needs told about, and the bot that
/// authors it cannot write a changelog entry. Six Dependabot pull requests sat
/// unmergeable because the gate below had no name for this.
fn only_bumps_dependencies() -> Option<bool> {
    let changed = changed_since_newest_tag()?;
    Some(is_dependency_bump(&changed))
}

/// Whether everything past the newest tag is that tag's advertisement plus
/// dependency bumps.
///
/// Returns `None` when git cannot answer, which callers must treat as "cannot
/// tell" rather than as "yes".
fn only_advertises_beside_dependency_bumps() -> Result<Option<bool>, TestError> {
    let Some(changed) = changed_since_newest_tag() else {
        return Ok(None);
    };
    let published = published_version()?;
    let Some(tag) = newest_tag() else {
        return Ok(None);
    };
    Ok(Some(is_advertisement_beside_dependency_bumps(
        &changed, published, tag,
    )))
}

// ── A. Unreleased work must declare itself ──────────────────────────

/// Code changed since the last tag must be declared in the changelog.
///
/// **This is the gate whose absence let three P0 fixes sit unshipped.** The
/// tree was green, the suite passed, and nothing anywhere said users did not
/// have them. An `[Unreleased]` heading costs one line and turns invisible
/// latency into a visible fact.
#[test]
fn code_changed_since_the_last_tag_is_declared_in_the_changelog() -> Result<(), TestError> {
    let Some(unreleased_code) = has_unreleased_code() else {
        // Cannot tell — say so rather than passing. A shallow clone is the
        // usual cause and is a legitimate reason not to judge.
        cannot_tell("git could not report changes since the newest tag")?;
        return Ok(());
    };
    if !unreleased_code {
        return Ok(());
    }
    if only_advertises_the_newest_tag()? == Some(true) {
        return Ok(());
    }
    let (_, has_unreleased_heading) = changelog_sections()?;
    let newest_changelog = {
        let mut v = changelog_sections()?.0;
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
    Ok(())
}

/// An `[Unreleased]` section must not be empty.
///
/// A heading with nothing under it is worse than no heading: it reads as "we
/// checked, there is nothing", which is the one conclusion an unreleased P0
/// disproves.
#[test]
fn an_unreleased_section_is_never_an_empty_promise() -> Result<(), TestError> {
    let Some(body) = unreleased_body()? else {
        return Ok(());
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
    Ok(())
}

/// An `[Unreleased]` section requires unreleased work to exist.
#[test]
fn an_unreleased_section_exists_only_when_something_is_unreleased() -> Result<(), TestError> {
    let (_, has_unreleased) = changelog_sections()?;
    if !has_unreleased {
        return Ok(());
    }
    let Some(n) = commits_since_newest_tag() else {
        return Ok(());
    };
    // The commit being made counts too. The pre-commit hook runs this with
    // HEAD still AT the tag and the new work in the index, so the first
    // commit after a release, the one that opens [Unreleased], was refused
    // for describing work it was itself carrying. In CI the index is clean
    // and this adds nothing.
    let staged =
        git(&["diff", "--cached", "--name-only", "HEAD"]).is_some_and(|names| !names.is_empty());
    assert!(
        n > 0 || staged,
        "CHANGELOG.md carries an [Unreleased] section while HEAD is exactly at \
         the newest tag and nothing is staged. Either the section is stale from \
         the last release or the tag was moved; both make the section describe \
         nothing."
    );
    Ok(())
}

/// Unreleased commits are bounded, and the bound is the alarm.
///
/// Not a style rule. Each commit that lands without shipping widens the gap
/// between what is proven and what is delivered, and the failure this file
/// exists for was exactly that gap growing while every other gate stayed
/// green. The number is deliberately generous — this fires on a stall, not on
/// ordinary batching.
#[test]
fn unreleased_commits_do_not_accumulate_without_a_release() -> Result<(), TestError> {
    let Some(n) = commits_since_newest_tag() else {
        cannot_tell("git could not count commits since the newest tag")?;
        return Ok(());
    };
    let cutting = match newest_tag() {
        Some(t) => crate_version()? > t,
        None => false,
    };
    let held = unreleased_body()?.and_then(|body| {
        body.lines().find_map(|l| {
            l.trim()
                .strip_prefix("**Held:**")
                .map(|r| r.trim().to_string())
        })
    });
    if let Err(why) = unreleased_accumulation(n, cutting, held.as_deref()) {
        return Err(format!(
            "{why} Newest tag {:?}. A backlog of unreleased commits is invisible to \
             every other gate here.",
            newest_tag()
        )
        .into());
    }
    Ok(())
}

/// A security fix must never be quietly unreleased.
///
/// Ranked separately from ordinary code because the consequence is different:
/// an unshipped feature is a delay, an unshipped security fix is an exposure
/// with a known remedy sitting in a repository.
#[test]
fn a_security_relevant_change_since_the_tag_is_declared() -> Result<(), TestError> {
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
        return Ok(());
    };
    let touched: Vec<&String> = changed
        .iter()
        .filter(|f| SECURITY_PATHS.iter().any(|p| f.starts_with(p)))
        .collect();
    if touched.is_empty() {
        return Ok(());
    }
    if only_advertises_the_newest_tag()? == Some(true) {
        return Ok(());
    }
    let (_, has_unreleased) = changelog_sections()?;
    let newest_changelog = {
        let mut v = changelog_sections()?.0;
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
    Ok(())
}

/// The newest changelog entry is the crate version or newer.
#[test]
fn the_changelog_never_trails_the_crate_version() -> Result<(), TestError> {
    let (mut versions, _) = changelog_sections()?;
    // Sections are written newest-first, so `last()` is the OLDEST entry.
    // Sorting makes the intent explicit and survives a file that is out of
    // order — which `changelog_sections_are_ordered_newest_first` catches
    // separately rather than silently compensating for here.
    versions.sort_unstable();
    let Some(newest) = versions.last().copied() else {
        return Err("CHANGELOG.md has no version sections at all".into());
    };
    assert!(
        newest >= crate_version()?,
        "the crate is {:?} and the newest changelog entry is {newest:?}. A \
         version with no entry ships undocumented.",
        crate_version()?
    );
    Ok(())
}

/// Changelog version sections descend, newest first.
#[test]
fn changelog_sections_are_ordered_newest_first() -> Result<(), TestError> {
    let (versions, _) = changelog_sections()?;
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
    Ok(())
}

// ── B. The site must not lag silently ───────────────────────────────

/// The site never advertises a version the crate has not reached.
#[test]
fn the_site_never_advertises_a_version_ahead_of_the_crate() -> Result<(), TestError> {
    assert!(
        published_version()? <= crate_version()?,
        "the site advertises {:?} and the crate is {:?}; a visitor is offered \
         something that was never built here",
        published_version()?,
        crate_version()?
    );
    Ok(())
}

/// The advertised version has a tag.
#[test]
fn the_advertised_version_has_a_tag_in_this_repository() -> Result<(), TestError> {
    let t = tags();
    if t.is_empty() {
        cannot_tell("no tags in this checkout")?;
        return Ok(());
    }
    assert!(
        t.contains(&published_version()?),
        "the site advertises {:?}, which has no tag. published_version must \
         move only to a release that exists.",
        published_version()?
    );
    Ok(())
}

/// The site is at most one patch release behind the crate.
///
/// One is the legal interim state of the two-phase flow: the crate is bumped
/// and tagged, artifacts build, then `published_version` moves. Two means a
/// release was cut and never advertised — the failure that shipped 0.5.128 to
/// nobody.
#[test]
fn the_site_is_at_most_one_release_behind_the_crate() -> Result<(), TestError> {
    let (cm, cn, cp) = crate_version()?;
    let (pm, pn, pp) = published_version()?;
    if (cm, cn) != (pm, pn) {
        // A minor bump is a different conversation; the patch rule does not
        // apply across it and asserting it would misfire.
        return Ok(());
    }
    assert!(
        cp.saturating_sub(pp) <= 1,
        "the crate is {:?} and the site still advertises {:?}. More than one \
         release behind means a tagged release was never advertised, which is \
         indistinguishable to a visitor from it never existing.",
        crate_version()?,
        published_version()?
    );
    Ok(())
}

/// The advertised version has a changelog entry.
#[test]
fn the_advertised_version_is_described_in_the_changelog() -> Result<(), TestError> {
    let (versions, _) = changelog_sections()?;
    assert!(
        versions.contains(&published_version()?),
        "the site advertises {:?} and CHANGELOG.md does not describe it",
        published_version()?
    );
    Ok(())
}

/// Every tag has a changelog entry.
///
/// The reverse direction, and the one that catches a release cut in a hurry:
/// artifacts exist, the tag exists, and nothing says what changed.
#[test]
fn every_tag_is_described_in_the_changelog() -> Result<(), TestError> {
    let (versions, _) = changelog_sections()?;
    let described: BTreeSet<_> = versions.into_iter().collect();
    let undescribed: Vec<_> = tags()
        .into_iter()
        .filter(|t| !described.contains(t))
        .collect();
    assert!(
        undescribed.is_empty(),
        "these tags have no changelog entry: {undescribed:?}"
    );
    Ok(())
}

// ── C. The instruments must be able to fire ─────────────────────────

/// The tag scan found real tags.
#[test]
fn the_tag_scan_reads_a_real_repository() -> Result<(), TestError> {
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
    Ok(())
}

/// The changelog parser found real sections.
#[test]
fn the_changelog_parser_reads_real_sections() -> Result<(), TestError> {
    let (versions, _) = changelog_sections()?;
    assert!(
        versions.len() >= 5,
        "the changelog parser found {} version section(s); it has stopped \
         matching and every comparison against it is vacuous",
        versions.len()
    );
    Ok(())
}

/// `git` answering and `git` reporting nothing are different outcomes.
///
/// The distinction this whole file rests on. If `commits_since_newest_tag`
/// folded a git failure into `0`, every latency gate here would report a
/// perfectly shipped repository from a checkout where git does not work.
#[test]
fn a_git_failure_is_not_reported_as_zero_commits() -> Result<(), TestError> {
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
    Ok(())
}

/// The version parser accepts the forms this repository uses and rejects junk.
#[test]
fn the_version_parser_accepts_real_forms_and_rejects_junk() -> Result<(), TestError> {
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
    Ok(())
}

/// The unreleased-section reader distinguishes absent, empty and filled.
#[test]
fn the_unreleased_reader_tells_absent_from_empty() -> Result<(), TestError> {
    // Against the real file, whatever state it is in, the reader must return
    // a value consistent with the heading's presence.
    let text = read("CHANGELOG.md")?;
    let heading_present = text
        .lines()
        .any(|l| l.starts_with("## ") && l.to_ascii_lowercase().contains("[unreleased]"));
    assert_eq!(
        unreleased_body()?.is_some(),
        heading_present,
        "the reader disagrees with the file about whether an [Unreleased] \
         heading exists"
    );
    Ok(())
}

/// The shippable-path list actually matches this tree's layout.
///
/// A path list that matches nothing turns `has_unreleased_code` into a
/// permanent `false`, and the loudest gate in this file would go quiet.
#[test]
fn the_shippable_path_list_matches_this_repository() -> Result<(), TestError> {
    for p in SHIPPABLE {
        let target = repo().join(p.trim_end_matches('/'));
        assert!(
            target.exists(),
            "SHIPPABLE names {p}, which does not exist; the unreleased-code \
             check would never fire"
        );
    }
    Ok(())
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
fn every_transition_from_committed_to_deployed_has_a_gate() -> Result<(), TestError> {
    let this_file = read("tests/release_delivery_test.rs")?;
    let completeness = read("tests/release_completeness_test.rs")?;
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
    Ok(())
}

/// The crate version and the newest tag are in one of two legal states.
#[test]
fn the_crate_version_and_newest_tag_are_in_a_legal_pair() -> Result<(), TestError> {
    let Some(t) = newest_tag() else {
        return Ok(());
    };
    let c = crate_version()?;
    assert!(
        c >= t,
        "the crate is {c:?} and a tag {t:?} exists ahead of it; a tag must \
         never name a version the tree has not reached"
    );
    Ok(())
}

/// A version bump obliges a changelog entry in the same tree.
#[test]
fn a_version_bump_carries_its_changelog_entry() -> Result<(), TestError> {
    let Some(t) = newest_tag() else {
        return Ok(());
    };
    let c = crate_version()?;
    if c == t {
        return Ok(());
    }
    let (versions, _) = changelog_sections()?;
    assert!(
        versions.contains(&c),
        "the crate was bumped to {c:?} past the newest tag {t:?} and \
         CHANGELOG.md has no entry for it. The bump and its description belong \
         in the same commit; separated, the entry is written from memory."
    );
    Ok(())
}

/// Closed P0 backlog items must be released or declared unreleased.
///
/// Ties the backlog to delivery. An item marked done is a promise that the
/// problem is gone; while it sits untagged it is gone only here.
#[test]
fn a_p0_marked_done_is_released_or_declared() -> Result<(), TestError> {
    let Some(backlog) = local_backlog() else {
        return Ok(());
    };
    let p0_start = backlog
        .find("## P0 — panics & security")
        .ok_or("backlog has a P0 section")?;
    let p0_end = backlog[p0_start..]
        .find("\n## P1")
        .map(|i| p0_start + i)
        .unwrap_or(backlog.len());
    let p0 = &backlog[p0_start..p0_end];
    let closed = p0.lines().filter(|line| line.starts_with("- [x] ")).count();
    assert!(
        closed >= 5,
        "only {closed} closed P0 item(s) found; the scan has stopped matching \
         and this gate proves nothing"
    );
    let open = p0.lines().filter(|line| line.starts_with("- [ ] ")).count();
    if open > 0 {
        // Open P0s are a different problem and are not this gate's business.
        return Ok(());
    }
    let Some(n) = commits_since_newest_tag() else {
        return Ok(());
    };
    if n == 0 {
        return Ok(());
    }
    if only_advertises_the_newest_tag()? == Some(true) {
        // Phase two of this very release. Nothing is waiting to ship.
        return Ok(());
    }
    if only_bumps_dependencies() == Some(true) {
        // A dependency bump ships nothing a reader needs told about, and the
        // bot that authors it cannot write a changelog entry. Without this arm
        // the gate reported every Dependabot pull request as an undeclared
        // release and made all six unmergeable against a branch protection
        // requiring `CI success`.
        return Ok(());
    }
    if only_advertises_beside_dependency_bumps()? == Some(true) {
        // Phase two landing after Dependabot merges: both arms above ask
        // whether every path is of their kind, so the mixture passes neither,
        // though each of its paths would.
        return Ok(());
    }
    let (_, has_unreleased) = changelog_sections()?;
    let newest_changelog = {
        let mut v = changelog_sections()?.0;
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
    Ok(())
}

/// `published_version` never names a version with no changelog date.
#[test]
fn the_advertised_version_carries_a_date() -> Result<(), TestError> {
    let text = read("CHANGELOG.md")?;
    let (pm, pn, pp) = published_version()?;
    let heading = format!("## [{pm}.{pn}.{pp}]");
    let line = text
        .lines()
        .find(|l| l.starts_with(&heading))
        .ok_or_else(|| format!("no changelog heading for the advertised {pm}.{pn}.{pp}"))?;
    assert!(
        line.contains(" - 2"),
        "the advertised version's changelog heading carries no date: {line:?}. \
         An undated entry cannot be checked against the release."
    );
    Ok(())
}

/// The advertisement exemption must not swallow ordinary work.
///
/// It exists so the release flow's own second phase — moving
/// `published_version` after the artifacts exist — does not read as
/// undeclared work. An exemption that also covered a `src/` change would
/// silence the gates this file is entirely about, and it would do so
/// invisibly, because the tree would simply go quiet.
#[test]
fn the_advertisement_exemption_stays_narrow() -> Result<(), TestError> {
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
    Ok(())
}

/// The exemption applies only when the site actually names the newest tag.
///
/// Touching `website/config.toml` is not the same as advertising a release. A
/// commit that edits it while leaving `published_version` behind the newest
/// tag is ordinary work wearing the release flow's clothes, and must still be
/// declared.
#[test]
fn the_advertisement_exemption_requires_the_site_to_name_the_newest_tag() -> Result<(), TestError> {
    let Some(tag) = newest_tag() else {
        cannot_tell("no tags in this checkout")?;
        return Ok(());
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
    Ok(())
}

/// A limited checkout may decline to judge.
///
/// A shallow clone and a tagless checkout are legitimate: the gate has no
/// input, and inventing one would be worse than saying so.
#[test]
fn a_gate_that_cannot_tell_skips_when_git_may_be_limited() -> Result<(), TestError> {
    assert_eq!(cannot_tell_verdict(false), CannotTell::Skip);
    Ok(())
}

/// The push-time run may not.
///
/// This is the arm the whole split exists for. `pre-push` is the first moment
/// the commit under judgement exists AND the last before it reaches everyone
/// else; a gate that skips there passes for the same reason it would have
/// passed at pre-commit, and nothing downstream can tell the two apart.
#[test]
fn a_gate_that_cannot_tell_fails_at_push_time() -> Result<(), TestError> {
    assert_eq!(cannot_tell_verdict(true), CannotTell::Fail);
    Ok(())
}

// ── The changed-file list is taken from the tree the gates read ─────

/// The variables `git commit` exports to a hook. A fixture's git must not
/// inherit them, or it reads and writes the repository being committed to.
const HOOK_GIT_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_WORK_TREE",
    "GIT_PREFIX",
    "GIT_COMMON_DIR",
];

/// A git command in a fixture directory, without the hook's environment and
/// without the user's or the system's configuration.
fn fixture_git(dir: &std::path::Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(dir);
    for var in HOOK_GIT_ENV {
        c.env_remove(var);
    }
    c.env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    c
}

/// A fixture repository: `main` holds a release tagged `v1.0.0`, and the
/// checkout is on `topic`, which branched before the release.
struct TagFixture(test_scratch::ScratchDir);

impl TagFixture {
    fn new(name: &str) -> Result<Self, TestError> {
        let dir = test_scratch::ScratchDir::new(&format!("sipnab-delivery-{name}-"))?;
        let f = Self(dir);
        f.run(&["init", "-q", "-b", "main"])?;
        f.run(&["config", "user.email", "t@example.invalid"])?;
        f.run(&["config", "user.name", "t"])?;
        std::fs::create_dir_all(f.0.join("src"))?;
        f.write("src/lib.rs", "// base\n")?;
        f.write("README.md", "base\n")?;
        f.commit("base")?;
        f.run(&["branch", "topic"])?;
        f.write("src/released.rs", "// in the release\n")?;
        f.commit("released code")?;
        f.run(&["tag", "v1.0.0"])?;
        f.run(&["checkout", "-q", "topic"])?;
        f.write("docs.md", "topic work\n")?;
        f.commit("topic work, no shippable file")?;
        Ok(f)
    }
    fn run(&self, args: &[&str]) -> Result<(), TestError> {
        let out = fixture_git(&self.0).args(args).output()?;
        if !out.status.success() {
            return Err(format!(
                "git {args:?} failed in the fixture: {}",
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        Ok(())
    }
    fn write(&self, rel: &str, body: &str) -> Result<(), TestError> {
        std::fs::write(self.0.join(rel), body)?;
        Ok(())
    }
    fn commit(&self, subject: &str) -> Result<(), TestError> {
        self.run(&["add", "-A"])?;
        self.run(&["commit", "-qm", subject])
    }
    /// What the gate's own arguments answer in this fixture.
    fn changed(&self) -> Result<Vec<String>, TestError> {
        let args = changed_since_args("v1.0.0");
        let out = git_stdout(fixture_git(&self.0).args(&args))
            .ok_or("git could not list the changes in the fixture")?;
        Ok(name_lines(&out))
    }
}

/// The comparison names no commit of its own, so git compares the tag with
/// the working tree: the files every other gate in this file reads.
#[test]
fn the_changed_list_compares_the_tag_with_the_working_tree() {
    let args = changed_since_args("v9.8.7");
    assert_eq!(
        args,
        ["diff", "--name-only", "v9.8.7"],
        "the comparison is the tag against the working tree"
    );
    assert!(
        args.iter().all(|a| !a.contains("HEAD")),
        "an argument names HEAD, so a merge in progress is judged by the \
         commit before it: {args:?}"
    );
}

/// A branch from before the release, with the release merged and not yet
/// committed, holds every released file. Nothing shippable differs.
///
/// On 2026-11-10 the pre-commit hook refused exactly this merge: `HEAD` was
/// still the commit before the merge, so every file of the release counted as
/// code changed since the tag.
#[test]
fn a_merge_of_the_release_in_progress_changes_nothing_shippable() -> Result<(), TestError> {
    let f = TagFixture::new("merge")?;
    f.run(&["merge", "--no-commit", "--no-ff", "-q", "main"])?;
    let changed = f.changed()?;
    assert_eq!(changed, ["docs.md"], "only the topic's own file differs");
    assert!(
        !changed
            .iter()
            .any(|c| SHIPPABLE.iter().any(|p| c.starts_with(p))),
        "a merge in progress counts released code as unreleased: {changed:?}"
    );
    Ok(())
}

/// The same merge once committed gives the same answer.
#[test]
fn a_committed_merge_of_the_release_changes_nothing_shippable() -> Result<(), TestError> {
    let f = TagFixture::new("merged")?;
    f.run(&["merge", "--no-ff", "-q", "-m", "merge", "main"])?;
    assert_eq!(
        f.changed()?,
        ["docs.md"],
        "a committed merge of the release differs by the topic's file only"
    );
    Ok(())
}

/// A shippable file committed after the tag is listed.
#[test]
fn a_committed_change_after_the_tag_is_listed() -> Result<(), TestError> {
    let f = TagFixture::new("committed")?;
    f.run(&["merge", "--no-ff", "-q", "-m", "merge", "main"])?;
    f.write("src/new.rs", "// after the tag\n")?;
    f.commit("new code")?;
    assert_eq!(
        f.changed()?,
        ["docs.md", "src/new.rs"],
        "a file committed after the tag is missing from the list"
    );
    Ok(())
}

/// A shippable change that is staged and not committed is listed: the commit
/// being made is judged, not the one before it.
#[test]
fn a_staged_change_after_the_tag_is_listed() -> Result<(), TestError> {
    let f = TagFixture::new("staged")?;
    f.run(&["merge", "--no-ff", "-q", "-m", "merge", "main"])?;
    f.write("src/lib.rs", "// edited\n")?;
    f.run(&["add", "src/lib.rs"])?;
    assert_eq!(
        f.changed()?,
        ["docs.md", "src/lib.rs"],
        "a staged change is missing: the commit before it was judged"
    );
    Ok(())
}

/// A branch that has not merged the release differs by the release's files,
/// so the gate still sees a tree that lacks released code.
#[test]
fn a_branch_behind_the_tag_lists_the_released_files() -> Result<(), TestError> {
    let f = TagFixture::new("behind")?;
    assert_eq!(
        f.changed()?,
        ["docs.md", "src/released.rs"],
        "a branch without the release must differ by the released file"
    );
    Ok(())
}

/// A tag git does not have gives no answer, which the gates treat as
/// "cannot tell" and never as "nothing changed".
#[test]
fn an_unknown_tag_gives_no_answer() -> Result<(), TestError> {
    let f = TagFixture::new("unknown")?;
    let args = changed_since_args("v7.7.7");
    assert_eq!(
        git_stdout(fixture_git(&f.0).args(&args)),
        None,
        "a tag git does not have must not read as an empty change list"
    );
    Ok(())
}

/// The fixture's git drops the hook's variables, or it would read the
/// repository being committed to.
#[test]
fn the_fixture_git_drops_the_hook_environment() {
    let c = fixture_git(std::path::Path::new("."));
    for var in HOOK_GIT_ENV {
        assert!(
            c.get_envs()
                .any(|(k, v)| k == std::ffi::OsStr::new(var) && v.is_none()),
            "{var} is inherited by the fixture's git"
        );
    }
}

// ── A changelog section names each kind of change once ────────────────────
//
// Two branches that each add a `### Fixed` list to `[Unreleased]` merge
// without a conflict when their lists are not adjacent, and the section then
// carries the heading twice. #749's merge left exactly that on main
// (f7157fe4f: `### Fixed` at lines 17 and 30), and nothing refused it. The
// rule is `release_logic::repeated_headings`, a pure function over a
// section's body; these tables drive it, and the last test holds the real
// `[Unreleased]` section to it. Released sections are history: 23 of them
// repeat a heading (counted 2026-11-11, 0.5.246 among them) and are not
// rewritten.

/// Bodies with no heading repeated.
const HEADINGS_ONCE: &[&str] = &[
    "",
    "\n\n",
    "- a change with no heading",
    "### Fixed\n\n- a",
    "### Added\n\n- a\n\n### Fixed\n\n- b",
    "### Added\n- a\n### Changed\n- b\n### Fixed\n- c\n### Dependencies\n- d\n### Security\n- e",
    "### Fixed\n\n- the page said `### Fixed` twice",
    "### Fixed\n\n- a\n\n#### Fixed\n\n- a fourth-level heading is not a section heading",
    "### Fixed\n\n- a\n\n## Fixed",
    "### Fixed\n\n- a\n\n###Fixed",
    "### Fixed\n\n- a\n\n    ### Fixed",
    "### Fixed\n\n```\n### Fixed\n```",
    "### Fixed\n\n~~~\n### Fixed\n~~~",
    "### Fixed\n\n- a step:\n\n  ```\n### Fixed\n  ```",
    "### Fixed\n\n- a\n\n### Fixed in 0.5.1",
    "### Fixed\n\n- a\n\n### Fixes",
];

/// Bodies with a repeated heading: the body, the heading, its 1-based lines.
const HEADINGS_REPEATED: &[(&str, &str, &[usize])] = &[
    ("### Fixed\n\n- a\n\n### Fixed\n\n- b", "### Fixed", &[1, 5]),
    ("### Fixed\n### Fixed", "### Fixed", &[1, 2]),
    (
        "### Changed\n- a\n### Fixed\n- b\n### Fixed\n- c",
        "### Fixed",
        &[3, 5],
    ),
    (
        "### Fixed\n- a\n### Changed\n- b\n### Fixed\n- c",
        "### Fixed",
        &[1, 5],
    ),
    (
        "### Fixed\n- a\n### Fixed\n- b\n### Fixed\n- c",
        "### Fixed",
        &[1, 3, 5],
    ),
    ("### Fixed\n- a\n### fixed\n- b", "### Fixed", &[1, 3]),
    ("### Fixed\n- a\n### FIXED\n- b", "### Fixed", &[1, 3]),
    ("### Fixed\n- a\n### Fixed  \n- b", "### Fixed", &[1, 3]),
    ("### Fixed\n- a\n### Fixed\t\n- b", "### Fixed", &[1, 3]),
    ("### Fixed\n- a\n###  Fixed\n- b", "### Fixed", &[1, 3]),
    ("### Fixed\r\n- a\r\n### Fixed\r\n- b", "### Fixed", &[1, 3]),
    (
        "\n\n### Dependencies\n\n- a\n\n### Security\n\n- b\n\n### Dependencies\n",
        "### Dependencies",
        &[3, 11],
    ),
    (
        "### Fixed\n\n```\n### Fixed\n```\n\n### Fixed\n",
        "### Fixed",
        &[1, 7],
    ),
    (
        "### Bug fixes and repairs\n- a\n### Bug fixes and repairs\n- b",
        "### Bug fixes and repairs",
        &[1, 3],
    ),
];

#[test]
fn a_section_with_each_heading_once_reports_nothing() {
    assert!(
        HEADINGS_ONCE.len() >= 12,
        "the table lost cases: {}",
        HEADINGS_ONCE.len()
    );
    for body in HEADINGS_ONCE {
        let found = release_logic::repeated_headings(body);
        assert!(
            found.is_empty(),
            "no heading repeats in {body:?}, yet the rule reported {found:?}"
        );
    }
}

#[test]
fn a_repeated_heading_is_reported_with_every_line_it_is_on() {
    assert!(
        HEADINGS_REPEATED.len() >= 12,
        "the table lost cases: {}",
        HEADINGS_REPEATED.len()
    );
    for (body, heading, lines) in HEADINGS_REPEATED {
        let found = release_logic::repeated_headings(body);
        assert_eq!(
            found,
            vec![((*heading).to_string(), lines.to_vec())],
            "wrong report for {body:?}"
        );
    }
}

#[test]
fn two_repeated_headings_are_both_reported_in_the_order_they_first_appear() {
    let body = "### Fixed\n- a\n### Added\n- b\n### Added\n- c\n### Fixed\n- d\n### Changed\n- e";
    assert_eq!(
        release_logic::repeated_headings(body),
        vec![
            ("### Fixed".to_string(), vec![1, 7]),
            ("### Added".to_string(), vec![3, 5]),
        ],
        "both repeats, first-appearance order, and Changed left out"
    );
}

#[test]
fn a_fence_left_open_hides_the_rest_of_the_section_and_nothing_before_it() {
    assert_eq!(
        release_logic::repeated_headings("### Fixed\n### Fixed\n```\n### Added\n### Added"),
        vec![("### Fixed".to_string(), vec![1, 2])],
        "the lines before the open fence are still read; those after are code"
    );
}

#[test]
fn the_report_keeps_the_spelling_of_the_first_appearance() {
    assert_eq!(
        release_logic::repeated_headings("### fixed\n### Fixed"),
        vec![("### fixed".to_string(), vec![1, 2])],
        "the first spelling names the heading"
    );
}

/// The real file: `[Unreleased]` carries each `### ` heading once.
#[test]
fn the_unreleased_section_names_each_kind_of_change_once() -> Result<(), TestError> {
    let Some(body) = unreleased_body()? else {
        return Ok(());
    };
    let found = release_logic::repeated_headings(&body);
    let report: Vec<String> = found
        .iter()
        .map(|(h, lines)| {
            format!(
                "`{h}` appears {} times (section lines {lines:?})",
                lines.len()
            )
        })
        .collect();
    assert!(
        found.is_empty(),
        "CHANGELOG.md's [Unreleased] section repeats a heading; move the entries under one \
         heading (a merge of two branches leaves this without a conflict):\n{}",
        report.join("\n")
    );
    Ok(())
}

// ── Which tags a release test counts (tests/support/release_tags.rs) ──────
//
// RELEASE-TESTS-READ-UNREACHABLE-TAGS. `TagFixture` is the case that failed:
// `main` holds a release tagged `v1.0.0`, and the checkout is on `topic`,
// which branched before it. The tag is in the repository and is not part of
// what `topic` holds.

/// The release tags that count in the fixture, sorted.
fn counted_tags(f: &TagFixture) -> Result<Vec<String>, TestError> {
    let mut tags = release_tags::reachable_release_tags(f.0.path())
        .ok_or("git could not list the fixture's tags")?;
    tags.sort();
    Ok(tags)
}

/// The defect: a tag fetched into the repository, on a commit the branch
/// does not hold, is not one of the branch's releases.
#[test]
fn a_tag_the_branch_does_not_hold_is_not_counted() -> Result<(), TestError> {
    let f = TagFixture::new("tags-unreachable")?;
    assert_eq!(
        counted_tags(&f)?,
        Vec::<String>::new(),
        "topic branched before v1.0.0 and has not merged it"
    );
    Ok(())
}

/// On the branch that holds the release, its tag counts.
#[test]
fn a_tag_on_the_checked_out_branch_is_counted() -> Result<(), TestError> {
    let f = TagFixture::new("tags-on-branch")?;
    f.run(&["checkout", "-q", "main"])?;
    assert_eq!(counted_tags(&f)?, ["v1.0.0"], "main holds the release");
    Ok(())
}

/// A merge in progress counts the tags of the side it merges in: the commit
/// hook runs these tests before the merge commit exists, on a working tree
/// that already holds the release.
#[test]
fn a_merge_in_progress_counts_the_tags_it_brings_in() -> Result<(), TestError> {
    let f = TagFixture::new("tags-merging")?;
    f.run(&["merge", "-q", "--no-ff", "--no-commit", "main"])?;
    assert!(
        release_tags::merge_in_progress(f.0.path()),
        "the fixture has a merge in progress"
    );
    assert_eq!(
        counted_tags(&f)?,
        ["v1.0.0"],
        "the release being merged in counts before the merge commit exists"
    );
    Ok(())
}

/// Once the merge is committed the tag is reachable from `HEAD` itself.
#[test]
fn a_merged_release_tag_is_counted_after_the_merge_commit() -> Result<(), TestError> {
    let f = TagFixture::new("tags-merged")?;
    f.run(&["merge", "-q", "--no-ff", "--no-commit", "main"])?;
    f.run(&["commit", "-qm", "merge the release"])?;
    assert!(
        !release_tags::merge_in_progress(f.0.path()),
        "the merge is committed"
    );
    assert_eq!(counted_tags(&f)?, ["v1.0.0"], "the merged release counts");
    Ok(())
}

/// A later release on `main` does not count on a branch that merged only
/// the earlier one: each tag is judged by itself.
#[test]
fn only_the_merged_one_of_two_releases_is_counted() -> Result<(), TestError> {
    let f = TagFixture::new("tags-two-releases")?;
    f.run(&["merge", "-q", "--no-ff", "-m", "merge the release", "main"])?;
    f.run(&["checkout", "-q", "main"])?;
    f.write("src/later.rs", "// in the later release\n")?;
    f.commit("later release")?;
    f.run(&["tag", "v1.0.1"])?;
    assert_eq!(
        counted_tags(&f)?,
        ["v1.0.0", "v1.0.1"],
        "main holds both releases"
    );
    f.run(&["checkout", "-q", "topic"])?;
    assert_eq!(
        counted_tags(&f)?,
        ["v1.0.0"],
        "topic merged v1.0.0 and not v1.0.1"
    );
    Ok(())
}

/// A tag that is not a `v*` tag is not a release tag, reachable or not.
#[test]
fn a_tag_that_is_not_a_release_tag_is_not_counted() -> Result<(), TestError> {
    let f = TagFixture::new("tags-other-names")?;
    f.run(&["tag", "nightly"])?;
    f.run(&["tag", "release-1.0.0"])?;
    f.run(&["tag", "v0.9.0"])?;
    assert_eq!(
        counted_tags(&f)?,
        ["v0.9.0"],
        "of three tags on HEAD only the v* one is a release tag"
    );
    Ok(())
}

/// An older release tagged on a commit the branch does not hold still
/// counts, as `v0.5.144` does in this repository: it is not newer than the
/// newest release the branch holds. On a branch that holds no release it
/// does not count.
#[test]
fn an_older_release_on_a_commit_outside_the_history_is_counted() -> Result<(), TestError> {
    let f = TagFixture::new("tags-old-side")?;
    f.run(&["checkout", "-q", "-b", "side", "topic"])?;
    f.write("side.md", "a release cut from a side commit\n")?;
    f.commit("side release")?;
    f.run(&["tag", "v0.9.0"])?;
    f.run(&["checkout", "-q", "main"])?;
    assert_eq!(
        counted_tags(&f)?,
        ["v0.9.0", "v1.0.0"],
        "main holds v1.0.0, and v0.9.0 is older than it"
    );
    f.run(&["checkout", "-q", "topic"])?;
    assert_eq!(
        counted_tags(&f)?,
        Vec::<String>::new(),
        "topic holds no release, so no tag is known to be older than one"
    );
    Ok(())
}

/// The rule as a function of the two lists: every tag in the repository, and
/// the reachable ones.
#[test]
fn the_counting_rule_drops_only_releases_newer_than_the_newest_reachable_one() {
    let list = |names: &[&str]| names.iter().map(|n| (*n).to_string()).collect::<Vec<_>>();
    let all = list(&[
        "v0.5.144", "v0.5.245", "v0.5.246", "v0.5.247", "v0.5.9", "vnext",
    ]);
    assert_eq!(
        release_tags::counted_tags(&all, &list(&["v0.5.9", "v0.5.245"])),
        list(&["v0.5.144", "v0.5.245", "v0.5.9"]),
        "a checkout at 0.5.245: the two later releases and the unparsed name are dropped"
    );
    assert_eq!(
        release_tags::counted_tags(&all, &list(&["v0.5.9", "v0.5.245", "v0.5.246", "v0.5.247"])),
        list(&["v0.5.144", "v0.5.245", "v0.5.246", "v0.5.247", "v0.5.9"]),
        "a checkout at the newest release counts every vX.Y.Z tag"
    );
    assert_eq!(
        release_tags::counted_tags(&all, &list(&["vnext"])),
        list(&["vnext"]),
        "a reachable tag counts whatever its name; with no reachable version nothing else does"
    );
    assert_eq!(
        release_tags::counted_tags(&all, &[]),
        Vec::<String>::new(),
        "nothing reachable, nothing counted"
    );
    assert_eq!(
        release_tags::counted_tags(&[], &list(&["v1.0.0", "v1.0.0"])),
        list(&["v1.0.0"]),
        "a reachable tag missing from the full list still counts, once"
    );
}

/// A tag name is a version only as `vX.Y.Z` with three numbers.
#[test]
fn a_tag_name_is_a_version_only_as_v_and_three_numbers() {
    assert_eq!(
        release_tags::tag_version("v0.5.247"),
        Some((0, 5, 247)),
        "vX.Y.Z"
    );
    for name in [
        "0.5.247",
        "v0.5",
        "v0.5.247.1",
        "v0.5.x",
        "v0.5.247-rc1",
        "vnext",
        "v",
        "",
    ] {
        assert_eq!(
            release_tags::tag_version(name),
            None,
            "{name:?} is not vX.Y.Z"
        );
    }
}

/// A directory that is not a repository gives no answer, which is not the
/// same as an empty list.
#[test]
fn a_directory_that_is_not_a_repository_gives_no_tag_list() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-delivery-tags-no-repo-")?;
    // GIT_CEILING_DIRECTORIES is not needed: the scratch directory is under
    // the system temp directory, outside any repository.
    assert_eq!(
        release_tags::reachable_release_tags(dir.path()),
        None,
        "a directory with no repository"
    );
    assert!(
        !release_tags::merge_in_progress(dir.path()),
        "no repository, no merge"
    );
    Ok(())
}

/// A repository with no commit yet gives no answer either: `HEAD` names
/// nothing a tag could be reachable from.
#[test]
fn a_repository_with_no_commit_gives_no_tag_list() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-delivery-tags-unborn-")?;
    let made = fixture_git(dir.path())
        .args(["init", "-q", "-b", "main"])
        .status()?;
    assert!(made.success(), "git init in the scratch directory");
    assert_eq!(
        release_tags::reachable_release_tags(dir.path()),
        None,
        "a repository with no commit"
    );
    Ok(())
}

/// The arguments name `HEAD`, name `MERGE_HEAD` only during a merge, and
/// keep the `v*` pattern.
#[test]
fn the_tag_list_arguments_name_head_and_the_merge_only_when_merging() {
    assert_eq!(
        release_tags::tag_list_args(false).join(" "),
        "tag --list v* --merged HEAD",
        "with no merge in progress"
    );
    assert_eq!(
        release_tags::tag_list_args(true).join(" "),
        "tag --list v* --merged HEAD --merged MERGE_HEAD",
        "with a merge in progress"
    );
}

/// The hook's own variables do not point the listing at another repository:
/// git sets `GIT_DIR` and `GIT_INDEX_FILE` for a hook, and this listing runs
/// inside the commit hook.
#[test]
fn the_tag_listing_ignores_a_hooks_git_variables() -> Result<(), TestError> {
    let f = TagFixture::new("tags-hook-env")?;
    f.run(&["checkout", "-q", "main"])?;
    let text = std::fs::read_to_string(repo().join("tests/support/release_tags.rs"))?;
    for var in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
        assert!(
            text.contains(&format!(".env_remove(\"{var}\")")),
            "tests/support/release_tags.rs does not clear {var}"
        );
    }
    assert_eq!(counted_tags(&f)?, ["v1.0.0"], "the fixture's own tags");
    Ok(())
}

/// One rule in one place: no test file lists tags with its own `git tag`
/// arguments. A second copy of the rule is how three files came to read
/// every tag in the repository while one read the reachable ones.
#[test]
fn only_the_shared_rule_lists_tags() -> Result<(), TestError> {
    let root = repo().join("tests");
    let mut found = Vec::new();
    for dir in [root.clone(), root.join("support")] {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_none_or(|e| e != "rs")
                || path.ends_with("support/release_tags.rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            for (i, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or_default();
                let lists = code.contains(concat!("\"tag\", ", "\"--list\""))
                    || code.contains(concat!("\"tag\", ", "\"--merged\""))
                    || code.contains(concat!("\"tag\", ", "\"-l\""));
                if lists {
                    let name = path.strip_prefix(&root).unwrap_or(&path).display();
                    found.push(format!("tests/{name}:{}", i + 1));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "these lines list tags with their own arguments; use \
         `release_tags::reachable_release_tags` (tests/support/release_tags.rs):\n{}",
        found.join("\n")
    );
    Ok(())
}
