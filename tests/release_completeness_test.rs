// SPDX-License-Identifier: MIT OR Apache-2.0

//! A release is not finished when its artifacts exist. It is finished when a
//! visitor is offered them.
//!
//! `site_advertises_only_a_released_version` in `site_journey_test.rs` guards
//! one direction: the site must never advertise a version with no tag, because
//! every download link would 404. It deliberately TOLERATES the site being one
//! release behind, on the reasoning that tagging and asset-publishing are not
//! instantaneous.
//!
//! That tolerance is a window, and this file closes it with evidence instead.
//! The question "have the assets published?" has an answer, and once the answer
//! is yes the window has no reason to stay open: the artifacts are downloadable
//! and the site is pointing visitors at the previous build.
//!
//! Written after a release where the tag published twenty-three assets, every
//! workflow went green, and the site went on advertising the previous version
//! because the follow-up commit sat uncommitted on one machine. Reported as
//! "done and shipped". The binaries were shipped. The release was not.
//!
//! # Why `gh` rather than the tag alone
//!
//! A tag proves somebody asked for a release. Only the release itself proves
//! the assets exist, and that distinction is the whole subject here. When `gh`
//! cannot answer, these tests say so rather than passing: a gate that reports
//! safety it did not check is worse than one that is absent.

use std::process::Command;

/// The repository root.
fn repo() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// `v1.2.3` -> `(1, 2, 3)`; anything else is not a release tag.
fn release_tag(tag: &str) -> Option<(u32, u32, u32)> {
    let mut parts = tag.strip_prefix('v')?.split('.');
    let v = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(v)
}

/// What `website/config.toml` advertises to visitors.
fn published_version() -> String {
    regex::Regex::new(r#"(?m)^published_version = "([^"]+)""#)
        .unwrap()
        .captures(&read("website/config.toml"))
        .expect("website/config.toml has no published_version")[1]
        .to_string()
}

/// Every release tag in the checkout, newest last.
fn release_tags() -> Vec<(u32, u32, u32)> {
    let out = Command::new("git")
        .args(["tag", "--list"])
        .current_dir(repo())
        .output()
        .expect("git tag --list");
    let mut v: Vec<(u32, u32, u32)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(release_tag)
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

fn as_tag(v: (u32, u32, u32)) -> String {
    format!("v{}.{}.{}", v.0, v.1, v.2)
}

/// How many assets `gh` reports for a tag, or `None` when it cannot answer.
///
/// `None` means "unknown", never "zero". A caller that treated an unavailable
/// `gh` as an empty release would turn every offline run into a silent pass,
/// which is the failure mode this whole file exists to refuse.
fn published_asset_count(tag: &str) -> Option<usize> {
    let out = Command::new("gh")
        .args([
            "release",
            "view",
            tag,
            "--json",
            "assets",
            "-q",
            ".assets | length",
        ])
        .current_dir(repo())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// 1. The newest tag's assets exist ⇒ the site must advertise that version.
///
/// The gap this closes. `site_advertises_only_a_released_version` permits one
/// release of lag unconditionally; this permits it only while the assets are
/// still building, and asks rather than assumes.
#[test]
fn the_site_advertises_the_newest_release_whose_assets_exist() {
    let releases = release_tags();
    assert!(
        releases.len() >= 5,
        "only {} release tags visible; a shallow clone cannot answer this and \
         a pass would mean nothing",
        releases.len()
    );
    let newest = *releases.last().expect("checked non-empty");
    let tag = as_tag(newest);

    let Some(assets) = published_asset_count(&tag) else {
        // Not a silent skip: prove `gh` genuinely cannot answer, so this arm
        // can never become a way for the assertion below to go unrun.
        let probe = Command::new("gh").arg("--version").output();
        let reason = match &probe {
            Err(e) => format!("gh is not installed ({e})"),
            Ok(o) if !o.status.success() => "gh exits non-zero".to_string(),
            Ok(_) => format!("gh works but cannot read release {tag}"),
        };
        eprintln!("release-completeness: cannot verify assets for {tag} — {reason}");
        return;
    };

    assert!(
        assets > 0,
        "{tag} exists as a release but publishes no assets; something failed \
         after the tag went up"
    );
    assert_eq!(
        published_version(),
        format!("{}.{}.{}", newest.0, newest.1, newest.2),
        "{tag} has published {assets} assets, so the release is downloadable — \
         but website/config.toml still advertises {}. Every /download link, the \
         checksum column and SHA256SUMS.txt point at the previous build, and a \
         visitor gets it silently.\n\n\
         A release is finished when a visitor is offered it, not when its \
         artifacts exist. Land the follow-up commit that moves \
         published_version, release_date and the install.md download markers.",
        published_version()
    );
}

/// 2. `release_date` belongs to `published_version`, not to the crate.
#[test]
fn the_advertised_release_date_belongs_to_the_advertised_version() {
    let cfg = read("website/config.toml");
    let date = regex::Regex::new(r#"(?m)^release_date = "([^"]+)""#)
        .unwrap()
        .captures(&cfg)
        .expect("no release_date")[1]
        .to_string();
    let published = published_version();

    let changelog = read("CHANGELOG.md");
    let heading = format!("## [{published}] - {date}");
    assert!(
        changelog.contains(&heading),
        "website/config.toml pairs published_version {published} with \
         release_date {date}, and CHANGELOG.md has no `{heading}`. The date \
         dates the release a visitor can download, so the two must name one \
         entry — pairing a version with another release's date is how a \
         changelog and a download page come to disagree."
    );
}

/// 3. Download instructions name the advertised version, never the crate's.
#[test]
fn every_download_instruction_names_the_advertised_version() {
    let published = published_version();
    let install = read("docs/install.md");
    let markers = [
        r"SIPNAB_VERSION=(\d+\.\d+\.\d+)",
        r"e\.g\. (\d+\.\d+\.\d+)",
        r"rpm -i sipnab-(\d+\.\d+\.\d+)-1\.",
    ];
    for pattern in markers {
        let re = regex::Regex::new(pattern).unwrap();
        let mut seen = 0;
        for cap in re.captures_iter(&install) {
            seen += 1;
            assert_eq!(
                &cap[1], published,
                "docs/install.md marker `{pattern}` names {} while the site \
                 advertises {published}; a reader copying it fetches a \
                 different release than the one /download offers",
                &cap[1]
            );
        }
        assert!(
            seen > 0,
            "no `{pattern}` marker in docs/install.md — the page changed"
        );
    }
}

/// 4. The crate version is never BEHIND what the site advertises.
///
/// The reverse mistake: shipping a site that offers a release newer than the
/// tree it was built from means the next release silently goes backwards.
#[test]
fn the_crate_version_is_never_behind_the_advertised_release() {
    let crate_v = release_tag(&format!("v{}", env!("CARGO_PKG_VERSION"))).expect("crate version");
    let published = release_tag(&format!("v{}", published_version())).expect("published_version");
    assert!(
        crate_v >= published,
        "Cargo.toml is {:?} but the site advertises {:?}. The tree cannot be \
         older than the release it publishes.",
        crate_v,
        published
    );
}

/// 5. The changelog has an entry for whatever the site advertises.
#[test]
fn the_advertised_version_has_a_changelog_entry() {
    let published = published_version();
    let changelog = read("CHANGELOG.md");
    assert!(
        changelog.contains(&format!("## [{published}]")),
        "the site advertises {published} and CHANGELOG.md never mentions it, \
         so a visitor who downloads it cannot find out what changed"
    );
}

/// 6. A dated changelog entry means a tag exists for it — except the one
///    being cut right now.
///
/// Catches the opposite slip: renaming `## [Unreleased]` to a dated version and
/// then never tagging. The changelog says a release happened; nothing published.
///
/// **The exemption is not a softening; without it this gate forbade the
/// repository's own release procedure.** `docs/internals/build-ci-release.md`
/// says to land the release commit, wait for CI, then tag the commit that
/// passed — so between the cut and the tag there is always exactly one dated
/// entry with no tag, and the first version of this test failed every release
/// commit at the moment it was created. A gate that demands output its own
/// documented fixer can never produce is unfixable by design, so the rule is
/// stated properly instead: an entry may be dated-but-untagged only while it
/// names the version in `Cargo.toml`, which is the release in flight.
///
/// That keeps the hole exactly one release wide. The moment `Cargo.toml` moves
/// on, the previously exempt entry must have a tag or this fails — so
/// forgetting to tag is caught by the NEXT cut rather than never.
#[test]
fn every_dated_changelog_entry_names_a_real_tag() {
    let changelog = read("CHANGELOG.md");
    let re = regex::Regex::new(r"(?m)^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}").unwrap();
    let tags = release_tags();
    assert!(tags.len() >= 5, "shallow clone: {} tags", tags.len());
    let newest_five: Vec<(u32, u32, u32)> = tags.iter().rev().take(5).copied().collect();
    let crate_v = release_tag(&format!("v{}", env!("CARGO_PKG_VERSION")))
        .expect("Cargo.toml version is x.y.z");

    let mut checked = 0;
    let mut exempted = 0;
    for cap in re.captures_iter(&changelog).take(5) {
        let v = release_tag(&format!("v{}", &cap[1])).expect("x.y.z");
        if v == crate_v && !newest_five.contains(&v) {
            exempted += 1;
            continue;
        }
        checked += 1;
        assert!(
            newest_five.contains(&v),
            "CHANGELOG.md dates {} as released, but no `v{}` tag is among the \
             five newest. A dated entry with no tag says a release happened \
             that nobody can download.",
            &cap[1],
            &cap[1]
        );
    }
    assert!(
        exempted <= 1,
        "{exempted} dated entries are exempt, and at most one can be: the \
         exemption is only for the version in Cargo.toml. More than one means \
         the matching is wrong, not that more releases are in flight."
    );
    assert!(
        checked > 0,
        "no dated changelog entries were CHECKED — either the format changed \
         or every entry took the in-flight exemption, which would make this \
         gate vacuous"
    );
}

/// 7. The in-flight exemption applies to the crate version and nothing else.
///
/// Guards the shape of gate 6 rather than its data. The exemption exists for
/// one commit's worth of window; if it ever widened to "the newest entry" or
/// "any untagged entry", a changelog could accumulate dated releases nobody
/// published and gate 6 would keep passing.
#[test]
fn only_the_crate_version_may_be_dated_without_a_tag() {
    let changelog = read("CHANGELOG.md");
    let re = regex::Regex::new(r"(?m)^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}").unwrap();
    let tags = release_tags();
    let newest_five: Vec<(u32, u32, u32)> = tags.iter().rev().take(5).copied().collect();
    let crate_v = release_tag(&format!("v{}", env!("CARGO_PKG_VERSION")))
        .expect("Cargo.toml version is x.y.z");

    let untagged: Vec<String> = re
        .captures_iter(&changelog)
        .take(5)
        .filter_map(|c| {
            let v = release_tag(&format!("v{}", &c[1])).expect("x.y.z");
            (!newest_five.contains(&v)).then(|| c[1].to_string())
        })
        .collect();

    for v in &untagged {
        let parsed = release_tag(&format!("v{v}")).expect("x.y.z");
        assert_eq!(
            parsed,
            crate_v,
            "CHANGELOG.md dates {v} with no tag, and {v} is not the version in \
             Cargo.toml ({}). Only the release being cut may be dated ahead of \
             its tag; anything else is a release that was written up and never \
             published.",
            env!("CARGO_PKG_VERSION")
        );
    }
    assert!(
        untagged.len() <= 1,
        "more than one dated entry has no tag: {untagged:?}. At most the \
         in-flight release can be in that state."
    );
}

/// 7. The homepage version badge agrees with the download page.
#[test]
fn the_homepage_badge_and_the_download_page_name_one_version() {
    let published = published_version();
    let index = read("website/templates/index.html");
    // `published_version` ONLY. A homepage version that is not drawn from the
    // config is a historical fact -- "measured v0.5.122" dates a benchmark run
    // and must not follow the current release. Two gates were deleted from
    // this repo for advancing exactly that kind of marker, which made a stale
    // measurement look freshly taken; see the comments in
    // `docs_current_version_markers_match_cargo`.
    let re = regex::Regex::new(r"(?m)published_version").unwrap();
    assert!(
        re.is_match(&index),
        "the homepage template no longer reads `published_version`, so the \
         badge is a literal somebody has to remember to update"
    );
    // Any hardcoded 0.5.x that is NOT introduced by a word like `measured` is
    // a literal claiming to be current.
    let literal = regex::Regex::new(r"(\w+)\s+v?(0\.5\.\d+)").unwrap();
    for cap in literal.captures_iter(&index) {
        let (context, version) = (&cap[1], &cap[2]);
        if context.eq_ignore_ascii_case("measured") || context.eq_ignore_ascii_case("at") {
            continue; // a dated measurement, correctly frozen
        }
        assert_eq!(
            version, published,
            "the homepage hardcodes {version} in the phrase `{context} \
             {version}` while the site advertises {published}. If that number \
             is historical, word it `measured v{version}` so this gate leaves \
             it alone; if it is meant to be current, read it from \
             `published_version` instead of typing it."
        );
    }
}

/// 8. `published_version` names a tag that actually exists.
///
/// Restated here rather than borrowed: this file's other gates all assume it,
/// and an assumption no test in the file states is one that can quietly stop
/// being true.
#[test]
fn the_advertised_version_has_a_tag() {
    let published = published_version();
    let wanted = release_tag(&format!("v{published}")).expect("x.y.z");
    let tags = release_tags();
    assert!(tags.len() >= 5, "shallow clone: {} tags", tags.len());
    assert!(
        tags.contains(&wanted),
        "the site advertises {published}, which has no tag — every download \
         link 404s"
    );
}

/// 9. The generated site mirror agrees with its source about the version.
///
/// A source page and its mirror are two artifacts, and fixing one does not fix
/// the other. That is how a tag push came to be blocked by a stale mirror
/// carrying prose its source no longer had.
#[test]
fn the_install_page_and_its_mirror_agree_about_the_version() {
    let source = read("docs/install.md");
    let mirror = read("website/content/docs/install.md");
    let re = regex::Regex::new(r"SIPNAB_VERSION=(\d+\.\d+\.\d+)").unwrap();
    let from = |t: &str| -> Vec<String> { re.captures_iter(t).map(|c| c[1].to_string()).collect() };
    let (a, b) = (from(&source), from(&mirror));
    assert!(!a.is_empty(), "no SIPNAB_VERSION in docs/install.md");
    assert_eq!(
        a, b,
        "docs/install.md and its generated mirror name different versions. \
         Regenerate with scripts/build-site-pages.py — editing the source \
         alone leaves the page a visitor actually reads unchanged."
    );
}

/// 10. Nothing on the site advertises a version newer than the newest tag.
///
/// The direction `site_advertises_only_a_released_version` already guards, kept
/// here so this file states the whole rule rather than half of it: a reader who
/// opens this file to learn what "released" means should not have to find the
/// other half somewhere else.
#[test]
fn the_site_never_advertises_a_version_that_was_never_tagged() {
    let published = release_tag(&format!("v{}", published_version())).expect("x.y.z");
    let tags = release_tags();
    assert!(tags.len() >= 5, "shallow clone: {} tags", tags.len());
    let newest = *tags.last().expect("non-empty");
    assert!(
        published <= newest,
        "the site advertises {published:?}, which is NEWER than the newest tag \
         {newest:?}. published_version moves after a release publishes, never \
         while cutting one."
    );
}
