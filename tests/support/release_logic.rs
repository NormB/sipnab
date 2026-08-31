// SPDX-License-Identifier: MIT OR Apache-2.0

//! The delivery gates' decision logic, as pure functions over values.
//!
//! Extracted here so it can be driven with inputs the working tree cannot
//! produce. That is not tidiness — it is the fix for a specific defect.
//!
//! The first version of this logic read git and the filesystem inline. Two
//! mutations against it SURVIVED: deleting the tag-agreement check, and making
//! an empty changeset count as advertising. Both survived because this tree
//! exercises neither branch — the changeset is never empty here, and
//! `published_version` already equals the newest tag — so removing either
//! changed nothing observable. A gate whose logic can only run in one state is
//! a gate whose logic is mostly untested, and it will look healthy the whole
//! time.
//!
//! Everything here takes its inputs as arguments and touches nothing global.

// Shared test support: each test binary compiles this module independently and
// uses a different slice of it, so an item one binary does not call is dead
// code there even though another binary's tests drive it. `expect` is wrong
// here for the same reason -- it would fire in the binary that DOES use the
// item.
#![allow(dead_code)]

/// Files and directories the SECOND phase of a release touches, and nothing
/// else.
///
/// A trailing `/` means a directory and matches its children; every other
/// entry is an EXACT file path. See [`advertisement_path`] for why that
/// distinction is load-bearing.
pub const ADVERTISEMENT_PATHS: &[&str] = &[
    "website/config.toml",
    "docs/install.md",
    "website/content/",
    "website/static/",
    "CHANGELOG.md",
];

/// Whether one path is an advertisement file.
///
/// The exact-vs-prefix distinction was missing from the first version, which
/// used `starts_with` for both kinds of entry. That exempted
/// `docs/install.md.bak`, `CHANGELOG.md.orig`, `website/config.toml.tmp` and
/// even `website/config.tomlx` — any file whose name merely begins with an
/// advertisement file's name. A commit carrying one of those beside real work
/// would have read as "just advertising a release" and skipped every delivery
/// gate.
#[must_use]
pub fn advertisement_path(f: &str) -> bool {
    ADVERTISEMENT_PATHS.iter().any(|p| {
        if let Some(dir) = p.strip_suffix('/') {
            // A directory matches its CHILDREN, so the next byte must be the
            // separator. Without that check `website/contentious.md` matches
            // `website/content/`.
            f.starts_with(dir) && f.as_bytes().get(dir.len()) == Some(&b'/')
        } else {
            f == *p
        }
    })
}

/// Whether a changeset is nothing but the newest tag's own advertisement.
///
/// `published` and `newest_tag` are passed in rather than read, so a caller
/// can ask the question about states this repository is not currently in.
#[must_use]
pub fn is_advertisement(
    changed: &[String],
    published: (u32, u32, u32),
    newest_tag: (u32, u32, u32),
) -> bool {
    // An empty changeset advertises nothing. Returning `true` here would
    // exempt the case where git reported nothing at all — which is the same
    // failure as treating "cannot look" as "nothing to see".
    if changed.is_empty() {
        return false;
    }
    if !changed.iter().all(|f| advertisement_path(f)) {
        return false;
    }
    // It must advertise THIS tag, not merely touch those files: a commit that
    // edits the site config while leaving it behind the newest release is
    // ordinary work wearing the release flow's clothes.
    published == newest_tag
}

/// A semantic version triple parsed from `0.5.131` or `v0.5.131`.
#[must_use]
pub fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
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

/// The most notifications a correctly debouncing server may send for a burst
/// of changes lasting `burst_secs`, given a debounce window of `window_secs`.
///
/// One per window, plus one for the change still pending when the burst ended.
/// That last one arrives after the burst, which is why the drain that collects
/// it must not be added to `burst_secs` — doing so inflated the ceiling while
/// the change count stopped growing, and on a slow runner the two met and the
/// test's own fixture guard fired.
#[must_use]
pub fn debounce_ceiling(burst_secs: f64, window_secs: f64) -> usize {
    (burst_secs / window_secs).ceil() as usize + 1
}

/// Files a DEPENDENCY BUMP touches, and nothing else.
///
/// Same shape as [`ADVERTISEMENT_PATHS`]: a trailing `/` is a directory, every
/// other entry is an exact file.
pub const DEPENDENCY_PATHS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "fuzz/Cargo.toml",
    "fuzz/Cargo.lock",
    "e2e/package.json",
    "e2e/package-lock.json",
    "Dockerfile",
    "bench/Dockerfile",
    ".github/workflows/",
];

/// Whether one path is a dependency-manifest file.
#[must_use]
pub fn dependency_path(f: &str) -> bool {
    DEPENDENCY_PATHS.iter().any(|p| {
        if let Some(dir) = p.strip_suffix('/') {
            f.starts_with(dir) && f.as_bytes().get(dir.len()) == Some(&b'/')
        } else {
            f == *p
        }
    })
}

/// Whether a changeset is nothing but a dependency bump.
///
/// # Why this exists
///
/// `a_p0_marked_done_is_released_or_declared` fires on any post-tag commit that
/// does not declare itself in the CHANGELOG. That is right for feature work and
/// wrong for a Dependabot bump: a lockfile update ships nothing a reader needs
/// told about, and the bot cannot write a changelog entry.
///
/// The cost was not theoretical. Six Dependabot pull requests sat unmergeable
/// against a branch protection requiring `CI success`, and the failing test was
/// this repository's own delivery gate reporting a bump as an undeclared
/// release. The gate was working exactly as written; what it lacked was a name
/// for the one kind of post-tag commit that legitimately says nothing.
///
/// Deliberately NARROW. A commit that edits `Cargo.toml` alongside `src/` is
/// not a bump, and a version bump touches the site config and the man page too,
/// so neither is exempted here.
///
/// # The one entry that is wider than its name
///
/// `.github/workflows/` is a DIRECTORY, so a workflow-only commit skips the
/// gate whether it pins a new action version or rewrites the CI logic by hand.
/// That is a decision rather than an oversight, and it is written down because
/// the list is called "dependency paths" and this entry is not only that:
/// Dependabot's `github_actions` group edits nothing else, so refusing the
/// directory would block those pull requests for the exact reason the whole
/// exemption exists. The gate asks whether USER-FACING work sits past the tag
/// undeclared, and a CI workflow ships nothing to a user.
///
/// If that trade ever stops being worth it, the narrowing is to require the
/// diff to touch only `uses:` lines — which needs the diff, not the path list,
/// and is why it is not done here.
#[must_use]
pub fn is_dependency_bump(changed: &[String]) -> bool {
    if changed.is_empty() {
        return false;
    }
    changed.iter().all(|f| dependency_path(f))
}
