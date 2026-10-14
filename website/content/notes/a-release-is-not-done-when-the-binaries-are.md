+++
title = "Download page kept offering 0.5.127 after GitHub published the 0.5.128 release files"
date = 2026-08-27
updated = 2026-10-11
description = "Why the sipnab website deliberately lags a new release, why a test allowed the 0.5.128 download links to stay on 0.5.127 after the release files existed, and the test that now checks for that case."

[extra]
kind = "postmortem"
+++

## In short

The sipnab website shows a version number and download links.

- On 2026-08-27 GitHub published the files of release 0.5.128.
- But the website went on offering 0.5.127 until a separate change updated it.

The website waits for a release to finish by design. A test allowed it to stay
one version behind. That test did not check whether the newer release's files
already existed.

A new test now checks. It fails when the files exist and the website still
names the older version.

## What happened

The tag `v0.5.128` dates from 2026-08-27 at 15:58:57 (UTC-4). Tagging starts
the release workflow. The workflow builds the release files and publishes them
on GitHub.

The website's version badge and every link on its download page read the field
`published_version` in `website/config.toml`.

- That field still read `0.5.127` after the 0.5.128 files were available.
- So a visitor who followed the download or install instructions received
  0.5.127.

The commit `ddb05f3a`, "Tell the website that 0.5.128 exists", did two things
at 16:39:00 the same day:

- It changed `published_version` from `0.5.127` to `0.5.128`.
- It added `tests/release_completeness_test.rs`.

Its commit message records that the release had published twenty-three files.
At the same time, these still pointed at 0.5.127:

- the download page,
- its checksum column,
- its `SHA256SUMS.txt` link.

## Why it happened

### The website waits for a release on purpose

`website/config.toml` has two version fields:

- `version` is the version of the source code.
  - The website build copies it from `Cargo.toml`.
  - So it changes as soon as a release commit reaches the main branch.
- `published_version` is the newest version a visitor can download.
  - These read this field: every download link, the homepage badge, the footer
    and the structured page data.
  - A separate commit changes it after a release finishes publishing.

The split exists because a release commit reaches the website before its tag
and its files exist.

- If the download links followed `version`, every link would return "not
  found" (HTTP 404) during that time.
- On 0.5.61 that period was longer than usual:
  - The release commit `345344e7` (14:28:15 on 2026-07-29) was never tagged.
  - The tag `v0.5.61`, dated 14:59:38, points at the next commit, `6cf58a8e`.

### The test allowed one version of lag without checking why

`site_advertises_only_a_released_version` in `tests/site_journey_test.rs` has
two rules:

- `published_version` must name a version that has a tag.
- It may be at most one release behind the newest tag.

Its message gives the reason:

```text
One behind is allowed: that is the window between tagging a release and its assets finishing publishing.
```

On 2026-08-27, `published_version` was exactly one release behind. So the test
passed.

- It accepted the lag whether or not GitHub had already published the files of
  the newer release.
- Nothing else checked for them.

## What changed

`tests/release_completeness_test.rs` adds a check beside the one-version
allowance. The allowance stays in place.

- `the_site_advertises_the_newest_release_whose_assets_exist` asks the GitHub
  command-line tool (`gh`) how many files the newest release has.
- If the release has files, the test requires `published_version` to name
  that release.
- `gh` may not be able to answer, for example because it is not installed.
  Then the test prints the reason on standard error and passes.
  - In that case it has not checked the release.
  - Its standard error output says so.

The same file holds ten more tests. They check, among other things, that:

- the advertised release date belongs to the advertised version,
- every download instruction names the advertised version,
- the source version is never behind it,
- it has a changelog entry and a tag,
- every dated changelog entry names a real tag,
- the install page and its website copy name the same version.

## What you can check yourself

These commands run in a clone of the sipnab repository with its tags.

The two version fields and the release date today:

```bash
grep -n -E '^(version|published_version|release_date) =' website/config.toml
```

```text
37:version = "0.5.211"
51:published_version = "0.5.211"
60:release_date = "2026-10-11"
```

The change that moved `published_version` to 0.5.128:

```bash
git show ddb05f3a -- website/config.toml | grep '^[-+]published'
```

```text
-published_version = "0.5.127"
+published_version = "0.5.128"
```

The last line of the commit message of the commit before the one the 0.5.61
tag points at:

```bash
git cat-file -p 'v0.5.61^{commit}^' | tail -n 1
```

```text
Release 0.5.61
```

The number of tests in the release-completeness file:

```bash
grep -c '^#\[test\]' tests/release_completeness_test.rs
```

```text
11
```

## Terms used here

- **Release**: a published version of sipnab, with its built files.
- **Release files** (assets): the downloadable archives, packages and checksum
  files attached to a GitHub release.
- **Tag**: the name git gives the exact source of a released version.
  Creating one starts the release build.
- **Commit**: one recorded change to the source.
- **Workflow**: an automated job that runs on GitHub when something changes in
  the repository.
- **Changelog**: the file `CHANGELOG.md`. It lists the changes in each
  version.
- **Test**: code that checks a fact about the project and fails when it does
  not hold.
- **`gh`**: GitHub's command-line tool.
- **Standard error**: the output channel a program uses for messages. It is
  separate from its normal output.

## Related guides

- [Install sipnab](@/docs/install.md)
