# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/flag-since.py between a release's merge and its tag (backlog
RELEASE-SINCE-BEFORE-TAG).

437b77271 dated the flags of an untagged release from CHANGELOG.md's FIRST
`## [` heading: a cut `[X.Y.Z]` equal to Cargo.toml's version, with no tag
vX.Y.Z, made every flag no tag declares read X.Y.Z. That holds on the
release commit alone. The next pull request adds its own entry under a new
`## [Unreleased]` above `## [X.Y.Z]`, as the CHANGELOG rules require, and
the first heading is `[Unreleased]` again. On 2026-10-27 the merge tree of
PR #577 (85190ea5) had `[Unreleased]` above `[0.5.231]`, Cargo.toml said
0.5.231, and v0.5.231 was pushed at 23:44:34Z, 33 minutes after the job's
checkout: every flag of 0.5.231 read Unreleased and
the_since_column_is_what_tagged_history_says failed on every pull request.

The untagged release is now found in history: the oldest commit of HEAD
whose CHANGELOG.md adds the line `## [X.Y.Z]`, for the newest cut heading,
when X.Y.Z is Cargo.toml's version and no tag vX.Y.Z exists. That commit
stands in for the tag: flags it declares read X.Y.Z, and flags added after
it read Unreleased, which is what the tag gives once it is pushed.
"""

import subprocess
import sys

import pytest

from conftest import SCRIPTS, load
from test_flag_since import BPF, DEVICE, DRY_RUN, NEW, OLD, args_group, cli, commit, commit_file, cut, git

since = load("flag-since")
SCRIPT = SCRIPTS / "flag-since.py"


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    cut(root, "Unreleased", "0.0.0")
    return root


def changelog(*headings):
    """A CHANGELOG.md with `headings`, newest first, then [0.0.1]."""
    body = "# Changelog\n\nIntro naming [Keep a Changelog].\n\n"
    for h in headings:
        dated = "" if h == "Unreleased" else " - 2026-02-02"
        body += f"## [{h}]{dated}\n\n### Added\n\n- x\n\n"
    return body + "## [0.0.1] - 2026-01-01\n"


def write_changelog(root, *headings, message=None):
    (root / "CHANGELOG.md").write_text(changelog(*headings))
    if message:
        git(root, "add", "CHANGELOG.md")
        git(root, "commit", "-q", "-m", message)


def release_window(repo, version="0.2.0"):
    """v0.1.0 declares --device; --dry-run is added; the release commit cuts
    `version` with Cargo.toml at `version`, and no tag is pushed yet."""
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    commit(repo, cli(DEVICE, DRY_RUN))
    cut(repo, version, version)
    return git(repo, "rev-parse", "HEAD")


def pr_entry(repo, version="0.2.0", committed=True):
    """The next pull request: its entry under a new [Unreleased] above the cut."""
    write_changelog(repo, "Unreleased", version, message="PR entry" if committed else None)


# ---- success: the untagged release keeps its version --------------------


@pytest.mark.parametrize("version", ["0.2.0", "1.0.0", "0.10.3"])
def test_a_pull_request_entry_above_the_untagged_release_keeps_its_version(repo, version):
    release_window(repo, version)
    pr_entry(repo, version)
    assert since.flag_since(repo) == {"device": "0.1.0", "dry-run": version}, \
        "the flags of the untagged release read its version, not Unreleased"


def test_the_entry_before_it_is_committed_keeps_the_version(repo):
    release_window(repo)
    pr_entry(repo, committed=False)
    assert since.flag_since(repo) == {"device": "0.1.0", "dry-run": "0.2.0"}


def test_a_flag_the_pull_request_adds_reads_unreleased(repo):
    release_window(repo)
    pr_entry(repo)
    commit(repo, cli(DEVICE, DRY_RUN, BPF))
    got = since.flag_since(repo)
    assert got["<BPF_FILTER>"] == "Unreleased", got
    assert got["dry-run"] == "0.2.0", got


def test_pushing_the_tag_later_changes_nothing(repo):
    release = release_window(repo)
    pr_entry(repo)
    commit(repo, cli(DEVICE, DRY_RUN, BPF))
    before = since.flag_since(repo)
    git(repo, "tag", "v0.2.0", release)
    assert since.flag_since(repo) == before, "the tag must give what the release commit gave"


def test_two_pull_requests_after_the_release_keep_the_version(repo):
    release_window(repo)
    pr_entry(repo)
    commit(repo, cli(DEVICE, DRY_RUN, BPF), message="second PR")
    (repo / "CHANGELOG.md").write_text(changelog("Unreleased", "0.2.0") + "\n- second entry\n")
    git(repo, "commit", "-qam", "second PR entry")
    got = since.flag_since(repo)
    assert (got["dry-run"], got["<BPF_FILTER>"]) == ("0.2.0", "Unreleased"), got


def test_a_flag_in_a_group_file_at_the_release_keeps_the_version(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    commit_file(repo, "src/cli/query.rs", args_group(DRY_RUN))
    cut(repo, "0.2.0", "0.2.0")
    pr_entry(repo)
    assert since.flag_since(repo)["dry-run"] == "0.2.0"


def test_an_alias_a_pull_request_adds_to_a_released_flag_keeps_the_version(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    commit(repo, cli(DEVICE, OLD))
    cut(repo, "0.2.0", "0.2.0")
    pr_entry(repo)
    commit(repo, cli(DEVICE, NEW))
    got = since.flag_since(repo)
    assert got["new-name"] == got["old-name"] == "0.2.0", got


def test_the_release_commit_itself_still_reads_its_version(repo):
    release_window(repo)
    assert since.flag_since(repo) == {"device": "0.1.0", "dry-run": "0.2.0"}


def test_after_the_tag_a_pull_request_entry_changes_nothing(repo):
    release = release_window(repo)
    git(repo, "tag", "v0.2.0", release)
    pr_entry(repo)
    assert since.flag_since(repo) == {"device": "0.1.0", "dry-run": "0.2.0"}


def test_check_passes_in_the_window_on_the_page_the_release_wrote(repo):
    doc = repo / "docs" / "cli-reference.md"
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text("| Flag | Value | Default | Since | Description |\n"
                   "|------|-------|---------|-------|-------------|\n"
                   "| `--device` | name | none | 0.1.0 | Device |\n"
                   "| `--dry-run` | - | off | 0.2.0 | Do nothing |\n")
    git(repo, "add", "docs/cli-reference.md")
    release_window(repo)
    pr_entry(repo)
    p = run(repo, "--check")
    assert p.returncode == 0, p.stdout + p.stderr


def test_a_flag_removed_after_the_release_is_not_listed(repo):
    release_window(repo)
    pr_entry(repo)
    commit(repo, cli(DEVICE))
    assert since.flag_since(repo) == {"device": "0.1.0"}


def test_the_pending_release_names_the_version_and_the_commit(repo):
    release = release_window(repo)
    pr_entry(repo)
    assert since.pending_release(repo, ["v0.1.0"]) == ("0.2.0", release)


def test_the_release_commit_in_the_working_tree_names_no_commit(repo):
    release_window(repo)
    assert since.pending_release(repo, ["v0.1.0"]) == ("0.2.0", None)


# ---- failure: what cannot be answered is refused, and wrong pages fail ----


def test_a_cut_heading_no_commit_adds_is_refused(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    cut(repo, "Unreleased", "0.2.0")
    write_changelog(repo, "Unreleased", "0.2.0")  # only in the working tree
    with pytest.raises(since.FlagSinceError, match=r"no commit of HEAD adds `## \[0.2.0\]`"):
        since.flag_since(repo)


def test_a_cut_made_only_on_another_branch_is_refused(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    git(repo, "checkout", "-q", "-b", "release")
    cut(repo, "0.2.0", "0.2.0")
    git(repo, "checkout", "-q", "main")
    cut(repo, "Unreleased", "0.2.0")
    write_changelog(repo, "Unreleased", "0.2.0")
    with pytest.raises(since.FlagSinceError, match="no commit of HEAD adds"):
        since.flag_since(repo)


def merging_the_untagged_release(repo, version="0.2.0", entry=True):
    """A branch that started before the release, merging main after the
    release commit and before its tag: what its pre-commit hook sees. The
    branch's entry goes under a fresh [Unreleased] in the merge's tree."""
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    git(repo, "checkout", "-q", "-b", "feature")
    commit_file(repo, "notes.txt", "feature work\n", message="feature")
    git(repo, "checkout", "-q", "main")
    commit(repo, cli(DEVICE, DRY_RUN))
    cut(repo, version, version)
    release = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-q", "feature")
    git(repo, "merge", "-q", "--no-commit", "--no-ff", "main")
    if entry:
        write_changelog(repo, "Unreleased", version)
        git(repo, "add", "CHANGELOG.md")
    return release


def test_a_merge_of_the_untagged_release_reads_its_version(repo):
    # 2026-11-21: the merge of release 0.5.269 into a branch, before
    # v0.5.269 was pushed, failed the hook: "no commit of HEAD adds".
    merging_the_untagged_release(repo)
    assert since.flag_since(repo) == {"device": "0.1.0", "dry-run": "0.2.0"}, \
        "in a merge, the release commit the merge brings stands in for the tag"


def test_a_merge_names_the_release_commit_it_brings(repo):
    release = merging_the_untagged_release(repo)
    assert since.pending_release(repo, ["v0.1.0"]) == ("0.2.0", release)


def test_a_merge_of_a_branch_without_the_cut_is_still_refused(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    git(repo, "checkout", "-q", "-b", "other")
    commit_file(repo, "other.txt", "no release here\n", message="other")
    git(repo, "checkout", "-q", "main")
    cut(repo, "Unreleased", "0.2.0")
    git(repo, "merge", "-q", "--no-commit", "--no-ff", "other")
    write_changelog(repo, "Unreleased", "0.2.0")
    with pytest.raises(since.FlagSinceError, match="no commit of HEAD adds"):
        since.flag_since(repo)


def test_a_merge_into_a_branch_that_holds_the_release_reads_its_version(repo):
    release = release_window(repo)
    git(repo, "checkout", "-q", "-b", "side", "v0.1.0")
    commit_file(repo, "side.txt", "side work\n", message="side")
    git(repo, "checkout", "-q", "main")
    git(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
    write_changelog(repo, "Unreleased", "0.2.0")
    assert since.pending_release(repo, ["v0.1.0"]) == ("0.2.0", release), \
        "HEAD's own history still counts while a merge is in progress"


def test_the_merge_once_committed_reads_the_same(repo):
    release = merging_the_untagged_release(repo)
    git(repo, "commit", "-q", "-m", "merge main")
    assert since.pending_release(repo, ["v0.1.0"]) == ("0.2.0", release)
    assert since.flag_since(repo) == {"device": "0.1.0", "dry-run": "0.2.0"}


def test_the_program_exits_2_and_names_the_heading_it_cannot_find(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    cut(repo, "Unreleased", "0.2.0")
    write_changelog(repo, "Unreleased", "0.2.0")
    window_page(repo, "0.1.0", "Unreleased")
    p = run(repo, "--check")
    assert p.returncode == 2, p.stdout + p.stderr
    assert "## [0.2.0]" in p.stderr, p.stderr


def window_page(repo, device, dry_run, bpf=None):
    rows = [f"| `--device` | name | none | {device} | Device |",
            f"| `--dry-run` | - | off | {dry_run} | Do nothing |"]
    if bpf:
        rows.append(f"| `<BPF_FILTER>` | expr | none | {bpf} | Filter |")
    doc = repo / "docs" / "cli-reference.md"
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text("| Flag | Value | Default | Since | Description |\n"
                   "|------|-------|---------|-------|-------------|\n" + "\n".join(rows) + "\n")


@pytest.mark.parametrize("device,dry_run", [("0.1.0", "Unreleased"), ("0.1.0", "0.1.0"),
                                            ("0.2.0", "0.2.0"), ("Unreleased", "0.2.0")])
def test_check_refuses_a_wrong_cell_in_the_window(repo, device, dry_run):
    release_window(repo)
    pr_entry(repo)
    window_page(repo, device, dry_run)
    p = run(repo, "--check")
    assert p.returncode == 1, p.stdout + p.stderr


def test_a_first_cut_heading_unequal_to_the_crate_version_is_still_refused(repo):
    release_window(repo)
    cut(repo, "0.2.0", "0.1.9")
    with pytest.raises(since.FlagSinceError, match=r"first heading is \[0.2.0\]"):
        since.flag_since(repo)


def test_a_missing_cargo_manifest_is_refused_in_the_window(repo):
    release_window(repo)
    pr_entry(repo)
    (repo / "Cargo.toml").unlink()
    with pytest.raises(since.FlagSinceError, match="Cargo.toml"):
        since.flag_since(repo)


def test_a_malformed_cargo_manifest_is_refused_in_the_window(repo):
    release_window(repo)
    pr_entry(repo)
    (repo / "Cargo.toml").write_text("[package\nversion = ")
    with pytest.raises(since.FlagSinceError, match="Cargo.toml"):
        since.flag_since(repo)


def test_the_refusal_says_how_the_heading_is_expected_to_arrive(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    cut(repo, "Unreleased", "0.2.0")
    write_changelog(repo, "Unreleased", "0.2.0")
    with pytest.raises(since.FlagSinceError, match="release commit"):
        since.flag_since(repo)


# ---- edges -----------------------------------------------------------------


def test_between_releases_the_newest_heading_is_tagged_and_nothing_is_pending(repo):
    release = release_window(repo)
    git(repo, "tag", "v0.2.0", release)
    pr_entry(repo)
    assert since.pending_release(repo, ["v0.1.0", "v0.2.0"]) is None


def test_an_untagged_heading_unequal_to_the_crate_version_changes_nothing(repo):
    # The fixture's own [0.0.1] is untagged and Cargo.toml says 0.0.0: an old
    # untagged heading is not a release in progress.
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    commit(repo, cli(DEVICE, DRY_RUN))
    assert since.flag_since(repo) == {"device": "0.1.0", "dry-run": "Unreleased"}


def test_the_oldest_commit_that_adds_the_heading_is_the_release(repo):
    release = release_window(repo)
    pr_entry(repo)
    write_changelog(repo, "Unreleased", message="heading dropped by mistake")
    write_changelog(repo, "Unreleased", "0.2.0", message="heading restored")
    assert since.pending_release(repo, ["v0.1.0"]) == ("0.2.0", release)


def test_a_dot_in_the_version_is_not_a_wildcard(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    write_changelog(repo, "0x2y0", message="a heading that is no version")
    commit(repo, cli(DEVICE, DRY_RUN))
    cut(repo, "0.2.0", "0.2.0")
    release = git(repo, "rev-parse", "HEAD")
    pr_entry(repo)
    assert since.pending_release(repo, ["v0.1.0"]) == ("0.2.0", release)


def test_the_heading_named_only_in_prose_is_not_the_cut(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    (repo / "CHANGELOG.md").write_text(changelog("Unreleased") + "\nSee ## [0.2.0] later.\n")
    git(repo, "commit", "-qam", "prose names the heading")
    commit(repo, cli(DEVICE, DRY_RUN))
    cut(repo, "0.2.0", "0.2.0")
    release = git(repo, "rev-parse", "HEAD")
    pr_entry(repo)
    assert since.pending_release(repo, ["v0.1.0"]) == ("0.2.0", release)


def test_the_heading_in_another_file_is_not_the_cut(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    commit_file(repo, "docs/notes.md", "## [0.2.0]\n")
    commit(repo, cli(DEVICE, DRY_RUN))
    cut(repo, "0.2.0", "0.2.0")
    release = git(repo, "rev-parse", "HEAD")
    pr_entry(repo)
    assert since.pending_release(repo, ["v0.1.0"]) == ("0.2.0", release)


def test_a_flag_added_between_the_release_and_the_entry_reads_unreleased(repo):
    release_window(repo)
    commit(repo, cli(DEVICE, DRY_RUN, BPF), message="lands before its entry")
    pr_entry(repo)
    assert since.flag_since(repo)["<BPF_FILTER>"] == "Unreleased"


def test_the_released_flags_of_older_tags_keep_their_versions(repo):
    release_window(repo)
    pr_entry(repo)
    assert since.flag_since(repo)["device"] == "0.1.0", "the stand-in is ordered after every tag"


def test_an_only_unreleased_changelog_with_no_cut_heading_is_not_pending(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    (repo / "CHANGELOG.md").write_text("# Changelog\n\n## [Unreleased]\n\n- x\n")
    assert since.pending_release(repo, ["v0.1.0"]) is None


def test_the_window_is_answered_without_writing_to_git(repo):
    release_window(repo)
    pr_entry(repo)
    before = git(repo, "for-each-ref")
    since.flag_since(repo)
    assert git(repo, "for-each-ref") == before, "no tag or ref is created to answer"


def test_a_pre_release_heading_does_not_stand_in_for_a_release(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    commit(repo, cli(DEVICE, DRY_RUN))
    cut(repo, "0.2.0-rc1", "0.2.0-rc1")
    pr_entry(repo, "0.2.0-rc1")
    assert since.flag_since(repo)["dry-run"] == "Unreleased", \
        "a pre-release is no release, as with tags"


def test_a_tag_on_a_later_commit_decides_once_it_exists(repo):
    release_window(repo)
    pr_entry(repo)
    commit(repo, cli(DEVICE, DRY_RUN, BPF))
    git(repo, "tag", "v0.2.0")  # the tag went on a later commit that holds the PR's flag
    assert since.flag_since(repo)["<BPF_FILTER>"] == "0.2.0", "a pushed tag's history answers"


def test_two_untagged_cut_headings_stand_in_only_for_the_newest(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    commit(repo, cli(DEVICE, DRY_RUN))
    write_changelog(repo, "0.2.0", message="cut 0.2.0, never tagged")
    write_changelog(repo, "0.3.0", "0.2.0")
    (repo / "Cargo.toml").write_text('[package]\nname = "fixture"\nversion = "0.3.0"\n')
    git(repo, "commit", "-qam", "cut 0.3.0")
    release = git(repo, "rev-parse", "HEAD")
    pr_entry(repo, "0.3.0")
    (repo / "CHANGELOG.md").write_text(changelog("Unreleased", "0.3.0", "0.2.0"))
    git(repo, "commit", "-qam", "entry")
    assert since.pending_release(repo, ["v0.1.0"]) == ("0.3.0", release)
    assert since.flag_since(repo)["dry-run"] == "0.3.0", "0.2.0 was never tagged, so never released"


def test_a_cut_heading_with_no_date_is_found(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    (repo / "CHANGELOG.md").write_text("# Changelog\n\n## [0.2.0]\n\n- x\n")
    (repo / "Cargo.toml").write_text('[package]\nname = "fixture"\nversion = "0.2.0"\n')
    git(repo, "commit", "-qam", "cut without a date")
    release = git(repo, "rev-parse", "HEAD")
    (repo / "CHANGELOG.md").write_text("# Changelog\n\n## [Unreleased]\n\n- y\n\n## [0.2.0]\n\n- x\n")
    assert since.pending_release(repo, ["v0.1.0"]) == ("0.2.0", release)


def test_a_bracketed_name_that_is_not_a_version_is_not_pending(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    (repo / "CHANGELOG.md").write_text(changelog("Unreleased", "v0.2.0"))
    (repo / "Cargo.toml").write_text('[package]\nname = "fixture"\nversion = "v0.2.0"\n')
    assert since.pending_release(repo, ["v0.1.0"]) is None


def test_a_release_merged_with_a_merge_commit_is_found(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    git(repo, "checkout", "-q", "-b", "release")
    commit(repo, cli(DEVICE, DRY_RUN))
    cut(repo, "0.2.0", "0.2.0")
    release = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-q", "main")
    git(repo, "merge", "-q", "--no-ff", "-m", "Merge release", "release")
    pr_entry(repo)
    assert since.pending_release(repo, ["v0.1.0"]) == ("0.2.0", release)
    assert since.flag_since(repo)["dry-run"] == "0.2.0"


def test_a_pull_request_merge_tree_like_ci_checks_out_is_answered(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    git(repo, "checkout", "-q", "-b", "pr")
    (repo / "CHANGELOG.md").write_text(changelog("Unreleased") + "\n- PR entry\n")
    git(repo, "commit", "-qam", "PR entry, based before the release")
    git(repo, "checkout", "-q", "main")
    commit(repo, cli(DEVICE, DRY_RUN))
    cut(repo, "0.2.0", "0.2.0")
    git(repo, "checkout", "-q", "pr")
    git(repo, "merge", "-q", "-X", "theirs", "-m", "Merge main into pr", "main")
    write_changelog(repo, "Unreleased", "0.2.0", message="entry above the cut")
    assert since.flag_since(repo) == {"device": "0.1.0", "dry-run": "0.2.0"}


@pytest.mark.parametrize("committed", [True, False])
def test_the_pull_request_flag_reads_unreleased_whether_or_not_its_entry_is_committed(repo, committed):
    release_window(repo)
    commit(repo, cli(DEVICE, DRY_RUN, BPF))
    pr_entry(repo, committed=committed)
    assert since.flag_since(repo)["<BPF_FILTER>"] == "Unreleased"


def test_write_in_the_window_dates_the_release_flags(repo):
    window_page(repo, "0.1.0", "Unreleased")
    release_window(repo)
    pr_entry(repo)
    assert run(repo, "--write").returncode == 0
    assert "| off | 0.2.0 | Do nothing |" in (repo / "docs/cli-reference.md").read_text()
    assert run(repo, "--check").returncode == 0


def test_write_refuses_and_changes_nothing_when_the_cut_commit_is_missing(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    cut(repo, "Unreleased", "0.2.0")
    write_changelog(repo, "Unreleased", "0.2.0")
    window_page(repo, "0.1.0", "0.1.0")
    before = (repo / "docs/cli-reference.md").read_text()
    p = run(repo, "--write")
    assert p.returncode == 2, p.stdout + p.stderr
    assert (repo / "docs/cli-reference.md").read_text() == before


@pytest.mark.parametrize("version", ["1.0.0", "0.10.3"])
def test_a_missing_cut_commit_is_refused_for_any_version(repo, version):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    cut(repo, "Unreleased", version)
    write_changelog(repo, "Unreleased", version)
    with pytest.raises(since.FlagSinceError, match=rf"`## \[{version}\]`"):
        since.flag_since(repo)


def test_the_refusal_is_a_message_not_a_traceback(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    cut(repo, "Unreleased", "0.2.0")
    write_changelog(repo, "Unreleased", "0.2.0")
    window_page(repo, "0.1.0", "Unreleased")
    p = run(repo, "--check")
    assert p.returncode == 2 and "Traceback" not in p.stderr, p.stderr
    assert "no commit of HEAD adds" in p.stderr, p.stderr


@pytest.mark.parametrize("bpf", ["0.2.0", "0.1.0"])
def test_check_refuses_a_released_version_on_a_flag_added_after_the_release(repo, bpf):
    release_window(repo)
    pr_entry(repo)
    commit(repo, cli(DEVICE, DRY_RUN, BPF))
    window_page(repo, "0.1.0", "0.2.0", bpf=bpf)
    p = run(repo, "--check")
    assert p.returncode == 1 and "BPF_FILTER" in p.stdout, p.stdout + p.stderr


def run(repo, *args):
    return subprocess.run([sys.executable, str(SCRIPT), "--repo", str(repo), *args],
                          capture_output=True, text=True, timeout=120)
