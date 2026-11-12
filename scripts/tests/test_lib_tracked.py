# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""`lib_tracked`: an unmerged path is listed once per stage and read once.

The fixtures write the index a conflicted merge leaves (one path at stages 1,
2 and 3) with `git update-index --index-info`: no commit and no merge.
"""

import subprocess

import pytest

from conftest import load

lib_tracked = load("lib_tracked")


def _git(repo, *args, stdin=""):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        input=stdin,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _unmerged_repo(tmp_path, conflicted=("conflict.md",), clean=("clean.md",)):
    """A repository with `conflicted` at stages 1-3 and `clean` at stage 0."""
    _git(tmp_path, "init", "-q")
    entries = []
    for rel in conflicted:
        for stage, body in ((1, "base\n"), (2, "ours\n"), (3, "theirs\n")):
            blob = _git(tmp_path, "hash-object", "-w", "--stdin", stdin=body + rel)
            entries.append(f"100644 {blob} {stage}\t{rel}\n")
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("<<<<<<< ours\n", encoding="utf-8")
    for rel in clean:
        blob = _git(tmp_path, "hash-object", "-w", "--stdin", stdin="clean\n" + rel)
        entries.append(f"100644 {blob} 0\t{rel}\n")
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("clean\n", encoding="utf-8")
    _git(tmp_path, "update-index", "--index-info", stdin="".join(entries))
    return tmp_path


# --- unique_paths: the rule -------------------------------------------------


def test_a_listing_without_repeats_is_kept_in_order():
    assert lib_tracked.unique_paths("b.md\0a.md\0c.md\0") == ["b.md", "a.md", "c.md"]


def test_an_unmerged_path_is_returned_once():
    listing = "README.md\0docs/a.md\0docs/a.md\0docs/a.md\0docs/b.md\0"
    assert lib_tracked.unique_paths(listing) == ["README.md", "docs/a.md", "docs/b.md"]


def test_two_unmerged_pages_count_as_two():
    listing = "a.md\0a.md\0a.md\0b.md\0b.md\0b.md\0c.md\0"
    assert len(lib_tracked.unique_paths(listing)) == 3


def test_a_repeat_that_is_not_adjacent_is_removed():
    assert lib_tracked.unique_paths("x\0y\0x\0z\0y\0") == ["x", "y", "z"]


def test_bytes_and_text_listings_agree():
    assert lib_tracked.unique_paths(b"a.md\0a.md\0b.md\0") == ["a.md", "b.md"]
    assert lib_tracked.unique_paths("a.md\0a.md\0b.md\0") == ["a.md", "b.md"]


def test_an_empty_listing_is_empty():
    assert lib_tracked.unique_paths("") == []
    assert lib_tracked.unique_paths(b"\0\0") == []
    assert lib_tracked.unique_paths("only.md") == ["only.md"]


def test_whitespace_inside_a_name_does_not_split_it():
    listing = "docs/a b.md\0docs/a\nb.md\0docs/a b.md\0"
    assert lib_tracked.unique_paths(listing) == ["docs/a b.md", "docs/a\nb.md"]


def test_a_non_utf8_name_is_one_path():
    assert len(lib_tracked.unique_paths(b"caf\xe9.md\0caf\xe9.md\0caf\xe9.md\0")) == 1


# --- ls_files: the command --------------------------------------------------


def test_git_itself_lists_the_unmerged_path_three_times(tmp_path):
    """The fixture is the real condition, or the next tests prove nothing."""
    repo = _unmerged_repo(tmp_path)
    raw = _git(repo, "ls-files").splitlines()
    assert raw.count("conflict.md") == 3


def test_ls_files_returns_an_unmerged_path_once(tmp_path):
    repo = _unmerged_repo(tmp_path)
    assert lib_tracked.ls_files(repo) == ["clean.md", "conflict.md"]


def test_ls_files_with_a_pathspec_returns_an_unmerged_path_once(tmp_path):
    repo = _unmerged_repo(tmp_path, conflicted=("docs/x.md", "y.md"))
    assert lib_tracked.ls_files(repo, "--", "docs/*.md") == ["docs/x.md"]


def test_ls_files_fails_loudly_outside_a_repository(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    with pytest.raises(subprocess.CalledProcessError):
        lib_tracked.ls_files(tmp_path)


# --- the scripts that list tracked files ------------------------------------


def test_add_source_headers_lists_an_unmerged_path_once(tmp_path, monkeypatch):
    repo = _unmerged_repo(tmp_path, conflicted=("src/a.rs",), clean=("src/b.rs",))
    monkeypatch.chdir(repo)
    mod = load("add-source-headers")
    assert mod.tracked() == ["src/a.rs", "src/b.rs"]


def test_no_itu_values_lists_an_unmerged_path_once(tmp_path):
    repo = _unmerged_repo(tmp_path, conflicted=("a.bin",), clean=("b.bin",))
    mod = load("no-itu-values")
    listed = [p.name for p in mod.git_files(repo)]
    assert listed.count("a.bin") == 1, listed
    assert sorted(listed) == ["a.bin", "b.bin"]


def test_rfc_links_lists_an_unmerged_path_once(tmp_path):
    repo = _unmerged_repo(tmp_path, conflicted=("docs/a.md",), clean=("docs/b.md",))
    mod = load("rfc-links")
    listed = [p.name for p in mod._tracked(repo, "*.md")]
    assert listed == ["a.md", "b.md"]


def test_check_line_drift_lists_an_unmerged_path_once(tmp_path, monkeypatch):
    repo = _unmerged_repo(tmp_path, conflicted=("docs/a.md",), clean=("docs/b.md",))
    mod = load("check-line-drift")
    monkeypatch.setattr(mod, "REPO", repo)
    listed = [p.name for p in mod.tracked("docs/**/*.md")]
    assert listed == ["a.md", "b.md"]
