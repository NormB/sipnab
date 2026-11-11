# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""`check-rustfmt.sh --list`: the file list rustfmt is given, each file once.

git lists an unmerged path once per index stage. The list goes to
`xargs -P`, so a file listed three times could be given to three rustfmt
processes at once, and `--fix` would then write it from all three. `--list`
prints the list and runs no rustfmt, which is what lets a test read it.
"""

import pathlib
import subprocess

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "check-rustfmt.sh"


def _git(repo, *args, stdin=""):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        input=stdin,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _listed(repo):
    out = subprocess.run(
        ["bash", str(SCRIPT), "--list"], cwd=repo, capture_output=True, check=False
    )
    assert out.returncode == 0, out.stderr.decode()
    return [p for p in out.stdout.decode().split("\0") if p]


def _repo(tmp_path, unmerged=(), tracked=(), untracked=()):
    _git(tmp_path, "init", "-q")
    entries = []
    for rel in unmerged:
        for stage in (1, 2, 3):
            blob = _git(tmp_path, "hash-object", "-w", "--stdin", stdin=f"// {stage}\n")
            entries.append(f"100644 {blob} {stage}\t{rel}\n")
    for rel in tracked:
        blob = _git(tmp_path, "hash-object", "-w", "--stdin", stdin="// clean\n")
        entries.append(f"100644 {blob} 0\t{rel}\n")
    _git(tmp_path, "update-index", "--index-info", stdin="".join(entries))
    for rel in (*unmerged, *tracked, *untracked):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fn main() {}\n", encoding="utf-8")
    return tmp_path


def test_a_tracked_and_a_new_file_are_both_listed(tmp_path):
    repo = _repo(tmp_path, tracked=("src/a.rs",), untracked=("src/new.rs",))
    assert sorted(_listed(repo)) == ["src/a.rs", "src/new.rs"]


def test_an_unmerged_file_is_listed_once(tmp_path):
    repo = _repo(tmp_path, unmerged=("src/conflict.rs",), tracked=("src/a.rs",))
    assert _git(repo, "ls-files").splitlines().count("src/conflict.rs") == 3
    assert sorted(_listed(repo)) == ["src/a.rs", "src/conflict.rs"]


def test_two_unmerged_files_are_two_entries(tmp_path):
    repo = _repo(tmp_path, unmerged=("a.rs", "b/c.rs"), untracked=("d.rs",))
    assert sorted(_listed(repo)) == ["a.rs", "b/c.rs", "d.rs"]


def test_a_name_with_a_space_stays_one_entry(tmp_path):
    repo = _repo(tmp_path, unmerged=("src/a b.rs",))
    assert _listed(repo) == ["src/a b.rs"]


def test_a_tracked_file_deleted_from_the_work_tree_is_not_listed(tmp_path):
    repo = _repo(tmp_path, unmerged=("gone.rs",), tracked=("kept.rs",))
    (repo / "gone.rs").unlink()
    assert _listed(repo) == ["kept.rs"]


def test_list_outside_a_work_tree_exits_2(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    out = subprocess.run(
        ["bash", str(SCRIPT), "--list"], cwd=tmp_path, capture_output=True, check=False
    )
    assert out.returncode == 2
    assert b"not inside a git work tree" in out.stderr


def test_an_unknown_argument_is_a_usage_error(tmp_path):
    out = subprocess.run(
        ["bash", str(SCRIPT), "--lst"], cwd=tmp_path, capture_output=True, check=False
    )
    assert out.returncode == 2
    assert b"usage: scripts/check-rustfmt.sh [--fix|--list]" in out.stderr
