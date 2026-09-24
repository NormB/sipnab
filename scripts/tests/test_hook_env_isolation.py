"""No script test may reach the repository the pre-commit hook is committing to.

`git commit` runs the hook with GIT_DIR and GIT_INDEX_FILE exported, and the
hook runs these tests whenever a commit stages anything under scripts/. A
fixture that builds a throwaway repository with `git init` and `git add`
inherits both, so its git talks to the REAL repository instead of the
throwaway one.

In the main checkout GIT_INDEX_FILE is relative, `.git/index`, and resolves
inside the fixture's own directory, so nothing showed. In a linked worktree git
exports absolute paths. On 2026-09-24 the rfc-links fixture then replaced the
worktree's index with its two-file tree, so the commit being made deleted 1386
files, and `git init` set `core.bare = true` in the config every worktree of
the clone shares, which stopped the main checkout working at all.

This runs the fixtures that call git the way the hook does, with both variables
pointing at a sentinel repository, and requires the sentinel to be untouched.
"""

import os
import pathlib
import subprocess
import sys

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
ROOT = SCRIPTS.parent

# Tests whose fixtures run `git init` / `git add` in a temporary directory.
GIT_FIXTURE_TESTS = [
    "scripts/tests/test_rfc_links.py::test_check_mode_fails_when_the_fixer_would_change_something",
    "scripts/tests/test_check_line_drift.py::test_an_untracked_page_under_docs_is_not_read",
]


def _clean_env():
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, env=_clean_env(), check=True,
                   capture_output=True)


def test_git_fixtures_leave_the_hooks_repository_alone(tmp_path):
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    _git("init", "-q", cwd=sentinel)
    (sentinel / "kept.txt").write_text("kept\n")
    _git("add", "kept.txt", cwd=sentinel)
    gitdir = sentinel / ".git"
    index_before = (gitdir / "index").read_bytes()
    config_before = (gitdir / "config").read_text()

    # What `git commit` exports to a hook running in a linked worktree.
    env = _clean_env()
    env["GIT_DIR"] = str(gitdir)
    env["GIT_INDEX_FILE"] = str(gitdir / "index")
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         *GIT_FIXTURE_TESTS],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=300,
    )
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]

    assert (gitdir / "index").read_bytes() == index_before, (
        "a fixture's `git add` wrote to the hook's index"
    )
    assert (gitdir / "config").read_text() == config_before, (
        "a fixture's `git init` rewrote the hook's repository config"
    )
