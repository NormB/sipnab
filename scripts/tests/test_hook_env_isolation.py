# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

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
import shutil
import subprocess
import sys

from conftest import load
from test_gate_cache_hooks import git, pre_commit_sandbox

lib_tracked = load("lib_tracked")

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
ROOT = SCRIPTS.parent

# Tests whose fixtures run `git init` / `git add` in a temporary directory.
GIT_FIXTURE_TESTS = [
    "scripts/tests/test_rfc_links.py::test_check_mode_fails_when_the_fixer_would_change_something",
    "scripts/tests/test_check_line_drift.py::test_an_untracked_page_under_docs_is_not_read",
    "scripts/tests/test_fetch_vcon_datasets.py::test_a_cached_checkout_at_another_commit_is_moved_to_the_pin",
    "scripts/tests/test_flag_since.py::test_write_fixes_the_table_and_check_then_agrees",
    "scripts/tests/test_gate_cache.py::test_an_untracked_file_is_in_the_snapshot",
    "scripts/tests/test_gate_cache_hooks.py::test_a_docs_only_change_reuses_the_build_stamps_and_runs_the_suite",
    "scripts/tests/test_gate_cache_hooks.py::test_a_second_push_of_the_same_tree_runs_no_cached_step",
    # A module-scoped fixture: on 2026-11-27 its git commands reached the
    # hook's repository, made twelve commits on the branch being committed and
    # set `core.bare = true` in the shared config.
    "scripts/tests/test_feature_rows_for_history.py::test_failure_the_826_fixture_fails_the_g729_row_push_rows_picks",
]

# A test file whose git runs at import and in a module-scoped fixture, the two
# places a function-scoped autouse fixture cannot reach: pytest imports a test
# module, and sets up a module fixture, before any function fixture of it.
# Each `git init` and `git commit` runs with the environment the test process
# has, as a careless fixture would.
PLANTED_TEST = '''\
import os
import subprocess
import tempfile

import pytest


def _commit_in(directory):
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.name=E", "-c", "user.email=e@example.com", "-c", "commit.gpgsign=false",
                  "commit", "-q", "--allow-empty", "-m", "planted"]):
        subprocess.run(["git", *args], cwd=directory, env=env, check=True, capture_output=True, timeout=60)


AT_IMPORT = tempfile.mkdtemp()
with open(os.path.join(AT_IMPORT, "f.txt"), "w") as f:
    f.write("import\\n")
_commit_in(AT_IMPORT)


@pytest.fixture(scope="module")
def module_repo(tmp_path_factory):
    d = tmp_path_factory.mktemp("module-repo")
    (d / "f.txt").write_text("module\\n")
    _commit_in(d)
    return d


def test_planted(module_repo):
    mark = os.environ.get("SIPNAB_SCRIPT_MARK")
    if mark:
        with open(mark, "a") as f:
            f.write("ran\\n")
    assert (module_repo / ".git").is_dir(), "the fixture made its own repository"
'''


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


def _sentinel(path):
    """A repository with one staged file: (git dir, what to compare later)."""
    path.mkdir()
    _git("init", "-q", cwd=path)
    (path / "kept.txt").write_text("kept\n")
    _git("add", "kept.txt", cwd=path)
    gitdir = path / ".git"
    return gitdir, _repo_state(gitdir)


def _repo_state(gitdir):
    """The config's bytes, the index's entries (mode, blob, stage, path) and
    HEAD. The entries, not the index's bytes: a hook's own `git status`
    refreshes the stat data in it."""
    head = subprocess.run(["git", "--git-dir", str(gitdir), "rev-parse", "-q", "--verify", "HEAD"],
                          env=_clean_env(), capture_output=True, text=True).stdout.strip()
    return {"config": (gitdir / "config").read_bytes(),
            "index": lib_tracked.ls_files(gitdir.parent, "--stage", env=_clean_env()), "head": head}


def _assert_untouched(gitdir, before):
    after = _repo_state(gitdir)
    assert after["config"] == before["config"], (
        "a test's `git init` rewrote the hook's repository config: "
        + after["config"].decode(errors="replace"))
    assert b"bare = true" not in after["config"], "the hook's repository was made bare"
    assert after["index"] == before["index"], "a test's `git add` wrote the hook's index"
    assert after["head"] == before["head"], f"a test committed to the hook's repository ({after['head']})"


def test_a_module_scoped_fixture_and_import_time_git_leave_the_hooks_repository_alone(tmp_path):
    gitdir, before = _sentinel(tmp_path / "sentinel")
    tests = tmp_path / "planted"
    tests.mkdir()
    # The real conftest is the rule under test.
    shutil.copy(SCRIPTS / "tests/conftest.py", tests / "conftest.py")
    (tests / "test_planted.py").write_text(PLANTED_TEST)
    env = _clean_env()
    env["GIT_DIR"] = str(gitdir)
    env["GIT_INDEX_FILE"] = str(gitdir / "index")
    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(tests)],
                         cwd=tests, env=env, capture_output=True, text=True, timeout=300)
    _assert_untouched(gitdir, before)
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]


def test_the_hooks_script_test_step_leaves_the_repository_alone(tmp_path):
    # The real pre-commit hook, in a sandbox, with GIT_DIR and GIT_INDEX_FILE
    # absolute, as `git commit` exports them in a linked worktree. The staged
    # change is the planted test file, so the Script tests step runs it.
    with pre_commit_sandbox(tmp_path / "harness") as sb:
        tests = sb.tree / "scripts/tests"
        tests.mkdir(parents=True, exist_ok=True)
        shutil.copy(SCRIPTS / "tests/conftest.py", tests / "conftest.py")
        (tests / "test_planted.py").write_text(PLANTED_TEST)
        git(sb.tree, "add", "scripts/tests/conftest.py", "scripts/tests/test_planted.py")
        gitdir = sb.tree / ".git"
        before = _repo_state(gitdir)
        mark = tmp_path / "mark"
        rc, out = sb.run(GIT_DIR=str(gitdir), GIT_INDEX_FILE=str(gitdir / "index"),
                         SIPNAB_SCRIPT_MARK=str(mark))
        _assert_untouched(gitdir, before)
        assert rc == 0, out[-3000:]
        assert mark.is_file() and mark.read_text() == "ran\n", f"the Script tests step ran the planted test once: {out}"
