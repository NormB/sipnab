# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""No script test writes a tracked file of the checkout it runs in.

On 2026-11-13 a full `pytest scripts/tests` changed docs/internals/testing.md
in the real checkout: two tests of test_link_repo_paths.py ran the path
linker with `--apply` and `cwd` = the repository. The file was already
staged, so the index and the tree differed, and the pre-commit hook's suite,
which reads the tree, failed on a count the pin gates had passed minutes
before. On 2026-11-09 test_prepare_commit.py had done the same and was fixed
alone. The cause is general: a test that runs a fixer where it stands.

conftest.py now reads the state of the tracked files before and after each
test file and fails the file that changed it. These tests hold that guard.
"""

import os
import pathlib
import subprocess
import textwrap

import conftest
import pytest

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
REPO = SCRIPTS.parent


def git(repo, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=repo, env=env, capture_output=True, text=True, check=True,
    )


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    (root / "docs/page.md").write_text("one\n")
    (root / "other.txt").write_text("a\n")
    git(root, "init", "-q")
    git(root, "add", "docs/page.md", "other.txt")
    git(root, "commit", "-q", "-m", "first")
    return root


# ── the comparison ─────────────────────────────────────────────────────────


def test_success_an_untouched_tree_has_no_change(repo):
    assert conftest.tree_changes(conftest.tree_state(repo), conftest.tree_state(repo)) == []


def test_success_a_tracked_file_written_is_named(repo):
    before = conftest.tree_state(repo)
    (repo / "docs/page.md").write_text("two\n")
    assert conftest.tree_changes(before, conftest.tree_state(repo)) == ["docs/page.md"]


def test_success_a_file_that_was_already_modified_and_changes_again_is_named(repo):
    (repo / "docs/page.md").write_text("two\n")
    before = conftest.tree_state(repo)
    (repo / "docs/page.md").write_text("three\n")
    assert conftest.tree_changes(before, conftest.tree_state(repo)) == ["docs/page.md"]


def test_success_a_staged_file_whose_tree_copy_changes_is_named(repo):
    (repo / "docs/page.md").write_text("two\n")
    git(repo, "add", "docs/page.md")
    before = conftest.tree_state(repo)
    (repo / "docs/page.md").write_text("three\n")
    assert conftest.tree_changes(before, conftest.tree_state(repo)) == ["docs/page.md"]


def test_failure_a_change_of_the_index_alone_is_named(repo):
    (repo / "other.txt").write_text("b\n")
    before = conftest.tree_state(repo)
    git(repo, "add", "other.txt")
    assert conftest.tree_changes(before, conftest.tree_state(repo)) == ["other.txt"]


def test_failure_a_deleted_tracked_file_is_named(repo):
    before = conftest.tree_state(repo)
    (repo / "other.txt").unlink()
    assert conftest.tree_changes(before, conftest.tree_state(repo)) == ["other.txt"]


def test_failure_two_files_written_are_both_named_in_order(repo):
    before = conftest.tree_state(repo)
    (repo / "other.txt").write_text("b\n")
    (repo / "docs/page.md").write_text("two\n")
    assert conftest.tree_changes(before, conftest.tree_state(repo)) == ["docs/page.md", "other.txt"]


def test_edge_a_file_written_back_to_what_it_was_is_no_change(repo):
    before = conftest.tree_state(repo)
    (repo / "docs/page.md").write_text("two\n")
    (repo / "docs/page.md").write_text("one\n")
    assert conftest.tree_changes(before, conftest.tree_state(repo)) == []


def test_edge_an_untracked_file_is_not_a_change(repo):
    before = conftest.tree_state(repo)
    (repo / "scratch.txt").write_text("x\n")
    assert conftest.tree_changes(before, conftest.tree_state(repo)) == []


def test_edge_a_directory_that_is_no_repository_has_no_state(tmp_path):
    assert conftest.tree_state(tmp_path) is None
    assert conftest.tree_changes(None, None) == []


def test_edge_the_state_is_read_without_the_hooks_git_variables(repo, monkeypatch):
    # `git commit` runs the hook with GIT_DIR and GIT_INDEX_FILE set; read
    # with them, the state would be that of another index.
    monkeypatch.setenv("GIT_INDEX_FILE", str(repo / "no-such-index"))
    before = conftest.tree_state(repo)
    assert before == {}, f"a clean checkout read through another index: {before}"
    (repo / "docs/page.md").write_text("two\n")
    assert conftest.tree_changes(before, conftest.tree_state(repo)) == ["docs/page.md"]


# ── the guard, in a pytest run of its own ──────────────────────────────────


def run_suite(repo, tmp_path, body):
    """Run pytest on one test file beside a copy of the real conftest.py,
    with the guard pointed at `repo`."""
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "conftest.py").write_text((SCRIPTS / "tests/conftest.py").read_text())
    (suite / "test_sample.py").write_text(textwrap.dedent(body))
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["SIPNAB_TREE_GUARD_REPO"] = str(repo)
    return subprocess.run(
        ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", str(suite)],
        capture_output=True, text=True, timeout=120, env=env, cwd=suite, check=False,
    )


def test_failure_a_test_file_that_writes_a_tracked_file_fails(repo, tmp_path):
    r = run_suite(repo, tmp_path, f"""
        import pathlib

        def test_writes():
            pathlib.Path({str(repo / "docs/page.md")!r}).write_text("rewritten\\n")
    """)
    assert r.returncode != 0, r.stdout
    assert "docs/page.md" in r.stdout and "test_sample.py" in r.stdout, r.stdout
    assert "wrote tracked files of the checkout" in r.stdout, r.stdout


def test_success_a_test_file_that_writes_only_its_own_directory_passes(repo, tmp_path):
    r = run_suite(repo, tmp_path, """
        def test_writes_a_temporary_file(tmp_path):
            (tmp_path / "x").write_text("x")
    """)
    assert r.returncode == 0, r.stdout


def test_edge_the_guard_is_on_for_every_test_file_without_being_asked():
    text = (SCRIPTS / "tests/conftest.py").read_text()
    assert '@pytest.fixture(autouse=True, scope="module")\ndef _no_test_file_writes_the_checkout' in text


# ── the two tests that did it ──────────────────────────────────────────────


def test_the_linker_tests_run_the_fixer_in_a_clone():
    text = (SCRIPTS / "tests/test_link_repo_paths.py").read_text()
    for line in text.splitlines():
        if '"--apply"' in line:
            assert "run_in_clone(" in line, f"the fixer runs in the real checkout: {line.strip()}"
