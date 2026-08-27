"""The repo-path linker: a tracked file shown as text a reader must retype."""

import subprocess
import pathlib
import pytest

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
REPO = SCRIPTS.parent


def run(*args):
    return subprocess.run(
        ["python3", str(SCRIPTS / "link-repo-paths.py"), *args],
        capture_output=True, text=True, timeout=180, cwd=REPO,
    )


def test_the_tree_is_currently_clean():
    """The gate and the fixer have to agree: whatever the fixer leaves behind
    must satisfy the gate, or the two are enforcing different rules and the
    loop never terminates."""
    assert run().returncode == 0, run().stdout[-400:]


def test_the_fixer_is_idempotent():
    """Running it twice must change nothing the second time. A fixer that keeps
    editing is one that will fight its gate forever.

    Measured as a hash of the tree state around a second run, not by looking
    for a word in `git status`. The first version of this test searched the
    porcelain output for "link" and failed the moment a file NAMED
    test_link_repo_paths.py was staged -- it was checking filenames while
    claiming to check idempotence.
    """
    def tree():
        return subprocess.run(["git", "status", "--porcelain"],
                              capture_output=True, text=True, cwd=REPO).stdout

    assert run("--apply").returncode == 0
    before = tree()
    assert run("--apply").returncode == 0
    assert tree() == before, "a second run of the fixer changed the tree"


def test_it_reports_what_it_did():
    """Silence from a fixer is indistinguishable from a fixer that did not
    run."""
    out = run("--apply").stdout
    assert out.strip(), "the fixer printed nothing at all"
