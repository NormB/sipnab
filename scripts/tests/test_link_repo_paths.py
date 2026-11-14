# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The repo-path linker: a tracked file shown as text a reader must retype."""

import atexit
import functools
import os
import shutil
import subprocess
import pathlib
import tempfile
import pytest

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent
REPO = SCRIPTS.parent


def run(*args):
    return subprocess.run(
        ["python3", str(SCRIPTS / "link-repo-paths.py"), *args],
        capture_output=True, text=True, timeout=180, cwd=REPO,
    )


@functools.lru_cache(maxsize=1)
def clone():
    """A throw-away clone of this repository's HEAD for the fixer to write in.

    `--apply` rewrites the docs of the tree it runs in. Until 2026-11-13 the
    tests below ran it in the real checkout: a full run of these tests linked
    a path in a page that was already staged, and the pre-commit hook then
    failed on a tree the pin gates had passed."""
    base = tempfile.mkdtemp(prefix="sipnab-linker-test.")
    atexit.register(shutil.rmtree, base, ignore_errors=True)
    copy = pathlib.Path(base) / "repo"
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    subprocess.run(["git", "clone", "--quiet", "--shared", str(REPO), str(copy)],
                   check=True, env=env, capture_output=True)
    return copy


def run_in_clone(*args):
    copy = clone()
    return subprocess.run(
        ["python3", str(copy / "scripts/link-repo-paths.py"), *args],
        capture_output=True, text=True, timeout=180, cwd=copy,
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
        return subprocess.run(["git", "diff"], capture_output=True, text=True, cwd=clone()).stdout

    assert run_in_clone("--apply").returncode == 0
    before = tree()
    assert run_in_clone("--apply").returncode == 0
    assert tree() == before, "a second run of the fixer changed the tree"


def test_it_reports_what_it_did():
    """Silence from a fixer is indistinguishable from a fixer that did not
    run."""
    out = run_in_clone("--apply").stdout
    assert out.strip(), "the fixer printed nothing at all"
