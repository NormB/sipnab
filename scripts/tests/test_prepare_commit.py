# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The fixer sweep.

Most of the failures this script exists to prevent were not defects in the
fixers. They were the fixers not being run, discovered five minutes into a
commit when a gate refused. The sweep is only worth having if it reports
honestly, so these check the reporting rather than the fixing.
"""

import atexit
import functools
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SWEEP = REPO / "scripts/prepare-commit.sh"


@functools.lru_cache(maxsize=1)
def checkout():
    """A throw-away clone of this repository's HEAD for the sweep to rewrite."""
    base = tempfile.mkdtemp(prefix="sipnab-sweep-test.")
    atexit.register(shutil.rmtree, base, ignore_errors=True)
    copy = pathlib.Path(base) / "repo"
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    subprocess.run(["git", "clone", "--quiet", "--shared", str(REPO), str(copy)],
                   check=True, env=env, capture_output=True)
    return copy


def run():
    copy = checkout()
    return subprocess.run(["bash", str(copy / "scripts/prepare-commit.sh")],
                          capture_output=True, text=True, timeout=900, cwd=copy)


def test_the_sweep_under_test_never_runs_in_this_checkout(monkeypatch):
    """prepare-commit.sh rewrites the tree it runs in. On 2026-11-09 this file
    ran it in the real worktree: it linked a path in a doc after the ratchets
    had passed, the code-link count moved from 825 to 826, and the commit hook
    failed 507 s later on a tree the gates had already passed."""
    real_run = subprocess.run
    seen = []

    def spy(argv, **kw):
        if argv[0] == "bash":
            seen.append((argv[1], kw.get("cwd")))
            return subprocess.CompletedProcess(argv, 0, "Nothing to fix", "")
        return real_run(argv, **kw)

    monkeypatch.setattr(subprocess, "run", spy)
    run()
    assert seen, "run() did not run the sweep"
    script, cwd = seen[0]
    assert pathlib.Path(cwd).resolve() != REPO
    assert not pathlib.Path(script).resolve().is_relative_to(REPO)


def test_every_fixer_the_gate_relies_on_is_in_the_sweep():
    """A fixer the sweep forgets is one somebody discovers from a failed
    commit. The list is checked against the scripts that exist rather than
    trusted, because adding a fixer and forgetting the sweep is exactly how
    this gap reopens."""
    body = SWEEP.read_text()
    for fixer in ("check-line-drift.py", "link-repo-paths.py",
                  "build-site-pages.py", "backlog-status.py"):
        assert fixer in body, f"{fixer} is not run by the sweep"


def test_a_clean_tree_reports_nothing_to_fix():
    """The sweep runs against a tree that is already correct, so it must say
    so plainly. A script that always prints work invites being ignored."""
    out = run()
    assert out.returncode == 0, out.stdout[-500:]
    assert "Nothing to fix" in out.stdout or "changed" in out.stdout


def test_it_stages_nothing():
    """Deciding what belongs in a commit is not a script's job. A sweep that
    staged its own edits would quietly enlarge every commit it touched."""
    before = subprocess.run(["git", "diff", "--cached", "--name-only"],
                            capture_output=True, text=True, cwd=checkout()).stdout
    run()
    after = subprocess.run(["git", "diff", "--cached", "--name-only"],
                           capture_output=True, text=True, cwd=checkout()).stdout
    assert before == after, "the sweep changed the index"
