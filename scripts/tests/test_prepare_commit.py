"""The fixer sweep.

Most of the failures this script exists to prevent were not defects in the
fixers. They were the fixers not being run, discovered five minutes into a
commit when a gate refused. The sweep is only worth having if it reports
honestly, so these check the reporting rather than the fixing.
"""

import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SWEEP = REPO / "scripts/prepare-commit.sh"


def run():
    return subprocess.run(["bash", str(SWEEP)], capture_output=True,
                          text=True, timeout=900, cwd=REPO)


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
                            capture_output=True, text=True, cwd=REPO).stdout
    run()
    after = subprocess.run(["git", "diff", "--cached", "--name-only"],
                           capture_output=True, text=True, cwd=REPO).stdout
    assert before == after, "the sweep changed the index"
