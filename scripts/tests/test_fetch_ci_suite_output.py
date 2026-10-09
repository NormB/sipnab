"""pages.yml takes the suite output from CI's run of the same commit.

The site does not run the test suite itself: ci.yml's Check job on Linux
already runs it, and the published number must describe that run. The deploy
waits for the run's `suite-output` artifact, and refuses to publish when the
run finished without one, which is what a failed or skipped Test step leaves.

GitHub's API is not reachable from a test, so `gh` is replaced by a stub on
PATH that answers from files, and the decision is tested as a pure function.
"""

import json
import os
import pathlib
import stat
import subprocess
import sys

from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/fetch-ci-suite-output.py"

fetch = load("fetch-ci-suite-output")


def test_no_run_yet_means_wait():
    assert fetch.next_action(None, [])[0] == "wait"


def test_a_running_run_without_the_artifact_means_wait():
    run = {"id": 7, "status": "in_progress", "conclusion": None}
    assert fetch.next_action(run, [])[0] == "wait"


def test_the_artifact_present_means_download_even_before_the_run_ends():
    # The Check job uploads it; the rest of the run can still be going.
    run = {"id": 7, "status": "in_progress", "conclusion": None}
    assert fetch.next_action(run, ["suite-output"])[0] == "download"


def test_a_finished_run_without_the_artifact_means_fail():
    run = {"id": 7, "status": "completed", "conclusion": "failure"}
    action, reason = fetch.next_action(run, ["coverage"])
    assert action == "fail"
    assert "suite-output" in reason and "7" in reason


def _stub_gh(tmp_path, runs, artifacts):
    """A `gh` that answers the two API reads and a download from fixtures."""
    (tmp_path / "runs.json").write_text(json.dumps({"workflow_runs": runs}))
    (tmp_path / "artifacts.json").write_text(json.dumps({"artifacts": artifacts}))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    gh = bindir / "gh"
    gh.write_text(
        f"""#!{sys.executable}
import json, pathlib, sys
d = pathlib.Path({str(tmp_path)!r})
a = sys.argv[1:]
(d / "calls.log").open("a").write(" ".join(a) + "\\n")
if a[0] == "api" and "/actions/workflows/ci.yml/runs" in a[1]:
    print((d / "runs.json").read_text())
elif a[0] == "api" and a[1].endswith("/artifacts"):
    print((d / "artifacts.json").read_text())
elif a[:2] == ["run", "download"]:
    dest = pathlib.Path(a[a.index("-D") + 1])
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "test-output.txt").write_text("test result: ok. 5 passed; 0 failed;\\n")
else:
    sys.exit("unexpected gh call: " + " ".join(a))
"""
    )
    gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
    return bindir


def _run(tmp_path, bindir, *extra):
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            "o/r",
            "--sha",
            "abc123",
            "--dest",
            str(tmp_path / "out"),
            "--poll-secs",
            "0",
            *extra,
        ],
        capture_output=True,
        text=True,
        env=env,
    )


def test_downloads_the_artifact_of_the_run_for_this_commit(tmp_path):
    bindir = _stub_gh(
        tmp_path,
        [{"id": 42, "status": "completed", "conclusion": "success", "head_sha": "abc123"}],
        [{"name": "suite-output", "id": 9, "expired": False}],
    )
    res = _run(tmp_path, bindir)
    assert res.returncode == 0, res.stderr
    assert (tmp_path / "out" / "test-output.txt").exists()
    calls = (tmp_path / "calls.log").read_text()
    assert "head_sha=abc123" in calls and "event=push" in calls
    assert "run download 42" in calls and "-n suite-output" in calls


def test_a_finished_run_without_the_artifact_fails(tmp_path):
    bindir = _stub_gh(
        tmp_path,
        [{"id": 42, "status": "completed", "conclusion": "failure", "head_sha": "abc123"}],
        [],
    )
    res = _run(tmp_path, bindir)
    assert res.returncode != 0
    assert "finished without a suite-output artifact" in res.stderr
    assert not (tmp_path / "out").exists()


def test_an_expired_artifact_is_not_downloaded(tmp_path):
    bindir = _stub_gh(
        tmp_path,
        [{"id": 42, "status": "completed", "conclusion": "success", "head_sha": "abc123"}],
        [{"name": "suite-output", "id": 9, "expired": True}],
    )
    res = _run(tmp_path, bindir)
    assert res.returncode != 0
    assert "finished without a suite-output artifact" in res.stderr


def test_gives_up_at_the_deadline_while_the_run_is_still_going(tmp_path):
    bindir = _stub_gh(
        tmp_path,
        [{"id": 42, "status": "in_progress", "conclusion": None, "head_sha": "abc123"}],
        [],
    )
    res = _run(tmp_path, bindir, "--deadline-secs", "0")
    assert res.returncode != 0
    assert "deadline" in res.stderr
