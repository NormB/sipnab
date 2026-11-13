# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""A job that no hosted runner took is re-run; any other failure is left.

scripts/rerun-not-acquired.py decides, from the jobs and annotations GitHub
reports for one attempt of a workflow run, whether the run failed only because
jobs never started. .github/workflows/rerun-not-acquired.yml asks it when a CI
or Release run completes.

GitHub's API is not reachable from a test, and a real run must not be
canceled to make one. The decision is a pure function, tested against two
captured responses (tests/fixtures/rerun_not_acquired: the first attempt of
the Release run for v0.5.249 and the annotations of its job that never
started) and against responses built here in the same shape. The command is
tested with `gh` replaced by a stub on PATH that answers from files.
"""

import copy
import json
import os
import pathlib
import re
import stat
import subprocess
import sys

import pytest

from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/rerun-not-acquired.py"
WORKFLOW = REPO / ".github/workflows/rerun-not-acquired.yml"
FIXTURES = REPO / "tests/fixtures/rerun_not_acquired"

rerun = load("rerun-not-acquired")

MESSAGE = "The job was not acquired by Runner of type hosted even after multiple attempts"
NOTICE = (
    "Due to capacity constraints, jobs targeting macOS arm64 runners may "
    "experience longer queue times."
)


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def run(conclusion="failure", attempt=1, status="completed"):
    return {
        "id": 500,
        "name": "CI",
        "event": "push",
        "status": status,
        "conclusion": conclusion,
        "run_attempt": attempt,
    }


def step(number=1, conclusion="success"):
    return {"name": f"step {number}", "status": "completed", "conclusion": conclusion, "number": number}


def job(job_id, conclusion="success", steps=3, status="completed", name=None):
    return {
        "id": job_id,
        "name": name or f"job {job_id}",
        "status": status,
        "conclusion": conclusion,
        "steps": [step(n + 1) for n in range(steps)] if isinstance(steps, int) else steps,
    }


def never_ran(job_id, name=None):
    return job(job_id, conclusion="cancelled", steps=0, name=name)


def annotation(message=MESSAGE, level="failure"):
    return {"path": ".github", "annotation_level": level, "title": "", "message": message}


def acquired_never(*job_ids):
    """Annotations as GitHub gives them for jobs no runner took."""
    return {i: [annotation(), annotation(NOTICE, "notice")] for i in job_ids}


def action(run_, jobs, annotations, **kw):
    return rerun.decide(run_, jobs, annotations, **kw)[0]


# ---------------------------------------------------------------------------
# Success: the run failed only because jobs never started.
# ---------------------------------------------------------------------------


def test_the_captured_release_run_is_rerun():
    jobs = fixture("release_run_attempt_1_jobs.json")["jobs"]
    never = [j for j in jobs if j["conclusion"] == "cancelled"]
    assert [j["name"] for j in never] == ["Build (x86_64-apple-darwin)"]
    annotations = {never[0]["id"]: fixture("not_acquired_annotations.json")}
    verdict, reason = rerun.decide(fixture("release_run_attempt_1.json"), jobs, annotations)
    assert verdict == "rerun", reason
    assert "Build (x86_64-apple-darwin)" in reason


def test_the_captured_job_never_started():
    jobs = fixture("release_run_attempt_1_jobs.json")["jobs"]
    never = next(j for j in jobs if j["conclusion"] == "cancelled")
    assert rerun.never_started(never, fixture("not_acquired_annotations.json")) is True


def test_the_captured_annotations_hold_the_message_the_script_looks_for():
    messages = [a["message"] for a in fixture("not_acquired_annotations.json")]
    assert rerun.NOT_ACQUIRED in messages
    assert rerun.NOT_ACQUIRED == MESSAGE


def test_one_job_no_runner_took_among_successes_is_rerun():
    jobs = [job(1), job(2), never_ran(3), job(4)]
    assert action(run(), jobs, acquired_never(3)) == "rerun"


def test_the_second_attempt_is_rerun_too():
    jobs = [job(1), never_ran(3)]
    assert action(run(attempt=2), jobs, acquired_never(3)) == "rerun"


def test_two_jobs_no_runner_took_are_rerun():
    jobs = [job(1), never_ran(3, "Check (macos-latest)"), never_ran(4, "Symbol split")]
    verdict, reason = rerun.decide(run(), jobs, acquired_never(3, 4))
    assert verdict == "rerun"
    assert "Check (macos-latest)" in reason and "Symbol split" in reason


def test_jobs_skipped_because_their_need_never_started_do_not_block():
    jobs = [job(1), never_ran(3), job(5, "skipped", 0), job(6, "skipped", 0)]
    assert action(run(), jobs, acquired_never(3)) == "rerun"


def test_the_message_is_found_after_the_notices():
    notes = {3: [annotation(NOTICE, "notice"), annotation(NOTICE, "notice"), annotation()]}
    assert action(run(), [job(1), never_ran(3)], notes) == "rerun"


def test_a_run_github_concluded_canceled_is_rerun_when_its_jobs_never_started():
    assert action(run("cancelled"), [job(1), never_ran(3)], acquired_never(3)) == "rerun"


def test_a_run_of_one_job_that_never_started_is_rerun():
    assert action(run(), [never_ran(3)], acquired_never(3)) == "rerun"


def test_annotations_keyed_by_the_job_id_as_text_are_found():
    assert action(run(), [job(1), never_ran(3)], {"3": [annotation()]}) == "rerun"


def test_whitespace_around_the_message_is_not_a_different_message():
    notes = {3: [annotation("  " + MESSAGE + "\n")]}
    assert action(run(), [job(1), never_ran(3)], notes) == "rerun"


@pytest.mark.parametrize("attempt", [1, 2])
def test_every_attempt_below_the_limit_is_rerun(attempt):
    assert attempt < rerun.MAX_ATTEMPTS
    assert action(run(attempt=attempt), [never_ran(3)], acquired_never(3)) == "rerun"


def test_the_limit_is_three_attempts():
    assert rerun.MAX_ATTEMPTS == 3


# ---------------------------------------------------------------------------
# Failure: something ran, or nothing shows that no runner took the job.
# ---------------------------------------------------------------------------


def test_a_job_that_failed_beside_one_that_never_started_blocks_the_rerun():
    jobs = [job(1), job(2, "failure", 4), never_ran(3)]
    verdict, reason = rerun.decide(run(), jobs, acquired_never(3))
    assert verdict == "leave"
    assert "job 2" in reason


def test_a_canceled_job_that_ran_a_step_is_left():
    jobs = [job(1), job(3, "cancelled", 1)]
    assert action(run(), jobs, acquired_never(3)) == "leave"


def test_a_canceled_job_without_the_annotation_is_left():
    # What a person's "Cancel run" leaves for a job still in the queue.
    assert action(run("cancelled"), [job(1), never_ran(3)], {3: []}) == "leave"


def test_a_canceled_job_with_only_the_capacity_notice_is_left():
    notes = {3: [annotation(NOTICE, "notice")]}
    assert action(run(), [job(1), never_ran(3)], notes) == "leave"


def test_a_canceled_job_with_no_annotations_entry_is_left():
    assert action(run(), [job(1), never_ran(3)], {}) == "leave"


def test_the_third_attempt_is_left():
    verdict, reason = rerun.decide(run(attempt=3), [never_ran(3)], acquired_never(3))
    assert verdict == "leave"
    assert "attempt 3" in reason


def test_a_fourth_attempt_is_left():
    assert action(run(attempt=4), [never_ran(3)], acquired_never(3)) == "leave"


def test_a_successful_run_is_left():
    assert action(run("success"), [job(1), job(2)], {}) == "leave"


def test_a_run_that_has_not_completed_is_left():
    assert action(run(None, status="in_progress"), [never_ran(3)], acquired_never(3)) == "leave"


@pytest.mark.parametrize("status", ["queued", "in_progress", "requested", "waiting", "pending", None])
def test_a_run_whose_status_is_not_completed_is_left_whatever_its_conclusion(status):
    verdict, reason = rerun.decide(run("failure", status=status), [never_ran(3)], acquired_never(3))
    assert verdict == "leave"
    assert "not completed" in reason


def test_one_job_canceled_after_it_started_blocks_the_others():
    jobs = [never_ran(3), job(4, "cancelled", 2)]
    assert action(run("cancelled"), jobs, acquired_never(3, 4)) == "leave"


def test_a_timed_out_job_blocks_the_rerun():
    jobs = [job(2, "timed_out", 6), never_ran(3)]
    assert action(run(), jobs, acquired_never(3)) == "leave"


def test_a_self_hosted_runner_that_did_not_take_the_job_is_left():
    other = MESSAGE.replace("type hosted", "type self-hosted")
    assert action(run(), [never_ran(3)], {3: [annotation(other)]}) == "leave"


def test_a_run_with_no_jobs_is_left():
    verdict, reason = rerun.decide(run(), [], {})
    assert verdict == "leave"
    assert "lists no jobs" in reason


def test_a_failed_run_whose_jobs_all_passed_or_were_skipped_is_left():
    jobs = [job(1), job(2, "skipped", 0)]
    assert action(run(), jobs, {}) == "leave"


def test_one_of_two_canceled_jobs_without_the_annotation_blocks_both():
    jobs = [never_ran(3), never_ran(4)]
    assert action(run("cancelled"), jobs, acquired_never(3)) == "leave"


@pytest.mark.parametrize(
    "conclusion",
    ["success", "timed_out", "startup_failure", "action_required", "neutral", "skipped", "stale", None],
)
def test_only_a_failed_or_canceled_run_is_considered(conclusion):
    assert action(run(conclusion), [never_ran(3)], acquired_never(3)) == "leave"


@pytest.mark.parametrize("conclusion", ["failure", "timed_out", "neutral", "action_required", "stale", None])
def test_a_job_with_zero_steps_and_another_conclusion_is_left(conclusion):
    jobs = [job(1), job(3, conclusion, 0)]
    assert action(run(), jobs, acquired_never(3)) == "leave"


# ---------------------------------------------------------------------------
# Edge cases.
# ---------------------------------------------------------------------------


def test_the_limit_counts_the_attempt_that_would_be_started():
    # Attempt 2 may start attempt 3; attempt 3 may not start a fourth.
    assert action(run(attempt=2), [never_ran(3)], acquired_never(3), max_attempts=3) == "rerun"
    assert action(run(attempt=3), [never_ran(3)], acquired_never(3), max_attempts=3) == "leave"


def test_a_limit_of_one_attempt_never_reruns():
    assert action(run(attempt=1), [never_ran(3)], acquired_never(3), max_attempts=1) == "leave"


@pytest.mark.parametrize("attempt", [None, "1", 0, -1, True, 1.0])
def test_an_attempt_number_that_is_not_a_positive_integer_is_left(attempt):
    assert action(run(attempt=attempt), [never_ran(3)], acquired_never(3)) == "leave"


def test_a_longer_message_that_contains_the_text_is_not_the_message():
    notes = {3: [annotation(MESSAGE + ". The step log follows.")]}
    assert action(run(), [never_ran(3)], notes) == "leave"


def test_the_message_in_the_title_and_not_the_message_field_is_left():
    note = annotation("")
    note["title"] = MESSAGE
    assert action(run(), [never_ran(3)], {3: [note]}) == "leave"


@pytest.mark.parametrize("notes", [None, "text", {"message": MESSAGE}, [None], [MESSAGE], [{"message": None}]])
def test_annotations_of_another_shape_are_left(notes):
    assert action(run(), [never_ran(3)], {3: notes}) == "leave"


def test_a_job_without_a_steps_list_is_not_taken_as_zero_steps():
    broken = never_ran(3)
    del broken["steps"]
    assert action(run(), [broken], acquired_never(3)) == "leave"
    broken["steps"] = None
    assert action(run(), [broken], acquired_never(3)) == "leave"


def test_a_canceled_job_whose_one_step_was_skipped_still_has_a_step():
    jobs = [job(3, "cancelled", [step(1, "skipped")])]
    assert action(run(), jobs, acquired_never(3)) == "leave"


def test_a_skipped_job_that_lists_steps_is_left():
    jobs = [never_ran(3), job(5, "skipped", 2)]
    assert action(run(), jobs, acquired_never(3)) == "leave"


def test_a_job_without_an_id_is_left():
    nameless = never_ran(3)
    del nameless["id"]
    assert action(run(), [nameless], acquired_never(3)) == "leave"


def test_a_job_still_queued_in_a_completed_run_is_left():
    jobs = [job(3, None, 0, status="queued")]
    assert action(run(), jobs, acquired_never(3)) == "leave"


def test_a_canceled_job_that_is_not_completed_is_left():
    jobs = [job(3, "cancelled", 0, status="in_progress")]
    assert action(run(), jobs, acquired_never(3)) == "leave"


@pytest.mark.parametrize("jobs", [None, "jobs", [None], ["job"], [[]]])
def test_jobs_of_another_shape_are_left(jobs):
    assert action(run(), jobs, {}) == "leave"


@pytest.mark.parametrize("run_", [None, [], "run", {}])
def test_a_run_of_another_shape_is_left(run_):
    assert action(run_, [never_ran(3)], acquired_never(3)) == "leave"


def test_the_decision_does_not_change_what_it_is_given():
    jobs = [job(1), never_ran(3)]
    notes = acquired_never(3)
    before = copy.deepcopy((jobs, notes))
    rerun.decide(run(), jobs, notes)
    assert (jobs, notes) == before


def test_the_annotation_of_one_job_does_not_cover_another():
    jobs = [never_ran(3), never_ran(33)]
    assert action(run(), jobs, {3: [annotation()], 33: []}) == "leave"


def test_every_job_name_that_blocks_is_in_the_reason():
    jobs = [job(2, "failure", 4, name="Clippy"), job(4, "cancelled", 2, name="Test"), never_ran(3)]
    reason = rerun.decide(run(), jobs, acquired_never(3))[1]
    assert "Clippy" in reason and "Test" in reason


# ---------------------------------------------------------------------------
# The command, with `gh` answered from files.
# ---------------------------------------------------------------------------


def _stub_gh(tmp_path, run_, pages, annotations):
    """A `gh` that answers the run, jobs and annotations reads from files.

    `pages` is the list of jobs pages. A file named `fail` holds a text;
    a call whose arguments contain it exits 1.
    """
    (tmp_path / "run.json").write_text(json.dumps(run_))
    for n, page in enumerate(pages, start=1):
        (tmp_path / f"jobs_{n}.json").write_text(json.dumps(page))
    for job_id, notes in annotations.items():
        (tmp_path / f"annotations_{job_id}.json").write_text(json.dumps(notes))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    gh = bindir / "gh"
    gh.write_text(
        f"""#!{sys.executable}
import pathlib, re, sys
d = pathlib.Path({str(tmp_path)!r})
a = sys.argv[1:]
line = " ".join(a)
(d / "calls.log").open("a").write(line + "\\n")
fail = d / "fail"
if fail.exists() and fail.read_text() in line:
    sys.stderr.write("HTTP 502: stub failure\\n")
    sys.exit(1)
if a[0] != "api":
    sys.exit("unexpected gh call: " + line)
if a[1:3] == ["-X", "POST"]:
    if not a[3].endswith("/rerun-failed-jobs"):
        sys.exit("unexpected POST: " + line)
    # GitHub answers 201 with no body.
    sys.exit(0)
path = a[1]
m = re.search(r"/attempts/(\\d+)/jobs\\?per_page=100&page=(\\d+)$", path)
n = re.search(r"/check-runs/(\\d+)/annotations\\?per_page=100&page=(\\d+)$", path)
if m:
    page = d / f"jobs_{{m.group(2)}}.json"
    print(page.read_text() if page.exists() else '{{"total_count": 0, "jobs": []}}')
elif n:
    notes = d / f"annotations_{{n.group(1)}}.json"
    print(notes.read_text() if notes.exists() and n.group(2) == "1" else "[]")
elif re.search(r"/actions/runs/\\d+$", path):
    print((d / "run.json").read_text())
else:
    sys.exit("unexpected gh call: " + line)
"""
    )
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
    return bindir


def _page(jobs, total=None):
    return {"total_count": len(jobs) if total is None else total, "jobs": jobs}


def _cli(tmp_path, bindir, *args):
    env = dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}")
    env.pop("GITHUB_OUTPUT", None)
    out = subprocess.run(
        [sys.executable, str(SCRIPT), "--repo", "example/project", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    log = tmp_path / "calls.log"
    calls = log.read_text().splitlines() if log.exists() else []
    return out, calls


def _posts(calls):
    return [c for c in calls if "POST" in c]


def test_the_command_reruns_the_failed_jobs_once_when_told_to_apply(tmp_path):
    bindir = _stub_gh(tmp_path, run(), [_page([job(1), never_ran(3)])], acquired_never(3))
    out, calls = _cli(tmp_path, bindir, "--run-id", "500", "--attempt", "1", "--apply")
    assert out.returncode == 0, out.stderr
    assert _posts(calls) == ["api -X POST repos/example/project/actions/runs/500/rerun-failed-jobs"]
    assert "decision: rerun" in out.stdout


def test_the_command_without_apply_changes_nothing(tmp_path):
    bindir = _stub_gh(tmp_path, run(), [_page([job(1), never_ran(3)])], acquired_never(3))
    out, calls = _cli(tmp_path, bindir, "--run-id", "500", "--attempt", "1")
    assert out.returncode == 0, out.stderr
    assert _posts(calls) == []
    assert "decision: rerun" in out.stdout
    assert "not applied" in out.stdout


def test_the_command_leaves_a_run_with_a_real_failure(tmp_path):
    jobs = [job(2, "failure", 4), never_ran(3)]
    bindir = _stub_gh(tmp_path, run(), [_page(jobs)], acquired_never(3))
    out, calls = _cli(tmp_path, bindir, "--run-id", "500", "--attempt", "1", "--apply")
    assert out.returncode == 0, out.stderr
    assert _posts(calls) == []
    assert "decision: leave" in out.stdout


def test_the_command_reads_every_page_of_jobs(tmp_path):
    first = [job(n) for n in range(1, 101)]
    second = [job(n) for n in range(101, 150)] + [never_ran(900)]
    pages = [_page(first, 150), _page(second, 150)]
    bindir = _stub_gh(tmp_path, run(), pages, acquired_never(900))
    out, calls = _cli(tmp_path, bindir, "--run-id", "500", "--attempt", "1", "--apply")
    assert out.returncode == 0, out.stderr
    assert len(_posts(calls)) == 1
    assert any("page=2" in c for c in calls)


def test_a_failure_on_the_second_page_is_seen(tmp_path):
    first = [job(n) for n in range(1, 100)] + [never_ran(900)]
    second = [job(101, "failure", 3)]
    pages = [_page(first, 101), _page(second, 101)]
    bindir = _stub_gh(tmp_path, run(), pages, acquired_never(900))
    out, calls = _cli(tmp_path, bindir, "--run-id", "500", "--attempt", "1", "--apply")
    assert out.returncode == 0, out.stderr
    assert _posts(calls) == []
    assert "decision: leave" in out.stdout


def test_fewer_jobs_than_github_counted_is_an_error(tmp_path):
    bindir = _stub_gh(tmp_path, run(), [_page([never_ran(3)], 7)], acquired_never(3))
    out, calls = _cli(tmp_path, bindir, "--run-id", "500", "--attempt", "1", "--apply")
    assert out.returncode == 1
    assert _posts(calls) == []
    assert "7" in out.stderr


def test_annotations_are_read_only_for_canceled_jobs_with_no_steps(tmp_path):
    jobs = [job(1), job(2, "skipped", 0), never_ran(3)]
    bindir = _stub_gh(tmp_path, run(), [_page(jobs)], acquired_never(3))
    _, calls = _cli(tmp_path, bindir, "--run-id", "500", "--attempt", "1")
    read = [c for c in calls if "/annotations" in c]
    assert read == ["api repos/example/project/check-runs/3/annotations?per_page=100&page=1"]


def test_the_command_reads_the_jobs_of_the_attempt_it_was_given(tmp_path):
    bindir = _stub_gh(tmp_path, run(attempt=2), [_page([never_ran(3)])], acquired_never(3))
    out, calls = _cli(tmp_path, bindir, "--run-id", "500", "--attempt", "2", "--apply")
    assert out.returncode == 0, out.stderr
    assert any("/actions/runs/500/attempts/2/jobs?" in c for c in calls)
    assert len(_posts(calls)) == 1


def test_a_run_that_moved_on_to_a_later_attempt_is_left(tmp_path):
    # The event names attempt 1; by the time it is handled, attempt 2 exists.
    bindir = _stub_gh(tmp_path, run(attempt=2), [_page([never_ran(3)])], acquired_never(3))
    out, calls = _cli(tmp_path, bindir, "--run-id", "500", "--attempt", "1", "--apply")
    assert out.returncode == 0, out.stderr
    assert _posts(calls) == []
    assert "decision: leave" in out.stdout
    assert "attempt 2" in out.stdout


def test_without_an_attempt_the_command_takes_the_runs_latest(tmp_path):
    bindir = _stub_gh(tmp_path, run(attempt=2), [_page([never_ran(3)])], acquired_never(3))
    out, calls = _cli(tmp_path, bindir, "--run-id", "500")
    assert out.returncode == 0, out.stderr
    assert any("/attempts/2/jobs?" in c for c in calls)
    assert "decision: rerun" in out.stdout


def test_the_third_attempt_is_left_before_any_job_is_read(tmp_path):
    bindir = _stub_gh(tmp_path, run(attempt=3), [_page([never_ran(3)])], acquired_never(3))
    out, calls = _cli(tmp_path, bindir, "--run-id", "500", "--attempt", "3", "--apply")
    assert out.returncode == 0, out.stderr
    assert _posts(calls) == []
    assert not any("/jobs?" in c for c in calls)
    assert "decision: leave" in out.stdout


@pytest.mark.parametrize("failing", ["/actions/runs/500 ", "/jobs?", "/annotations", "POST"])
def test_a_failed_api_call_is_an_error_and_not_a_decision(tmp_path, failing):
    bindir = _stub_gh(tmp_path, run(), [_page([never_ran(3)])], acquired_never(3))
    (tmp_path / "fail").write_text(failing.strip())
    out, calls = _cli(tmp_path, bindir, "--run-id", "500", "--attempt", "1", "--apply")
    assert out.returncode == 1
    assert "decision:" not in out.stdout or failing == "POST"
    assert "stub failure" in out.stderr
    if failing != "POST":
        assert _posts(calls) == []


@pytest.mark.parametrize(
    "args",
    [
        ["--run-id", "abc"],
        ["--run-id", "5;id"],
        ["--run-id", "-5"],
        ["--run-id", "500", "--attempt", "x"],
        ["--run-id", "500", "--attempt", "0"],
        [],
    ],
)
def test_arguments_that_are_not_numbers_are_refused(tmp_path, args):
    bindir = _stub_gh(tmp_path, run(), [_page([never_ran(3)])], acquired_never(3))
    out, calls = _cli(tmp_path, bindir, *args, "--apply")
    assert out.returncode == 2
    assert calls == []


@pytest.mark.parametrize("repo", ["project", "a/b/c", "a/b?x=1", "../b", "a b/c", ""])
def test_a_repository_that_is_not_owner_and_name_is_refused(tmp_path, repo):
    bindir = _stub_gh(tmp_path, run(), [_page([never_ran(3)])], acquired_never(3))
    env = dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}")
    out = subprocess.run(
        [sys.executable, str(SCRIPT), "--repo", repo, "--run-id", "500", "--apply"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert out.returncode == 2
    assert not (tmp_path / "calls.log").exists()


def test_the_captured_run_through_the_command(tmp_path):
    jobs = fixture("release_run_attempt_1_jobs.json")
    never = next(j for j in jobs["jobs"] if j["conclusion"] == "cancelled")
    notes = {never["id"]: fixture("not_acquired_annotations.json")}
    bindir = _stub_gh(tmp_path, fixture("release_run_attempt_1.json"), [jobs], notes)
    out, calls = _cli(tmp_path, bindir, "--run-id", "43270479515", "--attempt", "1", "--apply")
    assert out.returncode == 0, out.stderr
    assert len(_posts(calls)) == 1
    assert "Build (x86_64-apple-darwin)" in out.stdout


# ---------------------------------------------------------------------------
# The workflow that asks.
# ---------------------------------------------------------------------------


def _workflow():
    return WORKFLOW.read_text()


def _code(text):
    """The workflow without its comment lines."""
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def _workflow_name(path):
    first = (REPO / ".github/workflows" / path).read_text().splitlines()[0]
    assert first.startswith("name: ")
    return first[len("name: ") :].strip()


def test_the_workflow_watches_ci_and_release_by_the_names_they_carry():
    names = re.search(r"^    workflows: \[(.*)\]$", _code(_workflow()), re.M)
    assert names, "no `workflows:` list under workflow_run"
    watched = [n.strip().strip("'\"") for n in names.group(1).split(",")]
    assert watched == [_workflow_name("ci.yml"), _workflow_name("release.yml")]


def test_the_workflow_runs_when_a_watched_run_completes():
    code = _code(_workflow())
    assert re.search(r"^  workflow_run:\n    workflows: .*\n    types: \[completed\]$", code, re.M)


def test_the_workflow_grants_actions_write_to_its_one_job_and_nothing_else():
    code = _code(_workflow())
    assert re.search(r"^permissions: \{\}$", code, re.M), "the workflow-level grant is not empty"
    blocks = re.findall(r"^    permissions:\n((?:      .*\n)+)", code, re.M)
    assert blocks == ["      actions: write\n"]
    assert len(re.findall(r"^  [a-z][a-z0-9_-]*:$", code.split("\njobs:\n")[1], re.M)) == 1


def test_the_workflow_checks_out_the_default_branch_and_no_other_ref():
    code = _code(_workflow())
    assert "actions/checkout@" in code
    assert not re.search(r"^\s+ref:", code, re.M), "a ref would run code the event names"
    assert "persist-credentials: false" in code


def test_the_workflow_hands_event_values_to_the_shell_through_env_only():
    code = _code(_workflow())
    in_run = False
    indent = 0
    for line in code.splitlines():
        stripped = line.lstrip()
        here = len(line) - len(stripped)
        if in_run and stripped and here <= indent:
            in_run = False
        if in_run:
            assert "${{" not in line, f"an expression inside a run script: {line.strip()}"
        if stripped.startswith("run:"):
            in_run = True
            indent = here
            assert "${{" not in line, f"an expression inside a run script: {line.strip()}"


def test_the_workflows_first_filter_only_keeps_a_run_that_passed_out():
    # Which conclusions are looked into is RERUN_CONCLUSIONS in the script;
    # the workflow names none of them, so there is no second list to drift.
    code = _code(_workflow())
    assert re.findall(r"github\.event\.workflow_run\.conclusion (\S+ '[a-z_]+')", code) == [
        "!= 'success'"
    ]
    assert "success" not in rerun.RERUN_CONCLUSIONS


def test_the_workflow_states_no_attempt_limit_of_its_own():
    # The limit is MAX_ATTEMPTS in the script; a second copy here would drift.
    code = _code(_workflow())
    assert "run_attempt <" not in code and "run_attempt >" not in code
    assert "--max-attempts" not in code


def test_only_the_run_completed_event_applies_the_decision():
    code = _code(_workflow())
    assert code.count("--apply") == 1
    assert re.search(r'if \[ "\$EVENT_NAME" = workflow_run \]', code)


def test_the_workflow_runs_the_script_under_test():
    ran = re.findall(r"python3 (\S+)", _code(_workflow()))
    assert ran == ["scripts/rerun-not-acquired.py", "scripts/rerun-not-acquired.py"]
