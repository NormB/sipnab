# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/release-train.py: a job no hosted runner took is still pending.

RELEASE-TRAIN-STOPS-ON-NOT-ACQUIRED. The 0.5.262 train stopped at ci-failed
twice, and the 0.5.263 train once at 18:43Z, because a macOS job of the
release pull request's CI was canceled with "The job was not acquired by
Runner of type hosted even after multiple attempts". When that run completed,
.github/workflows/rerun-not-acquired.yml re-ran the job, as it was written to
do, but the train had already stopped and a person restarted it each time.

The train counted every canceled check as failed. It now asks the re-run
script's own rule (`rerun_coming` in scripts/rerun-not-acquired.py, the rule
that script applies through `decide`) whether the job will be re-run, and
counts such a job as pending while its run is in progress and for
`rerun_grace_s` after it completed. A job the re-run workflow will not touch
(its third attempt, a job that ran a step, a cancel without the message, a
workflow it does not watch) is still failed, and so is one whose re-run did
not come within the grace: the wait is bounded.

The job in these tests is the one of 2026-11-17: job 134322727032 of run
44163342006, "Symbol split (aarch64-apple-darwin)", canceled at 20:13:38Z
with no steps.
"""

import json

import pytest
from conftest import load
from test_release_train import HEAD, MIN, T0, World, facts, iso

rt = load("release-train")
rr = load("rerun-not-acquired")

MESSAGE = "The job was not acquired by Runner of type hosted even after multiple attempts"
NOTICE = "Due to capacity constraints, jobs targeting macOS arm64 runners may experience longer queue times."
RUN_ID = 44163342006
JOB_ID = 134322727032
NAME = "Symbol split (aarch64-apple-darwin)"
URL = f"https://github.com/NormB/sipnab/actions/runs/{RUN_ID}/job/{JOB_ID}"


@pytest.fixture
def cfg(tmp_path):
    return rt.Config(version="0.5.242", host="releaser@vm.example.invalid", repo="NormB/sipnab",
                     state_file=tmp_path / "train.json")


# GitHub's own conclusion value for a job it gave up on, in the rollup's spelling.
GONE = "cancelled".upper()


def item(name=NAME, conclusion=GONE, url=URL, workflow="CI", status="COMPLETED"):
    """One check run of a statusCheckRollup, as `gh pr view` gives it."""
    c = {"__typename": "CheckRun", "name": name, "status": status, "conclusion": conclusion,
         "startedAt": iso(T0), "completedAt": iso(T0 + 20 * MIN), "workflowName": workflow}
    if url is not None:
        c["detailsUrl"] = url
    return c


def passed(name="Check (ubuntu-24.04)"):
    return item(name=name, conclusion="SUCCESS", url=None)


def job(attempt=1, steps=(), conclusion="cancelled", status="completed", job_id=JOB_ID):
    return {"id": job_id, "run_id": RUN_ID, "run_attempt": attempt, "workflow_name": "CI",
            "status": status, "conclusion": conclusion, "steps": list(steps), "name": NAME}


def gh_run(attempt=1, status="in_progress", conclusion=None, updated=T0 + 20 * MIN, name="CI"):
    r = {"id": RUN_ID, "name": name, "status": status, "conclusion": conclusion, "run_attempt": attempt}
    if updated is not None:
        r["updated_at"] = iso(updated)
    return r


def notes(*messages):
    return [{"path": ".github", "annotation_level": "failure", "message": m} for m in messages]


NOT_ACQUIRED = notes(MESSAGE, NOTICE, NOTICE)


def awaits(it=None, run_=None, job_=None, ann=None, now=T0 + 21 * MIN, grace=600):
    return rt.awaits_rerun(it or item(), run_ or gh_run(), job_ or job(),
                           NOT_ACQUIRED if ann is None else ann, now, grace)


class GhApi:
    """`gh api` answers for one run, one job and its annotations; every other
    command goes to `world`."""

    def __init__(self, world, run_=None, job_=None, ann=None, fail=None):
        self.world = world
        self.run = run_ or gh_run()
        self.job = job_ or job()
        self.ann = NOT_ACQUIRED if ann is None else ann
        self.fail = fail
        self.asked = []

    def __call__(self, argv, timeout):
        j = " ".join(argv)
        if argv[:2] == ["gh", "api"]:
            path = argv[2]
            for key, answer in ((f"actions/runs/{RUN_ID}", self.run), (f"actions/jobs/{JOB_ID}", self.job),
                                (f"check-runs/{JOB_ID}/annotations", self.ann)):
                if path.startswith(f"repos/NormB/sipnab/{key}"):
                    self.asked.append(key)
                    if self.fail == key:
                        return rt.Result(1, "gh: HTTP 502\n")
                    return rt.Result(0, json.dumps(answer))
        return self.world(argv, timeout)


def rollup_world(items):
    w = World()
    w.rollup = lambda: items
    return w


# ---------------------------------------------------------------------------
# Success: the job will be re-run, so the train waits for it
# ---------------------------------------------------------------------------


def test_success_the_0_5_263_job_awaits_a_rerun_while_its_run_is_in_progress():
    assert awaits() is True, "a not-acquired job of a running CI run is re-run when the run completes"


def test_success_a_completed_run_within_the_grace_awaits_its_rerun():
    run_ = gh_run(status="completed", conclusion="failure", updated=T0 + 20 * MIN)
    assert awaits(run_=run_, now=T0 + 25 * MIN) is True, "the re-run workflow starts within minutes"


def test_success_the_second_attempt_still_awaits_a_rerun():
    assert awaits(run_=gh_run(attempt=2), job_=job(attempt=2)) is True, "attempt 2 of 3 is re-run"


def test_success_a_release_run_awaits_a_rerun_too():
    assert awaits(it=item(workflow="Release"), run_=gh_run(name="Release")) is True, "Release is watched"


def test_success_the_facts_count_the_job_pending_not_failed(cfg):
    f = rt.read_facts(cfg, GhApi(rollup_world([item(), passed()])), T0 + 21 * MIN)
    assert f.failed == (), f"a job that will be re-run is not a failure: {f.failed}"
    assert f.pending == 1, f"it is pending: {f.pending}"


def test_success_the_stage_is_ci_wait_not_ci_failed(cfg):
    f = rt.read_facts(cfg, GhApi(rollup_world([item(), passed()])), T0 + 21 * MIN)
    assert rt.stage_of(f) == "ci-wait", rt.stage_of(f)


def test_success_the_facts_name_the_job_awaiting_a_rerun(cfg):
    f = rt.read_facts(cfg, GhApi(rollup_world([item(), passed()])), T0 + 21 * MIN)
    assert f.rerunning == (NAME,), f.rerunning


def test_success_a_job_awaiting_a_rerun_keeps_the_window_closed(cfg):
    f = rt.read_facts(cfg, GhApi(rollup_world([item(), passed()])), T0 + 21 * MIN)
    assert f.stuck >= 1, "a job no runner took waits for a runner, as a queued one does"
    assert rt.window_wanted("ci-wait", f.pending, 0, cfg, f.stuck, f.long_remaining) is False


def test_success_two_jobs_awaiting_a_rerun_are_both_pending(cfg):
    other = f"https://github.com/NormB/sipnab/actions/runs/{RUN_ID}/job/{JOB_ID + 1}"
    w = rollup_world([item(), item(name="Test (macos-26, shard 1)", url=other), passed()])
    api = GhApi(w)
    base = api.__call__

    def call(argv, timeout):
        if argv[:2] == ["gh", "api"] and f"/{JOB_ID + 1}" in argv[2]:
            body = job(job_id=JOB_ID + 1) if "actions/jobs" in argv[2] else NOT_ACQUIRED
            return rt.Result(0, json.dumps(body))
        return base(argv, timeout)

    f = rt.read_facts(cfg, call, T0 + 21 * MIN)
    assert f.failed == () and f.pending == 2, (f.failed, f.pending)
    assert set(f.rerunning) == {NAME, "Test (macos-26, shard 1)"}, f.rerunning
    assert api.asked.count(f"actions/runs/{RUN_ID}") == 1, f"one run is read once: {api.asked}"


def test_success_read_rollup_counts_a_named_rerun_as_pending():
    pending, failed, _ = rt.read_rollup([item(), passed()], rerunning={URL})
    assert (pending, failed) == (1, ()), (pending, failed)


def test_success_the_train_lands_after_the_rerun_passes(cfg):
    """The 0.5.263 morning, end to end: the job is canceled at minute 20, its
    run completes at 36, the re-run passes at 50, and the train lands."""
    w = World()
    extra = {"cancel_at": T0 + 20 * MIN, "run_done": T0 + 36 * MIN, "rerun_done": T0 + 50 * MIN}
    base_rollup = w.rollup

    def rollup():
        items = base_rollup()
        if w.now < extra["cancel_at"]:
            items.append(item(status="IN_PROGRESS", conclusion=""))
        elif w.now < extra["run_done"] + 60:
            items.append(item())
        elif w.now < extra["rerun_done"]:
            items.append(item(status="IN_PROGRESS", conclusion="", url=URL + "0"))
        else:
            items.append(item(conclusion="SUCCESS", url=URL + "0"))
        return items

    w.rollup = rollup

    def run_state():
        done = w.now >= extra["run_done"]
        return gh_run(status="completed" if done else "in_progress", conclusion="failure" if done else None,
                      updated=extra["run_done"] if done else w.now)

    api = GhApi(w)

    def call(argv, timeout):
        api.run = run_state()
        return api(argv, timeout)

    out = rt.train(cfg, call, sleep=w.sleep, clock=w.clock)
    assert out == 0, "the train must wait for the re-run and land, not stop at ci-failed"
    assert "land" in w.names(), w.names()
    assert w.at("land")[0] >= extra["rerun_done"], "it landed only after the re-run passed"


def test_success_the_train_says_once_which_job_awaits_a_rerun(cfg, capsys):
    w = rollup_world([item(), passed()])
    api = GhApi(w)
    for _ in range(3):
        rt.tick(cfg, api, w.clock, w.sleep)
        w.now += 30
    out = capsys.readouterr().out
    assert out.count(f"awaits a re-run: {NAME}") == 1, out


# ---------------------------------------------------------------------------
# Failure: no re-run will come, so the cancel is a failure
# ---------------------------------------------------------------------------


def test_failure_the_third_attempt_is_failed():
    assert awaits(run_=gh_run(attempt=3), job_=job(attempt=3)) is False, "the re-run script stops at 3"


def test_failure_a_job_that_ran_a_step_is_failed():
    steps = [{"name": "Set up job", "status": "completed", "conclusion": "success", "number": 1}]
    assert awaits(job_=job(steps=steps)) is False, "a runner lost mid-job is left to a person"


def test_failure_a_cancel_without_the_message_is_failed():
    assert awaits(ann=notes(NOTICE)) is False, "a person's cancel carries no such annotation"


def test_failure_a_cancel_with_no_annotations_is_failed():
    assert awaits(ann=[]) is False, "no annotation, no re-run"


def test_failure_a_workflow_the_rerun_does_not_watch_is_failed():
    assert awaits(it=item(workflow="CodeQL")) is False, "rerun-not-acquired.yml watches CI and Release only"


def test_failure_a_completed_run_past_the_grace_is_failed():
    run_ = gh_run(status="completed", conclusion="failure", updated=T0 + 20 * MIN)
    assert awaits(run_=run_, now=T0 + 20 * MIN + 601) is False, "the wait for a re-run is bounded"


def test_failure_a_job_of_an_earlier_attempt_is_failed():
    assert awaits(run_=gh_run(attempt=2), job_=job(attempt=1)) is False, "the run moved on without it"


def test_failure_a_failed_job_is_never_a_rerun_candidate(cfg):
    w = rollup_world([item(conclusion="FAILURE"), passed()])
    api = GhApi(w)
    f = rt.read_facts(cfg, api, T0 + 21 * MIN)
    assert f.failed == (NAME,), f.failed
    assert api.asked == [], f"a failure costs no extra reads: {api.asked}"


def test_failure_a_timed_out_job_is_never_a_rerun_candidate(cfg):
    w = rollup_world([item(conclusion="TIMED_OUT"), passed()])
    f = rt.read_facts(cfg, GhApi(w), T0 + 21 * MIN)
    assert f.failed == (NAME,), f.failed


def test_failure_a_real_failure_beside_a_not_acquired_job_stops_the_train(cfg):
    w = rollup_world([item(), item(name="Test (ubuntu-24.04, shard 1)", conclusion="FAILURE", url=None)])
    f = rt.read_facts(cfg, GhApi(w), T0 + 21 * MIN)
    assert rt.stage_of(f) == "ci-failed", rt.stage_of(f)
    assert f.failed == ("Test (ubuntu-24.04, shard 1)",), f.failed


def test_failure_a_check_without_a_job_link_is_failed(cfg):
    w = rollup_world([item(url=None), passed()])
    api = GhApi(w)
    f = rt.read_facts(cfg, api, T0 + 21 * MIN)
    assert f.failed == (NAME,) and api.asked == [], (f.failed, api.asked)


def test_failure_a_link_that_is_not_an_actions_job_is_failed(cfg):
    w = rollup_world([item(url="https://app.example.com/scan/261644099"), passed()])
    api = GhApi(w)
    f = rt.read_facts(cfg, api, T0 + 21 * MIN)
    assert f.failed == (NAME,) and api.asked == [], (f.failed, api.asked)


def test_failure_a_commit_status_is_never_a_rerun_candidate(cfg):
    w = rollup_world([{"context": "license/cla", "state": "FAILURE", "startedAt": iso(T0)}])
    api = GhApi(w)
    f = rt.read_facts(cfg, api, T0 + 21 * MIN)
    assert f.failed == ("license/cla",) and api.asked == [], (f.failed, api.asked)


@pytest.mark.parametrize("key", [f"actions/runs/{RUN_ID}", f"actions/jobs/{JOB_ID}",
                                 f"check-runs/{JOB_ID}/annotations"])
def test_failure_a_read_that_fails_is_a_read_error_not_a_guess(cfg, key):
    w = rollup_world([item(), passed()])
    with pytest.raises(rt.ReadError):
        rt.read_facts(cfg, GhApi(w, fail=key), T0 + 21 * MIN)


def test_failure_the_train_stops_when_the_rerun_never_comes(cfg):
    w = rollup_world([item(), passed()])
    run_ = gh_run(status="completed", conclusion="failure", updated=T0)
    out = rt.train(cfg, GhApi(w, run_=run_), sleep=w.sleep, clock=w.clock)
    assert out == 1, "past the grace the train stops at ci-failed"
    assert w.now - T0 <= 600 + 2 * cfg.poll, f"it waited {w.now - T0} s, longer than the grace"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


JOB_URLS = [
    (URL, (RUN_ID, JOB_ID)),
    (URL + "?pr=838", (RUN_ID, JOB_ID)),
    (URL + "#step:1:1", (RUN_ID, JOB_ID)),
    (URL + "/", (RUN_ID, JOB_ID)),
    (f"https://github.com/NormB/sipnab/actions/runs/{RUN_ID}", None),
    (f"https://github.com/NormB/sipnab/actions/runs/x/job/{JOB_ID}", None),
    (URL + "x", None),
    ("", None),
    (None, None),
    ("https://app.example.com/featurebranch/scan/261644099?groupId=125678", None),
]


@pytest.mark.parametrize("url,want", JOB_URLS)
def test_edge_job_ids_reads_the_run_and_job_from_the_link(url, want):
    c = item(url=url)
    assert rt.job_ids(c) == want, (url, rt.job_ids(c))


def test_edge_a_completed_run_exactly_at_the_grace_awaits_its_rerun():
    run_ = gh_run(status="completed", conclusion="failure", updated=T0 + 20 * MIN)
    assert awaits(run_=run_, now=T0 + 20 * MIN + 600) is True, "the grace includes its last second"


def test_edge_a_completion_after_the_local_clock_is_within_the_grace():
    run_ = gh_run(status="completed", conclusion="failure", updated=T0 + 20 * MIN + 5)
    assert awaits(run_=run_, now=T0 + 20 * MIN) is True, "a clock a few seconds behind GitHub's"


def test_edge_a_completed_run_with_no_update_time_is_failed():
    run_ = gh_run(status="completed", conclusion="failure", updated=None)
    assert awaits(run_=run_) is False, "the grace cannot be judged, so no wait"


def test_edge_without_a_clock_a_completed_run_is_failed():
    run_ = gh_run(status="completed", conclusion="failure")
    assert awaits(run_=run_, now=None) is False, "the grace cannot be judged without a clock"


def test_edge_without_a_clock_a_running_run_awaits_its_rerun():
    assert awaits(now=None) is True, "an in-progress run has not reached the re-run workflow"


def test_edge_a_lowercase_conclusion_is_read_as_github_spells_it():
    assert rt.rerun_candidate(item(conclusion="cancelled")) is True, "conclusions compare in lowercase"


def test_edge_a_pending_check_is_never_a_rerun_candidate():
    assert rt.rerun_candidate(item(status="IN_PROGRESS", conclusion="")) is False


def test_edge_a_check_with_no_workflow_name_is_not_a_candidate():
    c = item()
    del c["workflowName"]
    assert rt.rerun_candidate(c) is False, "the watched workflows are named; an unnamed one is not"


def test_edge_facts_built_without_reruns_have_none():
    assert facts().rerunning == (), facts().rerunning


def test_edge_a_green_rollup_costs_no_extra_reads(cfg):
    w = World()
    api = GhApi(w)
    rt.read_facts(cfg, api, T0 + 30)
    assert api.asked == [], api.asked


def test_edge_a_merged_pull_request_reads_no_jobs(cfg):
    w = rollup_world([item()])
    w.pr["state"] = "MERGED"
    w.pr["mergeCommit"] = {"oid": "b" * 40}
    api = GhApi(w)
    f = rt.read_facts(cfg, api, T0 + 21 * MIN)
    assert api.asked == [] and f.rerunning == (), (api.asked, f.rerunning)


def test_edge_the_grace_is_a_setting_of_the_train(cfg):
    assert cfg.rerun_grace_s == 600, cfg.rerun_grace_s
    run_ = gh_run(status="completed", conclusion="failure", updated=T0)
    cfg.rerun_grace_s = 60
    w = rollup_world([item(), passed()])
    f = rt.read_facts(cfg, GhApi(w, run_=run_), T0 + 61)
    assert f.failed == (NAME,), "the configured grace decides"


# ---------------------------------------------------------------------------
# One rule: the train asks the re-run script, and both agree
# ---------------------------------------------------------------------------


AGREE = [
    ("the 0.5.263 job", 1, (), NOT_ACQUIRED, True),
    ("attempt 2", 2, (), NOT_ACQUIRED, True),
    ("attempt 3", 3, (), NOT_ACQUIRED, False),
    ("a step ran", 1, ({"name": "Set up job", "number": 1},), NOT_ACQUIRED, False),
    ("no message", 1, (), notes(NOTICE), False),
    ("message with spaces around it", 1, (), notes(f"  {MESSAGE}  "), True),
]


@pytest.mark.parametrize("kind,attempt,steps,ann,want", AGREE, ids=[a[0] for a in AGREE])
def test_edge_the_train_and_the_rerun_script_agree(kind, attempt, steps, ann, want):
    """`decide` on the completed run, with this one job, and the train's
    reading of the same job must give the same answer."""
    j = job(attempt=attempt, steps=steps)
    done = gh_run(attempt=attempt, status="completed", conclusion="failure")
    verdict, reason = rr.decide(done, [j], {JOB_ID: ann})
    assert (verdict == "rerun") is want, f"{kind}: decide said {verdict}: {reason}"
    assert awaits(run_=done, job_=j, ann=ann, now=T0 + 21 * MIN) is want, f"{kind}: the train disagrees"


def test_edge_the_train_reads_the_watched_workflows_from_the_rerun_script():
    assert rt._rerun.WORKFLOWS == rr.WORKFLOWS, "one list of watched workflows"
    assert rt._rerun.MAX_ATTEMPTS == rr.MAX_ATTEMPTS, "one limit of attempts"


def test_edge_the_head_the_train_lands_is_unchanged_by_a_rerun(cfg):
    f = rt.read_facts(cfg, GhApi(rollup_world([item(), passed()])), T0 + 21 * MIN)
    assert f.head == HEAD, f.head
