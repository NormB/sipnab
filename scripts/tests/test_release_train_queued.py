# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/release-train.py: a check that waits for a runner is not nearly done.

RELEASE-TRAIN-WINDOW-QUEUED-JOB. On the 0.5.244 release the pull request's one
pending check was a re-run macOS job. It was queued from 15:39:23Z with no
runner, and GitHub canceled it at 15:55:06Z. The window rule counted it as one
of the last few checks, so the train held the release window open for those
minutes: the main slot was idle and two ordinary jobs waited behind the window.

A queued check has not started, so nothing says when it ends. The rule now
keeps the window closed while a check has been queued for longer than
`queued_grace_s`. A check that became ready a moment ago is queued for a few
seconds on an ordinary day, and that must not close a window the landing
needs, so a young queued check and one with no start time do not count.
"""

import pytest
from conftest import load
from test_release_train import MIN, T0, World, drive, facts, iso

rt = load("release-train")

# GitHub's own conclusion value for a job it gave up on, in its spelling.
GONE = "cancelled".upper()


@pytest.fixture
def cfg(tmp_path):
    return rt.Config(version="0.5.242", host="releaser@vm.example.invalid", repo="NormB/sipnab",
                     state_file=tmp_path / "train.json")


def queued(name="mac", since=T0, status="QUEUED"):
    return {"name": name, "status": status, "conclusion": "", "startedAt": iso(since)}


def running(name="linux", since=T0):
    return {"name": name, "status": "IN_PROGRESS", "conclusion": "", "startedAt": iso(since)}


def done(name="done", conclusion="SUCCESS"):
    return {"name": name, "status": "COMPLETED", "conclusion": conclusion, "startedAt": iso(T0)}


# ---------------------------------------------------------------------------
# stuck_queued: which checks wait for a runner
# ---------------------------------------------------------------------------


def test_success_a_check_queued_past_the_grace_is_stuck(cfg):
    assert rt.stuck_queued([queued(since=T0)], T0 + cfg.queued_grace_s, cfg.queued_grace_s) == 1


def test_success_the_0_5_244_job_is_stuck_twelve_minutes_in(cfg):
    assert rt.stuck_queued([queued(since=T0)], T0 + 12 * MIN, cfg.queued_grace_s) == 1


def test_success_every_stuck_check_is_counted(cfg):
    items = [queued("a"), queued("b"), running("c"), done("d")]
    assert rt.stuck_queued(items, T0 + 10 * MIN, cfg.queued_grace_s) == 2


@pytest.mark.parametrize("status", ["QUEUED", "WAITING", "REQUESTED", "PENDING"])
def test_success_every_status_before_a_runner_counts(cfg, status):
    assert rt.stuck_queued([queued(status=status)], T0 + 10 * MIN, cfg.queued_grace_s) == 1


def test_success_a_lowercase_status_counts(cfg):
    assert rt.stuck_queued([queued(status="queued")], T0 + 10 * MIN, cfg.queued_grace_s) == 1


def test_failure_a_running_check_is_not_stuck(cfg):
    assert rt.stuck_queued([running()], T0 + 60 * MIN, cfg.queued_grace_s) == 0


def test_failure_a_completed_check_is_not_stuck(cfg):
    assert rt.stuck_queued([done()], T0 + 60 * MIN, cfg.queued_grace_s) == 0


def test_failure_a_canceled_check_is_not_stuck(cfg):
    assert rt.stuck_queued([done(conclusion=GONE)], T0 + 60 * MIN, cfg.queued_grace_s) == 0


def test_failure_a_pending_commit_status_is_not_stuck(cfg):
    item = {"context": "license/cla", "state": "PENDING", "startedAt": iso(T0)}
    assert rt.stuck_queued([item], T0 + 60 * MIN, cfg.queued_grace_s) == 0


def test_failure_an_unknown_status_is_not_stuck(cfg):
    assert rt.stuck_queued([queued(status="BANANA")], T0 + 60 * MIN, cfg.queued_grace_s) == 0


def test_edge_a_check_queued_one_second_short_of_the_grace_is_not_stuck(cfg):
    assert rt.stuck_queued([queued(since=T0)], T0 + cfg.queued_grace_s - 1, cfg.queued_grace_s) == 0


def test_edge_a_queued_check_with_no_start_time_is_not_stuck(cfg):
    assert rt.stuck_queued([{"name": "a", "status": "QUEUED"}], T0 + 60 * MIN, cfg.queued_grace_s) == 0


def test_edge_a_queued_check_with_an_unreadable_start_time_is_not_stuck(cfg):
    item = {"name": "a", "status": "QUEUED", "startedAt": "soon"}
    assert rt.stuck_queued([item], T0 + 60 * MIN, cfg.queued_grace_s) == 0


def test_edge_githubs_zero_time_is_no_start_time(cfg):
    item = {"name": "a", "status": "QUEUED", "startedAt": "0001-01-01T00:00:00Z"}
    assert rt.stuck_queued([item], T0 + 60 * MIN, cfg.queued_grace_s) == 0


def test_edge_no_checks_means_none_stuck(cfg):
    assert rt.stuck_queued([], T0, cfg.queued_grace_s) == 0


def test_edge_a_missing_status_is_not_stuck(cfg):
    assert rt.stuck_queued([{"name": "a", "startedAt": iso(T0)}], T0 + 60 * MIN, cfg.queued_grace_s) == 0


def test_edge_a_start_time_after_now_is_not_stuck(cfg):
    assert rt.stuck_queued([queued(since=T0 + 5 * MIN)], T0, cfg.queued_grace_s) == 0


def test_edge_a_zero_grace_counts_a_check_queued_this_second():
    assert rt.stuck_queued([queued(since=T0)], T0, 0) == 1


# ---------------------------------------------------------------------------
# window_wanted: a stuck check keeps the window closed during CI
# ---------------------------------------------------------------------------


def test_success_the_last_few_checks_open_the_window_when_none_is_stuck(cfg):
    assert rt.window_wanted("ci-wait", 1, 30 * MIN, cfg, stuck=0)


def test_success_the_lead_time_opens_the_window_when_none_is_stuck(cfg):
    assert rt.window_wanted("ci-wait", 15, cfg.lead_s, cfg, stuck=0)


def test_success_the_stuck_count_defaults_to_none(cfg):
    assert rt.window_wanted("ci-wait", 1, 30 * MIN, cfg)


def test_failure_one_stuck_check_among_the_last_few_keeps_the_window_closed(cfg):
    assert not rt.window_wanted("ci-wait", 1, 30 * MIN, cfg, stuck=1)


def test_failure_a_stuck_check_keeps_the_window_closed_past_the_estimate(cfg):
    assert not rt.window_wanted("ci-wait", 1, 0, cfg, stuck=1)


def test_failure_several_stuck_checks_keep_the_window_closed(cfg):
    assert not rt.window_wanted("ci-wait", 3, 0, cfg, stuck=3)


@pytest.mark.parametrize("stage", ["land", "tag"])
def test_edge_a_local_step_keeps_the_window_whatever_is_queued(cfg, stage):
    assert rt.window_wanted(stage, 0, 0, cfg, stuck=2)


@pytest.mark.parametrize("stage", ["release-wait", "post", "done", "ci-failed", "no-pr"])
def test_edge_a_stage_with_no_window_has_none_with_a_stuck_check(cfg, stage):
    assert not rt.window_wanted(stage, 0, 0, cfg, stuck=1)


# ---------------------------------------------------------------------------
# The facts carry the count
# ---------------------------------------------------------------------------


class QueuedWorld(World):
    """A release whose last check is queued with no runner from `queued_from`
    until `runner_at`, then runs for `run_minutes`."""

    def __init__(self, queued_from, runner_at, run_minutes=5, **kw):
        super().__init__(**kw)
        self.queued_from = queued_from
        self.runner_at = runner_at
        self.mac_end = runner_at + run_minutes * MIN

    def rollup(self):
        items = super().rollup()
        if self.now >= self.mac_end:
            items.append({"name": "mac", "status": "COMPLETED", "conclusion": "SUCCESS",
                          "startedAt": iso(self.runner_at)})
        elif self.now >= self.runner_at:
            items.append({"name": "mac", "status": "IN_PROGRESS", "conclusion": "",
                          "startedAt": iso(self.runner_at)})
        else:
            items.append({"name": "mac", "status": "QUEUED", "conclusion": "",
                          "startedAt": iso(self.queued_from)})
        return items

    def window_open(self, t):
        """Whether the window was open at time `t`, from the log of changes."""
        state = False
        for when, what in self.window_log:
            if when > t:
                break
            state = what == "open"
        return state


def test_success_the_facts_count_a_stuck_check(cfg):
    w = QueuedWorld(queued_from=T0, runner_at=T0 + 60 * MIN)
    w.now = T0 + 10 * MIN
    assert rt.read_facts(cfg, w, w.now).stuck == 1


def test_success_the_facts_count_none_once_the_runner_took_the_job(cfg):
    w = QueuedWorld(queued_from=T0, runner_at=T0 + 5 * MIN)
    w.now = T0 + 6 * MIN
    assert rt.read_facts(cfg, w, w.now).stuck == 0


def test_edge_facts_built_without_a_count_have_none():
    assert facts().stuck == 0


def test_failure_a_merged_pull_request_has_no_stuck_checks(cfg):
    w = QueuedWorld(queued_from=T0, runner_at=T0 + 60 * MIN)
    w.pr["state"] = "MERGED"
    w.pr["mergeCommit"] = {"oid": "b" * 40}
    assert rt.read_facts(cfg, w, T0 + 30 * MIN).stuck == 0


# ---------------------------------------------------------------------------
# A whole release with a job that waits for a runner
# ---------------------------------------------------------------------------


def test_success_the_window_stays_closed_while_the_last_check_waits_for_a_runner(cfg):
    # The other checks end at 36 min; the macOS job gets a runner at 60 min.
    w = QueuedWorld(queued_from=T0 + 30, runner_at=T0 + 60 * MIN)
    assert drive(cfg, w) == 0
    for minute in (37, 45, 55, 59):
        assert not w.window_open(T0 + minute * MIN), f"the window was open at minute {minute}"


def test_success_the_window_opens_once_the_runner_takes_the_job(cfg):
    w = QueuedWorld(queued_from=T0 + 30, runner_at=T0 + 60 * MIN)
    assert drive(cfg, w) == 0
    assert w.window_open(T0 + 61 * MIN + 30)
    assert w.at("land")[2], "the landing ran with the window closed"
    assert w.at("tag-push")[2], "the tag push ran with the window closed"


def test_success_a_window_opened_by_the_lead_time_closes_when_a_job_is_queued_again(cfg):
    # A re-run: the job is queued from minute 30, after the lead time opened
    # the window at about minute 22.
    w = QueuedWorld(queued_from=T0 + 30 * MIN, runner_at=T0 + 60 * MIN)

    def rollup():
        items = World.rollup(w)
        if w.now >= T0 + 30 * MIN:
            items += QueuedWorld.rollup(w)[-1:]
        return items

    w.rollup = rollup
    assert drive(cfg, w) == 0
    assert w.window_open(T0 + 25 * MIN), "the lead time did not open the window"
    assert not w.window_open(T0 + 40 * MIN), "the window stayed open over a queued job"
    assert w.window_open(T0 + 62 * MIN)


def test_failure_a_job_that_never_gets_a_runner_and_is_canceled_stops_the_train(cfg):
    w = QueuedWorld(queued_from=T0 + 30, runner_at=T0 + 600 * MIN)

    def rollup():
        items = World.rollup(w)
        gone = w.now >= T0 + 50 * MIN
        items.append({"name": "mac", "status": "COMPLETED" if gone else "QUEUED",
                      "conclusion": GONE if gone else "", "startedAt": iso(T0 + 30)})
        return items

    w.rollup = rollup
    assert drive(cfg, w) == 1
    assert not any(what == "open" for _, what in w.window_log), "the window opened for a job with no runner"
    assert "land" not in w.names()


def test_edge_a_clean_release_opens_the_window_as_before(cfg):
    w = World()
    assert drive(cfg, w) == 0
    opened = [t for t, what in w.window_log if what == "open"]
    assert opened and opened[0] <= T0 + 22 * MIN + 30


def test_edge_a_check_queued_for_seconds_does_not_close_the_window(cfg):
    # The job becomes ready at minute 30 and gets its runner 60 s later.
    w = QueuedWorld(queued_from=T0 + 30 * MIN, runner_at=T0 + 31 * MIN)

    def rollup():
        items = World.rollup(w)
        if w.now >= T0 + 30 * MIN:
            items += QueuedWorld.rollup(w)[-1:]
        return items

    w.rollup = rollup
    assert drive(cfg, w) == 0
    closes = [t for t, what in w.window_log if what == "close" and t < T0 + 36 * MIN]
    assert closes == [], f"the window closed during CI at {closes}"


def test_edge_the_rollup_query_is_unchanged(cfg):
    w = World()
    seen = []

    def spy(argv, timeout):
        seen.append(" ".join(argv))
        return w(argv, timeout)

    rt.read_facts(cfg, spy, T0)
    view = next(c for c in seen if "gh pr view" in c)
    assert view.endswith("--json statusCheckRollup")
    assert sum("gh pr view" in c for c in seen) == 1, "the count costs a second query"
