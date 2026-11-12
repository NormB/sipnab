# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/release-train.py: one resumable entry point from a release PR to done.

RELEASE-FAST E. The heavy-run release window holds ordinary main-slot jobs
back so a release's local steps do not queue behind them. Two measurements set
what it must do:

- 0.5.239: the window did not exist, and the tag push waited 769 s behind an
  ordinary job that had started 7 s earlier.
- 0.5.240: the window was closed for the whole of the PR's CI, an ordinary hook
  started in the same second, and the tag queued 434 s behind it.

So the train closes the window during a remote wait and re-opens it before the
next local step: when the PR's pending checks drop to the last few, or a set
time before CI's expected finish. A job already running is never stopped, so
the window has to be open for about one hook's length before the tag push.

Every decision is a pure function, and a whole release runs here on a fake
clock against a fake GitHub, host and heavy-run.
"""

import datetime
import json

import pytest
from conftest import load

rt = load("release-train")

VERSION = "0.5.242"
HEAD = "a" * 40
MERGE = "b" * 40
PRE = "d" * 40  # main before the release: where the train's checkout starts
MIN = 60
T0 = 1_800_000_000


def iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main_run(name, seconds, conclusion="success", status="completed", start=T0 - 3600):
    """One line of the check-runs read: a check run of main's head commit."""
    return json.dumps({"name": name, "status": status, "conclusion": conclusion,
                       "started_at": iso(start), "completed_at": iso(start + seconds)})


def facts(**kw):
    base = dict(pr_state="OPEN", pr_number=9, head=HEAD, merge_sha="", pending=0, failed=(),
                first_started=T0, tag_exists=False, run_status="", run_conclusion="", post_rc=None)
    base.update(kw)
    return rt.Facts(**base)


@pytest.fixture
def cfg(tmp_path):
    return rt.Config(version=VERSION, host="releaser@vm.example.invalid", repo="NormB/sipnab",
                     state_file=tmp_path / "train.json")


# ---------------------------------------------------------------------------
# A whole release, on a fake clock
# ---------------------------------------------------------------------------


class Runaway(BaseException):
    """The train kept going past where it should have stopped. Not an
    Exception, so the train's own handler cannot turn it into an exit status."""


class World:
    """GitHub, the host and heavy-run, driven by one clock."""

    def __init__(self, ci_minutes=36, n_checks=20, post_rc=0, release_minutes=30,
                 conclusion="SUCCESS", run_conclusion="success"):
        self.now = T0
        self.pr = {"number": 9, "state": "OPEN", "headRefOid": HEAD, "mergeCommit": None}
        self.checks = []
        for i in range(n_checks):
            end = T0 + ci_minutes * MIN * (i + 1) / n_checks
            self.checks.append({"name": f"job-{i}", "start": T0 + 30, "end": end, "conclusion": conclusion})
        self.tag = False
        self.local_tag = None
        self.release_end = None
        self.release_minutes = release_minutes
        self.run_conclusion = run_conclusion
        self.post_rc = post_rc
        self.window = None  # (owner, until)
        self.log = []
        self.window_log = []
        self.overrides = []
        # The train's own checkout, and how long after the merge GitHub takes
        # to list the pull request for the merge commit (RELEASE-TRAIN-TAG-RACE).
        self.checkout = PRE
        self.dirty = ""
        self.merged_at = None
        self.proof_lag = 20
        self.proof_asks = []
        # main's head commit: seconds each check took there (None: the read
        # fails). Empty by default, so the older tests run on the count rule.
        self.usual = {}
        self.usual_asks = []

    def sleep(self, s):
        self.now += s

    def clock(self):
        return self.now

    def event(self, name):
        self.log.append((self.now, name, self.window is not None and self.window[1] > self.now))

    def rollup(self):
        items = []
        for c in self.checks:
            done = self.now >= c["end"]
            items.append({"name": c["name"], "status": "COMPLETED" if done else "IN_PROGRESS",
                          "conclusion": c["conclusion"] if done else "", "startedAt": iso(c["start"])})
        items.append({"context": "license/cla", "state": "SUCCESS", "startedAt": iso(T0)})
        return items

    def pending(self):
        return sum(1 for c in self.checks if self.now < c["end"])

    def __call__(self, argv, timeout):
        self.calls = getattr(self, "calls", 0) + 1
        if self.calls > 5000:
            raise Runaway(" ".join(argv))
        j = " ".join(argv)
        for pred, result in self.overrides:
            if pred in j:
                return rt.Result(*result)
        if "--release-window status" in j:
            if self.window and self.window[1] > self.now:
                return rt.Result(0, f"open {self.window[0]} until {iso(self.window[1])}\n")
            return rt.Result(0, "closed\n")
        if "--release-window open" in j:
            owner, mins = argv[-2], int(argv[-1])
            if self.window and self.window[1] > self.now and self.window[0] != owner:
                return rt.Result(1, f"heavy-run: the release window is open for {self.window[0]}\n")
            self.window = (owner, self.now + mins * MIN)
            self.window_log.append((self.now, "open"))
            return rt.Result(0, "")
        if "--release-window close" in j:
            self.window = None
            self.window_log.append((self.now, "close"))
            return rt.Result(0, "closed\n")
        if "/check-runs" in j:
            self.usual_asks.append(self.now)
            if self.usual is None:
                return rt.Result(1, "gh: HTTP 502\n")
            return rt.Result(0, "".join(main_run(n, s) + "\n" for n, s in self.usual.items()))
        if "gh pr list" in j:
            return rt.Result(0, json.dumps([self.pr]))
        if "gh pr view" in j:
            return rt.Result(0, json.dumps({"statusCheckRollup": self.rollup()}))
        if "cla-owner-exempt" in j:
            self.event("cla")
            return rt.Result(0, "")
        if "ls-remote --tags" in j:
            return rt.Result(0, f"{MERGE}\trefs/tags/v{VERSION}\n" if self.tag else "")
        if "gh run list" in j:
            if not self.tag:
                return rt.Result(0, "[]")
            done = self.now >= self.release_end
            return rt.Result(0, json.dumps([{"status": "completed" if done else "in_progress",
                                             "conclusion": self.run_conclusion if done else ""}]))
        if "land-queue" in j:
            self.event("land")
            self.pr["state"] = "MERGED"
            self.pr["mergeCommit"] = {"oid": MERGE}
            self.merged_at = self.now
            return rt.Result(0, getattr(self, "land_out", ""))
        if "fetch origin" in j:
            return rt.Result(0, "")
        if "rev-parse HEAD" in j:
            return rt.Result(0, self.checkout + "\n")
        if "status --porcelain" in j:
            return rt.Result(0, self.dirty)
        if "checkout --detach" in j:
            self.event("checkout")
            self.checkout = argv[-1]
            return rt.Result(0, "")
        if "tag-push-proof.py --ready" in j:
            self.proof_asks.append(self.now)
            if self.merged_at is None or self.now - self.merged_at >= self.proof_lag:
                return rt.Result(0, "tag-only push: proven\ntag CI gate: head\n")
            return rt.Result(1, "tag-only push: the full gates run -- the proof is not found yet\n")
        if "rev-parse" in j:
            return rt.Result(0 if self.local_tag else 128, (self.local_tag or "") + "\n")
        if "tag -s" in j:
            self.event("tag")
            self.local_tag = MERGE
            return rt.Result(0, "")
        if "verify-tag" in j:
            return rt.Result(0, "Good\n")
        if "push origin" in j:
            self.event("tag-push")
            self.pushed_from = self.checkout
            self.tag = True
            self.release_end = self.now + self.release_minutes * MIN
            return rt.Result(0, "")
        if "post-release.py" in j:
            self.event("post")
            return rt.Result(self.post_rc, "bpf: OK\n")
        raise AssertionError(f"no rule for {j}")

    def names(self):
        return [n for _, n, _ in self.log]

    def at(self, name):
        return next(e for e in self.log if e[1] == name)


def drive(cfg, w):
    return rt.train(cfg, w, sleep=w.sleep, clock=w.clock)


# ---------------------------------------------------------------------------
# The stage is read from the facts
# ---------------------------------------------------------------------------


def test_success_pending_checks_are_the_ci_wait():
    assert rt.stage_of(facts(pending=4)) == "ci-wait"


def test_success_a_green_open_pr_is_the_land_stage():
    assert rt.stage_of(facts()) == "land"


def test_success_a_merged_pr_with_no_tag_is_the_tag_stage():
    assert rt.stage_of(facts(pr_state="MERGED", merge_sha=MERGE)) == "tag"


def test_success_a_tag_with_a_running_release_is_the_release_wait():
    assert rt.stage_of(facts(pr_state="MERGED", merge_sha=MERGE, tag_exists=True, run_status="in_progress")) == "release-wait"


def test_success_a_finished_release_run_is_the_post_stage():
    assert rt.stage_of(facts(pr_state="MERGED", merge_sha=MERGE, tag_exists=True, run_status="completed",
                             run_conclusion="success")) == "post"


def test_success_a_post_exit_of_0_is_done():
    assert rt.stage_of(facts(pr_state="MERGED", merge_sha=MERGE, tag_exists=True, run_status="completed",
                             run_conclusion="success", post_rc=0)) == "done"


def test_failure_a_failed_check_is_ci_failed_even_with_others_pending():
    assert rt.stage_of(facts(pending=5, failed=("Docs",))) == "ci-failed"


def test_failure_no_pr_is_its_own_stage():
    assert rt.stage_of(facts(pr_state="", pr_number=None)) == "no-pr"


def test_failure_a_pr_closed_unmerged_is_no_pr():
    assert rt.stage_of(facts(pr_state="CLOSED")) == "no-pr"


def test_failure_a_failed_release_run_is_release_failed():
    assert rt.stage_of(facts(pr_state="MERGED", merge_sha=MERGE, tag_exists=True, run_status="completed",
                             run_conclusion="failure")) == "release-failed"


def test_failure_a_withdrawn_release_stops_at_post_withdrawn():
    assert rt.stage_of(facts(pr_state="MERGED", merge_sha=MERGE, tag_exists=True, run_status="completed",
                             run_conclusion="success", post_rc=3)) == "post-withdrawn"


def test_failure_a_failed_withdrawal_stops_at_post_withdrawn():
    assert rt.stage_of(facts(pr_state="MERGED", merge_sha=MERGE, tag_exists=True, run_status="completed",
                             run_conclusion="success", post_rc=4)) == "post-withdrawn"


def test_edge_an_open_pr_with_no_checks_yet_is_a_wait_not_a_landing():
    # GitHub lists no checks for the first seconds after a push.
    assert rt.stage_of(facts(pending=0, first_started=None)) == "ci-wait"


def test_edge_a_tag_with_no_run_listed_yet_is_the_release_wait():
    assert rt.stage_of(facts(pr_state="MERGED", merge_sha=MERGE, tag_exists=True)) == "release-wait"


def test_edge_a_post_exit_of_1_runs_the_post_stage_again():
    # Every check is safe to repeat, so a re-run retries it.
    assert rt.stage_of(facts(pr_state="MERGED", merge_sha=MERGE, tag_exists=True, run_status="completed",
                             run_conclusion="success", post_rc=1)) == "post"


def test_edge_a_tag_outranks_the_pr_state():
    # A resume after the tag: nothing about the PR can move the train back.
    assert rt.stage_of(facts(pr_state="OPEN", pending=3, tag_exists=True, run_status="in_progress")) == "release-wait"


# ---------------------------------------------------------------------------
# The window rule
# ---------------------------------------------------------------------------


def test_success_the_window_is_open_for_the_landing(cfg):
    assert rt.window_wanted("land", 0, 0, cfg)


def test_success_the_window_is_open_for_the_tag(cfg):
    assert rt.window_wanted("tag", 0, 0, cfg)


def test_success_the_window_opens_when_the_last_few_checks_remain(cfg):
    assert rt.window_wanted("ci-wait", cfg.last_few, 30 * MIN, cfg)


def test_success_the_window_opens_a_set_time_before_the_expected_finish(cfg):
    assert rt.window_wanted("ci-wait", 15, cfg.lead_s, cfg)


def test_failure_a_remote_wait_with_many_checks_pending_does_not_hold_the_window(cfg):
    assert not rt.window_wanted("ci-wait", cfg.last_few + 1, cfg.lead_s + 1, cfg)


def test_failure_the_release_workflow_wait_does_not_hold_the_window(cfg):
    assert not rt.window_wanted("release-wait", 0, 0, cfg)


def test_failure_the_post_checks_do_not_hold_the_window(cfg):
    # post-release.py runs nothing through heavy-run.
    assert not rt.window_wanted("post", 0, 0, cfg)


@pytest.mark.parametrize("stage", ["no-pr", "ci-failed", "release-failed", "post-withdrawn", "done"])
def test_failure_a_stopped_train_holds_no_window(cfg, stage):
    assert not rt.window_wanted(stage, 0, 0, cfg)


def test_edge_a_window_opens_exactly_at_the_lead(cfg):
    assert rt.window_wanted("ci-wait", 15, cfg.lead_s, cfg)
    assert not rt.window_wanted("ci-wait", 15, cfg.lead_s + 1, cfg)


def test_edge_ci_overrunning_its_estimate_counts_as_no_time_left(cfg):
    assert rt.ci_remaining(facts(first_started=T0), cfg, T0 + cfg.expected_ci_s + 500) == 0


def test_edge_no_check_started_yet_means_the_whole_estimate(cfg):
    assert rt.ci_remaining(facts(first_started=None), cfg, T0 + 500) == cfg.expected_ci_s


# ---------------------------------------------------------------------------
# A whole release
# ---------------------------------------------------------------------------


def test_success_a_clean_release_runs_end_to_end(cfg):
    w = World()
    assert drive(cfg, w) == 0
    assert w.names() == ["cla", "land", "checkout", "tag", "tag-push", "post"]


def test_success_no_remote_wait_holds_the_window(cfg):
    # Early in CI, with every check pending and the finish far away.
    w = World()
    seen = []
    real = w.__call__

    def spy(argv, timeout):
        if "--release-window status" in " ".join(argv) and w.pending() > cfg.last_few \
                and T0 + cfg.expected_ci_s - w.now > cfg.lead_s:
            seen.append(w.window is None)
        return real(argv, timeout)

    assert rt.train(cfg, spy, sleep=w.sleep, clock=w.clock) == 0
    assert seen and all(seen)


def test_success_the_window_is_open_before_the_tag_push_queues(cfg):
    w = World()
    drive(cfg, w)
    assert w.at("tag-push")[2]


def test_success_the_window_opened_at_least_the_lead_before_the_tag_push(cfg):
    # 36 min of CI against a 37 min estimate: it opens at the lead.
    w = World()
    drive(cfg, w)
    first_open = next(t for t, kind in w.window_log if kind == "open")
    assert w.at("tag-push")[0] - first_open >= 8 * MIN


def test_success_the_last_few_checks_open_the_window_when_ci_runs_fast(cfg):
    # Well inside the estimate, so only the pending count can open it.
    w = World(ci_minutes=10, n_checks=20)
    drive(cfg, w)
    first_open = next(t for t, kind in w.window_log if kind == "open")
    assert first_open < w.at("land")[0]


def test_success_the_window_closes_after_the_tag_is_pushed(cfg):
    w = World()
    drive(cfg, w)
    closes = [t for t, kind in w.window_log if kind == "close"]
    assert closes and closes[0] >= w.at("tag-push")[0]
    assert closes[0] < w.at("post")[0]


def test_success_the_window_is_closed_when_the_train_ends(cfg):
    w = World()
    drive(cfg, w)
    assert w.window is None


def test_success_the_tag_points_at_the_merge_commit_and_is_signed(cfg):
    w = World()
    calls = []
    real = w.__call__

    def spy(argv, timeout):
        calls.append(argv)
        return real(argv, timeout)

    rt.train(cfg, spy, sleep=w.sleep, clock=w.clock)
    tag = next(c for c in calls if "tag" in c and "-s" in c)
    assert MERGE in tag and f"v{VERSION}" in tag and f"sipnab {VERSION}" in tag


def test_success_the_tag_push_uses_the_lane(cfg):
    w = World()
    calls = []
    real = w.__call__

    def spy(argv, timeout):
        calls.append(" ".join(argv))
        return real(argv, timeout)

    rt.train(cfg, spy, sleep=w.sleep, clock=w.clock)
    assert any("heavy-run --lane -- git" in c and f"push origin v{VERSION}" in c for c in calls)


def test_success_the_landing_runs_required_checks_and_matches_the_head(cfg):
    w = World()
    calls = []
    real = w.__call__

    def spy(argv, timeout):
        calls.append(" ".join(argv))
        return real(argv, timeout)

    rt.train(cfg, spy, sleep=w.sleep, clock=w.clock)
    land = next(c for c in calls if "land-queue sipnab" in c)
    assert "required-checks NormB/sipnab " + HEAD in land
    assert "--match-head-commit " + HEAD in land
    assert "--admin" not in land


def test_success_the_post_stage_gets_the_host(cfg):
    w = World()
    calls = []
    real = w.__call__

    def spy(argv, timeout):
        calls.append(" ".join(argv))
        return real(argv, timeout)

    rt.train(cfg, spy, sleep=w.sleep, clock=w.clock)
    assert any("post-release.py run " + VERSION + " --host releaser@vm.example.invalid" in c for c in calls)


def test_failure_a_failed_check_stops_the_train_and_names_it(cfg, capsys):
    w = World()
    w.checks[0]["conclusion"] = "FAILURE"
    assert drive(cfg, w) == 1
    assert "job-0" in capsys.readouterr().out
    assert "land" not in w.names()


def test_failure_a_failed_release_run_stops_before_the_post_checks(cfg):
    w = World(run_conclusion="failure")
    assert drive(cfg, w) == 1
    assert "post" not in w.names()


def test_failure_no_pr_stops_without_doing_anything(cfg):
    w = World()
    w.overrides.append(("gh pr list", (0, "[]")))
    assert drive(cfg, w) == 1
    assert w.names() == []


def test_failure_a_withdrawn_release_exits_3(cfg):
    w = World(post_rc=3)
    assert drive(cfg, w) == 3


def test_failure_a_failed_withdrawal_exits_4(cfg):
    w = World(post_rc=4)
    assert drive(cfg, w) == 4


def test_failure_a_failed_post_check_exits_1(cfg):
    w = World(post_rc=1)
    assert drive(cfg, w) == 1


def test_failure_a_failed_landing_stops_the_train(cfg):
    w = World()
    w.overrides.append(("land-queue", (1, "required check missing\n")))
    assert drive(cfg, w) == 1


def test_failure_a_cla_status_that_cannot_be_posted_stops_the_train(cfg):
    w = World()
    w.overrides.append(("cla-owner-exempt", (1, "does not qualify\n")))
    assert drive(cfg, w) == 1
    assert "land" not in w.names()


def test_failure_a_failed_tag_push_stops_the_train(cfg):
    w = World()
    w.overrides.append(("push origin", (1, "pre-push refused\n")))
    assert drive(cfg, w) == 1


def test_failure_a_failed_read_of_github_stops_rather_than_guessing(cfg):
    w = World()
    w.overrides.append(("gh pr list", (1, "HTTP 502\n")))
    assert drive(cfg, w) == 1


def test_failure_a_failed_read_that_prints_json_is_still_a_failed_read(cfg, capsys):
    # An empty list from a failed command must not read as "no pull request".
    w = World()
    w.overrides.append(("gh pr list", (1, "[]")))
    assert drive(cfg, w) == 1
    assert "read failed" in capsys.readouterr().out


def test_failure_a_local_tag_on_another_commit_is_refused(cfg):
    w = World()
    w.local_tag = "c" * 40
    assert drive(cfg, w) == 1
    assert "tag-push" not in w.names()


def test_failure_a_stopped_train_leaves_its_window_closed(cfg):
    w = World()
    w.overrides.append(("land-queue", (1, "no\n")))
    drive(cfg, w)
    assert w.window is None


def test_failure_a_crash_mid_train_leaves_its_window_closed(cfg):
    w = World()
    real = w.__call__

    def boom(argv, timeout):
        if "land-queue" in " ".join(argv):
            raise OSError("disk full")
        return real(argv, timeout)

    assert rt.train(cfg, boom, sleep=w.sleep, clock=w.clock) == 1
    assert w.window is None


# ---------------------------------------------------------------------------
# Resuming
# ---------------------------------------------------------------------------


def test_edge_a_resume_after_the_landing_does_not_land_again(cfg):
    w = World()
    w.now = T0 + 40 * MIN
    w.pr["state"] = "MERGED"
    w.pr["mergeCommit"] = {"oid": MERGE}
    assert drive(cfg, w) == 0
    assert "land" not in w.names()


def test_edge_a_resume_after_the_tag_does_not_tag_again(cfg):
    w = World()
    w.now = T0 + 40 * MIN
    w.pr["state"] = "MERGED"
    w.pr["mergeCommit"] = {"oid": MERGE}
    w.tag = True
    w.release_end = w.now + 5 * MIN
    assert drive(cfg, w) == 0
    assert "tag" not in w.names() and "tag-push" not in w.names()


def test_edge_a_resume_after_a_pass_runs_nothing(cfg):
    w = World()
    assert drive(cfg, w) == 0
    n = len(w.log)
    assert drive(cfg, w) == 0
    assert len(w.log) == n


def test_edge_a_resume_with_the_local_tag_already_made_pushes_it(cfg):
    w = World()
    w.now = T0 + 40 * MIN
    w.pr["state"] = "MERGED"
    w.pr["mergeCommit"] = {"oid": MERGE}
    w.local_tag = MERGE
    assert drive(cfg, w) == 0
    assert "tag" not in w.names() and "tag-push" in w.names()


def test_edge_a_withdrawn_release_is_not_rechecked_on_resume(cfg):
    w = World(post_rc=3)
    drive(cfg, w)
    n = w.names().count("post")
    assert drive(cfg, w) == 3
    assert w.names().count("post") == n


def test_edge_retry_post_runs_a_withdrawn_release_again(cfg):
    w = World(post_rc=3)
    drive(cfg, w)
    w.post_rc = 0
    cfg.retry_post = True
    assert drive(cfg, w) == 0


def test_edge_a_failed_post_is_retried_on_resume(cfg):
    w = World(post_rc=1)
    drive(cfg, w)
    w.post_rc = 0
    assert drive(cfg, w) == 0


def test_edge_the_cla_status_is_posted_once_per_head(cfg):
    w = World()
    drive(cfg, w)
    assert w.names().count("cla") == 1


def test_edge_a_new_head_gets_its_own_cla_status(cfg):
    w = World(ci_minutes=2)
    rt.tick(cfg, w, w.clock)
    w.pr["headRefOid"] = "d" * 40
    rt.tick(cfg, w, w.clock)
    assert w.names().count("cla") == 2


def test_edge_the_cla_status_is_not_posted_for_a_merged_pr(cfg):
    w = World()
    w.pr["state"] = "MERGED"
    w.pr["mergeCommit"] = {"oid": MERGE}
    rt.tick(cfg, w, w.clock)
    assert "cla" not in w.names()


# ---------------------------------------------------------------------------
# Sharing the window
# ---------------------------------------------------------------------------


def test_edge_another_owners_window_is_never_closed(cfg):
    w = World()
    w.window = ("vcon-0.4.1", T0 + 500 * MIN)
    drive(cfg, w)
    assert w.window[0] == "vcon-0.4.1"


def test_edge_another_owners_window_does_not_stop_the_train(cfg):
    w = World()
    w.window = ("vcon-0.4.1", T0 + 500 * MIN)
    assert drive(cfg, w) == 0


def test_edge_a_window_near_its_expiry_is_extended(cfg):
    w = World()
    w.window = (rt.window_owner(cfg), w.now + 5 * MIN)
    assert rt.sync_window(cfg, w, True, w.now) == "open"


def test_edge_a_window_with_time_left_is_left_alone(cfg):
    w = World()
    w.window = (rt.window_owner(cfg), w.now + 50 * MIN)
    assert rt.sync_window(cfg, w, True, w.now) == "none"


def test_edge_a_window_status_that_does_not_parse_is_not_ours():
    assert rt.parse_window("banana") == (None, None)


def test_edge_a_closed_window_parses_as_nobodys():
    assert rt.parse_window("closed\n") == (None, None)


def test_edge_an_open_window_parses_its_owner_and_expiry():
    owner, until = rt.parse_window(f"open release-1 until {iso(T0)}\n")
    assert owner == "release-1" and until == T0


# ---------------------------------------------------------------------------
# Reading the checks
# ---------------------------------------------------------------------------


def test_success_the_rollup_counts_pending_and_failed():
    pending, failed, first = rt.read_rollup([
        {"name": "a", "status": "IN_PROGRESS", "conclusion": "", "startedAt": iso(T0 + 9)},
        {"name": "b", "status": "COMPLETED", "conclusion": "FAILURE", "startedAt": iso(T0)},
        {"name": "c", "status": "COMPLETED", "conclusion": "SUCCESS", "startedAt": iso(T0 + 3)},
    ])
    assert (pending, failed, first) == (1, ("b",), T0)


@pytest.mark.parametrize("conclusion", ["FAILURE", "TIMED_OUT", "cancelled".upper(), "ACTION_REQUIRED", "STARTUP_FAILURE"])
def test_failure_every_bad_conclusion_counts_as_failed(conclusion):
    assert rt.read_rollup([{"name": "a", "status": "COMPLETED", "conclusion": conclusion}])[1] == ("a",)


@pytest.mark.parametrize("conclusion", ["SUCCESS", "NEUTRAL", "SKIPPED"])
def test_success_every_good_conclusion_counts_as_passed(conclusion):
    assert rt.read_rollup([{"name": "a", "status": "COMPLETED", "conclusion": conclusion}])[:2] == (0, ())


def test_failure_a_status_context_in_error_counts_as_failed():
    assert rt.read_rollup([{"context": "license/cla", "state": "ERROR"}])[1] == ("license/cla",)


def test_edge_a_pending_status_context_counts_as_pending():
    assert rt.read_rollup([{"context": "license/cla", "state": "PENDING"}])[0] == 1


def test_edge_an_unknown_check_status_counts_as_pending_not_passed():
    assert rt.read_rollup([{"name": "a", "status": "WAITING", "conclusion": ""}])[0] == 1


def test_edge_a_completed_check_with_an_unknown_conclusion_is_not_passed():
    assert rt.read_rollup([{"name": "a", "status": "COMPLETED", "conclusion": "BANANA"}])[:2] == (1, ())


def test_edge_a_check_with_no_start_time_is_tolerated():
    assert rt.read_rollup([{"name": "a", "status": "QUEUED"}])[2] is None


def test_edge_an_empty_rollup_has_no_start():
    assert rt.read_rollup([]) == (0, (), None)


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def test_failure_a_version_that_is_not_x_y_z_is_a_usage_error():
    assert rt.main(["v0.5.242", "--host", "releaser@vm.example.invalid"], runner=World()) == 2


def test_failure_no_host_is_a_usage_error():
    assert rt.main([VERSION], runner=World()) == 2


def test_edge_the_state_file_holds_only_the_post_result(cfg):
    w = World()
    drive(cfg, w)
    # The usual times: main's head had no completed run to read, so the table
    # is empty and the last read is some time inside the 36 min of CI.
    state = json.loads(cfg.state_file.read_text())
    assert T0 <= state.pop("usual_read_at") <= T0 + 36 * MIN
    assert state == {"post_rc": 0, "cla_head": HEAD, "usual_s": {}}


# ---------------------------------------------------------------------------
# RELEASE-TRAIN-TAG-RACE: the checkout and the proof, before the tag
# ---------------------------------------------------------------------------
#
# Measured on 0.5.243: #734 merged at 07:27:34Z and the train pushed the tag at
# 07:27:35Z. The pre-push hook refused it twice, about six minutes in all.
# (1) GitHub did not yet list #734 for the merge commit 88f46bb83, so
# scripts/tag-push-proof.py found no proof and every gate ran. (2) The train's
# checkout was still at 4fae9a255, the main before the release, and the hook's
# release-delivery test reads the checkout it runs in.


def test_success_the_tag_is_pushed_from_a_checkout_at_the_merge_commit(cfg):
    w = World()
    assert drive(cfg, w) == 0
    assert w.pushed_from == MERGE


def test_failure_a_checkout_with_uncommitted_changes_is_not_moved_and_the_train_stops(cfg, capsys):
    w = World()
    w.dirty = " M src/main.rs\n"
    assert drive(cfg, w) == 1
    assert "checkout" not in w.names() and "tag" not in w.names() and "tag-push" not in w.names()
    out = capsys.readouterr().out
    assert "uncommitted changes" in out and f"git -C {rt.REPO} checkout --detach {MERGE}" in out, out


def test_failure_a_status_that_cannot_be_read_does_not_move_the_checkout(cfg, capsys):
    w = World()
    w.overrides.append(("status --porcelain", (128, "fatal: not a git repository\n")))
    assert drive(cfg, w) == 1
    assert "checkout" not in w.names() and "tag-push" not in w.names()
    assert "could not be read" in capsys.readouterr().out


def test_failure_a_head_that_cannot_be_read_stops_before_any_tag(cfg, capsys):
    w = World()
    w.overrides.append(("rev-parse HEAD", (128, "fatal: bad HEAD\n")))
    assert drive(cfg, w) == 1
    assert "checkout" not in w.names() and "tag" not in w.names()
    assert "could not be read: fatal: bad HEAD" in capsys.readouterr().out


def test_failure_a_checkout_that_git_refuses_stops_with_the_command_to_run(cfg, capsys):
    w = World()
    w.overrides.append(("checkout --detach", (1, "error: unable to create file\n")))
    assert drive(cfg, w) == 1
    assert "tag" not in w.names() and "tag-push" not in w.names()
    out = capsys.readouterr().out
    assert "unable to create file" in out and f"checkout --detach {MERGE}" in out, out


def test_failure_a_checkout_that_reports_success_but_lands_elsewhere_is_refused(cfg, capsys):
    # The check is the commit HEAD names afterwards, not git's exit status.
    w = World()
    real = w.__call__

    def lying(argv, timeout):
        if "checkout" in argv and "--detach" in argv:
            return rt.Result(0, "")
        return real(argv, timeout)

    assert rt.train(cfg, lying, sleep=w.sleep, clock=w.clock) == 1
    assert "tag" not in w.names() and "tag-push" not in w.names()
    assert "is still at ddddddddd" in capsys.readouterr().out


def test_success_a_checkout_already_at_the_merge_commit_is_left_alone(cfg):
    w = World()
    w.checkout = MERGE
    assert drive(cfg, w) == 0
    assert "checkout" not in w.names() and w.pushed_from == MERGE


def test_success_the_move_is_reported_with_both_commits(cfg, capsys):
    drive(cfg, World())
    assert "checkout: moved from ddddddddd to the merge commit bbbbbbbbb" in capsys.readouterr().out


def test_edge_a_dirty_checkout_already_at_the_merge_commit_is_not_refused(cfg):
    # Nothing has to move, so uncommitted changes are not the train's concern.
    w = World()
    w.checkout = MERGE
    w.dirty = " M notes.txt\n"
    assert drive(cfg, w) == 0


def test_edge_untracked_files_do_not_stop_the_move(cfg):
    w = World()
    calls = []
    real = w.__call__

    def spy(argv, timeout):
        calls.append(argv)
        return real(argv, timeout)

    assert rt.train(cfg, spy, sleep=w.sleep, clock=w.clock) == 0
    status = next(c for c in calls if "--porcelain" in c)
    assert "--untracked-files=no" in status


def test_edge_the_fetch_comes_before_the_checkout_and_the_checkout_before_the_tag(cfg):
    w = World()
    order = []
    real = w.__call__

    def spy(argv, timeout):
        j = " ".join(argv)
        for key in ("fetch origin", "checkout --detach", "tag -s", "push origin"):
            if key in j:
                order.append(key)
        return real(argv, timeout)

    assert rt.train(cfg, spy, sleep=w.sleep, clock=w.clock) == 0
    assert order == ["fetch origin", "checkout --detach", "tag -s", "push origin"]


def test_edge_a_resume_with_the_local_tag_made_still_moves_the_checkout_before_the_push(cfg):
    # 0.5.243's second attempt: the local tag existed and the checkout was at
    # the main before the release.
    w = World()
    w.now = T0 + 40 * MIN
    w.pr["state"] = "MERGED"
    w.pr["mergeCommit"] = {"oid": MERGE}
    w.local_tag = MERGE
    assert drive(cfg, w) == 0
    assert w.pushed_from == MERGE and "tag" not in w.names()


# The proof: the hook's own query, polled before the tag exists.


def test_success_the_tag_is_not_pushed_before_github_can_prove_the_merge_commit(cfg):
    w = World()
    assert drive(cfg, w) == 0
    assert w.at("tag-push")[0] - w.merged_at >= w.proof_lag


def test_failure_a_proof_that_never_resolves_stops_the_train_within_the_bound(cfg, capsys):
    w = World()
    w.proof_lag = 10**9
    assert drive(cfg, w) == 1
    assert "tag" not in w.names() and "tag-push" not in w.names()
    waited = w.proof_asks[-1] - w.proof_asks[0]
    assert cfg.proof_wait_s <= waited < cfg.proof_wait_s + cfg.proof_poll_s, waited
    out = capsys.readouterr().out
    assert f"did not resolve in {cfg.proof_wait_s} s" in out and "the proof is not found yet" in out, out
    assert "re-run" in out, out


def test_success_a_wait_for_the_proof_is_reported_once_with_how_long_it_took(cfg, capsys):
    w = World()
    assert drive(cfg, w) == 0
    out = capsys.readouterr().out
    assert out.count("tag: waiting for GitHub's proof") == 1 and "tag: the proof resolved after 20 s" in out, out


def test_success_a_proof_there_at_the_first_ask_costs_one_query_and_no_wait(cfg, capsys):
    w = World()
    w.proof_lag = 0
    assert drive(cfg, w) == 0
    assert len(w.proof_asks) == 1 and w.at("tag-push")[0] == w.merged_at
    assert "waiting for GitHub's proof" not in capsys.readouterr().out


def test_success_the_query_is_the_hooks_own_script_on_the_merge_commit(cfg):
    w = World()
    calls = []
    real = w.__call__

    def spy(argv, timeout):
        calls.append(argv)
        return real(argv, timeout)

    assert rt.train(cfg, spy, sleep=w.sleep, clock=w.clock) == 0
    ask = next(c for c in calls if "--ready" in c)
    assert ask[1] == str(rt.SCRIPTS / "tag-push-proof.py") and ask[2:] == ["--ready", MERGE]


def test_success_the_proof_is_asked_for_before_the_tag_is_made(cfg):
    w = World()
    assert drive(cfg, w) == 0
    assert w.proof_asks[-1] <= w.at("tag")[0] and w.at("tag")[0] - w.merged_at >= w.proof_lag


def test_failure_a_proof_script_that_fails_every_time_stops_with_its_output(cfg, capsys):
    w = World()
    w.overrides.append(("tag-push-proof.py --ready", (2, "usage: tag-push-proof.py\n")))
    assert drive(cfg, w) == 1
    assert "tag-push" not in w.names() and "usage: tag-push-proof.py" in capsys.readouterr().out


def test_failure_the_window_is_closed_when_the_proof_never_resolves(cfg):
    w = World()
    w.proof_lag = 10**9
    drive(cfg, w)
    assert w.window is None


def test_edge_a_proof_that_resolves_at_the_last_ask_inside_the_bound_is_used(cfg):
    w = World()
    w.proof_lag = cfg.proof_wait_s
    assert drive(cfg, w) == 0
    assert "tag-push" in w.names()


def test_edge_a_proof_one_poll_past_the_bound_is_not_waited_for(cfg):
    w = World()
    w.proof_lag = cfg.proof_wait_s + cfg.proof_poll_s
    assert drive(cfg, w) == 1
    assert "tag-push" not in w.names()


def test_edge_the_window_stays_open_while_the_train_waits_for_the_proof(cfg):
    w = World()
    assert drive(cfg, w) == 0
    assert w.at("tag-push")[2] and w.at("tag")[2]


def test_edge_a_resume_after_the_bound_asks_again_and_pushes_when_the_proof_is_there(cfg):
    w = World()
    w.proof_lag = 400
    assert drive(cfg, w) == 1
    assert drive(cfg, w) == 0
    assert w.names().count("tag-push") == 1 and w.pushed_from == MERGE


def test_edge_the_bound_is_settable_on_the_command_line(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(rt, "train", lambda cfg, run: seen.update(wait=cfg.proof_wait_s) or 0)
    monkeypatch.setattr(rt, "git_dir", lambda: tmp_path)
    assert rt.main(["0.5.244", "--host", "releaser@vm.example.invalid", "--proof-wait", "45"]) == 0
    assert seen == {"wait": 45}


def test_edge_the_bound_defaults_to_five_minutes(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(rt, "train", lambda cfg, run: seen.update(wait=cfg.proof_wait_s) or 0)
    monkeypatch.setattr(rt, "git_dir", lambda: tmp_path)
    assert rt.main(["0.5.244", "--host", "releaser@vm.example.invalid"]) == 0
    assert seen == {"wait": 300}


def test_failure_a_negative_bound_is_a_usage_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rt, "train", lambda cfg, run: 0)
    monkeypatch.setattr(rt, "git_dir", lambda: tmp_path)
    assert rt.main(["0.5.244", "--host", "releaser@vm.example.invalid", "--proof-wait", "-1"]) == 2
    assert "--proof-wait" in capsys.readouterr().err


def test_edge_a_bound_of_zero_asks_once_and_stops_if_the_proof_is_not_there(cfg):
    w = World()
    cfg.proof_wait_s = 0
    assert drive(cfg, w) == 1
    assert len(w.proof_asks) == 1 and "tag-push" not in w.names()


# ---------------------------------------------------------------------------
# RELEASE-TRAIN-WINDOW-OPENS-ON-LONG-LAST-CHECK: one long last check
# ---------------------------------------------------------------------------
#
# Measured on 0.5.246: with one check pending (Coverage, running since
# 11:57:38Z) the window was open at 12:31Z, the main slot was idle, and two
# ordinary jobs were held 13 and 4 minutes. Measured on 0.5.249: the window
# opened at 17:09:03Z and closed at 17:32:15Z while one check, a macOS job that
# ran from 16:57:06Z to 17:30:08Z, was the only one pending.
#
# The landing waits for every check, so the count of pending checks says
# nothing about when the landing is. What does is each pending check's start
# plus the time the same check took on main's head commit.


# --- the landing's output ---------------------------------------------------
#
# On 0.5.249 the train's output held no line from required-checks, and the
# release agent could not say from it that the script had run. It had (the
# landing log has the command at 17:30:21Z), and the train printed its output
# only when the landing failed. A `warning:` line of required-checks names a
# check an outside service has not completed, and a landing report quotes it.

LANDED = ("Coverage: success\n"
          "warning: codecov/patch: queued for 12 min, allowed unreported after 10 min\n"
          "Merged pull request #9\n")


def test_success_the_output_of_a_landing_that_passed_is_printed(cfg, capsys):
    w = World()
    w.land_out = LANDED
    assert drive(cfg, w) == 0
    out = capsys.readouterr().out
    assert "Coverage: success" in out and "Merged pull request #9" in out


def test_success_a_warning_line_of_required_checks_reaches_the_trains_output(cfg, capsys):
    w = World()
    w.land_out = LANDED
    drive(cfg, w)
    assert "warning: codecov/patch: queued for 12 min, allowed unreported after 10 min" in capsys.readouterr().out


def test_edge_a_landing_that_printed_nothing_adds_no_empty_line(cfg, capsys):
    w = World()
    assert drive(cfg, w) == 0
    assert "\n\n" not in capsys.readouterr().out


def test_failure_the_output_of_a_landing_that_failed_is_in_the_stop_message_once(cfg, capsys):
    w = World()
    w.overrides.append(("land-queue", (1, "Coverage: failure\n")))
    assert drive(cfg, w) == 1
    assert capsys.readouterr().out.count("Coverage: failure") == 1


# --- each line at once, whatever standard output is --------------------------
#
# On 0.5.249 the train ran with its output in a file, not on a terminal.
# Python block-buffers such an output, so the "stage:" lines appeared only
# when the train ended, and the release agent resumed it with `python3 -u`.
#
# The driver below runs the real `main` in a child process whose standard
# output is a pipe. Its runner answers the first tick (a pull request with one
# running check), says "blocked" on standard error at the first read of the
# second tick, and waits there until its standard input closes. So when
# "blocked" arrives the train is alive and has printed "stage: ci-wait"; the
# only question is whether that line has left the process.

DRIVER = r'''
import importlib.util, json, pathlib, sys
script, state_dir = sys.argv[1], pathlib.Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("release_train_child", script)
rt = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = rt
spec.loader.exec_module(rt)
rt.git_dir = lambda: state_dir
lists = 0

def runner(argv, timeout):
    global lists
    j = " ".join(argv)
    if "gh pr list" in j:
        lists += 1
        if lists == 2:
            sys.stderr.write("blocked\n")
            sys.stderr.flush()
            sys.stdin.read()
        if lists >= 2:
            return rt.Result(1, "the test is over\n")
        return rt.Result(0, json.dumps([{"number": 9, "state": "OPEN", "headRefOid": "a" * 40, "mergeCommit": None}]))
    if "gh pr view" in j:
        return rt.Result(0, json.dumps({"statusCheckRollup": [
            {"name": "Coverage", "status": "IN_PROGRESS", "conclusion": "", "startedAt": "2026-01-01T00:00:00Z"}]}))
    if "/check-runs" in j:
        return rt.Result(1, "no history\n")
    if "--release-window status" in j:
        return rt.Result(0, "closed\n")
    return rt.Result(0, "")

sys.exit(rt.main(["0.5.242", "--host", "releaser@vm.example.invalid", "--poll", "0"] + sys.argv[3:], runner=runner))
'''


def piped_train(tmp_path, *args):
    """Start the driver with pipes; return (process, whether "blocked" came)."""
    import subprocess
    import sys

    driver = tmp_path / "driver.py"
    driver.write_text(DRIVER, encoding="utf-8")
    p = subprocess.Popen([sys.executable, str(driver), str(rt.SCRIPTS / "release-train.py"), str(tmp_path), *args],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p, p.stderr.readline() == b"blocked\n"


def finish(p):
    p.stdin.close()
    rest = p.stdout.read()
    p.stderr.read()
    return rest, p.wait(timeout=60)


def readable(stream, seconds):
    import select

    return bool(select.select([stream], [], [], seconds)[0])


def test_success_a_stage_line_can_be_read_from_a_pipe_while_the_train_is_running(tmp_path):
    p, blocked = piped_train(tmp_path)
    try:
        assert blocked, "the driver never reached its second tick"
        assert p.poll() is None, "the train ended before the line was looked for"
        # The line was printed before "blocked" was written; 5 s is only how
        # long a train that kept the line to itself is given.
        assert readable(p.stdout, 5), "no line left the train while it was running"
        assert p.stdout.readline() == b"stage: ci-wait\n"
        assert p.poll() is None
    finally:
        finish(p)


def test_success_the_lines_after_the_wait_follow_and_the_train_ends(tmp_path):
    p, blocked = piped_train(tmp_path)
    assert blocked
    rest, rc = finish(p)
    assert rc == 1
    lines = rest.decode().splitlines()
    assert lines[0] == "stage: ci-wait"
    assert lines[-1] == "stopped: GitHub or git could not be read; re-run to resume"


def test_failure_a_usage_error_still_exits_2_with_its_output_on_a_pipe(tmp_path):
    import subprocess
    import sys

    r = subprocess.run([sys.executable, str(rt.SCRIPTS / "release-train.py"), "not-a-version", "--host", "h"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "the version is X.Y.Z" in r.stderr


def test_edge_an_output_that_cannot_be_reconfigured_does_not_stop_the_train(tmp_path, monkeypatch):
    class Plain:
        """A standard output with write and flush and nothing else."""

        def __init__(self):
            self.text = ""

        def write(self, s):
            self.text += s

        def flush(self):
            pass

    out = Plain()
    monkeypatch.setattr(rt.sys, "stdout", out)
    monkeypatch.setattr(rt, "train", lambda cfg, run: 0)
    monkeypatch.setattr(rt, "git_dir", lambda: tmp_path)
    assert rt.main([VERSION, "--host", "releaser@vm.example.invalid"]) == 0


def test_edge_the_setting_is_made_once_in_main_before_the_train_starts(tmp_path, monkeypatch):
    seen = []

    class Recording:
        def reconfigure(self, **kw):
            seen.append(("reconfigure", kw))

        def write(self, s):
            pass

        def flush(self):
            pass

    monkeypatch.setattr(rt.sys, "stdout", Recording())
    monkeypatch.setattr(rt, "train", lambda cfg, run: seen.append(("train", {})) or 0)
    monkeypatch.setattr(rt, "git_dir", lambda: tmp_path)
    rt.main([VERSION, "--host", "releaser@vm.example.invalid"])
    assert seen == [("reconfigure", {"line_buffering": True}), ("train", {})]


def check(name, start, status="IN_PROGRESS", conclusion=""):
    return {"name": name, "status": status, "conclusion": conclusion, "startedAt": iso(start)}


class Asks:
    """A runner that answers the check-runs read from a list of results, in
    order (the last one again after that), and counts the asks."""

    def __init__(self, *results):
        self.results = list(results)
        self.argvs = []

    def __call__(self, argv, timeout):
        self.argvs.append(argv)
        r = self.results[min(len(self.argvs), len(self.results)) - 1]
        return rt.Result(*r)


# --- longest_remaining -----------------------------------------------------


def test_success_one_running_check_has_its_usual_time_less_the_time_it_has_run():
    items = [check("Coverage", T0)]
    assert rt.longest_remaining(items, {"Coverage": 38 * MIN}, T0 + 8 * MIN) == 30 * MIN


def test_success_the_longest_of_several_pending_checks_decides():
    items = [check("a", T0), check("b", T0 + 60), check("c", T0)]
    assert rt.longest_remaining(items, {"a": 600, "b": 1800, "c": 900}, T0 + 300) == 1560


def test_success_completed_checks_are_not_counted():
    items = [check("slow", T0, "COMPLETED", "SUCCESS"), check("fast", T0)]
    assert rt.longest_remaining(items, {"slow": 3600, "fast": 120}, T0 + 20) == 100


def test_success_a_check_past_its_usual_time_has_none_left():
    assert rt.longest_remaining([check("Coverage", T0)], {"Coverage": 600}, T0 + 900) == 0


def test_success_a_check_just_queued_counts_from_the_time_it_was_made():
    assert rt.longest_remaining([check("mac", T0, "QUEUED")], {"mac": 1200}, T0 + 10) == 1190


def test_success_a_passed_commit_status_does_not_hide_the_estimate():
    items = [check("Coverage", T0), {"context": "license/cla", "state": "SUCCESS", "startedAt": iso(T0)}]
    assert rt.longest_remaining(items, {"Coverage": 600}, T0) == 600


def test_failure_a_pending_check_with_no_usual_time_gives_no_estimate():
    assert rt.longest_remaining([check("new-check", T0)], {"Coverage": 600}, T0) is None


def test_failure_one_unknown_check_among_known_ones_gives_no_estimate():
    items = [check("Coverage", T0), check("new-check", T0)]
    assert rt.longest_remaining(items, {"Coverage": 600}, T0) is None


def test_failure_a_pending_commit_status_gives_no_estimate():
    items = [check("Coverage", T0), {"context": "codecov/patch", "state": "PENDING", "startedAt": iso(T0)}]
    assert rt.longest_remaining(items, {"Coverage": 600, "codecov/patch": 5}, T0) is None


def test_failure_a_pending_check_with_no_start_time_gives_no_estimate():
    items = [{"name": "Coverage", "status": "IN_PROGRESS", "conclusion": ""}]
    assert rt.longest_remaining(items, {"Coverage": 600}, T0) is None


def test_edge_a_start_time_of_year_1_gives_no_estimate():
    items = [{"name": "Coverage", "status": "QUEUED", "conclusion": "", "startedAt": "0001-01-01T00:00:00Z"}]
    assert rt.longest_remaining(items, {"Coverage": 600}, T0) is None


def test_edge_nothing_pending_gives_no_estimate():
    assert rt.longest_remaining([check("a", T0, "COMPLETED", "SUCCESS")], {"a": 600}, T0) is None


def test_edge_an_empty_rollup_gives_no_estimate():
    assert rt.longest_remaining([], {"a": 600}, T0) is None


def test_edge_a_failed_check_is_not_pending_and_is_not_counted():
    items = [check("bad", T0, "COMPLETED", "FAILURE"), check("b", T0)]
    assert rt.longest_remaining(items, {"b": 60}, T0) == 60


def test_edge_a_completed_check_with_an_unknown_conclusion_is_still_pending_here_too():
    # read_rollup counts it as pending, so the estimate must cover it as well.
    items = [check("odd", T0, "COMPLETED", "STALE")]
    assert rt.read_rollup(items)[0] == 1
    assert rt.longest_remaining(items, {"odd": 300}, T0 + 100) == 200
    assert rt.longest_remaining(items, {}, T0 + 100) is None


def test_edge_a_usual_time_of_zero_leaves_nothing():
    assert rt.longest_remaining([check("a", T0)], {"a": 0}, T0) == 0


def test_edge_a_pending_commit_status_gives_no_estimate_whatever_names_have_a_usual_time():
    # A commit status has no name; "?" is what a nameless item is called.
    items = [{"context": "codecov/patch", "state": "PENDING", "startedAt": iso(T0)}]
    assert rt.longest_remaining(items, {"?": 5, "codecov/patch": 5}, T0) is None


def test_success_the_pending_names_are_those_of_the_check_runs_still_to_finish():
    items = [check("a", T0), check("b", T0, "COMPLETED", "SUCCESS"), check("c", T0, "QUEUED"),
             check("d", T0, "COMPLETED", "FAILURE"),
             {"context": "codecov/patch", "state": "PENDING", "startedAt": iso(T0)}]
    assert rt.pending_names(items) == ["a", "c"]


# --- usual_from_runs -------------------------------------------------------


def runs(*lines):
    return [json.loads(x) for x in lines]


def test_success_a_successful_run_gives_its_duration():
    assert rt.usual_from_runs(runs(main_run("Coverage", 2289))) == {"Coverage": 2289}


def test_success_every_name_gets_its_own_time():
    got = rt.usual_from_runs(runs(main_run("a", 10), main_run("b", 20), main_run("c", 30)))
    assert got == {"a": 10, "b": 20, "c": 30}


def test_edge_two_runs_of_one_name_give_the_longer():
    got = rt.usual_from_runs(runs(main_run("docker", 100), main_run("docker", 400), main_run("docker", 250)))
    assert got == {"docker": 400}


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "timed_out", "skipped", "neutral", "action_required"])
def test_failure_a_run_that_did_not_succeed_is_not_a_usual_time(conclusion):
    assert rt.usual_from_runs(runs(main_run("Coverage", 40, conclusion=conclusion))) == {}


def test_failure_a_run_still_in_progress_is_not_a_usual_time():
    line = {"name": "Coverage", "status": "in_progress", "conclusion": None,
            "started_at": iso(T0), "completed_at": None}
    assert rt.usual_from_runs([line]) == {}


def test_failure_a_run_with_times_that_do_not_parse_is_left_out():
    line = {"name": "Coverage", "status": "completed", "conclusion": "success",
            "started_at": "yesterday", "completed_at": iso(T0)}
    assert rt.usual_from_runs([line, json.loads(main_run("b", 7))]) == {"b": 7}


def test_edge_a_run_that_ends_before_it_starts_is_left_out():
    assert rt.usual_from_runs(runs(main_run("a", -5))) == {}


def test_edge_a_run_that_took_no_time_has_a_usual_time_of_zero():
    assert rt.usual_from_runs(runs(main_run("a", 0))) == {"a": 0}


def test_edge_no_runs_give_no_times():
    assert rt.usual_from_runs([]) == {}


def test_edge_a_run_with_no_name_or_that_is_not_an_object_is_left_out():
    nameless = json.loads(main_run("x", 9))
    nameless["name"] = None
    assert rt.usual_from_runs([nameless, "text", 3, None]) == {}


def test_edge_a_failed_run_does_not_hide_a_successful_one_of_the_same_name():
    got = rt.usual_from_runs(runs(main_run("a", 900, conclusion="failure"), main_run("a", 60)))
    assert got == {"a": 60}


# --- window_wanted with the estimate ---------------------------------------


def test_success_one_pending_check_with_thirty_minutes_left_keeps_the_window_closed(cfg):
    # The defect: one pending check is under `last_few`, and the window opened.
    assert not rt.window_wanted("ci-wait", 1, 30 * MIN, cfg, long_remaining=30 * MIN)


def test_success_the_window_stays_closed_past_the_whole_run_estimate_while_a_check_has_long_to_run(cfg):
    assert not rt.window_wanted("ci-wait", 1, 0, cfg, long_remaining=cfg.lead_s + 1)


def test_success_the_window_opens_when_the_longest_check_is_at_the_lead(cfg):
    assert rt.window_wanted("ci-wait", 12, 30 * MIN, cfg, long_remaining=cfg.lead_s)


def test_success_the_window_opens_for_a_check_past_its_usual_time(cfg):
    assert rt.window_wanted("ci-wait", 1, 30 * MIN, cfg, long_remaining=0)


def test_success_the_landing_and_the_tag_are_open_whatever_the_estimate(cfg):
    assert rt.window_wanted("land", 0, 0, cfg, long_remaining=9999)
    assert rt.window_wanted("tag", 0, 0, cfg, long_remaining=9999)


def test_failure_a_check_that_waits_for_a_runner_keeps_the_window_closed_whatever_the_estimate(cfg):
    assert not rt.window_wanted("ci-wait", 1, 0, cfg, stuck=1, long_remaining=0)


def test_failure_no_estimate_falls_back_to_the_count_of_pending_checks(cfg):
    assert rt.window_wanted("ci-wait", cfg.last_few, 30 * MIN, cfg, long_remaining=None)
    assert not rt.window_wanted("ci-wait", cfg.last_few + 1, cfg.lead_s + 1, cfg, long_remaining=None)


def test_failure_no_estimate_falls_back_to_the_whole_run_estimate(cfg):
    assert rt.window_wanted("ci-wait", 15, cfg.lead_s, cfg, long_remaining=None)


def test_failure_the_estimate_opens_no_window_outside_the_pull_request_ci(cfg):
    for stage in ("release-wait", "post", "done", "ci-failed", "no-pr"):
        assert not rt.window_wanted(stage, 0, 0, cfg, long_remaining=0), stage


def test_edge_nothing_left_opens_the_window_however_many_checks_are_pending(cfg):
    # An estimate of 0 is an estimate: the count rule would keep this closed.
    assert rt.window_wanted("ci-wait", cfg.last_few + 9, cfg.lead_s + 600, cfg, long_remaining=0)


def test_edge_one_second_past_the_lead_is_still_closed(cfg):
    assert not rt.window_wanted("ci-wait", 1, 0, cfg, long_remaining=cfg.lead_s + 1)
    assert rt.window_wanted("ci-wait", 1, 0, cfg, long_remaining=cfg.lead_s)


def test_edge_a_lead_of_zero_opens_only_when_nothing_is_left(cfg):
    cfg.lead_s = 0
    assert not rt.window_wanted("ci-wait", 1, 0, cfg, long_remaining=1)
    assert rt.window_wanted("ci-wait", 1, 0, cfg, long_remaining=0)


# --- the read of main's check runs -----------------------------------------


def test_success_the_read_gives_seconds_per_check_name(cfg):
    run = Asks((0, main_run("Coverage", 2289) + "\n" + main_run("Check (macos-latest)", 1260) + "\n"))
    assert rt.read_usual(cfg, run) == {"Coverage": 2289, "Check (macos-latest)": 1260}


def test_success_the_read_asks_for_the_check_runs_of_main_in_this_repository(cfg):
    run = Asks((0, ""))
    rt.read_usual(cfg, run)
    argv = run.argvs[0]
    assert argv[:2] == ["gh", "api"] and "--paginate" in argv
    assert any(a.startswith("repos/NormB/sipnab/commits/main/check-runs") for a in argv)


def test_failure_a_read_that_fails_gives_nothing_rather_than_an_empty_history(cfg):
    assert rt.read_usual(cfg, Asks((1, "gh: HTTP 502\n"))) is None


def test_failure_a_failed_read_that_prints_check_runs_is_still_a_failed_read(cfg):
    assert rt.read_usual(cfg, Asks((1, main_run("a", 5) + "\n"))) is None


def test_failure_a_read_with_a_line_that_is_not_json_gives_nothing(cfg):
    assert rt.read_usual(cfg, Asks((0, main_run("a", 5) + "\nwarning: something\n"))) is None


def test_edge_a_read_with_no_lines_is_an_empty_history(cfg):
    assert rt.read_usual(cfg, Asks((0, "\n"))) == {}


def test_success_the_usual_times_are_kept_in_the_state_file(cfg):
    run = Asks((0, main_run("Coverage", 2289) + "\n"))
    assert rt.usual_for(cfg, run, ["Coverage"], T0) == {"Coverage": 2289}
    state = json.loads(cfg.state_file.read_text())
    assert state["usual_s"] == {"Coverage": 2289} and state["usual_read_at"] == T0


def test_success_known_names_are_not_read_again(cfg):
    run = Asks((0, main_run("Coverage", 2289) + "\n"))
    for i in range(5):
        assert rt.usual_for(cfg, run, ["Coverage"], T0 + 1000 * i) == {"Coverage": 2289}
    assert len(run.argvs) == 1


def test_failure_a_failed_read_is_not_saved_and_is_made_again_at_the_next_tick(cfg):
    run = Asks((1, "gh: HTTP 502\n"), (0, main_run("Coverage", 2289) + "\n"))
    assert rt.usual_for(cfg, run, ["Coverage"], T0) == {}
    assert not cfg.state_file.exists()
    assert rt.usual_for(cfg, run, ["Coverage"], T0 + 30) == {"Coverage": 2289}
    assert len(run.argvs) == 2


def test_failure_a_failed_read_keeps_the_times_already_saved(cfg):
    run = Asks((0, main_run("a", 50) + "\n"), (1, "gh: HTTP 502\n"))
    rt.usual_for(cfg, run, ["a"], T0)
    assert rt.usual_for(cfg, run, ["a", "b"], T0 + cfg.usual_retry_s) == {"a": 50}
    assert json.loads(cfg.state_file.read_text())["usual_read_at"] == T0


def test_edge_a_name_main_does_not_have_is_asked_for_again_only_after_the_retry_time(cfg):
    run = Asks((0, main_run("a", 50) + "\n"), (0, main_run("a", 50) + "\n" + main_run("b", 70) + "\n"))
    assert rt.usual_for(cfg, run, ["a", "b"], T0) == {"a": 50}
    assert rt.usual_for(cfg, run, ["a", "b"], T0 + cfg.usual_retry_s - 1) == {"a": 50}
    assert len(run.argvs) == 1
    assert rt.usual_for(cfg, run, ["a", "b"], T0 + cfg.usual_retry_s) == {"a": 50, "b": 70}
    assert len(run.argvs) == 2


def test_edge_no_pending_check_means_no_read(cfg):
    run = Asks((0, ""))
    assert rt.usual_for(cfg, run, [], T0) == {}
    assert run.argvs == []


def test_edge_a_state_file_with_times_that_are_not_a_table_is_read_as_none(cfg):
    cfg.state_file.write_text(json.dumps({"usual_s": [1, 2], "usual_read_at": "then", "post_rc": 3}))
    run = Asks((0, main_run("a", 50) + "\n"))
    assert rt.usual_for(cfg, run, ["a"], T0) == {"a": 50}
    assert json.loads(cfg.state_file.read_text())["post_rc"] == 3


def test_edge_a_read_time_in_the_future_does_not_stop_the_next_read(cfg):
    cfg.state_file.write_text(json.dumps({"usual_s": {}, "usual_read_at": T0 + 10_000}))
    run = Asks((0, main_run("a", 50) + "\n"))
    assert rt.usual_for(cfg, run, ["a"], T0) == {"a": 50}


def test_edge_a_later_read_does_not_drop_a_name_main_no_longer_shows(cfg):
    run = Asks((0, main_run("a", 50) + "\n"), (0, main_run("b", 70) + "\n"))
    rt.usual_for(cfg, run, ["a"], T0)
    assert rt.usual_for(cfg, run, ["a", "b"], T0 + cfg.usual_retry_s) == {"a": 50, "b": 70}


# --- read_facts ------------------------------------------------------------


def test_success_the_facts_carry_the_longest_remaining_time(cfg):
    w = World(ci_minutes=10, n_checks=2)
    w.usual = {"job-0": 300, "job-1": 2000}
    f = rt.read_facts(cfg, w, T0 + 30)
    assert f.long_remaining == 2000


def test_edge_facts_read_without_a_time_carry_no_estimate_and_read_no_history(cfg):
    w = World(ci_minutes=10, n_checks=2)
    w.usual = {"job-0": 300, "job-1": 2000}
    assert rt.read_facts(cfg, w).long_remaining is None
    assert w.usual_asks == []


def test_edge_a_merged_pull_request_reads_no_history(cfg):
    w = World()
    w.pr["state"] = "MERGED"
    w.pr["mergeCommit"] = {"oid": MERGE}
    assert rt.read_facts(cfg, w, T0).long_remaining is None
    assert w.usual_asks == []


def test_failure_facts_with_a_history_that_cannot_be_read_carry_no_estimate(cfg):
    w = World(ci_minutes=10, n_checks=2)
    w.usual = None
    assert rt.read_facts(cfg, w, T0 + 30).long_remaining is None


# --- a whole release with one long last check ------------------------------

LONG_END = T0 + 45 * MIN


def long_last_check_world():
    """Twenty checks done in 10 min, and Coverage, which runs until minute 45
    as it did on main."""
    w = World(ci_minutes=10, n_checks=20)
    w.checks.append({"name": "Coverage", "start": T0 + 30, "end": LONG_END, "conclusion": "SUCCESS"})
    w.usual = {f"job-{i}": 600 for i in range(20)}
    w.usual["Coverage"] = LONG_END - (T0 + 30)
    return w


def first_open(w):
    return next(t for t, kind in w.window_log if kind == "open")


def test_success_the_window_stays_closed_until_the_lead_before_the_long_checks_end(cfg):
    w = long_last_check_world()
    assert drive(cfg, w) == 0
    assert first_open(w) >= LONG_END - cfg.lead_s, (first_open(w) - T0) / MIN


def test_success_the_window_still_opens_the_lead_before_the_landing(cfg):
    w = long_last_check_world()
    assert drive(cfg, w) == 0
    assert w.at("land")[2]
    assert w.at("land")[0] - first_open(w) >= cfg.lead_s - cfg.poll


def test_success_the_history_is_read_once_in_a_whole_release(cfg):
    w = long_last_check_world()
    assert drive(cfg, w) == 0
    assert w.usual_asks == [T0]


def test_success_a_resumed_train_uses_the_saved_times_and_reads_nothing(cfg):
    w = long_last_check_world()
    rt.tick(cfg, w, w.clock, w.sleep)
    w.usual = None  # any further read would fail
    w.now = T0 + 20 * MIN
    assert drive(cfg, w) == 0
    assert len(w.usual_asks) == 1
    assert first_open(w) >= LONG_END - cfg.lead_s


def test_success_a_long_check_that_overruns_has_the_window_open_from_its_usual_end(cfg):
    w = long_last_check_world()
    w.usual["Coverage"] = 20 * MIN
    assert drive(cfg, w) == 0
    opened = first_open(w)
    assert T0 + 30 + 20 * MIN - cfg.lead_s <= opened <= T0 + 30 + 20 * MIN - cfg.lead_s + cfg.poll


def test_failure_a_history_that_cannot_be_read_leaves_the_count_rule_and_the_release_completes(cfg):
    w = long_last_check_world()
    w.usual = None
    assert drive(cfg, w) == 0
    # The old rule: open once the last few checks remain, long before Coverage ends.
    assert first_open(w) < T0 + 10 * MIN


def test_failure_a_history_that_cannot_be_read_is_asked_for_at_every_tick_of_the_ci_wait(cfg):
    w = long_last_check_world()
    w.usual = None
    assert drive(cfg, w) == 0
    assert len(w.usual_asks) == 45 * 2
    assert "usual_s" not in json.loads(cfg.state_file.read_text())


def test_failure_a_history_that_comes_back_closes_the_window_the_count_rule_opened(cfg):
    w = long_last_check_world()
    saved, w.usual = w.usual, None
    while w.now < T0 + 12 * MIN:
        rt.tick(cfg, w, w.clock, w.sleep)
        w.sleep(cfg.poll)
    assert w.window is not None
    w.usual = saved
    rt.tick(cfg, w, w.clock, w.sleep)
    assert w.window is None and w.window_log[-1][1] == "close"


def test_failure_a_long_check_main_never_ran_falls_back_to_the_count_rule(cfg):
    w = long_last_check_world()
    del w.usual["Coverage"]
    assert drive(cfg, w) == 0
    assert first_open(w) < T0 + 10 * MIN
    # Asked again every five minutes while Coverage is pending: minutes 0 to 40.
    assert w.usual_asks == [T0 + 300 * i for i in range(9)]


def test_edge_a_long_check_that_waits_for_a_runner_keeps_the_window_closed_with_a_history(cfg):
    w = long_last_check_world()
    real = w.rollup

    def rollup():
        items = real()
        for c in items:
            if c.get("name") == "Coverage" and w.now < T0 + 20 * MIN:
                c["status"] = "QUEUED"
        return items

    w.rollup = rollup
    w.usual["Coverage"] = 60
    seen = []
    real_call = w.__call__

    def spy(argv, timeout):
        # From the tick after the one that first counts it as waiting.
        if "--release-window status" in " ".join(argv) \
                and T0 + 30 + cfg.queued_grace_s + cfg.poll <= w.now < T0 + 20 * MIN:
            seen.append(w.window is None)
        return real_call(argv, timeout)

    assert rt.train(cfg, spy, sleep=w.sleep, clock=w.clock) == 0
    assert seen and all(seen)


def test_edge_the_state_file_of_a_release_holds_the_usual_times(cfg):
    w = long_last_check_world()
    drive(cfg, w)
    state = json.loads(cfg.state_file.read_text())
    assert state["usual_s"] == w.usual and state["usual_read_at"] == T0 and state["post_rc"] == 0
