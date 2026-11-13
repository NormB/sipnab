# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/code-scanning-clean.py: how long it waits for CodeQL, and what it
says when it stops.

The check used to wait a fixed 1500 s from its own start. On 2026-11-10 the
CodeQL run of a pull request head was created at 20:34:16Z and sat queued
for a hosted runner until 21:20:03Z; its Rust analysis was uploaded at
21:31:28Z. The check ran from 21:03:33Z to 21:29:01Z and failed with "no
CodeQL analysis", 147 s before the analysis existed. No alert was open.

The wait now follows the state of the CodeQL workflow run of the commit:
queued or in progress means keep waiting, up to an upper bound. The three
ways of ending without a verdict say different things, and an open alert
still fails.

No test here reaches GitHub. The module's `subprocess.run` and `time.sleep`
raise unless a test replaces them, and the tests that run the script as a
program give it a PATH whose `gh` is a stub that answers from files.
"""

import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

from conftest import SCRIPTS, load

scan = load("code-scanning-clean")

SHA = "4308cf5d6" + "0" * 31
HEAD = "9e6919024" + "f" * 31
OTHER = "59c8c60ef" + "1" * 31
CAT = "/language:rust"


@pytest.fixture(autouse=True)
def _no_network_and_no_real_sleep(monkeypatch):
    """A test that reaches `gh` or sleeps for real, in this process, fails at
    once. The script's own names `subprocess` and `time` are replaced, not
    the modules, which the tests below use themselves to run the script."""

    class Refuse:
        def __init__(self, what):
            self.what = what

        def __getattr__(self, name):
            def refuse(*args, **kwargs):
                raise AssertionError(f"a test reached the real {self.what}.{name}: {args!r}")
            return refuse

    monkeypatch.setattr(scan, "subprocess", Refuse("subprocess"))
    monkeypatch.setattr(scan, "time", Refuse("time"))


def wf_run(status, conclusion=None, run_id=42896593489, created="2026-11-10T20:34:16Z"):
    return {"id": run_id, "status": status, "conclusion": conclusion,
            "created_at": created, "head_sha": HEAD, "event": "pull_request"}


def analysis(sha=SHA, category=CAT):
    return {"commit_sha": sha, "category": category}


def open_alert(sha=SHA, rule="rust/cleartext-logging"):
    return {"number": 7, "state": "open", "rule": {"id": rule},
            "most_recent_instance": {"commit_sha": sha,
                                     "location": {"path": "src/x.rs", "start_line": 12},
                                     "message": {"text": "logged in clear text"}}}


class Clock:
    """A clock that moves only when the code under test sleeps."""

    def __init__(self, step=None):
        self.t = 1000.0
        self.sleeps = []
        self.step = step

    def now(self):
        return self.t

    def sleep(self, secs):
        self.sleeps.append(secs)
        self.t += secs if self.step is None else self.step

    @property
    def waited(self):
        return self.t - 1000.0


class Timeline:
    """Answers that depend on how long the wait has run: `[(from_secs, value)]`."""

    def __init__(self, clock, points):
        self.clock = clock
        self.points = points
        self.calls = 0

    def __call__(self):
        self.calls += 1
        value = None
        for start, v in self.points:
            if self.clock.waited >= start:
                value = v
        return value


def wait(clock, analyses, runs, wait_secs=600, max_wait_secs=5400, settle_secs=120, poll_secs=30):
    a = Timeline(clock, analyses)
    r = Timeline(clock, runs)
    out = scan.wait_for_analysis(
        a, r, SHA, CAT, wait_secs=wait_secs, max_wait_secs=max_wait_secs,
        settle_secs=settle_secs, poll_secs=poll_secs, now=clock.now, sleep=clock.sleep)
    return out, a, r


# ---- the state of the CodeQL run -------------------------------------------


def test_a_queued_run_is_pending():
    assert scan.codeql_state([wf_run("queued")])[0] == scan.PENDING


def test_a_run_in_progress_is_pending():
    assert scan.codeql_state([wf_run("in_progress")])[0] == scan.PENDING


@pytest.mark.parametrize("status", ["waiting", "requested", "pending"])
def test_every_status_before_completed_is_pending(status):
    assert scan.codeql_state([wf_run(status)])[0] == scan.PENDING


def test_a_completed_run_is_finished():
    assert scan.codeql_state([wf_run("completed", "success")])[0] == scan.FINISHED


def test_a_failed_run_is_finished_and_the_detail_names_its_conclusion():
    state, detail = scan.codeql_state([wf_run("completed", "failure")])
    assert state == scan.FINISHED
    assert "failure" in detail and "42896593489" in detail


def test_a_canceled_run_is_finished_and_the_detail_says_so():
    state, detail = scan.codeql_state([wf_run("completed", "cancelled")])
    assert (state, "cancelled" in detail) == (scan.FINISHED, True)


def test_no_run_at_all_is_absent():
    assert scan.codeql_state([]) == (scan.ABSENT, "")


def test_an_unreadable_answer_is_unreadable():
    assert scan.codeql_state(None)[0] == scan.UNREADABLE


def test_one_run_done_and_one_queued_is_pending():
    runs = [wf_run("completed", "failure", run_id=1), wf_run("queued", run_id=2)]
    state, detail = scan.codeql_state(runs)
    assert state == scan.PENDING
    assert "2" in detail and "queued" in detail


def test_the_pending_detail_names_the_run_its_status_and_when_it_was_created():
    _, detail = scan.codeql_state([wf_run("queued")])
    assert "42896593489" in detail and "queued" in detail and "2026-11-10T20:34:16Z" in detail


@pytest.mark.parametrize("junk", [["text"], [7], [None], [{}], [{"status": None}], [{"status": 3}]])
def test_a_run_with_no_readable_status_is_unreadable_not_finished(junk):
    assert scan.codeql_state(junk)[0] == scan.UNREADABLE


def test_one_unreadable_entry_beside_a_queued_run_is_still_unreadable():
    assert scan.codeql_state([wf_run("queued"), "text"])[0] == scan.UNREADABLE


# ---- the wait: it ends with an analysis ------------------------------------


def test_an_analysis_at_the_first_read_returns_at_once_and_never_asks_for_runs():
    clock = Clock()
    (analyses, state, _detail, waited), a, r = wait(clock, [(0, [analysis()])], [(0, [wf_run("queued")])])
    assert scan.analysis_covers(analyses, SHA, CAT)
    assert (state, waited, clock.sleeps, a.calls, r.calls) == (scan.COVERED, 0, [], 1, 0)


def test_the_queue_of_2026_11_10_is_waited_out():
    """The check starts 1757 s after the run was created; the run starts
    990 s into the wait and the analysis exists 1675 s into it. The old
    fixed wait gave up at 1500 s."""
    clock = Clock()
    (analyses, state, _detail, waited), _a, _r = wait(
        clock,
        [(0, [analysis(OTHER)]), (1675, [analysis(OTHER), analysis()])],
        [(0, [wf_run("queued")]), (990, [wf_run("in_progress")]), (1684, [wf_run("completed", "success")])],
    )
    assert state == scan.COVERED
    assert scan.analysis_covers(analyses, SHA, CAT)
    assert 1675 <= waited < 1675 + 30
    assert waited > 1500


def test_a_run_in_progress_is_waited_for():
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(
        clock, [(0, []), (700, [analysis()])], [(0, [wf_run("in_progress")])], wait_secs=0)
    assert (state, 700 <= waited < 730) == (scan.COVERED, True)


def test_an_analysis_that_appears_just_after_the_run_completes_is_found():
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(
        clock, [(0, []), (90, [analysis()])], [(0, [wf_run("completed", "success")])], wait_secs=0)
    assert (state, waited) == (scan.COVERED, 90)


def test_a_run_that_does_not_exist_yet_then_queues_then_uploads_is_waited_for():
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(
        clock, [(0, []), (2000, [analysis()])],
        [(0, []), (60, [wf_run("queued")])], wait_secs=300)
    assert (state, 2000 <= waited < 2030) == (scan.COVERED, True)


def test_an_unreadable_run_state_that_recovers_is_waited_through():
    clock = Clock()
    (_an, state, _d, _w), _a, _r = wait(
        clock, [(0, []), (900, [analysis()])],
        [(0, None), (120, [wf_run("queued")])], wait_secs=300)
    assert state == scan.COVERED


def test_an_unreadable_analyses_answer_that_recovers_is_waited_through():
    clock = Clock()
    (analyses, state, _d, _w), _a, _r = wait(
        clock, [(0, None), (60, [analysis()])], [(0, [wf_run("in_progress")])])
    assert (state, analyses) == (scan.COVERED, [analysis()])


def test_a_rerun_after_a_failed_run_starts_the_wait_again():
    """completed -> queued again (a re-run) -> analysis: the settle time of
    the first completion must not end the wait."""
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(
        clock, [(0, []), (1500, [analysis()])],
        [(0, [wf_run("completed", "failure")]), (60, [wf_run("queued")]),
         (1400, [wf_run("in_progress")])], wait_secs=0)
    assert (state, 1500 <= waited < 1530) == (scan.COVERED, True)


def test_a_rerun_that_completes_gets_a_settle_time_of_its_own():
    """completed, queued again, completed again at 1400 s, upload at 1490 s.
    The settle time counts from the second completion, not the first."""
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(
        clock, [(0, []), (1490, [analysis()])],
        [(0, [wf_run("completed", "failure")]), (60, [wf_run("queued")]),
         (1400, [wf_run("completed", "success")])], wait_secs=0)
    assert (state, 1490 <= waited < 1520) == (scan.COVERED, True)


def test_the_analysis_of_this_commit_among_others_ends_the_wait():
    clock = Clock()
    listing = [analysis(SHA, "/language:actions"), analysis(OTHER), analysis()]
    (_an, state, _d, waited), _a, _r = wait(clock, [(0, listing)], [(0, [])])
    assert (state, waited) == (scan.COVERED, 0)


# ---- the wait: it ends without one -----------------------------------------


def test_a_run_queued_forever_stops_at_the_upper_bound_and_is_reported_pending():
    clock = Clock()
    (_an, state, detail, waited), _a, _r = wait(clock, [(0, [])], [(0, [wf_run("queued")])])
    assert state == scan.PENDING
    assert 5400 <= waited < 5400 + 30
    assert "queued" in detail


def test_a_run_in_progress_forever_stops_at_the_upper_bound():
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(
        clock, [(0, [])], [(0, [wf_run("in_progress")])], max_wait_secs=900)
    assert (state, 900 <= waited < 930) == (scan.PENDING, True)


def test_a_completed_run_with_no_analysis_stops_after_the_settle_time_not_the_bound():
    clock = Clock()
    (_an, state, detail, waited), _a, _r = wait(
        clock, [(0, [])], [(0, [wf_run("completed", "failure")])])
    assert state == scan.FINISHED
    assert 120 <= waited < 150
    assert "failure" in detail


def test_no_run_and_no_analysis_stops_after_wait_secs_not_the_bound():
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(clock, [(0, [])], [(0, [])])
    assert (state, 600 <= waited < 630) == (scan.ABSENT, True)


def test_an_unreadable_run_state_stops_after_wait_secs_not_the_bound():
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(clock, [(0, [])], [(0, None)])
    assert (state, 600 <= waited < 630) == (scan.UNREADABLE, True)


def test_unreadable_analyses_under_a_queued_run_stop_at_the_bound_and_stay_unreadable():
    clock = Clock()
    (analyses, state, _d, waited), _a, _r = wait(
        clock, [(0, None)], [(0, [wf_run("queued")])], wait_secs=0, max_wait_secs=300)
    assert (analyses, state, 300 <= waited < 330) == (None, scan.PENDING, True)


def test_an_analysis_in_another_category_never_ends_the_wait():
    clock = Clock()
    (analyses, state, _d, _w), _a, _r = wait(
        clock, [(0, [analysis(SHA, "/language:actions")])], [(0, [wf_run("completed", "success")])])
    assert state == scan.FINISHED
    assert not scan.analysis_covers(analyses, SHA, CAT)


def test_an_analysis_of_another_commit_never_ends_the_wait():
    clock = Clock()
    (_an, state, _d, _w), _a, _r = wait(clock, [(0, [analysis(OTHER)])], [(0, [])], wait_secs=60)
    assert state == scan.ABSENT


def test_a_run_that_completes_late_without_an_analysis_is_reported_finished():
    clock = Clock()
    (_an, state, detail, waited), _a, _r = wait(
        clock, [(0, [])],
        [(0, [wf_run("queued")]), (1200, [wf_run("completed", "cancelled")])])
    assert state == scan.FINISHED
    assert 1320 <= waited < 1350
    assert "cancelled" in detail


def test_a_run_that_vanishes_is_reported_absent_after_wait_secs_from_the_start():
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(
        clock, [(0, [])], [(0, [wf_run("queued")]), (900, [])], wait_secs=600)
    assert (state, 900 <= waited < 930) == (scan.ABSENT, True)


# ---- the wait: edges -------------------------------------------------------


@pytest.mark.parametrize("runs, expected", [
    ([wf_run("queued")], "pending"),
    ([wf_run("completed", "success")], "finished"),
    ([], "absent"),
    (None, "unreadable"),
])
def test_with_no_wait_at_all_each_state_is_read_once_and_nothing_sleeps(runs, expected):
    clock = Clock()
    (_an, state, _d, waited), a, r = wait(
        clock, [(0, [])], [(0, runs)], wait_secs=0, max_wait_secs=0)
    assert (state, waited, clock.sleeps, a.calls, r.calls) == (expected, 0, [], 1, 1)


def test_an_upper_bound_below_wait_secs_does_not_shorten_the_wait_for_a_queued_run():
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(
        clock, [(0, [])], [(0, [wf_run("queued")])], wait_secs=600, max_wait_secs=0)
    assert (state, 600 <= waited < 630) == (scan.PENDING, True)


def test_the_settle_time_never_passes_the_upper_bound():
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(
        clock, [(0, [])], [(0, [wf_run("completed", "success")])],
        wait_secs=0, max_wait_secs=60, settle_secs=600)
    assert (state, 60 <= waited < 90) == (scan.FINISHED, True)


def test_the_poll_interval_is_the_one_asked_for():
    clock = Clock()
    wait(clock, [(0, [])], [(0, [wf_run("queued")])], max_wait_secs=100, poll_secs=7)
    assert set(clock.sleeps) == {7}


def test_the_bound_is_measured_on_the_clock_not_in_polls():
    """Each 30 s sleep takes 400 s of clock: the wait ends by the clock."""
    clock = Clock(step=400)
    (_an, state, _d, waited), _a, _r = wait(
        clock, [(0, [])], [(0, [wf_run("queued")])], max_wait_secs=1000)
    assert (state, len(clock.sleeps), waited) == (scan.PENDING, 3, 1200)


def test_a_wait_that_reaches_the_bound_exactly_stops():
    clock = Clock()
    (_an, _state, _d, waited), _a, _r = wait(
        clock, [(0, [])], [(0, [wf_run("queued")])], wait_secs=0, max_wait_secs=90)
    assert (waited, len(clock.sleeps)) == (90, 3)


def test_the_settle_time_starts_when_the_run_is_first_seen_completed():
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(
        clock, [(0, [])], [(0, [wf_run("in_progress")]), (300, [wf_run("completed", "success")])])
    assert (state, waited) == (scan.FINISHED, 420)


def test_zero_settle_time_reports_a_completed_run_at_once():
    clock = Clock()
    (_an, state, _d, waited), _a, _r = wait(
        clock, [(0, [])], [(0, [wf_run("completed", "success")])], settle_secs=0)
    assert (state, waited) == (scan.FINISHED, 0)


def test_the_analyses_are_read_before_the_runs_on_every_poll():
    clock = Clock()
    (_an, _s, _d, _w), a, r = wait(
        clock, [(0, []), (60, [analysis()])], [(0, [wf_run("queued")])])
    assert (a.calls, r.calls) == (3, 2)


# ---- the verdict and its message -------------------------------------------


def verdict(alerts, analyses, state=None, detail="run 1 queued", waited=None):
    codeql = None if state is None else (state, detail)
    return scan.judge(alerts, analyses, SHA, CAT, codeql=codeql, waited=waited)


def test_a_pending_run_says_the_analysis_is_still_queued_or_running():
    rc, msg = verdict([], [], scan.PENDING, "run 42896593489 queued", waited=5400)
    assert rc == 2
    assert "still queued or running" in msg
    assert "42896593489" in msg and "5400 s" in msg and SHA[:8] in msg


def test_a_pending_run_is_not_reported_as_a_missing_analysis():
    _, msg = verdict([], [], scan.PENDING)
    assert "no CodeQL analysis" not in msg


def test_a_finished_run_without_an_analysis_says_no_analysis_exists_and_why():
    rc, msg = verdict([], [], scan.FINISHED, "run 9 completed: failure")
    assert rc == 2
    assert "no CodeQL analysis" in msg and "run 9 completed: failure" in msg
    assert "still queued" not in msg


def test_no_run_says_no_analysis_and_no_run_exist():
    rc, msg = verdict([], [], scan.ABSENT, "")
    assert rc == 2
    assert "no CodeQL analysis" in msg and "no CodeQL run" in msg


def test_an_unreadable_run_state_says_so():
    rc, msg = verdict([], [], scan.UNREADABLE, "")
    assert rc == 2
    assert "could not be read" in msg and "CodeQL run" in msg


def test_without_a_run_state_the_old_message_stands():
    rc, msg = verdict([], [])
    assert (rc, "no CodeQL analysis" in msg, "exists yet" in msg) == (2, True, True)


def test_the_four_endings_without_a_verdict_read_differently():
    msgs = {verdict([], [], s, "run 1 x")[1]
            for s in (scan.PENDING, scan.FINISHED, scan.ABSENT, scan.UNREADABLE)}
    msgs.add(verdict([], [])[1])
    assert len(msgs) == 5


@pytest.mark.parametrize("state", [None, "pending", "finished", "absent", "unreadable", "covered"])
def test_an_open_alert_on_an_analyzed_commit_fails_whatever_the_run_state(state):
    rc, msg = verdict([open_alert()], [analysis()], state)
    assert rc == 1
    assert "rust/cleartext-logging" in msg and "src/x.rs:12" in msg


@pytest.mark.parametrize("state", [None, "pending", "finished", "absent", "unreadable", "covered"])
def test_a_clean_analyzed_commit_passes_whatever_the_run_state(state):
    rc, msg = verdict([], [analysis()], state)
    assert (rc, "clean" in msg) == (0, True)


def test_an_open_alert_without_an_analysis_is_not_a_pass_under_a_pending_run():
    rc, _ = verdict([open_alert()], [], scan.PENDING)
    assert rc == 2


def test_unreadable_alerts_are_refused_under_a_pending_run():
    rc, msg = verdict(None, [analysis()], scan.PENDING)
    assert (rc, "could not be read" in msg) == (2, True)


def test_a_stale_alert_is_still_not_judged_after_the_wait():
    rc, msg = verdict([open_alert(OTHER)], [analysis()], scan.COVERED)
    assert (rc, "not yet re-evaluated" in msg) == (2, True)


def test_the_time_waited_is_left_out_when_it_is_not_known():
    _, msg = verdict([], [], scan.PENDING, waited=None)
    assert "after" not in msg


# ---- the script as a program: fixture mode ---------------------------------


def fixture_run(tmp_path, alerts, analyses, runs=None, runs_text=None, extra=()):
    (tmp_path / "alerts.json").write_text(json.dumps(alerts))
    (tmp_path / "analyses.json").write_text(json.dumps(analyses))
    argv = [sys.executable, str(SCRIPTS / "code-scanning-clean.py"), "--sha", SHA,
            "--alerts-json", str(tmp_path / "alerts.json"),
            "--analyses-json", str(tmp_path / "analyses.json"), *extra]
    if runs is not None or runs_text is not None:
        (tmp_path / "runs.json").write_text(runs_text if runs_text is not None else json.dumps(runs))
        argv += ["--runs-json", str(tmp_path / "runs.json")]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=60,
                       env={"PATH": str(tmp_path / "no-such-dir")})
    return p.returncode, p.stdout + p.stderr


def test_fixture_mode_with_a_queued_run_exits_2_and_says_still_queued(tmp_path):
    rc, out = fixture_run(tmp_path, [], [analysis(OTHER)], [wf_run("queued")])
    assert (rc, "still queued or running" in out) == (2, True), out


def test_fixture_mode_with_a_failed_run_exits_2_and_says_no_analysis(tmp_path):
    rc, out = fixture_run(tmp_path, [], [], [wf_run("completed", "failure")])
    assert rc == 2, out
    assert "no CodeQL analysis" in out and "completed: failure" in out


def test_fixture_mode_with_no_run_exits_2_and_says_no_run(tmp_path):
    rc, out = fixture_run(tmp_path, [], [], [])
    assert (rc, "no CodeQL run" in out) == (2, True), out


def test_fixture_mode_with_runs_that_are_not_json_exits_2_and_says_unreadable(tmp_path):
    rc, out = fixture_run(tmp_path, [], [], runs_text="<html>502</html>")
    assert (rc, "could not be read" in out) == (2, True), out


def test_fixture_mode_open_alert_exits_1_under_a_queued_run(tmp_path):
    rc, out = fixture_run(tmp_path, [open_alert()], [analysis()], [wf_run("queued")])
    assert (rc, "1 open alert" in out) == (1, True), out


def test_fixture_mode_clean_exits_0_with_a_completed_run(tmp_path):
    rc, out = fixture_run(tmp_path, [], [analysis()], [wf_run("completed", "success")])
    assert (rc, "clean" in out) == (0, True), out


# ---- the script as a program: live mode against a stub `gh` ----------------

STUB_GH = """#!{python}
import os, pathlib, sys
d = pathlib.Path(os.environ["STUB_GH_DIR"])
with open(d / "calls.log", "a") as log:
    log.write(" ".join(sys.argv[1:]) + "\\n")
path = next(a for a in sys.argv[1:] if a.startswith("repos/"))
kind = ("analyses" if "/code-scanning/analyses" in path
        else "alerts" if "/code-scanning/alerts" in path
        else "runs" if "/actions/workflows/" in path else None)
if kind is None:
    sys.stderr.write("stub gh: unexpected path " + path + "\\n")
    sys.exit(97)
counter = d / (kind + ".count")
n = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(n + 1))
while n > 0 and not (d / f"{{kind}}.{{n}}").exists():
    n -= 1
body = (d / f"{{kind}}.{{n}}").read_text()
if body.startswith("FAIL"):
    sys.stderr.write("stub gh: HTTP 403\\n")
    sys.exit(1)
sys.stdout.write(body)
"""


def live(tmp_path, analyses, runs, alerts, *args):
    """Run the script in live mode. Each of `analyses`, `runs` and `alerts` is
    the list of successive answers; the last one repeats. "FAIL" is an error."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(STUB_GH.format(python=sys.executable))
    gh.chmod(0o755)
    for kind, answers in (("analyses", analyses), ("runs", runs), ("alerts", alerts)):
        for i, answer in enumerate(answers):
            (tmp_path / f"{kind}.{i}").write_text(answer if answer == "FAIL" else json.dumps(answer))
    p = subprocess.run(
        [sys.executable, str(SCRIPTS / "code-scanning-clean.py"), "--sha", SHA,
         "--repo", "example/repo", "--ref", "refs/pull/1/merge", "--poll-secs", "0", *args],
        capture_output=True, text=True, timeout=60,
        env={"PATH": str(bin_dir), "STUB_GH_DIR": str(tmp_path)})
    calls = (tmp_path / "calls.log").read_text().splitlines() if (tmp_path / "calls.log").exists() else []
    return p.returncode, p.stdout + p.stderr, calls


def test_live_a_queued_then_running_run_is_waited_for_and_a_clean_commit_passes(tmp_path):
    rc, out, calls = live(
        tmp_path, [[], [], [], [analysis()]],
        [[wf_run("queued")], [wf_run("queued")], [wf_run("in_progress")]], [[]],
        "--head-sha", HEAD, "--max-wait-secs", "30")
    assert (rc, "clean" in out) == (0, True), out
    assert sum("/code-scanning/analyses" in c for c in calls) == 4, calls


def test_live_an_open_alert_found_after_the_wait_fails(tmp_path):
    rc, out, _ = live(
        tmp_path, [[], [analysis()]], [[wf_run("in_progress")]], [[open_alert()]],
        "--head-sha", HEAD, "--max-wait-secs", "30")
    assert (rc, "1 open alert" in out and "rust/cleartext-logging" in out) == (1, True), out


def test_live_the_runs_are_asked_for_by_head_sha_and_workflow(tmp_path):
    _, _, calls = live(tmp_path, [[]], [[]], [[]], "--head-sha", HEAD)
    runs_calls = [c for c in calls if "/actions/workflows/" in c]
    assert len(runs_calls) == 1, calls
    assert f"repos/example/repo/actions/workflows/codeql.yml/runs?head_sha={HEAD}" in runs_calls[0]
    # The endpoint answers with an object; the list is its `workflow_runs`.
    assert "--paginate" in runs_calls[0] and "--jq .workflow_runs" in runs_calls[0]


def test_live_without_head_sha_the_runs_are_asked_for_by_sha(tmp_path):
    _, _, calls = live(tmp_path, [[]], [[]], [[]])
    assert any(f"runs?head_sha={SHA}" in c for c in calls), calls


def test_live_another_workflow_file_can_be_named(tmp_path):
    _, _, calls = live(tmp_path, [[]], [[]], [[]], "--workflow", "scan.yml")
    assert any("/actions/workflows/scan.yml/runs?" in c for c in calls), calls


def test_live_a_run_still_queued_at_the_bound_exits_2_and_says_so(tmp_path):
    rc, out, _ = live(tmp_path, [[]], [[wf_run("queued")]], [[]], "--head-sha", HEAD)
    assert rc == 2, out
    assert "still queued or running" in out and "42896593489" in out


def test_live_a_failed_run_exits_2_and_says_no_analysis_exists(tmp_path):
    rc, out, _ = live(tmp_path, [[]], [[wf_run("completed", "failure")]], [[]],
                      "--head-sha", HEAD, "--max-wait-secs", "20", "--settle-secs", "0")
    assert rc == 2, out
    assert "no CodeQL analysis" in out and "completed: failure" in out
    # The run had failed, so the wait ends at the first answer and not at
    # --max-wait-secs. The seconds are the real clock's, around two `gh`
    # stand-ins this test starts: 0 on an idle host, 1 or more on a loaded
    # one (a pre-commit run on 2026-11-13 printed "after 1 s").
    waited = re.search(r" after (\d+) s:", out)
    assert waited and int(waited.group(1)) < 20, out


def test_live_no_run_exits_2_and_says_no_run(tmp_path):
    rc, out, _ = live(tmp_path, [[]], [[]], [[]], "--head-sha", HEAD)
    assert (rc, "no CodeQL run" in out) == (2, True), out


def test_live_a_runs_answer_gh_cannot_fetch_exits_2_and_says_unreadable(tmp_path):
    rc, out, _ = live(tmp_path, [[]], ["FAIL"], [[]], "--head-sha", HEAD)
    assert rc == 2, out
    assert "state of the CodeQL run could not be read" in out


def test_live_an_alerts_answer_gh_cannot_fetch_is_refused_after_a_good_wait(tmp_path):
    rc, out, _ = live(tmp_path, [[analysis()]], [[]], ["FAIL"], "--head-sha", HEAD)
    assert (rc, "could not be read" in out) == (2, True), out


def test_live_an_analysis_at_once_never_asks_for_the_runs(tmp_path):
    rc, _, calls = live(tmp_path, [[analysis()]], [[wf_run("queued")]], [[]], "--head-sha", HEAD)
    assert rc == 0
    assert not any("/actions/workflows/" in c for c in calls), calls


# ---- the CI job ------------------------------------------------------------


def ci_job():
    ci = (SCRIPTS.parent / ".github/workflows/ci.yml").read_text()
    start = ci.index("\n  code-scanning-clean:\n")
    end = ci.index("\n  ci-success:\n", start)
    return ci[start:end]


def test_the_ci_job_names_the_pull_request_head_for_the_run_lookup():
    """On a pull request `github.sha` is the merge commit, which the analysis
    is of; the CodeQL run is of the branch head."""
    job = ci_job()
    assert "HEAD_SHA: ${{ github.event.pull_request.head.sha || github.sha }}\n" in job
    assert ' --head-sha "$HEAD_SHA" ' in job
    assert ' --sha "${{ github.sha }}" ' in job


def test_the_ci_job_bounds_the_wait_for_a_queued_run_well_above_the_old_25_minutes():
    m = re.search(r"--max-wait-secs (\d+)", ci_job())
    assert m and int(m.group(1)) >= 3600, ci_job()


def test_the_ci_job_outlives_its_own_upper_bound():
    job = ci_job()
    bound = int(re.search(r"--max-wait-secs (\d+)", job).group(1))
    minutes = int(re.search(r"timeout-minutes: (\d+)", job).group(1))
    assert minutes * 60 >= bound + 300, (minutes, bound)


def test_the_ci_job_may_read_workflow_runs_and_alerts_and_nothing_more():
    job = ci_job()
    block = job[job.index("    permissions:\n"):job.index("    steps:\n")]
    granted = sorted(line.strip() for line in block.splitlines()[1:]
                     if line.strip() and not line.strip().startswith("#"))
    assert granted == ["actions: read", "contents: read", "security-events: read"]


def test_the_ci_job_still_waits_for_a_run_that_has_not_been_created():
    m = re.search(r"--wait-secs (\d+)", ci_job())
    assert m and 120 <= int(m.group(1)) <= 1500, ci_job()
