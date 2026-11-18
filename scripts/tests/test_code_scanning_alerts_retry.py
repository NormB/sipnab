# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/code-scanning-clean.py: the open-alerts answer is read again
when it cannot be judged yet (backlog GATE-CSRETRY1).

The analyses and the CodeQL runs are read inside a polling loop; the open
alerts were read exactly once, after it. One failed `gh api` call there (a
GitHub 5xx, a dropped connection) made the gate exit 2, "refusing to judge",
and turned `CI success` red on the pull request. The same one-shot read made
an answer whose alerts GitHub had not yet re-evaluated on the commit
("not yet re-evaluated", also exit 2) final, although GitHub re-evaluates
them shortly after the analysis is uploaded.

The alerts are now read up to --alerts-attempts times, --poll-secs apart,
while the answer is unreadable or names an open alert last seen on an older
commit. The gate still fails closed: when no read gives a judgeable answer
it exits 2, and an open alert on the commit still exits 1.

No test here reaches GitHub: `subprocess` and `time` in the module raise
unless a test replaces them, and the program runs against a stub `gh`.
"""

import json
import re
import subprocess
import sys

import pytest

from conftest import SCRIPTS, load

scan = load("code-scanning-clean")

SHA = "4308cf5d6" + "0" * 31
OLD = "59c8c60ef" + "1" * 31
CAT = "/language:rust"


@pytest.fixture(autouse=True)
def _no_network_and_no_real_sleep(monkeypatch):
    class Refuse:
        def __init__(self, what):
            self.what = what

        def __getattr__(self, name):
            def refuse(*args, **kwargs):
                raise AssertionError(f"a test reached the real {self.what}.{name}: {args!r}")
            return refuse

    monkeypatch.setattr(scan, "subprocess", Refuse("subprocess"))
    monkeypatch.setattr(scan, "time", Refuse("time"))


def alert(sha=SHA, state="open", rule="rust/cleartext-logging"):
    return {"number": 7, "state": state, "rule": {"id": rule},
            "most_recent_instance": {"commit_sha": sha,
                                     "location": {"path": "src/x.rs", "start_line": 12},
                                     "message": {"text": "logged in clear text"}}}


class Answers:
    """Successive answers of the alerts endpoint; the last one repeats."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = 0

    def __call__(self):
        value = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return value


class Sleeps:
    def __init__(self):
        self.calls = []

    def __call__(self, secs):
        self.calls.append(secs)


def read(*answers, attempts=6, poll_secs=30):
    fetch, sleep = Answers(*answers), Sleeps()
    alerts, reads = scan.read_alerts(fetch, SHA, attempts=attempts, poll_secs=poll_secs, sleep=sleep)
    return alerts, reads, fetch, sleep


# ---- success: an answer that could not be judged is read again -------------


@pytest.mark.parametrize("failures", [1, 2, 3, 4, 5])
def test_an_unreadable_answer_that_recovers_within_the_attempts_is_used(failures):
    alerts, reads, fetch, _ = read(*([None] * failures), [])
    assert alerts == [], f"after {failures} unreadable answers the readable one is the result"
    assert reads == failures + 1 == fetch.calls, (reads, fetch.calls)


def test_a_readable_first_answer_is_read_once_and_never_waits():
    alerts, reads, fetch, sleep = read([])
    assert (alerts, reads, fetch.calls, sleep.calls) == ([], 1, 1, []), "one read, no sleep"


def test_an_open_alert_on_the_commit_is_final_at_the_first_read():
    alerts, reads, _, sleep = read([alert()])
    assert reads == 1 and sleep.calls == [], "an alert found on this commit needs no second read"
    assert alerts == [alert()], alerts


def test_a_stale_answer_that_is_re_evaluated_clean_is_used():
    alerts, reads, _, _ = read([alert(OLD)], [])
    assert (alerts, reads) == ([], 2), (alerts, reads)


def test_a_stale_answer_that_is_re_evaluated_to_an_alert_on_the_commit_is_used():
    alerts, reads, _, _ = read([alert(OLD)], [alert(SHA)])
    assert (alerts, reads) == ([alert(SHA)], 2), (alerts, reads)


def test_unreadable_then_stale_then_clean_reads_three_times():
    alerts, reads, _, _ = read(None, [alert(OLD)], [])
    assert (alerts, reads) == ([], 3), (alerts, reads)


def test_each_wait_between_reads_is_the_poll_interval():
    _, reads, _, sleep = read(None, None, [], poll_secs=17)
    assert sleep.calls == [17, 17] and reads == 3, sleep.calls


def test_only_dismissed_alerts_on_an_older_commit_are_not_stale():
    alerts, reads, _, _ = read([alert(OLD, state="dismissed")])
    assert reads == 1, "a dismissed alert is no finding, so its commit does not matter"
    assert alerts == [alert(OLD, state="dismissed")]


def test_fixed_alerts_on_an_older_commit_are_not_stale():
    _, reads, _, _ = read([alert(OLD, state="fixed")])
    assert reads == 1, "a fixed alert is no finding"


def test_the_verdict_after_a_recovered_read_is_clean():
    alerts, reads, _, _ = read(None, [])
    rc, msg = scan.judge(alerts, [{"commit_sha": SHA, "category": CAT}], SHA, CAT, alert_reads=reads)
    assert (rc, "clean" in msg) == (0, True), msg


def test_the_verdict_after_a_recovered_read_still_fails_on_an_alert():
    alerts, reads, _, _ = read(None, [alert()])
    rc, msg = scan.judge(alerts, [{"commit_sha": SHA, "category": CAT}], SHA, CAT, alert_reads=reads)
    assert (rc, "1 open alert" in msg) == (1, True), msg


# ---- failure: no judgeable answer still refuses ---------------------------


@pytest.mark.parametrize("attempts", [1, 2, 3, 4, 5, 6])
def test_an_answer_unreadable_at_every_attempt_is_none_after_exactly_that_many_reads(attempts):
    alerts, reads, fetch, sleep = read(None, attempts=attempts)
    assert alerts is None, "no readable answer must stay unreadable, never become a pass"
    assert reads == attempts == fetch.calls, (reads, fetch.calls)
    assert len(sleep.calls) == attempts - 1, f"no sleep after the last read: {sleep.calls}"


@pytest.mark.parametrize("attempts", [1, 3, 6])
def test_an_answer_stale_at_every_attempt_is_returned_after_that_many_reads(attempts):
    alerts, reads, _, _ = read([alert(OLD)], attempts=attempts)
    assert alerts == [alert(OLD)] and reads == attempts, (alerts, reads)


def test_an_unreadable_answer_after_every_attempt_exits_2_and_says_how_many_reads():
    alerts, reads, _, _ = read(None, attempts=4)
    rc, msg = scan.judge(alerts, [{"commit_sha": SHA, "category": CAT}], SHA, CAT, alert_reads=reads)
    assert rc == 2, msg
    assert "could not be read" in msg and "4 reads" in msg, msg


def test_a_stale_answer_after_every_attempt_exits_2_and_says_how_many_reads():
    alerts, reads, _, _ = read([alert(OLD)], attempts=3)
    rc, msg = scan.judge(alerts, [{"commit_sha": SHA, "category": CAT}], SHA, CAT, alert_reads=reads)
    assert rc == 2, msg
    assert "not yet re-evaluated" in msg and "3 reads" in msg, msg


def test_a_stale_alert_beside_a_fresh_one_is_still_retried_and_refused():
    alerts, reads, _, _ = read([alert(SHA), alert(OLD)], attempts=2)
    assert reads == 2, "one stale alert keeps the answer unjudgeable"
    rc, _ = scan.judge(alerts, [{"commit_sha": SHA, "category": CAT}], SHA, CAT, alert_reads=reads)
    assert rc == 2, "a stale alert refuses to judge rather than fail on the fresh one alone"


def test_an_open_alert_with_no_instance_is_stale_and_retried():
    bare = {"number": 8, "state": "open", "rule": {"id": "r"}}
    _, reads, _, _ = read([bare], attempts=3)
    assert reads == 3, "an alert with no known commit is not judged on this commit"


# ---- edge cases -----------------------------------------------------------


def test_one_attempt_never_sleeps():
    _, reads, _, sleep = read(None, attempts=1)
    assert (reads, sleep.calls) == (1, []), sleep.calls


def test_no_sleep_follows_the_read_that_answered():
    _, _, _, sleep = read(None, [], poll_secs=5)
    assert sleep.calls == [5], sleep.calls


def test_an_empty_list_is_readable_and_distinct_from_none():
    alerts, reads, _, _ = read([])
    assert alerts == [] and alerts is not None and reads == 1


def test_entries_that_are_not_objects_do_not_make_the_answer_stale():
    _, reads, _, _ = read(["junk", 3, None])
    assert reads == 1, "open_alerts ignores non-objects, so nothing is stale"


def test_the_read_stops_at_the_first_judgeable_answer_even_if_later_ones_differ():
    alerts, reads, fetch, _ = read([], [alert()], None)
    assert (alerts, reads, fetch.calls) == ([], 1, 1)


def test_the_answers_are_returned_unchanged():
    answer = [alert(OLD, state="dismissed"), alert(SHA)]
    alerts, _, _, _ = read(answer)
    assert alerts is answer, "the answer is passed on as read"


def test_a_zero_poll_interval_still_reads_every_attempt():
    _, reads, _, sleep = read(None, attempts=3, poll_secs=0)
    assert (reads, sleep.calls) == (3, [0, 0]), sleep.calls


def test_the_message_without_a_read_count_is_unchanged():
    rc, msg = scan.judge(None, [], SHA, CAT)
    assert rc == 2 and "reads" not in msg, msg


@pytest.mark.parametrize("bad", ["0", "-1", "x", "1.5"])
def test_an_attempt_count_below_one_or_not_a_whole_number_is_refused(bad, tmp_path):
    p = subprocess.run(
        [sys.executable, str(SCRIPTS / "code-scanning-clean.py"), "--sha", SHA, "--alerts-attempts", bad],
        capture_output=True, text=True, timeout=60, env={"PATH": str(tmp_path / "none")})
    assert p.returncode == 2 and "--alerts-attempts" in p.stderr, p.stderr
    # An unknown flag is refused with the same exit code: the refusal must be
    # of the value, by a flag the script knows.
    assert "unrecognized arguments" not in p.stderr, p.stderr
    assert "whole number of at least 1" in p.stderr, p.stderr


# ---- the program, live mode against a stub `gh` ---------------------------

STUB_GH = """#!{python}
import os, pathlib, sys
d = pathlib.Path(os.environ["STUB_GH_DIR"])
path = next(a for a in sys.argv[1:] if a.startswith("repos/"))
kind = ("analyses" if "/code-scanning/analyses" in path
        else "alerts" if "/code-scanning/alerts" in path
        else "runs" if "/actions/workflows/" in path else None)
with open(d / "calls.log", "a") as log:
    log.write(str(kind) + "\\n")
counter = d / (kind + ".count")
n = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(n + 1))
while n > 0 and not (d / f"{{kind}}.{{n}}").exists():
    n -= 1
body = (d / f"{{kind}}.{{n}}").read_text()
if body.startswith("FAIL"):
    sys.stderr.write("stub gh: HTTP 502\\n")
    sys.exit(1)
sys.stdout.write(body)
"""


def live(tmp_path, alerts, *args):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(STUB_GH.format(python=sys.executable))
    gh.chmod(0o755)
    (tmp_path / "analyses.0").write_text(json.dumps([{"commit_sha": SHA, "category": CAT}]))
    (tmp_path / "runs.0").write_text("[]")
    for i, answer in enumerate(alerts):
        (tmp_path / f"alerts.{i}").write_text(answer if isinstance(answer, str) else json.dumps(answer))
    p = subprocess.run(
        [sys.executable, str(SCRIPTS / "code-scanning-clean.py"), "--sha", SHA,
         "--repo", "example/repo", "--ref", "refs/pull/1/merge", "--poll-secs", "0", *args],
        capture_output=True, text=True, timeout=60,
        env={"PATH": str(bin_dir), "STUB_GH_DIR": str(tmp_path)})
    calls = (tmp_path / "calls.log").read_text().splitlines()
    return p.returncode, p.stdout + p.stderr, calls.count("alerts")


def test_live_one_failed_alerts_read_then_a_clean_answer_passes(tmp_path):
    rc, out, n = live(tmp_path, ["FAIL", []])
    assert (rc, "clean" in out, n) == (0, True, 2), out


def test_live_two_failed_reads_then_an_alert_on_the_commit_fails(tmp_path):
    rc, out, n = live(tmp_path, ["FAIL", "FAIL", [alert()]])
    assert (rc, "1 open alert" in out, n) == (1, True, 3), out


def test_live_an_answer_that_is_not_json_is_read_again(tmp_path):
    rc, out, n = live(tmp_path, ["<html>502 Bad Gateway</html>", []])
    assert (rc, n) == (0, 2), out


def test_live_a_stale_answer_then_a_re_evaluated_one_passes(tmp_path):
    rc, out, n = live(tmp_path, [[alert(OLD)], []])
    assert (rc, n) == (0, 2), out


def test_live_alerts_that_never_answer_are_read_six_times_by_default_and_refused(tmp_path):
    rc, out, n = live(tmp_path, ["FAIL"])
    assert rc == 2 and "could not be read" in out, out
    assert n == 6, f"the default is 6 reads, got {n}"


def test_live_the_attempt_count_can_be_set(tmp_path):
    rc, out, n = live(tmp_path, ["FAIL"], "--alerts-attempts", "2")
    assert (rc, n) == (2, 2), out
    assert "2 reads" in out, out


def test_live_a_stale_answer_at_every_read_is_refused_not_failed(tmp_path):
    rc, out, n = live(tmp_path, [[alert(OLD)]], "--alerts-attempts", "3")
    assert (rc, "not yet re-evaluated" in out, n) == (2, True, 3), out


def test_fixture_mode_reads_its_alerts_file_once_and_does_not_retry(tmp_path):
    (tmp_path / "alerts.json").write_text("not json")
    (tmp_path / "analyses.json").write_text(json.dumps([{"commit_sha": SHA, "category": CAT}]))
    p = subprocess.run(
        [sys.executable, str(SCRIPTS / "code-scanning-clean.py"), "--sha", SHA,
         "--alerts-json", str(tmp_path / "alerts.json"), "--analyses-json", str(tmp_path / "analyses.json")],
        capture_output=True, text=True, timeout=60, env={"PATH": str(tmp_path / "none")})
    assert p.returncode == 2 and "could not be read" in p.stdout, p.stdout + p.stderr
    assert "reads" not in p.stdout, "a file does not change between reads, so fixture mode reads it once"


# ---- the CI job ------------------------------------------------------------


def ci_job():
    ci = (SCRIPTS.parent / ".github/workflows/ci.yml").read_text()
    start = ci.index("\n  code-scanning-clean:\n")
    return ci[start:ci.index("\n  ci-success:\n", start)]


def test_the_ci_job_outlives_the_wait_plus_every_alerts_read():
    job = ci_job()
    bound = int(re.search(r"--max-wait-secs (\d+)", job).group(1))
    minutes = int(re.search(r"timeout-minutes: (\d+)", job).group(1))
    m = re.search(r"--alerts-attempts (\d+)", job)
    attempts = int(m.group(1)) if m else 6
    poll = 30
    assert minutes * 60 >= bound + attempts * poll + 300, (minutes, bound, attempts)


def test_the_help_names_the_attempts_flag(tmp_path):
    p = subprocess.run([sys.executable, str(SCRIPTS / "code-scanning-clean.py"), "--help"],
                       capture_output=True, text=True, timeout=60, env={"PATH": str(tmp_path / "none")})
    assert "--alerts-attempts" in p.stdout, p.stdout
