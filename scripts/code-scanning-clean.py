#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Refuse to pass while code scanning has open alerts for the commit.

One rule in one place: CI's aggregate job runs this, and the pre-push tag
check runs this. Both used to look only at workflow conclusions, so CodeQL --
a separate workflow whose findings go to a tab -- never blocked anything, and
nine alerts sat open on main across three tagged releases.

Verdict is about the analysis of the COMMIT ASKED ABOUT (--sha), never merely
the latest one on the branch: CodeQL runs beside CI, not before it, so the
script waits for an analysis of that commit to exist.

How long it waits follows the CodeQL workflow run of the commit (--head-sha,
--workflow), not a fixed time. The run's queue time has no bound: on
2026-11-10 one sat queued for 46 minutes, and a fixed 25-minute wait ended
147 s before its analysis was uploaded.
  the run is queued or in progress   keep waiting, up to --max-wait-secs
  the run has completed              wait --settle-secs more for the upload
  no run of the commit is listed,    wait --wait-secs from the start
  or the list cannot be read

Exit codes -- a gate that cannot see must say so, never pass:
  exit 0  an analysis of --sha exists and no alert is open
  exit 1  open alerts (each printed as rule path:line message)
  exit 2  no verdict. The message says which:
            "still queued or running"   the CodeQL run had not finished at
                                        the upper bound; run the check again
            "no CodeQL analysis ..."    the run completed without uploading
                                        one, or no run of the commit exists
            "could not be read"         an API answer was not readable
            "not yet re-evaluated"      open alerts last seen on an older
                                        commit

Live mode reads GitHub through `gh api` (GH_TOKEN / GITHUB_TOKEN in CI, the
user's login locally). Fixture mode (--alerts-json, --analyses-json,
--runs-json) reads files instead, and the wait takes its clock and its
readers as arguments, so every branch above is driven from a test with no
network and no real waiting.
"""
import argparse
import json
import subprocess
import sys
import time


def open_alerts(alerts):
    """Alerts whose state is open -- dismissed and fixed ones are not findings."""
    return [a for a in alerts if isinstance(a, dict) and a.get("state") == "open"]


def analysis_covers(analyses, sha, category):
    """Whether the analysis that produces the alerts -- `category` -- has run on
    this exact commit. CodeQL uploads one analysis per language and the fast
    ones land in seconds; an `actions` analysis of the SHA says nothing about
    Rust alerts, and judging on it is judging the previous commit's Rust run."""
    return any(
        isinstance(a, dict) and a.get("commit_sha") == sha and a.get("category") == category
        for a in analyses
    )


def instance_on(alert, sha):
    """Whether the alert's most recent instance was found on this commit."""
    inst = alert.get("most_recent_instance", {}) or {}
    return inst.get("commit_sha") == sha


def describe(alert):
    inst = alert.get("most_recent_instance", {}) or {}
    loc = inst.get("location", {}) or {}
    msg = (inst.get("message", {}) or {}).get("text", "")
    rule = (alert.get("rule", {}) or {}).get("id", "?")
    return f"  {rule}  {loc.get('path', '?')}:{loc.get('start_line', '?')}  {msg}"


def merge_pages(text):
    """The pages `gh api --paginate` printed, as one list, or None if unreadable.

    --paginate writes each page's JSON array straight after the last one,
    `[...][...]`. Each page is decoded where it starts, so `][` inside an
    alert's text is just text. Splitting the output on `][` did read it as a
    page boundary: on 2026-10-27 a PR's open-alerts answer (an osv-scanner
    alert quoting a version range) became five unparseable pieces, and the
    gate refused to judge. Anything but whole JSON arrays, with only
    whitespace between them, is unreadable, and so is an empty answer.
    """
    if not isinstance(text, str):
        return None
    decoder = json.JSONDecoder()
    merged, i, pages = [], 0, 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i == len(text):
            break
        try:
            page, i = decoder.raw_decode(text, i)
        except json.JSONDecodeError:
            return None
        if not isinstance(page, list):
            return None
        merged.extend(page)
        pages += 1
    return merged if pages else None


def gh_paginated(path, jq=None):
    """Every page of a list endpoint via `gh api --paginate`, or None if unreadable.

    `jq` picks the list out of an endpoint that wraps it in an object; gh
    applies it to each page, so the output is still one array per page."""
    argv = ["gh", "api", "--paginate", "-H", "Accept: application/vnd.github+json", path]
    if jq:
        argv += ["--jq", jq]
    p = subprocess.run(argv, capture_output=True, text=True)
    if p.returncode != 0:
        sys.stderr.write(p.stderr)
        return None
    return merge_pages(p.stdout)


# What the CodeQL workflow runs of the commit say about an analysis to come.
COVERED = "covered"        # the analysis exists; the runs no longer matter
PENDING = "pending"        # a run is queued or in progress
FINISHED = "finished"      # every run has completed
ABSENT = "absent"          # no run of the commit is listed
UNREADABLE = "unreadable"  # the list could not be read


def codeql_state(runs):
    """(state, detail) for the workflow runs GitHub lists for the commit.

    One run that has not completed makes the commit PENDING, whatever the
    others say: a re-run, or a second event's run, can still upload the
    analysis. An entry with no status is UNREADABLE, never FINISHED: calling
    it finished would end the wait on an answer nobody understood."""
    if runs is None:
        return UNREADABLE, ""
    if not all(isinstance(r, dict) and isinstance(r.get("status"), str) for r in runs):
        return UNREADABLE, ""
    if not runs:
        return ABSENT, ""
    live = [r for r in runs if r["status"] != "completed"]
    if live:
        return PENDING, ", ".join(
            f"run {r.get('id', '?')} {r['status']}, created {r.get('created_at', '?')}" for r in live
        )
    return FINISHED, ", ".join(
        f"run {r.get('id', '?')} completed: {r.get('conclusion', '?')}" for r in runs
    )


def wait_for_analysis(fetch_analyses, fetch_runs, sha, category, *, wait_secs, max_wait_secs,
                      settle_secs, poll_secs, now, sleep):
    """Poll until an analysis of `sha` in `category` exists or waiting longer
    has no reason. Returns (analyses, state, detail, seconds waited).

    The analyses are read first on every poll; the runs are read only when
    the analysis is missing, to decide whether to go on:
      PENDING                keep going until the upper bound
      FINISHED               keep going `settle_secs` from the first poll that
                             saw it, since the upload is processed after the
                             job ends; a run that goes back to queued (a
                             re-run) starts this again
      ABSENT, UNREADABLE     keep going until `wait_secs` from the start
    The upper bound is `max_wait_secs`, or `wait_secs` when that is larger,
    so a caller that passes only the old flag waits as long as before.
    """
    start = now()
    limit = max(wait_secs, max_wait_secs)
    finished_since = None
    while True:
        analyses = fetch_analyses()
        if analyses is not None and analysis_covers(analyses, sha, category):
            return analyses, COVERED, "", now() - start
        state, detail = codeql_state(fetch_runs())
        t = now()
        elapsed = t - start
        if state == FINISHED:
            if finished_since is None:
                finished_since = t
            go_on = t - finished_since < settle_secs and elapsed < limit
        else:
            finished_since = None
            go_on = elapsed < (limit if state == PENDING else wait_secs)
        if not go_on:
            return analyses, state, detail, elapsed
        sleep(poll_secs)


def no_analysis_message(sha, category, codeql, waited):
    """Why there is no verdict when the analysis of the commit is missing."""
    what = f"CodeQL analysis of {sha[:8]} in {category}"
    state, detail = codeql if codeql else (None, "")
    after = "" if waited is None else f" after {int(waited)} s"
    if state == PENDING:
        return (f"code scanning: the {what} is still queued or running{after} ({detail})"
                " -- refusing to judge; run this check again when the CodeQL run has finished")
    if state == FINISHED:
        return (f"code scanning: no {what} exists{after}: the CodeQL run completed without"
                f" uploading one ({detail}) -- refusing to judge")
    if state == ABSENT:
        return (f"code scanning: no {what} exists{after}, and no CodeQL run of the commit"
                " is listed -- refusing to judge")
    if state == UNREADABLE:
        return (f"code scanning: no {what} exists yet{after}, and the state of the CodeQL run"
                " could not be read -- refusing to judge")
    return f"code scanning: no {what} exists yet -- refusing to judge"


def judge(alerts, analyses, sha, category, codeql=None, waited=None):
    """(exit code, message) for the given API answers.

    `codeql` is the (state, detail) of the commit's CodeQL runs when the
    caller knows it. It only words the message for a missing analysis: once
    the analysis exists, the alerts decide, whatever the runs say."""
    if alerts is None or analyses is None:
        return 2, "code scanning: the API answer could not be read (not JSON) -- refusing to judge"
    if not analysis_covers(analyses, sha, category):
        return 2, no_analysis_message(sha, category, codeql, waited)
    bad = open_alerts(alerts)
    stale = [a for a in bad if not instance_on(a, sha)]
    if stale:
        # The analysis of this commit exists, yet these alerts' most recent
        # instance is on an older one: the scanner has not re-evaluated them
        # here. Judging them now is judging the previous commit -- the exact
        # mistake this script's first run made. Wait, do not fail.
        return 2, f"code scanning: {len(stale)} open alert(s) not yet re-evaluated on {sha[:8]} -- refusing to judge"
    if bad:
        lines = "\n".join(describe(a) for a in bad)
        return 1, f"code scanning: {len(bad)} open alert(s) on {sha[:8]}:\n{lines}"
    return 0, f"code scanning: clean -- analysis of {sha[:8]} exists and no alert is open"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--sha", required=True, help="the commit whose analysis is judged")
    ap.add_argument("--repo", default="NormB/sipnab")
    ap.add_argument("--ref", default="refs/heads/main")
    ap.add_argument("--head-sha", help="the commit the CodeQL workflow run is of: on a pull request the "
                    "branch head, where --sha is the merge commit (default: --sha)")
    ap.add_argument("--workflow", default="codeql.yml", help="the workflow file whose runs upload the analysis")
    ap.add_argument("--wait-secs", type=int, default=0,
                    help="live mode: wait this long for an analysis of --sha while no CodeQL run of the commit is listed")
    ap.add_argument("--max-wait-secs", type=int, default=0,
                    help="live mode: wait up to this long while the CodeQL run is queued or in progress")
    ap.add_argument("--settle-secs", type=int, default=120,
                    help="live mode: wait this long for the upload after the CodeQL run completed")
    ap.add_argument("--poll-secs", type=float, default=30, help="live mode: seconds between reads")
    ap.add_argument("--category", default="/language:rust", help="the analysis category whose alerts are judged")
    ap.add_argument("--alerts-json", help="fixture mode: read alerts from this file")
    ap.add_argument("--analyses-json", help="fixture mode: read analyses from this file")
    ap.add_argument("--runs-json", help="fixture mode: read the CodeQL workflow runs from this file")
    a = ap.parse_args()

    if a.alerts_json or a.analyses_json:
        alerts = merge_pages(open(a.alerts_json).read()) if a.alerts_json else []
        analyses = merge_pages(open(a.analyses_json).read()) if a.analyses_json else []
        codeql = codeql_state(merge_pages(open(a.runs_json).read())) if a.runs_json else None
        rc, msg = judge(alerts, analyses, a.sha, a.category, codeql=codeql)
    else:
        head = a.head_sha or a.sha
        analyses, state, detail, waited = wait_for_analysis(
            lambda: gh_paginated(f"repos/{a.repo}/code-scanning/analyses?ref={a.ref}&per_page=100"),
            lambda: gh_paginated(
                f"repos/{a.repo}/actions/workflows/{a.workflow}/runs?head_sha={head}&per_page=100",
                jq=".workflow_runs"),
            a.sha, a.category, wait_secs=a.wait_secs, max_wait_secs=a.max_wait_secs,
            settle_secs=a.settle_secs, poll_secs=a.poll_secs, now=time.monotonic, sleep=time.sleep,
        )
        alerts = gh_paginated(f"repos/{a.repo}/code-scanning/alerts?state=open&ref={a.ref}&per_page=100")
        rc, msg = judge(alerts, analyses, a.sha, a.category, codeql=(state, detail), waited=waited)
    print(msg)
    sys.exit(rc)


if __name__ == "__main__":
    main()
