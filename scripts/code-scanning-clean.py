#!/usr/bin/env python3
"""Refuse to pass while code scanning has open alerts for the commit.

One rule in one place: CI's aggregate job runs this, and the pre-push tag
check runs this. Both used to look only at workflow conclusions, so CodeQL --
a separate workflow whose findings go to a tab -- never blocked anything, and
nine alerts sat open on main across three tagged releases.

Verdict is about the analysis of the COMMIT ASKED ABOUT (--sha), never merely
the latest one on the branch: CodeQL runs beside CI, not before it, so the
script waits (--wait-secs) for an analysis of that commit to exist.

Exit codes -- a gate that cannot see must say so, never pass:
  exit 0  an analysis of --sha exists and no alert is open
  exit 1  open alerts (each printed as rule path:line message)
  exit 2  the answer could not be read, or no CodeQL analysis of --sha exists
          within --wait-secs

Live mode reads GitHub through `gh api` (GH_TOKEN / GITHUB_TOKEN in CI, the
user's login locally). Fixture mode (--alerts-json, --analyses-json) reads
files instead, so every branch above is driven from a test with no network.
"""
import argparse
import json
import subprocess
import sys
import time


def parse(text):
    """The JSON the API answered, or None when it is not JSON at all."""
    try:
        v = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    return v if isinstance(v, list) else None


def open_alerts(alerts):
    """Alerts whose state is open -- dismissed and fixed ones are not findings."""
    return [a for a in alerts if isinstance(a, dict) and a.get("state") == "open"]


def analysis_covers(analyses, sha):
    """Whether any listed analysis is of this exact commit."""
    return any(isinstance(a, dict) and a.get("commit_sha") == sha for a in analyses)


def describe(alert):
    inst = alert.get("most_recent_instance", {}) or {}
    loc = inst.get("location", {}) or {}
    msg = (inst.get("message", {}) or {}).get("text", "")
    rule = (alert.get("rule", {}) or {}).get("id", "?")
    return f"  {rule}  {loc.get('path', '?')}:{loc.get('start_line', '?')}  {msg}"


def gh_paginated(path):
    """Every page of a list endpoint via `gh api --paginate`, or None if unreadable."""
    p = subprocess.run(
        ["gh", "api", "--paginate", "-H", "Accept: application/vnd.github+json", path],
        capture_output=True, text=True,
    )
    if p.returncode != 0:
        sys.stderr.write(p.stderr)
        return None
    # --paginate concatenates JSON arrays; join them into one.
    merged = []
    for chunk in p.stdout.replace("][", "]\n[").splitlines():
        v = parse(chunk)
        if v is None:
            return None
        merged.extend(v)
    return merged


def judge(alerts, analyses, sha):
    """(exit code, message) for the given API answers."""
    if alerts is None or analyses is None:
        return 2, "code scanning: the API answer could not be read (not JSON) -- refusing to judge"
    if not analysis_covers(analyses, sha):
        return 2, f"code scanning: no CodeQL analysis of {sha[:8]} exists yet -- refusing to judge"
    bad = open_alerts(alerts)
    if bad:
        lines = "\n".join(describe(a) for a in bad)
        return 1, f"code scanning: {len(bad)} open alert(s) on {sha[:8]}:\n{lines}"
    return 0, f"code scanning: clean -- analysis of {sha[:8]} exists and no alert is open"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--sha", required=True, help="the commit whose analysis is judged")
    ap.add_argument("--repo", default="NormB/sipnab")
    ap.add_argument("--ref", default="refs/heads/main")
    ap.add_argument("--wait-secs", type=int, default=0, help="live mode: wait this long for an analysis of --sha")
    ap.add_argument("--alerts-json", help="fixture mode: read alerts from this file")
    ap.add_argument("--analyses-json", help="fixture mode: read analyses from this file")
    a = ap.parse_args()

    if a.alerts_json or a.analyses_json:
        alerts = parse(open(a.alerts_json).read()) if a.alerts_json else []
        analyses = parse(open(a.analyses_json).read()) if a.analyses_json else []
        rc, msg = judge(alerts, analyses, a.sha)
    else:
        deadline = time.time() + a.wait_secs
        while True:
            analyses = gh_paginated(f"repos/{a.repo}/code-scanning/analyses?ref={a.ref}&per_page=100")
            if analyses is not None and analysis_covers(analyses, a.sha):
                break
            if time.time() >= deadline:
                break
            time.sleep(30)
        alerts = gh_paginated(f"repos/{a.repo}/code-scanning/alerts?state=open&ref={a.ref}&per_page=100")
        rc, msg = judge(alerts, analyses, a.sha)
    print(msg)
    sys.exit(rc)


if __name__ == "__main__":
    main()
