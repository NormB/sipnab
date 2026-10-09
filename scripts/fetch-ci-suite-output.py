#!/usr/bin/env python3
"""Download the test-suite output of CI's run of one commit.

pages.yml publishes the homepage's automated-test count, and that count must
describe the suite at the commit being deployed. ci.yml's Check job on Linux
already runs the full suite, derives the count with
scripts/published-test-count.py, and uploads the run's output as the
`suite-output` artifact. The deploy reuses that run instead of running the
suite a second time with a second copy of its setup.

The deploy starts on the same push as CI, so the artifact usually does not
exist yet. This polls until it does, then downloads it into DEST. It fails
when CI's run finishes without the artifact (the Test or count step failed, or
the job was skipped) and when the deadline passes, so the site is never built
from another commit's count or from none.

Usage:
    fetch-ci-suite-output.py --repo OWNER/NAME --sha SHA --dest DIR
                             [--deadline-secs N] [--poll-secs N]

Needs `gh` on PATH with a token that can read the repository's Actions
(GH_TOKEN with `actions: read` in a workflow).
"""

import argparse
import json
import subprocess
import sys
import time

ARTIFACT = "suite-output"


def next_action(run, artifact_names):
    """What to do given CI's run for the commit and its live artifact names.

    Returns ("wait" | "download" | "fail", reason).
    """
    if run is None:
        return "wait", "CI has not started a run for this commit yet"
    if ARTIFACT in artifact_names:
        return "download", f"CI run {run['id']} has the {ARTIFACT} artifact"
    if run.get("status") == "completed":
        return "fail", (
            f"CI run {run['id']} finished without a {ARTIFACT} artifact "
            f"(conclusion: {run.get('conclusion')}): the Check job on Linux did "
            "not pass its Test and count steps, so there is no count to publish"
        )
    return "wait", f"CI run {run['id']} is {run.get('status')}"


def gh_json(*args):
    out = subprocess.run(["gh", *args], check=True, capture_output=True, text=True)
    return json.loads(out.stdout)


def ci_run(repo, sha):
    runs = gh_json(
        "api",
        f"repos/{repo}/actions/workflows/ci.yml/runs?head_sha={sha}&event=push&per_page=1",
    )["workflow_runs"]
    return runs[0] if runs else None


def live_artifacts(repo, run_id):
    arts = gh_json("api", f"repos/{repo}/actions/runs/{run_id}/artifacts")["artifacts"]
    return [a["name"] for a in arts if not a.get("expired")]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--dest", required=True)
    # CI's Check job is bounded at 40 minutes, and the run can queue first.
    ap.add_argument("--deadline-secs", type=int, default=3600)
    ap.add_argument("--poll-secs", type=int, default=30)
    args = ap.parse_args(argv)

    deadline = time.monotonic() + args.deadline_secs
    while True:
        run = ci_run(args.repo, args.sha)
        names = live_artifacts(args.repo, run["id"]) if run else []
        action, reason = next_action(run, names)
        print(f"fetch-ci-suite-output: {reason}", file=sys.stderr)
        if action == "download":
            subprocess.run(
                ["gh", "run", "download", str(run["id"]), "-R", args.repo,
                 "-n", ARTIFACT, "-D", args.dest],
                check=True,
            )
            return 0
        if action == "fail":
            return 1
        if time.monotonic() >= deadline:
            print(
                f"fetch-ci-suite-output: deadline of {args.deadline_secs}s passed "
                f"waiting for CI's {ARTIFACT} artifact for {args.sha}",
                file=sys.stderr,
            )
            return 1
        time.sleep(args.poll_secs)


if __name__ == "__main__":
    sys.exit(main())
