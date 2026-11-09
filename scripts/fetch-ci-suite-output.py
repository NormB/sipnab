#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Download the test-suite output of CI's run of one commit.

pages.yml publishes the homepage's automated-test count, and that count must
describe the suite at the commit being deployed. ci.yml's `test` job runs the
full suite on Linux, in shards, and its `test-results` job merges their
outputs, derives the count with scripts/published-test-count.py, and uploads the run's output as the
`suite-output` artifact. The deploy reuses that run instead of running the
suite a second time with a second copy of its setup.

The deploy starts on the same push as CI, so the artifact usually does not
exist yet. This polls until it does, then downloads it into DEST. It fails
when CI's run finishes without the artifact (the Test or count step failed, or
the job was skipped) and when the deadline passes, so the site is never built
from another commit's count or from none.

RELEASE-FAST C. On 0.5.238 the deploy waited 39 minutes for the merge
commit's push run, although the release pull request's head had already run
the same suite on the same tree. ci.yml now uploads `suite-output` on pull
requests too, and `choose` takes it from a merged pull request's head when
GitHub reports the same tree for the head and the commit (`read_pr_heads` in
scripts/tag-push-proof.py, the rule the tag gate uses). The commit's own run
still decides once it has finished: completed without the artifact means its
suite failed on that tree, and no head stands in for it.

Usage:
    fetch-ci-suite-output.py --repo OWNER/NAME --sha SHA --dest DIR
                             [--deadline-secs N] [--poll-secs N]

Needs `gh` on PATH with a token that can read the repository's Actions
(GH_TOKEN with `actions: read` in a workflow).
"""

import argparse
import importlib.util
import json
import pathlib
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
            f"(conclusion: {run.get('conclusion')}): the Linux suite (ci.yml's test "
            "and test-results jobs) did not pass its Test and count steps, so "
            "there is no count to publish"
        )
    return "wait", f"CI run {run['id']} is {run.get('status')}"


def choose(own_run, own_names, heads):
    """(action, run id, reason) over the commit's own run and the runs of
    same-tree merged pull request heads (dicts of number, sha, run, names).

    The own run's artifact first; then the first head run that has one,
    unless the own run already finished without it, which fails."""
    action, reason = next_action(own_run, own_names)
    if action in ("download", "fail"):
        return action, own_run["id"], reason
    for h in heads:
        if h["run"] and ARTIFACT in h["names"]:
            return "download", h["run"]["id"], (
                f"CI run {h['run']['id']} of PR #{h['number']}'s head {h['sha'][:9]}, the same tree as "
                f"this commit, has the {ARTIFACT} artifact"
            )
    return "wait", None, reason


def _tag_push_proof():
    path = pathlib.Path(__file__).resolve().parent / "tag-push-proof.py"
    spec = importlib.util.spec_from_file_location("tag_push_proof", path)
    mod = importlib.util.module_from_spec(spec)
    # dataclasses resolve their module through sys.modules.
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


def head_sources(repo, sha, gh):
    """The newest ci.yml run, and its live artifact names, of each merged
    pull request head with the same tree as `sha`."""
    out = []
    for number, head_sha, same_tree in _tag_push_proof().read_pr_heads(repo, sha, gh):
        if not same_tree:
            continue
        run = head_run(repo, head_sha)
        out.append({"number": number, "sha": head_sha, "run": run,
                    "names": live_artifacts(repo, run["id"]) if run else []})
    return out


class GhError(Exception):
    """A `gh` call that exited non-zero; the message is gh's own stderr."""


def gh_json(*args):
    out = subprocess.run(["gh", *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise GhError(
            f"`gh {' '.join(args)}` exited {out.returncode}: "
            f"{out.stderr.strip() or '(no message)'}"
        )
    return json.loads(out.stdout)


def _gh_text(path, jq=None):
    """tag-push-proof's `gh` shape: (exit code, stdout)."""
    args = ["gh", "api", path] + (["--jq", jq] if jq else [])
    out = subprocess.run(args, capture_output=True, text=True)
    return out.returncode, out.stdout


def ci_run(repo, sha):
    runs = gh_json(
        "api",
        f"repos/{repo}/actions/workflows/ci.yml/runs?head_sha={sha}&event=push&per_page=1",
    )["workflow_runs"]
    return runs[0] if runs else None


def head_run(repo, sha):
    runs = gh_json(
        "api", f"repos/{repo}/actions/workflows/ci.yml/runs?head_sha={sha}&event=pull_request&per_page=1",
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
    # CI's test jobs are bounded at 45 minutes and test-results at 15, and
    # the run can queue first.
    ap.add_argument("--deadline-secs", type=int, default=3600)
    ap.add_argument("--poll-secs", type=int, default=30)
    args = ap.parse_args(argv)

    deadline = time.monotonic() + args.deadline_secs
    while True:
        # A failed read of GitHub's API (a 5xx, a dropped connection) is a
        # reason to poll again, not to fail the deploy: the deadline below
        # already bounds how long this waits. It failed the deploy of
        # 0c55cd1f on 2026-10-12 on one such error.
        try:
            run = ci_run(args.repo, args.sha)
            names = live_artifacts(args.repo, run["id"]) if run else []
            heads = [] if ARTIFACT in names else head_sources(args.repo, args.sha, _gh_text)
            action, run_id, reason = choose(run, names, heads)
        except GhError as e:
            action, run_id, reason = "wait", None, f"reading GitHub's API failed, polling again: {e}"
        print(f"fetch-ci-suite-output: {reason}", file=sys.stderr)
        if action == "download":
            subprocess.run(
                ["gh", "run", "download", str(run_id), "-R", args.repo,
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
