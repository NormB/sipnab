#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Re-run a workflow run that failed only because jobs never started.

GitHub cancels a job when no hosted runner takes it: the job ends with the
conclusion `"cancelled"`, no steps, and the annotation in NOT_ACQUIRED, and the
run it belongs to ends as failed although no test ran red. On 2026-11-12 that
happened six times on the hosted macOS runners; it turned main's CI red three
times and held the publication of a release for 43 minutes, and each run
passed when a person re-ran its failed jobs.

This script reads one attempt of one run and answers `rerun` only when every
job of that attempt either succeeded, was skipped, or never started. A job
never started when all of these hold:

  - its status is `completed` and its conclusion is `"cancelled"`;
  - its `steps` list is present and empty;
  - one of its annotations has exactly the message in NOT_ACQUIRED.

Anything else is left for a person: a job that failed or timed out, a job
canceled after its first step began, a job canceled in the queue by a
person (no such annotation), a self-hosted runner that did not take a job (a
different message), a run that is not completed, and a run already on
attempt MAX_ATTEMPTS. A skipped job blocks nothing: the jobs that need a job
that never started are skipped, and GitHub's "re-run failed jobs" runs them
again with it.

The limit counts attempts of one run, as GitHub numbers them
(`run_attempt`): attempts 1 and 2 may be re-run, so a run has at most
MAX_ATTEMPTS attempts made without a person.

Usage:
    rerun-not-acquired.py --repo OWNER/NAME --run-id N [--attempt N] [--apply]

Without --apply the decision is printed and nothing is changed. --attempt is
the attempt the caller was told about; when the run has since moved to a
later attempt, the answer is `leave`. The exit status is 0 for either
decision, 1 when GitHub's API could not be read or the re-run was refused,
and 2 for arguments that are not a repository and numbers.

Needs `gh` on PATH with a token that can read the repository's Actions and
re-run a workflow (GH_TOKEN with `actions: write` in a workflow).
"""

import argparse
import json
import re
import subprocess
import sys

# The annotation GitHub puts on a job that no hosted runner took.
NOT_ACQUIRED = "The job was not acquired by Runner of type hosted even after multiple attempts"

# The most attempts one run gets without a person, the first included.
MAX_ATTEMPTS = 3

# The conclusions of a run this script looks into. The workflow's `if:` names
# the same two, so that a run that passed does not start a job to say so.
RERUN_CONCLUSIONS = ("failure", "cancelled")

PER_PAGE = 100
# 50 pages of 100: more jobs than one run can hold.
MAX_PAGES = 50

REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*")


class ApiError(Exception):
    """GitHub's API could not be read, or answered in an unknown shape."""


def _is_count(value):
    """A positive integer, and not a bool or a float that equals one."""
    return type(value) is int and value >= 1


def _has_message(annotations):
    if not isinstance(annotations, list):
        return False
    for note in annotations:
        if not isinstance(note, dict):
            continue
        message = note.get("message")
        if isinstance(message, str) and message.strip() == NOT_ACQUIRED:
            return True
    return False


def _no_steps(job):
    steps = job.get("steps")
    return isinstance(steps, list) and len(steps) == 0


def is_candidate(job):
    """Canceled with no steps: the annotations decide the rest."""
    return (
        isinstance(job, dict)
        and job.get("status") == "completed"
        and job.get("conclusion") == "cancelled"
        and _no_steps(job)
    )


def never_started(job, annotations) -> bool:
    """Whether `job` ended because no hosted runner took it."""
    return is_candidate(job) and _has_message(annotations)


def run_blocks(run, max_attempts=MAX_ATTEMPTS):
    """Why the run itself rules a re-run out, or None when it does not."""
    if not isinstance(run, dict):
        return "the run was not readable"
    if run.get("status") != "completed":
        return f"the run is not completed (status {run.get('status')!r})"
    conclusion = run.get("conclusion")
    if conclusion not in RERUN_CONCLUSIONS:
        return f"the run concluded {conclusion!r}"
    attempt = run.get("run_attempt")
    if not _is_count(attempt):
        return f"the run's attempt number is {attempt!r}"
    if attempt >= max_attempts:
        return f"the run is on attempt {attempt} of at most {max_attempts}"
    return None


def _annotations_of(annotations, job_id):
    if not isinstance(annotations, dict):
        return None
    if job_id in annotations:
        return annotations[job_id]
    return annotations.get(str(job_id))


def _label(job):
    name = job.get("name") if isinstance(job, dict) else None
    return name if isinstance(name, str) and name else "a job without a name"


def decide(run, jobs, annotations, max_attempts=MAX_ATTEMPTS):
    """`("rerun", reason)` or `("leave", reason)` for one attempt of a run.

    `jobs` is the `jobs` list of GitHub's "list jobs for a workflow run
    attempt"; `annotations` maps a job id to that job's "list check run
    annotations" answer.
    """
    blocked = run_blocks(run, max_attempts)
    if blocked:
        return "leave", blocked
    if not isinstance(jobs, list) or not jobs:
        return "leave", "the run lists no jobs"

    never = []
    blocking = []
    for job in jobs:
        if not isinstance(job, dict):
            blocking.append("a job that was not readable")
            continue
        conclusion = job.get("conclusion")
        if job.get("status") == "completed" and conclusion == "success":
            continue
        if job.get("status") == "completed" and conclusion == "skipped" and _no_steps(job):
            continue
        if never_started(job, _annotations_of(annotations, job.get("id"))):
            never.append(_label(job))
            continue
        steps = job.get("steps")
        ran = len(steps) if isinstance(steps, list) else "unknown"
        blocking.append(f"{_label(job)} ({conclusion!r}, steps: {ran})")

    if blocking:
        return "leave", "not only jobs that never started: " + "; ".join(blocking)
    if not never:
        return "leave", "no job ended because no runner took it"
    return "rerun", "no hosted runner took: " + "; ".join(never)


def gh_api(*args) -> str:
    out = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise ApiError(f"gh api {' '.join(args)}: {out.stderr.strip()}")
    return out.stdout


def gh_json(*args):
    text = gh_api(*args)
    try:
        return json.loads(text)
    except json.JSONDecodeError as err:
        raise ApiError(f"gh api {' '.join(args)}: not JSON ({err})") from err


def read_jobs(repo, run_id, attempt):
    """Every job of the attempt, or ApiError when the pages do not add up."""
    jobs = []
    total = None
    for page in range(1, MAX_PAGES + 1):
        path = (
            f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}"
            f"/jobs?per_page={PER_PAGE}&page={page}"
        )
        answer = gh_json(path)
        if not isinstance(answer, dict) or not isinstance(answer.get("jobs"), list):
            raise ApiError(f"{path}: no jobs list")
        if total is None:
            total = answer.get("total_count")
        jobs.extend(answer["jobs"])
        if len(answer["jobs"]) < PER_PAGE:
            break
    if type(total) is not int or len(jobs) != total:
        raise ApiError(f"read {len(jobs)} jobs of the {total!r} GitHub counted")
    return jobs


def read_annotations(repo, job_id):
    notes = []
    for page in range(1, MAX_PAGES + 1):
        path = f"repos/{repo}/check-runs/{job_id}/annotations?per_page={PER_PAGE}&page={page}"
        answer = gh_json(path)
        if not isinstance(answer, list):
            raise ApiError(f"{path}: not a list")
        notes.extend(answer)
        if len(answer) < PER_PAGE:
            break
    return notes


def _count(text):
    if not re.fullmatch(r"[1-9][0-9]{0,18}", text):
        raise argparse.ArgumentTypeError(f"{text!r} is not a positive number")
    return int(text)


def _repo(text):
    if not REPO_RE.fullmatch(text):
        raise argparse.ArgumentTypeError(f"{text!r} is not OWNER/NAME")
    return text


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True, type=_repo)
    ap.add_argument("--run-id", required=True, type=_count)
    ap.add_argument("--attempt", type=_count)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)

    try:
        run = gh_json(f"repos/{args.repo}/actions/runs/{args.run_id}")
        latest = run.get("run_attempt") if isinstance(run, dict) else None
        blocked = run_blocks(run)
        if blocked is None and args.attempt is not None and latest != args.attempt:
            blocked = f"the run has moved on from attempt {args.attempt} to attempt {latest}"
        if blocked:
            verdict, reason = "leave", blocked
        else:
            jobs = read_jobs(args.repo, args.run_id, latest)
            annotations = {
                job["id"]: read_annotations(args.repo, job["id"])
                for job in jobs
                if is_candidate(job) and _is_count(job.get("id"))
            }
            verdict, reason = decide(run, jobs, annotations)

        print(f"run {args.run_id} attempt {latest}")
        print(f"decision: {verdict}: {reason}")
        if verdict != "rerun":
            return 0
        if not args.apply:
            print("not applied: --apply was not given")
            return 0
        # The answer to this request has no body to read.
        gh_api("-X", "POST", f"repos/{args.repo}/actions/runs/{args.run_id}/rerun-failed-jobs")
        print(
            f"::notice::Re-ran the failed jobs of run {args.run_id} after attempt "
            f"{latest} of at most {MAX_ATTEMPTS}: {reason}"
        )
        return 0
    except ApiError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
