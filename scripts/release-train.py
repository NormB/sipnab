#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""One resumable entry point from a release pull request to done (RELEASE-FAST E).

    release-train.py X.Y.Z --host USER@HOST [--repo OWNER/NAME] [--poll S]
                     [--bin DIR] [--retry-post] [--proof-wait S]

The release commit is written by hand and pushed on the branch release/X.Y.Z
with its pull request open. The train then drives what follows, and every run
starts by reading where the release is from GitHub and git, so a re-run after
a crash continues from there:

    ci-wait       post the CLA status for the head, wait for the checks
    land          land the pull request (land-queue, required-checks)
    tag           move this checkout to the merge commit, wait for GitHub's
                  proof of it, make the signed tag, push it in the lane
    release-wait  wait for the release workflow on the tag
    post          scripts/post-release.py run X.Y.Z --host USER@HOST
    done

THE WINDOW. The heavy-run release window stops ordinary main-slot jobs from
starting. It cannot stop one that is running, so it must be open for about one
hook's length before a local step. The rule is `window_wanted`:

- open for the landing and the tag;
- during the pull request's CI, closed, until the pending check with the most
  time left has at most `lead_s` seconds of it (`longest_remaining`: its
  start, plus the time the check of that name took on main's head commit);
- when that time cannot be said (a pending check that main has no successful
  run of, a pending commit status, a read of main's check runs that failed),
  closed until at most `last_few` checks are pending or `lead_s` seconds
  remain of CI's expected run;
- during the pull request's CI, closed again while a check has waited for a
  runner longer than `queued_grace_s` (`stuck_queued`): it has not started, so
  nothing says when it ends;
- closed for the release workflow and the post checks, which use no main slot.

Measured: on 0.5.239 there was no window, and the tag push waited 769 s behind
an ordinary job that had started 7 s before it. On 0.5.240 the window was
closed for all of CI, an ordinary hook started in the same second, and the tag
queued 434 s behind it. The default estimate is 0.5.240's 37 min of pull
request CI.

On 0.5.244 the one pending check was a re-run macOS job, queued with no runner
from 15:39:23Z until GitHub canceled it at 15:55:06Z. It counted as one of the
last few checks, the window was open for those minutes, the main slot was idle
and two ordinary jobs waited behind the window (RELEASE-TRAIN-WINDOW-QUEUED-JOB).

On 0.5.246 and 0.5.249 the one pending check was running: Coverage, and a
macOS job that ran from 16:57:06Z to 17:30:08Z. One check is under `last_few`,
so the window was open, from 17:09:03Z to 17:32:15Z on 0.5.249, and ordinary
jobs were held while the main slot was idle
(RELEASE-TRAIN-WINDOW-OPENS-ON-LONG-LAST-CHECK). The landing waits for every
check, so the count says nothing about when the landing is; each check's usual
time does. The usual times are read once (`read_usual`) and kept in the state
file; while a pending check has none they are read again, at most every
`usual_retry_s`. A failed read does not stop the train.

Another owner's window is left alone: it holds ordinary jobs just the same.

BEFORE THE TAG (RELEASE-TRAIN-TAG-RACE). On 0.5.243 the train pushed the tag
one second after the pull request merged, and the pre-push hook refused it
twice, about six minutes in all. So the tag stage does two things first:

- `checkout_at_merge`: the hook's release-delivery test reads the checkout it
  runs in, and this checkout predates the merge commit. With no uncommitted
  change to a tracked file it is moved there (`git checkout --detach`) and
  HEAD is read back; otherwise the train stops and prints the command.
- `wait_for_proof`: GitHub lists the merged pull request for the merge commit
  some time after the merge, and until then the hook's fast path does not
  engage. `tag-push-proof.py --ready` is the hook's two queries; the train
  asks every `proof_poll_s` for at most `proof_wait_s` (--proof-wait), and
  stops before making the tag if the proof never resolves.

Exit status: 0 done; 1 stopped (the output says at which stage and why, and a
re-run resumes); 2 usage; 3 the post checks withdrew the release; 4 the
withdrawal did not complete. After a 3 or a 4 the post checks do not run again
without --retry-post.

The state file holds two values GitHub cannot be asked for, the post checks'
exit status and the head the CLA status was posted for, and the usual times
with the time of their last read.

Tested by scripts/tests/test_release_train.py, on a fake clock.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import time

SCRIPTS = pathlib.Path(__file__).resolve().parent
REPO = SCRIPTS.parent

_spec = importlib.util.spec_from_file_location("post_release_for_train", SCRIPTS / "post-release.py")
_post = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _post
_spec.loader.exec_module(_post)
Result = _post.Result
subprocess_runner = _post.subprocess_runner

# GitHub's own conclusion values, compared in lowercase.
BAD_CONCLUSIONS = {"failure", "timed_out", "cancelled", "action_required", "startup_failure"}
GOOD_CONCLUSIONS = {"success", "neutral", "skipped"}
WAITS = {"ci-wait", "release-wait"}
READ_ATTEMPTS = 3
EXTEND_BELOW_S = 15 * 60


class ReadError(Exception):
    """GitHub or git could not be read. The train never guesses past one."""


class Stopped(Exception):
    """A local step failed; the message says which and why."""


@dataclasses.dataclass
class Facts:
    pr_state: str
    pr_number: int | None
    head: str
    merge_sha: str
    pending: int
    failed: tuple
    first_started: int | None
    tag_exists: bool
    run_status: str
    run_conclusion: str
    post_rc: int | None
    stuck: int = 0
    long_remaining: float | None = None


@dataclasses.dataclass
class Config:
    version: str
    host: str
    repo: str
    state_file: pathlib.Path
    poll: float = 30.0
    last_few: int = 3
    lead_s: int = 900
    expected_ci_s: int = 2220
    proof_wait_s: int = 300
    proof_poll_s: float = 10.0
    queued_grace_s: int = 120
    usual_retry_s: int = 300
    window_minutes: int = 60
    bin_dir: str = ""
    retry_post: bool = False


# ---------------------------------------------------------------------------
# Pure decisions
# ---------------------------------------------------------------------------


def stage_of(f: Facts) -> str:
    """Where the release is. A later fact outranks an earlier one."""
    if f.tag_exists:
        if f.run_status != "completed":
            return "release-wait"
        if f.run_conclusion != "success":
            return "release-failed"
        if f.post_rc == 0:
            return "done"
        if f.post_rc in (3, 4):
            return "post-withdrawn"
        return "post"
    if f.pr_state == "MERGED":
        return "tag"
    if f.pr_state != "OPEN":
        return "no-pr"
    if f.failed:
        return "ci-failed"
    if f.pending or f.first_started is None:
        return "ci-wait"
    return "land"


def window_wanted(stage: str, pending: int, remaining_s: float, cfg: Config, stuck: int = 0,
                  long_remaining: float | None = None) -> bool:
    """Whether the release window should be open. `stuck` is `stuck_queued`:
    during CI, a check that waits for a runner keeps the window closed.
    `long_remaining` is `longest_remaining`; when it is known it decides, and
    the count of pending checks and the whole-run estimate are not used."""
    if stage in ("land", "tag"):
        return True
    if stage == "ci-wait":
        if stuck:
            return False
        if long_remaining is not None:
            return long_remaining <= cfg.lead_s
        return pending <= cfg.last_few or remaining_s <= cfg.lead_s
    return False


# A check run's status before a runner has taken its job.
NO_RUNNER_YET = {"QUEUED", "WAITING", "REQUESTED", "PENDING"}


def stuck_queued(items, now: float, grace_s: float) -> int:
    """How many checks of a statusCheckRollup have waited for a runner for at
    least `grace_s` seconds.

    A check that became ready a moment ago is queued for a few seconds on an
    ordinary day, and closing the window for it would let an ordinary job start
    just before the landing. So a queued check counts only once it is
    `grace_s` old, and one whose start time cannot be read does not count.
    A commit status has no runner and never counts."""
    n = 0
    for c in items:
        if "context" in c or (c.get("status") or "").upper() not in NO_RUNNER_YET:
            continue
        t = _epoch(c.get("startedAt"))
        if t is not None and now - t >= grace_s:
            n += 1
    return n


def ci_remaining(f: Facts, cfg: Config, now: float) -> float:
    if f.first_started is None:
        return cfg.expected_ci_s
    return max(0, f.first_started + cfg.expected_ci_s - now)


def _epoch(text: str | None) -> int | None:
    if not text:
        return None
    try:
        t = datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    return int(t.timestamp()) if t.year >= 2000 else None


def check_state(c) -> str:
    """"passed", "failed" or "pending", for one item of a statusCheckRollup.
    The one place that says which checks the landing still waits for."""
    if "context" in c:
        state = c.get("state", "")
        if state in ("FAILURE", "ERROR"):
            return "failed"
        return "passed" if state == "SUCCESS" else "pending"
    if c.get("status") != "COMPLETED":
        return "pending"
    conclusion = (c.get("conclusion") or "").lower()
    if conclusion in BAD_CONCLUSIONS:
        return "failed"
    return "passed" if conclusion in GOOD_CONCLUSIONS else "pending"


def read_rollup(items) -> tuple:
    """(pending, failed names, earliest start) of a statusCheckRollup."""
    pending, failed, started = 0, [], []
    for c in items:
        state = check_state(c)
        if state == "failed":
            failed.append(c.get("name") or c.get("context") or "?")
        elif state == "pending":
            pending += 1
        t = _epoch(c.get("startedAt"))
        if t is not None:
            started.append(t)
    return pending, tuple(failed), min(started) if started else None


def pending_names(items) -> list:
    """The names of the pending check runs of a statusCheckRollup."""
    return [c.get("name") or "?" for c in items if "context" not in c and check_state(c) == "pending"]


def longest_remaining(items, usual: dict, now: float) -> float | None:
    """The most seconds any pending check of a statusCheckRollup still has to
    run: its start, plus what the check of that name took on main (`usual`),
    less `now`, and never under 0.

    None when that cannot be said: nothing is pending, or a pending item is a
    commit status (it has no run time), has no start time, or has a name with
    no usual time. The caller then uses the count of pending checks."""
    longest = None
    for c in items:
        if check_state(c) != "pending":
            continue
        t = _epoch(c.get("startedAt"))
        took = usual.get(c.get("name") or "?")
        if "context" in c or t is None or not isinstance(took, (int, float)):
            return None
        left = max(0, t + took - now)
        longest = left if longest is None else max(longest, left)
    return longest


def usual_from_runs(runs) -> dict:
    """Seconds per check name, from the check runs of a commit: the runs that
    completed with success, the longest when a name has several. A run that
    failed, was canceled or was skipped says nothing about a full run."""
    usual: dict = {}
    for r in runs:
        if not isinstance(r, dict) or not r.get("name"):
            continue
        if r.get("conclusion") != "success":
            continue
        start, end = _epoch(r.get("started_at")), _epoch(r.get("completed_at"))
        if start is None or end is None or end < start:
            continue
        usual[r["name"]] = max(usual.get(r["name"], 0), end - start)
    return usual


def parse_window(text: str) -> tuple:
    """(owner, expiry) from `heavy-run --release-window status`, or (None, None)."""
    m = re.fullmatch(r"open (\S+) until (\S+)\s*", text)
    if not m:
        return None, None
    until = _epoch(m.group(2))
    return (m.group(1), until) if until is not None else (None, None)


def window_owner(cfg: Config) -> str:
    return f"release-{cfg.version}"


# ---------------------------------------------------------------------------
# The world
# ---------------------------------------------------------------------------


def tool(cfg: Config, name: str) -> str:
    return str(pathlib.Path(cfg.bin_dir) / name) if cfg.bin_dir else name


def load_state(cfg: Config) -> dict:
    try:
        return json.loads(cfg.state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(cfg: Config, **changes) -> None:
    state = load_state(cfg)
    state.update(changes)
    cfg.state_file.write_text(json.dumps(state), encoding="utf-8")


def _read_json(run, argv):
    r = run(argv, 120)
    if r.rc != 0:
        raise ReadError(f"{' '.join(argv[:4])}: {r.out.strip()}")
    try:
        return json.loads(r.out)
    except ValueError as e:
        raise ReadError(f"{' '.join(argv[:4])}: not JSON: {e}") from e


def read_usual(cfg: Config, run) -> dict | None:
    """Seconds per check name on main's head commit, or None when GitHub could
    not be read. One line of JSON per check run, so that a paginated answer
    needs no joining."""
    r = run(["gh", "api", f"repos/{cfg.repo}/commits/main/check-runs?per_page=100", "--paginate",
             "--jq", ".check_runs[] | {name, status, conclusion, started_at, completed_at}"], 120)
    if r.rc != 0:
        return None
    runs = []
    for line in r.out.splitlines():
        if not line.strip():
            continue
        try:
            runs.append(json.loads(line))
        except ValueError:
            return None
    return usual_from_runs(runs)


def usual_for(cfg: Config, run, names, now: float) -> dict:
    """The usual times, from the state file; read from GitHub when one of
    `names` has none, and then at most once per `usual_retry_s`.

    A read that fails is not recorded, so the next tick reads again, and the
    train does not stop for it: the window rule falls back to the count."""
    state = load_state(cfg)
    usual = state.get("usual_s")
    usual = dict(usual) if isinstance(usual, dict) else {}
    if all(n in usual for n in names):
        return usual
    read_at = state.get("usual_read_at")
    if isinstance(read_at, (int, float)) and 0 <= now - read_at < cfg.usual_retry_s:
        return usual
    fresh = read_usual(cfg, run)
    if fresh is None:
        return usual
    usual.update(fresh)
    save_state(cfg, usual_s=usual, usual_read_at=now)
    return usual


def read_facts(cfg: Config, run, now: float | None = None) -> Facts:
    """The release's facts. With `now`, the checks that wait for a runner are
    counted (`stuck_queued`) and the longest pending check is estimated
    (`longest_remaining`); without it neither can be judged."""
    prs = _read_json(run, ["gh", "pr", "list", "--repo", cfg.repo, "--head", f"release/{cfg.version}",
                           "--state", "all", "--json", "number,state,headRefOid,mergeCommit", "--limit", "1"])
    pr = prs[0] if prs else {}
    state = pr.get("state", "")
    pending, failed, first, stuck, long_remaining = 0, (), None, 0, None
    if state == "OPEN":
        rollup = _read_json(run, ["gh", "pr", "view", str(pr["number"]), "--repo", cfg.repo,
                                  "--json", "statusCheckRollup"])
        items = rollup.get("statusCheckRollup") or []
        pending, failed, first = read_rollup(items)
        if now is not None:
            stuck = stuck_queued(items, now, cfg.queued_grace_s)
            long_remaining = longest_remaining(items, usual_for(cfg, run, pending_names(items), now), now)
    tag = run(["git", "-C", str(REPO), "ls-remote", "--tags", "origin", f"refs/tags/v{cfg.version}"], 60)
    if tag.rc != 0:
        raise ReadError(f"git ls-remote: {tag.out.strip()}")
    status, conclusion = "", ""
    if tag.out.strip():
        runs = _read_json(run, ["gh", "run", "list", "--repo", cfg.repo, "--workflow", "release.yml",
                                "--branch", f"v{cfg.version}", "--event", "push",
                                "--json", "status,conclusion", "--limit", "1"])
        if runs:
            status, conclusion = runs[0].get("status", ""), runs[0].get("conclusion", "")
    post_rc = load_state(cfg).get("post_rc")
    if cfg.retry_post and post_rc in (3, 4):
        post_rc = None
    return Facts(pr_state=state, pr_number=pr.get("number"), head=pr.get("headRefOid", ""),
                 merge_sha=(pr.get("mergeCommit") or {}).get("oid", ""), pending=pending, failed=failed,
                 first_started=first, tag_exists=bool(tag.out.strip()), run_status=status,
                 run_conclusion=conclusion, post_rc=post_rc, stuck=stuck, long_remaining=long_remaining)


def sync_window(cfg: Config, run, want: bool, now: float) -> str:
    """Make the window match; never touch another owner's. Returns what it did."""
    owner, until = parse_window(run([tool(cfg, "heavy-run"), "--release-window", "status"], 30).out)
    mine = window_owner(cfg)
    if not want:
        if owner == mine:
            run([tool(cfg, "heavy-run"), "--release-window", "close", mine], 30)
            return "close"
        return "none"
    if owner not in (None, mine):
        return "none"
    if owner == mine and until - now >= EXTEND_BELOW_S:
        return "none"
    run([tool(cfg, "heavy-run"), "--release-window", "open", mine, str(cfg.window_minutes)], 30)
    return "open"


# ---------------------------------------------------------------------------
# The local steps
# ---------------------------------------------------------------------------


def post_cla(cfg: Config, run, f: Facts) -> None:
    if load_state(cfg).get("cla_head") == f.head:
        return
    r = run([tool(cfg, "cla-owner-exempt"), cfg.repo, f.head], 400)
    if r.rc != 0:
        raise Stopped(f"the CLA status for {f.head} was not posted: {r.out.strip()}")
    save_state(cfg, cla_head=f.head)


def land(cfg: Config, run, f: Facts) -> None:
    """Land the pull request: `required-checks` on the head, and the merge
    only if it passes, both under the landing lock. The train waits for the
    check rollup, but what may land is that script's rule alone.

    A landing that passed is recorded by `landing_record`."""
    script = (f"{tool(cfg, 'required-checks')} {cfg.repo} {f.head} && "
              f"gh pr merge {f.pr_number} --repo {cfg.repo} --merge --match-head-commit {f.head}")
    r = run([tool(cfg, "land-queue"), "sipnab", "--", "bash", "-c", script], 1800)
    if r.rc != 0:
        raise Stopped(f"landing pull request {f.pr_number} failed: {r.out.strip()}")
    for line in landing_record(cfg.repo, f.pr_number, f.head, r.out):
        print(line)


def landing_record(repo: str, pr_number, head: str, out: str) -> list:
    """The lines the train prints for a landing that ended 0.

    The two tools write nothing for a pass: `required-checks` names only a
    check that is not a success, and `gh pr merge` prints nothing when its
    output is not a terminal. On 0.5.250 the train's output therefore held no
    line of the landing. The exit status 0 of `required-checks ... && gh pr
    merge ...` says that both ran and passed, so the train writes the two
    lines itself. What the landing did print sits between them: a `warning:`
    line of `required-checks` names a check an outside service has not
    completed."""
    said = [line for line in out.splitlines() if line.strip()]
    return [f"land: required-checks {repo} {head} passed (exit status 0)", *said,
            f"land: pull request {pr_number} merged with --match-head-commit {head}"]


def checkout_at_merge(run, f: Facts) -> None:
    """Put this checkout at the merge commit. The pre-push hook's
    release-delivery test reads the files and the HEAD of the checkout it runs
    in, and the train starts before the merge commit exists."""
    git = ["git", "-C", str(REPO)]
    head = run([*git, "rev-parse", "HEAD"], 30)
    if head.out.strip() == f.merge_sha:
        return
    by_hand = (f"The pre-push hook's release-delivery test reads the checkout it runs in, so the tag is "
               f"not pushed from here. Run `git -C {REPO} checkout --detach {f.merge_sha}`, then re-run the train.")
    at = head.out.strip()[:9] or "an unknown commit"
    dirty = run([*git, "status", "--porcelain", "--untracked-files=no"], 60)
    if head.rc != 0 or dirty.rc != 0:
        raise Stopped(f"this checkout's state could not be read: {(head.out if head.rc else dirty.out).strip()}. "
                      f"{by_hand}")
    if dirty.out.strip():
        raise Stopped(f"this checkout is at {at}, not the merge commit {f.merge_sha[:9]}, and it has "
                      f"uncommitted changes, so the train did not move it. Commit or set them aside first. {by_hand}")
    r = run([*git, "checkout", "--detach", f.merge_sha], 120)
    if r.rc != 0:
        raise Stopped(f"this checkout is at {at} and could not be moved to the merge commit "
                      f"{f.merge_sha[:9]}: {r.out.strip()}. {by_hand}")
    after = run([*git, "rev-parse", "HEAD"], 30).out.strip()
    if after != f.merge_sha:
        raise Stopped(f"after `git checkout --detach` this checkout is still at {after[:9] or 'an unknown commit'}, "
                      f"not the merge commit {f.merge_sha[:9]}. {by_hand}")
    print(f"checkout: moved from {at} to the merge commit {f.merge_sha[:9]} (detached)")


def wait_for_proof(cfg: Config, run, f: Facts, sleep, clock) -> None:
    """Wait, bounded, until the pre-push hook's fast path would carry the tag.

    `tag-push-proof.py --ready` is the hook's two queries in one call. GitHub
    lists a merged pull request for its merge commit some time after the
    merge; pushed before that, the tag gets every gate instead of the proof."""
    argv = [sys.executable, str(SCRIPTS / "tag-push-proof.py"), "--ready", f.merge_sha]
    start = clock()
    deadline = start + cfg.proof_wait_s
    while True:
        r = run(argv, 300)
        if r.rc == 0:
            if clock() > start:
                print(f"tag: the proof resolved after {clock() - start:.0f} s")
            return
        if clock() == start:
            print(f"tag: waiting for GitHub's proof of {f.merge_sha[:9]}, at most {cfg.proof_wait_s} s")
        if clock() >= deadline:
            raise Stopped(
                f"GitHub's proof for the merge commit {f.merge_sha[:9]} did not resolve in {cfg.proof_wait_s} s, "
                f"so the tag was not made or pushed. The last answer of `{' '.join(argv[1:])}`:\n"
                f"{r.out.strip()}\nWhen that command exits 0, re-run the train; it resumes at the tag.")
        sleep(cfg.proof_poll_s)


def tag_and_push(cfg: Config, run, f: Facts, sleep=time.sleep, clock=time.time) -> None:
    git = ["git", "-C", str(REPO)]
    name = f"v{cfg.version}"
    r = run([*git, "fetch", "origin", "main"], 300)
    if r.rc != 0:
        raise Stopped(f"git fetch failed: {r.out.strip()}")
    checkout_at_merge(run, f)
    wait_for_proof(cfg, run, f, sleep, clock)
    local = run([*git, "rev-parse", "--verify", "--quiet", f"refs/tags/{name}^{{commit}}"], 30)
    if local.rc == 0:
        if local.out.strip() != f.merge_sha:
            raise Stopped(f"the local tag {name} is on {local.out.strip()}, not the merge commit {f.merge_sha}")
    else:
        r = run([*git, "tag", "-s", "-m", f"sipnab {cfg.version}", name, f.merge_sha], 60)
        if r.rc != 0:
            raise Stopped(f"the signed tag failed: {r.out.strip()}")
    r = run([*git, "verify-tag", name], 30)
    if r.rc != 0:
        raise Stopped(f"the tag {name} does not verify: {r.out.strip()}")
    r = run([tool(cfg, "heavy-run"), "--lane", "--", *git, "push", "origin", name], 3600)
    if r.rc != 0:
        raise Stopped(f"pushing {name} failed: {r.out.strip()}")


def post_checks(cfg: Config, run) -> int:
    r = run([sys.executable, str(SCRIPTS / "post-release.py"), "run", cfg.version, "--host", cfg.host], 1800)
    print(r.out.rstrip())
    save_state(cfg, post_rc=r.rc)
    return r.rc


def tick(cfg: Config, run, clock, sleep=time.sleep, announce=None) -> str:
    """Read the facts, set the window, and take the one local step that is due.

    `announce` is called with the stage before its step runs, so the lines a
    step prints, and the message of a step that stops the train, come after
    the line that names the stage."""
    now = clock()
    f = read_facts(cfg, run, now)
    stage = stage_of(f)
    if announce is not None:
        announce(stage)
    sync_window(cfg, run, window_wanted(stage, f.pending, ci_remaining(f, cfg, now), cfg, f.stuck,
                                        f.long_remaining), now)
    if stage in ("ci-wait", "land"):
        post_cla(cfg, run, f)
    if stage == "land":
        land(cfg, run, f)
    elif stage == "tag":
        tag_and_push(cfg, run, f, sleep, clock)
    elif stage == "post":
        rc = post_checks(cfg, run)
        if rc == 0:
            return "done"
        return "post-withdrawn" if rc in (3, 4) else "post-failed"
    elif stage == "ci-failed":
        print(f"ci-failed: {', '.join(f.failed)}")
    return stage


def train(cfg: Config, run, sleep=time.sleep, clock=time.time) -> int:
    errors = 0
    last = None

    def announce(stage: str) -> None:
        nonlocal last
        if stage != last:
            print(f"stage: {stage}")
            last = stage

    try:
        while True:
            try:
                stage = tick(cfg, run, clock, sleep, announce)
            except ReadError as e:
                errors += 1
                print(f"read failed ({errors} of {READ_ATTEMPTS}): {e}")
                if errors >= READ_ATTEMPTS:
                    print("stopped: GitHub or git could not be read; re-run to resume")
                    return 1
                sleep(cfg.poll)
                continue
            errors = 0
            announce(stage)  # the post step ends in a stage of its own
            if stage == "done":
                return 0
            if stage == "post-withdrawn":
                rc = load_state(cfg).get("post_rc")
                return rc if rc in (3, 4) else 1
            if stage in ("no-pr", "ci-failed", "release-failed", "post-failed"):
                print(f"stopped at {stage}; fix it and re-run to resume")
                return 1
            if stage in WAITS:
                sleep(cfg.poll)
    except Stopped as e:
        print(f"stopped: {e}")
        return 1
    except Exception as e:  # noqa: BLE001 - the window below must close on any failure
        print(f"stopped: the train crashed: {e}")
        return 1
    finally:
        try:
            sync_window(cfg, run, False, clock())
        except Exception as e:  # noqa: BLE001
            print(f"the release window was not closed: {e}; it expires on its own")


def git_dir() -> pathlib.Path:
    out = subprocess.run(["git", "rev-parse", "--absolute-git-dir"], capture_output=True, text=True,
                         check=True, cwd=SCRIPTS).stdout.strip()
    return pathlib.Path(out)


def write_lines_at_once() -> None:
    """Make standard output hand over each line when it is printed.

    Python block-buffers a standard output that is not a terminal. On 0.5.249
    the train's output went to a file, and its "stage:" lines appeared only
    when it ended. An output with no `reconfigure` is left as it is."""
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(line_buffering=True)


def main(argv=None, runner=None) -> int:
    write_lines_at_once()
    p = argparse.ArgumentParser(prog="release-train.py")
    p.add_argument("version")
    # No default: the VM and its account are the operator's, and this
    # repository is public.
    p.add_argument("--host", required=True)
    p.add_argument("--repo", default="NormB/sipnab")
    p.add_argument("--poll", type=float, default=30.0)
    p.add_argument("--bin", default="", help="directory holding heavy-run and land-queue, when not on PATH")
    p.add_argument("--retry-post", action="store_true")
    p.add_argument("--proof-wait", type=int, default=Config.proof_wait_s,
                   help="seconds to wait for GitHub's proof of the merge commit before the tag (default 300)")
    try:
        args = p.parse_args(argv)
    except SystemExit:
        return 2
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        print(f"release-train: the version is X.Y.Z, not {args.version!r}", file=sys.stderr)
        return 2
    if args.proof_wait < 0:
        print(f"release-train: --proof-wait is a number of seconds, 0 or more, not {args.proof_wait}", file=sys.stderr)
        return 2
    cfg = Config(version=args.version, host=args.host, repo=args.repo, poll=args.poll, bin_dir=args.bin,
                 retry_post=args.retry_post, proof_wait_s=args.proof_wait,
                 state_file=git_dir() / f"release-train-{args.version}.json")
    return train(cfg, runner or subprocess_runner)


if __name__ == "__main__":
    sys.exit(main())
