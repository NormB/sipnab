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
- during the pull request's CI, closed, until at most `last_few` checks are
  pending or `lead_s` seconds remain of CI's expected run;
- closed for the release workflow and the post checks, which use no main slot.

Measured: on 0.5.239 there was no window, and the tag push waited 769 s behind
an ordinary job that had started 7 s before it. On 0.5.240 the window was
closed for all of CI, an ordinary hook started in the same second, and the tag
queued 434 s behind it. The default estimate is 0.5.240's 37 min of pull
request CI.

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

The state file holds two values GitHub cannot be asked for: the post checks'
exit status and the head the CLA status was posted for.

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


def window_wanted(stage: str, pending: int, remaining_s: float, cfg: Config) -> bool:
    if stage in ("land", "tag"):
        return True
    if stage == "ci-wait":
        return pending <= cfg.last_few or remaining_s <= cfg.lead_s
    return False


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


def read_rollup(items) -> tuple:
    """(pending, failed names, earliest start) of a statusCheckRollup."""
    pending, failed, started = 0, [], []
    for c in items:
        name = c.get("name") or c.get("context") or "?"
        if "context" in c:
            state = c.get("state", "")
            if state in ("FAILURE", "ERROR"):
                failed.append(name)
            elif state != "SUCCESS":
                pending += 1
        elif c.get("status") != "COMPLETED":
            pending += 1
        elif (c.get("conclusion") or "").lower() in BAD_CONCLUSIONS:
            failed.append(name)
        elif (c.get("conclusion") or "").lower() not in GOOD_CONCLUSIONS:
            pending += 1
        t = _epoch(c.get("startedAt"))
        if t is not None:
            started.append(t)
    return pending, tuple(failed), min(started) if started else None


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


def read_facts(cfg: Config, run) -> Facts:
    prs = _read_json(run, ["gh", "pr", "list", "--repo", cfg.repo, "--head", f"release/{cfg.version}",
                           "--state", "all", "--json", "number,state,headRefOid,mergeCommit", "--limit", "1"])
    pr = prs[0] if prs else {}
    state = pr.get("state", "")
    pending, failed, first = 0, (), None
    if state == "OPEN":
        rollup = _read_json(run, ["gh", "pr", "view", str(pr["number"]), "--repo", cfg.repo,
                                  "--json", "statusCheckRollup"])
        pending, failed, first = read_rollup(rollup.get("statusCheckRollup") or [])
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
                 run_conclusion=conclusion, post_rc=post_rc)


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
    script = (f"{tool(cfg, 'required-checks')} {cfg.repo} {f.head} && "
              f"gh pr merge {f.pr_number} --repo {cfg.repo} --merge --match-head-commit {f.head}")
    r = run([tool(cfg, "land-queue"), "sipnab", "--", "bash", "-c", script], 1800)
    if r.rc != 0:
        raise Stopped(f"landing pull request {f.pr_number} failed: {r.out.strip()}")


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


def tick(cfg: Config, run, clock, sleep=time.sleep) -> str:
    """Read the facts, set the window, and take the one local step that is due."""
    now = clock()
    f = read_facts(cfg, run)
    stage = stage_of(f)
    sync_window(cfg, run, window_wanted(stage, f.pending, ci_remaining(f, cfg, now), cfg), now)
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
    try:
        while True:
            try:
                stage = tick(cfg, run, clock, sleep)
            except ReadError as e:
                errors += 1
                print(f"read failed ({errors} of {READ_ATTEMPTS}): {e}")
                if errors >= READ_ATTEMPTS:
                    print("stopped: GitHub or git could not be read; re-run to resume")
                    return 1
                sleep(cfg.poll)
                continue
            errors = 0
            if stage != last:
                print(f"stage: {stage}")
                last = stage
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


def main(argv=None, runner=None) -> int:
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
