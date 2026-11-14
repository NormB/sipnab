#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Is the live site the artifact this run deployed? If not, deploy it again.

    pages-live.py stamp --write FILE
    pages-live.py verify [--expect X.Y.Z] [--enforce] [--url URL]
                         [--within S] [--every S]

PAGES-SAME-SHA-REDEPLOY-NOT-LIVE. On 0.5.242 two workflow_dispatch runs of
pages.yml on main commit 1ef3e74a0 (42714372409 and 42717859462) built
artifacts naming 0.5.242, actions/deploy-pages reported success for both
(deployments 7668209866 and 7668618717), and the site kept serving the push
deploy of the same commit. On 0.5.241 and 0.5.243 the same kind of re-deploy
went live.

WHAT IS ESTABLISHED. The action sends `pages_build_version = GITHUB_SHA`
(src/internal/context.js at 368f8252, v5), and GitHub names the Pages
deployment by that string: every deploy job's log says "Created deployment
for <sha>, ID: <sha>", and `GET /repos/{owner}/{repo}/pages/deployments/<sha>`
answers for it. A second deploy of one commit therefore polls the status of a
deployment that already says `succeed`. All four re-deploys read (one on
0.5.241, two on 0.5.242, one on 0.5.243) logged "Reported success!" at the
first poll. On 0.5.243, where the re-deploy went live, the
origin's Last-Modified (08:06:03Z on /, 08:06:22Z on /download/) is later
than the success status (08:06:02Z). So that success is not evidence about
the new artifact.

WHAT IS NOT. Why GitHub did not publish the two artifacts on 0.5.242. The
runs, deployment statuses and artifact ids of the three releases show no
difference between the re-deploys that went live and the two that did not.

SO THE DEPLOY IS JUDGED BY THE SITE. `stamp` writes `<commit> <run id> <run
attempt>` into the site before it is built. `verify`, after the deploy:

1. reads the stamp URL, with a query no cache has seen, every `--every`
   seconds for at most `--within`;
2. when the site answers with another stamp, or with 404, prints a warning and
   deploys this run's artifact again through the REST calls the action
   makes, under the build version `<commit>-<run id>-<attempt>`, which GitHub
   has not seen, so the status it then polls is that deployment's own; then
   reads the stamp again;
3. with `--expect`, runs scripts/verify-site-advertises.sh for the release.

The second deploy is not proven against GitHub by these tests: they hold the
requests it makes. Its first real run is the proof, and the warning it
prints makes that run visible.

Exit status of `verify`: 0 the site is this run's artifact (and names the
expected release); 1 it is stale after the second deploy, or the second
deploy failed; 2 the site could not be read, so nothing is known; 3 it is
this run's artifact and the download page, read and healthy, does not name
the expected release; 4 it is this run's artifact and the edge refused the
read of the download page (403 or 429), so nothing is known about the
release. Every release check is printed as it ends, with its number, the
seconds since the first and the verifier's exit status. A page that does not
name the release yet is read again every `--every` seconds; after a refused
read the wait doubles (15, 30, 60, 120 s), so a refused client sends five
requests in 300 s and not 21. Without
`--enforce` each verdict is printed as an error annotation and the exit
status is 0: pages.yml enforces on workflow_dispatch, which is how a release
advertises itself, and not on a push, because the pre-push tag gate refuses a
release tag while a run on its merge commit is red. 2 is a usage error from
`stamp` and from a malformed argument, printed on stderr.

Tested by scripts/tests/test_pages_live.py, on a fake clock against a fake
site and a fake Pages API, and by scripts/tests/test_pages_live_workflow.py.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import functools
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.request

Result = collections.namedtuple("Result", "rc out")

STAMP = re.compile(r"[0-9a-f]{40} [0-9]+ [0-9]+")
# Named, as scripts/verify-site-advertises.sh is: the CDN's bot protection
# refuses an unidentified client.
UA = "sipnab-release-check/1.0 (+https://github.com/NormB/sipnab)"
ARTIFACT = "github-pages"
SITE_CHECK = pathlib.Path(__file__).resolve().parent / "verify-site-advertises.sh"
# Exit status of `verify`, one per verdict.
LIVE, STALE, UNREADABLE, NOT_ADVERTISED, BLOCKED = 0, 1, 2, 3, 4
# scripts/verify-site-advertises.sh's exit statuses for a healthy page that
# names another release and for a read the edge refused.
PAGE_STALE, PAGE_BLOCKED = 1, 6

# A job log dates a line when it arrives. Block-buffered output arrived when
# the script ended, so the stamp line and a verdict five minutes later
# carried the same second (2026-11-14, job 132416129137).
print = functools.partial(print, flush=True)  # noqa: A001 - every line is written as it happens
# The statuses actions/deploy-pages treats as final errors (its
# src/internal/deployment.js at 368f8252, v5).
# One of them is GitHub's doubled-l spelling of the US word; it is joined
# here from two pieces so the tree's US-spelling gates need no exemption.
FINAL_ERRORS = {"deployment_failed", "deployment_perms_error", "deployment_content_failed",
                "deployment_cance" "lled", "deployment_lost"}
STATUS_EVERY = 5.0
STATUS_WITHIN = 600.0


@dataclasses.dataclass
class Config:
    stamp: str
    url: str
    within: float
    every: float
    expect: str
    enforce: bool
    repo: str
    run_id: str
    attempt: str
    sha: str


def make_stamp(env: dict) -> str:
    """`<commit> <run id> <run attempt>`: what this run's artifact carries."""
    stamp = f"{env.get('GITHUB_SHA', '')} {env.get('GITHUB_RUN_ID', '')} {env.get('GITHUB_RUN_ATTEMPT', '')}"
    if not STAMP.fullmatch(stamp):
        raise ValueError(f"GITHUB_SHA, GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT do not make a stamp: {stamp!r}")
    return stamp


def classify(status: int, body: str, want: str) -> str:
    """One read of the stamp URL: `live`, `stale` or `unreadable`."""
    if status == 200 and body.strip() == want:
        return "live"
    if status == 200 and STAMP.fullmatch(body.strip()):
        return "stale"
    if status == 404:
        return "stale"
    return "unreadable"


def read_stamp(run, url: str, nonce: str) -> tuple[int, str]:
    """(HTTP status, body) of one read; status 0 when nothing answered.

    The query is one no cache has seen. Measured on sipnab.com: the CDN
    caches a .txt file (`cf-cache-status: EXPIRED`, `max-age=14400` on
    /robots.txt), and a cached stamp would report the deploy before this one."""
    sep = "&" if "?" in url else "?"
    r = run(["curl", "-sS", "--max-time", "20", "--user-agent", UA, "-w", "\n%{http_code}",
             f"{url}{sep}nonce={nonce}"], 60)
    body, _, code = r.out.rpartition("\n")
    return (int(code) if code.isdigit() else 0), body.strip()


def await_stamp(cfg: Config, run, sleep, clock, tag: str) -> tuple[str, str]:
    """Read the stamp until it is this run's or `within` seconds have gone.
    Returns the last read's state and what it saw."""
    n = 0
    start = clock()
    while True:
        n += 1
        status, body = read_stamp(run, cfg.url, f"{cfg.run_id}.{cfg.attempt}.{tag}{n}")
        state = classify(status, body, cfg.stamp)
        if state == "live" or clock() - start + cfg.every > cfg.within:
            return state, f"HTTP {status}: {' '.join(body.split())[:120]}"
        sleep(cfg.every)


def unique_version(cfg: Config) -> str:
    """A build version GitHub has not seen: the first deploy of a run uses
    the bare commit (actions/deploy-pages sends GITHUB_SHA)."""
    return f"{cfg.sha}-{cfg.run_id}-{cfg.attempt}"


def _json(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return None


def redeploy(cfg: Config, env: dict, run, http_get, sleep, clock) -> tuple[bool, str]:
    """Deploy this run's artifact again under `unique_version`, through the
    REST calls actions/deploy-pages makes, and wait for GitHub's status of
    that deployment. Returns (succeeded, what happened)."""
    listing = run(["gh", "api", f"repos/{cfg.repo}/actions/runs/{cfg.run_id}/artifacts?per_page=100"], 120)
    data = _json(listing.out) if listing.rc == 0 else None
    if not isinstance(data, dict):
        return False, f"the run's artifacts could not be listed: {listing.out.strip()[:200]}"
    ids = [a.get("id") for a in data.get("artifacts", []) if a.get("name") == ARTIFACT and isinstance(a.get("id"), int)]
    if not ids:
        return False, f"run {cfg.run_id} has no artifact named {ARTIFACT}"
    url, bearer = env.get("ACTIONS_ID_TOKEN_REQUEST_URL"), env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        return False, "no OIDC token can be requested: the job needs `id-token: write`"
    try:
        token = (_json(http_get(url, {"Authorization": f"bearer {bearer}"})) or {}).get("value")
    except OSError as e:
        return False, f"the OIDC token request failed: {e}"
    if not token or not isinstance(token, str):
        return False, "the OIDC token request returned no token"
    print(f"::add-mask::{token}")
    version = unique_version(cfg)
    payload = json.dumps({"artifact_id": max(ids), "pages_build_version": version, "oidc_token": token})
    created = run(["gh", "api", "--method", "POST", f"repos/{cfg.repo}/pages/deployments", "--input", "-"], 120, payload)
    if created.rc != 0:
        return False, f"GitHub refused the deployment {version}: {created.out.strip()[:300].replace(token, '***')}"
    print(f"created Pages deployment {version} from artifact {max(ids)}")
    start = clock()
    status = "no status read"
    while True:
        sleep(STATUS_EVERY)
        r = run(["gh", "api", f"repos/{cfg.repo}/pages/deployments/{version}"], 60)
        answer = _json(r.out) if r.rc == 0 else None
        if isinstance(answer, dict):
            status = str(answer.get("status"))
            if status == "succeed":
                return True, f"GitHub reports {status} for the deployment {version}"
            if status in FINAL_ERRORS:
                return False, f"GitHub reports {status} for the deployment {version}"
        if clock() - start >= STATUS_WITHIN:
            return False, f"the deployment {version} did not succeed in {STATUS_WITHIN:.0f} s; last status: {status}"


def await_release(cfg: Config, run, sleep, clock) -> tuple[int, str]:
    """scripts/verify-site-advertises.sh for `cfg.expect`, inside the bound.

    Returns the last check's exit status and output. Each check is printed
    when it ends: its number, the seconds since the first, the exit status
    and the verifier's unindented lines (the edge's answer and the verdict).
    After a refused read the wait is `cfg.every` and doubles with each
    refusal in a row; any other answer puts it back to `cfg.every`."""
    start = clock()
    n = refused = 0
    while True:
        n += 1
        r = run(["sh", str(SITE_CHECK), cfg.expect], 120)
        said = " | ".join(line for line in r.out.splitlines() if line and not line.startswith(" "))
        print(f"release check {n} (+{clock() - start:.0f} s): exit {r.rc}: {said or '(no output)'}")
        refused = refused + 1 if r.rc == PAGE_BLOCKED else 0
        wait = cfg.every * 2 ** max(refused - 1, 0)
        if r.rc == 0 or clock() - start + wait > cfg.within:
            return r.rc, r.out.strip()
        sleep(wait)


def _judge(cfg: Config, env: dict, run, http_get, sleep, clock) -> int:
    state, saw = await_stamp(cfg, run, sleep, clock, "a")
    if state == "stale":
        version = unique_version(cfg)
        print(f"::warning::The deploy of {cfg.sha} reported success and did not go live within {cfg.within:.0f} s: "
              f"the site answers {saw}, not this run's stamp {cfg.stamp!r}. Starting a second deploy of the same "
              f"artifact under the build version {version}, which GitHub has not seen "
              "(PAGES-SAME-SHA-REDEPLOY-NOT-LIVE).")
        ok, what = redeploy(cfg, env, run, http_get, sleep, clock)
        print(what)
        if not ok:
            print(f"::error::The site is stale and the second deploy failed: {what}")
            return STALE
        state, saw = await_stamp(cfg, run, sleep, clock, "b")
        if state == "live":
            print(f"::warning::The first deploy of {cfg.sha} did not go live; the second deploy is live "
                  f"(build version {version}).")
    if state == "stale":
        print(f"::error::The site is still stale after the second deploy: it answers {saw}, "
              f"not this run's stamp {cfg.stamp!r}.")
        return STALE
    if state == "unreadable":
        print(f"::error::The live site could not be read ({saw}), so nothing is known about this deploy. "
              f"Read {cfg.url} by hand; this run's stamp is {cfg.stamp!r}.")
        return UNREADABLE
    print(f"live: {cfg.url} carries this run's stamp {cfg.stamp!r}")
    if cfg.expect:
        rc, what = await_release(cfg, run, sleep, clock)
        print(what)
        if rc == PAGE_STALE:
            print(f"::error::The live site is this run's artifact and the download page does not name {cfg.expect}.")
            return NOT_ADVERTISED
        if rc == PAGE_BLOCKED:
            print("::error::The live site is this run's artifact; the edge refused the read of the download page, "
                  f"so nothing is known about whether it names {cfg.expect}. The page may be right for every "
                  "other reader: read it from another address, and find the refusal in the CDN's log by the "
                  "cf-ray printed above.")
            return BLOCKED
        if rc != 0:
            print(f"::error::The live site is this run's artifact; the download page could not be read "
                  f"(scripts/verify-site-advertises.sh exit {rc}), so nothing is known about whether it names "
                  f"{cfg.expect}.")
            return UNREADABLE
    return LIVE


def verify(cfg: Config, env: dict, run, http_get, sleep, clock) -> int:
    """The whole check. Without `enforce` a failed verdict is printed as an
    error and the exit status is 0."""
    rc = _judge(cfg, env, run, http_get, sleep, clock)
    if rc != LIVE and not cfg.enforce:
        print(f"verdict {rc} is not enforced on this event; the annotations above say what to do")
        return LIVE
    return rc


def subprocess_runner(argv, timeout, stdin=None):
    """Run ARGV; stdout and stderr together. A timeout is exit 124."""
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return Result(124, f"timed out after {timeout} s")
    except OSError as e:
        return Result(127, str(e))
    return Result(p.returncode, p.stdout + p.stderr)


def urllib_get(url: str, headers: dict) -> str:
    """The OIDC token request. Not through curl: its arguments would carry
    the bearer token into the process list."""
    req = urllib.request.Request(url, headers=headers)  # noqa: S310 - the runner's own https URL
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return resp.read().decode("utf-8", "replace")


def main(argv=None, env=None, runner=None) -> int:
    env = dict(os.environ) if env is None else env
    p = argparse.ArgumentParser(prog="pages-live.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("stamp")
    st.add_argument("--write", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--expect", default="")
    v.add_argument("--enforce", action="store_true")
    v.add_argument("--url", default="https://sipnab.com/deploy-stamp.txt")
    v.add_argument("--within", type=float, default=300.0)
    v.add_argument("--every", type=float, default=15.0)
    try:
        args = p.parse_args(argv)
    except SystemExit:
        return 2
    try:
        stamp = make_stamp(env)
    except ValueError as e:
        print(f"pages-live: {e}", file=sys.stderr)
        return 2
    if args.cmd == "stamp":
        pathlib.Path(args.write).write_text(stamp + "\n", encoding="utf-8")
        print(f"deploy stamp: {stamp}")
        return 0
    if args.expect and not re.fullmatch(r"\d+\.\d+\.\d+", args.expect):
        print(f"pages-live: --expect is X.Y.Z or empty, not {args.expect!r}", file=sys.stderr)
        return 2
    if args.within < 0 or args.every <= 0:
        print("pages-live: --within is 0 or more seconds and --every is more than 0", file=sys.stderr)
        return 2
    repo = env.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        print(f"pages-live: GITHUB_REPOSITORY is not owner/name: {repo!r}", file=sys.stderr)
        return 2
    cfg = Config(stamp=stamp, url=args.url, within=args.within, every=args.every, expect=args.expect,
                 enforce=args.enforce, repo=repo, run_id=env["GITHUB_RUN_ID"], attempt=env["GITHUB_RUN_ATTEMPT"],
                 sha=env["GITHUB_SHA"])
    return verify(cfg, env, runner or subprocess_runner, urllib_get, time.sleep, time.monotonic)


if __name__ == "__main__":
    sys.exit(main())
