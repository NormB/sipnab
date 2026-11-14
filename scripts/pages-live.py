#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Is the live site the artifact this run deployed? If not, deploy it again.

    pages-live.py stamp --write FILE
    pages-live.py advertised --site DIR --config FILE
    pages-live.py verify [--expect X.Y.Z] [--enforce] [--url URL]
                         [--within S] [--every S] [--artifact TAR]
    pages-live.py daily --expect X.Y.Z [--url URL]

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

THE RELEASE VERDICT COMES FROM THE RUN'S OWN ARTIFACT
(CDN-REFUSED-RELEASE-CHECK-FROM-RUNNER). On 2026-11-14 the 0.5.254 release
run 43581489173 ended red twice: the live stamp was the run's, and the CDN
answered the hosted runner's read of the download page with a browser
challenge (403, `cf-mitigated: challenge`). The CDN challenges reads of HTML
pages from that runner image and answers static `.txt` files from every
runner. So:

* `advertised`, in the build after the site is generated, judges the built
  `download/index.html` with `verify-site-advertises.sh --classify` for the
  `published_version` of the site's config, fails the build when the page
  does not name it, and writes `advertised-release.txt` into the site: the
  stamp, that release and the page's sha256.
* `verify --artifact TAR` (the tar inside this run's `github-pages`
  artifact), once the live stamp is this run's: requires the artifact's
  stamp and its record to carry this run's stamp, judges the artifact's
  download page with the same `--classify`, requires the record to name the
  same release and the page's sha256, and requires the live
  `advertised-release.txt` to be the artifact's. The tar is read in memory:
  three members, each a regular file of at most MAX_MEMBER bytes; a member
  name that leaves the site refuses the whole archive. The live read of the
  download page stays as evidence: a page that answers and does not name
  the release fails the run; a read the edge refused is a warning that
  carries the edge's answer, and no second request is sent.
* `daily` (cert-expiry.yml) reads the two static files and the live page
  once. Files of one deploy that name the release verify it when the edge
  refuses the page; a page that answers is judged as before. When neither
  can be read the step writes a line that starts with `NOT VERIFIED:` to the
  job summary and to a warning, and the exit status is 0. What the files prove: what the page of
  the deployed build said. What they do not: that the edge serves that page
  to a visitor.

Exit status of `verify`: 0 the site is this run's artifact (and names the
expected release); 1 it is stale after the second deploy, or the second
deploy failed, or the live `advertised-release.txt` is not the artifact's;
2 the site could not be read, so nothing is known; 3 it is this run's
artifact and the download page (the artifact's, or the live one, read and
healthy) does not name the expected release, or the artifact's record
disagrees with its page; 4 nothing is known about the release: the artifact
could not be read or is not this deploy's, or, without `--artifact`, the
edge refused the read of the download page (403 or 429). Every release
check is printed as it ends, with its number, the
seconds since the first and the verifier's exit status. A page that does not
name the release yet is read again every `--every` seconds; after a refused
read, without `--artifact`, the wait doubles (15, 30, 60, 120 s), so a
refused client sends five requests in 300 s and not 21. Exit status of
`daily`: 0 verified, or not verified with the warning; 1 the site does not
advertise the release; otherwise the verifier's status for a page that gave
no answer to judge. Exit status of `advertised`: 0 written; 1 the built page
does not name the release. Without
`--enforce` each verdict is printed as an error annotation and the exit
status is 0: pages.yml enforces on workflow_dispatch, which is how a release
advertises itself, and not on a push, because the pre-push tag gate refuses a
release tag while a run on its merge commit is red. 2 is a usage error from
`stamp` and from a malformed argument, printed on stderr.

Tested by scripts/tests/test_pages_live.py and
scripts/tests/test_pages_live_artifact.py, on a fake clock against a fake
site and a fake Pages API, and by scripts/tests/test_pages_live_workflow.py.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import functools
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

Result = collections.namedtuple("Result", "rc out")
Advertised = collections.namedtuple("Advertised", "stamp release sha256")

STAMP = re.compile(r"[0-9a-f]{40} [0-9]+ [0-9]+")
# The three files read from the artifact, by their path inside the site.
STAMP_FILE = "deploy-stamp.txt"
PAGE_FILE = "download/index.html"
RECORD_FILE = "advertised-release.txt"
RECORD = re.compile(rf"stamp ({STAMP.pattern})\nrelease ([0-9]+\.[0-9]+\.[0-9]+)\nsha256 ([0-9a-f]{{64}})")
# Bounds on the artifact read. The download page of 0.5.254 is under 100 kB
# and the site has about 600 files.
MAX_MEMBER = 4 * 1024 * 1024
MAX_MEMBERS = 100_000
# How often `daily` reads the two static files again when they are of two
# deploys (a deploy can land between the two reads).
DAILY_READS = 3
# Named, as scripts/verify-site-advertises.sh is: the CDN's bot protection
# refuses an unidentified client.
UA = "sipnab-release-check/1.0 (+https://github.com/NormB/sipnab)"
ARTIFACT = "github-pages"
SITE_CHECK = pathlib.Path(__file__).resolve().parent / "verify-site-advertises.sh"
# Exit status of `verify`, one per verdict.
LIVE, STALE, UNREADABLE, NOT_ADVERTISED, BLOCKED = 0, 1, 2, 3, 4
# scripts/verify-site-advertises.sh's exit statuses for a healthy page that
# names another release, for an answer that is no download page and for a
# read the edge refused.
PAGE_STALE, PAGE_EMPTY, PAGE_BLOCKED = 1, 5, 6

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
    # The tar of this run's `github-pages` artifact; empty when the caller
    # has none, and then the release is judged by the live page alone.
    artifact: str = ""
    advertised_url: str = ""


class ArtifactError(Exception):
    """The artifact could not be read as a site that carries the three files."""


def read_artifact(path: str) -> dict:
    """The stamp, the download page and the record out of the artifact's tar,
    as bytes by their path inside the site. Nothing is written to disk and
    nothing is decompressed.

    Refused, with ArtifactError: a file that is not an uncompressed tar; a
    member name that is absolute or holds `..`, anywhere in the archive; more
    than MAX_MEMBERS members; one of the three files missing, there twice,
    not a regular file, or larger than MAX_MEMBER bytes."""
    wanted = (STAMP_FILE, PAGE_FILE, RECORD_FILE)
    found = {}
    try:
        with tarfile.open(path, "r:") as tar:
            for n, member in enumerate(tar, 1):
                if n > MAX_MEMBERS:
                    raise ArtifactError(f"{path} holds more than {MAX_MEMBERS} members")
                parts = member.name.split("/")
                if member.name.startswith("/") or ".." in parts:
                    raise ArtifactError(f"{path} holds a member outside the site: {member.name!r}")
                name = "/".join(p for p in parts if p not in ("", "."))
                if name not in wanted:
                    continue
                if name in found:
                    raise ArtifactError(f"{path} holds {name} twice")
                if not member.isreg():
                    raise ArtifactError(f"{name} in {path} is not a regular file")
                if member.size > MAX_MEMBER:
                    raise ArtifactError(f"{name} in {path} is {member.size} bytes, more than the {MAX_MEMBER} read")
                handle = tar.extractfile(member)
                data = handle.read(MAX_MEMBER + 1) if handle else b""
                if len(data) != member.size:
                    raise ArtifactError(f"{name} in {path} is cut short: {len(data)} of {member.size} bytes")
                found[name] = data
    except tarfile.TarError as e:
        raise ArtifactError(f"{path} is not a tar that can be read: {e}") from e
    except (OSError, EOFError) as e:
        raise ArtifactError(f"{path} could not be read: {e}") from e
    for name in wanted:
        if name not in found:
            raise ArtifactError(f"{path} has no {name}")
    return found


def format_advertised(stamp: str, release: str, page: bytes) -> str:
    """The text of advertised-release.txt for a built download page."""
    return f"stamp {stamp}\nrelease {release}\nsha256 {hashlib.sha256(page).hexdigest()}\n"


def parse_advertised(text: str):
    """The record in the text of advertised-release.txt, or None."""
    m = RECORD.fullmatch(text.replace("\r\n", "\n").strip())
    return Advertised(*m.groups()) if m else None


def judge_page(run, page: bytes, want: str) -> Result:
    """Does this download page name `want`? One rule for a live page and for
    a page out of a build or an artifact: the verifier's `--classify`, given
    the status line of an answered read and the page."""
    return run(["sh", str(SITE_CHECK), "--classify", want], 60, "200\n" + page.decode("utf-8", "replace"))


def first_line(text: str) -> str:
    return (text.strip().splitlines() or ["(no output)"])[0]


def write_advertised(site: pathlib.Path, config: pathlib.Path, stamp: str, run) -> int:
    """The build's step: judge the built download page, write the record."""
    try:
        m = re.search(r'(?m)^published_version = "([0-9]+\.[0-9]+\.[0-9]+)"\s*$', config.read_text(encoding="utf-8"))
    except OSError as e:
        print(f"::error::{config} could not be read: {e}")
        return 1
    if not m:
        print(f"::error::{config} holds no published_version of the form x.y.z, so the release the site "
              "advertises is not known.")
        return 1
    release = m.group(1)
    try:
        page = (site / PAGE_FILE).read_bytes()
    except OSError as e:
        print(f"::error::the built site has no {PAGE_FILE}: {e}")
        return 1
    r = judge_page(run, page, release)
    if r.rc != 0:
        print(f"::error::The built download page does not name {release}, the release this deploy advertises "
              f"(scripts/verify-site-advertises.sh --classify exit {r.rc}: {first_line(r.out)}). "
              f"{RECORD_FILE} is not written and the site is not published.")
        return 1
    text = format_advertised(stamp, release, page)
    (site / RECORD_FILE).write_text(text, encoding="utf-8")
    print(f"{RECORD_FILE}:\n{text}", end="")
    return 0


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


def said(out: str) -> str:
    """The verifier's unindented lines on one line: the edge's answer and the
    verdict, without the advice under them."""
    return " | ".join(line for line in out.splitlines() if line and not line.startswith(" ")) or "(no output)"


def await_release(cfg: Config, run, sleep, clock, evidence: str = "") -> tuple[int, str]:
    """scripts/verify-site-advertises.sh for `cfg.expect`, inside the bound.

    Returns the last check's exit status and output. Each check is printed
    when it ends: its number, the seconds since the first, the exit status
    and the verifier's unindented lines (the edge's answer and the verdict).
    After a refused read the wait is `cfg.every` and doubles with each
    refusal in a row; any other answer puts it back to `cfg.every`.

    `evidence` is for a caller whose verdict does not come from this read:
    `refused` ends the checks at the first read the edge refused, because a
    challenge is not passed by asking again; `once` ends them after one."""
    start = clock()
    n = refused = 0
    while True:
        n += 1
        r = run(["sh", str(SITE_CHECK), cfg.expect], 120)
        print(f"release check {n} (+{clock() - start:.0f} s): exit {r.rc}: {said(r.out)}")
        refused = refused + 1 if r.rc == PAGE_BLOCKED else 0
        wait = cfg.every * 2 ** max(refused - 1, 0)
        if r.rc == 0 or clock() - start + wait > cfg.within:
            return r.rc, r.out.strip()
        if evidence == "once" or (evidence == "refused" and r.rc == PAGE_BLOCKED):
            return r.rc, r.out.strip()
        sleep(wait)


def judge_artifact(cfg: Config, run) -> tuple[int, str]:
    """The verdict of this run's own artifact, and the release it was judged
    for (`cfg.expect`, or on a run that expects none the release the
    artifact's record names). LIVE: the artifact and its record carry this
    run's stamp, its download page names the release by the verifier's
    `--classify`, and the record names that release and that page's sha256."""
    try:
        files = read_artifact(cfg.artifact)
    except ArtifactError as e:
        print(f"::error::This run's site artifact could not be read ({e}), so nothing is known about the release "
              "this deploy advertises. The job downloads it in the step before this one: read that step's log.")
        return BLOCKED, cfg.expect
    stamp = files[STAMP_FILE].decode("utf-8", "replace").strip()
    if stamp != cfg.stamp:
        print(f"::error::The artifact read is not this deploy: its stamp is {stamp[:120]!r} and this run's is "
              f"{cfg.stamp!r}. Nothing is known about the release this deploy advertises.")
        return BLOCKED, cfg.expect
    record = parse_advertised(files[RECORD_FILE].decode("utf-8", "replace"))
    if record is None:
        print(f"::error::The artifact's {RECORD_FILE} is not a record (stamp, release, sha256), so nothing is "
              "known about the release this deploy advertises.")
        return BLOCKED, cfg.expect
    if record.stamp != cfg.stamp:
        print(f"::error::The artifact's {RECORD_FILE} is not this deploy: its stamp is {record.stamp!r} and this "
              f"run's is {cfg.stamp!r}.")
        return BLOCKED, cfg.expect
    want = cfg.expect or record.release
    page = files[PAGE_FILE]
    digest = hashlib.sha256(page).hexdigest()
    r = judge_page(run, page, want)
    if r.rc in (PAGE_STALE, PAGE_EMPTY):
        print(f"::error::The download page in this run's artifact does not name {want} "
              f"(sha256 {digest}; scripts/verify-site-advertises.sh --classify exit {r.rc}: {first_line(r.out)}). "
              "This is the page the deploy published, whatever a read of the live page says.")
        return NOT_ADVERTISED, want
    if r.rc != 0:
        print(f"::error::The download page in this run's artifact could not be judged "
              f"(scripts/verify-site-advertises.sh --classify exit {r.rc}: {first_line(r.out)}), so nothing is known "
              f"about whether it names {want}.")
        return BLOCKED, want
    if record.release != want:
        print(f"::error::The artifact's download page names {want} and its {RECORD_FILE} names {record.release}: "
              "the daily check reads that file and would judge another release.")
        return NOT_ADVERTISED, want
    if record.sha256 != digest:
        print(f"::error::The artifact's {RECORD_FILE} carries sha256 {record.sha256} and its download page is "
              f"sha256 {digest}: the record was not made from the page that was published.")
        return NOT_ADVERTISED, want
    print(f"artifact: {cfg.artifact} carries this run's stamp {cfg.stamp!r}; its download page (sha256 {digest}) "
          f"names {want}, and its {RECORD_FILE} says the same")
    return LIVE, want


def await_record(cfg: Config, run, sleep, clock) -> tuple[str, str]:
    """Read the live advertised-release.txt until it carries this run's stamp
    or `within` seconds have gone. A read the edge refused ends the wait:
    asking again does not pass a refusal. Returns the last read's state
    (`live`, `stale`, `refused` or `unreadable`) and what it saw."""
    n = 0
    start = clock()
    while True:
        n += 1
        status, body = read_stamp(run, cfg.advertised_url, f"{cfg.run_id}.{cfg.attempt}.r{n}")
        record = parse_advertised(body) if status == 200 else None
        if record is not None and record.stamp == cfg.stamp:
            state = "live"
        elif record is not None or status == 404:
            state = "stale"
        elif status in (403, 429):
            state = "refused"
        else:
            state = "unreadable"
        if state in ("live", "refused") or clock() - start + cfg.every > cfg.within:
            return state, f"HTTP {status}: {' '.join(body.split())[:160]}"
        sleep(cfg.every)


def _judge_release(cfg: Config, run, sleep, clock) -> int:
    """After the stamp is live, with this run's artifact: the verdict comes
    from the artifact, and the live reads are checked against it."""
    rc, want = judge_artifact(cfg, run)
    if rc != LIVE:
        if cfg.expect:
            # Evidence for whoever reads the log; the verdict stands.
            await_release(cfg, run, sleep, clock, evidence="once")
        return rc
    state, saw = await_record(cfg, run, sleep, clock)
    if state == "live":
        print(f"live: {cfg.advertised_url} is the record this run's artifact carries")
    elif state == "stale":
        print(f"::error::The live stamp is this run's and {cfg.advertised_url} is not this run's record after "
              f"{cfg.within:.0f} s: it answers {saw}. The daily check reads that file.")
        return STALE
    else:
        print(f"::warning::{cfg.advertised_url} could not be read ({saw}); the artifact's record names {want}. "
              "The daily check reads that file and will not verify the release from it while this lasts.")
    if not cfg.expect:
        return LIVE
    rc, what = await_release(cfg, run, sleep, clock, evidence="refused")
    if rc == 0:
        return LIVE
    if rc == PAGE_BLOCKED:
        print(f"::warning::The edge refused the read of the live download page ({said(what)}). The verdict comes "
              f"from this run's artifact, which is the live site by its stamp and names {cfg.expect}. The refusal "
              "is in the CDN's log under the cf-ray above.")
        return LIVE
    print(what)
    if rc == PAGE_STALE:
        print(f"::error::This run's artifact names {cfg.expect} and the live download page, read and healthy, "
              f"does not after {cfg.within:.0f} s: the edge serves another page than the one deployed.")
        return NOT_ADVERTISED
    print(f"::error::This run's artifact names {cfg.expect}; the live download page gave no answer to judge "
          f"(scripts/verify-site-advertises.sh exit {rc}), so the site is not known to serve it.")
    return UNREADABLE


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
    if cfg.artifact:
        return _judge_release(cfg, run, sleep, clock)
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


def static_state(stamp_read: tuple[int, str], record_read: tuple[int, str], expect: str) -> tuple[str, str]:
    """What one read of the live stamp and one of the live record say about
    `expect`: `ok` they are of one deploy and the record names it; `other`
    they are of one deploy and the record names another release; `mixed`
    they are of two deploys; `unknown` one of them is not what it should be."""
    (s_status, s_body), (r_status, r_body) = stamp_read, record_read
    if s_status != 200 or not STAMP.fullmatch(s_body.strip()):
        return "unknown", f"{STAMP_FILE} answered HTTP {s_status}: {' '.join(s_body.split())[:80]}"
    record = parse_advertised(r_body) if r_status == 200 else None
    if record is None:
        return "unknown", f"{RECORD_FILE} answered HTTP {r_status}: {' '.join(r_body.split())[:80]}"
    if record.stamp != s_body.strip():
        return "mixed", f"{STAMP_FILE} is of the deploy {s_body.strip()!r} and {RECORD_FILE} of {record.stamp!r}"
    if record.release != expect:
        return "other", (f"{RECORD_FILE} of the live deploy {record.stamp!r} names {record.release}, "
                         f"not {expect}")
    return "ok", f"{RECORD_FILE} of the live deploy {record.stamp!r} names {expect} (page sha256 {record.sha256})"


def daily_verdict(static: str, page_rc: int) -> tuple[int, str]:
    """The daily check's exit status and verdict from what the static files
    say (`ok`, `other`, `unknown`) and the verifier's status for the live
    page. A page that answered and does not name the release fails whatever
    the files say; a refused read (6) leaves the verdict to the files, and
    with files that say nothing the release is not verified."""
    if static == "other" or page_rc == PAGE_STALE:
        return 1, "not-advertised"
    if page_rc == 0 or (page_rc == PAGE_BLOCKED and static == "ok"):
        return 0, "verified"
    if page_rc == PAGE_BLOCKED:
        return 0, "not-verified"
    return page_rc, "unreadable"


def daily(expect: str, base: str, env: dict, run, sleep, clock, every: float = 15.0) -> int:
    """cert-expiry.yml's advertisement check: does the live site advertise
    `expect`? Prints the verdict, appends one line to the job summary and
    returns the exit status."""
    nonce = f"{env.get('GITHUB_RUN_ID', '0')}.{env.get('GITHUB_RUN_ATTEMPT', '0')}"
    for n in range(1, DAILY_READS + 1):
        static, detail = static_state(read_stamp(run, base + STAMP_FILE, f"{nonce}.d{n}"),
                                      read_stamp(run, base + RECORD_FILE, f"{nonce}.d{n}"), expect)
        print(f"static read {n}: {static}: {detail}")
        if static != "mixed" or n == DAILY_READS:
            break
        sleep(every)
    if static == "mixed":
        static = "unknown"
    r = run(["sh", str(SITE_CHECK), expect, base + "download/"], 120)
    page = said(r.out)
    print(f"live page: exit {r.rc}: {page}")
    rc, verdict = daily_verdict(static, r.rc)
    if verdict == "verified" and r.rc == 0:
        line = f"Advertisement VERIFIED: the live download page names {expect}"
        line += f", and {detail}." if static == "ok" else f". The static record said nothing: {detail}."
    elif verdict == "verified":
        line = (f"Advertisement VERIFIED: {detail}. The edge refused the read of the live download page, so what "
                "it serves a visitor was not read.")
        print(f"::warning title=Live download page not read::The edge refused the read of the live download page "
              f"({page}). The release {expect} is verified from the static files of the live deploy: {detail}.")
    elif verdict == "not-verified":
        line = (f"NOT VERIFIED: whether the site advertises {expect} is not known. The edge refused the read of "
                f"the live download page ({page}), and the static files say nothing: {detail}.")
        print(f"::warning title=Advertisement not verified::{line}")
    elif verdict == "not-advertised":
        line = f"Advertisement FAILED: the site does not advertise {expect}. Static files: {detail}. Live page: {page}."
        print(f"::error title=Release not advertised::{line}")
    else:
        line = (f"Advertisement FAILED: the live download page gave no answer to judge "
                f"(scripts/verify-site-advertises.sh exit {r.rc}: {page}). Static files: {detail}.")
        print(f"::error title=Download page not readable::{line}")
    print(line)
    summary = env.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(line + "\n")
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
    v.add_argument("--artifact", default="")
    ad = sub.add_parser("advertised")
    ad.add_argument("--site", required=True)
    ad.add_argument("--config", required=True)
    d = sub.add_parser("daily")
    d.add_argument("--expect", required=True)
    d.add_argument("--url", default="https://sipnab.com/")
    try:
        args = p.parse_args(argv)
    except SystemExit:
        return 2
    run = runner or subprocess_runner
    if args.cmd == "daily":
        if not re.fullmatch(r"\d+\.\d+\.\d+", args.expect):
            print(f"pages-live: --expect is X.Y.Z, not {args.expect!r}", file=sys.stderr)
            return 2
        if not args.url.startswith("https://"):
            print(f"pages-live: --url is an https URL, not {args.url!r}", file=sys.stderr)
            return 2
        return daily(args.expect, args.url.rstrip("/") + "/", env, run, time.sleep, time.monotonic)
    try:
        stamp = make_stamp(env)
    except ValueError as e:
        print(f"pages-live: {e}", file=sys.stderr)
        return 2
    if args.cmd == "stamp":
        pathlib.Path(args.write).write_text(stamp + "\n", encoding="utf-8")
        print(f"deploy stamp: {stamp}")
        return 0
    if args.cmd == "advertised":
        return write_advertised(pathlib.Path(args.site), pathlib.Path(args.config), stamp, run)
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
                 sha=env["GITHUB_SHA"], artifact=args.artifact,
                 advertised_url=urllib.parse.urljoin(args.url, RECORD_FILE))
    return verify(cfg, env, run, urllib_get, time.sleep, time.monotonic)


if __name__ == "__main__":
    sys.exit(main())
