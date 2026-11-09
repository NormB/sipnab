#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""The checks after a release's assets exist, side by side (RELEASE-FAST D).

    post-release.py run X.Y.Z --host USER@HOST [--repo OWNER/NAME]
    post-release.py withdraw X.Y.Z [--repo OWNER/NAME]

`run` starts four checks at once, each on its own thread, and none of them
through heavy-run, because none of them builds anything:

- bpf:  copies scripts/verify-bpf-load.sh to a fresh /tmp directory on the
        OpenSIPS VM, runs it there under sudo for the version, and removes
        the directory.
- deb:  downloads the amd64 .deb and SHA256SUMS.txt of the release, checks
        the sha256, simulates the install on the VM (only sipnab may change),
        installs it, checks `sipnab --version`, and checks that every listed
        service kept its PID and restart count and is active.
- site: scripts/verify-site-advertises.sh, retried while the page is only
        STALE, inside a time budget.
- tap:  renders the Homebrew formula from the release's SHA256SUMS.txt and
        commits it to the tap with this machine's SSH signing key.

THE TAP. On 0.5.241 the release job committed the bump through the contents
API with a personal access token, on the assumption that GitHub signs such a
commit. GitHub answered verified: false, reason: unsigned (83b56c480), so the
job refused it and the run concluded failure (HOMEBREW-TAP-API-COMMIT-UNSIGNED).
The commit is now made here and checked at three points: `git verify-commit`
before any push; GitHub's verification of the commit on a scratch branch
before main moves; and GitHub's verification of main afterward. The verified
value must be the JSON value true. main only ever fast-forwards, nothing is
forced, and a tap already holding a newer release is left alone.

THE SAFEGUARD. Since RELEASE-FAST C the site advertises a release as soon as
its assets exist, before the BPF verify; phase two used to hold the site until
it said ATTACHED. So a BPF check that does not end with the verifier exiting 0
and printing an `ATTACHED:` line, for any reason, an unreachable VM and a
crash included, withdraws the release at once, without waiting for the other
checks: `gh release edit vX.Y.Z --prerelease`, a read-back of the flag, and
only then `gh workflow run pages.yml --ref main`. advertise-release.py does
not advertise a prerelease, so that deploy puts the site back on the previous
release. A deploy dispatched before the flag reads back would re-advertise
the release, so a failed flag dispatches nothing and says what to run.

Exit status of `run`:
  0  all four checks passed
  1  the deb, site or tap check failed; the release stays advertised
  2  usage
  3  the BPF check failed and the release was withdrawn
  4  the BPF check failed and the withdrawal did NOT complete: run the
     commands it printed now
`withdraw` exits 0 when the release is flagged and the deploy dispatched,
4 otherwise.

Tested by scripts/tests/test_post_release.py, through an injected runner.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import dataclasses
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import time

SCRIPTS = pathlib.Path(__file__).resolve().parent
VERIFIER = SCRIPTS / "verify-bpf-load.sh"
SITE_CHECK = SCRIPTS / "verify-site-advertises.sh"
UPDATE_FORMULA = SCRIPTS.parent / "packaging" / "homebrew" / "update-formula.sh"

Result = collections.namedtuple("Result", "rc out")

SSH_OPTS = ("-o", "BatchMode=yes", "-o", "ConnectTimeout=15")
REMOTE_DIR = re.compile(r"^/tmp/sipnab-post\.[A-Za-z0-9]+$")
WITHDRAW_ATTEMPTS = 3
WITHDRAW_DELAY = 10.0
BPF_TIMEOUT = 240
INSTALL_TIMEOUT = 600
SITE_STALE = 1


@dataclasses.dataclass
class Config:
    version: str
    host: str
    repo: str
    units: tuple
    workdir: pathlib.Path
    site_budget: float = 600.0
    site_interval: float = 30.0
    tap_repo: str = "NormB/homebrew-tap"


@dataclasses.dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    # bpf only: None when nothing was withdrawn, True when the release is
    # flagged and the deploy dispatched, False when that did not complete.
    withdrawn: bool | None = None


def subprocess_runner(argv, timeout):
    """Run ARGV; stdout and stderr together. A timeout is exit 124."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return Result(124, f"timed out after {timeout} s: {' '.join(argv)}")
    return Result(p.returncode, p.stdout + p.stderr)


# ---------------------------------------------------------------------------
# Pure decisions
# ---------------------------------------------------------------------------


def bpf_attached(rc: int, out: str) -> bool:
    """The verifier exited 0 AND printed its ATTACHED verdict line."""
    return rc == 0 and any(line.startswith("ATTACHED: ") for line in out.splitlines())


APT_INST = re.compile(r"^Inst (\S+)(?: \[([^\]]*)\])? \((\S+) ")
APT_REMOVE = re.compile(r"^(?:Remv|Purg) (\S+)")


def apt_plan_ok(out: str, version: str) -> tuple[bool, str]:
    """An `apt-get -s install` plan that installs sipnab VERSION and nothing else."""
    installs, removals = [], []
    for line in out.splitlines():
        m = APT_INST.match(line)
        if m:
            installs.append((m.group(1), m.group(2), m.group(3)))
            continue
        m = APT_REMOVE.match(line)
        if m:
            removals.append(m.group(1))
    if removals:
        return False, f"the simulated install would remove {', '.join(removals)}"
    others = [p for p, _, _ in installs if p != "sipnab"]
    if others:
        return False, f"the simulated install would also install {', '.join(others)}"
    if len(installs) != 1:
        return False, "the simulated install does not install sipnab"
    _, old, new = installs[0]
    if new != version:
        return False, f"the simulated install would install sipnab {new}, not {version}"
    return True, f"sipnab {old or 'none'} -> {new}, nothing else"


def parse_units(out: str) -> dict:
    """`systemctl show -p Id,MainPID,NRestarts,ActiveState U...` by unit Id."""
    units = {}
    for block in re.split(r"\n\s*\n", out.strip()):
        kv = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if "Id" in kv:
            unit = kv.pop("Id")
            units[unit] = {k: kv.get(k, "") for k in ("MainPID", "NRestarts", "ActiveState")}
    return units


def units_active(units: dict, wanted) -> tuple[bool, str]:
    names = [u if u.endswith(".service") else f"{u}.service" for u in wanted]
    bad = [n for n in names if units.get(n, {}).get("ActiveState") != "active"]
    if bad:
        return False, f"not active before the upgrade: {', '.join(bad)}"
    return True, ""


def services_unchanged(before: dict, after: dict) -> tuple[bool, str]:
    """Every unit kept its PID and restart count, and is active."""
    changed = []
    for unit, b in before.items():
        a = after.get(unit)
        if a is None:
            changed.append(f"{unit} is missing after the upgrade")
        elif a["MainPID"] != b["MainPID"] or a["NRestarts"] != b["NRestarts"]:
            changed.append(f"{unit} restarted (PID {b['MainPID']} -> {a['MainPID']}, "
                           f"NRestarts {b['NRestarts']} -> {a['NRestarts']})")
        elif a["ActiveState"] != "active":
            changed.append(f"{unit} is {a['ActiveState']}")
    if changed:
        return False, "; ".join(changed)
    return True, ", ".join(f"{u} PID {b['MainPID']}" for u, b in before.items()) + " unchanged"


def sha_from_sums(text: str, name: str) -> str | None:
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == name:
            return parts[0]
    return None


# ---------------------------------------------------------------------------
# Remote helpers
# ---------------------------------------------------------------------------


def ssh(cfg, run, command, timeout=60):
    return run(["ssh", *SSH_OPTS, cfg.host, command], timeout)


def remote_dir(cfg, run) -> str:
    """A fresh /tmp directory on the host, or raise naming why not."""
    r = ssh(cfg, run, "mktemp -d /tmp/sipnab-post.XXXXXX", 30)
    if r.rc != 0:
        raise RuntimeError(f"no directory on {cfg.host}: {r.out.strip()}")
    d = r.out.strip()
    if not REMOTE_DIR.match(d):
        raise RuntimeError(f"the directory {cfg.host} gave, {d!r}, is not a fresh /tmp/sipnab-post.* one")
    return d


def remove_remote(cfg, run, d):
    if REMOTE_DIR.match(d):
        ssh(cfg, run, f"rm -rf {d}", 30)


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------


def withdraw(cfg, run, sleep=time.sleep) -> tuple[bool, str]:
    """Flag vX.Y.Z as a prerelease, read the flag back, then redeploy the site."""
    tag = f"v{cfg.version}"
    edit = ["gh", "release", "edit", tag, "--prerelease", "--repo", cfg.repo]
    deploy = ["gh", "workflow", "run", "pages.yml", "--ref", "main", "--repo", cfg.repo]
    last = ""
    for i in range(WITHDRAW_ATTEMPTS):
        r = run(edit, 60)
        if r.rc == 0:
            break
        last = r.out.strip()
        if i + 1 < WITHDRAW_ATTEMPTS:
            sleep(WITHDRAW_DELAY * (i + 1))
    flag = run(["gh", "release", "view", tag, "--repo", cfg.repo, "--json", "isPrerelease",
                "--jq", ".isPrerelease"], 60)
    if flag.rc != 0 or flag.out.strip() != "true":
        return False, (f"WITHDRAWAL FAILED: {tag} is not flagged as a prerelease ({last or flag.out.strip()}), "
                       f"so the site still advertises it. Run now: {' '.join(edit)}; then {' '.join(deploy)}")
    d = run(deploy, 60)
    if d.rc != 0:
        return False, (f"WITHDRAWAL INCOMPLETE: {tag} is flagged as a prerelease but the Pages deploy did not "
                       f"start ({d.out.strip()}). Run now: {' '.join(deploy)}")
    return True, f"withdrawn: {tag} is flagged as a prerelease and pages.yml was dispatched on main"


def _verify_bpf(cfg, run) -> tuple[bool, str]:
    d = remote_dir(cfg, run)
    try:
        cp = run(["scp", *SSH_OPTS, str(VERIFIER), f"{cfg.host}:{d}/"], 60)
        if cp.rc != 0:
            return False, f"copying the verifier failed: {cp.out.strip()}"
        r = ssh(cfg, run, f"sudo bash {d}/verify-bpf-load.sh {cfg.version}", BPF_TIMEOUT)
    finally:
        remove_remote(cfg, run, d)
    verdict = [line for line in r.out.splitlines() if line.startswith(("ATTACHED: ", "REFUSED: ", "NO VERDICT: "))]
    if bpf_attached(r.rc, r.out):
        return True, verdict[0] + "\n" + r.out
    tail = verdict[-1] if verdict else "\n".join(r.out.splitlines()[-5:])
    return False, f"the verifier exited {r.rc} without ATTACHED: {tail}"


def check_bpf(cfg, run, sleep=time.sleep) -> CheckResult:
    try:
        attached, detail = _verify_bpf(cfg, run)
    except Exception as e:  # noqa: BLE001 - any failure is "not ATTACHED"
        attached, detail = False, f"the BPF check failed: {e}"
    if attached:
        return CheckResult("bpf", True, detail)
    ok, wd = withdraw(cfg, run, sleep)
    return CheckResult("bpf", False, f"{detail}\n{wd}", withdrawn=ok)


def _units(cfg, run):
    r = ssh(cfg, run, "systemctl show -p Id,MainPID,NRestarts,ActiveState " + " ".join(cfg.units))
    if r.rc != 0:
        raise RuntimeError(f"systemctl show failed: {r.out.strip()}")
    return parse_units(r.out)


def check_deb(cfg, run) -> CheckResult:
    tag = f"v{cfg.version}"
    deb = f"sipnab_{cfg.version}_amd64.deb"
    local = cfg.workdir
    try:
        local.mkdir(parents=True, exist_ok=True)
        r = run(["gh", "release", "download", tag, "--repo", cfg.repo, "--pattern", deb,
                 "--pattern", "SHA256SUMS.txt", "--dir", str(local), "--clobber"], 300)
        if r.rc != 0:
            return CheckResult("deb", False, f"downloading {deb} failed: {r.out.strip()}")
        want = sha_from_sums((local / "SHA256SUMS.txt").read_text(encoding="utf-8"), deb)
        got = hashlib.sha256((local / deb).read_bytes()).hexdigest()
        if want != got:
            return CheckResult("deb", False, f"{deb} has sha256 {got}; SHA256SUMS.txt lists {want}")
        d = remote_dir(cfg, run)
        try:
            before = _units(cfg, run)
            ok, why = units_active(before, cfg.units)
            if not ok:
                return CheckResult("deb", False, why)
            cp = run(["scp", *SSH_OPTS, str(local / deb), f"{cfg.host}:{d}/"], 120)
            if cp.rc != 0:
                return CheckResult("deb", False, f"copying {deb} failed: {cp.out.strip()}")
            sim = ssh(cfg, run, f"apt-get -s install {d}/{deb}", 120)
            ok, plan = apt_plan_ok(sim.out, cfg.version)
            if sim.rc != 0 or not ok:
                return CheckResult("deb", False, f"not installed: {plan}")
            inst = ssh(cfg, run, f"sudo apt-get install -y {d}/{deb}", INSTALL_TIMEOUT)
            if inst.rc != 0:
                return CheckResult("deb", False, f"the install failed: {inst.out.strip()}")
            ver = ssh(cfg, run, "sipnab --version")
            if ver.rc != 0 or not ver.out.startswith(f"sipnab {cfg.version} "):
                return CheckResult("deb", False, f"sipnab --version says {ver.out.strip()!r}, not {cfg.version}")
            ok, why = services_unchanged(before, _units(cfg, run))
            if not ok:
                return CheckResult("deb", False, why)
            return CheckResult("deb", True, f"{plan}; {ver.out.splitlines()[0]}; {why}")
        finally:
            remove_remote(cfg, run, d)
    finally:
        shutil.rmtree(local, ignore_errors=True)


def check_site(cfg, run, sleep=time.sleep, clock=time.monotonic) -> CheckResult:
    start = clock()
    while True:
        r = run(["sh", str(SITE_CHECK), cfg.version], 120)
        if r.rc == 0:
            return CheckResult("site", True, r.out.strip())
        if r.rc != SITE_STALE or clock() - start + cfg.site_interval > cfg.site_budget:
            return CheckResult("site", False, f"verify-site-advertises.sh exited {r.rc}: {r.out.strip()}")
        sleep(cfg.site_interval)


def tap_dir(cfg) -> pathlib.Path:
    """The tap check's scratch directory, beside the deb check's own."""
    return cfg.workdir.with_name(cfg.workdir.name + "-tap")


def github_commit(cfg, run, ref) -> tuple[str | None, str]:
    """(sha, "") when GitHub reports REF verified, else (sha or None, why not)."""
    r = run(["gh", "api", f"repos/{cfg.tap_repo}/commits/{ref}", "--jq",
             "{sha: .sha, verification: .commit.verification}"], 60)
    if r.rc != 0:
        return None, f"reading {ref} on GitHub failed: {r.out.strip()}"
    try:
        answer = json.loads(r.out)
    except ValueError:
        return None, f"GitHub's answer for {ref} is not JSON: {r.out.strip()[:200]}"
    v = answer.get("verification") if isinstance(answer, dict) else None
    sha = answer.get("sha") if isinstance(answer, dict) else None
    if not isinstance(v, dict) or v.get("verified") is not True:
        reason = v.get("reason") if isinstance(v, dict) else "no verification in the answer"
        return sha, f"GitHub reports {ref} as not verified: {reason}"
    return sha, ""


def formula_version(text: str) -> tuple | None:
    m = re.search(r'(?m)^\s*version "(\d+)\.(\d+)\.(\d+)"$', text)
    return tuple(int(g) for g in m.groups()) if m else None


def _tap_fail(why: str) -> CheckResult:
    return CheckResult("tap", False, why)


def _push_tap(cfg, run, tap, branch) -> CheckResult:
    git = ["git", "-C", str(tap)]
    head = run([*git, "rev-parse", "HEAD"], 30)
    if head.rc != 0:
        return _tap_fail(f"no HEAD in the tap clone: {head.out.strip()}")
    sha = head.out.strip()
    if run([*git, "ls-remote", "--heads", "origin", branch], 60).out.strip():
        run([*git, "push", "origin", "--delete", branch], 60)
    pushed = run([*git, "push", "origin", f"HEAD:refs/heads/{branch}"], 120)
    if pushed.rc != 0:
        return _tap_fail(f"pushing {branch} failed: {pushed.out.strip()}")
    note = ""
    try:
        got, why = github_commit(cfg, run, sha)
        if why:
            return _tap_fail(f"not moving the tap's main: {why}")
        if got != sha:
            return _tap_fail(f"not moving the tap's main: GitHub answered for {got}, not {sha}")
        moved = run([*git, "push", "origin", "HEAD:refs/heads/main"], 120)
        if moved.rc != 0:
            return _tap_fail(f"the tap's main did not fast-forward: {moved.out.strip()}")
        got, why = github_commit(cfg, run, "main")
        if why:
            return _tap_fail(f"the tap's main moved to {sha}, and {why}")
        if got != sha:
            return _tap_fail(f"the tap's main is {got}, not {sha}")
    finally:
        gone = run([*git, "push", "origin", "--delete", branch], 60)
        if gone.rc != 0:
            note = f"; delete the branch {branch} by hand: {gone.out.strip()}"
    return CheckResult("tap", True, f"{cfg.tap_repo} main is {sha}, verified on GitHub{note}")


def check_tap(cfg, run) -> CheckResult:
    work = tap_dir(cfg)
    tag = f"v{cfg.version}"
    tap = work / "tap"
    sums = work / "SHA256SUMS.txt"
    rendered = work / "sipnab.rb"
    try:
        work.mkdir(parents=True, exist_ok=True)
        r = run(["gh", "release", "download", tag, "--repo", cfg.repo, "--pattern", "SHA256SUMS.txt",
                 "--dir", str(work), "--clobber"], 120)
        if r.rc != 0:
            return _tap_fail(f"downloading SHA256SUMS.txt failed: {r.out.strip()}")
        r = run(["bash", "-c", 'bash "$1" "$2" "$3" > "$4"', "render", str(UPDATE_FORMULA),
                 cfg.version, str(sums), str(rendered)], 60)
        if r.rc != 0:
            return _tap_fail(f"rendering the formula failed: {r.out.strip()}")
        r = run(["git", "clone", "--quiet", f"https://github.com/{cfg.tap_repo}.git", str(tap)], 120)
        if r.rc != 0:
            return _tap_fail(f"cloning the tap failed: {r.out.strip()}")
        formula = tap / "Formula" / "sipnab.rb"
        new = rendered.read_text(encoding="utf-8")
        old = formula.read_text(encoding="utf-8")
        if old == new:
            git_head = run(["git", "-C", str(tap), "rev-parse", "HEAD"], 30).out.strip()
            got, why = github_commit(cfg, run, "main")
            if why:
                return _tap_fail(f"the tap already has {cfg.version}, and {why}")
            if got != git_head:
                return _tap_fail(f"the tap's main is {got}, not the cloned {git_head}")
            return CheckResult("tap", True, f"{cfg.tap_repo} main already has {cfg.version}, verified on GitHub: {got}")
        have = formula_version(old)
        if have is None:
            return _tap_fail("the tap's formula names no version, so its release cannot be compared")
        if have > tuple(int(p) for p in cfg.version.split(".")):
            return _tap_fail(f"the tap is on {'.'.join(map(str, have))}, newer than {cfg.version}: left alone")
        formula.write_text(new, encoding="utf-8")
        git = ["git", "-C", str(tap)]
        r = run([*git, "add", "Formula/sipnab.rb"], 30)
        if r.rc != 0:
            return _tap_fail(f"git add failed: {r.out.strip()}")
        r = run([*git, "commit", "-S", "--quiet", "-m", f"sipnab: bump to {cfg.version}"], 60)
        if r.rc != 0:
            return _tap_fail(f"the signed commit failed: {r.out.strip()}")
        r = run([*git, "verify-commit", "HEAD"], 30)
        if r.rc != 0:
            return _tap_fail(f"the tap commit does not verify locally, so it was not pushed: {r.out.strip()}")
        return _push_tap(cfg, run, tap, f"sipnab-bump-{cfg.version}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_all(cfg, run, sleep=time.sleep) -> tuple[list, int]:
    """The four checks at once. The BPF check withdraws on its own thread."""
    checks = {
        "bpf": lambda: check_bpf(cfg, run, sleep),
        "deb": lambda: check_deb(cfg, run),
        "site": lambda: check_site(cfg, run, sleep),
        "tap": lambda: check_tap(cfg, run),
    }

    def guarded(name, fn):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - one check's crash fails that check only
            return CheckResult(name, False, f"the {name} check crashed: {e}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(checks), thread_name_prefix="post-release") as ex:
        futures = {name: ex.submit(guarded, name, fn) for name, fn in checks.items()}
        results = [futures[name].result() for name in checks]
    bpf = results[0]
    if not bpf.ok:
        return results, 3 if bpf.withdrawn else 4
    return results, 0 if all(r.ok for r in results) else 1


def git_dir() -> pathlib.Path:
    out = subprocess.run(["git", "rev-parse", "--absolute-git-dir"], capture_output=True, text=True,
                         check=True, cwd=SCRIPTS).stdout.strip()
    return pathlib.Path(out)


def main(argv=None, runner=None) -> int:
    p = argparse.ArgumentParser(prog="post-release.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("run", "withdraw"):
        s = sub.add_parser(name)
        s.add_argument("version")
        s.add_argument("--repo", default="NormB/sipnab")
        if name == "run":
            # No default: the VM and its account are the operator's, and this
            # repository is public.
            s.add_argument("--host", required=True)
            s.add_argument("--units", default="opensips,vcon-server,tfps")
    try:
        args = p.parse_args(argv)
    except SystemExit:
        return 2
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        print(f"post-release: the version is X.Y.Z, not {args.version!r}", file=sys.stderr)
        return 2
    run = runner or subprocess_runner
    workdir = git_dir() / f"post-release-{args.version}" if args.cmd == "run" else pathlib.Path()
    cfg = Config(version=args.version, host=getattr(args, "host", ""), repo=args.repo,
                 units=tuple(getattr(args, "units", "").split(",")), workdir=workdir)
    if args.cmd == "withdraw":
        ok, detail = withdraw(cfg, run)
        print(detail)
        return 0 if ok else 4
    results, code = run_all(cfg, run)
    for r in results:
        print(f"{r.name}: {'OK' if r.ok else 'FAILED'}: {r.detail.splitlines()[0] if r.detail else ''}")
        for line in r.detail.splitlines()[1:]:
            if line.startswith(("WITHDRAW", "withdrawn")):
                print(f"{r.name}: {line}")
    return code


if __name__ == "__main__":
    sys.exit(main())
