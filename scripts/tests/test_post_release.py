# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/post-release.py: the checks after a release's assets exist.

RELEASE-FAST D. Until 0.5.240 the release agent ran three checks one after
another once the release workflow finished: the eBPF load verification on the
OpenSIPS VM, the .deb upgrade on the same VM, and the live-site
check. On 0.5.239 the .deb steps also queued 10 minutes for the heavy-run main
slot, though none of them builds anything. post-release.py runs the three side
by side and never through heavy-run.

RELEASE-FAST C made the site advertise a release as soon as its assets exist,
BEFORE the BPF verify; phase two used to hold the site until the verify said
ATTACHED. The guarantee is kept here (coordinator, 2026-11-09 ~09:15Z): a BPF
verify that does not print ATTACHED marks the GitHub release as a prerelease at
once, which advertise-release.py excludes, and dispatches a Pages deploy, so
the site goes back to the previous release.

These tests drive every command through a fake runner. No host, no GitHub.
"""

import hashlib
import json
import pathlib
import threading
import time

import pytest
from conftest import load

pr = load("post-release")

VERSION = "0.5.241"
DEB = f"sipnab_{VERSION}_amd64.deb"
DEB_BYTES = b"a debian package\n"
DEB_SHA = hashlib.sha256(DEB_BYTES).hexdigest()

ATTACH_OUT = (
    "==> downloading sipnab-0.5.241-x86_64-unknown-linux-gnu.tar.gz\n"
    "==> verdict\n"
    "ATTACHED: BPF capture attached to 2 libraries plus tcp_sendmsg\n"
)
REFUSE_OUT = "==> verdict\nREFUSED: verifier rejected program: invalid mem access\n"
NOVERDICT_OUT = "==> verdict\nNO VERDICT: the run said neither that it attached nor why it could not\n"

UNITS_BEFORE = (
    "Id=opensips.service\nMainPID=826\nNRestarts=0\nActiveState=active\n\n"
    "Id=vcon-server.service\nMainPID=351114\nNRestarts=0\nActiveState=active\n\n"
    "Id=tfps.service\nMainPID=745\nNRestarts=0\nActiveState=active\n"
)
APT_SIM_OK = (
    "Reading package lists...\n"
    "The following packages will be upgraded:\n  sipnab\n"
    f"Inst sipnab [0.5.240] (0.5.241 /tmp/x/{DEB} [amd64])\n"
    f"Conf sipnab (0.5.241 /tmp/x/{DEB} [amd64])\n"
)
VERSION_OUT = "sipnab 0.5.241 (v0.5.241 0123abcd) features: native,tui,bpf\n"


class Fake:
    """A runner answering each command from rules: (predicate, result).

    A result is (rc, out) or a callable(argv) -> (rc, out). Every call is
    recorded with the thread that made it and the time it started.
    """

    def __init__(self, cfg=None):
        self.rules = []
        self.calls = []
        self.lock = threading.Lock()
        self.cfg = cfg

    def on(self, pred, result):
        self.rules.insert(0, (pred, result))
        return self

    def __call__(self, argv, timeout):
        with self.lock:
            self.calls.append({"argv": list(argv), "thread": threading.current_thread().name,
                               "t": time.monotonic(), "timeout": timeout})
        for pred, result in self.rules:
            if pred(argv):
                r = result(argv) if callable(result) else result
                return pr.Result(*r)
        raise AssertionError(f"no rule for {argv}")

    def argvs(self):
        return [c["argv"] for c in self.calls]

    def joined(self):
        return [" ".join(a) for a in self.argvs()]


def has(*words):
    return lambda argv: all(w in " ".join(argv) for w in words)


@pytest.fixture
def cfg(tmp_path):
    return pr.Config(version=VERSION, host="releaser@vm.example.invalid", repo="NormB/sipnab",
                     units=("opensips", "vcon-server", "tfps"), workdir=tmp_path / "work",
                     site_budget=0.0, site_interval=0.0)


def write_downloads(cfg, deb=DEB_BYTES, sums_sha=DEB_SHA):
    def act(argv):
        d = pathlib.Path(argv[argv.index("--dir") + 1])
        d.mkdir(parents=True, exist_ok=True)
        (d / DEB).write_bytes(deb)
        (d / "SHA256SUMS.txt").write_text(f"{sums_sha}  {DEB}\nffff  other.tar.gz\n")
        return (0, "")
    return act


def healthy(cfg, *, bpf=(0, ATTACH_OUT), site=(0, "OK: the page names 0.5.241"),
            after=UNITS_BEFORE, apt=(0, APT_SIM_OK), version_out=(0, VERSION_OUT)):
    f = Fake(cfg)
    f.on(lambda a: True, (0, ""))
    f.on(has("ssh", "mktemp"), (0, "/tmp/sipnab-post.abc\n"))
    f.on(has("gh", "release", "download"), write_downloads(cfg))
    f.on(has("sudo", "verify-bpf-load.sh"), bpf)
    f.on(has("verify-site-advertises.sh"), site)
    state = {"installed": False}

    def units(argv):
        return (0, after if state["installed"] else UNITS_BEFORE)

    def install(argv):
        state["installed"] = True
        return (0, "Setting up sipnab (0.5.241) ...\n")

    f.on(has("systemctl", "show"), units)
    f.on(has("apt-get", "-s"), apt)
    f.on(has("sudo", "apt-get", "install", "-y"), install)
    f.on(has("sipnab", "--version"), version_out)
    f.on(has("gh", "release", "view", "isPrerelease"), (0, "true\n"))
    tap_world(f, cfg)
    return f


# ---------------------------------------------------------------------------
# The Homebrew tap: a world of commands
# ---------------------------------------------------------------------------

TAP_SHA = "1bd0c0dd348f7d13e616b88e3c38337c48081eed"
# What GitHub answered for the commit the contents API made with the PAT on
# 0.5.241 (83b56c480, read back on 2026-11-09), trimmed to the fields read here.
UNSIGNED_0_5_241 = {"verified": False, "reason": "unsigned", "verified_at": None}
# What it answered for the hand-signed fast-forward 1bd0c0dd3.
VERIFIED_1BD0C0DD3 = {"verified": True, "reason": "valid"}
OLD_FORMULA = 'class Sipnab < Formula\n  version "0.5.240"\nend\n'
NEW_FORMULA = 'class Sipnab < Formula\n  version "0.5.241"\nend\n'


def commit_json(sha=TAP_SHA, verification=None):
    return json.dumps({"sha": sha, "verification": VERIFIED_1BD0C0DD3 if verification is None else verification})


def tap_world(f, cfg, existing=OLD_FORMULA, rendered=NEW_FORMULA, api=None):
    def clone(argv):
        tap = pathlib.Path(argv[-1])
        (tap / "Formula").mkdir(parents=True)
        (tap / "Formula/sipnab.rb").write_text(existing)
        return (0, "")

    def render(argv):
        pathlib.Path(argv[-1]).write_text(rendered)
        return (0, "")

    f.on(has("git", "clone"), clone)
    f.on(has("update-formula.sh"), render)
    f.on(has("rev-parse", "HEAD"), (0, TAP_SHA + "\n"))
    f.on(has("verify-commit"), (0, "Good \"git\" signature\n"))
    f.on(has("ls-remote"), (0, ""))
    f.on(has("gh", "api", "/commits/"), (0, commit_json()) if api is None else api)


def tap_calls(f, *words):
    return [a for a in f.argvs() if all(w in " ".join(a) for w in words)]


# ---------------------------------------------------------------------------
# The BPF verdict
# ---------------------------------------------------------------------------


def test_success_an_attached_verdict_with_exit_0_is_attached():
    assert pr.bpf_attached(0, ATTACH_OUT)


def test_failure_a_refusal_is_not_attached():
    assert not pr.bpf_attached(1, REFUSE_OUT)


def test_failure_no_verdict_is_not_attached():
    assert not pr.bpf_attached(2, NOVERDICT_OUT)


def test_failure_exit_0_without_an_attached_line_is_not_attached():
    # A verifier that exits 0 but never says ATTACHED proves nothing.
    assert not pr.bpf_attached(0, "==> verdict\n")


def test_failure_an_attached_line_with_a_nonzero_exit_is_not_attached():
    assert not pr.bpf_attached(1, ATTACH_OUT)


def test_edge_attached_must_start_its_line():
    # A refusal message quoting the word is not a verdict.
    assert not pr.bpf_attached(0, "REFUSED: expected ATTACHED: got nothing\n")


def test_edge_a_timeout_is_not_attached():
    assert not pr.bpf_attached(124, "")


# ---------------------------------------------------------------------------
# The BPF check and the withdrawal
# ---------------------------------------------------------------------------


def test_success_an_attached_release_is_not_withdrawn(cfg):
    f = healthy(cfg)
    r = pr.check_bpf(cfg, f)
    assert r.ok
    assert not any("--prerelease" in j for j in f.joined())
    assert not any("workflow run" in j for j in f.joined())


def test_success_the_verifier_runs_under_sudo_on_the_vm(cfg):
    f = healthy(cfg)
    pr.check_bpf(cfg, f)
    run = [a for a in f.argvs() if "verify-bpf-load.sh" in " ".join(a) and "sudo" in " ".join(a)]
    assert run and run[0][0] == "ssh" and "releaser@vm.example.invalid" in run[0]
    assert VERSION in run[0][-1]


def test_success_the_verifier_is_copied_to_a_fresh_remote_directory(cfg):
    f = healthy(cfg)
    pr.check_bpf(cfg, f)
    scp = [a for a in f.argvs() if a[0] == "scp"]
    assert scp and scp[0][-1] == "releaser@vm.example.invalid:/tmp/sipnab-post.abc/"
    assert scp[0][-2].endswith("scripts/verify-bpf-load.sh")


def test_success_the_attached_line_is_kept_for_the_ledger(cfg):
    r = pr.check_bpf(cfg, healthy(cfg))
    assert "ATTACHED: BPF capture attached to 2 libraries plus tcp_sendmsg" in r.detail


def test_failure_a_refusal_marks_the_release_a_prerelease(cfg):
    f = healthy(cfg, bpf=(1, REFUSE_OUT))
    r = pr.check_bpf(cfg, f)
    assert not r.ok
    assert ["gh", "release", "edit", f"v{VERSION}", "--prerelease", "--repo", "NormB/sipnab"] in f.argvs()
    assert r.withdrawn is True


def test_failure_a_refusal_dispatches_a_pages_deploy_on_main(cfg):
    f = healthy(cfg, bpf=(1, REFUSE_OUT))
    pr.check_bpf(cfg, f)
    assert ["gh", "workflow", "run", "pages.yml", "--ref", "main", "--repo", "NormB/sipnab"] in f.argvs()


def test_failure_the_deploy_comes_after_the_prerelease_flag(cfg):
    # A deploy that ran first would still find the release eligible.
    f = healthy(cfg, bpf=(1, REFUSE_OUT))
    pr.check_bpf(cfg, f)
    j = f.joined()
    edit = next(i for i, c in enumerate(j) if "--prerelease" in c)
    deploy = next(i for i, c in enumerate(j) if "workflow run pages.yml" in c)
    assert edit < deploy


def test_failure_no_verdict_withdraws_the_release(cfg):
    f = healthy(cfg, bpf=(2, NOVERDICT_OUT))
    r = pr.check_bpf(cfg, f)
    assert r.withdrawn is True


def test_failure_an_unreachable_vm_withdraws_the_release(cfg):
    # Fail closed: no ATTACHED is no ATTACHED, whatever the reason.
    f = healthy(cfg)
    f.on(has("ssh", "mktemp"), (255, "ssh: connect to host 192.0.2.40 port 22: No route to host\n"))
    r = pr.check_bpf(cfg, f)
    assert r.withdrawn is True
    assert "No route to host" in r.detail


def test_failure_a_failed_copy_of_the_verifier_withdraws_the_release(cfg):
    f = healthy(cfg)
    f.on(lambda a: a[0] == "scp", (1, "scp: write failed\n"))
    r = pr.check_bpf(cfg, f)
    assert r.withdrawn is True
    assert not any("sudo" in j and "verify-bpf-load.sh" in j for j in f.joined())


def test_failure_a_prerelease_flag_that_does_not_read_back_is_a_failed_withdrawal(cfg):
    f = healthy(cfg, bpf=(1, REFUSE_OUT))
    f.on(has("gh", "release", "view", "isPrerelease"), (0, "false\n"))
    r = pr.check_bpf(cfg, f)
    assert r.withdrawn is False
    assert "gh release edit v0.5.241 --prerelease" in r.detail


def test_failure_a_failed_withdrawal_still_dispatches_no_deploy(cfg):
    # A deploy with the flag unset would re-advertise the release.
    f = healthy(cfg, bpf=(1, REFUSE_OUT))
    f.on(has("gh", "release", "edit"), (1, "HTTP 502\n"))
    f.on(has("gh", "release", "view", "isPrerelease"), (0, "false\n"))
    r = pr.check_bpf(cfg, f, sleep=lambda s: None)
    assert r.withdrawn is False
    assert not any("workflow run" in j for j in f.joined())


def test_failure_a_failed_deploy_dispatch_is_reported_with_the_command(cfg):
    f = healthy(cfg, bpf=(1, REFUSE_OUT))
    f.on(has("gh", "workflow", "run"), (1, "HTTP 500\n"))
    r = pr.check_bpf(cfg, f)
    assert r.withdrawn is False
    assert "gh workflow run pages.yml --ref main --repo NormB/sipnab" in r.detail


def test_edge_the_prerelease_edit_is_retried_before_giving_up(cfg):
    f = healthy(cfg, bpf=(1, REFUSE_OUT))
    tries = {"n": 0}

    def edit(argv):
        tries["n"] += 1
        return (1, "HTTP 502\n") if tries["n"] < 3 else (0, "")

    f.on(has("gh", "release", "edit"), edit)
    r = pr.check_bpf(cfg, f, sleep=lambda s: None)
    assert tries["n"] == 3
    assert r.withdrawn is True


def test_edge_the_prerelease_edit_gives_up_after_its_attempts(cfg):
    f = healthy(cfg, bpf=(1, REFUSE_OUT))
    f.on(has("gh", "release", "edit"), (1, "HTTP 502\n"))
    f.on(has("gh", "release", "view", "isPrerelease"), (0, "false\n"))
    pr.check_bpf(cfg, f, sleep=lambda s: None)
    assert sum("--prerelease" in j for j in f.joined()) == pr.WITHDRAW_ATTEMPTS


def test_edge_the_remote_directory_is_removed_after_a_refusal(cfg):
    f = healthy(cfg, bpf=(1, REFUSE_OUT))
    pr.check_bpf(cfg, f)
    assert any(a[0] == "ssh" and "rm -rf /tmp/sipnab-post.abc" in a[-1] for a in f.argvs())


def test_edge_the_remote_directory_is_removed_after_an_attach(cfg):
    f = healthy(cfg)
    pr.check_bpf(cfg, f)
    assert any(a[0] == "ssh" and "rm -rf /tmp/sipnab-post.abc" in a[-1] for a in f.argvs())


def test_edge_a_remote_directory_outside_tmp_is_never_removed(cfg):
    f = healthy(cfg)
    f.on(has("ssh", "mktemp"), (0, "/var/lib\n"))
    r = pr.check_bpf(cfg, f)
    assert not any("rm -rf" in j for j in f.joined())
    assert r.withdrawn is True


def test_edge_the_verifier_has_a_bounded_timeout(cfg):
    f = healthy(cfg)
    pr.check_bpf(cfg, f)
    c = next(c for c in f.calls if "sudo" in " ".join(c["argv"]) and "verify-bpf-load.sh" in " ".join(c["argv"]))
    assert 0 < c["timeout"] <= 300


# ---------------------------------------------------------------------------
# The .deb upgrade
# ---------------------------------------------------------------------------


def test_success_an_apt_plan_of_only_sipnab_to_the_version_is_accepted():
    ok, why = pr.apt_plan_ok(APT_SIM_OK, VERSION)
    assert ok, why


def test_failure_an_apt_plan_that_installs_another_package_is_refused():
    out = APT_SIM_OK + "Inst libfoo1 (1.2 Debian:13 [amd64])\n"
    ok, why = pr.apt_plan_ok(out, VERSION)
    assert not ok and "libfoo1" in why


def test_failure_an_apt_plan_that_removes_a_package_is_refused():
    out = APT_SIM_OK + "Remv opensips [3.6.2]\n"
    ok, why = pr.apt_plan_ok(out, VERSION)
    assert not ok and "opensips" in why


def test_failure_an_apt_plan_to_another_version_is_refused():
    ok, why = pr.apt_plan_ok(APT_SIM_OK.replace("(0.5.241 ", "(0.5.240 "), VERSION)
    assert not ok


def test_edge_an_apt_plan_with_no_install_is_refused():
    ok, why = pr.apt_plan_ok("Reading package lists...\n0 upgraded, 0 newly installed\n", VERSION)
    assert not ok


def test_success_units_with_the_same_pids_are_unchanged():
    b = pr.parse_units(UNITS_BEFORE)
    ok, why = pr.services_unchanged(b, b)
    assert ok, why
    assert b["opensips.service"] == {"MainPID": "826", "NRestarts": "0", "ActiveState": "active"}


def test_failure_a_restarted_unit_is_reported_by_name():
    after = UNITS_BEFORE.replace("MainPID=745", "MainPID=9999")
    ok, why = pr.services_unchanged(pr.parse_units(UNITS_BEFORE), pr.parse_units(after))
    assert not ok and "tfps.service" in why


def test_failure_an_inactive_unit_is_reported():
    after = UNITS_BEFORE.replace("MainPID=826\nNRestarts=0\nActiveState=active", "MainPID=826\nNRestarts=0\nActiveState=failed")
    ok, why = pr.services_unchanged(pr.parse_units(UNITS_BEFORE), pr.parse_units(after))
    assert not ok and "opensips.service" in why


def test_edge_a_unit_missing_after_the_upgrade_is_a_change():
    after = UNITS_BEFORE.split("\n\n")[0]
    ok, why = pr.services_unchanged(pr.parse_units(UNITS_BEFORE), pr.parse_units(after))
    assert not ok and "vcon-server.service" in why


def test_edge_a_unit_inactive_before_the_upgrade_is_refused_before_installing(cfg):
    before = UNITS_BEFORE.replace("ActiveState=active\n\nId=vcon", "ActiveState=inactive\n\nId=vcon")
    f = healthy(cfg)
    f.on(has("systemctl", "show"), (0, before))
    r = pr.check_deb(cfg, f)
    assert not r.ok
    assert not any("install -y" in j for j in f.joined())


def test_success_the_deb_is_upgraded_and_reports_the_version(cfg):
    f = healthy(cfg)
    r = pr.check_deb(cfg, f)
    assert r.ok, r.detail
    assert any("sudo apt-get install -y /tmp/sipnab-post.abc/" + DEB in j for j in f.joined())


def test_success_the_deb_is_checked_against_sha256sums_before_it_is_copied(cfg):
    f = healthy(cfg)
    pr.check_deb(cfg, f)
    j = f.joined()
    dl = next(i for i, c in enumerate(j) if "release download" in c)
    cp = next(i for i, c in enumerate(j) if c.startswith("scp"))
    assert dl < cp


def test_failure_a_deb_whose_sha256_differs_is_not_copied(cfg):
    f = healthy(cfg)
    f.on(has("gh", "release", "download"), write_downloads(cfg, deb=b"substituted"))
    r = pr.check_deb(cfg, f)
    assert not r.ok and "sha256" in r.detail
    assert not any(a[0] == "scp" for a in f.argvs())


def test_failure_a_deb_missing_from_sha256sums_is_refused(cfg):
    f = healthy(cfg)
    f.on(has("gh", "release", "download"), write_downloads(cfg, sums_sha="0" * 64))
    r = pr.check_deb(cfg, f)
    assert not r.ok
    assert not any(a[0] == "scp" for a in f.argvs())


def test_failure_a_bad_apt_plan_installs_nothing(cfg):
    f = healthy(cfg, apt=(0, APT_SIM_OK + "Remv opensips [3.6.2]\n"))
    r = pr.check_deb(cfg, f)
    assert not r.ok
    assert not any("install -y" in j for j in f.joined())


def test_failure_a_wrong_installed_version_fails_the_check(cfg):
    f = healthy(cfg, version_out=(0, "sipnab 0.5.240 (v0.5.240 aa3532a5)\n"))
    r = pr.check_deb(cfg, f)
    assert not r.ok and "0.5.240" in r.detail


def test_failure_a_service_restarted_by_the_upgrade_fails_the_check(cfg):
    f = healthy(cfg, after=UNITS_BEFORE.replace("NRestarts=0\nActiveState=active\n\nId=tfps", "NRestarts=1\nActiveState=active\n\nId=tfps"))
    r = pr.check_deb(cfg, f)
    assert not r.ok and "vcon-server.service" in r.detail


def test_edge_the_deb_check_never_withdraws_the_release(cfg):
    # The package is checked on one host; the BPF verdict alone withdraws.
    f = healthy(cfg, version_out=(1, "boom"))
    r = pr.check_deb(cfg, f)
    assert not r.ok
    assert not any("--prerelease" in j for j in f.joined())


def test_edge_the_copied_deb_and_downloads_are_removed(cfg):
    f = healthy(cfg)
    pr.check_deb(cfg, f)
    assert any(a[0] == "ssh" and "rm -rf /tmp/sipnab-post.abc" in a[-1] for a in f.argvs())
    assert not cfg.workdir.exists()


# ---------------------------------------------------------------------------
# The site check
# ---------------------------------------------------------------------------


def test_success_the_site_naming_the_version_passes(cfg):
    r = pr.check_site(cfg, healthy(cfg))
    assert r.ok


def test_failure_a_tls_failure_is_not_retried(cfg):
    # A budget that would allow retries: only STALE is worth waiting out.
    cfg.site_budget = 30.0
    cfg.site_interval = 10.0
    f = healthy(cfg, site=(3, "TLS: certificate has expired"))
    now = {"t": 0.0}
    r = pr.check_site(cfg, f, sleep=lambda s: now.update(t=now["t"] + s), clock=lambda: now["t"])
    assert not r.ok and "TLS" in r.detail
    assert sum("verify-site-advertises.sh" in j for j in f.joined()) == 1


def test_edge_a_stale_page_is_retried_within_the_budget(cfg):
    cfg.site_budget = 30.0
    cfg.site_interval = 10.0
    answers = iter([(1, "STALE: names 0.5.240"), (1, "STALE: names 0.5.240"), (0, "OK")])
    f = healthy(cfg)
    f.on(has("verify-site-advertises.sh"), lambda a: next(answers))
    now = {"t": 0.0}
    r = pr.check_site(cfg, f, sleep=lambda s: now.update(t=now["t"] + s), clock=lambda: now["t"])
    assert r.ok


def test_failure_a_stale_page_past_the_budget_fails(cfg):
    cfg.site_budget = 20.0
    cfg.site_interval = 10.0
    f = healthy(cfg, site=(1, "STALE: names 0.5.240"))
    now = {"t": 0.0}
    r = pr.check_site(cfg, f, sleep=lambda s: now.update(t=now["t"] + s), clock=lambda: now["t"])
    assert not r.ok and "STALE" in r.detail
    assert sum("verify-site-advertises.sh" in j for j in f.joined()) == 3


# ---------------------------------------------------------------------------
# Running the three together
# ---------------------------------------------------------------------------


def test_success_all_four_checks_passing_exits_0(cfg):
    results, code = pr.run_all(cfg, healthy(cfg))
    assert code == 0
    assert [r.name for r in results] == ["bpf", "deb", "site", "tap"]


def test_success_the_four_checks_run_at_the_same_time(cfg):
    # Each check blocks until all four have started. Run one after another,
    # the first would wait out the barrier's timeout and the test would fail.
    barrier = threading.Barrier(4, timeout=5)
    f = healthy(cfg)

    def gate(result):
        # Only the first command each check sends waits: the deb check later
        # sends an `ssh mktemp` of its own, after the barrier has opened.
        first = threading.Event()

        def act(argv):
            if not first.is_set():
                first.set()
                barrier.wait()
            return result(argv) if callable(result) else result
        return act

    f.on(has("ssh", "mktemp"), gate((0, "/tmp/sipnab-post.abc\n")))
    f.on(lambda a: "release download" in " ".join(a) and DEB in " ".join(a), gate(write_downloads(cfg)))
    f.on(lambda a: "release download" in " ".join(a) and DEB not in " ".join(a), gate(write_downloads(cfg)))
    f.on(has("verify-site-advertises.sh"), gate((0, "OK")))
    results, code = pr.run_all(cfg, f)
    assert code == 0, [r.detail for r in results]


def test_success_no_command_goes_through_heavy_run(cfg):
    f = healthy(cfg)
    pr.run_all(cfg, f)
    assert f.calls
    assert not any("heavy-run" in j for j in f.joined())


def test_failure_a_withdrawn_release_exits_3(cfg):
    _, code = pr.run_all(cfg, healthy(cfg, bpf=(1, REFUSE_OUT)))
    assert code == 3


def test_failure_a_failed_withdrawal_exits_4(cfg):
    f = healthy(cfg, bpf=(1, REFUSE_OUT))
    f.on(has("gh", "release", "view", "isPrerelease"), (0, "false\n"))
    _, code = pr.run_all(cfg, f, sleep=lambda s: None)
    assert code == 4


def test_failure_a_deb_failure_alone_exits_1(cfg):
    _, code = pr.run_all(cfg, healthy(cfg, version_out=(1, "boom")))
    assert code == 1


def test_edge_the_withdrawal_does_not_wait_for_the_other_checks(cfg):
    # The deb check blocks until the withdrawal has been dispatched; if the
    # withdrawal waited for every check, this would deadlock to the timeout.
    dispatched = threading.Event()
    f = healthy(cfg, bpf=(1, REFUSE_OUT))

    def deploy(argv):
        dispatched.set()
        return (0, "")

    def slow_download(argv):
        assert dispatched.wait(timeout=5), "the withdrawal waited for the deb check"
        return write_downloads(cfg)(argv)

    f.on(has("gh", "workflow", "run"), deploy)
    f.on(lambda a: "release download" in " ".join(a) and DEB in " ".join(a), slow_download)
    _, code = pr.run_all(cfg, f)
    assert code == 3


def test_edge_a_crash_inside_one_check_fails_that_check_and_not_the_others(cfg):
    f = healthy(cfg)

    def boom(argv):
        raise OSError("disk full")

    f.on(has("verify-site-advertises.sh"), boom)
    results, code = pr.run_all(cfg, f)
    by = {r.name: r for r in results}
    assert not by["site"].ok and "disk full" in by["site"].detail
    assert by["bpf"].ok and by["deb"].ok
    assert code == 1


def test_edge_a_crash_inside_the_bpf_check_still_withdraws(cfg):
    f = healthy(cfg)

    def boom(argv):
        raise OSError("broken pipe")

    f.on(has("sudo", "verify-bpf-load.sh"), boom)
    results, code = pr.run_all(cfg, f)
    assert code == 3
    assert any("--prerelease" in j for j in f.joined())


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def test_failure_a_version_that_is_not_x_y_z_is_a_usage_error():
    assert pr.main(["run", "v0.5.241", "--host", "releaser@vm.example.invalid"], runner=Fake()) == 2


def test_failure_run_without_a_host_is_a_usage_error():
    # The VM and its account belong to the operator: this repository is
    # public, so the script carries no default for them.
    assert pr.main(["run", VERSION], runner=Fake()) == 2


def test_failure_no_subcommand_is_a_usage_error():
    assert pr.main([], runner=Fake()) == 2


def test_edge_withdraw_alone_flags_and_deploys(cfg, tmp_path):
    f = healthy(cfg)
    code = pr.main(["withdraw", VERSION], runner=f)
    assert code == 0
    assert any("--prerelease" in j for j in f.joined())
    assert any("workflow run pages.yml" in j for j in f.joined())


# ---------------------------------------------------------------------------
# The real wiring: subprocess, and gh found on PATH
# ---------------------------------------------------------------------------


def test_success_the_subprocess_runner_returns_the_exit_status_and_both_streams():
    r = pr.subprocess_runner(["sh", "-c", "echo out; echo err >&2; exit 3"], 10)
    assert r.rc == 3
    assert "out" in r.out and "err" in r.out


def test_edge_the_subprocess_runner_reports_a_timeout_as_exit_124():
    r = pr.subprocess_runner(["sleep", "5"], 0.2)
    assert r.rc == 124 and "timed out" in r.out


def test_success_withdraw_runs_the_gh_on_path(tmp_path, monkeypatch):
    log = tmp_path / "gh.log"
    gh = tmp_path / "bin" / "gh"
    gh.parent.mkdir()
    gh.write_text(f'#!/bin/sh\necho "$*" >> {log}\ncase "$*" in *isPrerelease*) echo true ;; esac\n')
    gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{gh.parent}:" + __import__("os").environ["PATH"])
    assert pr.main(["withdraw", VERSION]) == 0
    calls = log.read_text().splitlines()
    assert calls[0] == f"release edit v{VERSION} --prerelease --repo NormB/sipnab"
    assert calls[-1] == "workflow run pages.yml --ref main --repo NormB/sipnab"


# ---------------------------------------------------------------------------
# HOMEBREW-TAP-API-COMMIT-UNSIGNED
#
# On 0.5.241 the contents-API commit made with the HOMEBREW_TAP_TOKEN PAT came
# back unsigned (83b56c480), homebrew-tap-push.py refused it, the release run
# concluded failure, and the tap was bumped by hand with a signed
# fast-forward (1bd0c0dd3). The bump is now that hand step, tested.
# ---------------------------------------------------------------------------


def verified_answers(*answers):
    it = iter(answers)
    return lambda argv: (0, next(it))


def test_failure_the_0_5_241_unsigned_answer_is_refused(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, api=(0, commit_json(verification=UNSIGNED_0_5_241)))
    r = pr.check_tap(cfg, f)
    assert not r.ok
    assert "unsigned" in r.detail


def test_failure_an_unsigned_commit_never_reaches_the_tap_main(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, api=(0, commit_json(verification=UNSIGNED_0_5_241)))
    pr.check_tap(cfg, f)
    assert not tap_calls(f, "push", "refs/heads/main")


def test_failure_an_unsigned_commit_has_its_branch_deleted(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, api=(0, commit_json(verification=UNSIGNED_0_5_241)))
    pr.check_tap(cfg, f)
    assert tap_calls(f, "push", "origin", "--delete", f"sipnab-bump-{VERSION}")


def test_failure_a_string_true_is_not_verified(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, api=(0, commit_json(verification={"verified": "true", "reason": "valid"})))
    assert not pr.check_tap(cfg, f).ok


def test_failure_an_answer_with_no_verification_is_refused(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, api=(0, json.dumps({"sha": TAP_SHA})))
    assert not pr.check_tap(cfg, f).ok


def test_failure_an_answer_that_is_not_json_is_refused(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, api=(0, "<html>504</html>"))
    r = pr.check_tap(cfg, f)
    assert not r.ok
    assert not tap_calls(f, "push", "refs/heads/main")


def test_failure_a_failed_read_of_github_is_refused(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, api=(1, "HTTP 502\n"))
    r = pr.check_tap(cfg, f)
    assert not r.ok and "HTTP 502" in r.detail


def test_failure_a_different_sha_in_the_answer_is_refused(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, api=(0, commit_json(sha="0" * 40)))
    r = pr.check_tap(cfg, f)
    assert not r.ok
    assert not tap_calls(f, "push", "refs/heads/main")


def test_failure_a_local_commit_that_does_not_verify_is_never_pushed(cfg):
    f = healthy(cfg)
    f.on(has("verify-commit"), (1, "error: no signature found\n"))
    r = pr.check_tap(cfg, f)
    assert not r.ok and "no signature found" in r.detail
    assert not tap_calls(f, "git", "push", "HEAD:")


def test_failure_a_commit_that_cannot_be_made_is_reported(cfg):
    f = healthy(cfg)
    f.on(has("commit", "-S"), (128, "error: Load key: no such file\n"))
    r = pr.check_tap(cfg, f)
    assert not r.ok and "Load key" in r.detail
    assert not tap_calls(f, "git", "push", "HEAD:")


def test_failure_a_failed_clone_is_reported(cfg):
    f = healthy(cfg)
    f.on(has("git", "clone"), (128, "fatal: unable to access\n"))
    r = pr.check_tap(cfg, f)
    assert not r.ok and "unable to access" in r.detail


def test_failure_a_failed_render_is_reported(cfg):
    f = healthy(cfg)
    f.on(has("update-formula.sh"), (1, "update-formula: no checksum for x86_64-apple-darwin\n"))
    r = pr.check_tap(cfg, f)
    assert not r.ok and "no checksum" in r.detail
    assert not tap_calls(f, "commit", "-S")


def test_failure_a_failed_download_of_the_checksums_is_reported(cfg):
    f = healthy(cfg)
    f.on(has("gh", "release", "download"), (1, "release not found\n"))
    r = pr.check_tap(cfg, f)
    assert not r.ok and "release not found" in r.detail


def test_failure_a_refused_branch_push_never_touches_main(cfg):
    f = healthy(cfg)
    f.on(has("push", f"refs/heads/sipnab-bump-{VERSION}"), (1, "remote: denied\n"))
    r = pr.check_tap(cfg, f)
    assert not r.ok and "denied" in r.detail
    assert not tap_calls(f, "push", "refs/heads/main")


def test_failure_main_that_moved_refuses_the_fast_forward_and_deletes_the_branch(cfg):
    f = healthy(cfg)
    f.on(has("push", "refs/heads/main"), (1, "! [rejected] HEAD -> main (non-fast-forward)\n"))
    r = pr.check_tap(cfg, f)
    assert not r.ok and "non-fast-forward" in r.detail
    assert tap_calls(f, "--delete", f"sipnab-bump-{VERSION}")


def test_failure_main_not_at_the_commit_after_the_push_is_refused(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, api=verified_answers(commit_json(), commit_json(sha="f" * 40)))
    r = pr.check_tap(cfg, f)
    assert not r.ok


def test_failure_main_unverified_after_the_push_is_refused(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, api=verified_answers(commit_json(), commit_json(verification=UNSIGNED_0_5_241)))
    r = pr.check_tap(cfg, f)
    assert not r.ok and "unsigned" in r.detail


def test_success_a_signed_verified_commit_passes_and_names_it(cfg):
    f = healthy(cfg)
    r = pr.check_tap(cfg, f)
    assert r.ok, r.detail
    assert TAP_SHA in r.detail


def test_success_the_commit_is_signed_explicitly(cfg):
    f = healthy(cfg)
    pr.check_tap(cfg, f)
    c = tap_calls(f, "commit", "-S")
    assert c and "-m" in c[0]
    assert f"sipnab: bump to {VERSION}" in c[0]


def test_success_the_rendered_formula_is_what_is_staged(cfg):
    seen = {}
    f = healthy(cfg)

    def add(argv):
        tap = pathlib.Path(argv[argv.index("-C") + 1])
        seen["text"] = (tap / "Formula/sipnab.rb").read_text()
        return (0, "")

    f.on(has("git", " add "), add)
    pr.check_tap(cfg, f)
    assert seen["text"] == NEW_FORMULA


def test_success_the_branch_is_checked_before_main_moves(cfg):
    f = healthy(cfg)
    pr.check_tap(cfg, f)
    j = f.joined()
    branch = next(i for i, c in enumerate(j) if f"HEAD:refs/heads/sipnab-bump-{VERSION}" in c)
    check = next(i for i, c in enumerate(j) if f"/commits/{TAP_SHA}" in c)
    main = next(i for i, c in enumerate(j) if "HEAD:refs/heads/main" in c)
    assert branch < check < main


def test_success_the_local_signature_is_checked_before_any_push(cfg):
    f = healthy(cfg)
    pr.check_tap(cfg, f)
    j = f.joined()
    assert next(i for i, c in enumerate(j) if "verify-commit" in c) < next(i for i, c in enumerate(j) if " push " in c)


def test_success_github_is_read_again_for_main_after_the_push(cfg):
    f = healthy(cfg)
    pr.check_tap(cfg, f)
    j = f.joined()
    assert next(i for i, c in enumerate(j) if "HEAD:refs/heads/main" in c) < next(i for i, c in enumerate(j) if "/commits/main" in c)


def test_success_the_scratch_branch_is_deleted_after_a_pass(cfg):
    f = healthy(cfg)
    pr.check_tap(cfg, f)
    assert tap_calls(f, "--delete", f"sipnab-bump-{VERSION}")


def test_success_a_tap_already_at_the_formula_and_verified_makes_no_commit(cfg):
    # A re-run after the bump has landed.
    f = healthy(cfg)
    tap_world(f, cfg, existing=NEW_FORMULA)
    r = pr.check_tap(cfg, f)
    assert r.ok, r.detail
    assert not tap_calls(f, "commit", "-S")
    assert not tap_calls(f, " push ")


def test_edge_a_tap_already_at_the_formula_but_unverified_fails(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, existing=NEW_FORMULA, api=(0, commit_json(verification=UNSIGNED_0_5_241)))
    r = pr.check_tap(cfg, f)
    assert not r.ok and "unsigned" in r.detail


def test_edge_a_tap_on_a_newer_release_is_never_moved_back(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, existing='class Sipnab < Formula\n  version "0.5.300"\nend\n')
    r = pr.check_tap(cfg, f)
    assert not r.ok and "0.5.300" in r.detail
    assert not tap_calls(f, "commit", "-S")


def test_edge_a_tap_formula_with_no_version_is_refused(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, existing="class Sipnab < Formula\nend\n")
    r = pr.check_tap(cfg, f)
    assert not r.ok
    assert not tap_calls(f, "commit", "-S")


def test_edge_a_newer_patch_compares_numerically(cfg):
    # 0.5.99 is older than 0.5.241 though it sorts later as text.
    f = healthy(cfg)
    tap_world(f, cfg, existing='class Sipnab < Formula\n  version "0.5.99"\nend\n')
    assert pr.check_tap(cfg, f).ok


def test_edge_a_leftover_branch_is_deleted_before_the_push(cfg):
    f = healthy(cfg)
    f.on(has("ls-remote"), (0, f"abc\trefs/heads/sipnab-bump-{VERSION}\n"))
    pr.check_tap(cfg, f)
    j = f.joined()
    assert next(i for i, c in enumerate(j) if "--delete" in c) < next(i for i, c in enumerate(j) if "HEAD:refs/heads/sipnab-bump" in c)


def test_edge_nothing_is_ever_forced(cfg):
    f = healthy(cfg)
    f.on(has("ls-remote"), (0, f"abc\trefs/heads/sipnab-bump-{VERSION}\n"))
    pr.check_tap(cfg, f)
    for j in f.joined():
        assert "--force" not in j and " -f " not in j and "+HEAD" not in j


def test_edge_no_token_is_handed_to_any_tap_command(cfg):
    f = healthy(cfg)
    pr.check_tap(cfg, f)
    assert not any("HOMEBREW_TAP_TOKEN" in j for j in f.joined())


def test_edge_a_scratch_branch_that_cannot_be_deleted_still_passes_and_says_so(cfg):
    f = healthy(cfg)
    f.on(has("--delete"), (1, "remote: nope\n"))
    r = pr.check_tap(cfg, f)
    assert r.ok and "sipnab-bump" in r.detail


def test_edge_the_scratch_directory_is_removed_after_a_pass_and_a_failure(cfg):
    f = healthy(cfg)
    pr.check_tap(cfg, f)
    assert not pr.tap_dir(cfg).exists()
    g = healthy(cfg)
    tap_world(g, cfg, api=(0, commit_json(verification=UNSIGNED_0_5_241)))
    pr.check_tap(cfg, g)
    assert not pr.tap_dir(cfg).exists()


def test_edge_the_tap_directory_is_not_the_deb_directory(cfg):
    # The deb check removes its directory while the tap check is running.
    assert pr.tap_dir(cfg) != cfg.workdir
    assert not pr.tap_dir(cfg).is_relative_to(cfg.workdir)


def test_edge_a_failed_tap_never_withdraws_the_release(cfg):
    f = healthy(cfg)
    tap_world(f, cfg, api=(0, commit_json(verification=UNSIGNED_0_5_241)))
    _, code = pr.run_all(cfg, f)
    assert code == 1
    assert not any("--prerelease" in j for j in f.joined())


def test_edge_a_crash_in_the_tap_check_fails_only_that_check(cfg):
    f = healthy(cfg)

    def boom(argv):
        raise OSError("no space left")

    f.on(has("git", "clone"), boom)
    results, code = pr.run_all(cfg, f)
    by = {r.name: r for r in results}
    assert not by["tap"].ok and "no space left" in by["tap"].detail
    assert by["bpf"].ok and by["deb"].ok and by["site"].ok
    assert code == 1
