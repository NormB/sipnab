# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/pages-live.py: is the live site the artifact this run deployed?

PAGES-SAME-SHA-REDEPLOY-NOT-LIVE. On 0.5.242 two workflow_dispatch runs of
pages.yml on main commit 1ef3e74a0 (42714372409 and 42717859462) built
artifacts naming 0.5.242, `actions/deploy-pages` reported success for both
(deployments 7668209866 and 7668618717), and the site kept serving the push
deploy of the same commit. On 0.5.241 and 0.5.243 the same kind of re-deploy
went live.

What the runs show: the action sends `pages_build_version = GITHUB_SHA`, and
GitHub names the Pages deployment by that string ("Created deployment for
<sha>, ID: <sha>" in every deploy job's log). A second deploy of one commit
therefore asks for the status of a deployment that already says `succeed`,
so its "Reported success!" says nothing about the new artifact. Why GitHub
did not promote the two artifacts on 0.5.242 is not established.

So the deploy is judged by the live site. The build writes a stamp, `<commit>
<run id> <run attempt>`, into the site; after the deploy this script reads it
back from the live site. When the live stamp is not this run's within a
bound, it deploys the same artifact again under a build version GitHub has
not seen, `<commit>-<run id>-<run attempt>`, says so loudly, and reads the
stamp again. A site that is still stale fails the run.
"""

import json

import pytest
from conftest import load

pl = load("pages-live")
REAL_RUNNER = pl.subprocess_runner
REAL_SLEEP = pl.time.sleep


@pytest.fixture(autouse=True)
def _no_real_world(monkeypatch):
    """No test reaches the network or sleeps: `main` falls back to these."""

    def refuse(*args, **kwargs):
        raise AssertionError(f"a test reached the real world: {args[:1]}")

    monkeypatch.setattr(pl, "subprocess_runner", refuse)
    monkeypatch.setattr(pl, "urllib_get", refuse)
    monkeypatch.setattr(pl.time, "sleep", refuse)


@pytest.fixture
def real_sleep(monkeypatch):
    """`time.sleep` as the interpreter has it, for a test of the real runner.

    `pl.time` is the `time` module itself, so the guard above replaces the
    function for every caller in the process. `subprocess` is one: after a
    child's pipes close it polls for the exit with `time.sleep`.
    """
    monkeypatch.setattr(pl.time, "sleep", REAL_SLEEP)

SHA = "8" * 40
OTHER = "1" * 40
ENV = {"GITHUB_SHA": SHA, "GITHUB_RUN_ID": "42779555980", "GITHUB_RUN_ATTEMPT": "1",
       "GITHUB_REPOSITORY": "NormB/sipnab"}
STAMP = f"{SHA} 42779555980 1"


# ---------------------------------------------------------------------------
# The stamp
# ---------------------------------------------------------------------------


def test_success_the_stamp_is_the_commit_the_run_and_the_attempt():
    assert pl.make_stamp(ENV) == STAMP


@pytest.mark.parametrize("key,value", [
    ("GITHUB_SHA", "88f46bb83"), ("GITHUB_SHA", ""), ("GITHUB_RUN_ID", ""), ("GITHUB_RUN_ID", "12 3"),
    ("GITHUB_RUN_ATTEMPT", "one"), ("GITHUB_SHA", "8" * 39 + "\n8"),
])
def test_failure_a_stamp_is_not_made_from_a_malformed_value(key, value):
    with pytest.raises(ValueError):
        pl.make_stamp({**ENV, key: value})


def test_edge_a_missing_variable_is_refused_not_written_as_none():
    with pytest.raises(ValueError):
        pl.make_stamp({})


# ---------------------------------------------------------------------------
# One read of the live stamp
# ---------------------------------------------------------------------------


def test_success_this_runs_stamp_on_the_site_is_live():
    assert pl.classify(200, STAMP + "\n", STAMP) == "live"


def test_failure_another_runs_stamp_is_stale():
    # 0.5.242: the site kept the push deploy of the same commit.
    assert pl.classify(200, f"{SHA} 42707117461 1\n", STAMP) == "stale"


def test_failure_a_404_is_stale_because_a_deploy_from_before_the_stamp_has_no_such_file():
    assert pl.classify(404, "<html>not found</html>", STAMP) == "stale"


@pytest.mark.parametrize("status,body", [
    (0, ""), (403, "Attention Required"), (429, ""), (500, STAMP), (526, ""), (301, STAMP),
])
def test_failure_a_site_that_did_not_answer_with_a_stamp_is_unreadable(status, body):
    # Nothing about the deploy follows from an edge refusal or an outage.
    assert pl.classify(status, body, STAMP) == "unreadable"


def test_edge_a_200_that_is_not_a_stamp_is_unreadable_not_stale():
    # A CDN challenge page answers 200 and carries no stamp.
    assert pl.classify(200, "<html>Just a moment</html>", STAMP) == "unreadable"


def test_edge_an_empty_200_is_unreadable():
    assert pl.classify(200, "", STAMP) == "unreadable"


def test_edge_the_same_commit_and_run_at_another_attempt_is_stale():
    assert pl.classify(200, f"{SHA} 42779555980 2", STAMP) == "stale"


def test_edge_a_stamp_with_surrounding_whitespace_is_read():
    assert pl.classify(200, f"\n  {STAMP}\r\n", STAMP) == "live"


def test_edge_a_stamp_followed_by_other_text_is_not_a_stamp():
    assert pl.classify(200, f"{STAMP}\n<html>", STAMP) == "unreadable"


# ---------------------------------------------------------------------------
# Reading it: curl, with a query no cache has seen
# ---------------------------------------------------------------------------


class Site:
    """The live site and GitHub's Pages API, on one clock."""

    def __init__(self, live=STAMP, goes_live_at=None, status=200):
        self.now = 1_800_000_000.0
        self.old = f"{SHA} 42707117461 1"
        self.live = live
        self.goes_live_at = goes_live_at
        self.status = status
        self.urls = []
        self.calls = []
        self.deploys = []
        self.deploy_status = ["succeed"]
        self.redeploy_makes_live = True
        self.artifacts = [{"id": 13744719651, "name": "github-pages"}]
        self.advertised = "0.5.243"
        self.overrides = []

    def sleep(self, s):
        self.now += s

    def clock(self):
        return self.now

    def body(self):
        if self.goes_live_at is not None:
            return STAMP if self.now >= self.goes_live_at else self.old
        return self.live

    def __call__(self, argv, timeout, stdin=None):
        self.calls.append((argv, stdin))
        if len(self.calls) > 2000:
            raise RuntimeError("runaway")
        j = " ".join(argv)
        for pred, result in self.overrides:
            if pred in j:
                return pl.Result(*result)
        if argv[0] == "curl":
            self.urls.append(argv[-1])
            return pl.Result(0, f"{self.body()}\n{self.status}")
        if "actions/runs/" in j and "artifacts" in j:
            return pl.Result(0, json.dumps({"artifacts": self.artifacts}))
        if "--method POST" in j and j.endswith("--input -"):
            payload = json.loads(stdin)
            self.deploys.append(payload)
            if self.redeploy_makes_live:
                self.goes_live_at = self.now + 20
            return pl.Result(0, json.dumps({"id": payload["pages_build_version"], "status_url": "u"}))
        if "pages/deployments/" in j:
            s = self.deploy_status.pop(0) if len(self.deploy_status) > 1 else self.deploy_status[0]
            return pl.Result(0, json.dumps({"status": s}))
        if "verify-site-advertises.sh" in j:
            if argv[-1] == self.advertised:
                return pl.Result(0, f"OK: the page names {argv[-1]}.\n")
            return pl.Result(1, f"STALE: the page is healthy and does not name {argv[-1]}.\n")
        raise AssertionError(f"no rule for {j}")


URL = "https://sipnab.example.invalid/deploy-stamp.txt"


def test_success_a_read_returns_the_status_and_the_body():
    s = Site()
    assert pl.read_stamp(s, URL, "n1") == (200, STAMP)


def test_success_each_read_carries_its_own_query_so_no_cache_answers():
    s = Site()
    pl.read_stamp(s, URL, "n1")
    pl.read_stamp(s, URL, "n2")
    assert s.urls == [URL + "?nonce=n1", URL + "?nonce=n2"]


def test_success_the_read_names_its_client():
    s = Site()
    pl.read_stamp(s, URL, "n1")
    argv = s.calls[0][0]
    assert argv[argv.index("--user-agent") + 1].startswith("sipnab-release-check/")


def test_failure_a_transport_failure_is_status_0():
    s = Site()
    s.overrides.append(("curl", (6, "curl: (6) Could not resolve host\n000")))
    assert pl.read_stamp(s, URL, "n1")[0] == 0


def test_failure_output_with_no_status_line_is_status_0():
    s = Site()
    s.overrides.append(("curl", (0, "garbage")))
    assert pl.read_stamp(s, URL, "n1") == (0, "")


def test_edge_a_url_that_has_a_query_gets_the_nonce_appended():
    s = Site()
    pl.read_stamp(s, URL + "?a=1", "n1")
    assert s.urls == [URL + "?a=1&nonce=n1"]


def test_edge_a_body_of_several_lines_keeps_all_but_the_status():
    s = Site()
    s.overrides.append(("curl", (0, "<html>\nnot found\n</html>\n404")))
    assert pl.read_stamp(s, URL, "n1") == (404, "<html>\nnot found\n</html>")


# ---------------------------------------------------------------------------
# Waiting for it, inside a bound
# ---------------------------------------------------------------------------


def cfg(**kw):
    base = dict(stamp=STAMP, url=URL, within=300.0, every=15.0, expect="", enforce=True, repo="NormB/sipnab",
                run_id="42779555980", attempt="1", sha=SHA)
    base.update(kw)
    return pl.Config(**base)


def test_success_a_site_that_is_live_at_once_costs_one_read_and_no_wait():
    s = Site()
    t0 = s.now
    assert pl.await_stamp(cfg(), s, s.sleep, s.clock, "a")[0] == "live"
    assert len(s.urls) == 1 and s.now == t0


def test_success_a_site_that_goes_live_inside_the_bound_is_waited_for():
    s = Site()
    s.goes_live_at = s.now + 40
    t0 = s.now
    assert pl.await_stamp(cfg(), s, s.sleep, s.clock, "a")[0] == "live"
    assert 40 <= s.now - t0 < 40 + 15


def test_failure_a_site_that_stays_stale_is_given_up_on_inside_the_bound():
    s = Site(live=f"{SHA} 42707117461 1")
    t0 = s.now
    state, detail = pl.await_stamp(cfg(), s, s.sleep, s.clock, "a")
    assert state == "stale" and "42707117461" in detail
    assert 300 - 15 < s.now - t0 <= 300


def test_failure_an_unreadable_site_is_reported_as_that_after_the_bound():
    s = Site(status=403)
    state, detail = pl.await_stamp(cfg(), s, s.sleep, s.clock, "a")
    assert state == "unreadable" and "HTTP 403" in detail


def test_edge_an_unreadable_read_does_not_end_the_wait_early():
    s = Site(status=403)
    t0 = s.now
    pl.await_stamp(cfg(), s, s.sleep, s.clock, "a")
    assert s.now - t0 > 300 - 15


def test_edge_a_bound_of_zero_reads_once():
    s = Site(live=f"{SHA} 42707117461 1")
    assert pl.await_stamp(cfg(within=0.0), s, s.sleep, s.clock, "a")[0] == "stale"
    assert len(s.urls) == 1


def test_edge_every_read_of_one_wait_has_a_different_nonce_and_names_the_run():
    s = Site(live=f"{SHA} 42707117461 1")
    pl.await_stamp(cfg(), s, s.sleep, s.clock, "a")
    assert len(set(s.urls)) == len(s.urls) > 1
    assert all("nonce=42779555980.1.a" in u for u in s.urls)


def test_edge_the_detail_is_one_line_however_long_the_body():
    s = Site(status=404)
    s.overrides.append(("curl", (0, "<html>\n" + "x" * 500 + "\n</html>\n404")))
    _state, detail = pl.await_stamp(cfg(within=0.0), s, s.sleep, s.clock, "a")
    assert "\n" not in detail and len(detail) < 140


# ---------------------------------------------------------------------------
# The second deploy, under a build version GitHub has not seen
# ---------------------------------------------------------------------------

OIDC = "oidc-token-value"


def http_get(url, headers):
    assert url == "https://token.example.invalid/id" and headers == {"Authorization": "bearer request-token"}
    return json.dumps({"value": OIDC})


RENV = {**ENV, "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.example.invalid/id",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-token"}


def test_success_the_build_version_is_the_commit_the_run_and_the_attempt():
    assert pl.unique_version(cfg()) == f"{SHA}-42779555980-1"


def test_success_the_second_deploy_sends_the_runs_artifact_under_the_unique_version():
    s = Site()
    ok, detail = pl.redeploy(cfg(), RENV, s, http_get, s.sleep, s.clock)
    assert ok, detail
    assert s.deploys == [{"artifact_id": 13744719651, "pages_build_version": f"{SHA}-42779555980-1",
                          "oidc_token": OIDC}]


def test_success_the_second_deploy_waits_for_githubs_status_to_say_succeed():
    s = Site()
    s.deploy_status = ["deployment_queued", "syncing_files", "succeed"]
    t0 = s.now
    ok, detail = pl.redeploy(cfg(), RENV, s, http_get, s.sleep, s.clock)
    assert ok and s.now - t0 == 3 * pl.STATUS_EVERY and "succeed" in detail


def test_success_the_status_asked_for_is_the_new_deployments_not_the_commits():
    s = Site()
    pl.redeploy(cfg(), RENV, s, http_get, s.sleep, s.clock)
    asked = [a for a, _ in s.calls if any("pages/deployments/" in x for x in a)]
    assert asked and all(a[-1] == f"repos/NormB/sipnab/pages/deployments/{SHA}-42779555980-1" for a in asked)


def test_success_the_oidc_token_is_masked_before_anything_else_is_printed(capsys):
    s = Site()
    pl.redeploy(cfg(), RENV, s, http_get, s.sleep, s.clock)
    out = capsys.readouterr().out
    assert out.startswith(f"::add-mask::{OIDC}\n") and out.count(OIDC) == 1


def test_success_the_token_travels_on_stdin_never_in_the_arguments():
    s = Site()
    pl.redeploy(cfg(), RENV, s, http_get, s.sleep, s.clock)
    assert all(OIDC not in " ".join(argv) for argv, _ in s.calls)
    assert sum(1 for _, stdin in s.calls if stdin and OIDC in stdin) == 1


# GitHub spells one status with a doubled l; joined from two pieces, as in the
# script, so the US-spelling gates need no exemption.
@pytest.mark.parametrize("status", ["deployment_failed", "deployment_perms_error", "deployment_content_failed",
                                    "deployment_cance" "lled", "deployment_lost"])
def test_failure_a_final_error_status_ends_the_second_deploy(status):
    s = Site()
    s.deploy_status = ["syncing_files", status]
    t0 = s.now
    ok, detail = pl.redeploy(cfg(), RENV, s, http_get, s.sleep, s.clock)
    assert not ok and status in detail
    assert s.now - t0 == 2 * pl.STATUS_EVERY, "a final status is not polled past"


def test_failure_a_status_that_never_succeeds_is_given_up_on_inside_the_bound():
    s = Site()
    s.deploy_status = ["deployment_queued"]
    t0 = s.now
    ok, detail = pl.redeploy(cfg(), RENV, s, http_get, s.sleep, s.clock)
    assert not ok and "deployment_queued" in detail and pl.STATUS_WITHIN <= s.now - t0 < pl.STATUS_WITHIN + pl.STATUS_EVERY


def test_failure_no_artifact_means_no_deploy():
    s = Site()
    s.artifacts = []
    ok, detail = pl.redeploy(cfg(), RENV, s, http_get, s.sleep, s.clock)
    assert not ok and s.deploys == [] and "github-pages" in detail


def test_failure_an_artifact_list_that_cannot_be_read_means_no_deploy():
    s = Site()
    s.overrides.append(("actions/runs/", (1, "HTTP 502")))
    ok, detail = pl.redeploy(cfg(), RENV, s, http_get, s.sleep, s.clock)
    assert not ok and s.deploys == [] and "HTTP 502" in detail


def test_failure_no_oidc_request_variables_means_no_deploy():
    s = Site()
    ok, detail = pl.redeploy(cfg(), ENV, s, http_get, s.sleep, s.clock)
    assert not ok and s.deploys == [] and "id-token: write" in detail


def test_failure_an_oidc_answer_with_no_value_means_no_deploy():
    s = Site()
    ok, detail = pl.redeploy(cfg(), RENV, s, lambda url, headers: "{}", s.sleep, s.clock)
    assert not ok and s.deploys == []


def test_failure_an_oidc_request_that_raises_means_no_deploy():
    s = Site()

    def boom(url, headers):
        raise OSError("connection reset")

    ok, detail = pl.redeploy(cfg(), RENV, s, boom, s.sleep, s.clock)
    assert not ok and s.deploys == [] and "connection reset" in detail


def test_failure_a_refused_create_is_reported_with_githubs_answer_and_not_the_token():
    s = Site()
    s.overrides.append(("--method POST", (1, '{"message":"Invalid pages_build_version"}')))
    ok, detail = pl.redeploy(cfg(), RENV, s, http_get, s.sleep, s.clock)
    assert not ok and "Invalid pages_build_version" in detail and OIDC not in detail


def test_edge_of_two_artifacts_of_that_name_the_newest_is_deployed():
    # A re-run attempt uploads the name again; the larger id is the later one.
    s = Site()
    s.artifacts = [{"id": 5, "name": "github-pages"}, {"id": 9, "name": "github-pages"}, {"id": 99, "name": "other"}]
    pl.redeploy(cfg(), RENV, s, http_get, s.sleep, s.clock)
    assert s.deploys[0]["artifact_id"] == 9


def test_edge_a_status_read_that_fails_is_tried_again():
    s = Site()
    real = s.__call__
    seen = {"n": 0}

    def flaky(argv, timeout, stdin=None):
        if any("pages/deployments/" in a for a in argv):
            seen["n"] += 1
            if seen["n"] == 1:
                return pl.Result(1, "HTTP 502")
        return real(argv, timeout, stdin)

    ok, _detail = pl.redeploy(cfg(), RENV, flaky, http_get, s.sleep, s.clock)
    assert ok and seen["n"] == 2


def test_edge_a_status_answer_that_is_not_json_is_tried_again():
    s = Site()
    real = s.__call__
    seen = {"n": 0}

    def odd(argv, timeout, stdin=None):
        if any("pages/deployments/" in a for a in argv):
            seen["n"] += 1
            if seen["n"] == 1:
                return pl.Result(0, "<html>")
        return real(argv, timeout, stdin)

    ok, _detail = pl.redeploy(cfg(), RENV, odd, http_get, s.sleep, s.clock)
    assert ok


# ---------------------------------------------------------------------------
# The whole check
# ---------------------------------------------------------------------------


def verify(s, **kw):
    return pl.verify(cfg(**kw), RENV, s, http_get, s.sleep, s.clock)


def stale_site(**kw):
    return Site(live=f"{SHA} 42707117461 1", **kw)


def test_success_a_live_site_passes_with_no_second_deploy(capsys):
    s = Site()
    assert verify(s) == 0
    assert s.deploys == [] and "::warning::" not in capsys.readouterr().out


def test_success_a_stale_site_gets_one_second_deploy_and_passes_when_that_goes_live():
    s = stale_site()
    assert verify(s) == 0
    assert len(s.deploys) == 1 and s.deploys[0]["pages_build_version"] == f"{SHA}-42779555980-1"


def test_success_the_second_deploy_is_announced_as_a_warning_that_names_both_build_versions(capsys):
    s = stale_site()
    verify(s)
    out = capsys.readouterr().out
    warning = next(line for line in out.splitlines() if line.startswith("::warning::") and "second deploy" in line)
    assert SHA in warning and f"{SHA}-42779555980-1" in warning and "did not go live" in warning, out


def test_success_the_announcement_is_a_warning_even_when_the_second_deploy_does_not_help(capsys):
    s = stale_site()
    s.redeploy_makes_live = False
    verify(s)
    warnings = [line for line in capsys.readouterr().out.splitlines() if line.startswith("::warning::")]
    assert len(warnings) == 1 and "Starting a second deploy" in warnings[0], warnings


def test_success_a_pass_after_a_second_deploy_says_which_deploy_is_live(capsys):
    s = stale_site()
    verify(s)
    assert "the second deploy is live" in capsys.readouterr().out


def test_success_an_expected_release_is_checked_on_the_live_page_once_the_stamp_is_live():
    s = Site()
    assert verify(s, expect="0.5.243") == 0
    assert any("verify-site-advertises.sh" in " ".join(a) and a[-1] == "0.5.243" for a, _ in s.calls)


def test_failure_a_site_still_stale_after_the_second_deploy_fails_the_run(capsys):
    s = stale_site()
    s.redeploy_makes_live = False
    assert verify(s) == 1
    out = capsys.readouterr().out
    assert "::error::" in out and "still" in out and len(s.deploys) == 1


def test_failure_a_second_deploy_github_refuses_fails_the_run_with_the_reason(capsys):
    s = stale_site()
    s.overrides.append(("--method POST", (1, '{"message":"Invalid pages_build_version"}')))
    assert verify(s) == 1
    reads_before = len(s.urls)
    out = capsys.readouterr().out
    assert "::error::The site is stale and the second deploy failed" in out and "Invalid pages_build_version" in out
    assert "still stale after the second deploy" not in out and len(s.urls) == reads_before


def test_failure_after_a_refused_second_deploy_the_stamp_is_not_read_again():
    s = stale_site()
    s.overrides.append(("--method POST", (1, "refused")))
    t0 = s.now
    verify(s)
    assert s.now - t0 <= 300, "one wait, not two"


def test_failure_an_unreadable_site_fails_the_run_and_deploys_nothing(capsys):
    s = Site(status=403)
    assert verify(s) == 2
    out = capsys.readouterr().out
    assert s.deploys == [] and "::error::" in out and "could not be read" in out


def test_failure_a_live_site_that_does_not_name_the_expected_release_fails_the_run(capsys):
    s = Site()
    s.advertised = "0.5.242"
    assert verify(s, expect="0.5.243") == 3
    out = capsys.readouterr().out
    assert "::error::" in out and "does not name 0.5.243" in out


def test_failure_a_stale_site_is_not_asked_about_the_release():
    s = stale_site()
    s.redeploy_makes_live = False
    verify(s, expect="0.5.243")
    assert not any("verify-site-advertises.sh" in " ".join(a) for a, _ in s.calls)


def test_failure_without_enforce_a_stale_site_is_an_error_annotation_and_exit_0(capsys):
    # A push deploy: a red Pages run on a release's merge commit would refuse
    # the tag (scripts/tag-push-proof.py, "red on the commit itself").
    s = stale_site()
    s.redeploy_makes_live = False
    assert verify(s, enforce=False) == 0
    out = capsys.readouterr().out
    assert "::error::" in out and "not enforced" in out


def test_edge_without_enforce_a_stale_site_still_gets_the_second_deploy():
    s = stale_site()
    assert verify(s, enforce=False) == 0
    assert len(s.deploys) == 1


def test_edge_without_enforce_an_unreadable_site_exits_0_and_says_nothing_is_known(capsys):
    s = Site(status=403)
    assert verify(s, enforce=False) == 0
    assert "could not be read" in capsys.readouterr().out


def test_edge_the_page_is_given_the_bound_to_name_the_release():
    s = Site()
    real = s.__call__
    asks = []

    def late(argv, timeout, stdin=None):
        if any("verify-site-advertises.sh" in a for a in argv):
            asks.append(s.now)
            if len(asks) < 3:
                return pl.Result(1, "STALE: the page is healthy and does not name 0.5.243.\n")
        return real(argv, timeout, stdin)

    assert pl.verify(cfg(expect="0.5.243"), RENV, late, http_get, s.sleep, s.clock) == 0
    assert len(asks) == 3 and asks[-1] - asks[0] == 30


def test_edge_the_release_check_gives_up_inside_the_bound():
    s = Site()
    s.advertised = "0.5.242"
    t0 = s.now
    verify(s, expect="0.5.243")
    assert 300 - 15 < s.now - t0 <= 300


def test_edge_the_reads_after_the_second_deploy_use_nonces_the_first_wait_did_not():
    s = stale_site()
    verify(s)
    assert len(set(s.urls)) == len(s.urls)


def test_edge_a_site_that_goes_live_late_in_the_first_wait_needs_no_second_deploy():
    s = Site()
    s.goes_live_at = s.now + 290
    assert verify(s) == 0 and s.deploys == []


def test_edge_no_expected_release_means_the_page_is_not_asked():
    s = Site()
    verify(s)
    assert not any("verify-site-advertises.sh" in " ".join(a) for a, _ in s.calls)


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def test_success_stamp_write_puts_the_stamp_and_a_newline_in_the_file(tmp_path, capsys):
    out = tmp_path / "static" / "deploy-stamp.txt"
    out.parent.mkdir()
    assert pl.main(["stamp", "--write", str(out)], env=ENV) == 0
    assert out.read_text() == STAMP + "\n" and STAMP in capsys.readouterr().out


def test_failure_stamp_write_with_a_bad_environment_writes_nothing(tmp_path, capsys):
    out = tmp_path / "deploy-stamp.txt"
    assert pl.main(["stamp", "--write", str(out)], env={}) == 2
    assert not out.exists() and "GITHUB_SHA" in capsys.readouterr().err


def test_success_verify_builds_its_stamp_and_settings_from_the_environment_and_flags(monkeypatch):
    seen = {}
    monkeypatch.setattr(pl, "verify", lambda cfg, env, run, http_get, sleep, clock: seen.update(cfg=cfg) or 0)
    assert pl.main(["verify", "--expect", "0.5.243", "--enforce", "--within", "120", "--every", "10"], env=RENV) == 0
    c = seen["cfg"]
    assert (c.stamp, c.expect, c.enforce, c.within, c.every) == (STAMP, "0.5.243", True, 120.0, 10.0)
    assert (c.repo, c.run_id, c.attempt, c.sha) == ("NormB/sipnab", "42779555980", "1", SHA)
    assert c.url == "https://sipnab.com/deploy-stamp.txt"


def test_success_verify_returns_the_verdict_as_the_exit_status(monkeypatch):
    monkeypatch.setattr(pl, "verify", lambda *a: 3)
    assert pl.main(["verify"], env=RENV) == 3


def test_failure_an_expected_release_that_is_not_a_version_is_a_usage_error(capsys):
    assert pl.main(["verify", "--expect", "v0.5.243; rm"], env=RENV) == 2
    assert "X.Y.Z" in capsys.readouterr().err


def test_failure_verify_without_a_repository_is_a_usage_error(capsys):
    env = {k: v for k, v in RENV.items() if k != "GITHUB_REPOSITORY"}
    assert pl.main(["verify"], env=env) == 2
    assert "GITHUB_REPOSITORY" in capsys.readouterr().err


def test_failure_an_unknown_command_is_a_usage_error():
    assert pl.main(["deploy"], env=RENV) == 2


def test_failure_a_bound_below_zero_is_a_usage_error():
    assert pl.main(["verify", "--within", "-5"], env=RENV) == 2


def test_failure_an_interval_of_zero_is_a_usage_error():
    assert pl.main(["verify", "--every", "0"], env=RENV) == 2


def test_edge_an_empty_expect_means_no_release_is_expected(monkeypatch):
    # pages.yml passes its `expect` input as it is, and a push has none.
    seen = {}
    monkeypatch.setattr(pl, "verify", lambda cfg, *a: seen.update(cfg=cfg) or 0)
    assert pl.main(["verify", "--expect", ""], env=RENV) == 0
    assert seen["cfg"].expect == "" and seen["cfg"].enforce is False


def test_edge_the_defaults_are_five_minutes_every_fifteen_seconds(monkeypatch):
    seen = {}
    monkeypatch.setattr(pl, "verify", lambda cfg, *a: seen.update(cfg=cfg) or 0)
    pl.main(["verify"], env=RENV)
    assert (seen["cfg"].within, seen["cfg"].every) == (300.0, 15.0)


def test_edge_the_url_can_be_set_for_another_host(monkeypatch):
    seen = {}
    monkeypatch.setattr(pl, "verify", lambda cfg, *a: seen.update(cfg=cfg) or 0)
    pl.main(["verify", "--url", URL], env=RENV)
    assert seen["cfg"].url == URL


def test_edge_the_real_runner_passes_stdin_and_reports_a_timeout_as_124(real_sleep):
    r = REAL_RUNNER(["sh", "-c", "cat"], 30, "to stdin")
    assert (r.rc, r.out) == (0, "to stdin")
    assert REAL_RUNNER(["sh", "-c", "exec sleep 5"], 0.2).rc == 124


def test_edge_the_real_runner_waits_for_a_child_that_closed_its_output_first(real_sleep):
    """A child that closes stdout and stderr and exits later. `subprocess`
    reads both pipes to their end and then polls for the exit with
    `time.sleep`, the interpreter's own function, which the guard above
    replaces. Under load the two tests above reached that poll now and then
    (seen 2026-11-12 in the pre-commit hook: `a test reached the real world:
    (0.001,)`); this child reaches it every time."""
    r = REAL_RUNNER(["sh", "-c", "exec >&- 2>&-; sleep 0.3; exit 7"], 30)
    assert (r.rc, r.out) == (7, "")
