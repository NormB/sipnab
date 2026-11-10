# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""pages.yml judges its deploy by the live site (PAGES-SAME-SHA-REDEPLOY-NOT-LIVE).

`actions/deploy-pages` reported success for two re-deploys of main commit
1ef3e74a0 on 0.5.242 and the site did not change. scripts/pages-live.py is
the check and the second deploy; its behavior is tested in
test_pages_live.py. The jobs cannot run outside a real deploy, so these
tests hold the workflow text to the shape that script needs:

* the build writes the stamp into the site before `zola build`;
* a `live` job after `deploy` reads it back, with the scopes and the
  environment a second deploy needs;
* a workflow_dispatch run, which is how a release advertises itself and how
  a withdrawal redeploys, enforces the verdict; a push does not, because a
  red Pages run on a release's merge commit would refuse the tag.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[2]
PAGES = (REPO / ".github/workflows/pages.yml").read_text()
RELEASE = (REPO / ".github/workflows/release.yml").read_text()


def job(src, name):
    m = re.search(rf"(?m)^  {re.escape(name)}:\n", src)
    assert m, f"no `{name}` job"
    rest = src[m.end():]
    end = re.search(r"(?m)^  [a-z][a-z0-9-]*:\n", rest)
    return rest[: end.start()] if end else rest


def code(text):
    """The text without comment lines."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


# ── SUCCESS ────────────────────────────────────────────────────────────────

def test_success_the_build_writes_the_stamp_into_the_site():
    assert "python3 scripts/pages-live.py stamp --write website/static/deploy-stamp.txt" in job(PAGES, "build")


def test_success_the_stamp_is_written_before_the_site_is_built():
    assert PAGES.index("pages-live.py stamp --write") < PAGES.index("- name: Build site")


def test_success_a_live_job_reads_the_stamp_back_after_the_deploy():
    body = job(PAGES, "live")
    assert "needs: deploy" in body and "python3 scripts/pages-live.py verify" in body


def test_success_the_live_job_can_make_the_second_deploy():
    body = code(job(PAGES, "live"))
    for scope in ("pages: write", "id-token: write", "actions: read", "contents: read"):
        assert scope in body, scope
    assert re.search(r"environment:\n\s+name: github-pages", body)


def test_success_the_live_job_checks_out_the_script_it_runs():
    body = job(PAGES, "live")
    assert "actions/checkout@" in body and body.index("actions/checkout@") < body.index("pages-live.py verify")


def test_success_a_dispatch_enforces_the_verdict():
    body = job(PAGES, "live")
    assert "ENFORCE: ${{ github.event_name == 'workflow_dispatch' }}" in body
    assert re.search(r'if \[ "\$ENFORCE" = true \]; then\n\s+python3 scripts/pages-live\.py verify --expect "\$EXPECT" --enforce', body)


def test_success_the_expected_release_reaches_the_check():
    body = job(PAGES, "live")
    assert "EXPECT: ${{ inputs.expect }}" in body and '--expect "$EXPECT"' in body


def test_success_a_change_to_the_check_rebuilds_the_site():
    paths = PAGES[PAGES.index("    paths:"): PAGES.index("  workflow_dispatch:")]
    assert "- 'scripts/pages-live.py'" in paths


def test_success_a_change_to_the_release_check_it_runs_rebuilds_the_site():
    # pages-live.py runs verify-site-advertises.sh when a release is expected.
    paths = PAGES[PAGES.index("    paths:"): PAGES.index("  workflow_dispatch:")]
    assert "- 'scripts/verify-site-advertises.sh'" in paths


def test_success_the_release_run_says_what_a_failed_live_check_means():
    body = code(job(RELEASE, "advertise"))
    assert "gh run watch" in body and "--exit-status" in body
    failed = body[body.index("if ! gh run watch"):]
    assert "::error::" in failed and "pages-live.py" in failed and "stale" in failed and "exit 1" in failed


# ── FAILURE ────────────────────────────────────────────────────────────────

def test_failure_a_push_does_not_enforce_the_verdict():
    # tag-push-proof.py refuses a tag while a run on the merge commit is red.
    body = job(PAGES, "live")
    other = body[body.index("else\n"):]
    assert "pages-live.py verify" in other and "--enforce" not in other.split("fi\n")[0]


def test_failure_no_expression_is_expanded_inside_the_live_jobs_script():
    body = job(PAGES, "live")
    run = body[body.index("run: |"):]
    assert "${{" not in run


def test_failure_the_live_job_cannot_write_contents():
    assert "contents: write" not in job(PAGES, "live")


def test_failure_the_live_job_does_not_keep_the_token_in_the_checkout():
    assert "persist-credentials: false" in job(PAGES, "live")


def test_failure_the_csp_job_does_not_wait_for_the_live_check():
    # The CSP hashes come from the artifact; a page whose inline script
    # changed is blocked until they are refreshed.
    assert re.search(r"(?m)^    needs: deploy$", job(PAGES, "csp"))


def test_failure_the_deploy_job_still_deploys_through_the_action_first():
    body = code(job(PAGES, "deploy"))
    assert body.count("actions/deploy-pages@") == 2 and "pages-live.py" not in body


# ── EDGE ───────────────────────────────────────────────────────────────────

def test_edge_the_live_job_is_bounded():
    # 300 s for the stamp, 600 s for the second deploy's status, 300 s for the
    # stamp again and 300 s for the release: 25 minutes at the worst.
    m = re.search(r"timeout-minutes: (\d+)", job(PAGES, "live"))
    assert m and 25 < int(m.group(1)) <= 40


def test_edge_the_live_job_is_inside_the_pages_group_so_no_later_deploy_interleaves():
    assert re.search(r"(?m)^concurrency:\n  group: pages\n  cancel-in-progress: false", PAGES)
    assert "concurrency:" not in job(PAGES, "live")


def test_edge_the_live_job_has_the_token_gh_needs():
    assert "GH_TOKEN: ${{ github.token }}" in job(PAGES, "live")


def test_edge_the_advertise_jobs_wait_covers_the_live_job():
    # build 90 + deploy 25 + live: the release run must outlast the Pages run.
    live = int(re.search(r"timeout-minutes: (\d+)", job(PAGES, "live")).group(1))
    advertise = int(re.search(r"timeout-minutes: (\d+)", job(RELEASE, "advertise")).group(1))
    assert advertise >= 90 + 25 + live


def test_edge_the_stamp_file_is_not_committed():
    assert not (REPO / "website/static/deploy-stamp.txt").exists()
