# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""release.yml advertises the release itself, and records what phase two typed.

RELEASE-FAST C. After the `release` job publishes the assets:

* `advertise` dispatches pages.yml on main with `expect` set to the tag's
  version and waits for that run, so the release run fails when the site
  cannot advertise the release (an incomplete asset set, a failed build);
* pages.yml runs `scripts/advertise-release.py site` before `zola build`, on
  every deploy, so a later push to main cannot put the site back on the
  previous release;
* `records` measures the published x86_64-musl binary with
  `scripts/release-records.py ceiling` and uploads the `release-records`
  artifact the next release pull request's advertisement commit reads;
* `tap` bumps the Homebrew tap through the GitHub API with
  scripts/homebrew-tap-push.py, which moves the tap's main only to a commit
  GitHub reports as verified (HOMEBREW-TAP-UNSIGNED).

The jobs cannot run outside a real tag push, so these tests hold the
workflow text to that shape; the scripts' behavior is tested in their own
files.
"""

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
RELEASE = (REPO / ".github/workflows/release.yml").read_text()
PAGES = (REPO / ".github/workflows/pages.yml").read_text()


def job(src, name):
    m = re.search(rf"(?m)^  {re.escape(name)}:\n", src)
    assert m, f"no `{name}` job"
    rest = src[m.end():]
    end = re.search(r"(?m)^  [a-z][a-z0-9-]*:\n", rest)
    return rest[: end.start()] if end else rest


def step(src, name):
    i = src.index(f"- name: {name}")
    rest = src[i + 1:]
    j = rest.find("\n      - ")
    return src[i: i + 1 + (j if j >= 0 else len(rest))]


# ── SUCCESS ────────────────────────────────────────────────────────────────

def test_advertise_runs_after_the_assets_publish_on_a_tag_push():
    body = job(RELEASE, "advertise")
    assert "needs: release" in body
    assert "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')" in body


def test_advertise_dispatches_pages_on_main_expecting_the_tag():
    body = job(RELEASE, "advertise")
    assert "gh workflow run pages.yml" in body and "--ref main" in body
    assert '-f expect="$version"' in body


def test_advertise_waits_for_the_dispatched_run_and_fails_with_it():
    body = job(RELEASE, "advertise")
    assert "gh run watch" in body and "--exit-status" in body


def test_pages_advertises_before_the_site_is_built():
    i = PAGES.index("python3 scripts/advertise-release.py site")
    assert i < PAGES.index("- name: Build site")


def test_records_measures_the_published_tarball_and_uploads_the_line():
    body = job(RELEASE, "records")
    assert "needs: release" in body
    assert "scripts/release-records.py ceiling" in body
    assert "x86_64-unknown-linux-musl.tar.gz" in body and "SHA256SUMS.txt" in body
    assert "name: release-records" in body


def test_the_tap_is_bumped_through_the_api_script():
    body = job(RELEASE, "tap")
    assert "python3 scripts/homebrew-tap-push.py" in body


def test_pages_takes_expect_as_a_dispatch_input():
    assert re.search(r"(?m)^      expect:\n", PAGES)


# ── FAILURE ────────────────────────────────────────────────────────────────

def test_the_tap_job_never_pushes_a_local_commit():
    body = job(RELEASE, "tap")
    assert "git push" not in body and "git commit" not in body


def test_the_expect_input_reaches_the_script_through_the_environment_not_the_shell():
    # ${{ }} expanded inside `run:` would be a script injection.
    body = step(PAGES, "Advertise the newest complete release")
    run = body[body.index("run:"):]
    assert "${{" not in run
    assert "EXPECT: ${{ inputs.expect }}" in body


def test_advertise_holds_only_the_scopes_it_needs():
    body = job(RELEASE, "advertise")
    assert "actions: write" in body and "contents: read" in body
    assert "contents: write" not in body and "pages: write" not in body


def test_a_dispatch_without_expect_still_resolves_rather_than_skipping():
    body = step(PAGES, "Advertise the newest complete release")
    assert 'if [ -n "${EXPECT:-}" ]' in body
    assert body.count("advertise-release.py site") == 2


def test_the_records_job_verifies_before_it_measures():
    # The checksum check is inside release-records.py; the job must hand it
    # the published SHA256SUMS.txt rather than one it computed.
    body = job(RELEASE, "records")
    assert "gh release download" in body and "--sums SHA256SUMS.txt" in body
    assert "sha256sum" not in body


# ── EDGE ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "scripts/advertise-release.py",
    "scripts/download-markers.txt",
    "scripts/build-site-pages.py",
])
def test_a_change_to_what_pages_runs_rebuilds_the_site(path):
    paths = PAGES[PAGES.index("    paths:"): PAGES.index("  workflow_dispatch:")]
    assert f"- '{path}'" in paths


def test_advertise_bounds_its_wait():
    body = job(RELEASE, "advertise")
    assert re.search(r"timeout-minutes: \d+", body)


def test_advertise_finds_only_a_run_created_after_its_dispatch():
    body = job(RELEASE, "advertise")
    assert "createdAt" in body and "since" in body


def test_workflow_dispatch_of_release_never_advertises_or_records():
    for name in ("advertise", "records"):
        assert "github.event_name == 'push'" in job(RELEASE, name)


def test_the_daily_watcher_expects_the_release_the_deploy_rule_resolves():
    # The committed published_version lags the site by one release between
    # release pull requests, so the watcher must ask the same rule pages.yml
    # applies, or it reports a correct site as stale every day.
    wf = (REPO / ".github/workflows/cert-expiry.yml").read_text()
    body = step(wf, "The site advertises the release it claims to")
    assert "python3 scripts/advertise-release.py resolve" in body
    assert "GH_TOKEN: ${{ github.token }}" in body
    assert "sed -n 's/^published_version" not in body
