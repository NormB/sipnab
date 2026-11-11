# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Which release the site advertises, and the one writer that moves it.

RELEASE-FAST C removes the phase-two pull request. The site no longer waits
for a commit that moves `published_version`: pages.yml asks GitHub which
release is complete and rewrites the advertised version and the download
markers in its own checkout, with scripts/advertise-release.py. The same
writer makes the advertisement commit that the next release pull request
carries, so the committed tree and the built site cannot follow two rules.

GitHub is not reachable from a test, so the resolution is tested as a pure
function over the shape `gh api repos/OWNER/NAME/releases` returns.
"""

import pathlib
import subprocess
import sys

import pytest
from conftest import load

ad = load("advertise-release")

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/advertise-release.py"

NAMES = [
    "SHA256SUMS.txt",
    "SHA256SUMS.txt.sigstore.json",
    "sipnab-{v}-x86_64-unknown-linux-musl.tar.gz",
    "sipnab-{v}-x86_64-unknown-linux-musl.tar.gz.sha256",
    "sipnab_{v}_amd64.deb",
    "sipnab-{v}.intoto.jsonl",
]


def rel(v, names=None, draft=False, pre=False, state="uploaded", tag=None):
    return {
        "tag_name": tag or f"v{v}",
        "draft": draft,
        "prerelease": pre,
        "assets": [{"name": n.format(v=v), "state": state} for n in (names or NAMES)],
    }


# ── resolution: SUCCESS ────────────────────────────────────────────────────

def test_the_newest_complete_release_is_advertised():
    v, _ = ad.newest_to_advertise([rel("0.5.239"), rel("0.5.240"), rel("0.5.238")], "0.5.240")
    assert v == "0.5.240"


def test_versions_compare_as_numbers_not_strings():
    # String order puts 0.5.9 after 0.5.10.
    v, _ = ad.newest_to_advertise([rel("0.5.9"), rel("0.5.10")], "0.5.10")
    assert v == "0.5.10"


def test_a_release_that_adds_an_asset_is_still_complete():
    more = NAMES + ["sipnab-{v}-riscv64.tar.gz"]
    v, _ = ad.newest_to_advertise([rel("0.5.239"), rel("0.5.240", more)], "0.5.240")
    assert v == "0.5.240"


def test_the_reason_names_the_release_and_its_asset_count():
    _, why = ad.newest_to_advertise([rel("0.5.239"), rel("0.5.240")], "0.5.240")
    assert "v0.5.240" in why and str(len(NAMES)) in why


# ── resolution: FAILURE (falls back, or refuses) ───────────────────────────

def test_a_draft_is_never_advertised():
    v, _ = ad.newest_to_advertise([rel("0.5.239"), rel("0.5.240", draft=True)], "0.5.240")
    assert v == "0.5.239"


def test_a_prerelease_is_never_advertised_which_is_how_a_release_is_withdrawn():
    v, _ = ad.newest_to_advertise([rel("0.5.239"), rel("0.5.240", pre=True)], "0.5.240")
    assert v == "0.5.239"


def test_a_release_missing_an_asset_its_predecessor_had_is_not_advertised():
    fewer = [n for n in NAMES if not n.endswith(".deb")]
    v, why = ad.newest_to_advertise([rel("0.5.239"), rel("0.5.240", fewer)], "0.5.240")
    assert v == "0.5.239"
    assert "sipnab_<v>_amd64.deb" in why


def test_an_asset_still_uploading_does_not_count():
    r = rel("0.5.240")
    r["assets"][4]["state"] = "open"
    v, _ = ad.newest_to_advertise([rel("0.5.239"), r], "0.5.240")
    assert v == "0.5.239"


def test_a_release_newer_than_the_tree_is_not_advertised_by_it():
    v, _ = ad.newest_to_advertise([rel("0.5.239"), rel("0.5.241")], "0.5.240")
    assert v == "0.5.239"


def test_no_complete_release_at_all_is_a_refusal():
    with pytest.raises(ad.AdvertiseError, match="no complete release"):
        ad.newest_to_advertise([rel("0.5.240", draft=True)], "0.5.240")


def test_the_oldest_release_without_its_checksum_signature_is_incomplete():
    # With no predecessor to compare against, the release must still carry
    # the checksum list and its signature.
    with pytest.raises(ad.AdvertiseError):
        ad.newest_to_advertise([rel("0.5.240", ["SHA256SUMS.txt"])], "0.5.240")


def test_expect_refuses_when_the_named_release_is_not_the_one_resolved():
    with pytest.raises(ad.AdvertiseError, match="0.5.240"):
        ad.check_expected("0.5.239", "0.5.240", "v0.5.240 lacks sipnab_<v>_amd64.deb")


# ── resolution: EDGE ───────────────────────────────────────────────────────

def test_a_tag_that_is_not_x_y_z_is_ignored():
    v, _ = ad.newest_to_advertise([rel("0.5.239"), rel("0.5.240", tag="nightly")], "0.5.240")
    assert v == "0.5.239"


def test_a_complete_release_is_compared_with_the_newest_older_complete_one():
    # 0.5.239 is a draft and lacks the .deb; 0.5.240 is judged against 0.5.238.
    fewer = [n for n in NAMES if not n.endswith(".deb")]
    rs = [rel("0.5.238"), rel("0.5.239", fewer, draft=True), rel("0.5.240")]
    assert ad.newest_to_advertise(rs, "0.5.240")[0] == "0.5.240"


def test_the_crate_version_itself_may_be_advertised_once_complete():
    assert ad.newest_to_advertise([rel("0.5.240")], "0.5.240")[0] == "0.5.240"


def test_expect_accepts_the_resolved_release():
    ad.check_expected("0.5.240", "0.5.240", "ok")


# ── the writer: SUCCESS ────────────────────────────────────────────────────

CONFIG = '''version = "0.5.241"
# comment naming 0.5.239 stays
published_version = "0.5.239"
release_date = "2026-11-08"
'''

CHANGELOG = """# Changelog

## [Unreleased]

## [0.5.240] - 2026-11-09

## [0.5.239] - 2026-11-08
"""

MARKERS = ad.load_markers((REPO / "scripts/download-markers.txt").read_text())


def test_the_config_moves_the_advertised_version_and_its_date():
    out = ad.move_config(CONFIG, "0.5.240", "2026-11-09")
    assert 'published_version = "0.5.240"' in out
    assert 'release_date = "2026-11-09"' in out
    assert 'version = "0.5.241"' in out
    assert "comment naming 0.5.239 stays" in out


def test_the_release_date_comes_from_the_changelog_heading():
    assert ad.release_date(CHANGELOG, "0.5.240") == "2026-11-09"


def test_every_download_marker_in_the_real_install_page_moves():
    text = (REPO / "docs/install.md").read_text()
    old = ad.published_version((REPO / "website/config.toml").read_text())
    out, moved = ad.move_markers(text, MARKERS, old, "9.9.9")
    # The page's marker lines, and nothing else, now name 9.9.9.
    changed = [b for a, b in zip(text.splitlines(), out.splitlines()) if a != b]
    # The floor is the count of marker lines in the page. FEWER means a marker
    # stopped matching, or a line that named the release was removed: say
    # which before lowering it.
    # 20 -> 18 (OPS-4): the container section's live-capture commands no
    # longer name a release. Two lines went, `docker run --rm --net=host
    # --user root ghcr.io/normb/sipnab:<version> -N -d eth0` and the sentence
    # with `docker image inspect ghcr.io/normb/sipnab:<version>`. The section
    # that replaced them takes the image from `$TAG`, because no release up
    # to 0.5.245 holds the fix it describes.
    assert moved == len(changed) >= 18
    assert all("9.9.9" in line and old not in line for line in changed)


def test_the_crate_version_sample_does_not_move():
    text = "sipnab 0.5.239 (<hash>) features: native\nSIPNAB_VERSION=0.5.239 sh\n"
    out, moved = ad.move_markers(text, [ad.re.compile(r"SIPNAB_VERSION=(\d+\.\d+\.\d+)")], "0.5.239", "0.5.240")
    assert moved == 1
    assert out.splitlines()[0] == "sipnab 0.5.239 (<hash>) features: native"


def test_an_indented_version_line_is_a_marker_too():
    version_line = [m for m in MARKERS if "^ *VERSION=" in m.pattern]
    assert len(version_line) == 1
    out, moved = ad.move_markers("   VERSION=0.5.239\n", version_line, "0.5.239", "0.5.240")
    assert (out, moved) == ("   VERSION=0.5.240\n", 1)


# ── the writer: FAILURE ────────────────────────────────────────────────────

def test_a_version_with_no_changelog_heading_is_refused():
    with pytest.raises(ad.AdvertiseError, match="0.5.250"):
        ad.release_date(CHANGELOG, "0.5.250")


def test_a_config_without_published_version_is_refused():
    with pytest.raises(ad.AdvertiseError, match="published_version"):
        ad.move_config('version = "1.0.0"\nrelease_date = "2026-01-01"\n', "1.0.0", "2026-01-01")


def test_a_config_without_release_date_is_refused():
    with pytest.raises(ad.AdvertiseError, match="release_date"):
        ad.move_config('published_version = "1.0.0"\n', "1.0.0", "2026-01-01")


def test_a_marker_that_no_longer_matches_the_page_is_refused():
    pats = [ad.re.compile(r"SIPNAB_VERSION=(\d+\.\d+\.\d+)"), ad.re.compile(r"gone:(\d+\.\d+\.\d+)")]
    with pytest.raises(ad.AdvertiseError, match="gone"):
        ad.move_markers("SIPNAB_VERSION=0.5.239\n", pats, "0.5.239", "0.5.240")


def test_a_marker_naming_a_third_version_is_refused():
    # The page disagrees with itself; moving the rest would hide that.
    pats = [ad.re.compile(r"SIPNAB_VERSION=(\d+\.\d+\.\d+)")]
    with pytest.raises(ad.AdvertiseError, match="0.5.100"):
        ad.move_markers("SIPNAB_VERSION=0.5.239\nSIPNAB_VERSION=0.5.100\n", pats, "0.5.239", "0.5.240")


def test_a_marker_file_line_without_one_capture_group_is_refused():
    with pytest.raises(ad.AdvertiseError, match="capture group"):
        ad.load_markers(r"SIPNAB_VERSION=\d+" + "\n")


def test_a_version_that_is_not_x_y_z_is_refused_by_the_cli():
    out = subprocess.run([sys.executable, str(SCRIPT), "write", "v0.5.240", "--root", str(REPO)],
                         capture_output=True, text=True)
    assert out.returncode == 1 and "x.y.z" in out.stderr


# ── the writer: EDGE ───────────────────────────────────────────────────────

def test_moving_to_the_version_already_advertised_changes_nothing():
    text = "SIPNAB_VERSION=0.5.239 sh\n"
    out, moved = ad.move_markers(text, [ad.re.compile(r"SIPNAB_VERSION=(\d+\.\d+\.\d+)")], "0.5.239", "0.5.239")
    assert (out, moved) == (text, 0)


def test_two_markers_on_one_line_both_move():
    pat = [ad.re.compile(r"ghcr\.io/normb/sipnab:(\d+\.\d+\.\d+)")]
    out, moved = ad.move_markers("a ghcr.io/normb/sipnab:0.5.239 b ghcr.io/normb/sipnab:0.5.239\n", pat,
                                 "0.5.239", "0.5.240")
    assert moved == 2 and out.count("0.5.240") == 2


def test_a_longer_version_containing_the_old_one_is_not_a_match():
    pat = [ad.re.compile(r"SIPNAB_VERSION=(\d+\.\d+\.\d+)")]
    with pytest.raises(ad.AdvertiseError, match="0.5.2390"):
        ad.move_markers("SIPNAB_VERSION=0.5.2390\n", pat, "0.5.239", "0.5.240")


def test_comment_and_blank_lines_in_the_marker_file_are_skipped():
    assert len(ad.load_markers("# a comment\n\nSIPNAB_VERSION=(\\d+\\.\\d+\\.\\d+)\n")) == 1


def test_the_shared_marker_file_is_the_one_the_rust_gate_reads():
    # One rule: tests/docs_drift_test.rs reads the same file, so the writer
    # cannot move a set of lines the gate does not check.
    src = (REPO / "tests/docs_drift_test.rs").read_text()
    assert 'include_str!("../scripts/download-markers.txt")' in src
