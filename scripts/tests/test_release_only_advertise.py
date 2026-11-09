# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The advertisement commit a release pull request carries is release-only too.

RELEASE-FAST C removed the phase-two pull request. Its changes now ride in the
next release pull request as one commit made by `scripts/release-records.py
write <previous>`, before the version bump. If the hooks treated that commit
as ordinary work, the release pull request would run the whole suite in the
pre-commit and pre-push hooks again (29 minutes on 0.5.238), and the bump
commit's fast path would be lost for the whole range.

`classify_advertise` in scripts/release-only.py is the rule. A commit is an
advertisement when, and only when:

* the crate version does not change, and `published_version` moves forward to
  exactly the crate version;
* every changed file is one the writer touches (ADVERTISE_FILES), modified in
  place;
* every replaced line is the old line with the old advertised version, as a
  whole token, replaced by the new one, or `release_date` taking a real date;
* website/config.toml adds exactly one line, the new version's binary-ceiling
  measurement, and the eBPF ledger and its copies add exactly one row each,
  the new version's, and it attached.

The 0.5.239 phase-two commit 83bcb1083 is exactly such a commit, so it is the
fixture.
"""

import pathlib
import subprocess

from conftest import load

ro = load("release-only")

REPO = pathlib.Path(__file__).resolve().parents[2]
P, V = "0.5.238", "0.5.239"
CEIL = f"#   {V}  24,655,936 bytes   (+4,096, leaving 509,888 bytes of headroom under 24 MB)"
ROW = f"| {V} | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.115+deb13.1-amd64 | 2026-11-09 | attached, 2 libraries plus `tcp_sendmsg` |"


def mod(path, pairs=(), adds=()):
    return ro.FileChange(path=path, kind="modify", pairs=list(pairs), adds=list(adds))


def adv(*extra, config_adds=(CEIL,)):
    return [
        mod("website/config.toml", [(f'published_version = "{P}"', f'published_version = "{V}"')], config_adds),
        mod("docs/install.md", [(f"VERSION={P}", f"VERSION={V}")]),
        mod("docs/internals/uprobe-capture.md", adds=[ROW]),
        *extra,
    ]


def classify(changes, crate_old=V, crate_new=V, pub_old=P, pub_new=V):
    return ro.classify_advertise(changes, crate_old, crate_new, pub_old, pub_new)


def git_show(sha):
    out = subprocess.run(
        ["git", "-C", str(REPO), "show", "-U0", "--format=", "--no-color", "--no-ext-diff", "--no-renames",
         "--full-index", sha],
        capture_output=True, text=True, check=False,
    )
    assert out.returncode == 0, f"this test replays {sha} from the repository's history: {out.stderr}"
    return out.stdout


# ── SUCCESS ────────────────────────────────────────────────────────────────

def test_the_real_0_5_239_phase_two_commit_is_an_advertisement():
    verdict = classify(ro.parse_diff(git_show("83bcb1083")))
    assert verdict.ok, verdict.line


def test_a_minimal_advertisement_is_release_only():
    assert classify(adv()).ok


def test_the_verdict_names_both_advertised_versions():
    line = classify(adv()).line
    assert P in line and V in line and "advertises" in line


def test_the_release_date_may_take_a_new_date():
    extra = mod("website/config.toml", [(f'published_version = "{P}"', f'published_version = "{V}"'),
                                        ('release_date = "2026-11-08"', 'release_date = "2026-11-09"')], [CEIL])
    changes = [extra] + adv()[1:]
    assert classify(changes).ok


def test_a_pure_add_hunk_is_read_as_added_lines():
    diff = (
        "diff --git a/docs/internals/uprobe-capture.md b/docs/internals/uprobe-capture.md\n"
        "index 1111111111111111111111111111111111111111..2222222222222222222222222222222222222222 100644\n"
        "--- a/docs/internals/uprobe-capture.md\n+++ b/docs/internals/uprobe-capture.md\n"
        f"@@ -10,0 +11 @@\n+{ROW}\n"
    )
    [c] = ro.parse_diff(diff)
    assert (c.kind, c.pairs, c.adds) == ("modify", [], [ROW])


def test_a_range_of_an_advertisement_then_a_bump_is_release_only():
    bump = [ro.FileChange("Cargo.toml", "modify", [('version = "0.5.239"', 'version = "0.5.240"')]),
            ro.FileChange("CHANGELOG.md", "modify", [("## [Unreleased]", "## [0.5.240] - 2026-11-10")])]
    commits = [ro.Commit("a" * 40, 1, adv(), V, V, P, V), ro.Commit("b" * 40, 1, bump, V, "0.5.240", V, V)]
    verdict = ro.classify_range(commits)
    assert verdict.ok, verdict.line


def test_the_mirror_and_llms_copies_may_carry_the_same_lines():
    extra = (mod("website/content/docs/install.md", [(f"VERSION={P}", f"VERSION={V}")]),
             mod("website/content/docs/internals/uprobe-capture.md", adds=[ROW]),
             mod("website/static/llms-full.txt", [(f"VERSION={P}", f"VERSION={V}")], [ROW]))
    assert classify(adv(*extra)).ok


# ── FAILURE ────────────────────────────────────────────────────────────────

def test_a_crate_version_change_is_not_an_advertisement():
    assert not classify(adv(), crate_new="0.5.240").ok


def test_advertising_a_version_other_than_the_crate_is_not():
    v = classify(adv(), pub_new="0.5.237")
    assert not v.ok and "0.5.237" in v.line


def test_published_version_that_does_not_move_is_not():
    assert not classify(adv(), pub_old=V).ok


def test_a_file_the_writer_does_not_touch_is_named_and_refused():
    v = classify(adv(mod("src/main.rs", [("a", "b")])))
    assert not v.ok and "src/main.rs" in v.line


def test_a_line_changing_more_than_the_advertised_version_is_not():
    v = classify(adv(mod("website/content/docs/install.md", [(f"VERSION={P}", f"VERSION={V} # edited")])))
    assert not v.ok and "edited" in v.line


def test_two_ceiling_lines_are_not():
    assert not classify(adv(config_adds=(CEIL, CEIL))).ok


def test_a_ceiling_line_for_another_version_is_not():
    assert not classify(adv(config_adds=(CEIL.replace(V, "0.5.240", 1),))).ok


def test_no_ceiling_line_is_not():
    v = classify(adv(config_adds=()))
    assert not v.ok and "ceiling" in v.line


def test_a_ledger_row_that_did_not_attach_is_not():
    changes = adv()
    changes[2] = mod("docs/internals/uprobe-capture.md", adds=[ROW.replace("attached", "rejected")])
    assert not classify(changes).ok


def test_a_ledger_without_its_row_is_not():
    v = classify(adv()[:2])
    assert not v.ok and "uprobe" in v.line


def test_an_added_file_is_not():
    changes = adv(ro.FileChange("docs/new.md", "add", []))
    assert not classify(changes).ok


def test_a_bump_commit_with_an_added_line_is_still_not_a_bump():
    # The bump rule must not inherit the advertisement's adds.
    changes = [ro.FileChange("Cargo.toml", "modify", [('version = "0.5.239"', 'version = "0.5.240"')], ["x"]),
               ro.FileChange("CHANGELOG.md", "modify", [("## [Unreleased]", "## [0.5.240] - 2026-11-10")])]
    assert not ro.classify(changes, V, "0.5.240").ok


# ── EDGE ───────────────────────────────────────────────────────────────────

def test_an_unreadable_diff_is_not():
    assert not classify(None).ok


def test_a_release_date_that_is_not_a_date_is_not():
    cfg = mod("website/config.toml", [(f'published_version = "{P}"', f'published_version = "{V}"'),
                                      ('release_date = "2026-11-08"', 'release_date = "2026-13-40"')], [CEIL])
    assert not classify([cfg] + adv()[1:]).ok


def test_an_old_version_inside_a_longer_number_is_not_a_token():
    v = classify(adv(mod("website/content/docs/install.md", [(f"VERSION={P}0", f"VERSION={V}0")])))
    assert not v.ok


def test_published_version_moving_backwards_is_not():
    assert not classify(adv(), pub_old="0.5.240", pub_new=V).ok


def test_a_removed_line_without_a_replacement_is_not():
    # parse_diff reads a pure-delete hunk as a reshape.
    diff = (
        "diff --git a/docs/install.md b/docs/install.md\n"
        "index 1111111111111111111111111111111111111111..2222222222222222222222222222222222222222 100644\n"
        "--- a/docs/install.md\n+++ b/docs/install.md\n"
        "@@ -10 +9,0 @@\n-gone\n"
    )
    assert not classify(adv()[:1] + ro.parse_diff(diff) + adv()[2:]).ok


def test_the_hooks_list_the_record_gates_among_the_release_tests():
    assert {"release_gate_visibility_test", "bpf_load_verification_test"} <= set(ro.RELEASE_TESTS)


def test_advertising_forward_to_a_release_below_the_crate_version_is_not():
    # 0.5.238 -> 0.5.239 is forward, but the tree is 0.5.240: the commit
    # would advertise a release older than the one this tree is.
    v = classify(adv(), crate_old="0.5.240", crate_new="0.5.240")
    assert not v.ok and "0.5.240" in v.line
