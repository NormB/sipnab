# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""A commit that is exactly a release bump runs the release gates, not the suite.

The 0.5.238 release commit f151b38d8 spent 14 minutes in the pre-commit hook
and 15 in the pre-push hook running the whole suite and every tree gate, on a
diff of 24 changed lines: the version moving from 0.5.237 to 0.5.238 in 13
files, and the CHANGELOG heading `## [Unreleased]` becoming
`## [0.5.238] - 2026-11-08`. PR CI then ran the whole suite again (33 min).

scripts/release-only.py's `classify` is the one rule. A change is release-only
when, and only when:

* the crate version in Cargo.toml's [package] moves forward (x.y.z to a larger
  x.y.z);
* every changed file is modified in place (no file added, deleted, renamed,
  binary or with a new mode) and is a file a release bump touches;
* every changed line is the line before it with the old version replaced by
  the new one (whole version tokens only), or, in the CLI reference and its
  copies, a Since cell `| Unreleased |` becoming `| <new> |`;
* website/config.toml changes `version = "<old>"` alone, never
  `published_version` (that moves only once the assets exist);
* CHANGELOG.md changes exactly one line, `## [Unreleased]` to
  `## [<new>] - YYYY-MM-DD`, a real date.

Anything else, including anything the rule cannot read, is not release-only,
and the full gates run.
"""

import pathlib
import subprocess

import pytest
from conftest import load

ro = load("release-only")

REPO = pathlib.Path(__file__).resolve().parents[2]
OLD, NEW = "0.5.237", "0.5.238"


def mod(path, *pairs):
    return ro.FileChange(path=path, kind="modify", pairs=list(pairs))


def v(old=OLD, new=NEW):
    return (f'version = "{old}"', f'version = "{new}"')


HEADING = ("## [Unreleased]", f"## [{NEW}] - 2026-11-08")


def bump(*extra):
    return [mod("Cargo.toml", v()), mod("Cargo.lock", v()), mod("CHANGELOG.md", HEADING), *extra]


def classify(changes, old=OLD, new=NEW):
    return ro.classify(changes, old, new)


def git_show(sha):
    out = subprocess.run(
        ["git", "-C", str(REPO), "show", "-U0", "--format=", "--no-color", "--no-ext-diff", "--no-renames",
         "--full-index", sha],
        capture_output=True, text=True, check=False,
    )
    assert out.returncode == 0, f"this test replays {sha} from the repository's history: {out.stderr}"
    return out.stdout


# ── SUCCESS ────────────────────────────────────────────────────────────────


def test_the_real_0_5_238_release_commit_is_release_only():
    changes = ro.parse_diff(git_show("f151b38d8"))
    verdict = classify(changes)
    assert verdict.ok, verdict.line


def test_a_minimal_bump_is_release_only():
    assert classify(bump()).ok


def test_the_line_names_both_versions_and_the_file_count():
    line = classify(bump()).line
    assert OLD in line and NEW in line and "3 files" in line, line


def test_a_since_cell_in_the_cli_reference_may_move_to_the_new_version():
    row = ("| `--x` | -- | -- | Unreleased | Does x. |", f"| `--x` | -- | -- | {NEW} | Does x. |")
    assert classify(bump(mod("docs/cli-reference.md", row))).ok


def test_a_since_cell_in_the_site_copy_of_the_cli_reference_may_move():
    row = ("| `--x` | Unreleased | x |", f"| `--x` | {NEW} | x |")
    assert classify(bump(mod("website/content/docs/cli.md", row), mod("website/static/llms-full.txt", row))).ok


def test_the_man_page_heading_may_move():
    th = (f'.TH SIPNAB 1 "2026-10-13" "sipnab {OLD}" "User Commands"',
          f'.TH SIPNAB 1 "2026-10-13" "sipnab {NEW}" "User Commands"')
    assert classify(bump(mod("man/sipnab.1", th))).ok


def test_the_site_crate_version_may_move():
    assert classify(bump(mod("website/config.toml", v()))).ok


def test_a_docs_sample_naming_the_version_may_move():
    sample = (f"sipnab {OLD} (<hash>) features: native", f"sipnab {NEW} (<hash>) features: native")
    assert classify(bump(mod("docs/install.md", sample), mod("website/content/docs/install.md", sample))).ok


def test_a_line_naming_the_version_twice_moves_both():
    line = (f'"{OLD}" and "{OLD}"', f'"{NEW}" and "{NEW}"')
    assert classify(bump(mod("docs/mcp-deploy.md", line))).ok


def test_a_minor_bump_is_release_only():
    changes = [mod("Cargo.toml", v(OLD, "0.6.0")), mod("CHANGELOG.md", ("## [Unreleased]", "## [0.6.0] - 2026-11-08"))]
    assert ro.classify(changes, OLD, "0.6.0").ok


def test_the_package_version_is_read_from_the_package_table():
    text = '[workspace]\nmembers = ["x"]\n\n[package]\nname = "sipnab"\nversion = "0.5.238"\n\n[dependencies]\nfoo = { version = "1.2.3" }\n'
    assert ro.package_version(text) == "0.5.238"


def test_a_zero_context_diff_is_read_into_line_pairs():
    text = (
        "diff --git a/Cargo.toml b/Cargo.toml\nindex 1111111..2222222 100644\n--- a/Cargo.toml\n+++ b/Cargo.toml\n"
        "@@ -53 +53 @@ name = \"sipnab\"\n-version = \"0.5.237\"\n+version = \"0.5.238\"\n"
        "@@ -60,2 +60,2 @@\n-a 0.5.237\n-b 0.5.237\n+a 0.5.238\n+b 0.5.238\n"
    )
    assert ro.parse_diff(text) == [mod("Cargo.toml", v(), ("a 0.5.237", "a 0.5.238"), ("b 0.5.237", "b 0.5.238"))]


def test_a_nested_docs_page_may_carry_the_version():
    line = (f"sipnab {OLD}", f"sipnab {NEW}")
    assert classify(bump(mod("docs/internals/x.md", line))).ok


# ── FAILURE: anything outside the exact set means the full gates ───────────


def test_the_real_0_5_237_release_commit_which_removed_a_held_line_is_not():
    verdict = ro.classify(ro.parse_diff(git_show("8ae7313e2")), "0.5.236", "0.5.237")
    assert not verdict.ok and "CHANGELOG.md" in verdict.line, verdict.line


def test_a_rust_source_change_is_not_release_only_and_is_named():
    verdict = classify(bump(mod("src/main.rs", ("let a = 1;", "let a = 2;"))))
    assert not verdict.ok and "src/main.rs" in verdict.line, verdict.line


def test_a_version_in_a_rust_file_is_not_a_release_bump():
    assert not classify(bump(mod("src/version.rs", (f'"{OLD}"', f'"{NEW}"')))).ok


def test_a_changelog_entry_edited_beside_the_heading_is_not_release_only():
    changes = bump(mod("CHANGELOG.md", HEADING, ("- old text", "- new text")))
    changes = [c for c in changes if not (c.path == "CHANGELOG.md" and len(c.pairs) == 1)]
    assert not classify(changes).ok


def test_a_changelog_heading_naming_another_version_is_not():
    changes = [mod("Cargo.toml", v()), mod("CHANGELOG.md", ("## [Unreleased]", "## [0.5.239] - 2026-11-08"))]
    assert not classify(changes).ok


def test_a_changelog_heading_with_an_impossible_date_is_not():
    changes = [mod("Cargo.toml", v()), mod("CHANGELOG.md", ("## [Unreleased]", f"## [{NEW}] - 2026-13-40"))]
    assert not classify(changes).ok


def test_a_version_that_does_not_move_is_not_a_release():
    assert not ro.classify(bump(), OLD, OLD).ok


def test_a_version_that_moves_backwards_is_not_a_release():
    changes = [mod("Cargo.toml", v(NEW, OLD)), mod("CHANGELOG.md", ("## [Unreleased]", f"## [{OLD}] - 2026-11-08"))]
    verdict = ro.classify(changes, NEW, OLD)
    assert not verdict.ok and "forward" in verdict.line, verdict.line


def test_docs_alone_without_the_cargo_bump_is_not_a_release():
    sample = (f"sipnab {OLD}", f"sipnab {NEW}")
    assert not classify([mod("docs/install.md", sample), mod("CHANGELOG.md", HEADING)]).ok


def test_a_bump_without_the_changelog_heading_is_not_a_release():
    assert not classify([mod("Cargo.toml", v()), mod("Cargo.lock", v())]).ok


def test_a_line_that_changes_more_than_the_version_is_not():
    verdict = classify(bump(mod("docs/install.md", (f"sipnab {OLD} old", f"sipnab {NEW} new"))))
    assert not verdict.ok and "docs/install.md" in verdict.line, verdict.line


def test_published_version_does_not_move_in_a_release_commit():
    pv = (f'published_version = "{OLD}"', f'published_version = "{NEW}"')
    verdict = classify(bump(mod("website/config.toml", pv)))
    assert not verdict.ok and "website/config.toml" in verdict.line, verdict.line


def test_an_added_file_is_not_release_only():
    assert not classify(bump(ro.FileChange("docs/new.md", "add", []))).ok


def test_a_deleted_file_is_not_release_only():
    assert not classify(bump(ro.FileChange("docs/old.md", "delete", []))).ok


def test_a_binary_change_is_not_release_only():
    assert not classify(bump(ro.FileChange("website/static/logo.png", "binary", []))).ok


def test_a_mode_change_is_not_release_only():
    assert not classify(bump(ro.FileChange("scripts/x.sh", "mode", []))).ok


def test_a_hunk_that_adds_a_line_is_not_release_only():
    text = (
        "diff --git a/docs/install.md b/docs/install.md\nindex 1111111..2222222 100644\n--- a/docs/install.md\n"
        "+++ b/docs/install.md\n@@ -5 +5,2 @@\n-sipnab 0.5.237\n+sipnab 0.5.238\n+an extra line\n"
    )
    changes = ro.parse_diff(text)
    verdict = classify(bump(*changes))
    assert not verdict.ok and "docs/install.md adds or removes lines" in verdict.line, verdict.line


def test_a_dependency_line_in_cargo_toml_that_moves_otherwise_is_not():
    assert not classify(bump(mod("Cargo.toml", ('foo = "1.0"', 'foo = "1.1"')))).ok


def test_a_diff_that_cannot_be_read_is_none():
    assert ro.parse_diff("@@ -1 +1 @@\n-x\n+y\n") is None


def test_no_changes_read_is_not_release_only():
    assert not classify(None).ok


# ── EDGE ───────────────────────────────────────────────────────────────────


def test_a_longer_version_containing_the_old_one_is_not_the_old_one():
    verdict = classify(bump(mod("docs/install.md", ("lib 10.5.2370", "lib 10.5.2380"))))
    assert not verdict.ok, verdict.line


def test_a_tag_name_is_not_a_version_marker():
    # `v0.5.237` names a tag, which a release commit does not move.
    assert not classify(bump(mod("docs/internals/x.md", (f"v{OLD}", f"v{NEW}")))).ok


def test_unreleased_moves_only_in_the_cli_reference_and_its_copies():
    row = ("| `--x` | Unreleased |", f"| `--x` | {NEW} |")
    assert not classify(bump(mod("docs/tuning-capture.md", row))).ok


def test_unreleased_in_prose_is_not_a_since_cell():
    prose = ("Flags marked Unreleased are new.", f"Flags marked {NEW} are new.")
    assert not classify(bump(mod("docs/cli-reference.md", prose))).ok


def test_an_empty_change_is_not_a_release():
    assert not classify([]).ok


@pytest.mark.parametrize("bad", ["0.5.238-rc1", "0.5", "v0.5.238", "", None])
def test_a_version_that_is_not_x_y_z_is_not_a_release(bad):
    assert not ro.classify(bump(), OLD, bad).ok


def test_a_manifest_with_no_package_version_has_none():
    assert ro.package_version('[workspace]\nmembers = ["x"]\n') is None


def test_a_file_outside_the_bump_set_is_not_release_only_whatever_it_says():
    assert not classify(bump(mod("docs/notes.txt", (f"v{OLD}", f"v{NEW}")))).ok


def test_the_changelog_heading_twice_is_not_release_only():
    assert not classify([mod("Cargo.toml", v()), mod("CHANGELOG.md", HEADING, HEADING)]).ok


def test_a_heading_with_trailing_text_is_not_the_release_heading():
    changes = [mod("Cargo.toml", v()), mod("CHANGELOG.md", ("## [Unreleased]", f"## [{NEW}] - 2026-11-08 (held)"))]
    assert not classify(changes).ok


def test_a_rename_is_not_release_only():
    assert not classify(bump(ro.FileChange("docs/b.md", "rename", []))).ok


def test_a_range_of_release_only_commits_is_release_only():
    good = ro.Commit("a" * 40, 1, bump(), OLD, NEW)
    verdict = ro.classify_range([good])
    assert verdict.ok and "aaaaaaaaa" in verdict.line, verdict.line


def test_a_range_with_one_ordinary_commit_is_not():
    good = ro.Commit("a" * 40, 1, bump(), OLD, NEW)
    other = ro.Commit("b" * 40, 1, [mod("src/main.rs", ("a", "b"))], NEW, NEW)
    verdict = ro.classify_range([good, other])
    assert not verdict.ok and "bbbbbbbbb" in verdict.line, verdict.line


def test_a_merge_commit_in_the_range_is_not_release_only():
    merge = ro.Commit("c" * 40, 2, bump(), OLD, NEW)
    assert not ro.classify_range([merge]).ok


def test_an_empty_range_is_not_release_only():
    assert not ro.classify_range([]).ok


# ── Scenarios: the command line on a throwaway repository ──────────────────

SCRIPT = REPO / "scripts" / "release-only.py"


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def _repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "test")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "Cargo.toml").write_text(f'[package]\nname = "sipnab"\nversion = "{OLD}"\n')
    (repo / "CHANGELOG.md").write_text("# Changelog\n\n## [Unreleased]\n\n- a change\n")
    (repo / "src").mkdir()
    (repo / "src" / "main.rs").write_text("fn main() {}\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    return repo


def _bump(repo):
    (repo / "Cargo.toml").write_text(f'[package]\nname = "sipnab"\nversion = "{NEW}"\n')
    (repo / "CHANGELOG.md").write_text(f"# Changelog\n\n## [{NEW}] - 2026-11-08\n\n- a change\n")
    _git(repo, "add", "Cargo.toml", "CHANGELOG.md")


def _run(repo, *args):
    return subprocess.run(["python3", str(SCRIPT), *args], cwd=repo, capture_output=True, text=True, check=False)


def test_scenario_a_staged_release_bump_exits_zero_and_names_the_proof(tmp_path):
    repo = _repo(tmp_path)
    _bump(repo)
    out = _run(repo, "staged")
    assert out.returncode == 0 and "0.5.237 -> 0.5.238" in out.stdout, out


def test_scenario_a_staged_bump_with_a_code_change_exits_one_and_names_the_file(tmp_path):
    repo = _repo(tmp_path)
    _bump(repo)
    (repo / "src" / "main.rs").write_text("fn main() { println!(); }\n")
    _git(repo, "add", "src/main.rs")
    out = _run(repo, "staged")
    assert out.returncode == 1 and "src/main.rs" in out.stdout, out


def test_scenario_a_range_holding_only_the_bump_commit_exits_zero(tmp_path):
    repo = _repo(tmp_path)
    _bump(repo)
    _git(repo, "commit", "-qm", "Release")
    out = _run(repo, "range", "HEAD~1", "HEAD")
    assert out.returncode == 0, out


def test_scenario_a_range_with_an_ordinary_commit_after_the_bump_exits_one(tmp_path):
    repo = _repo(tmp_path)
    _bump(repo)
    _git(repo, "commit", "-qm", "Release")
    (repo / "src" / "main.rs").write_text("fn main() { println!(); }\n")
    _git(repo, "commit", "-qam", "code")
    out = _run(repo, "range", "HEAD~2", "HEAD")
    assert out.returncode == 1 and "does not move forward" in out.stdout, out


def test_scenario_a_range_git_cannot_resolve_exits_one(tmp_path):
    out = _run(_repo(tmp_path), "range", "no-such-ref", "HEAD")
    assert out.returncode == 1 and "could not list" in out.stdout, out


def test_scenario_outside_a_repository_staged_exits_one(tmp_path):
    out = _run(tmp_path, "staged")
    assert out.returncode == 1, out


def test_scenario_an_unknown_command_is_a_usage_error(tmp_path):
    assert _run(tmp_path, "everything").returncode == 2


# ── The push: every pushed branch range release-only ──────────────────────

Z = "0" * 40
L1, L2, R1 = "1" * 40, "2" * 40, "3" * 40
YES = ro.Verdict(True, "release-only: 111111111")
NO = ro.Verdict(False, "release-only: no -- src/main.rs is not a file a release bump changes")


def push_ref(remote="refs/heads/release/0.5.239", local=L1, remote_sha=Z):
    return ("refs/heads/x", local, remote, remote_sha)


def test_a_push_of_one_release_only_branch_is_release_only():
    v = ro.decide_push([push_ref()], {L1: YES})
    assert v.ok and "release/0.5.239" in v.line, v.line


def test_a_push_whose_range_is_not_release_only_is_not_and_says_why():
    v = ro.decide_push([push_ref()], {L1: NO})
    assert not v.ok and "src/main.rs" in v.line, v.line


def test_a_push_with_a_tag_is_not_a_release_only_branch_push():
    assert not ro.decide_push([push_ref(remote="refs/tags/v0.5.239")], {L1: YES}).ok


def test_a_push_of_two_branches_needs_both_release_only():
    refs = [push_ref(), push_ref(remote="refs/heads/topic", local=L2)]
    assert not ro.decide_push(refs, {L1: YES, L2: NO}).ok


def test_a_push_that_only_deletes_is_not_release_only():
    assert not ro.decide_push([push_ref(local=Z)], {}).ok


def test_an_empty_push_is_not_release_only():
    assert not ro.decide_push([], {}).ok


def test_a_range_that_could_not_be_judged_is_not_release_only():
    assert not ro.decide_push([push_ref()], {}).ok


def test_the_base_of_an_update_is_the_remote_sha():
    assert ro.push_base(push_ref(remote_sha=R1), lambda sha: True, lambda local: "m" * 40) == R1


def test_the_base_of_a_new_branch_is_its_merge_base_with_main():
    assert ro.push_base(push_ref(), lambda sha: True, lambda local: "m" * 40) == "m" * 40


def test_a_remote_sha_this_clone_lacks_falls_back_to_the_merge_base():
    assert ro.push_base(push_ref(remote_sha=R1), lambda sha: False, lambda local: "m" * 40) == "m" * 40


def test_no_merge_base_means_no_base():
    assert ro.push_base(push_ref(), lambda sha: True, lambda local: None) is None


def test_the_release_tests_are_test_targets_that_exist():
    for name in ro.RELEASE_TESTS:
        assert (REPO / "tests" / f"{name}.rs").is_file(), name


def test_the_release_tests_cover_the_version_markers_changelog_since_and_delivery():
    for name in ("docs_drift_test", "cli_flag_since_test", "release_delivery_test", "release_completeness_test"):
        assert name in ro.RELEASE_TESTS, name


def test_the_tests_command_prints_one_cargo_test_flag_per_target(tmp_path):
    out = _run(tmp_path, "tests")
    assert out.returncode == 0
    assert out.stdout.split() == [w for t in ro.RELEASE_TESTS for w in ("--test", t)], out.stdout


def test_scenario_a_push_of_a_new_release_branch_is_release_only(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "branch", "-M", "main")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    _bump(repo)
    _git(repo, "commit", "-qm", "Release")
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    stdin = f"refs/heads/release/0.5.238 {head} refs/heads/release/0.5.238 {Z}\n"
    out = subprocess.run(["python3", str(SCRIPT), "push"], cwd=repo, input=stdin, capture_output=True, text=True)
    assert out.returncode == 0, out


def test_scenario_a_push_of_a_branch_with_code_is_not_release_only(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "branch", "-M", "main")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    (repo / "src" / "main.rs").write_text("fn main() { println!(); }\n")
    _git(repo, "commit", "-qam", "code")
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    stdin = f"refs/heads/topic {head} refs/heads/topic {Z}\n"
    out = subprocess.run(["python3", str(SCRIPT), "push"], cwd=repo, input=stdin, capture_output=True, text=True)
    assert out.returncode == 1, out
