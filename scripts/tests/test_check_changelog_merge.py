# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/check-changelog-merge.py: a merge of main left the CHANGELOG as main has it.

Five times on 2026-11-13 and 2026-11-14 an automatic merge of main put
CHANGELOG entries in the wrong place without a conflict: inside a released
section; a heading joined to an entry with no blank line; main's `Changed`
entry under the branch's `### Fixed`. git merges the file line by line and
knows nothing of headings.

The gate compares the CHANGELOG of the index with the CHANGELOG of the base
(the commit being merged, or the merge base with origin/main):

1. an entry of the base's [Unreleased] that is also in ours sits under the
   same heading;
2. each heading is in [Unreleased] once, and each entry once;
3. a blank line comes before each heading;
4. the base's released part is the end of ours, byte for byte, unless the
   commit moves the pin `.config/changelog-released.sha256` to the sha256 of
   the released part it leaves (a rewrite made on purpose).

An entry is one top-level bullet with every indented line under it. The
format of an entry is not judged here: the changelog's format gate does that.
"""

import hashlib
import subprocess

import pytest
from conftest import load

cm = load("check-changelog-merge")

HEAD = "# Changelog\n\nAll notable changes.\n\n"
RELEASED = (
    "## [0.5.254] - 2026-11-14\n\n### Added\n\n- **History files are compressed.**\n  - Effect: smaller files.\n\n"
    "## [0.5.253] - 2026-11-13\n\n### Fixed\n\n- **A drain no longer ends on a signal.**\n  - Was: it ended.\n"
)
A = "- **The step log keeps the test total.**\n  - Effect: the total is in the log.\n  - Docs: [Testing](docs/testing.md).\n"
B = "- **A signal no longer ends a drain.**\n  - Was: the drain ended.\n"
C = "- **The history reader builds fewer rows.**\n  - Effect: a question is answered sooner.\n"
D = "- **Mine: a new flag.**\n  - Effect: it exists.\n"
LEAD_A, LEAD_B, LEAD_C, LEAD_D = (x.splitlines()[0] for x in (A, B, C, D))


def log(unreleased, released=RELEASED, head=HEAD):
    return f"{head}## [Unreleased]\n\n{unreleased}\n{released}"


def sections(**kw):
    """`Changed=A + C, Fixed=B` as the text of an [Unreleased] section."""
    return "\n".join(f"### {name}\n\n{body}" for name, body in kw.items())


BASE = log(sections(Changed=A, Fixed=B))


def problems(ours, base=BASE, **kw):
    return cm.check(ours, base, **kw)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


# ── SUCCESS ────────────────────────────────────────────────────────────────


def test_success_a_changelog_equal_to_the_bases_passes():
    assert problems(BASE) == []


def test_success_an_entry_of_the_branch_under_an_existing_heading_passes():
    assert problems(log(sections(Changed=A + D, Fixed=B))) == []


def test_success_an_entry_of_the_branch_before_mains_entry_passes():
    assert problems(log(sections(Changed=D + A, Fixed=B))) == []


def test_success_a_heading_only_the_branch_has_passes():
    assert problems(log(sections(Added=D, Changed=A, Fixed=B))) == []


def test_success_headings_in_another_order_pass():
    # The order of headings is the format gate's subject, not this one's.
    assert problems(log(sections(Fixed=B, Changed=A))) == []


def test_success_a_release_commit_that_adds_a_section_on_top_passes():
    released = "## [0.5.255] - 2026-11-15\n\n" + sections(Changed=A, Fixed=B) + "\n" + RELEASED
    assert problems(f"{HEAD}{released}") == []


def test_success_a_release_commit_that_leaves_a_fresh_unreleased_passes():
    released = "## [0.5.255] - 2026-11-15\n\n" + sections(Changed=A, Fixed=B) + "\n" + RELEASED
    assert problems(f"{HEAD}## [Unreleased]\n\n{released}") == []


def test_success_an_entry_of_main_that_the_branch_removed_passes():
    # A change no user sees has no entry; removing one is a decision.
    assert problems(log(sections(Changed=A))) == []


def test_success_an_entry_of_main_whose_lead_the_branch_rewrote_passes():
    rewritten = A.replace("keeps the test total", "holds the total of a passing suite")
    assert problems(log(sections(Fixed=rewritten + B))) == []


def test_success_sub_bullets_of_main_that_the_branch_rewrote_pass():
    assert problems(log(sections(Changed=A.replace("the total is in the log", "one line more"), Fixed=B))) == []


def test_success_two_entries_with_the_same_sub_bullet_are_two_entries():
    # A sub-bullet is never matched by itself.
    same = "- **Another entry.**\n  - Was: the drain ended.\n"
    assert problems(log(sections(Changed=A + same, Fixed=B))) == []


def test_success_a_rewrite_of_released_sections_with_the_pin_moved_passes():
    rewritten = RELEASED.replace("Was: it ended.", "Was: the drain ended early.")
    assert problems(log(sections(Changed=A, Fixed=B), released=rewritten), pin=sha(rewritten), base_pin="") == []


def test_success_a_base_without_an_unreleased_section_passes():
    assert problems(log(sections(Added=D)), base=HEAD + RELEASED) == []


def test_success_a_table_under_an_entry_belongs_to_it():
    table = "- **Sizes changed.**\n\n  | Target | Bytes |\n  |---|---|\n  | musl | 1 |\n"
    base = log(sections(Changed=table, Fixed=B))
    assert problems(log(sections(Changed=D + table, Fixed=B)), base=base) == []
    got = cm.entries(cm.split(base)[0])
    assert [e.lead for e in got] == ["- **Sizes changed.**", LEAD_B]
    # The blank line between the lead and the table does not end the entry.
    assert got[0].block == table.rstrip("\n").splitlines()


def test_success_the_real_changelog_passes_against_itself():
    text = (cm.ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert cm.check(text, text) == []


# ── FAILURE ────────────────────────────────────────────────────────────────


def test_failure_mains_changed_entry_under_the_branchs_fixed_is_named_with_both_headings():
    # 2026-11-14: main's `Changed` entry merged under the branch's `### Fixed`.
    got = problems(log(sections(Fixed=B + A)))
    assert len(got) == 1
    assert LEAD_A in got[0] and "'### Fixed'" in got[0] and "'### Changed'" in got[0]


def test_failure_the_message_says_where_to_move_the_entry():
    got = problems(log(sections(Fixed=B + A)))[0]
    assert "is under '### Fixed' here and under '### Changed' on the base" in got and "sub-bullets" in got


def test_failure_two_misplaced_entries_are_two_problems():
    got = problems(log(sections(Changed=B, Fixed=A)))
    assert len(got) == 2 and LEAD_A in got[0] + got[1] and LEAD_B in got[0] + got[1]


def test_failure_an_entry_before_any_heading_is_misplaced():
    got = problems(log(A + "\n" + sections(Fixed=B)))
    assert len(got) == 1 and LEAD_A in got[0] and "under no heading here" in got[0]


def test_failure_a_heading_twice_in_unreleased_is_refused():
    got = problems(log("### Changed\n\n" + A + "\n### Fixed\n\n" + B + "\n### Changed\n\n" + D))
    assert len(got) == 1 and "'### Changed' twice" in got[0] and "[Unreleased]" in got[0]


def test_failure_an_entry_twice_under_one_heading_is_refused():
    got = problems(log(sections(Changed=A + A, Fixed=B)))
    assert len(got) == 1 and LEAD_A in got[0] and "twice" in got[0]


def test_failure_an_entry_twice_under_two_headings_names_both_and_is_one_problem():
    got = problems(log(sections(Changed=A, Fixed=B + A)))
    assert len(got) == 1 and "twice" in got[0] and "'### Changed'" in got[0] and "'### Fixed'" in got[0]


def test_failure_a_heading_joined_to_an_entry_is_refused():
    # 2026-11-13: a heading joined to an entry with no blank line.
    got = problems(log("### Changed\n\n" + A + "### Fixed\n\n" + B))
    assert len(got) == 1 and "no blank line before the heading '### Fixed'" in got[0]


def test_failure_the_first_released_heading_joined_to_an_entry_is_refused():
    got = problems(f"{HEAD}## [Unreleased]\n\n{sections(Changed=A, Fixed=B)}{RELEASED}")
    assert len(got) == 1 and "no blank line before the heading '## [0.5.254] - 2026-11-14'" in got[0]


def test_failure_the_unreleased_heading_joined_to_the_text_above_is_refused():
    got = problems(log(sections(Changed=A, Fixed=B), head="# Changelog\n\nAll notable changes.\n"))
    assert len(got) == 1 and "'## [Unreleased]'" in got[0]


def test_failure_an_entry_merged_into_a_released_section_is_refused():
    # 2026-11-13, three times: an entry inside a released section.
    released = RELEASED.replace("### Fixed\n\n", "### Fixed\n\n" + D)
    got = problems(log(sections(Changed=A, Fixed=B), released=released))
    assert len(got) == 1 and "released part" in got[0] and LEAD_D in got[0]


def test_failure_the_released_message_says_what_to_do_in_both_cases():
    released = RELEASED.replace("### Fixed\n\n", "### Fixed\n\n" + D)
    got = problems(log(sections(Changed=A, Fixed=B), released=released))[0]
    assert "a merge moved an entry into a released section: move it back" in got
    assert f"you rewrote released sections on purpose: write {sha(released)} to .config/changelog-released.sha256" in got


def test_failure_a_changed_byte_in_an_old_release_is_refused():
    got = problems(log(sections(Changed=A, Fixed=B), released=RELEASED.replace("it ended.", "it ended"))
                   )
    assert len(got) == 1 and "released part" in got[0]


def test_failure_a_released_section_that_was_deleted_is_refused():
    cut = RELEASED[: RELEASED.index("## [0.5.253]")]
    assert len(problems(log(sections(Changed=A, Fixed=B), released=cut))) == 1


def test_failure_a_pin_that_is_not_the_sha256_of_the_released_part_does_not_pass():
    rewritten = RELEASED.replace("it ended.", "it ended early.")
    got = problems(log(sections(Changed=A, Fixed=B), released=rewritten), pin="0" * 64, base_pin="")
    assert len(got) == 1 and sha(rewritten) in got[0]


def test_failure_a_pin_the_base_already_had_does_not_pass():
    # The pin must move in the commit that rewrites: an old pin is no leave.
    rewritten = RELEASED.replace("it ended.", "it ended early.")
    got = problems(log(sections(Changed=A, Fixed=B), released=rewritten), pin=sha(rewritten), base_pin=sha(rewritten))
    assert len(got) == 1 and "released part" in got[0]


def test_failure_every_problem_is_reported_not_only_the_first():
    released = RELEASED.replace("### Fixed\n\n", "### Fixed\n\n" + D)
    got = problems(log("### Changed\n\n" + B + "### Fixed\n\n" + A, released=released))
    assert len(got) == 4


def test_failure_a_lead_is_shown_whole_when_it_is_long():
    long = "- **" + "word " * 40 + "end.**\n  - Effect: x.\n"
    base = log(sections(Changed=long, Fixed=B))
    got = problems(log(sections(Fixed=B + long)), base=base)
    assert long.splitlines()[0] in got[0]


# ── EDGE ───────────────────────────────────────────────────────────────────


def test_edge_an_entry_is_its_lead_and_every_indented_line_under_it():
    got = cm.entries(cm.split(BASE)[0])
    assert [(e.heading, e.lead) for e in got] == [("### Changed", LEAD_A), ("### Fixed", LEAD_B)]
    assert got[0].block == A.rstrip("\n").splitlines()


def test_edge_split_returns_the_unreleased_lines_and_the_released_text():
    unreleased, released = cm.split(BASE)
    assert unreleased[0] == "" and "### Changed" in unreleased and released == RELEASED


def test_edge_a_changelog_without_a_released_section_has_an_empty_released_part():
    assert cm.split(f"{HEAD}## [Unreleased]\n\n{sections(Changed=A)}")[1] == ""


def test_edge_a_changelog_without_unreleased_has_no_entries():
    assert cm.split(HEAD + RELEASED)[0] == [] and problems(HEAD + RELEASED, base=HEAD + RELEASED) == []


def test_edge_a_third_level_heading_inside_a_released_section_is_not_an_unreleased_heading():
    assert [e.heading for e in cm.entries(cm.split(BASE)[0])] == ["### Changed", "### Fixed"]


def test_edge_a_held_line_is_not_an_entry_and_ends_the_entry_above_it():
    held = "Held: 0.5.255 waits for the fleet change.\n"
    got = cm.entries(cm.split(log("### Changed\n\n" + A + "\n" + held + "\n### Fixed\n\n" + B))[0])
    assert [e.lead for e in got] == [LEAD_A, LEAD_B] and not any("Held" in line for e in got for line in e.block)


def test_edge_a_lead_that_differs_only_in_trailing_whitespace_is_the_same_entry():
    moved = A.replace("total.**\n", "total.**  \n")
    got = problems(log(sections(Fixed=B + moved)))
    assert len(got) == 1 and "'### Changed'" in got[0]


def test_edge_crlf_line_ends_in_ours_do_not_hide_a_misplaced_entry():
    ours = log(sections(Fixed=B + A)).replace("\n", "\r\n")
    got = cm.check(ours, BASE)
    assert any(LEAD_A in p and "'### Changed'" in p for p in got)
    assert not any("\r" in line for e in cm.entries(cm.split(ours)[0]) for line in e.block)


def test_failure_text_added_after_the_bases_released_part_is_refused():
    # The base's released part is in ours, and it is not the end of ours.
    got = problems(BASE + "\n" + D)
    assert len(got) == 1 and "released part" in got[0] and LEAD_D in got[0]


def test_edge_a_long_line_of_a_released_part_is_shown_by_its_start():
    # Entries from before the outline format are single lines of 2,000 characters.
    long = "- **Old entry.** " + "prose " * 400 + "\n"
    got = problems(log(sections(Changed=A, Fixed=B), released=RELEASED.replace("### Fixed\n\n", "### Fixed\n\n" + long)))
    assert len(got) == 1 and "- **Old entry.** prose" in got[0] and len(got[0]) < 1200


def test_edge_a_sub_bullet_with_no_entry_above_it_is_not_an_entry():
    orphan = "### Changed\n\n  - Effect: a line a merge left behind.\n\n" + A
    assert [e.lead for e in cm.entries(cm.split(log(orphan))[0])] == [LEAD_A]


def test_edge_a_base_with_an_empty_released_part_accepts_any_released_part():
    base = f"{HEAD}## [Unreleased]\n\n{sections(Changed=A)}"
    assert problems(log(sections(Changed=A)), base=base) == []


def test_edge_a_release_heading_with_a_link_form_still_starts_the_released_part():
    released = RELEASED.replace("## [0.5.254] - 2026-11-14", "## [0.5.254](https://example.invalid/r) - 2026-11-14")
    assert cm.split(log(sections(Changed=A), released=released))[1] == released


def test_edge_a_bullet_inside_a_code_fence_of_an_entry_stays_inside_it():
    fenced = "- **A command changed.**\n\n  ```sh\n  - not a bullet\n  ```\n"
    got = cm.entries(cm.split(log(sections(Changed=fenced + A)))[0])
    assert [e.lead for e in got] == ["- **A command changed.**", LEAD_A]


def test_edge_a_heading_at_the_very_start_of_the_file_needs_no_blank_line():
    text = "## [Unreleased]\n\n" + sections(Changed=A) + "\n" + RELEASED
    assert cm.check(text, text) == []


def test_edge_an_entry_moved_and_also_twice_is_reported_as_twice_only():
    got = problems(log(sections(Added=A, Fixed=B + A)))
    assert len(got) == 1 and "twice" in got[0]


def test_edge_the_pin_is_read_as_its_first_word():
    assert cm.pin_of("abc123  released part\n") == "abc123" and cm.pin_of("") == "" and cm.pin_of(None) == ""


def test_edge_comment_lines_of_the_pin_file_are_not_the_pin():
    assert cm.pin_of("# The sha256 of the released part.\n\nabc123\n") == "abc123" and cm.pin_of("# only\n") == ""


# ── The command line, against real repositories in a temporary directory ───


def git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        "-c", "commit.gpgsign=false", *args], capture_output=True, text=True, check=False, timeout=60)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


@pytest.fixture
def repo(tmp_path):
    """A repository whose `origin/main` holds BASE and whose branch `work`
    starts there."""
    root = tmp_path / "r"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "CHANGELOG.md").write_text(BASE)
    git(root, "add", "CHANGELOG.md")
    git(root, "commit", "-q", "-m", "base")
    git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(root, "switch", "-q", "-c", "work")
    return root


def run(repo, *args):
    return cm.main(["--repo", str(repo), *args])


def test_success_the_command_passes_on_a_branch_that_added_an_entry(repo, capsys):
    (repo / "CHANGELOG.md").write_text(log(sections(Changed=A + D, Fixed=B)))
    git(repo, "add", "CHANGELOG.md")
    assert run(repo) == 0 and "the CHANGELOG is as the base" in capsys.readouterr().out


def test_failure_the_command_fails_on_a_misplaced_entry_and_prints_it(repo, capsys):
    (repo / "CHANGELOG.md").write_text(log(sections(Fixed=B + A)))
    git(repo, "add", "CHANGELOG.md")
    assert run(repo) == 1
    err = capsys.readouterr().err
    assert LEAD_A in err and "'### Changed'" in err and "'### Fixed'" in err


def test_failure_the_command_reads_the_index_not_the_working_tree(repo):
    # A gate that reads the working tree passes a commit that holds the defect.
    (repo / "CHANGELOG.md").write_text(log(sections(Fixed=B + A)))
    git(repo, "add", "CHANGELOG.md")
    (repo / "CHANGELOG.md").write_text(BASE)
    assert run(repo) == 1


def test_success_the_base_is_the_commit_being_merged_while_a_merge_is_open(repo, capsys):
    # main gains C under Changed; the branch has D under Fixed.
    (repo / "CHANGELOG.md").write_text(log(sections(Changed=A, Fixed=B + D)))
    git(repo, "commit", "-q", "-am", "work")
    git(repo, "switch", "-q", "main")
    (repo / "CHANGELOG.md").write_text(log(sections(Changed=C + A, Fixed=B)))
    git(repo, "commit", "-q", "-am", "main moves")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(repo, "switch", "-q", "work")
    git(repo, "merge", "-q", "--no-commit", "--no-ff", "main")
    assert run(repo) == 0 and "MERGE_HEAD" in capsys.readouterr().out
    # The same merge with main's new entry under the wrong heading.
    (repo / "CHANGELOG.md").write_text(log(sections(Changed=A, Fixed=B + D + C)))
    git(repo, "add", "CHANGELOG.md")
    assert run(repo) == 1


def test_failure_a_rewrite_of_a_released_section_needs_the_pin_in_the_same_index(repo, capsys):
    rewritten = RELEASED.replace("it ended.", "it ended early.")
    (repo / "CHANGELOG.md").write_text(log(sections(Changed=A, Fixed=B), released=rewritten))
    git(repo, "add", "CHANGELOG.md")
    assert run(repo) == 1
    (repo / ".config").mkdir()
    (repo / ".config" / "changelog-released.sha256").write_text(sha(rewritten) + "\n")
    git(repo, "add", ".config/changelog-released.sha256")
    assert run(repo) == 0


def test_edge_an_explicit_base_is_used(repo):
    (repo / "CHANGELOG.md").write_text(log(sections(Fixed=B + A)))
    git(repo, "commit", "-q", "-am", "moved")
    assert run(repo, "--base", "HEAD") == 0 and run(repo, "--base", "origin/main") == 1


def test_edge_a_base_that_cannot_be_found_is_exit_2_not_a_pass(repo, capsys):
    git(repo, "update-ref", "-d", "refs/remotes/origin/main")
    assert run(repo) == 2 and "origin/main" in capsys.readouterr().err


def test_edge_a_base_without_a_changelog_is_exit_2(repo, capsys):
    assert run(repo, "--base", git(repo, "hash-object", "-t", "tree", "/dev/null")) == 2


def test_edge_an_unknown_argument_is_exit_2(repo):
    assert run(repo, "--skip") == 2


# ── Where the gate runs: the pre-commit hook and CI ────────────────────────

HOOK = (cm.ROOT / ".githooks/pre-commit").read_text(encoding="utf-8")
CI = (cm.ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
COMMAND = "python3 scripts/check-changelog-merge.py"


def hook_step():
    start = HOOK.index('step "CHANGELOG as the base has it"')
    return HOOK[start: HOOK.index('\nstep "', start + 1)]


def ci_step():
    start = CI.index("- name: The CHANGELOG is as the base has it")
    return CI[start: CI.index("\n      - ", start + 1)]


def test_success_the_hook_runs_the_gate_on_every_commit():
    body = hook_step()
    assert COMMAND in body and "exit 1" in body
    # Not inside the block that runs only when scripts/ is staged.
    assert HOOK.index('step "RFC citations linked"') < HOOK.index('step "CHANGELOG as the base has it"') < HOOK.index(
        'step "Script tests"')


def test_success_ci_runs_the_gate_in_the_job_that_has_the_history():
    assert COMMAND in ci_step()
    steps = CI[CI.index("steps: &check-steps"): CI.index("- name: The CHANGELOG is as the base has it")]
    assert "fetch-depth: 0" in steps


def test_failure_the_hook_prints_the_gates_output_when_it_fails():
    body = hook_step()
    assert "FAIL" in body and "CHANGELOG_OUT" in body


def test_failure_neither_place_can_skip_the_gate():
    for body in (hook_step(), ci_step()):
        assert "continue-on-error" not in body and "|| true" not in body and "SKIP_" not in body


def test_failure_the_hook_treats_a_base_it_cannot_find_as_a_failure():
    # Any exit but 0 fails the commit: 2 (a base or a CHANGELOG that cannot
    # be read) must not read as a pass.
    body = hook_step()
    assert "elif CHANGELOG_OUT=$(" + COMMAND + " 2>&1); then" in body
    after = body[body.index("elif CHANGELOG_OUT=$("):]
    assert after.index("else") < after.index("FAIL") < after.index("exit 1")


def test_edge_the_hook_skips_only_where_there_is_no_base_at_all():
    # A sandbox repository of the hook's own tests has no origin/main.
    body = hook_step()
    assert "origin/main^{commit}" in body and "MERGE_HEAD^{commit}" in body
    assert body.count("SKIP") == 2 and "no base" in body


def test_edge_ci_runs_the_gate_on_linux_only_once():
    assert "if: runner.os == 'Linux'" in ci_step() and CI.count(COMMAND) == 1


def test_edge_the_pin_file_holds_one_sha256_or_is_absent():
    pin = cm.ROOT / cm.PIN
    if pin.exists():
        assert len(cm.pin_of(pin.read_text())) == 64


# ── The released part against every commit the result holds ────────────────
#
# On 2026-11-25 a merge-train commit merged a car branch (MERGE_HEAD
# b7899d949, forked before 0.5.272) into a train that already held the
# 0.5.272 release. The merge put the car's [Unreleased] entries inside the
# released [0.5.272] section. The hook compared the index with MERGE_HEAD
# only: the car's released part (0.5.271 and older) is the end of any newer
# one, and an entry of the base that ours no longer holds in [Unreleased] is
# not a problem, so the gate printed "the CHANGELOG is as the base
# b7899d94956a has it" and passed. It happened in four merges that day.
#
# The rule: a commit never changes what was released before it, except on
# purpose with the pin. So the released part of the index must end with the
# released part of EVERY commit the result is built on: HEAD (the first
# parent, or the commit a rebase or a cherry-pick is replaying onto),
# MERGE_HEAD while a merge is open, and the merge base with origin/main.
# Whichever of them holds the newest release then judges it, whatever branch
# MERGE_HEAD is. Neither origin/main's tip nor the newest tag is the rule: a
# branch forked before a release does not hold that release, and would fail
# against either for no fault of its own; a tag may not be fetched at all.

OLD = "## [0.5.253] - 2026-11-13\n\n### Fixed\n\n- **A drain no longer ends on a signal.**\n  - Was: it ended.\n"
H = "- **History files are compressed.**\n  - Effect: smaller files.\n"
LEAD_H = H.splitlines()[0]
NEW_SECTION = "## [0.5.254] - 2026-11-14\n\n### Added\n\n" + H + "\n"
assert NEW_SECTION + OLD == RELEASED
# The defect: the car's D inside the released 0.5.254 section.
INJECTED = "## [0.5.254] - 2026-11-14\n\n### Added\n\n" + D + H + "\n" + OLD
GOOD_MERGE = log(sections(Added=D), released=RELEASED)
BAD_MERGE = log("", released=INJECTED)
SHA = "a" * 40
SHB = "b" * 40
SHC = "c" * 40


def git_rc(repo, *args):
    """A git command that may fail (a rebase or a merge that stops)."""
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                           "-c", "commit.gpgsign=false", *args], capture_output=True, text=True, check=False,
                          timeout=60).returncode


def write(repo, text, name="CHANGELOG.md"):
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text(text)
    git(repo, "add", name)


def commit(repo, text, message, name="CHANGELOG.md"):
    write(repo, text, name)
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def train(tmp_path):
    """main before the release holds H in [Unreleased]; `car` forks there and
    adds D; main then releases 0.5.254 (H moves into it) and origin/main
    follows; `train` forks from the release. No tag exists."""
    root = tmp_path / "t"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "x").write_text("0\n")
    git(root, "add", "x")
    commit(root, log(sections(Added=H), released=OLD), "before the release")
    git(root, "switch", "-q", "-c", "car")
    (root / "x").write_text("car\n")
    git(root, "add", "x")
    commit(root, log(sections(Added=H + D), released=OLD), "car: D")
    git(root, "switch", "-q", "main")
    (root / "x").write_text("main\n")
    git(root, "add", "x")
    commit(root, log("", released=RELEASED), "release 0.5.254")
    git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(root, "switch", "-q", "-c", "train")
    return root


def merge_car(repo, into="train", detach=False):
    """Open a merge of `car` into `into` that leaves the index as HEAD has it
    (`-s ours`), so a test writes the merge result it wants."""
    git(repo, "switch", "-q", *(["--detach"] if detach else []), into)
    git(repo, "merge", "-q", "-s", "ours", "--no-commit", "car")
    assert git(repo, "rev-parse", "MERGE_HEAD") == git(repo, "rev-parse", "car")


# The pure choice of bases.


def test_success_an_ordinary_commit_judges_its_released_part_by_the_merge_base_and_head():
    base, how, released = cm.choose_bases("", "", SHB, SHA)
    assert base == SHA and "merge base" in how
    assert [sha for sha, _ in released] == [SHA, SHB]


def test_success_an_open_merge_judges_its_released_part_by_both_parents_and_the_merge_base():
    base, how, released = cm.choose_bases("", SHC, SHB, SHA)
    assert base == SHC and "MERGE_HEAD" in how
    assert [sha for sha, _ in released] == [SHC, SHB, SHA]


def test_success_each_released_base_says_how_it_was_chosen():
    _, _, released = cm.choose_bases("", SHC, SHB, SHA)
    hows = [how for _, how in released]
    assert "MERGE_HEAD" in hows[0] and "HEAD" in hows[1] and "origin/main" in hows[2]


def test_success_an_explicit_base_is_the_only_base():
    base, how, released = cm.choose_bases(SHA, SHC, SHB, SHA)
    assert base == SHA and how == "--base" and released == [(SHA, "--base")]


def test_edge_head_equal_to_the_merge_base_is_one_base():
    _, _, released = cm.choose_bases("", "", SHA, SHA)
    assert [sha for sha, _ in released] == [SHA]


def test_edge_merge_head_equal_to_the_merge_base_is_one_base():
    _, _, released = cm.choose_bases("", SHA, SHB, SHA)
    assert [sha for sha, _ in released] == [SHA, SHB]


def test_edge_an_unborn_head_is_not_a_base():
    _, _, released = cm.choose_bases("", "", "", SHA)
    assert [sha for sha, _ in released] == [SHA]


def test_failure_no_merge_and_no_merge_base_is_no_base_even_with_a_head():
    base, how, released = cm.choose_bases("", "", SHB, "")
    assert base is None and "origin/main" in how and released == []


def test_edge_a_merge_without_origin_main_still_judges_by_both_parents():
    base, _, released = cm.choose_bases("", SHC, SHB, "")
    assert base == SHC and [sha for sha, _ in released] == [SHC, SHB]


# The pure check with several released bases.


def test_failure_an_entry_inside_a_release_only_head_holds_is_refused():
    found = cm.check(BAD_MERGE, log(sections(Added=H + D), released=OLD),
                     others=[("HEAD", log("", released=RELEASED), "")])
    assert len(found) == 1 and found[0].startswith("against HEAD:") and LEAD_D[:30] in found[0]


def test_success_the_same_entry_in_unreleased_passes_against_both():
    assert cm.check(GOOD_MERGE, log(sections(Added=H + D), released=OLD),
                    others=[("HEAD", log("", released=RELEASED), "")]) == []


def test_success_a_base_with_no_changelog_holds_nothing_released():
    assert cm.check(GOOD_MERGE, GOOD_MERGE, others=[("HEAD", None, "")]) == []


def test_failure_each_base_that_disagrees_is_its_own_problem():
    found = cm.check(BAD_MERGE, log(sections(Added=H + D), released=OLD),
                     others=[("HEAD", log("", released=RELEASED), ""), ("main", log("", released=RELEASED), "")])
    assert [p.split(":")[0] for p in found] == ["against HEAD", "against main"]


def test_success_a_rewrite_on_purpose_passes_every_base_with_another_pin():
    rewritten = RELEASED.replace("it ended.", "it ended early.")
    ours = log("", released=rewritten)
    assert cm.check(ours, log("", released=RELEASED), sha(rewritten), "",
                    others=[("HEAD", log("", released=RELEASED), "")]) == []


def test_failure_a_pin_that_head_already_had_does_not_excuse_a_change_against_head():
    rewritten = RELEASED.replace("it ended.", "it ended early.")
    ours = log("", released=rewritten)
    found = cm.check(ours, ours, sha(rewritten), sha(rewritten),
                     others=[("HEAD", log("", released=RELEASED), sha(rewritten))])
    assert len(found) == 1 and found[0].startswith("against HEAD:")


def test_edge_without_other_bases_the_check_is_as_before():
    assert cm.check(BAD_MERGE, log(sections(Added=H + D), released=OLD)) == []


# Against real repositories: the cases the brief names.


def test_failure_a_merge_of_an_old_car_into_a_train_that_puts_its_entry_under_a_release_is_refused(train, capsys):
    merge_car(train)
    write(train, BAD_MERGE)
    assert run(train) == 1
    err = capsys.readouterr().err
    assert "HEAD" in err and LEAD_D[:30] in err


def test_success_a_merge_of_an_old_car_into_a_train_that_keeps_its_entry_unreleased_passes(train, capsys):
    merge_car(train)
    write(train, GOOD_MERGE)
    assert run(train) == 0 and "the CHANGELOG is as the base" in capsys.readouterr().out


def test_failure_the_message_names_the_first_parent_it_compared(train, capsys):
    merge_car(train)
    write(train, BAD_MERGE)
    head = git(train, "rev-parse", "HEAD")
    assert run(train) == 1 and head[:12] in capsys.readouterr().err


def test_success_the_pass_message_names_every_base_it_compared(train, capsys):
    merge_car(train)
    write(train, GOOD_MERGE)
    assert run(train) == 0
    out = capsys.readouterr().out
    for ref in ("car", "HEAD"):
        assert git(train, "rev-parse", ref)[:12] in out


def test_failure_the_bad_merge_fails_even_when_origin_main_is_not_fetched(train):
    merge_car(train)
    write(train, BAD_MERGE)
    git(train, "update-ref", "-d", "refs/remotes/origin/main")
    assert run(train) == 1


def test_failure_the_bad_merge_fails_on_a_detached_head(train):
    merge_car(train, detach=True)
    write(train, BAD_MERGE)
    assert git_rc(train, "symbolic-ref", "-q", "HEAD") != 0
    assert run(train) == 1


def test_success_the_good_merge_passes_on_a_detached_head(train):
    merge_car(train, detach=True)
    write(train, GOOD_MERGE)
    assert run(train) == 0


def test_failure_ci_refuses_the_bad_merge_once_it_is_committed(train):
    # CI runs the script with no --base outside a merge: the base is the
    # merge base with origin/main, which holds the release.
    merge_car(train)
    write(train, BAD_MERGE)
    git(train, "commit", "-q", "-m", "merge car")
    assert run(train) == 1


def test_failure_ci_refuses_it_by_the_merge_base_alone(train):
    merge_car(train)
    write(train, BAD_MERGE)
    git(train, "commit", "-q", "-m", "merge car")
    assert run(train, "--base", git(train, "merge-base", "HEAD", "origin/main")) == 1


def test_success_ci_passes_the_good_merge_once_it_is_committed(train):
    merge_car(train)
    write(train, GOOD_MERGE)
    git(train, "commit", "-q", "-m", "merge car")
    assert run(train) == 0


def test_edge_an_explicit_base_of_the_old_car_still_passes_the_bad_merge(train):
    # --base names the one base to compare with: the caller chose it.
    merge_car(train)
    write(train, BAD_MERGE)
    assert run(train, "--base", "car") == 0


def test_failure_a_car_that_holds_the_release_merged_into_an_older_train_is_refused(train):
    # The other way round: the train forked before the release, the car merged
    # main, and the merge puts the train's entry inside the release.
    git(train, "switch", "-q", "car")
    git(train, "merge", "-q", "-s", "ours", "--no-commit", "main")
    write(train, log(sections(Added=D), released=RELEASED))
    git(train, "commit", "-q", "-m", "car merges main")
    git(train, "switch", "-q", "-c", "old-train", "car~1")
    commit(train, log(sections(Added=H, Fixed=B), released=OLD), "old train: B")
    git(train, "merge", "-q", "-s", "ours", "--no-commit", "car")
    write(train, log(sections(Added=D), released=NEW_SECTION.replace("### Added\n\n", "### Added\n\n" + B) + OLD))
    assert run(train) == 1


def test_success_a_merge_of_main_into_an_old_branch_that_keeps_its_entry_unreleased_passes(train):
    git(train, "switch", "-q", "car")
    git(train, "merge", "-q", "-s", "ours", "--no-commit", "main")
    write(train, GOOD_MERGE)
    assert run(train) == 0


def test_failure_a_merge_of_main_into_an_old_branch_that_puts_its_entry_under_the_release_is_refused(train):
    git(train, "switch", "-q", "car")
    git(train, "merge", "-q", "-s", "ours", "--no-commit", "main")
    write(train, BAD_MERGE)
    assert run(train) == 1


def test_failure_a_merge_of_main_that_drops_an_old_release_is_refused(train):
    git(train, "switch", "-q", "car")
    git(train, "merge", "-q", "-s", "ours", "--no-commit", "main")
    write(train, log(sections(Added=D), released=NEW_SECTION))
    assert run(train) == 1


def test_success_an_ordinary_commit_on_a_branch_behind_main_passes(train):
    # car does not hold the release; its own released part judges it.
    git(train, "switch", "-q", "car")
    write(train, log(sections(Added=H + D + C), released=OLD))
    assert run(train) == 0


def test_failure_an_ordinary_commit_that_edits_a_release_head_holds_is_refused(train):
    write(train, log(sections(Added=D), released=RELEASED.replace("smaller files", "small files")))
    assert run(train) == 1


def test_failure_an_ordinary_commit_that_moves_its_entry_into_a_release_is_refused(train):
    commit(train, log(sections(Added=D), released=RELEASED), "train: D")
    write(train, BAD_MERGE)
    assert run(train) == 1


def test_success_an_ordinary_commit_that_adds_an_entry_on_the_train_passes(train):
    write(train, GOOD_MERGE)
    assert run(train) == 0


def test_success_a_release_commit_on_the_train_passes(train):
    commit(train, GOOD_MERGE, "train: D")
    write(train, log("", released="## [0.5.255] - 2026-11-15\n\n### Added\n\n" + D + "\n" + RELEASED))
    assert run(train) == 0


def test_failure_a_rebase_that_puts_the_entry_under_the_release_is_refused(train):
    git(train, "switch", "-q", "car")
    assert git_rc(train, "rebase", "-q", "train") != 0, "the rebase was meant to stop on x"
    assert git_rc(train, "rev-parse", "-q", "--verify", "REBASE_HEAD") == 0
    write(train, "car\n", name="x")
    write(train, BAD_MERGE)
    assert run(train) == 1


def test_success_a_rebase_that_keeps_the_entry_unreleased_passes(train):
    git(train, "switch", "-q", "car")
    assert git_rc(train, "rebase", "-q", "train") != 0, "the rebase was meant to stop on x"
    write(train, "car\n", name="x")
    write(train, GOOD_MERGE)
    assert run(train) == 0


def test_failure_a_rebase_onto_a_train_ahead_of_a_stale_origin_main_is_refused(train):
    # origin/main still at the commit before the release: only HEAD (the
    # train being replayed onto) holds it.
    git(train, "update-ref", "refs/remotes/origin/main", "main~1")
    git(train, "switch", "-q", "car")
    assert git_rc(train, "rebase", "-q", "train") != 0, "the rebase was meant to stop on x"
    write(train, "car\n", name="x")
    write(train, BAD_MERGE)
    assert run(train) == 1


def test_failure_a_cherry_pick_that_puts_the_entry_under_the_release_is_refused(train):
    git(train, "update-ref", "refs/remotes/origin/main", "main~1")
    assert git_rc(train, "cherry-pick", "car") != 0, "the cherry-pick was meant to stop on x"
    write(train, "car\n", name="x")
    write(train, BAD_MERGE)
    assert run(train) == 1


def test_success_with_no_tag_the_gate_still_judges_by_the_commits(train):
    assert git(train, "tag", "--list") == ""
    merge_car(train)
    write(train, GOOD_MERGE)
    assert run(train) == 0


def test_failure_with_no_tag_the_bad_merge_is_still_refused(train):
    assert git(train, "tag", "--list") == ""
    merge_car(train)
    write(train, BAD_MERGE)
    assert run(train) == 1


def test_edge_a_tag_on_an_old_commit_does_not_change_the_result(train):
    git(train, "tag", "v0.5.253", "main~1")
    merge_car(train)
    write(train, BAD_MERGE)
    assert run(train) == 1


def test_edge_a_head_without_a_changelog_holds_nothing_released(tmp_path):
    # main has no CHANGELOG yet; a branch that adds one is merged into it.
    root = tmp_path / "n"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "x").write_text("0\n")
    git(root, "add", "x")
    git(root, "commit", "-q", "-m", "no changelog yet")
    git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(root, "switch", "-q", "-c", "b")
    commit(root, GOOD_MERGE, "b: the changelog")
    git(root, "switch", "-q", "main")
    git(root, "merge", "-q", "-s", "ours", "--no-commit", "b")
    write(root, GOOD_MERGE)
    assert cm.main(["--repo", str(root)]) == 0


def test_failure_a_base_named_by_the_choice_that_has_no_changelog_is_still_exit_2(tmp_path):
    root = tmp_path / "m"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "x").write_text("0\n")
    git(root, "add", "x")
    git(root, "commit", "-q", "-m", "no changelog yet")
    git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    write(root, GOOD_MERGE)
    assert cm.main(["--repo", str(root)]) == 2


def test_edge_a_changelog_with_no_released_section_yet_passes_any_merge(tmp_path):
    root = tmp_path / "u"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    commit(root, f"{HEAD}## [Unreleased]\n\n### Added\n\n{H}", "first")
    git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(root, "switch", "-q", "-c", "b")
    commit(root, f"{HEAD}## [Unreleased]\n\n### Added\n\n{H}{D}", "b: D")
    git(root, "switch", "-q", "main")
    git(root, "merge", "-q", "-s", "ours", "--no-commit", "b")
    write(root, f"{HEAD}## [Unreleased]\n\n### Added\n\n{H}{D}")
    assert cm.main(["--repo", str(root)]) == 0


def test_edge_a_merge_that_brings_mains_rewrite_on_purpose_passes_against_the_older_head(train):
    rewritten = RELEASED.replace("it ended.", "it ended early.")
    git(train, "switch", "-q", "main")
    write(train, sha(rewritten) + "\n", name=".config/changelog-released.sha256")
    commit(train, log("", released=rewritten), "rewrite on purpose")
    git(train, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(train, "switch", "-q", "train")
    git(train, "merge", "-q", "-s", "ours", "--no-commit", "main")
    write(train, sha(rewritten) + "\n", name=".config/changelog-released.sha256")
    write(train, log("", released=rewritten))
    assert run(train) == 0


def test_edge_a_problem_against_head_says_which_commit_and_why(train, capsys):
    merge_car(train)
    write(train, BAD_MERGE)
    assert run(train) == 1
    err = capsys.readouterr().err
    assert f"against {git(train, 'rev-parse', 'HEAD')[:12]} ({cm.ON_TOP_OF}):" in err


def test_success_a_merge_into_a_train_that_rewrote_a_release_on_purpose_passes(train):
    rewritten = RELEASED.replace("it ended.", "it ended early.")
    write(train, sha(rewritten) + "\n", name=".config/changelog-released.sha256")
    commit(train, log("", released=rewritten), "train: rewrite on purpose")
    merge_car(train)
    write(train, log(sections(Added=D), released=rewritten))
    assert run(train) == 0


def test_failure_a_merge_that_puts_the_entry_into_the_oldest_release_is_refused(train):
    merge_car(train)
    write(train, log("", released=NEW_SECTION + OLD.replace("### Fixed\n\n", "### Fixed\n\n" + D)))
    assert run(train) == 1


def test_edge_an_index_without_a_changelog_is_exit_2_during_a_merge(train, capsys):
    merge_car(train)
    git(train, "rm", "-q", "--cached", "CHANGELOG.md")
    assert run(train) == 2 and "the index" in capsys.readouterr().err


def test_edge_the_hook_still_calls_the_gate_without_a_base():
    # The fix is in the script's choice of bases, so the hook and CI keep
    # their one command.
    assert "elif CHANGELOG_OUT=$(" + COMMAND + " 2>&1); then" in hook_step()
    assert ci_step().rstrip().endswith("run: " + COMMAND)


def test_edge_the_docstring_states_the_released_rule_for_every_parent():
    doc = cm.__doc__
    assert "HEAD" in doc and "MERGE_HEAD" in doc and "every" in doc
