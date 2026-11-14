# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/check-changelog-size-claims.py: a size claim carries its numbers."""

import subprocess
import sys

import pytest

from conftest import SCRIPTS, load

claims = load("check-changelog-size-claims")
SCRIPT = SCRIPTS / "check-changelog-size-claims.py"
REPO = SCRIPTS.parent

HEADER = "# Changelog\n\nAll notable changes.\n\n"
RELEASED = "## [0.5.254] - 2026-11-14\n\n### Changed\n\n- An older change.\n"

# The sentence of the 0.5.254 entry, as it was released.
AS_RELEASED = (
    "  - The cost, in a release build on aarch64: encoding 2,000 heartbeats took 9.8 ms "
    "against 3.7 ms. The aarch64 gnu binary is 655,456 bytes larger. The static musl builds "
    "and the `-noaudio` packages do not carry the history store and are the same size."
)
WHAT = "without two byte counts of seven digits or more, or a release.yml run number"


def log(*lines, released=RELEASED):
    """A changelog whose [Unreleased] section holds `lines` under Changed."""
    body = "\n".join(lines)
    return f"{HEADER}## [Unreleased]\n\n### Changed\n\n{body}\n\n{released}"


def test_the_sentence_of_0_5_254_in_unreleased_is_a_fault():
    found = claims.faults(log("- **Compressed history files.** Text.", AS_RELEASED))
    assert found == [f"10: `bytes larger` {WHAT}, in the same bullet"], (
        "the released sentence has one byte count and no run number")


FAULTY = [
    "- The musl build is the same size.",
    "- The musl build is the SAME SIZE as before.",
    "- The binary is no larger.",
    "- The binary is 4,096 bytes larger.",
    "- The binary is 12 bytes smaller.",
    "- The binary is 655,456 bytes larger than 0.5.253.",
    "- The aarch64 gnu binary (27,693,832 bytes) is 589,920 bytes larger.",
    "- Same size on every target, as run 123 shows.",
    "- The binary is no larger, see the release page.",
    "- The package is the same size; the tarball is 1,000,000 bytes.",
    "- **Bold.** The binary is 2 MB and the same size as before.",
    "- The binary is 999,999 bytes and was 999,998 bytes, so it is 1 bytes larger.",
    "- The static builds are the same size (25 MB ceiling).",
    "  - A nested bullet: the same size.",
]


@pytest.mark.parametrize("bullet", FAULTY)
def test_a_claim_without_its_numbers_is_a_fault(bullet):
    found = claims.faults(log(bullet))
    assert len(found) == 1 and found[0].startswith("9: `"), (
        f"one fault at line 9 for {bullet!r}, got {found}")
    assert WHAT in found[0], f"the fault says what is missing: {found}"


SOUND = [
    "- The x86_64 musl binary is the same size: 25,385,600 bytes before and 25,385,600 after.",
    "- The binary is 4,096 bytes larger (25,385,600 and 25,389,696 bytes).",
    "- The binary is 4096 bytes larger (25385600 and 25389696 bytes).",
    "- The binary is no larger: release.yml run 43581489173 printed the sizes.",
    "- The binary is 8 bytes smaller (runs 43511633588 and 43581489173).",
    "- The binary is the same size, see run 43581489173.",
    "- aarch64 gnu 27,103,912 and 27,693,832 bytes (+589,920): 589,920 bytes larger.",
    "- The old entry said \"are the same size\". Measured: 20,944,840 and 20,944,840 bytes.",
    "- No larger. 1,234,567 then 1,234,567.",
    "- Same size on both targets (20,944,840 / 20,944,840).",
    "- The file is 655,456 bytes larger: 26,447,712 against 27,103,168 bytes.",
    "- The binary is 4,096 bytes larger.\n  Sizes: 25,385,600 and 25,389,696 bytes.",
    "- A bullet with no claim about bytes at all.",
    "- The page loads in the same time.",
    "- 16 MiB is the ceiling; nothing here is about a comparison.",
    "- The history files are smaller: 887,305 bytes became 62,048.",
]


@pytest.mark.parametrize("bullet", SOUND)
def test_a_claim_with_its_numbers_and_a_bullet_without_a_claim_pass(bullet):
    assert claims.faults(log(bullet)) == [], f"no fault for {bullet!r}"


@pytest.mark.parametrize("phrase", ["same size", "no larger", "bytes larger", "bytes smaller"])
def test_each_phrase_is_named_in_its_fault(phrase):
    found = claims.faults(log(f"- The binary: {phrase}."))
    assert found == [f"9: `{phrase}` {WHAT}, in the same bullet"], (
        f"the fault names the phrase {phrase!r}")


def test_a_bullet_with_two_claims_has_one_fault_that_names_the_first():
    found = claims.faults(log("- It is 9 bytes larger and the musl build is the same size."))
    assert found == [f"9: `bytes larger` {WHAT}, in the same bullet"], (
        "one fault for one bullet, naming the claim that comes first in the text")


def test_the_numbers_of_another_bullet_do_not_count():
    found = claims.faults(log(
        "- Sizes: 25,385,600 and 25,389,696 bytes.",
        "- The binary is the same size.",
    ))
    assert found == [f"10: `same size` {WHAT}, in the same bullet"], (
        "the second bullet has no number of its own")


def test_a_nested_bullet_is_a_bullet_of_its_own():
    found = claims.faults(log(
        "- **Entry.** 25,385,600 and 25,389,696 bytes.",
        "  - The static builds are the same size.",
        "  - A third bullet with run 43581489173.",
    ))
    assert found == [f"10: `same size` {WHAT}, in the same bullet"], (
        "the parent's numbers and the sibling's run number are not the nested bullet's")


def test_every_faulty_bullet_is_reported_in_line_order():
    found = claims.faults(log(
        "- The binary is no larger.",
        "- Fine: 1,000,000 and 1,000,001 bytes, 1 bytes larger.",
        "- The package is the same size.",
    ))
    assert [fault.split(":")[0] for fault in found] == ["9", "11"], (
        f"lines 9 and 11, not the bullet between them: {found}")


def test_a_released_section_is_not_checked():
    released = "## [0.5.254] - 2026-11-14\n\n### Changed\n\n" + AS_RELEASED + "\n"
    assert claims.faults(log("- A change.", released=released)) == [], (
        "a released section is history: the correction goes into [Unreleased]")


def test_a_changelog_without_an_unreleased_section_has_no_fault():
    text = HEADER + "## [0.5.254] - 2026-11-14\n\n- The binary is the same size.\n"
    assert claims.faults(text) == [], "right after a release there is no [Unreleased]"


def test_the_unreleased_section_ends_at_the_next_release_heading():
    lines = claims.unreleased(log("- One.", "- Two."))
    assert [number for number, _ in lines][:1] == [6], "the first line after the heading"
    assert all("0.5.254" not in line and "older change" not in line for _, line in lines), (
        "no line of the released section")
    assert [line for _, line in lines if line.startswith("- ")] == ["- One.", "- Two."], (
        "both bullets of the section")


def test_a_second_unreleased_section_a_merge_left_is_checked_too():
    second = RELEASED + "\n## [Unreleased]\n\n- The binary is no larger.\n"
    found = claims.faults(log("- A change.", released=second))
    assert found == [f"19: `no larger` {WHAT}, in the same bullet"], (
        f"the bullet of the second section, after a released one: {found}")


def test_an_empty_unreleased_section_has_no_fault():
    assert claims.faults(HEADER + "## [Unreleased]\n\n" + RELEASED) == [], "nothing to check"


def test_an_unreleased_section_at_the_end_of_the_file_is_checked():
    text = HEADER + "## [Unreleased]\n\n- The binary is the same size."
    assert claims.faults(text) == [f"7: `same size` {WHAT}, in the same bullet"], (
        "a section the file ends in, with no newline after its last bullet")


def test_a_bullet_ends_at_a_blank_line_a_heading_or_the_next_bullet():
    lines = [(1, "- First"), (2, "  continues"), (3, ""), (4, "25,385,600 and 25,389,696"),
             (5, "- Second"), (6, "### Fixed"), (7, "- Third"), (8, "  - Nested")]
    assert claims.bullets(lines) == [
        (1, "- First\n  continues"), (5, "- Second"), (7, "- Third"), (8, "  - Nested"),
    ], "four bullets; the paragraph after the blank line belongs to none"


@pytest.mark.parametrize("bullet,expected", [
    ("25,385,600 and 25,389,696", True),
    ("25385600 and 25389696", True),
    ("1,000,000 and 1,000,000", True),
    ("run 43581489173", True),
    ("runs 43511633588 and 43581489173", True),
    ("release.yml run 435814891", True),
    ("25,385,600 alone", False),
    ("999,999 and 999,998", False),
    ("655,456 and 4,096 and 7,488", False),
    ("run 123", False),
    ("the 2026-11-14 run", False),
    ("25,385,600 and run 12", False),
    ("", False),
])
def test_evidence_is_two_long_byte_counts_or_a_run_number(bullet, expected):
    assert claims.evidence(bullet) is expected, f"evidence in {bullet!r}"


def test_the_real_changelog_has_no_size_claim_without_its_numbers():
    text = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    assert claims.faults(text) == [], (
        "a bullet of [Unreleased] claims a size without the two sizes or a release.yml run; "
        "docs/internals/build-ci-release.md, \"The changelog\", says where the numbers come from")


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True,
                          check=False)


def test_the_command_exits_0_on_a_sound_changelog(tmp_path):
    path = tmp_path / "CHANGELOG.md"
    path.write_text(log(SOUND[0]), encoding="utf-8")
    done = run(str(path))
    assert (done.returncode, done.stdout) == (0, ""), f"no fault, no output: {done}"


def test_the_command_exits_1_and_names_file_line_and_phrase(tmp_path):
    path = tmp_path / "CHANGELOG.md"
    path.write_text(log(AS_RELEASED), encoding="utf-8")
    done = run(str(path))
    assert done.returncode == 1, f"a fault is exit 1: {done}"
    assert done.stdout == f"CHANGELOG.md:9: `bytes larger` {WHAT}, in the same bullet\n", (
        f"file, line and phrase: {done.stdout!r}")


def test_the_command_exits_2_when_the_file_is_not_there(tmp_path):
    done = run(str(tmp_path / "absent.md"))
    assert done.returncode == 2 and "absent.md" in done.stderr, (
        f"a file that cannot be read is not a pass: {done}")


def test_the_command_reads_the_repository_changelog_by_default():
    done = run()
    assert done.returncode == 0, f"the tree's own CHANGELOG.md passes: {done.stdout}"
