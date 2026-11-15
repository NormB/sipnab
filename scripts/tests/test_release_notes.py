# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The text of a GitHub release starts with the release's CHANGELOG section.

release.yml wrote the release text from the download table and GitHub's
generated notes, one line for each merged pull request. The CHANGELOG section
of the release, which holds what an operator must do before an upgrade, was
not on the release page (RELEASE-TEXT-LACKS-THE-CHANGELOG). scripts/
release-notes.py prints that section with its relative links made absolute to
the repository at the tag, and release.yml puts it first.
"""

import pathlib
import re
import subprocess
import sys

import pytest
from conftest import load

rn = load("release-notes")

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release-notes.py"
REPO = "example/sipnab"
AT = "https://github.com/example/sipnab/blob/v1.0.0"

CHANGELOG = """# Changelog

All notable changes are recorded here.

## [Unreleased]

### Fixed

- Not released yet.

## [0.4.4] - 2026-11-12

There is no downgrade from 0.4.4.

### Security

- **A dependency is updated.**
  - Effect: the advisory no longer applies.

### Added

- Key expiry. See the [upgrade page][upgrade].

## [0.4.3] - 2026-11-09

### Fixed

- A fix of 0.4.3.

## [0.4.10] - 2026-11-01

### Added

- A feature of 0.4.10.

## [0.1.0] - 2026-09-01

- The first release.

[Unreleased]: https://github.com/example/sipnab/compare/v0.4.4...HEAD
[upgrade]: https://example.com/docs/upgrading/
"""


def section(version, changelog=CHANGELOG):
    return rn.section(changelog, version)


def refusal(function, *arguments):
    """The message of the Refused that the call raises."""
    with pytest.raises(rn.Refused) as refused:
        function(*arguments)
    return str(refused.value)


def one(body):
    """A changelog whose version 1.0.0 holds `body`."""
    return f"## [1.0.0] - 2026-01-01\n\n{body}\n\n## [0.9.0] - 2025-12-01\n\n- Older.\n"


def of(body):
    """The section of 1.0.0, links as the changelog writes them."""
    return rn.section(one(body), "1.0.0")


def notes_of(body, version="1.0.0", repo=REPO):
    """The release text of a changelog whose one version holds `body`,
    without the newline at its end."""
    changelog = f"## [{version}] - 2026-01-01\n\n{body}\n\n## [0.9.0] - 2025-12-01\n\n- Older.\n"
    text = rn.notes(changelog, version, repo)
    assert text.endswith("\n") and not text.endswith("\n\n"), repr(text[-5:])
    return text[:-1]


def run(arguments, tmp_path, changelog=CHANGELOG):
    if changelog is not None:
        (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), *arguments],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


# ---------------------------------------------------------------- success


def test_the_section_of_a_version_is_the_text_under_its_heading():
    assert section("0.4.3") == "### Fixed\n\n- A fix of 0.4.3."


def test_the_section_ends_at_the_next_version():
    text = section("0.4.4")
    assert text.startswith("There is no downgrade from 0.4.4."), text
    assert text.endswith("- Key expiry. See the [upgrade page](https://example.com/docs/upgrading/)."), text
    assert "0.4.3" not in text


def test_the_subheadings_of_the_section_are_kept():
    text = section("0.4.4")
    assert "### Security\n" in text
    assert "### Added\n" in text


def test_the_heading_of_the_version_is_left_out():
    text = section("0.4.4")
    assert "## [0.4.4]" not in text
    assert text.split("\n")[0] == "There is no downgrade from 0.4.4."


def test_a_version_is_matched_whole():
    assert section("0.4.10") == "### Added\n\n- A feature of 0.4.10."


def test_a_version_that_is_the_start_of_another_is_not_confused_with_it():
    changelog = "## [0.4.10] - 2026-11-01\n\n- Ten.\n\n## [0.4.1] - 2026-10-01\n\n- One.\n"
    assert rn.section(changelog, "0.4.1") == "- One."


def test_the_unreleased_section_is_not_a_versions():
    assert "Not released yet" not in section("0.4.4")
    assert "Not released yet" not in "".join(text for _, text in rn.every_release_text(CHANGELOG, REPO))
    assert len(list(rn.every_release_text(CHANGELOG, REPO))) == 4


def test_a_pre_release_version_has_a_section_of_its_own():
    changelog = "## [1.0.0-rc.1] - 2026-01-01\n\n- A candidate.\n\n## [0.9.0] - 2025-12-01\n\n- Old.\n"
    assert rn.section(changelog, "1.0.0-rc.1") == "- A candidate."


def test_the_versions_are_listed_in_the_order_of_the_file():
    assert rn.versions(CHANGELOG) == ["0.4.4", "0.4.3", "0.4.10", "0.1.0"]


def test_an_entry_in_outline_form_is_copied_as_it_is():
    entry = (
        "### Changed\n\n"
        "- **Commands that listen no longer stay root.**\n"
        "  - Effect: `sipnab fleet serve` runs as `--user`.\n"
        "  - Do: Give the path to that user (`chown -R nobody /var/lib/sipnab`)."
    )
    assert notes_of(entry) == entry


def test_a_paragraph_of_three_lines_is_one_line():
    assert of("The upgrade is\nthe binary\nalone.") == "The upgrade is the binary alone."


def test_a_list_item_of_three_lines_is_one_line():
    assert of("- **New keys.** A key\n  expires 90 days\n  after it is made.") == (
        "- **New keys.** A key expires 90 days after it is made."
    )


def test_each_list_item_keeps_its_own_line():
    assert of("- One\n  more.\n- Two\n  more.") == "- One more.\n- Two more."


def test_a_numbered_item_of_two_lines_is_one_line():
    assert of("1. Stop\n   the server.\n2. Copy\n   the data.") == "1. Stop the server.\n2. Copy the data."


def test_a_relative_link_points_at_the_repository_at_the_tag():
    assert notes_of("- Docs: [Least privilege](docs/least-privilege.md).") == (
        f"- Docs: [Least privilege]({AT}/docs/least-privilege.md)."
    )


def test_a_relative_link_keeps_its_anchor():
    assert notes_of("- [Run the center](docs/fleet.md#run-the-center-as-a-service).") == (
        f"- [Run the center]({AT}/docs/fleet.md#run-the-center-as-a-service)."
    )


def test_a_link_to_a_file_at_the_top_of_the_repository_is_absolute():
    assert notes_of("- See [contributing](CONTRIBUTING.md#code-review).") == (
        f"- See [contributing]({AT}/CONTRIBUTING.md#code-review)."
    )


def test_two_links_on_one_line_are_both_absolute():
    assert notes_of("- Docs: [A](docs/a.md) and [B](docs/b.md#b).") == (
        f"- Docs: [A]({AT}/docs/a.md) and [B]({AT}/docs/b.md#b)."
    )


def test_a_link_whose_text_is_code_is_absolute():
    assert notes_of("- See [`sipnab fleet serve`](docs/fleet.md).") == f"- See [`sipnab fleet serve`]({AT}/docs/fleet.md)."


def test_a_link_by_reference_is_written_in_full_and_absolute():
    changelog = "## [1.0.0] - 2026-01-01\n\n- See the [fleet page][fleet].\n\n[fleet]: docs/fleet.md\n"
    assert rn.notes(changelog, "1.0.0", REPO) == f"- See the [fleet page]({AT}/docs/fleet.md).\n"


def test_the_link_names_the_repository_and_the_version_given():
    text = notes_of("- [A](docs/a.md).", version="2.3.4", repo="other/fork")
    assert text == "- [A](https://github.com/other/fork/blob/v2.3.4/docs/a.md)."


def test_the_notes_end_with_one_newline():
    text = rn.notes(CHANGELOG, "0.4.3", REPO)
    assert text == "### Fixed\n\n- A fix of 0.4.3.\n"


def test_the_command_prints_the_notes(tmp_path):
    result = run(["0.4.3", "--repo", REPO], tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "### Fixed\n\n- A fix of 0.4.3.\n"
    assert result.stderr == "", "nothing else is written"


def test_the_command_reads_the_changelog_it_is_given(tmp_path):
    other = tmp_path / "other.md"
    other.write_text("## [2.0.0] - 2027-01-01\n\n- Two, see [a](docs/a.md).\n", encoding="utf-8")
    result = run(["2.0.0", "--repo", REPO, "--changelog", str(other)], tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "- Two, see [a](https://github.com/example/sipnab/blob/v2.0.0/docs/a.md).\n"


# ---------------------------------------------------------------- failure


def test_a_version_with_no_section_is_refused():
    assert refusal(section, "9.9.9") == "CHANGELOG.md has no section `## [9.9.9] - <date>`"


def test_the_unreleased_section_is_refused_as_a_version():
    assert "is not a version" in refusal(section, "Unreleased")


def test_a_version_with_a_v_in_front_is_refused():
    assert refusal(section, "v0.4.4") == "`v0.4.4` is not a version: give it as Cargo.toml has it, such as 0.5.256"


@pytest.mark.parametrize("version", ["", "0.4..", ".*", "0.4", "0.4.4 ", "0.4.4\n"])
def test_a_text_that_is_not_a_version_is_refused(version):
    assert "is not a version" in refusal(section, version)


def test_a_development_version_is_refused():
    assert "has no section" in refusal(section, "0.4.4-dev.0123456789ab")


def test_a_section_with_no_text_is_refused():
    changelog = "## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-12-01\n\n- Old.\n"
    assert refusal(rn.section, changelog, "1.0.0") == "the section `## [1.0.0]` of CHANGELOG.md is empty"


def test_a_section_with_only_subheadings_is_refused():
    changelog = "## [1.0.0] - 2026-01-01\n\n### Added\n\n### Fixed\n\n## [0.9.0] - 2025-12-01\n\n- Old.\n"
    assert "is empty" in refusal(rn.section, changelog, "1.0.0")


def test_a_section_of_headings_with_no_blank_line_is_refused():
    changelog = "## [1.0.0] - 2026-01-01\n\n### Added\n### Fixed\n"
    assert "is empty" in refusal(rn.section, changelog, "1.0.0")


def test_two_sections_for_one_version_are_refused():
    changelog = "## [1.0.0] - 2026-01-01\n\n- One.\n\n## [1.0.0] - 2026-01-02\n\n- Again.\n"
    assert refusal(rn.section, changelog, "1.0.0") == "CHANGELOG.md has 2 sections `## [1.0.0]`"


def test_a_heading_without_a_date_is_not_the_versions_section():
    assert "has no section" in refusal(rn.section, "## [1.0.0]\n\n- One.\n", "1.0.0")


def test_a_heading_of_another_level_is_not_the_versions_section():
    assert "has no section" in refusal(rn.section, "### [1.0.0] - 2026-01-01\n\n- One.\n", "1.0.0")


def test_an_empty_changelog_is_refused():
    assert "has no section" in refusal(rn.section, "", "1.0.0")


@pytest.mark.parametrize("repo", ["", "sipnab", "a/b/c", "a b/c", "a/b --notes x", "https://github.com/a/b"])
def test_a_repository_that_is_not_owner_and_name_is_refused(repo):
    assert refusal(rn.notes, CHANGELOG, "0.4.4", repo) == f"`{repo}` is not a repository: give it as owner/name"


def test_a_section_longer_than_the_bound_is_refused():
    changelog = "## [1.0.0] - 2026-01-01\n\n" + "- A line of the section.\n" * 6000
    said = refusal(rn.notes, changelog, "1.0.0", REPO)
    assert f"at most {rn.BOUND}" in said, said
    assert "shorten the section" in said, said


def test_the_bound_counts_the_absolute_links():
    # 1,900 short links are under the bound as the changelog writes them
    # and over it once each holds the address of the repository at the tag.
    changelog = "## [1.0.0] - 2026-01-01\n\n" + "- [a](docs/a.md)\n" * 1900
    assert len(rn.section(changelog, "1.0.0")) < rn.BOUND
    assert "at most" in refusal(rn.notes, changelog, "1.0.0", REPO)


def test_a_link_that_leaves_the_repository_is_refused():
    said = refusal(rn.notes, one("- See [the neighbor](../other/README.md)."), "1.0.0", REPO)
    assert said == "the link target `../other/README.md` leaves the repository: write it from the repository's top"


def test_a_link_with_a_parent_step_in_the_middle_is_refused():
    assert "leaves the repository" in refusal(rn.notes, one("- [x](docs/../../x.md)."), "1.0.0", REPO)


def test_a_link_target_in_angle_brackets_is_refused():
    said = refusal(rn.notes, one("- See [a page](<docs/a page.md>)."), "1.0.0", REPO)
    assert said == "the link target `<docs/a page.md>` is in angle brackets: write it without them"


def test_a_version_with_no_section_fails_and_prints_no_notes(tmp_path):
    result = run(["9.9.9", "--repo", REPO], tmp_path)
    assert result.returncode == 1, "no section, no release text"
    assert result.stdout == "", "nothing a release could be made from"
    assert result.stderr == "release-notes: CHANGELOG.md has no section `## [9.9.9] - <date>`\n"


def test_an_empty_section_fails_and_prints_no_notes(tmp_path):
    changelog = "## [1.0.0] - 2026-01-01\n\n### Added\n\n## [0.9.0] - 2025-12-01\n\n- Old.\n"
    result = run(["1.0.0", "--repo", REPO], tmp_path, changelog)
    assert result.returncode == 1, result.stderr
    assert result.stdout == "", "nothing a release could be made from"
    assert result.stderr == "release-notes: the section `## [1.0.0]` of CHANGELOG.md is empty\n"


def test_a_missing_changelog_fails(tmp_path):
    result = run(["0.4.4", "--repo", REPO], tmp_path, changelog=None)
    assert result.returncode == 1, "no file to read"
    assert result.stdout == "", "no notes"
    assert "release-notes: CHANGELOG.md:" in result.stderr


@pytest.mark.parametrize(
    "arguments",
    [[], ["0.4.4"], ["--repo", REPO], ["0.4.4", "--repo"], ["0.4.4", "0.4.3", "--repo", REPO]],
)
def test_a_missing_argument_is_a_usage_error(arguments, tmp_path):
    result = run(arguments, tmp_path)
    assert result.returncode == 2, result.stderr
    assert result.stdout == "", "no notes"
    assert "usage: release-notes.py VERSION --repo OWNER/NAME [--changelog PATH]" in result.stderr


def test_an_option_given_twice_is_a_usage_error(tmp_path):
    result = run(["0.4.3", "--repo", REPO, "--repo", "other/fork"], tmp_path)
    assert result.returncode == 2, "which repository is meant is not guessed"
    assert result.stdout == "", "no notes"


def test_an_unknown_option_is_a_usage_error(tmp_path):
    result = run(["0.4.4", "--repo", REPO, "--draft"], tmp_path)
    assert result.returncode == 2, result.stderr
    assert result.stdout == "", "no notes"


def test_a_changelog_that_is_not_utf_8_fails(tmp_path):
    other = tmp_path / "other.md"
    other.write_bytes(b"## [2.0.0] - 2027-01-01\n\n- \xff\n")
    result = run(["2.0.0", "--repo", REPO, "--changelog", str(other)], tmp_path)
    assert result.returncode == 1, "not text"
    assert result.stdout == "", "no notes"
    assert "not UTF-8 text" in result.stderr


# ------------------------------------------------------------------- edge


def test_blank_lines_around_the_section_are_dropped():
    changelog = "## [1.0.0] - 2026-01-01\n\n\n\n- One.\n\n\n\n## [0.9.0] - 2025-12-01\n\n- Old.\n"
    assert rn.section(changelog, "1.0.0") == "- One."


def test_a_blank_line_inside_the_section_is_kept():
    assert of("First.\n\nSecond.") == "First.\n\nSecond."


def test_windows_line_ends_are_read():
    changelog = "## [1.0.0] - 2026-01-01\r\n\r\n- One\r\n  more.\r\n\r\n## [0.9.0] - 2025-12-01\r\n\r\n- Old.\r\n"
    assert rn.section(changelog, "1.0.0") == "- One more."


def test_a_heading_shown_in_a_code_block_does_not_end_the_section():
    body = "```text\n## [0.9.0] - not a heading\n```\n\n- After."
    assert of(body) == body


def test_the_last_section_ends_at_the_link_definitions():
    assert section("0.1.0") == "- The first release."


def test_a_link_shown_in_a_code_span_is_not_rewritten():
    body = "- Write `[page](docs/page.md)` to link a page."
    assert notes_of(body) == body


def test_a_link_shown_in_a_code_block_is_not_rewritten():
    body = "- Write:\n\n```text\n[page](docs/page.md)\n```"
    assert notes_of(body) == body


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com/a",
        "http://example.com/a#b",
        "mailto:security@example.com",
        "//example.com/a",
    ],
)
def test_a_target_that_is_already_absolute_is_left_as_it_is(target):
    body = f"- See [this]({target})."
    assert notes_of(body) == body


def test_a_link_to_an_anchor_alone_points_into_the_changelog_at_the_tag():
    assert notes_of("- See [above](#added).") == f"- See [above]({AT}/CHANGELOG.md#added)."


def test_a_target_that_starts_with_a_dot_step_is_written_from_the_top():
    assert notes_of("- [A](./docs/a.md).") == f"- [A]({AT}/docs/a.md)."


def test_a_target_that_starts_with_a_slash_is_read_from_the_top_of_the_repository():
    assert notes_of("- [A](/docs/a.md#x).") == f"- [A]({AT}/docs/a.md#x)."


def test_the_title_of_a_link_is_kept():
    assert notes_of('- [A](docs/a.md "The A page").') == f'- [A]({AT}/docs/a.md "The A page").'


def test_an_image_points_at_the_file_itself():
    assert notes_of("![The screen](docs/images/screen.png)") == (
        "![The screen](https://github.com/example/sipnab/raw/v1.0.0/docs/images/screen.png)"
    )


def test_a_pre_release_tag_is_named_in_the_link():
    text = notes_of("- [A](docs/a.md).", version="1.0.0-rc.1")
    assert text == "- [A](https://github.com/example/sipnab/blob/v1.0.0-rc.1/docs/a.md)."


def test_an_inline_link_that_breaks_across_lines_is_one_absolute_link():
    assert notes_of("- The\n  [terminal UI\n  page](docs/tui.md) lists\n  each screen.") == (
        f"- The [terminal UI page]({AT}/docs/tui.md) lists each screen."
    )


def test_brackets_with_no_definition_are_left_as_they_are():
    body = "- An array `[1, 2]` and [words] and [a][b]."
    assert notes_of(body) == body


def test_a_section_at_the_bound_passes_and_one_character_more_does_not():
    at = "## [1.0.0] - 2026-01-01\n\n" + "x" * rn.BOUND + "\n"
    assert len(rn.notes(at, "1.0.0", REPO)) == rn.BOUND + 1, "the text and the newline at its end"
    over = "## [1.0.0] - 2026-01-01\n\n" + "x" * (rn.BOUND + 1) + "\n"
    assert f"is {rn.BOUND + 1} characters" in refusal(rn.notes, over, "1.0.0", REPO)


def test_the_bound_leaves_room_under_what_a_release_holds():
    assert rn.BOUND == 100000
    assert rn.GITHUB_LIMIT == 125000
    assert rn.BOUND < rn.GITHUB_LIMIT


# The six tarballs a release builds, as ops/release/test-platform-table.sh
# names them.
TARBALLS = [
    f"sipnab-9.9.9-{target}.tar.gz"
    for target in (
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    )
]


def download_table(tmp_path):
    """What ops/release/platform-table.sh prints for a release's six
    tarballs."""
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    for name in TARBALLS:
        (artifacts / name).touch()
    result = subprocess.run(
        ["bash", str(ROOT / "ops" / "release" / "platform-table.sh"), str(artifacts)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("### Which download do I want?"), result.stdout[:80]
    return result.stdout


def test_the_action_cuts_a_release_text_one_character_under_what_github_holds():
    # softprops/action-gh-release cuts the text it sends, the file and the
    # generated notes after it, to this many characters.
    assert rn.ACTION_CUT == 124999
    assert rn.ACTION_CUT == rn.GITHUB_LIMIT - 1


def test_the_largest_section_and_the_table_stay_far_under_the_cut(tmp_path):
    # release-body.md is the section, a blank line and the table. A text
    # over the cut would lose its end without an error, so the file of the
    # largest section is held under it with room for the generated notes.
    table = download_table(tmp_path)
    changelog = real_changelog()
    largest = max(len(text) for _, text in rn.every_release_text(changelog, "NormB/sipnab"))
    body = largest + len("\n") + len(table)
    assert body < rn.ACTION_CUT // 2, f"release-body.md would be {body} characters of {rn.ACTION_CUT}"


def test_any_section_the_script_accepts_leaves_the_table_under_the_cut(tmp_path):
    # The bound, not today's largest section, is what holds a future one.
    table = download_table(tmp_path)
    room = rn.ACTION_CUT - (rn.BOUND + len("\n") + len(table))
    assert room >= 20000, f"{room} characters are left for the generated notes"


def test_the_rows_of_a_table_stay_apart():
    table = "| Key | Does |\n|---|---|\n| `q` | quits |"
    assert of(table) == table


def test_the_lines_of_a_code_block_stay_as_they_are():
    body = "Run:\n\n```sh\nline one\nline two\n```"
    assert of(body) == body


def test_text_around_a_code_block_is_not_joined_to_its_fences():
    assert of("Run\nthis:\n```sh\nline one\n```\nThen\nwait.") == "Run this:\n```sh\nline one\n```\nThen wait."


def test_the_lines_of_a_quote_stay_apart():
    assert of("> One.\n> Two.") == "> One.\n> Two."


def test_a_line_that_ends_with_a_backslash_keeps_its_break():
    assert of("One\\\ntwo.") == "One\\\ntwo."


def test_a_line_that_ends_with_two_spaces_keeps_its_break():
    assert of("One  \ntwo.") == "One  \ntwo."


def test_a_nested_item_keeps_its_line_and_its_indent():
    assert of("- Outer\n  text.\n  - Inner\n    text.\n- Next.") == "- Outer text.\n  - Inner text.\n- Next."


def test_a_line_under_a_heading_with_no_blank_line_stays_under_it():
    assert of("### Fixed\n- A fix.") == "### Fixed\n- A fix."
    assert of("### Fixed\nText\nof two lines.") == "### Fixed\nText of two lines."


def test_a_word_that_starts_with_a_dash_or_a_digit_is_joined():
    assert of("The flag is\n--no-expiry and the port\n8443. is it.") == "The flag is --no-expiry and the port 8443. is it."


def test_the_spaces_at_the_end_of_a_joined_line_are_not_doubled():
    assert of("One \nmore.") == "One more."


def test_the_lines_of_an_indented_code_block_stay_as_they_are():
    body = "Run:\n\n    line one\n    line two"
    assert of(body) == body


def test_a_dated_heading_that_is_not_a_version_starts_no_section():
    changelog = "## [Next] - 2027-01-01\n\n- Planned.\n\n## [1.0.0] - 2026-01-01\n\n- One.\n"
    assert rn.versions(changelog) == ["1.0.0"]
    assert [text for _, text in rn.every_release_text(changelog, REPO)] == ["- One.\n"]


def test_a_link_definition_shown_in_a_code_block_is_text_of_the_section():
    body = "- Write [page] and define it:\n\n```text\n[page]: https://example.com/shown\n```"
    assert of(body) == body


def test_the_name_of_a_reference_is_read_without_regard_to_case():
    changelog = "## [1.0.0] - 2026-01-01\n\n- See [the page][Page] and [page].\n\n[page]: https://example.com/page\n"
    assert rn.section(changelog, "1.0.0") == (
        "- See [the page](https://example.com/page) and [page](https://example.com/page)."
    )


# --------------------------------------- the repository's own files


def real_changelog():
    return (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def outside_code(text):
    """`text` without its code blocks and code spans."""
    kept = []
    fenced = False
    for line in text.split("\n"):
        if re.match(r" {0,3}(```|~~~)", line):
            fenced = not fenced
            continue
        if not fenced:
            kept.append(re.sub(r"`+[^`]*`+", "", line))
    return "\n".join(kept)


def test_every_section_of_the_changelog_makes_a_release_text():
    # A section that cannot be made into a release text fails here, in a
    # pull request, and not at the tag.
    changelog = real_changelog()
    versions = rn.versions(changelog)
    assert len(versions) >= 276, len(versions)
    for version, text in rn.every_release_text(changelog, "NormB/sipnab"):
        assert text.strip(), version
    assert [version for version, _ in rn.every_release_text(changelog, "NormB/sipnab")] == versions


def test_the_largest_section_of_the_changelog_is_under_the_bound():
    changelog = real_changelog()
    sizes = sorted(((len(text), version) for version, text in rn.every_release_text(changelog, "NormB/sipnab")), reverse=True)
    largest, version = sizes[0]
    assert largest <= rn.BOUND, f"the section of {version} is {largest} characters"
    assert largest > 30000, f"the census read {largest} for {version}: the sections are no longer measured"


def test_no_link_of_any_release_text_is_relative():
    changelog = real_changelog()
    texts = list(rn.every_release_text(changelog, "NormB/sipnab"))
    assert len(texts) >= 276, len(texts)
    for version, text in texts:
        for target in re.findall(r"\]\((\S+?)[\s)]", outside_code(text)):
            assert re.match(r"[A-Za-z][A-Za-z0-9+.-]*:|//", target), f"{version}: `{target}` is relative"


def test_the_links_of_the_newest_release_name_its_tag():
    changelog = real_changelog()
    newest = rn.versions(changelog)[0]
    text = rn.notes(changelog, newest, "NormB/sipnab")
    assert text.startswith("### "), text[:80]
    assert f"](https://github.com/NormB/sipnab/blob/v{newest}/docs/" in text, "its docs links are at its tag"


def test_the_command_makes_the_text_of_the_newest_release_from_the_repository(tmp_path):
    changelog = real_changelog()
    newest = rn.versions(changelog)[0]
    result = subprocess.run(
        [sys.executable, "-I", "scripts/release-notes.py", newest, "--repo", "NormB/sipnab"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == rn.notes(changelog, newest, "NormB/sipnab")


def job(name, following):
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    return workflow.split(f"\n  {name}:\n", 1)[1].split(f"\n  {following}:\n", 1)[0]


def step(job_text, name):
    """The text of the step `name`, to the next step of the job."""
    return job_text.split(f"      - name: {name}\n", 1)[1].split("\n      - ", 1)[0]


SECTION_COMMAND = 'python3 -I scripts/release-notes.py "${GITHUB_REF_NAME#v}" --repo "$GITHUB_REPOSITORY"'


def test_the_release_text_starts_with_the_section_and_then_holds_the_table():
    text = step(job("release", "crates-io"), "Render the release text")
    section_line = f"{SECTION_COMMAND} > release-body.md\n"
    table_line = "bash ops/release/platform-table.sh artifacts >> release-body.md\n"
    assert section_line in text, text
    assert table_line in text, text
    assert text.index(section_line) < text.index(table_line), "the section is first"
    assert len(re.findall(r"(?<!>)> release-body\.md", text)) == 1, "one command starts the file, the others add to it"


def test_a_failed_part_of_the_release_text_fails_its_step():
    text = step(job("release", "crates-io"), "Render the release text")
    lines = [line.strip() for line in text.split("\n")]
    assert lines[lines.index("run: |") + 1] == "set -euo pipefail", "the first failure ends the step"
    assert "|| true" not in text and "continue-on-error" not in text, text


def test_the_release_text_is_written_before_the_release_is_published():
    release = job("release", "crates-io")
    assert release.index("      - name: Render the release text\n") < release.index("      - name: Create GitHub Release\n")
    publish = step(release, "Create GitHub Release")
    assert "          body_path: release-body.md\n" in publish, publish
    assert "          generate_release_notes: true\n" in publish, "the pull request titles stay, after the file"
    assert release.count("release-body.md") == 4, "the section, the blank line, the table and the publish step"


def test_a_tag_with_no_changelog_section_stops_the_release_before_the_builds():
    preflight = job("preflight", "build")
    text = step(preflight, "Check that the release has its CHANGELOG section")
    assert "        if: startsWith(github.ref, 'refs/tags/v')\n" in text, "a run by hand is not a release"
    assert text.rstrip("\n").endswith(f"\n        run: {SECTION_COMMAND} > /dev/null"), text
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "    needs: preflight\n" in job("build", "release"), "the builds wait for the check"
    assert workflow.count("scripts/release-notes.py") >= 2


def test_the_release_page_documents_what_the_release_text_holds():
    page = (ROOT / "docs" / "internals" / "build-ci-release.md").read_text(encoding="utf-8")
    assert "### The text of a release" in page
    part = page.split("### The text of a release\n", 1)[1].split("\n## ", 1)[0].split("\n### ", 1)[0]
    for needed in ("scripts/release-notes.py", "ops/release/platform-table.sh", "100,000"):
        assert needed in part, f"`{needed}` is not in the section"
