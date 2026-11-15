#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Writes the first part of the text of a GitHub release: the CHANGELOG
section of the version, with its links made absolute.

release.yml runs this twice for a tag. Its preflight job runs it with the
output discarded, so a tag whose version has no CHANGELOG section stops
before the builds. Its release job writes the output to the start of
release-body.md, before the download table (ops/release/platform-table.sh)
and the notes GitHub generates from the pull request titles. The section is
first because it holds what an operator must do before an upgrade.

The section of a version is what CHANGELOG.md holds between the heading
`## [<version>] - <date>` and the next `## ` heading, without link
definitions (`[name]: <address>`). A link the section writes by reference
(`[text][name]` or `[name]`) is written in full, since the release text
does not hold the definitions.

A release page is not in the repository, so a relative link target would
resolve against the page's own address. Each one is written as an address
in the repository at the release's tag:
`docs/fleet.md#x` becomes `https://github.com/<owner>/<name>/blob/v<version>/docs/fleet.md#x`,
`#x` alone points into CHANGELOG.md, and an image points at the file
itself (`raw` in place of `blob`). A target with a scheme (`https:`,
`mailto:`) stays as it is. Text in a code block or a code span is copied
as it is.

GitHub shows each line break of a release text, so a paragraph or a list
item that the changelog writes on several lines is written on one. The
lines of a code block, a table and a quote stay as they are.

Refused, with exit status 1 and nothing on standard output: a version with
no section or with two, a section with no text, a link target that leaves
the repository (`..`) or is written in angle brackets, a repository that is
not `owner/name`, and a section longer than BOUND characters.

Usage:
    release-notes.py VERSION --repo OWNER/NAME [--changelog PATH]

VERSION is as Cargo.toml has it (0.5.256, not v0.5.256). PATH is
CHANGELOG.md in the current directory unless given.
"""

import pathlib
import re
import sys

USAGE = "usage: release-notes.py VERSION --repo OWNER/NAME [--changelog PATH]"

# The most characters GitHub takes as the body of a release. GitHub's REST
# documentation of releases (docs.github.com/en/rest/releases/releases, read
# 2026-11-14) states no limit. The number is from the API's own refusal, as
# quoted in github.com/intuit/auto issue 2418: "body is too long (maximum is
# 125000 characters)". Nobody measured it for this repository.
GITHUB_LIMIT = 125000

# What the step "Create GitHub Release" sends is cut, not refused, at this
# many characters: softprops/action-gh-release, at the commit release.yml
# pins (8a0cd651e5b2365bd640854a3fa5dfc70e4875f3), src/github.ts holds
# "// release notes can be a maximum of 125000 characters" and cuts the text,
# release-body.md followed by the generated notes, with
# `input.substring(0, githubNotesMaxCharLength - 1)`. A cut drops the end of
# the text without an error, so it must fall, if ever, in the generated notes.
ACTION_CUT = GITHUB_LIMIT - 1

# The most characters this script writes: a chosen bound. With the download
# table after it, release-body.md stays more than 20,000 characters under
# ACTION_CUT (scripts/tests/test_release_notes.py holds both), so the section
# is never what a cut removes. The largest section of CHANGELOG.md is 0.5.233,
# about 37,000 characters as the file writes it.
BOUND = 100000

_VERSION = re.compile(r"\d+\.\d+\.\d+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_HEADING = re.compile(r"## \[([^\]]+)\] - \S.*")
_DEFINITION = re.compile(r"\[([^\]]+)\]:\s+(\S+)\s*")
_FENCE = re.compile(r" {0,3}(```|~~~)")
_CODE_SPAN = re.compile(r"(`+[^`]*`+)")
_LINK = re.compile(r"(?<![\]\\])\[([^\]\[]+)\](\[([^\]\[]+)\])?(?![\[(:])")
# The end of an inline link or image: `](target)` or `](target "title")`.
_TARGET = re.compile(r"\]\((<[^>]*>|[^()\s<]+)(\s+\"[^\"]*\")?\)")
# A target that is an address already: it has a scheme, or names a host.
_ABSOLUTE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:|//")
# The start of a list item: a bullet, or a number (group 2).
_ITEM = re.compile(r" *([-*+]|(\d{1,9})[.)])( |$)")
_NUMBERED = re.compile(r" *\d{1,9}[.)]( |$)")
# A line that is never joined to another: a heading, a table row, a quote,
# a rule, or the line under a heading written with `===` or `---`.
_OWN_LINE = re.compile(r" *(#{1,6}( |$)|\||>|([-*_] *){3,}$|=+ *$|-+ *$)")
# The first line of a code block written by indentation.
_INDENTED = re.compile(r"( {4}|\t)")


class Refused(Exception):
    """Why no text is written."""


def _lines(changelog):
    """Each line of `changelog` with whether it is inside a code block (the
    lines of the fences are inside)."""
    fenced = False
    out = []
    for line in changelog.replace("\r\n", "\n").split("\n"):
        fence = _FENCE.match(line)
        out.append((line, fenced or bool(fence)))
        if fence:
            fenced = not fenced
    return out


def _sections(changelog):
    """The link definitions of `changelog` by lower-case name, and the
    lines of each version's section in the order of the file, as
    (version, lines) with the lines as `_lines` gives them. A `## ` heading
    that is not a version's (`## [Unreleased]`) ends a section and starts
    none."""
    definitions = {}
    sections = []
    inside = False
    for line, code in _lines(changelog):
        if not code and line.startswith("## "):
            match = _HEADING.fullmatch(line)
            inside = bool(match) and bool(_VERSION.fullmatch(match.group(1)))
            if inside:
                sections.append((match.group(1), []))
            continue
        definition = None if code else _DEFINITION.fullmatch(line)
        if definition:
            definitions[definition.group(1).lower()] = definition.group(2)
        elif inside:
            sections[-1][1].append((line, code))
    return definitions, sections


def versions(changelog):
    """The versions that have a section, in the order of the file."""
    return [version for version, _ in _sections(changelog)[1]]


def _resolved(line, definitions):
    """`line` with each link by reference written in full, outside code
    spans. A name with no definition is left as it is."""

    def link(match):
        name = match.group(3) if match.group(2) else match.group(1)
        address = definitions.get(name.lower())
        return match.group(0) if address is None else f"[{match.group(1)}]({address})"

    parts = _CODE_SPAN.split(line)
    return "".join(part if k % 2 else _LINK.sub(link, part) for k, part in enumerate(parts))


def _address(target, image, version, repo):
    """The address of the link target `target` in the repository `repo` at
    the tag of `version`."""
    if target.startswith("<"):
        raise Refused(f"the link target `{target}` is in angle brackets: write it without them")
    if _ABSOLUTE.match(target):
        return target
    at = f"https://github.com/{repo}"
    if target.startswith("#"):
        return f"{at}/blob/v{version}/CHANGELOG.md{target}"
    path, mark, anchor = target.partition("#")
    steps = [step for step in path.split("/") if step not in ("", ".")]
    if ".." in steps:
        raise Refused(f"the link target `{target}` leaves the repository: write it from the repository's top")
    return f"{at}/{'raw' if image else 'blob'}/v{version}/{'/'.join(steps)}{mark}{anchor}"


def _absolute(line, version, repo):
    """`line` with the target of each inline link and image written as an
    address, outside code spans."""

    def of(part):
        def target(match):
            # An image is `![alt](target)`: the bracket that opens the text
            # this target belongs to has `!` before it.
            opened = part.rfind("[", 0, match.start())
            image = opened > 0 and part[opened - 1] == "!"
            return f"]({_address(match.group(1), image, version, repo)}{match.group(2) or ''})"

        return _TARGET.sub(target, part)

    parts = _CODE_SPAN.split(line)
    return "".join(part if k % 2 else of(part) for k, part in enumerate(parts))


def _one_line(lines):
    """`lines`, as `_lines` gives them, with each paragraph and each list
    item on one line: a line that continues the one before it is joined to
    it with one space. A blank line, a line of a code block, a heading, a
    table row, a quote and a rule stay as they are, and so does the line
    after a break the text asks for (a line that ends with a backslash or
    with two spaces)."""
    out = []
    # The first line of the paragraph or item being joined, if one is open.
    first = None
    for line, code in lines:
        if code or not line.strip() or _OWN_LINE.match(line):
            out.append((line, code))
            first = None
            continue
        item = _ITEM.match(line)
        # A number other than 1 starts an item only in a numbered list.
        starts = bool(item) and (item.group(2) in (None, "1") or (first is not None and _NUMBERED.match(first)))
        before = out[-1][0] if out else ""
        if first is None or starts or before.endswith(("\\", "  ")) or _INDENTED.match(first):
            out.append((line, False))
            first = line
        else:
            out[-1] = (f"{before.rstrip(' ')} {line.strip(' ')}", False)
    return out


def _text(lines, definitions, version, repo):
    """The section of `version` as text, from its lines: no blank line at
    its start or end, each paragraph and list item on one line, links by
    reference in full and, when `repo` is given, every link absolute."""

    def written(line):
        line = _resolved(line, definitions)
        return line if repo is None else _absolute(line, version, repo)

    # Joined first, so a link or a code span that breaks across two lines
    # of the changelog is whole when links are rewritten.
    text = "\n".join(line if code else written(line) for line, code in _one_line(lines)).strip("\n")
    if not any(line.strip() and not line.startswith("### ") for line in text.split("\n")):
        raise Refused(f"the section `## [{version}]` of CHANGELOG.md is empty")
    return text


def section(changelog, version, repo=None):
    """The CHANGELOG section of `version`, links as the changelog writes
    them unless `repo` is given."""
    if not _VERSION.fullmatch(version):
        raise Refused(f"`{version}` is not a version: give it as Cargo.toml has it, such as 0.5.256")
    definitions, sections = _sections(changelog)
    found = [lines for name, lines in sections if name == version]
    if not found:
        raise Refused(f"CHANGELOG.md has no section `## [{version}] - <date>`")
    if len(found) > 1:
        raise Refused(f"CHANGELOG.md has {len(found)} sections `## [{version}]`")
    return _text(found[0], definitions, version, repo)


def _bounded(text, version):
    """`text` as the release text of `version`: it ends with one newline."""
    if len(text) > BOUND:
        raise Refused(
            f"the section `## [{version}]` is {len(text)} characters as a release text, "
            f"and this script writes at most {BOUND}: shorten the section"
        )
    return f"{text}\n"


def notes(changelog, version, repo):
    """The first part of the release text of `version` in the repository
    `repo`."""
    if not _REPO.fullmatch(repo):
        raise Refused(f"`{repo}` is not a repository: give it as owner/name")
    return _bounded(section(changelog, version, repo), version)


def every_release_text(changelog, repo):
    """(version, text) for every version of `changelog`, in the order of
    the file, with the text as `notes` gives it. The file is read once, so
    a test can hold every section to the rules a release holds one to."""
    if not _REPO.fullmatch(repo):
        raise Refused(f"`{repo}` is not a repository: give it as owner/name")
    definitions, sections = _sections(changelog)
    for version, lines in sections:
        yield version, _bounded(_text(lines, definitions, version, repo), version)


def _arguments(argv):
    """The version, the repository and the changelog's path, or None when
    the arguments are not the usage's."""
    positional = []
    options = {"--repo": None, "--changelog": "CHANGELOG.md"}
    given = set()
    k = 0
    while k < len(argv):
        if argv[k] in options:
            if k + 1 >= len(argv) or argv[k] in given:
                return None
            options[argv[k]] = argv[k + 1]
            given.add(argv[k])
            k += 2
        elif argv[k].startswith("--"):
            return None
        else:
            positional.append(argv[k])
            k += 1
    if len(positional) != 1 or options["--repo"] is None:
        return None
    return positional[0], options["--repo"], options["--changelog"]


def main(argv):
    arguments = _arguments(argv)
    if arguments is None:
        print(USAGE, file=sys.stderr)
        return 2
    version, repo, path = arguments
    try:
        changelog = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as error:
        print(f"release-notes: {path}: {error.strerror}", file=sys.stderr)
        return 1
    except UnicodeDecodeError:
        print(f"release-notes: {path}: not UTF-8 text", file=sys.stderr)
        return 1
    try:
        text = notes(changelog, version, repo)
    except Refused as refused:
        print(f"release-notes: {refused}", file=sys.stderr)
        return 1
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
