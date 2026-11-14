#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Did a merge of main leave CHANGELOG.md as main has it?

    check-changelog-merge.py [--base REF] [--repo DIR]

git merges CHANGELOG.md line by line and knows nothing of its headings. Five
times on 2026-11-13 and 2026-11-14 an automatic merge of main put entries in
the wrong place without a conflict: inside a released section; a heading
joined to an entry with no blank line; main's `Changed` entry under the
branch's `### Fixed`.

The gate compares the CHANGELOG.md of the INDEX with the one of the base.
The base is the commit being merged while a merge is open (MERGE_HEAD),
otherwise the merge base of HEAD and origin/main, or `--base`.

1. An entry of the base's [Unreleased] that is also in ours sits under the
   same `###` heading. An entry is one top-level bullet with every indented
   line under it (its sub-bullets or its table); it is known by its lead
   line. An entry of the base that ours no longer holds is not a problem:
   a release moves entries, and a branch may remove or reword one.
2. Each `###` heading is in [Unreleased] once, and each entry once.
3. A blank line comes before `## [Unreleased]`, before each `###` heading of
   it and before the first released heading.
4. The base's released part (from the first `## [x.y.z]` heading to the end)
   is the end of ours, byte for byte. A release commit adds a section on top
   and passes. A commit that rewrites released sections on purpose writes
   the sha256 of the released part it leaves to
   `.config/changelog-released.sha256`: the rule passes when the pin of the
   index is that sha256 and is not the base's pin.

The format of an entry is not judged here: that is the subject of the
changelog's format gate.

Exit status: 0 no problem; 1 problems, each printed on stderr with the
entry's lead and the two headings; 2 the base or a CHANGELOG could not be
read, or a usage error.

Tested by scripts/tests/test_check_changelog_merge.py.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILE = "CHANGELOG.md"
PIN = ".config/changelog-released.sha256"
UNRELEASED = "## [Unreleased]"
RELEASE_HEADING = re.compile(r"## \[[0-9]")
# How many differing lines of a released part a message shows.
SHOWN = 6
# How much of each of those lines: an entry from before the outline format
# is one line of 2,000 characters.
WIDTH = 160

Entry = collections.namedtuple("Entry", "heading lead block")


def split(text: str) -> tuple[list[str], str]:
    """(the lines of [Unreleased] after its heading, the released part).

    The released part is the text from the first `## [x.y.z]` heading to the
    end, exactly as it is in `text`; empty when there is no such heading."""
    lines = text.splitlines(keepends=True)
    first = next((i for i, line in enumerate(lines) if RELEASE_HEADING.match(line)), len(lines))
    released = "".join(lines[first:])
    start = next((i for i, line in enumerate(lines[:first]) if line.rstrip() == UNRELEASED), None)
    unreleased = [] if start is None else [line.rstrip("\r\n") for line in lines[start + 1:first]]
    return unreleased, released


def entries(unreleased: list[str]) -> list[Entry]:
    """The entries of an [Unreleased] section, each with the `###` heading it
    is under (empty before the first heading)."""
    out = []
    heading = ""
    block = None
    for line in unreleased + ["#"]:
        indented = line[:1] in (" ", "\t")
        if block is not None and (indented or not line.strip()):
            block.append(line)
            continue
        if block is not None:
            while block and not block[-1].strip():
                block.pop()
            out.append(Entry(heading, block[0].rstrip(), block))
            block = None
        if line.startswith("### "):
            heading = line.rstrip()
        elif line.startswith("- "):
            block = [line]
    return out


def where(heading: str) -> str:
    return f"under '{heading}'" if heading else "under no heading"


def blank_line_problems(text: str) -> list[str]:
    lines = [line.rstrip("\r\n") for line in text.splitlines()]
    first = next((i for i, line in enumerate(lines) if RELEASE_HEADING.match(line)), len(lines))
    start = next((i for i, line in enumerate(lines[:first]) if line.rstrip() == UNRELEASED), None)
    wanted = [] if start is None else [start] + [i for i in range(start + 1, first) if lines[i].startswith("### ")]
    if first < len(lines):
        wanted.append(first)
    return [f"no blank line before the heading '{lines[i].rstrip()}' (line {i + 1}): a merge joined it to the "
            "line above; put one empty line between them."
            for i in wanted if i > 0 and lines[i - 1].strip()]


def released_problem(ours: str, base: str, pin: str, base_pin: str) -> list[str]:
    if ours.endswith(base):
        return []
    digest = hashlib.sha256(ours.encode("utf-8")).hexdigest()
    if pin == digest and pin != base_pin:
        return []
    mine, theirs = collections.Counter(ours.splitlines()), collections.Counter(base.splitlines())
    added = [line[:WIDTH] for line in (mine - theirs) if line.strip()][:SHOWN]
    gone = [line[:WIDTH] for line in (theirs - mine) if line.strip()][:SHOWN]
    return ["the released part (from the first `## [x.y.z]` heading to the end) is not the base's. Lines here "
            f"that the base's released part does not hold (at most {SHOWN}, the first {WIDTH} characters of "
            f"each): {added}. Lines of the base's that are not here: {gone}. Either a merge moved an entry into a released "
            "section: move it back to [Unreleased], under its heading, until the released part is the base's "
            "byte for byte. Or you rewrote released sections on purpose: write "
            f"{digest} to {PIN} in the same commit."]


def check(ours: str, base: str, pin: str = "", base_pin: str = "") -> list[str]:
    """The problems of `ours` against `base`, both whole CHANGELOG texts."""
    problems = []
    our_unreleased, our_released = split(ours)
    base_unreleased, base_released = split(base)
    seen = collections.Counter(line.rstrip() for line in our_unreleased if line.startswith("### "))
    for heading, count in seen.items():
        if count > 1:
            problems.append(f"[Unreleased] holds the heading '{heading}' twice: a merge added a second list; put "
                            "its entries under the first heading and remove the second.")
    mine = collections.defaultdict(list)
    for entry in entries(our_unreleased):
        mine[entry.lead].append(entry.heading)
    for lead, headings in mine.items():
        if len(headings) > 1:
            places = " and ".join(where(h) for h in headings)
            problems.append(f"the entry {lead!r} is in [Unreleased] twice, {places}: keep one (its lead line and "
                            "its sub-bullets).")
    for entry in entries(base_unreleased):
        headings = mine.get(entry.lead, [])
        if len(headings) == 1 and headings[0] != entry.heading:
            problems.append(f"the entry {entry.lead!r} is {where(headings[0])} here and {where(entry.heading)} on "
                            f"the base: move it (its lead line and its sub-bullets) {where(entry.heading)}.")
    problems += blank_line_problems(ours)
    problems += released_problem(our_released, base_released, pin, base_pin)
    return problems


def pin_of(text) -> str:
    """The sha256 a pin file holds: the first word of its first line that is
    not empty and not a `#` comment, or nothing."""
    for line in (text or "").splitlines():
        words = line.split()
        if words and not words[0].startswith("#"):
            return words[0]
    return ""


def git(repo, *args):
    """Standard output of a git command, or None when git refuses."""
    try:
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None


def find_base(repo) -> tuple[str | None, str]:
    """(the base commit, how it was chosen)."""
    merging = git(repo, "rev-parse", "-q", "--verify", "MERGE_HEAD^{commit}")
    if merging:
        return merging.strip(), "MERGE_HEAD, the commit being merged"
    base = git(repo, "merge-base", "HEAD", "origin/main")
    if base:
        return base.strip(), "the merge base of HEAD and origin/main"
    return None, "no merge base of HEAD and origin/main: fetch origin/main, or pass --base"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="check-changelog-merge.py")
    p.add_argument("--base", default="")
    p.add_argument("--repo", default=str(ROOT))
    try:
        args = p.parse_args(argv)
    except SystemExit:
        return 2
    base, how = (args.base, "--base") if args.base else find_base(args.repo)
    if not base:
        print(f"check-changelog-merge: {how}", file=sys.stderr)
        return 2
    ours = git(args.repo, "show", f":{FILE}")
    theirs = git(args.repo, "show", f"{base}:{FILE}")
    if ours is None or theirs is None:
        which = "the index" if ours is None else base
        print(f"check-changelog-merge: {FILE} could not be read from {which}", file=sys.stderr)
        return 2
    problems = check(ours, theirs, pin_of(git(args.repo, "show", f":{PIN}")), pin_of(git(args.repo, "show", f"{base}:{PIN}")))
    if problems:
        print(f"check-changelog-merge: {FILE} of the index against {base[:12]} ({how}):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"check-changelog-merge: the CHANGELOG is as the base {base[:12]} has it ({how})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
