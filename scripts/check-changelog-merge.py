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
4. The released part (from the first `## [x.y.z]` heading to the end) of
   every commit the result is built on is the end of ours, byte for byte:
   the base, HEAD (the first parent, or the commit a rebase or a
   cherry-pick replays onto) and the merge base of HEAD and origin/main. A
   release commit adds a section on top and passes. A commit that rewrites
   released sections on purpose writes the sha256 of the released part it
   leaves to `.config/changelog-released.sha256`: the rule passes against a
   commit when the pin of the index is that sha256 and is not that commit's
   pin. A commit whose pin is older than the pin of the index does not judge
   either: the commit with the newest pin does. That is the case when another
   of the commits holds the pin of the index, its released part is the end of
   ours, and its history holds the older pin. With `--base`, that commit
   alone is compared.

   Why the newest pin judges: on 2026-11-25 main d023f4815 rewrote the
   released sections 0.5.214 to 0.5.190 as outlines and moved the pin, and
   0.5.273 then added a section on top. A branch forked before d023f4815
   holds the old text, so its HEAD and its merge base refused every merge of
   main, and a car forked before it refused its merge into a train; only a
   hand edit of the pin passed. The pin file's history is a chain: a rewrite
   on purpose writes a new sha256, every later commit keeps it until the
   next rewrite, and no commit moves it back. So a history that holds a pin
   has moved past it, and an older pin is replaced, not contradicted. An
   [Unreleased] entry moved into a released section is still refused: the
   commit with the newest pin judges the result, and its released part is
   not the end of ours. Two rewrites made apart from one pin do not excuse
   each other (neither history holds the other's pin): their merge writes a
   pin of its own.

   Why every commit and not the base alone: on 2026-11-25 a merge train
   merged a car branch forked before the 0.5.272 release (MERGE_HEAD) into a
   train that held it, and the merge put the car's [Unreleased] entries
   inside the released [0.5.272] section. The car's released part, 0.5.271
   and older, is the end of any newer one, so the gate passed four such
   merges. HEAD held 0.5.272 and refuses them. Neither origin/main's tip nor
   the newest tag is the rule: a branch forked before a release does not
   hold it and would fail against either for no fault of its own, and a tag
   may not be fetched. A commit never changes what was released before it,
   so each commit it is built on judges its own released part.

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


Released = collections.namedtuple("Released", "label released pin history")
Released.__doc__ = """A commit the result is built on: the label a problem is
prefixed with (None for the base), its released part (None without a
CHANGELOG), its pin, and every pin its history held (its own included; an
empty string for the commits before the pin file)."""


def released_problems(ours: str, pin: str, commits) -> list[str]:
    """Rule 4: the problems of our released part `ours`, under the pin `pin`
    of the index, against each of `commits` (Released).

    A commit's released part judges ours unless one of these holds:
    - it is the end of ours;
    - this commit rewrites on purpose: the pin is the sha256 of ours and is
      not that commit's pin;
    - its pin is older than the pin of the index: another of the commits
      holds the pin of the index, its released part is the end of ours, and
      its history holds this commit's pin. A rewrite on purpose moves the pin
      and no later commit moves it back, so a history that holds a pin has
      moved past it, and the commit with the newest pin judges the result."""
    digest = hashlib.sha256(ours.encode("utf-8")).hexdigest()
    judges = [c for c in commits if c.released is not None and ours.endswith(c.released)]
    problems = []
    for c in commits:
        if c.released is None or ours.endswith(c.released):
            continue
        if pin == digest and pin != c.pin:
            continue
        if pin != c.pin and any(d.pin == pin and c.pin in d.history for d in judges):
            continue
        newer = [d for d in judges if d.pin != pin and pin in d.history]
        problem = released_problem(ours, c.released, digest, newer[0] if newer else None)
        problems.append(problem if c.label is None else f"against {c.label}: {problem}")
    return problems


def released_problem(ours: str, base: str, digest: str, newer=None) -> str:
    """The message for a released part `ours` that `base` does not judge.
    `newer` is a commit whose pin is newer than the pin of the index."""
    mine, theirs = collections.Counter(ours.splitlines()), collections.Counter(base.splitlines())
    added = [line[:WIDTH] for line in (mine - theirs) if line.strip()][:SHOWN]
    gone = [line[:WIDTH] for line in (theirs - mine) if line.strip()][:SHOWN]
    take = "" if newer is None else (
        f" Or the pin of the index is older than the pin {newer.pin} of {newer.label or 'the base'}, which "
        f"rewrote released sections on purpose: write {newer.pin} to {PIN}, as that commit has it.")
    return ("the released part (from the first `## [x.y.z]` heading to the end) is not the base's. Lines here "
            f"that the base's released part does not hold (at most {SHOWN}, the first {WIDTH} characters of "
            f"each): {added}. Lines of the base's that are not here: {gone}. Either a merge moved an entry into a released "
            "section: move it back to [Unreleased], under its heading, until the released part is the base's "
            f"byte for byte.{take} Or you rewrote released sections on purpose: write "
            f"{digest} to {PIN} in the same commit.")


def check(ours: str, base: str, pin: str = "", base_pin: str = "", others=(), base_history=()) -> list[str]:
    """The problems of `ours` against `base`, both whole CHANGELOG texts.

    `others` holds (label, CHANGELOG text or None, pin[, pin history]) of the
    other commits the result is built on: rule 4 alone applies to them. A
    commit without a CHANGELOG has released nothing; a commit given without
    a pin history is judged as if its history held its own pin alone."""
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
    commits = [Released(None, base_released, base_pin, frozenset(base_history) | {base_pin})]
    for label, text, other_pin, *history in others:
        commits.append(Released(label, None if text is None else split(text)[1], other_pin,
                                frozenset(*history) | {other_pin}))
    return problems + released_problems(our_released, pin, commits)


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


MERGING = "MERGE_HEAD, the commit being merged"
MAIN_BASE = "the merge base of HEAD and origin/main"
ON_TOP_OF = "HEAD, the commit this one is built on"


def choose_bases(explicit: str, merge_head: str, head: str, main_base: str):
    """(the base, how it was chosen, [(commit, how)] whose released part ours
    must end with), from the commits git names; an empty string is a commit
    that does not exist. The base is None when there is none."""
    if explicit:
        return explicit, "--base", [(explicit, "--base")]
    base, how = (merge_head, MERGING) if merge_head else (main_base, MAIN_BASE)
    if not base:
        return None, "no merge base of HEAD and origin/main: fetch origin/main, or pass --base", []
    released = []
    for commit, why in ((base, how), (head, ON_TOP_OF), (main_base, MAIN_BASE)):
        if commit and commit not in (c for c, _ in released):
            released.append((commit, why))
    return base, how, released


def pin_history(repo, commit) -> frozenset:
    """Every pin `commit`'s history held: the pin of each commit in it that
    changed the pin file and of that commit's parents (so a history from
    before the pin file holds the empty pin). Empty when `commit` does not
    exist. Side branches count (--full-history): a merge that took a side
    branch moved past its pins as well."""
    log = git(repo, "log", "--full-history", "--format=%H %P", commit, "--", PIN)
    if log is None:
        return frozenset()
    commits = {c for line in log.splitlines() for c in line.split()} | {commit}
    return frozenset(pin_of(git(repo, "show", f"{c}:{PIN}")) for c in commits)


def commit_of(repo, rev) -> str:
    """The full name of `rev`, or an empty string when it does not exist."""
    return (git(repo, "rev-parse", "-q", "--verify", f"{rev}^{{commit}}") or "").strip()


def find_bases(repo, explicit: str = ""):
    """choose_bases() for the repository's MERGE_HEAD, HEAD and merge base of
    HEAD and origin/main."""
    if explicit:
        return choose_bases(explicit, "", "", "")
    return choose_bases("", commit_of(repo, "MERGE_HEAD"), commit_of(repo, "HEAD"),
                        (git(repo, "merge-base", "HEAD", "origin/main") or "").strip())


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="check-changelog-merge.py")
    p.add_argument("--base", default="")
    p.add_argument("--repo", default=str(ROOT))
    try:
        args = p.parse_args(argv)
    except SystemExit:
        return 2
    base, how, released = find_bases(args.repo, args.base)
    if not base:
        print(f"check-changelog-merge: {how}", file=sys.stderr)
        return 2
    ours = git(args.repo, "show", f":{FILE}")
    theirs = git(args.repo, "show", f"{base}:{FILE}")
    if ours is None or theirs is None:
        which = "the index" if ours is None else base
        print(f"check-changelog-merge: {FILE} could not be read from {which}", file=sys.stderr)
        return 2
    others = [(f"{commit[:12]} ({why})", git(args.repo, "show", f"{commit}:{FILE}"),
               pin_of(git(args.repo, "show", f"{commit}:{PIN}")), pin_history(args.repo, commit))
              for commit, why in released if commit != base]
    problems = check(ours, theirs, pin_of(git(args.repo, "show", f":{PIN}")),
                     pin_of(git(args.repo, "show", f"{base}:{PIN}")), others, pin_history(args.repo, base))
    if problems:
        print(f"check-changelog-merge: {FILE} of the index against {base[:12]} ({how}):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    also = "".join(f"; its released part was compared with the one of {other[0]}" for other in others)
    print(f"check-changelog-merge: the CHANGELOG is as the base {base[:12]} has it ({how}){also}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
