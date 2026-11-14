#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""A size claim in CHANGELOG.md's [Unreleased] section carries its numbers.

The 0.5.254 entry on compressed history files said that the static musl
builds and the `-noaudio` packages "are the same size" and that the aarch64
gnu binary "is 655,456 bytes larger". The release builds printed other
numbers. Nothing tied the sentence to a measurement.

This gate checks the form of a claim, not its truth: a bullet of the
[Unreleased] section that says `same size`, `no larger`, `bytes larger` or
`bytes smaller` must hold, in the same bullet, two byte counts of at least
seven digits (the two sizes that were compared) or the number of a
release.yml run (where a reader finds them). The numbers come from the
build jobs of release.yml, which print the size of each stripped binary;
docs/internals/build-ci-release.md, "The changelog", says how to get them.

A released section is not checked: it is history, and a correction goes
into [Unreleased].

usage: check-changelog-size-claims.py [CHANGELOG.md]
exit 0: no fault; exit 1: each fault on its own line; exit 2: no file.
"""

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

# What a bullet says when it compares two sizes.
CLAIMS = ("same size", "no larger", "bytes larger", "bytes smaller")

# A count of at least seven digits, with or without thousands separators.
BYTE_COUNT = re.compile(r"(?<![\d,])(?:\d{1,3}(?:,\d{3}){2,}|\d{7,})(?![\d,])")

# The number of a workflow run, as GitHub shows it: nine digits or more.
RUN = re.compile(r"\bruns? \d{9,}\b")

RELEASE_HEADING = re.compile(r"^## \[")
BULLET = re.compile(r"^\s*- ")


def unreleased(text):
    """The lines of the [Unreleased] section of `text`, each with its line
    number counted from 1. Empty when the changelog has no such section.
    A changelog that a merge left with two such sections has both read."""
    out = []
    inside = False
    for number, line in enumerate(text.splitlines(), start=1):
        if RELEASE_HEADING.match(line):
            inside = line.startswith("## [Unreleased]")
        elif inside:
            out.append((number, line))
    return out


def bullets(lines):
    """The bullets of `lines`: each a (line number, text) pair, where a
    bullet runs from its `- ` line to the next bullet, heading or blank
    line. A nested bullet is a bullet of its own."""
    out = []
    open_bullet = None
    for number, line in lines:
        if BULLET.match(line):
            open_bullet = [number, line]
            out.append(open_bullet)
        elif not line.strip() or line.startswith("#"):
            open_bullet = None
        elif open_bullet is not None:
            open_bullet[1] += "\n" + line
    return [(number, text) for number, text in out]


def evidence(bullet):
    """Whether `bullet` holds two byte counts of at least seven digits or
    the number of a release.yml run."""
    return len(BYTE_COUNT.findall(bullet)) >= 2 or RUN.search(bullet) is not None


def faults(text):
    """One message for each bullet of the [Unreleased] section of `text`
    that makes a size claim without its numbers."""
    out = []
    for number, bullet in bullets(unreleased(text)):
        lowered = bullet.lower()
        found = sorted((lowered.find(claim), claim) for claim in CLAIMS if claim in lowered)
        if found and not evidence(bullet):
            out.append(
                f"{number}: `{found[0][1]}` without two byte counts of seven digits or more, "
                "or a release.yml run number, in the same bullet"
            )
    return out


def main(argv):
    path = pathlib.Path(argv[1]) if len(argv) > 1 else REPO / "CHANGELOG.md"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        print(f"check-changelog-size-claims: {path}: {error}", file=sys.stderr)
        return 2
    found = faults(text)
    for fault in found:
        print(f"{path.name}:{fault}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
