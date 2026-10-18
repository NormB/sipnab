#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Judge Valgrind memcheck logs: fail on a leak or a memory error.

The rule the weekly Valgrind job (.github/workflows/memcheck.yml) applies to
every log it writes:

* "definitely lost" or "indirectly lost" above zero is a leak, and fails.
* An invalid read, write or free, or a mismatched free, fails whatever the
  leak summary says.
* "possibly lost" and "still reachable" pass. In sipnab they are interior
  pointers into live hash tables (hashbrown points at its control bytes, in
  the middle of the allocation) and per-thread handles, alive at exit; the
  2026-10-10 review traced every such record.
* A log with no LEAK SUMMARY, and no "All heap blocks were freed" line, was
  not judged: Valgrind did not finish, or the run never reached exit. That is
  refused rather than passed, because a check that read nothing proves
  nothing.

Usage:
    memcheck-verdict.py LOG...

Exit codes: 0 every log clean, 1 at least one leak or memory error,
2 a log could not be judged, or no log was given.
"""

import pathlib
import re
import sys

PREFIX = re.compile(r"^==\d+==\s?", re.M)
LOST = re.compile(r"^\s*(definitely|indirectly) lost: ([\d,]+) bytes in ([\d,]+) blocks", re.M)
ERRORS = re.compile(r"^\s*(Invalid read of size \d+|Invalid write of size \d+|Invalid free\(\)[^\n]*"
                    r"|Mismatched free\(\)[^\n]*)$", re.M)


class NotJudged(Exception):
    """The log holds no leak summary to judge."""


def judge(text):
    """The problems one memcheck log records; empty when it is clean."""
    body = PREFIX.sub("", text)
    problems = []
    for m in ERRORS.finditer(body):
        if m.group(1) not in problems:
            problems.append(m.group(1))
    if "All heap blocks were freed" in body:
        return problems
    if "LEAK SUMMARY:" not in body:
        raise NotJudged("no LEAK SUMMARY: Valgrind did not finish this run")
    for kind, nbytes, blocks in LOST.findall(body):
        if nbytes.replace(",", "") != "0":
            problems.append(f"{kind} lost: {nbytes} bytes in {blocks} blocks")
    return problems


def main(argv=None):
    paths = (argv if argv is not None else sys.argv[1:])
    if not paths:
        print("memcheck-verdict: no log given", file=sys.stderr)
        return 2
    failing = 0
    for path in paths:
        name = pathlib.Path(path).name
        try:
            problems = judge(pathlib.Path(path).read_text(errors="replace"))
        except (NotJudged, OSError) as e:
            print(f"{name}: NOT JUDGED: {e}")
            return 2
        if problems:
            failing += 1
            for p in problems:
                print(f"{name}: {p}")
        else:
            print(f"{name}: clean")
    print(f"{len(paths)} log(s), {failing} with a leak or memory error")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
