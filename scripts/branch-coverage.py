#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Report, and optionally enforce, total branch coverage.

`cargo llvm-cov report` has `--fail-under-lines`, `--fail-under-regions` and
`--fail-under-functions`, and no branch equivalent. The weekly branch-coverage
job in .github/workflows/quality.yml therefore exports a summary with

    cargo llvm-cov report --json --summary-only --output-path summary.json

and hands it to this script:

    scripts/branch-coverage.py summary.json [--floor PERCENT]

Exit 0 when branch data is present and (if a floor is given) the covered
fraction is at or above it; exit 1 otherwise. A report with no branches at all
is a failure, never a vacuous 100%: it means the collection ran without
`--branch` (or on a toolchain that ignores it), so nothing was measured.

The verdict is computed from the `covered` and `count` fields, not the export's
`percent`, so a rounded percentage cannot carry a run over the floor.
"""

import argparse
import json
import sys


def evaluate(doc, floor):
    """Return (ok, message) for one llvm-cov JSON export.

    Raises ValueError for a floor outside 0..100 or a document that carries
    no totals -- both are a broken invocation, not a coverage verdict.
    """
    if floor is not None and not 0 <= floor <= 100:
        raise ValueError(f"floor {floor} is not a percentage")
    try:
        branches = doc["data"][0]["totals"]["branches"]
        count = int(branches["count"])
        covered = int(branches["covered"])
    except (KeyError, IndexError, TypeError) as e:
        raise ValueError(f"no data[0].totals.branches in the export: {e!r}") from e

    if count == 0:
        return False, (
            "branch coverage: the export holds 0 branches. The collection ran "
            "without --branch, or on a toolchain that ignores it; nothing was "
            "measured, so nothing can pass."
        )

    percent = 100.0 * covered / count
    summary = f"branch coverage: {covered}/{count} = {percent:.2f}%"
    if floor is None:
        return True, f"{summary} (no floor enforced)"
    if percent < floor:
        return False, f"{summary}, below the floor of {floor}%"
    return True, f"{summary}, floor {floor}% met"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("summary", help="cargo llvm-cov --json --summary-only output")
    parser.add_argument("--floor", type=float, default=None, help="minimum percent")
    args = parser.parse_args(argv)

    with open(args.summary, encoding="utf-8") as f:
        doc = json.load(f)
    try:
        ok, message = evaluate(doc, args.floor)
    except ValueError as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1
    if ok:
        print(message)
        return 0
    print(f"::error::{message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
