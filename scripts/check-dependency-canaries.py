#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Fail once a dependency release that an accepted risk waits for exists.

Each canary names a crate, the first stable version that ends the wait, and
what to do then. An advisory exception in osv-scanner.toml that exists only
because no fixed release is stable yet has a canary here, so the release does
not go unnoticed until the exception's own expiry.

Usage:
    scripts/check-dependency-canaries.py [--from-json CRATE=FILE ...]

Exit 0: no awaited release is out. Exit 1: one is; the message says what to do.
Exit 2: the check could not run (crates.io unreachable, an answer without a
version). A check that did not run is not a pass.

--from-json reads a saved crates.io /api/v1/crates/<name> answer instead of
asking crates.io, for the tests.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request

# (crate, first stable version that ends the wait, what to do).
# `{found}` in the last field becomes the version crates.io reports.
#
# Empty since sipnab moved to rsa 0.10.0, the release the one entry waited
# for. Remove an entry in the change that makes the move it asks for.
CANARIES: list[tuple[str, tuple[int, int, int], str]] = []

USER_AGENT = "sipnab-dependency-canaries (https://github.com/NormB/sipnab)"


def stable_version(answer: dict) -> tuple[int, int, int] | None:
    """The crate's newest stable version from a crates.io answer, or None."""
    text = (answer.get("crate") or {}).get("max_stable_version")
    if not isinstance(text, str):
        return None
    try:
        major, minor, patch = (int(x) for x in text.split("."))
    except ValueError:
        return None
    return (major, minor, patch)


def fetch(name: str) -> dict:
    req = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}", headers={"User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-json", action="append", default=[], metavar="CRATE=FILE")
    args = ap.parse_args(argv)
    saved = dict(item.split("=", 1) for item in args.from_json)
    found_any = False
    if not CANARIES:
        print("ok: no dependency release is awaited")
    for name, awaited, todo in CANARIES:
        try:
            if name in saved:
                with open(saved[name], encoding="utf-8") as f:
                    answer = json.load(f)
            else:
                answer = fetch(name)
        except (OSError, ValueError) as e:
            print(f"NOT CHECKED: {name}: {e}", file=sys.stderr)
            return 2
        version = stable_version(answer)
        if version is None:
            print(f"NOT CHECKED: {name}: the answer names no stable version", file=sys.stderr)
            return 2
        shown = ".".join(map(str, version))
        if version >= awaited:
            print("CANARY: " + todo.format(found=shown))
            found_any = True
        else:
            print(f"ok: {name} newest stable is {shown}, still before {'.'.join(map(str, awaited))}")
    return 1 if found_any else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
