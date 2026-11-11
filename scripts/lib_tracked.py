# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""The one reader of ``git ls-files`` for the scripts.

``git ls-files`` prints an unmerged path once per index stage: a path in
conflict appears up to three times (base, ours, theirs). A script that reads
each listed file then reads that file three times, reports each finding three
times, and a count of the listing is too high. Seen on 2026-11-08: 350 tracked
Markdown pages counted against a real 346, with two unmerged pages.

:func:`unique_paths` is the rule, a pure function of the listing, and
:func:`ls_files` is the only place a script runs the command for a listing of
tracked paths. ``tests/support/tracked.rs`` holds the same rule for the Rust
tests, and ``tests/support_selftest.rs`` refuses a direct call anywhere else.
"""

from __future__ import annotations

import subprocess

__all__ = ["ls_files", "unique_paths"]


def unique_paths(listing: bytes | str) -> list[str]:
    """Each path of a NUL-separated ``git ls-files -z`` listing, once.

    The order is that of each path's first appearance. Empty fields (the one
    after the final NUL) are dropped. Bytes are decoded as UTF-8, with the
    undecodable ones kept as surrogate escapes so the name still opens.
    """
    if isinstance(listing, bytes):
        listing = listing.decode("utf-8", "surrogateescape")
    # A dict keeps insertion order and holds each key once.
    return list(dict.fromkeys(path for path in listing.split("\0") if path))


def ls_files(repo, *args: str, env: dict | None = None) -> list[str]:
    """The paths ``git -C <repo> ls-files -z <args>`` lists, each once.

    ``env`` replaces the environment of the child when given. Raises
    ``subprocess.CalledProcessError`` when git fails: an empty listing from a
    failed command would let a gate pass over nothing.
    """
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z", *args],
        capture_output=True,
        check=True,
        env=env,
    ).stdout
    return unique_paths(out)
