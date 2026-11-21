#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Print the line that turns off diff-informed CodeQL analysis, when a pull
request changes the CodeQL setup; print nothing otherwise.

usage: git diff --name-only HEAD^1 HEAD | scripts/codeql-full-analysis.py >> "$GITHUB_ENV"

The CodeQL bundle is pinned in .github/workflows/codeql.yml (`tools:`), so a
new CLI, and with it new queries, arrives only through a pull request that
edits that file or the config. A pull request's analysis is diff-informed by
default and reports only changed lines, so it would not show an alert a new
query finds in unchanged code; that alert would open on main after the merge.
For such a pull request this prints CODEQL_ACTION_DIFF_INFORMED_QUERIES=false,
which codeql-action reads (src/feature-flags.ts) to analyze the whole tree.
"""

import sys

# A change to one of these files, or to a file under one of the directories,
# changes what CodeQL runs.
WATCHED_FILES = (".github/workflows/codeql.yml",)
WATCHED_DIRS = (".github/codeql/",)

ENV_LINE = "CODEQL_ACTION_DIFF_INFORMED_QUERIES=false\n"


def paths_from(text: str) -> list[str]:
    """The paths in `text`, one per line, blank lines dropped."""
    return [line.strip() for line in text.splitlines() if line.strip()]


def full_analysis_needed(paths: list[str]) -> bool:
    """Whether any of `paths` is part of the CodeQL setup."""
    return any(p in WATCHED_FILES or p.startswith(WATCHED_DIRS) for p in paths)


def env_line(paths: list[str]) -> str:
    """The `$GITHUB_ENV` line for `paths`: the override, or nothing."""
    return ENV_LINE if full_analysis_needed(paths) else ""


def main() -> int:
    sys.stdout.write(env_line(paths_from(sys.stdin.read())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
