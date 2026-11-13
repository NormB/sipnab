#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Run the gates that count tracked files, alone, against the index.

    git add <the paths of the change>
    scripts/pin-gates.py [--jobs N] [--allow-untracked]
    scripts/pin-gates.py --list

Some tests hold a count of something the repository tracks (pages, links
between them, code links, workflows, error templates), or read the list of
tracked files itself. A new page, script or workflow moves those counts, and
the tests that hold them run among 16,000 others at the end of the pre-commit
hook. On 2026-11-12 one pull request spent three hook runs, about 25 minutes
of the host's build slot each, meeting five such pins one run at a time.

This runs only those tests, the way the hook runs them: the same nextest
profile, feature set and environment, through scripts/parallel-tests.py, so
the test binaries the hook built are the ones run here. Run it after
`git add` and before the hook.

WHY THE INDEX. The tests list files with `git ls-files`, which reads the
index. A file that is not staged yet is not counted, so its pins look right
until `git add` and the hook. This script therefore refuses to run while a
file is untracked and not ignored, and names it. `--allow-untracked` runs
anyway, for a scratch file that will not be committed.

THE LIST is .config/pin-gates.txt: one test binary a line, and `!name reason`
for a pin gate that is left to the hook. It cannot fall behind the tree: a
test under tests/ that declares an `EXPECTED_...: usize` count, calls
`git ls-files` or uses tests/support/tracked.rs is a pin gate by its source,
and this script, and scripts/tests/test_pin_gates.py, refuse a list that
neither runs nor excludes one.

Exit status: the run's; 2 when the list is wrong or a file is untracked.
"""

import argparse
import importlib.util
import os
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
LIST = ".config/pin-gates.txt"
# What the pre-commit hook hands scripts/parallel-tests.py after `--`, and the
# variables it removes; scripts/tests/test_pin_gates.py reads both from the hook.
CARGO_ARGS = ["--features", "full", "--color", "never"]
REMOVED_ENV = ("SIPNAB_CORPUS", "SIPNAB_VCON_DATASETS")

_NAME = re.compile(r"[a-z0-9_]+")
_PIN_MARK = re.compile(r"\bEXPECTED_[A-Z0-9_]+:\s*usize\b|\bls-files\b|support/tracked\.rs")


def _parallel_tests():
    spec = importlib.util.spec_from_file_location("parallel_tests", REPO / "scripts" / "parallel-tests.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_list(text: str) -> tuple[list[str], dict[str, str], list[str]]:
    """(binaries to run, {excluded binary: reason}, problems) of the list file's text."""
    run: list[str] = []
    excluded: dict[str, str] = {}
    problems: list[str] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        skip = line.startswith("!")
        name, _, reason = (line[1:] if skip else line).partition(" ")
        reason = reason.strip()
        if not _NAME.fullmatch(name) or (reason and not skip):
            problems.append(f"line {number}: {raw.strip()!r} is not a test binary name")
        elif name in run or name in excluded:
            problems.append(f"line {number}: {name} is listed twice")
        elif skip and not reason:
            problems.append(f"line {number}: {name} is excluded with no reason")
        elif skip:
            excluded[name] = reason
        else:
            run.append(name)
    return run, excluded, problems


def sources(repo: pathlib.Path) -> dict[str, str]:
    """{test binary: its source} for every tests/*.rs."""
    return {path.stem: path.read_text(encoding="utf-8") for path in sorted((repo / "tests").glob("*.rs"))}


def derived(texts: dict[str, str]) -> set[str]:
    """The test binaries that are pin gates by their source."""
    return {name for name, text in texts.items() if _PIN_MARK.search(text)}


def drift(run: list[str], excluded: dict[str, str], texts: dict[str, str]) -> list[str]:
    """Why the list does not fit the tree; empty when it does."""
    problems = []
    gates = derived(texts)
    for name in sorted(gates - set(run) - set(excluded)):
        problems.append(
            f"tests/{name}.rs counts tracked files (an EXPECTED_ count, git ls-files or support/tracked.rs) "
            f"and is neither run nor excluded in {LIST}"
        )
    for name in [*run, *excluded]:
        if name not in texts:
            problems.append(f"{LIST} names {name}, and there is no tests/{name}.rs")
    for name in excluded:
        if name in texts and name not in gates:
            problems.append(f"{LIST} excludes {name}, which is no pin gate by its source; remove the line")
    return problems


def untracked(porcelain: str) -> list[str]:
    """The untracked, not ignored paths in `git status --porcelain -z` output."""
    found = []
    entries = iter(porcelain.split("\0"))
    for entry in entries:
        status, path = entry[:2], entry[3:]
        if status == "??":
            found.append(path)
        elif "R" in status or "C" in status:
            next(entries, None)  # the path it was renamed or copied from
    return found


def selection(run: list[str]) -> list[str]:
    """Cargo's own selection of these binaries, `--test NAME` for each.

    Not a nextest filterset: `-E 'binary(=...)'` chooses what is run and still
    builds every test target of the package, minutes of build for seconds of
    tests.
    """
    if not run:
        raise ValueError("no test binary to run")
    return [word for name in run for word in ("--test", name)]


def command(run: list[str], jobs: int | None) -> list[str]:
    """The suite's own nextest command, for the listed binaries alone."""
    return _parallel_tests().nextest_command(CARGO_ARGS, [*selection(run), "--no-tests", "fail"], [], jobs)


def suite_env(env: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in env.items() if key not in REMOVED_ENV}


def git_status(repo: pathlib.Path) -> str:
    status = ["git", "status", "--porcelain", "-z", "--untracked-files=all"]
    return subprocess.run(status, cwd=repo, capture_output=True, text=True, check=True).stdout


def read_list(repo: pathlib.Path) -> str:
    return (repo / LIST).read_text(encoding="utf-8")


def run(cmd: list[str], env: dict[str, str]) -> int:
    os.environ.clear()
    os.environ.update(env)
    os.chdir(REPO)
    return _parallel_tests().run_nextest(cmd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--list", action="store_true", help="print the test binaries and run nothing")
    parser.add_argument("--allow-untracked", action="store_true", help="run though a file is untracked")
    parser.add_argument("--jobs", type=int, help="nextest's --test-threads")
    args = parser.parse_args(argv)

    names, excluded, problems = parse_list(read_list(REPO))
    problems = problems or drift(names, excluded, sources(REPO))
    if problems:
        for problem in problems:
            print(f"pin-gates: {problem}", file=sys.stderr)
        return 2
    if args.list:
        print("\n".join(names))
        return 0
    unseen = untracked(git_status(REPO))
    if unseen:
        shown = ", ".join(unseen[:10]) + (f" and {len(unseen) - 10} more" if len(unseen) > 10 else "")
        print(f"pin-gates: untracked, so not counted by any gate: {shown}", file=sys.stderr)
        if not args.allow_untracked:
            print("pin-gates: git add them first, or pass --allow-untracked if they will not be committed", file=sys.stderr)
            return 2
    print(f"pin-gates: running {len(names)} test binaries against the index", file=sys.stderr)
    return run(command(names, args.jobs), suite_env(dict(os.environ)))


if __name__ == "__main__":
    sys.exit(main())
