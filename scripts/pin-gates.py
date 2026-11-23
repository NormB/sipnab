#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Run the gates that count tracked files, alone, against the index.

    git add <the paths of the change>
    scripts/pin-gates.py [--jobs N] [--allow-untracked]
    scripts/pin-gates.py --list
    scripts/pin-gates.py --script-tests [--shard I/N] [--budget SECONDS]

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

THE PRE-CHECK. `--hook` runs .githooks/pre-commit itself with
SIPNAB_GATE_PRECHECK=1. In that mode the hook runs every one of its steps
(formatting, vale, codespell, clippy, the Python gates, the script tests)
except one: the full suite, which it replaces with `--source-gates`. The
script tests run by the hook's rule (gate-cache.py script_tests_needed),
started beside the other steps. The steps are the hook's own, so a step added
to the hook is in the pre-check with no second list to keep. A step that passes
writes the hook's own pass stamp where it has one (clippy, the sipnab-bpf-types
tests, the script tests),
so the commit's hook run does not repeat it; the suite's stamp and the hook's
are never written, so the commit still runs the full suite.

THE SCRIPT TESTS IN SHARDS. `--script-tests --shard I/N` runs shard I of N
of the hook's script-test run, with the hook's command, in a session of its
own that ends at `--budget` seconds. On 2026-11-23 the whole run took 370 to
539 s alone, and at a load average near 15 a 598 s limit ended it at 90%, so
one quick-slot job (600 s) cannot hold it. scripts/gate-cache.py holds the
rule: the split by test file, balanced on .config/script-test-durations.txt;
a pass record per shard, keyed on the hook's script-tests key; and the hook's
own script-tests stamp, written when every shard of the plan has a record on
the same key. The pre-check and the commit then skip the step. A shard that
passed on another tree has another key and does not count. `--script-tests`
alone is one shard of one.

`--source-gates` runs the pin gates above and every source gate: a test
binary that reads the tree and neither runs nor links sipnab (no
`CARGO_BIN_EXE`, no `sipnab::` path, no `use sipnab` or `extern crate sipnab`
in its source or in any file it includes as a module). In the week to
2026-11-21 such gates (the policy-doc sentence rule, the wasm-reach test, the
crypto-literal test, the assert-message count) and clippy failed hook runs
that this script, as it was, had passed. .config/precheck-skip.txt names the
source gates it leaves to the hook, `!name reason` a line, for one that takes
too long; a line that names no source gate is refused.

Exit status: the run's; 2 when a list is wrong or a file is untracked.
"""

import argparse
import importlib.util
import os
import pathlib
import posixpath
import re
import subprocess
import sys
import typing

REPO = pathlib.Path(__file__).resolve().parent.parent
LIST = ".config/pin-gates.txt"
SKIP_LIST = ".config/precheck-skip.txt"
HOOK = ".githooks/pre-commit"
MESSAGE_HOOK = ".githooks/commit-msg"
PRECHECK_ENV = "SIPNAB_GATE_PRECHECK"
# What the pre-commit hook hands scripts/parallel-tests.py after `--`, and the
# variables it removes; scripts/tests/test_pin_gates.py reads both from the hook.
CARGO_ARGS = ["--features", "full", "--color", "never"]
REMOVED_ENV = ("SIPNAB_CORPUS", "SIPNAB_VCON_DATASETS")

_NAME = re.compile(r"[a-z0-9_]+")
_PIN_MARK = re.compile(r"\bEXPECTED_[A-Z0-9_]+:\s*usize\b|\bls-files\b|support/tracked\.rs")
# What a test that runs or links sipnab says in its code (comment lines aside).
_RUNS_SIPNAB = re.compile(r"CARGO_BIN_EXE|\bsipnab::|\buse\s+sipnab\b|\bextern\s+crate\s+sipnab\b")
_PATH_ATTR = re.compile(r'#\[path\s*=\s*"([^"]+)"\]\s*')
_MOD_DECL = re.compile(r"(?:pub(?:\([^)]*\))?\s+)?mod\s+([a-z0-9_]+)\s*;")


def _parallel_tests():
    spec = importlib.util.spec_from_file_location("parallel_tests", REPO / "scripts" / "parallel-tests.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _gate_cache():
    """scripts/gate-cache.py, whose keys and stamps the hook reads."""
    name = "gate_cache_for_pin_gates"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / "gate-cache.py")
        module = importlib.util.module_from_spec(spec)
        # dataclasses looks the module up by name while a class is built.
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def shard_spec(text: str) -> tuple[int, int]:
    """argparse's type for --shard: gate-cache.py's rule."""
    try:
        return _gate_cache().parse_shard(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def run_script_test_shard(index: int, count: int, budget: float) -> int:
    """`--script-tests`: one shard of the hook's script-test run, by gate-cache.py."""
    gc = _gate_cache()
    return gc.script_test_shard(REPO, dict(os.environ), REPO / HOOK, index, count, budget=budget,
                                log=lambda line: print(f"pin-gates: {line}", file=sys.stderr, flush=True))


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


def _module_dir(rel: str) -> str:
    """The directory a `mod name;` with no `#[path]` in `rel` resolves against."""
    directory, name = posixpath.split(rel)
    if name == "mod.rs" or directory == "tests":
        return directory
    return posixpath.join(directory, name.removesuffix(".rs"))


def includes(rel: str, text: str) -> list[str]:
    """The repository paths `rel` includes as modules, in order.

    A `#[path = "..."]` module is its path, against the directory of `rel`; a
    plain `mod name;` is both places Rust looks, `name.rs` and `name/mod.rs`.
    An inline `mod name { ... }` and a comment that shows the syntax are none.
    """
    found: list[str] = []
    pending = None
    for raw in text.splitlines():
        rest = raw.strip()
        if rest.startswith("//"):
            continue
        attr = _PATH_ATTR.match(rest)
        if attr:
            pending = attr.group(1)
            rest = rest[attr.end():]
            if not rest:
                continue
        decl = _MOD_DECL.fullmatch(rest)
        if decl and pending:
            found.append(posixpath.normpath(posixpath.join(posixpath.dirname(rel), pending)))
        elif decl:
            base = _module_dir(rel)
            found += [posixpath.join(base, f"{decl.group(1)}.rs"), posixpath.join(base, decl.group(1), "mod.rs")]
        if decl or not rest.startswith("#["):
            pending = None
    return found


def reach(root: str, read: typing.Callable[[str], str | None]) -> dict[str, str]:
    """{path: text} of `root` and every file it includes, at any depth, that exists."""
    seen: dict[str, str] = {}
    todo = [root]
    while todo:
        rel = todo.pop()
        if rel in seen:
            continue
        text = read(rel)
        if text is None:
            continue
        seen[rel] = text
        todo.extend(includes(rel, text))
    return seen


def _code(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))


def is_source_gate(name: str, read: typing.Callable[[str], str | None]) -> bool:
    """True when tests/<name>.rs, with all it includes, neither runs nor links sipnab."""
    return not any(_RUNS_SIPNAB.search(_code(text)) for text in reach(f"tests/{name}.rs", read).values())


def source_gates(names: list[str], read: typing.Callable[[str], str | None]) -> set[str]:
    return {name for name in names if is_source_gate(name, read)}


def tree_reader(repo: pathlib.Path) -> typing.Callable[[str], str | None]:
    def read(rel: str) -> str | None:
        try:
            return (repo / rel).read_text(encoding="utf-8")
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            return None

    return read


def parse_skip_list(text: str) -> tuple[dict[str, str], list[str]]:
    """({skipped source gate: reason}, problems) of .config/precheck-skip.txt's text."""
    problems = [
        f"line {number}: {line.split('#', 1)[0].strip()!r} is not `!name reason`: each line names a source "
        "gate the pre-check leaves to the hook"
        for number, line in enumerate(text.splitlines(), 1)
        if line.split("#", 1)[0].strip() and not line.strip().startswith("!")
    ]
    _run, skipped, more = parse_list(text)
    return skipped, problems + more


def skip_drift(skipped: dict[str, str], gates: set[str], names: set[str]) -> list[str]:
    """Why the skip list does not fit the tree; empty when it does."""
    problems = []
    for name in skipped:
        if name not in names:
            problems.append(f"{SKIP_LIST} names {name}, and there is no tests/{name}.rs")
        elif name not in gates:
            problems.append(f"{SKIP_LIST} skips {name}, which is no source gate and is not run anyway; remove the line")
    return problems


def precheck_binaries(run: list[str], gates: set[str], skipped: dict[str, str]) -> list[str]:
    """The pin gates, and every source gate the skip list does not leave to the hook."""
    return sorted(set(run) | (gates - set(skipped)))


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


def read_skip_list(repo: pathlib.Path) -> str:
    return (repo / SKIP_LIST).read_text(encoding="utf-8")


def run(cmd: list[str], env: dict[str, str]) -> int:
    os.environ.clear()
    os.environ.update(env)
    os.chdir(REPO)
    return _parallel_tests().run_nextest(cmd)


def precheck_env(env: dict[str, str]) -> dict[str, str]:
    """The hook's environment for the pre-check: no GIT_* of a calling hook, and the mode set.

    The hook refuses the pre-check while GIT_INDEX_FILE is set, which is how it
    tells a `git commit` from a hand run.
    """
    kept = {key: value for key, value in env.items() if not key.startswith("GIT_")}
    return {**kept, PRECHECK_ENV: "1"}


def run_hook(env: dict[str, str]) -> int:
    return subprocess.run(["bash", HOOK], cwd=REPO, env=env, check=False).returncode


def run_message_checks(path: str, env: dict[str, str]) -> int:
    """The repository's commit-msg hook on `path`, as git would run it."""
    return subprocess.run(["bash", MESSAGE_HOOK, path], cwd=REPO, env=env, check=False).returncode


def check_message(message: str) -> int:
    """`--message`: the commit-msg checks, before every other step.

    git runs them only after the pre-commit hook passed, so one bad line cost
    a whole hook round (2026-11-23: refused for naming the build host, after
    every pre-commit gate had passed).
    """
    path = os.path.abspath(message)
    if not os.path.exists(path):
        print(f"pin-gates: no message file {path}", file=sys.stderr)
        return 2
    if not os.path.isfile(path):
        print(f"pin-gates: {path} is not a file", file=sys.stderr)
        return 2
    print(f"pin-gates: running {MESSAGE_HOOK} on {path} first", file=sys.stderr)
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    rc = run_message_checks(path, env)
    if rc:
        print("pin-gates: the message fails the commit-msg checks; reword it before the pre-check", file=sys.stderr)
    return rc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--list", action="store_true", help="print the test binaries and run nothing")
    parser.add_argument("--allow-untracked", action="store_true", help="run though a file is untracked")
    parser.add_argument("--jobs", type=int, help="nextest's --test-threads")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--source-gates", action="store_true", help="run the pin gates and every source gate")
    mode.add_argument("--hook", action="store_true", help="run the pre-commit hook as the pre-check")
    mode.add_argument("--script-tests", action="store_true", help="run the hook's script tests, or one shard of them")
    parser.add_argument("--message", metavar="FILE", help="with --hook: run the commit-msg checks on FILE first")
    parser.add_argument("--shard", metavar="I/N", type=shard_spec, help="with --script-tests: shard I of N")
    parser.add_argument("--budget", type=float, metavar="SECONDS",
                        help="with --script-tests: end the shard's run after SECONDS (default: gate-cache.py's)")
    args = parser.parse_args(argv)
    if args.message is not None and not args.hook:
        parser.error("--message goes with --hook")
    if (args.shard is not None or args.budget is not None) and not args.script_tests:
        parser.error("--shard goes with --script-tests" if args.shard is not None else "--budget goes with --script-tests")
    if args.script_tests:
        index, count = args.shard or (1, 1)
        budget = args.budget if args.budget is not None else _gate_cache().SHARD_BUDGET
        return run_script_test_shard(index, count, budget)
    if args.message is not None:
        rc = check_message(args.message)
        if rc:
            return rc

    names, excluded, problems = parse_list(read_list(REPO))
    texts = sources(REPO)
    problems = problems or drift(names, excluded, texts)
    if not problems and (args.source_gates or args.hook):
        gates = source_gates(sorted(texts), tree_reader(REPO))
        skipped, problems = parse_skip_list(read_skip_list(REPO))
        problems = problems or skip_drift(skipped, gates, set(texts))
        names = precheck_binaries(names, gates, skipped)
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
    if args.hook:
        print(f"pin-gates: running {HOOK} as the pre-check ({PRECHECK_ENV}=1)", file=sys.stderr)
        return run_hook(precheck_env(dict(os.environ)))
    if not names:
        print("pin-gates: no test binary to run: the lists leave nothing, and an empty run is no pass", file=sys.stderr)
        return 2
    which = " (the pin gates and the source gates)" if args.source_gates else ""
    print(f"pin-gates: running {len(names)} test binaries against the index{which}", file=sys.stderr)
    return run(command(names, args.jobs), suite_env(dict(os.environ)))


if __name__ == "__main__":
    sys.exit(main())
