#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Run the test suite under cargo-nextest, with a deadline on every test.

    parallel-tests.py [--jobs N] -- CARGO_ARGS...

The suite runs as `cargo nextest run --profile suite CARGO_ARGS`, then the
doctests, which nextest does not run, as `cargo test CARGO_ARGS --doc`. The
`suite` profile in .config/nextest.toml stops a test that runs past three
60-second periods (`slow-timeout`), so one hung test fails as that test, by
name, instead of holding the pre-commit hook until its wall-clock watchdog
fires (TEST-DEADLINE-NEXTEST-SIPNAB). nextest runs every test in a process of
its own, side by side, so no test binary waits on another; this replaced a
pool that ran `cargo test`'s binaries side by side but bounded none of them.

Everything that reads the suite's output reads libtest's text: the hook's
failure report (`test NAME ... FAILED`, `---- NAME stdout ----`, `test
result:`) and scripts/published-test-count.py, which counts the `passed`
field of every `test result` line. So this renders nextest's JUnit report in
that shape, one block per test binary, headed by a `Running` line, after the
run; the doctests print libtest's own text. nextest's progress (its `SLOW`,
`FAIL` and `TIMEOUT` lines) goes to standard error. Every test runs after
one fails, and the exit status is non-zero if any failed.

--jobs N becomes nextest's `--test-threads N` (1 runs one test at a time).

The installed cargo-nextest must be the version `nextest-version` pins in
.config/nextest.toml; a run with another stops before building, naming the
install command. check-hook-prerequisites.py asks the same question before
the pre-commit hook runs anything.

    parallel-tests.py --shard-index I --shard-count N --manifest FILE -- ARGS...
    parallel-tests.py merge --output FILE SHARD_DIR...

CI splits the suite across N runners (ci.yml's `test` job). With
--shard-index, this asks `cargo metadata` for the package's integration-test
targets, and `partition` decides which of them shard I (0-based) of N
compiles and runs; shard 0 also takes the library and binary unit tests and
the doctests. Each shard builds the examples, as plain `cargo test` does,
because tests/examples_run_test.rs runs them. Compiling is the larger half of
the suite's time, so a shard names its targets to nextest (`--test NAME ...`)
and compiles nothing else. FILE records what the shard ran.

`merge` reads each SHARD_DIR's manifest and output, refuses a set that is not
every shard exactly once with every target in exactly one shard, and writes
the outputs in shard order to --output: one run's output, which
scripts/published-test-count.py counts as it counts an unsharded run.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET

REPO = pathlib.Path(__file__).resolve().parent.parent
# The nextest profile every suite run uses, in the hook and in CI, and the
# JUnit file it writes, under <target>/nextest/<profile>/.
PROFILE = "suite"
JUNIT = "junit.xml"


def nextest_version(repo: pathlib.Path = REPO) -> str:
    """The cargo-nextest version .config/nextest.toml pins."""
    config = tomllib.loads((repo / ".config/nextest.toml").read_text(encoding="utf-8"))
    pinned = config.get("nextest-version")
    if isinstance(pinned, dict):
        pinned = pinned.get("required")
    if not isinstance(pinned, str):
        raise ValueError(".config/nextest.toml pins no nextest-version")
    return pinned


def nextest_problem(pinned: str, reported: str | None) -> str | None:
    """Why the installed cargo-nextest cannot run the suite, or None.

    `reported` is what `cargo nextest --version` printed, None when it could
    not run. Only the pinned version is accepted: a newer one can change what
    the suite profile means, and an older one may not read it.
    """
    fix = f"cargo install cargo-nextest --locked --version {pinned}"
    if reported is None:
        return f"cargo-nextest is not installed; the suite runs under {pinned}. Install it: {fix}"
    m = re.search(r"cargo-nextest (\d+\.\d+\.\d+)", reported)
    found = m.group(1) if m else reported.strip()
    if found != pinned:
        return f"cargo-nextest {found} is installed; the suite runs under {pinned}. Install it: {fix}"
    return None


def installed_nextest() -> str | None:
    """What `cargo nextest --version` prints, or None when it cannot run."""
    try:
        proc = subprocess.run(
            ["cargo", "nextest", "--version"], capture_output=True, text=True, check=False
        )
    except OSError:
        return None
    return proc.stdout if proc.returncode == 0 else None


def _text(element: ET.Element | None) -> str:
    return (element.text or "") if element is not None else ""


def _own_output(text: str, name: str) -> list[str]:
    """`text` without the harness lines of test `name`'s own libtest.

    nextest runs each test as `<binary> --exact NAME --nocapture`, so the
    text libtest prints around the test's output lands in what nextest
    captured. Carried into a failure block, its `test result:` line would be
    counted as a binary's result.
    """
    harness = {
        "running 1 test",
        "failures:",
        f"    {name}",
        f"---- {name} stdout ----",
        *(f"test {name} ... {v}" for v in ("ok", "FAILED", "ignored")),
    }
    lines = [
        line
        for line in text.splitlines()
        if line not in harness and not line.startswith("test result: ")
    ]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def render_junit(xml_text: str) -> tuple[str, int, int]:
    """nextest's JUnit report as libtest text: (text, passed, failed).

    One block per test binary, binaries and tests in name order: a `Running`
    line, a `test NAME ... ok|FAILED` line per test, a `---- NAME stdout ----`
    block per failure (the panic, then the test's own output), and a `test
    result:` line whose third and fourth fields are libtest's. nextest does
    not report skipped (ignored) tests, so the line says so rather than
    printing a count. A report that cannot be read, or that holds no test, is
    refused: a run that tested nothing must not pass.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise ValueError(f"the nextest report cannot be read: {e}") from e
    out: list[str] = []
    passed = failed = 0
    suites = sorted(root.iter("testsuite"), key=lambda s: s.get("name", ""))
    for suite in suites:
        cases = sorted(suite.iter("testcase"), key=lambda c: c.get("name", ""))
        if not cases:
            continue
        lines = [f"     Running {suite.get('name', '?')}", ""]
        blocks: list[str] = []
        names: list[str] = []
        ok = bad = 0
        seconds = 0.0
        for case in cases:
            name = case.get("name", "?")
            try:
                seconds += float(case.get("time", "0"))
            except ValueError:
                pass
            problem = case.find("failure")
            if problem is None:
                problem = case.find("error")
            if problem is None:
                ok += 1
                lines.append(f"test {name} ... ok")
                continue
            bad += 1
            names.append(name)
            lines.append(f"test {name} ... FAILED")
            body: list[str] = []
            if problem.get("type") == "test timeout":
                body.append(
                    "cargo-nextest stopped this test: it ran past the slow-timeout "
                    f"of the {PROFILE} profile in .config/nextest.toml."
                )
            body += _own_output(_text(problem), name) or _own_output(problem.get("message", ""), name)
            body += _own_output(_text(case.find("system-out")), name)
            body += [line for line in _own_output(_text(case.find("system-err")), name) if line not in body]
            blocks.append("\n".join([f"---- {name} stdout ----", *body]))
        if blocks:
            lines += ["", "failures:", ""]
            for block in blocks:
                lines += [block, ""]
            lines += ["failures:", *(f"    {n}" for n in names)]
        verdict = "ok" if bad == 0 else "FAILED"
        lines += [
            "",
            f"test result: {verdict}. {ok} passed; {bad} failed; ignored tests are not "
            f"reported by cargo-nextest; finished in {seconds:.2f}s",
            "",
        ]
        out += lines
        passed += ok
        failed += bad
    if passed + failed == 0:
        raise ValueError("the nextest report holds no test, so nothing was tested")
    return "\n".join(out) + "\n", passed, failed


def cargo_metadata() -> dict:
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        stdout=subprocess.PIPE,
        check=True,
    )
    return json.loads(out.stdout)


def target_dir() -> str:
    return cargo_metadata()["target_directory"]


# The library and binary unit tests and the doctests: one item of the
# partition, in shard 0, because cargo cannot split them.
UNIT_TESTS = "<lib, bins and doctests>"
# The unit tests' cost in integration-test binaries, for balancing.
UNIT_WEIGHT = 40
PACKAGE = "sipnab"
SHARD_MANIFEST = "shard.json"
SHARD_OUTPUT = "test-output.txt"


def test_targets(metadata: dict, package: str = PACKAGE) -> list[str]:
    """The integration-test targets of `package`, as `cargo metadata` lists them."""
    for pkg in metadata.get("packages", []):
        if pkg.get("name") == package:
            return sorted(t["name"] for t in pkg.get("targets", []) if "test" in t.get("kind", []))
    raise ValueError(f"cargo metadata lists no package {package!r}")


def partition(targets: list[str], count: int, unit_weight: int = UNIT_WEIGHT) -> list[list[str]]:
    """Split the suite into `count` shards: the one rule for what each runs.

    Shard 0 starts with UNIT_TESTS, weighed as `unit_weight` binaries. Then
    each target, in name order, goes to the shard with the least weight so
    far, the lowest index on a tie. The result depends only on the set of
    target names and `count`, every target is in exactly one shard, and a
    shard that would hold nothing is refused: `cargo test` given no target
    runs every target.
    """
    if count < 1:
        raise ValueError(f"a shard count of {count}: there must be at least one shard")
    if len(set(targets)) != len(targets):
        raise ValueError("a target name is listed twice")
    shards: list[list[str]] = [[] for _ in range(count)]
    load = [0] * count
    shards[0].append(UNIT_TESTS)
    load[0] = unit_weight
    for target in sorted(targets):
        i = min(range(count), key=lambda k: (load[k], k))
        shards[i].append(target)
        load[i] += 1
    empty = [i for i, s in enumerate(shards) if not s]
    if empty:
        raise ValueError(f"shard(s) {empty} of {count} would run nothing")
    return shards




def merge_problems(manifests: list[dict]) -> list[str]:
    """Why a set of shard manifests is not one complete run; empty if it is."""
    if not manifests:
        return ["no shard manifests"]
    problems = []
    counts = {m["count"] for m in manifests}
    target_lists = {tuple(sorted(m["all"])) for m in manifests}
    if len(counts) != 1:
        problems.append(f"the shards disagree on the shard count: {sorted(counts)}")
    if len(target_lists) != 1:
        problems.append("the shards disagree on the list of targets")
    count = max(counts)
    indices = sorted(m["index"] for m in manifests)
    for i in range(count):
        if indices.count(i) != 1:
            problems.append(f"shard {i} of {count} reported {indices.count(i)} times, not once")
    extra = [i for i in indices if not 0 <= i < count]
    if extra:
        problems.append(f"shard index(es) {extra} outside 0..{count - 1}")
    ran: dict[str, int] = {}
    for m in manifests:
        for t in m["targets"]:
            ran[t] = ran.get(t, 0) + 1
    expected = set().union(*(set(m["all"]) for m in manifests))
    missing = sorted(expected - set(ran))
    if missing:
        problems.append(f"no shard ran: {missing}")
    twice = sorted(t for t, n in ran.items() if n > 1)
    if twice:
        problems.append(f"more than one shard ran: {twice}")
    unknown = sorted(set(ran) - expected)
    if unknown:
        problems.append(f"a shard ran targets outside the list: {unknown}")
    return problems


def merge(output: str, dirs: list[str]) -> int:
    manifests = []
    for d in dirs:
        try:
            with open(os.path.join(d, SHARD_MANIFEST), encoding="utf-8") as f:
                manifests.append({**json.load(f), "dir": d})
        except (OSError, ValueError) as e:
            print(f"parallel-tests merge: {d}: {e}", file=sys.stderr)
            return 1
    problems = merge_problems(manifests)
    if problems:
        for p in problems:
            print(f"parallel-tests merge: {p}", file=sys.stderr)
        return 1
    tmp = f"{output}.{os.getpid()}.tmp"
    try:
        with open(tmp, "wb") as out:
            for m in sorted(manifests, key=lambda m: m["index"]):
                with open(os.path.join(m["dir"], SHARD_OUTPUT), "rb") as f:
                    shutil.copyfileobj(f, out)
        os.replace(tmp, output)
    except OSError as e:
        print(f"parallel-tests merge: {e}", file=sys.stderr)
        if os.path.exists(tmp):
            os.remove(tmp)
        return 1
    return 0



def split_args(cargo_args: list[str]) -> tuple[list[str], list[str]]:
    """(cargo's arguments, the arguments after `--` including it)."""
    split = cargo_args.index("--") if "--" in cargo_args else len(cargo_args)
    return cargo_args[:split], cargo_args[split:]


def nextest_command(cargo: list[str], selection: list[str], harness: list[str], jobs: int | None) -> list[str]:
    threads = ["--test-threads", str(jobs)] if jobs else []
    return ["nextest", "run", "--profile", PROFILE, *threads, *cargo, *selection, *harness]


def suite_commands(cargo_args: list[str], jobs: int | None = None) -> list[list[str]]:
    """The cargo commands an unsharded run makes, in order, without the `cargo`.

    `cargo nextest run` builds what `cargo test` builds, examples included,
    and runs every test target; the doctests are a run of their own.
    """
    cargo, harness = split_args(cargo_args)
    return [nextest_command(cargo, [], harness, jobs), ["test", *cargo, "--doc", *harness]]


def shard_commands(shard: list[str], cargo_args: list[str], jobs: int | None = None) -> list[list[str]]:
    """The cargo commands one shard runs, in order, without the `cargo`.

    Arguments after `--` go to the test binaries, so they reach only the test
    runs. `--doc` cannot be combined with another target flag, so the
    doctests are a run of their own.
    """
    cargo, harness = split_args(cargo_args)
    commands = [["build", *cargo, "--examples"]]
    selection: list[str] = []
    if UNIT_TESTS in shard:
        selection += ["--lib", "--bins"]
    for target in shard:
        if target != UNIT_TESTS:
            selection += ["--test", target]
    commands.append(nextest_command(cargo, selection, harness, jobs))
    if UNIT_TESTS in shard:
        commands.append(["test", *cargo, "--doc", *harness])
    return commands


def run_nextest(cmd: list[str]) -> int:
    """Run one `cargo nextest run`, then print its report as libtest text."""
    report = pathlib.Path(target_dir()) / "nextest" / PROFILE / JUNIT
    # A report left by an earlier run must never stand in for this one:
    # nextest writes none when the build fails.
    report.unlink(missing_ok=True)
    sys.stdout.flush()
    # nextest's own progress goes to standard error; standard output carries
    # only the rendered report and the doctests, the text the readers parse.
    rc = subprocess.run(["cargo", *cmd], stdout=sys.stderr, check=False).returncode
    try:
        text, _passed, failed = render_junit(report.read_text(encoding="utf-8"))
    except OSError:
        print(f"parallel-tests: cargo nextest exited {rc} and wrote no report at {report}", file=sys.stderr)
        return rc or 1
    except ValueError as e:
        print(f"parallel-tests: {e} ({report})", file=sys.stderr)
        return rc or 1
    sys.stdout.write(text)
    sys.stdout.flush()
    if failed and rc == 0:
        return 1
    return rc


def run_commands(commands: list[list[str]]) -> int:
    """Run each command in turn, every one even after a failure; 0 if all passed."""
    rc = 0
    for cmd in commands:
        if cmd[0] == "build":
            built = subprocess.run(["cargo", *cmd], stderr=subprocess.STDOUT, check=False).returncode
            if built != 0:
                return built
        elif cmd[0] == "nextest":
            rc = run_nextest(cmd) or rc
        else:
            sys.stdout.flush()
            rc = subprocess.run(["cargo", *cmd], stderr=subprocess.STDOUT, check=False).returncode or rc
    return rc


def check_nextest() -> int:
    problem = nextest_problem(nextest_version(), installed_nextest())
    if problem:
        print(f"parallel-tests: {problem}", file=sys.stderr)
        return 2
    return 0


def run_shard(index: int, count: int, manifest: str, cargo_args: list[str], jobs: int | None) -> int:
    shards = partition(test_targets(cargo_metadata()), count)
    if not 0 <= index < count:
        sys.exit(f"parallel-tests: shard index {index} is outside 0..{count - 1}")
    if check_nextest():
        return 2
    mine = shards[index]
    with open(manifest, "w", encoding="utf-8") as f:
        json.dump({"index": index, "count": count, "targets": mine, "all": [t for s in shards for t in s]}, f, indent=0)
    print(f"parallel-tests: shard {index} of {count}: {len(mine)} of {sum(map(len, shards))} items", flush=True)
    return run_commands(shard_commands(mine, cargo_args, jobs))


def main() -> int:
    argv = sys.argv[1:]
    if argv[:1] == ["merge"]:
        p = argparse.ArgumentParser(prog="parallel-tests.py merge")
        p.add_argument("--output", required=True)
        p.add_argument("dirs", nargs="+")
        a = p.parse_args(argv[1:])
        return merge(a.output, a.dirs)
    p = argparse.ArgumentParser(prog="parallel-tests.py")
    p.add_argument("--jobs", type=int)
    p.add_argument("--shard-index", type=int)
    p.add_argument("--shard-count", type=int)
    p.add_argument("--manifest")
    p.add_argument("cargo_args", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    if a.jobs is not None and a.jobs < 1:
        p.error("--jobs must be at least 1")
    cargo_args = a.cargo_args[1:] if a.cargo_args[:1] == ["--"] else a.cargo_args
    sharded = (a.shard_index, a.shard_count, a.manifest)
    if any(x is not None for x in sharded):
        if any(x is None for x in sharded):
            p.error("--shard-index, --shard-count and --manifest go together")
        return run_shard(a.shard_index, a.shard_count, a.manifest, cargo_args, a.jobs)
    if check_nextest():
        return 2
    return run_commands(suite_commands(cargo_args, a.jobs))


if __name__ == "__main__":
    sys.exit(main())
