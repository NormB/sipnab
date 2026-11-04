#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Run `cargo test`'s test binaries side by side instead of one at a time.

    parallel-tests.py [--jobs N] [--durations FILE] -- CARGO_TEST_ARGS...
    parallel-tests.py run-spool [--jobs N] [--durations FILE] SPOOL

`cargo test` runs every test binary in turn. Measured on 2026-09-29 (14
cores): the suite's ~355 binaries took 355 s of running with one core busy,
and 294 of them took under a second each. Tests INSIDE a binary already run
on threads; only the binaries queue.

The first form builds with `cargo test`, but with a runner configured
(scripts/record-test-binary.sh) that records each binary -- argv, working
directory, environment, exactly as cargo would run it -- and exits 0 without
running it. Doctests reach the runner too, but outside the target directory,
and the recorder runs those on the spot (see its header for why).
Then the recordings run in a pool of --jobs, the binary that took longest
last time first, so the slowest one is not the last to start.

Each binary's output is printed as ONE block after it exits, headed by the
`Running` line cargo would have printed, so everything that reads `cargo
test` output -- `test NAME ... FAILED`, the `---- NAME stdout ----` blocks,
`test result:` lines -- reads this unchanged. Every binary runs even after
one fails, and the exit status is non-zero if any failed.

The second form runs an already-recorded spool; the tests drive it directly.

    parallel-tests.py --shard-index I --shard-count N --manifest FILE -- ARGS...
    parallel-tests.py merge --output FILE SHARD_DIR...

CI splits the suite across N runners (ci.yml's `test` job). With
--shard-index, this asks `cargo metadata` for the package's integration-test
targets, and `partition` decides which of them shard I (0-based) of N
compiles and runs; shard 0 also takes the library and binary unit tests and
the doctests. Each shard builds the examples, as plain `cargo test` does,
because tests/examples_run_test.rs runs them. Compiling is the larger half of
the suite's time, so a shard names its targets to cargo (`--test NAME ...`)
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
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

RECORDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "record-test-binary.sh")
# Measured 2026-09-29 on 14 cores: 8 jobs and 14 both ran the suite in 58 s
# (serial: 314 s), so more than 8 buys nothing and costs headroom.
DEFAULT_JOBS = max(1, min(8, os.cpu_count() or 1))
RUNNING = re.compile(r"^\s+Running (.+) \((.+)\)\s*$")


def read_nul(path: str) -> list[str]:
    with open(path, "rb") as f:
        data = f.read().decode("utf-8", "surrogateescape")
    return [item for item in data.split("\0") if item]


def load_spool(spool: str) -> list[dict]:
    """The recorded binaries, in a stable order."""
    records = []
    for name in sorted(os.listdir(spool)):
        path = os.path.join(spool, name)
        if not os.path.isdir(path):
            continue
        if not os.path.exists(os.path.join(path, "ready")):
            sys.exit(f"parallel-tests: {path} was never finished recording")
        with open(os.path.join(path, "cwd"), encoding="utf-8", errors="surrogateescape") as f:
            cwd = f.read().rstrip("\n")
        env = dict(item.split("=", 1) for item in read_nul(os.path.join(path, "env")) if "=" in item)
        argv = read_nul(os.path.join(path, "argv"))
        records.append({"argv": argv, "cwd": cwd, "env": env, "label": argv[0]})
    # By path: the spool's directory names are random, and an order that
    # changes from run to run would hide a lost duration sort.
    return sorted(records, key=lambda r: r["argv"])


def load_durations(path: str) -> dict[str, float]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return {str(k): float(v) for k, v in data.items()}
    except (OSError, ValueError, AttributeError):
        return {}


def save_durations(path: str, durations: dict[str, float]) -> None:
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(durations, f, indent=0, sort_keys=True)
        os.replace(tmp, path)
    except OSError as e:
        # Only the scheduling order is lost; the run's verdict stands.
        print(f"parallel-tests: could not save {path}: {e}", file=sys.stderr)


def run_records(records: list[dict], jobs: int, durations_path: str) -> int:
    """Run every record in a pool; 0 only if every binary passed."""
    if not records:
        print(
            "parallel-tests: no test binaries were recorded, so nothing ran. "
            "A run that tests nothing must not pass.",
            file=sys.stderr,
        )
        return 2
    previous = load_durations(durations_path)
    # Unknown binaries sort as slowest: a new one may well be long.
    records = sorted(records, key=lambda r: -previous.get(r["label"], float("inf")))
    lock = threading.Lock()
    measured: dict[str, float] = {}
    failed: list[str] = []

    def run(record: dict) -> None:
        started = time.monotonic()
        try:
            proc = subprocess.run(
                record["argv"],
                cwd=record["cwd"],
                env=record["env"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
        except OSError as e:
            # That binary's failure, not the pool's: the rest still run.
            proc = subprocess.CompletedProcess(record["argv"], 127, f"could not start: {e}\n".encode())
        elapsed = time.monotonic() - started
        with lock:
            measured[record["label"]] = round(elapsed, 3)
            if proc.returncode != 0:
                failed.append(record["label"])
            out = sys.stdout.buffer
            out.write(f"     Running {record['label']}\n".encode())
            out.write(proc.stdout)
            if proc.stdout and not proc.stdout.endswith(b"\n"):
                out.write(b"\n")
            if proc.returncode != 0:
                out.write(f"error: {record['label']} exited with status {proc.returncode}\n".encode())
            out.flush()

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        for future in [pool.submit(run, r) for r in records]:
            future.result()
    save_durations(durations_path, {**previous, **measured})
    if failed:
        print(f"error: {len(failed)} test binaries failed: {' '.join(sorted(failed))}")
        return 1
    return 0


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


def shard_commands(shard: list[str], cargo_args: list[str]) -> list[list[str]]:
    """The cargo commands one shard runs, in order, without the `cargo`.

    Arguments after `--` go to the test binaries, so they reach only the
    `cargo test` runs. `--doc` cannot be combined with another target flag,
    so the doctests are a run of their own.
    """
    split = cargo_args.index("--") if "--" in cargo_args else len(cargo_args)
    cargo, harness = cargo_args[:split], cargo_args[split:]
    commands = [["build", *cargo, "--examples"]]
    selection: list[str] = []
    if UNIT_TESTS in shard:
        selection += ["--lib", "--bins"]
    for target in shard:
        if target != UNIT_TESTS:
            selection += ["--test", target]
    commands.append(["test", *cargo, *selection, *harness])
    if UNIT_TESTS in shard:
        commands.append(["test", *cargo, "--doc", *harness])
    return commands


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


def run_shard(index: int, count: int, manifest: str, cargo_args: list[str], jobs: int, durations: str | None) -> int:
    shards = partition(test_targets(cargo_metadata()), count)
    if not 0 <= index < count:
        sys.exit(f"parallel-tests: shard index {index} is outside 0..{count - 1}")
    mine = shards[index]
    with open(manifest, "w", encoding="utf-8") as f:
        json.dump({"index": index, "count": count, "targets": mine, "all": [t for s in shards for t in s]}, f, indent=0)
    print(f"parallel-tests: shard {index} of {count}: {len(mine)} of {sum(map(len, shards))} items", flush=True)
    rc = 0
    for cmd in shard_commands(mine, cargo_args):
        if cmd[0] == "build":
            built = subprocess.run(["cargo", *cmd], stderr=subprocess.STDOUT, check=False).returncode
            if built != 0:
                return built
        else:
            rc = capture_and_run(cmd[1:], jobs, durations) or rc
    return rc


def capture_and_run(cargo_args: list[str], jobs: int, durations: str | None) -> int:
    target = target_dir()
    os.makedirs(target, exist_ok=True)
    durations = durations or os.path.join(target, "sipnab-test-durations.json")
    spool = tempfile.mkdtemp(prefix="parallel-tests-", dir=target)
    try:
        runner = "[" + ", ".join(json.dumps(x) for x in ["sh", RECORDER, spool, target]) + "]"
        cmd = ["cargo", "--config", f"target.'cfg(all())'.runner = {runner}", "test", *cargo_args]
        labels: dict[str, str] = {}
        cargo_reported = False
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.decode("utf-8", "replace")
            m = RUNNING.match(line)
            if m:
                # Reprinted with the binary's output once it has run.
                labels[os.path.basename(m.group(2))] = m.group(1)
                continue
            cargo_reported = cargo_reported or line.startswith("test result:")
            sys.stdout.write(line)
            sys.stdout.flush()
        cargo_rc = proc.wait()
        records = load_spool(spool)
        # Nothing recorded is a real run when cargo ran the tests itself --
        # `-- --doc`, whose doctests all run on the spot -- or failed first.
        # Only when nothing reported a result at all is it a capture that
        # did not happen, and run_records refuses that.
        if not records and (cargo_rc != 0 or cargo_reported):
            return cargo_rc
        for r in records:
            r["label"] = labels.get(os.path.basename(r["argv"][0]), r["argv"][0])
        rc = run_records(records, jobs, durations)
        return cargo_rc or rc
    finally:
        shutil.rmtree(spool, ignore_errors=True)


def main() -> int:
    argv = sys.argv[1:]
    if argv[:1] == ["run-spool"]:
        p = argparse.ArgumentParser(prog="parallel-tests.py run-spool")
        p.add_argument("--jobs", type=int, default=DEFAULT_JOBS)
        p.add_argument("--durations", required=True)
        p.add_argument("spool")
        a = p.parse_args(argv[1:])
        return run_records(load_spool(a.spool), a.jobs, a.durations)
    if argv[:1] == ["merge"]:
        p = argparse.ArgumentParser(prog="parallel-tests.py merge")
        p.add_argument("--output", required=True)
        p.add_argument("dirs", nargs="+")
        a = p.parse_args(argv[1:])
        return merge(a.output, a.dirs)
    p = argparse.ArgumentParser(prog="parallel-tests.py")
    p.add_argument("--jobs", type=int, default=DEFAULT_JOBS)
    p.add_argument("--durations")
    p.add_argument("--shard-index", type=int)
    p.add_argument("--shard-count", type=int)
    p.add_argument("--manifest")
    p.add_argument("cargo_args", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    cargo_args = a.cargo_args[1:] if a.cargo_args[:1] == ["--"] else a.cargo_args
    sharded = (a.shard_index, a.shard_count, a.manifest)
    if any(x is not None for x in sharded):
        if any(x is None for x in sharded):
            p.error("--shard-index, --shard-count and --manifest go together")
        return run_shard(a.shard_index, a.shard_count, a.manifest, cargo_args, a.jobs, a.durations)
    return capture_and_run(cargo_args, a.jobs, a.durations)


if __name__ == "__main__":
    sys.exit(main())
