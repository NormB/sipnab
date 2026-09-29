#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
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


def target_dir() -> str:
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        stdout=subprocess.PIPE,
        check=True,
    )
    return json.loads(out.stdout)["target_directory"]


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
    p = argparse.ArgumentParser(prog="parallel-tests.py")
    p.add_argument("--jobs", type=int, default=DEFAULT_JOBS)
    p.add_argument("--durations")
    p.add_argument("cargo_args", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    cargo_args = a.cargo_args[1:] if a.cargo_args[:1] == ["--"] else a.cargo_args
    return capture_and_run(cargo_args, a.jobs, a.durations)


if __name__ == "__main__":
    sys.exit(main())
