#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Refuse a workflow job that runs the test suite before `cargo fetch --locked`.

Usage: check-suite-fetch.py WORKFLOW.yml [WORKFLOW.yml ...]

Why: tests/release_pipeline_gate_test.rs runs `cargo tree --offline --target
all`, which reads the crates of every platform from the local registry. A
build downloads only the crates of the platform it builds for. With a warm
cargo cache the registry held the others, so the test passed; on main
b8700e3f2 (2026-11-17) a new Cargo.lock missed the macOS cache, and macOS
shard 2 failed: "failed to download `alsa v0.11.0` ... --offline was
specified". `cargo fetch --locked`, with no `--target`, downloads every
platform's crates, so the precondition holds on a cold cache too.

The rule, for each job (a job alias `steps: *name` counts as its own job):
- a step runs the suite when it runs `scripts/parallel-tests.py` (not its
  `merge`), `cargo llvm-cov` (not its `report`) or
  `scripts/check-feature-matrix.py`;
- the job needs a step that runs `cargo fetch --locked` before its first suite
  step, and after the last step before it that restores ~/.cargo/registry
  from actions/cache (a restore can replace the fetched crates).

Exit status: 0 when every job holds, 1 when one does not (one line per job),
2 for a usage error or a file that cannot be read.
scripts/tests/test_check_suite_fetch.py holds it.
"""

import re
import sys
from dataclasses import dataclass

JOB = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(#.*)?$")
STEPS = re.compile(r"^    steps:\s*(?:&(\S+)|\*(\S+))?\s*(#.*)?$")
STEP_START = re.compile(r"^      - ")
SUITE = [
    re.compile(r"scripts/parallel-tests\.py(?!\s+merge\b)"),
    re.compile(r"\bcargo llvm-cov\b(?!\s+report\b)"),
    re.compile(r"scripts/check-feature-matrix\.py"),
]
FETCH = re.compile(r"^(?:-\s+)?(?:run:\s+)?cargo fetch --locked\s*(?:#.*)?$")
CACHE = re.compile(r"\buses:\s+actions/cache(?:/restore)?@")


@dataclass
class Step:
    text: str


def _code_lines(step: Step) -> list[str]:
    """The step's lines that are not comments, stripped."""
    return [s for s in (line.strip() for line in step.text.splitlines()) if s and not s.startswith("#")]


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def jobs(workflow: str) -> dict[str, list[Step]]:
    """Each job's steps, in file order; an alias job gets its anchor's steps."""
    lines = workflow.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if re.match(r"^jobs:\s*(#.*)?$", line))
    except StopIteration:
        return {}
    out: dict[str, list[Step]] = {}
    anchors: dict[str, list[Step]] = {}
    job = None
    steps: list[Step] | None = None
    anchor = None
    current: list[str] | None = None

    def close_step():
        nonlocal current
        if current is not None and steps is not None:
            steps.append(Step("\n".join(current) + "\n"))
        current = None

    for line in lines[start + 1:]:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and _indent(line) == 0:
            break  # the next top-level key ends `jobs:`
        m = JOB.match(line)
        if m:
            close_step()
            job = m.group(1)
            out[job] = []
            steps, anchor = None, None
            continue
        if job is None:
            continue
        m = STEPS.match(line)
        if m:
            close_step()
            if m.group(2):
                out[job] = list(anchors.get(m.group(2), []))
                steps = None
            else:
                steps = out[job]
                anchor = m.group(1)
                if anchor:
                    anchors[anchor] = steps
            continue
        if steps is None:
            continue
        if stripped and not stripped.startswith("#") and _indent(line) <= 4:
            close_step()  # another key of the job ends its steps
            steps = None
            continue
        if STEP_START.match(line):
            close_step()
            current = [line]
        elif current is not None:
            current.append(line)
    close_step()
    return out


def step_name(step: Step) -> str:
    for s in _code_lines(step):
        m = re.match(r"^(?:-\s+)?name:\s*(.+)$", s)
        if m:
            return m.group(1).strip().strip("'\"")
    for s in _code_lines(step):
        m = re.match(r"^(?:-\s+)?uses:\s*(\S+)", s)
        if m:
            return m.group(1)
    return "(unnamed step)"


def runs_suite(step: Step) -> bool:
    return any(p.search(s) for s in _code_lines(step) for p in SUITE)


def fetches_all_targets(step: Step) -> bool:
    return any(FETCH.match(s) for s in _code_lines(step))


def restores_registry(step: Step) -> bool:
    code = _code_lines(step)
    return any(CACHE.search(s) for s in code) and any("~/.cargo/registry" in s for s in code)


def violations(workflow: str, label: str) -> list[str]:
    """One line per job that runs the suite without a fetch it can rely on."""
    out = []
    for job, steps in jobs(workflow).items():
        first = next((i for i, s in enumerate(steps) if runs_suite(s)), None)
        if first is None:
            continue
        before = steps[:first]
        fetch = max((i for i, s in enumerate(before) if fetches_all_targets(s)), default=None)
        restore = max((i for i, s in enumerate(before) if restores_registry(s)), default=None)
        where = f"{label}: job `{job}`, step `{step_name(steps[first])}`"
        if fetch is None:
            out.append(f"{where} runs the suite with no `cargo fetch --locked` step before it")
        elif restore is not None and restore > fetch:
            out.append(
                f"{where}: the cache restore `{step_name(steps[restore])}` comes after `cargo fetch --locked`;"
                " move the fetch after it"
            )
    return out


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: check-suite-fetch.py WORKFLOW.yml [WORKFLOW.yml ...]", file=sys.stderr)
        return 2
    found = []
    for path in argv:
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except OSError as e:
            print(f"check-suite-fetch: cannot read {path}: {e}", file=sys.stderr)
            return 2
        found += violations(text, path)
    for line in found:
        print(line)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
