#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Print where the pre-commit hook spent its time.

usage: hook-steps.py [--log FILE] [--runs N | --mean N]

.githooks/pre-commit appends one line per step to
`<git-dir>/sipnab-pre-commit-steps.log`: the run (its start time in UTC and
the hook's process number), the step as the hook prints it, whole seconds and
the exit status, separated by tabs. The last line of a run is the step
`total`. A run that a pass stamp skipped whole writes nothing; a run that was
killed has no `total` line. A run whose suite passed also has a note, a line
of three fields: the run, `nextest`, and nextest's Summary line (tests run,
passed, skipped); the table of the run ends with it.

With no option the script prints the table of the newest run. `--runs N`
prints the newest N runs, oldest first. `--mean N` prints, for each step, the
mean and the longest time over the newest N runs that passed.

Exit status: 0 printed; 1 no log, or no line to print; 2 usage.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
from typing import NamedTuple

LOG_NAME = "sipnab-pre-commit-steps.log"
TOTAL = "total"
OUTSIDE = "(outside the steps)"
# The notes a run can leave: a line of three fields, the second one of these.
# `nextest` is the Summary line of a suite that passed.
NOTES = ("nextest",)
SCRIPTS = pathlib.Path(__file__).resolve().parent


class Row(NamedTuple):
    run: str
    step: str
    seconds: int
    rc: int


def parse(text: str) -> tuple:
    """The step lines of a log, and the count of lines that are not one.

    A line that is not four tab-separated fields with a run, a step, and two
    whole numbers is counted and left out: the log is appended to by a shell,
    and a killed hook can leave a torn last line."""
    rows, bad = [], 0
    for line in text.splitlines():
        if not line.strip() or _note(line) is not None:
            continue
        parts = line.split("\t")
        if (len(parts) != 4 or not parts[0].strip() or not parts[1].strip()
                or not re.fullmatch(r"\d+", parts[2]) or not re.fullmatch(r"\d+", parts[3])):
            bad += 1
            continue
        rows.append(Row(parts[0], parts[1], int(parts[2]), int(parts[3])))
    return rows, bad


def _note(line: str) -> tuple | None:
    """(run, name, text) of a note line: three fields, the second a NOTE name."""
    parts = line.split("\t")
    if len(parts) == 3 and parts[0].strip() and parts[1] in NOTES and parts[2].strip():
        return parts[0], parts[1], parts[2].strip()
    return None


def notes(text: str) -> dict:
    """{run: ["name: text", ...]} for the note lines of a log, in log order."""
    by: dict = {}
    for line in text.splitlines():
        note = _note(line)
        if note is not None:
            by.setdefault(note[0], []).append(f"{note[1]}: {note[2]}")
    return by


def runs(rows) -> dict:
    """The rows of each run, runs in the order their first line appears."""
    by: dict = {}
    for row in rows:
        by.setdefault(row.run, []).append(row)
    return by


def total_of(rows) -> Row | None:
    return next((r for r in rows if r.step == TOTAL), None)


def passed(rows) -> bool:
    total = total_of(rows)
    return total is not None and total.rc == 0


def _share(seconds: int, total: Row | None) -> str:
    if total is None or total.seconds <= 0:
        return "-"
    return f"{100 * seconds / total.seconds:.1f}%"


def _headline(run: str, steps, total: Row | None) -> str:
    if total is None:
        return (f"run {run}: NOT ENDED (no total line: the hook was killed, or is running); "
                f"{sum(r.seconds for r in steps)} s in its steps")
    if total.rc == 0:
        return f"run {run}: passed in {total.seconds} s"
    failed = next((r for r in steps if r.rc != 0), None)
    where = f"at {failed.step}" if failed else "outside the steps"
    return f"run {run}: FAILED {where} (exit status {total.rc}) after {total.seconds} s"


def table(run: str, rows) -> str:
    """The table of one run: a line per step, the time outside every step,
    and the total. A share is of the run's total."""
    steps = [r for r in rows if r.step != TOTAL]
    total = total_of(rows)
    width = max([len(OUTSIDE), len("step"), *(len(r.step) for r in steps)])
    lines = [_headline(run, steps, total), f"{'step'.ljust(width)}  {'seconds':>7}  {'share':>6}  rc"]
    for r in steps:
        lines.append(f"{r.step.ljust(width)}  {r.seconds:>7}  {_share(r.seconds, total):>6}  {r.rc}")
    if total is not None:
        rest = max(0, total.seconds - sum(r.seconds for r in steps))
        lines.append(f"{OUTSIDE.ljust(width)}  {rest:>7}  {_share(rest, total):>6}")
        lines.append(f"{TOTAL.ljust(width)}  {total.seconds:>7}  {_share(total.seconds, total):>6}  {total.rc}")
    return "\n".join(lines)


def mean_table(by: dict, newest: int) -> str | None:
    """Mean and longest seconds of each step over the newest `newest` runs
    that passed; None when no run passed. A step is counted in the runs that
    have it."""
    good = [rows for rows in by.values() if passed(rows)]
    if not good:
        return None
    left_out = len(by) - len(good)
    good = good[-newest:]
    times: dict = {}
    for rows in reversed(good):  # the newest run decides the order of the steps
        for r in rows:
            times.setdefault(r.step, []).append(r.seconds)
    head = f"mean of {len(good)} {'run' if len(good) == 1 else 'runs'} that passed"
    if left_out:
        head += f" ({left_out} that did not {'is' if left_out == 1 else 'are'} left out)"
    width = max(len("step"), *(len(s) for s in times))
    lines = [head, f"{'step'.ljust(width)}  {'mean':>7}  {'longest':>7}  runs"]
    for step, seconds in times.items():
        lines.append(f"{step.ljust(width)}  {round(sum(seconds) / len(seconds)):>7}  {max(seconds):>7}  {len(seconds)}")
    return "\n".join(lines)


def git_dir() -> pathlib.Path:
    out = subprocess.run(["git", "rev-parse", "--absolute-git-dir"], capture_output=True, text=True,
                         check=True, cwd=SCRIPTS).stdout.strip()
    return pathlib.Path(out)


def default_log() -> pathlib.Path:
    return git_dir() / LOG_NAME


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hook-steps.py")
    p.add_argument("--log", help=f"the step log (default: {LOG_NAME} in this checkout's git directory)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--runs", type=int, default=1, help="print the newest N runs (default 1)")
    g.add_argument("--mean", type=int, help="print each step's mean over the newest N runs that passed")
    try:
        args = p.parse_args(argv)
    except SystemExit:
        return 2
    if args.runs < 1 or (args.mean is not None and args.mean < 1):
        print("hook-steps: --runs and --mean take a number of runs, 1 or more", file=sys.stderr)
        return 2
    log = pathlib.Path(args.log) if args.log else default_log()
    try:
        text = log.read_text(errors="replace")
    except OSError as e:
        print(f"hook-steps: {log} cannot be read ({e.strerror}); the hook writes it on its next full run",
              file=sys.stderr)
        return 1
    rows, bad = parse(text)
    if bad:
        print(f"hook-steps: {bad} line of the log is not a step line and was left out" if bad == 1 else
              f"hook-steps: {bad} lines of the log are not step lines and were left out", file=sys.stderr)
    if not rows:
        print(f"hook-steps: {log} holds no step line", file=sys.stderr)
        return 1
    by = runs(rows)
    if args.mean is not None:
        text = mean_table(by, args.mean)
        if text is None:
            print(f"hook-steps: {log} holds no run that passed", file=sys.stderr)
            return 1
        print(text)
        return 0
    noted = notes(text)
    print("\n\n".join("\n".join([table(run, by[run]), *noted.get(run, [])]) for run in list(by)[-args.runs:]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
