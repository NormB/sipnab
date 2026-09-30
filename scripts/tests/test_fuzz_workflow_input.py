"""fuzz.yml's `max_total_time` dispatch input is validated before it is used.

OpenSSF Baseline BR-01.04 asks that a workflow validate input a collaborator
can supply. `max_total_time` is a free-form `workflow_dispatch` string. It
already reaches the shell through `env:` and is quoted, so it cannot inject a
command, but nothing checked that it is a number: a typo reached libFuzzer as
`-max_total_time=abc` and ran with whatever libFuzzer made of it.

These tests cut the run script out of the workflow and execute it with a stub
`cargo` that records its arguments, so nothing is built or fuzzed.
"""

import os
import pathlib
import re
import stat
import subprocess
import textwrap

WORKFLOW = pathlib.Path(__file__).resolve().parents[2] / ".github/workflows/fuzz.yml"
STEP = "Run ${{ matrix.target }}"


def _run_block() -> str:
    text = WORKFLOW.read_text()
    parts = re.split(r"(?m)^      - name: ", text)
    step = next(p for p in parts[1:] if p.splitlines()[0].strip() == STEP)
    lines = step.splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip() == "run: |") + 1
    body = []
    for line in lines[start:]:
        if line.strip() and not line.startswith("          "):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body))


def _run(tmp_path: pathlib.Path, value: str) -> tuple[int, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "cargo-args"
    cargo = bin_dir / "cargo"
    cargo.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "$CARGO_LOG"\n')
    cargo.chmod(cargo.stat().st_mode | stat.S_IXUSR)
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "TARGET": "fuzz_sip_parser",
        "MAX_TOTAL_TIME": value,
        "CARGO_LOG": str(log),
    }
    proc = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", _run_block()],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    return proc.returncode, log.read_text() if log.exists() else ""


def test_a_whole_number_reaches_libfuzzer(tmp_path):
    rc, args = _run(tmp_path, "300")
    assert rc == 0, "a valid max_total_time must run"
    assert "-max_total_time=300" in args.splitlines()


def test_anything_else_stops_the_job_before_cargo_runs(tmp_path):
    for i, bad in enumerate(["abc", "", "0", "30s", "-1", "1e3", "300 ", "1;true"]):
        case = tmp_path / str(i)
        case.mkdir()
        rc, args = _run(case, bad)
        assert rc != 0, f"max_total_time={bad!r} was accepted"
        assert args == "", f"max_total_time={bad!r} reached cargo: {args!r}"
