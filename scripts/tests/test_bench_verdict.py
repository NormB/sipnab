# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/bench-verdict.py, and bench/regression-gate.sh --reference.

The throughput gate shares its host with three other runners and the local
gates. Measured alone, a loaded host reads as a regression: 30.7% of
baseline on 2026-10-15, 34.7% on 2026-10-28 and 54.5% on 2026-11-04, each
for a commit that an interleaved A/B on the same host measured level with
its predecessor. So the gate measures the last release's binary in the same
run, alternating with the candidate, and judges the ratio. Load slows both;
a regression slows only the candidate.
"""

import os
import pathlib
import subprocess

import pytest

from conftest import SCRIPTS, load

verdict = load("bench-verdict")
REPO = SCRIPTS.parent
GATE = REPO / "bench" / "regression-gate.sh"
WORKFLOW = REPO / ".github" / "workflows" / "bench.yml"

BASE = 3_520_000
FLOOR = 80


def test_a_candidate_level_with_the_reference_passes():
    v = verdict.judge([(3.4e6, 3.3e6), (3.5e6, 3.5e6), (3.3e6, 3.4e6)], BASE, FLOOR)
    assert v.status == "ok"
    assert v.exit_code == 0


def test_a_candidate_slower_than_the_floor_ratio_is_a_regression():
    v = verdict.judge([(3.4e6, 2.0e6), (3.5e6, 2.1e6), (3.3e6, 1.9e6)], BASE, FLOOR)
    assert v.status == "regression"
    assert v.exit_code == 1


def test_a_loaded_host_slows_both_and_still_passes_when_the_reference_is_usable():
    # 2026-11-04 12:57Z, load 21: both binaries near 2.9M, B/A about 1.0.
    v = verdict.judge([(2.94e6, 2.89e6), (3.04e6, 2.93e6), (2.75e6, 2.80e6)], BASE, FLOOR)
    assert v.status == "ok"


def test_a_reference_below_the_floor_refuses_to_judge():
    # Both at about 55% of baseline: the host, not the candidate.
    v = verdict.judge([(1.9e6, 1.9e6), (2.0e6, 1.8e6), (1.9e6, 2.0e6)], BASE, FLOOR)
    assert v.status == "too-loaded"
    assert v.exit_code == 3


def test_refusal_wins_even_when_the_ratio_looks_like_a_regression():
    # Under that much load the ratio itself is noise (0.18-0.65M on 10-28).
    v = verdict.judge([(1.0e6, 0.4e6), (1.1e6, 0.5e6), (0.9e6, 0.4e6)], BASE, FLOOR)
    assert v.status == "too-loaded"


def test_the_ratio_is_the_median_of_per_round_ratios():
    # One wild round does not decide it.
    v = verdict.judge([(3.0e6, 3.0e6), (3.0e6, 3.0e6), (3.0e6, 0.3e6)], BASE, FLOOR)
    assert v.ratio == pytest.approx(1.0)
    assert v.status == "ok"


def test_the_floor_ratio_itself_passes():
    v = verdict.judge([(3.0e6, 2.4e6)], BASE, FLOOR)
    assert v.status == "ok"


def test_the_reference_floor_itself_is_usable():
    v = verdict.judge([(BASE * 0.8, BASE * 0.8)], BASE, FLOOR)
    assert v.status == "ok"


def test_no_rounds_is_refused_not_passed():
    with pytest.raises(ValueError, match="no rounds were measured"):
        verdict.judge([], BASE, FLOOR)


def test_a_zero_reference_is_refused_not_divided():
    v = verdict.judge([(0, 3.0e6)], BASE, FLOOR)
    assert v.status == "too-loaded"


def test_one_zero_reference_round_is_refused_even_with_a_good_median():
    v = verdict.judge([(3.0e6, 3.0e6), (3.0e6, 3.0e6), (0, 3.0e6)], BASE, FLOOR)
    assert v.status == "too-loaded"


# --- the gate itself, driven end to end with stand-in binaries -------------


def fake(tmp_path, name, seconds):
    """A 'sipnab' that takes `seconds` per run: 535000/seconds pkts/s.

    Every run other than --version appends `name` to calls.log, so a test can
    read the order the gate really ran the binaries in.
    """
    p = tmp_path / name
    log = tmp_path / "calls.log"
    p.write_text("#!/bin/sh\n"
                 f'[ "$1" = --version ] && {{ echo "fake {name}"; exit 0; }}\n'
                 f"echo {name} >> '{log}'\n"
                 f"sleep {seconds}\n")
    p.chmod(0o755)
    return p


def gate(tmp_path, ref, cand, floor_pct=10, rounds=3):
    """Run the real gate. Load on the host running the tests can only make a
    stand-in slower, so each test picks a floor that load cannot flip: a pass
    uses a low floor, a refusal uses slow stand-ins, and a regression puts a
    wide gap between the two binaries."""
    corpus = tmp_path / "corpus.pcap"
    corpus.write_bytes(b"\0")
    env = dict(os.environ, SIPNAB_BENCH_QUIET_WAIT="0",
               SIPNAB_BENCH_ROUNDS=str(rounds),
               SIPNAB_PERF_FLOOR_PCT=str(floor_pct))
    return subprocess.run(
        ["bash", str(GATE), "--reference", str(ref), str(cand), str(corpus)],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=300)


@pytest.fixture(scope="module")
def level_run(tmp_path_factory):
    """One passing run, read by the tests below: each run costs seconds."""
    d = tmp_path_factory.mktemp("level")
    r = gate(d, fake(d, "ref", 0.05), fake(d, "cand", 0.05))
    r.calls = (d / "calls.log").read_text().split()
    return r


def test_the_gate_passes_a_candidate_level_with_its_reference(level_run):
    r = level_run
    assert r.returncode == 0, r.stdout + r.stderr
    assert "OK" in r.stdout


def test_the_gate_fails_a_candidate_slower_than_its_reference(tmp_path):
    r = gate(tmp_path, fake(tmp_path, "ref", 0.05), fake(tmp_path, "cand", 2.0),
             floor_pct=20, rounds=1)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "FAIL" in r.stdout


def test_the_gate_refuses_to_judge_when_the_reference_is_slow(tmp_path):
    r = gate(tmp_path, fake(tmp_path, "ref", 1.0), fake(tmp_path, "cand", 1.0),
             floor_pct=80, rounds=1)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "host too loaded to judge" in r.stdout
    assert "FAIL: throughput" not in r.stdout


def test_the_gate_records_load_beside_every_round(level_run):
    rounds = [l for l in level_run.stdout.splitlines() if l.startswith("round ")]
    assert len(rounds) == 3, level_run.stdout
    for line in rounds:
        assert "load " in line and "ref " in line and "cand " in line, line


def test_the_gate_alternates_which_binary_runs_first(level_run):
    # Collapse the six runs (warmup + five) of each measurement into one.
    order = [c for i, c in enumerate(level_run.calls)
             if i == 0 or c != level_run.calls[i - 1]]
    assert order == ["ref", "cand", "ref", "cand"], level_run.calls
    assert len(level_run.calls) == 3 * 2 * 6, level_run.calls
    firsts = [l.split("first ")[1].split()[0]
              for l in level_run.stdout.splitlines() if l.startswith("round ")]
    assert firsts == ["ref", "cand", "ref"], level_run.stdout


def test_the_nightly_passes_a_reference_binary():
    text = WORKFLOW.read_text()
    assert "bench/regression-gate.sh --reference" in text
    assert "sha256sum -c" in text, "the reference artifact must be checksum-verified"
