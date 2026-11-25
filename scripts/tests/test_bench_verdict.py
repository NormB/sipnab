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

import json
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


# A baseline so low that no stand-in, however loaded the host, measures under
# a floor of it: the tests that judge a ratio cannot be refused as "too loaded".
TEST_BASELINE_PKTS = 1000


def baseline_file(tmp_path, pkts=TEST_BASELINE_PKTS, floor_pct=80, name="baseline.json"):
    p = tmp_path / name
    p.write_text(json.dumps({"cores_4_pkts_per_s": pkts, "floor_pct": floor_pct}))
    return p


def gate(tmp_path, ref, cand, floor_pct=80, rounds=3, baseline="test"):
    """Run the real gate. Load on the host running the tests can only make a
    stand-in slower, and it slows each run by about the same added time, which
    narrows the gap between two stand-ins (2026-11-21: about 3 ms a run at load
    8, about 0.5 s at load 24). So the ratio tests read a test baseline the
    refusal cannot trip on, and a floor that a regression's gap stays under
    for any added time up to OVERHEAD_LIMIT. `baseline=None` reads the
    committed bench/baseline.json."""
    corpus = tmp_path / "corpus.pcap"
    corpus.write_bytes(b"\0")
    env = dict(os.environ, SIPNAB_BENCH_QUIET_WAIT="0",
               SIPNAB_BENCH_ROUNDS=str(rounds),
               SIPNAB_PERF_FLOOR_PCT=str(floor_pct))
    env.pop("SIPNAB_BENCH_BASELINE_FILE", None)
    if baseline == "test":
        env["SIPNAB_BENCH_BASELINE_FILE"] = str(baseline_file(tmp_path))
    elif baseline is not None:
        env["SIPNAB_BENCH_BASELINE_FILE"] = str(baseline)
    return subprocess.run(
        ["bash", str(GATE), "--reference", str(ref), str(cand), str(corpus)],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=300)


@pytest.fixture(scope="module")
def level_run(tmp_path_factory):
    """One passing run, read by the tests below: each run costs seconds."""
    d = tmp_path_factory.mktemp("level")
    r = gate(d, fake(d, "ref", 0.05), fake(d, "cand", 0.05), floor_pct=10)
    r.calls = (d / "calls.log").read_text().split()
    return r


def test_the_gate_passes_a_candidate_level_with_its_reference(level_run):
    r = level_run
    assert r.returncode == 0, r.stdout + r.stderr
    assert "OK" in r.stdout


# The regression stand-ins and the floor that judges them. Every run of both
# pays the same added time o on a loaded host, so the ratio the gate sees is
# (REG_REF + o) / (REG_CAND + o); it stays under the floor while
# o < (floor * REG_CAND - REG_REF) / (1 - floor) = OVERHEAD_LIMIT.
REG_REF = 0.05
REG_CAND = 2.0
REG_FLOOR_PCT = 80
OVERHEAD_LIMIT = (REG_FLOOR_PCT / 100 * REG_CAND - REG_REF) / (1 - REG_FLOOR_PCT / 100)


def test_the_regression_floor_holds_for_seconds_of_added_time_a_run():
    # 7.75 s a run: fifteen times the 0.5 s the failing hook run of
    # 2026-11-21 implied at load 24.
    assert OVERHEAD_LIMIT > 7.0, OVERHEAD_LIMIT


def test_the_gate_fails_a_candidate_slower_than_its_reference(tmp_path):
    r = gate(tmp_path, fake(tmp_path, "ref", REG_REF), fake(tmp_path, "cand", REG_CAND),
             floor_pct=REG_FLOOR_PCT, rounds=1)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "FAIL" in r.stdout


def test_a_regression_is_caught_when_every_run_pays_the_same_added_time(tmp_path):
    # The 2026-11-21 failure, made deterministic: both stand-ins take 0.5 s
    # more a run, as the loaded host's start-up cost did. With the committed
    # baseline and a 20% floor the gate printed "ratio 24.4%" and "verdict OK".
    added = 0.5
    r = gate(tmp_path, fake(tmp_path, "ref", REG_REF + added),
             fake(tmp_path, "cand", REG_CAND + added), floor_pct=REG_FLOOR_PCT, rounds=1)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "FAIL: throughput" in r.stdout, r.stdout


def test_the_gate_reads_the_baseline_file_the_environment_names(tmp_path):
    named = baseline_file(tmp_path, pkts=4000, floor_pct=50, name="named.json")
    env = dict(os.environ, SIPNAB_BENCH_QUIET_WAIT="0", SIPNAB_BENCH_ROUNDS="1",
               SIPNAB_BENCH_BASELINE_FILE=str(named))
    env.pop("SIPNAB_PERF_FLOOR_PCT", None)
    corpus = tmp_path / "corpus.pcap"
    corpus.write_bytes(b"\0")
    r = subprocess.run(["bash", str(GATE), "--reference", str(fake(tmp_path, "ref", 0.05)),
                        str(fake(tmp_path, "cand", 0.05)), str(corpus)],
                       cwd=REPO, env=env, capture_output=True, text=True, timeout=300)
    assert "baseline  4000 pkts/s" in r.stdout, r.stdout + r.stderr
    assert "(50% of baseline)" in r.stdout, r.stdout
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_named_baseline_file_that_does_not_exist_is_a_usage_error(tmp_path):
    missing = tmp_path / "absent.json"
    r = gate(tmp_path, fake(tmp_path, "ref", 0.05), fake(tmp_path, "cand", 0.05),
             rounds=1, baseline=missing)
    assert r.returncode == 2, r.stdout + r.stderr
    assert f"missing {missing}" in r.stdout, r.stdout


def test_a_baseline_path_with_a_quote_is_read_as_a_path(tmp_path):
    # The path reaches python as an argument, not as text inside its code.
    d = tmp_path / "it's here"
    d.mkdir()
    named = baseline_file(d, pkts=6000, floor_pct=10)
    r = gate(tmp_path, fake(tmp_path, "ref", 0.05), fake(tmp_path, "cand", 0.05),
             floor_pct=10, rounds=1, baseline=named)
    assert "baseline  6000 pkts/s" in r.stdout, r.stdout + r.stderr
    assert r.returncode == 0, r.stdout + r.stderr


def test_an_empty_baseline_variable_reads_the_committed_baseline(tmp_path):
    r = gate(tmp_path, fake(tmp_path, "ref", 0.05), fake(tmp_path, "cand", 0.05),
             floor_pct=1, rounds=1, baseline="")
    assert f"baseline  {GATE_BASELINE} pkts/s" in r.stdout, r.stdout + r.stderr


# What the gate's packet count and the committed baseline make of a stand-in's
# sleep: the gate reports 535000 / seconds as pkts/s (bench/regression-gate.sh
# PACKETS) and reads the baseline from bench/baseline.json.
GATE_PACKETS = 535_000
GATE_BASELINE = json.loads((REPO / "bench" / "baseline.json").read_text())["cores_4_pkts_per_s"]
REFUSAL_SECONDS = GATE_PACKETS / (0.8 * GATE_BASELINE)
REF_SLOW = 0.4


def test_the_stand_in_arithmetic_reads_the_gates_own_packet_count():
    assert f"PACKETS={GATE_PACKETS}\n" in GATE.read_text()


def test_the_gate_refuses_to_judge_when_the_reference_is_slow(tmp_path):
    # The refusal reads the reference alone. With an 80% floor the reference
    # is refused when it measures under 0.8 x the baseline, that is when one
    # run of the 535,000-packet corpus takes longer than
    # REFUSAL_SECONDS = 535000 / (0.8 x baseline): 0.19 s at the baseline of
    # 3,520,000 pkts/s. The reference stand-in takes 0.4 s a run, 2.1 times
    # that, and load on the test host only makes it slower. The candidate is
    # fast (0.05 s): nothing about it can cause the refusal, and a gate that
    # judged the ratio here would report a pass, not exit status 3.
    assert REF_SLOW > 2 * REFUSAL_SECONDS, (REF_SLOW, REFUSAL_SECONDS)
    r = gate(tmp_path, fake(tmp_path, "ref", REF_SLOW), fake(tmp_path, "cand", 0.05),
             floor_pct=80, rounds=1, baseline=None)
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
