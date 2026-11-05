# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/bench-quiet.py, and bench/regression-gate.sh's use of it.

The throughput gate measures wall clock on a host it shares with three other
runners and the local gates. On 2026-11-04 it read 1.92M pkts/s (54.5% of
baseline) for a commit that an interleaved A/B on the same host measured
level with its parent (B/A 0.964-1.024 over six pairs): the measurement ran
while a reproducible build and two local cargo builds held the CPU.
"""

import os
import pathlib
import subprocess

import pytest

from conftest import SCRIPTS, load

quiet = load("bench-quiet")
REPO = SCRIPTS.parent
GATE = REPO / "bench" / "regression-gate.sh"

# /proc/stat "cpu" fields: user nice system idle iowait irq softirq steal.
BEFORE = [100, 0, 100, 800, 0, 0, 0, 0]


def test_idle_is_idle_plus_iowait_over_the_interval():
    after = [150, 0, 150, 1650, 50, 0, 0, 0]  # +100 busy, +900 idle/iowait
    assert quiet.idle_pct(BEFORE, after) == pytest.approx(90.0)


def test_a_fully_busy_interval_is_zero_idle():
    after = [1100, 0, 100, 800, 0, 0, 0, 0]
    assert quiet.idle_pct(BEFORE, after) == pytest.approx(0.0)


def test_steal_counts_as_busy():
    after = [100, 0, 100, 1300, 0, 0, 0, 500]
    assert quiet.idle_pct(BEFORE, after) == pytest.approx(50.0)


def test_an_interval_with_no_ticks_is_refused():
    with pytest.raises(ValueError):
        quiet.idle_pct(BEFORE, list(BEFORE))


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


def test_a_quiet_host_is_measured_at_once():
    c = Clock()
    got = quiet.wait_for_quiet(lambda: 97.0, 90, 600, 5, c.now, c.sleep)
    assert got == (True, 97.0, 0.0)


def test_it_waits_until_the_host_goes_quiet():
    c = Clock()
    seq = iter([40.0, 60.0, 95.0])
    got = quiet.wait_for_quiet(lambda: next(seq), 90, 600, 5, c.now, c.sleep)
    assert got == (True, 95.0, 10.0)


def test_a_host_that_never_goes_quiet_ends_at_the_budget():
    c = Clock()
    got = quiet.wait_for_quiet(lambda: 50.0, 90, 20, 5, c.now, c.sleep)
    assert got == (False, 50.0, 20.0)


def test_the_floor_itself_counts_as_quiet():
    c = Clock()
    assert quiet.wait_for_quiet(lambda: 90.0, 90, 0, 5, c.now, c.sleep)[0]


# --- the gate itself, driven end to end with a stand-in binary ------------


def fake_sipnab(tmp_path, seconds):
    """A 'sipnab' that takes `seconds` per run: 535000/seconds pkts/s."""
    p = tmp_path / "sipnab"
    p.write_text(f"#!/bin/sh\nsleep {seconds}\n")
    p.chmod(0o755)
    return p


def run_gate(tmp_path, binary, idle_floor, floor_pct=80):
    corpus = tmp_path / "corpus.pcap"
    corpus.write_bytes(b"\0")
    env = dict(os.environ,
               SIPNAB_BENCH_IDLE_PCT=str(idle_floor),
               SIPNAB_BENCH_QUIET_WAIT="0",
               SIPNAB_PERF_FLOOR_PCT=str(floor_pct))
    return subprocess.run(["bash", str(GATE), str(binary), str(corpus)],
                          cwd=REPO, env=env, capture_output=True, text=True,
                          timeout=120)


def test_the_gate_reports_a_quiet_host_before_measuring(tmp_path):
    # A 1% floor: load on the test host cannot turn this pass into a fail.
    r = run_gate(tmp_path, fake_sipnab(tmp_path, 0.05), 0, floor_pct=1)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = r.stdout.splitlines()
    host = [i for i, l in enumerate(lines) if l.startswith("host ")]
    measured = [i for i, l in enumerate(lines) if l.startswith("measured ")]
    assert host and measured and host[0] < measured[0], r.stdout
    assert "host      quiet" in r.stdout


def test_a_fail_on_a_busy_host_says_the_host_was_busy(tmp_path):
    # 101% idle cannot happen, so the host is never quiet within the budget.
    r = run_gate(tmp_path, fake_sipnab(tmp_path, 0.5), 101)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "host      NOT quiet" in r.stdout
    assert "measured while the host was busy" in r.stdout


def test_a_fail_on_a_quiet_host_does_not_blame_the_host(tmp_path):
    r = run_gate(tmp_path, fake_sipnab(tmp_path, 0.5), 0)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "measured while the host was busy" not in r.stdout


def test_a_busy_host_never_turns_a_fail_into_a_pass(tmp_path):
    # Contention is reported, never excused: the exit status is the floor's.
    r = run_gate(tmp_path, fake_sipnab(tmp_path, 0.5), 101)
    assert r.returncode == 1
    assert "FAIL" in r.stdout
