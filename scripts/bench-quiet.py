#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Wait, for a bounded time, until the host's CPUs are idle enough to measure.

bench/regression-gate.sh runs this right before it measures. The throughput
gate times wall clock on a host it shares with three other runners and the
local gates, so a figure taken while they hold the CPU measures them, not
sipnab. On 2026-11-04 the nightly read 1.92M pkts/s (54.5% of baseline) for
a commit that an interleaved A/B on the same host measured level with its
parent: the measurement ran beside a reproducible build and two local cargo
builds. The measurement itself takes seconds, so waiting for a quiet moment
costs little and removes most of that exposure.

Quiet means the share of CPU time spent idle (idle + iowait, across every
CPU) over a short sample is at least the floor. The default floor is 90%,
the figure bench/baseline.json's idle gate argues for: on 14 cores it leaves
at most 1.4 cores busy beside the measurement.

This never fails the gate and never excuses it. It prints one line, which the
gate echoes, and exits 0 when the host went quiet and 3 when the budget ran
out first; the gate then measures anyway and, if the figure is below the
floor, says the host was busy. The pass/fail decision stays the floor's.

Environment:
    SIPNAB_BENCH_IDLE_PCT    idle floor in percent (default 90)
    SIPNAB_BENCH_QUIET_WAIT  longest wait in seconds (default 1200)
"""

import os
import sys
import time

SAMPLE_S = 2.0


def idle_pct(before, after):
    """Idle share, in percent, between two /proc/stat `cpu` samples.

    Each sample is the first eight fields: user nice system idle iowait irq
    softirq steal. guest and guest_nice are already inside user and nice.
    """
    d = [b - a for a, b in zip(before[:8], after[:8])]
    total = sum(d)
    if total <= 0:
        raise ValueError("no CPU time elapsed between the two samples")
    return 100.0 * (d[3] + d[4]) / total


def wait_for_quiet(sample, floor, budget_s, interval_s, now, sleep):
    """Sample until idle reaches `floor` or `budget_s` has passed.

    Returns (quiet, last idle percent, seconds waited).
    """
    start = now()
    while True:
        idle = sample()
        waited = now() - start
        if idle >= floor:
            return True, idle, waited
        if waited >= budget_s:
            return False, idle, waited
        sleep(interval_s)


def read_cpu():
    with open("/proc/stat") as f:
        for line in f:
            if line.startswith("cpu "):
                return [int(x) for x in line.split()[1:9]]
    raise RuntimeError("/proc/stat has no aggregate cpu line")


def sample_idle():
    before = read_cpu()
    time.sleep(SAMPLE_S)
    return idle_pct(before, read_cpu())


def main():
    floor = float(os.environ.get("SIPNAB_BENCH_IDLE_PCT", "90"))
    budget = float(os.environ.get("SIPNAB_BENCH_QUIET_WAIT", "1200"))
    quiet, idle, waited = wait_for_quiet(
        sample_idle, floor, budget, 5.0, time.monotonic, time.sleep)
    if quiet:
        print(f"host      quiet: CPU {idle:.1f}% idle (floor {floor:g}%), "
              f"after waiting {waited:.0f} s")
        return 0
    print(f"host      NOT quiet: CPU {idle:.1f}% idle, under the {floor:g}% "
          f"floor, after waiting {waited:.0f} s; measuring anyway")
    return 3


if __name__ == "__main__":
    sys.exit(main())
