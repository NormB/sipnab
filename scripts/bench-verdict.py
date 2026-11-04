#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Judge a candidate's throughput against a reference measured in the same run.

bench/regression-gate.sh --reference measures the last release's binary and
the candidate alternately, round by round, and pipes one line per round,
"<reference pkts/s> <candidate pkts/s>", to this script.

Why a reference. The gate's host is shared with three other runners and the
local gates, so a figure measured alone reads load as a regression: 30.7% of
baseline on 2026-10-15, 34.7% on 2026-10-28 and 54.5% on 2026-11-04, each for
a commit an interleaved A/B on the same host measured level with its
predecessor. Load slows both binaries of a round; a regression slows only the
candidate. So the ratio is what is judged.

The rule, one place:

* The reference's median must reach floor_pct of the committed baseline.
  Below that, the host is too loaded for the ratio to mean anything (on
  2026-10-28 at load 26-32 the same binary measured 0.18 to 0.65M), and the
  verdict is "too-loaded", exit 3: a refusal to judge, not a pass and not a
  regression. A reference release that is itself slow lands here too, which
  is why the message names both causes rather than hiding the second.
* Otherwise the median of the per-round candidate/reference ratios must reach
  floor_pct. Below that the verdict is "regression", exit 1.
* Otherwise "ok", exit 0.

Usage: bench-verdict.py <baseline pkts/s> <floor pct>   (rounds on stdin)
"""

import statistics
import sys
from dataclasses import dataclass


@dataclass
class Verdict:
    status: str  # "ok", "regression" or "too-loaded"
    exit_code: int
    ratio: float  # median candidate/reference, 0.0 when not computed
    reference: float  # median reference pkts/s
    candidate: float  # median candidate pkts/s


def judge(rounds, baseline, floor_pct):
    """Judge rounds of (reference, candidate) pkts/s. See the module doc."""
    if not rounds:
        raise ValueError("no rounds were measured")
    ref = statistics.median(r for r, _ in rounds)
    cand = statistics.median(c for _, c in rounds)
    if ref < baseline * floor_pct / 100 or any(r <= 0 for r, _ in rounds):
        return Verdict("too-loaded", 3, 0.0, ref, cand)
    ratio = statistics.median(c / r for r, c in rounds)
    if ratio * 100 < floor_pct:
        return Verdict("regression", 1, ratio, ref, cand)
    return Verdict("ok", 0, ratio, ref, cand)


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    baseline, floor_pct = float(argv[1]), float(argv[2])
    rounds = []
    for line in sys.stdin:
        parts = line.split()
        if len(parts) == 2:
            rounds.append((float(parts[0]), float(parts[1])))
    try:
        v = judge(rounds, baseline, floor_pct)
    except ValueError as e:
        print(f"FAIL: {e}; refusing to report a pass.")
        return 2
    print(f"reference {v.reference:.0f} pkts/s median "
          f"({v.reference / baseline * 100:.1f}% of baseline)")
    print(f"candidate {v.candidate:.0f} pkts/s median")
    if v.status == "too-loaded":
        print(f"verdict   host too loaded to judge: the reference reached "
              f"{v.reference / baseline * 100:.1f}% of baseline, under the "
              f"{floor_pct:g}% it needs.")
        return v.exit_code
    print(f"ratio     {v.ratio * 100:.1f}% of the reference "
          f"(median of {len(rounds)} rounds)")
    print("verdict   " + ("OK" if v.status == "ok" else "regression"))
    return v.exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
