#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail when offline reconstruction throughput falls well below its recorded
# baseline.
#
# # Why this exists
#
# A 40% `--cores` regression shipped in 0.5.84 and survived four releases. The
# only thing that would have caught it was `docs/benchmarks.md`, which is
# re-measured by hand and had gone 41 releases stale. Nothing in CI measured
# speed at all, so the drop was invisible until someone re-ran the page and
# bisected it.
#
# # Why it is a nightly with a wide band, and not a tight per-PR check
#
# The reference host is a single self-hosted runner that also serves CI. Two
# jobs on it measure their own contention, not the tool -- so a per-PR gate on
# wall clock would be flaky in the direction that trains people to ignore it,
# which is worse than no gate.
#
# So: nightly, and a band wide enough that only a real regression trips it. The
# regression this exists to catch was 40%. Run-to-run spread on an idle host is
# ~2%, and ~10% when something else is running. A 20% floor sits clear of both.
# It will not notice a 5% erosion; noticing that reliably needs a quieter host
# than this project has, and a gate that cries wolf gets muted, at which point
# it catches nothing at all.
#
# The measurement is the 4-CORE figure, deliberately. It is the most
# reproducible point on the curve -- `site_journey_test` already records that a
# clean-clone re-run held it within 0.5% while the 2-core peak spanned
# 2.32-2.36M across replicates.
#
# # Baseline
#
# `bench/baseline.json`, committed. Raising it is a deliberate act in a commit,
# the same as the documentation ratchets. Do NOT lower it to make a red run go
# away -- that converts the gate into a record of whatever happened last.
#
# Usage: bench/regression-gate.sh <sipnab-binary> [corpus.pcap]

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

BIN="${1:?usage: regression-gate.sh <sipnab-binary> [corpus.pcap]}"
CORPUS="${2:-$(mktemp -d)/corpus.pcap}"
BASELINE_FILE="bench/baseline.json"
# Read from the baseline file, where the twelve lines of reasoning for this
# number already live. It used to be a literal 80 here with an env override,
# so `floor_pct` in bench/baseline.json was a knob nothing read: editing the
# number next to its own justification changed nothing. The env var still
# wins, for a one-off run.
FLOOR_PCT="${SIPNAB_PERF_FLOOR_PCT:-}"

[ -x "$BIN" ] || { echo "not executable: $BIN"; exit 2; }
[ -r "$BASELINE_FILE" ] || { echo "missing $BASELINE_FILE"; exit 2; }

# Regenerate rather than store: the generator is deterministic and a 128 MB
# fixture has no business in git. Same parameters the benchmarks page uses.
if [ ! -r "$CORPUS" ]; then
    echo "generating corpus at $CORPUS"
    python3 bench/carrier.py --calls 5000 --out "$CORPUS" -q || exit 2
fi

PACKETS=535000
BASE=$(python3 -c "import json,sys; print(json.load(open('$BASELINE_FILE'))['cores_4_pkts_per_s'])")
if [ -z "$FLOOR_PCT" ]; then
	FLOOR_PCT=$(python3 -c "import json; print(json.load(open('$BASELINE_FILE'))['floor_pct'])")
fi
FLOOR=$(python3 -c "print($BASE * $FLOOR_PCT / 100)")

echo "baseline  ${BASE} pkts/s @ 4 cores"
echo "floor     ${FLOOR} pkts/s (${FLOOR_PCT}% of baseline)"

MEASURED=$(bench/scaling.sh "$BIN" "$CORPUS" "$PACKETS" --cores 4 --runs 5 2>&1 \
    | awk '$1=="4"{ v=$2; sub(/M$/,"",v); printf "%d", v*1000000 }')

if [ -z "$MEASURED" ]; then
    echo "FAIL: the harness produced no 4-core figure at all."
    echo "That is a broken measurement, not a fast one -- refusing to report a pass."
    exit 1
fi

echo "measured  ${MEASURED} pkts/s"
PCT=$(python3 -c "print(f'{$MEASURED / $BASE * 100:.1f}')")
echo "ratio     ${PCT}% of baseline"

if python3 -c "import sys; sys.exit(0 if $MEASURED >= $FLOOR else 1)"; then
    echo "OK"
    exit 0
fi

cat <<EOF
FAIL: throughput is ${PCT}% of baseline, below the ${FLOOR_PCT}% floor.

This is the shape of the 0.5.84 regression: a change that is correct, passes
every test, and costs a large fraction of the packet path. Before touching the
baseline, find out what moved --

  git log --oneline <last-good>..HEAD -- src/
  bench/scaling.sh <old-binary> $CORPUS $PACKETS --cores 4 --runs 5

and bisect across release artifacts, which is cheaper than building each
candidate. Lowering the baseline to make this pass records the regression as
the new normal, which is exactly how the last one survived four releases.
EOF
exit 1
