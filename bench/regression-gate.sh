#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
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
# # Against a reference, in the same run
#
# The nightly passes `--reference <last release's binary>`. The host is shared
# with three other runners and the local gates, and a figure measured alone
# reads their load as a regression: 30.7% of baseline on 2026-10-15, 34.7% on
# 2026-10-28 and 54.5% on 2026-11-04, each for a commit an interleaved A/B on
# the same host measured level with its predecessor. With a reference the
# gate measures both binaries alternately, SIPNAB_BENCH_ROUNDS rounds (default
# 5), prints the load average beside every round, and judges the median
# candidate/reference ratio. scripts/bench-verdict.py holds the rule: a
# reference under floor_pct of the baseline means the host is too loaded to
# judge (exit 3, distinct from a regression's exit 1). Without --reference
# the gate judges the candidate against the baseline alone, as it always did.
#
# Usage: bench/regression-gate.sh [--reference <ref-binary>] <sipnab-binary> [corpus.pcap]
# Exit:  0 pass, 1 regression or broken measurement, 2 usage, 3 too loaded to judge.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

USAGE="usage: regression-gate.sh [--reference <ref-binary>] <sipnab-binary> [corpus.pcap]"
REF=""
if [ "${1:-}" = "--reference" ]; then
    REF="${2:?$USAGE}"
    shift 2
fi
BIN="${1:?$USAGE}"
CORPUS="${2:-$(mktemp -d)/corpus.pcap}"
ROUNDS="${SIPNAB_BENCH_ROUNDS:-5}"
BASELINE_FILE="bench/baseline.json"
# Read from the baseline file, where the twelve lines of reasoning for this
# number already live. It used to be a literal 80 here with an env override,
# so `floor_pct` in bench/baseline.json was a knob nothing read: editing the
# number next to its own justification changed nothing. The env var still
# wins, for a one-off run.
FLOOR_PCT="${SIPNAB_PERF_FLOOR_PCT:-}"

[ -x "$BIN" ] || { echo "not executable: $BIN"; exit 2; }
[ -z "$REF" ] || [ -x "$REF" ] || { echo "not executable: $REF"; exit 2; }
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

# Measure on a quiet host if one comes within the budget. The wait reports the
# host's state; it never decides the result.
python3 scripts/bench-quiet.py
QUIET_RC=$?

# One 4-core figure, median-of-5 after a warmup, in whole pkts/s.
measure() {
    bench/scaling.sh "$1" "$CORPUS" "$PACKETS" --cores 4 --runs 5 2>&1 \
        | awk '$1=="4"{ v=$2; sub(/M$/,"",v); printf "%d", v*1000000 }'
}

broken() {
    echo "FAIL: the harness produced no 4-core figure for $1."
    echo "That is a broken measurement, not a fast one -- refusing to report a pass."
    exit 1
}

advice() {
    cat <<EOF

This is the shape of the 0.5.84 regression: a change that is correct, passes
every test, and costs a large fraction of the packet path. Before touching the
baseline, find out what moved --

  git log --oneline <last-good>..HEAD -- src/
  bench/scaling.sh <old-binary> $CORPUS $PACKETS --cores 4 --runs 5

and bisect across release artifacts, which is cheaper than building each
candidate. Lowering the baseline to make this pass records the regression as
the new normal, which is exactly how the last one survived four releases.
EOF
}

if [ -n "$REF" ]; then
    echo "reference $("$REF" --version 2>&1 | sed -n 1p)"
    echo "candidate $("$BIN" --version 2>&1 | sed -n 1p)"
    PAIRS=""
    i=1
    while [ "$i" -le "$ROUNDS" ]; do
        load=$(cut -d' ' -f1 /proc/loadavg)
        # Alternate which binary goes first, so neither always meets the
        # warmer or the colder moment of a round.
        if [ $((i % 2)) -eq 1 ]; then
            first=ref; r=$(measure "$REF"); c=$(measure "$BIN")
        else
            first=cand; c=$(measure "$BIN"); r=$(measure "$REF")
        fi
        [ -n "$r" ] || broken "the reference"
        [ -n "$c" ] || broken "the candidate"
        echo "round $i  load $load  first $first  ref $r  cand $c"
        PAIRS="${PAIRS}${r} ${c}
"
        i=$((i + 1))
    done
    printf '%s' "$PAIRS" | python3 scripts/bench-verdict.py "$BASE" "$FLOOR_PCT"
    rc=$?
    case $rc in
        0) echo "OK"; exit 0 ;;
        1) echo "FAIL: throughput is below ${FLOOR_PCT}% of the reference measured in the same run."
           advice; exit 1 ;;
        3) cat <<EOF

Not judged. The reference binary itself measured under ${FLOOR_PCT}% of the
baseline, so the host was too busy for the ratio to mean anything -- see the
load beside each round. If the load was low, the reference release itself is
slow, and that is a regression which shipped: measure it against the commit
in bench/baseline.json. Re-run the workflow; do not lower the baseline.
EOF
           exit 3 ;;
        *) exit 2 ;;
    esac
fi

MEASURED=$(measure "$BIN")
[ -n "$MEASURED" ] || broken "the candidate"

echo "measured  ${MEASURED} pkts/s"
PCT=$(python3 -c "print(f'{$MEASURED / $BASE * 100:.1f}')")
echo "ratio     ${PCT}% of baseline"

if python3 -c "import sys; sys.exit(0 if $MEASURED >= $FLOOR else 1)"; then
    echo "OK"
    exit 0
fi

echo "FAIL: throughput is ${PCT}% of baseline, below the ${FLOOR_PCT}% floor."
if [ "$QUIET_RC" -ne 0 ]; then
    cat <<EOF

This figure was measured while the host was busy (see the host line above),
so it may be contention rather than the tool. Re-run the workflow on a quiet
host before bisecting, and do not lower the baseline either way.
EOF
fi
advice
exit 1
