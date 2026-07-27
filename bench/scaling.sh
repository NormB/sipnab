#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Measure sipnab offline reconstruction throughput and peak RSS.
#
# Companion to bench/carrier.py. Together they are the complete recipe behind
# the numbers on the benchmarks page -- which for twenty-nine releases claimed
# to be reproducible while the harness sat in an unpublished repository.
#
# Method: median-of-N after one discarded warmup, so the corpus is in page
# cache for every timed run. pkts/s = packets / wall-clock.
#
# Usage:
#   bench/scaling.sh <sipnab-binary> <corpus.pcap> [packets] [--cores LIST] [--runs N]
#
# Example:
#   bench/scaling.sh ./sipnab corpus.pcap 535000 --cores 1,2,4,8 --runs 5

set -u

die() { echo "error: $*" >&2; exit 1; }

[ $# -ge 2 ] || die "usage: $0 <sipnab-binary> <corpus.pcap> [packets] [--cores LIST] [--runs N]"

BIN="$1"; shift
CORPUS="$1"; shift

PACKETS=""
case "${1:-}" in
  ''|--*) ;;
  *) PACKETS="$1"; shift ;;
esac

CORES="1,2,4,8"
RUNS=5
while [ $# -gt 0 ]; do
  case "$1" in
    --cores) CORES="${2:-}"; shift 2 ;;
    --runs)  RUNS="${2:-}";  shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -x "$BIN" ] || die "not executable: $BIN"
[ -r "$CORPUS" ] || die "cannot read corpus: $CORPUS"

# Packet count: trust the caller, else ask sipnab to count them.
if [ -z "$PACKETS" ]; then
  PACKETS=$("$BIN" -N -I "$CORPUS" --no-cli-print 2>&1 \
    | sed -n 's/.*finished: \([0-9]*\) packets.*/\1/p' | tail -1)
  [ -n "$PACKETS" ] || die "could not determine packet count; pass it explicitly"
fi

# GNU time gives wall-clock and peak RSS in one measurement. BSD/macOS `time`
# does not, so require the GNU one rather than silently reporting nothing.
TIME_BIN=""
for c in /usr/bin/time gtime; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -f '%e %M' true >/dev/null 2>&1; then
    TIME_BIN="$c"; break
  fi
done
[ -n "$TIME_BIN" ] || die "GNU time not found (need /usr/bin/time or gtime)"

echo "binary:  $("$BIN" --version 2>&1 | head -1)"
echo "corpus:  $CORPUS ($PACKETS packets)"
echo "method:  median-of-$RUNS after 1 discarded warmup"
echo "host:    $(uname -sm), $(nproc) cores"
echo

printf '%-6s %10s %10s %10s %10s\n' cores pkts/s "wall(s)" "RSS(MiB)" runs
printf '%-6s %10s %10s %10s %10s\n' ------ ---------- ---------- ---------- ----------

IFS=','
for n in $CORES; do
  unset IFS
  stats=$(mktemp) || die "mktemp failed"

  # Warmup: pulls the corpus into page cache. Discarded.
  "$BIN" -N -I "$CORPUS" --cores "$n" --report --no-cli-print >/dev/null 2>&1

  # `time -f %e` resolves only to 10 ms, which on a sub-second corpus is two
  # significant figures. Wall-clock therefore comes from a nanosecond clock and
  # GNU time is kept solely for peak RSS.
  i=0
  while [ "$i" -lt "$RUNS" ]; do
    t0=$(date +%s%N)
    "$TIME_BIN" -f '%M' -o "$stats.rss" -a \
      "$BIN" -N -I "$CORPUS" --cores "$n" --report --no-cli-print >/dev/null 2>&1 \
      || die "sipnab failed at --cores $n"
    t1=$(date +%s%N)
    awk -v ns="$((t1 - t0))" -v rss="$(tail -1 "$stats.rss")" \
      'BEGIN { printf "%.6f %s\n", ns/1000000000, rss }' >> "$stats"
    i=$((i + 1))
  done

  # Median wall-clock, and the peak RSS observed across the timed runs.
  set -- $(awk '
    { w[NR] = $1; if ($2 > rss) rss = $2 }
    END {
      n = NR
      # insertion sort; n is 5, so the cost is irrelevant
      for (i = 2; i <= n; i++) {
        v = w[i]; j = i - 1
        while (j > 0 && w[j] > v) { w[j+1] = w[j]; j-- }
        w[j+1] = v
      }
      printf "%.4f %.1f", w[int((n+1)/2)], rss/1024
    }' "$stats")
  med_wall="$1"
  peak_rss="$2"

  rate=$(awk -v p="$PACKETS" -v w="$med_wall" \
    'BEGIN { if (w <= 0) { print "n/a"; exit } printf "%.2fM", p/w/1000000 }')
  printf '%-6s %10s %10s %10s %10s\n' "$n" "$rate" "$med_wall" "$peak_rss" "$RUNS"
  rm -f "$stats" "$stats.rss"
  IFS=','
done
unset IFS
