#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Time sipnab against the other SIP capture tools on one corpus.
#
# Replaces the `fourtool.sh` the benchmarks page has cited for twenty-nine
# releases without ever shipping it. Every tool is driven offline/headless to
# parse the whole file and exit.
#
# A tool that is not installed is reported as MISSING and excluded from the
# table. It is never quietly dropped -- a comparison with a silently absent
# competitor reads exactly like a comparison it won.
#
# Usage:
#   bench/compare.sh <sipnab-binary> <corpus.pcap> [packets] [--runs N]

set -u

die() { echo "error: $*" >&2; exit 1; }

[ $# -ge 2 ] || die "usage: $0 <sipnab-binary> <corpus.pcap> [packets] [--runs N]"

BIN="$1"; shift
CORPUS="$1"; shift

PACKETS=""
case "${1:-}" in
  ''|--*) ;;
  *) PACKETS="$1"; shift ;;
esac

RUNS=5
while [ $# -gt 0 ]; do
  case "$1" in
    --runs) RUNS="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -x "$BIN" ] || die "not executable: $BIN"
[ -r "$CORPUS" ] || die "cannot read corpus: $CORPUS"

if [ -z "$PACKETS" ]; then
  PACKETS=$("$BIN" -N -I "$CORPUS" --no-cli-print 2>&1 \
    | sed -n 's/.*finished: \([0-9]*\) packets.*/\1/p' | tail -1)
  [ -n "$PACKETS" ] || die "could not determine packet count; pass it explicitly"
fi

# Median-of-RUNS wall clock for one command, after a discarded warmup.
time_tool() {
  local stats i t0 t1
  stats=$(mktemp) || return 1
  "$@" >/dev/null 2>&1  # warmup
  i=0
  while [ "$i" -lt "$RUNS" ]; do
    t0=$(date +%s%N)
    "$@" >/dev/null 2>&1 || { rm -f "$stats"; return 1; }
    t1=$(date +%s%N)
    awk -v ns="$((t1 - t0))" 'BEGIN { printf "%.6f\n", ns/1000000000 }' >> "$stats"
    i=$((i + 1))
  done
  awk '
    { w[NR] = $1 }
    END {
      n = NR
      for (i = 2; i <= n; i++) {
        v = w[i]; j = i - 1
        while (j > 0 && w[j] > v) { w[j+1] = w[j]; j-- }
        w[j+1] = v
      }
      printf "%.4f", w[int((n+1)/2)]
    }' "$stats"
  rm -f "$stats"
}

emit() { # emit <label> <what-it-reconstructs> <wall>
  local rate
  rate=$(awk -v p="$PACKETS" -v w="$3" \
    'BEGIN { if (w <= 0) { print "n/a"; exit } printf "%.2fM", p/w/1000000 }')
  printf '%-34s %9s %9s   %s\n' "$1" "$rate" "$3" "$2"
}

echo "corpus:  $CORPUS ($PACKETS packets)"
echo "method:  median-of-$RUNS after 1 discarded warmup"
echo "host:    $(uname -sm), $(nproc) cores"
echo

missing=""
for t in sngrep sipgrep; do
  command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
done
if ! command -v voipmonitor >/dev/null 2>&1 \
   && ! { [ -n "${VM_IMAGE:-}" ] && [ -r "${VM_CONF:-}" ]; }; then
  missing="$missing voipmonitor"
fi

printf '%-34s %9s %9s   %s\n' tool "pkts/s" "wall(s)" "what it reconstructs"
printf '%-34s %9s %9s   %s\n' ---- --------- --------- --------------------

if command -v sngrep >/dev/null 2>&1; then
  w=$(time_tool sngrep -I "$CORPUS" -r -N -q) \
    && emit "sngrep $(sngrep --version 2>&1 | sed -n 's/.*sngrep - \([0-9.]*\).*/\1/p')" \
            "SIP dialogs; no RTP-stream reconstruction headless" "$w"
fi

if command -v sipgrep >/dev/null 2>&1; then
  w=$(time_tool sipgrep -I "$CORPUS" -C -G) \
    && emit "sipgrep $(sipgrep -V 2>&1 | sed -n 's/.*V\([0-9.]*\).*/\1/p')" \
            "grep-style SIP match + Call-ID grouping; no RTP" "$w"
fi

# voipmonitor, either natively or from a container image (VM_IMAGE). It is not
# packaged for most distributions, so the container is the realistic path --
# see bench/voipmonitor.Dockerfile.
#
# The container run does its OWN timing loop, inside a single `docker run`.
# Timing `docker run` itself would charge voipmonitor ~0.8s of container
# startup per invocation, which on this corpus is larger than sipnab's entire
# run -- it would hand sipnab a win worth several multiples, created entirely
# by the measurement apparatus.
VM_CONF="${VM_CONF:-}"
VM_IMAGE="${VM_IMAGE:-}"

if command -v voipmonitor >/dev/null 2>&1 && [ -r "$VM_CONF" ]; then
  w=$(time_tool voipmonitor -r "$CORPUS" -c -k --config-file="$VM_CONF") \
    && emit "voipmonitor $(voipmonitor --version 2>&1 | awk '{print $3}')" \
            "full call/CDR + RTP-stream association" "$w"
elif [ -n "$VM_IMAGE" ] && [ -r "$VM_CONF" ] && command -v docker >/dev/null 2>&1; then
  corpus_dir=$(cd "$(dirname "$CORPUS")" && pwd); corpus_base=$(basename "$CORPUS")
  conf_dir=$(cd "$(dirname "$VM_CONF")" && pwd);  conf_base=$(basename "$VM_CONF")

  vm_ver=$(docker run --rm --network none --entrypoint voipmonitor "$VM_IMAGE" \
             --version 2>&1 | awk '{print $3}')
  w=$(docker run --rm --network none \
        -v "$corpus_dir:/corpus:ro" -v "$conf_dir:/conf:ro" \
        --entrypoint sh "$VM_IMAGE" -c '
          vm() { voipmonitor -r /corpus/'"$corpus_base"' -c -k \
                   --config-file=/conf/'"$conf_base"' >/dev/null 2>&1; }
          vm    # warmup, discarded
          i=0
          while [ $i -lt '"$RUNS"' ]; do
            s=$(date +%s%N); vm; e=$(date +%s%N)
            awk -v n=$((e - s)) "BEGIN { printf \"%.6f\n\", n/1000000000 }"
            i=$((i + 1))
          done' | awk '
        { w[NR] = $1 }
        END {
          n = NR
          for (i = 2; i <= n; i++) {
            v = w[i]; j = i - 1
            while (j > 0 && w[j] > v) { w[j+1] = w[j]; j-- }
            w[j+1] = v
          }
          printf "%.4f", w[int((n+1)/2)]
        }') \
    && emit "voipmonitor $vm_ver (container)" \
            "full call/CDR + RTP-stream association" "$w"
fi

ver=$("$BIN" --version 2>&1 | awk '{print $2}')
for n in 1 4; do
  w=$(time_tool "$BIN" -N -I "$CORPUS" --cores "$n" --report --no-cli-print) \
    && emit "sipnab $ver --cores $n" "SIP dialogs + full RTP-stream reconstruction" "$w"
done

if [ -n "$missing" ]; then
  echo
  echo "MISSING (excluded from the table, NOT counted as a sipnab win):$missing"
  echo "voipmonitor additionally needs VM_CONF pointing at a config with"
  echo "sdp_multiplication=0, or it suppresses this corpus's duplicate-SDP streams."
fi
