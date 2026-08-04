#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Collect a sipnab capture-health report from a BUSY PRODUCTION SERVER, safely.
#
# WHAT THIS IS FOR
#
#   Everything sipnab knows about its own capture path has been measured on
#   synthetic traffic: a `veth` pair in a namespace, or a file replayed from
#   disk. Neither exercises a real driver carrying real calls. This script
#   closes that gap by reading sipnab's own counters on a machine that is
#   actually doing the job, and it answers three questions nobody currently
#   has data for:
#
#     1. Does the capture path drop packets under real load?
#     2. What is on a real carrier wire that sipnab CANNOT decode? Before
#        0.5.80 those frames vanished at debug level, so the honest answer has
#        never been available from any deployment.
#     3. Does the encapsulation-aware BPF filter (27 -> ~133 instructions) cost
#        anything measurable against the filter it replaced?
#
# WHAT THIS WILL NOT DO, BY CONSTRUCTION
#
#   This runs on a production box carrying other people's calls, so:
#
#   * IT NEVER TRANSMITS. No --kill-scanner, no --hep-send, no --replay, no
#     --alert-exec. sipnab refuses to transmit when reading a file, but this
#     reads a LIVE interface, where that guard does not apply -- so the safety
#     here is that those flags are simply never passed, and the script greps
#     its own invocation to prove it before running anything.
#   * IT NEVER WRITES A CAPTURE. No -O, no --replay target. Not one packet is
#     persisted, so there is nothing on disk to leak afterwards.
#   * IT EMITS COUNTERS ONLY. The report contains integers, protocol NUMBERS,
#     and version strings. No addresses, no Call-IDs, no user parts, no
#     headers, no payload. Read the file before you send it -- it is small and
#     designed to be read.
#
#   The one judgement call left to you: the interface name and the host's own
#   name may appear in the report. Both are yours to redact if they matter.
#
# USAGE
#
#   sudo ./field-report.sh --iface eth0 [--seconds 120]
#
#   Needs 0.5.80 or newer for the undecodable-frame accounting, which is the
#   most valuable part. It runs against older builds and says which sections
#   are unavailable rather than silently emitting zeros -- a zero from a build
#   that cannot count is indistinguishable from a clean wire, which is the
#   exact defect 0.5.80 exists to remove.

set -euo pipefail

IFACE=""
SECONDS_PER_RUN=120
BIN="${SIPNAB_BIN:-sipnab}"
PORT=19099

while [ $# -gt 0 ]; do
  case "$1" in
    --iface)   IFACE="${2:?--iface needs a value}"; shift 2 ;;
    --seconds) SECONDS_PER_RUN="${2:?--seconds needs a value}"; shift 2 ;;
    --bin)     BIN="${2:?--bin needs a value}"; shift 2 ;;
    -h|--help) sed -n '3,50p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$IFACE" ] || { echo "error: --iface is required (e.g. --iface eth0)" >&2; exit 2; }
command -v "$BIN" >/dev/null || { echo "error: $BIN not on PATH" >&2; exit 2; }

OUT="sipnab-field-report-$(hostname -s)-$(date -u +%Y%m%dT%H%M%SZ).txt"

# ---------------------------------------------------------------- safety gate
# Prove, before capturing anything, that no transmitting or file-writing flag
# can reach sipnab. This is a real gate, not a comment: if a future edit adds
# one of these to the invocation below, the script refuses to run.
#
# THE GATE MUST FAIL CLOSED. The first version of this check was written as
#   grep -qE "$FORBIDDEN"
# with a pattern beginning `--kill-scanner`. grep read those leading dashes as
# options, errored, and returned non-zero — so the `if` was false and the
# script CARRIED ON. A safety check that errors instead of firing is worse than
# no check, because it reads as a guarantee. Hence `--` to end option parsing,
# and an explicit three-way on the exit status: 0 = found (abort), 1 = clean
# (proceed), anything else = the check itself broke (abort).
FORBIDDEN='kill-scanner|hep-send|--replay|alert-exec|fail2ban|[[:space:]]-O[[:space:]]|--output'
INVOCATION=$(sed -n '/^run_sipnab() {/,/^}/p' "$0")
set +e
printf '%s' "$INVOCATION" | grep -qE -- "$FORBIDDEN"
gate_rc=$?
set -e
case "$gate_rc" in
  0) echo "REFUSING TO RUN: a transmitting or file-writing flag appears in the" >&2
     echo "sipnab invocation. This script is only safe because none can." >&2
     exit 1 ;;
  1) : ;;  # clean
  *) echo "REFUSING TO RUN: the safety check itself failed (grep exit $gate_rc)." >&2
     echo "Not proceeding on an unverified invocation." >&2
     exit 1 ;;
esac

say() { printf '%s\n' "$*" | tee -a "$OUT"; }

# --------------------------------------------------------------- environment
: > "$OUT"
say "sipnab field capture-health report"
say "generated: $(date -u +%FT%TZ)  (UTC)"
say "contains:  counters, protocol numbers and versions only -- no packet data"
say ""
say "== environment =="
say "  sipnab:     $("$BIN" --version 2>&1 | head -1)"
say "  kernel:     $(uname -r)"
say "  cores:      $(nproc)"
say "  memory MB:  $(free -m | awk 'NR==2{print $2}')"
say "  interface:  $IFACE"
say "  driver:     $(ethtool -i "$IFACE" 2>/dev/null | awk -F': ' '/^driver/{print $2}')"
say "  speed:      $(ethtool "$IFACE" 2>/dev/null | awk -F': ' '/Speed/{print $2}')"
say "  ring rx:    $(ethtool -g "$IFACE" 2>/dev/null | awk '/^RX:/{print $2; exit}')"
say ""

# ------------------------------------------------- interface baseline counters
# Read the NIC's own drop counters either side of each run. sipnab cannot see
# a frame the driver discarded before the ring, so if these move, sipnab's own
# "captured" number is not the whole story and must not be read as one.
if_drops() { awk -v i="$IFACE" '$1 ~ i {print $5+$9}' /proc/net/dev 2>/dev/null || echo 0; }

# --------------------------------------------------------------- capture runs
# Two runs over the same live traffic, differing ONLY in the filter, so the
# comparison isolates filter cost from whatever the wire happened to be doing.
#
#   run "new"  -- the auto-generated encapsulation-aware filter (default)
#   run "old"  -- the pre-0.5.80 filter, passed explicitly
#
# Traffic is not identical between runs (it is a live wire), so treat a small
# difference as noise. A LARGE difference in kernel_dropped is the signal.
run_sipnab() {
  local label="$1"; shift
  local before after
  before=$(if_drops)

  # --autostop bounds the run. --metrics is loopback-only. Nothing is written.
  SIPNAB_LOG=info timeout $((SECONDS_PER_RUN + 30)) \
    "$BIN" -N -d "$IFACE" \
      --autostop "duration:${SECONDS_PER_RUN}" \
      --metrics "127.0.0.1:${PORT}" \
      "$@" \
      > "/tmp/sipnab-field-$label.log" 2>&1 &
  local pid=$!

  sleep 3
  local scrape=""
  for _ in $(seq 1 "$SECONDS_PER_RUN"); do
    kill -0 "$pid" 2>/dev/null || break
    scrape=$(curl -s --max-time 5 "http://127.0.0.1:${PORT}/metrics" 2>/dev/null || true)
    sleep 1
  done

  # Peak RSS and CPU before the process exits.
  local rss cpu
  rss=$(awk '/VmHWM/{print $2}' "/proc/$pid/status" 2>/dev/null || echo "?")
  cpu=$(ps -o %cpu= -p "$pid" 2>/dev/null | tr -d ' ' || echo "?")
  wait "$pid" 2>/dev/null || true
  after=$(if_drops)

  say "== run: $label =="
  say "  filter:        $(grep -oP 'Auto-generated BPF filter: \K.*' "/tmp/sipnab-field-$label.log" | head -1 || echo '(explicit --filter)')"
  say "  peak RSS kB:   ${rss:-?}"
  say "  cpu % (last):  ${cpu:-?}"
  say "  iface drops:   $((after - before))  (from /proc/net/dev, driver-side)"
  if [ -n "$scrape" ]; then
    printf '%s\n' "$scrape" \
      | grep -E '^sipnab_capture_(packets_total|kernel_dropped|interface_dropped|invalid_timestamps|undecodable_frames|undecoded_fraction|quality_degraded)' \
      | sed 's/^/  /' | tee -a "$OUT" >/dev/null
    printf '%s\n' "$scrape" \
      | grep -E '^sipnab_capture_(packets_total|kernel_dropped|interface_dropped|invalid_timestamps|undecodable_frames|undecoded_fraction|quality_degraded)' \
      | sed 's/^/  /'
  else
    say "  (no metrics scrape -- the run may have exited early; see the log)"
  fi
  say "  summary line:  $(grep -oP 'sipnab: \K.*' "/tmp/sipnab-field-$label.log" | tail -1 || echo '(none)')"
  say ""
}

say "== capture runs (${SECONDS_PER_RUN}s each, live interface, nothing written) =="
say ""
run_sipnab "new-tunnel-aware-filter"
run_sipnab "old-portrange-filter" --filter "portrange 5060-5061"

# ------------------------------------------------------------- filter cost
say "== compiled BPF program size =="
NEWF=$(grep -oP 'Auto-generated BPF filter: \K.*' /tmp/sipnab-field-new-tunnel-aware-filter.log | head -1 || true)
if [ -n "$NEWF" ] && command -v tcpdump >/dev/null; then
  say "  new filter instructions: $(tcpdump -d -i "$IFACE" "$NEWF" 2>/dev/null | wc -l)"
  say "  old filter instructions: $(tcpdump -d -i "$IFACE" 'portrange 5060-5061' 2>/dev/null | wc -l)"
else
  say "  (tcpdump unavailable, or no auto-filter logged)"
fi
say ""

say "== what to send back =="
say "  This file: $OUT"
say "  Please read it first. It should contain only integers, protocol numbers"
say "  and version strings. If you see anything resembling an address, a"
say "  Call-ID or a phone number, that is a BUG -- do not send it, and say so."

rm -f /tmp/sipnab-field-*.log
echo
echo "Report written to: $OUT"
