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
#     3. Does the encapsulation-aware BPF filter cost anything measurable
#        against the narrow portrange filter it replaced?
#
# WHERE THE COUNTERS COME FROM, AND WHY NOT --metrics
#
#   Counters are read over MCP, via the `capture_health` tool, which returns
#   integers only and is the surface built for exactly this job.
#
#   NOT from `--metrics`. That flag parses, validates and REFUSES A BAD BIND,
#   so it looks wired -- but `start_metrics_server` has one call site, in
#   src/app/tui_mode.rs, and this script runs `-N`. Headless, `--metrics` binds
#   nothing and scrapes return nothing. An earlier version of this script
#   depended on it and reported "(no metrics scrape -- the run may have exited
#   early)" for every run, blaming sipnab for a flag that was never called.
#   Tracked separately; do not "fix" this by adding --metrics back.
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
#   * IT NEVER WIDENS THE MCP SURFACE. --mcp-file-root, --mcp-allow-shutdown
#     and --mcp-allow-open-capture stay off, and the same gate proves it. The
#     MCP server binds LOOPBACK ONLY and is killed when the run ends.
#   * IT EMITS COUNTERS ONLY. capture_health returns integers, protocol
#     NUMBERS and version strings -- no addresses, no Call-IDs, no user parts,
#     no headers, no payload. Read the file before you send it.
#
#   The one judgement call left to you: the interface name and the host's own
#   name may appear in the report. Both are yours to redact if they matter.
#
# USAGE
#
#   ./field-report.sh --iface eth0 [--seconds 30]
#
#   Needs 0.5.80 or newer (undecodable-frame accounting, and capture_health)
#   built with the mcp-http feature. Both are checked before anything runs,
#   because a zero from a build that cannot count is indistinguishable from a
#   clean wire -- the exact defect 0.5.80 exists to remove.
#
#   Root is not required for capture if the binary carries capabilities:
#     sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v sipnab)"
#   Root IS required for the BPF-instruction-count section; without it that
#   section says so rather than printing a zero it did not measure.

set -euo pipefail

IFACE=""
SECONDS_PER_RUN=30
BIN="${SIPNAB_BIN:-sipnab}"
PORT=18731

while [ $# -gt 0 ]; do
  case "$1" in
    --iface)   IFACE="${2:?--iface needs a value}"; shift 2 ;;
    --seconds) SECONDS_PER_RUN="${2:?--seconds needs a value}"; shift 2 ;;
    --bin)     BIN="${2:?--bin needs a value}"; shift 2 ;;
    -h|--help) sed -n '3,72p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$IFACE" ] || { echo "error: --iface is required (e.g. --iface eth0)" >&2; exit 2; }
command -v "$BIN" >/dev/null || { echo "error: $BIN not on PATH" >&2; exit 2; }
command -v curl >/dev/null || { echo "error: curl is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "error: python3 is required" >&2; exit 2; }

# `command -v` resolves the FIRST match on PATH, which is not necessarily the
# one a package manager installed. On the first box this ran against, a stale
# 0.5.78 in /usr/local/bin shadowed the 0.5.80 in /usr/bin, and the report
# would have carried 0.5.78's numbers under 0.5.80's name.
RESOLVED=$(command -v "$BIN")
VERSION_LINE=$("$RESOLVED" --version 2>&1 | head -1)

OUT="sipnab-field-report-$(hostname -s)-$(date -u +%Y%m%dT%H%M%SZ).txt"
LOGDIR=$(mktemp -d "${TMPDIR:-/tmp}/sipnab-field-XXXXXX")

# ---------------------------------------------------------------- safety gate
# Prove, before capturing anything, that no transmitting, file-writing or
# surface-widening flag can reach sipnab. This is a real gate, not a comment:
# if a future edit adds one of these to the invocation below, the script
# refuses to run.
#
# THE GATE MUST FAIL CLOSED. The first version of this check was written as
#   grep -qE "$FORBIDDEN"
# with a pattern beginning `--kill-scanner`. grep read those leading dashes as
# options, errored, and returned non-zero -- so the `if` was false and the
# script CARRIED ON. A safety check that errors instead of firing is worse than
# no check, because it reads as a guarantee. Hence `--` to end option parsing,
# and an explicit three-way on the exit status: 0 = found (abort), 1 = clean
# (proceed), anything else = the check itself broke (abort).
FORBIDDEN='kill-scanner|hep-send|--replay|alert-exec|fail2ban|[[:space:]]-O[[:space:]]|--output|mcp-file-root|mcp-allow-shutdown|mcp-allow-open-capture'
INVOCATION=$(sed -n '/^run_sipnab() {/,/^}/p' "$0")
[ -n "$INVOCATION" ] || {
  echo "REFUSING TO RUN: could not extract the sipnab invocation to check it." >&2
  exit 1; }
set +e
printf '%s' "$INVOCATION" | grep -qE -- "$FORBIDDEN"
gate_rc=$?
set -e
case "$gate_rc" in
  0) echo "REFUSING TO RUN: a transmitting, file-writing or surface-widening" >&2
     echo "flag appears in the sipnab invocation. This script is only safe" >&2
     echo "because none can." >&2
     exit 1 ;;
  1) : ;;  # clean
  *) echo "REFUSING TO RUN: the safety check itself failed (grep exit $gate_rc)." >&2
     echo "Not proceeding on an unverified invocation." >&2
     exit 1 ;;
esac

# Version and feature checks come AFTER the safety gate, deliberately.
#
# The gate is the check that must never be reachable-only-through another
# check. Refusing a transmitting flag matters whatever binary is installed; an
# old binary is a second reason to stop, not a turnstile in front of the first.
#
# Ordered the other way round -- as this script was first written -- a
# mutation test of the gate run on a box carrying an older sipnab exits at the
# version check and reports "refused" for the wrong reason, which reads exactly
# like the gate working. That is how the first mutation run of this gate
# proved nothing: three injected forbidden flags, three refusals, none of them
# from the gate.
case "$VERSION_LINE" in
  *" 0.5.8"*|*" 0.5.9"*|*" 0.6."*|*" 0.7."*|*" 1."*) : ;;
  *) echo "error: need sipnab 0.5.80 or newer for undecodable accounting and" >&2
     echo "       capture_health. Found: $VERSION_LINE" >&2
     echo "       (resolved to $RESOLVED)" >&2
     exit 2 ;;
esac
case "$VERSION_LINE" in
  *mcp-http*) : ;;
  *) echo "error: this build lacks the mcp-http feature, so counters cannot be" >&2
     echo "       read. Found: $VERSION_LINE" >&2
     exit 2 ;;
esac

say() { printf '%s\n' "$*" | tee -a "$OUT"; }

cleanup() { pkill -f "mcp-bind 127.0.0.1:${PORT}" 2>/dev/null || true; }
trap cleanup EXIT

# --------------------------------------------------------------- environment
: > "$OUT"
say "sipnab field capture-health report"
say "generated: $(date -u +%FT%TZ)  (UTC)"
say "contains:  counters, protocol numbers and versions only -- no packet data"
say ""
say "== environment =="
say "  sipnab:     $VERSION_LINE"
say "  binary:     $RESOLVED"
say "  kernel:     $(uname -r)"
say "  cores:      $(nproc)"
say "  memory MB:  $(free -m | awk 'NR==2{print $2}')"
say "  interface:  $IFACE"
say "  driver:     $(ethtool -i "$IFACE" 2>/dev/null | awk -F': ' '/^driver/{print $2}' || true)"
say "  speed:      $(ethtool "$IFACE" 2>/dev/null | awk -F': ' '/Speed/{print $2}' || true)"
say "  ring rx:    $(ethtool -g "$IFACE" 2>/dev/null | awk '/^RX:/{print $2; exit}' || true)"
say ""

# ------------------------------------------------- interface baseline counters
# Read the NIC's own drop counters either side of each run. sipnab cannot see
# a frame the driver discarded before the ring, so if these move, sipnab's own
# "captured" number is not the whole story and must not be read as one.
if_drops() { awk -v i="$IFACE" '$1 ~ i {print $5+$9}' /proc/net/dev 2>/dev/null || echo 0; }

# --------------------------------------------------------------- MCP plumbing
EP="http://127.0.0.1:${PORT}/mcp"
H_CT="Content-Type: application/json"
H_AC="Accept: application/json, text/event-stream"

# The transport is Streamable HTTP: responses arrive as SSE frames, so the
# JSON is on the LAST `data:` line rather than being the whole body.
mcp_last_data() { grep '^data: ' | tail -1 | cut -c7-; }

capture_health_json() {
  local secs="$1" sid
  sid=$(curl -s -D - -o /dev/null -X POST "$EP" -H "$H_CT" -H "$H_AC" \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"field-report","version":"1"}}}' \
        2>/dev/null | grep -i '^mcp-session-id:' | tr -d '\r' | cut -d' ' -f2)
  [ -n "$sid" ] || return 1
  curl -s -X POST "$EP" -H "$H_CT" -H "$H_AC" -H "Mcp-Session-Id: $sid" \
    -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null 2>&1
  curl -s --max-time $((secs + 30)) -X POST "$EP" -H "$H_CT" -H "$H_AC" \
    -H "Mcp-Session-Id: $sid" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"capture_health\",\"arguments\":{\"sample_seconds\":${secs}}}}" \
    2>/dev/null | mcp_last_data
}

# --------------------------------------------------------------- capture runs
# Two runs over the same live traffic, differing ONLY in the BPF filter, so the
# comparison isolates filter cost from whatever the wire happened to be doing.
#
#   run "new"  -- the auto-generated encapsulation-aware filter (default)
#   run "old"  -- the pre-0.5.80 narrow filter, passed explicitly
#
# The old filter is a TRAILING POSITIONAL, which is what sipnab parses as BPF
# (`Usage: sipnab [OPTIONS] [BPF_FILTER]...`). An earlier version passed it as
# `--filter`, which is the display-filter DSL: "portrange 5060-5061" is not a
# valid DSL expression, so that run died on startup while the report presented
# it as a completed comparison -- and because no explicit BPF was ever set,
# both runs actually used the SAME auto-generated filter. The A/B compared the
# filter against itself and reported the result as a measurement.
#
# Traffic is not identical between runs (it is a live wire), so treat a small
# difference as noise. A LARGE difference in kernel_dropped is the signal.
run_sipnab() {
  local label="$1"; shift
  local log="$LOGDIR/$label.log"
  local before after pid rss=0 cur health

  before=$(if_drops)

  # --autostop is a backstop only: if this harness dies, sipnab still stops.
  # The run is ended deliberately below. --mcp-bind is loopback, and no
  # allow-* opt-in is passed, so the surface is read-only counters.
  SIPNAB_LOG=info "$RESOLVED" -N -d "$IFACE" \
      --autostop "duration:$((SECONDS_PER_RUN + 120))" \
      --mcp --mcp-transport http --mcp-bind "127.0.0.1:${PORT}" \
      "$@" \
      > "$log" 2>&1 &
  pid=$!

  # Wait for the port to ANSWER, not merely to exist, and not a bare sleep.
  # A listening socket is not a working MCP server; the probe below is the
  # first thing that proves one.
  local ready=""
  for _ in $(seq 1 40); do
    kill -0 "$pid" 2>/dev/null || break
    if curl -s --max-time 2 -o /dev/null -X POST "$EP" -H "$H_CT" -H "$H_AC" \
         -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}' \
         2>/dev/null; then ready=yes; break; fi
    sleep 0.5
  done

  say "== run: $label =="
  if [ -z "$ready" ]; then
    say "  RUN FAILED: the MCP endpoint never answered. No counters were read."
    say "  This is NOT a clean wire and must not be read as one."
    say "  log kept at: $log"
    say "  first error line: $(grep -iE 'error|panic|refus|denied' "$log" | head -1 || echo '(none found)')"
    say ""
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 0
  fi

  # Peak RSS while the sample window runs. Sampled DURING, not after: the old
  # version read /proc/<pid>/status once the loop had already exited, by which
  # point the process was usually gone and the figure was either "?" or a
  # teardown artifact.
  ( while kill -0 "$pid" 2>/dev/null; do
      cur=$(awk '/VmHWM/{print $2}' "/proc/$pid/status" 2>/dev/null || true)
      [ -n "$cur" ] && [ "$cur" -gt "$rss" ] 2>/dev/null && rss=$cur
      printf '%s' "$rss" > "$LOGDIR/$label.rss"
      sleep 1
    done ) &
  local rsspid=$!

  health=$(capture_health_json "$SECONDS_PER_RUN" || true)

  kill "$rsspid" 2>/dev/null || true
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  after=$(if_drops)

  local bpf_desc="(auto-generated encapsulation-aware filter)"
  [ $# -gt 0 ] && bpf_desc="$*"
  local autogen
  autogen=$(grep -oP 'Auto-generated BPF filter: \K.*' "$log" | head -1 || true)

  say "  bpf requested: $bpf_desc"
  if [ -n "$autogen" ]; then
    say "  bpf effective: ${#autogen} chars, starts: $(printf '%.90s' "$autogen")..."
  else
    say "  bpf effective: $bpf_desc  (no auto-filter logged, as expected)"
  fi
  say "  peak RSS kB:   $(cat "$LOGDIR/$label.rss" 2>/dev/null || echo '?')"
  say "  iface drops:   $((after - before))  (from /proc/net/dev, driver-side)"

  if [ -z "$health" ]; then
    say "  COUNTERS UNAVAILABLE: capture_health returned nothing."
    say "  Treat this run as no data, not as zero. log kept at: $log"
  else
    printf '%s' "$health" > "$LOGDIR/$label.health.json"
    # Quoted heredoc, so the shell expands nothing and this Python can use
    # whichever quotes it needs. The previous version was a single-quoted
    # `python3 -c` string, which forced backslash-escaped quotes inside
    # f-strings. That is a SyntaxError, and one that fires only at the moment
    # a run actually produces counters -- so it survived every dry run.
    python3 - "$LOGDIR/$label.health.json" <<'PY' | tee -a "$OUT"
import json, sys

try:
    outer = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"  COUNTERS UNPARSEABLE: {e}")
    sys.exit(0)
res = outer.get("result", {})
if outer.get("error") or res.get("isError"):
    print(f"  capture_health returned an error: {json.dumps(outer)[:200]}")
    sys.exit(0)
try:
    h = json.loads(res["content"][0]["text"])
except Exception as e:
    print(f"  COUNTERS UNPARSEABLE: {e}")
    sys.exit(0)

w, t, iw = h.get("window", {}), h.get("totals", {}), h.get("in_window", {})
req, app = w.get("requested_seconds"), w.get("applied_seconds")
obs = w.get("observed_ms", 0) / 1000.0
clamp = "   (CLAMPED to the tool maximum)" if req != app else ""
print(f"  window:        requested {req}s, applied {app}s, observed {obs:.3f}s{clamp}")

pkts, total = iw.get("packets", 0), t.get("packets", 0)
rate = f"{pkts / obs:,.0f}" if obs > 0 else "?"
print(f"  packets/sec:   {rate}   ({pkts:,} in window; {total:,} total)")
for k in ("kernel_dropped", "interface_dropped", "invalid_timestamps",
          "undecodable_frames"):
    print(f"  {k + ':':<21}{iw.get(k, 0):,} in window / {t.get(k, 0):,} total")
print(f"  undecoded frac: {h.get('undecoded_fraction_in_window', 0.0)} in window"
      f" / {h.get('undecoded_fraction', 0.0)} total")

reasons = h.get("undecodable_by_reason") or []
if reasons:
    print("  undecodable by reason (the number no deployment has had before):")
    for r in reasons:
        print(f"    {r}")
else:
    print("  undecodable by reason: none recorded -- every frame decoded")
if h.get("undecodable_reasons_dropped"):
    print(f"  NOTE: {h['undecodable_reasons_dropped']} reason slot(s) overflowed")

print(f"  dialogs tracked: {h.get('dialogs_tracked', 0):,}"
      f"   streams tracked: {h.get('streams_tracked', 0):,}")

# Both notes exist to stop a zero being read as a finding, in either
# direction: a zero that is correct, and a zero that means nothing ran.
if pkts and not h.get("streams_tracked"):
    print("  NOTE: SIP present but zero RTP streams. With the default filter")
    print("        this is EXPECTED -- the auto BPF matches signaling only, so")
    print("        media never leaves the kernel. Not a defect unless you")
    print("        passed a BPF that should have matched media.")
if pkts == 0:
    print("  NOTE: zero packets in the window. The endpoint answered and the")
    print("        window elapsed, so this is a MEASURED zero (a quiet wire),")
    print("        not a failed measurement.")
PY
  fi
  say ""
}

say "== capture runs (${SECONDS_PER_RUN}s sample each, live interface, nothing written) =="
say ""
run_sipnab "new-tunnel-aware-filter"
run_sipnab "old-portrange-filter" "portrange 5060-5061"

# ------------------------------------------------------------- filter cost
# tcpdump -d must OPEN THE INTERFACE to learn its link type, so without root
# it fails and `wc -l` reports 0. The old version printed that 0 as
# "new filter instructions: 0" -- a measurement that never happened, formatted
# exactly like one that did, in the script written to expose silent zeros.
say "== compiled BPF program size =="
NEWF=$(grep -ohP 'Auto-generated BPF filter: \K.*' "$LOGDIR"/*.log 2>/dev/null | head -1 || true)
bpf_len() {
  local n
  n=$(tcpdump -d -i "$IFACE" "$1" 2>/dev/null | wc -l)
  [ "$n" -gt 0 ] && printf '%s' "$n" || printf 'UNAVAILABLE'
}
if ! command -v tcpdump >/dev/null; then
  say "  NOT MEASURED: tcpdump is not installed."
elif [ "$(id -u)" -ne 0 ]; then
  say "  NOT MEASURED: tcpdump -d must open $IFACE to learn its link type, which"
  say "  needs root. Re-run this section with sudo. (A 0 here would be the"
  say "  absence of a measurement, not a small program.)"
elif [ -z "$NEWF" ]; then
  say "  NOT MEASURED: no auto-generated filter was logged, so there is nothing"
  say "  to compile. Check the run sections above -- they probably failed."
else
  say "  new filter instructions: $(bpf_len "$NEWF")"
  say "  old filter instructions: $(bpf_len 'portrange 5060-5061')"
fi
say ""

say "== what to send back =="
say "  This file: $OUT"
say "  Please read it first. It should contain only integers, protocol numbers"
say "  and version strings. If you see anything resembling an address, a"
say "  Call-ID or a phone number, that is a BUG -- do not send it, and say so."

# Logs are kept when a run failed, because the failure text is the only thing
# that says why. On a clean run they hold nothing the report does not.
if grep -q 'RUN FAILED\|COUNTERS UNAVAILABLE\|UNPARSEABLE' "$OUT"; then
  echo
  echo "At least one run did not produce counters. Logs kept in: $LOGDIR"
else
  rm -rf "$LOGDIR"
fi

echo
echo "Report written to: $OUT"
