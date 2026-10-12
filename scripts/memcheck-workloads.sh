#!/usr/bin/env bash
# Run sipnab under Valgrind memcheck across its offline, archive, HEP, MCP and
# REST paths, writing one log per workload into OUT. scripts/memcheck-verdict.py
# then judges the logs. The weekly job is .github/workflows/memcheck.yml.
#
# The binary MUST be built without mimalloc (RUSTFLAGS="--cfg sipnab_tsan"):
# memcheck sees only the C library's heap, so against the shipped allocator it
# would report nothing about Rust's and prove nothing.
#
# --undef-value-errors=no: on optimized builds memcheck reports reads of
# Option payload bytes that LLVM loads before testing the discriminant, which
# never decide a result. All three such reports of the 2026-10-10 review
# (hep.rs capture_limit_reached, tempfile, schemars) were absent at -O0. Leak
# detection and invalid read/write/free detection stay on.
#
# Usage: memcheck-workloads.sh SIPNAB OUT REPO
set -uo pipefail
if [ $# -ne 3 ]; then
  echo "usage: $0 SIPNAB OUT REPO" >&2
  exit 2
fi
BIN=$1; OUT=$2; REPO=$3
P="$REPO/tests/pcap-samples"
F="$REPO/tests/fixtures"
mkdir -p "$OUT"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
VG=(valgrind --tool=memcheck --leak-check=full --show-leak-kinds=definite,indirect
    --undef-value-errors=no --num-callers=40)

run() {  # run NAME ARGS...
  local name=$1; shift
  timeout 1800 "${VG[@]}" --log-file="$OUT/$name.log" "$BIN" "$@" >/dev/null 2>&1
  echo "$name: exit $?"
}

run offline-report        -N -I "$P/sip-rtp-g711.pcap" --report
run offline-json-dialogs  -N -I "$P/register-invite-reinvite-bye.pcap" --json-dialogs
run offline-json-messages -N -I "$P/sip-proxy.pcap" --json
run offline-analyze       -N -I "$P/sip-problem-call.pcap" --analyze
run offline-lint          -N -I "$P/sip-lint-findings.pcap" --lint
run offline-security      -N -I "$F/sip-scanner-and-register-flood.pcap" --fraud-detect --reg-flood --digest-leak --report
run offline-rtp-quality   -N -I "$P/codec-negotiation.pcap" --report --quality-interval 1
run offline-stun-turn     -N -I "$F/turn_relay.pcap" --stun
run offline-tcp           -N -I "$P/sip-over-tcp.pcap" --report
run offline-dir-recursive -N -I "$P" --recursive --report
run offline-parallel      -N -I "$P/sipp-branch-scenario.pcapng" --cores 4 --report

mkdir -p "$WORK/vcon"
run offline-vcon-export   -N -I "$P/sip-rtp-g711.pcap" --export-vcon-when "state == 'Completed'" --export-vcon-dir "$WORK/vcon"
(cd "$P" && zip -q "$WORK/samples.zip" sip-rtp-g711.pcap sip-proxy.pcap sip-problem-call.pcap)
run offline-zip-archive   -N -I "$WORK/samples.zip" --report
run offline-pcap-write    -N -I "$P/sip-rtp-g711.pcap" -O "$WORK/out.pcapng" --pcapng

# HEP listener under memcheck, fed by the same binary outside it.
timeout 1800 "${VG[@]}" --log-file="$OUT/hep-listener.log" "$BIN" -N -L 127.0.0.1:19960 --duration 90 --report >/dev/null 2>&1 &
vpid=$!
sleep 30
for _ in 1 2 3; do
  "$BIN" -N -I "$P/sip-rtp-g711.pcap" -H 127.0.0.1:19960 >/dev/null 2>&1
  "$BIN" -N -I "$P/register-invite-reinvite-bye.pcap" -H 127.0.0.1:19960 >/dev/null 2>&1
done
wait $vpid; echo "hep-listener: exit $?"

# MCP over stdio: initialize, list, call several tools, then end of input.
{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"memcheck","version":"1"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  for t in list_dialogs find_problems triage rtp_stats runtime_stats get_capture_report; do
    printf '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"%s","arguments":{}}}\n' "$t"
  done
  sleep 30
} > "$WORK/mcp.in"
timeout 1800 "${VG[@]}" --log-file="$OUT/mcp-stdio.log" "$BIN" --mcp -N -I "$P/sip-problem-call.pcap" <"$WORK/mcp.in" >/dev/null 2>&1
echo "mcp-stdio: exit $?"

# REST API over a capture. With -I the API keeps serving after the file is
# read and --duration does not end it, so the run is stopped as an operator
# would stop it: SIGINT.
timeout 1800 "${VG[@]}" --log-file="$OUT/rest-api.log" "$BIN" -N -I "$P/sip-problem-call.pcap" --api 127.0.0.1:19961 >/dev/null 2>&1 &
vpid=$!
sleep 45
for path in /v1/dialogs /v1/stats /v1/streams /v1/runtime /metrics; do
  curl -s -o /dev/null -w "rest-api $path %{http_code}\n" "http://127.0.0.1:19961$path"
done
vgpid=$(pgrep -P "$vpid" -f valgrind || true)
kill -INT "${vgpid:-$vpid}"
wait $vpid; echo "rest-api: exit $?"
