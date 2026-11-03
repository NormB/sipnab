#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# e2e.sh <opensips-image> <sipnab-binary>
#
# The deployment docs/opensips-sipnab.md describes, run for real: OpenSIPS
# with topology_hiding("C") and the E_SIPNAB_TH_MAP event lines, and a live
# sipnab that captures the SIP off the network AND receives the events on
# --hep-listen. Three calls are placed with SIPp; then sipnab's REST API is
# asked how each callee leg was joined, and the script fails unless every
# one was joined to its own caller leg by the mapping.
#
# Private Docker network, RFC 5737 TEST-NET-1 only: OpenSIPS at 192.0.2.10,
# the host (SIPp, and sipnab's listener, on port 9617) at 192.0.2.1. Needs docker, sipp,
# curl, jq, and sudo for the capture.
set -euo pipefail
image=$1 sipnab=$(realpath "$2")
here=$(cd "$(dirname "$0")" && pwd)
net=sipnabth2
api=127.0.0.1:18617
# Not 9060: a collector on the host may already hold it.
port=9617
work=$(mktemp -d)
cleanup() {
  docker rm -f sipnab-th-e2e-opensips >/dev/null 2>&1 || true
  [ -n "${sipnab_pid:-}" ] && sudo kill "$sipnab_pid" 2>/dev/null || true
  [ -n "${uas_pid:-}" ] && kill "$uas_pid" 2>/dev/null || true
  docker network rm "$net" >/dev/null 2>&1 || true
  sudo rm -rf "$work"
}
trap cleanup EXIT

sed -e "s|@SIPNAB@|192.0.2.1:$port|" "$here/opensips.cfg.tmpl" > "$work/opensips.cfg"
docker network create --subnet 192.0.2.0/24 --gateway 192.0.2.1 \
  -o com.docker.network.bridge.name=$net "$net" >/dev/null

# sipnab first, so it hears the first INVITE: the SIP off the bridge, and the
# events on the listener, from OpenSIPS's address only. The capture filter is
# the one docs/opensips-sipnab.md gives: with --hep-listen as well as a
# device, sipnab's default filter keeps media only, expecting the signaling
# over HEP, and here the signaling is on the wire.
sudo "$sipnab" -N -d "$net" --hep-listen "192.0.2.1:$port" --hep-allow 192.0.2.10/32 \
  --api "$api" --config /dev/null 'udp port 5060 or udp[8] & 0xc0 = 0x80' \
  > "$work/sipnab.out" 2> "$work/sipnab.err" &
sipnab_pid=$!
for _ in $(seq 50); do
  curl -sf "http://$api/v1/stats" >/dev/null 2>&1 && break
  sleep 0.2
done

docker run -d --name sipnab-th-e2e-opensips --network "$net" --ip 192.0.2.10 \
  -v "$work/opensips.cfg:/etc/opensips/th.cfg:ro" --entrypoint opensips \
  "$image" -F -f /etc/opensips/th.cfg >/dev/null
sleep 2
sipp -sf "$here/uas.xml" -i 192.0.2.1 -p 5070 -nostdin -trace_err -error_file "$work/uas.err" >/dev/null 2>&1 &
uas_pid=$!
sleep 1
sipp -sf "$here/uac.xml" -i 192.0.2.1 -p 5080 -nostdin -s service 192.0.2.10:5060 -m 3 -r 1 -d 500 \
  -cid_str '%u-th-e2e@example.com' -timeout 20 -timeout_error \
  -trace_err -error_file "$work/uac.err" >/dev/null
sleep 2

stats=$(curl -sf "http://$api/v1/stats")
echo "dialogs: $(jq -c .dialogs <<<"$stats")"
echo "th_mappings: $(jq -c .th_mappings <<<"$stats")"
fail=0
for n in 1 2 3; do
  caller="$n-th-e2e@example.com"
  answer=$(curl -s "http://$api/v1/dialogs/$caller/correlated")
  callee=$(jq -r '[(.legs // [])[] | select(.method == "mapping")][0].call_id // empty' <<<"$answer" 2>/dev/null || true)
  if [ -z "$callee" ]; then
    echo "call $n: NOT joined by a mapping: $answer"
    fail=1
    continue
  fi
  back=$(curl -sf "http://$api/v1/dialogs/$callee/correlated")
  status=$(jq -r .th_callid <<<"$back")
  to=$(jq -r '[.legs[] | select(.method == "mapping")][0].call_id // empty' <<<"$back")
  echo "call $n: $caller <-> $callee (method mapping, th_callid $status)"
  [ "$to" = "$caller" ] && [ "$status" = mapped ] || fail=1
done
[ "$(jq .th_mappings.accepted <<<"$stats")" = 3 ] || fail=1
if [ "$fail" = 0 ]; then echo "e2e: PASS"; else echo "e2e: FAIL"; tail -20 "$work/sipnab.err"; exit 1; fi
