#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# capture.sh <opensips-image> <out.pcap>
#
# Records two calls with a blind transfer (REFER, RFC 3515) through an
# OpenSIPS proxy that record-routes, on a private Docker network that uses RFC
# 5737 TEST-NET-2 only: OpenSIPS at 198.51.100.10, the host (SIPp UAC on 5080,
# UAS on 5070) at 198.51.100.1. alice calls bob and asks him to call carol.
#   refer-done-1@example.com     bob reports 100 Trying, then 200 OK with the
#                                subscription terminated; alice hangs up.
#   refer-pending-1@example.com  bob reports 100 Trying only, and the capture
#                                ends with the transfer and the call open.
# Every URI host is example.com or one of those addresses. Running it again
# writes the same messages with other timestamps, tags and branches.
# Needs docker, sipp and dumpcap (the user in the wireshark group).
set -euo pipefail
image=$1 out=$2
here=$(cd "$(dirname "$0")" && pwd)
net=sipnabrefer0
work=$(mktemp -d)
cleanup() {
  docker rm -f sipnab-refer-opensips >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  [ -n "${cap_pid:-}" ] && kill "$cap_pid" 2>/dev/null || true
  [ -n "${uas_pid:-}" ] && kill "$uas_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

docker network create --subnet 198.51.100.0/24 --gateway 198.51.100.1 \
  -o com.docker.network.bridge.name=$net "$net" >/dev/null
docker run -d --name sipnab-refer-opensips --network "$net" --ip 198.51.100.10 \
  -v "$here/opensips.cfg:/etc/opensips/refer.cfg:ro" --entrypoint opensips \
  "$image" -F -f /etc/opensips/refer.cfg >/dev/null
sleep 2
{ status=$(docker ps --filter name=sipnab-refer-opensips --format '{{.Status}}') && grep -q Up <<<"$status"; } \
  || { docker logs sipnab-refer-opensips; exit 1; }

dumpcap -q -i "$net" -f "udp port 5060 or udp port 5070 or udp port 5080" -P -w "$work/raw.pcap" &
cap_pid=$!
sleep 1
for kind in done pending; do
  sipp -sf "$here/uas-$kind.xml" -i 198.51.100.1 -p 5070 -m 1 -nostdin \
    -trace_err -error_file "$work/uas-$kind.err" >/dev/null 2>&1 &
  uas_pid=$!
  sleep 1
  sipp -sf "$here/uac-$kind.xml" -i 198.51.100.1 -p 5080 -nostdin -s bob 198.51.100.10:5060 -m 1 \
    -cid_str "refer-$kind-%u@example.com" -timeout 20 -timeout_error \
    -trace_err -error_file "$work/uac-$kind.err" >/dev/null
  wait "$uas_pid"
  uas_pid=
  sleep 1
done
kill "$cap_pid"; wait "$cap_pid" 2>/dev/null || true
cap_pid=
cp "$work/raw.pcap" "$out"
echo "wrote $out"
