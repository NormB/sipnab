#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# capture.sh <opensips-image> <out.pcap>
#
# Records three calls through OpenSIPS topology_hiding("C") together with the
# E_SIPNAB_TH_MAP event OpenSIPS sends for each, on a private Docker network
# using RFC 5737 TEST-NET-1 only: OpenSIPS at 192.0.2.10, the host (SIPp UAC
# on 5080, UAS on 5070, and the event subscriber 192.0.2.1:9060) at
# 192.0.2.1. Nothing listens on 9060 here: the capture holds the datagrams
# OpenSIPS sent, which tests/th_mapping_test.rs replays into sipnab's HEP
# listener. Call-IDs are N-th-map@example.com.
# Needs docker, sipp and dumpcap (the user in the wireshark group).
set -euo pipefail
image=$1 out=$2
here=$(cd "$(dirname "$0")" && pwd)
net=sipnabth1
work=$(mktemp -d)
cleanup() {
  docker rm -f sipnab-th-map-opensips >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  [ -n "${cap_pid:-}" ] && kill "$cap_pid" 2>/dev/null || true
  [ -n "${uas_pid:-}" ] && kill "$uas_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

sed -e "s|@SIPNAB@|192.0.2.1:9060|" "$here/opensips.cfg.tmpl" > "$work/opensips.cfg"

docker network create --subnet 192.0.2.0/24 --gateway 192.0.2.1 \
  -o com.docker.network.bridge.name=$net "$net" >/dev/null
docker run -d --name sipnab-th-map-opensips --network "$net" --ip 192.0.2.10 \
  -v "$work/opensips.cfg:/etc/opensips/th.cfg:ro" --entrypoint opensips \
  "$image" -F -f /etc/opensips/th.cfg >/dev/null
sleep 2
docker ps --filter name=sipnab-th-map-opensips --format '{{.Status}}' | grep -q Up \
  || { docker logs sipnab-th-map-opensips; exit 1; }

dumpcap -q -i "$net" -f "udp port 5060 or udp port 5070 or udp port 5080 or udp port 9060" \
  -P -w "$work/raw.pcap" &
cap_pid=$!
sleep 1
sipp -sf "$here/uas.xml" -i 192.0.2.1 -p 5070 -nostdin -trace_err -error_file "$work/uas.err" >/dev/null 2>&1 &
uas_pid=$!
sleep 1
sipp -sf "$here/uac.xml" -i 192.0.2.1 -p 5080 -nostdin -s service 192.0.2.10:5060 -m 3 -r 1 -d 500 \
  -cid_str '%u-th-map@example.com' -timeout 20 -timeout_error \
  -trace_err -error_file "$work/uac.err" >/dev/null
sleep 2
kill "$cap_pid"; wait "$cap_pid" 2>/dev/null || true
cap_pid=
docker logs sipnab-th-map-opensips 2>&1 | grep -iE 'error|E_SIPNAB' || true
cp "$work/raw.pcap" "$out"
echo "wrote $out"
