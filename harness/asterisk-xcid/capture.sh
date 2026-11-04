#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# capture.sh <asterisk-image> <out.pcap>
#
# Records three calls through Asterisk (a back-to-back user agent, so each
# call has two Call-IDs) whose dialplan copies the caller's Call-ID into an
# X-CID header on the callee's INVITE. Runs on a private Docker network that
# uses RFC 5737 TEST-NET-3 only: Asterisk at 203.0.113.10, the host (SIPp
# UAC on 5080, UAS on 5070) at 203.0.113.1. The SIPp scenarios are
# harness/th-callid's. Caller Call-IDs are N-xcid-call@example.com; Asterisk
# writes its own for the callee's leg. The calls start three seconds apart, so
# that no call's start falls inside another's two-second timing window. Tested with andrius/asterisk:22
# (Asterisk 22.11.0). Running it again writes the same messages with other
# timestamps, tags, branches and Asterisk Call-IDs.
# Needs docker, sipp and dumpcap (the user in the wireshark group).
set -euo pipefail
image=$1 out=$2
here=$(cd "$(dirname "$0")" && pwd)
net=sipnabxcid0
work=$(mktemp -d)
cleanup() {
  docker rm -f sipnab-xcid-asterisk >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  [ -n "${cap_pid:-}" ] && kill "$cap_pid" 2>/dev/null || true
  [ -n "${uas_pid:-}" ] && kill "$uas_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

docker network create --subnet 203.0.113.0/24 --gateway 203.0.113.1 \
  -o com.docker.network.bridge.name=$net "$net" >/dev/null
docker run -d --name sipnab-xcid-asterisk --network "$net" --ip 203.0.113.10 \
  -v "$here/pjsip.conf:/etc/asterisk/pjsip.conf:ro" \
  -v "$here/extensions.conf:/etc/asterisk/extensions.conf:ro" \
  -v "$here/modules.conf:/etc/asterisk/modules.conf:ro" \
  --entrypoint asterisk "$image" -f >/dev/null
for _ in $(seq 1 30); do
  docker exec sipnab-xcid-asterisk asterisk -rx 'core waitfullybooted' >/dev/null 2>&1 && break
  sleep 1
done
docker exec sipnab-xcid-asterisk asterisk -rx 'core waitfullybooted' >/dev/null \
  || { docker logs sipnab-xcid-asterisk | tail -20; exit 1; }

dumpcap -q -i "$net" -f "udp port 5060 or udp port 5070 or udp port 5080" -P -w "$work/raw.pcap" &
cap_pid=$!
sleep 1
sipp -sf "$here/../th-callid/uas.xml" -i 203.0.113.1 -p 5070 -nostdin \
  -trace_err -error_file "$work/uas.err" >/dev/null 2>&1 &
uas_pid=$!
sleep 1
sipp -sf "$here/../th-callid/uac.xml" -i 203.0.113.1 -p 5080 -nostdin -s 100 203.0.113.10:5060 \
  -m 3 -r 1 -rp 3000 -d 500 -cid_str '%u-xcid-call@example.com' -timeout 30 -timeout_error \
  -trace_err -error_file "$work/uac.err" >/dev/null
sleep 2
kill "$cap_pid"; wait "$cap_pid" 2>/dev/null || true
cap_pid=
cp "$work/raw.pcap" "$out"
echo "wrote $out"
