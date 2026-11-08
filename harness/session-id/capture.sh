#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# capture.sh <opensips-image> <out.pcap>
#
# Records three calls through OpenSIPS topology_hiding("C") whose endpoints
# send an RFC 7989 Session-ID. OpenSIPS gives the callee's leg a new Call-ID
# and passes Session-ID through unchanged, so the two legs share it. The
# OpenSIPS script is harness/th-callid/opensips.cfg.tmpl with the default
# th_callid_passwd, moved to RFC 5737 TEST-NET-3: OpenSIPS at 203.0.113.10,
# the host (SIPp UAC on 5080, UAS on 5070) at 203.0.113.1. Call-IDs are
# N-sid-call@example.com, placed three seconds apart so that no call's start
# falls inside another's two-second timing window. Running it again writes the same messages with
# other timestamps, tags and branches.
# Needs docker, sipp and dumpcap (the user in the wireshark group).
set -euo pipefail
image=$1 out=$2
here=$(cd "$(dirname "$0")" && pwd)
net=sipnabsid0
work=$(mktemp -d)
cleanup() {
  docker rm -f sipnab-sid-opensips >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  [ -n "${cap_pid:-}" ] && kill "$cap_pid" 2>/dev/null || true
  [ -n "${uas_pid:-}" ] && kill "$uas_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

sed -e "s|@SECRET_LINE@||" -e "s|@LOOP@||" -e "s|@XCID@|#|" -e "s|192\.0\.2\.|203.0.113.|g" \
  "$here/../th-callid/opensips.cfg.tmpl" > "$work/opensips.cfg"

docker network create --subnet 203.0.113.0/24 --gateway 203.0.113.1 \
  -o com.docker.network.bridge.name=$net "$net" >/dev/null
docker run -d --name sipnab-sid-opensips --network "$net" --ip 203.0.113.10 \
  -v "$work/opensips.cfg:/etc/opensips/th.cfg:ro" --entrypoint opensips \
  "$image" -F -f /etc/opensips/th.cfg >/dev/null
sleep 2
{ status=$(docker ps --filter name=sipnab-sid-opensips --format '{{.Status}}') && grep -q Up <<<"$status"; } \
  || { docker logs sipnab-sid-opensips; exit 1; }

dumpcap -q -i "$net" -f "udp port 5060 or udp port 5070 or udp port 5080" -P -w "$work/raw.pcap" &
cap_pid=$!
sleep 1
sipp -sf "$here/uas.xml" -i 203.0.113.1 -p 5070 -nostdin -trace_err -error_file "$work/uas.err" >/dev/null 2>&1 &
uas_pid=$!
sleep 1
sipp -sf "$here/uac.xml" -i 203.0.113.1 -p 5080 -nostdin -s service 203.0.113.10:5060 -m 3 -r 1 -rp 3000 -d 500 \
  -cid_str '%u-sid-call@example.com' -timeout 20 -timeout_error \
  -trace_err -error_file "$work/uac.err" >/dev/null
sleep 2
kill "$cap_pid"; wait "$cap_pid" 2>/dev/null || true
cap_pid=
cp "$work/raw.pcap" "$out"
echo "wrote $out"
