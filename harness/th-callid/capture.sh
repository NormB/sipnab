#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# capture.sh <opensips-image> <out.pcap> <mode>
#
# Records calls through OpenSIPS topology_hiding("C") on a private Docker
# network using RFC 5737 TEST-NET-1 only: OpenSIPS at 192.0.2.10, the host
# (SIPp UAC on 5080, UAS on 5070) at 192.0.2.1. Call-IDs and hosts in the
# messages are example.com or TEST-NET addresses. Modes:
#   secret      th_callid_passwd from TH_SECRET (default th-lab-secret-0100)
#   secret-loop the same, with th_callid_loop_protection=1 (OpenSIPS 4.0+)
#   default     OpenSIPS's default th_callid_passwd
#   xcid        default secret, plus append_hf("X-CID: $ci") on the far leg
# Needs docker, sipp and dumpcap (the user in the wireshark group).
set -euo pipefail
image=$1 out=$2 mode=$3
secret=${TH_SECRET:-th-lab-secret-0100}
here=$(cd "$(dirname "$0")" && pwd)
net=sipnabth0
work=$(mktemp -d)
cleanup() {
  docker rm -f sipnab-th-opensips >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  [ -n "${cap_pid:-}" ] && kill "$cap_pid" 2>/dev/null || true
  [ -n "${uas_pid:-}" ] && kill "$uas_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

secret_line="modparam(\"topology_hiding\", \"th_callid_passwd\", \"$secret\")"
loop="" xcid="#"
case $mode in
  secret) ;;
  secret-loop) loop='modparam("topology_hiding", "th_callid_loop_protection", 1)' ;;
  default) secret_line="" ;;
  xcid) secret_line="" ; xcid="" ;;
  *) echo "capture.sh: unknown mode $mode" >&2; exit 2 ;;
esac
sed -e "s|@SECRET_LINE@|$secret_line|" -e "s|@LOOP@|$loop|" -e "s|@XCID@|$xcid|" \
  "$here/opensips.cfg.tmpl" > "$work/opensips.cfg"

docker network create --subnet 192.0.2.0/24 --gateway 192.0.2.1 \
  -o com.docker.network.bridge.name=$net "$net" >/dev/null
docker run -d --name sipnab-th-opensips --network "$net" --ip 192.0.2.10 \
  -v "$work/opensips.cfg:/etc/opensips/th.cfg:ro" --entrypoint opensips \
  "$image" -F -f /etc/opensips/th.cfg >/dev/null
sleep 2
docker ps --filter name=sipnab-th-opensips --format '{{.Status}}' | grep -q Up \
  || { docker logs sipnab-th-opensips; exit 1; }

dumpcap -q -i "$net" -f "udp port 5060 or udp port 5070 or udp port 5080" -P -w "$work/raw.pcap" &
cap_pid=$!
sleep 1
sipp -sf "$here/uas.xml" -i 192.0.2.1 -p 5070 -nostdin -trace_err -error_file "$work/uas.err" >/dev/null 2>&1 &
uas_pid=$!
sleep 1
sipp -sf "$here/uac.xml" -i 192.0.2.1 -p 5080 -nostdin -s service 192.0.2.10:5060 -m 3 -r 1 -d 500 \
  -cid_str '%u-th-call@example.com' -timeout 20 -timeout_error \
  -trace_err -error_file "$work/uac.err" >/dev/null
sleep 2
kill "$cap_pid"; wait "$cap_pid" 2>/dev/null || true
cap_pid=
cp "$work/raw.pcap" "$out"
echo "wrote $out"
