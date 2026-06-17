#!/bin/sh
# SIPp UAS: answers INVITEs relayed by opensips-1 and stays up indefinitely.
set -eu
IFACE="${IFACE:-eth0}"
IP="$(ip -4 -o addr show "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -1)"
cd /harness/scenarios
echo "sipp-uas: listening on ${IP}:5060 (media ${IP})"
# -aa auto-answers OPTIONS/INFO/NOTIFY/UPDATE; -nostdin for non-interactive run.
exec sipp -sf uas.xml -i "$IP" -p 5060 -mi "$IP" -nostdin -aa \
          -trace_err -default_behaviors all
