#!/bin/sh
# SIPp UAS: answers INVITEs relayed by opensips-1 and stays up indefinitely.
set -eu
IFACE="${IFACE:-eth0}"
IP="$(ip -4 -o addr show "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -1)"
cd /harness/scenarios
echo "sipp-uas: listening on ${IP}:5060 (media ${IP})"
# -aa auto-answers OPTIONS/INFO/NOTIFY/UPDATE; -nostdin for non-interactive run.
# SCENARIO selects the answering behavior: `uas_media.xml` echoes audio back
# to the caller, `uas.xml` answers signaling only. Echoing is the default
# because a one-way stream cannot show that media reached the far end and
# came back, which is the whole point of anchoring it through rtpengine.
SCENARIO="${UAS_SCENARIO:-uas_media.xml}"
echo "sipp-uas: scenario ${SCENARIO}"
exec sipp -sf "$SCENARIO" -i "$IP" -p 5060 -mi "$IP" -nostdin -aa \
          -trace_err -default_behaviors all
