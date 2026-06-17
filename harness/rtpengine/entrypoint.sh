#!/bin/sh
# rtpengine in userspace mode, bound to the shared (opensips-1) namespace IP.
set -eu

IFACE="${IFACE:-eth0}"
RTP_MIN="${RTP_MIN:-30000}"
RTP_MAX="${RTP_MAX:-30050}"

# We share opensips-1's netns; wait for its address, then anchor media on it.
i=0
while :; do
    DETECTED_IP="$(ip -4 -o addr show "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
    [ -n "$DETECTED_IP" ] && break
    i=$((i + 1)); [ "$i" -gt 30 ] && { echo "FATAL: $IFACE never came up" >&2; exit 1; }
    sleep 1
done
RTPENGINE_IF="${RTPENGINE_IF:-$DETECTED_IP}"

echo "rtpengine: interface=${RTPENGINE_IF} ng=127.0.0.1:22222 ports=${RTP_MIN}-${RTP_MAX} (userspace)"

exec rtpengine \
    --interface="${RTPENGINE_IF}" \
    --listen-ng=127.0.0.1:22222 \
    --port-min="${RTP_MIN}" \
    --port-max="${RTP_MAX}" \
    --table=-1 \
    --foreground \
    --log-stderr \
    --log-level=6
