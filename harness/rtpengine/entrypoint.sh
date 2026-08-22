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

# Optional: mirror the ng control plane to a Homer collector, which is how
# sipnab names media captured on a relay. OFF unless HOMER is set, so the
# default harness is unchanged.
#
# The destination does NOT have to listen. sipnab reads these datagrams off the
# wire rather than receiving them, because rtpengine takes exactly ONE Homer
# destination -- pointing it at a diagnostic tool would take it away from the
# collector it feeds. Aiming at an address nobody answers is therefore the
# HONEST default here: it reproduces the deployment sipnab is built for.
HOMER_ARGS=""
if [ -n "${HOMER:-}" ]; then
    HOMER_ARGS="--homer=${HOMER} --homer-protocol=udp --homer-id=${HOMER_ID:-2001} --homer-enable-ng"
    echo "rtpengine: mirroring ng control plane to ${HOMER} (capture proto 0x3d)"
fi

echo "rtpengine: interface=${RTPENGINE_IF} ng=127.0.0.1:22222 ports=${RTP_MIN}-${RTP_MAX} (userspace)"

# HOMER_ARGS is deliberately unquoted: it is either empty or several flags, and
# quoting it would pass one empty argument that rtpengine rejects.
# shellcheck disable=SC2086
exec rtpengine \
    --interface="${RTPENGINE_IF}" \
    --listen-ng=127.0.0.1:22222 \
    --port-min="${RTP_MIN}" \
    --port-max="${RTP_MAX}" \
    --table=-1 \
    --foreground \
    --log-stderr \
    --log-level=6 \
    ${HOMER_ARGS}
