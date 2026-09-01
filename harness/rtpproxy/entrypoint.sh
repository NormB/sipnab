#!/bin/sh
# rtpproxy in its own namespace, anchoring media for opensips-1.
#
# Deliberately shaped like rtpengine/entrypoint.sh beside it: same address
# discovery, same port-range variables, same "own namespace" rationale. The
# two anchors differ in what they can TELL you, not in how they are wired.
#
# What rtpproxy cannot do, stated here rather than discovered later: it has no
# Homer/HEP mirror of its control channel. rtpengine can be told to copy its
# `ng` control plane onto the wire, which is what lets a relay-side sipnab put
# a Call-ID on the media it sees. rtpproxy's control protocol is a terse UDP
# command language with no such mirror, so a sipnab watching this namespace
# sees media it cannot name until it can decode that protocol directly.
#
# That is not a gap in the harness -- it is the state an operator is in today,
# and capturing it is the point.
set -eu

IFACE="${IFACE:-eth0}"
RTP_MIN="${RTP_MIN:-30000}"
RTP_MAX="${RTP_MAX:-30050}"

i=0
while :; do
    DETECTED_IP="$(ip -4 -o addr show "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
    [ -n "$DETECTED_IP" ] && break
    i=$((i + 1)); [ "$i" -gt 30 ] && { echo "FATAL: $IFACE never came up" >&2; exit 1; }
    sleep 1
done
RTPPROXY_IF="${RTPPROXY_IF:-$DETECTED_IP}"

# The control socket must be reachable from opensips-1's namespace, so it
# cannot sit on loopback. This address and the RTPPROXY_SOCK that opensips-1
# is given must agree -- they are two halves of one fact, and a mismatch is
# silent on this side and a 500 on the other.
CTL="${RTPPROXY_CTL_BIND:-${RTPPROXY_IF}:22223}"

echo "rtpproxy: interface=${RTPPROXY_IF} control=udp:${CTL} ports=${RTP_MIN}-${RTP_MAX}"

# -f foreground (logs to stderr), -l the address advertised in rewritten SDP,
# -s the control socket OpenSIPS talks to, -m/-M the media port range.
#
# -u is NOT optional here. rtpproxy refuses to run as root in remote-control
# mode -- it exits with "running this program as superuser in a remote control
# mode is strongly not recommended" -- and under `restart: unless-stopped` that
# becomes a crash loop whose only outward symptom is the SIDECAR failing:
# sipnab-relay-rtpproxy joins this container's network namespace, so a relay
# that never stays up leaves the sidecar reporting
# "failed to open /proc/<pid>/ns/net: No such file or directory", which reads
# as a Docker fault rather than as the relay refusing to start.
#
# The fix is to drop privileges, not to pass -F and stay root. The alpine
# package ships an `rtpproxy` user for exactly this; ports are bound before the
# drop, and the media range is unprivileged anyway.
exec rtpproxy \
    -f \
    -u "${RTPPROXY_USER:-rtpproxy}" \
    -l "${RTPPROXY_IF}" \
    -s "udp:${CTL}" \
    -m "${RTP_MIN}" \
    -M "${RTP_MAX}" \
    -d "${RTPPROXY_LOG_LEVEL:-INFO}"
