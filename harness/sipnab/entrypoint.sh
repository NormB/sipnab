#!/bin/sh
# Start sipnab as a live-capture MCP HTTP server.
#
# Shares opensips-1's network namespace, so eth0 here is the single point
# through which all SIP signaling and (rtpengine-anchored) RTP media flow.
set -eu

IFACE="${CAPTURE_IFACE:-eth0}"
BIND="${MCP_BIND:-0.0.0.0:8731}"
ALLOWED_HOST="${MCP_ALLOWED_HOST:-*}"
PORTRANGE="${SIP_PORTRANGE:-5060-5061}"
RTP_PORTRANGE="${RTP_PORTRANGE:-30000-30050}"   # rtpengine media range to capture for RTP analysis
TOKEN_FILE="${MCP_TOKEN_FILE:-/run/secrets/mcp.token}"
PCAP_OUT="${CAPTURE_PCAP:-}"        # set to a path under /captures to persist a pcap

# Capture both SIP and the rtpengine media range. --portrange still identifies
# which ports are SIP; this BPF widens the kernel capture so RTP packets (on the
# media range) reach sipnab's RTP engine instead of being filtered out.
BPF="udp and (portrange ${PORTRANGE} or portrange ${RTP_PORTRANGE})"

if [ ! -s "$TOKEN_FILE" ]; then
    echo "FATAL: MCP token file $TOKEN_FILE is empty/missing; run 'make token'." >&2
    exit 1
fi

# Wait for the shared interface to carry an address (opensips-1 owns the netns).
i=0
while ! ip -4 addr show "$IFACE" 2>/dev/null | grep -q 'inet '; do
    i=$((i + 1))
    [ "$i" -gt 30 ] && { echo "FATAL: $IFACE never came up" >&2; exit 1; }
    sleep 1
done
echo "sipnab: capturing on $IFACE, MCP HTTP on $BIND (allowed-host=$ALLOWED_HOST)"

# Optional second capture method: persist a rotating pcap alongside live MCP
# analysis. tcpdump runs in the same netns; sipnab reads its own live capture.
if [ -n "$PCAP_OUT" ]; then
    echo "sipnab: also writing pcap -> $PCAP_OUT (via tcpdump)"
    tcpdump -i "$IFACE" -n -s 0 -U -w "$PCAP_OUT" \
        "$BPF" >/captures/tcpdump.log 2>&1 &
fi

exec sipnab \
    -N \
    --mcp --mcp-transport http \
    --mcp-bind "$BIND" \
    --mcp-token-file "$TOKEN_FILE" \
    --mcp-allowed-host "$ALLOWED_HOST" \
    --portrange "$PORTRANGE" \
    -d "$IFACE" \
    "$BPF"
