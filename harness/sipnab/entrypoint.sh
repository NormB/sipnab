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
SIGNING_KEY_FILE="${MCP_SIGNING_KEY_FILE:-/run/secrets/mcp.signing-key}"
TOKEN_FILE="${MCP_TOKEN_FILE:-/run/secrets/mcp.token}"
TOKEN_TTL="${MCP_TOKEN_TTL:-600}"               # minted-token lifetime (seconds)
ROTATE_INTERVAL="${MCP_ROTATE_INTERVAL:-300}"   # re-mint cadence; keep <= TTL/2 for overlap
ROTATE="${MCP_ROTATE_SCRIPT:-/usr/local/bin/rotate-token.sh}"
PCAP_OUT="${CAPTURE_PCAP:-}"        # set to a path under /captures to persist a pcap
API_BIND="${API_BIND:-}"            # set to expose the REST API alongside MCP
NODE_NAME="${NODE_NAME:-}"          # which capture point this is, for the logs

# Capture both SIP and the rtpengine media range. --portrange still identifies
# which ports are SIP; this BPF widens the kernel capture so RTP packets (on the
# media range) reach sipnab's RTP engine instead of being filtered out.
# CONTROL_PORTS widens the filter to the rtpengine ng control plane and the
# HEP mirror of it. On a relay this is not optional: signaling never transits
# rtpengine, so the ONLY thing that can tell the relay which call a stream
# belongs to is that control plane. Without these ports every relay stream
# carries associated_dialog=null, which reads as "media nobody claimed" rather
# than "the filter dropped the evidence".
CONTROL_PORTS="${CONTROL_PORTS:-}"
BPF="udp and (portrange ${PORTRANGE} or portrange ${RTP_PORTRANGE}"
for _p in $CONTROL_PORTS; do
    BPF="$BPF or port $_p"
done
BPF="$BPF)"

# The harness authenticates with rotating, short-lived bearer tokens minted from
# a long-lived HMAC signing key (never shared with clients). The static
# --mcp-token-file path is gone; clients read the rotating $TOKEN_FILE instead.
if [ ! -s "$SIGNING_KEY_FILE" ]; then
    echo "FATAL: MCP signing key $SIGNING_KEY_FILE is empty/missing; run 'make signing-key'." >&2
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

# Publish an initial token synchronously so $TOKEN_FILE is valid the instant the
# server accepts connections (and `make laptop` can read it right after up).
if ! "$ROTATE" "$SIGNING_KEY_FILE" "$TOKEN_FILE" "$TOKEN_TTL" sipnab; then
    echo "FATAL: initial token rotation failed" >&2
    exit 1
fi
echo "sipnab: minted MCP token (ttl=${TOKEN_TTL}s), rotating every ${ROTATE_INTERVAL}s -> $TOKEN_FILE"

# Background rotator: re-mint before the live token expires so the published
# file always carries a token with comfortable remaining validity. Runs as a
# separate process that survives the exec below.
(
    while true; do
        sleep "$ROTATE_INTERVAL"
        if ! "$ROTATE" "$SIGNING_KEY_FILE" "$TOKEN_FILE" "$TOKEN_TTL" sipnab; then
            echo "sipnab: WARNING token rotation failed; will retry next interval" >&2
        fi
    done
) &

# Optional second capture method: persist a rotating pcap alongside live MCP
# analysis. tcpdump runs in the same netns; sipnab reads its own live capture.
if [ -n "$PCAP_OUT" ]; then
    echo "sipnab: also writing pcap -> $PCAP_OUT (via tcpdump)"
    tcpdump -i "$IFACE" -n -s 0 -U -w "$PCAP_OUT" \
        "$BPF" >/captures/tcpdump.log 2>&1 &
fi

# The REST API is what a plain HTTP client reads; MCP is what an agent reads.
# Both doors answer from ONE capture, so a script and an agent asking the same
# question of the same node cannot get different answers.
# sipnab refuses a non-loopback REST bind with no authentication configured,
# which is the correct policy and not something to work around: the key is
# supplied instead. It is read from the secrets dir rather than passed as an
# environment variable so it does not show up in `docker inspect`.
API_KEY_FILE="${API_KEY_FILE:-/run/secrets/api.key}"
API_ARGS=""
if [ -n "$API_BIND" ]; then
    if [ ! -s "$API_KEY_FILE" ]; then
        echo "FATAL: REST API requested on $API_BIND but $API_KEY_FILE is empty/missing; run 'make api-key'." >&2
        exit 1
    fi
    SIPNAB_API_KEY="$(cat "$API_KEY_FILE")"
    export SIPNAB_API_KEY
    API_ARGS="--api $API_BIND"
    echo "sipnab${NODE_NAME:+ [$NODE_NAME]}: REST API on $API_BIND (authenticated)"
fi

# shellcheck disable=SC2086 # API_ARGS is a deliberate word-split flag pair.
exec sipnab \
    -N \
    $API_ARGS \
    --mcp --mcp-transport http \
    --mcp-bind "$BIND" \
    --mcp-signing-key-file "$SIGNING_KEY_FILE" \
    --mcp-allowed-host "$ALLOWED_HOST" \
    --portrange "$PORTRANGE" \
    -d "$IFACE" \
    "$BPF"
