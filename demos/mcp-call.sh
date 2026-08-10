#!/usr/bin/env bash
# One readable MCP tool call against the local harness, for the demo tapes.
#
# Usage: demos/mcp-call.sh <tool> [json-arguments]
#
# Why this exists rather than the tapes calling curl directly:
#
#   1. **The bearer token must never reach the screen.** These recordings are
#      published. The token is read from the harness secret file into a shell
#      variable and passed to curl through a header; it is never echoed, never
#      interpolated into a printed command, and never appears in the rendered
#      frame. `set -x` is deliberately absent for the same reason.
#   2. MCP replies over SSE, so the payload arrives as `data: {...}` lines with
#      the interesting part nested inside `result.content[0].text` as a JSON
#      STRING. Raw, that is unreadable on a 1200x700 recording. This unwraps it
#      once, so a viewer sees the answer rather than the envelope.
#
# Everything shown comes from a real sipnab answering about real traffic
# through opensips-1. Nothing here is scripted output.
set -uo pipefail

TOOL="${1:?usage: mcp-call.sh <tool> [json-arguments]}"
ARGS="${2:-{\}}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOKEN_FILE="$ROOT/harness/secrets/mcp.token"
PORT="${MCP_PORT:-8731}"
URL="http://127.0.0.1:${PORT}/mcp"

[ -s "$TOKEN_FILE" ] || { echo "no token at $TOKEN_FILE -- is the harness up? (make -C harness up)" >&2; exit 1; }
TOKEN="$(cat "$TOKEN_FILE")"

HDRS=(-H "Authorization: Bearer ${TOKEN}"
      -H "Content-Type: application/json"
      -H "Accept: application/json, text/event-stream")
HDRDUMP="$(mktemp)"
trap 'rm -f "$HDRDUMP"' EXIT

# initialize, capturing the session id the server assigns.
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"sipnab-demo","version":"0"}}}'
curl -sS -D "$HDRDUMP" "${HDRS[@]}" -X POST "$URL" --data "$init" >/dev/null
SID="$(grep -i '^mcp-session-id:' "$HDRDUMP" | awk '{print $2}' | tr -d '\r' || true)"
SIDH=()
[ -n "$SID" ] && SIDH=(-H "Mcp-Session-Id: ${SID}")

curl -sS "${HDRS[@]}" "${SIDH[@]}" -X POST "$URL" \
     --data '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null 2>&1 || true

body=$(printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"%s","arguments":%s}}' "$TOOL" "$ARGS")
curl -sS "${HDRS[@]}" "${SIDH[@]}" -X POST "$URL" --data "$body" \
  | sed 's/^data: //' \
  | jq -r '.result.content[0].text // (.error.message | "error: " + .) // "no content"' \
  | jq .
