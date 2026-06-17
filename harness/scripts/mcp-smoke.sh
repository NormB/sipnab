#!/usr/bin/env bash
# Exercise the sipnab MCP HTTP endpoint: initialize -> tools/list -> a tool call.
# Usage: mcp-smoke.sh <url> <token>
set -euo pipefail
URL="${1:?usage: mcp-smoke.sh <url> <token>}"
TOKEN="${2:?usage: mcp-smoke.sh <url> <token>}"

HDRS=(-H "Authorization: Bearer ${TOKEN}"
      -H "Content-Type: application/json"
      -H "Accept: application/json, text/event-stream")
HDRDUMP="$(mktemp)"
SID=""

req() { # <json-body>
  local extra=()
  [ -n "$SID" ] && extra=(-H "Mcp-Session-Id: ${SID}")
  curl -sS -D "$HDRDUMP" "${HDRS[@]}" "${extra[@]}" -X POST "$URL" --data "$1"
}

echo "== initialize =="
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-smoke","version":"0"}}}'
out="$(req "$init")"
SID="$(grep -i '^mcp-session-id:' "$HDRDUMP" | awk '{print $2}' | tr -d '\r' || true)"
echo "${out#data: }"
echo "session-id: ${SID:-<none>}"

# Required handshake completion before other calls.
req '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null 2>&1 || true

echo; echo "== tools/list =="
req '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | sed 's/^data: //'

echo; echo "== tools/call: stats =="
req '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"stats","arguments":{}}}' | sed 's/^data: //'

echo; echo "== tools/call: list_dialogs =="
req '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_dialogs","arguments":{}}}' | sed 's/^data: //'

rm -f "$HDRDUMP"
