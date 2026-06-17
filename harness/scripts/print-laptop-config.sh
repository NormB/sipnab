#!/usr/bin/env bash
# Print the MCP client configuration your laptop needs to reach this harness.
# Usage: print-laptop-config.sh <host-ip> <mcp-port> <token-file>
set -euo pipefail
HOST="${1:-<this-host-ip>}"
PORT="${2:-8731}"
TOKENF="${3:-secrets/mcp.token}"
TOKEN="$(cat "$TOKENF" 2>/dev/null || echo '<not minted yet: make up, then make logs-sipnab>')"
URL="http://${HOST}:${PORT}/mcp"

cat <<EOF

================= sipnab MCP -- connect from your laptop =================
  Endpoint : ${URL}
  Auth     : Bearer ${TOKEN}

Claude Code (on the laptop):
  claude mcp add --transport http sipnab "${URL}" \\
      --header "Authorization: Bearer ${TOKEN}"

Claude Desktop (claude_desktop_config.json):
  {
    "mcpServers": {
      "sipnab": {
        "command": "npx",
        "args": ["-y", "mcp-remote", "${URL}",
                 "--header", "Authorization: Bearer ${TOKEN}"]
      }
    }
  }

Smoke test from the laptop:
  curl -sS -X POST "${URL}" \\
    -H "Authorization: Bearer ${TOKEN}" \\
    -H "Content-Type: application/json" \\
    -H "Accept: application/json, text/event-stream" \\
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'

Then ask your agent to diagnose opensips-1, e.g.:
  - "List active SIP dialogs and flag any with problems."
  - "Show RTP quality (MOS / jitter / loss) for the current streams."
  - "Any security findings -- scanners, malformed messages, digest leaks?"

NOTE: the host running this stack must allow inbound TCP ${PORT} from your
laptop (firewall / security group). The bearer token is required; keep it
secret. If SIPNAB_MCP_ALLOWED_HOST is not '*', it must match the host name/IP
your laptop uses in the URL above.

NOTE: this bearer token is short-lived and ROTATES (the sipnab container
re-mints it on a timer). When your client starts getting 401s, re-run
'make laptop' to grab the current token. The signing key behind it stays put.
==========================================================================
EOF
