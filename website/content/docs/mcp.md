+++
title = "MCP Server"
weight = 9
+++

sipnab can run as a **Model Context Protocol** server, exposing its
read-only analysis surface (dialogs, streams, RTP quality, diagnostic
hints, security findings, call reports) as tools that an AI agent —
Claude Code, Claude Desktop, or any MCP-capable client — can call to
debug captures interactively.

## Why MCP

MCP is a fourth output mode alongside the existing TUI, `-N` CLI, and
`--json` modes. The same parser, dialog state machine, RTP store, and
diagnostic engine drive every output. Switching to MCP gives a remote or
local agent the ability to query live captures in natural language,
without you having to memorize CLI flags.

## Quick start (stdio)

The simplest way to drive sipnab from a local agent:

```bash
sipnab --mcp -I capture.pcap            # stdio is the default transport
```

Add this server to your MCP client. For Claude Desktop, the config block
looks like:

```json
{
  "mcpServers": {
    "sipnab": {
      "command": "sipnab",
      "args": ["--mcp", "-I", "/path/to/capture.pcap"]
    }
  }
}
```

For a live capture against an interface (root or `CAP_NET_RAW`):

```bash
sudo sipnab --mcp -d eth0
```

## Quick start (HTTP — remote agent)

When the agent runs on a different host, switch to the HTTP transport:

```bash
sipnab --mcp --mcp-transport http \
       --mcp-bind 127.0.0.1:8731 \
       --mcp-token-file /etc/sipnab/mcp.token \
       -I capture.pcap
```

- The default bind is loopback. Non-loopback binds **must** supply
  `--mcp-token` / `--mcp-token-file` / `SIPNAB_MCP_TOKEN`; otherwise
  sipnab refuses to start.
- For TLS, terminate it in nginx in front of sipnab. Bind sipnab to
  `127.0.0.1:8731` and let nginx handle the public 443 endpoint.

The agent then connects to `https://your-host/mcp` with a `Bearer
<token>` header.

### DNS-rebind protection (`--mcp-allowed-host`)

The HTTP transport refuses requests whose `Host` header isn't in its
allowlist. The default set is `localhost`, `127.0.0.1`, `::1`. When
clients reach sipnab via a hostname or non-loopback IP, add it to the
allowlist:

```bash
sipnab --mcp --mcp-transport http \
       --mcp-bind 0.0.0.0:8731 \
       --mcp-token-file /etc/sipnab/mcp.token \
       --mcp-allowed-host capture.example.com \
       --mcp-allowed-host 203.0.113.7 \
       -I capture.pcap
```

The literal `*` disables host checking entirely (paired with a
network-level source-IP allowlist as the substitute defense).

## Available tools

| Tool | Returns |
|---|---|
| `list_dialogs` | Dialog summaries with optional alias / DSL filter |
| `get_dialog_report` | Structured per-call report (JSON / Markdown / text) |
| `find_problems` | Dialogs matching one or more diagnostic alias names |
| `get_dialog` | Paginated dialog with full SIP messages |
| `get_message` | Single SIP message at a given index |
| `render_ladder` | Call-flow ladder (Markdown / text) |
| `rtp_stats` | Per-stream RTP quality + media diagnosis |
| `search_messages` | Substring search across method/From/To/UA/body |
| `tail_dialogs` | Cursor-based incremental dialog fetch |
| `security_findings` | Recent scanner / fraud / digest / reg-flood alerts |
| `stats` | Aggregate counters (dialog_count, stream_count, etc.) |

All tools are read-only. Responses are bounded by a hard limit of 1000
records per call; tools that can return more support cursor- or offset-
based pagination.

## Security model

- **Read-only by design.** No tool mutates the dialog/stream/alert
  stores or sends SIP. Capture lifecycle is owned by systemd / the
  CLI flags, not by the LLM.
- **Localhost-default.** HTTP transport binds `127.0.0.1:8731` unless
  explicitly overridden.
- **Bearer auth on non-loopback.** Tokens compared in constant time
  via the same code path as the REST API.
- **Host header allowlist.** rmcp's DNS-rebind protection is enabled
  by default; extend with `--mcp-allowed-host` for non-loopback
  clients.
- **No prompt-injection cooperation.** Tool descriptions never
  instruct the LLM to "trust" or "act on" returned content; they
  describe what the tool returns and stop there.
- **Privilege drop respected.** The MCP listener binds *after*
  privilege drop so sipnab runs as the unprivileged `sipnab` user.
  Default port (8731) is ≥ 1024 to permit this.

## Stdio invariant

In stdio mode, **stdout is the JSON-RPC wire**. sipnab routes all
logging through `tracing-subscriber` to stderr; a regression test
verifies that no log line ever leaks to stdout. If you see "Parse
error" from your MCP client after a sipnab log line, that's a
regression — please file an issue on GitHub.

A consequence: `--mcp` is incompatible with stdout-writing flags such
as `--json`, `--json-pretty`, `--report`, `--call-report`, `--hexdump`,
`--wireshark`, and `--tshark-filter`. Combine `--mcp` with `--quiet`
if you want the surrounding text-mode capture output suppressed
entirely.

## Build flags

```toml
mcp       # stdio transport (rmcp dep, ~3 MB binary cost)
mcp-http  # HTTP transport (mcp + api; rmcp/transport-streamable-http-server)
full      # native + tui + tls + hep + api + audio + mcp + mcp-http
```

The default build does not include `mcp` — operators who'll never
expose the MCP surface pay zero binary size for it.

## Client cookbook

Concrete examples for the MCP clients people actually use.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "sipnab": {
      "command": "sipnab",
      "args": ["--mcp", "-I", "/path/to/capture.pcap", "--quiet"]
    }
  }
}
```

For a live capture (requires `CAP_NET_RAW` or root — Claude Desktop won't grant either, so this is for environments where you'll manually `setcap` the binary):

```json
{
  "mcpServers": {
    "sipnab-live": {
      "command": "sudo",
      "args": ["-n", "sipnab", "--mcp", "-d", "eth0", "--quiet"]
    }
  }
}
```

(`sudo -n` fails fast if no NOPASSWD rule is in place — keeps the agent from hanging on a password prompt.)

Restart Claude Desktop. The agent will list `sipnab` under "Connected" — ask it "what dialogs failed in this capture?" and watch it call `find_problems` for you.

### Claude Code

From your project directory:

```bash
# Stdio against a fixed pcap (`--` ends `claude mcp add` flags so the
# trailing `sipnab --mcp ...` is treated as the launched command)
claude mcp add sipnab -- sipnab --mcp -I "$PWD/capture.pcap" --quiet

# HTTP against a remote sipnab — flags before the positional name + URL
claude mcp add --transport http \
       --header "Authorization: Bearer $(cat ~/.config/sipnab/token)" \
       sipnab-remote https://capture.example.com/mcp

# Verify
claude mcp list
```

### Raw stdio JSON-RPC test (for client developers)

The simplest way to confirm the server is alive without an MCP client:

```bash
{
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}'
  sleep 0.3
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  sleep 0.1
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  sleep 0.5
} | sipnab --mcp -I capture.pcap --quiet | head -c 2000
```

Expected first line of response:

```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"rmcp","version":"1.6.0"},"instructions":"sipnab MCP server — read-only access ..."}}
```

### Raw HTTP test

```bash
TOKEN=$(cat /etc/sipnab/mcp-token)
URL="http://capture.example.com:8731/mcp"

# Initialize
curl -sS "$URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'

# tools/call — find_problems with multiple aliases
curl -sS "$URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"find_problems",
                 "arguments":{"kinds":["one-way","late-media","codec-asym"]}}}'

# tools/call — get_dialog with pagination
curl -sS "$URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"get_dialog",
                 "arguments":{"call_id":"abc123@host","cursor":0,"max_messages":50}}}'

# tools/call — security_findings
curl -sS "$URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call",
       "params":{"name":"security_findings","arguments":{"limit":20}}}'
```

Common failure modes:

| Status | Cause |
|---|---|
| `401` | Missing or wrong `Authorization: Bearer ...` |
| `403 Forbidden: Host header is not allowed` | Your `Host:` doesn't match the rmcp allowlist. Either send `Host: localhost` explicitly, or start sipnab with `--mcp-allowed-host <your-host>` |
| `404` | Wrong path — must be exactly `/mcp` |
| `406 Not Acceptable` | Missing `Accept: application/json, text/event-stream` |

### Python MCP client (using the `mcp` SDK)

```python
"""Minimal MCP client driving sipnab over stdio."""
import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main(pcap: str) -> None:
    params = StdioServerParameters(
        command="sipnab",
        args=["--mcp", "-I", pcap, "--quiet"],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. List tools
            tools = await session.list_tools()
            for t in tools.tools:
                print(f"{t.name:20s}  {t.description[:60]}")

            # 2. Find one-way audio + late-media problems
            res = await session.call_tool(
                "find_problems",
                {"kinds": ["one-way", "late-media"], "limit": 50},
            )
            for content in res.content:
                if content.type == "text":
                    print(content.text[:500])


if __name__ == "__main__":
    import sys
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"))
```

Install + run:

```bash
pip install 'mcp>=1.0'
python sipnab_mcp.py /path/to/capture.pcap
```

### TypeScript MCP client

```typescript
// npm i @modelcontextprotocol/sdk
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "sipnab",
  args: ["--mcp", "-I", process.argv[2] ?? "capture.pcap", "--quiet"],
});

const client = new Client({ name: "sipnab-demo", version: "0.1" });
await client.connect(transport);

const tools = await client.listTools();
console.log(`${tools.tools.length} tools available`);

const result = await client.callTool({
  name: "find_problems",
  arguments: { kinds: ["nat-issues", "one-way"], limit: 20 },
});
console.log(JSON.stringify(result, null, 2));

await client.close();
```
