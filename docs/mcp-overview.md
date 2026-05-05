# MCP server mode

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
  sipnab refuses to start (D18).
- For TLS, terminate it in nginx in front of sipnab. Bind sipnab to
  `127.0.0.1:8731` and let nginx handle the public 443 endpoint.
- When clients reach sipnab by hostname or non-loopback IP, add that
  name to the host-header allowlist with `--mcp-allowed-host`
  (repeatable). The default allowlist is `localhost`, `127.0.0.1`, `::1`
  only; rmcp will return `403 Forbidden: Host header is not allowed`
  for any other `Host` value otherwise. A literal `*` disables host
  checking entirely — pair with a network-level source-IP allowlist.

```bash
# Network-bound, with the actual public hostname accepted
sipnab --mcp --mcp-transport http \
       --mcp-bind 0.0.0.0:8731 \
       --mcp-token-file /etc/sipnab/mcp.token \
       --mcp-allowed-host capture.example.com \
       -I capture.pcap
```

The agent then connects to `https://your-host/mcp` with a `Bearer
<token>` header.

## Available tools (v0.4)

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

See [`mcp-tools.md`](./mcp-tools.md) for parameter / response details.

## Security model

- **Read-only by design.** No tool mutates the dialog/stream/alert
  stores or sends SIP. Capture lifecycle is owned by systemd / the
  CLI flags, not by the LLM.
- **Localhost-default.** HTTP transport binds `127.0.0.1:8731` unless
  explicitly overridden.
- **Bearer auth on non-loopback.** Tokens compared in constant time
  via the existing `output::api::constant_time_eq` helper, sharing
  the same code path as the REST API.
- **No prompt-injection cooperation.** Tool descriptions never
  instruct the LLM to "trust" or "act on" returned content; they
  describe what the tool returns and stop there.
- **Privilege drop respected.** The MCP listener binds *after*
  `privilege::drop_privileges` so sipnab runs as the unprivileged
  `sipnab` user. Default port (8731) is ≥ 1024 to permit this.

## Stdio invariant

In stdio mode, **stdout is the JSON-RPC wire**. sipnab routes all
logging through `tracing-subscriber` to stderr (Phase 8.0b); a regression
test (`tests/parse_path_test.rs`) verifies that no log line ever leaks
to stdout. If you see "Parse error" from your MCP client after a
sipnab log line, that's a regression — please file an issue with the
SIPNAB_LOG level you reproduced it under.

## Build flags

```toml
mcp       # stdio transport (rmcp dep, ~3 MB binary cost)
mcp-http  # HTTP transport (mcp + api; rmcp/transport-streamable-http-server)
full      # default + tui + tls + hep + api + audio + mcp + mcp-http
```

The default build does not include `mcp` — operators who'll never
expose the MCP surface pay zero binary size for it.
