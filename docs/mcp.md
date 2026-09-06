# MCP server

sipnab can run as a **Model Context Protocol** server, so an AI agent — Claude
Code, Claude Desktop, or any MCP-capable client — can ask questions about a
capture instead of you memorizing CLI flags.

It is a fourth output mode beside the TUI, the `-N` CLI and `--json`. The same
parser, dialog state machine, RTP store and diagnostic engine drive all four, so
an agent sees exactly what the other modes see.

## See it work

Point sipnab at a pcap. Stdio is the default transport, so nothing else
applies:

```bash
sipnab --mcp -N -I capture.pcap
```

That is the whole server. It speaks JSON-RPC on stdout and waits.

To ask it something without wiring up a client first, the repo ships a one-shot
helper. Here it is answering *why did this call fail?*:

```bash
demos/mcp-stdio.sh tests/pcap-samples/sip-problem-call.pcap \
  triage_call '{"call_id":"busy-3a2b1c@192.0.2.30"}'
```

```json
{
  "call_id": "busy-3a2b1c@192.0.2.30",
  "final_status_code": 486,
  "media": {
    "hints": [],
    "nat_mismatch": false,
    "no_media": false,
    "one_way_audio": false,
    "problem": false,
    "stream_count": 0
  },
  "schema_version": 1,
  "signaling": {
    "hints": [
      "Call failed: 486 Busy Here."
    ],
    "problem": true
  },
  "source_exhausted": true,
  "source_stopped_early": false,
  "state": "Failed",
  "verdict": "signaling"
}
```

A verdict, not a packet list: signaling rather than media, the 486 that ended
it, and media explicitly ruled out rather than merely absent — `one_way_audio`,
`nat_mismatch` and `no_media` each say `false` rather than going unmentioned.

`source_exhausted` and `source_stopped_early` ride on every answer this server
gives from the capture. Together they say the verdict rests on the whole file
rather than on however much had loaded when the question arrived.

## Add it to your client

For Claude Desktop or Claude Code:

```json
{
  "mcpServers": {
    "sipnab": {
      "command": "sipnab",
      "args": ["--mcp", "-N", "-I", "/path/to/capture.pcap"]
    }
  }
}
```

To serve live traffic instead of a file, run as root or grant the binary
`CAP_NET_RAW`:

```bash
sudo sipnab --mcp -N -d eth0
```

<details>
<summary>The one invariant: why every example carries <code>-N</code></summary>

`--mcp` requires `-N`/`--no-tui` because **stdout is the JSON-RPC wire**. sipnab
refuses the TUI and every stdout-writing flag (`--json`, `--report`, …) rather
than corrupting the wire with report text. sipnab rejects such a combination at
startup instead of leaving the client to fail on malformed JSON-RPC later.

Stdio needs no token — it is a private pipe between client and server. A
listening transport does need one. See [MCP protocol](mcp-protocol.md).

</details>

<details>
<summary>Building with MCP support</summary>

MCP is feature-gated. Build with `mcp` for stdio, or `mcp-http` for the HTTP
transport:

```bash
cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http
```

The default build excludes `mcp`, so an operator who never exposes the MCP
surface pays no binary size for it. `sipnab --version` prints the features of
the binary.

</details>

## Explore the tools with MCP Inspector

[MCP Inspector](https://github.com/modelcontextprotocol/inspector) is the
reference client of the Model Context Protocol project. Point it at sipnab and
it lists every tool the binary registers, shows the JSON Schema of each tool's
arguments, and calls one by hand so you can read the answer — what
<https://sipnab.com/api-reference/> does for the [REST API](rest-api.md), for
this surface instead. sipnab registers 64 MCP tools, which is more than anyone
reads in a table, and the Tools tab is the fastest way to find the one you
want. Inspector belongs to the protocol rather than to sipnab, so it also
settles whose bug you are looking at.

Inspector needs Node 22.19 or newer. `npx` fetches it on demand, so there is
nothing to install first.

### Browse a capture file over stdio

This spawns the same stdio server your agent would spawn:

```bash
npx @modelcontextprotocol/inspector sipnab -- --mcp -N -I capture.pcap
```

The `--` is load-bearing. Everything after it becomes sipnab's own command
line. Leave it out and Inspector reads `--mcp` as one of its own flags, spawns
a bare `sipnab`, and hands you a live-capture permission error instead of a
tool list.

The command prints a URL on `http://127.0.0.1:6274` carrying a one-time token.
Open that URL, click **Connect**, then open the **Tools** tab.

### Browse a listening server over HTTP

Start sipnab with the HTTP transport as [MCP deployment](mcp-deploy.md)
describes, then give Inspector the URL rather than a command:

```bash
npx @modelcontextprotocol/inspector --server-url http://127.0.0.1:8731/mcp --transport http
```

A bind that is not loopback demands a bearer token, so send the header the
server expects:

```bash
npx @modelcontextprotocol/inspector --server-url https://capture.example.com/mcp --transport http --header "Authorization: Bearer $(cat ~/.config/sipnab/prod01.token)"
```

### Dump every schema without a browser

Inspector ships a scriptable client as well as the browser one, so the tool
list is something a shell pipeline or a coding agent can read. `--cli` selects
it, and each run performs one request and exits:

```bash
npx @modelcontextprotocol/inspector --cli sipnab --mcp -N -I capture.pcap -- --method tools/list --format json
```

**The `--` separator means the opposite thing in the two clients**, which is
the one detail that catches people out. The browser client takes sipnab's
flags after `--`. The `--cli` client takes the server command first and its
own flags after `--`. Copy the fences above as written.

Calling a tool by hand works the same way:

```bash
npx @modelcontextprotocol/inspector --cli sipnab --mcp -N -I capture.pcap -- --method tools/call --tool-name triage_call --tool-arg call_id=busy-3a2b1c@192.0.2.30 --format json
```

[`scripts/mcp-schema-dump.sh`](https://github.com/NormB/sipnab/blob/main/scripts/mcp-schema-dump.sh)
wraps the `tools/list` form and accepts either a capture file or an HTTP URL:

```bash
./scripts/mcp-schema-dump.sh capture.pcap
```

Read that dump as a description of the binary you ran it against, not of this
project. A feature-reduced build registers fewer tools than the tree defines,
and an older binary registers fewer still. The [MCP tool
reference](mcp-tools.md) remains the page that says what each tool means, and
`mcp_tool_table_lists_every_registered_tool` in
[`tests/docs_drift_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/docs_drift_test.rs)
already fails the build when that page stops naming every registered tool.

## Where to go next

| You want to | Page |
|---|---|
| Run it against a remote server, keep a capture alive between sessions, or expose it as a service | [MCP deployment](mcp-deploy.md) |
| Know what a tool returns, field by field | [MCP tool reference](mcp-tools.md) |
| Write a client, or review the security model | [MCP protocol](mcp-protocol.md) |
