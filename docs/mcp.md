# MCP server

sipnab can run as a **Model Context Protocol** server, so an AI agent — Claude
Code, Claude Desktop, or any MCP-capable client — can read a capture and answer
your questions about it instead of you memorizing CLI flags.

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

To ask it something with nothing but the installed binary and `jq`, pipe the
three messages a client would send into it. This sample capture holds four
failed calls:

```bash
curl -LO https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap
```

The first message opens the session, the second confirms it, and the third
asks `triage_call` why one call failed. The server exits when its input ends:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"triage_call","arguments":{"call_id":"busy-3a2b1c@192.0.2.30"}}}' \
  | sipnab --mcp -N -I sip-problem-call.pcap --quiet \
  | jq 'select(.id == 2) | .result.content[0].text | fromjson | {verdict, final_status_code, signaling}'
```

```json
{
  "verdict": "signaling",
  "final_status_code": 486,
  "signaling": {
    "hints": [
      "Call failed: 486 Busy Here."
    ],
    "problem": true
  }
}
```

From a source checkout, a one-shot helper does the same with less typing and
prints the whole answer:

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
<summary>Why every stdio example carries <code>-N</code></summary>

With the stdio transport, **stdout is the JSON-RPC wire**, so `--mcp` implies
`-N`/`--no-tui`. sipnab also refuses every stdout-writing flag (`--json`,
`--report`, …) at startup rather than corrupting the wire with report text,
which would leave the client to fail on malformed JSON-RPC later. The `-N` in
these examples states what `--mcp` already does.

Over HTTP the wire is a socket, so the TUI can stay up beside the server: see
[Query a capture over MCP while the TUI is open](#query-a-capture-over-mcp-while-the-tui-is-open).

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

## Query a capture over MCP while the TUI is open

Use this when you want to watch a capture in the TUI while an agent asks
questions about the same capture. One sipnab process does both: the TUI and
the MCP server read the same dialogs and streams, so the agent's answers match
what is on screen.

Start sipnab with the HTTP transport and without `-N`. This example uses the
sample capture from [See it work](#see-it-work), and names a port so that it
does not collide with a headless MCP server already on the default
`127.0.0.1:8731`:

```bash
sipnab -I sip-problem-call.pcap --mcp --mcp-transport http --mcp-bind 127.0.0.1:8735
```

The TUI opens as usual. The status line under the header says where MCP is
listening:

```text
 MCP over HTTP at http://127.0.0.1:8735/mcp
```

With `--mcp-bind 127.0.0.1:0` the kernel picks a free port, and the status line
shows the port it picked.

Point your agent at that URL. For Claude Code, use the `claude mcp add` command
in [MCP deployment](mcp-deploy.md). To check the server from a second terminal
with `curl` and `jq`, open a session, confirm it, and list the dialogs:

```bash
# Run all of these, in order.
URL=http://127.0.0.1:8735/mcp
H=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')
SID=$(curl -s -D - -o /dev/null "${H[@]}" "$URL" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"0"}}}' \
  | tr -d '\r' | awk 'tolower($1) == "mcp-session-id:" {print $2}')
curl -s "${H[@]}" -H "Mcp-Session-Id: $SID" "$URL" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
curl -s "${H[@]}" -H "Mcp-Session-Id: $SID" "$URL" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_dialogs","arguments":{}}}' \
  | sed -n 's/^data: //p' | jq '.result.content[0].text | fromjson | {returned, source_exhausted, call_ids: [.dialogs[].call_id]}'
```

```json
{
  "returned": 5,
  "source_exhausted": true,
  "call_ids": [
    "completed-9f8e7d@192.0.2.10",
    "busy-3a2b1c@192.0.2.30",
    "decline-7c6d5e@198.51.100.30",
    "notfound-1b2c3d@203.0.113.30",
    "unavail-4e5f60@192.0.2.50"
  ]
}
```

The same five calls are on the TUI's call list. `source_exhausted` is `true`
once sipnab has read the whole file.

Quit the TUI (`q`, then `y`) and the MCP server stops with it: the port closes
when the process exits.

What differs from a headless MCP server:

- **It needs a terminal.** Without one the TUI cannot start and sipnab exits
  with an error. A systemd unit or a container runs `-N`.
- **The HTTP rules stay the same.** A loopback bind needs no token, and any
  other bind needs one, as [MCP deployment](mcp-deploy.md) describes. The Host
  header check, the rate limits and the TLS flags are the ones a headless
  server reads.
- **A bind problem stops the run before the TUI opens.** A port already in
  use, or a non-loopback bind with no token, prints the reason and exits 2.
- **sipnab refuses five opt-ins with the TUI up.** Each acts on the process or on
  the relay rather than reading the capture, and the operator at the terminal
  owns both. Add `-N` to use them:

  | Flag | Why sipnab refuses it beside the TUI |
  |---|---|
  | `--mcp-allow-shutdown` | `shutdown_server` stops the capture and the servers, and the TUI stays on screen showing a stopped run. |
  | `--mcp-allow-open-capture` | `open_capture` replaces the capture the operator is reading. |
  | `--mcp-allow-tls-capture` | `start_tls_capture` writes a second capture into the stores the TUI shows. |
  | `--mcp-allow-save-findings` | `save_findings` writes to the log, and a TUI run logs only errors, so nobody would see the finding. |
  | `--mcp-allow-relay-query` | `query_relay` transmits on the run's one transmit permit, which the TUI's relay statistics view holds. |

- **The server writes nothing over the screen.** A TUI run logs only errors. To keep
  the server's log lines, send them to a file:

  ```bash
  SIPNAB_LOG=info sipnab -I sip-problem-call.pcap --mcp --mcp-transport http --mcp-bind 127.0.0.1:8735 2>sipnab.log
  ```

  `sipnab.log` then holds `MCP HTTP server listening on 127.0.0.1:8735` and
  the rest of the run's log lines.

## Explore the tools with MCP Inspector

[MCP Inspector](https://github.com/modelcontextprotocol/inspector) is the
reference client of the Model Context Protocol project. Point it at sipnab and
it lists every tool the binary registers, shows the JSON Schema of each tool's
arguments, and calls one by hand so you can read the answer — what
<https://sipnab.com/api-reference/> does for the [REST API](rest-api.md), for
this surface instead.

sipnab registers 72 MCP tools, which is more than anyone
reads in a table, and the Tools tab is the fastest way to find the one you
want.

Inspector belongs to the protocol rather than to sipnab, so it also
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

### Linting the advertised schemas

`--strict` reports schema spellings a client may not read. It exits non-zero
only on error severity, so a clean exit and a clean report are different
things -- read the summary line:

```bash
npx @modelcontextprotocol/inspector --cli sipnab --mcp -N -I capture.pcap -- --method tools/list --strict
```

Measured against 0.5.160: **0 errors and 83 warnings across 47 tools**, down
from 172. Every remaining warning is one class, and sipnab waives it on purpose.

`schemars` renders an optional field as `"type": ["string","null"]`. That is
legal JSON Schema and several clients cannot read it -- they take `type` as a
single string and either drop the constraint or refuse the whole tool. sipnab
collapses those unions on **input** schemas, where a client validates
arguments before calling and where a refusal costs you the tool.

Output schemas keep theirs, because sipnab writes an explicit `null` for an
absent optional field. Collapsing there would advertise a schema its own
responses violate, which is a worse problem than the spelling.

There is no CI job running this. `no_input_schema_advertises_a_spelling_a_strict_client_may_refuse` checks the
same property offline, against the live wire, with no network and no package
manager. Run the command above by hand when the
Inspector's rules move.

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

## Operator notes are not an MCP surface

An operator can put a note on a SIP message in the TUI, or write notes into a
pcapng copy with `--write-annotated` (see
[keybindings](keybindings.md#operator-notes) and the
[CLI reference](cli-reference.md#operator-notes)). No MCP tool reads a note or
writes one, and that is a decision, not a missing tool.

An agent that could read
a note would cite a person's conclusion as though the capture said it. An agent
that could write one would be putting its own text into a file that leaves the
machine. `save_findings` stays the only thing an agent writes, and it goes to
the log.

sipnab never reads a packet comment back, so a note in a capture an MCP
server opens is invisible to every tool. Invariant 13 in
[the invariants page](internals/invariants.md#13-operator-notes-are-output-never-input)
states the rule and what enforces it.

## Where to go next

| You want to | Page |
|---|---|
| Run it against a remote server, keep a capture alive between sessions, or expose it as a service | [MCP deployment](mcp-deploy.md) |
| Know what a tool returns, field by field | [MCP tool reference](mcp-tools.md) |
| Write a client, or review the security model | [MCP protocol](mcp-protocol.md) |
| Run what an agent does, end to end: triage over [stdio](client-examples.md#triage-a-capture-over-mcp-as-an-agent) or [HTTP with a signed token](client-examples.md#reach-a-production-box-over-http-with-a-signed-token), an [evidence package with repro scripts](client-examples.md#hand-an-agent-an-evidence-package-and-a-repro-script), or an [aggregate cut to a model's budget](client-examples.md#aggregate-dialogs-into-bounded-json-for-a-model) | [Runnable client examples](client-examples.md#ai-tasks) |
