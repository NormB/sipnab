# MCP server

sipnab can run as a **Model Context Protocol** server. An AI agent can then read
a capture and answer your questions about it. You do not need to memorize CLI
flags. The agent can be Claude Code, Claude Desktop, or any MCP-capable client.

It is a fourth output mode beside the TUI, the `-N` CLI and `--json`. The same
parts drive all four:

- the parser,
- the dialog state machine,
- the RTP store,
- the diagnostic engine.

So an agent sees exactly what the other modes see.

## Before you start

- **A sipnab binary with the `mcp` feature** for the stdio transport, and
  `mcp-http` as well for the HTTP transport. `sipnab --version` lists the
  features, and the release binaries carry both.
- **An MCP client,** such as Claude Code or Claude Desktop. The checks on this
  page need no client: they use the shell.
- **`jq`,** to read the answers in the examples, and **`curl`,** for the
  examples that use the HTTP transport.
- **A capture file, or capture rights on an interface.**
  [Install sipnab](install.md) grants the rights for a live capture.
- **No change on any other system** for the stdio transport: the client
  starts sipnab as a child process on its own machine. For a client on another
  machine, [MCP deployment](mcp-deploy.md#before-you-start) lists what
  changes on each side.

## See it work

Point sipnab at a pcap. Stdio is the default transport, so nothing else
applies:

```bash
sipnab --mcp -N -I capture.pcap
```

That is the whole server. It speaks JSON-RPC on stdout and waits.

You can ask it something with nothing but the installed binary and `jq`. Pipe
the three messages a client would send into it. This sample capture holds four
failed calls:

```bash
curl -LO https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap
```

- The first message opens the session.
- The second confirms it.
- The third asks `triage_call` why one call failed.

The server exits when its input ends:

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

A verdict, not a packet list:

- signaling rather than media,
- the 486 that ended it,
- media explicitly ruled out rather than merely absent.
  `one_way_audio`, `nat_mismatch` and `no_media` each say `false` rather than
  going unmentioned.

`source_exhausted` and `source_stopped_early` ride on every answer this server
gives from the capture. Together they say the verdict rests on the whole file.
It does not rest on however much had loaded when the question arrived.

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

With the stdio transport, **stdout is the JSON-RPC wire**. So `--mcp` implies
`-N`/`--no-tui`.

- On stdio, sipnab refuses at startup every flag that writes its answer to
  stdout, such as `--json` and `--report`, and exits 2, for example with `--mcp uses stdout for the JSON-RPC
  wire and cannot be combined with stdout-writing flags (--json)`.

  Write the report from a separate run without `--mcp`.
- The `-N` in these examples states what `--mcp` already does.

Over HTTP the wire is a socket, so the TUI can stay up beside the server: see
[Query a capture over MCP while the TUI is open](#query-a-capture-over-mcp-while-the-tui-is-open).

Stdio needs no token. It is a private pipe between client and server. A
listening transport does need one. See [MCP protocol](mcp-protocol.md).

</details>

<details>
<summary>Building with MCP support</summary>

MCP is feature-gated. Build with `mcp` for stdio, or `mcp-http` for the HTTP
transport:

```bash
cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http
```

The default build excludes `mcp`. `sipnab --version` prints the features of
the binary.

</details>

## Query a capture over MCP while the TUI is open

Use this when you want to watch a capture in the TUI while an agent asks
questions about the same capture.

- One sipnab process does both.
- The TUI and the MCP server read the same dialogs and streams.
- So the agent's answers match what is on screen.

Start sipnab with the HTTP transport and without `-N`.

- This example uses the sample capture from [See it work](#see-it-work).
- It names a port so that it does not collide with a headless MCP server
  already on the default `127.0.0.1:8731`:

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
in [MCP deployment](mcp-deploy.md).

To check the server from a second terminal with `curl` and `jq`:

- open a session,
- confirm it,
- list the dialogs:

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

Quit the TUI (`q`, then `y`) and the MCP server stops with it. The port closes
when the process exits.

What differs from a headless MCP server:

- **It needs a terminal.** Without one the TUI cannot start and sipnab exits
  with an error. A systemd unit or a container runs `-N`.
- **The HTTP rules stay the same.**
  - A loopback bind needs no token.
  - Any other bind needs one, as [MCP deployment](mcp-deploy.md) describes.
  - The Host header check, the rate limits and the TLS flags are the ones a
    headless server reads.
- **A bind problem stops the run before the TUI opens.** A port already in
  use, or a non-loopback bind with no token, prints the reason and exits 2.
- **sipnab refuses five opt-ins with the TUI up.** Each acts on the process or on
  the relay rather than reading the capture. The operator at the terminal
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

## Tools that write or act

Most tools only read what sipnab holds. Thirteen write a file or act on the
host or on TFPS. None of them can do either until you start the server
with the flag that allows it:

| Tool | What it does | Allowed by |
|---|---|---|
| `export_capture` | Writes the held SIP messages to a pcap file | `--mcp-file-root` |
| `export_audio` | Writes a call's audio to a WAV file | `--mcp-file-root` |
| `compare_captures` | Reads two capture files and compares them | `--mcp-file-root` |
| `build_evidence_package` | Writes a directory of evidence for the calls it names | `--mcp-file-root` |
| `generate_repro` | Returns a SIPp scenario; writes it to a file only when given a `filename` | `--mcp-file-root`, for the file |
| `open_capture` | Replaces the capture the server is reading with a file from the file root | `--mcp-allow-open-capture` and `--mcp-file-root` |
| `save_findings` | Writes findings to the log | `--mcp-allow-save-findings` |
| `shutdown_server` | Stops the capture and the servers | `--mcp-allow-shutdown` |
| `start_tls_capture` | Starts a uprobe TLS capture on this host | `--mcp-allow-tls-capture` |
| `stop_tls_capture` | Stops the capture `start_tls_capture` began | `--mcp-allow-tls-capture`, to have started one |
| `tfps_ban` | Asks TFPS to ban one source | `--allow-action tfps:mcp` |
| `tfps_unban` | Asks TFPS to lift a ban sipnab placed | `--allow-action tfps:mcp` |
| `actions_revert` | Backs out bans sipnab placed | `--allow-action tfps:mcp` |

Over HTTP, the three TFPS tools also need a token with the actions scope.

## Explore the tools with MCP Inspector

[MCP Inspector](https://github.com/modelcontextprotocol/inspector) is the
reference client of the Model Context Protocol project. Point it at sipnab and
it does these things:

- It lists every tool the binary registers.
- It shows the JSON Schema of each tool's arguments.
- It calls one by hand so you can read the answer.

It does for this surface what <https://sipnab.com/api-reference/> does for the
[REST API](rest-api.md).

sipnab registers 79 MCP tools. That is more than anyone reads in a table. The
Tools tab is the fastest way to find the one you want.

The MCP project maintains Inspector, not sipnab. When a tool
misbehaves in your own client, call it from Inspector to see whether the
fault is in sipnab or in the client.

Inspector needs Node 22.19 or newer. `npx` fetches it on demand. So there is
nothing to install first.

### Browse a capture file over stdio

This spawns the same stdio server your agent would spawn:

```bash
npx @modelcontextprotocol/inspector sipnab -- --mcp -N -I capture.pcap
```

Keep the `--`. Everything after it becomes sipnab's own command line. Leave it
out and Inspector does this:

- it reads `--mcp` as one of its own flags,
- it spawns a bare `sipnab`,
- it hands you a live-capture permission error instead of a tool list.

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

Inspector ships a scriptable client as well as the browser one. So the tool
list is something a shell pipeline or a coding agent can read. `--cli` selects
it. Each run performs one request and exits:

```bash
npx @modelcontextprotocol/inspector --cli sipnab --mcp -N -I capture.pcap -- --method tools/list --format json
```

**The `--` separator works the opposite way in the two clients:**

- The browser client takes sipnab's flags after `--`.
- The `--cli` client takes the server command first and its own flags after
  `--`.

Copy the fences above as written.

Calling a tool by hand works the same way:

```bash
npx @modelcontextprotocol/inspector --cli sipnab --mcp -N -I capture.pcap -- --method tools/call --tool-name triage_call --tool-arg call_id=busy-3a2b1c@192.0.2.30 --format json
```

### Check the advertised schemas with `--strict`

`--strict` reports schema spellings a client may not read. It exits non-zero
only on error severity, so a zero exit status does not mean the report is
clean. Read the summary line:

```bash
npx @modelcontextprotocol/inspector --cli sipnab --mcp -N -I capture.pcap -- --method tools/list --strict
```

Expect warnings about type unions only from output schemas:

- No **input** schema writes `type` as an array such as
  `"type": ["string","null"]`, so a client that reads `type` as one string
  can read every tool's arguments.
- **Output** schemas, which sipnab sends only with `--mcp-output-schemas`,
  keep unions such as `"type": ["string","null"]`, because a response carries
  an explicit `null` for an absent optional field. `--strict` may warn about
  them.

[`scripts/mcp-schema-dump.sh`](https://github.com/NormB/sipnab/blob/main/scripts/mcp-schema-dump.sh)
wraps the `tools/list` form and accepts either a capture file or an HTTP URL:

```bash
./scripts/mcp-schema-dump.sh capture.pcap
```

Read that dump as a description of the binary you ran it against, not of this
project.

- A feature-reduced build registers fewer tools than the tree defines.
- An older binary registers fewer still.
- The [MCP tool reference](mcp-tools.md) documents every tool the full build
  registers, and what each one means.

## Read and write operator notes outside MCP

No MCP tool reads or writes an operator note. To add notes to SIP messages,
use the TUI, then write them into a pcapng copy with `--write-annotated`. See
[keybindings](keybindings.md#operator-notes) and the
[CLI reference](cli-reference.md#operator-notes).

- sipnab never reads a packet comment back, so a note in a capture an MCP
  server opens is not visible to any tool.
- The only text an agent can record is a finding, written to the log with
  `save_findings`.

Invariant "Operator notes are output, never input" in
[the invariants page](internals/invariants.md#operator-notes-are-output-never-input)
states the rule and why it holds.

## Read resources and run prompts

Besides tools, the server offers two other MCP primitives. A client that
supports them shows them by name. They need no flag beyond `--mcp`.

- **Resources** are documents the client reads by URI: reference pages, one
  call's live state, one call's vCon. `resources/list` names the fixed ones,
  and `resources/templates/list` the patterns, such as
  `sipnab://live/dialogs/{call_id}`. `completion/complete` fills in a
  template's argument from what the capture holds.
- **Prompts** are procedures an agent follows, each naming the tools
  it calls in order. `prompts/list` names them, and `prompts/get` returns the
  text.

Over the stdio wire, these lines ask for each list, complete a Call-ID and
read one call:

```sh
# Run all of these, in order.
{ printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"doc","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"prompts/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"resources/list"}' \
  '{"jsonrpc":"2.0","id":4,"method":"resources/templates/list"}' \
  '{"jsonrpc":"2.0","id":5,"method":"completion/complete","params":{"ref":{"type":"ref/resource","uri":"sipnab://live/dialogs/{call_id}"},"argument":{"name":"call_id","value":"1-19"}}}' \
  '{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"sipnab://live/dialogs/1-1966@10.0.2.20"}}'
  sleep 3; } | sipnab -N --mcp -I tests/pcap-samples/sip-rtp-g711.pcap --quiet > mcp.out
```

Against the sample capture, the answers named:

| `id` | Answer |
|---|---|
| 2 | prompts `triage-outage`, `carrier-escalation`, `codec-interop-audit`, `post-change-verification`, `vcon-handoff` |
| 3 | resources `sipnab://reference/filter-dsl`, `sipnab://reference/sip-response-codes`, `sipnab://reference/mos-and-codecs`, `sipnab://live/dialogs` |
| 4 | templates `sipnab://live/dialogs/{call_id}`, `sipnab://lint/{rule_id}`, `sipnab://filter/{alias}`, `sipnab://reference/{topic}`, `sipnab://schema/{tool}`, `sipnab://vcon/{call_id}` |
| 5 | `{"completion": {"values": ["1-1966@10.0.2.20", "1-1968@10.0.2.20"], "total": 2, "hasMore": false}}` |
| 6 | the call's live state, as JSON text in `contents[0].text` |

[The prompts](mcp-tools.md#prompts) lists what each prompt is for, and
[Resources](mcp-protocol.md#resources) defines each URI.
[Export a call as a vCon](vcon.md) covers the export the `vcon-handoff` prompt drives.

When it does not work:

- A prompt is missing from `prompts/list`: the server did not load a bundle
  one of its tools is in. `prompts/get` for it names the bundles to add.
- `resources/read` answers `call_id '<id>' not found`, with `reason`
  `not_found`: the capture holds no such call. Complete the Call-ID first.

## Check that it worked

Send the server the two messages that open a session and a request for its
tool list. This uses the sample capture from [See it work](#see-it-work), and
it answers the same way for any capture, because neither answer reads the
capture:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | sipnab --mcp -N -I sip-problem-call.pcap --quiet \
  | jq -c 'if .id == 1 then .result.serverInfo.name else (.result.tools | map(.name) | index("triage_call") != null) end'
```

Expect two lines, the name the server gives itself and `true` for a tool list
that holds `triage_call`:

```text
"sipnab"
true
```

The test suite runs this check on each build: it sends the three messages of
the fence above to the binary and reads the same two fields. On Ubuntu 24.04
(Linux 6.8, aarch64) the full build answered `sipnab` and listed 79 tools,
`triage_call` among them. The suite reads the answers in Rust, not with `jq`.

## When something does not work

| Symptom | Likely cause |
|---|---|
| `--mcp requires the 'mcp' feature (not compiled in)`, exit 2 | The binary has no MCP server. Install a release binary, or build with the `mcp` feature |
| `--mcp uses stdout for the JSON-RPC wire and cannot be combined with stdout-writing flags (--json)`, exit 2 | A flag on the command line writes to standard output, which the stdio transport owns. Remove the flag the message names, or run the report without `--mcp` |
| `-I/--input: '/path/to/capture.pcap' does not exist`, exit 1 | The path in the client configuration is wrong. A client can start sipnab in a directory of its own choice, so give the capture as an absolute path |
| A tool call answers `tool not found`, with `reason` `unknown_tool` | The server does not register that tool: the name has a spelling error, or the build or the loaded bundles leave the tool out. `valid_values` in the same answer lists the tools the server registers |
| A tool call answers `call_id '<id>' not found`, with `reason` `not_found` | The capture holds no call with that Call-ID. Ask `list_dialogs` for the Call-IDs it holds |
| `MCP HTTP refuses to start: --mcp-bind 192.0.2.1:8731 is non-loopback` and a list of token flags, exit 2 | An HTTP bind on an address other than loopback needs a token or a signing key. Bind `127.0.0.1`, or give one of the flags the message lists, as [MCP deployment](mcp-deploy.md) describes |
| The client lists no sipnab tools, and sipnab works in a shell | Run the client's command by hand, with the arguments of its configuration. A live capture without capture rights stops at startup with a permission message: see [Install sipnab](install.md) |

## Where to go next

| You want to | Page |
|---|---|
| Run it against a remote server, keep a capture alive between sessions, or expose it as a service | [MCP deployment](mcp-deploy.md) |
| Know what a tool returns, field by field | [MCP tool reference](mcp-tools.md) |
| Write a client, or review the security model | [MCP protocol](mcp-protocol.md) |
| Run what an agent does, end to end: triage over [stdio](client-examples.md#triage-a-capture-over-mcp-as-an-agent) or [HTTP with a signed token](client-examples.md#reach-a-production-box-over-http-with-a-signed-token), an [evidence package with repro scripts](client-examples.md#hand-an-agent-an-evidence-package-and-a-repro-script), or an [aggregate cut to a model's budget](client-examples.md#aggregate-dialogs-into-bounded-json-for-a-model) | [Runnable client examples](client-examples.md#ai-tasks) |
