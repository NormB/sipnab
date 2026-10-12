+++
title = "MCP tool bundles: choose which tools sipnab's MCP server loads"
date = 2026-09-01
updated = 2026-10-11
description = "How --mcp-tools limits the tools sipnab's MCP server offers to an AI agent, what each bundle costs the agent's context, and which tools refuse until the operator enables them."

[extra]
kind = "feature"
+++

## In short

sipnab can run as an MCP server: a program an AI agent connects to and calls
named tools on, such as "list the calls in this capture". Each tool the server
offers adds its description to the text the agent's model reads before every
answer, so sipnab lets the operator offer fewer tools, grouped into named
bundles. Separately from that choice, the tools that stop the server, change
which capture it holds, send packets, read or write files, record findings,
read encrypted traffic or change another system
stay switched off until the operator turns each one on.

## Who this is for

Anyone connecting an AI agent to sipnab's MCP server who wants to give it only
the tools it needs, or needs to know which tools refuse by default.

## What it does

On connecting, an agent asks the server for its tool list (the MCP request
`tools/list`). The answer carries each tool's name, description and input
schema (the description of the arguments it takes), and the agent's client
keeps all of it in the model's context (the text the model reads before every
answer) for the whole session.

`--mcp-tools` decides which tools the server registers, and so what that list
holds. It takes a comma-separated list of:

- **bundles**: `core`, `signaling`, `captures`, `security`, `media`, `relay`,
  `tfps`, `server`, `vcon`, `tls`. Every tool is in exactly one bundle.
- **single tool names**, to add one tool without its whole bundle.
- **your own bundles**, defined under `[mcp.bundles]` in the config file.
- **`full`**, every tool the build carries. This is the default.

A tool that is not registered does not exist for that session: a call to it
gets the MCP error `tool not found`, not a refusal.

The MCP server needs the `mcp` Cargo feature (a compile-time option), which the
`full` build carries and the default build does not. `sipnab --version` lists the
features compiled into a binary. A build without a feature does not register
that feature's tools, so its bundles are smaller.

## How to turn it on

Every example below runs from the root of the sipnab repository against a
capture in it. Each one sends the server MCP requests on its standard input
and uses `jq` (a command-line JSON processor) to print one field of the reply.

1. Start the server with only the `core` bundle and list what it registers:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | sipnab -N --quiet -I tests/pcap-samples/sip-488-codec-reject.pcapng --mcp --mcp-tools core | jq -r 'select(.id==2) | .result.tools[].name'
```

```text
aggregate_dialogs
capture_status
find_problems
get_capture_report
get_dialog
list_dialogs
rtp_stats
search_messages
triage_call
```

The same command with `--mcp-tools full`, or with no `--mcp-tools`, lists 72
tools on sipnab 0.5.211 built with every feature.

2. Combine bundles and single tools. The server's handshake reply (to the MCP
   `initialize` request) ends by naming what it loaded and which bundles it
   left out, so an agent that misses a tool can tell the operator which bundle
   holds it:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' | sipnab -N --quiet -I tests/pcap-samples/sip-488-codec-reject.pcapng --mcp --mcp-tools core,relay,get_sdp_timeline | jq -r '.result.instructions'
```

```text
sipnab MCP server — queries captured SIP dialogs, RTP streams, diagnostics and security findings. No tool edits a capture's contents. `open_capture` can change WHICH capture is loaded and stays off unless enabled server-side; every response carries `capture_identity`, so a swap is visible rather than silent. File exports write only under the configured file root, and stopping the server requires an explicit server-side opt-in. This server changes no external system: the tools that would (tfps_ban, tfps_unban) refuse unless the operator enables them with --allow-action. Tools loaded: core, relay, get_sdp_timeline. Other bundles, which the operator can add with --mcp-tools or [mcp] tools: signaling, captures, security, media, tfps, server, vcon, tls.
```

3. A name sipnab does not know stops the run with exit status 2 and lists the
   valid bundles. Names are case-sensitive:

```sh
sipnab -N --quiet -I tests/pcap-samples/sip-488-codec-reject.pcapng --mcp --mcp-tools core,ladder
```

```text
2026-10-12T00:41:51.376191Z ERROR sipnab::app::bootstrap: --mcp-tools: unknown tool or bundle 'ladder'; bundles: core, signaling, captures, security, media, relay, tfps, server, vcon, tls, or full; tool names are listed in the MCP tool reference
```

4. To set the list once, put it in the config file (`-f`/`--config`). This
   example defines a bundle named `voice` and loads it beside `core`; with it,
   the handshake reply printed `Tools loaded: core, voice.`

```toml
[mcp]
tools = ["core", "voice"]

[mcp.bundles]
voice = ["media", "get_sdp_timeline", "check_codec_negotiation"]
```

`--mcp-tools` on the command line replaces `[mcp] tools`.

## What a bundle costs

The size of the `tools/list` answer is what the client keeps in context. This
command prints it in bytes for `core`, as the sum of each tool entry's compact
JSON:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | sipnab -N --quiet -I tests/pcap-samples/sip-488-codec-reject.pcapng --mcp --mcp-tools core | jq -r 'select(.id==2) | [.result.tools[] | tojson | utf8bytelength] | add'
```

```text
10981
```

The same command, run on sipnab 0.5.211 built with every feature, measured:

| `--mcp-tools` | Tools | Bytes | Bytes with `--mcp-output-schemas` |
|---|---|---|---|
| `core` | 9 | 10,981 | 30,909 |
| `full` | 72 | 80,612 | 198,008 |

Output schemas (a declared shape for each tool's answer) are optional in MCP
and off by default. Responses carry the same JSON with or without them. Turn
them on with `--mcp-output-schemas` only for a client that checks answers
against a declared shape. The per-bundle table in the tool reference comes
from a measurement on an earlier release. Sizes change as tools change.

## Tools that refuse until the operator enables them

Registering a tool does not permit it. With the default `full` list, the tools
below appear in `tools/list` but answer each call with an error that names the
flag they need. Leaving a tool out with `--mcp-tools` removes it. It does not
replace the flag.

| Tools | Enabled by |
|---|---|
| `shutdown_server` | `--mcp-allow-shutdown` |
| `open_capture` | `--mcp-allow-open-capture` |
| `query_relay`, `relay_stats`, `relay_compare` | `--mcp-allow-relay-query`, plus a relay address from `--rtpengine-control` and a live source (these tools send packets to the relay; a run reading a capture file cannot use them) |
| `start_tls_capture` | `--mcp-allow-tls-capture` |
| `save_findings` | `--mcp-allow-save-findings` |
| `tfps_ban`, `tfps_unban`, `actions_revert` | `--allow-action tfps:mcp` |
| `list_captures`, `export_capture`, `export_audio`, `compare_captures`, `build_evidence_package` | `--mcp-file-root <DIR>` |

What each of these flags allows, and which to turn on for an agent, is the
subject of
[What to switch on when an agent drives sipnab](@/notes/what-to-allow-when-an-agent-drives-sipnab.md).

## Limits

- The counts and byte sizes above hold for sipnab 0.5.211 with every feature.
  Another release or a build with fewer features gives other numbers.
- A custom bundle cannot reuse a built-in bundle or tool name, cannot be empty,
  and cannot hold `full` or another custom bundle. sipnab refuses to start when
  one breaks a rule, even if nothing uses it.
- `core` does not include `server_capabilities`, the tool that reports a
  binary's features and settings. Add it by name if the agent needs it.

## Terms used here

- **MCP (Model Context Protocol)**: a standard way for an AI agent to discover
  and call tools that a program offers.
- **Agent**: an AI model that calls tools on its own to answer a question.
- **Tool**: one named operation the MCP server offers, with declared arguments.
- **Bundle**: a named group of tools that `--mcp-tools` accepts as one entry.
- **Context**: the text a model reads before each answer; the tool list sits
  in it for the whole session.
- **Schema**: a machine-readable description of a tool's arguments or of the
  shape of its answer.
- **JSON-RPC**: the request-and-reply message format MCP uses.
- **Capture**: a recorded file of network packets, here a pcapng file.
- **Cargo feature**: an option chosen at sipnab's compile time. A feature left
  out removes its code from the binary.
- **Live source**: a network interface or listener sipnab is reading now, as
  opposed to a capture file.
- **jq**: a command-line program that reads JSON and prints selected fields.

## Related guides

- [Choosing which tools load](@/docs/mcp-tools.md#choosing-which-tools-load):
  the bundle table with every tool in each bundle.
- [Rules every tool follows](@/docs/mcp-tools.md#rules-every-tool-follows):
  row limits, paging and how answers mark capture text.
- [File tools — the shared rule](@/docs/mcp-tools.md#file-tools-the-shared-rule):
  what `--mcp-file-root` allows.
- [The `[mcp]` config section](@/docs/config.md#mcp): `tools`,
  `output_schemas` and `[mcp.bundles]`.
- [See it work](@/docs/mcp.md#see-it-work) and
  [Add it to your client](@/docs/mcp.md#add-it-to-your-client): starting the
  server and connecting a client.
- [Security model](@/docs/mcp-protocol.md#security-model): why the opt-in tools
  are off by default.
