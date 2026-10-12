+++
title = "Choose which actions an AI agent may take through sipnab's MCP server"
date = 2026-09-01
updated = 2026-10-11
description = "Which sipnab flags let an AI agent change state, write files, transmit or act on another system, which tools each flag unlocks, and how to keep a record of every call the agent makes."

[extra]
kind = "howto"
+++

## In short

sipnab can serve a capture to an AI agent (a program driven by a language
model) so the agent can ask questions about the calls in it. By default the
agent can only read: every tool that would stop the server, write a file, load
a different capture, read encrypted traffic, contact a media relay or ban an
address refuses and names the setting that would allow it. This page lists
those settings, the tools each one unlocks, and how to keep a file that
records every request the agent makes.

## Who this is for

Operators who start `sipnab --mcp` for an agent and need to decide which
actions to allow. For choosing which tools the agent sees at all, read
[MCP tool bundles: choose which tools sipnab's MCP server loads](@/notes/fifty-seven-tools-and-the-two-that-stay-off.md).

## Before you start

The commands below run from the root of a sipnab checkout, which holds the
sample captures, and need `jq` to pick one field out of the JSON reply. Each
one starts sipnab as an MCP server over stdio (standard input and output),
sends it three JSON-RPC messages (an MCP client's opening handshake and one
request), and prints the answer. `2>/dev/null` hides sipnab's log lines.

## Steps

1. Start a server with no opt-in flags and ask it to stop itself:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shutdown_server","arguments":{}}}' | sipnab --mcp -N --quiet -I tests/pcap-samples/sip-proxy.pcap 2>/dev/null | jq -r 'select(.id==2) | .error.message'
   ```

   ```text
   shutdown is disabled: start sipnab with --mcp-allow-shutdown to permit it. A stock server cannot be stopped by an agent.
   ```

   The server lists the tool, and refuses the call with a message that names
   the flag. Every gated tool behaves the same way, so an agent can tell the
   operator which flag a task needs.

2. List the tools that are not read-only. sipnab marks each tool with the MCP
   `readOnlyHint` annotation; these are the tools marked `false`:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | sipnab --mcp -N --quiet -I tests/pcap-samples/sip-proxy.pcap 2>/dev/null | jq -r 'select(.id==2) | .result.tools[] | select(.annotations.readOnlyHint == false) | .name'
   ```

   ```text
   actions_revert
   build_evidence_package
   compare_captures
   export_audio
   export_capture
   generate_repro
   open_capture
   save_findings
   shutdown_server
   start_tls_capture
   stop_tls_capture
   tfps_ban
   tfps_unban
   ```

3. List the tools that contact another system. These carry the
   `openWorldHint` annotation set to `true`:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | sipnab --mcp -N --quiet -I tests/pcap-samples/sip-proxy.pcap 2>/dev/null | jq -r 'select(.id==2) | .result.tools[] | select(.annotations.openWorldHint == true) | .name'
   ```

   ```text
   actions_revert
   query_relay
   relay_compare
   relay_stats
   tfps_ban
   tfps_unban
   ```

   `query_relay`, `relay_stats` and `relay_compare` carry `readOnlyHint: true`
   because they change nothing, but they send packets to a media relay.

4. Decide which flags the job needs, using the table below. Each row was
   checked by calling the tools on a server started without the flag; every
   one refused and named the flag.

   | Flag | Tools it unlocks | What the agent can then do |
   |---|---|---|
   | `--mcp-file-root <DIR>` | `list_captures`, `export_capture`, `export_audio`, `build_evidence_package`, `compare_captures`, and `generate_repro` when the call names a file | Read and write files in that one directory. The tools accept a bare file name and refuse a name containing `/`, `\` or `..`. |
   | `--retain-audio` | none on its own; `export_audio` needs it to have audio to decode | Decode call audio to a WAV file. Without it, `export_audio` refuses and says the run kept no audio payload. |
   | `--mcp-allow-save-findings` | `save_findings` | Write a conclusion to sipnab's log. No tool reads a finding back. `--mcp-max-findings` sets how many sipnab accepts (default 1000). Past that, sipnab refuses the write. |
   | `--mcp-allow-open-capture` | `open_capture` | Replace the loaded capture with another file from `--mcp-file-root`. It refuses while the source is a live interface or while sipnab is still reading it. |
   | `--mcp-allow-relay-query` | `query_relay`, `relay_stats`, `relay_compare` | Send control queries to the relay that `--rtpengine-control` names. The tools also need that flag and a live source; on a run reading a file they refuse. The agent cannot choose the destination. |
   | `--mcp-allow-tls-capture` | `start_tls_capture` | Attach kernel probes to a running process's TLS library and read the decrypted traffic. The server must still be running as root. `stop_tls_capture` answers without the flag and stops nothing unless a capture is running. |
   | `--mcp-allow-shutdown` | `shutdown_server` | Stop the server. The tool defaults to a dry run, and refuses to discard an unsaved live capture unless the call sets `discard_unsaved`. |
   | `--allow-action tfps:mcp` | `tfps_ban`, `tfps_unban`, `actions_revert` | Ask TFPS (a separate toll-fraud prevention program) to ban or release a source address. sipnab records each action in its actions journal first and refuses to start if it cannot use `--journal-dir`. Over HTTP the client also needs a token with the `actions` scope. |

   A server started with `--mcp -N --quiet -I <file>` and none of these flags
   reads the one capture on its command line and does nothing else.

5. Start the server with the one flag the job needs, and with
   `--mcp-audit-file` so sipnab records every tool call. This example allows
   `save_findings` and records a finding:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"save_findings","arguments":{"summary":"Call proxied-call-synth@192.0.2.101 completed normally."}}}' | sipnab --mcp -N --quiet -I tests/pcap-samples/sip-proxy.pcap --mcp-allow-save-findings --mcp-audit-file mcp-audit.jsonl 2>/dev/null | jq -c 'select(.id==2) | .result.structuredContent | {delivered_to, readable_over_mcp, recorded_total, remaining}'
   ```

   ```text
   {"delivered_to":"sipnab log (tracing/journald/stderr)","readable_over_mcp":false,"recorded_total":1,"remaining":999}
   ```

6. Read the audit file. It holds one JSON line per tool call, with the
   arguments, the outcome and a sequence number:

   ```bash
   cat mcp-audit.jsonl
   ```

   ```text
   {"args":"{\"summary\":\"Call proxied-call-synth@192.0.2.101 completed normally.\"}","caller":"stdio","elapsed_ms":0,"error":null,"id":"2","outcome":"ok","seq":1,"tool":"save_findings","ts":"2026-10-12T00:52:40.594048333+00:00"}
   ```

   `ts` is the time of the call, so it differs on every run.

7. Check the file's permissions. sipnab creates it readable and writable by
   its owner only, because it holds tool arguments:

   ```bash
   stat -c '%a' mcp-audit.jsonl
   ```

   ```text
   600
   ```

   sipnab appends to the file and never truncates it. If a record cannot be
   written, sipnab refuses the tool call instead of answering it unrecorded.

## Terms used here

- **AI agent**: a program, driven by a language model, that decides which
  tools to call and in what order.
- **MCP**: Model Context Protocol, the protocol an agent uses to list and call
  the tools a server offers.
- **JSON-RPC**: the request and reply format MCP messages use.
- **stdio**: standard input and output; in stdio mode the agent's client
  starts sipnab and talks to it through these streams.
- **Tool annotation**: a hint the server attaches to each tool, such as
  `readOnlyHint` (the tool changes nothing) or `openWorldHint` (the tool
  reaches a system outside the server).
- **Capture**: a recording of network packets, here a pcap file.
- **Media relay**: a server, such as rtpengine, that carries a call's audio
  between the two parties.
- **TLS**: the encryption used for SIP over TLS and HTTPS.
- **Kernel probe (uprobe)**: a hook the Linux kernel places in a running
  program so another program can read data as it passes.
- **TFPS**: a separate toll-fraud prevention program that bans source
  addresses in the firewall; sipnab can ask it to act.
- **Audit file**: the file `--mcp-audit-file` names, holding one record per
  tool call.

## Related guides

- [Security implications](@/docs/mcp-deploy.md#security-implications) in the
  MCP deployment guide.
- [File tools — the shared rule](@/docs/mcp-tools.md#file-tools-the-shared-rule)
  and [Find a tool by name](@/docs/mcp-tools.md#find-a-tool-by-name), which
  marks every tool that writes, transmits or is off by default, in the MCP
  tool reference.
- [`tfps_ban`](@/docs/mcp-tools-tfps.md#tfps-ban) in the MCP tool reference.
- [MCP server](@/docs/cli.md#mcp-server) and [Security](@/docs/cli.md#security)
  in the command-line reference, for every flag on this page.
- [Choosing which tools load](@/docs/mcp-tools.md#choosing-which-tools-load),
  for limiting the tool list itself.
