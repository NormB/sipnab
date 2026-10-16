+++
title = "Check which features and MCP tools a sipnab build has"
date = 2026-09-01
updated = 2026-10-16
description = "How to list the optional features a sipnab binary contains, and how that list decides which MCP tools the binary offers to an AI agent."

[extra]
kind = "feature"
+++

## In short

A sipnab binary may include or leave out optional parts, called features.

- `sipnab --version`, the MCP tool `server_capabilities` and the REST endpoint
  `GET /v1/capabilities` each list the features a binary contains. The three
  lists come from the same source, so they agree.
- sipnab's MCP server offers only the tools the binary can run. A build
  without the `vcon` feature does not offer `export_vcon` or `validate_vcon`.
- A build without a feature refuses the command-line flags that need it, and
  the message names the feature.

This holds from sipnab 0.5.142.

## Who this is for

- Anyone who runs sipnab as an MCP server for an AI agent, especially from a
  build with a reduced feature set.
- Anyone who needs to know which features a given sipnab binary has.

## What it does

An MCP client is the AI agent's side of the connection. It asks a server for
its tools with a `tools/list` request. The answer is the whole of what the
agent knows about what the server can do.

- **Tools follow the build.**
  - sipnab registers `export_vcon` and `validate_vcon` only when the binary
    includes the `vcon` feature.
  - A build without it leaves both out of `tools/list`. A call to either one
    gets the MCP error `tool not found`.
- **Every surface names the same features.**
  - `--version` prints them in build order.
  - `server_capabilities` returns them, in alphabetical order, in its
    `features` field.
  - `GET /v1/capabilities` on the REST API serves the same list.

## Check the features of a binary

Run:

```bash
sipnab --version
```

```text
sipnab 0.5.222 (16f7b0ea) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,wasm,plugins,bpf,vcon,opus,archive,g729
libpcap version 1.10.4 (with TPACKET_V3); alternate capture backends named: none
```

## Check the features over MCP

This command runs from the root of a sipnab checkout. It sends the MCP
handshake and one `server_capabilities` call on standard input, and uses `jq`
to print the `features` field:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"server_capabilities","arguments":{}}}' | sipnab --mcp -N --quiet -I tests/pcap-samples/sip-488-codec-reject.pcapng 2>/dev/null | jq -c 'select(.id==2) | .result.structuredContent.features'
```

```text
["api","archive","audio","bpf","g729","hep","mcp","mcp-http","metrics","native","opus","plugins","tls","tui","vcon","wasm"]
```

`vcon` is in the list, so `tools/list` on this binary includes the two vCon
tools:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | sipnab --mcp -N --quiet -I tests/pcap-samples/sip-488-codec-reject.pcapng 2>/dev/null | jq -r 'select(.id==2) | .result.tools[].name | select(. == "export_vcon" or . == "validate_vcon")'
```

```text
export_vcon
validate_vcon
```

On a build without `vcon`, the same command prints nothing.

## Read the refusal from a build without a feature

A build made with the default features has no `vcon`, `mcp`, `hep`, `tls` or
`api`. Its `--version` line reads:

```text
sipnab 0.5.222 (16f7b0ea) features: native,tui,audio,metrics
```

On that build, a vCon export flag stops the run with exit status 2:

```bash
sipnab -N -q -I tests/pcap-samples/sip-488-codec-reject.pcapng --export-vcon-when "response_code == 488" --export-vcon-dir vcons --no-cli-print
```

```text
2026-10-16T11:48:08.362440Z ERROR sipnab: --export-vcon-when, --export-vcon-dir need the 'vcon' Cargo feature, which this build does not carry. Rebuild with --features vcon (or --features full); `sipnab --version` lists the features a binary was built with
```

`--mcp` on the same build stops with:

```text
2026-10-16T11:49:14.538075Z ERROR sipnab::app::bootstrap: --mcp requires the 'mcp' feature (not compiled in)
```

To get the feature, install a build that carries it, or build sipnab with
`--features full`. The [Feature flags](@/docs/build.md#feature-flags) table
lists what each feature adds.

## Limits

- Build features and the `--mcp-tools` option are separate.
  - `--mcp-tools` selects which registered tools the server offers. An example
    is only the `vcon` bundle.
  - It does not change which features the binary contains, and it cannot add
    a tool whose feature the build lacks.
- Before sipnab 0.5.142, a build without `vcon` listed `export_vcon` and
  `validate_vcon` and refused every call to them, and `server_capabilities`
  did not name `vcon`, `bpf` or `wasm`. Upgrade to get an accurate list.

## Terms used here

- **MCP**: Model Context Protocol, the interface sipnab offers to AI agents.
- **Tool**: one operation an MCP server offers, such as `export_vcon`.
- **`tools/list`**: the MCP request a client sends to learn which tools a
  server offers.
- **Feature**: an optional part of sipnab that a build includes or leaves out.
- **Build**: one compiled sipnab binary with a particular set of features.
- **vCon**: a standard JSON format for a record of a conversation.
- **Exit status**: the number a program returns when it ends. 0 means success.
- **jq**: a command-line program that reads JSON and prints selected fields.

## Related guides

- [`server_capabilities`](@/docs/mcp-tools-server.md#server-capabilities)
- [Choosing which tools load](@/docs/mcp-tools.md#choosing-which-tools-load)
- [`export_vcon`](@/docs/mcp-tools-vcon.md#export-vcon) and [`validate_vcon`](@/docs/mcp-tools-vcon.md#validate-vcon)
- [REST API: `GET /v1/capabilities`](@/docs/api.md#get-v1-capabilities)
- [Feature flags](@/docs/build.md#feature-flags)
