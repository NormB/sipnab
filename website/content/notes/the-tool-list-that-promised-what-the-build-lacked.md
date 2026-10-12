+++
title = "MCP tool list and capability report match the features a build has"
date = 2026-09-01
updated = 2026-10-11
description = "Since 0.5.142, an MCP client sees only the tools a sipnab build can run, and the capability report names every optional feature the build contains. This note shows how to check both."

[extra]
kind = "feature"
+++

## In short

A sipnab binary may include or leave out optional parts, called features. One of
them, `vcon`, provides the tools that export and check call records in the
vCon format. Before version 0.5.142, a sipnab binary without `vcon` still
offered those two tools to AI agents and then refused every request to use
them. Since 0.5.142, such a build does not offer them at all, and sipnab's
capability report names every optional feature the build contains, so an
agent or an operator can see why a tool is absent.

## Who this is for

Anyone who runs sipnab as an MCP server for an AI agent, especially from a
build with a reduced feature set, and anyone who needs to know which features
a given sipnab binary has.

## What it does

An MCP client (the AI agent's side of the connection) asks a server for its
tools with a `tools/list` request. The answer is the whole of what the agent
knows about what the server can do. Since 0.5.142:

- **Tools follow the build.** sipnab registers `export_vcon` and
  `validate_vcon` only when the binary includes the `vcon` feature. A build
  without it leaves both out of `tools/list`.
- **`server_capabilities` names every feature.** The MCP tool
  `server_capabilities` returns a `features` list read from the same function
  that produces the `--version` line and the REST `GET /v1/capabilities`
  answer, so all three agree. Before 0.5.142 that list could name only ten
  features and never named `vcon`, `bpf` or `wasm`.

### What users saw before 0.5.142

A build with the features `native,hep,api,mcp,mcp-http` (one of the reduced
feature sets sipnab's CI builds) listed `export_vcon` and `validate_vcon` in
`tools/list`, with their input and output schemas. It refused every call to
either tool with this message:

```text
this sipnab was built without the 'vcon' Cargo feature, so it has no vCon exporter. Rebuild with --features vcon (or --features full); server_capabilities lists what this binary carries
```

The message pointed to `server_capabilities`, but that report did not name
`vcon` in any build, so it could not confirm whether the feature was present.

The cause was that two different places in the code decided the list of
tools and the code behind them. Every build assembled the same tool list, and
only the code that would do the work changed with the feature. Now the tool
definitions themselves exist only in a build with the feature, so a build that
lists the tools without being able to run them no longer compiles.

## How to check a build

It needs no setting. To see which features a binary contains, run:

```bash
sipnab --version
```

```text
sipnab 0.5.211 (15e5e7bd) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,plugins,vcon,archive
libpcap version 1.10.4 (with TPACKET_V3); alternate capture backends named: none
```

An agent connected over MCP gets the same list, in alphabetical order, from
`server_capabilities`, and the REST API serves it on `GET /v1/capabilities`.
On the binary above, the `features` field of the `server_capabilities` answer
was:

```text
"features":["api","archive","audio","hep","mcp","mcp-http","metrics","native","plugins","tls","tui","vcon"]
```

When `vcon` is in that list, `tools/list` includes `export_vcon` and
`validate_vcon`. When it is not, the server offers neither tool.

## Limits

- Build features and the `--mcp-tools` option are separate. `--mcp-tools`
  selects which registered tools the server offers (for example only the
  `vcon` bundle). It does not change which features the binary contains.
- The tests that hold this rule in place,
  `tests/mcp_capability_agreement_test.rs`, require that every tool module
  tied to a feature registers all of its tools or none of them, and that
  `server_capabilities` can name every feature that `Cargo.toml` declares.

## Terms used here

- **MCP**: Model Context Protocol, the interface sipnab offers to AI agents.
- **Tool**: one operation an MCP server offers, such as `export_vcon`.
- **`tools/list`**: the MCP request a client sends to learn which tools a
  server offers.
- **Feature**: an optional part of sipnab that a build includes or leaves out.
- **Build**: one compiled sipnab binary with a particular set of features.
- **vCon**: a standard JSON format for a record of a conversation.
- **CI**: continuous integration, the automated jobs that build and test
  sipnab, including builds with reduced feature sets.

## Related guides

- [`server_capabilities`](@/docs/mcp-tools-server.md#server-capabilities)
- [Choosing which tools load](@/docs/mcp-tools.md#choosing-which-tools-load)
- [`export_vcon`](@/docs/mcp-tools-vcon.md#export-vcon) and [`validate_vcon`](@/docs/mcp-tools-vcon.md#validate-vcon)
- [REST API: `GET /v1/capabilities`](@/docs/api.md#get-v1-capabilities)
- [Feature flags](@/docs/build.md#feature-flags)
