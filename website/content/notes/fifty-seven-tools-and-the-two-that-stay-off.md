+++
title = "Fifty-seven tools, and the two that stay off"
date = 2026-09-01
description = "The MCP surface an agent sees: what the full and core profiles register, why every answer carries how much of the capture it rests on, and why the two opt-in flags are opt-in — one of them makes sipnab transmit."

[extra]
kind = "feature"
+++

An agent that reads a capture through a shell has to parse text somebody wrote
for a person. sipnab's MCP server hands it structured answers instead: 57
tools, each returning JSON with a stated ceiling, over stdio or HTTP.

The surface sits behind the `mcp` Cargo feature, which the `full` feature
carries and the default build does not. The HTTP transport needs `mcp-http` on
top of it. `sipnab --version` prints what a binary holds, and the
`server_capabilities` tool answers the same question from inside a session.

## What a session gets

Start one against a capture file and point a client at it:

```bash
sipnab -N --mcp -I capture.pcap --mcp-file-root /var/spool/sipnab-captures
```

The 57 tools group by the question they answer — survey the capture, narrow to
the calls that matter, diagnose one call, check conformance, follow evidence
back to bytes, export. [The tool reference](@/docs/mcp-tools.md) is the
per-tool page. Three rules matter more than any individual entry.

**Every answer says how much of the capture is behind it.** Two booleans ride
on every response object: `source_exhausted`, true once sipnab has read the
source to its end, and `source_stopped_early`, true when a read ended before
the source did. A file source loads on a background thread, so an agent's first
call lands inside a window a human client never sees — on a 921 MB capture,
`list_dialogs` answered with 6 of 18,241 dialogs. The rendered documents
(`render_ladder`, and the Markdown and text arms of the report tools) have no
envelope to put a field in, so they end with the `INCOMPLETE RUN` block
`--report` appends.

**Absence and `false` are different values.** Until sipnab has read the source
to its end, a response omits `truncated: false` rather than sending it. That
value claims outright that the page holds every match, and a caller reading
only that field deserves no claim rather than a wrong one. `truncated: true`
still appears whenever the row cap really did keep matches out.

**Capture text arrives fenced.** Free text an endpoint wrote — display names,
`User-Agent`, SDP, whole messages — comes wrapped in
`⟦untrusted-capture-data⟧` markers, and identifiers such as Call-IDs, cursors
and addresses stay verbatim so they pass straight into the next call.

## The core profile, and what it costs to leave it off

`--mcp-tools` takes `core` or `full`, and `full` is the default:

```bash
sipnab -N --mcp -I capture.pcap --mcp-tools core
```

That registers eight tools — `capture_status`, `list_dialogs`, `get_dialog`,
`triage_call`, `rtp_stats`, `find_problems`, `aggregate_dialogs`,
`search_messages` — and nothing else.

The reason is a cost nobody meters. Every registered tool's name, description
and JSON schema goes to the client on `tools/list` and then rides in the
model's context for the whole session, before the agent has asked anything. At
fifty schemas that block is already the largest single thing the server says.

`core` is not a favorites list. It is the smallest set that still answers the
question an operator arrives with — *what happened on this call, and was it
signaling or media* — end to end, without the agent hitting a missing step and
improvising around it. Each member earns its place by being unreachable from
the others: drop `aggregate_dialogs` and a "how many, by what" question pages
the whole store through the model, which spends context rather than saving it.

`full` stays the default because shrinking the surface silently would change
what every existing client can do at upgrade time. And a `core` server removes
the dropped tools from the router rather than hiding them, so a call to one of
them comes back as an unknown tool rather than as a refusal an agent might
retry.

## The refusals, and why they are flags

Five capabilities stay off until an operator turns them on:
`--mcp-allow-shutdown`, `--mcp-allow-open-capture`, `--mcp-allow-relay-query`,
`--mcp-allow-tls-capture` and `--mcp-allow-save-findings`. All five tools still
appear in `tools/list` without them, because "not permitted here" and "this
build cannot" are different answers and an agent deserves to tell them apart.

Two of the five carry an argument worth reading.

**`--mcp-allow-relay-query` gates the only tool that transmits.** Every other
tool on the surface answers from bytes sipnab already holds. `query_relay` puts
a packet on the network, and it exists because a passive decoder has a real
gap: a call already in progress when sipnab started has no control exchange
left to read, which is exactly the state incident response begins in.

The tool needs three things and names whichever one is missing — the opt-in,
a relay address from `--rtpengine-control`, and a live source. A run reading a
capture file can obtain no transmit permit at all, so an analyst opening a
capture from another organization cannot make sipnab talk to the addresses
inside it.

**There is no address parameter, and that is the design.** The destination
comes from operator configuration and from nowhere else. A tool argument naming
the destination would turn this surface into a way to make sipnab send packets
to a host the caller chose, and an address sipnab could otherwise infer is one
it learned from packets — a host that served as a relay during the capture, and
may be somebody's laptop now.

**`--mcp-allow-open-capture` gates the one destructive read.** `open_capture`
replaces every dialog and stream the server holds with another capture from
`--mcp-file-root`. It refuses while the source is live or still filling the
stores, loads in the background, and mints a new capture identity that every
later answer carries, so the replacement cannot reach a consumer as an ordinary
update. Use it on a long-lived HTTP server working through a corpus, where a
restart costs an operator their session. In stdio, starting sipnab again with a
different `-I` does the same job and leaves a clean store behind.

## Telling it works

Ask `server_capabilities` first. `features` comes from `cfg!` at compile time,
so it cannot claim a feature the binary lacks, and `runtime` reports what the
operator turned on — a question no compile-time check can answer. Without it an
agent discovers the setup by calling a tool and collecting a refusal, and a
refusal mid-investigation reads as a dead end rather than as a server it was
never allowed to use that way.
