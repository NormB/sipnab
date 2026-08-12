# MCP tools: shutdown, and what else is missing

**Status:** SHIPPED, 2026-07-31 — the same morning this page proposed it. Every
tool proposed here exists, in the order the *Sequencing* section asked for:
`capture_status` and `server_capabilities` (`2951373`, 08:51), then
`explain_response_code`, `compare_dialogs`, `get_sdp_timeline` and
`search_by_time` (`e074834`, 09:31), then `list_captures`, `export_capture`,
`export_audio` and `shutdown_server` (`ebcbf58`, 09:59). `shutdown_server`
landed last and behind `--mcp-allow-shutdown`, in the same commit that made the
save path it depends on real. `open_capture`, the remaining Tier 3 item,
followed in `01bc541` on 2026-08-02.
**Check:** `grep -c '#\[tool(' src/mcp/server.rs` returns 31, where this
document counted eleven.

**The refusals held too, which is the other half of the record.** Running
`grep -cE 'name = "(set_filter|apply_filter|run_command|delete_capture)"' src/mcp/server.rs`
prints `0`: nobody quietly added the tools the *Not proposed* section declined,
so the sequencing this page recommended describes what the surface actually
did.

**Eleven was the right count on 2026-07-31**, so read that number as history
rather than as an error. One of the eleven, `stats`, folded into
`capture_status` in 0.5.92; the surface reached 31 by growing, not by renaming.

**One claim below no longer holds.** *"Every one of the eleven current tools is
a read-only query"* described the surface accurately then. Five tools now carry
`read_only_hint = false` — `export_audio`, `export_capture`, `open_capture`,
`save_findings` and `shutdown_server` — each inert unless an operator arms it.
The argument on this page is why: it asked for the guard, not for the absence
of the tool.

A design page records what its author understood when they wrote it, and here
that was fifteen minutes before the first implementation commit.

Two questions prompted this: *"how do I shut down the remote sipnab from my
laptop?"* and *"what other tools should the MCP server have?"*

## Part 1 — shutting down a remote sipnab

### First: in the most common setup there is nothing to shut down

This depends entirely on which of the three arrangements is running, and for
the one most people use the question dissolves:

| Setup | What is running | How it stops today |
|---|---|---|
| **SSH-launched stdio** | sipnab is a child of your SSH session | **It already exits.** End the agent session and the process is gone |
| Persistent HTTP service | A long-lived service on the server | `systemctl stop sipnab-mcp`, or `ssh server pkill sipnab` |
| Local stdio | A child of your local agent | Ends with the session |

So if you used the SSH recipe, closing Claude Code stops it. `claude mcp remove
sipnab-prod` unregisters it so it does not start again. **No tool is needed for
that case**, and adding one would suggest a lifecycle that does not exist.

The request is only meaningful for the **persistent HTTP** shape — a capture
deliberately outliving the session. That is the case worth designing for.

### Why this is not a routine feature request

Every one of the eleven current tools is a read-only query. That is not an
accident; it is a written invariant:

> **Rule.** No MCP tool mutates a store, and every response hits a size ceiling
> before serialization.
>
> **Why.** An LLM agent drives the MCP surface: it must not be able to change
> what an operator is looking at.

A shutdown tool is strictly more drastic than the mutation that rule forbids.
It lets a language model end a capture that an operator may be depending on,
and in the live case **the packets are gone** — a capture is not replayable.

That is not an argument against building it. It is an argument for building it
so that the failure mode is impossible rather than unlikely: an agent that
misreads "we can stop looking at this now" as an instruction should not be able
to destroy an afternoon of capture.

### The design

Three tools, because "shut down" is really three separate wants:

#### `capture_status` (read-only) — build this regardless

An agent currently **cannot tell what it is connected to**. There is no way to
ask whether this is a live capture or a file replay, how long it has been
running, or how much it holds. That gap is why an agent cannot reason sensibly
about stopping something, and it is worth closing on its own merits.

```
capture_status() -> {
  source: "live" | "file",        // interface name, or path
  device | path, uptime_sec,
  packets, dialogs, streams,
  unsaved: bool                   // live capture with no -O/--write target
}
```

#### `export_capture` (writes a file) — the "save my work" half

The half of the request that is genuinely missing today. Writes the retained
packets to a pcap/pcapng on the server and returns the path.

```
export_capture(path?, format?: "pcap" | "pcapng") -> { path, packets, bytes }
```

Worth having independently of shutdown: right now an agent can *analyse* a live
capture but cannot preserve it, so anything it finds dies with the process.

#### `shutdown_server` (destructive, opt-in, off by default)

```
shutdown_server(save_to?: string, dry_run?: bool = true) -> { ... }
```

Five constraints, each answering a specific way this goes wrong:

1. **Requires `--mcp-allow-shutdown` on the server.** Default off. An operator
   who never asked for a remotely-killable capture cannot get one, and the
   default deployment keeps today's read-only guarantee exactly.
2. **`dry_run` defaults to `true`.** The first call always reports what would
   happen — packets held, whether anything is unsaved — and changes nothing.
   Stopping requires a second, explicit call. This is the
   [planned-effect pattern](https://www.digitalapplied.com/blog/mcp-server-anti-patterns-design-mistakes-2026-developer-guide)
   the MCP community converged on for destructive tools.
3. **Refuses to discard unsaved live data** unless `save_to` is given or the
   caller passes an explicit `discard: true`. Losing a live capture to a
   misread sentence is the failure that matters; making the destructive path
   require naming the destruction is the cheapest guard against it.
4. **Annotated `destructiveHint: true`, `readOnlyHint: false`.** MCP clients
   use these to decide what needs human confirmation. Without them a client
   [treats every tool the same](https://kansei-link.com/en/insights/mcp-tool-schema-design-guide-2026.html).
5. **Logs who, what and when** at `warn`, so a stopped capture is explicable
   afterwards rather than a mystery.

### Recommendation

Build `capture_status` and `export_capture` first. They are read-only or
additive, useful on their own, and they turn out to be most of what the
original request actually wanted — *save the work, then stop it*. `shutdown_server`
is then a small, well-guarded addition rather than the whole feature.

## Part 2 — other tools worth adding

The current eleven are all queries over dialogs, streams and security findings.
The gaps cluster in three places.

### Tier 1 — the agent cannot see its own context

| Tool | Why |
|---|---|
| `capture_status` | As above. An agent cannot currently tell live from file, or how much it holds |
| `server_capabilities` | Which features are compiled in (`tls`, `hep`, `mcp-http`, `plugins`). An agent asking for decryption on a build without `tls` gets a confusing failure instead of a clear one |

These are the highest-value additions because they are about the agent knowing
what it is holding, and every wrong answer downstream traces back to not
knowing.

### Tier 2 — analysis sipnab can already do but does not expose

| Tool | Why |
|---|---|
| `explain_response_code` | sipnab already carries the full IANA table with RFC-sourced descriptions. An agent explaining `488` currently guesses from training data; this makes it cite the registry |
| `compare_dialogs` | "Why did this call work and that one not?" is the most common real question, and it is currently two calls plus manual diffing |
| `export_audio` | WAV export exists in the TUI and CLI; an agent cannot reach it |
| `get_sdp_timeline` | Codec/ptime negotiation over the life of a call — already computed, not exposed |

### Tier 3 — plausible, lower value

| Tool | Note |
|---|---|
| `list_captures` | Browse pcaps on the server. Useful for post-mortems; needs a path allowlist or it is an arbitrary-file-read |
| `open_capture` | Switch the active file mid-session. Mutates state — needs the same opt-in treatment as shutdown |
| `search_by_time` | Window queries. Mostly reachable through the filter DSL today |

### Not proposed, and why

- **`set_filter` / `apply_filter`** — mutates what the operator is looking at,
  which is exactly the invariant's target, and buys nothing: filters are
  already arguments to the query tools.
- **`run_command` / arbitrary CLI passthrough** — an obvious "flexibility" win
  and a straight sandbox escape. The MCP surface is deliberately a fixed set of
  verbs.
- **`delete_capture`** — destroys evidence, and no workflow needs it from an
  agent.

## Sequencing

1. `capture_status`, `server_capabilities` — read-only, unblock the agent's
   self-awareness.
2. `export_capture` — the "save my work" half of the shutdown request.
3. `explain_response_code`, `compare_dialogs` — expose analysis that exists.
4. `shutdown_server` — last, behind `--mcp-allow-shutdown`, once the save path
   it depends on is real.
