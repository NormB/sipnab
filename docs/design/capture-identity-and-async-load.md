# Capture identity, and a load that does not block the server

**Status:** built 2026-08-02, shipped with the `open_capture` MCP tool.
Verified against `main` at 70b95f9.

Two primitives landed together with `open_capture`, and both were written to be
reused rather than to serve that one tool.
[`deferred-and-declined.md` §4](deferred-and-declined.md) named them as build
requirements; this page is the part a future consumer needs — what they are,
what they promise, and where the edges are.

| Primitive | Lives in | Answers |
|---|---|---|
| Capture identity + store etag | [`src/provenance.rs`](../../src/provenance.rs) | "Is this the same capture I was reading, and has it changed?" |
| Background capture load | [`src/mcp/load.rs`](../../src/mcp/load.rs) | "Can a multi-gigabyte read happen without stopping every other client?" |

---

## 1. The identity primitive

### What was missing

`DialogStore::generation` ([`dialog_store.rs`](../../src/sip/dialog_store.rs))
is bumped by every mutating method, and so is `StreamStore::generation`. Neither
reached any wire: not `DialogSummary`, not a REST response, not an MCP payload.
A `/v1/dialogs` poller could therefore watch a dialog set change completely
between two requests with nothing to say the second answer described a different
file.

A generation counter alone cannot close that, and the reason is worth stating
because it is the whole design. Clearing a store bumps the counter, and the new
capture then counts up from wherever the old one stopped. Two captures can sit
at the same number, and one capture's number can look like another's. The
counter answers *how many times this store changed*; it cannot answer *which
capture this is*.

### The shape

```rust
CaptureIdentity { instance: String }          // rotates on every swap
CaptureEtag { instance, dialog_generation, stream_generation }
```

An instance id is `<process id><start nanos>-<n>`, hex, minted from a
process-wide counter. The only promise it carries: **two answers with the same
instance describe the same loaded capture, and two with different instances do
not.** It is not a content hash, not a UUID, and nothing may infer file identity
from it. The process prefix exists so a poller reconnecting to a *restarted*
server sees a different instance rather than the `-1` it held before.

`CaptureEtag` has a one-token string form — `<instance>:<dialogs>.<streams>` —
with `Display` and `FromStr` on both sides of it, so a consumer with a single
header or a single string field can carry the whole identity. The MCP surface
sends the object; anything with one slot sends the token.

### Reading it correctly

Comparing two etags gives three answers, and they need different handling:

| Comparison | Meaning | What a consumer does |
|---|---|---|
| Equal | Nothing changed | Nothing |
| Same instance, higher generation | The same capture grew | Re-read; cursors stay valid |
| Different instance | A different capture is loaded | Discard every cursor, index and Call-ID |

`CaptureEtag::is_different_capture` exists so that third row is a named
operation rather than a field comparison someone has to remember to write.

### The lock rule, which is not optional

The identity lives in `CaptureState` ([`src/mcp/server.rs`](../../src/mcp/server.rs))
beside the capture description and the in-flight load, behind one `RwLock`, and
the lock order is **capture, then dialog store, then stream store**.

Two things force it. `open_capture` clears both stores while holding the capture
lock, so a reader that takes a store guard first and then reaches for the
capture lock deadlocks against it. And a handler that reads the identity, drops
the capture lock, and *then* reads the stores can have a swap land in the gap —
producing an answer stamped with a capture it did not come from, which is worse
than no stamp at all because it looks self-consistent. Every handler that stamps
an answer holds all three guards across the read.

### Who consumes it, and who is expected to

Today: `capture_status`, `stats`, `list_dialogs`, `find_problems`,
`search_by_time`, `tail_dialogs`, and the capture-wide `rtp_stats` sweep. The
rule for adding one is *every response whose meaning depends on the whole
store* — a page with a cursor, or an aggregate count. A response keyed on a
Call-ID needs no stamp, because a Call-ID either resolves or does not.

Two approved features are expected to consume this rather than mint their own:

- **Write-back tools** ([`mcp-write-back.md`](mcp-write-back.md)) need a
  compare-and-set token so an annotation cannot land on a revision the caller
  never saw. `CaptureEtag` is that token, and `FromStr` refuses a mangled one
  rather than defaulting to generation zero — a silent default would make every
  stale write succeed.
- **Packet-level provenance** ([`deferred-and-declined.md` §1](deferred-and-declined.md))
  needs a capture-instance identity to bind a packet reference to.
  `CaptureEtag::instance` is stable for the life of one loaded capture while the
  generations move under it, which is exactly the lifetime a reference needs.

### What it does not cover yet

The REST API carries no etag. `/v1/dialogs` is the poller the missing signal was
first noticed on, and it still has nothing — the response bodies and the
`ETag`/`If-None-Match` handling belong in
[`src/output/api.rs`](../../src/output/api.rs), which was being changed by other
work when this landed. The primitive is shaped for it: `CaptureEtag`'s string
form is a valid `ETag` value, and the same instance-versus-generation
distinction is what a `304` decision needs.

---

## 2. The load model

### Why not in the handler

The API and MCP servers share one thread running one
`tokio::runtime::Builder::new_current_thread()`
([`src/app/servers.rs`](../../src/app/servers.rs)). A pcap read inside a tool
handler blocks that thread for the whole read: every other MCP tool call and
every REST request queues behind it. Nothing catches this. It is not a
lock-across-await violation, so `clippy::await_holding_lock` never fires — the
handler simply never yields.

### The shape, ported from the TUI

The TUI has solved this once already: opening a capture interactively spawns a
`pcap-load` worker that writes through the shared stores while the event loop
keeps running ([`src/tui/controllers/file_open.rs`](../../src/tui/controllers/file_open.rs)).
[`src/mcp/load.rs`](https://github.com/NormB/sipnab/blob/main/src/mcp/load.rs) is that design with a different poller.

```
open_capture                          mcp-pcap-load thread
────────────                          ───────────────────
take capture write lock
  refuse if live / loading / busy
  rotate identity        ─────────────►  (the new instance is already public)
  clear both stores
  spawn ──────────────────────────────►  read_into_stores()
  store the load handle                    per packet: process_packet()
release lock                               progress.packets += 1
return "loading" + new identity          set outcome, source_exhausted, done
                                       ◄──── capture_status reads all of it
```

Three decisions inside that are worth keeping:

**The identity rotates before the stores are cleared.** An answer that catches
the stores half-filled then names the new capture, which is true and useful. The
old id would be a claim about data that is already gone.

**The worker routes through `pipeline::process_packet`**, the same applier the
live path uses, rather than a second classify-and-store loop. The per-store
write locks stay as brief as they are on the live path, and an opened capture is
analysed the way an `-I` one is.

**The poller is `capture_status`, not a new tool.** It is already the tool an
agent is told to call first, the test harness already polls it for
`source_exhausted`, and a `load` object on it needs no new documentation surface.
`source_exhausted` is cleared when the load starts and set when it stops, so a
poller written against the original capture works unchanged against the new one.

### The second-writer question

Invariant 1 gives each store exactly one writer, with the TUI's `pcap-load` as
the documented exception. This is the second. Two conditions make it safe and
`open_capture` enforces both before spawning:

- **The source must not be live.** A live capture's writer never finishes, so a
  second writer would race it for as long as the process runs. This refusal has
  no opt-out.
- **The source must be exhausted.** `source_exhausted` already tells the tool
  when the original reader is done. A server with no exhaustion signal attached
  reads as not exhausted and is refused, because "we cannot prove the first
  writer stopped" is the same situation as "it has not".

A load already running is refused too, and that check runs *before* the
exhaustion check: a running load also holds `source_exhausted` false, so testing
exhaustion first answered "the current source has not finished reading" to an
agent whose own previous call was the thing still reading. The unit test that
found it is `a_second_load_is_refused_while_one_is_running`.

### Two known limits

**The port gate is off.** `read_into_stores` uses `PipelineOptions::default()`,
so `sip_portrange` is `None` and every port is considered for SIP. That matches
the TUI's interactive open, and it is the direction that cannot under-report —
`--portrange` narrows what counts as SIP, and a capture opened here is read
wide. It does mean an opened capture and an `-I` one can disagree about the same
file when `--portrange` is set, and the disagreement is in favour of the opened
one. `start_servers` takes the CLI without the config file, so plumbing the
resolved range would change a public signature for a difference that only ever
finds *more* SIP.

**A capture inside the `-I` set is refused.** `open_capture` reuses
`resolve_in_root` unchanged, and that resolver is also the output guard: it
refuses a name that is, or sits inside, something this run reads. The message
says "would overwrite", which reads oddly for a read. The outcome is right for a
different reason — that file is already loaded, and re-reading it under a new
identity would duplicate what the store holds — but an operator who points both
`-I` and `--mcp-file-root` at one directory will find every name refused. The
alternative is a second path resolver with different rules, and two
implementations of one confinement rule is a defect pattern this tree has
already been bitten by (issue #105, the symlink escape).
