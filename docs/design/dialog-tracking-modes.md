# Dialog tracking modes (`--dialog-track`)

**Status:** IMPLEMENTED (0.5.54, 2026-07-27).
**Context:** `--dialog-track <METHOD>` shipped from an unknown release until
0.5.52 as a *dead flag* — declared in `src/cli.rs`, read nowhere, accepting any
value including nonsense and changing nothing. It was removed rather than left
advertising a capability the binary did not have. This spec is what would have
to be true to reintroduce it honestly.

## The problem it solves

sipnab groups SIP messages into dialogs keyed by **Call-ID**. That is RFC 3261's
dialog identity and it is right for ordinary traffic.

It is wrong for two real populations:

- **Load generators.** `tests/pcap-samples/sipp-branch-scenario.pcapng` is
  8,989 packets in which one Call-ID is reused across many transactions. sipnab
  reports it as a handful of enormous dialogs; a reader wanting per-transaction
  detail cannot get it.
- **Proxies and B2BUAs under test**, where the same Call-ID legitimately recurs
  and the interesting unit is the transaction, not the call.

For those, the useful grouping key is the **top-Via branch** — RFC 3261's
transaction identifier.

## Semantics

| mode | groups by | unit |
|---|---|---|
| `call-id` (default) | Call-ID | dialog (RFC 3261 §12) |
| `branch` | Call-ID + top-Via branch | transaction (RFC 3261 §17) |

`branch` composes *with* Call-ID rather than replacing it. A branch is only
required to be unique within a transaction; keying on it alone would merge
unrelated calls from different endpoints that happened to pick the same value,
which is worse than the problem being solved.

### The wrinkle that must be documented, not hidden

A single call does **not** have one branch. RFC 3261 requires:

- the INVITE transaction to carry one branch,
- the ACK to a 2xx to carry a **new** branch (§17.1.1.3),
- the BYE, being a separate transaction, to carry another.

So under `branch`, one ordinary call becomes **three or more** tracked units,
not one. That is the correct transaction view and it is what the mode is for,
but a user who reads "track dialogs by branch" and expects one row per call
will be surprised. The `--help` text and the CLI reference must say
*transaction*, not *dialog*, and the report header must label the column
accordingly.

This is the single most likely source of "sipnab is broken" reports from the
feature, so it is called out here rather than discovered later.

## Design

### Keying

`DialogStore` currently holds `IndexMap<String, SipDialog>` keyed by the
Call-ID. The change is to key on a **derived** tracking key:

```
call-id mode:  key = call_id
branch  mode:  key = format!("{call_id}\n{branch}")     // \n cannot appear in
                                                        // a parsed header value
```

`\n` is already used as a collision-proof separator by `seen_cseq_key` in
`src/sip/dialog.rs` for exactly this reason; reuse it rather than inventing a
second convention.

Messages with no branch (RFC 2543 peers) fall back to the Call-ID alone, so
they group as they do today rather than vanishing into an empty-branch bucket.

### The blast radius, which is the real cost

Call-ID is not merely the store's key — it is the **public identifier** of a
dialog across every surface:

| surface | lookup |
|---|---|
| `--call-report <call-id>` | `DialogStore::get(call_id)` |
| REST API (`src/output/api.rs`) | call_id in paths and payloads |
| MCP tools (`src/mcp/server.rs`) | call_id as the tool argument |
| TUI timeline / raw message view | `store.get(call_id)` |
| WASM analyzer | three `get(call_id)` sites |
| RTP linkage | `stream_store.streams_for(call_id)` |

Under `branch`, a Call-ID no longer identifies exactly one entry, so every one
of those lookups becomes ambiguous. **This is why the feature is not a small
change**, and why keying the store differently without addressing it would
produce a subtler bug than the dead flag it replaces.

The proposed resolution:

1. `DialogStore::get(call_id)` keeps its signature and returns the **first**
   entry whose Call-ID matches, preserving today's behaviour in `call-id` mode
   exactly (where first == only).
2. A new `get_by_key(&str)` addresses a specific tracked unit.
3. The report, JSON and API surfaces gain a `tracking_key` field alongside
   `call_id`, empty in `call-id` mode. Consumers keying on `call_id` keep
   working; consumers wanting per-transaction identity have something stable.
4. `streams_for(call_id)` is left keyed on Call-ID: RTP is negotiated per call
   via SDP, not per transaction, so splitting media by branch would be wrong.

### Interaction with existing flags

- `--no-dialog` — unchanged; disables tracking entirely, so the mode is moot.
- `--limit` / `--rotate` — capacity now counts *transactions* in `branch` mode,
  so the same capture needs a higher `--limit` for equivalent retention. Worth
  a sentence in the CLI reference.
- `--cores N` — the parallel path shards by host pair and merges stores; the
  merge already keys on the map key, so it follows automatically. **Must be
  tested**, not assumed: `run_offline_parallel` has its own store-merge path.

## Testing

The corpus already exists: `sipp-branch-scenario.pcapng` reuses one Call-ID
across many transactions, so the two modes must disagree about the count on it.
That disagreement is the only proof the flag is wired to anything — the dead
flag passed a `default_dialog_track_is_none()` test precisely because it did
nothing.

Required:

1. `branch` yields strictly more tracked units than `call-id` on the sipp
   corpus, and both are > 0.
2. An ordinary single call yields **one** unit under `call-id` and **more than
   one** under `branch` (the ACK/BYE wrinkle above, asserted rather than
   discovered).
3. A message with no Via branch falls back to Call-ID grouping.
4. An unknown `--dialog-track` value is **rejected** at startup. The dead flag
   accepted `telepathy` and exited 0; a typo must not silently select the
   default.
5. The same assertions under `--cores 4`, because the parallel merge is a
   separate code path.
6. `--call-report <call-id>` still resolves in both modes.

## Rejected alternatives

- **Key on branch alone.** Branches are unique per transaction, not globally;
  unrelated calls could collide.
- **Re-key the store and rewrite every consumer to use transaction identity.**
  Correct in the abstract, but it changes the identity of a dialog across the
  REST API, MCP and WASM surfaces — a breaking change to three public
  interfaces to serve a diagnostic mode.
- **Ship it accepting any value, resolving later.** That is precisely what was
  removed in 0.5.52.
