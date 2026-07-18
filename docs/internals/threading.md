# Threading model

The topology below is the reality on `main` today. The core principle
(design decision D2): the packet path is synchronous threads + channels;
tokio exists only inside the optional servers.

## Topology

```
                       ┌──────────────────────────────────────────────────┐
                       │                 shared state                     │
                       │  Arc<RwLock<DialogStore>>  Arc<RwLock<StreamStore>>
                       │        (parking_lot, single writer)              │
                       └───────▲──────────────────────────▲───────────────┘
                        write  │                     read │ (try_read in TUI)
capture thread(s)              │                          │
  live device / file / HEP     │                          │
  (capture::start_multi_capture)                          │
        │ Packet               │                          │
        ▼                      │                          │
  capture::channel  ────► processing thread ──────► TUI event loop (main thread)
  (capped channel)        (TUI mode: pipeline::         │ crossterm events, render
                           process_packet;              │
                           batch mode: main.rs loop     ├── API server thread (api)
                           on the main thread)          │     own tokio runtime, axum
                                                        ├── MCP stdio thread (mcp)
                                                        │     own tokio runtime, rmcp
                                                        ├── MCP-HTTP thread (mcp-http)
                                                        │     own tokio runtime
                                                        ├── Prometheus server thread
                                                        ├── DNS resolver thread (names)
                                                        │     std::mpsc queue
                                                        └── scanner-kill worker
                                                              (process_isolation, bounded
                                                               crossbeam channel)
```

`--cores N` offline mode replaces the single processing thread with a
dispatcher + N workers: the dispatcher does a cheap host-pair peek and shards
raw packets over bounded channels; each worker owns a private
`PacketProcessor` + thread-local `DialogStore`/`StreamStore` (no locks on the
hot path), and the stores merge at EOF. Flow correctness holds because a
flow's packets share a host pair and therefore a worker.

## Lock discipline

- **Parse outside the lock.** SIP/RTP/SDP parsing happens before any store
  lock is taken; each store is write-locked once per packet, briefly
  (`pipeline.rs`).
- **Lock ordering:** when both stores are needed, dialog store first, then
  stream store; never hold both write locks at once (see the comment block
  at the top of `sip/dialog_store.rs`).
- **The TUI never blocks:** all render-side store access is `try_read()`.
  On contention the frame renders with the previous data (counts may be one
  frame stale — this is deliberate; an adaptive 10 fps active / 2 fps idle
  tick bounds staleness).
- **Pause** is an `AtomicBool` checked by the processing thread; no lock.
- `mcp/` denies `clippy::await_holding_lock` — parking_lot guards must never
  live across an `.await`.

## Channels in use

| Edge | Flavor |
|---|---|
| capture → processing | `capture::channel` (capped wrapper) |
| batch main loop | crossbeam bounded |
| `--cores` dispatcher → workers | crossbeam bounded (8192) |
| DNS resolve queue | `std::sync::mpsc` |
| inside api/mcp servers | tokio (axum/rmcp internals) |

## Known debt (tracked in MAINTAINABILITY-PERF-SPEC.md)

- Three single-thread tokio runtimes (api, mcp, mcp-http) where one shared
  runtime would do (WS2).
- Four channel flavors where crossbeam could serve all non-tokio edges (WS2).
- The TUI's long read-lock hold during filtered/searched call-list scans
  backpressures the processing thread's writes (WS4.3).
