# Process isolation, and what actually costs us on the hot path

**Status:** analysis, 2026-08-03. Verified against `main` at `f158afd`.
Answers two questions asked together: *should sipnab fork more?* and *would C
or assembler make capture faster?* They share one answer — **no, and the
measured bottleneck is somewhere else** — so they share one page.

Nothing here is a plan to fork. It is the record of why we are not going to,
what we are going to do instead, and the one place a child process is still
the right tool.

---

## 1. Where sipnab uses processes today

It essentially does not. Every concurrency boundary in the tool is a thread:
the fourteen named threads in
[`docs/internals/threading.md`](../internals/threading.md) are the whole
topology, and a `--mcp -N` process runs three of them with no children at all.

Child processes exist in exactly four places, and all four are `Command::spawn`
rather than `fork()`:

| Site | What it spawns | Why a process is right |
|---|---|---|
| [`src/output/event_exec.rs:443`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs#L443) | `sh -c` per `--on-*-exec` event | Operator-supplied code. Must not share our address space. |
| [`src/security/alerting.rs:717`](https://github.com/NormB/sipnab/blob/main/src/security/alerting.rs#L717) | `sh -c` per `--alert-exec` alert | Same. |
| [`src/privilege.rs:153`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L153) | `setcap` | One-shot install helper. |
| [`src/tui/clipboard.rs:89`](https://github.com/NormB/sipnab/blob/main/src/tui/clipboard.rs#L89) | `xclip`/`pbcopy` | Holds an X11 selection; must outlive the copy. |

Both exec paths are already correct: non-blocking `spawn` (never `status`),
rate-limited, capped by queue depth, and reaped. There is no gap here to close.

### The documented rationale is a decision that was never taken

Two design decisions govern this, and they disagree with each other.

**D2 — synchronous core, async only at the edges**
([`implementation-plan-v6.md:304`](https://github.com/NormB/sipnab/blob/main/docs/design/implementation-plan-v6.md#L304)) is what shipped.
[`threading.md:3-5`](https://github.com/NormB/sipnab/blob/main/docs/internals/threading.md#L3-L5) restates it: *"the packet path
is synchronous threads + channels. tokio exists only inside the optional
servers."*

**D16 — process isolation for dangerous operations**
([`implementation-plan-v6.md:564`](https://github.com/NormB/sipnab/blob/main/docs/design/implementation-plan-v6.md#L564)) is what did not.
It specified, in detail, child processes for two components:

> Scanner kill (packet injection) and the REST API (network-facing service) run
> in isolated child processes, not in the main packet processing loop. This
> limits blast radius: a vulnerability in the API handler or an exploit via
> crafted scanner-kill responses cannot compromise the capture/parse pipeline.

with `fork` before privilege drop, a Unix socket pair, and — at
[`implementation-plan-v6.md:2003`](https://github.com/NormB/sipnab/blob/main/docs/design/implementation-plan-v6.md#L2003) and
[`:2508`](https://github.com/NormB/sipnab/blob/main/docs/design/implementation-plan-v6.md#L2508) — acceptance gates reading *"verified by
checking PID differs from main"*.

Neither shipped as a process. Scanner-kill became a thread
([`src/process_isolation.rs:5`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L5): *"Provides
thread-based isolation"*), and the module still carries the aspiration at
[`:28`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L28):

> Future enhancement: replace threads with `fork()`/`Command` for true
> process-level isolation with separate address spaces.

The REST API became a tokio task on a shared thread reading the same
`Arc<RwLock<..>>` stores as the capture loop
([`src/app/servers.rs:164-197`](https://github.com/NormB/sipnab/blob/main/src/app/servers.rs#L164-L197)).

**This is the honest finding for "is there a documented rationale?"** — there is
not. The design demanded processes, the implementation substituted threads, and
no page anywhere records the trade being made.
[`deferred-and-declined.md`](deferred-and-declined.md) — the page whose entire
job is recording what was considered and rejected — contains no entry for
forking, process isolation, subprocesses, or address-space separation. The
substitution was never argued; it just happened.

### One consequence is a security claim that is not true

[`docs/architecture.md:149-150`](https://github.com/NormB/sipnab/blob/main/docs/architecture.md#L149-L150) still says:

> **D15/D16 — Privilege drop + process isolation.** sipnab drops root right
> after socket open; active responses run in an isolated child.

Active responses do not run in an isolated child. They run in the
`scanner-kill` thread, in the same address space as the parsers, the stores,
the TLS key material and the bearer tokens.

[`docs/rest-api.md:1117`](https://github.com/NormB/sipnab/blob/main/docs/rest-api.md#L1117) gets this right for the API and says
so plainly — *"it is not a separate OS process; treat the API bind address and
key accordingly"* — which is exactly the disclosure `architecture.md` owes for
scanner-kill and does not make. **Fixing that sentence is P0 and costs
nothing.** It is tracked in the backlog.

---

## 2. What forking would actually buy

The Rust argument for processes is not parallelism, so it has to be one of
four things. Three of them do not hold here.

### 2a. Fault isolation — the argument is real, but bigger than it looks

`[profile.release]` sets `panic = "abort"`
([`Cargo.toml:262`](https://github.com/NormB/sipnab/blob/main/Cargo.toml#L262)), confirmed by
[`src/crash.rs:6`](https://github.com/NormB/sipnab/blob/main/src/crash.rs#L6). **A panic on any thread aborts the whole
process.** Threads therefore provide *zero* panic containment in a release
build. A parser bug reached from a crafted packet does not kill a worker; it
kills the capture, the servers, and the evidence.

That is a genuine point in favour of processes. It is also a threat the project
already attacks head-on. D17 / [invariant 11](../internals/invariants.md) says:

> No parser reachable from packet bytes may panic, `unwrap()`, or exit.

enforced in three layers — the pre-commit gate rejecting `unwrap()`/`expect()`
in production code, the always-on
[`smoke_fuzz_test`](../../tests/smoke_fuzz_test.rs) floor under `catch_unwind`,
and fifteen coverage-guided targets in
[`fuzz/fuzz_targets/`](../../fuzz/fuzz_targets). A process boundary would be a
*fourth* layer under three that already work, bought at the cost of
re-architecting every store read in the tool (§3).

### 2b. Memory isolation — narrow, but this is the strongest argument

sipnab's own parsers are 100% safe Rust. Every `unsafe` block in the crate lives
in `playback.rs`, `privilege.rs`, `process_isolation.rs`, `crash.rs`,
`capture/live.rs`, `alerting.rs`, `names.rs`, `signals.rs`, `cli_print.rs` and
`tui/controllers/file_open.rs` — **none in `sip/`, `rtp/parser.rs`,
`capture/parse.rs` or `sdp.rs`.** The dependency graph agrees: `nom`,
`etherparse`, `opus-decoder` (pure Rust, no FFI), `flate2` (`rust_backend`) and
`wasmi` (interpreter, no JIT) are all memory-safe.

The exception is **libpcap** (`pcap = "2"`, [`Cargo.toml:58`](https://github.com/NormB/sipnab/blob/main/Cargo.toml#L58)),
a C library that touches every untrusted byte before Rust ever sees it, on both
the live and the offline path. A memory-safety bug there executes inside an
address space that also holds:

- TLS key material (`--tls-key`, keylog secrets),
- MCP and REST bearer tokens ([`src/auth.rs`](../../src/auth.rs)),
- the raw `CAP_NET_RAW` socket opened *before* the privilege drop and held for
  the whole run ([`process_isolation.rs:107-136`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L107-L136)),
- the dialog and stream stores.

This is the one argument that survives scrutiny. Note what it argues for: it
argues for isolating **the libpcap reader**, not for forking N analysis
workers. And §5 has a cheaper answer that closes more of the same path.

### 2c. Per-process pcap handles — no

Multi-device capture already gives each device its own thread and its own pcap
handle ([`capture/native.rs:302-353`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs#L302-L353)). Nothing is
contended. There is no handle problem to solve.

### 2d. Bypassing a shared-lock bottleneck — **no, and this is measured**

This is the argument that fails hardest, and it fails on data rather than on
opinion.

`--cores N` scaling, from [`docs/benchmarks.md:57-62`](https://github.com/NormB/sipnab/blob/main/docs/benchmarks.md#L57-L62):

| cores | pkts/s |
|------:|-------:|
| 1 | 1.07M |
| 2 | 2.21M |
| 4 | **2.32M** |
| 8 | 2.13M |

Throughput *peaks at four cores and then declines*. It peaked at two until
0.5.89 moved the frame-provenance digest off the sequential reader; the reader
is still the ceiling, which is why 8 cores remains slower than 4. The published
cause ([`benchmarks.md:64-70`](https://github.com/NormB/sipnab/blob/main/docs/benchmarks.md#L64-L70)) is:

> Through 0.5.88 the reader computed the frame-provenance digest on the single
> sequential stage that already sets this ceiling (read + buffer copy +
> host-pair peek), so adding work there capped every core count at once.

And critically: **`--cores` mode holds no shared locks at all.** Each worker
owns a thread-local `DialogStore` and `StreamStore`
([`parallel.rs:421-426`](https://github.com/NormB/sipnab/blob/main/src/parallel.rs#L421-L426)), merged at EOF. There is no
lock to bypass. Forking the workers would change nothing about the ceiling and
would make the merge worse — it becomes serialization and IPC of two whole
stores instead of a move.

Elsewhere, contention is **asserted but never measured**. The oldest claim,
[`implementation-plan-v6.md:368`](https://github.com/NormB/sipnab/blob/main/docs/design/implementation-plan-v6.md#L368), says the store
lock is *"read-heavy, write-rare, so RwLock contention is minimal"* — which is
simply stale: the batch loop takes `dialog_store.write()` **once per packet**
([`batch.rs:2243`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2243)), so at 2.3M pkts/s writes are the
most frequent operation in the process, not a rare one. No benchmark in
`benches/` acquires a lock; no metric reports contention. *We do not know what
it costs, and neither does anyone else.*

---

## 3. What forking would cost

Specific to this codebase, not in general.

**The stores are the product, and four surfaces read them in-process.** The
same `Arc<RwLock<DialogStore>>` / `Arc<RwLock<StreamStore>>` is held by the
capture loop ([`batch.rs:864-875`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L864-L875)), the REST handlers,
every MCP tool ([`mcp/server.rs`](../../src/mcp/server.rs)), the Prometheus
exporter and the TUI. Forking the capture away from the servers turns every one
of those reads into IPC. That is not a refactor; it is a new wire protocol,
with pagination, cursors, backpressure and versioning, for data that is
currently a pointer dereference.

**Two paths *write* the stores from outside the capture loop.** `open_capture`
spawns `mcp-pcap-load` ([`mcp/load.rs:132-174`](https://github.com/NormB/sipnab/blob/main/src/mcp/load.rs#L132-L174)) and the
TUI's file-open spawns `pcap-load`. Both are documented exceptions to
[invariant 1](../internals/invariants.md). Across a process boundary they stop
being exceptions and start being a replication problem.

**The TUI depends on being able to *fail* to read.** Every render-side access is
`try_read()`, and a contended read deliberately skips a frame
([`threading.md:154-157`](https://github.com/NormB/sipnab/blob/main/docs/internals/threading.md#L154-L157)). There is no `try_read`
over a socket.

**A merged view is the deliverable.** Multi-device capture merges N interfaces
into *one* dialog store, so a call seen on two interfaces is one call.
Per-source processes fragment exactly that. `--cores` already hit this and
needed `DialogStore::merge` to undo it —
[`parallel.rs:17-30`](https://github.com/NormB/sipnab/blob/main/src/parallel.rs#L17-L30) records that an earlier merge
dropped roughly half of every proxied call's signaling, invisibly, because the
dialog *count* was unaffected. That is the failure mode process-splitting
invites back.

**`fork()` in a multithreaded process is a trap.** Only async-signal-safe calls
are legal in the child. sipnab spawns the capture thread *before* the privilege
drop and chroot ([`threading.md:80-88`](https://github.com/NormB/sipnab/blob/main/docs/internals/threading.md#L80-L88)), so any fork
would have to happen in a narrow window before that — which is what D16
actually specified, and it is the hardest part of D16 to get right.

**Portability.** `fork` is POSIX-only. sipnab has live macOS paths
(`privilege.rs`, `clipboard.rs`).

---

## 4. Verdict

> **No. sipnab should not fork more as an architecture.** The one measured
> scaling limit is a serial reader, not a lock; the parsers that would be
> isolated are already memory-safe; and the shared stores that make forking
> expensive are the product itself.

Three exceptions and clarifications, ranked by value ÷ effort. All are tracked
as backlog items.

### R1 — Tell the truth about scanner-kill isolation *(P0, minutes)*
`architecture.md` claims an isolated child that does not exist. Every other
consideration on this page is a judgement call; this one is a factual error in a
security claim. Fix the sentence.

### R2 — Get `fork`/`exec` and stdout out of the store write locks *(P1, days)*
Not a forking change — the opposite. The batch loop takes **both** store write
locks at [`batch.rs:2243-2244`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2243-L2244) and holds them across
the entire per-packet body, which includes:

- `Command::spawn` (a real `fork`/`exec`) for `--on-*-exec` at
  [`batch.rs:2038`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2038) and
  [`:2348`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2348),
- `Command::spawn` for `--alert-exec`, reached through
  `alert_engine.write().fire(..)` at
  [`:2072`, `:2122`, `:2160`, `:2172`, `:2185`](../../src/app/batch.rs),
- a **third** lock (`Arc<RwLock<AlertEngine>>`) acquired while both store write
  locks are held,
- buffered stdout writes.

This violates two written rules. [Invariant 2](../internals/invariants.md) says
*"Never hold both write locks simultaneously"*, and
[`threading.md:144-147`](https://github.com/NormB/sipnab/blob/main/docs/internals/threading.md#L144-L147) says each store takes *"one
write lock per packet, briefly"*. A `posix_spawn` is on the order of hundreds of
microseconds against a packet budget of hundreds of nanoseconds — it is by far
the most expensive thing in the critical section, and it is there by accident.

The nested `AlertEngine` lock is worse than it currently looks. The ordering
`stores → alerts` exists only on this path; `security_findings`
([`mcp/server.rs:4848`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L4848)) takes `alerts.read()` and no
store lock, so there is no deadlock **today**. Nothing writes that ordering
down, and nothing enforces it. The next MCP tool that reads an alert and then a
dialog deadlocks the capture.

**Fix:** queue exec requests and per-message output during the locked section
and drain them after the guards drop. Then add the missing lock-ordering rule to
`invariants.md`.

### R3 — Scanner-kill as a real child process *(P2, weeks — do only if `--kill-scanner` gets real use)*
The single cleanest fork candidate in the tree, and the one D16 asked for. It
holds a `CAP_NET_RAW` raw socket that outlives the privilege drop, it
*transmits*, and it already has no shared state — it talks over a crossbeam
channel with messages that are **already**
`Serialize`/`Deserialize` ([`process_isolation.rs:307, 329`](../../src/process_isolation.rs)),
which is otherwise unexplained and is a fossil of the D16 IPC design.

`--rtpengine-control` transmits too, and is not a second candidate: its
reconciler thread writes the stream store, which is the shared state that
disqualifies everything else on this page.

Rank it P2 rather than P1 only because `--kill-scanner` is off by default and
niche. If it becomes a headline feature, this moves up.

### Declined

- **`--cores` as processes.** Measured bottleneck is the serial reader; there
  are no shared locks to escape; merge becomes IPC. See R5 for the real fix.
- **Per-capture-source processes.** Fragments the merged view that is the
  deliverable.
- **REST API in a child (D16's other half).** The store reads are the entire
  API. See §3.

---

## 5. "Would C or assembler make capture faster?"

**No, and the premise inverts the measurement.**

**The bottleneck is already C.** The sequential stage that caps `--cores` at 2×
is the pcap reader — and that is libpcap, a C library. Rewriting Rust into C
moves work *toward* the thing that is already the limit.

**Hand-vectorizing is a dead end because the hot loop is not arithmetic.** The
per-packet cost is dominated by a `memcpy` and an allocation
([`capture/live.rs:266`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L266): `pkt.data.to_vec()`), a
hash lookup, and pointer chasing through the stores. There is no scalar inner
loop for SIMD to widen.

**And the micro-optimization was already tried and honestly reported as a
loss.** [`docs/internals/zero-copy-payloads.md`](../internals/zero-copy-payloads.md)
predicted a 20–30% hot-path win from removing the per-packet copy, then
measured it:

> `payload_slice_zero_copy` (Bytes::slice): **15.6 ns**
> `payload_copy_to_vec` (heap copy): **15.1 ns**
> Honest conclusion: at typical SIP/RTP packet sizes the heap copy was already
> as cheap as the refcounted slice — the analysis claim of a 20-30% hot-path win
> did not hold.

If eliminating the copy entirely is worth ~0 ns, no amount of assembler around
that copy is worth anything either.

**The vectorization that pays is already in, via dependencies** — and the crate
contains no `asm!`, no `core::arch`, and no `target_feature` anywhere:

- `memchr` — SIMD CRLF scan in the SIP line scanner, replacing scalar
  `windows(2)` ([`Cargo.toml:51`](https://github.com/NormB/sipnab/blob/main/Cargo.toml#L51)),
- `ahash` — AES-backed hashing for the per-packet store lookups, replacing
  SipHash, which had been *"profiled at ~7% of total instructions"*
  ([`Cargo.toml:47`](https://github.com/NormB/sipnab/blob/main/Cargo.toml#L47)),
- `smallvec` — removes the per-packet heap allocation in
  `PacketProcessor::process`,
- `mimalloc` — replaces the system allocator for the whole native binary.

Each of those bought more than hand-written assembly would, and none of them
cost a line of `unsafe` in this crate.

### Where the throughput actually is, ranked

#### R4 — Parallel readers, so `--cores` can exceed 2× *(P2, the big one)*
[`parallel.rs:758`](https://github.com/NormB/sipnab/blob/main/src/parallel.rs#L758) reads a multi-file `-I` set in a
**serial `for` loop on one thread**. Since the reader is the proven ceiling, and
`-I` routinely names a directory or glob of rotated captures, N reader threads
each opening their own file — all sharding into the same worker pool, so
cross-file dialog stitching is preserved — attacks the measured bottleneck
directly. Threads, not processes: there is nothing to isolate.

**Open risk that must be settled first.** Packets would reach a worker
interleaved across files and therefore out of timestamp order.
`DialogStore::merge` is order-tolerant — `absorb_messages`
([`dialog_store.rs:1089-1106`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1089-L1106)) sorts by
timestamp and `replay_message_derived_state` re-runs the state machine — but a
*live* worker store is fed by `process_message` in arrival order. **I could not
determine whether out-of-order arrival within a single worker changes the
result.** A parity test at `--cores 1` vs parallel-reader `--cores N` over the
reference corpus is the gate, and it must be written before the feature.

#### R5 — Reconsider `immediate_mode(true)` for live capture *(P2, hours)*
[`capture/live.rs:152`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L152) enables libpcap immediate
mode unconditionally, which defeats kernel batching and costs roughly a wakeup
per packet. That is the right default for an interactive TUI and the wrong one
for a headless high-rate capture. Make it a policy — batched for `-N`,
immediate for the TUI — and measure. This is a one-line change with a real
chance of moving live-capture throughput, and it is the cheapest item on this
page.

#### R6 — `AF_PACKET` v3 / `PACKET_MMAP` ring, or `io_uring` *(P5, exploratory)*
The genuine order-of-magnitude lever for live capture is a shared-memory ring
that removes the per-packet copy and syscall — the same reason DPDK and PF_RING
exist. This is a *kernel-interface* change, not a language change, and it is
still Rust. Only worth opening after R4 and R5, and only against a measured
live-capture target.

---

## 6. What I could not determine

Stated plainly, because guessing here would be worse than the gap.

- **What the store lock actually costs.** No benchmark in `benches/` takes a
  lock; no metric reports contention; nothing measures the `--api`/`--mcp`
  attached case against the detached one. R2 is justified by *what is inside the
  critical section*, which is provable from the code, not by a measured stall.
- **Whether `fork`/`exec` under the store locks causes observable packet loss.**
  Plausible from the syscall cost, unmeasured. R2 should ship with the
  before/after number.
- **Whether out-of-order arrival within a `--cores` worker changes
  reconstruction.** The blocker for R4; see above.
- **The libpcap version and CVE exposure of the shipped artifacts.** Not audited
  here. §2b's argument stands or falls on it.
