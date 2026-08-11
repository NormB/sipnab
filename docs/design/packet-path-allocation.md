# Performance spec: what the packet path actually spends its time on

**Status:** analysis complete, implementation not started.
**Measured:** 2026-08-09, reference host, `--profile profiling`, `perf 6.8.12`.

This supersedes PERF1's original diagnosis in
[`backlog.md`](backlog.md). PERF1 said the cost was hashing every frame. A
profiler says hashing is a minor term and the real cost is **atomic traffic —
about 40% of samples**. Both statements came from the same person; only one came
from a profiler.

## What was measured

`perf record --call-graph dwarf` over the profiling build, reconstructing the
fixed-state corpus at `--cores 2`. Reproduced on the 2.14M-packet sweep, so it
is not a small-sample artifact.

| Symbol | 535k corpus | 2.14M corpus |
|---|---|---|
| `__aarch64_ldadd8_relax` | 12.09% | 15.18% |
| `__aarch64_ldadd8_rel` | 13.92% | 11.63% |
| `__aarch64_cas8_acq_rel` | 9.96% | 6.57% |
| `__aarch64_swp4_rel` | 5.52% | 5.71% |
| **atomics, total** | **41.5%** | **39.1%** |
| `_mi_page_malloc_zero` | 2.58% | 3.06% |
| `parse_packet` | 1.96% | 2.44% |
| `frame_digest` | **absent from the top 18** | **absent** |

Grouping atomic samples by their nearest meaningful caller:

| Driver | Samples | What it is |
|---|---|---|
| mimalloc cross-thread free | 30 | `mi_free`, `mi_free_try_collect_mt`, `mi_arena_try_claim_abandoned` |
| `parse_packet` | 23 | `frame_ref()` cloning the source `Arc<str>`, once per packet |
| `bytes` refcount | 10 | `shared_clone` / `shared_drop` |

## The three findings

**1. Cross-thread allocation churn is the largest single driver.** The reader
does `pkt.data.to_vec()` for every packet — one allocation each — and the
workers drop them. mimalloc's cross-thread free path is atomic, so every packet
pays. 535,000 allocations on one thread, freed on others.

**2. `parse_packet` clones an `Arc<str>` per packet.** It calls
`packet.frame_ref()` unconditionally, and `frame_ref()` does
`Arc::clone(self.interface.as_ref()?)`. That is one atomic increment per packet
and one decrement when the `FrameRef` drops — for a pointer that is *kept* by
roughly 35,000 of 535,000 frames (SIP messages plus stream openers). ~93% of the
refcount traffic is for pointers nobody retains.

**3. Hashing is real but secondary.** Moving it off the serial reader in 0.5.89
recovered 18% at 2 cores and ~81% of the loss at 4. What remains of it is
smaller than either item above.

## Why the earlier diagnosis was wrong

The bisect measured `9e12653` costing ~13% with `frame_digest` patched to
`return 0`, and concluded the cost was "an `Arc` clone and a struct write". That
inference was *directionally* right about the `Arc` and badly wrong about the
magnitude and the mechanism — it missed the allocator entirely, and it never
explained why an `Arc` clone would cost 13%. It cost that much because it is one
of several atomics per packet, in a pipeline where one thread produces and
several consume.

The lesson is in [`../internals/profiling.md`](../internals/profiling.md):
bisection identifies the commit, a profiler identifies the cost. Do not let the
first stand in for the second.

## Measured ceilings, 2026-08-09

Both changes were measured before either was implemented, by building a
diagnostic that removes the work entirely. Diagnostics are upper bounds, not
shippable code. Interleaved replicates, fixed-state corpus, reference host:

| | 2 cores | 4 cores |
|---|---|---|
| HEAD (0.5.89 + committed work) | 1.64-1.66M | 1.85-1.94M |
| P1 — `parse_packet` builds no `FrameRef` | 1.84-1.87M (+13%) | 2.08-2.11M (+10%) |
| P2 — reader allocates nothing per packet | 1.91-1.94M (+16%) | 1.86-1.89M (**~0%**) |

**This reverses the order these were first proposed in.** The profile showed
mimalloc's cross-thread free path as the single largest driver, so P2 looked
like the bigger win. It is — at two cores. At four it does nothing measurable,
while P1 helps at both. Do P1 first.

The likely reason, untested: the allocator's cross-thread traffic spreads
across more workers as cores rise, while the pointer construction in
`parse_packet` runs once per packet regardless. If that is right, P2's value
falls further as cores rise and P1's does not. Worth confirming with `coz`
before spending the P2 refactor, since `--cores 4` is the operating point the
tool comparison and the CI gate both use.

**One measurement in this file was wrong and is worth remembering.** P2's first
diagnostic ended in `b.clone()`, which allocates a fresh `Vec` per packet — it
kept the allocation it was meant to remove and added a copy. It measured "no
improvement", which would have killed the change on the strength of a bug in
the harness. A diagnostic needs its own sanity check: if removing work does not
speed anything up, suspect the removal before the conclusion.

## Proposed work, in order of measured value

Each step states what it should move and how to check. Do them one at a time and
re-measure between — several touch the same code and their effects are not
additive.

### P1 — Stop building a `FrameRef` for frames that do not keep one

`parse_packet` stamps `parsed.frame = packet.frame_ref()` for every packet. Only
a retained pointer needs one: a dialog's `first_frame`
(`sip/dialog.rs:318`), a stream's `first_frame` (`rtp/stream_store.rs:460`), and
a finding's `frame_ref`.

Constraints, all of them already enforced by existing tests — read these before
designing:

- `Packet::frame_ref()` must stay a pure accessor. Computing the digest inside
  it fails `a_frame_ref_needs_both_halves_or_it_is_not_offered`, and it does not
  help anyway because `parse_packet` calls it for every packet.
- `frame_digest` must stay FNV-1a with its published spec vectors, per
  [`tests/frame_provenance_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/frame_provenance_test.rs), so stored pointers still verify.
- Threading the `Packet` down to the retention sites is not viable:
  `process_rtp` alone has 78 call sites.
- The two retention sites take their frame from *different* types
  (`ParsedPacket` and `SipMessage`), so anything carried forward must reach
  both. `bytes::Bytes` clones are O(1), which makes carrying the frame bytes
  cheap in principle.

Expected: removes ~93% of the per-packet `Arc` refcount traffic and the
associated digest work. Verify with [`bench/regression-gate.sh`](https://github.com/NormB/sipnab/blob/main/bench/regression-gate.sh) and by
re-profiling — the `parse_packet` share of `ldadd8_relax` should collapse.

**The blocker, found 2026-08-09 while scoping it.** There are exactly two
production consumers of `parsed.frame`:

| site | assigns |
|---|---|
| `pipeline.rs:1747` | `sip_msg.frame = pp.frame.clone()` |
| `rtp/stream_store.rs:460` | `stream.first_frame = parsed.frame.clone()` |

Everything else is test code or reads `msg.frame` downstream. That looks like
"build the pointer at those two places instead" — but **neither can reach the
`Packet`.** `classify_packet(pp: &ParsedPacket, …)` takes no packet, and the
stream store is further downstream still. So the source `Arc<str>` has to be
inside `ParsedPacket` for either site to build a `FrameRef`, and putting it
there is the per-packet clone we are trying to remove.

Skipping non-SIP packets does not work either: `stream.first_frame` is
deliberate, the code says *"a stream with no provenance must say so"*, and
[`tests/provenance_surfaces_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/provenance_surfaces_test.rs) asserts it.

Three ways out, none of them a small edit — pick one and spec it before coding:

1. **Borrow the source.** `ParsedPacket<'a>` holding `&'a str`. Cheapest at
   runtime, ripples a lifetime through every signature that touches a parsed
   packet.
2. **Intern the source.** `FrameRef.source` becomes an index into a small
   per-run table, resolved when the pointer is rendered. No atomic per packet.
   Changes a public type that `--json`, the REST API and MCP all surface.
3. **Give the consumers their own handle.** The `StreamStore` and the SIP path
   each hold one `Arc<str>` per source, set once, and build the `FrameRef`
   themselves from a `FrameOrigin` — which is `Copy` and therefore free to
   carry in `ParsedPacket`. Smallest blast radius of the three, but it must
   handle a multi-file set where the source differs per packet.

Option 3 looks best on current evidence. It is the one to spec first.

### Option 3, specified — chosen 2026-08-09

The reader mints **one `Arc<str>` per file** (`parallel.rs:609`,
`capture/file.rs:607`) and clones it into every packet's `interface`.
`parse_packet` then clones it a *second* time inside `frame_ref()`, and each
retention site clones the resulting `FrameRef` a *third*. Only the third is
ever kept.

So the consumers need something `Copy` that identifies the source, not an
`Arc`. The mechanism:

1. The reader owns a `Vec<Arc<str>>` of sources for the run — one entry per
   file, which is a handful of entries even for a large set — and stamps each
   packet with a `source_idx: u32` alongside its ordinal. Both are `Copy`, so
   this costs no atomic.
2. `ParsedPacket` carries `frame_origin: Option<FrameOrigin>` and that index
   instead of `frame: Option<FrameRef>`. `FrameOrigin` is already `Copy`.
   `parse_packet` performs **no** refcount traffic.
3. Each worker holds one clone of the source table, taken once at spawn.
4. The two retention sites — `pipeline.rs:1747` and
   `rtp/stream_store.rs:460` — build the `FrameRef` themselves:
   `FrameRef { source: table[idx].clone(), origin }`. One atomic, paid only by
   the ~6.5% of frames that keep a pointer.

**Multi-file is what this design exists to handle**, and it is the thing to
test first: a two-file set must give each packet the source of *its own* file,
which the index does by construction and a per-worker single `Arc` would not.
`resolver_orders_a_set_by_first_packet_time` and the two-file fixtures in
[`tests/frame_provenance_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/frame_provenance_test.rs) already cover the ordering; the new assertion
is that a pointer from file B names file B.

**The 28 sites are all `frame: None` — there are zero `frame: Some(...)`.**
Measured 2026-08-09. That matters more than it sounds: `None` is `None`
whatever `T` is, so changing the *type* of `ParsedPacket::frame` breaks none of
those literals. The refactor is far smaller than the site count suggested. What
actually changes is:

- a new `Copy` locator type (`FrameOrigin` plus a source discriminator),
- `Packet` carrying that discriminator, set by the reader,
- `parse_packet` storing it instead of calling `frame_ref()`,
- the two retention sites building the `FrameRef`.

**The unresolved question is where the source table lives**, and it is the only
thing still worth thinking about before coding. `PipelineOptions` reaches the
SIP consumer and `StreamStore` reaches the media one, but threading a table
through both constructors is plumbing. Two lighter alternatives, neither yet
evaluated:

- Leak one `&'static str` per capture file in the reader — bounded, a handful
  of short strings for a process lifetime — and have each consumer memoise a
  single `(&'static str, Arc<str>)` pair, re-deriving only when the source
  changes. No table, no plumbing, correct across a multi-file set.
- Keep the index, and give each consumer a one-entry cache of the last
  `(idx, Arc<str>)` it resolved.

Both make the common single-source case one atomic per *run* rather than per
packet, which is the entire point.

**Decided: the leaked `&'static str`.** The index does not actually avoid the
table — a consumer memoising `(idx, Arc<str>)` still needs something to resolve
the index the *first* time, which is the plumbing the alternative existed to
avoid. A `&'static str` is self-describing: the consumer builds its `Arc<str>`
straight from it and memoises the pair, so no table reaches either consumer and
no constructor signature changes.

What is being leaked is one interned path per capture source, for the process
lifetime — a handful of short strings for a file set, exactly one for a live
capture or a HEP listener. That is interning, not a leak in the sense that
matters: the count is bounded by the number of sources a run opens, which is
the same thing already true of the `Arc<str>` it replaces.

The multi-file case falls out correctly by construction, which is the property
worth having: each packet carries its own source pointer, so a pointer from the
second file names the second file without anyone tracking which file is
current. That is what a single per-worker `Arc` would have got silently wrong.

Implementation order, with the multi-file assertion written first:

1. [`tests/frame_provenance_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/frame_provenance_test.rs) — a two-file set where a pointer from the
   second file must name the second file. It should pass today and keep passing;
   if it ever fails, this design is wrong and the number is not worth it.
2. Reader interns the source once per file and stamps `Packet` with it.
3. `ParsedPacket::frame` becomes the `Copy` locator. Zero literal churn — all
   28 sites are `None`.
4. `parse_packet` stores the locator instead of calling `frame_ref()`.
5. The two retention sites build the `FrameRef`, each memoising one
   `(&'static str, Arc<str>)` pair.

**`FrameRef` itself does not change**, so `--json`, the REST API and MCP keep
their current shape and every stored pointer still resolves. That is the whole
reason to prefer this over interning, which would have changed a public type.

### P2 — Stop allocating a fresh buffer per packet on the reader

`pkt.data.to_vec()` allocates for every frame on the serial reader, and the
workers free it on another thread. It is the largest driver in the *profile* —
but measurement put its value at +16% at two cores and **nothing at four**, so
treat the profile's ranking as a hypothesis this already partly refuted.

Options to evaluate, cheapest first:
- A per-shard buffer pool that recycles allocations back to the reader, so
  alloc and free happen on the same thread and mimalloc's cross-thread path is
  never taken.
- Batching packets into fewer, larger allocations — the batched worker loop
  already exists (`run_offline_parallel_file` sends `Vec<Packet>`).

Expected: +16% at two cores, nothing measurable at four. Verify by re-profiling
and watching `mi_free`, `mi_abandoned_page_try_reclaim` and
`_mi_page_malloc_zero`. **Do P1 first**, and re-measure this afterwards: P1
removes work from the same per-packet path, so these are not additive and P2's
remaining value may be smaller again.

### P2, specified — measured 2026-08-10, and worth MORE after P1

Re-measured on the tree P1 produced, because the two touch the same per-packet
path and are not additive:

| | P1 (shipped) | P1 + P2 | |
|---|---|---|---|
| 2 cores | 1.85-1.88M | **2.23-2.24M** | +20% |
| 4 cores | 2.05-2.10M | **2.15-2.18M** | +5% |

**The prediction was that P2 would be worth LESS after P1. It is worth more** —
+20% where it was +16%, and +5% at four cores where it was nothing. P1 removed
the per-packet `Arc` traffic that was masking the allocator, so the allocator's
share rose; and at four cores P1 lifted the ceiling far enough that allocation
became the constraint where it previously was not.

For scale: 0.5.47, before the regression, measured 2.02M at four cores. P1+P2
measures 2.18M. This is not recovery, it is faster than the tool has ever been
on this corpus.

**The diagnostic is not the implementation.** It bump-allocates every frame
into a leaked 512 MB arena — no per-packet allocation, no cross-thread free,
and correct bytes for the workers — but it never reclaims, so a long capture
exhausts memory. It exists to prove the ceiling.

**What to build.** The cost is not the allocation itself but *where it is
freed*: the reader calls `pkt.data.to_vec()` and a worker drops it, so
mimalloc's cross-thread path runs 535,000 times. Make allocation and free
happen on the same thread:

1. **Recycle buffers back to the reader.** Each worker returns finished buffers
   through a channel; the reader reuses them instead of allocating. The batched
   path already sends `Vec<Packet>` over `bounded::<Vec<Packet>>(64)`
   (`parallel.rs:846`), so a return channel of `Vec<Vec<u8>>` fits the existing
   shape. The single-packet path (`parallel.rs:411`,
   `bounded::<Packet>(8192)`) would need the same treatment or to be left
   alone.
2. **Bound the pool.** A pool that only grows is the leak again with extra
   steps. Cap it, and fall back to a plain allocation when empty — under
   backpressure that is the correct behaviour, not a failure.
3. **Do not hold buffers past the worker.** `Packet::data` is
   `bytes::Bytes`; anything that retains a packet beyond its batch pins that
   buffer, so recycling must happen where the batch is known finished.

**Verify** with [`bench/regression-gate.sh`](https://github.com/NormB/sipnab/blob/main/bench/regression-gate.sh) and by re-profiling: `mi_free`,
`mi_free_try_collect_mt`, `mi_abandoned_page_try_reclaim` and
`_mi_page_malloc_zero` should all collapse. If they do not, the buffers are
still crossing threads and the pool is not doing its job.

### P3 — Confirm with a causal profiler before optimising further

The `--cores` path is one serial reader feeding N workers. A conventional
profiler cannot say whether making a worker stage faster changes end-to-end
throughput, because the reader may gate it. `coz` answers exactly that and is
not yet installed. Worth doing before any further micro-optimisation, so effort
lands where it changes the number.

## Targets

Measured on the reference host, fixed-state corpus, 2 cores, interleaved:

| | pkts/s |
|---|---|
| 0.5.83, before the regression | 2.30M |
| 0.5.88, the regression | 1.39M |
| 0.5.89, current | 1.69M |
| whole provenance stamp removed — the ceiling this spec can reach | 2.05M |

**2.05M is the honest ceiling for P1 alone**, because that diagnostic removed
the stamp entirely and kept everything else. Reaching 2.30M needs P2 as well —
the allocator work predates the provenance commit and is not a regression at
all, just a cost nobody had measured.

Do not update [`bench/baseline.json`](https://github.com/NormB/sipnab/blob/main/bench/baseline.json) upward until a change is merged and
measured; the baseline records what ships, not what is hoped for.
