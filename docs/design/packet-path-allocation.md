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
  `tests/frame_provenance_test.rs`, so stored pointers still verify.
- Threading the `Packet` down to the retention sites is not viable:
  `process_rtp` alone has 78 call sites.
- The two retention sites take their frame from *different* types
  (`ParsedPacket` and `SipMessage`), so anything carried forward must reach
  both. `bytes::Bytes` clones are O(1), which makes carrying the frame bytes
  cheap in principle.

Expected: removes ~93% of the per-packet `Arc` refcount traffic and the
associated digest work. Verify with `bench/regression-gate.sh` and by
re-profiling — the `parse_packet` share of `ldadd8_relax` should collapse.

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

Do not update `bench/baseline.json` upward until a change is merged and
measured; the baseline records what ships, not what is hoped for.
