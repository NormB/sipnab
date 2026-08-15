# Making `PACKET_FANOUT` reachable

**Status:** DESIGN, on a mechanism that is already BUILT and deliberately not
wired. [`src/capture/fanout.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/fanout.rs) (221 lines) and
[`capture_live_fanout`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L224) are written and tested; no
caller and no flag reach them. That is the decision in section 7 — **measure
before wiring** — not an oversight, and section 7 names the result that would
mean "do not ship".
**Verified against:** `3267b08`, working tree.
**Backlog:** [`backlog.md`](backlog.md) **CT4** (`:473`) and **CT11** (`:496`).
**Check:** `grep -rn 'fanout' src/cli.rs` exits 1 — no flag reaches the mechanism.

That check is about REACHABILITY, and this Status line used to read "Nothing
here is implemented" above it. The check passed the whole time, because it was
never testing that claim: a grep of `cli.rs` cannot see 221 lines of built
mechanism in `capture/`. Evidence that verifies a narrower proposition than the
sentence it sits under is how a false claim survives a gate designed to catch
false claims.

**No number in this document is measured.** The repo's standing caveat applies
in full — [`capture-tuning-tasks.md:22`](https://github.com/NormB/sipnab/blob/main/docs/design/capture-tuning-tasks.md#L22): *"Nothing on
this page has been measured on a live NIC. Every throughput claim is reasoned
from syscall counts and ring arithmetic. Do not upgrade a reasoned claim to a
measured one without the measurement."* Section 5 is about turning that
sentence off for this one feature, and nothing else here should be read as
having done so.

## 1. What exists, and the one thing that does not

CT4's opening line is now stale and should be corrected when this is picked up.
It says *"`grep -rn 'FANOUT\|fanout' src/` matches nothing"*. That has not been
true since [`fanout.rs`](../../src/capture/fanout.rs) landed. What is true is
narrower and more interesting:

| Piece | Where | State |
|---|---|---|
| `setsockopt(SOL_PACKET, PACKET_FANOUT, …)` | [`fanout.rs:76`](https://github.com/NormB/sipnab/blob/main/src/capture/fanout.rs#L76) | written, unit-tested, and **verified against the running kernel** by an `#[ignore]`d root test |
| Platform split | [`fanout.rs:101`](https://github.com/NormB/sipnab/blob/main/src/capture/fanout.rs#L101) | non-Linux returns `ErrorKind::Unsupported`; the call site is unconditional so it cannot go unused (`82eb8ff`) |
| Plan / group id | [`live.rs:194`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L194), [`:209`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L209) | pure, tested without a device |
| Kernel probe | [`live.rs:293`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L293) | throwaway handle, so refusal is discovered once |
| N-socket driver | `capture_live_fanout`, [`live.rs:224`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L224) | complete, joins all threads, first error wins |
| **A caller** | — | **none** |

`grep -rn 'capture_live_fanout' src/ tests/ benches/` returns the definition and
one doc-comment mention. Every path into live capture goes through
`start_capture`, whose `Live` arm spawns exactly one thread running
`capture_live` ([`native.rs:256-262`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs#L256-L262)), and
`capture_live` is a one-line wrapper that passes `None` for the group
([`live.rs:175`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L175)).

So this is not "build fanout". It is "decide what a flag means, wire one call
site, and prove the thing was worth wiring". The third is the expensive part and
the rest of this page is mostly about it.

## 2. The flag surface

### The case for a new flag

`--cores` is documented as offline-only in three places that would all become
wrong at once, and one of them is a test that pins the *complement*:

- The help text, [`cli.rs:1447-1453`](https://github.com/NormB/sipnab/blob/main/src/cli.rs#L1447-L1453): *"CPU cores for OFFLINE
  pcap reconstruction (`-I`) … Advanced features (live capture, per-message
  output ordering, security detectors, SRTP decrypt) use the single-threaded
  path regardless."*
- `cores_ignored_warning` ([`bootstrap.rs:2277`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L2277)),
  whose live-capture branch says *"this run captures live rather than reading a
  saved file … parallel reconstruction is offline-only — it shards a capture
  FILE by host pair, which needs the whole capture up front. This run continues
  on ONE core"*.
- `cores_warning_is_the_exact_complement_of_the_parallel_path`
  ([`bootstrap.rs:2977`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L2977)), which asserts the warning
  fires for exactly the four input combinations the parallel path does not take.

And the two meanings really are different resources. Offline, `--cores N` buys N
**processing** threads with N private stores, sized per worker
(`ParallelConfig.max_streams` / `max_dialogs`,
[`parallel.rs:136-139`](https://github.com/NormB/sipnab/blob/main/src/parallel.rs#L136-L139)). Live, as built, it would buy N
**capture sockets** feeding one processing thread and one pair of stores. Same
number, different unit, different memory, different failure mode.

### The case for reusing it, which is stronger

Three things decide it.

**Nothing breaks, because the flag is currently inert live.** Today
`sipnab -d eth0 --cores 8` prints a warning and captures on one socket. There is
no live behaviour to preserve. Reuse is a strict widening of a flag that already
does nothing on this path — the rarest and cheapest kind of flag change.

**The module already assumes it.** `capture_live_fanout`'s own fallback warning
is written in terms of `--cores`
([`live.rs:236`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L236)): *"`--cores {sockets}` does not
widen a live capture here."* Shipping a second flag would make that message
wrong on the day it first becomes reachable.

**A second flag does not remove the ambiguity it is meant to remove.** Call it
`--capture-sockets N` and an operator still has to learn that it does not fan
out processing — the same thing `--cores N` live would fail to do. The
distinction the operator needs is *"how much of this did you parallelise"*, and
that is a log line and a help-text sentence, not a second noun.

**Decision: reuse `--cores`.** With three obligations, none optional:

1. **The help text states both meanings.** One sentence for the offline shard
   count, one for the live socket count, and an explicit "processing is one
   thread either way, live".
2. **`cores_ignored_warning` loses its live branch and keeps its
   `--multi-device` branch.** The `--multi-device` reason
   ([`bootstrap.rs:2977`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L2977)) stays true; see §2.1.
   `cores_warning_is_the_exact_complement_of_the_parallel_path` must be rewritten
   in the same commit, not after — it is currently the gate that would catch the
   two conditions drifting, and a half-updated complement is worse than none.
3. **The run says what it bought.** `capture_live_fanout` already logs
   *"capturing on {sockets} sockets, fanout group {group}"*
   ([`live.rs:256`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L256)). That line must also say that
   processing stays on one thread, or the log reads as "sipnab is now using 8
   cores".

`RunMode` gains nothing. Fanout is not a run mode — it is how the `Live` arm of
`start_capture` constructs its thread. `RunMode::CoresFile`
([`bootstrap.rs:71`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L71)) stays exactly as it is, still
requiring `-I`, because it selects the *offline parallel engine*, which live
capture is not getting.

### 2.1 The resource change nobody would expect

**`buffer_mb` is per handle.** `capture_live_group` applies
`config.buffer_mb` to each socket it opens, and the default is 64 MiB since CT2
(`DEFAULT_BUFFER_MB`, [`native.rs:166`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs#L166)). So
`--cores 8` on a live interface asks the kernel for **512 MiB of ring**, from a
flag that yesterday allocated nothing.

That is not an argument against the feature; N rings is the entire point. It is
an argument that the number must appear in the log line and in the docs, because
an operator who read `--cores` as "CPU" has no reason to expect memory. The
buffer ladder ([`live.rs:341`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L341)) will step each
socket down rather than fail, which means the failure mode is *quiet*: eight
sockets that each silently got less ring than asked.

**Open:** whether `--cores N` should divide `buffer_mb` across sockets rather
than multiply it. Dividing preserves the total and surprises nobody; multiplying
is what actually helps a burst. Not decidable from the code — it needs §5.

### 2.2 `--multi-device` composes badly and should stay refused

`start_multi_capture` ([`native.rs:404`](https://github.com/NormB/sipnab/blob/main/src/capture/native.rs#L404)) already
spawns one capture thread per interface into one shared channel, with a
coordinator thread and an aggregated readiness signal. That is the same topology
`capture_live_fanout` builds — which is a good sign for the design and a problem
for the combination: `--cores 4 -d eth0,eth1 --multi-device` would be eight
capture threads and eight rings, and `fanout_group_id`
([`live.rs:209`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L209)) derives **one group id per
process**, not per device.

**Unverified:** whether the kernel permits sockets bound to two different
interfaces in one fanout group, and what it does with the hash if it does. Until
someone reads `fanout_add()` for the device check and confirms it against a
running kernel — the same standard `fanout_applies_to_an_open_pcap_handle`
([`fanout.rs:183`](https://github.com/NormB/sipnab/blob/main/src/capture/fanout.rs#L183)) already set for the single-device
claim — `--cores` with `--multi-device` must keep its existing refusal.

## 3. What widening CAPTURE buys, exactly

`capture_live_fanout` gives every socket the same `tx`
([`live.rs:224`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L224)), and there is one receiver: the
`rx.recv_timeout` at [`batch.rs:2121`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2121). So the shape is
N producers, one consumer, one pair of stores, one sweep.

**It buys N rings and N drainers.** The overflow CT2 describes is per-socket:
the ring fills because one thread is not draining it fast enough during a burst.
N sockets means the burst is spread across N rings *and* N threads are draining.
That is the correct fix for a drainer-bound capture, and it is the only thing
`PACKET_FANOUT` is for.

**It buys nothing if the consumer is the limit.** `packet_channel`
([`channel.rs:131`](https://github.com/NormB/sipnab/blob/main/src/capture/channel.rs#L131)) is an unbounded data queue
plus a bounded slot semaphore, so `send` blocks once `capacity` packets are in
flight. When the processing loop cannot keep up, the channel saturates and the
capture threads block in `send` — and a blocked capture thread is a thread not
draining its ring, which is exactly the condition fanout was supposed to relieve.
Under a processor-bound load, `--cores 8` moves the queue and drops in eight
rings instead of one.

**This is the whole design decision, and it is measurable.** The two regimes are
distinguishable by instruments that already exist:

| Observation | Reading |
|---|---|
| `kernel_dropped` rising, queue depth low, backpressure blocks ~0 | drainer-bound — fanout is the right fix |
| `kernel_dropped` rising, queue at capacity, backpressure blocks climbing | processor-bound — fanout buys nothing and section 4 is the only path |
| `interface_dropped` rising | neither; the NIC discarded before libpcap, and no userspace change recovers it ([`server.rs:1719`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L1719)) |

`sipnab_capture_queue_depth_packets` and
`sipnab_capture_backpressure_blocks_total`
([`prometheus.rs:470`](https://github.com/NormB/sipnab/blob/main/src/output/prometheus.rs#L470),
[`:482`](https://github.com/NormB/sipnab/blob/main/src/output/prometheus.rs#L482)) are the second and third rows'
instrument, fed from `CaptureMeter`
([`channel.rs:68-86`](https://github.com/NormB/sipnab/blob/main/src/capture/channel.rs#L68-L86)), and they are scrapeable
from a headless run — `start_servers` is called with `metrics: true` and the
real meter from [`batch.rs:1861-1879`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L1861-L1879).

**One gap worth fixing before the experiment.** `CaptureCounters`, the
`capture_health` MCP response ([`server.rs:5849`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L5849)),
carries `packets`, `kernel_dropped`, `interface_dropped`, `invalid_timestamps`
and `undecodable_frames` — and **no queue depth and no backpressure count**. So
the surface built for production field reports
([`bench/field-report.sh`](../../bench/field-report.sh)) can see that packets
were lost and cannot see which of the two regimes lost them. Adding the two
integers is small, keeps the no-`String` structural guarantee intact, and is a
prerequisite of any field measurement rather than a nice-to-have.

## 4. Fanning out PROCESSING is a different design, not a bigger CT4

[`fanout.rs:31-35`](https://github.com/NormB/sipnab/blob/main/src/capture/fanout.rs#L31-L35) already says this, and
[`parallel.rs`](../../src/parallel.rs) says why in detail. Restating the
constraint in the form that matters here: **the offline engine is correct because
it has an EOF, and a live capture does not.**

Three things happen at that EOF, and none of them has a live equivalent:

1. **`DialogStore::merge` reassembles proxied calls.** A call through a proxy is
   captured on two host pairs and shards to two workers
   ([`parallel.rs:18-30`](https://github.com/NormB/sipnab/blob/main/src/parallel.rs#L18-L30)) — *"in one 100 MB file of the
   reference corpus 1173 of 2311 dialogs were proxied"*. Merge concatenates the
   fragments in capture-timestamp order and re-runs the state machine. Live,
   there is no moment at which a dialog is finished arriving.
2. **`StreamStore::reassociate_all` links streams to dialogs globally**
   ([`stream_store.rs:1326`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L1326)), because SDP and RTP
   routinely land on different workers when the carrier advertises a separate
   media IP.
3. **`final_sweep` runs exactly ONCE, after the merge, at the capture's final
   timestamp** ([`parallel.rs:116`](https://github.com/NormB/sipnab/blob/main/src/parallel.rs#L116)) — and
   [`parallel.rs:47-53`](https://github.com/NormB/sipnab/blob/main/src/parallel.rs#L47-L53) records why it is not per worker:
   a worker's local last timestamp can be minutes behind the capture's, so a
   per-worker sweep *"would measure each fragment against its own clock and
   produce a THIRD answer, matching neither path — worse than the divergence it
   replaced, because it would look right."*

Point 3 transfers verbatim to a live worker pool, and it is the one that should
stop anyone from treating this as CT4's sequel. The live loop already sweeps
every five seconds of capture time
([`batch.rs:2083-2093`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2083-L2093)) against one `SweepClock` fed by
every packet the single receiver saw. Give each of N workers its own clock and
the orphan/compaction verdict becomes a function of how the kernel hashed the
flows. That is a wrong answer that renders as a normal report.

The three shapes a live processing pool could take, and what each costs:

- **Periodic merge into a shared store.** Reintroduces a global write lock at
  merge cadence, and makes *"once, at the final timestamp"* undefined —
  `final_sweep`'s contract has no meaning under a repeated merge.
- **Shared stores with per-packet locking.** This is the design the single-writer
  rule exists to avoid ([`docs/internals/invariants.md`](../internals/invariants.md)),
  and it is the arrangement `--cores` was built to escape.
- **Partition so a dialog never crosses a worker.** Refuted by the 1173/2311
  measurement above: a proxied call's signalling is already on two host pairs
  before any hashing choice is made.

**Recommendation: do not attempt live processing fan-out as a follow-on to CT4.**
If it is ever attempted, it needs its own page, and the first thing that page has
to answer is what replaces `final_sweep`'s single well-defined moment.

## 5. The experiment, and the result that means "do not ship"

### Instruments

`KERNEL_DROPPED` / `IFACE_DROPPED`
([`live.rs:761`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L761)) are the loss counters;
`sipnab_capture_queue_depth_packets` and
`sipnab_capture_backpressure_blocks_total` are the regime discriminator (§3).
Both are read from the same process under test, which is why the controls below
are not optional.

### Controls, which come from the harness that already exists

[`bench/live-capture.sh`](../../bench/live-capture.sh) runs two controls before
any measurement, and either failing writes nothing:

- **Observability canary.** A known small count is replayed and `packets_total`
  must equal it exactly, because *"a veth with the link down, a wrong `-d`, or a
  scraper on the wrong side of the namespace all yield packets_total 0 and
  kernel_dropped 0 — indistinguishable from a flawless capture."*
- **Drop-instrument calibration.** The top rung is run once with a 2 MiB ring and
  **both** `_quality_degraded == 1` and `kernel_dropped > 0` are required,
  because `pcap_stats` failure is swallowed at `debug!`
  ([`live.rs:523`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L523)) while the default level is `info`
   — *"a broken stats path reports a flawless capture."* (The script cites
  `live.rs:344` for that swallow; the file has drifted and the current line is
  `:523`. The reasoning is unaffected.)

A fanout experiment needs a third control of its own: **the sockets must be
proven to be in one group.** Every socket seeing every packet, and every socket
in a group of one, both look like fanout working. The check is arithmetic:
summing per-thread packet counts must equal `packets_total`, and no single
thread may account for all of it. Without a per-thread counter — which does not
exist today — this control cannot be run, and it is a build prerequisite, not
an afterthought.

### The measurement

Fixed corpus from [`bench/carrier.py`](../../bench/carrier.py), fixed offered
rate ladder, `--cores` in `{1, 2, 4, 8}`, five runs per cell, in the private
netns. Record at each cell: `kernel_dropped`, `interface_dropped`, queue depth,
backpressure blocks, per-thread packet counts.

The decision point is **the lowest offered rate at which `--cores 1` drops**.
That is the only rate where the question is live; below it nothing is broken and
above it every configuration is failing.

### What each result means

| Result at the decision rate | Meaning |
|---|---|
| `--cores 1` drops with queue depth at capacity and backpressure climbing | Processor-bound. Fanout cannot help. **Do not ship.** Record it in V1 and close CT4 as measured-and-refuted |
| `--cores 4` reduces `kernel_dropped` by less than the spread of five `--cores 1` runs | No demonstrated benefit. **Do not ship** |
| `--cores 1` never drops at the harness's maximum offered rate | There is no problem in reach of the harness. **Do not ship yet** — the correct output is a note under V1 that the netns cannot generate the load, and the question moves to a real NIC |
| `--cores 4` cuts `kernel_dropped` materially with queue depth low | Drainer-bound and fanout works. Ship, with §2's three obligations |

### And then the real NIC

The netns veth is not a driver, and
[`bench/field-report.sh`](../../bench/field-report.sh) exists precisely because
*"Everything sipnab knows about its own capture path has been measured on
synthetic traffic: a `veth` pair in a namespace, or a file replayed from disk.
Neither exercises a real driver carrying real calls."* A netns result is
necessary and not sufficient; V1 is not closed by it. That is why §3's
`capture_health` gap matters — the field script reads counters over MCP, and
today it cannot read the two that decide this question.

## 6. CT11 is not next, and its own entry says so

CT11 proposes a hand-written cBPF program passed to `fanout_set_data_cbpf()`
that returns a worker index, pinning ports 5060/5061 to worker 0 so all
signalling is co-located with nothing having to hash it. Its stated condition:
*"Worth doing only after CT4 ships and only if cross-worker call correlation is
measured to be a real cost."*

**Under CT4 as built, cross-worker correlation is not a cost at all — there are
no workers.** Every socket feeds one channel and one store, so `HASH`'s inability
to co-locate a call's SIP with its media is invisible: the association happens
downstream of the merge point that does not exist, in a single loop that sees
both. CT11's premise is a processing pool, which §4 recommends against building.

Two further reasons not to reach for it even then:

- **It fixes one of the two cross-worker problems.** cBPF steering puts SIP and
  media on one worker. It does nothing for the proxied-dialog split — one
  Call-ID on two host pairs — which `parallel.rs` measured at 1173 of 2311
  dialogs and which `DialogStore::merge` exists to repair.
- **Worker 0 becomes the signalling hotspot.** All 5060/5061 on one core is a new
  serial stage on a signalling-heavy link, which is the load a SIP capture tool
  most often meets.

CT11's own unverified caveat also stands and should be carried forward verbatim:
that `bpf_prog_create_from_user()` contains no capability check beyond
`SOCK_FILTER_LOCKED` is *"unverified — confirm in `net/core/filter.c` before
relying on the 'no CAP_BPF' claim."* The neighbouring claim about
`fanout_add()` was verified by running it
([`fanout.rs:183`](https://github.com/NormB/sipnab/blob/main/src/capture/fanout.rs#L183)); this one has not been, and
reading kernel source is not the same as running against the kernel that is
installed.

**Recommendation: re-file CT11 as blocked on a design that does not exist**,
rather than as CT4's follow-on.

## 7. Recommendation

1. **Add queue depth and backpressure blocks to `CaptureCounters`.** Small,
   independently useful, and without it the field measurement cannot be taken.
2. **Add a per-thread packet counter to `capture_live_group`.** Needed as the
   third control; without it "fanout worked" is unfalsifiable.
3. **Run §5.** In the netns first, then via `field-report.sh` on a real NIC.
4. **Wire `--cores` into the `Live` arm only if §5 says drainer-bound**, with
   §2's three obligations and §2.1's buffer question answered by the same data.
5. **Leave CT11 filed as blocked**, and leave live processing fan-out unbuilt.

## 8. Open questions

Things this page could not answer from the code, listed so the next reader does
not mistake them for settled.

- **Does one fanout group accept sockets bound to different interfaces?**
  Unverified. Decides whether `--cores` can ever compose with `--multi-device`,
  and whether `fanout_group_id` must become per-device (§2.2).
- **Should `--cores N` multiply or divide `buffer_mb`?** Not decidable from the
  code; §5's data decides it (§2.1).
- **What offered rate can the netns harness actually reach?** Unknown. If it
  cannot make `--cores 1` drop, the whole experiment relocates to a real NIC and
  the netns result is a control, not a measurement.
- **Does `ROLLOVER` change the answer?** `FANOUT_HASH_WITH_ROLLOVER`
  ([`fanout.rs:47`](https://github.com/NormB/sipnab/blob/main/src/capture/fanout.rs#L47)) lets a full ring spill to
  another member. That should reduce drops and also breaks the symmetric-hash
  guarantee for the spilled packets. Harmless under capture-only fanout (one
  store), and a correctness question the moment processing is sharded. Nobody has
  measured how often rollover fires.
- **What does `PACKET_FANOUT` do on the `any` pseudo-device?**
  `join_fanout_group`'s doc names `any` as a possible `ENOPROTOOPT` source
  ([`fanout.rs:67-68`](https://github.com/NormB/sipnab/blob/main/src/capture/fanout.rs#L67-L68)) but marks it "on some
  kernels". The zero-argument default sniffs all interfaces via `any`
  ([`cli.rs:348-349`](https://github.com/NormB/sipnab/blob/main/src/cli.rs#L348-L349)), so this is the *default* invocation,
  not an edge case. The probe at [`live.rs:293`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L293) will
  catch it and fall back — the open question is whether the most common
  invocation silently gets no benefit.
- **Is `immediate_mode` right for N sockets?** `immediate_mode_for`
  ([`bootstrap.rs:1939`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L1939)) returns true only for the
  TUI. Whether the batched setting interacts with rollover or with N drainers is
  unexamined.
