# Capture tuning — working task list

A execution checklist, not a design doc. Opened 2026-08-03 on branch
`agent/capture-tuning-UNREVIEWED`; that branch was squashed onto `main` the
same day and cut as 0.5.77, so the ticked items below are shipped rather than
in flight. The reasoning behind each item lives in
[`process-isolation-and-hot-path-cost.md`](process-isolation-and-hot-path-cost.md)
and the `CT*`/`G*`/`LK*`/`PI*`/`PR*` entries in
[`backlog.md`](backlog.md); this page is only *what is left to do, in what
order*.

**Ground rules for anyone working from this file**

- Gates are `cargo fmt --check`, `cargo clippy --features full -- -D warnings`,
  `cargo test --features full`. All three, every time.
- **Capture real exit codes.** Piping cargo into `tail` and reading `$?` reads
  `tail`'s status and hides failures — that happened in this session and
  produced a false "all green". Redirect to a file, `echo $?`, grep the file.
- Use a unique `CARGO_TARGET_DIR` per worker. A shared one relinked a stale
  binary here once already.
- Tests alongside the implementation, never batched at the end.
- Nothing on this page has been measured on a live NIC. Every throughput claim
  is reasoned from syscall counts and ring arithmetic. Do not upgrade a
  reasoned claim to a measured one without the measurement.

---

## 0. Blocking — clear these before anything else

- [x] **B1 — Rebase the branch onto current `main`.** Done. The merge base was
  already `6465c61`, so only `b63f122` ("Wait for the hook to finish instead of
  sleeping and hoping") had to be replayed under. It touches the `fire_n` test
  helper in [`src/output/event_exec.rs`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs), which LK1 did not, so the rebase took
  no conflict.
- [x] **B2 — Fix the known-failing gate.** Done, and it was four pins rather
  than one: tracked-markdown 121 → 125 and tables 437 → 443 in
  `docs_drift_test.rs`, wiki-links 254 → 268 and docs-pages 34 → 35 in
  `link_integrity_test.rs`, plus `linked_code_targets_exist` 283 → 290 in
  `dev_docs_drift_test.rs`. Each carries a comment naming the doc that raised
  it. `every_site_operator_page_is_in_every_docs_nav` also fired, correctly:
  the new page had been registered in `build-wiki.py` alone, so the site
  generated no mirror and `troubleshooting.md`'s three pointers at the drop
  diagnosis rewrote to GitHub blob URLs — the site's own high-loss workflow
  ended by leaving the site. Registered in `build-site-pages.py`'s `PAGES`,
  `build-site-internals.py`'s `DOCS_TO_SITE`, and the nav in `base.html`,
  `page.html` and `section.html`.
- [x] **B3 — Re-run the full gate against the BRANCH.** Done, with real exit
  codes captured to a file rather than piped. Recorded in the merge commit.
- [x] **B4 — Reconcile the four in-flight agents' edits.** Done. Six agents in
  the end; no file was written by two. LK1 was re-reviewed rather than taken on
  report, because it reported complete while the branch could not compile: the
  deferred-effects tests were rebuilt to drive the real path and assert the
  drained side effects, and the rate-limit reservation, queue-depth cap and
  child reaping were each checked as untouched.

---

## 1. Tier 1 — P0

- [x] **CT1b — Make capture loss queryable, not just logged.** Shipped. The
  three counters travel as one `capture_quality` block — kernel drops,
  interface drops and invalid timestamps kept separate because the remedies
  disagree — through `/v1/stats`, the MCP `stats` tool and Prometheus, with a
  single `degraded` flag named for the direction there is evidence for. `G1`
  shipped folded into it as planned.
- [x] **CT7 — TPACKET_V3 selection.** Shipped. `immediate_mode_for()` in
  [`src/app/bootstrap.rs`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs) answers it by run mode: on for the TUI, off for every
  headless run. The V3 timeout trap was handled rather than inherited —
  `BATCHED_READ_TIMEOUT_MS = 5` replaces the interactive 100 ms on the batched
  path, because libpcap copies the read timeout into `tp_retire_blk_tov` and
  polls with `-1`. **Still needs live-NIC verification**: that V3 is actually
  selected, and what it is worth, are reasoned from libpcap's source. See V1.
- [x] **G7 — `$SIPNAB_AUDIO_PLUGIN` is `dlopen`ed ahead of trusted paths.**
  Shipped. Tried last rather than first, and only when the process gained no
  privileges at `execve` and the file is a regular file owned by root or the
  invoker, not group- or world-writable, in a directory that is not either.
  Every refusal names its reason.
- [ ] **CT2b — Justify the 64 MiB default with a measurement.** The default was
  raised 2 → 64 MiB with a halving fallback ladder, but the "prove it against a
  measured `dropped` of zero at line rate" half of CT2 is not done — and CT7
  caps how much of it is realisable.
- [ ] **CT7b — No escape hatch back to immediate mode on a headless run.**
  CT7 decides the ring by run mode with nothing an operator can say about it.
  A headless run that genuinely wants per-packet delivery — a `--json` feed
  driving a real-time reaction — has no way to ask for it. Split out of CT5
  rather than left implied by it.

## 2. Tier 2 — P1

- [x] **LK1 — Side effects out of the double store write-lock.** Shipped.
  `DeferredEffects` carries a packet's output, alert findings and hook commands
  out of the guarded section; `EventExecEngine::queue_*` decides a hook under
  the guards (where it needs the store) and `dispatch_pending` spawns it after
  they drop. `TumblingWindow::allows_with_reserved` declares the decisions
  parked in between, so `--exec-rate-limit N` still means N rather than N plus
  whatever was in flight. The `stores → alerts` rule is in `invariants.md`.
  Asserted directly rather than by proxy:
  `side_effects_are_raised_under_the_guards_and_performed_after_them` proves
  the guards are still held (`try_read().is_none()`) while `outcomes().spawned`
  is 0 and `pending_depth()` is 1 — because nothing about a capture's OUTPUT
  changes if this regresses. The *performance* claim is **reasoned, not
  measured**; the *parity* claim is measured, below.
  - **Output parity settled, and the one outlier explained.** A pre-LK1 and a
    post-LK1 release binary, differing in exactly three files
    ([`src/app/batch.rs`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs), [`src/output/event_exec.rs`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs),
    [`src/security/alerting.rs`](https://github.com/NormB/sipnab/blob/main/src/security/alerting.rs)) and nothing else, agree byte for byte over the
    whole reference corpus once the two fields that cannot match across
    processes — the fail2ban jail line's `Local::now()` and
    `std::process::id()` — are normalized away. The one file that mismatched
    on an early normalized sweep was re-run on an idle box, 60 paired
    iterations plus 60 self-versus-self iterations per binary: **0
    mismatches**, one distinct output hash per binary, and the *same* hash for
    both. It was not nondeterminism and not an ordering bug. The early
    normalizer stripped the PID and left the timestamp, and that file's
    detectors output spans a wall-clock second — replaying it with a PID-only
    normalizer reproduces the mismatch 29 times in 40, while 14 runs in 40
    carry more than one second in their own output. A partial normalizer, not
    `DeferredEffects`.
- [x] **G6 — `--cores N` silently ignored on live capture.** Shipped as a
  warning rather than a refusal: unlike the neighboring `--cores` +
  `--json`/`-O` check, which exits 2 because that combination emits nothing,
  here the output is complete and only the parallelism is missing, so refusing
  would break invocations that work today.

## 3. Tier 3 — P2

- [ ] **CT4 — `PACKET_FANOUT` for multicore live capture.** The single largest
  live-capture win still on the table, and **cheaper than first assessed**:
  `fanout_add()` accepts an already-bound, ring-mapped socket and the `pcap`
  crate exposes `AsRawFd for Capture<Active>`, so it is one `setsockopt` on a
  normal libpcap handle — **no libpcap fork**. `PACKET_FANOUT_HASH` uses
  `__skb_get_hash_symmetric()`, so bidirectional RTP affinity is already free.
  Unblocked: [`src/capture/live.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs) was the CT7 agent's and CT7 has landed.
- [ ] **CT11 — Call-aware fanout steering via `PACKET_FANOUT_CBPF`.** Only
  after CT4, and only if cross-worker SIP/media correlation is *measured* to
  cost something. Hand-written cBPF returning a worker index; no `CAP_BPF`, no
  clang, no BTF. *Unverified:* that `bpf_prog_create_from_user()` has no
  capability check beyond `SOCK_FILTER_LOCKED` — confirm in
  `net/core/filter.c` first.
- [ ] **CT3 — `--snaplen` capture profiles.** Not a bare default change:
  truncation breaks audio reconstruction and degrades `-O` re-emit. Ship named
  profiles, refuse/warn on the incompatible combinations, and surface
  `caplen` vs `origlen`.
- [x] **CT5 — `immediate_mode` as policy rather than a constant.** Closed as
  subsumed: CT7 landed exactly this, as `immediate_mode_for()`. What did NOT
  ship is an escape hatch to force immediate mode back on for a headless run —
  re-scoped and tracked as its own item rather than left implied by this one.
- [ ] **PR1 — Parallel readers so `--cores` can exceed 2×.** **Blocked on an
  unresolved correctness question**: packets would reach a worker interleaved
  across files and therefore out of timestamp order. `DialogStore::merge` is
  order-tolerant, but a *live* worker store is fed by `process_message` in
  arrival order and it is **not established** that out-of-order arrival is
  harmless. Write the `--cores 1` vs parallel-reader parity test over the
  reference corpus **before** writing the feature.
- [x] **CT6 — netmap in the static musl builds.** Shipped in both cross
  Dockerfiles: libpcap 1.10.6 (the first release that reports netmap in
  `pcap_lib_version()`, so presence can be asserted), pinned netmap headers,
  `-include sys/types.h` because musl does not paper over the `u_int` the
  headers use, and an `ar t | grep -qx pcap-netmap.o` assertion so the image
  build fails rather than shipping a binary quietly missing the backend. BSD-2
  notices row included. **Gap still open:** neither image was built here —
  x86_64 musl in particular has never been verified end to end.
- [ ] **CT6b — Report which backends the running binary actually supports.**
  `pcap_lib_version()` and `pcap_findalldevs` already expose this; nothing
  surfaces it. Without it, "set the device string to switch backend" is
  untestable by an operator.
- [ ] **CT6c — Document that backend *availability* differs per artifact.**
  musl tarballs (sipnab controls libpcap), gnu/.deb/Docker (stock Debian
  libpcap), macOS (none). State it rather than implying uniformity.
- [ ] **PI2 — Scanner-kill as a real child process.** Only if `--kill-scanner`
  becomes non-niche. The `KillRequest`/`KillResponse` types are already
  `Serialize`/`Deserialize` — a fossil of the original D16 IPC design.

---

## 4. Documentation cleanup and stale content

Each item is **verify, then fix** — do not delete on the strength of this list
alone.

### 4a. Known-false or self-contradictory claims

- [x] **D1 — `implementation-plan-v6.md` says the store lock is
  "read-heavy, write-rare, so RwLock contention is minimal".** The batch loop
  takes `dialog_store.write()` **once per packet**, so writes are the most
  frequent operation in the process. This is the premise every later contention
  judgement rests on. Correct it in place, per the repo's own "refute your own
  claims in place" norm. *(= G2)*
- [x] **D2 — `invariants.md` §2 contradicts the batch applier.** It states
  "Never hold both write locks simultaneously" and then claims the batch
  applier "holds their stores by `&mut` and so have no ordering to get wrong" —
  but `batch.rs` takes both `write()` guards. Either restate the rule as
  "consistent order, dialog before stream" or make the path match. Coordinate
  with LK1. *(= G3)*
- [x] **D3 — `large-capture-memory.md` describes uncommitted working-tree
  changes as the fix in progress** for the `--cores` multi-file defect. That
  work has since landed (`run_offline_parallel_file` takes a resolved
  `&[PathBuf]`). Re-verify and rewrite as history, or delete.
- [x] **D4 — `architecture.md` D15/D16.** Fixed on this branch (PI1) — it had
  claimed "active responses run in an isolated child", which is false. Confirm
  the fix survives the rebase.

### 4b. Stale by drift

- [x] **D5 — `benchmarks.md` numbers are pinned to 0.5.47** while the crate has
  moved many releases past it. Resolved by date-stamping the claim honestly
  rather than by re-measuring: the page now says when it was last measured and
  that it does not track the crate version. No crate version is named here, so
  this entry cannot go stale the way the page it describes did.
- [ ] **D6 — Sweep `docs/design/*.md` for in-flight language** — "being
  addressed", "uncommitted", "the working tree carries", "shipped 0.5.NN" —
  and resolve each to shipped, dropped, or still-open. *Partly done:* the
  capture-tuning pages are clean. Still carrying it:
  `threat-mitigation-hooks.md` (its header pins the whole page to "`63b771b`
  plus an uncommitted in-flight change", and §119 repeats it) and
  `backlog.md:782`. Neither is capture work, which is why they were left rather
  than swept blind.
- [ ] **D7 — Sweep the two implementation plans** (`implementation-plan-v6.md`
  ~185 KB, `implementation-plan-phases-8-10.md` ~180 KB) for unchecked `- [ ]`
  boxes describing work that shipped. D16's "verified by checking PID differs
  from main" gates are the known example — they describe a process architecture
  that was never built. Mark them as historical, or move them. *Partly done:*
  the D16 boxes now carry an "UNSATISFIABLE, AND NOT OUTSTANDING" annotation
  pointing at `PI2`. The rest of both files is unswept — it is ~365 KB and
  nobody has read it end to end.
- [x] **D8 — Record the declined technologies in
  `deferred-and-declined.md`.** That page's entire job is recording what was
  considered and rejected, and it currently has **no entry** for process
  forking, PF_RING, DPDK, AF_XDP or XDP. Add short entries pointing at the
  detailed verdicts so none of them gets re-proposed.

### 4c. Consistency

- [x] **D9 — Audit every doc that names a capture-tuning default.** `-B` moved
  2 → 64 MiB and its units changed from decimal MB to MiB. Confirm
  `cli-reference.md`, `config-reference.md`, both website mirrors, `examples.md`
  and `troubleshooting.md` all agree with the code.
- [x] **D10 — Cross-link `tuning-capture.md` from `troubleshooting.md`.** The
  "high loss" symptom there should point at the drop-diagnosis section rather
  than duplicating it.

---

## 5. Declined — do not re-propose

Recorded so these are not relitigated. Full reasoning in `backlog.md`.

| | Verdict | Decisive reason |
|---|---|---|
| **DPDK** | Declined | Deleted in libpcap 1.11; not in Debian's build; `selectable_fd = portid` means `dpdk:0` polls **stdin** and captures nothing |
| **PF_RING** | Declined | Proprietary ntop-EULA blobs linked into `libpfring`; incompatible with MIT/Apache-2.0 redistribution; ZC needs a paid per-MAC license |
| **AF_XDP** | Declined | Ingress-only (loses half of every call); no tee, so it steals host traffic; no libpcap module in any version |
| **XDP as a filter** | Declined | Runs *upstream* of the AF_PACKET taps — can only filter *from* sipnab, never *for* it |
| **Fork more broadly** | Declined | Shared `Arc<RwLock<..>>` stores are the product; forking turns every read into a wire protocol |
| **C / assembler rewrite** | Declined | The bottleneck is already C (libpcap); the per-packet copy was measured at ~15 ns and removing it won nothing |

---

## 6. Verification debt

- [ ] **V1 — Nothing is measured on a live NIC.** CT8 (poll-per-packet
  removal), CT7, CT4 and LK1 are all reasoned, not benchmarked. Build a
  live-capture harness with CT1's drop counters as the instrument.
- [ ] **V2 — Calibrate against a real capture ceiling.** Netdev 2.2 puts real
  `tcpdump` on TPACKET_V3 at ~0.74 Mpps at 64 B / ~0.62 Mpps at 1500 B — a
  tighter and more honest target than synthetic `rxdrop` figures.
- [ ] **V3 — Confirm the `any`-device ring arithmetic empirically.** The
  ~1,000-slot figure (and 31 slots at the old 2 MiB default) is derived from
  libpcap's `create_ring()` source, not observed. Verify against a running
  capture.
