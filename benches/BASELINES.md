# Benchmark baselines

Reference numbers for spotting regressions and measuring WS4.x optimization
work (see `../docs/design/maintainability-perf-spec.md`). Criterion's own history lives in
`target/criterion` and does not survive `cargo clean`; the durable record is
this file. Run with `cargo bench --profile profiling` (mandatory — see
CONTRIBUTING.md "Running Benchmarks").

> **What this file is, and is not.** Every entry below is a *historical*
> measurement, stamped with the date, host and toolchain it was taken on. None
> of them is re-verified against current `main`, and nothing in CI compares
> against them — the `Benchmarks (execute)` job in `quality.yml` runs each
> suite once to prove it still executes, which is a much weaker claim than "no
> regression". Read an entry as "this was true then, on that toolchain", not as
> a statement about the code today. The most recent entry predates the
> project's move to the 1.97.1 toolchain pin, so even the compiler differs.
>
> To make a number here current, re-run the suite and add a new dated entry.
> Do not edit an old one: the value of a baseline is that it records what was
> actually measured, and rewriting it destroys exactly that.

## 2026-08-15 — thor-02 (aarch64, Linux 6.8.12-rt-tegra, 14 cores), rustc 1.97.1, at 0.5.101

**Not comparable to the entries below.** Every earlier baseline in this file was
taken on opensips-1 — x86\_64 Debian, rustc 1.94. This is a different
architecture *and* a different compiler, so a smaller or larger number here is
not a regression or an improvement against them; it is a measurement of a
different machine. Recorded as a first aarch64 baseline, to be compared against
future aarch64 runs and nothing else.

Taken at `064a1d0b`, the tree as released for 0.5.101, with
`cargo bench --profile profiling`. Host idle 97-99% at launch (`vmstat`), no
other workload running. Criterion medians; 36 outlier notices across the run,
which is ordinary for a 14-core box and is why the widest-variance rows are
called out below rather than presented as tight.

### Parser

| case | median |
|---|---|
| sip_parser/parse_invite | 606.62 ns |
| sip_parser/parse_200ok | 404.93 ns |
| sip_scaling/via_headers/1 | 413.10 ns |
| sip_scaling/via_headers/5 | 599.27 ns |
| sip_scaling/via_headers/10 | 902.21 ns |
| sip_scaling/via_headers/20 | 1.6659 µs |
| sdp_parser/parse_sdp | 926.30 ns |
| rtp_parser/parse_rtp_header | 1.7321 ns |
| filter_dsl/parse_complex_filter | 25.041 µs |

`via_headers` scales close to linearly from 5 to 20 (599 ns → 1.67 µs for 4×
the headers), which is the property that matters: a proxy chain does not make
parsing super-linear.

### Detection and decapsulation

| case | median |
|---|---|
| sip_detection/is_sip_message_true | 12.824 ns |
| sip_detection/is_sip_message_false | 6.9271 ns |
| rtp_detection/is_rtp_packet_true | 769.57 ps |
| rtp_detection/is_rtp_packet_false | 385.19 ps |
| packet_decap/eth_ipv4_udp_160b | 99.675 ns |
| packet_decap/payload_slice_zero_copy | 18.321 ns |
| packet_decap/payload_copy_to_vec | 12.250 ns |

The negative case is cheaper than the positive one in both detectors, which is
the right way round: most packets on a busy trunk are neither.

`payload_copy_to_vec` measuring *faster* than `payload_slice_zero_copy`
(12.250 ns vs 18.321 ns) is the one result here that should not be read at face
value. At this scale both are within a few nanoseconds of measurement floor and
allocator warmth, and the names invite exactly the wrong conclusion. Do not cite
this pair as evidence that copying beats slicing.

### Packet path and stores

| case | median |
|---|---|
| packet_process/udp_rtp_160b | 125.88 ns |
| packet_process/udp_sip_invite | 125.75 ns |
| packet_process/tcp_sip_single_segment | 1.3550 µs |
| msg_pipeline/parse_and_insert | 2.6779 µs |
| msg_pipeline/insert_move | 1.5991 µs |
| msg_pipeline/insert_clone | 2.3046 µs |
| dialog_store/message_existing_dialog | 490.26 ns |
| dialog_store/new_dialog_at_cap_10k_rotate | 4.3433 µs |
| stream_store/rtp_existing_stream | 139.20 ns |
| stream_store/rtcp_match_1000_streams | 207.56 ns |

`rtcp_match_1000_streams` at 207 ns says the RTCP-to-stream match is not doing a
linear scan of a thousand streams.

### TUI derived state

| case | median |
|---|---|
| tui_derived/displayed_10k_plain | 5.2868 µs |
| tui_derived/search_frame_10k | 108.15 µs |
| tui_derived/prepare_ladder_200 | 168.21 µs |
| tui_derived/ladder_frame_200 | 112.37 µs |
| tui_derived/displayed_10k_search_miss | 2.1909 ms |

`displayed_10k_search_miss` is the outlier worth knowing: **2.19 ms**, roughly
400× `displayed_10k_plain`, because a search that matches nothing must touch
every one of ten thousand rows. At 2 ms it is still under a frame, but it is the
row to watch if the retention cap ever rises.


## 2026-07-06 — opensips-1, rustc 1.96, WS5f + WS4.3c result

The layout/style split (WS5f) plus the cross-tick ladder cache (WS4.3c):
`App::sync_caches` lays out the ladder at most once, keyed on the dialog
fingerprint + every layout input (and the whole-store generation in
extended mode, so `find_correlated` and the leg merge also run only on a
miss); the render pass re-styles the cached rows. RTP codec segments are
recomputed only when the stream store structurally changes.

| case | before | after | delta |
|---|---|---|---|
| ladder_frame_200 (new: full frame via App::render) | 313 µs | 134 µs | **−57% (2.3×)** — repeated frames run style+paint only |
| prepare_ladder_200 (one-shot layout+style) | 183 µs | 211 µs | +14% — the split's extra row-materialization pass, paid once per change instead of every frame |

## 2026-07-06 — opensips-1, rustc 1.94, WS4.3b result

After the derived-data work (displayed list computed at most once per tick,
cached across ticks keyed on the store generation + view inputs;
allocation-free ASCII-case-insensitive search):

| case | before | after | delta |
|---|---|---|---|
| search_frame_10k | 33.2 ms | 130 µs | **−99.6% (256×)** — repeated frames are pure cache hits |
| displayed_10k_search_miss | 11.5 ms | 6.27 ms | −45.5% — one cold search pass, no more per-message lowercasing |
| displayed_10k_plain | 2.90 µs | 2.93 µs | unchanged |
| prepare_ladder_200 | 183 µs | 180 µs | unchanged (WS4.3c next) |

Acceptance (≥ 5× on the search frame) exceeded by ~50×.

## 2026-07-06 — opensips-1, rustc 1.94, WS4.3 baseline (pre-optimization)

New `tui_derived` bench, recorded BEFORE the WS4.3 derived-data work so the
acceptance delta (≥ 5× on the search frame) is measurable. 10k-dialog store.

| case | time | note |
|---|---|---|
| displayed_10k_plain | 2.90 µs | filter+sort pass, no search |
| displayed_10k_search_miss | 11.5 ms | one full-text search pass (lowercases every message body) |
| search_frame_10k | 33.2 ms | one REAL App::render frame with active search — ≈ 3 × the search pass, confirming the triple recompute; eats the whole 30 fps budget |
| prepare_ladder_200 | 183 µs | CallFlow prepare_messages, 200-message dialog |

## 2026-07-03 — opensips-1 (Debian 13, x86_64), rustc 1.94, WS0 baseline

Recorded immediately after the WS0 quick wins (post `parallel.rs` clone
removal, pre WS4.1 parser-allocation work). Mean point estimates.

### packet_process (PacketProcessor::process, end to end)

| case | time | throughput |
|---|---|---|
| udp_rtp_160b | 101.1 ns | 9.89 M pkt/s |
| udp_sip_invite | 101.6 ns | 9.84 M pkt/s |
| tcp_sip_single_segment (fresh session) | 1.634 µs | 612 K pkt/s |

### msg_pipeline (parse → DialogStore::process_message)

| case | time | note |
|---|---|---|
| parse_and_insert | 3.876 µs | full per-SIP-message cost |
| insert_move | 2.431 µs | store insert, message moved |
| insert_clone | 2.895 µs | store insert + deep clone |

The **clone-vs-move delta is ~464 ns/message (+19% on insert)** — the cost
the `--jobs` path paid before WS0.1 and the batch path still pays until WS1
(structural; see the spec's WS0.1 scope correction).

### sip_parser / sip_scaling (parse_sip_bytes)

| case | time |
|---|---|
| parse_invite (11 headers + SDP) | 1.258 µs |
| parse_200ok (7 headers) | 937 ns |
| via_headers/1 | 964 ns |
| via_headers/5 | 1.488 µs |
| via_headers/10 | 1.994 µs |
| via_headers/20 | 3.808 µs |

Per-Via marginal cost ≈ 115 ns/header (1→10), rising to ≈ 181 ns/header
(10→20). WS4.1 (canonical header-name table, lazy unfold buffer,
`Vec::with_capacity`) should flatten this slope — re-measure here after.

## 2026-07-03 — same host, after WS4.1 (parser allocation reduction)

Steps 1–3 landed: exact-match canonical-name table (static `Cow::Borrowed`
names), lazy `Cow` unfold buffer (per-line copy only materializes on a real
continuation line), `Vec::with_capacity(16)`. Common-case allocations per
header: 3 → 1 (only the value `String` remains; removing it is the
`[SEMVER]` step 4, deferred to 0.5.0).

| case | before | after | delta |
|---|---|---|---|
| parse_invite | 1.258 µs | 920 ns | −27% |
| parse_200ok | 937 ns | 613 ns | −35% |
| via_headers/1 | 964 ns | 610 ns | −37% |
| via_headers/5 | 1.488 µs | 867 ns | −42% |
| via_headers/10 | 1.994 µs | 1.236 µs | −38% |
| via_headers/20 | 3.808 µs | 2.248 µs | −41% |

Per-Via marginal cost: ≈ 70 ns/header (1→10), ≈ 101 ns/header (10→20).

## 2026-07-04 — same host, after WS4.4 (PacketProcessor::process → SmallVec)

`process()` returned a heap `Vec<ParsedPacket>` per input packet; the
dominant cases (UDP, single-frame TCP, one reassembled fragment) yield
exactly one packet, so the return is now `SmallVec<[ParsedPacket; 1]>`
(`ParsedPackets`) — inline, no allocation. Criterion before/after on the
same tree base (clean baseline via `git stash`, statistically significant
p < 0.05):

| case | before | after | delta |
|---|---|---|---|
| udp_rtp_160b | 104.3 ns | 96.9 ns | −5.9% |
| udp_sip_invite | 103.1 ns | 93.2 ns | −5.3% |
| tcp_sip_single_segment | 1.398 µs | 1.333 µs | −3.7% |

The UDP path is every RTP packet, so this is the highest-volume win.
(smallvec was already a transitive dep via hyper; promoted to direct.)

Side effect worth knowing: `SipMessage` *clones* also got cheaper — header
names are now mostly `Cow::Borrowed` statics, so a clone copies pointers
instead of re-allocating every name (visible as `insert_clone` ≈ 2.2 µs in
a follow-up `msg_pipeline` run; that run's other intervals were too noisy
to record as baselines).
