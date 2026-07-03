# Benchmark baselines

Reference numbers for spotting regressions and measuring WS4.x optimization
work (see `MAINTAINABILITY-PERF-SPEC.md`). Criterion's own history lives in
`target/criterion` and does not survive `cargo clean`; the durable record is
this file. Run with `cargo bench --profile profiling` (mandatory — see
CONTRIBUTING.md "Running Benchmarks").

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

Side effect worth knowing: `SipMessage` *clones* also got cheaper — header
names are now mostly `Cow::Borrowed` statics, so a clone copies pointers
instead of re-allocating every name (visible as `insert_clone` ≈ 2.2 µs in
a follow-up `msg_pipeline` run; that run's other intervals were too noisy
to record as baselines).
