# sipnab — fault model and failure-path test coverage

How sipnab behaves under hostile and degraded conditions. This page covers:

- the fault classes a SIP/RTP capture tool faces,
- the invariants each surface guarantees,
- the tests that pin them.

A capture tool ingests bytes from an untrusted network. The governing
rule is: **no sequence of bytes an attacker can put on the wire (or in a
capture file) may panic, hang, or grow memory without bound.** A panic
in a parser is a remote DoS on the capture process.

Date: 2026-06-12.

---

## Fault classes

| # | Class | Surface | Invariant |
|---|-------|---------|-----------|
| 1 | **Hostile packet bytes** | every parser reachable from raw frames | parse returns `Result`/`Option`, never panics; bounded work + allocation |
| 2 | **Hostile capture file** | pcap/pcapng reader | malformed/truncated file → clean error or `None`, never panic |
| 3 | **Resource exhaustion** | dialog table, RTP stream table, reassembly, audio buffers | every attacker-keyed store has a ceiling + evicts; memory bounded under unique-key floods |
| 4 | **Capture-source faults** | live capture loop | iface down / perms / transient recv error → clean error, no hang |
| 5 | **Output-sink faults** | json / prometheus / fail2ban / event_exec / api | write failure propagates via `?`; packet data is shell-escaped (env-var exec) and log-sanitized |
| 6 | **Concurrency / shutdown** | channels, signals, locks | Ctrl-C drains cleanly; `parking_lot` locks (no poison cascade); closed-peer sends handled |

## Parser panic surface (class 1 & 2)

Two harnesses exercise every parser reachable from packet or file bytes
layers:

- **Coverage-guided fuzzing**: [`fuzz/fuzz_targets/`](https://github.com/NormB/sipnab/tree/main/fuzz/fuzz_targets) (cargo-fuzz /
  libFuzzer) — 20 targets: sip, sdp, rtp, rtcp, hep, websocket,
  filter-dsl, stir-shaken, tls-records, srtp-keys, keylog-line,
  pcap-reader, dtls, tcp-reassembly, siprec, rtpengine-ng, stun, llmnr,
  archive-password, g729-decode.
  - They run weekly (and on demand) via [`.github/workflows/fuzz.yml`](https://github.com/NormB/sipnab/blob/main/.github/workflows/fuzz.yml).
  - Crash reproducers upload as artifacts.
- **Continuous fuzzing**: the same targets run under ClusterFuzzLite from
  [`.clusterfuzzlite/`](https://github.com/NormB/sipnab/tree/main/.clusterfuzzlite).
  - Batch fuzzing and corpus pruning run daily. A coverage report runs weekly.
  - The difference from the weekly run above is the corpus.
    It persists between runs instead of restarting from the tracked seeds.
    So what libFuzzer learns accumulates instead of starting over.
- **Always-on smoke fuzz**: [`tests/smoke_fuzz_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/smoke_fuzz_test.rs) runs in
  `cargo test` (no nightly needed).
  - It runs ~40k random + structurally mutated inputs per entry point under `catch_unwind`.
  - It covers the same parser set **plus**:
    - the full link-layer decap chain (`parse_packet` across several link types),
    - the pcap file reader.
  - A caught panic fails the test. The offending input is hex-dumped for a repro seed.
  - Calling every fuzz entry point also compile-checks their signatures.
    So a target that drifts out of step with its parser breaks the test build.
    It does not drop out of the fuzz suite unnoticed.
  - Example: [`fuzz/fuzz_targets/sip_parser.rs`](https://github.com/NormB/sipnab/blob/main/fuzz/fuzz_targets/sip_parser.rs) had passed a `&str` transport
    argument where `parse_sip` takes `TransportProto`.
    The whole suite stopped compiling, with nothing in `cargo test` to say so.

The smoke layer is the regression floor. It found a UTF-8 char-boundary
panic in the TLS keylog hex decoder
([`src/capture/tls.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/tls.rs)).
Nobody had ever run the committed fuzz target against that decoder.

- The decoder checked **byte**-length parity, then sliced `&hex[i..i+2]` as a `str`.
- So a multi-byte UTF-8 char (e.g. `€`, 3 bytes) split by the 2-char window panicked.
  The message was "byte index is not a char boundary".
- That was a remote DoS via a crafted `SSLKEYLOGFILE` line.
- The decoder now works on raw bytes with explicit nibble validation instead.
  Any non-ASCII or non-hex byte gives a clean parse error naming its offset.
- The regression test `decode_hex_multibyte_utf8_does_not_panic` and the corpus seeds in
  [`fuzz/corpus/keylog_line/`](https://github.com/NormB/sipnab/tree/main/fuzz/corpus/keylog_line) pin it there.

- **Property tests**: [`tests/property_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/property_test.rs) (proptest) asserts the
  *semantic* invariants the fuzzers cannot:
  - a SIP message built from generated fields parses back to those fields,
  - SDP survives a build→parse→rebuild round trip,
  - the filter DSL is a total function on arbitrary text (parse then evaluate never panic).

**Verified bounded already in code** (confirmed by audit, exercised by
<!-- A list whose items carry their own parentheses and units. Semicolons are the
separator that keeps it readable -- the super-comma use Google's own guidance
keeps. Splitting on periods would turn one list into eight fragments. -->
<!-- vale Google.Semicolons = NO -->

fuzz): SIP header count (≤200) and fold size (≤8 KB); websocket payload
(≤64 KB); TLS record length (≤18432); IP/GRE encapsulation depth (≤5);
RTP CSRC / RTCP report counts (5-bit fields); all length-driven
<!-- vale Google.Semicolons = YES -->

`Vec::with_capacity` sites bounded by the actual slice.

- RTP/RTCP length-field arithmetic (`u16 * 4`) cannot overflow `usize`.
- Each multiply carries a bounds `ensure!` after it.

## Resource bounds (class 3)

The #1 memory-DoS surface is the attacker-keyed store. An attacker invents unlimited unique values to exhaust RAM:

- Call-IDs (dialog table),
- SSRCs (RTP stream table).

| Store | Cap | Policy | Bound proven by |
|-------|-----|--------|-----------------|
| `DialogStore` | `--limit` | LRU evict oldest at cap (default); `--no-rotate` → drop-new at cap | [`tests/resource_bounds_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/resource_bounds_test.rs) (50k unique Call-IDs, both modes, `len() ≤ cap` at every step) |
| `StreamStore` | `--max-streams` | always evict oldest | same test (50k unique SSRCs) |
| per-dialog messages | 500 | drop past cap | `dialog_store.rs` unit tests |
| per-stream audio frames | 1500 | ring buffer | `stream_store.rs` |
| IP/TCP reassembly | 10k entries / 30 s TTL | evict | `reassembly.rs` |

Both eviction policies are memory-safe.

- `rotate=true` is the default and is LRU.
- `rotate=false`, which `--no-rotate` selects, trades availability for never evicting a tracked dialog.
  Under a flood, sipnab drops new calls.

## Capture, sink, concurrency (classes 4–6)

Audited, found sound (true-positive findings: none):

- **Capture file** (`pcap_reader.rs`):
  - Magic/length/block-truncation all return clean errors.
  - Tests cover them (`too_short_file`, `invalid_magic`, `truncated_epb_block_no_panic`). The smoke fuzz also exercises them.
  - The FILE path now implements the same exit-status rule the live path below states. It did not before.
    - Reading a set deliberately continues past a truncated member and returns `Ok`.
    - So the join never saw it, and a truncated pcap exited 0 with a whole-looking report.
  - `ReadTally::report` is the one place both the single-threaded and `--cores` readers converge on.
    - It now records the same `lost` predicate that decides its log severity into `output::run_integrity`.
    - The exit-code sites and the `--json-dialogs`/`--report` markers read that record.
    - One place emits both the human sentence on stderr and the machine record. So they cannot disagree.
  - A `--plugin` that would not load is the same class and lands the same way
    (exit `1`, `plugins.failed` in the record).
  - The same record also carries idle compaction. Idle compaction deliberately does NOT move the exit status.
    A retention policy doing what you configured it to do is not a failed run.
- **Live loop** (`capture/live.rs`):
  - Device-open and BPF-compile failures return clean errors via the ready channel.
  - Receiver-dropped breaks cleanly.
  - A transient `recv()` error is currently fatal to the capture thread.
    That is acceptable, but untested (see the gaps in
    [the section "Known gaps (deliberate / lower priority)"](#known-gaps-deliberate--lower-priority)).
  - The thread ends by returning the error rather than panicking.
  - The run that joins it then logs at error level and exits non-zero.
    A capture that stopped early leaves every report above it resting on a partial read.
  - The exit status is the only place that distinction survives.
    Downgrade that join to a warning and exit 0, and an incomplete run reads exactly
    like a whole one to anything checking `$?`.
- **event_exec**:
  - Packet-derived fields travel as `$SIPNAB_*` env vars, never shell-interpolated (no command injection).
  - A cap of 100 bounds the spawn queue.
  - sipnab reaps children.
  - Tested.
- **Log/JSON sinks**:
  - `serde` escaping.
  - `\r\n` stripped from alert log values (log-injection guard, tested).
  - Writes use `?`, no `unwrap`.
- **HTTP sinks** (api, prometheus):
  - Read/write timeouts set (slow-loris).
  - Connection cap via semaphore (503 over limit).
- **Shutdown**:
  - Atomic-flag signal handlers (`signals.rs`, tested).
  - `parking_lot` locks cannot poison.
  - Closed-channel sends checked.
- **`unsafe`** (111 blocks outside `#[cfg(test)]`, across 28 files, the
  largest groups in [`src/privilege.rs`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs) (17), [`src/rtp/playback.rs`](https://github.com/NormB/sipnab/blob/main/src/rtp/playback.rs) (10) and
  [`src/capture/uprobe/perf.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/uprobe/perf.rs) (9)):
  - libc and other FFI calls, with RAII/Drop-guarded fd ops.
  - Every block states its own soundness argument.
  - [`Cargo.toml`](https://github.com/NormB/sipnab/blob/main/Cargo.toml) sets clippy's `undocumented_unsafe_blocks` to `warn`.
  - Both the pre-push hook and CI run clippy with `-D warnings`.
    So a block with no adjacent `// SAFETY:` comment fails the build.

## Known gaps (deliberate / lower priority)

- Live-capture **transient recv error** is fatal to the capture thread
  (clean exit, logged).
  - A retry-N-times policy could be more resilient.
  - Untested (needs a fault-injecting capture source).
- **Interface-down mid-capture** funnels into the same fatal recv path.
  Untested.
- **Opus decode** (`rtp/opus_decode.rs`) delegates to the external `libopus`.
  - Its FFI input is length-checked.
  - The codec itself is not fuzzed here.
- No disk-full test for the pcap/wav writers.
  - Writes propagate `?`, so there is no panic.
  - No test covers the error path.
