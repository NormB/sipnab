# sipnab — fault model and failure-path test coverage

How sipnab behaves under hostile and degraded conditions: the fault
classes a SIP/RTP capture tool faces, the invariants each surface
guarantees, and the tests that pin them.

A capture tool ingests bytes from an untrusted network. The governing
rule is: **no sequence of bytes an attacker can put on the wire (or in a
capture file) may panic, hang, or grow memory without bound.** A panic
in a parser is a remote DoS on the capture process.

Date: 2026-06-12.

---

## 1. Fault classes

| # | Class | Surface | Invariant |
|---|-------|---------|-----------|
| 1 | **Hostile packet bytes** | every parser reachable from raw frames | parse returns `Result`/`Option`, never panics; bounded work + allocation |
| 2 | **Hostile capture file** | pcap/pcapng reader | malformed/truncated file → clean error or `None`, never panic |
| 3 | **Resource exhaustion** | dialog table, RTP stream table, reassembly, audio buffers | every attacker-keyed store has a ceiling + evicts; memory bounded under unique-key floods |
| 4 | **Capture-source faults** | live capture loop | iface down / perms / transient recv error → clean error, no hang |
| 5 | **Output-sink faults** | json / prometheus / fail2ban / event_exec / api | write failure propagates via `?`; packet data is shell-escaped (env-var exec) and log-sanitized |
| 6 | **Concurrency / shutdown** | channels, signals, locks | Ctrl-C drains cleanly; `parking_lot` locks (no poison cascade); closed-peer sends handled |

## 2. Parser panic surface (class 1 & 2)

Two harnesses exercise every parser reachable from packet or file bytes
layers:

- **Coverage-guided fuzzing**: [`fuzz/fuzz_targets/`](https://github.com/NormB/sipnab/tree/main/fuzz/fuzz_targets) (cargo-fuzz /
  libFuzzer) — 16 targets: sip, sdp, rtp, rtcp, hep, websocket,
  filter-dsl, stir-shaken, tls-records, srtp-keys, keylog-line,
  pcap-reader, dtls, tcp-reassembly, siprec, rtpengine-ng. Run weekly (and on demand)
  via [`.github/workflows/fuzz.yml`](https://github.com/NormB/sipnab/blob/main/.github/workflows/fuzz.yml); crash reproducers upload as artifacts.
- **Always-on smoke fuzz**: [`tests/smoke_fuzz_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/smoke_fuzz_test.rs) runs in
  `cargo test` (no nightly needed) — ~40k random + structurally mutated
  inputs per entry point under `catch_unwind`, covering the same parser
  set **plus** the full link-layer decap chain (`parse_packet` across
  several link types) and the pcap file reader. A caught panic fails the
  test with the offending input hex-dumped for a repro seed.

The smoke layer is the regression floor. It found the keylog panic in §5
that nobody had ever run the committed fuzz target against.

- **Property tests**: [`tests/property_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/property_test.rs) (proptest) asserts the
  *semantic* invariants the fuzzers cannot — a SIP message built from
  generated fields parses back to those fields, SDP survives a
  build→parse→rebuild round trip, and the filter DSL is a total function
  on arbitrary text (parse then evaluate never panic).

**Verified bounded already in code** (confirmed by audit, exercised by
<!-- A list whose items carry their own parentheses and units. Semicolons are the
separator that keeps it readable -- the super-comma use Google's own guidance
keeps. Splitting on periods would turn one list into eight fragments. -->
<!-- vale Google.Semicolons = NO -->

fuzz): SIP header count (≤200) and fold size (≤8 KB); websocket payload
(≤64 KB); TLS record length (≤18432); IP/GRE encapsulation depth (≤5);
RTP CSRC / RTCP report counts (5-bit fields); all length-driven
<!-- vale Google.Semicolons = YES -->

`Vec::with_capacity` sites bounded by the actual slice. RTP/RTCP
length-field arithmetic (`u16 * 4`) cannot overflow `usize`, and each
multiply carries a bounds `ensure!` after it.

## 3. Resource bounds (class 3)

The #1 memory-DoS surface: an attacker invents unlimited unique Call-IDs
(dialog table) or SSRCs (RTP stream table) to exhaust RAM.

| Store | Cap | Policy | Bound proven by |
|-------|-----|--------|-----------------|
| `DialogStore` | `--limit` | LRU evict oldest at cap (default); `--no-rotate` → drop-new at cap | [`tests/resource_bounds_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/resource_bounds_test.rs) (50k unique Call-IDs, both modes, `len() ≤ cap` at every step) |
| `StreamStore` | `--max-streams` | always evict oldest | same test (50k unique SSRCs) |
| per-dialog messages | 500 | drop past cap | `dialog_store.rs` unit tests |
| per-stream audio frames | 1500 | ring buffer | `stream_store.rs` |
| IP/TCP reassembly | 10k entries / 30 s TTL | evict | `reassembly.rs` |

Both eviction policies are memory-safe. `rotate=true` is the default and is
LRU. `rotate=false`, which `--no-rotate` selects, trades availability (new
calls dropped under a flood) for never evicting a tracked dialog.

## 4. Capture, sink, concurrency (classes 4–6)

Audited, found sound (true-positive findings: none):

- **Capture file** (`pcap_reader.rs`): magic/length/block-truncation all
  return clean errors; tested (`too_short_file`, `invalid_magic`,
  `truncated_epb_block_no_panic`) and smoke-fuzzed.
- **Live loop** (`capture/live.rs`): device-open and BPF-compile
  failures return clean errors via the ready channel; receiver-dropped
  breaks cleanly. A transient `recv()` error is currently fatal to the
  capture thread — acceptable, but untested (see §6 gaps). The thread
  ends by returning the error rather than panicking; the run that joins
  it then logs at error level and exits non-zero, because a capture that
  stopped early leaves every report above it resting on a partial read.
  Until 0.5.83 that join downgraded the error to a warning and the
  process exited 0, which made an incomplete run indistinguishable from
  a whole one to anything reading `$?`.
- **event_exec**: packet-derived fields travel as `$SIPNAB_*` env
  vars, never shell-interpolated (no command injection); spawn queue
  capped at 100; children reaped. Tested.
- **Log/JSON sinks**: `serde` escaping; `\r\n` stripped from alert log
  values (log-injection guard, tested). Writes use `?`, no `unwrap`.
- **HTTP sinks** (api, prometheus): read/write timeouts set
  (slow-loris), connection cap via semaphore (503 over limit).
- **Shutdown**: atomic-flag signal handlers (`signals.rs`, tested);
  `parking_lot` locks cannot poison; closed-channel sends checked.
- **`unsafe`** (16 blocks, all in `privilege.rs` / `signals.rs` /
  `playback.rs` / `alerting.rs` / `cli_print.rs`): libc syscalls with no
  attacker-controlled pointer/length; RAII/Drop-guarded fd ops.

## 5. Fixed this pass

- **`decode_hex` UTF-8 char-boundary panic** ([`src/capture/tls.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/tls.rs)):
  the TLS keylog hex decoder checked **byte**-length parity, then sliced
  `&hex[i..i+2]` as a `str`. A multi-byte UTF-8 char (e.g. `€`, 3 bytes)
  split by the 2-char window panicked with "byte index is not a char
  boundary" — a remote DoS via a crafted `SSLKEYLOGFILE` line. Fixed by
  decoding on raw bytes with explicit nibble validation; any non-ASCII /
  non-hex byte is now a clean parse error. Regression:
  `decode_hex_multibyte_utf8_does_not_panic` + corpus seeds in
  [`fuzz/corpus/keylog_line/`](https://github.com/NormB/sipnab/tree/main/fuzz/corpus/keylog_line). Found by the smoke-fuzz harness.
- **Stale fuzz target** ([`fuzz/fuzz_targets/sip_parser.rs`](https://github.com/NormB/sipnab/blob/main/fuzz/fuzz_targets/sip_parser.rs)): passed a
  `&str` transport arg where the current `parse_sip` takes
  `TransportProto`, so the fuzz suite no longer compiled. Updated; the
  smoke harness now also compile-checks every fuzz entry-point signature
  so the suite cannot silently bit-rot again.

## 6. Known gaps (deliberate / lower priority)

- Live-capture **transient recv error** is fatal to the capture thread
  (clean exit, logged) — a retry-N-times policy could be more resilient;
  untested (needs a fault-injecting capture source).
- **Interface-down mid-capture** funnels into the same fatal recv path;
  untested.
- **Opus decode** (`rtp/opus_decode.rs`) delegates to the external
  `libopus`; its FFI input is length-checked but the codec itself is not
  fuzzed here.
- No disk-full test for the pcap/wav writers (writes propagate `?`; no
  panic, but no test covers the error path).
