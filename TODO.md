# sipnab improvement roadmap

Source: four-dimension project analysis (maintainability, survivability,
performance, usability), 2026-06-12. Method: every item lands via its own
branch + PR, TDD (failing test first, red → green), auto-merged when CI-green.

Priorities:
- **P0** — wrong-facing-users now (docs lie, silent failure)
- **P1** — high value / low-to-medium effort
- **P2** — medium value or medium effort
- **P3** — larger, scheduled after P0–P2
- **P4** — major refactors, last in queue

Status: `[ ]` todo · `[~]` in progress · `[x]` merged

---

## P0 — correctness of what users see

- [x] **U1. README advertises CLI flags that don't exist** — `--codec-asym`,
  `--ptime-asym`, `--payload-asym`, `--duration-asym`, `--late-media`
  (README.md:18) are filter-DSL aliases, not flags. Fix README, add a
  drift test asserting every `--flag` named in README exists in cli.rs.
- [x] **S7. Silent timestamp fallback corrupts capture timing** —
  `pcap_ts_to_chrono` (src/capture/live.rs:134) substitutes `Utc::now()` for
  unconvertible timestamps with no log. Warn loudly (rate-limited) and count.

## P1 — high value, tractable

- [x] **M4. CI feature-combination matrix** — CI only builds
  `--all-features`. Add matrix: `native`, `tls`, `api`, `mcp`,
  `native,tui,audio`, `tls,api`, and the headless recipe
  `native,tui,tls,hep,api`. (Test = the CI run itself; local pre-check
  via `cargo check` per combo.)
- [x] **S1. HEP receiver idle timeout** — UDP recv loop blocks forever if the
  upstream sender dies; capture stalls silently. Add idle timeout
  (default 30 s) → rate-limited warning + stat counter.
- [x] **S3. Worker-thread death is invisible** — scanner-kill worker
  (src/process_isolation.rs:82-90) can panic and the main loop never knows;
  defense silently disabled. Add health check (dead-worker detection on the
  handle) + loud error; audit other spawned workers for the same pattern.
- [x] **P4. Call-ID allocated per message just for lookup** —
  dialog_store.rs:101 does `id.to_string()` before `get_mut`. Use
  `Borrow<str>` lookup; allocate only on insert. Bench-verified.
- [x] ~~**P3. Up to 4 stream_store write-locks per RTP packet**~~ —
  INVALID FINDING (verified 2026-06-12): the four `stream_store.write()`
  sites in main.rs are mutually exclusive branches, each ending in
  `return`; every packet takes at most ONE stream-store lock, and parsing
  already happens outside the lock by design. No change needed.
- [x] **P8. Store-layer criterion benchmark** — criterion covers parsers
  only; add dialog_store/stream_store throughput bench so P3/P4/P7/P1
  wins are measurable. (Do BEFORE the store optimizations.)
- [x] **U3. Audio/libasound2 build footgun** — default `audio` feature
  fails at runtime on headless servers with no warning. Add
  `cargo:warning` in build.rs naming the headless recipe; prominent
  README note.
- [x] **S2. Idle-dialog memory creep** — per-dialog message Vec (cap 500)
  never shrinks; with default rotate=false, weeks-long runs accumulate GBs.
  Add age-based message eviction + "idle dialog cleanup" stat.

## P2 — medium

- [x] **P9. Retransmission check is O(messages) with per-message header
  re-parse** — `is_retransmission` (dialog_store.rs:385) scans every stored
  message and calls `existing.cseq()` (header parse) on each: ~16 µs per
  in-dialog message at the 500-message cap — this dominates the dialog hot
  path (found while benchmarking P4; the Call-ID alloc was noise by
  comparison). Maintain a per-dialog set of seen CSeq keys instead
  (`timing.retransmit_counts` already keys by `cseq_key`).
- [x] **P6. O(n) RTCP→stream lookup** — stream_store.rs:110-117 linear-scans
  all streams per RTCP report. Add `ssrc → key` secondary index.
- [x] **P7. O(n) dialog eviction** — `shift_remove_index(0)`
  (dialog_store.rs:356) shifts every entry; visible pause at 10k dialogs.
  O(1)-amortized eviction preserving insertion-order semantics.
- [x] **P5. Audio payload buffered for every RTP packet** —
  stream_store.rs:73,88 clones payload per packet to support an export most
  captures never use. Buffer only when export is possible/requested.
- [x] **M5. Consolidate `Result<_, String>` into structured errors** — 26
  occurrences (config.rs, output/wireshark.rs, rtp/audio_export.rs,
  rtp/playback.rs). Single `thiserror` enum; no stringly-typed errors.
- [x] ~~**M6. Unwrap/expect audit in risk modules**~~ — INVALID FINDING
  (verified 2026-06-12): every flagged file (srtp, dsl, api, matcher,
  crypto, parse, dialog, pcap_reader, parser, config) has ZERO
  unwrap/expect in production code — the analysis counted `#[cfg(test)]`
  modules, where unwrap is idiomatic. Hostile-input panic-freedom is
  separately enforced by tests/smoke_fuzz_test.rs. No change needed.
- [x] **M7. De-flake timing-based tests** — 14 `sleep()` calls
  (security_test.rs ×13, parse_path_test.rs ×2 [agent counts overlap],
  tui_e2e_test.rs ×1). Replace with channel `recv_timeout` / condition
  polling.
- [x] **U5. Filter-DSL error messages** — "unexpected token at position N"
  with no caret, no operator list, no hint for unquoted values
  (`method == INVITE`). Add caret line + suggestions.
- [x] **U2. Document `--filter` alias acceptance** — `--filter problems`
  works (main.rs:2050 expansion) but --help and cli-reference.md don't
  say so.
- [x] **U7. Document JSON/NDJSON output** — schema + jq piping examples
  (README + docs/output-formats.md).
- [x] **U8. Clarify `--no-cli-print` + `--report` interaction** — help text
  + cli-reference.md example for summary-only mode.
- [x] **U9. docs/examples.md cookbook** — top 10-15 real workflows (failed
  calls, export one call's audio, detect scanners, …), linked from README.
- [x] **U6. docs/mcp-setup.md** — token generation, stdio vs HTTP quick
  start, systemd unit.
- [x] **U10. contrib/sipnabrc.example** — shipped example config.
- [x] **U4. TUI help discoverability** — F1 help exists (tui/help.rs) but
  nothing on screen says so. "Press F1 for help" hint in the empty
  call-list state.
- [x] **S6. Disk-full (ENOSPC) handling test** — verify a mid-capture write
  failure produces a loud error and sane file state, not a silently
  truncated pcap.
- [x] ~~**S4. HEP cumulative memory cap / source rate limit**~~ — INVALID
  FINDING (verified 2026-06-12): HEP is bounded at every stage — per-chunk
  u16 lengths validated against the recv buffer (hep.rs), all parse
  allocations are per-packet transient, the listener has a token-bucket
  rate limiter (default 50k pps, `--hep-rate-limit`) + CIDR allowlist,
  and the packet channel is bounded at 10k (main.rs). No change needed.
- [x] **S5. TCP reassembly fragment-count budget** — original memory claim
  INVALID (per-entry 64KB byte-cap + 10k entry cap + 30s TTL already
  bound both reassemblers). Verification found the REAL issue: eviction
  at capacity was an O(n) min-scan + a warn! line PER incoming fragment —
  CPU-DoS + log flood under fragment flood. Fixed with batched eviction
  (cap/100 per O(n log n) sort, one summary log line), same pattern as P7.

## P3 — larger, after P0–P2

- [x] **M3. Move synthetic-packet building out of the TUI** —
  tui/mod.rs:4236-4276 `build_synthetic_packet` → output layer
  (src/output/synthetic.rs); removes TUI→capture layering violation.
- [ ] **M2. Extract packet pipeline from main.rs** — `process_parsed_packet`,
  TLS/WebSocket unwrap, batch orchestration (2,335-line main.rs) behind a
  testable PacketProcessor abstraction.
- [ ] **P2. `Cow<'a, str>` SIP header values** — parser.rs allocates a String
  per header value plus full `data.to_vec()`; borrow from the raw buffer.
  (Pairs with P1; do after P1's lifetime design.)
- [ ] **M8. Rustdoc on public API** — lib.rs re-exports have no docs;
  add rustdoc + `#![warn(missing_docs)]` for the library surface.

## P4 — major refactors (in scope, queued last)

- [ ] **P1. Zero-copy packet payloads** — `ParsedPacket.payload: Vec<u8>`
  cloned per packet (capture/parse.rs:431,446); biggest hot-path win
  (~20-30%). Lifetime/`Cow` design through ParsedPacket and all consumers.
  Design doc first; bench before/after (depends on P8).
- [ ] **M1. Split src/tui/mod.rs (5,342 lines)** — into state machine /
  widgets / event handler / renderer modules. Behavior-preserving;
  tui_state_test.rs (224 tests) + snapshot tests are the safety net.

## Noted, not scheduled (needs a decision)

- **M9. Heavy deps** (rodio, axum for 2 endpoints) — revisit if build
  times/audit surface become a problem; not worth churn now.
- **Prometheus label-cardinality guard** — theoretical until metrics gain
  user-controlled labels; add a cap if/when that happens.
- **Privilege-drop regression guard** — current startup `bail!` is correct;
  add a CI assertion that capture never runs as root (folds into M4/CI work).
