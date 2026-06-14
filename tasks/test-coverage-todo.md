# Test Coverage Improvement Plan

Baseline (`cargo llvm-cov --all-features --workspace`, 2026-06-14):
**82.30% lines · 83.72% regions · 88.12% functions** (27,509 lines, 4,868 missed).

Goal: lift line coverage toward ~90% by attacking the largest *feasible* gaps
first. Files are ranked below by **missed lines × feasibility**, not raw %.

Per project convention (TDD/BDD): write the test first, prove it fails red where
a real gap exists, then fill. Cover backslash / special-char / NUL / empty edge
cases on any parser-adjacent work.

---

## P0 — Quick wins (largest %/effort ratio, do first)

- [ ] **Exclude `tools_gen_fixture.rs` from the coverage denominator.**
  It's a `[[bin]]` dev fixture generator, not shipped product code — 0% / 212
  missed lines. Add it to `codecov.yml` `ignore:` and pass
  `--ignore-filename-regex 'tools_gen_fixture\.rs'` in the `quality.yml`
  coverage step. *Effect: ~+0.6% line coverage, zero test code.*

- [ ] **`src/sip/response_codes.rs` — 36.86% → ~100% (221 missed).**
  Pure `match code -> Option<&'static str>` table. Add one table-driven test
  iterating every implemented code (assert `Some` + substring) plus a sample of
  unimplemented codes (assert `None`) and boundary codes (99, 700). *Effect:
  ~+0.7%, ~30 min.*

> P0 alone moves the project from ~82.3% to ~85% line coverage.

---

## P1 — High impact, good feasibility

- [ ] **`src/main.rs` pure helpers — 56.28% (613 missed, the single biggest gap).**
  Add a `#[cfg(test)] mod tests` in `main.rs` covering the standalone helpers
  that need no live capture: `parse_portrange`, `parse_autostop`,
  `build_filter_expr`, `build_capture_config`, `generate_reports`,
  `dispatch_sip_output`. Drive `process_parsed_packet` with synthetic
  `ParsedPacket`s (reuse `test_utils`). Realistically recovers ~200–300 of the
  613 missed lines; the `run_tui_mode` / live-capture arms stay integration-only.

- [ ] **`src/output/prometheus_server.rs` — 34.08% (118 missed).**
  Lowest-coverage HTTP surface. Mirror the `output/api.rs` pattern (88%): spin
  the axum router on an ephemeral port, hit `/metrics` + health/404 routes with
  a test client, assert status + body. High feasibility.

- [ ] **`src/capture/decrypt.rs` — 64.75% (245 missed).**
  TLS session decryption. Add fixtures: a keylog line + matching encrypted
  record (see `tests/fixtures`, and the `keylog_line` / `tls_records` fuzz
  targets for input shapes). Cover the error paths (bad key, truncated record,
  unsupported cipher) which dominate the misses.

- [ ] **`src/capture/mod.rs` — 52.38% (130 missed) & `src/capture/writer.rs` — 71.08% (107 missed).**
  `writer`: round-trip a pcap to a `tempfile` and re-read it; assert header +
  packet bytes; cover rotation/error paths. `mod`: cover the capture-source
  dispatch and config-validation branches that don't require a live device.

---

## P2 — TUI rendering cluster (largest area; uniform approach)

~1,400 missed lines total. All testable with ratatui's `TestBackend` +
buffer/snapshot assertions already established in `tests/tui_snapshot_test.rs`
and `tests/tui_state_test.rs`. Tackle in this order (most-missed first):

- [ ] **`src/tui/call_flow/render.rs` — 46.39% (465 missed).** Biggest single TUI
  gap. Render call-flow diagrams for varied dialog shapes (1-leg, forked,
  REFER/replaces, error responses) into a `TestBackend` and snapshot.
- [ ] **`src/tui/render.rs` — 78.79% (239 missed)** — exercise the remaining
  panel/layout branches (narrow widths, empty state, truncation).
- [ ] **`src/tui/events.rs` — 79.53% (259 missed)** — extend `tui_state_test.rs`
  with the unhandled key/resize/mouse event arms.
- [ ] **`src/tui/save.rs` — 76.79% (120) · `src/tui/mod.rs` — 78.69% (127) ·
  `src/tui/call_flow/prepare.rs` — 77.15% (125) · `src/tui/stream_detail.rs` —
  75.87% (76).** Fill remaining branches; `save` error paths via tempfiles.

---

## P3 — Incremental fills (already healthy, push branches)

- [ ] **`src/mcp/server.rs` — 76.28% (116)** — cover remaining tool-handler error
  arms via the `mcp_stdio_test` / `mcp_http_test` harnesses.
- [ ] **`src/output/api.rs` — 87.20% (100)** & **`src/sip/dsl.rs` — 85.51% (111)** —
  add the missing error/edge branches; dsl already has 33 tests.
- [ ] **`src/capture/hep.rs` — 73.91% (198)** — extend the 21 existing tests to
  malformed/partial HEP frames (align with `hep_parser` fuzz corpus).

---

## P4 — Low feasibility (hardware/OS-bound; extract-or-accept)

Document these as intentionally low rather than chasing them, but extract pure
logic where it exists:

- [ ] **`src/rtp/playback.rs` — 0% (121, `audio` feature).** Wraps rodio audio
  hardware. Extract the decode/resample buffer math into a device-free function
  and unit-test that; leave the `Player`/`MixerDeviceSink` device path uncovered.
- [ ] **`src/privilege.rs` — 43.70% (67)** & **`src/capture/live.rs` — 61.03%`,
  `src/capture/device.rs` — 47.62%.** Need root / a live NIC. Cover argument
  parsing and the capability-computation logic; accept the syscall arms as
  uncovered (they're exercised in the `privilege_drop_test` integration test
  where the environment permits).

---

### Suggested sequencing
1. P0 (config + response_codes) — ~1 hour, ~+1.3%.
2. P1 main.rs helpers + prometheus_server — biggest absolute line recovery.
3. P2 TUI cluster — steady grind, snapshot-driven.
4. P3 / P4 as polish.
