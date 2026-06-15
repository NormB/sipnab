# sipnab Verification — Execution Plan

Derived from [`verification-spec.md`](./verification-spec.md). The spec defines *what/why*;
this plan defines *what to build, in what order, and how we know it's done*.

**How to use:** each task has an ID, concrete deliverable files, dependencies, a **success
(pass) criterion**, and a size (S ≈ ½ day, M ≈ 1 day, L ≈ 2–3 days). Work top-down; a task is
`done` only when it clears the **Validation protocol** below *and* its per-task success criterion
is green in CI. Status: `[ ]` todo · `[~]` in progress · `[x]` done.

---

## Validation protocol (applies to EVERY task)

How each task is validated — run locally, reproduced in CI, evidence captured. A task is **DONE**
only when **all** of these pass:

1. **TDD red→green** (repo rule): write the test first; show it **failing** against unfixed code
   (red), then **passing** after the change (green). Capture both outputs.
2. **Targeted test green:** the task's own test(s) pass — `cargo nextest run -E '<selector>'`.
3. **No regression:** full suite green — `cargo nextest run --all-features` → `0 failed`.
4. **Lint/format clean:** `cargo fmt --all -- --check` **and**
   `cargo clippy --all-targets --all-features -- -D warnings` both clean.
5. **No flake / determinism:** the task's test passes **3× consecutively** with no retries; any
   nondeterminism (timestamp, ordering, locale, color) = fail. PTY/E2E additionally pass under the
   nextest `e2e` profile.
6. **Coverage non-regression:** `cargo llvm-cov` line% ≥ prior run (tracked in
   `tasks/test-coverage-todo.md`).
7. **Evidence captured:** the exact command + trimmed output recorded in the PR description.

**Universal FAILURE criteria** — the task fails and does **not** merge if **any** hold:
compile error · its test is red · a previously-green test goes red · fmt/clippy regress · the test
is flaky or order-dependent · a golden/schema differs from expected without an approved, reviewed
update · coverage drops below target without written justification.

**Validation-effort meta-criteria** — how I know *my own validation* is trustworthy:
- **SUCCESS:** every milestone exit-gate command returns green, evidence is logged, and a
  **clean-tree reproduction** (`cargo clean --manifest-path ~/sipnab/Cargo.toml` → full build →
  test) reproduces the result; coverage ≥ target.
- **FAILURE:** any gate red · any non-reproducible "pass" · any "passed" claim lacking captured
  command output · any assertion-less test counted as coverage.

The per-task **Success (pass) criteria** column below is the task-specific *addition* to this
universal gate, and the per-milestone **Validate / Fails-if** lines give the concrete command(s)
and the layer-specific failure modes.

---

## Completeness mandate (hard gate — spec §15)

The bar is **100%**, not "representative": every CLI parameter, every UI option/control/button, and
every API request/response (incl. the full **bearer-token lifecycle**) must map to ≥1 passing test,
tracked in `tests/registry/surface.toml` and enforced by a CI gate that fails red on any uncovered
atom (T6.5/T6.6). These four classes contain **no** hardware/root waivers — they are fully automatable.

**Bearer-token expiration is CRITICAL and not yet implemented.** It must be **implemented →
documented → tested → validated** before its surface class can be marked done. That work is milestone
**M3b** below; until all four states are true it is an open **security gap**, never a waiver.

---

## Operating principles (apply to every task — spec §16–§17)

- **Industry best practices, always:** use established, well-maintained tools/patterns; no bespoke
  mechanism without written justification; when an area isn't already grounded here, **research the
  current standard and cite it** before building (append it to the spec §16 table).
- **Every documented example is proven (milestone M-Docs):** all examples in `README`, `docs/`,
  `--help`, config samples, and API/MCP docs are executed in CI; an example that no longer matches
  reality **fails the build**.

**Milestone → phase map**

| Milestone | Phase (spec §12) | Theme | Exit gate |
|---|---|---|---|
| **M1** | 1 | Foundations / unblock | shared harness + nextest + first goldens green |
| **M2** | 2 | Output-format goldens | all 12 formats have a golden (+schema where JSON) |
| **M3** | 3 | Service layer (API/MCP/HEP/metrics) | every L4 surface has a test |
| **M3b** | 3 | **Bearer-token lifecycle (CRITICAL feature)** | expiry/rotation/revocation implemented + documented + tested + validated |
| **M4** | 4 | TUI breadth | all views/dialogs/modes snapshotted; PTY E2E green w/o `continue-on-error` |
| **M5** | 5 | Crypto + live E2E | TLS/SRTP tests; docker harness nightly; perf gate |
| **M-Docs** | 5–6 | **Documentation & examples** | every documented example executed & proven in CI |
| **M6** | 6 | Governance | 100% surface registry enforced; no-untested-flag/control/example CI gate |

**Critical path:** `M1 → (M2 ∥ M3 → M3b ∥ M4) → (M5 ∥ M-Docs) → M6`. M2/M3/M4 are largely
independent once M1 lands and can run in parallel; **M3b** depends on M3's API/MCP harness; **M-Docs**
depends on M1 + the API harness and runs alongside M2–M5; **M6**'s 100% completeness gate depends on
M1–M5, M3b, and M-Docs being substantially done.

---

## M0 — Prerequisites & decisions (do first, ~½ day)

- [x] **D0.1** Tooling choices confirmed: CLI goldens = **`trycmd`/`snapbox`**; API client =
  **`reqwest`** (blocking, `rustls-tls`); schema = **`jsonschema`**; runner = **`cargo-nextest`**.
- [x] **D0.2** PR granularity: **one PR per coherent slice** (M0+T1.1/T1.2/T1.5 landed together as the
  test-support foundation).
- [x] **D0.3** Clock-seam discovery — **DONE. Finding: no Clock seam needed.** TUI/report render paths
  take *injected* timestamps; the only internal `now()` in production are (a) `Instant::now()`
  rate-limit windows (`output/event_exec.rs`, `output/api.rs` — not rendered) and (b) a few output
  timestamps in `output/fail2ban.rs`, `output/synthetic.rs`, `tui/call_flow/export.rs`, which the
  `normalize()` scrubber (T1.1) handles. The rest of the `now()` hits are in `#[cfg(test)]` code. So
  determinism is achieved via injected time + normalization, not a code seam.

---

## M1 — Foundations (Phase 1)

> Unblocks every other milestone. Low risk, high leverage.

| ID | Task | Deliverable files | Deps | Size | Success (pass) criteria |
|---|---|---|---|---|---|
| [x] **T1.1** | Shared test-support module | `tests/support/mod.rs`, `tests/support_selftest.rs` | — | M | ✅ `normalize()` scrubs timestamps/durations/temp-paths/PIDs/loopback-ports; 13 self-tests (incl. empty/backslash/NUL edge cases) red→green, 3× stable |
| [x] **T1.2** | Adopt `cargo-nextest` | `.config/nextest.toml` (CI step pending T6.3) | — | S | ✅ `cargo nextest run` green; `default`/`ci`/`e2e` profiles; `e2e` has `retries = 2` |
| [x] **T1.3** | JSON Schemas + validator | `tests/schemas/{message,dialog,stream,call_report}.schema.json`; `tests/support/schema.rs`; `tests/json_schema_test.rs`; `jsonschema` dev-dep | T1.1 | M | ✅ 4 schemas (`schema_version:1`, `additionalProperties:false`); **message** validated vs real `--json` NDJSON (≥5 msgs) and **call_report** vs `--call-report --json` on both no-RTP + RTP fixtures; **negative tests** (wrong type / missing required / wrong version / extra field) prove non-vacuity. **dialog** (REST summary) + **stream** (full RTP) authored + compile-checked now; live-output proof deferred to **M3/T3.2–T3.5** (API-only output) |
| [x] **T1.4** | CLI golden harness + first cases | `Cargo.toml` (`trycmd` dev-dep); `tests/cli_goldens.rs`; `tests/cli/cmd/{help,version,dump-config}.trycmd` | T1.1 | M | ✅ `--help`/`--version`/`--dump-config` goldens pass under the determinism env; volatile version/commit/feature banner matched with trycmd `[..]` so goldens are feature-set-independent; harness proven to catch real mismatches (red→green). **Note:** `.trycmd` cases MUST be fenced (```` ``` ````) and the bin registered via `CARGO_BIN_EXE_sipnab` (2 bins ⇒ auto-detect skips → false-green "ignored"). Exhaustive per-flag `--help` coverage left to T6.2 (feature-aware) |
| [x] **T1.5** | Determinism env contract | `tests/support/mod.rs` (`deterministic_env`, `FIXED_COLS/ROWS`) | — | S | ✅ `deterministic_env()` sets `TZ=UTC`/`NO_COLOR`/fixed `COLUMNS=120`/`LINES=40`; test-covered (consolidated into the support module rather than a separate `env.rs`) |

**M1 exit gate:** T1.1–T1.5 merged; `cargo nextest run --all-features` and the new golden/schema
tests green in CI.
- **Validate with:** `TZ=UTC NO_COLOR=1 cargo nextest run --all-features` (support+schema+golden
  suites), repeated 3×; plus `cargo insta test` / `trycmd` in check mode.
- **Fails if:** `normalize()` leaves any volatile token in a fixture's output · a schema **accepts**
  a doc with a required field removed (negative test must fail-closed) · the `--help`/`--version`
  goldens differ across two machines or locales · `.config/nextest.toml` retries/profile are ignored.

---

## M2 — Output-format goldens (Phase 2)

> One golden (and schema, where JSON) per output format. All run the binary against
> `tests/fixtures/sip_call.pcap`, pipe through `normalize()`, and snapshot. Each is **S** unless noted.

> **Reality reconciliation (M2):** CSV (T2.5) and mermaid/ladder (T2.10) are **not** CLI
> flags — they are **WASM** (`src/wasm.rs`, `target_arch=wasm32`-only) and **TUI export**
> (`src/tui/save.rs`) formats. They are therefore covered by in-crate content tests, not CLI
> goldens. `--payload-limit` (T2.1) has no effect on default text (one-liners) and is covered by
> the existing `cli_print::payload_limit_truncates` unit test. The 9 genuinely CLI-reachable
> formats are pinned by trycmd goldens in `tests/cli/out/`.

| ID | Format / flag | Deliverable | Deps | Success (pass) criteria |
|---|---|---|---|---|
| [x] **T2.1** | text (default), `--delta-time` (+`--payload-limit` via unit test) | `tests/cli/out/text.trycmd`, `text-delta.trycmd` | T1.4 | ✅ goldens stable (pcap-timestamp deterministic); color stripped via `NO_COLOR`; payload-limit covered by `cli_print` unit test |
| [x] **T2.2** | `--json`, `--json-pretty`, NDJSON | `tests/json_schema_test.rs` (`json_and_json_pretty_streams_validate`) | T1.3 | ✅ all 7 lines of **both** flags validate against `message.schema.json`; count pinned |
| [x] **T2.3** | `--report` | `tests/cli/out/report.trycmd` | T1.4 | ✅ dialog table header + row pinned (exact columns + trailing layout) |
| [x] **T2.4** | `--call-report` (text + `--markdown` + json) | `tests/cli/out/call-report.trycmd`, `call-report-markdown.trycmd`; json via `call_report.schema.json` (T1.3) | T1.3 | ✅ text + markdown goldens (Summary/Timing/Media/Issues sections); json schema-validated on no-RTP + RTP fixtures |
| [x] **T2.5** | CSV export (**WASM/TUI**, not CLI) | strengthened `src/tui/save.rs::csv_saves_with_header` | T1.4 | ✅ **column set pinned** (exact 11-col header) + row count; (WASM `export_csv` differs at 10 cols — noted) |
| [x] **T2.6** | pcap / pcapng (`-O`, `--pcapng`) roundtrip | `tests/capture_test.rs` (`pcap_roundtrip_preserves_linktype_and_magic`, `pcapng_roundtrip_and_magic`) | T1.1 | ✅ write→reread count + **linktype match**; classic-pcap magic (4 variants) + **pcapng SHB magic** `0a0d0d0a` asserted |
| [x] **T2.7** | `--hexdump` | `tests/cli/out/hexdump.trycmd` | T1.4 | ✅ full deterministic hexdump pinned (offset/hex/ASCII for all 7 msgs) |
| [x] **T2.8** | `--fail2ban` | `tests/cli/out/fail2ban.trycmd` | T1.4 | ✅ stable `scanner_detected src=… ua=… method=…` lines pinned; volatile syslog date+PID redacted with `[..]` (verified across 2 wall-clock runs) |
| [x] **T2.9** | `--wireshark`, `--tshark-filter` | `tests/cli/out/wireshark.trycmd`, `tshark-filter.trycmd` | T1.4 | ✅ message lines + emitted `tshark -r … -Y '…' -V` command + Call-ID filter pinned |
| [x] **T2.10** | mermaid/ladder export (**WASM/TUI**, not CLI) | strengthened `src/tui/save.rs::mermaid_saves_diagram` | T1.4 | ✅ **content** validated: `sequenceDiagram` + `participant` + `class="mermaid"` + renderer script (was existence-only) |
| [x] **T2.11** | `--group-by` | `tests/cli/out/group-by.trycmd` | T1.4 | ✅ group-by call-id output pinned |

**M2 exit gate:** every row in the spec's "Output formats" inventory has ≥1 green golden;
JSON-bearing formats also pass schema validation.
- **Validate each format with:** `sipnab -N <flag> -I tests/fixtures/sip_call.pcap | normalize`
  diffed against its committed golden; JSON/NDJSON formats additionally validated by `jsonschema`;
  pcap/pcapng by write→reread packet-count + linktype assertion. Run each 3×.
- **Fails if:** a golden drifts without a reviewed `cargo insta accept` · a JSON line fails its
  schema · pcap roundtrip count/linktype mismatches · output is nondeterministic across runs ·
  a documented format has **no** golden (coverage hole).

---

## M3 — Service / protocol layer (Phase 3)

> Spawn on ephemeral ports; feature-gated to each build. Biggest current gap area.

| ID | Task | Deliverable files | Deps | Size | Success (pass) criteria |
|---|---|---|---|---|---|
| [ ] **T3.1** | API spawn harness | `tests/support/server.rs` (spawn `--api 127.0.0.1:0`, read bound port, `reqwest` client); `reqwest` dev-dep | T1.1 | M | helper returns base URL + client; tears down cleanly |
| [ ] **T3.2** | API endpoint coverage | `tests/api_test.rs` | T3.1, T1.3 | M | GET `/health`,`/v1/dialogs`,`/v1/dialogs/{id}`,`/report`,`/v1/streams`,`/v1/streams/{id}`,`/v1/stats`,`/metrics` → 200 + schema-valid |
| [ ] **T3.3** | API auth / limits / TLS | `tests/api_test.rs` | T3.1 | M | bearer accept(200)/reject(401); `--api-max-conn` enforced; `--api-tls-cert/key` serves HTTPS |
| [ ] **T3.4** | Prometheus `/metrics` scrape | `tests/metrics_test.rs` | T3.1 | S | text-format parses; expected metric families/labels present |
| [ ] **T3.5** | MCP 12-tool round-trips | extend `tests/mcp_stdio_test.rs`, `tests/mcp_http_test.rs` | T1.3 | M | each of the 12 tools invoked; output schema-validated; http bearer + host-rebind retained |
| [ ] **T3.6** | HEP ingest/forward | `tests/hep_test.rs`; `tests/support/hep.rs` (HEP3 datagram builder) | T1.1 | M | **GAP closed**; `-L` ingests synthetic HEP3; CIDR allowlist + rate-limit honored; `--hep-send` forwards |

**M3 exit gate:** API, Prometheus, MCP (all 12 tools), and HEP each have a green automated test.
- **Validate with:** spawn the server on `127.0.0.1:0`, read the bound port, drive it with the
  `reqwest`/JSON-RPC/HEP client, assert **status + schema + auth**; tear down and confirm the port
  is released (no leak/hang). Run 3×.
- **Fails if:** any endpoint returns an unexpected status · a response fails its JSON schema · an
  auth **reject** path returns 2xx (auth bypass) · `--api-max-conn` is not enforced · the process
  hangs or leaks the port · any of the 12 MCP tools errors or returns a schema-invalid result ·
  HEP CIDR allowlist or rate-limit is not honored.

---

## M3b — Bearer-token lifecycle (CRITICAL feature: implement → document → test → validate)

> Tokens are static shared secrets today (`src/output/api.rs:287`, `src/mcp/transport.rs`). Maintainer
> direction: **expiration is critical**. This milestone *builds the feature* (production code), then
> documents, tests, and validates it. Not a test-only milestone. Blocks the spec §15 mandate.

| ID | Task | Deliverable files | Deps | Size | Success (pass) criteria |
|---|---|---|---|---|---|
| [ ] **T3b.1** | Design the token lifecycle model (decision) | design note appended here | — | S | settles: TTL source (`--api-token-ttl`/`--mcp-token-ttl` + per-token `expires_at` in token file), rotation (N overlapping-valid tokens), revocation (revocation list / removal), and self-describing (signed) vs server-tracked tokens; constant-time compare preserved |
| [ ] **T3b.2** | Implement expiry+rotation+revocation — **REST API** | `src/output/api.rs`, `src/cli.rs` (new flags), token store module | T3b.1 | L | TDD red→green; expired token → 401; rotation window accepts both; revoked → 401; non-loopback still requires a *valid* token; constant-time retained |
| [ ] **T3b.3** | Implement expiry+rotation+revocation — **MCP** | `src/mcp/transport.rs`, `src/cli.rs` | T3b.1 | L | same lifecycle semantics as API; http + stdio paths covered |
| [ ] **T3b.4** | Document the feature | `--help` text, `docs/` (security/auth page → wiki), `CONTRIBUTING.md` | T3b.2, T3b.3 | S | every new flag documented; token lifecycle (issue/use/expire/rotate/revoke) described; `docs_drift_test` green |
| [ ] **T3b.5** | Validate full lifecycle + register | `tests/api_token_test.rs`, `tests/mcp_token_test.rs`; `tests/registry/surface.toml` entries | T3b.2, T3b.3 | M | issue→use(200)→**expire→401**→rotation-overlap(200 for both)→**revoke→401**; **negative tests mandatory**; constant-time asserted; registry rows green |

**M3b exit gate:** token expiration/rotation/revocation are **implemented, documented, tested, and
validated** for both API and MCP; the spec §15 token-lifecycle row flips from ❌ CRITICAL GAP to ✅.
- **Validate with:** `cargo nextest run --all-features -E 'test(token)'` (3×); spawn API/MCP on `:0`,
  issue a short-TTL token, assert 200 before expiry and **401 after**; rotate and assert overlap;
  revoke and assert 401.
- **Fails if:** an expired or revoked token is **accepted** (must fail-closed) · rotation drops a
  still-valid token · TTL/clock handling is nondeterministic or flaky · constant-time comparison is
  lost · any token state lacks a registry entry · the feature ships undocumented.

---

## M-Docs — Documentation & examples validation (spec §17)

> Every example in the docs must be **executed and proven** in CI. Runs alongside M2–M5 as its surfaces
> become available; gated complete with M6.

| ID | Task | Deliverable files | Deps | Size | Success (pass) criteria |
|---|---|---|---|---|---|
| [ ] **MD.1** | Rustdoc doctests enabled + required | `cargo test --doc` CI step; examples on public API | M1 | M | doctests run in CI and pass; key public modules carry ≥1 runnable example |
| [ ] **MD.2** | README/`docs/` CLI-block runner | `tests/doc_examples.rs` (`trycmd` over extracted ```` ``` ```` blocks) | T1.4 | M | every CLI command block in README/`docs/` executes with its documented output against a fixture |
| [ ] **MD.3** | Help/usage goldens in docs | extends `tests/docs_drift_test.rs` | T1.4 | S | `--help`/usage shown in docs == actual output |
| [ ] **MD.4** | Config-sample validation | `tests/config_examples_test.rs` | T1.3 | S | every documented config sample parses + schema-validates; samples marked invalid must fail |
| [ ] **MD.5** | API/MCP example replay | `tests/doc_api_examples.rs` | T3.1, T3.5 | M | each documented API/MCP request replayed on `:0`; response schema-valid and matches the documented example |
| [ ] **MD.6** | Doc-example registry + gate | rows in `tests/registry/surface.toml`; CI gate | T6.5 | S | 100% of documented examples have a runner; a new example without one fails CI |

**M-Docs exit gate:** every documented example is executed and proven in CI; no untested example.
- **Validate with:** `cargo test --doc` + `cargo nextest run -E 'test(doc_)'`; intentionally break one
  documented example and confirm CI goes **red**, then revert.
- **Fails if:** any documented example is unexecuted · output diverges from the doc without a reviewed
  update · a new doc example merges without a runner entry.

---

## M4 — TUI breadth (Phase 4)

> Primary = `TestBackend`+`insta` (L3a). Black-box PTY (L3b) stays thin. All under the §4d
> determinism contract (T1.5).

| ID | Task | Deliverable files | Deps | Size | Success (pass) criteria |
|---|---|---|---|---|---|
| [ ] **T4.1** | Key-sequence snapshot harness | extend `tests/tui_snapshot_test.rs` (table: `keys → golden`) | T1.5 | M | helper drives `App::on_key` over a key list, renders 120×40, snapshots via `buffer_to_string` |
| [ ] **T4.2** | All 8 views × states | snapshots in `tests/snapshots/` | T4.1 | L | CallList/StreamList/CallFlow/RawMessage/MessageDiff/Help/Statistics/StreamDetail in empty + populated (+ failed-dialog where relevant) |
| [ ] **T4.3** | 4 dialogs | snapshots | T4.1 | L | Save (each format selection), Filter (5 fields + 10 method checkboxes + built DSL string), Settings (6 toggles), FileOpen browser |
| [ ] **T4.4** | Display-mode cycles | snapshots | T4.1 | M | SDP None/Summary/Full; Timestamp Absolute/Δprev/Δfirst/Scaled; Color method/call-id/cseq; split on/off; extended-flow; RTP-in-flow |
| [ ] **T4.5** | Layout states | snapshots | T4.1 | S | narrow (e.g. 60×20) vs wide (120×40) |
| [ ] **T4.6** | Keybinding coverage audit | `tests/tui_state_test.rs` additions | T4.1 | M | every key handled in `events.rs` has ≥1 asserting test (state or snapshot) |
| [ ] **T4.7** | Stabilize PTY E2E | `tests/tui_e2e_test.rs`; `ci.yml` | T1.2 | M | runs under nextest `e2e` profile with retries; **drop `continue-on-error: true`**; launch/view-switch/dialog/quit assert real frames |
| [ ] **T4.8** | Audio decode/error path | snapshot in `tests/tui_snapshot_test.rs` | T4.1 | S | `audio` feature: decode + cached-error message path covered; real device waived (§10) |

**M4 exit gate:** all 8 views, 4 dialogs, and display-mode cycles have deterministic snapshots;
PTY E2E green without `continue-on-error`; keybinding audit passes.
- **Validate with:** drive a key sequence through `App::on_key` → render to a fixed `TestBackend`
  (120×40) → `buffer_to_string` → `insta` compare (`cargo insta test`); each frame rendered 3× must
  be byte-identical. PTY tests via `cargo nextest run -E 'test(tui_e2e)'` under the `e2e` profile.
- **Fails if:** a snapshot diff is unreviewed · a frame is nondeterministic across the 3 renders ·
  a key handled in `events.rs` has **no** asserting test (the keybinding audit lists it) · the PTY
  suite only passes with `continue-on-error` or fails its no-retry stability check.

---

## M5 — Crypto + live E2E (Phase 5)

| ID | Task | Deliverable files | Deps | Size | Success (pass) criteria |
|---|---|---|---|---|---|
| [ ] **T5.1** | Crypto/edge fixtures + generator | `tests/pcap-samples/*` (TLS+keylog, SRTP+keys, HEP3, codec-reject, auth-fail, DTMF rfc2833+info); `make fixtures` | — | M | fixtures checked in; regenerable via sipp/harness; documented provenance |
| [ ] **T5.2** | TLS decryption test | `tests/tls_decrypt_test.rs` (feature `tls`) | T5.1, T1.1 | M | offline pcap + `--keylog` → decrypted SIP in `--json`; **GAP closed** |
| [ ] **T5.3** | SRTP decryption test | `tests/srtp_test.rs` (feature `tls`) | T5.1 | M | `--srtp-keys` decrypts RTP payload; **GAP closed** |
| [ ] **T5.4** | STIR/SHAKEN verify | `tests/stir_shaken_test.rs` (feature `tls`) | T5.1 | M | valid Identity header verifies; tampered one rejected; **GAP closed** (fuzz-only today) |
| [ ] **T5.5** | Docker harness → nightly CI | `.github/workflows/e2e-docker.yml` | — | M | scheduled job drives opensips+sipp+rtpengine; asserts sipnab `--json`/API on live traffic |
| [ ] **T5.6** | Perf regression gate | `ci.yml` nightly; criterion compare | — | S | criterion baseline stored; >X% regression on parser/store benches flags the run |

**M5 exit gate:** TLS/SRTP/STIR-SHAKEN tests green; nightly docker E2E and perf jobs running.
- **Validate with:** offline decrypt → assert expected plaintext SIP fields / RTP payload in
  `--json`; a **tampered** STIR/SHAKEN Identity must be **rejected**; docker harness asserts ≥1 live
  dialog + expected fields; `criterion` compares against a stored baseline.
- **Fails if:** decryption yields no/garbled SIP or RTP · a tampered Identity header is **accepted**
  (must fail-closed) · the harness cannot assert at least one live dialog with expected fields ·
  a parser/store bench regresses beyond the agreed threshold (e.g. >10%).

---

## M6 — Governance (Phase 6)

| ID | Task | Deliverable files | Deps | Size | Success (pass) criteria |
|---|---|---|---|---|---|
| [ ] **T6.1** | Living traceability matrix | `tasks/verification-matrix.md` | M2–M4 | M | one row per surface (every flag, format, view, dialog, MCP tool, endpoint) → layer → test → status; seeded from spec §9 |
| [ ] **T6.2** | "No untested flag" CI gate | extend `tests/docs_drift_test.rs` | T1.4, T6.1 | M | test fails if a CLI flag in `cli.rs` is referenced by zero tests/goldens |
| [ ] **T6.3** | CI job wiring | `.github/workflows/ci.yml`, `quality.yml` | M1–M5 | M | jobs `cli-goldens`, `service`, `tui-e2e` (nextest), `e2e-docker`, `perf`; global `TZ=UTC NO_COLOR=1 COLUMNS=120 LINES=40` |
| [ ] **T6.4** | Docs: test architecture | `CONTRIBUTING.md` / `docs/` | M1–M4 | S | "how to add a test at each layer" + the determinism contract documented |
| [ ] **T6.5** | Surface registry (all 4 classes) | `tests/registry/surface.toml` | M2–M4, M3b | L | one row per CLI param, UI control/button, API request/response field, and token-lifecycle state → validating test(s) + status; **100%** of shipped atoms present |
| [ ] **T6.6** | 100% completeness CI gate | extend `tests/docs_drift_test.rs` (or new `tests/registry_test.rs`) | T6.5 | M | build **fails red** if any registry atom has zero passing tests, or a new flag/endpoint/control/token-state ships without a registry entry; proven by a negative meta-test |

**M6 exit gate:** traceability matrix complete and CI-enforced; a new flag cannot merge untested.
- **Validate with:** run the extended `docs_drift_test`; as a **negative/meta-test**, add a throwaway
  flag with no referencing test and confirm the gate goes **red** (proving it actually guards), then
  revert; verify the matrix has a filled row for every shipped surface.
- **Fails if:** a real CLI flag escapes the gate (gate stays green when it shouldn't) · the matrix
  has an empty/`❌` row for a surface that is actually shipping · any milestone's exit gate is not
  reproducible from a clean tree.

---

## Effort summary (rough)

| Milestone | Tasks | Est. |
|---|---|---|
| M0 | 3 | ½ d |
| M1 | 5 | ~3 d |
| M2 | 11 | ~3–4 d |
| M3 | 6 | ~4 d |
| **M3b (token lifecycle — CRITICAL feature)** | 5 | ~4–5 d |
| M4 | 8 | ~5–6 d |
| M5 | 6 | ~4 d |
| **M-Docs (documentation & examples)** | 6 | ~3 d |
| M6 | 6 | ~3–4 d |
| **Total** | **56** | **~5–6 weeks** of focused work (parallelizable across M2/M3/M4/M-Docs; M3b gates the §15 mandate) |

## Definition of done (whole effort)

Mirrors spec §14 + the §15 mandate: every traceability-matrix row is `✅` or a documented `waiver`;
all output formats have goldens (+schema for JSON); all TUI views/dialogs/modes have deterministic
snapshots and PTY E2E is green without `continue-on-error`; REST/MCP/HEP/Prometheus each have an L4
test; **bearer-token expiration/rotation/revocation is implemented, documented, tested, and validated
(M3b)**; the **100% surface registry** is complete and CI-enforced (T6.5/T6.6); **every documented
example is executed and proved correct in CI (M-Docs)**; all work follows the **industry-best-practice
mandate (§16)**; CI green across the feature matrix; coverage held at/above target; no CLI flag — and
no UI control, token state, or documented example — can merge untested.

## Suggested first slice

**M0 + M1** in one focused pass (it's the unblock layer and ~3 days): shared `normalize()`,
nextest, JSON schemas, the `trycmd` harness with the first three goldens. Everything else fans out
from there.
