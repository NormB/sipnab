# sipnab Verification Spec / Plan

Status: **draft** · Author: maintainer-assisted · Scope: full automated verification of
every user-facing function across CLI, text/batch mode, and the interactive TUI, plus the
service surfaces (REST API, MCP, HEP, Prometheus).

The goal is a **layered, deterministic, industry-standard** test architecture in which
*every surface in the traceability matrix (§9) has at least one automated check* — or an
explicit, justified waiver for hardware/root-only paths.

---

## 1. Goals & non-goals

**Goals**
- Verify all 4 runtime modes: interactive **TUI**, **batch/CLI**, **MCP server**, **HEP listener**.
- Verify all 12 output formats and the REST/Prometheus/MCP protocol surfaces.
- Make the **TUI** testable with industry-standard techniques (virtual-terminal snapshots + PTY E2E).
- Be **deterministic and CI-friendly**: no live NICs, no audio device, no root, no wall-clock flakiness.
- Maintain a **traceability matrix** so coverage gaps are visible and new flags can't ship untested.
- **100% surface validation (hard gate, §15):** *every* CLI parameter, *every* UI option/control/button,
  and *every* API request/response — including the full **bearer-token lifecycle** — maps to ≥1 passing
  test, enforced by a surface registry in CI. Bearer-token **expiration** is **critical** per maintainer
  direction and must be *implemented* before its class can be marked validated (it does not exist today).
- **Industry best practices + proven docs (§16–§17):** every tool, pattern, and mechanism follows a
  current, cited industry standard (research it if not already grounded); and **every example in the
  documentation is executed and proven correct in CI** — no example ships unverified.

**Non-goals**
- Re-testing pure logic already covered by the ~1079 existing unit tests (we build on them).
- Verifying genuinely hardware/OS-bound paths in unit CI (live `pcap` device, real audio output,
  `setuid`/`chroot` as root) — these get a thin harness/manual waiver instead (§7, §10).

---

## 2. Current state (baseline, from codebase audit)

Already in place — we extend, not replace:

| Capability | Tool | Where |
|---|---|---|
| Unit tests (~1079 `#[test]`) | std | `src/**/*.rs` `#[cfg(test)]` |
| Integration tests (22 files) | std + helpers | `tests/*.rs` |
| TUI snapshot rendering | **ratatui `TestBackend` + `insta`** (43 goldens) | `tests/tui_snapshot_test.rs`, `tests/snapshots/` |
| TUI state machine (no render) | std | `tests/tui_state_test.rs` |
| TUI black-box E2E | **`expectrl`** PTY (5 `#[ignore]` tests) | `tests/tui_e2e_test.rs` |
| CLI process tests | inline `std::process::Command` | `tests/cli_*.rs` |
| JSON output schema asserts | `serde_json` inline | `tests/integration_test.rs`, `config_wiring_test.rs` |
| MCP stdio/http | `tokio`, raw JSON-RPC | `tests/mcp_*_test.rs` |
| Fuzzing (10 targets) | `cargo-fuzz` | `fuzz/` |
| Benchmarks | `criterion` | `benches/` |
| Coverage (~90% lines) | `cargo-llvm-cov` | `quality.yml`, `tasks/test-coverage-todo.md` |
| Live E2E harness | docker-compose (opensips+sipp+rtpengine) | `harness/` |
| Docs/CLI drift guard | std | `tests/docs_drift_test.rs` |

Dev-deps present: `criterion`, `insta`, `tempfile`, `tokio`, `expectrl`, `libc`.

---

## 3. Test architecture — the pyramid

```
        ┌─────────────────────────────────────────────┐
  L6    │ Fuzz · property · perf-regression (nightly)  │
        ├─────────────────────────────────────────────┤
  L5    │ E2E live: docker harness (opensips+sipp+rtp) │   slow / nightly
        ├─────────────────────────────────────────────┤
  L4    │ Service/protocol: REST API · MCP · HEP · /metrics │
        ├─────────────────────────────────────────────┤
  L3    │ TUI:  3a TestBackend snapshots (primary)     │
        │       3b PTY E2E via expectrl (smoke)        │
        ├─────────────────────────────────────────────┤
  L2    │ CLI process goldens (trycmd/snapbox)         │
        ├─────────────────────────────────────────────┤
  L1    │ Component goldens: output formatters, parsers│
        ├─────────────────────────────────────────────┤
  L0    │ Unit (pure fns) — already strong             │   fast / every commit
        └─────────────────────────────────────────────┘
```

Principle: push each check to the **lowest layer that can prove it**. A formatter is proven at
L1 with a golden string; a key-binding at L3a with a rendered frame; only true integration
(crossterm raw-mode init, real resize, process exit) needs L3b/L5.

---

## 4. TUI verification — industry-standard approach (the core ask)

TUIs are hard to test because they are **stateful, time-dependent, and terminal-dependent**.
The industry answer is two complementary layers plus a hard determinism contract.

### 4a. In-process virtual-terminal snapshots (primary)

The Rust-ecosystem standard, already used here: render the app to an **in-memory
`ratatui::backend::TestBackend`** buffer, serialize the buffer to text, and assert it against
an `insta` golden. This is the TUI analogue of Jest/React snapshot testing and Go Bubble Tea's
`teatest` harness.

- **Drive** the app by feeding synthetic `KeyEvent`s through the existing event handler
  (`App::on_key` / `handle_key_event`) — no PTY, no real terminal.
- **Capture** via the existing `buffer_to_string()` helper (`tests/tui_snapshot_test.rs`).
- **Assert** with `insta::assert_snapshot!`; review/accept with `cargo insta review`.
- **Fast, hermetic, debuggable** — runs in the normal `cargo test`/`nextest` pass.

Pattern — a table-driven "key-sequence → expected frame" harness (extends what exists):

```rust
// (sequence of keys)  ->  (named golden)
case("call_list → Enter → CallFlow",          &[Enter],                 "call_flow_basic");
case("CallFlow → 'V' toggles preview split",  &[Enter, Char('V')],      "call_flow_no_split");
case("FilterDialog open + tab nav",           &[Key::F(3), Tab, Tab],   "filter_dialog_focus");
```

### 4b. PTY black-box E2E (smoke / integration)

`TestBackend` can't catch crossterm init, raw-mode, alternate-screen, real terminal resize, or
clean process exit. For those, spawn the **real binary in a pseudo-terminal** — the
industry-standard technique (Tcl `expect`, Python `pexpect`, Node `node-pty`); here via
`expectrl` (already a dev-dep).

- Keep these **few and shallow** (launch, switch views, open a dialog, quit cleanly).
- Run under `cargo-nextest` with **retries** to absorb PTY timing flakiness (replaces the current
  `continue-on-error: true`, which hides real failures).
- Pin terminal size and timing (see §4d).

### 4c. Optional: VHS visual goldens

charmbracelet **`vhs`** scripts render a fixed key-sequence to a deterministic text/GIF artifact
for golden diffing and for docs. Nice-to-have for headline screens; not load-bearing.

### 4d. Determinism contract (mandatory for 4a/4b)

A TUI test is only meaningful if the frame is reproducible. Enforce all of:

1. **Fixed terminal size** — e.g. `TestBackend::new(120, 40)`; for PTY, export `COLUMNS=120 LINES=40`.
2. **Frozen time** — never snapshot `Utc::now()`. Inject timestamps at construction
   (`App::with_processed_messages(msgs)` with fixed `ts`), and **normalize** any residual
   volatile fields (durations, "age", `created/updated`) before asserting. *(Prereq: keep using
   constructor-injected time; if any view computes `now()` internally, add a `Clock` seam.)*
3. **Offline input only** — pcap fixtures; never a live device in CI.
4. **No animation/adaptive-refresh nondeterminism** — drive frames explicitly; don't sleep-and-hope.
5. **Locale/timezone pinned** — `TZ=UTC`, stable unicode width.
6. **Color pinned** — `--color never` / `NO_COLOR=1`, or a fixed theme, so ANSI doesn't leak into goldens.
7. **Normalization helper** — one shared function that scrubs timestamps/paths/PIDs/durations from
   both rendered frames and process output (generalize the canonicalizer in `parse_path_test.rs`).

### 4e. TUI coverage matrix (what 4a must exhaustively hit)

- **8 views**: CallList, StreamList, CallFlow, RawMessage, MessageDiff, Help, Statistics, StreamDetail.
- **4 dialogs**: Save (all formats), Filter (5 fields + 10 method checkboxes + DSL build), Settings (6 toggles), FileOpen (browser).
- **Display-mode cycles**: SDP None/Summary/Full; Timestamp Absolute/Δprev/Δfirst/Scaled; Color method/call-id/cseq; split-view on/off; extended-flow; RTP-in-flow.
- **Layout states**: narrow vs wide terminal; empty vs populated vs failed-dialog.
- **Every keybinding** in `events.rs` (navigation, search `/`, select `Space`, marks, folds, play `p`).
- **Audio (`audio` feature)**: cover the decode/error-message path with `TestBackend`; the real device path stays waived (§10).

---

## 5. CLI / text-mode verification

### 5a. Process goldens

Adopt **`trycmd`/`snapbox`** (the cargo-ecosystem standard for CLI golden tests) — or
`assert_cmd` + `insta` — to replace ad-hoc `Command::new` assertions. Each case pins
`args + stdin → stdout + stderr + exit-code`.

Cover, against a fixed fixture pcap (`tests/fixtures/sip_call.pcap`):
- `--help`, `--version`, `--dump-config` → goldens (also guards docs drift).
- **Every output format**: text, `--json`, `--json-pretty`, `--report`, `--call-report` (+`--markdown`),
  `--hexdump`, `--fail2ban`, `-T/--text-dump`, `--wireshark`, `--tshark-filter`, `--group-by`,
  CSV, NDJSON, pcap/pcapng (`-O`).
- **Flag-conflict / validation**: mutually exclusive flags, out-of-range values, feature-gated
  flags without the feature → assert exit code **2** and the right message.
- **Env-var precedence**: `SIPNAB_API_KEY`, `SIPNAB_MCP_TOKEN` vs flags.

### 5b. Output contracts (schema validation)

Define versioned **JSON Schemas** (the message object, dialog, stream, call-report — all already
carry `schema_version`) and validate emitted JSON with the `jsonschema` crate. Schema files live in
`tests/schemas/` and double as documentation. This catches field drift that golden strings miss.

### 5c. Normalization

Reuse the §4d.7 scrubber so goldens are stable: strip timestamps, durations, hostnames, temp
paths, PIDs; sort where emission order is legitimately nondeterministic; force `--color never`.

---

## 6. Service / protocol verification (currently the biggest gaps)

| Surface | Plan | Status |
|---|---|---|
| **REST API** (`--api 127.0.0.1:0`) | Spawn on ephemeral port; `reqwest` GET every endpoint (`/health`, `/v1/dialogs`, `/v1/dialogs/{id}`, `/report`, `/v1/streams`, `/v1/streams/{id}`, `/v1/stats`, `/metrics`); assert status + JSON-Schema; bearer accept/reject; `--api-max-conn`; TLS cert/key path | **GAP** |
| **Prometheus** `/metrics` | Scrape, parse with prometheus text-format parser, assert metric families/labels present | **GAP** |
| **MCP** (stdio + http) | Extend existing round-trip tests to invoke **all 12 tools**, validate each output schema; http bearer + host-rebind already partly covered | partial |
| **HEP listener** (`-L`) | Send synthetic HEP3 datagrams; assert ingestion, CIDR allowlist, rate-limit, `--hep-send` forward | **GAP** |

All L4 tests use ephemeral ports (`:0`) and are feature-gated to their build.

---

## 7. End-to-end live (docker harness)

Promote `harness/` (opensips + sipp + rtpengine + sipnab) to a **scheduled/nightly CI job**:
drive real SIP+RTP with sipp scenarios, then assert sipnab's `--json`/`--report`/API output and
(optionally) a TUI PTY smoke against the live stream. This is the only layer that exercises live
capture + decode end-to-end; it is slow and is **not** a per-commit gate.

---

## 8. Fixtures & determinism infrastructure

- **Pcap corpus** (have 20+). Add the missing-format fixtures to close gaps: TLS-encrypted SIP +
  `--keylog`, SRTP + `--srtp-keys`, a HEP3 capture, codec-reject/auth-fail, DTMF (info + RFC2833).
- **Reproducible generation**: keep sipp scenarios + a `make fixtures` target so captures are regenerable.
- **Shared test util crate/module**: the normalization scrubber, the TUI key-sequence harness, the
  API spawn-on-`:0` helper, and JSON-Schema loaders — one place, used by all layers.

---

## 9. Traceability matrix (living document)

The spec's backbone: one row per surface → owning layer → test file → status. Seed (excerpt; the
full matrix is maintained here and checked in CI):

| Surface | Layer | Test artifact | Status |
|---|---|---|---|
| CLI parse / `--help` / `--version` | L2 | `cli_*`, trycmd goldens | ✅ / extend |
| Output: text/json/ndjson/report/call-report | L1/L2 | goldens + schema | ✅ / extend |
| Output: CSV / pcapng / hexdump / fail2ban / wireshark / mermaid | L1/L2 | **add goldens** | ❌ GAP |
| SIP/SDP/RTP parse | L0/L6 | unit + fuzz | ✅ |
| Dialog/stream tracking & bounds | L0/L2 | unit, `resource_bounds_test` | ✅ |
| TUI 8 views | L3a | snapshots | ◐ partial → exhaustive |
| TUI 4 dialogs + display-mode cycles | L3a | **add snapshots** | ◐ GAP |
| TUI launch/quit/resize | L3b | `tui_e2e_test` (nextest+retry) | ✅ / stabilize |
| REST API endpoints + auth + TLS | L4 | **add** | ❌ GAP |
| Bearer-token lifecycle: use + **expiry** + rotation + revocation (API + MCP) | feat + L4 | HMAC signed tokens (`src/auth`) + `api_token_test`/`mcp_token_test` + unit negatives | ✅ implemented + documented ([`auth.md`](../docs/auth.md)) + tested + validated (M3b) |
| Prometheus `/metrics` scrape | L4 | **add** | ❌ GAP |
| MCP 12 tools round-trip | L4 | extend `mcp_*` | ◐ partial |
| HEP ingest/forward/limit | L4 | **add** | ❌ GAP |
| TLS/SRTP decryption | L1/L5 | **add fixtures+tests** | ❌ GAP |
| STIR/SHAKEN verify | L1 | **add** (fuzz only today) | ◐ GAP |
| Privilege drop / chroot | L2/L7 | `privilege_drop_test` (+waiver) | ✅ partial |
| Live capture / audio device | L5/waiver | harness / manual | waiver |

(`✅` covered · `◐` partial · `❌` no automated check · `waiver` = hardware/root-only)

---

## 10. Tooling additions (all industry-standard)

| Need | Tool | Why |
|---|---|---|
| CLI goldens | **`trycmd`** / `snapbox` (or `assert_cmd`+`predicates`) | cargo-ecosystem standard; declarative cases |
| JSON contract | **`jsonschema`** | versioned output schemas |
| API client | **`reqwest`** (or `ureq`) | drive REST/metrics endpoints |
| Test runner | **`cargo-nextest`** | parallel isolation + **retries** for PTY flakiness |
| Snapshot review | **`cargo-insta`** | already implied by `insta`; formal review workflow |
| Visual TUI goldens (opt) | **`vhs`** | deterministic terminal recordings for docs+regression |
| Coverage gate | **`cargo-llvm-cov`** (have it) | per-surface coverage tracking |

Waivers (documented, not silently skipped): live `pcap` device, real audio output, `setuid`/`chroot`
as root. Each is covered indirectly (offline pcap, decode-path unit test, `privilege_drop_test`) and
fully only in the docker harness or by manual checklist.

---

## 11. CI integration

Jobs (extending current `ci.yml`/`quality.yml`), all with `TZ=UTC`, `NO_COLOR=1`, fixed `COLUMNS/LINES`:

- `test` — unit + integration, **feature matrix** (existing).
- `cli-goldens` — trycmd/snapbox over all formats (new).
- `tui-snapshots` — L3a (existing, expand).
- `tui-e2e` — L3b under nextest **with retries**, drop `continue-on-error` once stable (change).
- `service` — API/MCP/HEP/metrics L4 (new).
- `coverage` — llvm-cov informational gate (existing).
- `fuzz` / `perf` — nightly (existing fuzz; add criterion compare).
- `e2e-docker` — nightly harness L5 (new).
- Extend **`docs_drift_test`** into a "every CLI flag has ≥1 referencing test" check so new flags can't merge untested.

---

## 12. Phased rollout

1. **Foundations** — shared normalization scrubber + JSON schemas + CLI golden harness (`trycmd`);
   adopt `nextest`. *(Unblocks everything; low risk.)*
2. **Output formats** — close the L1/L2 format gaps (CSV, pcapng, hexdump, fail2ban, wireshark, mermaid, prometheus).
3. **Service layer** — REST API + `/metrics` + HEP tests; finish MCP 12-tool round-trips.
4. **TUI breadth** — exhaustive L3a snapshots for all views/dialogs/display-modes; stabilize L3b PTY E2E.
5. **Crypto + live** — TLS/SRTP fixtures & decryption tests; promote docker harness to nightly L5; perf gate.
6. **Governance** — traceability matrix kept current; CI "no untested flag" check enforced.

---

## 13. Validation methodology & success / failure criteria

How each layer's tasks are *validated*, and the explicit pass/fail bar. The execution plan
([`verification-plan.md`](./verification-plan.md)) turns this into per-task commands.

### 13.1 Universal gate (applies to every task)

A task is validated only when **all** hold, run locally and reproduced in CI:
**TDD red→green** (test written first, shown failing then passing) · targeted test green ·
**full suite green** (`cargo nextest run --all-features` → `0 failed`) · `cargo fmt --check` and
`cargo clippy --all-targets --all-features -D warnings` clean · **3× no-flake** ·
**coverage non-regression** · **evidence captured** (command + output in the PR).

### 13.2 Per-layer validation & criteria

| Layer | Validated by | SUCCESS (pass) | FAILURE |
|---|---|---|---|
| **L0 unit** | `cargo nextest run --lib` | green, 3× stable | red · flaky · order-dependent |
| **L1 component golden** | output → `normalize()` → compare golden | byte-equal to golden | drift without reviewed `insta accept` · volatile field leaks |
| **L2 CLI process** | `trycmd`: `args+stdin → stdout/stderr/exit` | all three match | wrong exit code · stdout/stderr mismatch · nondeterministic |
| **L3a TUI snapshot** | `TestBackend`(120×40) → buffer → `insta` | frame == golden, 3× identical | unreviewed diff · nondeterministic frame |
| **L3b TUI PTY E2E** | `expectrl` screen-scrape under nextest `e2e` | expected screen within timeout | timeout · wrong screen · needs `continue-on-error` |
| **L4 service** | spawn on `:0` + client; assert status+schema+auth | 2xx · schema-valid · auth enforced | wrong status · schema invalid · **auth bypass** · port leak/hang |
| **L5 e2e docker** | live sipp traffic → assert sipnab output | ≥1 dialog + expected fields | no capture · missing/incorrect fields |
| **L6 fuzz / perf** | `cargo fuzz` (no crash) · `criterion` compare | no new crash · within threshold | crash/panic · regression beyond threshold |

### 13.3 Negative tests are mandatory

Every guard is proven by a failing case, not just a passing one: schemas must **reject** a
field-dropped document; auth must **reject** a bad token (non-2xx); tampered STIR/SHAKEN must be
**rejected**; the "no-untested-flag" gate must go **red** for a deliberately untested flag. A guard
that only ever sees the happy path is treated as **unvalidated**.

### 13.4 Evidence, reproducibility & flake policy

Every "done" claim carries the exact command and trimmed output, and must reproduce from a **clean
tree** (`cargo clean` → build → test). Tests must pass **3× consecutively** with no retries;
PTY/E2E may use nextest `retries=2` but must *also* clear a no-retry stability check. An
assertion-less test is never counted as coverage.

### 13.5 Validation-effort meta-criteria (is my validation itself trustworthy?)

- **SUCCESS:** every milestone exit-gate command returns green · evidence logged · clean-tree
  reproduction matches · coverage ≥ target.
- **FAILURE:** any gate red · any non-reproducible "pass" · any "passed" claim without captured
  output · any unreviewed golden/schema change · any undocumented coverage drop.

---

## 14. Definition of done

- Every traceability-matrix row is `✅` or a documented `waiver`.
- All output formats have a golden + (where JSON) a schema check.
- All 8 TUI views, 4 dialogs, and display-mode cycles have deterministic snapshots; PTY E2E is
  green without `continue-on-error`.
- REST/MCP/HEP/Prometheus surfaces each have an automated L4 test.
- CI is green across the full feature matrix; coverage held at/above current target.
- A new CLI flag cannot merge without a referencing test.
- The §15 completeness mandate is satisfied: 100% of CLI params, UI controls, and API
  requests/responses (incl. the full bearer-token lifecycle) are registry-tracked and validated.

---

## 15. Completeness mandate — 100% surface validation (hard requirement)

This is a **gating requirement**, not an aspiration: *every* atom in the four user-facing surface
classes below must map to ≥1 passing automated test, enforced in CI. "Representative" or "most"
coverage is insufficient — the bar is **100%**, because every atom here is fully automatable (none
are hardware/root-bound).

**Surface classes & what "validated" means**

1. **Every CLI parameter** (~87 flags in `cli.rs`): for each — parsed value, default, validation
   (accept valid; reject invalid with exit code 2), and its observable effect on output. Enumerated
   from the clap `Args` structs.
2. **Every UI option / control / button** (TUI): every keybinding in `events.rs`; every dialog field,
   checkbox, and button (Filter / Settings / Save / FileOpen); every view toggle and display-mode
   cycle — each asserted by an L3a snapshot or state test with its activating key/event exercised.
3. **Every API request and response**: each endpoint × method, validated for request handling **and
   every response field** (JSON-Schema), success and error status codes — likewise each MCP tool
   (request → schema-valid response).
4. **Bearer-token lifecycle — CRITICAL, and currently a security gap**: config/issuance (flag/file/env
   precedence) · accepted use (2xx) · reject when missing/wrong/malformed/non-Bearer (401) ·
   non-loopback-requires-token · constant-time comparison · **expiration** (expired → 401) ·
   **rotation** (overlapping-validity window) · **revocation** (revoked → 401).
   > Expiry/rotation/revocation are **not implemented today** (tokens are static shared secrets).
   > Per maintainer direction this feature is **critical**: it **must be implemented, documented,
   > tested, and validated** (plan **M3b**). It is an open **security gap**, never a waiver. The
   > class is "validated" only once all four states — implemented · documented · tested · validated —
   > are true.

**Enforcement (CI hard gate)**

- A machine-readable **surface registry** (`tests/registry/surface.toml`) enumerates every atom in
  classes 1–4 with the validating test(s) and a status.
- CI fails **red** if any atom has **zero** passing tests, or if a new flag / endpoint / control /
  token-state ships without a registry entry. This generalizes the §11 "no untested flag" gate to
  all four classes.
- This 100% surface gate **fails the build** (distinct from line-coverage, which stays informational).

**"Successfully validated" (per atom):** ≥1 test that clears the §13 universal gate (including a
**negative** case where applicable — e.g. expired/revoked token → 401), is non-flaky (3×), and is
listed green in the registry.

---

## 16. Industry-best-practices mandate

**Principle — applies to everything (code, tests, CI, security, docs):** every choice follows a
*current, established industry best practice*. Bespoke mechanisms require written justification in the
PR. Where a practice is **not already grounded** in this repo, the author **researches the current
industry standard and cites it** before adopting — do not invent. Prefer well-maintained, widely-used
tools and patterns over hand-rolled ones.

**Grounded baselines (researched, June 2026):**

| Area | Best practice adopted | Reference |
|---|---|---|
| TUI render tests | golden/snapshot via ratatui `TestBackend` + `insta`; **fixed terminal size** for reproducibility; headless in CI | [Ratatui testing recipe](https://ratatui.rs/recipes/testing/snapshots/), [ratatui-testlib](https://github.com/raibid-labs/ratatui-testlib) |
| TUI E2E | real PTY emulation + screen capture | [ratatui-testlib (PTY)](https://github.com/raibid-labs/ratatui-testlib) |
| CLI tests | declarative process goldens (`trycmd`/`snapbox`), `assert_cmd`+`predicates` | cargo-ecosystem standard |
| Output/API contracts | JSON-Schema validation | JSON Schema |
| Executable docs | "literate testing" / doctest — examples carry expected output and run in CI so code+tests+docs evolve together | [Python `doctest`](https://docs.python.org/3/library/doctest.html), Rust `cargo test --doc` |
| Test runner | parallel isolation + retries (`cargo-nextest`) | nextest |

**Best-practice review gate:** each PR names the established practice/tool it follows for any new test
or mechanism; a reviewer (or a CI lint, §11) rejects undocumented bespoke approaches. When a new area
arises that this table doesn't cover, the author researches + cites the standard and **appends a row
here**, keeping the mandate grounded rather than assumed.

## 17. Documentation & examples validation (every example must be proven)

**Requirement:** *every example that appears in any documentation is executed and proven correct in
CI.* No example ships unverified. "Documentation" includes `README.md`, everything under `docs/` (the
source of truth that auto-syncs to the Wiki), `--help`/usage text, config samples, every **API/MCP
request+response example**, and rustdoc code examples.

**Mechanisms — lowest layer that proves the example:**

| Example kind | Proven by |
|---|---|
| rustdoc code snippets | `cargo test --doc` (Rust doctests) |
| CLI command blocks in README/`docs/` | extracted + run via `trycmd` (args+stdin → stdout/exit) against fixtures |
| `--help`/usage shown in docs | golden-compared to actual `--help` (extends `docs_drift_test`) |
| config-file samples | parsed + schema-validated; samples documented as invalid must fail |
| API/MCP request/response examples | replayed against a spawned server (`:0`); response JSON-Schema-checked and diffed to the documented example |
| TUI screenshots / asciicasts | regenerated deterministically (VHS) and diffed |

**Anti-drift:** because `docs/` is the source of truth (→ Wiki), tested examples are what keep the docs
honest — a doc example that no longer matches reality **fails CI** instead of silently rotting.

**Success / failure**
- **PASS:** every documented example has an executing test that clears the §13 gate; the doc-example
  portion of the surface registry (§15) is 100% green.
- **FAIL:** any documented example is unexecuted · its output diverges from the doc without a reviewed
  update · a new doc example merges without a runner entry.
