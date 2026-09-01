# sipnab — Maintainability & Performance Improvement Spec

**Scope:** `sipnab` @ `main` (v0.4.18), ~68,300 lines across 101 files in `src/`,
plus [`crates/sipnab-audio`](https://github.com/NormB/sipnab/tree/main/crates/sipnab-audio).
**Method:** five parallel review passes — documentation standards, architecture
& complexity, idiomatic Rust / API design, hot-path performance, testing & CI —
each grounded in file:line evidence.
**Date:** 2026-07-03.

> **Status (2026-07-20): WS0–WS7 all shipped in v0.5.0.** Sections 0–9 below
> are the original 2026-07-03 review of v0.4.18 and are kept as the historical
> record — their counts (11 fuzz targets, ~2,200 tests) and "to build" framing
> describe the state *at review time*, not today. Tree at 2026-07-20: 15 fuzz
> targets, 2,569 tests — itself a dated observation, not a running total, and
> the test count has moved since. The only live section is **WS8** (§10, perf
> follow-ups), tracked against current `main`; see [`CHANGELOG.md`](https://github.com/NormB/sipnab/blob/main/CHANGELOG.md) for what
> each workstream landed in.

---

## 0. Executive summary

The review's headline is the opposite of the usual audit: **sipnab is well
above industry norm on hygiene** — 100% module docs, `#![warn(missing_docs)]`
enforced in CI, **zero** `unwrap`/`expect`/`panic!` in non-test library code,
bounds-checked parsers, 11 fuzz targets, ~2,200 tests including headless TUI
driving and self-enforcing docs/keybinding/CLI drift gates, and a store layer
that is genuinely well tuned (borrowed-key lookups, batched eviction, SSRC and
endpoint indexes).

The "overly complex" feel is real, but it is **concentrated, not diffuse**.
Four structures produce most of the reading pain:

1. **The per-packet pipeline exists four times** — `pipeline.rs` (canonical),
   a 402-line copy in `main.rs`, a drifted copy in `tui/events.rs`, and the
   sharded `parallel.rs` path.
2. **`main.rs` is a 3,343-line transaction script** (724/641/402-line
   functions, step comments numbered `// 1.` through `// 18.` spanning two
   functions).
3. **The TUI is a 74-field `App` god object + a 3,709-line event controller**
   (372 `KeyCode::` match arms, one 495-line handler), with render-time state
   mutation.
4. **"Dialog summary" is serialized five different ways** — with *shipped*
   drift: MCP says `message_count` where CLI/API say `msg_count`, and MCP emits
   `format!("{:?}", method)` where the API emits `method.as_str()`.

On performance, the packet spine (`Bytes` refcounting) and stores are already
zero-copy/tuned; what remains is per-message allocation debt in the SIP header
parser (~38–42 allocations per typical message), a full `SipMessage` clone on
both batch paths, and per-frame full-store recomputation in the TUI (worst
case: full-text search lowercases every stored message ×3 passes per frame
while holding the store read lock, backpressuring capture).

On testing, the theme is **safety nets that exist but never execute**: fuzzers
are compile-checked only (corpus for 1 of 11 targets), coverage is 100%
informational, the TUI e2e job is permanently `continue-on-error`, benches are
never built by CI, and `cargo doc` is never run (13 live rustdoc warnings,
including broken intra-doc links that render on docs.rs).

This spec is organized into workstreams **WS0–WS7**, ordered by
leverage-per-effort. WS0 is a batch of independent one-day fixes. WS1–WS3 are
the structural refactors that remove the complexity. WS4–WS5 are the
performance items (bench-first, per the TDD mandate). WS6–WS7 harden the API
surface and the CI safety nets.

---

## 1. Ground rules for all workstreams

- **TDD/BDD is mandatory** (per workspace policy). For refactors this means:
  characterization tests pinned *before* the move (most already exist — the
  drift-test suite and 2,200-test corpus are the safety net); for behavior
  changes, failing test first, shown red, then green. For performance work it
  means **bench-first**: add the criterion benchmark that measures the claimed
  hotspot, record the baseline number, then optimize and show the delta.
- **No public-API breakage without a version bump decision.** Several items
  (typed errors, `#[non_exhaustive]`, header-value representation) are
  semver-major for the library surface. They are flagged `[SEMVER]` below and
  should be batched into one 0.5.0 release rather than dribbled out.
- **One structural workstream in flight at a time.** WS1 (pipeline
  unification) and WS2 (main.rs decomposition) touch the same code; do them in
  order, not in parallel.
- Every workstream lists **acceptance criteria**; a workstream is done when
  all of them pass, not when the code "looks right".

---

## 2. WS0 — Quick wins (independent, ~1 day each, no design decisions)

Each item below is self-contained and can land as its own PR.

### WS0.1 Delete the batch-path `SipMessage` clone  *(perf, HIGH impact/trivial)*

- [`src/app/batch.rs:2806`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2806) — `dialog_store.process_message(sip_msg.clone());`
- [`src/parallel.rs:134`](https://github.com/NormB/sipnab/blob/main/src/parallel.rs#L134) — `ds.process_message(msg.clone());`

`pipeline.rs:150-169` already shows the fix: extract `call_id.to_string()`,
SDP links, and the `--tag`/event-exec fields *before* moving the message into
the store. A 12-header message currently pays ~14 extra heap allocations —
per SIP message, on exactly the offline-crunching paths where throughput
matters.

**Scope correction (found during implementation):** only the `parallel.rs`
(`--jobs`) clone is removable as a quick win. In `main.rs` the clone is
structural: the message is used extensively *after* store insertion (security
detectors, STIR/SHAKEN, `--calls-only` gate, output dispatch), and the filter
DSL must be evaluated against *post-update* dialog state, so the insertion
cannot move last. Removing that clone requires the WS1 hook restructuring
(or a shared-header representation, WS4.1 step 4) — deferred to WS1.

**TDD:** add the parse→`process_message` throughput bench (WS4.0) first;
record baseline; land; show delta.
**Accept:** no `.clone()` on the `process_message` argument in `parallel.rs`;
bench quantifies the clone-vs-move delta; full suite green; the `main.rs`
clone is tracked under WS1.

### WS0.2 CI rustdoc gate + fix the 13 live doc warnings  *(docs)*

No workflow runs `cargo doc`. `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
--all-features --workspace` fails today: unresolved intra-doc links
(`persist_to_config`, `decode_lost`, `link_to_dialog`, `compact_idle`), public
docs linking private items (`capture_hep` → `hep_to_packet`,
`verify_srtp_auth_tag` → `derive_session_key`), unclosed HTML tag at
[`src/error.rs:31`](https://github.com/NormB/sipnab/blob/main/src/error.rs#L31). The crate is published — docs.rs renders these broken.

**Accept:** the command above exits 0 locally and runs as a CI step in
`ci.yml`.

### WS0.3 `[workspace.lints]` table — lock in the discipline already achieved  *(idioms)*

Lint policy is currently scattered across [`src/lib.rs:23`](https://github.com/NormB/sipnab/blob/main/src/lib.rs#L23)
(`warn(missing_docs)`), [`src/mcp/mod.rs:24`](https://github.com/NormB/sipnab/blob/main/src/mcp/mod.rs#L24) (`deny(clippy::await_holding_lock)`),
and two CI flag sites; [`crates/sipnab-audio`](https://github.com/NormB/sipnab/tree/main/crates/sipnab-audio) has no `missing_docs` gate at all.
The codebase *already complies* with `unwrap_used`/`expect_used` in lib code —
nothing prevents regression.

Add to the workspace [`Cargo.toml`](https://github.com/NormB/sipnab/blob/main/Cargo.toml):

```toml
[workspace.lints.rust]
missing_docs = "warn"

[workspace.lints.clippy]
unwrap_used = "warn"
expect_used = "warn"
undocumented_unsafe_blocks = "warn"
missing_errors_doc = "warn"
missing_panics_doc = "warn"
await_holding_lock = "deny"
```

with `lints.workspace = true` in both member crates. Backfill what the new
lints flag: the ~46 missing `# Errors` sections (63 fallible pub fns, 17
documented) and the 7 missing `// SAFETY:` comments (`src/privilege.rs:247,253`;
`src/capture/live.rs:66,347,353,380`; [`src/rtp/playback.rs:419`](https://github.com/NormB/sipnab/blob/main/src/rtp/playback.rs#L419)). Convert the
15 `#[allow]`s to `#[expect]` so stale suppressions self-report.

**Accept:** `cargo clippy --workspace --all-features --all-targets -- -D warnings`
green with the table active; no lint attributes left in source files except
justified `#[expect]`s.

### WS0.4 Clippy `--all-targets` in the gating CI job  *(CI)*

The gating job runs `cargo clippy --all-features -- -D warnings` — benches and
test-target lints are only checked by the report-only SARIF job
(`continue-on-error: true`). Benches currently rot silently.

**Accept:** `ci.yml` clippy step uses `--all-targets`; benches compile under
the gate.

### WS0.5 Move `TransportProto` to a leaf module  *(architecture)*

`capture::parse::TransportProto` is imported by 10 files in `sip/` and
`security/` while `capture/` simultaneously imports `crate::sip` — the two
layers point at each other, and `sip` can never compile without `capture`
(relevant for wasm). Move it (and any shared vocabulary types) to a leaf
[`src/net.rs`](https://github.com/NormB/sipnab/blob/main/src/net.rs); re-export from `capture::parse` for compatibility.

**Accept:** `grep -r "capture::parse::TransportProto" src/sip src/security`
empty; all feature combos build.

### WS0.6 Micro-allocations with mechanical fixes  *(perf, LOW each)*

- `src/main.rs:1993,2013` — `dialog.state().to_string()` twice per message for
  change detection: compare the enum.
- [`src/sip/dialog.rs:136-144`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L136-L144) — `format!` per message for the retransmission
  probe key: packed tuple key or `SmallString`.
- [`src/capture/live.rs:224`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L224) — `interface_name.clone()` (an `Option<String>`)
  per packet: make `Packet.interface` an `Option<Arc<str>>` (`packet.rs:48`).

**Accept:** covered by the WS4.0 benches; suite green.

### WS0.7 `../architecture.md` + threading doc  *(docs)*

The architecture content exists but hides in `implementation-plan-v6.md`
(2,744 lines, planning-flavored name; README links it as "architecture and
roadmap"). Extract the Module Map + design decisions into a top-level
`../architecture.md` (matklad convention); link from CONTRIBUTING.md. Add
[`docs/internals/threading.md`](https://github.com/NormB/sipnab/blob/main/docs/internals/threading.md) with the actual topology (capture thread(s) →
PacketRx → processing thread → `Arc<RwLock<Store>>` ← TUI `try_read` readers;
API/MCP/MCP-HTTP/Prometheus/DNS/scanner-kill side threads) — today it is
reconstructible only by grep.

**Accept:** both docs exist; `docs_drift_test.rs` extended to keep the module
map's file list honest (it already has the machinery).

---

## 3. WS1 — Single per-packet pipeline  *(architecture, HIGHEST leverage)*

### WS1 — Problem

The routing sequence "WebSocket unwrap → SIP parse → dialog-store write →
SDP-to-stream link → RTCP check → RTP parse → RTP heuristic" exists in four
bodies:

| Copy | Location | Size | Consumer |
|---|---|---|---|
| Canonical | [`src/pipeline.rs:2331`](https://github.com/NormB/sipnab/blob/main/src/pipeline.rs#L2331) `process_packet` | 142 ln | TUI live |
| Batch | [`src/app/batch.rs:2870`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2870) `process_parsed_packet` | 402 ln | batch mode |
| TUI file-open | `src/tui/events.rs:1536` `load_pcap_file` | 194 ln | F3 open |
| Sharded | [`src/parallel.rs`](https://github.com/NormB/sipnab/blob/main/src/parallel.rs) + worker loops | ~200 ln | `--jobs N` |

`pipeline.rs:100-105` admits it ("the testable core that batch mode's richer
pipeline mirrors"). The TUI copy has already drifted: private
`is_rtcp_offline` instead of `pipeline::is_rtcp_packet`, its own copy of the
SDP-link 4-tuple, no `PipelineOptions`. Every protocol change is a 3–4-site
coordinated edit; this is the single largest maintenance liability found.

### WS1 — Design

Make `pipeline::process_packet` the only protocol router. Model the mode
differences as injected hooks, not copies:

```rust
/// What batch mode adds on top of the shared router.
pub trait PipelineHooks {
    fn on_sip(&mut self, msg: &SipMessage, pp: &ParsedPacket) {}   // output dispatch, --tag, event-exec
    fn on_rtp(&mut self, hdr: &RtpHeader, pp: &ParsedPacket) {}
    fn on_packet(&mut self, pp: &ParsedPacket) {}                  // writer / HEP forward
}
```

- Batch mode: `process_packet(pp, &stores, &opts, &mut decrypt, &mut batch_hooks)`
  where `BatchHooks` owns the writer, detectors (scanner/fraud/digest/
  reg-flood), and counters.
- TUI file-open: a plain loop over the same call with no-op hooks (or the
  detection hooks if the TUI grows them).
- Sharded path: same function against thread-local stores; `parallel.rs` keeps
  only shard/merge logic. The merge contract ("reproduce the single-threaded
  result", `parallel.rs:1-19`) becomes trivially true because both sides run
  the same function.
- WS0.1's clone fix and the WS4.2 single-SDP-parse change land naturally here:
  `process_packet` parses SDP once and passes `Option<&SdpSession>` into
  `process_message`/`track_sdp`.

### WS1 — TDD / migration order

1. Characterization first: a golden test that runs the *same* pcap fixture
   through batch mode and through `pipeline::process_packet` in a loop and
   asserts identical store contents + identical NDJSON output. Run it against
   the current code — it should pass for the overlapping behavior and
   documents the deltas (`--tag`, event-exec, writer) that become hooks.
2. Introduce `PipelineHooks` with default no-ops; port batch mode; delete
   `process_parsed_packet`.
3. Port `load_pcap_file`'s pipeline half; delete `is_rtcp_offline` and the
   duplicated SDP-link block.
4. Port `parallel.rs` workers.

### WS1 — Acceptance

- `grep -n "is_sip_message\|parse_sip_bytes\|link_to_dialog" src/main.rs src/tui/events.rs`
  → no protocol-routing hits outside `pipeline.rs`.
- The equivalence golden test passes; `tests/` suite green; `--jobs N` output
  byte-identical to `--jobs 1` on the fixture corpus (existing contract).
- Net line count of the four sites drops by ≥600 lines.

**Effort:** M (1–2 weeks). **Risk:** medium — mitigated by the equivalence
test and the existing 755 integration tests.

---

## 4. WS2 — Decompose `main.rs` into [`src/app/`](https://github.com/NormB/sipnab/tree/main/src/app)  *(architecture)*

### WS2 — Problem

`main.rs` is 3,343 lines: `run_batch_mode` 724 ln (`:1173`), `main` 641 ln
(`:107`), `run_tui_mode` 264 ln (`:905`), plus token minting, three server
bootstraps each hand-rolling its own single-thread tokio runtime
(`start_api_server:2710`, `start_mcp_server:2777`, `start_mcp_http_server:2831`),
TLS decrypt glue, output dispatch, and report generation. 55 of the
codebase's 167 `#[cfg(feature)]` sites live in this one file. The numbered
step comments run `// 1.`–`// 18.` *across two functions* — one giant script
cut in half, not decomposed. All of it is untestable except through the CLI.

### WS2 — Design

Create [`src/app/`](https://github.com/NormB/sipnab/tree/main/src/app) in the library (unit-testable, unlike `main.rs`):

- `app/bootstrap.rs` — steps 1–17: config merge, validation, privilege
  drop/chroot, capture setup. Returns a `RunPlan` value describing what to
  run. Pure enough to unit test ("given these CLI args + config, the plan is
  X").
- `app/batch.rs` — a `BatchRunner` struct owning writer/detectors/counters as
  fields (today `run_batch_mode` starts with a 24-line field-unpacking
  preamble at `main.rs:1913-1936` — the state already wants to be a struct).
  `run(&mut self, rx)` drives WS1's pipeline.
- `app/servers.rs` — API/MCP/MCP-HTTP/Prometheus startup. **One** shared
  tokio runtime when any is enabled (today: three runtimes, three threads).
  Expose unconditional `fn maybe_start_api(...) -> anyhow::Result<Option<Handle>>`
  whose *body* is cfg-swapped (enabled vs "feature not compiled" error), so
  the caller contains zero `cfg` — the `pipeline::MediaDecrypt` pattern
  (`pipeline.rs:83-97`), which is the codebase's own best practice.

`main.rs` target: <150 lines (parse args → build plan → dispatch).

### Feature-flag consolidation (rolls in the rest of arch Finding 5)

Same facade treatment for the other two cfg hotspots:

- [`src/rtp/srtp.rs`](https://github.com/NormB/sipnab/blob/main/src/rtp/srtp.rs) (26 × `tls` gates in 1,787 lines) → `srtp/parse.rs`
  (always compiled) + `srtp/decrypt.rs` (one `#[cfg(feature = "tls")]` at the
  `mod` line).
- [`src/capture/mod.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/mod.rs) (31 gates, 24 of them `native`) → `capture/native/`
  submodule gated once.

Target: total inline `#[cfg(feature` sites ≤ 60 (from 167), with `main.rs`/
`app/` at ~0.

### WS2 — TDD / acceptance

- Bootstrap decisions get direct unit tests (arg/config matrix → `RunPlan`),
  replacing CLI-only coverage; trycmd goldens stay green unchanged.
- `wc -l src/main.rs` < 150; no function in `app/` > 150 lines.
- One `Runtime::new` (or `Builder`) call site for the three servers.
- `rg -c '#\[cfg\(feature' src/ | sort` shows no file > 15.

**Effort:** M. **Risk:** low-medium — moves, not rewrites; the 51
`output/api.rs` and 33 `mcp/server.rs` async tests already pin server
behavior.

---

## 5. WS3 — One projection layer for dialog/stream summaries  *(architecture + shipped-drift fix)*

### WS3 — Problem

Five implementations of "dialog summary", already divergent on the wire:

| Surface | Site | Drift |
|---|---|---|
| CLI/NDJSON | [`src/output/json.rs:437`](https://github.com/NormB/sipnab/blob/main/src/output/json.rs#L437) `DialogJson` | `msg_count`, `schema_version: 1` |
| REST API | [`src/output/api.rs:715`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs#L715) ad-hoc `json!` | `msg_count`, `method.as_str()` |
| MCP | [`src/mcp/server.rs:8318`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L8318) `DialogSummary` | **`message_count`**, **`format!("{:?}", method)`** |
| TUI save | [`src/tui/save.rs:212`](https://github.com/NormB/sipnab/blob/main/src/tui/save.rs#L212) hand-built `json!` | third field set, no `schema_version` |
| Report | `src/output/call_report.rs:50/183` | independent text/markdown re-derivations |

Same pattern for streams (`api.rs:741` vs `json.rs:115` vs `save.rs:660`).
The "gather dialog → filter streams by `associated_dialog` → `diagnose_media`
→ `diagnose_asymmetry` → `generate_call_report`" ritual is copy-pasted at 6+
sites, and the `.filter(|s| s.associated_dialog.as_deref() == Some(...))`
line occurs at 10 non-test sites — each duplicating lock-ordering decisions.

### WS3 — Design

- New `src/report/` (or a `output/model.rs`): canonical
  `DialogSummary::from(&SipDialog)`, `StreamSummary::from(&RtpStream)`,
  `CallReportModel` — single constructors, serde-derived, consumed by JSON,
  API, MCP, TUI save, and the text/markdown renderers.
- **Scope notes from implementation:** a sixth drifted copy exists in
  [`src/wasm.rs`](https://github.com/NormB/sipnab/blob/main/src/wasm.rs) (`get_dialogs` also says `message_count`), but the website
  JS ([`website/static/js/analyze.js`](https://github.com/NormB/sipnab/blob/main/website/static/js/analyze.js), `analyze.html`) consumes that shape —
  unifying it needs coordinated website-bundle changes and is deferred
  (requires moving the model out of the native-gated `output/` to a leaf
  module first). The `CallReportModel`/text-renderer half is likewise a
  follow-up; this pass unified the four native summary surfaces.
- `DialogStore::streams_for(&self, call_id) -> ...` and a
  `build_call_report(call_id) -> CallReportModel` that owns the lock
  choreography (today MCP hand-rolls `drop(ss); drop(ds)` at
  `server.rs:615-616`).
- **Decision required (breaking-change policy):** unifying key names means
  either MCP changes `message_count` → `msg_count` (recommended — CLI/API are
  the majority and `schema_version` machinery exists) or vice versa. Bump the
  JSON `schema_version` and note it in CHANGELOG. Method strings become
  `as_str()` everywhere (the `{:?}` Debug form on the MCP wire is a bug in
  all but name).

### WS3 — TDD / acceptance

- Failing test first: extend [`tests/json_schema_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/json_schema_test.rs) with a cross-surface
  consistency test — the same fixture rendered via CLI JSON, API, MCP, and
  TUI save must produce identical field names/values for the shared core.
  It fails today (red); goes green with the unification.
- `api.rs:715-763`, `save.rs:212-278` deleted; `mcp::DialogSummary` folded in.
- `.filter(|s| s.associated_dialog...)` count in non-test code: ≤ 2.

**Effort:** S–M. **Risk:** low — schema-versioned, drift-tested.

---

## 6. WS4 — Hot-path performance (bench-first, in this order)

### WS4.0 Close the bench coverage gaps *(prerequisite for everything below)*

Existing benches measure `parse_sip`, via-scaling, RTP/SDP/DSL parse,
detection, and store ops — but **nothing measures** `PacketProcessor::process`
end-to-end, the parse→store per-message path, TCP framing/reassembly, or any
TUI derived-data computation. Also, parser benches call `parse_sip` (which
does an extra `Bytes::copy_from_slice`, `parser.rs:57`) rather than the hot
path's `parse_sip_bytes` — bench the function the pipeline actually runs.

Add, before optimizing:

1. `packet_process` — UDP fast path, TCP reassembly + `frame_tcp_sip`, IP
   fragments through `PacketProcessor::process`.
2. `msg_pipeline` — messages/sec through parse → `process_message` (catches
   WS0.1's clone and WS4.2's double SDP parse).
3. `tui_derived` — `displayed_dialogs` over a 10k-dialog store with/without
   search query; `prepare_messages` on a 500-message dialog.
4. Switch parser benches to `parse_sip_bytes`.

**Accept:** benches exist, run under `cargo bench -- --test` in CI (smoke
mode, seconds), baselines recorded in the PR description.

### WS4.1 SIP header parse: ~3 allocations/header → ~0–1  *(HIGH)*

[`src/sip/parser.rs`](https://github.com/NormB/sipnab/blob/main/src/sip/parser.rs) per header line: `:253` owned unfold buffer even when no
folding occurs (folding is rare); `:328` `value.trim().to_string()`; `:343-353`
`Cow::Owned` for every *long-form* header name (`Via`, `From`, `Call-ID` —
i.e. the common case; only compact single-char forms borrow); `:199`
`Vec::new()` with no capacity hint. ≈ 38–42 allocations per typical
12-header INVITE. The `raw`/`body` side is already zero-copy `Bytes`.

In ascending invasiveness (land 1–3 now; 4 is `[SEMVER]`, defer to 0.5.0):

1. Canonical-name table for the ~20 common long-form names (mirror of
   `COMPACT_HEADERS`, case-insensitive → `Cow::Borrowed(&'static str)`).
2. Parse from the borrowed line; materialize the unfold buffer only when a
   continuation (SP/HTAB peek) is actually present.
3. `Vec::with_capacity(16)` for headers.
4. `[SEMVER]` Header values as byte ranges into `raw` (as `body` already is).

**Accept:** via-scaling bench slope drops measurably; a dhat/heaptrack
allocation-count check shows ≤ 1 allocation per common header (steps 1–3).

### WS4.2 Parse SDP once per message  *(MEDIUM)*

`SipMessage::sdp()` re-parses the body on every call (`message.rs:139-149`).
Live path parses twice per SDP-carrying message — `pipeline.rs:151` and again
*inside the dialog-store write lock* via `track_sdp`
(`sdp_timeline.rs:68`). The TUI's `prepare.rs` calls it up to 4× per message
*per frame* (`:212,:259,:264,:275`).

Fix: parse once in `process_packet` and pass `Option<&SdpSession>` down
(composes with WS1), and/or memoize with `OnceLock<Option<SdpSession>>` in
`SipMessage`. **Accept:** `msg_pipeline` bench delta; write-lock hold time no
longer includes an SDP parse.

### WS4.3 TUI: compute derived data once, stop allocating in search  *(HIGH when interactive)*

Per frame in CallList view, the filter+search+sort pass runs **three times**
(`render.rs:35-84`, `:100-107`, `call_list.rs:437-443`), each pass sorts, and
full-text search allocates up to two lowercased Strings per stored message per
pass (`call_list.rs:343-347`, duplicated at `render.rs:74-78`) — all while
holding `dialog_store.try_read()`, so a slow search frame backpressures the
capture thread's `write()`.

- Compute `displayed_dialogs` once per frame; share for count/autoscroll/rows.
- Cache keyed on `(dialog_count, filter, query, sort)` — the count is already
  tracked (`mod.rs:1268-1275`).
- Replace lowercasing with an allocation-free ASCII case-insensitive scan
  (`memchr::memmem` with case-folded needle or `eq_ignore_ascii_case`
  windows).
- CallFlow: memoize the prepared ladder keyed on
  `(call_id, msg_count, options, selection)`; cache `find_correlated`
  (O(dialogs×messages) rescan per frame, `dialog_store.rs:356-449`) and
  `rtp_codec_segments` (full stream-store scan per frame, `mod.rs:1463-1480`)
  the same way.

**Accept:** `tui_derived` bench: 10k-dialog search frame cost drops ≥ 5×; one
`displayed_dialogs` execution per frame (assertable with a test counter);
existing 261 headless TUI state tests + 49 snapshots green.

### WS4.4 Per-packet floor  *(MEDIUM)*

- `PacketProcessor::process` returns `Vec<ParsedPacket>` — one ~150-byte Vec
  alloc per packet for the `vec![parsed]` common case
  (`capture/mod.rs:411,:528`). → `SmallVec<[ParsedPacket; 1]>` or enum return.
- Pure-Rust reader copies every packet out of an already-in-memory file
  (`pcap_reader.rs:63,:164`) → hold the file as `Bytes`, slice zero-copy.
- Audio capture copies the payload per RTP packet
  (`stream_store.rs:149,:167`) → `parsed.payload.slice(payload_start..)`
  (ring buffer capped at 1500 frames, pinning cost ≈ copy cost).
- TCP SIP framing scans with scalar `windows(4)` + an unconditional full
  `windows(2)` pass, and re-scans held leftovers from offset 0
  (`capture/mod.rs:564-601`) → `memchr::memmem::Finder`, remember last
  scanned offset.

**Accept:** `packet_process` bench deltas per item; suite green.

---

## 7. WS5 — TUI structural decomposition  *(architecture; do after WS1, pairs with WS4.3)*

### Problem

- `App` ([`src/tui/mod.rs:75`](https://github.com/NormB/sipnab/blob/main/src/tui/mod.rs#L75)): 67 fields — 6 independent scroll offsets,
  full save-dialog state (6 fields), file-open state (7 fields), name-popup
  state, render caches. No compiler help against stale cross-popup state.
- `src/tui/events.rs`: 3,709 lines, 372 `KeyCode::` arms in 21 `handle_*`
  fns; `handle_call_flow_key` is 495 lines opening with 45 lines of
  store-locking count computation. Non-event logic embedded: `load_pcap_file`
  (194 ln — removed by WS1) and `refresh_file_entries` (83 ln of directory
  browsing).
- `render_app` (`render.rs:15`, 490 ln) **mutates** state during render
  (`app.cached_dialog_count = ...` at `render.rs:36`), making render order
  load-bearing for navigation clamping (`events.rs:556-560` documents the
  coupling defensively).

### Design (standard TUI decomposition)

1. Per-view state structs — `SaveDialogState`, `FileOpenState`,
   `CallFlowViewState` (owning its scroll/selection/caches) — held as fields
   or inside the `View`/`Popup` enum variants, so opening popup B cannot see
   popup A's stale fields.
2. Split `events.rs` into `tui/controllers/{call_list,call_flow,save,
   file_open,filter,...}.rs` — one per existing `handle_*` fn (mechanical).
3. A `KeyAction` enum layer: key→action mapping (keymap-aware, testable in
   isolation) separated from action execution. The existing
   `keybinding_drift_test.rs` then checks the mapping table directly.
4. Move cache refresh out of `render_app` into an explicit
   `App::sync_caches()` called from the event-loop tick — renders become
   read-only.
5. Collapse the parameter clumps: a `ViewCtx { theme, keymap, area }` +
   per-view state kills the 8–10-param renderers (`stream_list.rs:217` has
   10 params) and most of the 7 `too_many_arguments` allows (WS0.3).
6. Split `prepare_messages` (514 ln, mixes lane layout + transaction folding
   + theme-colored text formatting) into pure `layout()` (theme-free) →
   `style()` — which also makes WS4.3's ladder memoization natural (layout is
   the cacheable part).

### TDD / acceptance

- The 261 headless state tests + 106 events tests + snapshots are the
  characterization net; they must pass unchanged (except mechanical import
  updates) after each split.
- New unit tests for the `KeyAction` mapping layer (red-green for at least
  one remapped key before the layer lands).
- No file in [`src/tui/`](https://github.com/NormB/sipnab/tree/main/src/tui) > 1,200 lines; no function > 150 lines; `App` direct
  scalar fields < 30; zero state writes inside `render_app` (grep for
  `app.` assignments in render fns).

**Effort:** L but mechanical. **Risk:** low given the test net.

---

## 8. WS6 — Library API hardening  `[SEMVER]`  *(idioms; batch into 0.5.0)*

### WS6.1 Typed errors for the re-exported parse/capture surface

[`src/error.rs`](https://github.com/NormB/sipnab/blob/main/src/error.rs) has a good `#[non_exhaustive]` thiserror enum — but it covers
only config/CLI/validation. Everything actually re-exported at the crate root
(`parse_sip`, `parse_sip_bytes`, `parse_packet`, `parse_rtp_header`,
`parse_sdp`, `PcapReader`, SRTP/HEP/decrypt) returns `anyhow::Result`, with
**42 `anyhow!` + 85 `bail!`** stringly errors in library modules — exactly the
"callers pattern-match on message text" problem `error.rs`'s own doc comment
says it was created to fix.

- Add `ParseError` / `CaptureError` thiserror enums with structured variants
  (`TooShort { need, got }`, `Truncated { at }`, `BadVersion(u8)`, ...).
- Minimum viable scope: convert the crate-root re-exports only (they define
  the semver contract for "available as a library", per `lib.rs:5-6`);
  interior modules can follow incrementally.
- `anyhow` remains for `main.rs`/`app/` orchestration only. (Today `main.rs`
  ironically doesn't use anyhow at all — hand-rolled `eprintln!` + exit
  codes, `main.rs:145-215`.)
- Fix `error.rs` variants carrying `reason: String` instead of
  `#[source] std::io::Error` / `toml::de::Error` — zero source-chaining today
  (C-GOOD-ERR).

**TDD:** for each converted function, a failing test first asserting a
*matchable* variant (e.g. truncated RTP → `ParseError::TooShort { .. }`), not
message text.

### WS6.2 API-guidelines sweep

- `#[non_exhaustive]` on growth-prone public enums (currently 5 of 39):
  `FilterExpr`, `FraudType`, `RtcpPacket`, `TransportProto`, ... — adding a
  variant is semver-major today.
- `derive(Debug)` for `StreamStore` (`stream_store.rs:40`) and `DialogStore`
  (`dialog_store.rs:61`) — keep the existing hand-written key-redacting
  `Debug` pattern (`srtp.rs:38`, `rsa_key.rs:21`) for anything holding
  secrets.
- Naming: `get_`-prefixed getters in [`src/wasm.rs:109-324`](https://github.com/NormB/sipnab/blob/main/src/wasm.rs#L109-L324); `SipMessage::
  to_user/to_host/to_tag/to_display` read as expensive `to_` conversions but
  are cheap "To:"-header accessors — rename toward `to_header_user()` or
  document loudly; `SipMethod::as_str(&self)` vs `TransportProto::as_str(self)`
  inconsistency.
- Decide the `#[doc(hidden)] pub mod cli/tui/privilege/...` question: either
  split a `sipnab-cli` bin crate (workspace already has a second member, so
  the pattern exists) or document explicitly that hidden modules carry no
  semver guarantee. Recommended: document now (one paragraph in lib.rs),
  split only if/when a real external library consumer appears.

### WS6.3 Doc-tests for the top library entry points

5 doctests exist for a 733-item public API; most `///` code fences are
non-compiled ```` ```text ```` blocks. Add compiled (`no_run` where I/O-bound)
examples to the top ~10 entry points: `PcapReader`, `parse_sip`,
`parse_packet`, `FilterExpr`, `DialogStore`, `StreamStore`; convert the
`ignore`d `dsl.rs:49` example to `no_run`. Compiled examples are the only
ones CI keeps honest.

**Accept (WS6):** 0.5.0 CHANGELOG documents the breaking changes; crate-root
re-exports return typed errors; `cargo test --doc` ≥ 15 passing doctests;
`cargo semver-checks` (one-shot, local) run to enumerate the break list
before release.

---

## 9. WS7 — Make the dormant safety nets execute  *(testing & CI)*

Ordered by risk closed per unit effort:

1. **Run the fuzzers.** 11 targets are compile-checked only; corpus exists
   for 1. Add a weekly scheduled workflow: `cargo fuzz run <target> --
   -max_total_time=300` per target, uploading crash artifacts; check in
   minimized corpora (also feeds `fuzz_corpus_replay.rs`, which currently
   replays a hardcoded seed set). ClusterFuzzLite is the lowest-maintenance
   alternative. For a privileged parser of hostile traffic this is the
   highest-value dormant asset in the repo.
2. **New fuzz targets for uncovered untrusted-input surfaces:** pcapng file
   reader (`pcap_reader.rs`/`pcapng_meta.rs` — a hostile `.pcapng` handed to
   `sipnab -I` is a primary workflow), DTLS (`capture/dtls.rs`), TCP
   reassembly (`capture/reassembly.rs`), SIPREC XML if hand-parsed. Seed from
   [`tests/pcap-samples/`](https://github.com/NormB/sipnab/tree/main/tests/pcap-samples).
3. **Property-based testing.** proptest as dev-dep; start with three
   properties: SIP build→parse→field round-trip (generator skeleton =
   `test_utils::build_sip_message`), SDP round-trip, filter-DSL parse/eval
   total-function. Complements the fuzzers (which only prove "no panic", not
   "parsed correctly").
4. **Latest-stable CI leg.** Everything pins 1.97.1 (good as an MSRV gate);
   add one `dtolnay/rust-toolchain@stable` job running
   `cargo test --all-features` (clippy on stable may be `continue-on-error`
   to absorb new-lint churn).
5. **wasm runtime tests.** [`src/wasm.rs`](https://github.com/NormB/sipnab/blob/main/src/wasm.rs) (415 ln) is check-only in CI with
   one source-text-level test; the pre-commit hook itself names "WASM module
   out of sync" as a historical bug class. Add `wasm-bindgen-test` +
   `wasm-pack test --node` CI step.
6. **Feature matrix:** replace the hand-curated 10-combo list with
   `cargo hack check --feature-powerset --depth 2 --no-dev-deps
   --exclude-features wasm` (depth-2 pairs are where cfg-rot lives — note
   WS2's cfg consolidation shrinks this risk at the source). Keep the
   curated *test* runs.
7. **Coverage:** flip Codecov **patch** status to non-informational at a
   modest target (70–80% of changed lines) — patch gates don't punish legacy
   code. Leave project status informational.
8. **TUI e2e visibility:** keep `continue-on-error` but write the result to
   the job summary, or move to a scheduled workflow that opens an issue on
   failure — a soft-forever gate is close to no gate.
9. **Deterministic clocks:** ~~inject a clock into the token-TTL path~~ **done** —
   [`tests/mcp_token_rotation_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/mcp_token_rotation_test.rs) no longer
   sleeps for a fixed multi-second span; it polls until the TTL elapses, for the
   reason its own comment gives. Still open: convert
   `parse_path_test.rs:140,147` fixed sleeps to the existing poll-until
   helper.
10. **One-shot calibration:** run `cargo mutants` locally on `sip/parser.rs`,
    `rtp/quality.rs`, `sip/dialog_store.rs` to measure assertion strength of
    the 2,200-test corpus; act only if the score is surprising.

**Accept:** fuzz cron green for 4 consecutive weeks with corpora checked in;
proptest suite in `tests/`; stable leg green; patch-coverage gate active.

---

## 10. Sequencing & effort summary

| Phase | Workstream | Effort | Depends on |
|---|---|---|---|
| 1 | WS0.1–WS0.7 quick wins | ~1 wk total | — |
| 1 | WS4.0 benches | 2–3 d | — |
| 2 | WS3 projection layer (fixes shipped drift) | 3–5 d | — |
| 2 | WS4.1–WS4.2 parser/SDP allocations | 3–5 d | WS4.0 |
| 3 | WS1 pipeline unification | 1–2 wk | WS4.0 (equivalence bench useful) |
| 3 | WS2 `main.rs` → `app/` + cfg facades | 1–2 wk | WS1 |
| 4 | WS5 TUI decomposition | 1–2 wk | WS1 (removes `load_pcap_file`) |
| 4 | WS4.3–WS4.4 TUI + packet-floor perf | 1 wk | WS4.0, ideally WS5.6 |
| 5 | WS6 API hardening → 0.5.0 | 1 wk | WS1–WS3 (stable surface first) |
| ongoing | WS7 safety nets | 1–2 d each | — |

Rationale for the order: the quick wins and benches are free; WS3 fixes
already-shipped wire inconsistency; WS1+WS2 are the complexity core and
everything else gets easier after them; WS6's semver-breaking batch should
land once, after the structure settles.

---

## 11. Explicit non-goals (verified good — don't spend review time here)

- **Panic hygiene:** 0 unwrap/expect/panic in non-test library code (all 706
  unwraps / 576 expects are in test modules); parsers bounds-check before
  every index. No action.
- **Regex compilation:** all compiled once (matcher at construction, DSL `=~`
  at filter-parse); the only call-path `Regex::new` is test code.
- **Store layer:** borrowed-key lookups, move-not-clone inserts, batched
  eviction with regression probes, SSRC/endpoint indexes, idle compaction —
  already tuned; leave alone.
- **Packet data spine:** `Packet.data`/`ParsedPacket.payload`/`SipMessage.raw`
  /`body` are `Bytes` refcount slices — zero-copy already.
- **JSON emit:** typed serde structs, single `to_string` per line, no
  intermediate `Value`.
- **Module docs / lib.rs curation:** 100% module-doc coverage; `lib.rs` is a
  model curated surface. The mod.rs re-export hygiene is consistent.
- **Insta/trycmd usage:** right-sized snapshots (largest 44 lines), and
  `flag_coverage_test.rs` self-enforces CLI coverage — a practice worth
  keeping as-is.
- **Build profiles:** LTO, CU=1, panic=abort, plus a dedicated `profiling`
  profile — nothing left on the table.
- **Existing allocator/hashing choices** (mimalloc, ahash, memchr line
  scanner, crossbeam, parking_lot): confirmed present and correct; not
  revisited.

## WS8 — 0.5.16 benchmark re-validation follow-ups (2026-07-20, aarch64)

The 0.5.16 re-run (see docs/benchmarks page) improved every multi-core and
sweep throughput number but appeared to surface two regressions vs the
0.4.16 session. **Both were closed the same day by a controlled A/B** of the
0.4.16 and 0.5.17 release binaries, same host/corpus/pinning, median-of-5:

- **WS8.1 — CLOSED, not a regression.** cores=1 with `-O`: 0.4.16 = 826k
  p/s, 0.5.17 = 814k p/s (−1.5%, noise); plain cores=1: 1.26M vs 1.24M.
  The June "1.05M" row does not reproduce with the 0.4.16 binary itself —
  session variance in the June figures.
- **WS8.2 — CLOSED, not a regression.** Sweep RSS with `-O`: @500 calls
  0.4.16 = 40 MiB vs 0.5.17 = 39; @2000 calls 99 vs 103. The June 33/72
  figures do not reproduce with 0.4.16 either.
- **WS8.3 — SHIPPED (2026-07-20):** `-O` pcap re-emit cost ~35% of
  single-core throughput because the plain-pcap backend paid one FFI call
  + locked stdio `fwrite` per packet through libpcap's `Savefile` (which
  also silently discarded write errors). Replaced with `RawPcapWriter`
  (writer.rs): classic-pcap records through a 512 KiB `BufWriter`, LE
  headers written directly, errors surfaced. Measured (535k corpus,
  cores=1, median-of-5) — CORRECTED 2026-07-20 after a provenance error:
  the initial "+8.3% on aarch64" compared a native build against a CI
  cross-built artifact and was mostly toolchain delta. The clean numbers:
  same-toolchain A/B (writer commit vs parent, identical local rustc) puts
  the per-packet write cost at −43% (overhead 115ms → 65ms over 535k pkts)
  and x86 e2e at +8–16%; artifact-vs-artifact on aarch64 shows e2e
  UNCHANGED (831k → 827k) because there the re-emit is bound by page-cache
  data volume, not per-packet overhead. The unconditional win is error
  surfacing. Lesson: A/B only same-provenance binaries.
